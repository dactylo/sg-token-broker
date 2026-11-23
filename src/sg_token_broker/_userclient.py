"""Client for the user-token service: fetch human-bound SG tokens."""

import datetime
import os
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import cast

import requests

from sg_token_broker._client import (
    EXPIRED_REST,
    EndpointRedirectError,
    redirect_error,
    redirect_hooks,
)
from sg_token_broker._diagnostics import local_send_detail
from sg_token_broker._retry import (
    DEFAULT_MAX_WAIT_SECONDS,
    DEFAULT_REFRESH_MARGIN_SECONDS,
    DEFAULT_RETRIES,
    DEFAULT_TIMEOUT_SECONDS,
    AcquisitionFailureError,
    Budget,
    RetryTiming,
    cold_delay,
    decide,
    parse_retry_after,
    validate_tuning,
)
from sg_token_broker._urlpolicy import endpoint_origin, require_https_or_loopback
from sg_token_broker._userauth import (
    SignInError,
    SignInSettingsError,
    decode_unverified_payload,
    default_id_token_source,
)

_ENV_URL = 'SG_USER_TOKEN_URL'
_OK_STATUS = 200
_REST_TYPE = 'rest'
_SESSION_TYPE = 'session'
_TOKEN_TYPES = frozenset({_REST_TYPE, _SESSION_TYPE})


@dataclass(frozen=True)
class UserToken:
    """Represent a human-bound SG token issued by the user-token service.

    `expires_at` is `None` for session tokens (no scheduled expiry; SG's
    sliding inactivity window governs). `cache_until` equals `expires_at` for
    REST tokens and is the service's caching hint for sessions; it is never a
    separate client refresh trigger.

    Attributes:
        token: Issued SG credential.
        token_type: Issued token type, `rest` or `session`.
        login: SG HumanUser login bound to the token.
        site_url: Base URL of the SG site.
        expires_at: REST refresh deadline derived from SG's lifetime minus a
            safety margin, or `None` for a session token.
        cache_until: Service-provided caching horizon.
    """

    token: str = field(repr=False)
    token_type: str
    login: str
    site_url: str
    expires_at: datetime.datetime | None
    cache_until: datetime.datetime


class UserTokenClientError(Exception):
    """User-token client configuration, sign-in or token acquisition failed."""


class UserTokenSettingsError(UserTokenClientError):
    """The user-token client settings are missing or invalid."""


class _ServiceRetrier:
    """Retry a user-token service request within the current caller's budget."""

    def __init__(
        self,
        *,
        max_wait: float,
        retries: int | None = DEFAULT_RETRIES,
        timing: RetryTiming | None = None,
    ) -> None:
        """Configure the request-start budget and retry timing."""
        self._retries = retries
        self._max_wait = max_wait
        self._timing = timing if timing is not None else RetryTiming()

    @staticmethod
    def _service_failure(response: requests.Response) -> tuple[str | None, str]:
        """Describe a rejected service response using its JSON fields when available."""
        message = f'service refused (HTTP {response.status_code}'
        try:
            body: object = response.json()
        except ValueError:
            body = None
        code = None
        if isinstance(body, dict):
            fields = cast('dict[str, object]', body)
            error = fields.get('error')
            if isinstance(error, str):
                code = error
                message += f' {error}'
            detail = fields.get('detail')
        else:
            detail = None
        message += ')'
        if isinstance(detail, str):
            message += f': {detail}'
        return code, message

    def _attempt(
        self, send: Callable[[], requests.Response], service_url: str, token_type: str
    ) -> UserToken | tuple[str, float | None]:
        """Return a usable token or the failure and minimum delay for another attempt."""
        try:
            response = send()
        except ValueError:
            raise UserTokenClientError(
                'invalid request or redirect URL; configure the final user-token service URL'
            ) from None
        except EndpointRedirectError as exc:
            raise UserTokenClientError(str(exc)) from None
        except requests.RequestException as exc:
            origin = endpoint_origin(service_url)
            message = f'cannot reach user-token service at {origin}: {type(exc).__name__}'
            if decide(None, None) == 'fail':
                raise UserTokenClientError(message) from None
            return message, None

        if response.status_code == _OK_STATUS:
            token = _parse_response(response, token_type)
            if token.expires_at is None or datetime.datetime.now(datetime.UTC) < token.expires_at:
                return token
            return EXPIRED_REST, None
        code, message = self._service_failure(response)
        if decide(response.status_code, code) == 'fail':
            raise UserTokenClientError(message)
        return message, parse_retry_after(
            response.headers.get('Retry-After'), datetime.datetime.now(datetime.UTC)
        )

    def request(
        self,
        send: Callable[[], requests.Response],
        service_url: str,
        budget: Budget,
        token_type: str,
    ) -> UserToken:
        """Fetch a usable token using the caller's deadline for starting requests.

        Args:
            send: Repeatable operation sending the same token request.
            service_url: Service endpoint used to identify transport failures.
            budget: Monotonic deadline for starting requests.
            token_type: Expected type of the returned token.

        Raises:
            UserTokenClientError: If the request cannot be sent, the endpoint
                redirects, the service refuses or returns unusable data, or the
                budget or attempt limit prevents another request.
        """
        attempts = 0
        last_failure = None
        while budget.can_start(self._timing.clock()):
            attempts += 1
            outcome = self._attempt(send, service_url, token_type)
            if isinstance(outcome, UserToken):
                return outcome
            last_failure, retry_after = outcome
            if self._retries is not None and attempts > self._retries:
                failure = AcquisitionFailureError('attempts', last_failure)
                break
            delay = cold_delay(attempts - 1, retry_after, rng=self._timing.rng)
            if not budget.can_start(self._timing.clock() + delay):
                failure = AcquisitionFailureError(
                    'budget',
                    last_failure,
                    delay or None,
                    retry_after_from='service' if retry_after is not None else None,
                )
                break
            self._timing.sleep(delay)
        else:
            failure = AcquisitionFailureError('budget', last_failure)
        raise UserTokenClientError(
            failure.describe(attempts=attempts, retries=self._retries, max_wait=self._max_wait)
        )

    def start_budget(self) -> Budget:
        """Start a fresh monotonic budget for the resolved identity."""
        return Budget(self._max_wait, self._timing.clock)


class UserTokenClient:
    """Fetch and memory-cache human-bound SG tokens.

    The lock is held across the sign-in and network round trip; concurrent
    callers serialize.
    Accepted tradeoff.
    """

    def __init__(  # noqa: PLR0913 - public keyword-only tuning matches BrokerClient
        self,
        service_url: str | None = None,
        *,
        id_token_source: Callable[[], str] | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        retries: int | None = DEFAULT_RETRIES,
        refresh_margin: float = DEFAULT_REFRESH_MARGIN_SECONDS,
        max_wait: float = DEFAULT_MAX_WAIT_SECONDS,
        session: requests.Session | None = None,
    ) -> None:
        """Configure user-token access and identity sourcing.

        Args:
            service_url: User-token service base URL. Defaults to
                `$SG_USER_TOKEN_URL`.
            id_token_source: Callable returning a current OIDC ID token. It is
                called on every `fetch_token`, and its `sub` claim selects
                which cached entries may be served.
                Defaults to `default_id_token_source`.
            timeout: Seconds allowed to connect and for each wait for response
                data.
            retries: Maximum retries after the first service request. Zero
                allows one request. With `None`, only the time budget limits
                retries.
            refresh_margin: Seconds before a REST token's expiry at which it is
                refreshed.
            max_wait: Seconds available to start service requests after
                resolving the identity. A request in progress may finish after
                this budget.
            session: Optional preconfigured Requests session. A fresh
                `requests.Session` is created when `None`.

        Raises:
            ValueError: If timeout or max_wait is non-finite or non-positive,
                retries is neither None nor a non-negative integer, or
                refresh_margin is non-finite or negative.
            UserTokenClientError: If the service URL or default sign-in
                settings are missing or invalid, or OIDC discovery fails.
        """
        validate_tuning(
            timeout=timeout, retries=retries, refresh_margin=refresh_margin, max_wait=max_wait
        )
        self._service_url = (service_url or os.environ.get(_ENV_URL, '')).rstrip('/')
        if not self._service_url:
            raise UserTokenSettingsError(
                f'service URL missing; set {_ENV_URL} or pass it explicitly'
            )
        try:
            require_https_or_loopback(self._service_url, 'user-token service URL')
        except ValueError as exc:
            raise UserTokenSettingsError(str(exc)) from exc
        self._retrier = _ServiceRetrier(max_wait=max_wait, retries=retries)
        if id_token_source is None:
            try:
                id_token_source = default_id_token_source()
            except SignInSettingsError as exc:
                raise UserTokenSettingsError(str(exc)) from exc
            except SignInError as exc:
                raise UserTokenClientError(str(exc)) from exc
        self._id_token_source = id_token_source
        self._timeout = timeout
        self._refresh_margin = refresh_margin
        self._session = session if session is not None else requests.Session()
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[str, UserToken]] = {}

    def _current_identity(self) -> tuple[str, str]:
        """Return (id_token, sub) from one snapshot of the identity source."""
        try:
            id_token = self._id_token_source()
        except SignInError as exc:
            raise UserTokenClientError(f'sign-in failed: {exc}') from exc
        try:
            payload = decode_unverified_payload(id_token)
        except SignInError as exc:
            raise UserTokenClientError('identity token has no decodable sub claim') from exc
        sub = payload.get('sub')
        if not isinstance(sub, str) or not sub:
            raise UserTokenClientError('identity token has no decodable sub claim')
        return id_token, sub

    def _request(
        self, token_type: str, id_token: str, budget: Budget, *, refresh: bool
    ) -> UserToken:
        """GET /v1/user-token and parse the response."""
        params: dict[str, str] = {'token_type': token_type}
        if refresh:
            params['refresh'] = 'true'

        def send() -> requests.Response:
            try:
                response = self._session.get(
                    f'{self._service_url}/v1/user-token',
                    allow_redirects=False,
                    hooks=redirect_hooks(self._session, 'user-token service URL', id_token),
                    params=params,
                    headers={'Authorization': f'Bearer {id_token}'},
                    timeout=self._timeout,
                )
            except requests.RequestException:
                raise
            except OSError as exc:
                detail = local_send_detail(exc, self._session.verify)
                raise UserTokenClientError(
                    f'user-token request could not be sent: {detail}'
                ) from None
            if HTTPStatus.MULTIPLE_CHOICES <= response.status_code < HTTPStatus.BAD_REQUEST:
                raise UserTokenClientError(
                    redirect_error(response, 'user-token service URL', id_token)
                )
            return response

        return self._retrier.request(send, self._service_url, budget, token_type)

    def _stale(self, token: UserToken) -> bool:
        """Return True if a REST token is within the refresh margin of expiry."""
        if token.expires_at is None:
            return False
        now = datetime.datetime.now(datetime.UTC)
        return (token.expires_at - now).total_seconds() <= self._refresh_margin

    def fetch_token(
        self, token_type: str = _SESSION_TYPE, *, force_refresh: bool = False
    ) -> UserToken:
        """Return a token of the given type, fetching from the service as needed.

        Resolve the current identity on every call. Reuse a client-cache entry
        only while its identity matches; REST entries also refresh near expiry.
        Session entries do not refresh based on `cache_until`.

        Args:
            token_type: `session` (default) or `rest`.
            force_refresh: Bypass the client cache. For sessions, ask the
                service to probe its cached session and replace it only if SG
                rejects it; a missing or expired service-cache entry causes a
                fresh mint without a probe. For REST, the service may still
                return its cached token.

        Returns:
            The cached or newly fetched token. Ordinary cache reuse does not
            establish that SG still accepts the token.

        Raises:
            UserTokenClientError: If the token type is unsupported, sign-in
                fails or the identity token has no decodable subject, the
                service is unreachable or refuses, or its response is malformed
                or mismatched.
            OSError: If the default sign-in flow cannot set up or close its
                local callback listener.
            RuntimeError: If the default sign-in flow cannot start its callback
                serving thread.
            Exception: Errors from a custom identity source propagate
                unchanged, except for `SignInError`, which is wrapped in
                `UserTokenClientError`.
        """
        with self._lock:
            if token_type not in _TOKEN_TYPES:
                raise UserTokenClientError(f'unsupported token_type: {token_type!r}')
            id_token, sub = self._current_identity()
            budget = self._retrier.start_budget()
            cached = self._cache.get(token_type)
            if cached is not None:
                cached_sub, token = cached
                if cached_sub == sub and not force_refresh and not self._stale(token):
                    return token
                self._cache.pop(token_type, None)
            fresh = self._request(token_type, id_token, budget, refresh=force_refresh)
            self._cache[token_type] = (sub, fresh)
            return fresh


def _parse_timestamp(value: str, name: str) -> datetime.datetime:
    """Parse an ISO timestamp, requiring timezone awareness."""
    try:
        parsed = datetime.datetime.fromisoformat(value)
    except ValueError as exc:
        raise UserTokenClientError(f'malformed service response: bad {name}') from exc
    if parsed.tzinfo is None or parsed.tzinfo.utcoffset(parsed) is None:
        raise UserTokenClientError(f'malformed service response: naive {name}')
    return parsed


def _parse(body: object) -> UserToken:
    """Build a UserToken from the service's JSON body."""
    if not isinstance(body, dict):
        raise UserTokenClientError('malformed service response')
    fields = cast('dict[str, object]', body)
    values: dict[str, str] = {}
    for name in ('token', 'token_type', 'login', 'site_url', 'cache_until'):
        value = fields.get(name)
        if not isinstance(value, str) or not value:
            raise UserTokenClientError(f'malformed service response: bad {name}')
        values[name] = value
    raw_expires = fields.get('expires_at')
    expires_at: datetime.datetime | None = None
    if raw_expires is not None:
        if not isinstance(raw_expires, str):
            raise UserTokenClientError('malformed service response: bad expires_at')
        expires_at = _parse_timestamp(raw_expires, 'expires_at')
    if values['token_type'] not in _TOKEN_TYPES:
        raise UserTokenClientError('malformed service response: bad token_type')
    cache_until = _parse_timestamp(values['cache_until'], 'cache_until')
    if values['token_type'] == _SESSION_TYPE and expires_at is not None:
        raise UserTokenClientError('malformed service response: session with expires_at')
    if values['token_type'] == _REST_TYPE and expires_at is None:
        raise UserTokenClientError('malformed service response: rest without expires_at')
    if values['token_type'] == _REST_TYPE and cache_until != expires_at:
        raise UserTokenClientError(
            'malformed service response: cache_until differs from expires_at'
        )
    return UserToken(
        token=values['token'],
        token_type=values['token_type'],
        login=values['login'],
        site_url=values['site_url'],
        expires_at=expires_at,
        cache_until=cache_until,
    )


def _parse_response(response: requests.Response, token_type: str) -> UserToken:
    """Validate the response body and match it to the requested token type."""
    try:
        body: object = response.json()
    except ValueError as exc:
        raise UserTokenClientError('service returned a non-JSON body') from exc
    token = _parse(body)
    if token.token_type != token_type:
        raise UserTokenClientError(
            f'service returned token_type {token.token_type!r} for a {token_type!r} request'
        )
    return token
