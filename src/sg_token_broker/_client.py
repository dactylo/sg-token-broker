"""Fetch and locally cache SG tokens from the broker."""

import datetime
import hashlib
import heapq
import hmac
import math
import os
import threading
from collections.abc import Callable, Collection, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import cast
from urllib.parse import urljoin

import requests

from sg_token_broker._config import CLIENT_ID_MAX_CHARS, is_client_id, is_credential_text
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
    first_refresh_time,
    parse_retry_after,
    renewal_delay,
    validate_tuning,
)
from sg_token_broker._urlpolicy import endpoint_origin, require_https_or_loopback

_ENV_PREFIX = 'SG_TOKEN_BROKER'
EXPIRED_REST = 'REST token expired before delivery; check the service clock and token lifetime'
_HISTORY_LIMIT = 8
_HISTORY_SECONDS = 24 * 60 * 60
_INVALIDATED = (
    'broker returned a token already reported rejected; no further request could be made'
)
_OLD_BROKER = 'broker returned a token already reported rejected; upgrade every broker to 0.3.0'
_SESSION_TYPE = 'session'


class BrokerClientError(Exception):
    """Broker client configuration or token acquisition failed."""


class _TransientError(Exception):
    """A retryable broker failure with its optional minimum delay."""

    def __init__(self, message: str, retry_after: float | None) -> None:
        """Remember the service delay in seconds."""
        super().__init__(message)
        self.retry_after = retry_after


@dataclass(frozen=True)
class ClientOptions:
    """Validated request and renewal settings used by the broker acquisition logic.

    Attributes:
        timeout: Per-request timeout in seconds.
        retries: Optional cap on retries after the caller's first request.
            Zero allows only the first request.
        refresh_margin: Seconds before the broker deadline to start renewal,
            with additional jitter to spread requests.
        max_wait: Monotonic budget in seconds for starting requests, including
            waits to join other callers. An in-flight request may finish later.

    Raises:
        ValueError: If a timeout or budget is non-finite or non-positive,
            retries is neither None nor a non-negative integer, or the margin
            is non-finite or negative.
    """

    timeout: float = DEFAULT_TIMEOUT_SECONDS
    retries: int | None = DEFAULT_RETRIES
    refresh_margin: float = DEFAULT_REFRESH_MARGIN_SECONDS
    max_wait: float = DEFAULT_MAX_WAIT_SECONDS

    def __post_init__(self) -> None:
        """Validate request timeouts, retry counts, and refresh margins.

        Raises:
            ValueError: If `timeout` is non-finite or not greater than zero,
                `retries` is neither None nor a non-negative integer,
                `refresh_margin` is non-finite or negative, or `max_wait` is
                non-finite or non-positive.
        """
        validate_tuning(
            timeout=self.timeout,
            retries=self.retries,
            refresh_margin=self.refresh_margin,
            max_wait=self.max_wait,
        )


@dataclass(frozen=True)
class TokenResponse:
    """Represent a token issued by the broker.

    Attributes:
        token: Issued token credential.
        token_type: Issued token type, `session` or `rest`.
        scope: Broker scope authorized for the token.
        site_url: Base URL of the SG site.
        expires_at: Broker refresh deadline. For REST tokens it is derived from
            SG's reported lifetime with a safety margin; for sessions it is an
            advisory reuse deadline, not an SG expiration.
    """

    token: str = field(repr=False)
    token_type: str
    scope: str
    site_url: str
    expires_at: datetime.datetime


class BrokerClient:
    """Fetches and locally caches SG tokens from the broker service.

    Concurrent callers for one scope and token type share requests. Each
    instance retains its own cache and recent SG rejection reports.
    """

    def __init__(  # noqa: PLR0913 - public keyword-only tuning matches UserTokenClient
        self,
        broker_url: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        retries: int | None = DEFAULT_RETRIES,
        refresh_margin: float = DEFAULT_REFRESH_MARGIN_SECONDS,
        max_wait: float = DEFAULT_MAX_WAIT_SECONDS,
        session: requests.Session | None = None,
    ) -> None:
        """Configure broker access, credentials, and retry behavior.

        Args:
            broker_url: Broker base URL. Defaults to `$SG_TOKEN_BROKER_URL`.
            client_id: Client identifier. Defaults to
                `$SG_TOKEN_BROKER_CLIENT_ID`.
            client_secret: Client secret. Defaults to
                `$SG_TOKEN_BROKER_CLIENT_SECRET`.
            timeout: Seconds allowed to connect and for each wait for response
                data.
            retries: Maximum retries after the first broker request. Zero
                allows one request. With `None`, only the time budget limits
                retries.
            refresh_margin: Seconds before the broker deadline to begin
                renewal, with additional jitter to spread requests.
            max_wait: Seconds available to start requests, including time spent
                waiting for another caller. An in-flight request may finish
                later.
            session: Optional preconfigured Requests session. Defaults to a new
                session.

        Raises:
            BrokerClientError: If any setting is missing, credential text is
                invalid, or the broker URL is malformed, unsupported, or
                insecure.
            ValueError: If timeout or max_wait is non-finite or non-positive,
                retries is neither None nor a non-negative integer, or
                refresh_margin is non-finite or negative.
        """
        options = ClientOptions(
            timeout=timeout, retries=retries, refresh_margin=refresh_margin, max_wait=max_wait
        )
        self._acquirer = KeyAcquirer(
            settings=resolve_client_settings(broker_url, client_id, client_secret),
            options=options,
            session=session if session is not None else requests.Session(),
        )

    def fetch_token(
        self,
        scope: str,
        token_type: str = _SESSION_TYPE,
        *,
        rejected_token: str | None = None,
        force_refresh: bool = False,
    ) -> TokenResponse:
        """Return a token for the scope, fetching from the broker as needed.

        Args:
            scope: Broker scope name (e.g. `read_all`).
            token_type: `session` (default) or `rest`.
            rejected_token: Token SG rejected. Report its digest even if this
                instance already holds a different token for the key.
            force_refresh: Discard the local token and request again. The
                broker may return the same token.

        Returns:
            The cached or newly fetched token. During a temporary outage,
            sessions remain usable past their advisory deadline. REST tokens
            can be reused only before their expiry.

        Raises:
            BrokerClientError: If the broker refuses the request, returns an
                invalid response, or no token is available within the caller's
                budget and request allowance.
        """
        return self._acquirer.fetch(
            scope,
            token_type,
            rejected_tokens=() if rejected_token is None else (rejected_token,),
            force_refresh=force_refresh,
        )


def _matches(token: TokenResponse, digests: Collection[str]) -> bool:
    """Check the full token digest against a rejection history."""
    if not digests:
        return False
    digest = hashlib.sha256(token.token.encode()).hexdigest()
    return any(hmac.compare_digest(digest, other) for other in digests)


def _request_error(
    status: int | None, code: str | None, message: str, retry_after: float | None
) -> Exception:
    """Classify the transport or service failure before scheduling retries."""
    if decide(status, code) == 'retry':
        return _TransientError(message, retry_after)
    return BrokerClientError(message)


def _response_error(response: requests.Response) -> Exception:
    """Extract the service's error message, classification and retry delay."""
    try:
        body: object = response.json()
    except ValueError:
        body = None
    fields = cast('dict[str, object]', body) if isinstance(body, dict) else {}
    detail = str(fields.get('detail', ''))
    code = fields.get('error')
    status = response.status_code
    if status >= HTTPStatus.INTERNAL_SERVER_ERROR:
        message = f'broker request failed with HTTP {status}'
        if detail:
            message += f': {detail}'
    else:
        message = f'broker refused (HTTP {status}): {detail}'
    retry_after = parse_retry_after(
        response.headers.get('Retry-After'), datetime.datetime.now(datetime.UTC)
    )
    return _request_error(status, code if isinstance(code, str) else None, message, retry_after)


def _usable(token: TokenResponse, now: datetime.datetime) -> bool:
    """Accept a session's advisory deadline or an unexpired REST token."""
    return token.token_type == _SESSION_TYPE or now < token.expires_at


def fetch_token(scope: str, token_type: str = _SESSION_TYPE) -> TokenResponse:
    """Fetch a broker token using settings from the environment.

    Args:
        scope: Broker scope name.
        token_type: `session` (default) or `rest`.

    Returns:
        The token returned by a new `BrokerClient`. The broker may reuse a
        cached token without probing its current SG acceptance.

    Raises:
        BrokerClientError: If settings are missing or invalid, the broker is
            unreachable or refuses, or its response is malformed or mismatched.
    """
    return BrokerClient().fetch_token(scope, token_type)


@dataclass(frozen=True)
class _ClientSettings:
    """Hold the validated broker endpoint and credentials for one client identity."""

    broker_url: str
    client_id: str
    client_secret: str = field(repr=False)


@dataclass(eq=False)
class _Call:
    """One caller's budget, personal request count and published outcome."""

    budget: Budget
    attempts: int = 0
    last_failure: str | None = None
    outcome: TokenResponse | BaseException | None = None


@dataclass
class _Key:
    """Cache, dispatch schedule and ordered callers protected by one condition."""

    references: int = 0
    condition: threading.Condition = field(default_factory=threading.Condition)
    cached: TokenResponse | None = None
    refresh_at: datetime.datetime | None = None
    permitted_at: float = -math.inf
    from_header: bool = False
    history: dict[str, float] = field(default_factory=dict[str, float])
    callers: list[_Call] = field(default_factory=list[_Call])
    sent: tuple[str, ...] | None = None

    def finish(self, outcome: TokenResponse | BaseException) -> None:
        """Publish a token or failure to all enrolled callers and clear their enrollment."""
        for call in self.callers:
            call.outcome = outcome
        self.callers.clear()

    def prune_history(self, now: float) -> None:
        """Expire rejection reports while holding the key lock.

        Args:
            now: Current monotonic timestamp in seconds.
        """
        self.history = {digest: end for digest, end in self.history.items() if now < end}

    def report(self, tokens: Sequence[str], now: float) -> None:
        """Remember reported rejections and discard a matching cached token.

        Args:
            tokens: Rejected token values in reporting order, most recent last.
                Retain at most eight distinct digests for 24 hours after
                reporting.
            now: Current monotonic timestamp in seconds.
        """
        self.prune_history(now)
        for token in tokens:
            digest = hashlib.sha256(token.encode()).hexdigest()
            self.history.pop(digest, None)
            self.history[digest] = now + _HISTORY_SECONDS
            if len(self.history) > _HISTORY_LIMIT:
                del self.history[next(iter(self.history))]
        if self.cached is not None and _matches(self.cached, self.history):
            self.cached = None

    def usable(self, now: datetime.datetime) -> TokenResponse | None:
        """Return a retained session or a REST token still before its expiry."""
        if self.cached and _usable(self.cached, now):
            return self.cached
        return None


class KeyAcquirer:
    """Coordinate token requests, rejection reports and renewals for a broker client."""

    def __init__(
        self,
        *,
        settings: _ClientSettings,
        options: ClientOptions,
        session: requests.Session,
        timing: RetryTiming | None = None,
    ) -> None:
        """Start an empty cache for one broker and client identity.

        Args:
            settings: Validated broker URL and client credentials.
            options: Per-attempt timeout, retry limits and refresh margin.
            session: Transport used for all broker requests.
            timing: Optional source of monotonic time, waits and scheduling
                jitter.
        """
        self._settings = settings
        self._options = options
        self._session = session
        self._timing = timing if timing is not None else RetryTiming()
        self._lock = threading.Lock()
        self._keys: dict[tuple[str, str], _Key] = {}
        self._retirements: list[tuple[float, tuple[str, str]]] = []
        self._scheduled: set[tuple[str, str]] = set()

    def _failure(self, error: AcquisitionFailureError, call: _Call) -> BrokerClientError:
        """Describe the applicable stopping rule without exposing credentials."""
        return BrokerClientError(
            error.describe(
                attempts=call.attempts,
                retries=self._options.retries,
                max_wait=self._options.max_wait,
            )
        )

    def _limit(self, key: _Key, call: _Call, now: float) -> AcquisitionFailureError | None:
        """Decide whether this caller may participate in another request."""
        retries = self._options.retries
        if retries is not None and call.attempts > retries:
            return AcquisitionFailureError('attempts', call.last_failure)
        if key.permitted_at > now and not call.budget.can_start(key.permitted_at):
            return AcquisitionFailureError(
                'budget',
                call.last_failure,
                key.permitted_at - now,
                retry_after_from='broker' if key.from_header else None,
            )
        if not call.budget.can_start(now):
            return AcquisitionFailureError('budget', call.last_failure)
        return None

    def _handoff(
        self, key: _Key, call: _Call, outcome: TokenResponse, now: float
    ) -> TokenResponse | None:
        """Deliver a usable outcome or rejoin recovery within the caller's allowance."""
        if key.history:
            key.prune_history(now)
        if _matches(outcome, key.history):
            call.last_failure = _INVALIDATED
        elif _usable(outcome, datetime.datetime.now(datetime.UTC)):
            return outcome
        else:
            call.last_failure = EXPIRED_REST
        replacement = key.usable(datetime.datetime.now(datetime.UTC))
        if replacement is not None:
            return replacement
        failure = self._limit(key, call, now)
        if failure is not None:
            raise self._failure(failure, call)
        call.outcome = None
        key.callers.append(call)
        return None

    @staticmethod
    def _parse(body: object, scope: str, token_type: str) -> TokenResponse:
        """Build a `TokenResponse` from the broker's JSON body."""
        if not isinstance(body, dict):
            raise BrokerClientError('malformed broker response')
        fields = cast('dict[str, object]', body)
        values: dict[str, str] = {}
        for name in ('token', 'token_type', 'scope', 'site_url', 'expires_at'):
            value = fields.get(name)
            if not isinstance(value, str) or not value:
                raise BrokerClientError(f'malformed broker response: bad {name}')
            values[name] = value
        try:
            expires_at = datetime.datetime.fromisoformat(values['expires_at'])
        except ValueError as exc:
            raise BrokerClientError('malformed broker response: bad expires_at') from exc
        if expires_at.tzinfo is None or expires_at.tzinfo.utcoffset(expires_at) is None:
            raise BrokerClientError('malformed broker response: naive expires_at')
        if values['scope'] != scope:
            raise BrokerClientError('broker response scope does not match the request')
        if values['token_type'] != token_type:
            raise BrokerClientError('broker response token_type does not match the request')
        return TokenResponse(
            token=values['token'],
            token_type=values['token_type'],
            scope=values['scope'],
            site_url=values['site_url'],
            expires_at=expires_at,
        )

    def _request(self, scope: str, token_type: str, sent: tuple[str, ...]) -> TokenResponse:
        """Dispatch one request with its immutable rejection snapshot."""
        payload: dict[str, str | list[str]] = {'scope': scope, 'token_type': token_type}
        if sent:
            payload['rejected_tokens_sha256'] = list(sent)
        try:
            response = self._session.post(
                f'{self._settings.broker_url}/v1/token',
                allow_redirects=False,
                hooks=redirect_hooks(self._session, 'broker URL', self._settings.client_secret),
                json=payload,
                auth=(self._settings.client_id, self._settings.client_secret),
                timeout=self._options.timeout,
            )
        except ValueError:
            # Requests parses Location to prepare Response.next even with redirects disabled.
            raise BrokerClientError(
                'invalid request or redirect URL; configure the final broker URL'
            ) from None
        except EndpointRedirectError as exc:
            raise BrokerClientError(str(exc)) from None
        except requests.RequestException as exc:
            origin = endpoint_origin(self._settings.broker_url)
            message = f'cannot reach broker at {origin}: {type(exc).__name__}'
            raise _request_error(None, None, message, None) from None
        except OSError as exc:
            detail = local_send_detail(exc, self._session.verify)
            raise BrokerClientError(f'broker request could not be sent: {detail}') from None
        if HTTPStatus.MULTIPLE_CHOICES <= response.status_code < HTTPStatus.BAD_REQUEST:
            raise BrokerClientError(
                redirect_error(response, 'broker URL', self._settings.client_secret)
            )
        if response.status_code != HTTPStatus.OK:
            raise _response_error(response)
        try:
            body: object = response.json()
        except ValueError as exc:
            raise BrokerClientError('broker returned 200 with a non-JSON body') from exc
        return self._parse(body, scope, token_type)

    def _retire_idle(self, identity: tuple[str, str], key: _Key, now: float) -> None:
        """Under the registry lock, retire an idle entry or schedule its next inspection."""
        if key.references:
            return
        key.cached = key.usable(datetime.datetime.now(datetime.UTC))
        if key.cached is not None:
            return
        deadline = max(key.permitted_at, max(key.history.values(), default=-math.inf))
        if deadline <= now:
            del self._keys[identity]
        elif identity not in self._scheduled:
            heapq.heappush(self._retirements, (deadline, identity))
            self._scheduled.add(identity)

    def _retain_key(self, identity: tuple[str, str]) -> _Key:
        """Pin an entry for enrollment and reclaim idle failures whose deadlines passed."""
        with self._lock:
            now = self._timing.clock()
            while self._retirements and self._retirements[0][0] <= now:
                _, due = heapq.heappop(self._retirements)
                self._scheduled.remove(due)
                existing = self._keys.get(due)
                if existing is not None:
                    self._retire_idle(due, existing, now)
            key = self._keys.get(identity)
            if key is None:
                self._keys[identity] = key = _Key()
            key.references += 1
            return key

    def _retire_spent(self, key: _Key, now: float) -> None:
        """Complete callers unable to participate in the next dispatch."""
        eligible: list[_Call] = []
        for call in key.callers:
            failure = self._limit(key, call, now)
            if failure is None:
                eligible.append(call)
            else:
                call.outcome = self._failure(failure, call)
        if len(eligible) < len(key.callers):
            key.callers = eligible
            key.condition.notify_all()

    def _complete_failure(self, key: _Key, error: _TransientError, attempt: int) -> None:
        """Schedule the next request and grant any usable fallback at completion."""
        now = self._timing.clock()
        delay = (
            renewal_delay(error.retry_after, rng=self._timing.rng)
            if key.cached is not None
            else cold_delay(attempt, error.retry_after, rng=self._timing.rng)
        )
        key.refresh_at = None
        key.permitted_at = now + delay
        key.from_header = error.retry_after is not None
        usable = key.usable(datetime.datetime.now(datetime.UTC))
        if usable is not None:
            key.finish(usable)
        else:
            for call in key.callers:
                call.last_failure = str(error)
            self._retire_spent(key, now)

    def _complete_token(
        self, key: _Key, fresh: TokenResponse, sent: tuple[str, ...], attempt: int
    ) -> None:
        """Compare the sent and current histories before publishing or following up."""
        now = self._timing.clock()
        key.prune_history(now)
        if _matches(fresh, sent):
            key.finish(BrokerClientError(_OLD_BROKER))
        elif _matches(fresh, key.history):
            for call in key.callers:
                call.last_failure = _INVALIDATED
            self._retire_spent(key, now)
        else:
            received = datetime.datetime.now(datetime.UTC)
            if not _usable(fresh, received):
                self._complete_failure(key, _TransientError(EXPIRED_REST, None), attempt)
                return
            if key.cached and (key.cached.token, key.cached.expires_at) == (
                fresh.token,
                fresh.expires_at,
            ):
                key.permitted_at = now + renewal_delay(None, rng=self._timing.rng)
                key.refresh_at = None
            else:
                key.permitted_at = -math.inf
                key.refresh_at = first_refresh_time(
                    fresh.expires_at, received, self._options.refresh_margin, rng=self._timing.rng
                )
            key.from_header = False
            key.cached = fresh
            key.finish(fresh)

    def _dispatch(
        self, key: _Key, identity: tuple[str, str], sent: tuple[str, ...], attempt: int
    ) -> None:
        """Run one HTTP attempt outside the lock and publish its outcome under the lock."""
        try:
            try:
                response = self._request(*identity, sent)
            except _TransientError as exc:
                response = exc
            with key.condition:
                if isinstance(response, _TransientError):
                    self._complete_failure(key, response, attempt)
                else:
                    self._complete_token(key, response, sent, attempt)
                key.sent = None
                key.condition.notify_all()
        except BaseException as exc:
            with key.condition:
                key.finish(exc)
                key.sent = None
                key.condition.notify_all()
            raise

    def _acquire(self, key: _Key, identity: tuple[str, str], call: _Call) -> TokenResponse:
        """Serve the queue in arrival order, spending allowance only for the actual sender."""
        while True:
            with key.condition:
                if isinstance(call.outcome, BaseException):
                    raise BrokerClientError(str(call.outcome)) from call.outcome
                if call.outcome is not None:
                    return call.outcome
                if key.sent is not None:
                    key.condition.wait()
                    continue
                now = self._timing.clock()
                failure = self._limit(key, call, now)
                if failure is not None:
                    raise self._failure(failure, call)
                if key.callers[0] is not call:
                    key.condition.wait()
                    continue
                delay = key.permitted_at - now
                sent = None
                if delay <= 0:
                    key.cached = key.usable(datetime.datetime.now(datetime.UTC))
                    key.prune_history(now)
                    self._retire_spent(key, now)
                    key.sent = sent = tuple(key.history)
                    call.attempts += 1
            if sent is None:
                self._timing.sleep(delay)
            else:
                self._dispatch(key, identity, sent, call.attempts - 1)

    def _fetch(
        self,
        key: _Key,
        identity: tuple[str, str],
        call: _Call,
        rejected_tokens: Sequence[str],
        *,
        force_refresh: bool,
    ) -> TokenResponse:
        """Enroll a caller with the current rejection history and wait for its result."""
        with key.condition:
            now = self._timing.clock()
            if rejected_tokens:
                key.report(rejected_tokens, now)
            if force_refresh:
                key.cached = None
            if not rejected_tokens and not force_refresh:
                wall = datetime.datetime.now(datetime.UTC)
                cached = key.usable(wall)
                if cached and (
                    now < key.permitted_at or (key.refresh_at and wall < key.refresh_at)
                ):
                    return cached
            key.callers.append(call)
        return self._acquire(key, identity, call)

    def fetch(
        self,
        scope: str,
        token_type: str,
        *,
        rejected_tokens: Sequence[str] = (),
        force_refresh: bool = False,
    ) -> TokenResponse:
        """Fetch or reuse a token, coordinating with concurrent callers for the same key.

        Args:
            scope: Broker scope name.
            token_type: Requested session or REST token.
            rejected_tokens: Tokens SG refused. Their digests accompany the
                next request.
            force_refresh: Discard the cached token before requesting another.

        Raises:
            BrokerClientError: If the request fails permanently, the service
                ignores a rejection, or the acquisition exhausts the caller's
                allowance or budget.
        """
        call = _Call(Budget(self._options.max_wait, self._timing.clock))
        identity = (scope, token_type)
        key = self._retain_key(identity)
        try:
            candidate = self._fetch(
                key, identity, call, rejected_tokens, force_refresh=force_refresh
            )
            while True:
                with key.condition, self._lock:
                    now = self._timing.clock()
                    ready = self._handoff(key, call, candidate, now)
                    if ready is not None:
                        key.references -= 1
                        self._retire_idle(identity, key, now)
                        return ready
                candidate = self._acquire(key, identity, call)
        except BaseException:
            with key.condition, self._lock:
                if call in key.callers:
                    key.callers.remove(call)
                    key.condition.notify_all()
                key.references -= 1
                self._retire_idle(identity, key, self._timing.clock())
            raise


class EndpointRedirectError(requests.RequestException):
    """A token endpoint returned a redirect before its response body was read."""


def redirect_error(response: requests.Response, setting: str, credential: str) -> str:
    """Describe a redirect using a printable destination origin when safe.

    Args:
        response: Redirect response supplying the status, request URL and
            location.
        setting: Setting the caller should point at the final endpoint.
        credential: Value whose presence in the destination authority
            suppresses the origin.
    """
    location = response.headers.get('Location')
    destination = ''
    if location:
        try:
            origin = endpoint_origin(urljoin(response.url, location))
            if origin and credential.lower() not in origin.partition('://')[2].lower():
                destination = f' to {origin}'
        except ValueError:
            pass
    return (
        f'HTTP {response.status_code} redirect{destination}; '
        f'configure the {setting} for the final endpoint'
    )


def redirect_hooks(
    session: requests.Session, setting: str, credential: str
) -> dict[str, list[Callable[..., object]]]:
    """Build per-request response hooks that reject redirects before normal session hooks.

    Args:
        session: Session whose existing response hooks should follow the guard.
        setting: Endpoint setting named in the repair message.
        credential: Value to exclude from the diagnostic destination.

    Returns:
        A Requests hook mapping. Its first response hook attempts to close a
        3xx response and raises `EndpointRedirectError`.
    """

    def reject(response: requests.Response, **_kwargs: object) -> None:
        if HTTPStatus.MULTIPLE_CHOICES <= response.status_code < HTTPStatus.BAD_REQUEST:
            message = redirect_error(response, setting, credential)
            with suppress(OSError):
                response.close()
            raise EndpointRedirectError(message, response=response)

    existing = (
        session.hooks.get('response', [])
        if isinstance(getattr(session, 'hooks', None), dict)
        else []
    )
    return {'response': [reject, *existing]}


def resolve_client_settings(
    broker_url: str | None, client_id: str | None, client_secret: str | None
) -> _ClientSettings:
    """Resolve and validate broker connection settings.

    Args:
        broker_url: Broker base URL, defaulting to SG_TOKEN_BROKER_URL.
        client_id: Client identifier, defaulting to SG_TOKEN_BROKER_CLIENT_ID.
        client_secret: Client secret, defaulting to
            SG_TOKEN_BROKER_CLIENT_SECRET.

    Returns:
        The normalized URL, client identifier and client secret.

    Raises:
        BrokerClientError: If a setting is missing, invalid or insecure.
    """
    broker_url = (broker_url or os.environ.get(f'{_ENV_PREFIX}_URL', '')).rstrip('/')
    client_id = client_id or os.environ.get(f'{_ENV_PREFIX}_CLIENT_ID', '')
    client_secret = client_secret or os.environ.get(f'{_ENV_PREFIX}_CLIENT_SECRET', '')
    if not (broker_url and client_id and client_secret):
        raise BrokerClientError(
            f'broker settings missing; set {_ENV_PREFIX}_URL, {_ENV_PREFIX}_CLIENT_ID, '
            f'and {_ENV_PREFIX}_CLIENT_SECRET or pass them explicitly'
        )
    if not is_client_id(client_id):
        raise BrokerClientError(
            f'client id must be 1..{CLIENT_ID_MAX_CHARS} printable ASCII characters '
            'with no colon or space'
        )
    if not is_credential_text(client_secret):
        raise BrokerClientError('client secret must be non-empty printable ASCII with no spaces')
    try:
        require_https_or_loopback(broker_url, 'broker URL')
    except ValueError as exc:
        raise BrokerClientError(str(exc)) from exc
    return _ClientSettings(broker_url, client_id, client_secret)
