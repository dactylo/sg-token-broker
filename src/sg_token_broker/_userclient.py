"""Client for the user-token service: fetch human-bound SG tokens."""

import datetime
import math
import os
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import cast

import requests

from sg_token_broker._urlpolicy import require_https_or_loopback
from sg_token_broker._userauth import (
    SignInError,
    SignInSettingsError,
    decode_unverified_payload,
    default_id_token_source,
)

_ENV_URL = 'SG_USER_TOKEN_URL'
_OK_STATUS = 200
_REFRESH_MARGIN_SECONDS = 60.0
_REQUEST_TIMEOUT_SECONDS = 10.0
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
    """The user-token service could not be reached or refused the request."""


class UserTokenSettingsError(UserTokenClientError):
    """The user-token client settings are missing or invalid."""


class UserTokenClient:
    """Fetch and memory-cache human-bound SG tokens.

    The lock is held across the sign-in and network round trip; concurrent
    callers serialize.
    Accepted tradeoff.
    """

    def __init__(
        self,
        service_url: str | None = None,
        *,
        id_token_source: Callable[[], str] | None = None,
        timeout: float = _REQUEST_TIMEOUT_SECONDS,
        refresh_margin: float = _REFRESH_MARGIN_SECONDS,
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
            timeout: Per-request timeout in seconds. Defaults to `10.0`.
            refresh_margin: Seconds before a REST token's expiry at which it is
                refreshed. Defaults to `60.0`.
            session: Optional preconfigured Requests session. A fresh
                `requests.Session` is created when `None`.

        Raises:
            UserTokenClientError: If the service URL is missing, malformed,
                unsupported, or insecure; if `timeout` is non-finite or not
                greater than zero; or if the default sign-in settings are
                missing or invalid, or OIDC discovery for the default sign-in
                fails.
        """
        self._service_url = (service_url or os.environ.get(_ENV_URL, '')).rstrip('/')
        if not self._service_url:
            raise UserTokenSettingsError(
                f'service URL missing; set {_ENV_URL} or pass it explicitly'
            )
        try:
            require_https_or_loopback(self._service_url, 'user-token service URL')
        except ValueError as exc:
            raise UserTokenSettingsError(str(exc)) from exc
        if not (math.isfinite(timeout) and timeout > 0):
            raise UserTokenSettingsError(
                f'timeout must be finite and greater than zero, got {timeout}'
            )
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

    def _request(self, token_type: str, id_token: str, *, refresh: bool) -> UserToken:
        """GET /v1/user-token and parse the response."""
        params: dict[str, str] = {'token_type': token_type}
        if refresh:
            params['refresh'] = 'true'
        try:
            response = self._session.get(
                f'{self._service_url}/v1/user-token',
                params=params,
                headers={'Authorization': f'Bearer {id_token}'},
                timeout=self._timeout,
            )
        except requests.RequestException as exc:
            raise UserTokenClientError(
                f'cannot reach user-token service at {self._service_url}: {exc.__class__.__name__}'
            ) from exc
        if response.status_code != _OK_STATUS:
            raise UserTokenClientError(f'service refused (HTTP {response.status_code})')
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
        """
        with self._lock:
            if token_type not in _TOKEN_TYPES:
                raise UserTokenClientError(f'unsupported token_type: {token_type!r}')
            id_token, sub = self._current_identity()
            cached = self._cache.get(token_type)
            if cached is not None:
                cached_sub, token = cached
                if cached_sub == sub and not force_refresh and not self._stale(token):
                    return token
                self._cache.pop(token_type, None)
            fresh = self._request(token_type, id_token, refresh=force_refresh)
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
