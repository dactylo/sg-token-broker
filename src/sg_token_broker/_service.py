"""Authenticate, authorize, mint, and audit broker token requests."""

import datetime
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol, TypeAlias

from sg_token_broker._audit import AuditLogger
from sg_token_broker._cache import TTLCache
from sg_token_broker._config import CLIENT_ID_MAX_CHARS, BrokerConfig, ScopeConfig
from sg_token_broker._secrets import (
    SecretError,
    hash_secret,
    resolve_script_key,
    token_fingerprint,
    verify_secret,
)
from sg_token_broker._sg import MintedToken, SGError

# Verified when the client_id is unknown so that unknown and known clients take
# the same scrypt time (no client-id enumeration via timing).
_DUMMY_HASH = hash_secret('timing-equalizer')
_RATE_WINDOW_SECONDS = 60.0
_REST_CACHE_TTL_SECONDS = 60.0
_REST_EXPIRY_MARGIN_SECONDS = 60
_REST_TYPE = 'rest'
_SESSION_TYPE = 'session'
_CachedMint: TypeAlias = tuple[MintedToken, datetime.datetime]


class BrokerError(Exception):
    """Base class for request-level broker failures.

    Attributes:
        status: HTTP status returned for the failure.
        error: Error code returned in the response body.
        reason: Optional audit-reason override for pre-service HTTP denials.
    """

    status = 500
    error = 'internal_error'
    reason: str = ''


class BadRequestError(BrokerError):
    """The request body is malformed or asks for an unknown token type."""

    status = 400
    error = 'bad_request'


class InvalidClientError(BrokerError):
    """Client credentials are missing or wrong (deliberately opaque)."""

    status = 401
    error = 'invalid_client'


@dataclass(frozen=True)
class IssuedToken:
    """Represent a token issued to a client.

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


@dataclass(frozen=True)
class TokenRequest:
    """Represent a token request parsed from the HTTP layer.

    Attributes:
        client_id: Presented broker client identifier.
        client_secret: Presented broker client secret.
        scope: Requested broker scope.
        token_type: Requested token type. Defaults to `session`.
        source_ip: Request source IP address. Defaults to an empty string.
        request_id: Request correlation identifier. Defaults to an empty
            string.
    """

    client_id: str
    client_secret: str = field(repr=False)
    scope: str
    token_type: str = _SESSION_TYPE
    source_ip: str = ''
    request_id: str = ''


class _ForbiddenError(BrokerError):
    """The authenticated client may not use the requested scope."""

    status = 403
    error = 'forbidden'


class _Minter(Protocol):
    """Anything that can mint SG tokens from script credentials."""

    def mint_rest_token(self, script_name: str, script_key: str) -> MintedToken:
        """Mint an SG REST access token.

        Args:
            script_name: ApiUser script name.
            script_key: ApiUser application key.

        Returns:
            The minted token with its SG-reported lifetime.

        Raises:
            SGError: If the upstream token request cannot be completed.
        """
        ...

    def mint_session_token(self, script_name: str, script_key: str) -> MintedToken:
        """Mint an SG session token.

        Args:
            script_name: ApiUser script name.
            script_key: ApiUser application key.

        Returns:
            The minted session token with `expires_in` set to `None`.

        Raises:
            SGError: If the upstream token request cannot be completed.
        """
        ...


class BrokerService:
    """Authenticate clients, enforce policy, and issue SG tokens."""

    def __init__(
        self,
        config: BrokerConfig,
        minter: _Minter,
        cache: TTLCache[_CachedMint],
        audit: AuditLogger,
    ) -> None:
        """Bind policy, minting, caching, and audit collaborators.

        Args:
            config: Validated broker configuration.
            minter: Upstream SG token minter.
            cache: Token cache keyed by client, scope, and token type.
            audit: Audit logger.
        """
        self._config = config
        self._minter = minter
        self._cache = cache
        self._audit = audit
        self._rate_limiter = _RateLimiter()

    def _issue(self, request: TokenRequest) -> tuple[IssuedToken, bool]:
        """Run the authenticate, authorize, mint pipeline."""
        client = self._config.clients.get(request.client_id)
        if client is None:
            verify_secret(request.client_secret, _DUMMY_HASH)
            raise InvalidClientError('unknown client or bad secret')
        if not verify_secret(request.client_secret, client.secret_hash):
            raise InvalidClientError('unknown client or bad secret')
        if not self._rate_limiter._check(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            client.client_id, client.rate_limit_per_minute
        ):
            raise _RateLimitedError('per-client rate limit exceeded')
        if request.token_type not in (_SESSION_TYPE, _REST_TYPE):
            raise BadRequestError(f'unknown token_type {request.token_type!r}')
        if request.scope not in client.scopes:
            raise _ForbiddenError(f'scope {request.scope!r} not allowed for this client')
        scope = self._config.scopes[request.scope]

        session_ttl = float(self._config.session_ttl_seconds)

        def mint() -> _CachedMint:
            key = _resolve_scope_key(scope)
            try:
                if request.token_type == _SESSION_TYPE:
                    minted = self._minter.mint_session_token(scope.script_name, key)
                else:
                    minted = self._minter.mint_rest_token(scope.script_name, key)
            except SGError as exc:
                raise _UpstreamError('SG upstream request failed') from exc
            lifetime = (
                session_ttl
                if minted.expires_in is None
                else max(float(minted.expires_in - _REST_EXPIRY_MARGIN_SECONDS), 1.0)
            )
            return minted, _utcnow() + datetime.timedelta(seconds=lifetime)

        cache_key = (request.client_id, request.scope, request.token_type)
        if request.token_type == _REST_TYPE:
            (minted, expires_at), cache_hit = self._cache.revalidate_or_replace(
                cache_key,
                _REST_CACHE_TTL_SECONDS,
                lambda cached: _utcnow() < cached[1],
                mint,
            )
        else:
            (minted, expires_at), cache_hit = self._cache.get_or_create(
                cache_key, session_ttl, mint
            )
        issued = IssuedToken(
            token=minted.token,
            token_type=request.token_type,
            scope=request.scope,
            site_url=self._config.site_url,
            expires_at=expires_at,
        )
        return issued, cache_hit

    def issue_token(self, request: TokenRequest) -> IssuedToken:
        """Issue a token for an authenticated, authorized client request.

        Args:
            request: The parsed token request.

        Returns:
            The issued token.

        Raises:
            BrokerError: A request-level failure, either this base class or a
                subclass, carrying the HTTP status and error code.
        """
        try:
            issued, cache_hit = self._issue(request)
        except BrokerError as exc:
            threshold = 500
            extra: dict[str, object] = {}
            if isinstance(exc, _UpstreamError):
                extra['detail'] = str(exc.__cause__ or exc)
            self._audit.log(
                'deny' if exc.status < threshold else 'error',
                **_audit_client_id(request.client_id),
                **extra,
                scope=request.scope if request.scope in self._config.scopes else 'invalid',
                token_type=(
                    request.token_type
                    if request.token_type in (_SESSION_TYPE, _REST_TYPE)
                    else 'invalid'
                ),
                source_ip=request.source_ip,
                request_id=request.request_id,
                reason=exc.error,
            )
            raise
        self._audit.log(
            'issue',
            client_id=request.client_id,
            scope=request.scope,
            token_type=request.token_type,
            token_fp=token_fingerprint(issued.token),
            cache='hit' if cache_hit else 'miss',
            source_ip=request.source_ip,
            request_id=request.request_id,
        )
        return issued

    def log_denied_request(self, *, reason: str, source_ip: str, request_id: str) -> None:
        """Audit a request the HTTP layer denied before reaching the service.

        Args:
            reason: Fixed denial reason from the HTTP layer's closed set.
            source_ip: TCP source address for the request.
            request_id: Correlation id generated by the HTTP layer.
        """
        self._audit.log('deny', reason=reason, source_ip=source_ip, request_id=request_id)

    def log_unhandled(
        self,
        *,
        source_ip: str,
        request_id: str,
        exc: BaseException,
    ) -> None:
        """Audit an unexpected failure answered by the HTTP layer.

        Args:
            source_ip: TCP source address for the request.
            request_id: Correlation id generated by the HTTP layer.
            exc: Unhandled exception; only its class name is recorded.
        """
        self._audit.log(
            'error',
            reason='internal_error',
            detail=exc.__class__.__name__,
            source_ip=source_ip,
            request_id=request_id,
        )


class _RateLimitedError(BrokerError):
    """The client exceeded its per-minute request budget."""

    status = 429
    error = 'rate_limited'


class _RateLimiter:
    """Fixed-window per-client rate limiter."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        """Start with no recorded requests using the selected clock."""
        self._clock = clock
        self._lock = threading.Lock()
        self._windows: dict[str, tuple[float, int]] = {}

    def _check(self, client_id: str, limit: int) -> bool:
        """Record one request; return False if the budget is exhausted."""
        now = self._clock()
        with self._lock:
            start, count = self._windows.get(client_id, (now, 0))
            if now - start >= _RATE_WINDOW_SECONDS:
                start, count = now, 0
            if count >= limit:
                self._windows[client_id] = (start, count)
                return False
            self._windows[client_id] = (start, count + 1)
            return True


class _UpstreamError(BrokerError):
    """SG itself failed; details are logged server-side only."""

    status = 502
    error = 'upstream_error'


def _audit_client_id(client_id: str) -> dict[str, object]:
    """Bound a caller-supplied client id for the audit log."""
    if len(client_id) <= CLIENT_ID_MAX_CHARS:
        return {'client_id': client_id}
    return {
        'client_id': client_id[:CLIENT_ID_MAX_CHARS],
        'client_id_truncated': True,
    }


def _resolve_scope_key(scope: ScopeConfig) -> str:
    """Resolve a scope's script key behind the broker error boundary."""
    try:
        return resolve_script_key(env=scope.script_key_env, file=scope.script_key_file)
    except SecretError as exc:
        raise BrokerError('internal error') from exc


def _utcnow() -> datetime.datetime:
    """Current UTC time; module-level seam so tests can freeze the clock."""
    return datetime.datetime.now(datetime.UTC)
