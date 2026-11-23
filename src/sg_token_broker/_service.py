"""Authenticate, authorize, mint, and audit broker token requests."""

import datetime
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from sg_token_broker._admission import SecretVerifier, ServerBusyError, WaitingShare
from sg_token_broker._audit import AuditLogger
from sg_token_broker._config import CLIENT_ID_MAX_CHARS, BrokerConfig, ScopeConfig
from sg_token_broker._issuance import (
    CachedMint,
    IssueOutcome,
    KeyedIssuer,
    MintBudget,
    MintPlan,
    MintRateLimitedError,
    UpstreamFailureError,
)
from sg_token_broker._secrets import (
    SecretError,
    resolve_script_key,
    token_fingerprint,
)
from sg_token_broker._sg import (
    MintedToken,
    SGError,
    SGInvalidResponseError,
)

_REST_CACHE_TTL_SECONDS = 60.0
_REST_EXPIRY_MARGIN_SECONDS = 60
_REST_TYPE = 'rest'
_SESSION_TYPE = 'session'


class BrokerError(Exception):
    """Base class for request-level broker failures.

    Attributes:
        status: HTTP status returned for the failure.
        error: Error code returned in the response body.
        retry_after: Seconds to wait before retrying, if specified.
        reason: Optional audit-reason override for pre-service HTTP denials.
    """

    status = 500
    error = 'internal_error'
    retry_after: float | None = None
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
class _IssuedToken:
    """Represent a token issued to a client."""

    # REST expiry uses SG's reported lifetime with a safety margin. Session
    # expiry is only an advisory reuse deadline, not an SG expiration.

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
        rejected_digests: Full SHA-256 digests of tokens SG rejected for this
            key.
    """

    client_id: str
    client_secret: str = field(repr=False)
    scope: str
    token_type: str = _SESSION_TYPE
    source_ip: str = ''
    request_id: str = ''
    rejected_digests: frozenset[str] = frozenset()


class _ForbiddenError(BrokerError):
    """The authenticated client may not use the requested scope or token type."""

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
        audit: AuditLogger,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Bind policy, minting, caching, and audit collaborators.

        Args:
            config: Validated broker configuration.
            minter: Upstream SG token minter.
            audit: Audit logger.
            clock: Monotonic seconds for admission windows and cache expiry.
        """
        self._config = config
        self._minter = minter
        self._audit = audit
        self._waiting = WaitingShare(24)
        self._verifier = SecretVerifier(
            waiting=self._waiting, work=config.max_secret_hashes, clock=clock
        )
        self._issuer = KeyedIssuer(waiting=self._waiting, budget=MintBudget(clock), clock=clock)

    def _authenticate(self, request: TokenRequest) -> str:
        """Authenticate the presented secret and return its configured credential ID."""
        client = self._config.clients.get(request.client_id)
        credentials = (
            tuple(zip(client.credential_ids, client.secret_hashes, strict=True)) if client else ()
        )
        try:
            matched = self._verifier.verify(request.client_id, credentials, request.client_secret)
        except ServerBusyError as exc:
            raise _ServerBusyError(retry_after=exc.retry_after) from exc
        if matched is not None:
            return matched
        raise InvalidClientError('unknown client or bad secret')

    def _check_policy(self, request: TokenRequest) -> None:
        """Enforce the authenticated client's allowed scopes and token types."""
        client = self._config.clients[request.client_id]
        if request.token_type not in (_SESSION_TYPE, _REST_TYPE):
            raise BadRequestError(f'unknown token_type {request.token_type!r}')
        if request.scope not in client.scopes:
            raise _ForbiddenError(f'scope {request.scope!r} not allowed for this client')
        if request.token_type not in client.token_types:
            raise _ForbiddenError(f'token_type {request.token_type!r} not allowed for this client')

    def _issue(self, request: TokenRequest) -> tuple[_IssuedToken, IssueOutcome]:
        """Reuse or mint a token for an authorized request."""
        scope = self._config.scopes[request.scope]

        session_ttl = float(self._config.session_ttl_seconds)

        def mint(charge: Callable[[], None]) -> CachedMint:
            key = _resolve_scope_key(scope)
            charge()
            if request.token_type == _SESSION_TYPE:
                minted = self._minter.mint_session_token(scope.script_name, key)
            else:
                minted = self._minter.mint_rest_token(scope.script_name, key)
            lifetime = session_ttl
            if minted.expires_in is not None:
                lifetime = minted.expires_in - _REST_EXPIRY_MARGIN_SECONDS
                if lifetime <= 0:
                    raise SGInvalidResponseError('SG token lifetime too short to serve')
            return minted, _utcnow() + datetime.timedelta(seconds=lifetime)

        is_rest = request.token_type == _REST_TYPE
        try:
            (minted, expires_at), outcome = self._issuer.issue(
                (request.client_id, request.scope, request.token_type),
                MintPlan(
                    mint=mint,
                    ttl=_REST_CACHE_TTL_SECONDS if is_rest else session_ttl,
                    still_valid=lambda cached: not is_rest or _utcnow() < cached[1],
                ),
                rate_limit=self._config.clients[request.client_id].rate_limit_per_minute,
                rejected=request.rejected_digests,
            )
        except ServerBusyError as exc:
            raise _ServerBusyError(retry_after=exc.retry_after) from exc
        except MintRateLimitedError as exc:
            raise _RateLimitedError(retry_after=exc.retry_after) from exc
        except UpstreamFailureError as exc:
            raise _upstream_error(exc) from (exc.__cause__ or exc)
        issued = _IssuedToken(
            token=minted.token,
            token_type=request.token_type,
            scope=request.scope,
            site_url=self._config.site_url,
            expires_at=expires_at,
        )
        return issued, outcome

    def issue_token(self, request: TokenRequest) -> _IssuedToken:
        """Issue a token for an authenticated, authorized client request.

        Args:
            request: The parsed token request.

        Returns:
            The issued token.

        Raises:
            BrokerError: A request-level failure, either this base class or a
                subclass, carrying the HTTP status and error code.
        """
        credential = None
        try:
            credential = self._authenticate(request)
            self._check_policy(request)
            issued, outcome = self._issue(request)
        except BrokerError as exc:
            threshold = 500
            extra: dict[str, object] = {}
            if credential is not None:
                extra['credential'] = credential
            if isinstance(exc.__cause__, SGError):
                extra['detail'] = exc.__cause__.audit_detail
            elif isinstance(exc.__cause__, SecretError):
                extra['detail'] = str(exc.__cause__)
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
            credential=credential,
            scope=request.scope,
            token_type=request.token_type,
            token_fp=token_fingerprint(issued.token),
            cache='hit' if outcome in ('hit', 'joined') else 'miss',
            outcome=outcome,
            **({'replaced': True} if outcome == 'replaced' else {}),
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


class _ServerBusyError(BrokerError):
    """Broker capacity is exhausted and the caller may retry shortly."""

    status = 503
    error = 'server_busy'

    def __init__(self, *, retry_after: float) -> None:
        """Report the wait before a caller retries."""
        super().__init__('server busy')
        self.retry_after = retry_after


class _RateLimitedError(BrokerError):
    """The client exceeded its per-minute mint budget."""

    status = 429
    error = 'rate_limited'

    def __init__(self, *, retry_after: float) -> None:
        """Report when the client can spend from its mint budget again."""
        super().__init__('per-client mint rate limit exceeded')
        self.retry_after = retry_after


class _SGRejectedError(BrokerError):
    """SG refused the upstream request."""

    status = 502
    error = 'sg_rejected'


class _InvalidUpstreamResponseError(BrokerError):
    """SG returned a successful response with unusable data."""

    status = 502
    error = 'sg_invalid_response'


class _UpstreamUnavailableError(BrokerError):
    """SG could not complete the request and a later retry may succeed."""

    status = 503
    error = 'upstream_unavailable'


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


def _upstream_error(failure: UpstreamFailureError) -> BrokerError:
    """Choose the service error for the classified SG failure."""
    error_type = {
        'rejected': _SGRejectedError,
        'invalid_response': _InvalidUpstreamResponseError,
        'unavailable': _UpstreamUnavailableError,
    }[failure.kind]
    error = error_type('SG upstream request failed')
    error.retry_after = failure.retry_after
    return error


def _utcnow() -> datetime.datetime:
    """Current UTC time; module-level seam so tests can freeze the clock."""
    return datetime.datetime.now(datetime.UTC)
