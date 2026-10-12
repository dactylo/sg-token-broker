"""Framework-free user-token core for REST and session minting."""

import datetime
from dataclasses import dataclass, field
from typing import Protocol, TypeAlias

from sg_token_broker._audit import AuditLogger
from sg_token_broker._cache import TTLCache
from sg_token_broker._gclaims import ClaimsError, VerifiedClaims
from sg_token_broker._secrets import token_fingerprint
from sg_token_broker._sg import MintedToken, SGError
from sg_token_broker._users import UnknownUserError, UserDirectory, UserLookupError

_DEFAULT_EXPIRES_IN = 600
_ERR_AUTH_CODE = 102
_MINTER_FAULT_MARKERS = ("does not have permission to 'sudo'", "can't authenticate script")
_REST_EXPIRY_MARGIN_SECONDS = 30
_REST_TYPE = 'rest'
_SERVER_ERROR_STATUS = 500
_SESSION_TYPE = 'session'
_TARGET_REFUSAL_MARKERS = ("cannot 'sudo'", 'cannot sudo as')
_TOKEN_CACHE_TTL_SECONDS = 120.0

_CachedMint: TypeAlias = tuple[MintedToken, datetime.datetime]


class ClaimsPolicy(Protocol):
    """Anything that validates an Authorization header into verified claims."""

    def validate(self, authorization: str) -> VerifiedClaims:
        """Validate the header and return verified claims.

        Args:
            authorization: Raw Authorization header value.

        Returns:
            The verified claims.

        Raises:
            ClaimsError: If the presented identity is missing, invalid, or
                disallowed. Provider failures must propagate separately.
        """
        ...


@dataclass(frozen=True)
class IssuedUserToken:
    """Represent a user-bound SG token ready for JSON serialization.

    `expires_at` is `None` for session tokens: a session has no scheduled
    expiry (SG's sliding inactivity window governs). `cache_until` is the
    service's caching hint: equal to `expires_at` for REST tokens, and the
    same-token horizon for sessions.

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


@dataclass(frozen=True)
class ServiceAccount:
    """Represent the sudo-capable service ApiUser and its SG site.

    Args:
        _site_url: Base URL of the SG site.
        _script_name: Service ApiUser script name.
        _script_key: Service ApiUser application key.
    """

    _site_url: str
    _script_name: str
    _script_key: str = field(repr=False)


class UserTokenError(Exception):
    """Base class for request-level user-token failures.

    Attributes:
        status: HTTP status returned for the failure.
        error: Error code returned in the response body.
    """

    status = 500
    error = 'internal_error'


@dataclass(frozen=True)
class UserTokenRequest:
    """Represent a raw user-token request received from the HTTP layer.

    Attributes:
        authorization: Raw Authorization header value.
        source_ip: Audited source address. Defaults to an empty string.
        request_id: Request correlation identifier. Defaults to an empty
            string.
        token_type: Requested token type. Defaults to `rest`.
        refresh: Whether to validate a cached session before serving it.
            Defaults to `False`.
    """

    authorization: str = field(repr=False)
    source_ip: str = ''
    request_id: str = ''
    token_type: str = _REST_TYPE
    refresh: bool = False


class _BadRequestError(UserTokenError):
    """The request asked for an unknown token type."""

    status = 400
    error = 'bad_request'


class _ForbiddenError(UserTokenError):
    """A token type is disallowed or SG lookup or minting refuses the user."""

    status = 403
    error = 'forbidden'


class _SudoMinter(Protocol):
    """Anything that can mint and probe SG tokens with script credentials."""

    def check_session_token(self, session_token: str) -> bool:
        """Return whether SG still accepts the session token.

        Args:
            session_token: SG session token to probe.

        Returns:
            True for acceptance and False for an explicit authentication
            rejection.

        Raises:
            SGError: If the probe fails or its response is inconclusive;
                these failures must not be reported as False.
        """
        ...

    def mint_rest_token(
        self, script_name: str, script_key: str, *, scope: str | None = None
    ) -> MintedToken:
        """Mint an SG REST access token, optionally sudo-scoped.

        Args:
            script_name: ApiUser script name.
            script_key: ApiUser application key.
            scope: Optional SG scope string, such as `sudo_as_login:<login>`;
                not a bare login.

        Returns:
            The minted token with its SG-reported lifetime.

        Raises:
            SGError: If the upstream token request cannot be completed.
        """
        ...

    def mint_session_token(
        self, script_name: str, script_key: str, *, sudo_login: str | None = None
    ) -> MintedToken:
        """Mint an SG session token, optionally bound to a HumanUser.

        Args:
            script_name: ApiUser script name.
            script_key: ApiUser application key.
            sudo_login: Optional SG login to bind to the session.

        Returns:
            The minted session token with `expires_in` set to `None`.

        Raises:
            SGError: If the upstream token request cannot be completed.
        """
        ...


class _UnauthorizedError(UserTokenError):
    """The identity token is missing, invalid, or not allowed."""

    status = 401
    error = 'unauthorized'


class _UpstreamError(UserTokenError):
    """SG itself failed; details are logged server-side only."""

    status = 502
    error = 'upstream_error'


class UserTokenService:
    """Exchange verified identities for user-bound SG tokens."""

    def __init__(  # noqa: PLR0913 - constructor interface mandated by the approved design
        self,
        account: ServiceAccount,
        claims: ClaimsPolicy,
        directory: UserDirectory,
        minter: _SudoMinter,
        audit: AuditLogger,
        *,
        token_types: frozenset[str] = frozenset({_REST_TYPE}),
        session_ttl_seconds: int = 600,
    ) -> None:
        """Bind identity policy and token-issuance collaborators.

        Args:
            account: Sudo-capable service ApiUser and its SG site.
            claims: Identity-token claims policy.
            directory: Email-to-login resolver.
            minter: Upstream SG token minter.
            audit: Audit logger.
            token_types: Token types this deployment may issue. Defaults to
                `rest` only.
            session_ttl_seconds: Maximum service-cache lifetime for sessions.
                Defaults to `600`.
        """
        self._site_url = account._site_url.rstrip('/')  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        self._script_name = account._script_name  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        self._script_key = account._script_key  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        self._claims = claims
        self._directory = directory
        self._minter = minter
        self._cache: TTLCache[_CachedMint] = TTLCache()
        self._audit = audit
        self._token_types = token_types
        self._session_ttl = float(session_ttl_seconds)

    def _log_denied(
        self, claims: VerifiedClaims, request: UserTokenRequest, exc: UserTokenError
    ) -> None:
        """Audit a post-authentication denial or upstream error."""
        self._audit.log(
            'deny' if exc.status < _SERVER_ERROR_STATUS else 'error',
            email=claims.email,
            aud=claims.audience,
            reason=exc.error,
            detail=str(exc.__cause__ or exc),
            source_ip=request.source_ip,
            request_id=request.request_id,
            token_type=_audit_token_type(request.token_type),
        )

    def _mint_rest(self, login: str) -> tuple[IssuedUserToken, str]:
        """Mint or serve the cached REST token for `login`."""

        def mint() -> _CachedMint:
            try:
                minted = self._minter.mint_rest_token(
                    self._script_name, self._script_key, scope=f'sudo_as_login:{login}'
                )
            except SGError as exc:
                raise _map_mint_error(exc) from exc
            expires_in = _DEFAULT_EXPIRES_IN if minted.expires_in is None else minted.expires_in
            lifetime = expires_in - _REST_EXPIRY_MARGIN_SECONDS
            if lifetime <= _TOKEN_CACHE_TTL_SECONDS:
                raise _UpstreamError('SG token lifetime too short to serve')
            return minted, _utcnow() + datetime.timedelta(seconds=float(lifetime))

        (minted, expires_at), cache_hit = self._cache.get_or_create(
            (login, _REST_TYPE), _TOKEN_CACHE_TTL_SECONDS, mint
        )
        issued = IssuedUserToken(
            token=minted.token,
            token_type=_REST_TYPE,
            login=login,
            site_url=self._site_url,
            expires_at=expires_at,
            cache_until=expires_at,
        )
        return issued, 'hit' if cache_hit else 'miss'

    def _mint_session(self, login: str, *, refresh: bool) -> tuple[IssuedUserToken, str]:
        """Mint, serve, or SG-verify-and-replace the session token for `login`."""

        def mint() -> _CachedMint:
            try:
                minted = self._minter.mint_session_token(
                    self._script_name, self._script_key, sudo_login=login
                )
            except SGError as exc:
                raise _map_mint_error(exc) from exc
            return minted, _utcnow() + datetime.timedelta(seconds=self._session_ttl)

        def alive(entry: _CachedMint) -> bool:
            try:
                return self._minter.check_session_token(entry[0].token)
            except SGError as exc:
                raise _UpstreamError('SG upstream request failed') from exc

        if refresh:
            (minted, cache_until), kept = self._cache.revalidate_or_replace(
                (login, _SESSION_TYPE), self._session_ttl, alive, mint
            )
            outcome = 'kept' if kept else 'miss'
        else:
            (minted, cache_until), cache_hit = self._cache.get_or_create(
                (login, _SESSION_TYPE), self._session_ttl, mint
            )
            outcome = 'hit' if cache_hit else 'miss'
        issued = IssuedUserToken(
            token=minted.token,
            token_type=_SESSION_TYPE,
            login=login,
            site_url=self._site_url,
            expires_at=None,
            cache_until=cache_until,
        )
        return issued, outcome

    def _resolve_login(self, email: str) -> str:
        """Resolve the email via the directory, mapping errors to statuses."""
        try:
            return self._directory.resolve_login(email)
        except UnknownUserError as exc:
            raise _ForbiddenError('no active SG user for this identity') from exc
        except UserLookupError as exc:
            raise _UpstreamError('SG upstream request failed') from exc

    def issue_token(self, request: UserTokenRequest) -> IssuedUserToken:
        """Issue a user-bound token for a verified caller.

        Args:
            request: The raw request from the HTTP layer.

        Returns:
            The cached or newly minted token. REST `expires_at` is derived from
            SG's lifetime minus a safety margin. Sessions have
            `expires_at=None` and an advisory `cache_until`. Ordinary cache
            reuse does not probe current SG acceptance.

        Raises:
            UserTokenError: One of the typed subclasses, mapping to an HTTP
                status. Messages stay generic; specifics go to the audit log.
        """
        try:
            claims = self._claims.validate(request.authorization)
        except ClaimsError as exc:
            self._audit.log(
                'deny',
                reason='unauthorized',
                detail=str(exc),
                source_ip=request.source_ip,
                request_id=request.request_id,
                token_type=_audit_token_type(request.token_type),
            )
            raise _UnauthorizedError('identity token rejected') from exc
        if request.token_type not in (_REST_TYPE, _SESSION_TYPE):
            exc = _BadRequestError('unknown token_type')
            self._log_denied(claims, request, exc)
            raise exc
        if request.token_type not in self._token_types:
            exc = _ForbiddenError('token type not allowed for this deployment')
            self._log_denied(claims, request, exc)
            raise exc
        try:
            login = self._resolve_login(claims.email)
            if request.token_type == _SESSION_TYPE:
                issued, cache_outcome = self._mint_session(login, refresh=request.refresh)
            else:
                issued, cache_outcome = self._mint_rest(login)
        except UserTokenError as exc:
            self._log_denied(claims, request, exc)
            raise
        self._audit.log(
            'issue',
            email=claims.email,
            login=issued.login,
            aud=claims.audience,
            token_fp=token_fingerprint(issued.token),
            cache=cache_outcome,
            source_ip=request.source_ip,
            request_id=request.request_id,
            token_type=issued.token_type,
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

    def log_unhandled(self, request: UserTokenRequest, exc: BaseException) -> None:
        """Audit an unexpected failure the HTTP layer answered with an opaque 500.

        Args:
            request: The raw request from the HTTP layer.
            exc: The unhandled exception (only its class name is logged).
        """
        self._audit.log(
            'error',
            reason='internal_error',
            detail=exc.__class__.__name__,
            source_ip=request.source_ip,
            request_id=request.request_id,
            token_type=_audit_token_type(request.token_type),
        )


def _audit_token_type(value: str) -> str:
    """Return a closed-set token type for the audit log."""
    return value if value in (_REST_TYPE, _SESSION_TYPE) else 'invalid'


def _classify_sg_refusal(exc: SGError) -> str:
    """Classify an SG minting failure as `target`, `minter`, or `unknown`."""
    if exc.error_code == _ERR_AUTH_CODE:
        refusal = (exc.rpc_message or '').lower()
    elif exc.status_code in (400, 401):
        refusal = (exc.error_title or '').lower()
    else:
        refusal = ''
    if any(marker in refusal for marker in _MINTER_FAULT_MARKERS):
        return 'minter'
    if any(marker in refusal for marker in _TARGET_REFUSAL_MARKERS):
        return 'target'
    return 'unknown'


def _map_mint_error(exc: SGError) -> UserTokenError:
    """Map an SG minting failure to the caller-visible error class."""
    if _classify_sg_refusal(exc) == 'target':
        return _ForbiddenError('SG refused to issue a token for this user')
    return _UpstreamError('SG upstream request failed')


def _utcnow() -> datetime.datetime:
    """Current UTC time; module-level seam so tests can freeze the clock."""
    return datetime.datetime.now(datetime.UTC)
