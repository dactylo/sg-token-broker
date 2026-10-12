"""Generic OIDC ID-token verification via discovery, JWKS, and PyJWT."""

import importlib
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from typing import Protocol, cast

import requests

from sg_token_broker._gclaims import Verifier
from sg_token_broker._urlpolicy import require_https_or_loopback

ASYMMETRIC_OIDC_ALGORITHMS = frozenset(
    {'ES256', 'ES384', 'ES512', 'EdDSA', 'PS256', 'PS384', 'PS512', 'RS256', 'RS384', 'RS512'}
)
_DISCOVERY_PATH = '/.well-known/openid-configuration'
_HTTP_OK = 200
_JWKS_REFRESH_INTERVAL_SECONDS = 5.0
_REQUEST_TIMEOUT_SECONDS = 10.0


class OidcUnavailableError(Exception):
    """PyJWT is not installed (the 'oidc' extra is missing)."""


class _CooldownClient(Protocol):
    """Optional refresh-cooldown setting exposed by newer PyJWT clients."""

    cooldown_duration: float


class _JwkSetCache(Protocol):
    """PyJWT JWK-set cache operations used by the resolver."""

    def get(self) -> object:
        """Return the cached JWK set, if present.

        Returns:
            The cached value, or None when absent or expired.
        """
        ...

    def put(self, jwk_set: dict[str, object]) -> None:
        """Store the current JWK set.

        Args:
            jwk_set: Provider JWK-set document.
        """
        ...


class _SigningKey(Protocol):
    """Resolved PyJWT signing-key surface used by verification."""

    @property
    def key(self) -> object:
        """Return the cryptographic key material."""
        ...


class _JwkClient(Protocol):
    """PyJWT JWK-client surface used by the resolver."""

    fetch_data: Callable[[], object]
    jwk_set_cache: _JwkSetCache | None

    def get_signing_key(self, kid: str) -> _SigningKey:
        """Return the signing key matching a key id.

        Args:
            kid: Provider key id.

        Returns:
            The matching signing key.
        """
        ...


class _JwtModule(Protocol):
    """PyJWT module surface used by the resolver."""

    PyJWKClientError: type[Exception]
    get_unverified_header: Callable[[str], Mapping[str, object]]


class _OidcTransportError(requests.RequestException):
    """The configured OIDC provider did not serve a required document."""


class _SigningKeyResolver:
    """Resolve signing keys with serialized, cooldown-bounded JWKS refreshes."""

    def __init__(
        self,
        jwk_client: _JwkClient,
        jwt_module: _JwtModule,
        fetch_jwks: Callable[[], dict[str, object]],
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Bind the PyJWT client to cooldown-bounded external refresh."""
        self._clock = clock
        self._fetch_jwks_external = fetch_jwks
        self._jwk_client = jwk_client
        self._jwt_module = jwt_module
        self._last_attempt_at: float | None = None
        self._last_attempt_succeeded: bool | None = None
        self._lock = threading.Lock()
        # PyJWT 2.14 added a second cooldown. Keep refresh timing under this
        # resolver's clock while retaining compatibility with older clients.
        if hasattr(self._jwk_client, 'cooldown_duration'):
            cast('_CooldownClient', self._jwk_client).cooldown_duration = 0.0
        self._jwk_client.fetch_data = self._fetch_jwks

    def __call__(self, presented: str) -> _SigningKey:
        """Return the signing key selected by a presented token's `kid`."""
        kid = self._jwt_module.get_unverified_header(presented).get('kid')
        if not isinstance(kid, str):
            raise self._jwt_module.PyJWKClientError('token header has no string kid')
        with self._lock:
            return self._jwk_client.get_signing_key(kid)

    def _attempt_is_recent(self) -> bool:
        """Return whether the last external attempt is inside the cooldown."""
        return (
            self._last_attempt_at is not None
            and self._clock() - self._last_attempt_at < _JWKS_REFRESH_INTERVAL_SECONDS
        )

    def _fetch_jwks(self) -> object:
        """Fetch once externally or replay the recent attempt classification."""
        if self._attempt_is_recent():
            if self._last_attempt_succeeded is False:
                raise _OidcTransportError('OIDC JWKS refresh failed recently')
            if self._jwk_client.jwk_set_cache is not None:
                jwk_set = self._jwk_client.jwk_set_cache.get()
                if jwk_set is not None:
                    # PyJWT caches either the raw document or a parsed key set,
                    # depending on its version. Replay its own representation.
                    return jwk_set
            raise self._jwt_module.PyJWKClientError('OIDC JWKS refresh is cooling down')
        try:
            jwk_set = self._fetch_jwks_external()
        except requests.RequestException:
            self._last_attempt_at = self._clock()
            self._last_attempt_succeeded = False
            raise
        self._last_attempt_at = self._clock()
        self._last_attempt_succeeded = True
        if self._jwk_client.jwk_set_cache is not None:
            self._jwk_client.jwk_set_cache.put(jwk_set)
        return jwk_set


def _fetch_json_without_redirects(
    http: requests.Session, url: str, timeout: float, name: str
) -> dict[str, object]:
    """Fetch a JSON object without redirects; provider failures raise RequestException."""
    response = http.get(url, timeout=timeout, allow_redirects=False)
    if response.is_redirect or response.is_permanent_redirect:
        raise _OidcTransportError(f'{name} redirect not allowed')
    if response.status_code != _HTTP_OK:
        raise _OidcTransportError(f'{name} returned HTTP {response.status_code}')
    try:
        document: object = response.json()
    except ValueError as exc:
        raise _OidcTransportError(f'{name} is not JSON') from exc
    if not isinstance(document, dict):
        raise _OidcTransportError(f'{name} is not a JSON object')
    return cast('dict[str, object]', document)


def oidc_verifier(
    issuer: str,
    algorithms: Iterable[str],
    *,
    timeout: float = _REQUEST_TIMEOUT_SECONDS,
    session: requests.Session | None = None,
) -> Verifier:
    """Build a Verifier for the given OIDC issuer.

    Discovery runs once at construction: the document's `issuer` must exactly
    equal the configured issuer, and the JWKS endpoint must satisfy the
    https-or-loopback policy. Signature, issuer, and expiry are verified on
    every token, and the `exp` claim is required. Key material is cached per
    `kid` without time-based expiry, subject to PyJWT's bounded cache; a
    provider that rotates a key while reusing its `kid` is not supported.
    `aud`/`azp` are validated by the claims policy layer, not here.

    Args:
        issuer: Issuer URL exactly as it appears in tokens' `iss` claim.
        algorithms: Allowlist drawn from `ASYMMETRIC_OIDC_ALGORITHMS`;
            symmetric and unsupported algorithms are rejected.
        timeout: Per-request timeout in seconds for discovery and JWKS.
        session: Optional preconfigured Requests session used for discovery and
            JWKS retrieval. Defaults to a new session.

    Returns:
        A `Verifier` raising `ValueError` for invalid tokens and
        `requests.RequestException` for OIDC provider failures.

    Raises:
        OidcUnavailableError: If PyJWT is not installed.
        requests.RequestException: If OIDC discovery cannot be retrieved
            successfully.
        ValueError: If an algorithm is unsupported, or the issuer or discovery
            document is invalid.
    """
    allowed = list(algorithms)
    unsupported = set(allowed) - ASYMMETRIC_OIDC_ALGORITHMS
    if unsupported:
        raise ValueError(
            'OIDC algorithms must name asymmetric JWS algorithms from '
            f'{sorted(ASYMMETRIC_OIDC_ALGORITHMS)}; got {sorted(unsupported)}'
        )
    try:
        jwt_module = importlib.import_module('jwt')
    except ImportError as exc:
        raise OidcUnavailableError('PyJWT is not installed; install the [oidc] extra') from exc
    issuer = require_https_or_loopback(issuer, 'OIDC issuer')
    http = session if session is not None else requests.Session()
    # The well-known path joins onto the issuer without its trailing slash
    # (OIDC Discovery); the issuer VALUE stays exact for all comparisons.
    fields = _fetch_json_without_redirects(
        http, f'{issuer.rstrip("/")}{_DISCOVERY_PATH}', timeout, 'OIDC discovery'
    )
    if fields.get('issuer') != issuer:
        raise ValueError(f'discovery issuer {fields.get("issuer")!r} != configured {issuer!r}')
    jwks_uri = fields.get('jwks_uri')
    if not isinstance(jwks_uri, str) or not jwks_uri:
        raise ValueError('OIDC discovery document has no jwks_uri')
    require_https_or_loopback(jwks_uri, 'OIDC jwks_uri')
    jwk_client: _JwkClient = jwt_module.PyJWKClient(jwks_uri, cache_keys=True, timeout=timeout)

    def fetch_jwks() -> dict[str, object]:
        return _fetch_json_without_redirects(http, jwks_uri, timeout, 'OIDC JWKS')

    signing_keys = _SigningKeyResolver(jwk_client, cast('_JwtModule', jwt_module), fetch_jwks)

    def verify(presented: str) -> Mapping[str, object]:
        try:
            signing_key = signing_keys(presented)
            payload: object = jwt_module.decode(
                presented,
                signing_key.key,
                algorithms=allowed,
                issuer=issuer,
                options={'require': ['exp'], 'verify_aud': False},
                leeway=10,
            )
        except jwt_module.PyJWTError as exc:
            raise ValueError(str(exc)) from exc
        if isinstance(payload, dict):
            return cast('Mapping[str, object]', payload)
        raise ValueError('decoded token payload is not an object')

    return verify
