"""Environment-only configuration for the user-token service."""

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, field

from sg_token_broker._oidcverify import ASYMMETRIC_OIDC_ALGORITHMS
from sg_token_broker._urlpolicy import require_https_or_loopback

_DEFAULT_EMAIL_CLAIM = 'email'
_DEFAULT_OIDC_ALGORITHMS = ('ES256', 'RS256')
_DEFAULT_PORT = 8080
_DEFAULT_SESSION_TTL_SECONDS = 600
_ENV_PREFIX = 'SGUT'
_KNOWN_PROVIDERS = frozenset({'google', 'oidc'})
_KNOWN_TOKEN_TYPES = frozenset({'rest', 'session'})
_MAX_PORT = 65535


class UserConfigError(Exception):
    """The service environment configuration is missing or malformed."""


@dataclass(frozen=True)
class UserTokenConfig:
    """Validated user-token service configuration.

    Do not serialize with `dataclasses.asdict` or `astuple`; they bypass
    `repr=False` and would leak `script_key`.

    Attributes:
        site_url: Base URL of the SG site without a trailing slash.
        script_name: Service ApiUser script name.
        script_key: Service ApiUser application key.
        audiences: Accepted identity-token audience values.
        allowed_domain: Required domain for caller email addresses.
        port: HTTP listening port.
        token_types: Token types the deployment may issue.
        session_ttl_seconds: Maximum service-cache lifetime for sessions.
        trusted_proxies: Peer addresses allowed to supply `X-Forwarded-For`.
        provider: Identity provider type, `google` or `oidc`.
        issuer: Configured OIDC issuer, or `None` for Google.
        email_claim: Identity-token claim containing the caller email.
        assume_email_verified: Whether the provider contract allows a missing
            `email_verified` claim.
        oidc_algorithms: Accepted asymmetric OIDC signature algorithms.
    """

    site_url: str
    script_name: str
    script_key: str = field(repr=False)
    audiences: tuple[str, ...]
    allowed_domain: str
    port: int
    token_types: frozenset[str]
    session_ttl_seconds: int
    trusted_proxies: frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address]
    provider: str
    issuer: str | None
    email_claim: str
    assume_email_verified: bool
    oidc_algorithms: tuple[str, ...]


def _nonempty(value: str, name: str) -> str:
    """Return `value`, rejecting an empty normalized string."""
    if not value:
        raise UserConfigError(f'{name} is empty after normalization')
    return value


def _require(environ: Mapping[str, str], name: str) -> str:
    """Return the stripped value of a required environment variable."""
    value = environ.get(name, '').strip()
    if not value:
        raise UserConfigError(f'{name} is not set or empty')
    return value


def _parse_provider(environ: Mapping[str, str]) -> tuple[str, str | None]:
    """Return the validated provider and optional OIDC issuer."""
    provider = environ.get(f'{_ENV_PREFIX}_PROVIDER', 'google').strip() or 'google'
    if provider not in _KNOWN_PROVIDERS:
        raise UserConfigError(
            f'{_ENV_PREFIX}_PROVIDER must be one of {sorted(_KNOWN_PROVIDERS)}; got {provider!r}'
        )
    issuer: str | None = None
    if provider == 'oidc':
        # Kept exactly as configured: an OIDC issuer identifier is compared
        # verbatim (a trailing slash is significant), never normalized.
        issuer = _require(environ, f'{_ENV_PREFIX}_ISSUER')
        try:
            require_https_or_loopback(issuer, f'{_ENV_PREFIX}_ISSUER')
        except ValueError as exc:
            raise UserConfigError(str(exc)) from exc
    return provider, issuer


def normalize_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parse an IP address, reducing IPv4-mapped IPv6 to the IPv4 address.

    Args:
        value: Textual IPv4 or IPv6 address.

    Returns:
        The canonical address object.

    Raises:
        ValueError: If `value` is not an IP address.
    """
    address = ipaddress.ip_address(value.strip())
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _parse_trusted_proxies(
    environ: Mapping[str, str],
) -> frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Return the validated trusted-proxy IP addresses."""
    raw_proxies = environ.get(f'{_ENV_PREFIX}_TRUSTED_PROXIES', '')
    trusted_proxies: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for part in raw_proxies.split(','):
        proxy = part.strip()
        if not proxy:
            continue
        try:
            trusted_proxies.append(normalize_ip(proxy))
        except ValueError as exc:
            raise UserConfigError(
                f'{_ENV_PREFIX}_TRUSTED_PROXIES entry is not an IP address: {proxy!r}'
            ) from exc
    return frozenset(trusted_proxies)


def load_user_token_config(environ: Mapping[str, str]) -> UserTokenConfig:
    """Load and validate the service configuration from environment variables.

    Args:
        environ: Environment mapping (pass `os.environ`).

    Returns:
        The validated configuration.

    Raises:
        UserConfigError: If a required variable is missing or any setting is
            malformed or invalid.
    """
    raw_audiences = _require(environ, f'{_ENV_PREFIX}_AUDIENCES')
    audiences = tuple(aud.strip() for aud in raw_audiences.split(',') if aud.strip())
    if not audiences:
        raise UserConfigError(f'{_ENV_PREFIX}_AUDIENCES contains no audiences')
    raw_port = environ.get('PORT', str(_DEFAULT_PORT)).strip()
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise UserConfigError(f'PORT is not an integer: {raw_port!r}') from exc
    if not 0 < port <= _MAX_PORT:
        raise UserConfigError(f'PORT is out of range (1-{_MAX_PORT}): {port}')
    site_url = _require(environ, f'{_ENV_PREFIX}_SITE_URL')
    try:
        require_https_or_loopback(site_url, f'{_ENV_PREFIX}_SITE_URL')
    except ValueError as exc:
        raise UserConfigError(str(exc)) from exc
    raw_types = _require(environ, f'{_ENV_PREFIX}_TOKEN_TYPES')
    token_types = frozenset(part.strip() for part in raw_types.split(',') if part.strip())
    unknown = token_types - _KNOWN_TOKEN_TYPES
    if not token_types or unknown:
        raise UserConfigError(
            f'{_ENV_PREFIX}_TOKEN_TYPES must be a comma list from '
            f'{sorted(_KNOWN_TOKEN_TYPES)}; got {raw_types!r}'
        )
    raw_ttl = environ.get(
        f'{_ENV_PREFIX}_SESSION_TTL_SECONDS', str(_DEFAULT_SESSION_TTL_SECONDS)
    ).strip()
    try:
        session_ttl = int(raw_ttl)
    except ValueError as exc:
        raise UserConfigError(
            f'{_ENV_PREFIX}_SESSION_TTL_SECONDS is not an integer: {raw_ttl!r}'
        ) from exc
    if session_ttl < 1:
        raise UserConfigError(f'{_ENV_PREFIX}_SESSION_TTL_SECONDS must be positive')
    trusted_proxies = _parse_trusted_proxies(environ)
    provider, issuer = _parse_provider(environ)
    email_claim = environ.get(f'{_ENV_PREFIX}_EMAIL_CLAIM', '').strip() or _DEFAULT_EMAIL_CLAIM
    raw_assume = environ.get(f'{_ENV_PREFIX}_ASSUME_EMAIL_VERIFIED', 'false').strip().lower()
    if raw_assume not in ('true', 'false'):
        raise UserConfigError(f'{_ENV_PREFIX}_ASSUME_EMAIL_VERIFIED must be true or false')
    raw_algorithms = environ.get(f'{_ENV_PREFIX}_OIDC_ALGORITHMS', '')
    algorithms = (
        tuple(sorted(part.strip() for part in raw_algorithms.split(',') if part.strip()))
        or _DEFAULT_OIDC_ALGORITHMS
    )
    symmetric = set(algorithms) - ASYMMETRIC_OIDC_ALGORITHMS
    if symmetric:
        raise UserConfigError(
            f'{_ENV_PREFIX}_OIDC_ALGORITHMS must name asymmetric JWS algorithms from '
            f'{sorted(ASYMMETRIC_OIDC_ALGORITHMS)}; got {sorted(symmetric)}'
        )
    return UserTokenConfig(
        site_url=site_url.rstrip('/'),
        script_name=_require(environ, f'{_ENV_PREFIX}_SCRIPT_NAME'),
        script_key=_require(environ, f'{_ENV_PREFIX}_SCRIPT_KEY'),
        audiences=audiences,
        allowed_domain=_nonempty(
            _require(environ, f'{_ENV_PREFIX}_ALLOWED_DOMAIN').lower().lstrip('@'),
            f'{_ENV_PREFIX}_ALLOWED_DOMAIN',
        ),
        port=port,
        token_types=token_types,
        session_ttl_seconds=session_ttl,
        trusted_proxies=trusted_proxies,
        provider=provider,
        issuer=issuer,
        email_claim=email_claim,
        assume_email_verified=raw_assume == 'true',
        oidc_algorithms=algorithms,
    )
