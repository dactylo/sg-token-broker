"""Enforce HTTPS except for loopback HTTP endpoints."""

import ipaddress
from urllib.parse import urlsplit

from urllib3.util import parse_url

_LOOPBACK_NAMES = frozenset({'localhost'})


def endpoint_origin(url: str) -> str:
    """Return the printable HTTP origin, or an empty string for an invalid endpoint."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ''
        if host and not host.isascii():
            host = parse_url(f'https://{host}').host or ''
        if (
            not host
            or parts.scheme not in {'http', 'https'}
            or not all(ch.isalnum() or ch in '.-:' for ch in host)
        ):
            return ''
        authority = f'[{host}]' if ':' in host else host
        if parts.port is not None:
            authority += f':{parts.port}'
    except ValueError:
        return ''
    return f'{parts.scheme}://{authority}'


def is_loopback_host(host: str) -> bool:
    """Return whether a host is a loopback name or address.

    Args:
        host: The hostname or IP address to classify.

    Returns:
        Whether the host resolves syntactically to a loopback name or address.
    """
    if host.lower() in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def require_https_or_loopback(
    url: str, name: str, *, credential_settings: str | None = None
) -> str:
    """Validate an HTTPS endpoint or a plain HTTP endpoint on a loopback host.

    Args:
        url: URL to validate.
        name: Setting name used in diagnostics.
        credential_settings: A nonempty value rejects embedded credentials and
            names the supported credential settings in the diagnostic.

    Returns:
        The original URL, unchanged.

    Raises:
        ValueError: If the URL is malformed, uses an unsupported scheme or
            port, selects remote plain HTTP, or contains disallowed embedded
            credentials.
    """
    if '\\' in url or any(character.isspace() or not character.isprintable() for character in url):
        raise ValueError(f'{name} is not a valid URL')
    try:
        parts = urlsplit(url)
        host = parts.hostname or ''
        _ = parts.port
    except ValueError:
        raise ValueError(f'{name} is not a valid URL') from None
    if credential_settings and parts.username is not None:
        raise ValueError(f'{name} must omit URL credentials; use {credential_settings} instead')
    if parts.scheme == 'https' and host:
        return url
    if parts.scheme == 'http' and is_loopback_host(host):
        return url
    origin = endpoint_origin(url)
    detail = f': {origin!r}' if origin else ''
    raise ValueError(
        f'{name} must be an https:// URL (plain http is allowed only on loopback hosts){detail}'
    )
