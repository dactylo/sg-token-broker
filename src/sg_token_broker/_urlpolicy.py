"""Enforce HTTPS except for loopback HTTP endpoints."""

import ipaddress
from urllib.parse import urlsplit

_LOOPBACK_NAMES = frozenset({'localhost'})


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


def require_https_or_loopback(url: str, name: str) -> str:
    """Validate that a URL uses https, or plain http on a loopback host only.

    Args:
        url: The URL to validate.
        name: Setting name used in the error message.

    Returns:
        The URL, unchanged.

    Raises:
        ValueError: If the URL is malformed, uses an unsupported scheme, has an
            invalid port, or uses plain HTTP on a remote host.
    """
    if '\\' in url or any(character.isspace() or not character.isprintable() for character in url):
        raise ValueError(f'{name} is not a valid URL: {url!r}')
    try:
        parts = urlsplit(url)
        host = parts.hostname or ''
        _ = parts.port
    except ValueError as exc:
        raise ValueError(f'{name} is not a valid URL: {url!r}') from exc
    if parts.scheme == 'https' and host:
        return url
    if parts.scheme == 'http' and is_loopback_host(host):
        return url
    raise ValueError(
        f'{name} must be an https:// URL (plain http is allowed only on loopback hosts): {url!r}'
    )
