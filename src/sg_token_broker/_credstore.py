"""Store refresh credentials in approved OS keychains with fail-closed fallback."""

import importlib
from types import ModuleType

_SECURE_BACKENDS = frozenset(
    {
        'keyring.backends.macOS.Keyring',
        'keyring.backends.SecretService.Keyring',
        'keyring.backends.Windows.WinVaultKeyring',
    }
)


def _backend_is_secure(backend: object) -> bool:
    """Return True if the resolved keyring backend is on the allowlist."""
    cls = type(backend)
    return f'{cls.__module__}.{cls.__qualname__}' in _SECURE_BACKENDS


def _keyring() -> ModuleType | None:
    """Import keyring, or None when the login extra is not installed."""
    try:
        return importlib.import_module('keyring')
    except ImportError:
        return None


def _delete_value(service: str, username: str) -> bool:
    """Delete one keyring entry; report whether it is gone."""
    keyring = _keyring()
    if keyring is None:
        return False
    try:
        backend = keyring.get_keyring()
        if not _backend_is_secure(backend):
            return False
        if backend.get_password(service, username) is None:
            return True
        backend.delete_password(service, username)
    except Exception:  # noqa: BLE001 - report any optional-backend fault
        return False
    return True


def _load_value(service: str, username: str) -> str | None:
    """Read one keyring entry through the backend allowlist, or None."""
    keyring = _keyring()
    if keyring is None:
        return None
    try:
        backend = keyring.get_keyring()
        if not _backend_is_secure(backend):
            return None
        value: str | None = backend.get_password(service, username)
    except Exception:  # noqa: BLE001 - degrade to no-store on any backend fault
        return None
    return value


def _meta_service_name(issuer: str, client_id: str) -> str:
    """Build a collision-resistant keyring service name for metadata."""
    return f'sg-token-broker-meta|{issuer}|{client_id}'


def _service_name(issuer: str, client_id: str) -> str:
    """Build the namespaced keyring service name."""
    return f'sg-token-broker|{issuer}|{client_id}'


def _store_value(service: str, username: str, value: str) -> bool:
    """Write one keyring entry through the backend allowlist; False on degradation."""
    keyring = _keyring()
    if keyring is None:
        return False
    try:
        backend = keyring.get_keyring()
        if not _backend_is_secure(backend):
            return False
        backend.set_password(service, username, value)
    except Exception:  # noqa: BLE001 - degrade to no-store on any backend fault
        return False
    return True


def delete_account(issuer: str, client_id: str) -> bool:
    """Remove the stored last-signed-in account pointer, if any.

    Args:
        issuer: The identity provider issuer URL.
        client_id: The OAuth client id.

    Returns:
        True if removed or already absent; False when deletion could not be
        confirmed.
    """
    return _delete_value(_meta_service_name(issuer, client_id), 'account')


def delete_refresh_token(issuer: str, client_id: str, account: str) -> bool:
    """Remove the stored refresh credential, if any.

    Args:
        issuer: The identity provider issuer URL.
        client_id: The OAuth client id.
        account: The signed-in account identifier.

    Returns:
        True if removed or already absent; False when deletion could not be
        confirmed.
    """
    return _delete_value(_service_name(issuer, client_id), account)


def load_account(issuer: str, client_id: str) -> str | None:
    """Return the last-signed-in account for this issuer and client, or None.

    Args:
        issuer: The identity provider issuer URL.
        client_id: The OAuth client id.

    Returns:
        The last-signed-in account, or None when absent, keyring is
        unavailable, the resolved backend is not allowlisted, or the backend
        errored.
    """
    return _load_value(_meta_service_name(issuer, client_id), 'account')


def load_refresh_token(issuer: str, client_id: str, account: str) -> str | None:
    """Return the stored refresh credential, or None.

    The secure-backend allowlist applies to reads exactly as to writes: an
    unapproved backend never supplies a credential.

    Args:
        issuer: The identity provider issuer URL.
        client_id: The OAuth client id.
        account: The signed-in account identifier.

    Returns:
        The credential, or None when absent, keyring is unavailable, the
        resolved backend is not allowlisted, or the backend errored.
    """
    return _load_value(_service_name(issuer, client_id), account)


def store_account(issuer: str, client_id: str, account: str) -> bool:
    """Record `account` as the last-signed-in account for this namespace.

    Args:
        issuer: The identity provider issuer URL.
        client_id: The OAuth client id.
        account: The account identifier to record.

    Returns:
        True if recorded; False on the same no-store degradations as
        `store_refresh_token`.
    """
    return _store_value(_meta_service_name(issuer, client_id), 'account', account)


def store_refresh_token(issuer: str, client_id: str, account: str, value: str) -> bool:
    """Store the refresh credential in an approved secure backend.

    Args:
        issuer: The identity provider issuer URL.
        client_id: The OAuth client id.
        account: The signed-in account identifier.
        value: The refresh credential.

    Returns:
        True if the backend reports a successful write; False when keyring is
        unavailable, the resolved backend is not allowlisted, or the backend
        errored. A backend error does not confirm whether a write took effect.
    """
    return _store_value(_service_name(issuer, client_id), account, value)
