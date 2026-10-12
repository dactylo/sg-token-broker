"""Hash client secrets and resolve SG script keys."""

import base64
import binascii
import hashlib
import hmac
import os
import secrets
from pathlib import Path

_HASH_FIELDS = 6
_SALT_BYTES = 16
_SCRYPT_DKLEN = 64
_SCRYPT_N = 16384
_SCRYPT_P = 1
_SCRYPT_R = 8


class SecretError(Exception):
    """A secret could not be hashed, verified, or resolved."""


def generate_secret() -> str:
    """Generate a new high-entropy client secret.

    Returns:
        A URL-safe random string suitable for use as a client secret.
    """
    return secrets.token_urlsafe(32)


def hash_secret(secret: str) -> str:
    """Hash a client secret with scrypt and a fresh random salt.

    Args:
        secret: The plaintext client secret.

    Returns:
        Hash string in the format `scrypt$N$r$p$<salt_b64>$<digest_b64>`.
    """
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.scrypt(
        secret.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN
    )
    fields = (
        'scrypt',
        str(_SCRYPT_N),
        str(_SCRYPT_R),
        str(_SCRYPT_P),
        base64.b64encode(salt).decode(),
        base64.b64encode(digest).decode(),
    )
    return '$'.join(fields)


def parse_secret_hash(secret_hash: str) -> tuple[bytes, bytes]:
    """Parse a stored scrypt hash, accepting only the production format.

    Args:
        secret_hash: Stored hash produced by `hash_secret`.

    Returns:
        Tuple of (salt, digest).

    Raises:
        SecretError: If the hash is malformed or uses parameters other than
            those `hash_secret` emits.
    """
    fields = secret_hash.split('$')
    if len(fields) != _HASH_FIELDS or fields[0] != 'scrypt':
        raise SecretError('malformed secret hash')
    if fields[1:4] != [str(_SCRYPT_N), str(_SCRYPT_R), str(_SCRYPT_P)]:
        raise SecretError('malformed secret hash: unsupported scrypt parameters')
    try:
        salt = base64.b64decode(fields[4], validate=True)
        digest = base64.b64decode(fields[5], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SecretError('malformed secret hash') from exc
    if len(salt) != _SALT_BYTES or len(digest) != _SCRYPT_DKLEN:
        raise SecretError('malformed secret hash: unsupported salt or digest length')
    return salt, digest


def resolve_script_key(*, env: str | None, file: Path | None) -> str:
    """Resolve a master SG script key from exactly one configured source.

    Args:
        env: Name of an environment variable holding the key, or `None` when
            using a file. Its value is returned without stripping.
        file: Path to a file whose stripped contents are the key, or `None`
            when using an environment variable.

    Returns:
        The non-empty script key.

    Raises:
        SecretError: If not exactly one source is given, the environment
            variable is unset or empty, or the file is unreadable or empty
            after stripping.
    """
    if env is not None and file is not None:
        raise SecretError('exactly one of env or file must be set')
    if env is not None:
        value = os.environ.get(env)
        if not value:
            raise SecretError(f'environment variable {env} is not set or empty')
        return value
    if file is None:
        raise SecretError('exactly one of env or file must be set')
    try:
        value = file.read_text(encoding='utf-8').strip()
    except (OSError, UnicodeError) as exc:
        raise SecretError(f'cannot read script key file {file}: {exc}') from exc
    if not value:
        raise SecretError(f'script key file {file} is empty')
    return value


def token_fingerprint(token: str) -> str:
    """Return a short non-reversible fingerprint of a token, safe for logs.

    Args:
        token: The token value.

    Returns:
        First 16 hex chars of the token's SHA-256 digest.
    """
    return hashlib.sha256(token.encode()).hexdigest()[:16]


def verify_secret(secret: str, secret_hash: str) -> bool:
    """Verify a plaintext secret against a stored scrypt hash in constant time.

    Args:
        secret: The plaintext client secret to check.
        secret_hash: Stored hash produced by `hash_secret`.

    Returns:
        True if the secret matches.

    Raises:
        SecretError: If the stored hash is malformed.
    """
    salt, expected = parse_secret_hash(secret_hash)
    actual = hashlib.scrypt(
        secret.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN
    )
    return hmac.compare_digest(actual, expected)
