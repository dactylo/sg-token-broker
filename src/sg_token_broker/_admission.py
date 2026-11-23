"""Bound secret verification work and the workers waiting on it."""

import functools
import hashlib
import hmac
import secrets
import threading
import time
from collections.abc import Callable, Sequence
from concurrent.futures import Future

from sg_token_broker import _secrets

_PROCESS_KEY = secrets.token_bytes(32)


class ServerBusyError(Exception):
    """The broker has no capacity for this request.

    Attributes:
        retry_after: Seconds to wait before retrying.
    """

    retry_after: float = 1.0


class WaitingShare:
    """A fixed pool of permits shared by workers waiting on broker operations."""

    def __init__(self, limit: int) -> None:
        """Allow at most `limit` workers to enter the share at once."""
        self._permits = threading.BoundedSemaphore(limit)

    def leave(self) -> None:
        """Return one permit after a successful entry."""
        self._permits.release()

    def try_enter(self) -> bool:
        """Take a permit immediately, returning false when all permits are held."""
        return self._permits.acquire(blocking=False)


class SecretVerifier:
    """Remember successful credential checks and share concurrent checks for the same input."""

    def __init__(
        self,
        *,
        waiting: WaitingShare,
        work: int,
        clock: Callable[[], float] = time.monotonic,
        retention: float = 600.0,
        slots: int = 2,
    ) -> None:
        """Start with no remembered credentials or active checks.

        Args:
            waiting: Shared permits for callers joining an active check.
            work: Maximum configured credentials per client. Failed checks run
                this many hashes.
            clock: Monotonic seconds used to measure retention.
            retention: Seconds a completed match can skip verification.
            slots: Maximum number of concurrent independent checks.
        """
        self._waiting = waiting
        self._work = work
        self._clock = clock
        self._retention = retention
        self._slots = slots
        self._lock = threading.Lock()
        self._matches: dict[tuple[str, str], tuple[bytes, float]] = {}
        self._active: dict[tuple[str, bytes], Future[str | None]] = {}
        self._padding_hash = _dummy_hash()

    def _check(self, credentials: Sequence[tuple[str, str]], secret: str) -> str | None:
        """Verify configured hashes in order and pad every failure to the same cost."""
        for credential_id, secret_hash in credentials:
            if _secrets.verify_secret(secret, secret_hash):
                return credential_id
        for _ in range(len(credentials), self._work):
            _secrets.verify_secret(secret, self._padding_hash)
        return None

    def verify(
        self, client_id: str, credentials: Sequence[tuple[str, str]], secret: str
    ) -> str | None:
        """Return the matching credential ID, or `None` for an unknown client or bad secret.

        Args:
            client_id: Presented client ID.
            credentials: Configured (credential ID, scrypt hash) pairs for this
                client, empty for an unknown ID.
            secret: Presented plaintext secret.

        Raises:
            ServerBusyError: No verification slot or waiting permit is
                available.
        """
        digest = hmac.new(_PROCESS_KEY, secret.encode(), hashlib.sha256).digest()
        key = (client_id, digest)
        with self._lock:
            now = self._clock()
            for credential_id, _ in credentials:
                match = self._matches.get((client_id, credential_id))
                if match and now < match[1] and hmac.compare_digest(digest, match[0]):
                    return credential_id

            pending = self._active.get(key)
            if pending is None:
                if len(self._active) >= self._slots:
                    raise ServerBusyError
                pending = Future[str | None]()
                self._active[key] = pending
                owner = True
            else:
                if not self._waiting.try_enter():
                    raise ServerBusyError
                owner = False

        if not owner:
            try:
                return pending.result()
            finally:
                self._waiting.leave()

        try:
            matched = self._check(credentials, secret)
            with self._lock:
                if matched is not None:
                    self._matches[client_id, matched] = (digest, self._clock() + self._retention)
                pending.set_result(matched)
                del self._active[key]
        except BaseException as exc:
            with self._lock:
                pending.set_exception(exc)
                del self._active[key]
            raise
        else:
            return matched


@functools.cache
def _dummy_hash() -> str:
    """Return the process-wide scrypt hash used to pad unsuccessful credential checks."""
    return _secrets.hash_secret('timing-equalizer')
