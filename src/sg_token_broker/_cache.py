"""Provide a thread-safe TTL cache with per-key singleflight."""

import threading
import time
from collections.abc import Callable, Hashable
from typing import Generic, TypeVar

_T = TypeVar('_T')


class _InFlight(Generic[_T]):
    """One in-progress factory call shared by every concurrent waiter."""

    def __init__(self) -> None:
        """Create an unpublished cache flight with a completion event."""
        self.done = threading.Event()
        self.error: BaseException | None = None
        self.outcome: tuple[_T, bool] | None = None

    def wait(self) -> tuple[_T, bool]:
        """Wait for the owner, then return its published outcome or raise its error.

        Returns:
            The owner's value and operation-specific flag. `get_or_create`
            publishes `False` for its new value; its waiter reports a cache hit
            separately. `revalidate_or_replace` publishes `True` when it keeps
            a cached value and `False` when it creates or replaces one.

        Raises:
            BaseException: If the owner failed while producing the outcome.
        """
        self.done.wait()
        if self.error is not None:
            raise self.error
        if self.outcome is None:
            raise RuntimeError('cache flight completed without an outcome')
        return self.outcome


class TTLCache(Generic[_T]):
    """Cache values in memory by TTL with per-key singleflight."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        """Create an empty cache using the selected time source.

        Args:
            clock: Monotonic time source. Defaults to `time.monotonic`.
        """
        self._clock = clock
        self._entries: dict[Hashable, tuple[_T, float]] = {}
        self._in_flight: dict[Hashable, _InFlight[_T]] = {}
        self._master_lock = threading.Lock()

    def _fail_flight(self, key: Hashable, flight: _InFlight[_T], exc: BaseException) -> None:
        """Publish a flight failure before removing it from in-progress work."""
        flight.error = exc
        flight.done.set()
        with self._master_lock:
            del self._in_flight[key]

    def _lookup(self, key: Hashable) -> tuple[_T, bool] | None:
        """Return a live cached value for key, or None."""
        entry = self._entries.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if self._clock() >= expires_at:
            del self._entries[key]
            return None
        return value, True

    def _prune_expired(self) -> None:
        """Drop every expired entry; caller holds `_master_lock`."""
        now = self._clock()
        for key in [key for key, (_, expires_at) in self._entries.items() if now >= expires_at]:
            del self._entries[key]

    def get_or_create(
        self,
        key: Hashable,
        ttl: float,
        factory: Callable[[], _T],
    ) -> tuple[_T, bool]:
        """Return the cached value for key, creating it via factory on miss.

        Args:
            key: Cache key.
            ttl: Lifetime in seconds for a newly created value.
            factory: Zero-argument callable producing the value on miss. It
                runs once for concurrent callers sharing a miss. If it raises,
                nothing is cached and the same exception propagates to every
                caller waiting on this key.

        Returns:
            Tuple of (value, cache_hit). The flag is False for the caller that
            ran the factory and True for a caller reusing a cached value or
            joining an in-progress flight.

        Raises:
            BaseException: If `factory` raises; the exception propagates to the
                owner and waiters.
        """
        with self._master_lock:
            flight = self._in_flight.get(key)
            if flight is None:
                cached = self._lookup(key)
                if cached is not None:
                    return cached
                flight = _InFlight[_T]()
                self._in_flight[key] = flight
                is_owner = True
            else:
                is_owner = False
        if not is_owner:
            return flight.wait()[0], True
        try:
            value = factory()
        except BaseException as exc:
            self._fail_flight(key, flight, exc)
            raise
        with self._master_lock:
            self._prune_expired()
            self._entries[key] = (value, self._clock() + ttl)
            del self._in_flight[key]
        flight.outcome = (value, False)
        flight.done.set()
        return value, False

    def revalidate_or_replace(
        self,
        key: Hashable,
        ttl: float,
        validate: Callable[[_T], bool],
        factory: Callable[[], _T],
    ) -> tuple[_T, bool]:
        """Keep the cached value if `validate` accepts it, else replace it.

        Probe, eviction, and replacement are one serialized operation per key:
        concurrent callers join a single flight and `factory` runs at most once
        per replacement. `validate` and `factory` run outside the master lock
        (they may perform network calls).

        An accepted value keeps its original expiry deadline. An absent or
        expired entry is created without validation. If validation raises, the
        entry remains cached; if validation rejects it, the entry is evicted
        before replacement, even when the replacement factory raises.

        Args:
            key: Cache key.
            ttl: Lifetime in seconds for a newly created value.
            validate: Returns True if the cached value is still live.
            factory: Produces the replacement value.

        Returns:
            Tuple of (value, kept): kept is True when the cached value was
            revalidated and served back unchanged. Waiters that joined an
            in-progress flight receive the owner's outcome.

        Raises:
            BaseException: If `validate` or `factory` raises; the exception
                propagates to the owner and waiters.
        """
        with self._master_lock:
            flight = self._in_flight.get(key)
            if flight is None:
                flight = _InFlight[_T]()
                self._in_flight[key] = flight
                is_owner = True
            else:
                is_owner = False
            cached = self._lookup(key)
        if not is_owner:
            return flight.wait()
        try:
            if cached is not None and validate(cached[0]):
                value, kept = cached[0], True
            else:
                if cached is not None:
                    # The cached value failed validation: evict it now so a
                    # failed replacement cannot leave a known-dead value
                    # behind for later requests.
                    with self._master_lock:
                        self._entries.pop(key, None)
                value, kept = factory(), False
        except BaseException as exc:
            self._fail_flight(key, flight, exc)
            raise
        flight.outcome = (value, kept)
        with self._master_lock:
            if not kept:
                self._prune_expired()
                self._entries[key] = (value, self._clock() + ttl)
            del self._in_flight[key]
        flight.done.set()
        return value, kept
