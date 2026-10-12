import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Generic, TypeVar

import pytest

from sg_token_broker._cache import TTLCache

_T = TypeVar('_T')


class TestTTLCache:
    def test_concurrent_revalidate_mints_at_most_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cache: TTLCache[str] = TTLCache()
        release_validation = threading.Event()
        validation_started = threading.Event()
        waiter_lookup = threading.Event()
        waiter_started = threading.Event()
        observed_flights = _make_observed_flights(waiter_started, waiter_lookup)
        monkeypatch.setattr(cache, '_in_flight', observed_flights)
        cache.get_or_create('k', 60.0, lambda: 'dead')
        mints: list[str] = []

        def validate(_value: str) -> bool:
            validation_started.set()
            release_validation.wait(timeout=5)
            return False

        def refresh() -> tuple[str, bool]:
            return cache.revalidate_or_replace(
                'k', 60.0, validate, lambda: mints.append('m') or 'new'
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            owner = pool.submit(refresh)
            assert validation_started.wait(timeout=5)
            waiter_started.set()
            waiter = pool.submit(refresh)
            assert waiter_lookup.wait(timeout=5)
            release_validation.set()
            results = [owner.result(), waiter.result()]
        assert len(mints) == 1
        assert results == [('new', False), ('new', False)]  # waiters see the owner's outcome

    def test_distinct_keys(self) -> None:
        cache: TTLCache[str] = TTLCache()
        assert cache.get_or_create('a', 60.0, lambda: 'va')[0] == 'va'
        assert cache.get_or_create('b', 60.0, lambda: 'vb')[0] == 'vb'

    def test_expired_entries_are_pruned_on_insert(self) -> None:
        now = [0.0]
        cache: TTLCache[str] = TTLCache(clock=lambda: now[0])
        for index in range(100):
            cache.get_or_create(f'k{index}', 10.0, lambda index=index: f'v{index}')
        now[0] = 11.0
        cache.get_or_create('fresh', 10.0, lambda: 'v-fresh')
        entries = cache._entries
        assert list(entries) == ['fresh']
        assert cache.get_or_create('k0', 10.0, lambda: 'again') == ('again', False)

    def test_expired_entries_are_pruned_on_revalidate_insert(self) -> None:
        now = [0.0]
        cache: TTLCache[str] = TTLCache(clock=lambda: now[0])
        cache.get_or_create('expired', 10.0, lambda: 'old')
        now[0] = 11.0
        assert cache.revalidate_or_replace('fresh', 10.0, lambda _: True, lambda: 'new') == (
            'new',
            False,
        )
        entries = cache._entries
        assert list(entries) == ['fresh']

    def test_expired_entry_is_deleted_when_recreation_fails(self) -> None:
        now = [0.0]
        cache: TTLCache[str] = TTLCache(clock=lambda: now[0])
        cache.get_or_create('expired', 10.0, lambda: 'old')
        now[0] = 11.0

        def explode() -> str:
            raise RuntimeError('mint failed')

        with pytest.raises(RuntimeError, match='mint failed'):
            cache.get_or_create('expired', 10.0, explode)
        entries = cache._entries
        assert entries == {}

    def test_expiry(self) -> None:
        now = [0.0]
        cache: TTLCache[str] = TTLCache(clock=lambda: now[0])
        cache.get_or_create('k', 10.0, lambda: 'a')
        now[0] = 11.0
        value, hit = cache.get_or_create('k', 10.0, lambda: 'b')
        assert (value, hit) == ('b', False)

    def test_factory_error_not_cached(self) -> None:
        cache: TTLCache[str] = TTLCache()

        def boom() -> str:
            raise RuntimeError('mint failed')

        with pytest.raises(RuntimeError):
            cache.get_or_create('k', 60.0, boom)
        value, hit = cache.get_or_create('k', 60.0, lambda: 'ok')
        assert (value, hit) == ('ok', False)

    def test_failed_replacement_evicts_the_dead_value(self) -> None:
        cache: TTLCache[str] = TTLCache()
        cache.get_or_create('k', 60.0, lambda: 'dead')

        def explode() -> str:
            raise RuntimeError('mint failed')

        with pytest.raises(RuntimeError):
            cache.revalidate_or_replace('k', 60.0, lambda _: False, explode)
        assert cache.get_or_create('k', 60.0, lambda: 'fresh') == ('fresh', False)

    def test_failing_factory_runs_once_for_concurrent_waiters(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cache: TTLCache[str] = TTLCache()
        calls: list[int] = []
        factory_entered = threading.Event()
        racer_lookup = threading.Event()
        racer_started = threading.Event()
        release_factory = threading.Event()
        release_last_waiter = threading.Event()
        monkeypatch.setattr(
            cache,
            '_in_flight',
            _make_observed_flights(racer_started, racer_lookup, expected_waiters=4),
        )

        def failing_factory() -> str:
            calls.append(1)
            factory_entered.set()
            assert release_factory.wait(timeout=5)
            raise RuntimeError('mint failed')

        errors: list[BaseException] = []

        def worker() -> None:
            try:
                cache.get_or_create('k', 60.0, failing_factory)
            except RuntimeError as exc:
                errors.append(exc)

        def delayed_worker() -> None:
            assert release_last_waiter.wait(timeout=5)
            worker()

        threads: list[threading.Thread] = []
        try:
            owner = threading.Thread(target=worker)
            owner.start()
            threads.append(owner)
            assert factory_entered.wait(timeout=5)
            racer_started.set()
            last_waiter = threading.Thread(target=delayed_worker)
            last_waiter.start()
            threads.append(last_waiter)
            for _ in range(3):
                waiter = threading.Thread(target=worker)
                waiter.start()
                threads.append(waiter)
            release_last_waiter.set()
            assert racer_lookup.wait(timeout=5)
        finally:
            release_last_waiter.set()
            release_factory.set()
            for thread in threads:
                thread.join(timeout=10)
            assert all(not thread.is_alive() for thread in threads)
        assert len(calls) == 1
        assert len(errors) == 5
        assert len({id(error) for error in errors}) == 1

    def test_failing_flight_remains_visible_until_failure_published(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cache: TTLCache[str] = TTLCache()
        completion_started = threading.Event()
        factory_entered = threading.Event()
        racer_lookup = threading.Event()
        racer_started = threading.Event()
        release_completion = threading.Event()
        release_factory = threading.Event()

        test_flight = _make_test_flight(completion_started, release_completion)
        observed_flights = _make_observed_flights(racer_started, racer_lookup)
        monkeypatch.setattr('sg_token_broker._cache._InFlight', test_flight)
        monkeypatch.setattr(cache, '_in_flight', observed_flights)
        failure = RuntimeError('mint failed')
        errors: list[BaseException] = []
        results: list[tuple[str, bool]] = []
        unexpected_calls: list[int] = []

        def failing_factory() -> str:
            factory_entered.set()
            release_factory.wait(timeout=5)
            raise failure

        def unexpected_factory() -> str:
            unexpected_calls.append(1)
            return 'unexpected'

        owner_thread = threading.Thread(
            target=_capture_cache_call, args=(cache, failing_factory, results, errors)
        )
        owner_thread.start()
        assert factory_entered.wait(timeout=5)
        release_factory.set()
        assert completion_started.wait(timeout=5)

        racer_started.set()
        racer_thread = threading.Thread(
            target=_capture_cache_call, args=(cache, unexpected_factory, results, errors)
        )
        racer_thread.start()
        assert racer_lookup.wait(timeout=5)
        release_completion.set()

        owner_thread.join(timeout=5)
        racer_thread.join(timeout=5)
        assert not owner_thread.is_alive()
        assert not racer_thread.is_alive()
        assert unexpected_calls == []
        assert results == []
        assert len(errors) == 2
        assert all(error is failure for error in errors)

        value, hit = cache.get_or_create('k', 60.0, lambda: 'retry')
        assert (value, hit) == ('retry', False)

    def test_get_or_create_waits_for_concurrent_revalidation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cache: TTLCache[str] = TTLCache()
        cache.get_or_create('k', 60.0, lambda: 'dead')
        release_validation = threading.Event()
        validation_started = threading.Event()
        waiter_lookup = threading.Event()
        waiter_started = threading.Event()
        monkeypatch.setattr(
            cache, '_in_flight', _make_observed_flights(waiter_started, waiter_lookup)
        )

        def validate(_value: str) -> bool:
            validation_started.set()
            assert release_validation.wait(timeout=5)
            return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            owner = pool.submit(
                cache.revalidate_or_replace,
                'k',
                60.0,
                validate,
                lambda: 'fresh',
            )
            assert validation_started.wait(timeout=5)
            waiter_started.set()
            waiter = pool.submit(cache.get_or_create, 'k', 60.0, lambda: 'unexpected')
            try:
                assert waiter_lookup.wait(timeout=1)
                assert not waiter.done()
            finally:
                release_validation.set()
            assert owner.result() == ('fresh', False)
            assert waiter.result() == ('fresh', True)

    def test_miss_then_hit(self) -> None:
        cache: TTLCache[str] = TTLCache()
        calls: list[int] = []

        def factory() -> str:
            calls.append(1)
            return 'tok'

        value, hit = cache.get_or_create('k', 60.0, factory)
        assert (value, hit) == ('tok', False)
        value, hit = cache.get_or_create('k', 60.0, factory)
        assert (value, hit) == ('tok', True)
        assert len(calls) == 1

    def test_revalidate_joining_concurrent_creation_reports_not_kept(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cache: TTLCache[str] = TTLCache()
        factory_started = threading.Event()
        release_factory = threading.Event()
        waiter_lookup = threading.Event()
        waiter_started = threading.Event()
        monkeypatch.setattr(
            cache, '_in_flight', _make_observed_flights(waiter_started, waiter_lookup)
        )

        def factory() -> str:
            factory_started.set()
            assert release_factory.wait(timeout=5)
            return 'fresh'

        validations: list[str] = []
        with ThreadPoolExecutor(max_workers=2) as pool:
            owner = pool.submit(cache.get_or_create, 'k', 60.0, factory)
            assert factory_started.wait(timeout=5)
            waiter_started.set()
            waiter = pool.submit(
                cache.revalidate_or_replace,
                'k',
                60.0,
                lambda value: validations.append(value) or True,
                lambda: 'unexpected',
            )
            try:
                assert waiter_lookup.wait(timeout=5)
            finally:
                release_factory.set()
            assert owner.result() == ('fresh', False)
            assert waiter.result() == ('fresh', False)
        assert validations == []

    def test_revalidate_keeps_live_value(self) -> None:
        cache: TTLCache[str] = TTLCache()
        cache.get_or_create('k', 60.0, lambda: 'old')
        value, kept = cache.revalidate_or_replace('k', 60.0, lambda _: True, lambda: 'new')
        assert (value, kept) == ('old', True)

    def test_revalidate_replaces_dead_value(self) -> None:
        cache: TTLCache[str] = TTLCache()
        cache.get_or_create('k', 60.0, lambda: 'old')
        value, kept = cache.revalidate_or_replace('k', 60.0, lambda _: False, lambda: 'new')
        assert (value, kept) == ('new', False)
        assert cache.get_or_create('k', 60.0, lambda: 'unused') == ('new', True)

    def test_revalidate_with_empty_cache_mints(self) -> None:
        cache: TTLCache[str] = TTLCache()
        value, kept = cache.revalidate_or_replace('k', 60.0, lambda _: True, lambda: 'new')
        assert (value, kept) == ('new', False)

    def test_singleflight_collapses_concurrent_misses(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cache: TTLCache[str] = TTLCache()
        calls: list[int] = []
        factory_started = threading.Event()
        release_factory = threading.Event()
        waiter_lookup = threading.Event()
        waiter_started = threading.Event()
        monkeypatch.setattr(
            cache, '_in_flight', _make_observed_flights(waiter_started, waiter_lookup)
        )

        def factory() -> str:
            calls.append(1)
            factory_started.set()
            assert release_factory.wait(timeout=5)
            return 'tok'

        with ThreadPoolExecutor(max_workers=2) as pool:
            owner = pool.submit(cache.get_or_create, 'k', 60.0, factory)
            assert factory_started.wait(timeout=5)
            waiter_started.set()
            waiter = pool.submit(cache.get_or_create, 'k', 60.0, factory)
            try:
                assert waiter_lookup.wait(timeout=5)
                assert not waiter.done()
            finally:
                release_factory.set()
            assert owner.result() == ('tok', False)
            assert waiter.result() == ('tok', True)
        assert calls == [1]


def _capture_cache_call(
    cache: TTLCache[str],
    factory: Callable[[], str],
    results: list[tuple[str, bool]],
    errors: list[BaseException],
) -> None:
    try:
        results.append(cache.get_or_create('k', 60.0, factory))
    except RuntimeError as exc:
        errors.append(exc)


def _make_observed_flights(
    racer_started: threading.Event,
    racer_lookup: threading.Event,
    *,
    expected_waiters: int = 1,
) -> object:

    class ObservedFlights:
        def __init__(self) -> None:
            self.entries: dict[object, object] = {}
            self.waiters = 0

        def __delitem__(self, key: object) -> None:
            del self.entries[key]

        def __setitem__(self, key: object, value: object) -> None:
            self.entries[key] = value

        def get(self, key: object) -> object | None:
            flight = self.entries.get(key)
            if flight is not None and racer_started.is_set():
                self.waiters += 1
                if self.waiters == expected_waiters:
                    racer_lookup.set()
            return flight

    return ObservedFlights()


def _make_test_flight(
    completion_started: threading.Event, release_completion: threading.Event
) -> type[object]:

    class PausingEvent(threading.Event):
        def set(self) -> None:
            completion_started.set()
            release_completion.wait(timeout=5)
            super().set()

    class TestFlight(Generic[_T]):
        def __init__(self) -> None:
            self._done = PausingEvent()
            self._error: BaseException | None = None
            self._kept: bool | None = None
            self._value: _T | None = None

    return TestFlight
