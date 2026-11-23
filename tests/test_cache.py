import sys
import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from typing import TypeVar

import pytest

from sg_token_broker._cache import TTLCache, _InFlight

_T = TypeVar('_T')


class TestTTLCache:
    def test_concurrent_revalidate_mints_at_most_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cache: TTLCache[str] = TTLCache(clock=lambda: 0.0)
        release_validation = threading.Event()
        validation_started = _WorkerSignal()
        waiter_lookup = _WorkerSignal()
        waiter_started = threading.Event()
        observed_flights = _make_observed_flights(waiter_started, waiter_lookup)
        monkeypatch.setattr(cache, '_in_flight', observed_flights)
        cache.get_or_create('k', 60.0, lambda: 'dead')
        mints: list[str] = []

        def validate(_value: str) -> bool:
            validation_started.set()
            release_validation.wait()
            return False

        def refresh() -> tuple[str, bool]:
            return cache.revalidate_or_replace(
                'k', 60.0, validate, lambda: mints.append('m') or 'new'
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            owner = pool.submit(refresh)
            try:
                _wait_for_future_signal(validation_started, owner)
                waiter_started.set()
                waiter = pool.submit(refresh)
                _wait_for_future_signal(waiter_lookup, waiter)
            finally:
                release_validation.set()
            results = [owner.result(), waiter.result()]
        assert len(mints) == 1
        assert results == [('new', False), ('new', False)]  # waiters see the owner's outcome

    def test_distinct_keys(self) -> None:
        cache: TTLCache[str] = TTLCache(clock=lambda: 0.0)
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
        cache: TTLCache[str] = TTLCache(clock=lambda: 0.0)

        def boom() -> str:
            raise RuntimeError('mint failed')

        with pytest.raises(RuntimeError):
            cache.get_or_create('k', 60.0, boom)
        value, hit = cache.get_or_create('k', 60.0, lambda: 'ok')
        assert (value, hit) == ('ok', False)

    def test_failed_replacement_evicts_the_dead_value(self) -> None:
        cache: TTLCache[str] = TTLCache(clock=lambda: 0.0)
        cache.get_or_create('k', 60.0, lambda: 'dead')

        def explode() -> str:
            raise RuntimeError('mint failed')

        with pytest.raises(RuntimeError):
            cache.revalidate_or_replace('k', 60.0, lambda _: False, explode)
        assert cache.get_or_create('k', 60.0, lambda: 'fresh') == ('fresh', False)

    def test_failing_factory_runs_once_for_concurrent_waiters(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cache: TTLCache[str] = TTLCache(clock=lambda: 0.0)
        calls: list[int] = []
        factory_entered = _WorkerSignal()
        racer_lookup = _WorkerSignal()
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
            release_factory.wait()
            raise RuntimeError('mint failed')

        errors: list[BaseException] = []

        def worker() -> None:
            try:
                cache.get_or_create('k', 60.0, failing_factory)
            except RuntimeError as exc:
                errors.append(exc)

        def delayed_worker() -> None:
            release_last_waiter.wait()
            worker()

        threads: list[_ObservedThread] = []
        try:
            owner = _ObservedThread(target=worker, signals=(factory_entered, racer_lookup))
            owner.start()
            threads.append(owner)
            factory_entered.wait_for_worker()
            racer_started.set()
            last_waiter = _ObservedThread(target=delayed_worker, signals=(racer_lookup,))
            last_waiter.start()
            threads.append(last_waiter)
            for _ in range(3):
                waiter = _ObservedThread(target=worker, signals=(racer_lookup,))
                waiter.start()
                threads.append(waiter)
            release_last_waiter.set()
            racer_lookup.wait_for_worker()
        finally:
            release_last_waiter.set()
            release_factory.set()
            for thread in threads:
                thread.join()
            for thread in threads:
                thread.raise_if_failed()
        assert len(calls) == 1
        assert len(errors) == 5
        assert len({id(error) for error in errors}) == 1

    @pytest.mark.parametrize('entry_point', ['get_or_create', 'revalidate_or_replace'])
    def test_failing_flight_remains_visible_until_failure_published(
        self, monkeypatch: pytest.MonkeyPatch, entry_point: str
    ) -> None:
        cache: TTLCache[str] = TTLCache(clock=lambda: 0.0)
        completion_started = _WorkerSignal()
        factory_entered = _WorkerSignal()
        racer_lookup = _WorkerSignal()
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
            release_factory.wait()
            raise failure

        def unexpected_factory() -> str:
            unexpected_calls.append(1)
            return 'unexpected'

        owner_thread = _ObservedThread(
            target=_capture_cache_call,
            args=(cache, entry_point, failing_factory, results, errors),
            signals=(factory_entered, completion_started),
        )
        racer_thread = _ObservedThread(
            target=_capture_cache_call,
            args=(cache, entry_point, unexpected_factory, results, errors),
            signals=(racer_lookup,),
        )
        owner_thread.start()
        try:
            factory_entered.wait_for_worker()
            release_factory.set()
            completion_started.wait_for_worker()
            racer_started.set()
            racer_thread.start()
            racer_lookup.wait_for_worker()
        finally:
            release_factory.set()
            release_completion.set()
            owner_thread.join()
            if racer_thread.ident is not None:
                racer_thread.join()
        owner_thread.raise_if_failed()
        racer_thread.raise_if_failed()
        assert unexpected_calls == []
        assert results == []
        assert len(errors) == 2
        assert all(error is failure for error in errors)

        value, hit = cache.get_or_create('k', 60.0, lambda: 'retry')
        assert (value, hit) == ('retry', False)

    def test_get_or_create_waits_for_concurrent_revalidation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cache: TTLCache[str] = TTLCache(clock=lambda: 0.0)
        cache.get_or_create('k', 60.0, lambda: 'dead')
        release_validation = threading.Event()
        validation_started = _WorkerSignal()
        waiter_lookup = _WorkerSignal()
        waiter_started = threading.Event()
        monkeypatch.setattr(
            cache, '_in_flight', _make_observed_flights(waiter_started, waiter_lookup)
        )

        def validate(_value: str) -> bool:
            validation_started.set()
            release_validation.wait()
            return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            owner = pool.submit(
                cache.revalidate_or_replace,
                'k',
                60.0,
                validate,
                lambda: 'fresh',
            )
            _wait_for_future_signal(validation_started, owner)
            waiter_started.set()
            waiter = pool.submit(cache.get_or_create, 'k', 60.0, lambda: 'unexpected')
            try:
                _wait_for_future_signal(waiter_lookup, waiter)
                assert not waiter.done()
            finally:
                release_validation.set()
            assert owner.result() == ('fresh', False)
            assert waiter.result() == ('fresh', True)

    def test_miss_then_hit(self) -> None:
        cache: TTLCache[str] = TTLCache(clock=lambda: 0.0)
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
        cache: TTLCache[str] = TTLCache(clock=lambda: 0.0)
        factory_started = _WorkerSignal()
        release_factory = threading.Event()
        waiter_lookup = _WorkerSignal()
        waiter_started = threading.Event()
        monkeypatch.setattr(
            cache, '_in_flight', _make_observed_flights(waiter_started, waiter_lookup)
        )

        def factory() -> str:
            factory_started.set()
            release_factory.wait()
            return 'fresh'

        validations: list[str] = []
        with ThreadPoolExecutor(max_workers=2) as pool:
            owner = pool.submit(cache.get_or_create, 'k', 60.0, factory)
            _wait_for_future_signal(factory_started, owner)
            waiter_started.set()
            waiter = pool.submit(
                cache.revalidate_or_replace,
                'k',
                60.0,
                lambda value: validations.append(value) or True,
                lambda: 'unexpected',
            )
            try:
                _wait_for_future_signal(waiter_lookup, waiter)
            finally:
                release_factory.set()
            assert owner.result() == ('fresh', False)
            assert waiter.result() == ('fresh', False)
        assert validations == []

    def test_revalidate_keeps_live_value(self) -> None:
        now = [0.0]
        cache: TTLCache[str] = TTLCache(clock=lambda: now[0])
        cache.get_or_create('k', 60.0, lambda: 'old')
        now[0] = 30.0
        value, kept = cache.revalidate_or_replace('k', 60.0, lambda _: True, lambda: 'new')
        assert (value, kept) == ('old', True)
        now[0] = 60.0
        assert cache.get_or_create('k', 60.0, lambda: 'new') == ('new', False)

    def test_revalidate_replaces_dead_value(self) -> None:
        cache: TTLCache[str] = TTLCache(clock=lambda: 0.0)
        cache.get_or_create('k', 60.0, lambda: 'old')
        value, kept = cache.revalidate_or_replace('k', 60.0, lambda _: False, lambda: 'new')
        assert (value, kept) == ('new', False)
        assert cache.get_or_create('k', 60.0, lambda: 'unused') == ('new', True)

    def test_revalidate_with_empty_cache_mints(self) -> None:
        cache: TTLCache[str] = TTLCache(clock=lambda: 0.0)
        value, kept = cache.revalidate_or_replace('k', 60.0, lambda _: True, lambda: 'new')
        assert (value, kept) == ('new', False)

    def test_singleflight_collapses_concurrent_misses(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cache: TTLCache[str] = TTLCache(clock=lambda: 0.0)
        calls: list[int] = []
        factory_started = _WorkerSignal()
        release_factory = threading.Event()
        waiter_lookup = _WorkerSignal()
        waiter_started = threading.Event()
        monkeypatch.setattr(
            cache, '_in_flight', _make_observed_flights(waiter_started, waiter_lookup)
        )

        def factory() -> str:
            calls.append(1)
            factory_started.set()
            release_factory.wait()
            return 'tok'

        with ThreadPoolExecutor(max_workers=2) as pool:
            owner = pool.submit(cache.get_or_create, 'k', 60.0, factory)
            _wait_for_future_signal(factory_started, owner)
            waiter_started.set()
            waiter = pool.submit(cache.get_or_create, 'k', 60.0, factory)
            try:
                _wait_for_future_signal(waiter_lookup, waiter)
                assert not waiter.done()
            finally:
                release_factory.set()
            assert owner.result() == ('tok', False)
            assert waiter.result() == ('tok', True)
        assert calls == [1]


class _WorkerSignal(threading.Event):
    def __init__(self) -> None:
        super().__init__()
        self._reached = False

    def set(self) -> None:
        self._reached = True
        super().set()

    def wait_for_worker(self) -> None:
        self.wait()
        assert self._reached, 'worker exited before reaching the expected signal'

    def wake_on_exit(self) -> None:
        super().set()


class _ObservedThread(threading.Thread):
    def __init__(
        self,
        *,
        target: Callable[..., object],
        signals: tuple[_WorkerSignal, ...],
        args: tuple[object, ...] = (),
    ) -> None:
        super().__init__(target=target, args=args)
        self._signals = signals
        self._error: BaseException | None = None

    def raise_if_failed(self) -> None:
        if self._error is not None:
            raise self._error

    def run(self) -> None:
        try:
            super().run()
        finally:
            self._error = sys.exception()
            for signal in self._signals:
                signal.wake_on_exit()


def _capture_cache_call(
    cache: TTLCache[str],
    entry_point: str,
    factory: Callable[[], str],
    results: list[tuple[str, bool]],
    errors: list[BaseException],
) -> None:
    try:
        if entry_point == 'get_or_create':
            results.append(cache.get_or_create('k', 60.0, factory))
        else:
            results.append(cache.revalidate_or_replace('k', 60.0, lambda _value: True, factory))
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
            self._entries: dict[object, object] = {}
            self._waiters = 0

        def __delitem__(self, key: object) -> None:
            del self._entries[key]

        def __setitem__(self, key: object, value: object) -> None:
            self._entries[key] = value

        def get(self, key: object) -> object | None:
            flight = self._entries.get(key)
            if flight is not None and racer_started.is_set():
                self._waiters += 1
                if self._waiters == expected_waiters:
                    racer_lookup.set()
            return flight

    return ObservedFlights()


def _make_test_flight(
    completion_started: threading.Event, release_completion: threading.Event
) -> type[object]:

    class PausingEvent(threading.Event):
        def set(self) -> None:
            completion_started.set()
            release_completion.wait()
            super().set()

    class TestFlight(_InFlight[_T]):
        def __init__(self) -> None:
            super().__init__()
            self.done = PausingEvent()

    return TestFlight


def _wait_for_future_signal(signal: _WorkerSignal, worker: Future[_T]) -> None:
    worker.add_done_callback(lambda _worker: signal.wake_on_exit())
    signal.wait_for_worker()
    if worker.done():
        worker.result()
