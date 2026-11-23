import datetime
import hashlib
import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from types import TracebackType
from typing import TypeVar
from unittest.mock import Mock

import pytest

from sg_token_broker import _issuance
from sg_token_broker._admission import ServerBusyError, WaitingShare
from sg_token_broker._issuance import (
    CachedMint,
    IssueOutcome,
    IssuerLimits,
    KeyedIssuer,
    MintBudget,
    MintPlan,
    MintRateLimitedError,
    UpstreamFailureError,
    _IssueKey,
)
from sg_token_broker._sg import MintedToken, SGError, SGFailureKind, SGInvalidResponseError

_KEY = ('farm', 'read', 'rest')
_TOKEN = (MintedToken('issued', 61), datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC))
_T = TypeVar('_T')


def _mint(charge: Callable[[], None]) -> CachedMint:
    charge()
    return _TOKEN


def _issue(
    issuer: KeyedIssuer,
    key: _IssueKey = _KEY,
    mint: Callable[[Callable[[], None]], CachedMint] = _mint,
    limit: int = 1,
    rejected: frozenset[str] = frozenset(),
) -> tuple[CachedMint, IssueOutcome]:
    return issuer.issue(
        key,
        MintPlan(mint=mint, ttl=60, still_valid=lambda _: True),
        rate_limit=limit,
        rejected=rejected,
    )


def _rejection(value: CachedMint) -> frozenset[str]:
    return frozenset({hashlib.sha256(value[0].token.encode()).hexdigest()})


def _wait_for(event: threading.Event, worker: Future[_T]) -> None:
    worker.add_done_callback(lambda _: event.set())
    event.wait()
    if worker.done():
        worker.result()
        pytest.fail('worker exited before the held operation')


@pytest.fixture
def clock() -> Mock:
    return Mock(return_value=0.0)


@pytest.fixture
def waiting() -> WaitingShare:
    return WaitingShare(24)


def _hold_joiner_delivery(
    issuer: KeyedIssuer,
    joined: threading.Event,
    deliver: threading.Event,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Patch only the joiner's delivery from the issuer's active Future.
    active = issuer._active[_KEY]
    read_result = active.result

    def delay_delivery() -> _issuance._Entry | None:
        joined.set()
        value = read_result()
        deliver.wait()
        return value

    monkeypatch.setattr(active, 'result', delay_delivery)


def test_budget_refusal_leaves_rejected_token_evicted(issuer: KeyedIssuer) -> None:
    assert _issue(issuer) == (_TOKEN, 'minted')
    with pytest.raises(MintRateLimitedError):
        _issue(issuer, rejected=_rejection(_TOKEN))
    with pytest.raises(MintRateLimitedError):
        _issue(issuer)


def test_cache_ttl_runs_from_mint_completion_and_hits_do_not_extend_it(
    issuer: KeyedIssuer, clock: Mock
) -> None:
    def mint(charge: Callable[[], None]) -> CachedMint:
        charge()
        clock.return_value = 10
        return _TOKEN

    assert _issue(issuer, mint=mint) == (_TOKEN, 'minted')
    clock.return_value = 69.5
    assert _issue(issuer) == (_TOKEN, 'hit')
    clock.return_value = 70
    assert _issue(issuer) == (_TOKEN, 'minted')


def test_delayed_joiner_cannot_deliver_an_evicted_generation(
    issuer: KeyedIssuer, monkeypatch: pytest.MonkeyPatch
) -> None:
    entered, finish_mint = threading.Event(), threading.Event()
    joined, deliver = threading.Event(), threading.Event()

    def mint(charge: Callable[[], None]) -> CachedMint:
        charge()
        entered.set()
        finish_mint.wait()
        return _TOKEN

    fresh = MintedToken('fresh', 61), _TOKEN[1]

    def renew(charge: Callable[[], None]) -> CachedMint:
        charge()
        return fresh

    with ThreadPoolExecutor(max_workers=2) as pool:
        owner = pool.submit(_issue, issuer, mint=mint, limit=2)
        try:
            _wait_for(entered, owner)
            _hold_joiner_delivery(issuer, joined, deliver, monkeypatch)
            joiner = pool.submit(_issue, issuer, limit=2)
            _wait_for(joined, joiner)
            finish_mint.set()
            assert owner.result() == (_TOKEN, 'minted')
            assert _issue(issuer, mint=renew, limit=2, rejected=_rejection(_TOKEN)) == (
                fresh,
                'replaced',
            )
        finally:
            finish_mint.set()
            deliver.set()
        assert joiner.result()[0] == fresh


def test_failed_replacement_leaves_no_token_during_or_after_refusal(
    issuer: KeyedIssuer, clock: Mock
) -> None:
    assert _issue(issuer, limit=3) == (_TOKEN, 'minted')

    def refuse(charge: Callable[[], None]) -> CachedMint:
        charge()
        raise SGError('refused', status_code=403)

    with pytest.raises(UpstreamFailureError) as refused:
        _issue(issuer, mint=refuse, limit=3, rejected=_rejection(_TOKEN))
    assert refused.value.kind == 'rejected'
    clock.return_value = 29.5
    with pytest.raises(UpstreamFailureError) as remembered:
        _issue(issuer, limit=3)
    assert remembered.value.kind == 'rejected'
    clock.return_value = 30
    fresh = MintedToken('fresh', 61), _TOKEN[1]

    def recover(charge: Callable[[], None]) -> CachedMint:
        charge()
        return fresh

    assert _issue(issuer, mint=recover, limit=3) == (fresh, 'minted')


def test_future_setup_failure_returns_the_only_waiting_place(
    clock: Mock, monkeypatch: pytest.MonkeyPatch
) -> None:
    issuer = KeyedIssuer(waiting=WaitingShare(1), budget=MintBudget(clock), clock=clock)

    class FailedFuture(Future[object]):
        def __init__(self) -> None:
            raise MemoryError('future setup')

    with monkeypatch.context() as patch:
        patch.setattr(_issuance, 'Future', FailedFuture)
        with pytest.raises(MemoryError, match='future setup'):
            _issue(issuer)
    assert _issue(issuer) == (_TOKEN, 'minted')


def test_joiner_rechecks_a_short_rest_lifetime_before_serving(
    issuer: KeyedIssuer, monkeypatch: pytest.MonkeyPatch
) -> None:
    entered, release = threading.Event(), threading.Event()
    joined, deliver = threading.Event(), threading.Event()
    deadline = _TOKEN[1]
    now = deadline - datetime.timedelta(seconds=1)

    def mint(charge: Callable[[], None]) -> CachedMint:
        charge()
        entered.set()
        release.wait()
        return _TOKEN

    def renew(charge: Callable[[], None]) -> CachedMint:
        charge()
        return MintedToken('renewed', 61), now + datetime.timedelta(seconds=1)

    plan = MintPlan(mint=renew, ttl=60, still_valid=lambda cached: now < cached[1])

    with ThreadPoolExecutor(max_workers=2) as pool:
        owner = pool.submit(_issue, issuer, _KEY, mint, 2)
        try:
            _wait_for(entered, owner)
            _hold_joiner_delivery(issuer, joined, deliver, monkeypatch)
            joiner = pool.submit(issuer.issue, _KEY, plan, rate_limit=2)
            _wait_for(joined, joiner)
            release.set()
            assert owner.result() == (_TOKEN, 'minted')
            # The owner already computed the one-second usable lifetime. At
            # delivery the UTC deadline has arrived, inside the 60s cache TTL.
            now = deadline
        finally:
            release.set()
            deliver.set()
        cached, outcome = joiner.result()
        assert (cached[0].token, outcome) == ('renewed', 'minted')


def test_key_resolution_failure_before_charge_spends_nothing(clock: Mock) -> None:
    issuer = KeyedIssuer(
        waiting=WaitingShare(1),
        budget=MintBudget(clock),
        limits=IssuerLimits(sg_calls=1),
        clock=clock,
    )
    with pytest.raises(ValueError, match='missing key'):
        _issue(issuer, mint=Mock(side_effect=ValueError('missing key')))
    assert _issue(issuer) == (_TOKEN, 'minted')


def test_racing_keys_share_a_client_budget(issuer: KeyedIssuer, clock: Mock) -> None:
    release = threading.Event()

    def contender(scope: str, ready: threading.Event) -> IssueOutcome:
        def mint(charge: Callable[[], None]) -> CachedMint:
            ready.set()
            release.wait()
            return _mint(charge)

        return _issue(issuer, ('farm', scope, 'rest'), mint)[1]

    with ThreadPoolExecutor(max_workers=2) as pool:
        workers: list[Future[IssueOutcome]] = []
        try:
            for scope in ('read', 'write'):
                ready = threading.Event()
                worker = pool.submit(contender, scope, ready)
                workers.append(worker)
                _wait_for(ready, worker)
        finally:
            release.set()
        outcomes: list[str] = []
        delays: list[float] = []
        for worker in workers:
            try:
                outcomes.append(worker.result())
            except MintRateLimitedError as exc:
                delays.append(exc.retry_after)
                outcomes.append('limited')
    assert sorted(outcomes) == ['limited', 'minted']
    assert delays == pytest.approx([60])
    clock.return_value = 59.5
    third = ('farm', 'third', 'rest')
    with pytest.raises(MintRateLimitedError) as caught:
        _issue(issuer, third)
    assert caught.value.retry_after == pytest.approx(0.5)
    assert _issue(issuer, ('other', 'read', 'rest')) == (_TOKEN, 'minted')
    clock.return_value = 60.0
    assert _issue(issuer, third) == (_TOKEN, 'minted')


@pytest.fixture
def issuer(waiting: WaitingShare, clock: Mock) -> KeyedIssuer:
    return KeyedIssuer(waiting=waiting, budget=MintBudget(clock), clock=clock)


def test_spends_late_in_a_fixed_window_reset_with_the_first_spend(clock: Mock) -> None:
    budget = MintBudget(clock)
    clock.return_value = 7
    assert budget.try_spend('farm', 2) is None
    clock.return_value = 66
    assert budget.try_spend('farm', 2) is None
    assert budget.try_spend('farm', 2) == pytest.approx(1)
    clock.return_value = 67
    assert budget.try_spend('farm', 2) is None
    assert budget.try_spend('farm', 2) is None


@pytest.mark.parametrize(
    ('error', 'kind', 'interval'),
    [
        (SGError('unavailable'), 'unavailable', 5),
        (SGError('refused', status_code=403), 'rejected', 30),
        (SGInvalidResponseError('SG token lifetime too short to serve'), 'invalid_response', 30),
    ],
)
def test_sg_failure_interval_and_budget_recovery(
    issuer: KeyedIssuer, clock: Mock, error: SGError, kind: SGFailureKind, interval: int
) -> None:
    def fail(charge: Callable[[], None]) -> CachedMint:
        charge()
        clock.return_value = 10
        raise error

    mint = Mock(side_effect=fail)
    with pytest.raises(UpstreamFailureError) as first:
        _issue(issuer, mint=mint, limit=2)
    assert first.value.kind == kind
    assert first.value.__cause__ is error
    assert first.value.retry_after == (interval if kind == 'unavailable' else None)
    clock.return_value = 10 + interval - 0.5
    with pytest.raises(UpstreamFailureError) as remembered:
        _issue(issuer, mint=mint, limit=2)
    assert remembered.value.kind == kind
    assert remembered.value.retry_after == (0.5 if kind == 'unavailable' else None)
    mint.assert_called_once()
    # The first failure spent one of two attempts and the remembered one was free.
    assert _issue(issuer, ('farm', 'other', 'rest'), limit=2) == (_TOKEN, 'minted')
    clock.return_value = 10 + interval
    with pytest.raises(MintRateLimitedError) as limited:
        _issue(issuer, limit=2)
    assert limited.value.retry_after == pytest.approx(60 - (10 + interval))
    clock.return_value = 60
    assert _issue(issuer, limit=2) == (_TOKEN, 'minted')


def _observe_next_entry(waiting: WaitingShare, monkeypatch: pytest.MonkeyPatch) -> threading.Event:
    entered = threading.Event()
    try_enter = waiting.try_enter

    def observe_entry() -> bool:
        admitted = try_enter()
        if admitted:
            entered.set()
        return admitted

    monkeypatch.setattr(waiting, 'try_enter', observe_entry)
    return entered


def test_eight_held_sg_calls_refuse_a_ninth_before_spending(clock: Mock) -> None:
    waiting = WaitingShare(9)
    issuer = KeyedIssuer(waiting=waiting, budget=MintBudget(clock), clock=clock)
    release = threading.Event()

    def issue(client: str, entered: threading.Event) -> IssueOutcome:
        def mint(charge: Callable[[], None]) -> CachedMint:
            charge()
            entered.set()
            release.wait()
            return _TOKEN

        return _issue(issuer, (client, 'read', 'rest'), mint)[1]

    with ThreadPoolExecutor(max_workers=8) as pool:
        workers: list[Future[IssueOutcome]] = []
        try:
            for index in range(8):
                entered = threading.Event()
                worker = pool.submit(issue, str(index), entered)
                workers.append(worker)
                _wait_for(entered, worker)
            with pytest.raises(ServerBusyError):
                _issue(issuer)
            assert waiting.try_enter()  # The refused owner returned its waiting permit.
            waiting.leave()
        finally:
            release.set()
        assert all(worker.result() == 'minted' for worker in workers)
    assert _issue(issuer) == (_TOKEN, 'minted')


@pytest.mark.parametrize(('status', 'interval'), [(503, 5), (403, 30)])
def test_expired_failure_admits_a_new_mint_before_failed_caller_returns(
    issuer: KeyedIssuer, clock: Mock, monkeypatch: pytest.MonkeyPatch, status: int, interval: int
) -> None:
    published, release = threading.Event(), threading.Event()
    lock = issuer._lock

    class PauseAfterFailure:
        def __enter__(self) -> None:
            lock.acquire()

        def __exit__(
            self,
            _type: type[BaseException] | None,
            _value: BaseException | None,
            _traceback: TracebackType | None,
        ) -> None:
            # Sample under the production lock. Hold the first caller after
            # the deadline is visible, with the lock free for a new admission.
            pause = _KEY in issuer._failures and not published.is_set()
            lock.release()
            if pause:
                published.set()
                release.wait()

    def fail(charge: Callable[[], None]) -> CachedMint:
        charge()
        raise SGError('SG failed', status_code=status)

    monkeypatch.setattr(issuer, '_lock', PauseAfterFailure())
    with ThreadPoolExecutor(max_workers=2) as pool:
        owner = pool.submit(_issue, issuer, _KEY, fail, 2)
        try:
            _wait_for(published, owner)
            clock.return_value = interval
            admitted = _observe_next_entry(issuer._waiting, monkeypatch)
            next_call = pool.submit(_issue, issuer, _KEY, _mint, 2)
            next_call.add_done_callback(lambda _: admitted.set())
            admitted.wait()
        finally:
            release.set()
        with pytest.raises(UpstreamFailureError) as first:
            owner.result()
        assert first.value.kind == ('unavailable' if status == 503 else 'rejected')
        assert next_call.result() == (_TOKEN, 'minted')


def test_fresh_mint_rejected_by_owner_is_available_only_to_existing_joiners(
    issuer: KeyedIssuer, waiting: WaitingShare, monkeypatch: pytest.MonkeyPatch
) -> None:
    minting, finish = threading.Event(), threading.Event()
    retired, retry = threading.Event(), threading.Event()
    owner_thread = threading.local()
    leave = waiting.leave

    def pause_retry() -> None:
        leave()
        if getattr(owner_thread, 'hold', False):
            retired.set()
            retry.wait()

    def mint(charge: Callable[[], None]) -> CachedMint:
        charge()
        owner_thread.hold = True
        minting.set()
        finish.wait()
        return _TOKEN

    fresh = MintedToken('fresh', 61), _TOKEN[1]

    def recover(charge: Callable[[], None]) -> CachedMint:
        charge()
        return fresh

    monkeypatch.setattr(waiting, 'leave', pause_retry)
    with ThreadPoolExecutor(max_workers=2) as pool:
        owner = pool.submit(_issue, issuer, mint=mint, limit=2, rejected=_rejection(_TOKEN))
        try:
            _wait_for(minting, owner)
            joined = _observe_next_entry(waiting, monkeypatch)
            joiner = pool.submit(_issue, issuer, limit=2)
            _wait_for(joined, joiner)
            finish.set()
            _wait_for(retired, owner)
            assert _issue(issuer, mint=recover, limit=2) == (fresh, 'minted')
            assert joiner.result() == (_TOKEN, 'joined')
        finally:
            finish.set()
            retry.set()
        assert owner.result() == (fresh, 'hit')


def test_joiner_replaces_the_result_its_own_report_rejects(
    issuer: KeyedIssuer, waiting: WaitingShare, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _issue(issuer, limit=3) == (_TOKEN, 'minted')
    second = MintedToken('second', 61), _TOKEN[1]
    third = MintedToken('third', 61), _TOKEN[1]
    entered, release = threading.Event(), threading.Event()

    def replace_first(charge: Callable[[], None]) -> CachedMint:
        charge()
        entered.set()
        release.wait()
        return second

    def replace_second(charge: Callable[[], None]) -> CachedMint:
        charge()
        return third

    with ThreadPoolExecutor(max_workers=2) as pool:
        owner = pool.submit(
            _issue, issuer, mint=replace_first, limit=3, rejected=_rejection(_TOKEN)
        )
        try:
            _wait_for(entered, owner)
            joined = _observe_next_entry(waiting, monkeypatch)
            joiner = pool.submit(
                _issue, issuer, mint=replace_second, limit=3, rejected=_rejection(second)
            )
            _wait_for(joined, joiner)
        finally:
            release.set()
        # If the joiner evicts the second generation before the owner delivers
        # it, the owner must also take the third generation.
        assert owner.result() in ((second, 'replaced'), (third, 'joined'), (third, 'hit'))
        assert joiner.result() == (third, 'replaced')
    assert _issue(issuer, rejected=_rejection(_TOKEN)) == (third, 'hit')


def test_joiners_and_hits_are_free_and_waiting_share_bounds_owners_and_joiners(
    clock: Mock, monkeypatch: pytest.MonkeyPatch
) -> None:
    entered, release = threading.Event(), threading.Event()
    waiting = WaitingShare(2)
    issuer = KeyedIssuer(waiting=waiting, budget=MintBudget(clock), clock=clock)

    def mint(charge: Callable[[], None]) -> CachedMint:
        charge()
        entered.set()
        release.wait()
        return _TOKEN

    other = ('other', 'read', 'rest')
    with ThreadPoolExecutor(max_workers=2) as pool:
        owner = pool.submit(_issue, issuer, _KEY, mint, 2)
        try:
            _wait_for(entered, owner)
            joined = _observe_next_entry(waiting, monkeypatch)
            joiner = pool.submit(_issue, issuer, _KEY, mint, 2)
            _wait_for(joined, joiner)
            for key in (_KEY, other):
                with pytest.raises(ServerBusyError):
                    _issue(issuer, key)
        finally:
            release.set()
        assert owner.result() == (_TOKEN, 'minted')
        assert joiner.result() == (_TOKEN, 'joined')
    assert _issue(issuer, _KEY, limit=2) == (_TOKEN, 'hit')
    assert _issue(issuer, ('farm', 'write', 'rest'), limit=2) == (_TOKEN, 'minted')
    assert _issue(issuer, other) == (_TOKEN, 'minted')
    assert waiting.try_enter()
    assert waiting.try_enter()
    waiting.leave()
    waiting.leave()


@pytest.mark.parametrize('limit', [1, 2])
def test_owner_and_joiner_repeat_admission_when_token_expires_before_publication(
    issuer: KeyedIssuer, clock: Mock, monkeypatch: pytest.MonkeyPatch, limit: int
) -> None:
    entered, finish_mint = threading.Event(), threading.Event()
    returned, publishing, resume = threading.Event(), threading.Event(), threading.Event()
    deadline = _TOKEN[1]
    now = deadline - datetime.timedelta(seconds=1)
    renewed = (MintedToken('renewed', 61), deadline + datetime.timedelta(seconds=1))
    attempts: list[str] = []

    def mint(charge: Callable[[], None]) -> CachedMint:
        charge()
        if not attempts:
            attempts.append('issued')
            entered.set()
            finish_mint.wait()
            returned.set()
            return _TOKEN
        attempts.append('renewed')
        return renewed

    def monotonic() -> float:
        # Pause the first sample after the mint returned, before publication.
        if returned.is_set() and not publishing.is_set():
            publishing.set()
            resume.wait()
        return 0.0

    clock.side_effect = monotonic
    plan = MintPlan(mint=mint, ttl=60, still_valid=lambda cached: now < cached[1])
    with ThreadPoolExecutor(max_workers=2) as pool:
        owner = pool.submit(issuer.issue, _KEY, plan, rate_limit=limit)
        try:
            _wait_for(entered, owner)
            joined = _observe_next_entry(issuer._waiting, monkeypatch)
            joiner = pool.submit(issuer.issue, _KEY, plan, rate_limit=limit)
            _wait_for(joined, joiner)
            finish_mint.set()
            _wait_for(publishing, owner)
            now = deadline
        finally:
            finish_mint.set()
            resume.set()
        for worker in (owner, joiner):
            if limit == 1:
                with pytest.raises(MintRateLimitedError):
                    worker.result()
            else:
                cached, _ = worker.result()
                assert cached == renewed
    assert attempts == (['issued'] if limit == 1 else ['issued', 'renewed'])


def test_replacement_evicts_before_reserving_a_waiting_place(clock: Mock) -> None:
    waiting = WaitingShare(1)
    issuer = KeyedIssuer(waiting=waiting, budget=MintBudget(clock), clock=clock)
    assert _issue(issuer) == (_TOKEN, 'minted')
    assert waiting.try_enter()
    try:
        with pytest.raises(ServerBusyError):
            _issue(issuer, rejected=_rejection(_TOKEN))
        with pytest.raises(ServerBusyError):
            _issue(issuer)
    finally:
        waiting.leave()
