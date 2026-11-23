import hashlib
import hmac
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from unittest.mock import Mock

import pytest

from sg_token_broker import _admission, _secrets
from sg_token_broker._admission import SecretVerifier, ServerBusyError, WaitingShare
from tests.conftest import BROKER_CREDENTIAL, BROKER_HASH

_CREDENTIALS = (('primary', BROKER_HASH),)


def _wait_for_entry(event: threading.Event, worker: Future[str | None]) -> None:
    worker.add_done_callback(lambda _: event.set())
    event.wait()
    if worker.done():
        worker.result()
        pytest.fail('worker exited before the held operation')


def test_full_verifier_refuses_only_uncached_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = SecretVerifier(waiting=WaitingShare(1), work=1, clock=lambda: 0.0)
    assert verifier.verify('farm', _CREDENTIALS, BROKER_CREDENTIAL) == 'primary'
    entered = {str(i): threading.Event() for i in range(2)}
    release = threading.Event()

    def check(secret: str, _secret_hash: str) -> bool:
        if secret in entered:
            entered[secret].set()
            release.wait()
        return False

    monkeypatch.setattr(_secrets, 'verify_secret', check)
    with ThreadPoolExecutor(max_workers=len(entered)) as pool:
        workers: list[Future[str | None]] = []
        try:
            for secret, event in entered.items():
                worker = pool.submit(verifier.verify, 'farm', _CREDENTIALS, secret)
                workers.append(worker)
                _wait_for_entry(event, worker)
            with pytest.raises(ServerBusyError):
                verifier.verify('farm', _CREDENTIALS, 'overflow')
            assert verifier.verify('farm', _CREDENTIALS, BROKER_CREDENTIAL) == 'primary'
        finally:
            release.set()
        for worker in workers:
            assert worker.result() is None


@pytest.mark.parametrize('outcome', ['match', 'miss', 'error'])
def test_joiners_share_one_check_and_release_the_waiting_share(
    outcome: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    waiting = WaitingShare(1)
    verifier = SecretVerifier(waiting=waiting, work=1, clock=lambda: 0.0, slots=1)
    entered = threading.Event()
    joined = threading.Event()
    release = threading.Event()
    try_enter = waiting.try_enter

    def observe_join() -> bool:
        admitted = try_enter()
        if admitted:
            joined.set()
        return admitted

    def check(_secret: str, _secret_hash: str) -> bool:
        entered.set()
        release.wait()
        if outcome == 'error':
            raise RuntimeError('check failed')
        return outcome == 'match'

    verify = Mock(side_effect=check)
    monkeypatch.setattr(waiting, 'try_enter', observe_join)
    monkeypatch.setattr(_secrets, 'verify_secret', verify)
    with ThreadPoolExecutor(max_workers=2) as pool:
        owner = pool.submit(verifier.verify, 'farm', _CREDENTIALS, BROKER_CREDENTIAL)
        try:
            _wait_for_entry(entered, owner)
            joiner = pool.submit(verifier.verify, 'farm', _CREDENTIALS, BROKER_CREDENTIAL)
            _wait_for_entry(joined, joiner)
            with pytest.raises(ServerBusyError):
                verifier.verify('farm', _CREDENTIALS, BROKER_CREDENTIAL)
        finally:
            release.set()
        for worker in (owner, joiner):
            if outcome == 'error':
                with pytest.raises(RuntimeError, match='check failed'):
                    worker.result()
            else:
                assert worker.result() == ('primary' if outcome == 'match' else None)
    verify.assert_called_once()
    assert waiting.try_enter()
    assert not waiting.try_enter()
    waiting.leave()
    # The sole verification slot is free, including after a failed computation.
    verify.side_effect = None
    verify.return_value = False
    assert verifier.verify('farm', _CREDENTIALS, 'different') is None


def test_only_matching_keyed_digests_are_remembered(monkeypatch: pytest.MonkeyPatch) -> None:
    verifier = SecretVerifier(waiting=WaitingShare(1), work=1, clock=lambda: 0.0)
    verify = Mock(wraps=_secrets.verify_secret)
    monkeypatch.setattr(_secrets, 'verify_secret', verify)
    assert verifier.verify('farm', _CREDENTIALS, BROKER_CREDENTIAL) == 'primary'
    for _ in range(2):
        assert verifier.verify('farm', _CREDENTIALS, BROKER_CREDENTIAL[:-1]) is None
    assert verify.call_count == 3
    expected = hmac.new(
        _admission._PROCESS_KEY, BROKER_CREDENTIAL.encode(), hashlib.sha256
    ).digest()
    assert verifier._matches == {('farm', 'primary'): (expected, 600.0)}


def test_same_secret_for_a_different_client_gets_an_independent_decision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = SecretVerifier(waiting=WaitingShare(0), work=1, clock=lambda: 0.0)
    entered = threading.Event()
    release = threading.Event()

    def check(_secret: str, secret_hash: str) -> bool:
        if secret_hash == BROKER_HASH:
            entered.set()
            release.wait()
            return True
        return False

    other_credentials = (('primary', 'other-hash'),)
    verify = Mock(side_effect=check)
    monkeypatch.setattr(_secrets, 'verify_secret', verify)
    with ThreadPoolExecutor(max_workers=1) as pool:
        owner = pool.submit(verifier.verify, 'farm', _CREDENTIALS, BROKER_CREDENTIAL)
        try:
            _wait_for_entry(entered, owner)
            assert verifier.verify('other', other_credentials, BROKER_CREDENTIAL) is None
        finally:
            release.set()
        assert owner.result() == 'primary'
    assert verifier.verify('other', other_credentials, BROKER_CREDENTIAL) is None
    assert verify.call_count == 3


def test_success_is_remembered_until_600_seconds_after_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = 10.0
    verifier = SecretVerifier(waiting=WaitingShare(1), work=1, clock=lambda: now)
    check = _secrets.verify_secret

    def advance_during_check(secret: str, secret_hash: str) -> bool:
        nonlocal now
        now += 10
        return check(secret, secret_hash)

    verify = Mock(side_effect=advance_during_check)
    monkeypatch.setattr(_secrets, 'verify_secret', verify)
    assert verifier.verify('farm', _CREDENTIALS, BROKER_CREDENTIAL) == 'primary'
    now += 599.0
    assert verifier.verify('farm', _CREDENTIALS, BROKER_CREDENTIAL) == 'primary'
    verify.assert_called_once_with(BROKER_CREDENTIAL, BROKER_HASH)
    now += 1
    assert verifier.verify('farm', _CREDENTIALS, BROKER_CREDENTIAL) == 'primary'
    assert verify.call_count == 2
