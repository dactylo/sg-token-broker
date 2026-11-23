import datetime
import hashlib
import json
import threading
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock, Mock

import pytest
import requests

from sg_token_broker import _client as client_module
from sg_token_broker import _service
from sg_token_broker._client import (
    BrokerClient,
    BrokerClientError,
    ClientOptions,
    KeyAcquirer,
    TokenResponse,
    resolve_client_settings,
)
from sg_token_broker._retry import RetryTiming
from tests._timeouts import STALL_TIMEOUT_SECONDS
from tests.conftest import BROKER_CREDENTIAL

_INVALIDATED = (
    'broker returned a token already reported rejected; no further request could be made'
)
_REST_TYPE = _service._REST_TYPE
_SESSION_TYPE = _service._SESSION_TYPE


class TestTokenResponseRepr:
    def test_repr_hides_the_token(self) -> None:
        value = 'secret-token-value'
        token = TokenResponse(
            token=value,
            token_type=_SESSION_TYPE,
            scope='read_all',
            site_url='https://studio.example.com',
            expires_at=datetime.datetime(2026, 7, 10, tzinfo=datetime.UTC),
        )
        assert value not in repr(token)
        assert value not in str(token)


class _CannedResponse:
    def __init__(self, status: int, body: bytes, retry_after: str | None = None) -> None:
        self.headers = {} if retry_after is None else {'Retry-After': retry_after}
        self.status_code = status
        self._body = body

    def json(self) -> object:
        return json.loads(self._body)


class _Clock:
    def __init__(self, now: datetime.datetime) -> None:
        self.now = now
        self.seconds = 0.0
        self.sleeps: list[float] = []

    def advance(self, seconds: float) -> None:
        self.now += datetime.timedelta(seconds=seconds)
        self.seconds += seconds

    def monotonic(self) -> float:
        return self.seconds

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.advance(seconds)


class TestBrokerClient:
    def test_backslash_authority_raises_before_request(self) -> None:
        with pytest.raises(BrokerClientError, match='broker URL'):
            BrokerClient('http://evil.example\\@localhost', 'farm', 's')

    def test_bad_credentials_raise(self, http_only_broker_url: str) -> None:
        client = BrokerClient(
            http_only_broker_url,
            'farm',
            BROKER_CREDENTIAL[:-1],
            timeout=STALL_TIMEOUT_SECONDS,
            retries=0,
            max_wait=STALL_TIMEOUT_SECONDS,
        )
        with pytest.raises(BrokerClientError, match='401'):
            client.fetch_token('read_all')

    def test_broker_reuse_window_costs_one_call_inside_the_margin(
        self, broker_url: str, clock: _Clock
    ) -> None:
        session, responses = _recording_session()
        client = BrokerClient(
            broker_url,
            'farm',
            BROKER_CREDENTIAL,
            session=session,
            timeout=STALL_TIMEOUT_SECONDS,
            retries=0,
            max_wait=STALL_TIMEOUT_SECONDS,
        )
        _inject_timing(client, clock, draw=1.0)
        first = client.fetch_token('read_all')

        # The broker keeps returning this token, with this deadline, until it expires.
        clock.advance((first.expires_at - clock.now).total_seconds() - 50)
        assert client.fetch_token('read_all').token == first.token
        for _ in range(3):
            clock.advance(10)
            assert client.fetch_token('read_all').token == first.token

        assert len(responses) == 2

    def test_env_discovery(self, broker_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv('SG_TOKEN_BROKER_URL', broker_url)
        monkeypatch.setenv('SG_TOKEN_BROKER_CLIENT_ID', 'farm')
        monkeypatch.setenv('SG_TOKEN_BROKER_CLIENT_SECRET', BROKER_CREDENTIAL)
        assert (
            BrokerClient(timeout=STALL_TIMEOUT_SECONDS, retries=0, max_wait=STALL_TIMEOUT_SECONDS)
            .fetch_token('read_all')
            .token
        )

    def test_failed_force_refresh_discards_the_cached_token(self, clock: _Clock) -> None:
        first, second = 'first-value', 'second-value'
        client, _ = _scripted_client(
            _CannedResponse(200, _expiring_body(clock, first, 3600)),
            _CannedResponse(503, b'{}'),
            _CannedResponse(200, _expiring_body(clock, second, 3600)),
            clock=clock,
        )
        assert client.fetch_token('read_all').token == first

        with pytest.raises(BrokerClientError, match='503'):
            client.fetch_token('read_all', force_refresh=True)

        assert client.fetch_token('read_all').token == second

    def test_final_transport_error_remains_a_reachability_error(self) -> None:
        client, _ = _scripted_client(requests.ConnectionError('connection lost'))

        with pytest.raises(BrokerClientError) as caught:
            client.fetch_token('read_all')

        assert str(caught.value) == (
            'no token after 1 attempt(s) (retries=0); last failure: '
            'cannot reach broker at https://broker.example: ConnectionError'
        )

    def test_force_refresh_replaces_the_cached_token(self, clock: _Clock) -> None:
        first, second = 'first-value', 'second-value'
        client, session = _scripted_client(
            _CannedResponse(200, _expiring_body(clock, first, 3600)),
            _CannedResponse(200, _expiring_body(clock, second, 3600)),
            clock=clock,
        )

        assert client.fetch_token('read_all').token == first
        assert client.fetch_token('read_all').token == first
        assert client.fetch_token('read_all', force_refresh=True).token == second
        assert client.fetch_token('read_all').token == second
        assert len(session.calls) == 2

    def test_https_broker_url_accepted(self) -> None:
        BrokerClient('https://broker.studio.internal', 'farm', 's')

    @pytest.mark.parametrize('client_id', ['a:b', 'x' * 65])
    def test_invalid_client_ids_are_rejected_before_any_request(self, client_id: str) -> None:
        with pytest.raises(BrokerClientError, match='client id must be'):
            BrokerClient('https://broker.example', client_id, 'secret')

    @pytest.mark.parametrize(
        'status', [429, 503, None], ids=['rate-limited', 'server-error', 'unreachable']
    )
    def test_margin_refresh_failure_keeps_the_cached_token(
        self, clock: _Clock, status: int | None
    ) -> None:
        first = 'first-value'
        client, session = _scripted_client(
            _CannedResponse(200, _expiring_body(clock, first, 300)),
            requests.ConnectionError('down') if status is None else _CannedResponse(status, b'{}'),
            _CannedResponse(503, b'{}'),
            clock=clock,
            draw=1.0,
        )
        assert client.fetch_token('read_all').token == first

        clock.advance(250)
        assert client.fetch_token('read_all').token == first
        clock.advance(40)
        assert client.fetch_token('read_all').token == first
        assert len(session.calls) == 2

        clock.advance(21)
        assert client.fetch_token('read_all').token == first
        assert len(session.calls) == 3

    @pytest.mark.parametrize(
        'status', [429, 503, None], ids=['rate-limited', 'server-error', 'unreachable']
    )
    def test_margin_refresh_failing_after_expiry_raises(
        self, clock: _Clock, status: int | None
    ) -> None:
        first, second = 'first-value', 'second-value'

        def fail_after_expiry() -> _CannedResponse | requests.RequestException:
            clock.advance(6)
            if status is None:
                return requests.ConnectionError('down')
            return _CannedResponse(status, b'{}')

        client, session = _scripted_client(
            _CannedResponse(200, _expiring_body(clock, first, 300, token_type=_REST_TYPE)),
            fail_after_expiry,
            _CannedResponse(200, _expiring_body(clock, second, 900, token_type=_REST_TYPE)),
            clock=clock,
        )
        assert client.fetch_token('read_all', 'rest').token == first

        clock.advance(295)
        with pytest.raises(BrokerClientError):
            client.fetch_token('read_all', 'rest')

        assert client.fetch_token('read_all', 'rest').token == second
        assert len(session.calls) == 3

    @pytest.mark.parametrize('status', [401, 403])
    def test_margin_refusal_raises(self, clock: _Clock, status: int) -> None:
        client, _ = _scripted_client(
            _CannedResponse(200, _expiring_body(clock, 'first-value', 300)),
            _CannedResponse(status, b'{"detail":"refused"}'),
            clock=clock,
        )
        client.fetch_token('read_all')

        clock.advance(250)
        with pytest.raises(BrokerClientError, match=str(status)):
            client.fetch_token('read_all')

    @pytest.mark.parametrize(
        ('broker_url', 'client_id', 'client_secret'),
        [
            (None, None, None),
            (None, 'farm', 'secret'),
            ('https://broker.example', None, 'secret'),
            ('https://broker.example', 'farm', None),
        ],
        ids=['all', 'url', 'client-id', 'client-secret'],
    )
    def test_missing_settings_raise(
        self,
        monkeypatch: pytest.MonkeyPatch,
        broker_url: str | None,
        client_id: str | None,
        client_secret: str | None,
    ) -> None:
        for var in (
            'SG_TOKEN_BROKER_URL',
            'SG_TOKEN_BROKER_CLIENT_ID',
            'SG_TOKEN_BROKER_CLIENT_SECRET',
        ):
            monkeypatch.delenv(var, raising=False)
        with pytest.raises(BrokerClientError) as exc_info:
            BrokerClient(broker_url, client_id, client_secret)
        message = str(exc_info.value)
        assert 'broker settings missing' in message
        assert 'SG_TOKEN_BROKER_URL' in message
        assert 'SG_TOKEN_BROKER_CLIENT_ID' in message
        assert 'SG_TOKEN_BROKER_CLIENT_SECRET' in message

    def test_non_ascii_credentials_are_rejected_before_any_request(self) -> None:
        with pytest.raises(BrokerClientError, match='printable ASCII'):
            BrokerClient('https://broker.example', 'cid', 'sm\u2019art')

    def test_non_server_error_is_not_retried(self, clock: _Clock) -> None:
        client, session = _scripted_client(
            _CannedResponse(400, b'{"detail":"bad request"}'), clock=clock, retries=2
        )
        with pytest.raises(BrokerClientError, match='400'):
            client.fetch_token('read_all')
        assert len(session.calls) == 1
        assert clock.sleeps == []

    @pytest.mark.parametrize(
        ('seconds_to_expiry', 'expected_requests'),
        [(61.0, 1), (60.0, 2), (59.0, 2)],
        ids=['outside', 'boundary', 'inside'],
    )
    def test_refresh_margin_boundary(
        self, clock: _Clock, seconds_to_expiry: float, expected_requests: int
    ) -> None:
        first, second = 'first-value', 'second-value'
        client, session = _scripted_client(
            _CannedResponse(200, _expiring_body(clock, first, 300)),
            _CannedResponse(200, _expiring_body(clock, second, 900)),
            clock=clock,
        )
        client.fetch_token('read_all')

        clock.advance(300 - seconds_to_expiry)
        result = client.fetch_token('read_all')

        assert len(session.calls) == expected_requests
        assert result.token == (first if expected_requests == 1 else second)

    @pytest.mark.parametrize('first', ['http', 'transport'])
    def test_final_server_error_reports_its_detail(self, clock: _Clock, first: str) -> None:
        failure = _CannedResponse(502, b'{"detail": "SG upstream request failed"}')
        initial = requests.ConnectionError('connection lost') if first == 'transport' else failure
        client, session = _scripted_client(initial, failure, clock=clock, retries=1, draw=1.0)

        with pytest.raises(BrokerClientError) as caught:
            client.fetch_token('read_all')

        assert str(caught.value) == (
            'no token after 2 attempt(s) (retries=1); last failure: '
            'broker request failed with HTTP 502: SG upstream request failed'
        )
        assert len(session.calls) == 2
        assert clock.sleeps == [0.5]

    def test_remote_http_broker_url_raises(self) -> None:
        with pytest.raises(BrokerClientError, match='https'):
            BrokerClient('http://broker.studio.internal', 'farm', 's')

    def test_request_exceptions_use_retries_plus_one_and_jitter(self, clock: _Clock) -> None:
        client, session = _scripted_client(
            requests.ConnectionError('first'),
            requests.Timeout('second'),
            _CannedResponse(200, _token_body()),
            clock=clock,
            retries=2,
            draw=0.5,
        )
        assert client.fetch_token('read_all').scope == 'read_all'
        assert len(session.calls) == 3
        assert clock.sleeps == [0.25, 0.5]

    def test_token_issued_inside_the_margin_renews_then_spaces_requests(
        self, clock: _Clock
    ) -> None:
        first, second = 'first', 'second'
        body = _expiring_body(clock, first, 30)
        client, session = _scripted_client(
            _CannedResponse(200, body),
            _CannedResponse(200, body),
            _CannedResponse(200, _expiring_body(clock, second, 90)),
            clock=clock,
        )
        assert client.fetch_token('read_all').token == first
        assert client.fetch_token('read_all').token == first
        clock.advance(9)
        assert client.fetch_token('read_all').token == first
        assert len(session.calls) == 2
        clock.advance(1)
        assert client.fetch_token('read_all').token == second


class TestBrokerClientTuning:
    @pytest.mark.parametrize(
        'timeout',
        [0.0, -1.0, float('nan'), float('inf'), float('-inf')],
    )
    def test_invalid_timeouts_raise(self, timeout: float) -> None:
        with pytest.raises(ValueError, match='timeout must be finite and greater than zero'):
            BrokerClient('https://broker.example', 'farm', 's', timeout=timeout)

    @pytest.mark.parametrize('margin', [-1.0, float('nan'), float('inf'), float('-inf')])
    def test_invalid_refresh_margins_raise(self, margin: float) -> None:
        with pytest.raises(ValueError, match='refresh_margin must be finite and >= 0'):
            BrokerClient('https://broker.example', 'farm', 's', refresh_margin=margin)

    def test_negative_retries_raise(self) -> None:
        with pytest.raises(ValueError, match='retries'):
            BrokerClient('https://broker.example', 'farm', 's', retries=-1)

    def test_zero_refresh_margin_is_accepted(self) -> None:
        client = BrokerClient('https://broker.example', 'farm', 's', refresh_margin=0.0)
        assert client._acquirer._options.refresh_margin == 0.0


class TestResponseValidation:
    def test_empty_token_raises(self) -> None:
        body = _token_body(token='')
        with pytest.raises(BrokerClientError, match='token'):
            _response_client(body).fetch_token('read_all')

    def test_integer_expiry_raises(self) -> None:
        body = _token_body(expires_at=1760000000)
        with pytest.raises(BrokerClientError, match='expires_at'):
            _response_client(body).fetch_token('read_all')

    def test_list_token_raises(self) -> None:
        body = _token_body(token=['tok'])
        with pytest.raises(BrokerClientError, match='token'):
            _response_client(body).fetch_token('read_all')

    def test_missing_field_raises(self) -> None:
        body = json.loads(_token_body())
        del body['scope']
        body = json.dumps(body).encode()
        with pytest.raises(BrokerClientError, match='scope'):
            _response_client(body).fetch_token('read_all')

    def test_naive_expiry_raises(self) -> None:
        body = _token_body(expires_at='2026-07-10T12:00:00')
        with pytest.raises(BrokerClientError, match='expires_at'):
            _response_client(body).fetch_token('read_all')

    def test_non_dict_body_raises(self) -> None:
        body = b'["nope"]'
        with pytest.raises(BrokerClientError, match='malformed'):
            _response_client(body).fetch_token('read_all')

    def test_non_json_200_raises_client_error(self) -> None:
        body = b'<html>oops</html>'
        with pytest.raises(BrokerClientError, match='JSON'):
            _response_client(body).fetch_token('read_all')

    @pytest.mark.parametrize(
        ('field', 'returned'),
        [('scope', 'different_scope'), ('token_type', 'rest')],
    )
    def test_response_must_match_the_request_before_caching(
        self, field: str, returned: str
    ) -> None:
        valid = 'valid'
        credential = 'returned-credential'
        body = _token_body(token=credential, **{field: returned})
        client, session = _scripted_client(_CannedResponse(200, body), _success(valid))

        with pytest.raises(BrokerClientError, match=field) as excinfo:
            client.fetch_token('read_all')

        assert credential not in str(excinfo.value)
        assert client.fetch_token('read_all').token == valid
        assert len(session.calls) == 2

    def test_valid_response_parses(self) -> None:
        body = _token_body()
        token = _response_client(body).fetch_token('read_all')
        assert token.token == json.loads(body)['token']
        assert token.expires_at.tzinfo is not None


class _ScriptedSession:
    def __init__(
        self,
        *outcomes: _CannedResponse
        | requests.RequestException
        | Callable[[], _CannedResponse | requests.RequestException],
    ) -> None:
        self.calls: list[dict[str, object]] = []
        self._outcomes = iter(outcomes)

    def post(self, url: str, **kwargs: object) -> _CannedResponse:
        self.calls.append({'url': url, **kwargs})
        outcome = next(self._outcomes)
        if callable(outcome):
            outcome = outcome()
        if isinstance(outcome, requests.RequestException):
            raise outcome
        return outcome


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _inject_timing(client: BrokerClient, clock: _Clock, *, draw: float) -> None:
    client._acquirer._timing = RetryTiming(clock.monotonic, clock.sleep, lambda: draw)


def _recording_session() -> tuple[requests.Session, list[requests.Response]]:
    session = requests.Session()
    responses: list[requests.Response] = []

    def record(response: requests.Response, **_kwargs: object) -> None:
        responses.append(response)

    session.hooks['response'].append(record)
    return session, responses


def _scripted_client(
    *outcomes: _CannedResponse
    | requests.RequestException
    | Callable[[], _CannedResponse | requests.RequestException],
    clock: _Clock | None = None,
    retries: int | None = 0,
    draw: float = 0.0,
    max_wait: float = STALL_TIMEOUT_SECONDS,
) -> tuple[BrokerClient, _ScriptedSession]:
    session = _ScriptedSession(*outcomes)
    client = BrokerClient(
        'https://broker.example',
        'farm',
        's',
        timeout=STALL_TIMEOUT_SECONDS,
        retries=retries,
        max_wait=max_wait,
        session=cast('requests.Session', session),
    )
    _inject_timing(client, clock or _Clock(datetime.datetime.now(datetime.UTC)), draw=draw)
    return client, session


def _response_client(body: bytes) -> BrokerClient:
    return _scripted_client(_CannedResponse(200, body))[0]


def _signal_when_enrolled(
    client: BrokerClient, monkeypatch: pytest.MonkeyPatch
) -> threading.Event:
    enrolled = threading.Event()
    condition = client._acquirer._keys['read_all', 'session'].condition
    wait = condition.wait

    def waiting() -> bool:
        enrolled.set()
        return wait()

    monkeypatch.setattr(condition, 'wait', waiting)
    return enrolled


def _token_body(**overrides: object) -> bytes:
    body: dict[str, object] = {
        'token': 'tok',
        'token_type': 'session',
        'scope': 'read_all',
        'site_url': 'https://studio.example.com',
        'expires_at': '2026-07-10T12:00:00+00:00',
    }
    body.update(overrides)
    return json.dumps(body).encode()


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    # Give the client its own clock without changing the datetime module for other threads.
    real_datetime = datetime.datetime
    clock = _Clock(real_datetime(2026, 8, 24, 12, 0, tzinfo=datetime.UTC))

    class FrozenDateTime(real_datetime):
        @classmethod
        def now(cls, tz: datetime.tzinfo | None = None) -> datetime.datetime:
            assert tz is datetime.UTC
            return clock.now

    monkeypatch.setattr(
        client_module,
        'datetime',
        SimpleNamespace(UTC=datetime.UTC, datetime=FrozenDateTime, timedelta=datetime.timedelta),
    )
    monkeypatch.setattr(_service, '_utcnow', lambda: clock.now)
    return clock


def _expire_at_registry_lock(
    client: BrokerClient, session: _ScriptedSession, clock: _Clock
) -> None:
    lock = client._acquirer._lock
    advanced = 0

    def acquire() -> None:
        nonlocal advanced
        lock.acquire()
        if len(session.calls) > advanced:
            advanced = len(session.calls)
            clock.advance(2)

    def release(*_args: object) -> None:
        lock.release()

    wrapper = MagicMock()
    wrapper.__enter__.side_effect = acquire
    wrapper.__exit__.side_effect = release
    client._acquirer._lock = wrapper


def _expiring_body(
    clock: _Clock, value: str, seconds: float, *, token_type: str = _SESSION_TYPE
) -> bytes:
    expires_at = clock.now + datetime.timedelta(seconds=seconds)
    return _token_body(token=value, token_type=token_type, expires_at=expires_at.isoformat())


def _body(session: _ScriptedSession, n: int = -1) -> dict[str, object]:
    return cast('dict[str, object]', session.calls[n]['json'])


def _success(token: str, *, scope: str = 'read_all') -> _CannedResponse:
    return _CannedResponse(
        200, _token_body(token=token, scope=scope, expires_at='2099-01-01T00:00:00Z')
    )


def test_batched_rejections_are_sent_in_the_first_request(clock: _Clock) -> None:
    fresh = 'new'
    session = _ScriptedSession(_success(fresh))
    credential = 'test-credential'
    settings = resolve_client_settings('https://broker.example/', 'farm', credential)
    assert credential not in repr(settings)
    acquirer = KeyAcquirer(
        settings=settings,
        session=cast('requests.Session', session),
        options=ClientOptions(timeout=STALL_TIMEOUT_SECONDS, max_wait=STALL_TIMEOUT_SECONDS),
        timing=RetryTiming(clock.monotonic, clock.sleep, lambda: 0.0),
    )
    reported = ('one', 'two', 'three')
    assert acquirer.fetch('read_all', 'session', rejected_tokens=reported).token == fresh
    assert len(session.calls) == 1
    assert _body(session) == {
        'scope': 'read_all',
        'token_type': 'session',
        'rejected_tokens_sha256': [_digest(t) for t in reported],
    }


def test_broker_restart_accepts_token_outside_reported_history() -> None:
    older, fresh = 'older', 'after-restart'
    client, session = _scripted_client(_success('before-restart'), _success(fresh))
    previous = client.fetch_token('read_all', rejected_token=older)
    replacement = client.fetch_token('read_all', rejected_token=previous.token)
    assert replacement.token == fresh
    assert _body(session)['rejected_tokens_sha256'] == [_digest(older), _digest(previous.token)]


def test_cold_rate_limit_waits_for_header_and_jitter(clock: _Clock) -> None:
    fresh = 'available'
    client, session = _scripted_client(
        _CannedResponse(429, b'{}', retry_after='3'),
        _success(fresh),
        clock=clock,
        retries=None,
        draw=0.5,
    )
    assert client.fetch_token('read_all').token == fresh
    assert clock.sleeps == [3.25]
    assert len(session.calls) == 2


def test_expired_rest_token_uses_cold_backoff_when_service_is_down(clock: _Clock) -> None:
    first, fresh = 'expired', 'fresh'
    client, session = _scripted_client(
        _CannedResponse(200, _expiring_body(clock, first, 180, token_type=_REST_TYPE)),
        _CannedResponse(503, b'{}'),
        _CannedResponse(200, _expiring_body(clock, fresh, 500, token_type=_REST_TYPE)),
        clock=clock,
        retries=None,
        draw=0.5,
    )
    assert client.fetch_token('read_all', 'rest').token == first
    clock.advance(180)
    assert client.fetch_token('read_all', 'rest').token == fresh
    assert clock.sleeps == [0.25]
    assert len(session.calls) == 3


def test_first_and_subsequent_session_renewals_are_spread(clock: _Clock) -> None:
    shared, early_value, late_value = 'shared', 'early', 'late'
    first = _CannedResponse(200, _expiring_body(clock, shared, 300))
    failure = _CannedResponse(503, b'{}', retry_after='60')
    early, early_session = _scripted_client(
        first, failure, _success(early_value), clock=clock, draw=1
    )
    late, late_session = _scripted_client(
        first, failure, _success(late_value), clock=clock, draw=0
    )
    for client in (early, late):
        assert client.fetch_token('read_all').token == shared
    clock.advance(180)
    for client in (early, late):
        assert client.fetch_token('read_all').token == shared
    assert [len(early_session.calls), len(late_session.calls)] == [2, 1]
    clock.advance(60)
    assert late.fetch_token('read_all').token == shared
    # Both renewals get the same header. Early waits 110 seconds; late waits 60.
    clock.advance(49)
    assert early.fetch_token('read_all').token == shared
    clock.advance(1)
    assert early.fetch_token('read_all').token == early_value
    clock.advance(9)
    assert late.fetch_token('read_all').token == shared
    clock.advance(1)
    assert late.fetch_token('read_all').token == late_value
    assert clock.sleeps == []


def test_forbidden_scopes_release_empty_client_keys() -> None:
    client, _ = _scripted_client(*[_CannedResponse(403, b'{}')] * 3)
    for scope in ('one', 'two', 'three'):
        with pytest.raises(BrokerClientError, match='403'):
            client.fetch_token(scope)
    assert not client._acquirer._keys


def test_force_refresh_with_history_detects_old_broker() -> None:
    rejected, fresh = 'X', 'Y'
    client, session = _scripted_client(_success(fresh), _success(rejected))
    assert client.fetch_token('read_all', rejected_token=rejected).token == fresh
    with pytest.raises(BrokerClientError) as caught:
        client.fetch_token('read_all', force_refresh=True)
    assert (
        str(caught.value)
        == 'broker returned a token already reported rejected; upgrade every broker to 0.3.0'
    )
    assert _body(session)['rejected_tokens_sha256'] == [_digest(rejected)]


def test_history_tracks_recent_distinct_reports_for_24_hours(clock: _Clock) -> None:
    client, session = _scripted_client(*(_success(f'fresh-{i}') for i in range(12)), clock=clock)
    for token in 'abcdefgh':
        client.fetch_token('read_all', rejected_token=token)
    clock.advance(1)
    for token in 'ai':
        client.fetch_token('read_all', rejected_token=token)
    assert _body(session)['rejected_tokens_sha256'] == [_digest(t) for t in 'cdefghai']
    clock.advance(86400 - 1)
    client.fetch_token('read_all', force_refresh=True)
    assert _body(session)['rejected_tokens_sha256'] == [_digest(t) for t in 'ai']
    clock.advance(1)
    client.fetch_token('read_all', force_refresh=True)
    assert 'rejected_tokens_sha256' not in _body(session)


def test_key_retirement_waits_for_a_caller_about_to_enroll(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, session = _scripted_client(_CannedResponse(403, b'{}'), _success('replacement'))
    acquire = client._acquirer
    enroll = acquire._fetch

    def before_enrollment(
        key: client_module._Key,
        identity: tuple[str, str],
        call: client_module._Call,
        rejected_tokens: Sequence[str],
        *,
        force_refresh: bool,
    ) -> TokenResponse:
        monkeypatch.setattr(acquire, '_fetch', enroll)
        with pytest.raises(BrokerClientError, match='403'):
            client.fetch_token('read_all')
        return enroll(key, identity, call, rejected_tokens, force_refresh=force_refresh)

    monkeypatch.setattr(acquire, '_fetch', before_enrollment)
    first = client.fetch_token('read_all')
    assert client.fetch_token('read_all') == first
    assert len(session.calls) == 2


def test_missing_ca_bundle_is_a_setup_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = tmp_path / 'missing-ca.pem'
    monkeypatch.setenv('REQUESTS_CA_BUNDLE', str(missing))
    with requests.Session() as session:
        post = Mock(wraps=session.post)
        monkeypatch.setattr(session, 'post', post)
        client = BrokerClient(
            'https://127.0.0.1:1',
            'c',
            's',
            session=session,
            timeout=STALL_TIMEOUT_SECONDS,
            max_wait=STALL_TIMEOUT_SECONDS,
        )
        client._acquirer._timing = RetryTiming(sleep=Mock(side_effect=AssertionError('retry')))
        with pytest.raises(BrokerClientError) as caught:
            client.fetch_token('read_all')
        post.assert_called_once()
    assert caught.value.__suppress_context__
    assert str(caught.value).startswith(
        'broker request could not be sent: Could not find a suitable TLS CA certificate bundle'
    )
    assert str(missing) in str(caught.value)


def test_old_broker_diagnosis_uses_sent_history_even_after_expiry(clock: _Clock) -> None:
    rejected = 'old'

    def late() -> _CannedResponse:
        clock.advance(86400)
        return _success(rejected)

    client, _ = _scripted_client(late, clock=clock)
    with pytest.raises(BrokerClientError, match='upgrade every broker'):
        client.fetch_token('read_all', rejected_token=rejected)


def test_other_scope_completes_while_request_is_held() -> None:
    first_value, second_value = 'first', 'second'
    dispatched, release = threading.Event(), threading.Event()

    def held() -> _CannedResponse:
        dispatched.set()
        release.wait()
        return _success(first_value)

    client, _ = _scripted_client(held, _success(second_value, scope='another'))
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(client.fetch_token, 'read_all')
        first.add_done_callback(lambda _: dispatched.set())
        try:
            dispatched.wait()
            assert client.fetch_token('another').token == second_value
        finally:
            release.set()
        assert first.result().token == first_value


@pytest.mark.parametrize('processes', [2, 8])
def test_proxy_recovery_with_an_older_starting_token(processes: int) -> None:
    caches = [f'stale-{i}' for i in range(processes)]

    def dispatch() -> _CannedResponse:
        process = (len(session.calls) - 1) % processes
        if _digest(caches[process]) in cast('list[str]', _body(session)['rejected_tokens_sha256']):
            caches[process] = 'fresh'
        return _success(caches[process])

    client, session = _scripted_client(*[dispatch] * (processes + 1))
    issued = 'older'
    for _ in range(processes + 1):
        issued = client.fetch_token('read_all', rejected_token=issued).token
        if issued == 'fresh':
            break
    assert issued == 'fresh'


@pytest.mark.parametrize('max_wait', [0.0, -1.0, float('inf'), float('nan')])
def test_max_wait_must_be_positive_and_finite(max_wait: float) -> None:
    with pytest.raises(ValueError, match='max_wait'):
        BrokerClient('https://broker.example', 'farm', 's', max_wait=max_wait)


@pytest.mark.parametrize('succeed', [False, True])
def test_budget_limits_request_starts_and_accepts_late_success(
    clock: _Clock, *, succeed: bool
) -> None:
    late = 'late'

    def at_deadline() -> _CannedResponse:
        clock.advance(6 if succeed else 5)
        return _success(late) if succeed else _CannedResponse(503, b'{"detail":"busy"}')

    client, session = _scripted_client(at_deadline, clock=clock, retries=None, max_wait=5)
    if succeed:
        assert client.fetch_token('read_all').token == late
    else:
        with pytest.raises(BrokerClientError) as caught:
            client.fetch_token('read_all')
        assert (
            str(caught.value) == 'max_wait 5s exhausted; last failure: '
            'broker request failed with HTTP 503: busy'
        )
    assert len(session.calls) == 1
    assert clock.sleeps == []


def test_reported_session_never_falls_back_on_failure() -> None:
    rejected = 'rejected'
    client, _ = _scripted_client(_success(rejected), _CannedResponse(503, b'{"detail":"busy"}'))
    client.fetch_token('read_all')
    with pytest.raises(BrokerClientError) as caught:
        client.fetch_token('read_all', rejected_token=rejected)
    assert (
        str(caught.value) == 'no token after 1 attempt(s) (retries=0); last failure: '
        'broker request failed with HTTP 503: busy'
    )


def test_reporting_older_token_always_contacts_broker() -> None:
    older, cached, fresh = 'X', 'Y', 'Z'
    client, session = _scripted_client(_success(cached), _success(fresh))
    assert client.fetch_token('read_all').token == cached
    assert client.fetch_token('read_all', rejected_token=older).token == fresh
    assert len(session.calls) == 2
    assert _body(session)['rejected_tokens_sha256'] == [_digest(older)]


def test_rest_fallback_lasts_until_expiry_then_waits_for_permission(clock: _Clock) -> None:
    first, fresh = 'cached', 'fresh'
    client, session = _scripted_client(
        _CannedResponse(200, _expiring_body(clock, first, 10, token_type=_REST_TYPE)),
        _CannedResponse(503, b'{}', retry_after='60'),
        _CannedResponse(200, _expiring_body(clock, fresh, 500, token_type=_REST_TYPE)),
        clock=clock,
    )
    for _ in range(2):
        assert client.fetch_token('read_all', 'rest').token == first
    clock.advance(9)
    assert client.fetch_token('read_all', 'rest').token == first
    assert len(session.calls) == 2
    clock.advance(1)
    assert client.fetch_token('read_all', 'rest').token == fresh
    assert clock.sleeps == [50]


@pytest.mark.parametrize('header', ['60', 'malformed', None])
def test_rest_without_usable_token_fails_before_sleeping(
    clock: _Clock, header: str | None
) -> None:
    # Expiry occurs during the failed renewal. The next call starts in the REST gap.
    def fail() -> _CannedResponse:
        clock.advance(1)
        return _CannedResponse(503, b'{}', retry_after=header)

    client, session = _scripted_client(
        _CannedResponse(200, _expiring_body(clock, 'rest', 1, token_type=_REST_TYPE)),
        fail,
        clock=clock,
        draw=0.0 if header == '60' else 1.0,
        max_wait=5,
    )
    client.fetch_token('read_all', 'rest')
    with pytest.raises(BrokerClientError, match='503'):
        client.fetch_token('read_all', 'rest')
    with pytest.raises(BrokerClientError) as caught:
        client.fetch_token('read_all', 'rest')
    attribution = ' (Retry-After from the broker)' if header == '60' else ''
    assert str(caught.value) == f'next request permitted in 60s, beyond max_wait 5s{attribution}'
    assert clock.sleeps == []
    assert len(session.calls) == 2


def test_retry_during_recovery_respects_the_renewal_interval(clock: _Clock) -> None:
    older, usable, fresh = 'old', 'usable', 'fresh'
    client, session = _scripted_client(
        _success(usable), _CannedResponse(503, b'{}'), _success(fresh), clock=clock
    )
    assert client.fetch_token('read_all').token == usable
    assert client.fetch_token('read_all', rejected_token=older).token == usable
    clock.advance(9)
    assert client.fetch_token('read_all').token == usable
    clock.advance(1)
    assert client.fetch_token('read_all').token == fresh
    assert _body(session)['rejected_tokens_sha256'] == [_digest(older)]


@pytest.mark.parametrize(
    'case', ['sender', 'joiner', 'later-budget', 'expired', '401', 'sg_rejected', 'retryable']
)
def test_shared_request_outcomes_and_followup_sender(
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    rejected, fresh = 'X', 'Y'
    dispatched, release = threading.Event(), threading.Event()
    senders: list[int] = []

    def held() -> _CannedResponse:
        senders.append(threading.get_ident())
        dispatched.set()
        release.wait()
        return {
            '401': _CannedResponse(401, b'{"detail":"bad credentials"}'),
            'sg_rejected': _CannedResponse(502, b'{"error":"sg_rejected","detail":"SG refused"}'),
            'retryable': _CannedResponse(503, b'{}'),
        }.get(case, _success(rejected))

    def followup() -> _CannedResponse:
        senders.append(threading.get_ident())
        return _success(fresh)

    client, session = _scripted_client(
        held,
        followup,
        clock=clock,
        retries=0 if case == 'joiner' else None,
        max_wait=5 if case in {'expired', 'later-budget'} else STALL_TIMEOUT_SECONDS,
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(client.fetch_token, 'read_all')
        first.add_done_callback(lambda _: dispatched.set())
        try:
            dispatched.wait()
            enrolled = _signal_when_enrolled(client, monkeypatch)
            if case == 'later-budget':
                clock.advance(4)
            second = pool.submit(client.fetch_token, 'read_all', rejected_token=rejected)
            second.add_done_callback(lambda _: enrolled.set())
            enrolled.wait()
            if case in {'expired', 'later-budget'}:
                clock.advance(5 if case == 'expired' else 1)
        finally:
            release.set()

        if case in {'401', 'sg_rejected', 'expired'}:
            errors = [first.exception(), second.exception()]
            message = {
                '401': 'broker refused (HTTP 401): bad credentials',
                'sg_rejected': 'broker request failed with HTTP 502: SG refused',
                'expired': f'max_wait 5s exhausted; last failure: {_INVALIDATED}',
            }[case]
            assert all(isinstance(error, BrokerClientError) for error in errors)
            assert [str(error) for error in errors] == [message, message]
            if case in {'401', 'sg_rejected'}:
                assert errors[1] is not None
                assert errors[1] is not errors[0]
                assert errors[1].__cause__ is errors[0]
            assert len(session.calls) == 1
        else:
            joiner_sends = case in {'joiner', 'later-budget'}
            if joiner_sends:
                with pytest.raises(BrokerClientError) as caught:
                    first.result()
                limit = (
                    'no token after 1 attempt(s) (retries=0)'
                    if case == 'joiner'
                    else 'max_wait 5s exhausted'
                )
                assert str(caught.value) == f'{limit}; last failure: {_INVALIDATED}'
            else:
                assert first.result().token == fresh
            assert second.result().token == fresh
            assert len(session.calls) == 2
            assert 'rejected_tokens_sha256' not in _body(session, 0)
            assert _body(session)['rejected_tokens_sha256'] == [_digest(rejected)]
            assert (senders[0] == senders[1]) == (not joiner_sends)


@pytest.mark.parametrize(
    ('wake_at', 'finish_at'), [(6.0, 6.0), (4.25, 10.0)], ids=['expired-at-start', 'late-response']
)
def test_followup_checks_every_enrolled_budget_at_dispatch(
    clock: _Clock, monkeypatch: pytest.MonkeyPatch, wake_at: float, finish_at: float
) -> None:
    sampled, dispatched, enrolled, release = (threading.Event() for _ in range(4))
    sender = threading.current_thread()
    fresh = 'Y'

    def sample() -> float:
        now = clock.monotonic()
        if not sampled.is_set():
            sampled.set()
            dispatched.wait()
        return now

    def busy() -> _CannedResponse:
        dispatched.set()
        enrolled.wait()
        return _CannedResponse(503, b'{"detail":"busy"}')

    def sleep(delay: float) -> None:
        clock.sleep(delay)
        clock.advance(wake_at - clock.seconds)

    def success() -> _CannedResponse:
        clock.advance(finish_at - clock.seconds)
        return _success(fresh)

    client, session = _scripted_client(busy, success, clock=clock, retries=None, max_wait=5)
    client._acquirer._timing = RetryTiming(sample, sleep, lambda: 0.5)
    acquire = client._acquirer._acquire

    def after_enrollment(
        key: client_module._Key, identity: tuple[str, str], call: client_module._Call
    ) -> TokenResponse:
        if threading.current_thread() is not sender:
            enrolled.set()
            release.wait()
        return acquire(key, identity, call)

    monkeypatch.setattr(client._acquirer, '_acquire', after_enrollment)
    with ThreadPoolExecutor(max_workers=1) as pool:
        earlier = pool.submit(client.fetch_token, 'read_all')
        earlier.add_done_callback(lambda _: enrolled.set())
        earlier.add_done_callback(lambda _: sampled.set())
        try:
            sampled.wait()
            clock.advance(4)
            assert client.fetch_token('read_all').token == fresh
        finally:
            dispatched.set()
            release.set()
        if wake_at >= 5:
            with pytest.raises(BrokerClientError) as caught:
                earlier.result()
            assert str(caught.value) == (
                'max_wait 5s exhausted; last failure: broker request failed with HTTP 503: busy'
            )
        else:
            assert earlier.result().token == fresh
    assert clock.sleeps == [0.25]
    assert len(session.calls) == 2


@pytest.mark.parametrize('case', ['recovered', 'fallback', 'retry', 'spent'])
def test_report_after_publication_before_handoff(
    clock: _Clock, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    rejected, replacement = 'X', 'Y'
    published, release = threading.Event(), threading.Event()
    initial = _CannedResponse(200, _expiring_body(clock, rejected, 30))
    reporter_succeeds = case in {'recovered', 'fallback'}
    recovery = _success(replacement) if reporter_succeeds else _CannedResponse(401, b'{}')
    outcomes = [initial, recovery]
    if case == 'fallback':
        outcomes.insert(1, _CannedResponse(503, b'{}', retry_after='0'))
    if case == 'retry':
        outcomes.append(_success(replacement))
    client, session = _scripted_client(*outcomes, clock=clock, retries=int(case == 'retry'))
    if case == 'fallback':
        assert client.fetch_token('read_all').token == rejected

    dispatch = client._acquirer._dispatch

    def after_publication(
        key: client_module._Key, identity: tuple[str, str], sent: tuple[str, ...], attempt: int
    ) -> None:
        dispatch(key, identity, sent, attempt)
        if not published.is_set():
            published.set()
            release.wait()

    monkeypatch.setattr(client._acquirer, '_dispatch', after_publication)
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(client.fetch_token, 'read_all')
        first.add_done_callback(lambda _: published.set())
        try:
            published.wait()
            if reporter_succeeds:
                assert client.fetch_token('read_all', rejected_token=rejected).token == replacement
            else:
                with pytest.raises(BrokerClientError, match='401'):
                    client.fetch_token('read_all', rejected_token=rejected)
        finally:
            release.set()
        if case == 'spent':
            with pytest.raises(BrokerClientError) as caught:
                first.result()
            assert (
                str(caught.value)
                == f'no token after 1 attempt(s) (retries=0); last failure: {_INVALIDATED}'
            )
        else:
            assert first.result().token == replacement
    assert len(session.calls) == len(outcomes)
    assert _body(session)['rejected_tokens_sha256'] == [_digest(rejected)]


@pytest.mark.parametrize('retries', [0, 1])
@pytest.mark.parametrize('when', ['receipt', 'delivery', 'fallback-delivery'])
def test_rest_expiry_checks_the_callers_remaining_allowance(
    clock: _Clock, monkeypatch: pytest.MonkeyPatch, when: str, retries: int
) -> None:
    first, replacement = 'first', 'fresh'
    initial = _CannedResponse(
        200, _expiring_body(clock, first, int(when != 'receipt'), token_type=_REST_TYPE)
    )
    fresh = _CannedResponse(200, _expiring_body(clock, replacement, 600, token_type=_REST_TYPE))
    outcomes = [initial, fresh]
    if when == 'fallback-delivery':
        outcomes.insert(1, _CannedResponse(503, b'{}'))
    client, session = _scripted_client(*outcomes, clock=clock, retries=retries)
    if when == 'fallback-delivery':
        assert client.fetch_token('read_all', 'rest').token == first
    publish = client_module._Key.finish

    def deliver(key: client_module._Key, result: TokenResponse | BaseException) -> None:
        if isinstance(result, TokenResponse) and result.token == first:
            assert when != 'receipt', 'expired at receipt but published'
            clock.advance(1)
        publish(key, result)

    monkeypatch.setattr(client_module._Key, 'finish', deliver)
    if retries:
        assert client.fetch_token('read_all', 'rest').token == replacement
    else:
        with pytest.raises(BrokerClientError, match='REST token expired'):
            client.fetch_token('read_all', 'rest')
    assert len(session.calls) == 1 + retries + (when == 'fallback-delivery')


@pytest.mark.parametrize('retries', [0, 1])
def test_rest_expiry_at_final_registry_lock(clock: _Clock, retries: int) -> None:
    fresh = 'fresh'
    client, session = _scripted_client(
        _CannedResponse(200, _expiring_body(clock, 'first', 1, token_type=_REST_TYPE)),
        _CannedResponse(200, _expiring_body(clock, fresh, 600, token_type=_REST_TYPE)),
        clock=clock,
        retries=retries,
    )
    _expire_at_registry_lock(client, session, clock)
    if retries:
        assert client.fetch_token('read_all', 'rest').token == fresh
    else:
        with pytest.raises(BrokerClientError, match='REST token expired'):
            client.fetch_token('read_all', 'rest')
    assert len(session.calls) == retries + 1


def test_spent_rest_fetch_releases_expired_cache(clock: _Clock) -> None:
    scopes = ('one', 'two', 'three')

    def response(scope: str) -> _CannedResponse:
        expiry = clock.now + datetime.timedelta(seconds=1)
        return _CannedResponse(
            200, _token_body(scope=scope, token_type=_REST_TYPE, expires_at=expiry.isoformat())
        )

    client, session = _scripted_client(
        *(partial(response, scope) for scope in scopes), _CannedResponse(403, b'{}'), clock=clock
    )
    _expire_at_registry_lock(client, session, clock)
    for scope in scopes:
        with pytest.raises(BrokerClientError, match='REST token expired'):
            client.fetch_token(scope, 'rest')
    clock.advance(25 * 3600)
    with pytest.raises(BrokerClientError, match='403'):
        client.fetch_token('unrelated')
    assert not client._acquirer._keys


def test_unrelated_fetch_reclaims_expired_failed_keys(clock: _Clock) -> None:
    client, _ = _scripted_client(
        *[_CannedResponse(503, b'{}', '10')] * 3, *[_CannedResponse(403, b'{}')] * 3, clock=clock
    )
    for scope in ('one', 'two', 'three'):
        with pytest.raises(BrokerClientError, match='503'):
            client.fetch_token(scope)
    with pytest.raises(BrokerClientError, match='403'):
        client.fetch_token('four', rejected_token=BROKER_CREDENTIAL)
    assert len(client._acquirer._keys) == 4
    clock.advance(10)
    with pytest.raises(BrokerClientError, match='403'):
        client.fetch_token('another')
    assert set(client._acquirer._keys) == {('four', 'session')}
    clock.advance(25 * 3600)
    with pytest.raises(BrokerClientError, match='403'):
        client.fetch_token('unrelated')
    assert not client._acquirer._keys
