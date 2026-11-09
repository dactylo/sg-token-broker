import datetime
import json
from collections.abc import Callable
from pathlib import Path
from typing import cast
from unittest.mock import Mock

import pytest
import requests

from sg_token_broker import _client as client_module
from sg_token_broker import _service
from sg_token_broker._client import BrokerClient, BrokerClientError, ClientOptions, TokenResponse
from tests.conftest import BROKER_CREDENTIAL, FakeSG

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
    def __init__(self, status: int, body: bytes) -> None:
        self.status_code = status
        self._body = body

    def json(self) -> object:
        return json.loads(self._body)


class _Clock:
    def __init__(self, now: datetime.datetime) -> None:
        self.now = now

    def advance(self, seconds: float) -> None:
        self.now += datetime.timedelta(seconds=seconds)


class TestBrokerClient:
    def test_backslash_authority_raises_before_request(self) -> None:
        with pytest.raises(BrokerClientError, match='broker URL'):
            BrokerClient('http://evil.example\\@localhost', 'farm', 's')

    def test_bad_credentials_raise(self, broker_url: str) -> None:
        client = BrokerClient(broker_url, 'farm', BROKER_CREDENTIAL[:-1])
        with pytest.raises(BrokerClientError, match='401'):
            client.fetch_token('read_all')

    def test_broker_reuse_window_costs_one_call_inside_the_margin(
        self, broker_url: str, clock: _Clock
    ) -> None:
        session, responses = _recording_session()
        client = BrokerClient(broker_url, 'farm', BROKER_CREDENTIAL, session=session)
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
        assert BrokerClient().fetch_token('read_all').token

    def test_failed_force_refresh_discards_the_cached_token(self) -> None:
        first, second = 'first-value', 'second-value'
        client, _ = _scripted_client(
            _CannedResponse(200, _future_token_body(first)),
            _CannedResponse(503, b'{}'),
            _CannedResponse(200, _future_token_body(second)),
        )
        assert client.fetch_token('read_all').token == first

        with pytest.raises(BrokerClientError, match='503'):
            client.fetch_token('read_all', force_refresh=True)

        assert client.fetch_token('read_all').token == second

    def test_fetch_token(self, broker_url: str, fake_sg: FakeSG) -> None:
        client = BrokerClient(broker_url, 'farm', BROKER_CREDENTIAL)
        token = client.fetch_token('read_all')
        assert token.token == fake_sg.canned_session
        assert token.token_type == _SESSION_TYPE
        assert token.site_url

    def test_final_transport_error_remains_a_reachability_error(self) -> None:
        client, _ = _scripted_client(requests.ConnectionError('connection lost'))

        with pytest.raises(BrokerClientError) as caught:
            client.fetch_token('read_all')

        assert str(caught.value) == (
            'cannot reach broker at https://broker.example: connection lost'
        )

    def test_force_refresh_replaces_the_cached_token(self) -> None:
        first, second = 'first-value', 'second-value'
        client, session = _scripted_client(
            _CannedResponse(200, _future_token_body(first)),
            _CannedResponse(200, _future_token_body(second)),
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
        )
        assert client.fetch_token('read_all').token == first

        clock.advance(250)
        assert client.fetch_token('read_all').token == first
        clock.advance(40)
        assert client.fetch_token('read_all').token == first
        assert len(session.calls) == 2

        clock.advance(10)
        with pytest.raises(BrokerClientError, match='503'):
            client.fetch_token('read_all')

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
            _CannedResponse(200, _expiring_body(clock, first, 300)),
            fail_after_expiry,
            _CannedResponse(200, _expiring_body(clock, second, 900)),
        )
        assert client.fetch_token('read_all').token == first

        clock.advance(295)
        with pytest.raises(BrokerClientError):
            client.fetch_token('read_all')

        assert client.fetch_token('read_all').token == second
        assert len(session.calls) == 3

    @pytest.mark.parametrize('status', [401, 403])
    def test_margin_refusal_raises(self, clock: _Clock, status: int) -> None:
        client, _ = _scripted_client(
            _CannedResponse(200, _expiring_body(clock, 'first-value', 300)),
            _CannedResponse(status, b'{"detail":"refused"}'),
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

    def test_non_server_error_is_not_retried(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sleeps: list[float] = []
        monkeypatch.setattr('sg_token_broker._client.time.sleep', sleeps.append)
        session = _ScriptedSession(_CannedResponse(400, b'{"detail":"bad request"}'))
        client = BrokerClient(
            'https://broker.example',
            'farm',
            's',
            options=ClientOptions(retries=2),
            session=cast('requests.Session', session),
        )

        with pytest.raises(BrokerClientError, match='400'):
            client.fetch_token('read_all')

        assert len(session.calls) == 1
        assert sleeps == []

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
        )
        client.fetch_token('read_all')

        clock.advance(300 - seconds_to_expiry)
        result = client.fetch_token('read_all')

        assert len(session.calls) == expected_requests
        assert result.token == (first if expected_requests == 1 else second)

    @pytest.mark.parametrize('first', ['http', 'transport'])
    def test_final_server_error_reports_its_detail(
        self, monkeypatch: pytest.MonkeyPatch, first: str
    ) -> None:
        sleeps: list[float] = []
        monkeypatch.setattr('sg_token_broker._client.time.sleep', sleeps.append)
        failure = _CannedResponse(502, b'{"detail": "SG upstream request failed"}')
        initial = requests.ConnectionError('connection lost') if first == 'transport' else failure
        session = _ScriptedSession(initial, failure)
        client = BrokerClient(
            'https://broker.example',
            'farm',
            's',
            options=ClientOptions(retries=1),
            session=cast('requests.Session', session),
        )

        with pytest.raises(BrokerClientError) as caught:
            client.fetch_token('read_all')

        assert str(caught.value) == (
            'broker request failed with HTTP 502: SG upstream request failed'
        )
        assert len(session.calls) == 2
        assert sleeps == [0.5]

    def test_remote_http_broker_url_raises(self) -> None:
        with pytest.raises(BrokerClientError, match='https'):
            BrokerClient('http://broker.studio.internal', 'farm', 's')

    def test_request_exceptions_use_retries_plus_one_and_linear_backoff(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sleeps: list[float] = []
        monkeypatch.setattr('sg_token_broker._client.time.sleep', sleeps.append)
        session = _ScriptedSession(
            requests.ConnectionError('first'),
            requests.Timeout('second'),
            _CannedResponse(200, _token_body()),
        )
        client = BrokerClient(
            'https://broker.example',
            'farm',
            's',
            options=ClientOptions(retries=2),
            session=cast('requests.Session', session),
        )

        assert client.fetch_token('read_all').scope == 'read_all'
        assert len(session.calls) == 3
        assert sleeps == [0.5, 1.0]

    def test_server_error_is_retried_with_linear_backoff(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sleeps: list[float] = []
        monkeypatch.setattr('sg_token_broker._client.time.sleep', sleeps.append)
        session = _ScriptedSession(
            _CannedResponse(503, b'{}'),
            _CannedResponse(200, _token_body()),
        )
        client = BrokerClient(
            'https://broker.example',
            'farm',
            's',
            options=ClientOptions(retries=1),
            session=cast('requests.Session', session),
        )

        assert client.fetch_token('read_all').scope == 'read_all'
        assert len(session.calls) == 2
        assert sleeps == [0.5]

    def test_token_issued_inside_the_margin_is_kept_until_expiry(self, clock: _Clock) -> None:
        first, second = 'first-value', 'second-value'
        client, session = _scripted_client(
            _CannedResponse(200, _expiring_body(clock, first, 30)),
            _CannedResponse(200, _expiring_body(clock, second, 90)),
        )
        assert client.fetch_token('read_all').token == first

        clock.advance(29)
        assert client.fetch_token('read_all').token == first
        assert len(session.calls) == 1

        clock.advance(1)
        assert client.fetch_token('read_all').token == second

    def test_unreachable_broker_raises(self) -> None:
        client = BrokerClient(
            'http://127.0.0.1:1', 'farm', 's', options=ClientOptions(timeout=0.2, retries=0)
        )
        with pytest.raises(BrokerClientError):
            client.fetch_token('read_all')


class TestClientOptions:
    @pytest.mark.parametrize(
        'timeout',
        [0.0, -1.0, float('nan'), float('inf'), float('-inf')],
    )
    def test_invalid_timeouts_raise(self, timeout: float) -> None:
        with pytest.raises(ValueError, match='timeout must be finite and greater than zero'):
            ClientOptions(timeout=timeout)

    @pytest.mark.parametrize('margin', [-1.0, float('nan'), float('inf'), float('-inf')])
    def test_invalid_refresh_margins_raise(self, margin: float) -> None:
        with pytest.raises(ValueError, match='refresh_margin must be finite and >= 0'):
            ClientOptions(refresh_margin=margin)

    def test_negative_retries_raise(self) -> None:
        with pytest.raises(ValueError, match='retries'):
            ClientOptions(retries=-1)

    def test_zero_refresh_margin_is_accepted(self) -> None:
        assert ClientOptions(refresh_margin=0.0).refresh_margin == 0.0


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
        credential = 'returned-credential'
        body = _token_body(token=credential, **{field: returned})
        client = _response_client(body)

        with pytest.raises(BrokerClientError, match=field) as excinfo:
            client.fetch_token('read_all')

        assert credential not in str(excinfo.value)
        assert client._cache == {}

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


def _recording_session() -> tuple[requests.Session, list[requests.Response]]:
    session = requests.Session()
    responses: list[requests.Response] = []

    def record(response: requests.Response, **_kwargs: object) -> None:
        responses.append(response)

    session.hooks['response'].append(record)
    return session, responses


def _response_client(body: bytes) -> BrokerClient:
    return BrokerClient(
        'https://broker.example',
        'farm',
        's',
        options=ClientOptions(timeout=5, retries=0),
        session=cast('requests.Session', _ScriptedSession(_CannedResponse(200, body))),
    )


def _scripted_client(
    *outcomes: _CannedResponse
    | requests.RequestException
    | Callable[[], _CannedResponse | requests.RequestException],
) -> tuple[BrokerClient, _ScriptedSession]:
    session = _ScriptedSession(*outcomes)
    client = BrokerClient(
        'https://broker.example',
        'farm',
        's',
        options=ClientOptions(retries=0),
        session=cast('requests.Session', session),
    )
    return client, session


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


def _future_token_body(value: str) -> bytes:
    expires_at = datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
    return _token_body(token=value, expires_at=expires_at.isoformat())


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    # Patches the shared datetime class, so an in-process broker reads this clock too.
    real_datetime = datetime.datetime
    clock = _Clock(real_datetime(2026, 8, 24, 12, 0, tzinfo=datetime.UTC))

    class FrozenDateTime(real_datetime):
        @classmethod
        def now(cls, tz: datetime.tzinfo | None = None) -> datetime.datetime:
            assert tz is datetime.UTC
            return clock.now

    monkeypatch.setattr(client_module.datetime, 'datetime', FrozenDateTime)
    return clock


def _expiring_body(clock: _Clock, value: str, seconds: float) -> bytes:
    expires_at = clock.now + datetime.timedelta(seconds=seconds)
    return _token_body(token=value, expires_at=expires_at.isoformat())


def test_missing_ca_bundle_is_a_setup_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(client_module.time, 'sleep', Mock(side_effect=AssertionError('retry')))
    missing = tmp_path / 'missing-ca.pem'
    monkeypatch.setenv('REQUESTS_CA_BUNDLE', str(missing))
    monkeypatch.setattr(
        'urllib3.connection.HTTPSConnection.connect',
        Mock(side_effect=AssertionError('unexpected connection')),
    )
    with requests.Session() as session:
        post = Mock(wraps=session.post)
        monkeypatch.setattr(session, 'post', post)
        with pytest.raises(BrokerClientError) as caught:
            BrokerClient('https://127.0.0.1:1', 'c', 's', session=session).fetch_token('read_all')
        post.assert_called_once()
    assert isinstance(caught.value.__cause__, OSError)
    assert not isinstance(caught.value.__cause__, requests.RequestException)
    assert str(caught.value) == 'broker request could not be sent: ' + str(caught.value.__cause__)
    assert str(missing) in str(caught.value)
