import datetime
import json
from typing import cast

import pytest
import requests

from sg_token_broker import _client as client_module
from sg_token_broker import _service
from sg_token_broker._client import BrokerClient, BrokerClientError, ClientOptions, TokenResponse
from tests.conftest import BROKER_CREDENTIAL, _FakeSG

_SESSION_TYPE = _service._SESSION_TYPE


class TestBrokerClient:
    def test_backslash_authority_raises_before_request(self) -> None:
        with pytest.raises(BrokerClientError, match='broker URL'):
            BrokerClient('http://evil.example\\@localhost', 'farm', 's')

    def test_bad_credentials_raise(self, broker_url: str) -> None:
        client = BrokerClient(broker_url, 'farm', BROKER_CREDENTIAL[:-1])
        with pytest.raises(BrokerClientError, match='401'):
            client.fetch_token('read_all')

    def test_env_discovery(self, broker_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv('SG_TOKEN_BROKER_URL', broker_url)
        monkeypatch.setenv('SG_TOKEN_BROKER_CLIENT_ID', 'farm')
        monkeypatch.setenv('SG_TOKEN_BROKER_CLIENT_SECRET', BROKER_CREDENTIAL)
        assert BrokerClient().fetch_token('read_all').token

    def test_fetch_token(self, broker_url: str, fake_sg: _FakeSG) -> None:
        client = BrokerClient(broker_url, 'farm', BROKER_CREDENTIAL)
        token = client.fetch_token('read_all')
        assert token.token == fake_sg._canned_session
        assert token.token_type == _SESSION_TYPE
        assert token.site_url

    def test_https_broker_url_accepted(self) -> None:
        BrokerClient('https://broker.studio.internal', 'farm', 's')

    @pytest.mark.parametrize('client_id', ['a:b', 'x' * 65])
    def test_invalid_client_ids_are_rejected_before_any_request(self, client_id: str) -> None:
        with pytest.raises(BrokerClientError, match='client id must be'):
            BrokerClient('https://broker.example', client_id, 'secret')

    def test_local_cache_returns_same_token(self, broker_url: str) -> None:
        client = BrokerClient(broker_url, 'farm', BROKER_CREDENTIAL)
        assert client.fetch_token('read_all') is client.fetch_token('read_all')

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
        [(61.0, 0), (60.0, 1), (59.0, 1)],
        ids=['outside', 'boundary', 'inside'],
    )
    def test_refresh_margin_boundary(
        self,
        monkeypatch: pytest.MonkeyPatch,
        seconds_to_expiry: float,
        expected_requests: int,
    ) -> None:
        real_datetime = datetime.datetime
        fixed_now = real_datetime(2026, 8, 24, 12, 0, tzinfo=datetime.UTC)

        class FixedDateTime(real_datetime):
            @classmethod
            def now(cls, tz: datetime.tzinfo | None = None) -> datetime.datetime:
                assert tz is datetime.UTC
                return fixed_now

        monkeypatch.setattr(client_module.datetime, 'datetime', FixedDateTime)
        response_expiry = fixed_now + datetime.timedelta(minutes=5)
        session = _ScriptedSession(
            _CannedResponse(200, _token_body(expires_at=response_expiry.isoformat()))
        )
        client = BrokerClient(
            'https://broker.example',
            'farm',
            's',
            options=ClientOptions(retries=0, refresh_margin=60.0),
            session=cast('requests.Session', session),
        )
        cached_value = 'cached-token'
        session_type = 'session'
        cached = TokenResponse(
            token=cached_value,
            token_type=session_type,
            scope='read_all',
            site_url='https://studio.example.com',
            expires_at=fixed_now + datetime.timedelta(seconds=seconds_to_expiry),
        )
        client._cache[('read_all', 'session')] = cached

        result = client.fetch_token('read_all')

        assert len(session.calls) == expected_requests
        assert (result is cached) is (expected_requests == 0)

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

    def test_negative_retries_raise(self) -> None:
        with pytest.raises(ValueError, match='retries'):
            ClientOptions(retries=-1)


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


class _ScriptedSession:
    def __init__(self, *outcomes: _CannedResponse | requests.RequestException) -> None:
        self.calls: list[dict[str, object]] = []
        self._outcomes = iter(outcomes)

    def post(self, url: str, **kwargs: object) -> _CannedResponse:
        self.calls.append({'url': url, **kwargs})
        outcome = next(self._outcomes)
        if isinstance(outcome, requests.RequestException):
            raise outcome
        return outcome


def _response_client(body: bytes) -> BrokerClient:
    return BrokerClient(
        'https://broker.example',
        'farm',
        's',
        options=ClientOptions(timeout=5, retries=0),
        session=cast('requests.Session', _ScriptedSession(_CannedResponse(200, body))),
    )


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
