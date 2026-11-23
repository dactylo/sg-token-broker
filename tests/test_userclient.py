import base64
import datetime
import json
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
from requests.adapters import HTTPAdapter

from sg_token_broker import (
    BrokerClient,
    BrokerClientError,
    UserTokenClient,
    UserTokenClientError,
    _client,
    _userclient,
)
from sg_token_broker._retry import RetryTiming
from sg_token_broker._userauth import SignInError
from tests._timeouts import STALL_TIMEOUT_SECONDS

_REST_TYPE = 'rest'
_SESSION_TYPE = 'session'


@dataclass
class _FakeService:
    url: str = ''
    now: datetime.datetime = datetime.datetime(2026, 8, 24, 12, 0, tzinfo=datetime.UTC)
    session_token: str = ''
    request_count: int = 0
    last_query: str = ''
    last_authorization: str = ''
    rest_expires_in: int = 600
    respond_as: str | None = None
    corrupt_rest_cache_until: bool = False
    corrupt_session_expiry: bool = False
    failure: tuple[int, str] | None = None

    def fail_next(self, status: int, error: str) -> None:
        self.failure = (status, error)


@dataclass
class _RetryClock:
    now: float = 0.0
    sleeps: list[float] = field(default_factory=list[float])

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds

    def install(self, client: UserTokenClient, max_wait: float) -> None:
        client._retrier = _userclient._ServiceRetrier(
            max_wait=max_wait, timing=RetryTiming(lambda: self.now, self.sleep, lambda: 0.5)
        )


class TestUserTokenClient:
    def test_defaults_to_the_full_sign_in_flow(
        self, fake_service: _FakeService, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        token = _idt('jane')
        monkeypatch.setattr(
            'sg_token_broker._userclient.default_id_token_source',
            lambda: lambda: token,
        )
        client = _service_client(fake_service.url)
        client.fetch_token('session')
        assert fake_service.last_authorization == f'Bearer {token}'

    def test_error_statuses_raise(self, fake_service: _FakeService) -> None:
        fake_service.fail_next(403, 'forbidden')
        client = _service_client(fake_service.url, id_token_source=lambda: _idt('jane'))
        with pytest.raises(UserTokenClientError, match='403'):
            client.fetch_token('session')

    def test_failed_stale_rest_refresh_does_not_resurrect_the_expired_token(
        self, fake_service: _FakeService
    ) -> None:
        fake_service.rest_expires_in = 30
        client = _service_client(fake_service.url, id_token_source=lambda: _idt('jane'))
        first = client.fetch_token('rest')
        fake_service.fail_next(502, 'sg_invalid_response')
        with pytest.raises(UserTokenClientError):
            client.fetch_token('rest')
        cache = client._cache
        assert first.token
        assert 'rest' not in cache

    def test_fetches_a_session_token(self, fake_service: _FakeService) -> None:
        id_token = _idt('jane')
        client = _service_client(fake_service.url, id_token_source=lambda: id_token)
        user_token = client.fetch_token('session')
        assert user_token.token == fake_service.session_token
        assert user_token.expires_at is None
        assert fake_service.last_query == 'token_type=session'
        assert fake_service.last_authorization == f'Bearer {id_token}'

    def test_force_refresh_from_a_fresh_client_sends_refresh(
        self, fake_service: _FakeService
    ) -> None:
        client = _service_client(fake_service.url, id_token_source=lambda: _idt('jane'))
        client.fetch_token('session', force_refresh=True)
        assert 'refresh=true' in fake_service.last_query

    def test_identity_switch_never_serves_the_previous_identity(
        self, fake_service: _FakeService
    ) -> None:
        identities = iter([_idt('alice'), _idt('bob'), _idt('alice')])
        client = _service_client(fake_service.url, id_token_source=lambda: next(identities))
        first = client.fetch_token('session')
        second = client.fetch_token('session')
        third = client.fetch_token('session')
        assert (first.login, second.login, third.login) == ('alice', 'bob', 'alice')
        assert 'alice' in first.token
        assert 'bob' in second.token
        assert 'alice' in third.token
        assert first.token != third.token
        assert fake_service.request_count == 3

    def test_mismatched_token_type_is_rejected(self, fake_service: _FakeService) -> None:
        fake_service.respond_as = 'rest'
        client = _service_client(fake_service.url, id_token_source=lambda: _idt('jane'))
        with pytest.raises(UserTokenClientError, match='token_type'):
            client.fetch_token('session')

    def test_negative_retries_raise(self) -> None:
        with pytest.raises(ValueError, match='retries must be a non-negative integer'):
            UserTokenClient(
                'https://service.example', id_token_source=lambda: _idt('alice'), retries=-1
            )

    @pytest.mark.parametrize(
        'force_refresh', [True, False], ids=['forced-session', 'account-switch']
    )
    def test_outage_discards_previous_session(
        self, fake_service: _FakeService, *, force_refresh: bool
    ) -> None:
        identities = iter(
            [_idt('alice'), _idt('alice' if force_refresh else 'bob'), _idt('alice')]
        )
        client = _service_client(fake_service.url, id_token_source=lambda: next(identities))
        clock = _RetryClock()
        clock.install(client, 0.25)
        first = client.fetch_token('session')
        fake_service.fail_next(503, 'upstream_unavailable')

        with pytest.raises(UserTokenClientError, match='upstream_unavailable'):
            client.fetch_token('session', force_refresh=force_refresh)

        assert _sub_of(fake_service.last_authorization) == ('alice' if force_refresh else 'bob')
        assert ('refresh=true' in fake_service.last_query) == force_refresh
        assert clock.sleeps == []
        assert client.fetch_token('session').token != first.token

    @pytest.mark.usefixtures('no_requests')
    def test_four_part_id_token_is_a_client_error(self) -> None:
        id_token = f'{_idt("jane")}.extra'
        client = UserTokenClient('https://service.example', id_token_source=lambda: id_token)
        with pytest.raises(UserTokenClientError, match='sub'):
            client.fetch_token('session')

    @pytest.mark.usefixtures('no_requests')
    def test_id_token_without_sub_is_a_client_error(self) -> None:
        id_token = _idt_from_payload({})
        client = UserTokenClient('https://service.example', id_token_source=lambda: id_token)
        with pytest.raises(UserTokenClientError, match='sub'):
            client.fetch_token('session')

    def test_requires_service_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv('SG_USER_TOKEN_URL', raising=False)
        with pytest.raises(UserTokenClientError, match='SG_USER_TOKEN_URL'):
            UserTokenClient(id_token_source=lambda: _idt('jane'))

    def test_rest_cache_until_must_equal_expiry(self, fake_service: _FakeService) -> None:
        fake_service.corrupt_rest_cache_until = True
        client = _service_client(fake_service.url, id_token_source=lambda: _idt('jane'))
        with pytest.raises(UserTokenClientError, match='cache_until'):
            client.fetch_token('rest')

    def test_rest_refreshes_near_expiry(self, fake_service: _FakeService) -> None:
        fake_service.rest_expires_in = 61
        client = _service_client(fake_service.url, id_token_source=lambda: _idt('jane'))
        first = client.fetch_token('rest')
        assert client.fetch_token('rest').token == first.token
        assert fake_service.request_count == 1
        fake_service.now += datetime.timedelta(seconds=1)
        assert client.fetch_token('rest').token != first.token
        assert fake_service.request_count == 2

    @pytest.mark.parametrize(
        ('status', 'body', 'message'),
        [
            (
                403,
                {'error': 'forbidden', 'detail': 'token type not allowed for this deployment'},
                'service refused (HTTP 403 forbidden): token type not allowed for this deployment',
            ),
            (400, ValueError('HTML body'), 'service refused (HTTP 400)'),
            (502, {'error': 'sg_rejected'}, 'service refused (HTTP 502 sg_rejected)'),
        ],
    )
    def test_service_rejection_reports_available_details(
        self, status: int, body: dict[str, str] | ValueError, message: str
    ) -> None:
        response = Mock(status_code=status, headers={})
        response.json = (
            Mock(side_effect=body) if isinstance(body, ValueError) else Mock(return_value=body)
        )
        session = Mock(get=Mock(return_value=response))
        client = UserTokenClient(
            'https://service.example',
            id_token_source=lambda: _idt('jane'),
            session=cast('requests.Session', session),
        )

        clock = _RetryClock()
        clock.install(client, STALL_TIMEOUT_SECONDS)
        with pytest.raises(UserTokenClientError) as caught:
            client.fetch_token('session')

        session.get.assert_called_once()
        assert str(caught.value) == message

    @pytest.mark.parametrize(
        'timeout',
        [0.0, -1.0, float('nan'), float('inf'), float('-inf')],
    )
    def test_invalid_timeouts_raise(self, timeout: float) -> None:
        with pytest.raises(
            ValueError,
            match='timeout must be finite and greater than zero',
        ):
            UserTokenClient(
                'https://user-token.example',
                id_token_source=lambda: _idt('jane'),
                timeout=timeout,
            )

    @pytest.mark.parametrize('margin', [-1.0, float('nan'), float('inf'), float('-inf')])
    def test_invalid_refresh_margins_raise(self, margin: float) -> None:
        with pytest.raises(ValueError, match='refresh_margin must be finite and >= 0'):
            UserTokenClient(
                'https://user-token.example',
                id_token_source=lambda: _idt('jane'),
                refresh_margin=margin,
            )

    def test_session_is_cached_until_force_refresh(self, fake_service: _FakeService) -> None:
        client = _service_client(fake_service.url, id_token_source=lambda: _idt('jane'))
        first = client.fetch_token('session')
        after_cache_horizon = first.cache_until + datetime.timedelta(seconds=1)

        fake_service.now = after_cache_horizon
        second = client.fetch_token('session')
        assert first.token == second.token
        assert fake_service.request_count == 1
        client.fetch_token('session', force_refresh=True)
        assert fake_service.request_count == 2
        assert 'refresh=true' in fake_service.last_query

    def test_session_with_expiry_is_rejected(self, fake_service: _FakeService) -> None:
        fake_service.corrupt_session_expiry = True
        client = _service_client(fake_service.url, id_token_source=lambda: _idt('jane'))
        with pytest.raises(UserTokenClientError, match='expires_at'):
            client.fetch_token('session')

    @pytest.mark.usefixtures('no_requests')
    def test_sign_in_failures_surface_as_client_errors(self) -> None:

        def failing_source() -> str:
            raise SignInError('browser timeout')

        client = UserTokenClient('https://service.example', id_token_source=failing_source)
        with pytest.raises(UserTokenClientError, match='sign-in failed'):
            client.fetch_token('session')

    @pytest.mark.parametrize('transport_failure', [True, False], ids=['connection', 'busy'])
    def test_retry_reuses_identity_after_slow_sign_in(self, *, transport_failure: bool) -> None:
        clock = _RetryClock()
        id_token = _idt('alice')

        def sign_in() -> str:
            clock.now += 10
            return id_token

        source = Mock(side_effect=sign_in)
        success = Mock(
            status_code=200,
            json=Mock(
                return_value={
                    'token': 'fresh',
                    'token_type': 'session',
                    'login': 'alice',
                    'site_url': 'https://sg.example',
                    'expires_at': None,
                    'cache_until': '2026-11-19T00:00:00Z',
                }
            ),
        )

        def send(*_args: object, **_kwargs: object) -> Mock:
            if session.get.call_count == 1:
                if transport_failure:
                    raise requests.ConnectionError('connection lost')
                return Mock(
                    status_code=503,
                    headers={'Retry-After': '1'},
                    json=Mock(return_value={'error': 'server_busy'}),
                )
            clock.now += 5  # The successful request ends beyond the two-second budget.
            return success

        session = Mock(get=Mock(side_effect=send))
        client = UserTokenClient(
            'https://service.example', id_token_source=source, session=session
        )
        clock.install(client, 2)

        assert client.fetch_token(force_refresh=True).login == 'alice'
        source.assert_called_once_with()
        assert clock.sleeps == pytest.approx([0.25 if transport_failure else 1.25])
        for request in session.get.call_args_list:
            assert request.kwargs['headers'] == {'Authorization': f'Bearer {id_token}'}
            assert request.kwargs['params'] == {'token_type': 'session', 'refresh': 'true'}

    @pytest.mark.parametrize(('header', 'delay'), [('99', 99.25), ('bad', 0.25)])
    def test_delay_outside_budget_skips_sleep(self, header: str, delay: float) -> None:
        clock = _RetryClock()
        busy = Mock(
            status_code=503,
            headers={'Retry-After': header},
            json=Mock(
                return_value={
                    'error': 'server_busy',
                    'detail': 'all workers occupied',
                }
            ),
        )
        session = Mock(get=Mock(return_value=busy))
        client = UserTokenClient(
            'https://service.example', id_token_source=lambda: _idt('a'), session=session
        )
        clock.install(client, 0.25)

        with pytest.raises(UserTokenClientError) as caught:
            client.fetch_token()

        message = str(caught.value)
        assert f'next request permitted in {delay:g}s' in message
        assert 'beyond max_wait 0.25s' in message
        assert 'service refused (HTTP 503 server_busy): all workers occupied' in message
        assert ('Retry-After' in message) == (header == '99')
        assert clock.sleeps == []
        session.get.assert_called_once()

    @pytest.mark.parametrize('retries', [0, 2])
    def test_retries_cap_requests_before_sleeping_again(
        self, retries: int, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = _RetryClock()
        timing = RetryTiming(lambda: clock.now, clock.sleep, lambda: 0.5)
        monkeypatch.setattr(_userclient, 'RetryTiming', lambda: timing)
        session = Mock(
            get=Mock(
                side_effect=[
                    requests.ConnectionError(f'disconnect {i}') for i in range(1, retries + 2)
                ]
            )
        )
        client = UserTokenClient(
            'https://service.example',
            id_token_source=lambda: _idt('alice'),
            session=session,
            retries=retries,
            max_wait=STALL_TIMEOUT_SECONDS,
        )

        with pytest.raises(UserTokenClientError) as caught:
            client.fetch_token()

        assert str(caught.value) == (
            f'no token after {retries + 1} attempt(s) (retries={retries}); last failure: '
            'cannot reach user-token service at https://service.example: ConnectionError'
        )
        assert session.get.call_count == retries + 1
        assert clock.sleeps == pytest.approx([0.25, 0.5][:retries])

    @pytest.mark.parametrize('max_wait', [0.0, -1.0, float('nan'), float('inf'), float('-inf')])
    def test_invalid_max_wait_raises(self, max_wait: float) -> None:
        with pytest.raises(ValueError, match='max_wait must be finite and greater than zero'):
            UserTokenClient(
                'https://service.example', id_token_source=lambda: _idt('a'), max_wait=max_wait
            )

    def test_sleep_that_resumes_at_deadline_cannot_start_another_request(self) -> None:
        clock = _RetryClock()
        first = Mock(
            status_code=502, headers={}, json=Mock(side_effect=ValueError('HTML response'))
        )
        session = Mock(get=Mock(side_effect=[first, AssertionError('request after deadline')]))
        client = UserTokenClient(
            'https://service.example', id_token_source=lambda: _idt('alice'), session=session
        )

        def resume_late(seconds: float) -> None:
            clock.sleep(seconds)
            clock.now = 1

        client._retrier = _userclient._ServiceRetrier(
            max_wait=1, timing=RetryTiming(lambda: clock.now, resume_late, lambda: 0.5)
        )
        with pytest.raises(
            UserTokenClientError, match=r'max_wait 1s.*service refused \(HTTP 502\)'
        ):
            client.fetch_token()
        session.get.assert_called_once()
        assert clock.sleeps == pytest.approx([0.25])

    def test_source_is_consulted_on_every_call(self, fake_service: _FakeService) -> None:
        calls: list[int] = []

        def source() -> str:
            calls.append(1)
            return _idt('jane')

        client = _service_client(fake_service.url, id_token_source=source)
        client.fetch_token('session')
        client.fetch_token('session')
        assert len(calls) == 2
        assert fake_service.request_count == 1

    def test_transport_error_includes_last_failure_when_budget_runs_out(self) -> None:
        session = Mock(get=Mock(side_effect=requests.ConnectionError('connection lost')))
        client = UserTokenClient(
            'https://service.example',
            id_token_source=lambda: _idt('jane'),
            session=cast('requests.Session', session),
        )
        clock = _RetryClock()
        clock.install(client, 1)

        with pytest.raises(UserTokenClientError) as caught:
            client.fetch_token('session')

        assert 'beyond max_wait 1s' in str(caught.value)
        assert (
            'cannot reach user-token service at https://service.example: ConnectionError'
            in str(caught.value)
        )
        assert 'Retry-After' not in str(caught.value)
        assert session.get.call_count == 3
        assert clock.sleeps == pytest.approx([0.25, 0.5])

    @pytest.mark.usefixtures('no_requests')
    def test_two_part_id_token_is_a_client_error(self) -> None:
        id_token = _idt('jane').removesuffix('.')
        client = UserTokenClient('https://service.example', id_token_source=lambda: id_token)
        with pytest.raises(UserTokenClientError, match='sub'):
            client.fetch_token('session')

    @pytest.mark.usefixtures('no_requests')
    def test_unknown_requested_token_type_is_rejected(self) -> None:
        client = UserTokenClient('https://service.example', id_token_source=lambda: _idt('jane'))
        with pytest.raises(UserTokenClientError, match='token_type'):
            client.fetch_token('bearer')

    def test_unknown_response_token_type_is_rejected(self, fake_service: _FakeService) -> None:
        fake_service.respond_as = 'bearer'
        client = _service_client(fake_service.url, id_token_source=lambda: _idt('jane'))
        with pytest.raises(UserTokenClientError, match='token_type'):
            client.fetch_token('session')


def _idt_from_payload(payload: dict[str, object]) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b'=').decode()
    encoded = json.dumps(payload).encode()
    body = base64.urlsafe_b64encode(encoded).rstrip(b'=').decode()
    return f'{header}.{body}.'


def _service_client(
    service_url: str, *, id_token_source: Callable[[], str] | None = None
) -> UserTokenClient:
    client = UserTokenClient(
        service_url,
        id_token_source=id_token_source,
        timeout=STALL_TIMEOUT_SECONDS,
        max_wait=STALL_TIMEOUT_SECONDS,
    )
    _RetryClock().install(client, STALL_TIMEOUT_SECONDS)
    return client


def _idt(sub: str, *, exp_offset: int = 3600) -> str:
    return _idt_from_payload({'sub': sub, 'exp': int(time.time()) + exp_offset})


def _sub_of(authorization: str) -> str:
    token = authorization.removeprefix('Bearer ')
    try:
        segment = token.split('.')[1]
        payload = json.loads(base64.urlsafe_b64decode(segment + '=' * (-len(segment) % 4)))
    except (IndexError, ValueError):
        return 'anon'
    return str(payload.get('sub', 'anon'))


@pytest.fixture
def fake_service(monkeypatch: pytest.MonkeyPatch) -> Iterator[_FakeService]:
    state = _FakeService()

    class FixedDateTime(datetime.datetime):
        @classmethod
        def now(cls, tz: datetime.tzinfo | None = None) -> datetime.datetime:
            assert tz is datetime.UTC
            return state.now

    monkeypatch.setattr(
        _userclient,
        'datetime',
        SimpleNamespace(UTC=datetime.UTC, datetime=FixedDateTime),
    )

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            state.request_count += 1
            state.last_query = parts.query
            state.last_authorization = self.headers.get('Authorization', '')
            if state.failure is not None:
                status, error = state.failure
                state.failure = None
                self._send(status, {'error': error})
                return
            requested_type = parse_qs(parts.query).get('token_type', ['session'])[0]
            token_type = state.respond_as or requested_type
            now = state.now
            sub = _sub_of(state.last_authorization)
            token = f'{token_type}-token-{sub}-{state.request_count}'
            if token_type == _SESSION_TYPE:
                state.session_token = token
            expires_at = None
            if token_type == _REST_TYPE or state.corrupt_session_expiry:
                expires_at = (now + datetime.timedelta(seconds=state.rest_expires_in)).isoformat()
            cache_until = now + datetime.timedelta(minutes=5)
            if token_type == _REST_TYPE:
                cache_until = now + datetime.timedelta(seconds=state.rest_expires_in)
                if state.corrupt_rest_cache_until:
                    cache_until += datetime.timedelta(seconds=1)
            self._send(
                200,
                {
                    'token': token,
                    'token_type': token_type,
                    'login': sub,
                    'site_url': 'https://sg.example',
                    'expires_at': expires_at,
                    'cache_until': cache_until.isoformat(),
                },
            )

        def log_message(self, *args: object, **kwargs: object) -> None:
            pass

        def _send(self, status: int, body: dict[str, object]) -> None:
            payload = json.dumps(body).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    host, port = cast('tuple[str, int]', server.server_address)
    state.url = f'http://{host}:{port}'
    thread = threading.Thread(
        target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True
    )
    thread.start()
    try:
        yield state
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


@pytest.mark.parametrize('user', [False, True], ids=['app', 'user'])
@pytest.mark.parametrize('mode', ['normal', 'malformed-host', 'body-timeout', 'redirect-limit'])
def test_endpoint_redirect_is_reported_after_one_adapter_send(
    monkeypatch: pytest.MonkeyPatch, mode: str, *, user: bool
) -> None:
    timing = RetryTiming(lambda: 0.0, lambda _: None, lambda: 0.0)
    monkeypatch.setattr(_client, 'RetryTiming', lambda: timing)
    monkeypatch.setattr(_userclient, 'RetryTiming', lambda: timing)
    response = requests.Response()
    response.status_code = 307
    host = '[invalid-host' if mode == 'malformed-host' else 'new.example'
    response.headers['Location'] = f'https://ignored:password@{host}/path?secret=query#fragment'
    raw = Mock(
        spec=['stream', 'close'], stream=Mock(side_effect=requests.ReadTimeout('body timed out'))
    )
    response.raw = raw if mode == 'body-timeout' else BytesIO(b'')
    with requests.Session() as session:
        if mode == 'redirect-limit':
            session.max_redirects = 0
        adapter = Mock(spec=HTTPAdapter)

        def reply(request: requests.PreparedRequest, **_kwargs: object) -> requests.Response:
            if adapter.send.call_count != 1:
                raise AssertionError('unexpected second request')
            response.request = request
            response.url = str(request.url)
            return response

        adapter.send.side_effect = reply
        session.mount('https://', adapter)
        if user:
            client = UserTokenClient(
                'https://old.example',
                id_token_source=lambda: _idt('a'),
                session=session,
                retries=1,
            )
            with pytest.raises(UserTokenClientError) as caught:
                client.fetch_token()
            message = str(caught.value)
        else:
            app = BrokerClient(
                'https://old.example', 'farm', 'password', session=session, retries=1
            )
            with pytest.raises(BrokerClientError) as error:
                app.fetch_token('read_all')
            message = str(error.value)
        adapter.send.assert_called_once()
    if mode == 'body-timeout':
        raw.stream.assert_not_called()
        raw.close.assert_called_once_with()
    if mode != 'malformed-host':
        assert '307' in message
        assert 'new.example' in message
    assert 'redirect' in message
    assert 'URL' in message
    assert all(value not in message for value in ('ignored', 'password', 'query', 'fragment'))


@pytest.mark.parametrize('retries', [0, 1])
def test_expired_service_response_retries_within_original_allowance(
    retries: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    wall = datetime.datetime(2040, 1, 1, tzinfo=datetime.UTC)
    monkeypatch.setattr(
        _userclient,
        'datetime',
        SimpleNamespace(
            UTC=datetime.UTC,
            datetime=Mock(
                now=Mock(return_value=wall), fromisoformat=datetime.datetime.fromisoformat
            ),
        ),
    )

    def response(seconds: int) -> Mock:
        deadline = (wall + datetime.timedelta(seconds=seconds)).isoformat()
        return Mock(
            status_code=200,
            json=Mock(
                return_value={
                    'token': f'token-{seconds}',
                    'token_type': 'rest',
                    'login': 'user',
                    'site_url': 'https://sg.example',
                    'expires_at': deadline,
                    'cache_until': deadline,
                }
            ),
        )

    session = Mock(get=Mock(side_effect=[response(0), response(600)]))
    clock = _RetryClock()
    monkeypatch.setattr(
        _userclient,
        'RetryTiming',
        lambda: RetryTiming(lambda: clock.now, clock.sleep, lambda: 0.5),
    )
    client = UserTokenClient(
        'https://service.example',
        id_token_source=lambda: _idt('a'),
        session=session,
        retries=retries,
    )
    if retries:
        expected = 'token-600'
        assert client.fetch_token('rest').token == expected
    else:
        with pytest.raises(UserTokenClientError, match='REST token expired'):
            client.fetch_token('rest')
    assert session.get.call_count == 1 + retries


def test_missing_ca_bundle_is_a_setup_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = tmp_path / 'missing-ca.pem'
    monkeypatch.setenv('REQUESTS_CA_BUNDLE', str(missing))
    with pytest.raises(UserTokenClientError) as caught:
        UserTokenClient(
            'https://127.0.0.1:1',
            id_token_source=lambda: _idt('jane'),
            timeout=STALL_TIMEOUT_SECONDS,
        ).fetch_token()
    assert caught.value.__suppress_context__
    assert str(caught.value).startswith(
        'user-token request could not be sent: Could not find a suitable TLS CA certificate bundle'
    )
    assert str(missing) in str(caught.value)


@pytest.mark.parametrize('user', [False, True], ids=['app', 'user'])
def test_transport_diagnosis_omits_url_credentials(*, user: bool) -> None:
    endpoint = 'https://account:private@service.example/token?param=query-value#fragment'
    session = Mock()
    failure = requests.ConnectionError(f'offline at {endpoint}')
    session.get.side_effect = session.post.side_effect = failure
    if user:
        client = UserTokenClient(
            endpoint, id_token_source=lambda: _idt('a'), session=session, retries=0
        )
        with pytest.raises(UserTokenClientError) as caught:
            client.fetch_token()
        message = str(caught.value)
    else:
        app = BrokerClient(endpoint, 'farm', 'password', session=session, retries=0)
        with pytest.raises(BrokerClientError) as error:
            app.fetch_token('read_all')
        message = str(error.value)
    assert 'service.example' in message
    assert all(value not in message for value in ('account', 'private', 'query-value', 'fragment'))


def test_transport_failure_uses_shared_retry_decision(monkeypatch: pytest.MonkeyPatch) -> None:
    decision = Mock(return_value='fail')
    monkeypatch.setattr(_userclient, 'decide', decision)
    session = Mock(get=Mock(side_effect=requests.ConnectionError('offline')))
    client = UserTokenClient(
        'https://service.example', id_token_source=lambda: _idt('a'), session=session, retries=0
    )
    with pytest.raises(UserTokenClientError, match='cannot reach'):
        client.fetch_token()
    decision.assert_called_once_with(None, None)
