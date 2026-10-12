import base64
import datetime
import json
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import cast
from urllib.parse import parse_qs, urlsplit

import pytest

from sg_token_broker import UserTokenClient, UserTokenClientError
from sg_token_broker._userauth import SignInError

_REST_TYPE = 'rest'
_SESSION_TYPE = 'session'


@dataclass
class _FakeService:
    url: str = ''
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


class TestUserTokenClient:
    def test_defaults_to_the_full_sign_in_flow(
        self, fake_service: _FakeService, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        token = _idt('jane')
        monkeypatch.setattr(
            'sg_token_broker._userclient.default_id_token_source',
            lambda: lambda: token,
        )
        client = UserTokenClient(fake_service.url)
        client.fetch_token('session')
        assert fake_service.last_authorization == f'Bearer {token}'

    def test_error_statuses_raise(self, fake_service: _FakeService) -> None:
        fake_service.fail_next(403, 'forbidden')
        client = UserTokenClient(fake_service.url, id_token_source=lambda: _idt('jane'))
        with pytest.raises(UserTokenClientError, match='403'):
            client.fetch_token('session')

    def test_failed_force_refresh_does_not_resurrect_the_rejected_session(
        self, fake_service: _FakeService
    ) -> None:
        client = UserTokenClient(fake_service.url, id_token_source=lambda: _idt('jane'))
        first = client.fetch_token('session')
        fake_service.fail_next(502, 'upstream_error')
        with pytest.raises(UserTokenClientError):
            client.fetch_token('session', force_refresh=True)
        second = client.fetch_token('session')
        assert second.token != first.token

    def test_failed_stale_rest_refresh_does_not_resurrect_the_expired_token(
        self, fake_service: _FakeService
    ) -> None:
        fake_service.rest_expires_in = 30
        client = UserTokenClient(fake_service.url, id_token_source=lambda: _idt('jane'))
        first = client.fetch_token('rest')
        fake_service.fail_next(502, 'upstream_error')
        with pytest.raises(UserTokenClientError):
            client.fetch_token('rest')
        cache = client._cache
        assert first.token
        assert 'rest' not in cache

    def test_fetches_a_session_token(self, fake_service: _FakeService) -> None:
        id_token = _idt('jane')
        client = UserTokenClient(fake_service.url, id_token_source=lambda: id_token)
        user_token = client.fetch_token('session')
        assert user_token.token == fake_service.session_token
        assert user_token.expires_at is None
        assert fake_service.last_query == 'token_type=session'
        assert fake_service.last_authorization == f'Bearer {id_token}'

    def test_force_refresh_from_a_fresh_client_sends_refresh(
        self, fake_service: _FakeService
    ) -> None:
        client = UserTokenClient(fake_service.url, id_token_source=lambda: _idt('jane'))
        client.fetch_token('session', force_refresh=True)
        assert 'refresh=true' in fake_service.last_query

    def test_four_part_id_token_is_a_client_error(self, fake_service: _FakeService) -> None:
        id_token = f'{_idt("jane")}.extra'
        client = UserTokenClient(fake_service.url, id_token_source=lambda: id_token)
        with pytest.raises(UserTokenClientError, match='sub'):
            client.fetch_token('session')

    def test_id_token_without_sub_is_a_client_error(self, fake_service: _FakeService) -> None:
        id_token = _idt_from_payload({})
        client = UserTokenClient(fake_service.url, id_token_source=lambda: id_token)
        with pytest.raises(UserTokenClientError, match='sub'):
            client.fetch_token('session')

    def test_identity_switch_never_serves_the_previous_identity(
        self, fake_service: _FakeService
    ) -> None:
        identities = iter([_idt('alice'), _idt('bob'), _idt('alice')])
        client = UserTokenClient(fake_service.url, id_token_source=lambda: next(identities))
        first = client.fetch_token('session')
        second = client.fetch_token('session')
        third = client.fetch_token('session')
        assert (first.login, second.login, third.login) == ('alice', 'bob', 'alice')
        assert 'alice' in first.token
        assert 'bob' in second.token
        assert 'alice' in third.token
        assert first.token != third.token
        assert fake_service.request_count == 3

    @pytest.mark.parametrize(
        'timeout',
        [0.0, -1.0, float('nan'), float('inf'), float('-inf')],
    )
    def test_invalid_timeouts_raise(self, timeout: float) -> None:
        with pytest.raises(
            UserTokenClientError,
            match='timeout must be finite and greater than zero',
        ):
            UserTokenClient(
                'https://user-token.example',
                id_token_source=lambda: _idt('jane'),
                timeout=timeout,
            )

    def test_mismatched_token_type_is_rejected(self, fake_service: _FakeService) -> None:
        fake_service.respond_as = 'rest'
        client = UserTokenClient(fake_service.url, id_token_source=lambda: _idt('jane'))
        with pytest.raises(UserTokenClientError, match='token_type'):
            client.fetch_token('session')

    def test_requires_service_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv('SG_USER_TOKEN_URL', raising=False)
        with pytest.raises(UserTokenClientError, match='SG_USER_TOKEN_URL'):
            UserTokenClient(id_token_source=lambda: _idt('jane'))

    def test_rest_cache_until_must_equal_expiry(self, fake_service: _FakeService) -> None:
        fake_service.corrupt_rest_cache_until = True
        client = UserTokenClient(fake_service.url, id_token_source=lambda: _idt('jane'))
        with pytest.raises(UserTokenClientError, match='cache_until'):
            client.fetch_token('rest')

    def test_rest_refreshes_near_expiry(self, fake_service: _FakeService) -> None:
        fake_service.rest_expires_in = 30
        client = UserTokenClient(fake_service.url, id_token_source=lambda: _idt('jane'))
        client.fetch_token('rest')
        client.fetch_token('rest')
        assert fake_service.request_count == 2

    def test_session_is_cached_until_force_refresh(
        self, fake_service: _FakeService, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = UserTokenClient(fake_service.url, id_token_source=lambda: _idt('jane'))
        first = client.fetch_token('session')
        after_cache_horizon = first.cache_until + datetime.timedelta(seconds=1)

        class FixedDateTime(datetime.datetime):
            @classmethod
            def now(cls, tz: datetime.tzinfo | None = None) -> datetime.datetime:
                assert tz is datetime.UTC
                return after_cache_horizon

        monkeypatch.setattr(datetime, 'datetime', FixedDateTime)
        second = client.fetch_token('session')
        assert first.token == second.token
        assert fake_service.request_count == 1
        client.fetch_token('session', force_refresh=True)
        assert fake_service.request_count == 2
        assert 'refresh=true' in fake_service.last_query

    def test_session_with_expiry_is_rejected(self, fake_service: _FakeService) -> None:
        fake_service.corrupt_session_expiry = True
        client = UserTokenClient(fake_service.url, id_token_source=lambda: _idt('jane'))
        with pytest.raises(UserTokenClientError, match='expires_at'):
            client.fetch_token('session')

    def test_sign_in_failures_surface_as_client_errors(self, fake_service: _FakeService) -> None:

        def failing_source() -> str:
            raise SignInError('browser timeout')

        client = UserTokenClient(fake_service.url, id_token_source=failing_source)
        with pytest.raises(UserTokenClientError, match='sign-in failed'):
            client.fetch_token('session')

    def test_source_is_consulted_on_every_call(self, fake_service: _FakeService) -> None:
        calls: list[int] = []

        def source() -> str:
            calls.append(1)
            return _idt('jane')

        client = UserTokenClient(fake_service.url, id_token_source=source)
        client.fetch_token('session')
        client.fetch_token('session')
        assert len(calls) == 2
        assert fake_service.request_count == 1

    def test_two_part_id_token_is_a_client_error(self, fake_service: _FakeService) -> None:
        id_token = _idt('jane').removesuffix('.')
        client = UserTokenClient(fake_service.url, id_token_source=lambda: id_token)
        with pytest.raises(UserTokenClientError, match='sub'):
            client.fetch_token('session')

    def test_unknown_requested_token_type_is_rejected(self, fake_service: _FakeService) -> None:
        client = UserTokenClient(fake_service.url, id_token_source=lambda: _idt('jane'))
        with pytest.raises(UserTokenClientError, match='token_type'):
            client.fetch_token('bearer')

    def test_unknown_response_token_type_is_rejected(self, fake_service: _FakeService) -> None:
        fake_service.respond_as = 'bearer'
        client = UserTokenClient(fake_service.url, id_token_source=lambda: _idt('jane'))
        with pytest.raises(UserTokenClientError, match='token_type'):
            client.fetch_token('session')


def _idt_from_payload(payload: dict[str, object]) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b'=').decode()
    encoded = json.dumps(payload).encode()
    body = base64.urlsafe_b64encode(encoded).rstrip(b'=').decode()
    return f'{header}.{body}.'


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
def fake_service() -> Iterator[_FakeService]:
    state = _FakeService()

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
            now = datetime.datetime.now(datetime.UTC)
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
