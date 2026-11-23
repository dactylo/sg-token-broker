import base64
import hashlib
import json
import socket
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from functools import partial
from http.client import HTTPResponse
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import Path
from queue import Queue
from types import SimpleNamespace
from typing import Protocol
from unittest.mock import Mock
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
import requests

import sg_token_broker._userauth as userauth
from sg_token_broker._userauth import (
    _GOOGLE_AUTHORIZATION_ENDPOINT,
    SignInError,
    _refresh_id_token,
    _TokenBundle,
    account_from_id_token,
    default_id_token_source,
    identity_settings,
)
from tests._timeouts import STALL_TIMEOUT_SECONDS

_CALLBACK_REQUEST_TIMEOUT_SECONDS = userauth._REQUEST_TIMEOUT_SECONDS
_CALLBACK_WAKEUP_TIMEOUT_SECONDS = userauth._WAKEUP_TIMEOUT_SECONDS
# Stored Google sign-ins live under this keyring issuer; changing it orphans them.
_GOOGLE_KEYRING_ISSUER = 'https://oauth2.googleapis.com/token'
_PROVIDER_ENDPOINT = 'https://idp.example/token'

_sign_in = partial(userauth.sign_in, timeout=STALL_TIMEOUT_SECONDS)


class TestAccountFromIdToken:
    def test_falls_back_to_sub(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv('SG_USER_TOKEN_EMAIL_CLAIM', raising=False)
        assert account_from_id_token(_id_token({'sub': 'abc123'})) == 'abc123'

    def test_reads_the_configured_claim(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv('SG_USER_TOKEN_EMAIL_CLAIM', 'upn')
        token = _id_token({'upn': 'jane@corp.example', 'email': 'other@x'})
        assert account_from_id_token(token) == 'jane@corp.example'


class TestIdentitySettings:
    @pytest.mark.parametrize('invalid_endpoint', [None, 'authorization', 'token'])
    def test_discovered_settings_validate_endpoints(
        self, monkeypatch: pytest.MonkeyPatch, invalid_endpoint: str | None
    ) -> None:
        monkeypatch.setenv('SG_USER_TOKEN_CLIENT_ID', 'client-1')
        monkeypatch.setenv('SG_USER_TOKEN_ISSUER', 'https://idp.example')
        document = {
            'issuer': 'https://idp.example',
            'authorization_endpoint': 'https://idp.example/authorize',
            'token_endpoint': 'https://idp.example/token',
        }
        response = Mock(status_code=200, json=Mock(return_value=document))
        monkeypatch.setattr(requests, 'get', Mock(return_value=response))

        if invalid_endpoint is not None:
            document[f'{invalid_endpoint}_endpoint'] = 'http://idp.example/unsafe'
            with pytest.raises(SignInError, match=f'invalid {invalid_endpoint} endpoint'):
                identity_settings()
            return

        assert identity_settings() == (
            'https://idp.example',
            'client-1',
            'https://idp.example/authorize',
            'https://idp.example/token',
        )

    @pytest.mark.parametrize('status', [302, 307])
    def test_discovery_redirect_is_rejected(
        self, monkeypatch: pytest.MonkeyPatch, status: int
    ) -> None:
        monkeypatch.setenv('SG_USER_TOKEN_CLIENT_ID', 'client-1')
        monkeypatch.setenv('SG_USER_TOKEN_ISSUER', 'https://idp.example')
        response = requests.Response()
        response.status_code = status
        get = Mock(return_value=response)
        monkeypatch.setattr(requests, 'get', get)

        with pytest.raises(SignInError, match=f'OIDC discovery .* returned {status}'):
            identity_settings()

        assert get.call_args.kwargs['allow_redirects'] is False


class _Browser:
    authorization_endpoint = 'https://idp.example/authorize'

    def __init__(self) -> None:
        self.authorization_query: dict[str, list[str]] = {}
        self.authorization_error: tuple[str, str] | None = None
        self.second_callback_rejected = False
        self.tamper_state = False

    def scripted_browser(self, url: str) -> object:
        self.authorization_query = parse_qs(urlsplit(url).query)
        state = self.authorization_query['state'][0]
        if self.tamper_state:
            state = 'wrong'
        redirect_uri = self.authorization_query['redirect_uri'][0]
        if self.authorization_error is None:
            query = {'code': 'fake-code', 'state': state}
        else:
            error, description = self.authorization_error
            query = {'error': error, 'error_description': description, 'state': state}
        with urllib.request.urlopen(  # noqa: S310 - controlled loopback test URL
            f'{redirect_uri}?{urlencode(query)}'
        ) as response:
            result = response.read()
        if self.second_callback_rejected:
            # A request queued before listener shutdown is reset rather than refused.
            with pytest.raises((urllib.error.URLError, ConnectionResetError)):
                urllib.request.urlopen(  # noqa: S310 - controlled loopback test URL
                    f'{redirect_uri}?code=second&state=wrong'
                )
        return result


class _CallablePatcher(Protocol):
    def delenv(self, name: str, raising: bool = True) -> None: ...

    def setattr(self, target: object, name: str, value: Callable[..., object]) -> None: ...

    def setenv(self, name: str, value: str, prepend: str | None = None) -> None: ...


class TestDefaultIdTokenSource:
    @pytest.fixture(autouse=True)
    def _google_env(self, monkeypatch: _CallablePatcher) -> None:
        monkeypatch.setenv('SG_USER_TOKEN_CLIENT_ID', 'client-1')
        monkeypatch.delenv('SG_USER_TOKEN_CLIENT_SECRET', raising=False)
        monkeypatch.delenv('SG_USER_TOKEN_ISSUER', raising=False)
        monkeypatch.delenv('SG_USER_TOKEN_EMAIL_CLAIM', raising=False)
        monkeypatch.setenv('SG_USER_TOKEN_ACCOUNT', 'jane@s.example')

    def test_account_falls_back_to_the_stored_pointer(self, monkeypatch: _CallablePatcher) -> None:
        monkeypatch.delenv('SG_USER_TOKEN_ACCOUNT', raising=False)
        monkeypatch.setattr(userauth, 'load_account', lambda *_args: 'jane@s.example')
        loaded: list[str] = []

        def load_refresh_token(_issuer: str, _client_id: str, account: str) -> str:
            loaded.append(account)
            return 'rt-1'

        monkeypatch.setattr(
            userauth,
            'load_refresh_token',
            load_refresh_token,
        )
        monkeypatch.setattr(
            userauth, '_refresh_id_token', lambda *_args, **_kwargs: ('idt-2', None)
        )
        assert default_id_token_source()() == 'idt-2'
        assert loaded == ['jane@s.example', 'jane@s.example']

    def test_account_switch_discards_the_reused_sign_in(
        self, monkeypatch: _CallablePatcher
    ) -> None:
        monkeypatch.delenv('SG_USER_TOKEN_ACCOUNT', raising=False)
        accounts = iter(['jane@s.example', 'jane@s.example', 'bob@s.example'])
        monkeypatch.setattr(userauth, 'load_account', lambda *_args: next(accounts))
        monkeypatch.setattr(userauth, 'load_refresh_token', lambda *_args: None)
        tokens = iter(
            _id_token({'email': email, 'exp': int(time.time()) + 3600})
            for email in ('jane@s.example', 'bob@s.example')
        )
        monkeypatch.setattr(
            userauth, 'sign_in', lambda *_args, **_kwargs: _TokenBundle(id_token=next(tokens))
        )
        source = default_id_token_source()

        jane, bob = source(), source()

        assert account_from_id_token(jane) == 'jane@s.example'
        assert account_from_id_token(bob) == 'bob@s.example'

    def test_account_switch_never_overwrites_the_stored_credential(
        self, monkeypatch: _CallablePatcher
    ) -> None:
        bob_token = _id_token({'email': 'bob@s.example'})
        monkeypatch.setattr(userauth, 'load_refresh_token', lambda *_args: 'rt-1')
        stored: list[object] = []
        monkeypatch.setattr(
            userauth, 'store_refresh_token', lambda *args: stored.append(args) or True
        )
        responses = iter([(None, None), ('idt-3', 'rt-10')])

        def interactive(_client_id: str, **_kwargs: object) -> _TokenBundle:
            return _TokenBundle(
                id_token=bob_token,
                refresh_token='rt-9',  # noqa: S106 - fake credential
            )

        monkeypatch.setattr(
            userauth, '_refresh_id_token', lambda *_args, **_kwargs: next(responses)
        )
        monkeypatch.setattr(
            userauth,
            'sign_in',
            interactive,
        )
        source = default_id_token_source()
        assert source() == bob_token
        assert source() == 'idt-3'
        assert stored == []

    def test_configured_client_secret_reaches_refresh_and_sign_in(
        self, monkeypatch: _CallablePatcher, fake_provider: '_FakeProvider'
    ) -> None:
        monkeypatch.setenv('SG_USER_TOKEN_CLIENT_SECRET', ' secret-1 ')
        fake_provider.refresh_response = {'id_token': ''}
        monkeypatch.setattr(
            userauth,
            'identity_settings',
            lambda: (
                _GOOGLE_KEYRING_ISSUER,
                'client-1',
                fake_provider.authorization_endpoint,
                fake_provider.token_endpoint,
            ),
        )
        monkeypatch.setattr(userauth, 'load_refresh_token', lambda *_args: 'rt-1')
        interactive = Mock(return_value=_TokenBundle(id_token=_id_token({'email': 'j@s.example'})))
        monkeypatch.setattr(userauth, 'sign_in', interactive)

        default_id_token_source()()

        assert fake_provider.token_form['client_secret'] == ['secret-1']
        assert [interactive.call_args.kwargs['client_secret']] == ['secret-1']

    def test_empty_refresh_token_result_reauthenticates(
        self, monkeypatch: _CallablePatcher, fake_provider: '_FakeProvider'
    ) -> None:
        fake_provider.refresh_response = {'id_token': ''}
        monkeypatch.setattr(
            userauth,
            'identity_settings',
            lambda: (
                _GOOGLE_KEYRING_ISSUER,
                'client-1',
                fake_provider.authorization_endpoint,
                fake_provider.token_endpoint,
            ),
        )
        monkeypatch.setattr(userauth, 'load_refresh_token', lambda *_args: 'rt-1')
        interactive_token = _id_token({'email': 'jane@s.example'})
        interactive = Mock(return_value=_TokenBundle(id_token=interactive_token))
        monkeypatch.setattr(userauth, 'sign_in', interactive)

        assert default_id_token_source()() == interactive_token
        interactive.assert_called_once_with(
            'client-1',
            authorization_endpoint=fake_provider.authorization_endpoint,
            token_endpoint=fake_provider.token_endpoint,
            client_secret=None,
            issuer=_GOOGLE_KEYRING_ISSUER,
        )
        assert fake_provider.token_form['grant_type'] == ['refresh_token']
        assert 'client_secret' not in fake_provider.token_form

    def test_factory_result_repr_hides_the_credential(self, monkeypatch: _CallablePatcher) -> None:
        credential = 'credential-that-must-not-appear'
        monkeypatch.setattr(userauth, 'load_refresh_token', lambda *_args: credential)

        source = default_id_token_source()

        assert credential not in repr(source)

    def test_failed_interactive_store_does_not_revive_the_stale_credential(
        self, monkeypatch: _CallablePatcher
    ) -> None:
        token = _id_token({'email': 'jane@s.example'})
        stale_credential = 'rt-old'
        fresh_credential = 'rt-new'
        monkeypatch.setattr(userauth, 'load_refresh_token', lambda *_args: stale_credential)
        monkeypatch.setattr(userauth, 'load_account', lambda *_args: 'jane@s.example')
        monkeypatch.setattr(userauth, 'store_refresh_token', lambda *_args: False)
        browser_opens: list[str] = []

        def interactive(_client_id: str, **_kwargs: object) -> _TokenBundle:
            browser_opens.append('open')
            return _TokenBundle(id_token=token, refresh_token=fresh_credential)

        refreshes: list[str] = []

        def refresh(
            _client_id: str, refresh_token: str, **_kwargs: object
        ) -> tuple[str, str | None]:
            refreshes.append(refresh_token)
            if refresh_token == stale_credential:
                raise SignInError('rejected')
            return token, None

        monkeypatch.setattr(userauth, '_refresh_id_token', refresh)
        monkeypatch.setattr(userauth, 'sign_in', interactive)
        source = default_id_token_source()
        assert [source(), source(), source()] == [token, token, token]
        assert browser_opens == ['open']
        assert refreshes == [stale_credential, fresh_credential, fresh_credential]

    def test_failed_persist_stops_further_store_attempts(
        self, monkeypatch: _CallablePatcher
    ) -> None:
        monkeypatch.setattr(userauth, 'load_refresh_token', lambda *_args: 'rt-1')
        attempts: list[object] = []
        monkeypatch.setattr(
            userauth, 'store_refresh_token', lambda *args: attempts.append(args) or False
        )
        responses = iter([('idt-2', 'rt-2'), ('idt-3', 'rt-3')])
        monkeypatch.setattr(
            userauth, '_refresh_id_token', lambda *_args, **_kwargs: next(responses)
        )
        source = default_id_token_source()
        assert source() == 'idt-2'
        assert source() == 'idt-3'
        assert len(attempts) == 1

    def test_interactive_without_stored_credential_stays_memory_only(
        self, monkeypatch: _CallablePatcher
    ) -> None:
        token = _id_token({'email': 'jane@s.example'})
        monkeypatch.setattr(userauth, 'load_refresh_token', lambda *_args: None)
        stored: list[object] = []

        def interactive(_client_id: str, **_kwargs: object) -> _TokenBundle:
            return _TokenBundle(
                id_token=token,
                refresh_token='rt-1',  # noqa: S106 - fake credential
            )

        monkeypatch.setattr(
            userauth, 'store_refresh_token', lambda *args: stored.append(args) or True
        )
        monkeypatch.setattr(
            userauth,
            'sign_in',
            interactive,
        )
        assert default_id_token_source()() == token
        assert stored == []

    def test_missing_stored_credential_at_refresh_time_reauths(
        self, monkeypatch: _CallablePatcher
    ) -> None:
        token = _id_token({'email': 'jane@s.example'})
        values = iter(['rt-1', None])

        def interactive(_client_id: str, **_kwargs: object) -> _TokenBundle:
            return _TokenBundle(id_token=token, refresh_token=None)

        monkeypatch.setattr(userauth, 'load_refresh_token', lambda *_args: next(values))
        monkeypatch.setattr(
            userauth,
            '_refresh_id_token',
            lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError()),
        )
        monkeypatch.setattr(
            userauth,
            'sign_in',
            interactive,
        )
        assert default_id_token_source()() == token

    def test_reauths_when_refresh_returns_no_id_token(self, monkeypatch: _CallablePatcher) -> None:
        token = _id_token({'email': 'jane@s.example'})
        monkeypatch.setattr(userauth, 'load_refresh_token', lambda *_args: 'rt-1')
        stored: list[tuple[str, str, str, str]] = []

        def interactive(_client_id: str, **_kwargs: object) -> _TokenBundle:
            return _TokenBundle(
                id_token=token,
                refresh_token='rt-2',  # noqa: S106 - fake credential
            )

        monkeypatch.setattr(
            userauth, 'store_refresh_token', lambda *args: stored.append(args) or True
        )
        monkeypatch.setattr(userauth, '_refresh_id_token', lambda *_args, **_kwargs: (None, None))
        monkeypatch.setattr(
            userauth,
            'sign_in',
            interactive,
        )
        assert default_id_token_source()() == token
        assert stored == [(_GOOGLE_KEYRING_ISSUER, 'client-1', 'jane@s.example', 'rt-2')]

    def test_refreshes_silently_and_persists_rotation(self, monkeypatch: _CallablePatcher) -> None:
        monkeypatch.setattr(userauth, 'load_refresh_token', lambda *_args: 'rt-1')
        stored: list[tuple[str, str, str, str]] = []
        monkeypatch.setattr(
            userauth, 'store_refresh_token', lambda *args: stored.append(args) or True
        )
        monkeypatch.setattr(
            userauth, '_refresh_id_token', lambda *_args, **_kwargs: ('idt-2', 'rt-2')
        )
        source = default_id_token_source()
        assert source() == 'idt-2'
        assert stored == [(_GOOGLE_KEYRING_ISSUER, 'client-1', 'jane@s.example', 'rt-2')]

    def test_reloads_the_stored_account_before_refreshing(
        self, monkeypatch: _CallablePatcher
    ) -> None:
        monkeypatch.delenv('SG_USER_TOKEN_ACCOUNT', raising=False)
        stored_account = ['a@s.example']
        monkeypatch.setattr(userauth, 'load_account', lambda *_args: stored_account[0])
        credentials = {'a@s.example': 'rt-a', 'b@s.example': 'rt-b'}

        def load_refresh_token(_issuer: str, _client_id: str, account: str) -> str:
            return credentials[account]

        monkeypatch.setattr(
            userauth,
            'load_refresh_token',
            load_refresh_token,
        )
        used: list[str] = []

        def refresh(_client_id: str, refresh_token: str, **_kwargs: object) -> tuple[str, None]:
            used.append(refresh_token)
            return f'idt-{refresh_token}', None

        monkeypatch.setattr(userauth, '_refresh_id_token', refresh)
        source = default_id_token_source()

        assert source() == 'idt-rt-a'
        stored_account[0] = 'b@s.example'
        assert source() == 'idt-rt-b'
        assert used == ['rt-a', 'rt-b']

    def test_reloads_the_stored_credential_before_refreshing(
        self, monkeypatch: _CallablePatcher
    ) -> None:
        values = iter(['rt-1', 'rt-2', 'rt-3'])
        monkeypatch.setattr(userauth, 'load_refresh_token', lambda *_args: next(values))
        used: list[str] = []

        def refresh(client_id: str, refresh_token: str, **kwargs: object) -> tuple[str, None]:
            del client_id, kwargs
            used.append(refresh_token)
            return 'idt-2', None

        monkeypatch.setattr(userauth, '_refresh_id_token', refresh)
        source = default_id_token_source()

        assert [source(), source()] == ['idt-2', 'idt-2']
        assert used == ['rt-2', 'rt-3']

    def test_removal_after_interactive_store_discards_the_new_refresh_credential(
        self, monkeypatch: _CallablePatcher
    ) -> None:
        stored: list[str | None] = ['rt-old']
        monkeypatch.setattr(userauth, 'load_refresh_token', lambda *_args: stored[0])

        def store(*args: str) -> bool:
            stored[0] = args[-1]
            return True

        monkeypatch.setattr(userauth, 'store_refresh_token', store)
        tokens = [
            _id_token({'email': 'jane@s.example', 'exp': int(time.time()) + lifetime})
            for lifetime in (3600, 7200)
        ]
        interactive = Mock(
            side_effect=[_TokenBundle(tokens[0], 'rt-new'), _TokenBundle(tokens[1])]
        )
        refresh = Mock(return_value=('stale-refresh-result', None))
        monkeypatch.setattr(userauth, 'sign_in', interactive)
        monkeypatch.setattr(userauth, '_refresh_id_token', refresh)
        source = default_id_token_source()

        stored[0] = None
        assert source() == tokens[0]
        assert stored[0] == 'rt-new'
        stored[0] = None
        assert source() == tokens[1]
        assert source() == tokens[1]
        refresh.assert_not_called()
        assert interactive.call_count == 2

    @pytest.mark.parametrize('earlier_sign_in', [False, True])
    def test_removed_credential_reauthenticates_once_then_reuses_until_expiry(
        self, monkeypatch: pytest.MonkeyPatch, earlier_sign_in: bool
    ) -> None:
        now = [1_700_000_000]
        monkeypatch.setattr(userauth, 'time', SimpleNamespace(time=lambda: now[0]))
        stored: list[str | None] = ['rt-old']

        def load_refresh_token(*_args: object) -> str | None:
            return stored[0]

        monkeypatch.setattr(userauth, 'load_refresh_token', load_refresh_token)
        tokens = [
            _id_token({'email': 'jane@s.example', 'exp': now[0] + lifetime})
            for lifetime in (4000, 3600, 7200, 8000)
        ]
        interactive = Mock(
            side_effect=[_TokenBundle(id_token=token) for token in tokens[not earlier_sign_in :]]
        )
        refresh = Mock(return_value=(None, None))
        monkeypatch.setattr(userauth, 'sign_in', interactive)
        monkeypatch.setattr(userauth, '_refresh_id_token', refresh)
        source = default_id_token_source()
        if earlier_sign_in:
            assert source() == tokens[0]

        stored[0] = None
        assert source() == tokens[1]
        assert source() == tokens[1]
        assert interactive.call_count == 1 + earlier_sign_in
        assert refresh.call_count == int(earlier_sign_in)

        now[0] += 3540
        assert source() == tokens[2]
        assert interactive.call_count == 2 + earlier_sign_in

        stored[0] = 'rt-restored'
        refresh.return_value = ('restored-id-token', None)
        assert source() == 'restored-id-token'
        assert refresh.call_args.args == ('client-1', 'rt-restored')
        assert interactive.call_count == 2 + earlier_sign_in

        stored[0] = None
        assert source() == tokens[3]
        assert source() == tokens[3]
        assert interactive.call_count == 3 + earlier_sign_in

    @pytest.mark.parametrize(
        ('lifetime', 'sign_ins'),
        [(3600, 1), (60, 2), (None, 2)],
        ids=['fresh', 'within-margin', 'no-exp'],
    )
    def test_sign_in_without_refresh_token_is_reused_until_near_expiry(
        self, monkeypatch: _CallablePatcher, lifetime: int | None, sign_ins: int
    ) -> None:
        payload: dict[str, object] = {'email': 'jane@s.example'}
        if lifetime is not None:
            payload['exp'] = int(time.time()) + lifetime
        token = _id_token(payload)
        monkeypatch.setattr(userauth, 'load_refresh_token', lambda *_args: None)
        calls: list[str] = []

        def interactive(client_id: str, **_kwargs: object) -> _TokenBundle:
            calls.append(client_id)
            return _TokenBundle(id_token=token)

        monkeypatch.setattr(userauth, 'sign_in', interactive)
        source = default_id_token_source()

        assert [source(), source()] == [token, token]
        assert len(calls) == sign_ins


class _CallbackReads:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._monkeypatch = monkeypatch
        self.reads: Queue[threading.Event | None] = Queue()
        self._gates: list[threading.Event] = []
        self._released = False
        self.errors: list[BaseException] = []
        self._closed_at_join: list[bool] = []
        original_read = socket.SocketIO.readinto
        outer = self

        class Callback(userauth._CallbackServer):
            def _serve_until_callback(self) -> None:
                try:
                    super()._serve_until_callback()
                finally:
                    error = sys.exception()
                    if error is not None:
                        outer.errors.append(error)
                    outer.reads.put(None)

        def read(reader: socket.SocketIO, buffer: bytearray) -> int | None:
            if threading.current_thread() is self.callback._thread and not self._released:
                gate = threading.Event()
                self._gates.append(gate)
                self.reads.put(gate)
                gate.wait()
            return original_read(reader, buffer)

        monkeypatch.setattr(socket.SocketIO, 'readinto', read)
        self.callback = Callback()

    def assert_closed_before_join(self) -> None:
        assert self._closed_at_join == [True], 'active callback socket was not closed before join'
        assert not self.callback._thread.is_alive()
        assert not self.errors

    def next_read(self) -> threading.Event:
        gate = self.reads.get()
        assert not self.errors
        assert gate is not None, 'callback thread exited before its next socket read'
        return gate

    def release(self) -> None:
        self._released = True
        for gate in self._gates:
            gate.set()

    def observe_close(self, client: socket.socket) -> None:
        request = self.callback._active_request
        assert request is not None
        shutdowns: list[socket.socket] = []
        closes: list[socket.socket] = []
        original_shutdown = socket.socket.shutdown
        original_close = socket.socket.close
        original_join = self.callback._thread.join

        def shutdown(sock: socket.socket, how: int) -> None:
            if sock is request and how == socket.SHUT_RDWR:
                shutdowns.append(sock)
            original_shutdown(sock, how)

        def close(sock: socket.socket) -> None:
            if sock is request:
                closes.append(sock)
            original_close(sock)

        def join(timeout: float | None = None) -> None:
            del timeout
            self._closed_at_join.append(request in shutdowns and request in closes)
            # Release even a defective implementation, then assert the recorded cause.
            # This lets a missing socket interruption fail without the hang backstop.
            with suppress(OSError):
                original_shutdown(client, socket.SHUT_RDWR)
            self.release()
            original_join()

        self._monkeypatch.setattr(socket.socket, 'shutdown', shutdown)
        self._monkeypatch.setattr(socket.socket, 'close', close)
        self._monkeypatch.setattr(self.callback._thread, 'join', join)


class _FakeProvider(_Browser):
    def __init__(self) -> None:
        super().__init__()
        self.refresh_response: dict[str, object] = {'id_token': 'idt-2'}
        self.token_body_override: bytes | None = None
        self.token_form: dict[str, list[str]] = {}
        self.token_status = 200
        self.wrong_nonce = False
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers['Content-Length'])
                outer.token_form = parse_qs(self.rfile.read(length).decode())
                body = outer.token_body_override
                if body is None:
                    if outer.token_form['grant_type'] == ['refresh_token']:
                        response = outer.refresh_response
                    else:
                        nonce = outer.authorization_query['nonce'][0]
                        if outer.wrong_nonce:
                            nonce = 'wrong'
                        response = {
                            'id_token': _id_token({'nonce': nonce}),
                            'refresh_token': 'rt-1',
                        }
                    body = json.dumps(response).encode()
                self.send_response(outer.token_status)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object, **kwargs: object) -> None:
                del args, kwargs

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True
        )
        self.token_endpoint = f'http://127.0.0.1:{self.server.server_address[1]}/token'

    @property
    def issued_id_token(self) -> str:
        nonce = self.authorization_query['nonce'][0]
        return _id_token({'nonce': nonce})

    @property
    def issued_refresh_token(self) -> str:
        return 'rt-1'


class TestMalformedTokenEndpoint:
    @pytest.mark.parametrize('operation', ['refresh', 'code exchange'])
    @pytest.mark.parametrize(
        ('body', 'message'),
        [
            (b'not json', 'token endpoint returned a non-JSON body'),
            (b'[]', 'token endpoint returned a malformed body'),
        ],
        ids=['invalid-json', 'non-object'],
    )
    def test_malformed_body_is_a_sign_in_error(
        self, fake_provider: _FakeProvider, operation: str, body: bytes, message: str
    ) -> None:
        fake_provider.token_body_override = body
        if operation == 'refresh':
            exchange = partial(
                _refresh_id_token, 'client-1', 'rt-1', token_endpoint=fake_provider.token_endpoint
            )
        else:
            exchange = partial(
                _sign_in,
                'client-1',
                authorization_endpoint=fake_provider.authorization_endpoint,
                token_endpoint=fake_provider.token_endpoint,
                open_browser=fake_provider.scripted_browser,
            )
        with pytest.raises(SignInError, match=message):
            exchange()

    def test_provider_rejection_reports_oauth_error(self) -> None:
        response = Mock(
            status_code=400,
            json=Mock(return_value={'error': 'invalid_grant', 'error_description': 'Bad Request'}),
        )
        session = Mock(post=Mock(return_value=response))

        with pytest.raises(SignInError) as caught:
            userauth._post_token_endpoint(
                session,
                'https://idp.example/token',
                {'grant_type': 'refresh_token'},
                operation='refresh',
            )

        assert str(caught.value).startswith(
            'refresh rejected (HTTP 400) at https://idp.example: invalid_grant'
        )
        assert 'sign in again' in str(caught.value)
        assert 'Bad Request' not in str(caught.value)


class TestRefreshIdToken:
    @pytest.mark.parametrize(
        'response',
        [{'access_token': 'at'}, {'id_token': ''}, {'id_token': 42}],
        ids=['absent', 'empty', 'non-string'],
    )
    def test_missing_id_token_signals_reauth(
        self, fake_provider: _FakeProvider, response: dict[str, object]
    ) -> None:
        fake_provider.refresh_response = response
        id_token, _ = _refresh_id_token(
            'client-1', 'rt-1', token_endpoint=fake_provider.token_endpoint
        )
        assert id_token is None

    @pytest.mark.parametrize(('secret', 'sent'), [(None, []), ('secret-1', ['secret-1'])])
    def test_client_secret_is_sent_only_when_configured(
        self, fake_provider: _FakeProvider, secret: str | None, sent: list[str]
    ) -> None:
        _refresh_id_token(
            'client-1', 'rt-1', token_endpoint=fake_provider.token_endpoint, client_secret=secret
        )
        assert fake_provider.token_form.get('client_secret', []) == sent

    def test_refresh_exchange_disables_redirects(self, monkeypatch: pytest.MonkeyPatch) -> None:
        response = requests.Response()
        response.status_code = 307
        post = Mock(return_value=response)
        monkeypatch.setattr(requests.Session, 'post', post)
        endpoint = 'https://idp.example/token'

        with pytest.raises(SignInError, match='HTTP 307'):
            _refresh_id_token(
                'client-1',
                'rt-1',
                token_endpoint=endpoint,
            )

        assert post.call_args.kwargs['allow_redirects'] is False

    def test_returns_new_id_token_and_rotation(self, fake_provider: _FakeProvider) -> None:
        fake_provider.refresh_response = {'id_token': 'idt-2', 'refresh_token': 'rt-2'}
        result = _refresh_id_token('client-1', 'rt-1', token_endpoint=fake_provider.token_endpoint)
        assert result == ('idt-2', 'rt-2')
        assert fake_provider.token_form == {
            'grant_type': ['refresh_token'],
            'client_id': ['client-1'],
            'refresh_token': ['rt-1'],
        }


class TestSignIn:
    def test_authorization_endpoint_query_is_preserved(self, fake_provider: _FakeProvider) -> None:
        _sign_in(
            'client-1',
            authorization_endpoint=f'{fake_provider.authorization_endpoint}?tenant=studio',
            token_endpoint=fake_provider.token_endpoint,
            open_browser=fake_provider.scripted_browser,
        )

        assert fake_provider.authorization_query['tenant'] == ['studio']
        assert fake_provider.authorization_query['client_id'] == ['client-1']
        assert fake_provider.authorization_query['response_type'] == ['code']

    def test_callback_is_one_shot(self, fake_provider: _FakeProvider) -> None:
        fake_provider.second_callback_rejected = True
        bundle = _sign_in(
            'client-1',
            authorization_endpoint=fake_provider.authorization_endpoint,
            token_endpoint=fake_provider.token_endpoint,
            open_browser=fake_provider.scripted_browser,
        )
        assert bundle.id_token == fake_provider.issued_id_token
        assert fake_provider.token_form['code'] == ['fake-code']

    def test_callback_page_reports_a_provider_error(self, fake_provider: _FakeProvider) -> None:
        fake_provider.authorization_error = ('access_denied', 'The user denied access.')
        pages: list[bytes] = []

        def browser(url: str) -> object:
            page = fake_provider.scripted_browser(url)
            assert isinstance(page, bytes)
            pages.append(page)
            return True

        with pytest.raises(SignInError, match='access_denied'):
            _sign_in(
                'client-1',
                authorization_endpoint=fake_provider.authorization_endpoint,
                token_endpoint=fake_provider.token_endpoint,
                open_browser=browser,
            )
        assert b'did not finish' in pages[0].lower()

    def test_callback_page_sends_the_person_back_to_the_program(
        self, fake_provider: _FakeProvider
    ) -> None:
        pages: list[bytes] = []

        def browser(url: str) -> object:
            page = fake_provider.scripted_browser(url)
            assert isinstance(page, bytes)
            pages.append(page)
            return True

        _sign_in(
            'client-1',
            authorization_endpoint=fake_provider.authorization_endpoint,
            token_endpoint=fake_provider.token_endpoint,
            open_browser=browser,
        )
        assert b'complete' not in pages[0].lower()
        assert b'return to the program' in pages[0].lower()

    def test_callback_response_failure_still_completes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        callback = userauth._CallbackServer()
        original_flush = BaseHTTPRequestHandler.flush_headers

        def fail_response(handler: BaseHTTPRequestHandler) -> None:
            if handler.server is callback:
                raise BrokenPipeError
            original_flush(handler)

        monkeypatch.setattr(BaseHTTPRequestHandler, 'flush_headers', fail_response)
        try:
            host, port = callback._address
            with pytest.raises(requests.ConnectionError):
                requests.get(
                    f'http://{host}:{port}/callback?code=ok&state=expected',
                )
            callback._thread.join()
            assert (
                callback.code,
                callback.state,
                callback.received.is_set(),
                callback._thread.is_alive(),
            ) == ('ok', 'expected', True, False)
        finally:
            callback._close()

    def test_close_is_bounded_when_the_wakeup_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(userauth, '_WAKEUP_TIMEOUT_SECONDS', _CALLBACK_WAKEUP_TIMEOUT_SECONDS)
        # No real serving thread is needed to verify the bound passed to join.
        callback = _StoppedCallback(join_timeout=userauth._JOIN_TIMEOUT_SECONDS)
        callback._thread.join()
        thread = Mock(is_alive=Mock(return_value=True))
        monkeypatch.setattr(callback, '_thread', thread)
        wakeup = Mock(side_effect=TimeoutError('injected wakeup deadline'))
        original_connect = socket.create_connection

        def connect(
            address: tuple[str, int],
            timeout: float | None = None,
            source_address: tuple[str, int] | None = None,
            *,
            all_errors: bool = False,
        ) -> socket.socket:
            if address == callback._address:
                return wakeup(address, timeout=timeout)
            return original_connect(address, timeout, source_address, all_errors=all_errors)

        monkeypatch.setattr(socket, 'create_connection', connect)
        expired_wait = Mock(return_value=False)
        monkeypatch.setattr(callback.received, 'wait', expired_wait)

        with pytest.raises(SignInError, match='timed out'):
            callback._wait(userauth._SIGN_IN_TIMEOUT_SECONDS)

        expired_wait.assert_called_once_with(userauth._SIGN_IN_TIMEOUT_SECONDS)
        thread.join.assert_called_once_with(userauth._JOIN_TIMEOUT_SECONDS)
        wakeup.assert_called_once_with(callback._address, timeout=0.25)
        assert callback.socket.fileno() == -1

    @pytest.mark.parametrize(('secret', 'sent'), [(None, []), ('secret-1', ['secret-1'])])
    def test_code_exchange_sends_client_secret_only_when_configured(
        self, fake_provider: _FakeProvider, secret: str | None, sent: list[str]
    ) -> None:
        _sign_in(
            'client-1',
            authorization_endpoint=fake_provider.authorization_endpoint,
            token_endpoint=fake_provider.token_endpoint,
            open_browser=fake_provider.scripted_browser,
            client_secret=secret,
        )
        assert fake_provider.token_form.get('client_secret', []) == sent

    @pytest.mark.parametrize(
        'result',
        [RuntimeError('browser unavailable'), False, None],
        ids=['exception', 'false', 'none'],
    )
    @pytest.mark.usefixtures('no_requests')
    def test_browser_failure_closes_callback(self, result: RuntimeError | bool | None) -> None:
        callback_threads: set[threading.Thread] = set()
        redirect_uri = ''
        threads_before = set(threading.enumerate())

        def rejected_browser(url: str) -> object:
            nonlocal callback_threads, redirect_uri
            callback_threads = set(threading.enumerate()) - threads_before
            redirect_uri = parse_qs(urlsplit(url).query)['redirect_uri'][0]
            if isinstance(result, RuntimeError):
                raise result
            return result

        with pytest.raises(SignInError, match='browser launch'):
            _sign_in(
                'client-1',
                authorization_endpoint='https://idp.example/authorize',
                token_endpoint=_PROVIDER_ENDPOINT,
                open_browser=rejected_browser,
            )
        assert callback_threads
        for thread in callback_threads:
            thread.join()
        assert not any(thread.is_alive() for thread in callback_threads)
        parts = urlsplit(redirect_uri)
        assert parts.hostname is not None
        assert parts.port is not None
        with pytest.raises(ConnectionRefusedError):
            socket.create_connection((parts.hostname, parts.port))

    @pytest.mark.parametrize(
        ('platform', 'closing', 'error', 'suppressed'),
        [
            ('win32', True, OSError(10038, 'not a socket'), True),
            ('win32', False, OSError(10038, 'not a socket'), False),
            ('linux', True, OSError(10038, 'not a socket'), False),
            ('win32', True, OSError(5, 'unrelated IO error'), False),
            ('win32', True, ConnectionResetError('peer disconnected'), True),
            ('win32', False, ConnectionResetError('peer disconnected'), False),
        ],
    )
    def test_callback_shutdown_preserves_unrelated_errors(
        self,
        monkeypatch: pytest.MonkeyPatch,
        platform: str,
        closing: bool,
        error: OSError,
        suppressed: bool,
    ) -> None:
        monkeypatch.setattr(
            userauth, 'sys', SimpleNamespace(platform=platform, exception=sys.exception)
        )
        reported = Mock()
        callback = userauth._CallbackServer()
        original_error = HTTPServer.handle_error

        def handle_error(
            server: HTTPServer,
            request: socket.socket | tuple[bytes, socket.socket],
            address: object,
        ) -> None:
            if server is callback:
                reported(request, address)
            else:
                original_error(server, request, address)

        monkeypatch.setattr(HTTPServer, 'handle_error', handle_error)
        try:
            callback._closing = closing
            with socket.socket() as request:
                try:
                    raise error
                except OSError:
                    callback.handle_error(request, ('127.0.0.1', 0))
            assert reported.call_count == (0 if suppressed else 1)
        finally:
            callback._close()

    @pytest.mark.usefixtures('no_requests')
    def test_code_exchange_disables_redirects(
        self,
        browser: _Browser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        response = requests.Response()
        response.status_code = 307
        session = requests.Session()
        post = Mock(return_value=response)
        monkeypatch.setattr(session, 'post', post)
        endpoint = 'https://idp.example/token'

        with pytest.raises(SignInError, match='HTTP 307'):
            _sign_in(
                'client-1',
                authorization_endpoint=browser.authorization_endpoint,
                token_endpoint=endpoint,
                open_browser=browser.scripted_browser,
                session=session,
            )

        assert post.call_args.kwargs['allow_redirects'] is False

    def test_full_pkce_flow(self, fake_provider: _FakeProvider) -> None:
        bundle = _sign_in(
            'client-1',
            authorization_endpoint=fake_provider.authorization_endpoint,
            token_endpoint=fake_provider.token_endpoint,
            open_browser=fake_provider.scripted_browser,
        )
        assert bundle.id_token == fake_provider.issued_id_token
        assert bundle.refresh_token == fake_provider.issued_refresh_token
        auth_query = fake_provider.authorization_query
        assert auth_query['code_challenge_method'] == ['S256']
        assert 'offline_access' in auth_query['scope'][0]
        assert 'access_type' not in auth_query
        verifier = fake_provider.token_form['code_verifier'][0]
        digest = hashlib.sha256(verifier.encode('ascii')).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
        assert auth_query['code_challenge'] == [expected]
        assert fake_provider.token_form['grant_type'] == ['authorization_code']
        assert fake_provider.token_form['client_id'] == ['client-1']
        assert fake_provider.token_form['redirect_uri'] == auth_query['redirect_uri']

    def test_google_endpoints_use_google_offline_parameters(
        self, fake_provider: _FakeProvider
    ) -> None:
        _sign_in(
            'client-1',
            authorization_endpoint=_GOOGLE_AUTHORIZATION_ENDPOINT,
            token_endpoint=fake_provider.token_endpoint,
            open_browser=fake_provider.scripted_browser,
        )
        auth_query = fake_provider.authorization_query
        assert auth_query['access_type'] == ['offline']
        assert auth_query['prompt'] == ['consent']
        assert 'offline_access' not in auth_query['scope'][0]

    def test_idle_connection_times_out_without_consuming_callback(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            userauth, '_REQUEST_TIMEOUT_SECONDS', _CALLBACK_REQUEST_TIMEOUT_SECONDS
        )
        original_read = socket.SocketIO.readinto
        timed_out: list[float | None] = []
        callback = userauth._CallbackServer()

        def timeout_idle_read(reader: socket.SocketIO, buffer: bytearray) -> int | None:
            if threading.current_thread() is callback._thread and not timed_out:
                request = callback._active_request
                timed_out.append(request.gettimeout() if request is not None else None)
                raise TimeoutError('idle callback read expired')
            return original_read(reader, buffer)

        monkeypatch.setattr(socket.SocketIO, 'readinto', timeout_idle_read)
        try:
            with socket.create_connection(callback._address) as idle:
                assert idle.recv(1) == b''
            assert timed_out == [_CALLBACK_REQUEST_TIMEOUT_SECONDS]
            assert not callback.received.is_set()
            monkeypatch.setattr(callback.RequestHandlerClass, 'timeout', STALL_TIMEOUT_SECONDS)
            host, port = callback._address
            response = requests.get(f'http://{host}:{port}/callback?code=ok')
            assert response.status_code == 200
            callback._thread.join()
            assert callback.received.is_set()
        finally:
            callback._close()

    def test_malformed_callback_target_gets_plain_text_400(self) -> None:
        callback = userauth._CallbackServer()
        try:
            with socket.create_connection(callback._address) as sock:
                sock.sendall(b'GET http://[ HTTP/1.1\r\nHost: x\r\n\r\n')
                with HTTPResponse(sock) as response:
                    response.begin()
                    assert response.status == 400
                    content_type = response.getheader('Content-Type')
                    assert content_type is not None
                    assert content_type.partition(';')[0].strip().lower() == 'text/plain'
            assert not callback.received.is_set()
        finally:
            callback._close()

    def test_missing_client_secret_rejection_names_the_setting(
        self, fake_provider: _FakeProvider
    ) -> None:
        fake_provider.token_status = 400
        fake_provider.token_body_override = json.dumps(
            {'error': 'invalid_request', 'error_description': 'client_secret is missing.'}
        ).encode()
        with pytest.raises(SignInError) as raised:
            _sign_in(
                'client-1',
                authorization_endpoint=fake_provider.authorization_endpoint,
                token_endpoint=fake_provider.token_endpoint,
                open_browser=fake_provider.scripted_browser,
            )
        origin = fake_provider.token_endpoint.removesuffix('/token')
        assert str(raised.value).startswith(
            f'code exchange rejected (HTTP 400) at {origin}: invalid_request'
        )
        assert 'SG_USER_TOKEN_CLIENT_SECRET' in str(raised.value)
        assert 'client_secret is missing' not in str(raised.value)

    @pytest.mark.parametrize(
        'body',
        [b'{}', b'{"id_token": ""}', b'{"id_token": 42}'],
        ids=['absent', 'empty', 'non-string'],
    )
    def test_missing_id_token_is_rejected(self, fake_provider: _FakeProvider, body: bytes) -> None:
        fake_provider.token_body_override = body
        with pytest.raises(SignInError, match='token endpoint returned no id_token'):
            _sign_in(
                'client-1',
                authorization_endpoint=fake_provider.authorization_endpoint,
                token_endpoint=fake_provider.token_endpoint,
                open_browser=fake_provider.scripted_browser,
            )

    def test_nonce_mismatch_is_rejected(self, fake_provider: _FakeProvider) -> None:
        fake_provider.wrong_nonce = True
        with pytest.raises(SignInError, match='nonce'):
            _sign_in(
                'client-1',
                authorization_endpoint=fake_provider.authorization_endpoint,
                token_endpoint=fake_provider.token_endpoint,
                open_browser=fake_provider.scripted_browser,
            )

    def test_partial_callback_timeout_does_not_print_traceback(
        self,
        capfd: pytest.CaptureFixture[str],
        callback_reads: '_CallbackReads',
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        callback = callback_reads.callback
        expired_wait = Mock(return_value=False)
        monkeypatch.setattr(callback.received, 'wait', expired_wait)
        with socket.create_connection(callback._address) as client:
            client.sendall(b'GET /callback?code=partial')
            callback_reads.next_read().set()
            callback_reads.next_read()
            callback_reads.observe_close(client)
            with pytest.raises(SignInError, match='timed out'):
                callback._wait(userauth._SIGN_IN_TIMEOUT_SECONDS)
            expired_wait.assert_called_once_with(userauth._SIGN_IN_TIMEOUT_SECONDS)
            callback_reads.assert_closed_before_join()
            assert capfd.readouterr().err == ''

    @pytest.mark.usefixtures('no_requests')
    @pytest.mark.parametrize('code', ['access_denied', 'unknown-private-value'])
    def test_provider_refusal_keeps_only_recognized_code(
        self, browser: _Browser, code: str
    ) -> None:
        browser.authorization_error = (code, 'private provider description')
        with pytest.raises(SignInError) as caught:
            _sign_in(
                'client-1',
                authorization_endpoint=browser.authorization_endpoint,
                token_endpoint=_PROVIDER_ENDPOINT,
                open_browser=browser.scripted_browser,
            )
        expected = 'authorization request rejected at https://idp.example'
        if code == 'access_denied':
            expected += ': access_denied: authorize the application to sign in'
        assert str(caught.value) == expected

    def test_queued_partial_callback_cannot_race_shutdown(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        callback = _StoppedCallback()
        callback._thread.join()
        request, client = socket.socketpair()

        original_accept = HTTPServer.get_request

        def accept_after_close(server: HTTPServer) -> tuple[socket.socket, object]:
            if server is not callback:
                return original_accept(server)
            # Closing wins the race between accept() and registering ownership.
            callback._begin_close()
            return request, ('127.0.0.1', 0)

        monkeypatch.setattr(HTTPServer, 'get_request', accept_after_close)
        try:
            with pytest.raises(OSError, match='callback server is closing'):
                callback.get_request()
            assert request.fileno() == -1
            assert callback._active_request is None
            assert client.recv(1) == b''
        finally:
            request.close()
            client.close()
            callback._close()

    @pytest.mark.usefixtures('no_requests')
    def test_state_mismatch_is_rejected(self, browser: _Browser) -> None:
        browser.tamper_state = True
        with pytest.raises(SignInError, match='state'):
            _sign_in(
                'client-1',
                authorization_endpoint=browser.authorization_endpoint,
                token_endpoint=_PROVIDER_ENDPOINT,
                open_browser=browser.scripted_browser,
            )

    def test_trickled_partial_callback_cannot_block_shutdown(
        self, callback_reads: '_CallbackReads'
    ) -> None:
        callback = callback_reads.callback
        with socket.create_connection(callback._address) as client:
            # Deliver each chunk only after the handler reaches the next read.
            # There is no gap whose duration determines whether shutdown works.
            client.sendall(b'GET /oauth/callback?code=partial')
            callback_reads.next_read().set()
            gate = callback_reads.next_read()
            client.sendall(b'x')
            gate.set()
            callback_reads.next_read()
            callback_reads.observe_close(client)
            callback._close()
            callback_reads.assert_closed_before_join()

    def test_unrelated_request_does_not_consume_callback_listener(self) -> None:
        callback = userauth._CallbackServer()
        try:
            host, port = callback._address
            wrong = requests.get(f'http://{host}:{port}/favicon.ico')
            assert wrong.status_code == 404
            valid = requests.get(
                f'http://{host}:{port}/callback?code=ok&state=expected',
            )
            assert valid.status_code == 200
            callback._thread.join()
            assert callback.received.is_set()
        finally:
            callback._close()

    def test_windows_close_disposes_socket_with_open_reader(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(userauth, 'sys', SimpleNamespace(platform='win32'))
        request, peer = socket.socketpair()
        reader = request.makefile('rb')
        descriptor = request.fileno()
        shutdown = socket.socket.shutdown
        native_close = socket.close
        disposed: list[int] = []
        both_closers_entered = threading.Barrier(2)

        def concurrent_shutdown(sock: socket.socket, how: int) -> None:
            if sock is request:
                both_closers_entered.wait()
            shutdown(sock, how)

        def observed_close(file_descriptor: int) -> None:
            if file_descriptor == descriptor:
                disposed.append(file_descriptor)
            native_close(file_descriptor)

        try:
            with monkeypatch.context() as disposal_patch:
                disposal_patch.setattr(socket, 'close', observed_close)
                with monkeypatch.context() as shutdown_patch:
                    shutdown_patch.setattr(socket.socket, 'shutdown', concurrent_shutdown)
                    with ThreadPoolExecutor(max_workers=2) as executor:
                        closers = [
                            executor.submit(userauth._CallbackServer._close_socket, request)
                            for _ in range(2)
                        ]
                        for closer in closers:
                            closer.result()
                assert request.fileno() == -1, (
                    'close deferred disposal until buffered reader close'
                )
                assert disposed == [descriptor]
                reader.close()
                userauth._CallbackServer._close_socket(request)
                assert disposed == [descriptor]
        finally:
            reader.close()
            request.close()
            peer.close()


class _StoppedCallback(userauth._CallbackServer):
    def _serve_until_callback(self) -> None:
        pass


@pytest.fixture(autouse=True)
def _callback_stall_timeouts(monkeypatch: pytest.MonkeyPatch) -> None:
    original_init = userauth._CallbackServer.__init__

    def initialize(
        callback: userauth._CallbackServer, *, join_timeout: float = STALL_TIMEOUT_SECONDS
    ) -> None:
        original_init(callback, join_timeout=join_timeout)

    monkeypatch.setattr(userauth._CallbackServer, '__init__', initialize)
    monkeypatch.setattr(userauth, '_REQUEST_TIMEOUT_SECONDS', STALL_TIMEOUT_SECONDS)
    monkeypatch.setattr(userauth, '_WAKEUP_TIMEOUT_SECONDS', STALL_TIMEOUT_SECONDS)


def _id_token(payload: dict[str, object]) -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
    return f'e30.{encoded}.x'


@pytest.fixture
def callback_reads(monkeypatch: pytest.MonkeyPatch) -> Iterator[_CallbackReads]:
    reads = _CallbackReads(monkeypatch)
    try:
        yield reads
    finally:
        reads.release()
        reads.callback._close()
        reads.callback._thread.join()
        assert not reads.errors


@pytest.fixture
def browser() -> _Browser:
    return _Browser()


@pytest.fixture
def fake_provider() -> Iterator[_FakeProvider]:
    provider = _FakeProvider()
    provider.thread.start()
    try:
        yield provider
    finally:
        provider.server.shutdown()
        provider.server.server_close()
        provider.thread.join()


@pytest.mark.parametrize(
    ('site', 'message'),
    [
        ('discovery', 'OIDC discovery for https://127.0.0.1:1 could not be sent: '),
        ('token', 'test at https://127.0.0.1:1 could not be sent: '),
    ],
)
def test_missing_ca_bundle_is_a_setup_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, site: str, message: str
) -> None:
    missing = tmp_path / 'missing-ca.pem'
    monkeypatch.setenv('REQUESTS_CA_BUNDLE', str(missing))
    monkeypatch.setattr(
        'urllib3.connection.HTTPSConnection.connect',
        Mock(side_effect=AssertionError('unexpected connection')),
    )
    send = (
        partial(userauth._discovery_document, 'https://127.0.0.1:1')
        if site == 'discovery'
        else partial(
            userauth._post_token_endpoint,
            requests.Session(),
            'https://127.0.0.1:1/token',
            {},
            operation='test',
        )
    )
    with pytest.raises(SignInError) as caught:
        send()
    assert caught.value.__suppress_context__
    assert str(caught.value).startswith(message)
    assert str(missing) in str(caught.value)


@pytest.mark.parametrize('mode', ['transport', 'mismatch', 'refusal'])
def test_discovery_diagnosis_uses_only_the_issuer_origin(
    monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    issuer = 'https://issuer.example/tenant?key=query-marker#fragment'
    monkeypatch.setenv('SG_USER_TOKEN_ISSUER', issuer)
    monkeypatch.setenv('SG_USER_TOKEN_CLIENT_ID', 'client')
    body = (
        {'issuer': 'provider-private-value'}
        if mode == 'mismatch'
        else {
            'error': 'invalid_request',
            'error_description': 'tenant refused query-marker ' + 'x' * 300,
        }
    )
    response = Mock(status_code=200 if mode == 'mismatch' else 400, json=Mock(return_value=body))
    monkeypatch.setattr(
        requests,
        'get',
        Mock(
            return_value=response,
            side_effect=requests.ConnectionError(issuer) if mode == 'transport' else None,
        ),
    )
    with pytest.raises(SignInError) as caught:
        identity_settings()
    message = str(caught.value)
    assert 'https://issuer.example' in message
    assert all(part not in message for part in ('private', 'query-marker', 'fragment'))
    assert 'query-marker' not in ''.join(traceback.format_exception(caught.value))
    if mode == 'transport':
        assert 'discovery' in message
    if mode == 'refusal':
        assert '400' in message
        assert 'invalid_request' in message
        assert 'tenant refused' not in message
        assert 'x' * 121 not in message


@pytest.mark.parametrize('code', ['invalid_client', 'opaque-provider-marker'])
def test_client_id_keeps_recognized_code_and_secret_hint(code: str) -> None:
    response = Mock(
        status_code=401,
        json=Mock(
            return_value={
                'error': code,
                'error_description': 'provider-marker client_secret is missing',
            }
        ),
    )
    with pytest.raises(SignInError) as caught:
        userauth._post_token_endpoint(
            Mock(post=Mock(return_value=response)),
            _PROVIDER_ENDPOINT,
            {'client_id': 'client'},
            operation='code exchange',
        )
    message = str(caught.value)
    assert 'HTTP 401' in message
    assert 'provider-marker' not in message
    if code == 'invalid_client':
        assert 'invalid_client' in message
        assert 'SG_USER_TOKEN_CLIENT_SECRET' in message


@pytest.mark.parametrize(
    ('code', 'hint'),
    [
        ('invalid_scope', 'scopes allowed'),
        ('server_error', 'check the identity provider'),
        ('temporarily_unavailable', 'try the identity provider again'),
        ('unauthorized_client', 'enable this grant'),
        ('unsupported_grant_type', 'grant types enabled'),
        ('unsupported_response_type', 'authorization code flow'),
    ],
)
def test_recognized_oauth_refusals_explain_repair(code: str, hint: str) -> None:
    response = Mock(
        status_code=400,
        json=Mock(return_value={'error': code, 'error_description': 'private-text'}),
    )
    with pytest.raises(SignInError) as caught:
        userauth._post_token_endpoint(
            Mock(post=Mock(return_value=response)), _PROVIDER_ENDPOINT, {}, operation='refresh'
        )
    assert code in str(caught.value)
    assert hint in str(caught.value)
    assert 'private-text' not in str(caught.value)
