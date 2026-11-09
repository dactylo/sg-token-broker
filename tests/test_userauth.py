import base64
import hashlib
import json
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import Path
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
    sign_in,
)

# Stored Google sign-ins live under this keyring issuer; changing it orphans them.
_GOOGLE_KEYRING_ISSUER = 'https://oauth2.googleapis.com/token'
_PROVIDER_ENDPOINT = 'https://idp.example/token'


class TestAccountFromIdToken:
    def test_falls_back_to_sub(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv('SG_USER_TOKEN_EMAIL_CLAIM', raising=False)
        assert account_from_id_token(_id_token({'sub': 'abc123'})) == 'abc123'

    def test_reads_the_configured_claim(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv('SG_USER_TOKEN_EMAIL_CLAIM', 'upn')
        token = _id_token({'upn': 'jane@corp.example', 'email': 'other@x'})
        assert account_from_id_token(token) == 'jane@corp.example'


class TestIdentitySettings:
    def test_discovered_settings_lead_with_the_issuer(
        self, monkeypatch: pytest.MonkeyPatch
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

    def test_unreachable_issuer_is_a_sign_in_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv('SG_USER_TOKEN_CLIENT_ID', 'client-1')
        monkeypatch.setenv('SG_USER_TOKEN_ISSUER', 'https://127.0.0.1:1')
        with pytest.raises(SignInError, match='discovery'):
            identity_settings()


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
        self, monkeypatch: _CallablePatcher, earlier_sign_in: bool
    ) -> None:
        now = [1_700_000_000]
        monkeypatch.setattr(userauth.time, 'time', lambda: now[0])
        stored: list[str | None] = ['rt-old']
        monkeypatch.setattr(userauth, 'load_refresh_token', lambda *_args: stored[0])
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
                sign_in,
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

        assert str(caught.value) == 'refresh rejected (HTTP 400): invalid_grant: Bad Request'


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
        session = requests.Session()
        post = Mock(return_value=response)
        monkeypatch.setattr(session, 'post', post)
        endpoint = 'https://idp.example/token'

        with pytest.raises(SignInError, match='HTTP 307'):
            _refresh_id_token(
                'client-1',
                'rt-1',
                token_endpoint=endpoint,
                session=session,
            )

        assert post.call_args.kwargs['allow_redirects'] is False

    def test_returns_new_id_token_and_rotation(self, fake_provider: _FakeProvider) -> None:
        fake_provider.refresh_response = {'id_token': 'idt-2', 'refresh_token': 'rt-2'}
        result = _refresh_id_token('client-1', 'rt-1', token_endpoint=fake_provider.token_endpoint)
        assert result == ('idt-2', 'rt-2')


class TestSignIn:
    def test_authorization_endpoint_query_is_preserved(self, fake_provider: _FakeProvider) -> None:
        sign_in(
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
        bundle = sign_in(
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
            sign_in(
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

        sign_in(
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
        def fail_response(_handler: BaseHTTPRequestHandler) -> None:
            raise BrokenPipeError

        monkeypatch.setattr(BaseHTTPRequestHandler, 'flush_headers', fail_response)
        callback = userauth._CallbackServer()
        try:
            host, port = callback._address
            with pytest.raises(requests.ConnectionError):
                requests.get(
                    f'http://{host}:{port}/callback?code=ok&state=expected',
                    timeout=1,
                )
            callback._thread.join(timeout=1)
            assert (
                callback.code,
                callback.state,
                callback.received.is_set(),
                callback._thread.is_alive(),
            ) == ('ok', 'expected', True, False)
        finally:
            callback._close()

    def test_close_is_bounded_when_the_wakeup_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        callback = userauth._CallbackServer(join_timeout=0.05)

        def refuse(*_args: object, **_kwargs: object) -> socket.socket:
            raise OSError('wakeup refused')

        monkeypatch.setattr(userauth.socket, 'create_connection', refuse)
        started = time.monotonic()
        with pytest.raises(SignInError, match='timed out'):
            callback._wait(0.05)
        assert time.monotonic() - started < 1.0

    @pytest.mark.parametrize(('secret', 'sent'), [(None, []), ('secret-1', ['secret-1'])])
    def test_code_exchange_sends_client_secret_only_when_configured(
        self, fake_provider: _FakeProvider, secret: str | None, sent: list[str]
    ) -> None:
        sign_in(
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
            sign_in(
                'client-1',
                authorization_endpoint='https://idp.example/authorize',
                token_endpoint=_PROVIDER_ENDPOINT,
                open_browser=rejected_browser,
                timeout=0.01,
            )
        assert callback_threads
        for thread in callback_threads:
            thread.join(0.25)
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
        monkeypatch.setattr(HTTPServer, 'handle_error', reported)
        callback = userauth._CallbackServer()
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
            sign_in(
                'client-1',
                authorization_endpoint=browser.authorization_endpoint,
                token_endpoint=endpoint,
                open_browser=browser.scripted_browser,
                session=session,
            )

        assert post.call_args.kwargs['allow_redirects'] is False

    def test_full_pkce_flow(self, fake_provider: _FakeProvider) -> None:
        bundle = sign_in(
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

    def test_google_endpoints_use_google_offline_parameters(
        self, fake_provider: _FakeProvider
    ) -> None:
        sign_in(
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
        monkeypatch.setattr(userauth, '_REQUEST_TIMEOUT_SECONDS', 0.05)
        callback = userauth._CallbackServer()
        idle = socket.create_connection(callback._address, timeout=1)
        try:
            host, port = callback._address
            response = requests.get(f'http://{host}:{port}/callback?code=ok', timeout=1)
            assert response.status_code == 200
            callback._wait(1)
        finally:
            idle.close()
            callback._close()

    def test_malformed_callback_target_gets_plain_text_400(self) -> None:
        callback = userauth._CallbackServer()
        try:
            with socket.create_connection(callback._address, timeout=2) as sock:
                sock.sendall(b'GET http://[ HTTP/1.1\r\nHost: x\r\n\r\n')
                raw = sock.recv(4096)
            assert raw.split(b' ', 2)[1] == b'400'
            assert b'Content-Type: text/plain' in raw
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
            sign_in(
                'client-1',
                authorization_endpoint=fake_provider.authorization_endpoint,
                token_endpoint=fake_provider.token_endpoint,
                open_browser=fake_provider.scripted_browser,
            )
        assert str(raised.value) == (
            'code exchange rejected (HTTP 400): invalid_request: client_secret is missing.; '
            "set SG_USER_TOKEN_CLIENT_SECRET to the OAuth client's secret"
        )

    @pytest.mark.parametrize(
        'body',
        [b'{}', b'{"id_token": ""}', b'{"id_token": 42}'],
        ids=['absent', 'empty', 'non-string'],
    )
    def test_missing_id_token_is_rejected(self, fake_provider: _FakeProvider, body: bytes) -> None:
        fake_provider.token_body_override = body
        with pytest.raises(SignInError, match='token endpoint returned no id_token'):
            sign_in(
                'client-1',
                authorization_endpoint=fake_provider.authorization_endpoint,
                token_endpoint=fake_provider.token_endpoint,
                open_browser=fake_provider.scripted_browser,
            )

    def test_nonce_mismatch_is_rejected(self, fake_provider: _FakeProvider) -> None:
        fake_provider.wrong_nonce = True
        with pytest.raises(SignInError, match='nonce'):
            sign_in(
                'client-1',
                authorization_endpoint=fake_provider.authorization_endpoint,
                token_endpoint=fake_provider.token_endpoint,
                open_browser=fake_provider.scripted_browser,
            )

    def test_partial_callback_timeout_does_not_print_traceback(
        self, capfd: pytest.CaptureFixture[str]
    ) -> None:
        callback = userauth._CallbackServer()
        client = socket.create_connection(callback._address, timeout=1)
        try:
            client.sendall(b'GET /callback?code=partial')
            _wait_for_callback_read(callback)
            with pytest.raises(SignInError, match='timed out'):
                callback._wait(0)
            assert not callback._thread.is_alive()
            assert capfd.readouterr().err == ''
        finally:
            client.close()
            callback._close()

    @pytest.mark.usefixtures('no_requests')
    def test_provider_error_is_reported(self, browser: _Browser) -> None:
        browser.authorization_error = ('access_denied', 'user cancelled')
        with pytest.raises(SignInError, match=r'access_denied.*user cancelled'):
            sign_in(
                'client-1',
                authorization_endpoint=browser.authorization_endpoint,
                token_endpoint=_PROVIDER_ENDPOINT,
                open_browser=browser.scripted_browser,
            )

    def test_queued_partial_callback_cannot_race_shutdown(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        entered_get_request = threading.Event()
        release_get_request = threading.Event()
        original_get_request = HTTPServer.get_request

        def delayed_get_request(server: HTTPServer) -> tuple[socket.socket, object]:
            entered_get_request.set()
            assert release_get_request.wait(timeout=1)
            return original_get_request(server)

        monkeypatch.setattr(HTTPServer, 'get_request', delayed_get_request)
        callback = userauth._CallbackServer()
        original_create_connection = socket.create_connection
        client = original_create_connection(callback._address, timeout=1)
        client.sendall(b'GET /oauth/callback?code=partial')
        assert entered_get_request.wait(timeout=1)
        wakeup_queued = threading.Event()

        def observed_create_connection(address: tuple[str, int], timeout: float) -> socket.socket:
            connection = original_create_connection(address, timeout)
            wakeup_queued.set()
            return connection

        monkeypatch.setattr(socket, 'create_connection', observed_create_connection)
        closed = threading.Event()

        def close_callback() -> None:
            callback._close()
            closed.set()

        closer = threading.Thread(target=close_callback, daemon=True)
        closer.start()
        assert wakeup_queued.wait(timeout=1)
        release_get_request.set()
        try:
            assert closed.wait(timeout=1)
        finally:
            client.close()
            release_get_request.set()
            closer.join(timeout=2)
        assert not closer.is_alive()
        assert not callback._thread.is_alive()

    @pytest.mark.usefixtures('no_requests')
    def test_state_mismatch_is_rejected(self, browser: _Browser) -> None:
        browser.tamper_state = True
        with pytest.raises(SignInError, match='state'):
            sign_in(
                'client-1',
                authorization_endpoint=browser.authorization_endpoint,
                token_endpoint=_PROVIDER_ENDPOINT,
                open_browser=browser.scripted_browser,
            )

    def test_trickled_partial_callback_cannot_block_shutdown(self) -> None:
        callback = userauth._CallbackServer()
        client = socket.create_connection(callback._address, timeout=1)
        client.sendall(b'GET /oauth/callback?code=partial')
        stop = threading.Event()
        trickled = threading.Event()

        def trickle_request() -> None:
            while not stop.wait(0.05):
                try:
                    client.sendall(b'x')
                except OSError:
                    return
                trickled.set()

        dripper = threading.Thread(target=trickle_request, daemon=True)
        dripper.start()
        closed = threading.Event()

        def close_callback() -> None:
            callback._close()
            closed.set()

        closer = threading.Thread(target=close_callback, daemon=True)
        try:
            assert trickled.wait(timeout=1)
            _wait_for_callback_read(callback)
            closer.start()
            assert closed.wait(timeout=1)
            assert not callback._thread.is_alive()
        finally:
            stop.set()
            client.close()
            dripper.join(timeout=2)
            if closer.ident is not None:
                closer.join(timeout=2)
            callback._close()
        assert not dripper.is_alive()
        assert not closer.is_alive()
        assert not callback._thread.is_alive()

    def test_unrelated_request_does_not_consume_callback_listener(self) -> None:
        callback = userauth._CallbackServer()
        try:
            host, port = callback._address
            wrong = requests.get(f'http://{host}:{port}/favicon.ico', timeout=1)
            assert wrong.status_code == 404
            valid = requests.get(
                f'http://{host}:{port}/callback?code=ok&state=expected',
                timeout=1,
            )
            assert valid.status_code == 200
            callback._wait(1)
        finally:
            callback._close()

    def test_windows_close_disposes_socket_with_open_reader(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(userauth, 'sys', SimpleNamespace(platform='win32'))
        request, peer = socket.socketpair()
        reader = request.makefile('rb')
        descriptor = request.fileno()
        shutdown = request.shutdown
        native_close = socket.close
        disposed: list[int] = []
        both_closers_entered = threading.Barrier(2)

        def concurrent_shutdown(sock: socket.socket, how: int) -> None:
            assert sock is request
            both_closers_entered.wait(timeout=5)
            shutdown(how)

        def observed_close(file_descriptor: int) -> None:
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
                            closer.result(timeout=5)
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


def _id_token(payload: dict[str, object]) -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
    return f'e30.{encoded}.x'


def _wait_for_callback_read(callback: userauth._CallbackServer) -> None:
    # Acceptance alone does not prove the handler reached its buffered reader.
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        frame = sys._current_frames().get(callback._thread.ident or -1)
        while frame is not None:
            if frame.f_code is socket.SocketIO.readinto.__code__:
                reader = frame.f_locals.get('self')
                request = callback._active_request
                assert isinstance(reader, socket.SocketIO)
                assert request is not None
                assert reader.fileno() == request.fileno()
                return
            frame = frame.f_back
        time.sleep(0.001)
    pytest.fail('callback did not reach its buffered socket read')


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
        ('token', 'token endpoint request could not be sent: '),
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
    assert isinstance(caught.value.__cause__, OSError)
    assert not isinstance(caught.value.__cause__, requests.RequestException)
    assert str(caught.value) == message + str(caught.value.__cause__)
    assert str(missing) in str(caught.value)
