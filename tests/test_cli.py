import argparse
import base64
import datetime
import importlib.metadata
import io
import json
import logging
import os
import ssl
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import NoReturn, TextIO, cast
from unittest.mock import Mock

import pytest
import requests

import sg_token_broker._cli as cli_module
from sg_token_broker import _downstream
from sg_token_broker._cli import main
from sg_token_broker._client import BrokerClientError
from sg_token_broker._googleverify import VerifierUnavailableError
from sg_token_broker._oidcverify import OidcUnavailableError
from sg_token_broker._secrets import verify_secret
from sg_token_broker._sg import MintedToken, SGError
from sg_token_broker._userauth import _GOOGLE_TOKEN_ENDPOINT, SignInError, TokenBundle
from sg_token_broker._userclient import UserToken, UserTokenClientError
from tests.cli_helpers import invoke_cli
from tests.conftest import BROKER_CREDENTIAL, _FakeSG

# Precomputed valid hash of 'x' for configuration setup.
_CONFIG_HASH = (
    'scrypt$16384$8$1$40vcdl7AgTzLmOGl+anfBQ==$'
    'wL+YRQJWbt9/zf6Wpcl3nDff4/OkYaw7LIU04aIrjpqBs/boSojdqPdZXy8s3oZxk/CJN5/VcQy138851oY/sw=='
)
_ID_TOKEN = (
    'e30.'
    + base64.urlsafe_b64encode(json.dumps({'email': 'jane@s.example', 'nonce': 'n'}).encode())
    .rstrip(b'=')
    .decode()
    + '.x'
)
VALID_COMMAND_ARGUMENTS = ['hash-secret']


class TestCheckConfig:
    def test_control_characters_in_errors_are_escaped(self, tmp_path: Path) -> None:
        cfg = tmp_path / 'bad\x1b[31m.yml'
        status, _, stderr = invoke_cli(['check-config', '--config', str(cfg)])
        assert status == 2
        assert '\x1b' not in stderr
        assert 'bad\\x1b[31m.yml' in stderr

    def test_every_unresolvable_script_key_is_reported_on_one_line(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv('SGTB_ABSENT_A', raising=False)
        monkeypatch.delenv('SGTB_ABSENT_B', raising=False)
        cfg = _write_config(tmp_path, 'SGTB_ABSENT_A', 'SGTB_ABSENT_B')
        assert invoke_cli(['check-config', '--config', str(cfg)]) == (
            2,
            '',
            (
                "error: scope 'scope_0': environment variable SGTB_ABSENT_A is not set or empty; "
                "scope 'scope_1': environment variable SGTB_ABSENT_B is not set or empty\n"
            ),
        )

    def test_invalid_config(self, tmp_path: Path) -> None:
        cfg = tmp_path / 'broker.yml'
        cfg.write_text('site_url: 42')
        assert invoke_cli(['check-config', '--config', str(cfg)]) == (
            2,
            '',
            'error: site_url must be an https URL string\n',
        )

    def test_undecodable_script_key_file_fails(
        self,
        tmp_path: Path,
    ) -> None:
        keyfile = tmp_path / 'key'
        keyfile.write_bytes(b'\xff')
        cfg = tmp_path / 'broker.yml'
        cfg.write_text(f"""
site_url: https://studio.shotgunstudio.com
scopes:
  read_all:
    script_name: s
    script_key_file: {json.dumps(str(keyfile))}
clients:
  farm:
    secret_hash: "{_CONFIG_HASH}"
    scopes: [read_all]
""")
        assert invoke_cli(['check-config', '--config', str(cfg)]) == (
            2,
            '',
            (
                f"error: scope 'read_all': cannot read script key file {keyfile}: "
                "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte\n"
            ),
        )

    def test_unreadable_config_is_a_configuration_error(self, tmp_path: Path) -> None:
        cfg = tmp_path / 'missing.yml'
        status, stdout, stderr = invoke_cli(['check-config', '--config', str(cfg)])
        assert (status, stdout) == (2, '')
        assert stderr.startswith(f'error: cannot read config file {cfg}: ')
        assert stderr.count('\n') == 1

    def test_unresolvable_script_key_fails(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv('SGTB_ABSENT_KEY', raising=False)
        cfg = _write_config(tmp_path, 'SGTB_ABSENT_KEY', scope_name='read_all')
        assert invoke_cli(['check-config', '--config', str(cfg)]) == (
            2,
            '',
            "error: scope 'read_all': environment variable SGTB_ABSENT_KEY is not set or empty\n",
        )

    def test_valid_config(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv('SGTB_KEY_READ_ALL', 'k')
        cfg = _write_config(tmp_path, 'SGTB_KEY_READ_ALL', scope_name='read_all')
        assert invoke_cli(['check-config', '--config', str(cfg)]) == (
            0,
            'ok: 1 scope(s), 1 client(s)\n',
            '',
        )

    def test_yaml_syntax_error_is_one_line_with_its_position(self, tmp_path: Path) -> None:
        cfg = tmp_path / 'broker.yml'
        cfg.write_text('site_url: https://sg.example\nscopes: a: b\n', encoding='utf-8')
        assert invoke_cli(['check-config', '--config', str(cfg)]) == (
            2,
            '',
            (
                f'error: invalid YAML in {cfg} at line 2, column 10: '
                'mapping values are not allowed here\n'
            ),
        )


class TestGetToken:
    def test_failure_exits_nonzero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv('SG_TOKEN_BROKER_URL', 'http://127.0.0.1:1')
        monkeypatch.setenv('SG_TOKEN_BROKER_CLIENT_ID', 'farm')
        monkeypatch.setenv('SG_TOKEN_BROKER_CLIENT_SECRET', 'x')
        status, stdout, stderr = invoke_cli(
            ['get-token', '--scope', 'read_all', '--timeout', '0.2', '--retries', '0']
        )
        assert (status, stdout) == (1, '')
        assert stderr.startswith('error: cannot reach broker at http://127.0.0.1:1: ')
        assert stderr.count('\n') == 1

    @pytest.mark.parametrize('timeout', ['0', '-1', 'nan', 'inf', '-inf'])
    def test_invalid_timeout_is_usage_error(
        self, timeout: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(['get-token', '--scope', 'read_all', f'--timeout={timeout}'])
        assert exc_info.value.code == 2
        assert 'finite floating-point value greater than zero' in capsys.readouterr().err

    def test_missing_broker_settings_are_a_setup_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for name in (
            'SG_TOKEN_BROKER_URL',
            'SG_TOKEN_BROKER_CLIENT_ID',
            'SG_TOKEN_BROKER_CLIENT_SECRET',
        ):
            monkeypatch.delenv(name, raising=False)
        assert invoke_cli(['get-token', '--scope', 'read_all']) == (
            2,
            '',
            (
                'error: broker settings missing; set SG_TOKEN_BROKER_URL, '
                'SG_TOKEN_BROKER_CLIENT_ID, and SG_TOKEN_BROKER_CLIENT_SECRET or pass them '
                'explicitly\n'
            ),
        )

    def test_negative_retries_are_usage_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(['get-token', '--scope', 'read_all', '--retries', '-1'])
        assert exc_info.value.code == 2
        assert 'must be >= 0' in capsys.readouterr().err

    def test_prints_token_json(
        self,
        broker_url: str,
        fake_sg: _FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv('SG_TOKEN_BROKER_URL', broker_url)
        monkeypatch.setenv('SG_TOKEN_BROKER_CLIENT_ID', 'farm')
        monkeypatch.setenv('SG_TOKEN_BROKER_CLIENT_SECRET', BROKER_CREDENTIAL)
        assert main(['get-token', '--scope', 'read_all']) == 0
        body = json.loads(capsys.readouterr().out)
        assert body['token'] == fake_sg._canned_session

    def test_refused_request_is_a_runtime_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cli_module, 'BrokerClient', _RefusingBrokerClient)
        assert invoke_cli(['get-token', '--scope', 'read_all']) == (
            1,
            '',
            'error: broker refused (HTTP 401): invalid client credentials\n',
        )


@pytest.mark.usefixtures('isolate_identity_environment')
class TestGetUserToken:
    def test_get_user_token_passes_force_refresh(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fetched: list[tuple[str, bool]] = []

        class FakeClient:
            def __init__(self, *args: object, **kwargs: object) -> None:
                pass

            def fetch_token(self, token_type: str, *, force_refresh: bool = False) -> UserToken:
                fetched.append((token_type, force_refresh))
                return _fake_user_token(token_type)

        monkeypatch.setattr(cli_module, 'UserTokenClient', FakeClient)
        assert main(['get-user-token', '--token-type', 'session', '--force-refresh']) == 0
        assert fetched == [('session', True)]

    def test_get_user_token_prints_token_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        fetched: list[tuple[str, bool]] = []

        class FakeClient:
            def __init__(self, *args: object, **kwargs: object) -> None:
                pass

            def fetch_token(self, token_type: str, *, force_refresh: bool = False) -> UserToken:
                fetched.append((token_type, force_refresh))
                return _fake_user_token(token_type)

        monkeypatch.setattr(cli_module, 'UserTokenClient', FakeClient)
        assert main(['get-user-token', '--token-type', 'session']) == 0
        assert fetched == [('session', False)]
        body = json.loads(capsys.readouterr().out)
        assert body['token_type'] == 'session'  # noqa: S105 - token type, not credential
        assert body['expires_at'] is None

    def test_missing_client_id_is_a_setup_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv('SG_USER_TOKEN_URL', 'https://user-tokens.example.invalid')
        assert invoke_cli(['get-user-token']) == (
            2,
            '',
            'error: SG_USER_TOKEN_CLIENT_ID is not set\n',
        )

    def test_missing_service_url_is_a_setup_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv('SG_USER_TOKEN_URL', raising=False)
        assert invoke_cli(['get-user-token']) == (
            2,
            '',
            'error: service URL missing; set SG_USER_TOKEN_URL or pass it explicitly\n',
        )

    def test_refused_request_is_a_runtime_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class RefusingClient:
            def __init__(self, *_args: object, **_kwargs: object) -> None:
                pass

            def fetch_token(self, token_type: str, *, force_refresh: bool = False) -> NoReturn:
                del token_type, force_refresh
                raise UserTokenClientError('service refused (HTTP 403)')

        monkeypatch.setattr(cli_module, 'UserTokenClient', RefusingClient)
        assert invoke_cli(['get-user-token']) == (
            1,
            '',
            'error: service refused (HTTP 403)\n',
        )

    def test_unreachable_identity_provider_is_a_runtime_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv('SG_USER_TOKEN_URL', 'https://user-tokens.example.invalid')
        monkeypatch.setenv('SG_USER_TOKEN_CLIENT_ID', 'client-1')
        monkeypatch.setenv('SG_USER_TOKEN_ISSUER', 'https://idp.example.com')
        monkeypatch.setattr('sg_token_broker._userauth.requests.get', _offline_discovery)
        assert invoke_cli(['get-user-token']) == (
            1,
            '',
            'error: OIDC discovery for https://idp.example.com failed: ConnectionError\n',
        )


class TestHashSecret:
    @pytest.mark.parametrize('secret', ['', 'café', 'has space'])
    def test_hash_secret_rejects_bad_grammar(self, secret: str) -> None:
        assert invoke_cli(['hash-secret', '--secret', secret]) == (
            2,
            '',
            'error: secret must be non-empty printable ASCII with no spaces\n',
        )

    def test_hashes_provided_secret(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(['hash-secret', '--secret', BROKER_CREDENTIAL]) == 0
        lines = dict(line.split(': ', 1) for line in capsys.readouterr().out.strip().splitlines())
        assert lines['secret'] == BROKER_CREDENTIAL
        assert verify_secret(BROKER_CREDENTIAL, lines['hash'])

    def test_outputs_secret_and_hash(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(['hash-secret']) == 0
        out = capsys.readouterr().out
        lines = dict(line.split(': ', 1) for line in out.strip().splitlines())
        assert verify_secret(lines['secret'], lines['hash'])


@pytest.mark.usefixtures('isolate_identity_environment')
class TestLogin:
    def test_browser_sign_in_failure_is_a_runtime_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv('SG_USER_TOKEN_CLIENT_ID', 'client-1')

        def time_out(_client_id: str, **_kwargs: object) -> NoReturn:
            raise SignInError('timed out waiting for the browser sign-in')

        monkeypatch.setattr(cli_module, 'sign_in', time_out)
        assert invoke_cli(['login']) == (
            1,
            '',
            'error: timed out waiting for the browser sign-in\n',
        )

    def test_insecure_issuer_is_a_setup_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv('SG_USER_TOKEN_CLIENT_ID', 'client-1')
        monkeypatch.setenv('SG_USER_TOKEN_ISSUER', 'http://idp.example.com')
        assert invoke_cli(['login']) == (
            2,
            '',
            (
                'error: SG_USER_TOKEN_ISSUER must be an https:// URL (plain http is allowed only '
                "on loopback hosts): 'http://idp.example.com'\n"
            ),
        )

    def test_login_no_store_skips_storage(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv('SG_USER_TOKEN_CLIENT_ID', 'client-1')
        monkeypatch.setattr(
            cli_module,
            'sign_in',
            _fake_sign_in,
        )
        called: list[object] = []

        def store(*args: object) -> bool:
            called.append(args)
            return True

        monkeypatch.setattr(
            cli_module,
            'store_refresh_token',
            store,
        )
        assert main(['login', '--no-store']) == 0
        assert called == []

    def test_login_stores_refresh_token_and_account_pointer(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv('SG_USER_TOKEN_CLIENT_ID', 'client-1')
        monkeypatch.delenv('SG_USER_TOKEN_ISSUER', raising=False)
        monkeypatch.setattr(
            cli_module,
            'sign_in',
            _fake_sign_in,
        )
        stored: list[tuple[str, str, str, str]] = []

        def store(issuer: str, client_id: str, account: str, value: str) -> bool:
            stored.append((issuer, client_id, account, value))
            return True

        monkeypatch.setattr(
            cli_module,
            'store_refresh_token',
            store,
        )
        pointed: list[tuple[str, str, str]] = []

        def point(issuer: str, client_id: str, account: str) -> bool:
            pointed.append((issuer, client_id, account))
            return True

        monkeypatch.setattr(
            cli_module,
            'store_account',
            point,
        )
        assert main(['login']) == 0
        assert stored == [(_GOOGLE_TOKEN_ENDPOINT, 'client-1', 'jane@s.example', 'rt-1')]
        assert pointed == [(_GOOGLE_TOKEN_ENDPOINT, 'client-1', 'jane@s.example')]
        assert 'signed in as jane@s.example' in capsys.readouterr().out

    def test_login_warns_when_the_pointer_cannot_be_saved(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv('SG_USER_TOKEN_CLIENT_ID', 'client-1')
        monkeypatch.delenv('SG_USER_TOKEN_ISSUER', raising=False)
        monkeypatch.setattr(
            cli_module,
            'sign_in',
            _fake_sign_in,
        )
        monkeypatch.setattr(cli_module, 'store_refresh_token', _store_true)
        monkeypatch.setattr(cli_module, 'store_account', _store_false)
        assert main(['login']) == 0
        captured = capsys.readouterr()
        assert 'signed in as jane@s.example' in captured.out
        assert 'SG_USER_TOKEN_ACCOUNT=jane@s.example' in captured.err

    def test_missing_client_id_is_a_setup_error(self) -> None:
        assert invoke_cli(['login']) == (2, '', 'error: SG_USER_TOKEN_CLIENT_ID is not set\n')

    def test_unreachable_identity_provider_is_a_runtime_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv('SG_USER_TOKEN_CLIENT_ID', 'client-1')
        monkeypatch.setenv('SG_USER_TOKEN_ISSUER', 'https://idp.example.com')
        monkeypatch.setattr('sg_token_broker._userauth.requests.get', _offline_discovery)
        assert invoke_cli(['login']) == (
            1,
            '',
            'error: OIDC discovery for https://idp.example.com failed: ConnectionError\n',
        )


@pytest.mark.usefixtures('isolate_identity_environment')
class TestLogout:
    def test_logout_deletes_credential_and_pointer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv('SG_USER_TOKEN_CLIENT_ID', 'client-1')
        monkeypatch.setenv('SG_USER_TOKEN_ACCOUNT', 'jane@s.example')
        monkeypatch.setattr(cli_module, 'load_account', _load_jane)
        dropped: list[object] = []
        pointer_dropped: list[object] = []

        def drop_refresh(*args: object) -> bool:
            dropped.append(args)
            return True

        def drop_pointer(*args: object) -> bool:
            pointer_dropped.append(args)
            return True

        monkeypatch.setattr(cli_module, 'delete_refresh_token', drop_refresh)
        monkeypatch.setattr(
            cli_module,
            'delete_account',
            drop_pointer,
        )
        assert main(['logout']) == 0
        assert dropped == [(_GOOGLE_TOKEN_ENDPOINT, 'client-1', 'jane@s.example')]
        assert pointer_dropped == [(_GOOGLE_TOKEN_ENDPOINT, 'client-1')]

    def test_logout_failure_keeps_pointer_and_reports_error(
        self,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv('SG_USER_TOKEN_CLIENT_ID', 'client-1')
        monkeypatch.setenv('SG_USER_TOKEN_ACCOUNT', 'jane@s.example')
        monkeypatch.setattr(cli_module, 'load_account', _load_jane)
        pointer_deletes: list[object] = []

        def fail_refresh(*_args: object) -> bool:
            return False

        def drop_pointer(*args: object) -> bool:
            pointer_deletes.append(args)
            return True

        monkeypatch.setattr(cli_module, 'delete_refresh_token', fail_refresh)
        monkeypatch.setattr(
            cli_module,
            'delete_account',
            drop_pointer,
        )

        assert main(['logout']) == 1
        captured = capsys.readouterr()
        assert captured.err == 'error: could not remove stored credential for jane@s.example\n'
        assert 'signed out' not in captured.out
        assert pointer_deletes == []

    def test_logout_of_an_overridden_account_keeps_the_pointer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv('SG_USER_TOKEN_CLIENT_ID', 'client-1')
        monkeypatch.setenv('SG_USER_TOKEN_ACCOUNT', 'bob@s.example')
        monkeypatch.setattr(cli_module, 'load_account', _load_jane)
        dropped: list[object] = []
        pointer_dropped: list[object] = []

        def drop_refresh(*args: object) -> bool:
            dropped.append(args)
            return True

        def drop_pointer(*args: object) -> bool:
            pointer_dropped.append(args)
            return True

        monkeypatch.setattr(cli_module, 'delete_refresh_token', drop_refresh)
        monkeypatch.setattr(
            cli_module,
            'delete_account',
            drop_pointer,
        )
        assert main(['logout']) == 0
        assert dropped == [(_GOOGLE_TOKEN_ENDPOINT, 'client-1', 'bob@s.example')]
        assert pointer_dropped == []

    def test_logout_pointer_failure_reports_partial_error(
        self,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv('SG_USER_TOKEN_CLIENT_ID', 'client-1')
        monkeypatch.setenv('SG_USER_TOKEN_ACCOUNT', 'jane@s.example')
        monkeypatch.setattr(cli_module, 'load_account', _load_jane)

        def fail_pointer(*_args: object) -> bool:
            return False

        def drop_refresh(*_args: object) -> bool:
            return True

        monkeypatch.setattr(cli_module, 'delete_refresh_token', drop_refresh)
        monkeypatch.setattr(cli_module, 'delete_account', fail_pointer)

        assert main(['logout']) == 1
        captured = capsys.readouterr()
        assert captured.err == 'error: credential removed, but account pointer remains\n'
        assert 'signed out' not in captured.out

    def test_logout_resolves_account_from_the_stored_pointer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv('SG_USER_TOKEN_CLIENT_ID', 'client-1')
        monkeypatch.delenv('SG_USER_TOKEN_ISSUER', raising=False)
        monkeypatch.delenv('SG_USER_TOKEN_ACCOUNT', raising=False)
        monkeypatch.setattr(cli_module, 'load_account', _load_jane)
        deleted: list[object] = []

        def delete(*args: object) -> bool:
            deleted.append(args)
            return True

        monkeypatch.setattr(cli_module, 'delete_refresh_token', delete)
        monkeypatch.setattr(cli_module, 'delete_account', delete)
        assert main(['logout']) == 0
        assert deleted[0] == (_GOOGLE_TOKEN_ENDPOINT, 'client-1', 'jane@s.example')

    def test_missing_account_is_a_negative_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv('SG_USER_TOKEN_CLIENT_ID', 'client-1')
        monkeypatch.setattr(cli_module, 'load_account', _load_nothing)
        assert invoke_cli(['logout']) == (1, '', 'error: no signed-in account found\n')

    def test_missing_client_id_is_a_setup_error(self) -> None:
        assert invoke_cli(['logout']) == (2, '', 'error: SG_USER_TOKEN_CLIENT_ID is not set\n')


class TestServe:
    def test_invalid_config_stops_the_broker(self, tmp_path: Path) -> None:
        cfg = tmp_path / 'broker.yml'
        cfg.write_text('site_url: 42')
        assert invoke_cli(['serve-app-tokens', '--config', str(cfg)]) == (
            2,
            '',
            'error: site_url must be an https URL string\n',
        )

    def test_rejected_tls_material_is_a_configuration_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv('SGTB_KEY_READ_ALL', 'k')

        def reject(*_args: object, **_kwargs: object) -> NoReturn:
            raise ssl.SSLError(1, 'PEM lib')

        monkeypatch.setattr(cli_module, 'create_server', reject)
        cfg = _write_config(tmp_path, 'SGTB_KEY_READ_ALL')
        assert invoke_cli(['serve-app-tokens', '--config', str(cfg)]) == (
            2,
            '',
            'error: cannot load the TLS certificate and key: PEM lib\n',
        )

    def test_serve_app_tokens_reports_bind_failure(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv('SGTB_KEY_READ_ALL', 'k')
        cfg = _write_config(tmp_path, 'SGTB_KEY_READ_ALL', scope_name='read_all')

        def fail(*_args: object, **_kwargs: object) -> object:
            raise OSError(98, 'Address already in use')

        monkeypatch.setattr('sg_token_broker._cli.create_server', fail)
        assert invoke_cli(['serve-app-tokens', '--config', str(cfg)]) == (
            1,
            '',
            'error: cannot start the broker on port 8743: Address already in use\n',
        )

    def test_serve_app_tokens_requires_config(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit):
            main(['serve-app-tokens'])
        assert '--config' in capsys.readouterr().err

    @pytest.mark.parametrize(
        'case',
        [
            ('::1', ('::1', 8743, 0, 0), 'http://[::1]:8743'),
            ('127.0.0.1', ('127.0.0.1', 8743), 'http://127.0.0.1:8743'),
            ('localhost', ('127.0.0.1', 8743), 'http://localhost:8743'),
        ],
    )
    def test_serve_app_tokens_startup_url(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
        case: tuple[str, tuple[str, int] | tuple[str, int, int, int], str],
    ) -> None:
        host, address, expected_url = case
        monkeypatch.setenv('SGTB_KEY_READ_ALL', 'k')
        cfg = _write_config(tmp_path, 'SGTB_KEY_READ_ALL', scope_name='read_all', bind=host)
        server = Mock(server_address=address)
        server.serve_forever.side_effect = KeyboardInterrupt
        create_server = Mock(return_value=server)
        monkeypatch.setattr(cli_module, 'create_server', create_server)

        assert main(['serve-app-tokens', '--config', str(cfg)]) == 0
        assert f'serving on {expected_url}\n' in capsys.readouterr().err
        assert create_server.call_args.args[0].server.bind == host
        server.serve_forever.assert_called_once_with()
        server.server_close.assert_called_once_with()

    def test_unresolvable_script_key_fails_fast(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv('SGTB_ABSENT_KEY', raising=False)
        cfg = _write_config(tmp_path, 'SGTB_ABSENT_KEY', scope_name='read_all')
        assert invoke_cli(['serve-app-tokens', '--config', str(cfg)]) == (
            2,
            '',
            "error: scope 'read_all': environment variable SGTB_ABSENT_KEY is not set or empty\n",
        )


class TestServeUserTokens:
    @pytest.fixture(autouse=True)
    def _clear_service_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for name in [n for n in os.environ if n.startswith('SGUT_')]:
            monkeypatch.delenv(name)
        monkeypatch.delenv('PORT', raising=False)

    def test_interrupt_while_serving_stops_quietly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_user_service_environment(monkeypatch)
        monkeypatch.setattr(cli_module, 'google_auth_verifier', _load_accepting_verifier)
        server = Mock(server_address=('', 8080))
        server.serve_forever.side_effect = KeyboardInterrupt
        monkeypatch.setattr(cli_module, 'create_user_token_server', Mock(return_value=server))

        assert invoke_cli(['serve-user-tokens']) == (
            0,
            '',
            'serving user tokens on port 8080\n',
        )
        server.server_close.assert_called_once_with()

    def test_log_lines_after_stdout_closes_are_dropped_quietly(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _set_user_service_environment(monkeypatch)
        monkeypatch.setattr(cli_module, 'google_auth_verifier', _load_accepting_verifier)
        server = Mock(server_address=('', 8080))

        def serve_one_logged_request() -> None:
            logging.getLogger('sg_token_broker.audit').info('{"event": "issue"}')
            raise KeyboardInterrupt

        server.serve_forever.side_effect = serve_one_logged_request
        monkeypatch.setattr(cli_module, 'create_user_token_server', Mock(return_value=server))
        monkeypatch.setattr(_downstream, '_silence_descriptor', _pretend_silenced)
        monkeypatch.setattr(sys, 'stdout', _ClosedPipe())
        saved_handlers = logging.root.handlers[:]
        saved_level = logging.root.level
        logging.root.handlers.clear()
        try:
            status = main(['serve-user-tokens'])
        finally:
            logging.root.handlers[:] = saved_handlers
            logging.root.setLevel(saved_level)

        assert status == 0
        assert capsys.readouterr().err == 'serving user tokens on port 8080\n'

    def test_missing_env_config_fails_fast(self) -> None:
        assert invoke_cli(['serve-user-tokens']) == (
            2,
            '',
            'error: SGUT_AUDIENCES is not set or empty\n',
        )

    def test_missing_google_auth_fails_fast(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_user_service_environment(monkeypatch)

        def unavailable() -> NoReturn:
            raise VerifierUnavailableError('google-auth is not installed')

        monkeypatch.setattr('sg_token_broker._cli.google_auth_verifier', unavailable)
        assert invoke_cli(['serve-user-tokens']) == (
            2,
            '',
            'error: google-auth is not installed\n',
        )

    def test_missing_oidc_extra_is_a_setup_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_user_service_environment(monkeypatch, oidc=True)

        def unavailable(_issuer: str, _algorithms: object) -> NoReturn:
            raise OidcUnavailableError('PyJWT is not installed; install the [oidc] extra')

        monkeypatch.setattr(cli_module, 'oidc_verifier', unavailable)
        assert invoke_cli(['serve-user-tokens']) == (
            2,
            '',
            'error: PyJWT is not installed; install the [oidc] extra\n',
        )

    def test_oidc_provider_startup_error_fails_fast(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_user_service_environment(monkeypatch, oidc=True)

        def failing_verifier(issuer: str, algorithms: object) -> object:
            del algorithms
            raise ValueError(f'OIDC discovery for {issuer} failed')

        monkeypatch.setattr('sg_token_broker._cli.oidc_verifier', failing_verifier)
        assert invoke_cli(['serve-user-tokens']) == (
            1,
            '',
            (
                'error: cannot verify identity tokens: '
                'OIDC discovery for https://idp.example.com failed\n'
            ),
        )

    def test_serve_user_tokens_reports_bind_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_user_service_environment(monkeypatch)

        def verifier(_token: str) -> dict[str, object]:
            return {}

        def load_verifier() -> object:
            return verifier

        def fail(*_args: object, **_kwargs: object) -> object:
            raise OSError(98, 'Address already in use')

        monkeypatch.setattr('sg_token_broker._cli.google_auth_verifier', load_verifier)
        monkeypatch.setattr('sg_token_broker._cli.create_user_token_server', fail)
        assert invoke_cli(['serve-user-tokens']) == (
            1,
            '',
            'error: cannot start the user-token service on port 8080: Address already in use\n',
        )

    def test_unreachable_oidc_provider_is_a_runtime_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_user_service_environment(monkeypatch, oidc=True)

        def offline(_issuer: str, _algorithms: object) -> NoReturn:
            raise requests.ConnectionError('provider offline')

        monkeypatch.setattr(cli_module, 'oidc_verifier', offline)
        assert invoke_cli(['serve-user-tokens']) == (
            1,
            '',
            'error: cannot verify identity tokens: provider offline\n',
        )


class TestVerifyRevocation:
    @pytest.mark.parametrize(
        ('failure', 'diagnostic'),
        [
            ('mint', 'credentials rejected\x1b[31m'),
            ('tls', 'SSLError: certificate verify failed'),
            ('fresh', 'freshly minted session token did not validate'),
        ],
    )
    def test_early_setup_failure_is_one_safe_stderr_line(
        self, monkeypatch: pytest.MonkeyPatch, failure: str, diagnostic: str
    ) -> None:
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')

        def mint(*_args: object) -> MintedToken:
            if failure == 'fresh':
                return MintedToken('fresh-session', None)
            raise SGError(f'SG request failed: {diagnostic}')

        def reject_fresh(*_args: object) -> bool:
            return False

        monkeypatch.setattr(cli_module.SGMinter, 'mint_session_token', mint)
        monkeypatch.setattr(cli_module.SGMinter, 'check_session_token', reject_fresh)
        status, stdout, stderr = invoke_cli(
            [
                'verify-revocation',
                '--site-url',
                'https://sg.example.invalid',
                '--script-name',
                's',
                '--script-key-env',
                'SGTB_VERIFY_KEY',
            ]
        )
        assert status == 2
        assert stdout == ''
        assert stderr.startswith('error: ')
        assert len(stderr.splitlines()) == 1
        assert diagnostic.replace('\x1b', '\\x1b') in stderr
        assert not stderr.rstrip('\n').endswith('.')
        if failure == 'tls':
            assert 'corporate CA' in stderr
            assert '--ca-bundle' in stderr
            assert 'REQUESTS_CA_BUNDLE' in stderr
            assert '--insecure' in stderr

    def test_insecure_run_warns_on_stderr(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')

        def revoked(*_args: object) -> int:
            return 0

        monkeypatch.setattr(cli_module, 'run_revocation_check', revoked)
        assert invoke_cli(
            [
                'verify-revocation',
                '--site-url',
                'https://sg.example.invalid',
                '--script-name',
                's',
                '--script-key-env',
                'SGTB_VERIFY_KEY',
                '--insecure',
            ]
        ) == (0, '', 'warning: TLS verification disabled; only use with a disposable script key\n')

    def test_mid_flow_upstream_fault_is_setup_error(
        self,
        fake_sg: _FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')

        def fake_input(prompt: str) -> str:
            del prompt
            fake_sg._rpc_fault = True
            return ''

        monkeypatch.setattr('builtins.input', fake_input)
        result = main(
            [
                'verify-revocation',
                '--site-url',
                fake_sg._url,
                '--script-name',
                'broker_read_all',
                '--script-key-env',
                'SGTB_VERIFY_KEY',
            ]
        )
        assert result == 2
        assert 'inconclusive' in capsys.readouterr().err

    def test_missing_key_env_is_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv('SGTB_ABSENT', raising=False)
        assert invoke_cli(
            [
                'verify-revocation',
                '--site-url',
                'https://sg.example.invalid',
                '--script-name',
                's',
                '--script-key-env',
                'SGTB_ABSENT',
            ]
        ) == (2, '', 'error: environment variable SGTB_ABSENT is not set or empty\n')

    def test_remote_http_is_rejected_before_key_prompt(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def unexpected_prompt(prompt: str) -> NoReturn:
            raise AssertionError(f'unexpected credential prompt: {prompt}')

        monkeypatch.setattr('getpass.getpass', unexpected_prompt)
        assert invoke_cli(
            [
                'verify-revocation',
                '--site-url',
                'http://sg.studio.internal',
                '--script-name',
                's',
            ]
        ) == (
            2,
            '',
            (
                'error: SG site URL must be an https:// URL (plain http is allowed only on '
                "loopback hosts): 'http://sg.studio.internal'\n"
            ),
        )

    def test_remote_http_is_rejected_without_request(
        self,
        fake_sg: _FakeSG,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')
        result = main(
            [
                'verify-revocation',
                '--site-url',
                'http://sg.studio.internal',
                '--script-name',
                's',
                '--script-key-env',
                'SGTB_VERIFY_KEY',
                '--proxy',
                fake_sg._url,
            ]
        )
        assert result == 2
        assert fake_sg._requests == []

    def test_runs_full_flow(
        self,
        fake_sg: _FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')

        def fake_input(prompt: str) -> str:
            del prompt
            fake_sg._fail_rpc = True
            fake_sg._session_revoked = True
            return ''

        monkeypatch.setattr('builtins.input', fake_input)
        result = main(
            [
                'verify-revocation',
                '--site-url',
                fake_sg._url,
                '--script-name',
                'broker_read_all',
                '--script-key-env',
                'SGTB_VERIFY_KEY',
            ]
        )
        assert result == 0
        assert 'key rotation immediately revoked' in capsys.readouterr().out

    def test_sg_failure_after_the_first_mint_is_inconclusive(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')

        def fail(*_args: object) -> NoReturn:
            raise SGError('SG session probe failed: probe fault')

        monkeypatch.setattr(cli_module, 'run_revocation_check', fail)
        assert invoke_cli(
            [
                'verify-revocation',
                '--site-url',
                'https://sg.example.invalid',
                '--script-name',
                's',
                '--script-key-env',
                'SGTB_VERIFY_KEY',
            ]
        ) == (
            2,
            '',
            'error: revocation check is inconclusive: SG session probe failed: probe fault\n',
        )


class TestVerifyRevocationProxy:
    def test_proxy_is_used(
        self,
        fake_sg: _FakeSG,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'k')
        result = main(
            [
                'verify-revocation',
                '--site-url',
                'http://127.0.0.1:9',
                '--script-name',
                's',
                '--script-key-env',
                'SGTB_VERIFY_KEY',
                '--proxy',
                fake_sg._url,
            ]
        )
        assert result == 2
        proxied = [str(r['path']) for r in fake_sg._requests]
        assert any(p.startswith('http://127.0.0.1:9') for p in proxied)


class _ClosedPipe(io.StringIO):
    def flush(self) -> None:
        raise BrokenPipeError

    def write(self, _text: str) -> int:
        raise BrokenPipeError


class _RefusingBrokerClient:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        pass

    def fetch_token(self, scope: str, token_type: str) -> NoReturn:
        del scope, token_type
        raise BrokerClientError('broker refused (HTTP 401): invalid client credentials')


def _fake_sign_in(_client_id: str, **_kwargs: object) -> TokenBundle:
    return TokenBundle(
        id_token=_ID_TOKEN,
        refresh_token='rt-1',  # noqa: S106 - fake credential
    )


def _fake_user_token(token_type: str) -> UserToken:
    return UserToken(
        token='token-1',  # noqa: S106 - fake credential
        token_type=token_type,
        login='jane@s.example',
        site_url='https://studio.shotgunstudio.com',
        expires_at=None,
        cache_until=datetime.datetime(2026, 8, 7, tzinfo=datetime.UTC),
    )


def _fixed_version(_name: str) -> str:
    return '9.8.7'


def _help_entries(
    parser: argparse.ArgumentParser, prefix: str
) -> Iterator[tuple[str, str | None]]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            subparsers = cast('argparse._SubParsersAction[argparse.ArgumentParser]', action)
            visible = [choice.dest for choice in subparsers._choices_actions]
            for choice in subparsers._choices_actions:
                yield f'{prefix} {choice.dest}', choice.help
            for name in visible:
                yield from _help_entries(subparsers.choices[name], f'{prefix} {name}')
        elif action.help is not argparse.SUPPRESS:
            label = '/'.join(action.option_strings) or action.dest
            yield f'{prefix} {label}', action.help


def _load_accepting_verifier() -> Callable[[str], dict[str, object]]:
    def verify(_token: str) -> dict[str, object]:
        return {}

    return verify


def _load_jane(*_args: object) -> str:
    return 'jane@s.example'


def _load_nothing(*_args: object) -> None:
    return None


def _offline_discovery(*_args: object, **_kwargs: object) -> NoReturn:
    raise requests.ConnectionError('offline')


def _pretend_silenced(_stream: TextIO) -> bool:
    return True


def _set_user_service_environment(monkeypatch: pytest.MonkeyPatch, *, oidc: bool = False) -> None:
    monkeypatch.setenv('SGUT_SITE_URL', 'https://sg.example.com')
    monkeypatch.setenv('SGUT_TOKEN_TYPES', 'rest')
    monkeypatch.setenv('SGUT_SCRIPT_NAME', 's')
    monkeypatch.setenv('SGUT_SCRIPT_KEY', 'k')
    monkeypatch.setenv('SGUT_AUDIENCES', 'aud-1')
    monkeypatch.setenv('SGUT_ALLOWED_DOMAIN', 'example.com')
    if oidc:
        monkeypatch.setenv('SGUT_PROVIDER', 'oidc')
        monkeypatch.setenv('SGUT_ISSUER', 'https://idp.example.com')


def _store_false(*_args: object) -> bool:
    return False


def _store_true(*_args: object) -> bool:
    return True


def _unexpected_provider_discovery(*_args: object, **_kwargs: object) -> NoReturn:
    raise AssertionError('unexpected provider discovery')


def _write_config(
    tmp_path: Path,
    *key_envs: str,
    scope_name: str | None = None,
    bind: str | None = None,
) -> Path:
    assert scope_name is None or len(key_envs) == 1
    scopes = ''
    for index, name in enumerate(key_envs):
        current_scope = scope_name or f'scope_{index}'
        script_name = 's' if scope_name is not None else f's{index}'
        scopes += (
            f'  {current_scope}:\n    script_name: {script_name}\n    script_key_env: {name}\n'
        )
    first_scope = scope_name or 'scope_0'
    server = f'server:\n  bind: {json.dumps(bind)}\n' if bind is not None else ''
    config = tmp_path / 'broker.yml'
    config.write_text(
        'site_url: https://studio.shotgunstudio.com\n'
        f'{server}'
        f'scopes:\n{scopes}'
        'clients:\n'
        '  farm:\n'
        f'    secret_hash: "{_CONFIG_HASH}"\n'
        f'    scopes: [{first_scope}]\n',
        encoding='utf-8',
    )
    return config


@pytest.fixture
def isolate_identity_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv('SG_USER_TOKEN_CLIENT_ID', raising=False)
    monkeypatch.delenv('SG_USER_TOKEN_ISSUER', raising=False)
    monkeypatch.delenv('SG_USER_TOKEN_EMAIL_CLAIM', raising=False)
    monkeypatch.delenv('SG_USER_TOKEN_ACCOUNT', raising=False)
    monkeypatch.setattr('sg_token_broker._userauth.requests.get', _unexpected_provider_discovery)


def test_every_visible_option_and_command_has_help() -> None:
    problems = [
        f'{name}: {text!r}'
        for name, text in _help_entries(cli_module._build_parser(), 'sg-token-broker')
        if not text
    ]
    assert problems == []


def test_get_token_usage_names_option_values() -> None:
    status, stdout, _ = invoke_cli(['get-token', '--help'])
    assert status == 0
    assert ' '.join(stdout.split('\n\n', 1)[0].split()) == (
        'usage: sg-token-broker get-token [-h] --scope NAME [--token-type {session,rest}] '
        '[--timeout SECONDS] [--retries COUNT]'
    )


def test_help_goes_to_stdout() -> None:
    status, stdout, stderr = invoke_cli(['--help'])
    assert (status, stderr) == (0, '')
    assert stdout.startswith('usage: sg-token-broker [-h] [--version] COMMAND ...\n')


def test_help_lists_commands_in_titled_groups() -> None:
    status, stdout, stderr = invoke_cli(['--help'])
    assert (status, stderr) == (0, '')
    headings = [line for line in stdout.splitlines() if line and not line.startswith(' ')]
    assert headings == [
        'usage: sg-token-broker [-h] [--version] COMMAND ...',
        'Issue SG tokens to pipeline tools without giving them SG script keys.',
        'options:',
        'services:',
        'clients:',
        'verification:',
    ]
    commands = [
        line.split()[0]
        for line in stdout.splitlines()
        if line.startswith('  ') and not line.startswith(('   ', '  -'))
    ]
    assert commands == [
        'serve-app-tokens',
        'serve-user-tokens',
        'check-config',
        'hash-secret',
        'get-token',
        'login',
        'logout',
        'get-user-token',
        'verify-revocation',
    ]


def test_interrupt_before_the_broker_serves_exits_130(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def interrupt(path: Path) -> NoReturn:
        del path
        raise KeyboardInterrupt

    monkeypatch.setattr(cli_module, 'load_config', interrupt)
    assert invoke_cli(['serve-app-tokens', '--config', 'broker.yml']) == (130, '', '')


def test_interrupt_outside_a_service_exits_130(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def interrupt() -> NoReturn:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli_module, 'generate_secret', interrupt)
    assert invoke_cli(['hash-secret']) == (130, '', '')


def test_missing_command_is_a_usage_error() -> None:
    status, stdout, stderr = invoke_cli([])
    assert (status, stdout) == (2, '')
    assert stderr.endswith(
        'sg-token-broker: error: the following arguments are required: COMMAND\n'
    )


def test_missing_metadata_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(name: str) -> str:
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, 'version', missing)
    status, stdout, stderr = invoke_cli(['--version'])
    assert (status, stdout) == (2, '')
    assert stderr == 'error: installed distribution metadata for sg-token-broker is unavailable\n'


def test_normal_runs_do_not_read_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(name: str) -> str:
        raise AssertionError(name)

    monkeypatch.setattr(importlib.metadata, 'version', forbidden)
    assert invoke_cli(['--help'])[0] == 0


@pytest.mark.parametrize(
    ('command', 'headings'),
    [
        ('serve-app-tokens', ['options:']),
        ('check-config', ['options:']),
        ('hash-secret', ['options:']),
        ('login', ['options:']),
        ('get-user-token', ['options:']),
        ('get-token', ['options:', 'request:', 'connection:']),
        ('verify-revocation', ['options:', 'site and script:', 'connection:']),
    ],
)
def test_subcommand_options_are_grouped_only_by_kind(command: str, headings: list[str]) -> None:
    status, stdout, stderr = invoke_cli([command, '--help'])
    assert (status, stderr) == (0, '')
    assert [
        line for line in stdout.splitlines() if line.endswith(':') and not line.startswith(' ')
    ] == headings


def test_unavailable_stdout_is_an_error(capsys: pytest.CaptureFixture[str]) -> None:
    # Restore stdout before capsys finalizes, so its capture stream is not reinstated.
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(sys, 'stdout', None)
        status = main(['--help'])

    assert (status, capsys.readouterr().err) == (2, 'error: standard output is unavailable\n')


def test_verify_revocation_help_states_its_exit_statuses() -> None:
    status, stdout, stderr = invoke_cli(['verify-revocation', '--help'])
    assert (status, stderr) == (0, '')
    assert ' '.join(stdout.split()).endswith(
        'Exit status: 0 if a procedure retired the token immediately, 1 if the token '
        'survived every step tried, 2 if setup failed or an SG error made the run '
        'inconclusive, and 3 if the run ended on an unverified step.'
    )


def test_version_ignores_other_valid_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(importlib.metadata, 'version', _fixed_version)
    assert invoke_cli(['--version', *VALID_COMMAND_ARGUMENTS]) == (
        0,
        'sg-token-broker 9.8.7\n',
        '',
    )


def test_version_prints_the_installed_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(importlib.metadata, 'version', _fixed_version)
    assert invoke_cli(['--version']) == (0, 'sg-token-broker 9.8.7\n', '')
