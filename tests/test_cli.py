import argparse
import base64
import datetime
import getpass
import hashlib
import importlib.metadata
import inspect
import json
import logging
import os
import ssl
import sys
import warnings
from collections.abc import Callable, Iterator
from contextlib import nullcontext
from functools import partial
from pathlib import Path
from typing import NoReturn, cast
from unittest.mock import Mock

import pytest
import requests

import sg_token_broker._cli as cli_module
from sg_token_broker import BrokerClient, UserTokenClient
from sg_token_broker._cli import main
from sg_token_broker._googleverify import VerifierUnavailableError
from sg_token_broker._oidcverify import OidcUnavailableError
from sg_token_broker._retry import (
    DEFAULT_MAX_WAIT_SECONDS,
    DEFAULT_REFRESH_MARGIN_SECONDS,
    DEFAULT_RETRIES,
    DEFAULT_TIMEOUT_SECONDS,
    RetryTiming,
)
from sg_token_broker._secrets import verify_secret
from sg_token_broker._sg import MintedToken, SGError, SGMinter
from sg_token_broker._userauth import SignInError, _TokenBundle
from sg_token_broker._userclient import UserToken, UserTokenClientError
from tests._timeouts import STALL_TIMEOUT_SECONDS
from tests.cli_helpers import invoke_cli
from tests.conftest import BROKER_CREDENTIAL, FakeSG

# Precomputed valid hash of 'x' for configuration setup.
_CONFIG_HASH = (
    'scrypt$16384$8$1$40vcdl7AgTzLmOGl+anfBQ==$'
    'wL+YRQJWbt9/zf6Wpcl3nDff4/OkYaw7LIU04aIrjpqBs/boSojdqPdZXy8s3oZxk/CJN5/VcQy138851oY/sw=='
)
_GET_TOKEN_ARGS = ['get-token', '--scope', 'read_all', '--max-wait', str(STALL_TIMEOUT_SECONDS)]
# Stored Google sign-ins live under this keyring issuer; changing it orphans them.
_GOOGLE_KEYRING_ISSUER = 'https://oauth2.googleapis.com/token'
_ID_TOKEN = (
    'e30.'
    + base64.urlsafe_b64encode(json.dumps({'email': 'jane@s.example', 'nonce': 'n'}).encode())
    .rstrip(b'=')
    .decode()
    + '.x'
)
_VALID_COMMAND_ARGUMENTS = ['hash-secret']


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
        status, stdout, stderr = invoke_cli(['check-config', '--config', str(cfg)])
        assert (status, stdout) == (2, '')
        [diagnostic] = stderr.splitlines()
        prefix = f"error: scope 'read_all': cannot read script key file {keyfile}: "
        assert diagnostic.startswith(prefix)
        assert 'utf-8' in diagnostic.removeprefix(prefix).lower()

    def test_unreadable_config_is_a_configuration_error(self, tmp_path: Path) -> None:
        cfg = tmp_path / 'missing.yml'
        status, stdout, stderr = invoke_cli(['check-config', '--config', str(cfg)])
        assert (status, stdout) == (2, '')
        assert stderr.startswith(f'error: cannot read config file {cfg}: ')
        assert stderr.count('\n') == 1

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
        status, stdout, stderr = invoke_cli(['check-config', '--config', str(cfg)])
        assert (status, stdout) == (2, '')
        [diagnostic] = stderr.splitlines()
        prefix = f'error: invalid YAML in {cfg} at line 2, column 10: '
        assert diagnostic.startswith(prefix)
        assert diagnostic.removeprefix(prefix).strip()


class TestGetToken:
    def test_blank_input_requests_an_ordinary_token(self, broker_post: Mock) -> None:
        broker_post.return_value = _broker_success('new-session')
        status, stdout, stderr = invoke_cli(
            [*_GET_TOKEN_ARGS, '--replace-rejected'],
            stdin='\n \t\n',
        )
        assert (status, stderr) == (0, '')
        assert json.loads(stdout) == broker_post.return_value.json.return_value
        assert broker_post.call_args.kwargs['json'] == {
            'scope': 'read_all',
            'token_type': 'session',
        }

    def test_broker_failure_redacts_all_submitted_tokens(self, broker_post: Mock) -> None:
        first, second = 'synthetic.alpha', 'synthetic.beta'
        refusal = Mock(status_code=401, headers={})
        refusal.json.return_value = {'detail': f'access denied for {first}, {second}, {first}'}
        broker_post.return_value = refusal
        status, stdout, stderr = invoke_cli(
            [*_GET_TOKEN_ARGS, '--replace-rejected'], stdin=f'{first}\n{second}\n'
        )
        assert (status, stdout) == (1, '')
        assert first not in stderr
        assert second not in stderr
        assert stderr == (
            'error: broker refused (HTTP 401): access denied for '
            '[redacted], [redacted], [redacted]\n'
        )

    def test_failure_exits_nonzero(self, broker_post: Mock) -> None:
        broker_post.side_effect = requests.ConnectionError('offline')
        status, stdout, stderr = invoke_cli(
            [*_GET_TOKEN_ARGS, '--timeout', str(STALL_TIMEOUT_SECONDS), '--retries', '0']
        )
        assert (status, stdout) == (1, '')
        assert stderr.startswith(
            'error: no token after 1 attempt(s) (retries=0); last failure: '
            'cannot reach broker at https://broker.example.invalid: ConnectionError'
        )
        assert stderr.endswith('\n')
        assert stderr.count('\n') == 1

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

    def test_missing_scope_with_replacement_names_the_option(self) -> None:
        status, stdout, stderr = invoke_cli(['get-token', '--replace-rejected'])
        assert (status, stdout) == (2, '')
        assert 'required: --scope' in stderr

    def test_negative_retries_are_usage_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(['get-token', '--scope', 'read_all', '--retries', '-1'])
        assert exc_info.value.code == 2
        assert 'must be >= 0' in capsys.readouterr().err

    def test_old_broker_repeating_a_rejected_token(self, broker_post: Mock) -> None:
        rejected = 'previous-credential'
        broker_post.return_value = _broker_success(rejected)
        status, stdout, stderr = invoke_cli(
            [*_GET_TOKEN_ARGS, '--replace-rejected'],
            stdin=f'{rejected}\nsecond-credential\n',
        )
        assert (status, stdout) == (1, '')
        assert 'upgrade every broker to 0.3.0' in stderr
        assert rejected not in stderr
        assert 'second-credential' not in stderr
        broker_post.assert_called_once()

    def test_ordinary_get_token_preserves_stray_argument_diagnostic(self) -> None:
        status, stdout, stderr = invoke_cli(['get-token', '--scope', 'read_all', 'stray'])
        assert (status, stdout) == (2, '')
        assert 'unrecognized arguments: stray' in stderr

    def test_prints_token_json(
        self,
        broker_url: str,
        fake_sg: FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv('SG_TOKEN_BROKER_URL', broker_url)
        monkeypatch.setenv('SG_TOKEN_BROKER_CLIENT_ID', 'farm')
        monkeypatch.setenv('SG_TOKEN_BROKER_CLIENT_SECRET', BROKER_CREDENTIAL)
        args = [*_GET_TOKEN_ARGS, '--timeout', str(STALL_TIMEOUT_SECONDS), '--token-type', 'rest']
        assert main(args) == 0
        body = json.loads(capsys.readouterr().out)
        assert body['token'] == fake_sg.canned_rest

    def test_refused_request_is_a_runtime_failure(self, broker_post: Mock) -> None:
        refusal = Mock(status_code=401, headers={})
        refusal.json.return_value = {'detail': 'invalid client credentials'}
        broker_post.return_value = refusal
        assert invoke_cli(_GET_TOKEN_ARGS) == (
            1,
            '',
            'error: broker refused (HTTP 401): invalid client credentials\n',
        )

    def test_rejected_input_limit(self, broker_post: Mock) -> None:
        status, stdout, stderr = invoke_cli(
            ['get-token', '--scope', 'read_all', '--replace-rejected'],
            stdin='one-repeated-secret\n' * 9,
        )
        assert (status, stdout) == (2, '')
        assert 'at most 8 rejected tokens' in stderr
        assert 'one-repeated-secret' not in stderr
        broker_post.assert_not_called()

    @pytest.mark.parametrize('processes', [2, 8])
    def test_replacement_across_broker_processes(self, processes: int, broker_post: Mock) -> None:
        caches = [f'stale-{i}' for i in range(processes)]
        fresh = 'fresh-session'
        history = ['older-than-every-cache']
        argv = [*_GET_TOKEN_ARGS, '--replace-rejected']

        def dispatch(_url: str, *, json: dict[str, object], **_kwargs: object) -> Mock:
            digests = [hashlib.sha256(value.encode()).hexdigest() for value in history[-8:]]
            assert json == {
                'scope': 'read_all',
                'token_type': 'session',
                'rejected_tokens_sha256': digests,
            }
            index = (broker_post.call_count - 1) % processes
            if hashlib.sha256(caches[index].encode()).hexdigest() in digests:
                caches[index] = fresh
            return _broker_success(caches[index])

        broker_post.side_effect = dispatch
        for call in range(1, processes + 2):
            status, stdout, stderr = invoke_cli(argv, stdin='\n \t\n'.join(history[-8:]))
            assert (status, stderr) == (0, '')
            assert broker_post.call_count == call
            assert all(previous not in stdout for previous in history)
            issued = json.loads(stdout)['token']
            history.append(issued)
            if issued == fresh:
                break
        assert history[-1] == fresh

    def test_setup_error_redacts_submitted_token(
        self, monkeypatch: pytest.MonkeyPatch, broker_post: Mock
    ) -> None:
        rejected = 'synthetic-credential'
        monkeypatch.setenv('SG_TOKEN_BROKER_URL', f'http://broker.example.invalid/{rejected}')
        status, stdout, stderr = invoke_cli(
            [*_GET_TOKEN_ARGS, '--replace-rejected'], stdin=rejected
        )
        assert (status, stdout) == (2, '')
        assert rejected not in stderr
        assert 'broker URL must be an https:// URL' in stderr
        broker_post.assert_not_called()

    def test_terminal_input_names_how_to_pipe_tokens(
        self,
        broker_post: Mock,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(sys, 'stdin', Mock(isatty=lambda: True))
        assert main(['get-token', '--scope', 'read_all', '--replace-rejected']) == 2
        captured = capsys.readouterr()
        assert captured.out == ''
        assert 'pipe' in captured.err
        broker_post.assert_not_called()

    @pytest.mark.parametrize(
        'arguments',
        [
            ['--scope', 'read_all', '--replace-rejected={}'],
            ['--scope', 'read_all', '--replace-rejected', '{}'],
            ['--scope', 'read_all', '--replace-rejected', '-h={}'],
            ['--scope', 'read_all', '--replace-rejected', '--r={}'],
            ['--scope', 'read_all', '--replace-rejected', '--token-type', '{}'],
            ['--replace-rejected', '{}'],
        ],
    )
    def test_token_argument_is_redacted(self, arguments: list[str]) -> None:
        misplaced = 'misplaced-credential'
        status, stdout, stderr = invoke_cli(
            ['get-token', *(arg.format(misplaced) for arg in arguments)]
        )
        assert (status, stdout) == (2, '')
        assert misplaced not in stderr
        assert 'standard input' in stderr

    @pytest.mark.parametrize('max_wait', [None, 1.5])
    def test_retries_until_max_wait(
        self, max_wait: float | None, broker_post: Mock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        now = 0.0

        def advance(seconds: float) -> None:
            nonlocal now
            now += seconds

        timing = RetryTiming(lambda: now, advance, lambda: 0.0)
        monkeypatch.setattr('sg_token_broker._client.RetryTiming', lambda: timing)
        busy = Mock(status_code=503, headers={'Retry-After': '1'})
        later = Mock(status_code=503, headers={'Retry-After': '600'})
        broker_post.side_effect = [busy, busy, busy, later]
        options = ['--max-wait', str(max_wait)] if max_wait is not None else []
        status, stdout, stderr = invoke_cli(['get-token', '--scope', 'read_all', *options])
        assert (status, stdout) == (1, '')
        budget = DEFAULT_MAX_WAIT_SECONDS if max_wait is None else max_wait
        assert f'beyond max_wait {budget:g}s' in stderr
        assert broker_post.call_count == (4 if max_wait is None else 2)

    def test_unknown_replacement_option_is_redacted(self) -> None:
        status, stdout, stderr = invoke_cli(
            [
                'get-token',
                '--scope',
                'typed-scope',
                '--replace-rejected',
                '--typed-option=typed-value',
            ]
        )
        assert (status, stdout) == (2, '')
        assert 'typed-' not in stderr
        assert stderr.startswith('usage: sg-token-broker get-token ')
        assert stderr.endswith(
            '--replace-rejected reads rejected tokens from standard input, one per line; '
            'do not pass tokens as arguments\n'
        )


@pytest.mark.usefixtures('isolate_identity_environment')
class TestGetUserToken:
    @pytest.mark.parametrize('max_wait', [None, 1.5])
    def test_get_user_token_passes_request_options(
        self, max_wait: float | None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        factory = Mock()
        factory.return_value.fetch_token.return_value = _fake_user_token('session')
        monkeypatch.setattr(cli_module, 'UserTokenClient', factory)
        options = (
            []
            if max_wait is None
            else ['--max-wait', str(max_wait), '--retries', '0', '--timeout', '2.5']
        )
        assert main(['get-user-token', '--force-refresh', *options]) == 0
        factory.assert_called_once_with(
            max_wait=DEFAULT_MAX_WAIT_SECONDS if max_wait is None else max_wait,
            retries=None if max_wait is None else 0,
            timeout=DEFAULT_TIMEOUT_SECONDS if max_wait is None else 2.5,
        )
        factory.return_value.fetch_token.assert_called_once_with('session', force_refresh=True)

    @pytest.mark.parametrize(
        ('kind', 'expiry'), [('session', None), ('rest', '2026-08-08T00:00:00+00:00')]
    )
    def test_get_user_token_prints_token_json(
        self, kind: str, expiry: str | None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        factory = Mock()
        factory.return_value.fetch_token.return_value = _fake_user_token(kind)
        monkeypatch.setattr(cli_module, 'UserTokenClient', factory)
        status, stdout, stderr = invoke_cli(['get-user-token', '--token-type', kind])
        assert (status, stderr) == (0, '')
        factory.return_value.fetch_token.assert_called_once_with(kind, force_refresh=False)
        assert json.loads(stdout) == {
            'token': 'token-1',
            'token_type': kind,
            'login': 'jane@s.example',
            'site_url': 'https://studio.shotgunstudio.com',
            'expires_at': expiry,
            'cache_until': '2026-08-07T00:00:00+00:00',
        }

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

    def test_negative_retries_is_usage_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as caught:
            main(['get-user-token', '--retries=-1'])
        assert caught.value.code == 2
        assert 'must be >= 0' in capsys.readouterr().err

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
    def test_hashes_stdin_secret_without_echo(self) -> None:
        status, stdout, stderr = invoke_cli(
            ['hash-secret', '--secret'], stdin=f'{BROKER_CREDENTIAL}\nignored\n'
        )
        assert (status, stderr) == (0, '')
        assert stdout.startswith('hash: ')
        assert stdout.count('\n') == 1
        assert BROKER_CREDENTIAL not in stdout
        assert verify_secret(BROKER_CREDENTIAL, stdout.removeprefix('hash: ').removesuffix('\n'))

    def test_hashes_terminal_secret_without_echo(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        prompt = Mock(return_value=BROKER_CREDENTIAL)
        monkeypatch.setattr(cli_module.sys, 'stdin', Mock(isatty=lambda: True))
        monkeypatch.setattr(cli_module.getpass, 'getpass', prompt)
        assert main(['hash-secret', '--secret']) == 0
        captured = capsys.readouterr()
        prompt.assert_called_once_with('secret: ')
        assert captured.err == ''
        assert captured.out.startswith('hash: ')
        assert captured.out.count('\n') == 1
        assert BROKER_CREDENTIAL not in captured.out
        assert verify_secret(
            BROKER_CREDENTIAL, captured.out.removeprefix('hash: ').removesuffix('\n')
        )

    def test_outputs_secret_and_hash(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(['hash-secret']) == 0
        out = capsys.readouterr().out
        lines = dict(line.split(': ', 1) for line in out.strip().splitlines())
        assert verify_secret(lines['secret'], lines['hash'])

    @pytest.mark.parametrize('secret', ['', 'café', 'has space'])
    def test_stdin_secret_rejects_bad_grammar(self, secret: str) -> None:
        assert invoke_cli(['hash-secret', '--secret'], stdin=f'{secret}\n') == (
            2,
            '',
            'error: secret must be non-empty printable ASCII with no spaces\n',
        )

    def test_terminal_echo_warning_rejects_before_fallback_read(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        fallback_read = Mock(return_value=BROKER_CREDENTIAL)
        terminal_input = Mock()
        terminal_input.isatty.return_value = True
        terminal_input.readline.side_effect = AssertionError('unexpected standard-input read')

        def warn_then_fallback(prompt: str) -> str:
            assert prompt == 'secret: '
            warnings.warn('cannot control terminal echo', getpass.GetPassWarning, stacklevel=2)
            return fallback_read()

        monkeypatch.setattr(cli_module.sys, 'stdin', terminal_input)
        monkeypatch.setattr(cli_module.getpass, 'getpass', warn_then_fallback)
        assert main(['hash-secret', '--secret']) == 2
        captured = capsys.readouterr()
        assert captured.out == ''
        assert captured.err == (
            'error: cannot hide the secret on this terminal; pipe it on standard input instead\n'
        )
        fallback_read.assert_not_called()
        terminal_input.readline.assert_not_called()


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
        assert invoke_cli(['login', '--no-store']) == (
            0,
            'signed in as jane@s.example (credential not stored)\n',
            '',
        )
        assert called == []

    def test_login_passes_the_configured_client_secret(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv('SG_USER_TOKEN_CLIENT_ID', 'client-1')
        monkeypatch.setenv('SG_USER_TOKEN_CLIENT_SECRET', 'secret-1')
        sign_in = Mock(side_effect=_fake_sign_in)
        monkeypatch.setattr(cli_module, 'sign_in', sign_in)

        assert invoke_cli(['login', '--no-store'])[0] == 0
        assert [sign_in.call_args.kwargs['client_secret']] == ['secret-1']

    def test_login_reports_when_provider_issues_no_refresh_credential(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv('SG_USER_TOKEN_CLIENT_ID', 'client-1')

        def sign_in_without_refresh(_client_id: str, **_kwargs: object) -> _TokenBundle:
            return _TokenBundle(id_token=_ID_TOKEN, refresh_token=None)

        monkeypatch.setattr(cli_module, 'sign_in', sign_in_without_refresh)
        store = Mock(side_effect=AssertionError('no credential to store'))
        monkeypatch.setattr(cli_module, 'store_refresh_token', store)
        assert invoke_cli(['login']) == (
            0,
            (
                'signed in as jane@s.example '
                '(credential not stored: the provider issued no refresh credential)\n'
            ),
            '',
        )
        store.assert_not_called()

    def test_login_reports_when_storage_is_unavailable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv('SG_USER_TOKEN_CLIENT_ID', 'client-1')
        monkeypatch.setattr(cli_module, 'sign_in', _fake_sign_in)
        monkeypatch.setattr(cli_module, 'store_refresh_token', _store_false)
        assert invoke_cli(['login']) == (
            0,
            (
                'signed in as jane@s.example '
                '(credential not stored: install sg-token-broker[login] or use a supported '
                'keyring)\n'
            ),
            '',
        )

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
        assert stored == [(_GOOGLE_KEYRING_ISSUER, 'client-1', 'jane@s.example', 'rt-1')]
        assert pointed == [(_GOOGLE_KEYRING_ISSUER, 'client-1', 'jane@s.example')]
        assert capsys.readouterr().out == 'signed in as jane@s.example\n'

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
    @pytest.mark.parametrize(
        'issuer', [_GOOGLE_KEYRING_ISSUER, 'https://legacy:private@idp.example/tenant']
    )
    @pytest.mark.usefixtures('no_requests')
    def test_logout_deletes_credential_and_pointer(
        self, monkeypatch: pytest.MonkeyPatch, issuer: str
    ) -> None:
        monkeypatch.setenv('SG_USER_TOKEN_ISSUER', issuer)
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
        assert dropped == [(issuer, 'client-1', 'jane@s.example')]
        assert pointer_dropped == [(issuer, 'client-1')]

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
        assert dropped == [(_GOOGLE_KEYRING_ISSUER, 'client-1', 'bob@s.example')]
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
        assert deleted[0] == (_GOOGLE_KEYRING_ISSUER, 'client-1', 'jane@s.example')

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

        assert invoke_cli(['serve-app-tokens', '--config', str(cfg)]) == (
            0,
            '',
            f'serving on {expected_url}\n',
        )
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
            for _ in range(3):
                server.logger.log(logging.INFO, '{"event": "issue"}')
            raise KeyboardInterrupt

        server.serve_forever.side_effect = serve_one_logged_request
        monkeypatch.setattr(cli_module, 'create_user_token_server', Mock(return_value=server))
        private_output = Mock()
        private_output.write.side_effect = BrokenPipeError
        monkeypatch.setattr(
            cli_module,
            'service_streams',
            Mock(return_value=nullcontext((private_output, sys.stderr))),
        )
        assert main(['serve-user-tokens']) == 0
        assert private_output.write.call_count == 1
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

        session = requests.Session()
        session.headers['Authorization'] = 'private-transport-credential'

        def refuse(request: requests.PreparedRequest, **_kwargs: object) -> requests.Response:
            body = {
                'error': 'invalid_client',
                'error_description': request.headers['Authorization'],
            }
            return Mock(
                status_code=401,
                is_redirect=False,
                is_permanent_redirect=False,
                json=Mock(return_value=body),
            )

        monkeypatch.setattr(session, 'send', refuse)
        monkeypatch.setattr(requests, 'Session', Mock(return_value=session))
        assert invoke_cli(['serve-user-tokens']) == (
            1,
            '',
            (
                'error: cannot verify identity tokens: OIDC discovery returned HTTP 401 '
                'at https://idp.example.com: invalid_client: '
                'check the configured OAuth client ID and secret\n'
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

    @pytest.mark.usefixtures('_slow_revocation_minter')
    def test_mid_flow_upstream_fault_is_setup_error(
        self,
        fake_sg: FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')

        def fake_input(prompt: str) -> str:
            del prompt
            fake_sg.rpc_fault = True
            return ''

        monkeypatch.setattr('builtins.input', fake_input)
        result = main(
            [
                'verify-revocation',
                '--site-url',
                fake_sg.url,
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
        offline_sg: FakeSG,
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
                offline_sg.url,
            ]
        )
        assert result == 2

    @pytest.mark.usefixtures('_slow_revocation_minter')
    def test_runs_full_flow(
        self,
        fake_sg: FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')

        def fake_input(prompt: str) -> str:
            del prompt
            fake_sg.fail_rpc = True
            fake_sg.session_revoked = True
            return ''

        monkeypatch.setattr('builtins.input', fake_input)
        result = main(
            [
                'verify-revocation',
                '--site-url',
                fake_sg.url,
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
    @pytest.mark.usefixtures('_slow_revocation_minter')
    def test_proxy_is_used(
        self,
        fake_sg: FakeSG,
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
                fake_sg.url,
            ]
        )
        assert result == 2
        proxied = [str(r['path']) for r in fake_sg.requests]
        assert any(p.startswith('http://127.0.0.1:9') for p in proxied)


def _broker_success(value: str) -> Mock:
    response = Mock(status_code=200)
    response.json.return_value = {
        'token': value,
        'scope': 'read_all',
        'token_type': 'session',
        'site_url': 'https://sg.example.invalid',
        'expires_at': '2099-01-01T00:00:00+00:00',
    }
    return response


def _fake_sign_in(_client_id: str, **_kwargs: object) -> _TokenBundle:
    return _TokenBundle(
        id_token=_ID_TOKEN,
        refresh_token='rt-1',  # noqa: S106 - fake credential
    )


def _fake_user_token(kind: str) -> UserToken:
    return UserToken(
        token='token-1',  # noqa: S106 - fake credential
        token_type=kind,
        login='jane@s.example',
        site_url='https://studio.shotgunstudio.com',
        expires_at=datetime.datetime(2026, 8, 8, tzinfo=datetime.UTC) if kind == 'rest' else None,
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


def _help_groups(output: str) -> list[tuple[str, list[str]]]:
    groups: list[tuple[str, list[str]]] = []
    heading = ''
    members: list[str] = []
    for line in output.splitlines():
        if line and not line.startswith(' '):
            heading = line[:-1] if line.endswith(':') else ''
            members = []
        elif heading and line.startswith('  ') and not line.startswith('   '):
            if not members:
                groups.append((heading, members))
            members.append(line.split()[0].rstrip(','))
    return groups


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


def _store_false(*_args: object) -> bool:
    return False


def _store_true(*_args: object) -> bool:
    return True


def _unexpected_provider_discovery(*_args: object, **_kwargs: object) -> NoReturn:
    raise AssertionError('unexpected provider discovery')


@pytest.fixture
def broker_post(monkeypatch: pytest.MonkeyPatch) -> Mock:
    monkeypatch.setenv('SG_TOKEN_BROKER_URL', 'https://broker.example.invalid')
    monkeypatch.setenv('SG_TOKEN_BROKER_CLIENT_ID', 'farm')
    monkeypatch.setenv('SG_TOKEN_BROKER_CLIENT_SECRET', BROKER_CREDENTIAL)
    post = Mock()
    monkeypatch.setattr(requests.Session, 'post', post)
    return post


@pytest.fixture
def _slow_revocation_minter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_module,
        'SGMinter',
        partial(SGMinter, timeout=STALL_TIMEOUT_SECONDS),
    )


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
    monkeypatch.delenv('SG_USER_TOKEN_CLIENT_SECRET', raising=False)
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
        '[--replace-rejected] [--timeout SECONDS] [--max-wait SECONDS] [--retries COUNT]'
    )
    help_text = ' '.join(stdout.split())
    assert 'standard input, one per line' in help_text
    assert 'default: no cap' in help_text
    assert f'default: {DEFAULT_MAX_WAIT_SECONDS:g}' in help_text


def test_help_lists_commands_in_titled_groups() -> None:
    status, stdout, stderr = invoke_cli(['--help'])
    assert (status, stderr) == (0, '')
    assert stdout.startswith('usage: sg-token-broker [-h] [--version] COMMAND ...\n')
    assert _help_groups(stdout) == [
        ('options', ['-h', '--version']),
        ('services', ['serve-app-tokens', 'serve-user-tokens', 'check-config', 'hash-secret']),
        ('clients', ['get-token', 'login', 'logout', 'get-user-token']),
        ('verification', ['verify-revocation']),
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
    'argv',
    [
        ['--help', '--rep'],
        ['--replace-rejected', '--help'],
        ['--help', '--', '--replace-rejected'],
        ['--help', 'get-token', '--replace-rejected'],
    ],
)
def test_root_help_in_replacement_mode_matches_ordinary_help(argv: list[str]) -> None:
    _, ordinary_help, _ = invoke_cli(['--help'])
    assert invoke_cli(argv) == (0, ordinary_help, '')


@pytest.mark.parametrize(
    ('argv', 'marker'),
    [
        (['--unknown', 'ROOT_MARKER', 'get-token', '--replace-rejected'], 'ROOT_MARKER'),
        (
            ['verify-revocation', '--replace-rejected', '--unknown=ATTACHED_MARKER'],
            'ATTACHED_MARKER',
        ),
        (['--rep=PREFIX_MARKER', 'logout'], 'PREFIX_MARKER'),
    ],
)
def test_misplaced_replacement_option_redacts_usage_errors(argv: list[str], marker: str) -> None:
    status, stdout, stderr = invoke_cli(argv)
    assert (status, stdout) == (2, '')
    assert marker not in stderr
    assert stderr.endswith(
        ': error: --replace-rejected reads rejected tokens from standard input, one per line; '
        'do not pass tokens as arguments\n'
    )


@pytest.mark.parametrize(
    ('command', 'groups'),
    [
        ('serve-app-tokens', {'options': ['-h', '--config']}),
        ('check-config', {'options': ['-h', '--config']}),
        ('hash-secret', {'options': ['-h', '--secret']}),
        ('login', {'options': ['-h', '--no-store']}),
        (
            'get-user-token',
            {
                'options': ['-h'],
                'request': ['--token-type', '--force-refresh'],
                'connection': ['--timeout', '--max-wait', '--retries'],
            },
        ),
        (
            'get-token',
            {
                'options': ['-h'],
                'request': ['--scope', '--token-type', '--replace-rejected'],
                'connection': ['--timeout', '--max-wait', '--retries'],
            },
        ),
        (
            'verify-revocation',
            {
                'options': ['-h'],
                'site and script': ['--site-url', '--script-name', '--script-key-env'],
                'connection': ['--proxy', '--ca-bundle', '--insecure'],
            },
        ),
    ],
)
def test_subcommand_options_are_grouped_only_by_kind(
    command: str, groups: dict[str, list[str]]
) -> None:
    status, stdout, stderr = invoke_cli([command, '--help'])
    assert (status, stderr) == (0, '')
    assert _help_groups(stdout) == list(groups.items())


@pytest.mark.parametrize(
    ('command', 'option', 'value'),
    [
        *(('get-token', '--timeout', value) for value in ('0', '-1', 'nan', 'inf', '-inf', 'abc')),
        ('get-token', '--max-wait', '0'),
        ('get-user-token', '--timeout', '0'),
        ('get-user-token', '--max-wait', '0'),
    ],
)
def test_invalid_request_seconds_are_usage_errors(command: str, option: str, value: str) -> None:
    scope = ['--scope', 'read_all'] if command == 'get-token' else []
    status, stdout, stderr = invoke_cli([command, *scope, f'{option}={value}'])
    assert (status, stdout) == (2, '')
    assert 'finite floating-point value greater than zero' in stderr


@pytest.mark.parametrize('kind', ['readable', 'directory', 'unreadable'])
def test_ca_bundle_requires_a_readable_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    bundle = tmp_path / 'ca.pem'
    if kind == 'directory':
        bundle.mkdir()
    else:
        bundle.write_bytes(b'certificate data')
    if kind == 'unreadable':
        monkeypatch.setattr(Path, 'open', Mock(side_effect=PermissionError('denied')))
    module = cli_module
    if kind == 'readable':
        assert module._readable_ca_bundle(str(bundle)) == str(bundle)
    else:
        with pytest.raises(argparse.ArgumentTypeError) as caught:
            module._readable_ca_bundle(str(bundle))
        assert str(caught.value) == f'no readable CA bundle at {bundle}'


@pytest.mark.parametrize(
    ('arguments', 'client_type'),
    [(['get-token', '--scope', 'read_all'], BrokerClient), (['get-user-token'], UserTokenClient)],
)
def test_cli_and_python_share_tuning_defaults(
    arguments: list[str], client_type: type[BrokerClient] | type[UserTokenClient]
) -> None:
    expected = {
        'timeout': DEFAULT_TIMEOUT_SECONDS,
        'retries': DEFAULT_RETRIES,
        'refresh_margin': DEFAULT_REFRESH_MARGIN_SECONDS,
        'max_wait': DEFAULT_MAX_WAIT_SECONDS,
    }
    parameters = inspect.signature(client_type).parameters
    assert {name: parameters[name].default for name in expected} == expected
    options = cli_module._build_parser().parse_args(arguments)
    assert (options.timeout, options.retries, options.max_wait) == (
        DEFAULT_TIMEOUT_SECONDS,
        DEFAULT_RETRIES,
        DEFAULT_MAX_WAIT_SECONDS,
    )
    status, stdout, _ = invoke_cli([arguments[0], '--help'])
    assert status == 0
    assert f'seconds to wait for each request (default: {options.timeout:g})' in ' '.join(
        stdout.split()
    )


@pytest.mark.parametrize(
    ('argv', 'prog', 'hint'),
    [
        (['--vers'], 'sg-token-broker', '--vers (did you mean --version?)'),
        (
            ['get-user-token', '--hel'],
            'sg-token-broker get-user-token',
            '--hel (did you mean --help?)',
        ),
        (
            ['get-token', '--scope', 's', '--ret', 'x'],
            'sg-token-broker get-token',
            '--ret (did you mean --retries?)',
        ),
        (
            ['verify-revocation', '--ca', 'x'],
            'sg-token-broker verify-revocation',
            '--ca (did you mean --ca-bundle?)',
        ),
        (
            ['get-token', '--scop', 's'],
            'sg-token-broker get-token',
            '--scop (did you mean --scope?)',
        ),
    ],
)
def test_abbreviated_long_options_are_usage_errors(argv: list[str], prog: str, hint: str) -> None:
    status, stdout, stderr = invoke_cli(argv)
    assert (status, stdout) == (2, '')
    assert stderr.startswith(f'usage: {prog} [-h]')
    assert stderr.endswith(f'{prog}: error: unrecognized arguments: {hint}\n')


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


def test_verify_revocation_missing_ca_bundle_is_a_usage_error(tmp_path: Path) -> None:
    missing = tmp_path / 'missing-ca.pem'
    status, _, stderr = invoke_cli(
        [
            'verify-revocation',
            '--site-url',
            'https://127.0.0.1:1',
            '--script-name',
            's',
            '--ca-bundle',
            str(missing),
        ]
    )
    assert status == 2
    assert f'no readable CA bundle at {missing}' in stderr


def test_version_ignores_other_valid_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(importlib.metadata, 'version', _fixed_version)
    assert invoke_cli(['--version', *_VALID_COMMAND_ARGUMENTS]) == (
        0,
        'sg-token-broker 9.8.7\n',
        '',
    )


def test_version_prints_the_installed_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(importlib.metadata, 'version', _fixed_version)
    assert invoke_cli(['--version']) == (0, 'sg-token-broker 9.8.7\n', '')
