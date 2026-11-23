import argparse
import hashlib
from functools import partial
from pathlib import Path
from types import ModuleType
from typing import NoReturn
from unittest.mock import Mock

import pytest
import requests

from tests._revocation import (
    ISSUED_SESSION,
    REPLACEMENT_KEY,
    assert_operator_steps,
    assert_replacement_procedure,
    assert_restore_reminder,
)
from tests.conftest import FakeSG
from tests.scripts._helpers import load_script as _load_path

_SCRIPT_PATH = Path(__file__).parents[2] / 'scripts' / 'verify_sg_revocation.py'
_ARGS = [
    '--site-url',
    'https://sg.example.invalid',
    '--script-name',
    's',
    '--script-key-env',
    'SGTB_VERIFY_KEY',
]


class TestBuildSession:
    def test_default_verifies(self) -> None:
        module = _load_script()
        session = module._build_session(proxy=None, ca_bundle=None, insecure=False)
        assert session.verify is True
        assert session.proxies == {}

    def test_insecure_disables_verification(self) -> None:
        module = _load_script()
        session = module._build_session(proxy=None, ca_bundle=None, insecure=True)
        assert session.verify is False

    def test_proxy_and_ca_bundle(self) -> None:
        module = _load_script()
        session = module._build_session(
            proxy='http://proxy.example:3128', ca_bundle='/etc/corp-ca.pem', insecure=False
        )
        assert session.verify == '/etc/corp-ca.pem'
        assert session.proxies == {
            'http': 'http://proxy.example:3128',
            'https': 'http://proxy.example:3128',
        }


class TestCredentialRedirectPolicy:
    def test_rest_lifetime_disables_redirects(self) -> None:
        response = Mock(status_code=307, text='', json=Mock(return_value={}))
        session = Mock()
        session.post = Mock(return_value=response)
        module = _load_script()

        module._rest_token_expires_in(session, 'https://studio.example.com', 's', 'k')
        assert session.post.call_args.kwargs['allow_redirects'] is False

    def test_rpc_disables_redirects(self) -> None:
        response = Mock(status_code=307, text='', json=Mock(return_value={}))
        session = Mock()
        session.post = Mock(return_value=response)
        module = _load_script()

        module._rpc_get_session_token(
            session,
            'https://studio.example.com',
            {'script_name': 's', 'script_key': 'k'},
        )
        assert session.post.call_args.kwargs['allow_redirects'] is False


class TestProxySupport:
    def test_proxy_is_used(
        self,
        fake_sg: FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        del capsys
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'k')
        result = module._main(
            [
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


class TestRPCDiagnostics:
    def test_non_json_body_never_echoes_its_content(self) -> None:
        sensitive_field = 'private_token'
        sensitive_value = 'LIVE-NONJSON-SECRET'
        body = f'<html>{sensitive_field}={sensitive_value}</html>'
        response = Mock(
            status_code=502,
            text=body,
            json=Mock(side_effect=ValueError),
        )
        session = Mock()
        session.post = Mock(return_value=response)
        module = _load_script()

        with pytest.raises(RuntimeError) as excinfo:
            module._mint_session_token(session, 'https://studio.example.com', 'script', 'key')

        message = str(excinfo.value)
        assert sensitive_field not in message
        assert sensitive_value not in message
        assert body not in message
        assert 'classification: non_json' in message

    def test_unknown_json_field_never_echoes_its_name_or_value(self) -> None:
        sensitive_field = 'private_token'
        sensitive_value = 'LIVE-UNKNOWN-SECRET'
        body = {sensitive_field: sensitive_value}
        response = Mock(
            status_code=200,
            text='',
            json=Mock(return_value=body),
        )
        session = Mock()
        session.post = Mock(return_value=response)
        module = _load_script()

        token, error = module._mint_session_token(
            session, 'https://studio.example.com', 'script', 'key'
        )

        assert token is None
        assert sensitive_field not in error
        assert sensitive_value not in error
        assert str(body) not in error
        assert 'classification: no_session_id; keys present: none' in error


class TestStandaloneScript:
    def test_bad_key_is_setup_error_with_classification(
        self,
        fake_sg: FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        module = _load_script()
        fake_sg.fail_rpc = True
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'wrong')
        result = module._main(
            [
                '--site-url',
                fake_sg.url,
                '--script-name',
                's',
                '--script-key-env',
                'SGTB_VERIFY_KEY',
            ]
        )
        assert result == 2
        streams = capsys.readouterr()
        assert streams.out == ''
        assert 'Cannot authenticate' not in streams.err
        assert 'error_shape' in streams.err

    def test_diagnostics_never_echo_the_body(self, fake_sg: FakeSG) -> None:
        module = _load_script()
        fake_sg.nested_results = True
        fake_sg.rpc_results_as_list = True
        fake_sg.rpc_session_id_override = 'LIVE-SECRET'
        session = module._build_session(proxy=None, ca_bundle=None, insecure=False)
        token, error = module._mint_session_token(session, fake_sg.url, 'script', 'key')
        assert token is None
        assert 'LIVE-SECRET' not in error
        assert 'no_session_id' in error
        assert 'results' in error

    def test_disable_then_restore_reports_resurrection(
        self,
        fake_sg: FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')
        actions = [
            lambda: setattr(fake_sg, 'fail_rpc', True),
            lambda: setattr(fake_sg, 'session_revoked', True),
            lambda: setattr(fake_sg, 'session_revoked', False),
        ]

        def fake_input(prompt: str) -> str:
            del prompt
            if actions:
                actions.pop(0)()
            return ''

        monkeypatch.setattr('builtins.input', fake_input)
        result = module._main(
            [
                '--site-url',
                fake_sg.url,
                '--script-name',
                'broker_read_all',
                '--script-key-env',
                'SGTB_VERIFY_KEY',
            ]
        )
        assert result == 3
        out = capsys.readouterr().out
        assert 'WORKS AGAIN after the script is restored' in out
        assert 'unverified' in out

    def test_float_auth_code_is_inconclusive(self, fake_sg: FakeSG) -> None:
        module = _load_script()
        fake_sg.rpc_fault = True
        fake_sg.rpc_error_code_override = 102.0
        session = module._build_session(proxy=None, ca_bundle=None, insecure=False)
        with pytest.raises(RuntimeError, match='not an authentication rejection'):
            module._check_session_token(session, fake_sg.url, fake_sg.canned_session)

    def test_http_error_auth_code_is_inconclusive(self, fake_sg: FakeSG) -> None:
        module = _load_script()
        fake_sg.session_revoked = True
        fake_sg.rpc_status_override = 503
        session = module._build_session(proxy=None, ca_bundle=None, insecure=False)
        with pytest.raises(RuntimeError) as excinfo:
            module._check_session_token(session, fake_sg.url, fake_sg.canned_session)
        message = str(excinfo.value)
        assert 'HTTP 503' in message
        assert 'Session expired' not in message
        assert 'error_shape' in message

    def test_http_error_session_id_is_inconclusive(self, fake_sg: FakeSG) -> None:
        module = _load_script()
        fake_sg.rpc_status_override = 503
        session = module._build_session(proxy=None, ca_bundle=None, insecure=False)
        with pytest.raises(RuntimeError) as excinfo:
            module._check_session_token(session, fake_sg.url, fake_sg.canned_session)
        message = str(excinfo.value)
        assert 'HTTP 503' in message
        assert fake_sg.canned_session not in message
        assert 'no_session_id' in message

    def test_non_auth_fault_is_inconclusive_not_pass(
        self,
        fake_sg: FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')

        def fake_input(prompt: str) -> str:
            del prompt
            fake_sg.rpc_fault = True
            return ''

        monkeypatch.setattr('builtins.input', fake_input)
        result = module._main(
            [
                '--site-url',
                fake_sg.url,
                '--script-name',
                'broker_read_all',
                '--script-key-env',
                'SGTB_VERIFY_KEY',
            ]
        )
        assert result == 2
        captured = capsys.readouterr()
        assert captured.err.startswith(
            'error: revocation check is inconclusive: session probe was not an '
            'authentication rejection: '
        )
        assert 'Passed:' not in captured.out

    def test_nothing_revokes_exits_1(
        self,
        fake_sg: FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')

        def fake_input(prompt: str) -> str:
            del prompt
            return ''

        monkeypatch.setattr('builtins.input', fake_input)
        result = module._main(
            [
                '--site-url',
                fake_sg.url,
                '--script-name',
                'broker_read_all',
                '--script-key-env',
                'SGTB_VERIFY_KEY',
            ]
        )
        assert result == 1
        assert 'survived BOTH' in capsys.readouterr().out

    def test_remote_http_is_rejected_before_key_prompt(
        self,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        module = _load_script()

        def unexpected_prompt(prompt: str) -> str:
            raise AssertionError(f'unexpected credential prompt: {prompt}')

        monkeypatch.setattr('getpass.getpass', unexpected_prompt)
        result = module._main(
            ['--site-url', 'http://sg.studio.internal', '--script-name', 'broker_read_all']
        )
        assert result == 2
        assert 'https' in capsys.readouterr().err

    def test_remote_http_is_rejected_without_request(
        self,
        offline_sg: FakeSG,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')
        result = module._main(
            [
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

    @pytest.mark.parametrize(('status', 'expected'), [(200, 173), (403, None)])
    def test_rest_lifetime_requires_success(self, status: int, expected: int | None) -> None:
        session = Mock()
        session.post.return_value.status_code = status
        session.post.return_value.json.return_value = {'expires_in': 173}
        lifetime = _load_script()._rest_token_expires_in(
            session, 'https://studio.example.com', 's', 'k'
        )
        assert lifetime == expected

    @pytest.mark.parametrize(
        ('nested_results', 'session_id'),
        [(False, ''), (False, '  \t'), (True, ''), (True, '  \t')],
    )
    def test_blank_session_id_is_inconclusive(
        self,
        fake_sg: FakeSG,
        nested_results: bool,
        session_id: str,
    ) -> None:
        module = _load_script()
        fake_sg.nested_results = nested_results
        fake_sg.rpc_session_id_override = session_id
        session = module._build_session(proxy=None, ca_bundle=None, insecure=False)
        with pytest.raises(RuntimeError, match='session_id'):
            module._check_session_token(session, fake_sg.url, fake_sg.canned_session)

    @pytest.mark.parametrize('nested_results', [False, True])
    def test_mint_preserves_nonempty_session_id(
        self,
        fake_sg: FakeSG,
        nested_results: bool,
    ) -> None:
        module = _load_script()
        expected = '  padded-token  '
        fake_sg.nested_results = nested_results
        fake_sg.rpc_session_id_override = expected
        session = module._build_session(proxy=None, ca_bundle=None, insecure=False)
        token, error = module._mint_session_token(session, fake_sg.url, 's', 'k')
        assert token == expected
        assert error == ''

    def test_restore_instructions_survive_a_crash_after_disable(
        self,
        fake_sg: FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')
        actions = [
            lambda: setattr(fake_sg, 'fail_rpc', True),
            lambda: setattr(fake_sg, 'hard_fail', True),
        ]

        def fake_input(prompt: str) -> str:
            del prompt
            if actions:
                actions.pop(0)()
            return ''

        monkeypatch.setattr('builtins.input', fake_input)
        result = module._main(
            [
                '--site-url',
                fake_sg.url,
                '--script-name',
                'broker_read_all',
                '--script-key-env',
                'SGTB_VERIFY_KEY',
            ]
        )
        assert result == 2
        out = capsys.readouterr().out
        assert "Restore: the ApiUser 'broker_read_all'" in out
        assert "'broker_read_all'" in out

    def test_rotation_revokes(
        self,
        fake_sg: FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')

        def fake_input(prompt: str) -> str:
            del prompt
            fake_sg.fail_rpc = True
            fake_sg.session_revoked = True
            return ''

        monkeypatch.setattr('builtins.input', fake_input)
        result = module._main(
            [
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

    def test_step4_verifies_replacement(
        self,
        fake_sg: FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')
        actions = [
            lambda: setattr(fake_sg, 'fail_rpc', True),
            lambda: setattr(fake_sg, 'session_revoked', True),
            lambda: setattr(fake_sg, 'session_revoked', False),
            lambda: (
                setattr(fake_sg, 'session_revoked', True),
                setattr(fake_sg, 'fail_rpc', False),
            ),
        ]
        replies = ['', '', '', 'y']

        def fake_input(prompt: str) -> str:
            del prompt
            if actions:
                actions.pop(0)()
            return replies.pop(0) if replies else ''

        monkeypatch.setattr('builtins.input', fake_input)

        def fake_getpass(prompt: str) -> str:
            del prompt
            return 'new-replacement-key'

        monkeypatch.setattr('getpass.getpass', fake_getpass)
        result = module._main(
            [
                '--site-url',
                fake_sg.url,
                '--script-name',
                'broker_read_all',
                '--script-key-env',
                'SGTB_VERIFY_KEY',
            ]
        )
        assert result == 0
        out = capsys.readouterr().out
        assert 'dead while the renamed original stays trashed' in out
        assert 'replacement script mints under the original name' in out

    def test_unexpected_json_shape_shows_status_and_classification(
        self,
        fake_sg: FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        module = _load_script()
        fake_sg.weird_json = True
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')
        result = module._main(
            [
                '--site-url',
                fake_sg.url,
                '--script-name',
                's',
                '--script-key-env',
                'SGTB_VERIFY_KEY',
            ]
        )
        assert result == 2
        streams = capsys.readouterr()
        assert streams.out == ''
        assert 'HTTP 403' in streams.err
        assert 'blocked-by-policy' not in streams.err
        assert 'no_session_id' in streams.err


class TestStandaloneTranscript:
    @pytest.mark.parametrize(
        ('failure', 'diagnostic'),
        [
            ('mint', 'credentials rejected\x1b[31m'),
            ('fresh', 'freshly minted session token did not validate'),
        ],
    )
    def test_early_setup_failure_is_one_safe_stderr_line(
        self,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
        failure: str,
        diagnostic: str,
    ) -> None:
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')

        def mint(*_args: object) -> tuple[str | None, str]:
            return ('fresh-session', '') if failure == 'fresh' else (None, diagnostic)

        def reject_fresh(*_args: object) -> bool:
            return False

        monkeypatch.setattr(module, '_mint_session_token', mint)
        monkeypatch.setattr(module, '_check_session_token', reject_fresh)

        assert module._main(_ARGS) == 2
        streams = capsys.readouterr()
        assert streams.out == ''
        expected_clause = (
            'freshly minted session token'
            if failure == 'fresh'
            else 'could not mint a session token'
        )
        assert streams.err.startswith(f'error: {expected_clause}')
        assert len(streams.err.splitlines()) == 1
        assert diagnostic.replace('\x1b', '\\x1b') in streams.err
        assert not streams.err.rstrip('\n').endswith('.')

    def test_insecure_run_warns_on_stderr(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')
        _script_site(monkeypatch, module, [True, False])
        assert module._main([*_ARGS, '--insecure']) == 0
        assert capsys.readouterr().err == (
            'warning: TLS verification disabled; only use with a disposable script key\n'
        )

    @pytest.mark.parametrize('survives', [False, True], ids=['retired', 'survived'])
    def test_replacement_outcome(
        self,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
        *,
        survives: bool,
    ) -> None:
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')
        prompts = _script_site(monkeypatch, module, [True, True, False, True, survives])
        result = module._main(_ARGS)
        streams = capsys.readouterr()
        out = streams.out.lower()
        assert_operator_steps(prompts, 4, replacement_key=not survives)
        assert 'works again' in out
        assert 'only suspends' in out
        if survives:
            assert result == 1
            assert 'still alive' in out
            assert 'renamed and trashed' in out
            assert 'retirement procedure verified' not in out
            assert 'reassess issuing app-token session tokens' not in out
            assert_restore_reminder(out, after='still alive')
        else:
            assert result == 0
            assert REPLACEMENT_KEY not in streams.out + streams.err
            assert all(REPLACEMENT_KEY not in prompt for prompt in prompts)
            assert 'dead while the renamed original stays trashed' in out
            assert 'replacement script mints under the original name' in out
            assert_replacement_procedure(out, 'retirement procedure verified')
            assert_restore_reminder(out, after='retirement procedure verified')

    def test_sg_failure_after_the_first_mint_is_inconclusive(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')

        def unreachable(*_args: object) -> int:
            raise RuntimeError('cannot reach SG site: ConnectionError: offline')

        monkeypatch.setattr(module, '_run_test', unreachable)
        assert module._main(_ARGS) == 2
        assert capsys.readouterr().err == (
            'error: revocation check is inconclusive: cannot reach SG site: ConnectionError: '
            'offline\n'
        )

    def test_survival_advises_reassessing_app_session_tokens(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')
        prompts = _script_site(monkeypatch, module, [True, True, True])
        assert module._main(_ARGS) == 1
        fingerprint = hashlib.sha256(ISSUED_SESSION.encode()).hexdigest()[:16]
        out = capsys.readouterr().out.lower()
        assert fingerprint in out
        assert ISSUED_SESSION not in out
        assert 'rest access tokens' in out
        assert '600s' in out
        assert 'survived key rotation' in out
        assert 'survived both key rotation and apiuser disable' in out
        assert 'site session expiry' in out
        assert 'indefinite while in use' in out
        assert 'reassess issuing app-token session tokens' in out
        assert_restore_reminder(out, after='reassess issuing app-token session tokens')
        assert_operator_steps(prompts, 2)

    def test_tls_mint_transport_error_is_one_safe_stderr_line(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')

        def reject_tls(*_args: object, **_kwargs: object) -> NoReturn:
            raise requests.exceptions.SSLError('certificate verify failed\x1b[31m')

        monkeypatch.setattr(requests.Session, 'post', reject_tls)
        assert module._main(_ARGS) == 2
        streams = capsys.readouterr()
        assert streams.out == ''
        assert streams.err.startswith(
            'error: revocation check is inconclusive: cannot reach SG site: SSLError: '
        )
        assert len(streams.err.splitlines()) == 1
        assert 'certificate verify failed\\x1b[31m' in streams.err
        assert '\x1b' not in streams.err
        assert 'corporate CA' in streams.err
        assert '--ca-bundle' in streams.err
        assert 'REQUESTS_CA_BUNDLE' in streams.err
        assert '--insecure' in streams.err
        assert not streams.err.rstrip('\n').endswith('.')


def _load_script() -> ModuleType:
    return _load_path(_SCRIPT_PATH)


def _script_site(
    monkeypatch: pytest.MonkeyPatch, module: ModuleType, alive: list[bool]
) -> list[str]:
    checks = list(alive)
    mints: list[str] = []
    prompts: list[str] = []

    def mint(
        _session: object, _site_url: str, _script_name: str, script_key: str
    ) -> tuple[str | None, str]:
        mints.append(script_key)
        if len(mints) == 1 or script_key == REPLACEMENT_KEY:
            return ISSUED_SESSION, ''
        return None, 'SG error (HTTP 200); classification: error_shape; keys present: exception'

    def check(_session: object, _site_url: str, token: str) -> bool:
        assert token == ISSUED_SESSION
        return checks.pop(0)

    def expires(*_args: object) -> int:
        return 600

    def answer(prompt: str) -> str:
        prompts.append(prompt)
        return 'y' if 'replacement' in prompt.lower() else ''

    def replacement_key(prompt: str) -> str:
        prompts.append(prompt)
        return REPLACEMENT_KEY

    monkeypatch.setattr(module, '_mint_session_token', mint)
    monkeypatch.setattr(module, '_check_session_token', check)
    monkeypatch.setattr(module, '_rest_token_expires_in', expires)
    monkeypatch.setattr('builtins.input', answer)
    monkeypatch.setattr('getpass.getpass', replacement_key)
    return prompts


def test_missing_ca_bundle_argument_is_a_usage_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_script()
    missing = tmp_path / 'missing-ca.pem'
    monkeypatch.setenv('SGTB_VERIFY_KEY', 'key')
    monkeypatch.setattr(
        'urllib3.connection.HTTPSConnection.connect',
        Mock(side_effect=AssertionError('unexpected connection')),
    )
    with pytest.raises(SystemExit) as caught:
        module._main([*_ARGS, '--ca-bundle', str(missing)])
    assert caught.value.code == 2
    assert f'no readable CA bundle at {missing}' in capsys.readouterr().err


def test_missing_ca_bundle_environment_exits_two(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / 'missing-ca.pem'
    monkeypatch.setenv('REQUESTS_CA_BUNDLE', str(missing))
    monkeypatch.setenv('SGTB_VERIFY_KEY', 'key')
    monkeypatch.setattr(
        'urllib3.connection.HTTPSConnection.connect',
        Mock(side_effect=AssertionError('unexpected connection')),
    )
    assert _load_script()._main(_ARGS) == 2
    assert 'cannot send the SG request: ' in capsys.readouterr().err


@pytest.mark.parametrize('site', ['rpc', 'rest'])
def test_missing_ca_bundle_is_a_setup_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, site: str
) -> None:
    module = _load_script()
    missing = tmp_path / 'missing-ca.pem'
    monkeypatch.setenv('REQUESTS_CA_BUNDLE', str(missing))
    monkeypatch.setattr(
        'urllib3.connection.HTTPSConnection.connect',
        Mock(side_effect=AssertionError('unexpected connection')),
    )
    with requests.Session() as session:
        send = (
            partial(module._rpc_get_session_token, session, 'https://127.0.0.1:1', {})
            if site == 'rpc'
            else partial(module._rest_token_expires_in, session, 'https://127.0.0.1:1', 's', 'k')
        )
        with pytest.raises(RuntimeError) as caught:
            send()
    assert isinstance(caught.value.__cause__, OSError)
    assert not isinstance(caught.value.__cause__, requests.RequestException)
    assert str(caught.value) == 'cannot send the SG request: ' + str(caught.value.__cause__)
    assert str(missing) in str(caught.value)


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
    module = _load_script()
    if kind == 'readable':
        assert module._readable_ca_bundle(str(bundle)) == str(bundle)
    else:
        with pytest.raises(argparse.ArgumentTypeError) as caught:
            module._readable_ca_bundle(str(bundle))
        assert str(caught.value) == f'no readable CA bundle at {bundle}'
