import hashlib
from pathlib import Path
from types import ModuleType
from typing import NoReturn
from unittest.mock import Mock

import pytest
import requests

from tests.conftest import _FakeSG
from tests.scripts._helpers import load_script as _load_path

SCRIPT_PATH = Path(__file__).parents[2] / 'scripts' / 'verify_sg_revocation.py'
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

    def test_insecure_flow_against_fake(
        self,
        fake_sg: _FakeSG,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')

        def fake_input(prompt: str) -> str:
            del prompt
            fake_sg._fail_rpc = True
            fake_sg._session_revoked = True
            return ''

        monkeypatch.setattr('builtins.input', fake_input)
        result = module.main(
            [
                '--site-url',
                fake_sg._url,
                '--script-name',
                'broker_read_all',
                '--script-key-env',
                'SGTB_VERIFY_KEY',
                '--insecure',
            ]
        )
        assert result == 0

    def test_proxy_and_ca_bundle(self) -> None:
        module = _load_script()
        session = module._build_session(
            proxy='http://squid:8080', ca_bundle='/etc/corp-ca.pem', insecure=False
        )
        assert session.verify == '/etc/corp-ca.pem'
        assert session.proxies == {'http': 'http://squid:8080', 'https': 'http://squid:8080'}


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
        fake_sg: _FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        del capsys
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'k')
        result = module.main(
            [
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
        fake_sg: _FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        module = _load_script()
        fake_sg._fail_rpc = True
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'wrong')
        result = module.main(
            [
                '--site-url',
                fake_sg._url,
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

    @pytest.mark.parametrize(
        ('nested_results', 'session_id'),
        [(False, ''), (False, '  \t'), (True, ''), (True, '  \t')],
    )
    def test_blank_session_id_is_inconclusive(
        self,
        fake_sg: _FakeSG,
        nested_results: bool,
        session_id: str,
    ) -> None:
        module = _load_script()
        fake_sg._nested_results = nested_results
        fake_sg._rpc_session_id_override = session_id
        session = module._build_session(proxy=None, ca_bundle=None, insecure=False)
        with pytest.raises(RuntimeError, match='session_id'):
            module._check_session_token(session, fake_sg._url, fake_sg._canned_session)

    def test_diagnostics_never_echo_the_body(self, fake_sg: _FakeSG) -> None:
        module = _load_script()
        fake_sg._nested_results = True
        fake_sg._rpc_results_as_list = True
        fake_sg._rpc_session_id_override = 'LIVE-SECRET'
        session = module._build_session(proxy=None, ca_bundle=None, insecure=False)
        token, error = module._mint_session_token(session, fake_sg._url, 'script', 'key')
        assert token is None
        assert 'LIVE-SECRET' not in error
        assert 'no_session_id' in error
        assert 'results' in error

    def test_disable_then_restore_reports_resurrection(
        self,
        fake_sg: _FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')
        actions = [
            lambda: setattr(fake_sg, '_fail_rpc', True),
            lambda: setattr(fake_sg, '_session_revoked', True),
            lambda: setattr(fake_sg, '_session_revoked', False),
        ]

        def fake_input(prompt: str) -> str:
            del prompt
            if actions:
                actions.pop(0)()
            return ''

        monkeypatch.setattr('builtins.input', fake_input)
        result = module.main(
            [
                '--site-url',
                fake_sg._url,
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

    def test_float_auth_code_is_inconclusive(self, fake_sg: _FakeSG) -> None:
        module = _load_script()
        fake_sg._rpc_fault = True
        fake_sg._rpc_error_code_override = 102.0
        session = module._build_session(proxy=None, ca_bundle=None, insecure=False)
        with pytest.raises(RuntimeError, match='not an authentication rejection'):
            module._check_session_token(session, fake_sg._url, fake_sg._canned_session)

    def test_http_error_auth_code_is_inconclusive(self, fake_sg: _FakeSG) -> None:
        module = _load_script()
        fake_sg._session_revoked = True
        fake_sg._rpc_status_override = 503
        session = module._build_session(proxy=None, ca_bundle=None, insecure=False)
        with pytest.raises(RuntimeError) as excinfo:
            module._check_session_token(session, fake_sg._url, fake_sg._canned_session)
        message = str(excinfo.value)
        assert 'HTTP 503' in message
        assert 'Session expired' not in message
        assert 'error_shape' in message

    def test_http_error_session_id_is_inconclusive(self, fake_sg: _FakeSG) -> None:
        module = _load_script()
        fake_sg._rpc_status_override = 503
        session = module._build_session(proxy=None, ca_bundle=None, insecure=False)
        with pytest.raises(RuntimeError) as excinfo:
            module._check_session_token(session, fake_sg._url, fake_sg._canned_session)
        message = str(excinfo.value)
        assert 'HTTP 503' in message
        assert fake_sg._canned_session not in message
        assert 'no_session_id' in message

    @pytest.mark.parametrize('nested_results', [False, True])
    def test_mint_preserves_nonempty_session_id(
        self,
        fake_sg: _FakeSG,
        nested_results: bool,
    ) -> None:
        module = _load_script()
        expected = '  padded-token  '
        fake_sg._nested_results = nested_results
        fake_sg._rpc_session_id_override = expected
        session = module._build_session(proxy=None, ca_bundle=None, insecure=False)
        token, error = module._mint_session_token(session, fake_sg._url, 's', 'k')
        assert token == expected
        assert error == ''

    def test_non_auth_fault_is_inconclusive_not_pass(
        self,
        fake_sg: _FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')

        def fake_input(prompt: str) -> str:
            del prompt
            fake_sg._rpc_fault = True
            return ''

        monkeypatch.setattr('builtins.input', fake_input)
        result = module.main(
            [
                '--site-url',
                fake_sg._url,
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
        fake_sg: _FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')

        def fake_input(prompt: str) -> str:
            del prompt
            return ''

        monkeypatch.setattr('builtins.input', fake_input)
        result = module.main(
            [
                '--site-url',
                fake_sg._url,
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
        result = module.main(
            ['--site-url', 'http://sg.studio.internal', '--script-name', 'broker_read_all']
        )
        assert result == 2
        assert 'https' in capsys.readouterr().err

    def test_remote_http_is_rejected_without_request(
        self,
        fake_sg: _FakeSG,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')
        result = module.main(
            [
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

    def test_restore_instructions_survive_a_crash_after_disable(
        self,
        fake_sg: _FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')
        actions = [
            lambda: setattr(fake_sg, '_fail_rpc', True),
            lambda: setattr(fake_sg, '_hard_fail', True),
        ]

        def fake_input(prompt: str) -> str:
            del prompt
            if actions:
                actions.pop(0)()
            return ''

        monkeypatch.setattr('builtins.input', fake_input)
        result = module.main(
            [
                '--site-url',
                fake_sg._url,
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
        fake_sg: _FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')

        def fake_input(prompt: str) -> str:
            del prompt
            fake_sg._fail_rpc = True
            fake_sg._session_revoked = True
            return ''

        monkeypatch.setattr('builtins.input', fake_input)
        result = module.main(
            [
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

    def test_step4_verifies_replacement(
        self,
        fake_sg: _FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')
        actions = [
            lambda: setattr(fake_sg, '_fail_rpc', True),
            lambda: setattr(fake_sg, '_session_revoked', True),
            lambda: setattr(fake_sg, '_session_revoked', False),
            lambda: (
                setattr(fake_sg, '_session_revoked', True),
                setattr(fake_sg, '_fail_rpc', False),
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
        result = module.main(
            [
                '--site-url',
                fake_sg._url,
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
        fake_sg: _FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        module = _load_script()
        fake_sg._weird_json = True
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')
        result = module.main(
            [
                '--site-url',
                fake_sg._url,
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

        assert module.main(_ARGS) == 2
        streams = capsys.readouterr()
        assert streams.out == ''
        expected_clause = (
            'freshly minted session token'
            if failure == 'fresh'
            else 'sg rejected the script credentials'
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
        assert module.main([*_ARGS, '--insecure']) == 0
        assert capsys.readouterr().err == (
            'warning: TLS verification disabled; only use with a disposable script key\n'
        )

    def test_sg_failure_after_the_first_mint_is_inconclusive(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')

        def unreachable(*_args: object) -> int:
            raise RuntimeError('cannot reach SG site: ConnectionError: offline')

        monkeypatch.setattr(module, '_run_test', unreachable)
        assert module.main(_ARGS) == 2
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
        assert module.main(_ARGS) == 1
        fingerprint = hashlib.sha256(b'live-session').hexdigest()[:16]
        assert capsys.readouterr().out.splitlines() == [
            f'Minted a live session token (fingerprint {fingerprint}).',
            'Note: REST access tokens on this site expire in 600s (site pref).',
            'Result: the outstanding session token SURVIVED key rotation.',
            'Failed: the session token survived BOTH key rotation and ApiUser disable.',
            (
                'Outstanding tokens can only age out via the site session expiry (sliding - '
                'indefinite while in use). Reassess issuing app-token session tokens on this site.'
            ),
            (
                "Restore: the ApiUser 's' may still be disabled or trashed - restore it "
                '(SG Admin > Scripts) unless you intend to leave it retired.'
            ),
        ]
        assert prompts == [
            (
                "Step 1: In SG Admin > Scripts, regenerate the application key for 's', "
                'then press Enter... '
            ),
            "Step 2: Now disable/trash the ApiUser 's' (SG Admin > Scripts), then press Enter... ",
        ]

    def test_tls_mint_transport_error_is_one_safe_stderr_line(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')

        def reject_tls(*_args: object, **_kwargs: object) -> NoReturn:
            raise requests.exceptions.SSLError('certificate verify failed\x1b[31m')

        monkeypatch.setattr(requests.Session, 'post', reject_tls)
        assert module.main(_ARGS) == 2
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

    def test_verified_replacement_names_the_full_procedure(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')
        prompts = _script_site(monkeypatch, module, [True, True, False, True, False])
        assert module.main(_ARGS) == 0
        assert capsys.readouterr().out.splitlines()[-6:] == [
            'Caution: the old session token WORKS AGAIN after the script is restored.',
            'Disabling only suspends tokens; it does not retire them.',
            'Passed: the old token is dead while the renamed original stays trashed.',
            'Passed: the replacement script mints under the original name.',
            (
                'Retirement procedure verified: rotate the key, rename the script, trash it '
                'permanently; replace it with a new script reusing the original name.'
            ),
            (
                "Restore: the ApiUser 's' may still be disabled or trashed - restore it "
                '(SG Admin > Scripts) unless you intend to leave it retired.'
            ),
        ]
        assert prompts[2:] == [
            "Step 3: Now restore/re-enable the ApiUser 's', then press Enter... ",
            (
                'Step 4 (optional): verify the replacement retirement procedure: rotate the key, '
                'RENAME this script (e.g. s-retired), trash it, then create a NEW script with the '
                "ORIGINAL name 's' and a fresh key. Type y + Enter when done (anything else to "
                'skip)... '
            ),
        ]


class TestURLPolicy:
    @pytest.mark.parametrize(
        'url',
        [
            'https://studio.example',
            'http://localhost:8080',
            'http://127.0.0.1:8080',
            'http://[::1]:8080',
        ],
    )
    def test_accepts_https_and_loopback_http(self, url: str) -> None:
        validator = _load_script()._require_https_or_loopback
        assert validator(url) == url

    @pytest.mark.parametrize(
        'url',
        [
            'http://sg.studio.internal',
            'http://evil.example\\@localhost',
            '\x00https://studio.example',
            ' https://studio.example',
            'https://studio.example/path with space',
            'https://studio.example:notaport',
            'https://studio.example:65536',
            'http://10.1.2.3',
            'ftp://studio.example',
            'https://',
            'not-a-url',
        ],
    )
    def test_rejects_unsafe_or_malformed_urls(self, url: str) -> None:
        validator = _load_script()._require_https_or_loopback
        with pytest.raises(ValueError, match='site URL'):
            validator(url)


def _load_script() -> ModuleType:
    return _load_path(SCRIPT_PATH)


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
        if len(mints) == 1 or script_key == 'replacement-key':
            return 'live-session', ''
        return None, 'SG error (HTTP 200); classification: error_shape; keys present: exception'

    def check(_session: object, _site_url: str, _token: str) -> bool:
        return checks.pop(0)

    def expires(*_args: object) -> int:
        return 600

    def answer(prompt: str) -> str:
        prompts.append(prompt)
        return 'y' if prompt.startswith('Step 4') else ''

    def replacement_key(_prompt: str) -> str:
        return 'replacement-key'

    monkeypatch.setattr(module, '_mint_session_token', mint)
    monkeypatch.setattr(module, '_check_session_token', check)
    monkeypatch.setattr(module, '_rest_token_expires_in', expires)
    monkeypatch.setattr('builtins.input', answer)
    monkeypatch.setattr('getpass.getpass', replacement_key)
    return prompts
