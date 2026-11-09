import argparse
from collections.abc import Callable
from functools import partial
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock

import pytest
import requests

from tests.conftest import FakeSG
from tests.scripts._helpers import load_script as _load_path

_SCRIPT_PATH = Path(__file__).parents[2] / 'scripts' / 'verify_sg_sudo.py'


class TestCredentialRedirectPolicy:
    def test_project_query_disables_redirects(
        self, fake_sg: FakeSG, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = _load_script()
        session = module._build_session(proxy=None, ca_bundle=None, insecure=False)
        recorder = Mock(wraps=session.get)
        monkeypatch.setattr(session, 'get', recorder)

        assert module._count_projects(session, fake_sg.url, 'bearer') == (5, 200)
        assert recorder.call_args.kwargs['allow_redirects'] is False

    def test_rest_mint_disables_redirects(self) -> None:
        response = Mock(status_code=307, text='', json=Mock(return_value={}))
        session = Mock()
        session.post = Mock(return_value=response)
        module = _load_script()

        module._mint_rest_token(session, 'https://studio.example.com', 's', 'k', None)
        assert session.post.call_args.kwargs['allow_redirects'] is False


def _load_script() -> ModuleType:
    return _load_path(_SCRIPT_PATH)


def _run(
    fake_sg: FakeSG,
    monkeypatch: pytest.MonkeyPatch,
    actions: list[object],
    clock: Callable[[], float] | None = None,
) -> int:
    module = _load_script()
    monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')
    queue = list(actions)

    def fake_input(prompt: str) -> str:
        del prompt
        if queue:
            action = queue.pop(0)
            if callable(action):
                action()
        return ''

    monkeypatch.setattr('builtins.input', fake_input)
    return module._main(
        [
            '--site-url',
            fake_sg.url,
            '--script-name',
            'sudo_capable',
            '--script-key-env',
            'SGTB_VERIFY_KEY',
            '--sudo-login',
            'tuser',
        ],
        clock=clock,
    )


class TestSudoScript:
    def test_baseline_query_failure_is_inconclusive(
        self,
        fake_sg: FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fake_sg.dead_bearers.append(fake_sg.canned_rest)
        result = _run(fake_sg, monkeypatch, [lambda: None, lambda: None])
        assert result == 0
        out = capsys.readouterr().out
        assert 'baseline plain-token project query failed' in out
        assert 'permissions follow the user' not in out

    def test_bogus_login_5xx_is_inconclusive(
        self,
        fake_sg: FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fake_sg.bogus_sudo_failure_status = 503
        result = _run(fake_sg, monkeypatch, [lambda: None, lambda: None])
        assert result == 0
        out = capsys.readouterr().out
        assert 'Inconclusive: the bogus-login mint failed with HTTP 503' in out
        assert 'bogus login was rejected at mint time' not in out

    def test_disabled_probe_5xx_is_inconclusive(
        self,
        fake_sg: FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def disable_user() -> None:
            fake_sg.disabled_login = 'tuser'
            fake_sg.fail_entities_status = 500

        def enable_user() -> None:
            fake_sg.disabled_login = ''
            fake_sg.fail_entities_status = 0

        result = _run(fake_sg, monkeypatch, [disable_user, enable_user])
        assert result == 3
        out = capsys.readouterr().out
        assert 'Inconclusive: the sudo-token project query failed with HTTP 500' in out
        assert 'outstanding sudo token died' not in out

    def test_equal_counts_reported_inconclusive(
        self,
        fake_sg: FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fake_sg.sudo_project_count = 5
        result = _run(fake_sg, monkeypatch, [lambda: None, lambda: None])
        del result
        assert 'Inconclusive: the project counts match' in capsys.readouterr().out

    def test_expired_token_rejection_is_inconclusive(
        self,
        fake_sg: FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fake_sg.rest_expires_in = 600
        now = [0.0]

        def disable_user() -> None:
            fake_sg.disabled_login = 'tuser'
            fake_sg.dead_bearers.append('rest-sudo_as_login:tuser')
            now[0] = 700.0

        result = _run(
            fake_sg,
            monkeypatch,
            [disable_user, lambda: None],
            clock=lambda: now[0],
        )
        out = capsys.readouterr().out
        assert result == 3
        assert 'Inconclusive: the sudo token was rejected' in out
        assert 'elapsed 700s of a 600s lifetime' in out

    def test_full_flow_token_dies_on_disable(
        self,
        fake_sg: FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def disable_user() -> None:
            fake_sg.disabled_login = 'tuser'
            fake_sg.dead_bearers.append('rest-sudo_as_login:tuser')

        def enable_user() -> None:
            fake_sg.disabled_login = ''

        result = _run(fake_sg, monkeypatch, [disable_user, enable_user])
        assert result == 0
        out = capsys.readouterr().out
        assert 'sudo_as_login:tuser' in fake_sg.rest_scopes
        assert 'plain token sees 5 project(s); sudo token sees 2' in out
        assert 'permissions follow the user' in out
        assert 'bogus login was rejected at mint' in out
        assert 'new sudo mints for the disabled user are rejected' in out
        assert 'outstanding sudo token died when the user was disabled' in out

    def test_insecure_run_warns_on_stderr(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = _load_script()
        monkeypatch.setenv('SGTB_VERIFY_KEY', 'masterkey')

        def finished(_context: object) -> int:
            return 0

        monkeypatch.setattr(module, '_run_survey', finished)
        result = module._main(
            [
                '--site-url',
                'https://sg.example.invalid',
                '--script-name',
                'sudo_capable',
                '--script-key-env',
                'SGTB_VERIFY_KEY',
                '--sudo-login',
                'tuser',
                '--insecure',
            ]
        )
        assert result == 0
        assert capsys.readouterr().err == (
            'warning: TLS verification disabled; only use with a disposable script key\n'
        )

    def test_non_json_project_failure_preserves_status(self, fake_sg: FakeSG) -> None:
        fake_sg.fail_entities_status = 403
        fake_sg.entities_non_json = True
        module = _load_script()
        session = module._build_session(proxy=None, ca_bundle=None, insecure=False)

        assert module._count_projects(session, fake_sg.url, 'bearer') == (None, 403)

    def test_non_json_rest_failure_preserves_status(self, fake_sg: FakeSG) -> None:
        fake_sg.fail_rest = True
        fake_sg.rest_failure_status = 403
        fake_sg.rest_non_json = True
        module = _load_script()
        session = module._build_session(proxy=None, ca_bundle=None, insecure=False)

        assert module._mint_rest_token(session, fake_sg.url, 'script', 'key', None) == (
            None,
            0,
            403,
            'HTTP 403: non-JSON body',
        )

    @pytest.mark.parametrize('status', [400, 401, 403])
    def test_reenabled_probe_auth_rejection_reports_remains_dead(
        self,
        fake_sg: FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
        status: int,
    ) -> None:
        def disable_user() -> None:
            fake_sg.disabled_login = 'tuser'
            fake_sg.dead_bearers.append('rest-sudo_as_login:tuser')

        def enable_user() -> None:
            fake_sg.disabled_login = ''
            fake_sg.fail_entities_status = status

        result = _run(fake_sg, monkeypatch, [disable_user, enable_user])
        assert result == 0
        out = capsys.readouterr().out
        assert 'after re-enabling the user, the outstanding sudo token remains dead' in out

    def test_reenabled_probe_malformed_200_is_inconclusive(
        self,
        fake_sg: FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def disable_user() -> None:
            fake_sg.disabled_login = 'tuser'
            fake_sg.dead_bearers.append('rest-sudo_as_login:tuser')

        def enable_user() -> None:
            fake_sg.disabled_login = ''
            fake_sg.fail_entities_status = 200

        result = _run(fake_sg, monkeypatch, [disable_user, enable_user])
        assert result == 0
        out = capsys.readouterr().out
        assert (
            'Inconclusive: after re-enabling the user, the sudo-token project query failed '
            'with HTTP 200' in out
        )
        assert 'after re-enabling the user, the outstanding sudo token remains dead' not in out

    def test_reenabled_probe_server_error_is_inconclusive(
        self,
        fake_sg: FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def disable_user() -> None:
            fake_sg.disabled_login = 'tuser'
            fake_sg.dead_bearers.append('rest-sudo_as_login:tuser')

        def enable_user() -> None:
            fake_sg.disabled_login = ''
            fake_sg.fail_entities_status = 503

        result = _run(fake_sg, monkeypatch, [disable_user, enable_user])
        assert result == 0
        out = capsys.readouterr().out
        assert (
            'Inconclusive: after re-enabling the user, the sudo-token project query failed '
            'with HTTP 503' in out
        )
        assert 'after re-enabling the user, the outstanding sudo token remains dead' not in out

    def test_remint_5xx_is_inconclusive(
        self,
        fake_sg: FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def break_mints() -> None:
            fake_sg.fail_rest = True
            fake_sg.rest_failure_status = 503

        def restore_mints() -> None:
            fake_sg.fail_rest = False

        result = _run(fake_sg, monkeypatch, [break_mints, restore_mints])
        assert result == 0
        out = capsys.readouterr().out
        assert 'Inconclusive: the sudo remint failed with HTTP 503' in out
        assert 'new sudo mints for the disabled user are rejected' not in out

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
            [
                '--site-url',
                'http://sg.studio.internal',
                '--script-name',
                'sudo_capable',
                '--sudo-login',
                'tuser',
            ]
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
                'sudo_capable',
                '--script-key-env',
                'SGTB_VERIFY_KEY',
                '--sudo-login',
                'tuser',
                '--proxy',
                offline_sg.url,
            ]
        )
        assert result == 2

    def test_restore_instructions_survive_a_crash_after_disable(
        self,
        fake_sg: FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def break_site() -> None:
            fake_sg.hard_fail = True

        result = _run(fake_sg, monkeypatch, [break_site])
        assert result == 2
        out = capsys.readouterr().out
        assert "Restore: make sure the test user 'tuser'" in out

    def test_string_error_element_is_rendered_without_assuming_a_mapping(self) -> None:
        module = _load_script()
        first_error = module.__dict__['_first_error']

        assert first_error({'errors': ['plain provider error']}) == 'plain provider error'
        assert first_error({'errors': [{'detail': 'mapped provider error'}]}) == (
            'mapped provider error'
        )

    def test_sudo_mint_rejected_is_setup_error(
        self,
        fake_sg: FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fake_sg.disabled_login = 'tuser'
        result = _run(fake_sg, monkeypatch, [])
        assert result == 2
        assert 'sudo permission' in capsys.readouterr().out

    def test_token_survival_reports_minted_lifetime(
        self,
        fake_sg: FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fake_sg.rest_expires_in = 3600

        def disable_user() -> None:
            fake_sg.disabled_login = 'tuser'

        result = _run(fake_sg, monkeypatch, [disable_user, lambda: None])
        assert result == 0
        assert '(3600s here)' in capsys.readouterr().out

    def test_token_survives_disable_reported(
        self,
        fake_sg: FakeSG,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def disable_user() -> None:
            fake_sg.disabled_login = 'tuser'

        result = _run(fake_sg, monkeypatch, [disable_user, lambda: None])
        assert result == 0
        out = capsys.readouterr().out
        assert 'outstanding sudo token STILL WORKS with the user disabled' in out
        assert 'after re-enabling the user, the outstanding sudo token works again' in out
        assert 'bounded by the token lifetime (600s here)' in out


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
        module._main(
            [
                '--site-url',
                'https://127.0.0.1:1',
                '--script-name',
                's',
                '--script-key-env',
                'SGTB_VERIFY_KEY',
                '--sudo-login',
                'test',
                '--ca-bundle',
                str(missing),
            ]
        )
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
    assert (
        _load_script()._main(
            [
                '--site-url',
                'https://127.0.0.1:1',
                '--script-name',
                's',
                '--script-key-env',
                'SGTB_VERIFY_KEY',
                '--sudo-login',
                'test',
            ]
        )
        == 2
    )
    assert 'cannot send the SG request: ' in capsys.readouterr().err


@pytest.mark.parametrize('site', ['query', 'rest'])
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
            partial(module._count_projects, session, 'https://127.0.0.1:1', 'bearer')
            if site == 'query'
            else partial(module._mint_rest_token, session, 'https://127.0.0.1:1', 's', 'k', None)
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
