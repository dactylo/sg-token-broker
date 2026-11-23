from collections.abc import Callable
from unittest.mock import Mock
from urllib.parse import quote_plus

import pytest

from sg_token_broker import _verify
from sg_token_broker._sg import MintedToken, SGError, SGMinter
from sg_token_broker._verify import run_revocation_check
from tests._revocation import (
    ISSUED_SESSION,
    REPLACEMENT_KEY,
    assert_operator_steps,
    assert_replacement_procedure,
    assert_restore_reminder,
)
from tests._timeouts import STALL_TIMEOUT_SECONDS
from tests.conftest import FakeSG

# Documented exit codes of `sg-token-broker verify-revocation`.
_EXIT_NOT_REVOKED = 1
_EXIT_REVOKED = 0


class TestRunRevocationCheck:
    def test_bad_key_is_setup_error(self, fake_sg: FakeSG) -> None:
        fake_sg.fail_rpc = True
        io = _ScriptedIO([])
        with pytest.raises(_verify.VerifySetupError, match='could not mint a session token'):
            _run(fake_sg, io)
        assert io.lines == []

    def test_restore_instructions_survive_a_crash_after_disable(self, fake_sg: FakeSG) -> None:
        def rotate_only() -> None:
            fake_sg.fail_rpc = True

        def break_site() -> None:
            fake_sg.hard_fail = True

        io = _ScriptedIO([rotate_only, break_site])
        with pytest.raises(SGError):
            _run(fake_sg, io)
        assert "Restore: the ApiUser 'broker_read_all'" in io.text()

    def test_step4_verifies_replacement_procedure(self, fake_sg: FakeSG) -> None:
        def rotate_only() -> None:
            fake_sg.fail_rpc = True

        def disable() -> None:
            fake_sg.session_revoked = True

        def restore() -> None:
            fake_sg.session_revoked = False

        def replace() -> None:
            fake_sg.session_revoked = True
            fake_sg.fail_rpc = False

        io = _ScriptedIO(
            [rotate_only, disable, restore, replace],
            replies=['', '', '', 'y'],
            key_reply='new-replacement-key',
        )
        assert _run(fake_sg, io) == _EXIT_REVOKED
        out = io.text()
        assert 'dead while the renamed original stays trashed' in out
        assert 'replacement script mints under the original name' in out


class TestSSLHint:
    def test_ssl_error_gets_interception_hint(self) -> None:
        class SSLFailingMinter:
            def mint_session_token(self, script_name: str, script_key: str) -> MintedToken:
                del script_name, script_key
                raise SGError('SG request to /api3/json failed: SSLError')

            def mint_rest_token(self, script_name: str, script_key: str) -> MintedToken:
                del script_name, script_key
                raise SGError('SG request failed: SSLError')

            def check_session_token(self, session_token: str) -> bool:
                del session_token
                return False

        io = _ScriptedIO([])
        with pytest.raises(_verify.VerifySetupError) as raised:
            run_revocation_check(SSLFailingMinter(), 's', 'k', io)
        assert str(raised.value).startswith('could not mint a session token:')
        assert 'corporate CA' in str(raised.value)
        assert io.lines == []


class TestWalkthrough:
    def test_disable_that_stays_effective_after_restore(self) -> None:
        io = _ScriptedIO([])
        assert _run_scripted(_ScriptedMinter([True, True, False, False]), io) == _EXIT_REVOKED
        assert_operator_steps(io.prompts, 3)
        out = io.text().lower()
        assert '67bf8c20b2162328' in out
        assert ISSUED_SESSION not in out
        assert 'rest access tokens' in out
        assert '600s' in out
        assert 'survived key rotation' in out
        assert 'rotation alone cannot retire' in out
        assert 'disabling the apiuser revoked' in out
        assert 'stay dead' in out
        advice = out.split('retirement procedure')[1]
        assert advice.index('rotate') < advice.index('trash') < advice.index('then restore')
        assert_restore_reminder(out, after='retirement procedure for a leaked scope')

    @pytest.mark.parametrize('survives', [False, True], ids=['retired', 'survived'])
    def test_replacement_outcome(self, *, survives: bool) -> None:
        io = _ScriptedIO([], replies=['', '', '', 'y'], key_reply=REPLACEMENT_KEY)
        minter = _ScriptedMinter([True, True, False, True, survives])
        result = _run_scripted(minter, io)
        assert_operator_steps(io.prompts, 4, replacement_key=not survives)
        out = io.text().lower()
        if survives:
            assert result == _EXIT_NOT_REVOKED
            assert 'still alive' in out
            assert 'renamed and trashed' in out
            assert 'retirement procedure verified' not in out
            assert 'reassess issuing app-token session tokens' not in out
            assert_restore_reminder(out, after='still alive')
        else:
            assert result == _EXIT_REVOKED
            assert REPLACEMENT_KEY not in io.text()
            assert 'dead while the renamed original stays trashed' in out
            assert 'replacement script mints under the original name' in out
            assert_replacement_procedure(out, 'retirement procedure verified')
            assert_restore_reminder(out, after='retirement procedure verified')

    def test_rotation_names_the_retirement_procedure(self) -> None:
        io = _ScriptedIO([])
        minter = _ScriptedMinter([True, False], old_key_still_mints=True)
        assert _run_scripted(minter, io) == _EXIT_REVOKED
        assert_operator_steps(io.prompts, 1)
        out = io.text().lower()
        assert 'old key still mints' in out
        assert 'key rotation immediately revoked' in out
        assert 'rotate its application key' in out

    def test_skipped_replacement_is_unverified(self) -> None:
        io = _ScriptedIO([])
        assert _run_scripted(_ScriptedMinter([True, True, False, True]), io) == 3
        assert_operator_steps(io.prompts, 4)
        out = io.text().lower()
        assert 'works again' in out
        assert 'only suspends' in out
        assert_replacement_procedure(out, 'rename step unverified')
        assert_restore_reminder(out, after='rename step unverified')

    def test_survival_advises_reassessing_app_session_tokens(self) -> None:
        io = _ScriptedIO([])
        assert _run_scripted(_ScriptedMinter([True, True, True]), io) == _EXIT_NOT_REVOKED
        assert_operator_steps(io.prompts, 2)
        out = io.text().lower()
        assert 'survived both key rotation and apiuser disable' in out
        assert 'site session expiry' in out
        assert 'indefinite while in use' in out
        assert 'reassess issuing app-token session tokens' in out
        assert_restore_reminder(out, after='reassess issuing app-token session tokens')

    def test_token_that_fails_to_validate_is_a_setup_failure(self) -> None:
        io = _ScriptedIO([])
        with pytest.raises(_verify.VerifySetupError, match='freshly minted session token'):
            _run_scripted(_ScriptedMinter([False]), io)
        assert io.lines == []


class _ScriptedIO:
    def __init__(
        self,
        actions: list[Callable[[], None]],
        replies: list[str] | None = None,
        key_reply: str = '',
    ) -> None:
        self._actions = list(actions)
        self._replies = list(replies or [])
        self._key_reply = key_reply
        self.lines: list[str] = []
        self.prompts: list[str] = []

    def ask(self, message: str) -> str:
        self.prompts.append(message)
        self.lines.append(message)
        if self._actions:
            self._actions.pop(0)()
        return self._replies.pop(0) if self._replies else ''

    def ask_secret(self, message: str) -> str:
        self.prompts.append(message)
        self.lines.append(message)
        return self._key_reply

    def say(self, message: str) -> None:
        self.lines.append(message)

    def text(self) -> str:
        return '\n'.join(self.lines)


class _ScriptedMinter:
    def __init__(self, alive: list[bool], *, old_key_still_mints: bool = False) -> None:
        self._alive = list(alive)
        self._old_key_still_mints = old_key_still_mints
        self._session_mints = 0

    def check_session_token(self, session_token: str) -> bool:
        assert session_token == ISSUED_SESSION
        return self._alive.pop(0)

    def mint_rest_token(self, script_name: str, script_key: str) -> MintedToken:
        del script_name, script_key
        return MintedToken('rest-token', 600)

    def mint_session_token(self, script_name: str, script_key: str) -> MintedToken:
        del script_name
        self._session_mints += 1
        if self._session_mints == 1 or self._old_key_still_mints or script_key == REPLACEMENT_KEY:
            return MintedToken(ISSUED_SESSION, None)
        raise SGError('SG rejected authentication', status_code=200, error_code=102)


def _run(fake_sg: FakeSG, io: _ScriptedIO) -> int:
    return run_revocation_check(
        SGMinter(fake_sg.url, timeout=STALL_TIMEOUT_SECONDS), 'broker_read_all', 'masterkey', io
    )


def _run_scripted(minter: _ScriptedMinter, io: _ScriptedIO) -> int:
    return run_revocation_check(minter, 's', 'masterkey', io)


@pytest.mark.parametrize(
    'failure',
    [
        SGError('offline'),
        SGError('busy', status_code=503),
        SGError('unknown RPC', status_code=200, error_code=109),
    ],
)
def test_old_key_probe_stops_on_inconclusive_response(failure: SGError) -> None:
    minter = Mock()
    minter.mint_session_token.side_effect = [MintedToken('session', None), failure]
    minter.mint_rest_token.return_value = MintedToken('rest', 60)
    minter.check_session_token.side_effect = [True, False]
    io = _ScriptedIO([])
    with pytest.raises(SGError) as caught:
        run_revocation_check(minter, 'script', 'key', io)
    assert caught.value is failure
    assert 'Passed:' not in io.text()


def test_rest_probe_displays_a_sanitized_sg_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    key = 'key /+ operator'
    sent = quote_plus(key)
    response = Mock(
        status_code=401,
        json=Mock(return_value={'errors': [{'title': f'private-transport-detail {sent}'}]}),
    )
    minter = SGMinter('https://sg.example', session=Mock(post=Mock(return_value=response)))
    monkeypatch.setattr(
        minter,
        'mint_session_token',
        Mock(
            side_effect=[
                MintedToken('session', None),
                SGError('authentication failed', status_code=200, error_code=102),
            ]
        ),
    )
    monkeypatch.setattr(minter, 'check_session_token', Mock(side_effect=[True, False]))
    io = _ScriptedIO([])
    assert run_revocation_check(minter, 'script', key, io) == 0
    assert 'HTTP 401' in io.text()
    assert key not in io.text()
    assert sent not in io.text()
    assert 'private-transport-detail' not in io.text()
