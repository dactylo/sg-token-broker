from collections.abc import Callable

import pytest

from sg_token_broker import _verify
from sg_token_broker._secrets import token_fingerprint
from sg_token_broker._sg import MintedToken, SGError, SGMinter
from sg_token_broker._verify import run_revocation_check
from tests.conftest import _FakeSG

_EXIT_NOT_REVOKED = _verify._EXIT_NOT_REVOKED
_EXIT_REVOKED = _verify._EXIT_REVOKED
_MINTED = f'Minted a live session token (fingerprint {token_fingerprint("live-session")}).'
_REST_NOTE = 'Note: REST access tokens on this site expire in 600s (site pref).'
_RESTORE = (
    "Restore: the ApiUser 's' may still be disabled or trashed - restore it "
    '(SG Admin > Scripts) unless you intend to leave it retired.'
)
_STEP_1 = (
    "Step 1: In SG Admin > Scripts, regenerate the application key for 's', then press Enter... "
)
_STEP_2 = "Step 2: Now disable/trash the ApiUser 's' (SG Admin > Scripts), then press Enter... "
_STEP_3 = "Step 3: Now restore/re-enable the ApiUser 's', then press Enter... "
_STEP_4 = (
    'Step 4 (optional): verify the replacement retirement procedure: rotate the key, RENAME '
    'this script (e.g. s-retired), trash it, then create a NEW script with the ORIGINAL name '
    "'s' and a fresh key. Type y + Enter when done (anything else to skip)... "
)
_SURVIVED_ROTATION = [
    'Result: the outstanding session token SURVIVED key rotation.',
    'Key rotation alone cannot retire already-issued tokens on this site.',
    _STEP_2,
]


class TestRunRevocationCheck:
    def test_bad_key_is_setup_error(self, fake_sg: _FakeSG) -> None:
        fake_sg._fail_rpc = True
        io = _ScriptedIO([])
        with pytest.raises(_verify.VerifySetupError, match='could not mint a session token'):
            _run(fake_sg, io)
        assert io._lines == []

    def test_disable_revokes_and_stays_dead_after_restore(self, fake_sg: _FakeSG) -> None:
        def rotate_only() -> None:
            fake_sg._fail_rpc = True

        def disable() -> None:
            fake_sg._session_revoked = True

        io = _ScriptedIO([rotate_only, disable, lambda: None])
        assert _run(fake_sg, io) == _EXIT_REVOKED
        out = io._text()
        assert 'SURVIVED key rotation' in out
        assert 'disabling the ApiUser revoked' in out
        assert 'stay dead after the script is restored' in out

    def test_disable_revokes_but_token_resurrects_after_restore(self, fake_sg: _FakeSG) -> None:
        def rotate_only() -> None:
            fake_sg._fail_rpc = True

        def disable() -> None:
            fake_sg._session_revoked = True

        def restore() -> None:
            fake_sg._session_revoked = False

        io = _ScriptedIO([rotate_only, disable, restore])
        assert _run(fake_sg, io) == 3
        out = io._text()
        assert 'WORKS AGAIN after the script is restored' in out
        assert 'replacement' in out

    def test_nothing_revokes(self, fake_sg: _FakeSG) -> None:
        def rotate_only() -> None:
            fake_sg._fail_rpc = True

        io = _ScriptedIO([rotate_only, lambda: None])
        assert _run(fake_sg, io) == _EXIT_NOT_REVOKED
        assert 'survived BOTH' in io._text()

    def test_reports_rest_expiry(self, fake_sg: _FakeSG) -> None:
        def rotate() -> None:
            fake_sg._fail_rpc = True
            fake_sg._session_revoked = True

        io = _ScriptedIO([rotate])
        _run(fake_sg, io)
        assert '600' in io._text()

    def test_restore_instructions_survive_a_crash_after_disable(self, fake_sg: _FakeSG) -> None:
        def rotate_only() -> None:
            fake_sg._fail_rpc = True

        def break_site() -> None:
            fake_sg._hard_fail = True

        io = _ScriptedIO([rotate_only, break_site])
        with pytest.raises(SGError):
            _run(fake_sg, io)
        assert "Restore: the ApiUser 'broker_read_all'" in io._text()

    def test_rotation_revokes_token(self, fake_sg: _FakeSG) -> None:
        def rotate() -> None:
            fake_sg._fail_rpc = True
            fake_sg._session_revoked = True

        io = _ScriptedIO([rotate])
        assert _run(fake_sg, io) == _EXIT_REVOKED
        assert 'key rotation immediately revoked' in io._text()

    def test_step4_verifies_replacement_procedure(self, fake_sg: _FakeSG) -> None:
        def rotate_only() -> None:
            fake_sg._fail_rpc = True

        def disable() -> None:
            fake_sg._session_revoked = True

        def restore() -> None:
            fake_sg._session_revoked = False

        def replace() -> None:
            fake_sg._session_revoked = True
            fake_sg._fail_rpc = False

        io = _ScriptedIO(
            [rotate_only, disable, restore, replace],
            replies=['', '', '', 'y'],
            key_reply='new-replacement-key',
        )
        assert _run(fake_sg, io) == _EXIT_REVOKED
        out = io._text()
        assert 'dead while the renamed original stays trashed' in out
        assert 'replacement script mints under the original name' in out

    def test_warns_if_old_key_still_mints(self, fake_sg: _FakeSG) -> None:
        def revoke_session_only() -> None:
            fake_sg._session_revoked = True

        io = _ScriptedIO([revoke_session_only])
        assert _run(fake_sg, io) == _EXIT_REVOKED
        assert 'warning: the old key still mints new tokens' in io._text()


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
        assert io._lines == []


class TestWalkthroughTranscript:
    def test_disable_that_stays_effective_after_restore(self) -> None:
        io = _ScriptedIO([])
        assert _run_scripted(_ScriptedMinter([True, True, False, False]), io) == _EXIT_REVOKED
        assert io._lines == [
            _MINTED,
            _REST_NOTE,
            _STEP_1,
            *_SURVIVED_ROTATION,
            'Passed: disabling the ApiUser revoked the outstanding session token.',
            _STEP_3,
            'Passed: tokens stay dead after the script is restored.',
            (
                'Retirement procedure for a leaked scope: rotate the key FIRST '
                '(not possible while '
                'trashed), then trash the script, then restore it.'
            ),
            _RESTORE,
        ]

    def test_rotation_names_the_retirement_procedure(self) -> None:
        io = _ScriptedIO([])
        minter = _ScriptedMinter([True, False], old_key_still_mints=True)
        assert _run_scripted(minter, io) == _EXIT_REVOKED
        assert io._lines == [
            _MINTED,
            _REST_NOTE,
            _STEP_1,
            'warning: the old key still mints new tokens - was the key actually rotated?',
            'Passed: key rotation immediately revoked the outstanding session token.',
            'Retirement procedure for a leaked scope: rotate its application key.',
        ]

    def test_skipped_replacement_is_unverified(self) -> None:
        io = _ScriptedIO([])
        assert _run_scripted(_ScriptedMinter([True, True, False, True]), io) == 3
        assert io._lines == [
            _MINTED,
            _REST_NOTE,
            _STEP_1,
            *_SURVIVED_ROTATION,
            'Passed: disabling the ApiUser revoked the outstanding session token.',
            _STEP_3,
            'Caution: the old session token WORKS AGAIN after the script is restored.',
            'Disabling only suspends tokens; it does not retire them.',
            _STEP_4,
            (
                'Retirement procedure (rename step unverified): rotate the key, '
                'rename the script, '
                'trash it permanently; create a replacement script with the original name.'
            ),
            _RESTORE,
        ]

    def test_survival_advises_reassessing_app_session_tokens(self) -> None:
        io = _ScriptedIO([])
        assert _run_scripted(_ScriptedMinter([True, True, True]), io) == _EXIT_NOT_REVOKED
        assert io._lines == [
            _MINTED,
            _REST_NOTE,
            _STEP_1,
            *_SURVIVED_ROTATION,
            'Failed: the session token survived BOTH key rotation and ApiUser disable.',
            (
                'Outstanding tokens can only age out via the site session expiry (sliding - '
                'indefinite while in use). Reassess issuing app-token session tokens on this site.'
            ),
            _RESTORE,
        ]

    def test_token_that_fails_to_validate_is_a_setup_failure(self) -> None:
        io = _ScriptedIO([])
        with pytest.raises(_verify.VerifySetupError, match='freshly minted session token'):
            _run_scripted(_ScriptedMinter([False]), io)
        assert io._lines == []

    def test_verified_replacement_names_the_full_procedure(self) -> None:
        io = _ScriptedIO([], replies=['', '', '', 'y'], key_reply='replacement-key')
        minter = _ScriptedMinter([True, True, False, True, False])
        assert _run_scripted(minter, io) == _EXIT_REVOKED
        assert io._lines[-6:] == [
            _STEP_4,
            'Passed: the old token is dead while the renamed original stays trashed.',
            'application key for the replacement script (Enter to skip): ',
            'Passed: the replacement script mints under the original name.',
            (
                'Retirement procedure verified: rotate the key, rename the script, trash it '
                'permanently; replace it with a new script reusing the original name.'
            ),
            _RESTORE,
        ]


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
        self._lines: list[str] = []

    def _text(self) -> str:
        return '\n'.join(self._lines)

    def ask(self, message: str) -> str:
        self._lines.append(message)
        if self._actions:
            self._actions.pop(0)()
        return self._replies.pop(0) if self._replies else ''

    def ask_secret(self, message: str) -> str:
        self._lines.append(message)
        return self._key_reply

    def say(self, message: str) -> None:
        self._lines.append(message)


class _ScriptedMinter:
    def __init__(self, alive: list[bool], *, old_key_still_mints: bool = False) -> None:
        self._alive = list(alive)
        self._old_key_still_mints = old_key_still_mints
        self._session_mints = 0

    def check_session_token(self, session_token: str) -> bool:
        del session_token
        return self._alive.pop(0)

    def mint_rest_token(self, script_name: str, script_key: str) -> MintedToken:
        del script_name, script_key
        return MintedToken('rest-token', 600)

    def mint_session_token(self, script_name: str, script_key: str) -> MintedToken:
        del script_name
        self._session_mints += 1
        if (
            self._session_mints == 1
            or self._old_key_still_mints
            or script_key == 'replacement-key'
        ):
            return MintedToken('live-session', None)
        raise SGError('SG request to /api3/json returned HTTP 200: Authentication failed')


def _run(fake_sg: _FakeSG, io: _ScriptedIO) -> int:
    return run_revocation_check(SGMinter(fake_sg._url), 'broker_read_all', 'masterkey', io)


def _run_scripted(minter: _ScriptedMinter, io: _ScriptedIO) -> int:
    return run_revocation_check(minter, 's', 'masterkey', io)
