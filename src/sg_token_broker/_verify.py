"""Guide an Admin through verifying SG token revocation behavior."""

from typing import Protocol

from sg_token_broker._secrets import token_fingerprint
from sg_token_broker._sg import MintedToken, SGError

_EXIT_NOT_REVOKED = 1
_EXIT_REVOKED = 0
EXIT_SETUP_ERROR = 2
_EXIT_UNVERIFIED = 3
_SSL_CLAUSE = (
    'a certificate-verification failure behind a corporate proxy usually means the '
    'proxy intercepts TLS and re-signs it with a corporate CA. Pass that CA file via '
    '--ca-bundle (or set REQUESTS_CA_BUNDLE), or use --insecure for this one-shot test'
)


class _RevocationMinter(Protocol):
    """SG operations used by the revocation walkthrough."""

    def check_session_token(self, session_token: str) -> bool:
        """Check whether SG still accepts a session token.

        Args:
            session_token: SG session token to probe.

        Returns:
            True for acceptance and False for an explicit authentication
            rejection.

        Raises:
            SGError: If the probe fails or its response is inconclusive;
                these failures must not be reported as False.
        """
        ...

    def mint_rest_token(self, script_name: str, script_key: str) -> MintedToken:
        """Mint a REST token for the named script.

        Args:
            script_name: ApiUser script name.
            script_key: ApiUser application key.

        Returns:
            The minted access token with its SG-reported lifetime.

        Raises:
            SGError: If the upstream token request cannot be completed.
        """
        ...

    def mint_session_token(self, script_name: str, script_key: str) -> MintedToken:
        """Mint a session token for the named script.

        Args:
            script_name: ApiUser script name.
            script_key: ApiUser application key.

        Returns:
            The minted session token with `expires_in` set to `None`.

        Raises:
            SGError: If the upstream token request cannot be completed.
        """
        ...


class _VerifyIO(Protocol):
    """Interactive I/O surface for the revocation walkthrough."""

    def ask(self, message: str) -> str:
        """Show a blocking prompt and return the entered line.

        Args:
            message: Prompt text.

        Returns:
            The entered line.
        """
        ...

    def ask_secret(self, message: str) -> str:
        """Show a no-echo prompt (for keys) and return the entered value.

        Args:
            message: Prompt text.

        Returns:
            The entered value.
        """
        ...

    def say(self, message: str) -> None:
        """Emit one line of output.

        Args:
            message: Output text.
        """
        ...


class VerifySetupError(Exception):
    """Report a failure before the revocation walkthrough can start."""


def _old_key_rejected(minter: _RevocationMinter, script_name: str, script_key: str) -> bool:
    """Return True if minting with the (now rotated) key fails as expected."""
    try:
        minter.mint_session_token(script_name, script_key)
    except SGError:
        return True
    return False


def _verify_restore(minter: _RevocationMinter, script_name: str, token: str, io: _VerifyIO) -> int:
    """Run step 3 (restore re-probe) and the optional step 4 (replacement)."""
    io.ask(f'Step 3: Now restore/re-enable the ApiUser {script_name!r}, then press Enter... ')
    if not minter.check_session_token(token):
        io.say('Passed: tokens stay dead after the script is restored.')
        io.say(
            'Retirement procedure for a leaked scope: rotate the key FIRST (not possible while '
            'trashed), then trash the script, then restore it.'
        )
        return _EXIT_REVOKED

    io.say('Caution: the old session token WORKS AGAIN after the script is restored.')
    io.say('Disabling only suspends tokens; it does not retire them.')
    answer = io.ask(
        'Step 4 (optional): verify the replacement retirement procedure: rotate the key, RENAME '
        f'this script (e.g. {script_name}-retired), trash it, then create a NEW script with '
        f'the ORIGINAL name {script_name!r} and a fresh key. '
        'Type y + Enter when done (anything else to skip)... '
    )
    if answer.strip().lower() != 'y':
        io.say(
            'Retirement procedure (rename step unverified): rotate the key, rename the script, '
            'trash it permanently; create a replacement script with the original name.'
        )
        return _EXIT_UNVERIFIED
    if minter.check_session_token(token):
        io.say(
            'Failed: the old token is STILL ALIVE with the original script renamed and trashed.'
        )
        return _EXIT_NOT_REVOKED
    io.say('Passed: the old token is dead while the renamed original stays trashed.')
    new_key = io.ask_secret('application key for the replacement script (Enter to skip): ')
    if new_key:
        try:
            minter.mint_session_token(script_name, new_key)
            io.say('Passed: the replacement script mints under the original name.')
        except SGError as exc:
            io.say(f'warning: could not mint with the replacement key: {exc}')
    io.say(
        'Retirement procedure verified: rotate the key, rename the script, trash it permanently; '
        'replace it with a new script reusing the original name.'
    )
    return _EXIT_REVOKED


def run_revocation_check(
    minter: _RevocationMinter,
    script_name: str,
    script_key: str,
    io: _VerifyIO,
) -> int:
    """Walk an Admin through testing whether SG revokes outstanding tokens.

    Args:
        minter: SG minter pointed at the real SG site.
        script_name: ApiUser script name to test with (use a disposable one).
        script_key: Its current application key.
        io: Interactive I/O surface (prompts and output).

    Returns:
        0 if a retirement procedure was demonstrated, 1 if the outstanding
        session survived every step tried, or 3 if the run ended on an
        unverified step.

    Raises:
        VerifySetupError: If the first token cannot be minted or its initial
            probe explicitly rejects it.
        SGError: If a session probe, including the initial probe, fails or has
            an inconclusive response.
    """
    try:
        minted = minter.mint_session_token(script_name, script_key)
    except SGError as exc:
        message = f'could not mint a session token: {exc}'.rstrip('.')
        if 'SSLError' in str(exc):
            message += f'; {_SSL_CLAUSE}'
        raise VerifySetupError(message) from exc
    if not minter.check_session_token(minted.token):
        raise VerifySetupError('freshly minted session token did not validate')
    io.say(f'Minted a live session token (fingerprint {token_fingerprint(minted.token)}).')

    try:
        rest = minter.mint_rest_token(script_name, script_key)
        io.say(f'Note: REST access tokens on this site expire in {rest.expires_in}s (site pref).')
    except SGError as exc:
        io.say(f'Note: REST access token mint failed ({exc}); continuing with the session test.')

    io.ask(
        f'Step 1: In SG Admin > Scripts, regenerate the application key for '
        f'{script_name!r}, then press Enter... '
    )
    if not _old_key_rejected(minter, script_name, script_key):
        io.say('warning: the old key still mints new tokens - was the key actually rotated?')
    if not minter.check_session_token(minted.token):
        io.say('Passed: key rotation immediately revoked the outstanding session token.')
        io.say('Retirement procedure for a leaked scope: rotate its application key.')
        return _EXIT_REVOKED

    io.say('Result: the outstanding session token SURVIVED key rotation.')
    io.say('Key rotation alone cannot retire already-issued tokens on this site.')
    io.ask(
        f'Step 2: Now disable/trash the ApiUser {script_name!r} '
        f'(SG Admin > Scripts), then press Enter... '
    )
    try:
        if minter.check_session_token(minted.token):
            io.say('Failed: the session token survived BOTH key rotation and ApiUser disable.')
            io.say(
                'Outstanding tokens can only age out via the site session expiry '
                '(sliding - indefinite while in use). Reassess issuing app-token session '
                'tokens on this site.'
            )
            return _EXIT_NOT_REVOKED

        io.say('Passed: disabling the ApiUser revoked the outstanding session token.')
        return _verify_restore(minter, script_name, minted.token, io)
    finally:
        io.say(
            f'Restore: the ApiUser {script_name!r} may still be disabled or trashed - restore '
            'it (SG Admin > Scripts) unless you intend to leave it retired.'
        )
