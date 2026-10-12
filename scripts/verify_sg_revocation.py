#!/usr/bin/env python
"""Standalone SG revocation test - single file, copy anywhere and run as a site Admin.

Mirrors `sg-token-broker verify-revocation` without needing the package
installed; requires only Python 3.11+ and `requests`. Use a DISPOSABLE script
(ApiUser), not a production one - this test rotates and disables it.

Usage:
    export SGTB_VERIFY_KEY=<application key>
    python verify_sg_revocation.py --site-url https://studio.shotgunstudio.com
        --script-name disposable_revocation_test --script-key-env SGTB_VERIFY_KEY
        --proxy http://squid:8080 --ca-bundle /path/to/corp-root-ca.pem
    (single command line; wrapped here for readability)

Networks with a TLS-intercepting proxy re-sign the site's certificate with a
corporate CA that Python does not trust by default; pass that CA via
`--ca-bundle` (or the `REQUESTS_CA_BUNDLE` env var), or use `--insecure` to
skip verification for this one-shot test.

Exit codes: 0 = an immediate retirement procedure exists (output names it),
1 = outstanding session tokens survive everything, 2 = setup or inconclusive SG
error,
3 = the run ended on an unverified step.
"""

import argparse
import getpass
import hashlib
import ipaddress
import os
import re
import sys
import warnings
from collections.abc import Iterable
from typing import TypeAlias, cast
from urllib.parse import urlsplit

import requests
import urllib3

_CONTROL_CHARACTERS = re.compile(r'[\x00-\x1f\x7f-\x9f]')
_DIAGNOSTIC_KEYS = ('session_id', 'results', 'exception', 'message')
# shotgun_api3's AuthenticationFault error_code: SG rejected the credentials/session.
_ERR_AUTH_CODE = 102
_EXIT_UNVERIFIED = 3
_HTTP_OK = 200
_LOOPBACK_NAMES = frozenset({'localhost'})
_REST_AUTH_PATH = '/api/v1.1/auth/access_token'
_RPC_PATH = '/api3/json'
_SSL_HINT = (
    'a "certificate verify failed" error behind a corporate proxy usually means the '
    'proxy intercepts TLS and re-signs it with a corporate CA. Pass that CA file via '
    '--ca-bundle (or set REQUESTS_CA_BUNDLE), or use --insecure for this one-shot test'
)
_TIMEOUT_SECONDS = 15.0

_JSONValue: TypeAlias = (
    bool | int | float | str | list['_JSONValue'] | dict[str, '_JSONValue'] | None
)


def _build_session(
    *, proxy: str | None, ca_bundle: str | None, insecure: bool
) -> requests.Session:
    """Build the HTTP session used for all SG calls."""
    session = requests.Session()
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
    if insecure:
        session.verify = False
        warnings.simplefilter('ignore', urllib3.exceptions.InsecureRequestWarning)
    elif ca_bundle:
        session.verify = ca_bundle
    return session


def _classify_rpc_body(data: object) -> str:
    """Describe a decoded RPC body by shape and allowlisted key presence only."""
    if not isinstance(data, dict):
        return 'not_object'
    fields = cast('dict[str, object]', data)
    present = [key for key in _DIAGNOSTIC_KEYS if key in fields]
    kind = 'error_shape' if fields.get('exception') else 'no_session_id'
    return f'{kind}; keys present: {", ".join(present) or "none"}'


def _describe(exc: Exception) -> str:
    """Render a transport error with a TLS-interception hint when relevant."""
    message = f'{exc.__class__.__name__}: {exc}'
    if isinstance(exc, requests.exceptions.SSLError):
        message = f'{message}\nhint: {_SSL_HINT}.'
    return message


def _is_loopback_host(host: str) -> bool:
    """Return True if the host is a loopback name or address."""
    if host.lower() in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _report_error(message: str) -> None:
    """Print an anticipated error on one terminal-safe stderr line."""
    message = message.replace(f'\nhint: {_SSL_HINT}.', f'; {_SSL_HINT}')
    visible = _CONTROL_CHARACTERS.sub(lambda match: f'\\x{ord(match.group()):02x}', message)
    print(f'error: {visible.rstrip(".")}', file=sys.stderr)


def _require_https_or_loopback(url: str) -> str:
    """Require HTTPS, except for HTTP on a loopback host."""
    if '\\' in url or any(character.isspace() or not character.isprintable() for character in url):
        raise ValueError(f'site URL is not a valid URL: {url!r}')
    try:
        parts = urlsplit(url)
        host = parts.hostname or ''
        _ = parts.port
    except ValueError as exc:
        raise ValueError(f'site URL is not a valid URL: {url!r}') from exc
    if parts.scheme == 'https' and host:
        return url
    if parts.scheme == 'http' and _is_loopback_host(host):
        return url
    raise ValueError(
        f'site URL must be an https:// URL (plain http is allowed only on loopback hosts): {url!r}'
    )


def _rest_token_expires_in(
    session: requests.Session, site_url: str, script_name: str, script_key: str
) -> int | None:
    """Report the site's REST access-token lifetime in seconds, if mintable."""
    try:
        response = session.post(
            f'{site_url.rstrip("/")}{_REST_AUTH_PATH}',
            data={
                'grant_type': 'client_credentials',
                'client_id': script_name,
                'client_secret': script_key,
            },
            headers={'Accept': 'application/json'},
            timeout=_TIMEOUT_SECONDS,
            allow_redirects=False,
        )
        data: object = response.json()
    except (requests.RequestException, ValueError):
        return None
    if isinstance(data, dict):
        expires = cast('dict[str, object]', data).get('expires_in')
        if isinstance(expires, int):
            return expires
    return None


def _rpc_get_session_token(
    session: requests.Session, site_url: str, auth: dict[str, _JSONValue]
) -> tuple[str | None, str, int | None]:
    """Call the get_session_token RPC and return its session id, error, and error code."""
    try:
        response = session.post(
            f'{site_url.rstrip("/")}{_RPC_PATH}',
            json={'method_name': 'get_session_token', 'params': [auth]},
            headers={'Accept': 'application/json'},
            timeout=_TIMEOUT_SECONDS,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise RuntimeError(f'cannot reach SG site: {_describe(exc)}') from exc
    try:
        data: object = response.json()
    except ValueError as exc:
        raise RuntimeError(
            f'SG returned non-JSON response (HTTP {response.status_code}); '
            'classification: non_json'
        ) from exc
    classification = _classify_rpc_body(data)
    status = response.status_code
    if status != _HTTP_OK:
        return None, f'HTTP {status} response; classification: {classification}', None
    if not isinstance(data, dict):
        return (
            None,
            f'non-JSON-object response (HTTP {status}); classification: {classification}',
            None,
        )
    fields = cast('dict[str, object]', data)
    if fields.get('exception'):
        code = fields.get('error_code')
        return (
            None,
            f'SG error (HTTP {status}); classification: {classification}',
            code if type(code) is int else None,
        )
    # The production server returns the id at the top level; the nested
    # results shape is accepted too, mirroring the official client.
    session_id = fields.get('session_id')
    if isinstance(session_id, str) and session_id.strip():
        return session_id, '', None
    results = fields.get('results')
    if isinstance(results, dict):
        nested = cast('dict[str, object]', results).get('session_id')
        if isinstance(nested, str) and nested.strip():
            return nested, '', None
    return (
        None,
        f'response contained no session_id (HTTP {status}); classification: {classification}',
        None,
    )


def _check_session_token(session: requests.Session, site_url: str, session_token: str) -> bool:
    """Return True if SG still accepts the outstanding session token."""
    probe, error, code = _rpc_get_session_token(
        session, site_url, {'session_token': session_token, 'reject_if_expired': True}
    )
    if probe is not None:
        return True
    if code == _ERR_AUTH_CODE:
        return False
    raise RuntimeError(f'session probe was not an authentication rejection: {error}')


def _mint_session_token(
    session: requests.Session, site_url: str, script_name: str, script_key: str
) -> tuple[str | None, str]:
    """Mint a session token from script credentials."""
    token, error, _ = _rpc_get_session_token(
        session, site_url, {'script_name': script_name, 'script_key': script_key}
    )
    return token, error


def _verify_restore(session: requests.Session, site_url: str, script_name: str, token: str) -> int:
    """Run step 3 (restore re-probe) and the optional step 4 (replacement)."""
    input(f'Step 3: Now restore/re-enable the ApiUser {script_name!r}, then press Enter... ')
    if not _check_session_token(session, site_url, token):
        print('Passed: tokens stay dead after the script is restored.')
        print(
            'Retirement procedure: rotate the key FIRST (not possible while trashed), '
            'then trash the script, then restore it.'
        )
        return 0

    print('Caution: the old session token WORKS AGAIN after the script is restored.')
    print('Disabling only suspends tokens; it does not retire them.')
    answer = input(
        'Step 4 (optional): verify the replacement retirement procedure: rotate the key, RENAME '
        f'this script (e.g. {script_name}-retired), trash it, then create a NEW script with '
        f'the ORIGINAL name {script_name!r} and a fresh key. '
        'Type y + Enter when done (anything else to skip)... '
    )
    if answer.strip().lower() != 'y':
        print(
            'Retirement procedure (rename step unverified): rotate the key, rename the script, '
            'trash it permanently; create a replacement script with the original name.'
        )
        return _EXIT_UNVERIFIED
    if _check_session_token(session, site_url, token):
        print('Failed: the old token is STILL ALIVE with the original script renamed and trashed.')
        return 1
    print('Passed: the old token is dead while the renamed original stays trashed.')
    new_key = getpass.getpass('application key for the replacement script (Enter to skip): ')
    if new_key:
        replacement, error = _mint_session_token(session, site_url, script_name, new_key)
        if replacement is not None:
            print('Passed: the replacement script mints under the original name.')
        else:
            print(f'warning: could not mint with the replacement key: {error}')
    print(
        'Retirement procedure verified: rotate the key, rename the script, trash it permanently; '
        'replace it with a new script reusing the original name.'
    )
    return 0


def _run_test(session: requests.Session, site_url: str, script_name: str, key: str) -> int:
    """Run the interactive mint/rotate/disable flow; returns the exit code."""
    minted, error = _mint_session_token(session, site_url, script_name, key)
    if minted is None:
        _report_error(f'sg rejected the script credentials: {error}')
        return 2
    if not _check_session_token(session, site_url, minted):
        _report_error('freshly minted session token did not validate')
        return 2
    fingerprint = hashlib.sha256(minted.encode()).hexdigest()[:16]
    print(f'Minted a live session token (fingerprint {fingerprint}).')

    expires = _rest_token_expires_in(session, site_url, script_name, key)
    if expires is not None:
        print(f'Note: REST access tokens on this site expire in {expires}s (site pref).')

    input(
        f'Step 1: In SG Admin > Scripts, regenerate the application key for '
        f'{script_name!r}, then press Enter... '
    )
    remint, _ = _mint_session_token(session, site_url, script_name, key)
    if remint is not None:
        print('warning: the old key still mints new tokens - was the key actually rotated?')
    if not _check_session_token(session, site_url, minted):
        print('Passed: key rotation immediately revoked the outstanding session token.')
        print('Retirement procedure for a leaked scope: rotate its application key.')
        return 0

    print('Result: the outstanding session token SURVIVED key rotation.')
    input(
        f'Step 2: Now disable/trash the ApiUser {script_name!r} '
        f'(SG Admin > Scripts), then press Enter... '
    )
    try:
        if _check_session_token(session, site_url, minted):
            print('Failed: the session token survived BOTH key rotation and ApiUser disable.')
            print(
                'Outstanding tokens can only age out via the site session expiry '
                '(sliding - indefinite while in use). Reassess issuing app-token session '
                'tokens on this site.'
            )
            return 1

        print('Passed: disabling the ApiUser revoked the outstanding session token.')
        return _verify_restore(session, site_url, script_name, minted)
    finally:
        print(
            f'Restore: the ApiUser {script_name!r} may still be disabled or trashed - restore '
            'it (SG Admin > Scripts) unless you intend to leave it retired.'
        )


def main(argv: Iterable[str] | None = None) -> int:
    """Run the interactive revocation test.

    Args:
        argv: Arguments (defaults to `sys.argv[1:]`).

    Returns:
        Process exit code (0 revocable, 1 not revocable, 2 setup or
        inconclusive SG error, 3 unverified).

    Raises:
        SystemExit: With status 0 for help or 2 for invalid arguments.
    """
    parser = argparse.ArgumentParser(
        description=(__doc__ or '').splitlines()[0],
        epilog='Exit status: 0 if a procedure retired the token immediately, 1 if the token '
        'survived every step tried, 2 if setup failed or an SG error made the run '
        'inconclusive, and 3 if the run ended on an unverified step.',
    )
    parser.add_argument('--site-url', required=True, metavar='URL', help='SG site URL')
    parser.add_argument(
        '--script-name',
        required=True,
        metavar='NAME',
        help='name of the disposable ApiUser script to test with',
    )
    parser.add_argument(
        '--script-key-env',
        metavar='NAME',
        help='environment variable that holds the application key (prompts without echo '
        'if omitted)',
    )
    parser.add_argument(
        '--proxy',
        metavar='URL',
        help='HTTP(S) proxy URL, e.g. http://squid:8080 '
        '(HTTP_PROXY/HTTPS_PROXY env vars are honored without this flag)',
    )
    parser.add_argument(
        '--ca-bundle',
        metavar='FILE',
        help='CA bundle file for TLS verification, e.g. the corporate root CA when the '
        'proxy intercepts TLS (REQUESTS_CA_BUNDLE env var is honored without this flag)',
    )
    parser.add_argument(
        '--insecure',
        action='store_true',
        help='disable TLS verification; use only for a one-off test with a disposable key',
    )
    args = parser.parse_args(argv)

    try:
        args.site_url = _require_https_or_loopback(args.site_url)
    except ValueError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2

    if args.script_key_env:
        key = os.environ.get(args.script_key_env, '')
        if not key:
            print(f'error: environment variable {args.script_key_env} is not set', file=sys.stderr)
            return 2
    else:
        key = getpass.getpass(f'application key for {args.script_name!r}: ')

    if args.insecure:
        print(
            'warning: TLS verification disabled; only use with a disposable script key',
            file=sys.stderr,
        )
    session = _build_session(proxy=args.proxy, ca_bundle=args.ca_bundle, insecure=args.insecure)
    try:
        result = _run_test(session, args.site_url, args.script_name, key)
    except RuntimeError as exc:
        _report_error(f'revocation check is inconclusive: {exc}')
        return 2
    return result


if __name__ == '__main__':
    sys.exit(main())
