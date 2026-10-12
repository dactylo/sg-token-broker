#!/usr/bin/env python
"""Standalone SG sudo-scoped REST token check - run as a site Admin.

Checks the SG behavior that the user-token service relies on: that a REST
access token minted with `scope=sudo_as_login:<login>` acts with that user's
permissions, and what happens to it when the user is disabled. Companion to
`verify_sg_revocation.py`; same flags, needs only Python 3.11+ and `requests`.

Requirements: the ApiUser (script) used must have a permission rule set with
"sudo" allowed, and you need a test HumanUser you can safely disable for a
minute. For a conclusive permission check, pick a test user who can see FEWER
projects than the script can.

Usage:
    export SGTB_VERIFY_KEY=<application key>
    python verify_sg_sudo.py --site-url https://studio.shotgunstudio.com
        --script-name sudo_capable_script --script-key-env SGTB_VERIFY_KEY
        --sudo-login some.testuser
        --proxy http://squid:8080 --ca-bundle /path/to/corp-root-ca.pem
    (single command line; wrapped here for readability)

Exit codes: 0 = the disabled-user check was conclusive (read the other printed
results), 2 = setup error, 3 = the disabled-user check was inconclusive because
ordinary expiry could not be ruled out or SG did not answer cleanly.
"""

# pyright: reportPrivateUsage=false

import argparse
import getpass
import ipaddress
import os
import sys
import time
import warnings
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import cast
from urllib.parse import urlsplit

import requests
import urllib3

_API_BASE = '/api/v1.1'
_AUTH_REJECT_STATUSES = frozenset({400, 401, 403})
_BOGUS_LOGIN = 'zzz_no_such_user_999'
_EXIT_UNVERIFIED = 3
_EXPIRY_MARGIN_SECONDS = 60
_HTTP_OK = 200
_LOOPBACK_NAMES = frozenset({'localhost'})
_REST_AUTH_PATH = '/api/v1.1/auth/access_token'
_TIMEOUT_SECONDS = 15.0


@dataclass(frozen=True)
class _SurveyContext:
    """Carry shared state for the sudo verification survey."""

    _session: requests.Session
    _site_url: str
    _script_name: str
    _key: str
    _sudo_login: str
    _clock: Callable[[], float]


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


def _count_projects(
    session: requests.Session, site_url: str, bearer: str
) -> tuple[int | None, int]:
    """Count projects visible to a bearer token (first page, up to 500)."""
    try:
        response = session.get(
            f'{site_url.rstrip("/")}{_API_BASE}/entity/projects?fields=name&page[size]=500',
            headers={'Authorization': f'Bearer {bearer}', 'Accept': 'application/json'},
            timeout=_TIMEOUT_SECONDS,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise RuntimeError(f'cannot reach SG site: {exc.__class__.__name__}: {exc}') from exc
    if response.status_code != _HTTP_OK:
        return None, response.status_code
    try:
        data: object = response.json()
    except ValueError:
        return None, response.status_code
    if not isinstance(data, dict):
        return None, response.status_code
    rows = cast('dict[str, object]', data).get('data')
    if isinstance(rows, list):
        return len(cast('list[object]', rows)), response.status_code
    return None, response.status_code


def _check_disabled_user(
    context: _SurveyContext,
    mint_sudo: Callable[[], tuple[str | None, int, int, str]],
    sudo_token: str,
    *,
    minted_at: float,
    expires_in: int,
) -> str:
    """Check sudo tokens while the test user is disabled and after re-enabling."""
    input(
        f'Step: Disable the test user {context._sudo_login!r} in SG (Admin > People, uncheck '
        'active / set status), then press Enter... '
    )
    disabled_result = 'INCONCLUSIVE'
    try:
        remint, _, status, error = mint_sudo()
        if remint is not None:
            print('Caution: SG still mints sudo tokens for the disabled user.')
        elif status in _AUTH_REJECT_STATUSES:
            print(f'Passed: new sudo mints for the disabled user are rejected ({error}).')
        else:
            print(
                f'Inconclusive: the sudo remint failed with HTTP {status}, which is not a clean '
                f'rejection ({error}).'
            )
        count, status = _count_projects(context._session, context._site_url, sudo_token)
        elapsed = context._clock() - minted_at
        window = f'elapsed {elapsed:.0f}s of a {expires_in}s lifetime'
        if count is not None:
            disabled_result = 'SURVIVED'
            print(
                'Caution: the outstanding sudo token STILL WORKS with the user disabled '
                f'({window}). Revocation is then bounded by the token lifetime '
                f'({expires_in}s here), '
                'not immediate.'
            )
        elif status in _AUTH_REJECT_STATUSES and elapsed < expires_in - _EXPIRY_MARGIN_SECONDS:
            disabled_result = 'PASS'
            print(
                'Passed: the outstanding sudo token died when the user was disabled '
                f'(HTTP {status}; {window}).'
            )
        elif status in _AUTH_REJECT_STATUSES:
            disabled_result = 'INCONCLUSIVE'
            print(
                f'Inconclusive: the sudo token was rejected (HTTP {status}) but {window}; '
                'ordinary expiry cannot be ruled out.'
            )
        else:
            disabled_result = 'INCONCLUSIVE'
            print(
                f'Inconclusive: the sudo-token project query failed with HTTP {status} '
                f'({window}); cannot distinguish revocation from an outage.'
            )
        input(f'Step: Re-enable the test user {context._sudo_login!r}, then press Enter... ')
        count, status = _count_projects(context._session, context._site_url, sudo_token)
        if count is not None:
            print('Note: after re-enabling the user, the outstanding sudo token works again.')
        elif status in _AUTH_REJECT_STATUSES:
            print('Note: after re-enabling the user, the outstanding sudo token remains dead.')
        else:
            print(
                'Inconclusive: after re-enabling the user, the sudo-token project query failed '
                f'with HTTP {status}; cannot determine the outstanding token state.'
            )
    finally:
        print(
            f'Restore: make sure the test user {context._sudo_login!r} is re-enabled in SG '
            '(Admin > People) before you leave.'
        )
    return disabled_result


def _compare_project_visibility(
    session: requests.Session, site_url: str, plain_token: str, sudo_token: str
) -> None:
    """Compare project visibility between the plain and sudo tokens."""
    plain_count, plain_status = _count_projects(session, site_url, plain_token)
    if plain_count is None:
        print(
            f'warning: the baseline plain-token project query failed (HTTP {plain_status}); '
            'the permission comparison is inconclusive'
        )
        return
    sudo_count, sudo_status = _count_projects(session, site_url, sudo_token)
    if sudo_count is None:
        print(f'warning: the sudo-token project query failed (HTTP {sudo_status})')
        return
    print(f'plain token sees {plain_count} project(s); sudo token sees {sudo_count}.')
    if plain_count != sudo_count:
        print('Passed: permissions follow the user; the sudo token is user-bound.')
    else:
        print(
            'Inconclusive: the project counts match. Either the user sees the same '
            'projects as the script, or sudo is not applied. Re-run with a test user who '
            'has restricted project access.'
        )


def _first_error(fields: dict[str, object]) -> str:
    """Extract the first error title/detail from a REST error body."""
    errors = fields.get('errors')
    if isinstance(errors, list) and errors:
        first: object = cast('list[object]', errors)[0]
        if isinstance(first, dict):
            error = cast('dict[str, object]', first)
            return str(error.get('detail') or error.get('title') or error)
        return str(first)
    return str(fields)


def _is_loopback_host(host: str) -> bool:
    """Return True if the host is a loopback name or address."""
    if host.lower() in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _mint_rest_token(
    session: requests.Session,
    site_url: str,
    script_name: str,
    script_key: str,
    scope: str | None,
) -> tuple[str | None, int, int, str]:
    """Mint a REST access token, optionally with a sudo scope."""
    form = {
        'grant_type': 'client_credentials',
        'client_id': script_name,
        'client_secret': script_key,
    }
    if scope:
        form['scope'] = scope
    try:
        response = session.post(
            f'{site_url.rstrip("/")}{_REST_AUTH_PATH}',
            data=form,
            headers={'Accept': 'application/json'},
            timeout=_TIMEOUT_SECONDS,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise RuntimeError(f'cannot reach SG site: {exc.__class__.__name__}: {exc}') from exc
    status = response.status_code
    try:
        data: object = response.json()
    except ValueError:
        return None, 0, status, f'HTTP {status}: non-JSON body'
    if not isinstance(data, dict):
        return None, 0, status, f'non-JSON-object response (HTTP {status})'
    fields = cast('dict[str, object]', data)
    token = fields.get('access_token')
    expires = fields.get('expires_in')
    if isinstance(token, str):
        return token, expires if isinstance(expires, int) else 0, status, ''
    return None, 0, status, f'HTTP {status}: {_first_error(fields)}'


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


def _run_survey(context: _SurveyContext) -> int:
    """Run the full sudo-token survey; returns the exit code."""
    plain_token, expires, _, error = _mint_rest_token(
        context._session,
        context._site_url,
        context._script_name,
        context._key,
        None,
    )
    if plain_token is None:
        print(f'Setup failed: could not mint a plain REST token: {error}')
        return 2
    print(
        f'Minted a plain REST token (expires in {expires}s, how long a leaked REST token '
        'stays usable).'
    )

    minted_at = context._clock()
    sudo_token, sudo_expires, _, error = _mint_rest_token(
        context._session,
        context._site_url,
        context._script_name,
        context._key,
        f'sudo_as_login:{context._sudo_login}',
    )
    if sudo_token is None:
        print(f'Setup failed: sudo-scoped mint rejected: {error}')
        print(
            f'hint: the ApiUser {context._script_name!r} likely needs a permission rule set with '
            'sudo permission enabled, and the login must match an active HumanUser.'
        )
        return 2
    print(f'Minted a sudo-scoped REST token for {context._sudo_login!r}.')

    bogus, _, status, error = _mint_rest_token(
        context._session,
        context._site_url,
        context._script_name,
        context._key,
        f'sudo_as_login:{_BOGUS_LOGIN}',
    )
    if bogus is not None:
        print(
            'Caution: SG minted a sudo token for a nonexistent login; SG may check the '
            'login only when the token is used.'
        )
    elif status in _AUTH_REJECT_STATUSES:
        print(f'Passed: a bogus login was rejected at mint time ({error}).')
    else:
        print(
            f'Inconclusive: the bogus-login mint failed with HTTP {status}, which is not a '
            f'clean rejection ({error}).'
        )

    _compare_project_visibility(context._session, context._site_url, plain_token, sudo_token)

    def mint_sudo() -> tuple[str | None, int, int, str]:
        return _mint_rest_token(
            context._session,
            context._site_url,
            context._script_name,
            context._key,
            f'sudo_as_login:{context._sudo_login}',
        )

    disabled_result = _check_disabled_user(
        context,
        mint_sudo,
        sudo_token,
        minted_at=minted_at,
        expires_in=sudo_expires,
    )
    print('Survey complete - save this output for analysis.')
    return _EXIT_UNVERIFIED if disabled_result == 'INCONCLUSIVE' else 0


def main(
    argv: Iterable[str] | None = None,
    *,
    clock: Callable[[], float] | None = None,
) -> int:
    """Run the interactive sudo-token survey.

    Args:
        argv: Arguments (defaults to `sys.argv[1:]`).
        clock: Monotonic clock used to measure the sudo token's age.

    Returns:
        Process exit code (0 when the disabled-user check was conclusive,
        2 for a setup error, 3 when the disabled-user check was inconclusive).

    Raises:
        SystemExit: With status 0 for help or 2 for invalid arguments.
    """
    parser = argparse.ArgumentParser(
        description=(__doc__ or '').splitlines()[0],
        epilog=(
            'Exit status: 0 if the disabled-user check was conclusive, 2 for a setup '
            'error, and 3 if the disabled-user check was inconclusive.'
        ),
    )
    parser.add_argument('--site-url', required=True, help='SG site URL')
    parser.add_argument(
        '--script-name', required=True, help='ApiUser script name with sudo permission'
    )
    parser.add_argument(
        '--script-key-env',
        help='environment variable that holds the application key '
        '(prompts without echo if omitted)',
    )
    parser.add_argument(
        '--sudo-login', required=True, help='login of a test HumanUser you can safely disable'
    )
    parser.add_argument(
        '--proxy',
        help='HTTP(S) proxy URL, e.g. http://squid:8080 '
        '(HTTP_PROXY/HTTPS_PROXY env vars are honored without this flag)',
    )
    parser.add_argument(
        '--ca-bundle',
        help='CA bundle file for TLS verification, e.g. the corporate root CA when the '
        'proxy intercepts TLS (REQUESTS_CA_BUNDLE env var is honored without this flag)',
    )
    parser.add_argument(
        '--insecure',
        action='store_true',
        help='disable TLS verification; use only for a one-off test with a disposable key',
    )
    args = parser.parse_args(argv)
    tick = clock if clock is not None else time.monotonic

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
        result = _run_survey(
            _SurveyContext(
                _session=session,
                _site_url=args.site_url,
                _script_name=args.script_name,
                _key=key,
                _sudo_login=args.sudo_login,
                _clock=tick,
            )
        )
    except RuntimeError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2
    return result


if __name__ == '__main__':
    sys.exit(main())
