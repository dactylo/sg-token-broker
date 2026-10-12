"""CLI for serving and fetching tokens, managing sign-in, and verifying revocation."""

import argparse
import getpass
import importlib.metadata
import json
import logging
import math
import os
import re
import ssl
import sys
import warnings
from collections.abc import Iterable
from pathlib import Path

import requests
import urllib3

from sg_token_broker._audit import AuditLogger
from sg_token_broker._cache import TTLCache
from sg_token_broker._client import BrokerClient, BrokerClientError, ClientOptions
from sg_token_broker._config import BrokerConfig, ConfigError, is_credential_text, load_config
from sg_token_broker._credstore import (
    delete_account,
    delete_refresh_token,
    load_account,
    store_account,
    store_refresh_token,
)
from sg_token_broker._downstream import closable_stdout
from sg_token_broker._gclaims import ClaimsValidator, OidcClaimsValidator
from sg_token_broker._googleverify import VerifierUnavailableError, google_auth_verifier
from sg_token_broker._http import create_server
from sg_token_broker._oidcverify import OidcUnavailableError, oidc_verifier
from sg_token_broker._secrets import SecretError, generate_secret, hash_secret, resolve_script_key
from sg_token_broker._service import BrokerService
from sg_token_broker._sg import SGError, SGMinter
from sg_token_broker._userauth import (
    SignInError,
    SignInSettingsError,
    account_from_id_token,
    credential_namespace,
    identity_settings,
    sign_in,
)
from sg_token_broker._userclient import (
    UserTokenClient,
    UserTokenClientError,
    UserTokenSettingsError,
)
from sg_token_broker._userconfig import UserConfigError, load_user_token_config
from sg_token_broker._userhttp import create_user_token_server
from sg_token_broker._users import UserDirectory
from sg_token_broker._usertoken import ClaimsPolicy, ServiceAccount, UserTokenService
from sg_token_broker._verify import EXIT_SETUP_ERROR, VerifySetupError, run_revocation_check

_COMMAND_GROUPS: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = (
    (
        'services',
        (
            ('serve-app-tokens', 'run the app-token broker service'),
            (
                'serve-user-tokens',
                'run the user-token service, configured by SGUT_* environment variables',
            ),
            ('check-config', 'validate the broker configuration without starting the broker'),
            ('hash-secret', 'generate a client secret and its hash'),
        ),
    ),
    (
        'clients',
        (
            ('get-token', 'fetch an app token from the broker and print it as JSON'),
            ('login', 'sign in with the studio identity provider'),
            ('logout', 'remove the stored sign-in credential'),
            ('get-user-token', 'fetch a token for the signed-in person and print it as JSON'),
        ),
    ),
    (
        'verification',
        (
            (
                'verify-revocation',
                'check how SG revokes outstanding session tokens, using a disposable script',
            ),
        ),
    ),
)
_COMMAND_HELP = {name: text for _title, commands in _COMMAND_GROUPS for name, text in commands}

_CONTROL_CHARACTERS = re.compile(r'[\x00-\x1f\x7f-\x9f]')


class _ConsoleIO:
    """Console implementation of the verify-revocation I/O surface."""

    def ask(self, message: str) -> str:
        """Prompt on the terminal and return the entered line.

        Args:
            message: Prompt text.

        Returns:
            The entered line.
        """
        return input(message)

    def ask_secret(self, message: str) -> str:
        """Prompt without echo and return the entered value.

        Args:
            message: Prompt text.

        Returns:
            The entered value.
        """
        return getpass.getpass(message)

    def say(self, message: str) -> None:
        """Print one line of output.

        Args:
            message: Output text.
        """
        print(message)


class _RootParser(argparse.ArgumentParser):
    """Render options first and top-level commands under titled groups."""

    def format_help(self, formatter: argparse.HelpFormatter | None = None) -> str:
        """Return help with options first and commands in titled groups."""
        if formatter is None:
            formatter = self._get_formatter()
        formatter.add_usage(self.usage, self._actions, self._mutually_exclusive_groups)
        formatter.add_text(self.description)
        formatter.start_section('options')
        formatter.add_arguments(self._get_optional_actions())
        formatter.end_section()
        for title, commands in _COMMAND_GROUPS:
            formatter.start_section(title)
            formatter.add_arguments(
                [argparse.Action([], name, help=text) for name, text in commands]
            )
            formatter.end_section()
        formatter.add_text(self.epilog)
        return formatter.format_help()


def _non_negative_int(value: str) -> int:
    """Argparse type: a non-negative integer."""
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError(f'must be >= 0, got {value}')
    return number


def _positive_finite_float(value: str) -> float:
    """Parse a finite floating-point value greater than zero."""
    number = float(value)
    if not (math.isfinite(number) and number > 0):
        raise argparse.ArgumentTypeError('must be a finite floating-point value greater than zero')
    return number


def _print_version() -> int:
    """Print the installed distribution version without other work."""
    try:
        version = importlib.metadata.version('sg-token-broker')
    except importlib.metadata.PackageNotFoundError:
        print(
            'error: installed distribution metadata for sg-token-broker is unavailable',
            file=sys.stderr,
        )
        return 2
    print(f'sg-token-broker {version}')
    return 0


def _report_error(message: str) -> None:
    """Print one terminal-safe error line to standard error."""
    visible = _CONTROL_CHARACTERS.sub(lambda match: f'\\x{ord(match.group()):02x}', message)
    print(f'error: {visible}', file=sys.stderr)


def _cmd_get_token(args: argparse.Namespace) -> int:
    """Fetch a token from the broker and print it as JSON."""
    options = ClientOptions(timeout=args.timeout, retries=args.retries)
    try:
        client = BrokerClient(options=options)
    except BrokerClientError as exc:
        _report_error(str(exc))
        return 2
    try:
        token = client.fetch_token(args.scope, args.token_type)
    except BrokerClientError as exc:
        _report_error(str(exc))
        return 1
    print(
        json.dumps(
            {
                'token': token.token,
                'token_type': token.token_type,
                'scope': token.scope,
                'site_url': token.site_url,
                'expires_at': token.expires_at.isoformat(),
            }
        )
    )
    return 0


def _cmd_get_user_token(args: argparse.Namespace) -> int:
    """Fetch a user token via the library's default sign-in flow."""
    try:
        client = UserTokenClient()
    except UserTokenSettingsError as exc:
        _report_error(str(exc))
        return 2
    except UserTokenClientError as exc:
        _report_error(str(exc))
        return 1
    try:
        token = client.fetch_token(args.token_type, force_refresh=args.force_refresh)
    except (UserTokenClientError, SignInError) as exc:
        _report_error(str(exc))
        return 1
    print(
        json.dumps(
            {
                'token': token.token,
                'token_type': token.token_type,
                'login': token.login,
                'site_url': token.site_url,
                'expires_at': token.expires_at.isoformat() if token.expires_at else None,
                'cache_until': token.cache_until.isoformat(),
            }
        )
    )
    return 0


def _cmd_hash_secret(args: argparse.Namespace) -> int:
    """Generate (or hash a provided) client secret."""
    secret = generate_secret() if args.secret is None else args.secret
    if not is_credential_text(secret):
        _report_error('secret must be non-empty printable ASCII with no spaces')
        return 2
    print(f'secret: {secret}')
    print(f'hash: {hash_secret(secret)}')
    return 0


def _cmd_login(args: argparse.Namespace) -> int:
    """Interactively sign in; optionally store the refresh credential."""
    try:
        client_id, issuer_key, auth_endpoint, token_endpoint = identity_settings()
        bundle = sign_in(
            client_id,
            authorization_endpoint=auth_endpoint,
            token_endpoint=token_endpoint,
            request_offline_access=not args.no_store,
        )
        account = account_from_id_token(bundle.id_token)
    except SignInSettingsError as exc:
        _report_error(str(exc))
        return 2
    except SignInError as exc:
        _report_error(str(exc))
        return 1
    stored = False
    if not args.no_store and bundle.refresh_token is not None:
        stored = store_refresh_token(issuer_key, client_id, account, bundle.refresh_token)
        if stored and not store_account(issuer_key, client_id, account):
            print(
                f'warning: account pointer not saved; set SG_USER_TOKEN_ACCOUNT={account} '
                f'to use the stored credential',
                file=sys.stderr,
            )
    print(f'signed in as {account}' + ('' if stored else ' (credential not stored)'))
    return 0


def _cmd_logout(args: argparse.Namespace) -> int:
    """Remove the stored refresh credential and account pointer."""
    del args
    try:
        client_id, issuer_key = credential_namespace()
    except SignInSettingsError as exc:
        _report_error(str(exc))
        return 2
    pointer = load_account(issuer_key, client_id)
    account = os.environ.get('SG_USER_TOKEN_ACCOUNT', '').strip() or (pointer or '')
    if not account:
        _report_error('no signed-in account found')
        return 1
    if not delete_refresh_token(issuer_key, client_id, account):
        _report_error(f'could not remove stored credential for {account}')
        return 1
    # Remove the pointer only when it names the account being signed
    # out; an env override for a different account must not orphan the
    # last signed-in account's pointer.
    if pointer == account and not delete_account(issuer_key, client_id):
        _report_error('credential removed, but account pointer remains')
        return 1
    print(f'signed out {account}')
    return 0


def _cmd_serve_user_tokens(args: argparse.Namespace) -> int:
    """Run the user-token service until interrupted."""
    del args
    logging.basicConfig(level=logging.INFO, format='%(message)s', stream=sys.stdout)
    try:
        config = load_user_token_config(os.environ)
    except UserConfigError as exc:
        _report_error(str(exc))
        return 2
    claims: ClaimsPolicy
    if config.provider == 'oidc':
        issuer = config.issuer
        if issuer is None:  # enforced by load_user_token_config
            raise RuntimeError('OIDC provider has no issuer')
        try:
            verifier = oidc_verifier(issuer, config.oidc_algorithms)
        except OidcUnavailableError as exc:
            _report_error(str(exc))
            return 2
        except (ValueError, requests.RequestException) as exc:
            _report_error(f'cannot verify identity tokens: {exc}')
            return 1
        claims = OidcClaimsValidator(
            verifier,
            config.audiences,
            config.allowed_domain,
            email_claim=config.email_claim,
            assume_email_verified=config.assume_email_verified,
        )
    else:
        try:
            claims = ClaimsValidator(
                google_auth_verifier(), config.audiences, config.allowed_domain
            )
        except VerifierUnavailableError as exc:
            _report_error(str(exc))
            return 2
    minter = SGMinter(config.site_url)
    service = UserTokenService(
        ServiceAccount(config.site_url, config.script_name, config.script_key),
        claims,
        UserDirectory(config.site_url, minter, config.script_name, config.script_key),
        minter,
        AuditLogger(),
        token_types=config.token_types,
        session_ttl_seconds=config.session_ttl_seconds,
    )
    # '' binds all interfaces, which Cloud Run requires.
    try:
        server = create_user_token_server(
            '', config.port, service, trusted_proxies=config.trusted_proxies
        )
    except OSError as exc:
        _report_error(
            f'cannot start the user-token service on port {config.port}: {exc.strerror or exc}'
        )
        return 1
    print(f'serving user tokens on port {server.server_address[1]}', file=sys.stderr)
    # Cloud Run stops instances with SIGTERM (default disposition: abrupt exit,
    # skipping the finally). Accepted: the service is stateless, handlers are
    # sub-second, and Cloud Run drains routing before the signal.
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def _cmd_verify_revocation(args: argparse.Namespace) -> int:
    """Interactively verify SG revocation behavior against a real site."""
    session = requests.Session()
    if args.proxy:
        session.proxies = {'http': args.proxy, 'https': args.proxy}
    if args.insecure:
        print(
            'warning: TLS verification disabled; only use with a disposable script key',
            file=sys.stderr,
        )
        session.verify = False
        warnings.simplefilter('ignore', urllib3.exceptions.InsecureRequestWarning)
    elif args.ca_bundle:
        session.verify = args.ca_bundle
    try:
        minter = SGMinter(args.site_url, session=session)
    except SGError as exc:
        _report_error(str(exc))
        return EXIT_SETUP_ERROR
    if args.script_key_env:
        try:
            key = resolve_script_key(env=args.script_key_env, file=None)
        except SecretError as exc:
            _report_error(str(exc))
            return EXIT_SETUP_ERROR
    else:
        key = getpass.getpass(f'application key for {args.script_name!r}: ')
    try:
        return run_revocation_check(minter, args.script_name, key, _ConsoleIO())
    except VerifySetupError as exc:
        _report_error(str(exc))
        return EXIT_SETUP_ERROR
    except SGError as exc:
        _report_error(f'revocation check is inconclusive: {exc}')
        return EXIT_SETUP_ERROR


def _resolve_config_keys(config: BrokerConfig) -> list[str]:
    """Collect one error message per scope whose script key does not resolve."""
    errors: list[str] = []
    for name, scope in config.scopes.items():
        try:
            resolve_script_key(env=scope.script_key_env, file=scope.script_key_file)
        except SecretError as exc:
            errors.append(f'scope {name!r}: {exc}')
    return errors


def _cmd_check_config(args: argparse.Namespace) -> int:
    """Validate the config file without starting the server."""
    try:
        config = load_config(Path(args.config))
    except ConfigError as exc:
        _report_error(str(exc))
        return 2
    key_errors = _resolve_config_keys(config)
    if key_errors:
        _report_error('; '.join(key_errors))
        return 2
    print(f'ok: {len(config.scopes)} scope(s), {len(config.clients)} client(s)')
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    """Run the broker service until interrupted."""
    logging.basicConfig(level=logging.INFO, format='%(message)s', stream=sys.stderr)
    try:
        config = load_config(Path(args.config))
    except ConfigError as exc:
        _report_error(str(exc))
        return 2
    key_errors = _resolve_config_keys(config)
    if key_errors:
        _report_error('; '.join(key_errors))
        return 2
    service = BrokerService(
        config=config,
        minter=SGMinter(config.site_url),
        cache=TTLCache(),
        audit=AuditLogger(),
    )
    try:
        server = create_server(config, service)
    except ssl.SSLError as exc:
        _report_error(f'cannot load the TLS certificate and key: {exc}')
        return 2
    except OSError as exc:
        _report_error(
            f'cannot start the broker on port {config.server.port}: {exc.strerror or exc}'
        )
        return 1
    scheme = 'https' if config.server.tls else 'http'
    host = config.server.bind
    if ':' in host:
        host = f'[{host}]'
    print(
        f'serving on {scheme}://{host}:{server.server_address[1]}',
        file=sys.stderr,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all subcommands."""
    parser = _RootParser(
        prog='sg-token-broker',
        description='Issue SG tokens to pipeline tools without giving them SG script keys.',
    )
    parser.add_argument('--version', action='store_true', help='show the version and exit')
    commands = parser.add_subparsers(
        dest='command', metavar='COMMAND', parser_class=argparse.ArgumentParser
    )

    serve = commands.add_parser(
        'serve-app-tokens',
        help=_COMMAND_HELP['serve-app-tokens'],
        description='Run the app-token broker until it is stopped.',
    )
    serve.add_argument(
        '--config', required=True, metavar='FILE', help='broker YAML configuration file'
    )
    serve.set_defaults(func=_cmd_serve)

    serve_user = commands.add_parser(
        'serve-user-tokens',
        help=_COMMAND_HELP['serve-user-tokens'],
        description=(
            'Run the user-token service until it is stopped, with settings from SGUT_* '
            'environment variables.'
        ),
    )
    serve_user.set_defaults(func=_cmd_serve_user_tokens)

    check = commands.add_parser(
        'check-config',
        help=_COMMAND_HELP['check-config'],
        description=(
            'Validate the broker configuration, including its TLS files and script keys, '
            'without starting the broker.'
        ),
    )
    check.add_argument(
        '--config', required=True, metavar='FILE', help='broker YAML configuration file'
    )
    check.set_defaults(func=_cmd_check_config)

    hash_cmd = commands.add_parser(
        'hash-secret',
        help=_COMMAND_HELP['hash-secret'],
        description='Print a new client secret and its hash, or the hash of a given secret.',
    )
    hash_cmd.add_argument(
        '--secret',
        metavar='SECRET',
        help='hash this printable-ASCII secret instead of generating one',
    )
    hash_cmd.set_defaults(func=_cmd_hash_secret)

    get = commands.add_parser(
        'get-token',
        help=_COMMAND_HELP['get-token'],
        description=(
            'Fetch an app token from the broker and print it as JSON, using the '
            'SG_TOKEN_BROKER_* environment variables.'
        ),
    )
    get_request = get.add_argument_group('request')
    get_request.add_argument(
        '--scope', required=True, metavar='NAME', help='broker scope to request'
    )
    get_request.add_argument(
        '--token-type',
        default='session',
        choices=['session', 'rest'],
        help='token type to request (default: session)',
    )
    get_connection = get.add_argument_group('connection')
    get_connection.add_argument(
        '--timeout',
        type=_positive_finite_float,
        default=10.0,
        metavar='SECONDS',
        help='seconds to wait for each broker request (default: 10)',
    )
    get_connection.add_argument(
        '--retries',
        type=_non_negative_int,
        default=2,
        metavar='COUNT',
        help='retries after a connection failure or server error (default: 2)',
    )
    get.set_defaults(func=_cmd_get_token)

    login = commands.add_parser(
        'login',
        help=_COMMAND_HELP['login'],
        description=(
            'Sign in through the browser with the studio identity provider, storing the '
            'refresh credential when a supported keyring is available.'
        ),
    )
    login.add_argument(
        '--no-store',
        action='store_true',
        help='do not store the refresh credential, for shared or ephemeral machines',
    )
    login.set_defaults(func=_cmd_login)

    logout = commands.add_parser(
        'logout',
        help=_COMMAND_HELP['logout'],
        description="Remove the selected account's stored sign-in credential.",
    )
    logout.set_defaults(func=_cmd_logout)

    get_user = commands.add_parser(
        'get-user-token',
        help=_COMMAND_HELP['get-user-token'],
        description=(
            "Fetch an SG token bound to the signed-in person's SG account and print it as "
            'JSON, signing in through the browser when no stored credential is available.'
        ),
    )
    get_user.add_argument(
        '--token-type',
        default='session',
        choices=['session', 'rest'],
        help='token type to request (default: session)',
    )
    get_user.add_argument(
        '--force-refresh',
        action='store_true',
        help='ask the service to check its cached session with SG and replace it if SG rejects it',
    )
    get_user.set_defaults(func=_cmd_get_user_token)

    verify = commands.add_parser(
        'verify-revocation',
        help=_COMMAND_HELP['verify-revocation'],
        description=(
            'Walk an SG administrator through testing how the site revokes outstanding '
            'session tokens.'
        ),
        epilog=(
            'Exit status: 0 if a procedure retired the token immediately, 1 if the token '
            'survived every step tried, 2 if setup failed or an SG error made the run '
            'inconclusive, and 3 if the run ended on an unverified step.'
        ),
    )
    verify_target = verify.add_argument_group('site and script')
    verify_target.add_argument('--site-url', required=True, metavar='URL', help='SG site URL')
    verify_target.add_argument(
        '--script-name',
        required=True,
        metavar='NAME',
        help='name of the disposable ApiUser script to test with',
    )
    verify_target.add_argument(
        '--script-key-env',
        metavar='NAME',
        help='environment variable that holds the application key (prompts without echo '
        'if omitted)',
    )
    verify_connection = verify.add_argument_group('connection')
    verify_connection.add_argument(
        '--proxy',
        metavar='URL',
        help='HTTP(S) proxy URL, e.g. http://squid:8080 '
        '(HTTP_PROXY/HTTPS_PROXY env vars are honored without this flag)',
    )
    verify_connection.add_argument(
        '--ca-bundle',
        metavar='FILE',
        help='CA bundle file for TLS verification, e.g. the corporate root CA when the '
        'proxy intercepts TLS (REQUESTS_CA_BUNDLE env var is honored without this flag)',
    )
    verify_connection.add_argument(
        '--insecure',
        action='store_true',
        help='disable TLS verification; use only for a one-off test with a disposable key',
    )
    verify.set_defaults(func=_cmd_verify_revocation)

    return parser


def _run(arguments: list[str]) -> int:
    """Parse arguments and run the selected command."""
    parser = _build_parser()
    args = parser.parse_args(arguments)
    if args.version:
        return _print_version()
    if args.command is None:
        parser.error('the following arguments are required: COMMAND')
    result: int = args.func(args)
    return result


def main(argv: Iterable[str] | None = None) -> int:
    """Run the sg-token-broker command-line interface.

    If a reader closes standard output early, the command keeps running and
    remaining output is discarded. The exit status reflects the command's
    outcome.

    Args:
        argv: Arguments to parse, or `None` to use `sys.argv[1:]`.

    Returns:
        The command's exit status, 2 if standard output is unavailable, or
        130 if an uncaught keyboard interrupt stops the command.

    Raises:
        SystemExit: With status 0 for help or 2 for invalid arguments.
    """
    if sys.stdout is None:
        # Started with standard output closed: nothing can be delivered, and the
        # closed-stdout wrapper cannot wrap a missing stream.
        _report_error('standard output is unavailable')
        return 2
    with closable_stdout():
        try:
            return _run(sys.argv[1:] if argv is None else list(argv))
        except KeyboardInterrupt:
            return 130
