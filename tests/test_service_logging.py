import atexit
import base64
import faulthandler
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import threading
import warnings
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, nullcontext, suppress
from http.client import HTTPConnection
from io import BytesIO, TextIOWrapper
from logging.handlers import MemoryHandler
from pathlib import Path
from typing import TextIO
from unittest.mock import Mock, patch

import jwt
import pytest
import requests
import urllib3
from google.auth.transport import requests as google_transport
from google.oauth2 import id_token
from requests.adapters import HTTPAdapter
from urllib3 import connection
from urllib3.exceptions import HeaderParsingError

from sg_token_broker import _cli, _http, _httpbase, _userhttp
from sg_token_broker._config import ConfigError
from sg_token_broker._servicelog import service_logging
from sg_token_broker._sg import MintedToken, SGError, SGMinter
from sg_token_broker._userconfig import UserConfigError
from sg_token_broker._usertoken import UserTokenService
from tests._timeouts import STALL_TIMEOUT_SECONDS
from tests.cli_helpers import invoke_cli, process_transcript, run_setup
from tests.conftest import BROKER_CREDENTIAL, BROKER_HASH, FakeSG

_MARKER = 'PRIVATE-upstream-credential'
_AUDIENCE = 'public-client'


def _configure_user_service(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in {
        'SGUT_TOKEN_TYPES': 'rest',
        'SGUT_SITE_URL': 'https://sg.example',
        'SGUT_SCRIPT_NAME': 'script',
        'SGUT_SCRIPT_KEY': 'key',
        'SGUT_AUDIENCES': _AUDIENCE,
        'SGUT_ALLOWED_DOMAIN': 'example.com',
        'SGUT_PROVIDER': 'google',
    }.items():
        monkeypatch.setenv(name, value)


def _outcome_request(command: str, outcome: str) -> bytes:
    if outcome == 'parser':
        return b'GET / extra HTTP/1.1\r\n'
    if outcome == 'deny':
        return b'PATCH / HTTP/1.1\r\n\r\n'
    if command == 'serve-user-tokens':
        return b'GET /v1/user-token HTTP/1.1\r\nAuthorization: Bearer presented\r\n\r\n'
    basic = base64.b64encode(f'test:{BROKER_CREDENTIAL}'.encode())
    body = b'{"scope":"test"}'
    return (
        b'POST /v1/token HTTP/1.1\r\nAuthorization: Basic '
        + basic
        + f'\r\nContent-Length: {len(body)}\r\n\r\n'.encode()
        + body
    )


def _run_deferred_probe() -> None:
    receipt = Path(sys.argv.pop())

    class DeferredTarget(logging.StreamHandler[TextIO]):
        def emit(self, record: logging.LogRecord) -> None:
            super().emit(record)
            with receipt.open('a', encoding='ascii') as file:
                file.write('delivered\n')

    def load(_config: object) -> None:
        logger = logging.getLogger('deferred.provider')
        logger.propagate = False
        buffers = [
            MemoryHandler(capacity=10, target=DeferredTarget(stream))
            for stream in (sys.stdout, sys.stderr)
        ]
        for buffer in buffers:
            logger.addHandler(buffer)
        logger.warning(_MARKER)
        assert all(buffer.buffer for buffer in buffers)
        assert not receipt.exists()
        error = ConfigError if sys.argv[1] == 'serve-app-tokens' else UserConfigError
        raise error('service setup stopped')

    with (
        patch.object(_cli, 'load_config', load),
        patch.object(_cli, 'load_user_token_config', load),
    ):
        raise SystemExit(_cli.main())


def _run_fault_probe() -> None:
    real_enable = faulthandler.enable

    def enable(*, file: int | TextIO) -> None:
        real_enable(file=file)

        def dump_at_exit() -> None:
            faulthandler.dump_traceback(file=file)

        atexit.register(dump_at_exit)
        faulthandler.dump_traceback(file=file)

    with patch.object(faulthandler, 'enable', enable):
        raise SystemExit(_cli.main())


def _service_args(command: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    args = [command]
    if command == 'serve-app-tokens':
        config = tmp_path / 'config.yml'
        config.write_text(
            'site_url: https://sg.example\nserver: {bind: 127.0.0.1, port: 0}\n'
            'scopes: {test: {script_name: script, script_key_env: SGTB_TEST_KEY}}\n'
            f'clients: {{test: {{secret_hash: "{BROKER_HASH}", scopes: [test]}}}}\n'
        )
        monkeypatch.setenv('SGTB_TEST_KEY', 'key')
        args.extend(['--config', str(config)])
    else:
        _configure_user_service(monkeypatch)
    return args


def _stub_mint(monkeypatch: pytest.MonkeyPatch, outcome: str) -> None:
    claims = {
        'email': 'user@example.com',
        'hd': 'example.com',
        'aud': _AUDIENCE,
        'email_verified': True,
    }
    monkeypatch.setattr(id_token, 'verify_oauth2_token', Mock(return_value=claims))
    monkeypatch.setattr(_cli.UserDirectory, 'resolve_login', Mock(return_value='user'))
    mint = Mock(return_value=MintedToken('issued', 600))
    if outcome == 'error':
        mint.side_effect = RuntimeError('mint failed')
    monkeypatch.setattr(SGMinter, 'mint_rest_token', mint)
    monkeypatch.setattr(SGMinter, 'mint_session_token', mint)


def _run_signal_probe() -> None:
    signum = int(sys.argv.pop())
    held = threading.Event()
    release = threading.Event()
    flush_headers = _httpbase.JsonErrorHandler.flush_headers

    def hold_response(handler: _httpbase.JsonErrorHandler) -> None:
        os.write(1, _MARKER.encode())
        os.write(2, _MARKER.encode())
        held.set()
        release.wait()
        flush_headers(handler)

    def signal_when_held(_server: object) -> None:
        if held.is_set():
            try:
                signal.raise_signal(signum)
            finally:
                release.set()
            raise AssertionError('stop signal returned')

    def create(_bind: str, _port: int, service: UserTokenService, **_kwargs: object) -> object:
        return _userhttp.create_user_token_server('127.0.0.1', 0, service)

    with (
        pytest.MonkeyPatch.context() as monkeypatch,
        patch.object(_cli, 'create_user_token_server', create),
        patch.object(_httpbase.JsonErrorHandler, 'flush_headers', hold_response),
        patch.object(_httpbase.BoundedThreadingHTTPServer, 'service_actions', signal_when_held),
    ):
        _stub_mint(monkeypatch, 'issue')
        raise SystemExit(_cli.main())


def test_broker_log_reduces_dependency_warnings(
    monkeypatch: pytest.MonkeyPatch, fake_sg: FakeSG
) -> None:
    monkeypatch.setattr(
        connection, 'assert_header_parsing', Mock(side_effect=HeaderParsingError([], _MARKER))
    )

    def load(_path: Path) -> None:
        requests.get(fake_sg.url, timeout=STALL_TIMEOUT_SECONDS)
        logging.getLogger('third.party').warning('external %s', _MARKER)
        raise ConfigError('invalid configuration')

    monkeypatch.setattr(_cli, 'load_config', load)
    status, _stdout, log = invoke_cli(['serve-app-tokens', '--config', 'unused'])
    assert status == 2
    assert _MARKER not in log
    assert 'urllib3.connection' in log
    assert 'WARNING' in log
    assert 'malformed headers' in log
    assert 'HeaderParsingError' in log
    assert 'connection.py' in log
    assert 'in getresponse' in log
    assert 'third.party' in log
    assert 'external' not in log


def test_host_handlers_and_reconstructed_records_survive_service() -> None:
    root = logging.getLogger()
    previous = root.handlers, root.level, warnings.showwarning, sys.excepthook
    provider = logging.getLogger('host.service.receiver')
    handler = logging.StreamHandler(sys.stderr)
    try:
        with service_logging(sys.stdout, 'sg_token_broker.http'):
            record = logging.makeLogRecord(
                {'name': 'receiver', 'msg': 'received', 'levelno': logging.WARNING}
            )
            provider.addHandler(handler)
            provider.propagate = False
            provider.handle(record)
            provider.warning('host warning')
        assert handler in provider.handlers
        assert not provider.propagate
        assert (root.handlers, root.level, warnings.showwarning, sys.excepthook) == previous
    finally:
        provider.removeHandler(handler)
        provider.propagate = True
        handler.close()


def test_http_parser_logs_status_without_request_line(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    handler = _userhttp._Handler.__new__(_userhttp._Handler)
    handler.client_address = ('127.0.0.1', 1234)
    handler.rfile = BytesIO(f'GET /{_MARKER} extra HTTP/1.1\r\n'.encode())
    handler.wfile = BytesIO()
    name = 'sg_token_broker.userhttp'
    monkeypatch.setattr(logging.getLogger(name), 'level', logging.DEBUG)
    with service_logging(sys.stdout, name) as writer:
        handler.server = Mock(logger=writer, trusted_proxies=frozenset())
        handler.handle_one_request()
        assert handler.wfile.getvalue().startswith(b'HTTP/1.1 400')
    stdout, stderr = capsys.readouterr()
    assert _MARKER not in stdout + stderr
    assert '400' in stdout


def test_import_preserves_host_logging() -> None:
    probe = """
import logging, sys, warnings
root = logging.getLogger()
handler = logging.StreamHandler()
provider = logging.getLogger('provider')
provider.addHandler(handler)
provider.propagate = False
root.addHandler(handler)
before = root.level, logging.getLogRecordFactory(), warnings.showwarning, sys.excepthook
from sg_token_broker import BrokerClient, _servicelog
assert root.handlers == provider.handlers == [handler]
assert not provider.propagate
assert before == (root.level, logging.getLogRecordFactory(), warnings.showwarning, sys.excepthook)
provider.warning('host output')
"""
    assert run_setup([sys.executable, '-c', probe]).stderr.splitlines() == [b'host output']


@pytest.fixture
def user_request(monkeypatch: pytest.MonkeyPatch) -> Callable[[str], tuple[int, str]]:
    _configure_user_service(monkeypatch)

    def request(token: str) -> tuple[int, str]:
        statuses: list[int] = []

        def create(
            _bind: str, _port: int, service: UserTokenService, **_kwargs: object
        ) -> _userhttp._UserTokenHTTPServer:
            server = _userhttp.create_user_token_server('127.0.0.1', 0, service)

            def serve_one() -> None:
                with ThreadPoolExecutor(1) as pool:
                    accept = pool.submit(server.handle_request)
                    with closing(
                        HTTPConnection(
                            '127.0.0.1', server.server_port, timeout=STALL_TIMEOUT_SECONDS
                        )
                    ) as client:
                        client.request(
                            'GET', '/v1/user-token', headers={'Authorization': f'Bearer {token}'}
                        )
                        with client.getresponse() as response:
                            statuses.append(response.status)
                            response.read()
                    accept.result()

            monkeypatch.setattr(server, 'serve_forever', serve_one)
            return server

        monkeypatch.setattr(_cli, 'create_user_token_server', create)
        status, log, _stderr = invoke_cli(['serve-user-tokens'])
        assert _MARKER not in _stderr
        assert status == 0, _stderr
        return statuses[0], log

    return request


def test_google_ca_diagnosis_reaches_service_log(
    user_request: Callable[[str], tuple[int, str]], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    missing = str(tmp_path / 'configured-ca.pem')
    monkeypatch.setenv('REQUESTS_CA_BUNDLE', missing)
    status, log = user_request('presented')
    assert status == 500
    assert missing in log


@pytest.mark.parametrize(
    ('http_status', 'body', 'expected'),
    [
        (200, b'{"keys":[{"kty":"oct","k":"cHVibGlj","kid":"known","alg":"HS256"}]}', 401),
        (
            200,
            json.dumps(
                {
                    'keys': [
                        {'kty': 'oct', 'k': 'cHVibGlj', 'kid': 'known', 'alg': 'HS256'},
                        {'kty': 'unsupported', 'kid': _MARKER},
                    ]
                }
            ).encode(),
            500,
        ),
        (503, _MARKER.encode(), 500),
        (200, _MARKER.encode(), 500),
        (200, b'{}', 500),
        (200, b'{"keys":[]}', 500),
        (200, json.dumps({'known': _MARKER}).encode(), 500),
    ],
    ids=[
        'unknown-kid',
        'unusable-selected-kid',
        'outage',
        'non-json',
        'empty-x509',
        'empty-jwks',
        'invalid-x509',
    ],
)
def test_google_provider_service_log(
    user_request: Callable[[str], tuple[int, str]],
    monkeypatch: pytest.MonkeyPatch,
    http_status: int,
    body: bytes,
    expected: int,
) -> None:
    monkeypatch.setattr(
        google_transport.Request,
        '__call__',
        Mock(return_value=Mock(status=http_status, data=body)),
    )
    token = jwt.encode({}, key=b'x' * 32, algorithm='HS256', headers={'kid': _MARKER})
    status, log = user_request(token)
    assert status == expected
    assert _MARKER not in log
    reason = json.loads(log.splitlines()[0])['reason']
    if expected == 401:
        assert reason == 'unauthorized'
    else:
        assert reason == 'internal_error'
        assert 'Google certificate' in log
        assert 'in verify' in log
        if http_status == 503:
            assert 'TransportError' in log


@pytest.mark.parametrize('redirect', [True, False], ids=['redirect', 'cold-key'])
def test_directory_failure_service_log(
    user_request: Callable[[str], tuple[int, str]],
    monkeypatch: pytest.MonkeyPatch,
    *,
    redirect: bool,
) -> None:
    claims = {
        'email': 'user@example.com',
        'hd': 'example.com',
        'aud': _AUDIENCE,
        'email_verified': True,
    }
    monkeypatch.setattr(id_token, 'verify_oauth2_token', Mock(return_value=claims))
    if redirect:
        response = requests.Response()
        response.status_code = 302
        response.url = 'https://sg.example/users'
        response.headers['Location'] = f'https://[{_MARKER}]/'
        response.raw = BytesIO(b'')
        monkeypatch.setattr(
            SGMinter, 'mint_rest_token', Mock(return_value=MintedToken('bearer', 600))
        )
        monkeypatch.setattr(HTTPAdapter, 'send', Mock(return_value=response))
    else:
        response = requests.Response()
        response.status_code = 401
        response.raw = BytesIO(json.dumps({'errors': [{'title': _MARKER}]}).encode())
        monkeypatch.setattr(requests.Session, 'post', Mock(return_value=response))
    status, log = user_request('presented')
    assert _MARKER not in log
    assert status == (503 if redirect else 502)
    detail = json.loads(log)['detail']
    assert ('ValueError' if redirect else 'check the SG script name and key') in detail


class _ProviderFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = vars(record).get('response_body', _MARKER)
        record.args = ()
        record.exc_text = _MARKER
        record.stack_info = _MARKER
        return True


def _exercise_process_output() -> None:
    urllib3.add_stderr_logger(logging.WARNING)
    logging.getLogger('urllib3.connection').warning(_MARKER)
    logging.getLogger('provider.isolated').warning(_MARKER)
    late = logging.getLogger('provider.late')
    late.propagate = False
    late.addHandler(logging.StreamHandler())
    late.warning(_MARKER)
    provider = logging.getLogger('provider.transport')
    provider.addFilter(_ProviderFilter())
    provider.warning('provider response', extra={'response_body': _MARKER})
    with closing(HTTPConnection('unused.invalid')) as client:
        client.sock = Mock()
        client.set_debuglevel(1)
        client.send(_MARKER.encode())
    warnings.warn(_MARKER, RuntimeWarning, stacklevel=2)
    print(_MARKER)
    os.write(1, _MARKER.encode())
    os.write(2, _MARKER.encode())
    raise ArithmeticError(_MARKER)


def _run_service_probe() -> None:
    # Use the real command, audit emitter and HTTP client. Only its server is a double.
    server = Mock(server_address=('127.0.0.1', 8743))
    create = Mock(return_value=server)
    previous = sys.stdout, sys.stderr, warnings.showwarning, sys.excepthook
    previous_signals = signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT)
    stdout_fd, stderr_fd = os.fstat(1), os.fstat(2)
    isolated = logging.getLogger('provider.isolated')
    isolated.propagate = False
    isolated.addHandler(logging.StreamHandler(sys.stdout))
    logging.getLogger('sg_token_broker.audit').addFilter(_ProviderFilter())

    def serve() -> None:
        service = create.call_args.args[-1]
        service.log_denied_request(reason='unauthorized', source_ip='127.0.0.1', request_id='one')
        previous[0].write(_MARKER)
        _exercise_process_output()

    server.serve_forever.side_effect = serve
    with (
        patch.object(_cli, 'create_server', create),
        patch.object(_cli, 'create_user_token_server', create),
    ):
        try:
            raise SystemExit(_cli.main(sys.argv[1:]))
        finally:
            assert (sys.stdout, sys.stderr, warnings.showwarning, sys.excepthook) == previous
            assert (
                signal.getsignal(signal.SIGTERM),
                signal.getsignal(signal.SIGINT),
            ) == previous_signals
            assert os.path.samestat(stdout_fd, os.fstat(1))
            assert os.path.samestat(stderr_fd, os.fstat(2))
            logging.getLogger('provider.late').warning('host handler restored')


@pytest.mark.parametrize('command', ['serve-app-tokens', 'serve-user-tokens'])
def test_service_process_output(
    command: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = _service_args(command, tmp_path, monkeypatch)
    probe = f'from {__name__} import {_run_service_probe.__name__} as probe; probe()'
    result = run_setup([sys.executable, '-c', probe, *args], check=False)
    assert result.returncode == 1, process_transcript(result)
    stdout, stderr = result.stdout.decode(), result.stderr.decode()
    assert _MARKER not in stdout + stderr
    assert stderr.splitlines()[-1] == 'host handler restored'
    if command == 'serve-app-tokens':
        assert not stdout
        assert 'serving on ' in stderr
        log = stderr
    else:
        assert stderr.splitlines() == ['serving user tokens on port 8743', 'host handler restored']
        log = stdout
    [audit] = [json.loads(line) for line in log.splitlines() if line.startswith('{')]
    assert (audit['event'], audit['reason']) == ('deny', 'unauthorized')
    for logger in ('urllib3.connection', 'provider.transport', 'py.warnings'):
        assert log.count(f'{logger} WARNING: dependency diagnostic') == 1
    assert 'ArithmeticError' in log
    assert 'in _exercise_process_output' in log


@pytest.mark.parametrize('command', ['serve-app-tokens', 'serve-user-tokens'])
def test_standalone_deferred_handler_flushes_to_discard_at_exit(
    tmp_path: Path, command: str
) -> None:
    receipt = tmp_path / 'delivery'
    probe = f'from {__name__} import {_run_deferred_probe.__name__} as probe; probe()'
    args = ['--config', 'unused'] if command == 'serve-app-tokens' else []
    result = run_setup(
        [sys.executable, '-c', probe, command, *args, str(receipt)],
        check=False,
    )
    assert result.returncode == 2, process_transcript(result)
    assert receipt.read_text().splitlines() == ['delivered', 'delivered']
    assert _MARKER.encode() not in result.stdout + result.stderr
    assert b'error: service setup stopped' in result.stderr


@pytest.mark.parametrize('enabled', [True, False])
def test_fault_handler_follows_operator_setting_through_exit(
    tmp_path: Path, *, enabled: bool
) -> None:
    probe = f'from {__name__} import {_run_fault_probe.__name__} as probe; probe()'
    result = run_setup(
        [
            sys.executable,
            '-E',
            *(['-X', 'faulthandler'] if enabled else []),
            '-c',
            probe,
            'serve-app-tokens',
            '--config',
            str(tmp_path / 'missing.yml'),
        ],
        check=False,
    )
    assert result.returncode == 2, process_transcript(result)
    assert not result.stdout
    assert (b'in enable' in result.stderr) is enabled
    assert (b'in dump_at_exit' in result.stderr) is enabled


@pytest.mark.parametrize('command', ['serve-app-tokens', 'serve-user-tokens'])
@pytest.mark.parametrize('signum', [signal.SIGTERM, signal.SIGINT])
def test_stop_signal_cuts_off_held_audited_request(
    command: str, signum: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = _service_args(command, tmp_path, monkeypatch)
    probe = f'from {__name__} import {_run_signal_probe.__name__} as probe; probe()'
    with subprocess.Popen(
        [sys.executable, '-c', probe, *args, str(int(signum))],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        try:
            assert process.stderr is not None
            startup = process.stderr.readline()
            port = int(
                startup.rstrip().rsplit(b':' if command == 'serve-app-tokens' else b' ', 1)[1]
            )
            with socket.create_connection(('127.0.0.1', port)) as client:
                client.sendall(_outcome_request(command, 'issue'))
                # Either EOF or a TCP reset cuts the connection before the first byte.
                with suppress(ConnectionResetError):
                    assert client.recv(1) == b''
            stdout, stderr = process.communicate()
        finally:
            process.kill()
    assert process.returncode == 128 + signum
    audit, other = (stderr, stdout) if command == 'serve-app-tokens' else (stdout, stderr)
    assert not other
    record = json.loads(audit)
    assert record['event'] == 'issue'
    assert record['token_fp']
    assert _MARKER.encode() not in startup + stdout + stderr


@pytest.mark.parametrize('command', ['serve-app-tokens', 'serve-user-tokens'])
@pytest.mark.parametrize(
    ('outcome', 'status'), [('issue', 200), ('error', 500), ('deny', 405), ('parser', 400)]
)
def test_audit_write_and_flush_attempt_precedes_first_final_response_byte(
    command: str, outcome: str, status: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = _service_args(command, tmp_path, monkeypatch)
    _stub_mint(monkeypatch, outcome)
    raw_log = BytesIO()
    observed: list[tuple[bytes, bytes]] = []
    server = Mock(
        server_address=('127.0.0.1', 1234), trusted_proxies={_userhttp.normalize_ip('127.0.0.1')}
    )
    create = Mock(return_value=server)

    def response_write(data: bytes) -> int:
        observed.append((data, raw_log.getvalue()))
        return len(data)

    def serve() -> None:
        server.service = create.call_args.args[-1]
        cls = _http._Handler if command == 'serve-app-tokens' else _userhttp._Handler
        handler = cls.__new__(cls)
        handler.server = server
        handler.client_address = ('127.0.0.1', 1234)
        request = _outcome_request(command, outcome)
        if outcome == 'issue':
            request = request.replace(b'HTTP/1.1\r\n', b'HTTP/1.1\r\nExpect: 100-continue\r\n', 1)
        handler.rfile = BytesIO(request)
        handler.wfile = Mock()
        handler.wfile.write.side_effect = response_write
        handler.handle_one_request()

    server.serve_forever.side_effect = serve
    monkeypatch.setattr(_cli, 'create_server', create)
    monkeypatch.setattr(_cli, 'create_user_token_server', create)
    with TextIOWrapper(raw_log, encoding='utf-8') as destination:
        monkeypatch.setattr(
            _cli, 'service_streams', Mock(return_value=nullcontext((destination, destination)))
        )
        assert _cli.main(args) == 0
        [audit_line] = [line for line in raw_log.getvalue().splitlines() if line.startswith(b'{')]
    if outcome == 'issue':
        interim, before_continue = observed.pop(0)
        assert interim == b'HTTP/1.1 100 Continue\r\n\r\n'
        assert audit_line not in before_continue.splitlines()
    first_write, flushed_before_write = observed[0]
    assert first_write.startswith(f'HTTP/1.1 {status} '.encode())
    assert audit_line in flushed_before_write.splitlines()
    audit = json.loads(audit_line)
    assert audit['event'] == ('deny' if outcome == 'parser' else outcome)
    if outcome == 'parser':
        assert audit['reason'] == 'bad_request'
        assert audit['source_ip'] == '127.0.0.1'


def test_user_service_log_keeps_frames_and_local_exception_messages(
    user_request: Callable[[str], tuple[int, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    def resolve() -> None:
        raise SGError('local diagnostic') from ArithmeticError(_MARKER)

    def fail(*_args: object, **_kwargs: object) -> None:
        try:
            resolve()
        except SGError as cause:
            raise RuntimeError(_MARKER) from cause

    monkeypatch.setattr(id_token, 'verify_oauth2_token', fail)
    status, log = user_request('presented')
    assert status == 500
    assert _MARKER not in log
    assert 'RuntimeError' in log
    assert 'in resolve' in log
    assert 'ArithmeticError' in log
    assert 'SGError: local diagnostic' in log
    assert 'in fail' in log
    assert 'in _serve_user_token' in log
    assert 'unhandled error issuing user token' in log
