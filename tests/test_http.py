import base64
import errno
import json
import logging
import socket
import ssl
import threading
from collections.abc import Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from queue import SimpleQueue
from unittest.mock import Mock, patch

import pytest
import requests

from sg_token_broker import _http, _secrets, _service
from sg_token_broker._config import BrokerConfig, _ServerConfig, _TlsConfig
from sg_token_broker._http import create_server
from sg_token_broker._service import BrokerService, TokenRequest
from tests._tls import write_tls_material
from tests.conftest import BROKER_CREDENTIAL, REST_REFRESH_MARKER, FakeSG

_HANDLER = _http._Handler
_SESSION_TYPE = _service._SESSION_TYPE
_VALID_AUTHORIZATION_LINE = (
    f'Authorization: Basic {base64.b64encode(f"farm:{BROKER_CREDENTIAL}".encode()).decode()}\r\n'
)


class TestConnectionLifetime:
    def test_health_response_closes_before_a_pipelined_request(
        self, http_only_broker_url: str
    ) -> None:
        first = b'GET /healthz HTTP/1.1\r\nHost: b\r\n\r\n'
        second = b'GET /healthz HTTP/1.1\r\nHost: b\r\nConnection: close\r\n\r\n'
        raw = _raw_exchange(http_only_broker_url, first + second, allow_reset=True)
        assert raw.startswith(b'HTTP/1.1 200')
        assert raw.count(b'HTTP/1.1 ') == 1


class TestHealthz:
    def test_healthz_ignores_a_query_string(self, http_only_broker_url: str) -> None:
        assert requests.get(f'{http_only_broker_url}/healthz?probe=1').status_code == 200

    def test_ipv6_loopback_round_trip(self) -> None:
        # Probe OS support separately so a product startup failure cannot be skipped.
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
                probe.bind(('::1', 0))
        except OSError as exc:
            if exc.errno in {errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, errno.EADDRNOTAVAIL}:
                pytest.skip(f'OS IPv6 loopback unavailable: {exc}')
            raise

        config = BrokerConfig(
            site_url='https://studio.example.com',
            server=_ServerConfig(bind='::1', port=0, tls=None),
            session_ttl_seconds=600,
            scopes={},
            clients={},
        )
        server = create_server(config, Mock(spec=BrokerService))
        thread = threading.Thread(
            target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True
        )
        thread.start()
        try:
            with requests.Session() as session:
                session.trust_env = False
                response = session.get(f'http://[::1]:{server.server_address[1]}/healthz')
            assert response.status_code == 200
            assert response.json() == {'status': 'ok'}
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        assert not thread.is_alive()

    def test_ok_without_auth(self, http_only_broker_url: str) -> None:
        response = requests.get(f'{http_only_broker_url}/healthz')
        assert response.status_code == 200
        assert response.json() == {'status': 'ok'}

    def test_unknown_get_path_is_404(self, http_only_broker_url: str) -> None:
        response = requests.get(f'{http_only_broker_url}/nope')
        assert response.status_code == 404


class TestTlsAcceptLoop:
    def test_stalled_handshake_does_not_block_later_connections(
        self,
        tls_broker_url: tuple[
            str,
            tuple[str, int],
            _http._BrokerHTTPServer,
            threading.Thread,
            SimpleQueue[threading.Thread | BaseException | None],
        ],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        url, address, server, serve_thread, startup = tls_broker_url
        assert isinstance(server.socket, ssl.SSLSocket)
        assert vars(server.socket)['do_handshake_on_connect'] is False
        setup_threads: list[threading.Thread] = []
        original_setup = _HANDLER.setup

        def setup(handler: _http._Handler) -> None:
            if handler.server is not server:
                original_setup(handler)
                return
            setup_threads.append(threading.current_thread())
            try:
                original_setup(handler)
            except BaseException as exc:
                startup.put(exc)
                raise
            startup.put(threading.current_thread())

        monkeypatch.setattr(_HANDLER, 'setup', setup)
        try:
            with socket.create_connection(address):
                started = startup.get()
                assert isinstance(started, threading.Thread), f'handler did not start: {started!r}'
                assert started is not serve_thread
                response = requests.get(
                    f'{url}/healthz',
                    verify=str(tmp_path / 'certificate.pem'),
                )
        finally:
            for worker in setup_threads:
                worker.join()
        assert response.status_code == 200
        assert len(setup_threads) == 2
        assert all(thread is not serve_thread for thread in setup_threads)


def _auth_header(client_id: str = 'farm', secret: str = BROKER_CREDENTIAL) -> dict[str, str]:
    creds = base64.b64encode(f'{client_id}:{secret}'.encode()).decode()
    return {'Authorization': f'Basic {creds}'}


def _raw_exchange(
    broker_url: str, payload: bytes, *, allow_reset: bool = False, half_close: bool = False
) -> bytes:
    host, _, port = broker_url.removeprefix('http://').partition(':')
    with socket.create_connection((host, int(port))) as sock:
        sock.sendall(payload)
        if half_close:
            sock.shutdown(socket.SHUT_WR)
        chunks: list[bytes] = []
        while True:
            try:
                data = sock.recv(65536)
            except ConnectionResetError:
                if not allow_reset:
                    raise
                # Linux may reset after rejecting unread client bytes. The full
                # response must still have arrived; verify its framing below.
                break
            if not data:
                break
            chunks.append(data)
    raw = b''.join(chunks)
    head, separator, body = raw.partition(b'\r\n\r\n')
    assert separator, 'connection closed before complete response headers'
    lengths = [
        line.partition(b':')[2].strip()
        for line in head.split(b'\r\n')[1:]
        if line.lower().startswith(b'content-length:')
    ]
    assert len(lengths) == 1, 'expected one response Content-Length'
    assert b'connection: close' in head.lower()
    expected_length = 0 if payload.startswith(b'HEAD ') else int(lengths[0])
    assert len(body) == expected_length, 'connection closed before the complete response body'
    return raw


class TestRequestFraming:
    def test_accepts_8192_byte_token_request(self, broker_url: str, fake_sg: FakeSG) -> None:
        body = b'{"scope":"read_all"}'.ljust(8192)
        head = (
            'POST /v1/token HTTP/1.1\r\nHost: b\r\n'
            + _VALID_AUTHORIZATION_LINE
            + 'Content-Length: 8192\r\n\r\n'
        )
        raw = _raw_exchange(broker_url, head.encode() + body)
        assert raw.startswith(b'HTTP/1.1 200')
        assert json.loads(raw.partition(b'\r\n\r\n')[2])['token'] == fake_sg.canned_session

    def test_body_read_timeout_is_400_and_closed(
        self, http_only_broker_url: str, timeout_body_read: Mock
    ) -> None:
        body = b'{"scope":"read_all"}'
        head = (
            b'POST /v1/token HTTP/1.1\r\nHost: b\r\n'
            + f'Authorization: {_auth_header()["Authorization"]}\r\n'.encode()
            + f'Content-Length: {len(body) + 5}\r\n\r\n'.encode()
        )
        raw = _raw_exchange(http_only_broker_url, head)
        assert raw.startswith(b'HTTP/1.1 400')
        assert raw.count(b'HTTP/1.1 ') == 1
        timeout_body_read.assert_called_once_with(len(body) + 5)

    @pytest.mark.parametrize(
        ('length_headers', 'body'),
        [
            (b'Content-Length: 5\r\nContent-Length: 0\r\n', b'xxxxx'),
            (b'Content-Length: 5\r\nContent-Length: 5\r\n', b'xxxxx'),
        ],
        ids=['conflicting', 'matching'],
    )
    def test_duplicate_content_lengths_are_rejected_and_closed(
        self, http_only_broker_url: str, length_headers: bytes, body: bytes
    ) -> None:
        second = b'GET /healthz HTTP/1.1\r\nHost: b\r\nConnection: close\r\n\r\n'
        raw = _raw_exchange(
            http_only_broker_url,
            b'POST /v1/token HTTP/1.1\r\nHost: b\r\n' + length_headers + b'\r\n' + body + second,
            allow_reset=True,
        )
        assert raw.startswith(b'HTTP/1.1 400')
        assert raw.count(b'HTTP/1.1 ') == 1

    def test_get_transfer_encoding_is_rejected_and_closed(self, http_only_broker_url: str) -> None:
        first = b'GET /healthz HTTP/1.1\r\nHost: b\r\nTransfer-Encoding: chunked\r\n\r\n'
        chunked = b'5\r\nxxxxx\r\n0\r\n\r\n'
        second = b'GET /healthz HTTP/1.1\r\nHost: b\r\nConnection: close\r\n\r\n'
        raw = _raw_exchange(http_only_broker_url, first + chunked + second, allow_reset=True)
        assert raw.startswith(b'HTTP/1.1 400')
        assert raw.count(b'HTTP/1.1 ') == 1

    def test_get_with_body_is_rejected_and_closed(self, http_only_broker_url: str) -> None:
        first = b'GET /healthz HTTP/1.1\r\nHost: b\r\nContent-Length: 5\r\n\r\nxxxxx'
        second = b'GET /healthz HTTP/1.1\r\nHost: b\r\nConnection: close\r\n\r\n'
        raw = _raw_exchange(http_only_broker_url, first + second, allow_reset=True)
        assert raw.startswith(b'HTTP/1.1 400')
        assert raw.count(b'HTTP/1.1 ') == 1

    def test_get_with_large_zero_length_succeeds(self, http_only_broker_url: str) -> None:
        length = b'0' * 5000
        head = b'GET /healthz HTTP/1.1\r\nHost: b\r\nContent-Length: ' + length + b'\r\n\r\n'
        second = b'GET /healthz HTTP/1.1\r\nHost: b\r\nConnection: close\r\n\r\n'
        raw = _raw_exchange(http_only_broker_url, head + second, allow_reset=True)
        assert raw.startswith(b'HTTP/1.1 200')
        assert raw.count(b'HTTP/1.1 ') == 1

    def test_get_with_zero_length_succeeds(self, http_only_broker_url: str) -> None:
        head = (
            b'GET /healthz HTTP/1.1\r\nHost: b\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
        )
        raw = _raw_exchange(http_only_broker_url, head)
        assert raw.startswith(b'HTTP/1.1 200')

    def test_head_gets_405_with_no_body(self, http_only_broker_url: str) -> None:
        raw = _raw_exchange(http_only_broker_url, b'HEAD /healthz HTTP/1.1\r\nHost: x\r\n\r\n')
        head, _, body = raw.partition(b'\r\n\r\n')
        assert head.startswith(b'HTTP/1.1 405')
        assert b'Content-Length:' in head
        assert body == b''

    @pytest.mark.parametrize(
        ('length', 'body'),
        [
            (b'-0', b''),
            (b'+5', b'xxxxx'),
            (b'5_0', b'x' * 50),
            (b'5 ', b'xxxxx'),
            (b'\xff', b''),
        ],
        ids=['negative-zero', 'positive-sign', 'underscore', 'whitespace', 'non-ascii'],
    )
    def test_invalid_content_length_forms_are_rejected_and_closed(
        self, http_only_broker_url: str, length: bytes, body: bytes
    ) -> None:
        first = b'POST /v1/token HTTP/1.1\r\nHost: b\r\nContent-Length: ' + length + b'\r\n\r\n'
        second = b'GET /healthz HTTP/1.1\r\nHost: b\r\nConnection: close\r\n\r\n'
        raw = _raw_exchange(http_only_broker_url, first + body + second, allow_reset=True)
        assert raw.startswith(b'HTTP/1.1 400')
        assert raw.count(b'HTTP/1.1 ') == 1

    def test_new_connection_after_rejection_succeeds(self, http_only_broker_url: str) -> None:
        _raw_exchange(
            http_only_broker_url,
            b'POST /v1/token HTTP/1.1\r\nHost: b\r\nContent-Length: -5\r\n\r\n',
        )
        assert requests.get(f'{http_only_broker_url}/healthz').status_code == 200

    def test_oversized_body_is_413_and_closed(self, http_only_broker_url: str) -> None:
        body = b'x' * 8193
        first = (
            b'POST /v1/token HTTP/1.1\r\nHost: b\r\n'
            + f'Content-Length: {len(body)}\r\n\r\n'.encode()
            + body
        )
        second = b'GET /healthz HTTP/1.1\r\nHost: b\r\nConnection: close\r\n\r\n'
        raw = _raw_exchange(http_only_broker_url, first + second, allow_reset=True)
        assert raw.startswith(b'HTTP/1.1 413')
        assert raw.count(b'HTTP/1.1 ') == 1

    def test_oversized_body_short_eof_is_413_and_closed(self, http_only_broker_url: str) -> None:
        head = b'POST /v1/token HTTP/1.1\r\nHost: b\r\nContent-Length: 10000\r\n\r\n'
        raw = _raw_exchange(http_only_broker_url, head + b'x' * 100, half_close=True)
        assert raw.startswith(b'HTTP/1.1 413')
        assert raw.count(b'HTTP/1.1 ') == 1

    def test_oversized_body_timeout_is_413_and_closed(
        self, http_only_broker_url: str, timeout_body_read: Mock
    ) -> None:
        head = b'POST /v1/token HTTP/1.1\r\nHost: b\r\nContent-Length: 10000\r\n\r\n'
        raw = _raw_exchange(http_only_broker_url, head)
        assert raw.startswith(b'HTTP/1.1 413')
        assert raw.count(b'HTTP/1.1 ') == 1
        timeout_body_read.assert_called_once_with(8192)

    def test_oversized_drain_stops_at_the_allowance(self) -> None:
        consumed = 0

        def read(size: int) -> bytes:
            nonlocal consumed
            assert 0 < size <= 65536 - consumed, 'read beyond the drain allowance'
            consumed += size
            return b'x' * size

        handler = _HANDLER.__new__(_HANDLER)
        handler.rfile = Mock(read=read)
        handler._drain(1000000)
        assert consumed == 65536

    def test_partial_valid_json_body_is_400_and_closed(self, http_only_broker_url: str) -> None:
        body = b'{"scope":"read_all"}'
        head = (
            b'POST /v1/token HTTP/1.1\r\nHost: b\r\n'
            + f'Authorization: {_auth_header()["Authorization"]}\r\n'.encode()
            + f'Content-Length: {len(body) + 5}\r\n\r\n'.encode()
        )
        raw = _raw_exchange(http_only_broker_url, head + body, half_close=True)
        assert raw.startswith(b'HTTP/1.1 400')
        assert b'HTTP/1.1 200' not in raw

    def test_transfer_encoding_is_rejected_and_closed(self, http_only_broker_url: str) -> None:
        head = b'POST /v1/token HTTP/1.1\r\nHost: b\r\nTransfer-Encoding: chunked\r\n\r\n'
        raw = _raw_exchange(http_only_broker_url, head)
        assert raw.startswith(b'HTTP/1.1 400')

    def test_unknown_get_with_body_is_rejected_before_routing(
        self, http_only_broker_url: str
    ) -> None:
        head = b'GET /nope HTTP/1.1\r\nHost: b\r\nContent-Length: 5\r\n\r\nxxxxx'
        raw = _raw_exchange(http_only_broker_url, head, half_close=True, allow_reset=True)
        assert raw.startswith(b'HTTP/1.1 400')
        assert raw.count(b'HTTP/1.1 ') == 1

    @pytest.mark.parametrize('method', ['GET', 'POST'])
    def test_unparseable_target_gets_400_without_a_traceback(
        self, http_only_broker_url: str, caplog: pytest.LogCaptureFixture, method: str
    ) -> None:
        with caplog.at_level(logging.ERROR):
            raw = _raw_exchange(
                http_only_broker_url,
                f'{method} http://[ HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n'.encode(),
            )
        assert raw.startswith(b'HTTP/1.1 400')
        assert b'"bad_request"' in raw
        assert not [r for r in caplog.records if r.levelno >= logging.ERROR]

    @pytest.mark.parametrize(
        'line',
        [
            'PUT /healthz HTTP/1.1',
            'DELETE /v1/token HTTP/1.1',
            'GET /v1/token HTTP/1.1',
            'POST /healthz HTTP/1.1',
            'TRACE /healthz HTTP/1.1',
            'BREW /healthz HTTP/1.1',
        ],
    )
    def test_wrong_method_is_405(self, http_only_broker_url: str, line: str) -> None:
        raw = _raw_exchange(
            http_only_broker_url,
            f'{line}\r\nHost: x\r\nContent-Length: 0\r\n\r\n'.encode(),
        )
        assert raw.startswith(b'HTTP/1.1 405')
        assert b'"method_not_allowed"' in raw


class TestTokenEndpoint:
    def test_eight_reported_digests_are_deduplicated(self, broker_url: str) -> None:
        values = ['a' * 64, 'b' * 64] * 4
        with patch.object(
            BrokerService, 'issue_token', autospec=True, side_effect=BrokerService.issue_token
        ) as issue:
            response = requests.post(
                f'{broker_url}/v1/token',
                json={'scope': 'read_all', 'rejected_tokens_sha256': values},
                headers=_auth_header(),
            )
        assert response.status_code == 200
        assert issue.call_args.args[1].rejected_digests == frozenset(values)

    def test_forbidden_scope_is_403(self, http_only_broker_url: str) -> None:
        response = requests.post(
            f'{http_only_broker_url}/v1/token',
            json={'scope': 'other'},
            headers=_auth_header(),
        )
        assert response.status_code == 403

    def test_fractional_retry_after_rounds_up(
        self, http_only_broker_url: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        error = _service.BrokerError('try later')
        error.retry_after = 2.25
        monkeypatch.setattr(BrokerService, 'issue_token', Mock(side_effect=error))
        response = requests.post(
            f'{http_only_broker_url}/v1/token', json={'scope': 'read_all'}, headers=_auth_header()
        )
        assert response.headers['Retry-After'] == '3'

    def test_full_verifier_returns_server_busy_with_retry_after(
        self, http_only_broker_url: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        entered = {f'held-{index}': threading.Event() for index in range(2)}
        release = threading.Event()

        def hold_check(secret: str, _secret_hash: str) -> bool:
            if secret in entered:
                entered[secret].set()
                release.wait()
            return False

        def request(secret: str) -> requests.Response:
            return requests.post(
                f'{http_only_broker_url}/v1/token',
                auth=('farm', secret),
                json={'scope': 'read_all'},
            )

        monkeypatch.setattr(_secrets, 'verify_secret', hold_check)
        with ThreadPoolExecutor(max_workers=len(entered)) as pool:
            workers: list[Future[requests.Response]] = []
            try:
                for secret, signal in entered.items():
                    worker = pool.submit(request, secret)
                    workers.append(worker)
                    worker.add_done_callback(lambda _, signal=signal: signal.set())
                    signal.wait()
                    if worker.done():
                        pytest.fail(f'held check exited with status {worker.result().status_code}')
                response = request('overflow')
                assert response.status_code == 503
                assert response.json()['error'] == 'server_busy'
                assert response.headers['Retry-After'] == '1'
            finally:
                release.set()
            assert all(worker.result().status_code == 401 for worker in workers)

    @pytest.mark.parametrize(
        'value', [None, 'a' * 64, ['a' * 64] * 9, ['A' * 64], ['g' * 64], ['a' * 63], [1]]
    )
    def test_invalid_rejection_report_names_the_field(
        self, http_only_broker_url: str, value: str | list[str | int] | None
    ) -> None:
        response = requests.post(
            f'{http_only_broker_url}/v1/token',
            json={'scope': 'read_all', 'rejected_tokens_sha256': value},
            headers=_auth_header(),
        )
        assert response.status_code == 400
        assert 'rejected_tokens_sha256' in response.json()['detail']

    def test_issues_token(self, broker_url: str, fake_sg: FakeSG) -> None:
        response = requests.post(
            f'{broker_url}/v1/token',
            json={'scope': 'read_all'},
            headers=_auth_header(),
        )
        assert response.status_code == 200
        body = response.json()
        assert body['token'] == fake_sg.canned_session
        assert body['token_type'] == _SESSION_TYPE
        assert 'expires_at' in body

    def test_missing_scope_is_400(self, http_only_broker_url: str) -> None:
        response = requests.post(
            f'{http_only_broker_url}/v1/token', json={}, headers=_auth_header()
        )
        assert response.status_code == 400

    def test_rest_mint_fails_closed_when_sg_rejects_the_master_key(
        self, broker_url: str, fake_sg: FakeSG
    ) -> None:
        fake_sg.rest_credentials = {'broker_read_all': 'not-the-configured-key'}
        response = requests.post(
            f'{broker_url}/v1/token',
            json={'scope': 'read_all', 'token_type': 'rest'},
            headers=_auth_header(),
        )
        assert response.status_code == 502
        assert response.json() == {'error': 'sg_rejected', 'detail': 'SG upstream request failed'}
        assert 'Retry-After' not in response.headers

    def test_rest_response_omits_refresh_credentials(
        self, broker_url: str, fake_sg: FakeSG
    ) -> None:
        response = requests.post(
            f'{broker_url}/v1/token',
            json={'scope': 'read_all', 'token_type': 'rest'},
            headers=_auth_header(),
        )
        assert response.status_code == 200
        body = response.json()
        assert body['token'] == fake_sg.canned_rest
        encoded = json.dumps(body)
        assert '"refresh_token":' not in encoded
        assert REST_REFRESH_MARKER not in encoded

    @pytest.mark.parametrize('broker_rate_limit', [1])
    def test_spent_budget_reports_remaining_window(
        self, broker_url: str, broker_clock: Mock, fake_sg: FakeSG
    ) -> None:
        url = f'{broker_url}/v1/token'
        response = requests.post(url, json={'scope': 'read_all'}, headers=_auth_header())
        assert response.status_code == 200
        broker_clock.return_value = 13
        response = requests.post(
            url, json={'scope': 'read_all', 'token_type': 'rest'}, headers=_auth_header()
        )
        assert response.status_code == 429
        assert response.json()['error'] == 'rate_limited'
        assert response.headers['Retry-After'] == '47'
        assert len(fake_sg.requests) == 1

    @pytest.mark.parametrize(
        'case',
        [(503, 503, 'upstream_unavailable', '3'), (403, 502, 'sg_rejected', None)],
    )
    def test_remembered_sg_failure_makes_no_new_request(
        self,
        broker_url: str,
        broker_clock: Mock,
        fake_sg: FakeSG,
        case: tuple[int, int, str, str | None],
    ) -> None:
        sg_status, status, error, retry = case
        fake_sg.rpc_status_override = sg_status
        for now, expected_retry in ((0, '5' if retry else None), (2, retry)):
            broker_clock.return_value = now
            response = requests.post(
                f'{broker_url}/v1/token', json={'scope': 'read_all'}, headers=_auth_header()
            )
            assert response.status_code == status
            assert response.json() == {'error': error, 'detail': 'SG upstream request failed'}
            assert response.headers.get('Retry-After') == expected_retry
            assert len(fake_sg.requests) == 1

    @pytest.mark.parametrize(
        'case',
        [
            ('POST /v1/token HTTP/1.1', '', b'{}', 'missing_authorization', b'401'),
            (
                'POST /v1/token HTTP/1.1',
                'Authorization: Basic !!!\r\n',
                b'{}',
                'malformed_authorization',
                b'401',
            ),
            (
                'POST /v1/token HTTP/1.1',
                'Authorization: Basic Zm9v\r\n',
                b'{}',
                'malformed_authorization',
                b'401',
            ),
            ('POST /nope HTTP/1.1', '', b'{}', 'not_found', b'404'),
            ('PUT /v1/token HTTP/1.1', '', b'{}', 'method_not_allowed', b'405'),
            ('TRACE /healthz HTTP/1.1', '', b'{}', 'method_not_allowed', b'405'),
            ('HEAD /healthz HTTP/1.1', '', b'{}', 'method_not_allowed', b'405'),
            ('GET /v1/token HTTP/1.1', '', b'{}', 'method_not_allowed', b'405'),
            ('POST http://[ HTTP/1.1', '', b'{}', 'bad_request', b'400'),
            (
                'POST /v1/token HTTP/1.1',
                _VALID_AUTHORIZATION_LINE,
                b'not json',
                'bad_request',
                b'400',
            ),
            (
                'POST /v1/token HTTP/1.1',
                _VALID_AUTHORIZATION_LINE,
                b'{"scope": 5}',
                'bad_request',
                b'400',
            ),
        ],
    )
    def test_pre_service_denials_emit_exactly_one_audit_line(
        self,
        http_only_broker_url: str,
        caplog: pytest.LogCaptureFixture,
        case: tuple[str, str, bytes, str, bytes],
    ) -> None:
        line, headers, body, reason, status = case
        payload = (
            f'{line}\r\nHost: x\r\n{headers}Content-Length: {len(body)}\r\n\r\n'.encode() + body
        )
        with caplog.at_level(logging.INFO, logger='sg_token_broker.audit'):
            raw = _raw_exchange(http_only_broker_url, payload, allow_reset=bool(body))
        assert raw.split(b' ', 2)[1] == status
        lines = [json.loads(record.getMessage()) for record in caplog.records]
        assert [(entry['event'], entry['reason']) for entry in lines] == [('deny', reason)]
        assert set(lines[0]) == {'ts', 'event', 'reason', 'source_ip', 'request_id'}

    @pytest.mark.parametrize(
        'case',
        [
            ('rpc_missing_session_id', 'sg_invalid_response', 502, None),
            ('hard_fail', 'upstream_unavailable', 503, '5'),
        ],
    )
    def test_failed_session_mint(
        self,
        broker_url: str,
        fake_sg: FakeSG,
        monkeypatch: pytest.MonkeyPatch,
        case: tuple[str, str, int, str | None],
    ) -> None:
        setting, error, status, retry_after = case
        monkeypatch.setattr(fake_sg, setting, True)
        response = requests.post(
            f'{broker_url}/v1/token', json={'scope': 'read_all'}, headers=_auth_header()
        )
        assert response.status_code == status
        assert response.json() == {'error': error, 'detail': 'SG upstream request failed'}
        assert response.headers.get('Retry-After') == retry_after

    @pytest.mark.parametrize('site', ['issue', 'parse'])
    def test_unexpected_error_is_opaque_500_and_audited(
        self,
        http_only_broker_url: str,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
        site: str,
    ) -> None:
        if site == 'issue':
            monkeypatch.setattr(
                BrokerService,
                'issue_token',
                Mock(side_effect=RuntimeError('secret implementation detail')),
            )
        else:
            original = _HANDLER._parse_token_request
            port = int(http_only_broker_url.rpartition(':')[2])

            def explode(handler: _http._Handler, raw: bytes, request_id: str) -> TokenRequest:
                if (
                    isinstance(handler.server, _http._BrokerHTTPServer)
                    and handler.server.server_address[1] == port
                ):
                    raise RuntimeError('secret implementation detail')
                return original(handler, raw, request_id)

            monkeypatch.setattr(_HANDLER, '_parse_token_request', explode)
        with caplog.at_level(logging.INFO, logger='sg_token_broker.audit'):
            response = requests.post(
                f'{http_only_broker_url}/v1/token',
                json={'scope': 'read_all'},
                headers=_auth_header(),
            )
        assert response.status_code == 500
        assert response.json() == {'error': 'internal_error', 'detail': 'internal error'}
        records = [record for record in caplog.records if record.name == 'sg_token_broker.audit']
        assert len(records) == 1
        audit_message = records[0].getMessage()
        audit = json.loads(audit_message)
        assert set(audit) == {'ts', 'event', 'reason', 'detail', 'source_ip', 'request_id'}
        assert audit['event'] == 'error'
        assert audit['reason'] == 'internal_error'
        assert audit['detail'] == 'RuntimeError'
        assert audit['source_ip'] == '127.0.0.1'
        assert audit['request_id']
        assert 'secret implementation detail' not in audit_message
        assert BROKER_CREDENTIAL not in audit_message
        http_records = [
            record for record in caplog.records if record.name == 'sg_token_broker.http'
        ]
        assert len(http_records) == 1
        assert http_records[0].exc_info is not None
        assert 'secret implementation detail' not in response.text

    def test_wrong_secret_returns_401_and_audits_denial(
        self, http_only_broker_url: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.INFO, logger='sg_token_broker.audit'):
            response = requests.post(
                f'{http_only_broker_url}/v1/token',
                json={'scope': 'read_all'},
                headers=_auth_header(secret=BROKER_CREDENTIAL[:-1]),
            )
        assert response.status_code == 401
        events = [
            json.loads(r.getMessage()) for r in caplog.records if r.name == 'sg_token_broker.audit'
        ]
        assert [(e['event'], e['reason'], e['client_id']) for e in events] == [
            ('deny', 'invalid_client', 'farm')
        ]


@pytest.fixture
def timeout_body_read(monkeypatch: pytest.MonkeyPatch, http_only_broker_url: str) -> Mock:
    read = Mock(side_effect=TimeoutError('injected body read deadline'))
    original = _HANDLER._read_body
    port = int(http_only_broker_url.rpartition(':')[2])

    def read_body(handler: _http._Handler) -> bytes:
        if (
            not isinstance(handler.server, _http._BrokerHTTPServer)
            or handler.server.server_address[1] != port
        ):
            return original(handler)
        # Inject only this server's body read; header reads retain the lifted bound.
        with patch.object(handler.rfile, 'read', read):
            return original(handler)

    monkeypatch.setattr(_HANDLER, '_read_body', read_body)
    return read


@pytest.fixture
def tls_broker_url(
    tmp_path: Path,
) -> Iterator[
    tuple[
        str,
        tuple[str, int],
        _http._BrokerHTTPServer,
        threading.Thread,
        SimpleQueue[threading.Thread | BaseException | None],
    ]
]:
    certificate_path, key_path = write_tls_material(tmp_path)
    config = BrokerConfig(
        site_url='https://studio.example.com',
        server=_ServerConfig(
            bind='127.0.0.1',
            port=0,
            tls=_TlsConfig(cert_file=certificate_path, key_file=key_path),
        ),
        session_ttl_seconds=600,
        scopes={},
        clients={},
    )
    server = create_server(config, Mock(spec=BrokerService))
    startup: SimpleQueue[threading.Thread | BaseException | None] = SimpleQueue()

    def serve() -> None:
        try:
            server.serve_forever(poll_interval=0.01)
        finally:
            startup.put(None)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        address = ('127.0.0.1', server.server_address[1])
        yield f'https://127.0.0.1:{address[1]}', address, server, thread, startup
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
