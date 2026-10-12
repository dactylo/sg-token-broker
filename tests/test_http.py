import base64
import errno
import json
import logging
import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import cast
from unittest.mock import Mock

import pytest
import requests

from sg_token_broker import _http, _service
from sg_token_broker._config import BrokerConfig, ServerConfig, TlsConfig
from sg_token_broker._http import create_server
from sg_token_broker._httpbase import BoundedThreadingHTTPServer
from sg_token_broker._service import BrokerService, TokenRequest
from tests._tls import _write_tls_material
from tests.conftest import BROKER_CREDENTIAL, _FakeSG

_HANDLER = _http._Handler
_MAX_BODY_BYTES = _http._MAX_BODY_BYTES
_SESSION_TYPE = _service._SESSION_TYPE
_VALID_AUTHORIZATION_LINE = (
    f'Authorization: Basic {base64.b64encode(f"farm:{BROKER_CREDENTIAL}".encode()).decode()}\r\n'
)


class TestConnectionLifetime:
    def test_health_response_closes_before_a_pipelined_request(self, broker_url: str) -> None:
        first = b'GET /healthz HTTP/1.1\r\nHost: b\r\n\r\n'
        second = b'GET /healthz HTTP/1.1\r\nHost: b\r\nConnection: close\r\n\r\n'
        raw = _raw_exchange(broker_url, first + second)
        assert raw.startswith(b'HTTP/1.1 200')
        assert b'connection: close' in raw.lower()
        assert raw.count(b'HTTP/1.1 ') == 1


class TestHealthz:
    def test_healthz_ignores_a_query_string(self, broker_url: str) -> None:
        assert requests.get(f'{broker_url}/healthz?probe=1', timeout=5).status_code == 200

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
            server=ServerConfig(bind='::1', port=0, tls=None),
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
                response = session.get(
                    f'http://[::1]:{server.server_address[1]}/healthz', timeout=5
                )
            assert response.status_code == 200
            assert response.json() == {'status': 'ok'}
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        assert not thread.is_alive()

    def test_ok_without_auth(self, broker_url: str) -> None:
        response = requests.get(f'{broker_url}/healthz', timeout=5)
        assert response.status_code == 200
        assert response.json() == {'status': 'ok'}

    def test_unknown_get_path_is_404(self, broker_url: str) -> None:
        response = requests.get(f'{broker_url}/nope', timeout=5)
        assert response.status_code == 404


class TestTlsAcceptLoop:
    def test_stalled_handshake_does_not_block_later_connections(
        self, tls_broker_url: tuple[str, tuple[str, int]], tmp_path: Path
    ) -> None:
        url, address = tls_broker_url
        stalled = socket.create_connection(address, timeout=5)
        try:
            response = requests.get(
                f'{url}/healthz',
                verify=str(tmp_path / 'certificate.pem'),
                timeout=5,
            )
        finally:
            stalled.close()
        assert response.status_code == 200


def _auth_header(client_id: str = 'farm', secret: str = BROKER_CREDENTIAL) -> dict[str, str]:
    creds = base64.b64encode(f'{client_id}:{secret}'.encode()).decode()
    return {'Authorization': f'Basic {creds}'}


def _raw_exchange(broker_url: str, payload: bytes, *, half_close: bool = False) -> bytes:
    host, _, port = broker_url.removeprefix('http://').partition(':')
    with socket.create_connection((host, int(port)), timeout=10) as sock:
        sock.sendall(payload)
        if half_close:
            sock.shutdown(socket.SHUT_WR)
        sock.settimeout(10)
        chunks: list[bytes] = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
    return b''.join(chunks)


class TestAddressFamily:
    @pytest.mark.parametrize(
        ('host', 'expected_family'),
        [
            ('::1', socket.AF_INET6),
            ('2001:db8::1', socket.AF_INET6),
            ('127.0.0.1', socket.AF_INET),
            ('localhost', socket.AF_INET),
        ],
    )
    def test_family_is_selected_before_socket_creation(
        self, monkeypatch: pytest.MonkeyPatch, host: str, expected_family: socket.AddressFamily
    ) -> None:
        families: list[int] = []

        def record_family(
            server: BoundedThreadingHTTPServer,
            address: tuple[str, int],
            handler: type[BaseHTTPRequestHandler],
        ) -> None:
            del handler
            assert address == (host, 0)
            families.append(server.address_family)

        monkeypatch.setattr(BoundedThreadingHTTPServer, '__init__', record_family)
        config = BrokerConfig(
            site_url='https://studio.example.com',
            server=ServerConfig(bind=host, port=0, tls=None),
            session_ttl_seconds=600,
            scopes={},
            clients={},
        )
        create_server(config, Mock(spec=BrokerService))
        assert families == [expected_family]


class TestRequestFraming:
    def test_body_read_timeout_is_400_and_closed(
        self, monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
    ) -> None:
        monkeypatch.setattr(_HANDLER, 'timeout', 0.05)
        broker_url = cast('str', request.getfixturevalue('broker_url'))
        body = b'{"scope":"read_all"}'
        head = (
            b'POST /v1/token HTTP/1.1\r\nHost: b\r\n'
            + f'Authorization: {_auth_header()["Authorization"]}\r\n'.encode()
            + f'Content-Length: {len(body) + 5}\r\n\r\n'.encode()
        )
        raw = _raw_exchange(broker_url, head + body)
        assert raw.startswith(b'HTTP/1.1 400')
        assert b'connection: close' in raw.lower()
        assert raw.count(b'HTTP/1.1 ') == 1

    @pytest.mark.parametrize(
        ('length_headers', 'body'),
        [
            (b'Content-Length: 5\r\nContent-Length: 0\r\n', b'xxxxx'),
            (b'Content-Length: 5\r\nContent-Length: 5\r\n', b'xxxxx'),
        ],
        ids=['conflicting', 'matching'],
    )
    def test_duplicate_content_lengths_are_rejected_and_closed(
        self, broker_url: str, length_headers: bytes, body: bytes
    ) -> None:
        second = b'GET /healthz HTTP/1.1\r\nHost: b\r\nConnection: close\r\n\r\n'
        raw = _raw_exchange(
            broker_url,
            b'POST /v1/token HTTP/1.1\r\nHost: b\r\n' + length_headers + b'\r\n' + body + second,
        )
        assert raw.startswith(b'HTTP/1.1 400')
        assert b'connection: close' in raw.lower()
        assert raw.count(b'HTTP/1.1 ') == 1

    def test_get_transfer_encoding_is_rejected_and_closed(self, broker_url: str) -> None:
        first = b'GET /healthz HTTP/1.1\r\nHost: b\r\nTransfer-Encoding: chunked\r\n\r\n'
        chunked = b'5\r\nxxxxx\r\n0\r\n\r\n'
        second = b'GET /healthz HTTP/1.1\r\nHost: b\r\nConnection: close\r\n\r\n'
        raw = _raw_exchange(broker_url, first + chunked + second)
        assert raw.startswith(b'HTTP/1.1 400')
        assert b'connection: close' in raw.lower()
        assert raw.count(b'HTTP/1.1 ') == 1

    def test_get_with_body_is_rejected_and_closed(self, broker_url: str) -> None:
        first = b'GET /healthz HTTP/1.1\r\nHost: b\r\nContent-Length: 5\r\n\r\nxxxxx'
        second = b'GET /healthz HTTP/1.1\r\nHost: b\r\nConnection: close\r\n\r\n'
        raw = _raw_exchange(broker_url, first + second)
        assert raw.startswith(b'HTTP/1.1 400')
        assert b'connection: close' in raw.lower()
        assert raw.count(b'HTTP/1.1 ') == 1

    def test_get_with_large_zero_length_succeeds(self, broker_url: str) -> None:
        length = b'0' * 5000
        head = b'GET /healthz HTTP/1.1\r\nHost: b\r\nContent-Length: ' + length + b'\r\n\r\n'
        second = b'GET /healthz HTTP/1.1\r\nHost: b\r\nConnection: close\r\n\r\n'
        raw = _raw_exchange(broker_url, head + second)
        assert raw.startswith(b'HTTP/1.1 200')
        assert b'connection: close' in raw.lower()
        assert raw.count(b'HTTP/1.1 ') == 1

    def test_get_with_zero_length_succeeds(self, broker_url: str) -> None:
        head = (
            b'GET /healthz HTTP/1.1\r\nHost: b\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
        )
        raw = _raw_exchange(broker_url, head)
        assert raw.startswith(b'HTTP/1.1 200')

    def test_head_gets_405_with_no_body(self, broker_url: str) -> None:
        raw = _raw_exchange(broker_url, b'HEAD /healthz HTTP/1.1\r\nHost: x\r\n\r\n')
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
        self, broker_url: str, length: bytes, body: bytes
    ) -> None:
        first = b'POST /v1/token HTTP/1.1\r\nHost: b\r\nContent-Length: ' + length + b'\r\n\r\n'
        second = b'GET /healthz HTTP/1.1\r\nHost: b\r\nConnection: close\r\n\r\n'
        raw = _raw_exchange(broker_url, first + body + second)
        assert raw.startswith(b'HTTP/1.1 400')
        assert b'connection: close' in raw.lower()
        assert raw.count(b'HTTP/1.1 ') == 1

    def test_negative_content_length_is_rejected_and_closed(self, broker_url: str) -> None:
        head = b'POST /v1/token HTTP/1.1\r\nHost: broker\r\nContent-Length: -5\r\n\r\n'
        raw = _raw_exchange(broker_url, head)
        assert raw.startswith(b'HTTP/1.1 400')
        assert b'connection: close' in raw.lower()
        assert raw.count(b'HTTP/1.1 ') == 1

    def test_new_connection_after_rejection_succeeds(self, broker_url: str) -> None:
        _raw_exchange(
            broker_url, b'POST /v1/token HTTP/1.1\r\nHost: b\r\nContent-Length: -5\r\n\r\n'
        )
        assert requests.get(f'{broker_url}/healthz', timeout=5).status_code == 200

    def test_oversized_body_is_413_and_closed(self, broker_url: str) -> None:
        body = b'x' * (_MAX_BODY_BYTES + 1)
        first = (
            b'POST /v1/token HTTP/1.1\r\nHost: b\r\n'
            + f'Content-Length: {len(body)}\r\n\r\n'.encode()
            + body
        )
        second = b'GET /healthz HTTP/1.1\r\nHost: b\r\nConnection: close\r\n\r\n'
        raw = _raw_exchange(broker_url, first + second)
        assert raw.startswith(b'HTTP/1.1 413')
        assert b'connection: close' in raw.lower()
        assert raw.count(b'HTTP/1.1 ') == 1

    def test_oversized_body_short_eof_is_413_and_closed(self, broker_url: str) -> None:
        head = b'POST /v1/token HTTP/1.1\r\nHost: b\r\nContent-Length: 10000\r\n\r\n'
        raw = _raw_exchange(broker_url, head + b'x' * 100, half_close=True)
        assert raw.startswith(b'HTTP/1.1 413')
        assert b'connection: close' in raw.lower()
        assert raw.count(b'HTTP/1.1 ') == 1

    def test_oversized_body_timeout_is_413_and_closed(
        self, monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
    ) -> None:
        monkeypatch.setattr(_HANDLER, 'timeout', 0.05)
        broker_url = cast('str', request.getfixturevalue('broker_url'))
        head = b'POST /v1/token HTTP/1.1\r\nHost: b\r\nContent-Length: 10000\r\n\r\n'
        raw = _raw_exchange(broker_url, head + b'x' * 100)
        assert raw.startswith(b'HTTP/1.1 413')
        assert b'connection: close' in raw.lower()
        assert raw.count(b'HTTP/1.1 ') == 1

    def test_partial_valid_json_body_is_400_and_closed(self, broker_url: str) -> None:
        body = b'{"scope":"read_all"}'
        head = (
            b'POST /v1/token HTTP/1.1\r\nHost: b\r\n'
            + f'Authorization: {_auth_header()["Authorization"]}\r\n'.encode()
            + f'Content-Length: {len(body) + 5}\r\n\r\n'.encode()
        )
        raw = _raw_exchange(broker_url, head + body, half_close=True)
        assert raw.startswith(b'HTTP/1.1 400')
        assert b'connection: close' in raw.lower()
        assert b'HTTP/1.1 200' not in raw

    def test_transfer_encoding_is_rejected_and_closed(self, broker_url: str) -> None:
        head = b'POST /v1/token HTTP/1.1\r\nHost: b\r\nTransfer-Encoding: chunked\r\n\r\n'
        raw = _raw_exchange(broker_url, head)
        assert raw.startswith(b'HTTP/1.1 400')
        assert b'connection: close' in raw.lower()

    def test_undrainable_oversized_body_closes_the_connection(self, broker_url: str) -> None:
        # Declares far more than the drain limit but stops sending early; the
        # server must give up, answer 413, and close instead of desyncing.
        sent = b'x' * 70000
        head = b'POST /v1/token HTTP/1.1\r\nHost: b\r\nContent-Length: 1000000\r\n\r\n'
        raw = _raw_exchange(broker_url, head + sent, half_close=True)
        assert raw.startswith(b'HTTP/1.1 413')
        assert b'connection: close' in raw.lower()
        assert raw.count(b'HTTP/1.1 ') == 1

    def test_unknown_get_with_body_is_rejected_before_routing(self, broker_url: str) -> None:
        head = b'GET /nope HTTP/1.1\r\nHost: b\r\nContent-Length: 5\r\n\r\nxxxxx'
        raw = _raw_exchange(broker_url, head, half_close=True)
        assert raw.startswith(b'HTTP/1.1 400')
        assert b'connection: close' in raw.lower()
        assert raw.count(b'HTTP/1.1 ') == 1

    @pytest.mark.parametrize('method', ['GET', 'POST'])
    def test_unparseable_target_gets_400_without_a_traceback(
        self, broker_url: str, caplog: pytest.LogCaptureFixture, method: str
    ) -> None:
        with caplog.at_level(logging.ERROR):
            raw = _raw_exchange(
                broker_url,
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
    def test_wrong_method_is_405(self, broker_url: str, line: str) -> None:
        raw = _raw_exchange(
            broker_url,
            f'{line}\r\nHost: x\r\nContent-Length: 0\r\n\r\n'.encode(),
        )
        assert raw.startswith(b'HTTP/1.1 405')
        assert b'"method_not_allowed"' in raw


class TestTokenEndpoint:
    def test_bad_secret_is_401(self, broker_url: str) -> None:
        response = requests.post(
            f'{broker_url}/v1/token',
            json={'scope': 'read_all'},
            headers=_auth_header(secret=BROKER_CREDENTIAL[:-1]),
            timeout=5,
        )
        assert response.status_code == 401

    def test_forbidden_scope_is_403(self, broker_url: str) -> None:
        response = requests.post(
            f'{broker_url}/v1/token',
            json={'scope': 'other'},
            headers=_auth_header(),
            timeout=5,
        )
        assert response.status_code == 403

    def test_garbage_basic_auth_is_401(self, broker_url: str) -> None:
        response = requests.post(
            f'{broker_url}/v1/token',
            json={'scope': 'read_all'},
            headers={'Authorization': 'Basic !!!not-base64!!!'},
            timeout=5,
        )
        assert response.status_code == 401

    def test_invalid_json_is_400(self, broker_url: str) -> None:
        response = requests.post(
            f'{broker_url}/v1/token',
            data='{nope',
            headers={**_auth_header(), 'Content-Type': 'application/json'},
            timeout=5,
        )
        assert response.status_code == 400

    def test_issues_token(self, broker_url: str, fake_sg: _FakeSG) -> None:
        response = requests.post(
            f'{broker_url}/v1/token',
            json={'scope': 'read_all'},
            headers=_auth_header(),
            timeout=5,
        )
        assert response.status_code == 200
        body = response.json()
        assert body['token'] == fake_sg._canned_session
        assert body['token_type'] == _SESSION_TYPE
        assert 'expires_at' in body

    def test_known_client_wrong_secret_still_emits_exactly_one_line(
        self, broker_url: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.INFO, logger='sg_token_broker.audit'):
            requests.post(
                f'{broker_url}/v1/token',
                json={'scope': 'read_all'},
                headers=_auth_header(secret=BROKER_CREDENTIAL[:-1]),
                timeout=5,
            )
        assert len(caplog.records) == 1

    def test_missing_auth_is_401(self, broker_url: str) -> None:
        response = requests.post(f'{broker_url}/v1/token', json={'scope': 'read_all'}, timeout=5)
        assert response.status_code == 401

    def test_missing_scope_is_400(self, broker_url: str) -> None:
        response = requests.post(
            f'{broker_url}/v1/token', json={}, headers=_auth_header(), timeout=5
        )
        assert response.status_code == 400

    def test_oversized_body_is_413(self, broker_url: str) -> None:
        response = requests.post(
            f'{broker_url}/v1/token',
            data='x' * 10000,
            headers={**_auth_header(), 'Content-Type': 'application/json'},
            timeout=5,
        )
        assert response.status_code == 413

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
        broker_url: str,
        caplog: pytest.LogCaptureFixture,
        case: tuple[str, str, bytes, str, bytes],
    ) -> None:
        line, headers, body, reason, status = case
        payload = (
            f'{line}\r\nHost: x\r\n{headers}Content-Length: {len(body)}\r\n\r\n'.encode() + body
        )
        with caplog.at_level(logging.INFO, logger='sg_token_broker.audit'):
            raw = _raw_exchange(broker_url, payload)
        assert raw.split(b' ', 2)[1] == status
        lines = [json.loads(record.getMessage()) for record in caplog.records]
        assert [(entry['event'], entry['reason']) for entry in lines] == [('deny', reason)]
        assert set(lines[0]) == {'ts', 'event', 'reason', 'source_ip', 'request_id'}

    def test_rest_mint_fails_closed_when_sg_rejects_the_master_key(
        self, broker_url: str, fake_sg: _FakeSG
    ) -> None:
        fake_sg._rest_credentials = {'broker_read_all': 'not-the-configured-key'}
        response = requests.post(
            f'{broker_url}/v1/token',
            json={'scope': 'read_all', 'token_type': 'rest'},
            headers=_auth_header(),
            timeout=5,
        )
        assert response.status_code == 502
        assert response.json()['error'] == 'upstream_error'

    def test_unexpected_parse_error_is_opaque_500_and_audited(
        self,
        broker_url: str,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def explode(*_args: object, **_kwargs: object) -> TokenRequest:
            raise RuntimeError('secret implementation detail')

        monkeypatch.setattr(_HANDLER, '_parse_token_request', explode)
        with caplog.at_level(logging.INFO, logger='sg_token_broker.audit'):
            response = requests.post(
                f'{broker_url}/v1/token',
                json={'scope': 'read_all'},
                headers=_auth_header(),
                timeout=5,
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

    def test_unknown_path_is_404(self, broker_url: str) -> None:
        response = requests.post(f'{broker_url}/nope', json={}, headers=_auth_header(), timeout=5)
        assert response.status_code == 404


@pytest.fixture
def tls_broker_url(tmp_path: Path) -> Iterator[tuple[str, tuple[str, int]]]:
    certificate_path, key_path = _write_tls_material(tmp_path)
    config = BrokerConfig(
        site_url='https://studio.example.com',
        server=ServerConfig(
            bind='127.0.0.1',
            port=0,
            tls=TlsConfig(cert_file=certificate_path, key_file=key_path),
        ),
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
        address = ('127.0.0.1', server.server_address[1])
        yield f'https://127.0.0.1:{address[1]}', address
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
