import logging
import socket
import threading
from collections.abc import Iterator
from http.client import HTTPMessage
from http.server import BaseHTTPRequestHandler

import pytest
import requests

from sg_token_broker._http import _BrokerHTTPServer
from sg_token_broker._httpbase import BoundedThreadingHTTPServer, parse_content_length
from sg_token_broker._userhttp import _UserTokenHTTPServer


class TestContentLength:
    @pytest.mark.parametrize(
        'fields',
        [
            [('Content-Length', '0'), ('Content-Length', '0')],
            [('Content-Length', '0'), ('Content-Length', '5')],
            [('Transfer-Encoding', '')],
            [('Transfer-Encoding', 'chunked'), ('Content-Length', '0')],
            [('Content-Length', '')],
            [('Content-Length', '0, 5')],
            [('Content-Length', '-0')],
            [('Content-Length', '+5')],
            [('Content-Length', '5_0')],
            [('Content-Length', ' 5')],
            [('Content-Length', '5 ')],
            [('Content-Length', '\u0665')],
            [('Content-Length', 'five')],
            [('Content-Length', '9' * 5000)],
        ],
        ids=[
            'matching-duplicates',
            'conflicting-duplicates',
            'empty-transfer-encoding',
            'transfer-encoding-with-length',
            'empty',
            'comma-separated',
            'negative',
            'positive-sign',
            'underscore',
            'leading-whitespace',
            'trailing-whitespace',
            'non-ascii-decimal',
            'non-decimal',
            'integer-conversion-limit',
        ],
    )
    def test_malformed_framing_is_rejected(self, fields: list[tuple[str, str]]) -> None:
        headers = HTTPMessage()
        for name, value in fields:
            headers[name] = value
        with pytest.raises(ValueError, match=r'Content-Length|Transfer-Encoding'):
            parse_content_length(headers)

    @pytest.mark.parametrize(
        ('value', 'expected'),
        [(None, 0), ('0', 0), ('12', 12), ('0' * 5000, 0), ('0' * 5000 + '12', 12)],
        ids=['missing', 'zero', 'positive', 'long-zero', 'long-leading-zeroes'],
    )
    def test_valid_length_is_parsed(self, value: str | None, expected: int) -> None:
        headers = HTTPMessage()
        if value is not None:
            headers['Content-Length'] = value
        assert parse_content_length(headers) == expected


class TestServerErrorLogging:
    @pytest.mark.parametrize(
        ('server_type', 'logger_name'),
        [
            (_BrokerHTTPServer, 'sg_token_broker.http'),
            (_UserTokenHTTPServer, 'sg_token_broker.userhttp'),
        ],
    )
    def test_inherited_handler_keeps_server_logger_and_exception(
        self,
        server_type: type[BoundedThreadingHTTPServer],
        logger_name: str,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        def fail() -> None:
            raise RuntimeError('fault')

        server = server_type.__new__(server_type)
        with socket.socket() as request, caplog.at_level(logging.ERROR, logger=logger_name):
            try:
                fail()
            except RuntimeError:
                server.handle_error(request, ('127.0.0.1', 1))
        records = [record for record in caplog.records if record.name == logger_name]
        assert len(records) == 1
        assert records[0].getMessage() == "unhandled error serving request from ('127.0.0.1', 1)"
        assert records[0].exc_info is not None
        assert records[0].exc_info[0] is RuntimeError


class TestWorkerCap:
    def test_connections_beyond_cap_are_closed_and_shutdown_stays_bounded(
        self, capped_server: tuple[BoundedThreadingHTTPServer, str, int]
    ) -> None:
        server, host, port = capped_server
        idle = socket.create_connection((host, port), timeout=5)
        try:
            assert _SignallingHandler.started.wait(5), 'idle connection never took the slot'
            with pytest.raises(requests.exceptions.ConnectionError):
                requests.get(f'http://{host}:{port}/', timeout=2)
            done = threading.Event()
            threading.Thread(target=lambda: (server.shutdown(), done.set()), daemon=True).start()
            assert done.wait(2.0), 'shutdown() blocked while a slot was held'
        finally:
            idle.close()


class _OKHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b'{"status": "ok"}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_request(self, code: int | str = '-', size: int | str = '-') -> None:
        del code, size


class _QuietServer(BoundedThreadingHTTPServer):
    def handle_error(self, request: object, client_address: object) -> None:
        del request, client_address


class _SignallingHandler(_OKHandler):
    started = threading.Event()

    def setup(self) -> None:
        super().setup()
        self.started.set()


@pytest.fixture
def capped_server(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[BoundedThreadingHTTPServer, str, int]]:
    monkeypatch.setattr('sg_token_broker._httpbase._MAX_CONCURRENT_REQUESTS', 1)
    _SignallingHandler.started = threading.Event()
    server = _QuietServer(('127.0.0.1', 0), _SignallingHandler)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True
    )
    thread.start()
    yield (server, '127.0.0.1', server.server_address[1])
    if thread.is_alive():
        server.shutdown()
    server.server_close()
