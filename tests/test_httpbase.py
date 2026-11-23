import json
import logging
import select
import socket
import socketserver
import sys
import threading
from collections.abc import Iterator
from contextlib import ExitStack
from http.client import HTTPConnection, HTTPMessage, parse_headers
from http.server import BaseHTTPRequestHandler
from io import BytesIO
from unittest.mock import ANY, Mock, call, patch

import pytest

from sg_token_broker import _httpbase
from sg_token_broker._http import _BrokerHTTPServer
from sg_token_broker._httpbase import BoundedThreadingHTTPServer, parse_content_length
from sg_token_broker._userhttp import _UserTokenHTTPServer


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
        self,
        monkeypatch: pytest.MonkeyPatch,
        host: str,
        expected_family: socket.AddressFamily,
    ) -> None:
        families: list[int] = []
        test_thread = threading.current_thread()
        original = socketserver.TCPServer.__init__

        def record_family(
            server: BoundedThreadingHTTPServer,
            address: tuple[str, int],
            handler: type[BaseHTTPRequestHandler],
            bind_and_activate: bool = True,
        ) -> None:
            if threading.current_thread() is not test_thread:
                original(server, address, handler, bind_and_activate)
                return
            assert address == (host, 0)
            assert handler is _OKHandler
            assert bind_and_activate
            families.append(server.address_family)

        monkeypatch.setattr(socketserver.TCPServer, '__init__', record_family)
        BoundedThreadingHTTPServer((host, 0), _OKHandler)
        assert families == [expected_family]


class TestContentLength:
    def test_length_exceeding_integer_conversion_limit_is_rejected(self) -> None:
        headers = HTTPMessage()
        headers['Content-Length'] = '9' * 5000
        previous = sys.get_int_max_str_digits()
        try:
            sys.set_int_max_str_digits(4300)
            with pytest.raises(ValueError, match='Content-Length'):
                parse_content_length(headers)
        finally:
            sys.set_int_max_str_digits(previous)

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


class TestListenBacklog:
    def test_accepted_large_backlog_is_kept(self) -> None:
        server = _QuietServer.__new__(_QuietServer)
        listener = Mock(spec=socket.socket)
        server.socket = listener
        server.server_activate()
        assert server.request_queue_size == 1024
        listener.listen.assert_called_once_with(1024)

    def test_fallback_listen_failure_propagates(self) -> None:
        server = _QuietServer.__new__(_QuietServer)
        listener = Mock(spec=socket.socket)
        listener.listen.side_effect = [OSError('backlog refused'), OSError('fallback refused')]
        server.socket = listener
        with pytest.raises(OSError, match='fallback refused'):
            server.server_activate()
        assert listener.listen.call_args_list == [call(1024), call(5)]

    def test_refused_large_backlog_falls_back_and_serves(self) -> None:
        with _QuietServer(('127.0.0.1', 0), _OKHandler, bind_and_activate=False) as server:
            server.server_bind()
            bound_socket = server.socket
            listener = Mock(wraps=bound_socket)
            server.socket = listener

            def listen(backlog: int) -> None:
                if backlog == 1024:
                    raise OSError('backlog refused')
                bound_socket.listen(backlog)

            listener.listen.side_effect = listen
            server.server_activate()
            assert listener.listen.call_args_list == [call(1024), call(5)]
            client = HTTPConnection('127.0.0.1', server.server_address[1])
            try:
                client.request('GET', '/')
                server.handle_request()
                with client.getresponse() as response:
                    assert response.status == 200
                    assert response.read() == b'{"status": "ok"}'
            finally:
                client.close()


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
    def test_busy_response_and_shutdown_with_all_workers_held(
        self,
        capped_server: tuple[BoundedThreadingHTTPServer, socket.socket, list[threading.Thread]],
    ) -> None:
        server, loop_exit, workers = capped_server
        address = ('127.0.0.1', server.server_address[1])

        def receive(client: socket.socket) -> bytes:
            readable, _, _ = select.select([client, loop_exit], [], [])
            assert loop_exit not in readable, 'accept loop exited before shutdown'
            return client.recv(4096)

        with ExitStack() as clients:
            for _ in range(32):
                client = clients.enter_context(socket.create_connection(address))
                assert receive(client) == b'+'
            with socket.create_connection(address) as extra:
                response = bytearray()
                while chunk := receive(extra):
                    response.extend(chunk)
                    # The controlled send below checks the proposed response itself.
                    # A nonblocking socket may deliver only its prefix before EOF.
                    assert _httpbase._BUSY_RESPONSE.startswith(response)
            server.shutdown()
            for worker in workers:
                clients.enter_context(
                    patch.object(
                        worker, 'join', side_effect=AssertionError('joined a held worker')
                    )
                )
            server.server_close()
            assert all(worker.is_alive() for worker in workers)

    @pytest.mark.parametrize('failure', [None, RuntimeError('handler failed')])
    def test_completed_request_restores_capacity(
        self, monkeypatch: pytest.MonkeyPatch, failure: RuntimeError | None
    ) -> None:
        server = _QuietServer(('127.0.0.1', 0), _OKHandler, bind_and_activate=False)
        server._worker_slots = threading.BoundedSemaphore(1)
        finish = Mock(side_effect=failure)
        monkeypatch.setattr(server, 'finish_request', finish)
        try:
            assert server._worker_slots.acquire(blocking=False)
            with socket.socket() as request:
                server.process_request_thread(request, ('127.0.0.1', 1))
                finish.assert_called_once_with(request, ('127.0.0.1', 1))
            assert server._worker_slots.acquire(blocking=False)
            assert not server._worker_slots.acquire(blocking=False)
        finally:
            server.server_close()

    @pytest.mark.parametrize('outcome', ['would-block', 'short-send', 'sent'])
    def test_busy_send_is_nonblocking_and_never_retried(self, outcome: str) -> None:
        server = _QuietServer.__new__(_QuietServer)
        slots = Mock()
        slots.acquire.return_value = False
        server._worker_slots = slots
        request = Mock(spec=socket.socket)

        def send(message: bytes) -> int:
            if outcome == 'would-block':
                raise BlockingIOError
            return 1 if outcome == 'short-send' else len(message)

        request.send.side_effect = send
        server.process_request(request, ('127.0.0.1', 1))
        slots.acquire.assert_called_once_with(blocking=False)
        request.assert_has_calls([call.settimeout(0), call.send(ANY)])
        request.send.assert_called_once()
        request.close.assert_called_once_with()
        message = BytesIO(request.send.call_args.args[0])
        assert message.readline().split(maxsplit=2)[:2] == [b'HTTP/1.1', b'503']
        headers = parse_headers(message)
        body = message.read()
        assert headers['Retry-After'] == '1'
        assert headers['Connection'].lower() == 'close'
        assert headers.get_content_type() == 'application/json'
        assert int(headers['Content-Length']) == len(body)
        assert json.loads(body) == {'error': 'server_busy', 'detail': 'server busy; retry later'}

    def test_failed_thread_start_allows_immediate_close(self) -> None:
        with (
            _QuietServer(('127.0.0.1', 0), _OKHandler) as server,
            socket.socket() as request,
            patch.object(threading.Thread, 'start', side_effect=RuntimeError('start failed')),
        ):
            server._worker_slots = threading.BoundedSemaphore(1)
            with pytest.raises(RuntimeError, match='start failed'):
                server.process_request(request, ('127.0.0.1', 1))
            assert server._worker_slots.acquire(blocking=False)


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


@pytest.fixture
def capped_server() -> Iterator[
    tuple[BoundedThreadingHTTPServer, socket.socket, list[threading.Thread]]
]:
    release = threading.Event()
    workers: list[threading.Thread] = []

    class HeldHandler(_OKHandler):
        def handle(self) -> None:
            workers.append(threading.current_thread())
            self.wfile.write(b'+')
            release.wait()

    with _QuietServer(('127.0.0.1', 0), HeldHandler) as server:
        loop_exit, notify_exit = socket.socketpair()

        def serve() -> None:
            with notify_exit:
                server.serve_forever()

        with loop_exit:
            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            try:
                yield server, loop_exit, workers
            finally:
                release.set()
                server.shutdown()
                thread.join()
                for worker in workers:
                    worker.join()
