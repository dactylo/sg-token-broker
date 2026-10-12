"""Share HTTP framing, JSON responses, routing helpers, and bounded concurrency."""

import json
import logging
import socket
import threading
import uuid
from collections.abc import Mapping
from email.message import Message
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import SplitResult, urlsplit

_MAX_CONCURRENT_REQUESTS = 32


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a hard cap on concurrent worker threads.

    Worker threads are daemons. Connections accepted at capacity are closed
    without a response. When using inherited `handle_error`, configure
    `error_logger` before serving requests.

    Attributes:
        error_logger: Logger receiving unexpected request-handler failures.
    """

    daemon_threads = True
    error_logger: logging.Logger
    _worker_slots: threading.BoundedSemaphore

    def handle_error(
        self, request: socket.socket | tuple[bytes, socket.socket], client_address: object
    ) -> None:
        """Log unexpected per-request errors via the server's logger.

        Args:
            request: The accepted server request.
            client_address: The client address associated with the request.
        """
        del request
        self.error_logger.log(
            logging.ERROR,
            'unhandled error serving request from %s',
            client_address,
            exc_info=True,
        )

    def process_request(
        self, request: socket.socket | tuple[bytes, socket.socket], client_address: object
    ) -> None:
        """Dispatch one request if a worker slot is free; otherwise close it.

        Never blocks the accept loop: at capacity the accepted connection is
        shut down and closed without a response, so `shutdown()` is bounded by
        `serve_forever`'s poll interval regardless of held slots.

        Args:
            request: Accepted client connection.
            client_address: Address associated with the client connection.
        """
        if not self._worker_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._worker_slots.release()
            raise

    def process_request_thread(
        self, request: socket.socket | tuple[bytes, socket.socket], client_address: object
    ) -> None:
        """Handle one request in its worker thread, then release its slot.

        Args:
            request: Accepted client connection.
            client_address: Address associated with the client connection.
        """
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._worker_slots.release()

    def server_activate(self) -> None:
        """Create the worker-slot semaphore, then activate the socket."""
        self._worker_slots = threading.BoundedSemaphore(_MAX_CONCURRENT_REQUESTS)
        super().server_activate()


class JsonErrorHandler(BaseHTTPRequestHandler):
    """Request handler that maps unknown methods to JSON 405 responses.

    `BaseHTTPRequestHandler` calls `send_error(501, ...)` when a request's
    method has no `do_*` handler. This override maps that one case to 405 and
    reports it through `log_denial`; every other stdlib error is unchanged.

    When using inherited `log_request`, configure `access_logger` before
    handling requests. Subclasses may override `log_denial` to record
    unsupported-method denials.

    Attributes:
        access_logger: Logger receiving per-request access records at DEBUG.
    """

    access_logger: logging.Logger

    def log_denial(self, reason: str) -> None:
        """Record an unsupported-method denial; no-op by default.

        Args:
            reason: Fixed denial reason (`method_not_allowed`).
        """
        del reason

    def log_request(self, code: int | str = '-', size: int | str = '-') -> None:
        """Route per-request access logging into the server's logger.

        Args:
            code: HTTP response status code.
            size: Response size in bytes.
        """
        self.access_logger.debug('%s %s %s', self.requestline, code, size)

    def send_error(
        self, code: int, message: str | None = None, explain: str | None = None
    ) -> None:
        """Map an unknown-method error to JSON 405 and preserve other errors.

        Args:
            code: HTTP status the stdlib chose.
            message: Error summary passed through for non-501 errors.
            explain: Error explanation passed through for non-501 errors.
        """
        if code != HTTPStatus.NOT_IMPLEMENTED:
            super().send_error(code, message, explain)
            return
        self.log_denial('method_not_allowed')
        respond(self, 405, {'error': 'method_not_allowed', 'detail': 'method not allowed'})


def new_request_id() -> str:
    """Return a short random identifier for a request or early denial."""
    return uuid.uuid4().hex[:12]


def parse_content_length(headers: Message) -> int:
    """Parse a singleton ASCII decimal Content-Length, defaulting to zero.

    Args:
        headers: Request headers, retaining duplicate fields.

    Raises:
        ValueError: If Transfer-Encoding is present, Content-Length is repeated
            or malformed, or its digits after leading zeroes exceed the integer
            conversion limit.
    """
    if 'Transfer-Encoding' in headers:
        raise ValueError('Transfer-Encoding is not supported')
    values = headers.get_all('Content-Length')
    if values is None:
        return 0
    if len(values) != 1:
        raise ValueError('invalid Content-Length')
    value = values[0]
    if not value or not value.isascii() or not value.isdecimal():
        raise ValueError('invalid Content-Length')
    try:
        return int(value.lstrip('0') or '0')
    except ValueError as exc:
        raise ValueError('invalid Content-Length') from exc


def respond(handler: BaseHTTPRequestHandler, status: int, body: Mapping[str, object]) -> None:
    """Send one JSON response and close the connection.

    Args:
        handler: The request handler writing the response.
        status: HTTP status code.
        body: JSON-serializable response body. Its bytes are omitted for a HEAD
            request (the headers, including Content-Length, are sent).
    """
    payload = json.dumps(dict(body)).encode()
    handler.send_response(status)
    handler.send_header('Content-Type', 'application/json')
    handler.send_header('Content-Length', str(len(payload)))
    handler.send_header('Cache-Control', 'no-store')
    handler.send_header('Pragma', 'no-cache')
    handler.send_header('X-Content-Type-Options', 'nosniff')
    handler.send_header('Connection', 'close')
    handler.close_connection = True
    handler.end_headers()
    if handler.command != 'HEAD':
        handler.wfile.write(payload)


def split_target(path: str) -> SplitResult:
    """Split a request target into path and query.

    Args:
        path: The raw request target from the request line.

    Returns:
        The split result; routing uses `.path` and ignores `.query` unless the
        route defines query parameters.

    Raises:
        ValueError: If the target cannot be parsed (for example an unbalanced
            IPv6 bracket in an absolute-form target).
    """
    return urlsplit(path)
