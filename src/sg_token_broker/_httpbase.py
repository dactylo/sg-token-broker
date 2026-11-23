"""Share HTTP framing, JSON responses, routing helpers, and bounded concurrency."""

import ipaddress
import json
import logging
import math
import socket
import threading
import uuid
from collections.abc import Mapping
from contextlib import suppress
from email.message import Message
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import cast
from urllib.parse import SplitResult, urlsplit

from sg_token_broker._servicelog import ServiceWriter

_BUSY_BODY = b'{"error": "server_busy", "detail": "server busy; retry later"}'
_BUSY_RESPONSE: bytes = (
    b'HTTP/1.1 503 Service Unavailable\r\n'
    b'Retry-After: 1\r\n'
    b'Connection: close\r\n'
    b'Content-Type: application/json\r\n'
    b'Content-Length: %d\r\n\r\n%s' % (len(_BUSY_BODY), _BUSY_BODY)
)
_MAX_CONCURRENT_REQUESTS = 32


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a hard cap on concurrent worker threads.

    Closing the listener leaves daemon workers to exit with the process.
    At capacity the server attempts one non-blocking 503 response before
    closing the connection.

    Attributes:
        logger: Destination for request-handler failures.
    """

    # Threading registers live workers at startup. No close-time join list is needed.
    block_on_close = False
    request_queue_size = 1024
    logger: logging.Logger | ServiceWriter = logging.getLogger(__name__)
    _worker_slots: threading.BoundedSemaphore

    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler_class: type[BaseHTTPRequestHandler],
        bind_and_activate: bool = True,
    ) -> None:
        """Create a server socket using the bind address's IP family.

        A literal IPv6 address selects IPv6; other addresses select IPv4.

        Args:
            server_address: Bind host and port. Port zero requests an
                operating-system-assigned port.
            request_handler_class: Handler class instantiated for accepted
                connections.
            bind_and_activate: Whether to bind and activate immediately.
                When false, call `server_bind()` and `server_activate()` before
                serving.

        Raises:
            OSError: If socket creation, binding, or activation fails.
        """
        try:
            host = ipaddress.ip_address(server_address[0])
        except ValueError:
            self.address_family = socket.AF_INET
        else:
            self.address_family = (
                socket.AF_INET6 if isinstance(host, ipaddress.IPv6Address) else socket.AF_INET
            )
        super().__init__(server_address, request_handler_class, bind_and_activate)

    def handle_error(
        self, request: socket.socket | tuple[bytes, socket.socket], client_address: object
    ) -> None:
        """Log unexpected per-request errors via the server's logger.

        Args:
            request: The accepted server request.
            client_address: The client address associated with the request.
        """
        del request
        self.logger.log(
            logging.ERROR,
            'unhandled error serving request from %s',
            client_address,
            exc_info=True,
        )

    def process_request(
        self, request: socket.socket | tuple[bytes, socket.socket], client_address: object
    ) -> None:
        """Dispatch one request if a worker slot is free; otherwise close it.

        At capacity, attempt one non-blocking send of a 503 response. A short
        write or socket error ends the attempt so the accept loop can continue.

        Args:
            request: Accepted client connection.
            client_address: Address associated with the client connection.

        Raises:
            RuntimeError: If a worker thread cannot be started; its reserved
                slot is released.
            OSError: If closing a rejected connection fails.
        """
        if not self._worker_slots.acquire(blocking=False):
            if not isinstance(request, tuple):
                with suppress(OSError):
                    request.settimeout(0)  # Non-blocking for both plain and TLS sockets.
                    request.send(_BUSY_RESPONSE)
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
        """Listen with the burst backlog, falling back to five if refused.

        The operating system may cap the requested backlog.

        Raises:
            OSError: If the socket cannot begin listening.
        """
        self._worker_slots = threading.BoundedSemaphore(_MAX_CONCURRENT_REQUESTS)
        try:
            self.socket.listen(self.request_queue_size)
        except OSError:
            self.socket.listen(5)


class JsonErrorHandler(BaseHTTPRequestHandler):
    """Request handler that maps unknown methods to JSON 405 responses.

    `BaseHTTPRequestHandler` calls `send_error(501, ...)` when a request's
    method has no `do_*` handler. This override maps that one case to 405 and
    reports it through `_log_denial`. Other parser errors keep the stdlib
    response.

    When using inherited `log_request`, configure the server logger before
    handling requests. Subclasses may override `_log_denial` to record parser
    and unsupported-method denials.

    Attributes:
        access_logger: Logger receiving per-request access records at DEBUG.
    """

    def _log_denial(self, reason: str) -> None:
        """Record a parser or unsupported-method denial; no-op by default."""
        del reason

    @property
    def access_logger(self) -> logging.Logger | ServiceWriter:
        """Return the logger selected for this server."""
        return cast('BoundedThreadingHTTPServer', self.server).logger

    def log_message(self, *args: object, **kwargs: object) -> None:
        """Route stdlib diagnostics to the service log using only a local status."""
        del kwargs
        match args:
            case ('code %d, message %s', int(code), _):
                self.access_logger.log(
                    logging.WARNING, 'HTTP request rejected with status %d', code
                )
            case _:
                self.access_logger.log(logging.WARNING, 'HTTP request handling error')

    def log_request(self, code: int | str = '-', size: int | str = '-') -> None:
        """Route per-request access logging into the server's logger.

        Args:
            code: HTTP response status code.
            size: Response size in bytes.
        """
        del size
        self.access_logger.log(
            logging.DEBUG, 'HTTP response status %s', code if isinstance(code, int) else '-'
        )

    def send_error(
        self, code: int, message: str | None = None, explain: str | None = None
    ) -> None:
        """Map an unknown-method error to JSON 405 and preserve other errors.

        Args:
            code: HTTP status the stdlib chose.
            message: Error summary passed through for non-501 errors.
            explain: Error explanation passed through for non-501 errors.

        Raises:
            OSError: If the HTTP response cannot be written.
        """
        if code != HTTPStatus.NOT_IMPLEMENTED:
            self._log_denial('bad_request')
            super().send_error(code, message, explain)
            return
        self._log_denial('method_not_allowed')
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


def respond(
    handler: BaseHTTPRequestHandler,
    status: int,
    body: Mapping[str, object],
    *,
    headers: Mapping[str, str] | None = None,
) -> None:
    """Send one JSON response and close the connection.

    Args:
        handler: The request handler writing the response.
        status: HTTP status code.
        body: JSON-serializable response body. Its bytes are omitted for a HEAD
            request (the headers, including Content-Length, are sent).
        headers: Additional response headers.

    Raises:
        OSError: If the response headers or body cannot be written.
    """
    payload = json.dumps(dict(body)).encode()
    handler.send_response(status)
    handler.send_header('Content-Type', 'application/json')
    handler.send_header('Content-Length', str(len(payload)))
    handler.send_header('Cache-Control', 'no-store')
    handler.send_header('Pragma', 'no-cache')
    handler.send_header('X-Content-Type-Options', 'nosniff')
    handler.send_header('Connection', 'close')
    if headers:
        for name, value in headers.items():
            handler.send_header(name, value)
    handler.close_connection = True
    handler.end_headers()
    if handler.command != 'HEAD':
        handler.wfile.write(payload)


def retry_after_headers(seconds: float | None) -> dict[str, str]:
    """Return a `Retry-After` header rounded up to whole seconds, or no headers for `None`."""
    return {} if seconds is None else {'Retry-After': str(math.ceil(seconds))}


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
