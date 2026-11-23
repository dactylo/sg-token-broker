"""Time client TCP and TLS operations in the thread performing each benchmark request."""

import socket
import ssl
import time
from collections.abc import Callable, Generator
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from http.client import HTTPConnection, HTTPException, HTTPResponse
from pathlib import Path
from typing import ParamSpec, TypeVar
from unittest.mock import patch

_CURRENT: ContextVar[dict[str, object] | None] = ContextVar('farm_attempt', default=None)
_SCHEDSTAT = Path('/proc/thread-self/schedstat')
_Params = ParamSpec('_Params')
_Result = TypeVar('_Result')


def _exception_chain(exc: BaseException) -> list[dict[str, object]]:
    """Keep exception types and OS error numbers without messages or request contents."""
    chain: list[dict[str, object]] = []
    pending = [exc]
    seen: set[int] = set()
    while pending:
        error = pending.pop()
        if id(error) in seen:
            continue
        seen.add(id(error))
        item: dict[str, object] = {'type': type(error).__name__}
        if isinstance(error, OSError) and isinstance(error.errno, int):
            item['errno'] = error.errno
        chain.append(item)
        nested = (error.__cause__, error.__context__, getattr(error, 'reason', None), *error.args)
        pending.extend(child for child in reversed(nested) if isinstance(child, BaseException))
    return chain


def _port(sock: socket.socket | None) -> None:
    """Record the port of the client socket used by this HTTP attempt."""
    event = _CURRENT.get()
    if sock is not None and event is not None and 'local_port' not in event:
        with suppress(OSError):
            address = sock.getsockname()
            if isinstance(address, tuple) and address[1]:
                event['local_port'] = address[1]


def _stamp(event: dict[str, object], name: str) -> None:
    """Timestamp the operation and optionally sample this generator thread's scheduler counters."""
    event[name] = time.perf_counter()
    if event.get('sample_scheduler') and _SCHEDSTAT.exists():
        runtime, runnable_wait, _ = _SCHEDSTAT.read_text().split()
        event[f'{name}_schedstat'] = (int(runtime), int(runnable_wait))


def _with_phase(name: str, operation: Callable[_Params, _Result]) -> Callable[_Params, _Result]:
    """Identify the innermost HTTP operation that propagated a transport error."""

    def observed(*args: _Params.args, **kwargs: _Params.kwargs) -> _Result:
        try:
            return operation(*args, **kwargs)
        except (OSError, HTTPException):
            if (event := _CURRENT.get()) is not None:
                event.setdefault('failure_phase', name)
            raise

    return observed


@contextmanager
def attempt(event: dict[str, object]) -> Generator[None, None, None]:
    """Attach transport observations to this send and restore the previous context on exit.

    Args:
        event: Mutable destination for timing, connection and failure evidence.

    Raises:
        OSError: If the enclosed transport raises an OS error.
        HTTPException: If the enclosed HTTP operation fails.
    """
    token = _CURRENT.set(event)
    try:
        yield
    except (OSError, HTTPException) as exc:
        event['exception_chain'] = _exception_chain(exc)
        raise
    finally:
        _CURRENT.reset(token)


@contextmanager
def _stage(name: str) -> Generator[None, None, None]:
    """Time a transport stage in the active attempt and mark the innermost failing stage."""
    event = _CURRENT.get()
    if event is not None:
        if name == 'connect':
            event['connection'] = 'new'
        _stamp(event, f'{name}_start')
    try:
        yield
    except (OSError, HTTPException):
        if event is not None:
            event.setdefault('failure_phase', name)
        raise
    finally:
        if event is not None:
            _stamp(event, f'{name}_finish')


@contextmanager
def instrument() -> Generator[None, None, None]:
    """Temporarily instrument process-wide TCP, TLS, HTTP send and response operations.

    Only an active attempt in the calling context receives observations.
    Leaving the context restores the original methods.
    """
    connect = socket.socket.connect
    handshake = ssl.SSLSocket.do_handshake
    send = _with_phase('http_send', HTTPConnection.send)

    def connected(sock: socket.socket, address: tuple[str, int]) -> None:
        with _stage('connect'):
            try:
                connect(sock, address)
            finally:
                _port(sock)

    def negotiated(sock: ssl.SSLSocket, block: bool = False) -> None:
        with _stage('tls'):
            handshake(sock, block)
            if (event := _CURRENT.get()) is not None:
                event['tls_session_reused'] = sock.session_reused

    def sent(conn: HTTPConnection, data: bytes) -> None:
        event = _CURRENT.get()
        if event is not None:
            event.setdefault('http_send_entry', time.perf_counter())
            if conn.sock is not None:
                event.setdefault('connection', 'reused')
                _port(conn.sock)
        send(conn, data)
        if event is not None:
            event['http_send_finish'] = time.perf_counter()

    with (
        patch.object(socket.socket, 'connect', connected),
        patch.object(ssl.SSLSocket, 'do_handshake', negotiated),
        patch.object(HTTPConnection, 'send', sent),
        patch.object(
            HTTPConnection, 'getresponse', _with_phase('read_headers', HTTPConnection.getresponse)
        ),
        patch.object(HTTPResponse, 'read', _with_phase('read_body', HTTPResponse.read)),
    ):
        yield
