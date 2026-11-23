"""Write service and dependency logs without exposing foreign diagnostic text."""

import faulthandler
import logging
import os
import sys
import traceback
import warnings
from collections.abc import Generator, Mapping
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from io import TextIOWrapper
from pathlib import Path
from types import TracebackType
from typing import TextIO, cast


class ServiceWriter(logging.Handler):
    """Write complete product lines directly to the service destination."""

    def __init__(self, stream: TextIO, logger: logging.Logger) -> None:
        """Use the named logger for debug verbosity and serialize writes to the stream."""
        super().__init__()
        self._output = logging.StreamHandler(stream)
        self._logger = logger

    def write_line(self, line: str) -> None:
        """Send a locally composed line through the private synchronized writer."""
        self._output.handle(logging.LogRecord('', 0, '', 0, line, (), None))

    def emit(self, record: logging.LogRecord) -> None:
        """Write only a local summary, exception types and stack frames."""
        line = _dependency_summary(record)
        if record.exc_info and record.exc_info[1] is not None:
            line += '\n' + _trace(record.exc_info[1], record.exc_info[2], local_messages=False)
        self.write_line(line)

    def log(self, level: int, message: str, *args: object, exc_info: bool = False) -> None:
        """Write an enabled product message and optionally the active exception's traceback.

        Args:
            level: Levels at or above INFO are always written. Lower levels use
                the logger.
            message: Locally composed logging format string.
            *args: Trusted values for percent-style interpolation.
            exc_info: Include the current exception's sanitized chain and
                frames.
        """
        if level >= logging.INFO or self._logger.isEnabledFor(level):
            line = message % args if args else message
            error = sys.exception() if exc_info else None
            if error is not None:
                line += '\n' + _trace(error, error.__traceback__, local_messages=True)
            self.write_line(line)


def _product(name: str) -> bool:
    """Identify the product namespace without matching sibling packages."""
    return name.partition('.')[0] == 'sg_token_broker'


def _record_source(name: object, level: object) -> str:
    """Only emit registered logger names and numeric levels after foreign filters run."""
    logger = logging.root.manager.loggerDict.get(name) if isinstance(name, str) else None
    label = 'root' if name == 'root' else 'dependency'
    if isinstance(logger, logging.Logger):
        label = logger.name
    severity = logging.getLevelName(level) if isinstance(level, int) else 'UNKNOWN'
    return f'{label} {severity}'


def _dependency_summary(record: logging.LogRecord) -> str:
    """Summarize foreign records without evaluating their message or arguments."""
    summary = 'dependency diagnostic'
    if (
        record.name == 'urllib3.connection'
        and isinstance(record.msg, str)
        and record.msg == 'Failed to parse headers (url=%s): %s'
    ):
        summary = 'an upstream response had malformed headers'
    args = record.args.values() if isinstance(record.args, Mapping) else record.args or ()
    names = dict.fromkeys(
        type(arg).__name__ for arg in (record.msg, *args) if isinstance(arg, BaseException)
    )
    classes = ', '.join(names)
    source = _record_source(record.name, record.levelno)
    return f'{source}: {summary}' + (f' ({classes})' if classes else '')


def _trace(error: BaseException, tb: TracebackType | None, *, local_messages: bool) -> str:
    """Render frames and exception chains without source lines, notes or foreign messages."""
    lines = ['Traceback (outermost exception first):']
    pending = [('', error, tb)]
    seen: set[int] = set()
    while pending:
        relation, current, stack = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        lines.append(relation + type(current).__name__)
        if local_messages and _product(type(current).__module__):
            lines[-1] += f': {current}'
        for frame, number in traceback.walk_tb(stack):
            code = frame.f_code
            lines.append(f'  File "{code.co_filename}", line {number}, in {code.co_name}')
        if isinstance(current, BaseExceptionGroup):
            pending.extend(
                ('Group member: ', child, child.__traceback__)
                for child in reversed(
                    cast('BaseExceptionGroup[BaseException]', current).exceptions
                )
            )
        if current.__cause__ is not None:
            cause = current.__cause__
            pending.append(('Caused by: ', cause, cause.__traceback__))
        elif not current.__suppress_context__ and current.__context__ is not None:
            context = current.__context__
            pending.append(('During handling of: ', context, context.__traceback__))
    return '\n'.join(lines)


@contextmanager
def service_streams(*, standalone: bool = False) -> Generator[tuple[TextIO, TextIO], None, None]:
    """Reserve private product streams and discard incidental process output.

    Args:
        standalone: Keep standard streams and descriptors redirected through
            interpreter shutdown. Otherwise restore them when the context
            exits.

    Yields:
        Private stdout and stderr writers valid for the duration of the
        context.

    Raises:
        OSError: If a stream cannot be flushed or a descriptor cannot be
            duplicated, redirected or restored.
    """
    with ExitStack() as stack, ExitStack() as restore:
        stdout, stderr = sys.stdout, sys.stderr

        def text_stream(fd: int, stream: TextIO, *, private: bool) -> TextIO:
            raw = os.fdopen(os.dup(fd) if private else fd, 'wb', buffering=0, closefd=private)
            if private:
                stack.enter_context(raw)
            writer = TextIOWrapper(
                raw, encoding=stream.encoding, errors=stream.errors, write_through=True
            )
            return stack.enter_context(writer) if private else writer

        stdout.flush()
        stderr.flush()
        output = text_stream(1, stdout, private=True)
        errors = text_stream(2, stderr, private=True)
        sink = stack.enter_context(Path(os.devnull).open('w', encoding='utf-8'))
        for fd, saved in ((1, output), (2, errors)):
            inheritable = os.get_inheritable(fd)
            os.dup2(sink.fileno(), fd, inheritable=inheritable)
            restore.callback(os.dup2, saved.fileno(), fd, inheritable=inheritable)
        # Cached references to the original Python streams may have buffered incidental writes.
        restore.callback(stdout.flush)
        restore.callback(stderr.flush)
        # A handler created during the command may keep its stream after shutdown.
        # Borrow 1 and 2 so those references follow the restored descriptors as well.
        restore.enter_context(redirect_stdout(text_stream(1, stdout, private=False)))
        restore.enter_context(redirect_stderr(text_stream(2, stderr, private=False)))
        if standalone:
            if faulthandler.is_enabled():
                # Fatal handlers may still run after these service writers close.
                # The OS closes this non-inheritable diagnostic fd at process exit.
                fault_fd = os.dup(errors.fileno())
                try:
                    faulthandler.enable(file=fault_fd)
                except BaseException:
                    os.close(fault_fd)
                    raise
            restore.pop_all()
        yield output, errors


@contextmanager
def service_logging(stream: TextIO, name: str) -> Generator[ServiceWriter, None, None]:
    """Capture service diagnostics for the lifetime of one command.

    Args:
        stream: Destination for product messages and sanitized diagnostics.
        name: Product logger controlling debug verbosity.

    Yields:
        The service writer while root handlers, warning capture and the
        exception hook are configured for the command.

    Raises:
        KeyboardInterrupt: If the command is interrupted.
        SystemExit: Integer and empty exit statuses propagate. Other uncaught
            failures are reported through the writer and converted to status 1.
    """
    root = logging.getLogger()
    previous, level = root.handlers, root.level
    writer = ServiceWriter(stream, logging.getLogger(name))
    showwarning, excepthook = warnings.showwarning, sys.excepthook

    def uncaught(
        _kind: type[BaseException], error: BaseException, tb: TracebackType | None
    ) -> None:
        writer.write_line('uncaught exception\n' + _trace(error, tb, local_messages=True))

    root.handlers = [writer]
    root.setLevel(logging.INFO)
    try:
        logging.captureWarnings(capture=True)
        sys.excepthook = uncaught
        yield writer
    except BaseException as exc:
        if isinstance(exc, KeyboardInterrupt) or (
            isinstance(exc, SystemExit) and isinstance(exc.code, int | type(None))
        ):
            raise
        # The interpreter would call the restored host hook after the context exits.
        uncaught(type(exc), exc, exc.__traceback__)
        raise SystemExit(1) from None
    finally:
        sys.excepthook = excepthook
        if warnings.showwarning is not showwarning:
            logging.captureWarnings(capture=False)
        root.handlers = previous
        root.setLevel(level)
        writer.close()
