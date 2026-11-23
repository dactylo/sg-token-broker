"""Keep externally supplied failure text out of benchmark observations and report keys."""

from http import HTTPStatus
from pathlib import Path
from typing import cast

import requests

from benchmarks.farm import rows

_BROKER_CODES = frozenset(
    {
        'bad_request',
        'forbidden',
        'internal_error',
        'invalid_client',
        'method_not_allowed',
        'not_found',
        'payload_too_large',
        'rate_limited',
        'server_busy',
        'sg_invalid_response',
        'sg_rejected',
        'upstream_unavailable',
    }
)
_TRANSPORT_ERRORS = frozenset(
    {
        'BrokenPipeError',
        'ChunkedEncodingError',
        'ConnectionError',
        'ConnectionRefusedError',
        'ConnectionResetError',
        'ConnectTimeout',
        'ContentDecodingError',
        'HTTPError',
        'OSError',
        'ProxyError',
        'ReadTimeout',
        'RequestException',
        'SSLError',
        'Timeout',
        'TimeoutError',
        'TooManyRedirects',
        'redirect',
    }
)


def _known_code(code: object) -> bool:
    """Accept only error codes the broker defines."""
    return isinstance(code, str) and code in _BROKER_CODES


def record_response(event: dict[str, object], response: requests.Response) -> None:
    """Record status and any recognized broker error code without retaining response text.

    Args:
        event: Observation to update in place.
        response: HTTP response whose error body may supply a broker code.
    """
    event['status'] = response.status_code
    if response.status_code < HTTPStatus.BAD_REQUEST:
        return
    try:
        body: object = response.json()
    except ValueError:
        return
    if isinstance(body, dict):
        code = cast('dict[str, object]', body).get('error')
        if _known_code(code):
            event['code'] = code


def transport_error(name: object) -> str:
    """Return an allowlisted failure name, or `transport_error` for any other value."""
    return name if isinstance(name, str) and name in _TRANSPORT_ERRORS else 'transport_error'


def _sanitize_attempt(event: dict[str, object]) -> None:
    """Discard untrusted legacy wire codes and normalize transport failures."""
    if 'code' in event and not _known_code(event['code']):
        del event['code']
    if 'error' in event:
        event['error'] = transport_error(event['error'])


def observation_rows(path: Path) -> list[dict[str, object]]:
    """Read caller observations and normalize legacy error fields.

    Returns:
        Records in file order with recognized error categories, or an empty
        list if the file is absent.

    Raises:
        OSError: If the file cannot be read.
        ValueError: If a line is not valid UTF-8 JSON.
    """
    result = rows(path)
    for event in result:
        for attempt in cast('list[dict[str, object]]', event.get('attempts', [])):
            _sanitize_attempt(attempt)
        if 'group' in event and 'error' in event:
            event['error'] = 'cli_error' if event['group'] == 'get-token' else 'client_error'
        else:
            _sanitize_attempt(event)
    return result


def record_send_error(event: dict[str, object], exc: BaseException) -> None:
    """Record a safe transport category and any available HTTP failure status.

    Args:
        event: Observation to update in place.
        exc: Send failure. A Requests exception carrying a 3xx status is
            recorded as `redirect`.
    """
    event['error'] = transport_error(type(exc).__name__)
    if not isinstance(exc, requests.RequestException) or exc.response is None:
        return
    status = exc.response.status_code
    if status:
        event['status'] = status
        if HTTPStatus.MULTIPLE_CHOICES <= status < HTTPStatus.BAD_REQUEST:
            event['error'] = 'redirect'
