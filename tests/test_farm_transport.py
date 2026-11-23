import errno
import json
import socket
from http.client import HTTPConnection, RemoteDisconnected
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock, patch

import pytest
import requests
from urllib3.exceptions import ProtocolError

from benchmarks.farm import _transport, loadgen


def test_sampled_handshake_records_dispatch_thread_scheduler_counters(tmp_path: Path) -> None:
    counters = tmp_path / 'schedstat'
    counters.write_text('7 11 1\n')
    event: dict[str, object] = {'sample_scheduler': True}
    with (
        patch.object(_transport, '_SCHEDSTAT', counters),
        _transport.attempt(event),
        _transport._stage('tls'),
    ):
        counters.write_text('17 111 3\n')
    assert event['tls_start_schedstat'] == (7, 11)
    assert event['tls_finish_schedstat'] == (17, 111)


@pytest.mark.parametrize('phase', ['http_send', 'read_headers'])
def test_transport_error_preserves_socket_and_phase_without_exception_text(phase: str) -> None:
    conn = HTTPConnection('127.0.0.1')
    conn.sock = MagicMock(spec=socket.socket)
    conn.sock.getsockname.return_value = ('127.1.0.8', 41234)
    error = (
        BrokenPipeError(errno.EPIPE, 'private-marker')
        if phase == 'http_send'
        else RemoteDisconnected('private-marker')
    )
    event: dict[str, object] = {}

    def send_request() -> None:
        with _transport.attempt(event):
            try:
                conn.send(b'')
                conn.getresponse()
            except OSError as exc:
                raise requests.ConnectionError(ProtocolError('private-marker', exc)) from None

    with (
        patch.object(HTTPConnection, 'send', side_effect=error if phase == 'http_send' else None),
        patch.object(HTTPConnection, 'getresponse', side_effect=error),
        _transport.instrument(),
        pytest.raises(requests.ConnectionError),
    ):
        send_request()
    assert event['failure_phase'] == phase
    assert event['connection'] == 'reused'
    assert event['local_port'] == 41234
    chain = cast('list[dict[str, object]]', event['exception_chain'])
    assert {e['type'] for e in chain} == {'ConnectionError', 'ProtocolError', type(error).__name__}
    if phase == 'http_send':
        assert {'type': 'BrokenPipeError', 'errno': errno.EPIPE} in chain
    assert 'private-marker' not in json.dumps(event)


def test_transport_stages_distinguish_connect_failure_from_reuse() -> None:
    events: dict[str, object] = {}
    with (
        loadgen.transport.attempt(events),
        pytest.raises(ConnectionRefusedError),
        loadgen.transport._stage('connect'),
    ):
        raise ConnectionRefusedError
    assert events['connection'] == 'new'
    assert 'connect_start' in events
    assert 'connect_finish' in events
    assert 'tls_start' not in events


def test_transport_trace_discards_nonnumeric_os_error_fields() -> None:
    event: dict[str, object] = {}
    with pytest.raises(OSError, match='private-marker'), _transport.attempt(event):
        raise OSError('private-marker', 'private-marker')
    assert event['exception_chain'] == [{'type': 'OSError'}]
