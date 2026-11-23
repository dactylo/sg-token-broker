import io
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from benchmarks.farm import publish
from benchmarks.farm._fake_sg import FakeSG, _Handler


def test_fixture_flushes_mint_evidence_outside_reply_path(tmp_path: Path) -> None:
    with patch('http.server.ThreadingHTTPServer.__init__'):
        sg = FakeSG(tmp_path)
    sg.mint('broker-0-0', 'scope-0-0', 'session')
    assert not (tmp_path / 'mints.jsonl').exists()
    sg.flush()
    assert json.loads((tmp_path / 'mints.jsonl').read_text())['generation'] == 1


def test_fixture_listen_queue_covers_concurrent_mints(tmp_path: Path) -> None:
    with (
        patch('socketserver.socket.socket', autospec=True) as create_socket,
        patch.object(FakeSG, 'server_bind'),
        FakeSG(tmp_path),
    ):
        listen = create_socket.return_value.listen
        listen.assert_called_once()
        # Up to eight broker processes can each have eight upstream calls in flight.
        assert listen.call_args.args[0] >= 8 * 8


def test_fixture_records_the_injected_sleep_across_a_wall_clock_step(tmp_path: Path) -> None:
    with patch('http.server.ThreadingHTTPServer.__init__'):
        fixture = FakeSG(tmp_path)
    elapsed = 10.0

    def advance(seconds: float) -> None:
        nonlocal elapsed
        elapsed += seconds

    with (
        patch('benchmarks.farm._fake_sg.time.monotonic', side_effect=lambda: elapsed),
        patch('benchmarks.farm._fake_sg.time.time', side_effect=[100, 101, 99]),
        patch('benchmarks.farm._fake_sg.time.sleep', side_effect=advance),
    ):
        fixture.activate('slow-sg')
        fixture.mint('broker-0-0', 'scope-0-0', 'session')
    fixture.flush()
    mint = json.loads((tmp_path / 'mints.jsonl').read_text())
    assert mint['finished_monotonic'] - mint['started_monotonic'] == 5
    assert mint['finished'] < mint['started']


@pytest.mark.parametrize(
    ('process', 'exception', 'quiet'),
    [
        ('broker-0-0', BrokenPipeError, True),
        ('broker-0-1', BrokenPipeError, False),
        ('broker-0-0', PermissionError, False),
    ],
)
def test_only_retired_peer_disconnect_is_quiet(
    tmp_path: Path, process: str, exception: type[OSError], *, quiet: bool
) -> None:
    publish(tmp_path / 'retired-broker.json', 'broker-0-0')
    with patch('http.server.ThreadingHTTPServer.__init__'):
        fixture = FakeSG(tmp_path)
    handler = object.__new__(_Handler)
    handler.server = fixture
    handler.path = f'/{process}/api/v1.1/auth/access_token'
    body = b'client_id=scope-0-0'
    handler.rfile = io.BytesIO(body)
    with (
        patch.object(handler, 'headers', {'Content-Length': str(len(body))}, create=True),
        patch.object(handler, '_respond', side_effect=exception),
    ):
        if quiet:
            handler.do_POST()
        else:
            with pytest.raises(exception):
                handler.do_POST()
    fixture.flush()
    assert json.loads((tmp_path / 'mints.jsonl').read_text())['process'] == process


def test_outage_deadline_is_the_clock_used_by_the_fixture(tmp_path: Path) -> None:
    with patch('http.server.ThreadingHTTPServer.__init__'):
        fixture = FakeSG(tmp_path)
    with patch('benchmarks.farm._fake_sg.time.monotonic', return_value=17.0):
        activation = fixture.activate('sg-outage')
    assert activation['monotonic'] == 17
    assert activation['unavailable_until_monotonic'] == 47
