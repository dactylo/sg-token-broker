from pathlib import Path
from unittest.mock import patch

import pytest

from benchmarks.farm import launcher


def test_client_socket_sample_preserves_each_live_tls_peer() -> None:
    sockets = {
        '101': ('0100007F:01BB', '0200017F:A001'),
        '102': ('0100007F:01BB', '0200017F:A002'),
        '103': ('0100007F:A003', '0100007F:2227'),
    }
    assert launcher._tls_peers(sockets) == ['0200017F:A001', '0200017F:A002']


def test_cpu_sample_excludes_guest_double_count_and_unselected_cpus(tmp_path: Path) -> None:
    (tmp_path / 'stat').write_text('cpu 0\ncpu0 1 1 1 1 1 1 1 1 1 1\ncpu4 7 1 2 30 2 3 4 1 6 0\n')
    (tmp_path / 'schedstat').write_text('version 17\ntimestamp 100\ncpu4 0 0 0 0 0 0 900 800 7\n')
    assert launcher._cpu_sample(tmp_path, {4}) == {
        'cpu4': {'total_ticks': 50, 'idle_ticks': 32, 'runtime_ns': 900, 'runnable_wait_ns': 800}
    }


def test_kernel_pressure_reads_named_counters(tmp_path: Path) -> None:
    (tmp_path / 'netstat').write_text(
        'TcpExt: ListenDrops TCPSynRetrans ListenOverflows Other\nTcpExt: 8 17 4 11\n'
    )
    (tmp_path / 'cpu.stat').write_text(
        'usage_usec 919\nnr_periods 18\nnr_throttled 3\nthrottled_usec 125\n'
    )
    assert launcher._pressure(tmp_path, tmp_path) == {
        'ListenOverflows': 4,
        'ListenDrops': 8,
        'TCPSynRetrans': 17,
        'nr_periods': 18,
        'nr_throttled': 3,
        'throttled_usec': 125,
    }


def test_pre_handler_refusal_has_no_handler_or_attempt() -> None:
    trace = launcher._BrokerTrace()
    with patch.object(launcher.time, 'monotonic', side_effect=[10, 12]):
        trace.accepted(('127.0.0.1', 4123))
        trace.closed(('127.0.0.1', 4123))
    assert trace.records[0]['accepted'] == 10
    assert trace.records[0]['finished'] == 12
    assert trace.records[0]['disposition'] == 'pre_handler'
    assert 'attempt_id' not in trace.records[0]


def test_process_sample_distinguishes_cpu_runtime_from_runnable_wait(tmp_path: Path) -> None:
    (tmp_path / 'status').write_text('VmRSS: 100 kB\nVmHWM: 110 kB\nThreads: 1\n')
    (tmp_path / 'stat').write_text('7 (nginx worker) ' + ' '.join(['0'] * 11 + ['5', '7']))
    (tmp_path / 'limits').write_text('Max open files    8192     16384    files\n')
    (tmp_path / 'schedstat').write_text('900000000 250000000 406\n')
    sample = launcher._process_sample(tmp_path)
    assert sample['nofile_soft'] == 8192
    assert sample['nofile_hard'] == 16384
    assert sample['cpu_ticks'] == 12
    assert sample['main_thread_runtime_ns'] == 900_000_000
    assert sample['main_thread_runnable_wait_ns'] == 250_000_000
    (tmp_path / 'schedstat').unlink()
    assert 'main_thread_runnable_wait_ns' not in launcher._process_sample(tmp_path)


def test_process_sample_skips_an_exited_child(tmp_path: Path) -> None:
    (tmp_path / 'status').write_text('State: Z (zombie)\nThreads: 1\n')
    (tmp_path / 'stat').write_text('7 (child) Z ' + ' '.join(['0'] * 14))
    with pytest.raises(ProcessLookupError):
        launcher._process_sample(tmp_path)


def test_proxy_connection_sample_includes_third_broker() -> None:
    sockets = {
        'third': ('0100007F:A003', '0100007F:2229'),
        'unused': ('0100007F:A004', '0100007F:222A'),
    }
    assert launcher._proxy_connections(sockets, {8743, 8744, 8745})['upstream'] == 1


def test_proxy_socket_totals_exclude_broker_and_private_peer_sides(tmp_path: Path) -> None:
    lines = ['sl local remote state queues timer retransmit uid timeout inode']
    for inode, (local, remote, state) in enumerate(
        [
            ('0100007F:01BB', '0100017F:A000', '01'),
            ('0100017F:A000', '0100007F:01BB', '01'),
            ('0100007F:A001', '0100007F:2227', '01'),
            ('0100007F:2227', '0100007F:A001', '01'),
            ('0200007F:A002', '0100007F:2227', '01'),
            ('0100007F:01BB', '00000000:0000', '0A'),
        ],
        1,
    ):
        lines.append(f'0: {local} {remote} {state} 0 0 0 0 0 {inode}')
    (tmp_path / 'tcp').write_text('\n'.join(lines))
    assert launcher._proxy_connections(launcher._tcp_sockets(tmp_path), {8743, 8744}) == {
        'ingress': 1,
        'upstream': 1,
    }
