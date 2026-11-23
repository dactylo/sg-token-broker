import json
from pathlib import Path

from benchmarks.farm import _cpu_layout, clock_domain


def test_clock_domain_uses_shared_network_namespace_and_monotonic_offset(tmp_path: Path) -> None:
    (tmp_path / 'fixture').write_bytes(b'synthetic')
    proc = tmp_path / 'proc'
    (proc / 'ns').mkdir(parents=True)
    (proc / 'ns' / 'net').symlink_to('net:[123]')
    offsets = proc / 'timens_offsets'
    offsets.write_text('monotonic 0 0\nboottime 9 5\n')
    clock_domain(tmp_path, 'deployment', proc)
    offsets.write_text('monotonic 0 0\nboottime 2 0\n')
    clock_domain(tmp_path, 'fleet', proc)
    offsets.write_text('monotonic 1 0\nboottime 2 0\n')
    clock_domain(tmp_path, 'different', proc)
    domains = [
        json.loads((tmp_path / f'clock-{x}.json').read_text())['domain']
        for x in ('deployment', 'fleet', 'different')
    ]
    assert domains[0] is not None
    assert domains[0] == domains[1]
    assert domains[0] != domains[2]


def test_cpu_layout_uses_visible_cpus_and_keeps_deployment_disjoint() -> None:
    visible = {2, 3, 4, 5, 7, 8, 11, 13, 14}
    assert _cpu_layout(visible, 'deployment') == {2, 3, 4, 5}
    assert _cpu_layout(visible, 'fleet') == {7, 8, 11, 13}
    assert _cpu_layout(visible, 'stream') == {14}
    assert _cpu_layout({2, 3}, 'fleet') == {2, 3}
