import asyncio
import atexit
import contextlib
import io
import json
import logging
import operator
import socket
import ssl
import threading
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import asdict, replace
from functools import partial
from http.client import HTTPConnection
from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import requests
from requests.adapters import HTTPAdapter

from benchmarks.farm import (
    Run,
    _scenarios,
    _warm_stream,
    append,
    launcher,
    loadgen,
    publish,
    rows,
)
from benchmarks.farm import __main__ as benchmark
from benchmarks.farm._observations import observation_rows, record_response
from benchmarks.farm._reconciliation import upstream_evidence
from benchmarks.farm._scenarios import (
    _bad_secrets,
    _burst,
    _caller_summary,
    _Evidence,
    _fault,
    _recovery,
    _renewal,
    _slow,
    measurements,
)
from sg_token_broker._admission import SecretVerifier, WaitingShare
from tests.conftest import BROKER_HASH


def _call(
    run: Run, machine: int, generation: int, phase: str, interval: tuple[float, float]
) -> None:
    start, finish = interval
    append(
        run.directory / 'calls-0.jsonl',
        {
            'machine': machine,
            'generation': generation,
            'phase': phase,
            'start': start,
            'start_monotonic': start,
            'finish': finish,
            'seconds': finish - start,
            'attempts': [
                {'start': start, 'start_monotonic': start, 'finish': finish, 'status': 200}
            ],
            'scope': 'warm'
            if run.scenario in {'slow-sg', 'slow-control'} and machine == run.machines
            else 'scope-0-0',
            'expires_at': 125.0,
            'token_type': 'session',
            'group': 'library',
        },
    )


def _gateway_assignments(run: Run) -> tuple[set[tuple[int, str, str]], int, set[str]]:
    e = _Evidence(run)
    assert all(
        obs.receipt and obs.receipt['route'].hops
        for obs in e.trace.observations
        if obs.event or obs.recovered
    )
    assignments = {
        (failure.event.line, obs.identifier, failure.backend)
        for obs in e.trace.observations
        for failure in obs.failures()
        if failure.event
    }
    intended = cast('dict[str,int]', _scenarios._errors(e)['intended_fault'])
    joined = {obs.identifier for obs in e.trace.observations if obs.receipt}
    return assignments, sum(intended.values()), joined


def _receipt(
    run: Run,
    phase: str,
    machine: int,
    attempt_id: str,
    response: tuple[int, str],
    **fields: object,
) -> None:
    append(
        run.directory / 'proxy.jsonl',
        {
            'method': 'POST',
            'uri': '/v1/token',
            'tag': '-',
            'phase': phase,
            'peer': f'127.1.0.{machine + 1}',
            'attempt_id': attempt_id,
            'status': response[0],
            'upstream': response[1],
            **(
                {
                    'upstream_addr': '-',
                    'upstream_connect_time': '-',
                    'upstream_header_time': '-',
                    'upstream_response_time': '-',
                }
                if response == (429, '-')
                else {}
            ),
            'finish': 11,
            'elapsed': 0.1,
            **fields,
        },
    )


def _receipt_mutations(
    receipts: list[dict[str, object]], index: int, field: str
) -> Iterator[dict[str, object] | None]:
    row = receipts[index]
    if field.startswith('upstream'):
        values = str(row[field]).split(', ') if field in row else []
        yield {**row, field: ', '.join([*values, values[-1] if values else '-'])}
        for i in range(len(values)):
            yield {**row, field: ', '.join(values[:i] + values[i + 1 :])}
    yield {k: v for k, v in row.items() if k != field}
    if field == 'attempt_id' and sum(r[field] == row[field] for r in receipts) > 1:
        yield None


def _record_renewal_mints(directory: Path, processes: int, fault: str) -> None:
    for slot in range(processes):
        for phase, generation, due in [
            ('prepare', 1 + slot, 1),
            ('measure', 10 + slot, 251 + slot),
        ]:
            if fault == 'one serving successor' and phase == 'measure' and slot == 1:
                continue
            stamp = 10 if phase == 'measure' and fault == 'early mint' and slot == 1 else due
            mint = {
                'process': f'broker-{slot}-0',
                'scope': 'scope-0-0',
                'token_type': 'session',
                'generation': generation,
                'started': stamp,
                'finished': stamp,
                'outcome': 'minted',
            }
            append(directory / 'mints.jsonl', mint)


def _recorded_route_evidence(row: dict[str, object]) -> set[str]:
    route = upstream_evidence(row)
    facts = {name for hop in route.hops for name, value in asdict(hop).items() if value}
    if route.local_refusal:
        facts.add('local_refusal')
    return facts


def _run(directory: Path, scenario: str, machines: int = 1, *, variant: str = 'one-source') -> Run:
    publish(directory / 'dispatch.json', 10.0)
    publish(directory / 'fleet-release.json', {'monotonic': 10.0, 'wall_time': 10.0})
    publish(directory / 'release-0.json', {'wall_time': 10.0, 'monotonic': 10.0})
    for role in ('deployment', 'fleet', 'observer', 'stream', 'probe', 'broker-0-0', 'broker-1-0'):
        publish(directory / f'clock-{role}.json', {'domain': 'test'})
    publish(directory / 'deployment.json', {})
    publish(directory / 'active.json', {'time': 9.0, 'cutoff': 0})
    return Run(directory, scenario, machines, variant, direct=False)


def _gateway_receipt_trace(directory: Path, fixture: str) -> Run:
    run = _run(directory, 'process-restart')
    publish(directory / 'restart.json', {'started_monotonic': 40.12, 'finished_monotonic': 41.0})
    a, b = '127.0.0.1:8743', '127.0.0.1:8744'
    no_peer = ('502', 'brokers', '-', '-')
    first = {
        'headers': ('504', a, '0.001', '-'),
        'body': ('200', a, '0.001', '0.002'),
        # Run 314 recorded this 503, including the connect dash.
        'body with connect dash': ('503', a, '-', '0.136'),
        'no peers': no_peer,
        'ordered': no_peer,
        'partial timing': ('504, 200', f'{a}, {b}', '-, 0.001', '-, 0.002'),
        'overlong connect': ('504, 429', f'{a}, {b}', '0.001, 0.002, 0.003', '-, 0.002'),
        'recovered': ('200', b, '0.001', '0.002'),
        'duplicate attempt ID': ('429', b, '0.001', '0.002'),
    }.get(fixture, ('504, 429', f'{a}, {b}', '-, 0.001', '-, 0.002'))
    second = no_peer if fixture == 'ordered' else ('502, 200', f'{a}, {b}', '-, 0.001', '-, 0.002')
    stage = 'timed out while connecting to upstream'
    if fixture == 'headers':
        stage = 'timed out while reading response header from upstream'
    elif fixture.startswith('body'):
        stage = 'timed out while reading upstream'
    elif first == no_peer:
        stage = 'no live upstreams'
    calls: list[dict[str, object]] = []
    for i, (status, backend, connect, header) in enumerate((first, second)):
        finish = 40.1 if i == 0 else 40.2
        start = 10 if i == 0 else 40.15
        code = int(status.rsplit(', ', 1)[-1])
        key = f'post-{i}'
        _call(run, 0, 1, 'measure', (start, finish))
        call = json.loads((directory / 'calls-0.jsonl').read_text().splitlines()[-1])
        call['attempts'][0].update(attempt_id=key, finish_monotonic=finish, status=code)
        calls.append(call)
        _receipt(
            run,
            'measure',
            0,
            key,
            (code, status),
            connection='7',
            connection_requests=str(i + 1),
            upstream_addr=backend,
            upstream_connect_time=connect,
            upstream_header_time=header,
            limit_req='PASSED',
            limit_conn='PASSED',
            remote_port='50000',
            worker_pid='24',
            ssl_protocol='TLSv1.3',
            ssl_curve='X25519',
            ssl_session_reused='.',
            upstream_response_time=header,
            retry_after='-',
            finish=finish,
            elapsed=finish - start,
        )
    (directory / 'calls-0.jsonl').write_text(''.join(json.dumps(c) + '\n' for c in calls))
    addr = 'brokers' if fixture in {'no peers', 'ordered'} else a
    line = (
        f'1970/01/01 00:00:40 *7 upstream {stage}, client: 127.1.0.1, '
        f'request: "POST /v1/token HTTP/1.1", upstream: "http://{addr}/v1/token"\n'
    )
    refused = (
        f'1970/01/01 00:00:40 *7 connect() failed (111: Connection refused) '
        f'while connecting to upstream, upstream: "http://{a}/v1/token"\n'
    )
    (directory / 'nginx-error.log').write_text(line + (line if fixture == 'ordered' else refused))
    if fixture in {'partial timing', 'contradictory limiter', 'duplicate attempt ID'}:
        path = directory / 'proxy.jsonl'
        first_row, second_row = (json.loads(line) for line in path.read_text().splitlines())
        if fixture == 'partial timing':
            del first_row['upstream_header_time']
        elif fixture == 'contradictory limiter':
            first_row.update(
                upstream='',
                upstream_addr='',
                upstream_connect_time='',
                upstream_header_time='',
                upstream_response_time='0.136',
                limit_req='REJECTED',
            )
        else:
            first_row['attempt_id'] = second_row['attempt_id']
        path.write_text(json.dumps(first_row) + '\n' + json.dumps(second_row) + '\n')
    return run


def _outage_retry_run(directory: Path, statuses: tuple[int, ...], *, direct: bool) -> Run:
    run = replace(_run(directory, 'sg-outage'), direct=direct)
    publish(
        directory / 'active.json',
        {
            'time': 10,
            'monotonic': 10,
            'unavailable_until_monotonic': 40,
            'cutoff': 0,
        },
    )
    for role in ('deployment', 'broker-0-0', 'observer', 'fleet'):
        cpus = [4] if role in {'observer', 'fleet'} else [0, 1, 2, 3]
        publish(directory / f'clock-{role}.json', {'domain': 'test', 'cpus': cpus})
    if not direct:
        publish(directory / 'proxy-affinity.json', [0, 1, 2, 3])
        publish(directory / 'service-pids.json', {'proxy': 12, 'broker-0-0': 11})
        publish(directory / 'proxy-config.json', {'broker_ports': [8743]})
        publish(
            directory / 'deployment.json',
            {'cgroup': {'cpu.max': '400000 100000', 'memory.max': str(8 * 1024**3)}},
        )
    (directory / 'audit-broker-0-0.jsonl').touch()
    for phase in ('baseline', 'final'):
        publish(
            directory / f'{phase}-broker-0-0.json',
            {'verified': {}, 'scrypt': {}, 'audit_bytes': 0},
        )
    for start, outcome in [(10.1, 'unavailable'), (41.1, 'minted')]:
        append(
            directory / 'mints.jsonl',
            {
                'scope': 'scope-0-0',
                'process': 'broker-0-0',
                'token_type': 'session',
                'started': start,
                'started_monotonic': start,
                'finished': start + 0.1,
                'finished_monotonic': start + 0.1,
                'outcome': outcome,
                **({'generation': 1} if outcome == 'minted' else {}),
            },
        )
    _call(run, 0, 1, 'measure', (10, 42))
    path = directory / 'calls-0.jsonl'
    call = json.loads(path.read_text())
    call['attempts'] = []
    for index, status in enumerate((*statuses, 200)):
        start = 41 if status == 200 else 10 + index
        key = str(index)
        call['attempts'].append(
            {
                'attempt_id': key,
                'start': start,
                'start_monotonic': start,
                'finish': start + 0.5,
                'finish_monotonic': start + 0.5,
                'status': status,
                **({} if status == 200 else {'code': 'upstream_unavailable'}),
            }
        )
        append(
            directory / 'hops-broker-0-0.jsonl',
            {
                'attempt_id': key,
                'handler_start': start + 0.05,
                'finished': start + 0.4,
                'disposition': 'handled',
            },
        )
        if not direct:
            _receipt(
                run,
                'measure',
                0,
                key,
                (status, str(status)),
                finish=start + 0.45,
                upstream_addr='127.0.0.1:8743',
            )
    publish(path, call)
    return run


def _paced_negative_stream(tmp_path: Path) -> Run:
    run = _run(tmp_path, 'bad-secrets', variant='unthrottled-broker')
    for role in ('negative', 'fleet', 'deployment'):
        publish(tmp_path / f'clock-{role}.json', {'domain': 'test'})
    _call(run, 0, 1, 'measure', (10, 10.1))
    sends = [9.995 + seq / 200 for seq in range(23)]
    # Leave an 18 ms gap before dispatch 11, within the 20 ms pacing limit.
    sends[8:11] = [10.032] * 3
    for seq, sent in enumerate(sends):
        append(
            tmp_path / 'invalid.jsonl',
            {
                'sent_monotonic': sent,
                'scheduled_monotonic': sent,
                'sequence': seq,
                'fixture': 'absent' if seq % 2 else 'repeated',
                'status': 401,
                'finish': sent + 0.01,
            },
        )
    publish(
        tmp_path / 'invalid-schedule.json',
        {'scheduled': 23, 'dropped': 0, 'target_per_second': 200},
    )
    (tmp_path / 'audit-broker-0-0.jsonl').touch()
    append(
        tmp_path / 'proxy.jsonl',
        {
            'method': 'POST',
            'uri': '/v1/token',
            'tag': '-',
            'phase': 'measure',
            'peer': '127.1.0.1',
            'status': 200,
            'upstream': '200',
            'finish': 10.1,
            'elapsed': 0.1,
        },
    )
    publish(
        tmp_path / 'final-broker-0-0.json',
        {'verified': {}, 'scrypt': {}, 'audit_bytes': 0, 'direct_negative_accepts': 23},
    )
    return run


def _renewal_trace(directory: Path, processes: int, fault: str = '') -> Run:
    run = _run(directory, 'synchronized-renewal', 4)
    publish(directory / 'deployment-topology.json', processes)
    _record_renewal_mints(directory, processes, fault)
    for machine in range(4):
        for phase in ('prepare', 'measure'):
            prime = phase == 'prepare'
            slot = (machine if prime else machine + 1) % processes
            if not prime and fault == 'one serving successor':
                slot = 0
            generation = (1 if prime else 10) + slot
            expiry = (250 if prime else 500) + slot
            start, finish = (2, 3) if prime else (250 + slot, 252 + slot)
            if not prime and machine == 0:
                if fault == 'old generation':
                    generation = 1 + slot
                    expiry = 250 + slot
                elif fault == 'wrong backend':
                    slot = (slot + 1) % processes
                elif fault == 'different expiry':
                    expiry += 1
            response_finish = (
                start + 0.25 if fault == 'early HTTP response' and not prime else finish
            )
            attempt_id = f'{phase}-{machine}'
            append(
                directory / 'calls-0.jsonl',
                {
                    'phase': phase,
                    'machine': machine,
                    'scope': 'scope-0-0',
                    'token_type': 'session',
                    'group': 'library',
                    'start': start,
                    'finish': finish,
                    'seconds': finish - start,
                    'generation': generation,
                    'expires_at': expiry,
                    'attempts': [
                        {
                            'start': start,
                            'finish': response_finish,
                            'status': 200,
                            'attempt_id': attempt_id,
                        }
                    ],
                },
            )
            _receipt(
                run,
                phase,
                machine,
                attempt_id,
                (200, '200'),
                upstream_addr=f'127.0.0.1:{8743 + slot}',
                finish=response_finish,
            )
    return run


def _warm_run(tmp_path: Path) -> Run:
    run = _run(tmp_path, 'warm-burst')
    publish(tmp_path / 'cache-broker-0-0.json', {'2': 3.1})
    path = tmp_path / 'calls-0.jsonl'
    for phase, start in [('prepare', 3), ('measure', 10)]:
        _call(run, 0, 1, phase, (start, start + 1))
        session = json.loads(path.read_text().splitlines()[-1])
        append(path, {**session, 'token_type': 'rest', 'generation': 2})
    for gen, kind in enumerate(['session', 'rest'], 1):
        append(
            tmp_path / 'mints.jsonl',
            {
                'process': 'broker-0-0',
                'scope': 'scope-0-0',
                'token_type': kind,
                'started': 3,
                'finished': 3.1,
                'generation': gen,
                'outcome': 'minted',
            },
        )
    calls = [json.loads(line) for line in path.read_text().splitlines()]
    for call in calls:
        if call['phase'] == 'prepare':
            attempt_id = call['token_type']
            call['attempts'][0]['attempt_id'] = attempt_id
            _receipt(run, 'prepare', 0, attempt_id, (200, '200'))
    path.write_text(''.join(json.dumps(call) + '\n' for call in calls))
    path = tmp_path / 'proxy.jsonl'
    records = [
        dict(json.loads(line), upstream_addr='127.0.0.1:8743')
        for line in path.read_text().splitlines()
    ]
    path.write_text(''.join(json.dumps(r) + '\n' for r in records))
    (tmp_path / 'audit-broker-0-0.jsonl').touch()
    for phase in ['baseline', 'final']:
        publish(
            tmp_path / f'{phase}-broker-0-0.json',
            {'scrypt': {'fixture': 1}, 'verified': {'fixture': 1}, 'audit_bytes': 0},
        )
    return run


@pytest.fixture
def isolated_farm_audit() -> Iterator[None]:
    logger = logging.getLogger('farm.audit')
    level = logger.level
    with patch.object(logger, 'handlers', []):
        try:
            yield
        finally:
            logger.setLevel(level)


def test_an_unrelated_retry_does_not_establish_outage_recovery(tmp_path: Path) -> None:
    run = _run(tmp_path, 'sg-outage', 2)
    for i in range(2):
        _call(run, i, 1, 'measure', (50, 51))
    for start, outcome in [(10, 'unavailable'), (50, 'minted')]:
        append(
            tmp_path / 'mints.jsonl',
            {
                'process': 'broker-0-0',
                'scope': 'scope-0-0',
                'token_type': 'session',
                'started': start,
                'finished': start + 0.1,
                'generation': 1,
                'outcome': outcome,
            },
        )
    path = tmp_path / 'calls-0.jsonl'
    data = [json.loads(line) for line in path.read_text().splitlines()]
    data[0]['attempts'].insert(0, {'start': 50, 'finish': 50.1, 'status': 429})
    path.write_text(''.join(json.dumps(row) + '\n' for row in data))
    assert not cast('dict[str, bool]', measurements(run)['expected_outcomes'])[
        'clients_observed_retry'
    ]


def test_archived_terminal_text_and_code_stay_out_of_error_keys(tmp_path: Path) -> None:
    run = _outage_retry_run(tmp_path, (503,), direct=False)
    path = tmp_path / 'calls-0.jsonl'
    prior = json.loads(path.read_text())
    failure = json.loads(path.read_text())
    failure['machine'] = 1
    marker = 'sk-fixture-credential-322'
    prior['attempts'][0]['code'] = marker
    del failure['generation']
    failure['error'] = marker
    failure['attempts'][-1].update(code=marker, status=401)
    path.write_text(json.dumps(prior) + '\n' + json.dumps(failure) + '\n')
    assert marker not in json.dumps(measurements(run))


def test_broker_handler_excludes_a_preconnect_failure(tmp_path: Path) -> None:
    run = _run(tmp_path, 'cold-burst')
    _call(run, 0, 1, 'measure', (10, 11))
    path = tmp_path / 'calls-0.jsonl'
    call = json.loads(path.read_text())
    call['attempts'][0].update(attempt_id='handled', status=502, code='sg_rejected')
    publish(path, call)
    _receipt(
        run, 'measure', 0, 'handled', (502, '502'), upstream_addr='127.0.0.1:8743', connection='3'
    )
    (tmp_path / 'nginx-error.log').write_text('*3 upstream timed out while connecting\n')
    append(
        tmp_path / 'hops-broker-0-0.jsonl',
        {'accepted': 10.1, 'handler_start': 10.2, 'finished': 10.4, 'attempt_id': 'handled'},
    )
    trace = _Evidence(run).trace
    [obs] = trace.observations
    assert obs.cause == 'sg_rejected'
    assert obs.domain == 'test'
    assert [h['process'] for h in obs.hops] == ['broker-0-0']
    assert trace.unassigned == trace.events


def test_calibration_receiver_is_independent_of_the_broker(tmp_path: Path) -> None:
    run = _run(tmp_path, 'generator-calibration')
    with (
        patch.object(launcher, '_REFERENCE', Path('docs/reverse-proxy.conf')),
        patch.object(launcher.shutil, 'which', return_value='nginx'),
        patch.object(launcher.shutil, 'copyfile'),
    ):
        _, config = launcher._proxy_config(run, tmp_path)
    receiver = Path(config).read_text()
    assert 'location = /v1/token' in receiver
    assert 'return 200' in receiver
    assert json.loads((tmp_path / 'proxy-config.json').read_text())['calibration_receiver']


def test_cli_attempt_observer_defers_decoding_and_storage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / 'attempts.jsonl'
    monkeypatch.setenv('FARM_ATTEMPTS', str(target))
    monkeypatch.setenv('FARM_CALL_PHASE', 'measure')
    monkeypatch.delenv('FARM_VALID_MACHINE', raising=False)
    response = requests.Response()
    response.status_code = 503
    hooks = (socket.socket.connect, ssl.SSLSocket.do_handshake, HTTPConnection.send)
    with (
        patch.object(requests, 'Session', requests.Session),
        patch.object(requests.Session, 'send', return_value=response),
        patch.object(response, 'json', return_value={'error': 'upstream_unavailable'}) as decode,
        contextlib.ExitStack() as cleanup,
        patch.object(atexit, 'register') as register,
    ):
        loadgen.install_cli_recorder()
        cleanup.callback(register.call_args_list[0].args[0])
        prepared = requests.Request('POST', 'https://127.0.0.1').prepare()
        with (
            requests.Session() as session,
            patch.object(loadgen.time, 'time', side_effect=[10.0, 11.0]),
            patch.object(loadgen.time, 'perf_counter', return_value=99.0),
        ):
            session.send(prepared)
        assert not target.exists()
        decode.assert_not_called()
        flush, *args = register.call_args.args
        signal = io.StringIO()

        def decode_after_signal() -> dict[str, str]:
            assert signal.getvalue().startswith('FARM_RESULT_READY ')
            return {'error': 'upstream_unavailable'}

        decode.side_effect = decode_after_signal
        with patch.object(loadgen.sys, 'stdout', signal):
            flush(*args)
    assert hooks == (socket.socket.connect, ssl.SSLSocket.do_handshake, HTTPConnection.send)
    assert json.loads(target.read_text()) == {
        'attempt_id': prepared.headers['X-Farm-Attempt'],
        'start_monotonic': 99.0,
        'finish_monotonic': 99.0,
        'start': 10.0,
        'finish': 11.0,
        'status': 503,
        'code': 'upstream_unavailable',
    }


def test_cli_latency_distributions_include_staged_wait(tmp_path: Path) -> None:
    run = _run(tmp_path, 'tls-smoke')
    _call(run, 0, 1, 'measure', (10, 12))
    path = tmp_path / 'calls-0.jsonl'
    call = json.loads(path.read_text())
    path.write_text(
        json.dumps(
            {
                **call,
                'group': 'get-token',
                'loadgen_queue_seconds': 3,
                'dispatch_to_result_seconds': 5,
            }
        )
    )
    summary = _caller_summary(_Evidence(run).measure)
    assert cast('dict[str,float]', summary['queue_wait_seconds'])['median'] == 3
    assert cast('dict[str,float]', summary['dispatch_to_result_seconds'])['median'] == 5


def test_cli_result_releases_slot_before_recorder_tail(tmp_path: Path) -> None:
    run = _run(tmp_path, 'tls-smoke')
    (tmp_path / 'fixture').write_bytes(b'fixture')
    machine = loadgen._Machine(run, 0)
    slot = threading.BoundedSemaphore(1)

    def child(
        _kind: str, _history: list[str], _phase: str, available: Callable[[float, float], None]
    ) -> tuple[str, str]:
        async def output_lines() -> AsyncIterator[bytes]:
            yield b'shipping result\n'
            yield b'FARM_RESULT_READY 12 12\n'
            # The child's recorder is still running and stdout has not reached EOF.
            assert slot.acquire(blocking=False)
            slot.release()

        stream = MagicMock()
        stream.__aiter__.side_effect = output_lines
        assert asyncio.run(loadgen._cli_output(stream, available)) == b'shipping result\n'
        return '1.fixture', '2026-11-20T12:00:00+00:00'

    with (
        patch.object(loadgen, '_CLI_SLOTS', slot),
        patch.object(machine, '_invoke_cli', side_effect=child),
        patch.object(loadgen.time, 'perf_counter', side_effect=[8.0, 10.0, 25.0]),
        patch.object(loadgen.time, 'time', return_value=10.0),
    ):
        assert machine.fetch('measure')
    call = machine.calls[0]
    assert (
        call['seconds'],
        call['dispatch_to_result_seconds'],
        call['recorder_tail_seconds'],
    ) == (2.0, 4.0, 13.0)
    assert slot.acquire(blocking=False)
    slot.release()
    machine.close()


def test_cli_stderr_stays_out_of_records_and_report(tmp_path: Path) -> None:
    run = _run(tmp_path, 'tls-smoke')
    (tmp_path / 'fixture').write_bytes(b'fixture')
    machine = loadgen._Machine(run, 0)
    marker = 'sk-fixture-credential-491'
    child = MagicMock(returncode=1)
    child.stderr.read = AsyncMock(return_value=marker.encode())
    child.wait = AsyncMock(return_value=1)
    child.stdout.__aiter__.return_value = [b'FARM_RESULT_READY 12 12\n']
    try:
        with patch.object(loadgen.asyncio, 'create_subprocess_exec', return_value=child) as launch:
            assert not machine.fetch('measure')
        assert launch.call_args.kwargs['stderr'] == loadgen.asyncio.subprocess.DEVNULL
        append(tmp_path / 'calls-0.jsonl', machine.calls[0])
        assert marker not in (tmp_path / 'calls-0.jsonl').read_text()
        assert marker not in json.dumps(measurements(run))
    finally:
        machine.close()


def test_cold_burst_requires_both_types_per_machine(tmp_path: Path) -> None:
    run = _run(tmp_path, 'cold-burst')
    _call(run, 0, 1, 'measure', (10, 11))
    _call(run, 0, 1, 'measure', (11, 12))
    assert not _Evidence(run).complete()


def test_completion_can_exceed_the_attempt_start_budget(tmp_path: Path) -> None:
    run = _run(tmp_path, 'cold-burst')
    _call(run, 0, 1, 'measure', (10, 311))
    log = tmp_path / 'calls-0.jsonl'
    session = json.loads(log.read_text())
    append(
        log,
        {
            **session,
            'token_type': 'rest',
            'start': 312,
            'finish': 313,
            'seconds': 1,
            'attempts': [{'start': 312, 'finish': 313, 'status': 200}],
        },
    )
    assert _burst(_Evidence(run))['attempts_started_within_max_wait']


def test_direct_receipts_required_even_with_a_well_paced_stream(tmp_path: Path) -> None:
    run = _paced_negative_stream(tmp_path)
    checks, _ = _bad_secrets(_Evidence(run))
    assert checks['invalid_traffic_spanned_valid_acquisitions']
    assert checks['proxy_path_observed']
    path = tmp_path / 'final-broker-0-0.json'
    publish(path, dict(json.loads(path.read_text()), direct_negative_accepts=22))
    checks, _ = _bad_secrets(_Evidence(run))
    assert checks['invalid_traffic_spanned_valid_acquisitions']
    assert not checks['proxy_path_observed']


def test_direct_smoke_ignores_unused_warm_broker_count(tmp_path: Path) -> None:
    with (
        patch(
            'sys.argv',
            [
                'bench',
                '--scenario',
                'smoke',
                '--direct',
                '--warm-brokers',
                '2',
                '--report',
                str(tmp_path / 'unused'),
            ],
        ),
        patch.object(benchmark, '_measure') as measure,
    ):
        benchmark._main()
    measure.assert_awaited_once()


def test_direct_two_broker_prime_rejected_before_deployment(tmp_path: Path) -> None:
    with (
        patch(
            'sys.argv',
            [
                'bench',
                '--scenario',
                'warm-burst',
                '--direct',
                '--warm-brokers',
                '2',
                '--report',
                str(tmp_path / 'unused'),
            ],
        ),
        patch.object(benchmark, '_measure') as measure,
        pytest.raises(SystemExit) as exc,
    ):
        benchmark._main()
    assert exc.value.code == 2
    measure.assert_not_called()


def test_elapsed_tail_keeps_full_occupancy(tmp_path: Path) -> None:
    run = _run(tmp_path, 'slow-sg')
    records: list[dict[str, object]] = [
        {'sequence': i, 'slot': 'sent', 'acquisition_start': 9 + i / 4, 'finish_monotonic': 10.5}
        for i in range(4)
    ]
    _warm_stream._publish_slots(run, records, 9, 11)
    assert [r['slot'] for r in records[4:]] == ['suppressed', 'suppressed', 'late', 'late']
    assert records[4]['outstanding'] == [0, 1, 2, 3]


def test_failed_calls_do_not_improve_primary_latency(tmp_path: Path) -> None:
    run = _run(tmp_path, 'cold-burst')
    _call(run, 0, 1, 'measure', (10, 13))
    path = tmp_path / 'calls-0.jsonl'
    failure = json.loads(path.read_text())
    del failure['generation']
    failure['seconds'] = 0
    failure.update({'token_type': 'rest', 'finish': 10, 'error': 'client_error', 'attempts': []})
    append(path, failure)
    report = measurements(run)
    primary = cast('dict[str, object]', report['primary_latency'])
    assert primary['call_seconds'] == {'median': 3, 'p95': 3, 'p99': 3, 'max': 3}
    callers = cast('dict[str, dict[str, object]]', report['callers'])
    assert callers['measure']['acquisition_seconds'] == primary['call_seconds']
    assert callers['measure']['failed_calls'] == 1
    assert primary['failed_calls'] == primary['successful_calls'] == 1
    assert not cast('dict[str, bool]', report['service_results'])['primary_latency_target']


def test_farm_tls_prepares_a_verifying_context_before_release(tmp_path: Path) -> None:
    with requests.Session() as session, patch.object(loadgen, 'create_urllib3_context') as context:
        loadgen._farm_session(session, 0, tmp_path)
        adapter = session.get_adapter(loadgen.PROXY_URL + '/')
        assert isinstance(adapter, HTTPAdapter)
        assert adapter.poolmanager.connection_pool_kw['ssl_context'] is context.return_value
        context.return_value.load_verify_locations.assert_called_once_with(
            cafile=str(tmp_path / 'ca.pem')
        )
        assert session.verify == str(tmp_path / 'ca.pem')


def test_first_connection_ignores_earlier_cache_only_calls(tmp_path: Path) -> None:
    run = _warm_run(tmp_path)
    first, second = (c for c in _Evidence(run).measure)
    first['attempts'].clear()
    second['attempts'][0]['connection'] = 'new'
    evidence = _Evidence(run)
    evidence.by_machine[0] = [first, second]
    counts, _ = _scenarios._fleet_connections(evidence)
    assert counts['machine_first'] == {'new': 1}
    assert not counts['subsequent_call_first']


@pytest.mark.usefixtures('isolated_farm_audit')
def test_fixture_minter_ignores_environment_proxy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv('http_proxy', 'http://fixture-proxy.invalid:8080')
    monkeypatch.setenv('no_proxy', '')
    monkeypatch.setenv('NO_PROXY', '')
    config = tmp_path / 'config.json'
    url = 'http://127.0.0.1:9000'
    publish(
        config,
        {
            'site_url': url,
            'clients': {'farm-0': {'secret_hash': BROKER_HASH, 'scopes': ['read']}},
            'scopes': {'read': {'script_name': 'read', 'script_key_env': 'FIXTURE_KEY'}},
        },
    )
    with (
        patch.object(launcher, 'SGMinter', wraps=launcher.SGMinter) as construct,
        patch.object(launcher, 'create_server', side_effect=RuntimeError('before bind')),
        pytest.raises(RuntimeError, match='before bind'),
    ):
        launcher._broker(config, tmp_path, 'broker-0-0')
    session = construct.call_args.kwargs.get('session')
    assert isinstance(session, requests.Session)
    assert not session.merge_environment_settings(url, {}, None, None, None)['proxies']


def test_foreign_clock_invalidates_restart_not_local_latency(tmp_path: Path) -> None:
    run = _run(tmp_path, 'process-restart')
    publish(tmp_path / 'clock-deployment.json', {'domain': 'one'})
    publish(tmp_path / 'clock-fleet.json', {'domain': 'two'})
    _call(run, 0, 1, 'measure', (10, 11))
    report = measurements(run)
    assert 'shared_monotonic_clock' in cast('list[str]', report['invalid_reasons'])
    assert cast('dict[str, object]', report['primary_latency'])['successful_calls'] == 1


def test_gateway_cause_survives_a_local_503(tmp_path: Path) -> None:
    run = _run(tmp_path, 'cold-burst')
    _call(run, 0, 1, 'measure', (10, 12))
    path = tmp_path / 'calls-0.jsonl'
    call = json.loads(path.read_text())
    call['attempts'][0].update(status=503, attempt_id='one')
    path.write_text(json.dumps(call) + '\n')
    _receipt(run, 'measure', 0, 'one', (503, '502'))
    path = tmp_path / 'proxy.jsonl'
    receipt = json.loads(path.read_text())
    receipt.update(
        connection='7',
        retry_after='1',
        upstream_addr='brokers',
        upstream_connect_time='-',
        upstream_header_time='-',
    )
    path.write_text(json.dumps(receipt) + '\n')
    (tmp_path / 'nginx-error.log').write_text(
        '2026/11/20 [error] 1#1: *7 no live upstreams while connecting to upstream\n'
    )
    report = cast('dict[str, object]', measurements(run)['errors'])
    assert report['original_causes'] == {'no_available_upstream': 1}
    assert report['client_observations'] == {'503': 1}


def test_gateway_event_with_ambiguous_connection_survives_verdict(tmp_path: Path) -> None:
    run = _run(tmp_path, 'cold-burst')
    _call(run, 0, 1, 'measure', (10, 12))
    path = tmp_path / 'calls-0.jsonl'
    call = json.loads(path.read_text())
    call['attempts'] = [
        dict(call['attempts'][0], attempt_id=i, code='server_busy', status=503)
        for i in ('one', 'two')
    ]
    path.write_text(json.dumps(call) + '\n')
    for attempt in call['attempts']:
        _receipt(run, 'measure', 0, attempt['attempt_id'], (503, '502'))
    path = tmp_path / 'proxy.jsonl'
    receipts = [dict(json.loads(line), connection='7') for line in path.read_text().splitlines()]
    path.write_text(''.join(json.dumps(r) + '\n' for r in receipts))
    (tmp_path / 'nginx-error.log').write_text(
        '*7 no live upstreams while connecting to upstream\n'
    )
    report = measurements(run)
    assert not cast('dict[str, bool]', report['service_results'])[
        'no_avoidable_transport_or_gateway_errors'
    ]
    errors = cast('dict[str, object]', report['errors'])
    assert errors['gateway_events'] == {'no_available_upstream': 1}
    assert errors['original_causes'] == {'unclassified': 2}


def test_generator_affinity_precedes_role_clock_independent_of_route(tmp_path: Path) -> None:
    with (
        patch.object(
            loadgen.sys,
            'argv',
            ['loadgen', 'negative', str(tmp_path), 'bad-secrets', '1', 'one-source', '--direct'],
        ),
        patch.object(loadgen, 'pin_cpus') as pin,
        patch.object(loadgen, 'clock_domain', side_effect=RuntimeError('before any workload')),
        pytest.raises(RuntimeError, match='before any workload'),
    ):
        loadgen._main()
    pin.assert_called_once_with('negative')


def test_health_check_error_remains_in_independent_total(tmp_path: Path) -> None:
    run = _run(tmp_path, 'cold-burst')
    _call(run, 0, 1, 'measure', (10, 11))
    path = tmp_path / 'calls-0.jsonl'
    call = json.loads(path.read_text())
    call['attempts'][0].update(attempt_id='token', status=502)
    publish(path, call)
    _receipt(run, 'measure', 0, 'token', (502, '502'))
    receipt = tmp_path / 'proxy.jsonl'
    publish(receipt, dict(json.loads(receipt.read_text()), connection='1'))
    (tmp_path / 'nginx-error.log').write_text(
        '*1 no live upstreams, request: "GET /healthz HTTP/1.1"\n'
    )
    errors = _scenarios._errors(_Evidence(run))
    assert (
        errors['gateway_events']
        == errors['unassigned_gateway_events']
        == {'no_available_upstream': 1}
    )
    assert errors['original_causes'] == {'unclassified': 1}


def test_interrupted_send_retains_attempt_without_inventing_status() -> None:
    request = requests.Request('POST', 'https://origin.example').prepare()
    stopped = KeyboardInterrupt()
    buffer = loadgen._AttemptBuffer()
    with (
        requests.Session() as session,
        patch.object(session, 'send', side_effect=stopped),
        pytest.raises(KeyboardInterrupt) as caught,
    ):
        buffer.observe(session.send)(request)
    assert caught.value is stopped
    (attempt,) = buffer.drain()
    assert attempt['attempt_id'] == request.headers['X-Farm-Attempt']
    assert attempt['error'] == 'transport_error'
    assert 'status' not in attempt


def test_invalid_schedule_keeps_observed_results_and_success_denominator(tmp_path: Path) -> None:
    run = _run(tmp_path, 'cold-burst', variant='simultaneous')
    for kind, start, finish in [('session', 12, 15), ('rest', 15, 16)]:
        _call(run, 0, 1, 'measure', (start, finish))
        path = tmp_path / 'calls-0.jsonl'
        calls = [json.loads(line) for line in path.read_text().splitlines()]
        calls[-1]['token_type'] = kind
        path.write_text(''.join(json.dumps(c) + '\n' for c in calls))
    report = measurements(run)
    assert report['verdict'] == 'inconclusive'
    assert 'arrival_schedule_observed' in cast('list[str]', report['invalid_reasons'])
    primary = cast('dict[str, object]', report['primary_latency'])
    assert primary['successful_calls'] == primary['attempted_calls'] == 2
    assert primary['call_seconds'] == {'median': 1, 'p95': 3, 'p99': 3, 'max': 3}
    assert primary['whole_machine_seconds'] == {'median': 4, 'p95': 4, 'p99': 4, 'max': 4}
    assert cast('dict[str, bool]', report['service_results'])['every_machine_received_tokens']


def test_json_limiter_receipt_requires_recorded_empty_upstream_fields() -> None:
    # Run 405 logs empty strings for unset nginx variables with escape=json.
    row: dict[str, object] = {
        'status': 429,
        'limit_req': 'REJECTED',
        'limit_conn': '',
        'upstream': '',
        'upstream_addr': '',
        'upstream_connect_time': '',
        'upstream_header_time': '',
        'upstream_response_time': '',
    }
    assert upstream_evidence(row).local_refusal
    assert not upstream_evidence({**row, 'limit_req': 'PASSED'}).local_refusal
    for key in row:
        if key.startswith('upstream'):
            assert not upstream_evidence({k: v for k, v in row.items() if k != key}).local_refusal
            assert not upstream_evidence({**row, key: '0.012'}).local_refusal


def test_late_wake_cannot_suppress_slot_for_later_occupants(tmp_path: Path) -> None:
    run = _run(tmp_path, 'slow-sg')
    publish(tmp_path / 'stream-clock.json', {'epoch': 9, 'stop': 10.25, 'slots': 5, 'cpus': [9]})
    for seq in range(4):
        start = 9 + seq / 4
        append(
            tmp_path / 'stream.jsonl',
            {
                'sequence': seq,
                'start_monotonic': start,
                'finish_monotonic': 10 if seq == 0 else 11,
                'attempt_id': str(seq),
                'error': 'ReadTimeout',
            },
        )
    append(tmp_path / 'stream.jsonl', {'sequence': 4, 'slot': 'suppressed', 'wake': 10.2})
    valid, detail = _scenarios._stream_evidence(_Evidence(run), [(9.75, 10.25)], {}, 9.5)
    assert not valid
    assert detail['invalid_suppressions'] == [4]


def test_library_result_precedes_benchmark_expiry_serialization(tmp_path: Path) -> None:
    run = _run(tmp_path, 'cold-burst')
    (tmp_path / 'fixture').write_bytes(b'fixture')
    machine = loadgen._Machine(run, 0)
    clock = [10.0]

    def serialize() -> str:
        clock[0] += 5
        return '2099-01-01T00:00:00+00:00'

    result = MagicMock()
    result.token = f'1.{run.scenario}'
    result.expires_at.isoformat.side_effect = serialize
    try:
        with (
            patch.object(machine._client, 'fetch_token', return_value=result),
            patch.object(loadgen.time, 'perf_counter', side_effect=lambda: clock[0]),
        ):
            assert machine.fetch('measure')
        assert machine.calls[-1]['finish_monotonic'] == 10
    finally:
        machine.close()


def test_lost_result_does_not_shorten_injected_fault(tmp_path: Path) -> None:
    run = _run(tmp_path, 'slow-sg')
    append(
        tmp_path / 'mints.jsonl',
        {
            'started': 10,
            'finished': 15,
            'started_monotonic': 10,
            'finished_monotonic': 15,
            'scope': 'scope-0-0',
            'token_type': 'session',
            'outcome': 'minted',
            'generation': 1,
            'process': 'broker-0-0',
        },
    )
    checks, _ = _slow(_Evidence(run))
    assert checks['measured_slow_cold_mint']
    assert not checks['cold_generation_delivered']


def test_minute_worker_schedules_from_common_fleet_release(tmp_path: Path) -> None:
    run = _run(tmp_path, 'cold-burst', 2, variant='minute')
    publish(tmp_path / 'dispatch.json', 10.020)
    publish(tmp_path / 'fleet-release.json', {'wall_time': 5.0, 'monotonic': 495.0})
    (tmp_path / 'fixture').write_bytes(b'fixture')
    with (
        patch.object(loadgen, 'time', autospec=True) as clock,
        patch.object(loadgen._Machine, 'fetch', return_value=True),
    ):
        clock.perf_counter.return_value = 500.0
        clock.time.return_value = 10.0
        loadgen._worker(run, 1, 1)
    clock.sleep.assert_called_once_with(25.0)
    assert json.loads((tmp_path / 'release-1.json').read_text()) == {
        'monotonic': 500.0,
        'wall_time': 10.0,
    }


def test_missing_receipt_for_retry_in_a_later_interval(tmp_path: Path) -> None:
    run = _run(tmp_path, 'slow-sg')
    publish(tmp_path / 'stream-clock.json', {'epoch': 9, 'stop': 20, 'slots': 44, 'cpus': [9]})
    for seq in range(44):
        due = 9 + seq / 4
        attempts = [
            {
                'attempt_id': f'stream-{seq}-0',
                'start_monotonic': due,
                'finish_monotonic': due + 0.1,
                'error': 'ReadTimeout',
            }
        ]
        if seq == 6:
            attempts.append(
                {
                    'attempt_id': 'stream-6-1',
                    'start_monotonic': 16,
                    'finish_monotonic': 16.1,
                    'status': 200,
                }
            )
        append(
            tmp_path / 'stream.jsonl',
            {'sequence': seq, 'start_monotonic': due, 'attempts': attempts},
        )
    _, detail = _scenarios._stream_evidence(_Evidence(run), [(10, 15), (15, 20)], {}, 10)
    results = cast('list[dict[str,object]]', detail['interval_results'])
    assert results[1]['verdict'] == 'inconclusive'


def test_missing_rotation_warm_receipt(tmp_path: Path) -> None:
    run = _run(tmp_path, 'rotation')
    for phase in ('measure', 'warm'):
        _call(run, 0, 1, phase, (10, 11))
    path = tmp_path / 'calls-0.jsonl'
    calls = [json.loads(line) for line in path.read_text().splitlines()]
    for c in calls:
        c['attempts'][0]['attempt_id'] = c['phase']
    path.write_text(''.join(json.dumps(c) + '\n' for c in calls))
    _receipt(run, 'measure', 0, 'measure', (200, '200'))
    assert not cast('dict[str, bool]', measurements(run)['expected_outcomes'])[
        'valid_proxy_source_distribution'
    ]
    _receipt(run, 'warm', 0, 'warm', (200, '200'))
    assert cast('dict[str, bool]', measurements(run)['expected_outcomes'])[
        'valid_proxy_source_distribution'
    ]
    # The request ID and peer still match when only the receipt's phase changes.
    proxy = tmp_path / 'proxy.jsonl'
    receipts = rows(proxy)
    receipts[-1]['phase'] = 'prepare'
    proxy.write_text(''.join(json.dumps(row) + '\n' for row in receipts))
    assert not cast('dict[str, bool]', measurements(run)['expected_outcomes'])[
        'valid_proxy_source_distribution'
    ]


def test_negative_fixture_receipt_in_error_inventory(tmp_path: Path) -> None:
    run = _run(tmp_path, 'bad-secrets')
    append(
        tmp_path / 'invalid.jsonl',
        {'sequence': 0, 'fixture': 'repeated', 'status': 429, 'finish': 10},
    )
    _receipt(run, '', 0, '', (429, '-'))
    path = tmp_path / 'proxy.jsonl'
    publish(path, dict(json.loads(path.read_text()), tag='0', retry_after='1'))
    errors = _scenarios._errors(_Evidence(run))
    assert errors['client_observations'] == {'429': 1}
    assert errors['original_causes'] == {'local_throttle_with_retry_after': 1}


def test_negative_proxy_route_requires_every_receipt(tmp_path: Path) -> None:
    run = _run(tmp_path, 'bad-secrets')
    publish(tmp_path / 'final-broker-0-0.json', {'direct_negative_accepts': 0})
    _receipt(run, 'measure', 0, 'valid', (200, '200'))
    for seq in range(2):
        append(
            tmp_path / 'invalid.jsonl',
            {'sequence': seq, 'status': 401, 'fixture': 'repeated' if seq == 0 else 'absent'},
        )
        _receipt(run, '-', 0, f'negative:{seq}', (401, '401'), tag=str(seq))
    checks, _ = _bad_secrets(_Evidence(run))
    assert checks['proxy_path_observed']
    path = tmp_path / 'proxy.jsonl'
    receipts = path.read_text().splitlines(keepends=True)
    path.write_text(''.join(receipts[:-1]))
    checks, _ = _bad_secrets(_Evidence(run))
    assert not checks['proxy_path_observed']


def test_negative_stream_gap_invalidates_cadence(tmp_path: Path) -> None:
    run = _paced_negative_stream(tmp_path)
    checks, _ = _bad_secrets(_Evidence(run))
    assert checks['invalid_traffic_spanned_valid_acquisitions']

    path = tmp_path / 'invalid.jsonl'
    dispatches = rows(path)
    # Delay just this dispatch by 4 ms. The window count and schedule still qualify.
    dispatches[11]['sent_monotonic'] = 10.054
    path.write_text(''.join(json.dumps(row) + '\n' for row in dispatches))
    checks, _ = _bad_secrets(_Evidence(run))
    assert not checks['invalid_traffic_spanned_valid_acquisitions']


def test_observer_control_disables_only_benchmark_access_log(tmp_path: Path) -> None:
    run = _run(tmp_path, 'slow-sg')
    (tmp_path / 'observer-control').touch()
    publish(tmp_path / 'deployment-topology.json', 4)
    reference = Path(__file__).resolve().parents[1] / 'docs' / 'reverse-proxy.conf'
    with (
        patch.object(launcher, '_REFERENCE', reference),
        patch.object(launcher.shutil, 'which', return_value='/usr/sbin/nginx'),
        patch.object(launcher.shutil, 'copyfile'),
    ):
        _, conf = launcher._proxy_config(run, tmp_path)
    assert Path(conf).read_text().replace('    access_log off;\n', '') == reference.read_text()


def test_one_source_generator_shares_linux_namespace_and_uses_tls(tmp_path: Path) -> None:
    run = _run(tmp_path, 'bad-secrets')
    with (
        patch.object(benchmark, '_docker', return_value='docker'),
        patch.object(benchmark.asyncio, 'create_subprocess_exec') as launch,
    ):
        assert asyncio.run(benchmark._generator(run, 'negative')) is launch.return_value
    args = launch.call_args.args
    assert args[0] == 'docker'
    assert (
        args[args.index('--network') + 1]
        == f'container:sgtb-{tmp_path.parent.name}-{tmp_path.name}'
    )
    assert '--farm-network' in args
    assert '--direct' not in args


def test_outage_cause_needs_observer_clock(tmp_path: Path) -> None:
    run = _run(tmp_path, 'sg-outage')
    publish(
        tmp_path / 'active.json',
        {'time': 9, 'monotonic': 9, 'unavailable_until_monotonic': 39, 'cutoff': 0},
    )
    for role in ('fleet', 'deployment', 'observer'):
        publish(
            tmp_path / f'clock-{role}.json', {'domain': 'foreign' if role == 'observer' else 'vm'}
        )
    _call(run, 0, 1, 'measure', (10, 11))
    path = tmp_path / 'calls-0.jsonl'
    call = json.loads(path.read_text())
    call['attempts'][0].update(
        attempt_id='sg', code='upstream_unavailable', status=503, finish_monotonic=11
    )
    publish(path, call)
    _receipt(run, 'measure', 0, 'sg', (503, '503'))
    path = tmp_path / 'proxy.jsonl'
    publish(path, dict(json.loads(path.read_text()), upstream_addr='127.0.0.1:8743'))
    append(
        tmp_path / 'mints.jsonl',
        {
            'scope': 'scope-0-0',
            'process': 'broker-0-0',
            'token_type': 'session',
            'outcome': 'unavailable',
            'started': 10,
            'finished': 10.5,
        },
    )
    assert not _scenarios._errors(_Evidence(run))['intended_fault']
    publish(tmp_path / 'clock-observer.json', {'domain': 'vm'})
    assert _scenarios._errors(_Evidence(run))['intended_fault'] == {'upstream_unavailable': 1}


def test_overlapping_service_and_observer_masks_invalidate_workload(tmp_path: Path) -> None:
    run = _run(tmp_path, 'slow-sg')
    for role, mask in {
        'deployment': [0, 1, 2, 3],
        'broker-0-0': [0, 1, 2, 3],
        'fleet': [4, 5, 6, 7, 8],
        'stream': [9],
        'probe': [4, 5, 6, 7, 8],
        'observer': [4],
    }.items():
        publish(tmp_path / f'clock-{role}.json', {'domain': 'test', 'cpus': mask})
    publish(tmp_path / 'proxy-affinity.json', [0, 1, 2, 3])
    report = measurements(run)
    assert cast('dict[str, bool]', report['workload_predicates'])['disjoint_cpu_placement']
    publish(tmp_path / 'clock-observer.json', {'domain': 'test', 'cpus': [3, 4]})
    report = measurements(run)
    assert 'disjoint_cpu_placement' in cast('list[str]', report['invalid_reasons'])


def test_partial_machine_cannot_meet_latency_target(tmp_path: Path) -> None:
    run = _run(tmp_path, 'cold-burst')
    _call(run, 0, 1, 'measure', (10, 11))
    report = measurements(run)
    primary = cast('dict[str, object]', report['primary_latency'])
    assert primary['successful_machines'] == 0
    assert primary['successful_calls'] == primary['missing_calls'] == 1
    assert primary['scheduled_calls'] == 2
    assert primary['call_seconds'] == dict.fromkeys(('median', 'p95', 'p99', 'max'), 1)
    assert not cast('dict[str, bool]', report['service_results'])['primary_latency_target']


def test_proxy_logs_all_hop_fields(tmp_path: Path) -> None:
    run = _run(tmp_path, 'cold-burst')
    with (
        patch.object(launcher, '_REFERENCE', Path('docs/reverse-proxy.conf')),
        patch.object(launcher.shutil, 'which', return_value='nginx'),
        patch.object(launcher.shutil, 'copyfile'),
    ):
        _, config = launcher._proxy_config(run, tmp_path)
    for field in (
        'connection',
        'connection_requests',
        'ssl_session_reused',
        'upstream_connect_time',
        'upstream_header_time',
        'upstream_response_time',
    ):
        assert f'${field}"' in Path(config).read_text()


@pytest.mark.parametrize('scenario', ['slow-sg', 'slow-control'])
def test_public_report_preserves_each_warm_interval(tmp_path: Path, scenario: str) -> None:
    run = _run(tmp_path, scenario)
    for role, mask in {
        'deployment': [0, 1, 2, 3],
        'broker-0-0': [0, 1, 2, 3],
        'fleet': [4],
        'observer': [4],
        'probe': [4],
        'stream': [5],
    }.items():
        publish(tmp_path / f'clock-{role}.json', {'domain': 'test', 'cpus': mask})
    publish(tmp_path / 'proxy-affinity.json', [0, 1, 2, 3])
    _call(run, 1, 1, 'prepare', (7, 8))
    calls = tmp_path / 'calls-0.jsonl'
    prime = json.loads(calls.read_text())
    prime['attempts'][0]['attempt_id'] = 'prime'
    calls.write_text(json.dumps(prime) + '\n')
    _receipt(run, 'prepare', 1, 'prime', (200, '200'), upstream_addr='127.0.0.1:8743')
    control = scenario == 'slow-control'
    intervals = [(10, 10.1)] if control else [(10, 15), (15, 20)]
    for generation, (start, end) in enumerate([(7, 7.5), *intervals], 1):
        append(
            tmp_path / 'mints.jsonl',
            {
                'started': start,
                'finished': end,
                'started_monotonic': start,
                'finished_monotonic': end,
                'outcome': 'minted',
                'scope': 'warm' if generation == 1 else 'scope-0-0',
                'process': 'broker-0-0',
                'token_type': 'session',
                'generation': generation,
            },
        )
        if generation > 1:
            _call(run, 0, generation, 'measure', (start, end))
    publish(tmp_path / 'stream-clock.json', {'epoch': 9, 'stop': 20, 'slots': 44, 'cpus': [9]})
    for seq in range(44):
        due = 9 + seq / 4
        append(
            tmp_path / 'stream.jsonl',
            {
                'sequence': seq,
                'start_monotonic': due + (0.2 if seq == 5 and not control else 0),
                'attempt_id': str(seq),
                'error': 'ReadTimeout',
                'finish_monotonic': due + 0.3,
            },
        )
    report = measurements(run)
    detail = cast('dict[str, object]', report['warm_stream'])
    results = cast('list[dict[str, object]]', detail['interval_results'])
    assert [(r['start'], r['end'], r['verdict']) for r in results] == (
        [(10, 15, 'miss')] if control else [(10, 15, 'inconclusive'), (15, 20, 'miss')]
    )


@pytest.mark.parametrize('code', ['invalid_client', 'server_busy', 'private-marker'])
def test_negative_fixture_records_only_known_error_codes(tmp_path: Path, code: str) -> None:
    run = _run(tmp_path, 'bad-secrets')
    response = MagicMock(status_code=401 if code == 'invalid_client' else 503)
    response.json.return_value = {'error': code, 'detail': 'private-marker'}
    with patch.object(requests.Session, 'send', return_value=response) as send:
        record = loadgen._negative_fixture(run, 0, 'synthetic-test-value', 10)
    assert send.call_args.args[0].headers['X-Farm-Attempt'] == 'negative:0'
    assert record.get('code') == (None if code == 'private-marker' else code)
    assert 'private-marker' not in json.dumps(record)


@pytest.mark.parametrize('scenario', ['rejected-tokens', 'cold-burst'])
def test_only_recovery_constrains_generator_and_observer_memory(
    tmp_path: Path, scenario: str
) -> None:
    run = replace(_run(tmp_path, scenario), direct=False)
    for start, budget in (
        (partial(benchmark._generator, run, 'fleet'), '8g'),
        (partial(benchmark._observer, run), '1g'),
    ):
        with (
            patch.object(benchmark, '_docker', return_value='docker'),
            patch.object(benchmark.asyncio, 'create_subprocess_exec') as launch,
        ):
            assert asyncio.run(start()) is launch.return_value
        args = launch.call_args.args
        if scenario == 'rejected-tokens':
            assert args[args.index('--memory') + 1] == budget
            assert args[args.index('--memory-swap') + 1] == budget
        else:
            assert '--memory' not in args
            assert '--memory-swap' not in args


@pytest.mark.parametrize('processes', [1, 2])
def test_common_successor_reached_through_refresh(tmp_path: Path, processes: int) -> None:
    run = _renewal_trace(tmp_path, processes)
    checks, _ = _renewal(_Evidence(run))
    assert all(checks.values())


@pytest.mark.usefixtures('isolated_farm_audit')
def test_raw_scrypt_counts_name_computed_hash_and_padding(tmp_path: Path) -> None:
    config = tmp_path / 'config.json'
    publish(
        config,
        {
            'site_url': 'http://127.0.0.1:8743',
            'clients': {'farm': {'secret_hash': BROKER_HASH, 'scopes': ['read']}},
            'scopes': {'read': {'script_name': 'read', 'script_key_env': 'FIXTURE_KEY'}},
        },
    )

    def exercise(*_args: object) -> MagicMock:
        verifier = SecretVerifier(waiting=WaitingShare(1), work=2)
        credentials = (('old', 'hash-a'), ('new', 'hash-b'))
        for client, hashes, secret in [
            ('farm', credentials, 'hash-b'),
            ('farm', credentials, 'hash-b'),
            ('farm', credentials, 'wrong'),
            ('absent', (), 'wrong'),
        ]:
            verifier.verify(client, hashes, secret)
        return MagicMock()

    with (
        patch.object(launcher._secrets, 'verify_secret', side_effect=operator.eq),
        patch.object(launcher, 'create_server', side_effect=exercise),
        patch.object(launcher.sys, 'stdin', io.StringIO()),
    ):
        launcher._broker(config, tmp_path, 'broker')
    counts = json.loads((tmp_path / 'final-broker.json').read_text())
    assert counts['verified'] == {'farm/new': 1}
    assert counts['scrypt'] == {'farm/old': 2, 'farm/new': 2, 'padding': 2}


def test_receipt_gap_only_invalidates_its_interval(tmp_path: Path) -> None:
    run = _run(tmp_path, 'slow-sg')
    publish(tmp_path / 'stream-clock.json', {'epoch': 9, 'stop': 20, 'slots': 44, 'cpus': [9]})
    for i in range(44):
        due = 9 + i / 4
        append(
            tmp_path / 'stream.jsonl',
            {
                'sequence': i,
                'start_monotonic': due,
                'finish_monotonic': due + 0.1,
                'attempt_id': f'stream-{i}-0',
                'status': 429,
            },
        )
        if i != 6:
            _receipt(run, 'stream', 2, f'stream-{i}-0', (429, '-'))
    _, detail = _scenarios._stream_evidence(_Evidence(run), [(10, 15), (15, 20)], {}, 10)
    assert not detail['reconciled']
    assert [r['verdict'] for r in cast('list[dict[str,object]]', detail['interval_results'])] == [
        'inconclusive',
        'miss',
    ]


def test_recovery_concurrency_is_bounded_across_a_full_fleet(tmp_path: Path) -> None:
    run = _run(tmp_path, 'rejected-tokens', 10_000)
    starts = range(0, run.machines, run.shard_size)
    assert len(starts) <= 8
    assert len(starts) * loadgen.CLI_SLOTS_PER_SHARD <= 16
    assert replace(run, scenario='cold-burst').shard_size == 80


def test_recovery_shard_primes_both_groups_before_releasing_jobs(tmp_path: Path) -> None:
    run = _run(tmp_path, 'rejected-tokens', 6)
    machines = [MagicMock(index=i, expiry=100.0, calls=[]) for i in range(run.machines)]
    checks = MagicMock()
    publish(tmp_path / 'fleet-release.json', {'monotonic': 1.0})
    for machine in machines:

        def measured(*_args: object, m: MagicMock = machine) -> None:
            assert all(other.prime.called for other in machines)
            assert (tmp_path / 'primed-0.json').exists()
            m.calls.append(
                {
                    'loadgen_queue_seconds': 0.0,
                    'dispatch_to_result_seconds': 1.0,
                    'finish_monotonic': 8.0,
                }
            )

        machine.measure.side_effect = measured
    with (
        patch.object(loadgen, '_Machine', side_effect=machines),
        patch.object(loadgen, '_SessionChecks', return_value=checks),
        patch.object(loadgen.time, 'perf_counter', return_value=2.0),
    ):
        loadgen._worker(run, 0, run.machines)
    for machine in machines:
        machine.prime.assert_called_once_with()
        machine.measure.assert_called_once_with(checks, 1.0, 0)
        assert machine.calls[0]['loadgen_queue_seconds'] == 1.0
        assert machine.calls[0]['dispatch_to_result_seconds'] == 7.0


def test_reference_allows_one_failover_without_replaying_a_sent_post() -> None:
    directives = [
        line.strip().rstrip(';').split()
        for line in Path('docs/reverse-proxy.conf').read_text().splitlines()
        if line.strip().startswith('proxy_next_upstream')
    ]
    assert sorted(directives) == [
        ['proxy_next_upstream', 'error', 'timeout'],
        ['proxy_next_upstream_timeout', '3s'],
        ['proxy_next_upstream_tries', '2'],
    ]


def test_reference_has_four_eligible_peers_with_burst_headroom() -> None:
    directives = [
        line.strip().rstrip(';').split()
        for line in Path('docs/reverse-proxy.conf').read_text().splitlines()
        if line.strip().startswith('server 127.0.0.1:')
    ]
    assert [peer[1] for peer in directives] == [f'127.0.0.1:{port}' for port in range(8743, 8747)]
    assert all('max_fails=0' in peer for peer in directives)
    assert all('max_conns=768' in peer for peer in directives)


def test_renewal_allows_a_primed_backend_to_receive_no_refreshes(tmp_path: Path) -> None:
    checks, _ = _renewal(_Evidence(_renewal_trace(tmp_path, 2, 'one serving successor')))
    assert all(checks.values())


def test_renewal_allows_only_one_successor_per_serving_process(tmp_path: Path) -> None:
    run = _renewal_trace(tmp_path, 1)
    checks, _ = _renewal(_Evidence(run))
    assert all(checks.values())
    path = tmp_path / 'mints.jsonl'
    successor = rows(path)[-1]
    append(path, dict(successor, generation=20, started=260, finished=260))
    checks, _ = _renewal(_Evidence(run))
    assert not checks['at_most_one_successor_per_process']
    assert not checks['all_moved_to_new_generation']


def test_renewal_needs_a_prime_for_every_machine(tmp_path: Path) -> None:
    run = _renewal_trace(tmp_path, 1)
    checks, _ = _renewal(_Evidence(run))
    assert all(checks.values())
    path = tmp_path / 'calls-0.jsonl'
    calls = rows(path)
    path.write_text(
        ''.join(
            json.dumps(call) + '\n'
            for call in calls
            if (call['machine'], call['phase']) != (1, 'prepare')
        )
    )
    checks, _ = _renewal(_Evidence(run))
    assert not checks['one_initial_generation_per_process']
    assert not checks['all_moved_to_new_generation']


@pytest.mark.parametrize(
    'fault',
    [
        'early mint',
        'early HTTP response',
        'old generation',
        'wrong backend',
        'different expiry',
    ],
)
def test_renewal_needs_the_serving_process_successor(tmp_path: Path, fault: str) -> None:
    checks, _ = _renewal(_Evidence(_renewal_trace(tmp_path, 2, fault)))
    assert not checks['all_moved_to_new_generation']


@pytest.mark.parametrize(
    ('second_process', 'covered'), [('broker-1-0', True), ('broker-3-0', False)]
)
def test_many_client_keys_can_be_split_between_configured_brokers(
    tmp_path: Path, second_process: str, covered: bool
) -> None:
    run = _run(tmp_path, 'many-clients', 2)
    publish(tmp_path / 'deployment-topology.json', 2)
    for slot in range(2):
        process = f'broker-{slot}-0'
        (tmp_path / f'audit-{process}.jsonl').touch()
        for phase in ('baseline', 'final'):
            publish(
                tmp_path / f'{phase}-{process}.json',
                {'verified': {}, 'scrypt': {}, 'audit_bytes': 0},
            )
        _call(run, slot, slot + 1, 'measure', (11, 12))
        append(
            tmp_path / 'mints.jsonl',
            {
                'process': second_process if slot else process,
                'scope': f'scope-0-{slot}',
                'token_type': 'session',
                'generation': slot + 1,
                'started': 11,
                'finished': 11.5,
                'outcome': 'minted',
            },
        )
    with (
        patch.object(_scenarios, 'MANY_CLIENTS', 1),
        patch.object(_scenarios, 'SCOPES_PER_CLIENT', 2),
    ):
        assert _burst(_Evidence(run))['workload_coverage'] is covered


def test_renewal_polling_continues_after_another_initial_session(tmp_path: Path) -> None:
    run = _run(tmp_path, 'synchronized-renewal')
    machine = loadgen._Machine.__new__(loadgen._Machine)
    machine._run = run
    machine.generation = 1
    results = iter([2, 3])

    def fetch(*_args: object) -> bool:
        machine.generation = next(results)
        return True

    with patch.object(machine, 'fetch', side_effect=fetch), patch.object(loadgen, 'time') as clock:
        clock.monotonic.return_value = 10.0
        machine.measure(None, 10, 2)
    assert machine.generation == 3


def test_rest_prime_starved_backend_publishes_incomplete_proof(tmp_path: Path) -> None:
    run = _run(tmp_path, 'warm-burst', variant='simultaneous')
    publish(tmp_path / 'warm-topology.json', 2)
    (tmp_path / 'prime-rest').touch()
    machine = MagicMock(index=0, scope='scope', generation=1)
    machine.calls = [{'generation': 1, 'token_type': 'rest', 'attempts': []}]
    append(
        tmp_path / 'mints.jsonl',
        {
            'generation': 1,
            'scope': 'scope',
            'process': 'broker-0-0',
            'token_type': 'rest',
            'outcome': 'minted',
        },
    )

    def fetch(*_args: object, **_kwargs: object) -> bool:
        machine.calls.append({'attempts': [{'attempt_id': 'only-first-peer'}]})
        return True

    machine.fetch.side_effect = fetch
    with (
        patch.object(loadgen.time, 'monotonic', side_effect=iter(range(0, 1801, 10))),
        patch.object(loadgen.time, 'sleep'),
    ):
        loadgen._prime_rest_window(machine, run)
    assert json.loads((tmp_path / 'rest-primed.json').read_text())['incomplete']


def test_rest_prime_waits_for_matching_fixture_record_and_both_peers(tmp_path: Path) -> None:
    run = _run(tmp_path, 'warm-burst', variant='simultaneous')
    (tmp_path / 'prime-rest').touch()
    publish(tmp_path / 'warm-topology.json', 2)
    mint = {
        'scope': 'scope-0-0',
        'process': 'broker-0-0',
        'token_type': 'session',
        'outcome': 'minted',
        'finished': 1,
        'finished_monotonic': 1,
        'generation': 1,
    }
    append(tmp_path / 'mints.jsonl', mint)
    machine = MagicMock(index=0, scope='scope-0-0', generation=2)
    machine.calls = [{'phase': 'prepare', 'token_type': 'rest', 'generation': 2}]

    def flush(_: float) -> None:
        path = tmp_path / 'mints.jsonl'
        if len(path.read_text().splitlines()) == 1:
            append(path, {**mint, 'token_type': 'rest', 'generation': 2})

    responses = iter([(0, 3), (0, 3), (1, 4)])

    def fetch(_phase: str, _kind: str, *, force: bool) -> bool:
        peer, gen = next(responses)
        assert force
        name = f'prime-{len(machine.calls)}'
        machine.calls.append(
            {
                'phase': 'prime-rest',
                'token_type': 'rest',
                'generation': gen,
                'attempts': [{'attempt_id': name, 'status': 200}],
            }
        )
        machine.generation = gen
        append(
            tmp_path / 'mints.jsonl',
            {
                **mint,
                'token_type': 'rest',
                'generation': gen,
                'process': f'broker-{peer}-0',
                'finished': 68,
                'started_monotonic': 67,
                'finished_monotonic': 68,
            },
        )
        append(
            tmp_path / 'proxy.jsonl',
            {
                'phase': 'prime-rest',
                'attempt_id': name,
                'method': 'POST',
                'uri': '/v1/token',
                'peer': '127.1.0.1',
                'upstream_addr': f'127.0.0.1:{8743 + peer}',
                'upstream': '200',
                'status': 200,
            },
        )
        return True

    machine.fetch.side_effect = fetch
    with (
        patch.object(loadgen.time, 'sleep', side_effect=flush),
        patch.object(loadgen.time, 'monotonic', return_value=65),
        patch.object(loadgen.time, 'time', return_value=65),
    ):
        loadgen._prime_rest_window(machine, run)
    assert machine.fetch.call_count == 3
    marker = json.loads((tmp_path / 'rest-primed.json').read_text())
    assert not marker.get('incomplete')
    assert marker['by_upstream'] == {'127.0.0.1:8743': 3, '127.0.0.1:8744': 4}
    assert marker['evidence'] == 'proxy_receipt'


def test_rest_window_uses_broker_cache_insertion(tmp_path: Path) -> None:
    run = _warm_run(tmp_path)
    group = next(v for k, v in _Evidence(run).priming.items() if k.endswith('/rest'))
    first = dict(group[0], cache_started_monotonic=4)
    second = dict(group[0], started_monotonic=63.9, started=100)
    assert not _scenarios._mint_bound(cast('list[_scenarios._Mint]', [first, second]))


def test_restart_attributes_only_the_affected_upstream(tmp_path: Path) -> None:
    run = _run(tmp_path, 'process-restart')
    for role in ('fleet', 'deployment'):
        publish(tmp_path / f'clock-{role}.json', {'domain': 'test'})
    publish(tmp_path / 'restart.json', {'started_monotonic': 12, 'finished_monotonic': 13})
    _call(run, 0, 1, 'measure', (11, 14))
    path = tmp_path / 'calls-0.jsonl'
    call = json.loads(path.read_text())
    call['attempts'] = [
        dict(
            call['attempts'][0],
            attempt_id=str(i),
            status=502,
            start_monotonic=12.1,
            finish_monotonic=12.9,
        )
        for i in range(2)
    ]
    publish(path, call)
    for i in range(2):
        _receipt(run, 'measure', 0, str(i), (502, '502'))
    path = tmp_path / 'proxy.jsonl'
    receipts = [
        dict(
            json.loads(line),
            connection=str(i),
            upstream_addr=f'127.0.0.1:{8743 + i}',
            upstream_connect_time='-',
            upstream_header_time='-',
        )
        for i, line in enumerate(path.read_text().splitlines())
    ]
    path.write_text(''.join(json.dumps(r) + '\n' for r in receipts))
    (tmp_path / 'nginx-error.log').write_text(
        ''.join(f'*{i} upstream timed out while connecting\n' for i in range(2))
    )
    errors = _scenarios._errors(_Evidence(run))
    assert errors['intended_fault'] == {'upstream_connect_timeout': 1}
    assert errors['other_causes'] == {'upstream_connect_timeout': 1}


def test_restart_between_calls_is_outside_the_burst(tmp_path: Path) -> None:
    run = _run(tmp_path, 'process-restart', 2)
    for i in range(2):
        name = f'broker-0-{i}'
        publish(tmp_path / f'final-{name}.json', {'scrypt': {}, 'verified': {}, 'audit_bytes': 0})
        (tmp_path / f'audit-{name}.jsonl').touch()
    publish(
        tmp_path / 'baseline-broker-0-0.json', {'scrypt': {}, 'verified': {}, 'audit_bytes': 0}
    )
    append(
        tmp_path / 'mints.jsonl',
        {
            'process': 'broker-0-1',
            'scope': 'scope-0-0',
            'token_type': 'session',
            'started': 14,
            'finished': 14.1,
            'generation': 2,
            'outcome': 'minted',
        },
    )
    _call(run, 0, 1, 'measure', (10, 11))
    _call(run, 1, 2, 'measure', (14, 15))
    publish(tmp_path / 'restart.json', {'started': 12, 'finished': 13})
    assert not _fault(_Evidence(run))['broker_restarted_mid_burst']


def test_restart_failover_attributes_the_final_broker_reply(tmp_path: Path) -> None:
    run = _run(tmp_path, 'process-restart')
    _call(run, 0, 1, 'measure', (10, 11))
    path = tmp_path / 'calls-0.jsonl'
    call = json.loads(path.read_text())
    call['attempts'][0].update(attempt_id='busy', status=503, code='server_busy')
    publish(path, call)
    _receipt(
        run,
        'measure',
        0,
        'busy',
        (503, '502, 503'),
        upstream_addr='127.0.0.1:8743, 127.0.0.1:8744',
        upstream_connect_time='-, 0.001',
        upstream_header_time='-, 0.003',
    )
    evidence = _Evidence(run)
    errors = _scenarios._errors(evidence)
    assert errors['original_causes'] == {'server_busy': 1}
    assert errors['upstream_failover_status_chains'] == {'502, 503': 1}
    assert evidence.trace.logs[0]['route'].terminal.backend == '127.0.0.1:8744'


@pytest.mark.parametrize(('status', 'code'), [(200, ''), (503, 'server_busy')])
def test_restart_timeout_followed_by_a_broker_response(
    tmp_path: Path, status: int, code: str
) -> None:
    run = _run(tmp_path, 'process-restart')
    publish(tmp_path / 'restart.json', {'started_monotonic': 10, 'finished_monotonic': 14})
    _call(run, 0, 1, 'measure', (10.1, 13))
    path = tmp_path / 'calls-0.jsonl'
    call = json.loads(path.read_text())
    call['attempts'][0].update(attempt_id='retried', finish_monotonic=13, status=status, code=code)
    publish(path, call)
    _receipt(
        run,
        'measure',
        0,
        'retried',
        (status, f'504, {status}'),
        connection='7',
        upstream_addr='127.0.0.1:8743, 127.0.0.1:8744',
        upstream_connect_time='-, 0.002',
        upstream_header_time='-, 0.003',
        finish=13,
        elapsed=2.8,
    )
    append(tmp_path / 'hops-broker-1-0.jsonl', {'attempt_id': 'retried', 'handler_start': 12.9})
    (tmp_path / 'nginx-error.log').write_text(
        '1970/01/01 00:00:12 *7 upstream timed out while connecting to upstream, '
        'client: 127.1.0.1, request: "POST /v1/token HTTP/1.1", '
        'upstream: "http://127.0.0.1:8743/v1/token"\n'
    )
    errors = _scenarios._errors(_Evidence(run))
    assert errors['intended_fault'] == {'upstream_connect_timeout': 1}
    assert errors['unassigned_gateway_events'] == {}
    assert errors['original_causes'] == {
        'upstream_connect_timeout': 1,
        **({code: 1} if code else {}),
    }
    assert errors['client_observations'] == {str(status): 1}
    assert errors['collateral_fault'] == ({code: 1} if code else {})


@pytest.mark.parametrize(
    ('stage', 'first_hop_fields', 'second_peer', 'owner'),
    [
        ('reading response header from', ('504', '0.002', '-'), 8743, 'first'),
        ('reading response header from', ('504', 'unknown', '-'), 8743, None),
        ('reading', ('503', '-', 'unknown'), 8743, None),
        ('connecting to', ('504, 200', '-, 0.002', None), 8743, None),
        ('connecting to', ('504, 200', '-, 0.002', '0.003'), 8743, None),
        ('connecting to', ('504, 200', '-, 0.002', None), 8745, None),
        ('connecting to', ('504, 200', '0.001, 0.002', None), 8743, 'second'),
        ('connecting to', ('504, 200', '0.001, 0.002', '-, -, 0.003'), 8743, 'second'),
        ('connecting to', ('504, 200', '-, 0.002', '0.136, 0.003'), 8743, 'second'),
    ],
)
def test_gateway_stage_and_partial_hops_on_adjacent_requests(
    tmp_path: Path,
    stage: str,
    first_hop_fields: tuple[str, str, str | None],
    second_peer: int,
    owner: str | None,
) -> None:
    run = _run(tmp_path, 'process-restart')
    _call(run, 0, 1, 'measure', (10, 41))
    path = tmp_path / 'calls-0.jsonl'
    call = json.loads(path.read_text())
    first_chain, connect, header = first_hop_fields
    first_status = int(first_chain.rsplit(', ', 1)[-1])
    call['attempts'] = [
        {'attempt_id': 'first', 'status': first_status},
        {'attempt_id': 'second', 'status': 200},
    ]
    publish(path, call)
    a, b = '127.0.0.1:8743', '127.0.0.1:8744'
    _receipt(
        run,
        'measure',
        0,
        'first',
        (first_status, first_chain),
        connection='7',
        connection_requests='1',
        upstream_addr=f'{a}, {b}' if ', ' in first_chain else a,
        upstream_connect_time=connect,
        finish=40.1,
        elapsed=30,
        **({'upstream_header_time': header} if header is not None else {}),
    )
    _receipt(
        run,
        'measure',
        0,
        'second',
        (200, '502, 200'),
        connection='7',
        connection_requests='2',
        upstream_addr=f'127.0.0.1:{second_peer}, {b}',
        upstream_connect_time='-, 0.001',
        upstream_header_time='-, 0.003',
        finish=40.2,
        elapsed=0.05,
    )
    (tmp_path / 'nginx-error.log').write_text(
        f'1970/01/01 00:00:40 *7 upstream timed out while {stage} upstream, '
        f'client: 127.1.0.1, request: "POST /v1/token HTTP/1.1", upstream: "http://{a}/v1/token"\n'
    )
    trace = _Evidence(run).trace
    assert [o.identifier for o in trace.observations if o.event or o.recovered] == (
        [owner] if owner else []
    )
    assert len(trace.unassigned) == int(owner is None)


@pytest.mark.parametrize('fixture', ['throttled upstream', 'overlong connect'])
@pytest.mark.parametrize('column', ['504, 429', '429', None])
def test_missing_upstream_status_cannot_exempt_the_competing_restart(
    tmp_path: Path,
    fixture: str,
    column: str | None,
) -> None:
    run = _gateway_receipt_trace(tmp_path, fixture)
    path = tmp_path / 'proxy.jsonl'
    first, second = (json.loads(line) for line in path.read_text().splitlines())
    if column is None:
        del first['upstream']
    else:
        first['upstream'] = column
    path.write_text(json.dumps(first) + '\n' + json.dumps(second) + '\n')
    e = _Evidence(run)
    errors = _scenarios._errors(e)
    assert (
        errors['gateway_events']
        == errors['unassigned_gateway_events']
        == {'upstream_connect_timeout': 1}
    )
    assert not errors['intended_fault']
    assert e.trace.observations[0].cause == 'unclassified'


@pytest.mark.parametrize(
    'fixture',
    [
        'headers',
        'partial timing',
        'throttled upstream',
        'overlong connect',
        'recovered',
        'body',
        'body with connect dash',
        'contradictory limiter',
        'duplicate attempt ID',
        'no peers',
        'ordered',
    ],
)
def test_losing_receipt_evidence_cannot_strengthen_assignment(
    tmp_path: Path,
    fixture: str,
) -> None:
    run = _gateway_receipt_trace(tmp_path, fixture)
    prior, exempted, prior_joined = _gateway_assignments(run)
    path = tmp_path / 'proxy.jsonl'
    receipts = [json.loads(line) for line in path.read_text().splitlines()]
    for index, row in enumerate(receipts):
        recorded = _recorded_route_evidence(row)
        for field in (
            'upstream',
            'upstream_addr',
            'upstream_connect_time',
            'upstream_header_time',
            'connection',
            'connection_requests',
            'finish',
            'elapsed',
            'status',
            'peer',
            'attempt_id',
            'phase',
            'method',
            'uri',
            'tag',
            'remote_port',
            'worker_pid',
            'ssl_protocol',
            'ssl_curve',
            'ssl_session_reused',
            'upstream_response_time',
            'retry_after',
            'limit_req',
            'limit_conn',
        ):
            for damaged in _receipt_mutations(receipts, index, field):
                changed = receipts.copy()
                if damaged is None:
                    del changed[index]
                else:
                    changed[index] = damaged
                path.write_text(''.join(json.dumps(r) + '\n' for r in changed))
                assignments, intended, joined = _gateway_assignments(run)
                remaining = _recorded_route_evidence(damaged or {})
                # A repair restores route evidence or a unique request join.
                # Compare from the repaired trace to the one with less evidence.
                if remaining - recorded or joined - prior_joined:
                    assert prior <= assignments == {(1, 'post-1', '127.0.0.1:8743')}, field
                    assert exempted <= intended == 1, field
                else:
                    assert assignments <= prior, (index, field, damaged and damaged.get(field))
                    assert intended <= exempted, (index, field, damaged and damaged.get(field))
                if fixture.startswith('body') and index == 0 and field == 'upstream_connect_time':
                    assert assignments == prior == {(1, 'post-0', '127.0.0.1:8743')}, field
                    assert intended == exempted == 0, field


def test_scheduler_publishes_elapsed_tail_after_stop(tmp_path: Path) -> None:
    run = _run(tmp_path, 'slow-control')
    records: list[dict[str, object]] = [{'sequence': 0, 'slot': 'sent', 'due': 10}]
    _warm_stream._publish_slots(run, records, 10, 10.9)
    result = [json.loads(line) for line in (tmp_path / 'stream.jsonl').read_text().splitlines()]
    assert [(r['sequence'], r['slot']) for r in result] == [
        (0, 'sent'),
        (1, 'late'),
        (2, 'late'),
        (3, 'late'),
    ]


def test_second_broker_expired_rest_cannot_hide_behind_fresh_first(tmp_path: Path) -> None:
    run = _warm_run(tmp_path)
    publish(tmp_path / 'warm-topology.json', 2)
    publish(tmp_path / 'fleet-release.json', {'monotonic': 101})
    evidence = _Evidence(run)
    key = 'broker-0-0/farm-0/scope-0-0/rest'
    mint = evidence.priming[key][0]
    second = mint.copy()
    mint['cache_started_monotonic'] = 98
    second.update(process='broker-1-0', generation=4, cache_started_monotonic=3)
    evidence.priming[key.replace('broker-0-0', 'broker-1-0')].append(second)
    assert not _scenarios._rest_windows_cover_release(evidence)
    second['cache_started_monotonic'] = 99
    assert _scenarios._rest_windows_cover_release(evidence)


@pytest.mark.parametrize(
    ('scenario', 'expected'),
    [
        ('cold-burst', 3),
        ('warm-burst', 3),
        ('many-clients', 3),
        ('rotation', 3),
        ('bad-secrets', 3),
        ('sg-outage', 3),
        ('rejected-script-key', 3),
        ('process-restart', 3),
        ('synchronized-renewal', 3),
        ('two-processes', 2),
        ('rejected-tokens', 2),
    ],
)
def test_selected_deployment_preserves_prescribed_topologies(
    tmp_path: Path, scenario: str, expected: int
) -> None:
    run = _run(tmp_path, scenario)
    publish(tmp_path / 'deployment-topology.json', 3)
    assert run.brokers == expected


@pytest.mark.parametrize('duplicate', [False, True])
def test_negative_proxy_route_needs_unique_dispatches(tmp_path: Path, *, duplicate: bool) -> None:
    run = _run(tmp_path, 'bad-secrets')
    _receipt(run, 'measure', 0, 'valid', (200, '200'))
    publish(tmp_path / 'final-broker-0-0.json', {'direct_negative_accepts': 0})
    for sequence, status in [(4, 401), (4 if duplicate else 5, 503)]:
        append(
            tmp_path / 'invalid.jsonl',
            {'sequence': sequence, 'status': status, 'fixture': 'repeated'},
        )
        _receipt(run, '-', 0, '-', (status, str(status)), tag=str(sequence), peer='127.0.0.1')
    checks, _ = _bad_secrets(_Evidence(run))
    assert checks['proxy_path_observed'] is not duplicate


@pytest.mark.parametrize(
    ('field', 'value', 'routed'),
    [
        ('peer', None, False),
        ('peer', '-', False),
        ('peer', 'invalid', False),
        ('peer', 1, False),
        ('attempt_id', 'negative:1', False),
        ('attempt_id', None, True),
    ],
)
def test_one_source_requires_recorded_address_and_consistent_ids(
    tmp_path: Path, field: str, value: object, *, routed: bool
) -> None:
    run = _run(tmp_path, 'bad-secrets')
    publish(tmp_path / 'final-broker-0-0.json', {'direct_negative_accepts': 0})
    _receipt(run, 'measure', 0, 'valid', (200, '200'))
    append(tmp_path / 'invalid.jsonl', {'sequence': 0, 'status': 401, 'fixture': 'repeated'})
    _receipt(run, '-', 0, 'negative:0', (401, '401'), tag='0')
    path = tmp_path / 'proxy.jsonl'
    valid, negative = map(json.loads, path.read_text().splitlines())
    if value is None:
        del negative[field]
    else:
        negative[field] = value
    path.write_text(json.dumps(valid) + '\n' + json.dumps(negative) + '\n')
    report = measurements(run)
    assert cast('dict[str, bool]', report['workload_predicates'])['proxy_path_observed'] is routed
    if field == 'peer':
        assert cast('dict[str, bool]', report['service_results'])['invalid_statuses_allowed']


@pytest.mark.parametrize('existing', [True, False])
def test_partial_setup_cleans_only_its_own_seed(tmp_path: Path, *, existing: bool) -> None:
    run = Run(tmp_path / 'case', 'tls-smoke', 1, 'simultaneous', direct=False)
    seed = run.directory / 'fixture'
    if existing:
        run.directory.mkdir()
        seed.write_bytes(b'prior')
        with pytest.raises(FileExistsError):
            asyncio.run(benchmark._case(run, MagicMock(), smoke=False))
        assert seed.read_bytes() == b'prior'
        return
    with (
        patch.object(benchmark, 'publish', side_effect=OSError('marker failed')),
        pytest.raises(OSError, match='marker failed'),
    ):
        asyncio.run(benchmark._case(run, MagicMock(), smoke=False))
    assert not seed.exists()


@pytest.mark.parametrize('population', ['fleet', 'stream'])
def test_reflected_broker_code_stays_out_of_attempts(tmp_path: Path, population: str) -> None:
    run = _run(tmp_path, 'slow-sg')
    (tmp_path / 'fixture').write_bytes(b'fixture')
    marker = 'sk-fixture-credential-104'
    response = requests.Response()
    response.status_code = 401
    with (
        requests.Session() as session,
        patch.object(session, 'send', return_value=response),
        patch.object(response, 'json', return_value={'error': marker, 'detail': marker}),
    ):
        if population == 'fleet':
            buffer = loadgen._AttemptBuffer()
            buffer.observe(session.send)(requests.Request('POST', run.url).prepare())
            attempts = buffer.drain()
        else:
            event = _warm_stream._send(session, run, 7, 10)
            attempts = cast('list[dict[str, object]]', event['attempts'])
        assert marker not in json.dumps(attempts)
        assert attempts[0]['status'] == 401
        assert attempts[0]['attempt_id']


@pytest.mark.parametrize('product_hook', [False, True], ids=['malformed-host', 'closed-response'])
def test_failed_redirect_keeps_wire_attempt(tmp_path: Path, *, product_hook: bool) -> None:
    response = requests.Response()
    response.status_code = 307
    response.url = 'https://origin.example/token'
    response.headers['Location'] = 'https://[invalid-host/path?secret=private-marker'
    response.raw = io.BytesIO(b'')
    rejection = requests.RequestException('private-marker', response=response)

    def reject(reply: requests.Response, **_kwargs: object) -> None:
        reply.close()
        raise rejection

    with requests.Session() as session:
        prepared = session.prepare_request(requests.Request('POST', response.url))
        response.request = prepared
        if product_hook:
            prepared.register_hook('response', reject)
        original_hooks = list(prepared.hooks['response'])
        adapter = MagicMock(spec=HTTPAdapter)
        adapter.send.return_value = response
        session.mount('https://', adapter)
        buffer = loadgen._AttemptBuffer()
        with pytest.raises(requests.RequestException if product_hook else ValueError) as caught:
            buffer.observe(session.send)(prepared, allow_redirects=False)
        if product_hook:
            assert caught.value is rejection
        adapter.send.assert_called_once()
        assert prepared.hooks['response'] == original_hooks
        path = tmp_path / 'attempts.jsonl'
        (attempt,) = buffer.drain()
        append(path, attempt)
        (saved,) = observation_rows(path)
        assert saved['attempt_id'] == adapter.send.call_args.args[0].headers['X-Farm-Attempt']
        assert saved['status'] == 307
        assert saved['error'] == ('redirect' if product_hook else 'transport_error')
        assert 'private-marker' not in path.read_text()


@pytest.mark.parametrize(('status', 'code'), [(404, 'not_found'), (405, 'method_not_allowed')])
def test_broker_routing_errors_survive_observation(tmp_path: Path, status: int, code: str) -> None:
    response = requests.Response()
    response.status_code = status
    attempt: dict[str, object] = {}
    with patch.object(response, 'json', return_value={'error': code}):
        record_response(attempt, response)
    path = tmp_path / 'attempts.jsonl'
    append(path, attempt)
    (saved,) = observation_rows(path)
    assert (saved['status'], saved['code']) == (status, code)


@pytest.mark.parametrize(
    ('status', 'upstream', 'allowed'),
    [(502, '502', False), (429, '-', True), (429, '429', False), (503, '503', True)],
)
def test_negative_proxy_routing_is_independent_of_allowed_status(
    tmp_path: Path, status: int, upstream: str, *, allowed: bool
) -> None:
    run = _run(tmp_path, 'bad-secrets')
    publish(tmp_path / 'final-broker-0-0.json', {'direct_negative_accepts': 0})
    _receipt(run, 'measure', 0, 'valid', (200, '200'))
    append(tmp_path / 'invalid.jsonl', {'sequence': 0, 'status': status, 'fixture': 'repeated'})
    _receipt(run, '-', 0, '-', (status, upstream), tag='0')
    checks, _ = _bad_secrets(_Evidence(run))
    assert checks['proxy_path_observed']
    assert checks['invalid_statuses_allowed'] is allowed


@pytest.mark.parametrize('variant', ['one-source', 'unthrottled-broker'])
def test_negative_causes_require_independent_broker_evidence(tmp_path: Path, variant: str) -> None:
    run = _run(tmp_path, 'bad-secrets', variant=variant)
    for seq, (status, code) in enumerate(
        [(401, 'invalid_client'), (503, 'server_busy'), (401, 'invalid_client')]
    ):
        append(
            tmp_path / 'invalid.jsonl',
            {
                'sequence': seq,
                'status': status,
                'code': code,
                'fixture': 'absent',
                'local_port': 5000 + seq,
            },
        )
        if seq == 2:
            continue
        if variant == 'one-source':
            _receipt(
                run,
                '-',
                0,
                '-',
                (status, str(status)),
                tag=str(seq),
                upstream_addr='127.0.0.1:8743',
            )
        else:
            hop = (
                {'attempt_id': 'negative:0', 'disposition': 'handled'}
                if seq == 0
                else {'disposition': 'pre_handler'}
            )
            append(tmp_path / 'hops-broker-0-0.jsonl', dict(hop, peer=['127.0.0.2', 5000 + seq]))
    errors = _scenarios._errors(_Evidence(run))
    assert errors['original_causes'] == {'invalid_client': 1, 'server_busy': 1, 'unclassified': 1}


@pytest.mark.parametrize(('received', 'recovered'), [(41.5, True), (40.5, False)])
def test_outage_retry_can_be_in_flight_when_sg_recovers(
    tmp_path: Path, received: float, *, recovered: bool
) -> None:
    run = _outage_retry_run(tmp_path, (503,), direct=False)
    path = tmp_path / 'calls-0.jsonl'
    call = json.loads(path.read_text())
    # SG recovers at 40 and finishes issuing the returned generation at 41.2.
    call['attempts'][-1].update(
        start=39.9, start_monotonic=39.9, finish=received, finish_monotonic=received
    )
    publish(path, call)
    service = cast('dict[str, bool]', measurements(run)['service_results'])
    assert service['clients_observed_retry'] is recovered


@pytest.mark.parametrize('direct', [False, True])
@pytest.mark.parametrize('statuses', [(503,), (500,), (500, 503)])
def test_outage_retry_requires_the_contracted_broker_status(
    tmp_path: Path, statuses: tuple[int, ...], *, direct: bool
) -> None:
    report = measurements(_outage_retry_run(tmp_path, statuses, direct=direct))
    assert not report['invalid_reasons']
    errors = cast('dict[str, object]', report['errors'])
    assert errors['original_causes'] == {'upstream_unavailable': len(statuses)}
    assert report['outage_exposure_by_machine'] == {
        0: {'broker_upstream_unavailable': len(statuses)}
    }
    assert errors['client_observations'] == {str(s): statuses.count(s) for s in statuses}
    assert report['outage_client_outcomes_by_machine'] == {
        0: {'upstream_unavailable': len(statuses)}
    }
    contracted = all(s == 503 for s in statuses)
    assert (
        cast('dict[str, bool]', report['service_results'])['clients_observed_retry'] is contracted
    )
    assert report['verdict'] == ('pass' if contracted else 'miss')
    if contracted:
        assert errors['intended_fault'] == {'upstream_unavailable': len(statuses)}


@pytest.mark.parametrize(
    'evidence', ['missing_receipt', 'missing_hop', 'pre_handler', 'other_broker', 'duplicate_hop']
)
def test_outage_cause_requires_evidence_on_the_selected_route(
    tmp_path: Path, evidence: str
) -> None:
    run = _outage_retry_run(tmp_path, (503,), direct=evidence != 'missing_receipt')
    hops = tmp_path / 'hops-broker-0-0.jsonl'
    if evidence == 'missing_receipt':
        (tmp_path / 'proxy.jsonl').unlink()
    elif evidence == 'missing_hop':
        hops.unlink()
    elif evidence == 'pre_handler':
        publish(hops, {'attempt_id': '0', 'disposition': 'pre_handler'})
    elif evidence == 'other_broker':
        hops.rename(tmp_path / 'hops-broker-1-0.jsonl')
    else:
        append(hops, json.loads(hops.read_text().splitlines()[0]))
    report = measurements(run)
    assert report['outage_exposure_by_machine'] == {0: {'unclassified': 1}}
    assert not cast('dict[str, bool]', report['service_results'])['clients_observed_retry']


@pytest.mark.parametrize(
    ('upstream', 'cause'),
    [
        ('503', 'broker_upstream_unavailable'),
        (None, 'unclassified'),
        ('502', 'no_available_upstream'),
    ],
)
def test_outage_exposure_can_differ_between_retrying_machines(
    tmp_path: Path, upstream: str | None, cause: str
) -> None:
    run = _run(tmp_path, 'sg-outage', 2)
    for start, outcome in [(10, 'unavailable'), (50, 'minted')]:
        append(
            tmp_path / 'mints.jsonl',
            {
                'process': 'broker-0-0',
                'scope': 'scope-0-0',
                'token_type': 'session',
                'started': start,
                'finished': start + 0.1,
                'generation': 1,
                'outcome': outcome,
            },
        )
    for i, status in enumerate([503, 429]):
        _call(run, i, 1, 'measure', (10, 52))
        if i == 1:
            _receipt(run, 'measure', i, str(i), (status, '-'))
        elif upstream is not None:
            no_peer = upstream == '502'
            _receipt(
                run,
                'measure',
                i,
                str(i),
                (status, upstream),
                connection='1',
                upstream_addr='brokers' if no_peer else '127.0.0.1:8743',
                upstream_connect_time='-' if no_peer else '0.001',
                upstream_header_time='-' if no_peer else '0.002',
            )
            if no_peer:
                (tmp_path / 'nginx-error.log').write_text('*1 no live upstreams\n')
    path = tmp_path / 'calls-0.jsonl'
    calls = [json.loads(line) for line in path.read_text().splitlines()]
    for i, c in enumerate(calls):
        c['attempts'] = [
            {
                'start': 10,
                'finish': 11,
                'status': 503 if i == 0 else 429,
                'code': 'upstream_unavailable' if i == 0 else None,
                'attempt_id': str(i),
            },
            {'start': 51, 'finish': 52, 'status': 200, 'attempt_id': f'ok-{i}'},
        ]
    path.write_text(''.join(json.dumps(c) + '\n' for c in calls))
    result = measurements(run)
    assert cast('dict[str, bool]', result['expected_outcomes'])['clients_observed_retry'] == (
        cause == 'broker_upstream_unavailable'
    )
    assert result['outage_exposure_by_machine'] == {
        0: {cause: 1},
        1: {'proxy_throttled': 1},
    }
    assert result['outage_client_outcomes_by_machine'] == {
        0: {'upstream_unavailable': 1},
        1: {'429': 1},
    }
    if upstream == '503':
        # This broker error preceded the first unavailable SG mint.
        calls[0]['attempts'][0]['finish'] = 10.05
        path.write_text(''.join(json.dumps(c) + '\n' for c in calls))
        result = measurements(run)
        assert not cast('dict[str, bool]', result['expected_outcomes'])['clients_observed_retry']
        assert result['outage_exposure_by_machine'] == {
            0: {'broker_upstream_unavailable': 1},
            1: {'proxy_throttled': 1},
        }
        calls[0]['attempts'][0]['finish'] = 11

    calls[0]['attempts'][0]['code'] = 'server_busy'
    path.write_text(''.join(json.dumps(c) + '\n' for c in calls))
    assert not cast('dict[str, bool]', measurements(run)['expected_outcomes'])[
        'clients_observed_retry'
    ]


@pytest.mark.parametrize(
    ('bounds', 'disposition'),
    [
        ((11, 14, 11.1, 0), 'unresolved_fault'),
        ((20.1, 20.4, 20.2, 0), 'collateral_fault'),
        ((11, 12.8, 12.2, 0.01), 'intended_fault'),
        ((12.01, 12.99, 12.02, 0.05), 'unresolved_fault'),
    ],
)
def test_restart_failure_uses_monotonic_bounds(
    tmp_path: Path, bounds: tuple[float, float, float, float], disposition: str
) -> None:
    start, finish, sent, uncertainty = bounds
    run = _run(tmp_path, 'process-restart')
    publish(
        tmp_path / 'restart.json',
        {'started': 112, 'finished': 113, 'started_monotonic': 12, 'finished_monotonic': 13},
    )
    publish(
        tmp_path / 'clock-fleet.json',
        {'domain': 'test', 'sampling_uncertainty_seconds': uncertainty},
    )
    _call(run, 0, 1, 'measure', (11, 14))
    path = tmp_path / 'calls-0.jsonl'
    call = json.loads(path.read_text())
    call['attempts'] = [
        dict(
            call['attempts'][0],
            attempt_id='r',
            start_monotonic=start,
            http_send_entry=sent,
            finish_monotonic=finish,
            status=504,
        )
    ]
    publish(path, call)
    _receipt(run, 'measure', 0, 'r', (504, '504'))
    path = tmp_path / 'proxy.jsonl'
    receipt = dict(
        json.loads(path.read_text()),
        connection='1',
        upstream_addr='127.0.0.1:8743',
        finish=112.25,
        upstream_connect_time='0.001',
        upstream_header_time='-',
    )
    publish(path, receipt)
    (tmp_path / 'nginx-error.log').write_text('*1 upstream timed out while reading\n')
    errors = _scenarios._errors(_Evidence(run))
    assert errors[disposition] == {'upstream_read_timeout': 1}
    assert bool(errors['intended_fault']) == (disposition == 'intended_fault')


@pytest.mark.parametrize('scenario', ['bad-secrets', 'two-processes', 'rejected-tokens'])
def test_generated_proxy_only_adds_measured_directives(tmp_path: Path, scenario: str) -> None:
    reference = Path(__file__).resolve().parents[1] / 'docs' / 'reverse-proxy.conf'
    run = _run(tmp_path, scenario)
    with (
        patch.object(launcher, '_REFERENCE', reference),
        patch.object(launcher.shutil, 'which', return_value='/usr/sbin/nginx'),
        patch.object(launcher.shutil, 'copyfile'),
    ):
        _, config = launcher._proxy_config(run, tmp_path)
    evidence = json.loads((tmp_path / 'proxy-config.json').read_text())
    lines = Path(config).read_text().splitlines(keepends=True)
    for directive in evidence['added_log_directives']:
        assert directive.lstrip().startswith(('log_format ', 'access_log '))
        lines.remove(directive + '\n')
    expected = reference.read_text()
    if scenario in {'two-processes', 'rejected-tokens'}:
        expected = expected.replace('zone=farm:1m rate=2000r/s', 'zone=farm:1m rate=1000r/s')
        for port in (8743, 8744):
            expected = expected.replace(f':{port} max_conns=768', f':{port} max_conns=1024')
    for port in range(8743 + run.brokers, 8747):
        expected = expected.replace(
            f'        server 127.0.0.1:{port} ', f'        # server 127.0.0.1:{port} '
        )
    assert ''.join(lines) == expected
    assert evidence['broker_ports'] == list(range(8743, 8743 + run.brokers))


@pytest.mark.parametrize('processes', [1, 2, 3])
@pytest.mark.parametrize('second_prefix', ['', '# '])
@pytest.mark.parametrize('extra_reference_peers', [False, True])
def test_proxy_serves_only_selected_loopback_upstreams(
    tmp_path: Path, processes: int, second_prefix: str, extra_reference_peers: bool
) -> None:
    run = _run(tmp_path, 'slow-control')
    publish(tmp_path / 'warm-topology.json', processes)
    reference = tmp_path / 'reference.conf'
    settings = 'max_conns=128 max_fails=0'
    reference.write_text(
        'http {\n    upstream brokers {\n'
        f'        server 127.0.0.1:8743 {settings};\n'
        f'        {second_prefix}server 127.0.0.1:8744 {settings};\n'
        + (f'        server 127.0.0.1:8745 {settings};\n' if extra_reference_peers else '')
        + '    }\n}\n',
        newline='\n',
    )
    with (
        patch.object(launcher, '_REFERENCE', reference),
        patch.object(launcher.shutil, 'which', return_value='nginx'),
        patch.object(launcher.shutil, 'copyfile'),
    ):
        _, config = launcher._proxy_config(run, tmp_path)
    routes = [
        line.strip()
        for line in Path(config).read_text().splitlines()
        if line.strip().startswith('server 127.0.0.1:')
    ]
    assert routes == [f'server 127.0.0.1:{8743 + i} {settings};' for i in range(processes)]
    evidence = json.loads((tmp_path / 'proxy-config.json').read_text())
    assert evidence['active_upstreams'] == routes
    assert evidence['broker_ports'] == list(range(8743, 8743 + processes))


@pytest.mark.parametrize('mismatch', ['', 'cpu', 'memory', 'routes', 'process', 'duplicate_pid'])
def test_deployment_check_matches_running_processes_ports_and_quota(
    tmp_path: Path, mismatch: str
) -> None:
    run = _run(tmp_path, 'two-processes')
    limits = {
        'cpu.max': '200000 100000' if mismatch == 'cpu' else '400000 100000',
        'memory.max': str((4 if mismatch == 'memory' else 8) * 1024**3),
    }
    publish(tmp_path / 'deployment.json', {'cgroup': limits})
    pids = {'broker-0-0': 31, 'broker-1-0': 32, 'proxy': 33}
    if mismatch == 'process':
        del pids['broker-1-0']
    elif mismatch == 'duplicate_pid':
        pids['broker-1-0'] = 31
    publish(tmp_path / 'service-pids.json', pids)
    publish(
        tmp_path / 'proxy-config.json',
        {'broker_ports': [8743, 8750 if mismatch == 'routes' else 8744]},
    )
    report = measurements(run)
    checks = cast('dict[str, bool]', report['workload_predicates'])
    assert checks['deployment_configuration_observed'] == (not mismatch)


def test_serial_comparison_requires_fixture_domain(tmp_path: Path) -> None:
    run = _run(tmp_path, 'slow-sg')
    publish(tmp_path / 'clock-probe.json', {'domain': 'other'})
    summary = _scenarios._serial_intervals(_Evidence(run), [(10, 15)], {})
    assert summary['shared_monotonic_clock'] is False
    assert summary['interval_results'] == []


def test_serial_prime_publishes_missing_process(tmp_path: Path) -> None:
    run = _run(tmp_path, 'slow-sg')
    publish(tmp_path / 'warm-topology.json', 2)
    append(
        tmp_path / 'mints.jsonl', {'scope': 'warm', 'outcome': 'minted', 'process': 'broker-0-0'}
    )
    with (
        patch.object(loadgen, '_Machine') as machine,
        patch.object(loadgen.time, 'monotonic', side_effect=[10, 10 + loadgen.MAX_WAIT]),
        patch.object(loadgen, '_observe_release', return_value={}),
        patch.object(_warm_stream, 'finished', return_value=True),
    ):
        loadgen._warm_probe(run)
    machine.return_value.fetch.assert_called_once_with('prepare', force=True)
    assert json.loads((tmp_path / 'probe-ready.json').read_text()) == {
        'incomplete': True,
        'missing_processes': ['broker-1-0'],
    }


def test_serial_probe_uses_serving_backend_after_retry(tmp_path: Path) -> None:
    run = _run(tmp_path, 'slow-control')
    publish(tmp_path / 'warm-topology.json', 2)
    path = tmp_path / 'calls-0.jsonl'
    logs = tmp_path / 'proxy.jsonl'
    for i, phase in enumerate(('prepare', 'prepare', 'probe')):
        generation = min(1, i) + 1
        start = 3 + i if phase == 'prepare' else 12
        _call(run, 1, generation, phase, (start, start + 1))
        calls = [json.loads(line) for line in path.read_text().splitlines()]
        call = calls[-1]
        call['scope'] = 'warm'
        call['attempts'][-1].update(attempt_id=str(i), finish_monotonic=start + 0.5)
        if phase == 'probe':
            call['attempts'].insert(0, dict(call['attempts'][0], attempt_id='refused', status=503))
        path.write_text(''.join(json.dumps(c) + '\n' for c in calls))
        _receipt(run, phase, 1, str(i), (200, '200'))
        receipts = [json.loads(line) for line in logs.read_text().splitlines()]
        receipts[-1]['upstream_addr'] = f'127.0.0.1:{8742 + generation}'
        logs.write_text(''.join(json.dumps(r) + '\n' for r in receipts))
        if phase == 'prepare':
            append(
                tmp_path / 'mints.jsonl',
                {
                    'started': start,
                    'finished': start + 0.1,
                    'scope': 'warm',
                    'process': f'broker-{i}-0',
                    'token_type': 'session',
                    'outcome': 'minted',
                    'generation': generation,
                },
            )
    append(
        tmp_path / 'mints.jsonl',
        {
            'started': 10,
            'finished': 10.1,
            'started_monotonic': 10,
            'finished_monotonic': 10.1,
            'process': 'broker-0-0',
            'scope': 'scope-0-0',
            'token_type': 'session',
            'outcome': 'minted',
            'generation': 3,
        },
    )
    _, detail = _slow(_Evidence(run))
    probe = cast('dict[str, object]', detail['warm_probe'])
    assert probe['interval_results'] == [
        {
            'start': 10,
            'end': 15,
            'maximum_gap_seconds': 2.5,
            'receipts_reconciled': False,
            'replies_by_upstream': {'127.0.0.1:8743': 0, '127.0.0.1:8744': 1},
        }
    ]


def test_slow_sg_includes_minute_and_matched_control() -> None:
    assert benchmark._variants('slow-sg') == ('simultaneous', 'minute')
    assert benchmark._variants('slow-control') == ('simultaneous',)


def test_stream_epoch_must_follow_its_own_startup_sample(tmp_path: Path) -> None:
    run = _run(tmp_path, 'slow-sg')
    publish(
        tmp_path / 'clock-stream.json',
        {'domain': 'test', 'monotonic': 999, 'sampling_uncertainty_seconds': 0.01},
    )
    publish(tmp_path / 'stream-clock.json', {'epoch': 1, 'stop': 1005, 'slots': 1, 'cpus': [9]})
    valid, detail = _scenarios._stream_evidence(_Evidence(run), [(1000, 1005)], {}, 1000)
    assert not valid
    assert detail['missed_slots'] == []


def test_stream_retries_keep_one_slot_and_distinct_attempt_ids(tmp_path: Path) -> None:
    run = _run(tmp_path, 'slow-sg')
    (tmp_path / 'fixture').write_bytes(b'fixture')
    bad = requests.Response()
    bad.status_code = 503
    good = requests.Response()
    good.status_code = 200
    ids: list[str] = []

    def fetch(scope: str) -> MagicMock:
        assert scope == 'warm'
        for _ in range(2):
            req = requests.Request('POST', run.url).prepare()
            session.send(req)
            ids.append(str(req.headers['X-Farm-Attempt']))
        return MagicMock(token=f'1.{scope}')

    with (
        requests.Session() as session,
        patch.object(session, 'send', side_effect=[bad, good]),
        patch.object(_warm_stream, 'BrokerClient') as client,
    ):
        client.return_value.fetch_token.side_effect = fetch
        event = _warm_stream._send(session, run, 3, 0)
    assert client.call_args.kwargs.get('retries') is None
    assert len(set(ids)) == 2
    assert [a['status'] for a in cast('list[dict[str, int]]', event['attempts'])] == [503, 200]
    assert event['generation'] == 1


def test_stream_stop_does_not_define_its_own_population(tmp_path: Path) -> None:
    run = _run(tmp_path, 'slow-sg')
    publish(tmp_path / 'stream-clock.json', {'epoch': 9, 'stop': 15, 'slots': 21, 'cpus': [9]})
    for seq in range(21):
        append(
            tmp_path / 'stream.jsonl',
            {
                'sequence': seq,
                'start_monotonic': 9 + seq / 4,
                'error': 'ReadTimeout',
            },
        )
    valid, detail = _scenarios._stream_evidence(_Evidence(run), [(10, 15)], {}, 10)
    assert not valid
    assert detail['missed_slots'] == [21, 22, 23]


def test_successful_mint_cannot_establish_refusal_spacing(tmp_path: Path) -> None:
    run = _run(tmp_path, 'rejected-script-key')
    append(
        tmp_path / 'mints.jsonl',
        {
            'process': 'broker-0-0',
            'scope': 'scope-0-0',
            'token_type': 'session',
            'started': 10,
            'finished': 11,
            'outcome': 'minted',
            'generation': 1,
        },
    )
    assert not _fault(_Evidence(run))['sg_attempts_bounded_by_refusal_interval']


def test_successful_warm_responses_cover_the_slow_cold_mint(tmp_path: Path) -> None:
    run = _run(tmp_path, 'slow-sg')
    _call(run, 1, 1, 'prepare', (7, 8))
    _call(run, 0, 2, 'measure', (10, 16))
    for index in range(5):
        _call(run, 1, 1, 'probe', (10.1 + index, 10.5 + index))
    append(
        tmp_path / 'mints.jsonl',
        {
            'started': 10.1,
            'finished': 15.1,
            'process': 'broker-0-0',
            'scope': 'scope-0-0',
            'token_type': 'session',
            'generation': 2,
            'outcome': 'minted',
        },
    )
    path = tmp_path / 'calls-0.jsonl'
    calls = [json.loads(line) for line in path.read_text().splitlines()]
    calls[0]['attempts'][0]['attempt_id'] = 'prime'
    path.write_text(''.join(json.dumps(c) + '\n' for c in calls))
    path = tmp_path / 'mints.jsonl'
    mint = json.loads(path.read_text())
    path.write_text(json.dumps(dict(mint, started_monotonic=10.1, finished_monotonic=15.1)) + '\n')
    append(path, dict(mint, scope='warm', started=7, finished=7.5, generation=1))
    _receipt(run, 'prepare', 1, 'prime', (200, '200'))
    path = tmp_path / 'proxy.jsonl'
    receipt = json.loads(path.read_text())
    path.write_text(json.dumps(dict(receipt, upstream_addr='127.0.0.1:8743')) + '\n')
    publish(tmp_path / 'stream-clock.json', {'epoch': 9, 'stop': 16, 'slots': 28, 'cpus': [9]})
    for seq in range(28):
        due = 9 + seq / 4
        append(
            tmp_path / 'stream.jsonl',
            {
                'sequence': seq,
                'attempt_id': f'stream-{seq}',
                'slot': 'sent',
                'start_monotonic': due,
                'finish_monotonic': due + 0.125,
                'status': 200,
                'generation': 1,
            },
        )
        append(
            path,
            dict(
                receipt,
                upstream_addr='127.0.0.1:8743',
                phase='stream',
                attempt_id=f'stream-{seq}',
                peer='127.1.0.3',
            ),
        )
    checks, _ = _slow(_Evidence(run))
    assert all(checks.values())


def test_suppressed_slot_reports_where_each_acquisition_waited(tmp_path: Path) -> None:
    run = _run(tmp_path, 'slow-sg')
    for role in ('stream', 'deployment'):
        publish(tmp_path / f'clock-{role}.json', {'domain': 'test'})
    publish(tmp_path / 'stream-clock.json', {'epoch': 9, 'stop': 10.25, 'slots': 5, 'cpus': [9]})
    for seq in range(4):
        start = 9 + seq / 4
        attempt = {
            'attempt_id': str(seq),
            'start_monotonic': start,
            'finish_monotonic': 11,
            'status': 503,
            'start': start,
            'finish': 11,
        }
        event: dict[str, object] = {
            'sequence': seq,
            'start_monotonic': start,
            'finish_monotonic': 11,
            'attempts': [attempt],
        }
        if seq == 0:
            attempt['finish_monotonic'] = 9.1
            event['retry_sleeps'] = [(9.1, 10.5, 0)]
        if seq == 1:
            attempt['tls_finish'] = 10.1
        append(tmp_path / 'stream.jsonl', event)
        _receipt(run, 'stream', 2, str(seq), (503, '503'))
    append(
        tmp_path / 'hops-broker-0-0.jsonl', {'attempt_id': '2', 'accepted': 9.9, 'finished': 10.4}
    )
    append(tmp_path / 'stream.jsonl', {'sequence': 4, 'slot': 'suppressed', 'wake': 10})
    _, detail = _scenarios._stream_evidence(_Evidence(run), [(9.5, 10.25)], {}, 9.25)
    assert detail['outstanding_by_suppressed_slot'] == {
        4: {0: 'retry_sleep_after_refusal', 1: 'before_nginx', 2: 'broker_service', 3: 'unknown'}
    }


def test_suppressed_slots_preserve_the_warm_gap(tmp_path: Path) -> None:
    run = _run(tmp_path, 'slow-sg')
    publish(tmp_path / 'stream-clock.json', {'epoch': 9, 'stop': 15, 'slots': 24, 'cpus': [9]})
    for seq in range(24):
        if seq >= 4:
            append(
                tmp_path / 'stream.jsonl',
                {'sequence': seq, 'slot': 'suppressed', 'wake': 9 + seq / 4},
            )
        else:
            append(
                tmp_path / 'stream.jsonl',
                {
                    'sequence': seq,
                    'start_monotonic': 9 + seq / 4,
                    'finish_monotonic': 16,
                    'attempt_id': f'stream-{seq}',
                    'error': 'ReadTimeout',
                },
            )
    valid, detail = _scenarios._stream_evidence(_Evidence(run), [(10, 15)], {}, 10)
    assert valid
    assert detail['maximum_gap_seconds'] == 5
    assert detail['suppressed_slots'] == list(range(4, 24))


def test_timeout_with_proxy_receipt_followed_by_retry(tmp_path: Path) -> None:
    run = _run(tmp_path, 'cold-burst')
    _call(run, 0, 1, 'measure', (10, 12))
    path = tmp_path / 'calls-0.jsonl'
    c = json.loads(path.read_text())
    c['attempts'] = [
        {'start': 10, 'finish': 11, 'error': 'ReadTimeout', 'attempt_id': 'a'},
        {'start': 11.1, 'finish': 12, 'status': 200, 'attempt_id': 'b'},
    ]
    path.write_text(json.dumps(c))
    _receipt(run, 'measure', 0, 'a', (499, '-'))
    _receipt(run, 'measure', 0, 'b', (200, '200'))
    result = measurements(run)
    assert cast('dict[str, bool]', result['expected_outcomes'])['valid_proxy_source_distribution']
    assert cast('dict[str, object]', result['proxy_sources'])['proxy_statuses'] == {499: 1, 200: 1}
    assert _caller_summary(_Evidence(run).measure)['attempt_outcomes'] == {
        'ReadTimeout': 1,
        '200': 1,
    }
    # Same peer and response counts, but no receipt for the second attempt.
    c['attempts'][1]['attempt_id'] = 'different'
    path.write_text(json.dumps(c))
    assert not cast('dict[str, bool]', measurements(run)['expected_outcomes'])[
        'valid_proxy_source_distribution'
    ]


def test_tls_cli_defaults_to_reference_upstream_count(tmp_path: Path) -> None:
    reference = Path('docs/reverse-proxy.conf').read_text()
    ports = [
        line for line in reference.splitlines() if line.strip().startswith('server 127.0.0.1:')
    ]
    with (
        patch(
            'sys.argv', ['bench', '--scenario', 'cold-burst', '--report', str(tmp_path / 'unused')]
        ),
        patch.object(benchmark, '_measure') as measure,
    ):
        benchmark._main()
    assert measure.await_args is not None
    assert measure.await_args.args[0].brokers == len(ports)


def test_two_process_minute_prepares_fresh_rest_windows(tmp_path: Path) -> None:
    run = _run(tmp_path, 'warm-burst', variant='minute')
    publish(tmp_path / 'warm-topology.json', 2)
    assert run.fresh_rest_window


def test_verified_warm_reply_uses_last_transport_finish(tmp_path: Path) -> None:
    run = _run(tmp_path, 'slow-sg')
    publish(tmp_path / 'stream-clock.json', {'epoch': 9, 'stop': 10, 'slots': 4, 'cpus': [9]})
    append(
        tmp_path / 'stream.jsonl',
        {
            'sequence': 0,
            'start_monotonic': 9,
            'finish_monotonic': 11,
            'generation': 2,
            'attempts': [{'attempt_id': 'retry', 'status': 200, 'finish_monotonic': 9.25}],
        },
    )
    _receipt(run, 'stream', 2, 'retry', (200, '200'))
    path = tmp_path / 'proxy.jsonl'
    publish(path, dict(json.loads(path.read_text()), upstream_addr='second'))
    _, detail = _scenarios._stream_evidence(
        _Evidence(run), [(9, 10)], {'first': 1, 'second': 2}, 10
    )
    assert detail['warm_response_times_monotonic'] == [9.25]


def test_warm_burst_requires_matching_backend_prime_receipts(tmp_path: Path) -> None:
    run = _warm_run(tmp_path)
    (tmp_path / 'proxy.jsonl').write_text('')
    assert not _burst(_Evidence(run))['successful_priming']


def test_warm_first_tls_eof_is_a_new_attempt_without_a_full_handshake(tmp_path: Path) -> None:
    run = _warm_run(tmp_path)
    path = tmp_path / 'calls-0.jsonl'
    calls = [json.loads(line) for line in path.read_text().splitlines()]
    first_call = next(c for c in calls if c['phase'] == 'measure')
    retry = first_call['attempts'][0]
    retry.update(start=10.3, start_monotonic=10.3, connection='new', tls_session_reused=False)
    first_call['attempts'].insert(
        0,
        {
            'attempt_id': 'tls-eof',
            'connection': 'new',
            'start': 10.0,
            'start_monotonic': 10.0,
            'tls_start': 10.1,
            'tls_finish': 10.2,
            'finish': 10.2,
            'error': 'SSLError',
        },
    )
    path.write_text(''.join(json.dumps(call) + '\n' for call in calls))
    report = measurements(run)
    connections = cast('dict[str, object]', report['fleet_connections'])
    assert connections['machine_first'] == {'new': 1}
    assert connections['retry'] == {'new': 1}
    assert connections['full_tls_first'] == 0
    assert not cast('dict[str, bool]', report['workload_predicates'])[
        'fresh_tls_first_attempt_per_machine'
    ]


def test_warm_proof_requires_rest_window_at_release(tmp_path: Path) -> None:
    run = _warm_run(tmp_path)
    publish(tmp_path / 'cache-broker-0-0.json', {'2': 3.1})
    publish(tmp_path / 'fleet-release.json', {'monotonic': 63.1})
    assert not _burst(_Evidence(run))['successful_priming']
    publish(tmp_path / 'fleet-release.json', {'monotonic': 63.09})
    assert _burst(_Evidence(run))['successful_priming']


def test_warm_stream_counts_missed_slots_and_boundary_gaps(tmp_path: Path) -> None:
    run = _run(tmp_path, 'slow-sg')
    publish(tmp_path / 'stream-clock.json', {'epoch': 9, 'stop': 12, 'slots': 12, 'cpus': [9]})
    for seq in range(12):
        if seq == 5:
            continue
        due = 9 + seq / 4
        append(
            tmp_path / 'stream.jsonl',
            {
                'sequence': seq,
                'attempt_id': f'stream-{seq}',
                'start_monotonic': due,
                'finish_monotonic': due + 0.125,
                'status': 200 if seq < 6 else 429,
                'generation': 1,
            },
        )
        append(
            tmp_path / 'proxy.jsonl',
            {
                'phase': 'stream',
                'attempt_id': f'stream-{seq}',
                'peer': '127.1.0.3',
                'status': 200 if seq < 6 else 429,
                'upstream_addr': '127.0.0.1:8743',
                'upstream': '200' if seq < 6 else '429',
                'method': 'POST',
                'uri': '/v1/token',
            },
        )
    valid, detail = _scenarios._stream_evidence(
        _Evidence(run), [(10, 11.75)], {'127.0.0.1:8743': 1}, 10
    )
    assert not valid
    assert detail['missed_slots'] == [5]
    assert detail['maximum_gap_seconds'] == 1.625


def test_warm_stream_records_rejected_redirect(tmp_path: Path) -> None:
    run = Run(tmp_path, 'slow-sg', 1, 'minute', direct=False)
    (tmp_path / 'fixture').write_bytes(b'fixture')
    response = requests.Response()
    response.status_code = 307
    response.headers['Location'] = 'https://new.example/token?private-marker'
    response.raw = io.BytesIO(b'')
    with requests.Session() as session:
        adapter = MagicMock(spec=HTTPAdapter)
        adapter.send.return_value = response
        session.mount('https://', adapter)
        event = _warm_stream._send(session, run, 7, 10)
    adapter.send.assert_called_once()
    (attempt,) = cast('list[dict[str, object]]', event['attempts'])
    assert attempt['attempt_id'] == adapter.send.call_args.args[0].headers['X-Farm-Attempt']
    assert (attempt.get('status'), attempt.get('error')) == (307, 'redirect')
    assert event['terminal_error'] == 'BrokerClientError'
    assert 'private-marker' not in json.dumps(event)


def test_warm_topology_preserves_prescribed_recovery(tmp_path: Path) -> None:
    publish(tmp_path / 'warm-topology.json', 2)
    for scenario in ('slow-sg', 'slow-control', 'warm-burst', 'rejected-tokens'):
        assert _run(tmp_path, scenario).brokers == 2
    assert _run(tmp_path, 'cold-burst').brokers == 1


@pytest.mark.parametrize('missing', ['baseline', 'final', 'priming'])
def test_warm_work_needs_successful_priming_and_snapshots(tmp_path: Path, missing: str) -> None:
    run = _warm_run(tmp_path)
    path = tmp_path / 'calls-0.jsonl'
    assert _burst(_Evidence(run))['no_new_verifications']
    if missing == 'priming':
        records = [json.loads(line) for line in path.read_text().splitlines()]
        del records[0]['generation']
        path.write_text(''.join(json.dumps(c) + '\n' for c in records))
    else:
        (tmp_path / f'{missing}-broker-0-0.json').unlink()
    checks = _burst(_Evidence(run))
    assert not checks['rest_mints_only_after_cache_expiry']
    assert not checks['no_new_session_mints']
    assert not checks['no_new_verifications']


@pytest.mark.parametrize(('variant', 'start'), [('minute', 71), ('simultaneous', 12)])
def test_missed_burst_dispatch(tmp_path: Path, variant: str, start: int) -> None:
    run = _run(tmp_path, 'cold-burst', 2, variant=variant)
    _call(run, 0, 1, 'measure', (10, 11))
    _call(run, 1, 1, 'measure', (start, start + 1))
    assert not _burst(_Evidence(run))['arrival_schedule_observed']


@pytest.mark.parametrize('missing', [None, 'initial issue', 'replacement flag'])
def test_recovery_requires_account_observations_and_recorded_replacement(
    tmp_path: Path, missing: str | None
) -> None:
    run = _run(tmp_path, 'rejected-tokens', 2)
    publish(tmp_path / 'active.json', {'time': 9, 'cutoff': 2})
    for machine in range(2):
        process = f'broker-{machine}-0'
        audit = tmp_path / f'audit-{process}.jsonl'
        audit.touch()
        for phase, generation, started in [
            ('prepare', machine + 1, 5),
            ('measure', machine + 3, 10),
        ]:
            measured = phase == 'measure'
            fingerprint = f'fixture-{generation}'
            append(
                tmp_path / 'mints.jsonl',
                {
                    'process': process,
                    'scope': 'scope-0-0',
                    'token_type': 'session',
                    'started': started,
                    'finished': started + 0.2,
                    'generation': generation,
                    'token_fp': fingerprint,
                    'outcome': 'minted',
                },
            )
            if (machine, phase, missing) != (0, 'prepare', 'initial issue'):
                append(
                    audit,
                    {
                        'event': 'issue',
                        'scope': 'scope-0-0',
                        'client_id': 'farm-0',
                        'token_type': 'session',
                        'token_fp': fingerprint,
                        'outcome': 'replaced' if measured else 'minted',
                        'replaced': measured
                        and not (machine == 0 and missing == 'replacement flag'),
                    },
                )
            prefix = 'final' if measured else 'baseline'
            publish(
                tmp_path / f'{prefix}-{process}.json',
                {'audit_bytes': audit.stat().st_size, 'scrypt': {}, 'verified': {}},
            )
            append(
                tmp_path / 'probes.jsonl',
                {
                    'time': 11 if measured else 9.5,
                    'generation': generation,
                    'token_fp': fingerprint,
                    'accepted': measured,
                },
            )
            append(
                tmp_path / 'calls-0.jsonl',
                {
                    'phase': phase,
                    'machine': machine,
                    'scope': 'scope-0-0',
                    'token_type': 'session',
                    'start': started,
                    'finish': started + 1,
                    'seconds': 1,
                    'generation': generation,
                    'group': 'get-token' if machine else 'library',
                    'attempts': [{'start': started, 'finish': started + 1, 'status': 200}],
                    'reported_generation': machine + 1,
                    'accepted_by_sg': measured,
                },
            )
    checks, _ = _recovery(_Evidence(run))
    assert checks['both_brokers_held_rejected_generations'] is (missing != 'initial issue')
    assert checks['one_mint_per_key_process_rejected_generation'] is (missing is None)
    assert checks['within_three_reports'] is (missing is None)


@pytest.mark.parametrize('scenario', ['rotation', 'slow-sg'])
def test_required_proxy_phase_needs_its_own_peers(tmp_path: Path, scenario: str) -> None:
    run = _run(tmp_path, scenario)
    _call(run, 0, 1, 'measure', (10, 11))
    path = tmp_path / 'calls-0.jsonl'
    call = json.loads(path.read_text())
    call['attempts'][0]['attempt_id'] = 'primary'
    path.write_text(json.dumps(call))
    _receipt(run, 'measure', 0, 'primary', (200, '200'))
    checks = cast('dict[str, bool]', measurements(run)['expected_outcomes'])
    assert not checks['valid_proxy_source_distribution']


@pytest.mark.parametrize(
    ('shard_lag', 'delay', 'on_schedule'),
    [(0.0, 0.004, True), (0.0, 1.2, False), (10.0, 0.004, False)],
)
def test_arrivals_use_the_common_fleet_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    shard_lag: float,
    delay: float,
    *,
    on_schedule: bool,
) -> None:
    monkeypatch.setattr(_scenarios, 'SHARD_SIZE', 1)
    run = _run(tmp_path, 'cold-burst', 2, variant='simultaneous')
    publish(tmp_path / 'dispatch.json', 10.020)
    publish(tmp_path / 'fleet-release.json', {'wall_time': 10.0, 'monotonic': 100.0})
    for machine, origin, lag in [(0, 100.0, 0.002), (1, 100.0 + shard_lag, delay)]:
        publish(
            tmp_path / f'release-{machine}.json',
            {'wall_time': 10.0 + origin - 100.0, 'monotonic': origin},
        )
        append(
            tmp_path / f'calls-{machine}.jsonl',
            {
                'phase': 'measure',
                'machine': machine,
                'start': 10.0 + lag,
                'start_monotonic': origin + lag,
                'attempts': [
                    {
                        'start': 10.0 + lag,
                        'start_monotonic': origin + lag,
                        'finish': 11.0 + lag,
                        'status': 200,
                    }
                ],
            },
        )
    observed, detail = _scenarios._arrivals(_Evidence(run))
    assert observed is on_schedule
    assert detail['arrival_skew_seconds'] == pytest.approx(shard_lag + delay - 0.002)
    offsets = cast('dict[int,float]', detail['cross_clock_observed_minus_host_seconds_by_shard'])
    assert offsets == pytest.approx({0: -0.020, 1: shard_lag - 0.020})
    assert detail['cross_clock_fleet_observed_minus_host_seconds'] == pytest.approx(-0.020)
    assert detail['shard_observation_after_fleet_release_seconds'] == {0: 0.0, 1: shard_lag}
    assert detail['first_attempt_after_shard_observation_seconds'] == pytest.approx(
        {0: 0.002, 1: delay}
    )


@pytest.mark.parametrize('first_outcome', [{'error': 'ConnectTimeout'}, {'status': 503}])
def test_missing_receipt_depends_on_whether_the_client_received_http(
    tmp_path: Path, first_outcome: dict[str, object]
) -> None:
    run = _run(tmp_path, 'cold-burst')
    _call(run, 0, 1, 'measure', (10, 12))
    path = tmp_path / 'calls-0.jsonl'
    c = json.loads(path.read_text())
    c['attempts'] = [
        {'start': 10.0, 'finish': 11.0, 'attempt_id': 'first', **first_outcome},
        {'start': 11.0, 'finish': 12.0, 'status': 200, 'attempt_id': 'second'},
    ]
    path.write_text(json.dumps(c))
    _receipt(run, 'measure', 0, 'second', (200, '200'))
    covered, detail = _scenarios._proxy_coverage(_Evidence(run))
    assert covered is ('error' in first_outcome)
    assert detail['measured_attempt_count'] == 2
    assert detail['transport_failures_without_receipt'] == (
        {'ConnectTimeout': 1} if 'error' in first_outcome else {}
    )

    _receipt(run, 'measure', 0, 'unknown', (429, '-'))
    covered, detail = _scenarios._proxy_coverage(_Evidence(run))
    assert not covered
    assert detail['unmatched_receipts'] == 1


@pytest.mark.parametrize(
    ('refresh_starts', 'valid'),
    [((63.0,), False), ((63.1,), True), ((63.1, 122.1), False)],
)
def test_warm_rest_refresh_respects_each_cache_window(
    tmp_path: Path, refresh_starts: tuple[float, ...], valid: bool
) -> None:
    run = _warm_run(tmp_path)
    path = tmp_path / 'mints.jsonl'
    prime = json.loads(path.read_text().splitlines()[-1])
    # The priming mint finished at 3.1 s. Keep the measured REST call open
    # across every synthetic mint to exercise the full phase boundary.
    calls_path = tmp_path / 'calls-0.jsonl'
    calls = [json.loads(line) for line in calls_path.read_text().splitlines()]
    rest = calls[-1]
    rest.update(finish=124.0, seconds=114.0, generation=2 + len(refresh_starts))
    rest['attempts'][-1]['finish'] = 124.0
    calls_path.write_text(''.join(json.dumps(c) + '\n' for c in calls))
    starts = {'2': 3.1}
    for gen, start in enumerate(refresh_starts, 3):
        append(
            path,
            {
                **prime,
                'started': start,
                'started_monotonic': start,
                'finished': start + 0.1,
                'generation': gen,
            },
        )
        starts[str(gen)] = start + 0.1
    publish(tmp_path / 'cache-broker-0-0.json', starts)
    assert _burst(_Evidence(run))['rest_mints_only_after_cache_expiry'] is valid


@pytest.mark.parametrize(('duration', 'valid'), [(4.99, False), (5.0, True)])
def test_slow_fault_uses_monotonic_time_and_keeps_invalid_intervals(
    tmp_path: Path, duration: float, *, valid: bool
) -> None:
    run = _run(tmp_path, 'slow-sg')
    publish(tmp_path / 'active.json', {'time': 9, 'monotonic': 9, 'cutoff': 0})
    _call(run, 0, 2, 'measure', (10, 17))
    append(
        tmp_path / 'mints.jsonl',
        {
            'scope': 'scope-0-0',
            'process': 'broker-0-0',
            'token_type': 'session',
            'outcome': 'minted',
            'generation': 2,
            'started': 10.5,
            'finished': 8,
            'started_monotonic': 10.5,
            'finished_monotonic': 10.5 + duration,
        },
    )
    checks, detail = _slow(_Evidence(run))
    assert checks['measured_slow_cold_mint'] is valid
    assert detail['cold_mint_monotonic_intervals'] == [(10.5, 10.5 + duration)]


@pytest.mark.parametrize('scenario', ['cold-burst', 'many-clients', 'two-processes'])
def test_mint_limit_uses_each_previous_cache_start(tmp_path: Path, scenario: str) -> None:
    run = _run(tmp_path, scenario)
    evidence = _Evidence(run)
    evidence.missing.clear()
    key = 'broker-0-0/farm-0/scope-0-0/'
    mint: _scenarios._Mint = {
        'token_type': 'rest',
        'scope': 'scope-0-0',
        'process': 'broker-0-0',
        'outcome': 'minted',
        'started': 10,
        'finished': 11,
        'started_monotonic': 10,
        'cache_started_monotonic': 12,
        'rejected_through': 0,
    }
    evidence.by_key[key + 'session'] = [{**mint, 'token_type': 'session'}]
    rest = evidence.by_key[key + 'rest']
    rest.extend([mint, {**mint, 'started_monotonic': 72, 'cache_started_monotonic': 85}])
    bound = 'mints_within_per_key_cache_lifetimes'
    with patch.object(evidence, 'complete', return_value=True):
        assert _burst(evidence)[bound]
        rest.append({**mint, 'started_monotonic': 144.999})
        assert not _burst(evidence)[bound]
        rest[-1]['started_monotonic'] = 145
        assert _burst(evidence)[bound]
        del rest[1]['cache_started_monotonic']
        assert not _burst(evidence)[bound]
        rest.pop()
        evidence.by_key[key + 'session'] *= 2
        assert not _burst(evidence)[bound]


@pytest.mark.parametrize(
    ('second', 'cause'),
    [(200, 'client_transport_unknown'), (429, 'local_throttle_with_retry_after')],
)
def test_gateway_event_has_only_one_compatible_receipt(
    tmp_path: Path, second: int, cause: str
) -> None:
    run = _run(tmp_path, 'cold-burst')
    _call(run, 0, 1, 'measure', (10, 12))
    path = tmp_path / 'calls-0.jsonl'
    call = json.loads(path.read_text())
    call['attempts'] = [
        {'attempt_id': 'first', 'status': 502},
        {'attempt_id': 'second', 'error': 'ReadTimeout'},
    ]
    publish(path, call)
    _receipt(
        run,
        'measure',
        0,
        'first',
        (502, '502'),
        upstream_addr='brokers',
        upstream_header_time='-',
        upstream_connect_time='-',
    )
    _receipt(
        run,
        'measure',
        0,
        'second',
        (second, '200' if second == 200 else '-'),
        upstream_addr='127.0.0.1:8743' if second == 200 else '-',
    )
    path = tmp_path / 'proxy.jsonl'
    records = [
        dict(json.loads(line), connection='7', retry_after='2')
        for line in path.read_text().splitlines()
    ]
    path.write_text(''.join(json.dumps(r) + '\n' for r in records))
    (tmp_path / 'nginx-error.log').write_text(
        '*7 no live upstreams while connecting to upstream\n'
    )
    errors = _scenarios._errors(_Evidence(run))
    assert errors['original_causes'] == {'no_available_upstream': 1, cause: 1}
    assert errors['gateway_events'] == {'no_available_upstream': 1}


@pytest.mark.parametrize('delivered', [False, True])
def test_restart_uses_the_gateway_failure_bounds(tmp_path: Path, *, delivered: bool) -> None:
    run = _run(tmp_path, 'process-restart')
    for role in ('fleet', 'deployment'):
        publish(
            tmp_path / f'clock-{role}.json',
            {'domain': 'vm', 'sampling_uncertainty_seconds': 0.001},
        )
    publish(
        tmp_path / 'restart.json',
        {'started': 112, 'finished': 113, 'started_monotonic': 12, 'finished_monotonic': 13},
    )
    _call(run, 0, 1, 'measure', (11, 14))
    path = tmp_path / 'calls-0.jsonl'
    call = json.loads(path.read_text())
    call['attempts'] = [
        dict(
            call['attempts'][0],
            attempt_id='failure',
            start_monotonic=12.1,
            http_send_entry=12.12,
            finish_monotonic=12.5,
            status=504,
        )
    ]
    if not delivered:
        del call['attempts'][0]['status']
        call['attempts'][0]['error'] = 'ReadTimeout'
    publish(path, call)
    _receipt(
        run,
        'measure',
        0,
        'failure',
        (504, '504'),
        connection='7',
        upstream_addr='127.0.0.1:8743',
        upstream_connect_time='0.001',
        upstream_header_time='-',
        elapsed=0.3 if delivered else 2.38,
        finish=112.45 if delivered else 114.5,
    )
    second = '52' if delivered else '54'
    (tmp_path / 'nginx-error.log').write_text(
        f'1970/01/01 00:01:{second} *7 upstream timed out '
        'while reading response header from upstream\n'
    )
    report = measurements(run)
    errors = cast('dict[str,object]', report['errors'])
    assert errors['transport_errors'] == int(not delivered)
    assert errors['original_causes'] == {'upstream_read_timeout': 1}
    assert errors['intended_fault'] == ({'upstream_read_timeout': 1} if delivered else {})
    if not delivered:
        assert errors['unresolved_fault'] == {'upstream_read_timeout': 1}
    assert (
        cast('dict[str,bool]', report['service_results'])[
            'no_avoidable_transport_or_gateway_errors'
        ]
        is delivered
    )


@pytest.mark.parametrize('foreign', [False, True])
def test_unproven_stream_clock_retains_observations_without_inventing_slots(
    tmp_path: Path, *, foreign: bool
) -> None:
    run = _run(tmp_path, 'slow-sg')
    if foreign:
        publish(tmp_path / 'stream-clock.json', {'epoch': 9, 'stop': 10, 'slots': 4, 'cpus': [9]})
        publish(tmp_path / 'clock-stream.json', {'domain': 'foreign'})
    append(tmp_path / 'stream.jsonl', {'sequence': 0, 'start_monotonic': 9})
    valid, detail = _scenarios._stream_evidence(_Evidence(run), [(1000, 1005)], {}, 1000)
    assert not valid
    assert not detail['missed_slots']
    assert detail['recorded_sequences'] == [0]


@pytest.mark.parametrize('reverse', [False, True])
def test_no_peer_and_broker_error_on_reused_connection(tmp_path: Path, *, reverse: bool) -> None:
    run = _run(tmp_path, 'cold-burst')
    _call(run, 0, 1, 'measure', (10, 12))
    path = tmp_path / 'calls-0.jsonl'
    call = json.loads(path.read_text())
    call['attempts'] = [
        {'attempt_id': 'n', 'status': 502},
        {'attempt_id': 'b', 'status': 502, 'code': 'sg_rejected'},
    ]
    publish(path, call)
    pairs = [('n', 'brokers', '-'), ('b', '127.0.0.1:8743', '0.002')]
    for name, backend, header in reversed(pairs) if reverse else pairs:
        append(
            tmp_path / 'proxy.jsonl',
            {
                'attempt_id': name,
                'upstream_addr': backend,
                'upstream_connect_time': '-' if backend == 'brokers' else '0.001',
                'upstream_header_time': header,
                'connection': '7',
                'status': 502,
                'upstream': '502',
                'phase': 'measure',
                'peer': '127.1.0.1',
                'tag': '-',
                'method': 'POST',
                'uri': '/v1/token',
                'finish': 11,
                'elapsed': 0.03,
            },
        )
    (tmp_path / 'nginx-error.log').write_text(
        '*7 no live upstreams while connecting\n*8 upstream timed out while reading\n'
    )
    evidence = _scenarios._errors(_Evidence(run))
    assert evidence['original_causes'] == {'no_available_upstream': 1, 'sg_rejected': 1}
    assert evidence['unassigned_gateway_events'] == {'upstream_read_timeout': 1}


@pytest.mark.parametrize(
    ('stage', 'owner'),
    [('reading upstream', 'body'), ('reading response header from upstream', 'header')],
)
def test_read_timeout_joins_only_the_logged_stage(tmp_path: Path, stage: str, owner: str) -> None:
    run = _run(tmp_path, 'cold-burst')
    _call(run, 0, 1, 'measure', (10, 12))
    path = tmp_path / 'calls-0.jsonl'
    call = json.loads(path.read_text())
    call['attempts'] = [
        {'attempt_id': 'body', 'error': 'ChunkedEncodingError'},
        {'attempt_id': 'header', 'status': 504},
    ]
    publish(path, call)
    for key, status, header in [('body', 200, '0.02'), ('header', 504, '-')]:
        _receipt(
            run,
            'measure',
            0,
            key,
            (status, str(status)),
            upstream_addr='127.0.0.1:8743',
            upstream_connect_time='0.001',
            upstream_header_time=header,
            connection='7',
            finish=11.5,
            elapsed=0.2,
        )
    (tmp_path / 'nginx-error.log').write_text(
        f'1970/01/01 00:00:11 *7 upstream timed out while {stage}, client: 127.1.0.1, '
        'request: "POST /v1/token HTTP/1.1", upstream: "http://127.0.0.1:8743/v1/token"\n'
    )
    evidence = _Evidence(run)
    assert [o.identifier for o in evidence.trace.observations if o.event] == [owner]
    assert not evidence.trace.unassigned
    errors = _scenarios._errors(evidence)
    assert errors['gateway_events'] == {'upstream_read_timeout': 1}
    other = 'unclassified' if owner == 'body' else 'client_transport_unknown'
    assert errors['original_causes'] == {'upstream_read_timeout': 1, other: 1}
    assert errors['client_observations'] == {'ChunkedEncodingError': 1, '504': 1}


@pytest.mark.parametrize('reverse', [False, True])
def test_warm_retry_evidence_belongs_to_its_attempt(tmp_path: Path, *, reverse: bool) -> None:
    run = _run(tmp_path, 'slow-sg')
    publish(tmp_path / 'stream-clock.json', {'epoch': 9, 'stop': 20, 'cpus': [9]})
    for seq in range(44):
        due = 9 + seq / 4
        attempts = [
            {
                'attempt_id': f'stream-{seq}-0',
                'start_monotonic': due,
                'finish_monotonic': due + 0.02,
                'error': 'Timeout',
            }
        ]
        if seq == 6:
            attempts = [
                {
                    'attempt_id': 'stream-6-0',
                    'start_monotonic': due,
                    'finish_monotonic': due + 0.1,
                    'status': 429,
                },
                {
                    'attempt_id': 'stream-6-2',
                    'start_monotonic': 17.5,
                    'finish_monotonic': 17.52,
                    'status': 200,
                },
            ]
        append(
            tmp_path / 'stream.jsonl',
            {
                'sequence': seq,
                'generation': 1,
                'start_monotonic': due,
                'attempts': attempts,
                'finish_monotonic': 17.53 if seq == 6 else due + 0.03,
            },
        )
    for key in reversed(['stream-6-1', 'stream-6-2']) if reverse else ['stream-6-1', 'stream-6-2']:
        append(
            tmp_path / 'proxy.jsonl',
            {
                'attempt_id': key,
                'peer': '127.1.0.3',
                'phase': 'stream',
                'status': 200,
                'method': 'POST',
                'uri': '/v1/token',
                'upstream_addr': 'broker',
                'upstream': '200',
                'finish': 16.5 if key == 'stream-6-1' else 17.51,
                'elapsed': 0.02,
            },
        )
    intervals: list[tuple[float, float]] = [(10, 15), (15, 18), (18, 20)]
    _, result = _scenarios._stream_evidence(_Evidence(run), intervals, {'broker': 1}, 10)
    assert result['warm_response_times_monotonic'] == [17.52]
    assert result['receipt_faults_by_interval'] == [[6], [6], []]
    assert [r['verdict'] for r in cast('list[dict[str, object]]', result['interval_results'])] == [
        'inconclusive',
        'inconclusive',
        'miss',
    ]
    # Removing just the orphan restores the later interval; the first 429
    # still lacks its receipt and the final retry is still independently verified.
    path = tmp_path / 'proxy.jsonl'
    final = next(r for r in path.read_text().splitlines() if 'stream-6-2' in r)
    path.write_text(final + '\n')
    _, result = _scenarios._stream_evidence(_Evidence(run), intervals, {'broker': 1}, 10)
    assert result['receipt_faults_by_interval'] == [[6], [], []]
    assert result['warm_response_times_monotonic'] == [17.52]
    path.write_text('')
    _, result = _scenarios._stream_evidence(_Evidence(run), intervals, {'broker': 1}, 10)
    assert result['receipt_faults_by_interval'] == [[6], [6], []]
    assert not result['warm_response_times_monotonic']


@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('second', [11, 12])
def test_sequential_proxy_receipts_resolve_overlapping_events(
    tmp_path: Path, second: int, *, reverse: bool
) -> None:
    run = _run(tmp_path, 'cold-burst')
    _call(run, 0, 1, 'measure', (10, 12))
    call = json.loads((tmp_path / 'calls-0.jsonl').read_text())
    call['attempts'] = [{'attempt_id': key, 'status': 502} for key in ('a', 'b')]
    publish(tmp_path / 'calls-0.jsonl', call)
    pairs = [('a', 3), ('b', 4)]
    for key, seq in reversed(pairs) if reverse else pairs:
        append(
            tmp_path / 'proxy.jsonl',
            {
                'attempt_id': key,
                'peer': '127.1.0.1',
                'phase': 'measure',
                'status': 502,
                'upstream': '502',
                'method': 'POST',
                'uri': '/v1/token',
                'tag': '-',
                'connection': '3',
                'connection_requests': str(seq),
                'upstream_addr': 'brokers',
                'upstream_header_time': '-',
                'upstream_connect_time': '-',
                'finish': 11.4 if key == 'a' else 12.01,
                'elapsed': 0.2,
            },
        )
    (tmp_path / 'nginx-error.log').write_text(
        ''.join(
            f'1970/01/01 00:00:{stamp} *3 no live upstreams, request: "POST /v1/token HTTP/1.1"\n'
            for stamp in (11, second)
        )
    )
    trace = _Evidence(run).trace
    assert [
        (obs.identifier, obs.event.line if obs.event else None) for obs in trace.observations
    ] == [('a', 1), ('b', 2)]
    assert not trace.unassigned


@pytest.mark.parametrize(
    ('bounds', 'expected'),
    [((11.8, 12.2), 'unresolved_fault'), ((13.1, 13.5), 'collateral_fault')],
)
def test_unjoined_transport_is_never_exempt(
    tmp_path: Path, bounds: tuple[float, float], expected: str
) -> None:
    run = _run(tmp_path, 'process-restart')
    publish(tmp_path / 'restart.json', {'started_monotonic': 12, 'finished_monotonic': 13})
    _call(run, 0, 1, 'measure', bounds)
    path = tmp_path / 'calls-0.jsonl'
    call = json.loads(path.read_text())
    call['attempts'] = [
        {
            'attempt_id': 'timeout',
            'start': bounds[0],
            'finish': bounds[1],
            'error': 'ReadTimeout',
            'start_monotonic': bounds[0],
            'finish_monotonic': bounds[1],
        }
    ]
    publish(path, call)
    report = measurements(run)
    errors = cast('dict[str,object]', report['errors'])
    assert errors[expected] == {'client_transport_unknown': 1}
    assert not cast('dict[str,bool]', report['service_results'])[
        'no_avoidable_transport_or_gateway_errors'
    ]


@pytest.mark.parametrize(
    ('connection', 'resumed', 'valid'),
    [('new', False, True), ('reused', False, False), ('new', True, False)],
)
def test_warm_burst_proves_full_handshake_on_each_machine_first_send(
    tmp_path: Path, connection: str, resumed: bool, valid: bool
) -> None:
    run = _warm_run(tmp_path)
    path = tmp_path / 'calls-0.jsonl'
    calls = [json.loads(line) for line in path.read_text().splitlines()]
    fleet = [c for c in calls if c['phase'] == 'measure']
    fleet[0]['attempts'][0].update(connection=connection, tls_session_reused=resumed)
    fleet[1]['attempts'].insert(0, dict(fleet[1]['attempts'][0], connection='reused', status=503))
    fleet[1]['attempts'][1]['connection'] = 'new'
    path.write_text(''.join(json.dumps(c) + '\n' for c in calls))
    report = measurements(run)
    assert (
        cast('dict[str, bool]', report['workload_predicates'])[
            'fresh_tls_first_attempt_per_machine'
        ]
        is valid
    )
    assert report['fleet_connections'] == {
        'machine_first': {connection: 1},
        'subsequent_call_first': {'reused': 1},
        'retry': {'new': 1},
        'full_tls_first': int(valid),
    }
    assert report['verified_priming_by_machine'] == {0: {'session': 1, 'rest': 2}}
    (tmp_path / 'proxy.jsonl').write_text('')
    missing = measurements(run)
    assert missing['verified_priming_by_machine'] == {}
    assert not cast('dict[str, bool]', missing['workload_predicates'])['every_machine_primed']


def test_warm_worker_closes_priming_pool_before_measured_request(tmp_path: Path) -> None:
    run = _warm_run(tmp_path)
    publish(tmp_path / 'fleet-release.json', {'monotonic': 10})
    order: list[str] = []
    machine = MagicMock(index=0, expiry=5, calls=[])
    machine.prime.side_effect = lambda: order.append('prime')
    machine.close.side_effect = lambda: order.append('close')

    def measure(*_args: object) -> None:
        order.append('measure')

    def prime_rest(*_args: object) -> None:
        order.append('rest')

    machine.measure.side_effect = measure
    with (
        patch.object(loadgen, '_Machine', return_value=machine),
        patch.object(loadgen, '_prime_rest_window', side_effect=prime_rest),
    ):
        loadgen._worker(run, 0, 1)
    assert order == ['prime', 'rest', 'close', 'measure', 'close']


def test_worker_socket_peaks_keep_unmatched_and_ambiguous_peers(tmp_path: Path) -> None:
    run = _run(tmp_path, 'cold-burst')
    for machine, port, worker in [(0, '1000', '20'), (1, '2000', '21'), (1, '2000', '20')]:
        _receipt(run, 'measure', machine, 'id', (200, '200'), remote_port=port, worker_pid=worker)
    append(
        tmp_path / 'client-sockets.jsonl',
        {
            'peers': ['0100017F:03E8', '0200017F:07D0', '0300017F:07D0'],
            'byteorder': 'little',
        },
    )
    assert _scenarios._worker_socket_peaks(tmp_path) == {
        'samples': 1,
        'peak_live_by_worker': {'20': 1},
        'peak_unattributed': 2,
    }
