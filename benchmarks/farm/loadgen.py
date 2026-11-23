"""Drive shipping library and CLI clients in independent load-generator processes.

Library callers retain their client across acquisitions. Each measured
`get-token` invocation starts a new interpreter. Caller timing includes startup
and retry sleeps through result availability. Transport timing records
individual sends. A separate CLI measurement covers the interval from the
result marker through child exit and parent result processing.

Valid farm machines use stable loopback addresses in a container sharing the
proxy network namespace. The CLI startup hook installs the machine address and
run CA. The host TLS smoke uses the ordinary host network path.
"""

import argparse
import asyncio
import atexit
import contextlib
import datetime
import json
import math
import os
import secrets
import sys
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from http import HTTPStatus
from pathlib import Path
from typing import ParamSpec, cast

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

from benchmarks.farm import (
    CLI_SLOTS_PER_SHARD,
    DIRECT_NEGATIVE_PEER,
    DIRECT_PORT,
    MANY_CLIENTS,
    MAX_WAIT,
    NEGATIVE_RATE,
    PROXY_URL,
    RECOVERY_LIBRARY_WORKERS,
    REST,
    REST_CACHE_SECONDS,
    SCOPES_PER_CLIENT,
    SHARD_SIZE,
    Run,
    _warm_stream,
    append,
    clock_domain,
    machine_address,
    pin_cpus,
    publish,
    recovery_memory,
    rows,
)
from benchmarks.farm import _transport as transport
from benchmarks.farm._observations import (
    observation_rows,
    record_response,
    record_send_error,
    transport_error,
)
from benchmarks.farm._reconciliation import upstream_evidence
from sg_token_broker import BrokerClient, BrokerClientError
from sg_token_broker._sg import SGMinter

_Params = ParamSpec('_Params')
_RESULT_MARKER = 'FARM_RESULT_READY'
_RECOVERY_LIMIT = 8
_POLL = 0.1
_NEGATIVE_QUEUE = 96
# Limit simultaneous interpreter launches without limiting retained-client requests.
_CLI_SLOTS = threading.BoundedSemaphore(CLI_SLOTS_PER_SHARD)


class _AttemptBuffer:
    """Capture transport boundaries in memory and decode errors after acquisition returns."""

    def __init__(self, *, sample_scheduler: bool = False) -> None:
        """Start an empty per-client recorder with a fresh attempt-ID prefix."""
        self._sample_scheduler = sample_scheduler
        self._prefix = secrets.token_hex(16)
        self._sequence = 0
        self._pending: list[
            tuple[str, float, float, float, requests.Response | None, dict[str, object]]
        ] = []

    def drain(self) -> list[dict[str, object]]:
        """Reduce buffered responses to safe fields and release them after the invocation."""
        events: list[dict[str, object]] = []
        for attempt_id, start, monotonic, finish, response, hops in self._pending:
            event: dict[str, object] = {
                'attempt_id': attempt_id,
                'start': start,
                'start_monotonic': monotonic,
                'finish': finish,
                **hops,
            }
            if response is not None:
                record_response(event, response)
            events.append(event)
        self._pending.clear()
        return events

    def observe(
        self, send: Callable[_Params, requests.Response]
    ) -> Callable[_Params, requests.Response]:
        """Wrap a Requests send operation to buffer timing and outcome evidence.

        Args:
            send: Operation accepting a prepared request.

        Returns:
            A callable that adds the correlation header, records the outcome
            and returns the original response or propagates the original send
            failure.
        """

        def observed(*args: _Params.args, **kwargs: _Params.kwargs) -> requests.Response:
            request = args[0] if args else kwargs['request']
            if not isinstance(request, requests.PreparedRequest):
                raise TypeError('attempt recorder requires a prepared request')
            self._sequence += 1
            attempt_id = f'{self._prefix}-{self._sequence}'
            request.headers['X-Farm-Attempt'] = attempt_id
            start = time.time()
            monotonic = time.perf_counter()
            hops: dict[str, object] = {'sample_scheduler': True} if self._sample_scheduler else {}

            def capture_status(reply: requests.Response, **_kwargs: object) -> None:
                hops['status'] = reply.status_code

            # Requests can fail in a response hook or while preparing the redirect target.
            hooks = request.hooks
            original = hooks['response']
            hooks['response'] = [capture_status, *original]
            response = None
            try:
                with transport.attempt(hops):
                    response = send(*args, **kwargs)
                    return response
            except BaseException as exc:
                record_send_error(hops, exc)
                raise
            finally:
                finish = time.time()
                hops['finish_monotonic'] = time.perf_counter()
                hooks['response'] = original
                self._pending.append((attempt_id, start, monotonic, finish, response, hops))

        return observed

    def write(self, path: Path) -> None:
        """Flush the CLI result marker to stdout, then write the buffered attempts.

        Args:
            path: Per-process JSON-lines destination to replace.

        Raises:
            OSError: If stdout or the attempt file cannot be written.
        """
        # Flushing the marker also flushes the shipping JSON result on stdout.
        print(_RESULT_MARKER, time.time(), time.perf_counter(), flush=True)
        with path.open('w', encoding='utf-8') as stream:
            for event in self.drain():
                stream.write(json.dumps(event) + '\n')


class _LiveRecords:
    """Follow complete records from a fixture or proxy log while its writer is active."""

    def __init__(self, path: Path) -> None:
        """Follow the specified log from its first byte."""
        self._path = path
        self._offset = 0

    def read(self) -> list[dict[str, object]]:
        """Read newly completed records and advance past each decoded line.

        Returns:
            New records in file order, or an empty list if none are complete.

        Raises:
            OSError: If a present log cannot be read.
            ValueError: If a complete line is not valid JSON.
        """
        result: list[dict[str, object]] = []
        if self._path.exists():
            with self._path.open('rb') as source:
                source.seek(self._offset)
                while line := source.readline():
                    if not line.endswith(b'\n'):
                        break
                    result.append(json.loads(line))
                    self._offset = source.tell()
        return result


class _SessionChecks:
    """Share real SG session-use observations across a shard in a fixed rejection epoch."""

    def __init__(self, run: Run) -> None:
        """Bind the account probe to the deployment's loopback SG fixture."""
        port = int(json.loads((run.directory / 'fixture-port.json').read_text()))
        self._session = requests.Session()
        self._session.trust_env = False
        self._minter = SGMinter(f'http://127.0.0.1:{port}/account', session=self._session)
        self._lock = threading.Lock()
        self._results: dict[str, bool] = {}

    def accepted(self, token: str) -> bool:
        """Return the cached acceptance verdict or probe this token in the fixed epoch.

        Raises:
            SGError: If the fixture cannot establish acceptance or rejection.
        """
        with self._lock:
            if token not in self._results:
                self._results[token] = self._minter.check_session_token(token)
            return self._results[token]

    def close(self) -> None:
        """Release the SG session-probe transport."""
        self._session.close()


class _Machine:
    """Keep the shipping client, latest tokens and observations for one machine."""

    def __init__(self, run: Run, index: int) -> None:
        """Configure the fixture identity, transport and caller group."""
        self._run = run
        self.index = index
        client = index % MANY_CLIENTS if run.scenario == 'many-clients' else 0
        scope = (
            (index // MANY_CLIENTS) % SCOPES_PER_CLIENT if run.scenario == 'many-clients' else 0
        )
        self.scope = f'scope-{client}-{scope}'
        if run.scenario in {'slow-sg', 'slow-control'} and index == run.machines:
            self.scope = 'warm'
            client = 1
        self._client_id = f'farm-{client}'
        self._secret = run.credential(client, int(run.scenario == 'rotation' and index % 2 == 1))
        self._session = requests.Session()
        self._session.trust_env = False
        if not run.direct:
            self._session.verify = str(run.directory / 'ca.pem')
        if run.farm_network:
            _farm_session(self._session, index, run.directory)
        self._attempts = _AttemptBuffer(
            sample_scheduler=run.farm_network and index % SHARD_SIZE == 0
        )
        self._session.send = self._attempts.observe(self._session.send)
        self._client = BrokerClient(run.url, self._client_id, self._secret, session=self._session)
        self._cli = run.scenario == 'tls-smoke' or (
            run.scenario == 'rejected-tokens' and index % 2 == 1
        )
        self._token = ''
        self.generation = 0
        self.expiry = 0.0
        self.calls: list[dict[str, object]] = []

    def _invoke_cli(
        self, kind: str, history: list[str], phase: str, available: Callable[[float, float], None]
    ) -> tuple[str, str]:
        """Launch the instrumented CLI with secrets confined to stdin and its environment."""
        directory = self._run.directory
        attempt_log = directory / f'cli-{self.index}.jsonl'
        env = {
            **os.environ,
            'SG_TOKEN_BROKER_URL': self._run.url,
            'SG_TOKEN_BROKER_CLIENT_ID': self._client_id,
            'SG_TOKEN_BROKER_CLIENT_SECRET': self._secret,
            'FARM_CALL_PHASE': phase,
            'FARM_ATTEMPTS': str(attempt_log),
            'NO_PROXY': '127.0.0.1',
            'PYTHONPATH': os.pathsep.join([str(directory / 'instrument'), str(Path.cwd())]),
        }
        env.pop('FARM_VALID_MACHINE', None)
        if self._run.farm_network:
            env['FARM_VALID_MACHINE'] = str(self.index)
        if not self._run.direct:
            env['REQUESTS_CA_BUNDLE'] = str(directory / 'ca.pem')
        args = ['--scope', self.scope, '--token-type', kind]
        if self._run.scenario == 'rejected-tokens':
            args.append('--replace-rejected')
        return asyncio.run(_get_token(args, env, history, available))

    def close(self) -> None:
        """Close all HTTP connections owned by the machine."""
        self._session.close()

    def fetch(
        self,
        phase: str,
        kind: str = 'session',
        *,
        force: bool = False,
        history: list[str] | None = None,
    ) -> bool:
        """Record one public acquisition and its actual transports, including cache hits.

        Args:
            phase: Phase label attached to the call and outgoing requests.
            kind: Requested token type.
            force: Bypass the library caller's local cache.
            history: Rejected tokens in reporting order. The CLI receives the
                list and the library receives its most recent entry.

        Returns:
            Whether the call supplied a synthetic token generation.

        Raises:
            OSError: If CLI execution or attempt-artifact I/O fails.
            RuntimeError: If the CLI exits without its result marker.
            ValueError: If returned generation, expiry or evidence data cannot
                be decoded.
            KeyError: If a CLI result omits its token or expiry.
            TypeError: If the CLI result is not a JSON object.
        """
        queued = time.perf_counter()
        with contextlib.ExitStack() as admission:
            if self._cli:
                admission.enter_context(_CLI_SLOTS)
            self._session.headers['X-Farm-Phase'] = phase
            start = time.time()
            clock = time.perf_counter()
            call: dict[str, object] = {
                'phase': phase,
                'loadgen_queue_seconds': clock - queued,
                'machine': self.index,
                'start': start,
                'start_monotonic': clock,
                'group': 'get-token' if self._cli else 'library',
                'scope': self.scope,
                'token_type': kind,
            }
            result_clock: float | None = None

            def available(finish: float, ended: float) -> None:
                nonlocal result_clock
                result_clock = ended
                admission.close()
                call.update(
                    finish=finish,
                    finish_monotonic=ended,
                    seconds=ended - clock,
                    dispatch_to_result_seconds=ended - queued,
                )

            if history:
                call['reported_generation'] = int(history[-1].partition('.')[0])
            try:
                if self._cli:
                    token, expiry = self._invoke_cli(kind, history or [], phase, available)
                else:
                    result = self._client.fetch_token(
                        self.scope,
                        kind,
                        force_refresh=force,
                        rejected_token=history[-1] if history else None,
                    )
                    available(time.time(), time.perf_counter())
                    token, expiry = result.token, result.expires_at.isoformat()
                self._token = token
                self.generation = int(token.partition('.')[0])
                self.expiry = datetime.datetime.fromisoformat(expiry).timestamp()
                call['generation'] = self.generation
                call['expires_at'] = self.expiry
            except BrokerClientError:
                if not self._cli:
                    available(time.time(), time.perf_counter())
                call['error'] = 'cli_error' if self._cli else 'client_error'
            finally:
                if self._cli:
                    if result_clock is not None:
                        call['recorder_tail_seconds'] = time.perf_counter() - result_clock
                    attempt_log = self._run.directory / f'cli-{self.index}.jsonl'
                    call['attempts'] = observation_rows(attempt_log)
                    attempt_log.unlink(missing_ok=True)
                else:
                    call['attempts'] = self._attempts.drain()
                self.calls.append(call)
            return 'generation' in call

    def measure(
        self, checks: _SessionChecks | None, dispatch: float, initial_generation: int
    ) -> None:
        """Drive the machine's measured calls under the shipping acquisition policy.

        Args:
            checks: Session-acceptance probe for rejected-token recovery, or
                `None`.
            dispatch: Monotonic release timestamp for staggered arrivals.
            initial_generation: Generation to advance beyond during
                synchronized renewal.

        Raises:
            SGError: If recovery probing cannot establish the token's
                acceptance.
            OSError: If CLI execution or evidence I/O fails.
            RuntimeError: If a CLI result marker is missing.
            ValueError: If generation, expiry or evidence data cannot be
                decoded.
            KeyError: If a CLI result omits its token or expiry.
            TypeError: If the CLI result is not a JSON object.
        """
        scenario = self._run.scenario
        if self._run.variant == 'minute':
            time.sleep(
                max(0, dispatch + 60 * self.index / self._run.machines - time.perf_counter())
            )
        if checks is not None:
            history: list[str] = []
            while (
                self._token and not checks.accepted(self._token) and len(history) < _RECOVERY_LIMIT
            ):
                history.append(self._token)
                if not self.fetch('measure', history=history):
                    break
                self.calls[-1]['accepted_by_sg'] = checks.accepted(self._token)
        elif scenario == 'synchronized-renewal':
            deadline = time.monotonic() + MAX_WAIT
            while (
                self.fetch('measure')
                and self.generation <= initial_generation
                and time.monotonic() < deadline
            ):
                time.sleep(1)
        else:
            for kind in _kinds(scenario):
                self.fetch('measure', kind, force=scenario == 'warm-burst')

    def prime(self) -> None:
        """Populate the initial caller and broker caches for workloads with a warm baseline."""
        if self._run.scenario in {'warm-burst', 'rejected-tokens', 'synchronized-renewal'}:
            for kind in _kinds(self._run.scenario):
                self.fetch('prepare', kind)


def _await_marker(directory: Path, name: str) -> None:
    """Observe a host phase signal and abort promptly on shutdown."""
    while not (directory / name).exists():
        if (directory / 'stop').exists():
            raise RuntimeError('benchmark stopped during phase coordination')
        time.sleep(_POLL)


async def _cli_output(
    stream: asyncio.StreamReader, available: Callable[[float, float], None]
) -> bytes:
    """Release admission on the child result marker while its recorder finishes."""
    output = bytearray()
    marked = False
    async for line in stream:
        if line.startswith(_RESULT_MARKER.encode() + b' '):
            _, wall, monotonic = line.split()
            available(float(wall), float(monotonic))
            marked = True
        else:
            output.extend(line)
    if not marked:
        raise RuntimeError('get-token exited without a result marker')
    return bytes(output)


def _farm_session(session: requests.Session, index: int, directory: Path) -> None:
    """Bind a valid fixture's session to its lifetime address and the run's proxy only."""
    adapter = HTTPAdapter()
    context = create_urllib3_context()
    context.load_verify_locations(cafile=str(directory / 'ca.pem'))
    adapter.poolmanager.connection_pool_kw['ssl_context'] = context
    adapter.poolmanager.connection_pool_kw['source_address'] = (machine_address(index), 0)
    session.close()
    session.adapters.clear()
    session.mount(f'{PROXY_URL}/', adapter)
    session.trust_env = False
    session.verify = str(directory / 'ca.pem')


async def _fleet(run: Run) -> None:
    """Run independent thread shards and reap the group if any shard fails."""

    async def shard(first: int) -> None:
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            '-m',
            'benchmarks.farm.loadgen',
            'worker',
            str(run.directory),
            run.scenario,
            str(run.machines),
            run.variant,
            '--first',
            str(first),
            '--count',
            str(min(run.shard_size, run.machines - first)),
            *(['--direct'] if run.direct else []),
            *(['--farm-network'] if run.farm_network else []),
        )
        try:
            if await process.wait():
                raise RuntimeError(f'load shard starting at machine {first} failed')
        finally:
            if process.returncode is None:
                process.terminate()
                await process.wait()

    async with asyncio.TaskGroup() as group:
        for first in range(0, run.machines, run.shard_size):
            group.create_task(shard(first))
        # All shards share this generator's monotonic clock. Publish the origin
        # before any shard can begin its measured arrivals.
        while not (run.directory / 'dispatch.json').exists():
            if (run.directory / 'stop').exists():
                raise RuntimeError('benchmark stopped before fleet release')
            await asyncio.sleep(_POLL)
        initial_generation = 0
        if run.scenario == 'synchronized-renewal':
            initial_generation = int(
                json.loads((run.directory / 'active.json').read_text())['generation_at_activation']
            )
        publish(
            run.directory / 'fleet-release.json',
            {
                'monotonic': time.perf_counter(),
                'wall_time': time.time(),
                'initial_generation': initial_generation,
            },
        )
    publish(run.directory / 'fleet-finished.json', time.monotonic())


async def _get_token(
    arguments: list[str],
    env: dict[str, str],
    history: list[str],
    available: Callable[[float, float], None],
) -> tuple[str, str]:
    """Send the rejection history on stdin and capture the real CLI's result."""
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        '-m',
        'sg_token_broker',
        'get-token',
        *arguments,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        env=env,
    )
    if process.stdin is None or process.stdout is None:
        raise RuntimeError('missing CLI pipe')
    process.stdin.write(('\n'.join(history)).encode())
    process.stdin.close()
    stdout, _ = await asyncio.gather(_cli_output(process.stdout, available), process.wait())
    if process.returncode:
        raise BrokerClientError('get-token failed')
    value = json.loads(stdout)
    return str(value['token']), str(value['expires_at'])


def _kinds(scenario: str) -> tuple[str, ...]:
    """Exercise both session and REST caches in the cold and warm burst workloads."""
    return ('session', 'rest') if scenario in {'cold-burst', 'warm-burst'} else ('session',)


def _negative_fixture(
    run: Run, sequence: int, repeated: str, scheduled_at: float
) -> dict[str, object]:
    """Record a prepared fixture at transport dispatch, including failures before receipt."""
    known = sequence % 2 == 0
    client = 'farm-0' if known else f'absent-{secrets.token_hex(12)}'
    secret = repeated if known else secrets.token_urlsafe(32)
    record: dict[str, object] = {
        'sequence': sequence,
        'scheduled_monotonic': scheduled_at,
        'fixture': 'repeated' if known else 'absent',
    }
    with requests.Session() as session:
        session.trust_env = False
        if run.direct:
            adapter = HTTPAdapter()
            adapter.poolmanager.connection_pool_kw['source_address'] = (DIRECT_NEGATIVE_PEER, 0)
            session.mount(run.url + '/', adapter)
        else:
            session.verify = str(run.directory / 'ca.pem')
        prepared = session.prepare_request(
            requests.Request(
                'POST',
                f'{run.url}/v1/token',
                auth=(client, secret),
                headers={
                    'X-Farm-Fixture': str(sequence),
                    'X-Farm-Attempt': f'negative:{sequence}',
                },
                json={'scope': 'scope-0-0'},
            )
        )
        record['dispatch'] = time.time()
        hops: dict[str, object] = {}
        try:
            with transport.attempt(hops):
                response = session.send(prepared, timeout=10, allow_redirects=False)
        except requests.RequestException as exc:
            record['error'] = transport_error(type(exc).__name__)
        else:
            record_response(record, response)
    record['finish'] = time.time()
    if 'http_send_finish' in hops:
        record['sent_monotonic'] = hops['http_send_finish']
    if 'local_port' in hops:
        record['local_port'] = hops['local_port']
    return record


def _negative_stream(run: Run) -> None:
    """Schedule 200 fixed-rate negative fixtures per second across the valid burst."""
    # The known client's synthetic secret is hexadecimal. The repeated negative
    # fixture cannot match it, and the other fixture IDs are never configured.
    repeated = 'invalid-' + secrets.token_hex(16)
    directory = run.directory
    sequence = 0
    dropped = 0
    pending: set[Future[dict[str, object]]] = set()
    start = time.monotonic()
    ready = False
    with (
        transport.instrument(),
        ThreadPoolExecutor(48) as pool,
        (directory / 'invalid.jsonl').open('w') as output,
    ):
        while not (directory / 'probe-stop').exists() and not (directory / 'stop').exists():
            due = max(sequence, math.floor((time.monotonic() - start) * NEGATIVE_RATE))
            dropped += due - sequence
            sequence = due
            delay = start + sequence / NEGATIVE_RATE - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            for job in tuple(pending):
                if job.done():
                    output.write(json.dumps(job.result()) + '\n')
                    pending.remove(job)
                    if not ready:
                        publish(directory / 'negative-ready.json', time.time())
                        ready = True
            if len(pending) < _NEGATIVE_QUEUE:
                pending.add(
                    pool.submit(
                        _negative_fixture,
                        run,
                        sequence,
                        repeated,
                        start + sequence / NEGATIVE_RATE,
                    )
                )
            else:
                dropped += 1
            sequence += 1
        for job in pending:
            output.write(json.dumps(job.result()) + '\n')
    publish(
        directory / 'invalid-schedule.json',
        {'scheduled': sequence, 'dropped': dropped, 'target_per_second': NEGATIVE_RATE},
    )


def _observe_release(directory: Path) -> dict[str, float]:
    """Timestamp the release marker where this generator observes it."""
    _await_marker(directory, 'fleet-release.json')
    return {'monotonic': time.perf_counter(), 'wall_time': time.time()}


def _recovery_shard(run: Run, machines: list[_Machine], checks: _SessionChecks) -> None:
    """Prime and recover every client with a bounded number of live CLI processes."""
    directory = run.directory
    first = machines[0].index
    with (
        ThreadPoolExecutor(RECOVERY_LIBRARY_WORKERS) as library,
        ThreadPoolExecutor(CLI_SLOTS_PER_SHARD) as cli,
    ):
        # Unlike an arrival burst, recovery starts with every machine already
        # holding a rejected session. Keep its real caller across both phases.
        assignments = [(machine, cli if machine.index % 2 else library) for machine in machines]
        priming = [pool.submit(machine.prime) for machine, pool in assignments]
        for job in priming:
            job.result()
        publish(directory / f'primed-{first}.json', max(machine.expiry for machine in machines))
        observed = _observe_release(directory)
        dispatch = float(json.loads((directory / 'fleet-release.json').read_text())['monotonic'])
        publish(directory / f'release-{first}.json', observed)

        def recover(machine: _Machine) -> None:
            entered = time.perf_counter()
            index = len(machine.calls)
            machine.measure(checks, dispatch, 0)
            if len(machine.calls) > index:
                call = machine.calls[index]
                queued = max(0.0, entered - dispatch)
                call['loadgen_queue_seconds'] = float(str(call['loadgen_queue_seconds'])) + queued
                call['dispatch_to_result_seconds'] = (
                    float(str(call['finish_monotonic'])) - dispatch
                )

        jobs = [pool.submit(recover, machine) for machine, pool in assignments]
        for job in jobs:
            job.result()


def _rest_mints(log: _LiveRecords, machine: _Machine) -> dict[int, dict[str, object]]:
    """Index successful REST mints only for the key being prepared."""
    return {
        int(str(m['generation'])): m
        for m in log.read()
        if m['scope'] == machine.scope and m['token_type'] == REST and m['outcome'] == 'minted'
    }


def _initial_rest_mints(
    machine: _Machine, run: Run, log: _LiveRecords, deadline: float
) -> dict[int, dict[str, object]]:
    """Allow the observer to flush the successful initial prime within preparation."""
    mints = _rest_mints(log, machine)
    while machine.generation not in mints:
        if (run.directory / 'stop').exists() or time.monotonic() >= deadline:
            return {}
        time.sleep(_POLL)
        mints.update(_rest_mints(log, machine))
    return mints


def _prime_rest_window(machine: _Machine, run: Run) -> None:
    """Obtain a fresh REST response from every eligible backend before fleet release."""
    if not run.fresh_rest_window or machine.index != 0:
        return
    directory = run.directory
    marker = directory / 'rest-primed.json'
    if run.direct and run.brokers > 1:
        publish(marker, {'incomplete': True, 'reason': 'direct route serves one backend'})
        return
    _await_marker(directory, 'prime-rest')
    mint_log = _LiveRecords(directory / 'mints.jsonl')
    proxy_log = _LiveRecords(directory / 'proxy.jsonl')
    deadline = time.monotonic() + MAX_WAIT
    initial = machine.generation
    if not any(c.get('generation') == initial and c['token_type'] == REST for c in machine.calls):
        publish(marker, {'incomplete': True, 'reason': 'initial REST acquisition failed'})
        return
    mints = _initial_rest_mints(machine, run, mint_log, deadline - REST_CACHE_SECONDS)
    if not mints:
        publish(marker, {'incomplete': True, 'reason': 'initial REST mint missing'})
        return
    # All shards finished preparation before the controller requested a refresh.
    # Waiting one lifetime here expires their caches even across clock domains.
    time.sleep(REST_CACHE_SECONDS)
    mints.update(_rest_mints(mint_log, machine))
    old_generations = set(mints)
    responses: dict[str, int] = {}
    started: dict[int, float] = {}
    receipts: dict[str, str] = {}
    eligible = {f'127.0.0.1:{DIRECT_PORT + i}': f'broker-{i}-0' for i in range(run.brokers)}
    # The reduced-observer control intentionally lacks per-request proxy logs.
    # Finish preparation using returned generations there; its report remains inconclusive.
    observe_route = not run.direct and not (directory / 'observer-control').exists()
    while not (directory / 'stop').exists() and time.monotonic() < deadline:
        invoked = time.monotonic()
        if not machine.fetch('prime-rest', REST, force=True):
            break
        started.setdefault(machine.generation, invoked)
        attempts = cast('list[dict[str, object]]', machine.calls[-1]['attempts'])
        if attempts:
            responses[str(attempts[-1]['attempt_id'])] = machine.generation
        mints.update(_rest_mints(mint_log, machine))
        receipts.update(
            {
                str(r['attempt_id']): upstream_evidence(r).terminal.backend
                for r in proxy_log.read()
                if r.get('phase') == 'prime-rest'
                and r['status'] == HTTPStatus.OK
                and r['peer'] == machine_address(machine.index)
            }
        )
        now = time.monotonic()
        fresh = {
            generation
            for generation in started.keys() & mints.keys() - old_generations
            if now < started[generation] + REST_CACHE_SECONDS
        }
        if observe_route:
            proven = {
                backend: generation
                for key, backend in receipts.items()
                if (generation := responses.get(key)) in fresh
                and eligible.get(backend) == mints[generation]['process']
            }
        else:
            proven = {
                address: g
                for g in sorted(fresh)
                for address, process in eligible.items()
                if mints[g]['process'] == process
            }
        if len(proven) == len(eligible) and time.monotonic() <= deadline:
            publish(
                directory / 'rest-primed.json',
                {
                    'by_upstream': proven,
                    'evidence': 'proxy_receipt' if observe_route else 'fixture_generation',
                },
            )
            return
        time.sleep(_POLL)
    publish(
        marker,
        {
            'incomplete': True,
            'responses': len(responses),
            'reason': 'fresh REST receipts incomplete',
        },
    )


def _prepare_fleet_transport(machines: list[_Machine], run: Run) -> None:
    """Finish cache preparation and release warm-burst sockets before the measured jobs start."""
    _prime_rest_window(machines[0], run)
    if run.scenario == 'warm-burst':
        for machine in machines:
            machine.close()


def _burst_shard(run: Run, machines: list[_Machine]) -> None:
    """Release every primed burst caller from its own waiting thread."""
    count = len(machines)
    first = machines[0].index
    barrier = threading.Barrier(count + 1)
    release: Future[tuple[float, int]] = Future()
    directory = run.directory

    def exercise(machine: _Machine) -> None:
        try:
            machine.prime()
        finally:
            barrier.wait()
        machine.measure(None, *release.result())

    with ThreadPoolExecutor(count) as pool:
        try:
            jobs = [pool.submit(exercise, machine) for machine in machines]
            barrier.wait()
            publish(directory / f'primed-{first}.json', max(m.expiry for m in machines))
            _prepare_fleet_transport(machines, run)
            observation = _observe_release(directory)
            fleet: dict[str, float] = json.loads((directory / 'fleet-release.json').read_text())
        except BaseException as exc:
            barrier.abort()
            release.set_exception(exc)
            raise
        release.set_result((fleet['monotonic'], int(fleet.get('initial_generation', 0))))
        publish(directory / f'release-{first}.json', observation)
        for job in jobs:
            job.result()
        if run.scenario == 'rotation':
            publish(directory / f'cold-{first}.json', value=True)
            _await_marker(directory, 'warm.json')
            warm = [pool.submit(m.fetch, 'warm', force=True) for m in machines]
            for job in warm:
                job.result()


def _warm_probe(run: Run) -> None:
    """Send periodic broker requests on an independently primed scope during slow mints."""
    machine = _Machine(run, run.machines)
    try:
        eligible = {f'broker-{slot}-0' for slot in range(run.brokers)}
        deadline = time.monotonic() + MAX_WAIT
        primed: set[str] = set()
        while machine.fetch('prepare', force=True):
            primed = {
                str(mint['process'])
                for mint in rows(run.directory / 'mints.jsonl')
                if mint['scope'] == 'warm' and mint['outcome'] == 'minted'
            }
            if (
                eligible <= primed
                or time.monotonic() >= deadline
                or (run.directory / 'stop').exists()
            ):
                break
        missing = sorted(eligible - primed)
        publish(
            run.directory / 'probe-ready.json',
            {'incomplete': bool(missing), 'missing_processes': missing},
        )
        publish(run.directory / 'release-probe.json', _observe_release(run.directory))
        while not _warm_stream.finished(run):
            machine.fetch('probe', force=True)
            time.sleep(0.25)
    finally:
        machine.close()
        for call in machine.calls:
            append(run.directory / 'calls-probe.jsonl', call)


def _worker(run: Run, first: int, count: int) -> None:
    """Retain each machine through preparation, measurement and trace collection."""
    machines = [_Machine(run, first + i) for i in range(count)]
    directory = run.directory
    try:
        if run.scenario == 'rejected-tokens':
            with contextlib.closing(_SessionChecks(run)) as checks:
                _recovery_shard(run, machines, checks)
        else:
            _burst_shard(run, machines)
    finally:
        for machine in machines:
            machine.close()
        with (directory / f'calls-{first}.jsonl').open('w', encoding='utf-8') as stream:
            for machine in machines:
                for call in machine.calls:
                    stream.write(json.dumps(call, separators=(',', ':')) + '\n')


def _main() -> None:
    """Dispatch the fleet, worker, warm probe, scheduled stream or negative-load role."""
    parser = argparse.ArgumentParser()
    parser.add_argument('role', choices=['worker', 'probe', 'stream', 'negative', 'fleet'])
    parser.add_argument('directory', type=Path)
    parser.add_argument('scenario')
    parser.add_argument('machines', type=int)
    parser.add_argument('variant')
    parser.add_argument('--direct', action='store_true')
    parser.add_argument('--farm-network', action='store_true')
    parser.add_argument('--first', type=int, default=0)
    parser.add_argument('--count', type=int, default=1)
    args = parser.parse_args()
    run = Run(
        args.directory, args.scenario, args.machines, args.variant, args.direct, args.farm_network
    )
    if args.role in {'fleet', 'stream', 'probe', 'negative'}:
        if run.farm_network or (args.role == 'negative' and run.direct):
            pin_cpus(args.role)
        clock_domain(run.directory, args.role)
    if args.role == 'fleet':
        try:
            asyncio.run(_fleet(run))
        finally:
            recovery_memory(run, 'fleet')
    elif args.role == 'negative':
        _negative_stream(run)
    elif args.role == 'stream':
        _await_marker(run.directory, 'probe-ready.json')
        with contextlib.ExitStack() as stack:
            stack.enter_context(transport.instrument())
            sessions = [stack.enter_context(requests.Session()) for _ in range(_warm_stream.SLOTS)]
            for session in sessions:
                session.trust_env = False
                if run.farm_network:
                    _farm_session(session, run.machines + 1, run.directory)
            _warm_stream.run_stream(run, sessions)
    elif args.role == 'probe':
        with transport.instrument():
            _warm_probe(run)
    else:
        with transport.instrument():
            _worker(run, args.first, args.count)


def install_cli_recorder() -> None:
    """Install process-wide observation hooks in a short-lived benchmark CLI interpreter.

    `FARM_ATTEMPTS` selects the exit-time evidence file. New sessions use
    `FARM_CALL_PHASE`, and optional `FARM_VALID_MACHINE` selects the pinned
    fixture transport. At exit the recorder flushes and transport timing is
    restored.

    Raises:
        KeyError: If `FARM_ATTEMPTS` is absent.
    """
    destination = Path(os.environ['FARM_ATTEMPTS'])
    index = os.environ.get('FARM_VALID_MACHINE')
    buffer = _AttemptBuffer()

    class _InstrumentedSession(requests.Session):
        """Collect attempts in this short-lived CLI interpreter."""

        def __init__(self) -> None:
            """Use the CLI transport with benchmark-only observation."""
            super().__init__()
            self.headers['X-Farm-Phase'] = os.environ['FARM_CALL_PHASE']
            if index is not None:
                _farm_session(self, int(index), destination.parent)
            self.send = buffer.observe(self.send)

    timing = contextlib.ExitStack()
    timing.enter_context(transport.instrument())
    atexit.register(timing.close)
    atexit.register(buffer.write, destination)
    requests.Session = _InstrumentedSession


if __name__ == '__main__':
    _main()
