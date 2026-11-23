"""Launch the production HTTP service and collect per-process evidence on Linux.

The deployment reads phase signals from a shared run directory. Only the
reference proxy accepts traffic from outside the deployment namespace.
"""

import argparse
import asyncio
import contextlib
import hashlib
import io
import json
import logging
import os
import platform
import re
import secrets
import shutil
import socket
import sys
import tempfile
import threading
import time
from collections import Counter
from collections.abc import Callable, Sequence
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import requests

from benchmarks.farm import (
    DIRECT_NEGATIVE_PEER,
    DIRECT_PORT,
    MANY_CLIENTS,
    SCOPES_PER_CLIENT,
    Run,
    append,
    clock_domain,
    pin_cpus,
    publish,
    recovery_memory,
)
from benchmarks.farm._fake_sg import FakeSG
from sg_token_broker import _secrets
from sg_token_broker._admission import SecretVerifier
from sg_token_broker._audit import AuditLogger
from sg_token_broker._config import load_config
from sg_token_broker._http import create_server
from sg_token_broker._service import BrokerService
from sg_token_broker._sg import MintedToken, SGMinter

_REFERENCE = Path('/etc/nginx/reverse-proxy.conf')
_INTERVAL = 0.2
_TLS_PORT = 443


class _BrokerTrace:
    """Buffer socket lifetime records, including accepts rejected before HTTP parsing."""

    def __init__(self) -> None:
        """Start with an empty socket history and no open peer records."""
        self.records: list[dict[str, object]] = []
        self._open: dict[tuple[str, int], dict[str, object]] = {}

    def accepted(self, peer: tuple[str, int]) -> None:
        """Timestamp an accept on the deployment clock and correlate it to wall time."""
        record: dict[str, object] = {
            'peer': peer,
            'accepted': time.monotonic(),
            'wall': time.time(),
        }
        self.records.append(record)
        self._open[peer] = record

    def closed(self, peer: tuple[str, int]) -> None:
        """Close the record without attributing an unread request to a client attempt."""
        record = self._open.pop(peer)
        record['finished'] = time.monotonic()
        record['disposition'] = 'handled' if 'handler_start' in record else 'pre_handler'

    def parsed(self, peer: tuple[str, int], attempt_id: str | None) -> None:
        """Link a parsed request to its client and nginx observation."""
        if attempt_id:
            self._open[peer]['attempt_id'] = attempt_id

    def started(self, peer: tuple[str, int]) -> None:
        """Record entry to the worker before it parses the request."""
        self._open[peer]['handler_start'] = time.monotonic()


class _Deployment:
    """Manage phase boundaries, broker incarnations and resource sampling."""

    def __init__(self, run: Run, private: Path, sg: FakeSG | None) -> None:
        """Prepare generated server configuration in a private directory."""
        self._run = run
        self._private = private
        self._sg = sg
        self._port = int(json.loads((run.directory / 'fixture-port.json').read_text()))
        script = private / 'script'
        script.write_text(secrets.token_urlsafe(32))
        self._config = _config(run, script)
        self._children: dict[str, asyncio.subprocess.Process] = {}

    async def _close(self) -> None:
        """Stop and reap the proxy and drain every remaining broker child."""
        proxy = self._children.pop('proxy', None)
        try:
            if proxy is not None:
                if proxy.returncode is None:
                    proxy.terminate()
                await proxy.wait()
        finally:
            await asyncio.gather(*(_close_broker(child) for child in self._children.values()))

    async def _proxy(self) -> asyncio.subprocess.Process:
        """Start the configured proxy as a supervised child."""
        executable, config = _proxy_config(self._run, self._private)
        test = await asyncio.create_subprocess_exec(executable, '-t', '-c', config)
        if await test.wait():
            raise RuntimeError('nginx rejected the verified benchmark configuration')
        return await asyncio.create_subprocess_exec(
            executable,
            '-c',
            config,
            '-e',
            str(self._run.directory / 'nginx-error.log'),
            '-g',
            'daemon off;',
        )

    def _publish_pids(self) -> None:
        """Publish the current service incarnations to the PID-namespace observer."""
        if sys.platform == 'linux' and 'proxy' in self._children:
            publish(
                self._run.directory / 'proxy-affinity.json',
                sorted(os.sched_getaffinity(self._children['proxy'].pid)),
            )
        publish(
            self._run.directory / 'service-pids.json',
            {k: v.pid for k, v in self._children.items()},
        )

    def _release(self) -> None:
        """Release held SG replies during a restart or on shutdown."""
        if self._sg is None:
            (self._run.directory / 'fixture-release').touch()
        else:
            self._sg.release_replies()

    async def _snapshot(self, label: str) -> None:
        """Request a named counter and audit snapshot from each broker and await its reply."""
        for name, child in self._children.items():
            if name.startswith('broker') and child.stdin and child.stdout:
                child.stdin.write(f'{label}\n'.encode())
                await child.stdin.drain()
                if (await child.stdout.readline()).strip() != label.encode():
                    raise RuntimeError(f'{name} exited before the measured phase')

    async def _activate(self) -> None:
        """Set the fault boundary after sampling pre-warmed counters."""
        await self._snapshot('baseline')
        publish(
            self._run.directory / 'pressure-baseline.json',
            _pressure(Path('/proc/net'), Path('/sys/fs/cgroup')),
        )
        if self._sg is None:
            (self._run.directory / 'fixture-activate').touch()
        else:
            publish(self._run.directory / 'active.json', self._sg.activate(self._run.scenario))

    async def _start(self, slot: int, incarnation: int) -> None:
        """Start a fresh broker cache on the selected upstream socket."""
        name = f'broker-{slot}-{incarnation}'
        config = self._private / f'{name}.json'
        publish(
            config,
            {
                **self._config,
                'server': {'port': DIRECT_PORT + slot},
                'site_url': f'http://127.0.0.1:{self._port}/{name}',
            },
        )
        self._children[name] = await _start_broker(config, self._run, name)

    async def serve(self) -> None:
        """Supervise the deployment through phase changes, requested restarts and shutdown.

        Raises:
            RuntimeError: If a required executable or service is unavailable,
                refuses its configuration, or a supervised child exits
                unexpectedly.
            OSError: If starting a process or reading or writing run artifacts
                fails.
            ValueError: If topology data or the reference proxy configuration
                is invalid.
            TypeError: If the topology value cannot be converted to an integer.
        """
        directory = self._run.directory
        active = False
        try:
            for slot in range(
                0 if self._run.scenario == 'generator-calibration' else self._run.brokers
            ):
                await self._start(slot, 0)
            if not self._run.direct:
                self._children['proxy'] = await self._proxy()
            self._publish_pids()
            publish(directory / 'ready.json', value=True)
            while not (directory / 'stop').exists():
                if any(child.returncode is not None for child in self._children.values()):
                    raise RuntimeError('a deployment process exited unexpectedly')
                if not active and (directory / 'activate').exists():
                    await self._activate()
                    active = True
                if (
                    self._run.scenario == 'process-restart'
                    and active
                    and (directory / 'mints.jsonl').exists()
                    and 'broker-0-0' in self._children
                ):
                    started = time.time()
                    monotonic = time.monotonic()
                    await _close_broker(self._children.pop('broker-0-0'))
                    publish(directory / 'retired-broker.json', 'broker-0-0')
                    self._release()
                    await self._start(0, 1)
                    self._publish_pids()
                    publish(
                        directory / 'restart.json',
                        {
                            'started': started,
                            'finished': time.time(),
                            'started_monotonic': monotonic,
                            'finished_monotonic': time.monotonic(),
                        },
                    )
                if (directory / 'start-warm').exists() and not (directory / 'warm.json').exists():
                    await self._snapshot('warm')
                    publish(directory / 'warm.json', value=True)
                if self._sg is not None:
                    self._sg.flush()
                    _sample(directory, {k: v.pid for k, v in self._children.items()})
                await asyncio.sleep(_INTERVAL)
        finally:
            publish(
                directory / 'pressure-final.json',
                _pressure(Path('/proc/net'), Path('/sys/fs/cgroup')),
            )
            self._release()
            await self._close()


class _VerificationCounts:
    """Collect additional benchmark verification counts at phase boundaries."""

    def __init__(self) -> None:
        """Create the shared lock and empty computation and verification counters."""
        self.lock = threading.Lock()
        self.computations: Counter[str] = Counter()
        self.verified: Counter[str] = Counter()


def _cache_clock(minter: SGMinter) -> tuple[dict[int, float], Callable[[], float]]:
    """Record the first broker clock sample after a successful REST mint returns."""
    local = threading.local()
    cache_starts: dict[int, float] = {}

    def clock() -> float:
        stamp = time.monotonic()
        generation = getattr(local, 'rest_generation', None)
        if generation is not None:
            cache_starts[generation] = stamp
            del local.rest_generation
        return stamp

    mint_rest = minter.mint_rest_token

    def timed_rest(script_name: str, script_key: str, *, scope: str | None = None) -> MintedToken:
        result = mint_rest(script_name, script_key, scope=scope)
        local.rest_generation = int(result.token.partition('.')[0])
        return result

    minter.mint_rest_token = timed_rest
    return cache_starts, clock


async def _close_broker(child: asyncio.subprocess.Process) -> None:
    """Close the control stream so the broker drains and publishes counters."""
    if child.stdin is not None:
        child.stdin.close()
    if await child.wait():
        raise RuntimeError(f'broker exited with status {child.returncode}')


def _config(run: Run, script_file: Path) -> dict[str, object]:
    """Build the real broker configuration using only generated credentials."""
    clients: dict[str, object] = {}
    scopes: dict[str, object] = {}
    many = run.scenario == 'many-clients'
    for index in range(MANY_CLIENTS if many else 1):
        names = [f'scope-{index}-{j}' for j in range(SCOPES_PER_CLIENT if many else 1)]
        for name in names:
            scopes[name] = {'script_name': name, 'script_key_file': str(script_file)}
        slots = 2 if run.scenario == 'rotation' else 1
        clients[f'farm-{index}'] = {
            'secret_hashes': [
                _secrets.hash_secret(run.credential(index, i)) for i in range(slots)
            ],
            'scopes': names,
        }
    if run.scenario in {'slow-sg', 'slow-control'}:
        scopes['warm'] = {'script_name': 'warm', 'script_key_file': str(script_file)}
        clients['farm-1'] = {
            'secret_hash': _secrets.hash_secret(run.credential(1)),
            'scopes': ['warm'],
        }
    return {
        'clients': clients,
        'scopes': scopes,
        'defaults': {
            # Allow the full proxy-limited priming burst to see one expiry.
            'session_ttl_seconds': (
                125 + run.machines // 10 if run.scenario == 'synchronized-renewal' else 3600
            )
        },
    }


def _count_verifications(counts: _VerificationCounts) -> contextlib.ExitStack:
    """Install counters for the instrumented service only."""
    raw = _secrets.verify_secret
    verify = SecretVerifier.verify
    local = threading.local()
    lock, computations, verified = counts.lock, counts.computations, counts.verified

    def count_raw(secret: str, secret_hash: str) -> bool:
        credentials: Sequence[tuple[str, str]] = local.credentials
        label = next(
            (
                f'{local.client_id}/{credential_id}'
                for credential_id, stored in credentials
                if stored == secret_hash
            ),
            'padding',
        )
        local.computed = True
        with lock:
            computations[label] += 1
        return raw(secret, secret_hash)

    def count_verified(
        owner: SecretVerifier, client_id: str, credentials: Sequence[tuple[str, str]], secret: str
    ) -> str | None:
        local.client_id = client_id
        local.credentials = credentials
        local.computed = False
        try:
            matched = verify(owner, client_id, credentials, secret)
            if matched and local.computed:
                with lock:
                    verified[f'{client_id}/{matched}'] += 1
            return matched
        finally:
            del local.credentials, local.client_id, local.computed

    hooks = contextlib.ExitStack()
    hooks.enter_context(patch.object(_secrets, 'verify_secret', count_raw))
    hooks.enter_context(patch.object(SecretVerifier, 'verify', count_verified))
    return hooks


def _cpu_sample(proc: Path, cpus: set[int]) -> dict[str, dict[str, int]]:
    """Read VM CPU totals and task scheduler wait on the observer and fleet CPUs."""
    names = {f'cpu{cpu}' for cpu in cpus}
    sample: dict[str, dict[str, int]] = {}
    for line in (proc / 'stat').read_text().splitlines():
        fields = line.split()
        if fields and fields[0] in names:
            ticks = list(map(int, fields[1:9]))
            sample[fields[0]] = {'total_ticks': sum(ticks), 'idle_ticks': sum(ticks[3:5])}
    schedstat = proc / 'schedstat'
    if schedstat.exists():
        for line in schedstat.read_text().splitlines():
            fields = line.split()
            if fields and fields[0] in sample:
                sample[fields[0]].update(
                    runtime_ns=int(fields[-3]), runnable_wait_ns=int(fields[-2])
                )
    return sample


def _environment() -> dict[str, object]:
    """Record the actual deployment platform and kernel-enforced cgroup limits."""
    limits = {}
    for name in ('cpu.max', 'memory.max', 'pids.max'):
        path = Path('/sys/fs/cgroup') / name
        if path.exists():
            limits[name] = path.read_text().strip()
    return {
        'platform': platform.platform(),
        'machine': platform.machine(),
        'python': platform.python_version(),
        'logical_cpus': os.cpu_count(),
        'cgroup': limits,
        'somaxconn': int(Path('/proc/sys/net/core/somaxconn').read_text())
        if sys.platform == 'linux'
        else None,
    }


def _observe_accepts(
    accept: Callable[[], tuple[socket.socket, tuple[str, int]]],
    counts: Counter[str],
) -> Callable[[], tuple[socket.socket, tuple[str, int]]]:
    """Count the dedicated fixture peer at accept, including pre-handler refusals."""

    def observed() -> tuple[socket.socket, tuple[str, int]]:
        connection, peer = accept()
        if peer[0] == DIRECT_NEGATIVE_PEER:
            counts[peer[0]] += 1
        return connection, peer

    return observed


def _owned_connections(pid: int, sockets: dict[str, tuple[str, str]]) -> int:
    """Count a broker's accepted client sockets and outbound SG sockets."""
    connected = 0
    for fd in Path(f'/proc/{pid}/fd').iterdir():
        with contextlib.suppress(FileNotFoundError):
            link = str(fd.readlink())
            connected += link.startswith('socket:[') and link[8:-1] in sockets
    return connected


def _pressure(proc_net: Path, cgroup: Path) -> dict[str, int]:
    """Read namespace TCP and deployment cgroup counters by their kernel names."""
    counters: dict[str, int] = {}
    netstat = proc_net / 'netstat'
    if netstat.exists():
        lines = iter(netstat.read_text().splitlines())
        for header, values in zip(lines, lines, strict=True):
            if header.startswith('TcpExt:') and values.startswith('TcpExt:'):
                counters.update(
                    {
                        key: int(value)
                        for key, value in zip(header.split(), values.split(), strict=True)
                        if key in {'ListenOverflows', 'ListenDrops', 'TCPSynRetrans'}
                    }
                )
    stat = cgroup / 'cpu.stat'
    if stat.exists():
        for line in stat.read_text().splitlines():
            name, value = line.split()
            if name in {'nr_periods', 'nr_throttled', 'throttled_usec'}:
                counters[name] = int(value)
    return counters


def _process_sample(proc: Path) -> dict[str, int]:
    """Read process totals and main-thread scheduler counters from Linux procfs."""
    status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines())
    if status.get('State', '').strip().startswith(('Z', 'X')):
        raise ProcessLookupError('process exited before resource sampling')
    stat = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
    counters = {
        'cpu_ticks': int(stat[11]) + int(stat[12]),
        'rss_kib': int(status['VmRSS'].split()[0]),
        'peak_rss_kib': int(status['VmHWM'].split()[0]),
        'threads': int(status['Threads']),
    }
    limits = proc / 'limits'
    if limits.exists():
        maximum = re.search(r'^Max open files\s+(\S+)\s+(\S+)', limits.read_text(), re.MULTILINE)
        if maximum:
            for name, value in zip(('nofile_soft', 'nofile_hard'), maximum.groups(), strict=True):
                counters[name] = -1 if value == 'unlimited' else int(value)
    schedstat = proc / 'schedstat'
    if schedstat.exists():
        runtime, runnable_wait, _ = schedstat.read_text().split()
        counters['main_thread_runtime_ns'] = int(runtime)
        counters['main_thread_runnable_wait_ns'] = int(runnable_wait)
    return counters


def _proxy_connections(
    sockets: dict[str, tuple[str, str]], broker_ports: set[int]
) -> dict[str, int]:
    """Count TLS ingress and the nginx side of connections to the IPv4 loopback upstreams."""
    loopback = int.from_bytes(socket.inet_aton('127.0.0.1'), sys.byteorder)
    source = f'{loopback:08X}'
    upstreams = {f'{source}:{port:04X}' for port in broker_ports}
    ingress = upstream = 0
    for local, remote in sockets.values():
        address, _, port = local.partition(':')
        ingress += int(port, 16) == _TLS_PORT
        upstream += address == source and remote in upstreams
    return {'ingress': ingress, 'upstream': upstream}


def _select_upstreams(reference: str, count: int) -> str:
    """Select consecutive loopback peers, preserving each configured server's options."""
    peers = re.findall(
        r'^        (?:# )?(server 127\.0\.0\.1:(\d+) [^;\n]+;)$', reference, re.MULTILINE
    )
    ports = [int(port) for _, port in peers]
    if not peers or ports != list(range(DIRECT_PORT, DIRECT_PORT + len(peers))):
        raise ValueError('reference broker ports must start at 8743 and be consecutive')
    baseline = reference
    for index, (directive, _) in enumerate(peers):
        selected = f'        {"" if index < count else "# "}{directive}'
        if index == len(peers) - 1:
            for extra in range(len(peers), count):
                peer = directive.replace(f':{ports[-1]} ', f':{DIRECT_PORT + extra} ')
                selected += f'\n        {peer}'
        baseline = re.sub(
            rf'^        (?:# )?{re.escape(directive)}$', selected, baseline, flags=re.MULTILINE
        )
    return baseline


def _proxy_config(run: Run, private: Path) -> tuple[str, str]:
    """Prepare the instrumented nginx configuration and return its executable and path."""
    executable = shutil.which('nginx')
    if executable is None:
        raise RuntimeError('use the farm benchmark image to start nginx')
    reference = _REFERENCE.read_bytes().decode()
    baseline = _select_upstreams(reference, run.brokers)
    if run.scenario in {'two-processes', 'rejected-tokens'}:
        # Use the deployment guide's two-peer sizing from the same image.
        baseline, zones = re.subn(r'(zone=farm:1m rate=)\d+r/s;', r'\g<1>1000r/s;', baseline)
        baseline, peers = re.subn(
            r'^(        server 127\.0\.0\.1:\d+ [^;\n]*?max_conns=)\d+',
            r'\g<1>1024',
            baseline,
            flags=re.MULTILINE,
        )
        if (zones, peers) != (1, 2):
            raise ValueError('two-process sizing needs one farm rate and two upstream limits')
    directives = [
        (
            '    log_format farm escape=json '
            '\'{"phase":"$http_x_farm_phase","finish":$msec,"elapsed":$request_time,"peer":"$remote_addr",'
            '"remote_port":"$remote_port","worker_pid":"$pid","status":$status,'
            '"limit_req":"$limit_req_status","limit_conn":"$limit_conn_status",'
            '"connection":"$connection","connection_requests":"$connection_requests",'
            '"ssl_protocol":"$ssl_protocol","ssl_curve":"$ssl_curve",'
            '"ssl_session_reused":"$ssl_session_reused","upstream_connect_time":"$upstream_connect_time",'
            '"upstream_header_time":"$upstream_header_time","upstream_response_time":"$upstream_response_time",'
            '"upstream_addr":"$upstream_addr","retry_after":"$sent_http_retry_after","upstream":"$upstream_status","method":"$request_method","uri":"$uri",'
            '"attempt_id":"$http_x_farm_attempt","tag":"$http_x_farm_fixture"}\';'
        ),
        '    access_log /results/proxy.jsonl farm buffer=32k flush=1s;',
    ]
    if (run.directory / 'observer-control').exists():
        directives = ['    access_log off;']
    anchor = 'http {\n'
    addition = '\n'.join(directives) + '\n'
    if baseline.count(anchor) != 1:
        raise ValueError('expected one http block in the reference proxy configuration')
    calibration = run.scenario == 'generator-calibration'
    if calibration:
        # A separate TLS receiver returns only a fixed synthetic result. It has
        # no upstream, SG integration, or access to a token-issuing service.
        body = json.dumps(
            {
                'token': '1.synthetic',
                'scope': 'scope-0-0',
                'token_type': 'session',
                'site_url': 'https://example.invalid',
                'expires_at': '2099-01-01T00:00:00+00:00',
            }
        )
        baseline = (
            'worker_processes auto;\nevents { worker_connections 16384; }\nhttp {\n'
            '    server { listen 443 ssl;\n'
            '        ssl_certificate /etc/nginx/tls/fullchain.pem;\n'
            '        ssl_certificate_key /etc/nginx/tls/privkey.pem;\n'
            '        location = /healthz { return 200; }\n'
            f"location = /v1/token {{ default_type application/json; return 200 '{body}'; }}\n"
            '    }\n}\n'
        )
    config = private / 'nginx.conf'
    config.write_bytes(baseline.replace(anchor, anchor + addition).encode())
    actual = config.read_bytes().decode()
    if (
        actual.count(anchor + addition) != 1
        or actual.replace(anchor + addition, anchor) != baseline
    ):
        raise ValueError('unexpected difference from the reference proxy configuration')
    routes = re.findall(r'^        (server 127\.0\.0\.1:(\d+) [^;\n]+;)$', actual, re.MULTILINE)
    ports = [int(port) for _, port in routes]
    expected = [] if calibration else list(range(DIRECT_PORT, DIRECT_PORT + run.brokers))
    if ports != expected:
        raise ValueError(f'active upstream ports {ports} differ from selected ports {expected}')
    publish(
        run.directory / 'proxy-config.json',
        {
            'calibration_receiver': calibration,
            'reference_sha256': hashlib.sha256(reference.encode()).hexdigest(),
            'effective_sha256': hashlib.sha256(baseline.encode()).hexdigest(),
            'farm_rate_zone': next(
                (line.strip() for line in actual.splitlines() if ' zone=farm:' in line), None
            ),
            'active_upstreams': [directive for directive, _ in routes],
            'active_second_upstream': routes[1][0] if len(routes) > 1 else None,
            'broker_ports': ports,
            'added_log_directives': directives,
        },
    )
    shutil.copyfile('/etc/nginx/tls/fullchain.pem', run.directory / 'ca.pem')
    return executable, str(config)


def _serve(run: Run) -> None:
    """Run the deployment until shutdown, hosting the SG fixture locally in direct mode."""
    if not run.direct:
        pin_cpus('deployment')
        clock_domain(run.directory, 'deployment')
        publish(run.directory / 'deployment.json', _environment())
        while not (run.directory / 'fixture-port.json').exists():
            if (run.directory / 'stop').exists():
                return
            time.sleep(_INTERVAL)
        with tempfile.TemporaryDirectory() as private:
            asyncio.run(_Deployment(run, Path(private), None).serve())
        return
    clock_domain(run.directory, 'deployment')
    publish(run.directory / 'deployment.json', _environment())
    with tempfile.TemporaryDirectory() as temporary, FakeSG(run.directory) as sg:
        publish(run.directory / 'fixture-port.json', sg.server_port)
        worker = threading.Thread(target=sg.serve_forever)
        worker.start()
        try:
            asyncio.run(_Deployment(run, Path(temporary), sg).serve())
        finally:
            sg.shutdown()
            worker.join()
            sg.flush()


async def _start_broker(config: Path, run: Run, name: str) -> asyncio.subprocess.Process:
    """Wait for the broker's bound listening socket or its startup error."""
    child = await asyncio.create_subprocess_exec(
        sys.executable,
        '-m',
        'benchmarks.farm.launcher',
        'broker',
        str(config),
        str(run.directory),
        name,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
    )
    if child.stdout is None or (await child.stdout.readline()).strip() != b'ready':
        await child.wait()
        raise RuntimeError(f'broker {name} failed to start (exit {child.returncode})')
    return child


def _supervise(server: ThreadingHTTPServer, snapshot: Callable[[str], None]) -> None:
    """Serve until the supervisor closes the measurement control stream."""
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    try:
        print('ready', flush=True)
        for command in sys.stdin:
            if command.strip() in {'baseline', 'warm'}:
                snapshot(command.strip())
                print(command.strip(), flush=True)
    finally:
        server.shutdown()
        worker.join()


def _tcp_sockets(proc_net: Path = Path('/proc/net')) -> dict[str, tuple[str, str]]:
    """Read local and remote endpoints for each owned, non-listening TCP socket."""
    sockets: dict[str, tuple[str, str]] = {}
    for version in ('tcp', 'tcp6'):
        table = proc_net / version
        if table.exists():
            for line in table.read_text().splitlines()[1:]:
                fields = line.split()
                if fields[3] != '0A' and fields[9] != '0':
                    sockets[fields[9]] = (fields[1], fields[2])
    return sockets


def _tls_peers(sockets: dict[str, tuple[str, str]]) -> list[str]:
    """Keep live ingress endpoints for offline attribution to nginx worker PIDs."""
    return [remote for local, remote in sockets.values() if local.endswith(f':{_TLS_PORT:04X}')]


def _sample(directory: Path, pids: dict[str, int]) -> None:
    """Sample every broker, nginx master and current nginx worker."""
    if sys.platform != 'linux' or not Path('/proc/self/stat').exists():
        return
    if 'proxy' in pids:
        pid = pids['proxy']
        workers = Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
        pids.update({f'proxy-{worker}': int(worker) for worker in workers})
    scan_start = time.time()
    append(
        directory / 'observer-cpu.jsonl',
        {
            'monotonic': time.monotonic(),
            'cpus': _cpu_sample(Path('/proc'), os.sched_getaffinity(0)),
        },
    )
    sockets = _tcp_sockets()
    if 'proxy' in pids:
        if (directory / 'sample-client-sockets').exists():
            append(
                directory / 'client-sockets.jsonl',
                {
                    'start': scan_start,
                    'byteorder': sys.byteorder,
                    'finish': time.time(),
                    'peers': _tls_peers(sockets),
                },
            )
        broker_ports = {
            DIRECT_PORT + int(name.split('-')[1]) for name in pids if name.startswith('broker-')
        }
        append(
            directory / 'proxy-connections.jsonl',
            {'time': time.time(), **_proxy_connections(sockets, broker_ports)},
        )
    for name, pid in pids.items():
        with contextlib.suppress(FileNotFoundError, ProcessLookupError):
            counters = _process_sample(Path('/proc') / str(pid))
            if name.startswith('broker'):
                counters['connections'] = _owned_connections(pid, sockets)
            append(
                directory / 'resources.jsonl',
                {
                    'time': time.time(),
                    'process': name,
                    'pid': pid,
                    'ticks_per_second': os.sysconf('SC_CLK_TCK'),
                    **counters,
                },
            )


def _observer(run: Run) -> None:
    """Serve the SG fixture and sample service PIDs outside the deployment cgroup."""
    pin_cpus('observer')
    clock_domain(run.directory, 'observer')
    directory = run.directory
    activated = False
    sample_resources = not (directory / 'observer-control').exists()
    with FakeSG(directory) as sg:
        worker = threading.Thread(target=sg.serve_forever)
        worker.start()
        try:
            publish(directory / 'fixture-port.json', sg.server_port)
            while not (directory / 'observer-stop').exists():
                sg.flush()
                if not activated and (directory / 'fixture-activate').exists():
                    publish(directory / 'active.json', sg.activate(run.scenario))
                    activated = True
                if (directory / 'fixture-release').exists():
                    sg.release_replies()
                pids = directory / 'service-pids.json'
                if sample_resources and pids.exists():
                    _sample(directory, json.loads(pids.read_text()))
                time.sleep(_INTERVAL)
        finally:
            sg.release_replies()
            sg.shutdown()
            worker.join()
            sg.flush()


def _trace_server(
    server: ThreadingHTTPServer, accepts: Counter[str], trace: _BrokerTrace
) -> contextlib.ExitStack:
    """Trace server socket events and temporarily wrap the process-wide HTTP request parser."""
    peers: dict[socket.socket, tuple[str, int]] = {}
    original_accept = _observe_accepts(server.get_request, accepts)
    original_finish = server.finish_request
    original_close = server.close_request
    original_parse = BaseHTTPRequestHandler.parse_request

    def accept() -> tuple[socket.socket, tuple[str, int]]:
        sock, peer = original_accept()
        peers[sock] = peer
        trace.accepted(peer)
        return sock, peer

    def finish(sock: socket.socket, peer: tuple[str, int]) -> None:
        trace.started(peer)
        original_finish(sock, peer)

    def close(sock: socket.socket) -> None:
        trace.closed(peers.pop(sock))
        original_close(sock)

    def parse(request: BaseHTTPRequestHandler) -> bool:
        parsed = original_parse(request)
        if parsed:
            trace.parsed(request.client_address, request.headers.get('X-Farm-Attempt'))
        return parsed

    server.get_request = accept

    traces = contextlib.ExitStack()
    traces.enter_context(patch.object(server, 'finish_request', finish))
    traces.enter_context(patch.object(server, 'close_request', close))
    traces.enter_context(patch.object(BaseHTTPRequestHandler, 'parse_request', parse))
    return traces


def _broker(config: Path, directory: Path, name: str) -> None:
    """Run a shipping broker until its supervisor closes standard input."""
    counters = _VerificationCounts()
    if (directory / 'fixture').exists():
        clock_domain(directory, name)
    settings = load_config(config)
    logger = logging.getLogger('farm.audit')
    logger.setLevel(logging.INFO)
    accepts: Counter[str] = Counter()
    trace = _BrokerTrace()
    with (
        io.StringIO() as audit_buffer,
        (directory / f'audit-{name}.jsonl').open('wb') as audit_file,
        contextlib.closing(logging.StreamHandler(audit_buffer)) as handler,
        requests.Session() as upstream,
    ):
        upstream.trust_env = False
        logger.addHandler(handler)
        minter = SGMinter(settings.site_url, session=upstream)
        cache_starts, clock = _cache_clock(minter)
        service = BrokerService(settings, minter, AuditLogger(logger), clock=clock)

        def snapshot(label: str) -> None:
            handler.acquire()
            try:
                audit_file.write(audit_buffer.getvalue().encode())
                audit_file.flush()
                audit_buffer.seek(0)
                audit_buffer.truncate()
            finally:
                handler.release()
            with counters.lock:
                publish(
                    directory / f'{label}-{name}.json',
                    {
                        'scrypt': dict(counters.computations),
                        'verified': dict(counters.verified),
                        'direct_negative_accepts': accepts[DIRECT_NEGATIVE_PEER],
                        'audit_bytes': audit_file.tell(),
                    },
                )

        with contextlib.ExitStack() as hooks:
            instrumented = not (directory / 'observer-control').exists()
            if instrumented:
                hooks.enter_context(_count_verifications(counters))
            server = hooks.enter_context(create_server(settings, service))
            if instrumented:
                hooks.enter_context(_trace_server(server, accepts, trace))
            _supervise(server, snapshot)
        snapshot('final')
        publish(directory / f'cache-{name}.json', cache_starts)
        with (directory / f'hops-{name}.jsonl').open('w', encoding='utf-8') as stream:
            for record in trace.records:
                stream.write(json.dumps(record) + '\n')


def _main() -> None:
    """Dispatch the broker, deployment supervisor or independent observer role."""
    parser = argparse.ArgumentParser()
    subs = parser.add_subparsers(dest='role', required=True)
    broker = subs.add_parser('broker')
    broker.add_argument('config', type=Path)
    broker.add_argument('directory', type=Path)
    broker.add_argument('name')
    deployment = subs.add_parser('serve', aliases=['observe'])
    deployment.add_argument('directory', type=Path)
    deployment.add_argument('scenario')
    deployment.add_argument('machines', type=int)
    deployment.add_argument('variant')
    deployment.add_argument('--direct', action='store_true')
    args = parser.parse_args()
    if args.role == 'broker':
        _broker(args.config, args.directory, args.name)
    else:
        run = Run(args.directory, args.scenario, args.machines, args.variant, args.direct)
        try:
            if args.role == 'observe':
                _observer(run)
            else:
                _serve(run)
        finally:
            recovery_memory(run, 'observer' if args.role == 'observe' else 'deployment')


if __name__ == '__main__':
    _main()
