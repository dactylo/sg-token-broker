"""Measure farm acquisitions against an isolated deployment of the shipping broker.

Build the image first with `docker build -f benchmarks/farm/Dockerfile -t
sgtb-farm-bench .`. By default Docker runs the brokers and nginx. A separate
load generator shares their network namespace so nginx can distinguish valid
machines. Use --direct inside the image for a loopback diagnosis or --scenario
tls-smoke for a host-side CLI request. Host runs save raw artifacts in
`bench-results/` at the repository root.
"""

import argparse
import asyncio
import contextlib
import json
import os
import platform
import secrets
import shutil
import sys
import tempfile
import time
from pathlib import Path

import requests

from benchmarks.farm import HOST_PORT, Run, publish
from benchmarks.farm._scenarios import SCENARIOS, measurements

_ARTIFACTS = Path(__file__).resolve().parents[2] / 'bench-results'
_STARTUP_SECONDS = 30
_IMAGE = 'sgtb-farm-bench'


def _args(run: Run, directory: Path) -> list[str]:
    """Pass the same workload description to each child."""
    return [
        str(directory),
        run.scenario,
        str(run.machines),
        run.variant,
        *(['--direct'] if run.direct else []),
    ]


def _docker() -> str:
    """Locate the Docker client used to start the isolated deployment."""
    executable = shutil.which('docker')
    if not executable:
        raise RuntimeError('Docker is required for the TLS deployment')
    return executable


def _healthy(run: Run) -> bool:
    """Check the actual bound endpoint, including the host's certificate trust path."""
    with requests.Session() as session:
        session.trust_env = False
        try:
            response = session.get(
                f'{run.url}/healthz',
                timeout=2,
                verify=True if run.direct else str(run.directory / 'ca.pem'),
            )
        except requests.ConnectionError:
            return False
        return response.ok


async def _observer(run: Run) -> asyncio.subprocess.Process:
    """Join the deployment namespaces from a separate, independently pinned cgroup."""
    name = f'container:sgtb-{run.directory.parent.name}-{run.directory.name}'
    return await asyncio.create_subprocess_exec(
        _docker(),
        'run',
        '--rm',
        *(['--memory', '1g', '--memory-swap', '1g'] if run.scenario == 'rejected-tokens' else []),
        '--network',
        name,
        '--pid',
        name,
        '--mount',
        f'type=bind,source={run.directory},target=/results',
        _IMAGE,
        'python',
        '-m',
        'benchmarks.farm.launcher',
        'observe',
        *_args(run, Path('/results')),
    )


def _prepare(run: Run) -> None:
    """Create a fresh, private fixture and the benchmark-only CLI startup hook."""
    (run.directory / 'fixture').write_bytes(secrets.token_bytes(32))
    instrument = run.directory / 'instrument'
    instrument.mkdir()
    (instrument / 'sitecustomize.py').write_text(
        'from benchmarks.farm.loadgen import install_cli_recorder\ninstall_cli_recorder()\n'
    )


def _raw_directory(direct: bool) -> tuple[Path, Path]:
    """Create a private artifact tree under the host checkout or the container mount."""
    raw = (
        Path('/results')
        if direct and sys.platform == 'linux' and Path('/results').is_mount()
        else _ARTIFACTS
    )
    raw.mkdir(parents=True, exist_ok=True)
    parent = Path(tempfile.mkdtemp(prefix='farm-', dir=raw)).resolve()
    return raw, parent


async def _server(run: Run, *, smoke: bool) -> asyncio.subprocess.Process:
    """Start the deployment locally or in the resource-limited Linux container."""
    launch = ['-m', 'benchmarks.farm.launcher', 'serve']
    if run.direct:
        return await asyncio.create_subprocess_exec(
            sys.executable, *launch, *_args(run, run.directory)
        )
    root = await asyncio.to_thread(_ARTIFACTS.resolve)
    checkout = Path(__file__).parents[2]
    if not root.is_relative_to(checkout) or not run.directory.is_relative_to(root):
        raise ValueError('the Docker mount must be inside the repository benchmark directory')
    return await asyncio.create_subprocess_exec(
        _docker(),
        'run',
        '--rm',
        '--name',
        f'sgtb-{run.directory.parent.name}-{run.directory.name}',
        '--cpus',
        '4',
        '--memory',
        '1g' if smoke else '8g',
        '--publish',
        f'127.0.0.1:{HOST_PORT}:443',
        '--mount',
        f'type=bind,source={run.directory},target=/results',
        _IMAGE,
        'python',
        *launch,
        *_args(run, Path('/results')),
    )


async def _shard(run: Run, role: str, *extra: str) -> asyncio.subprocess.Process:
    """Start a host load generator outside the deployment's resource limit."""
    return await asyncio.create_subprocess_exec(
        sys.executable, '-m', 'benchmarks.farm.loadgen', role, *_args(run, run.directory), *extra
    )


async def _generator(run: Run, role: str) -> asyncio.subprocess.Process:
    """Run direct and host TLS loads locally, others in a container on the deployment network."""
    if run.direct or run.scenario == 'tls-smoke':
        return await _shard(run, role)
    name = f'sgtb-{run.directory.parent.name}-{run.directory.name}'
    return await asyncio.create_subprocess_exec(
        _docker(),
        'run',
        '--rm',
        *(
            ['--memory', '8g', '--memory-swap', '8g']
            if role == 'fleet' and run.scenario == 'rejected-tokens'
            else []
        ),
        '--network',
        f'container:{name}',
        '--mount',
        f'type=bind,source={run.directory},target=/results',
        _IMAGE,
        'python',
        '-m',
        'benchmarks.farm.loadgen',
        role,
        *_args(run, Path('/results')),
        '--direct'
        if role == 'negative' and run.variant == 'unthrottled-broker'
        else '--farm-network',
    )


async def _stop(child: asyncio.subprocess.Process) -> None:
    """Terminate any remaining load generator and reap its exit."""
    if child.returncode is None:
        with contextlib.suppress(ProcessLookupError):
            child.terminate()
    await child.wait()


async def _success(children: list[asyncio.subprocess.Process]) -> None:
    """Fail on load generator infrastructure errors while preserving caller failures as data."""
    for job in asyncio.as_completed([child.wait() for child in children]):
        result = await job
        if result:
            raise RuntimeError(f'load generator exited with status {result}')


def _variants(name: str) -> tuple[str, ...]:
    """Expand the workloads which require separate, independently cold deployments."""
    if name in {'cold-burst', 'warm-burst', 'slow-sg'}:
        return ('simultaneous', 'minute')
    if name == 'bad-secrets':
        return ('one-source', 'unthrottled-broker')
    return ('simultaneous',)


async def _wait(paths: list[Path], children: list[asyncio.subprocess.Process]) -> None:
    """Wait for every phase marker while watching for a failed or departed participant."""
    while not all(path.exists() for path in paths):
        for child in children:
            if child.returncode is not None:
                raise RuntimeError(
                    f'worker {child.pid} exited {child.returncode} before {paths[0].name}'
                )
        await asyncio.sleep(0.05)


async def _drive(run: Run, server: asyncio.subprocess.Process) -> None:
    """Coordinate priming, faults, simultaneous dispatch and measurement completion."""
    directory = run.directory
    shards: list[asyncio.subprocess.Process] = []
    others: list[asyncio.subprocess.Process] = []
    starts = range(0, run.machines, run.shard_size)
    try:
        shards.append(await _generator(run, 'fleet'))
        primed = [directory / f'primed-{i}.json' for i in starts]
        markers = list(primed)
        if run.scenario in {'slow-sg', 'slow-control'}:
            others.append(await _generator(run, 'probe'))
            others.append(await _generator(run, 'stream'))
            markers.extend([directory / 'probe-ready.json', directory / 'stream-ready.json'])
        await _wait(markers, [server, *shards, *others])
        if run.fresh_rest_window:
            (directory / 'prime-rest').touch()
            await _wait([directory / 'rest-primed.json'], [server, *shards])
        if run.scenario == 'bad-secrets':
            others.append(await _generator(run, 'negative'))
            await _wait([directory / 'negative-ready.json'], [server, *shards, *others])
        if run.scenario == 'synchronized-renewal':
            latest = max(float(json.loads(path.read_text())) for path in primed)
            # Start polling before the earliest scheduled first refresh. Clients
            # retain their production jitter and renewal spacing throughout.
            await asyncio.sleep(max(0, latest - 125 - time.time()))
        (directory / 'activate').touch()
        await _wait([directory / 'active.json'], [server])
        publish(directory / 'dispatch.json', time.time())
        if run.scenario == 'rotation':
            await _wait([directory / f'cold-{i}.json' for i in starts], [server, *shards])
            (directory / 'start-warm').touch()
        await _success(shards)
        (directory / 'probe-stop').touch()
        await _success(others)
    finally:
        await asyncio.gather(*(_stop(child) for child in [*shards, *others]))


async def _workload(run: Run, server: asyncio.subprocess.Process) -> None:
    """Stop the clients if their deployment exits during a phase."""
    await _wait([run.directory / 'ready.json'], [server])
    started = time.monotonic()
    while not await asyncio.to_thread(_healthy, run):
        if server.returncode is not None or time.monotonic() - started > _STARTUP_SECONDS:
            raise RuntimeError('benchmark health check failed; inspect the deployment output')
        await asyncio.sleep(0.1)
    work = asyncio.create_task(_drive(run, server))
    exit_status = asyncio.create_task(server.wait())
    try:
        done, _ = await asyncio.wait([work, exit_status], return_when=asyncio.FIRST_COMPLETED)
        if exit_status in done:
            raise RuntimeError(f'deployment exited during workload: {exit_status.result()}')
        await work
    finally:
        work.cancel()
        exit_status.cancel()
        await asyncio.gather(work, exit_status, return_exceptions=True)


async def _case(run: Run, args: argparse.Namespace, *, smoke: bool) -> dict[str, object]:
    """Run an independent case and finalize all evidence before reading its report."""
    run.directory.mkdir(mode=0o700)
    try:
        _prepare(run)
        if smoke:
            (run.directory / 'smoke').touch()
        publish(run.directory / 'warm-topology.json', args.warm_brokers)
        if args.brokers is not None:
            publish(run.directory / 'deployment-topology.json', args.brokers)
        if args.sample_client_sockets:
            (run.directory / 'sample-client-sockets').touch()
        if args.observer_control:
            (run.directory / 'observer-control').touch()
        server = await _server(run, smoke=smoke)
        observer = None
        try:
            if not run.direct:
                await _wait([run.directory / 'deployment.json'], [server])
                observer = await _observer(run)
                await _wait([run.directory / 'ready.json'], [server, observer])
            if observer is None:
                await _workload(run, server)
            else:
                work = asyncio.create_task(_workload(run, server))
                observed = asyncio.create_task(observer.wait())
                try:
                    done, _ = await asyncio.wait(
                        [work, observed], return_when=asyncio.FIRST_COMPLETED
                    )
                    if observed in done:
                        raise RuntimeError('observer exited before the workload completed')
                    await work
                finally:
                    work.cancel()
                    observed.cancel()
                    await asyncio.gather(work, observed, return_exceptions=True)
        finally:
            (run.directory / 'observer-stop').touch()
            observer_status = await observer.wait() if observer else 0
            (run.directory / 'stop').touch()
            if await server.wait() or observer_status:
                raise RuntimeError('deployment or observer exited unsuccessfully')
        return measurements(run)
    finally:
        (run.directory / 'fixture').unlink(missing_ok=True)


async def _measure(args: argparse.Namespace, names: tuple[str, ...]) -> None:
    """Write each completed case to the requested report, including unmet expectations."""
    smoke = args.smoke or args.scenario in {'smoke', 'tls-smoke'}
    raw, parent = await asyncio.to_thread(_raw_directory, args.direct)
    results: list[dict[str, object]] = []
    report = {
        'host': platform.platform(),
        'cpus': os.cpu_count(),
        'python': platform.python_version(),
        'raw_directory': str(parent.relative_to(raw.resolve())),
        'direct': args.direct,
        'cases': results,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    for name in names:
        variants = ('simultaneous',) if args.scenario == 'smoke' else _variants(name)
        if args.variant is not None:
            variants = (args.variant,)
        machines = args.machines or (100 if smoke else 10_000)
        if name == 'tls-smoke':
            machines = 1
        for variant in variants:
            run = Run(parent / f'{name}-{variant}', name, machines, variant, args.direct)
            results.append(await _case(run, args, smoke=smoke))
            publish(args.report, report)
            print(f'{name} ({variant}): {machines} machines; report {args.report}', flush=True)


def _main() -> None:
    """Parse workload selection and start the benchmark."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--scenario',
        required=True,
        choices=[*SCENARIOS, 'slow-control', 'generator-calibration', 'all', 'smoke', 'tls-smoke'],
    )
    parser.add_argument(
        '--observer-control',
        action='store_true',
        help='measure without service hop traces, access logs, counters or resource samples',
    )
    topology = parser.add_mutually_exclusive_group()
    topology.add_argument(
        '--warm-brokers',
        type=int,
        choices=range(1, 9),
        help='broker processes for warm burst, slow SG and matched control',
    )
    topology.add_argument(
        '--brokers',
        type=int,
        choices=range(1, 9),
        help='deployment process count (two-process and rejected-token scenarios always use two)',
    )
    parser.add_argument(
        '--sample-client-sockets',
        action='store_true',
        help='save live TLS peer endpoints to join with nginx worker IDs for capacity sizing',
    )
    parser.add_argument('--report', required=True, type=Path, help='JSON measurement report')
    parser.add_argument(
        '--variant',
        choices=('simultaneous', 'minute'),
        help='select one cold, warm or slow-SG burst arrival schedule',
    )
    parser.add_argument(
        '--direct', action='store_true', help='run brokers and clients here on loopback'
    )
    parser.add_argument(
        '--machines', type=int, help='override the 10,000-machine acceptance workload'
    )
    parser.add_argument(
        '--smoke',
        action='store_true',
        help='diagnostic scale: 100 machines and a 1 GiB deployment (TLS runs)',
    )
    args = parser.parse_args()
    names: tuple[str, ...] = {
        'all': (*SCENARIOS, 'slow-control'),
        'smoke': ('cold-burst', 'rotation'),
    }.get(args.scenario, (args.scenario,))
    if args.warm_brokers is None:
        args.warm_brokers = 1
        if (
            args.brokers is None
            and not args.direct
            and not args.smoke
            and args.scenario != 'smoke'
        ):
            reference = Path(__file__).resolve().parents[2] / 'docs' / 'reverse-proxy.conf'
            if not reference.exists():
                reference = Path('/etc/nginx/reverse-proxy.conf')
            args.brokers = sum(
                line.lstrip().startswith('server 127.0.0.1:')
                for line in reference.read_text().splitlines()
            )
    if args.variant is not None and (
        args.scenario not in {'cold-burst', 'warm-burst', 'slow-sg'}
        or args.variant not in _variants(args.scenario)
    ):
        parser.error(
            '--variant requires a cold, warm or slow-SG burst and a matching arrival schedule'
        )
    if (
        args.direct
        and args.warm_brokers > 1
        and {'warm-burst', 'slow-sg', 'slow-control'}.intersection(names)
    ):
        parser.error(
            'multiple warm brokers require the proxy route; omit --direct or use --warm-brokers 1'
        )
    if args.direct and args.brokers and args.brokers > 1:
        parser.error('multiple broker processes require the proxy route; omit --direct')
    if args.machines is not None and args.machines < 1:
        parser.error('--machines must be positive')
    if args.scenario == 'tls-smoke' and args.direct:
        parser.error('tls-smoke uses the container proxy; omit --direct')
    asyncio.run(_measure(args, names))


if __name__ == '__main__':
    _main()
