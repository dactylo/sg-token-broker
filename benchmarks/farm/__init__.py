"""Run synthetic broker workloads with `python -m benchmarks.farm --scenario NAME --report PATH`.

Use `python -m benchmarks.farm --help` for scenario names and deployment
options.
"""

import hashlib
import hmac
import json
import os
import sys
import time
from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path
from typing import cast

CLI_SLOTS_PER_SHARD = 2
DIRECT_NEGATIVE_PEER = '127.0.0.2'
DIRECT_PORT = 8743
HOST_PORT = 18443
MANY_CLIENTS = 100
MAX_WAIT = 300.0
NEGATIVE_RATE = 200
_RECOVERY_SHARDS = 8
RECOVERY_LIBRARY_WORKERS = 16
PROXY_URL = 'https://127.0.0.1'
REST = 'rest'
REST_CACHE_SECONDS = 60
SCOPES_PER_CLIENT = 3
SHARD_SIZE = 80


@dataclass(frozen=True)
class Run:
    """Describe one deployment and the workload shared by its participants.

    Attributes:
        directory: Shared directory for this run's fixtures, signals and
            observations.
        scenario: Workload to exercise.
        machines: Number of legitimate simulated farm machines.
        variant: Scenario-specific workload or deployment variant.
        direct: Use the broker's loopback route for this participant. In a
            direct deployment the supervisor also omits nginx.
        farm_network: Use the proxy endpoint inside the shared network
            namespace.
    """

    directory: Path
    scenario: str
    machines: int
    variant: str
    direct: bool
    farm_network: bool = False

    @property
    def shard_size(self) -> int:
        """Return machines per shard, raising the limit as needed for rejected-token recovery."""
        if self.scenario == 'rejected-tokens':
            return max(SHARD_SIZE, (self.machines + _RECOVERY_SHARDS - 1) // _RECOVERY_SHARDS)
        return SHARD_SIZE

    @property
    def url(self) -> str:
        """Return the loopback endpoint for this deployment."""
        if self.farm_network:
            return PROXY_URL
        return (
            f'http://127.0.0.1:{DIRECT_PORT}' if self.direct else f'https://127.0.0.1:{HOST_PORT}'
        )

    @property
    def brokers(self) -> int:
        """Return the configured broker count, even for calibration runs that launch none.

        Raises:
            OSError: If the selected topology file cannot be read.
            ValueError: If the file contains invalid JSON or an invalid integer
                string.
            TypeError: If its JSON value cannot be converted to an integer.
        """
        if self.scenario in {'two-processes', 'rejected-tokens'}:
            return 2
        selected = self.directory / 'deployment-topology.json'
        if (
            self.scenario
            in {
                'cold-burst',
                'warm-burst',
                'many-clients',
                'slow-sg',
                'slow-control',
                'sg-outage',
                'rejected-script-key',
                'rotation',
                'bad-secrets',
                'synchronized-renewal',
                'process-restart',
            }
            and selected.exists()
        ):
            return int(json.loads(selected.read_text()))
        if self.scenario in {'slow-sg', 'slow-control', 'warm-burst'}:
            topology = self.directory / 'warm-topology.json'
            if topology.exists():
                return int(json.loads(topology.read_text()))
        return 1

    @property
    def fresh_rest_window(self) -> bool:
        """Return whether warm-burst preparation needs a fresh REST cache window.

        Simultaneous arrivals and deployments with multiple brokers need a
        fresh window.

        Raises:
            OSError: If the selected topology cannot be read.
            ValueError: If its JSON or integer string is invalid.
            TypeError: If its value cannot be converted to an integer.
        """
        return self.scenario == 'warm-burst' and (
            self.variant == 'simultaneous' or self.brokers > 1
        )

    def credential(self, index: int, slot: int = 0) -> str:
        """Derive a repeatable synthetic secret from this run's fixture seed.

        Args:
            index: Synthetic client number.
            slot: Credential slot for that client during rotation.

        Raises:
            OSError: If the fixture seed cannot be read.
        """
        seed = (self.directory / 'fixture').read_bytes()
        return hmac.new(seed, f'{index}/{slot}'.encode(), hashlib.sha256).hexdigest()


def _cpu_layout(visible: set[int], role: str) -> set[int]:
    """Split Linux CPUs by role, sharing the full set when fewer than six are visible."""
    ordered = sorted(visible)
    deployment_cpus = 4
    if len(ordered) < deployment_cpus + 2:
        return visible
    if role == 'deployment':
        return set(ordered[:deployment_cpus])
    if role == 'stream':
        return {ordered[-1]}
    return set(ordered[deployment_cpus:-1])


def append(path: Path, value: object) -> None:
    """Append one JSON record and a newline to a single-writer stream.

    Args:
        path: Destination JSON-lines file.
        value: JSON-serializable record.

    Raises:
        OSError: If opening or writing the stream fails.
    """
    with path.open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(value, separators=(',', ':')) + '\n')


def machine_address(index: int) -> str:
    """Return the loopback address for a simulated machine.

    Args:
        index: Zero-based offset from `127.1.0.1`.

    Raises:
        ValueError: If the index falls outside the benchmark loopback range.
    """
    address = IPv4Address(int(IPv4Address('127.1.0.1')) + index)
    if index < 0 or not address.is_loopback:
        raise ValueError('machine index exceeds the benchmark loopback network')
    return str(address)


def pin_cpus(role: str) -> None:
    """Set the affinity inherited by new workers on Linux. Other platforms skip this step.

    Args:
        role: Use `deployment` for the first four CPUs, `stream` for the last
            CPU, or another role for the CPUs between them. All roles share
            sets smaller than six.

    Raises:
        OSError: If Linux cannot read or apply the affinity mask.
    """
    if sys.platform == 'linux':
        os.sched_setaffinity(0, _cpu_layout(os.sched_getaffinity(0), role))


def publish(path: Path, value: object) -> None:
    """Atomically replace a run artifact with one complete JSON value.

    Args:
        path: Destination owned by a single writer.
        value: JSON-serializable artifact.

    Raises:
        OSError: If the temporary file cannot be written or replaced.
    """
    pending = path.with_suffix(path.suffix + '.pending')
    pending.write_text(json.dumps(value), encoding='utf-8')
    pending.replace(path)


def clock_domain(directory: Path, role: str, proc: Path = Path('/proc/self')) -> None:
    """Publish a role's clock sample and available Linux clock-domain evidence.

    Args:
        directory: Run directory containing the fixture seed and receiving the
            sample.
        role: Participant name used in the output filename.
        proc: Process directory supplying network namespace and time-offset
            evidence.

    Raises:
        OSError: If available evidence cannot be read or the sample cannot be
            written.
    """
    network = proc / 'ns/net'
    offsets = proc / 'timens_offsets'
    domain = None
    if network.is_symlink() and offsets.exists():
        monotonic = next(
            (
                line.split()[1:]
                for line in offsets.read_text().splitlines()
                if line.split()[0] == 'monotonic'
            ),
            None,
        )
        if monotonic is not None:
            # Docker network=container joins the same kernel. Time namespaces
            # with equal CLOCK_MONOTONIC offsets share its monotonic timebase.
            domain = hmac.new(
                (directory / 'fixture').read_bytes(),
                bytes(network.readlink()) + ' '.join(monotonic).encode(),
                hashlib.sha256,
            ).hexdigest()
    before = time.monotonic()
    wall = time.time()
    after = time.monotonic()
    publish(
        directory / f'clock-{role}.json',
        {
            'domain': domain,
            'cpus': sorted(os.sched_getaffinity(0)) if sys.platform == 'linux' else [],
            'wall': wall,
            'monotonic': (before + after) / 2,
            'sampling_uncertainty_seconds': (after - before) / 2,
        },
    )


def recovery_memory(run: Run, role: str) -> None:
    """Save available cgroup memory counters for Linux rejected-token recovery.

    Args:
        run: Run whose scenario selects collection and whose directory receives
            it.
        role: Participant name used in the output filename.

    Raises:
        OSError: If an available counter cannot be read or the report cannot be
            written.
    """
    if run.scenario != 'rejected-tokens' or sys.platform != 'linux':
        return
    cgroup = Path('/sys/fs/cgroup')
    names = ('memory.current', 'memory.peak', 'memory.max', 'memory.swap.max', 'memory.events')
    publish(
        run.directory / f'memory-{role}.json',
        {name: (cgroup / name).read_text().strip() for name in names if (cgroup / name).exists()},
    )


def rows(path: Path) -> list[dict[str, object]]:
    """Read a completed JSON-lines benchmark stream.

    Returns:
        Records in file order, or an empty list when the file is absent.

    Raises:
        OSError: If the file cannot be read.
        ValueError: If a line is not valid UTF-8 JSON.
    """
    if not path.exists():
        return []
    with path.open(encoding='utf-8') as stream:
        return [cast('dict[str, object]', json.loads(line)) for line in stream]
