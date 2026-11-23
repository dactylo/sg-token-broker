"""Reduce farm observations into measurements and report the evidence for each scenario check."""

import json
import math
import re
from bisect import bisect_left
from collections import Counter, defaultdict
from collections.abc import Iterator
from functools import cached_property
from http import HTTPStatus
from ipaddress import IPv4Address, ip_address
from itertools import pairwise
from pathlib import Path
from typing import NotRequired, TypedDict, cast

from benchmarks.farm import (
    CLI_SLOTS_PER_SHARD,
    DIRECT_PORT,
    MANY_CLIENTS,
    MAX_WAIT,
    NEGATIVE_RATE,
    REST,
    REST_CACHE_SECONDS,
    SCOPES_PER_CLIENT,
    SHARD_SIZE,
    Run,
    machine_address,
    rows,
)
from benchmarks.farm._observations import observation_rows
from benchmarks.farm._reconciliation import (
    Call as _Call,
)
from benchmarks.farm._reconciliation import (
    Failure,
    Observation,
    Reconciliation,
)
from benchmarks.farm._reconciliation import (
    slot_attempts as _slot_attempts,
)
from benchmarks.farm._warm_stream import LATE_SECONDS, PERIOD, SLOTS
from sg_token_broker._issuance import IssuerLimits

SCENARIOS = (
    'cold-burst',
    'warm-burst',
    'many-clients',
    'two-processes',
    'slow-sg',
    'sg-outage',
    'rejected-script-key',
    'rejected-tokens',
    'rotation',
    'bad-secrets',
    'synchronized-renewal',
    'process-restart',
)
_REPORT_BOUND = 3
_ARRIVAL_MINUTE = 60.0
_SESSION = 'session'
_CADENCE_WINDOW = 0.1
_CADENCE_TOLERANCE = 0.1
_SEND_LAG_LIMIT = 4 / NEGATIVE_RATE
_SLOW_MINT_SECONDS = 5
_OUTAGE_SECONDS = 30
_DEPLOYMENT_CPUS = 4


class _Evidence:
    """Join caller records to sanitized per-process counter, audit and upstream evidence."""

    def __init__(self, run: Run) -> None:
        """Load the run artifacts and index caller, mint and broker evidence by phase."""
        self.run = run
        directory = run.directory
        active = json.loads((directory / 'active.json').read_text())
        self.activated = float(active['time'])
        self.active_monotonic: float | None = active.get('monotonic')
        self.outage_end: float | None = active.get('unavailable_until_monotonic')
        self.cutoff = int(active['cutoff'])
        self.calls = [
            c
            for p in sorted(directory.glob('calls-*.jsonl'))
            for c in cast('list[_Call]', observation_rows(p))
        ]
        self.clocks = _clock_records(directory)
        self.fixture_role = 'deployment' if run.direct else 'observer'
        self.clock_offset = (
            self.activated - self.active_monotonic if self.active_monotonic is not None else None
        )
        self.measure = [c for c in self.calls if c['phase'] == 'measure']
        self.by_machine: defaultdict[int, list[_Call]] = defaultdict(list)
        for call in self.measure:
            self.by_machine[call['machine']].append(call)
        all_mints = cast('list[_Mint]', rows(directory / 'mints.jsonl'))
        _align_phase_events(
            [
                c
                for c in self.calls
                if self.shared_clock(
                    'probe'
                    if run.scenario in {'slow-sg', 'slow-control'} and c['machine'] == run.machines
                    else 'fleet',
                    self.fixture_role,
                )
            ],
            all_mints,
            self.clock_offset,
            run.scenario,
        )
        _add_cache_starts(directory, all_mints)

        def measured(mint: _Mint) -> bool:
            if 'monotonic' in active and 'started_monotonic' in mint:
                return mint['started_monotonic'] >= float(active['monotonic'])
            return mint['started'] >= self.activated

        self.mints = [m for m in all_mints if measured(m)]
        self.by_key: defaultdict[str, list[_Mint]] = defaultdict(list)
        self.priming: defaultdict[str, list[_Mint]] = defaultdict(list)
        generations: dict[tuple[str, str], int] = {}
        for mint in all_mints:
            key = _mint_key(mint)
            phase = self.by_key if measured(mint) else self.priming
            phase[key].append(mint)
            if 'generation' in mint and 'token_fp' in mint:
                generations[key, mint['token_fp']] = mint['generation']
        self.verified: Counter[str] = Counter()
        self.raw: Counter[str] = Counter()
        self.warm: dict[str, dict[str, dict[str, int]]] = {}
        self.audit: Counter[str] = Counter()
        self.issues: Counter[tuple[str, str, int, str]] = Counter()
        self.processes = {f'broker-{i}-0' for i in range(run.brokers)}
        if run.scenario == 'process-restart':
            self.processes.add('broker-0-1')
        if run.scenario == 'generator-calibration':
            self.processes.clear()
        self.missing: list[str] = []
        for name in sorted(self.processes):
            self._read_broker(name, generations)

    def _read_audit(
        self, name: str, baseline: int, end: int, generations: dict[tuple[str, str], int]
    ) -> None:
        """Resolve issued fingerprints only within the emitting process and token key."""
        with (self.run.directory / f'audit-{name}.jsonl').open('rb') as stream:
            while stream.tell() < end:
                phase = 'prepare' if stream.tell() < baseline else 'measure'
                event = json.loads(stream.readline())
                key = '/'.join(
                    (
                        name,
                        event.get('client_id', '-'),
                        event.get('scope', '-'),
                        event.get('token_type', '-'),
                    )
                )
                generation = generations.get((key, event.get('token_fp')))
                outcome = event.get('outcome', event.get('reason', event['event']))
                if phase == 'measure':
                    self.audit[f'{key}/{generation or "-"}/{outcome}'] += 1
                if (
                    event['event'] == 'issue'
                    and generation is not None
                    and (outcome != 'replaced' or event.get('replaced') is True)
                ):
                    self.issues[phase, key, generation, outcome] += 1

    def _read_broker(self, name: str, generations: dict[tuple[str, str], int]) -> None:
        """Partition the process audit with its counter snapshots at phase boundaries."""
        directory = self.run.directory
        final = _snapshot(directory / f'final-{name}.json')
        start: _Counters | None = _snapshot(directory / f'baseline-{name}.json')
        if name == 'broker-0-1':
            # This incarnation was born after the measured phase started.
            start = {'verified': {}, 'scrypt': {}, 'audit_bytes': 0}
        audit = directory / f'audit-{name}.jsonl'
        if start is None:
            self.missing.append(f'baseline-{name}')
        if final is None:
            self.missing.append(f'final-{name}')
        if not audit.exists():
            self.missing.append(audit.name)
        if start is None or final is None or not audit.exists():
            return
        if not 0 <= start['audit_bytes'] <= final['audit_bytes'] <= audit.stat().st_size:
            self.missing.append(f'audit-boundary-{name}')
            return
        counts = _difference(final, start)
        self.verified.update({f'{name}/{k}': v for k, v in counts['verified'].items()})
        self.raw.update({f'{name}/{k}': v for k, v in counts['scrypt'].items()})
        if self.run.scenario == 'rotation':
            warm = _snapshot(directory / f'warm-{name}.json')
            if (
                warm is None
                or not start['audit_bytes'] <= warm['audit_bytes'] <= final['audit_bytes']
            ):
                self.missing.append(f'warm-{name}')
            else:
                self.warm[name] = _difference(final, warm)
        self._read_audit(name, start['audit_bytes'], final['audit_bytes'], generations)

    def fleet(self, phase: str) -> bool:
        """Require every scheduled machine, token type, successful result and phase boundary."""
        kinds = (
            {'session', 'rest'}
            if self.run.scenario in {'cold-burst', 'warm-burst'}
            else {'session'}
        )
        records = [c for c in self.calls if c['phase'] == phase]
        expected = {(i, kind) for i in range(self.run.machines) for kind in kinds}
        observed = {(c['machine'], c['token_type']) for c in records}
        multiple = (
            self.run.scenario in {'synchronized-renewal', 'rejected-tokens'} and phase == 'measure'
        )
        return (
            observed == expected
            and (multiple or len(records) == len(expected))
            and all(
                'generation' in c
                and c['finish'] >= c['start']
                and (
                    c['finish'] <= self.activated
                    if phase == 'prepare'
                    else c['start'] >= self.activated
                )
                and (
                    _http_success(c)
                    or (
                        self.run.scenario == 'synchronized-renewal'
                        and phase == 'measure'
                        and not c['attempts']
                    )
                )
                for c in records
            )
        )

    def complete(self) -> bool:
        """Require successful measured calls from the intended population."""
        return self.fleet('measure')

    def shared_clock(self, *roles: str) -> bool:
        """Require a common proven monotonic domain for every participant."""
        return _same_domain(self.clocks, 'deployment', *roles)

    def spacing(self, interval: float) -> bool:
        """Check spacing between consecutive measured mints for each process and key.

        Args:
            interval: Minimum seconds from one attempt's finish to the next
                start.

        Returns:
            Whether there is measured key evidence and every consecutive pair
            satisfies the minimum.
        """
        return bool(self.by_key) and all(
            b.get('started_monotonic', b['started']) - a.get('finished_monotonic', a['finished'])
            >= interval
            for mints in self.by_key.values()
            for a, b in pairwise(mints)
        )

    @cached_property
    def trace(self) -> Reconciliation:
        """Build and cache the shared attempt ledger on first access.

        Raises:
            OSError: If evidence cannot be read.
            ValueError: If evidence cannot be decoded or a numeric field is
                invalid.
            KeyError: If a required record field is missing.
            TypeError: If an evidence record has an incompatible JSON type.
        """
        return Reconciliation(self.run, self.calls, self.clocks)


class _Mint(TypedDict):
    """Describe an upstream result without its synthetic token."""

    process: str
    scope: str
    token_type: str
    outcome: str
    generation: NotRequired[int]
    token_fp: NotRequired[str]
    started: float
    finished: float
    started_monotonic: NotRequired[float]
    finished_monotonic: NotRequired[float]
    cache_started_monotonic: NotRequired[float]
    rejected_through: int


class _Counters(TypedDict):
    """Snapshot scrypt and verification counts at an audit boundary."""

    scrypt: dict[str, int]
    verified: dict[str, int]
    audit_bytes: int


class _Negative(TypedDict):
    """Describe one synthetic negative fixture outcome."""

    sent_monotonic: NotRequired[float]
    sequence: NotRequired[int]
    scheduled_monotonic: NotRequired[float]
    finish: float
    fixture: str
    status: NotRequired[int]
    error: NotRequired[str]


class _Resources(TypedDict):
    """Describe one process sample from Linux procfs."""

    cpu_ticks: int
    ticks_per_second: int
    rss_kib: int
    peak_rss_kib: int
    threads: int
    connections: NotRequired[int]
    process: str
    time: float


def _account_generations(e: _Evidence) -> tuple[dict[str, int], dict[str, int]]:
    """Join actual account use to an SG mint and the matching broker issue audit."""
    probes = {
        (p['generation'], p['token_fp'], p['accepted'])
        for p in rows(e.run.directory / 'probes.jsonl')
        if float(str(p['time'])) >= e.activated
    }
    caches: list[dict[str, int]] = []
    for phase, groups, outcome, accepted in [
        ('prepare', e.priming, 'minted', False),
        ('measure', e.by_key, 'replaced', True),
    ]:
        cache: dict[str, int] = {}
        for key, mints in groups.items():
            if len(mints) != 1:
                continue
            mint = mints[0]
            gen = mint.get('generation')
            if (
                gen is not None
                and (gen > e.cutoff) == accepted
                and (gen, mint.get('token_fp'), accepted) in probes
                and e.issues[phase, key, gen, outcome] == 1
            ):
                cache[key] = gen
        caches.append(cache)
    return caches[0], caches[1]


def _add_cache_starts(directory: Path, all_mints: list[_Mint]) -> None:
    """Join each synthetic generation to the broker's monotonic cache start."""
    cache: dict[str, dict[str, float]] = {
        path.stem.removeprefix('cache-'): json.loads(path.read_text())
        for path in directory.glob('cache-broker-*.json')
    }
    for mint in all_mints:
        stamp = cache.get(mint['process'], {}).get(str(mint.get('generation')))
        if stamp is not None:
            mint['cache_started_monotonic'] = stamp


def _cadence(invalid: list[_Negative], valid: list[_Call]) -> tuple[bool, dict[str, object]]:
    """Measure actual sends in contiguous windows across the valid machines' acquisitions."""
    sends = sorted(r['sent_monotonic'] for r in invalid if 'sent_monotonic' in r)
    lags = [
        r['sent_monotonic'] - r['scheduled_monotonic']
        for r in invalid
        if 'sent_monotonic' in r and 'scheduled_monotonic' in r
    ]
    if not sends or not valid or any('start_monotonic' not in c for c in valid):
        return False, {'dispatch_times_observed': len(sends)}
    start = min(c.get('start_monotonic', math.inf) for c in valid)
    finish = max(c.get('start_monotonic', -math.inf) + c['seconds'] for c in valid)
    left, right = bisect_left(sends, start), bisect_left(sends, finish)
    times = [start, *sends[left:right], finish]
    gap = max(b - a for a, b in pairwise(times))
    counts: list[int] = []
    paced = finish > start and right > left and sends[0] <= start and sends[-1] >= finish
    for index in range(math.ceil((finish - start) / _CADENCE_WINDOW)):
        lower = start + index * _CADENCE_WINDOW
        upper = min(finish, start + (index + 1) * _CADENCE_WINDOW)
        expected = (upper - lower) * NEGATIVE_RATE
        observed = bisect_left(sends, upper) - bisect_left(sends, lower)
        counts.append(observed)
        paced &= abs(observed - expected) <= max(1.0, expected * _CADENCE_TOLERANCE) + 1e-6
    lag = max(lags, default=math.inf)
    return (
        paced and gap <= _SEND_LAG_LIMIT and len(lags) == len(invalid) and lag <= _SEND_LAG_LIMIT
    ), {
        'valid_window': [start, finish],
        'target_per_second': NEGATIVE_RATE,
        'window_seconds': _CADENCE_WINDOW,
        'tolerance_fraction': _CADENCE_TOLERANCE,
        'minimum_count_tolerance': 1,
        'sends_by_window': counts,
        'max_gap_seconds': gap,
        'allowed_gap_and_lag_seconds': _SEND_LAG_LIMIT,
        'max_schedule_lag_seconds': max(lags, default=None),
    }


def _clock_records(directory: Path) -> dict[str, dict[str, object]]:
    """Read each participant's domain proof at startup."""
    return {
        p.stem.removeprefix('clock-'): json.loads(p.read_text())
        for p in directory.glob('clock-*.json')
    }


def _deployment_matches(
    run: Run, cgroup: dict[str, str], configured_ports: object, pids: dict[str, int]
) -> bool:
    """Check the listener routes, supervised processes and enforced container limits."""
    count = 0 if run.scenario == 'generator-calibration' else run.brokers
    names = {f'broker-{i}-0' for i in range(count)}
    if run.scenario == 'process-restart':
        names.remove('broker-0-0')
        names.add('broker-0-1')
    quota, _, period = cgroup.get('cpu.max', '').partition(' ')
    memory_gib = 1 if (run.directory / 'smoke').exists() else 8
    return (
        set(pids) == names | {'proxy'}
        and len(set(pids.values())) == len(pids)
        and all(pid > 0 for pid in pids.values())
        and configured_ports == list(range(DIRECT_PORT, DIRECT_PORT + count))
        and quota.isdecimal()
        and period.isdecimal()
        and int(period) > 0
        and int(quota) == _DEPLOYMENT_CPUS * int(period)
        and cgroup.get('memory.max') == str(memory_gib * 1024**3)
    )


def _difference(end: _Counters, start: _Counters) -> dict[str, dict[str, int]]:
    """Subtract each credential's pre-phase counts."""
    return {
        name: dict(Counter(end[name]) - Counter(start[name])) for name in ('scrypt', 'verified')
    }


def _distribution(values: list[float]) -> dict[str, float]:
    """Return seconds with median and nearest-rank upper quantiles."""
    if not values:
        return {}
    ordered = sorted(values)
    return {
        'median': ordered[math.ceil(len(ordered) / 2) - 1],
        'p95': ordered[math.ceil(0.95 * len(ordered)) - 1],
        'p99': ordered[math.ceil(0.99 * len(ordered)) - 1],
        'max': ordered[-1],
    }


def _arrivals(e: _Evidence) -> tuple[bool, dict[str, object]]:
    """Compare the first invocation and first transport start with each scheduled arrival."""
    path = e.run.directory / 'dispatch.json'
    host_wall_time = float(json.loads(path.read_text())) if path.exists() else None
    marker = e.run.directory / 'fleet-release.json'
    fleet: dict[str, float] = json.loads(marker.read_text()) if marker.exists() else {}
    epoch = fleet.get('monotonic')
    shard_lags: dict[int, float] = {}
    shard_reactions: dict[int, float] = {}
    cross_clock: dict[int, float] = {}
    offsets: dict[int, float] = {}
    lags: dict[int, float] = {}
    invocation: dict[int, float] = {}
    minute = e.run.variant == 'minute'
    tolerance = 1.0
    for shard in range(0, e.run.machines, SHARD_SIZE):
        marker = e.run.directory / f'release-{shard}.json'
        local: dict[str, float] = json.loads(marker.read_text()) if marker.exists() else {}
        if epoch is None:
            continue
        if 'monotonic' in local:
            shard_lags[shard] = local['monotonic'] - epoch
        if host_wall_time is not None and 'wall_time' in local:
            cross_clock[shard] = local['wall_time'] - host_wall_time
        for machine in range(shard, min(shard + SHARD_SIZE, e.run.machines)):
            calls = e.by_machine.get(machine)
            if not calls or not calls[0]['attempts']:
                continue
            first = calls[0]
            called = first.get('start_monotonic')
            sent = first['attempts'][0].get('start_monotonic')
            if called is None or sent is None:
                continue
            planned = machine * _ARRIVAL_MINUTE / e.run.machines if minute else 0
            invocation[machine] = called - epoch - planned
            offsets[machine] = sent - epoch
            if 'monotonic' in local:
                shard_reactions[machine] = sent - local['monotonic']
            lags[machine] = offsets[machine] - planned
    observed = set(offsets) == set(range(e.run.machines)) and all(
        0 <= invocation[i] <= lag <= tolerance and (not minute or offsets[i] < _ARRIVAL_MINUTE)
        for i, lag in lags.items()
    )
    return observed, {
        'cross_clock_observed_minus_host_seconds_by_shard': cross_clock,
        'fleet_release_monotonic': epoch,
        'cross_clock_fleet_observed_minus_host_seconds': (
            fleet['wall_time'] - host_wall_time
            if 'wall_time' in fleet and host_wall_time is not None
            else None
        ),
        'shard_observation_after_fleet_release_seconds': shard_lags,
        'first_attempt_after_shard_observation_seconds': shard_reactions,
        'allowed_lag_seconds': tolerance,
        'first_attempt_offset_seconds': offsets,
        'first_invocation_lag_seconds': _distribution(list(invocation.values())),
        'first_attempt_lag_seconds': _distribution(list(lags.values())),
        'arrival_skew_seconds': max(offsets.values()) - min(offsets.values()) if offsets else None,
    }


def _caller_summary(calls: list[_Call]) -> dict[str, object]:
    """Aggregate caller latency separately from actual transport work and retries."""
    attempts: Counter[int] = Counter()
    retries: Counter[int] = Counter()
    statuses: Counter[str] = Counter()
    errors: Counter[str] = Counter()
    successes = 0
    for call in calls:
        requests = call['attempts']
        attempts[call['machine']] += len(requests)
        retries[call['machine']] += max(len(requests) - 1, 0)
        statuses.update(str(a.get('status', a.get('error'))) for a in requests)
        if 'generation' in call:
            successes += 1
        else:
            errors[call.get('error', 'unknown error')] += 1
    return {
        'calls': len(calls),
        'successes': successes,
        'success_rate': successes / len(calls) if calls else None,
        'failed_calls': len(calls) - successes,
        'acquisition_seconds': _distribution([c['seconds'] for c in calls if 'generation' in c]),
        'queue_wait_seconds': _distribution(
            [c['loadgen_queue_seconds'] for c in calls if 'loadgen_queue_seconds' in c]
        ),
        'dispatch_to_result_seconds': _distribution(
            [c['dispatch_to_result_seconds'] for c in calls if 'dispatch_to_result_seconds' in c]
        ),
        'completions_after_max_wait': sum(c['seconds'] > MAX_WAIT for c in calls),
        'attempt_start_offset_seconds': _distribution(
            [a['start'] - c['start'] for c in calls for a in c['attempts']]
        ),
        'recorder_tail_seconds': _distribution(
            [c['recorder_tail_seconds'] for c in calls if 'recorder_tail_seconds' in c]
        ),
        'attempts_per_machine': dict(attempts),
        'retries_per_machine': dict(retries),
        'attempt_outcomes': statuses,
        'terminal_errors': errors,
        'zero_attempt_calls': sum(not c['attempts'] for c in calls),
    }


def _fault_interval(
    e: _Evidence,
    obs: Observation,
    failure: Failure,
    owner: str,
    interval: tuple[float, float],
) -> str:
    """Compare monotonic enclosures conservatively at both edges of the fault."""
    lower, upper = interval
    start, finish = obs.failure_bounds(failure.event)
    margin = sum(
        float(str(e.clocks[role].get('sampling_uncertainty_seconds', 0)))
        for role in sorted({owner, obs.caller})
    )
    if start - margin > upper or finish + margin < lower:
        return 'collateral_fault'
    if lower <= start - margin <= finish + margin <= upper and math.isfinite(finish):
        return 'intended_fault'
    return 'unresolved_fault'


def _fault_disposition(
    e: _Evidence,
    obs: Observation,
    restart: dict[str, float],
    implicated: dict[str, str],
    failure: Failure,
) -> str:
    """Exempt only a proven failure on the affected hop wholly within the fault."""
    cause, backend, event = failure
    unknown = cause in {'unclassified', 'client_transport_unknown'}
    if e.run.scenario == 'process-restart':
        affected = f'127.0.0.1:{DIRECT_PORT}'
        proven = event is not None and backend == affected
        possible = unknown and (not backend or backend == affected)
        owner = 'deployment'
        lower, upper = restart.get('started_monotonic'), restart.get('finished_monotonic')
    elif e.run.scenario in {'sg-outage', 'rejected-script-key'}:
        expected = (
            'sg_rejected' if e.run.scenario == 'rejected-script-key' else 'upstream_unavailable'
        )
        handler = obs.direct_handler
        affected_hop = handler in implicated if handler else backend in implicated.values()
        proven = cause == expected and affected_hop
        possible = (unknown or cause == expected) and (affected_hop or not (handler or backend))
        owner = e.fixture_role
        lower = e.active_monotonic
        upper = math.inf if e.run.scenario == 'rejected-script-key' else e.outage_end
    else:
        return 'collateral_fault'
    if not (possible or proven):
        return 'collateral_fault'
    if lower is None or upper is None or not e.shared_clock(obs.caller, owner):
        return 'unresolved_fault'
    location = _fault_interval(e, obs, failure, owner, (lower, upper))
    return 'unresolved_fault' if location == 'intended_fault' and not proven else location


def _errors(e: _Evidence) -> dict[str, object]:
    """Aggregate the same per-attempt causes and fault dispositions for every view."""
    trace = e.trace
    causes: Counter[str] = Counter()
    client: Counter[str] = Counter()
    dispositions: defaultdict[str, Counter[str]] = defaultdict(Counter)
    populations: defaultdict[str, Counter[str]] = defaultdict(Counter)
    original: defaultdict[str, Counter[str]] = defaultdict(Counter)
    transports: Counter[str] = Counter()
    restart_path = e.run.directory / 'restart.json'
    restart: dict[str, float] = (
        json.loads(restart_path.read_text()) if restart_path.exists() else {}
    )
    implicated = {
        m['process']: f'127.0.0.1:{DIRECT_PORT + int(m["process"].split("-")[1])}'
        for m in e.mints
        if m['outcome'] in {'refused', 'unavailable'}
    }
    for obs in trace.observations:
        attempt = obs.attempt
        failures = list(obs.failures())
        if not failures:
            continue
        outcome = str(attempt.get('status', attempt.get('error', 'unknown')))
        client[outcome] += 1
        populations[obs.phase][outcome] += 1
        for failure in failures:
            disposition = _fault_disposition(e, obs, restart, implicated, failure)
            cause = failure.cause
            causes[cause] += 1
            dispositions[disposition][cause] += 1
            original[obs.phase][cause] += 1
            if 'error' in attempt and failure.event is obs.event:
                transports[disposition] += 1
    return {
        'original_causes': causes,
        'upstream_failover_status_chains': Counter(
            receipt['route'].status_chain
            for receipt in trace.logs
            if receipt['route'].status_chain
        ),
        'gateway_events': Counter(event.cause for event in trace.events),
        'unassigned_gateway_events': Counter(event.cause for event in trace.unassigned),
        'client_observations': client,
        'intended_fault': dispositions['intended_fault'],
        'unresolved_fault': dispositions['unresolved_fault'],
        'collateral_fault': dispositions['collateral_fault'],
        'other_causes': causes - dispositions['intended_fault'],
        'original_causes_by_population': original,
        'client_observations_by_population': populations,
        'transport_errors': transports.total(),
        'collateral_transport_errors': transports['collateral_fault'],
        'unresolved_transport_errors': transports['unresolved_fault'],
    }


def _fleet_connections(e: _Evidence) -> tuple[dict[str, Counter[str]], int]:
    """Count the first socket per machine, later calls on it, and transport retries."""
    groups: dict[str, Counter[str]] = {
        name: Counter() for name in ('machine_first', 'subsequent_call_first', 'retry')
    }
    full = 0
    for machine, calls in e.by_machine.items():
        wire_calls = (call for call in calls if call['attempts'])
        for n, call in enumerate(wire_calls):
            for i, attempt in enumerate(call['attempts']):
                group = 'retry' if i else 'subsequent_call_first' if n else 'machine_first'
                kind = attempt.get('connection', 'unknown')
                groups[group][kind] += 1
                if group == 'machine_first' and kind == 'new' and 0 <= machine < e.run.machines:
                    reused = attempt.get('tls_session_reused')
                    if reused is None:
                        obs = e.trace.unique(attempt.get('attempt_id', ''))
                        receipt = obs.receipt if obs else None
                        full += bool(
                            receipt
                            and receipt.get('ssl_session_reused') == '.'
                            and receipt.get('connection_requests') == '1'
                        )
                    else:
                        full += not reused
    return groups, full


def _http_success(call: _Call) -> bool:
    """Require a completed successful HTTP exchange within the public invocation."""
    if not call['attempts']:
        return False
    last = call['attempts'][-1]
    return (
        last.get('status') == HTTPStatus.OK
        and call['start'] <= last['start'] <= last['finish'] <= call['finish']
    )


def _fault(e: _Evidence) -> dict[str, bool]:
    """Require the actual upstream fault and its effect on individual calls."""
    limits = IssuerLimits()
    if e.run.scenario == 'rejected-script-key':
        refused = bool(e.mints) and all(m['outcome'] == 'refused' for m in e.mints)
        first = min((m['finished'] for m in e.mints), default=math.inf)
        stopped = (
            refused
            and set(e.by_machine) == set(range(e.run.machines))
            and len(e.measure) == e.run.machines
            and all(
                'error' in c
                and c['start'] >= e.activated
                and c['attempts']
                and c['attempts'][-1].get('status') == HTTPStatus.BAD_GATEWAY
                and c['attempts'][-1].get('code') == 'sg_rejected'
                and first <= c['attempts'][-1]['finish']
                and 0 <= c['finish'] - c['attempts'][-1]['finish'] <= 1.0
                and sum(a.get('code') == 'sg_rejected' for a in c['attempts']) == 1
                for c in e.measure
            )
        )
        return {
            'every_machine_stopped_at_sg_rejected': stopped,
            'sg_attempts_bounded_by_refusal_interval': refused
            and e.spacing(limits.refusal_interval),
        }
    marker = e.run.directory / 'restart.json'
    restarted: dict[str, float] = json.loads(marker.read_text()) if marker.exists() else {}
    if e.clock_offset is not None and 'finished_monotonic' in restarted:
        restarted['started'] = e.clock_offset + restarted['started_monotonic']
        restarted['finished'] = e.clock_offset + restarted['finished_monotonic']
    fresh = {
        m.get('generation')
        for m in e.mints
        if m['process'] == 'broker-0-1' and m['outcome'] == 'minted'
    }
    return {
        'every_machine_received_tokens': e.complete(),
        'broker_restarted_mid_burst': bool(
            restarted
            and e.shared_clock('fleet')
            and not e.missing
            and any(
                c['start'] <= restarted['started'] <= restarted['finished'] <= c['finish']
                and any(a['start'] <= restarted['started'] <= a['finish'] for a in c['attempts'])
                and c.get('generation') in fresh
                and _http_success(c)
                for c in e.measure
            )
        ),
    }


def _mint_bound(group: list[_Mint]) -> bool:
    """Require a successful prime and one REST mint at most per cache lifetime."""
    if not group or any(m['outcome'] != 'minted' for m in group):
        return False
    if group[0]['token_type'] == _SESSION:
        return len(group) == 1
    return all(
        'started_monotonic' in b
        and 'cache_started_monotonic' in a
        and b['started_monotonic'] >= a['cache_started_monotonic'] + REST_CACHE_SECONDS
        for a, b in pairwise(group)
    )


def _mint_key(mint: _Mint) -> str:
    """Identify the upstream request by its process and configured script scope."""
    scope = mint['scope']
    client = scope.split('-')[1] if scope.startswith('scope-') else '1'
    return '/'.join((mint['process'], f'farm-{client}', scope, mint['token_type']))


def _occupied_cause(
    event: dict[str, object],
    due: float,
    e: _Evidence,
) -> str:
    """Attribute occupancy only during a traced retry sleep or a proven transport stage."""
    attempts = _slot_attempts(event)
    for start, end, index in cast('list[tuple[float, float, int]]', event.get('retry_sleeps', [])):
        if start <= due < end and 0 <= index < len(attempts):
            attempt = attempts[index]
            obs = e.trace.unique(attempt.get('attempt_id', ''))
            receipt = obs.receipt if obs else None
            if (
                receipt
                and receipt['status'] == attempt.get('status')
                and receipt['status'] in {429, 503}
            ):
                return 'retry_sleep_after_refusal'
    for attempt in attempts:
        if (
            attempt.get('start_monotonic', math.inf)
            <= due
            < attempt.get('finish_monotonic', -math.inf)
        ):
            obs = e.trace.unique(attempt.get('attempt_id', ''))
            if (
                obs
                and e.shared_clock('stream')
                and any(
                    float(str(h.get('accepted', math.inf)))
                    <= due
                    < float(str(h.get('finished', -math.inf)))
                    for h in obs.hops
                )
            ):
                return 'broker_service'
            write = cast('dict[str, object]', attempt).get('http_send_entry')
            tls = cast('dict[str, object]', attempt).get('tls_finish')
            if any(isinstance(t, (float, int)) and due < t for t in (write, tls)):
                return 'before_nginx'
    return 'unknown'


def _one_source(peers: set[object]) -> bool:
    """Require one observed IP address for the entire stream."""
    if len(peers) != 1:
        return False
    peer = next(iter(peers))
    if not isinstance(peer, str):
        return False
    try:
        ip_address(peer)
    except ValueError:
        return False
    return True


def _negative_route(e: _Evidence, proxy_count: int) -> tuple[bool, bool, dict[str, object]]:
    """Reconcile each proxied negative ID or every direct broker accept against dispatches."""
    trace = e.trace
    dispatches = [obs for obs in trace.observations if obs.phase == 'negative']
    records = [
        obs.receipts[0]
        for obs in dispatches
        if len(obs.receipts) == 1
        and obs.receipts[0]['tag'] not in {'', '-'}
        and obs.receipts[0]['method'] == 'POST'
        and obs.receipts[0]['uri'] == '/v1/token'
    ]
    brokers = list(e.run.directory.glob('final-broker-*.json'))
    receipts = [json.loads(p.read_text()).get('direct_negative_accepts') for p in brokers]
    direct = (
        sum(receipts)
        if len(receipts) == e.run.brokers and all(type(n) is int for n in receipts)
        else None
    )
    forwarded = Counter(
        r['route'].terminal.status for r in records if r['route'].terminal.header not in {'-', ''}
    )
    limited = sum(
        r['route'].local_refusal and r['status'] == HTTPStatus.TOO_MANY_REQUESTS for r in records
    )
    complete = bool(dispatches) and all(trace.unique(obs.identifier) is obs for obs in dispatches)
    if e.run.variant == 'one-source':
        route = (
            complete
            and direct == 0
            and len(records) == proxy_count == len(dispatches)
            and _one_source({r['peer'] for r in records})
        )
        allowed = all(
            obs.receipt is not None
            and (
                obs.attempt.get('status')
                in {HTTPStatus.UNAUTHORIZED, HTTPStatus.SERVICE_UNAVAILABLE}
                or (
                    obs.attempt.get('status') == HTTPStatus.TOO_MANY_REQUESTS
                    and obs.receipt['route'].local_refusal
                )
            )
            for obs in dispatches
        )
    else:
        route = complete and proxy_count == 0 and direct == len(dispatches)
        forwarded = Counter(
            str(obs.attempt['status']) for obs in dispatches if 'status' in obs.attempt
        )
        allowed = all(
            obs.attempt.get('status') in {HTTPStatus.UNAUTHORIZED, HTTPStatus.SERVICE_UNAVAILABLE}
            for obs in dispatches
        )
    return (
        route,
        bool(dispatches) and allowed,
        {
            'broker_responses': forwarded,
            'proxy_throttled_429': limited,
            'direct_broker_accepts': direct,
            'proxy_fixture_receipts': proxy_count,
            'matched_proxy_fixture_receipts': len(records),
        },
    )


def _outage(e: _Evidence) -> tuple[dict[str, bool], dict[str, object]]:
    """Classify each retry during the confirmed outage and identify its recovery result."""
    recovery = e.activated + 30
    if e.outage_end and e.active_monotonic is not None:
        recovery = e.activated + (e.outage_end - e.active_monotonic)
    failures = [m for m in e.mints if m['outcome'] == 'unavailable' and m['started'] < recovery]
    successes = {
        m['generation']: m['finished']
        for m in e.mints
        if m['outcome'] == 'minted' and 'generation' in m and m['started'] >= recovery
    }
    observed = bool(failures and successes) and all(
        m['outcome'] == ('unavailable' if m['started'] < recovery else 'minted') for m in e.mints
    )
    first_failure = min((m['finished'] for m in failures), default=math.inf)
    observed_refusal = False
    exposure: defaultdict[int, Counter[str]] = defaultdict(Counter)
    client_outcomes: defaultdict[int, Counter[str]] = defaultdict(Counter)
    shared = e.shared_clock('fleet', e.fixture_role)
    retried = e.complete() and observed and shared
    for c in e.measure:
        seen = exposure[c['machine']]
        client = client_outcomes[c['machine']]
        if not shared or not c['attempts']:
            retried = False
            continue
        last = c['attempts'][-1]
        for a in c['attempts'][:-1]:
            if not (e.activated <= a['start'] < recovery and a['finish'] <= last['start']):
                continue
            obs = e.trace.unique(a.get('attempt_id', ''))
            cause = obs.cause if obs else 'unclassified'
            if cause == 'upstream_unavailable':
                observed_refusal |= first_failure <= a['finish']
                retried &= a.get('status') == HTTPStatus.SERVICE_UNAVAILABLE
            category = {
                'upstream_unavailable': 'broker_upstream_unavailable',
                'local_throttle_with_retry_after': 'proxy_throttled',
                'local_throttle_without_retry_after': 'proxy_throttled',
            }.get(cause, cause)
            seen[category] += 1
            client[str(a.get('error') or a.get('code') or a.get('status'))] += 1
        minted = successes.get(c['generation']) if 'generation' in c else None
        retried &= (
            bool(seen) and _http_success(c) and minted is not None and minted <= last['finish']
        )
    return {
        'every_machine_recovered': e.complete()
        and observed
        and all(c.get('generation') in successes for c in e.measure),
        'sg_unavailable_then_recovered': observed,
        'attempts_bounded_by_failure_interval': observed
        and e.spacing(IssuerLimits().failure_interval),
        'clients_observed_retry': retried and observed_refusal,
    }, {
        'outage_exposure_by_machine': exposure,
        'outage_client_outcomes_by_machine': client_outcomes,
    }


def _phase_clock(call: _Call, offset: float) -> None:
    """Compare phases on elapsed time anchored once to the activation epoch."""
    if 'start_monotonic' in call and 'finish_monotonic' in call:
        call['start'] = offset + call['start_monotonic']
        call['finish'] = offset + call['finish_monotonic']
    for attempt in call['attempts']:
        if 'start_monotonic' in attempt and 'finish_monotonic' in attempt:
            attempt['start'] = offset + attempt['start_monotonic']
            attempt['finish'] = offset + attempt['finish_monotonic']


def _align_phase_events(
    calls: list[_Call], mints: list[_Mint], offset: float | None, scenario: str
) -> None:
    """Use the deployment epoch when reading the VM clocks; retain raw logs on disk."""
    if offset is None:
        return
    if scenario != 'tls-smoke':
        for call in calls:
            _phase_clock(call, offset)
    for mint in mints:
        if 'started_monotonic' in mint and 'finished_monotonic' in mint:
            mint['started'] = offset + mint['started_monotonic']
            mint['finished'] = offset + mint['finished_monotonic']


def _pressure_delta(directory: Path) -> dict[str, object]:
    """Report measured namespace TCP and deployment cgroup counter changes."""
    before = directory / 'pressure-baseline.json'
    after = directory / 'pressure-final.json'
    start: dict[str, int] = json.loads(before.read_text()) if before.exists() else {}
    end: dict[str, int] = json.loads(after.read_text()) if after.exists() else {}
    return {
        'tcp_scope': 'shared deployment network namespace, all listeners',
        'cpu_scope': 'deployment cgroup',
        'baseline': start,
        'final': end,
        'delta': {key: value - start[key] for key, value in end.items() if key in start},
    }


def _primary(e: _Evidence) -> dict[str, object]:
    """Report successful calls and complete machines with their own denominators."""
    successes = [c for c in e.measure if 'generation' in c]
    whole: list[float] = []
    kinds = {'session', 'rest'} if e.run.scenario in {'cold-burst', 'warm-burst'} else {'session'}
    scheduled = e.run.machines * len(kinds)
    missing = scheduled
    extra = 0
    repeated = e.run.scenario in {'synchronized-renewal', 'rejected-tokens'}
    for machine, calls in e.by_machine.items():
        observed = {c['token_type'] for c in calls}
        covered = len(kinds & observed) if 0 <= machine < e.run.machines else 0
        missing -= covered
        if not repeated or not kinds.issuperset(observed) or not covered:
            extra += len(calls) - covered
        if (
            covered == len(kinds)
            and observed == kinds
            and (repeated or len(calls) == covered)
            and all('generation' in c and 'start_monotonic' in c for c in calls)
        ):
            starts = [c.get('start_monotonic', 0) for c in calls]
            whole.append(
                max(t + c['seconds'] for t, c in zip(starts, calls, strict=True)) - min(starts)
            )
    return {
        'scheduled_machines': e.run.machines,
        'scheduled_calls': scheduled,
        'missing_calls': missing,
        'unexpected_calls': extra,
        'attempted_calls': len(e.measure),
        'successful_calls': len(successes),
        'failed_calls': len(e.measure) - len(successes),
        'call_seconds': _distribution([c['seconds'] for c in successes]),
        'attempted_machines': len(e.by_machine),
        'successful_machines': len(whole),
        'whole_machine_seconds': _distribution(whole),
    }


def _assessment(e: _Evidence, checks: dict[str, bool]) -> dict[str, object]:
    """Classify failed workload predicates separately from service outcomes."""
    predicates = {
        'deployment_configuration_observed',
        'fresh_tls_first_attempt_per_machine',
        'every_machine_primed',
        'one_initial_generation_per_process',
        'both_brokers_held_rejected_generations',
        'arrival_schedule_observed',
        'measured_slow_cold_mint',
        'measured_control_mint',
        'warm_stream_schedule_observed',
        'warm_primed_on_all_processes',
        'required_snapshots_present',
        'valid_proxy_source_distribution',
        'successful_priming',
        'scheduled_requests_dispatched',
        'proxy_path_observed',
        'invalid_traffic_spanned_valid_acquisitions',
    }
    workload = {k: v for k, v in checks.items() if k in predicates}
    clocks = e.clocks
    if e.run.scenario != 'tls-smoke':
        needed = {'fleet'}
        if e.run.scenario == 'bad-secrets':
            needed.add('negative')
        if e.run.scenario in {'slow-control', 'slow-sg'}:
            needed.update(('stream', 'probe'))
        if not e.run.direct:
            needed.add('observer')
        workload['shared_monotonic_clock'] = e.shared_clock(*needed)
        masks = {
            role: set(cast('list[int]', record.get('cpus', []))) for role, record in clocks.items()
        }
        deployment = masks.get('deployment', set())
        stream = masks.get('stream', set())
        proxy_mask = e.run.directory / 'proxy-affinity.json'
        workload['disjoint_cpu_placement'] = (
            (
                e.run.direct
                or (proxy_mask.exists() and set(json.loads(proxy_mask.read_text())) == deployment)
            )
            and len(deployment) == _DEPLOYMENT_CPUS
            and all(masks.get(p) == deployment for p in e.processes)
            and all(bool(masks.get(p)) and deployment.isdisjoint(masks[p]) for p in needed)
            and (
                'stream' not in needed
                or (
                    len(stream) == 1
                    and all(stream.isdisjoint(masks.get(p, set())) for p in needed - {'stream'})
                )
            )
        )
    if e.run.scenario == 'sg-outage':
        workload['full_outage_interval'] = (
            e.active_monotonic is not None
            and e.outage_end is not None
            and e.outage_end - e.active_monotonic >= _OUTAGE_SECONDS
            and any(m['outcome'] == 'unavailable' for m in e.mints)
            and any(m.get('started_monotonic', -math.inf) >= e.outage_end for m in e.mints)
        )
    service = {k: v for k, v in checks.items() if k not in predicates}
    primary = _primary(e)
    errors = _errors(e)
    collateral_gateway = cast('Counter[str]', errors['gateway_events']) - cast(
        'Counter[str]', errors['intended_fault']
    )
    if e.run.scenario != 'generator-calibration':
        service['no_avoidable_transport_or_gateway_errors'] = not (
            errors['collateral_transport_errors']
            or errors['unresolved_transport_errors']
            or collateral_gateway
        )
    targets: tuple[int, int] | None = None
    minute = e.run.variant == 'minute'
    if e.run.scenario in {'cold-burst', 'warm-burst'}:
        targets = (1, 5) if minute else (15, 30)
    if e.run.scenario == 'slow-sg':
        targets = (6, 10) if minute else (20, 35)
    if targets:
        seconds = cast('dict[str, float]', primary['call_seconds'])
        service['primary_latency_target'] = primary['failed_calls'] == primary[
            'missing_calls'
        ] == primary['unexpected_calls'] == 0 and (
            seconds.get('p99', math.inf) <= targets[0]
            and seconds.get('max', math.inf) <= targets[1]
        )
    invalid = [name for name, valid in workload.items() if not valid]
    return {
        'workload_predicates': workload,
        'invalid_reasons': invalid,
        'service_results': service,
        'verdict': 'inconclusive' if invalid else 'pass' if all(service.values()) else 'miss',
        'primary_latency': primary,
        'target_seconds_p99_max': targets,
        'errors': errors,
        'kernel_and_cgroup': _pressure_delta(e.run.directory),
        'clock_domains': clocks,
    }


def _primed_calls(e: _Evidence) -> Iterator[tuple[_Call, str, list[_Mint]]]:
    """Join each preparation result to its actual proxy route and token generation."""
    by_address = {f'127.0.0.1:{DIRECT_PORT + i}': f'broker-{i}-0' for i in range(e.run.brokers)}
    for call in e.calls:
        if (
            call['phase'] not in {'prepare', 'prime-rest'}
            or not _http_success(call)
            or call['finish'] > e.activated
        ):
            continue
        obs = e.trace.unique(call['attempts'][-1].get('attempt_id', ''))
        receipt = obs.receipt if obs else None
        if (
            not receipt
            or receipt['status'] != HTTPStatus.OK
            or receipt['peer'] != machine_address(call['machine'])
        ):
            continue
        process = by_address.get(receipt['route'].terminal.backend)
        client = 'farm-1' if call['scope'] == 'warm' else 'farm-0'
        key = f'{process}/{client}/{call["scope"]}/{call["token_type"]}'
        group = e.priming.get(key)
        if (
            group
            and 'generation' in call
            and any(
                mint.get('generation') == call.get('generation')
                and mint['outcome'] == 'minted'
                and mint['finished'] <= call['finish']
                for mint in group
            )
        ):
            yield call, key, group


def _connection_evidence(e: _Evidence) -> tuple[dict[str, bool], dict[str, object]]:
    """Prove the warm cache and the independent fresh connection of each measured machine."""
    run = e.run
    checks: dict[str, bool] = {}
    detail: dict[str, object] = {}
    connections, full = _fleet_connections(e)
    detail['fleet_connections'] = {**connections, 'full_tls_first': full}
    if run.direct or run.scenario not in {'warm-burst', 'synchronized-renewal', 'rejected-tokens'}:
        return checks, detail
    verified: defaultdict[int, dict[str, int]] = defaultdict(dict)
    if e.shared_clock('fleet', e.fixture_role):
        for call, _, _ in _primed_calls(e):
            if call['phase'] == 'prepare' and 'generation' in call:
                verified[call['machine']][call['token_type']] = call['generation']
    detail['verified_priming_by_machine'] = dict(verified)
    if run.scenario == 'warm-burst':
        checks['every_machine_primed'] = all(
            set(verified.get(i, {})) == {'session', REST} for i in range(run.machines)
        )
        checks['fresh_tls_first_attempt_per_machine'] = full == run.machines and connections[
            'machine_first'
        ] == {'new': run.machines}
    return checks, detail


def _prime_receipts(e: _Evidence) -> dict[str, int]:
    """Prove the latest primed generation of each serving process and key over TLS."""
    role = 'probe' if e.run.scenario in {'slow-sg', 'slow-control'} else 'fleet'
    if not e.shared_clock(role, e.fixture_role):
        return {}
    marker = e.run.directory / ('probe-ready.json' if role == 'probe' else 'rest-primed.json')
    if marker.exists():
        preparation: object = json.loads(marker.read_text())
        if isinstance(preparation, dict) and cast('dict[str,object]', preparation).get(
            'incomplete'
        ):
            return {}
    proven: dict[str, int] = {}
    for call, key, group in _primed_calls(e):
        if (
            e.run.fresh_rest_window
            and call['token_type'] == REST
            and call['phase'] != 'prime-rest'
        ):
            continue
        if group and 'generation' in call and call['generation'] == group[-1].get('generation'):
            proven[key] = call['generation']
    return proven


def _proxy_coverage(e: _Evidence) -> tuple[bool, dict[str, object]]:
    """Join each measured transport attempt to its nginx receipt by phase, peer and ID."""
    run = e.run
    required = {'measure': {machine_address(i) for i in range(run.machines)}}
    if run.scenario == 'rotation':
        required['warm'] = required['measure']
    if run.scenario in {'slow-sg', 'slow-control'}:
        required['probe'] = {machine_address(run.machines)}
    by_phase: defaultdict[str, Counter[str]] = defaultdict(Counter)
    observed: Counter[tuple[str, str, str]] = Counter()
    statuses: Counter[int] = Counter()
    invalid: Counter[str] = Counter()
    for r in e.trace.logs:
        phase = r.get('phase', 'unknown')
        if phase in required:
            observed[phase, r['peer'], r.get('attempt_id', '')] += 1
            statuses[r['status']] += 1
        if r['tag'] not in {'', '-'}:
            invalid[r['peer']] += 1
        else:
            by_phase[phase][r['peer']] += 1
    valid = by_phase['measure']
    host = run.scenario == 'tls-smoke' and len(valid) == 1
    if host:
        required['measure'] = set(valid)
    expected: Counter[tuple[str, str, str]] = Counter()
    responses: Counter[tuple[str, str, str]] = Counter()
    failures: dict[tuple[str, str, str], str] = {}
    coverage = [obs for obs in e.trace.observations if obs.phase in required]
    for obs in coverage:
        attempt = obs.attempt
        key = (obs.phase, obs.peer, obs.identifier)
        expected[key] += 1
        if 'status' in attempt:
            responses[key] += 1
        elif 'error' in attempt:
            failures[key] = attempt['error']
    complete = (
        all(
            {peer for p, peer, _ in observed if p == phase} == peers
            for phase, peers in required.items()
        )
        and bool(expected)
        and all(not obs.receipt_fault for obs in coverage)
        and responses.total() + len(failures) == expected.total()
        and responses <= observed <= expected
        and all(
            attempt_id not in {'', '-'} and n == 1 for (_, _, attempt_id), n in expected.items()
        )
    )
    return complete, {
        'by_phase': by_phase,
        'measured_attempt_count': expected.total(),
        'measured_response_count': responses.total(),
        'transport_failures': Counter(failures.values()),
        'transport_failures_without_receipt': Counter(
            error for key, error in failures.items() if key not in observed
        ),
        'proxy_response_count': observed.total(),
        'proxy_statuses': statuses,
        'unmatched_attempts': (responses - observed).total(),
        'unmatched_receipts': (observed - expected).total(),
        'valid_distinct': len(valid),
        'valid_requests': valid,
        'invalid_distinct': len(invalid),
        'invalid_requests': invalid,
    }


def _recovery(e: _Evidence) -> tuple[dict[str, bool], dict[str, object]]:
    """Trace each machine's reports from a rejected issued session to a verified successor."""
    old, new = _account_generations(e)
    expected = {f'{name}/farm-0/scope-0-0/session' for name in e.processes}
    primed = not e.missing and set(old) == expected == set(e.priming) and e.fleet('prepare')
    replaced = bool(new) and set(new) == set(e.by_key) <= expected
    initial = {c['machine']: c.get('generation') for c in e.calls if c['phase'] == 'prepare'}
    primed &= set(initial.values()) == set(old.values())
    groups: dict[str, object] = {}
    recovered: dict[int, int] = {}
    for group, parity in [('library', 0), ('get-token', 1)]:
        machines = range(parity, e.run.machines, 2)
        reports: dict[int, int | None] = {}
        for i in machines:
            calls = e.by_machine.get(i, [])
            previous = initial.get(i)
            for call in calls:
                if (
                    previous not in old.values()
                    or call.get('reported_generation') != previous
                    or call['group'] != group
                    or not _http_success(call)
                ):
                    break
                previous = call.get('generation')
            else:
                if calls and calls[-1].get('accepted_by_sg') and previous in new.values():
                    recovered[i] = len(calls)
            reports[i] = recovered.get(i)
        groups[group] = {
            'outcomes': _caller_summary([c for c in e.measure if c['group'] == group]),
            'reports_to_fresh': reports,
        }
    fresh = primed and replaced and e.complete() and set(recovered) == set(range(e.run.machines))
    return {
        'both_brokers_held_rejected_generations': primed,
        'every_machine_received_fresh_token': fresh,
        'within_three_reports': fresh and max(recovered.values(), default=0) <= _REPORT_BOUND,
        'one_mint_per_key_process_rejected_generation': primed and replaced,
    }, {
        'recovery_by_group': groups,
        'cli_admission': {
            'machine_slots_per_shard': e.run.shard_size,
            'concurrent_cli_invocations_per_shard': CLI_SLOTS_PER_SHARD,
            'timing': (
                'The first report includes fleet staging in queue and dispatch-to-result time. '
                'CLI acquisition starts at admission and ends at the child result marker. '
                'Its worker waits for recorder exit before launching another child.'
            ),
        },
        'role_memory': {
            path.stem.removeprefix('memory-'): json.loads(path.read_text())
            for path in sorted(e.run.directory.glob('memory-*.json'))
        },
        'rejected_generation_by_process_key': old,
        'replacement_generation_by_process_key': new,
        'account_probes': rows(e.run.directory / 'probes.jsonl'),
        'issue_audit_by_phase_process_key_generation_outcome': {
            '/'.join((p, k, str(g), o)): n for (p, k, g, o), n in e.issues.items()
        },
    }


def _renewal_mints(
    groups: dict[str, list[_Mint]], processes: set[str], *, require_all: bool
) -> tuple[dict[int, _Mint], bool]:
    """Require one identifiable session mint for the renewal key on every backend."""
    keys = {f'{process}/farm-0/scope-0-0/session' for process in processes}
    mints = {
        mint['generation']: mint
        for group in groups.values()
        for mint in group
        if mint.get('outcome') == 'minted' and 'generation' in mint
    }
    covered = set(groups) == keys if require_all else set(groups) <= keys
    return mints, covered and all(len(group) == 1 for group in groups.values()) and len(
        mints
    ) == len(groups)


def _renewal_route(e: _Evidence, call: _Call, mint: _Mint) -> bool:
    """Prove which backend served this generation on the successful transport."""
    if mint['process'] not in e.processes or not _http_success(call):
        return False
    obs = e.trace.unique(call['attempts'][-1].get('attempt_id', ''))
    if obs is None or mint['finished'] > obs.attempt['finish']:
        return False
    if obs.direct:
        return obs.direct_handler == mint['process']
    port = DIRECT_PORT + int(mint['process'].split('-')[1])
    return bool(
        obs.receipt
        and obs.receipt['route'].terminal.status == '200'
        and obs.receipt['route'].terminal.backend == f'127.0.0.1:{port}'
    )


def _initial_sessions(
    e: _Evidence, before: dict[int, _Mint], fleet: set[int]
) -> tuple[dict[int, int], dict[int, float], bool]:
    """Record each machine's initial session and the expiry shared by its backend."""
    initial: dict[int, int] = {}
    epochs: dict[int, float] = {}
    prime_calls = [c for c in e.calls if c['phase'] == 'prepare']
    primed = len(prime_calls) == len(fleet)
    for call in prime_calls:
        generation = call.get('generation')
        expiry = call.get('expires_at')
        if (
            generation is None
            or expiry is None
            or generation not in before
            or call['scope'] != 'scope-0-0'
            or call['token_type'] != _SESSION
            or call['finish'] > e.activated
            or not _renewal_route(e, call, before[generation])
        ):
            primed = False
            continue
        primed &= epochs.setdefault(generation, expiry) == expiry
        initial[call['machine']] = generation
    primed &= set(initial) == fleet and set(epochs) == set(before)
    return initial, epochs, primed


def _renewal(e: _Evidence) -> tuple[dict[str, bool], dict[str, object]]:
    """Follow every caller across the independent session caches of its serving processes."""
    before, initial_bounded = _renewal_mints(e.priming, e.processes, require_all=True)
    after, renewed_once = _renewal_mints(e.by_key, e.processes, require_all=False)
    fleet = set(range(e.run.machines))
    initial, epochs, primed = _initial_sessions(e, before, fleet)
    primed &= initial_bounded
    refresh_epoch = {m['process']: epochs[g] for g, m in before.items() if g in epochs}
    renewed_once &= before.keys().isdisjoint(after) and all(
        m['process'] in refresh_epoch
        and m['started'] >= max(e.activated, refresh_epoch[m['process']] - 120)
        for m in after.values()
    )
    mints = before | after
    moves: dict[int, dict[str, object]] = {}
    refreshes: dict[int, float] = {}
    continued = primed and set(e.by_machine) == fleet
    for machine, calls in e.by_machine.items():
        held = initial.get(machine)
        for call in calls:
            generation = call.get('generation')
            expiry = call.get('expires_at')
            if (
                generation is None
                or generation not in mints
                or expiry is None
                or held is None
                or call['token_type'] != _SESSION
                or call['scope'] != 'scope-0-0'
                or call['start'] < e.activated
                or call['finish'] < call['start']
                or 'error' in call
            ):
                continued = False
                continue
            eligible = [
                a['start']
                for a in call['attempts']
                if max(epochs[held] - 120, e.activated, call['start'])
                <= a['start']
                <= call['finish']
            ]
            if eligible:
                refreshes.setdefault(machine, min(eligible))
            if _http_success(call):
                continued &= _renewal_route(e, call, mints[generation])
            elif generation != held:
                continued = False
            continued &= epochs.setdefault(generation, expiry) == expiry
            if generation in after:
                if machine not in moves and eligible and _http_success(call):
                    moves[machine] = {
                        'generation': generation,
                        'process': after[generation]['process'],
                        'time': call['finish'],
                    }
            elif machine in moves:
                continued = False
            held = generation
    return {
        'one_initial_generation_per_process': primed,
        'at_most_one_successor_per_process': renewed_once,
        'each_machine_attempted_refresh': primed and set(refreshes) == fleet,
        'no_machine_lost_its_session': continued,
        'all_moved_to_new_generation': continued and renewed_once and set(moves) == fleet,
    }, {
        'initial_generation_per_machine': initial,
        'common_refresh_epoch': next(iter(refresh_epoch.values()))
        if primed and len(refresh_epoch) == 1
        else None,
        'initial_expiry_by_process': refresh_epoch,
        'successor_expiry_by_process': {m['process']: epochs.get(g) for g, m in after.items()},
        'first_refresh_attempt_per_machine': refreshes,
        'moved_per_machine': moves,
    }


def _resources(directory: Path) -> dict[str, dict[str, float]]:
    """Summarize sampled CPU time, current and peak RSS, threads and connections per PID."""
    resources: dict[str, dict[str, float]] = {}
    for sample in cast('list[_Resources]', rows(directory / 'resources.jsonl')):
        group = resources.setdefault(sample['process'], {})
        group['cpu_seconds'] = sample['cpu_ticks'] / sample['ticks_per_second']
        group['last_rss_kib'] = sample['rss_kib']
        for field in ('peak_rss_kib', 'threads', 'connections'):
            value = sample.get(field)
            if isinstance(value, int):
                group[f'max_{field}'] = max(group.get(f'max_{field}', 0), value)
    return resources


def _rest_windows_cover_release(e: _Evidence) -> bool:
    """Require the last REST generation in each broker cache to be usable at release."""
    marker = e.run.directory / 'fleet-release.json'
    release = json.loads(marker.read_text()).get('monotonic') if marker.exists() else None
    return (
        isinstance(release, (float, int))
        and e.shared_clock('fleet', *e.processes)
        and all(
            (start := group[-1].get('cache_started_monotonic')) is not None
            and start <= release < start + REST_CACHE_SECONDS
            for key, group in e.priming.items()
            if key.endswith('/rest')
        )
    )


def _burst(e: _Evidence) -> dict[str, bool]:
    """Evaluate authentication and mint work against each burst's cache state."""
    scenario = e.run.scenario
    common = {
        'every_machine_received_tokens': e.complete(),
        'arrival_schedule_observed': _arrivals(e)[0],
    }
    evidence = e.complete() and not e.missing
    kinds = {'rest', 'session'} if scenario in {'warm-burst', 'cold-burst'} else {'session'}
    expected = {f'{name}/farm-0/scope-0-0/{kind}' for name in e.processes for kind in kinds}
    if scenario == 'warm-burst':
        primed = (
            e.fleet('prepare')
            and set(_prime_receipts(e)) == expected
            and set(e.priming) == expected
            and _rest_windows_cover_release(e)
            and all(_mint_bound(group) for group in e.priming.values())
        )
        known = set(e.by_key) <= expected
        return {
            **common,
            'successful_priming': primed,
            'no_new_session_mints': evidence
            and primed
            and known
            and all(m['token_type'] == REST for m in e.mints),
            'rest_mints_only_after_cache_expiry': evidence
            and primed
            and known
            and all(
                _mint_bound([*e.priming[key], *group])
                for key, group in e.by_key.items()
                if key.endswith('/rest')
            ),
            'no_new_verifications': evidence and primed and not e.verified and not e.raw,
        }
    if scenario == 'cold-burst':
        return {
            **common,
            'one_verification_per_credential_per_process': evidence
            and len(e.verified) == len(e.processes)
            and all(v == 1 for v in e.verified.values()),
            'mints_within_per_key_cache_lifetimes': evidence
            and set(e.by_key) == expected
            and all(_mint_bound(g) for g in e.by_key.values()),
            'attempts_started_within_max_wait': e.complete()
            and all(
                0 <= a['start'] - c['start'] < MAX_WAIT for c in e.measure for a in c['attempts']
            ),
        }
    if scenario == 'rotation':
        return {
            **common,
            'two_credentials_verified_once': evidence
            and len(e.verified) == 2 * len(e.processes)
            and all(v == 1 for v in e.verified.values()),
            'warm_hits_without_scrypt_or_verification': evidence
            and e.fleet('warm')
            and all(not any(group.values()) for group in e.warm.values()),
            'scrypt_work_includes_second_hash': evidence and e.raw.total() > e.verified.total(),
        }
    observed = set(e.by_key)
    valid_processes = all(m['process'] in e.processes for m in e.mints)
    if scenario == 'many-clients':
        observed = {key.partition('/')[2] for key in e.by_key}
        expected = {
            f'farm-{client}/scope-{client}-{scope}/session'
            for client in range(MANY_CLIENTS)
            for scope in range(SCOPES_PER_CLIENT)
        }
    return {
        **common,
        'each_credential_verified_at_most_once': evidence
        and bool(e.verified)
        and max(e.verified.values()) <= 1,
        'mints_within_per_key_cache_lifetimes': evidence
        and bool(e.by_key)
        and all(_mint_bound(g) for g in e.by_key.values()),
        'workload_coverage': evidence and valid_processes and observed == expected,
    }


def _same_domain(clocks: dict[str, dict[str, object]], *roles: str) -> bool:
    """Compare only participants with a nonempty common domain identifier."""
    domains = {clocks.get(r, {}).get('domain') for r in roles}
    return len(domains) == 1 and all(isinstance(domain, str) and domain for domain in domains)


def _snapshot(path: Path) -> _Counters | None:
    """Require both counter families and the corresponding audit offset."""
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return None
    if type(data) is not dict:
        return None
    fields = cast('dict[str, object]', data)
    if type(fields.get('audit_bytes')) is not int:
        return None
    for family in ('verified', 'scrypt'):
        counters = fields.get(family)
        if not isinstance(counters, dict) or not all(
            type(n) is int and n >= 0 for n in cast('dict[str,object]', counters).values()
        ):
            return None
    return cast('_Counters', data)


def _sources(trace: Reconciliation) -> tuple[Counter[str], Counter[str]]:
    """Count valid and negative requests by peer address."""
    logs = trace.logs
    return (
        Counter(r['peer'] for r in logs if r['tag'] in {'', '-'} and r.get('phase') == 'measure'),
        Counter(r['peer'] for r in logs if r['tag'] not in {'', '-'}),
    )


def _bad_secrets(e: _Evidence) -> tuple[dict[str, bool], dict[str, object]]:
    """Measure concurrent invalid traffic, valid callers and independent receipt evidence."""
    directory = e.run.directory
    valid_sources, negative_sources = _sources(e.trace)
    invalid = cast('list[_Negative]', observation_rows(directory / 'invalid.jsonl'))
    path = directory / 'invalid-schedule.json'
    schedule: dict[str, int] = json.loads(path.read_text()) if path.exists() else {}
    statuses = Counter(str(event.get('status', event.get('error'))) for event in invalid)
    paced, cadence = (
        _cadence(invalid, e.measure)
        if e.shared_clock('negative', 'fleet')
        else (False, {'clock_domain_unproven': True})
    )
    routed, allowed, receipt = _negative_route(e, negative_sources.total())
    one_source = e.run.variant == 'one-source'
    checks = {
        'valid_machines_received_tokens_within_budget': e.complete()
        and all(c['seconds'] <= MAX_WAIT for c in e.measure),
        'invalid_traffic_spanned_valid_acquisitions': paced,
        'invalid_statuses_allowed': allowed,
        'scheduled_requests_dispatched': bool(invalid)
        and schedule.get('scheduled') == len(invalid)
        and schedule.get('dropped') == 0
        and schedule.get('target_per_second') == NEGATIVE_RATE
        and {r.get('sequence') for r in invalid} == set(range(len(invalid)))
        and all(
            r['fixture'] == ('absent' if r.get('sequence', 0) % 2 else 'repeated') for r in invalid
        ),
        'proxy_path_observed': routed and bool(valid_sources),
    }
    label = (
        'one source through nginx'
        if one_source
        else 'direct broker stress; distributed proxy exposure unmeasured'
    )
    return checks, {
        'configuration': label,
        'negative_schedule': schedule,
        'invalid_outcomes': statuses,
        'negative_dispatch_cadence': cadence,
        'negative_receipts': receipt,
        'invalid_fixtures': Counter(event['fixture'] for event in invalid),
        'proxy_valid_sources': valid_sources,
        'proxy_invalid_sources': negative_sources,
    }


def _stream_receipt_faults(
    trace: Reconciliation, epoch: float
) -> tuple[dict[int, list[tuple[float, float]]], set[str]]:
    """Localize each conflicting attempt to its own interval, preserving orphan evidence."""
    faults: defaultdict[int, list[tuple[float, float]]] = defaultdict(list)
    unplaced: set[str] = set()
    acquisitions: defaultdict[int, list[tuple[float, float]]] = defaultdict(list)
    for event in trace.slots:
        seq = int(str(event['sequence']))
        begin = event.get('acquisition_start', event.get('start_monotonic'))
        finish = event.get('finish_monotonic')
        acquisitions[seq].append(
            (
                float(begin) if isinstance(begin, (float, int)) else epoch + seq * PERIOD,
                float(finish) if isinstance(finish, (float, int)) else math.inf,
            )
        )
    for obs in trace.observations:
        if obs.slot is None or not obs.receipt_fault:
            continue
        start, end = obs.bounds
        due = epoch + obs.slot * PERIOD
        faults[obs.slot].append(
            (
                start if math.isfinite(start) else due,
                end if math.isfinite(end) else max(due, start),
            )
        )
    for receipt in trace.orphans:
        if receipt.get('phase') == 'stream':
            identifier = receipt.get('attempt_id', '')
            match = re.fullmatch(r'stream-(\d+)-\d+', identifier)
            if match:
                slot = int(match[1])
                faults[slot].extend(acquisitions.get(slot, [(epoch + slot * PERIOD, math.inf)]))
            else:
                unplaced.add(identifier)
    return faults, unplaced


def _suppression_evidence(
    e: _Evidence, suppressed: list[int], epoch: float
) -> dict[int, dict[int, str]]:
    """Reconstruct the acquisitions outstanding at each suppressed slot."""
    observations = e.trace.slots
    occupants: dict[int, dict[int, str]] = {}
    for seq in suppressed:
        due = epoch + seq * PERIOD
        held: dict[int, str] = {}
        for event in observations:
            begin = event.get('acquisition_start', event.get('start_monotonic'))
            finish = event.get('finish_monotonic')
            if (
                isinstance(begin, (float, int))
                and isinstance(finish, (float, int))
                and begin <= due < finish
            ):
                held[int(str(event['sequence']))] = _occupied_cause(event, due, e)
        occupants[seq] = held

    return occupants


def _warm_gaps(intervals: list[tuple[float, float]], answered: list[float]) -> list[float]:
    """Count both boundaries when measuring gaps between successful warm replies."""
    answered.sort()
    return [
        max(b - a for a, b in pairwise([start, *(t for t in answered if start <= t <= end), end]))
        for start, end in intervals
    ]


def _serial_intervals(
    e: _Evidence, intervals: list[tuple[float, float]], primed: dict[str, int]
) -> dict[str, object]:
    """Count the serial client's verified final HTTP replies by process in each interval."""
    calls = [c for c in e.calls if c['phase'] == 'probe']
    shared = _same_domain(e.clocks, 'probe', e.fixture_role)
    summary = {**_caller_summary(calls), 'shared_monotonic_clock': shared}
    if not shared:
        return {**summary, 'interval_results': [], 'verdict': 'inconclusive'}
    replies: list[tuple[float, str]] = []
    for call in calls:
        if _http_success(call):
            obs = e.trace.unique(call['attempts'][-1].get('attempt_id', ''))
            if obs and (reply := obs.warm_reply(call.get('generation'), primed)):
                replies.append(reply)
    faults = [
        obs.bounds for obs in e.trace.observations if obs.phase == 'probe' and obs.receipt_fault
    ]
    orphan = any(r.get('phase') == 'probe' for r in e.trace.orphans)
    gaps = _warm_gaps(intervals, [t for t, _ in replies])
    return {
        **summary,
        'interval_results': [
            {
                'start': a,
                'end': b,
                'maximum_gap_seconds': gap,
                'receipts_reconciled': not orphan
                and not any(lo < b and hi >= a for lo, hi in faults),
                'replies_by_upstream': {
                    peer: sum(a <= t <= b and p == peer for t, p in replies) for peer in primed
                },
            }
            for (a, b), gap in zip(intervals, gaps, strict=True)
        ],
    }


def _stream_evidence(
    e: _Evidence, intervals: list[tuple[float, float]], primed: dict[str, int], release: float
) -> tuple[bool, dict[str, object]]:
    """Reconcile due slots and measure boundary-inclusive warm reply gaps per interval."""
    run = e.run
    clock_path = run.directory / 'stream-clock.json'
    clock: dict[str, object] = json.loads(clock_path.read_text()) if clock_path.exists() else {}
    epoch = clock.get('epoch')
    stop = clock.get('stop')
    observations = e.trace.slots
    clocks = e.clocks
    shared = _same_domain(clocks, 'fleet', 'stream', 'deployment' if run.direct else 'observer')
    sample = clocks.get('stream', {})
    earliest = float(str(sample.get('monotonic', 0))) - float(
        str(sample.get('sampling_uncertainty_seconds', 0))
    )
    if not (
        shared
        and isinstance(epoch, (int, float))
        and math.isfinite(epoch)
        and epoch > 0
        and epoch >= earliest
        and isinstance(stop, (int, float))
        and math.isfinite(stop)
        and stop >= epoch
    ):
        return False, {
            'shared_monotonic_clock': shared,
            'recorded_sequences': [r['sequence'] for r in observations],
            'recorded_slots': observations,
            'missed_slots': [],
            'maximum_gap_seconds': None,
            'interval_results': [],
            'clock': clock,
            'verdict': 'inconclusive',
        }
    bad_receipts, unplaced = _stream_receipt_faults(e.trace, epoch)
    replies: list[tuple[float, str]] = []
    starts: list[float] = []
    late: list[int] = []
    suppressed: list[int] = []
    observed: Counter[int] = Counter()
    for event in observations:
        seq = int(str(event['sequence']))
        observed[seq] += 1
        due = epoch + seq * PERIOD
        if event.get('slot') == 'suppressed':
            suppressed.append(seq)
            continue
        start = event.get('start_monotonic')
        if isinstance(start, (float, int)):
            starts.append(start)
            if not 0 <= start - due <= LATE_SECONDS:
                late.append(seq)
        else:
            late.append(seq)
            continue
        if attempts := _slot_attempts(event):
            obs = e.trace.unique(attempts[-1].get('attempt_id', ''))
            if obs and (reply := obs.warm_reply(event.get('generation'), primed)):
                replies.append(reply)
    missing = sorted(set(range(math.ceil((stop - epoch) / PERIOD))) - observed.keys())
    duplicate = {seq for seq, count in observed.items() if count != 1}
    occupants = _suppression_evidence(e, suppressed, epoch)
    invalid_suppressions = [seq for seq, held in occupants.items() if len(held) != SLOTS]
    bad = set(late) | set(missing) | duplicate | set(invalid_suppressions)
    interval_late = [
        [seq for seq in sorted(bad) if start <= epoch + seq * PERIOD < end]
        for start, end in intervals
    ]
    interval_receipts = [
        [
            seq
            for seq, bounds in sorted(bad_receipts.items())
            if any(lo <= end and hi >= start for lo, hi in bounds)
        ]
        for start, end in intervals
    ]
    answered = [stamp for stamp, _ in replies]
    gaps = _warm_gaps(intervals, answered)
    ready = (
        bool(starts)
        and len(cast('list[int]', clock.get('cpus', []))) == 1
        and min(starts) < release
        and not unplaced
    )
    results: list[dict[str, object]] = []
    for (start, end), lag, faults, gap in zip(
        intervals, interval_late, interval_receipts, gaps, strict=True
    ):
        valid = ready and epoch <= start <= end <= stop and not lag and not faults
        results.append(
            {
                'start': start,
                'end': end,
                'schedule_valid': valid,
                'maximum_gap_seconds': gap,
                'observed_miss': gap > 1,
                'verdict': 'inconclusive' if not valid else 'miss' if gap > 1 else 'pass',
                'replies_by_upstream': {
                    p: sum(start <= t <= end and peer == p for t, peer in replies) for p in primed
                },
            }
        )
    return bool(results) and all(r['schedule_valid'] for r in results), {
        'missed_slots': missing,
        'late_slots': late,
        'late_or_missing_by_interval': interval_late,
        'interval_results': results,
        'suppressed_slots': suppressed,
        'outstanding_by_suppressed_slot': occupants,
        'invalid_suppressions': invalid_suppressions,
        'reconciled': not bad_receipts and not unplaced,
        'receipt_fault_slots': sorted(bad_receipts),
        'receipt_faults_by_interval': interval_receipts,
        'unplaced_receipts': sorted(unplaced),
        'replies_by_upstream': Counter(peer for _, peer in replies),
        'interval_maximum_gaps_seconds': gaps,
        'maximum_gap_seconds': max(gaps, default=None),
        'warm_response_times_monotonic': answered,
        'clock': clock,
    }


def _slow(e: _Evidence) -> tuple[dict[str, bool], dict[str, object]]:
    """Measure primary warm availability independently of the serial production client."""
    control = e.run.scenario == 'slow-control'
    cold = [m for m in e.mints if m['scope'] != 'warm']
    intervals = [
        (m['started_monotonic'], m['finished_monotonic'])
        for m in cold
        if 'started_monotonic' in m and 'finished_monotonic' in m
    ]
    slow = (
        bool(cold)
        and len(intervals) == len(cold)
        and all(
            end >= start and (control or end - start >= _SLOW_MINT_SECONDS)
            for start, end in intervals
        )
    )
    delivered = (
        e.shared_clock('fleet', e.fixture_role)
        and bool(cold)
        and len(intervals) == len(cold)
        and all(
            m['outcome'] == 'minted'
            and 'generation' in m
            and any(
                c.get('generation') == m['generation']
                and c['scope'] == m['scope']
                and c.get('start_monotonic', math.inf)
                <= start
                <= end
                <= c.get('start_monotonic', -math.inf) + c['seconds']
                for c in e.measure
            )
            for (start, end), m in zip(intervals, cold, strict=True)
        )
    )
    reference = intervals
    if control and intervals:
        start = min(a for a, _ in intervals)
        reference = [(start, start + _SLOW_MINT_SECONDS)]
    proven = _prime_receipts(e)
    primed = {
        f'127.0.0.1:{DIRECT_PORT + i}': proven[key]
        for i in range(e.run.brokers)
        if (key := f'broker-{i}-0/farm-1/warm/session') in proven
    }
    warm = set(primed) == {f'127.0.0.1:{DIRECT_PORT + n}' for n in range(e.run.brokers)}
    marker = e.run.directory / 'fleet-release.json'
    release = json.loads(marker.read_text())['monotonic'] if marker.exists() else 0
    valid, stream = _stream_evidence(e, reference, primed, release)
    gap = stream['maximum_gap_seconds']
    return {
        'every_machine_received_tokens': e.complete(),
        'measured_slow_cold_mint' if not control else 'measured_control_mint': slow,
        'cold_generation_delivered': delivered,
        'warm_primed_on_all_processes': warm,
        'warm_stream_schedule_observed': valid,
        'warm_requests_answered_throughout': isinstance(gap, (float, int)) and gap <= 1 and warm,
    }, {
        'cold_mint_monotonic_intervals': intervals,
        'cold_mint_intervals': [(m['started'], m['finished']) for m in cold],
        'warm_reference_monotonic_intervals': reference,
        'primed_generation_by_upstream': primed,
        'warm_stream': stream,
        'warm_probe': _serial_intervals(e, reference, primed),
    }


def _expectations(e: _Evidence) -> tuple[dict[str, bool], dict[str, object]]:
    """Select the spec row corresponding to the actual workload."""
    scenario = e.run.scenario
    readers = {
        'rejected-tokens': _recovery,
        'synchronized-renewal': _renewal,
        'slow-sg': _slow,
        'slow-control': _slow,
        'sg-outage': _outage,
        'bad-secrets': _bad_secrets,
    }
    if scenario in readers:
        return readers[scenario](e)
    if scenario in {'rejected-script-key', 'process-restart'}:
        return _fault(e), {}
    if scenario == 'generator-calibration':
        return {'all_receiver_calls_succeeded': e.complete()}, {}
    if scenario == 'tls-smoke':
        return {
            'get_token_over_tls': e.complete()
            and all(
                c['group'] == 'get-token'
                and any(a.get('status') == HTTPStatus.OK for a in c['attempts'])
                for c in e.measure
            )
        }, {}
    return _burst(e), {}


def _worker_socket_peaks(directory: Path) -> dict[str, object]:
    """Attribute sampled live ingress to the worker recorded for that peer and port."""
    owners: defaultdict[tuple[str, int], set[str]] = defaultdict(set)
    for receipt in rows(directory / 'proxy.jsonl'):
        port = str(receipt.get('remote_port', ''))
        worker = str(receipt.get('worker_pid', ''))
        if port.isdecimal() and worker.isdecimal():
            owners[str(receipt['peer']), int(port)].add(worker)
    peaks: Counter[str] = Counter()
    samples = rows(directory / 'client-sockets.jsonl')
    for sample in samples:
        live: Counter[str] = Counter()
        for peer in cast('list[str]', sample['peers']):
            address, port = peer.split(':')
            packed = bytes.fromhex(address)
            if sample.get('byteorder', 'little') == 'little':
                packed = packed[::-1]
            workers = owners.get((str(IPv4Address(packed)), int(port, 16)), set())
            live[next(iter(workers)) if len(workers) == 1 else 'unattributed'] += 1
        peaks |= live
    unmatched = peaks.pop('unattributed', 0)
    return {
        'samples': len(samples),
        'peak_live_by_worker': dict(peaks),
        'peak_unattributed': unmatched,
    }


def measurements(run: Run) -> dict[str, object]:
    """Reduce the available run artifacts into a scenario report.

    Returns:
        Caller, service and resource measurements together with workload
        checks, assessment and missing broker evidence.

    Raises:
        OSError: If a required artifact is missing or cannot be read.
        ValueError: If an artifact cannot be decoded or a required number is
            invalid.
        KeyError: If a required record field is absent.
        TypeError: If a required artifact value has an incompatible JSON type.
    """
    e = _Evidence(run)
    checks, detail = _expectations(e)
    connection_checks, connection_detail = _connection_evidence(e)
    checks.update(connection_checks)
    detail.update(connection_detail)
    deployment = json.loads((run.directory / 'deployment.json').read_text())
    if not run.direct:
        checks['valid_proxy_source_distribution'], detail['proxy_sources'] = _proxy_coverage(e)
        config_report = run.directory / 'proxy-config.json'
        config: dict[str, object] = (
            json.loads(config_report.read_text()) if config_report.exists() else {}
        )
        detail['proxy_config'] = config or None
        pid_report = run.directory / 'service-pids.json'
        pids: dict[str, int] = json.loads(pid_report.read_text()) if pid_report.exists() else {}
        detail['service_processes'] = sorted(pids)
        checks['deployment_configuration_observed'] = _deployment_matches(
            run, deployment.get('cgroup', {}), config.get('broker_ports'), pids
        )
    if run.scenario not in {'rejected-tokens', 'synchronized-renewal', 'tls-smoke'}:
        checks['arrival_schedule_observed'], detail['arrival_schedule'] = _arrivals(e)
    checks['required_snapshots_present'] = not e.missing
    if run.scenario == 'rejected-script-key':
        detail['refusal_to_completion_seconds'] = _distribution(
            [
                c['finish'] - c['attempts'][-1]['finish']
                for c in e.measure
                if c['attempts'] and c['attempts'][-1].get('code') == 'sg_rejected'
            ]
        )
        detail['prompt_stop_tolerance_seconds'] = 1.0
    proxy_samples = rows(run.directory / 'proxy-connections.jsonl')
    if not run.direct:
        detail['deployment_proxy_connections'] = {
            'scope': 'All nginx workers in the deployment network namespace',
            'samples': len(proxy_samples),
            'max_ingress': max((int(str(r['ingress'])) for r in proxy_samples), default=None),
            'max_upstream': max((int(str(r['upstream'])) for r in proxy_samples), default=None),
        }
    if (run.directory / 'client-sockets.jsonl').exists():
        detail['worker_client_connections'] = _worker_socket_peaks(run.directory)
    assessment = _assessment(e, checks)
    if run.scenario in {'slow-sg', 'slow-control'}:
        prerequisites = cast('dict[str, bool]', assessment['workload_predicates'])
        stream = cast('dict[str, object]', detail['warm_stream'])
        for item in cast('list[dict[str, object]]', stream['interval_results']):
            duration = float(str(item['end'])) - float(str(item['start']))
            item['comparison_valid'] = bool(
                item['schedule_valid']
                and duration >= _SLOW_MINT_SECONDS
                and prerequisites['warm_primed_on_all_processes']
                and prerequisites['disjoint_cpu_placement']
            )
            if not item['comparison_valid']:
                item['verdict'] = 'inconclusive'
    phases = dict.fromkeys(c['phase'] for c in e.calls)
    return {
        'observer_control': (run.directory / 'observer-control').exists(),
        'scenario': run.scenario,
        'variant': run.variant,
        'machines': run.machines,
        'max_wait_seconds': MAX_WAIT,
        'callers': {p: _caller_summary([c for c in e.calls if c['phase'] == p]) for p in phases},
        'mints_by_process_client_scope_type': dict(e.by_key),
        'priming_mints_by_process_client_scope_type': dict(e.priming),
        'missing_broker_evidence': e.missing,
        'deployment': deployment,
        'audit_by_process_client_scope_type_generation_outcome': e.audit,
        'scrypt_by_process_credential': e.raw,
        'verifications_by_process_credential': e.verified,
        'warm_counter_changes': e.warm,
        'resource_scope': (
            'CPU, RSS and threads are per process. Broker connections are per process. '
            'Proxy connections cover all nginx workers.'
        ),
        'resources': _resources(run.directory),
        'expected_outcomes': checks,
        **assessment,
        **detail,
    }
