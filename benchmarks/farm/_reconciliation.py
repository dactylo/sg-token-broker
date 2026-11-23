"""Reconcile request identities before attributing benchmark outcomes to service hops."""

import datetime
import math
import re
from collections import Counter, defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum, auto
from http import HTTPStatus
from pathlib import Path
from typing import NamedTuple, NotRequired, TypedDict, cast

from benchmarks.farm import DIRECT_NEGATIVE_PEER, DIRECT_PORT, Run, machine_address, rows
from benchmarks.farm._observations import observation_rows
from sg_token_broker._retry import parse_retry_after


class _Attempt(TypedDict):
    """Record wall-clock seconds and optional monotonic timing for one transport attempt."""

    start: float
    connection: NotRequired[str]
    tls_session_reused: NotRequired[bool]
    http_send_entry: NotRequired[float]
    start_monotonic: NotRequired[float]
    finish_monotonic: NotRequired[float]
    finish: float
    status: NotRequired[int]
    error: NotRequired[str]
    code: NotRequired[str]
    attempt_id: NotRequired[str]


class Call(TypedDict):
    """Describe one client invocation, including calls served without a transport.

    Attributes:
        phase: Workload phase in which the call ran.
        machine: Synthetic machine number.
        start: Wall-clock invocation start in seconds.
        finish: Wall-clock result time in seconds.
        start_monotonic: Optional monotonic invocation start.
        finish_monotonic: Optional monotonic result time.
        seconds: Elapsed invocation time.
        group: Library or `get-token` caller.
        scope: Requested broker scope.
        token_type: Requested SG token type.
        generation: Synthetic token generation returned on success.
        loadgen_queue_seconds: Delay awaiting generator admission.
        dispatch_to_result_seconds: Time from generator dispatch to result.
        recorder_tail_seconds: Elapsed seconds from the child's result marker
            until the parent begins collecting the attempt file.
        reported_generation: Most recent generation reported rejected.
        accepted_by_sg: Observed session-probe outcome during recovery.
        expires_at: Returned expiry as wall-clock seconds.
        error: Sanitized caller failure category.
        attempts: Actual transport attempts in order, possibly empty on a cache
            hit.
    """

    phase: str
    machine: int
    start: float
    start_monotonic: NotRequired[float]
    finish_monotonic: NotRequired[float]
    finish: float
    seconds: float
    group: str
    scope: str
    token_type: str
    generation: NotRequired[int]
    loadgen_queue_seconds: NotRequired[float]
    dispatch_to_result_seconds: NotRequired[float]
    recorder_tail_seconds: NotRequired[float]
    reported_generation: NotRequired[int]
    accepted_by_sg: NotRequired[bool]
    expires_at: NotRequired[float]
    error: NotRequired[str]
    attempts: list[_Attempt]


class _Match(Enum):
    """Distinguish contradictory hop evidence from absent or supporting fields."""

    EXCLUDED = auto()
    POSSIBLE = auto()
    SUPPORTED = auto()


@dataclass(frozen=True, slots=True)
class _UpstreamHop:
    """One peer in an nginx access record's ordered upstream history."""

    status: str
    backend: str
    connect: str
    header: str

    def stage_match(self, event: '_GatewayEvent') -> _Match:
        """Compare an error's stage with this hop's connection and header evidence.

        Returns:
            `EXCLUDED` for a contradiction, `SUPPORTED` for affirmative stage
            and peer evidence, or `POSSIBLE` when the fields are insufficient.
        """
        received_headers = self.header.replace('.', '', 1).isdecimal()
        if event.read_stage == 'body':
            # The upstream's response headers prove the connection, even with a connect dash.
            if self.header == '-' or (self.status and not self.status.isdecimal()):
                return _Match.EXCLUDED
            proven = received_headers and self.status.isdecimal()
        else:
            if received_headers or self.status not in {'', '502', '504'}:
                return _Match.EXCLUDED
            if event.cause == 'no_available_upstream' and ':' in self.backend:
                return _Match.EXCLUDED
            preconnect = event.cause in {'no_available_upstream', 'upstream_connect_timeout'}
            connected = self.connect.replace('.', '', 1).isdecimal()
            if (preconnect and connected) or (not preconnect and self.connect == '-'):
                return _Match.EXCLUDED
            connect_evidence = self.connect == '-' if preconnect else connected
            proven = connect_evidence and self.header == '-' and bool(self.status)
        return _Match.SUPPORTED if proven and self.backend else _Match.POSSIBLE


@dataclass(frozen=True, slots=True)
class _UpstreamEvidence:
    """Represent nginx's ordered upstream hops and evidence of a local limiter refusal."""

    hops: tuple[_UpstreamHop, ...]
    local_refusal: bool
    status_chain: str

    @property
    def terminal(self) -> _UpstreamHop:
        """Return the terminal fields, all unknown when the hop count is unknown."""
        return self.hops[-1] if self.hops else _UpstreamHop('', '', '', '')


class _ProxyRecord(TypedDict):
    """Describe a candidate proxy receipt whose route is known only as far as the log shows."""

    finish: float
    elapsed: float
    peer: str
    status: int
    ssl_session_reused: NotRequired[str]
    connection_requests: NotRequired[str]
    connection: NotRequired[str]
    retry_after: NotRequired[str]
    route: _UpstreamEvidence
    method: str
    uri: str
    phase: NotRequired[str]
    attempt_id: NotRequired[str]
    tag: str


@dataclass(frozen=True, slots=True)
class _GatewayEvent:
    """Locate an nginx error by log line and, when recorded, its UTC wall-clock second."""

    line: int
    connection: str
    cause: str
    peer: str
    upstream: str
    request: str
    wall_second: float | None
    read_stage: str | None

    def _compatible_request(self, receipt: _ProxyRecord) -> bool:
        """Retain receipts whose request and time do not contradict this error."""
        if self.wall_second is not None and 'finish' in receipt and 'elapsed' in receipt:
            # Both nginx logs use the deployment's UTC wall clock. Access times
            # are millisecond samples; the error timestamp spans a whole second.
            end = receipt['finish']
            if (
                end + 0.001 < self.wall_second
                or end - receipt['elapsed'] - 0.001 > self.wall_second + 1
            ):
                return False
        return not any(
            observed and observed != logged
            for observed, logged in zip(
                (receipt['method'], receipt['uri']), self.request.split()[:2], strict=False
            )
        )

    def match(
        self, receipt: _ProxyRecord, owner: 'Observation | None', hop: _UpstreamHop | None
    ) -> _Match:
        """Assess whether this error can belong to a particular access-log hop.

        Args:
            receipt: Candidate access record.
            owner: Associated client observation, or `None` if ownership is
                unknown.
            hop: Candidate upstream hop, or `None` if its fields are
                unavailable.

        Returns:
            Whether the evidence excludes, permits or supports the association.
        """
        route = receipt['route']
        if (
            route.local_refusal
            or not self._compatible_request(receipt)
            or (self.peer and receipt['peer'] and self.peer != receipt['peer'])
        ):
            return _Match.EXCLUDED
        if hop is None:
            return _Match.POSSIBLE
        if (self.upstream and hop.backend and self.upstream != hop.backend) or (
            hop is route.terminal
            and receipt['status']
            and self.read_stage != 'body'
            and receipt['status'] < HTTPStatus.BAD_REQUEST
        ):
            return _Match.EXCLUDED
        support = hop.stage_match(self)
        if (
            owner
            and owner.hops
            and self.cause in {'no_available_upstream', 'upstream_connect_timeout'}
        ):
            # A parsed POST excludes connect failure at that peer. With a
            # missing peer identity the hop can still compete for the event.
            if len(route.hops) == 1:
                return _Match.EXCLUDED
            for handled in owner.hops:
                process = re.fullmatch(r'broker-(\d+)-\d+', str(handled.get('process', '')))
                if (
                    process
                    and (hop.backend or self.upstream)
                    == f'127.0.0.1:{DIRECT_PORT + int(process[1])}'
                ):
                    return _Match.EXCLUDED
                if not process and support is _Match.SUPPORTED:
                    support = _Match.POSSIBLE
        if support is _Match.SUPPORTED and (
            owner is None
            or not receipt.get('connection')
            or not receipt['status']
            or (
                self.wall_second is not None
                and ('finish' not in receipt or 'elapsed' not in receipt)
            )
        ):
            support = _Match.POSSIBLE
        return support


class Failure(NamedTuple):
    """Describe a recovered or terminal failure attributed to one observation.

    Attributes:
        cause: Classified failure category.
        backend: Upstream address, or an empty string if unknown.
        event: Supporting nginx error, or `None` for a failure without one.
    """

    cause: str
    backend: str
    event: _GatewayEvent | None


@dataclass(slots=True)
class Observation:
    """Collect the client, proxy and broker evidence for one actual transport.

    Attributes:
        identifier: Client correlation ID, possibly empty or shared by multiple
            observations.
        attempt: Recorded client transport.
        phase: Workload phase.
        caller: Participant role that recorded the attempt.
        domain: Clock-domain evidence for that role.
        peer: Expected client address when known.
        direct: Whether this transport bypassed nginx.
        slot: Scheduled warm-stream sequence, if applicable.
        receipts: Proxy records with the candidate identifier.
        receipt: Uniquely matched proxy record, if established.
        hops: Associated broker socket or handler records.
        receipt_fault: No receipt matched, and there are candidate receipts, a
            recorded HTTP status, or a missing or ambiguous attempt ID.
        event: Matched terminal nginx error, if established.
        recovered: Failures from earlier upstream hops.
        candidates: Possible terminal error causes with compatible evidence.
    """

    identifier: str
    attempt: _Attempt
    phase: str
    caller: str
    domain: object
    peer: str
    direct: bool
    slot: int | None = None
    receipts: tuple[_ProxyRecord, ...] = ()
    receipt: _ProxyRecord | None = None
    hops: list[dict[str, object]] = field(default_factory=list[dict[str, object]])
    receipt_fault: bool = False
    event: _GatewayEvent | None = None
    recovered: list[Failure] = field(default_factory=list[Failure])
    candidates: set[str] = field(default_factory=set[str])

    @property
    def bounds(self) -> tuple[float, float]:
        """Return the transport's monotonic start and finish in seconds.

        Returns:
            Lower and upper bounds, using negative or positive infinity for a
            missing endpoint.
        """
        return self.attempt.get('start_monotonic', -math.inf), self.attempt.get(
            'finish_monotonic', math.inf
        )

    @property
    def cause(self) -> str:
        """Return the matched or inferred terminal cause, or `unclassified` if uncertain."""
        if self.event:
            return self.event.cause
        if self.candidates or (self.receipt_fault and self.receipts):
            return 'unclassified'
        return _cause(self)

    @property
    def direct_handler(self) -> str:
        """Return the uniquely handled direct-route broker name, or an empty string."""
        if not self.direct or self.receipts or len(self.hops) != 1:
            return ''
        hop = self.hops[0]
        process = str(hop['process'])
        # The direct URL always selects broker slot zero, including after restart.
        handled = hop.get('disposition') == 'handled' or (
            'disposition' not in hop and 'handler_start' in hop
        )
        return process if handled and process.startswith('broker-0-') else ''

    def failure_bounds(self, event: _GatewayEvent | None) -> tuple[float, float]:
        """Enclose a failure using causally ordered monotonic timestamps.

        Args:
            event: Matched gateway error, or `None` when there is no matched
                error.

        Returns:
            Earliest and latest possible failure times in seconds. An unproven
            end is positive infinity. Inconsistent ordering leaves both ends
            open.
        """
        start, finish = self.bounds
        sent = self.attempt.get('http_send_entry', start)
        if not start <= sent <= finish:
            return -math.inf, math.inf
        if event and ('status' not in self.attempt or event.read_stage == 'body'):
            # Giving up or receiving upstream headers does not establish when
            # nginx stopped waiting. Its two logs have wall timestamps only.
            return sent, math.inf
        return sent, finish

    def failures(self) -> Iterator[Failure]:
        """Yield recovered gateway failures and any separate terminal failure."""
        yield from self.recovered
        if (
            self.event
            or self.attempt.get('status', 0) >= HTTPStatus.BAD_REQUEST
            or 'error' in self.attempt
        ):
            backend = self.receipt['route'].terminal.backend if self.receipt else ''
            yield Failure(self.cause, backend, self.event)

    def warm_reply(self, generation: object, primed: dict[str, int]) -> tuple[float, str] | None:
        """Qualify a successful response against its primed backend generation.

        Args:
            generation: Generation reported by the caller.
            primed: Expected generation keyed by backend address.

        Returns:
            Monotonic finish time and backend address, or `None` if the
            receipt, status, generation or timestamp cannot establish the
            match.
        """
        backend = self.receipt['route'].terminal.backend if self.receipt else ''
        finish = self.attempt.get('finish_monotonic')
        if (
            self.receipt
            and self.attempt.get('status') == self.receipt['status'] == HTTPStatus.OK
            and backend in primed
            and generation == primed[backend]
            and finish is not None
        ):
            return finish, backend
        return None


class Reconciliation:
    """Join recorded client transports to proxy, broker and gateway evidence.

    Attributes:
        slots: Recorded warm-stream schedule entries.
        observations: Individual client transports in collection order.
        logs: Access records that could represent a token POST.
        orphans: Access records whose ID has no client observation.
        events: Relevant nginx error-log events.
        unassigned: Events without proven ownership, ordered by source line.
    """

    def __init__(self, run: Run, calls: list[Call], clocks: dict[str, dict[str, object]]) -> None:
        """Build the evidence joins for one recorded run.

        Args:
            run: Deployment, workload and directory containing the evidence.
            calls: Caller records, including each invocation's actual attempts.
            clocks: Clock samples keyed by participant role.

        Raises:
            OSError: If a present evidence file cannot be read.
            ValueError: If an artifact contains invalid JSON, an invalid
                numeric field, or a machine index outside the benchmark address
                range.
            KeyError: If a record lacks a field required for the join.
        """
        self.slots = observation_rows(run.directory / 'stream.jsonl')
        self.observations: list[Observation] = []
        self._by_id: defaultdict[str, list[Observation]] = defaultdict(list)
        self.logs = _proxy_posts(run)
        host_peers: set[str] = (
            {r['peer'] for r in self.logs if r.get('phase') == 'measure'}
            if run.scenario == 'tls-smoke'
            else set()
        )

        def record(
            attempt: _Attempt,
            phase: str,
            role: str,
            peer: str,
            slot: int | None = None,
        ) -> Observation:
            identifier = attempt.get('attempt_id', '')
            obs = Observation(
                identifier,
                attempt,
                phase,
                role,
                clocks.get(role, {}).get('domain'),
                peer,
                direct=(run.direct and not run.farm_network)
                or (phase == 'negative' and run.variant == 'unthrottled-broker'),
                slot=slot,
            )
            self.observations.append(obs)
            self._by_id[identifier].append(obs)
            return obs

        for call in calls:
            phase = call['phase']
            is_probe = (
                run.scenario in {'slow-sg', 'slow-control'} and call['machine'] == run.machines
            )
            peer = (
                next(iter(host_peers))
                if len(host_peers) == 1
                else machine_address(call['machine'])
            )
            for attempt in call['attempts']:
                record(
                    attempt,
                    phase,
                    'probe' if is_probe else 'fleet',
                    peer,
                )
        for slot in self.slots:
            for attempt in slot_attempts(slot):
                record(
                    attempt,
                    'stream',
                    'stream',
                    machine_address(run.machines + 1),
                    int(str(slot['sequence'])),
                )
        direct_ports: defaultdict[int, list[Observation]] = defaultdict(list)
        for entry in observation_rows(run.directory / 'invalid.jsonl'):
            negative = record(
                cast(
                    '_Attempt',
                    {
                        **entry,
                        'attempt_id': f'negative:{entry["sequence"]}'
                        if 'sequence' in entry
                        else '',
                    },
                ),
                'negative',
                'negative',
                '',
            )
            port = entry.get('local_port')
            if negative.direct and isinstance(port, int):
                direct_ports[port].append(negative)
        self.orphans: list[_ProxyRecord] = []
        owners = self._join_receipts()
        self._join_hops(run.directory, direct_ports)
        self.events = _gateway_events(run.directory)
        self.unassigned = self._join_events(owners)

    def _join_events(self, owners: dict[int, Observation]) -> list[_GatewayEvent]:
        """Assign events once, retaining every receipt that could compete for an event."""
        by_connection: defaultdict[str, list[_ProxyRecord]] = defaultdict(list)
        for receipt in self.logs:
            by_connection[receipt.get('connection', '')].append(receipt)
        errors: defaultdict[str, list[_GatewayEvent]] = defaultdict(list)
        for event in self.events:
            errors[event.connection].append(event)
        unassigned: list[_GatewayEvent] = []
        for connection, events in errors.items():
            # An unknown connection cannot establish ownership, but its
            # receipts can compete with matching requests on this connection.
            receipts = by_connection[connection] + by_connection[''] if connection else []
            hops = [
                (receipt, hop) for receipt in receipts for hop in receipt['route'].hops or (None,)
            ]
            choices = [_event_choices(event, hops, owners) for event in events]
            pairs = _event_pairs(events, choices, [receipt for receipt, _ in hops])
            for event, candidates in zip(events, choices, strict=True):
                index = pairs.get(event)
                if index is None or candidates.get(index) is not _Match.SUPPORTED:
                    unassigned.append(event)
                    continue
                receipt, hop = hops[index]
                obs = owners.get(id(receipt))
                if obs is None or hop is None:
                    unassigned.append(event)
                elif hop is receipt['route'].terminal:
                    obs.event = event
                else:
                    obs.recovered.append(Failure(event.cause, hop.backend, event))
        return sorted(unassigned, key=lambda event: event.line)

    def unique(self, identifier: str) -> Observation | None:
        """Return the sole observation for an ID, or `None` for missing or ambiguous IDs.

        Args:
            identifier: Client attempt ID. An empty string or `-` denotes no
                ID.
        """
        group = self._by_id.get(identifier, [])
        return group[0] if identifier not in {'', '-'} and len(group) == 1 else None

    def _join_hops(self, directory: Path, direct_ports: dict[int, list[Observation]]) -> None:
        """Join parsed IDs and uniquely identifiable pre-handler fixture sockets."""
        sockets: defaultdict[int, list[dict[str, object]]] = defaultdict(list)
        for path in sorted(directory.glob('hops-broker-*.jsonl')):
            process = path.stem.removeprefix('hops-')
            for hop in rows(path):
                obs = self.unique(str(hop.get('attempt_id', '')))
                if obs:
                    obs.hops.append({**hop, 'process': process})
                match hop.get('peer'):
                    case [str(address), int(port)] if (
                        address == DIRECT_NEGATIVE_PEER and port in direct_ports
                    ):
                        sockets[port].append({**hop, 'process': process})
                    case _:
                        pass
        # Admission can refuse a socket before the broker reads its attempt ID.
        for port, attempts in direct_ports.items():
            matches = sockets[port]
            if (
                len(attempts) == len(matches) == 1
                and matches[0].get('disposition') == 'pre_handler'
            ):
                obs = attempts[0]
                if self.unique(obs.identifier) is obs and not obs.hops:
                    obs.hops.append(matches[0])

    def _join_receipts(self) -> dict[int, Observation]:
        """Attach competing receipts and index the uniquely matched ones by object identity."""
        by_id: defaultdict[str, list[_ProxyRecord]] = defaultdict(list)
        for receipt in self.logs:
            key = _receipt_id(receipt)
            by_id[key].append(receipt)
            if key not in self._by_id:
                self.orphans.append(receipt)
        owners: dict[int, Observation] = {}
        for obs in self.observations:
            obs.receipts = tuple(by_id.get(obs.identifier, ()))
            if not obs.direct and self.unique(obs.identifier) is obs and len(obs.receipts) == 1:
                receipt = obs.receipts[0]
                route = (
                    receipt.get('tag') not in {None, '', '-'}
                    if obs.phase == 'negative'
                    else obs.phase == receipt.get('phase') and obs.peer == receipt['peer']
                )
                if (
                    route
                    and receipt['method'] == 'POST'
                    and receipt['uri'] == '/v1/token'
                    and ('status' not in obs.attempt or obs.attempt['status'] == receipt['status'])
                ):
                    obs.receipt = receipt
                    owners[id(receipt)] = obs
            obs.receipt_fault = obs.receipt is None and (
                bool(obs.receipts)
                or 'status' in obs.attempt
                or self.unique(obs.identifier) is not obs
            )
        return owners


def _cause(obs: Observation) -> str:
    """Distinguish an upstream failure, a local proxy refusal and an unknown observation."""
    attempt, receipt = obs.attempt, obs.receipt
    if receipt and receipt['route'].local_refusal and 'finish' in receipt:
        return (
            'local_throttle_with_retry_after'
            if parse_retry_after(
                receipt.get('retry_after'),
                datetime.datetime.fromtimestamp(receipt['finish'], datetime.UTC),
            )
            is not None
            else 'local_throttle_without_retry_after'
        )
    if 'error' in attempt:
        return 'client_transport_unknown'
    code = attempt.get('code', '')
    broker_response = 'status' in attempt and (
        bool(obs.direct_handler)
        or (receipt is not None and receipt['route'].terminal.status == str(attempt['status']))
    )
    if obs.phase == 'negative':
        if (
            broker_response
            and attempt.get('status') == HTTPStatus.UNAUTHORIZED
            and code == 'invalid_client'
        ):
            return code
        if (
            obs.direct
            and not obs.receipts
            and len(obs.hops) == 1
            and obs.hops[0].get('process') == 'broker-0-0'
            and obs.hops[0].get('disposition') == 'pre_handler'
            and attempt.get('status') == HTTPStatus.SERVICE_UNAVAILABLE
            and code == 'server_busy'
        ):
            return code
    if broker_response and code in {
        'server_busy',
        'upstream_unavailable',
        'sg_rejected',
        'sg_invalid_response',
    }:
        return code
    return 'unclassified'


def _event_choices(
    event: _GatewayEvent,
    hops: list[tuple[_ProxyRecord, _UpstreamHop | None]],
    owners: dict[int, Observation],
) -> dict[int, _Match]:
    """Retain compatible peers, including receipts whose owner is uncertain."""
    eligible: dict[int, _Match] = {}
    for index, (receipt, hop) in enumerate(hops):
        obs = owners.get(id(receipt))
        support = event.match(receipt, obs, hop)
        if support is not _Match.EXCLUDED:
            eligible[index] = support
            if obs and (hop is None or hop is receipt['route'].terminal):
                obs.candidates.add(event.cause)
    return eligible


def _event_pairs(
    events: list[_GatewayEvent], choices: list[dict[int, _Match]], receipts: list[_ProxyRecord]
) -> dict[_GatewayEvent, int]:
    """Prove a chronological bijection or retain only individually unambiguous pairs."""
    counts = Counter(index for group in choices for index in group)
    if (
        len(counts) == len(events)
        and all(e.request.endswith(' HTTP/1.1') for e in events)
        and all(v is _Match.SUPPORTED for group in choices for v in group.values())
    ):
        numbers = {i: receipts[i].get('connection_requests', '') for i in counts}
        if all(n.isdecimal() for n in numbers.values()):
            indices = sorted(numbers, key=lambda i: int(numbers[i]))
            if len({int(n) for n in numbers.values()}) == len(events) and all(
                i in group for i, group in zip(indices, choices, strict=True)
            ):
                return dict(zip(events, indices, strict=True))
    return {
        event: idx
        for event, group in zip(events, choices, strict=True)
        if len(group) == 1
        for idx in group
        if counts[idx] == 1
    }


def _gateway_events(directory: Path) -> list[_GatewayEvent]:
    """Read each relevant error independently of access or client observations."""
    path = directory / 'nginx-error.log'
    events: list[_GatewayEvent] = []
    if not path.exists():
        return events
    with path.open() as stream:
        for number, line in enumerate(stream, 1):
            conn = re.search(r'\*(\d+) ', line)
            read_stage = None
            if 'no live upstreams' in line:
                cause = 'no_available_upstream'
            elif 'upstream timed out' in line:
                cause = (
                    'upstream_connect_timeout'
                    if 'while connecting' in line
                    else 'upstream_read_timeout'
                )
                if 'while reading response header from upstream' in line:
                    read_stage = 'header'
                elif 'while reading upstream' in line:
                    read_stage = 'body'
            else:
                continue
            peer = re.search(r', client: ([^,]+)', line)
            request = re.search(r', request: "([^"]+)"', line)
            addr = re.search(r', upstream: "https?://([^/"]+)', line)
            stamp = re.match(r'\d{4}/\d\d/\d\d \d\d:\d\d:\d\d', line)
            second = (
                datetime.datetime.strptime(stamp[0], '%Y/%m/%d %H:%M:%S')
                .replace(tzinfo=datetime.UTC)
                .timestamp()
                if stamp
                else None
            )
            events.append(
                _GatewayEvent(
                    number,
                    conn[1] if conn else '',
                    cause,
                    peer[1] if peer else '',
                    addr[1] if addr else '',
                    request[1] if request else '',
                    second,
                    read_stage,
                )
            )
    return events


def _receipt_id(receipt: _ProxyRecord) -> str:
    """Use the attempt ID or negative tag, returning an empty ID when the two disagree."""
    tag = receipt.get('tag')
    attempt_id = receipt.get('attempt_id', '')
    if tag in {None, '', '-'}:
        return attempt_id
    expected = f'negative:{tag}'
    return expected if attempt_id in {'', '-', expected} else ''


def slot_attempts(event: dict[str, object]) -> list[_Attempt]:
    """Read the actual transports for one scheduled warm acquisition.

    Returns:
        The recorded attempt list, a singleton for a legacy inline attempt, or
        an empty list for an unsent slot.
    """
    if 'attempts' in event:
        return cast('list[_Attempt]', event['attempts'])
    return [cast('_Attempt', event)] if 'attempt_id' in event else []


def upstream_evidence(row: dict[str, object]) -> _UpstreamEvidence:
    """Decode one access line. A dash is recorded; empty or unalignable fields are unknown."""
    recorded = [
        row.get(key)
        for key in (
            'upstream',
            'upstream_addr',
            'upstream_connect_time',
            'upstream_header_time',
            'upstream_response_time',
        )
    ]
    columns = [str(value).split(', ') if value else [] for value in recorded[:4]]
    statuses, addresses = columns[:2]
    count = len(statuses) if len(statuses) == len(addresses) else 0
    aligned = [values if len(values) == count else [''] * count for values in columns]
    hops = tuple(_UpstreamHop(*fields) for fields in zip(*aligned, strict=True))
    rejected = 'REJECTED' in (row.get('limit_req'), row.get('limit_conn'))
    # escape=json writes unset variables as empty strings for local limiter
    # rejections. A missing key (None) provides no such evidence.
    local = (rejected and all(v in ('', '-') for v in recorded)) or (
        row.get('status') == HTTPStatus.TOO_MANY_REQUESTS and all(v == '-' for v in recorded)
    )
    return _UpstreamEvidence(hops, local, ', '.join(statuses) if count > 1 else '')


def _proxy_posts(run: Run) -> list[_ProxyRecord]:
    """Read candidate token POSTs in log order, including records with incomplete identity."""
    posts: list[_ProxyRecord] = []
    for row in rows(run.directory / 'proxy.jsonl'):
        if row.get('method') not in {None, '', 'POST'} or row.get('uri') not in {
            None,
            '',
            '/v1/token',
        }:
            continue
        route = upstream_evidence(row)
        post = cast('_ProxyRecord', row)
        post['route'] = route
        for key in ('method', 'uri', 'tag', 'peer'):
            row.setdefault(key, '')
        row.setdefault('status', 0)
        posts.append(post)
    return posts
