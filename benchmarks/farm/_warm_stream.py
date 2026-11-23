"""Send independent warm requests on a fixed schedule through the benchmark proxy."""

import json
import os
import queue
import sys
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from contextvars import ContextVar
from unittest.mock import patch

import requests

from benchmarks.farm import Run, _transport, publish, rows
from benchmarks.farm._observations import record_response, record_send_error
from sg_token_broker import BrokerClient, BrokerClientError, _client
from sg_token_broker._retry import RetryTiming

LATE_SECONDS = 0.05
PERIOD = 0.25
SLOTS = 4


_RETRY = ContextVar[tuple[list[dict[str, object]], list[tuple[float, float, int]]] | None](
    'warm_retry', default=None
)


def _cpus() -> list[int]:
    """Read this stream's effective Linux CPU affinity without changing it."""
    if sys.platform != 'linux':
        return []
    return sorted(os.sched_getaffinity(0))


def _occupants(records: list[dict[str, object]], due: float) -> list[int]:
    """Identify acquisitions in progress at the scheduled instant."""
    return [
        int(str(r['sequence']))
        for r in records
        if float(str(r.get('acquisition_start', float('inf'))))
        <= due
        < float(str(r.get('finish_monotonic', float('inf'))))
    ]


def _publish_slots(run: Run, records: list[dict[str, object]], epoch: float, stop: float) -> None:
    """Persist all elapsed slots, including an unsent tail after a delayed wake."""
    sequence = len(records)
    while epoch + sequence * PERIOD < stop:
        due = epoch + sequence * PERIOD
        occupants = _occupants(records, due)
        record: dict[str, object] = {
            'sequence': sequence,
            'due': due,
            'slot': 'late',
            'wake': stop,
        }
        if len(occupants) == SLOTS:
            record.update(slot='suppressed', outstanding=occupants)
        records.append(record)
        sequence += 1
    with (run.directory / 'stream.jsonl').open('w', encoding='utf-8') as output:
        for record in records:
            output.write(json.dumps(record) + '\n')
    publish(
        run.directory / 'stream-clock.json',
        {'epoch': epoch, 'stop': stop, 'slots': sequence, 'cpus': _cpus()},
    )


def _send(
    session: requests.Session,
    run: Run,
    seq: int,
    due: float,
    event: dict[str, object] | None = None,
) -> dict[str, object]:
    """Time one real call with its own client and an exclusively held transport."""
    attempts: list[dict[str, object]] = []
    if event is None:
        event = {}
    event.update(sequence=seq, due=due, attempts=attempts)
    send = session.send

    def observed(request: requests.PreparedRequest, **kwargs: object) -> requests.Response:
        attempt_id = f'stream-{seq}-{len(attempts)}'
        request.headers['X-Farm-Phase'] = 'stream'
        request.headers['X-Farm-Attempt'] = attempt_id
        start = time.monotonic()
        if not attempts:
            event.update(
                start_monotonic=start, slot='late' if start - due > LATE_SECONDS else 'sent'
            )
        trace: dict[str, object] = {
            'attempt_id': attempt_id,
            'start_monotonic': start,
            'start': time.time(),
        }
        attempts.append(trace)
        try:
            with _transport.attempt(trace):
                response = send(request, **kwargs)
        except requests.RequestException as exc:
            record_send_error(trace, exc)
            raise
        finally:
            trace['finish_monotonic'] = time.monotonic()
        record_response(trace, response)
        return response

    sleeps: list[tuple[float, float, int]] = []
    context = _RETRY.set((attempts, sleeps))
    session.send = observed
    try:
        client = BrokerClient(run.url, 'farm-1', run.credential(1), session=session)
        event['acquisition_start'] = time.monotonic()
        try:
            result = client.fetch_token('warm')
        finally:
            event['finish_monotonic'] = time.monotonic()
        token = result.token
        event['generation'] = int(token.partition('.')[0])
    except BrokerClientError:
        event['terminal_error'] = 'BrokerClientError'
    finally:
        _RETRY.reset(context)
        event['retry_sleeps'] = sleeps
        session.send = send
    return event


def _sleep(delay: float) -> None:
    """Measure the shipping retry sleep for the calling warm acquisition."""
    context = _RETRY.get()
    start = time.monotonic()
    time.sleep(delay)
    if context is not None:
        attempts, sleeps = context
        sleeps.append((start, time.monotonic(), len(attempts) - 1))


def finished(run: Run) -> bool:
    """Return whether the warm stream may stop.

    The global stop marker ends every run. After probe stop, a slow control
    continues through its five-second reference interval.

    Raises:
        OSError: If a reference artifact cannot be read.
        ValueError: If a reference timestamp or JSON record is invalid.
        KeyError: If a mint record lacks its scope or a non-warm mint lacks its
            monotonic start.
        TypeError: If a reference record has an incompatible JSON type.
    """
    if (run.directory / 'stop').exists():
        return True
    if not (run.directory / 'probe-stop').exists():
        return False
    if run.scenario != 'slow-control':
        return True
    starts = [
        float(str(m['started_monotonic']))
        for m in rows(run.directory / 'mints.jsonl')
        if m['scope'] != 'warm'
    ]
    if starts:
        return time.monotonic() >= min(starts) + 5
    marker = run.directory / 'fleet-finished.json'
    return marker.exists() and time.monotonic() >= float(json.loads(marker.read_text())) + 5


def _monitor(run: Run, ready: threading.Event, ending: threading.Event) -> None:
    """Publish readiness and poll stop markers off the scheduling thread."""
    announced = False
    while not ending.is_set():
        if ready.is_set() and not announced:
            publish(run.directory / 'stream-ready.json', value=True)
            announced = True
        if finished(run):
            ending.set()
            return
        ending.wait(0.05)


def run_stream(run: Run, sessions: list[requests.Session]) -> None:
    """Drive fixed-cadence warm acquisitions and publish the completed slot ledger.

    Args:
        run: Workload and directory containing phase signals and output
            artifacts.
        sessions: Caller-owned transports lent exclusively to individual
            acquisitions.

    Raises:
        OSError: If the worker cannot read run fixtures or write evidence.
        ValueError: If required reference data cannot be decoded.
        RuntimeError: If a scheduling worker cannot be started.
        KeyError: If a mint record lacks its scope or a non-warm mint lacks its
            monotonic start.
        TypeError: If a reference record has an incompatible JSON type.
    """
    idle: queue.SimpleQueue[requests.Session] = queue.SimpleQueue()
    for session in sessions:
        idle.put(session)
    records: list[dict[str, object]] = []
    ending = threading.Event()
    ready = threading.Event()

    def dispatch(session: requests.Session, event: dict[str, object]) -> None:
        try:
            _send(session, run, int(str(event['sequence'])), float(str(event['due'])), event)
            ready.set()
        except BaseException:
            ending.set()
            raise
        finally:
            idle.put(session)

    with (
        ThreadPoolExecutor(max_workers=SLOTS + 1) as pool,
        patch.object(_client, 'RetryTiming', lambda: RetryTiming(sleep=_sleep)),
    ):
        watcher = pool.submit(_monitor, run, ready, ending)
        watcher.add_done_callback(lambda _: ending.set())
        jobs: list[Future[None]] = []
        epoch = time.monotonic()
        sequence = 0
        while not ending.is_set():
            due = epoch + sequence * PERIOD
            now = time.monotonic()
            if now < due:
                ending.wait(due - now)
                continue
            occupants = _occupants(records, due)
            record: dict[str, object] = {'sequence': sequence, 'due': due, 'wake': now}
            records.append(record)
            if len(occupants) == SLOTS:
                record.update(slot='suppressed', outstanding=occupants)
            elif idle.empty():
                record.update(slot='late')
            else:
                jobs.append(pool.submit(dispatch, idle.get_nowait(), record))
            sequence += 1
        stop = time.monotonic()
        watcher.result()
        for job in jobs:
            job.result()
    _publish_slots(run, records, epoch, stop)
