"""Serve synthetic SG requests on loopback and record mint evidence by broker incarnation."""

import json
import secrets
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast
from urllib.parse import parse_qs

from sg_token_broker._secrets import token_fingerprint


class FakeSG(ThreadingHTTPServer):
    """Serve synthetic SG mint and session-probe requests on loopback.

    Start `serve_forever` in a worker and call `shutdown` from its supervisor.
    Call `flush` to persist buffered observations. The server context closes
    the listening socket on exit.
    """

    # Eight broker processes can each have eight concurrent upstream calls.
    request_queue_size = 128

    def __init__(self, directory: Path) -> None:
        """Bind an ephemeral loopback listener with healthy, empty mint state.

        Args:
            directory: Run directory for mint, probe and broker-retirement
                evidence.

        Raises:
            OSError: If the fixture cannot create or bind the listening socket.
        """
        super().__init__(('127.0.0.1', 0), _Handler)
        self._log = directory / 'mints.jsonl'
        self._probes = directory / 'probes.jsonl'
        self._retired = directory / 'retired-broker.json'
        self._pending: list[tuple[Path, dict[str, object]]] = []
        self._issued: dict[str, int] = {}
        self._lock = threading.Lock()
        self._reply = threading.Event()
        self._reply.set()
        self._generation = 0
        self._latency = 0.0
        self._unavailable_until = 0.0
        self._refuse = False
        self._rejected_through = 0

    def activate(self, scenario: str) -> dict[str, float | int]:
        """Apply the selected fault and snapshot its activation boundary.

        Args:
            scenario: Workload selecting latency, refusal, outage, token
                rejection or a restart reply gate.

        Returns:
            The wall and monotonic activation times, current generation,
            rejection cutoff and monotonic outage deadline.
        """
        with self._lock:
            start = time.monotonic()
            wall = time.time()
            self._latency = 5.0 if scenario == 'slow-sg' else 0.0
            self._refuse = scenario == 'rejected-script-key'
            if scenario == 'process-restart':
                self._reply.clear()
            if scenario == 'sg-outage':
                self._unavailable_until = start + 30
            if scenario == 'rejected-tokens':
                self._rejected_through = self._generation
            return {
                'cutoff': self._rejected_through,
                'generation_at_activation': self._generation,
                'monotonic': start,
                'time': wall,
                'unavailable_until_monotonic': self._unavailable_until,
            }

    def flush(self) -> None:
        """Drain pending mint and probe records in order within each output stream.

        Raises:
            OSError: If appending a detached batch fails. Unwritten records
                from that batch are no longer queued.
        """
        with self._lock:
            records, self._pending = self._pending, []
        for path in (self._log, self._probes):
            batch = [record for destination, record in records if destination == path]
            if batch:
                with path.open('a', encoding='utf-8') as stream:
                    stream.writelines(json.dumps(record) + '\n' for record in batch)

    def mint(self, process: str, scope: str, kind: str) -> tuple[HTTPStatus, dict[str, object]]:
        """Prepare a synthetic SG mint response and buffer its sanitized observation.

        Args:
            process: Broker incarnation requesting the mint.
            scope: Script identity supplied in the request.
            kind: `session` selects an RPC response and `rest` selects an
                access-token response.

        Returns:
            HTTP status and protocol-specific body after any restart reply gate
            opens.
        """
        started = time.time()
        with self._lock:
            monotonic = time.monotonic()
            unavailable = monotonic < self._unavailable_until
            latency = self._latency
            refuse = self._refuse
        if latency:
            time.sleep(latency)
        with self._lock:
            record: dict[str, object] = {
                'started': started,
                'started_monotonic': monotonic,
                'finished_monotonic': time.monotonic(),
                'finished': time.time(),
                'process': process,
                'scope': scope,
                'token_type': kind,
                'rejected_through': self._rejected_through,
            }
            status = HTTPStatus.OK
            body: dict[str, object]
            if unavailable:
                status, body = HTTPStatus.SERVICE_UNAVAILABLE, {}
                record['outcome'] = 'unavailable'
            elif refuse:
                status = HTTPStatus.OK if kind == 'session' else HTTPStatus.UNAUTHORIZED
                body = {'exception': True, 'error_code': 102, 'message': 'fixture refusal'}
                record['outcome'] = 'refused'
            else:
                self._generation += 1
                token = f'{self._generation}.{secrets.token_urlsafe(32)}'
                self._issued[token] = self._generation
                body = (
                    {'session_id': token}
                    if kind == 'session'
                    else {'access_token': token, 'expires_in': 3600}
                )
                record.update(
                    generation=self._generation,
                    token_fp=token_fingerprint(token),
                    outcome='minted',
                )
            self._pending.append((self._log, record))
        # Keep the original broker inside its first upstream request until the
        # supervisor restarts it, even for a one-machine diagnostic workload.
        self._reply.wait()
        return status, body

    def probe(self, token: str) -> dict[str, object]:
        """Record session use and apply the fixture's rejection cutoff.

        Returns:
            A session-ID response for an accepted generation, or an RPC
            authentication fault for an unknown or rejected token.
        """
        with self._lock:
            generation = self._issued.get(token)
            accepted = generation is not None and generation > self._rejected_through
            self._pending.append(
                (
                    self._probes,
                    {
                        'time': time.time(),
                        'monotonic': time.monotonic(),
                        'generation': generation,
                        'accepted': accepted,
                        'token_fp': token_fingerprint(token),
                    },
                )
            )
        if accepted:
            return {'session_id': token}
        return {'exception': True, 'error_code': 102, 'message': 'rejected session'}

    def release_replies(self) -> None:
        """Open the reply gate for all waiting and subsequent mints."""
        self._reply.set()

    def retired(self, process: str) -> bool:
        """Return whether the retirement marker names this broker incarnation.

        Raises:
            OSError: If a present retirement marker cannot be read.
            ValueError: If the marker is not valid JSON.
        """
        return self._retired.exists() and json.loads(self._retired.read_bytes()) == process


class _Handler(BaseHTTPRequestHandler):
    """Accept the two wire formats used by the production SG minter."""

    def _respond(self, status: HTTPStatus, body: dict[str, object]) -> None:
        """Write a JSON reply for a mint or an account session probe."""
        encoded = json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self) -> None:
        """Serve the fixture's session probe, session mint and REST mint routes.

        Raises:
            OSError: If reading or answering a request fails, or the retirement
                marker cannot be read. Broken pipes and connection resets are
                ignored when the marker confirms the mint peer retired.
            ValueError: If the retirement marker cannot be decoded while
                checking a disconnected mint peer.
        """
        process, _, route = self.path.lstrip('/').partition('/')
        raw = self.rfile.read(int(self.headers['Content-Length']))
        if route == 'api3/json':
            params = json.loads(raw)['params'][0]
            if 'session_token' in params:
                self._respond(
                    HTTPStatus.OK, cast('FakeSG', self.server).probe(str(params['session_token']))
                )
                return
            scope = str(params['script_name'])
            kind = 'session'
        elif route == 'api/v1.1/auth/access_token':
            scope = parse_qs(raw.decode())['client_id'][0]
            kind = 'rest'
        else:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        fixture = cast('FakeSG', self.server)
        status, body = fixture.mint(process, scope, kind)
        try:
            self._respond(status, body)
        except (BrokenPipeError, ConnectionResetError):
            if not fixture.retired(process):
                raise

    def log_message(self, *args: object, **kwargs: object) -> None:
        """Keep HTTP bodies and URLs out of benchmark output."""
