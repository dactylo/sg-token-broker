"""Coordinate per-key app-token mints and limit the broker work they consume."""

import datetime
import hashlib
import hmac
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future
from dataclasses import dataclass
from typing import Literal, TypeAlias

from sg_token_broker._admission import ServerBusyError, WaitingShare
from sg_token_broker._sg import MintedToken, SGError, SGFailureKind, classify_sg_failure

CachedMint: TypeAlias = tuple[MintedToken, datetime.datetime]
_IssueKey: TypeAlias = tuple[str, str, str]
IssueOutcome: TypeAlias = Literal['hit', 'joined', 'minted', 'replaced']

_RATE_WINDOW_SECONDS = 60.0


@dataclass(frozen=True)
class IssuerLimits:
    """Per-process admission limits and SG failure retention.

    Attributes:
        sg_calls: Maximum simultaneous mint owners across all keys.
        failure_interval: Seconds before another attempt after SG was
            unavailable.
        refusal_interval: Seconds to remember a refusal or unusable response.
    """

    sg_calls: int = 8
    failure_interval: float = 5.0
    refusal_interval: float = 30.0


@dataclass(frozen=True)
class MintPlan:
    """Define how to mint and reuse the token for one key.

    Attributes:
        mint: Resolves the script key and calls the supplied charge callback
            immediately before sending the SG request.
        ttl: Maximum seconds to reuse a token after mint completion.
        still_valid: Additional validity check for a cached token.
    """

    mint: Callable[[Callable[[], None]], CachedMint]
    ttl: float
    still_valid: Callable[[CachedMint], bool]


class MintRateLimitedError(Exception):
    """The client's fixed mint window is full.

    Attributes:
        retry_after: Seconds remaining before another attempt is permitted.
    """

    def __init__(self, retry_after: float) -> None:
        """Record the active client's mint-window delay.

        Args:
            retry_after: Seconds until the client can attempt another mint.
        """
        super().__init__('per-client mint rate limit exceeded')
        self.retry_after = retry_after


class UpstreamFailureError(Exception):
    """SG could not supply a usable token for the key.

    Attributes:
        kind: Classification of the upstream error.
        retry_after: Seconds remaining for temporary failures, otherwise None.
    """

    def __init__(self, kind: SGFailureKind, retry_after: float | None) -> None:
        """Record the classified SG failure and any temporary retry delay.

        Args:
            kind: Upstream failure category.
            retry_after: Remaining seconds for a temporary failure, otherwise
                `None`.
        """
        super().__init__(kind)
        self.kind: SGFailureKind = kind
        self.retry_after = retry_after


class MintBudget:
    """Charge actual SG attempts to a fixed window per client."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        """Use monotonic seconds to measure windows from each client's first spend."""
        self._clock = clock
        self._lock = threading.Lock()
        self._windows: dict[str, tuple[float, int]] = {}

    def try_spend(self, client_id: str, limit: int) -> float | None:
        """Attempt to charge one mint to the client's fixed window.

        Args:
            client_id: Client whose attempts share the budget across all keys.
            limit: Maximum attempts allowed in the 60-second window.

        Returns:
            `None` after a successful spend, otherwise seconds until the window
            ends.
        """
        with self._lock:
            now = self._clock()
            end, spent = self._windows.get(client_id, (now, 0))
            if now >= end:
                end, spent = now + _RATE_WINDOW_SECONDS, 0
            if spent >= limit:
                return end - now
            self._windows[client_id] = (end, spent + 1)
            return None


@dataclass
class _Entry:
    """A completed mint with its monotonic completion time."""

    value: CachedMint
    minted_at: float
    evicted: bool = False

    def matches(self, rejected: frozenset[str]) -> bool:
        """Compare the full token digest with the caller's rejection report."""
        if not rejected:
            return False
        digest = hashlib.sha256(self.value[0].token.encode()).hexdigest()
        return any(hmac.compare_digest(digest, other) for other in rejected)

    def usable(self, plan: MintPlan, now: float) -> bool:
        """Check eviction, the cache lifetime and the token's own validity."""
        return (
            not self.evicted and now < self.minted_at + plan.ttl and plan.still_valid(self.value)
        )


class KeyedIssuer:
    """Share one active mint per key and bound both owners and waiting workers."""

    def __init__(
        self,
        *,
        waiting: WaitingShare,
        budget: MintBudget,
        limits: IssuerLimits | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Start with an empty token cache and no remembered failures.

        Args:
            waiting: Process-wide permits shared with secret verification.
            budget: Client-wide allowance charged by the mint callback.
            limits: Concurrent SG call cap and failure retention intervals.
            clock: Monotonic seconds for cache and failure expiry.
        """
        self._waiting = waiting
        self._budget = budget
        self._limits = limits if limits is not None else IssuerLimits()
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: dict[_IssueKey, _Entry] = {}
        self._active: dict[_IssueKey, Future[_Entry | None]] = {}
        self._failures: dict[_IssueKey, tuple[SGFailureKind, float]] = {}

    def _check_failure(self, key: _IssueKey, now: float) -> None:
        """Raise a remembered failure while its interval is active, under the issuer lock."""
        failure = self._failures.get(key)
        if failure is not None:
            kind, end = failure
            if now < end:
                raise UpstreamFailureError(kind, end - now if kind == 'unavailable' else None)
            del self._failures[key]

    def _live_entry(self, key: _IssueKey, plan: MintPlan, now: float) -> _Entry | None:
        """Discard an expired entry or return the live generation under the issuer lock."""
        entry = self._entries.get(key)
        if entry is not None and not entry.usable(plan, now):
            entry.evicted = True
            del self._entries[key]
            return None
        return entry

    def _mint(self, key: _IssueKey, plan: MintPlan, rate_limit: int) -> _Entry:
        """Charge at dispatch and classify SG failures before publishing the outcome."""

        def charge() -> None:
            retry_after = self._budget.try_spend(key[0], rate_limit)
            if retry_after is not None:
                raise MintRateLimitedError(retry_after)

        try:
            value = plan.mint(charge)
        except SGError as exc:
            kind = classify_sg_failure(exc)
            retry_after = self._limits.failure_interval if kind == 'unavailable' else None
            raise UpstreamFailureError(kind, retry_after) from exc
        return _Entry(value, self._clock())

    def _run_mint(
        self,
        key: _IssueKey,
        plan: MintPlan,
        rate_limit: int,
        pending: Future[_Entry | None],
        rejected: frozenset[str],
    ) -> _Entry | None:
        """Resolve current waiters and cache only a result the owner can serve."""
        try:
            entry = self._mint(key, plan, rate_limit)
            with self._lock:
                ready = entry if entry.usable(plan, self._clock()) else None
                if ready is not None and not ready.matches(rejected):
                    self._entries[key] = ready
                # Existing joiners apply their own reports even when the owner
                # cannot cache this freshly minted generation.
                pending.set_result(ready)
                del self._active[key]
        except BaseException as exc:
            with self._lock:
                pending.set_exception(exc)
                del self._active[key]
                if isinstance(exc, UpstreamFailureError):
                    interval = exc.retry_after
                    if interval is None:
                        interval = self._limits.refusal_interval
                    self._failures[key] = (exc.kind, self._clock() + interval)
            raise
        return ready

    def _start_mint(self, key: _IssueKey) -> Future[_Entry | None]:
        """Reserve an SG slot and register the new owner under the issuer lock."""
        if len(self._active) >= self._limits.sg_calls:
            raise ServerBusyError
        pending = Future[_Entry | None]()
        self._active[key] = pending
        return pending

    def issue(
        self,
        key: _IssueKey,
        plan: MintPlan,
        *,
        rate_limit: int,
        rejected: frozenset[str] = frozenset(),
    ) -> tuple[CachedMint, IssueOutcome]:
        """Serve a valid cached token or share a single mint with concurrent callers.

        Args:
            key: Client ID, scope and token type.
            plan: Mint callback and cache validity rules for this key.
            rate_limit: Client-wide maximum SG attempts per minute.
            rejected: Full lowercase SHA-256 digests of tokens SG rejected for
                this key.

        Returns:
            Minted token and expiry paired with the cache or mint outcome.

        Raises:
            ServerBusyError: The waiting share or SG call slots are full.
            MintRateLimitedError: The client's budget is spent.
            UpstreamFailureError: SG failed or its failure interval is active.
            Exception: A local mint prerequisite such as key resolution failed.
        """
        replacing = False
        while True:
            reserved = False
            try:
                with self._lock:
                    now = self._clock()
                    entry = self._live_entry(key, plan, now)
                    if entry is not None:
                        if not entry.matches(rejected):
                            return entry.value, 'hit'
                        entry.evicted = True
                        replacing = True
                        del self._entries[key]
                    self._check_failure(key, now)
                    reserved = self._waiting.try_enter()
                    if not reserved:
                        raise ServerBusyError
                    pending = self._active.get(key)
                    owner = pending is None
                    if pending is None:
                        pending = self._start_mint(key)

                entry = (
                    self._run_mint(key, plan, rate_limit, pending, rejected)
                    if owner
                    else pending.result()
                )
            finally:
                if reserved:
                    self._waiting.leave()
            with self._lock:
                if entry is not None and entry.usable(plan, self._clock()):
                    if not entry.matches(rejected):
                        if not owner:
                            return entry.value, 'joined'
                        return entry.value, 'replaced' if replacing else 'minted'
                    replacing = True
