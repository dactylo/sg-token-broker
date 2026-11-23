"""Choose when a token acquisition can retry a failed request."""

import calendar
import datetime
import math
import random
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from http import HTTPStatus
from typing import Literal, TypeAlias

__all__ = [
    'DEFAULT_MAX_WAIT_SECONDS',
    'DEFAULT_REFRESH_MARGIN_SECONDS',
    'DEFAULT_RETRIES',
    'DEFAULT_TIMEOUT_SECONDS',
    'AcquisitionFailureError',
    'Budget',
    'RetryDecision',
    'RetryTiming',
    'cold_delay',
    'decide',
    'first_refresh_time',
    'parse_retry_after',
    'renewal_delay',
    'validate_tuning',
]

DEFAULT_MAX_WAIT_SECONDS = 300.0
DEFAULT_REFRESH_MARGIN_SECONDS = 60.0
DEFAULT_RETRIES: int | None = None
DEFAULT_TIMEOUT_SECONDS = 10.0

RetryDecision: TypeAlias = Literal['retry', 'fail']
_FailureReason: TypeAlias = Literal['budget', 'attempts', 'terminal']

_DAY = r'(?P<day>[0-9]{2})'
_MONTH = r'(?P<month>[A-Z][a-z]{2})'
_MONTH_NAMES = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')
_SERVER_ERRORS = range(500, 600)
_SHORT_YEAR_DIGITS = 2
_TIME = r'(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})'
_WEEKDAY = r'[A-Z][a-z]{2}'
_WEEKDAY_NAMES = ('Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun')
_YEAR = r'(?P<year>[0-9]{4})'

_HTTP_DATES = (
    re.compile(rf'{_WEEKDAY}, {_DAY} {_MONTH} {_YEAR} {_TIME} GMT'),
    re.compile(
        rf'(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), '
        rf'{_DAY}-{_MONTH}-(?P<year>[0-9]{{2}}) {_TIME} GMT'
    ),
    re.compile(rf'{_WEEKDAY} {_MONTH} (?P<day>[ 0-9][0-9]) {_TIME} {_YEAR}'),
)


class AcquisitionFailureError(Exception):
    """Describe why a client stopped trying to acquire a token.

    Attributes:
        reason: Whether the budget, request allowance or a terminal failure
            stopped the call.
        last_failure: Description of the last failure for the caller.
        permitted_in: Seconds until another request is permitted, if known.
    """

    def __init__(
        self,
        reason: _FailureReason,
        last_failure: str | None,
        permitted_in: float | None = None,
        *,
        retry_after_from: Literal['broker', 'service'] | None = None,
    ) -> None:
        """Record why acquisition stopped and the failure observed by this caller.

        Args:
            reason: Whether the budget, attempt allowance or a terminal failure
                stopped the call.
            last_failure: Earlier failure description, or `None` if none was
                observed.
            permitted_in: Seconds until another request is permitted, if known.
            retry_after_from: Source of a service-imposed delay, if one was
                supplied.
        """
        super().__init__(last_failure)
        self.reason: _FailureReason = reason
        self.last_failure = last_failure
        self.permitted_in = permitted_in
        self._retry_after_from = retry_after_from

    def describe(self, *, attempts: int, retries: int | None, max_wait: float) -> str:
        """Describe the stopping rule and any failure observed by this caller.

        Args:
            attempts: Requests sent by this caller.
            retries: Configured cap on additional requests.
            max_wait: Request-start budget in seconds.
        """
        if self.reason == 'attempts':
            message = f'no token after {attempts} attempt(s) (retries={retries})'
        elif self.permitted_in is not None:
            message = (
                f'next request permitted in {self.permitted_in:g}s, beyond max_wait {max_wait:g}s'
            )
            if self._retry_after_from is not None:
                message += f' (Retry-After from the {self._retry_after_from})'
        elif self.reason == 'terminal':
            return self.last_failure or 'token request failed'
        else:
            message = f'max_wait {max_wait:g}s exhausted'
        if self.last_failure is not None:
            message += f'; last failure: {self.last_failure}'
        return message


class Budget:
    """Limit request starts to times strictly before a fixed monotonic deadline.

    Attributes:
        deadline: First monotonic timestamp at which a request may no longer
            start.
    """

    def __init__(self, max_wait: float, clock: Callable[[], float]) -> None:
        """Start the budget at the current monotonic time.

        Args:
            max_wait: Number of seconds available for starting requests.
            clock: Source of monotonic timestamps in seconds.
        """
        self.deadline = clock() + max_wait

    def can_start(self, at: float) -> bool:
        """Return whether the proposed monotonic timestamp is within the budget."""
        return at < self.deadline


@dataclass(frozen=True)
class RetryTiming:
    """Supply the monotonic clock, delay and jitter used by acquiring clients.

    Attributes:
        clock: Return a monotonic timestamp in seconds.
        sleep: Wait for the requested number of seconds.
        rng: Draw a fraction from zero to one.
    """

    clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep
    rng: Callable[[], float] = random.random


def _finite(value: float) -> bool:
    """Return whether a supplied duration represents a finite number of seconds."""
    try:
        return math.isfinite(value)
    except (TypeError, OverflowError):
        return False


def _http_date_delay(match: re.Match[str], now: datetime.datetime) -> float | None:
    """Return seconds until an HTTP-date after resolving its year and weekday."""
    year = int(match['year'])
    month = _MONTH_NAMES.index(match['month']) + 1
    day, hour, minute, second = (int(match[key]) for key in ('day', 'hour', 'minute', 'second'))
    if len(match['year']) == _SHORT_YEAR_DIGITS:
        # Interpret the latest matching year no more than 50 years after receipt.
        utc = now.astimezone(datetime.UTC)
        last_year = utc.year + 50
        if (month, day, hour, minute, second) > utc.timetuple()[1:6]:
            last_year -= 1
        year = last_year - (last_year - year) % 100
    leap_second = (hour, minute, second) == (23, 59, 60) and day == calendar.monthrange(
        year, month
    )[1]
    # datetime cannot represent 23:59:60. Validate the weekday before accounting for it.
    when = datetime.datetime(
        year, month, day, hour, minute, 59 if leap_second else second, tzinfo=datetime.UTC
    )
    if not match[0].startswith(_WEEKDAY_NAMES[when.weekday()]):
        return None
    delay = (when - now).total_seconds()
    return max(0.0, delay + 1.0 if leap_second else delay)


def cold_delay(attempt: int, retry_after: float | None, *, rng: Callable[[], float]) -> float:
    """Return the header delay plus full jitter over a capped exponential backoff, in seconds.

    Args:
        attempt: Zero-based index of the retry.
        retry_after: Minimum delay in seconds, or None when no valid header was
            supplied.
        rng: Draw a fraction from zero to one.
    """
    step = 0.5 * 2 ** min(attempt, 3)
    return (retry_after if retry_after is not None else 0.0) + rng() * step


def decide(status: int | None, error_code: str | None) -> RetryDecision:
    """Classify a transport failure or an HTTP response for retry.

    Args:
        status: HTTP status, or None for a transport failure.
        error_code: Service error code if present in the response.
    """
    if status is None or status == HTTPStatus.TOO_MANY_REQUESTS:
        return 'retry'
    if status in _SERVER_ERRORS and error_code not in {'sg_rejected', 'sg_invalid_response'}:
        return 'retry'
    return 'fail'


def first_refresh_time(
    expires_at: datetime.datetime,
    received_at: datetime.datetime,
    margin: float,
    *,
    rng: Callable[[], float],
) -> datetime.datetime:
    """Spread the first refresh over the minute before the margin, clamped to receipt.

    Args:
        expires_at: Token's UTC reuse deadline.
        received_at: UTC timestamp when the client received the token.
        margin: Seconds before expiry to begin refreshing.
        rng: Draw a fraction from zero to one.
    """
    return max(received_at, expires_at - datetime.timedelta(seconds=margin + rng() * 60.0))


def parse_retry_after(value: str | None, now: datetime.datetime) -> float | None:
    """Return a finite, nonnegative delay in seconds, or None for an absent or malformed header.

    Args:
        value: Retry-After header containing delta-seconds or an HTTP-date.
        now: Timezone-aware wall-clock timestamp at receipt.
    """
    if value is None:
        return None
    value = value.strip(' \t')
    if value.isascii() and value.isdecimal():
        seconds = float(value)
        return seconds if math.isfinite(seconds) else None
    for pattern in _HTTP_DATES:
        match = pattern.fullmatch(value)
        if match:
            try:
                return _http_date_delay(match, now)
            except ValueError:
                return None
    return None


def renewal_delay(retry_after: float | None, *, rng: Callable[[], float]) -> float:
    """Spread the next renewal over 50 seconds starting at the permitted delay.

    Args:
        retry_after: Minimum delay in seconds, or None for the ten-second
            minimum.
        rng: Draw a fraction from zero to one.

    Returns:
        Seconds until the next permitted request.
    """
    return (retry_after if retry_after is not None else 10.0) + rng() * 50.0


def validate_tuning(
    *, timeout: float, retries: object, refresh_margin: float, max_wait: float
) -> None:
    """Validate client settings before resolving credentials or endpoints.

    Args:
        timeout: Positive finite per-attempt timeout in seconds.
        retries: Non-negative integer retry count or None for no cap.
        refresh_margin: Non-negative finite renewal margin in seconds.
        max_wait: Positive finite request-start budget in seconds.

    Raises:
        ValueError: If a setting violates its range or type.
    """
    if not (_finite(timeout) and timeout > 0):
        raise ValueError(f'timeout must be finite and greater than zero, got {timeout}')
    if retries is not None and (
        not isinstance(retries, int) or isinstance(retries, bool) or retries < 0
    ):
        raise ValueError(f'retries must be a non-negative integer or None, got {retries}')
    if not (_finite(refresh_margin) and refresh_margin >= 0):
        raise ValueError(f'refresh_margin must be finite and >= 0 seconds, got {refresh_margin}')
    if not (_finite(max_wait) and max_wait > 0):
        raise ValueError(f'max_wait must be finite and greater than zero, got {max_wait}')
