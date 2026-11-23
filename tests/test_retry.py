import datetime
import re
import time
from typing import cast
from unittest.mock import Mock

import pytest

from sg_token_broker import BrokerClient, BrokerClientError, UserTokenClient, UserTokenClientError
from sg_token_broker._retry import (
    DEFAULT_MAX_WAIT_SECONDS,
    AcquisitionFailureError,
    Budget,
    RetryTiming,
    cold_delay,
    decide,
    first_refresh_time,
    parse_retry_after,
    renewal_delay,
)

_RECEIVED = datetime.datetime(2026, 11, 19, tzinfo=datetime.UTC)


def test_budget_excludes_its_deadline_despite_wall_clock_jumps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wall_time = _RECEIVED.timestamp()
    monotonic = 100.0
    with monkeypatch.context() as patch:
        patch.setattr(time, 'time', lambda: wall_time)
        budget = Budget(5.0, lambda: monotonic)
        assert budget.deadline == pytest.approx(105.0)
        wall_time += 3600
        monotonic += 4.9
        assert budget.can_start(monotonic)
        wall_time -= 7200
        monotonic = 105.0
        assert not budget.can_start(monotonic)


def test_cold_delay_increases_until_capped() -> None:
    assert [cold_delay(i, None, rng=lambda: 1.0) for i in range(8)] == pytest.approx(
        [0.5, 1, 2, 4, 4, 4, 4, 4]
    )


def test_cold_delay_jitters_only_the_backoff() -> None:
    assert cold_delay(2, None, rng=lambda: 0.25) == pytest.approx(0.5)
    assert cold_delay(2, 8.0, rng=lambda: 0.25) == pytest.approx(8.5)


@pytest.mark.parametrize(
    ('status', 'error_code', 'expected'),
    [
        (None, None, 'retry'),
        (429, 'rate_limited', 'retry'),
        (500, None, 'retry'),
        (502, None, 'retry'),
        (502, 'upstream_error', 'retry'),
        (503, 'upstream_unavailable', 'retry'),
        (503, 'server_busy', 'retry'),
        (504, None, 'retry'),
        (599, None, 'retry'),
        (502, 'sg_rejected', 'fail'),
        (502, 'sg_invalid_response', 'fail'),
        (503, 'sg_rejected', 'fail'),
        (200, None, 'fail'),
        (400, 'bad_request', 'fail'),
        (401, None, 'fail'),
        (403, None, 'fail'),
        (499, None, 'fail'),
        (600, None, 'fail'),
    ],
)
def test_decide(status: int | None, error_code: str | None, expected: str) -> None:
    assert decide(status, error_code) == expected


def test_obsolete_http_date_resolves_century_from_receipt() -> None:
    now = datetime.datetime(1999, 1, 1, tzinfo=datetime.UTC)
    assert parse_retry_after('Saturday, 01-Jan-00 00:00:00 GMT', now) == 365 * 86400
    assert parse_retry_after('Monday, 01-Jan-68 00:00:00 GMT', now) == 0.0


def test_retry_after_beyond_budget_preserves_the_permitted_delay() -> None:
    start = 100.0
    budget = Budget(DEFAULT_MAX_WAIT_SECONDS, lambda: start)
    assert budget.deadline == pytest.approx(start + 300.0)
    retry_after = parse_retry_after('86400', _RECEIVED)
    permitted_in = cold_delay(0, retry_after, rng=lambda: 0.5)
    assert not budget.can_start(start + permitted_in)
    failure = AcquisitionFailureError('budget', 'server busy', permitted_in)
    assert failure.reason == 'budget'
    assert failure.last_failure == 'server busy'
    assert failure.permitted_in == pytest.approx(86400.25)


def test_retry_after_includes_the_leap_second() -> None:
    received = datetime.datetime(2016, 12, 31, 23, 59, 30, tzinfo=datetime.UTC)
    assert parse_retry_after('Sat, 31 Dec 2016 23:59:60 GMT', received) == 30.0


@pytest.mark.parametrize(
    ('value', 'seconds'),
    [
        ('3', 3.0),
        pytest.param('1' + '0' * 308, 1e308, id='large-finite-delay'),
        ('Thu, 19 Nov 2026 00:01:00 GMT', 60.0),
        ('Thursday, 19-Nov-26 00:01:00 GMT', 60.0),
        ('Thu Nov 19 00:01:00 2026', 60.0),
        ('Wed, 18 Nov 2026 23:59:00 GMT', 0.0),
    ],
)
def test_retry_after_seconds_and_http_dates(value: str, seconds: float) -> None:
    assert parse_retry_after(value, _RECEIVED) == pytest.approx(seconds)


@pytest.mark.parametrize(
    'value',
    [
        None,
        '',
        '-1',
        'soon',
        '+3',
        '3.5',
        '1e2',
        pytest.param('9' * 309, id='delta-seconds-overflow'),
        'Fri, 19 Nov 2026 00:01:00 GMT',
        'Friday, 19-Nov-26 00:01:00 GMT',
        'Fri Nov 19 00:01:00 2026',
        'Sat, 31 Dec 2016 22:59:60 GMT',
        'Fri, 30 Dec 2016 23:59:60 GMT',
        'Sat, 31 Dec 2016 23:59:61 GMT',
        'Thu, 31 Nov 2026 00:01:00 GMT',
        'Thu, 19 Nov 2026 00:01:00 GMT junk',
    ],
)
def test_malformed_retry_after_counts_as_absent(value: str | None) -> None:
    assert parse_retry_after(value, _RECEIVED) is None


@pytest.mark.parametrize(('header', 'expected'), [(None, 4.0), (60.0, 64.0)])
def test_cold_delay_caps_extreme_attempts(header: float | None, expected: float) -> None:
    assert cold_delay(5000, header, rng=lambda: 1.0) == pytest.approx(expected)


@pytest.mark.parametrize(
    ('header', 'draw', 'expected'),
    [(60.0, 0.1, 65.0), (60.0, 0.9, 105.0), (None, 0.0, 10.0), (None, 1.0, 60.0), (0.0, 0, 0)],
)
def test_renewal_delay(header: float | None, draw: float, expected: float) -> None:
    assert renewal_delay(header, rng=lambda: draw) == pytest.approx(expected)


@pytest.mark.parametrize(
    ('lifetime', 'draw', 'offset'), [(600, 0.0, 540), (600, 1.0, 480), (30, 1.0, 0)]
)
def test_first_refresh_spreads_before_margin_but_never_before_receipt(
    lifetime: int, draw: float, offset: int
) -> None:
    expires = _RECEIVED + datetime.timedelta(seconds=lifetime)
    assert first_refresh_time(expires, _RECEIVED, 60.0, rng=lambda: draw) == (
        _RECEIVED + datetime.timedelta(seconds=offset)
    )


@pytest.mark.parametrize('client_type', [BrokerClient, UserTokenClient])
@pytest.mark.parametrize(
    ('tuning', 'message'),
    [
        ((0, -1, -1, 0), 'timeout must be finite and greater than zero, got 0'),
        ((1, -1, -1, 0), 'retries must be a non-negative integer or None, got -1'),
        ((1, None, -1, 0), 'refresh_margin must be finite and >= 0 seconds, got -1'),
        ((1, 0, 0, 0), 'max_wait must be finite and greater than zero, got 0'),
        *[
            ((1, value, 0, 1), f'retries must be a non-negative integer or None, got {value}')
            for value in (0.5, float('nan'), float('inf'), True, False)
        ],
    ],
)
def test_clients_validate_tuning_before_resolving_connection(
    client_type: type[BrokerClient] | type[UserTokenClient],
    tuning: tuple[float, object, float, float],
    message: str,
) -> None:
    timeout, retries, refresh_margin, max_wait = tuning
    with pytest.raises(ValueError, match=f'^{re.escape(message)}$'):
        client_type(
            'http://insecure.example',
            timeout=timeout,
            retries=cast('int | None', retries),
            refresh_margin=refresh_margin,
            max_wait=max_wait,
        )


@pytest.mark.parametrize('provider', ['broker', 'service'])
@pytest.mark.parametrize('case', ['initial', 'spent', 'header', 'late-header', 'malformed'])
def test_clients_explain_the_same_budget_stops(provider: str, case: str) -> None:
    max_wait = 0.25 if case == 'malformed' else 5.0
    now = 0.0

    def clock() -> float:
        nonlocal now
        instant = now
        if case == 'initial':
            now = max_wait  # The budget expires before the first request can start.
        return instant

    def busy(*_args: object, **_kwargs: object) -> Mock:
        nonlocal now
        if case in {'spent', 'late-header'}:
            now = max_wait
        return Mock(
            status_code=503,
            headers={'Retry-After': '60' if case in {'header', 'late-header'} else 'bad'},
            json=Mock(return_value={'error': 'server_busy', 'detail': 'all workers occupied'}),
        )

    request = Mock(side_effect=busy)
    session = Mock(get=request, post=request)
    sleep = Mock(side_effect=AssertionError('out-of-budget sleep'))
    timing = RetryTiming(clock, sleep, lambda: 0.0 if case == 'spent' else 0.5)
    if provider == 'broker':
        broker = BrokerClient(
            'https://broker.example', 'farm', 's', max_wait=max_wait, session=session
        )
        broker._acquirer._timing = timing
        with pytest.raises(BrokerClientError) as caught:
            broker.fetch_token('read_all')
        failure = 'broker request failed with HTTP 503: all workers occupied'
        message = str(caught.value)
    else:
        user = UserTokenClient(
            'https://service.example',
            id_token_source=lambda: 'e30.eyJzdWIiOiJhIn0.',
            max_wait=max_wait,
            session=session,
        )
        user._retrier._timing = timing
        with pytest.raises(UserTokenClientError) as user_error:
            user.fetch_token()
        failure = 'service refused (HTTP 503 server_busy): all workers occupied'
        message = str(user_error.value)

    expected = {
        'initial': 'max_wait 5s exhausted',
        'spent': f'max_wait 5s exhausted; last failure: {failure}',
        'header': (
            'next request permitted in 60.25s, beyond max_wait 5s '
            f'(Retry-After from the {provider}); last failure: {failure}'
        ),
        'malformed': (
            f'next request permitted in 0.25s, beyond max_wait 0.25s; last failure: {failure}'
        ),
    }
    assert message == expected['header' if case == 'late-header' else case]
    assert request.call_count == (0 if case == 'initial' else 1)
    sleep.assert_not_called()
