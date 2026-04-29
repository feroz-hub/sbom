"""Unit tests for app.services.scheduling — pure functions, no DB needed."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.services.scheduling import (
    ScheduleSpec,
    ScheduleValidationError,
    compute_failure_backoff,
    compute_next_run_at,
    validate_spec,
)


def _utc(*args) -> datetime:
    return datetime(*args, tzinfo=UTC)


# ---------------------------------------------------------------------------
# validate_spec
# ---------------------------------------------------------------------------


def test_validate_rejects_unknown_cadence():
    with pytest.raises(ScheduleValidationError):
        validate_spec(ScheduleSpec(cadence="HOURLY"))


def test_validate_rejects_out_of_range_hour():
    with pytest.raises(ScheduleValidationError):
        validate_spec(ScheduleSpec(cadence="DAILY", hour_utc=24))


def test_validate_weekly_requires_day_of_week():
    with pytest.raises(ScheduleValidationError):
        validate_spec(ScheduleSpec(cadence="WEEKLY"))


def test_validate_monthly_caps_day_of_month_at_28():
    with pytest.raises(ScheduleValidationError):
        validate_spec(ScheduleSpec(cadence="MONTHLY", day_of_month=29))


# ---------------------------------------------------------------------------
# compute_next_run_at — every cadence path
# ---------------------------------------------------------------------------


def test_daily_today_if_hour_not_yet_passed():
    spec = ScheduleSpec(cadence="DAILY", hour_utc=14)
    now = _utc(2026, 4, 29, 10, 0)
    assert compute_next_run_at(spec, now) == _utc(2026, 4, 29, 14, 0)


def test_daily_tomorrow_if_hour_passed():
    spec = ScheduleSpec(cadence="DAILY", hour_utc=2)
    now = _utc(2026, 4, 29, 10, 0)
    assert compute_next_run_at(spec, now) == _utc(2026, 4, 30, 2, 0)


def test_weekly_picks_correct_weekday():
    # Wed Apr 29 2026 → next Monday is May 4 2026
    spec = ScheduleSpec(cadence="WEEKLY", day_of_week=0, hour_utc=2)
    now = _utc(2026, 4, 29, 10, 0)
    assert compute_next_run_at(spec, now) == _utc(2026, 5, 4, 2, 0)


def test_weekly_skips_to_next_week_when_today_already_passed():
    # Same weekday as 'now', but hour already passed → +7 days
    spec = ScheduleSpec(cadence="WEEKLY", day_of_week=2, hour_utc=2)  # Wed @ 02:00
    now = _utc(2026, 4, 29, 10, 0)  # Wed @ 10:00
    assert compute_next_run_at(spec, now) == _utc(2026, 5, 6, 2, 0)


def test_biweekly_advances_14_days():
    spec = ScheduleSpec(cadence="BIWEEKLY", day_of_week=2, hour_utc=2)
    now = _utc(2026, 4, 29, 10, 0)  # Wed past 02:00
    assert compute_next_run_at(spec, now) == _utc(2026, 5, 13, 2, 0)


def test_monthly_this_month_if_day_not_yet_passed():
    spec = ScheduleSpec(cadence="MONTHLY", day_of_month=15, hour_utc=2)
    now = _utc(2026, 4, 29, 10, 0)  # past the 15th already
    assert compute_next_run_at(spec, now) == _utc(2026, 5, 15, 2, 0)


def test_monthly_rolls_over_to_january():
    spec = ScheduleSpec(cadence="MONTHLY", day_of_month=15, hour_utc=2)
    now = _utc(2026, 12, 28, 0, 0)
    assert compute_next_run_at(spec, now) == _utc(2027, 1, 15, 2, 0)


def test_quarterly_advances_three_months():
    spec = ScheduleSpec(cadence="QUARTERLY", day_of_month=1, hour_utc=2)
    now = _utc(2026, 4, 29, 10, 0)
    # April 1 already passed → next is July 1
    assert compute_next_run_at(spec, now) == _utc(2026, 7, 1, 2, 0)


def test_returns_strictly_future_value():
    """next_run_at must be > now even when the slot is "right now"."""
    spec = ScheduleSpec(cadence="DAILY", hour_utc=10)
    now = _utc(2026, 4, 29, 10, 0)
    nxt = compute_next_run_at(spec, now)
    assert nxt > now


# ---------------------------------------------------------------------------
# compute_failure_backoff
# ---------------------------------------------------------------------------


def test_failure_backoff_grows_then_caps():
    base = _utc(2026, 4, 29, 12, 0)
    # 1 → 1h, 2 → 2h, 3 → 4h, 4 → 8h, 5 → 16h, 6 → 24h (cap), 7 → 24h
    assert compute_failure_backoff(1, base) - base == timedelta(hours=1)
    assert compute_failure_backoff(2, base) - base == timedelta(hours=2)
    assert compute_failure_backoff(5, base) - base == timedelta(hours=16)
    assert compute_failure_backoff(6, base) - base == timedelta(hours=24)
    assert compute_failure_backoff(99, base) - base == timedelta(hours=24)
