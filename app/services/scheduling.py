"""
Scheduling service — cadence preset → next firing time.

Pure, framework-free helpers used by the schedule REST API and the
``tick_scheduled_analyses`` Celery task. No DB, no Celery, no settings —
the caller passes a schedule snapshot, the function returns a UTC datetime.

Cadence semantics (UTC, computed against ``hour_utc``):
  DAILY      — fires every day at hour_utc
  WEEKLY     — fires on day_of_week (0=Mon … 6=Sun) at hour_utc
  BIWEEKLY   — fires on day_of_week every 14 days, anchored to the most
                recent occurrence of that weekday
  MONTHLY    — fires on day_of_month (1..28) at hour_utc
  QUARTERLY  — fires on day_of_month at hour_utc, every 3rd month
  CUSTOM     — fires per cron_expression (5-field cron)

We deliberately cap day_of_month at 28 to sidestep Feb-29/Feb-30/Feb-31
edge cases — a "monthly on the 31st" preset would silently skip months
shorter than 31 days, which is a user-hostile surprise.

The 'timezone' field on the schedule is stored for *display* only — all
firing decisions happen in UTC against ``hour_utc``. This keeps DST
transitions out of the scheduler's hot path; the UI is responsible for
rendering "02:00 UTC" as "07:30 IST" or whatever the operator prefers.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

# Optional dependency — only used when cadence='CUSTOM'. The standard
# library has no cron parser, so cron presets work even if croniter
# isn't installed; full cron expressions raise a friendly error.
try:
    from croniter import croniter as _croniter
except ImportError:  # pragma: no cover - optional
    _croniter = None


VALID_CADENCES = frozenset({"DAILY", "WEEKLY", "BIWEEKLY", "MONTHLY", "QUARTERLY", "CUSTOM"})


@dataclass(frozen=True)
class ScheduleSpec:
    """Immutable snapshot of the scheduling fields needed to compute next_run_at.

    Decoupled from the SQLAlchemy model so unit tests don't need a DB.
    """

    cadence: str
    cron_expression: str | None = None
    day_of_week: int | None = None  # 0=Mon..6=Sun
    day_of_month: int | None = None  # 1..28
    hour_utc: int = 2


class ScheduleValidationError(ValueError):
    """Raised when a ScheduleSpec is malformed for its cadence."""


def validate_spec(spec: ScheduleSpec) -> None:
    """Raise ScheduleValidationError if the spec is internally inconsistent."""
    if spec.cadence not in VALID_CADENCES:
        raise ScheduleValidationError(
            f"cadence must be one of {sorted(VALID_CADENCES)}, got {spec.cadence!r}"
        )
    if not (0 <= spec.hour_utc <= 23):
        raise ScheduleValidationError("hour_utc must be in [0, 23]")

    if spec.cadence in {"WEEKLY", "BIWEEKLY"}:
        if spec.day_of_week is None:
            raise ScheduleValidationError(f"{spec.cadence} requires day_of_week (0=Mon..6=Sun)")
        if not (0 <= spec.day_of_week <= 6):
            raise ScheduleValidationError("day_of_week must be in [0, 6]")

    if spec.cadence in {"MONTHLY", "QUARTERLY"}:
        if spec.day_of_month is None:
            raise ScheduleValidationError(f"{spec.cadence} requires day_of_month (1..28)")
        if not (1 <= spec.day_of_month <= 28):
            raise ScheduleValidationError("day_of_month must be in [1, 28]")

    if spec.cadence == "CUSTOM":
        if not (spec.cron_expression and spec.cron_expression.strip()):
            raise ScheduleValidationError("CUSTOM cadence requires cron_expression")
        if _croniter is None:
            raise ScheduleValidationError(
                "CUSTOM cadence needs the 'croniter' package; pip install croniter"
            )
        if not _croniter.is_valid(spec.cron_expression):
            raise ScheduleValidationError(f"invalid cron expression: {spec.cron_expression!r}")


def _ensure_utc(dt: datetime) -> datetime:
    """Coerce a datetime to a tz-aware UTC datetime (treat naive as UTC)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _at_hour(d: datetime, hour: int) -> datetime:
    """Return ``d`` with hour=hour, minute=0, second=0, microsecond=0 (UTC)."""
    return d.replace(hour=hour, minute=0, second=0, microsecond=0)


def _add_months(d: datetime, months: int) -> datetime:
    """Add N calendar months, clamping day to ≤ 28 (callers always pass ≤ 28)."""
    total_months = d.month - 1 + months
    new_year = d.year + total_months // 12
    new_month = total_months % 12 + 1
    return d.replace(year=new_year, month=new_month)


def compute_next_run_at(spec: ScheduleSpec, now: datetime) -> datetime:
    """
    Return the next UTC firing time strictly **after** ``now``.

    "After" not "at-or-after" — bumping ``next_run_at`` after a fire must
    advance the cursor, otherwise the tick task would re-fire the same
    schedule on the next pass.

    Catch-up rule: if the most recent slot is in the past (e.g. beat was
    down for 2 days), we fast-forward to the first slot strictly in the
    future. We do **not** schedule backlogged catch-up runs — see Plan §
    "Catch-up on miss".
    """
    validate_spec(spec)
    now = _ensure_utc(now)

    if spec.cadence == "DAILY":
        candidate = _at_hour(now, spec.hour_utc)
        if candidate <= now:
            candidate += timedelta(days=1)
        return candidate

    if spec.cadence == "WEEKLY":
        # Python weekday(): Monday=0..Sunday=6 — matches our DOW convention.
        delta_days = (spec.day_of_week - now.weekday()) % 7
        candidate = _at_hour(now + timedelta(days=delta_days), spec.hour_utc)
        if candidate <= now:
            candidate += timedelta(days=7)
        return candidate

    if spec.cadence == "BIWEEKLY":
        delta_days = (spec.day_of_week - now.weekday()) % 7
        candidate = _at_hour(now + timedelta(days=delta_days), spec.hour_utc)
        if candidate <= now:
            candidate += timedelta(days=14)
        return candidate

    if spec.cadence == "MONTHLY":
        candidate = _at_hour(now.replace(day=spec.day_of_month), spec.hour_utc)
        if candidate <= now:
            candidate = _add_months(candidate, 1)
        return candidate

    if spec.cadence == "QUARTERLY":
        candidate = _at_hour(now.replace(day=spec.day_of_month), spec.hour_utc)
        while candidate <= now:
            candidate = _add_months(candidate, 3)
        return candidate

    # CUSTOM
    assert _croniter is not None  # validate_spec already enforced this
    return _croniter(spec.cron_expression, now).get_next(datetime).astimezone(UTC)


def compute_failure_backoff(consecutive_failures: int, base: datetime) -> datetime:
    """
    Compute next_run_at after a failed run.

    Exponential: 1h, 2h, 4h, 8h, 16h, capped at 24h. Keeps a flapping
    integration (e.g. an upstream NVD outage) from drowning the queue
    while still attempting recovery within a day.
    """
    base = _ensure_utc(base)
    hours = min(1 << max(0, consecutive_failures - 1), 24)
    return base + timedelta(hours=hours)


def to_iso(dt: datetime) -> str:
    """Project-standard ISO8601 in UTC, microsecond-stripped."""
    return _ensure_utc(dt).replace(microsecond=0).isoformat()
