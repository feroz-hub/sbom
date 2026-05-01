"""Run-count metrics. Spec §3.6."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import AnalysisRun
from .base import COMPLETED_RUN_STATUSES


def runs_total_lifetime(db: Session) -> int:
    """runs.total_lifetime — see metrics-spec.md §3.6.

    Every run, all statuses (incl. ERROR/RUNNING/PENDING). The Q3 lock —
    "runs executed" reads honestly when failed runs still count.
    """
    return db.execute(select(func.count(AnalysisRun.id))).scalar() or 0


def runs_completed_lifetime(db: Session) -> int:
    """runs.completed_lifetime — see metrics-spec.md §3.6.

    Count of successful runs (OK/FINDINGS/PARTIAL).
    """
    return (
        db.execute(
            select(func.count(AnalysisRun.id)).where(
                AnalysisRun.run_status.in_(COMPLETED_RUN_STATUSES)
            )
        ).scalar()
        or 0
    )


def runs_completed_this_week(db: Session) -> int:
    """runs.completed_this_week — see metrics-spec.md §3.6.

    Q6 lock: count by ``completed_on`` (not ``started_on``). A run that
    started 8 days ago and finished yesterday is "this week's work".
    """
    one_week_ago = (datetime.now(UTC) - timedelta(days=7)).isoformat()
    return (
        db.execute(
            select(func.count(AnalysisRun.id)).where(
                AnalysisRun.completed_on >= one_week_ago
            )
        ).scalar()
        or 0
    )


def runs_distinct_dates_with_data(db: Session) -> int:
    """runs.distinct_dates_with_data — see metrics-spec.md §3.6.

    Drives the trend empty-state condition: ``< 7`` distinct dates → empty.
    Uses ``substr(started_on, 1, 10)`` to extract YYYY-MM-DD without a
    backend-specific date cast (SQLite + Postgres parity).
    """
    return (
        db.execute(
            select(
                func.count(func.distinct(func.substr(AnalysisRun.started_on, 1, 10)))
            ).where(AnalysisRun.run_status.in_(COMPLETED_RUN_STATUSES))
        ).scalar()
        or 0
    )


def runs_first_completed_at(db: Session) -> str | None:
    """runs.first_completed_at — see metrics-spec.md §3.6.

    Earliest ``completed_on`` over successful runs, ISO-8601 string.
    ``None`` until the first successful run.
    """
    return db.execute(
        select(func.min(AnalysisRun.completed_on)).where(
            AnalysisRun.run_status.in_(COMPLETED_RUN_STATUSES)
        )
    ).scalar()


__all__ = [
    "runs_total_lifetime",
    "runs_completed_lifetime",
    "runs_completed_this_week",
    "runs_distinct_dates_with_data",
    "runs_first_completed_at",
]
