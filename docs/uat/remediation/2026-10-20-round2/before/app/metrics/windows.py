"""Time-window metrics — net change with first-period signaling. Spec §3.7."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import AnalysisRun
from .base import COMPLETED_RUN_STATUSES, NetChangeResult
from .cache import memoize_with_ttl
from .findings import findings_distinct_active_as_of


def findings_net_change(db: Session, *, days: int = 7) -> NetChangeResult:
    """findings.net_change — see metrics-spec.md §3.7.

    The Bug 5 lock: when no successful run completed strictly before
    ``today − days``, the comparison is undefined. ``is_first_period=True``
    is set; the FE renders "first scan this week" instead of ``+N / −0``.

    Caching: 5 minutes (spec §6).
    """

    return memoize_with_ttl(
        name="findings.net_change",
        ttl_seconds=5 * 60,
        db=db,
        key_extra=(days,),
        compute=lambda: _compute_net_change(db, days=days),
    )


def _compute_net_change(db: Session, *, days: int) -> NetChangeResult:
    today = datetime.now(UTC).date()
    prior_date = today - timedelta(days=days)

    # is_first_period: any successful run completed strictly before the
    # start of the comparison window? If not, there is nothing to compare
    # against and "+N / −0" would be misleading.
    has_prior = (
        db.execute(
            select(func.count(AnalysisRun.id))
            .where(AnalysisRun.run_status.in_(COMPLETED_RUN_STATUSES))
            .where(AnalysisRun.completed_on < prior_date.isoformat())
        ).scalar()
        or 0
    )

    today_set = findings_distinct_active_as_of(db, as_of=today)

    if has_prior == 0:
        return NetChangeResult(
            added=len(today_set),
            resolved=0,
            is_first_period=True,
            window_days=days,
        )

    prior_set = findings_distinct_active_as_of(db, as_of=prior_date)
    return NetChangeResult(
        added=len(today_set - prior_set),
        resolved=len(prior_set - today_set),
        is_first_period=False,
        window_days=days,
    )


__all__ = ["findings_net_change"]
