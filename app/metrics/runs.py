"""Run-count metrics. Spec §3.6."""

from __future__ import annotations

from dataclasses import dataclass
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
            select(func.count(AnalysisRun.id)).where(AnalysisRun.run_status.in_(COMPLETED_RUN_STATUSES))
        ).scalar()
        or 0
    )


def runs_completed_this_week(db: Session) -> int:
    """runs.completed_this_week — see metrics-spec.md §3.6.

    Q6 lock: count by ``completed_on`` (not ``started_on``). A run that
    started 8 days ago and finished yesterday is "this week's work".
    """
    one_week_ago = (datetime.now(UTC) - timedelta(days=7)).isoformat()
    return db.execute(select(func.count(AnalysisRun.id)).where(AnalysisRun.completed_on >= one_week_ago)).scalar() or 0


def runs_distinct_dates_with_data(db: Session) -> int:
    """runs.distinct_dates_with_data — see metrics-spec.md §3.6.

    Drives the trend empty-state condition: ``< 7`` distinct dates → empty.
    Uses ``substr(started_on, 1, 10)`` to extract YYYY-MM-DD without a
    backend-specific date cast (SQLite + Postgres parity).
    """
    return (
        db.execute(
            select(func.count(func.distinct(func.substr(AnalysisRun.started_on, 1, 10)))).where(
                AnalysisRun.run_status.in_(COMPLETED_RUN_STATUSES)
            )
        ).scalar()
        or 0
    )


def runs_first_completed_at(db: Session) -> str | None:
    """runs.first_completed_at — see metrics-spec.md §3.6.

    Earliest ``completed_on`` over successful runs, ISO-8601 string.
    ``None`` until the first successful run.
    """
    return db.execute(
        select(func.min(AnalysisRun.completed_on)).where(AnalysisRun.run_status.in_(COMPLETED_RUN_STATUSES))
    ).scalar()


# ---------------------------------------------------------------------------
# Aggregate for the Analysis Runs page tiles — Convention A,
# scope=optional sbom_id / project_id. Replaces the FE-side reduce that
# silently undercounted above 100 runs (audit §I0.4-F2) and filtered on
# legacy ``PASS`` / ``FAIL`` strings (§I0.4-F1).
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RunsAggregate:
    """Counts every Analysis Runs page tile reads from one query.

    ``total_runs == sum(by_outcome.values())`` is the I-A invariant — the
    canonical reconciliation check (see test_metric_consistency.py).
    """

    total_runs: int
    by_outcome: dict[str, int]
    total_findings: int


def runs_aggregate(
    db: Session,
    *,
    sbom_id: int | None = None,
    project_id: int | None = None,
) -> RunsAggregate:
    """The numbers behind the six Analysis Runs page tiles.

    One round-trip, server-side, scoped per filters. Returns canonical
    outcome buckets keyed on the ADR-0001 status names — never the legacy
    ``PASS`` / ``FAIL`` aliases. The FE consumes this verbatim instead of
    reducing over a paginated client-side slice.

    Outcome buckets (sum to ``total_runs``):
      * ``no_issues``       — ``run_status='OK'``       (completed clean)
      * ``with_findings``   — ``run_status='FINDINGS'`` (completed, vulns)
      * ``source_errors``   — ``run_status='PARTIAL'``  (some feed errored)
      * ``failed``          — ``run_status='ERROR'``    (technical failure)
      * ``other``           — ``RUNNING``/``PENDING``/``NO_DATA`` and any
        future status. Keeps the sum-equals-total invariant unconditional.
    """
    scope_clauses = []
    if sbom_id is not None:
        scope_clauses.append(AnalysisRun.sbom_id == sbom_id)
    if project_id is not None:
        scope_clauses.append(AnalysisRun.project_id == project_id)

    total = db.execute(select(func.count(AnalysisRun.id)).where(*scope_clauses)).scalar() or 0

    rows = db.execute(
        select(AnalysisRun.run_status, func.count(AnalysisRun.id))
        .where(*scope_clauses)
        .group_by(AnalysisRun.run_status)
    ).all()

    raw: dict[str, int] = {(s or "").upper(): int(n) for s, n in rows}
    by_outcome: dict[str, int] = {
        "no_issues": raw.pop("OK", 0),
        "with_findings": raw.pop("FINDINGS", 0),
        "source_errors": raw.pop("PARTIAL", 0),
        "failed": raw.pop("ERROR", 0),
        "other": sum(raw.values()),
    }

    findings_sum = (
        db.execute(select(func.coalesce(func.sum(AnalysisRun.total_findings), 0)).where(*scope_clauses)).scalar() or 0
    )

    return RunsAggregate(
        total_runs=total,
        by_outcome=by_outcome,
        total_findings=findings_sum,
    )


__all__ = [
    "runs_total_lifetime",
    "runs_completed_lifetime",
    "runs_completed_this_week",
    "runs_distinct_dates_with_data",
    "runs_first_completed_at",
    "runs_aggregate",
    "RunsAggregate",
]
