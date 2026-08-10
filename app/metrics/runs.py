"""Run-count metrics. Spec §3.6."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import AnalysisRun
from ..services.analysis_service import (
    RUN_STATUS_FINDINGS,
    RUN_STATUS_PARTIAL,
    normalize_run_status,
    source_summary_from_details,
)
from ..sources.routing import coverage_gap_sources, has_incomplete_source_coverage
from ._helpers import latest_run_per_sbom_subquery
from .base import COMPLETED_RUN_STATUSES

log = logging.getLogger("sbom.metrics.runs")


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
      * ``source_errors``   — ``run_status='PARTIAL'``  (incomplete coverage:
        a source errored, or could not assess some/all components). Wire
        name kept for API compatibility; the UI labels it "incomplete
        coverage".
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

    by_outcome: dict[str, int] = {
        "no_issues": 0,
        "with_findings": 0,
        "source_errors": 0,
        "failed": 0,
        "other": 0,
    }
    for status, count in rows:
        normalized = normalize_run_status(status)
        if normalized == "OK":
            by_outcome["no_issues"] += int(count)
        elif normalized == "FINDINGS":
            by_outcome["with_findings"] += int(count)
        elif normalized == "PARTIAL":
            by_outcome["source_errors"] += int(count)
        elif normalized == "ERROR":
            by_outcome["failed"] += int(count)
        else:
            by_outcome["other"] += int(count)

    findings_sum = (
        db.execute(select(func.coalesce(func.sum(AnalysisRun.total_findings), 0)).where(*scope_clauses)).scalar() or 0
    )

    return RunsAggregate(
        total_runs=total,
        by_outcome=by_outcome,
        total_findings=findings_sum,
    )


# ---------------------------------------------------------------------------
# Source coverage over the dashboard scope (latest successful run per SBOM).
#
# Zero findings means two different things depending on coverage, and the
# dashboard headline must not conflate them: "every selected source assessed
# the components and found nothing" is a clean result; "OSV and NVD assessed
# 0 of 69 components" is an absence of evidence. The predicate itself is NOT
# redefined here — ``app.sources.routing.has_incomplete_source_coverage`` is
# the one definition and this module feeds it the per-run summary.
# ---------------------------------------------------------------------------


CoverageStatus = Literal["complete", "incomplete", "unknown"]

# How many runs' ``raw_report`` payloads this metric will parse per call.
# ``raw_report`` holds the entire details blob (findings included), so reading
# it for every SBOM on every dashboard load is not affordable. The cheap
# columns below already settle the verdict for anything written by the current
# writer; the parse is a cross-check for legacy rows and the source of the
# human-readable gap names. Truncation is logged, never silent.
COVERAGE_SUMMARY_INSPECTION_LIMIT = 50


@dataclass(frozen=True, slots=True)
class CoverageAssessment:
    """Aggregate source-coverage verdict for the dashboard scope.

    ``status``:
      * ``complete``   — every run in scope was fully assessed.
      * ``incomplete`` — at least one run had a source that errored or
        assessed none/only some of its components.
      * ``unknown``    — nothing in scope to judge (no runs at all).

    ``gap_sources`` names the sources responsible, best-effort, for UI copy
    like "Coverage gaps: OSV, NVD". It can be empty on an ``incomplete``
    verdict when the run predates per-source summaries.
    """

    status: CoverageStatus
    gap_sources: list[str] = field(default_factory=list)


def _run_details_by_id(db: Session, run_ids: list[int]) -> list[tuple[int, dict]]:
    """Parse ``raw_report`` for the given runs. Unparseable rows are skipped."""
    if not run_ids:
        return []
    rows = db.execute(
        select(AnalysisRun.id, AnalysisRun.raw_report).where(AnalysisRun.id.in_(run_ids))
    ).all()
    out: list[tuple[int, dict]] = []
    for run_id, raw_report in rows:
        if not raw_report:
            continue
        try:
            details = json.loads(raw_report)
        except (TypeError, ValueError):
            continue
        if isinstance(details, dict):
            out.append((int(run_id), details))
    return out


def runs_latest_per_sbom_coverage(db: Session) -> CoverageAssessment:
    """Source-coverage verdict over the latest successful run per SBOM.

    Same scope as every other posture metric (``latest_run_per_sbom_subquery``),
    so the coverage claim and the severity counts describe the same runs.

    Two passes, cheapest first:

    1. **Columns.** ``run_status == PARTIAL`` already means "errored or left
       coverage gaps" (see ``compute_report_status``), ``query_error_count > 0``
       means a source failed, and the persisted ``source`` label carries the
       ``(partial)`` marker the orchestrator derives from
       ``has_incomplete_source_coverage``. Any of the three ⇒ incomplete, with
       no JSON read at all. ``OK`` conversely *is* the verdict "no errors and
       no coverage gaps", so it needs no confirmation.
    2. **Summaries.** For up to :data:`COVERAGE_SUMMARY_INSPECTION_LIMIT` runs
       the stored per-source summary is read and handed to the shared
       predicate. This catches ``FINDINGS`` runs whose status says nothing
       about coverage, and collects the gap-source names.
    """
    rows = db.execute(
        select(
            AnalysisRun.id,
            AnalysisRun.run_status,
            AnalysisRun.query_error_count,
            AnalysisRun.source,
        ).where(AnalysisRun.id.in_(latest_run_per_sbom_subquery()))
    ).all()
    if not rows:
        return CoverageAssessment("unknown", [])

    incomplete = False
    # Runs whose columns already answered "incomplete" — parsed only to name
    # the sources. Undecided runs are parsed first because their summary is
    # what settles the verdict.
    decided_ids: list[int] = []
    undecided_ids: list[int] = []
    for run_id, run_status, query_error_count, source_label in rows:
        normalized = normalize_run_status(run_status)
        label = str(source_label or "").lower()
        if (
            normalized == RUN_STATUS_PARTIAL
            or int(query_error_count or 0) > 0
            or "(partial)" in label
        ):
            incomplete = True
            decided_ids.append(int(run_id))
        elif normalized == RUN_STATUS_FINDINGS:
            # Findings outrank coverage in the run status, so FINDINGS alone
            # does not tell us whether every source ran.
            undecided_ids.append(int(run_id))

    inspect_order = undecided_ids + decided_ids
    inspect_ids = inspect_order[:COVERAGE_SUMMARY_INSPECTION_LIMIT]
    if len(inspect_order) > len(inspect_ids):
        log.info(
            "coverage.summary_inspection_truncated",
            extra={
                "event": "coverage_summary_inspection_truncated",
                "inspected": len(inspect_ids),
                "candidates": len(inspect_order),
                "limit": COVERAGE_SUMMARY_INSPECTION_LIMIT,
            },
        )

    gap_sources: list[str] = []
    for _run_id, details in _run_details_by_id(db, inspect_ids):
        summary = source_summary_from_details(details)
        if not summary:
            continue
        if has_incomplete_source_coverage(summary):
            incomplete = True
        for name in coverage_gap_sources(summary):
            if name not in gap_sources:
                gap_sources.append(name)

    return CoverageAssessment("incomplete" if incomplete else "complete", gap_sources)


__all__ = [
    "runs_total_lifetime",
    "runs_completed_lifetime",
    "runs_completed_this_week",
    "runs_distinct_dates_with_data",
    "runs_first_completed_at",
    "runs_aggregate",
    "runs_latest_per_sbom_coverage",
    "COVERAGE_SUMMARY_INSPECTION_LIMIT",
    "CoverageAssessment",
    "CoverageStatus",
    "RunsAggregate",
]
