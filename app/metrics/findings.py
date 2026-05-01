"""Findings metrics — single-run, latest-state, lifetime, and daily-distinct.

Each function references its catalog entry in ``docs/dashboard-metrics-spec.md``.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import AnalysisFinding, AnalysisRun
from ._helpers import (
    finding_key,
    latest_run_per_sbom_as_of_subquery,
    latest_run_per_sbom_subquery,
)
from .base import COMPLETED_RUN_STATUSES, SEVERITY_KEYS, TrendPoint
from .cache import memoize_with_ttl

# ---------------------------------------------------------------------------
# Single run — Convention A, scope=run
# ---------------------------------------------------------------------------


def findings_in_run_total(db: Session, *, run_id: int) -> int:
    """findings.in_run.total — see metrics-spec.md §3.1.

    Count of finding-rows in a single run. Equals ``analysis_run.total_findings``
    on the run row (writer-side invariant).
    """
    return (
        db.execute(
            select(func.count(AnalysisFinding.id)).where(
                AnalysisFinding.analysis_run_id == run_id
            )
        ).scalar()
        or 0
    )


def findings_in_run_severity_distribution(
    db: Session, *, run_id: int
) -> dict[str, int]:
    """findings.in_run.severity_distribution — see metrics-spec.md §3.1.

    ``sum(values()) == findings_in_run_total(run_id)``. Severities are
    lower-cased; null/unknown go in ``unknown``.
    """
    rows = db.execute(
        select(AnalysisFinding.severity, func.count(AnalysisFinding.id))
        .where(AnalysisFinding.analysis_run_id == run_id)
        .group_by(AnalysisFinding.severity)
    ).all()
    return _bucket_severities(rows)


# ---------------------------------------------------------------------------
# Latest state — Convention A, scope=latest_per_sbom
# ---------------------------------------------------------------------------


def findings_latest_per_sbom_total(db: Session) -> int:
    """findings.latest_per_sbom.total — see metrics-spec.md §3.2.

    Σ over SBOMs of finding-rows in that SBOM's latest successful run.
    """
    latest = latest_run_per_sbom_subquery()
    return (
        db.execute(
            select(func.count(AnalysisFinding.id)).where(
                AnalysisFinding.analysis_run_id.in_(latest)
            )
        ).scalar()
        or 0
    )


def findings_latest_per_sbom_severity_distribution(db: Session) -> dict[str, int]:
    """findings.latest_per_sbom.severity_distribution — see metrics-spec.md §3.2."""
    latest = latest_run_per_sbom_subquery()
    rows = db.execute(
        select(AnalysisFinding.severity, func.count(AnalysisFinding.id))
        .where(AnalysisFinding.analysis_run_id.in_(latest))
        .group_by(AnalysisFinding.severity)
    ).all()
    return _bucket_severities(rows)


def findings_latest_per_sbom_distinct_vulnerabilities(db: Session) -> int:
    """findings.latest_per_sbom.distinct_vulnerabilities — see metrics-spec.md §3.2."""
    latest = latest_run_per_sbom_subquery()
    return (
        db.execute(
            select(func.count(func.distinct(AnalysisFinding.vuln_id))).where(
                AnalysisFinding.analysis_run_id.in_(latest)
            )
        ).scalar()
        or 0
    )


def findings_latest_per_sbom_fix_available(db: Session) -> int:
    """findings.latest_per_sbom.fix_available — see metrics-spec.md §3.2.

    Distinct vulns in scope whose ``fixed_versions`` is a non-empty JSON array.
    """
    latest = latest_run_per_sbom_subquery()
    return (
        db.execute(
            select(func.count(func.distinct(AnalysisFinding.vuln_id))).where(
                AnalysisFinding.analysis_run_id.in_(latest),
                AnalysisFinding.fixed_versions.is_not(None),
                AnalysisFinding.fixed_versions != "",
                AnalysisFinding.fixed_versions != "[]",
            )
        ).scalar()
        or 0
    )


# ---------------------------------------------------------------------------
# Lifetime distinct — Convention B
# ---------------------------------------------------------------------------


def findings_distinct_lifetime(db: Session) -> int:
    """findings.distinct_lifetime — see metrics-spec.md §3.4.

    Distinct ``(vuln_id, component_name, component_version)`` tuples across
    every successful run, ever. Successful-only filter is the Q2 lock —
    ERROR/PARTIAL-failed runs do not inflate the cumulative tile.
    """

    def _compute() -> int:
        composite = (
            func.coalesce(AnalysisFinding.vuln_id, "")
            + "|"
            + func.coalesce(AnalysisFinding.component_name, "")
            + "|"
            + func.coalesce(AnalysisFinding.component_version, "")
        )
        return (
            db.execute(
                select(func.count(func.distinct(composite)))
                .join(AnalysisRun, AnalysisRun.id == AnalysisFinding.analysis_run_id)
                .where(AnalysisRun.run_status.in_(COMPLETED_RUN_STATUSES))
            ).scalar()
            or 0
        )

    return memoize_with_ttl(
        name="findings.distinct_lifetime",
        ttl_seconds=3600,  # spec §6
        db=db,
        compute=_compute,
    )


def findings_distinct_active_as_of(
    db: Session, *, as_of: date
) -> set[tuple[str, str, str]]:
    """findings.distinct_active_as_of — see metrics-spec.md §3.4.

    Distinct ``(vuln_id, component_name, component_version)`` tuples in the
    latest successful run of each SBOM completed on or before ``as_of``.
    Returns the set so callers can do set-difference for net change.

    ``as_of`` is interpreted at end-of-day in UTC.
    """
    as_of_iso = as_of.isoformat() + "T23:59:59"
    latest_as_of = latest_run_per_sbom_as_of_subquery(as_of_iso)

    rows = db.execute(
        select(
            AnalysisFinding.vuln_id,
            AnalysisFinding.component_name,
            AnalysisFinding.component_version,
        ).where(AnalysisFinding.analysis_run_id.in_(latest_as_of))
    ).all()

    return {finding_key(v, c, w) for v, c, w in rows}


# ---------------------------------------------------------------------------
# Daily distinct active — the trend chart query (Bug 3 lock)
# ---------------------------------------------------------------------------


def findings_daily_distinct_active(
    db: Session, *, days: int = 30, today: date | None = None
) -> list[TrendPoint]:
    """findings.daily_distinct_active — see metrics-spec.md §3.4.

    For each of the last ``days`` calendar days, compute the distinct
    ``(vuln_id, component_name, component_version)`` tuples present in the
    latest-successful-run-per-SBOM-as-of-end-of-day, grouped by severity.

    This replaces the broken ``build_trend_points`` from
    ``app/services/dashboard_metrics.py``. The shape Σ over days no longer
    over-counts — each day is an independent snapshot.

    Spec invariant I4: ``Σ severities[d] ≤ findings.distinct_lifetime``.
    """

    end = today or datetime.now(UTC).date()
    days_list: list[date] = [end - timedelta(days=i) for i in range(days - 1, -1, -1)]

    def _compute() -> list[TrendPoint]:
        return _daily_distinct_active_uncached(db, days_list)

    return memoize_with_ttl(
        name="findings.daily_distinct_active",
        ttl_seconds=15 * 60,  # spec §6
        db=db,
        key_extra=(days, end.isoformat()),
        compute=_compute,
    )


def _daily_distinct_active_uncached(
    db: Session, days_list: list[date]
) -> list[TrendPoint]:
    """The actual computation, factored out so the cache wrapper stays tidy."""
    # Load every successful run with its sbom_id and completed_on, sorted
    # for monotonic walk per SBOM.
    runs = db.execute(
        select(AnalysisRun.id, AnalysisRun.sbom_id, AnalysisRun.completed_on)
        .where(AnalysisRun.run_status.in_(COMPLETED_RUN_STATUSES))
        .order_by(AnalysisRun.sbom_id, AnalysisRun.id)
    ).all()

    # Group by SBOM: list of (completed_date, run_id), already in id-order.
    sbom_runs: dict[int, list[tuple[date, int]]] = defaultdict(list)
    for run_id, sbom_id, completed_on in runs:
        if not completed_on:
            continue
        try:
            d = datetime.fromisoformat(completed_on[:10]).date()
        except ValueError:
            continue
        sbom_runs[sbom_id].append((d, run_id))

    # For each requested day, find the latest run id per SBOM whose
    # completed_date <= day. Collect every run id we'll need to load
    # findings for so the JOIN happens in one shot.
    day_to_runs: dict[date, list[int]] = {}
    runs_needed: set[int] = set()
    for d in days_list:
        latest_per_sbom: list[int] = []
        for timeline in sbom_runs.values():
            best: int | None = None
            for run_date, run_id in timeline:
                if run_date <= d and (best is None or run_id > best):
                    best = run_id
            if best is not None:
                latest_per_sbom.append(best)
                runs_needed.add(best)
        day_to_runs[d] = latest_per_sbom

    # Single query for every finding row across every needed run.
    findings_by_run: dict[int, list[tuple[str, str, str, str]]] = defaultdict(list)
    if runs_needed:
        rows = db.execute(
            select(
                AnalysisFinding.analysis_run_id,
                AnalysisFinding.vuln_id,
                AnalysisFinding.component_name,
                AnalysisFinding.component_version,
                AnalysisFinding.severity,
            ).where(AnalysisFinding.analysis_run_id.in_(runs_needed))
        ).all()
        for run_id, vuln, comp, ver, sev in rows:
            findings_by_run[run_id].append(
                ((vuln or ""), (comp or ""), (ver or ""), (sev or "unknown"))
            )

    # Per-day distinct snapshot. First-occurrence severity wins on ties (a
    # finding appearing in two SBOMs' latest runs on the same day takes the
    # severity from whichever run was queried first; severity for the same
    # vuln+component+version should be identical across runs anyway).
    points: list[TrendPoint] = []
    for d in days_list:
        seen: dict[tuple[str, str, str], str] = {}
        for run_id in day_to_runs.get(d, []):
            for vuln, comp, ver, sev in findings_by_run.get(run_id, []):
                key = (vuln, comp, ver)
                if key not in seen:
                    seen[key] = sev
        buckets = {k: 0 for k in SEVERITY_KEYS}
        for sev in seen.values():
            k = (sev or "unknown").lower()
            if k not in buckets:
                k = "unknown"
            buckets[k] += 1
        total = sum(buckets.values())
        points.append(
            TrendPoint(
                date=d.isoformat(),
                critical=buckets["critical"],
                high=buckets["high"],
                medium=buckets["medium"],
                low=buckets["low"],
                unknown=buckets["unknown"],
                total=total,
            )
        )
    return points


# ---------------------------------------------------------------------------
# Internal — severity bucketing helper
# ---------------------------------------------------------------------------


def _bucket_severities(rows) -> dict[str, int]:
    buckets: dict[str, int] = {k: 0 for k in SEVERITY_KEYS}
    for sev, count in rows:
        key = (sev or "unknown").lower()
        if key in buckets:
            buckets[key] += int(count or 0)
        else:
            buckets["unknown"] += int(count or 0)
    return buckets
