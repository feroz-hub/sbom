"""
Main dashboard endpoints router.

Routes:
  GET /dashboard/stats              summary counts (KPIs)
  GET /dashboard/recent-sboms       recently uploaded SBOMs
  GET /dashboard/activity           active vs stale SBOM counts
  GET /dashboard/severity           aggregate severity counts
  GET /dashboard/posture            posture band + KEV/fix counts (ADR-0001)

Scoping rule (ADR-0001 / docs/terminology.md):
  All aggregate counts are computed over the *latest successful run per SBOM*,
  where successful = {OK, FINDINGS, PARTIAL}. ERROR/RUNNING/PENDING/NO_DATA
  runs do not contribute to severity, finding, or vulnerability counts —
  their numbers may be partial or wrong, and surfacing them on the home
  dashboard would inflate or contradict the headline.
"""

import logging
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..etag import maybe_not_modified
from ..models import (
    AnalysisFinding,
    AnalysisRun,
    KevEntry,
    Projects,
    SBOMSource,
)
from ..schemas_dashboard import DashboardPostureResponse, LifetimeMetrics
from ..services.analysis_service import SUCCESSFUL_RUN_STATUSES
from ..services.dashboard_metrics import (
    compute_headline_state,
    compute_lifetime_metrics,
    compute_net_7day_change,
)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


def _latest_successful_run_ids_subq():
    """SQL subquery: ids of the latest *successful* (OK/FINDINGS/PARTIAL) run per SBOM.

    Implemented as ``MAX(id) GROUP BY sbom_id`` filtered to successful statuses.
    ``id`` is monotonic with ``started_on`` for our writer (single-process
    per-SBOM serialisation), so this is safe and avoids a self-join.
    """
    return (
        select(func.max(AnalysisRun.id))
        .where(AnalysisRun.run_status.in_(SUCCESSFUL_RUN_STATUSES))
        .group_by(AnalysisRun.sbom_id)
        .scalar_subquery()
    )


@router.get("/stats")
def dashboard_stats(request: Request, response: Response, db: Session = Depends(get_db)):
    """KPI counts for the home dashboard.

    Definitions (locked in ``docs/terminology.md``):
      * ``total_active_projects`` — projects with ``project_status = 1``
      * ``total_sboms`` — count of SBOM sources
      * ``total_distinct_vulnerabilities`` — distinct CVE-equivalent identifiers
        in the latest successful run per SBOM (one CVE → one count regardless
        of how many components it affects)
      * ``total_findings`` — distinct (run_id, vuln_id, component) tuples in
        the latest successful run per SBOM (this is what the severity bar sums)
    """
    latest_runs = _latest_successful_run_ids_subq()

    total_active_projects = db.execute(
        select(func.count(Projects.id)).where(Projects.project_status == 1)
    ).scalar_one()
    total_sboms = db.execute(select(func.count(SBOMSource.id))).scalar_one()

    total_findings = (
        db.execute(
            select(func.count(AnalysisFinding.id)).where(
                AnalysisFinding.analysis_run_id.in_(latest_runs)
            )
        ).scalar_one()
        or 0
    )
    total_distinct_vulnerabilities = (
        db.execute(
            select(func.count(func.distinct(AnalysisFinding.vuln_id))).where(
                AnalysisFinding.analysis_run_id.in_(latest_runs)
            )
        ).scalar_one()
        or 0
    )

    payload = {
        "total_active_projects": total_active_projects,
        "total_sboms": total_sboms,
        "total_findings": total_findings,
        "total_distinct_vulnerabilities": total_distinct_vulnerabilities,
        # Backwards-compat aliases — emit both shapes for one release so older
        # frontend bundles cached in service workers don't break. Drop after
        # the next deploy cycle.
        "total_projects": total_active_projects,
        "total_vulnerabilities": total_distinct_vulnerabilities,
    }
    nm = maybe_not_modified(request, response, payload)
    if nm is not None:
        return nm
    return payload


@router.get("/recent-sboms")
def dashboard_recent_sboms(
    limit: int = Query(5, ge=1, le=50),
    db: Session = Depends(get_db),
):
    """Most recently uploaded SBOMs for the home dashboard list."""
    items = db.execute(select(SBOMSource).order_by(SBOMSource.id.desc()).limit(limit)).scalars().all()
    return [{"id": s.id, "sbom_name": s.sbom_name, "created_on": s.created_on} for s in items]


@router.get("/activity")
def dashboard_activity(request: Request, response: Response, db: Session = Depends(get_db)):
    """Active vs stale SBOM counts for the activity doughnut chart."""
    cutoff = (datetime.now(UTC) - timedelta(days=30)).isoformat()
    active = db.execute(select(func.count(SBOMSource.id)).where(SBOMSource.created_on >= cutoff)).scalar_one()
    total = db.execute(select(func.count(SBOMSource.id))).scalar_one()
    payload = {"active_30d": active, "stale": max(0, total - active)}
    nm = maybe_not_modified(request, response, payload)
    if nm is not None:
        return nm
    return payload


@router.get("/severity")
def dashboard_severity(request: Request, response: Response, db: Session = Depends(get_db)):
    """Aggregate severity counts scoped to the latest successful run per SBOM.

    UNKNOWN is returned as-is for the data-quality pill on the hero — it is NOT
    a severity tier and the UI must render it separately (see ADR-0001).
    """
    latest_runs = _latest_successful_run_ids_subq()
    rows = db.execute(
        select(AnalysisFinding.severity, func.count(AnalysisFinding.id))
        .where(AnalysisFinding.analysis_run_id.in_(latest_runs))
        .group_by(AnalysisFinding.severity)
    ).all()
    buckets: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for sev, cnt in rows:
        key = (sev or "unknown").lower()
        if key in buckets:
            buckets[key] += cnt
        else:
            buckets["unknown"] += cnt
    nm = maybe_not_modified(request, response, buckets)
    if nm is not None:
        return nm
    return buckets


@router.get("/posture", response_model=DashboardPostureResponse)
def dashboard_posture(request: Request, response: Response, db: Session = Depends(get_db)):
    """Compute the dashboard posture envelope — single round-trip for the v2 hero.

    v2 additions (see ``docs/dashboard-redesign.md`` §9.3):

    * ``total_findings`` / ``distinct_vulnerabilities`` — previously on
      ``/dashboard/stats`` so the hero needed two requests; now folded in.
    * ``net_7day_added`` / ``net_7day_resolved`` — vuln-id deltas vs 7 days ago.
    * ``headline_state`` / ``primary_action`` — server-computed rules so the
      hero, sidebar, and (future) digest emails all agree on the framing.

    Original v1 fields are preserved unchanged — the v1 hero sparkline and
    sidebar consumers keep working through the deprecation window.
    """
    latest_runs = _latest_successful_run_ids_subq()

    # Severity counts (scoped). Reuses the severity logic above.
    severity_rows = db.execute(
        select(AnalysisFinding.severity, func.count(AnalysisFinding.id))
        .where(AnalysisFinding.analysis_run_id.in_(latest_runs))
        .group_by(AnalysisFinding.severity)
    ).all()
    severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for sev, cnt in severity_rows:
        key = (sev or "unknown").lower()
        if key in severity:
            severity[key] += cnt
        else:
            severity["unknown"] += cnt

    # KEV count: distinct vuln_ids in scope that match a row in kev_entry.
    kev_count = (
        db.execute(
            select(func.count(func.distinct(AnalysisFinding.vuln_id)))
            .join(KevEntry, KevEntry.cve_id == AnalysisFinding.vuln_id)
            .where(AnalysisFinding.analysis_run_id.in_(latest_runs))
        ).scalar_one()
        or 0
    )

    # Fix-available count: distinct vuln_ids in scope where fixed_versions is
    # a non-empty JSON array. We treat "[]" and "" as no-fix so that the
    # writers can use either convention without affecting this count.
    fix_available_count = (
        db.execute(
            select(func.count(func.distinct(AnalysisFinding.vuln_id))).where(
                AnalysisFinding.analysis_run_id.in_(latest_runs),
                AnalysisFinding.fixed_versions.is_not(None),
                AnalysisFinding.fixed_versions != "",
                AnalysisFinding.fixed_versions != "[]",
            )
        ).scalar_one()
        or 0
    )

    # Freshness: most recent completed_on across successful runs.
    last_successful_run_at = db.execute(
        select(func.max(AnalysisRun.completed_on)).where(
            AnalysisRun.run_status.in_(SUCCESSFUL_RUN_STATUSES)
        )
    ).scalar_one_or_none()

    total_active_projects = db.execute(
        select(func.count(Projects.id)).where(Projects.project_status == 1)
    ).scalar_one()
    total_sboms = db.execute(select(func.count(SBOMSource.id))).scalar_one()

    # v2 — fold in the counts the v1 hero used to fetch separately.
    total_findings = (
        db.execute(
            select(func.count(AnalysisFinding.id)).where(
                AnalysisFinding.analysis_run_id.in_(latest_runs)
            )
        ).scalar_one()
        or 0
    )
    distinct_vulnerabilities = (
        db.execute(
            select(func.count(func.distinct(AnalysisFinding.vuln_id))).where(
                AnalysisFinding.analysis_run_id.in_(latest_runs)
            )
        ).scalar_one()
        or 0
    )

    net_7day_added, net_7day_resolved = compute_net_7day_change(db)

    headline_state, primary_action = compute_headline_state(
        total_sboms=int(total_sboms),
        total_findings=int(total_findings),
        critical=severity["critical"],
        high=severity["high"],
        kev_count=int(kev_count),
    )

    payload = {
        "severity": severity,
        "kev_count": kev_count,
        "fix_available_count": fix_available_count,
        "last_successful_run_at": last_successful_run_at,
        "total_sboms": total_sboms,
        "total_active_projects": total_active_projects,
        "total_findings": int(total_findings),
        "distinct_vulnerabilities": int(distinct_vulnerabilities),
        "net_7day_added": int(net_7day_added),
        "net_7day_resolved": int(net_7day_resolved),
        "headline_state": headline_state,
        "primary_action": primary_action,
        "schema_version": 1,
    }
    nm = maybe_not_modified(request, response, payload)
    if nm is not None:
        return nm
    return payload


@router.get("/lifetime", response_model=LifetimeMetrics)
def dashboard_lifetime(request: Request, response: Response, db: Session = Depends(get_db)):
    """Cumulative "Your Analyzer, So Far" metrics — growth, not snapshot.

    These numbers only go up and tell the user "the tool has been working
    for me." Computation is cached in-process for 15 minutes keyed by the
    cheapest invalidation tuple (max run id, run count, sbom count) — so a
    new run completing busts the cache immediately. See
    ``docs/dashboard-redesign.md`` §6 for the panel rationale and §9.3 for
    the caching choice.
    """
    metrics = compute_lifetime_metrics(db)
    payload = metrics.model_dump()
    nm = maybe_not_modified(request, response, payload)
    if nm is not None:
        return nm
    return payload
