"""
Main dashboard endpoints router.

Routes:
  GET /dashboard/stats              summary counts (KPIs)
  GET /dashboard/recent-sboms       recently uploaded SBOMs
  GET /dashboard/activity           active vs stale SBOM counts
  GET /dashboard/severity           aggregate severity counts
  GET /dashboard/posture            posture band + KEV/fix counts (ADR-0001)
  GET /dashboard/lifetime           "Your Analyzer, So Far" cumulative metrics

Scoping rule (ADR-0001 / docs/terminology.md):
  All aggregate counts are computed over the *latest successful run per SBOM*,
  where successful = {OK, FINDINGS, PARTIAL}. ERROR/RUNNING/PENDING/NO_DATA
  runs do not contribute to severity, finding, or vulnerability counts —
  their numbers may be partial or wrong, and surfacing them on the home
  dashboard would inflate or contradict the headline.

All numbers come from ``app.metrics`` — see
``docs/dashboard-metrics-spec.md`` for definitions and reconciliation
invariants. **Do not add inline metric SQL here.**
"""

import logging
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import metrics
from ..db import get_db
from ..etag import maybe_not_modified
from ..models import SBOMSource
from ..schemas_dashboard import (
    DashboardPostureResponse,
    LifetimeMetrics,
    NetChange,
)
from ..services.dashboard_metrics import (
    compute_headline_state,
    compute_lifetime_metrics,
)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats")
def dashboard_stats(request: Request, response: Response, db: Session = Depends(get_db)):
    """KPI counts for the home dashboard.

    Definitions (locked in ``docs/dashboard-metrics-spec.md`` §3):
      * ``total_active_projects`` — ``projects.active_total``
      * ``total_sboms`` — ``sboms.total``
      * ``total_findings`` — ``findings.latest_per_sbom.total``
      * ``total_distinct_vulnerabilities`` — ``findings.latest_per_sbom.distinct_vulnerabilities``
    """
    total_active_projects = metrics.projects_active_total(db)
    total_sboms = metrics.sboms_total(db)
    total_findings = metrics.findings_latest_per_sbom_total(db)
    total_distinct_vulnerabilities = (
        metrics.findings_latest_per_sbom_distinct_vulnerabilities(db)
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
    buckets = metrics.findings_latest_per_sbom_severity_distribution(db)
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
    * ``net_7day`` — vuln-id deltas vs 7 days ago, with ``is_first_period``
      flag (Bug 5 lock).
    * ``headline_state`` / ``primary_action`` — server-computed rules so the
      hero, sidebar, and (future) digest emails all agree on the framing.

    Original v1 fields are preserved unchanged — the v1 hero sparkline and
    sidebar consumers keep working through the deprecation window.

    Every numeric field comes from ``app.metrics``. KEV uses the canonical
    alias-aware predicate — same logic as the run-detail KEV badge (Bug 1
    lock). See ``docs/dashboard-metrics-spec.md`` §3.3 / §4 invariant I3.
    """
    severity = metrics.findings_latest_per_sbom_severity_distribution(db)
    kev_count = metrics.findings_kev_in_scope(db, scope="latest_per_sbom")
    fix_available_count = metrics.findings_latest_per_sbom_fix_available(db)
    total_findings = metrics.findings_latest_per_sbom_total(db)
    distinct_vulnerabilities = (
        metrics.findings_latest_per_sbom_distinct_vulnerabilities(db)
    )
    total_active_projects = metrics.projects_active_total(db)
    total_sboms = metrics.sboms_total(db)
    last_successful_run_at = _last_successful_completed_at(db)

    net = metrics.findings_net_change(db, days=7)
    net_envelope = NetChange(
        added=net.added,
        resolved=net.resolved,
        is_first_period=net.is_first_period,
        window_days=net.window_days,
    )

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
        # Canonical envelope.
        "net_7day": net_envelope.model_dump(),
        # Back-compat flat aliases — drop after the v2 FE bundle ships.
        "net_7day_added": net.added,
        "net_7day_resolved": net.resolved,
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
    ``docs/dashboard-redesign.md`` §6 for the panel rationale and
    ``docs/dashboard-metrics-spec.md`` §3 for canonical definitions.
    """
    base = compute_lifetime_metrics(db)
    # Augment with the canonical run counts (Bug 6 lock for the trend
    # empty-state). ``runs_completed_total`` is successful-only;
    # ``runs_distinct_dates`` is what gates the trend chart visibility.
    runs_completed_total = metrics.runs_completed_lifetime(db)
    runs_distinct_dates = metrics.runs_distinct_dates_with_data(db)

    payload = base.model_dump()
    payload["runs_completed_total"] = int(runs_completed_total)
    payload["runs_distinct_dates"] = int(runs_distinct_dates)

    nm = maybe_not_modified(request, response, payload)
    if nm is not None:
        return nm
    return payload


def _last_successful_completed_at(db: Session) -> str | None:
    """Most recent ``completed_on`` across successful runs.

    Inlined here because there's no canonical metric for "latest activity
    timestamp" — it's a freshness display, not a count. Add to spec §3 if a
    second consumer ever needs it.
    """
    from ..models import AnalysisRun
    from ..services.analysis_service import SUCCESSFUL_RUN_STATUSES

    return db.execute(
        select(func.max(AnalysisRun.completed_on)).where(
            AnalysisRun.run_status.in_(SUCCESSFUL_RUN_STATUSES)
        )
    ).scalar_one_or_none()
