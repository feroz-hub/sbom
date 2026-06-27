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
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .. import metrics
from ..db import get_db
from ..etag import maybe_not_modified
from ..models import SBOMSource
from ..schemas_dashboard import (
    DashboardPostureResponse,
    LifetimeMetrics,
    NetChange,
    VulnerabilityAgeResponse,
)
from ..services.lifecycle.vex_provider import vex_dashboard_summary

# Observation-window lengths (days) for the vulnerability-age period filter.
_AGE_PERIOD_DAYS = {"day": 1, "week": 7, "month": 30, "year": 365}
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
    total_distinct_vulnerabilities = metrics.findings_latest_per_sbom_distinct_vulnerabilities(db)

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
    high_epss_count = metrics.findings_high_epss_in_scope(db, scope="latest_per_sbom")
    needs_review_count = metrics.findings_needs_review_in_scope(db, scope="latest_per_sbom")
    fix_available_count = metrics.findings_latest_per_sbom_fix_available(db)
    total_findings = metrics.findings_latest_per_sbom_total(db)
    distinct_vulnerabilities = metrics.findings_latest_per_sbom_distinct_vulnerabilities(db)
    total_active_projects = metrics.projects_active_total(db)
    total_sboms = metrics.sboms_total(db)
    total_sboms_analysed = metrics.sboms_analysed_total(db)
    total_applications_scanned = metrics.applications_scanned_total(db)
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
        "high_epss_count": int(high_epss_count),
        "needs_review_count": int(needs_review_count),
        "fix_available_count": fix_available_count,
        "last_successful_run_at": last_successful_run_at,
        "total_sboms": total_sboms,
        "total_sboms_analysed": int(total_sboms_analysed),
        "total_applications_scanned": int(total_applications_scanned),
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


def _resolve_age_window(
    period: str, date_from: str | None, date_to: str | None
) -> tuple[str | None, str | None] | None:
    """Translate the period selector into a ``(start_iso, end_iso)`` window on
    the scan (run) date, or ``None`` for all-time.

    day/week/month/year are rolling look-backs ending now (open upper bound);
    ``custom`` uses the supplied ISO bounds (all-time if both are blank).
    """
    if period == "all":
        return None
    if period == "custom":
        if not date_from and not date_to:
            return None
        return (date_from, date_to)
    days = _AGE_PERIOD_DAYS.get(period)
    if not days:
        return None
    start_iso = (datetime.now(UTC) - timedelta(days=days)).isoformat()
    return (start_iso, None)


@router.get("/vulnerability-age", response_model=VulnerabilityAgeResponse)
def dashboard_vulnerability_age(
    period: Literal["all", "day", "week", "month", "year", "custom"] = Query("all"),
    date_from: str | None = Query(None, description="ISO start (custom period; filters scan date)"),
    date_to: str | None = Query(None, description="ISO end (custom period; filters scan date)"),
    db: Session = Depends(get_db),
):
    """ "Vulnerability by Age" pie.

    Buckets findings in the latest-successful-run-per-SBOM scope by CVE age
    (``now - published_on``). ``period`` is an *observation window on the scan
    date* — "of what we detected in this window, how old is it?". The age
    buckets are fixed; the window narrows which findings are counted. All
    numbers come from ``app.metrics`` (no inline metric SQL here).
    """
    window = _resolve_age_window(period, date_from, date_to)
    buckets = metrics.findings_age_distribution(db, window=window)
    return {
        "buckets": buckets,
        "total": sum(buckets.values()),
        "period": period,
        "date_from": date_from,
        "date_to": date_to,
        "schema_version": 1,
    }


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
        select(func.max(AnalysisRun.completed_on)).where(AnalysisRun.run_status.in_(SUCCESSFUL_RUN_STATUSES))
    ).scalar_one_or_none()


@router.get("/lifecycle")
def get_dashboard_lifecycle(db: Session = Depends(get_db)):
    """Fetch component lifecycle metrics for the dashboard."""
    summary = metrics.lifecycle_summary(db)
    return {
        **summary,
        # Backward-compatible aliases used by the existing dashboard bundle.
        "eol_components": metrics.lifecycle_eol_total(db),
        "eos_upcoming": metrics.lifecycle_eos_upcoming_total(db),
        "unsupported": metrics.lifecycle_unsupported_total(db),
        "stale_count": summary.get("stale_lifecycle_count", 0),
    }


@router.get("/vex")
def get_dashboard_vex(db: Session = Depends(get_db)):
    """Fetch VEX exploitability metrics for the dashboard."""
    return vex_dashboard_summary(db)


@router.get("/health")
def get_dashboard_health(db: Session = Depends(get_db)):
    """Fetch completeness and outdated component metrics for the dashboard."""
    return {
        "completeness_score": metrics.health_completeness_average(db),
        "missing_metadata": metrics.health_missing_metadata_count(db),
        "outdated_components": metrics.health_outdated_components_count(db),
    }


@router.get("/remediation-stats")
def get_dashboard_remediation_stats(db: Session = Depends(get_db)):
    """Fetch remediation progress, aging counts, and SLA metrics for the dashboard."""
    rem_summary = metrics.remediation_summary(db)
    sla_data = rem_summary.get("sla") or {}

    return {
        "status_counts": metrics.remediation_status_counts(db),
        "aging_count": metrics.remediation_aging_count(db),
        "sla": {
            "overdue": sla_data.get("overdue", 0),
            "due_soon": sla_data.get("due_soon", 0),
            "ok": sla_data.get("ok", 0),
        },
    }


@router.get("/summary")
def get_dashboard_summary(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    """Aggregate dashboard summary containing posture, lifecycle, health, VEX,
    vulnerability_age, trend, forecast, exploitation, remediation, remediation_stats,
    risk_map, risk_matrix, recent_sboms.

    This is optimized to load all metrics sequentially in a single DB session,
    preventing 15+ concurrent requests on frontend dashboard load.
    """
    from statistics import fmean

    from ..services.dashboard_metrics import build_trend_annotations

    # 1. Posture
    severity = metrics.findings_latest_per_sbom_severity_distribution(db)
    kev_count = metrics.findings_kev_in_scope(db, scope="latest_per_sbom")
    high_epss_count = metrics.findings_high_epss_in_scope(db, scope="latest_per_sbom")
    needs_review_count = metrics.findings_needs_review_in_scope(db, scope="latest_per_sbom")
    fix_available_count = metrics.findings_latest_per_sbom_fix_available(db)
    total_findings = metrics.findings_latest_per_sbom_total(db)
    distinct_vulnerabilities = metrics.findings_latest_per_sbom_distinct_vulnerabilities(db)
    total_active_projects = metrics.projects_active_total(db)
    total_sboms = metrics.sboms_total(db)
    total_sboms_analysed = metrics.sboms_analysed_total(db)
    total_applications_scanned = metrics.applications_scanned_total(db)
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

    posture_payload = {
        "severity": severity,
        "kev_count": kev_count,
        "high_epss_count": int(high_epss_count),
        "needs_review_count": int(needs_review_count),
        "fix_available_count": fix_available_count,
        "last_successful_run_at": last_successful_run_at,
        "total_sboms": total_sboms,
        "total_sboms_analysed": int(total_sboms_analysed),
        "total_applications_scanned": int(total_applications_scanned),
        "total_active_projects": total_active_projects,
        "total_findings": int(total_findings),
        "distinct_vulnerabilities": int(distinct_vulnerabilities),
        "net_7day": net_envelope.model_dump(),
        "net_7day_added": net.added,
        "net_7day_resolved": net.resolved,
        "headline_state": headline_state,
        "primary_action": primary_action,
        "schema_version": 1,
    }

    # 2. Lifecycle
    lifecycle_sum = metrics.lifecycle_summary(db)
    lifecycle_payload = {
        **lifecycle_sum,
        "eol_components": metrics.lifecycle_eol_total(db),
        "eos_upcoming": metrics.lifecycle_eos_upcoming_total(db),
        "unsupported": metrics.lifecycle_unsupported_total(db),
        "stale_count": lifecycle_sum.get("stale_lifecycle_count", 0),
    }

    # 3. Health
    health_payload = {
        "completeness_score": metrics.health_completeness_average(db),
        "missing_metadata": metrics.health_missing_metadata_count(db),
        "outdated_components": metrics.health_outdated_components_count(db),
    }

    # 4. VEX
    vex_payload = vex_dashboard_summary(db)

    # 5. Vulnerability Age
    age_buckets = metrics.findings_age_distribution(db, window=None)
    vuln_age_payload = {
        "buckets": age_buckets,
        "total": sum(age_buckets.values()),
        "period": "all",
        "date_from": None,
        "date_to": None,
        "schema_version": 1,
    }

    # 6. Trend
    earliest_iso = metrics.runs_first_completed_at(db)
    earliest_run_date = earliest_iso[:10] if earliest_iso else None
    runs_total = metrics.runs_total_lifetime(db)
    runs_distinct_dates = metrics.runs_distinct_dates_with_data(db)

    points = metrics.findings_daily_distinct_active(db, days=30)
    try:
        annotations = build_trend_annotations(db, days=30)
    except SQLAlchemyError:
        log.exception("Failed to build dashboard trend annotations")
        annotations = []
    point_dicts = [
        {
            "date": p.date,
            "critical": p.critical,
            "high": p.high,
            "medium": p.medium,
            "low": p.low,
            "unknown": p.unknown,
            "total": p.total,
        }
        for p in points
    ]
    avg_total = fmean(p.total for p in points) if points else 0.0
    trend_payload = {
        "days": 30,
        "points": point_dicts,
        "series": point_dicts,
        "annotations": [a.model_dump() for a in annotations],
        "avg_total": round(avg_total, 2),
        "earliest_run_date": earliest_run_date,
        "runs_total": int(runs_total),
        "runs_distinct_dates": int(runs_distinct_dates),
        "granularity": None,
        "schema_version": 1,
    }

    # 7. Forecast
    forecast_payload = metrics.findings_forecast(db, history_days=30, horizon_days=14)

    # 8. Exploitation
    exploitation_payload = metrics.portfolio_exploitation_outlook(db)

    # 9. Remediation (dashboard_remediation)
    remediation_payload = metrics.remediation_summary(db)

    # 10. Remediation Stats
    rem_summary = metrics.remediation_summary(db)
    sla_data = rem_summary.get("sla") or {}
    remediation_stats_payload = {
        "status_counts": metrics.remediation_status_counts(db),
        "aging_count": metrics.remediation_aging_count(db),
        "sla": {
            "overdue": sla_data.get("overdue", 0),
            "due_soon": sla_data.get("due_soon", 0),
            "ok": sla_data.get("ok", 0),
        },
    }

    # 11. Risk Map
    risk_map_payload = metrics.portfolio_risk_map(db)

    # 12. Risk Matrix
    risk_matrix_payload = metrics.portfolio_risk_matrix(db, limit=300)

    # 13. Recent SBOMs
    recent_items = db.execute(select(SBOMSource).order_by(SBOMSource.id.desc()).limit(5)).scalars().all()
    recent_sboms_payload = [{"id": s.id, "sbom_name": s.sbom_name, "created_on": s.created_on} for s in recent_items]

    # 14. Lifetime Metrics
    from ..services.dashboard_metrics import compute_lifetime_metrics

    lifetime_base = compute_lifetime_metrics(db)
    lifetime_runs_completed = metrics.runs_completed_lifetime(db)
    lifetime_runs_distinct = metrics.runs_distinct_dates_with_data(db)
    lifetime_payload = lifetime_base.model_dump()
    lifetime_payload["runs_completed_total"] = int(lifetime_runs_completed)
    lifetime_payload["runs_distinct_dates"] = int(lifetime_runs_distinct)

    payload = {
        "posture": posture_payload,
        "lifecycle": lifecycle_payload,
        "health": health_payload,
        "vex": vex_payload,
        "vulnerability_age": vuln_age_payload,
        "trend": trend_payload,
        "forecast": forecast_payload,
        "exploitation": exploitation_payload,
        "remediation": remediation_payload,
        "remediation_stats": remediation_stats_payload,
        "risk_map": risk_map_payload,
        "risk_matrix": risk_matrix_payload,
        "recent_sboms": recent_sboms_payload,
        "lifetime": lifetime_payload,
    }

    nm = maybe_not_modified(request, response, payload)
    if nm is not None:
        return nm
    return payload
