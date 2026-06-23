# routers/dashboard.py — Findings Trend endpoint (v2)
#
# v1 returned only days that had findings, which made Recharts render
# isolated dots when only one day was populated. v2 always returns exactly
# ``days`` data points (zero-filled), restores ``unknown`` as a first-class
# bucket, and ships annotations + 30-day average + earliest-run hint so the
# chart can tell a complete story without a second round-trip.
#
# Wire format and rules locked in ``docs/dashboard-redesign.md`` §9.2.
# Metric definitions live in ``docs/dashboard-metrics-spec.md``.
from __future__ import annotations

import logging
from statistics import fmean
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy.orm import Session

from .. import metrics
from ..db import get_db
from ..etag import maybe_not_modified
from ..schemas_dashboard import FindingsTrendResponse
from ..services.dashboard_metrics import build_trend_annotations

log = logging.getLogger("sbom.api.dashboard")

router = APIRouter()


@router.get("/trend", response_model=FindingsTrendResponse, status_code=200)
def dashboard_trend(
    request: Request,
    response: Response,
    days: int = Query(30, ge=1, le=365, description="Number of days to look back (legacy daily path)"),
    granularity: Literal["day", "week", "month", "year"] | None = Query(
        None,
        description="Period bucketing. Omit for the legacy daily series; set it for the "
        "manager dashboard trend (adds fix_available + resolved overlays).",
    ),
    application_ids: list[int] | None = Query(
        None, description="Restrict to runs of these projects (manager app filter)."
    ),
    db: Session = Depends(get_db),
):
    """Findings trend for the chart.

    **Legacy path (``granularity`` omitted):** zero-filled daily severity
    counts from ``findings.daily_distinct_active`` (spec §3.4) +
    annotations — unchanged, so the existing chart keeps working.

    **Manager path (``granularity`` set):** period-bucketed
    (day/week/month/year) distinct-active snapshots from ``findings.trend``,
    optionally filtered to ``application_ids``, with ``fix_available`` and
    ``resolved`` overlays on each point. Annotations are omitted for periods >
    a day (they're day-scoped event markers).
    """
    earliest_iso = metrics.runs_first_completed_at(db)
    earliest_run_date = earliest_iso[:10] if earliest_iso else None
    runs_total = metrics.runs_total_lifetime(db)
    runs_distinct_dates = metrics.runs_distinct_dates_with_data(db)

    if granularity is None:
        # ── Legacy daily path — behaviour preserved verbatim. ──
        points = metrics.findings_daily_distinct_active(db, days=days)
        annotations = build_trend_annotations(db, days=days)
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
        payload_dict = {
            "days": days,
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
    else:
        # ── Manager path — period buckets + app filter + fix overlays. ──
        point_dicts = metrics.findings_trend(db, granularity=granularity, application_ids=application_ids)
        avg_total = fmean(p["total"] for p in point_dicts) if point_dicts else 0.0
        payload_dict = {
            "days": days,
            "points": point_dicts,
            "series": point_dicts,
            "annotations": [],  # day-scoped markers don't map to wider periods
            "avg_total": round(avg_total, 2),
            "earliest_run_date": earliest_run_date,
            "runs_total": int(runs_total),
            "runs_distinct_dates": int(runs_distinct_dates),
            "granularity": granularity,
            "schema_version": 1,
        }

    nm = maybe_not_modified(request, response, payload_dict)
    if nm is not None:
        return nm
    return payload_dict
