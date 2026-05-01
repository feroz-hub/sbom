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
    days: int = Query(30, ge=1, le=365, description="Number of days to look back"),
    db: Session = Depends(get_db),
):
    """Return zero-filled daily severity counts + annotations for the chart.

    Each day's severity counts come from ``findings.daily_distinct_active``
    (spec §3.4) — distinct ``(vuln_id, component_name, component_version)``
    tuples in the latest successful run of each SBOM as-of-end-of-day. This
    replaces the old "sum raw rows across runs" implementation that
    over-counted by orders of magnitude (Bug 3).

    ``runs_total`` and ``runs_distinct_dates`` are exposed so the FE
    empty-state copy/condition stops lying about run counts (Bug 2 / Bug 6).
    """
    points = metrics.findings_daily_distinct_active(db, days=days)
    annotations = build_trend_annotations(db, days=days)

    avg_total = fmean(p.total for p in points) if points else 0.0

    earliest_iso = metrics.runs_first_completed_at(db)
    earliest_run_date = earliest_iso[:10] if earliest_iso else None

    runs_total = metrics.runs_total_lifetime(db)
    runs_distinct_dates = metrics.runs_distinct_dates_with_data(db)

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

    payload_dict = {
        "days": days,
        "points": point_dicts,
        # series alias — same data, same field shape. Removed in a follow-up
        # release once the v2 frontend ships and the v1 bundle is retired.
        "series": point_dicts,
        "annotations": [a.model_dump() for a in annotations],
        "avg_total": round(avg_total, 2),
        "earliest_run_date": earliest_run_date,
        "runs_total": int(runs_total),
        "runs_distinct_dates": int(runs_distinct_dates),
        "schema_version": 1,
    }

    nm = maybe_not_modified(request, response, payload_dict)
    if nm is not None:
        return nm
    return payload_dict
