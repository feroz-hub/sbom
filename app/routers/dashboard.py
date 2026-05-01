# routers/dashboard.py — Findings Trend endpoint (v2)
#
# v1 returned only days that had findings, which made Recharts render
# isolated dots when only one day was populated. v2 always returns exactly
# ``days`` data points (zero-filled), restores ``unknown`` as a first-class
# bucket, and ships annotations + 30-day average + earliest-run hint so the
# chart can tell a complete story without a second round-trip.
#
# Wire format and rules locked in ``docs/dashboard-redesign.md`` §9.2.
from __future__ import annotations

import logging
from statistics import fmean

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..etag import maybe_not_modified
from ..models import AnalysisRun
from ..schemas_dashboard import FindingsTrendResponse
from ..services.analysis_service import SUCCESSFUL_RUN_STATUSES
from ..services.dashboard_metrics import (
    build_trend_annotations,
    build_trend_points,
)

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

    The shape always carries exactly ``days`` points so the frontend can
    render an honest time-series — including the long stretches of zero
    that "we just started using this tool" looks like in the first weeks.

    ``points`` is the canonical field; ``series`` is a one-release alias kept
    so the v1 hero sparkline renders unchanged until Phase 4 ships. Both
    arrays carry the same data.
    """
    points = build_trend_points(db, days=days)
    annotations = build_trend_annotations(db, days=days)

    avg_total = fmean(p.total for p in points) if points else 0.0

    # Earliest-run-date hint — the frontend uses this to decide between the
    # populated chart and an explanatory empty state ("Trend will appear
    # after a week of regular scanning"). Computed in scope so it matches
    # the trend itself; failed/pending runs don't count.
    earliest_iso = db.execute(
        select(func.min(AnalysisRun.started_on)).where(
            AnalysisRun.run_status.in_(SUCCESSFUL_RUN_STATUSES)
        )
    ).scalar()
    earliest_run_date = earliest_iso[:10] if earliest_iso else None

    payload_dict = {
        "days": days,
        "points": [p.model_dump() for p in points],
        # series alias — same data, same field shape. Removed in a follow-up
        # release once the v2 frontend ships and the v1 bundle is retired.
        "series": [p.model_dump() for p in points],
        "annotations": [a.model_dump() for a in annotations],
        "avg_total": round(avg_total, 2),
        "earliest_run_date": earliest_run_date,
        "schema_version": 1,
    }

    nm = maybe_not_modified(request, response, payload_dict)
    if nm is not None:
        return nm
    return payload_dict
