# routers/dashboard.py — Dashboard trend endpoint (B10)
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..etag import maybe_not_modified
from ..models import AnalysisFinding, AnalysisRun
from ..services.analysis_service import SUCCESSFUL_RUN_STATUSES

log = logging.getLogger("sbom.api.dashboard")

router = APIRouter()


@router.get("/trend", status_code=200)
def dashboard_trend(
    request: Request,
    response: Response,
    days: int = Query(30, ge=1, le=365, description="Number of days to look back"),
    db: Session = Depends(get_db),
):
    """Return daily finding counts for the last N days grouped by severity.

    Performance: this used to fetch every AnalysisFinding row in the window
    as a hydrated ORM object and aggregate in Python — fine for tiny demo
    DBs, painful as soon as the project accumulates real data because the
    dashboard renders this on every visit. We now push the aggregation to
    SQL: a single GROUP BY (date(started_on), severity) returns at most
    ``days * |severities|`` rows, which the API just shapes into the
    series the chart expects.
    """
    cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()

    # SQL-level aggregation. ``substr(started_on, 1, 10)`` extracts the
    # YYYY-MM-DD prefix from the ISO string we store in started_on; this
    # works on both SQLite and Postgres without a dialect-specific date
    # cast. Joining to AnalysisRun is what keys the day to a real run;
    # findings without a parent run are filtered out by the inner join.
    # ADR-0001: exclude ERROR/RUNNING/PENDING/NO_DATA runs — their findings
    # may be partial or wrong and shouldn't shape a trend chart.
    date_expr = func.substr(AnalysisRun.started_on, 1, 10).label("date")
    rows = db.execute(
        select(
            date_expr,
            AnalysisFinding.severity.label("severity"),
            func.count(AnalysisFinding.id).label("count"),
        )
        .join(AnalysisRun, AnalysisRun.id == AnalysisFinding.analysis_run_id)
        .where(
            AnalysisRun.started_on >= cutoff,
            AnalysisRun.run_status.in_(SUCCESSFUL_RUN_STATUSES),
        )
        .group_by(date_expr, AnalysisFinding.severity)
    ).all()

    if not rows:
        payload = {"days": days, "series": []}
        nm = maybe_not_modified(request, response, payload)
        return nm if nm is not None else payload

    daily: dict = defaultdict(lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0})
    for date, severity, count in rows:
        if not date:
            continue
        sev = (severity or "unknown").lower()
        if sev in ("critical", "high", "medium", "low"):
            daily[date][sev] += count

    series = [{"date": date, **counts} for date, counts in sorted(daily.items())]
    payload = {"days": days, "series": series}

    # ETag — stable hash of the payload. The dashboard refetches on every
    # navigation; serving a 304 to an unchanged window costs ~one round
    # trip and zero query work.
    nm = maybe_not_modified(request, response, payload)
    return nm if nm is not None else payload
