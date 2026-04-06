# routers/dashboard.py — Dashboard trend endpoint (B10)
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import AnalysisFinding, AnalysisRun

log = logging.getLogger("sbom.api.dashboard")

router = APIRouter()


@router.get("/trend", status_code=200)
def dashboard_trend(
    days: int = Query(30, ge=1, le=365, description="Number of days to look back"),
    db: Session = Depends(get_db),
):
    """Return daily finding counts for the last N days grouped by severity."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    runs = db.execute(
        select(AnalysisRun).where(AnalysisRun.started_on >= cutoff)
    ).scalars().all()

    if not runs:
        return {"days": days, "series": []}

    run_ids = [r.id for r in runs]
    run_date_map = {r.id: (r.started_on or "")[:10] for r in runs}

    findings = db.execute(
        select(AnalysisFinding).where(AnalysisFinding.analysis_run_id.in_(run_ids))
    ).scalars().all()

    daily: dict = defaultdict(lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0})
    for f in findings:
        date = run_date_map.get(f.analysis_run_id, "")
        if date:
            sev = (f.severity or "unknown").lower()
            if sev in ("critical", "high", "medium", "low"):
                daily[date][sev] += 1

    series = [
        {"date": date, **counts}
        for date, counts in sorted(daily.items())
    ]

    return {"days": days, "series": series}
