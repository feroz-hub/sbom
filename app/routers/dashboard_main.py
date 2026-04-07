"""
Main dashboard endpoints router.

Routes:
  GET /dashboard/stats              summary counts
  GET /dashboard/recent-sboms       recently uploaded SBOMs
  GET /dashboard/activity           active vs stale SBOM counts
  GET /dashboard/severity           aggregate severity counts
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Projects, SBOMSource, AnalysisFinding, AnalysisRun

log = logging.getLogger(__name__)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats")
def dashboard_stats(db: Session = Depends(get_db)):
    """Summary counts for the home dashboard cards."""
    total_projects = db.execute(select(func.count(Projects.id))).scalar_one()
    total_sboms = db.execute(select(func.count(SBOMSource.id))).scalar_one()
    total_vulnerabilities = db.execute(select(func.count(AnalysisFinding.id))).scalar_one()
    return {
        "total_projects": total_projects,
        "total_sboms": total_sboms,
        "total_vulnerabilities": total_vulnerabilities,
    }


@router.get("/recent-sboms")
def dashboard_recent_sboms(
    limit: int = Query(5, ge=1, le=50),
    db: Session = Depends(get_db),
):
    """Most recently uploaded SBOMs for the home dashboard list."""
    items = db.execute(
        select(SBOMSource).order_by(SBOMSource.id.desc()).limit(limit)
    ).scalars().all()
    return [
        {"id": s.id, "sbom_name": s.sbom_name, "created_on": s.created_on}
        for s in items
    ]


@router.get("/activity")
def dashboard_activity(db: Session = Depends(get_db)):
    """Active vs stale SBOM counts for the activity doughnut chart."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    active = db.execute(
        select(func.count(SBOMSource.id)).where(SBOMSource.created_on >= cutoff)
    ).scalar_one()
    total = db.execute(select(func.count(SBOMSource.id))).scalar_one()
    return {"active_30d": active, "stale": max(0, total - active)}


@router.get("/severity")
def dashboard_severity(db: Session = Depends(get_db)):
    """Aggregate severity counts across all findings for the severity chart."""
    rows = db.execute(
        select(AnalysisFinding.severity, func.count(AnalysisFinding.id))
        .group_by(AnalysisFinding.severity)
    ).all()
    buckets: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for sev, cnt in rows:
        key = (sev or "unknown").lower()
        if key in buckets:
            buckets[key] += cnt
        else:
            buckets["unknown"] += cnt
    return buckets
