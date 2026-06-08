"""Portfolio counts — SBOMs and projects. Spec §3.8."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import AnalysisRun, Projects, SBOMSource
from .base import COMPLETED_RUN_STATUSES


def sboms_total(db: Session) -> int:
    """sboms.total — see metrics-spec.md §3.8.

    "Total SBOMs Stored" — every uploaded SBOM, regardless of analysis state.
    """
    return db.execute(select(func.count(SBOMSource.id))).scalar() or 0


def sboms_analysed_total(db: Session) -> int:
    """sboms.analysed_total — "Total SBOMs Analysed".

    Distinct SBOMs that have at least one *completed* analysis run
    (``run_status`` in OK/FINDINGS/PARTIAL). A subset of ``sboms_total``.
    """
    return (
        db.execute(
            select(func.count(func.distinct(AnalysisRun.sbom_id))).where(
                AnalysisRun.run_status.in_(COMPLETED_RUN_STATUSES)
            )
        ).scalar()
        or 0
    )


def applications_scanned_total(db: Session) -> int:
    """applications.scanned_total — "Total Applications Scanned".

    Distinct applications (projects) with at least one completed analysis run
    across any of their SBOMs. ``project_id`` is nullable on a run, so null
    projects are excluded.
    """
    return (
        db.execute(
            select(func.count(func.distinct(AnalysisRun.project_id)))
            .where(AnalysisRun.run_status.in_(COMPLETED_RUN_STATUSES))
            .where(AnalysisRun.project_id.is_not(None))
        ).scalar()
        or 0
    )


def projects_total(db: Session) -> int:
    """projects.total — see metrics-spec.md §3.8."""
    return db.execute(select(func.count(Projects.id))).scalar() or 0


def projects_active_total(db: Session) -> int:
    """projects.active_total — see metrics-spec.md §3.8."""
    return (
        db.execute(
            select(func.count(Projects.id)).where(Projects.project_status == 1)
        ).scalar()
        or 0
    )


__all__ = [
    "sboms_total",
    "sboms_analysed_total",
    "applications_scanned_total",
    "projects_total",
    "projects_active_total",
]
