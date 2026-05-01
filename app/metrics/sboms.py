"""Portfolio counts — SBOMs and projects. Spec §3.8."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Projects, SBOMSource


def sboms_total(db: Session) -> int:
    """sboms.total — see metrics-spec.md §3.8."""
    return db.execute(select(func.count(SBOMSource.id))).scalar() or 0


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


__all__ = ["sboms_total", "projects_total", "projects_active_total"]
