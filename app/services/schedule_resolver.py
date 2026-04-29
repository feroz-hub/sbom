"""
Schedule resolver — turn the (project, sbom) hierarchy into a concrete
list of SBOMs that need to be re-analyzed at tick time.

Resolution rules (Plan §"Inheritance rule"):
  1. An SBOM with its own enabled SBOM-level schedule wins.
  2. Otherwise, an enabled PROJECT-level schedule cascades to every SBOM
     in the project that does NOT have its own schedule (enabled or
     disabled — an explicit SBOM-level row, even paused, opts out of the
     cascade).
  3. SBOMs with no SBOM- or project-level schedule are left alone.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AnalysisSchedule, SBOMSource


@dataclass(frozen=True)
class DueTarget:
    """A concrete SBOM that should be analyzed, with the schedule that triggered it."""

    sbom_id: int
    schedule_id: int
    schedule_scope: str  # 'PROJECT' | 'SBOM'


def find_due_targets(db: Session, now_iso_str: str) -> list[DueTarget]:
    """
    Return every SBOM that is due to be re-analyzed at ``now_iso_str``.

    Walks all enabled schedules whose ``next_run_at <= now`` and expands
    project-scope schedules into their member SBOMs, honouring the
    "SBOM-level row opts out of cascade" rule.
    """
    due_schedules = (
        db.execute(
            select(AnalysisSchedule)
            .where(AnalysisSchedule.enabled.is_(True))
            .where(AnalysisSchedule.next_run_at.isnot(None))
            .where(AnalysisSchedule.next_run_at <= now_iso_str)
            .order_by(AnalysisSchedule.id.asc())
        )
        .scalars()
        .all()
    )

    if not due_schedules:
        return []

    # SBOM-scope schedules: one target each, deduped by sbom_id (a sanity
    # belt — the partial-unique index already prevents this row-side).
    sbom_scope_targets: dict[int, DueTarget] = {}
    project_scope_schedules: list[AnalysisSchedule] = []

    for sched in due_schedules:
        if sched.scope == "SBOM" and sched.sbom_id is not None:
            sbom_scope_targets[sched.sbom_id] = DueTarget(
                sbom_id=sched.sbom_id,
                schedule_id=sched.id,
                schedule_scope="SBOM",
            )
        elif sched.scope == "PROJECT" and sched.project_id is not None:
            project_scope_schedules.append(sched)

    # For project-scope expansion we need the set of SBOM IDs that have
    # ANY sbom-level schedule (even disabled ones — explicit override).
    overridden_sbom_ids: set[int] = set(
        db.execute(
            select(AnalysisSchedule.sbom_id).where(
                AnalysisSchedule.scope == "SBOM",
                AnalysisSchedule.sbom_id.isnot(None),
            )
        )
        .scalars()
        .all()
    )

    targets: list[DueTarget] = list(sbom_scope_targets.values())

    for sched in project_scope_schedules:
        member_ids = (
            db.execute(
                select(SBOMSource.id).where(SBOMSource.projectid == sched.project_id)
            )
            .scalars()
            .all()
        )
        for sid in member_ids:
            if sid in overridden_sbom_ids:
                continue
            if sid in sbom_scope_targets:  # belt-and-suspenders
                continue
            targets.append(
                DueTarget(
                    sbom_id=sid,
                    schedule_id=sched.id,
                    schedule_scope="PROJECT",
                )
            )

    return targets


def resolve_for_sbom(db: Session, sbom_id: int) -> AnalysisSchedule | None:
    """
    Return the effective schedule for a single SBOM, or None.

    Used by the API ``GET /api/sboms/{id}/schedule`` to render the
    "inherited from project" badge in the UI.
    """
    own = db.execute(
        select(AnalysisSchedule).where(
            AnalysisSchedule.scope == "SBOM",
            AnalysisSchedule.sbom_id == sbom_id,
        )
    ).scalar_one_or_none()
    if own is not None:
        return own

    sbom = db.get(SBOMSource, sbom_id)
    if sbom is None or sbom.projectid is None:
        return None

    return db.execute(
        select(AnalysisSchedule).where(
            AnalysisSchedule.scope == "PROJECT",
            AnalysisSchedule.project_id == sbom.projectid,
        )
    ).scalar_one_or_none()
