"""SBOM > PRODUCT > PROJECT > TENANT; explicit paused children opt out."""
from dataclasses import dataclass

from sqlalchemy import or_, select

from ..models import AnalysisSchedule, Product, Projects, SBOMSource


@dataclass(frozen=True)
class DueTarget:
    sbom_id: int
    schedule_id: int
    schedule_scope: str


def _eligible_sboms(db):
    return list(db.scalars(select(SBOMSource).where(
        or_(SBOMSource.projectid.is_(None), SBOMSource.projectid.in_(select(Projects.id).where(Projects.is_active.is_(True)))),
        or_(SBOMSource.product_id.is_(None), SBOMSource.product_id.in_(select(Product.id).where(Product.is_active.is_(True)))),
    )))


def _index(schedules):
    return {(s.tenant_id, s.scope, s.sbom_id if s.scope == "SBOM" else s.product_id if s.scope == "PRODUCT" else s.project_id if s.scope == "PROJECT" else s.tenant_id): s for s in schedules}


def _effective(sbom, index):
    for scope, identifier in [("SBOM", sbom.id), ("PRODUCT", sbom.product_id), ("PROJECT", sbom.projectid), ("TENANT", sbom.tenant_id)]:
        if identifier is not None and (row := index.get((sbom.tenant_id, scope, identifier))) is not None:
            return row
    return None


def find_due_targets(db, now_iso_str):
    index = _index(db.scalars(select(AnalysisSchedule).order_by(AnalysisSchedule.id)))
    targets = []
    for sbom in _eligible_sboms(db):
        row = _effective(sbom, index)
        if row and row.enabled and row.next_run_at and row.next_run_at <= now_iso_str:
            targets.append(DueTarget(sbom.id, row.id, row.scope))
    return targets


def targets_for_schedule(db, schedule):
    index = _index(db.scalars(select(AnalysisSchedule).where(AnalysisSchedule.tenant_id == schedule.tenant_id)))
    return [sbom.id for sbom in _eligible_sboms(db) if sbom.tenant_id == schedule.tenant_id
            and (row := _effective(sbom, index)) is not None and row.id == schedule.id]


def resolve_for_sbom(db, sbom_id):
    sbom = next((s for s in _eligible_sboms(db) if s.id == sbom_id), None)
    if not sbom:
        return None
    return _effective(sbom, _index(db.scalars(select(AnalysisSchedule).where(AnalysisSchedule.tenant_id == sbom.tenant_id))))
