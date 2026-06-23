"""Tenant-scoped resource lookup helpers.

Use these instead of fetching tenant-owned rows by primary key alone.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Projects, SBOMComponent, SBOMSource


def get_project_for_tenant(db: Session, project_id: int, tenant_id: int) -> Projects | None:
    return db.execute(
        select(Projects).where(Projects.id == project_id, Projects.tenant_id == tenant_id)
    ).scalar_one_or_none()


def get_sbom_for_tenant(db: Session, sbom_id: int, tenant_id: int) -> SBOMSource | None:
    return db.execute(
        select(SBOMSource).where(SBOMSource.id == sbom_id, SBOMSource.tenant_id == tenant_id)
    ).scalar_one_or_none()


def get_component_for_tenant(db: Session, component_id: int, tenant_id: int) -> SBOMComponent | None:
    return db.execute(
        select(SBOMComponent).where(SBOMComponent.id == component_id, SBOMComponent.tenant_id == tenant_id)
    ).scalar_one_or_none()
