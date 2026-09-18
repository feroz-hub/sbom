"""Validated ownership and eligible data for dashboard requests.

The dashboard's metric functions share a Session.  A scope installed on that
Session is applied by the existing ORM read filter in ``app.db``; metric SQL
therefore keeps its canonical definitions while every query sees the same
tenant, hierarchy and active HEAD SBOM set.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.context import CurrentContext
from ..core.security import get_current_tenant_context
from ..db import get_db
from ..models import Product, Projects, SBOMSource


@dataclass(frozen=True)
class DashboardScope:
    tenant_id: int
    project_id: int | None = None
    product_id: int | None = None
    sbom_id: int | None = None

    @property
    def key(self) -> tuple[int, int | None, int | None, int | None]:
        return (self.tenant_id, self.project_id, self.product_id, self.sbom_id)

    @property
    def level(self) -> str:
        if self.sbom_id is not None:
            return "SBOM"
        if self.product_id is not None:
            return "APPLICATION"
        if self.project_id is not None:
            return "PROJECT"
        return "TENANT"

    def eligible_sbom_ids(self):
        """SQL subquery, not a Python list; usable by every metric query."""
        s = SBOMSource.__table__.c
        statement = select(s.id).where(s.tenant_id == self.tenant_id, s.is_active.is_(True))
        # Core subqueries need the same parent visibility rules that ORM
        # queries receive from SoftDeleteMixin and Product's deleted_at field.
        # Nullable links remain eligible for older uploads without a Product.
        project = Projects.__table__.c
        visible_projects = select(project.id).where(
            project.tenant_id == self.tenant_id, project.is_active.is_(True),
        )
        product = Product.__table__.c
        visible_products = select(product.id).where(
            product.tenant_id == self.tenant_id,
            product.is_active.is_(True), product.deleted_at.is_(None),
        )
        statement = statement.where(
            s.projectid.is_(None) | s.projectid.in_(visible_projects),
            s.product_id.is_(None) | s.product_id.in_(visible_products),
        )
        # A later version supersedes its parent in operational dashboards.
        child = SBOMSource.__table__.alias("dashboard_child")
        statement = statement.where(
            ~s.id.in_(select(child.c.parent_id).where(
                child.c.tenant_id == self.tenant_id,
                child.c.parent_id.is_not(None),
            ))
        )
        if self.project_id is not None:
            statement = statement.where(s.projectid == self.project_id)
        if self.product_id is not None:
            statement = statement.where(s.product_id == self.product_id)
        if self.sbom_id is not None:
            statement = statement.where(s.id == self.sbom_id)
        return statement


def resolve_dashboard_scope(
    db: Session,
    *,
    tenant_id: int | None,
    project_id: int | None = None,
    product_id: int | None = None,
    sbom_id: int | None = None,
) -> DashboardScope:
    if tenant_id is None:
        raise HTTPException(status_code=403, detail="Tenant selection required")
    if product_id is not None and project_id is None:
        raise HTTPException(status_code=400, detail="Select a project before an application")
    if sbom_id is not None and product_id is None:
        raise HTTPException(status_code=400, detail="Select an application before an SBOM")
    if project_id is not None and db.execute(
        select(Projects.id).where(Projects.id == project_id, Projects.tenant_id == tenant_id)
    ).scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Dashboard scope not found")
    if product_id is not None and db.execute(
        select(Product.id).where(
            Product.id == product_id,
            Product.project_id == project_id,
            Product.tenant_id == tenant_id,
            Product.deleted_at.is_(None),
        )
    ).scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Dashboard scope not found")
    if sbom_id is not None and db.execute(
        select(SBOMSource.id).where(
            SBOMSource.id == sbom_id,
            SBOMSource.projectid == project_id,
            SBOMSource.product_id == product_id,
            SBOMSource.tenant_id == tenant_id,
        )
    ).scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Dashboard scope not found")
    scope = DashboardScope(tenant_id, project_id, product_id, sbom_id)
    if sbom_id is not None and db.execute(scope.eligible_sbom_ids()).scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Dashboard scope not found")
    return scope


@contextmanager
def dashboard_scope(db: Session, scope: DashboardScope) -> Iterator[None]:
    previous = db.info.get("dashboard_scope")
    db.info["dashboard_scope"] = scope
    try:
        yield
    finally:
        if previous is None:
            db.info.pop("dashboard_scope", None)
        else:
            db.info["dashboard_scope"] = previous


def dashboard_scope_dependency(
    request: Request,
    project_id: int | None = Query(None, ge=1),
    product_id: int | None = Query(None, ge=1),
    sbom_id: int | None = Query(None, ge=1),
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
) -> Iterator[DashboardScope]:
    scope = resolve_dashboard_scope(
        db, tenant_id=context.tenant_id, project_id=project_id,
        product_id=product_id, sbom_id=sbom_id,
    )
    request.state.dashboard_scope = scope
    with dashboard_scope(db, scope):
        yield scope
