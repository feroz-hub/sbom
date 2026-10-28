"""Product hierarchy helpers.

Products sit between Projects and SBOMs. This module keeps the compatibility
policy in one place: legacy callers that only know ``project_id`` are assigned
to the project's default "Legacy / Unassigned Product".
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..models import Product, Projects
from .tenant_access import get_project_for_tenant

DEFAULT_PRODUCT_NAME = "Legacy / Unassigned Product"
DEFAULT_PRODUCT_SLUG = "legacy-unassigned-product"
DEFAULT_UNASSIGNED_PROJECT_NAME = "Unassigned Project"


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def normalize_product_name(name: str) -> str:
    return re.sub(r"\s+", " ", (name or "").strip()).casefold()


def slugify_product_name(name: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9]+", "-", (name or "").strip().lower()).strip("-")
    return value or "product"


def get_product_for_tenant(db: Session, product_id: int, tenant_id: int) -> Product | None:
    return db.execute(
        select(Product).where(
            Product.id == product_id,
            Product.tenant_id == tenant_id,
            Product.is_active.is_(True),
        )
    ).scalar_one_or_none()


def ensure_unique_product_slug(db: Session, *, tenant_id: int, project_id: int, name: str, product_id: int | None = None) -> str:
    base = slugify_product_name(name)
    slug = base
    suffix = 2
    while True:
        stmt = select(Product.id).where(
            Product.tenant_id == tenant_id,
            Product.project_id == project_id,
            Product.slug == slug,
        )
        if product_id is not None:
            stmt = stmt.where(Product.id != product_id)
        existing = db.execute(stmt).scalar_one_or_none()
        if existing is None:
            return slug
        slug = f"{base}-{suffix}"
        suffix += 1


def get_or_create_default_product(
    db: Session,
    *,
    tenant_id: int,
    project_id: int,
    actor: str = "system",
) -> Product:
    project = get_project_for_tenant(db, project_id, tenant_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    existing = db.execute(
        select(Product).where(
            Product.tenant_id == tenant_id,
            Product.project_id == project_id,
            Product.slug == DEFAULT_PRODUCT_SLUG,
        )
    ).scalar_one_or_none()
    if existing is not None:
        if not existing.is_active:
            existing.is_active = True
            existing.deleted_at = None
            existing.deactivated_at = None
            existing.deactivated_by = None
            existing.updated_at = now_iso()
            db.add(existing)
            db.flush()
        return existing

    product = Product(
        tenant_id=tenant_id,
        project_id=project_id,
        name=DEFAULT_PRODUCT_NAME,
        normalized_name=normalize_product_name(DEFAULT_PRODUCT_NAME),
        slug=DEFAULT_PRODUCT_SLUG,
        description="Compatibility product for SBOMs uploaded before product assignment became required.",
        status="active",
        created_by=actor,
        created_at=now_iso(),
        updated_at=now_iso(),
    )
    db.add(product)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        product = db.execute(
            select(Product).where(
                Product.tenant_id == tenant_id,
                Product.project_id == project_id,
                Product.slug == DEFAULT_PRODUCT_SLUG,
            )
        ).scalar_one()
    return product


def get_or_create_unassigned_project(db: Session, *, tenant_id: int, actor: str = "system") -> Projects:
    existing = db.execute(
        select(Projects).where(
            Projects.tenant_id == tenant_id,
            Projects.project_name == DEFAULT_UNASSIGNED_PROJECT_NAME,
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing
    project = Projects(
        tenant_id=tenant_id,
        project_name=DEFAULT_UNASSIGNED_PROJECT_NAME,
        project_details="Compatibility project for legacy SBOMs created without project_id.",
        project_status=1,
        created_on=now_iso(),
        created_by=actor,
    )
    db.add(project)
    db.flush()
    return project


def resolve_product_assignment(
    db: Session,
    *,
    tenant_id: int,
    project_id: int | None,
    product_id: int | None,
    actor: str = "system",
    require_project: bool = True,
) -> tuple[int | None, Product | None, bool]:
    """Resolve project/product IDs and enforce tenant/project consistency.

    Returns ``(project_id, product, used_default_product)``.
    """
    if project_id is not None and get_project_for_tenant(db, project_id, tenant_id) is None:
        raise HTTPException(status_code=404, detail="Project not found")

    if product_id is not None:
        product = get_product_for_tenant(db, product_id, tenant_id)
        if product is None:
            raise HTTPException(status_code=404, detail="Product not found")
        if project_id is not None and product.project_id != project_id:
            raise HTTPException(status_code=409, detail="Product does not belong to submitted project")
        return product.project_id, product, False

    if project_id is None:
        if require_project:
            project = get_or_create_unassigned_project(db, tenant_id=tenant_id, actor=actor)
            product = get_or_create_default_product(db, tenant_id=tenant_id, project_id=project.id, actor=actor)
            return project.id, product, True
        return None, None, False

    product = get_or_create_default_product(db, tenant_id=tenant_id, project_id=project_id, actor=actor)
    return project_id, product, True
