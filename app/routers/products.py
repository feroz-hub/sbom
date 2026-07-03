"""Product CRUD and Product → SBOM listing APIs."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Path, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.context import CurrentContext
from ..core.security import get_current_tenant_context
from ..db import get_db
from ..models import Product, SBOMSource
from ..schemas import ProductCreate, ProductListResponse, ProductRead, ProductSummary, ProductUpdate, SBOMSourceOut
from ..services import audit_service
from ..services.product_service import (
    ensure_unique_product_slug,
    normalize_product_name,
    now_iso,
)
from ..services.tenant_access import get_product_for_tenant, get_project_for_tenant

router = APIRouter(prefix="/api", tags=["products"])


def _ensure_name_available(
    db: Session,
    *,
    tenant_id: int,
    project_id: int,
    name: str,
    product_id: int | None = None,
) -> None:
    normalized = normalize_product_name(name)
    stmt = select(Product.id).where(
        Product.tenant_id == tenant_id,
        Product.project_id == project_id,
        Product.normalized_name == normalized,
        Product.is_active.is_(True),
    )
    if product_id is not None:
        stmt = stmt.where(Product.id != product_id)
    if db.execute(stmt).scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="Product name already exists in this project")


def _summary(db: Session, product: Product) -> ProductSummary:
    latest = db.execute(
        select(SBOMSource.id, SBOMSource.sbom_version, SBOMSource.productver)
        .where(
            SBOMSource.tenant_id == product.tenant_id,
            SBOMSource.product_id == product.id,
            SBOMSource.is_active.is_(True),
        )
        .order_by(SBOMSource.id.desc())
        .limit(1)
    ).first()
    count = db.execute(
        select(func.count(SBOMSource.id)).where(
            SBOMSource.tenant_id == product.tenant_id,
            SBOMSource.product_id == product.id,
            SBOMSource.is_active.is_(True),
        )
    ).scalar_one()
    return ProductSummary(
        id=product.id,
        project_id=product.project_id,
        name=product.name,
        slug=product.slug,
        description=product.description,
        vendor=product.vendor,
        category=product.category,
        status=product.status,
        sbom_count=int(count or 0),
        latest_sbom_id=latest[0] if latest else None,
        latest_sbom_version=(latest[1] or latest[2]) if latest else None,
    )


def _read(db: Session, product: Product) -> ProductRead:
    summary = _summary(db, product)
    return ProductRead(
        id=product.id,
        tenant_id=product.tenant_id,
        project_id=product.project_id,
        name=product.name,
        normalized_name=product.normalized_name,
        slug=product.slug,
        description=product.description,
        product_key=product.product_key,
        vendor=product.vendor,
        category=product.category,
        status=product.status,
        latest_version=product.latest_version,
        metadata_json=product.metadata_json,
        created_by=product.created_by,
        created_at=product.created_at,
        updated_at=product.updated_at,
        is_active=bool(product.is_active),
        deleted_at=product.deleted_at,
        sbom_count=summary.sbom_count,
        latest_sbom_id=summary.latest_sbom_id,
        latest_sbom_version=summary.latest_sbom_version,
    )


@router.post("/projects/{project_id}/products", response_model=ProductRead, status_code=status.HTTP_201_CREATED)
def create_product(
    payload: ProductCreate,
    project_id: int = Path(..., ge=1),
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    if get_project_for_tenant(db, project_id, context.tenant_id) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    name = payload.name.strip()
    _ensure_name_available(db, tenant_id=context.tenant_id, project_id=project_id, name=name)
    product = Product(
        tenant_id=context.tenant_id,
        project_id=project_id,
        name=name,
        normalized_name=normalize_product_name(name),
        slug=ensure_unique_product_slug(db, tenant_id=context.tenant_id, project_id=project_id, name=name),
        description=payload.description,
        product_key=payload.product_key,
        vendor=payload.vendor,
        category=payload.category,
        status=(payload.status or "active").strip().lower(),
        latest_version=payload.latest_version,
        metadata_json=payload.metadata_json,
        created_by=context.actor_label(),
        created_at=now_iso(),
        updated_at=now_iso(),
    )
    db.add(product)
    db.flush()
    audit_service.write_audit_log(
        db,
        context,
        "product.created",
        entity_type="product",
        entity_id=product.id,
        new_value={"project_id": project_id, "product_id": product.id, "name": product.name},
    )
    db.commit()
    db.refresh(product)
    return _read(db, product)


@router.get("/projects/{project_id}/products", response_model=ProductListResponse)
def list_project_products(
    project_id: int = Path(..., ge=1),
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    if get_project_for_tenant(db, project_id, context.tenant_id) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    products = db.execute(
        select(Product)
        .where(
            Product.tenant_id == context.tenant_id,
            Product.project_id == project_id,
            Product.is_active.is_(True),
        )
        .order_by(Product.name.asc())
    ).scalars().all()
    items = [_summary(db, product) for product in products]
    return ProductListResponse(items=items, total=len(items))


@router.get("/products/{product_id}", response_model=ProductRead)
def get_product(
    product_id: int = Path(..., ge=1),
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    product = get_product_for_tenant(db, product_id, context.tenant_id)
    if product is None:
        raise HTTPException(status_code=404, detail="Product not found")
    return _read(db, product)


@router.patch("/products/{product_id}", response_model=ProductRead)
def update_product(
    payload: ProductUpdate,
    product_id: int = Path(..., ge=1),
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    product = get_product_for_tenant(db, product_id, context.tenant_id)
    if product is None:
        raise HTTPException(status_code=404, detail="Product not found")
    old_value = {
        "project_id": product.project_id,
        "product_id": product.id,
        "name": product.name,
        "slug": product.slug,
    }
    data = payload.model_dump(exclude_unset=True)
    if "name" in data and data["name"] is not None:
        name = data["name"].strip()
        _ensure_name_available(
            db,
            tenant_id=context.tenant_id,
            project_id=product.project_id,
            name=name,
            product_id=product.id,
        )
        product.name = name
        product.normalized_name = normalize_product_name(name)
        product.slug = ensure_unique_product_slug(
            db,
            tenant_id=context.tenant_id,
            project_id=product.project_id,
            name=name,
            product_id=product.id,
        )
    for field in ("description", "product_key", "vendor", "category", "status", "latest_version", "metadata_json"):
        if field in data:
            setattr(product, field, data[field])
    product.updated_at = now_iso()
    db.add(product)
    audit_service.write_audit_log(
        db,
        context,
        "product.updated",
        entity_type="product",
        entity_id=product.id,
        old_value=old_value,
        new_value={"project_id": product.project_id, "product_id": product.id, "name": product.name},
    )
    db.commit()
    db.refresh(product)
    return _read(db, product)


@router.delete("/products/{product_id}", status_code=status.HTTP_200_OK)
def delete_product(
    product_id: int = Path(..., ge=1),
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    product = get_product_for_tenant(db, product_id, context.tenant_id)
    if product is None:
        raise HTTPException(status_code=404, detail="Product not found")
    sbom_count = db.execute(
        select(func.count(SBOMSource.id)).where(
            SBOMSource.tenant_id == context.tenant_id,
            SBOMSource.product_id == product.id,
            SBOMSource.is_active.is_(True),
        )
    ).scalar_one()
    if sbom_count:
        raise HTTPException(status_code=409, detail="Product has SBOMs. Move SBOMs before deleting the product.")
    product.is_active = False
    product.deleted_at = now_iso()
    product.deactivated_by = context.actor_label()
    product.updated_at = now_iso()
    db.add(product)
    audit_service.write_audit_log(
        db,
        context,
        "product.deleted",
        entity_type="product",
        entity_id=product.id,
        old_value={"project_id": product.project_id, "product_id": product.id, "name": product.name},
    )
    db.commit()
    return {"status": "deleted", "product_id": product.id}


@router.get("/products/{product_id}/sboms", response_model=list[SBOMSourceOut])
def list_product_sboms(
    product_id: int = Path(..., ge=1),
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    product = get_product_for_tenant(db, product_id, context.tenant_id)
    if product is None:
        raise HTTPException(status_code=404, detail="Product not found")
    return db.execute(
        select(SBOMSource)
        .where(
            SBOMSource.tenant_id == context.tenant_id,
            SBOMSource.product_id == product.id,
            SBOMSource.is_active.is_(True),
        )
        .order_by(SBOMSource.id.desc())
    ).scalars().all()
