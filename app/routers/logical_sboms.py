"""Tenant-scoped logical SBOM identities and version history; evidence keeps its IDs."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.context import CurrentContext
from ..core.security import require_permission
from ..db import get_db
from ..models import LogicalSBOM, SBOMSource
from ..schemas import LogicalSBOMCreate, LogicalSBOMListResponse, LogicalSBOMOut, SBOMSourceOut
from ..services import audit_service
from ..services.logical_sbom_service import get_logical_sbom, now_iso, ordered_versions, versions_for
from ..services.tenant_access import get_product_for_tenant
from .sboms_crud import _latest_analysis_by_sbom_id, _serialize_sbom_out

router = APIRouter(prefix="/api", tags=["logical-sboms"])


def serialize_master(db, master, versions=None):
    rows = ordered_versions(versions if versions is not None else versions_for(db, master))
    out = LogicalSBOMOut.model_validate(master, from_attributes=True)
    out.version_count = len(rows)
    out.latest_version = _serialize_sbom_out(rows[0], db=db) if rows else None
    return out


@router.post("/products/{product_id}/logical-sboms", response_model=LogicalSBOMOut, status_code=201)
def create_logical_sbom(
    product_id: int,
    payload: LogicalSBOMCreate,
    context: CurrentContext = Depends(require_permission("sbom:upload")),
    assignment=Depends(require_permission("product:assign_sbom")),
    db: Session = Depends(get_db),
):
    product = get_product_for_tenant(db, product_id, context.tenant_id)
    if product is None:
        raise HTTPException(404, detail="Product not found")
    name = payload.name.strip()
    if not name:
        raise HTTPException(422, detail="SBOM name is required")
    master = LogicalSBOM(
        tenant_id=context.tenant_id,
        product_id=product.id,
        name=name,
        description=payload.description,
        created_by=context.actor_label(),
        created_at=now_iso(),
        updated_at=now_iso(),
    )
    db.add(master)
    db.flush()
    audit_service.write_audit_log(
        db,
        context,
        "logical_sbom.created",
        entity_type="logical_sbom",
        entity_id=master.id,
        new_value={"name": master.name, "product_id": master.product_id},
    )
    db.commit()
    return serialize_master(db, master)


@router.get("/products/{product_id}/logical-sboms", response_model=LogicalSBOMListResponse)
def list_logical_sboms(
    product_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    context: CurrentContext = Depends(require_permission("sbom:read")),
    db: Session = Depends(get_db),
):
    if get_product_for_tenant(db, product_id, context.tenant_id) is None:
        raise HTTPException(404, detail="Product not found")
    where = (LogicalSBOM.product_id == product_id, LogicalSBOM.tenant_id == context.tenant_id)
    total = db.scalar(select(func.count()).select_from(LogicalSBOM).where(*where))
    masters = list(
        db.scalars(
            select(LogicalSBOM)
            .where(*where)
            .order_by(LogicalSBOM.id.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    )
    rows = list(
        db.scalars(
            select(SBOMSource).where(
                SBOMSource.logical_sbom_id.in_([m.id for m in masters]), SBOMSource.tenant_id == context.tenant_id
            )
        )
    )
    by_master = {m.id: [] for m in masters}
    for row in rows:
        by_master[row.logical_sbom_id].append(row)
    return LogicalSBOMListResponse(
        items=[serialize_master(db, m, by_master[m.id]) for m in masters],
        total=total or 0,
        page=page,
        page_size=page_size,
    )


@router.get("/logical-sboms/{logical_id}", response_model=LogicalSBOMOut)
def get_master(
    logical_id: int, context: CurrentContext = Depends(require_permission("sbom:read")), db: Session = Depends(get_db)
):
    return serialize_master(db, get_logical_sbom(db, logical_id, context.tenant_id))


@router.get("/logical-sboms/{logical_id}/versions", response_model=list[SBOMSourceOut])
def list_versions(
    logical_id: int, context: CurrentContext = Depends(require_permission("sbom:read")), db: Session = Depends(get_db)
):
    master = get_logical_sbom(db, logical_id, context.tenant_id)
    rows = ordered_versions(versions_for(db, master))
    summaries = _latest_analysis_by_sbom_id(db, sbom_ids=[r.id for r in rows], tenant_id=context.tenant_id)
    return [_serialize_sbom_out(row, latest_analysis=summaries.get(row.id)) for row in rows]
