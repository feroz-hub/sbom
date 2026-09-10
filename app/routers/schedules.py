"""
Periodic analysis schedules — CRUD + actions router.

Endpoints
---------
Project-scope:
    POST   /api/projects/{id}/schedule    create or replace
    GET    /api/projects/{id}/schedule
    PATCH  /api/projects/{id}/schedule
    DELETE /api/projects/{id}/schedule

Product-scope (overrides project cascade):
    POST   /api/products/{id}/schedule
    GET    /api/products/{id}/schedule
    PATCH  /api/products/{id}/schedule
    DELETE /api/products/{id}/schedule

SBOM-scope (overrides product/project cascade):
    POST   /api/sboms/{id}/schedule       create or replace SBOM-level override
    GET    /api/sboms/{id}/schedule       returns the effective inherited schedule
    PATCH  /api/sboms/{id}/schedule
    DELETE /api/sboms/{id}/schedule       removes override; SBOM falls back to cascade

Operator surface:
    GET    /api/schedules                 flat list (filter by scope/enabled)
    GET    /api/schedules/{id}/targets    effective target preview with reasons
    POST   /api/schedules/{id}/run-now    fire immediately, does NOT change next_run_at
    POST   /api/schedules/{id}/pause      enabled=false
    POST   /api/schedules/{id}/resume     enabled=true, recomputes next_run_at
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.context import CurrentContext
from ..core.security import require_permission
from ..db import get_db
from ..models import AnalysisSchedule, Product, Projects, SBOMSource
from ..schemas import ScheduleOut, ScheduleResolved, ScheduleTargetPreview, ScheduleUpsert
from ..services.schedule_resolver import resolve_effective_schedule, resolve_effective_schedule_for_product
from ..services.scheduling import (
    ScheduleSpec,
    ScheduleValidationError,
    compute_next_run_at,
    to_iso,
    validate_spec,
)
from ..services.soft_delete import SoftDeleteService
from ..services.tenant_access import get_product_for_tenant, get_project_for_tenant, get_sbom_for_tenant

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["schedules"])


def _tenant_schedule(db, tenant_id, context):
    from ..services.report_access import is_report_admin, report_error
    if context.tenant_id != tenant_id or not is_report_admin(context):
        raise report_error("TENANT_SCHEDULE_ADMIN_REQUIRED", "A tenant administrator must manage tenant-wide schedules.")
    return db.scalar(select(AnalysisSchedule).where(AnalysisSchedule.tenant_id == tenant_id, AnalysisSchedule.scope == "TENANT"))


@router.get("/tenants/{tenant_id}/schedule", response_model=ScheduleOut | None)
def get_tenant_schedule(tenant_id: int, context: CurrentContext = Depends(require_permission("product:read")), db: Session = Depends(get_db)):
    row = _tenant_schedule(db, tenant_id, context)
    return _serialize(row) if row else None


@router.post("/tenants/{tenant_id}/schedule", response_model=ScheduleOut)
@router.patch("/tenants/{tenant_id}/schedule", response_model=ScheduleOut)
def upsert_tenant_schedule(payload: ScheduleUpsert, tenant_id: int, context: CurrentContext = Depends(require_permission("product:manage_schedule")), db: Session = Depends(get_db)):
    _validate_scope_options("TENANT", payload)
    row = _tenant_schedule(db, tenant_id, context)
    if row is None:
        row = AnalysisSchedule(tenant_id=tenant_id, scope="TENANT", created_on=to_iso(_now()), created_by=context.actor_label())
        db.add(row)
    _apply_payload(row, payload, partial=False)
    _validate_or_422(_spec_from_row(row))
    _refresh_next_run_at(row)
    row.modified_on = to_iso(_now())
    db.flush()
    _audit_schedule(db, context, "schedule.tenant.upsert", row)
    db.commit()
    return _serialize(row)


@router.delete("/tenants/{tenant_id}/schedule", status_code=204)
def delete_tenant_schedule(tenant_id: int, context: CurrentContext = Depends(require_permission("product:manage_schedule")), db: Session = Depends(get_db)):
    from ..services.audit_service import write_audit_log
    row = _tenant_schedule(db, tenant_id, context)
    if row:
        row.is_active, row.enabled = False, False
        row.deactivated_at, row.deactivated_by = _now(), context.actor_label()
        write_audit_log(db, context, "schedule.tenant.delete", entity_type="analysis_schedule", entity_id=row.id)
        db.commit()
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _spec_from_payload(payload: ScheduleUpsert) -> ScheduleSpec:
    return ScheduleSpec(
        cadence=payload.cadence,
        cron_expression=payload.cron_expression,
        day_of_week=payload.day_of_week,
        day_of_month=payload.day_of_month,
        hour_utc=payload.hour_utc,
    )


def _spec_from_row(row: AnalysisSchedule) -> ScheduleSpec:
    return ScheduleSpec(
        cadence=row.cadence,
        cron_expression=row.cron_expression,
        day_of_week=row.day_of_week,
        day_of_month=row.day_of_month,
        hour_utc=row.hour_utc,
    )


def _apply_payload(row: AnalysisSchedule, payload: ScheduleUpsert, *, partial: bool) -> None:
    """Copy non-None fields from payload onto the ORM row.

    For PATCH (``partial=True``) we treat unset fields as "leave alone";
    for POST (``partial=False``) all fields are written so the result is
    fully derived from the payload.
    """
    data = payload.model_dump(exclude_unset=partial)
    for field in (
        "cadence",
        "cron_expression",
        "day_of_week",
        "day_of_month",
        "hour_utc",
        "timezone",
        "mode",
        "target_version_policy",
        "enabled",
        "min_gap_minutes",
    ):
        if field in data:
            setattr(row, field, data[field])
    if data.get("modified_by"):
        row.modified_by = data["modified_by"]
    if row.scope == "SBOM":
        row.target_version_policy = "CURRENT_ONLY"
    if row.mode == "EXCLUDED":
        row.enabled = False


def _validate_or_422(spec: ScheduleSpec) -> None:
    try:
        validate_spec(spec)
    except ScheduleValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _refresh_next_run_at(row: AnalysisSchedule) -> None:
    """Recompute next_run_at from the row's cadence and the current clock.

    Called after every create / patch / resume so the tick scanner sees a
    correct cursor without waiting for the row to drift naturally.
    """
    if not row.enabled or row.mode == "EXCLUDED":
        row.next_run_at = None
        return
    nxt = compute_next_run_at(_spec_from_row(row), _now())
    row.next_run_at = to_iso(nxt)


def _get_project_or_404(db: Session, project_id: int, tenant_id: int | None = None) -> Projects:
    proj = get_project_for_tenant(db, project_id, tenant_id) if tenant_id is not None else db.get(Projects, project_id)
    if proj is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return proj


def _get_sbom_or_404(db: Session, sbom_id: int, tenant_id: int | None = None) -> SBOMSource:
    sbom = get_sbom_for_tenant(db, sbom_id, tenant_id) if tenant_id is not None else db.get(SBOMSource, sbom_id)
    if sbom is None:
        raise HTTPException(status_code=404, detail="SBOM not found")
    return sbom


def _get_product_or_404(db: Session, product_id: int, tenant_id: int | None = None) -> Product:
    product = get_product_for_tenant(db, product_id, tenant_id) if tenant_id is not None else db.get(Product, product_id)
    if product is None:
        raise HTTPException(status_code=404, detail="Product not found")
    return product


def _serialize(row: AnalysisSchedule) -> dict[str, Any]:
    project = row.project
    product = row.product
    sbom = row.sbom
    if project is None and product is not None:
        project = product.project
    if sbom is not None:
        product = product or sbom.product
        project = project or sbom.project
    state = "EXCLUDED" if row.mode == "EXCLUDED" else "PAUSED" if not row.enabled else "CUSTOM"
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "scope": row.scope,
        "project_id": row.project_id,
        "product_id": row.product_id,
        "sbom_id": row.sbom_id,
        "cadence": row.cadence,
        "cron_expression": row.cron_expression,
        "day_of_week": row.day_of_week,
        "day_of_month": row.day_of_month,
        "hour_utc": row.hour_utc,
        "timezone": row.timezone,
        "mode": row.mode,
        "target_version_policy": row.target_version_policy,
        "state": state,
        "enabled": bool(row.enabled),
        "next_run_at": row.next_run_at,
        "last_run_at": row.last_run_at,
        "last_run_status": row.last_run_status,
        "last_run_id": row.last_run_id,
        "consecutive_failures": row.consecutive_failures or 0,
        "min_gap_minutes": row.min_gap_minutes or 60,
        "created_on": row.created_on,
        "created_by": row.created_by,
        "modified_on": row.modified_on,
        "modified_by": row.modified_by,
        "project_name": project.project_name if project else None,
        "product_name": product.name if product else None,
        "sbom_name": sbom.sbom_name if sbom else None,
        "sbom_version": (sbom.sbom_version or sbom.productver) if sbom else None,
    }


def _validate_scope_options(scope: str, payload: ScheduleUpsert) -> None:
    if payload.mode == "EXCLUDED" and scope not in {"PRODUCT", "SBOM"}:
        raise HTTPException(status_code=422, detail="Only Product and SBOM schedules can be excluded")
    if scope == "SBOM" and payload.target_version_policy != "CURRENT_ONLY":
        raise HTTPException(status_code=422, detail="SBOM schedules always target their exact SBOM")


def _audit_schedule(db: Session, context: CurrentContext, action: str, row: AnalysisSchedule) -> None:
    from ..services.audit_service import write_audit_log

    write_audit_log(
        db,
        context,
        action,
        entity_type="analysis_schedule",
        entity_id=row.id,
        new_value={
            "scope": row.scope,
            "project_id": row.project_id,
            "product_id": row.product_id,
            "sbom_id": row.sbom_id,
            "mode": row.mode,
            "enabled": bool(row.enabled),
            "target_version_policy": row.target_version_policy,
        },
    )


def _set_excluded(
    db: Session,
    context: CurrentContext,
    *,
    scope: str,
    product_id: int | None = None,
    sbom_id: int | None = None,
) -> AnalysisSchedule:
    stmt = select(AnalysisSchedule).where(
        AnalysisSchedule.tenant_id == context.tenant_id,
        AnalysisSchedule.scope == scope,
    )
    stmt = stmt.where(AnalysisSchedule.product_id == product_id) if scope == "PRODUCT" else stmt.where(
        AnalysisSchedule.sbom_id == sbom_id
    )
    row = db.scalar(stmt)
    if row is None:
        row = AnalysisSchedule(
            tenant_id=context.tenant_id,
            scope=scope,
            product_id=product_id,
            sbom_id=sbom_id,
            cadence="DAILY",
            hour_utc=2,
            timezone="UTC",
            created_on=to_iso(_now()),
            created_by=context.actor_label(),
        )
        db.add(row)
    row.mode = "EXCLUDED"
    row.enabled = False
    row.next_run_at = None
    row.target_version_policy = "CURRENT_ONLY"
    row.modified_on = to_iso(_now())
    row.modified_by = context.actor_label()
    db.flush()
    _audit_schedule(db, context, f"schedule.{scope.lower()}.exclude", row)
    db.commit()
    db.refresh(row)
    return row


def _restore_inheritance(db: Session, context: CurrentContext, row: AnalysisSchedule) -> dict[str, Any]:
    schedule_id = int(row.id)
    scope = row.scope
    SoftDeleteService(db).soft_delete(row, user_id=context.actor_label(), cascade=False)
    _audit_schedule(db, context, f"schedule.{scope.lower()}.restore_inheritance", row)
    db.commit()
    return {"status": "inherited", "id": schedule_id, "scope": scope}


# ---------------------------------------------------------------------------
# Project-scope endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/projects/{project_id}/schedule",
    response_model=ScheduleOut,
    status_code=status.HTTP_201_CREATED,
)
def upsert_project_schedule(
    payload: ScheduleUpsert,
    project_id: int = Path(..., ge=1),
    context: CurrentContext = Depends(require_permission("product:manage_schedule")),
    db: Session = Depends(get_db),
):
    _get_project_or_404(db, project_id, context.tenant_id)
    _validate_scope_options("PROJECT", payload)
    _validate_or_422(_spec_from_payload(payload))

    existing = db.execute(
        select(AnalysisSchedule).where(
            AnalysisSchedule.tenant_id == context.tenant_id,
            AnalysisSchedule.scope == "PROJECT",
            AnalysisSchedule.project_id == project_id,
        )
    ).scalar_one_or_none()

    if existing is None:
        existing = AnalysisSchedule(
            tenant_id=context.tenant_id,
            scope="PROJECT",
            project_id=project_id,
            sbom_id=None,
            cadence=payload.cadence,
            created_on=to_iso(_now()),
            created_by=context.actor_label(),
        )
        db.add(existing)

    _apply_payload(existing, payload, partial=False)
    existing.modified_on = to_iso(_now())
    _refresh_next_run_at(existing)

    db.flush()
    _audit_schedule(db, context, "schedule.project.upsert", existing)
    db.commit()
    db.refresh(existing)
    return _serialize(existing)


@router.get("/projects/{project_id}/schedule", response_model=ScheduleOut)
def get_project_schedule(
    project_id: int = Path(..., ge=1),
    context: CurrentContext = Depends(require_permission("product:read")),
    db: Session = Depends(get_db),
):
    _get_project_or_404(db, project_id, context.tenant_id)
    row = db.execute(
        select(AnalysisSchedule).where(
            AnalysisSchedule.tenant_id == context.tenant_id,
            AnalysisSchedule.scope == "PROJECT",
            AnalysisSchedule.project_id == project_id,
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="No schedule configured for this project")
    return _serialize(row)


@router.patch("/projects/{project_id}/schedule", response_model=ScheduleOut)
def patch_project_schedule(
    payload: ScheduleUpsert,
    project_id: int = Path(..., ge=1),
    context: CurrentContext = Depends(require_permission("product:manage_schedule")),
    db: Session = Depends(get_db),
):
    _get_project_or_404(db, project_id, context.tenant_id)
    _validate_scope_options("PROJECT", payload)
    row = db.execute(
        select(AnalysisSchedule).where(
            AnalysisSchedule.tenant_id == context.tenant_id,
            AnalysisSchedule.scope == "PROJECT",
            AnalysisSchedule.project_id == project_id,
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="No schedule configured for this project")

    _apply_payload(row, payload, partial=True)
    _validate_or_422(_spec_from_row(row))
    row.modified_on = to_iso(_now())
    _refresh_next_run_at(row)

    _audit_schedule(db, context, "schedule.project.update", row)
    db.commit()
    db.refresh(row)
    return _serialize(row)


@router.delete("/projects/{project_id}/schedule", status_code=status.HTTP_200_OK)
def delete_project_schedule(
    project_id: int = Path(..., ge=1),
    permanent: bool = Query(
        False,
        description=(
            "If true, permanently remove the schedule row. If false "
            "(default), soft-delete: leave the row in place but mark "
            "it inactive."
        ),
    ),
    user_id: str | None = Query(None),
    context: CurrentContext = Depends(require_permission("product:manage_schedule")),
    db: Session = Depends(get_db),
):
    _get_project_or_404(db, project_id, context.tenant_id)
    row = db.execute(
        select(AnalysisSchedule).where(
            AnalysisSchedule.tenant_id == context.tenant_id,
            AnalysisSchedule.scope == "PROJECT",
            AnalysisSchedule.project_id == project_id,
        )
    ).scalar_one_or_none()
    if row is None:
        return {"status": "no_schedule"}

    schedule_id = row.id
    service = SoftDeleteService(db)
    _audit_schedule(
        db,
        context,
        "schedule.project.permanent_delete" if permanent else "schedule.project.delete",
        row,
    )
    if permanent:
        service.hard_delete(row)
    else:
        service.soft_delete(row, user_id=context.actor_label(), cascade=False)
    db.commit()
    return {"status": "deleted", "permanent": permanent, "id": schedule_id}


# ---------------------------------------------------------------------------
# Product-scope endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/products/{product_id}/schedule",
    response_model=ScheduleOut,
    status_code=status.HTTP_201_CREATED,
)
def upsert_product_schedule(
    payload: ScheduleUpsert,
    product_id: int = Path(..., ge=1),
    context: CurrentContext = Depends(require_permission("product:manage_schedule")),
    db: Session = Depends(get_db),
):
    _get_product_or_404(db, product_id, context.tenant_id)
    _validate_scope_options("PRODUCT", payload)
    _validate_or_422(_spec_from_payload(payload))
    existing = db.execute(
        select(AnalysisSchedule).where(
            AnalysisSchedule.tenant_id == context.tenant_id,
            AnalysisSchedule.scope == "PRODUCT",
            AnalysisSchedule.product_id == product_id,
        )
    ).scalar_one_or_none()
    if existing is None:
        existing = AnalysisSchedule(
            tenant_id=context.tenant_id,
            scope="PRODUCT",
            project_id=None,
            product_id=product_id,
            sbom_id=None,
            cadence=payload.cadence,
            created_on=to_iso(_now()),
            created_by=context.actor_label(),
        )
        db.add(existing)
    _apply_payload(existing, payload, partial=False)
    existing.modified_on = to_iso(_now())
    _refresh_next_run_at(existing)
    db.flush()
    _audit_schedule(db, context, "schedule.product.upsert", existing)
    db.commit()
    db.refresh(existing)
    return _serialize(existing)


@router.get("/products/{product_id}/schedule", response_model=ScheduleOut)
def get_product_schedule(
    product_id: int = Path(..., ge=1),
    context: CurrentContext = Depends(require_permission("product:read")),
    db: Session = Depends(get_db),
):
    _get_product_or_404(db, product_id, context.tenant_id)
    row = db.execute(
        select(AnalysisSchedule).where(
            AnalysisSchedule.tenant_id == context.tenant_id,
            AnalysisSchedule.scope == "PRODUCT",
            AnalysisSchedule.product_id == product_id,
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="No schedule configured for this product")
    return _serialize(row)


@router.get("/products/{product_id}/schedule/effective", response_model=ScheduleResolved)
def get_effective_product_schedule(
    product_id: int = Path(..., ge=1),
    context: CurrentContext = Depends(require_permission("product:read")),
    db: Session = Depends(get_db),
):
    _get_product_or_404(db, product_id, context.tenant_id)
    resolution = resolve_effective_schedule_for_product(db, product_id)
    if resolution is None or resolution.schedule is None:
        return {"inherited": False, "schedule": None, "state": "NONE", "resolution_reason": "NO_SCHEDULE"}
    return {
        "inherited": resolution.schedule.scope != "PRODUCT",
        "schedule": _serialize(resolution.schedule),
        "state": resolution.state,
        "source_scope": resolution.schedule.scope,
        "resolution_reason": resolution.reason,
        "included": resolution.included,
    }


@router.post("/products/{product_id}/schedule/exclude", response_model=ScheduleOut)
def exclude_product_from_parent_schedule(
    product_id: int = Path(..., ge=1),
    context: CurrentContext = Depends(require_permission("product:manage_schedule")),
    db: Session = Depends(get_db),
):
    _get_product_or_404(db, product_id, context.tenant_id)
    return _serialize(_set_excluded(db, context, scope="PRODUCT", product_id=product_id))


@router.post("/products/{product_id}/schedule/inherit")
def restore_product_schedule_inheritance(
    product_id: int = Path(..., ge=1),
    context: CurrentContext = Depends(require_permission("product:manage_schedule")),
    db: Session = Depends(get_db),
):
    _get_product_or_404(db, product_id, context.tenant_id)
    row = db.scalar(
        select(AnalysisSchedule).where(
            AnalysisSchedule.tenant_id == context.tenant_id,
            AnalysisSchedule.scope == "PRODUCT",
            AnalysisSchedule.product_id == product_id,
        )
    )
    return _restore_inheritance(db, context, row) if row else {"status": "already_inherited"}


@router.patch("/products/{product_id}/schedule", response_model=ScheduleOut)
def patch_product_schedule(
    payload: ScheduleUpsert,
    product_id: int = Path(..., ge=1),
    context: CurrentContext = Depends(require_permission("product:manage_schedule")),
    db: Session = Depends(get_db),
):
    _get_product_or_404(db, product_id, context.tenant_id)
    _validate_scope_options("PRODUCT", payload)
    row = db.execute(
        select(AnalysisSchedule).where(
            AnalysisSchedule.tenant_id == context.tenant_id,
            AnalysisSchedule.scope == "PRODUCT",
            AnalysisSchedule.product_id == product_id,
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="No schedule configured for this product")
    _apply_payload(row, payload, partial=True)
    _validate_or_422(_spec_from_row(row))
    row.modified_on = to_iso(_now())
    _refresh_next_run_at(row)
    _audit_schedule(db, context, "schedule.product.update", row)
    db.commit()
    db.refresh(row)
    return _serialize(row)


@router.delete("/products/{product_id}/schedule", status_code=status.HTTP_200_OK)
def delete_product_schedule(
    product_id: int = Path(..., ge=1),
    permanent: bool = Query(False),
    user_id: str | None = Query(None),
    context: CurrentContext = Depends(require_permission("product:manage_schedule")),
    db: Session = Depends(get_db),
):
    _get_product_or_404(db, product_id, context.tenant_id)
    row = db.execute(
        select(AnalysisSchedule).where(
            AnalysisSchedule.tenant_id == context.tenant_id,
            AnalysisSchedule.scope == "PRODUCT",
            AnalysisSchedule.product_id == product_id,
        )
    ).scalar_one_or_none()
    if row is None:
        return {"status": "no_schedule"}
    schedule_id = row.id
    service = SoftDeleteService(db)
    _audit_schedule(
        db,
        context,
        "schedule.product.permanent_delete" if permanent else "schedule.product.delete",
        row,
    )
    if permanent:
        service.hard_delete(row)
    else:
        service.soft_delete(row, user_id=context.actor_label(), cascade=False)
    db.commit()
    return {"status": "deleted", "permanent": permanent, "id": schedule_id}


# ---------------------------------------------------------------------------
# SBOM-scope endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/sboms/{sbom_id}/schedule",
    response_model=ScheduleOut,
    status_code=status.HTTP_201_CREATED,
)
def upsert_sbom_schedule(
    payload: ScheduleUpsert,
    sbom_id: int = Path(..., ge=1),
    context: CurrentContext = Depends(require_permission("product:manage_schedule")),
    db: Session = Depends(get_db),
):
    _get_sbom_or_404(db, sbom_id, context.tenant_id)
    _validate_scope_options("SBOM", payload)
    _validate_or_422(_spec_from_payload(payload))

    existing = db.execute(
        select(AnalysisSchedule).where(
            AnalysisSchedule.tenant_id == context.tenant_id,
            AnalysisSchedule.scope == "SBOM",
            AnalysisSchedule.sbom_id == sbom_id,
        )
    ).scalar_one_or_none()

    if existing is None:
        existing = AnalysisSchedule(
            tenant_id=context.tenant_id,
            scope="SBOM",
            project_id=None,
            sbom_id=sbom_id,
            cadence=payload.cadence,
            created_on=to_iso(_now()),
            created_by=context.actor_label(),
        )
        db.add(existing)

    _apply_payload(existing, payload, partial=False)
    existing.modified_on = to_iso(_now())
    _refresh_next_run_at(existing)

    db.flush()
    _audit_schedule(db, context, "schedule.sbom.upsert", existing)
    db.commit()
    db.refresh(existing)
    return _serialize(existing)


@router.get("/sboms/{sbom_id}/schedule", response_model=ScheduleResolved)
def get_sbom_schedule(
    sbom_id: int = Path(..., ge=1),
    context: CurrentContext = Depends(require_permission("product:read")),
    db: Session = Depends(get_db),
):
    """
    Return the effective schedule for an SBOM.

    UI uses ``inherited=true`` to render an "Inherits from project" badge
    and offer an "Override" button.
    """
    _get_sbom_or_404(db, sbom_id, context.tenant_id)
    resolution = resolve_effective_schedule(db, sbom_id)
    if resolution is None or resolution.schedule is None:
        return {
            "inherited": False,
            "schedule": None,
            "state": "NONE",
            "resolution_reason": "NO_SCHEDULE",
            "included": False,
        }
    row = resolution.schedule
    return {
        "inherited": row.scope != "SBOM",
        "schedule": _serialize(row),
        "state": resolution.state,
        "source_scope": row.scope,
        "resolution_reason": resolution.reason,
        "included": resolution.included,
    }


@router.post("/sboms/{sbom_id}/schedule/exclude", response_model=ScheduleOut)
def exclude_sbom_from_parent_schedule(
    sbom_id: int = Path(..., ge=1),
    context: CurrentContext = Depends(require_permission("product:manage_schedule")),
    db: Session = Depends(get_db),
):
    _get_sbom_or_404(db, sbom_id, context.tenant_id)
    return _serialize(_set_excluded(db, context, scope="SBOM", sbom_id=sbom_id))


@router.post("/sboms/{sbom_id}/schedule/inherit")
def restore_sbom_schedule_inheritance(
    sbom_id: int = Path(..., ge=1),
    context: CurrentContext = Depends(require_permission("product:manage_schedule")),
    db: Session = Depends(get_db),
):
    _get_sbom_or_404(db, sbom_id, context.tenant_id)
    row = db.scalar(
        select(AnalysisSchedule).where(
            AnalysisSchedule.tenant_id == context.tenant_id,
            AnalysisSchedule.scope == "SBOM",
            AnalysisSchedule.sbom_id == sbom_id,
        )
    )
    return _restore_inheritance(db, context, row) if row else {"status": "already_inherited"}


@router.patch("/sboms/{sbom_id}/schedule", response_model=ScheduleOut)
def patch_sbom_schedule(
    payload: ScheduleUpsert,
    sbom_id: int = Path(..., ge=1),
    context: CurrentContext = Depends(require_permission("product:manage_schedule")),
    db: Session = Depends(get_db),
):
    _get_sbom_or_404(db, sbom_id, context.tenant_id)
    _validate_scope_options("SBOM", payload)
    row = db.execute(
        select(AnalysisSchedule).where(
            AnalysisSchedule.tenant_id == context.tenant_id,
            AnalysisSchedule.scope == "SBOM",
            AnalysisSchedule.sbom_id == sbom_id,
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=404,
            detail=("No SBOM-level schedule. POST a new override or rely on the project-level cascade."),
        )

    _apply_payload(row, payload, partial=True)
    _validate_or_422(_spec_from_row(row))
    row.modified_on = to_iso(_now())
    _refresh_next_run_at(row)

    _audit_schedule(db, context, "schedule.sbom.update", row)
    db.commit()
    db.refresh(row)
    return _serialize(row)


@router.delete("/sboms/{sbom_id}/schedule", status_code=status.HTTP_200_OK)
def delete_sbom_schedule(
    sbom_id: int = Path(..., ge=1),
    permanent: bool = Query(False),
    user_id: str | None = Query(None),
    context: CurrentContext = Depends(require_permission("product:manage_schedule")),
    db: Session = Depends(get_db),
):
    _get_sbom_or_404(db, sbom_id, context.tenant_id)
    row = db.execute(
        select(AnalysisSchedule).where(
            AnalysisSchedule.tenant_id == context.tenant_id,
            AnalysisSchedule.scope == "SBOM",
            AnalysisSchedule.sbom_id == sbom_id,
        )
    ).scalar_one_or_none()
    if row is None:
        return {"status": "no_override"}

    schedule_id = row.id
    service = SoftDeleteService(db)
    _audit_schedule(
        db,
        context,
        "schedule.sbom.permanent_delete" if permanent else "schedule.sbom.delete",
        row,
    )
    if permanent:
        service.hard_delete(row)
    else:
        service.soft_delete(row, user_id=context.actor_label(), cascade=False)
    db.commit()
    return {"status": "deleted", "permanent": permanent, "id": schedule_id}


# ---------------------------------------------------------------------------
# Operator surface — flat list + per-row actions
# ---------------------------------------------------------------------------


@router.get("/schedules", response_model=list[ScheduleOut])
def list_schedules(
    scope: str | None = Query(None, description="PROJECT|PRODUCT|SBOM"),
    enabled: bool | None = Query(None),
    project_id: int | None = Query(None, ge=1),
    product_id: int | None = Query(None, ge=1),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    response: Response = None,
    context: CurrentContext = Depends(require_permission("product:read")),
    db: Session = Depends(get_db),
):
    base = select(AnalysisSchedule).where(AnalysisSchedule.tenant_id == context.tenant_id)
    if scope:
        norm = scope.strip().upper()
        if norm not in {"TENANT", "PROJECT", "PRODUCT", "SBOM"}:
            raise HTTPException(status_code=422, detail="scope must be TENANT, PROJECT, PRODUCT, or SBOM")
        base = base.where(AnalysisSchedule.scope == norm)
    if enabled is not None:
        base = base.where(AnalysisSchedule.enabled.is_(enabled))
    if project_id is not None:
        base = base.where(AnalysisSchedule.project_id == project_id)
    if product_id is not None:
        base = base.where(AnalysisSchedule.product_id == product_id)

    total_rows = db.execute(base).scalars().all()  # small table, count-by-fetch is fine
    if response is not None:
        response.headers["X-Total-Count"] = str(len(total_rows))

    offset = (page - 1) * page_size
    return [_serialize(r) for r in total_rows[offset : offset + page_size]]


def _get_schedule_or_404(db: Session, schedule_id: int, tenant_id: int | None = None) -> AnalysisSchedule:
    if tenant_id is None:
        row = db.get(AnalysisSchedule, schedule_id)
    else:
        row = db.execute(
            select(AnalysisSchedule).where(
                AnalysisSchedule.id == schedule_id,
                AnalysisSchedule.tenant_id == tenant_id,
            )
        ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return row


@router.get("/schedules/{schedule_id}/targets", response_model=ScheduleTargetPreview)
def preview_schedule_targets(
    schedule_id: int = Path(..., ge=1),
    context: CurrentContext = Depends(require_permission("product:read")),
    db: Session = Depends(get_db),
):
    from ..services.schedule_resolver import preview_targets_for_schedule

    row = _get_schedule_or_404(db, schedule_id, context.tenant_id)
    if row.scope == "TENANT":
        _tenant_schedule(db, row.tenant_id, context)
    targets = preview_targets_for_schedule(db, row)
    return {
        "schedule_id": row.id,
        "scope": row.scope,
        "target_count": sum(item.included for item in targets),
        "skipped_count": sum(not item.included for item in targets),
        "targets": [item.__dict__ for item in targets],
    }


@router.post("/schedules/{schedule_id}/pause", response_model=ScheduleOut)
def pause_schedule(
    schedule_id: int = Path(..., ge=1),
    context: CurrentContext = Depends(require_permission("product:manage_schedule")),
    db: Session = Depends(get_db),
):
    row = _get_schedule_or_404(db, schedule_id, context.tenant_id)
    if row.scope == "TENANT":
        _tenant_schedule(db, row.tenant_id, context)
    row.enabled = False
    row.next_run_at = None  # paused → no cursor
    row.modified_on = to_iso(_now())
    _audit_schedule(db, context, "schedule.pause", row)
    db.commit()
    db.refresh(row)
    return _serialize(row)


@router.post("/schedules/{schedule_id}/resume", response_model=ScheduleOut)
def resume_schedule(
    schedule_id: int = Path(..., ge=1),
    context: CurrentContext = Depends(require_permission("product:manage_schedule")),
    db: Session = Depends(get_db),
):
    row = _get_schedule_or_404(db, schedule_id, context.tenant_id)
    if row.scope == "TENANT":
        _tenant_schedule(db, row.tenant_id, context)
    if row.mode == "EXCLUDED":
        raise HTTPException(
            status_code=409,
            detail={"code": "schedule_excluded", "message": "Restore inheritance or create a custom schedule first."},
        )
    row.enabled = True
    _refresh_next_run_at(row)
    row.modified_on = to_iso(_now())
    _audit_schedule(db, context, "schedule.resume", row)
    db.commit()
    db.refresh(row)
    return _serialize(row)


@router.post("/schedules/{schedule_id}/run-now", status_code=status.HTTP_202_ACCEPTED)
def run_schedule_now(
    schedule_id: int = Path(..., ge=1),
    context: CurrentContext = Depends(require_permission("product:manage_schedule")),
    db: Session = Depends(get_db),
):
    """
    Trigger the schedule's analysis fan-out immediately.

    Does NOT modify ``next_run_at`` — the regular cadence is preserved.
    Returns the list of SBOM IDs that were enqueued.
    """
    from ..workers.scheduled_analysis import analyze_sbom_async

    row = _get_schedule_or_404(db, schedule_id, context.tenant_id)
    if row.scope == "TENANT":
        _tenant_schedule(db, row.tenant_id, context)

    from ..services.schedule_resolver import preview_targets_for_schedule
    preview = preview_targets_for_schedule(db, row)
    target_sbom_ids = [int(item.sbom_id) for item in preview if item.included and item.sbom_id is not None]

    from ..settings import get_settings
    report_cycle = None
    if get_settings().report_notifications_enabled:
        from ..services.report_cycles import prepare_run_cycle
        from ..services.schedule_resolver import DueTarget
        try:
            report_cycle = _now().isoformat()
            prepare_run_cycle(db, [DueTarget(sid, row.id, row.scope) for sid in target_sbom_ids], report_cycle)
        except Exception:
            db.rollback()
            report_cycle = None
            log.warning("schedule_manual_report_cycle_failed")

    enqueued: list[int] = []
    failed: list[int] = []
    last_error: str | None = None
    for sid in target_sbom_ids:
        try:
            analyze_sbom_async.delay(sbom_id=sid, schedule_id=row.id, **({"report_cycle": report_cycle} if report_cycle else {}))
            enqueued.append(sid)
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            log.exception(
                "schedule_run_now_enqueue_failed",
                extra={"schedule_id": row.id, "sbom_id": sid},
            )
            failed.append(sid)

    # If we have targets but none of them got onto the queue, the broker
    # is the most likely cause. Fail loudly with 502 — silently returning
    # 202 with an empty list misleads users into thinking the click worked.
    if target_sbom_ids and not enqueued:
        raise HTTPException(
            status_code=502,
            detail={
                "code": "broker_unavailable",
                "message": (
                    "Could not enqueue any analyses — the task broker is unreachable. "
                    "Check that Redis/Celery is running."
                ),
                "last_error": last_error,
                "schedule_id": row.id,
                "failed_sbom_ids": failed,
            },
        )

    _audit_schedule(db, context, "schedule.run_now", row)
    db.commit()
    return {
        "status": "enqueued" if not failed else "partial",
        "schedule_id": row.id,
        "scope": row.scope,
        "sbom_ids": enqueued,
        "failed_sbom_ids": failed,
        "target_count": len(enqueued),
        "skipped_count": sum(not item.included for item in preview),
    }
