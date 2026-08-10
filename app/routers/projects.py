"""
Projects CRUD router.

Routes:
  POST /api/projects                    create project
  GET /api/projects/{project_id}        get project with SBOM count and latest analysis
  GET /api/projects                     list all projects
  PATCH /api/projects/{project_id}      update project
  DELETE /api/projects/{project_id}     delete project with cascade
"""

import logging
import re
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from ..core.context import CurrentContext
from ..core.security import get_current_tenant_context
from ..db import get_db
from ..models import (
    AnalysisFinding,
    AnalysisRun,
    AnalysisSchedule,
    Projects,
    SBOMAnalysisReport,
    SBOMComponent,
    SBOMSource,
)
from ..schemas import ProjectCreate, ProjectOut, ProjectUpdate
from ..services import audit_log
from ..services.soft_delete import SoftDeleteService
from ..services.tenant_access import get_project_for_tenant

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["projects"])


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


_USER_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def _validate_user_id(raw: str | None) -> str | None:
    if raw is None:
        return None
    user_id = raw.strip()
    if not user_id:
        raise HTTPException(status_code=422, detail="Query parameter 'user_id' must not be empty or whitespace.")
    if not _USER_ID_PATTERN.fullmatch(user_id):
        raise HTTPException(
            status_code=422,
            detail=("Invalid 'user_id'. Allowed: letters, digits, '_', '-', '.'; length 1–64 characters."),
        )
    return user_id


def _validate_positive_int(value: int, param_name: str = "id") -> int:
    if not isinstance(value, int):
        raise HTTPException(status_code=422, detail=f"'{param_name}' must be an integer.")
    if value < 1:
        raise HTTPException(status_code=422, detail=f"'{param_name}' must be a positive integer (>= 1).")
    return value


@router.post("/projects", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project(
    payload: ProjectCreate,
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    try:
        existing_project = db.query(Projects).filter(Projects.project_name == payload.project_name).first()

        if existing_project:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "PROJECT_ALREADY_EXISTS", "message": "A project with this name already exists."},
            )

        data = payload.model_dump()
        data["created_by"] = data.get("created_by") or context.actor_label()
        obj = Projects(**data, created_on=now_iso())
        db.add(obj)
        db.commit()
        db.refresh(obj)

        return obj

    except HTTPException:
        db.rollback()
        raise
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "PROJECT_ALREADY_EXISTS", "message": "A project with this name already exists."},
        )

    except Exception:
        db.rollback()
        log.exception("create_project failed: project_name=%s", payload.project_name)
        raise HTTPException(
            status_code=500,
            detail={"code": "internal_error", "message": "Internal server error."},
        )


@router.get("/projects/{project_id}", response_model=ProjectOut)
def get_project_details(
    project_id: int = Path(..., description="Project ID (positive integer)"),
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    project_id = _validate_positive_int(project_id)
    try:
        project = get_project_for_tenant(db, project_id, context.tenant_id)
        if not project:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
        return project
    except HTTPException:
        raise
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="Internal database error while fetching project details.") from exc


@router.get("/projects", response_model=list[ProjectOut])
def list_projects(db: Session = Depends(get_db)):
    return db.execute(select(Projects).order_by(Projects.id.desc())).scalars().all()


@router.patch("/projects/{project_id}", response_model=ProjectOut)
def update_project(
    project_id: int = Path(..., description="Project ID (positive integer)"),
    payload: ProjectUpdate = ...,
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    project_id = _validate_positive_int(project_id, "project_id")
    data = payload.model_dump(exclude_unset=True, exclude_none=True)
    if not data:
        raise HTTPException(status_code=422, detail="No updatable fields provided in payload.")

    try:
        project = get_project_for_tenant(db, project_id, context.tenant_id)
        if not project:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

        for k, v in data.items():
            setattr(project, k, v)

        project.modified_on = now_iso()
        project.modified_by = data.get("modified_by") or context.actor_label()

        db.add(project)
        db.commit()
        db.refresh(project)
        return project
    except HTTPException:
        raise
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="Internal database error while updating project.") from exc


@router.get("/projects/{project_id}/delete-impact", status_code=status.HTTP_200_OK)
def project_delete_impact(
    project_id: int = Path(..., ge=1),
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    """Pre-flight cascade preview for the delete confirmation modal.

    Phase 4 §4.2: returns the count of dependent rows that a soft-delete
    on this project would tombstone. Counts respect Option C — only
    currently-active rows are counted, so a re-run after a partial
    cascade reflects what's still left to remove.
    """
    project = get_project_for_tenant(db, project_id, context.tenant_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    from sqlalchemy import func

    sbom_ids = db.execute(select(SBOMSource.id).where(SBOMSource.projectid == project_id)).scalars().all()
    run_ids = db.execute(select(AnalysisRun.id).where(AnalysisRun.project_id == project_id)).scalars().all()
    components = (
        db.execute(
            select(func.count(SBOMComponent.id)).where(SBOMComponent.sbom_id.in_(sbom_ids) if sbom_ids else False)
        ).scalar()
        if sbom_ids
        else 0
    )
    findings = (
        db.execute(
            select(func.count(AnalysisFinding.id)).where(
                AnalysisFinding.analysis_run_id.in_(run_ids) if run_ids else False
            )
        ).scalar()
        if run_ids
        else 0
    )
    schedules = db.execute(
        select(func.count(AnalysisSchedule.id)).where(AnalysisSchedule.project_id == project_id)
    ).scalar()

    return {
        "project_id": project_id,
        "project_name": project.project_name,
        "sboms": len(sbom_ids),
        "components": int(components or 0),
        "runs": len(run_ids),
        "findings": int(findings or 0),
        "schedules": int(schedules or 0),
    }


@router.delete("/projects/{project_id}", status_code=status.HTTP_200_OK)
def delete_project(
    project_id: int,
    confirm: str = Query("no", description="Set to 'yes' to confirm deletion"),
    permanent: bool = Query(
        False,
        description=(
            "If true, permanently remove the project and every dependent row "
            "(SBOMs, components, runs, findings, schedules, AI fix batches). "
            "If false (default), soft-delete: mark the project and its "
            "ownership tree as inactive, leaving rows in place for recovery."
        ),
    ),
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    project = get_project_for_tenant(db, project_id, context.tenant_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    user_id = context.actor_label()

    if (confirm or "").strip().lower() not in {"yes", "y"}:
        return {
            "status": "pending_confirmation",
            "message": (
                "This will delete the Project. Re-send with confirm=yes "
                "to proceed (and add permanent=true to bypass soft delete)."
            ),
            "example": f"/api/projects/{project_id}?confirm=yes",
        }

    service = SoftDeleteService(db)

    if permanent:
        # Hard delete with explicit cascade. Existing FKs do NOT carry
        # ON DELETE CASCADE for SBOM children (only schedules and AI
        # fix batches do), so we walk the tree manually. Mirrors the
        # SBOM hard-delete pattern in sboms_crud.py.
        try:
            tenant_id = project.tenant_id
            sbom_ids = (
                db.execute(
                    select(SBOMSource.id)
                    .where(SBOMSource.projectid == project_id)
                    .execution_options(include_deleted=True)
                )
                .scalars()
                .all()
            )
            run_ids = (
                db.execute(
                    select(AnalysisRun.id)
                    .where(AnalysisRun.project_id == project_id)
                    .execution_options(include_deleted=True)
                )
                .scalars()
                .all()
            )
            if run_ids:
                db.execute(
                    delete(AnalysisFinding)
                    .where(
                        AnalysisFinding.analysis_run_id.in_(run_ids),
                        AnalysisFinding.tenant_id == tenant_id,
                    )
                    .execution_options(synchronize_session=False)
                )
                db.execute(
                    delete(AnalysisRun)
                    .where(AnalysisRun.id.in_(run_ids), AnalysisRun.tenant_id == tenant_id)
                    .execution_options(synchronize_session=False)
                )
            if sbom_ids:
                db.execute(
                    delete(SBOMComponent)
                    .where(SBOMComponent.sbom_id.in_(sbom_ids), SBOMComponent.tenant_id == tenant_id)
                    .execution_options(synchronize_session=False)
                )
                db.execute(
                    delete(SBOMAnalysisReport)
                    .where(
                        SBOMAnalysisReport.sbom_ref_id.in_(sbom_ids),
                        SBOMAnalysisReport.tenant_id == tenant_id,
                    )
                    .execution_options(synchronize_session=False)
                )
                db.execute(
                    delete(SBOMSource)
                    .where(SBOMSource.id.in_(sbom_ids), SBOMSource.tenant_id == tenant_id)
                    .execution_options(synchronize_session=False)
                )
            db.flush()
            service.hard_delete(project)
            db.commit()
        except Exception:
            db.rollback()
            log.exception("permanent delete_project failed: project_id=%s", project_id)
            raise HTTPException(status_code=500, detail="Internal database error during permanent delete.")

        audit_log.record(
            db,
            user_id=user_id,
            action="project.permanent_delete",
            target_kind="project",
            target_id=project_id,
            detail=f"sboms={len(sbom_ids)} runs={len(run_ids)}",
            metadata={"sbom_ids": list(sbom_ids), "run_ids": list(run_ids)},
        )
        return {
            "status": "deleted",
            "permanent": True,
            "message": f"Project {project_id} permanently deleted.",
        }

    # Soft delete with cascade through the ownership tree.
    try:
        cascaded_count = service.soft_delete(project, user_id=user_id, cascade=True)
        db.commit()
    except Exception:
        db.rollback()
        log.exception("soft delete_project failed: project_id=%s", project_id)
        raise HTTPException(status_code=500, detail="Internal database error during soft delete.")

    audit_log.record(
        db,
        user_id=user_id,
        action="project.soft_delete",
        target_kind="project",
        target_id=project_id,
        detail=f"cascaded={cascaded_count}",
        metadata={"cascaded_count": cascaded_count},
    )
    return {
        "status": "deleted",
        "permanent": False,
        "cascaded_count": cascaded_count,
        "message": f"Project {project_id} moved to deleted (recoverable).",
    }


@router.post("/projects/{project_id}/restore", status_code=status.HTTP_200_OK)
def restore_project(
    project_id: int = Path(..., ge=1),
    user_id: str | None = Query(None),
    db: Session = Depends(get_db),
):
    """Restore a soft-deleted project. Does not cascade — children must
    be restored individually if also tombstoned. (Phase 3.4: admin
    recovery surface; UI affordance ships in a follow-up PR.)"""
    project = db.execute(
        select(Projects).where(Projects.id == project_id).execution_options(include_deleted=True)
    ).scalar_one_or_none()
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    if project.is_active:
        return {"status": "already_active", "id": project_id}

    SoftDeleteService(db).restore(project)
    db.commit()
    audit_log.record(
        db,
        user_id=user_id,
        action="project.restore",
        target_kind="project",
        target_id=project_id,
    )
    return {"status": "restored", "id": project_id}
