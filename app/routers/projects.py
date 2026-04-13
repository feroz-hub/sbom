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
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import AnalysisRun, Projects, SBOMSource
from ..schemas import ProjectCreate, ProjectOut, ProjectUpdate

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
def create_project(payload: ProjectCreate, db: Session = Depends(get_db)):
    try:
        existing_project = db.query(Projects).filter(Projects.project_name == payload.project_name).first()

        if existing_project:
            raise HTTPException(status_code=400, detail="Project with this name already exists")

        obj = Projects(**payload.model_dump(), created_on=now_iso())
        db.add(obj)
        db.commit()
        db.refresh(obj)

        return obj

    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Duplicate project name not allowed")

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Something went wrong: {str(e)}")


@router.get("/projects/{project_id}", response_model=ProjectOut)
def get_project_details(
    project_id: int = Path(..., description="Project ID (positive integer)"), db: Session = Depends(get_db)
):
    project_id = _validate_positive_int(project_id)
    try:
        project = db.get(Projects, project_id)
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
    user_id: str | None = Query(
        None, description="Optional: if provided, must match Projects.created_by (letters/digits/_/./-, 1–64)"
    ),
    db: Session = Depends(get_db),
):
    project_id = _validate_positive_int(project_id, "project_id")
    user_id = _validate_user_id(user_id)
    data = payload.model_dump(exclude_unset=True, exclude_none=True)
    if not data:
        raise HTTPException(status_code=422, detail="No updatable fields provided in payload.")

    try:
        project = db.get(Projects, project_id)
        if not project:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

        if user_id is not None:
            if (project.created_by or "").strip().lower() != user_id.lower():
                raise HTTPException(status_code=403, detail="Forbidden: user cannot update this Project")

        for k, v in data.items():
            setattr(project, k, v)

        project.modified_on = now_iso()
        project.modified_by = data.get("modified_by") or user_id or project.modified_by

        db.add(project)
        db.commit()
        db.refresh(project)
        return project
    except HTTPException:
        raise
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="Internal database error while updating project.") from exc


@router.delete("/projects/{project_id}", status_code=status.HTTP_200_OK)
def delete_project(
    project_id: int,
    user_id: str | None = Query(None, description="Optional: if provided, must match Projects.created_by"),
    confirm: str = Query("no", description="Set to 'yes' to confirm deletion"),
    db: Session = Depends(get_db),
):
    project = db.get(Projects, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if user_id is not None:
        if (project.created_by or "").strip().lower() != (user_id or "").strip().lower():
            raise HTTPException(status_code=403, detail="Forbidden: user cannot delete this Project")

    has_sboms = db.execute(
        select(SBOMSource.id).where(SBOMSource.projectid == project_id).limit(1)
    ).scalar_one_or_none()
    has_runs = db.execute(
        select(AnalysisRun.id).where(AnalysisRun.project_id == project_id).limit(1)
    ).scalar_one_or_none()
    if has_sboms or has_runs:
        raise HTTPException(
            status_code=409, detail="Cannot delete Project: SBOMs or Analysis Runs exist. Delete/reassign them first."
        )

    if (confirm or "").strip().lower() not in {"yes", "y"}:
        return {
            "status": "pending_confirmation",
            "message": "This will permanently delete the Project. Re-send with confirm=yes to proceed.",
            "example": f"/api/projects/{project_id}?confirm=yes",
        }

    db.delete(project)
    db.commit()
    return {"status": "deleted", "message": f"Project {project_id} deleted successfully."}
