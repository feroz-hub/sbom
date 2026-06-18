"""Validation repair workspace API."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import SBOMValidationSession
from ..schemas import SBOMSourceOut
from ..services.validation_repair_service import (
    ValidationRepairService,
    session_to_dict,
)
from ..services.sbom_enrichment_service import run_post_upload_enrichment

router = APIRouter(prefix="/api/sbom-validation-sessions", tags=["sbom-validation-sessions"])


class SessionUpdateRequest(BaseModel):
    current_content: str | None = None
    project_id: int | None = None


class AiSuggestRequest(BaseModel):
    user_instruction: str | None = None


class ApplyPatchRequest(BaseModel):
    patches: list[dict[str, Any]] = Field(default_factory=list)


@router.get("/{session_id}")
def get_validation_session(session_id: str, db: Session = Depends(get_db)):
    service = ValidationRepairService(db)
    return session_to_dict(service.get_session(session_id))


@router.patch("/{session_id}")
def update_validation_session(
    session_id: str,
    payload: SessionUpdateRequest,
    db: Session = Depends(get_db),
    x_user_id: str | None = Header(None, alias="X-User-Id"),
):
    service = ValidationRepairService(db)
    return session_to_dict(
        service.update_session(
            session_id,
            content=payload.current_content,
            project_id=payload.project_id,
            actor_user_id=x_user_id,
        )
    )


@router.post("/{session_id}/validate")
def validate_session(
    session_id: str,
    strict_ntia: bool = Query(False),
    verify_signature: bool = Query(False),
    db: Session = Depends(get_db),
    x_user_id: str | None = Header(None, alias="X-User-Id"),
):
    service = ValidationRepairService(db)
    return session_to_dict(
        service.validate_session(
            session_id,
            strict_ntia=strict_ntia,
            verify_signature=verify_signature,
            actor_user_id=x_user_id,
        )
    )


@router.post("/{session_id}/import", response_model=SBOMSourceOut)
def import_session(
    session_id: str,
    background_tasks: BackgroundTasks,
    strict_ntia: bool = Query(False),
    verify_signature: bool = Query(False),
    project_required: bool = Query(False),
    db: Session = Depends(get_db),
    x_user_id: str | None = Header(None, alias="X-User-Id"),
):
    session = db.get(SBOMValidationSession, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Validation session not found")
    if project_required and session.project_id is None:
        raise HTTPException(status_code=400, detail="Project assignment is required to import this SBOM")
    service = ValidationRepairService(db)
    sbom = service.import_session(
        session_id,
        strict_ntia=strict_ntia,
        verify_signature=verify_signature,
        actor_user_id=x_user_id,
    )
    background_tasks.add_task(run_post_upload_enrichment, sbom.id)
    return sbom


@router.post("/{session_id}/ai/suggest-fixes")
async def suggest_fixes(
    session_id: str,
    payload: AiSuggestRequest | None = None,
    db: Session = Depends(get_db),
    x_user_id: str | None = Header(None, alias="X-User-Id"),
):
    service = ValidationRepairService(db)
    return await service.suggest_fixes(
        session_id,
        user_instruction=payload.user_instruction if payload else None,
        actor_user_id=x_user_id,
    )


@router.post("/{session_id}/apply-patch")
def apply_patch(
    session_id: str,
    payload: ApplyPatchRequest,
    strict_ntia: bool = Query(False),
    verify_signature: bool = Query(False),
    db: Session = Depends(get_db),
    x_user_id: str | None = Header(None, alias="X-User-Id"),
):
    service = ValidationRepairService(db)
    return session_to_dict(
        service.apply_patch(
            session_id,
            payload.patches,
            strict_ntia=strict_ntia,
            verify_signature=verify_signature,
            actor_user_id=x_user_id,
        )
    )


@router.get("/{session_id}/history")
def session_history(session_id: str, db: Session = Depends(get_db)):
    service = ValidationRepairService(db)
    return service.history(session_id)
