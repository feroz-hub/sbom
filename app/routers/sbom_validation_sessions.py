"""Validation repair workspace API."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..core.context import CurrentContext
from ..core.security import get_current_tenant_context
from ..db import get_db
from ..models import SBOMValidationSession
from ..schemas import SBOMSourceOut
from ..services import audit_service
from ..services.sbom_enrichment_service import run_post_upload_enrichment
from ..services.validation_repair_service import (
    ValidationRepairService,
    session_to_dict,
)

router = APIRouter(prefix="/api/sbom-validation-sessions", tags=["sbom-validation-sessions"])
compat_router = APIRouter(prefix="/api/validation-sessions", tags=["validation-sessions"])
workspace_router = APIRouter(prefix="/api/sbom-workspaces", tags=["sbom-workspaces"])


class SessionUpdateRequest(BaseModel):
    current_content: str | None = None
    project_id: int | None = None


class RepairDraftRequest(BaseModel):
    content: str
    base_version: str | None = None


class AiSuggestRequest(BaseModel):
    user_instruction: str | None = None


class ApplyPatchRequest(BaseModel):
    patches: list[dict[str, Any]] = Field(default_factory=list)


class ApplyLinePatchRequest(BaseModel):
    patches: list[dict[str, Any]] = Field(default_factory=list)


@router.get("/{session_id}")
def get_validation_session(
    session_id: str,
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    service = ValidationRepairService(db, tenant_id=context.tenant_id)
    return session_to_dict(service.get_session(session_id))


@router.get("/{session_id}/content")
def get_validation_session_content(
    session_id: str,
    source: str = Query("repair_draft", pattern="^(original|repair_draft|repair)$"),
    offset: int = Query(0, ge=0),
    limit: int = Query(65536, ge=1, le=1048576),
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    service = ValidationRepairService(db, tenant_id=context.tenant_id)
    return service.content_chunk_for_source(session_id, source=source, offset=offset, limit=limit)


@router.get("/{session_id}/content/chunk")
def get_validation_session_content_chunk(
    session_id: str,
    source: str = Query("repair_draft", pattern="^(original|repair_draft|repair)$"),
    offset: int = Query(0, ge=0),
    limit: int = Query(65536, ge=1, le=1048576),
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    service = ValidationRepairService(db, tenant_id=context.tenant_id)
    return service.content_chunk_for_source(session_id, source=source, offset=offset, limit=limit)


@router.get("/{session_id}/content-lines")
def get_validation_session_content_lines(
    session_id: str,
    source: str = Query("repair_draft", pattern="^(original|repair_draft|repair)$"),
    start_line: int = Query(1, ge=1),
    line_count: int = Query(500, ge=1, le=5000),
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    service = ValidationRepairService(db, tenant_id=context.tenant_id)
    return service.content_lines_for_source(session_id, source=source, start_line=start_line, line_count=line_count)


@router.get("/{session_id}/content/lines")
def get_validation_session_content_lines_alias(
    session_id: str,
    source: str = Query("repair_draft", pattern="^(original|repair_draft|repair)$"),
    start_line: int = Query(1, ge=1),
    line_count: int = Query(500, ge=1, le=5000),
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    service = ValidationRepairService(db, tenant_id=context.tenant_id)
    return service.content_lines_for_source(session_id, source=source, start_line=start_line, line_count=line_count)


@router.get("/{session_id}/download-original")
def download_original_validation_session(
    session_id: str,
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    service = ValidationRepairService(db, tenant_id=context.tenant_id)
    iterator, media_type, filename, size = service.original_download_stream(session_id, actor_user_id=context.actor_label())
    audit_service.write_audit_log(
        db,
        context,
        "sbom.validation_session.download_original",
        entity_type="sbom_validation_session",
        entity_id=session_id,
        new_value={"file_size_bytes": size},
    )
    db.commit()
    safe_filename = filename.replace('"', "").replace("\r", "").replace("\n", "")
    return StreamingResponse(
        iterator,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{safe_filename}"'},
    )


@router.get("/{session_id}/download-repair-draft")
def download_repair_draft_validation_session(
    session_id: str,
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    service = ValidationRepairService(db, tenant_id=context.tenant_id)
    iterator, media_type, filename, size = service.repair_download_stream(session_id, actor_user_id=context.actor_label())
    audit_service.write_audit_log(
        db,
        context,
        "sbom.validation_session.download_repair_draft",
        entity_type="sbom_validation_session",
        entity_id=session_id,
        new_value={"file_size_bytes": size},
    )
    db.commit()
    safe_filename = filename.replace('"', "").replace("\r", "").replace("\n", "")
    return StreamingResponse(
        iterator,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{safe_filename}"'},
    )


@router.get("/{session_id}/search")
def search_validation_session(
    session_id: str,
    q: str = Query(..., min_length=1, max_length=256),
    source: str = Query("repair_draft", pattern="^(original|repair_draft|repair)$"),
    limit: int = Query(100, ge=1, le=1000),
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    service = ValidationRepairService(db, tenant_id=context.tenant_id)
    return service.search(session_id, query=q, source=source, limit=limit)


@router.patch("/{session_id}")
def update_validation_session(
    session_id: str,
    payload: SessionUpdateRequest,
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
    x_user_id: str | None = Header(None, alias="X-User-Id"),
):
    service = ValidationRepairService(db, tenant_id=context.tenant_id)
    return session_to_dict(
        service.update_session(
            session_id,
            content=payload.current_content,
            project_id=payload.project_id,
            actor_user_id=x_user_id or context.actor_label(),
        )
    )


@router.put("/{session_id}/repair-draft")
def save_repair_draft(
    session_id: str,
    payload: RepairDraftRequest,
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
    x_user_id: str | None = Header(None, alias="X-User-Id"),
):
    service = ValidationRepairService(db, tenant_id=context.tenant_id)
    session = service.get_session(session_id)
    if payload.base_version and session.updated_at != payload.base_version:
        raise HTTPException(status_code=409, detail="Repair draft was modified by another request")
    updated = service.update_session(
        session_id,
        content=payload.content,
        actor_user_id=x_user_id or context.actor_label(),
    )
    audit_service.write_audit_log(
        db,
        context,
        "sbom.validation_session.repair_draft_saved",
        entity_type="sbom_validation_session",
        entity_id=session_id,
        new_value={
            "stored_size_bytes": updated.stored_size_bytes,
            "stored_sha256": updated.stored_sha256,
            "total_lines": updated.total_lines,
        },
    )
    db.commit()
    return session_to_dict(updated)


@router.post("/{session_id}/validate")
def validate_session(
    session_id: str,
    strict_ntia: bool = Query(False),
    verify_signature: bool = Query(False),
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
    x_user_id: str | None = Header(None, alias="X-User-Id"),
):
    service = ValidationRepairService(db, tenant_id=context.tenant_id)
    updated = service.validate_session(
        session_id,
        strict_ntia=strict_ntia,
        verify_signature=verify_signature,
        actor_user_id=x_user_id or context.actor_label(),
    )
    audit_service.write_audit_log(
        db,
        context,
        "sbom.validation_session.revalidated",
        entity_type="sbom_validation_session",
        entity_id=session_id,
        new_value={
            "validation_status": updated.validation_status,
            "error_count": (updated.latest_error_report_json or {}).get("error_count"),
            "warning_count": (updated.latest_error_report_json or {}).get("warning_count"),
        },
    )
    db.commit()
    return session_to_dict(updated)


@router.post("/{session_id}/revalidate")
def revalidate_session(
    session_id: str,
    strict_ntia: bool = Query(False),
    verify_signature: bool = Query(False),
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
    x_user_id: str | None = Header(None, alias="X-User-Id"),
):
    service = ValidationRepairService(db, tenant_id=context.tenant_id)
    updated = service.validate_session(
        session_id,
        strict_ntia=strict_ntia,
        verify_signature=verify_signature,
        actor_user_id=x_user_id or context.actor_label(),
    )
    audit_service.write_audit_log(
        db,
        context,
        "sbom.validation_session.revalidated",
        entity_type="sbom_validation_session",
        entity_id=session_id,
        new_value={
            "validation_status": updated.validation_status,
            "error_count": (updated.latest_error_report_json or {}).get("error_count"),
            "warning_count": (updated.latest_error_report_json or {}).get("warning_count"),
        },
    )
    db.commit()
    return session_to_dict(updated)


@router.post("/{session_id}/import", response_model=SBOMSourceOut)
def import_session(
    session_id: str,
    background_tasks: BackgroundTasks,
    strict_ntia: bool = Query(False),
    verify_signature: bool = Query(False),
    project_required: bool = Query(False),
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
    x_user_id: str | None = Header(None, alias="X-User-Id"),
):
    session = (
        db.query(SBOMValidationSession)
        .filter(SBOMValidationSession.id == session_id, SBOMValidationSession.tenant_id == context.tenant_id)
        .first()
    )
    if not session:
        raise HTTPException(status_code=404, detail="Validation session not found")
    if project_required and session.project_id is None:
        raise HTTPException(status_code=400, detail="Project assignment is required to import this SBOM")
    service = ValidationRepairService(db, tenant_id=context.tenant_id)
    sbom = service.import_session(
        session_id,
        strict_ntia=strict_ntia,
        verify_signature=verify_signature,
        actor_user_id=x_user_id or context.actor_label(),
    )
    audit_service.write_audit_log(
        db,
        context,
        "sbom.validation_session.imported",
        entity_type="sbom_validation_session",
        entity_id=session_id,
        new_value={"imported_sbom_id": sbom.id, "project_id": sbom.projectid},
    )
    db.commit()
    background_tasks.add_task(run_post_upload_enrichment, sbom.id, context.tenant_id)
    return sbom


@router.post("/{session_id}/ai/suggest-fixes")
async def suggest_fixes(
    session_id: str,
    payload: AiSuggestRequest | None = None,
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
    x_user_id: str | None = Header(None, alias="X-User-Id"),
):
    service = ValidationRepairService(db, tenant_id=context.tenant_id)
    return await service.suggest_fixes(
        session_id,
        user_instruction=payload.user_instruction if payload else None,
        actor_user_id=x_user_id or context.actor_label(),
    )


@router.post("/{session_id}/apply-patch")
def apply_patch(
    session_id: str,
    payload: ApplyPatchRequest,
    strict_ntia: bool = Query(False),
    verify_signature: bool = Query(False),
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
    x_user_id: str | None = Header(None, alias="X-User-Id"),
):
    service = ValidationRepairService(db, tenant_id=context.tenant_id)
    return session_to_dict(
        service.apply_patch(
            session_id,
            payload.patches,
            strict_ntia=strict_ntia,
            verify_signature=verify_signature,
            actor_user_id=x_user_id or context.actor_label(),
        )
    )


@router.post("/{session_id}/repair/patches")
def apply_line_patches(
    session_id: str,
    payload: ApplyLinePatchRequest,
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
    x_user_id: str | None = Header(None, alias="X-User-Id"),
):
    service = ValidationRepairService(db, tenant_id=context.tenant_id)
    updated = service.apply_line_patches(
        session_id,
        payload.patches,
        actor_user_id=x_user_id or context.actor_label(),
    )
    audit_service.write_audit_log(
        db,
        context,
        "sbom.validation_session.patch_created",
        entity_type="sbom_validation_session",
        entity_id=session_id,
        new_value={"patch_count": len(payload.patches), "stored_sha256": updated.stored_sha256},
    )
    db.commit()
    return session_to_dict(updated)


@router.get("/{session_id}/history")
def session_history(
    session_id: str,
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    service = ValidationRepairService(db, tenant_id=context.tenant_id)
    return service.history(session_id)


compat_router.add_api_route("/{session_id}", get_validation_session, methods=["GET"])
compat_router.add_api_route("/{session_id}/content", get_validation_session_content, methods=["GET"])
compat_router.add_api_route("/{session_id}/content/chunk", get_validation_session_content_chunk, methods=["GET"])
compat_router.add_api_route("/{session_id}/content-lines", get_validation_session_content_lines, methods=["GET"])
compat_router.add_api_route("/{session_id}/content/lines", get_validation_session_content_lines_alias, methods=["GET"])
compat_router.add_api_route("/{session_id}/download-original", download_original_validation_session, methods=["GET"])
compat_router.add_api_route("/{session_id}/download-repair-draft", download_repair_draft_validation_session, methods=["GET"])
compat_router.add_api_route("/{session_id}/search", search_validation_session, methods=["GET"])
compat_router.add_api_route("/{session_id}", update_validation_session, methods=["PATCH"])
compat_router.add_api_route("/{session_id}/repair-draft", save_repair_draft, methods=["PUT"])
compat_router.add_api_route("/{session_id}/validate", validate_session, methods=["POST"])
compat_router.add_api_route("/{session_id}/revalidate", revalidate_session, methods=["POST"])
compat_router.add_api_route("/{session_id}/import", import_session, methods=["POST"], response_model=SBOMSourceOut)
compat_router.add_api_route("/{session_id}/ai/suggest-fixes", suggest_fixes, methods=["POST"])
compat_router.add_api_route("/{session_id}/apply-patch", apply_patch, methods=["POST"])
compat_router.add_api_route("/{session_id}/repair/patches", apply_line_patches, methods=["POST"])
compat_router.add_api_route("/{session_id}/history", session_history, methods=["GET"])

workspace_router.add_api_route("/{session_id}", get_validation_session, methods=["GET"])
workspace_router.add_api_route("/{session_id}/content", get_validation_session_content, methods=["GET"])
workspace_router.add_api_route("/{session_id}/content/chunk", get_validation_session_content_chunk, methods=["GET"])
workspace_router.add_api_route("/{session_id}/content-lines", get_validation_session_content_lines, methods=["GET"])
workspace_router.add_api_route("/{session_id}/content/lines", get_validation_session_content_lines_alias, methods=["GET"])
workspace_router.add_api_route("/{session_id}/download-original", download_original_validation_session, methods=["GET"])
workspace_router.add_api_route("/{session_id}/download-repair-draft", download_repair_draft_validation_session, methods=["GET"])
workspace_router.add_api_route("/{session_id}/search", search_validation_session, methods=["GET"])
workspace_router.add_api_route("/{session_id}", update_validation_session, methods=["PATCH"])
workspace_router.add_api_route("/{session_id}/repair-draft", save_repair_draft, methods=["PUT"])
workspace_router.add_api_route("/{session_id}/validate", validate_session, methods=["POST"])
workspace_router.add_api_route("/{session_id}/revalidate", revalidate_session, methods=["POST"])
workspace_router.add_api_route("/{session_id}/import", import_session, methods=["POST"], response_model=SBOMSourceOut)
workspace_router.add_api_route("/{session_id}/ai/suggest-fixes", suggest_fixes, methods=["POST"])
workspace_router.add_api_route("/{session_id}/apply-patch", apply_patch, methods=["POST"])
workspace_router.add_api_route("/{session_id}/repair/patches", apply_line_patches, methods=["POST"])
workspace_router.add_api_route("/{session_id}/history", session_history, methods=["GET"])
