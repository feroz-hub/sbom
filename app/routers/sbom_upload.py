"""POST /api/sboms/upload — multipart endpoint that runs the eight-stage
validation pipeline.

This route is the **canonical** ingress shape from ADR-0007. It accepts a
multipart upload, runs :func:`app.validation.run`, and either:

* responds 202 with the new ``SBOMSource`` row id and the report's warnings
  / info entries (so the frontend can surface NTIA hints), or
* responds 400 / 413 / 415 / 422 with the structured ``ErrorReport`` and,
  when safe, a validation repair session id.

Rejected SBOMs are never inserted into ``SBOMSource``. They may be staged
only in ``sbom_validation_sessions`` for repair and later import after the
same validation pipeline passes.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Query, UploadFile, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..core.context import CurrentContext
from ..core.security import get_current_tenant_context
from ..db import get_db
from ..models import SBOMSource, SBOMType
from ..services import audit_service
from ..services.sbom_document_service import byte_size, count_lines, parsed_component_count
from ..services.sbom_enrichment_service import mark_enrichment_pending, run_post_upload_enrichment
from ..services.sbom_service import sync_sbom_components
from ..services.tenant_access import get_project_for_tenant
from ..services.validation_repair_service import (
    ValidationRepairService,
    build_validation_failed_detail,
)
from ..settings import get_settings
from ..validation import run as run_validation

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/sboms", tags=["sboms"])


class SbomAcceptedResponse(BaseModel):
    """Response body for a successful upload."""

    status: str = "valid"
    workspace_id: str
    validation_session_id: str
    repair_workspace_url: str
    sbom_id: int
    sbom_name: str
    project_id: int | None = None
    project_name: str | None = None
    spec: str
    spec_version: str
    detected_format: str | None = None
    detected_spec_version: str | None = None
    detection_confidence: float | None = None
    detection_evidence: dict | list | None = None
    file_size_bytes: int
    total_lines: int
    sha256: str
    is_large_file: bool
    full_editor_allowed: bool
    components: int
    validation_errors: list[dict] = []
    validation_warnings: list[dict] = []
    warnings: list[dict]
    info: list[dict]
    enrichment_status: str = "pending"
    message: str = "SBOM uploaded successfully. Enrichment is running in background."


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


@router.post(
    "/upload",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=SbomAcceptedResponse,
)
async def upload_sbom(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="SBOM document (SPDX or CycloneDX)"),
    sbom_name: str = Form(..., min_length=1, max_length=255),
    project_id: int | None = Form(None),
    sbom_type: int | None = Form(None),
    context: CurrentContext = Depends(get_current_tenant_context),
    strict_ntia: bool = Query(False, description="Promote NTIA warnings to hard errors."),
    db: Session = Depends(get_db),
) -> SbomAcceptedResponse:
    """Validate, normalise, and persist an SBOM uploaded as multipart/form-data.

    Validation runs **before** any DB write — a rejected SBOM never gets a
    row in :class:`SBOMSource`. Stage 1's size cap is checked again here in
    case the upstream :class:`MaxBodySizeMiddleware` was bypassed (e.g. a
    direct connection to the worker).
    """
    settings = get_settings()
    max_bytes = int(getattr(settings, "MAX_UPLOAD_BYTES", 50 * 1024 * 1024))

    created_by = context.actor_label()

    if project_id is not None and get_project_for_tenant(db, project_id, context.tenant_id) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    if sbom_type is not None and db.get(SBOMType, sbom_type) is None:
        raise HTTPException(status_code=404, detail="SBOM type not found")

    raw = await file.read()
    if len(raw) > max_bytes:
        # The middleware should have caught this; if not, return the same
        # structured 413 the validator would have produced.
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={
                "entries": [
                    {
                        "code": "SBOM_VAL_E001_SIZE_EXCEEDED",
                        "severity": "error",
                        "stage": "ingress",
                        "path": "",
                        "message": (f"Uploaded body of {len(raw)} bytes exceeds MAX_UPLOAD_BYTES ({max_bytes})."),
                        "remediation": (
                            "Compress the SBOM, split into multi-part, or contact your operator to raise the limit."
                        ),
                        "spec_reference": None,
                    }
                ],
                "truncated": False,
            },
        )

    content_encoding = file.headers.get("content-encoding") if file.headers else None
    report = run_validation(
        raw,
        content_encoding=content_encoding,
        strict_ntia=strict_ntia,
        verify_signature=bool(getattr(settings, "SBOM_SIGNATURE_VERIFICATION", False)),
    )

    body_text_original = raw.decode("utf-8", errors="replace")
    body_text = body_text_original
    if body_text.startswith("﻿"):
        body_text = body_text.lstrip("﻿")

    if report.has_errors():
        service = ValidationRepairService(db)
        session, blocked_reason = service.create_failed_upload_session(
            raw_text=body_text_original,
            raw_bytes=raw,
            content_type=file.content_type,
            report=report,
            sbom_name=sbom_name,
            original_filename=file.filename,
            project_id=project_id,
            sbom_type=sbom_type,
            user_id=created_by,
        )
        if session is not None:
            audit_service.write_audit_log(
                db,
                context,
                "sbom.validation_session.created",
                entity_type="sbom_validation_session",
                entity_id=session.id,
                new_value={
                    "sbom_name": sbom_name,
                    "project_id": project_id,
                    "file_size_bytes": session.file_size_bytes,
                    "sha256": session.sha256,
                    "error_count": report.error_count,
                },
            )
            db.commit()
        raise HTTPException(
            status_code=report.http_status,
            detail=build_validation_failed_detail(
                report=report,
                sbom_name=sbom_name,
                session=session,
                blocked_reason=blocked_reason,
            ),
        )

    service = ValidationRepairService(db)
    validation_status = "valid_with_warnings" if report.warning_count else "valid"
    session, blocked_reason = service.create_upload_session(
        raw_text=body_text_original,
        raw_bytes=raw,
        content_type=file.content_type,
        report=report,
        sbom_name=sbom_name,
        original_filename=file.filename,
        project_id=project_id,
        sbom_type=sbom_type,
        user_id=created_by,
        validation_status=validation_status,
    )
    if session is None:
        raise HTTPException(status_code=422, detail={"code": "workspace_blocked", "message": blocked_reason})
    audit_service.write_audit_log(
        db,
        context,
        "sbom.validation_session.created",
        entity_type="sbom_validation_session",
        entity_id=session.id,
        new_value={
            "sbom_name": sbom_name,
            "project_id": project_id,
            "file_size_bytes": session.file_size_bytes,
            "sha256": session.sha256,
            "validation_status": session.validation_status,
            "detected_format": session.detected_format,
        },
    )
    db.commit()

    spec = session.detected_format or ""
    spec_version = session.detected_version or ""
    components_count = 0
    try:
        as_dict = json.loads(body_text)
        if isinstance(as_dict, dict):
            if as_dict.get("bomFormat") == "CycloneDX":
                spec = "cyclonedx"
                spec_version = str(as_dict.get("specVersion") or "")
                components_count = len(as_dict.get("components") or [])
            elif "spdxVersion" in as_dict:
                spec = "spdx"
                spec_version = str(as_dict.get("spdxVersion") or "")
                components_count = len(as_dict.get("packages") or [])
    except Exception:
        pass

    obj = SBOMSource(
        sbom_name=sbom_name.strip(),
        sbom_data=body_text,
        sbom_type=sbom_type,
        projectid=project_id,
        created_by=created_by,
        created_on=_now_iso(),
        status="validated",
        failed_stage=None,
        validation_errors=[e.model_dump(mode="json") for e in report.entries] if report.entries else None,
        error_count=report.error_count,
        warning_count=report.warning_count,
        validated_at=_now_iso(),
        original_format=spec or None,
        current_format=spec or None,
    )
    mark_enrichment_pending(obj)
    try:
        db.add(obj)
        db.commit()
        db.refresh(obj)
        session.imported_sbom_id = obj.id
        session.updated_at = _now_iso()
        db.add(session)
        db.commit()
        audit_service.write_audit_log(
            db,
            context,
            "sbom.upload",
            entity_type="sbom",
            entity_id=obj.id,
            new_value={"sbom_name": obj.sbom_name, "project_id": obj.projectid},
        )
        db.commit()
    except Exception:
        db.rollback()
        log.exception("upload_sbom: persist failed for name=%s", sbom_name)
        raise HTTPException(
            status_code=500,
            detail={"code": "internal_error", "message": "Failed to persist SBOM."},
        )

    try:
        sync_sbom_components(db, obj)
        db.commit()
        components_count = parsed_component_count(obj.sbom_data)
    except Exception as exc:  # pragma: no cover - defensive enrichment path
        db.rollback()
        log.warning("Failed to sync uploaded SBOM components %s: %s", obj.id, exc)
        components_count = 0

    log.info(
        "upload_sbom: persisted sbom_id=%s name=%s filename=%s bytes=%s lines=%s format=%s components=%s validation=%s",
        obj.id,
        obj.sbom_name,
        file.filename,
        byte_size(body_text),
        count_lines(body_text),
        spec or "unknown",
        components_count,
        obj.status,
    )

    background_tasks.add_task(run_post_upload_enrichment, obj.id, context.tenant_id)

    return SbomAcceptedResponse(
        status=validation_status,
        workspace_id=session.id,
        validation_session_id=session.id,
        repair_workspace_url=f"/repair/{session.id}",
        sbom_id=obj.id,
        sbom_name=obj.sbom_name,
        project_id=obj.projectid,
        project_name=obj.project_name,
        spec=spec,
        spec_version=spec_version,
        detected_format=session.detected_format,
        detected_spec_version=session.detected_version,
        detection_confidence=session.detection_confidence,
        detection_evidence=session.detection_evidence_json,
        file_size_bytes=session.file_size_bytes or len(raw),
        total_lines=session.total_lines or count_lines(body_text),
        sha256=session.sha256 or "",
        is_large_file=bool(session.is_large_file),
        full_editor_allowed=bool(session.full_editor_allowed),
        components=components_count,
        validation_errors=[],
        validation_warnings=[w.model_dump() for w in report.warnings],
        warnings=[w.model_dump() for w in report.warnings],
        info=[i.model_dump() for i in report.info],
        enrichment_status=obj.enrichment_status or "pending",
        message="SBOM uploaded successfully. Enrichment is running in background.",
    )
