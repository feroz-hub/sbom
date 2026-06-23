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

from ..db import get_db
from ..models import Projects, SBOMSource, SBOMType
from ..services.sbom_enrichment_service import mark_enrichment_pending, run_post_upload_enrichment
from ..services.sbom_service import sync_sbom_components
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

    sbom_id: int
    sbom_name: str
    project_id: int | None = None
    project_name: str | None = None
    spec: str
    spec_version: str
    components: int
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
    created_by: str | None = Form(None),
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

    if project_id is not None and db.get(Projects, project_id) is None:
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

    body_text = raw.decode("utf-8", errors="replace")
    if body_text.startswith("﻿"):
        body_text = body_text.lstrip("﻿")

    if report.has_errors():
        service = ValidationRepairService(db)
        session, blocked_reason = service.create_failed_upload_session(
            raw_text=body_text,
            report=report,
            sbom_name=sbom_name,
            original_filename=file.filename,
            project_id=project_id,
            sbom_type=sbom_type,
            user_id=created_by,
        )
        raise HTTPException(
            status_code=report.http_status,
            detail=build_validation_failed_detail(
                report=report,
                sbom_name=sbom_name,
                session=session,
                blocked_reason=blocked_reason,
            ),
        )

    spec = ""
    spec_version = ""
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
    except Exception as exc:  # pragma: no cover - defensive enrichment path
        db.rollback()
        log.warning("Failed to sync uploaded SBOM components %s: %s", obj.id, exc)

    background_tasks.add_task(run_post_upload_enrichment, obj.id)

    return SbomAcceptedResponse(
        sbom_id=obj.id,
        sbom_name=obj.sbom_name,
        project_id=obj.projectid,
        project_name=obj.project_name,
        spec=spec,
        spec_version=spec_version,
        components=components_count,
        warnings=[w.model_dump() for w in report.warnings],
        info=[i.model_dump() for i in report.info],
        enrichment_status=obj.enrichment_status or "pending",
        message="SBOM uploaded successfully. Enrichment is running in background.",
    )
