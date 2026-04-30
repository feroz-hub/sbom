"""POST /api/sboms/upload — multipart endpoint that runs the eight-stage
validation pipeline.

This route is the **canonical** ingress shape from ADR-0007. It accepts a
multipart upload, runs :func:`app.validation.run`, and either:

* responds 202 with the new ``SBOMSource`` row id and the report's warnings
  / info entries (so the frontend can surface NTIA hints), or
* responds 400 / 413 / 415 / 422 with the structured ``ErrorReport``.

The legacy JSON-string endpoint (``POST /api/sboms``) keeps working
unchanged — see :mod:`app.routers.sboms_crud`. New integrations should
prefer the multipart shape; the JSON-string shape is marked deprecated in
the OpenAPI doc.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import SBOMSource
from ..settings import get_settings
from ..validation import run as run_validation

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/sboms", tags=["sboms"])


class SbomAcceptedResponse(BaseModel):
    """Response body for a successful upload."""

    sbom_id: int
    sbom_name: str
    spec: str
    spec_version: str
    components: int
    warnings: list[dict]
    info: list[dict]


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


@router.post(
    "/upload",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=SbomAcceptedResponse,
)
async def upload_sbom(
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
                        "message": (
                            f"Uploaded body of {len(raw)} bytes exceeds "
                            f"MAX_UPLOAD_BYTES ({max_bytes})."
                        ),
                        "remediation": (
                            "Compress the SBOM, split into multi-part, or "
                            "contact your operator to raise the limit."
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

    if report.has_errors():
        raise HTTPException(status_code=report.http_status, detail=report.to_dict())

    # Persist. The body bytes (decoded as UTF-8) are stored as a JSON / XML /
    # tag-value string on `SBOMSource.sbom_data`. The legacy ``parse``
    # pipeline keeps working against this column for one release.
    body_text = raw.decode("utf-8", errors="replace")
    if body_text.startswith("﻿"):
        body_text = body_text.lstrip("﻿")

    obj = SBOMSource(
        sbom_name=sbom_name.strip(),
        sbom_data=body_text,
        sbom_type=sbom_type,
        projectid=project_id,
        created_by=created_by,
        created_on=_now_iso(),
    )
    try:
        db.add(obj)
        db.commit()
        db.refresh(obj)
    except Exception:
        db.rollback()
        log.exception("upload_sbom: persist failed for name=%s", sbom_name)
        raise HTTPException(
            status_code=500,
            detail={"code": "internal_error", "message": "Failed to persist validated SBOM."},
        )

    spec = ""
    spec_version = ""
    components_count = 0
    parsed = report.entries  # noqa: F841 — used to silence linter; real data below
    # The pipeline does not expose the internal model on ErrorReport; for the
    # response shape we re-derive minimal stats from the parsed dict by
    # re-parsing the body. This is cheap on the success path because the
    # document already passed every cap.
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
        # XML / tag-value path; surface 0 components in the response — the
        # legacy parser will populate the components table on first analyse.
        pass

    return SbomAcceptedResponse(
        sbom_id=obj.id,
        sbom_name=obj.sbom_name,
        spec=spec,
        spec_version=spec_version,
        components=components_count,
        warnings=[w.model_dump() for w in report.warnings],
        info=[i.model_dump() for i in report.info],
    )
