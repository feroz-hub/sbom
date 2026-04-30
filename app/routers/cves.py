"""
CVE detail endpoints — backs the in-app CVE modal.

Routes:
  GET  /api/v1/cves/{cve_id}                       single advisory
  POST /api/v1/cves/batch                          batch lookup (≤50 IDs)
  GET  /api/v1/scans/{scan_id}/cves/{cve_id}       scan-aware (component + upgrade)

Auth: relies on app-level ``require_auth`` dependency wired in ``main.py``.
Rate limits: 60/min single, 10/min batch (per (IP, token) bucket — the
default ``rate_limit_key`` already handles JWT-aware partitioning).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..db import get_db
from ..integrations.cve.identifiers import SUPPORTED_FORMATS, IdKind, classify
from ..rate_limit import limiter
from ..schemas_cve import (
    CveBatchRequest,
    CveBatchResponse,
    CveDetail,
    CveDetailWithContext,
)
from ..services.cve_service import (
    CveDetailService,
    UnrecognizedIdFormatError,
)

log = logging.getLogger("sbom.routers.cves")

router = APIRouter(prefix="/api/v1", tags=["cves"])

#: Stable error code so the frontend can branch on the contract instead of
#: parsing the human-readable message.
ERR_UNRECOGNIZED = "CVE_VAL_E001_UNRECOGNIZED_ID"


def _unrecognized_response(raw_id: str) -> HTTPException:
    """Structured 400 envelope for unrecognized advisory identifiers.

    The envelope is shaped to satisfy the prompt's Phase-2 §2.2 spec —
    ``error_code`` is the discriminator the frontend reads, ``raw_id``
    is echoed for context, and ``supported_formats`` is the sole source
    of truth for the help text.
    """
    return HTTPException(
        status_code=400,
        detail={
            "error_code": ERR_UNRECOGNIZED,
            "message": "We don't recognize this advisory identifier format.",
            "raw_id": raw_id,
            "supported_formats": list(SUPPORTED_FORMATS),
            "retryable": False,
        },
    )


def _service(db: Session) -> CveDetailService:
    return CveDetailService(db)


@router.get("/cves/{cve_id}", response_model=CveDetail)
@limiter.limit("60/minute")
async def get_cve_detail(
    request: Request,  # noqa: ARG001 — required for slowapi key extraction
    cve_id: str,
    db: Session = Depends(get_db),
) -> CveDetail:
    """Return the merged CVE detail payload (cached, TTL-bucketed)."""
    try:
        return await _service(db).get(cve_id)
    except UnrecognizedIdFormatError as exc:
        raise _unrecognized_response(exc.raw_id) from exc


@router.post("/cves/batch", response_model=CveBatchResponse)
@limiter.limit("10/minute")
async def batch_cve_detail(
    request: Request,  # noqa: ARG001 — required for slowapi key extraction
    body: CveBatchRequest,
    db: Session = Depends(get_db),
) -> CveBatchResponse:
    """Bulk lookup. Up to 50 IDs per call (enforced by ``CveBatchRequest``).

    Mixed-validity batches: unknown IDs are collected into ``not_found`` and
    the remaining IDs proceed. A batch with *zero* recognised IDs returns
    400 (the request itself is bad). The structured 400 envelope from
    ``_unrecognized_response`` is reused for the all-unknown case.
    """
    cleaned: list[str] = []
    rejected: list[str] = []
    for raw in body.ids:
        v = classify(raw)
        if v.kind == IdKind.UNKNOWN:
            rejected.append(raw)
        else:
            cleaned.append(v.normalized)
    if not cleaned:
        raise _unrecognized_response(rejected[0] if rejected else "")

    items = await _service(db).get_many(cleaned)
    return CveBatchResponse(items=items, not_found=rejected)


@router.get(
    "/scans/{scan_id}/cves/{cve_id}",
    response_model=CveDetailWithContext,
)
@limiter.limit("60/minute")
async def get_cve_detail_with_scan_context(
    request: Request,  # noqa: ARG001
    scan_id: int,
    cve_id: str,
    db: Session = Depends(get_db),
) -> CveDetailWithContext:
    """Scan-aware variant — joins SBOMComponent + computes recommended upgrade."""
    try:
        return await _service(db).get_with_scan_context(cve_id, scan_id)
    except UnrecognizedIdFormatError as exc:
        raise _unrecognized_response(exc.raw_id) from exc
