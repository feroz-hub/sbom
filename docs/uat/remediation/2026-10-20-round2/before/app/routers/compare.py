"""
Compare Runs v2 router (ADR-0008).

Routes:

    POST /api/v1/compare                          run a fresh diff (or read cached)
    POST /api/v1/compare/{cache_key}/export       export cached result as md/csv/json

Auth comes from the app-level ``require_auth`` dependency wired in
``main.py``. Rate limiting applied per-route — diffs are expensive (one
SQL query per run + cache write); exports are cheap but unbounded if we
let them through.

Streaming variant (``POST /api/v1/compare/stream``) is reserved for
larger diffs above ``Settings.compare_streaming_threshold``. Phase 3 ships
the non-streaming path; the streaming path arrives in a follow-up once
the frontend's progressive-render loop is built (Phase 4 §4.3).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import CompareCache
from ..rate_limit import limiter
from ..schemas_compare import (
    ERR_COMPARE_BAD_REQUEST,
    CompareExportRequest,
    CompareRequest,
    CompareResult,
)
from ..services.compare_export import export
from ..services.compare_service import (
    CompareError,
    CompareService,
    RunNotFoundError,
    RunNotReadyError,
    SameRunError,
)

log = logging.getLogger("sbom.routers.compare")

router = APIRouter(prefix="/api/v1", tags=["compare"])


def _envelope(exc: CompareError) -> HTTPException:
    """Map service errors into the project's structured 4xx envelope.

    Matches the shape of ``app/routers/cves.py:_unrecognized_response`` so
    the frontend has a consistent ``{error_code, message, retryable}`` to
    branch on.
    """
    detail: dict = {
        "error_code": exc.error_code,
        "message": str(exc),
        "retryable": False,
    }
    if isinstance(exc, RunNotFoundError):
        detail["run_id"] = exc.run_id
    elif isinstance(exc, RunNotReadyError):
        detail["run_id"] = exc.run_id
        detail["status"] = exc.status
        detail["retryable"] = True  # client may poll
    elif isinstance(exc, SameRunError):
        detail["run_id"] = exc.run_id
    return HTTPException(status_code=exc.http_status, detail=detail)


@router.post("/compare", response_model=CompareResult)
@limiter.limit("30/minute")
def compare_runs(
    request: Request,  # noqa: ARG001 — required for slowapi key extraction
    body: CompareRequest,
    db: Session = Depends(get_db),
) -> CompareResult:
    """Diff two analysis runs. Reads from cache when fresh, computes when stale."""
    svc = CompareService(db)
    try:
        return svc.compare(body.run_a_id, body.run_b_id)
    except CompareError as exc:
        raise _envelope(exc) from exc


@router.post("/compare/{cache_key}/export")
@limiter.limit("10/minute")
def export_compare(
    request: Request,  # noqa: ARG001 — required for slowapi key extraction
    cache_key: str,
    body: CompareExportRequest,
    db: Session = Depends(get_db),
) -> Response:
    """Re-serialise a cached compare result into ``markdown``, ``csv``, or ``json``.

    The export endpoint is cache-only: the diff must already exist in
    ``compare_cache``. This avoids running a second expensive computation
    just to produce a download. Clients should always call ``POST /compare``
    first; if cache_key isn't recognised they get a structured 404 with the
    same error envelope as the fresh-diff endpoint.
    """
    if len(cache_key) != 64 or not all(c in "0123456789abcdef" for c in cache_key.lower()):
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": ERR_COMPARE_BAD_REQUEST,
                "message": "cache_key must be a 64-char hex string",
                "retryable": False,
            },
        )
    row = db.get(CompareCache, cache_key.lower())
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error_code": "COMPARE_E006_CACHE_MISS",
                "message": "compare result not in cache; re-run POST /api/v1/compare first",
                "retryable": True,
            },
        )
    try:
        result = CompareResult.model_validate(row.payload)
    except Exception as exc:
        log.warning(
            "compare cache_corrupt cache_key=%s err=%s — discarding row",
            cache_key,
            exc,
        )
        db.delete(row)
        db.commit()
        raise HTTPException(
            status_code=503,
            detail={
                "error_code": "COMPARE_E007_CACHE_CORRUPT",
                "message": "cached compare result was corrupt and has been discarded; re-run POST /api/v1/compare",
                "retryable": True,
            },
        ) from exc

    content, media_type, filename = export(result, body.format)
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
