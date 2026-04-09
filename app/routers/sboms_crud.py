"""
SBOM CRUD and analysis trigger router.

Routes:
  GET /api/sboms/{sbom_id}             get single SBOM
  POST /api/sboms                       create SBOM (with component sync, NO auto-analysis)
  GET /api/sboms                        list SBOMs with filtering
  PATCH /api/sboms/{sbom_id}            update SBOM
  DELETE /api/sboms/{sbom_id}           delete SBOM with cascade
  GET /api/sboms/{sbom_id}/components   list components
  POST /api/sboms/{sbom_id}/analyze     trigger manual analysis
  POST /api/sboms/{sbom_id}/analyze/stream   streaming analysis with SSE
"""
import asyncio
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Optional, List, Dict, Tuple
from urllib.parse import unquote

from fastapi import APIRouter, Depends, HTTPException, Query, status, Path, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select, delete, func
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from ..db import get_db
from ..models import (
    Projects,
    SBOMSource,
    SBOMType,
    SBOMComponent,
    AnalysisRun,
    AnalysisFinding,
    SBOMAnalysisReport,
)
from ..schemas import (
    SBOMSourceCreate,
    SBOMSourceOut,
    SBOMSourceUpdate,
    SBOMComponentOut,
    AnalysisRunOut,
)
from dataclasses import replace as dataclass_replace

from ..analysis import (
    get_analysis_settings_multi,
    extract_components,
    _augment_components_with_cpe,
    enrich_component_for_osv,
    osv_query_by_components,
    github_query_by_components,
    nvd_query_by_components_async,
    deduplicate_findings,
    analyze_sbom_multi_source_async,
)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["sboms"])


# ---- Helper Functions ----

def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _coerce_sbom_data(value: Any) -> Optional[str]:
    """
    Ensure sbom_data is always stored as a JSON string in the DB Text column,
    even if the client sends a dict/list. Leave strings as-is.
    """
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return value if isinstance(value, str) else str(value)


def normalized_key(value: Optional[str]) -> str:
    return (value or "").strip().lower()


def upsert_components(db: Session, sbom_obj: SBOMSource, components: list[dict]) -> dict:
    existing_rows = db.execute(
        select(SBOMComponent).where(SBOMComponent.sbom_id == sbom_obj.id)
    ).scalars().all()

    by_comp_triplet = {}
    by_cpe = {}

    for row in existing_rows:
        triplet = (
            normalized_key(row.cpe),
            normalized_key(row.name),
            normalized_key(row.version),
        )
        by_comp_triplet.setdefault(triplet, row)
        if row.cpe:
            by_cpe.setdefault(normalized_key(row.cpe), []).append(row)

    for comp in components:
        name = (comp.get("name") or "").strip()
        if not name:
            fallback = (comp.get("bom_ref") or comp.get("purl") or comp.get("cpe") or "component").strip()
            name = fallback[:255] if fallback else "component"

        version = (comp.get("version") or "").strip() or None
        cpe = (comp.get("cpe") or "").strip() or None
        triplet = (normalized_key(cpe), normalized_key(name), normalized_key(version))

        if triplet in by_comp_triplet:
            continue

        row = SBOMComponent(
            sbom_id=sbom_obj.id,
            bom_ref=(comp.get("bom_ref") or "").strip() or None,
            component_type=(comp.get("type") or "").strip() or None,
            component_group=(comp.get("group") or "").strip() or None,
            name=name,
            version=version,
            purl=(comp.get("purl") or "").strip() or None,
            cpe=cpe,
            supplier=(comp.get("supplier") or "").strip() or None,
            scope=(comp.get("scope") or "").strip() or None,
            created_on=now_iso(),
        )
        db.add(row)
        db.flush()

        by_comp_triplet[triplet] = row
        if cpe:
            by_cpe.setdefault(normalized_key(cpe), []).append(row)

    return {"triplet": by_comp_triplet, "cpe": by_cpe}


def sync_sbom_components(db: Session, sbom_obj: SBOMSource) -> list[dict]:
    if not sbom_obj.sbom_data:
        return []
    components = extract_components(sbom_obj.sbom_data)
    upsert_components(db, sbom_obj, components)
    return components


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def compute_report_status(total_findings: int, query_errors: list[dict]) -> str:
    if total_findings > 0:
        return "FAIL"
    if query_errors:
        return "PARTIAL"
    return "PASS"


def persist_analysis_run(
    db: Session,
    sbom_obj: SBOMSource,
    details: dict,
    components: list[dict],
    run_status: str,
    source: str,
    started_on: str,
    completed_on: str,
    duration_ms: int,
) -> AnalysisRun:
    component_maps = upsert_components(db, sbom_obj, components)

    run = AnalysisRun(
        sbom_id=sbom_obj.id,
        project_id=sbom_obj.projectid,
        run_status=run_status,
        source=source,
        started_on=started_on,
        completed_on=completed_on,
        duration_ms=duration_ms,
        total_components=safe_int(details.get("total_components")),
        components_with_cpe=safe_int(details.get("components_with_cpe")),
        total_findings=safe_int(details.get("total_findings")),
        critical_count=safe_int(details.get("critical")),
        high_count=safe_int(details.get("high")),
        medium_count=safe_int(details.get("medium")),
        low_count=safe_int(details.get("low")),
        unknown_count=safe_int(details.get("unknown")),
    )
    db.add(run)
    db.flush()

    for finding_raw in details.get("findings", []):
        cpe = (finding_raw.get("cpe") or "").strip() or None
        cname = (finding_raw.get("component_name") or "").strip() or None
        cversion = (finding_raw.get("component_version") or "").strip() or None

        triplet = (
            normalized_key(cpe),
            normalized_key(cname),
            normalized_key(cversion),
        )
        # `upsert_components` returns SBOMComponent ORM rows (not ints) in the
        # triplet map; pull the .id off so SQLAlchemy gets a real FK value.
        triplet_row = component_maps["triplet"].get(triplet)
        component_id = triplet_row.id if triplet_row is not None else None
        if not component_id and cpe:
            cpe_rows = component_maps["cpe"].get(normalized_key(cpe), [])
            if cpe_rows:
                component_id = cpe_rows[0].id

        sources = finding_raw.get("sources", [])
        if isinstance(sources, list):
            sources_str = ",".join(str(s) for s in sources)
        else:
            sources_str = str(sources) if sources else ""

        aliases_json = None
        if finding_raw.get("aliases"):
            try:
                aliases_json = json.dumps(finding_raw["aliases"])
            except (TypeError, ValueError):
                pass

        # `cwe` may arrive as a list (NVD/GHSA/OSV multi-source path) or as a
        # legacy scalar string. Persist as a JSON-encoded list when it's a
        # collection, otherwise fall back to the trimmed string.
        cwe_raw = finding_raw.get("cwe")
        if isinstance(cwe_raw, (list, tuple, set)):
            cwe_value = json.dumps(sorted({str(x) for x in cwe_raw if x})) if cwe_raw else None
        elif isinstance(cwe_raw, str):
            cwe_value = cwe_raw.strip() or None
        else:
            cwe_value = None

        finding = AnalysisFinding(
            analysis_run_id=run.id,
            component_id=component_id,
            component_name=cname,
            component_version=cversion,
            cpe=cpe,
            # Multi-source orchestrator emits the canonical id under "vuln_id";
            # legacy callers may still use "id". Accept both, prefer the new key.
            vuln_id=((finding_raw.get("vuln_id") or finding_raw.get("id") or "").strip() or None),
            severity=(finding_raw.get("severity") or "UNKNOWN").upper(),
            score=finding_raw.get("score"),
            vector=(finding_raw.get("vector") or "").strip() or None,
            published_on=(finding_raw.get("published") or "").strip() or None,
            reference_url=(finding_raw.get("url") or "").strip() or None,
            source=sources_str,
            description=(finding_raw.get("description") or "").strip() or None,
            cwe=cwe_value,
            attack_vector=(finding_raw.get("attack_vector") or "").strip() or None,
            aliases=aliases_json,
            fixed_versions=json.dumps(finding_raw.get("fixed_versions", [])) if finding_raw.get("fixed_versions") else None,
        )
        db.add(finding)

    return run


async def create_auto_report(db: Session, sbom_obj: SBOMSource) -> Optional[AnalysisRun]:
    """
    Trigger default multi-source analysis for an SBOM and persist the run.

    Delegates to ``analyze_sbom_multi_source_async`` which fans NVD + OSV + GitHub
    out concurrently with ``asyncio.gather``. Previously this function ran the
    three sources serially via three blocking ``asyncio.run()`` calls inside a
    sync handler, which (a) blocked the worker thread for the full sum of all
    three round trips and (b) starved concurrent uploads.
    """
    if not sbom_obj.sbom_data:
        return None

    # Extract components up front so we can short-circuit empty SBOMs without
    # paying for any outbound HTTP, and so we can pass the same component list
    # into ``persist_analysis_run`` for component-row upserting.
    try:
        components_raw = extract_components(sbom_obj.sbom_data)
        components_raw = [enrich_component_for_osv(c) for c in components_raw]
        components, _ = _augment_components_with_cpe(components_raw)
    except Exception as exc:
        log.warning("Component extraction failed for SBOM id=%d: %s", sbom_obj.id, exc)
        return None

    if not components:
        return None

    started_on = now_iso()
    started_at = time.perf_counter()

    try:
        cfg = get_analysis_settings_multi()
        details = await analyze_sbom_multi_source_async(
            sbom_obj.sbom_data,
            sources=["NVD", "OSV", "GITHUB"],
            settings=cfg,
        )
    except Exception as exc:
        log.error("Auto-analysis failed for SBOM id=%d: %s", sbom_obj.id, exc, exc_info=True)
        return None

    all_errors: List[dict] = list(details.get("query_errors") or [])
    final_findings: List[dict] = list(details.get("findings") or [])
    sources_used = (details.get("analysis_metadata") or {}).get("sources") or [
        "NVD",
        "OSV",
        "GITHUB",
    ]

    run_status = compute_report_status(len(final_findings), all_errors)
    source_label = ",".join(sources_used)
    if all_errors:
        source_label += " (partial)"

    duration_ms = int((time.perf_counter() - started_at) * 1000)
    run = persist_analysis_run(
        db=db,
        sbom_obj=sbom_obj,
        details=details,
        components=components,
        run_status=run_status,
        source=source_label,
        started_on=started_on,
        completed_on=now_iso(),
        duration_ms=duration_ms,
    )
    db.commit()
    return run


def _sse_event(event_type: str, data: dict) -> str:
    """Format a single Server-Sent Event string."""
    return f"event: {event_type}\ndata: {json.dumps(data)}\n\n"


class AnalyzeStreamPayload(BaseModel):
    sources: Optional[List[str]] = ["NVD", "OSV", "GITHUB"]
    nvd_api_key: Optional[str] = None
    github_token: Optional[str] = None


# ---- Validation Helper ----

_USER_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def _validate_user_id(raw: Optional[str]) -> Optional[str]:
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


# ---- Routes ----

@router.get("/sboms/{sbom_id}", response_model=SBOMSourceOut)
def get_sbom(sbom_id: int, db: Session = Depends(get_db)):
    sbom = db.get(SBOMSource, sbom_id)
    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")
    return sbom


@router.post("/sboms", response_model=SBOMSourceOut, status_code=status.HTTP_201_CREATED)
def create_sbom(payload: SBOMSourceCreate, db: Session = Depends(get_db)):
    log.info("Creating SBOM: name='%s' project_id=%s", payload.sbom_name, payload.projectid)
    # --- Foreign key checks ---
    if payload.projectid is not None and db.get(Projects, payload.projectid) is None:
        log.warning("create_sbom: project_id=%s not found", payload.projectid)
        raise HTTPException(status_code=404, detail="Project not found")
    if payload.sbom_type is not None and db.get(SBOMType, payload.sbom_type) is None:
        log.warning("create_sbom: sbom_type=%s not found", payload.sbom_type)
        raise HTTPException(status_code=404, detail="SBOM type not found")

    # --- Preflight duplicate check on name (global uniqueness) ---
    if payload.sbom_name:
        exists = db.execute(
            select(SBOMSource.id).where(SBOMSource.sbom_name == payload.sbom_name.strip())
        ).first()
        if exists:
            log.warning("create_sbom: duplicate name '%s'", payload.sbom_name)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "duplicate_name", "message": f"An SBOM with name '{payload.sbom_name}' already exists."}
            )

    try:
        obj = SBOMSource(**payload.model_dump(), created_on=now_iso())
        db.add(obj)
        db.flush()
        db.commit()
        db.refresh(obj)
        log.info("SBOM created: id=%d name='%s'", obj.id, obj.sbom_name)

        # Persist parsed components immediately so the UI can display them
        try:
            components = sync_sbom_components(db, obj)
            db.commit()
            log.info("SBOM components synced: sbom id=%d components=%d", obj.id, len(components))
        except Exception as exc:
            db.rollback()
            log.warning("Component sync failed for SBOM id=%d: %s", obj.id, exc)

        return obj

    except IntegrityError as exc:
        db.rollback()
        msg = str(getattr(exc, "orig", exc))
        log.error("create_sbom IntegrityError: %s", msg)
        if "UNIQUE" in msg.upper() and "sbom_name" in msg:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "duplicate_name", "message": f"An SBOM with name '{payload.sbom_name}' already exists."}
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "integrity_error", "message": "Integrity constraint violated while creating SBOM."}
        ) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        log.error("create_sbom DB error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=500,
            detail={"code": "db_error", "message": "Internal database error while creating SBOM."}
        ) from exc
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail={"code": "unexpected", "message": "Unexpected error while creating SBOM."}
        )


@router.get("/sboms", response_model=List[SBOMSourceOut])
def get_sbom_details(
    user_id: Optional[str] = Query(None, description="Filter by CreatedBy (letters/digits/_/./-, 1–64 chars)"),
    page: int = Query(1, ge=1, description="Page number (>=1)"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page (1..500)"),
    response: Response = None,
    db: Session = Depends(get_db),
):
    user_id = _validate_user_id(user_id)
    page = 1 if page < 1 else page
    page_size = max(1, min(page_size, 500))
    offset = (page - 1) * page_size

    try:
        stmt = select(SBOMSource)
        count_stmt = select(func.count(SBOMSource.id))
        if user_id is not None:
            stmt = stmt.where(SBOMSource.created_by == user_id)
            count_stmt = count_stmt.where(SBOMSource.created_by == user_id)

        total = db.execute(count_stmt).scalar_one()

        stmt = stmt.order_by(SBOMSource.id.desc()).limit(page_size).offset(offset)
        items = db.execute(stmt).scalars().all()

        if response is not None:
            response.headers["X-Total-Count"] = str(total)

        return items
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="Internal database error while fetching SBOMs.") from exc


@router.get("/sboms/{sbom_id}/components", response_model=list[SBOMComponentOut])
def get_sbom_components(
    sbom_id: int = Path(..., description="SBOM ID (positive integer)"),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=1000),
    response: Response = None,
    db: Session = Depends(get_db),
):
    sbom_id = _validate_positive_int(sbom_id, param_name="sbom_id")
    page = 1 if page < 1 else page
    page_size = max(1, min(page_size, 1000))
    offset = (page - 1) * page_size

    try:
        sbom = db.get(SBOMSource, sbom_id)
        if not sbom:
            raise HTTPException(status_code=404, detail="SBOM not found")

        total = db.execute(
            select(func.count(SBOMComponent.id)).where(SBOMComponent.sbom_id == sbom_id)
        ).scalar_one()

        stmt = (
            select(SBOMComponent)
            .where(SBOMComponent.sbom_id == sbom_id)
            .order_by(SBOMComponent.name.asc(), SBOMComponent.version.asc())
            .limit(page_size)
            .offset(offset)
        )
        items = db.execute(stmt).scalars().all()

        if response is not None:
            response.headers["X-Total-Count"] = str(total)

        return items
    except HTTPException:
        raise
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="Internal database error while fetching SBOM components.") from exc


@router.patch("/sboms/{sbom_id}", response_model=SBOMSourceOut)
def update_sbom(
    sbom_id: int,
    payload: SBOMSourceUpdate,
    user_id: str = Query(..., description="Must match SBOM.created_by"),
    db: Session = Depends(get_db),
):
    sbom = db.get(SBOMSource, sbom_id)
    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")

    actual_owner = (sbom.created_by or "").strip().lower()
    caller = (user_id or "").strip().lower()
    if actual_owner and actual_owner != caller:
        raise HTTPException(status_code=403, detail="Forbidden: user cannot update this SBOM")
    if not sbom.created_by:
        sbom.created_by = user_id

    data = payload.model_dump(exclude_unset=True, exclude_none=True)

    if "projectid" in data and data["projectid"] is not None:
        if db.get(Projects, data["projectid"]) is None:
            raise HTTPException(status_code=404, detail="Project not found")
    if "sbom_type" in data and data["sbom_type"] is not None:
        if db.get(SBOMType, data["sbom_type"]) is None:
            raise HTTPException(status_code=404, detail="SBOM type not found")

    if "sbom_data" in data:
        data["sbom_data"] = _coerce_sbom_data(data["sbom_data"])

    try:
        for k, v in data.items():
            setattr(sbom, k, v)
        sbom.modified_on = now_iso()
        sbom.modified_by = data.get("modified_by") or user_id

        db.add(sbom)
        db.commit()
        db.refresh(sbom)
        return sbom
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update SBOM: {exc}") from exc


@router.delete("/sboms/{sbom_id}", status_code=status.HTTP_200_OK)
def delete_sbom(
    sbom_id: int,
    user_id: str = Query(..., description="CreatedBy user id; must match SBOM.created_by"),
    confirm: str = Query("no", description="Set to 'yes' to confirm deletion"),
    db: Session = Depends(get_db),
):
    if sbom_id is None or not isinstance(sbom_id, int) or sbom_id <= 0:
        raise HTTPException(status_code=400, detail="Invalid sbom_id. It must be a positive integer.")

    sbom = db.get(SBOMSource, sbom_id)
    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")

    def _norm(s: Optional[str]) -> str:
        return (s or "").strip().lower()

    if sbom.created_by and _norm(sbom.created_by) != _norm(user_id):
        raise HTTPException(status_code=403, detail="Forbidden: user cannot delete this SBOM")

    if _norm(confirm) not in {"yes", "y"}:
        return {
            "status": "pending_confirmation",
            "message": (
                "This operation will permanently delete the SBOM and all related analysis data. "
                "To proceed, resend the request with confirm=yes."
            ),
            "example": f"/api/sboms/{sbom_id}?user_id={user_id}&confirm=yes",
        }

    try:
        run_ids = db.execute(
            select(AnalysisRun.id).where(AnalysisRun.sbom_id == sbom_id)
        ).scalars().all()

        if run_ids:
            db.execute(
                delete(AnalysisFinding)
                .where(AnalysisFinding.analysis_run_id.in_(run_ids))
                .execution_options(synchronize_session=False)
            )

        db.execute(
            delete(AnalysisRun)
            .where(AnalysisRun.sbom_id == sbom_id)
            .execution_options(synchronize_session=False)
        )
        db.execute(
            delete(SBOMComponent)
            .where(SBOMComponent.sbom_id == sbom_id)
            .execution_options(synchronize_session=False)
        )
        db.execute(
            delete(SBOMAnalysisReport)
            .where(SBOMAnalysisReport.sbom_ref_id == sbom_id)
            .execution_options(synchronize_session=False)
        )
        db.flush()

        db.delete(sbom)
        db.commit()

        return {
            "status": "deleted",
            "message": f"SBOM {sbom_id} and related data have been deleted successfully.",
            "sbom_id": sbom_id,
            "requested_by": user_id,
        }
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete SBOM: {exc}") from exc


@router.post("/sboms/{sbom_id}/analyze", response_model=AnalysisRunOut, status_code=status.HTTP_201_CREATED)
async def run_analysis_for_sbom(sbom_id: int, db: Session = Depends(get_db)):
    log.info("Manual analysis triggered for SBOM id=%d", sbom_id)
    sbom = db.get(SBOMSource, sbom_id)
    if not sbom:
        log.warning("Analysis requested for unknown SBOM id=%d", sbom_id)
        raise HTTPException(status_code=404, detail="SBOM not found")
    try:
        report = await create_auto_report(db, sbom)
    except Exception as exc:
        db.rollback()
        log.error("Analysis run failed for SBOM id=%d: %s", sbom_id, exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Unable to generate analysis report") from exc
    if not report:
        log.error("Analysis report generation failed for SBOM id=%d", sbom_id)
        raise HTTPException(status_code=500, detail="Unable to generate analysis report")
    return report


@router.post("/sboms/{sbom_id}/analyze/stream")
async def analyze_sbom_stream(
    sbom_id: int,
    payload: AnalyzeStreamPayload,
    db: Session = Depends(get_db),
):
    """
    Run multi-source SBOM analysis and stream per-source progress via SSE.

    SSE event types:
      progress  — phase/source status updates (started, parsed, running, complete, error)
      complete  — final result with runId + severity counts
      error     — fatal error (SBOM not found, parse failure, etc.)
    """
    sbom_row = db.get(SBOMSource, sbom_id)

    async def _stream_not_found():
        yield _sse_event("error", {"message": f"SBOM {sbom_id} not found", "code": 404})

    if not sbom_row:
        return StreamingResponse(
            _stream_not_found(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    async def event_stream():
        started_at = time.perf_counter()

        def elapsed() -> int:
            return int((time.perf_counter() - started_at) * 1000)

        try:
            cfg = get_analysis_settings_multi()

            # Per-request GitHub token override — never mutate os.environ from a
            # request handler (it would race across concurrent requests). The
            # override is preferred over the env var inside
            # `github_query_by_components`.
            if payload.github_token and payload.github_token.strip():
                cfg = dataclass_replace(cfg, gh_token_override=payload.github_token.strip())

            sources = [s.strip().upper() for s in (payload.sources or ["NVD", "OSV", "GITHUB"])]

            yield _sse_event("progress", {
                "phase": "started",
                "sources": sources,
                "elapsed_ms": elapsed(),
            })
            await asyncio.sleep(0)

            try:
                sbom_data = sbom_row.sbom_data or ""
                components_raw = extract_components(sbom_data)
                components_raw = [enrich_component_for_osv(c) for c in components_raw]
                components, _gen_cpe = _augment_components_with_cpe(components_raw)
            except Exception as exc:
                yield _sse_event("error", {"message": f"SBOM parse failed: {exc}", "code": 400})
                return

            yield _sse_event("progress", {
                "phase": "parsed",
                "components": len(components),
                "elapsed_ms": elapsed(),
            })
            await asyncio.sleep(0)

            all_findings: List[dict] = []
            all_errors: List[dict] = []

            source_map = {
                "NVD": lambda: nvd_query_by_components_async(
                    components, cfg, nvd_api_key=payload.nvd_api_key
                ),
                "OSV": lambda: osv_query_by_components(components, cfg),
                "GITHUB": lambda: github_query_by_components(components, cfg),
            }

            # Run all selected sources CONCURRENTLY (instead of one-by-one) and
            # surface per-source start/complete/error events as soon as they
            # arrive via an asyncio.Queue. This converges on the same parallel
            # pattern used by `create_auto_report` while preserving the SSE
            # progress contract.
            event_queue: asyncio.Queue = asyncio.Queue()
            active_sources = [s for s in sources if s in source_map]

            async def _run_source(source_name: str) -> None:
                src_start = time.perf_counter()
                await event_queue.put({
                    "kind": "progress",
                    "data": {
                        "source": source_name,
                        "status": "running",
                        "elapsed_ms": elapsed(),
                    },
                })
                try:
                    findings, errors, _warnings = await source_map[source_name]()
                    await event_queue.put({
                        "kind": "result",
                        "source": source_name,
                        "findings": findings,
                        "errors": errors,
                        "source_ms": int((time.perf_counter() - src_start) * 1000),
                    })
                except Exception as exc:
                    await event_queue.put({
                        "kind": "exception",
                        "source": source_name,
                        "error": str(exc),
                        "source_ms": int((time.perf_counter() - src_start) * 1000),
                    })

            async def _orchestrate() -> None:
                try:
                    await asyncio.gather(
                        *(_run_source(name) for name in active_sources),
                        return_exceptions=False,
                    )
                finally:
                    await event_queue.put({"kind": "done"})

            orchestrator = asyncio.create_task(_orchestrate())

            try:
                while True:
                    msg = await event_queue.get()
                    kind = msg.get("kind")
                    if kind == "done":
                        break
                    if kind == "progress":
                        yield _sse_event("progress", msg["data"])
                    elif kind == "result":
                        findings = msg["findings"]
                        errors = msg["errors"]
                        all_findings.extend(findings)
                        all_errors.extend(errors)
                        yield _sse_event("progress", {
                            "source": msg["source"],
                            "status": "complete",
                            "findings": len(findings),
                            "errors": len(errors),
                            "source_ms": msg["source_ms"],
                            "elapsed_ms": elapsed(),
                        })
                    elif kind == "exception":
                        all_errors.append({"source": msg["source"], "error": msg["error"]})
                        yield _sse_event("progress", {
                            "source": msg["source"],
                            "status": "error",
                            "error": msg["error"],
                            "source_ms": msg["source_ms"],
                            "elapsed_ms": elapsed(),
                        })
                    await asyncio.sleep(0)
            finally:
                if not orchestrator.done():
                    orchestrator.cancel()
                    try:
                        await orchestrator
                    except (asyncio.CancelledError, Exception):
                        pass

            final_findings = deduplicate_findings(all_findings)

            buckets = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
            for f in final_findings:
                sev = str((f or {}).get("severity", "UNKNOWN")).upper()
                buckets[sev if sev in buckets else "UNKNOWN"] += 1

            details: dict = {
                "total_components": len(components),
                "components_with_cpe": sum(1 for c in components if c.get("cpe")),
                "total_findings": len(final_findings),
                "critical": buckets["CRITICAL"],
                "high": buckets["HIGH"],
                "medium": buckets["MEDIUM"],
                "low": buckets["LOW"],
                "unknown": buckets["UNKNOWN"],
                "query_errors": all_errors,
                "findings": final_findings,
                "analysis_metadata": {"sources": sources},
            }

            run_status = compute_report_status(len(final_findings), all_errors)
            source_label = ",".join(sources)
            if all_errors:
                source_label += " (partial)"

            duration_ms = elapsed()
            run = persist_analysis_run(
                db=db,
                sbom_obj=sbom_row,
                details=details,
                components=components,
                run_status=run_status,
                source=source_label,
                started_on=now_iso(),
                completed_on=now_iso(),
                duration_ms=duration_ms,
            )
            db.commit()

            yield _sse_event("complete", {
                "runId": run.id,
                "status": run_status,
                "total": len(final_findings),
                "critical": buckets["CRITICAL"],
                "high": buckets["HIGH"],
                "medium": buckets["MEDIUM"],
                "low": buckets["LOW"],
                "unknown": buckets["UNKNOWN"],
                "errors": len(all_errors),
                "duration_ms": duration_ms,
            })

        except Exception as exc:
            log.error("SSE stream unhandled error: %s", exc, exc_info=True)
            yield _sse_event("error", {"message": str(exc), "code": 500})

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
