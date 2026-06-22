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
import re
import time
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Path, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from ..analysis import (
    _augment_components_with_cpe,
    deduplicate_findings,
    enrich_component_for_osv,
    extract_components,
    get_analysis_settings_multi,
)
from ..auth import require_roles
from ..db import get_db
from ..idempotency import (
    analysis_run_to_dict,
    get_cached,
    normalize_idempotency_key,
    put_cached,
    run_idempotent,
)
from ..models import (
    AnalysisRun,
    Projects,
    SBOMSource,
    SBOMType,
)
from ..rate_limit import analyze_route_limit
from ..schemas import (
    AnalysisRunOut,
    SBOMComponentListResponse,
    SbomPatchRequest,
    SBOMSourceCreate,
    SBOMSourceOut,
)
from ..services import audit_log
from ..services.analysis_service import compute_report_status, persist_analysis_run
from ..services.sbom_delete_service import SBOMDeleteConflict, SBOMDeleteService
from ..services.sbom_enrichment_service import mark_enrichment_pending, run_post_upload_enrichment
from ..services.sbom_service import coerce_sbom_data
from ..services.soft_delete import SoftDeleteService
from ..services.validation_repair_service import (
    ValidationRepairService,
    build_validation_failed_detail,
)
from ..sources import (
    EVENT_COMPLETE,
    EVENT_DONE,
    EVENT_ERROR,
    EVENT_RUNNING,
    build_source_adapters,
    configured_default_sources,
    normalize_source_names,
    run_sources_concurrently,
)
from ..validation import ErrorReport
from ..validation import run as run_validation

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["sboms"])
_security_role = Depends(require_roles("admin", "security"))


# ---- Helper Functions ----


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _coerce_sbom_data(value: Any) -> str | None:
    return coerce_sbom_data(value)


def _classify_status(report: ErrorReport) -> str:
    """Map an ErrorReport to one of the canonical sbom_source.status values.

    ``quarantined`` is reserved for security-stage errors (XXE, depth bombs,
    prototype-pollution keys) — they require admin attention rather than
    a re-upload. Everything else with errors is ``failed``; clean reports
    (errors-free, regardless of warnings) are ``validated``.
    """
    if not report.has_errors():
        return "validated"
    for entry in report.errors:
        if entry.stage == "security":
            return "quarantined"
    return "failed"


def _validation_failure_response(sbom_id: int, report: ErrorReport, sbom_name: str) -> HTTPException:
    """Build the structured 4xx response for a rejected upload.

    The ``detail`` shape mirrors ``ErrorReport.to_dict()`` plus the bits
    the frontend needs to navigate to the persisted row: ``sbom_id``,
    ``status``, ``failed_stage``, and the count summary.
    """
    return HTTPException(
        status_code=report.http_status,
        detail={
            "code": "sbom_validation_failed",
            "message": (
                f"SBOM '{sbom_name}' did not pass validation; "
                f"{report.error_count} error(s) at stage '{report.first_error_stage}'."
            ),
            "sbom_id": sbom_id,
            "status": _classify_status(report),
            "failed_stage": report.first_error_stage,
            "error_count": report.error_count,
            "warning_count": report.warning_count,
            "entries": [e.model_dump() for e in report.entries],
            "truncated": report.truncated,
        },
    )


def normalized_key(value: str | None) -> str:
    return (value or "").strip().lower()


def upsert_components(db: Session, sbom_obj: SBOMSource, components: list[dict]) -> dict:
    from ..services.sbom_service import _upsert_components

    return _upsert_components(db, sbom_obj, components)


def sync_sbom_components(db: Session, sbom_obj: SBOMSource) -> list[dict]:
    from ..services.sbom_service import sync_sbom_components as service_sync_sbom_components

    return service_sync_sbom_components(db, sbom_obj)


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


async def create_auto_report(
    db: Session,
    sbom_obj: SBOMSource,
    *,
    force_refresh: bool = False,
) -> AnalysisRun | None:
    """
    Trigger default multi-source analysis for an SBOM and persist the run.

    Uses the shared ``app.sources`` adapter runner so configured sources
    (NVD, OSV, GitHub, VulDB, etc.) are fanned out consistently with the
    streaming and ad-hoc analysis endpoints.

    ``force_refresh`` (roadmap #2 PR-E): when True AND the source-response
    cache is enabled, every external-source fetch IGNORES cached hits and
    re-queries upstream — then writes the fresh result, overwriting the
    stale entry. Scheduled scans pass ``False`` (default) so they reuse
    cached responses; only an operator-triggered "scan fresh" should
    pass ``True``. No-op when ``source_cache_enabled`` is False.
    """
    if not sbom_obj.sbom_data:
        return None

    # Extract components up front so we can short-circuit empty SBOMs without
    # paying for any outbound HTTP, and so we can pass the same component list
    # into ``persist_analysis_run`` for component-row upserting.
    try:
        components_raw = extract_components(sbom_obj.sbom_data)

        # Deduplicate components before scanning
        try:
            sbom_dict = json.loads(sbom_obj.sbom_data) if isinstance(sbom_obj.sbom_data, str) else sbom_obj.sbom_data
        except Exception:
            sbom_dict = {}
        dependencies = []
        if isinstance(sbom_dict, dict):
            if sbom_dict.get("bomFormat") == "CycloneDX":
                dependencies = sbom_dict.get("dependencies") or []
            elif sbom_dict.get("spdxVersion") or sbom_dict.get("SPDXID"):
                dependencies = sbom_dict.get("relationships") or []

        from ..services.component_deduplication_service import ComponentDeduplicationService

        canonical_raw, _, _, _, _ = ComponentDeduplicationService.deduplicate_components(components_raw, dependencies)

        components_raw = [enrich_component_for_osv(c) for c in canonical_raw]
        components, _ = _augment_components_with_cpe(components_raw)
    except Exception as exc:
        log.warning("Component extraction failed for SBOM id=%d: %s", sbom_obj.id, exc)
        return None

    if not components:
        return None

    started_on = now_iso()
    started_at = time.perf_counter()

    cfg = get_analysis_settings_multi()
    if force_refresh:
        # Per-run override via ``dataclasses.replace`` — never mutate
        # the cached singleton, which is shared across requests.
        from dataclasses import replace as _dc_replace

        cfg = _dc_replace(cfg, source_cache_force_refresh=True)
    sources_used = configured_default_sources()
    try:
        raw_findings, all_errors, all_warnings = await run_sources_concurrently(
            sources=build_source_adapters(sources_used),
            components=components,
            settings=cfg,
        )
    except Exception as exc:
        log.error("Auto-analysis failed for SBOM id=%d: %s", sbom_obj.id, exc, exc_info=True)
        return None

    final_findings: list[dict] = deduplicate_findings(raw_findings)

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
        "query_warnings": all_warnings,
        "findings": final_findings,
        "analysis_metadata": {
            "sources": sources_used,
            "provider_status": [
                warning["provider_status"]
                for warning in all_warnings
                if isinstance(warning, dict) and isinstance(warning.get("provider_status"), dict)
            ],
        },
    }

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
    sources: list[str] | None = None


# ---- Validation Helper ----

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


# ---- Routes ----


@router.get("/sboms/{sbom_id}", response_model=SBOMSourceOut)
def get_sbom(sbom_id: int, db: Session = Depends(get_db)):
    sbom = db.get(SBOMSource, sbom_id)
    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")
    return sbom


@router.post("/sboms", response_model=SBOMSourceOut, status_code=status.HTTP_201_CREATED)
def create_sbom(
    payload: SBOMSourceCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
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
        exists = db.execute(select(SBOMSource.id).where(SBOMSource.sbom_name == payload.sbom_name.strip())).first()
        if exists:
            log.warning("create_sbom: duplicate name '%s'", payload.sbom_name)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "code": "duplicate_name",
                    "message": f"An SBOM with name '{payload.sbom_name}' already exists.",
                },
            )

    # --- Run the 8-stage validator BEFORE the insert. Failed uploads are
    # staged in sbom_validation_sessions when safe; they are never inserted
    # into sbom_source as trusted records. ---
    raw_text = _coerce_sbom_data(payload.sbom_data) or ""
    report = run_validation(raw_text.encode("utf-8"))
    if report.has_errors():
        session, blocked_reason = ValidationRepairService(db).create_failed_upload_session(
            raw_text=raw_text,
            report=report,
            sbom_name=payload.sbom_name,
            original_filename=payload.sbom_name,
            project_id=payload.projectid,
            sbom_type=payload.sbom_type,
            user_id=payload.created_by,
        )
        raise HTTPException(
            status_code=report.http_status,
            detail=build_validation_failed_detail(
                report=report,
                sbom_name=payload.sbom_name,
                session=session,
                blocked_reason=blocked_reason,
            ),
        )
    serialized_entries = [e.model_dump(mode="json") for e in report.entries] if report.entries else None

    try:
        data = payload.model_dump()
        data["sbom_data"] = raw_text or None
        obj = SBOMSource(
            **data,
            created_on=now_iso(),
            status="validated",
            failed_stage=None,
            validation_errors=serialized_entries,
            error_count=report.error_count,
            warning_count=report.warning_count,
            validated_at=now_iso(),
        )
        mark_enrichment_pending(obj)
        db.add(obj)
        db.flush()
        db.commit()
        db.refresh(obj)
        log.info(
            "SBOM created: id=%d name='%s' status=%s errors=%d warnings=%d",
            obj.id,
            obj.sbom_name,
            obj.status,
            report.error_count,
            report.warning_count,
        )

        # Clean SBOM (or warnings only) — sync components for the UI.
        try:
            components = sync_sbom_components(db, obj)
            db.commit()
            log.info("SBOM components synced: sbom id=%d components=%d", obj.id, len(components))
        except Exception as exc:
            db.rollback()
            log.warning("Component sync failed for SBOM id=%d: %s", obj.id, exc)

        background_tasks.add_task(run_post_upload_enrichment, obj.id)
        return obj

    except IntegrityError as exc:
        db.rollback()
        msg = str(getattr(exc, "orig", exc))
        log.error("create_sbom IntegrityError: %s", msg)
        if "UNIQUE" in msg.upper() and "sbom_name" in msg:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "code": "duplicate_name",
                    "message": f"An SBOM with name '{payload.sbom_name}' already exists.",
                },
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "integrity_error", "message": "Integrity constraint violated while creating SBOM."},
        ) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        log.error("create_sbom DB error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=500, detail={"code": "db_error", "message": "Internal database error while creating SBOM."}
        ) from exc
    except HTTPException:
        # Validation-failure responses fall through here without rollback —
        # the row was already committed and is the navigation target the
        # frontend report links to.
        raise
    except Exception:
        db.rollback()
        log.exception("create_sbom unexpected error: name=%s", payload.sbom_name)
        raise HTTPException(
            status_code=500, detail={"code": "unexpected", "message": "Unexpected error while creating SBOM."}
        )


_ALLOWED_STATUSES = {"validated", "failed", "quarantined", "pending"}
_ALLOWED_STAGES = {
    "ingress",
    "detect",
    "schema",
    "semantic",
    "integrity",
    "security",
    "ntia",
    "signature",
}


@router.get("/sboms", response_model=list[SBOMSourceOut])
def get_sbom_details(
    user_id: str | None = Query(None, description="Filter by CreatedBy (letters/digits/_/./-, 1–64 chars)"),
    status_filter: str | None = Query(
        None,
        alias="status",
        description="Filter by validation status: validated | failed | quarantined | pending.",
    ),
    stage: str | None = Query(
        None,
        description="Filter by failed_stage (ingress | detect | schema | semantic | integrity | security | ntia | signature).",
    ),
    page: int = Query(1, ge=1, description="Page number (offset mode; ignored when cursor is set)"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page (1..500)"),
    cursor: int | None = Query(
        None,
        description="Keyset pagination: return SBOMs with id strictly less than this value (desc by id). When set, page offset is ignored.",
    ),
    response: Response = None,
    db: Session = Depends(get_db),
):
    user_id = _validate_user_id(user_id)
    page = 1 if page < 1 else page
    page_size = max(1, min(page_size, 500))

    if status_filter is not None and status_filter not in _ALLOWED_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=f"status must be one of {sorted(_ALLOWED_STATUSES)}",
        )
    if stage is not None and stage not in _ALLOWED_STAGES:
        raise HTTPException(
            status_code=422,
            detail=f"stage must be one of {sorted(_ALLOWED_STAGES)}",
        )

    try:
        stmt = select(SBOMSource)
        count_stmt = select(func.count(SBOMSource.id))
        if user_id is not None:
            stmt = stmt.where(SBOMSource.created_by == user_id)
            count_stmt = count_stmt.where(SBOMSource.created_by == user_id)
        if status_filter is not None:
            stmt = stmt.where(SBOMSource.status == status_filter)
            count_stmt = count_stmt.where(SBOMSource.status == status_filter)
        if stage is not None:
            stmt = stmt.where(SBOMSource.failed_stage == stage)
            count_stmt = count_stmt.where(SBOMSource.failed_stage == stage)

        total = db.execute(count_stmt).scalar_one()

        if cursor is not None:
            if cursor < 1:
                raise HTTPException(status_code=422, detail="cursor must be >= 1")
            stmt = stmt.where(SBOMSource.id < cursor)
            stmt = stmt.order_by(SBOMSource.id.desc()).limit(page_size)
        else:
            offset = (page - 1) * page_size
            stmt = stmt.order_by(SBOMSource.id.desc()).limit(page_size).offset(offset)

        items = db.execute(stmt).scalars().all()

        if response is not None:
            response.headers["X-Total-Count"] = str(total)
            if items and len(items) == page_size:
                response.headers["X-Next-Cursor"] = str(items[-1].id)

        return items
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="Internal database error while fetching SBOMs.") from exc


@router.get("/sboms/{sbom_id}/components", response_model=SBOMComponentListResponse)
def get_sbom_components(
    sbom_id: int = Path(..., description="SBOM ID (positive integer)"),
    include_duplicates: bool = Query(False, description="Whether to include duplicate components in the response"),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=1000),
    search: str | None = Query(None, description="Case-insensitive search across component fields"),
    sort_by: str = Query("name", description="Sort field: name, version, component_type, license, lifecycle_status"),
    sort_order: str = Query("asc", description="Sort direction: asc or desc"),
    db: Session = Depends(get_db),
):
    sbom_id = _validate_positive_int(sbom_id, param_name="sbom_id")
    if sort_by not in {"name", "version", "component_type", "license", "lifecycle_status"}:
        raise HTTPException(status_code=400, detail=f"Unsupported sort_by value: {sort_by}")
    if sort_order.lower() not in {"asc", "desc"}:
        raise HTTPException(status_code=400, detail=f"Unsupported sort_order value: {sort_order}")

    try:
        sbom = db.get(SBOMSource, sbom_id)
        if not sbom:
            raise HTTPException(status_code=404, detail="SBOM not found")

        from ..services.sbom_service import list_sbom_components

        return list_sbom_components(
            db,
            sbom_id,
            include_duplicates=include_duplicates,
            page=page,
            page_size=page_size,
            search=search,
            sort_by=sort_by,
            sort_order=sort_order,
        )
    except HTTPException:
        raise
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="Internal database error while fetching SBOM components.") from exc


@router.get("/sboms/{sbom_id}/dedupe-report")
def get_sbom_dedupe_report(
    sbom_id: int = Path(..., description="SBOM ID (positive integer)"),
    db: Session = Depends(get_db),
):
    sbom_id = _validate_positive_int(sbom_id, param_name="sbom_id")
    try:
        sbom = db.get(SBOMSource, sbom_id)
        if not sbom:
            raise HTTPException(status_code=404, detail="SBOM not found")
        report = sbom.dedupe_report_json
        if not report:
            report = {
                "duplicates_found": 0,
                "duplicates_merged": 0,
                "conflicts": [],
                "ref_mapping": {},
                "remapped_dependencies": {},
            }
        return report
    except HTTPException:
        raise
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="Internal database error while fetching dedupe report.") from exc


@router.patch("/sboms/{sbom_id}", response_model=SBOMSourceOut)
def update_sbom(
    sbom_id: int,
    payload: SbomPatchRequest,
    user_id: str | None = Query(None, description="Must match SBOM.created_by"),
    db: Session = Depends(get_db),
):
    sbom = db.get(SBOMSource, sbom_id)
    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")

    actual_owner = (sbom.created_by or "").strip().lower()
    if user_id:
        caller = user_id.strip().lower()
        if actual_owner and actual_owner != caller:
            raise HTTPException(status_code=403, detail="Forbidden: user cannot update this SBOM")
        if not sbom.created_by:
            sbom.created_by = user_id

    old_project_id = sbom.projectid
    old_name = sbom.sbom_name

    data = payload.model_dump(exclude_unset=True)

    if "project_id" in data:
        new_proj_id = data["project_id"]
        if new_proj_id is not None:
            try:
                p_id = int(new_proj_id)
                if p_id <= 0:
                    raise ValueError
            except (ValueError, TypeError):
                raise HTTPException(status_code=400, detail="Invalid project_id format")

            project = db.get(Projects, p_id)
            if not project:
                raise HTTPException(status_code=400, detail="Project not found")
            new_proj_id = p_id

        # Update project_id in SBOMSource
        sbom.projectid = new_proj_id

        # Update project_id in related AnalysisRuns
        from sqlalchemy import update as sa_update

        db.execute(
            sa_update(AnalysisRun)
            .where(AnalysisRun.sbom_id == sbom.id, AnalysisRun.tenant_id == sbom.tenant_id)
            .values(project_id=new_proj_id)
        )

    if "name" in data:
        sbom.sbom_name = data["name"]
    if "product_name" in data:
        sbom.product_name = data["product_name"]
    if "product_version" in data:
        sbom.productver = data["product_version"]
    if "sbom_version" in data:
        sbom.sbom_version = data["sbom_version"]
    if "description" in data:
        sbom.description = data["description"]

    sbom.modified_on = now_iso()
    if user_id:
        sbom.modified_by = user_id

    try:
        db.add(sbom)
        db.commit()
        db.refresh(sbom)

        # Log to generic audit trail
        audit_log.record(
            db,
            user_id=user_id,
            action="sbom.update",
            target_kind="sbom",
            target_id=sbom.id,
            detail=f"SBOM updated. Reason: {payload.change_reason or 'No reason specified'}",
            metadata={
                "old_project_id": old_project_id,
                "new_project_id": sbom.projectid,
                "old_name": old_name,
                "new_name": sbom.sbom_name,
                "changed_by": user_id,
                "changed_at": now_iso(),
                "change_reason": payload.change_reason,
            },
        )
        return sbom
    except Exception:
        db.rollback()
        log.exception("update_sbom failed: sbom_id=%s user=%s", sbom_id, user_id)
        raise HTTPException(
            status_code=500,
            detail={"code": "internal_error", "message": "Internal server error."},
        )


@router.get("/sboms/{sbom_id}/delete-impact", status_code=status.HTTP_200_OK)
def sbom_delete_impact(
    sbom_id: int = Path(..., ge=1),
    db: Session = Depends(get_db),
):
    """Return the complete permanent-delete impact, including descendants."""
    try:
        return SBOMDeleteService(db).get_delete_impact(sbom_id)
    except LookupError:
        raise HTTPException(status_code=404, detail="SBOM not found")


@router.delete("/sboms/{sbom_id}", status_code=status.HTTP_200_OK)
def delete_sbom(
    sbom_id: int,
    user_id: str = Query(..., description="CreatedBy user id; must match SBOM.created_by"),
    confirm: str = Query("no", description="Set to 'yes' to confirm deletion"),
    permanent: bool = Query(
        False,
        description=(
            "If true, permanently delete the SBOM and every dependent row. "
            "If false (default), soft-delete: mark the SBOM and its runs / "
            "components / findings as inactive, leaving rows in place for "
            "recovery."
        ),
    ),
    db: Session = Depends(get_db),
):
    if sbom_id is None or not isinstance(sbom_id, int) or sbom_id <= 0:
        raise HTTPException(status_code=400, detail="Invalid sbom_id. It must be a positive integer.")

    service = SBOMDeleteService(db)
    sbom = service.get_sbom(sbom_id)
    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")

    def _norm(s: str | None) -> str:
        return (s or "").strip().lower()

    if sbom.created_by and _norm(sbom.created_by) != _norm(user_id):
        raise HTTPException(status_code=403, detail="Forbidden: user cannot delete this SBOM")

    confirmed = _norm(confirm) in {"yes", "y"}
    if not confirmed and not permanent:
        return {
            "status": "pending_confirmation",
            "message": (
                "This operation will delete the SBOM and all related analysis data. "
                "To proceed, resend the request with confirm=yes "
                "(and add permanent=true to bypass soft delete)."
            ),
            "example": f"/api/sboms/{sbom_id}?user_id={user_id}&confirm=yes",
        }

    if permanent:
        try:
            return service.permanently_delete_sbom(sbom_id, user_id, confirmed)
        except SBOMDeleteConflict as exc:
            detail: dict[str, Any] = {
                "code": "sbom_delete_conflict",
                "message": exc.message,
                "blocking_dependencies": exc.blocking_dependencies,
            }
            if exc.impact is not None:
                detail["delete_impact"] = exc.impact
            raise HTTPException(status_code=409, detail=detail)
        except Exception:
            log.exception("permanent delete_sbom failed: sbom_id=%s user=%s", sbom_id, user_id)
            raise HTTPException(
                status_code=500,
                detail={"code": "internal_error", "message": "Internal server error."},
            )

    try:
        return service.soft_delete_sbom(sbom_id, user_id)
    except Exception:
        log.exception("soft delete_sbom failed: sbom_id=%s user=%s", sbom_id, user_id)
        raise HTTPException(
            status_code=500,
            detail={"code": "internal_error", "message": "Internal server error."},
        )


@router.post("/sboms/{sbom_id}/restore", status_code=status.HTTP_200_OK)
def restore_sbom(
    sbom_id: int = Path(..., ge=1),
    user_id: str | None = Query(None),
    _principal=_security_role,
    db: Session = Depends(get_db),
):
    """Restore a soft-deleted SBOM. Does not cascade — children must be
    restored individually. Phase 3.4 admin recovery surface."""
    sbom = db.execute(
        select(SBOMSource).where(SBOMSource.id == sbom_id).execution_options(include_deleted=True)
    ).scalar_one_or_none()
    if sbom is None:
        raise HTTPException(status_code=404, detail="SBOM not found")
    if sbom.is_active:
        return {"status": "already_active", "id": sbom_id}

    SoftDeleteService(db).restore(sbom)
    db.commit()
    audit_log.record(
        db,
        user_id=user_id,
        action="sbom.restore",
        target_kind="sbom",
        target_id=sbom_id,
    )
    return {"status": "restored", "id": sbom_id}


@router.post("/sboms/{sbom_id}/revalidate", response_model=SBOMSourceOut)
def revalidate_sbom(
    sbom_id: int = Path(..., description="SBOM ID (positive integer)"),
    db: Session = Depends(get_db),
):
    """Re-run the 8-stage validator against the stored ``sbom_data``.

    Brings legacy rows (uploaded before validation was wired into
    ``create_sbom``) onto the same status convention as freshly-uploaded
    rows. The endpoint is also a generic idempotent revalidation hook —
    re-running is safe and produces the same result for any given body.

    Response shape mirrors :func:`create_sbom`: 200 with
    :class:`SBOMSourceOut` on a clean report, or 4xx with the structured
    ``detail`` (sbom_id, status, failed_stage, entries, …) when the
    report carries any error-severity entry. NTIA-only warnings keep
    ``status='validated'`` and return 200 with ``warning_count > 0``.
    """
    sbom_id = _validate_positive_int(sbom_id, param_name="sbom_id")
    sbom = db.get(SBOMSource, sbom_id)
    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")

    body = sbom.sbom_data
    if not body:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "sbom_data_missing",
                "message": (
                    "Cannot revalidate this SBOM — no document body is stored "
                    "on the row. Re-upload the SBOM to populate it."
                ),
            },
        )

    raw = body.encode("utf-8") if isinstance(body, str) else bytes(body)
    report = run_validation(raw)
    sbom_status = _classify_status(report)
    serialized_entries = [e.model_dump() for e in report.entries] if report.entries else None

    sbom.status = sbom_status
    sbom.failed_stage = report.first_error_stage
    sbom.validation_errors = serialized_entries
    sbom.error_count = report.error_count
    sbom.warning_count = report.warning_count
    sbom.validated_at = now_iso()

    try:
        db.add(sbom)
        db.commit()
        db.refresh(sbom)
    except SQLAlchemyError as exc:
        db.rollback()
        log.error("revalidate_sbom DB error sbom_id=%d: %s", sbom_id, exc, exc_info=True)
        raise HTTPException(
            status_code=500,
            detail={"code": "db_error", "message": "Failed to persist revalidation."},
        ) from exc

    log.info(
        "SBOM revalidated: id=%d name='%s' status=%s errors=%d warnings=%d",
        sbom_id,
        sbom.sbom_name,
        sbom_status,
        report.error_count,
        report.warning_count,
    )

    if report.has_errors():
        raise _validation_failure_response(int(sbom.id), report, str(sbom.sbom_name))

    return sbom


@router.post("/sboms/{sbom_id}/analyze", response_model=AnalysisRunOut, status_code=status.HTTP_201_CREATED)
@analyze_route_limit
async def run_analysis_for_sbom(
    request: Request,
    sbom_id: int,
    force_refresh: bool = Query(
        False,
        description=(
            "Roadmap #2 PR-E — scan fresh. When True AND the source-response "
            "cache is enabled, external-source fetches IGNORE cached hits "
            "(query upstream live) but still write the fresh result, "
            "refreshing the cache for next time. Scheduled scans default "
            "False; only operator-driven 're-scan now' flows should pass "
            "True. No-op when the cache flag is off."
        ),
    ),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
):
    async def _execute() -> dict:
        log.info(
            "Manual analysis triggered for SBOM id=%d (force_refresh=%s)",
            sbom_id,
            force_refresh,
        )
        sbom = db.get(SBOMSource, sbom_id)
        if not sbom:
            log.warning("Analysis requested for unknown SBOM id=%d", sbom_id)
            raise HTTPException(status_code=404, detail="SBOM not found")
        try:
            report = await create_auto_report(db, sbom, force_refresh=force_refresh)
        except Exception as exc:
            db.rollback()
            log.error("Analysis run failed for SBOM id=%d: %s", sbom_id, exc, exc_info=True)
            raise HTTPException(status_code=500, detail="Unable to generate analysis report") from exc
        if not report:
            log.error("Analysis report generation failed for SBOM id=%d", sbom_id)
            raise HTTPException(status_code=500, detail="Unable to generate analysis report")
        return analysis_run_to_dict(report)

    key = normalize_idempotency_key(idempotency_key)
    if key:
        data = await run_idempotent(f"post_analyze:{sbom_id}", key, _execute)
    else:
        data = await _execute()
    return AnalysisRunOut.model_validate(data)


@router.post("/sboms/{sbom_id}/analyze/stream")
@analyze_route_limit
async def analyze_sbom_stream(
    request: Request,
    sbom_id: int,
    payload: AnalyzeStreamPayload,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
):
    """
    Run multi-source SBOM analysis and stream per-source progress via SSE.

    SSE event types:
      progress  — phase/source status updates (started, parsed, running, complete, error)
      complete  — final result with runId + severity counts
      error     — fatal error (SBOM not found, parse failure, etc.)
    """
    idem = normalize_idempotency_key(idempotency_key)
    sbom_row = db.get(SBOMSource, sbom_id)

    async def _stream_not_found():
        yield _sse_event("error", {"message": f"SBOM {sbom_id} not found", "code": 404})

    if not sbom_row:
        return StreamingResponse(
            _stream_not_found(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    if idem:
        cached_complete = await get_cached(f"analyze_stream:{sbom_id}", idem)
        if cached_complete:

            async def _replay_cached():
                yield _sse_event("complete", cached_complete)

            return StreamingResponse(
                _replay_cached(),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "X-Accel-Buffering": "no",
                    "Connection": "keep-alive",
                },
            )

    async def event_stream():
        started_at = time.perf_counter()

        def elapsed() -> int:
            return int((time.perf_counter() - started_at) * 1000)

        try:
            cfg = get_analysis_settings_multi()

            sources = normalize_source_names(payload.sources, default=configured_default_sources())

            yield _sse_event(
                "progress",
                {
                    "phase": "started",
                    "sources": sources,
                    "elapsed_ms": elapsed(),
                },
            )
            await asyncio.sleep(0)

            try:
                sbom_data = sbom_row.sbom_data or ""
                components_raw = extract_components(sbom_data)
                components_raw = [enrich_component_for_osv(c) for c in components_raw]
                components, _gen_cpe = _augment_components_with_cpe(components_raw)
            except Exception as exc:
                yield _sse_event("error", {"message": f"SBOM parse failed: {exc}", "code": 400})
                return

            yield _sse_event(
                "progress",
                {
                    "phase": "parsed",
                    "components": len(components),
                    "elapsed_ms": elapsed(),
                },
            )
            await asyncio.sleep(0)

            # Build per-request VulnSource adapter instances. Credentials are
            # bound at construction time so the request handler never mutates
            # process-global environment.
            active_adapters = build_source_adapters(sources)

            # Fan out concurrently via the shared runner. SSE progress events
            # are forwarded as soon as the runner emits them, preserving the
            # streaming contract while killing the inline source-dispatch loop.
            all_findings: list[dict] = []
            all_errors: list[dict] = []
            all_warnings: list[dict] = []
            event_queue: asyncio.Queue = asyncio.Queue()

            async def _drive_runner() -> None:
                f, e, _w = await run_sources_concurrently(
                    sources=active_adapters,
                    components=components,
                    settings=cfg,
                    progress_queue=event_queue,
                )
                # Stash final aggregates on the queue itself so the consumer
                # loop below can pick them up after EVENT_DONE.
                all_findings.extend(f)
                all_errors.extend(e)
                all_warnings.extend(_w)

            orchestrator = asyncio.create_task(_drive_runner())

            try:
                while True:
                    msg = await event_queue.get()
                    kind = msg.get("kind")
                    if kind == EVENT_DONE:
                        break
                    if kind == EVENT_RUNNING:
                        yield _sse_event(
                            "progress",
                            {
                                "source": msg["source"],
                                "status": "running",
                                "elapsed_ms": elapsed(),
                            },
                        )
                    elif kind == EVENT_COMPLETE:
                        yield _sse_event(
                            "progress",
                            {
                                "source": msg["source"],
                                "status": "complete",
                                "findings": msg["findings"],
                                "errors": msg["errors"],
                                "source_ms": msg["source_ms"],
                                "elapsed_ms": elapsed(),
                            },
                        )
                    elif kind == EVENT_ERROR:
                        yield _sse_event(
                            "progress",
                            {
                                "source": msg["source"],
                                "status": "error",
                                "error": msg["error"],
                                "source_ms": msg["source_ms"],
                                "elapsed_ms": elapsed(),
                            },
                        )
                    await asyncio.sleep(0)
            finally:
                if not orchestrator.done():
                    orchestrator.cancel()
                    try:
                        await orchestrator
                    except (asyncio.CancelledError, Exception):
                        pass

            # Make sure the orchestrator task finished cleanly so its
            # `all_findings`/`all_errors` mutations are visible.
            if orchestrator.done() and not orchestrator.cancelled():
                # Surface any unhandled exception from inside _drive_runner.
                orchestrator.result()

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
                "analysis_metadata": {
                    "sources": sources,
                    "provider_status": [
                        warning["provider_status"]
                        for warning in all_warnings
                        if isinstance(warning, dict) and isinstance(warning.get("provider_status"), dict)
                    ],
                },
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

            complete_payload = {
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
                "provider_status": details["analysis_metadata"]["provider_status"],
            }
            if idem:
                put_cached(f"analyze_stream:{sbom_id}", idem, complete_payload)
            yield _sse_event("complete", complete_payload)

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
