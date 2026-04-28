"""
Ad-hoc analysis endpoints — single-source and consolidated.

Routes:
  POST /analyze-sbom-nvd             NVD-only analysis
  POST /analyze-sbom-github          GitHub Advisory analysis
  POST /analyze-sbom-osv             OSV analysis
  POST /analyze-sbom-vulndb          VulDB / VulnDB analysis
  POST /analyze-sbom-consolidated    Combined NVD + GHSA + OSV + VulDB analysis

Architecture
------------
All four endpoints are thin wrappers around a single shared helper
``_run_legacy_analysis`` that:

  1. Builds the requested ``VulnSource`` adapter(s) with constructor-bound
     credentials (no ``os.environ`` mutation, no ``dataclass_replace``
     plumbing).
  2. Fans them out concurrently via ``run_sources_concurrently``.
  3. Persists the resulting findings into ``AnalysisRun``/``AnalysisFinding``
     using the same ``persist_analysis_run`` helper that
     ``POST /api/sboms/{id}/analyze`` uses, so dashboard / runs / findings
     endpoints all see the same data.
  4. Returns the flat ``AnalysisRunOut``-shaped dict that the frontend's
     ``ConsolidatedAnalysisResult`` type already expects, plus a legacy
     ``summary.findings.bySeverity`` block so the defensive reader in
     ``frontend/src/hooks/useBackgroundAnalysis.ts:65`` keeps working.
"""

import logging
import time

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..analysis import (
    _augment_components_with_cpe,
    deduplicate_findings,
    enrich_component_for_osv,
    get_analysis_settings_multi,
)
from ..db import get_db
from ..idempotency import normalize_idempotency_key, run_idempotent
from ..rate_limit import analyze_route_limit
from ..services.sbom_service import load_sbom_from_ref as _load_sbom_from_ref
from ..services.sbom_service import now_iso
from ..settings import get_settings
from ..sources import (
    build_source_adapters,
    run_sources_concurrently,
)
from ..services.analysis_service import compute_report_status, persist_analysis_run

DEFAULT_RESULTS_PER_PAGE = get_settings().DEFAULT_RESULTS_PER_PAGE

log = logging.getLogger(__name__)

router = APIRouter(tags=["analyze"])


# ---- Request models -------------------------------------------------------


class AnalysisByRefNVD(BaseModel):
    sbom_id: int | None = None
    sbom_name: str | None = None
    results_per_page: int = DEFAULT_RESULTS_PER_PAGE


class AnalysisByRefGitHub(BaseModel):
    sbom_id: int | None = None
    sbom_name: str | None = None
    first: int = 100


class AnalysisByRefOSV(BaseModel):
    sbom_id: int | None = None
    sbom_name: str | None = None
    hydrate: bool = True


class AnalysisByRefVulnDb(BaseModel):
    sbom_id: int | None = None
    sbom_name: str | None = None


class AnalysisByRefConsolidated(BaseModel):
    sbom_id: int | None = None
    sbom_name: str | None = None
    results_per_page: int = DEFAULT_RESULTS_PER_PAGE
    first: int = 100
    osv_hydrate: bool = True


# ---- Shared runner --------------------------------------------------------


async def _run_legacy_analysis(
    db: Session,
    *,
    sbom_id: int | None,
    sbom_name: str | None,
    sources_list: list[str],
) -> dict:
    """
    Shared body for the four legacy ad-hoc endpoints.

    Loads the SBOM by id/name, builds the requested adapters with their
    bound credentials, fans them out concurrently, persists the resulting
    run, and returns a flat dict that satisfies BOTH the new
    ``AnalysisRunOut`` consumers AND the legacy
    ``summary.findings.bySeverity`` defensive readers.
    """
    # 1. Load + parse the SBOM
    try:
        sbom_row, _, sbom_format, spec_version, raw_components = _load_sbom_from_ref(
            db, sbom_id=sbom_id, sbom_name=sbom_name
        )
    except ValueError as exc:
        # _load_sbom_from_ref raises ValueError for missing / invalid SBOMs.
        raise HTTPException(status_code=404, detail=str(exc))

    if not raw_components:
        raise HTTPException(status_code=400, detail="No components detected in SBOM.")

    # 2. CPE augmentation + OSV enrichment so the adapters get the same
    #    component shape that the production multi-source path uses.
    enriched = [enrich_component_for_osv(c) for c in raw_components]
    components, _generated_cpe = _augment_components_with_cpe(enriched)

    # 3. Build per-request adapters. Credentials are bound at construction
    #    time so the request handler never has to mutate os.environ.
    adapters = build_source_adapters(sources_list)
    if not adapters:
        raise HTTPException(
            status_code=400,
            detail=f"No supported sources requested. Got {sources_list!r}.",
        )

    # 4. Fan out concurrently via the registry runner.
    started_on = now_iso()
    started_at = time.perf_counter()

    cfg = get_analysis_settings_multi()
    raw_findings, query_errors, _query_warnings = await run_sources_concurrently(
        sources=adapters,
        components=components,
        settings=cfg,
    )

    # 5. Two-pass CVE↔GHSA dedupe (same pass production uses).
    final_findings = deduplicate_findings(raw_findings)

    buckets = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for f in final_findings:
        sev = str((f or {}).get("severity", "UNKNOWN")).upper()
        buckets[sev if sev in buckets else "UNKNOWN"] += 1

    details = {
        "total_components": len(components),
        "components_with_cpe": sum(1 for c in components if c.get("cpe")),
        "total_findings": len(final_findings),
        "critical": buckets["CRITICAL"],
        "high": buckets["HIGH"],
        "medium": buckets["MEDIUM"],
        "low": buckets["LOW"],
        "unknown": buckets["UNKNOWN"],
        "query_errors": query_errors,
        "findings": final_findings,
        "analysis_metadata": {"sources": sources_list},
    }

    run_status = compute_report_status(len(final_findings), query_errors)
    source_label = ",".join(sources_list)
    if query_errors:
        source_label += " (partial)"

    duration_ms = int((time.perf_counter() - started_at) * 1000)
    completed_on = now_iso()

    # 6. Persist into AnalysisRun + AnalysisFinding (the same path the
    #    production endpoint uses). The PDF endpoint already falls back
    #    from RunCache to AnalysisRun via `rebuild_run_from_db`, so PDF
    #    generation continues to work.
    run = persist_analysis_run(
        db=db,
        sbom_obj=sbom_row,
        details=details,
        components=components,
        run_status=run_status,
        source=source_label,
        started_on=started_on,
        completed_on=completed_on,
        duration_ms=duration_ms,
    )
    db.commit()

    log.info(
        "Legacy analysis complete: sources=%s sbom='%s' components=%d findings=%d "
        "errors=%d status=%s duration=%dms run_id=%d",
        sources_list,
        sbom_row.sbom_name,
        len(components),
        len(final_findings),
        len(query_errors),
        run_status,
        duration_ms,
        run.id,
    )

    # 7. Build the response shape — flat AnalysisRunOut fields PLUS the
    #    legacy ``sbom``/``summary`` blocks the frontend's defensive reader
    #    falls back to.
    return {
        # Flat fields — primary contract for ConsolidatedAnalysisResult
        "id": run.id,
        "runId": run.id,  # legacy alias
        "sbom_id": sbom_row.id,
        "sbom_name": sbom_row.sbom_name,
        "project_id": sbom_row.projectid,
        "run_status": run_status,
        "status": run_status,  # legacy alias
        "source": source_label,
        "started_on": started_on,
        "completed_on": completed_on,
        "duration_ms": duration_ms,
        "total_components": details["total_components"],
        "components_with_cpe": details["components_with_cpe"],
        "total_findings": details["total_findings"],
        "critical_count": buckets["CRITICAL"],
        "high_count": buckets["HIGH"],
        "medium_count": buckets["MEDIUM"],
        "low_count": buckets["LOW"],
        "unknown_count": buckets["UNKNOWN"],
        "query_error_count": len(query_errors),
        # Legacy compatibility blocks (read by useBackgroundAnalysis.ts:65)
        "sbom": {
            "id": sbom_row.id,
            "name": sbom_row.sbom_name,
            "format": sbom_format,
            "specVersion": spec_version,
        },
        "summary": {
            "components": details["total_components"],
            "withCPE": details["components_with_cpe"],
            "findings": {
                "total": details["total_findings"],
                "bySeverity": buckets,
            },
            "errors": len(query_errors),
            "durationMs": duration_ms,
            "completedOn": completed_on,
        },
    }


# ---- NVD ------------------------------------------------------------------


@router.post("/analyze-sbom-nvd")
@analyze_route_limit
async def analyze_sbom_nvd(
    request: Request,
    payload: AnalysisByRefNVD = Body(...),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
):
    """Run NVD-only analysis on an SBOM (by id or name)."""
    if payload.sbom_id is None and not (payload.sbom_name and payload.sbom_name.strip()):
        raise HTTPException(status_code=422, detail="Provide 'sbom_id' or 'sbom_name' in request body")
    log.info("NVD analysis started: sbom_id=%s sbom_name=%s", payload.sbom_id, payload.sbom_name)

    async def _inner() -> dict:
        return await _run_legacy_analysis(
            db,
            sbom_id=payload.sbom_id,
            sbom_name=payload.sbom_name,
            sources_list=["NVD"],
        )

    key = normalize_idempotency_key(idempotency_key)
    scope = f"legacy_nvd:{payload.sbom_id}:{payload.sbom_name or ''}"
    if key:
        return await run_idempotent(scope, key, _inner)
    return await _inner()


# ---- GitHub Advisories ----------------------------------------------------


@router.post("/analyze-sbom-github")
@analyze_route_limit
async def analyze_sbom_github(
    request: Request,
    payload: AnalysisByRefGitHub = Body(...),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
):
    """Run GitHub Security Advisory analysis on an SBOM (by id or name)."""
    if payload.sbom_id is None and not (payload.sbom_name and payload.sbom_name.strip()):
        raise HTTPException(status_code=422, detail="Provide 'sbom_id' or 'sbom_name' in request body")
    log.info("GHSA analysis started: sbom_id=%s sbom_name=%s", payload.sbom_id, payload.sbom_name)

    async def _inner() -> dict:
        return await _run_legacy_analysis(
            db,
            sbom_id=payload.sbom_id,
            sbom_name=payload.sbom_name,
            sources_list=["GITHUB"],
        )

    key = normalize_idempotency_key(idempotency_key)
    scope = f"legacy_github:{payload.sbom_id}:{payload.sbom_name or ''}"
    if key:
        return await run_idempotent(scope, key, _inner)
    return await _inner()


# ---- OSV ------------------------------------------------------------------


@router.post("/analyze-sbom-osv")
@analyze_route_limit
async def analyze_sbom_osv(
    request: Request,
    payload: AnalysisByRefOSV = Body(...),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
):
    """Run OSV analysis on an SBOM (by id or name)."""
    if payload.sbom_id is None and not (payload.sbom_name and payload.sbom_name.strip()):
        raise HTTPException(status_code=422, detail="Provide 'sbom_id' or 'sbom_name' in request body")
    log.info("OSV analysis started: sbom_id=%s sbom_name=%s", payload.sbom_id, payload.sbom_name)

    async def _inner() -> dict:
        return await _run_legacy_analysis(
            db,
            sbom_id=payload.sbom_id,
            sbom_name=payload.sbom_name,
            sources_list=["OSV"],
        )

    key = normalize_idempotency_key(idempotency_key)
    scope = f"legacy_osv:{payload.sbom_id}:{payload.sbom_name or ''}"
    if key:
        return await run_idempotent(scope, key, _inner)
    return await _inner()


# ---- VulDB / VulnDB --------------------------------------------------------


@router.post("/analyze-sbom-vulndb")
@analyze_route_limit
async def analyze_sbom_vulndb(
    request: Request,
    payload: AnalysisByRefVulnDb = Body(...),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
):
    """Run VulDB / VulnDB analysis on an SBOM (by id or name)."""
    if payload.sbom_id is None and not (payload.sbom_name and payload.sbom_name.strip()):
        raise HTTPException(status_code=422, detail="Provide 'sbom_id' or 'sbom_name' in request body")
    if not get_settings().vulndb_configured:
        raise HTTPException(status_code=400, detail="VULNDB_API_KEY is required for VulDB-only analysis.")
    log.info("VulDB analysis started: sbom_id=%s sbom_name=%s", payload.sbom_id, payload.sbom_name)

    async def _inner() -> dict:
        return await _run_legacy_analysis(
            db,
            sbom_id=payload.sbom_id,
            sbom_name=payload.sbom_name,
            sources_list=["VULNDB"],
        )

    key = normalize_idempotency_key(idempotency_key)
    scope = f"legacy_vulndb:{payload.sbom_id}:{payload.sbom_name or ''}"
    if key:
        return await run_idempotent(scope, key, _inner)
    return await _inner()


# ---- Consolidated (NVD + GHSA + OSV + VulDB) -------------------------------


@router.post("/analyze-sbom-consolidated")
@analyze_route_limit
async def analyze_sbom_consolidated(
    request: Request,
    payload: AnalysisByRefConsolidated = Body(...),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
):
    """Run consolidated analysis (NVD + GHSA + OSV + VulDB) on an SBOM (by id or name)."""
    if payload.sbom_id is None and not (payload.sbom_name and payload.sbom_name.strip()):
        raise HTTPException(status_code=422, detail="Provide 'sbom_id' or 'sbom_name' in request body")
    log.info(
        "Consolidated analysis started (NVD+GHSA+OSV+VulDB): sbom_id=%s sbom_name=%s",
        payload.sbom_id,
        payload.sbom_name,
    )

    async def _inner() -> dict:
        return await _run_legacy_analysis(
            db,
            sbom_id=payload.sbom_id,
            sbom_name=payload.sbom_name,
            sources_list=["NVD", "OSV", "GITHUB", "VULNDB"],
        )

    key = normalize_idempotency_key(idempotency_key)
    scope = f"legacy_consolidated:{payload.sbom_id}:{payload.sbom_name or ''}"
    if key:
        return await run_idempotent(scope, key, _inner)
    return await _inner()
