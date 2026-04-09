"""
Ad-hoc analysis endpoints — single-source and consolidated.

Routes:
  POST /analyze-sbom-nvd             NVD-only analysis
  POST /analyze-sbom-github          GitHub Advisory analysis
  POST /analyze-sbom-osv             OSV analysis
  POST /analyze-sbom-consolidated    Combined NVD + GHSA + OSV analysis

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

from __future__ import annotations

import logging
import time
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import get_db
from ..settings import get_settings
from ..services.sbom_service import now_iso, load_sbom_from_ref as _load_sbom_from_ref
from ..analysis import (
    get_analysis_settings_multi,
    enrich_component_for_osv,
    _augment_components_with_cpe,
    deduplicate_findings,
)
from ..sources import (
    NvdSource,
    OsvSource,
    GhsaSource,
    run_sources_concurrently,
)
from .sboms_crud import persist_analysis_run, compute_report_status

DEFAULT_RESULTS_PER_PAGE = get_settings().DEFAULT_RESULTS_PER_PAGE

log = logging.getLogger(__name__)

router = APIRouter(tags=["analyze"])


# ---- Request models -------------------------------------------------------

class AnalysisByRefNVD(BaseModel):
    sbom_id: Optional[int] = None
    sbom_name: Optional[str] = None
    nvd_api_key: Optional[str] = None
    results_per_page: int = DEFAULT_RESULTS_PER_PAGE


class AnalysisByRefGitHub(BaseModel):
    sbom_id: Optional[int] = None
    sbom_name: Optional[str] = None
    github_token: Optional[str] = None  # falls back to env if None
    first: int = 100


class AnalysisByRefOSV(BaseModel):
    sbom_id: Optional[int] = None
    sbom_name: Optional[str] = None
    hydrate: bool = True


class AnalysisByRefConsolidated(BaseModel):
    sbom_id: Optional[int] = None
    sbom_name: Optional[str] = None
    nvd_api_key: Optional[str] = None
    results_per_page: int = DEFAULT_RESULTS_PER_PAGE
    github_token: Optional[str] = None
    first: int = 100
    osv_hydrate: bool = True


# ---- Shared runner --------------------------------------------------------

async def _run_legacy_analysis(
    db: Session,
    *,
    sbom_id: Optional[int],
    sbom_name: Optional[str],
    sources_list: List[str],
    nvd_api_key: Optional[str] = None,
    github_token: Optional[str] = None,
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
    adapter_map = {
        "NVD": lambda: NvdSource(api_key=nvd_api_key),
        "OSV": lambda: OsvSource(),
        "GITHUB": lambda: GhsaSource(token=github_token),
    }
    adapters = [adapter_map[name]() for name in sources_list if name in adapter_map]
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
async def analyze_sbom_nvd(payload: AnalysisByRefNVD, db: Session = Depends(get_db)):
    """Run NVD-only analysis on an SBOM (by id or name)."""
    if payload.sbom_id is None and not (payload.sbom_name and payload.sbom_name.strip()):
        raise HTTPException(status_code=422, detail="Provide 'sbom_id' or 'sbom_name' in request body")
    log.info("NVD analysis started: sbom_id=%s sbom_name=%s", payload.sbom_id, payload.sbom_name)
    return await _run_legacy_analysis(
        db,
        sbom_id=payload.sbom_id,
        sbom_name=payload.sbom_name,
        sources_list=["NVD"],
        nvd_api_key=payload.nvd_api_key,
    )


# ---- GitHub Advisories ----------------------------------------------------

@router.post("/analyze-sbom-github")
async def analyze_sbom_github(payload: AnalysisByRefGitHub, db: Session = Depends(get_db)):
    """Run GitHub Security Advisory analysis on an SBOM (by id or name)."""
    if payload.sbom_id is None and not (payload.sbom_name and payload.sbom_name.strip()):
        raise HTTPException(status_code=422, detail="Provide 'sbom_id' or 'sbom_name' in request body")
    log.info("GHSA analysis started: sbom_id=%s sbom_name=%s", payload.sbom_id, payload.sbom_name)
    return await _run_legacy_analysis(
        db,
        sbom_id=payload.sbom_id,
        sbom_name=payload.sbom_name,
        sources_list=["GITHUB"],
        github_token=payload.github_token,
    )


# ---- OSV ------------------------------------------------------------------

@router.post("/analyze-sbom-osv")
async def analyze_sbom_osv(payload: AnalysisByRefOSV, db: Session = Depends(get_db)):
    """Run OSV analysis on an SBOM (by id or name)."""
    if payload.sbom_id is None and not (payload.sbom_name and payload.sbom_name.strip()):
        raise HTTPException(status_code=422, detail="Provide 'sbom_id' or 'sbom_name' in request body")
    log.info("OSV analysis started: sbom_id=%s sbom_name=%s", payload.sbom_id, payload.sbom_name)
    return await _run_legacy_analysis(
        db,
        sbom_id=payload.sbom_id,
        sbom_name=payload.sbom_name,
        sources_list=["OSV"],
    )


# ---- Consolidated (NVD + GHSA + OSV) --------------------------------------

@router.post("/analyze-sbom-consolidated")
async def analyze_sbom_consolidated(payload: AnalysisByRefConsolidated, db: Session = Depends(get_db)):
    """Run consolidated analysis (NVD + GHSA + OSV) on an SBOM (by id or name)."""
    if payload.sbom_id is None and not (payload.sbom_name and payload.sbom_name.strip()):
        raise HTTPException(status_code=422, detail="Provide 'sbom_id' or 'sbom_name' in request body")
    log.info(
        "Consolidated analysis started (NVD+GHSA+OSV): sbom_id=%s sbom_name=%s",
        payload.sbom_id,
        payload.sbom_name,
    )
    return await _run_legacy_analysis(
        db,
        sbom_id=payload.sbom_id,
        sbom_name=payload.sbom_name,
        sources_list=["NVD", "OSV", "GITHUB"],
        nvd_api_key=payload.nvd_api_key,
        github_token=payload.github_token,
    )
