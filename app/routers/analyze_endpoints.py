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

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import get_db
from ..deprecation import LEGACY_ANALYSIS_SUNSET, mark_deprecated
from ..idempotency import normalize_idempotency_key, run_idempotent
from ..models import AnalysisRun
from ..rate_limit import analyze_route_limit
from ..services.analysis_orchestrator import AnalysisOrchestrator
from ..settings import get_settings

DEFAULT_RESULTS_PER_PAGE = get_settings().DEFAULT_RESULTS_PER_PAGE

log = logging.getLogger(__name__)

router = APIRouter(tags=["analyze"])


def _already_running_response(run: AnalysisRun) -> dict:
    return {
        "status": "already_running",
        "run_status": run.run_status,
        "run_id": run.id,
        "runId": run.id,
        "id": run.id,
        "sbom_id": run.sbom_id,
        "sbom_name": run.sbom_name,
        "project_id": run.project_id,
        "product_id": run.product_id,
        "product_name": run.product_name,
        "source": run.source,
        "trigger_source": run.trigger_source,
        "message": "Analysis is already running for this SBOM.",
        "started_on": run.started_on,
        "completed_on": run.completed_on,
        "duration_ms": run.duration_ms,
        "total_components": run.total_components,
        "components_with_cpe": run.components_with_cpe,
        "total_findings": run.total_findings,
        "critical_count": run.critical_count,
        "high_count": run.high_count,
        "medium_count": run.medium_count,
        "low_count": run.low_count,
        "unknown_count": run.unknown_count,
        "query_error_count": run.query_error_count,
    }


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
    orchestrator = AnalysisOrchestrator(db)
    try:
        sbom_row, sbom_format, spec_version = orchestrator.resolve_sbom(
            sbom_id=sbom_id,
            sbom_name=sbom_name,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    outcome = await orchestrator.run(sbom_row, sources=sources_list, trigger_source="api")
    if outcome is None:
        raise HTTPException(status_code=400, detail="No components detected in SBOM.")
    run, execution = outcome
    if execution is None:
        return _already_running_response(run)
    details = execution.details
    buckets = execution.buckets
    completed_on = run.completed_on
    duration_ms = int(run.duration_ms or 0)
    return {
        "id": run.id,
        "runId": run.id,
        "sbom_id": sbom_row.id,
        "sbom_name": sbom_row.sbom_name,
        "project_id": sbom_row.projectid,
        "product_id": sbom_row.product_id,
        "product_name": sbom_row.product_name,
        "run_status": run.run_status,
        "status": run.run_status,
        "source": run.source,
        "trigger_source": "api",
        "started_on": run.started_on,
        "completed_on": completed_on,
        "duration_ms": duration_ms,
        "total_components": run.total_components,
        "components_with_cpe": run.components_with_cpe,
        "total_findings": run.total_findings,
        "critical_count": run.critical_count,
        "high_count": run.high_count,
        "medium_count": run.medium_count,
        "low_count": run.low_count,
        "unknown_count": run.unknown_count,
        "query_error_count": run.query_error_count,
        **(
            {"provider_status": details["analysis_metadata"]["provider_status"]}
            if details["analysis_metadata"]["provider_status"]
            else {}
        ),
        "sbom": {
            "id": sbom_row.id,
            "name": sbom_row.sbom_name,
            "format": sbom_format,
            "specVersion": spec_version,
        },
        "summary": {
            "components": run.total_components,
            "withCPE": run.components_with_cpe,
            "findings": {"total": run.total_findings, "bySeverity": buckets},
            "errors": run.query_error_count,
            "durationMs": duration_ms,
            "completedOn": completed_on,
        },
    }


# ---- NVD ------------------------------------------------------------------


@router.post("/analyze-sbom-nvd", deprecated=True)
@analyze_route_limit
async def analyze_sbom_nvd(
    request: Request,
    response: Response,
    payload: AnalysisByRefNVD = Body(...),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
):
    """Run NVD-only analysis on an SBOM (by id or name)."""
    if payload.sbom_id is None and not (payload.sbom_name and payload.sbom_name.strip()):
        raise HTTPException(status_code=422, detail="Provide 'sbom_id' or 'sbom_name' in request body")
    log.info("NVD analysis started: sbom_id=%s sbom_name=%s", payload.sbom_id, payload.sbom_name)

    async def _inner() -> dict:
        result = await _run_legacy_analysis(
            db,
            sbom_id=payload.sbom_id,
            sbom_name=payload.sbom_name,
            sources_list=["NVD"],
        )
        successor = f"/api/sboms/{result['sbom_id']}/analyze"
        mark_deprecated(
            response,
            endpoint="POST /analyze-sbom-nvd",
            successor=successor,
            sunset=LEGACY_ANALYSIS_SUNSET,
        )
        return result

    key = normalize_idempotency_key(idempotency_key)
    scope = f"legacy_nvd:{payload.sbom_id}:{payload.sbom_name or ''}"
    if key:
        return await run_idempotent(scope, key, _inner)
    return await _inner()


# ---- GitHub Advisories ----------------------------------------------------


@router.post("/analyze-sbom-github", deprecated=True)
@analyze_route_limit
async def analyze_sbom_github(
    request: Request,
    response: Response,
    payload: AnalysisByRefGitHub = Body(...),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
):
    """Run GitHub Security Advisory analysis on an SBOM (by id or name)."""
    if payload.sbom_id is None and not (payload.sbom_name and payload.sbom_name.strip()):
        raise HTTPException(status_code=422, detail="Provide 'sbom_id' or 'sbom_name' in request body")
    log.info("GHSA analysis started: sbom_id=%s sbom_name=%s", payload.sbom_id, payload.sbom_name)

    async def _inner() -> dict:
        result = await _run_legacy_analysis(
            db,
            sbom_id=payload.sbom_id,
            sbom_name=payload.sbom_name,
            sources_list=["GITHUB"],
        )
        mark_deprecated(
            response,
            endpoint="POST /analyze-sbom-github",
            successor=f"/api/sboms/{result['sbom_id']}/analyze",
            sunset=LEGACY_ANALYSIS_SUNSET,
        )
        return result

    key = normalize_idempotency_key(idempotency_key)
    scope = f"legacy_github:{payload.sbom_id}:{payload.sbom_name or ''}"
    if key:
        return await run_idempotent(scope, key, _inner)
    return await _inner()


# ---- OSV ------------------------------------------------------------------


@router.post("/analyze-sbom-osv", deprecated=True)
@analyze_route_limit
async def analyze_sbom_osv(
    request: Request,
    response: Response,
    payload: AnalysisByRefOSV = Body(...),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
):
    """Run OSV analysis on an SBOM (by id or name)."""
    if payload.sbom_id is None and not (payload.sbom_name and payload.sbom_name.strip()):
        raise HTTPException(status_code=422, detail="Provide 'sbom_id' or 'sbom_name' in request body")
    log.info("OSV analysis started: sbom_id=%s sbom_name=%s", payload.sbom_id, payload.sbom_name)

    async def _inner() -> dict:
        result = await _run_legacy_analysis(
            db,
            sbom_id=payload.sbom_id,
            sbom_name=payload.sbom_name,
            sources_list=["OSV"],
        )
        mark_deprecated(
            response,
            endpoint="POST /analyze-sbom-osv",
            successor=f"/api/sboms/{result['sbom_id']}/analyze",
            sunset=LEGACY_ANALYSIS_SUNSET,
        )
        return result

    key = normalize_idempotency_key(idempotency_key)
    scope = f"legacy_osv:{payload.sbom_id}:{payload.sbom_name or ''}"
    if key:
        return await run_idempotent(scope, key, _inner)
    return await _inner()


# ---- VulDB / VulnDB --------------------------------------------------------


@router.post("/analyze-sbom-vulndb", deprecated=True)
@analyze_route_limit
async def analyze_sbom_vulndb(
    request: Request,
    response: Response,
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
        result = await _run_legacy_analysis(
            db,
            sbom_id=payload.sbom_id,
            sbom_name=payload.sbom_name,
            sources_list=["VULNDB"],
        )
        mark_deprecated(
            response,
            endpoint="POST /analyze-sbom-vulndb",
            successor=f"/api/sboms/{result['sbom_id']}/analyze",
            sunset=LEGACY_ANALYSIS_SUNSET,
        )
        return result

    key = normalize_idempotency_key(idempotency_key)
    scope = f"legacy_vulndb:{payload.sbom_id}:{payload.sbom_name or ''}"
    if key:
        return await run_idempotent(scope, key, _inner)
    return await _inner()


# ---- Consolidated (NVD + GHSA + OSV + VulDB) -------------------------------


@router.post("/analyze-sbom-consolidated", deprecated=True)
@analyze_route_limit
async def analyze_sbom_consolidated(
    request: Request,
    response: Response,
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
        result = await _run_legacy_analysis(
            db,
            sbom_id=payload.sbom_id,
            sbom_name=payload.sbom_name,
            sources_list=["NVD", "OSV", "GITHUB", "VULNDB"],
        )
        mark_deprecated(
            response,
            endpoint="POST /analyze-sbom-consolidated",
            successor=f"/api/sboms/{result['sbom_id']}/analyze",
            sunset=LEGACY_ANALYSIS_SUNSET,
        )
        return result

    key = normalize_idempotency_key(idempotency_key)
    scope = f"legacy_consolidated:{payload.sbom_id}:{payload.sbom_name or ''}"
    if key:
        return await run_idempotent(scope, key, _inner)
    return await _inner()
