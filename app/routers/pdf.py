"""
PDF Report Generation router.

Routes:
  POST /api/pdf-report  generate PDF from run ID
"""
import json
import logging
from typing import Optional, Dict, Any
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import AnalysisRun, AnalysisFinding, SBOMSource
from ..pdf_report import build_pdf_from_run_bytes

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["pdf"])


class PdfReportByIdRequest(BaseModel):
    runId: int
    title: Optional[str] = "SBOM Vulnerability Report"
    filename: Optional[str] = "sbom_report.pdf"


def _rebuild_run_from_db(db: Session, run_id: int) -> Optional[dict]:
    """
    Reconstruct a consolidated-style run dict from AnalysisRun + AnalysisFinding
    rows. This is the fallback when RunCache has no entry (e.g. runs created by
    the multi-source auto-analysis path which writes to analysis_run/finding but
    not to run_cache).
    """
    run_row: Optional[AnalysisRun] = db.get(AnalysisRun, run_id)
    if run_row is None:
        return None

    findings = (
        db.query(AnalysisFinding)
        .filter(AnalysisFinding.analysis_run_id == run_id)
        .all()
    )

    sbom_row = db.get(SBOMSource, run_row.sbom_id) if run_row.sbom_id else None

    # Group findings by component name+version
    comp_map: dict[str, dict] = {}
    for f in findings:
        key = f"{f.component_name or ''}||{f.component_version or ''}"
        if key not in comp_map:
            comp_map[key] = {
                "name": f.component_name or "",
                "version": f.component_version or "",
                "purl": None,
                "cpe": f.cpe,
                "combined": [],
            }
        aliases = []
        if f.aliases:
            try:
                aliases = json.loads(f.aliases)
            except (json.JSONDecodeError, TypeError):
                pass
        sources = [s.strip() for s in (f.source or "").split(",") if s.strip()]
        comp_map[key]["combined"].append({
            "id": f.vuln_id,
            "severity": (f.severity or "UNKNOWN").upper(),
            "score": f.score,
            "vector": f.vector,
            "published": f.published_on,
            "url": f.reference_url,
            "sources": sources,
            "aliases": aliases,
            "description": f.description,
            "cwe": [c.strip() for c in (f.cwe or "").split(",") if c.strip()],
            "attack_vector": f.attack_vector,
            "fixed_versions": json.loads(f.fixed_versions) if f.fixed_versions else [],
        })
        # Inherit CPE from finding if component-level is missing
        if not comp_map[key]["cpe"] and f.cpe:
            comp_map[key]["cpe"] = f.cpe

    components = list(comp_map.values())

    sev_counts = {
        "CRITICAL": run_row.critical_count or 0,
        "HIGH": run_row.high_count or 0,
        "MEDIUM": run_row.medium_count or 0,
        "LOW": run_row.low_count or 0,
        "UNKNOWN": run_row.unknown_count or 0,
    }

    return {
        "status": run_row.run_status,
        "sbom": {
            "id": run_row.sbom_id,
            "name": (sbom_row.sbom_name if sbom_row else None) or f"SBOM #{run_row.sbom_id}",
        },
        "summary": {
            "components": run_row.total_components or len(components),
            "withCPE": run_row.components_with_cpe or 0,
            "findings": {"total": run_row.total_findings or len(findings), "bySeverity": sev_counts},
            "errors": run_row.query_error_count or 0,
            "durationMs": run_row.duration_ms or 0,
            "completedOn": run_row.completed_on,
        },
        "components": components,
    }


@router.post("/pdf-report", response_class=None)
async def create_pdf_report_by_run_id(
    payload: PdfReportByIdRequest,
    db: Session = Depends(get_db),
):
    """
    Accepts JSON with { runId, title?, filename? }.
    Loads the run from the database, generates a PDF and returns it as a download.
    Tries RunCache first; falls back to reconstructing from AnalysisRun + findings.
    """
    from fastapi.responses import Response
    from ..services.pdf_service import load_run_cache

    log.info("PDF report requested: run_id=%d filename=%s", payload.runId, payload.filename)
    run_id = payload.runId

    # 1. Try RunCache (populated by ad-hoc consolidated endpoint)
    run = load_run_cache(db, run_id)

    # 2. Fallback: reconstruct from AnalysisRun + AnalysisFinding tables
    if run is None:
        log.info("PDF report: run_id=%d not in cache, rebuilding from DB", run_id)
        run = _rebuild_run_from_db(db, run_id)

    if run is None:
        log.warning("PDF report: run_id=%d not found anywhere", run_id)
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found.")

    filename = payload.filename or "sbom_report.pdf"
    if not filename.lower().endswith(".pdf"):
        filename = f"{filename}.pdf"

    title = payload.title or "SBOM Vulnerability Report"

    try:
        pdf_bytes = build_pdf_from_run_bytes(run, title=title)
        log.info("PDF generated: run_id=%d size=%d bytes", run_id, len(pdf_bytes))
    except Exception as e:
        log.error("PDF generation failed: run_id=%d error=%s", run_id, e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {e}")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
