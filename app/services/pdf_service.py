"""
PDF Service Layer - PDF report generation from analysis runs.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC

from sqlalchemy.orm import Session

from ..models import AnalysisFinding, AnalysisRun, RunCache, SBOMSource
from ..pdf_report import build_pdf_from_run_bytes

log = logging.getLogger(__name__)


# ============================================================
# Run Cache Management
# ============================================================


def load_run_cache(db: Session, run_id: int) -> dict | None:
    """
    Load a previously persisted ad-hoc run from the cache, or return None.

    Args:
        db: Database session
        run_id: ID of the cached run to retrieve

    Returns:
        Parsed run dictionary, or None if not found or invalid
    """
    cache = db.get(RunCache, run_id)
    if cache is None:
        return None
    try:
        return json.loads(cache.run_json)
    except (json.JSONDecodeError, TypeError):
        log.warning("RunCache id=%d has invalid JSON", run_id)
        return None


def store_run_cache(db: Session, run_record: dict, source: str = "consolidated", sbom_id: int | None = None) -> int:
    """
    Persist an ad-hoc analysis run to the cache and return the DB-assigned ID.

    Args:
        db: Database session
        run_record: Run dictionary to persist
        source: Source identifier (consolidated, nvd, osv, ghsa)
        sbom_id: Optional SBOM ID for cache invalidation

    Returns:
        ID of the newly created cache entry
    """
    cache = RunCache(
        run_json=json.dumps(run_record),
        created_on=_now_iso(),
        source=source,
        sbom_id=sbom_id,
    )
    db.add(cache)
    db.commit()
    db.refresh(cache)
    return cache.id


def _now_iso() -> str:
    """Get current UTC time in ISO format without microseconds."""
    from datetime import datetime

    return datetime.now(UTC).replace(microsecond=0).isoformat()


# ============================================================
# Run Reconstruction
# ============================================================


def rebuild_run_from_db(db: Session, run_id: int) -> dict | None:
    """
    Reconstruct a consolidated-style run dict from AnalysisRun + AnalysisFinding rows.

    This is the fallback when RunCache has no entry (e.g. runs created by
    the multi-source auto-analysis path which writes to analysis_run/finding
    but not to run_cache).

    Args:
        db: Database session
        run_id: ID of the AnalysisRun to reconstruct

    Returns:
        Run dictionary suitable for PDF generation, or None if not found

    Structure:
        {
            "status": "PASS|FAIL|ERROR|...",
            "sbom": {"id": int, "name": str},
            "summary": {
                "components": int,
                "withCPE": int,
                "findings": {"total": int, "bySeverity": {...}},
                "errors": int,
                "durationMs": int,
                "completedOn": str,
            },
            "components": [...],
        }
    """
    run_row: AnalysisRun | None = db.get(AnalysisRun, run_id)
    if run_row is None:
        log.warning("AnalysisRun id=%d not found", run_id)
        return None

    findings = db.query(AnalysisFinding).filter(AnalysisFinding.analysis_run_id == run_id).all()

    sbom_row = db.get(SBOMSource, run_row.sbom_id) if run_row.sbom_id else None

    # Group findings by component name+version
    comp_map: dict = {}
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
        comp_map[key]["combined"].append(
            {
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
            }
        )
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


# ============================================================
# PDF Generation
# ============================================================


def generate_pdf_report(
    db: Session,
    run_id: int,
    title: str = "SBOM Vulnerability Report",
    filename: str = "sbom_report.pdf",
) -> tuple[bytes, str]:
    """
    Generate a PDF report for a given analysis run.

    Tries RunCache first; falls back to reconstructing from the database.

    Args:
        db: Database session
        run_id: ID of the analysis run
        title: PDF report title
        filename: Desired filename for the report

    Returns:
        Tuple of (pdf_bytes, filename)

    Raises:
        ValueError: If run not found or PDF generation fails
    """
    # Ensure filename has .pdf extension
    if not filename.lower().endswith(".pdf"):
        filename = f"{filename}.pdf"

    # Try RunCache first
    run = load_run_cache(db, run_id)

    # Fallback: reconstruct from AnalysisRun + AnalysisFinding tables
    if run is None:
        log.debug("Run id=%d not in cache, rebuilding from DB", run_id)
        run = rebuild_run_from_db(db, run_id)

    if run is None:
        raise ValueError(f"Run {run_id} not found in cache or database")

    try:
        pdf_bytes = build_pdf_from_run_bytes(run, title=title)
        log.info("PDF generated: run_id=%d size=%d bytes filename=%s", run_id, len(pdf_bytes), filename)
        return pdf_bytes, filename
    except Exception as e:
        log.error("PDF generation failed: run_id=%d error=%s", run_id, e, exc_info=True)
        raise ValueError(f"Failed to generate PDF: {e}")
