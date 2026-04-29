# routers/sbom.py — SBOM feature endpoints (B4: risk-summary, B8: info)
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import AnalysisFinding, AnalysisRun, SBOMSource
from ..services.risk_score import score_findings

log = logging.getLogger("sbom.api.sbom")

router = APIRouter()


@router.get("/{sbom_id}/risk-summary", status_code=200)
def get_sbom_risk_summary(sbom_id: int, db: Session = Depends(get_db)):
    """
    CVSS + EPSS + KEV composite risk summary for the latest analysis run.

    Replaces the legacy bucket-and-weight scorer. See
    ``app/services/risk_score.py`` for the full formula and rationale.

    Response shape (additive — old keys preserved for client compat):
        sbom_id            int
        run_id             int                (NEW)
        total_risk_score   float
        risk_band          "CRITICAL"|...
        components         list[dict]
        worst_finding      dict|None          (NEW) the highest-scoring CVE
        kev_count          int                (NEW) findings on CISA KEV
        epss_avg           float              (NEW) mean EPSS across findings
        methodology        dict               (NEW) formula + sources
    """
    sbom = db.get(SBOMSource, sbom_id)
    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")

    run = (
        db.execute(
            select(AnalysisRun)
            .where(AnalysisRun.sbom_id == sbom_id)
            .order_by(AnalysisRun.id.desc())
        )
        .scalars()
        .first()
    )
    if not run:
        raise HTTPException(status_code=404, detail="No analysis run found for this SBOM")

    findings = (
        db.execute(
            select(AnalysisFinding).where(AnalysisFinding.analysis_run_id == run.id)
        )
        .scalars()
        .all()
    )

    summary = score_findings(db, findings)
    return {
        "sbom_id": sbom_id,
        "run_id": run.id,
        **summary,
    }


@router.get("/{sbom_id}/info", status_code=200)
def get_sbom_info(sbom_id: int, db: Session = Depends(get_db)):
    """Return parsed metadata about the stored SBOM without running analysis."""
    sbom = db.get(SBOMSource, sbom_id)
    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")
    if not sbom.sbom_data:
        raise HTTPException(status_code=400, detail="SBOM has no data stored")

    try:
        if isinstance(sbom.sbom_data, str):
            sbom_dict = json.loads(sbom.sbom_data)
        else:
            sbom_dict = sbom.sbom_data
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid SBOM JSON: {e}")

    # Detect format
    fmt = "Unknown"
    spec_version = None
    if sbom_dict.get("bomFormat") == "CycloneDX" or "components" in sbom_dict:
        fmt = "CycloneDX"
        spec_version = sbom_dict.get("specVersion")
    elif sbom_dict.get("spdxVersion") or sbom_dict.get("SPDXID"):
        fmt = "SPDX"
        spec_version = sbom_dict.get("spdxVersion")

    try:
        from ..analysis import _parse_purl, extract_components

        components = extract_components(sbom_dict)
    except Exception:
        components = []

    ecosystems = set()
    has_purls = False
    has_cpes = False
    for c in components:
        if c.get("purl"):
            has_purls = True
            try:
                from ..analysis import _parse_purl

                parsed = _parse_purl(c["purl"])
                if parsed.get("type"):
                    ecosystems.add(parsed["type"].lower())
            except Exception:
                pass
        if c.get("cpe"):
            has_cpes = True

    preview = [c.get("name") for c in components[:5] if c.get("name")]

    return {
        "sbom_id": sbom_id,
        "format": fmt,
        "spec_version": spec_version,
        "component_count": len(components),
        "ecosystems": sorted(ecosystems),
        "has_purls": has_purls,
        "has_cpes": has_cpes,
        "components_preview": preview,
    }
