# routers/sbom.py — SBOM feature endpoints (B4: risk-summary, B8: info)
from __future__ import annotations

import json
import logging
from collections import defaultdict
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import AnalysisFinding, AnalysisRun, SBOMComponent, SBOMSource

log = logging.getLogger("sbom.api.sbom")

router = APIRouter()


@router.get("/{sbom_id}/risk-summary", status_code=200)
def get_sbom_risk_summary(sbom_id: int, db: Session = Depends(get_db)):
    """Compute a risk score per component and overall risk band for the latest analysis run."""
    sbom = db.get(SBOMSource, sbom_id)
    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")

    run = db.execute(
        select(AnalysisRun)
        .where(AnalysisRun.sbom_id == sbom_id)
        .order_by(AnalysisRun.id.desc())
    ).scalars().first()
    if not run:
        raise HTTPException(status_code=404, detail="No analysis run found for this SBOM")

    findings = db.execute(
        select(AnalysisFinding).where(AnalysisFinding.analysis_run_id == run.id)
    ).scalars().all()

    comp_findings: dict = defaultdict(list)
    for f in findings:
        key = (f.component_name or "unknown", f.component_version or "")
        comp_findings[key].append(f)

    component_scores = []
    total_risk = 0.0
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

    for (cname, cver), flist in comp_findings.items():
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        has_network = False
        highest_sev = "LOW"

        for f in flist:
            sev = (f.severity or "UNKNOWN").upper()
            if sev in counts:
                counts[sev] += 1
            attack_vec = getattr(f, "attack_vector", None) or ""
            if attack_vec.lower() == "network":
                has_network = True
            if sev_order.get(sev, 0) > sev_order.get(highest_sev, 0):
                highest_sev = sev

        exploitability = 1.5 if has_network else 1.0
        score = (
            counts["CRITICAL"] * 10
            + counts["HIGH"] * 7
            + counts["MEDIUM"] * 4
            + counts["LOW"] * 1
        ) * exploitability
        total_risk += score

        component_scores.append({
            "name": cname,
            "version": cver,
            "critical": counts["CRITICAL"],
            "high": counts["HIGH"],
            "medium": counts["MEDIUM"],
            "low": counts["LOW"],
            "component_score": round(score, 2),
            "highest_severity": highest_sev,
        })

    component_scores.sort(key=lambda x: x["component_score"], reverse=True)

    if total_risk >= 100:
        risk_band = "CRITICAL"
    elif total_risk >= 50:
        risk_band = "HIGH"
    elif total_risk >= 20:
        risk_band = "MEDIUM"
    else:
        risk_band = "LOW"

    return {
        "sbom_id": sbom_id,
        "total_risk_score": round(total_risk, 2),
        "risk_band": risk_band,
        "components": component_scores,
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
        from ..analysis import extract_components, _parse_purl
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
