# routers/analysis.py — Analysis run export endpoints (B5: SARIF, B6: CSV, B9: compare)
from __future__ import annotations

import csv
import io
import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import AnalysisFinding, AnalysisRun, SBOMComponent

log = logging.getLogger("sbom.api.analysis")

router = APIRouter()


@router.get("/compare", status_code=200)
def compare_analysis_runs(
    run_a: int = Query(..., description="First run ID"),
    run_b: int = Query(..., description="Second run ID"),
    db: Session = Depends(get_db),
):
    """Compare two AnalysisRun records and return diff of findings."""
    run_a_obj = db.get(AnalysisRun, run_a)
    run_b_obj = db.get(AnalysisRun, run_b)

    if not run_a_obj:
        raise HTTPException(status_code=404, detail=f"Run {run_a} not found")
    if not run_b_obj:
        raise HTTPException(status_code=404, detail=f"Run {run_b} not found")

    findings_a = db.execute(
        select(AnalysisFinding).where(AnalysisFinding.analysis_run_id == run_a)
    ).scalars().all()
    findings_b = db.execute(
        select(AnalysisFinding).where(AnalysisFinding.analysis_run_id == run_b)
    ).scalars().all()

    ids_a = {f.vuln_id for f in findings_a if f.vuln_id}
    ids_b = {f.vuln_id for f in findings_b if f.vuln_id}

    def _sev_counts(findings):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = (f.severity or "").lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    counts_a = _sev_counts(findings_a)
    counts_b = _sev_counts(findings_b)

    return {
        "run_a": {
            "id": run_a,
            "sbom_name": run_a_obj.sbom_name,
            "completed_on": run_a_obj.completed_on,
        },
        "run_b": {
            "id": run_b,
            "sbom_name": run_b_obj.sbom_name,
            "completed_on": run_b_obj.completed_on,
        },
        "new_findings": sorted(ids_b - ids_a),
        "resolved_findings": sorted(ids_a - ids_b),
        "common_findings": sorted(ids_a & ids_b),
        "severity_delta": {
            "critical": counts_b["critical"] - counts_a["critical"],
            "high": counts_b["high"] - counts_a["high"],
            "medium": counts_b["medium"] - counts_a["medium"],
            "low": counts_b["low"] - counts_a["low"],
        },
    }


@router.get("/{run_id}/export/sarif", status_code=200)
def export_sarif(run_id: int, db: Session = Depends(get_db)):
    """Export findings as SARIF 2.1.0 for GitHub Code Scanning, VS Code, Azure DevOps."""
    run = db.get(AnalysisRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Analysis run not found")

    findings = db.execute(
        select(AnalysisFinding).where(AnalysisFinding.analysis_run_id == run_id)
    ).scalars().all()

    def _sev_to_level(sev: str) -> str:
        s = (sev or "").upper()
        if s in ("CRITICAL", "HIGH"):
            return "error"
        if s == "MEDIUM":
            return "warning"
        if s == "LOW":
            return "note"
        return "none"

    rules_map: dict = {}
    for f in findings:
        vid = f.vuln_id or "UNKNOWN"
        if vid not in rules_map:
            rules_map[vid] = {
                "id": vid,
                "name": vid,
                "shortDescription": {"text": f.title or vid},
                "fullDescription": {"text": f.description or f.title or vid},
                "helpUri": f.reference_url or f"https://nvd.nist.gov/vuln/detail/{vid}",
                "properties": {
                    "severity": f.severity or "UNKNOWN",
                    "tags": ["security", "vulnerability"],
                },
            }

    results = []
    for f in findings:
        purl = None
        if f.component_id:
            comp = db.get(SBOMComponent, f.component_id)
            if comp:
                purl = comp.purl

        results.append({
            "ruleId": f.vuln_id or "UNKNOWN",
            "level": _sev_to_level(f.severity),
            "message": {"text": f.description or f.title or f.vuln_id or ""},
            "locations": [{
                "logicalLocations": [{
                    "name": f.component_name or "unknown",
                    "fullyQualifiedName": purl or f.component_name or "unknown",
                }]
            }],
            "properties": {
                "score": f.score,
                "cpe": f.cpe,
                "published": f.published_on,
            },
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SBOM-Analyzer",
                    "version": "2.0.0",
                    "rules": list(rules_map.values()),
                }
            },
            "results": results,
        }],
    }

    return Response(
        content=json.dumps(sarif, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="sbom_findings_{run_id}.sarif"'},
    )


@router.get("/{run_id}/export/csv", status_code=200)
def export_csv(run_id: int, db: Session = Depends(get_db)):
    """Export all findings from an AnalysisRun as CSV."""
    run = db.get(AnalysisRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Analysis run not found")

    findings = db.execute(
        select(AnalysisFinding)
        .where(AnalysisFinding.analysis_run_id == run_id)
        .order_by(AnalysisFinding.score.desc())
    ).scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "vuln_id", "severity", "score", "component_name", "component_version",
        "cpe", "purl", "published_on", "attack_vector", "cwe",
        "fixed_versions", "reference_url", "source", "description",
    ])

    for f in findings:
        purl = None
        if f.component_id:
            comp = db.get(SBOMComponent, f.component_id)
            if comp:
                purl = comp.purl

        writer.writerow([
            f.vuln_id or "",
            f.severity or "",
            f.score if f.score is not None else "",
            f.component_name or "",
            f.component_version or "",
            f.cpe or "",
            purl or "",
            f.published_on or "",
            getattr(f, "attack_vector", None) or "",
            f.cwe or "",
            getattr(f, "fixed_versions", None) or "",
            f.reference_url or "",
            f.source or "",
            (f.description or "").replace("\n", " "),
        ])

    content = output.getvalue()
    return Response(
        content=content,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="sbom_findings_{run_id}.csv"'},
    )
