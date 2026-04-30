# routers/analysis.py — Analysis run export endpoints (B5: SARIF, B6: CSV, B9: compare)
from __future__ import annotations

import csv
import io
import itertools
import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import AnalysisFinding, AnalysisRun, SBOMComponent
from ..schemas_compare import COMPARABLE_RUN_STATUSES

log = logging.getLogger("sbom.api.analysis")

router = APIRouter()

# -----------------------------------------------------------------------------
# Compare v1 — DEPRECATED in favour of POST /api/v1/compare (ADR-0008)
# -----------------------------------------------------------------------------
# This endpoint is preserved during the strangler period for back-compat with
# any external consumers (CI scripts, scripted exports). It MUST stay correct
# while it lives — Phase 1 §6 surfaced two pre-existing bugs we fix here:
#
#   B7  No status guard. v1 happily diffed RUNNING / ERROR runs and produced
#       nonsense. Now returns 409 with a structured envelope when either run
#       is not in COMPARABLE_RUN_STATUSES.
#
#   Identity collision (Phase 1 §C-1). v1 diffs by plain ``vuln_id`` set, so
#   "CVE-X against pkgA" and "CVE-X against pkgB" collapse to one. We do NOT
#   fix this in v1 — that's the whole reason v2 exists. Documented here so
#   future readers understand why the bug is left in place.
#
# Telemetry: every call increments a tiny in-process counter and emits a
# structured WARNING-level log. Ops grep these to verify "<1% relative
# traffic for two consecutive weeks" before deleting the endpoint per
# ADR-0008 §1.
#
# Deprecation headers: per RFC 9745 / RFC 8594 the response carries
# ``Deprecation: true`` and ``Sunset: <date>`` so caching proxies and SDKs
# can surface the warning to their users.
#: Stable date the deprecated endpoint is scheduled for removal. Bumped if we
#: discover a major dependency that needs longer to migrate.
COMPARE_V1_SUNSET_DATE = "Wed, 31 Dec 2026 23:59:59 GMT"

#: In-process counter so ops can read /api/_telemetry/compare-v1 (added in
#: a follow-up admin endpoint) to confirm traffic levels without parsing
#: logs. Process-local only — multi-worker deployments require log
#: aggregation for an absolute total.
_compare_v1_counter = itertools.count(start=1)
_compare_v1_total = 0


def _record_compare_v1_call() -> int:
    global _compare_v1_total
    _compare_v1_total = next(_compare_v1_counter)
    return _compare_v1_total


def get_compare_v1_call_count() -> int:
    """Read-only accessor used by tests and the ops telemetry endpoint."""
    return _compare_v1_total


@router.get("/compare", status_code=200)
def compare_analysis_runs(
    response: Response,
    run_a: int = Query(..., description="First run ID"),
    run_b: int = Query(..., description="Second run ID"),
    db: Session = Depends(get_db),
):
    """[DEPRECATED] Diff two analysis runs by vuln_id set.

    Use ``POST /api/v1/compare`` (ADR-0008) for new integrations — it produces
    per-finding events with attribution, posture deltas, and component diffs.
    This endpoint is preserved for back-compat and will be removed once
    telemetry shows <1% relative traffic for two consecutive weeks.
    """
    call_count = _record_compare_v1_call()
    log.warning(
        "compare_v1_deprecated_call run_a=%d run_b=%d total_calls=%d sunset=%s",
        run_a,
        run_b,
        call_count,
        COMPARE_V1_SUNSET_DATE,
    )
    response.headers["Deprecation"] = "true"
    response.headers["Sunset"] = COMPARE_V1_SUNSET_DATE
    response.headers["Link"] = '</api/v1/compare>; rel="successor-version"'

    run_a_obj = db.get(AnalysisRun, run_a)
    run_b_obj = db.get(AnalysisRun, run_b)

    if not run_a_obj:
        raise HTTPException(
            status_code=404,
            detail={
                "error_code": "COMPARE_V1_E001_RUN_NOT_FOUND",
                "message": f"Run {run_a} not found",
                "run_id": run_a,
                "retryable": False,
            },
        )
    if not run_b_obj:
        raise HTTPException(
            status_code=404,
            detail={
                "error_code": "COMPARE_V1_E001_RUN_NOT_FOUND",
                "message": f"Run {run_b} not found",
                "run_id": run_b,
                "retryable": False,
            },
        )

    # B7 patch — both runs must be in a comparable status. Pre-fix v1 happily
    # diffed RUNNING runs and returned nonsense. v2 returns the same envelope.
    for run in (run_a_obj, run_b_obj):
        status = (run.run_status or "").upper()
        if status not in COMPARABLE_RUN_STATUSES:
            raise HTTPException(
                status_code=409,
                detail={
                    "error_code": "COMPARE_V1_E002_RUN_NOT_READY",
                    "message": f"Run {run.id} status={status} is not comparable",
                    "run_id": run.id,
                    "status": status,
                    "retryable": True,
                },
            )

    findings_a = db.execute(select(AnalysisFinding).where(AnalysisFinding.analysis_run_id == run_a)).scalars().all()
    findings_b = db.execute(select(AnalysisFinding).where(AnalysisFinding.analysis_run_id == run_b)).scalars().all()

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

    findings = db.execute(select(AnalysisFinding).where(AnalysisFinding.analysis_run_id == run_id)).scalars().all()

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

        results.append(
            {
                "ruleId": f.vuln_id or "UNKNOWN",
                "level": _sev_to_level(f.severity),
                "message": {"text": f.description or f.title or f.vuln_id or ""},
                "locations": [
                    {
                        "logicalLocations": [
                            {
                                "name": f.component_name or "unknown",
                                "fullyQualifiedName": purl or f.component_name or "unknown",
                            }
                        ]
                    }
                ],
                "properties": {
                    "score": f.score,
                    "cpe": f.cpe,
                    "published": f.published_on,
                },
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SBOM-Analyzer",
                        "version": "2.0.0",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
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

    findings = (
        db.execute(
            select(AnalysisFinding)
            .where(AnalysisFinding.analysis_run_id == run_id)
            .order_by(AnalysisFinding.score.desc())
        )
        .scalars()
        .all()
    )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "vuln_id",
            "severity",
            "score",
            "component_name",
            "component_version",
            "cpe",
            "purl",
            "published_on",
            "attack_vector",
            "cwe",
            "fixed_versions",
            "reference_url",
            "source",
            "description",
        ]
    )

    for f in findings:
        purl = None
        if f.component_id:
            comp = db.get(SBOMComponent, f.component_id)
            if comp:
                purl = comp.purl

        writer.writerow(
            [
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
            ]
        )

    content = output.getvalue()
    return Response(
        content=content,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="sbom_findings_{run_id}.csv"'},
    )
