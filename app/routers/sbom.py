# routers/sbom.py — SBOM feature endpoints (B4: risk-summary, B8: info)
from __future__ import annotations

import json
import logging
from collections import Counter

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import AnalysisFinding, AnalysisRun, SBOMSource, SBOMValidationSession
from ..schemas import ValidationErrorEntry, ValidationReportResponse
from ..services.risk_score import score_findings
from ..validation.stages import STAGE_NUMBERS

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
        db.execute(select(AnalysisRun).where(AnalysisRun.sbom_id == sbom_id).order_by(AnalysisRun.id.desc()))
        .scalars()
        .first()
    )
    if not run:
        raise HTTPException(status_code=404, detail="No analysis run found for this SBOM")

    findings = db.execute(select(AnalysisFinding).where(AnalysisFinding.analysis_run_id == run.id)).scalars().all()

    summary = score_findings(db, findings)
    return {
        "sbom_id": sbom_id,
        "run_id": run.id,
        **summary,
    }


def _detect_format_from_data(sbom_data: str | None) -> tuple[str | None, str | None]:
    """Best-effort (format, spec_version) extraction from a stored SBOM.

    Returns ``(None, None)`` for non-JSON or malformed bodies. The
    validation-report endpoint surfaces this so the UI can label "Stopped
    at: Schema validation · CycloneDX 1.6" without re-running the
    detection stage.
    """
    if not sbom_data:
        return None, None
    try:
        as_dict = json.loads(sbom_data) if isinstance(sbom_data, str) else sbom_data
    except (json.JSONDecodeError, TypeError):
        return None, None
    if not isinstance(as_dict, dict):
        return None, None
    if as_dict.get("bomFormat") == "CycloneDX":
        return "cyclonedx", str(as_dict.get("specVersion") or "") or None
    if "spdxVersion" in as_dict:
        return "spdx", str(as_dict.get("spdxVersion") or "") or None
    return None, None


@router.get(
    "/{sbom_id}/validation-report",
    status_code=200,
    response_model=ValidationReportResponse,
)
def get_sbom_validation_report(sbom_id: int, db: Session = Depends(get_db)):
    """Return the persisted 8-stage validation report for an SBOM.

    Always returns a row for any ``SBOMSource`` that exists, even rows
    that predate migration 012 (those report ``status='validated'`` with
    empty entries). The frontend's detail-page report section is the
    primary consumer; the JSON download affordance also calls this
    endpoint and serialises the response verbatim.
    """
    sbom = db.get(SBOMSource, sbom_id)
    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")

    raw_entries: list[dict] = list(sbom.validation_errors or [])
    enriched: list[ValidationErrorEntry] = []
    severity_summary: Counter[str] = Counter()
    stage_summary: Counter[str] = Counter()
    info_count = 0
    for raw in raw_entries:
        if not isinstance(raw, dict):
            continue
        stage = str(raw.get("stage") or "")
        severity = str(raw.get("severity") or "")
        enriched.append(
            ValidationErrorEntry(
                code=str(raw.get("code") or ""),
                severity=severity,
                stage=stage,
                stage_number=STAGE_NUMBERS.get(stage, 0),
                path=str(raw.get("path") or ""),
                message=str(raw.get("message") or ""),
                remediation=str(raw.get("remediation") or ""),
                spec_reference=raw.get("spec_reference"),
            )
        )
        severity_summary[severity] += 1
        stage_summary[stage] += 1
        if severity == "info":
            info_count += 1

    spec_detected, spec_version_detected = _detect_format_from_data(sbom.sbom_data)

    session = (
        db.execute(
            select(SBOMValidationSession)
            .where(SBOMValidationSession.imported_sbom_id == sbom.id)
            .order_by(SBOMValidationSession.created_at.desc())
        )
        .scalars()
        .first()
    )

    if not session and sbom.status in {"failed", "quarantined"}:
        from ..services.validation_repair_service import ValidationRepairService
        from ..validation import run as run_validation

        raw = sbom.sbom_data.encode("utf-8") if sbom.sbom_data else b""
        report = run_validation(raw)

        service = ValidationRepairService(db)
        session, blocked_reason = service.create_failed_upload_session(
            raw_text=sbom.sbom_data or "",
            report=report,
            sbom_name=sbom.sbom_name,
            original_filename=sbom.sbom_name,
            project_id=sbom.projectid,
            sbom_type=sbom.sbom_type,
            user_id=sbom.created_by,
        )
        if session:
            session.imported_sbom_id = sbom.id
            db.add(session)
            db.commit()
            db.refresh(session)

    return ValidationReportResponse(
        sbom_id=int(sbom.id),
        filename=str(sbom.sbom_name),
        status=str(sbom.status or "validated"),
        failed_stage=sbom.failed_stage,
        error_count=int(sbom.error_count or 0),
        warning_count=int(sbom.warning_count or 0),
        info_count=info_count,
        entries=enriched,
        validated_at=sbom.validated_at,
        spec_detected=spec_detected,
        spec_version_detected=spec_version_detected,
        severity_summary=dict(severity_summary),
        stage_summary=dict(stage_summary),
        truncated=False,
        session_id=session.id if session else None,
        can_edit=bool(session and session.can_edit),
    )


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
