"""VEX import and exploitability statement endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..db import get_db
from ..services.lifecycle.vex_provider import apply_vex_override, import_vex_document, list_vex_statements

router = APIRouter(tags=["vex"])


@router.post("/api/sboms/{sbom_id}/vex")
def upload_vex_document(
    sbom_id: int,
    payload: dict[str, Any],
    db: Session = Depends(get_db),
):
    """Upload/import CycloneDX/OpenVEX-style exploitability statements."""
    document = payload.get("document") if isinstance(payload.get("document"), dict) else payload
    return import_vex_document(
        db,
        sbom_id,
        document,
        source_type=str(payload.get("source_type") or "uploaded"),
        source_name=str(payload.get("source_name") or "Uploaded VEX"),
        source_url=payload.get("source_url"),
        author=payload.get("author"),
        uploaded_by=payload.get("uploaded_by"),
    )


@router.get("/api/sboms/{sbom_id}/vex")
def get_vex_statements(sbom_id: int, db: Session = Depends(get_db)):
    """List VEX statements for an SBOM."""
    return list_vex_statements(db, sbom_id)


@router.get("/api/sboms/{sbom_id}/vex/report")
def get_vex_report(sbom_id: int, db: Session = Depends(get_db)):
    """Return detailed VEX statement evidence for export/UI reports."""
    return list_vex_statements(db, sbom_id)


@router.patch("/api/components/{component_id}/vulnerabilities/{vulnerability_id}/vex-override")
def patch_vex_override(
    component_id: int,
    vulnerability_id: str,
    payload: dict[str, Any],
    db: Session = Depends(get_db),
):
    """Apply an audited manual VEX override."""
    statement = apply_vex_override(
        db,
        component_id,
        vulnerability_id,
        payload,
        changed_by=payload.get("updated_by") or payload.get("changed_by"),
    )
    return {
        "id": statement.id,
        "component_id": statement.component_id,
        "vulnerability_id": statement.vulnerability_id,
        "status": statement.status,
        "justification": statement.justification,
        "impact_statement": statement.impact_statement,
        "action_statement": statement.action_statement,
        "fixed_version": statement.fixed_version,
        "mitigation": statement.mitigation,
        "source_name": statement.source_name,
        "source_url": statement.source_url,
        "confidence": statement.confidence,
        "created_at": statement.created_at,
    }
