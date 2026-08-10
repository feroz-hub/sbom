"""VEX import and exploitability statement endpoints."""

from __future__ import annotations

import json
import zipfile
from io import BytesIO
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..core.context import CurrentContext
from ..core.security import get_current_tenant_context
from ..db import get_db
from ..models import VexOverrideAudit
from ..services.lifecycle.vex_discovery import discover_and_import_vex_documents
from ..services.lifecycle.vex_provider import (
    apply_vex_override,
    import_vex_document,
    list_vex_statements,
    vex_report,
    vex_report_csv,
)
from ..services.tenant_access import get_component_for_tenant, get_sbom_for_tenant

router = APIRouter(tags=["vex"])


def _require_sbom(db: Session, sbom_id: int, tenant_id: int) -> None:
    if get_sbom_for_tenant(db, sbom_id, tenant_id) is None:
        raise HTTPException(status_code=404, detail="SBOM not found")


@router.post("/api/sboms/{sbom_id}/vex")
def upload_vex_document(
    sbom_id: int,
    payload: dict[str, Any],
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    """Upload/import CycloneDX/OpenVEX-style exploitability statements."""
    _require_sbom(db, sbom_id, context.tenant_id)
    document = payload.get("document") if isinstance(payload.get("document"), dict) else payload
    return import_vex_document(
        db,
        sbom_id,
        document,
        source_type=str(payload.get("source_type") or "uploaded"),
        source_name=str(payload.get("source_name") or "Uploaded VEX"),
        source_url=payload.get("source_url"),
        author=payload.get("author"),
        uploaded_by=payload.get("uploaded_by") or context.actor_label(),
    )


@router.get("/api/sboms/{sbom_id}/vex")
def get_vex_statements(
    sbom_id: int,
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    """List VEX statements for an SBOM."""
    _require_sbom(db, sbom_id, context.tenant_id)
    return list_vex_statements(db, sbom_id)


@router.get("/api/sboms/{sbom_id}/vex/report")
def get_vex_report(
    sbom_id: int,
    format: str = Query("json", pattern="^(json|csv)$"),
    report_type: str | None = Query(
        None, description="affected, not_affected, fixed, under_investigation, unknown, remediation_action"
    ),
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    """Return detailed VEX statement evidence for export/UI reports."""

    _require_sbom(db, sbom_id, context.tenant_id)
    status_filter = _report_status_filter(report_type)
    if format == "csv":
        content = vex_report_csv(db, sbom_id, status_filter=status_filter)
        suffix = f"_{report_type}" if report_type else ""
        return Response(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="sbom_{sbom_id}_vex{suffix}.csv"'},
        )
    return vex_report(db, sbom_id, status_filter=status_filter)


@router.get("/api/sboms/{sbom_id}/reports/vex-pack")
def get_vex_report_pack(
    sbom_id: int,
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    """Download a ZIP pack of VEX JSON and focused CSV reports."""

    _require_sbom(db, sbom_id, context.tenant_id)
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("vex.json", json.dumps(vex_report(db, sbom_id), indent=2))
        for report_type in ("affected", "not_affected", "fixed", "under_investigation", "unknown"):
            zf.writestr(f"vex_{report_type}.csv", vex_report_csv(db, sbom_id, status_filter=report_type))
        zf.writestr("vex_remediation_action.csv", vex_report_csv(db, sbom_id))
    return Response(
        content=buffer.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="sbom_{sbom_id}_vex_reports.zip"'},
    )


@router.post("/api/sboms/{sbom_id}/vex/discover")
def discover_vex_documents(
    sbom_id: int,
    force: bool = Query(False),
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    """Discover and import vendor-hosted VEX documents without blocking upload."""

    _require_sbom(db, sbom_id, context.tenant_id)
    return discover_and_import_vex_documents(db, sbom_id, force=force)


@router.patch("/api/components/{component_id}/vulnerabilities/{vulnerability_id}/vex-override")
def patch_vex_override(
    component_id: int,
    vulnerability_id: str,
    payload: dict[str, Any],
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    """Apply an audited manual VEX override."""
    if get_component_for_tenant(db, component_id, context.tenant_id) is None:
        raise HTTPException(status_code=404, detail="Component not found")
    statement = apply_vex_override(
        db,
        component_id,
        vulnerability_id,
        payload,
        changed_by=payload.get("updated_by") or payload.get("changed_by") or context.actor_label(),
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


@router.get("/api/components/{component_id}/vulnerabilities/{vulnerability_id}/vex-override/history")
def get_vex_override_history(
    component_id: int,
    vulnerability_id: str,
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    if get_component_for_tenant(db, component_id, context.tenant_id) is None:
        raise HTTPException(status_code=404, detail="Component not found")
    rows = (
        db.query(VexOverrideAudit)
        .filter(VexOverrideAudit.component_id == component_id)
        .filter(VexOverrideAudit.vulnerability_id == vulnerability_id)
        .order_by(VexOverrideAudit.id.asc())
        .all()
    )
    return {
        "component_id": component_id,
        "vulnerability_id": vulnerability_id,
        "history": [
            {
                "id": row.id,
                "old_value": row.old_value_json,
                "new_value": row.new_value_json,
                "reason": row.reason,
                "evidence_url": row.evidence_url,
                "changed_by": row.changed_by,
                "changed_at": row.changed_at,
            }
            for row in rows
        ],
    }


def _report_status_filter(report_type: str | None) -> str | None:
    if not report_type:
        return None
    key = report_type.strip().lower().replace("-", "_")
    if key in {"affected", "not_affected", "fixed", "under_investigation", "unknown"}:
        return key
    return None
