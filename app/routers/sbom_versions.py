"""
Sbom versions router — Endpoints for version control, manual editing, comparisons, and export.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import SBOMSource
from ..schemas import SbomEditPayload, SBOMSourceOut
from ..validation import run as run_validation
from ..services.version_control_service import compare_versions, edit_sbom, restore_version

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/sboms", tags=["sbom-versions"])


def _root_for_lineage(db: Session, sbom: SBOMSource) -> SBOMSource:
    """Walk parent links until the oldest reachable ancestor."""
    current = sbom
    seen = {sbom.id}
    while current.parent_id is not None:
        if current.parent_id in seen:
            break
        parent = db.get(SBOMSource, current.parent_id)
        if parent is None:
            break
        current = parent
        seen.add(current.id)
    return current


def _lineage_ids(db: Session, root_id: int) -> set[int]:
    """Collect the strict parent/child lineage rooted at ``root_id``."""
    ids = {root_id}
    frontier = [root_id]
    while frontier:
        children = db.execute(
            select(SBOMSource.id).where(SBOMSource.parent_id.in_(frontier))
        ).scalars().all()
        frontier = [child_id for child_id in children if child_id not in ids]
        ids.update(frontier)
    return ids


def _detect_native_format(raw: str) -> tuple[str, str]:
    """Return (standard, encoding) for the stored SBOM document."""
    content = raw.strip()
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        if content.startswith("<"):
            if "CycloneDX" in content or "<bom" in content:
                return "cyclonedx", "xml"
            return "xml", "xml"
        if content.startswith("SPDXVersion:"):
            return "spdx", "tag-value"
        return "unknown", "text"

    if isinstance(parsed, dict):
        bom_format = str(parsed.get("bomFormat") or "").lower()
        if bom_format == "cyclonedx" or ("specVersion" in parsed and "components" in parsed):
            return "cyclonedx", "json"
        if "spdxVersion" in parsed or "SPDXID" in parsed:
            return "spdx", "json"
    return "unknown", "json"


def _normalized_export_format(value: str) -> str:
    requested = (value or "native").strip().lower()
    aliases = {
        "cdx": "cyclonedx",
        "cyclonedx-json": "cyclonedx",
        "spdx-json": "spdx",
        "tagvalue": "spdx",
        "tag-value": "spdx",
    }
    requested = aliases.get(requested, requested)
    allowed = {"native", "json", "xml", "cyclonedx", "spdx"}
    if requested not in allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported export format '{value}'. Supported formats: native, json, xml, CycloneDX, SPDX.",
        )
    return requested


def _media_type(standard: str, encoding: str) -> str:
    if encoding == "xml":
        return "application/xml"
    if standard == "cyclonedx" and encoding == "json":
        return "application/vnd.cyclonedx+json"
    if standard == "spdx" and encoding == "json":
        return "application/spdx+json"
    if standard == "spdx" and encoding == "tag-value":
        return "text/spdx"
    if encoding == "json":
        return "application/json"
    return "text/plain"


@router.post("/{id}/edit", response_model=SBOMSourceOut)
def edit_sbom_endpoint(
    id: int,
    payload: SbomEditPayload,
    user_id: str | None = Query(None),
    db: Session = Depends(get_db)
):
    """
    Manually edit SBOM components, metadata, or dependencies.
    Creates a new version of the SBOM in the DB.
    """
    try:
        new_version = edit_sbom(
            db=db,
            sbom_id=id,
            user_id=user_id,
            updates=payload.model_dump(exclude_none=True),
            change_summary=payload.change_summary
        )
        return new_version
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get("/{id}/versions", response_model=list[SBOMSourceOut])
def get_sbom_versions(id: int, db: Session = Depends(get_db)):
    """
    Retrieve all versions in the lineage chain of this SBOM.
    """
    sbom = db.get(SBOMSource, id)
    if not sbom:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SBOM with ID {id} not found."
        )
        
    root = _root_for_lineage(db, sbom)
    ids = _lineage_ids(db, root.id)
    versions = db.execute(
        select(SBOMSource)
        .where(SBOMSource.id.in_(ids))
        .order_by(SBOMSource.id.asc())
    ).scalars().all()
    
    return list(versions)


@router.get("/compare-versions", response_model=dict[str, Any])
def compare_sbom_versions(
    version_a: int = Query(...),
    version_b: int = Query(...),
    db: Session = Depends(get_db)
):
    """
    Compare two SBOM versions and return added, removed, and changed components.
    """
    sbom_a = db.get(SBOMSource, version_a)
    sbom_b = db.get(SBOMSource, version_b)
    if not sbom_a or not sbom_b:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="One or both of the specified SBOM versions were not found."
        )
    return compare_versions(db, version_a, version_b)


@router.post("/{id}/restore/{version_id}", response_model=SBOMSourceOut)
def restore_sbom_version(
    id: int,
    version_id: int,
    user_id: str | None = Query(None),
    db: Session = Depends(get_db)
):
    """
    Restore a previous version of the SBOM.
    Clones the target version and saves it as the current head version.
    """
    try:
        restored = restore_version(db, id, version_id, user_id)
        return restored
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get("/{id}/export")
def export_sbom(
    id: int,
    format: str = Query("native", description="native, json, xml, CycloneDX, or SPDX"),
    db: Session = Depends(get_db)
):
    """
    Export the current SBOM data in its native format.
    """
    sbom = db.get(SBOMSource, id)
    if not sbom or not sbom.sbom_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SBOM with ID {id} has no data."
        )
    requested = _normalized_export_format(format)
    standard, encoding = _detect_native_format(sbom.sbom_data)

    if requested in {"cyclonedx", "spdx"} and standard != requested:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Unsupported SBOM conversion from {standard} to {requested}. "
                "Only native-format export is currently supported."
            ),
        )
    if requested in {"json", "xml"} and encoding != requested:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Unsupported SBOM conversion from native {encoding} to {requested}. "
                "Only native-format export is currently supported."
            ),
        )

    content = sbom.sbom_data
    if encoding == "json":
        try:
            content = json.dumps(json.loads(content), indent=2)
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Stored SBOM JSON is invalid and cannot be exported: {exc}",
            ) from exc

    report = run_validation(content.encode("utf-8"))
    if report.has_errors():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "message": "Stored SBOM failed validation and cannot be exported.",
                "errors": [entry.model_dump() for entry in report.entries],
            },
        )

    extension = "json" if encoding == "json" else "xml" if encoding == "xml" else "spdx"
    filename = f"{sbom.sbom_name}_v{sbom.sbom_version or '1'}.{extension}"
    headers = {
        "Content-Disposition": f"attachment; filename=\"{filename}\""
    }
    
    return Response(content=content, media_type=_media_type(standard, encoding), headers=headers)
