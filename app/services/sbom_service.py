"""
SBOM Service Layer - Business logic for SBOM handling and component management.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..analysis import extract_components
from ..models import SBOMComponent, SBOMSource
from ..parsing import detect_sbom_format

log = logging.getLogger(__name__)


# ============================================================
# Utility Functions
# ============================================================


def now_iso() -> str:
    """Get current UTC time in ISO format without microseconds."""
    from datetime import datetime

    return datetime.now(UTC).replace(microsecond=0).isoformat()


def normalized_key(value: str | None) -> str:
    """Normalize a string for comparison (lowercase, stripped)."""
    return (value or "").strip().lower()


def safe_int(value: Any, default: int = 0) -> int:
    """Safely convert value to int, return default on failure."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ============================================================
# SBOM Data Coercion
# ============================================================


def coerce_sbom_data(value: Any) -> str | None:
    """
    Ensure sbom_data is always stored as a JSON string in the DB Text column,
    even if the client sends a dict/list. Leave strings as-is.

    Args:
        value: The SBOM data to coerce (dict, list, str, or None)

    Returns:
        JSON string, original string, or None
    """
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return value if isinstance(value, str) else str(value)


def load_json_bytes_with_fallback(data: bytes) -> Any:
    """
    Decode bytes as UTF-8, fallback to UTF-8-SIG and parse JSON.

    Args:
        data: Raw bytes to decode and parse

    Returns:
        Parsed JSON object

    Raises:
        ValueError: If unable to decode or parse JSON
    """
    try:
        text = data.decode("utf-8")
        return json.loads(text)
    except UnicodeDecodeError:
        try:
            text = data.decode("utf-8-sig")
            return json.loads(text)
        except UnicodeDecodeError as e:
            raise ValueError(f"Unable to decode JSON as UTF-8/UTF-8-SIG: {e}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")


# ============================================================
# Component Management
# ============================================================


def sync_sbom_components(db: Session, sbom_obj: SBOMSource) -> list[dict]:
    """
    Extract components from SBOM data, deduplicate, and upsert them into the database.

    Args:
        db: Database session
        sbom_obj: SBOM source object containing sbom_data

    Returns:
        List of extracted canonical component dictionaries
    """
    if not sbom_obj.sbom_data:
        return []

    components = extract_components(sbom_obj.sbom_data)

    # Parse dependencies from raw SBOM JSON
    try:
        if isinstance(sbom_obj.sbom_data, str):
            sbom_dict = json.loads(sbom_obj.sbom_data)
        elif isinstance(sbom_obj.sbom_data, dict):
            sbom_dict = sbom_obj.sbom_data
        else:
            sbom_dict = {}
    except Exception:
        sbom_dict = {}

    dependencies = []
    if isinstance(sbom_dict, dict):
        if sbom_dict.get("bomFormat") == "CycloneDX":
            dependencies = sbom_dict.get("dependencies") or []
        elif sbom_dict.get("spdxVersion") or sbom_dict.get("SPDXID"):
            dependencies = sbom_dict.get("relationships") or []

    from .component_deduplication_service import ComponentDeduplicationService

    canonical_components, duplicate_components, _, dedupe_report, _ = \
        ComponentDeduplicationService.deduplicate_components(components, dependencies)

    # Save dedupe report to SBOMSource
    sbom_obj.dedupe_report_json = dedupe_report
    db.add(sbom_obj)
    db.flush()

    _upsert_components(db, sbom_obj, canonical_components, duplicate_components)
    return canonical_components


def _upsert_components(
    db: Session,
    sbom_obj: SBOMSource,
    canonical_components: list[dict],
    duplicate_components: list[dict] | None = None
) -> dict:
    """
    Internal: Upsert components into the database, avoiding duplicates.

    Args:
        db: Database session
        sbom_obj: SBOM source object
        canonical_components: List of canonical component dictionaries
        duplicate_components: Optional list of duplicate component dictionaries

    Returns:
        Dictionary with 'triplet', 'cpe', and 'bom_ref' maps for lookup
    """
    from .component_deduplication_service import ComponentDeduplicationService, get_component_identity_key

    if duplicate_components is None:
        # Backward compatibility path: deduplicate components internally
        canonical_components, duplicate_components, _, _, _ = \
            ComponentDeduplicationService.deduplicate_components(canonical_components, [])

    existing_rows = db.execute(select(SBOMComponent).where(SBOMComponent.sbom_id == sbom_obj.id)).scalars().all()

    by_bom_ref: dict[str, SBOMComponent] = {}
    by_comp_triplet: dict = {}
    by_name_version: dict = {}
    by_cpe: dict = {}

    # Build lookup maps from existing components
    for row in existing_rows:
        if row.bom_ref:
            by_bom_ref[row.bom_ref] = row
        triplet = (
            normalized_key(row.cpe),
            normalized_key(row.name),
            normalized_key(row.version),
        )
        by_comp_triplet.setdefault(triplet, row)
        nv = (normalized_key(row.name), normalized_key(row.version))
        by_name_version.setdefault(nv, []).append(row)
        if row.cpe:
            by_cpe.setdefault(normalized_key(row.cpe), []).append(row)

    def save_comp_row(comp: dict, is_dup: bool, dup_of_id: int | None = None) -> SBOMComponent:
        name = (comp.get("name") or "").strip()
        if not name:
            fallback = (comp.get("bom_ref") or comp.get("purl") or comp.get("cpe") or "component").strip()
            name = fallback[:255] if fallback else "component"

        version = (comp.get("version") or "").strip() or None
        cpe = (comp.get("cpe") or "").strip() or None
        triplet = (normalized_key(cpe), normalized_key(name), normalized_key(version))
        ref = (comp.get("bom_ref") or "").strip() or None

        # If it already exists by bom-ref, update fields in place
        if ref and ref in by_bom_ref:
            row = by_bom_ref[ref]
            row.is_duplicate = is_dup
            row.duplicate_of_component_id = dup_of_id
            row.normalized_component_key = get_component_identity_key(comp)
            db.add(row)
            db.flush()
            return row

        # Backfill case for canonical components
        if not is_dup and cpe:
            nv_key = (normalized_key(name), normalized_key(version))
            backfill_target = next(
                (r for r in by_name_version.get(nv_key, []) if not (r.cpe or "").strip() and not r.is_duplicate),
                None,
            )
            if backfill_target is not None:
                backfill_target.cpe = cpe
                backfill_target.is_duplicate = False
                backfill_target.normalized_component_key = get_component_identity_key(comp)
                db.add(backfill_target)
                db.flush()
                # Maintain lookup maps
                empty_triplet = (normalized_key(None), normalized_key(name), normalized_key(version))
                by_comp_triplet.pop(empty_triplet, None)
                by_comp_triplet[triplet] = backfill_target
                by_cpe.setdefault(normalized_key(cpe), []).append(backfill_target)
                if ref:
                    by_bom_ref[ref] = backfill_target
                return backfill_target

        row = SBOMComponent(
            sbom_id=sbom_obj.id,
            bom_ref=ref,
            component_type=(comp.get("type") or "").strip() or None,
            component_group=(comp.get("group") or "").strip() or None,
            name=name,
            version=version,
            purl=(comp.get("purl") or "").strip() or None,
            cpe=cpe,
            supplier=(comp.get("supplier") or "").strip() or None,
            scope=(comp.get("scope") or "").strip() or None,
            license=(comp.get("license") or "").strip() or None,
            hashes=(comp.get("hashes") or "").strip() or None,
            created_on=now_iso(),
            is_duplicate=is_dup,
            duplicate_of_component_id=dup_of_id,
            normalized_component_key=get_component_identity_key(comp),
        )
        db.add(row)
        db.flush()

        if ref:
            by_bom_ref[ref] = row
        if not is_dup:
            by_comp_triplet[triplet] = row
            nv_key = (normalized_key(name), normalized_key(version))
            by_name_version.setdefault(nv_key, []).append(row)
            if cpe:
                by_cpe.setdefault(normalized_key(cpe), []).append(row)

        return row

    # Upsert canonical components first
    canonical_rows = {}
    for comp in canonical_components:
        row = save_comp_row(comp, is_dup=False)
        ref = comp.get("bom_ref") or comp.get("SPDXID") or ""
        if ref:
            canonical_rows[ref] = row

    # Upsert duplicate components next, resolving parent IDs
    for comp in duplicate_components:
        parent_ref = comp.get("duplicate_of_ref")
        parent_row = canonical_rows.get(parent_ref) if parent_ref else None
        parent_id = parent_row.id if parent_row else None
        save_comp_row(comp, is_dup=True, dup_of_id=parent_id)

    return {"triplet": by_comp_triplet, "cpe": by_cpe, "bom_ref": by_bom_ref}


def resolve_component_id(finding: dict, component_maps: dict) -> int | None:
    """
    Resolve a finding to a component ID using the component maps.

    Tries to match by exact (cpe, name, version) triplet first,
    then falls back to CPE match if available.

    Args:
        finding: Finding dictionary with cpe, component_name, component_version
        component_maps: Maps dict from _upsert_components with 'triplet' and 'cpe' keys

    Returns:
        Component ID if found, None otherwise
    """
    cpe = (finding.get("cpe") or "").strip() or None
    name = (finding.get("component_name") or "").strip() or None
    version = (finding.get("component_version") or "").strip() or None

    triplet = (
        normalized_key(cpe),
        normalized_key(name),
        normalized_key(version),
    )
    row = component_maps["triplet"].get(triplet)
    if row:
        return row.id

    if cpe:
        cpe_rows = component_maps["cpe"].get(normalized_key(cpe), [])
        if cpe_rows:
            return cpe_rows[0].id

    return None


# ============================================================
# SBOM Loading
# ============================================================


def load_sbom_from_ref(
    db: Session, sbom_id: int | None = None, sbom_name: str | None = None
) -> tuple[SBOMSource, dict, str, str, list[dict]]:
    """
    Load an SBOM from the database by ID or name and extract its components.

    Args:
        db: Database session
        sbom_id: SBOM ID (if provided)
        sbom_name: SBOM name (if provided)

    Returns:
        Tuple of (sbom_row, sbom_dict, sbom_format, spec_version, components)

    Raises:
        ValueError: If SBOM not found, has no data, or parsing fails
    """
    # Validate input
    if sbom_id is None and not (isinstance(sbom_name, str) and sbom_name.strip()):
        raise ValueError("Provide 'sbom_id' or 'sbom_name'")

    # Lookup by id first (if given)
    sbom_row: SBOMSource | None = None
    if sbom_id is not None:
        try:
            sbom_row = db.get(SBOMSource, int(sbom_id))
        except Exception:
            sbom_row = None
        if sbom_row is None:
            raise ValueError(f"SBOM with id {sbom_id} not found")

    # If not found and name provided, lookup by name
    if sbom_row is None and sbom_name:
        sbom_row = db.execute(select(SBOMSource).where(SBOMSource.sbom_name == sbom_name.strip())).scalars().first()
        if sbom_row is None:
            raise ValueError(f"SBOM with name '{sbom_name}' not found")

    # If both id and name provided, ensure they match the same row
    if sbom_id is not None and sbom_name and sbom_row and sbom_row.sbom_name != sbom_name.strip():
        raise ValueError(f"SBOM mismatch: id={sbom_id} does not match name='{sbom_name}'.")

    # Ensure content present
    if not sbom_row or not sbom_row.sbom_data:
        raise ValueError("SBOM has no sbom_data stored")

    # Parse JSON from stored text/dict
    if isinstance(sbom_row.sbom_data, str):
        try:
            sbom_dict = json.loads(sbom_row.sbom_data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid SBOM JSON in storage: {e}")
    elif isinstance(sbom_row.sbom_data, dict):
        sbom_dict = sbom_row.sbom_data
    else:
        raise ValueError("Unsupported sbom_data type in storage")

    # Extract and detect SBOM format
    try:
        components = extract_components(sbom_dict)
        sbom_format, spec_version = detect_sbom_format(sbom_dict)
    except Exception as e:
        raise ValueError(f"SBOM parsing error: {e}")

    return sbom_row, sbom_dict, sbom_format, spec_version, components
