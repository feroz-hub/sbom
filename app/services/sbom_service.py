"""
SBOM Service Layer - Business logic for SBOM handling and component management.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..analysis import extract_components
from ..db import SessionLocal
from ..models import SBOMComponent, SBOMSource

log = logging.getLogger(__name__)


# ============================================================
# Utility Functions
# ============================================================

def now_iso() -> str:
    """Get current UTC time in ISO format without microseconds."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalized_key(value: Optional[str]) -> str:
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

def coerce_sbom_data(value: Any) -> Optional[str]:
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

def sync_sbom_components(db: Session, sbom_obj: SBOMSource) -> List[Dict]:
    """
    Extract components from SBOM data and upsert them into the database.

    Args:
        db: Database session
        sbom_obj: SBOM source object containing sbom_data

    Returns:
        List of extracted component dictionaries
    """
    if not sbom_obj.sbom_data:
        return []

    components = extract_components(sbom_obj.sbom_data)
    _upsert_components(db, sbom_obj, components)
    return components


def _upsert_components(db: Session, sbom_obj: SBOMSource, components: List[Dict]) -> Dict:
    """
    Internal: Upsert components into the database, avoiding duplicates.

    Args:
        db: Database session
        sbom_obj: SBOM source object
        components: List of component dictionaries

    Returns:
        Dictionary with 'triplet' and 'cpe' maps for lookup
    """
    existing_rows = db.execute(
        select(SBOMComponent).where(SBOMComponent.sbom_id == sbom_obj.id)
    ).scalars().all()

    by_comp_triplet: Dict = {}
    by_cpe: Dict = {}

    # Build lookup maps from existing components
    for row in existing_rows:
        triplet = (
            normalized_key(row.cpe),
            normalized_key(row.name),
            normalized_key(row.version),
        )
        by_comp_triplet.setdefault(triplet, row)
        if row.cpe:
            by_cpe.setdefault(normalized_key(row.cpe), []).append(row)

    # Upsert new components
    for comp in components:
        name = (comp.get("name") or "").strip()
        if not name:
            fallback = (comp.get("bom_ref") or comp.get("purl") or comp.get("cpe") or "component").strip()
            name = fallback[:255] if fallback else "component"

        version = (comp.get("version") or "").strip() or None
        cpe = (comp.get("cpe") or "").strip() or None
        triplet = (normalized_key(cpe), normalized_key(name), normalized_key(version))

        if triplet in by_comp_triplet:
            continue

        row = SBOMComponent(
            sbom_id=sbom_obj.id,
            bom_ref=(comp.get("bom_ref") or "").strip() or None,
            component_type=(comp.get("type") or "").strip() or None,
            component_group=(comp.get("group") or "").strip() or None,
            name=name,
            version=version,
            purl=(comp.get("purl") or "").strip() or None,
            cpe=cpe,
            supplier=(comp.get("supplier") or "").strip() or None,
            scope=(comp.get("scope") or "").strip() or None,
            created_on=now_iso(),
        )
        db.add(row)
        db.flush()

        by_comp_triplet[triplet] = row
        if cpe:
            by_cpe.setdefault(normalized_key(cpe), []).append(row)

    return {"triplet": by_comp_triplet, "cpe": by_cpe}


def resolve_component_id(finding: Dict, component_maps: Dict) -> Optional[int]:
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
    db: Session,
    sbom_id: Optional[int] = None,
    sbom_name: Optional[str] = None
) -> Tuple[SBOMSource, Dict, str, str, List[Dict]]:
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
    sbom_row: Optional[SBOMSource] = None
    if sbom_id is not None:
        try:
            sbom_row = db.get(SBOMSource, int(sbom_id))
        except Exception:
            sbom_row = None
        if sbom_row is None:
            raise ValueError(f"SBOM with id {sbom_id} not found")

    # If not found and name provided, lookup by name
    if sbom_row is None and sbom_name:
        sbom_row = db.execute(
            select(SBOMSource).where(SBOMSource.sbom_name == sbom_name.strip())
        ).scalars().first()
        if sbom_row is None:
            raise ValueError(f"SBOM with name '{sbom_name}' not found")

    # If both id and name provided, ensure they match the same row
    if sbom_id is not None and sbom_name and sbom_row and sbom_row.sbom_name != sbom_name.strip():
        raise ValueError(
            f"SBOM mismatch: id={sbom_id} does not match name='{sbom_name}'."
        )

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
        sbom_format, spec_version = _detect_sbom_format(sbom_dict)
    except Exception as e:
        raise ValueError(f"SBOM parsing error: {e}")

    return sbom_row, sbom_dict, sbom_format, spec_version, components


def _detect_sbom_format(sbom: Dict[str, Any]) -> Tuple[str, str]:
    """
    Detect SBOM format (CycloneDX or SPDX) and return format and version.

    Args:
        sbom: Parsed SBOM dictionary

    Returns:
        Tuple of (format, version) where format is 'cyclonedx' or 'spdx'

    Raises:
        ValueError: If format cannot be detected
    """
    # CycloneDX indicators
    if (isinstance(sbom.get("bomFormat"), str) and sbom.get("bomFormat").lower() == "cyclonedx") \
       or ("components" in sbom and isinstance(sbom["components"], list)):
        version_str = sbom.get("specVersion") or sbom.get("version") or "unknown"
        return "cyclonedx", str(version_str)

    # SPDX indicators
    if "spdxVersion" in sbom or "packages" in sbom:
        version_str = sbom.get("spdxVersion", "unknown")
        return "spdx", str(version_str)

    raise ValueError(
        "Unable to detect SBOM format. Expected CycloneDX (bomFormat/components) or SPDX (spdxVersion/packages)."
    )
