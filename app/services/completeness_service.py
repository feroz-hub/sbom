"""
SBOM Completeness Validation Service.
Scores SBOM data quality by checking for mandatory fields.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy.orm import Session

from ..models import SBOMSource

log = logging.getLogger(__name__)


def validate_completeness(sbom_json: dict[str, Any]) -> dict[str, Any]:
    """
    Validate the completeness of an SBOM parsed as a dictionary.

    Mandatory fields:
    - Component Name
    - Component Version
    - Component Supplier
    - Component License
    - Component Hash/Checksum
    - Document Dependency Information
    """
    components_details = []
    missing_fields_by_component = []
    document_warnings = []

    is_cyclonedx = sbom_json.get("bomFormat") == "CycloneDX"
    is_spdx = "spdxVersion" in sbom_json or "SPDXID" in sbom_json

    components = []
    has_dependencies = False

    # 1. Extract components and check dependency graphs
    if is_cyclonedx:
        components = sbom_json.get("components") or []
        has_dependencies = len(sbom_json.get("dependencies") or []) > 0
    elif is_spdx:
        components = sbom_json.get("packages") or []
        has_dependencies = any(
            (r.get("relationshipType") or "").upper() in ("DEPENDS_ON", "CONTAINS", "DESCENDANT_OF")
            for r in sbom_json.get("relationships") or []
        )
    else:
        # Fallback best-effort
        components = sbom_json.get("components") or sbom_json.get("packages") or []
        has_dependencies = len(sbom_json.get("dependencies") or sbom_json.get("relationships") or []) > 0

    total_components = len(components)

    # 2. Check document level
    if not has_dependencies:
        document_warnings.append(
            "No dependency relationship declared (CycloneDX `dependencies[]` or SPDX `relationships[]` is missing or empty)."
        )

    # Check creators / authors metadata
    has_author = False
    if is_cyclonedx:
        metadata = sbom_json.get("metadata") or {}
        tools = metadata.get("tools") or {}
        if isinstance(tools, dict):
            tools_present = bool(tools.get("components") or tools.get("services"))
        else:
            tools_present = bool(tools)
        has_author = tools_present or len(metadata.get("authors") or []) > 0
    elif is_spdx:
        creation_info = sbom_json.get("creationInfo") or {}
        has_author = len(creation_info.get("creators") or []) > 0

    if not has_author:
        document_warnings.append("Document has no author / SBOM-data creator.")

    # 3. Check each component
    total_fields_possible = total_components * 5
    total_fields_present = 0

    for i, c in enumerate(components):
        comp_name = c.get("name")
        comp_version = c.get("version")
        bom_ref = c.get("bom-ref") or c.get("bomRef") or c.get("SPDXID") or f"index-{i}"

        # Check supplier
        comp_supplier = None
        if is_cyclonedx:
            supplier_raw = c.get("supplier")
            comp_supplier = supplier_raw.get("name") if isinstance(supplier_raw, dict) else supplier_raw
        elif is_spdx:
            comp_supplier = c.get("supplier") or c.get("originator")

        # Check license
        has_license = False
        if is_cyclonedx:
            licenses_list = c.get("licenses")
            if licenses_list and isinstance(licenses_list, list):
                has_license = len(licenses_list) > 0
        elif is_spdx:
            concluded = c.get("licenseConcluded")
            declared = c.get("licenseDeclared")
            has_license = bool(
                (concluded and concluded != "NOASSERTION" and concluded != "NONE")
                or (declared and declared != "NOASSERTION" and declared != "NONE")
            )

        # Check hash
        has_hash = False
        if is_cyclonedx:
            has_hash = len(c.get("hashes") or []) > 0
        elif is_spdx:
            has_hash = len(c.get("checksums") or []) > 0

        missing = []
        if not comp_name:
            missing.append("name")
        else:
            total_fields_present += 1

        if not comp_version:
            missing.append("version")
        else:
            total_fields_present += 1

        if not comp_supplier:
            missing.append("supplier")
        else:
            total_fields_present += 1

        if not has_license:
            missing.append("license")
        else:
            total_fields_present += 1

        if not has_hash:
            missing.append("hash")
        else:
            total_fields_present += 1

        if missing:
            missing_fields_by_component.append(
                {
                    "bom_ref": bom_ref,
                    "name": comp_name or "unknown",
                    "version": comp_version or "unknown",
                    "missing": missing,
                }
            )

    # Calculate completeness score
    component_weight = total_fields_present / total_fields_possible if total_fields_possible > 0 else 1.0
    doc_weight = 1.0 if has_dependencies else 0.0

    # Combined score
    score = (component_weight * 0.9 + doc_weight * 0.1) * 100.0
    score = round(max(0.0, min(100.0, score)), 1)

    return {
        "completeness_score": score,
        "missing_fields": missing_fields_by_component,
        "document_warnings": document_warnings,
        "total_components": total_components,
        "complete_components": total_components - len(missing_fields_by_component),
    }


def compute_and_save_completeness(db: Session, sbom: SBOMSource) -> dict[str, Any]:
    """
    Compute completeness score for an SBOM source and save it to the DB row.
    """
    if not sbom.sbom_data:
        return {"completeness_score": 0.0, "missing_fields": [], "document_warnings": ["No SBOM data stored."]}

    try:
        sbom_json = json.loads(sbom.sbom_data) if isinstance(sbom.sbom_data, str) else sbom.sbom_data
        report = validate_completeness(sbom_json)

        # Save to DB row
        sbom.completeness_score = report["completeness_score"]
        sbom.completeness_report = report
        db.add(sbom)
        db.commit()
        db.refresh(sbom)
        return report
    except Exception as e:
        log.exception("compute_and_save_completeness: failed for sbom_id=%d", sbom.id)
        return {
            "completeness_score": 0.0,
            "missing_fields": [],
            "document_warnings": [f"Failed to parse SBOM JSON for completeness validation: {e}"],
        }
