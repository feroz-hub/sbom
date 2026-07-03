"""
SBOM Version Control & Editing Service.
Handles editing SBOM components/metadata, versioning (parent-child lineages),
comparing different versions, and restoring previous versions.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AuditLog, SBOMComponent, SBOMSource
from ..validation import run as run_validation
from .completeness_service import compute_and_save_completeness
from .lifecycle.types import DEPRECATED, canonical_status, now_iso
from .lifecycle.vex_provider import process_embedded_vex_for_sbom
from .lifecycle_service import sync_lifecycle_for_sbom
from .sbom_service import _upsert_components

log = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _apply_lifecycle_update(comp: SBOMComponent, update: dict[str, Any]) -> None:
    """Apply only lifecycle fields that were explicitly provided by the edit payload."""
    if "lifecycle_status" in update:
        comp.lifecycle_status = canonical_status(update.get("lifecycle_status"))
    if "eos_date" in update:
        comp.eos_date = update.get("eos_date")
    if "eol_date" in update:
        comp.eol_date = update.get("eol_date")
    if "eof_date" in update:
        comp.eof_date = update.get("eof_date")
    if "is_deprecated" in update:
        comp.is_deprecated = update.get("is_deprecated")
    if "deprecated" in update:
        comp.deprecated = update.get("deprecated")
        comp.is_deprecated = bool(comp.deprecated)
    if "maintenance_status" in update:
        comp.maintenance_status = update.get("maintenance_status")
    if "latest_supported_version" in update:
        comp.latest_supported_version = update.get("latest_supported_version")
    if "recommended_version" in update:
        comp.recommended_version = update.get("recommended_version")
    if "recommendation" in update or "lifecycle_recommendation" in update:
        comp.lifecycle_recommendation = update.get("recommendation") or update.get("lifecycle_recommendation")

    evidence_url = update.get("evidence_url") or update.get("lifecycle_source_url")
    if evidence_url:
        comp.lifecycle_source_url = evidence_url
    if update.get("reason") or update.get("note") or evidence_url:
        comp.lifecycle_evidence_json = {
            "reason": update.get("reason") or update.get("note"),
            "evidence_url": evidence_url,
        }
    if update:
        comp.lifecycle_source = update.get("lifecycle_source") or "Manual Override"
        comp.lifecycle_confidence = "High" if evidence_url else "Medium"
        comp.lifecycle_checked_at = now_iso()
        comp.lifecycle_manual_override = True
        comp.lifecycle_is_stale = False
        if canonical_status(comp.lifecycle_status) == DEPRECATED:
            comp.deprecated = True
            comp.is_deprecated = True


def _copy_lifecycle_fields(target: SBOMComponent, source: SBOMComponent) -> None:
    """Copy lifecycle enrichment fields across SBOM versions."""
    target.ecosystem = source.ecosystem
    target.lifecycle_status = source.lifecycle_status
    target.eos_date = source.eos_date
    target.eol_date = source.eol_date
    target.eof_date = source.eof_date
    target.is_deprecated = source.is_deprecated
    target.deprecated = source.deprecated
    target.maintenance_status = source.maintenance_status
    target.latest_supported_version = source.latest_supported_version
    target.recommended_version = source.recommended_version
    target.lifecycle_recommendation = source.lifecycle_recommendation
    target.lifecycle_source = source.lifecycle_source
    target.lifecycle_source_url = source.lifecycle_source_url
    target.lifecycle_confidence = source.lifecycle_confidence
    target.lifecycle_checked_at = source.lifecycle_checked_at
    target.lifecycle_evidence_json = source.lifecycle_evidence_json
    target.lifecycle_is_stale = source.lifecycle_is_stale
    target.lifecycle_manual_override = source.lifecycle_manual_override


def apply_edits_to_json(sbom_json: dict[str, Any], updates: dict[str, Any]) -> dict[str, Any]:
    """
    Mutate the parsed SBOM dict according to the specified updates.

    updates format:
    {
        "metadata": { "sbom_name": "New Name", "sbom_version": "1.0.2" },
        "components": [
            {
                "bom_ref": "pkg:maven/org.jruby.extras/bytelist@1.0.3",
                "name": "bytelist-edited",
                "version": "1.0.4",
                "supplier": "New Supplier",
                "license": "MIT",
                "hashes": "0c53bed34ab24f083fc55f6a896d2f2b474b08d0"
            }
        ]
    }
    """
    doc = dict(sbom_json)
    is_cyclonedx = doc.get("bomFormat") == "CycloneDX"
    is_spdx = "spdxVersion" in doc or "SPDXID" in doc

    # 1. Update metadata
    meta_updates = updates.get("metadata") or {}
    if meta_updates:
        if is_cyclonedx:
            metadata = doc.setdefault("metadata", {})
            comp = metadata.setdefault("component", {})
            if "sbom_name" in meta_updates:
                comp["name"] = meta_updates["sbom_name"]
            if "sbom_version" in meta_updates:
                comp["version"] = meta_updates["sbom_version"]
        elif is_spdx:
            if "sbom_name" in meta_updates:
                doc["name"] = meta_updates["sbom_name"]
            if "sbom_version" in meta_updates:
                doc["versionInfo"] = meta_updates["sbom_version"]

    # 2. Update components
    comp_updates = updates.get("components") or []
    if comp_updates:
        comp_map = {c["bom_ref"]: c for c in comp_updates if "bom_ref" in c}

        if is_cyclonedx:
            components = doc.setdefault("components", [])
            for c in components:
                ref = c.get("bom-ref") or c.get("bomRef")
                if ref in comp_map:
                    u = comp_map[ref]
                    if "name" in u:
                        c["name"] = u["name"]
                    if "version" in u:
                        c["version"] = u["version"]
                    if "supplier" in u:
                        c["supplier"] = {"name": u["supplier"]}
                    if "license" in u:
                        c["licenses"] = [{"license": {"name": u["license"]}}]
                    if "hashes" in u:
                        # Represent hash as SHA-256 for CycloneDX
                        c["hashes"] = [{"alg": "SHA-256", "content": u["hashes"]}]
        elif is_spdx:
            packages = doc.setdefault("packages", [])
            for pkg in packages:
                ref = pkg.get("SPDXID")
                if ref in comp_map:
                    u = comp_map[ref]
                    if "name" in u:
                        pkg["name"] = u["name"]
                    if "version" in u:
                        pkg["versionInfo"] = u["version"]
                    if "supplier" in u:
                        pkg["supplier"] = f"Organization: {u['supplier']}"
                    if "license" in u:
                        pkg["licenseConcluded"] = u["license"]
                        pkg["licenseDeclared"] = u["license"]
                    if "hashes" in u:
                        pkg["checksums"] = [{"algorithm": "SHA256", "checksumValue": u["hashes"]}]

    return doc


def reapply_edit_lifecycle_overrides(
    db: Session,
    sbom_id: int,
    override_map: dict[str, dict[str, Any]],
) -> None:
    """Re-apply explicit lifecycle overrides after provider enrichment."""

    if not override_map:
        return

    components = db.execute(select(SBOMComponent).where(SBOMComponent.sbom_id == sbom_id)).scalars().all()
    for comp in components:
        if comp.bom_ref in override_map:
            _apply_lifecycle_update(comp, override_map[comp.bom_ref])
            db.add(comp)
    db.commit()


def edit_sbom(
    db: Session,
    sbom_id: int,
    user_id: str | None,
    updates: dict[str, Any],
    change_summary: str,
    *,
    defer_enrichment: bool = False,
) -> SBOMSource:
    """
    Perform an edit on an SBOM.
    Clones the parent, applies edits to the JSON payload, validates,
    and inserts as a new version.
    """
    parent = db.get(SBOMSource, sbom_id)
    if not parent:
        raise ValueError(f"Parent SBOM with ID {sbom_id} not found")

    try:
        sbom_dict = json.loads(parent.sbom_data) if isinstance(parent.sbom_data, str) else parent.sbom_data
    except Exception as e:
        raise ValueError(f"Failed to parse original SBOM JSON: {e}")

    # Apply edits
    new_dict = apply_edits_to_json(sbom_dict, updates)
    new_data_str = json.dumps(new_dict)

    # Run validation pipeline on the new JSON string
    report = run_validation(new_data_str.encode("utf-8"))

    sbom_status = "validated"
    if report.has_errors():
        sbom_status = "quarantined" if any(e.stage == "security" for e in report.errors) else "failed"

    # Increment version number
    current_ver_str = parent.sbom_version or "1.0.0"
    try:
        parts = current_ver_str.split(".")
        if len(parts) == 3:
            parts[2] = str(int(parts[2]) + 1)
            new_version_str = ".".join(parts)
        else:
            new_version_str = f"{current_ver_str}.1"
    except Exception:
        new_version_str = f"{current_ver_str}-revised"

    # Create the new SBOMSource row
    new_sbom = SBOMSource(
        sbom_name=parent.sbom_name,
        sbom_data=new_data_str,
        sbom_type=parent.sbom_type,
        projectid=parent.projectid,
        product_id=parent.product_id,
        created_by=user_id,
        created_on=_now_iso(),
        sbom_version=new_version_str,
        productver=parent.productver,
        product_name=parent.product_name,
        description=parent.description,
        status=sbom_status,
        failed_stage=report.first_error_stage,
        validation_errors=[e.model_dump() for e in report.entries] if report.entries else None,
        error_count=report.error_count,
        warning_count=report.warning_count,
        validated_at=_now_iso(),
        parent_id=parent.id,
        change_summary=change_summary,
    )

    db.add(new_sbom)
    db.commit()
    db.refresh(new_sbom)

    # 3. Synchronize components for the new version
    from ..analysis import extract_components

    try:
        components_list = extract_components(new_dict)
        _upsert_components(db, new_sbom, components_list)
    except Exception as e:
        log.warning("Component extraction failed for edited SBOM id=%d: %s", new_sbom.id, e)

    # 4. Map and carry forward manual lifecycle status of unmodified components
    # If a component was not modified, copy its lifecycle status from the parent's component!
    parent_components = db.execute(select(SBOMComponent).where(SBOMComponent.sbom_id == parent.id)).scalars().all()

    parent_lifecycle = {(c.name.lower(), c.version): c for c in parent_components if c.lifecycle_status}

    # Apply these to the new component rows
    new_components = db.execute(select(SBOMComponent).where(SBOMComponent.sbom_id == new_sbom.id)).scalars().all()

    # If the component was edited, check if updates carried any lifecycle overrides.
    # Otherwise, carry forward the parent's lifecycle parameters if they exist.
    override_map = {}
    for comp_up in updates.get("components") or []:
        if "bom_ref" in comp_up and "lifecycle" in comp_up:
            override_map[comp_up["bom_ref"]] = comp_up["lifecycle"]

    for comp in new_components:
        # Check explicit lifecycle override in the edit payload
        if comp.bom_ref in override_map:
            _apply_lifecycle_update(comp, override_map[comp.bom_ref])
            db.add(comp)
        else:
            # Carry forward parent's status
            key = (comp.name.lower(), comp.version)
            if key in parent_lifecycle:
                _copy_lifecycle_fields(comp, parent_lifecycle[key])
                db.add(comp)

    db.commit()

    if defer_enrichment:
        from .sbom_enrichment_service import mark_enrichment_pending

        mark_enrichment_pending(new_sbom)
        db.commit()
    else:
        # Run lifecycle backfill for new/modified components that have no lifecycle state
        sync_lifecycle_for_sbom(db, new_sbom.id)
        process_embedded_vex_for_sbom(db, new_sbom.id)

        if override_map:
            reapply_edit_lifecycle_overrides(db, new_sbom.id, override_map)

        # Re-run completeness validation
        compute_and_save_completeness(db, new_sbom)

    # Log audit entry
    db.add(
        AuditLog(
            user_id=user_id,
            action="sbom.edit",
            target_kind="sbom",
            target_id=new_sbom.id,
            detail=f"Edited SBOM version {new_version_str} ({change_summary})",
            metadata_json={"parent_id": parent.id, "version": new_version_str},
            created_at=_now_iso(),
        )
    )
    db.commit()

    return new_sbom


def compare_versions(db: Session, sbom_a_id: int, sbom_b_id: int) -> dict[str, Any]:
    """
    Compare two SBOM versions and identify added, removed, and modified components.
    """
    comps_a = db.execute(select(SBOMComponent).where(SBOMComponent.sbom_id == sbom_a_id)).scalars().all()
    comps_b = db.execute(select(SBOMComponent).where(SBOMComponent.sbom_id == sbom_b_id)).scalars().all()

    def component_key(component: SBOMComponent) -> str:
        if component.bom_ref:
            return f"ref:{component.bom_ref}"
        return f"name:{component.name.lower()}:{component.version or ''}"

    def component_summary(component: SBOMComponent) -> dict[str, Any]:
        return {
            "bom_ref": component.bom_ref,
            "name": component.name,
            "version": component.version,
            "purl": component.purl,
            "ecosystem": component.ecosystem,
            "supplier": component.supplier,
            "license": component.license,
            "hashes": component.hashes,
            "lifecycle_status": component.lifecycle_status,
            "eos_date": component.eos_date,
            "eol_date": component.eol_date,
            "eof_date": component.eof_date,
            "is_deprecated": bool(component.is_deprecated),
            "deprecated": bool(component.deprecated or component.is_deprecated),
            "maintenance_status": component.maintenance_status,
            "latest_supported_version": component.latest_supported_version,
            "recommended_version": component.recommended_version,
            "lifecycle_recommendation": component.lifecycle_recommendation,
            "lifecycle_source": component.lifecycle_source,
            "lifecycle_source_url": component.lifecycle_source_url,
            "lifecycle_confidence": component.lifecycle_confidence,
            "lifecycle_is_stale": bool(component.lifecycle_is_stale),
            "lifecycle_manual_override": bool(component.lifecycle_manual_override),
        }

    def load_document(sbom_id: int) -> dict[str, Any]:
        sbom = db.get(SBOMSource, sbom_id)
        if not sbom or not sbom.sbom_data:
            return {}
        if isinstance(sbom.sbom_data, dict):
            return sbom.sbom_data
        try:
            parsed = json.loads(sbom.sbom_data)
        except (TypeError, json.JSONDecodeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def metadata_view(doc: dict[str, Any]) -> dict[str, Any]:
        if str(doc.get("bomFormat") or "").lower() == "cyclonedx":
            metadata = doc.get("metadata")
            return metadata if isinstance(metadata, dict) else {}
        if "spdxVersion" in doc or "SPDXID" in doc:
            return {
                key: value
                for key, value in doc.items()
                if key not in {"packages", "relationships", "snippets", "files", "annotations"}
            }
        return {}

    def top_level_diff(old: dict[str, Any], new: dict[str, Any]) -> dict[str, dict[str, Any]]:
        changes = {}
        for key in sorted(set(old) | set(new)):
            old_value = old.get(key)
            new_value = new.get(key)
            if json.dumps(old_value, sort_keys=True, default=str) != json.dumps(new_value, sort_keys=True, default=str):
                changes[key] = {"old": old_value, "new": new_value}
        return changes

    def dependency_view(doc: dict[str, Any]) -> dict[str, set[str]]:
        deps: dict[str, set[str]] = {}
        if str(doc.get("bomFormat") or "").lower() == "cyclonedx":
            for dep in doc.get("dependencies") or []:
                if not isinstance(dep, dict):
                    continue
                ref = dep.get("ref") or dep.get("bom-ref") or dep.get("bomRef")
                if not ref:
                    continue
                depends_on = dep.get("dependsOn") or []
                if isinstance(depends_on, str):
                    depends_on = [depends_on]
                deps[str(ref)] = {str(item) for item in depends_on if item}
        elif "spdxVersion" in doc or "SPDXID" in doc:
            for rel in doc.get("relationships") or []:
                if not isinstance(rel, dict):
                    continue
                rel_type = str(rel.get("relationshipType") or "").upper()
                left = rel.get("spdxElementId") or rel.get("spdxElementID")
                right = rel.get("relatedSpdxElement") or rel.get("relatedSpdxElementID")
                if not left or not right:
                    continue
                if rel_type == "DEPENDS_ON":
                    deps.setdefault(str(left), set()).add(str(right))
                elif rel_type == "DEPENDENCY_OF":
                    deps.setdefault(str(right), set()).add(str(left))
        return deps

    def dependency_diff(old: dict[str, set[str]], new: dict[str, set[str]]) -> dict[str, Any]:
        added = sorted(set(new) - set(old))
        removed = sorted(set(old) - set(new))
        changed = []
        for ref in sorted(set(old) & set(new)):
            added_deps = sorted(new[ref] - old[ref])
            removed_deps = sorted(old[ref] - new[ref])
            if added_deps or removed_deps:
                changed.append(
                    {
                        "ref": ref,
                        "added_dependencies": added_deps,
                        "removed_dependencies": removed_deps,
                    }
                )
        return {"added": added, "removed": removed, "changed": changed}

    # Map components by bom_ref, falling back to name + version when no ref exists.
    map_a = {component_key(c): c for c in comps_a}
    map_b = {component_key(c): c for c in comps_b}

    added = []
    removed = []
    changed = []

    for key, cb in map_b.items():
        if key not in map_a:
            added.append(component_summary(cb))
            continue

        ca = map_a[key]
        old_summary = component_summary(ca)
        new_summary = component_summary(cb)
        diffs = top_level_diff(old_summary, new_summary)
        if diffs:
            changed.append(
                {
                    **new_summary,
                    "changes": diffs,
                }
            )

    for key, ca in map_a.items():
        if key not in map_b:
            removed.append(component_summary(ca))

    doc_a = load_document(sbom_a_id)
    doc_b = load_document(sbom_b_id)
    metadata_changes = top_level_diff(metadata_view(doc_a), metadata_view(doc_b))
    dependency_changes = dependency_diff(dependency_view(doc_a), dependency_view(doc_b))

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "metadata_changes": metadata_changes,
        "dependency_changes": dependency_changes,
        "total_added": len(added),
        "total_removed": len(removed),
        "total_changed": len(changed),
    }


def restore_version(db: Session, sbom_id: int, restore_version_id: int, user_id: str | None) -> SBOMSource:
    """
    Restore a previous version by cloning its JSON data and inserting it as a new version.
    """
    target = db.get(SBOMSource, restore_version_id)
    if not target:
        raise ValueError(f"Restoration target version ID {restore_version_id} not found")

    parent = db.get(SBOMSource, sbom_id)
    if not parent:
        raise ValueError(f"Current version SBOM ID {sbom_id} not found")

    change_summary = f"Restored previous version {target.sbom_version} (created on {target.created_on})"

    # Increment version number from current parent version
    current_ver_str = parent.sbom_version or "1.0.0"
    try:
        parts = current_ver_str.split(".")
        if len(parts) == 3:
            parts[2] = str(int(parts[2]) + 1)
            new_version_str = ".".join(parts)
        else:
            new_version_str = f"{current_ver_str}.1"
    except Exception:
        new_version_str = f"{current_ver_str}-revised"

    # Create the new SBOMSource row using target's data
    new_sbom = SBOMSource(
        sbom_name=parent.sbom_name,
        sbom_data=target.sbom_data,
        sbom_type=parent.sbom_type,
        projectid=parent.projectid,
        product_id=parent.product_id,
        created_by=user_id,
        created_on=_now_iso(),
        sbom_version=new_version_str,
        productver=target.productver,
        product_name=target.product_name,
        description=target.description,
        status=target.status,
        failed_stage=target.failed_stage,
        validation_errors=target.validation_errors,
        error_count=target.error_count,
        warning_count=target.warning_count,
        validated_at=_now_iso(),
        parent_id=parent.id,
        change_summary=change_summary,
    )

    db.add(new_sbom)
    db.commit()
    db.refresh(new_sbom)

    # Extract and insert components for the restored version
    try:
        target_dict = json.loads(target.sbom_data) if isinstance(target.sbom_data, str) else target.sbom_data
        from ..analysis import extract_components

        components_list = extract_components(target_dict)
        _upsert_components(db, new_sbom, components_list)
    except Exception as e:
        log.warning("Component extraction failed for restored SBOM id=%d: %s", new_sbom.id, e)

    # Copy lifecycle status from target's components
    target_components = db.execute(select(SBOMComponent).where(SBOMComponent.sbom_id == target.id)).scalars().all()

    new_components = db.execute(select(SBOMComponent).where(SBOMComponent.sbom_id == new_sbom.id)).scalars().all()

    target_lifecycle = {(c.name.lower(), c.version): c for c in target_components}

    for comp in new_components:
        key = (comp.name.lower(), comp.version)
        if key in target_lifecycle:
            _copy_lifecycle_fields(comp, target_lifecycle[key])
            db.add(comp)

    db.commit()

    # Re-run completeness validation
    compute_and_save_completeness(db, new_sbom)

    # Log audit entry
    db.add(
        AuditLog(
            user_id=user_id,
            action="sbom.restore",
            target_kind="sbom",
            target_id=new_sbom.id,
            detail=f"Restored SBOM to version {new_version_str} (from version {target.sbom_version})",
            metadata_json={"parent_id": parent.id, "target_version_id": target.id, "version": new_version_str},
            created_at=_now_iso(),
        )
    )
    db.commit()

    return new_sbom
