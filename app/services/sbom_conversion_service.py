"""SPDX to CycloneDX conversion service.

Converts validated SPDX JSON documents into CycloneDX 1.6 JSON while preserving
maximum SPDX traceability via component properties and conversion warnings.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from ..validation import run as run_validation

_CONVERSION_TOOL = "SBOM Analyzer"
_TARGET_SPEC_VERSION = "1.6"

# SPDX checksum algorithm → CycloneDX hash algorithm
_CHECKSUM_ALG_MAP = {
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
    "sha3-256": "SHA3-256",
    "sha3-384": "SHA3-384",
    "sha3-512": "SHA3-512",
    "md5": "MD5",
    "md2": "MD2",
    "md4": "MD4",
    "md6": "MD6",
    "blake2b-256": "BLAKE2b-256",
    "blake2b-384": "BLAKE2b-384",
    "blake2b-512": "BLAKE2b-512",
    "blake3": "BLAKE3",
}

# SPDX relationship types that map to CycloneDX dependencies
_DEPENDENCY_REL_TYPES = frozenset({"DEPENDS_ON", "DEPENDENCY_OF", "CONTAINS"})
# Relationship types preserved as properties when not mappable to dependencies
_PROPERTY_REL_TYPES = frozenset({"GENERATED_FROM", "PACKAGE_OF"})
# DESCRIBES from document → package becomes dependency edge
_DESCRIBES_REL = "DESCRIBES"

_SUPPORTED_HASH_ALGS = set(_CHECKSUM_ALG_MAP.values())


class ConversionResult(BaseModel):
    cyclonedx_bom: dict[str, Any]
    conversion_warnings: list[str] = Field(default_factory=list)
    conversion_errors: list[str] = Field(default_factory=list)
    source_format: str = "SPDX"
    target_format: str = "CycloneDX"
    component_mapping: dict[str, str] = Field(default_factory=dict)
    relationship_mapping: list[dict[str, Any]] = Field(default_factory=list)
    unmapped_fields: list[str] = Field(default_factory=list)


@dataclass
class _ConversionState:
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    component_mapping: dict[str, str] = field(default_factory=dict)
    relationship_mapping: list[dict[str, Any]] = field(default_factory=list)
    unmapped_fields: list[str] = field(default_factory=list)
    bom_refs: dict[str, str] = field(default_factory=dict)  # spdx_id -> bom-ref
    used_bom_refs: set[str] = field(default_factory=set)


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _sanitize_bom_ref(spdx_id: str, state: _ConversionState) -> str:
    """Return a stable, unique bom-ref derived from an SPDXID."""
    base = re.sub(r"[^A-Za-z0-9._\-:]+", "-", spdx_id.strip())
    if not base:
        base = "component"
    candidate = base
    suffix = 1
    while candidate in state.used_bom_refs:
        candidate = f"{base}-{suffix}"
        suffix += 1
    state.used_bom_refs.add(candidate)
    return candidate


def _parse_supplier(raw: str | None) -> dict[str, str] | None:
    if not raw or raw in ("NOASSERTION", "NONE"):
        return None
    name = raw
    for prefix in ("Organization: ", "Person: ", "Tool: "):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    return {"name": name.strip()} if name.strip() else None


def _map_checksums(checksums: list[Any], state: _ConversionState, path: str) -> list[dict[str, str]]:
    hashes: list[dict[str, str]] = []
    for chk in checksums or []:
        if not isinstance(chk, dict):
            continue
        alg_raw = chk.get("algorithm")
        value = chk.get("checksumValue")
        if not isinstance(alg_raw, str) or not isinstance(value, str):
            continue
        alg = _CHECKSUM_ALG_MAP.get(alg_raw.lower().replace("_", "-"))
        if alg:
            hashes.append({"alg": alg, "content": value})
        else:
            state.warnings.append(
                f"Unsupported SPDX checksum algorithm '{alg_raw}' at {path}; checksum skipped."
            )
    return hashes


def _map_license_declared(license_declared: str | None) -> list[dict[str, Any]]:
    if not license_declared or license_declared in ("NOASSERTION", "NONE"):
        return []
    return [{"expression": license_declared}]


def _map_external_refs(
    external_refs: list[Any],
    state: _ConversionState,
    path: str,
) -> tuple[str | None, str | None, list[dict[str, Any]], list[dict[str, str]]]:
    purl: str | None = None
    cpe: str | None = None
    external_references: list[dict[str, Any]] = []
    extra_properties: list[dict[str, str]] = []

    for ref in external_refs or []:
        if not isinstance(ref, dict):
            continue
        category = (ref.get("referenceCategory") or "").upper()
        rtype = (ref.get("referenceType") or "").lower()
        locator = ref.get("referenceLocator")
        if not isinstance(locator, str):
            continue
        if category == "PACKAGE-MANAGER" and rtype == "purl":
            purl = locator
        elif "cpe" in rtype:
            if locator.startswith("cpe:"):
                cpe = locator
            else:
                extra_properties.append({"name": "spdx:cpe", "value": locator})
        elif category in {"SECURITY", "PACKAGE-MANAGER", "PERSISTENT-ID", "OTHER"}:
            external_references.append(
                {
                    "type": rtype or "other",
                    "url": locator,
                }
            )
        else:
            state.warnings.append(f"Unsupported SPDX external reference at {path}: {rtype}={locator}")
            extra_properties.append({"name": f"spdx:externalRef:{rtype}", "value": locator})

    return purl, cpe, external_references, extra_properties


def _component_properties(pkg: dict[str, Any], spdx_id: str, bom_ref: str) -> list[dict[str, str]]:
    props: list[dict[str, str]] = [
        {"name": "spdx:SPDXID", "value": spdx_id},
    ]
    for spdx_key, prop_name in (
        ("licenseConcluded", "spdx:licenseConcluded"),
        ("licenseDeclared", "spdx:licenseDeclared"),
        ("downloadLocation", "spdx:downloadLocation"),
        ("filesAnalyzed", "spdx:filesAnalyzed"),
    ):
        value = pkg.get(spdx_key)
        if value is not None and value not in ("NOASSERTION", "NONE", ""):
            props.append({"name": prop_name, "value": str(value)})
    props.append({"name": "conversion:sourceFormat", "value": "SPDX"})
    props.append({"name": "conversion:targetFormat", "value": "CycloneDX"})
    return props


def _map_package_to_component(
    pkg: dict[str, Any],
    index: int,
    state: _ConversionState,
) -> dict[str, Any]:
    spdx_id = pkg.get("SPDXID")
    if not isinstance(spdx_id, str):
        spdx_id = f"SPDXRef-Package-{index}"
        state.warnings.append(f"Package at packages[{index}] missing SPDXID; generated '{spdx_id}'.")

    bom_ref = _sanitize_bom_ref(spdx_id, state)
    state.component_mapping[spdx_id] = bom_ref
    state.bom_refs[spdx_id] = bom_ref

    path = f"packages[{index}]"
    purl, cpe, external_refs, extra_props = _map_external_refs(pkg.get("externalRefs") or [], state, path)

    if not purl and not cpe:
        state.warnings.append(f"SPDX package '{pkg.get('name')}' at {path} has no PURL or CPE identifier.")

    version = pkg.get("versionInfo")
    if not version or version in ("NOASSERTION", "NONE"):
        state.warnings.append(f"SPDX package '{pkg.get('name')}' at {path} has no version.")

    name = pkg.get("name") or spdx_id
    component: dict[str, Any] = {
        "type": "library",
        "bom-ref": bom_ref,
        "name": name,
    }
    if version and version not in ("NOASSERTION", "NONE"):
        component["version"] = version
    if purl:
        component["purl"] = purl
    if cpe:
        component["cpe"] = cpe

    supplier = _parse_supplier(pkg.get("supplier") if isinstance(pkg.get("supplier"), str) else None)
    if supplier:
        component["supplier"] = supplier

    licenses = _map_license_declared(pkg.get("licenseDeclared") if isinstance(pkg.get("licenseDeclared"), str) else None)
    if licenses:
        expr = licenses[0].get("expression", "")
        if " " in expr or expr.startswith("("):
            state.warnings.append(
                f"SPDX license expression '{expr}' at {path} stored as CycloneDX expression; "
                "complex SPDX-only constructs may not round-trip."
            )
        component["licenses"] = licenses

    license_concluded = pkg.get("licenseConcluded")
    if isinstance(license_concluded, str) and license_concluded not in ("NOASSERTION", "NONE"):
        if " " in license_concluded or license_concluded.startswith("("):
            state.warnings.append(
                f"SPDX licenseConcluded expression at {path} preserved as property only."
            )

    hashes = _map_checksums(pkg.get("checksums") or [], state, path)
    if hashes:
        component["hashes"] = hashes

    download_location = pkg.get("downloadLocation")
    if isinstance(download_location, str) and download_location not in ("NOASSERTION", "NONE"):
        external_refs.append({"type": "distribution", "url": download_location})

    homepage = pkg.get("homepage")
    if isinstance(homepage, str) and homepage not in ("NOASSERTION", "NONE"):
        external_refs.append({"type": "website", "url": homepage})

    if external_refs:
        component["externalReferences"] = external_refs

    summary = pkg.get("summary") or pkg.get("description")
    if isinstance(summary, str) and summary not in ("NOASSERTION", "NONE"):
        component["description"] = summary

    props = _component_properties(pkg, spdx_id, bom_ref) + extra_props
    component["properties"] = props
    return component


def _map_relationships(
    spdx_data: dict[str, Any],
    doc_spdx_id: str,
    doc_bom_ref: str,
    state: _ConversionState,
) -> list[dict[str, Any]]:
    """Map SPDX relationships to CycloneDX dependencies."""
    deps_by_ref: dict[str, set[str]] = {}
    all_package_refs = set(state.bom_refs.keys())

    def _resolve_ref(spdx_ref: str) -> str | None:
        if spdx_ref == doc_spdx_id:
            return doc_bom_ref
        return state.bom_refs.get(spdx_ref)

    def _add_dep(source_ref: str, target_ref: str, rel_type: str) -> None:
        if source_ref not in deps_by_ref:
            deps_by_ref[source_ref] = set()
        deps_by_ref[source_ref].add(target_ref)
        state.relationship_mapping.append(
            {
                "spdx_relationship_type": rel_type,
                "source": source_ref,
                "target": target_ref,
                "mapped_to": "dependency",
            }
        )

    for index, rel in enumerate(spdx_data.get("relationships") or []):
        if not isinstance(rel, dict):
            continue
        source = rel.get("spdxElementId")
        target = rel.get("relatedSpdxElement")
        rel_type = (rel.get("relationshipType") or "RELATES_TO").upper()
        if not isinstance(source, str) or not isinstance(target, str):
            state.warnings.append(f"Malformed relationship at relationships[{index}]; skipped.")
            continue

        source_ref = _resolve_ref(source)
        target_ref = _resolve_ref(target)

        if rel_type == _DESCRIBES_REL:
            if source == doc_spdx_id and target in state.bom_refs:
                if source_ref and target_ref:
                    _add_dep(source_ref, target_ref, rel_type)
            else:
                state.warnings.append(
                    f"SPDX DESCRIBES relationship at relationships[{index}] outside document scope; "
                    "preserved as property."
                )
                state.relationship_mapping.append(
                    {
                        "spdx_relationship_type": rel_type,
                        "source": source,
                        "target": target,
                        "mapped_to": "property",
                    }
                )
            continue

        if rel_type == "DEPENDS_ON":
            if source_ref and target_ref and source in all_package_refs:
                _add_dep(source_ref, target_ref, rel_type)
            elif source_ref and target_ref:
                state.warnings.append(
                    f"SPDX DEPENDS_ON at relationships[{index}] involves non-package element; skipped."
                )
            else:
                state.warnings.append(
                    f"SPDX DEPENDS_ON at relationships[{index}] has unresolved refs; skipped."
                )
            continue

        if rel_type == "DEPENDENCY_OF":
            # Reverse edge: target depends on source
            if target_ref and source_ref and target in all_package_refs:
                _add_dep(target_ref, source_ref, rel_type)
            else:
                state.warnings.append(
                    f"SPDX DEPENDENCY_OF at relationships[{index}] could not be mapped safely; skipped."
                )
            continue

        if rel_type == "CONTAINS":
            if source_ref and target_ref:
                _add_dep(source_ref, target_ref, rel_type)
            else:
                state.warnings.append(
                    f"SPDX CONTAINS at relationships[{index}] has unresolved refs; skipped."
                )
            continue

        if rel_type in _PROPERTY_REL_TYPES:
            state.relationship_mapping.append(
                {
                    "spdx_relationship_type": rel_type,
                    "source": source,
                    "target": target,
                    "mapped_to": "property",
                }
            )
            state.warnings.append(
                f"SPDX relationship type '{rel_type}' at relationships[{index}] preserved as property, "
                "not mapped to CycloneDX dependency."
            )
            continue

        state.warnings.append(
            f"SPDX relationship type '{rel_type}' at relationships[{index}] cannot be mapped to "
            "CycloneDX dependency; preserved in conversion report only."
        )
        state.relationship_mapping.append(
            {
                "spdx_relationship_type": rel_type,
                "source": source,
                "target": target,
                "mapped_to": "unmapped",
            }
        )

    dependencies: list[dict[str, Any]] = []
    for ref, depends in sorted(deps_by_ref.items()):
        # Only emit dependency if ref exists in components (doc or package bom-refs)
        valid_depends = [d for d in sorted(depends) if d in state.used_bom_refs and d != ref]
        if valid_depends:
            dependencies.append({"ref": ref, "dependsOn": valid_depends})
        elif depends:
            state.warnings.append(
                f"Dependency entry for '{ref}' dropped because dependsOn targets were unresolved."
            )
    return dependencies


def convert_spdx_to_cyclonedx(spdx_data: dict[str, Any], *, validate: bool = True) -> ConversionResult:
    """Convert an SPDX JSON document to CycloneDX 1.6 JSON."""
    state = _ConversionState()

    if not isinstance(spdx_data, dict):
        return ConversionResult(
            cyclonedx_bom={},
            conversion_errors=["SPDX document must be a JSON object."],
        )

    if "spdxVersion" not in spdx_data:
        state.errors.append("Required field 'spdxVersion' is missing.")
        return ConversionResult(cyclonedx_bom={}, conversion_errors=state.errors)

    packages = spdx_data.get("packages") or []
    if not packages:
        state.errors.append("No SPDX packages found; conversion requires at least one package.")
        return ConversionResult(cyclonedx_bom={}, conversion_errors=state.errors)

    doc_spdx_id = spdx_data.get("SPDXID")
    if not isinstance(doc_spdx_id, str):
        doc_spdx_id = "SPDXRef-DOCUMENT"
        state.warnings.append("SPDX document missing SPDXID; using 'SPDXRef-DOCUMENT'.")

    doc_bom_ref = _sanitize_bom_ref(doc_spdx_id, state)
    state.bom_refs[doc_spdx_id] = doc_bom_ref

    # Document-level metadata component (also added to components[] for integrity)
    doc_name = spdx_data.get("name") or "converted-spdx-document"
    creation_info = spdx_data.get("creationInfo") or {}
    created = creation_info.get("created") if isinstance(creation_info.get("created"), str) else _now_iso()
    creators = [c for c in (creation_info.get("creators") or []) if isinstance(c, str)]

    metadata_properties: list[dict[str, str]] = []
    if isinstance(spdx_data.get("documentNamespace"), str):
        metadata_properties.append({"name": "spdx:documentNamespace", "value": spdx_data["documentNamespace"]})
    if isinstance(spdx_data.get("spdxVersion"), str):
        metadata_properties.append({"name": "spdx:spdxVersion", "value": spdx_data["spdxVersion"]})
    metadata_properties.extend(
        [
            {"name": "spdx:sourceSPDXID", "value": doc_spdx_id},
            {"name": "conversion:sourceFormat", "value": "SPDX"},
            {"name": "conversion:targetFormat", "value": "CycloneDX"},
            {"name": "conversion:convertedAt", "value": _now_iso()},
            {"name": "conversion:tool", "value": _CONVERSION_TOOL},
        ]
    )

    tools: list[dict[str, str]] = []
    for creator in creators:
        if creator.startswith("Tool: "):
            tools.append({"name": creator[len("Tool: "):], "vendor": "SPDX"})
        elif creator.startswith("Organization: "):
            tools.append({"name": creator, "vendor": creator[len("Organization: "):]})
        else:
            tools.append({"name": creator})

    metadata: dict[str, Any] = {
        "timestamp": created,
        "component": {
            "type": "application",
            "bom-ref": doc_bom_ref,
            "name": doc_name,
        },
        "properties": metadata_properties,
    }
    if tools:
        metadata["tools"] = tools

    # Map packages to components
    components: list[dict[str, Any]] = []
    # Document component first (required for dependency integrity)
    components.append(
        {
            "type": "application",
            "bom-ref": doc_bom_ref,
            "name": doc_name,
            "properties": [
                {"name": "spdx:SPDXID", "value": doc_spdx_id},
                {"name": "spdx:documentNamespace", "value": spdx_data.get("documentNamespace") or ""},
            ],
        }
    )

    for index, pkg in enumerate(packages):
        if not isinstance(pkg, dict):
            state.warnings.append(f"Non-object entry at packages[{index}]; skipped.")
            continue
        components.append(_map_package_to_component(pkg, index, state))

    # Skip SPDX file-level data
    files = spdx_data.get("files") or []
    if files:
        state.warnings.append(f"SPDX file-level data ({len(files)} files) skipped; not mapped to CycloneDX components.")
        state.unmapped_fields.append("files")

    # Preserve annotations as metadata properties
    annotations = spdx_data.get("annotations") or []
    if annotations:
        for ann_index, ann in enumerate(annotations):
            if isinstance(ann, dict):
                metadata_properties.append(
                    {
                        "name": f"spdx:annotation:{ann_index}",
                        "value": str(ann.get("comment") or ann),
                    }
                )
        state.warnings.append(f"SPDX annotations ({len(annotations)}) preserved as metadata properties.")

    external_doc_refs = spdx_data.get("externalDocumentRefs") or []
    if external_doc_refs:
        for edr_index, edr in enumerate(external_doc_refs):
            if isinstance(edr, dict):
                metadata_properties.append(
                    {"name": f"spdx:externalDocumentRef:{edr_index}", "value": str(edr.get("externalDocumentId") or edr)}
                )

    dependencies = _map_relationships(spdx_data, doc_spdx_id, doc_bom_ref, state)

    serial_number = f"urn:uuid:{uuid.uuid4()}"
    cyclonedx_bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": _TARGET_SPEC_VERSION,
        "serialNumber": serial_number,
        "version": 1,
        "metadata": metadata,
        "components": components,
        "dependencies": dependencies,
    }

    # Validate output when requested — persist path validates once after save.
    if validate:
        validation_report = run_validation(
            __import__("json").dumps(cyclonedx_bom).encode("utf-8"),
        )
        if validation_report.has_errors():
            for entry in validation_report.errors:
                state.errors.append(f"{entry.code}: {entry.message}")
            return ConversionResult(
                cyclonedx_bom=cyclonedx_bom,
                conversion_warnings=state.warnings,
                conversion_errors=state.errors,
                component_mapping=state.component_mapping,
                relationship_mapping=state.relationship_mapping,
                unmapped_fields=state.unmapped_fields,
            )

    return ConversionResult(
        cyclonedx_bom=cyclonedx_bom,
        conversion_warnings=state.warnings,
        conversion_errors=state.errors,
        component_mapping=state.component_mapping,
        relationship_mapping=state.relationship_mapping,
        unmapped_fields=state.unmapped_fields,
    )


def build_conversion_report(result: ConversionResult, source_sbom_id: int | None = None) -> dict[str, Any]:
    """Build a structured conversion report dict for persistence."""
    mapped = sum(1 for r in result.relationship_mapping if r.get("mapped_to") == "dependency")
    unmapped = sum(1 for r in result.relationship_mapping if r.get("mapped_to") != "dependency")
    return {
        "source_format": result.source_format,
        "target_format": result.target_format,
        "source_sbom_id": source_sbom_id,
        "package_count": len(result.component_mapping),
        "component_count": len(result.component_mapping) + 1,  # +1 for document component
        "mapped_relationships": mapped,
        "unmapped_relationships": unmapped,
        "warnings": result.conversion_warnings,
        "errors": result.conversion_errors,
        "unmapped_fields": result.unmapped_fields,
        "component_mapping": result.component_mapping,
        "relationship_mapping": result.relationship_mapping,
        "converted_at": _now_iso(),
        "conversion_tool": _CONVERSION_TOOL,
    }


def _parse_spdx_dict(sbom_data: str) -> dict[str, Any]:
    import json

    parsed = json.loads(sbom_data)
    if not isinstance(parsed, dict):
        raise ValueError("SPDX document must be a JSON object.")
    return parsed


def convert_and_persist_spdx_to_cyclonedx(
    db,
    source_sbom: Any,
    *,
    user_id: str | None = None,
) -> tuple[Any, ConversionResult, dict[str, Any]]:
    """Convert an SPDX SBOM to CycloneDX and persist as a related SBOM record.

    Performs only the fast synchronous path: convert, validate, save, sync
    component rows. Lifecycle/VEX/completeness enrichment must be triggered
    separately via :func:`run_post_conversion_enrichment`.

    Returns (converted_sbom, conversion_result, conversion_report).
    """
    import json

    from ..models import SBOMSource
    from ..services.sbom_service import sync_sbom_components

    if source_sbom.format != "spdx":
        raise ValueError(f"Source SBOM format is '{source_sbom.format}', expected 'spdx'.")

    if source_sbom.converted_sbom_id is not None:
        existing = db.get(SBOMSource, source_sbom.converted_sbom_id)
        if existing is not None:
            raise ValueError(
                f"SPDX SBOM already converted to CycloneDX (converted_sbom_id={existing.id})."
            )

    started_at = _now_iso()
    source_sbom.conversion_started_at = started_at
    source_sbom.conversion_status = "running"

    spdx_data = _parse_spdx_dict(source_sbom.sbom_data)
    result = convert_spdx_to_cyclonedx(spdx_data, validate=False)
    if result.conversion_errors:
        source_sbom.conversion_status = "failed"
        source_sbom.conversion_error = "; ".join(result.conversion_errors)
        source_sbom.conversion_completed_at = _now_iso()
        db.commit()
        raise ValueError("; ".join(result.conversion_errors))

    report = build_conversion_report(result, source_sbom_id=source_sbom.id)
    converted_json = json.dumps(result.cyclonedx_bom, indent=2)
    now = _now_iso()
    conv_status = "completed_with_warnings" if result.conversion_warnings else "completed"

    converted = SBOMSource(
        sbom_name=f"{source_sbom.sbom_name} (CycloneDX)",
        sbom_data=converted_json,
        sbom_type=source_sbom.sbom_type,
        projectid=source_sbom.projectid,
        created_by=user_id or source_sbom.created_by,
        created_on=now,
        sbom_version="1.0.0",
        parent_id=source_sbom.id,
        change_summary="Converted from SPDX to CycloneDX",
        productver=source_sbom.productver,
        product_name=source_sbom.product_name,
        description=source_sbom.description,
        status="validated",
        validated_at=now,
        original_format="spdx",
        current_format="cyclonedx",
        converted_from_format="spdx",
        source_sbom_id=source_sbom.id,
        conversion_status=conv_status,
        conversion_started_at=started_at,
        conversion_completed_at=now,
        enrichment_status="pending",
        conversion_warnings_json=[{"message": w} for w in result.conversion_warnings],
        conversion_report_json=report,
        converted_at=now,
        converted_by=user_id or source_sbom.created_by,
    )
    db.add(converted)
    db.flush()

    validation_report = run_validation(converted_json.encode("utf-8"))
    converted.validation_errors = (
        [e.model_dump(mode="json") for e in validation_report.entries] if validation_report.entries else None
    )
    converted.error_count = validation_report.error_count
    converted.warning_count = validation_report.warning_count

    if validation_report.has_errors():
        db.rollback()
        source_sbom.conversion_status = "failed"
        source_sbom.conversion_error = "Converted CycloneDX failed validation."
        source_sbom.conversion_completed_at = _now_iso()
        db.commit()
        raise ValueError("Converted CycloneDX failed validation.")

    if not source_sbom.original_format:
        source_sbom.original_format = "spdx"
    source_sbom.current_format = "spdx"
    source_sbom.converted_sbom_id = converted.id
    source_sbom.conversion_status = conv_status
    source_sbom.conversion_completed_at = now
    source_sbom.conversion_error = None
    source_sbom.conversion_warnings_json = converted.conversion_warnings_json
    source_sbom.conversion_report_json = report
    source_sbom.converted_at = now
    source_sbom.converted_by = user_id or source_sbom.created_by
    source_sbom.enrichment_status = "pending"
    source_sbom.enrichment_error = None

    db.commit()
    db.refresh(converted)
    db.refresh(source_sbom)

    # Local DB sync only — no external provider calls.
    sync_sbom_components(db, converted)
    db.commit()

    return converted, result, report


def run_post_conversion_enrichment(converted_sbom_id: int, source_sbom_id: int | None = None) -> None:
    """Background enrichment: lifecycle providers, VEX, completeness.

    Uses its own DB session. Failures are recorded on the converted SBOM row
    and do not affect the already-completed conversion.
    """
    import logging

    from ..db import SessionLocal
    from ..models import SBOMSource
    from ..services.completeness_service import compute_and_save_completeness
    from ..services.lifecycle.vex_provider import process_embedded_vex_for_sbom
    from ..services.lifecycle_service import sync_lifecycle_for_sbom

    log = logging.getLogger(__name__)
    db = SessionLocal()
    try:
        converted = db.get(SBOMSource, converted_sbom_id)
        if converted is None:
            return

        started = _now_iso()
        converted.enrichment_status = "running"
        converted.enrichment_started_at = started
        converted.enrichment_error = None
        if source_sbom_id is not None:
            source = db.get(SBOMSource, source_sbom_id)
            if source is not None:
                source.enrichment_status = "running"
                source.enrichment_started_at = started
                source.enrichment_error = None
        db.commit()

        sync_lifecycle_for_sbom(db, converted_sbom_id)
        process_embedded_vex_for_sbom(db, converted_sbom_id)
        compute_and_save_completeness(db, converted)

        completed = _now_iso()
        converted.enrichment_status = "completed"
        converted.enrichment_completed_at = completed
        if source_sbom_id is not None:
            source = db.get(SBOMSource, source_sbom_id)
            if source is not None:
                source.enrichment_status = "completed"
                source.enrichment_completed_at = completed
        db.commit()
    except Exception as exc:
        log.exception(
            "Post-conversion enrichment failed for converted_sbom_id=%s",
            converted_sbom_id,
        )
        db.rollback()
        converted = db.get(SBOMSource, converted_sbom_id)
        if converted is not None:
            converted.enrichment_status = "failed"
            converted.enrichment_error = str(exc)[:2000]
            converted.enrichment_completed_at = _now_iso()
            if source_sbom_id is not None:
                source = db.get(SBOMSource, source_sbom_id)
                if source is not None:
                    source.enrichment_status = "failed"
                    source.enrichment_error = str(exc)[:2000]
                    source.enrichment_completed_at = converted.enrichment_completed_at
            db.commit()
    finally:
        db.close()
