"""
Sbom versions router — Endpoints for version control, manual editing, comparisons, and export.
"""

from __future__ import annotations

import json
import logging
import zipfile
from io import BytesIO
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.context import CurrentContext
from ..core.security import get_current_tenant_context
from ..db import get_db
from ..models import SBOMComponent, SBOMSource
from ..schemas import SbomConversionReportResponse, SbomConversionResponse, SbomEditPayload, SBOMSourceOut
from ..services.lifecycle import (
    LifecycleEnrichmentService,
    component_lifecycle_dict,
    lifecycle_report_csv,
    lifecycle_report_openeox,
)
from ..services.sbom_conversion_service import (
    convert_and_persist_spdx_to_cyclonedx,
    run_post_conversion_enrichment,
)
from ..services.sbom_enrichment_service import run_post_edit_enrichment
from ..services.sbom_vulnerability_excel_report_service import (
    SbomNotFoundError,
    SbomVulnerabilityExcelReportService,
)
from ..services.version_control_service import compare_versions, edit_sbom, restore_version
from ..validation import run as run_validation

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/sboms", tags=["sbom-versions"])
EXCEL_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


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
        children = db.execute(select(SBOMSource.id).where(SBOMSource.parent_id.in_(frontier))).scalars().all()
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
    allowed = {"native", "json", "xml", "cyclonedx", "spdx", "conversion-report"}
    if requested not in allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported export format '{value}'. Supported formats: native, json, xml, CycloneDX, SPDX, conversion-report.",
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


def _components_for_sbom(db: Session, sbom_id: int) -> list[SBOMComponent]:
    return db.execute(select(SBOMComponent).where(SBOMComponent.sbom_id == sbom_id)).scalars().all()


def _lifecycle_properties(component: SBOMComponent) -> list[dict[str, str]]:
    values = {
        "lifecycle:status": component.lifecycle_status,
        "lifecycle:maintenanceStatus": component.maintenance_status,
        "lifecycle:eolDate": component.eol_date,
        "lifecycle:eosDate": component.eos_date,
        "lifecycle:eofDate": component.eof_date,
        "lifecycle:deprecated": str(bool(component.deprecated or component.is_deprecated)).lower()
        if (component.deprecated or component.is_deprecated)
        else None,
        "lifecycle:unsupported": str(bool(component.unsupported)).lower() if component.unsupported else None,
        "lifecycle:recommendedVersion": component.recommended_version,
        "lifecycle:source": component.lifecycle_source,
        "lifecycle:evidenceUrl": component.lifecycle_source_url,
        "lifecycle:confidence": component.lifecycle_confidence,
        "lifecycle:checkedAt": component.lifecycle_checked_at,
        "lifecycle:manualOverride": str(bool(component.lifecycle_manual_override)).lower()
        if getattr(component, "lifecycle_manual_override", None)
        else None,
    }
    return [{"name": key, "value": str(value)} for key, value in values.items() if value not in (None, "")]


def _augment_lifecycle_metadata(db: Session, sbom: SBOMSource, parsed: dict[str, Any], standard: str) -> dict[str, Any]:
    components = _components_for_sbom(db, sbom.id)
    if not components:
        return parsed
    by_bom_ref = {component.bom_ref: component for component in components if component.bom_ref}
    by_name_version = {(component.name.lower(), component.version): component for component in components}
    by_purl = {component.purl: component for component in components if component.purl}

    if standard == "cyclonedx":
        for cdx_component in parsed.get("components") or []:
            if not isinstance(cdx_component, dict):
                continue
            match = (
                by_bom_ref.get(cdx_component.get("bom-ref"))
                or by_purl.get(cdx_component.get("purl"))
                or by_name_version.get((str(cdx_component.get("name") or "").lower(), cdx_component.get("version")))
            )
            if not match:
                continue
            existing = [
                prop
                for prop in cdx_component.get("properties") or []
                if not str(prop.get("name") or "").startswith("lifecycle:")
            ]
            cdx_component["properties"] = existing + _lifecycle_properties(match)
        return parsed

    if standard == "spdx":
        annotations = list(parsed.get("annotations") or [])
        for component in components:
            lifecycle = component_lifecycle_dict(component)
            if lifecycle["lifecycle_status"] == "Unknown" and not lifecycle["recommendation"]:
                continue
            annotations.append(
                {
                    "annotationType": "OTHER",
                    "annotator": "Tool: SBOM Analyzer",
                    "annotationDate": component.lifecycle_checked_at or "",
                    "comment": json.dumps(
                        {"component": component.name, "version": component.version, "lifecycle": lifecycle}
                    ),
                }
            )
        if annotations:
            parsed["annotations"] = annotations
        return parsed

    return parsed


def _maybe_augment_export_with_lifecycle(
    db: Session, sbom: SBOMSource, content: str, standard: str, encoding: str
) -> str:
    if encoding != "json" or standard not in {"cyclonedx", "spdx"}:
        return content
    parsed = json.loads(content)
    if not isinstance(parsed, dict):
        return content
    candidate = json.dumps(_augment_lifecycle_metadata(db, sbom, parsed, standard), indent=2)
    validation_report = run_validation(candidate.encode("utf-8"))
    return content if validation_report.has_errors() else candidate


@router.post("/{id}/edit", response_model=SBOMSourceOut)
def edit_sbom_endpoint(
    id: int,
    payload: SbomEditPayload,
    background_tasks: BackgroundTasks,
    user_id: str | None = Query(None),
    db: Session = Depends(get_db),
):
    """
    Manually edit SBOM components, metadata, or dependencies.
    Creates a new version of the SBOM in the DB.
    """
    override_map = {
        comp_up["bom_ref"]: comp_up["lifecycle"]
        for comp_up in (payload.model_dump(exclude_none=True).get("components") or [])
        if "bom_ref" in comp_up and "lifecycle" in comp_up
    }
    try:
        new_version = edit_sbom(
            db=db,
            sbom_id=id,
            user_id=user_id,
            updates=payload.model_dump(exclude_none=True),
            change_summary=payload.change_summary,
            defer_enrichment=True,
        )
        if override_map:
            background_tasks.add_task(run_post_edit_enrichment, new_version.id, override_map)
        else:
            background_tasks.add_task(run_post_edit_enrichment, new_version.id)
        return new_version
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/{id}/versions", response_model=list[SBOMSourceOut])
def get_sbom_versions(id: int, db: Session = Depends(get_db)):
    """
    Retrieve all versions in the lineage chain of this SBOM.
    """
    sbom = db.get(SBOMSource, id)
    if not sbom:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"SBOM with ID {id} not found.")

    root = _root_for_lineage(db, sbom)
    ids = _lineage_ids(db, root.id)
    versions = (
        db.execute(select(SBOMSource).where(SBOMSource.id.in_(ids)).order_by(SBOMSource.id.asc())).scalars().all()
    )

    return list(versions)


@router.get("/compare-versions", response_model=dict[str, Any])
def compare_sbom_versions(version_a: int = Query(...), version_b: int = Query(...), db: Session = Depends(get_db)):
    """
    Compare two SBOM versions and return added, removed, and changed components.
    """
    sbom_a = db.get(SBOMSource, version_a)
    sbom_b = db.get(SBOMSource, version_b)
    if not sbom_a or not sbom_b:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="One or both of the specified SBOM versions were not found."
        )
    return compare_versions(db, version_a, version_b)


@router.post("/{id}/restore/{version_id}", response_model=SBOMSourceOut)
def restore_sbom_version(
    id: int,
    version_id: int,
    user_id: str | None = Query(None),
    db: Session = Depends(get_db),
):
    """
    Restore a previous version of the SBOM.
    Clones the target version and saves it as the current head version.
    """
    try:
        restored = restore_version(db, id, version_id, user_id)
        return restored
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/{id}/lifecycle/refresh")
def refresh_sbom_lifecycle(
    id: int,
    force: bool = Query(True),
    db: Session = Depends(get_db),
):
    """Refresh provider-backed lifecycle data for all components in an SBOM."""

    return LifecycleEnrichmentService().enrich_sbom(db, id, force_refresh=force)


@router.get("/{id}/lifecycle/report")
def get_sbom_lifecycle_report(
    id: int,
    format: str = Query("json", pattern="^(json|csv|openeox)$"),
    report_type: str | None = Query(None, description="all, unsupported, eol_eos_eof, or deprecated"),
    db: Session = Depends(get_db),
):
    """Return a detailed lifecycle report suitable for export or UI evidence views."""

    if format == "csv":
        content = lifecycle_report_csv(db, id, report_type=report_type)
        suffix = f"_{report_type}" if report_type else ""
        return Response(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="sbom_{id}_lifecycle{suffix}.csv"'},
        )
    report = LifecycleEnrichmentService().lifecycle_report(db, id)
    if format == "openeox":
        return Response(
            content=json.dumps(lifecycle_report_openeox(report), indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="sbom_{id}_lifecycle.openeox.json"'},
        )
    return report


@router.get("/{id}/reports/lifecycle-pack")
def get_lifecycle_report_pack(
    id: int,
    db: Session = Depends(get_db),
):
    """Download a ZIP pack of lifecycle JSON and focused CSV reports."""

    report = LifecycleEnrichmentService().lifecycle_report(db, id)
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lifecycle.json", json.dumps(report, indent=2))
        zf.writestr("lifecycle.openeox.json", json.dumps(lifecycle_report_openeox(report), indent=2))
        zf.writestr("lifecycle_all.csv", lifecycle_report_csv(db, id))
        zf.writestr("lifecycle_unsupported.csv", lifecycle_report_csv(db, id, report_type="unsupported"))
        zf.writestr("lifecycle_eol_eos_eof.csv", lifecycle_report_csv(db, id, report_type="eol_eos_eof"))
        zf.writestr("lifecycle_deprecated.csv", lifecycle_report_csv(db, id, report_type="deprecated"))
    return Response(
        content=buffer.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="sbom_{id}_lifecycle_reports.zip"'},
    )


def _sync_flat_to_raw(flat: dict, raw: dict, standard: str) -> None:
    # 1. Licenses
    if flat.get("license"):
        if standard == "cyclonedx":
            licenses_list = []
            for lic in flat["license"].split(", "):
                lic = lic.strip()
                if lic:
                    if " " not in lic:
                        licenses_list.append({"license": {"id": lic}})
                    else:
                        licenses_list.append({"license": {"name": lic}})
            if licenses_list:
                raw["licenses"] = licenses_list
        else:  # spdx
            raw["licenseConcluded"] = flat["license"]
            raw["licenseDeclared"] = flat["license"]

    # 2. Hashes
    if flat.get("hashes"):
        if standard == "cyclonedx":
            hashes_list = []
            for h in flat["hashes"].split(", "):
                h = h.strip()
                if ":" in h:
                    alg, content = h.split(":", 1)
                    hashes_list.append({"alg": alg.strip(), "content": content.strip()})
            if hashes_list:
                raw["hashes"] = hashes_list
        else:  # spdx
            checksums_list = []
            for h in flat["hashes"].split(", "):
                h = h.strip()
                if ":" in h:
                    alg, content = h.split(":", 1)
                    spdx_alg = alg.strip().replace("-", "")
                    checksums_list.append({"algorithm": spdx_alg, "checksumValue": content.strip()})
            if checksums_list:
                raw["checksums"] = checksums_list

    # 3. Supplier
    if flat.get("supplier"):
        if standard == "cyclonedx":
            if isinstance(raw.get("supplier"), dict):
                raw["supplier"]["name"] = flat["supplier"]
            else:
                raw["supplier"] = {"name": flat["supplier"]}
        else:  # spdx
            existing = raw.get("supplier") or ""
            prefix = "Organization: "
            if existing.startswith("Person: "):
                prefix = "Person: "
            elif existing.startswith("Organization: "):
                prefix = "Organization: "

            clean_sup = flat["supplier"]
            if clean_sup.startswith("Organization: "):
                clean_sup = clean_sup[len("Organization: ") :]
            elif clean_sup.startswith("Person: "):
                clean_sup = clean_sup[len("Person: ") :]
            raw["supplier"] = f"{prefix}{clean_sup}"

    # 4. Scope
    if flat.get("scope"):
        if standard == "cyclonedx":
            raw["scope"] = flat["scope"]

    # 5. Type and Group
    if flat.get("type"):
        if standard == "cyclonedx":
            raw["type"] = flat["type"]
    if flat.get("group"):
        if standard == "cyclonedx":
            raw["group"] = flat["group"]


@router.post("/{id}/convert/cyclonedx", response_model=SbomConversionResponse)
def convert_spdx_to_cyclonedx_endpoint(
    id: int,
    background_tasks: BackgroundTasks,
    user_id: str | None = Query(None),
    db: Session = Depends(get_db),
):
    """Convert a validated SPDX SBOM to CycloneDX and persist as a related record."""

    sbom = db.get(SBOMSource, id)
    if not sbom:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"SBOM with ID {id} not found.")
    if sbom.format != "spdx":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"SBOM format is '{sbom.format}'; only SPDX SBOMs can be converted to CycloneDX.",
        )
    if sbom.status != "validated":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SBOM must pass validation before conversion.",
        )
    try:
        converted, result, report = convert_and_persist_spdx_to_cyclonedx(db, sbom, user_id=user_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    background_tasks.add_task(run_post_conversion_enrichment, converted.id, id)

    conv_status = "completed_with_warnings" if result.conversion_warnings else "completed"
    return SbomConversionResponse(
        source_sbom_id=id,
        converted_sbom_id=converted.id,
        source_format="SPDX",
        target_format="CycloneDX",
        status=conv_status,
        conversion_status=conv_status,
        enrichment_status="pending",
        message="Converted to CycloneDX. Lifecycle enrichment is running in background.",
        warnings=result.conversion_warnings,
        errors=result.conversion_errors,
        conversion_report=report,
    )


@router.get("/{id}/conversion-report", response_model=SbomConversionReportResponse)
def get_conversion_report(id: int, db: Session = Depends(get_db)):
    """Return the SPDX to CycloneDX conversion report for an SBOM."""

    sbom = db.get(SBOMSource, id)
    if not sbom:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"SBOM with ID {id} not found.")

    report = sbom.conversion_report_json or {}
    if not report and sbom.source_sbom_id:
        source = db.get(SBOMSource, sbom.source_sbom_id)
        if source and source.conversion_report_json:
            report = source.conversion_report_json

    if not report and not sbom.conversion_status:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No conversion report found for this SBOM.",
        )

    warnings = report.get("warnings") or sbom.conversion_warnings_json or []
    if warnings and isinstance(warnings[0], dict):
        warnings = [w.get("message", str(w)) for w in warnings]

    return SbomConversionReportResponse(
        source_format=report.get("source_format") or sbom.converted_from_format or sbom.original_format,
        target_format=report.get("target_format") or "CycloneDX",
        converted_at=report.get("converted_at") or sbom.converted_at,
        converted_by=sbom.converted_by,
        source_sbom_id=sbom.source_sbom_id or (id if sbom.converted_sbom_id else None),
        converted_sbom_id=sbom.converted_sbom_id or (id if sbom.source_sbom_id else None),
        conversion_status=sbom.conversion_status,
        enrichment_status=report.get("enrichment_status") or sbom.enrichment_status,
        package_count=report.get("package_count", 0),
        component_count=report.get("component_count", 0),
        mapped_relationships=report.get("mapped_relationships", 0),
        unmapped_relationships=report.get("unmapped_relationships", 0),
        warnings=warnings,
        errors=report.get("errors") or [],
        unmapped_fields=report.get("unmapped_fields") or [],
        component_mapping=report.get("component_mapping") or {},
        relationship_mapping=report.get("relationship_mapping") or [],
        conversion_report=report,
    )


@router.get("/{sbom_id}/reports/vulnerabilities.xlsx")
def export_sbom_vulnerabilities_excel(
    sbom_id: int,
    include_duplicates: bool = Query(False),
    severity: str | None = Query(None),
    package_name: str | None = Query(None),
    db: Session = Depends(get_db),
):
    """Export the SBOM's latest stored vulnerability findings as Excel."""
    service = SbomVulnerabilityExcelReportService(db)
    try:
        sbom = service.get_sbom(sbom_id)
        content = service.generate(
            sbom,
            include_duplicates=include_duplicates,
            severity=severity,
            package_name=package_name,
        )
    except SbomNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    filename = f"sbom-{sbom_id}-vulnerability-report.xlsx"
    return StreamingResponse(
        BytesIO(content),
        media_type=EXCEL_MEDIA_TYPE,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{id}/export")
def export_sbom(
    id: int,
    format: str = Query("native", description="native, json, xml, CycloneDX, SPDX, or conversion-report"),
    export_mode: str = Query(
        "original", description="Export mode: 'original', 'converted', 'enriched', or 'normalized'"
    ),
    db: Session = Depends(get_db),
):
    """
    Export the current SBOM data in its native format, or a converted/enriched variant.
    """
    allowed_modes = {"original", "converted", "enriched", "normalized"}
    if export_mode not in allowed_modes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported export mode '{export_mode}'. Supported modes: {', '.join(sorted(allowed_modes))}.",
        )

    sbom = db.get(SBOMSource, id)
    if not sbom or not sbom.sbom_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"SBOM with ID {id} has no data.")
    requested = _normalized_export_format(format)

    # Conversion report download
    if requested == "conversion-report" or format.strip().lower() == "conversion-report":
        report = sbom.conversion_report_json
        if not report and sbom.source_sbom_id:
            source = db.get(SBOMSource, sbom.source_sbom_id)
            report = source.conversion_report_json if source else None
        if not report:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No conversion report available for this SBOM.",
            )
        content = json.dumps(report, indent=2)
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="sbom_{id}_conversion-report.json"'},
        )

    standard, encoding = _detect_native_format(sbom.sbom_data)

    # SPDX-origin exports: resolve target SBOM and content based on export_mode
    export_sbom_obj = sbom
    skip_lifecycle_augment = False
    if standard == "spdx":
        if export_mode == "original" or requested in {"native", "spdx", "json"}:
            pass  # export original SPDX from sbom.sbom_data
        elif export_mode in {"converted", "enriched"} or requested == "cyclonedx":
            if not sbom.converted_sbom_id:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="No CycloneDX conversion exists for this SPDX SBOM. Run conversion first.",
                )
            converted = db.get(SBOMSource, sbom.converted_sbom_id)
            if not converted or not converted.sbom_data:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Converted CycloneDX SBOM not found.",
                )
            export_sbom_obj = converted
            standard, encoding = _detect_native_format(converted.sbom_data)
            skip_lifecycle_augment = export_mode == "converted"
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Unsupported SBOM conversion from {standard} to {requested}. "
                    "Use export_mode=converted or enriched with format=cyclonedx."
                ),
            )
    elif requested in {"cyclonedx", "spdx"} and standard != requested:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Unsupported SBOM conversion from {standard} to {requested}. "
                "Only native-format export is currently supported."
            ),
        )
    elif requested in {"json", "xml"} and encoding != requested:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Unsupported SBOM conversion from native {encoding} to {requested}. "
                "Only native-format export is currently supported."
            ),
        )

    if export_mode == "normalized":
        if encoding != "json":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Normalized export mode is only supported for JSON formatted SBOMs.",
            )
        try:
            doc = json.loads(sbom.sbom_data)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Stored SBOM JSON is invalid: {exc}",
            ) from exc

        from ..parsing import extract_components
        from ..services.component_deduplication_service import ComponentDeduplicationService

        if standard == "cyclonedx":
            flat_comps = extract_components(doc)
            original_components = doc.get("components") or []

            # Match 1-to-1 to attach original raw dicts
            for flat, raw in zip(flat_comps, original_components, strict=False):
                flat["raw"] = raw

            dependencies = doc.get("dependencies") or []
            canonical_flat, _, ref_mapping, _, _ = ComponentDeduplicationService.deduplicate_components(
                flat_comps, dependencies
            )

            # Sync flat canonical attributes back to raw
            for flat in canonical_flat:
                if "raw" in flat:
                    _sync_flat_to_raw(flat, flat["raw"], "cyclonedx")

            # Update doc components
            doc["components"] = [flat["raw"] for flat in canonical_flat if "raw" in flat]

            # Remap and merge dependencies
            cdx_deps_by_ref = {}
            for dep in doc.get("dependencies") or []:
                ref = dep.get("ref")
                depends_on = dep.get("dependsOn") or []

                new_ref = ref_mapping.get(ref, ref)
                new_depends_on = [ref_mapping.get(d, d) for d in depends_on]
                new_depends_on = [d for d in new_depends_on if d != new_ref]

                if new_ref not in cdx_deps_by_ref:
                    cdx_deps_by_ref[new_ref] = {"dep": dict(dep), "depends": []}
                cdx_deps_by_ref[new_ref]["depends"].extend(new_depends_on)

            new_deps = []
            for new_ref, info in cdx_deps_by_ref.items():
                unique_depends = list(dict.fromkeys(info["depends"]))
                new_dep = info["dep"]
                new_dep["ref"] = new_ref
                new_dep["dependsOn"] = unique_depends
                new_deps.append(new_dep)

            if "dependencies" in doc:
                doc["dependencies"] = new_deps

        elif standard == "spdx":
            flat_comps = extract_components(doc)
            original_packages = doc.get("packages") or []
            original_elements = [el for el in doc.get("elements") or [] if el.get("type") == "software:package"]
            raw_list = original_packages + original_elements

            # Match 1-to-1 to attach original raw dicts
            for flat, raw in zip(flat_comps, raw_list, strict=False):
                flat["raw"] = raw

            relationships = doc.get("relationships") or []
            canonical_flat, _, ref_mapping, _, _ = ComponentDeduplicationService.deduplicate_components(
                flat_comps, relationships
            )

            # Sync flat canonical attributes back to raw
            for flat in canonical_flat:
                if "raw" in flat:
                    _sync_flat_to_raw(flat, flat["raw"], "spdx")

            # Rebuild packages and elements lists, keeping only canonical ones
            canonical_raw_set = {id(flat["raw"]) for flat in canonical_flat if "raw" in flat}

            new_packages = [pkg for pkg in original_packages if id(pkg) in canonical_raw_set]
            new_elements = [
                el
                for el in doc.get("elements") or []
                if el.get("type") != "software:package" or id(el) in canonical_raw_set
            ]

            if "packages" in doc:
                doc["packages"] = new_packages
            if "elements" in doc:
                doc["elements"] = new_elements

            # Remap and deduplicate relationships
            seen_rels = set()
            new_relationships = []
            for rel in doc.get("relationships") or []:
                elem_id = rel.get("spdxElementId")
                related_id = rel.get("relatedSpdxElement")
                rel_type = rel.get("relationshipType")

                new_elem_id = ref_mapping.get(elem_id, elem_id)
                new_related_id = ref_mapping.get(related_id, related_id)

                if new_elem_id == new_related_id and rel_type in {"DEPENDS_ON", "CONTAINS", "DESCRIBES"}:
                    continue

                rel_key = (new_elem_id, rel_type, new_related_id)
                if rel_key not in seen_rels:
                    seen_rels.add(rel_key)
                    new_rel = dict(rel)
                    new_rel["spdxElementId"] = new_elem_id
                    new_rel["relatedSpdxElement"] = new_related_id
                    new_relationships.append(new_rel)
            if "relationships" in doc:
                doc["relationships"] = new_relationships

        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Normalized export mode not supported for standard {standard}.",
            )

        content = json.dumps(doc, indent=2)

    else:
        content = export_sbom_obj.sbom_data
        if encoding == "json":
            try:
                content = json.dumps(json.loads(content), indent=2)
            except json.JSONDecodeError as exc:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Stored SBOM JSON is invalid and cannot be exported: {exc}",
                ) from exc

    if encoding == "json" and not skip_lifecycle_augment and export_mode != "normalized":
        try:
            content = _maybe_augment_export_with_lifecycle(db, export_sbom_obj, content, standard, encoding)
        except Exception as exc:
            log.warning("Lifecycle augmentation failed: %s", exc)

    report = run_validation(content.encode("utf-8"))
    if report.has_errors():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "message": "Stored SBOM failed validation and cannot be exported.",
                "errors": [entry.model_dump() for entry in report.entries],
            },
        )

    if standard == "cyclonedx" and encoding == "json":
        extension = "cdx.json"
    elif standard == "spdx" and encoding == "json":
        extension = "spdx.json"
    else:
        extension = "json" if encoding == "json" else "xml" if encoding == "xml" else "spdx"

    mode_suffix = ""
    if export_mode == "converted":
        mode_suffix = "_converted"
    elif export_mode == "enriched":
        mode_suffix = "_enriched"
    elif export_mode == "original" and standard == "spdx":
        mode_suffix = "_original"

    filename = f"{sbom.sbom_name}{mode_suffix}.{extension}"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}

    return Response(content=content, media_type=_media_type(standard, encoding), headers=headers)


@router.get("/{id}/lifecycle/diagnostics")
def get_sbom_lifecycle_diagnostics(id: int, db: Session = Depends(get_db)):
    """Return component count, provider hit count, cache hit count, and sample components."""
    sbom = db.get(SBOMSource, id)
    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")

    components = db.execute(select(SBOMComponent).where(SBOMComponent.sbom_id == id)).scalars().all()

    total = len(components)
    enriched = sum(1 for c in components if c.lifecycle_checked_at is not None)
    unknown = sum(1 for c in components if (c.lifecycle_status or "Unknown") == "Unknown")

    cache_hits = 0
    provider_hits = 0
    provider_failures = 0

    for c in components:
        evidence = c.lifecycle_evidence_json or {}
        if c.lifecycle_source == "Manual Override":
            continue
        if c.lifecycle_source == "Lifecycle Providers":
            # Failed to match any provider
            provider_failures += 1
        elif evidence.get("cached") or evidence.get("stale_cache") or c.lifecycle_source == "Cached Provider":
            cache_hits += 1
        elif c.lifecycle_source in {
            "endoflife.date",
            "npm registry",
            "PyPI",
            "NuGet",
            "Maven Central",
            "OSV",
            "Repository Health",
        }:
            provider_hits += 1

    sample_unknown = []
    sample_matched = []

    for c in components:
        status_canonical = c.lifecycle_status or "Unknown"
        if status_canonical == "Unknown":
            if len(sample_unknown) < 10:
                reason = "No matching lifecycle evidence found across providers."
                if c.lifecycle_source == "Lifecycle Providers":
                    reason = "All providers returned Unknown."
                sample_unknown.append(
                    {
                        "id": c.id,
                        "name": c.name,
                        "version": c.version,
                        "purl": c.purl,
                        "cpe": c.cpe,
                        "ecosystem": c.ecosystem,
                        "reason": reason,
                    }
                )
        else:
            if len(sample_matched) < 10:
                sample_matched.append(
                    {
                        "id": c.id,
                        "name": c.name,
                        "version": c.version,
                        "status": status_canonical,
                        "source": c.lifecycle_source,
                        "evidence": c.lifecycle_evidence_json,
                    }
                )

    return {
        "component_count": total,
        "components_enriched": enriched,
        "unknown_count": unknown,
        "provider_hit_count": provider_hits,
        "cache_hit_count": cache_hits,
        "provider_failure_count": provider_failures,
        "sample_unknown_components": sample_unknown,
        "sample_matched_components": sample_matched,
    }
