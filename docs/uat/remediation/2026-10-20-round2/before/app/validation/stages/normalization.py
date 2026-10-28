"""Stage 9 — normalization and deduplication.

This stage is pure and side-effect-free. It computes normalized component
identities, duplicate groups, and dependency remapping evidence after the SBOM
has passed schema, semantic, integrity, security, NTIA, and signature checks.
Persistence happens later in the trusted import path.
"""

from __future__ import annotations

from app.normalization.component_deduplicator import ComponentDeduplicator

from .. import errors as E
from ..context import ValidationContext

_STAGE = "normalization"


def run(ctx: ValidationContext) -> ValidationContext:
    sbom = ctx.internal_model
    if sbom is None:
        return ctx
    components = [
        {
            "name": component.name,
            "version": component.version,
            "purl": component.purl,
            "cpe": component.cpe,
            "cpes": _cpes_from_raw(component.raw),
            "supplier": component.supplier,
            "type": component.type,
            "bom_ref": component.ref,
            "license": ", ".join(component.licenses) if component.licenses else None,
            "hashes": ", ".join(
                f"{h.get('alg') or h.get('algorithm')}:{h.get('content') or h.get('checksumValue')}"
                for h in component.hashes
                if h.get("content") or h.get("checksumValue")
            )
            or None,
        }
        for component in sbom.components
    ]
    dependencies = [
        {"source": edge.source, "target": edge.target, "kind": edge.kind}
        for edge in sbom.dependencies
    ]
    _canonical, _duplicates, _mapping, report, warnings = ComponentDeduplicator.deduplicate(components, dependencies)
    ctx.normalization_report = report
    for group in report.get("duplicate_groups") or []:
        ctx.report.add(
            E.W120_DUPLICATE_COMPONENT_DETECTED,
            stage=_STAGE,
            path="components",
            message=(
                "Duplicate component group detected for "
                f"{group.get('normalized_component_key')} ({group.get('count')} entries)."
            ),
            remediation="The trusted import will retain duplicate rows for audit and use the canonical identity for enrichment.",
        )
    for warning in warnings[:5]:
        ctx.report.add(
            E.W121_NORMALIZATION_WARNING,
            stage=_STAGE,
            path="components",
            message=warning,
            remediation="Review the normalization report for duplicate evidence and canonical component selection.",
        )
    return ctx


def _cpes_from_raw(raw: dict) -> list[str]:
    cpes: list[str] = []
    if isinstance(raw.get("cpe"), str):
        cpes.append(raw["cpe"])
    for ref in raw.get("externalReferences") or raw.get("externalRefs") or []:
        if not isinstance(ref, dict):
            continue
        rtype = str(ref.get("type") or ref.get("referenceType") or "").lower()
        locator = ref.get("url") or ref.get("referenceLocator")
        if "cpe" in rtype and isinstance(locator, str):
            cpes.append(locator)
    return cpes
