"""Stage 7 — NTIA minimum elements (soft validation).

Default behaviour: each missing element produces a **warning** (W100-W106).
``ctx.strict_ntia=True`` promotes the same checks to hard errors with HTTP
status 422 — the codes themselves are unchanged so callers keying on
``code`` see the same value either way.

Stage 7 always runs, even when earlier stages have failed, so the user gets
a complete report on partial input. (Some checks degrade gracefully when
``ctx.internal_model`` is absent — e.g., we cannot compute "supplier
missing" without a normalised model, so we silently skip those.)
"""

from __future__ import annotations

from .. import errors as E
from ..context import ValidationContext
from ..errors import Severity

_STAGE = "ntia"


def run(ctx: ValidationContext) -> ValidationContext:
    sbom = ctx.internal_model
    if sbom is None:
        return ctx  # nothing to walk; earlier stages already failed

    severity = Severity.ERROR if ctx.strict_ntia else Severity.WARNING

    if not sbom.metadata.creators:
        ctx.report.add(
            E.W105_NTIA_AUTHOR_MISSING,
            stage=_STAGE,
            path="creationInfo.creators" if sbom.spec == "spdx" else "metadata.tools",
            message="Document has no author / SBOM-data creator.",
            remediation=(
                "Add `creationInfo.creators` (SPDX) or `metadata.tools[]` "
                "(CycloneDX)."
            ),
            spec_reference="NTIA 2021 §6",
            severity=severity,
        )

    if not sbom.metadata.created:
        ctx.report.add(
            E.W106_NTIA_TIMESTAMP_MISSING,
            stage=_STAGE,
            path="creationInfo.created" if sbom.spec == "spdx" else "metadata.timestamp",
            message="Document has no created / metadata.timestamp.",
            remediation="Add the document creation timestamp.",
            spec_reference="NTIA 2021 §7",
            severity=severity,
        )

    if not sbom.dependencies:
        ctx.report.add(
            E.W104_NTIA_DEPENDENCY_RELATIONSHIP_MISSING,
            stage=_STAGE,
            path="dependencies" if sbom.spec == "cyclonedx" else "relationships",
            message="No dependency relationship is declared between any components.",
            remediation=(
                "Add at least one dependency edge (CycloneDX `dependencies[]` "
                "or SPDX `relationships[]`)."
            ),
            spec_reference="NTIA 2021 §5",
            severity=severity,
        )

    for comp in sbom.components:
        if not comp.supplier:
            ctx.report.add(
                E.W100_NTIA_SUPPLIER_MISSING,
                stage=_STAGE,
                path=f"{comp.raw_path}.supplier",
                message=f"Component '{comp.ref}' has no supplier name.",
                remediation="Add `supplier.name` (CycloneDX) or `supplier` (SPDX).",
                spec_reference="NTIA 2021 §1",
                severity=severity,
            )
        if not comp.name:
            ctx.report.add(
                E.W101_NTIA_COMPONENT_NAME_MISSING,
                stage=_STAGE,
                path=f"{comp.raw_path}.name",
                message=f"Component '{comp.ref}' has no name.",
                remediation="Add the component name.",
                spec_reference="NTIA 2021 §2",
                severity=severity,
            )
        if not comp.version:
            ctx.report.add(
                E.W102_NTIA_COMPONENT_VERSION_MISSING,
                stage=_STAGE,
                path=f"{comp.raw_path}.version",
                message=f"Component '{comp.ref}' has no version.",
                remediation="Add the component version.",
                spec_reference="NTIA 2021 §3",
                severity=severity,
            )
        if not (comp.purl or comp.cpe or comp.ref.startswith("SPDXRef-")):
            ctx.report.add(
                E.W103_NTIA_UNIQUE_ID_MISSING,
                stage=_STAGE,
                path=comp.raw_path,
                message=f"Component '{comp.ref}' has no PURL, CPE, or SPDXID.",
                remediation=(
                    "Add at least one unique identifier so the scanner can match "
                    "against vulnerability databases."
                ),
                spec_reference="NTIA 2021 §4",
                severity=severity,
            )
    return ctx
