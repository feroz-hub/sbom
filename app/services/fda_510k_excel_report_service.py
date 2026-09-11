"""FDA 510(k) final SBOM Excel report generation from persisted data."""

from __future__ import annotations

import json
import logging
import re
from copy import copy
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from io import BytesIO
from pathlib import Path
from typing import Any

from openpyxl import load_workbook
from openpyxl.formula.translate import Translator
from openpyxl.worksheet.worksheet import Worksheet
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..metrics import COMPLETED_RUN_STATUSES
from ..models import (
    AnalysisFinding,
    AnalysisRun,
    EpssScore,
    KevEntry,
    Projects,
    SBOMComponent,
    SBOMSource,
    VexStatement,
)

log = logging.getLogger(__name__)

EXCEL_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
FDA_510K_TEMPLATE_PATH = Path(__file__).resolve().parents[1] / "templates" / "reports" / "FDA_510k_SBOM_Template 1.xlsx"

DATA_SHEETS = (
    "SBOM Components",
    "Environment & 3rd-Party Deps",
    "Vulnerabilities & VEX",
    "Lifecycle & Support Plan",
    "Supplier & Security Contacts",
)
EXPECTED_SHEETS = ("Instructions", "SBOM Metadata", *DATA_SHEETS, "FDA Compliance Dashboard")
INCOMPLETE_ANALYSIS_CODE = "fda_510k_report_incomplete_analysis"

# Data rows begin at 3 on every sheet: row 1 is the merged group band, row 2
# the column headers. Row 3 ships a worked example that must be cleared.
DATA_START_ROW = 3

# The template pre-builds styling, per-row formulas and dropdown validation
# down to row 500. Rows within that range are written in place; only a larger
# SBOM needs the row template copied downward.
TEMPLATE_LAST_ROW = 500

# Column maps, keyed by the header text on row 2. Named rather than inlined as
# integers: the FDA template has been revised once already, and last time every
# writer had to be re-counted by hand because the positions were magic numbers.
#
# Columns carrying a template formula are deliberately ABSENT from these maps —
# writing a value there would replace the calculation the workbook (and the
# Compliance Dashboard that reads it) depends on:
#   * SBOM Components  V "Days to EOS",  W "Lifecycle Flag"   <- from T (EOS)
#   * Lifecycle        H "Days to EOS"                        <- from F (EOS)
COMPONENT_COLS = {
    "index": 1,               # A  #
    "name": 2,                # B  Component Name                     [NTIA]
    "version": 3,             # C  Version                            [NTIA]
    "supplier": 4,            # D  Supplier / Legal Entity Name       [NTIA]
    "unique_id_type": 5,      # E  Unique ID Type                     [NTIA]
    "unique_id_value": 6,     # F  Unique ID Value                    [NTIA]
    "dependency_type": 7,     # G  Dependency Type                    [NTIA]
    "depends_on": 8,          # H  Parent / Depends-On Component
    "dependency_depth": 9,    # I  Dependency Depth
    "component_type": 10,     # J  Component Type
    "origin_category": 11,    # K  Origin / Category
    "license": 12,            # L  License
    "runtime_or_build": 13,   # M  Runtime / Build-Time
    "criticality": 14,        # N  Criticality to Device Operation
    "safety_relevance": 15,   # O  Safety Relevance
    "network_exposure": 16,   # P  Network Exposure
    "auth_dependency": 17,    # Q  Authentication Dependency
    "internet_facing": 18,    # R  Internet-Facing
    "support_level": 19,      # S  Level of Support
    "eos_date": 20,           # T  End-of-Support (EOS) Date
    "eol_date": 21,           # U  End-of-Life (EOL) Date
    # V, W are formulas
    "vulnerabilities": 24,    # X  Known Vulnerabilities (CVE/IDs)
    "patch_mechanism": 25,    # Y  Patch / Update Mechanism
    "hash": 26,               # Z  Component Hash / Checksum (SHA-256)
    "signature_status": 27,   # AA Cryptographic Signature Status
    "provenance": 28,         # AB Build Environment / Provenance ID
    "supplier_contact": 29,   # AC Supplier Security Contact (Email)
    "notes": 30,              # AD Notes / Justification
}

VULNERABILITY_COLS = {
    "index": 1,               # A  #
    "component_name": 2,      # B
    "component_version": 3,   # C
    "vulnerability_id": 4,    # D
    "cvss_version": 5,        # E
    "cvss_score": 6,          # F
    "cvss_vector": 7,         # G
    "severity": 8,            # H
    "epss_score": 9,          # I
    "kev_status": 10,         # J  CISA KEV Status
    "vex_status": 11,         # K
    "vex_justification": 12,  # L
    "patient_impact": 13,     # M
    "exploitability": 14,     # N
    "remediation": 15,        # O
    "fixed_versions": 16,     # P
    "remediation_owner": 17,  # Q
    "target_date": 18,        # R
    "status": 19,             # S
    "notes": 20,              # T
}

LIFECYCLE_COLS = {
    "index": 1,               # A  #
    "name": 2,                # B
    "version": 3,             # C
    "supplier": 4,            # D
    "support_level": 5,       # E
    "eos_date": 6,            # F
    "eol_date": 7,            # G
    # H is a formula
    "risk": 9,                # I  Risk if Unsupported
    "plan": 10,               # J  Mitigation / Replacement Plan
    "controls": 11,           # K  Compensating Controls
    "verification": 12,       # L  Verification Method
    "owner": 13,              # M  Owner / Responsible
    "target_date": 14,        # N  Target Action Date
    "status": 15,             # O  Status
}

ENVIRONMENT_COLS = {
    "index": 1,               # A  #
    "category": 2,            # B  Dependency Category
    "name": 3,                # C
    "version": 4,             # D  Version / Tag / Digest
    "supplier": 5,            # E
    "unique_id": 6,           # F  PURL / Image Digest / CPE
    "support_level": 7,       # G
    "eos_date": 8,            # H
    "eol_date": 9,            # I
    "vulnerabilities": 10,    # J
    "network_exposure": 11,   # K
    "notes": 12,              # L
}

# Values the template's dropdowns accept. Writing anything else leaves Excel
# showing a validation warning on a submitted workbook, so every value the
# service produces for these columns is mapped into one of these sets.
SUPPORT_LEVELS = ("Actively maintained", "No longer maintained", "Abandoned", "Unknown")
COMPONENT_TYPES = (
    "Application",
    "Operating System",
    "Library",
    "Framework",
    "Driver",
    "Firmware",
    "Middleware",
    "Container/Image",
    "Other",
)
ORIGIN_CATEGORIES = (
    "Commercial (COTS)",
    "Open-Source (OSS)",
    "Off-the-Shelf (OTS)",
    "Proprietary / In-house",
    "Other",
)
UNIQUE_ID_TYPES = ("CPE", "PURL", "SWID", "OmniBOR", "Other")
VEX_STATUS_LABELS = {
    "not_affected": "Not Affected",
    "affected": "Affected",
    "fixed": "Fixed",
    "under_investigation": "Under Investigation",
    "unknown": "Under Investigation",
}
EXPLOITABILITY_KEV = "Actively Exploited (CISA KEV)"
EXPLOITABILITY_NONE = "None Known"

# Ecosystems that belong on the Environment sheet rather than the component
# inventory: FDA Sec. VII separates OS/container/firmware dependencies from
# application libraries.
ENVIRONMENT_PURL_TYPES = {
    "deb": "Operating System",
    "rpm": "Operating System",
    "apk": "Operating System",
    "alpine": "Operating System",
    "oci": "Container Base Image",
    "docker": "Container Base Image",
}


class Fda510kReportError(ValueError):
    """Base class for request validation errors."""


class Fda510kTemplateMissingError(Fda510kReportError):
    """Raised when the approved workbook template is unavailable."""


class Fda510kIncompleteAnalysisError(Fda510kReportError):
    """Raised when required persisted analyses are not complete."""

    def __init__(self, blockers: list[dict[str, Any]]) -> None:
        self.blockers = blockers
        super().__init__("Required analyses are incomplete for one or more selected SBOMs.")

    def detail(self) -> dict[str, Any]:
        return {
            "code": INCOMPLETE_ANALYSIS_CODE,
            "message": str(self),
            "blockers": self.blockers,
        }


@dataclass(frozen=True)
class Fda510kReportMetadata:
    device_name: str
    manufacturer_sponsor: str
    device_software_version: str
    author_of_sbom_data: str
    prepared_by: str
    device_model_catalog_number: str | None = None
    submission_type: str | None = None
    submission_number: str | None = None
    product_code_regulation_number: str | None = None
    top_level_primary_component: str | None = None
    sbom_version: str | None = None
    sbom_formats_for_submission: str | None = None
    sbom_generation_tool_and_version: str | None = None
    primary_data_source: str | None = None
    date_prepared: date | None = None
    reviewed_approved_by: str | None = None
    date_approved: date | None = None
    # Author block, split out by the revised template (rows 16-18).
    author_organization: str | None = None
    author_role_title: str | None = None
    author_email: str | None = None
    # Manufacturer security-contact block (rows 26-28), added by the revised
    # template to support the 21 U.S.C. 360n-2 (Sec. 524B) coordinated
    # disclosure expectations.
    psirt_contact: str | None = None
    cvd_policy_url: str | None = None
    vulnerability_intake_method: str | None = None


@dataclass(frozen=True)
class Fda510kSelection:
    sbom_id: int
    findings_analysis_run_id: int | None = None
    lifecycle_analysis_run_id: int | None = None


@dataclass
class _ComponentAggregate:
    key: str
    name: str = ""
    version: str = ""
    supplier: str = ""
    unique_id_type: str = ""
    unique_id_value: str = ""
    component_type: str = ""
    origin_category: str = ""
    license: str = ""
    support_level: str = ""
    eos_date: date | None = None
    eol_date: date | None = None
    patch_mechanism: str = ""
    crypto_info: str = ""
    component_hash: str = ""
    runtime_or_build: str = ""
    environment_category: str = ""
    dependency_depth: int | None = None
    source_sboms: set[str] = field(default_factory=set)
    dependencies: set[str] = field(default_factory=set)
    depends_on: set[str] = field(default_factory=set)
    required_by: set[str] = field(default_factory=set)
    is_direct: bool = False
    vulnerabilities: set[str] = field(default_factory=set)
    lifecycle_recommendations: set[str] = field(default_factory=set)
    components: list[SBOMComponent] = field(default_factory=list)


def _clean(value: Any) -> str:
    return " ".join(str(value or "").split())


def _first_text(*values: Any) -> str:
    return next((_clean(value) for value in values if _clean(value)), "")


def _parse_json(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return None


def _as_list(value: Any) -> list[str]:
    parsed = _parse_json(value)
    if isinstance(parsed, list):
        return [_clean(item) for item in parsed if _clean(item)]
    if isinstance(value, (list, tuple, set)):
        return [_clean(item) for item in value if _clean(item)]
    text = _clean(value)
    if not text:
        return []
    return [part.strip() for part in re.split(r"[,;\n]", text) if part.strip()]


def _parse_date(value: Any) -> date | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value).strip()
    if not text:
        return None
    for candidate in (text, text[:10]):
        try:
            return date.fromisoformat(candidate)
        except ValueError:
            continue
    return None


def _severity(value: Any) -> str:
    text = _clean(value).lower()
    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "moderate": "Medium",
        "low": "Low",
        "none": "None",
        "info": "None",
        "informational": "None",
    }
    return mapping.get(text, "None" if not text else text[:1].upper() + text[1:])


def _safe_filename(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    safe = safe.strip("._")
    return safe or "project"


def _component_identity(component: SBOMComponent) -> str:
    for prefix, value in (
        ("purl", component.normalized_purl or component.purl),
        ("cpe", component.primary_cpe or component.cpe),
        ("identity", component.normalized_component_key),
        ("canonical", component.dedupe_canonical_id),
    ):
        if _clean(value):
            return f"{prefix}:{_clean(value).casefold()}"
    fallback = "|".join(
        [
            _clean(component.normalized_supplier or component.supplier).casefold(),
            _clean(component.normalized_name or component.name).casefold(),
            _clean(component.normalized_version or component.version).casefold(),
            _clean(component.normalized_ecosystem or component.ecosystem).casefold(),
            _clean(component.purl_namespace or component.component_group).casefold(),
        ]
    )
    return f"fallback:{fallback}"


def _unique_id(component: SBOMComponent) -> tuple[str, str]:
    if _clean(component.normalized_purl or component.purl):
        return "PURL", _clean(component.normalized_purl or component.purl)
    if _clean(component.primary_cpe or component.cpe):
        return "CPE", _clean(component.primary_cpe or component.cpe)
    if _clean(component.bom_ref):
        return "Other", _clean(component.bom_ref)
    return "", ""


def _coerce_choice(value: Any, allowed: tuple[str, ...], fallback: str = "") -> str:
    """Snap a value onto one of the template's dropdown options.

    Case- and separator-insensitive, then a substring match, so "operating
    system" / "OPERATING_SYSTEM" / "os-image" all resolve. Anything that still
    does not match returns ``fallback`` — an unrecognised value in a validated
    cell shows as an error in a workbook that goes to a regulator.
    """
    text = _clean(value)
    if not text:
        return fallback
    squashed = text.casefold().replace("_", " ").replace("-", " ")
    for option in allowed:
        if squashed == option.casefold().replace("_", " ").replace("-", " "):
            return option
    for option in allowed:
        head = option.split("(")[0].split("/")[0].strip().casefold()
        if head and (head in squashed or squashed in head):
            return option
    return fallback


def _component_hash(component: SBOMComponent) -> str:
    """Prefer SHA-256 from the component's hashes, per template column Z.

    Two storage shapes occur in practice: a JSON array of
    ``{"alg": ..., "content": ...}`` objects from a CycloneDX import, and the
    flattened ``"SHA-256:abc123"`` string the component upsert writes. Both are
    accepted, because the FDA column wants the digest either way.
    """
    raw = component.hashes
    if isinstance(raw, str):
        parsed = _parse_json(raw)
        raw = parsed if isinstance(parsed, list) else raw

    def pick(alg: str, digest: str) -> str | None:
        normalized = alg.upper().replace("-", "").replace("_", "")
        return digest if normalized in {"SHA256", "SHA2256"} else None

    fallback = ""
    if isinstance(raw, list):
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            alg = _clean(entry.get("alg") or entry.get("algorithm"))
            digest = _clean(entry.get("content") or entry.get("value") or entry.get("checksumValue"))
            if not digest:
                continue
            exact = pick(alg, digest)
            if exact:
                return exact
            fallback = fallback or f"{alg or 'HASH'}: {digest}"
        return fallback

    for piece in re.split(r"[,;\s]+", _clean(raw)):
        if not piece:
            continue
        alg, _, digest = piece.partition(":")
        if not digest:
            alg, digest = "", alg
        exact = pick(alg, digest)
        if exact:
            return digest
        fallback = fallback or (f"{alg}: {digest}" if alg else digest)
    return fallback


def _purl_type(component: SBOMComponent) -> str:
    purl = _clean(component.purl)
    if not purl.lower().startswith("pkg:"):
        return ""
    return purl[4:].split("/", 1)[0].split("@", 1)[0].strip().casefold()


def _environment_category(component: SBOMComponent) -> str:
    """Environment-sheet category, or "" when the component is an app library."""
    mapped = ENVIRONMENT_PURL_TYPES.get(_purl_type(component))
    if mapped:
        return mapped
    declared = _clean(component.component_type).casefold()
    if declared in {"operating-system", "operating system", "os"}:
        return "Operating System"
    if declared in {"container", "container-image", "image"}:
        return "Container Base Image"
    if declared in {"firmware", "device"}:
        return "Embedded Firmware"
    return ""


def _support_level(component: SBOMComponent) -> str:
    status = _first_text(component.maintenance_status, component.lifecycle_status)
    lowered = status.casefold()
    if lowered in {"active", "supported", "maintained", "eol soon"}:
        return "Actively maintained"
    if "deprecated" in lowered or "unmaintained" in lowered:
        return "No longer maintained"
    if "abandoned" in lowered or "unsupported" in lowered or "eol" in lowered or "eos" in lowered:
        return "Abandoned" if "abandoned" in lowered else "No longer maintained"
    return "Unknown" if not status else status


def _origin_category(component: SBOMComponent) -> str:
    license_text = _clean(component.license).casefold()
    if any(token in license_text for token in ("mit", "apache", "gpl", "bsd", "mpl", "epl")):
        return "Open-Source (OSS)"
    if _clean(component.supplier):
        return "Commercial (COTS)"
    return "Other"


def _risk_for_lifecycle(component: SBOMComponent) -> str:
    status = _clean(component.lifecycle_status).casefold()
    if status in {"eol", "eos", "eof", "unsupported"} or component.unsupported:
        return "High"
    if "deprecated" in status or "soon" in status or component.deprecated or component.is_deprecated:
        return "Medium"
    return "Low"


@dataclass
class _DependencyFacts:
    """Structured dependency view for one (sbom_id, bom_ref)."""

    relationships: set[str] = field(default_factory=set)
    depends_on: set[str] = field(default_factory=set)
    required_by: set[str] = field(default_factory=set)
    depth: int | None = None
    is_direct: bool = False


def _dependency_depths(roots: list[str], edges: dict[str, set[str]]) -> dict[str, int]:
    """Breadth-first depth from the document's root component(s).

    Depth 1 is a direct dependency of the device software, 2+ transitive. BFS
    (not DFS) so a component reachable by both a short and a long path reports
    the shortest — the honest answer to "how far from the product is this".
    """
    depths: dict[str, int] = {}
    frontier = [(root, 0) for root in roots]
    seen = set(roots)
    while frontier:
        node, depth = frontier.pop(0)
        for child in sorted(edges.get(node, set())):
            if child in seen:
                continue
            seen.add(child)
            depths[child] = depth + 1
            frontier.append((child, depth + 1))
    return depths


def _extract_dependency_facts(sboms: list[SBOMSource]) -> dict[tuple[int, str], _DependencyFacts]:
    facts: dict[tuple[int, str], _DependencyFacts] = {}

    def entry(sbom_id: int, ref: str) -> _DependencyFacts:
        return facts.setdefault((sbom_id, ref), _DependencyFacts())

    for sbom in sboms:
        raw = _parse_json(sbom.sbom_data)
        if not isinstance(raw, dict):
            continue

        names: dict[str, str] = {}
        for component in raw.get("components") or raw.get("packages") or []:
            if not isinstance(component, dict):
                continue
            ref = _first_text(
                component.get("bom-ref"), component.get("SPDXID"), component.get("spdxid"), component.get("id")
            )
            name = _first_text(component.get("name"), component.get("packageName"), ref)
            if ref:
                names[ref] = name

        edges: dict[str, set[str]] = {}
        for dep in raw.get("dependencies") or []:
            if not isinstance(dep, dict):
                continue
            ref = _clean(dep.get("ref"))
            depends = [_clean(item) for item in dep.get("dependsOn") or [] if _clean(item)]
            if not ref or not depends:
                continue
            edges.setdefault(ref, set()).update(depends)
            entry(sbom.id, ref).depends_on.update(names.get(item, item) for item in depends)
            entry(sbom.id, ref).relationships.add(
                "Depends on: " + ", ".join(names.get(item, item) for item in depends)
            )
            for item in depends:
                entry(sbom.id, item).required_by.add(names.get(ref, ref))
                entry(sbom.id, item).relationships.add(f"Required by: {names.get(ref, ref)}")

        # Roots are the document's own component plus anything nothing depends on.
        metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
        top = metadata.get("component") if isinstance(metadata.get("component"), dict) else {}
        declared_root = _first_text(top.get("bom-ref"), top.get("name"))
        depended_on = {child for children in edges.values() for child in children}
        roots = [ref for ref in edges if ref not in depended_on]
        if declared_root and declared_root not in roots:
            roots.append(declared_root)

        for ref, depth in _dependency_depths(roots, edges).items():
            record = entry(sbom.id, ref)
            record.depth = depth if record.depth is None else min(record.depth, depth)
            record.is_direct = record.is_direct or depth == 1

        for rel in raw.get("relationships") or []:
            if not isinstance(rel, dict):
                continue
            source = _first_text(rel.get("spdxElementId"), rel.get("source"))
            target = _first_text(rel.get("relatedSpdxElement"), rel.get("target"))
            rel_type = _first_text(rel.get("relationshipType"), rel.get("type"))
            if source and target and rel_type:
                entry(sbom.id, source).relationships.add(f"{rel_type}: {names.get(target, target)}")
                if rel_type.upper() in {"DEPENDS_ON", "CONTAINS"}:
                    entry(sbom.id, source).depends_on.add(names.get(target, target))
                    entry(sbom.id, target).required_by.add(names.get(source, source))
    return facts


def _extract_dependency_map(sboms: list[SBOMSource]) -> dict[tuple[int, str], set[str]]:
    result: dict[tuple[int, str], set[str]] = {}
    for sbom in sboms:
        raw = _parse_json(sbom.sbom_data)
        if not isinstance(raw, dict):
            continue
        names: dict[str, str] = {}
        for component in raw.get("components") or raw.get("packages") or []:
            if not isinstance(component, dict):
                continue
            ref = _first_text(component.get("bom-ref"), component.get("SPDXID"), component.get("spdxid"), component.get("id"))
            name = _first_text(component.get("name"), component.get("packageName"), ref)
            if ref:
                names[ref] = name

        for dep in raw.get("dependencies") or []:
            if not isinstance(dep, dict):
                continue
            ref = _clean(dep.get("ref"))
            depends = [_clean(item) for item in dep.get("dependsOn") or [] if _clean(item)]
            if ref and depends:
                result.setdefault((sbom.id, ref), set()).add("Depends on: " + ", ".join(names.get(item, item) for item in depends))
                for item in depends:
                    result.setdefault((sbom.id, item), set()).add(f"Required by: {names.get(ref, ref)}")

        for rel in raw.get("relationships") or []:
            if not isinstance(rel, dict):
                continue
            source = _first_text(rel.get("spdxElementId"), rel.get("source"))
            target = _first_text(rel.get("relatedSpdxElement"), rel.get("target"))
            rel_type = _first_text(rel.get("relationshipType"), rel.get("type"))
            if source and target and rel_type:
                result.setdefault((sbom.id, source), set()).add(f"{rel_type}: {names.get(target, target)}")
    return result


def _copy_row_template(ws: Worksheet, source_row: int, target_row: int) -> None:
    ws.row_dimensions[target_row].height = ws.row_dimensions[source_row].height
    for col in range(1, ws.max_column + 1):
        source = ws.cell(source_row, col)
        target = ws.cell(target_row, col)
        if source.has_style:
            target._style = copy(source._style)
        if source.number_format:
            target.number_format = source.number_format
        if source.font:
            target.font = copy(source.font)
        if source.fill:
            target.fill = copy(source.fill)
        if source.border:
            target.border = copy(source.border)
        if source.alignment:
            target.alignment = copy(source.alignment)
        if source.protection:
            target.protection = copy(source.protection)
        if source.value and isinstance(source.value, str) and source.value.startswith("="):
            target.value = Translator(source.value, origin=source.coordinate).translate_formula(target.coordinate)
        else:
            target.value = None


def _clear_and_prepare_rows(ws: Worksheet, *, start_row: int, style_row: int, last_row: int) -> None:
    """Blank the example row(s), then extend the template for oversized data.

    The template already carries styling, per-row formulas and validation to
    ``TEMPLATE_LAST_ROW``, so within that band only literal values are cleared
    — re-copying the style row would overwrite the formula columns. Beyond it,
    the row template is copied so a >498-row SBOM still renders (and its
    formulas are translated by ``_copy_row_template``).
    """
    formula_safe_last = min(TEMPLATE_LAST_ROW, max(ws.max_row, last_row))
    for row in range(start_row, formula_safe_last + 1):
        for col in range(1, ws.max_column + 1):
            cell = ws.cell(row, col)
            if isinstance(cell.value, str) and cell.value.startswith("="):
                continue
            cell.value = None
    for row in range(TEMPLATE_LAST_ROW + 1, last_row + 1):
        _copy_row_template(ws, style_row, row)


def _set_row_values(ws: Worksheet, row: int, values: dict[int, Any]) -> None:
    for col, value in values.items():
        ws.cell(row, col).value = value


class Fda510kExcelReportService:
    """Build the approved FDA workbook from persisted SBOM analysis data."""

    def __init__(self, db: Session, *, template_path: Path = FDA_510K_TEMPLATE_PATH) -> None:
        self.db = db
        self.template_path = template_path

    def build(
        self,
        project_id: int,
        selections: list[Fda510kSelection],
        metadata: Fda510kReportMetadata,
    ) -> tuple[bytes, str]:
        project, sboms, runs = self._validate_request(project_id, selections)
        dependency_facts = _extract_dependency_facts(sboms)
        aggregates = self._component_aggregates(sboms, runs, dependency_facts)
        # FDA Sec. VII keeps OS / container / firmware dependencies on their own
        # sheet, so they are split out of the application component inventory
        # rather than listed twice.
        component_rows = [row for row in aggregates if not row.environment_category]
        environment_rows = [row for row in aggregates if row.environment_category]
        vulnerability_rows = self._vulnerability_rows(runs)
        lifecycle_rows = self._lifecycle_rows(aggregates)
        content = self._build_workbook(
            metadata,
            component_rows,
            environment_rows,
            vulnerability_rows,
            lifecycle_rows,
        )
        filename = self.filename_for(project.project_name)
        return content, filename

    @staticmethod
    def filename_for(project_name: str | None) -> str:
        stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M")
        return f"{_safe_filename(project_name or 'project')}_FDA_510k_SBOM_Report_{stamp}.xlsx"

    def _validate_request(
        self,
        project_id: int,
        selections: list[Fda510kSelection],
    ) -> tuple[Projects, list[SBOMSource], dict[int, AnalysisRun]]:
        if not self.template_path.exists():
            raise Fda510kTemplateMissingError(f"Expected FDA 510(k) template at {self.template_path}")
        if not selections:
            raise Fda510kReportError("At least one SBOM must be selected.")

        project = self.db.get(Projects, project_id)
        if project is None or not project.is_active:
            raise Fda510kReportError("Project not found.")

        unique_ids = list(dict.fromkeys(selection.sbom_id for selection in selections))
        if len(unique_ids) != len(selections):
            raise Fda510kReportError("Duplicate SBOM selections are not allowed.")

        sboms = list(
            self.db.execute(select(SBOMSource).where(SBOMSource.id.in_(unique_ids)).order_by(SBOMSource.id.asc())).scalars()
        )
        by_id = {sbom.id: sbom for sbom in sboms}
        missing = [sbom_id for sbom_id in unique_ids if sbom_id not in by_id]
        if missing:
            raise Fda510kReportError(f"Selected SBOM not found: {missing[0]}")

        wrong_project = [sbom for sbom in sboms if sbom.projectid != project_id]
        if wrong_project:
            raise Fda510kReportError(f"Selected SBOM '{wrong_project[0].sbom_name}' does not belong to project {project_id}.")

        blockers: list[dict[str, Any]] = []
        runs: dict[int, AnalysisRun] = {}
        for selection in selections:
            sbom = by_id[selection.sbom_id]
            run = self._resolve_findings_run(sbom, selection.findings_analysis_run_id)
            if run is None:
                blockers.append(self._blocker(sbom, "findings", self._latest_findings_status(sbom)))
            elif run.run_status not in COMPLETED_RUN_STATUSES:
                blockers.append(self._blocker(sbom, "findings", run.run_status or "unknown"))
            else:
                runs[sbom.id] = run

            if selection.lifecycle_analysis_run_id is not None:
                lifecycle_run = self.db.get(AnalysisRun, selection.lifecycle_analysis_run_id)
                if lifecycle_run is None or lifecycle_run.sbom_id != sbom.id:
                    raise Fda510kReportError(
                        f"Lifecycle analysis run {selection.lifecycle_analysis_run_id} does not belong to SBOM {sbom.id}."
                    )
                if lifecycle_run.run_status not in COMPLETED_RUN_STATUSES:
                    blockers.append(self._blocker(sbom, "lifecycle", lifecycle_run.run_status or "unknown"))

            lifecycle_status = self._lifecycle_completion_status(sbom)
            if lifecycle_status != "completed":
                blockers.append(self._blocker(sbom, "lifecycle", lifecycle_status))

        if blockers:
            raise Fda510kIncompleteAnalysisError(blockers)
        return project, [by_id[sbom_id] for sbom_id in unique_ids], runs

    def _resolve_findings_run(self, sbom: SBOMSource, run_id: int | None) -> AnalysisRun | None:
        if run_id is not None:
            run = self.db.get(AnalysisRun, run_id)
            if run is None or run.sbom_id != sbom.id:
                raise Fda510kReportError(f"Findings analysis run {run_id} does not belong to SBOM {sbom.id}.")
            return run
        return self.db.execute(
            select(AnalysisRun)
            .where(AnalysisRun.sbom_id == sbom.id, AnalysisRun.run_status.in_(COMPLETED_RUN_STATUSES))
            .order_by(AnalysisRun.completed_on.desc(), AnalysisRun.id.desc())
            .limit(1)
        ).scalar_one_or_none()

    def _latest_findings_status(self, sbom: SBOMSource) -> str:
        run = self.db.execute(
            select(AnalysisRun)
            .where(AnalysisRun.sbom_id == sbom.id)
            .order_by(AnalysisRun.completed_on.desc(), AnalysisRun.id.desc())
            .limit(1)
        ).scalar_one_or_none()
        return run.run_status if run is not None and run.run_status else "missing"

    def _lifecycle_completion_status(self, sbom: SBOMSource) -> str:
        status = _clean(sbom.enrichment_status).casefold()
        if status in {"running", "pending", "queued", "in_progress"}:
            return "running"
        if status in {"failed", "error", "cancelled", "canceled"}:
            return status
        components = list(
            self.db.execute(
                select(SBOMComponent).where(
                    SBOMComponent.sbom_id == sbom.id,
                    (SBOMComponent.is_duplicate.is_(False)) | (SBOMComponent.is_duplicate.is_(None)),
                )
            ).scalars()
        )
        if not components:
            return "missing"
        if all(_clean(component.lifecycle_checked_at) for component in components):
            return "completed"
        return "missing"

    @staticmethod
    def _blocker(sbom: SBOMSource, analysis_type: str, status: str) -> dict[str, Any]:
        return {
            "sbom_id": sbom.id,
            "sbom_name": sbom.sbom_name,
            "analysis_type": analysis_type,
            "status": status,
        }

    def _component_aggregates(
        self,
        sboms: list[SBOMSource],
        runs: dict[int, AnalysisRun],
        dependency_facts: dict[tuple[int, str], _DependencyFacts],
    ) -> list[_ComponentAggregate]:
        findings_by_component: dict[int, set[str]] = {}
        for finding in self.db.execute(
            select(AnalysisFinding).where(AnalysisFinding.analysis_run_id.in_([run.id for run in runs.values()]))
        ).scalars():
            if finding.component_id is not None:
                findings_by_component.setdefault(finding.component_id, set()).add(finding.vuln_id)

        aggregates: dict[str, _ComponentAggregate] = {}
        components = list(
            self.db.execute(
                select(SBOMComponent)
                .where(
                    SBOMComponent.sbom_id.in_([sbom.id for sbom in sboms]),
                    (SBOMComponent.is_duplicate.is_(False)) | (SBOMComponent.is_duplicate.is_(None)),
                )
                .order_by(SBOMComponent.name.asc(), SBOMComponent.version.asc(), SBOMComponent.id.asc())
            ).scalars()
        )
        sbom_names = {sbom.id: sbom.sbom_name for sbom in sboms}
        for component in components:
            key = _component_identity(component)
            unique_type, unique_value = _unique_id(component)
            aggregate = aggregates.get(key)
            if aggregate is None:
                aggregate = _ComponentAggregate(
                    key=key,
                    name=_first_text(component.name, component.normalized_name),
                    version=_first_text(component.version, component.normalized_version),
                    supplier=_first_text(component.supplier, component.normalized_supplier),
                    unique_id_type=unique_type,
                    unique_id_value=unique_value,
                    component_type=_first_text(component.component_type, "Library"),
                    origin_category=_origin_category(component),
                    license=_clean(component.license),
                    support_level=_support_level(component),
                    eos_date=_parse_date(component.eos_date),
                    eol_date=_parse_date(component.eol_date or component.eof_date),
                    patch_mechanism=_first_text(component.recommended_version, component.latest_supported_version),
                    crypto_info="",
                    component_hash=_component_hash(component),
                    environment_category=_environment_category(component),
                )
                aggregates[key] = aggregate
            aggregate.source_sboms.add(sbom_names.get(component.sbom_id, f"SBOM #{component.sbom_id}"))
            facts = dependency_facts.get((component.sbom_id, component.bom_ref or ""))
            if facts is not None:
                aggregate.dependencies.update(facts.relationships)
                aggregate.depends_on.update(facts.required_by)
                aggregate.required_by.update(facts.required_by)
                aggregate.is_direct = aggregate.is_direct or facts.is_direct
                if facts.depth is not None:
                    aggregate.dependency_depth = (
                        facts.depth
                        if aggregate.dependency_depth is None
                        else min(aggregate.dependency_depth, facts.depth)
                    )
            aggregate.vulnerabilities.update(findings_by_component.get(component.id, set()))
            if _clean(component.lifecycle_recommendation):
                aggregate.lifecycle_recommendations.add(_clean(component.lifecycle_recommendation))
            aggregate.components.append(component)

        return sorted(aggregates.values(), key=lambda item: (item.name.casefold(), item.version.casefold(), item.key))

    def _vulnerability_rows(self, runs: dict[int, AnalysisRun]) -> list[dict[str, Any]]:
        if not runs:
            return []
        findings = list(
            self.db.execute(
                select(AnalysisFinding)
                .where(AnalysisFinding.analysis_run_id.in_([run.id for run in runs.values()]))
                .order_by(AnalysisFinding.vuln_id.asc(), AnalysisFinding.component_name.asc(), AnalysisFinding.id.asc())
            ).scalars()
        )
        component_ids = [finding.component_id for finding in findings if finding.component_id is not None]
        components = {
            component.id: component
            for component in self.db.execute(select(SBOMComponent).where(SBOMComponent.id.in_(component_ids))).scalars()
        }
        vex_rows = list(
            self.db.execute(
                select(VexStatement).where(VexStatement.sbom_id.in_([run.sbom_id for run in runs.values()]))
            ).scalars()
        )
        # Threat-intel columns added by the revised template (I "EPSS Score",
        # J "CISA KEV Status"). Batched by CVE rather than per finding.
        cve_ids = {_clean(finding.vuln_id) for finding in findings if _clean(finding.vuln_id)}
        epss_by_cve: dict[str, float | None] = {}
        kev_by_cve: dict[str, bool] = {}
        if cve_ids:
            for score in self.db.execute(select(EpssScore).where(EpssScore.cve_id.in_(cve_ids))).scalars():
                epss_by_cve[_clean(score.cve_id).casefold()] = score.epss
            for entry in self.db.execute(select(KevEntry).where(KevEntry.cve_id.in_(cve_ids))).scalars():
                kev_by_cve[_clean(entry.cve_id).casefold()] = True

        vex_by_key: dict[tuple[int, int, int | None, str], VexStatement] = {}
        from .lifecycle.vex_provider import effective_vex_statements

        for row in effective_vex_statements(vex_rows):
            for vuln in (row.vulnerability_id, row.cve_id):
                if _clean(vuln):
                    vex_by_key[(row.tenant_id, row.sbom_id, row.component_id, _clean(vuln).casefold())] = row
                    # Component-specific decisions must never apply to another component.

        rows: list[dict[str, Any]] = []
        seen = set()
        runs_by_id = {run.id: run for run in runs.values()}
        for finding in findings:
            component = components.get(finding.component_id) if finding.component_id else None
            identity = _component_identity(component) if component else f"finding-component:{finding.component_name}:{finding.component_version}"
            run = runs_by_id[finding.analysis_run_id]
            key = (run.tenant_id, run.sbom_id, identity, finding.vuln_id.casefold())
            if key in seen:
                continue
            seen.add(key)
            vex = vex_by_key.get((run.tenant_id, run.sbom_id, finding.component_id, finding.vuln_id.casefold())) if finding.component_id else None
            raw_status = _clean(getattr(vex, "status", None)).casefold().replace(" ", "_")
            status = VEX_STATUS_LABELS.get(raw_status, "Under Investigation")
            kev = kev_by_cve.get(finding.vuln_id.casefold())
            rows.append(
                {
                    "component_name": _first_text(component.name if component else None, finding.component_name),
                    "component_version": _first_text(component.version if component else None, finding.component_version),
                    "vulnerability_id": finding.vuln_id,
                    "cvss_version": _first_text(
                        finding.cvss_version, "3.1" if _clean(finding.vector).startswith("CVSS:3.") else ""
                    ),
                    "cvss_score": finding.score,
                    "cvss_vector": _clean(finding.vector),
                    "severity": _severity(finding.severity),
                    "epss_score": epss_by_cve.get(finding.vuln_id.casefold()),
                    "kev_status": "Yes" if kev else "No",
                    "vex_status": status,
                    "vex_justification": _first_text(getattr(vex, "justification", None)),
                    "patient_impact": "",
                    # Only KEV membership is evidence the platform holds; the
                    # richer options (PoC, weaponized) are analyst judgements
                    # and stay blank rather than being guessed at.
                    "exploitability": EXPLOITABILITY_KEV if kev else "",
                    "remediation": _first_text(
                        getattr(vex, "action_statement", None),
                        getattr(vex, "mitigation", None),
                    ),
                    "fixed_versions": _first_text(
                        getattr(vex, "fixed_version", None),
                        ", ".join(_as_list(finding.fixed_versions)),
                    ),
                    "remediation_owner": "",
                    "target_date": None,
                    "status": "Resolved" if status.casefold() == "fixed" else "Open",
                    "notes": _first_text(finding.source, finding.reference_url, finding.match_reason),
                }
            )
        return rows

    @staticmethod
    def _dependency_type(row: _ComponentAggregate) -> str:
        """Direct / Transitive for column G, blank when the graph is unknown.

        An SBOM with no dependency graph gives no basis to call a component
        either, and guessing "Direct" would overstate what the document says.
        """
        if row.is_direct or row.dependency_depth == 1:
            return "Direct"
        if row.dependency_depth is not None and row.dependency_depth > 1:
            return "Transitive"
        if row.required_by:
            return "Transitive"
        return ""

    @staticmethod
    def _lifecycle_rows(component_rows: list[_ComponentAggregate]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for aggregate in component_rows:
            representative = aggregate.components[0] if aggregate.components else None
            if representative is None:
                continue
            status = _clean(representative.lifecycle_status)
            has_lifecycle_signal = any(
                [
                    aggregate.eos_date,
                    aggregate.eol_date,
                    status and status.casefold() not in {"unknown", "active", "supported"},
                    representative.unsupported,
                    representative.deprecated,
                    representative.is_deprecated,
                ]
            )
            if not has_lifecycle_signal:
                continue
            rows.append(
                {
                    "name": aggregate.name,
                    "version": aggregate.version,
                    "supplier": aggregate.supplier,
                    "support_level": aggregate.support_level,
                    "eos_date": aggregate.eos_date,
                    "eol_date": aggregate.eol_date,
                    "risk": _risk_for_lifecycle(representative),
                    "plan": _first_text(
                        "; ".join(sorted(aggregate.lifecycle_recommendations)),
                        representative.recommended_version and f"Upgrade to {representative.recommended_version}",
                    ),
                    "controls": "",
                    "verification": "",
                    "owner": "",
                    "target_date": None,
                    "status": "Planned",
                }
            )
        return rows

    def _build_workbook(
        self,
        metadata: Fda510kReportMetadata,
        component_rows: list[_ComponentAggregate],
        environment_rows: list[_ComponentAggregate],
        vulnerability_rows: list[dict[str, Any]],
        lifecycle_rows: list[dict[str, Any]],
    ) -> bytes:
        workbook = load_workbook(self.template_path)
        if tuple(workbook.sheetnames) != EXPECTED_SHEETS:
            raise Fda510kReportError(f"FDA template sheet contract mismatch: {workbook.sheetnames}")

        metadata_ws = workbook["SBOM Metadata"]
        generated_at = datetime.now(UTC).replace(tzinfo=None, microsecond=0)
        # Row numbers follow the revised template: the author block gained
        # Organization / Role / Email at 16-18, pushing Timestamp to 19, and a
        # Manufacturer Security Contact block at 26-28 pushed Sign-off to 31.
        # Rows 37+ are the workbook's own live formulas — never written here.
        metadata_values = {
            "C5": metadata.device_name,
            "C6": metadata.device_model_catalog_number,
            "C7": metadata.manufacturer_sponsor,
            "C8": metadata.submission_type or "510(k)",
            "C9": metadata.submission_number,
            "C10": metadata.product_code_regulation_number,
            "C11": metadata.device_software_version,
            "C12": metadata.top_level_primary_component,
            "C15": metadata.author_of_sbom_data,
            "C16": metadata.author_organization,
            "C17": metadata.author_role_title,
            "C18": metadata.author_email,
            "C19": generated_at,
            "C20": metadata.sbom_version,
            "C21": metadata.sbom_formats_for_submission,
            "C22": metadata.sbom_generation_tool_and_version,
            "C23": metadata.primary_data_source,
            "C26": metadata.psirt_contact,
            "C27": metadata.cvd_policy_url,
            "C28": metadata.vulnerability_intake_method,
            "C31": metadata.prepared_by,
            "C32": metadata.date_prepared,
            "C33": metadata.reviewed_approved_by,
            "C34": metadata.date_approved,
        }
        for cell, value in metadata_values.items():
            metadata_ws[cell] = value
        metadata_ws["C19"].number_format = "yyyy-mm-dd hh:mm"
        metadata_ws["C32"].number_format = "yyyy-mm-dd"
        metadata_ws["C34"].number_format = "yyyy-mm-dd"

        comp_ws = workbook["SBOM Components"]
        _clear_and_prepare_rows(
            comp_ws,
            start_row=DATA_START_ROW,
            style_row=DATA_START_ROW,
            last_row=max(DATA_START_ROW, DATA_START_ROW - 1 + len(component_rows)),
        )
        for index, row in enumerate(component_rows, start=1):
            _set_row_values(
                comp_ws,
                DATA_START_ROW - 1 + index,
                {
                    COMPONENT_COLS["index"]: index,
                    COMPONENT_COLS["name"]: row.name,
                    COMPONENT_COLS["version"]: row.version,
                    COMPONENT_COLS["supplier"]: row.supplier,
                    COMPONENT_COLS["unique_id_type"]: _coerce_choice(
                        row.unique_id_type, UNIQUE_ID_TYPES, "Other" if row.unique_id_value else ""
                    ),
                    COMPONENT_COLS["unique_id_value"]: row.unique_id_value,
                    COMPONENT_COLS["dependency_type"]: self._dependency_type(row),
                    COMPONENT_COLS["depends_on"]: "; ".join(sorted(row.required_by)),
                    COMPONENT_COLS["dependency_depth"]: row.dependency_depth,
                    COMPONENT_COLS["component_type"]: _coerce_choice(
                        row.component_type, COMPONENT_TYPES, "Library"
                    ),
                    COMPONENT_COLS["origin_category"]: _coerce_choice(
                        row.origin_category, ORIGIN_CATEGORIES
                    ),
                    COMPONENT_COLS["license"]: row.license,
                    COMPONENT_COLS["support_level"]: _coerce_choice(
                        row.support_level, SUPPORT_LEVELS, "Unknown"
                    ),
                    COMPONENT_COLS["eos_date"]: row.eos_date,
                    COMPONENT_COLS["eol_date"]: row.eol_date,
                    COMPONENT_COLS["vulnerabilities"]: ", ".join(sorted(row.vulnerabilities)),
                    COMPONENT_COLS["patch_mechanism"]: row.patch_mechanism,
                    COMPONENT_COLS["hash"]: row.component_hash,
                    COMPONENT_COLS["notes"]: "; ".join(
                        part
                        for part in (
                            "Source SBOM(s): " + ", ".join(sorted(row.source_sboms))
                            if row.source_sboms
                            else "",
                            "; ".join(sorted(row.dependencies)),
                        )
                        if part
                    ),
                },
            )

        # Environment & 3rd-Party Deps — OS, container base images and firmware,
        # split out of the component inventory per FDA Sec. VII.
        env_ws = workbook["Environment & 3rd-Party Deps"]
        _clear_and_prepare_rows(
            env_ws,
            start_row=DATA_START_ROW,
            style_row=DATA_START_ROW,
            last_row=max(DATA_START_ROW, DATA_START_ROW - 1 + len(environment_rows)),
        )
        for index, row in enumerate(environment_rows, start=1):
            _set_row_values(
                env_ws,
                DATA_START_ROW - 1 + index,
                {
                    ENVIRONMENT_COLS["index"]: index,
                    ENVIRONMENT_COLS["category"]: row.environment_category,
                    ENVIRONMENT_COLS["name"]: row.name,
                    ENVIRONMENT_COLS["version"]: row.version,
                    ENVIRONMENT_COLS["supplier"]: row.supplier,
                    ENVIRONMENT_COLS["unique_id"]: row.unique_id_value,
                    ENVIRONMENT_COLS["support_level"]: _coerce_choice(
                        row.support_level, SUPPORT_LEVELS, "Unknown"
                    ),
                    ENVIRONMENT_COLS["eos_date"]: row.eos_date,
                    ENVIRONMENT_COLS["eol_date"]: row.eol_date,
                    ENVIRONMENT_COLS["vulnerabilities"]: ", ".join(sorted(row.vulnerabilities)),
                    ENVIRONMENT_COLS["notes"]: "; ".join(sorted(row.source_sboms)),
                },
            )

        vuln_ws = workbook["Vulnerabilities & VEX"]
        _clear_and_prepare_rows(
            vuln_ws,
            start_row=DATA_START_ROW,
            style_row=DATA_START_ROW,
            last_row=max(DATA_START_ROW, DATA_START_ROW - 1 + len(vulnerability_rows)),
        )
        for index, row in enumerate(vulnerability_rows, start=1):
            _set_row_values(
                vuln_ws,
                DATA_START_ROW - 1 + index,
                {
                    VULNERABILITY_COLS["index"]: index,
                    VULNERABILITY_COLS["component_name"]: row["component_name"],
                    VULNERABILITY_COLS["component_version"]: row["component_version"],
                    VULNERABILITY_COLS["vulnerability_id"]: row["vulnerability_id"],
                    VULNERABILITY_COLS["cvss_version"]: row["cvss_version"],
                    VULNERABILITY_COLS["cvss_score"]: row["cvss_score"],
                    VULNERABILITY_COLS["cvss_vector"]: row["cvss_vector"],
                    VULNERABILITY_COLS["severity"]: row["severity"],
                    VULNERABILITY_COLS["epss_score"]: row["epss_score"],
                    VULNERABILITY_COLS["kev_status"]: row["kev_status"],
                    VULNERABILITY_COLS["vex_status"]: row["vex_status"],
                    VULNERABILITY_COLS["vex_justification"]: row["vex_justification"],
                    VULNERABILITY_COLS["patient_impact"]: row["patient_impact"],
                    VULNERABILITY_COLS["exploitability"]: row["exploitability"],
                    VULNERABILITY_COLS["remediation"]: row["remediation"],
                    VULNERABILITY_COLS["fixed_versions"]: row["fixed_versions"],
                    VULNERABILITY_COLS["remediation_owner"]: row["remediation_owner"],
                    VULNERABILITY_COLS["target_date"]: row["target_date"],
                    VULNERABILITY_COLS["status"]: row["status"],
                    VULNERABILITY_COLS["notes"]: row["notes"],
                },
            )

        lifecycle_ws = workbook["Lifecycle & Support Plan"]
        _clear_and_prepare_rows(
            lifecycle_ws,
            start_row=DATA_START_ROW,
            style_row=DATA_START_ROW,
            last_row=max(DATA_START_ROW, DATA_START_ROW - 1 + len(lifecycle_rows)),
        )
        for index, row in enumerate(lifecycle_rows, start=1):
            _set_row_values(
                lifecycle_ws,
                DATA_START_ROW - 1 + index,
                {
                    LIFECYCLE_COLS["index"]: index,
                    LIFECYCLE_COLS["name"]: row["name"],
                    LIFECYCLE_COLS["version"]: row["version"],
                    LIFECYCLE_COLS["supplier"]: row["supplier"],
                    LIFECYCLE_COLS["support_level"]: _coerce_choice(
                        row["support_level"], SUPPORT_LEVELS, "Unknown"
                    ),
                    LIFECYCLE_COLS["eos_date"]: row["eos_date"],
                    LIFECYCLE_COLS["eol_date"]: row["eol_date"],
                    LIFECYCLE_COLS["risk"]: row["risk"],
                    LIFECYCLE_COLS["plan"]: row["plan"],
                    LIFECYCLE_COLS["controls"]: row["controls"],
                    LIFECYCLE_COLS["verification"]: row["verification"],
                    LIFECYCLE_COLS["owner"]: row["owner"],
                    LIFECYCLE_COLS["target_date"]: row["target_date"],
                    LIFECYCLE_COLS["status"]: row["status"],
                },
            )

        # Supplier & Security Contacts is left blank for manual completion:
        # PSIRT addresses and CVD policy URLs are not data the platform holds,
        # and inventing them in a regulatory submission would be worse than an
        # empty sheet the submitter must fill in.
        contacts_ws = workbook["Supplier & Security Contacts"]
        _clear_and_prepare_rows(
            contacts_ws,
            start_row=DATA_START_ROW,
            style_row=DATA_START_ROW,
            last_row=DATA_START_ROW,
        )

        workbook.calculation.calcMode = "auto"
        workbook.calculation.fullCalcOnLoad = True
        workbook.calculation.forceFullCalc = True

        output = BytesIO()
        workbook.save(output)
        return output.getvalue()


__all__ = [
    "EXCEL_MEDIA_TYPE",
    "FDA_510K_TEMPLATE_PATH",
    "Fda510kExcelReportService",
    "Fda510kIncompleteAnalysisError",
    "Fda510kReportError",
    "Fda510kReportMetadata",
    "Fda510kSelection",
    "Fda510kTemplateMissingError",
    "INCOMPLETE_ANALYSIS_CODE",
]
