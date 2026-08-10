"""Component-level normalization for Stage 9."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from .cpe_normalizer import cpe_version, normalize_cpes
from .purl_normalizer import normalize_purl
from .version_normalizer import normalize_version

ECOSYSTEM_ALIASES = {
    "node": "npm",
    "nodejs": "npm",
    "javascript": "npm",
    "js": "npm",
    "pypi": "pypi",
    "python": "pypi",
    "pip": "pypi",
    "maven": "maven",
    "java": "maven",
    "nuget": "nuget",
    "dotnet": "nuget",
    ".net": "nuget",
    "gem": "rubygems",
    "rubygems": "rubygems",
    "deb": "debian",
    "debian": "debian",
    "rpm": "rpm",
    "redhat": "redhat",
    "rhel": "redhat",
    "apk": "alpine",
    "alpine": "alpine",
    "generic": "generic",
    "unknown": "generic",
}

NAME_ALIASES = {
    "node.js": "nodejs",
    "node": "nodejs",
    "postgres": "postgresql",
    "postgresql": "postgresql",
    ".net": "dotnet",
    "dotnet": "dotnet",
    "aspnetcore": "dotnet",
}


@dataclass(slots=True)
class NormalizedComponentResult:
    component: dict[str, Any]
    notes: list[str] = field(default_factory=list)


def normalize_component(component: dict[str, Any], *, index: int = 0) -> NormalizedComponentResult:
    raw_name = _clean(component.get("name"))
    raw_version = _clean(component.get("version"))
    raw_supplier = _clean(component.get("supplier"))
    raw_type = _clean(component.get("type") or component.get("component_type"))
    raw_group = _clean(component.get("group") or component.get("component_group"))
    notes: list[str] = []

    purl_result = normalize_purl(component.get("purl"), fallback_version=raw_version)
    notes.extend(purl_result.notes)
    ecosystem = normalize_ecosystem(component.get("ecosystem") or purl_result.purl_type or raw_type or raw_group)
    version_result = normalize_version(purl_result.version or raw_version, ecosystem=ecosystem)
    notes.extend(version_result.notes)
    cpe_result = normalize_cpes(component.get("cpes"), component.get("cpe"))
    notes.extend(cpe_result.notes)

    normalized_name = _name_from_purl(purl_result) or raw_name or ""
    normalized_name = normalize_name(normalized_name, ecosystem=ecosystem)
    if not normalized_name and cpe_result.primary_cpe:
        parts = cpe_result.primary_cpe.split(":")
        if len(parts) == 13:
            normalized_name = normalize_name(parts[4], ecosystem=ecosystem)

    supplier = normalize_supplier(raw_supplier)
    identity_key, confidence, reason = build_identity_key(
        normalized_purl=purl_result.normalized_purl if purl_result.valid else None,
        primary_cpe=cpe_result.primary_cpe,
        ecosystem=ecosystem,
        normalized_name=normalized_name,
        normalized_version=version_result.normalized_version,
        supplier=supplier,
    )
    canonical_id = hashlib.sha256(identity_key.encode("utf-8")).hexdigest() if identity_key else None
    package_key = _package_key(ecosystem, normalized_name, supplier)

    out = dict(component)
    out.update(
        {
            "original_name": raw_name,
            "normalized_name": normalized_name or None,
            "original_version": raw_version,
            "normalized_version": version_result.normalized_version,
            "normalized_ecosystem": ecosystem,
            "ecosystem": component.get("ecosystem") or ecosystem,
            "original_purl": _clean(component.get("purl")),
            "normalized_purl": purl_result.normalized_purl,
            "purl_type": purl_result.purl_type,
            "purl_namespace": purl_result.namespace,
            "purl_name": purl_result.name,
            "purl_version": purl_result.version,
            "purl_qualifiers_json": purl_result.qualifiers,
            "purl_subpath": purl_result.subpath,
            "normalized_cpes": cpe_result.normalized_cpes,
            "primary_cpe": cpe_result.primary_cpe,
            "cpe_evidence_json": cpe_result.evidence,
            "normalized_supplier": supplier,
            "normalized_package_key": package_key,
            "normalized_component_key": identity_key,
            "dedupe_canonical_id": canonical_id,
            "canonical_identity_confidence": confidence,
            "dedupe_confidence": confidence,
            "dedupe_reason": reason,
            "normalization_notes_json": list(dict.fromkeys(notes)),
            "normalization_index": index,
        }
    )
    if out.get("purl") and purl_result.normalized_purl:
        out["purl"] = purl_result.normalized_purl
    if cpe_result.primary_cpe:
        out["cpe"] = cpe_result.primary_cpe
    if version_result.normalized_version:
        out["version"] = version_result.normalized_version
    if normalized_name:
        out["name"] = normalized_name if ecosystem in {"npm", "pypi", "rubygems"} else raw_name or normalized_name
    return NormalizedComponentResult(out, out["normalization_notes_json"])


def normalize_ecosystem(value: Any) -> str:
    cleaned = _clean(value)
    if not cleaned:
        return "generic"
    return ECOSYSTEM_ALIASES.get(cleaned.lower(), cleaned.lower())


def normalize_name(value: Any, *, ecosystem: str | None = None) -> str:
    cleaned = re.sub(r"\s+", " ", str(value or "").strip())
    if not cleaned:
        return ""
    eco = normalize_ecosystem(ecosystem)
    lowered = cleaned.lower()
    if eco == "npm" and lowered.startswith("%40"):
        lowered = "@" + lowered[3:]
    if eco in {"npm", "pypi", "rubygems", "nuget", "maven", "golang", "go"}:
        cleaned = lowered
    if eco == "maven":
        cleaned = cleaned.replace(":", "/")
    cleaned = NAME_ALIASES.get(cleaned.lower(), cleaned)
    if eco in {"npm", "pypi", "rubygems"}:
        cleaned = cleaned.replace("_", "-")
    return cleaned


def normalize_supplier(value: Any) -> str | None:
    cleaned = _clean(value)
    if not cleaned:
        return None
    lowered = re.sub(r"\s+", " ", cleaned).lower()
    for prefix in ("organization: ", "person: "):
        if lowered.startswith(prefix):
            return lowered[len(prefix) :]
    return lowered


def build_identity_key(
    *,
    normalized_purl: str | None,
    primary_cpe: str | None,
    ecosystem: str,
    normalized_name: str | None,
    normalized_version: str | None,
    supplier: str | None,
) -> tuple[str | None, str, str | None]:
    if normalized_purl and "@" in normalized_purl:
        return f"purl:{normalized_purl}", "High", "same_normalized_purl"
    if primary_cpe and cpe_version(primary_cpe):
        return f"cpe:{primary_cpe}", "High", "same_normalized_cpe"
    if ecosystem and normalized_name and normalized_version and supplier:
        return f"name:{ecosystem}:{normalized_name}:{normalized_version}:{supplier}", "Medium", "same_ecosystem_name_version_supplier"
    if ecosystem and normalized_name and normalized_version and ecosystem != "generic":
        return f"name:{ecosystem}:{normalized_name}:{normalized_version}", "Medium", "same_ecosystem_name_version"
    return None, "Low", "insufficient_identity"


def _name_from_purl(purl_result) -> str | None:
    if not purl_result.valid or not purl_result.name:
        return None
    if purl_result.purl_type == "npm" and purl_result.namespace:
        return f"@{purl_result.namespace.lstrip('@')}/{purl_result.name}"
    if purl_result.purl_type in {"maven", "golang", "go", "nuget"} and purl_result.namespace:
        return f"{purl_result.namespace}/{purl_result.name}"
    return purl_result.name


def _package_key(ecosystem: str, normalized_name: str | None, supplier: str | None) -> str | None:
    if not normalized_name:
        return None
    return ":".join(part for part in (ecosystem, normalized_name, supplier or "") if part)


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = " ".join(str(value).strip().split())
    return cleaned or None
