"""Component normalization for lifecycle enrichment providers."""

from __future__ import annotations

import re
from typing import Any

from packageurl import PackageURL

from .types import NormalizedComponent, canonical_ecosystem


def normalize_component(component: Any) -> NormalizedComponent:
    """Normalize an ORM component or component-like object for providers."""

    raw_name = (getattr(component, "name", None) or "").strip()
    raw_version = _clean_version(getattr(component, "version", None))
    raw_purl = _clean_str(getattr(component, "purl", None))
    raw_cpe = _clean_str(getattr(component, "cpe", None))
    supplier = _clean_str(getattr(component, "supplier", None))
    component_type = _clean_str(getattr(component, "component_type", None))
    component_group = _clean_str(getattr(component, "component_group", None))
    ecosystem = canonical_ecosystem(getattr(component, "ecosystem", None) or component_type or component_group)
    normalized_name = raw_name.lower()
    normalized_version = raw_version

    if raw_purl:
        parsed = _parse_purl(raw_purl)
        if parsed:
            ecosystem = canonical_ecosystem(parsed.type)
            purl_name = _name_from_purl(parsed)
            normalized_name = purl_name.lower() if purl_name else normalized_name
            normalized_version = _clean_version(parsed.version) or raw_version

    if ecosystem == "generic":
        ecosystem = _infer_ecosystem(raw_name, supplier, component_type, component_group, raw_cpe)

    if not normalized_name and raw_name:
        normalized_name = raw_name.lower()

    return NormalizedComponent(
        component_id=getattr(component, "id", None),
        name=raw_name,
        version=raw_version,
        normalized_name=normalized_name,
        normalized_version=normalized_version,
        ecosystem=ecosystem,
        purl=raw_purl,
        cpe=raw_cpe,
        supplier=supplier,
        component_type=component_type,
        component_group=component_group,
        repository_url=_repository_url_from_component(component),
        external_references=[],
    )


def _parse_purl(value: str) -> PackageURL | None:
    try:
        return PackageURL.from_string(value)
    except Exception:
        return None


def _name_from_purl(purl: PackageURL) -> str:
    name = purl.name or ""
    namespace = purl.namespace or ""
    if purl.type == "npm" and namespace:
        return f"@{namespace.lstrip('@')}/{name}"
    if purl.type in {"maven", "golang", "go", "nuget"} and namespace:
        return f"{namespace}/{name}"
    return name


def _clean_str(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None


def _clean_version(value: Any) -> str | None:
    cleaned = _clean_str(value)
    if not cleaned:
        return None
    if cleaned.lower().startswith("version "):
        cleaned = cleaned[8:].strip()
    if cleaned.startswith("v") and len(cleaned) > 1 and cleaned[1].isdigit():
        cleaned = cleaned[1:]
    return cleaned or None


def _infer_ecosystem(
    name: str,
    supplier: str | None,
    component_type: str | None,
    component_group: str | None,
    cpe: str | None,
) -> str:
    haystack = " ".join(part for part in (name, supplier or "", component_type or "", component_group or "") if part)
    lowered = haystack.lower()
    if re.search(r"(^|[-_/])npm($|[-_/])", lowered) or lowered.startswith("@"):
        return "npm"
    if "pypi" in lowered or lowered.startswith("python-"):
        return "pypi"
    if "maven" in lowered or component_group:
        return "maven"
    if "nuget" in lowered or ".net" in lowered or "dotnet" in lowered:
        return "nuget"
    if "rubygems" in lowered or lowered.startswith("ruby-"):
        return "gem"
    if "golang" in lowered or lowered.startswith("golang.org/") or lowered.startswith("github.com/"):
        return "go"
    if "cargo" in lowered or "crates.io" in lowered:
        return "cargo"
    if "ubuntu" in lowered:
        return "ubuntu"
    if "debian" in lowered:
        return "debian"
    if "alpine" in lowered:
        return "alpine"
    if "docker" in lowered or (component_type and component_type.lower() == "container"):
        return "docker"
    if cpe and ":ubuntu:" in cpe.lower():
        return "ubuntu"
    if cpe and ":debian:" in cpe.lower():
        return "debian"
    return "generic"


def _repository_url_from_component(component: Any) -> str | None:
    evidence = getattr(component, "lifecycle_evidence_json", None) or {}
    if isinstance(evidence, dict):
        url = evidence.get("repository_url") or evidence.get("repository")
        if isinstance(url, str) and url.strip():
            return url.strip()
    return None


__all__ = ["normalize_component"]
