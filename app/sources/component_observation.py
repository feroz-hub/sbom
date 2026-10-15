"""Attach trusted query context to provider observations (never cache DB IDs)."""

from __future__ import annotations

import re

from packageurl import PackageURL
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version
from semantic_version import Version as SemVersion

from .osv_eligibility import canonical_osv_ecosystem


def bind_component(finding: dict, component: dict) -> dict:
    for field in ("component_id", "sbom_id", "tenant_id", "bom_ref", "purl", "ecosystem", "normalized_name"):
        if component.get(field) is not None:
            finding[field] = component[field]
    finding["component_name"] = (
        component.get("original_name") or component.get("name") or component.get("component_name") or ""
    )
    finding["component_version"] = (
        component.get("original_version") or component.get("version") or component.get("component_version")
    )
    return finding


def applicable_osv_record(vuln: dict, component: dict) -> dict | None:
    """Constrain query-confirmed evidence to its package; reject local contradictions.

    OSV's version-qualified query is authoritative for ecosystem-specific range
    semantics. Locally comparable ranges/explicit version lists additionally guard
    against stale cache payloads. Unsupported range dialects retain query evidence.
    """
    if vuln.get("withdrawn"):
        return None
    version = component.get("version")
    if not version:
        return None
    name = component.get("normalized_name") or component.get("name") or ""
    ecosystem = component.get("ecosystem") or ""
    try:
        purl = PackageURL.from_string(component.get("purl") or "")
        ecosystem = purl.type
        if (
            purl.version
            and purl.version != version
            and not (purl.type == "npm" and purl.version.lstrip("v") == version.lstrip("v"))
        ):
            return None
        name = (
            f"{purl.namespace}:{purl.name}"
            if purl.type == "maven" and purl.namespace
            else f"@{purl.namespace.lstrip('@')}/{purl.name}"
            if purl.type == "npm" and purl.namespace
            else f"{purl.namespace}/{purl.name}"
            if purl.namespace
            else purl.name
        )
    except ValueError:
        pass

    def package_name(eco, value):
        value = str(value or "")
        if eco == "PyPI":
            return canonicalize_name(value)
        return value.lower() if eco in {"npm", "NuGet"} else value

    matched = []
    for affected in vuln.get("affected") or []:
        pkg = affected.get("package") or {}
        eco = canonical_osv_ecosystem(pkg.get("ecosystem"))
        if eco and eco != canonical_osv_ecosystem(ecosystem):
            continue
        if package_name(eco, pkg.get("name")) != package_name(eco, name):
            continue
        versions, ranges = affected.get("versions") or [], affected.get("ranges") or []
        if version in versions:
            matched.append(affected)
            continue
        decisions = []
        unknown_range = False
        for rng in ranges:
            if rng.get("type") not in {"SEMVER", "ECOSYSTEM"}:
                unknown_range = True
                continue
            try:

                def parsed(value, kind=rng.get("type"), package_ecosystem=eco):
                    if kind == "SEMVER" or package_ecosystem in {"npm", "Go", "crates.io"}:
                        return SemVersion(value.removeprefix("v"))
                    if package_ecosystem == "PyPI" or (package_ecosystem == "Maven" and re.fullmatch(r"\d+(?:\.\d+)*", value)):
                        return Version(value)
                    raise InvalidVersion("No validated local comparator for this range")

                installed = parsed(version)
                start = None
                included = False
                for event in rng.get("events") or []:
                    if "introduced" in event:
                        start = event["introduced"]
                    else:
                        bound_kind = next((kind for kind in ("fixed", "last_affected", "limit") if kind in event), None)
                        if bound_kind and start is not None:
                            above_start = start == "0" or installed >= parsed(start)
                            end = parsed(event[bound_kind])
                            included |= above_start and (
                                installed <= end if bound_kind == "last_affected" else installed < end
                            )
                            start = None
                if start is not None:
                    included |= start == "0" or installed >= parsed(start)
                decisions.append(included)
            except ValueError:
                unknown_range = True
                continue
        if decisions and not any(decisions) and not unknown_range:
            continue
        if versions and not ranges:
            continue
        matched.append(affected)
    if vuln.get("affected") and not matched:
        return None
    selected = dict(vuln)
    selected["affected"] = matched
    return selected
