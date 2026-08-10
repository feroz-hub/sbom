"""Component Deduplication Service - Stage 9 compatibility facade."""

from __future__ import annotations

from typing import Any

from app.normalization.component_deduplicator import (
    ComponentDeduplicator,
)
from app.normalization.component_deduplicator import (
    choose_canonical_component as _choose_canonical_component,
)
from app.normalization.component_deduplicator import (
    merge_components as _merge_components,
)
from app.normalization.component_normalizer import normalize_component


def get_purl_identity_key(purl_str: str | None) -> str | None:
    if not purl_str:
        return None
    normalized = normalize_component({"purl": purl_str}).component
    key = normalized.get("normalized_component_key")
    return str(key) if key and str(key).startswith("purl:") else None


def get_cpe_identity_key(cpe_str: str | None) -> str | None:
    if not cpe_str:
        return None
    normalized = normalize_component({"cpe": cpe_str}).component
    key = normalized.get("normalized_component_key")
    return str(key) if key and str(key).startswith("cpe:") else None


def get_fallback_identity_key(comp: dict) -> str:
    supplier = (comp.get("supplier") or "").strip().lower()
    name = (comp.get("name") or "").strip().lower()
    version = (comp.get("version") or "").strip().lower()
    comp_type = (comp.get("type") or "").strip().lower()

    hashes = comp.get("hashes")
    hash_str = ""
    if isinstance(hashes, list):
        hash_parts = []
        for h in hashes:
            if isinstance(h, dict):
                alg = (h.get("alg") or h.get("algorithm") or "").strip().upper()
                val = (h.get("content") or h.get("checksumValue") or "").strip().lower()
                if alg and val:
                    hash_parts.append(f"{alg}:{val}")
        if hash_parts:
            hash_str = ",".join(sorted(hash_parts))
    elif isinstance(hashes, str) and hashes.strip():
        hash_str = hashes.strip().lower()

    return f"fallback:{supplier}:{name}:{version}:{comp_type}:{hash_str}"


def get_component_identity_key(comp: dict) -> str:
    normalized = normalize_component(comp).component
    return normalized.get("normalized_component_key") or get_fallback_identity_key(comp)


def get_metadata_completeness(comp: dict) -> int:
    score = 0
    for key in ["name", "version", "purl", "cpe", "supplier", "scope", "type", "group", "license"]:
        if comp.get(key):
            score += 1
    if comp.get("hashes"):
        score += 1
    return score


def choose_canonical_component(candidates: list[dict]) -> dict:
    return _choose_canonical_component(candidates)


def parse_licenses_to_set(license_str: str | None) -> set[str]:
    if not license_str:
        return set()
    return {lic.strip() for lic in license_str.split(",") if lic.strip()}


def parse_hashes_to_list(hashes_str: Any) -> list[dict[str, str]]:
    if not hashes_str:
        return []
    if isinstance(hashes_str, list):
        return list(hashes_str)
    res = []
    parts = str(hashes_str).split(",")
    for p in parts:
        p = p.strip()
        if ":" in p:
            alg, val = p.split(":", 1)
            res.append({"alg": alg.strip(), "content": val.strip()})
        elif p:
            res.append({"alg": "UNKNOWN", "content": p})
    return res


def merge_components(canonical: dict, duplicate: dict, key: str, conflicts: list[dict]) -> dict:
    return _merge_components(canonical, duplicate, key, conflicts)


class ComponentDeduplicationService:
    @staticmethod
    def deduplicate_components(
        components: list[dict], dependencies: list[dict]
    ) -> tuple[list[dict], list[dict], dict, dict, list[str]]:
        """
        Deduplicates components based on PURL, CPE, or fallback identity keys.

        Args:
            components: List of raw/extracted component dicts.
            dependencies: List of dependency edges/dicts.

        Returns:
            Tuple of:
            - canonical_components: list of merged canonical component dicts.
            - duplicate_components: list of duplicate component dicts containing
              duplicate metadata, but marked with is_duplicate = True and tracking
              their canonical link.
            - ref_mapping: dict mapping duplicate bom_ref -> canonical bom_ref.
            - dedupe_report: deduplication report dictionary.
            - warnings: list of warning strings.
        """
        return ComponentDeduplicator.deduplicate(components, dependencies)
