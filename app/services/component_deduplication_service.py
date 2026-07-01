"""Component Deduplication Service - Stage 9 compatibility facade."""

from __future__ import annotations

from typing import Any

from app.normalization.component_deduplicator import (
    ComponentDeduplicator,
    get_component_identity_key,  # noqa: F401  re-exported for service-layer callers
    get_fallback_identity_key,  # noqa: F401  re-exported for service-layer callers
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


# ``get_component_identity_key`` / ``get_fallback_identity_key`` now live in the
# validation-safe ``app.normalization.component_deduplicator`` and are re-exported
# here for backward compatibility (services import them from this facade). The
# dependency direction is services -> validation-safe helper.


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
