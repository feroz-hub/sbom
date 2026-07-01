"""Audit-safe component and relationship deduplication."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .component_normalizer import normalize_component


def get_fallback_identity_key(comp: dict[str, Any]) -> str:
    """Deterministic identity key for components that yield no normalized key.

    Pure string logic (no DB / services / HTTP) so it is safe to import from
    ``app.validation`` as well as the service layer.
    """
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


def get_component_identity_key(comp: dict[str, Any]) -> str:
    """Normalized identity key for a component, with a deterministic fallback."""
    normalized = normalize_component(comp).component
    return normalized.get("normalized_component_key") or get_fallback_identity_key(comp)


class ComponentDeduplicator:
    """Normalize components, group high-confidence identities, and mark duplicates."""

    @staticmethod
    def deduplicate(
        components: list[dict[str, Any]],
        dependencies: list[dict[str, Any]] | None = None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, str], dict[str, Any], list[str]]:
        normalized = [normalize_component(component, index=index).component for index, component in enumerate(components)]
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        unique_components: list[dict[str, Any]] = []
        low_confidence = 0

        for component in normalized:
            key = component.get("normalized_component_key")
            confidence = component.get("canonical_identity_confidence")
            if not key or confidence == "Low":
                low_confidence += 1
                component["is_duplicate"] = False
                component["dedupe_group_id"] = None
                unique_components.append(component)
                continue
            groups[str(key)].append(component)

        canonical_components: list[dict[str, Any]] = []
        duplicate_components: list[dict[str, Any]] = []
        ref_mapping: dict[str, str] = {}
        duplicate_groups: list[dict[str, Any]] = []
        conflicts: list[dict[str, Any]] = []
        warnings: list[str] = []

        for key, candidates in groups.items():
            canonical = choose_canonical_component(candidates)
            group_id = canonical.get("dedupe_canonical_id")
            canonical_ref = _ref(canonical)
            group_refs = [_ref(item) for item in candidates if _ref(item)]
            canonical["is_duplicate"] = False
            canonical["duplicate_of_ref"] = None
            canonical["dedupe_group_id"] = group_id
            canonical["dedupe_evidence_json"] = {
                "group_key": key,
                "canonical_ref": canonical_ref,
                "component_refs": group_refs,
                "identity_confidence": canonical.get("canonical_identity_confidence"),
            }

            if len(candidates) == 1:
                canonical_components.append(canonical)
                continue

            merged = dict(canonical)
            for item in candidates:
                if item is canonical:
                    continue
                merged = merge_components(merged, item, key, conflicts)
                item_ref = _ref(item)
                if item_ref and canonical_ref:
                    ref_mapping[item_ref] = canonical_ref
                duplicate = dict(item)
                duplicate.update(
                    {
                        "is_duplicate": True,
                        "duplicate_of_ref": canonical_ref,
                        "dedupe_group_id": group_id,
                        "dedupe_reason": duplicate.get("dedupe_reason") or canonical.get("dedupe_reason"),
                        "dedupe_confidence": duplicate.get("dedupe_confidence") or canonical.get("dedupe_confidence"),
                        "dedupe_evidence_json": {
                            "group_key": key,
                            "canonical_ref": canonical_ref,
                            "duplicate_ref": item_ref,
                            "component_refs": group_refs,
                        },
                    }
                )
                duplicate_components.append(duplicate)

            merged["is_duplicate"] = False
            merged["dedupe_group_id"] = group_id
            merged["dedupe_evidence_json"] = {
                "group_key": key,
                "canonical_ref": canonical_ref,
                "component_refs": group_refs,
                "merged_duplicate_count": len(candidates) - 1,
            }
            canonical_components.append(merged)
            duplicate_groups.append(
                {
                    "group_id": group_id,
                    "normalized_component_key": key,
                    "canonical_ref": canonical_ref,
                    "duplicate_refs": [ref for ref in group_refs if ref != canonical_ref],
                    "count": len(candidates),
                    "confidence": canonical.get("canonical_identity_confidence"),
                    "reason": canonical.get("dedupe_reason"),
                }
            )
            warnings.append(f"Duplicate component group '{key}' contains {len(candidates)} entries.")

        canonical_components.extend(unique_components)
        remapped_dependencies, remapped_refs, relationship_duplicates = remap_dependencies(dependencies or [], ref_mapping)
        total = len(components)
        duplicate_count = len(duplicate_components)
        report = {
            "stage_name": "Normalization & Deduplication",
            "stage_number": 9,
            "status": "warning" if duplicate_count or warnings else "passed",
            "summary": {
                "total_components": total,
                "canonical_components": len(canonical_components),
                "duplicate_components": duplicate_count,
                "duplicate_groups": len(duplicate_groups),
                "normalized_purls": sum(1 for item in normalized if item.get("normalized_purl")),
                "normalized_cpes": sum(1 for item in normalized if item.get("primary_cpe")),
                "relationship_duplicates": relationship_duplicates,
                "low_confidence_groups": low_confidence,
            },
            "duplicates_found": duplicate_count + len(duplicate_groups),
            "duplicates_merged": duplicate_count,
            "duplicate_groups": duplicate_groups,
            "conflicts": conflicts,
            "ref_mapping": ref_mapping,
            "remapped_dependencies": remapped_refs,
            "normalized_dependencies": remapped_dependencies,
            "warnings": warnings,
        }
        return canonical_components, duplicate_components, ref_mapping, report, warnings


def choose_canonical_component(candidates: list[dict[str, Any]]) -> dict[str, Any]:
    def rank(item_index_pair):
        item, index = item_index_pair
        return (
            0 if item.get("normalized_purl") else 1,
            0 if item.get("primary_cpe") else 1,
            -metadata_completeness(item),
            0 if item.get("license") else 1,
            0 if item.get("hashes") else 1,
            0 if item.get("supplier") else 1,
            index,
        )

    return sorted(((item, index) for index, item in enumerate(candidates)), key=rank)[0][0]


def metadata_completeness(component: dict[str, Any]) -> int:
    keys = ("name", "version", "purl", "cpe", "supplier", "scope", "type", "group", "license", "hashes")
    return sum(1 for key in keys if component.get(key))


def merge_components(canonical: dict[str, Any], duplicate: dict[str, Any], key: str, conflicts: list[dict[str, Any]]) -> dict[str, Any]:
    merged = dict(canonical)
    for field in ("license", "hashes"):
        if field == "license" and canonical.get(field) and duplicate.get(field) and str(canonical.get(field)).strip() != str(duplicate.get(field)).strip():
            conflicts.append({"component": key, "field": field, "values": [canonical.get(field), duplicate.get(field)], "selected": canonical.get(field)})
        merged[field] = _merge_csv(canonical.get(field), duplicate.get(field))
    for field in ("supplier", "scope", "type", "group", "purl", "cpe"):
        if not merged.get(field) and duplicate.get(field):
            merged[field] = duplicate[field]
        elif merged.get(field) and duplicate.get(field) and str(merged[field]).strip() != str(duplicate[field]).strip():
            if field in {"supplier", "license"}:
                conflicts.append({"component": key, "field": field, "values": [merged[field], duplicate[field]], "selected": merged[field]})
    merged_notes = list(merged.get("normalization_notes_json") or [])
    for note in duplicate.get("normalization_notes_json") or []:
        if note not in merged_notes:
            merged_notes.append(note)
    merged["normalization_notes_json"] = merged_notes
    return merged


def remap_dependencies(dependencies: list[dict[str, Any]], ref_mapping: dict[str, str]) -> tuple[list[dict[str, Any]], dict[str, str], int]:
    remapped: list[dict[str, Any]] = []
    remapped_refs: dict[str, str] = {}
    duplicate_edges = 0
    edge_seen: set[tuple[str, str, str]] = set()
    cdx_by_ref: dict[str, dict[str, Any]] = {}

    for dep in dependencies:
        if not isinstance(dep, dict):
            continue
        if "source" in dep and "target" in dep:
            source = str(dep.get("source") or "")
            target = str(dep.get("target") or "")
            kind = str(dep.get("kind") or "DEPENDS_ON")
            new_source = ref_mapping.get(source, source)
            new_target = ref_mapping.get(target, target)
            if new_source == new_target:
                duplicate_edges += 1
                continue
            edge = (new_source, new_target, kind)
            if edge in edge_seen:
                duplicate_edges += 1
                continue
            edge_seen.add(edge)
            row = dict(dep)
            row.update({"source": new_source, "target": new_target})
            remapped.append(row)
            if new_source != source or new_target != target:
                remapped_refs[f"{source} -> {target}"] = f"{new_source} -> {new_target}"
            continue
        if "ref" in dep:
            ref = str(dep.get("ref") or "")
            new_ref = ref_mapping.get(ref, ref)
            depends = [ref_mapping.get(str(item), str(item)) for item in (dep.get("dependsOn") or []) if item]
            depends = [item for item in depends if item != new_ref]
            bucket = cdx_by_ref.setdefault(new_ref, {"dep": dict(dep), "depends": []})
            bucket["depends"].extend(depends)
            if new_ref != ref:
                remapped_refs[ref] = new_ref

    for new_ref, info in cdx_by_ref.items():
        unique_depends = []
        seen = set()
        for target in info["depends"]:
            edge = (new_ref, target, "DEPENDS_ON")
            if target in seen or edge in edge_seen:
                duplicate_edges += 1
                continue
            seen.add(target)
            edge_seen.add(edge)
            unique_depends.append(target)
        dep = info["dep"]
        dep["ref"] = new_ref
        dep["dependsOn"] = unique_depends
        remapped.append(dep)

    return remapped, remapped_refs, duplicate_edges


def _merge_csv(a: Any, b: Any) -> str | None:
    values = []
    for raw in (a, b):
        if isinstance(raw, list):
            parts = [str(item) for item in raw]
        else:
            parts = str(raw or "").split(",")
        for part in parts:
            cleaned = part.strip()
            if cleaned and cleaned not in values:
                values.append(cleaned)
    return ", ".join(values) if values else None


def _ref(component: dict[str, Any]) -> str:
    return str(component.get("bom_ref") or component.get("SPDXID") or "")
