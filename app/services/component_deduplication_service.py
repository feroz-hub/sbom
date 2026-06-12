"""Component Deduplication Service - Identifies and merges duplicate SBOM components."""

from __future__ import annotations

import logging
from typing import Any

from ..services.lifecycle.normalizer import parse_purl
from ..services.lifecycle.types import canonical_ecosystem

log = logging.getLogger(__name__)


def get_purl_identity_key(purl_str: str | None) -> str | None:
    if not purl_str:
        return None
    try:
        parsed = parse_purl(purl_str.strip())
        if parsed is None:
            return None
        eco = canonical_ecosystem(parsed.type)
        ns = (parsed.namespace or "").strip().lower()
        name = (parsed.name or "").strip().lower()
        ver = (parsed.version or "").strip()
        # Normalized key: ecosystem + namespace + name + version
        return f"purl:{eco}:{ns}:{name}:{ver}"
    except Exception:
        return None


def get_cpe_identity_key(cpe_str: str | None) -> str | None:
    if not cpe_str:
        return None
    return f"cpe:{cpe_str.strip().lower()}"


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
    purl_key = get_purl_identity_key(comp.get("purl"))
    if purl_key:
        return purl_key
    cpe_key = get_cpe_identity_key(comp.get("cpe"))
    if cpe_key:
        return cpe_key
    return get_fallback_identity_key(comp)


def get_metadata_completeness(comp: dict) -> int:
    score = 0
    for key in ["name", "version", "purl", "cpe", "supplier", "scope", "type", "group", "license"]:
        if comp.get(key):
            score += 1
    if comp.get("hashes"):
        score += 1
    return score


def choose_canonical_component(candidates: list[dict]) -> dict:
    purl_candidates = [c for c in candidates if c.get("purl") and get_purl_identity_key(c["purl"])]
    if purl_candidates:
        candidates_to_use = purl_candidates
    else:
        cpe_candidates = [c for c in candidates if c.get("cpe") and get_cpe_identity_key(c["cpe"])]
        if cpe_candidates:
            candidates_to_use = cpe_candidates
        else:
            candidates_to_use = candidates

    def rank_key(item_index_pair):
        item, index = item_index_pair
        has_hashes = 1 if item.get("hashes") else 0
        completeness = get_metadata_completeness(item)
        return (-has_hashes, -completeness, index)

    pairs = [(item, idx) for idx, item in enumerate(candidates_to_use)]
    pairs.sort(key=rank_key)
    return pairs[0][0]


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
    merged = dict(canonical)

    # 1. Merge licenses
    lics_canonical = parse_licenses_to_set(canonical.get("license"))
    lics_duplicate = parse_licenses_to_set(duplicate.get("license"))
    if lics_duplicate - lics_canonical:
        union_lics = lics_canonical | lics_duplicate
        merged["license"] = ", ".join(sorted(union_lics)) if union_lics else None
        raw_c = canonical.get("license")
        raw_d = duplicate.get("license")
        if raw_c and raw_d and raw_c.strip() != raw_d.strip():
            conflicts.append({
                "component": key,
                "field": "license",
                "values": sorted(list({raw_c, raw_d})),
                "selected": raw_c
            })

    # 2. Merge hashes
    hashes_canonical = parse_hashes_to_list(canonical.get("hashes"))
    hashes_duplicate = parse_hashes_to_list(duplicate.get("hashes"))
    seen_hashes = {f"{h['alg']}:{h['content']}" for h in hashes_canonical}
    for h in hashes_duplicate:
        h_key = f"{h['alg']}:{h['content']}"
        if h_key not in seen_hashes:
            hashes_canonical.append(h)
            seen_hashes.add(h_key)

    if hashes_canonical:
        merged["hashes"] = ", ".join(f"{h['alg']}:{h['content']}" for h in hashes_canonical)
    else:
        merged["hashes"] = None

    # 3. Merge suppliers
    sup_c = canonical.get("supplier")
    sup_d = duplicate.get("supplier")
    if sup_d and sup_c != sup_d:
        if sup_c:
            conflicts.append({
                "component": key,
                "field": "supplier",
                "values": sorted(list({sup_c, sup_d})),
                "selected": sup_c
            })
        else:
            merged["supplier"] = sup_d

    # 4. Merge scope
    scope_c = canonical.get("scope")
    scope_d = duplicate.get("scope")
    if not scope_c and scope_d:
        merged["scope"] = scope_d

    # 5. Merge type/group
    for field in ["type", "group"]:
        if not canonical.get(field) and duplicate.get(field):
            merged[field] = duplicate[field]

    # 6. Merge raw dictionary (externalReferences / properties)
    raw_canonical = dict(canonical.get("raw") or {})
    raw_duplicate = dict(duplicate.get("raw") or {})

    # externalReferences / externalRefs
    ext_c = raw_canonical.get("externalReferences") or raw_canonical.get("externalRefs") or []
    ext_d = raw_duplicate.get("externalReferences") or raw_duplicate.get("externalRefs") or []
    if isinstance(ext_c, list) and isinstance(ext_d, list) and ext_d:
        seen_refs = set()
        union_refs = []
        for r in ext_c:
            ref_key = str(r.get("url") or r.get("referenceLocator") or r) if isinstance(r, dict) else str(r)
            if ref_key not in seen_refs:
                union_refs.append(r)
                seen_refs.add(ref_key)
        for r in ext_d:
            ref_key = str(r.get("url") or r.get("referenceLocator") or r) if isinstance(r, dict) else str(r)
            if ref_key not in seen_refs:
                union_refs.append(r)
                seen_refs.add(ref_key)
        if "externalReferences" in raw_canonical or "bomFormat" in raw_canonical:
            raw_canonical["externalReferences"] = union_refs
        else:
            raw_canonical["externalRefs"] = union_refs

    # properties
    prop_c = raw_canonical.get("properties") or []
    prop_d = raw_duplicate.get("properties") or []
    if isinstance(prop_c, list) and isinstance(prop_d, list) and prop_d:
        seen_props = set()
        union_props = []
        for p in prop_c:
            prop_key = p.get("name") if isinstance(p, dict) else str(p)
            if prop_key not in seen_props:
                union_props.append(p)
                seen_props.add(prop_key)
        for p in prop_d:
            prop_key = p.get("name") if isinstance(p, dict) else str(p)
            if prop_key not in seen_props:
                union_props.append(p)
                seen_props.add(prop_key)
        raw_canonical["properties"] = union_props

    merged["raw"] = raw_canonical
    return merged


class ComponentDeduplicationService:
    @staticmethod
    def deduplicate_components(
        components: list[dict],
        dependencies: list[dict]
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
        # Group components by identity key
        grouped: dict[str, list[dict]] = {}
        for c in components:
            key = get_component_identity_key(c)
            grouped.setdefault(key, []).append(c)

        canonical_components = []
        duplicate_components = []
        ref_mapping = {}
        conflicts = []
        warnings = []
        duplicates_found = 0
        duplicates_merged = 0

        for key, candidates in grouped.items():
            if len(candidates) == 1:
                # No duplicate
                canonical_components.append(candidates[0])
                continue

            duplicates_found += len(candidates)
            duplicates_merged += len(candidates) - 1

            # Choose canonical component
            canonical = choose_canonical_component(candidates)
            canonical_ref = canonical.get("bom_ref") or canonical.get("SPDXID") or ""

            # Merge candidates into canonical
            merged = canonical
            for item in candidates:
                item_ref = item.get("bom_ref") or item.get("SPDXID") or ""
                if item is canonical:
                    continue

                merged = merge_components(merged, item, key, conflicts)
                ref_mapping[item_ref] = canonical_ref

                # Mark duplicate component
                dup_comp = dict(item)
                dup_comp["is_duplicate"] = True
                dup_comp["duplicate_of_ref"] = canonical_ref
                duplicate_components.append(dup_comp)

            canonical_components.append(merged)
            warnings.append(f"SBOM_VAL_W120_DUPLICATE_COMPONENT_DETECTED: Component with key '{key}' has duplicate definitions merged.")

        # Remap dependency references
        remapped_dependencies = []
        remapped_refs = {}

        # Group and merge CycloneDX dependency entries
        cdx_deps_by_ref = {}
        seen_edges = set()

        for dep in dependencies:
            if "source" in dep and "target" in dep:
                # DependencyEdge format
                src = dep["source"]
                tgt = dep["target"]
                new_src = ref_mapping.get(src, src)
                new_tgt = ref_mapping.get(tgt, tgt)
                if new_src == new_tgt:
                    continue
                edge_key = (new_src, new_tgt)
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    remapped_dep = dict(dep)
                    remapped_dep["source"] = new_src
                    remapped_dep["target"] = new_tgt
                    remapped_dependencies.append(remapped_dep)
                    if new_src != src or new_tgt != tgt:
                        remapped_refs[f"{src} -> {tgt}"] = f"{new_src} -> {new_tgt}"
            elif "ref" in dep:
                # CycloneDX dependency format
                ref = dep["ref"]
                new_ref = ref_mapping.get(ref, ref)
                new_depends = [ref_mapping.get(t, t) for t in (dep.get("dependsOn") or [])]
                new_depends = [d for d in new_depends if d != new_ref]

                if new_ref not in cdx_deps_by_ref:
                    cdx_deps_by_ref[new_ref] = {"dep": dict(dep), "depends": []}
                cdx_deps_by_ref[new_ref]["depends"].extend(new_depends)

                if new_ref != ref or new_depends != dep.get("dependsOn"):
                    remapped_refs[ref] = new_ref

        # Re-construct remapped dependencies for CycloneDX
        for new_ref, info in cdx_deps_by_ref.items():
            unique_depends = list(dict.fromkeys(info["depends"]))
            remapped_dep = info["dep"]
            remapped_dep["ref"] = new_ref
            remapped_dep["dependsOn"] = unique_depends
            remapped_dependencies.append(remapped_dep)

        # Prepare dedupe report
        dedupe_report = {
            "duplicates_found": duplicates_found,
            "duplicates_merged": duplicates_merged,
            "conflicts": conflicts,
            "ref_mapping": ref_mapping,
            "remapped_dependencies": remapped_refs
        }

        return canonical_components, duplicate_components, ref_mapping, dedupe_report, warnings
