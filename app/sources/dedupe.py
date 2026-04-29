"""
Cross-source finding deduplication.

Canonical extraction from ``app/analysis.py``. Performs the two-pass
CVE ↔ GHSA alias cross-merge that the runner+adapter chain consumes;
``app.analysis.deduplicate_findings`` is now a re-export of this
function.
"""

from __future__ import annotations

_SEV_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3, "UNKNOWN": -1}


def deduplicate_findings(all_findings: list[dict]) -> list[dict]:
    """
    Two-pass CVE ↔ GHSA alias cross-deduplication.

    Pass 1 builds an alias index so any finding referenced by either its
    canonical id or one of its aliases collapses to the same key. Pass 2
    merges colliding records, taking the union of sources / aliases /
    references / fixed_versions / cwe and the worst severity / score.
    """
    alias_index: dict[str, str] = {}
    for v in all_findings:
        vid = v.get("vuln_id") or ""
        for alias in v.get("aliases") or []:
            if alias and alias not in alias_index:
                alias_index[alias] = vid
        if vid and vid not in alias_index:
            alias_index[vid] = vid

    def _canonical_key(v: dict) -> str:
        vid = v.get("vuln_id") or ""
        canonical = alias_index.get(vid, vid)
        if canonical:
            return canonical
        for a in v.get("aliases") or []:
            if a:
                return alias_index.get(a, a)
        return v.get("component_name") or ""

    merged: dict[str, dict] = {}
    for v in all_findings:
        key = _canonical_key(v)
        if key not in merged:
            merged[key] = dict(v)
            continue

        existing = merged[key]
        existing["sources"] = list(set(existing.get("sources", []) + v.get("sources", [])))
        existing["aliases"] = list(set(existing.get("aliases", []) + v.get("aliases", [])))
        existing["cwe"] = list(set((existing.get("cwe") or []) + (v.get("cwe") or [])))
        existing["references"] = list(
            set([r for r in (existing.get("references") or []) if r] + [r for r in (v.get("references") or []) if r])
        )
        existing["fixed_versions"] = list(set((existing.get("fixed_versions") or []) + (v.get("fixed_versions") or [])))
        e_rank = _SEV_RANK.get(str(existing.get("severity", "UNKNOWN")).upper(), -1)
        v_rank = _SEV_RANK.get(str(v.get("severity", "UNKNOWN")).upper(), -1)
        if v_rank > e_rank:
            existing["severity"] = v["severity"]
            if v.get("score") is not None:
                existing["score"] = v["score"]
        if not existing.get("attack_vector") and v.get("attack_vector"):
            existing["attack_vector"] = v["attack_vector"]

    return list(merged.values())
