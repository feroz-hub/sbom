"""One deterministic component/vulnerability reconciliation policy.

Provider observations are immutable evidence. Only verified occurrence IDs or
explicit document references are merge keys; unidentified observations stay apart.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict

from .cvss_assessment import select_assessment, severity_for_score

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


def strings(value) -> list[str]:
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            parsed = value.split(",")
        value = parsed if isinstance(parsed, list) else [value]
    return [str(v).strip() for v in value or [] if str(v).strip()]


def canonical_vulnerability(vuln_id, aliases=()) -> str:
    vid = str(vuln_id or "").strip().upper()
    cves = sorted({str(v).strip().upper() for v in [vid, *aliases] if CVE_RE.fullmatch(str(v).strip())})
    if CVE_RE.fullmatch(vid):
        return vid
    if len(cves) == 1:
        return cves[0]
    return vid or "UNKNOWN-VULNERABILITY"


def stable(value) -> str:
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))


def occurrence_identity(row: dict) -> str:
    scope = [row.get(k) for k in ("tenant_id", "sbom_id", "analysis_run_id")]
    if row.get("component_id") is not None:
        return stable([scope, "id", row["component_id"]])
    if row.get("bom_ref"):
        return stable([scope, "ref", row["bom_ref"]])
    # Stable evidence fingerprint suppresses exact replays, never name/CPE joins.
    return "unresolved:" + hashlib.sha256(stable(row).encode()).hexdigest()


def reconcile(findings: list[dict]) -> list[dict]:
    groups = defaultdict(list)
    alias_cves = defaultdict(set)
    for row in findings:
        vid = str(row.get("vuln_id") or row.get("id") or "").upper()
        aliases = strings(row.get("aliases"))
        cves = {v.upper() for v in [vid, *aliases] if CVE_RE.fullmatch(v)}
        # Multi-CVE advisories are deliberately not alias bridges.
        for alias in [vid, *aliases]:
            alias_cves[alias.upper()].update(cves)
    for row in findings:
        vid = str(row.get("vuln_id") or row.get("id") or "").upper()
        candidates = alias_cves[vid]
        canonical = next(iter(candidates)) if len(candidates) == 1 else vid
        if CVE_RE.fullmatch(vid):
            canonical = vid
        groups[(occurrence_identity(row), canonical)].append(row)
    output = []
    for (_, vid), rows in sorted(groups.items()):
        rows = sorted(rows, key=stable)
        merged = dict(rows[0])
        merged["vuln_id"] = vid
        observations = {}
        for row in rows:
            for observation in row.get("source_observations") or [row]:
                obs = {
                    k: v
                    for k, v in observation.items()
                    if k
                    not in {
                        "source_observations",
                        "selected_cvss",
                        "rating_disagreement",
                        "reconciliation_key",
                        "evidence_json",
                    }
                }
                if "provider" not in obs:
                    obs["provider"] = ",".join(sorted(strings(obs.get("sources") or obs.get("source"))))
                observations[stable(obs)] = obs
        evidence = [observations[key] for key in sorted(observations)]
        selected = select_assessment(evidence, cve=bool(CVE_RE.fullmatch(vid)))
        for field in ("aliases", "references", "fixed_versions", "cwe", "sources"):
            values = {v for row in rows for v in strings(row.get(field))}
            if field == "aliases":
                values.update(str(row.get("vuln_id")) for row in rows if row.get("vuln_id"))
            if field == "sources":
                values.update(v for obs in evidence for v in strings(obs.get("provider")))
            merged[field] = sorted(values)
        # Fill absent summary fields deterministically; rating fields are atomic.
        for row in rows:
            for field, value in row.items():
                if not merged.get(field) and value and field not in {"score", "vector", "cvss_version"}:
                    merged[field] = value
        authority = {"NVD": 0, "GITHUB": 1, "GHSA": 1, "OSV": 2}
        classification = min(evidence, key=lambda o: (authority.get(o.get("provider"), 3), stable(o)))
        merged.update(
            score=selected["score"] if selected else None,
            vector=selected["vector"] if selected else None,
            cvss_version=selected["version"] if selected else None,
            cvss_source=selected["provider"] if selected else None,
            severity=severity_for_score(selected["score"]) if selected else classification.get("severity") or "UNKNOWN",
            selected_cvss=selected,
            source_observations=evidence,
            resolution_status="resolved" if merged.get("component_id") is not None else "unresolved",
        )
        merged["rating_disagreement"] = any(
            obs.get("severity")
            and obs["severity"].upper() not in {"UNKNOWN", merged["severity"].upper()}
            or (obs.get("score") is not None and str(obs["score"]) != str(merged["score"]))
            for obs in evidence
        )
        output.append(merged)
    return output
