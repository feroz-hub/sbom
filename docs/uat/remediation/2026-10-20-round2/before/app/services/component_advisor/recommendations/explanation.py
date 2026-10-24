"""Human-readable rationale from structured evidence (FR-SCA-018, US-SCA-12).

Pure template rendering. Structured reason / limitation codes remain the
authoritative evidence; these sentences are generated *from* them and never
add a claim the codes do not support. Vocabulary is checked by tests: no
"safe", "secure" or "vulnerability free".
"""

from __future__ import annotations

from typing import Any

REASON_TEXT = {
    "SAME_ECOSYSTEM": "Uses the same package ecosystem as the current component.",
    "SIMILAR_PURPOSE": "Has the same evidenced technology category ({detail}).",
    "LOWER_CURRENT_RISK": "Has a lower current risk classification ({detail}).",
    "NO_KNOWN_ACTIONABLE_VULNS_CURRENT_SNAPSHOT": "Has no known actionable vulnerabilities in the current snapshot.",
    "FOUND_IN_N_ACTIVE_TENANT_SBOMS": "Is already present in {count} active SBOM(s) in this tenant.",
    "USED_BY_N_TENANT_PRODUCTS": "Is already used by {count} product(s) in this tenant.",
    "SUPPORTED_LIFECYCLE": "Is in a supported lifecycle state.",
    "SAFER_SUPPORTED_VERSION": "Is a supported version of the same component with lower current risk.",
    "FIXES_SOURCE_VULNERABILITIES": "Is at or past a declared fix for {vulnerabilities}.",
    "LIFECYCLE_PROVIDER_RECOMMENDED": "Is the version recommended by lifecycle enrichment.",
    "LIFECYCLE_PROVIDER_LATEST_SUPPORTED": "Is the latest supported version reported by lifecycle enrichment.",
    "REVIEWER_PROPOSED": "Was proposed by a reviewer: {detail}",
}
LIMITATION_TEXT = {
    "MIGRATION_REGRESSION_TESTING_REQUIRED": "Regression testing is required before any change.",
    "API_COMPATIBILITY_REQUIRES_VERIFICATION": "API compatibility must be verified.",
    "MIGRATION_REQUIRED": "Switching components requires code changes; this is not a drop-in replacement.",
    "TRANSITIVE_DEPENDENCY_DIFFERENCES": "Transitive dependencies were not compared.",
    "VULNERABILITY_POSTURE_NOT_OBSERVED": "Its current vulnerability posture is unknown because it is not in this tenant's active SBOMs.",
    "LIFECYCLE_EVIDENCE_UNAVAILABLE": "Lifecycle evidence is unavailable.",
    "LICENSE_EVIDENCE_UNAVAILABLE": "License evidence is unavailable.",
    "LICENSE_CHANGED": "Its license differs from the current component.",
    "PLATFORM_EVIDENCE_INCOMPLETE": "Platform, runtime and architecture evidence is incomplete.",
    "HISTORY_NOT_EVALUATED": "Vulnerability history was not evaluated.",
    "RELEASE_CADENCE_UNKNOWN": "Release cadence and maintenance health are unknown.",
    "DOWNGRADE": "It is older than the current version.",
    "VERSION_ORDER_UNKNOWN": "Its version order relative to the current version is unknown.",
    "CANDIDATE_REVIEW_REASONS": "Its own evidence needs review.",
    "EXTERNAL_METADATA_ONLY": "Evidence comes only from external package metadata.",
}
CONFIDENCE_TEXT = {
    "HIGH": "Confidence is high: evidence is complete and current.",
    "MEDIUM": "Confidence is medium: most evidence is available.",
    "LOW": "Confidence is low: material evidence is missing or stale.",
    "INSUFFICIENT_EVIDENCE": "There is insufficient evidence to assess this candidate.",
}


def _render(template: str, item: dict[str, Any]) -> str:
    values = {"detail": item.get("detail", ""), "count": item.get("count", ""),
              "vulnerabilities": ", ".join(item.get("vulnerabilities", []) or [])}
    return template.format(**values).strip()


def explain(candidate_name: str, version: str | None, *, reasons: list[dict], limitations: list[dict],
            confidence_level: str, blocked: bool, blocking_checks: list[str], history: dict[str, Any] | None) -> dict[str, Any]:
    subject = f"{candidate_name} {version or ''}".strip()
    reason_lines = [_render(REASON_TEXT[r["code"]], r) for r in reasons if r.get("code") in REASON_TEXT]
    limitation_lines = sorted({LIMITATION_TEXT[item["code"]] for item in limitations if item.get("code") in LIMITATION_TEXT})
    lines = []
    if blocked:
        lines.append(f"{subject} is blocked by compatibility checks ({', '.join(blocking_checks)}) and cannot be approved.")
    lines.append(f"{subject} is proposed because it:" if reason_lines else f"{subject} has no supporting reasons recorded.")
    if history:
        if history.get("status") == "NO_HISTORY_COVERAGE":
            lines.append("No vulnerability history source covers the observation window.")
        elif history.get("note"):
            lines.append(history["note"] + ".")
        else:
            lines.append(f"{history.get('disclosed_vulnerability_count', 0)} vulnerabilities "
                         f"({history.get('critical_high_count', 0)} critical/high) were disclosed in the covered "
                         f"{history.get('coverage', {}).get('covered_months', 0)} month(s).")
    return {
        "summary": " ".join(lines),
        "reasons": reason_lines,
        "limitations": limitation_lines,
        "confidence": CONFIDENCE_TEXT[confidence_level],
        "generated_from": "STRUCTURED_EVIDENCE",
    }


__all__ = ["CONFIDENCE_TEXT", "LIMITATION_TEXT", "REASON_TEXT", "explain"]
