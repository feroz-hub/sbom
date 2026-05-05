"""Phase 2 fixtures — canonical schema-conforming bundles + GroundingContexts.

The bundles here mirror the five examples in the Phase 2 prompt §8 exactly.
Tests use them as the "what the LLM should return" canned responses, and
the smoke script can compare a real provider's output against them as a
quality baseline.
"""

from __future__ import annotations

from datetime import date

from app.ai.grounding import ComponentRef, FixVersionRef, GroundingContext

# Bundles are kept as plain dicts so they can also feed the fake-provider
# JSON path without serialisation round-trips.

EX1_CRITICAL_KEV_WITH_FIX_BUNDLE: dict = {
    "remediation_prose": {
        "summary_in_context": (
            "This is an actively-exploited remote code execution vulnerability "
            "in log4j-core 2.16.0. Your direct dependency on "
            "org.apache.logging.log4j:log4j-core means any application code "
            "that processes attacker-controlled log messages is at risk."
        ),
        "exploitation_likelihood": "actively_exploited",
        "recommended_path": "Upgrade to 2.17.1 immediately. This is the minimum version that resolves CVE-2021-44832 fully and is the most-tested fix.",
        "confidence": "high",
    },
    "upgrade_command": {
        "ecosystem": "Maven",
        "command": "<dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.17.1</version></dependency>",
        "target_version": "2.17.1",
        "rationale": "Smallest semver-stable upgrade that includes the fix; 2.17.x is the current Apache-supported branch for Java 8.",
        "breaking_change_risk": "minor",
        "tested_against_data": True,
    },
    "decision_recommendation": {
        "priority": "urgent",
        "reasoning": [
            "Listed in CISA KEV as actively exploited",
            "CVSS 9.0 (Critical) on a network-reachable attack vector",
            "EPSS percentile 100% — highest exploitation probability in scope",
            "Stable fix version available in same major branch",
        ],
        "citations": ["kev", "nvd", "epss", "fix_version_data"],
        "confidence": "high",
        "caveats": [],
    },
}


EX2_MEDIUM_WITH_FIX_BUNDLE: dict = {
    "remediation_prose": {
        "summary_in_context": (
            "This medium-severity issue in requests 2.31.0 affects only "
            "specific certificate-pinning workflows. If your code uses "
            "requests for standard HTTPS traffic without custom certificate "
            "handling, the practical risk is low."
        ),
        "exploitation_likelihood": "low",
        "recommended_path": "Upgrade to 2.32.0 during your next routine dependency cycle.",
        "confidence": "high",
    },
    "upgrade_command": {
        "ecosystem": "PyPI",
        "command": "pip install --upgrade requests==2.32.0",
        "target_version": "2.32.0",
        "rationale": "Minor version bump; backward compatible with 2.31.x API.",
        "breaking_change_risk": "none",
        "tested_against_data": True,
    },
    "decision_recommendation": {
        "priority": "scheduled",
        "reasoning": [
            "Not in CISA KEV",
            "EPSS percentile only 8% — low exploitation likelihood",
            "Specific exploitation requires custom cert-pinning code, not common in typical use",
            "Fix is a backward-compatible minor bump",
        ],
        "citations": ["nvd", "epss", "fix_version_data"],
        "confidence": "high",
        "caveats": [],
    },
}


EX3_HIGH_NO_FIX_BUNDLE: dict = {
    "remediation_prose": {
        "summary_in_context": (
            "This high-severity flaw in some-abandoned-pkg 1.2.3 has no "
            "published fix. The package appears unmaintained — last release "
            "was over two years ago. Continued use carries unmitigated risk."
        ),
        "exploitation_likelihood": "moderate",
        "recommended_path": "Plan a migration to a maintained alternative. As an interim, evaluate whether your usage of some-abandoned-pkg can be removed or sandboxed.",
        "confidence": "medium",
    },
    "upgrade_command": {
        "ecosystem": "npm",
        "command": "npm uninstall some-abandoned-pkg",
        "target_version": "n/a",
        "rationale": "No fix version exists. Removal or replacement is the only path.",
        "breaking_change_risk": "unknown",
        "tested_against_data": False,
    },
    "decision_recommendation": {
        "priority": "soon",
        "reasoning": [
            "High CVSS (7.8) with moderate EPSS (35%)",
            "No upstream fix; package appears unmaintained",
            "Risk persists indefinitely without remediation",
            "Migration requires evaluation of replacement package",
        ],
        "citations": ["nvd", "epss"],
        "confidence": "medium",
        "caveats": [
            "No fix-version data available; recommendations are inferred from severity and maintenance signals",
            "Replacement-package guidance requires human review of usage patterns",
        ],
    },
}


# A grounding context that matches Example 1 exactly.
def grounding_for_example_1() -> GroundingContext:
    return GroundingContext(
        cve_id="CVE-2021-44832",
        aliases=["GHSA-jfh8-c2jp-5v3q"],
        component=ComponentRef(
            name="org.apache.logging.log4j:log4j-core",
            version="2.16.0",
            ecosystem="Maven",
            purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.16.0",
        ),
        cve_summary_from_db="Apache Log4j2 RCE via JDBC Appender.",
        severity="critical",
        cvss_v3_score=9.0,
        cwe_ids=["CWE-502"],
        epss_score=0.97,
        epss_percentile=1.0,
        kev_listed=True,
        kev_due_date=date(2022, 6, 30),
        fix_versions=[
            FixVersionRef(ecosystem="Maven", package="log4j-core", fixed_in="2.17.1"),
            FixVersionRef(ecosystem="Maven", package="log4j-core", fixed_in="2.12.4"),
        ],
        sources_used=["nvd", "kev", "epss", "fix_version_data"],
    )


def grounding_for_example_3_no_fix() -> GroundingContext:
    return GroundingContext(
        cve_id="CVE-2024-99001",
        component=ComponentRef(
            name="some-abandoned-pkg",
            version="1.2.3",
            ecosystem="npm",
        ),
        cve_summary_from_db="Prototype pollution → RCE; package unmaintained.",
        severity="high",
        cvss_v3_score=7.8,
        epss_score=0.35,
        epss_percentile=0.85,
        kev_listed=False,
        fix_versions=[],
        sources_used=["nvd", "epss"],
    )
