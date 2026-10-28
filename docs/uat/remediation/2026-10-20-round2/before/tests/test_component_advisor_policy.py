"""Secure Component Advisor — policy and purpose domain rules (spec Step 4).

FR-SCA-004 (accepted risk), FR-SCA-005 (trust), FR-SCA-009 (purpose).
Prompt §10: T8 (accepted risk evaluates against the correct policy version),
T9 (adoption alone never creates trusted status), T15 (purpose search only
returns sufficiently evidenced matches), T16 (AI purpose is marked/provenanced).
"""

from datetime import UTC, datetime, timedelta

import pytest

from app.parsing.cyclonedx import parse_cyclonedx_dict, parse_cyclonedx_xml
from app.parsing.spdx import parse_spdx_dict
from app.services.component_advisor.classification import ClassificationInput, RiskClassification, classify
from app.services.component_advisor.lifecycle_mapping import LifecycleBucket
from app.services.component_advisor.policy import (
    ComponentFacts,
    PolicyKind,
    PolicyStatus,
    PolicyValidationError,
    PolicyVersionRef,
    evaluate_accepted_risk,
    evaluate_trust,
    validate_accepted_risk_rules,
    validate_trust_rules,
)
from app.services.component_advisor.purpose import (
    PurposeRecord,
    PurposeSource,
    resolve_purpose,
    validate_purpose_payload,
)

NOW = datetime(2026, 10, 1, tzinfo=UTC)


def ref(kind, rules, *, version_id=11, version=1):
    validated = validate_accepted_risk_rules(rules) if kind is PolicyKind.ACCEPTED_RISK else validate_trust_rules(rules)
    return PolicyVersionRef(version_id, 1, kind, version, PolicyStatus.ACTIVE, "TENANT", validated)


def facts(**overrides):
    base = dict(
        classification=RiskClassification.MEDIUM,
        highest_actionable_severity="MEDIUM",
        max_actionable_cvss=5.0,
        actionable_vulnerability_count=1,
        actionable_vex_statuses=frozenset({"UNDER_INVESTIGATION"}),
        lifecycle=LifecycleBucket.SUPPORTED,
        latest_analysis_at=(NOW - timedelta(days=2)).isoformat(),
        has_review_reasons=False,
        licenses=("MIT",),
        product_count=1,
    )
    base.update(overrides)
    return ComponentFacts(**base)


# ---------------------------------------------------------------------------
# Accepted risk (FR-SCA-004)
# ---------------------------------------------------------------------------


def test_T08_accepted_risk_records_the_evaluating_policy_version__FR_SCA_004():
    v1 = ref(PolicyKind.ACCEPTED_RISK, {"max_actionable_severity": "MEDIUM"}, version_id=101, version=1)
    v2 = ref(PolicyKind.ACCEPTED_RISK, {"max_actionable_severity": "LOW"}, version_id=102, version=2)
    under_v1 = evaluate_accepted_risk(v1, facts(), now=NOW)
    under_v2 = evaluate_accepted_risk(v2, facts(), now=NOW)
    assert (under_v1.satisfied, under_v1.policy_version_id) == (True, 101)
    assert (under_v2.satisfied, under_v2.policy_version_id) == (False, 102)
    assert "MAX_ACTIONABLE_SEVERITY" in under_v2.failures
    result = classify(ClassificationInput(True, ("MEDIUM",), accepted_risk=under_v1))
    assert result.classification is RiskClassification.ACCEPTED_RISK
    assert result.accepted_risk_policy_version_id == 101


@pytest.mark.parametrize("severity", ["HIGH", "CRITICAL", "", None])
def test_accepted_risk_cannot_cover_high_or_critical__FR_SCA_004(severity):
    with pytest.raises(PolicyValidationError):
        validate_accepted_risk_rules({"max_actionable_severity": severity})


def test_accepted_risk_rejects_unknown_rules():
    with pytest.raises(PolicyValidationError):
        validate_accepted_risk_rules({"max_actionable_severity": "LOW", "auto_upgrade": True})


def test_accepted_risk_is_never_satisfied_with_review_reasons():
    outcome = evaluate_accepted_risk(ref(PolicyKind.ACCEPTED_RISK, {"max_actionable_severity": "MEDIUM"}), facts(has_review_reasons=True), now=NOW)
    assert not outcome.satisfied and "NO_REVIEW_REASONS" in outcome.failures


@pytest.mark.parametrize(
    ("rules", "fact_overrides", "failing"),
    [
        ({"max_cvss_score": 4.0}, {}, "MAX_CVSS_SCORE"),
        ({"max_cvss_score": 4.0}, {"max_actionable_cvss": None}, "MAX_CVSS_SCORE"),
        ({"allowed_actionable_vex_statuses": ["UNDER_INVESTIGATION"]}, {"actionable_vex_statuses": frozenset({"AFFECTED"})}, "ALLOWED_VEX_STATUSES"),
        ({"max_actionable_vulnerabilities": 0}, {}, "MAX_ACTIONABLE_VULNERABILITIES"),
        ({"allowed_lifecycle": ["SUPPORTED"]}, {"lifecycle": LifecycleBucket.EOL}, "ALLOWED_LIFECYCLE"),
        ({"max_analysis_age_days": 1}, {}, "ANALYSIS_FRESHNESS"),
        ({"max_analysis_age_days": 30}, {"latest_analysis_at": None}, "ANALYSIS_FRESHNESS"),
    ],
)
def test_accepted_risk_criteria_each_fail_closed(rules, fact_overrides, failing):
    policy = ref(PolicyKind.ACCEPTED_RISK, {"max_actionable_severity": "MEDIUM", **rules})
    outcome = evaluate_accepted_risk(policy, facts(**fact_overrides), now=NOW)
    assert not outcome.satisfied
    assert failing in outcome.failures
    # Every criterion is explained for the UI (US-SCA-03).
    assert all({"criterion", "passed", "detail"} <= set(item) for item in outcome.criteria)


def test_accepted_risk_unknown_highest_severity_is_not_accepted():
    policy = ref(PolicyKind.ACCEPTED_RISK, {"max_actionable_severity": "MEDIUM"})
    assert not evaluate_accepted_risk(policy, facts(highest_actionable_severity="UNKNOWN"), now=NOW).satisfied


# ---------------------------------------------------------------------------
# Trust (FR-SCA-005)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rules",
    [
        {"min_tenant_products": 1},
        {"min_tenant_products": 5, "allowed_lifecycle": ["SUPPORTED"]},
        {"min_tenant_products": 5, "allowed_classifications": ["NO_KNOWN_ACTIONABLE_VULNERABILITIES"]},
    ],
)
def test_T09_adoption_only_trust_policy_is_invalid__FR_SCA_005(rules):
    with pytest.raises(PolicyValidationError):
        validate_trust_rules(rules)


def test_T09_heavy_adoption_never_grants_trust_when_other_criteria_fail__FR_SCA_005():
    policy = ref(PolicyKind.TRUST, {
        "allowed_classifications": ["NO_KNOWN_ACTIONABLE_VULNERABILITIES"],
        "allowed_lifecycle": ["SUPPORTED"],
        "min_tenant_products": 2,
    })
    popular_but_risky = facts(classification=RiskClassification.MEDIUM, product_count=500)
    outcome = evaluate_trust(policy, popular_but_risky, now=NOW)
    assert outcome.trusted is False
    passed = {c.name for c in outcome.criteria if c.passed}
    assert "MIN_TENANT_ADOPTION" in passed and "ACCEPTABLE_CURRENT_RISK" not in passed


@pytest.mark.parametrize("bucket", ["CRITICAL", "HIGH", "REVIEW_REQUIRED", "UNKNOWN"])
def test_trust_policy_cannot_allow_unacceptable_classifications(bucket):
    with pytest.raises(PolicyValidationError):
        validate_trust_rules({"allowed_classifications": [bucket], "allowed_lifecycle": ["SUPPORTED"]})


def test_trust_requires_every_criterion_and_reports_policy_version():
    policy = ref(PolicyKind.TRUST, {
        "allowed_classifications": ["NO_KNOWN_ACTIONABLE_VULNERABILITIES", "LOW"],
        "allowed_lifecycle": ["SUPPORTED"],
        "allowed_licenses": ["MIT", "Apache-2.0"],
        "denied_licenses": ["AGPL-3.0"],
        "max_evidence_age_days": 30,
    }, version_id=77)
    good = facts(classification=RiskClassification.LOW)
    outcome = evaluate_trust(policy, good, now=NOW)
    assert outcome.trusted and outcome.policy_version_id == 77
    assert not evaluate_trust(policy, facts(classification=RiskClassification.LOW, licenses=("AGPL-3.0",)), now=NOW).trusted
    assert not evaluate_trust(policy, facts(classification=RiskClassification.LOW, licenses=()), now=NOW).trusted
    assert not evaluate_trust(policy, facts(classification=RiskClassification.LOW, lifecycle=LifecycleBucket.EOL), now=NOW).trusted
    stale = (NOW - timedelta(days=90)).isoformat()
    assert not evaluate_trust(policy, facts(classification=RiskClassification.LOW, latest_analysis_at=stale), now=NOW).trusted


# ---------------------------------------------------------------------------
# Purpose (FR-SCA-009)
# ---------------------------------------------------------------------------


def record(source, *, tenant_id=1, category=None, purpose=None, use_case=None, confidence="HIGH", provenance=None):
    return PurposeRecord(PurposeSource(source), tenant_id, purpose, use_case, category, confidence, provenance)


def test_purpose_priority_sbom_then_package_then_curated_then_ai():
    resolved = resolve_purpose(
        sbom_descriptions=[(1, "Simple Logging Facade for Java")],
        records=[
            record("AI", category="ai-guess", purpose="ai text", confidence="HIGH", provenance={"model": "m"}),
            record("CURATED", category="logging", use_case="Application logging"),
            record("PACKAGE", purpose="package text"),
        ],
    )
    as_dict = resolved.to_dict()
    assert as_dict["functional_description"]["source"] == "SBOM"
    assert as_dict["primary_use_case"]["source"] == "CURATED"
    assert as_dict["technology_category"] == {
        "value": "logging", "source": "CURATED", "confidence": "HIGH", "ai_assisted": False,
        "provenance": {"record_id": None, "scope": "TENANT"},
    }
    assert as_dict["ai_assisted"] is False


def test_tenant_curated_row_overrides_platform_row():
    resolved = resolve_purpose(records=[record("CURATED", tenant_id=None, category="platform"), record("CURATED", category="tenant")])
    assert resolved.to_dict()["technology_category"]["value"] == "tenant"


def test_T16_ai_purpose_is_marked_and_provenanced__FR_SCA_009():
    resolved = resolve_purpose(records=[record("AI", category="pdf", confidence="MEDIUM", provenance={"model": "claude", "generated_at": "2026-10-01"})])
    category = resolved.to_dict()["technology_category"]
    assert category["ai_assisted"] is True and category["source"] == "AI"
    assert category["provenance"]["model"] == "claude"
    assert resolved.to_dict()["ai_assisted"] is True


def test_T16_ai_purpose_without_provenance_is_rejected__FR_SCA_009():
    with pytest.raises(ValueError):
        validate_purpose_payload({"source": "AI", "technology_category": "logging", "confidence": "HIGH"})
    with pytest.raises(ValueError):
        validate_purpose_payload({"source": "AI", "technology_category": "logging", "confidence": "HIGH", "provenance": {"model": "m"}})
    ok = validate_purpose_payload({
        "source": "AI", "technology_category": "logging", "confidence": "LOW",
        "provenance": {"model": "m", "generated_at": "2026-10-01T00:00:00Z"},
    })
    assert ok["source"] is PurposeSource.AI


def test_sbom_evidence_cannot_be_written_as_a_row():
    with pytest.raises(ValueError):
        validate_purpose_payload({"source": "SBOM", "technology_category": "logging"})


def test_T15_purpose_search_needs_sufficient_evidence__FR_SCA_009():
    low_ai = resolve_purpose(records=[record("AI", category="logging", confidence="LOW", provenance={"model": "m"})])
    medium_ai = resolve_purpose(records=[record("AI", category="logging", confidence="MEDIUM", provenance={"model": "m"})])
    curated = resolve_purpose(records=[record("CURATED", category="Logging")])
    sbom = resolve_purpose(sbom_descriptions=[(1, "Structured logging for Python")])
    assert not low_ai.matches("logging", "category")
    assert medium_ai.matches("logging", "category")
    assert curated.matches("logging", "category")
    assert sbom.matches("logging", "purpose") and not sbom.matches("logging", "category")
    assert not resolve_purpose().matches("logging", "all")


def test_sbom_descriptions_pick_the_most_common_and_cite_sboms():
    resolved = resolve_purpose(sbom_descriptions=[(1, "PDF rendering"), (2, "PDF rendering"), (3, "Other"), (4, None)])
    field = resolved.to_dict()["functional_description"]
    assert field["value"] == "PDF rendering"
    assert field["confidence"] == "MEDIUM"  # SBOMs disagree
    assert field["provenance"]["sbom_ids"] == [1, 2]


# ---------------------------------------------------------------------------
# Parser: component descriptions (purpose evidence of source SBOM)
# ---------------------------------------------------------------------------


def test_cyclonedx_json_and_xml_and_spdx_keep_component_descriptions__FR_SCA_009():
    cdx = parse_cyclonedx_dict({"bomFormat": "CycloneDX", "components": [{"name": "slf4j", "version": "2", "description": " Logging facade "}]})
    assert cdx[0]["description"] == "Logging facade"
    xml = (
        '<bom xmlns="http://cyclonedx.org/schema/bom/1.5"><components><component type="library">'
        "<name>a</name><version>1</version><description>PDF generation</description></component></components></bom>"
    )
    assert parse_cyclonedx_xml(xml)[0]["description"] == "PDF generation"
    spdx = parse_spdx_dict({"spdxVersion": "SPDX-2.3", "packages": [{"name": "p", "versionInfo": "1", "SPDXID": "SPDXRef-p", "summary": "HTTP client"}]})
    assert spdx[0]["description"] == "HTTP client"
    assert parse_cyclonedx_dict({"bomFormat": "CycloneDX", "components": [{"name": "x", "version": "1"}]})[0]["description"] is None
