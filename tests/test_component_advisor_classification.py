"""Secure Component Advisor — pure risk-classification rules (FR-SCA-003, spec §2).

Test matrix ids (T1…T7) come from the implementation prompt §10; decision ids
(D-3…D-6) from docs/secure-component-advisor/phase0-analysis.md.
"""

import pytest

from app.services.component_advisor.classification import (
    INFORMATIONAL_SUPPORTED,
    AcceptedRiskOutcome,
    ClassificationInput,
    ReviewReason,
    RiskClassification,
    bucket_counts,
    classify,
    is_actionable,
)
from app.services.component_advisor.identity import split_licenses, version_identity
from app.services.component_advisor.lifecycle_mapping import LifecycleBucket, lifecycle_bucket, lifecycle_view


def _classify(*severities, evidence=True, reasons=(), accepted=None):
    return classify(
        ClassificationInput(
            has_vulnerability_evidence=evidence,
            actionable_severities=tuple(severities),
            review_reasons=frozenset(reasons),
            accepted_risk=accepted,
        )
    )


def test_T01_zero_actionable_findings_is_no_known_actionable__FR_SCA_003():
    result = _classify()
    assert result.classification is RiskClassification.NO_KNOWN_ACTIONABLE_VULNERABILITIES
    assert result.highest_actionable_severity is None


@pytest.mark.parametrize("status", ["FIXED", "NOT_AFFECTED"])
def test_T02_T03_fixed_or_not_affected_is_not_actionable__FR_SCA_003(status):
    assert is_actionable(status) is False


@pytest.mark.parametrize("status", ["AFFECTED", "UNDER_INVESTIGATION", "under_investigation"])
def test_T04_affected_and_under_investigation_are_actionable__FR_SCA_003(status):
    assert is_actionable(status) is True


def test_finding_without_vex_context_is_actionable__VEX_REC_002_A():
    """Reconciliation lag must fail safe, never read as "no known vulnerabilities"."""
    assert is_actionable(None) is True


def test_T05_critical_plus_low_is_critical_bucket__FR_SCA_003():
    result = _classify("LOW", "CRITICAL")
    assert result.classification is RiskClassification.CRITICAL
    assert result.highest_actionable_severity == "CRITICAL"


def test_T06_high_plus_medium_is_high_bucket__FR_SCA_003():
    assert _classify("MEDIUM", "high").classification is RiskClassification.HIGH


@pytest.mark.parametrize(
    ("severity", "bucket"),
    [("MEDIUM", RiskClassification.MEDIUM), ("LOW", RiskClassification.LOW)],
)
def test_medium_and_low_buckets(severity, bucket):
    assert _classify(severity).classification is bucket


def test_known_severity_outranks_unknown_severity():
    assert _classify("UNKNOWN", "HIGH").classification is RiskClassification.HIGH


def test_only_unknown_severity_actionable_requires_review__D3():
    result = _classify("UNKNOWN", None)
    assert result.classification is RiskClassification.REVIEW_REQUIRED
    assert ReviewReason.UNKNOWN_ACTIONABLE_SEVERITY.value in result.review_reasons


def test_no_vulnerability_evidence_is_unknown_not_no_known_actionable__spec_s2():
    """Zero observed vulnerabilities is not proof when nothing was analysed (§1.4)."""
    assert _classify(evidence=False).classification is RiskClassification.UNKNOWN


@pytest.mark.parametrize("severity", ["CRITICAL", "HIGH"])
def test_critical_and_high_outrank_review_reasons__D3_amended(severity):
    """Critical/High KPIs must never understate known risk (decision 2026-10-01)."""
    result = _classify(severity, "LOW", reasons={ReviewReason.VEX_CONFLICT})
    assert result.classification is RiskClassification(severity)
    # The review reason is still reported so the version stays in the review queue.
    assert result.review_reasons == (ReviewReason.VEX_CONFLICT.value,)


@pytest.mark.parametrize("severities", [("MEDIUM",), ("LOW",), ()])
def test_review_reason_outranks_medium_low_and_none__D3(severities):
    result = _classify(*severities, reasons={ReviewReason.VEX_CONFLICT})
    assert result.classification is RiskClassification.REVIEW_REQUIRED
    assert result.review_reasons == (ReviewReason.VEX_CONFLICT.value,)


def test_review_reason_outranks_unknown_when_no_evidence__D3():
    result = _classify(evidence=False, reasons={ReviewReason.LOW_IDENTITY_CONFIDENCE})
    assert result.classification is RiskClassification.REVIEW_REQUIRED


def test_accepted_risk_never_overrides_critical_high_or_review():
    satisfied = AcceptedRiskOutcome(satisfied=True, policy_version_id=7)
    assert _classify("HIGH", accepted=satisfied).classification is RiskClassification.HIGH
    assert _classify("CRITICAL", accepted=satisfied).classification is RiskClassification.CRITICAL
    reviewed = _classify("MEDIUM", accepted=satisfied, reasons={ReviewReason.VEX_REVALIDATION})
    assert reviewed.classification is RiskClassification.REVIEW_REQUIRED


def test_accepted_risk_requires_a_satisfied_policy__FR_SCA_004():
    satisfied = AcceptedRiskOutcome(satisfied=True, policy_version_id=7, reasons=("MAX_SEVERITY_MEDIUM",))
    result = _classify("MEDIUM", accepted=satisfied)
    assert result.classification is RiskClassification.ACCEPTED_RISK
    assert result.accepted_risk_policy_version_id == 7
    assert _classify("MEDIUM", accepted=AcceptedRiskOutcome(satisfied=False)).classification is RiskClassification.MEDIUM


def test_accepted_risk_never_applies_without_actionable_findings():
    satisfied = AcceptedRiskOutcome(satisfied=True, policy_version_id=7)
    assert _classify(accepted=satisfied).classification is RiskClassification.NO_KNOWN_ACTIONABLE_VULNERABILITIES


def test_informational_is_never_produced__D4():
    assert INFORMATIONAL_SUPPORTED is False
    produced = {_classify(sev).classification for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "INFO")}
    assert RiskClassification.INFORMATIONAL not in produced


def test_T07_bucket_counts_reconcile_with_inputs__FR_SCA_003():
    classifications = [
        _classify("CRITICAL").classification,
        _classify("LOW").classification,
        _classify().classification,
        _classify(evidence=False).classification,
        _classify("HIGH", reasons={ReviewReason.LOW_IDENTITY_CONFIDENCE}).classification,
    ]
    counts = bucket_counts(classifications)
    assert set(counts) == {bucket.value for bucket in RiskClassification}
    assert sum(counts.values()) == len(classifications)


def test_classification_vocabulary_never_claims_safety__spec_s1_2():
    for bucket in RiskClassification:
        assert "SAFE" not in bucket.value
        assert "SECURE" not in bucket.value
        assert "VULNERABILITY_FREE" not in bucket.value


@pytest.mark.parametrize(
    ("status", "bucket"),
    [
        ("Supported", LifecycleBucket.SUPPORTED),
        ("active", LifecycleBucket.SUPPORTED),
        ("EOL Soon", LifecycleBucket.MAINTENANCE),
        ("Deprecated", LifecycleBucket.MAINTENANCE),
        ("Possibly Unmaintained", LifecycleBucket.MAINTENANCE),
        ("EOS", LifecycleBucket.EOS),
        ("EOF", LifecycleBucket.EOS),
        ("EOL", LifecycleBucket.EOL),
        ("Unsupported", LifecycleBucket.EOL),
        ("Unknown", LifecycleBucket.UNKNOWN),
        (None, LifecycleBucket.UNKNOWN),
    ],
)
def test_lifecycle_bucket_mapping__D6(status, bucket):
    assert lifecycle_bucket(status) is bucket


class _Row:
    def __init__(self, **values):
        self.id = values.pop("id", 1)
        for name in (
            "dedupe_canonical_id", "normalized_purl", "primary_cpe", "normalized_ecosystem",
            "normalized_name", "normalized_version", "normalized_supplier",
            "canonical_identity_confidence", "lifecycle_status", "eol_date", "eos_date", "eof_date",
            "lifecycle_checked_at", "lifecycle_is_stale", "lifecycle_source", "lifecycle_manual_override",
        ):
            setattr(self, name, values.pop(name, None))
        assert not values, values


def test_lifecycle_manual_override_wins_then_latest_check():
    older = _Row(lifecycle_status="EOL", eol_date="2025-01-01", lifecycle_checked_at="2026-01-01")
    newer = _Row(lifecycle_status="Supported", lifecycle_checked_at="2026-06-01")
    assert lifecycle_view([older, newer]).bucket is LifecycleBucket.SUPPORTED
    manual = _Row(lifecycle_status="EOL", eol_date="2025-01-01", lifecycle_checked_at="2025-01-01", lifecycle_manual_override=True)
    view = lifecycle_view([newer, manual])
    assert view.bucket is LifecycleBucket.EOL
    assert view.effective_date == "2025-01-01"
    assert lifecycle_view([]).bucket is LifecycleBucket.UNKNOWN


def test_identity_rebuilds_persisted_canonical_key():
    """A row normalized before ``dedupe_canonical_id`` existed gets the same key."""
    import hashlib

    key = hashlib.sha256(b"purl:pkg:npm/lodash@4.17.20").hexdigest()
    persisted = version_identity(_Row(id=1, dedupe_canonical_id=key, normalized_purl="pkg:npm/lodash@4.17.20"))
    rebuilt = version_identity(_Row(id=2, normalized_purl="pkg:npm/lodash@4.17.20", normalized_ecosystem="npm"))
    assert persisted.key == rebuilt.key == key
    assert rebuilt.basis == "purl" and rebuilt.confidence == "HIGH"


def test_identity_without_evidence_is_per_occurrence_and_low_confidence():
    identity = version_identity(_Row(id=42, normalized_name="mystery"))
    assert identity.key == "occ-42"
    assert identity.confidence == "LOW"


def test_split_licenses_dedupes_case_insensitively():
    assert split_licenses("MIT, Apache-2.0", "mit", None, "") == ["Apache-2.0", "MIT"]
