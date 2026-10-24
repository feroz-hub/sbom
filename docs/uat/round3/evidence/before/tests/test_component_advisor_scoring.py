"""Secure Component Advisor — history, scoring, confidence, freshness, explanation (spec Step 7).

FR-SCA-016..020, US-SCA-11..13. Prompt §10: T27 (missing compatibility
evidence reduces confidence), T28 (zero vulnerabilities never yields an
absolute "safe" claim), T29 (ranking exposes factor breakdown and policy
version), T30 (24-month history where available; actual coverage visible).
"""

from datetime import UTC, datetime, timedelta

import pytest

from app.services.component_advisor.policy import PolicyKind, PolicyStatus, PolicyValidationError, PolicyVersionRef
from app.services.component_advisor.recommendations.confidence import confidence, freshness_view
from app.services.component_advisor.recommendations.explanation import (
    CONFIDENCE_TEXT,
    LIMITATION_TEXT,
    REASON_TEXT,
    explain,
)
from app.services.component_advisor.recommendations.history import (
    ZERO_HISTORY_NOTE,
    NvdObservation,
    build_history,
    candidate_cpe,
)
from app.services.component_advisor.recommendations.scoring import (
    BUILTIN_LABEL,
    DEFAULT_SCORING_RULES,
    FACTORS,
    ScoringPolicy,
    score_candidate,
    validate_scoring_rules,
)

NOW = datetime(2026, 10, 1, tzinfo=UTC)
CHECK_TYPES = ("LICENSE", "LIFECYCLE", "FUNCTIONAL_PURPOSE", "PRODUCT_CONSTRAINTS", "API_COMPATIBILITY")


def iso(days_ago):
    return (NOW - timedelta(days=days_ago)).isoformat()


def evaluation(*, classification="NO_KNOWN_ACTIONABLE_VULNERABILITIES", observed=True, lifecycle="SUPPORTED",
               analysed_days_ago=5, products=3, checks=None, history=None):
    checks = checks or {t: "PASS" for t in CHECK_TYPES}
    counts = {"PASS": 0, "FAIL": 0, "REVIEW_REQUIRED": 0, "UNKNOWN": 0}
    for result in checks.values():
        counts[result] += 1
    return {
        "current_posture": {"status": "OBSERVED", "classification": classification} if observed else {"status": "NOT_OBSERVED_IN_TENANT"},
        "lifecycle": {"bucket": lifecycle},
        "freshness": {"latest_analysis_at": iso(analysed_days_ago) if analysed_days_ago is not None else None,
                      "lifecycle_checked_at": iso(analysed_days_ago) if analysed_days_ago is not None else None},
        "adoption": {"product_count": products},
        "compatibility": {"counts": counts, "blocked": False, "drop_in_representable": counts["PASS"] == len(checks)},
        "compatibility_checks": [{"check_type": t, "result": r} for t, r in checks.items()],
        "history": history or build_history(tenant={"runs": 4, "findings": [], "earliest_run_at": iso(800), "latest_run_at": iso(5)},
                                             nvd=None, nvd_status="DISABLED", now=NOW),
    }


def scored(ev, policy=None):
    policy = policy or ScoringPolicy.resolve(None)
    score, factors = score_candidate(ev, policy, now=NOW)
    fresh = freshness_view(ev, source_freshness={}, stale_after_days=policy.rules["stale_after_days"], now=NOW)
    return score, factors, confidence(ev, factors, fresh, weights=policy.rules["weights"])


# ---------------------------------------------------------------------------
# History (T30, T28)
# ---------------------------------------------------------------------------


def test_T30_default_window_is_24_months_with_actual_coverage__FR_SCA_016():
    history = build_history(
        tenant={"runs": 2, "earliest_run_at": iso(180), "latest_run_at": iso(1), "findings": [
            {"canonical_id": "CVE-2026-1", "severity": "HIGH", "published_on": iso(100), "observed_at": iso(90)},
            {"canonical_id": "CVE-2019-1", "severity": "CRITICAL", "published_on": iso(2000), "observed_at": iso(90)},
        ]},
        nvd=None, nvd_status="DISABLED", now=NOW,
    )
    assert history["window_months"] == 24
    assert history["window_start"] == (NOW - timedelta(days=730)).date().isoformat()
    # Only six months are actually covered — reported, not hidden.
    assert 5.5 <= history["coverage"]["covered_months"] <= 6.5
    assert any(gap.startswith("COVERAGE_STARTS_") for gap in history["coverage"]["gaps"])
    assert "NVD_MIRROR_DISABLED" in history["coverage"]["gaps"]
    # The 2019 disclosure is outside the window.
    assert history["disclosed_vulnerability_count"] == 1 and history["critical_high_count"] == 1
    assert history["first_observed"] and history["last_observed"]


def test_T30_nvd_mirror_covers_the_full_window_when_available__FR_SCA_016():
    nvd = [NvdObservation("CVE-2026-9", NOW - timedelta(days=30), "CRITICAL"),
           NvdObservation("CVE-2020-9", NOW - timedelta(days=2000), "CRITICAL")]
    history = build_history(tenant=None, nvd=nvd, nvd_status="AVAILABLE", now=NOW)
    assert history["coverage"]["covered_months"] >= 23.5
    assert history["severity_distribution"]["CRITICAL"] == 1
    assert {s["source"]: s["status"] for s in history["coverage"]["sources"]} == {"TENANT_ANALYSIS": "NO_DATA", "NVD_MIRROR": "AVAILABLE"}


def test_T28_zero_vulnerabilities_is_never_presented_as_safe__FR_SCA_016():
    covered = build_history(tenant={"runs": 3, "findings": [], "earliest_run_at": iso(700), "latest_run_at": iso(1)},
                            nvd=None, nvd_status="DISABLED", now=NOW)
    assert covered["status"] == "NO_VULNERABILITIES_IN_COVERED_WINDOW" and covered["note"] == ZERO_HISTORY_NOTE
    empty = build_history(tenant=None, nvd=None, nvd_status="DISABLED", now=NOW)
    assert empty["status"] == "NO_HISTORY_COVERAGE" and empty["coverage"]["covered_months"] == 0.0
    assert "NO_SOURCE_COVERS_THE_WINDOW" in empty["coverage"]["gaps"]


def test_T28_no_generated_text_claims_safety__spec_s1_2():
    texts = [*REASON_TEXT.values(), *LIMITATION_TEXT.values(), *CONFIDENCE_TEXT.values(), ZERO_HISTORY_NOTE]
    for text in texts:
        lowered = text.lower().replace("not proof of security", "")
        assert "safe" not in lowered and "secure" not in lowered and "vulnerability free" not in lowered, text
    summary = explain("lib", "1.0", reasons=[{"code": "NO_KNOWN_ACTIONABLE_VULNS_CURRENT_SNAPSHOT"}], limitations=[],
                      confidence_level="LOW", blocked=False, blocking_checks=[],
                      history=build_history(tenant=None, nvd=None, nvd_status="DISABLED", now=NOW))["summary"]
    assert "safe" not in summary.lower()


def test_candidate_cpe_replaces_only_the_version_slot():
    assert candidate_cpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", "2.17.1") == "cpe:2.3:a:apache:log4j:2.17.1:*:*:*:*:*:*:*"
    assert candidate_cpe(None, "1") is None and candidate_cpe("not-a-cpe", "1") is None


# ---------------------------------------------------------------------------
# Scoring (T29)
# ---------------------------------------------------------------------------


def test_T29_score_exposes_every_factor_and_the_policy_version__FR_SCA_017():
    score, factors, _ = scored(evaluation())
    assert [f.factor for f in factors] == list(FACTORS)
    policy = ScoringPolicy.resolve(None)
    rows = [f.to_dict(policy) for f in factors]
    assert all(row["policy_version_label"] == BUILTIN_LABEL and row["policy_version_id"] is None for row in rows)
    assert {"raw_value", "normalized_value", "weight", "contribution", "missing_data_treatment",
            "evidence_source", "evidence_at"} <= set(rows[0])
    assert abs(sum(f.weight for f in factors) - 1.0) < 1e-5  # weights are stored rounded to 6 dp
    assert abs(sum(f.contribution for f in factors) * 100 - score) < 0.01
    # Maintenance has no evidence source yet; recorded as penalized, never imputed.
    maintenance = next(f for f in factors if f.factor == "maintenance")
    assert maintenance.normalized_value is None and maintenance.missing_data_treatment == "PENALIZE"


def test_T29_a_versioned_scoring_policy_changes_the_order_and_is_recorded__FR_SCA_017():
    ref = PolicyVersionRef(42, 7, PolicyKind.SCORING, 3, PolicyStatus.ACTIVE, "TENANT",
                           validate_scoring_rules({"weights": {"tenant_adoption": 1.0}}))
    adoption_policy = ScoringPolicy.resolve(ref)
    clean_unused = evaluation(products=0)
    risky_popular = evaluation(classification="MEDIUM", products=5)
    default = ScoringPolicy.resolve(None)
    assert scored(clean_unused, default)[0] > scored(risky_popular, default)[0]
    assert scored(risky_popular, adoption_policy)[0] > scored(clean_unused, adoption_policy)[0]
    assert scored(risky_popular, adoption_policy)[1][0].to_dict(adoption_policy)["policy_version_id"] == 42
    assert adoption_policy.label == "tenant-v3"


def test_exclude_missing_data_renormalizes_weights():
    ref = PolicyVersionRef(1, 1, PolicyKind.SCORING, 1, PolicyStatus.ACTIVE, "TENANT",
                           validate_scoring_rules({**DEFAULT_SCORING_RULES, "missing_data": "EXCLUDE"}))
    _, factors = score_candidate(evaluation(), ScoringPolicy.resolve(ref), now=NOW)
    assert next(f for f in factors if f.factor == "maintenance").weight == 0.0
    assert abs(sum(f.weight for f in factors) - 1.0) < 1e-5  # weights are stored rounded to 6 dp


@pytest.mark.parametrize("rules", [{"weights": {"safety": 1}}, {"weights": {"current_risk": -1}},
                                   {"weights": {"current_risk": 0}}, {"missing_data": "IMPUTE"},
                                   {"history_window_months": 3}, {"colour": "red"}])
def test_invalid_scoring_rules_are_rejected(rules):
    with pytest.raises(PolicyValidationError):
        validate_scoring_rules(rules)


# ---------------------------------------------------------------------------
# Confidence and freshness (T27, FR-SCA-019/020)
# ---------------------------------------------------------------------------


def test_complete_fresh_observed_evidence_is_high_confidence__FR_SCA_019():
    _, _, conf = scored(evaluation())
    assert conf["level"] == "HIGH" and conf["unknown_material_checks"] == []


def test_T27_missing_compatibility_evidence_reduces_confidence__FR_SCA_019():
    full = scored(evaluation())[2]
    missing_one = scored(evaluation(checks={**{t: "PASS" for t in CHECK_TYPES}, "LICENSE": "UNKNOWN"}))[2]
    missing_two = scored(evaluation(checks={**{t: "PASS" for t in CHECK_TYPES}, "LICENSE": "UNKNOWN", "LIFECYCLE": "UNKNOWN"}))[2]
    order = ("INSUFFICIENT_EVIDENCE", "LOW", "MEDIUM", "HIGH")
    assert order.index(full["level"]) > order.index(missing_one["level"]) > order.index(missing_two["level"])
    assert "MATERIAL_COMPATIBILITY_EVIDENCE_MISSING" in missing_one["reasons"]
    assert missing_one["drop_in_representable"] is False


def test_unobserved_candidate_without_history_has_insufficient_evidence__FR_SCA_019():
    no_history = build_history(tenant=None, nvd=None, nvd_status="DISABLED", now=NOW)
    conf = scored(evaluation(observed=False, analysed_days_ago=None, products=0, history=no_history))[2]
    assert conf["level"] == "INSUFFICIENT_EVIDENCE"


def test_stale_evidence_lowers_confidence_and_is_flagged__FR_SCA_020():
    _, _, conf = scored(evaluation(analysed_days_ago=200))
    assert conf["level"] in ("MEDIUM", "LOW")
    assert "STALE_EVIDENCE" in conf["reasons"]
    fresh = freshness_view(evaluation(analysed_days_ago=200), source_freshness={"nvd_mirror_last_success_at": iso(1)},
                           stale_after_days=90, now=NOW)
    assert "ANALYSIS_EVIDENCE_STALE" in fresh["stale_flags"]
    assert fresh["vulnerability_source_refreshed_at"] == iso(1)
    assert fresh["observation_window"]["months"] == 24


def test_unavailable_analysis_never_silently_passes__FR_SCA_020():
    fresh = freshness_view(evaluation(analysed_days_ago=None), source_freshness={}, stale_after_days=90, now=NOW)
    assert "ANALYSIS_EVIDENCE_UNAVAILABLE" in fresh["stale_flags"]


def test_explanation_is_generated_from_structured_codes__FR_SCA_018():
    result = explain("logback-classic", "1.4.14",
                     reasons=[{"code": "SIMILAR_PURPOSE", "detail": "Same technology category (logging)"},
                              {"code": "USED_BY_N_TENANT_PRODUCTS", "count": 4}],
                     limitations=[{"code": "MIGRATION_REQUIRED"}], confidence_level="MEDIUM", blocked=True,
                     blocking_checks=["LICENSE"], history=None)
    assert result["generated_from"] == "STRUCTURED_EVIDENCE"
    assert "blocked by compatibility checks (LICENSE)" in result["summary"]
    assert "Is already used by 4 product(s) in this tenant." in result["reasons"]
    assert any("not a drop-in replacement" in line for line in result["limitations"])
