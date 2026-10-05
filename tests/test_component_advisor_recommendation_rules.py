"""Secure Component Advisor — recommendation workflow and same-family discovery rules.

FR-SCA-011 / FR-SCA-013 (spec Step 5). Pure rules exercised on real
``ComponentVersionIntelligence`` records built from an in-memory schema.
Prompt §10: T17–T19 (triggers), T21 (same-family versions evaluated first).
"""

from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import Tenant
from app.services.component_advisor.intelligence_service import build_snapshot
from app.services.component_advisor.recommendations.version_discovery import discover_same_family
from app.services.component_advisor.recommendations.workflow import (
    ALLOWED_TRANSITIONS,
    OPEN_STATUSES,
    InvalidTransition,
    RecommendationStatus,
    TriggerNotSupported,
    TriggerType,
    can_evaluate,
    eligible_triggers,
    require_transition,
    trigger_evidence,
)
from app.services.dashboard_scope import DashboardScope
from tests.component_advisor_support import World


@pytest.fixture
def world():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        now = datetime.now(UTC)
        db.add(Tenant(id=1, name="One", slug="one", status="ACTIVE", created_at=now, updated_at=now))
        db.flush()
        yield World(db)
    engine.dispose()


def versions(world):
    return {(v.name, v.version): v for v in build_snapshot(world.db, DashboardScope(1)).versions}


def log4j_world(world):
    """log4j-core 2.14.1 CRITICAL plus observed 2.17.1 (clean), 2.16.0 (HIGH), 2.13.0 (CRITICAL)."""
    sboms = [world.sbom(world.product()) for _ in range(4)]
    source = world.component(sboms[0], "log4j-core", "2.14.1", ecosystem="maven", license="Apache-2.0",
                             latest_version="2.24.1", recommended_version="2.17.1", lifecycle_status="EOL")
    world.finding(source, "CVE-2021-44228", "CRITICAL")
    world.component(sboms[1], "log4j-core", "2.17.1", ecosystem="maven", license="Apache-2.0", lifecycle_status="Supported")
    high = world.component(sboms[2], "log4j-core", "2.16.0", ecosystem="maven", license="Apache-2.0")
    world.finding(high, "CVE-2021-45105", "HIGH")
    old = world.component(sboms[3], "log4j-core", "2.13.0", ecosystem="maven")
    world.finding(old, "CVE-2021-44228", "CRITICAL")
    return versions(world)


# ---------------------------------------------------------------------------
# Workflow
# ---------------------------------------------------------------------------


def test_happy_path_transitions_follow_the_spec_state_machine__FR_SCA_011():
    path = ["OPEN", "EVALUATING", "REVIEW_REQUIRED", "RECOMMENDED", "ACCEPTED", "CLOSED"]
    for current, target in zip(path, path[1:]):
        assert require_transition(current, target) is RecommendationStatus(target)


@pytest.mark.parametrize(("current", "target"), [("OPEN", "RECOMMENDED"), ("EVALUATING", "ACCEPTED"),
                                                 ("REVIEW_REQUIRED", "ACCEPTED"), ("CLOSED", "OPEN")])
def test_shortcuts_past_human_review_are_rejected__FR_SCA_021(current, target):
    with pytest.raises(InvalidTransition):
        require_transition(current, target)


def test_only_review_required_or_recommended_can_reach_a_decision():
    reaches_accepted = {s for s, targets in ALLOWED_TRANSITIONS.items() if RecommendationStatus.ACCEPTED in targets}
    assert reaches_accepted == {RecommendationStatus.RECOMMENDED}


def test_open_statuses_and_re_evaluation():
    assert {s.value for s in OPEN_STATUSES} == {"OPEN", "EVALUATING", "REVIEW_REQUIRED", "RECOMMENDED"}
    assert can_evaluate("OPEN") and can_evaluate("REVIEW_REQUIRED")
    assert not any(can_evaluate(s) for s in ("EVALUATING", "RECOMMENDED", "ACCEPTED", "REJECTED", "DEFERRED", "CLOSED"))


# ---------------------------------------------------------------------------
# Triggers (T17–T19)
# ---------------------------------------------------------------------------


def test_T17_critical_affected_component_can_trigger__FR_SCA_011(world):
    source = log4j_world(world)[("log4j-core", "2.14.1")]
    evidence = trigger_evidence(source, TriggerType.CRITICAL_FINDING)
    assert evidence["highest_actionable_severity"] == "CRITICAL"
    assert evidence["evidence"][0]["analysis_run_id"]
    with pytest.raises(TriggerNotSupported):
        trigger_evidence(source, TriggerType.HIGH_FINDING)


def test_T18_high_affected_component_can_trigger__FR_SCA_011(world):
    high = log4j_world(world)[("log4j-core", "2.16.0")]
    assert trigger_evidence(high, "HIGH_FINDING")["highest_actionable_severity"] == "HIGH"
    with pytest.raises(TriggerNotSupported):
        trigger_evidence(high, "CRITICAL_FINDING")


def test_T19_eol_eos_and_manual_triggers__FR_SCA_011(world):
    sbom = world.sbom(world.product())
    world.component(sbom, "eol-lib", "1.0", lifecycle_status="EOL")
    world.component(sbom, "eos-lib", "1.0", lifecycle_status="EOS")
    world.component(sbom, "fine-lib", "1.0", lifecycle_status="Supported")
    snap = versions(world)
    assert "EOL" in eligible_triggers(snap[("eol-lib", "1.0")])
    assert "EOS" in eligible_triggers(snap[("eos-lib", "1.0")])
    assert eligible_triggers(snap[("fine-lib", "1.0")]) == ["MANUAL"]
    with pytest.raises(TriggerNotSupported):
        trigger_evidence(snap[("fine-lib", "1.0")], "EOL")


def test_T19_policy_violation_requires_a_failing_configured_policy__FR_SCA_011(world):
    from app.services.component_advisor.policy import PolicyKind, PolicyStatus, PolicyVersionRef, evaluate_trust, validate_trust_rules
    from app.services.component_advisor.intelligence_service import component_facts

    sbom = world.sbom(world.product())
    world.component(sbom, "gpl-lib", "1.0", license="AGPL-3.0", lifecycle_status="Supported")
    record = versions(world)[("gpl-lib", "1.0")]
    with pytest.raises(TriggerNotSupported):
        trigger_evidence(record, "POLICY_VIOLATION")  # no policy configured
    rules = validate_trust_rules({"allowed_classifications": ["NO_KNOWN_ACTIONABLE_VULNERABILITIES"],
                                  "allowed_lifecycle": ["SUPPORTED"], "denied_licenses": ["AGPL-3.0"]})
    record.trust = evaluate_trust(PolicyVersionRef(9, 1, PolicyKind.TRUST, 1, PolicyStatus.ACTIVE, "TENANT", rules), component_facts(record))
    evidence = trigger_evidence(record, "POLICY_VIOLATION")
    assert evidence["policy_failures"][0]["criterion"] == "NO_DENIED_LICENSE"
    assert evidence["policy_failures"][0]["policy_version_id"] == 9


# ---------------------------------------------------------------------------
# Same-family discovery (FR-SCA-013, T21)
# ---------------------------------------------------------------------------


def discover(world):
    snap = log4j_world(world)
    source = snap[("log4j-core", "2.14.1")]
    family = [v for v in snap.values() if v.family_key == source.family_key]
    result = discover_same_family(
        source, family,
        lifecycle_hints={"LIFECYCLE_LATEST": "2.24.1", "LIFECYCLE_RECOMMENDED": "2.17.1"},
        fixed_versions={"CVE-2021-44228": ["2.15.0", "2.12.2"]},
    )
    return result, {c.version: c for c in result.candidates}


def test_T21_safer_same_family_versions_are_evaluated__FR_SCA_013(world):
    result, by_version = discover(world)
    assert all(c.kind.value == "SAME_FAMILY_VERSION" for c in result.candidates)
    assert set(by_version) == {"2.17.1", "2.16.0", "2.15.0", "2.24.1"}
    assert result.summary()["alternatives_status"] == "NOT_EVALUATED"
    # Observed, safer versions are reviewed first; the clean one leads.
    assert [c.version for c in result.candidates][:2] == ["2.17.1", "2.16.0"]
    assert [c.rank for c in result.candidates] == [1, 2, 3, 4]


def test_versions_that_are_not_safer_are_excluded_with_a_reason(world):
    result, by_version = discover(world)
    excluded = {item["version"]: item["reason"] for item in result.excluded}
    assert excluded["2.13.0"] == "NOT_SAFER_THAN_SOURCE"
    assert excluded["2.12.2"] == "DOWNGRADE_WITHOUT_OBSERVED_POSTURE"
    assert "2.14.1" not in by_version


def test_observed_candidate_carries_tenant_posture_and_reasons__FR_SCA_013(world):
    _, by_version = discover(world)
    clean = by_version["2.17.1"]
    assert clean.source_type.value == "TENANT_OBSERVED" and clean.canonical_key
    assert set(clean.evidence_sources) == {"TENANT_OBSERVED", "LIFECYCLE_RECOMMENDED"}
    codes = {r["code"] for r in clean.reasons}
    assert {"SAME_ECOSYSTEM", "LOWER_CURRENT_RISK", "NO_KNOWN_ACTIONABLE_VULNS_CURRENT_SNAPSHOT",
            "SUPPORTED_LIFECYCLE", "SAFER_SUPPORTED_VERSION", "LIFECYCLE_PROVIDER_RECOMMENDED",
            "FIXES_SOURCE_VULNERABILITIES", "FOUND_IN_N_ACTIVE_TENANT_SBOMS"} <= codes
    assert clean.evaluation["current_posture"]["classification"] == "NO_KNOWN_ACTIONABLE_VULNERABILITIES"
    assert clean.evaluation["fix_coverage"]["fixed"] == ["CVE-2021-44228"]
    assert clean.evaluation["version_change"] == {"direction": "UPGRADE", "major_version_change": False,
                                                  "from": "2.14.1", "to": "2.17.1"}


def test_unobserved_candidates_state_their_missing_evidence__spec_s1_4(world):
    _, by_version = discover(world)
    latest = by_version["2.24.1"]
    assert latest.source_type.value == "EXTERNAL"
    assert latest.evaluation["current_posture"] == {"status": "NOT_OBSERVED_IN_TENANT"}
    limitation_codes = {item["code"] for item in latest.limitations}
    assert {"VULNERABILITY_POSTURE_NOT_OBSERVED", "LIFECYCLE_EVIDENCE_UNAVAILABLE",
            "LICENSE_EVIDENCE_UNAVAILABLE", "MIGRATION_REGRESSION_TESTING_REQUIRED",
            "HISTORY_NOT_EVALUATED", "PLATFORM_EVIDENCE_INCOMPLETE"} <= limitation_codes
    # Zero observed findings is never presented as safe.
    assert "NO_KNOWN_ACTIONABLE_VULNS_CURRENT_SNAPSHOT" not in {r["code"] for r in latest.reasons}


def test_major_version_change_requires_api_verification(world):
    sbom = world.sbom(world.product())
    source = world.component(sbom, "jackson-databind", "1.9.0", ecosystem="maven")
    world.finding(source, "CVE-2026-1", "HIGH")
    world.component(world.sbom(world.product()), "jackson-databind", "2.17.0", ecosystem="maven")
    snap = versions(world)
    src = snap[("jackson-databind", "1.9.0")]
    result = discover_same_family(src, [v for v in snap.values() if v.family_key == src.family_key])
    candidate = result.candidates[0]
    assert candidate.evaluation["version_change"]["major_version_change"] is True
    assert "API_COMPATIBILITY_REQUIRES_VERIFICATION" in {item["code"] for item in candidate.limitations}


def test_license_change_is_a_stated_limitation(world):
    sbom = world.sbom(world.product())
    src_row = world.component(sbom, "libx", "1.0.0", license="MIT")
    world.finding(src_row, "CVE-2026-2", "HIGH")
    world.component(world.sbom(world.product()), "libx", "1.1.0", license="GPL-3.0")
    snap = versions(world)
    src = snap[("libx", "1.0.0")]
    candidate = discover_same_family(src, [v for v in snap.values() if v.family_key == src.family_key]).candidates[0]
    assert candidate.evaluation["license"]["changed"] is True
    assert "LICENSE_CHANGED" in {item["code"] for item in candidate.limitations}


def test_no_candidates_is_explicit(world):
    sbom = world.sbom(world.product())
    lonely = world.component(sbom, "lonely", "1.0")
    world.finding(lonely, "CVE-2026-3", "CRITICAL")
    src = versions(world)[("lonely", "1.0")]
    result = discover_same_family(src, [src])
    assert result.candidates == [] and result.summary()["status"] == "NO_CANDIDATES_FOUND"
