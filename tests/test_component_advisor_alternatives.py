"""Secure Component Advisor — alternative discovery and compatibility gates (spec Step 6).

FR-SCA-012, FR-SCA-014, FR-SCA-015, NFR-SCA-003. Prompt §10:
T22 (tenant-observed candidate includes adoption evidence), T23 (zero findings
but incompatible purpose is rejected), T24 (incompatible license cannot be
overridden), T25 (unsupported platform / API break cannot be overridden),
T26 (EOL candidate follows lifecycle policy).
"""

import time
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import ComponentPurposeMetadata, Tenant
from app.services.component_advisor import sources
from app.services.component_advisor.intelligence_service import build_snapshot
from app.services.component_advisor.lifecycle_mapping import LifecycleBucket
from app.services.component_advisor.policy import PolicyKind, PolicyStatus, PolicyVersionRef, validate_trust_rules
from app.services.component_advisor.recommendations.alternative_discovery import (
    discover_alternatives,
    manual_candidate,
    product_constraints,
)
from app.services.component_advisor.recommendations.compatibility import (
    CHECK_TYPES,
    CandidateFacts,
    CompatibilityEvidence,
    ProductConstraints,
    evaluate_compatibility,
    summarize,
)
from app.services.component_advisor.recommendations.workflow import CandidateKind
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


@pytest.fixture(autouse=True)
def no_external_sources():
    sources.clear_sources()
    yield
    sources.clear_sources()


def curate(world, family_key, category):
    now = datetime.now(UTC)
    world.db.add(ComponentPurposeMetadata(tenant_id=1, family_key=family_key, source="CURATED", category=category,
                                          confidence="HIGH", created_at=now, updated_at=now))
    world.db.flush()


def logging_world(world):
    """log4j-core CRITICAL (logging) in 2 products; logback clean (logging) in 2; pdfbox clean (pdf)."""
    p1, p2, p3 = world.product(), world.product(), world.product()
    s1, s2, s3 = world.sbom(p1), world.sbom(p2), world.sbom(p3)
    for s in (s1, s2):
        world.finding(world.component(s, "log4j-core", "2.14.1", ecosystem="maven", license="Apache-2.0"),
                      "CVE-2021-44228", "CRITICAL")
    world.component(s1, "logback-classic", "1.4.14", ecosystem="maven", license="EPL-1.0", lifecycle_status="Supported")
    world.component(s3, "logback-classic", "1.4.14", ecosystem="maven", license="EPL-1.0", lifecycle_status="Supported")
    world.component(s2, "pdfbox", "3.0.1", ecosystem="maven", license="Apache-2.0", lifecycle_status="Supported")
    world.component(s3, "winston", "3.11.0", ecosystem="npm", license="MIT", lifecycle_status="Supported")
    for family, category in (("maven:log4j-core", "logging"), ("maven:logback-classic", "logging"),
                             ("maven:pdfbox", "pdf"), ("npm:winston", "logging")):
        curate(world, family, category)
    snap = build_snapshot(world.db, DashboardScope(1)).versions
    return next(v for v in snap if v.name == "log4j-core"), snap


def trust(rules, version_id=5):
    return PolicyVersionRef(version_id, 1, PolicyKind.TRUST, 1, PolicyStatus.ACTIVE, "TENANT", validate_trust_rules(rules))


def facts(**overrides):
    base = dict(kind=CandidateKind.ALTERNATIVE, name="alt", version="1.0", ecosystem="maven", family_key="maven:alt",
                observed=True, purpose=None, licenses=("Apache-2.0",), lifecycle=LifecycleBucket.SUPPORTED,
                major_version_change=None)
    base.update(overrides)
    return CandidateFacts(**base)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def test_T22_tenant_observed_alternative_includes_adoption_evidence__FR_SCA_012(world):
    source, versions = logging_world(world)
    result = discover_alternatives(source, versions, constraints=product_constraints(source, versions))
    assert result.status == "EVALUATED"
    assert [c.name for c in result.candidates] == ["logback-classic"]
    alt = result.candidates[0]
    assert alt.source_type.value == "TENANT_OBSERVED" and alt.kind.value == "ALTERNATIVE"
    reasons = {r["code"]: r for r in alt.reasons}
    assert reasons["FOUND_IN_N_ACTIVE_TENANT_SBOMS"]["count"] == 2
    assert reasons["USED_BY_N_TENANT_PRODUCTS"]["count"] == 2
    assert "SIMILAR_PURPOSE" in reasons and "SAME_ECOSYSTEM" in reasons
    assert alt.evaluation["adoption"]["interpretation"] == "CONTEXTUAL_EVIDENCE_NOT_PROOF"
    assert "MIGRATION_REQUIRED" in {item["code"] for item in alt.limitations}


def test_T23_clean_component_with_a_different_purpose_is_rejected__FR_SCA_012(world):
    source, versions = logging_world(world)
    result = discover_alternatives(source, versions, constraints=product_constraints(source, versions))
    assert "pdfbox" not in [c.name for c in result.candidates]
    assert {"family_key": "maven:pdfbox", "reason": "PURPOSE_MISMATCH", "category": "pdf"} in result.excluded
    # Different ecosystem never qualifies either, even with the same purpose.
    assert "winston" not in [c.name for c in result.candidates]


def test_T23_manual_candidate_without_purpose_fails_a_blocking_purpose_check(world):
    source, versions = logging_world(world)
    candidate = manual_candidate(source, {"name": "mystery", "version": "1.0", "rationale": "looks clean"},
                                 versions, actor="reviewer@test")
    checks = {c.check_type: c for c in evaluate_compatibility(source, candidate.facts, constraints=product_constraints(source, versions))}
    assert checks["FUNCTIONAL_PURPOSE"].result.value == "FAIL" and checks["FUNCTIONAL_PURPOSE"].blocking


@pytest.mark.parametrize(
    ("setup", "status"),
    [("no_purpose", "INSUFFICIENT_PURPOSE_EVIDENCE"), ("generic", "INSUFFICIENT_ECOSYSTEM_EVIDENCE"),
     ("no_constraints", "PRODUCT_CONSTRAINTS_UNAVAILABLE")],
)
def test_alternatives_only_when_ecosystem_purpose_and_constraints_are_established__FR_SCA_012(world, setup, status):
    sbom = world.sbom(world.product())
    ecosystem = "generic" if setup == "generic" else "maven"
    world.finding(world.component(sbom, "lib", "1.0", ecosystem=ecosystem), "CVE-2026-1", "HIGH")
    if setup != "no_purpose":
        curate(world, f"{ecosystem}:lib", "logging")
    versions = build_snapshot(world.db, DashboardScope(1)).versions
    source = versions[0]
    constraints = ProductConstraints(established=False) if setup == "no_constraints" else product_constraints(source, versions)
    result = discover_alternatives(source, versions, constraints=constraints)
    assert result.status == status and result.candidates == []


def test_product_constraints_come_from_the_products_using_the_source(world):
    source, versions = logging_world(world)
    constraints = product_constraints(source, versions)
    # log4j is in products 1 and 2; winston (npm) is only in product 3.
    assert constraints.established and constraints.ecosystems == frozenset({"maven"})


# ---------------------------------------------------------------------------
# External adapters (NFR-SCA-003)
# ---------------------------------------------------------------------------


class FakeSource:
    def __init__(self, name, behaviour):
        self.name, self.behaviour, self.calls = name, behaviour, 0

    def find_alternatives(self, *, ecosystem, category, purpose_text):
        self.calls += 1
        if self.behaviour == "raise":
            raise ConnectionError("down")
        if self.behaviour == "slow":
            time.sleep(0.5)
        return [
            sources.ExternalCandidate(name="tinylog", version="2.7.0", ecosystem="maven", licenses=("Apache-2.0",),
                                      purpose={"technology_category": "logging", "confidence": "HIGH"},
                                      lifecycle_status="Supported", provenance={"retrieved_at": "2026-10-01"}),
            sources.ExternalCandidate(name="itext", version="8", ecosystem="maven",
                                      purpose={"technology_category": "pdf"}),
        ]


def test_external_adapter_candidates_are_gated_like_any_other(world):
    sources.register_source(FakeSource("fake-registry", "ok"))
    source, versions = logging_world(world)
    result = discover_alternatives(source, versions, constraints=product_constraints(source, versions))
    external = [c for c in result.candidates if c.source_type.value == "EXTERNAL"]
    assert [c.name for c in external] == ["tinylog"]
    assert external[0].evaluation["current_posture"] == {"status": "NOT_OBSERVED_IN_TENANT"}
    assert external[0].evaluation["purpose"]["technology_category"]["source"] == "PACKAGE"
    assert {"name": "itext", "source": "fake-registry", "reason": "PURPOSE_OR_ECOSYSTEM_MISMATCH"} in result.excluded


@pytest.mark.parametrize("behaviour", ["raise", "slow"])
def test_failing_adapter_degrades_but_never_breaks_discovery__NFR_SCA_003(world, behaviour):
    sources.register_source(FakeSource("flaky", behaviour))
    source, versions = logging_world(world)
    query = (lambda **kw: sources.query_sources(**kw, timeout=0.05)) if behaviour == "slow" else sources.query_sources
    result = discover_alternatives(source, versions, constraints=product_constraints(source, versions), external_query=query)
    assert result.status.endswith("_EXTERNAL_SOURCE_DEGRADED")
    assert [c.name for c in result.candidates] == ["logback-classic"]  # tenant-observed still delivered
    assert result.external_sources[0]["outcome"] == "error"


def test_circuit_breaker_stops_calling_a_failing_adapter():
    flaky = FakeSource("flaky", "raise")
    sources.register_source(flaky)
    outcomes = [sources.query_sources(ecosystem="maven", category="logging", purpose_text=None)[0].outcome.value for _ in range(5)]
    assert outcomes[:3] == ["error"] * 3 and outcomes[3:] == ["circuit_open"] * 2
    assert flaky.calls == 3


# ---------------------------------------------------------------------------
# Compatibility gates (T24–T26)
# ---------------------------------------------------------------------------


def test_every_candidate_gets_all_fourteen_checks__FR_SCA_014(world):
    source, versions = logging_world(world)
    alt = discover_alternatives(source, versions, constraints=product_constraints(source, versions)).candidates[0]
    checks = evaluate_compatibility(source, alt.facts, constraints=product_constraints(source, versions))
    assert [c.check_type for c in checks] == list(CHECK_TYPES)
    assert all(c.result.value in {"PASS", "FAIL", "REVIEW_REQUIRED", "UNKNOWN"} for c in checks)
    assert all(c.reason and c.evaluated_at for c in checks)
    by_type = {c.check_type: c for c in checks}
    assert by_type["FUNCTIONAL_PURPOSE"].result.value == "PASS"
    assert by_type["API_COMPATIBILITY"].result.value == "REVIEW_REQUIRED"
    assert by_type["TRANSITIVE_DEPENDENCIES"].result.value == "UNKNOWN"
    assert summarize(checks)["drop_in_representable"] is False


def test_T24_incompatible_license_blocks_the_candidate__FR_SCA_015(world):
    source, versions = logging_world(world)
    policy = trust({"allowed_classifications": ["NO_KNOWN_ACTIONABLE_VULNERABILITIES"], "allowed_lifecycle": ["SUPPORTED"],
                    "denied_licenses": ["EPL-1.0"]})
    alt = discover_alternatives(source, versions, constraints=product_constraints(source, versions)).candidates[0]
    checks = evaluate_compatibility(source, alt.facts, constraints=product_constraints(source, versions), trust_policy=policy)
    license_check = next(c for c in checks if c.check_type == "LICENSE")
    assert license_check.result.value == "FAIL" and license_check.blocking
    assert license_check.evidence["policy_version_id"] == 5
    summary = summarize(checks)
    assert summary["blocked"] and "LICENSE" in summary["blocking_checks"]


def test_allowed_license_list_also_blocks_unlisted_licenses():
    policy = trust({"allowed_classifications": ["LOW"], "allowed_lifecycle": ["SUPPORTED"], "allowed_licenses": ["MIT"]})
    source = type("S", (), {"ecosystem": "maven", "purpose": None, "licenses": ["MIT"]})()
    checks = evaluate_compatibility(source, facts(kind=CandidateKind.SAME_FAMILY_VERSION, licenses=("GPL-3.0",)),
                                    constraints=ProductConstraints(True, frozenset({"maven"})), trust_policy=policy)
    assert next(c for c in checks if c.check_type == "LICENSE").blocking


@pytest.mark.parametrize(
    ("evidence", "check_type"),
    [({"known_breaking_api": True}, "API_COMPATIBILITY"), ({"known_breaking_abi": True}, "ABI_COMPATIBILITY"),
     ({"unsupported_runtimes": ["java-8"]}, "RUNTIME"), ({"unsupported_operating_systems": ["windows"]}, "OPERATING_SYSTEM"),
     ({"unsupported_architectures": ["arm64"]}, "CPU_ARCHITECTURE"), ({"regulatory_block": "FDA 524B"}, "REGULATORY")],
)
def test_T25_platform_api_and_regulatory_blocks__FR_SCA_015(evidence, check_type):
    source = type("S", (), {"ecosystem": "maven", "purpose": None, "licenses": ["Apache-2.0"]})()
    constraints = ProductConstraints(True, frozenset({"maven"}), runtimes=frozenset({"java-8"}),
                                     operating_systems=frozenset({"windows"}), architectures=frozenset({"arm64"}))
    checks = evaluate_compatibility(source, facts(kind=CandidateKind.SAME_FAMILY_VERSION,
                                                  evidence=CompatibilityEvidence.from_dict(evidence, source="test")),
                                    constraints=constraints)
    check = next(c for c in checks if c.check_type == check_type)
    assert check.result.value == "FAIL" and check.blocking
    assert summarize(checks)["blocked"]


def test_unsupported_platform_without_known_product_need_is_review_not_block():
    source = type("S", (), {"ecosystem": "maven", "purpose": None, "licenses": []})()
    checks = evaluate_compatibility(source, facts(kind=CandidateKind.SAME_FAMILY_VERSION,
                                                  evidence=CompatibilityEvidence(unsupported_runtimes=("java-8",))),
                                    constraints=ProductConstraints(True, frozenset({"maven"})))
    runtime = next(c for c in checks if c.check_type == "RUNTIME")
    assert runtime.result.value == "REVIEW_REQUIRED" and not runtime.blocking


@pytest.mark.parametrize(
    ("bucket", "policy_lifecycle", "result", "blocking"),
    [(LifecycleBucket.EOL, None, "FAIL", True), (LifecycleBucket.EOS, None, "REVIEW_REQUIRED", False),
     (LifecycleBucket.SUPPORTED, None, "PASS", False), (LifecycleBucket.EOL, ["SUPPORTED", "EOL"], "PASS", False),
     (LifecycleBucket.EOS, ["SUPPORTED"], "FAIL", True), (None, None, "UNKNOWN", False)],
)
def test_T26_eol_candidate_follows_lifecycle_policy__FR_SCA_015(bucket, policy_lifecycle, result, blocking):
    source = type("S", (), {"ecosystem": "maven", "purpose": None, "licenses": []})()
    policy = trust({"allowed_classifications": ["LOW"], "allowed_lifecycle": policy_lifecycle}) if policy_lifecycle else None
    checks = evaluate_compatibility(source, facts(kind=CandidateKind.SAME_FAMILY_VERSION, lifecycle=bucket),
                                    constraints=ProductConstraints(True, frozenset({"maven"})), trust_policy=policy)
    lifecycle = next(c for c in checks if c.check_type == "LIFECYCLE")
    assert (lifecycle.result.value, lifecycle.blocking) == (result, blocking)


@pytest.mark.parametrize(("candidate_eco", "check_type"), [("npm", "PACKAGE_ECOSYSTEM"), ("npm", "LANGUAGE"),
                                                           ("npm", "PRODUCT_CONSTRAINTS")])
def test_cross_ecosystem_candidate_is_blocked(candidate_eco, check_type):
    source = type("S", (), {"ecosystem": "maven", "purpose": None, "licenses": []})()
    checks = evaluate_compatibility(source, facts(ecosystem=candidate_eco),
                                    constraints=ProductConstraints(True, frozenset({"maven"})))
    assert next(c for c in checks if c.check_type == check_type).blocking


def test_missing_evidence_is_unknown_never_pass():
    source = type("S", (), {"ecosystem": "maven", "purpose": None, "licenses": []})()
    checks = {c.check_type: c for c in evaluate_compatibility(
        source, facts(kind=CandidateKind.SAME_FAMILY_VERSION, licenses=None, lifecycle=None),
        constraints=ProductConstraints(False))}
    for check_type in ("LICENSE", "LIFECYCLE", "PRODUCT_CONSTRAINTS", "REGULATORY", "OPERATING_SYSTEM", "SUPPORTED_VERSIONS"):
        assert checks[check_type].result.value == "UNKNOWN", check_type
