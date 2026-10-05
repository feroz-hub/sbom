"""Secure Component Advisor — scoring, confidence, history and evidence over HTTP (spec Step 7).

FR-SCA-016..020. End-to-end through evaluation: every candidate is scored
with a persisted factor breakdown and policy version (T29), carries history
with coverage (T30), a confidence level and an explanation; a blocked
candidate never outranks an unblocked one whatever its score (T24/T25 via
FR-SCA-015); the NVD mirror contributes history when enabled.
"""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select, text

from app.db import SessionLocal
from app.metrics.cache import reset_cache
from app.models import ComponentRecommendationFactor
from app.services.component_advisor import sources
from tests.component_advisor_support import NOW, World, purl_key

BASE = "/api/component-advisor"
LOG4J = purl_key("pkg:maven/log4j-core@2.14.1")


@pytest.fixture()
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(autouse=True)
def no_external_sources():
    sources.clear_sources()
    yield
    sources.clear_sources()


@pytest.fixture()
def seeded(db):
    reset_cache()
    world = World(db)
    products = [world.product(name=f"app-{i}") for i in range(3)]
    s1, s2, s3 = (world.sbom(p) for p in products)
    source = world.component(s1, "log4j-core", "2.14.1", ecosystem="maven", license="Apache-2.0",
                             cpe="cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                             primary_cpe="cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
    world.finding(source, "CVE-2021-44228", "CRITICAL", score=10.0)
    world.component(s2, "log4j-core", "2.17.1", ecosystem="maven", license="EPL-1.0", lifecycle_status="Supported")
    world.component(s3, "log4j-core", "2.17.1", ecosystem="maven", license="EPL-1.0", lifecycle_status="Supported")
    high = world.component(s3, "log4j-core", "2.16.0", ecosystem="maven", license="Apache-2.0", lifecycle_status="Supported")
    world.finding(high, "CVE-2021-45105", "HIGH")
    db.commit()
    yield
    reset_cache()


def evaluate(client):
    response = client.post(f"{BASE}/recommendations", json={"canonical_key": LOG4J, "trigger_type": "CRITICAL_FINDING"})
    assert response.status_code == 201, response.text
    return response.json()


def publish(client, kind, rules, row_version=0):
    response = client.post(f"{BASE}/policies/{kind}/versions",
                           json={"status": "ACTIVE", "rules": rules, "reason": "test", "row_version": row_version})
    assert response.status_code == 201, response.text
    return response.json()


def test_T29_candidates_carry_score_factors_and_policy_version__FR_SCA_017(client, seeded, db):
    item = evaluate(client)
    top = item["candidates"][0]
    assert isinstance(top["score"], float) and top["confidence"] in {"HIGH", "MEDIUM", "LOW", "INSUFFICIENT_EVIDENCE"}
    evidence = client.get(f"{BASE}/recommendations/{item['id']}/candidates/{top['id']}/evidence").json()
    assert evidence["score_semantics"] == "ORDERS_CANDIDATES_ONLY"
    assert len(evidence["factors"]) == 8
    assert {f["policy_version_label"] for f in evidence["factors"]} == {"builtin-default-2026-10-01"}
    assert evidence["scoring_policy"]["rules"]["weights"]["current_risk"] == 0.30
    assert evidence["explanation"]["generated_from"] == "STRUCTURED_EVIDENCE"
    assert db.scalar(select(text("count(*)")).select_from(ComponentRecommendationFactor)) == 8 * len(item["candidates"])


def test_T29_tenant_scoring_policy_is_used_and_traceable__FR_SCA_017(client, seeded):
    version = publish(client, "scoring", {"weights": {"tenant_adoption": 1.0}})["version"]
    item = evaluate(client)
    evidence = client.get(f"{BASE}/recommendations/{item['id']}/candidates/{item['candidates'][0]['id']}/evidence").json()
    assert {f["policy_version_id"] for f in evidence["factors"]} == {version["id"]}
    assert item["discovery"]["scoring_policy"]["policy_version_id"] == version["id"]


def test_score_never_lifts_a_blocked_candidate__FR_SCA_015(client, seeded):
    unblocked = evaluate(client)
    by_version = {c["version"]: c for c in unblocked["candidates"]}
    assert by_version["2.17.1"]["score"] > by_version["2.16.0"]["score"]
    assert [c["version"] for c in unblocked["candidates"]][:2] == ["2.17.1", "2.16.0"]

    publish(client, "trust", {"allowed_classifications": ["NO_KNOWN_ACTIONABLE_VULNERABILITIES", "LOW", "MEDIUM"],
                              "allowed_lifecycle": ["SUPPORTED"], "denied_licenses": ["EPL-1.0"]})
    reevaluated = client.post(f"{BASE}/recommendations/{unblocked['id']}/evaluate").json()
    order = [(c["version"], c["blocked"]) for c in reevaluated["candidates"] if c["candidate_kind"] == "SAME_FAMILY_VERSION"]
    blocked_positions = [i for i, (_, blocked) in enumerate(order) if blocked]
    unblocked_positions = [i for i, (_, blocked) in enumerate(order) if not blocked]
    assert ("2.17.1", True) in order
    assert max(unblocked_positions) < min(blocked_positions)


def test_T30_source_and_candidate_history_with_coverage__FR_SCA_016(client, seeded):
    item = evaluate(client)
    source_history = item["discovery"]["source_history"]
    assert source_history["window_months"] == 24
    assert source_history["disclosed_vulnerability_count"] == 1
    assert {s["source"] for s in source_history["coverage"]["sources"]} == {"TENANT_ANALYSIS", "NVD_MIRROR"}
    clean = next(c for c in item["candidates"] if c["version"] == "2.17.1")
    assert clean["history"]["status"] == "NO_VULNERABILITIES_IN_COVERED_WINDOW"
    assert clean["history"]["note"].endswith("not proof of security")
    unobserved = [c for c in item["candidates"] if c["source_type"] == "EXTERNAL"]
    for candidate in unobserved:
        assert candidate["history"]["status"] == "NO_HISTORY_COVERAGE"
        assert "HISTORY_COVERAGE_UNAVAILABLE" in {item["code"] for item in candidate["limitations"]}


def test_T30_nvd_mirror_history_when_enabled__FR_SCA_016(client, seeded, monkeypatch):
    from app.nvd_mirror import settings as mirror_settings
    from app.nvd_mirror.adapters import cve_repository

    monkeypatch.setattr(mirror_settings, "load_mirror_settings_from_env", lambda: SimpleNamespace(enabled=True))
    seen = []

    def fake_find_by_cpe(self, cpe23):
        seen.append(cpe23)
        published = datetime.now(UTC) - timedelta(days=60)
        return [SimpleNamespace(cve_id="CVE-2026-7777", published=published, score_v40=None, score_v31=9.8,
                                score_v2=None, severity_text=None)] if ":2.14.1:" in cpe23 else []

    monkeypatch.setattr(cve_repository.SqlAlchemyCveRepository, "find_by_cpe", fake_find_by_cpe)
    item = evaluate(client)
    history = item["discovery"]["source_history"]
    assert {s["source"]: s["status"] for s in history["coverage"]["sources"]}["NVD_MIRROR"] == "AVAILABLE"
    assert history["disclosed_vulnerability_count"] == 2  # tenant CVE-2021-44228 + mirror CVE-2026-7777
    assert history["coverage"]["covered_months"] >= 23.5
    # Same-family candidates are looked up by the source CPE with their own version.
    assert "cpe:2.3:a:apache:log4j:2.17.1:*:*:*:*:*:*:*" in seen


def test_confidence_and_freshness_are_explained__FR_SCA_019_020(client, seeded):
    item = evaluate(client)
    evidence = client.get(f"{BASE}/recommendations/{item['id']}/candidates/{item['candidates'][0]['id']}/evidence").json()
    basis = evidence["confidence_basis"]
    assert {"level", "completeness", "unknown_material_checks", "stale_flags", "drop_in_representable"} <= set(basis)
    assert basis["drop_in_representable"] is False
    freshness = evidence["freshness"]
    assert {"latest_sbom_analysis_at", "vulnerability_source_refreshed_at", "lifecycle_refreshed_at",
            "tenant_observation_at", "observation_window", "stale_flags"} <= set(freshness)
    assert evidence["approved_replacement"] is False


def test_unobserved_candidates_are_lower_confidence_than_observed__FR_SCA_019(client, seeded):
    item = evaluate(client)
    levels = ("INSUFFICIENT_EVIDENCE", "LOW", "MEDIUM", "HIGH")
    observed = [c for c in item["candidates"] if c["source_type"] == "TENANT_OBSERVED"]
    unobserved = [c for c in item["candidates"] if c["source_type"] != "TENANT_OBSERVED"]
    if unobserved:
        assert max(levels.index(c["confidence"]) for c in unobserved) <= min(levels.index(c["confidence"]) for c in observed)


def test_summary_meta_reports_vulnerability_source_freshness__FR_SCA_020(client, seeded):
    meta = client.get(f"{BASE}/summary").json()["meta"]
    assert "vulnerability_source_refreshed_at" in meta["freshness"]
