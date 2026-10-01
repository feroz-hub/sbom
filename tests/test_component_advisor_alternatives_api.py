"""Secure Component Advisor — alternatives and compatibility over HTTP (spec Step 6).

FR-SCA-012/014/015, NFR-SCA-003, US-SCA-10. End-to-end: evaluation persists
same-family and alternative candidates with all fourteen compatibility
checks; blocked candidates are ranked last and never approved; manual
candidates go through the same gates; a failing external adapter degrades
the recommendation without breaking it or core SBOM viewing.
"""

from datetime import UTC, datetime

import pytest
from sqlalchemy import text

from app.core.context import CurrentContext
from app.core.permissions import ROLE_PERMISSIONS
from app.core.security import get_current_tenant_context
from app.db import SessionLocal
from app.metrics.cache import reset_cache
from app.models import ComponentPurposeMetadata
from app.services.component_advisor import sources
from tests.component_advisor_support import NOW, World, purl_key
from tests.test_vex_scoped_authorization import make_member

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
    db.execute(
        text(
            "INSERT INTO tenants (id, name, slug, external_iam_tenant_id, status, created_at, updated_at) "
            "VALUES (2, 'Other', 'other', 'other', 'ACTIVE', :now, :now) ON CONFLICT (id) DO NOTHING"
        ),
        {"now": NOW},
    )
    world = World(db)
    p1, p2 = world.product(name="app-1"), world.product(name="app-2")
    s1, s2 = world.sbom(p1), world.sbom(p2)
    world.finding(world.component(s1, "log4j-core", "2.14.1", ecosystem="maven", license="Apache-2.0"),
                  "CVE-2021-44228", "CRITICAL")
    world.component(s2, "log4j-core", "2.17.1", ecosystem="maven", license="Apache-2.0", lifecycle_status="Supported")
    world.component(s1, "logback-classic", "1.4.14", ecosystem="maven", license="EPL-1.0", lifecycle_status="Supported")
    world.component(s2, "logback-classic", "1.4.14", ecosystem="maven", license="EPL-1.0", lifecycle_status="Supported")
    world.component(s2, "pdfbox", "3.0.1", ecosystem="maven", license="Apache-2.0", lifecycle_status="Supported")
    other = world.sbom(world.product(tenant_id=2, name="other"))
    world.component(other, "tinylog", "2.7.0", ecosystem="maven", lifecycle_status="Supported")
    now = datetime.now(UTC)
    for tenant_id, family, category in ((1, "maven:log4j-core", "logging"), (1, "maven:logback-classic", "logging"),
                                        (1, "maven:pdfbox", "pdf"), (2, "maven:tinylog", "logging")):
        db.add(ComponentPurposeMetadata(tenant_id=tenant_id, family_key=family, source="CURATED", category=category,
                                        confidence="HIGH", created_at=now, updated_at=now))
    db.commit()
    yield
    reset_cache()


def evaluate(client):
    response = client.post(f"{BASE}/recommendations", json={"canonical_key": LOG4J, "trigger_type": "CRITICAL_FINDING"})
    assert response.status_code == 201, response.text
    return response.json()


def as_role(client, role, tenant_id=1):
    with SessionLocal() as session:
        user_id = make_member(session, role, tenant_id=tenant_id).user_id
    client.app.dependency_overrides[get_current_tenant_context] = lambda: CurrentContext(
        user_id=user_id, external_user_id=str(user_id), email=None, display_name=role, tenant_id=tenant_id,
        external_tenant_id=str(tenant_id), roles=frozenset({role}), permissions=ROLE_PERMISSIONS[role],
    )


@pytest.fixture()
def reset_overrides(client):
    yield
    client.app.dependency_overrides.pop(get_current_tenant_context, None)


def test_same_family_versions_come_before_alternatives__T21_T22(client, seeded):
    item = evaluate(client)
    kinds = [(c["candidate_kind"], c["name"], c["version"]) for c in item["candidates"]]
    assert kinds == [("SAME_FAMILY_VERSION", "log4j-core", "2.17.1"), ("ALTERNATIVE", "logback-classic", "1.4.14")]
    discovery = item["discovery"]
    assert discovery["alternatives_status"] == "EVALUATED"
    assert discovery["alternative_category"] == "logging"
    assert discovery["product_constraints"]["ecosystems"] == ["maven"]
    assert {"family_key": "maven:pdfbox", "reason": "PURPOSE_MISMATCH", "category": "pdf"} in discovery["excluded"]
    # Another tenant's logging library is never proposed (FR-SCA-023).
    assert "tinylog" not in [c["name"] for c in item["candidates"]]


def test_every_candidate_has_fourteen_persisted_checks__FR_SCA_014(client, seeded):
    item = evaluate(client)
    for candidate in item["candidates"]:
        detail = client.get(f"{BASE}/recommendations/{item['id']}/candidates/{candidate['id']}").json()
        assert len(detail["compatibility_checks"]) == 14
        compat = client.get(f"{BASE}/recommendations/{item['id']}/candidates/{candidate['id']}/compatibility").json()
        assert compat["summary"]["status"] in {"PASS", "REVIEW_REQUIRED", "BLOCKED"}
        assert compat["summary"]["drop_in_representable"] is False
        assert {i["check_type"] for i in compat["items"]} >= {"LICENSE", "LIFECYCLE", "FUNCTIONAL_PURPOSE", "API_COMPATIBILITY"}


def test_T24_denied_license_blocks_and_ranks_last_and_is_never_approved__FR_SCA_015(client, seeded):
    publish = client.post(f"{BASE}/policies/trust/versions", json={
        "status": "ACTIVE", "reason": "license policy", "row_version": 0,
        "rules": {"allowed_classifications": ["NO_KNOWN_ACTIONABLE_VULNERABILITIES"],
                  "allowed_lifecycle": ["SUPPORTED"], "denied_licenses": ["EPL-1.0"]},
    })
    assert publish.status_code == 201, publish.text
    item = evaluate(client)
    logback = next(c for c in item["candidates"] if c["name"] == "logback-classic")
    assert logback["blocked"] is True and logback["approved_replacement"] is False
    assert "LICENSE" in logback["compatibility"]["blocking_checks"]
    assert item["discovery"]["blocked_candidates"] == 1


def test_T25_manual_candidate_with_known_api_break_is_blocked__FR_SCA_015(client, seeded):
    item = evaluate(client)
    response = client.post(f"{BASE}/recommendations/{item['id']}/candidates", json={
        "name": "log4j-core", "version": "3.0.0-beta1", "ecosystem": "maven", "rationale": "next major",
        "compatibility_evidence": {"known_breaking_api": True},
    })
    assert response.status_code == 201, response.text
    manual = next(c for c in response.json()["candidates"] if c["source_type"] == "MANUAL")
    assert manual["candidate_kind"] == "SAME_FAMILY_VERSION"
    assert manual["blocked"] is True and "API_COMPATIBILITY" in manual["compatibility"]["blocking_checks"]
    assert manual["reasons"][0] == {"code": "REVIEWER_PROPOSED", "detail": "next major"}


def test_manual_candidates_survive_re_evaluation(client, seeded):
    item = evaluate(client)
    client.post(f"{BASE}/recommendations/{item['id']}/candidates", json={
        "name": "slf4j-simple", "version": "2.0.9", "ecosystem": "maven", "rationale": "team standard",
        "technology_category": "logging", "licenses": ["MIT"], "lifecycle_status": "Supported",
    })
    again = client.post(f"{BASE}/recommendations/{item['id']}/evaluate").json()
    manual = [c for c in again["candidates"] if c["source_type"] == "MANUAL"]
    assert [c["name"] for c in manual] == ["slf4j-simple"]
    assert again["discovery"]["manual_candidates"] == 1
    assert manual[0]["evaluation"]["purpose"]["technology_category"]["provenance"]["rationale"] == "team standard"


def test_manual_candidate_requires_review_permission_and_review_state(client, seeded, db, reset_overrides):
    item = evaluate(client)
    payload = {"name": "x", "version": "1", "rationale": "r"}
    as_role(client, "DEVELOPER")
    assert client.post(f"{BASE}/recommendations/{item['id']}/candidates", json=payload).status_code == 403
    as_role(client, "SECURITY_ANALYST")
    assert client.post(f"{BASE}/recommendations/{item['id']}/candidates", json=payload).status_code == 201
    db.execute(text("UPDATE component_recommendation SET status = 'REJECTED' WHERE id = :id"), {"id": item["id"]})
    db.commit()
    assert client.post(f"{BASE}/recommendations/{item['id']}/candidates", json=payload).status_code == 409


def test_candidate_endpoints_are_tenant_isolated__FR_SCA_023(client, seeded, reset_overrides):
    item = evaluate(client)
    candidate_id = item["candidates"][0]["id"]
    as_role(client, "TENANT_ADMIN", tenant_id=2)
    assert client.get(f"{BASE}/recommendations/{item['id']}/candidates/{candidate_id}").status_code == 404
    assert client.get(f"{BASE}/recommendations/{item['id']}/candidates/{candidate_id}/compatibility").status_code == 404
    assert client.post(f"{BASE}/recommendations/{item['id']}/candidates",
                       json={"name": "x", "rationale": "r"}).status_code == 404


class _DownSource:
    name = "down-registry"

    def find_alternatives(self, **_kwargs):
        raise ConnectionError("registry unreachable")


def test_external_source_failure_degrades_without_breaking_anything__NFR_SCA_003(client, seeded):
    sources.register_source(_DownSource())
    item = evaluate(client)
    assert item["status"] == "REVIEW_REQUIRED" and item["evaluation_error"] is None
    assert item["discovery"]["alternatives_status"] == "EVALUATED_EXTERNAL_SOURCE_DEGRADED"
    assert item["discovery"]["external_sources"][0] == {
        "source": "down-registry", "outcome": "error", "candidates": 0, "error": "ConnectionError",
        "latency_ms": item["discovery"]["external_sources"][0]["latency_ms"],
    }
    assert [c["name"] for c in item["candidates"]] == ["log4j-core", "logback-classic"]
    # Core SBOM viewing is unaffected.
    assert client.get("/api/sboms").status_code == 200
    assert client.get(f"{BASE}/summary").status_code == 200
