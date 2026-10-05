"""Secure Component Advisor — analytics and observability (spec Step 10).

FR-SCA-024 / US-SCA-17: recommendation outcome counts, tenant-observed reuse,
newly introduced High/Critical components; analytics never change
classification. NFR-SCA-004: the spec's structured events are emitted with
correlation ids.
"""

import logging

import pytest
from sqlalchemy import text

from app.core.context import CurrentContext
from app.core.permissions import ROLE_PERMISSIONS
from app.core.security import get_current_tenant_context
from app.db import SessionLocal
from app.metrics.cache import reset_cache
from app.services.component_advisor import sources
from tests.component_advisor_support import NOW, World, purl_key
from tests.test_vex_scoped_authorization import make_member

BASE = "/api/component-advisor"
LOG4J = purl_key("pkg:maven/log4j-core@2.14.1")
LODASH = purl_key("pkg:npm/lodash@3.10.1")


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
    db.execute(text(
        "INSERT INTO tenants (id, name, slug, external_iam_tenant_id, status, created_at, updated_at) "
        "VALUES (2, 'Other', 'other', 'other', 'ACTIVE', :now, :now) ON CONFLICT (id) DO NOTHING"), {"now": NOW})
    world = World(db)
    s1, s2 = world.sbom(world.product(name="app-1")), world.sbom(world.product(name="app-2"))
    log4j = world.component(s1, "log4j-core", "2.14.1", ecosystem="maven", license="Apache-2.0", created_on="2026-09-15T00:00:00Z")
    world.finding(log4j, "CVE-2021-44228", "CRITICAL")
    world.component(s2, "log4j-core", "2.17.1", ecosystem="maven", license="Apache-2.0", lifecycle_status="Supported")
    world.component(s2, "lodash", "3.10.1", lifecycle_status="EOL")
    db.commit()
    yield
    reset_cache()


def decide(client, item, decision, **extra):
    body = {"decision": decision, "reason": "test", "row_version": item["row_version"], **extra}
    response = client.post(f"{BASE}/recommendations/{item['id']}/decisions", json=body)
    assert response.status_code == 200, response.text
    return response.json()


def test_analytics_count_outcomes_and_tenant_observed_reuse__FR_SCA_024(client, seeded):
    item = client.post(f"{BASE}/recommendations", json={"canonical_key": LOG4J, "trigger_type": "CRITICAL_FINDING"}).json()
    clean = next(c for c in item["candidates"] if c["version"] == "2.17.1")
    item = decide(client, item, "RECOMMEND", candidate_id=clean["id"])
    decide(client, item, "ACCEPT")
    other = client.post(f"{BASE}/recommendations", json={"canonical_key": LODASH, "trigger_type": "EOL"}).json()
    decide(client, decide(client, other, "REQUEST_MORE_EVIDENCE"), "REJECT")

    body = client.get(f"{BASE}/analytics").json()
    assert body["analytical_only"] is True and body["window"]["months"] == 12
    assert body["recommendations"] | {"by_trigger": None} == {
        "generated": 2, "recommended": 1, "accepted": 1, "rejected": 1, "deferred": 0,
        "more_evidence_requested": 1, "closed": 0, "by_trigger": None,
    }
    assert body["recommendations"]["by_trigger"] == {"CRITICAL_FINDING": 1, "EOL": 1}
    assert body["tenant_observed_reuse"] == {
        "accepted_total": 1, "accepted_tenant_observed": 1, "accepted_external": 0, "accepted_manual": 0,
        "tenant_observed_share": 1.0,
    }


def test_new_high_critical_series_by_first_seen_month__US_SCA_17(client, seeded):
    body = client.get(f"{BASE}/analytics", params={"months": 3}).json()["new_high_critical_components"]
    months = {point["month"]: point for point in body["series"]}
    assert len(months) == 3
    assert months["2026-09"]["critical"] == 1 and months["2026-09"]["high"] == 0
    assert body["current_high_critical_versions"] == 1


def test_analytics_never_change_classification__US_SCA_17(client, seeded):
    before = client.get(f"{BASE}/summary").json()["by_classification"]
    client.get(f"{BASE}/analytics")
    assert client.get(f"{BASE}/summary").json()["by_classification"] == before


def test_analytics_are_tenant_isolated__FR_SCA_023(client, seeded):
    client.post(f"{BASE}/recommendations", json={"canonical_key": LOG4J, "trigger_type": "CRITICAL_FINDING"})
    with SessionLocal() as session:
        user_id = make_member(session, "TENANT_ADMIN", tenant_id=2).user_id
    client.app.dependency_overrides[get_current_tenant_context] = lambda: CurrentContext(
        user_id=user_id, external_user_id=str(user_id), email=None, display_name="b", tenant_id=2,
        external_tenant_id="2", roles=frozenset({"TENANT_ADMIN"}), permissions=ROLE_PERMISSIONS["TENANT_ADMIN"],
    )
    try:
        body = client.get(f"{BASE}/analytics").json()
        assert body["recommendations"]["generated"] == 0
        assert body["new_high_critical_components"]["current_high_critical_versions"] == 0
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)


def test_structured_events_cover_the_recommendation_lifecycle__NFR_SCA_004(client, seeded, caplog):
    caplog.set_level(logging.INFO)
    client.get(f"{BASE}/summary")
    response = client.post(f"{BASE}/recommendations", headers={"X-Request-ID": "obs-corr-1"},
                           json={"canonical_key": LOG4J, "trigger_type": "CRITICAL_FINDING"})
    item = response.json()
    clean = next(c for c in item["candidates"] if c["version"] == "2.17.1")
    item = decide(client, item, "RECOMMEND", candidate_id=clean["id"])
    decide(client, item, "ACCEPT")
    events = {record.getMessage(): record for record in caplog.records}
    for name in ("secure_component_advisor.query", "recommendation.created", "recommendation.discovery.started",
                 "recommendation.discovery.completed", "recommendation.compatibility.completed",
                 "recommendation.scoring.completed", "recommendation.reviewed", "recommendation.recommended",
                 "recommendation.accepted"):
        assert name in events, name
    assert getattr(events["recommendation.created"], "correlation_id", None) == "obs-corr-1"
    assert isinstance(getattr(events["recommendation.scoring.completed"], "duration_ms", None), float)
    # No component names, purls or reasons in the structured fields (NFR-SCA-004).
    assert "log4j" not in str(vars(events["recommendation.accepted"])).lower()
