"""Secure Component Advisor — human review, audit and isolation (spec Step 8).

FR-SCA-021, FR-SCA-022, FR-SCA-023, NFR-SCA-001, NFR-SCA-007; US-SCA-14..16.
Prompt §10: T31 (unauthorized user cannot accept), T32 (decisions audited),
T33 (accept modifies no dependency / source / SBOM), T34 (audit has actor /
reason / state / correlation), plus the T11/T12 isolation sweep across every
advisor endpoint.
"""

import logging

import pytest
from sqlalchemy import select, text

from app.core.context import CurrentContext
from app.core.permissions import ROLE_PERMISSIONS
from app.core.security import get_current_tenant_context
from app.db import SessionLocal
from app.metrics.cache import reset_cache
from app.models import ComponentRecommendationEvent
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
    products = [world.product(name=f"app-{i}") for i in range(2)]
    s1, s2 = (world.sbom(p) for p in products)
    log4j = world.component(s1, "log4j-core", "2.14.1", ecosystem="maven", license="Apache-2.0",
                            latest_version="2.24.1")
    world.finding(log4j, "CVE-2021-44228", "CRITICAL", score=10.0)
    world.component(s2, "log4j-core", "2.17.1", ecosystem="maven", license="EPL-1.0", lifecycle_status="Supported")
    high = world.component(s2, "log4j-core", "2.16.0", ecosystem="maven", license="Apache-2.0", lifecycle_status="Supported")
    world.finding(high, "CVE-2021-45105", "HIGH")
    world.component(s2, "lodash", "3.10.1", lifecycle_status="EOL")
    other = world.sbom(world.product(tenant_id=2, name="other"))
    world.component(other, "tenant-b-secret-lib", "1.0.0", lifecycle_status="EOL")
    db.commit()
    yield
    reset_cache()


def as_role(client, role, tenant_id=1):
    with SessionLocal() as session:
        member = make_member(session, role, tenant_id=tenant_id)
        user_id, label = member.user_id, f"{role.lower()}-{member.user_id}@test"
    client.app.dependency_overrides[get_current_tenant_context] = lambda: CurrentContext(
        user_id=user_id, external_user_id=label, email=label, display_name=role, tenant_id=tenant_id,
        external_tenant_id=str(tenant_id), roles=frozenset({role}), permissions=ROLE_PERMISSIONS[role],
    )
    return label


@pytest.fixture()
def reset_overrides(client):
    yield
    client.app.dependency_overrides.pop(get_current_tenant_context, None)


def new_item(client, key=LOG4J, trigger="CRITICAL_FINDING"):
    response = client.post(f"{BASE}/recommendations", json={"canonical_key": key, "trigger_type": trigger})
    assert response.status_code == 201, response.text
    return response.json()


def decide(client, item, decision, *, reason="reviewed", candidate_id=None, row_version=None, headers=None):
    body = {"decision": decision, "reason": reason, "row_version": row_version or item["row_version"]}
    if candidate_id is not None:
        body["candidate_id"] = candidate_id
    return client.post(f"{BASE}/recommendations/{item['id']}/decisions", json=body, headers=headers or {})


def candidate(item, version):
    return next(c for c in item["candidates"] if c["version"] == version)


def checksums(db):
    tables = ("sbom_source", "sbom_component", "analysis_run", "analysis_finding", "vex_investigation",
              "vex_statements", "products", "projects")
    return {t: db.execute(text(f"SELECT count(*), coalesce(md5(string_agg(t::text, '|' ORDER BY t::text)), '') FROM {t} t")).one()
            for t in tables}


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------


def test_recommend_then_accept_then_close__FR_SCA_021(client, seeded, reset_overrides):
    as_role(client, "TENANT_ADMIN")
    item = new_item(client)
    clean = candidate(item, "2.17.1")
    recommended = decide(client, item, "RECOMMEND", candidate_id=clean["id"], reason="lowest current risk")
    assert recommended.status_code == 200, recommended.text
    body = recommended.json()
    assert body["status"] == "RECOMMENDED" and body["review"]["recommended_candidate_id"] == clean["id"]
    assert body["capabilities"]["can_accept"] is True
    assert candidate(body, "2.17.1")["approved_replacement"] is False  # not until a human accepts

    accepted = decide(client, body, "ACCEPT", reason="approved by architecture board").json()
    assert accepted["status"] == "ACCEPTED"
    assert accepted["review"]["accepted_candidate_id"] == clean["id"]
    assert accepted["review"]["last_decision_reason"] == "approved by architecture board"
    assert candidate(accepted, "2.17.1")["approved_replacement"] is True
    assert all(not c["approved_replacement"] for c in accepted["candidates"] if c["version"] != "2.17.1")

    closed = decide(client, accepted, "CLOSE", reason="rolled out").json()
    assert closed["status"] == "CLOSED" and candidate(closed, "2.17.1")["approved_replacement"] is True


@pytest.mark.parametrize("decision", ["REJECT", "DEFER"])
def test_reject_and_defer_from_review__FR_SCA_021(client, seeded, decision):
    item = new_item(client)
    response = decide(client, item, decision, reason="not now")
    assert response.status_code == 200
    assert response.json()["status"] == {"REJECT": "REJECTED", "DEFER": "DEFERRED"}[decision]


def test_request_more_evidence_returns_to_review__US_SCA_14(client, seeded):
    item = new_item(client)
    in_review = decide(client, item, "REQUEST_MORE_EVIDENCE", reason="need license review").json()
    assert in_review["status"] == "REVIEW_REQUIRED" and in_review["review"]["last_decision"] == "REQUEST_MORE_EVIDENCE"
    recommended = decide(client, in_review, "RECOMMEND", candidate_id=candidate(in_review, "2.17.1")["id"]).json()
    back = decide(client, recommended, "REQUEST_MORE_EVIDENCE", reason="API change unclear").json()
    assert back["status"] == "REVIEW_REQUIRED" and back["review"]["recommended_candidate_id"] is None
    deferred = decide(client, back, "DEFER", reason="next quarter").json()
    assert decide(client, deferred, "REQUEST_MORE_EVIDENCE", reason="reopen").json()["status"] == "REVIEW_REQUIRED"


def test_accept_requires_a_recommended_candidate_and_only_that_one(client, seeded):
    item = new_item(client)
    assert decide(client, item, "ACCEPT").status_code == 409  # REVIEW_REQUIRED → ACCEPTED is not allowed
    recommended = decide(client, item, "RECOMMEND", candidate_id=candidate(item, "2.17.1")["id"]).json()
    other = decide(client, recommended, "ACCEPT", candidate_id=candidate(recommended, "2.16.0")["id"])
    assert other.status_code == 422 and other.json()["detail"]["code"] == "NOT_RECOMMENDED_CANDIDATE"


def test_blocked_candidate_cannot_be_recommended__FR_SCA_015(client, seeded):
    client.post(f"{BASE}/policies/trust/versions", json={
        "status": "ACTIVE", "reason": "license", "row_version": 0,
        "rules": {"allowed_classifications": ["NO_KNOWN_ACTIONABLE_VULNERABILITIES", "HIGH"][:1],
                  "allowed_lifecycle": ["SUPPORTED"], "denied_licenses": ["EPL-1.0"]}})
    item = new_item(client)
    blocked = candidate(item, "2.17.1")
    assert blocked["blocked"] is True
    response = decide(client, item, "RECOMMEND", candidate_id=blocked["id"])
    assert response.status_code == 422 and response.json()["detail"]["code"] == "CANDIDATE_BLOCKED"


def test_insufficient_evidence_candidate_cannot_be_recommended__FR_SCA_019(client, seeded):
    item = new_item(client)
    unobserved = candidate(item, "2.24.1")
    assert unobserved["confidence"] == "INSUFFICIENT_EVIDENCE"
    response = decide(client, item, "RECOMMEND", candidate_id=unobserved["id"])
    assert response.status_code == 422 and response.json()["detail"]["code"] == "INSUFFICIENT_EVIDENCE"


def test_stale_row_version_and_missing_reason_are_rejected(client, seeded):
    item = new_item(client)
    assert decide(client, item, "DEFER", reason="x").status_code == 200
    stale = decide(client, item, "REJECT", reason="y")
    assert stale.status_code == 409 and stale.json()["detail"]["code"] == "RECOMMENDATION_CONFLICT"
    assert decide(client, item, "REJECT", reason="").status_code == 422


# ---------------------------------------------------------------------------
# Permissions (T31, spec §9)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("role", "recommend", "accept"), [
    ("TENANT_ADMIN", 200, 200), ("SECURITY_ANALYST", 200, 403), ("DEVELOPER", 403, 403), ("VIEWER", 403, 403),
])
def test_T31_only_authorized_roles_decide__FR_SCA_021(client, seeded, reset_overrides, role, recommend, accept):
    as_role(client, "TENANT_ADMIN")
    item = new_item(client)
    clean_id = candidate(item, "2.17.1")["id"]
    as_role(client, role)
    response = decide(client, item, "RECOMMEND", candidate_id=clean_id)
    assert response.status_code == recommend
    as_role(client, "TENANT_ADMIN")
    current = client.get(f"{BASE}/recommendations/{item['id']}").json()
    if current["status"] != "RECOMMENDED":
        current = decide(client, current, "RECOMMEND", candidate_id=clean_id).json()
    as_role(client, role)
    capabilities = client.get(f"{BASE}/recommendations/{item['id']}").json()["capabilities"]
    assert capabilities["can_accept"] is (accept == 200)
    assert decide(client, current, "ACCEPT").status_code == accept


def test_unauthorized_accept_leaves_no_trace(client, seeded, db, reset_overrides):
    as_role(client, "TENANT_ADMIN")
    item = new_item(client)
    item = decide(client, item, "RECOMMEND", candidate_id=candidate(item, "2.17.1")["id"]).json()
    before = db.scalar(select(text("count(*)")).select_from(ComponentRecommendationEvent))
    as_role(client, "SECURITY_ANALYST")
    assert decide(client, item, "ACCEPT").status_code == 403
    assert db.scalar(select(text("count(*)")).select_from(ComponentRecommendationEvent)) == before
    assert client.get(f"{BASE}/recommendations/{item['id']}").json()["status"] == "RECOMMENDED"


# ---------------------------------------------------------------------------
# Audit (T32, T34) and advisory-only (T33)
# ---------------------------------------------------------------------------


def test_T32_every_lifecycle_step_and_decision_is_audited__FR_SCA_022(client, seeded):
    item = new_item(client)
    item = decide(client, item, "REQUEST_MORE_EVIDENCE", reason="more").json()
    item = decide(client, item, "RECOMMEND", candidate_id=candidate(item, "2.17.1")["id"], reason="best").json()
    item = decide(client, item, "ACCEPT", reason="go").json()
    other = decide(client, new_item(client, LODASH, "EOL"), "REJECT", reason="no").json()
    deferred = decide(client, new_item(client, LOG4J, "MANUAL"), "DEFER", reason="later").json()
    actions = [e["action"] for e in client.get(f"{BASE}/recommendations/{item['id']}/events").json()["items"]]
    assert actions[0] == "CREATED"
    assert {"CANDIDATE_DISCOVERED", "COMPATIBILITY_EVALUATED", "CANDIDATE_SCORED", "DISCOVERY_COMPLETED",
            "MOVED_TO_REVIEW", "MORE_EVIDENCE_REQUESTED", "RECOMMENDED", "ACCEPTED"} <= set(actions)
    assert actions.count("CANDIDATE_SCORED") == len(item["candidates"])
    assert "REJECTED" in [e["action"] for e in client.get(f"{BASE}/recommendations/{other['id']}/events").json()["items"]]
    assert "DEFERRED" in [e["action"] for e in client.get(f"{BASE}/recommendations/{deferred['id']}/events").json()["items"]]


def test_T34_decision_events_carry_actor_reason_state_and_correlation__FR_SCA_022(client, seeded, reset_overrides):
    actor = as_role(client, "TENANT_ADMIN")
    item = new_item(client)
    clean = candidate(item, "2.17.1")
    item = decide(client, item, "RECOMMEND", candidate_id=clean["id"], reason="lowest risk",
                  headers={"X-Request-ID": "sca-review-corr-1"}).json()
    events = client.get(f"{BASE}/recommendations/{item['id']}/events").json()["items"]
    event = next(e for e in events if e["action"] == "RECOMMENDED")
    assert event["actor"] == actor and event["actor_user_id"]
    assert event["reason"] == "lowest risk" and event["decision"] == "RECOMMEND"
    assert (event["old_status"], event["new_status"]) == ("REVIEW_REQUIRED", "RECOMMENDED")
    assert event["correlation_id"] == "sca-review-corr-1"
    assert event["candidate"]["id"] == clean["id"] and event["candidate"]["version"] == "2.17.1"
    assert event["score"] == clean["score"] and event["confidence"] == clean["confidence"]
    assert event["policy_versions"]["label"].startswith("builtin-default")
    assert event["evidence_refs"][0]["analysis_run_id"]
    assert event["source"] == "API" and event["created_at"]


def test_T33_accept_modifies_no_dependency_source_or_sbom__spec_s1_1(client, seeded, db):
    item = new_item(client)
    item = decide(client, item, "RECOMMEND", candidate_id=candidate(item, "2.17.1")["id"]).json()
    before = checksums(db)
    accepted = decide(client, item, "ACCEPT", reason="approved")
    assert accepted.status_code == 200
    db.expire_all()
    assert checksums(db) == before
    # The source component still reports its own version and risk.
    assert client.get(f"{BASE}/components/{LOG4J}").json()["risk"]["classification"] == "CRITICAL"


def test_events_are_append_only__NFR_SCA_007(client, seeded, db):
    new_item(client)
    event = db.scalar(select(ComponentRecommendationEvent))
    event.reason = "rewritten"
    with pytest.raises(RuntimeError, match="append-only"):
        db.flush()
    db.rollback()
    db.delete(db.scalar(select(ComponentRecommendationEvent)))
    with pytest.raises(RuntimeError, match="append-only"):
        db.flush()
    db.rollback()


def test_policy_publishes_are_in_the_tenant_audit_history__FR_SCA_022(client, seeded):
    client.post(f"{BASE}/policies/scoring/versions", json={
        "status": "ACTIVE", "reason": "weights review", "row_version": 0, "rules": {"weights": {"current_risk": 1}}})
    events = client.get(f"{BASE}/audit/events", params={"action": "POLICY_VERSION_PUBLISHED"}).json()["items"]
    assert events and events[0]["policy_versions"]["kind"] == "SCORING" and events[0]["reason"] == "weights review"


@pytest.mark.parametrize(("role", "status"), [("TENANT_ADMIN", 200), ("SECURITY_ANALYST", 200),
                                              ("DEVELOPER", 403), ("VIEWER", 403)])
def test_audit_access_respects_authorization__US_SCA_15(client, seeded, reset_overrides, role, status):
    item = new_item(client)
    decide(client, item, "DEFER", reason="later")
    as_role(client, role)
    assert client.get(f"{BASE}/recommendations/{item['id']}/events").status_code == status
    assert client.get(f"{BASE}/audit/events").status_code == status
    # Everyone who can read the item sees the decision summary ("limited" audit).
    review = client.get(f"{BASE}/recommendations/{item['id']}").json()["review"]
    assert review["last_decision"] == "DEFER" and review["last_decision_reason"] == "later"


# ---------------------------------------------------------------------------
# Tenant isolation sweep (T11 / T12, FR-SCA-023, US-SCA-16)
# ---------------------------------------------------------------------------


def test_T12_every_advisor_endpoint_rejects_foreign_ids_without_leaking__FR_SCA_023(client, seeded, db, reset_overrides, caplog):
    as_role(client, "TENANT_ADMIN")
    item = new_item(client)
    cid = item["candidates"][0]["id"]
    project_id = db.execute(text("SELECT id FROM projects WHERE tenant_id = 1 ORDER BY id LIMIT 1")).scalar()
    as_role(client, "TENANT_ADMIN", tenant_id=2)
    caplog.set_level(logging.DEBUG)
    rid = item["id"]
    probes = [
        ("GET", f"/components/{LOG4J}"), ("GET", f"/components/{LOG4J}/classification"),
        ("GET", f"/recommendations/{rid}"), ("GET", f"/recommendations/{rid}/candidates"),
        ("GET", f"/recommendations/{rid}/candidates/{cid}"), ("GET", f"/recommendations/{rid}/candidates/{cid}/compatibility"),
        ("GET", f"/recommendations/{rid}/candidates/{cid}/evidence"), ("GET", f"/recommendations/{rid}/events"),
        ("POST", f"/recommendations/{rid}/evaluate"), ("GET", f"/summary?project_id={project_id}"),
        ("GET", f"/components?project_id={project_id}"), ("GET", f"/search?q=log4j&project_id={project_id}"),
    ]
    for method, path in probes:
        response = client.request(method, f"{BASE}{path}")
        assert response.status_code == 404, (method, path, response.status_code)
        assert "log4j" not in response.text.lower() and "app-0" not in response.text
    decision = client.post(f"{BASE}/recommendations/{rid}/decisions",
                           json={"decision": "REJECT", "reason": "x", "row_version": item["row_version"]})
    assert decision.status_code == 404
    manual = client.post(f"{BASE}/recommendations/{rid}/candidates", json={"name": "x", "rationale": "y"})
    assert manual.status_code == 404
    create = client.post(f"{BASE}/recommendations", json={"canonical_key": LOG4J, "trigger_type": "MANUAL"})
    assert create.status_code == 404
    # Lists only ever show the caller's tenant.
    assert client.get(f"{BASE}/recommendations").json()["items"] == []
    assert client.get(f"{BASE}/audit/events").json()["items"] == []
    names = [i["name"] for i in client.get(f"{BASE}/components").json()["items"]]
    assert names == ["tenant-b-secret-lib"]
    # Nothing about tenant 1's data reached the logs of tenant 2's requests. (The
    # probe's own "q=log4j" is echoed by request logging, so check data tenant 2
    # never sent: tenant 1's product name, vulnerability id and candidate version.)
    for leaked in ("app-0", "CVE-2021-44228", "2.17.1"):
        assert leaked not in caplog.text, leaked
