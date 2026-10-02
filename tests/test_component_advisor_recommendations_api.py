"""Secure Component Advisor — recommendation work items over HTTP (spec Step 5).

FR-SCA-011, FR-SCA-013, NFR-SCA-004. Prompt §10: T17–T19 (triggers),
T20 (re-run returns the existing open item), T21 (same-family versions
first), plus tenant isolation, roles, the background task and the advisory-only
guarantee (nothing outside recommendation state is written).
"""

import pytest
from sqlalchemy import select, text

from app.core.context import CurrentContext
from app.core.permissions import ROLE_PERMISSIONS
from app.core.security import get_current_tenant_context
from app.db import SessionLocal
from app.metrics.cache import reset_cache
from app.models import AuditLog, ComponentRecommendation
from app.workers.component_advisor_tasks import evaluate_recommendation_task
from tests.component_advisor_support import NOW, World, purl_key
from tests.test_vex_scoped_authorization import make_member

BASE = "/api/component-advisor"
LOG4J = purl_key("pkg:maven/log4j-core@2.14.1")
JACKSON = purl_key("pkg:maven/jackson-databind@2.9.0")
LODASH = purl_key("pkg:npm/lodash@3.10.1")
THEIRS = purl_key("pkg:npm/tenant-b-lib@1.0.0")


@pytest.fixture()
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


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
    products = [world.product(name=f"app-{i}") for i in range(3)]
    s1, s2, s3 = (world.sbom(p) for p in products)
    log4j = world.component(s1, "log4j-core", "2.14.1", ecosystem="maven", license="Apache-2.0",
                            latest_version="2.24.1", recommended_version="2.17.1")
    world.finding(log4j, "CVE-2021-44228", "CRITICAL", score=10.0)
    db.flush()
    db.execute(text("UPDATE analysis_finding SET fixed_versions = :f WHERE vuln_id = 'CVE-2021-44228'"),
               {"f": '["2.15.0"]'})
    world.component(s2, "log4j-core", "2.17.1", ecosystem="maven", license="Apache-2.0", lifecycle_status="Supported")
    jackson = world.component(s2, "jackson-databind", "2.9.0", ecosystem="maven")
    world.finding(jackson, "CVE-2026-2000", "HIGH")
    world.component(s3, "lodash", "3.10.1", lifecycle_status="EOL", eol_date="2020-01-01")
    other = world.sbom(world.product(tenant_id=2, name="other"))
    world.component(other, "log4j-core", "2.20.0", ecosystem="maven")
    world.component(other, "tenant-b-lib", "1.0.0")
    db.commit()
    yield {"sboms": (s1, s2, s3), "products": products}
    reset_cache()


def create(client, key, trigger, params=None, **extra):
    return client.post(f"{BASE}/recommendations", params=params or {}, json={"canonical_key": key, "trigger_type": trigger, **extra})


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


def table_counts(db):
    tables = ("sbom_source", "sbom_component", "analysis_run", "analysis_finding", "vex_investigation", "vex_statements")
    return {t: db.execute(text(f"SELECT count(*), coalesce(sum(length(t::text)), 0) FROM {t} t")).one() for t in tables}


# ---------------------------------------------------------------------------
# Triggers and creation (T17–T19)
# ---------------------------------------------------------------------------


def test_T17_critical_component_creates_and_evaluates_a_work_item__FR_SCA_011(client, seeded):
    response = create(client, LOG4J, "CRITICAL_FINDING")
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["created"] is True
    assert body["status"] == "REVIEW_REQUIRED"  # human review is mandatory
    assert body["trigger_evidence"]["highest_actionable_severity"] == "CRITICAL"
    assert body["trigger_evidence"]["evidence"][0]["sbom_id"] == seeded["sboms"][0].id
    assert body["discovery"]["status"] == "CANDIDATES_FOUND"
    assert body["correlation_id"]
    assert body["advisory_only"] is True
    assert body["capabilities"]["can_decide"] is False


def test_T18_high_component_can_trigger__FR_SCA_011(client, seeded):
    assert create(client, JACKSON, "HIGH_FINDING").status_code == 201


def test_T19_eol_component_can_trigger__FR_SCA_011(client, seeded):
    response = create(client, LODASH, "EOL")
    assert response.status_code == 201
    assert response.json()["trigger_evidence"]["lifecycle_bucket"] == "EOL"


@pytest.mark.parametrize(("key", "trigger"), [(LOG4J, "HIGH_FINDING"), (JACKSON, "CRITICAL_FINDING"),
                                              (LOG4J, "EOL"), (LODASH, "EOS"), (LODASH, "POLICY_VIOLATION")])
def test_trigger_must_match_current_evidence__FR_SCA_011(client, seeded, key, trigger):
    response = create(client, key, trigger)
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "TRIGGER_NOT_SUPPORTED_BY_EVIDENCE"


def test_manual_trigger_is_always_allowed(client, seeded):
    assert create(client, LODASH, "MANUAL").status_code == 201


def test_detail_exposes_eligible_triggers_and_open_item(client, seeded):
    before = client.get(f"{BASE}/components/{LOG4J}").json()
    assert set(before["eligible_triggers"]) == {"CRITICAL_FINDING", "MANUAL"}
    assert before["recommendation"] == {"status": "NOT_EVALUATED"}
    item = create(client, LOG4J, "CRITICAL_FINDING").json()
    after = client.get(f"{BASE}/components/{LOG4J}").json()
    assert after["recommendation"] == {"status": "REVIEW_REQUIRED", "id": item["id"], "trigger_type": "CRITICAL_FINDING"}
    row = next(i for i in client.get(f"{BASE}/components", params={"limit": 500}).json()["items"] if i["canonical_key"] == LOG4J)
    assert row["recommendation"]["id"] == item["id"]


# ---------------------------------------------------------------------------
# Idempotency (T20)
# ---------------------------------------------------------------------------


def test_T20_rerun_returns_the_existing_open_item__FR_SCA_011(client, seeded, db):
    first = create(client, LOG4J, "CRITICAL_FINDING").json()
    again = create(client, LOG4J, "CRITICAL_FINDING")
    assert again.status_code == 200
    assert again.json()["created"] is False and again.json()["id"] == first["id"]
    assert db.scalar(select(text("count(*)")).select_from(ComponentRecommendation)) == 1


def test_T20_different_context_or_trigger_is_a_separate_item__D10(client, seeded):
    sbom = seeded["sboms"][0]
    product = seeded["products"][0]
    tenant_wide = create(client, LOG4J, "CRITICAL_FINDING").json()
    manual = create(client, LOG4J, "MANUAL").json()
    scoped = create(client, LOG4J, "CRITICAL_FINDING",
                    params={"project_id": product.project_id, "product_id": product.id, "sbom_id": sbom.id}).json()
    assert len({tenant_wide["id"], manual["id"], scoped["id"]}) == 3
    assert scoped["context"] == {"project_id": product.project_id, "product_id": product.id, "sbom_id": sbom.id, "level": "SBOM"}


def test_T20_a_closed_item_does_not_block_a_new_one(client, seeded, db):
    first = create(client, LOG4J, "CRITICAL_FINDING").json()
    db.execute(text("UPDATE component_recommendation SET status = 'REJECTED' WHERE id = :id"), {"id": first["id"]})
    db.commit()
    second = create(client, LOG4J, "CRITICAL_FINDING")
    assert second.status_code == 201 and second.json()["id"] != first["id"]


def test_T20_database_rejects_a_second_open_item_for_one_context(seeded, db):
    from datetime import UTC, datetime

    from sqlalchemy.exc import IntegrityError

    now = datetime.now(UTC)
    row = dict(tenant_id=1, scope_key=0, source_canonical_key=LOG4J, source_name="log4j-core", trigger_type="MANUAL",
               status="REVIEW_REQUIRED", created_at=now, updated_at=now)
    db.execute(ComponentRecommendation.__table__.insert().values(**row))
    with pytest.raises(IntegrityError):
        db.execute(ComponentRecommendation.__table__.insert().values(**{**row, "status": "OPEN"}))
    db.rollback()


# ---------------------------------------------------------------------------
# Candidates (T21) and advisory-only behaviour
# ---------------------------------------------------------------------------


def test_T21_same_family_candidates_with_evidence__FR_SCA_013(client, seeded):
    item = create(client, LOG4J, "CRITICAL_FINDING").json()
    candidates = client.get(f"{BASE}/recommendations/{item['id']}/candidates").json()
    versions = [c["version"] for c in candidates["items"]]
    assert versions == ["2.17.1", "2.15.0", "2.24.1"]
    assert all(c["candidate_kind"] == "SAME_FAMILY_VERSION" for c in candidates["items"])
    # No purpose metadata in this scenario, so alternatives cannot be established (Step 6).
    assert candidates["discovery"]["alternatives_status"] == "INSUFFICIENT_PURPOSE_EVIDENCE"
    top = candidates["items"][0]
    assert top["source_type"] == "TENANT_OBSERVED"
    assert top["evaluation"]["fix_coverage"]["fixed"] == ["CVE-2021-44228"]
    assert {"FOUND_IN_N_ACTIVE_TENANT_SBOMS", "USED_BY_N_TENANT_PRODUCTS"} <= {r["code"] for r in top["reasons"]}
    # No candidate is an approved replacement before human review; confidence is set from Step 7.
    assert all(c["approved_replacement"] is False for c in candidates["items"])
    assert {c["confidence"] for c in candidates["items"]} <= {"HIGH", "MEDIUM", "LOW", "INSUFFICIENT_EVIDENCE"}


def test_other_tenants_versions_are_never_candidates__FR_SCA_023(client, seeded):
    item = create(client, LOG4J, "CRITICAL_FINDING").json()
    assert "2.20.0" not in [c["version"] for c in item["candidates"]]


def test_creating_and_evaluating_never_modifies_sbom_data__spec_s1_1(client, seeded, db):
    before = table_counts(db)
    item = create(client, LOG4J, "CRITICAL_FINDING").json()
    client.post(f"{BASE}/recommendations/{item['id']}/evaluate")
    db.expire_all()
    assert table_counts(db) == before


def test_creation_and_evaluation_are_audited_with_correlation__NFR_SCA_004(client, seeded, db):
    response = client.post(f"{BASE}/recommendations", headers={"X-Request-ID": "sca-test-corr-1"},
                           json={"canonical_key": LOG4J, "trigger_type": "CRITICAL_FINDING"})
    assert response.json()["correlation_id"] == "sca-test-corr-1"
    actions = set(db.scalars(select(AuditLog.action).where(AuditLog.entity_id == str(response.json()["id"]))).all())
    assert {"component_advisor.recommendation.created", "component_advisor.recommendation.evaluated"} <= actions


def test_re_evaluate_is_idempotent_and_blocked_after_decisions(client, seeded, db):
    item = create(client, LOG4J, "CRITICAL_FINDING").json()
    again = client.post(f"{BASE}/recommendations/{item['id']}/evaluate").json()
    assert again["status"] == "REVIEW_REQUIRED" and len(again["candidates"]) == len(item["candidates"])
    assert again["row_version"] == item["row_version"] + 1
    db.execute(text("UPDATE component_recommendation SET status = 'ACCEPTED' WHERE id = :id"), {"id": item["id"]})
    db.commit()
    blocked = client.post(f"{BASE}/recommendations/{item['id']}/evaluate")
    assert blocked.status_code == 409 and blocked.json()["detail"]["code"] == "INVALID_STATE"


def test_create_without_evaluation_stays_open(client, seeded):
    item = create(client, LOG4J, "CRITICAL_FINDING", evaluate=False).json()
    assert item["status"] == "OPEN" and item["candidates"] == [] and item["discovery"] == {"status": "NOT_EVALUATED"}


def test_background_task_evaluates_once_and_is_retry_safe__NFR_SCA_004(client, seeded, db):
    item = create(client, LOG4J, "CRITICAL_FINDING", evaluate=False).json()
    assert evaluate_recommendation_task(item["id"], 1, "task-corr") == "REVIEW_REQUIRED"
    db.execute(text("UPDATE component_recommendation SET status = 'REJECTED' WHERE id = :id"), {"id": item["id"]})
    db.commit()
    assert evaluate_recommendation_task(item["id"], 1, "task-corr") == "REJECTED"  # unchanged
    assert evaluate_recommendation_task(item["id"], 2, "task-corr") == "NOT_FOUND"  # wrong tenant


def test_background_task_evaluates_a_non_default_tenant__NFR_SCA_004(client, seeded, db):
    """Regression (found by the Step 10 migration smoke on real data): with no
    request context, audit rows must belong to the item's tenant, not tenant 1."""
    from app.core.context import minimal_background_context, tenant_scope
    from app.services.component_advisor.recommendations.service import create_recommendation
    from app.services.dashboard_scope import DashboardScope

    with tenant_scope(minimal_background_context(2)):
        item, created = create_recommendation(db, context=None, scope=DashboardScope(2),
                                              canonical_key=THEIRS, trigger="MANUAL", correlation_id="task-tenant-2")
        db.commit()
        item_id = item.id
    assert created
    assert evaluate_recommendation_task(item_id, 2, "task-tenant-2") == "REVIEW_REQUIRED"
    rows = db.execute(text(
        "SELECT DISTINCT tenant_id, user_id FROM audit_log WHERE entity_type = 'component_recommendation' AND entity_id = :id"
    ), {"id": str(item_id)}).all()
    assert [tuple(r) for r in rows] == [(2, "system")]


# ---------------------------------------------------------------------------
# Isolation and roles
# ---------------------------------------------------------------------------


def test_cross_tenant_component_and_item_are_404__FR_SCA_023(client, seeded, reset_overrides):
    assert create(client, THEIRS, "MANUAL").status_code == 404
    item = create(client, LOG4J, "CRITICAL_FINDING").json()
    as_role(client, "TENANT_ADMIN", tenant_id=2)
    assert client.get(f"{BASE}/recommendations/{item['id']}").status_code == 404
    assert client.get(f"{BASE}/recommendations/{item['id']}/candidates").status_code == 404
    assert client.post(f"{BASE}/recommendations/{item['id']}/evaluate").status_code == 404
    assert client.get(f"{BASE}/recommendations").json()["items"] == []


@pytest.mark.parametrize(("role", "expected"), [("TENANT_ADMIN", 201), ("SECURITY_ANALYST", 201),
                                                ("DEVELOPER", 201), ("VIEWER", 403)])
def test_run_recommendation_permission_follows_spec_section_9(client, seeded, reset_overrides, role, expected):
    as_role(client, role)
    assert create(client, LODASH, "EOL").status_code == expected


def test_viewer_can_read_but_not_evaluate(client, seeded, reset_overrides):
    item = create(client, LOG4J, "CRITICAL_FINDING").json()
    as_role(client, "VIEWER")
    body = client.get(f"{BASE}/recommendations/{item['id']}").json()
    assert body["capabilities"]["can_evaluate"] is False and body["capabilities"]["read_only_reason"]
    assert client.post(f"{BASE}/recommendations/{item['id']}/evaluate").status_code == 403


def test_list_filters(client, seeded):
    create(client, LOG4J, "CRITICAL_FINDING")
    create(client, LODASH, "EOL")
    assert client.get(f"{BASE}/recommendations").json()["total"] == 2
    assert client.get(f"{BASE}/recommendations", params={"trigger_type": "EOL"}).json()["total"] == 1
    assert client.get(f"{BASE}/recommendations", params={"canonical_key": LOG4J}).json()["total"] == 1
    assert client.get(f"{BASE}/recommendations", params={"status": "ACCEPTED"}).json()["total"] == 0
    assert client.get(f"{BASE}/recommendations", params={"status": "BOGUS"}).status_code == 400
