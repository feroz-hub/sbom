"""Secure Component Advisor — policies, purpose and adoption over HTTP (spec Step 4).

FR-SCA-004/005/009/010, NFR-SCA-007, US-SCA-03/04/07/08. Prompt §10:
T8 (accepted risk uses the correct policy version), T9 (adoption alone never
trusted), T15 (purpose search returns only evidenced matches), T16 (AI
purpose marked/provenanced). Plus policy versioning / concurrency / isolation
and role checks.
"""

from datetime import UTC, datetime

import pytest
from sqlalchemy import select, text

from app.core.context import CurrentContext
from app.core.permissions import ROLE_PERMISSIONS
from app.core.security import get_current_tenant_context
from app.db import SessionLocal
from app.metrics.cache import reset_cache
from app.models import AdvisorPolicy, AdvisorPolicyVersion, AuditLog
from tests.component_advisor_support import NOW, World, purl_key
from tests.test_vex_scoped_authorization import make_member

BASE = "/api/component-advisor"
COMMONS = purl_key("pkg:maven/commons-io@2.6")
SLF4J = purl_key("pkg:maven/slf4j-api@2.0.9")


@pytest.fixture()
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def seeded(db):
    """Tenant 1: a MEDIUM version, a clean version used by 3 products, an EOL one."""
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
    sboms = [world.sbom(p) for p in products]
    commons = world.component(sboms[0], "commons-io", "2.6", ecosystem="maven")
    world.finding(commons, "CVE-2024-47554", "MEDIUM", score=4.3)
    for s in sboms:
        world.component(s, "slf4j-api", "2.0.9", ecosystem="maven", license="MIT", lifecycle_status="Supported",
                        description="Simple Logging Facade for Java")
    world.component(sboms[1], "slf4j-api", "1.7.36", ecosystem="maven", license="MIT", lifecycle_status="EOL")
    other = world.sbom(world.product(tenant_id=2, name="other"))
    world.component(other, "tenant-b-pdf", "1.0.0", description="PDF generation library")
    db.commit()
    yield {"products": products, "sboms": sboms}
    reset_cache()


def kpi(body, key):
    return next(card for card in body["kpis"] if card["key"] == key)


def publish(client, kind, status="ACTIVE", rules=None, row_version=0, reason="test"):
    return client.post(
        f"{BASE}/policies/{kind}/versions",
        json={"status": status, "rules": rules, "reason": reason, "row_version": row_version},
    )


def as_role(client, role, tenant_id=1):
    """Act as a real member (audit rows reference ``iam_users``)."""
    with SessionLocal() as session:
        member = make_member(session, role, tenant_id=tenant_id)
        user_id = member.user_id
    client.app.dependency_overrides[get_current_tenant_context] = lambda: CurrentContext(
        user_id=user_id, external_user_id=str(user_id), email=None, display_name=role,
        tenant_id=tenant_id, external_tenant_id=str(tenant_id), roles=frozenset({role}),
        permissions=ROLE_PERMISSIONS[role],
    )


@pytest.fixture()
def reset_overrides(client):
    yield
    client.app.dependency_overrides.pop(get_current_tenant_context, None)


# ---------------------------------------------------------------------------
# Accepted-risk policy (T8)
# ---------------------------------------------------------------------------


def test_no_policy_means_not_configured_everywhere__FR_SCA_004(client, seeded):
    state = client.get(f"{BASE}/policies/accepted-risk").json()
    assert state["configured"] is False and state["effective"] is None and state["row_version"] == 0
    explanation = client.get(f"{BASE}/components/{COMMONS}/classification").json()
    assert explanation["classification"] == "MEDIUM"
    assert explanation["accepted_risk"] == {"status": "POLICY_NOT_CONFIGURED"}


def test_T08_accepted_risk_uses_the_active_policy_version_and_history_is_kept__FR_SCA_004(client, seeded, db):
    v1 = publish(client, "accepted-risk", rules={"max_actionable_severity": "MEDIUM", "max_cvss_score": 5.0})
    assert v1.status_code == 201, v1.text
    v1_id = v1.json()["version"]["id"]

    summary = client.get(f"{BASE}/summary").json()
    assert kpi(summary, "within_accepted_risk") | {"filter": None} == {
        "key": "within_accepted_risk", "label": "Components Within Accepted Risk", "value": 1,
        "status": "OK", "render": True, "filter": None,
    }
    assert summary["meta"]["policy_versions"]["accepted_risk"]["policy_version_id"] == v1_id
    explanation = client.get(f"{BASE}/components/{COMMONS}/classification").json()
    assert explanation["classification"] == "ACCEPTED_RISK"
    assert explanation["decided_by"] == "ACCEPTED_RISK_POLICY_SATISFIED"
    assert explanation["accepted_risk"]["policy_version_id"] == v1_id
    assert all(item["passed"] for item in explanation["accepted_risk"]["criteria"])

    v2 = publish(client, "accepted-risk", rules={"max_actionable_severity": "LOW"}, row_version=1, reason="tighten")
    assert v2.status_code == 201, v2.text
    v2_id = v2.json()["version"]["id"]
    explanation = client.get(f"{BASE}/components/{COMMONS}/classification").json()
    assert explanation["classification"] == "MEDIUM"
    assert explanation["accepted_risk"]["policy_version_id"] == v2_id
    assert explanation["accepted_risk"]["satisfied"] is False

    # Changing policy never rewrites history (US-SCA-03, NFR-SCA-007).
    history = client.get(f"{BASE}/policies/accepted-risk/versions").json()["items"]
    assert [(item["version"], item["rules"]["max_actionable_severity"]) for item in history] == [(2, "LOW"), (1, "MEDIUM")]
    stored = db.scalar(select(AdvisorPolicyVersion).where(AdvisorPolicyVersion.id == v1_id))
    assert stored.rules_json["max_actionable_severity"] == "MEDIUM"
    assert db.scalar(select(AuditLog).where(AuditLog.action == "component_advisor.policy.version_published", AuditLog.entity_id == str(v2_id)))


def test_stale_row_version_is_409_with_current_value__NFR_SCA_007(client, seeded):
    assert publish(client, "accepted-risk", rules={"max_actionable_severity": "LOW"}).status_code == 201
    conflict = publish(client, "accepted-risk", rules={"max_actionable_severity": "MEDIUM"}, row_version=0)
    assert conflict.status_code == 409
    assert conflict.json()["detail"]["row_version"] == 1


def test_invalid_policy_is_422_and_nothing_is_written(client, seeded, db):
    response = publish(client, "accepted-risk", rules={"max_actionable_severity": "HIGH"})
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "INVALID_POLICY"
    assert db.scalar(select(AdvisorPolicy.id)) is None


def test_disabled_policy_blocks_platform_default_and_inherit_restores_it(client, seeded, db):
    now = datetime.now(UTC)
    platform = AdvisorPolicy(tenant_id=None, kind="ACCEPTED_RISK", created_at=now, updated_at=now)
    db.add(platform)
    db.flush()
    db.add(AdvisorPolicyVersion(
        policy_id=platform.id, tenant_id=None, kind="ACCEPTED_RISK", version=1, status="ACTIVE",
        rules_json={"max_actionable_severity": "MEDIUM", "allowed_actionable_vex_statuses": ["AFFECTED", "UNDER_INVESTIGATION"],
                    "max_cvss_score": None, "max_actionable_vulnerabilities": None, "allowed_lifecycle": None,
                    "max_analysis_age_days": None},
        reason="platform default", created_at=now,
    ))
    db.commit()
    state = client.get(f"{BASE}/policies/accepted-risk").json()
    assert state["effective"]["scope"] == "PLATFORM"
    assert client.get(f"{BASE}/components/{COMMONS}").json()["risk"]["classification"] == "ACCEPTED_RISK"

    assert publish(client, "accepted-risk", status="DISABLED").status_code == 201
    assert client.get(f"{BASE}/policies/accepted-risk").json()["configured"] is False
    assert client.get(f"{BASE}/components/{COMMONS}").json()["risk"]["classification"] == "MEDIUM"

    assert publish(client, "accepted-risk", status="INHERIT", row_version=1).status_code == 201
    assert client.get(f"{BASE}/policies/accepted-risk").json()["effective"]["scope"] == "PLATFORM"


def test_inherit_without_override_is_422(client, seeded):
    assert publish(client, "accepted-risk", status="INHERIT").status_code == 422


def test_policy_versions_are_append_only_in_the_orm__NFR_SCA_007(client, seeded, db):
    publish(client, "accepted-risk", rules={"max_actionable_severity": "LOW"})
    row = db.scalar(select(AdvisorPolicyVersion))
    row.reason = "rewritten"
    with pytest.raises(RuntimeError, match="append-only"):
        db.flush()
    db.rollback()
    db.delete(db.scalar(select(AdvisorPolicyVersion)))
    with pytest.raises(RuntimeError, match="append-only"):
        db.flush()
    db.rollback()


def test_policies_are_tenant_isolated__FR_SCA_023(client, seeded, reset_overrides):
    assert publish(client, "accepted-risk", rules={"max_actionable_severity": "MEDIUM"}).status_code == 201
    as_role(client, "TENANT_ADMIN", tenant_id=2)
    state = client.get(f"{BASE}/policies/accepted-risk").json()
    assert state["configured"] is False and state["tenant_override"] is None
    assert client.get(f"{BASE}/policies/accepted-risk/versions").json()["items"] == []


@pytest.mark.parametrize(
    ("role", "read", "write"),
    [("TENANT_ADMIN", 200, 201), ("SECURITY_ANALYST", 200, 403), ("DEVELOPER", 403, 403), ("VIEWER", 403, 403)],
)
def test_policy_permissions_follow_spec_section_9(client, seeded, reset_overrides, role, read, write):
    as_role(client, role)
    assert client.get(f"{BASE}/policies/accepted-risk").status_code == read
    assert publish(client, "accepted-risk", rules={"max_actionable_severity": "LOW"}).status_code == write


def test_unknown_policy_kind_is_404(client, seeded):
    assert client.get(f"{BASE}/policies/safety").status_code == 404


# ---------------------------------------------------------------------------
# Trust policy (T9)
# ---------------------------------------------------------------------------


TRUST_RULES = {
    "allowed_classifications": ["NO_KNOWN_ACTIONABLE_VULNERABILITIES"],
    "allowed_lifecycle": ["SUPPORTED"],
    "allowed_licenses": ["MIT"],
    "min_tenant_products": 2,
}


def test_trusted_kpi_renders_only_with_a_policy_and_reconciles__FR_SCA_005(client, seeded):
    before = kpi(client.get(f"{BASE}/summary").json(), "trusted_by_policy")
    assert before["render"] is False and before["value"] is None
    assert publish(client, "trust", rules=TRUST_RULES).status_code == 201
    card = kpi(client.get(f"{BASE}/summary").json(), "trusted_by_policy")
    assert card["render"] is True and card["value"] == 1
    rows = client.get(f"{BASE}/components", params=card["filter"]).json()
    assert rows["total"] == 1 and rows["items"][0]["name"] == "slf4j-api" and rows["items"][0]["version"] == "2.0.9"
    trust = client.get(f"{BASE}/components/{SLF4J}/classification").json()["trust"]
    assert trust["status"] == "TRUSTED_BY_POLICY" and trust["policy_version_id"]
    assert {c["criterion"] for c in trust["criteria"]} >= {"ACCEPTABLE_CURRENT_RISK", "SUPPORTED_LIFECYCLE", "MIN_TENANT_ADOPTION"}


def test_T09_adoption_only_trust_policy_is_rejected__FR_SCA_005(client, seeded):
    response = publish(client, "trust", rules={"min_tenant_products": 1})
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Purpose metadata and search (T15 / T16)
# ---------------------------------------------------------------------------


def put_purpose(client, family, **body):
    body.setdefault("row_version", 0)
    return client.put(f"{BASE}/purpose/{family}", json=body)


def test_T15_category_search_returns_curated_matches_only__FR_SCA_009(client, seeded):
    assert client.get(f"{BASE}/search", params={"q": "logging", "facet": "category"}).json()["search_status"] == "NO_MATCHING_COMPONENTS"
    saved = put_purpose(client, "maven:slf4j-api", technology_category="Logging", primary_use_case="Application logging")
    assert saved.status_code == 200, saved.text
    body = client.get(f"{BASE}/search", params={"q": "logging", "facet": "category"}).json()
    assert [item["name"] for item in body["items"]] == ["slf4j-api"]
    assert body["items"][0]["purpose"]["technology_category"]["source"] == "CURATED"
    # The name "commons-io" never matches a category search.
    assert client.get(f"{BASE}/search", params={"q": "commons", "facet": "category"}).json()["items"] == []


def test_T15_purpose_search_uses_sbom_declared_descriptions__FR_SCA_009(client, seeded):
    body = client.get(f"{BASE}/search", params={"q": "logging facade", "facet": "purpose"}).json()
    assert [item["name"] for item in body["items"]] == ["slf4j-api"]
    detail = client.get(f"{BASE}/components/{SLF4J}").json()
    assert detail["purpose"]["functional_description"]["source"] == "SBOM"
    assert detail["purpose"]["functional_description"]["provenance"]["occurrences_declaring"] == 3


def test_T15_low_confidence_ai_never_matches_purpose_search__FR_SCA_009(client, seeded):
    provenance = {"model": "claude-test", "generated_at": "2026-10-01T00:00:00Z"}
    assert put_purpose(client, "maven:commons-io", source="AI", technology_category="file utilities",
                       confidence="LOW", provenance=provenance).status_code == 200
    assert client.get(f"{BASE}/search", params={"q": "file utilities", "facet": "category"}).json()["items"] == []


def test_T16_ai_purpose_is_marked_and_requires_provenance__FR_SCA_009(client, seeded):
    rejected = put_purpose(client, "maven:commons-io", source="AI", technology_category="io", confidence="HIGH")
    assert rejected.status_code == 422
    provenance = {"model": "claude-test", "generated_at": "2026-10-01T00:00:00Z"}
    assert put_purpose(client, "maven:commons-io", source="AI", technology_category="file utilities",
                       confidence="MEDIUM", provenance=provenance).status_code == 200
    detail = client.get(f"{BASE}/components/{COMMONS}").json()
    category = detail["purpose"]["technology_category"]
    assert category["source"] == "AI" and category["ai_assisted"] is True
    assert category["provenance"]["model"] == "claude-test"
    assert detail["purpose"]["ai_assisted"] is True


def test_purpose_write_conflict_and_permission(client, seeded, reset_overrides):
    assert put_purpose(client, "maven:slf4j-api", technology_category="Logging").status_code == 200
    stale = put_purpose(client, "maven:slf4j-api", technology_category="Other", row_version=0)
    assert stale.status_code == 409 and stale.json()["detail"]["row_version"] == 1
    as_role(client, "VIEWER")
    assert put_purpose(client, "maven:slf4j-api", technology_category="x", row_version=1).status_code == 403


def test_purpose_rows_are_tenant_isolated__FR_SCA_023(client, seeded, reset_overrides):
    assert put_purpose(client, "maven:slf4j-api", technology_category="Logging").status_code == 200
    as_role(client, "TENANT_ADMIN", tenant_id=2)
    assert client.get(f"{BASE}/purpose/maven:slf4j-api").json()["items"] == []
    # Tenant B's own SBOM description is visible to tenant B only.
    assert [i["name"] for i in client.get(f"{BASE}/search", params={"q": "pdf", "facet": "purpose"}).json()["items"]] == ["tenant-b-pdf"]


def test_tenant_b_descriptions_never_reach_tenant_a__FR_SCA_023(client, seeded):
    body = client.get(f"{BASE}/search", params={"q": "pdf", "facet": "purpose"}).json()
    assert body["items"] == []


# ---------------------------------------------------------------------------
# Adoption intelligence (FR-SCA-010)
# ---------------------------------------------------------------------------


def test_adoption_view_lists_products_and_observed_versions__FR_SCA_010(client, seeded):
    detail = client.get(f"{BASE}/components/{SLF4J}").json()
    adoption = detail["adoption"]
    assert adoption["interpretation"] == "CONTEXTUAL_EVIDENCE_NOT_PROOF"
    assert adoption["active_sbom_occurrences"] == 3
    assert sorted(p["name"] for p in adoption["products"]) == ["app-0", "app-1", "app-2"]
    observed = {v["version"]: v for v in adoption["observed_versions"]}
    assert set(observed) == {"1.7.36", "2.0.9"}
    assert observed["2.0.9"]["is_this_version"] is True
    assert observed["1.7.36"]["lifecycle_bucket"] == "EOL"
    assert observed["2.0.9"]["licenses"] == ["MIT"]


# ---------------------------------------------------------------------------
# Description backfill (migration 068 companion script)
# ---------------------------------------------------------------------------


def test_backfill_fills_only_missing_descriptions_from_stored_sbom(db):
    import json

    from app.models import SBOMComponent, SBOMSource
    from scripts.backfill_component_descriptions import backfill

    document = {"bomFormat": "CycloneDX", "components": [
        {"bom-ref": "a", "name": "slf4j-api", "version": "2.0.9", "description": "Logging facade"},
        {"bom-ref": "b", "name": "commons-io", "version": "2.6", "description": "IO utilities"},
    ]}
    sbom = SBOMSource(sbom_name="legacy", sbom_data=json.dumps(document), tenant_id=1, is_active=True)
    db.add(sbom)
    db.flush()
    missing = SBOMComponent(sbom_id=sbom.id, tenant_id=1, name="slf4j-api", version="2.0.9", bom_ref="a")
    kept = SBOMComponent(sbom_id=sbom.id, tenant_id=1, name="commons-io", version="2.6", bom_ref="b", description="Curated")
    db.add_all([missing, kept])
    db.commit()

    assert backfill(apply=False).components_updated == 1
    db.expire_all()
    assert db.get(SBOMComponent, missing.id).description is None  # dry run writes nothing
    assert backfill(apply=True).components_updated == 1
    db.expire_all()
    assert db.get(SBOMComponent, missing.id).description == "Logging facade"
    assert db.get(SBOMComponent, kept.id).description == "Curated"
