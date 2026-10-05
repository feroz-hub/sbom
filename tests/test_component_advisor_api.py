"""Secure Component Advisor read API (spec Step 3).

FR-SCA-002/006/007/008, FR-SCA-023, NFR-SCA-001. Prompt §10 tests:
T11 (tenant isolation), T12 (cross-tenant ids → 404, no existence leak),
T13 (KPIs and drill-down use identical filters / as-of and reconcile),
T14 (search by name / PURL / ecosystem).

Driven through HTTP with the shared ``client`` fixture (Postgres, app
lifespan). Role checks use a synthetic ``CurrentContext`` per role, the
pattern from ``tests/test_vex_scoped_authorization.py``.
"""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from app.core.context import CurrentContext
from app.core.permissions import ROLE_PERMISSIONS
from app.core.security import get_current_tenant_context
from app.db import SessionLocal
from app.metrics.cache import reset_cache
from app.models import VexInvestigation
from tests.component_advisor_support import NOW, World, purl_key

BASE = "/api/component-advisor"


@pytest.fixture()
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def seeded(db):
    """Tenant 1 with a spread of risk states; tenant 2 with its own data.

    Tenant 1 unique versions:
      log4j-core 2.14.1   CRITICAL       (2 products)
      jackson 2.9.0       HIGH           (+ FIXED critical, ignored)
      commons-io 2.6      REVIEW_REQUIRED (VEX conflict on a MEDIUM)
      lodash 4.17.21      NO_KNOWN_ACTIONABLE (NOT_AFFECTED), EOL, 3 products
      react 18.2.0        NO_KNOWN_ACTIONABLE, Supported
    """
    reset_cache()
    db.execute(
        text(
            "INSERT INTO tenants (id, name, slug, external_iam_tenant_id, status, created_at, updated_at) "
            "VALUES (2, 'Other', 'other', 'other', 'ACTIVE', :now, :now) ON CONFLICT (id) DO NOTHING"
        ),
        {"now": NOW},
    )
    world = World(db)
    p1, p2, p3 = world.product(name="alpha"), world.product(name="beta"), world.product(name="gamma")
    s1, s2, s3 = world.sbom(p1), world.sbom(p2), world.sbom(p3)

    log4j = [world.component(s, "log4j-core", "2.14.1", ecosystem="maven") for s in (s1, s2)]
    for c in log4j:
        world.finding(c, "CVE-2021-44228", "CRITICAL", score=10.0)

    jackson = world.component(s1, "jackson-databind", "2.9.0", ecosystem="maven", supplier="FasterXML")
    world.finding(jackson, "CVE-2026-2000", "HIGH")
    world.finding(jackson, "CVE-2026-2002", "CRITICAL")
    world.vex(jackson, "CVE-2026-2002", "FIXED")

    commons = world.component(s2, "commons-io", "2.6", ecosystem="maven")
    world.finding(commons, "CVE-2024-47554", "MEDIUM")
    world.vex(commons, "CVE-2024-47554", "UNDER_INVESTIGATION", "CONFLICT_REVIEW_REQUIRED")

    for s in (s1, s2, s3):
        lodash = world.component(s, "lodash", "4.17.21", lifecycle_status="EOL", eol_date="2026-01-01")
        world.finding(lodash, "CVE-2026-0001", "HIGH")
        world.vex(lodash, "CVE-2026-0001", "NOT_AFFECTED")
    world.component(s3, "react", "18.2.0", lifecycle_status="Supported")

    other = world.product(tenant_id=2, name="other")
    s_other = world.sbom(other)
    secret = world.component(s_other, "tenant-b-secret-lib", "9.9.9")
    world.finding(secret, "CVE-2026-9999", "CRITICAL")
    world.component(s_other, "react", "18.2.0")
    db.commit()
    yield {"products": (p1, p2, p3), "sboms": (s1, s2, s3), "other_product": other, "other_sbom": s_other, "log4j": log4j}
    reset_cache()


def kpi(body, key):
    return next(card for card in body["kpis"] if card["key"] == key)


def names(body):
    return sorted(item["name"] for item in body["items"])


# ---------------------------------------------------------------------------
# Summary and drill-down
# ---------------------------------------------------------------------------


def test_summary_kpis_for_tenant_default_scope__FR_SCA_002_US_SCA_01(client, seeded):
    body = client.get(f"{BASE}/summary").json()
    assert body["meta"]["scope"]["level"] == "TENANT"
    assert kpi(body, "unique_component_versions")["value"] == 5
    assert kpi(body, "critical")["value"] == 1
    assert kpi(body, "high")["value"] == 1
    assert kpi(body, "no_known_actionable_vulnerabilities")["value"] == 2
    assert kpi(body, "end_of_life_or_support")["value"] == 1
    assert kpi(body, "frequently_adopted")["value"] == 1  # lodash in 3 products
    assert kpi(body, "requiring_review")["value"] == 1
    assert sum(body["by_classification"].values()) == 5


def test_policy_kpis_report_not_configured_instead_of_zero__FR_SCA_004_005(client, seeded):
    body = client.get(f"{BASE}/summary").json()
    accepted = kpi(body, "within_accepted_risk")
    assert accepted["status"] == "POLICY_NOT_CONFIGURED" and accepted["value"] is None
    trusted = kpi(body, "trusted_by_policy")
    assert trusted["render"] is False and trusted["status"] == "POLICY_NOT_CONFIGURED"
    assert body["meta"]["policy_versions"] == {"accepted_risk": None, "trust": None}


@pytest.mark.parametrize("scope_args", [{}, {"project": True}, {"product": True}])
def test_T13_every_kpi_reconciles_with_its_drill_down__FR_SCA_002(client, seeded, scope_args):
    params = {}
    if scope_args:
        product = seeded["products"][0]
        params["project_id"] = product.project_id
        if scope_args.get("product"):
            params["product_id"] = product.id
    summary = client.get(f"{BASE}/summary", params=params).json()
    for card in summary["kpis"]:
        if card["value"] is None:
            continue
        rows = client.get(f"{BASE}/components", params={**params, **card["filter"], "limit": 500}).json()
        assert rows["total"] == card["value"], card["key"]
        assert rows["meta"]["applied_filters"] == {
            **summary["meta"]["applied_filters"],
            **{k: (sorted(v) if isinstance(v, list) else v) for k, v in card["filter"].items()},
        }


def test_T13_filters_apply_identically_to_kpis_and_rows__FR_SCA_007(client, seeded):
    params = {"lifecycle": "EOL"}
    summary = client.get(f"{BASE}/summary", params=params).json()
    rows = client.get(f"{BASE}/components", params=params).json()
    assert kpi(summary, "unique_component_versions")["value"] == rows["total"] == 1
    assert names(rows) == ["lodash"]
    assert summary["meta"]["applied_filters"] == rows["meta"]["applied_filters"]


def test_risk_filter_accepts_repeat_and_comma_forms__FR_SCA_007(client, seeded):
    repeated = client.get(f"{BASE}/components", params=[("risk", "CRITICAL"), ("risk", "HIGH")]).json()
    comma = client.get(f"{BASE}/components", params={"risk": "critical,high"}).json()
    assert names(repeated) == names(comma) == ["jackson-databind", "log4j-core"]
    assert repeated["meta"]["applied_filters"]["risk"] == ["CRITICAL", "HIGH"]


def test_informational_filter_is_accepted_but_reported_unsupported__D4(client, seeded):
    body = client.get(f"{BASE}/components", params={"risk": "INFORMATIONAL"}).json()
    assert body["total"] == 0
    assert "risk=INFORMATIONAL" in body["meta"]["unsupported_filters"]
    assert body["meta"]["capabilities"]["informational_severity_supported"] is False


def test_unknown_filter_value_is_400(client, seeded):
    response = client.get(f"{BASE}/components", params={"risk": "SAFE"})
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "INVALID_FILTER"


def test_components_are_paged_and_sorted_by_risk_by_default(client, seeded):
    body = client.get(f"{BASE}/components", params={"limit": 2}).json()
    assert body["total"] == 5 and len(body["items"]) == 2
    assert [item["risk"]["classification"] for item in body["items"]] == ["CRITICAL", "HIGH"]
    rest = client.get(f"{BASE}/components", params={"limit": 2, "offset": 4}).json()
    assert len(rest["items"]) == 1


def test_component_detail_includes_usage_lifecycle_and_evidence__FR_SCA_001(client, seeded):
    key = purl_key("pkg:maven/log4j-core@2.14.1")
    body = client.get(f"{BASE}/components/{key}").json()
    assert body["usage"]["active_sbom_occurrences"] == 2
    assert body["usage"]["product_count"] == 2
    assert body["risk"]["classification"] == "CRITICAL"
    assert body["risk"]["cvss"]["max_score"] == 10.0
    assert {e["sbom_id"] for e in body["evidence"]} == {s.id for s in seeded["sboms"][:2]}
    assert body["meta"]["freshness"]["latest_analysis_at"] == NOW


def test_meta_envelope_is_present_on_every_endpoint__spec_step3(client, seeded):
    key = purl_key("pkg:npm/react@18.2.0")
    for path, params in [("/summary", {}), ("/components", {}), (f"/components/{key}", {}), ("/search", {"q": "react"})]:
        meta = client.get(f"{BASE}{path}", params=params).json()["meta"]
        assert {"applied_filters", "scope", "as_of", "freshness", "policy_versions"} <= set(meta), path
        assert meta["historical_view"] is False


def test_vex_decision_change_is_reflected_without_waiting_for_ttl(client, seeded, db):
    before = kpi(client.get(f"{BASE}/summary").json(), "critical")["value"]
    for component in seeded["log4j"]:
        world = World(db)
        world.vex(component, "CVE-2021-44228", "NOT_AFFECTED")
    db.commit()
    after = kpi(client.get(f"{BASE}/summary").json(), "critical")["value"]
    assert (before, after) == (1, 0)


def test_summary_supports_etag_revalidation(client, seeded):
    first = client.get(f"{BASE}/summary")
    etag = first.headers.get("etag")
    assert etag
    assert client.get(f"{BASE}/summary", headers={"If-None-Match": etag}).status_code == 304


# ---------------------------------------------------------------------------
# as-of (D-11)
# ---------------------------------------------------------------------------


def test_current_as_of_is_accepted(client, seeded):
    now = datetime.now(UTC).isoformat()
    assert client.get(f"{BASE}/summary", params={"as_of": now}).status_code == 200


@pytest.mark.parametrize("as_of", [(datetime.now(UTC) - timedelta(days=30)).isoformat(), "yesterday"])
def test_historical_or_invalid_as_of_is_rejected__D11(client, seeded, as_of):
    response = client.get(f"{BASE}/summary", params={"as_of": as_of})
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "AS_OF_NOT_SUPPORTED"


# ---------------------------------------------------------------------------
# Search (T14)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("q", "facet", "expected"),
    [
        ("log4j", "name", ["log4j-core"]),
        ("pkg:maven/jackson", "purl", ["jackson-databind"]),
        ("maven", "ecosystem", ["commons-io", "jackson-databind", "log4j-core"]),
        ("fasterxml", "supplier", ["jackson-databind"]),
        ("lod", "all", ["lodash"]),
    ],
)
def test_T14_search_by_name_purl_ecosystem_supplier__FR_SCA_008(client, seeded, q, facet, expected):
    body = client.get(f"{BASE}/search", params={"q": q, "facet": facet}).json()
    assert sorted(item["name"] for item in body["items"]) == expected
    assert body["search_status"] == "OK"


def test_search_results_expose_versions_and_risk_posture__US_SCA_07(client, seeded):
    body = client.get(f"{BASE}/search", params={"q": "lodash"}).json()
    family = body["items"][0]
    assert family["family_key"] == "npm:lodash"
    assert family["versions"][0]["classification"] == "NO_KNOWN_ACTIONABLE_VULNERABILITIES"
    assert family["versions"][0]["lifecycle_bucket"] == "EOL"


@pytest.mark.parametrize("facet", ["purpose", "category"])
def test_purpose_search_never_guesses_from_names__FR_SCA_009(client, seeded, facet):
    body = client.get(f"{BASE}/search", params={"q": "logging", "facet": facet}).json()
    assert body["items"] == []
    assert body["search_status"] == "INSUFFICIENT_PURPOSE_EVIDENCE"


def test_search_with_no_match_is_explicit(client, seeded):
    body = client.get(f"{BASE}/search", params={"q": "does-not-exist"}).json()
    assert body["search_status"] == "NO_MATCHING_COMPONENTS"


# ---------------------------------------------------------------------------
# Tenant isolation (T11 / T12) and authorization
# ---------------------------------------------------------------------------


def test_T11_tenant_a_responses_never_include_tenant_b__FR_SCA_023(client, seeded):
    rows = client.get(f"{BASE}/components", params={"limit": 500}).json()
    assert "tenant-b-secret-lib" not in names(rows)
    react = next(item for item in rows["items"] if item["name"] == "react")
    assert react["usage"]["active_sbom_occurrences"] == 1
    assert client.get(f"{BASE}/search", params={"q": "tenant-b"}).json()["items"] == []
    summary = client.get(f"{BASE}/summary").json()
    assert summary["meta"]["scope"]["tenant"]["id"] == 1


def test_T12_cross_tenant_component_key_is_404__FR_SCA_023(client, seeded):
    key = purl_key("pkg:npm/tenant-b-secret-lib@9.9.9")
    response = client.get(f"{BASE}/components/{key}")
    assert response.status_code == 404
    assert "tenant" not in response.text.lower()


def test_T12_unknown_component_key_is_indistinguishable_from_foreign(client, seeded):
    foreign = client.get(f"{BASE}/components/{purl_key('pkg:npm/tenant-b-secret-lib@9.9.9')}")
    unknown = client.get(f"{BASE}/components/{'0' * 64}")
    assert (foreign.status_code, foreign.json()) == (unknown.status_code, unknown.json())


@pytest.mark.parametrize("path", ["/summary", "/components", "/search?q=react"])
def test_T12_cross_tenant_scope_ids_are_404__FR_SCA_006(client, seeded, path):
    other = seeded["other_product"]
    sep = "&" if "?" in path else "?"
    assert client.get(f"{BASE}{path}{sep}project_id={other.project_id}").status_code == 404
    assert (
        client.get(f"{BASE}{path}{sep}project_id={other.project_id}&product_id={other.id}").status_code == 404
    )


def test_child_scope_without_parent_is_400__US_SCA_05(client, seeded):
    product = seeded["products"][0]
    assert client.get(f"{BASE}/summary", params={"product_id": product.id}).status_code == 400


def test_scope_narrowing_updates_every_widget__US_SCA_05(client, seeded):
    product = seeded["products"][2]  # gamma: lodash + react
    params = {"project_id": product.project_id, "product_id": product.id}
    summary = client.get(f"{BASE}/summary", params=params).json()
    rows = client.get(f"{BASE}/components", params=params).json()
    assert summary["meta"]["scope"]["level"] == "APPLICATION"
    assert kpi(summary, "unique_component_versions")["value"] == rows["total"] == 2
    assert names(rows) == ["lodash", "react"]


def _context(role, tenant_id=1, permissions=None):
    return CurrentContext(
        user_id=900 + len(role), external_user_id=f"test-{role}", email=None, display_name=role,
        tenant_id=tenant_id, external_tenant_id=str(tenant_id), roles=frozenset({role}),
        permissions=ROLE_PERMISSIONS[role] if permissions is None else permissions,
    )


@pytest.mark.parametrize("role", ["TENANT_ADMIN", "SECURITY_ANALYST", "DEVELOPER", "VIEWER"])
def test_every_tenant_role_can_read_the_advisor__spec_s9(client, seeded, role):
    client.app.dependency_overrides[get_current_tenant_context] = lambda: _context(role)
    try:
        for path in ("/summary", "/components", "/search?q=react"):
            assert client.get(f"{BASE}{path}").status_code == 200, (role, path)
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)


def test_missing_read_permission_is_403__NFR_SCA_001(client, seeded):
    permissions = ROLE_PERMISSIONS["VIEWER"] - {"component_advisor:read"}
    client.app.dependency_overrides[get_current_tenant_context] = lambda: _context("VIEWER", permissions=permissions)
    try:
        for path in ("/summary", "/components", f"/components/{'0' * 64}", "/search?q=react"):
            assert client.get(f"{BASE}{path}").status_code == 403, path
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)


def test_tenant_b_actor_sees_only_tenant_b__FR_SCA_023(client, seeded):
    client.app.dependency_overrides[get_current_tenant_context] = lambda: _context("VIEWER", tenant_id=2)
    try:
        rows = client.get(f"{BASE}/components").json()
        assert names(rows) == ["react", "tenant-b-secret-lib"]
        own_project = seeded["products"][0].project_id
        assert client.get(f"{BASE}/summary", params={"project_id": own_project}).status_code == 404
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)


def test_read_endpoints_never_write(client, seeded, db):
    """Spec §1.1 advisory-only: reads leave every advisor input table unchanged."""
    tables = ("sbom_component", "analysis_finding", "vex_investigation", "sbom_source")
    before = {t: db.execute(text(f"SELECT count(*) FROM {t}")).scalar() for t in tables}
    client.get(f"{BASE}/summary")
    client.get(f"{BASE}/components")
    client.get(f"{BASE}/search", params={"q": "log4j"})
    db.expire_all()
    assert {t: db.execute(text(f"SELECT count(*) FROM {t}")).scalar() for t in tables} == before
    assert db.query(VexInvestigation).count() == before["vex_investigation"]
