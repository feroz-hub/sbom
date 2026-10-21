"""Posture endpoint must aggregate real per-lineage evidence at every scope."""

import json
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from app.core.security import get_current_tenant_context
from app.metrics.findings import findings_latest_per_sbom_total
from app.models import Product, Projects, SBOMSource, Tenant
from app.services.dashboard_scope import DashboardScope, dashboard_scope

from tests.test_vex_scoped_authorization import actor, make_member

pytest_plugins = ["tests.test_vex_version_lifecycle"]
URL = "/dashboard/posture-versions"


@pytest.fixture
def db(client):
    from app.core.context import minimal_background_context, tenant_scope
    from app.db import SessionLocal

    with tenant_scope(minimal_background_context(1)), SessionLocal() as session:
        yield session


def response(client, **params):
    # Positive domain fixtures supply internal IDs to the metric layer. The
    # HTTP boundary requires the corresponding public UUIDs.
    from app.db import SessionLocal
    models = {"project_id": Projects, "product_id": Product, "sbom_id": SBOMSource}
    with SessionLocal() as db:
        from tests.tenant_fixture_scope import verified_fixture_tenant
        with verified_fixture_tenant(db, 1):
            wire_params = {key: str(db.get(models[key], value).public_id) for key, value in params.items()}
    r = client.get(URL, params=wire_params)
    assert r.status_code == 200, r.text
    return r.json()


def seed_two(app_line, db):
    a = app_line.version("1.0")
    ca = app_line.component(a, "library-a", "1")
    ra = app_line.run(a, [(ca, "CVE-2026-1001"), (ca, "CVE-2026-1002")])
    app_line.product.current_sbom_id = a.id
    project = Projects(tenant_id=1, project_name="Second project", project_status=1)
    db.add(project)
    db.flush()
    product = Product(
        tenant_id=1,
        project_id=project.id,
        name="Second application",
        normalized_name="second",
        slug="second",
        created_at="2026-10-09T00:00:00Z",
    )
    db.add(product)
    db.flush()
    b = SBOMSource(
        sbom_name="second-application-2.0",
        sbom_data="{}",
        tenant_id=1,
        is_active=True,
        projectid=project.id,
        product_id=product.id,
        sbom_version="2.0",
        productver="2.0",
        lifecycle_status="ACTIVE",
    )
    db.add(b)
    db.commit()
    app_line.component(b, "library-b", "2")
    rb = app_line.run(b, [], status="OK")
    rb.project_id = project.id
    rb.product_id = product.id
    product.current_sbom_id = b.id
    db.commit()
    return a, b, ra, rb, project, product


@pytest.mark.parametrize("level", ["tenant", "project", "application", "sbom"])
def test_two_analyzed_applications_agree_with_metrics_at_every_scope(client, app_line, db, level):
    a, b, ra, rb, project, product = seed_two(app_line, db)
    params = {} if level == "tenant" else {"project_id": app_line.project.id}
    if level in {"application", "sbom"}:
        params["product_id"] = app_line.product.id
    if level == "sbom":
        params["sbom_id"] = a.id
    data = response(client, **params)
    assert data["summary"]["evidence_status"] == "AVAILABLE"
    assert data["summary"]["missing_targets"] == 0
    assert {i["analysis_run_id"] for i in data["items"]} == ({ra.id, rb.id} if level == "tenant" else {ra.id})
    scope = DashboardScope(1, params.get("project_id"), params.get("product_id"), params.get("sbom_id"))
    with dashboard_scope(db, scope):
        assert sum(i["analysis_finding_rows"] for i in data["items"]) == findings_latest_per_sbom_total(db) == 2
    zero = response(client, project_id=project.id, product_id=product.id, sbom_id=b.id)
    assert zero["items"][0]["analysis_run_id"] == rb.id and zero["items"][0]["analysis_finding_rows"] == 0
    assert zero["summary"]["evidence_status"] == "AVAILABLE"


@pytest.mark.parametrize("status", [None, "ERROR"])
def test_pending_and_failed_replacement_have_available_last_known_evidence(client, app_line, db, status):
    a = app_line.version("1")
    c = app_line.component(a, "library", "1")
    run = app_line.run(a, [(c, "CVE-2026-1001")])
    b = app_line.version("2", parent=a)
    app_line.product.current_sbom_id = b.id
    db.commit()
    if status:
        app_line.run(b, [], status=status)
    data = response(client)
    assert data["summary"]["evidence_status"] == "AVAILABLE"
    item = data["items"][0]
    assert item["target_sbom_id"] == str(b.public_id) and item["posture_sbom_id"] == str(a.public_id) and item["analysis_run_id"] == run.id
    assert item["last_known_posture"] and item["analysis_finding_rows"] == 1


def test_partial_missing_is_scoped_not_global_unavailable(client, app_line, db):
    a = app_line.version("1")
    c = app_line.component(a, "library", "1")
    app_line.run(a, [(c, "CVE-2026-1001")])
    missing = app_line.version("independent")
    data = response(client)
    assert data["summary"]["evidence_status"] == "PARTIAL"
    assert data["summary"]["available_targets"] == 1 and data["summary"]["missing_targets"] == 1
    assert next(i for i in data["items"] if i["target_sbom_id"] == str(missing.public_id))["analysis_run_id"] is None
    assert sum(i["analysis_finding_rows"] or 0 for i in data["items"]) == 1


def test_legacy_metadata_and_missing_parent_do_not_hide_valid_analysis(client, app_line, db):
    sbom = app_line.version(None)
    component = app_line.component(sbom, "library", "1")
    run = app_line.run(sbom, [(component, "CVE-2026-1001")])
    run.raw_report = json.dumps({"source_summary": [{"source": "NVD", "status": "success"}]})
    db.commit()
    item = response(client)["items"][0]
    assert item["analysis_run_id"] == run.id and not item["last_known_posture"]
    assert item["current_sbom"]["version"] is None and item["current_sbom"]["name"] == sbom.sbom_name
    assert not item["coverage_incomplete"]


def test_provider_coverage_is_not_missing_version_evidence(client, app_line, db):
    sbom = app_line.version("1")
    component = app_line.component(sbom, "library", "1")
    run = app_line.run(sbom, [], status="OK")
    run.raw_report = json.dumps(
        {"source_summary": [{"source": "NVD", "status": "success", "queried": 0, "skipped": 1}]}
    )
    db.commit()
    data = response(client)
    assert data["summary"]["evidence_status"] == "AVAILABLE"
    assert data["summary"]["coverage_incomplete_targets"] == 1
    assert data["items"][0]["analysis_finding_rows"] == 0


def test_unavailable_and_empty_are_valid_200_statuses(client, app_line):
    assert response(client)["summary"]["evidence_status"] == "EMPTY"
    app_line.version("pending")
    assert response(client)["summary"]["evidence_status"] == "UNAVAILABLE"


def test_dashboard_posture_is_tenant_isolated_and_permission_protected(client, app_line, db):
    sbom = app_line.version("1")
    component = app_line.component(sbom, "library", "1")
    app_line.run(sbom, [(component, "CVE-2026-1001")])
    tenant = Tenant(name="Other", slug="posture-other", created_at=datetime.now(UTC), updated_at=datetime.now(UTC))
    db.add(tenant)
    db.commit()
    member = make_member(db, "VIEWER", tenant_id=tenant.id)
    try:
        client.app.dependency_overrides[get_current_tenant_context] = lambda: actor(member)
        assert response(client)["items"] == []
        assert (
            client.get(
                URL, params={"project_id": str(app_line.project.public_id), "product_id": str(app_line.product.public_id), "sbom_id": str(sbom.public_id)}
            ).status_code
            == 404
        )
        client.app.dependency_overrides[get_current_tenant_context] = lambda: replace(
            actor(member), permissions=frozenset()
        )
        assert client.get(URL).status_code == 403
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)
