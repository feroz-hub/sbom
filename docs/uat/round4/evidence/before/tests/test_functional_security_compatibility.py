"""Functional recovery must retain database RBAC, audit identity and validation."""

import json

import pytest
from app.core.security import get_current_tenant_context
from app.db import SessionLocal
from app.models import Projects, SBOMSource, VulnerabilityRemediation, VulnerabilityRemediationAudit
from app.services.version_control_service import compare_versions, edit_sbom
from fastapi import HTTPException
from sqlalchemy import func, select

from tests.functional_security_support import tenant_actor_from_database
from tests.tenant_fixture_scope import declare_fixture_tenant, scoped_context_override, verified_fixture_tenant


@pytest.fixture
def db(client):
    with SessionLocal() as session, verified_fixture_tenant(session, 1):
        yield session
        session.rollback()


@pytest.mark.parametrize("role,status,expected", [
    ("VIEWER", "Open", 403), ("DEVELOPER", "In Progress", 200), ("DEVELOPER", "Closed", 403),
    ("SECURITY_ANALYST", "Closed", 200), ("TENANT_ADMIN", "Closed", 200),
])
def test_database_roles_preserve_remediation_close_boundary(client, db, role, status, expected):
    actor = tenant_actor_from_database(db, role)
    project = Projects(project_name="Batch C remediation")
    db.add(project)
    db.commit()
    project_id = project.id
    assert not actor.has_permission("platform:user:manage_status")
    client.app.dependency_overrides[get_current_tenant_context] = scoped_context_override(lambda: actor)
    try:
        response = client.post("/api/remediation", params={"project_id": project_id, "user_id": "spoofed-admin"},
                               json={"vuln_id": "CVE-2026-1234", "component_name": "lib", "component_version": "1",
                                     "status": status, "resolution_date": "2026-10-14" if status == "Closed" else None})
        assert response.status_code == expected, response.text
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)
    assert db.scalar(select(func.count()).select_from(VulnerabilityRemediation)) == (1 if expected == 200 else 0)
    assert db.scalar(select(func.count()).select_from(VulnerabilityRemediationAudit)) == (1 if expected == 200 else 0)
    if expected == 200:
        assert db.scalar(select(VulnerabilityRemediationAudit.changed_by)) == actor.actor_label()


def test_authenticated_writer_cannot_mutate_foreign_remediation(client, db):
    actor = tenant_actor_from_database(db, "DEVELOPER")
    declare_fixture_tenant(db, 2)
    db.commit()
    with verified_fixture_tenant(db, 2):
        project = Projects(project_name="Foreign remediation")
        db.add(project)
        db.commit()
        foreign_id = project.id
    client.app.dependency_overrides[get_current_tenant_context] = scoped_context_override(lambda: actor)
    try:
        response = client.post("/api/remediation", params={"project_id": foreign_id, "user_id": "platform-admin"},
                               json={"vuln_id": "CVE-2026-1234", "component_name": "lib", "component_version": "1",
                                     "status": "Open"})
        assert response.status_code == 404, response.text
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)
    for owner in (1, 2):
        with verified_fixture_tenant(db, owner):
            assert db.scalar(select(func.count()).select_from(VulnerabilityRemediation)) == 0
            assert db.scalar(select(func.count()).select_from(VulnerabilityRemediationAudit)) == 0


def test_invalid_edit_is_persisted_as_failed_and_cannot_be_compared(db):
    document = {"bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1,
                "components": [{"type": "library", "bom-ref": "fixture-lib", "name": "lib", "version": "1"}]}
    parent = SBOMSource(sbom_name="Invalid edit remains blocked", sbom_data=json.dumps(document),
                        sbom_version="1.0.0", status="validated")
    db.add(parent)
    db.commit()
    child = edit_sbom(db, parent.id, user_id="fixture-editor",
                      updates={"components": [{"bom_ref": "fixture-lib", "hashes": "not-a-valid-sha256"}]},
                      change_summary="Invalid integrity fixture", defer_enrichment=True)
    assert child.status == "failed" and child.error_count > 0
    before = (parent.sbom_data, parent.status, child.sbom_data, child.status)
    with pytest.raises(HTTPException) as denied:
        compare_versions(db, parent.id, child.id)
    assert denied.value.status_code == 409
    assert denied.value.detail["code"] == "SBOM_VALIDATION_BLOCKED"
    assert (parent.sbom_data, parent.status, child.sbom_data, child.status) == before


@pytest.mark.parametrize("params,expected", [
    ({"user_id": "actor@example.test"}, 422), ({"user_id": "' OR 1=1 --"}, 422),
    ({"sbom_id": 123}, 400),
])
def test_list_error_contract_is_preserved_without_mutations(client, db, params, expected):
    before = db.scalar(select(func.count()).select_from(SBOMSource))
    response = client.get("/api/sboms", params=params)
    assert response.status_code == expected, response.text
    assert isinstance(response.json()["detail"], str)
    assert db.scalar(select(func.count()).select_from(SBOMSource)) == before


def test_stream_foreign_sbom_is_hidden_and_cannot_create_run(client, db):
    from app.models import AnalysisRun

    from tests.test_sboms_analyze_stream import _parse_sse_events

    declare_fixture_tenant(db, 2)
    db.commit()
    with verified_fixture_tenant(db, 2):
        sbom = SBOMSource(sbom_name="Foreign stream", sbom_data="{}", status="validated")
        db.add(sbom)
        db.commit()
        foreign_id = sbom.id
    # The existing SSE contract returns one terminal error for both foreign
    # and missing records. Transport status is 200; business denial is 404.
    for identifier in (foreign_id, 99999999):
        response = client.post(f"/api/sboms/{identifier}/analyze/stream", json={"sources": ["NVD"]})
        assert response.status_code == 200
        assert _parse_sse_events(response.text) == [{
            "event": "error", "data": {"message": f"SBOM {identifier} not found", "code": 404},
        }]
    for owner in (1, 2):
        with verified_fixture_tenant(db, owner):
            assert db.scalar(select(func.count()).select_from(AnalysisRun)) == 0


def test_viewer_cannot_open_analysis_stream_or_create_run(client, db):
    from app.models import AnalysisRun

    actor = tenant_actor_from_database(db, "VIEWER")
    sbom = SBOMSource(sbom_name="Viewer cannot analyze", sbom_data="{}", status="validated")
    db.add(sbom)
    db.commit()
    identifier = sbom.id
    client.app.dependency_overrides[get_current_tenant_context] = scoped_context_override(lambda: actor)
    try:
        response = client.post(f"/api/sboms/{identifier}/analyze/stream", json={"sources": ["NVD"]})
        assert response.status_code == 403, response.text
        assert "text/event-stream" not in response.headers.get("content-type", "")
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)
    assert db.scalar(select(func.count()).select_from(AnalysisRun)) == 0
