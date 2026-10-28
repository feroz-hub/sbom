"""Integer public-ID rejection survives obsolete fixture corrections (SBO-54)."""
from uuid import UUID, uuid4

import pytest
from app.db import SessionLocal
from app.models import Projects, SBOMSource

from tests.public_id_fixture import public_row, tenant_uuid
from tests.tenant_fixture_scope import verified_fixture_tenant


@pytest.mark.parametrize("path", [
    "/api/projects/1", "/api/products/1", "/api/sboms/1", "/api/sboms/1/validation-report",
    "/api/sboms/1/reports/vulnerabilities.xlsx", "/dashboard/priority-findings?project_id=1",
    "/api/component-advisor/summary?project_id=1", "/api/runs/aggregate?sbom_id=1",
])
def test_integer_public_identifiers_are_rejected(client, path):
    response = client.get(path)
    assert response.status_code == 422, response.text
    assert response.json() == {"detail": "Resource identifier must be a UUIDv4"}


@pytest.mark.parametrize("header", ["1", "0", "not-a-uuid"])
def test_invalid_tenant_headers_do_not_select_a_tenant(client, header):
    response = client.get("/api/auth/context", headers={"X-Tenant-ID": header})
    assert response.status_code == 422


def test_wire_uuid_and_internal_integer_keys_are_distinct(client, sample_sbom_dict):
    import json
    project = client.post("/api/projects", json={"project_name": "round4-identity-boundary"})
    assert project.status_code == 201
    project_id = project.json()["id"]
    assert UUID(project_id).version == 4
    sbom = client.post("/api/sboms", json={"sbom_name": "round4-identity-boundary", "sbom_data": json.dumps(sample_sbom_dict), "project_id": project_id})
    assert sbom.status_code == 201, sbom.text
    sbom_id = sbom.json()["id"]
    assert UUID(sbom_id).version == 4
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        row = public_row(db, SBOMSource, sbom_id)
        project_row = public_row(db, Projects, project_id)
        assert type(row.id) is int and type(row.projectid) is int
        assert row.projectid == project_row.id
        internal_id = row.id
    assert client.get(f"/api/sboms/{sbom_id}").json()["project_id"] == project_id
    assert client.get(f"/api/sboms/{internal_id}").status_code == 422
    assert client.get(f"/api/sboms/{uuid4()}").status_code == 404
    assert client.get("/api/auth/me").json()["tenant_id"] == tenant_uuid(1)


def test_greenfield_public_identity_downgrade_stays_forbidden():
    import importlib.util
    from pathlib import Path
    path = Path(__file__).resolve().parents[1] / "alembic/versions/100_greenfield_uuid_final.py"
    spec = importlib.util.spec_from_file_location("greenfield_identity_revision", path)
    revision = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(revision)
    with pytest.raises(RuntimeError, match="Public identities cannot be downgraded"):
        revision.downgrade()
