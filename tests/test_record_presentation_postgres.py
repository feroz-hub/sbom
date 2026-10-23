"""Persisted display keys on an explicitly selected disposable PostgreSQL DB."""

from datetime import UTC, datetime
from uuid import UUID

from app.db import SessionLocal
from app.models import AnalysisRun, Projects, SBOMSource

from tests.public_id_fixture import public_row
from tests.tenant_fixture_scope import verified_fixture_tenant


def test_project_and_related_application_display_ids_are_real_keys(client):
    response = client.post("/api/projects", json={"project_name": "Synthetic display project", "project_status": 1})
    assert response.status_code == 201, response.text
    project = response.json()
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        stored = public_row(db, Projects, project["id"])
        assert project["display_id"] == stored.id
        assert str(stored.public_id) == project["id"]
    application = client.post(f"/api/projects/{project['id']}/products", json={"name": "Synthetic display application"})
    assert application.status_code == 201, application.text
    assert application.json()["project_display_id"] == project["display_id"]
    assert application.json()["project_id"] == project["id"]
    assert client.get(f"/api/projects/{project['display_id']}").status_code == 422
    assert client.patch(f"/api/projects/{project['id']}", json={"display_id": 999}).status_code == 422


def test_sbom_and_run_display_ids_match_persisted_relationships(client, seeded_sbom):
    sbom_id = seeded_sbom["id"]
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        source = public_row(db, SBOMSource, sbom_id)
        internal = source.id
        now = datetime.now(UTC).isoformat()
        run = AnalysisRun(
            tenant_id=1, sbom_id=source.id, run_status="OK", source="OSV", started_on=now, completed_on=now
        )
        db.add(run)
        db.flush()
        run_key, run_public = run.id, str(run.public_id)
        db.commit()
    source_wire = client.get(f"/api/sboms/{sbom_id}")
    assert source_wire.status_code == 200, source_wire.text
    assert source_wire.json()["display_id"] == internal
    response = client.get(f"/api/runs/{run_public}")
    assert response.status_code == 200, response.text
    assert response.json()["id"] == run_public and UUID(run_public).version == 4
    assert response.json()["display_id"] == run_key
    assert response.json()["sbom_id"] == sbom_id and response.json()["sbom_display_id"] == internal
    assert client.get(f"/api/runs/{run_key}").status_code == 422
    assert client.get("/api/runs/not-a-uuid").status_code == 422
