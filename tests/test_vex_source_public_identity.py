"""SBO-54 broader regression: source-native IDs are not business UUIDs."""
import json
from pathlib import Path

from tests import test_component_advisor_policies_api as fixtures

db = fixtures.db
seeded = fixtures.seeded


def test_csaf_native_product_ids_survive_public_boundary(client, seeded, db):
    from app.models import VexDocument
    from sqlalchemy import select

    document = json.loads((Path(__file__).parent / "fixtures/vex/supplier-csaf.json").read_text())
    body = {"document": document}
    sbom = seeded["sboms"][0]
    result = client.post(f"/api/sboms/{sbom.public_id}/vex", json=body)
    assert result.status_code == 200, result.text
    assert result.json()["statements_imported"] > 0
    stored = db.scalar(select(VexDocument).where(VexDocument.sbom_id == sbom.id))
    assert stored.raw_document_json == document
    # Accepting source-native identifiers must not accept internal resource IDs.
    assert client.post(f"/api/sboms/{sbom.id}/vex", json=body).status_code == 422


def test_source_document_does_not_bypass_tenant_resolution(client, seeded, db):
    from app.models import SBOMSource
    from sqlalchemy import select

    from tests.tenant_fixture_scope import verified_fixture_tenant

    with verified_fixture_tenant(db, 2):
        foreign = db.scalar(select(SBOMSource))
        public_id = str(foreign.public_id)
    response = client.post(f"/api/sboms/{public_id}/vex", json={"document": {}})
    assert response.status_code == 404
