"""Phase 1 — POST /api/sboms/{id}/revalidate.

Locks the contract for the recovery affordance behind migration 013:

* Legacy rows (created before the validator was wired in) carry
  ``status='pending'`` after the migration. Hitting the endpoint
  promotes them to ``failed`` (Snyk-shaped JSON) or ``validated``
  (a real CycloneDX) by re-running the 8-stage pipeline against
  the stored body.
* Idempotent — calling twice on the same row produces the same
  result.
* Edge cases: 404 on unknown id, 400 on a row whose ``sbom_data``
  is empty/NULL.
"""

from __future__ import annotations

import json
import uuid

import pytest

_VALID_CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
    "version": 1,
    "metadata": {
        "timestamp": "2026-04-30T12:00:00Z",
        "component": {
            "type": "application",
            "bom-ref": "pkg:generic/revalidate-valid@1.0.0",
            "name": "revalidate-valid",
            "version": "1.0.0",
        },
    },
    "components": [
        {
            "type": "library",
            "bom-ref": "pkg:pypi/requests@2.32.0",
            "name": "requests",
            "version": "2.32.0",
            "purl": "pkg:pypi/requests@2.32.0",
        }
    ],
}

_SNYK_REPORT = {
    "ok": False,
    "dependencyCount": 10052,
    "summary": "Found 3 issues",
    "vulnerabilities": [{"id": "SNYK-JS-BRACEEXPANSION-9789073", "packageName": "brace-expansion"}],
}


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _seed_legacy_row(client, name: str, body: str | None) -> int:
    """Seed legacy validation state while preserving current logical-SBOM relationships."""
    from app.db import SessionLocal
    from app.models import SBOMSource

    from tests.tenant_fixture_scope import verified_fixture_tenant

    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        sbom = SBOMSource(sbom_name=name, sbom_data=body, status="validated", tenant_id=1)
        db.add(sbom)
        db.commit()
        return str(sbom.public_id)


def _set_pending(client, sbom_id: int) -> None:
    from app.db import SessionLocal
    from app.models import SBOMSource
    from sqlalchemy import update

    from tests.tenant_fixture_scope import verified_fixture_tenant

    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        from tests.public_id_fixture import public_row
        row = public_row(db, SBOMSource, sbom_id)
        db.execute(update(SBOMSource).where(SBOMSource.id == row.id,
                   SBOMSource.validated_at.is_(None), SBOMSource.status == "validated").values(status="pending"))
        db.commit()


def test_revalidate_legacy_snyk_row_becomes_failed(client):
    name = _unique("legacy-snyk")
    sbom_id = _seed_legacy_row(client, name, json.dumps(_SNYK_REPORT))
    _set_pending(client, sbom_id)

    # Sanity: the row is pending before we hit the endpoint.
    pre = client.get(f"/api/sboms/{sbom_id}").json()
    assert pre["status"] == "pending"
    assert pre["validated_at"] is None

    resp = client.post(f"/api/sboms/{sbom_id}/revalidate")
    assert resp.status_code == 415, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == "sbom_validation_failed"
    assert detail["status"] == "failed"
    assert detail["failed_stage"] == "detect"
    assert detail["entries"][0]["code"] == "SBOM_VAL_E010_FORMAT_INDETERMINATE"

    # Persisted row now reflects the new outcome.
    after = client.get(f"/api/sboms/{sbom_id}").json()
    assert after["status"] == "failed"
    assert after["failed_stage"] == "detect"
    assert after["validated_at"] is not None
    assert after["error_count"] == 1


def test_revalidate_legacy_clean_row_becomes_validated(client):
    name = _unique("legacy-clean")
    sbom_id = _seed_legacy_row(client, name, json.dumps(_VALID_CYCLONEDX))
    _set_pending(client, sbom_id)

    resp = client.post(f"/api/sboms/{sbom_id}/revalidate")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "validated"
    assert body["error_count"] == 0
    assert body["validated_at"] is not None


def test_revalidate_is_idempotent(client):
    name = _unique("idempotent")
    sbom_id = _seed_legacy_row(client, name, json.dumps(_SNYK_REPORT))
    _set_pending(client, sbom_id)

    first = client.post(f"/api/sboms/{sbom_id}/revalidate")
    second = client.post(f"/api/sboms/{sbom_id}/revalidate")
    assert first.status_code == second.status_code == 415
    assert first.json()["detail"]["entries"] == second.json()["detail"]["entries"]
    assert first.json()["detail"]["error_count"] == second.json()["detail"]["error_count"]


def test_revalidate_404_on_unknown_id(client):
    resp = client.post(f"/api/sboms/{uuid.uuid4()}/revalidate")
    assert resp.status_code == 404


def test_revalidate_400_when_sbom_data_missing(client):
    """A row whose body is NULL cannot be revalidated — 400 with a clear
    message, not a crash."""
    name = _unique("no-body")
    sbom_id = _seed_legacy_row(client, name, None)
    _set_pending(client, sbom_id)

    resp = client.post(f"/api/sboms/{sbom_id}/revalidate")
    assert resp.status_code == 400
    detail = resp.json()["detail"]
    assert detail["code"] == "sbom_data_missing"


def test_legacy_rows_get_reclassified_to_pending_at_startup(client):
    """The startup-time equivalent of migration 013 (in app.main._ensure_seed_data)
    fires the same UPDATE so SQLite dev DBs don't need an alembic run.

    Asserting through the running TestClient confirms the reclassification
    is in effect by the time the first request is served.
    """
    name = _unique("startup-legacy")
    # Insert a legacy-shaped row WITHOUT going through the route. This
    # mimics what migration 012's server_default did to pre-existing rows:
    # status='validated', validated_at IS NULL.
    sbom_id = _seed_legacy_row(client, name, json.dumps(_SNYK_REPORT))

    # Re-trigger the startup helper as a test would experience post-restart.
    from app.main import _ensure_seed_data

    _ensure_seed_data()

    fetched = client.get(f"/api/sboms/{sbom_id}").json()
    assert fetched["status"] == "pending"
    assert fetched["validated_at"] is None
    # Reclassification doesn't manufacture validation history.
    assert fetched["validation_errors"] is None
    assert fetched["failed_stage"] is None


@pytest.mark.parametrize("scenario", ["snyk", "clean"])
def test_revalidate_does_not_disturb_other_rows(client, scenario):
    """A revalidate call writes only to the targeted row."""
    other = _seed_legacy_row(client, _unique("other"), json.dumps(_VALID_CYCLONEDX))
    _set_pending(client, other)

    target_body = _SNYK_REPORT if scenario == "snyk" else _VALID_CYCLONEDX
    target = _seed_legacy_row(client, _unique(f"target-{scenario}"), json.dumps(target_body))
    _set_pending(client, target)

    client.post(f"/api/sboms/{target}/revalidate")

    other_after = client.get(f"/api/sboms/{other}").json()
    assert other_after["status"] == "pending"
    assert other_after["validated_at"] is None
