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
from sqlalchemy import text

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


def _seed_legacy_row(client, name: str, body: str) -> int:
    """Simulate a pre-validator row: insert directly with the legacy
    column shape (status default fires; validated_at NULL)."""
    from app.db import SessionLocal

    db = SessionLocal()
    try:
        db.execute(
            text(
                "INSERT INTO sbom_source (sbom_name, sbom_data, status, tenant_id) "
                "VALUES (:name, :data, 'validated', 1)"
            ),
            {"name": name, "data": body},
        )
        db.commit()
        row = db.execute(
            text("SELECT id FROM sbom_source WHERE sbom_name = :name"),
            {"name": name},
        ).first()
        assert row is not None
        return int(row[0])
    finally:
        db.close()


def _set_pending(client, sbom_id: int) -> None:
    """Apply migration 013's reclassification to a single row."""
    from app.db import SessionLocal

    db = SessionLocal()
    try:
        db.execute(
            text(
                "UPDATE sbom_source SET status = 'pending' "
                "WHERE id = :id AND validated_at IS NULL AND status = 'validated'"
            ),
            {"id": sbom_id},
        )
        db.commit()
    finally:
        db.close()


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
    resp = client.post("/api/sboms/99999999/revalidate")
    assert resp.status_code == 404


def test_revalidate_400_when_sbom_data_missing(client):
    """A row whose body is NULL cannot be revalidated — 400 with a clear
    message, not a crash."""
    name = _unique("no-body")
    from app.db import SessionLocal

    db = SessionLocal()
    try:
        db.execute(
            text(
                "INSERT INTO sbom_source (sbom_name, sbom_data, status, tenant_id) VALUES (:name, NULL, 'pending', 1)"
            ),
            {"name": name},
        )
        db.commit()
        row = db.execute(
            text("SELECT id FROM sbom_source WHERE sbom_name = :name"),
            {"name": name},
        ).first()
        sbom_id = int(row[0])
    finally:
        db.close()

    resp = client.post(f"/api/sboms/{sbom_id}/revalidate")
    assert resp.status_code == 400
    detail = resp.json()["detail"]
    assert detail["code"] == "sbom_data_missing"


# The legacy 'validated' -> 'pending' reclassification is owned by Alembic
# migration 013. DB Schema Management Phase 4 removed the duplicate per-boot
# startup backfill (app.main._ensure_seed_data no longer re-runs it), so the
# coverage moved to a disposable-DB migration test:
# test_schema_management_safety.py::test_migration_013_reclassifies_legacy_validated_rows.


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
