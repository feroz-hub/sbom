from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path

import pytest
from app.db import SessionLocal
from app.models import SBOMComponent, SBOMSource
from app.services.analysis_service import backfill_analytics_tables
from sqlalchemy import select, text


@pytest.fixture(autouse=True)
def _initialized_database(client):
    return None


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _cyclonedx_doc() -> dict:
    return json.loads((Path(__file__).parent / "fixtures" / "sample_sbom.json").read_text())


def _spdx_doc() -> dict:
    return {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "test-spdx",
        "packages": [
            {
                "name": "requests",
                "SPDXID": "SPDXRef-Package-requests",
                "versionInfo": "2.32.0",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:pypi/requests@2.32.0",
                    }
                ],
            }
        ],
    }


def _seed_sbom(name: str, data: str | None, *, status: str = "validated") -> int:
    db = SessionLocal()
    try:
        sbom = SBOMSource(sbom_name=name, sbom_data=data, status=status)
        db.add(sbom)
        db.commit()
        db.refresh(sbom)
        return int(sbom.id)
    finally:
        db.close()


def _get_sbom(sbom_id: int) -> SBOMSource:
    db = SessionLocal()
    try:
        sbom = db.get(SBOMSource, sbom_id)
        assert sbom is not None
        db.expunge(sbom)
        return sbom
    finally:
        db.close()


def _component_count(sbom_id: int) -> int:
    db = SessionLocal()
    try:
        return int(db.scalar(select(SBOMComponent.id).where(SBOMComponent.sbom_id == sbom_id).limit(1)) is not None)
    finally:
        db.close()


def _run_backfill() -> None:
    db = SessionLocal()
    try:
        backfill_analytics_tables(db)
        db.commit()
    finally:
        db.close()


def test_startup_extraction_skips_invalid_sbom_without_warning_spam(caplog):
    sbom_id = _seed_sbom(_unique("unsupported-startup"), json.dumps({"ok": False}), status="pending")

    caplog.set_level(logging.WARNING, logger="app.services.analysis_service")
    _run_backfill()

    messages = [record.getMessage() for record in caplog.records]
    assert not any("Component extraction failed for SBOM id=" in message for message in messages)
    sbom = _get_sbom(sbom_id)
    assert sbom.component_extraction_status == "skipped"
    assert "validation status" in (sbom.component_extraction_error or "")


def test_unsupported_sbom_is_marked_skipped_and_not_retried_on_next_startup(caplog):
    sbom_id = _seed_sbom(_unique("unsupported-once"), json.dumps({"dependencyCount": 10}), status="validated")

    _run_backfill()
    first = _get_sbom(sbom_id)
    assert first.component_extraction_status == "skipped"
    assert "Unsupported SBOM format" in (first.component_extraction_error or "")
    first_attempted_at = first.component_extraction_attempted_at

    caplog.set_level(logging.WARNING, logger="app.services.analysis_service")
    _run_backfill()

    second = _get_sbom(sbom_id)
    assert second.component_extraction_status == "skipped"
    assert second.component_extraction_attempted_at == first_attempted_at
    assert not any("Component extraction failed for SBOM id=" in record.getMessage() for record in caplog.records)


def test_valid_cyclonedx_sbom_still_extracts_components():
    sbom_id = _seed_sbom(_unique("valid-cdx"), json.dumps(_cyclonedx_doc()))

    _run_backfill()

    sbom = _get_sbom(sbom_id)
    assert sbom.component_extraction_status == "completed"
    assert sbom.component_extraction_error is None
    assert _component_count(sbom_id) == 1


def test_valid_spdx_sbom_still_extracts_components():
    sbom_id = _seed_sbom(_unique("valid-spdx"), json.dumps(_spdx_doc()))

    _run_backfill()

    sbom = _get_sbom(sbom_id)
    assert sbom.component_extraction_status == "completed"
    assert sbom.component_extraction_error is None
    assert _component_count(sbom_id) == 1


def test_unknown_format_does_not_crash_startup():
    sbom_id = _seed_sbom(_unique("unknown-format"), "not-json-or-xml")

    _run_backfill()

    sbom = _get_sbom(sbom_id)
    assert sbom.component_extraction_status == "skipped"
    assert "not parseable" in (sbom.component_extraction_error or "")


def test_missing_raw_content_does_not_crash_startup():
    sbom_id = _seed_sbom(_unique("missing-content"), None)

    _run_backfill()

    sbom = _get_sbom(sbom_id)
    assert sbom.component_extraction_status == "skipped"
    assert "missing" in (sbom.component_extraction_error or "").lower()


def test_reprocess_endpoint_can_process_valid_repaired_sbom(client):
    sbom_id = _seed_sbom(_unique("reprocess-valid"), json.dumps(_cyclonedx_doc()), status="failed")

    response = client.post(f"/api/sboms/{sbom_id}/components/reprocess")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["component_extraction_status"] == "completed"
    assert body["component_count"] > 0
    sbom = _get_sbom(sbom_id)
    assert sbom.status == "validated"
    assert sbom.component_extraction_status == "completed"


def test_reprocess_endpoint_returns_clear_error_for_unsupported_format(client):
    sbom_id = _seed_sbom(_unique("reprocess-unsupported"), json.dumps({"ok": False}), status="validated")

    response = client.post(f"/api/sboms/{sbom_id}/components/reprocess")

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["code"] in {"sbom_validation_failed", "unsupported_sbom_format"}
    sbom = _get_sbom(sbom_id)
    assert sbom.component_extraction_status == "skipped"


def test_reprocess_endpoint_preserves_tenant_isolation(client):
    name = _unique("tenant2-sbom")
    db = SessionLocal()
    try:
        db.execute(
            text(
                "INSERT INTO tenants (id, name, slug, external_iam_tenant_id, status, created_at, updated_at) "
                "VALUES (2, 'Tenant Two', 'tenant-two', 'tenant-two', 'ACTIVE', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) "
                "ON CONFLICT(id) DO NOTHING"
            )
        )
        db.execute(
            text(
                "INSERT INTO sbom_source (sbom_name, sbom_data, status, tenant_id) "
                "VALUES (:name, :data, 'validated', 2)"
            ),
            {"name": name, "data": json.dumps(_cyclonedx_doc())},
        )
        db.commit()
        sbom_id = int(db.execute(text("SELECT id FROM sbom_source WHERE sbom_name = :name"), {"name": name}).scalar_one())
    finally:
        db.close()

    response = client.post(f"/api/sboms/{sbom_id}/components/reprocess")

    assert response.status_code == 404


def test_list_api_still_returns_skipped_extraction_records(client):
    sbom_id = _seed_sbom(_unique("list-skipped"), json.dumps({"ok": False}), status="validated")
    _run_backfill()

    response = client.get("/api/sboms")

    assert response.status_code == 200, response.text
    rows = response.json()
    row = next(item for item in rows if item["id"] == sbom_id)
    assert row["component_extraction_status"] == "skipped"
