from __future__ import annotations

import pytest
from app.db import Base, SessionLocal, engine
from app.models import (
    AuditLog,
    LifecycleProviderConfig,
    LifecycleProviderSecret,
    LifecycleVendorRecord,
)
from app.security.secrets import generate_master_key
from app.services.lifecycle.provider_config_service import (
    LifecycleProviderConfigService,
    invalidate_provider_config_cache,
)
from app.services.lifecycle.provider_registry import LifecycleProviderRegistry


@pytest.fixture(autouse=True)
def lifecycle_secret_key(monkeypatch):
    monkeypatch.setenv("APP_SECRET_KEY", generate_master_key())


@pytest.fixture()
def db_session(app):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_default_provider_configs_are_bootstrapped(db_session):
    service = LifecycleProviderConfigService()
    service.bootstrap_defaults(db_session)
    rows = service.list_configs(db_session)
    keys = {row.provider_key for row in rows}
    assert "endoflife_date" in keys
    assert "repository_health" in keys
    assert "openeox" in keys
    assert len(keys) >= 11


def test_admin_can_list_lifecycle_providers(client):
    response = client.get("/api/admin/lifecycle-providers")
    assert response.status_code == 200
    body = response.json()
    assert any(row["provider_key"] == "endoflife_date" for row in body)
    assert all("encrypted_value" not in row for row in body)


def test_admin_can_enable_disable_and_change_priority(client):
    response = client.put(
        "/api/admin/lifecycle-providers/repository_health",
        json={"enabled": False, "priority": 90},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["enabled"] is False
    assert body["priority"] == 90


def test_openeox_requires_feed_url_when_enabled(client):
    response = client.put("/api/admin/lifecycle-providers/openeox", json={"enabled": True, "feed_urls": []})
    assert response.status_code == 422


def test_openeox_can_be_enabled_with_feed_url(client):
    response = client.put(
        "/api/admin/lifecycle-providers/openeox",
        json={"enabled": True, "feed_urls": ["https://example.com/openeox.json"]},
    )
    assert response.status_code == 200, response.text
    assert response.json()["feed_urls"] == ["https://example.com/openeox.json"]


def test_xeol_db_requires_existing_path(client):
    response = client.put(
        "/api/admin/lifecycle-providers/xeol_db",
        json={"enabled": True, "config": {"db_path": "/definitely/not/here.json"}},
    )
    assert response.status_code == 422


def test_secret_is_encrypted_and_not_returned(client, db_session):
    response = client.put(
        "/api/admin/lifecycle-providers/xeol_api/secret",
        json={"secret_name": "api_key", "secret_value": "sk_live_123456abcd"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["value_preview"] == "sk_liv****abcd"

    list_response = client.get("/api/admin/lifecycle-providers")
    assert "sk_live_123456abcd" not in list_response.text

    row = db_session.query(LifecycleProviderSecret).filter_by(provider_key="xeol_api", secret_name="api_key").one()
    assert row.encrypted_value != "sk_live_123456abcd"
    assert "sk_live_123456abcd" not in row.encrypted_value


def test_provider_chain_uses_enabled_db_config_order(db_session):
    service = LifecycleProviderConfigService()
    service.bootstrap_defaults(db_session)
    db_session.query(LifecycleProviderConfig).filter_by(provider_key="repository_health").one().enabled = False
    db_session.query(LifecycleProviderConfig).filter_by(provider_key="osv").one().priority = 15
    db_session.commit()
    invalidate_provider_config_cache()

    providers = LifecycleProviderRegistry().build_provider_chain(db_session)
    names = [provider.name for provider in providers]
    assert "Repository Health" not in names
    assert names.index("OSV") < names.index("endoflife.date")


def test_provider_test_endpoint_returns_health_result(client):
    response = client.post("/api/admin/lifecycle-providers/package_registry/test")
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "healthy"


def test_provider_sync_endpoint_returns_status(client):
    response = client.post("/api/admin/lifecycle-providers/xeol_db/sync")
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "completed"


def test_custom_vendor_record_crud_and_lookup_participation(client, db_session):
    create = client.post(
        "/api/admin/lifecycle-vendor-records",
        json={
            "vendor_name": "Acme",
            "product_name": "legacy-runtime",
            "product_aliases": ["legacy"],
            "ecosystem": "generic",
            "version_pattern": "1",
            "lifecycle_status": "EOL",
            "eol_date": "2024-01-01",
            "evidence_url": "https://example.com/lifecycle",
            "confidence": "High",
        },
    )
    assert create.status_code == 201, create.text
    record_id = create.json()["id"]

    list_response = client.get("/api/admin/lifecycle-vendor-records?search=legacy")
    assert list_response.status_code == 200
    assert list_response.json()["total"] >= 1

    client.put("/api/admin/lifecycle-providers/custom_vendor_records", json={"enabled": True})
    providers = LifecycleProviderRegistry().build_provider_chain(db_session)
    assert "Vendor Lifecycle" in [provider.name for provider in providers]

    delete = client.delete(f"/api/admin/lifecycle-vendor-records/{record_id}")
    assert delete.status_code == 204
    disabled = db_session.get(LifecycleVendorRecord, record_id)
    assert disabled.enabled is False


def test_audit_logs_written_for_provider_changes(client, db_session):
    response = client.put("/api/admin/lifecycle-providers/osv", json={"priority": 75})
    assert response.status_code == 200
    audit = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "lifecycle.provider_config.update", AuditLog.entity_id == "osv")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert "sk_" not in str(audit.new_value).lower()
