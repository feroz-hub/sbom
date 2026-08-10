from __future__ import annotations

import sqlite3

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
from app.services.lifecycle.xeol_db_provider import XeolDbProvider


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


def write_xeol_sqlite(path):
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            """
            CREATE TABLE products (
              id integer PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              permalink TEXT NOT NULL
            );
            CREATE TABLE cycles (
              id integer PRIMARY KEY AUTOINCREMENT,
              lts boolean,
              release_cycle TEXT NOT NULL,
              eol date,
              eol_bool boolean,
              latest_release TEXT,
              latest_release_date date,
              release_date date,
              support boolean,
              product_id integer NOT NULL
              CHECK (eol IS NOT NULL OR eol_bool IS NOT NULL)
            );
            CREATE TABLE purls (
              id integer PRIMARY KEY AUTOINCREMENT,
              purl TEXT NOT NULL,
              product_id integer NOT NULL
            );
            CREATE TABLE id (
              build_timestamp TEXT NOT NULL,
              schema_version INTEGER NOT NULL
            );
            INSERT INTO id (build_timestamp, schema_version) VALUES ('2026-07-05T00:00:00Z', 1);
            INSERT INTO products (id, name, permalink) VALUES (1, 'legacy-lib', 'https://example.test/legacy-lib');
            INSERT INTO cycles (release_cycle, eol, eol_bool, product_id) VALUES ('2.0', '2023-06-01', NULL, 1);
            INSERT INTO purls (purl, product_id) VALUES ('pkg:npm/legacy-lib', 1);
            """
        )
        connection.commit()
    finally:
        connection.close()


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
    assert body["health_status"] == "disabled"


def test_reenabled_provider_returns_unknown_not_disabled(client):
    disable = client.put("/api/admin/lifecycle-providers/repository_health", json={"enabled": False})
    assert disable.status_code == 200, disable.text
    assert disable.json()["health_status"] == "disabled"

    enable = client.put("/api/admin/lifecycle-providers/repository_health", json={"enabled": True})
    assert enable.status_code == 200, enable.text
    body = enable.json()
    assert body["enabled"] is True
    assert body["health_status"] == "unknown"

    list_response = client.get("/api/admin/lifecycle-providers")
    row = next(item for item in list_response.json() if item["provider_key"] == "repository_health")
    assert row["enabled"] is True
    assert row["health_status"] == "unknown"


def test_enabled_provider_with_stale_disabled_health_serializes_unknown(client, db_session):
    service = LifecycleProviderConfigService()
    service.bootstrap_defaults(db_session)
    row = db_session.query(LifecycleProviderConfig).filter_by(provider_key="repository_health").one()
    row.enabled = True
    row.health_status = "disabled"
    db_session.commit()
    invalidate_provider_config_cache()

    response = client.get("/api/admin/lifecycle-providers")
    assert response.status_code == 200, response.text
    body = next(item for item in response.json() if item["provider_key"] == "repository_health")
    assert body["enabled"] is True
    assert body["health_status"] == "unknown"

    status_response = client.get("/api/lifecycle/provider-status")
    provider_status = next(item for item in status_response.json()["providers"] if item["provider_key"] == "repository_health")
    assert provider_status["enabled"] is True
    assert provider_status["status"] == "unknown"


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


def test_xeol_db_requires_supported_readable_file_when_enabled(client, tmp_path):
    invalid = tmp_path / "xeol.db"
    invalid.write_text("not a sqlite db or json export", encoding="utf-8")

    response = client.put(
        "/api/admin/lifecycle-providers/xeol_db",
        json={"enabled": True, "config": {"db_path": str(invalid)}},
    )

    assert response.status_code == 422
    assert "neither SQLite nor a valid Xeol JSON export" in response.text


def test_xeol_db_valid_sqlite_can_be_enabled_and_tested(client, db_session, tmp_path):
    db_path = tmp_path / "xeol.db"
    write_xeol_sqlite(db_path)

    update = client.put(
        "/api/admin/lifecycle-providers/xeol_db",
        json={"enabled": True, "config": {"db_path": str(db_path)}},
    )
    assert update.status_code == 200, update.text
    assert update.json()["enabled"] is True
    assert update.json()["health_status"] == "unknown"

    test = client.post("/api/admin/lifecycle-providers/xeol_db/test")
    assert test.status_code == 200, test.text
    body = test.json()
    assert body["success"] is True
    assert body["status"] == "healthy"
    assert body["message"] == "Local Xeol DB path is readable."

    db_session.expire_all()
    row = db_session.query(LifecycleProviderConfig).filter_by(provider_key="xeol_db").one()
    assert row.enabled is True
    assert row.health_status == "healthy"
    assert row.last_success_at is not None
    assert row.last_failure_at is None


def test_xeol_db_test_failure_sets_failure_fields(client, db_session, tmp_path):
    invalid = tmp_path / "xeol.db"
    invalid.write_text("invalid", encoding="utf-8")
    service = LifecycleProviderConfigService()
    service.bootstrap_defaults(db_session)
    row = db_session.query(LifecycleProviderConfig).filter_by(provider_key="xeol_db").one()
    row.enabled = True
    row.config_json = {"db_path": str(invalid)}
    row.health_status = "unknown"
    db_session.commit()
    invalidate_provider_config_cache()

    response = client.post("/api/admin/lifecycle-providers/xeol_db/test")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["success"] is False
    assert body["status"] == "degraded"
    db_session.expire_all()
    row = db_session.query(LifecycleProviderConfig).filter_by(provider_key="xeol_db").one()
    assert row.last_failure_at is not None
    assert row.last_failure_message


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


def test_provider_chain_uses_db_stored_xeol_config(db_session, tmp_path):
    db_path = tmp_path / "xeol.db"
    write_xeol_sqlite(db_path)
    service = LifecycleProviderConfigService()
    service.bootstrap_defaults(db_session)
    row = db_session.query(LifecycleProviderConfig).filter_by(provider_key="xeol_db").one()
    row.enabled = True
    row.config_json = {"db_path": str(db_path)}
    row.health_status = "unknown"
    db_session.commit()
    invalidate_provider_config_cache()

    providers = LifecycleProviderRegistry().build_provider_chain(db_session)
    xeol = next(provider for provider in providers if isinstance(provider, XeolDbProvider))

    assert xeol.db_path == str(db_path)


def test_provider_test_endpoint_returns_health_result(client):
    response = client.post("/api/admin/lifecycle-providers/package_registry/test")
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "healthy"


def test_provider_sync_endpoint_returns_status(client):
    response = client.post("/api/admin/lifecycle-providers/xeol_db/sync")
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "completed"


def test_xeol_sync_clears_cache_and_retests(client, db_session, tmp_path, monkeypatch):
    db_path = tmp_path / "xeol.db"
    write_xeol_sqlite(db_path)
    client.put(
        "/api/admin/lifecycle-providers/xeol_db",
        json={"enabled": True, "config": {"db_path": str(db_path)}},
    )
    called = False

    def fake_clear_cache():
        nonlocal called
        called = True

    monkeypatch.setattr("app.services.lifecycle.provider_config_service.clear_xeol_db_cache", fake_clear_cache)

    response = client.post("/api/admin/lifecycle-providers/xeol_db/sync")

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "completed"
    assert called is True
    db_session.expire_all()
    row = db_session.query(LifecycleProviderConfig).filter_by(provider_key="xeol_db").one()
    assert row.health_status == "healthy"
    assert row.last_success_at is not None


def test_endoflife_date_probe_uses_product_endpoint(client, monkeypatch):
    requested_urls: list[str] = []

    class FakeResponse:
        status_code = 200

        def json(self):
            return [{"cycle": "12", "eol": "2028-06-10"}]

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, url):
            requested_urls.append(url)
            return FakeResponse()

    monkeypatch.setattr("app.services.lifecycle.provider_config_service.httpx.Client", FakeClient)

    response = client.post("/api/admin/lifecycle-providers/endoflife_date/test")

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "healthy"
    assert requested_urls == ["https://endoflife.date/api/v1/products/debian/"]


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
