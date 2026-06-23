"""HTTP integration tests for HCL IAM auth endpoints."""

from __future__ import annotations

import pytest


def test_auth_me_dev_mode(client):
    resp = client.get("/api/auth/me")
    assert resp.status_code == 200
    body = resp.json()
    assert body["external_user_id"] == "dev-user"
    assert body["tenant_id"] == 1
    assert "permissions" in body


def test_list_tenants_dev_mode(client):
    resp = client.get("/api/tenants")
    assert resp.status_code == 200
    tenants = resp.json()
    assert isinstance(tenants, list)
    assert len(tenants) >= 1


def test_missing_token_when_auth_enabled(client, monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("HCL_IAM_ISSUER", "https://iam.example.com/realms/sbom")
    monkeypatch.setenv("HCL_IAM_AUDIENCE", "sbom-analyzer")
    monkeypatch.setenv("HCL_IAM_JWKS_URL", "https://iam.example.com/jwks")
    monkeypatch.setenv("HCL_IAM_CLIENT_ID", "sbom-ui")
    from app.settings import reset_settings

    reset_settings()
    resp = client.get("/api/auth/me")
    assert resp.status_code == 401
