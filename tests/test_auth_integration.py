"""HTTP integration tests for HCL IAM auth endpoints."""

from __future__ import annotations

from datetime import UTC, datetime


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


def test_authenticated_tenant_write_preserves_context(client, app, monkeypatch):
    """The tenant binding must cross FastAPI's sync endpoint thread boundary."""
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("DEV_DEFAULT_TENANT", "false")

    from app.core.security import get_current_user
    from app.db import SessionLocal
    from app.models import IAMUser, Projects, Tenant, TenantUser
    from app.settings import reset_settings
    from sqlalchemy import select

    reset_settings()
    claims = {
        "sub": "authenticated-context-user",
        "email": "context-user@example.test",
        "name": "Context User",
        "tenant_id": "local-default",
    }
    now = datetime.now(UTC)
    with SessionLocal() as db:
        tenant = db.execute(select(Tenant).where(Tenant.external_iam_tenant_id == "local-default")).scalar_one()
        user = IAMUser(
            external_iam_user_id=claims["sub"],
            email=claims["email"],
            display_name=claims["name"],
            status="ACTIVE",
            created_at=now,
            updated_at=now,
        )
        db.add(user)
        db.flush()
        db.add(
            TenantUser(
                tenant_id=tenant.id,
                user_id=user.id,
                role="TENANT_ADMIN",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
            )
        )
        db.commit()
        tenant_id = tenant.id

    app.dependency_overrides[get_current_user] = lambda: claims
    try:
        response = client.post("/api/projects", json={"project_name": "Authenticated Context Project"})
        assert response.status_code == 201, response.text
        with SessionLocal() as db:
            project = db.execute(
                select(Projects).where(Projects.project_name == "Authenticated Context Project")
            ).scalar_one()
            assert project.tenant_id == tenant_id
    finally:
        app.dependency_overrides.pop(get_current_user, None)
