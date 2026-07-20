from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from app.core.security import _resolve_context
from app.models import AuthorizationAuditLog, IAMUser, PlatformUserRole, Tenant, TenantUser
from fastapi import HTTPException
from sqlalchemy import select


def _now():
    return datetime.now(UTC)


def _seed_user(db, *, status: str = "PENDING") -> IAMUser:
    suffix = uuid4().hex
    now = _now()
    user = IAMUser(
        external_iam_user_id=f"managed-{suffix}",
        email=f"managed-{suffix}@example.test",
        display_name="Managed User",
        status=status,
        created_at=now,
        updated_at=now,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def test_membership_lifecycle_validation_and_audit(client):
    from app.db import SessionLocal

    with SessionLocal() as db:
        user = _seed_user(db)
        external_id = user.external_iam_user_id

    created = client.post(
        "/api/tenants/1/users",
        json={"external_user_id": external_id, "role": "SECURITY_ANALYST"},
    )
    assert created.status_code == 201, created.text
    membership_id = created.json()["membership_id"]
    assert created.json()["user_status"] == "ACTIVE"

    fetched = client.get(f"/api/tenants/1/users/{membership_id}")
    assert fetched.status_code == 200
    assert fetched.json()["role"] == "SECURITY_ANALYST"

    updated = client.patch(
        f"/api/tenants/1/users/{membership_id}",
        json={"role": "VIEWER"},
    )
    assert updated.status_code == 200
    assert updated.json()["role"] == "VIEWER"

    assert client.patch(f"/api/tenants/1/users/{membership_id}", json={"role": "PLATFORM_ADMIN"}).status_code == 422
    assert client.patch(f"/api/tenants/1/users/{membership_id}", json={"status": "ENABLED123"}).status_code == 422

    deactivated = client.post(f"/api/tenants/1/users/{membership_id}/deactivate")
    assert deactivated.status_code == 200
    assert deactivated.json()["status"] == "DISABLED"
    activated = client.post(f"/api/tenants/1/users/{membership_id}/activate")
    assert activated.status_code == 200
    assert activated.json()["status"] == "ACTIVE"
    removed = client.delete(f"/api/tenants/1/users/{membership_id}")
    assert removed.status_code == 204

    with SessionLocal() as db:
        assert db.get(TenantUser, membership_id) is None
        actions = set(db.execute(select(AuthorizationAuditLog.action)).scalars())
        assert {
            "membership.created",
            "membership.role_changed",
            "membership.deactivated",
            "membership.activated",
            "membership.removed",
        } <= actions


def test_membership_identifier_is_tenant_scoped(client):
    from app.core.context import minimal_background_context, tenant_scope
    from app.db import SessionLocal

    with SessionLocal() as db:
        now = _now()
        other = Tenant(
            name="Other Tenant",
            slug=f"other-{uuid4().hex}",
            external_iam_tenant_id=f"other-ext-{uuid4().hex}",
            status="ACTIVE",
            created_at=now,
            updated_at=now,
        )
        db.add(other)
        db.flush()
        with tenant_scope(minimal_background_context(other.id, other.external_iam_tenant_id)):
            user = _seed_user(db, status="ACTIVE")
            membership = TenantUser(
                tenant_id=other.id,
                user_id=user.id,
                role="VIEWER",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
            )
            db.add(membership)
            db.commit()
            membership_id = membership.id
            tenant_id = other.id
    assert client.get(f"/api/tenants/{tenant_id}/users/{membership_id}").status_code == 404
    assert client.patch(f"/api/tenants/{tenant_id}/users/{membership_id}", json={"role": "DEVELOPER"}).status_code == 404
    assert client.delete(f"/api/tenants/{tenant_id}/users/{membership_id}").status_code == 404


def test_last_active_tenant_admin_is_protected(client):
    from app.db import SessionLocal

    response = client.post("/api/tenants/1/users/1/deactivate")
    assert response.status_code == 409
    response = client.patch("/api/tenants/1/users/1", json={"role": "VIEWER"})
    assert response.status_code == 409
    response = client.delete("/api/tenants/1/users/1")
    assert response.status_code == 409
    with SessionLocal() as db:
        denied = set(
            db.execute(
                select(AuthorizationAuditLog.action).where(AuthorizationAuditLog.outcome == "DENIED")
            ).scalars()
        )
        assert {"membership.update_denied", "membership.status_change_denied", "membership.remove_denied"} <= denied


def test_tenant_admin_cannot_use_platform_routes_or_create_tenant(client):
    assert client.get("/api/platform/administrators").status_code == 403
    assert client.post(
        "/api/tenants",
        json={"name": "Forbidden", "slug": "forbidden-tenant", "external_iam_tenant_id": "forbidden"},
    ).status_code == 403


def test_platform_admin_can_list_create_and_audit_tenants(client):
    from app.db import SessionLocal

    with SessionLocal() as db:
        dev_user = db.execute(select(IAMUser).where(IAMUser.external_iam_user_id == "dev-user")).scalar_one()
        now = _now()
        db.add(
            PlatformUserRole(
                user_id=dev_user.id,
                role="PLATFORM_ADMIN",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
            )
        )
        dev_user_id = dev_user.id
        db.commit()

    suffix = uuid4().hex[:10]
    payload = {
        "name": "  Acme Security  ",
        "slug": f"acme-{suffix}",
        "external_iam_tenant_id": f"acme-external-{suffix}",
    }
    created = client.post("/api/tenants", json=payload, headers={"X-Correlation-ID": "tenant-create-test"})
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["name"] == "Acme Security"
    assert body["slug"] == payload["slug"]
    assert body["external_iam_tenant_id"] == payload["external_iam_tenant_id"]
    assert body["status"] == "ACTIVE"
    assert body["created_at"]

    listed = client.get("/api/platform/tenants")
    assert listed.status_code == 200
    assert any(tenant["id"] == body["id"] for tenant in listed.json())

    with SessionLocal() as db:
        assert db.execute(select(Tenant).where(Tenant.slug == payload["slug"])).scalar_one().id == body["id"]
        audit = db.execute(
            select(AuthorizationAuditLog).where(
                AuthorizationAuditLog.action == "tenant.created",
                AuthorizationAuditLog.tenant_id == body["id"],
            )
        ).scalar_one()
        assert audit.actor_user_id == dev_user_id
        assert audit.outcome == "SUCCESS"
        assert audit.correlation_id == "tenant-create-test"
        assert audit.new_value == {
            "name": "Acme Security",
            "slug": payload["slug"],
            "external_iam_tenant_id": payload["external_iam_tenant_id"],
            "status": "ACTIVE",
        }


def test_tenant_creation_validation_and_duplicate_conflicts(client):
    from app.db import SessionLocal

    with SessionLocal() as db:
        dev_user = db.execute(select(IAMUser).where(IAMUser.external_iam_user_id == "dev-user")).scalar_one()
        now = _now()
        db.add(PlatformUserRole(user_id=dev_user.id, role="PLATFORM_ADMIN", status="ACTIVE", created_at=now, updated_at=now))
        db.commit()

    suffix = uuid4().hex[:10]
    payload = {"name": "Conflict Tenant", "slug": f"conflict-{suffix}", "external_iam_tenant_id": f"external-{suffix}"}
    assert client.post("/api/tenants", json=payload).status_code == 201

    duplicate_slug = client.post(
        "/api/tenants",
        json={"name": "Other Name", "slug": payload["slug"], "external_iam_tenant_id": f"other-{suffix}"},
    )
    assert duplicate_slug.status_code == 409
    assert duplicate_slug.json()["detail"] == "A tenant with this slug already exists."

    duplicate_external = client.post(
        "/api/tenants",
        json={"name": "Other Name", "slug": f"other-{suffix}", "external_iam_tenant_id": payload["external_iam_tenant_id"]},
    )
    assert duplicate_external.status_code == 409
    assert duplicate_external.json()["detail"] == "A tenant with this external IAM tenant ID already exists."

    for invalid in (
        {"name": "   ", "slug": f"blank-{suffix}", "external_iam_tenant_id": f"blank-{suffix}"},
        {"name": "Invalid Slug", "slug": "Invalid slug", "external_iam_tenant_id": f"invalid-{suffix}"},
        {"name": "Double Hyphen", "slug": "double--hyphen", "external_iam_tenant_id": f"double-{suffix}"},
    ):
        assert client.post("/api/tenants", json=invalid).status_code == 422


@pytest.mark.parametrize("role", ["TENANT_ADMIN", "SECURITY_ANALYST", "DEVELOPER", "VIEWER"])
def test_tenant_roles_cannot_create_or_list_platform_tenants(client, role):
    from app.db import SessionLocal

    with SessionLocal() as db:
        membership = db.execute(select(TenantUser).where(TenantUser.user_id == 1, TenantUser.tenant_id == 1)).scalar_one()
        membership.role = role
        db.commit()
    suffix = uuid4().hex[:10]
    assert client.get("/api/platform/tenants").status_code == 403
    assert client.post(
        "/api/tenants",
        json={"name": "Forbidden", "slug": f"forbidden-{suffix}", "external_iam_tenant_id": f"forbidden-{suffix}"},
    ).status_code == 403


def test_platform_grant_lifecycle_and_immediate_revocation(client, monkeypatch):
    from app.db import SessionLocal
    from app.settings import reset_settings

    with SessionLocal() as db:
        dev_user = db.execute(select(IAMUser).where(IAMUser.external_iam_user_id == "dev-user")).scalar_one()
        target = _seed_user(db, status="ACTIVE")
        now = _now()
        dev_grant = PlatformUserRole(
            user_id=dev_user.id,
            role="PLATFORM_ADMIN",
            status="ACTIVE",
            created_at=now,
            updated_at=now,
        )
        db.add(dev_grant)
        db.commit()
        dev_grant_id = dev_grant.id
        target_external_id = target.external_iam_user_id
        target_user_id = target.id

    assert client.get("/api/platform/administrators").status_code == 200
    assert client.patch(f"/api/platform/users/{target_user_id}", json={"status": "SUPERUSER"}).status_code == 422
    assert client.patch("/api/platform/tenants/1", json={"status": "ENABLED123"}).status_code == 422
    granted = client.post("/api/platform/administrators", json={"external_user_id": target_external_id})
    assert granted.status_code == 201, granted.text
    grant_id = granted.json()["grant_id"]
    assert client.delete(f"/api/platform/administrators/{grant_id}").status_code == 204
    assert client.delete(f"/api/platform/administrators/{dev_grant_id}").status_code == 409

    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("DEV_DEFAULT_TENANT", "false")
    reset_settings()
    with SessionLocal() as db:
        with pytest.raises(HTTPException) as exc_info:
            _resolve_context(db, {"sub": target_external_id, "tenant_id": "local-default"}, None)
        assert exc_info.value.status_code == 403


def test_user_and_tenant_deactivation_are_immediate(client, monkeypatch):
    from app.db import SessionLocal
    from app.settings import reset_settings

    with SessionLocal() as db:
        now = _now()
        user = _seed_user(db, status="ACTIVE")
        membership = TenantUser(tenant_id=1, user_id=user.id, role="VIEWER", status="ACTIVE", created_at=now, updated_at=now)
        db.add(membership)
        db.commit()
        subject = user.external_iam_user_id

    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("DEV_DEFAULT_TENANT", "false")
    reset_settings()
    with SessionLocal() as db:
        assert _resolve_context(db, {"sub": subject, "tenant_id": "local-default"}, None).roles == frozenset({"VIEWER"})
        user = db.execute(select(IAMUser).where(IAMUser.external_iam_user_id == subject)).scalar_one()
        user.status = "DISABLED"
        db.commit()
        with pytest.raises(HTTPException) as exc_info:
            _resolve_context(db, {"sub": subject, "tenant_id": "local-default"}, None)
        assert exc_info.value.status_code == 403
        user.status = "ACTIVE"
        tenant = db.get(Tenant, 1)
        tenant.status = "DISABLED"
        db.commit()
        with pytest.raises(HTTPException) as exc_info:
            _resolve_context(db, {"sub": subject, "tenant_id": "local-default"}, None)
        assert exc_info.value.status_code == 403


def test_membership_deactivation_is_immediate(client, monkeypatch):
    from app.db import SessionLocal
    from app.settings import reset_settings

    with SessionLocal() as db:
        now = _now()
        user = _seed_user(db, status="ACTIVE")
        membership = TenantUser(
            tenant_id=1,
            user_id=user.id,
            role="SECURITY_ANALYST",
            status="ACTIVE",
            created_at=now,
            updated_at=now,
        )
        db.add(membership)
        db.commit()
        subject = user.external_iam_user_id
        membership_id = membership.id

    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("DEV_DEFAULT_TENANT", "false")
    reset_settings()
    with SessionLocal() as db:
        context = _resolve_context(db, {"sub": subject, "tenant_id": "local-default"}, None)
        assert context.has_permission("analysis:run")
        membership = db.get(TenantUser, membership_id)
        membership.status = "DISABLED"
        db.commit()
        with pytest.raises(HTTPException) as exc_info:
            _resolve_context(db, {"sub": subject, "tenant_id": "local-default"}, None)
        assert exc_info.value.status_code == 403


def test_authorization_audit_metadata_contains_no_secrets(client):
    from app.db import SessionLocal

    with SessionLocal() as db:
        user = _seed_user(db)

    response = client.post(
        "/api/tenants/1/users",
        json={"external_user_id": user.external_iam_user_id, "role": "VIEWER"},
    )
    assert response.status_code == 201
    with SessionLocal() as db:
        records = db.execute(select(AuthorizationAuditLog)).scalars().all()
        serialized = " ".join(
            f"{record.action} {record.detail} {record.old_value} {record.new_value}" for record in records
        ).lower()
        assert "access_token" not in serialized
        assert "refresh_token" not in serialized
        assert "password" not in serialized
        assert "session_cookie" not in serialized
