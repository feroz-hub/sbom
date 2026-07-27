from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from app.core.identity_states import AuthorizationState, NextAction
from app.core.security import get_current_user
from app.models import AuthorizationAuditLog, IAMUser, PlatformUserRole, Tenant, TenantUser
from app.services.auth_context_service import resolve_authorization_state
from sqlalchemy import select


def _claims(suffix: str):
    return {
        "iss": "https://hcl-cs.example.test",
        "sub": f"context-{suffix}",
        "email": f"context-{suffix}@example.test",
        "name": "Context User",
        "preferred_username": f"context-{suffix}@example.test",
        "employee_id": f"00{suffix[:6]}",
        "department": "Security",
    }


def _seed_user(db, claims, *, status="ACTIVE", verified=True):
    now = datetime.now(UTC)
    user = IAMUser(
        external_iam_user_id=claims["sub"],
        external_issuer=claims["iss"],
        external_subject=claims["sub"],
        email=claims["email"],
        display_name=claims["name"],
        user_principal_name=claims["preferred_username"],
        employee_id=claims["employee_id"],
        department=claims["department"],
        status=status,
        email_verified=verified,
        email_verified_at=now if verified else None,
        verification_required=not verified,
        created_at=now,
        updated_at=now,
    )
    db.add(user)
    db.flush()
    return user


def _seed_tenant(db, suffix: str):
    now = datetime.now(UTC)
    tenant = Tenant(
        name=f"Tenant {suffix}",
        slug=f"tenant-{suffix}",
        external_iam_tenant_id=f"external-{suffix}",
        status="ACTIVE",
        created_at=now,
        updated_at=now,
    )
    db.add(tenant)
    db.flush()
    return tenant


@pytest.mark.parametrize(
    ("status", "verified", "expected", "action"),
    [
        ("DISABLED", True, AuthorizationState.ACCOUNT_DISABLED, NextAction.CONTACT_SUPPORT),
        ("PENDING", True, AuthorizationState.ACCOUNT_PENDING_APPROVAL, NextAction.WAIT_FOR_APPROVAL),
        ("ACTIVE", False, AuthorizationState.VERIFICATION_REQUIRED, NextAction.VERIFY_EMAIL),
        ("ACTIVE", True, AuthorizationState.NO_TENANT, NextAction.CONTACT_ADMIN),
    ],
)
def test_state_precedence_without_tenant(status, verified, expected, action):
    from app.db import SessionLocal

    claims = _claims(uuid4().hex)
    with SessionLocal() as db:
        user = _seed_user(db, claims, status=status, verified=verified)
        db.commit()
        result = resolve_authorization_state(db, user)
        assert result.status == expected
        assert result.next_action == action


def test_single_and_multiple_tenant_resolution():
    from app.db import SessionLocal

    suffix = uuid4().hex[:8]
    claims = _claims(suffix)
    now = datetime.now(UTC)
    with SessionLocal() as db:
        user = _seed_user(db, claims)
        first = _seed_tenant(db, f"a-{suffix}")
        db.add(
            TenantUser(
                tenant_id=first.id,
                user_id=user.id,
                role="VIEWER",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
            )
        )
        db.commit()
        single = resolve_authorization_state(db, user)
        assert single.status == AuthorizationState.READY
        assert single.selection_source == "AUTO_SINGLE"
        second = _seed_tenant(db, f"b-{suffix}")
        db.add(
            TenantUser(
                tenant_id=second.id,
                user_id=user.id,
                role="DEVELOPER",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
            )
        )
        db.commit()
        multiple = resolve_authorization_state(db, user)
        assert multiple.status == AuthorizationState.TENANT_SELECTION_REQUIRED
        selected = resolve_authorization_state(db, user, selected_tenant=second.slug)
        assert selected.status == AuthorizationState.READY
        assert selected.active_tenant.id == second.id
        assert selected.selection_source == "HEADER"


def test_platform_administrator_without_tenant_opens_platform():
    from app.db import SessionLocal

    claims = _claims(uuid4().hex)
    now = datetime.now(UTC)
    with SessionLocal() as db:
        user = _seed_user(db, claims)
        db.add(
            PlatformUserRole(
                user_id=user.id,
                role="PLATFORM_ADMIN",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
            )
        )
        db.commit()
        result = resolve_authorization_state(db, user)
        assert result.status == AuthorizationState.READY
        assert result.next_action == NextAction.OPEN_PLATFORM_ADMIN
        assert result.active_tenant is None
        assert result.is_platform_admin is True


@pytest.mark.parametrize(
    ("status", "verified", "expected"),
    [
        ("DISABLED", True, AuthorizationState.ACCOUNT_DISABLED),
        ("PENDING", True, AuthorizationState.ACCOUNT_PENDING_APPROVAL),
        ("ACTIVE", False, AuthorizationState.VERIFICATION_REQUIRED),
    ],
)
def test_platform_grant_does_not_override_local_or_verification_state(status, verified, expected):
    from app.db import SessionLocal

    claims = _claims(uuid4().hex)
    now = datetime.now(UTC)
    with SessionLocal() as db:
        user = _seed_user(db, claims, status=status, verified=verified)
        db.add(
            PlatformUserRole(
                user_id=user.id,
                role="PLATFORM_ADMIN",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
            )
        )
        db.commit()
        result = resolve_authorization_state(db, user)
        assert result.status == expected
        assert result.is_platform_admin is False


def test_inactive_memberships_and_tenants_are_excluded():
    from app.db import SessionLocal

    suffix = uuid4().hex[:8]
    claims = _claims(suffix)
    now = datetime.now(UTC)
    with SessionLocal() as db:
        user = _seed_user(db, claims)
        other_user = _seed_user(db, _claims(f"other-{suffix}"))
        inactive_membership_tenant = _seed_tenant(db, f"inactive-membership-{suffix}")
        inactive_tenant = _seed_tenant(db, f"inactive-tenant-{suffix}")
        inactive_tenant.status = "DISABLED"
        other_tenant = _seed_tenant(db, f"other-user-{suffix}")
        db.add_all(
            [
                TenantUser(
                    tenant_id=inactive_membership_tenant.id,
                    user_id=user.id,
                    role="VIEWER",
                    status="DISABLED",
                    created_at=now,
                    updated_at=now,
                ),
                TenantUser(
                    tenant_id=inactive_tenant.id,
                    user_id=user.id,
                    role="VIEWER",
                    status="ACTIVE",
                    created_at=now,
                    updated_at=now,
                ),
                TenantUser(
                    tenant_id=other_tenant.id,
                    user_id=other_user.id,
                    role="VIEWER",
                    status="ACTIVE",
                    created_at=now,
                    updated_at=now,
                ),
            ]
        )
        db.commit()
        result = resolve_authorization_state(db, user)
        assert result.status == AuthorizationState.NO_TENANT
        assert result.memberships == ()


def test_state_resolution_audits_pre_tenant_events_without_fake_tenant():
    from app.db import SessionLocal

    claims = _claims(uuid4().hex)
    with SessionLocal() as db:
        user = _seed_user(db, claims)
        db.commit()
        result = resolve_authorization_state(db, user, audit_resolution=True)
        db.commit()
        assert result.status == AuthorizationState.NO_TENANT
        rows = db.scalars(
            select(AuthorizationAuditLog).where(
                AuthorizationAuditLog.target_user_id == user.id
            )
        ).all()
        assert {row.action for row in rows} >= {"IAM_NO_TENANT", "IAM_AUTH_CONTEXT_RESOLVED"}
        assert all(row.tenant_id is None for row in rows)


def test_context_provisions_unverified_user_and_legacy_me_aliases_match(client, app):
    from app.db import SessionLocal

    claims = _claims(uuid4().hex)
    app.dependency_overrides[get_current_user] = lambda: claims
    try:
        response = client.get("/api/auth/context")
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "VERIFICATION_REQUIRED"
        assert response.json()["next_action"] == "VERIFY_EMAIL"
        assert response.json()["tenant_context"]["available_tenants"] == []
        legacy = client.get("/api/auth/me")
        versioned = client.get("/api/v1/auth/me")
        assert legacy.status_code == versioned.status_code == 200
        assert legacy.json() == versioned.json()
        assert legacy.json()["auth_context"]["status"] == "VERIFICATION_REQUIRED"
        with SessionLocal() as db:
            user = db.scalar(
                select(IAMUser).where(
                    IAMUser.external_issuer == claims["iss"],
                    IAMUser.external_subject == claims["sub"],
                )
            )
            assert user.status == "ACTIVE"
            assert user.email_verified is False
    finally:
        app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.parametrize(
    ("status", "verified", "expected"),
    [
        ("DISABLED", True, "ACCOUNT_DISABLED"),
        ("PENDING", True, "ACCOUNT_PENDING_APPROVAL"),
    ],
)
def test_context_and_me_aliases_remain_available_for_restricted_users(
    client,
    app,
    status,
    verified,
    expected,
):
    from app.db import SessionLocal

    claims = _claims(uuid4().hex)
    with SessionLocal() as db:
        _seed_user(db, claims, status=status, verified=verified)
        db.commit()
    app.dependency_overrides[get_current_user] = lambda: claims
    try:
        context = client.get("/api/auth/context")
        legacy = client.get("/api/auth/me")
        versioned = client.get("/api/v1/auth/me")
        assert context.status_code == legacy.status_code == versioned.status_code == 200
        assert context.json()["status"] == expected
        assert legacy.json() == versioned.json()
        assert legacy.json()["auth_context"]["status"] == expected
        assert legacy.json()["tenant_id"] is None
        assert legacy.json()["permissions"] == []
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_unauthorized_tenant_header_returns_stable_error(client, app):
    from app.db import SessionLocal

    claims = _claims(uuid4().hex)
    with SessionLocal() as db:
        user = _seed_user(db, claims)
        db.commit()
    app.dependency_overrides[get_current_user] = lambda: claims
    try:
        response = client.get("/api/auth/context", headers={"X-Tenant-ID": "not-authorized"})
        assert response.status_code == 403
        assert response.json()["detail"]["code"] == "IAM_UNAUTHORIZED_TENANT"
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_jwt_tenant_hint_does_not_authorize_auth_context(client, app):
    from app.db import SessionLocal

    claims = _claims(uuid4().hex)
    claims["tenant_id"] = "local-default"
    with SessionLocal() as db:
        _seed_user(db, claims)
        db.commit()
    app.dependency_overrides[get_current_user] = lambda: claims
    try:
        response = client.get("/api/auth/context")
        assert response.status_code == 200
        assert response.json()["status"] == "NO_TENANT"
        assert response.json()["tenant_context"]["active_tenant"] is None
    finally:
        app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/projects"),
        ("POST", "/api/sboms/upload"),
        ("GET", "/api/runs/1/findings"),
        ("POST", "/api/projects/1/reports/fda-510k-sbom/export"),
        ("GET", "/api/tenants/1/users"),
        ("GET", "/api/platform/administrators"),
    ],
)
def test_unverified_user_is_blocked_from_application_routes(client, app, method, path):
    claims = _claims(uuid4().hex)
    app.dependency_overrides[get_current_user] = lambda: claims
    try:
        response = client.request(method, path)
        assert response.status_code == 403, response.text
        assert response.json()["detail"]["code"] == "IAM_EMAIL_VERIFICATION_REQUIRED"
        context = client.get("/api/auth/context")
        assert context.status_code == 200
        assert context.json()["status"] == "VERIFICATION_REQUIRED"
    finally:
        app.dependency_overrides.pop(get_current_user, None)
