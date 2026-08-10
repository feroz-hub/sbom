"""Platform administrators sign in to PLATFORM context, not tenant context.

A platform administrator can reach every tenant in the deployment. That reach
is authority, not membership: it must never turn sign-in into a mandatory
"pick one of N tenants" step (which does not scale past a handful of tenants),
and it must never silently widen a tenant-scoped API into a cross-tenant one.

These tests pin the API contract the frontend bootstrap depends on:
  * no explicit tenant  -> READY, ``tenant_id`` null, no selection required
  * explicit tenant     -> tenant context, without creating a membership
  * platform endpoints  -> usable with no X-Tenant-ID
  * tenant endpoints    -> still require explicit tenant context
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from app.core.security import get_current_user
from app.models import Tenant, TenantUser
from sqlalchemy import func, select

from .phase6_helpers import identity_claims, seed_membership, seed_platform_grant, seed_user


def _seed_tenant(db, label: str) -> Tenant:
    timestamp = datetime.now(UTC)
    suffix = uuid4().hex[:12]
    tenant = Tenant(
        name=f"Tenant {label} {suffix}",
        slug=f"tenant-{label}-{suffix}",
        external_iam_tenant_id=f"external-{label}-{suffix}",
        status="ACTIVE",
        created_at=timestamp,
        updated_at=timestamp,
    )
    db.add(tenant)
    db.flush()
    return tenant


def _seed_platform_admin(db, *, membership_tenants: int = 0) -> tuple[dict, list[int]]:
    user = seed_user(db)
    seed_platform_grant(db, user)
    tenant_ids: list[int] = []
    for index in range(membership_tenants):
        tenant = _seed_tenant(db, f"member-{index}")
        seed_membership(db, user, tenant_id=tenant.id, role="TENANT_ADMIN")
        tenant_ids.append(tenant.id)
    db.commit()
    return identity_claims(user), tenant_ids


def _seed_tenant_user(db, *, memberships: int) -> tuple[dict, list[int]]:
    user = seed_user(db)
    tenant_ids: list[int] = []
    for index in range(memberships):
        tenant = _seed_tenant(db, f"plain-{index}")
        seed_membership(db, user, tenant_id=tenant.id, role="VIEWER")
        tenant_ids.append(tenant.id)
    db.commit()
    return identity_claims(user), tenant_ids


def _as(app, claims: dict):
    app.dependency_overrides[get_current_user] = lambda: claims


def test_platform_admin_without_memberships_is_ready_in_platform_context(client, app):
    from app.db import SessionLocal

    with SessionLocal() as db:
        # Tenants exist in the deployment; none of them is a membership.
        _seed_tenant(db, "unrelated")
        claims, _ = _seed_platform_admin(db)
    _as(app, claims)
    try:
        response = client.get("/api/auth/me")
        assert response.status_code == 200, response.text
        body = response.json()
        context = body["auth_context"]
        assert body["is_platform_admin"] is True
        assert body["tenant_id"] is None
        assert context["status"] == "READY"
        assert context["next_action"] == "OPEN_PLATFORM_ADMIN"
        assert context["tenant_context"]["selection_required"] is False
        assert context["tenant_context"]["active_tenant"] is None
        assert context["tenant_context"]["available_tenants"] == []
        # Platform identity and permissions are retained without a tenant.
        assert "PLATFORM_ADMIN" in body["roles"]
        assert "platform:admin" in body["permissions"]
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_platform_admin_with_one_membership_still_defaults_to_platform_context(client, app):
    from app.db import SessionLocal

    with SessionLocal() as db:
        claims, tenant_ids = _seed_platform_admin(db, membership_tenants=1)
    _as(app, claims)
    try:
        body = client.get("/api/auth/me").json()
        context = body["auth_context"]
        assert body["tenant_id"] is None
        assert context["status"] == "READY"
        assert context["tenant_context"]["selection_required"] is False
        # The membership is offered to the switcher, not auto-entered.
        assert [tenant["id"] for tenant in context["tenant_context"]["available_tenants"]] == tenant_ids
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_a_hundred_reachable_tenants_never_require_platform_admin_selection(client, app):
    from app.db import SessionLocal

    with SessionLocal() as db:
        claims, _ = _seed_platform_admin(db)
        reachable = [_seed_tenant(db, f"reach-{index}") for index in range(100)]
        reachable_ids = [tenant.id for tenant in reachable]
        db.commit()
    _as(app, claims)
    try:
        body = client.get("/api/auth/me").json()
        context = body["auth_context"]
        assert context["status"] == "READY"
        assert context["tenant_context"]["selection_required"] is False
        assert context["tenant_context"]["available_tenants"] == []
        assert body["tenant_id"] is None
        # None of the reachable tenants became a membership.
        with SessionLocal() as db:
            assert (
                db.scalar(
                    select(func.count(TenantUser.id)).where(
                        TenantUser.tenant_id.in_(reachable_ids)
                    )
                )
                == 0
            )
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        # Keep the session-scoped database small for the rest of the suite.
        with SessionLocal() as db:
            db.query(Tenant).filter(Tenant.id.in_(reachable_ids)).delete(
                synchronize_session=False
            )
            db.commit()


def test_explicit_tenant_selection_enters_tenant_context_without_a_membership(client, app):
    from app.db import SessionLocal

    with SessionLocal() as db:
        claims, _ = _seed_platform_admin(db)
        target = _seed_tenant(db, "explicit")
        target_id = target.id
        db.commit()
    _as(app, claims)
    try:
        body = client.get("/api/auth/me", headers={"X-Tenant-ID": str(target_id)}).json()
        context = body["auth_context"]
        assert body["tenant_id"] == target_id
        assert context["status"] == "READY"
        assert context["tenant_context"]["selection_source"] == "HEADER"
        assert context["tenant_context"]["active_tenant"]["id"] == target_id
        # Platform authority granted the context; no membership was created.
        assert context["tenant_context"]["active_tenant"]["membership_status"] is None
        assert context["tenant_context"]["available_tenants"] == []
        with SessionLocal() as db:
            assert (
                db.scalar(
                    select(func.count(TenantUser.id)).where(
                        TenantUser.tenant_id == target_id
                    )
                )
                == 0
            )
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_platform_apis_work_without_tenant_context(client, app):
    from app.db import SessionLocal

    with SessionLocal() as db:
        claims, _ = _seed_platform_admin(db)
    _as(app, claims)
    try:
        for path in (
            "/api/platform/tenants",
            "/api/platform/administrators",
            "/api/platform/users",
        ):
            response = client.get(path)
            assert response.status_code == 200, f"{path}: {response.text}"
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_tenant_scoped_api_still_requires_explicit_tenant_context(client, app):
    from app.db import SessionLocal

    with SessionLocal() as db:
        claims, _ = _seed_platform_admin(db)
        target = _seed_tenant(db, "scoped")
        target_id = target.id
        db.commit()
    _as(app, claims)
    try:
        unscoped = client.get("/api/projects")
        assert unscoped.status_code == 403
        assert unscoped.json()["detail"]["code"] == "IAM_NO_TENANT"

        scoped = client.get("/api/projects", headers={"X-Tenant-ID": str(target_id)})
        assert scoped.status_code == 200, scoped.text
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_normal_user_with_one_membership_is_auto_selected(client, app):
    from app.db import SessionLocal

    with SessionLocal() as db:
        claims, tenant_ids = _seed_tenant_user(db, memberships=1)
    _as(app, claims)
    try:
        body = client.get("/api/auth/me").json()
        context = body["auth_context"]
        assert body["is_platform_admin"] is False
        assert body["tenant_id"] == tenant_ids[0]
        assert context["status"] == "READY"
        assert context["tenant_context"]["selection_source"] == "AUTO_SINGLE"
        assert context["tenant_context"]["selection_required"] is False
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_normal_user_with_several_memberships_must_select(client, app):
    from app.db import SessionLocal

    with SessionLocal() as db:
        claims, tenant_ids = _seed_tenant_user(db, memberships=2)
    _as(app, claims)
    try:
        body = client.get("/api/auth/me").json()
        context = body["auth_context"]
        assert body["tenant_id"] is None
        assert context["status"] == "TENANT_SELECTION_REQUIRED"
        assert context["next_action"] == "SELECT_TENANT"
        assert context["tenant_context"]["selection_required"] is True
        assert sorted(
            tenant["id"] for tenant in context["tenant_context"]["available_tenants"]
        ) == sorted(tenant_ids)

        # And a tenant-scoped API stays closed until one is chosen.
        blocked = client.get("/api/projects")
        assert blocked.status_code == 403
        assert blocked.json()["detail"]["code"] == "IAM_TENANT_SELECTION_REQUIRED"
    finally:
        app.dependency_overrides.pop(get_current_user, None)
