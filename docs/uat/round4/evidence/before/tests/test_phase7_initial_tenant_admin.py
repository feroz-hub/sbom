from __future__ import annotations

import pytest
from app.core.identity_states import AuthorizationState, NextAction
from app.models import TenantUser
from app.services.auth_context_service import resolve_authorization_state
from app.services.tenant_service import ensure_not_last_active_tenant_admin
from fastapi import HTTPException
from sqlalchemy import select

from .phase6_helpers import identity_claims, seed_membership
from .phase7_helpers import seed_eligible_admin, seed_requester, tenant_payload


@pytest.mark.parametrize(
    ("user_options", "expected_code"),
    [
        ({"status": "PENDING"}, "IAM_ACCOUNT_PENDING_APPROVAL"),
        ({"status": "DISABLED"}, "IAM_ACCOUNT_DISABLED"),
        ({"verified": False}, "IAM_EMAIL_VERIFICATION_REQUIRED"),
    ],
)
def test_ineligible_initial_admin_is_rejected_without_membership(
    client,
    user_options,
    expected_code,
):
    from app.db import SessionLocal

    with SessionLocal() as db:
        seed_requester(db)
        user = seed_eligible_admin(db, **user_options)
        payload = tenant_payload(user.id)
    response = client.post("/api/tenants", json=payload)
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == expected_code
    with SessionLocal() as db:
        assert db.scalar(
            select(TenantUser.id).where(TenantUser.user_id == user.id)
        ) is None


def test_unknown_initial_admin_is_not_created(client):
    from app.db import SessionLocal

    with SessionLocal() as db:
        seed_requester(db)
    response = client.post("/api/tenants", json=tenant_payload(999_999_999))
    assert response.status_code == 404
    assert (
        response.json()["detail"]["code"]
        == "IAM_INITIAL_TENANT_ADMIN_NOT_FOUND"
    )


def test_existing_roles_do_not_block_eligible_admin_and_context_selects_new_tenant(
    client,
):
    from app.db import SessionLocal

    with SessionLocal() as db:
        seed_requester(db)
        user = seed_eligible_admin(db)
        payload = tenant_payload(user.id)
    created = client.post("/api/tenants", json=payload)
    assert created.status_code == 201
    tenant_id = created.json()["tenant"]["id"]

    with SessionLocal() as db:
        stored_user = db.get(type(user), user.id)
        state = resolve_authorization_state(db, stored_user)
        assert state.status == AuthorizationState.READY
        assert state.next_action == NextAction.OPEN_DASHBOARD
        assert state.active_tenant.id == tenant_id
        assert state.selection_source == "AUTO_SINGLE"

        seed_membership(db, stored_user, tenant_id=1, role="VIEWER")
        db.commit()
        state = resolve_authorization_state(db, stored_user)
        assert state.status == AuthorizationState.TENANT_SELECTION_REQUIRED
        assert len(state.memberships) == 2


def test_initial_admin_receives_existing_last_admin_protection(client):
    from app.db import SessionLocal

    with SessionLocal() as db:
        seed_requester(db)
        user = seed_eligible_admin(db)
        payload = tenant_payload(user.id)
    created = client.post("/api/tenants", json=payload)
    assert created.status_code == 201

    with SessionLocal() as db:
        membership = db.scalar(
            select(TenantUser).where(
                TenantUser.tenant_id == created.json()["tenant"]["id"]
            )
        )
        with pytest.raises(HTTPException) as exc:
            ensure_not_last_active_tenant_admin(
                db,
                membership,
                next_role="VIEWER",
            )
        assert exc.value.status_code == 409


def test_initial_admin_sees_new_tenant_through_context_me_and_listing(
    client,
    app,
):
    from app.core.security import get_current_user
    from app.db import SessionLocal

    with SessionLocal() as db:
        seed_requester(db)
        user = seed_eligible_admin(db)
        user_id = user.id
        claims = identity_claims(user)
        payload = tenant_payload(user_id)
    created = client.post("/api/tenants", json=payload)
    assert created.status_code == 201
    tenant_id = created.json()["tenant"]["id"]

    app.dependency_overrides[get_current_user] = lambda: claims
    try:
        context = client.get("/api/auth/context")
        assert context.status_code == 200, context.text
        context_body = context.json()
        assert context_body["status"] == "READY"
        assert context_body["next_action"] == "OPEN_DASHBOARD"
        assert (
            context_body["tenant_context"]["active_tenant"]["id"]
            == tenant_id
        )
        assert (
            context_body["tenant_context"]["selection_source"]
            == "AUTO_SINGLE"
        )

        me = client.get("/api/auth/me")
        legacy_me = client.get("/api/v1/auth/me")
        assert me.status_code == legacy_me.status_code == 200
        assert me.json()["tenant_id"] == legacy_me.json()["tenant_id"] == tenant_id

        listed = client.get("/api/tenants")
        assert listed.status_code == 200
        assert [tenant["id"] for tenant in listed.json()] == [tenant_id]
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_unrelated_user_cannot_select_or_list_new_tenant_and_jwt_hint_is_ignored(
    client,
    app,
):
    from app.core.security import get_current_user
    from app.db import SessionLocal

    with SessionLocal() as db:
        seed_requester(db)
        initial_admin = seed_eligible_admin(db)
        payload = tenant_payload(initial_admin.id)
    created = client.post("/api/tenants", json=payload)
    assert created.status_code == 201
    new_tenant_id = created.json()["tenant"]["id"]

    with SessionLocal() as db:
        unrelated = seed_eligible_admin(db)
        seed_membership(db, unrelated, tenant_id=1, role="VIEWER")
        db.commit()
        claims = identity_claims(unrelated, tenant_id=str(new_tenant_id))

    app.dependency_overrides[get_current_user] = lambda: claims
    try:
        denied = client.get(
            "/api/auth/context",
            headers={"X-Tenant-ID": str(new_tenant_id)},
        )
        assert denied.status_code == 403
        assert denied.json()["detail"]["code"] == "IAM_UNAUTHORIZED_TENANT"

        token_hint = client.get("/api/auth/context")
        assert token_hint.status_code == 200
        assert token_hint.json()["tenant_context"]["active_tenant"]["id"] == 1
        assert (
            token_hint.json()["tenant_context"]["selection_source"]
            == "AUTO_SINGLE"
        )

        listed = client.get("/api/tenants")
        assert listed.status_code == 200
        assert [tenant["id"] for tenant in listed.json()] == [1]
    finally:
        app.dependency_overrides.pop(get_current_user, None)
