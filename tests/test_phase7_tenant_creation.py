from __future__ import annotations

import pytest
from app.core.identity_states import IdentityAuditEvent
from app.models import (
    AuthorizationAuditLog,
    EmailVerificationToken,
    PlatformUserRole,
    Tenant,
    TenantUser,
)
from sqlalchemy import func, select

from .phase7_helpers import seed_eligible_admin, seed_requester, tenant_payload


def test_atomic_api_creation_returns_safe_nested_contract(client):
    from app.db import SessionLocal

    with SessionLocal() as db:
        requester = seed_requester(db)
        requester_id = requester.id
        initial_admin = seed_eligible_admin(db, display_name="Initial Admin")
        payload = tenant_payload(
            initial_admin.id,
            name="  Engineering Security  ",
            slug="  ENGINEERING-SECURITY  ",
            external_iam_tenant_id=None,
        )

    response = client.post(
        "/api/tenants",
        json=payload,
        headers={"X-Correlation-ID": "phase7-create"},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["tenant"]["name"] == "Engineering Security"
    assert body["tenant"]["slug"] == "engineering-security"
    assert body["tenant"]["external_iam_tenant_id"] == "sbom-engineering-security"
    assert body["tenant"]["status"] == "ACTIVE"
    assert body["initial_administrator"] == {
        "user_id": initial_admin.id,
        "email": initial_admin.email,
        "display_name": "Initial Admin",
        "membership_status": "ACTIVE",
        "role": "TENANT_ADMIN",
    }
    serialized = str(body)
    assert "external_subject" not in serialized
    assert "external_iam_user_id" not in serialized
    assert "employee_id" not in serialized

    with SessionLocal() as db:
        tenant = db.scalar(
            select(Tenant).where(Tenant.id == body["tenant"]["id"])
        )
        memberships = db.scalars(
            select(TenantUser).where(TenantUser.tenant_id == tenant.id)
        ).all()
        assert len(memberships) == 1
        assert memberships[0].user_id == initial_admin.id
        assert memberships[0].role == "TENANT_ADMIN"
        assert memberships[0].status == "ACTIVE"
        assert db.scalar(
            select(func.count(PlatformUserRole.id)).where(
                PlatformUserRole.user_id == initial_admin.id
            )
        ) == 0
        assert db.scalar(
            select(func.count(EmailVerificationToken.id)).where(
                EmailVerificationToken.user_id == initial_admin.id
            )
        ) == 0
        actions = set(
            db.scalars(
                select(AuthorizationAuditLog.action).where(
                    AuthorizationAuditLog.correlation_id == "phase7-create"
                )
            )
        )
        assert {
            str(IdentityAuditEvent.PLATFORM_TENANT_CREATE_REQUESTED),
            str(IdentityAuditEvent.TENANT_INITIAL_ADMIN_VALIDATED),
            str(IdentityAuditEvent.PLATFORM_TENANT_CREATED),
            str(IdentityAuditEvent.TENANT_INITIAL_ADMIN_ASSIGNED),
        } <= actions
        assert requester_id != initial_admin.id


def test_missing_initial_admin_is_stable_422_and_creates_no_tenant(client):
    from app.db import SessionLocal

    with SessionLocal() as db:
        seed_requester(db)
        before = db.scalar(select(func.count(Tenant.id)))

    response = client.post(
        "/api/tenants",
        json={"name": "Orphan", "slug": "orphan-tenant"},
    )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "IAM_INITIAL_TENANT_ADMIN_REQUIRED"
    with SessionLocal() as db:
        assert db.scalar(select(func.count(Tenant.id))) == before


def test_duplicate_slug_and_external_id_have_specific_safe_conflicts(client):
    from app.db import SessionLocal

    with SessionLocal() as db:
        seed_requester(db)
        initial_admin = seed_eligible_admin(db)
        first = tenant_payload(initial_admin.id)

    assert client.post("/api/tenants", json=first).status_code == 201
    slug_conflict = client.post(
        "/api/tenants",
        json=tenant_payload(
            initial_admin.id,
            slug=first["slug"],
        ),
    )
    assert slug_conflict.status_code == 409
    assert slug_conflict.json()["detail"]["code"] == "IAM_TENANT_SLUG_CONFLICT"

    external_conflict = client.post(
        "/api/tenants",
        json=tenant_payload(
            initial_admin.id,
            external_iam_tenant_id=first["external_iam_tenant_id"],
        ),
    )
    assert external_conflict.status_code == 409
    assert (
        external_conflict.json()["detail"]["code"]
        == "IAM_TENANT_EXTERNAL_ID_CONFLICT"
    )


@pytest.mark.parametrize(
    ("overrides", "expected_code"),
    [
        ({"name": "   "}, "IAM_TENANT_NAME_INVALID"),
        ({"name": "bad\x00name"}, "IAM_TENANT_NAME_INVALID"),
        ({"name": "x" * 256}, "IAM_TENANT_NAME_INVALID"),
        ({"slug": "-leading"}, "IAM_TENANT_SLUG_INVALID"),
        ({"slug": "trailing-"}, "IAM_TENANT_SLUG_INVALID"),
        ({"slug": "double--hyphen"}, "IAM_TENANT_SLUG_INVALID"),
        ({"slug": "bad_symbol"}, "IAM_TENANT_SLUG_INVALID"),
        ({"slug": "xy"}, "IAM_TENANT_SLUG_INVALID"),
    ],
)
def test_tenant_name_and_slug_validation_uses_stable_codes(
    client,
    overrides,
    expected_code,
):
    from app.db import SessionLocal

    with SessionLocal() as db:
        seed_requester(db)
        initial_admin = seed_eligible_admin(db)
        payload = tenant_payload(initial_admin.id, **overrides)
    response = client.post("/api/tenants", json=payload)
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == expected_code
