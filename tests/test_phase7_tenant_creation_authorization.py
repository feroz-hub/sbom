from __future__ import annotations

import pytest
from app.models import PlatformUserRole
from sqlalchemy import select

from .phase7_helpers import seed_eligible_admin, seed_requester, tenant_payload


def test_normal_user_and_tenant_role_cannot_create_tenant(client):
    from app.db import SessionLocal

    with SessionLocal() as db:
        target = seed_eligible_admin(db)
        payload = tenant_payload(target.id)
    response = client.post("/api/tenants", json=payload)
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "IAM_PLATFORM_PERMISSION_DENIED"


def test_inactive_database_platform_grant_cannot_create(client):
    from app.db import SessionLocal

    with SessionLocal() as db:
        requester = seed_requester(db)
        target = seed_eligible_admin(db)
        grant = db.scalar(
            select(PlatformUserRole).where(
                PlatformUserRole.user_id == requester.id
            )
        )
        grant.status = "DISABLED"
        db.commit()
        payload = tenant_payload(target.id)
    response = client.post("/api/tenants", json=payload)
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "IAM_PLATFORM_PERMISSION_DENIED"


def test_effective_platform_admin_may_assign_self(client):
    from app.db import SessionLocal

    with SessionLocal() as db:
        requester = seed_requester(db)
        payload = tenant_payload(requester.id)
    response = client.post("/api/tenants", json=payload)
    assert response.status_code == 201
    assert (
        response.json()["initial_administrator"]["user_id"]
        == requester.id
    )


@pytest.mark.parametrize(
    ("status", "verified", "expected_code"),
    [
        ("PENDING", True, "IAM_ACCOUNT_PENDING_APPROVAL"),
        ("DISABLED", True, "IAM_ACCOUNT_DISABLED"),
        ("ACTIVE", False, "IAM_EMAIL_VERIFICATION_REQUIRED"),
    ],
)
def test_restricted_database_platform_admin_cannot_create(
    client,
    status,
    verified,
    expected_code,
):
    from app.db import SessionLocal

    with SessionLocal() as db:
        requester = seed_requester(db)
        target = seed_eligible_admin(db)
        requester.status = status
        requester.email_verified = verified
        requester.verification_required = not verified
        if not verified:
            requester.email_verified_at = None
        db.commit()
        payload = tenant_payload(target.id)
    response = client.post("/api/tenants", json=payload)
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == expected_code
