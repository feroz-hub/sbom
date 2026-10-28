"""V2 global account lifecycle is not ordinary Platform Admin authority."""

import pytest
from app.db import SessionLocal
from app.models import IAMUser, TenantUser

from tests.phase6_helpers import seed_dev_platform_admin, seed_membership, seed_user


@pytest.mark.parametrize(
    ("before", "requested"),
    [
        ("PENDING", "ACTIVE"),
        ("ACTIVE", "DISABLED"),
        ("DISABLED", "ACTIVE"),
        ("ACTIVE", "ACTIVE"),
        ("ACTIVE", "PENDING"),
        ("ACTIVE", "SUSPENDED"),
    ],
)
def test_platform_admin_cannot_change_global_account_status(client, before, requested):
    with SessionLocal() as db:
        seed_dev_platform_admin(db)
        target = seed_user(db, status=before)
        membership = seed_membership(db, target)
        user_id, member_id = target.id, membership.id
        db.commit()
    for route in (f"/api/platform/users/{user_id}/status", f"/api/platform/users/{user_id}"):
        response = client.patch(route, json={"status": requested, "reason": "V2 denial"})
        assert response.status_code == 403, response.text
    with SessionLocal() as db:
        assert db.get(IAMUser, user_id).status == before
        assert db.get(TenantUser, member_id).status == "ACTIVE"


def test_platform_admin_cannot_mark_email_verified(client):
    with SessionLocal() as db:
        seed_dev_platform_admin(db)
        target = seed_user(db, verified=False)
        user_id = target.id
        db.commit()
    response = client.patch(f"/api/platform/users/{user_id}/status", json={"status": "ACTIVE", "email_verified": True})
    assert response.status_code == 403
    with SessionLocal() as db:
        assert not db.get(IAMUser, user_id).email_verified
