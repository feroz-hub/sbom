from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import pytest
from app.core.identity_states import IdentityAuditEvent
from app.models import AuthorizationAuditLog, IAMUser, PlatformUserRole, TenantUser
from app.services.identity_service import provision_local_identity
from sqlalchemy import func, select

pytestmark = pytest.mark.postgres


def test_concurrent_first_login_creates_exactly_one_identity_and_audit():
    from app.db import SessionLocal

    suffix = uuid4().hex
    claims = {
        "iss": "https://hcl-cs.example.test",
        "sub": f"concurrent-{suffix}",
        "email": f"concurrent-{suffix}@example.test",
        "name": "Concurrent User",
        "preferred_username": f"concurrent-{suffix}@example.test",
        "employee_id": f"00{suffix[:6]}",
        "department": "Security",
    }
    barrier = Barrier(2)

    def provision() -> int:
        with SessionLocal() as db:
            result = provision_local_identity(
                db,
                dict(claims),
                before_insert=lambda: barrier.wait(timeout=10),
            )
            user_id = result.user.id
            db.commit()
            return user_id

    with ThreadPoolExecutor(max_workers=2) as executor:
        user_ids = list(executor.map(lambda _index: provision(), range(2)))

    assert user_ids[0] == user_ids[1]
    with SessionLocal() as db:
        user_id = user_ids[0]
        assert db.scalar(
            select(func.count(IAMUser.id)).where(
                IAMUser.external_issuer == claims["iss"],
                IAMUser.external_subject == claims["sub"],
            )
        ) == 1
        assert db.scalar(
            select(func.count(AuthorizationAuditLog.id)).where(
                AuthorizationAuditLog.action == str(IdentityAuditEvent.USER_PROVISIONED),
                AuthorizationAuditLog.target_user_id == user_id,
            )
        ) == 1
        assert db.scalar(select(func.count(TenantUser.id)).where(TenantUser.user_id == user_id)) == 0
        assert db.scalar(
            select(func.count(PlatformUserRole.id)).where(PlatformUserRole.user_id == user_id)
        ) == 0


def test_concurrent_conflicting_profiles_preserve_one_composite_identity():
    from app.db import SessionLocal

    suffix = uuid4().hex
    barrier = Barrier(2)

    def provision(email_prefix: str) -> int:
        claims = {
            "iss": "https://hcl-cs.example.test",
            "sub": f"conflicting-{suffix}",
            "email": f"{email_prefix}-{suffix}@example.test",
            "name": f"{email_prefix} User",
            "preferred_username": f"{email_prefix}-{suffix}@example.test",
            "employee_id": f"00{suffix[:6]}",
            "department": "Security",
        }
        with SessionLocal() as db:
            result = provision_local_identity(
                db,
                claims,
                before_insert=lambda: barrier.wait(timeout=10),
            )
            user_id = result.user.id
            db.commit()
            return user_id

    with ThreadPoolExecutor(max_workers=2) as executor:
        user_ids = list(executor.map(provision, ("first", "second")))
    assert user_ids[0] == user_ids[1]
    with SessionLocal() as db:
        rows = db.scalars(
            select(IAMUser).where(
                IAMUser.external_issuer == "https://hcl-cs.example.test",
                IAMUser.external_subject == f"conflicting-{suffix}",
            )
        ).all()
        assert len(rows) == 1
        assert rows[0].email in {
            f"first-{suffix}@example.test",
            f"second-{suffix}@example.test",
        }
        assert rows[0].email_verified is False
        assert rows[0].verification_required is True
