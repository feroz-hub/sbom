"""Reusable seeds and request helpers for Phase 7 tenant creation tests."""

from __future__ import annotations

from uuid import uuid4

from app.models import IAMUser, PlatformUserRole
from sqlalchemy import select

from .phase6_helpers import seed_platform_grant, seed_user


def seed_requester(db) -> IAMUser:
    requester = db.scalar(
        select(IAMUser).where(IAMUser.external_iam_user_id == "dev-user")
    )
    if requester is None:
        requester = seed_user(
            db,
            email="dev-user@example.test",
            display_name="Development User",
        )
        requester.external_iam_user_id = "dev-user"
        requester.external_subject = "dev-user"
        db.flush()
    existing = db.scalar(
        select(PlatformUserRole).where(
            PlatformUserRole.user_id == requester.id,
            PlatformUserRole.status == "ACTIVE",
        )
    )
    if existing is None:
        seed_platform_grant(db, requester)
    db.commit()
    return requester


def seed_eligible_admin(db, **overrides) -> IAMUser:
    user = seed_user(db, **overrides)
    db.commit()
    return user


def tenant_payload(user_id: int, **overrides) -> dict:
    suffix = uuid4().hex[:12]
    payload = {
        "name": "Engineering Security",
        "slug": f"engineering-{suffix}",
        "external_iam_tenant_id": f"external-{suffix}",
        "initial_admin_user_id": user_id,
    }
    payload.update(overrides)
    return payload
