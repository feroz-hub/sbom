"""Reusable Phase 9 role-assignment test seeds."""

from __future__ import annotations

from app.models import TenantUser
from app.services.tenant_role_assignment_service import create_initial_assignment

from .phase6_helpers import now, seed_user


def seed_role_membership(
    db,
    *,
    role: str = "VIEWER",
    tenant_id: int = 1,
    user=None,
    source: str = "SYSTEM",
):
    user = user or seed_user(db)
    timestamp = now()
    membership = TenantUser(
        tenant_id=tenant_id,
        user_id=user.id,
        role=role,
        role_assignment_version=1,
        status="ACTIVE",
        created_at=timestamp,
        updated_at=timestamp,
    )
    db.add(membership)
    db.flush()
    assignment = create_initial_assignment(
        db,
        membership,
        role_code=role,
        actor_user_id=user.id,
        source=source,
    )
    db.commit()
    return user, membership, assignment
