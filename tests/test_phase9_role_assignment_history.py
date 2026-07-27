from app.db import SessionLocal
from app.models import TenantUserRoleAssignmentHistory
from app.services import tenant_role_assignment_service as service
from sqlalchemy import select

from .phase9_helpers import seed_role_membership


def test_grant_and_revoke_append_history_with_versions():
    with SessionLocal() as db:
        user, membership, _ = seed_role_membership(db)
        service.grant_role(
            db,
            1,
            user.id,
            role_code="DEVELOPER",
            expected_version=1,
            make_primary=False,
            reason="grant",
            actor_user_id=user.id,
            is_platform_admin=False,
        )
        service.revoke_role(
            db,
            1,
            user.id,
            role_code="DEVELOPER",
            expected_version=2,
            replacement_primary_role_code=None,
            reason="revoke",
            actor_user_id=user.id,
            is_platform_admin=False,
        )
        rows = list(
            db.scalars(
                select(TenantUserRoleAssignmentHistory)
                .where(TenantUserRoleAssignmentHistory.tenant_user_id == membership.id)
                .order_by(TenantUserRoleAssignmentHistory.id)
            )
        )
    assert [row.event_type for row in rows][-2:] == ["GRANTED", "REVOKED"]
    assert rows[-1].before_membership_version == 2
    assert rows[-1].after_membership_version == 3
