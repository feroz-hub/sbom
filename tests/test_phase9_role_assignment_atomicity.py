import pytest
from app.db import SessionLocal
from app.models import TenantUserRoleAssignment, TenantUserRoleAssignmentHistory
from app.services import tenant_role_assignment_service as service
from sqlalchemy import func, select

from .phase9_helpers import seed_role_membership


def test_invalid_complete_replacement_rolls_back_assignments_and_history():
    with SessionLocal() as db:
        user, membership, _ = seed_role_membership(db)
        before_assignments = db.scalar(
            select(func.count(TenantUserRoleAssignment.id)).where(
                TenantUserRoleAssignment.tenant_user_id == membership.id
            )
        )
        before_history = db.scalar(
            select(func.count(TenantUserRoleAssignmentHistory.id)).where(
                TenantUserRoleAssignmentHistory.tenant_user_id == membership.id
            )
        )
        with pytest.raises(service.AssignmentProblem):
            service.replace_roles(
                db,
                1,
                user.id,
                role_codes=["DOES_NOT_EXIST"],
                primary_role_code="DOES_NOT_EXIST",
                expected_version=1,
                reason=None,
                actor_user_id=user.id,
                is_platform_admin=False,
            )
        assert db.scalar(
            select(func.count(TenantUserRoleAssignment.id)).where(
                TenantUserRoleAssignment.tenant_user_id == membership.id
            )
        ) == before_assignments
        assert db.scalar(
            select(func.count(TenantUserRoleAssignmentHistory.id)).where(
                TenantUserRoleAssignmentHistory.tenant_user_id == membership.id
            )
        ) == before_history
