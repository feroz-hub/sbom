from app.db import SessionLocal
from app.models import TenantUserRoleAssignment, TenantUserRoleAssignmentHistory
from app.services.tenant_service import create_tenant_with_initial_admin
from sqlalchemy import select

from .phase7_helpers import seed_eligible_admin, seed_requester


def test_tenant_creation_atomically_creates_initial_primary_assignment():
    with SessionLocal() as db:
        requester = seed_requester(db)
        admin = seed_eligible_admin(db)
        result = create_tenant_with_initial_admin(
            db,
            actor_user_id=requester.id,
            name="Phase Nine Tenant",
            slug="phase-nine-tenant",
            external_iam_tenant_id="phase-nine-tenant",
            initial_admin_user_id=admin.id,
        )
        assignment = db.scalar(
            select(TenantUserRoleAssignment).where(
                TenantUserRoleAssignment.tenant_user_id == result.membership.id
            )
        )
        history = db.scalar(
            select(TenantUserRoleAssignmentHistory).where(
                TenantUserRoleAssignmentHistory.assignment_id == assignment.id
            )
        )
    assert assignment.status == "ACTIVE"
    assert assignment.is_primary is True
    assert assignment.assignment_source == "TENANT_CREATION"
    assert history.event_type == "GRANTED"
