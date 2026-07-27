from datetime import UTC, datetime

import pytest
from app.db import SessionLocal
from app.models import (
    AuthorizationRole,
    Tenant,
    TenantUserRoleAssignment,
)
from app.services import platform_service
from app.services import tenant_role_assignment_service as service
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .phase9_helpers import seed_role_membership


def test_cross_tenant_assignment_is_rejected_by_composite_foreign_key():
    with SessionLocal() as db:
        user, membership, _ = seed_role_membership(db)
        now = datetime.now(UTC)
        tenant = Tenant(
            name="Other",
            slug="other",
            external_iam_tenant_id="other",
            status="ACTIVE",
            created_at=now,
            updated_at=now,
        )
        db.add(tenant)
        db.flush()
        role = db.scalar(
            select(AuthorizationRole).where(AuthorizationRole.code == "DEVELOPER")
        )
        db.add(
            TenantUserRoleAssignment(
                tenant_id=tenant.id,
                tenant_user_id=membership.id,
                role_id=role.id,
                status="ACTIVE",
                is_primary=False,
                assignment_source="SYSTEM",
                assigned_at=now,
                version=1,
                created_at=now,
                updated_at=now,
            )
        )
        with pytest.raises((IntegrityError, RuntimeError)):
            db.flush()


def test_final_role_of_active_membership_cannot_be_revoked():
    with SessionLocal() as db:
        user, _membership, _ = seed_role_membership(db)
        with pytest.raises(service.AssignmentProblem) as caught:
            service.revoke_role(
                db,
                1,
                user.id,
                role_code="VIEWER",
                expected_version=1,
                replacement_primary_role_code=None,
                reason=None,
                actor_user_id=user.id,
                is_platform_admin=False,
            )
    assert caught.value.code.value == "IAM_ACTIVE_MEMBERSHIP_REQUIRES_ROLE"


def test_disabling_final_effective_tenant_admin_is_rejected():
    with SessionLocal() as db:
        user, _membership, _ = seed_role_membership(db, role="TENANT_ADMIN")
        with pytest.raises(HTTPException) as caught:
            platform_service.update_user_status(db, user.id, "DISABLED")
    assert caught.value.status_code == 409
    assert caught.value.detail["code"] == "IAM_LAST_TENANT_ADMIN_PROTECTED"
