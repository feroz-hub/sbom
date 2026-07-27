from __future__ import annotations

import pytest
from app.core.identity_states import IdentityAuditEvent
from app.models import AuthorizationAuditLog, Projects, Tenant, TenantUser
from app.services.tenant_service import (
    TenantCreationError,
    create_tenant_with_initial_admin,
)
from sqlalchemy import func, select

from .phase7_helpers import seed_eligible_admin, seed_requester, tenant_payload


@pytest.mark.parametrize("failure_stage", ["tenant_flushed", "membership_flushed", "audit_added"])
def test_forced_failure_rolls_back_tenant_membership_and_success_audits(
    failure_stage,
):
    from app.db import SessionLocal

    with SessionLocal() as db:
        requester = seed_requester(db)
        initial_admin = seed_eligible_admin(db)
        payload = tenant_payload(initial_admin.id)
        before_tenants = db.scalar(select(func.count(Tenant.id)))
        before_memberships = db.scalar(select(func.count(TenantUser.id)))
        db.rollback()

        def fail(stage: str) -> None:
            if stage == failure_stage:
                raise RuntimeError("injected phase7 failure")

        with pytest.raises(TenantCreationError):
            create_tenant_with_initial_admin(
                db,
                actor_user_id=requester.id,
                failure_hook=fail,
                **payload,
            )

        assert db.scalar(select(func.count(Tenant.id))) == before_tenants
        assert (
            db.scalar(select(func.count(TenantUser.id))) == before_memberships
        )
        success_actions = {
            str(IdentityAuditEvent.PLATFORM_TENANT_CREATED),
            str(IdentityAuditEvent.TENANT_INITIAL_ADMIN_ASSIGNED),
        }
        assert not set(
            db.scalars(
                select(AuthorizationAuditLog.action).where(
                    AuthorizationAuditLog.action.in_(success_actions)
                )
            )
        )
        failure_actions = set(
            db.scalars(
                select(AuthorizationAuditLog.action).where(
                    AuthorizationAuditLog.outcome == "FAILED"
                )
            )
        )
        assert str(IdentityAuditEvent.TENANT_CREATION_ROLLED_BACK) in failure_actions


def test_global_tenant_write_guard_remains_enabled(monkeypatch):
    from app.db import SessionLocal
    from app.settings import get_settings

    monkeypatch.setattr(get_settings(), "auth_enabled", True)
    with SessionLocal() as db:
        db.add(
            Projects(
                project_name="must-not-write",
                project_status=1,
                tenant_id=None,
            )
        )
        with pytest.raises(RuntimeError, match="Tenant context is required"):
            db.flush()
        db.rollback()
