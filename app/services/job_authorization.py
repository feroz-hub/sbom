"""Live authorization for user-triggered background jobs from the trusted broker."""

from fastapi import HTTPException
from sqlalchemy import select

from ..core.context import CurrentContext
from ..models import IAMUser, Tenant, TenantUser
from .identity_verification_policy import verification_complete
from .tenant_role_assignment_service import effective_permissions, effective_role_codes


def authorize_job_actor(db, *, actor_user_id: int | None, tenant_id: int, permission: str) -> CurrentContext:
    if type(actor_user_id) is not int or actor_user_id <= 0 or type(tenant_id) is not int or tenant_id <= 0:
        raise HTTPException(403, "Background job authorization denied")
    user = db.get(IAMUser, actor_user_id)
    tenant = db.get(Tenant, tenant_id)
    member = db.scalar(
        select(TenantUser).where(
            TenantUser.user_id == actor_user_id, TenantUser.tenant_id == tenant_id, TenantUser.status == "ACTIVE"
        )
    )
    if not user or user.status != "ACTIVE" or not verification_complete(user):
        raise HTTPException(403, "Background job authorization denied")
    if not tenant or tenant.status != "ACTIVE" or not member:
        raise HTTPException(403, "Background job authorization denied")
    permissions = effective_permissions(db, member, actor_user_id=user.id)
    context = CurrentContext(
        user.id,
        user.external_iam_user_id,
        user.email,
        user.display_name,
        tenant.id,
        tenant.external_iam_tenant_id,
        effective_role_codes(db, member, actor_user_id=user.id),
        permissions,
    )
    if not context.has_permission(permission):
        raise HTTPException(403, "Background job authorization denied")
    return context
