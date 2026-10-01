"""Configuration ownership, separate from tenant-owned operational data."""

from fastapi import Depends, HTTPException
from sqlalchemy import select

from ..core.context import get_bound_context
from ..models import Tenant


def current_configuration_tenant() -> int | None:
    context = get_bound_context()
    return context.tenant_id if context else None


def scope_clause(model, tenant_id):
    return model.tenant_id.is_(None) if tenant_id is None else model.tenant_id == tenant_id


def require_active_configuration_tenant(db, tenant_id):
    if tenant_id is not None and db.scalar(select(Tenant.status).where(Tenant.id == tenant_id)) != "ACTIVE":
        raise HTTPException(403, "An active tenant is required for configuration use")


def require_configuration_permission(family, action):
    from ..core.security import get_current_tenant_context

    def dependency(context=Depends(get_current_tenant_context)):
        scope = "tenant" if context.tenant_id is not None else "platform"
        if not context.has_permission(f"{scope}:{family}:{action}"):
            raise HTTPException(403, "Configuration permission is required")
        return context

    return dependency
