"""Database-authoritative, tenant-bound investigation capabilities.

assigned_to stores a namespaced TenantUser id. Legacy free text is display-only
and never confers access. No broad permission is added to Developer.
"""

from __future__ import annotations

import re
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core.context import CurrentContext
from ...models import IAMUser, TenantUser, VexInvestigation
from .. import platform_service, tenant_role_assignment_service
from ..identity_verification_policy import verification_complete


def membership_key(member: TenantUser) -> str:
    return f"membership:{member.id}"


def membership(db: Session, tenant_id: int, *, user_id: int | None = None, key: str | None = None) -> TenantUser | None:
    query = select(TenantUser).where(TenantUser.tenant_id == tenant_id)
    if user_id is not None:
        query = query.where(TenantUser.user_id == user_id)
    elif key and re.fullmatch(r"membership:[1-9][0-9]{0,9}", key) and int(key[11:]) <= 2147483647:
        query = query.where(TenantUser.id == int(key[11:]))
    else:
        return None
    return db.scalar(query.execution_options(populate_existing=True))


def active_roles(db: Session, member: TenantUser | None) -> frozenset[str]:
    if member is None or member.status != "ACTIVE":
        return frozenset()
    user = db.get(IAMUser, member.user_id, populate_existing=True)
    if user is None or user.status != "ACTIVE" or not verification_complete(user):
        return frozenset()
    return tenant_role_assignment_service.effective_role_codes(db, member)


def actor_roles(db: Session, context: CurrentContext) -> frozenset[str]:
    user = db.get(IAMUser, context.user_id, populate_existing=True)
    if not user or user.status != "ACTIVE" or not verification_complete(user):
        return frozenset()
    if platform_service.get_effective_platform_grant(db, user):
        return frozenset({"TENANT_ADMIN"})
    return active_roles(db, membership(db, context.tenant_id, user_id=context.user_id))


def eligible_roles(roles: frozenset[str]) -> set[str]:
    if "TENANT_ADMIN" in roles:
        return {"SECURITY_ANALYST", "DEVELOPER"}
    if "SECURITY_ANALYST" in roles:
        return {"DEVELOPER"}
    return set()


def eligible_target(roles: frozenset[str], allowed: set[str]) -> bool:
    # A higher role cannot be disguised by an additional Developer role.
    return (
        bool(roles & allowed)
        and "TENANT_ADMIN" not in roles
        and not ("SECURITY_ANALYST" in roles and "SECURITY_ANALYST" not in allowed)
    )


def owner(db: Session, investigation: VexInvestigation, context: CurrentContext | None = None) -> dict[str, Any]:
    key = investigation.assigned_to
    member = membership(db, investigation.tenant_id, key=key)
    roles = active_roles(db, member)
    active = eligible_target(roles, {"SECURITY_ANALYST", "DEVELOPER"})
    return {
        "id": key,
        "label": (member.user.display_name or member.user.email or "Tenant user")
        if member
        else ("Assigned user is no longer active" if key else "Unassigned"),
        "active": active,
        "is_self": bool(active and context and member.user_id == context.user_id),
        "roles": sorted(roles),
    }


def capabilities(
    db: Session, context: CurrentContext | None, investigation: VexInvestigation, *, include_candidates: bool = True
) -> dict[str, Any]:
    roles = actor_roles(db, context) if context and context.tenant_id == investigation.tenant_id else frozenset()
    allowed = eligible_roles(roles)
    broad = bool(allowed and context.has_permission("vex:write"))
    assigned = owner(db, investigation, context)
    can_update = broad or ("DEVELOPER" in roles and assigned["is_self"])
    candidates = []
    if broad and include_candidates:
        for member in db.scalars(
            select(TenantUser).where(TenantUser.tenant_id == investigation.tenant_id, TenantUser.status == "ACTIVE")
        ).all():
            target_roles = active_roles(db, member)
            if eligible_target(target_roles, allowed):
                candidates.append(
                    {
                        "id": membership_key(member),
                        "label": member.user.display_name or member.user.email or "Tenant user",
                        "roles": sorted(target_roles),
                    }
                )
    return {
        "can_assign": broad,
        "can_unassign": broad
        and ("TENANT_ADMIN" in roles or not assigned["active"] or "SECURITY_ANALYST" not in assigned["roles"]),
        "can_update": can_update,
        "can_map": broad,
        "eligible_roles": sorted(allowed) if broad else [],
        "candidates": sorted(candidates, key=lambda item: item["label"].casefold()),
        "owner": assigned,
        "read_only_reason": None
        if can_update
        else (
            "This investigation must be assigned to you before you can update it. This investigation must be assigned by a Tenant Administrator or Security Analyst before you can update it."
            if "DEVELOPER" in roles and not investigation.assigned_to
            else (
                f"This investigation is assigned to {assigned['label']}. "
                if "DEVELOPER" in roles and investigation.assigned_to
                else ""
            )
            + "You can view this investigation, but only the assigned Developer, a Security Analyst, or Tenant Administrator can update it."
        ),
    }


def require_update(
    db: Session, context: CurrentContext, investigation: VexInvestigation, *, mapping: bool = False
) -> None:
    access = capabilities(db, context, investigation, include_candidates=False)
    if not access["can_map" if mapping else "can_update"]:
        raise HTTPException(
            403, access["read_only_reason"] or "You don't have permission to update this investigation."
        )


def require_assignment(db: Session, context: CurrentContext, investigation: VexInvestigation, key: str | None) -> None:
    access = capabilities(db, context, investigation, include_candidates=False)
    if not access["can_assign"]:
        raise HTTPException(403, "You don't have permission to assign VEX investigations.")
    if key is None:
        if not access["can_unassign"]:
            raise HTTPException(403, "You don't have permission to remove this assignment.")
        return
    member = membership(db, investigation.tenant_id, key=key)
    if member is None:
        raise HTTPException(403, "The selected user is not eligible for this tenant investigation.")
    if not eligible_target(active_roles(db, member), set(access["eligible_roles"])):
        raise HTTPException(403, "This user cannot be assigned to VEX investigations.")
