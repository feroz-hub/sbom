"""Tenant and IAM user business logic."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..core.permissions import (
    MEMBERSHIP_STATUSES,
    TENANT_ROLES,
    normalize_role,
    permissions_for_roles,
)
from ..models import IAMUser, Tenant, TenantUser
from ..settings import get_settings


def _tenant_identity_filter(tenant_model, value: str):
    clauses = [tenant_model.slug == value, tenant_model.external_iam_tenant_id == value]
    if value.isdigit():
        clauses.append(tenant_model.id == int(value))
    return or_(*clauses)


def get_or_create_user_from_claims(db: Session, claims: dict[str, Any]) -> tuple[IAMUser, bool]:
    """Discover an HCL.CS subject locally; new identities are PENDING and unauthorized."""
    external_id = str(claims["sub"])
    now = datetime.now(UTC)
    user = db.execute(select(IAMUser).where(IAMUser.external_iam_user_id == external_id)).scalar_one_or_none()

    needs_commit = False
    if user is None:
        user = IAMUser(
            external_iam_user_id=external_id,
            email=claims.get("email"),
            display_name=claims.get("name") or claims.get("preferred_username"),
            status="PENDING",
            created_at=now,
            updated_at=now,
            last_login_at=now,
        )
        db.add(user)
        db.flush()
        needs_commit = True
    else:
        changed = False
        new_email = claims.get("email")
        new_name = claims.get("name") or claims.get("preferred_username")

        if new_email and user.email != new_email:
            user.email = new_email
            changed = True
        if new_name and user.display_name != new_name:
            user.display_name = new_name
            changed = True

        last_login = user.last_login_at
        if last_login is not None:
            if last_login.tzinfo is None:
                time_diff = (datetime.now(UTC).replace(tzinfo=None) - last_login).total_seconds()
            else:
                time_diff = (now - last_login).total_seconds()
        else:
            time_diff = 999999

        if time_diff > 300:
            user.last_login_at = now
            user.updated_at = now
            changed = True

        if changed:
            db.add(user)
            db.flush()
            needs_commit = True

    return user, needs_commit


def validate_tenant_role(role: str) -> str:
    normalized = normalize_role(role)
    if normalized not in TENANT_ROLES:
        raise HTTPException(status_code=422, detail="Invalid tenant role")
    return normalized


def validate_membership_status(status_value: str) -> str:
    normalized = status_value.strip().upper()
    if normalized not in MEMBERSHIP_STATUSES:
        raise HTTPException(status_code=422, detail="Invalid membership status")
    return normalized


def get_user_memberships(db: Session, user_id: int) -> list[tuple[TenantUser, Tenant]]:
    return list(
        db.execute(
            select(TenantUser, Tenant)
            .join(Tenant, Tenant.id == TenantUser.tenant_id)
            .where(
                TenantUser.user_id == user_id,
                TenantUser.status == "ACTIVE",
                Tenant.status == "ACTIVE",
            )
        ).all()
    )


def resolve_active_tenant(
    db: Session,
    user: IAMUser,
    memberships: list[tuple[TenantUser, Tenant]],
    *,
    selected_tenant: str | None,
    tenant_claim: Any,
    is_platform_admin: bool,
    auth_enabled: bool,
    allow_platform_context: bool = False,
) -> tuple[Tenant | None, TenantUser | None, frozenset[str], frozenset[str], bool]:
    """Resolve tenant, membership, roles, permissions. Raises HTTPException on denial."""
    settings = get_settings()
    requested = (selected_tenant or "").strip()
    selected: Tenant | None = None
    membership: TenantUser | None = None

    if requested:
        for member, tenant in memberships:
            if requested in {str(tenant.id), tenant.slug, tenant.external_iam_tenant_id}:
                membership, selected = member, tenant
                break
        if selected is None and is_platform_admin:
            selected = db.execute(
                select(Tenant).where(Tenant.status == "ACTIVE", _tenant_identity_filter(Tenant, requested))
            ).scalar_one_or_none()
    elif tenant_claim is not None:
        claim_value = str(tenant_claim)
        for member, tenant in memberships:
            if claim_value in {str(tenant.id), tenant.slug, tenant.external_iam_tenant_id}:
                membership, selected = member, tenant
                break
        if selected is None and is_platform_admin:
            selected = db.execute(
                select(Tenant).where(Tenant.status == "ACTIVE", Tenant.external_iam_tenant_id == claim_value)
            ).scalar_one_or_none()
    elif len(memberships) == 1:
        membership, selected = memberships[0]
    elif not auth_enabled and settings.dev_default_tenant:
        selected = db.execute(
            select(Tenant).where(Tenant.slug == settings.default_tenant_slug, Tenant.status == "ACTIVE")
        ).scalar_one_or_none()
        if selected:
            membership = db.execute(
                select(TenantUser).where(
                    TenantUser.tenant_id == selected.id,
                    TenantUser.user_id == user.id,
                    TenantUser.status == "ACTIVE",
                )
            ).scalar_one_or_none()

    if selected is None and is_platform_admin and allow_platform_context:
        roles = frozenset({"PLATFORM_ADMIN"})
        return None, None, roles, permissions_for_roles(roles), True

    if selected is None or (membership is None and not is_platform_admin):
        raise HTTPException(status_code=403, detail="Tenant access denied")

    roles = {normalize_role(membership.role)} if membership else set()
    if is_platform_admin:
        roles.add("PLATFORM_ADMIN")
    permissions = permissions_for_roles(frozenset(roles))
    return selected, membership, frozenset(roles), permissions, is_platform_admin


def create_tenant(db: Session, *, name: str, slug: str, external_iam_tenant_id: str) -> Tenant:
    now = datetime.now(UTC)
    tenant = Tenant(
        name=name.strip(),
        slug=slug,
        external_iam_tenant_id=external_iam_tenant_id,
        status="ACTIVE",
        created_at=now,
        updated_at=now,
    )
    db.add(tenant)
    db.flush()
    return tenant


def get_available_tenants_for_user(db: Session, user_id: int, is_platform_admin: bool) -> list[tuple[Tenant, str | None]]:
    if is_platform_admin:
        tenants = db.execute(select(Tenant).where(Tenant.status == "ACTIVE").order_by(Tenant.name)).scalars()
        return [(t, "PLATFORM_ADMIN") for t in tenants]
    rows = db.execute(
        select(Tenant, TenantUser.role)
        .join(TenantUser, TenantUser.tenant_id == Tenant.id)
        .where(
            TenantUser.user_id == user_id,
            TenantUser.status == "ACTIVE",
            Tenant.status == "ACTIVE",
        )
        .order_by(Tenant.name)
    ).all()
    return [(tenant, role) for tenant, role in rows]


def list_tenant_users(db: Session, tenant_id: int) -> list[tuple[TenantUser, IAMUser]]:
    return list(
        db.execute(
            select(TenantUser, IAMUser)
            .join(IAMUser, IAMUser.id == TenantUser.user_id)
            .where(TenantUser.tenant_id == tenant_id)
            .order_by(IAMUser.email, IAMUser.external_iam_user_id)
        ).all()
    )


def add_user_to_tenant(
    db: Session,
    tenant_id: int,
    *,
    external_iam_user_id: str,
    role: str,
    status: str = "ACTIVE",
) -> tuple[TenantUser, IAMUser]:
    now = datetime.now(UTC)
    role = validate_tenant_role(role)
    status = validate_membership_status(status)
    user = db.execute(select(IAMUser).where(IAMUser.external_iam_user_id == external_iam_user_id)).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="IAM user not found; the user must sign in once before onboarding")
    if user.status == "DISABLED":
        raise HTTPException(status_code=422, detail="Disabled IAM user cannot receive an active membership")
    if status == "ACTIVE" and user.status == "PENDING":
        # Adding an active membership is the tenant administrator's explicit
        # onboarding approval for this discovered identity.
        user.status = "ACTIVE"
        user.updated_at = now
    membership = db.execute(
        select(TenantUser).where(TenantUser.tenant_id == tenant_id, TenantUser.user_id == user.id)
    ).scalar_one_or_none()
    if membership is None:
        membership = TenantUser(
            tenant_id=tenant_id,
            user_id=user.id,
            role=role,
            status=status,
            created_at=now,
            updated_at=now,
        )
        db.add(membership)
    else:
        membership.role = role
        membership.status = status
        membership.updated_at = now
    db.flush()
    return membership, user


def update_user_role(
    db: Session,
    tenant_id: int,
    membership_id: int,
    *,
    role: str | None = None,
    status: str | None = None,
) -> tuple[TenantUser, dict, dict]:
    membership = db.execute(
        select(TenantUser).where(TenantUser.id == membership_id, TenantUser.tenant_id == tenant_id)
    ).scalar_one_or_none()
    if membership is None:
        raise HTTPException(status_code=404, detail="Membership not found")
    old = {"role": membership.role, "status": membership.status}
    if role is not None:
        membership.role = validate_tenant_role(role)
    if status is not None:
        membership.status = validate_membership_status(status)
    membership.updated_at = datetime.now(UTC)
    new = {"role": membership.role, "status": membership.status}
    db.flush()
    return membership, old, new


def disable_user_membership(db: Session, tenant_id: int, membership_id: int) -> TenantUser:
    membership = db.execute(
        select(TenantUser).where(TenantUser.id == membership_id, TenantUser.tenant_id == tenant_id)
    ).scalar_one_or_none()
    if membership is None:
        raise HTTPException(status_code=404, detail="Membership not found")
    membership.status = "DISABLED"
    membership.updated_at = datetime.now(UTC)
    db.flush()
    return membership


def get_tenant_membership(db: Session, tenant_id: int, membership_id: int) -> tuple[TenantUser, IAMUser]:
    row = db.execute(
        select(TenantUser, IAMUser)
        .join(IAMUser, IAMUser.id == TenantUser.user_id)
        .where(TenantUser.id == membership_id, TenantUser.tenant_id == tenant_id)
    ).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Membership not found")
    return row


def _active_tenant_admin_count(db: Session, tenant_id: int, *, excluding: int | None = None) -> int:
    statement = select(TenantUser.id).where(
        TenantUser.tenant_id == tenant_id,
        TenantUser.role == "TENANT_ADMIN",
        TenantUser.status == "ACTIVE",
    )
    if excluding is not None:
        statement = statement.where(TenantUser.id != excluding)
    return len(db.execute(statement).scalars().all())


def ensure_not_last_active_tenant_admin(
    db: Session,
    membership: TenantUser,
    *,
    next_role: str | None = None,
    next_status: str | None = None,
    deleting: bool = False,
    platform_override: bool = False,
) -> None:
    removes_admin = deleting or (next_role is not None and next_role != "TENANT_ADMIN") or (
        next_status is not None and next_status != "ACTIVE"
    )
    if (
        not platform_override
        and membership.role == "TENANT_ADMIN"
        and membership.status == "ACTIVE"
        and removes_admin
        and _active_tenant_admin_count(db, membership.tenant_id, excluding=membership.id) == 0
    ):
        raise HTTPException(status_code=409, detail="Cannot remove or disable the last active tenant administrator")


def set_membership_status(db: Session, tenant_id: int, membership_id: int, status_value: str) -> tuple[TenantUser, dict, dict]:
    return update_user_role(db, tenant_id, membership_id, status=validate_membership_status(status_value))


def remove_membership(db: Session, tenant_id: int, membership_id: int) -> TenantUser:
    membership, _user = get_tenant_membership(db, tenant_id, membership_id)
    db.delete(membership)
    db.flush()
    return membership
