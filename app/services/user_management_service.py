"""Safe profile, membership and audit projections for lifecycle administration."""

from datetime import UTC, datetime

from fastapi import HTTPException
from sqlalchemy import exists, func, or_, select
from sqlalchemy.orm import Session

from ..models import (
    AuthorizationAuditLog,
    AuthorizationRole,
    IAMUser,
    NativeUserCredential,
    Tenant,
    TenantUser,
    TenantUserRoleAssignment,
    UserIdentity,
)
from . import audit_service
from .platform_service import _escape_search


def providers(db: Session, user: IAMUser) -> list[str]:
    values = set(db.scalars(select(UserIdentity.provider_type).where(UserIdentity.user_id == user.id)))
    if user.external_issuer or user.external_iam_user_id:
        values.add("HCL_CS")
    return sorted(values)


def profile(db: Session, user: IAMUser) -> dict:
    return dict(
        user_id=user.id,
        first_name=user.first_name,
        last_name=user.last_name,
        display_name=user.display_name,
        email=user.email,
        phone=user.phone,
        account_status=user.status,
        email_verified=user.email_verified,
        last_login_at=user.last_login_at,
        created_at=user.created_at,
        updated_at=user.updated_at,
        providers=providers(db, user),
    )


def membership_summary(db: Session, member: TenantUser, tenant: Tenant) -> dict:
    # Show assigned roles even when membership is disabled; these are not
    # effective permissions and cannot grant access until reactivation.
    assignments = db.scalars(
        select(AuthorizationRole.code)
        .join(TenantUserRoleAssignment.__table__, TenantUserRoleAssignment.__table__.c.role_id == AuthorizationRole.id)
        .where(
            TenantUserRoleAssignment.__table__.c.tenant_user_id == member.id,
            TenantUserRoleAssignment.__table__.c.tenant_id == member.tenant_id,
            TenantUserRoleAssignment.__table__.c.status == "ACTIVE",
            AuthorizationRole.status == "ACTIVE",
        )
    ).all()
    return dict(
        membership_id=member.id,
        tenant_id=tenant.id,
        tenant_name=tenant.name,
        tenant_slug=tenant.slug,
        tenant_status=tenant.status,
        membership_status=member.status,
        current_role=member.role,
        primary_role=member.role,
        roles=sorted(assignments),
        role_assignment_version=member.role_assignment_version,
    )


def role_filter(code: str, tenant_id: int | None = None):
    query = (
        select(TenantUser.id)
        .join(
            TenantUserRoleAssignment.__table__,
            (TenantUserRoleAssignment.__table__.c.tenant_user_id == TenantUser.id)
            & (TenantUserRoleAssignment.__table__.c.tenant_id == TenantUser.tenant_id),
        )
        .join(AuthorizationRole, AuthorizationRole.id == TenantUserRoleAssignment.__table__.c.role_id)
        .where(
            TenantUser.user_id == IAMUser.id,
            AuthorizationRole.code == code,
            AuthorizationRole.status == "ACTIVE",
            TenantUserRoleAssignment.__table__.c.status == "ACTIVE",
        )
    )
    if tenant_id is not None:
        query = query.where(TenantUser.tenant_id == tenant_id)
    return exists(query.correlate(IAMUser))


def tenant_page(db, tenant_id, *, page, page_size, search=None, account_status=None, role=None):
    query = (
        select(TenantUser, IAMUser)
        .join(IAMUser, IAMUser.id == TenantUser.user_id)
        .where(TenantUser.tenant_id == tenant_id)
    )
    if search:
        pattern = f"%{_escape_search(search.strip())}%"
        query = query.where(
            or_(IAMUser.email.ilike(pattern, escape="\\"), IAMUser.display_name.ilike(pattern, escape="\\"))
        )
    if account_status:
        query = query.where(IAMUser.status == account_status)
    if role:
        query = query.where(role_filter(role, tenant_id))
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    tenant = db.get(Tenant, tenant_id)
    rows = db.execute(
        query.order_by(IAMUser.display_name, IAMUser.id).offset((page - 1) * page_size).limit(page_size)
    ).all()
    return dict(
        items=[profile(db, u) | membership_summary(db, m, tenant) for m, u in rows],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


def audit_history(db, user_id, *, tenant_id=None, page=1, page_size=50):
    query = select(AuthorizationAuditLog).where(AuthorizationAuditLog.target_user_id == user_id)
    if tenant_id is not None:
        query = query.where(AuthorizationAuditLog.tenant_id == tenant_id)
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    rows = db.scalars(
        query.order_by(AuthorizationAuditLog.created_at.desc(), AuthorizationAuditLog.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    # Explicit safe projection. Arbitrary historical audit JSON is not exposed.
    return dict(
        items=[
            dict(
                id=r.id,
                action=r.action,
                outcome=r.outcome,
                tenant_id=r.tenant_id,
                actor_user_id=r.actor_user_id,
                timestamp=r.created_at,
            )
            for r in rows
        ],
        total=total,
        page=page,
        page_size=page_size,
    )


def security_summary(db, user_id):
    credential = db.scalar(select(NativeUserCredential).where(NativeUserCredential.user_id == user_id))
    return (
        dict(
            password_changed_at=credential.password_changed_at,
            failed_login_count=credential.failed_login_count,
            locked_at=credential.locked_at,
            locked_until=credential.locked_until,
        )
        if credential
        else None
    )


def update_profile(db, user_id, changes, *, actor_user_id, tenant_id=None):
    if set(changes) - {"first_name", "last_name", "phone"}:
        raise HTTPException(422, "Unsupported profile field")
    with db.begin_nested():
        if tenant_id is not None:
            db.scalar(select(Tenant).where(Tenant.id == tenant_id).with_for_update())
        user = db.scalar(
            select(IAMUser).where(IAMUser.id == user_id).with_for_update().execution_options(populate_existing=True)
        )
        if not user:
            raise HTTPException(404, "User not found")
        if tenant_id is not None and not db.scalar(
            select(TenantUser.id)
            .where(TenantUser.tenant_id == tenant_id, TenantUser.user_id == user_id)
            .with_for_update()
        ):
            raise HTTPException(404, "Tenant member not found")
        before = {key: getattr(user, key) for key in changes}
        for key, value in changes.items():
            setattr(user, key, value)
        if "first_name" in changes or "last_name" in changes:
            user.display_name = " ".join(filter(None, [user.first_name, user.last_name])) or user.display_name
        user.updated_at = datetime.now(UTC)
        audit_service.write_authorization_audit(
            db,
            action="USER_UPDATED",
            actor_user_id=actor_user_id,
            target_user_id=user_id,
            tenant_id=tenant_id,
            old_value=before,
            new_value=changes,
        )
        db.flush()
    return user
