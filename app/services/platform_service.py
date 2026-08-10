"""Database-authoritative platform user and administrator management."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from math import ceil

from fastapi import HTTPException
from sqlalchemy import and_, exists, func, or_, select, update
from sqlalchemy.orm import Session

from ..core.identity_states import IdentityErrorCode
from ..core.permissions import TENANT_STATUSES
from ..models import EmailVerificationToken, IAMUser, PlatformUserRole, Tenant, TenantUser


@dataclass(frozen=True, slots=True)
class PageResult:
    items: list
    page: int
    page_size: int
    total: int

    @property
    def total_pages(self) -> int:
        return ceil(self.total / self.page_size) if self.total else 0


@dataclass(frozen=True, slots=True)
class GrantMutation:
    grant: PlatformUserRole
    user: IAMUser
    action: str
    old_state: dict | None


@dataclass(frozen=True, slots=True)
class StatusMutation:
    user: IAMUser
    old_status: str
    changed: bool


def _error(
    code: IdentityErrorCode,
    message: str,
    *,
    status_code: int,
) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"code": str(code), "message": message},
    )


def is_effective_platform_administrator(
    user: IAMUser,
    grant: PlatformUserRole | None,
) -> bool:
    return bool(
        grant is not None
        and grant.role == "PLATFORM_ADMIN"
        and grant.status == "ACTIVE"
        and user.status == "ACTIVE"
        and user.email_verified
        and not user.verification_required
    )


def get_active_platform_grant(db: Session, user_id: int) -> PlatformUserRole | None:
    """Compatibility lookup for an active grant, independent of user eligibility."""
    return db.scalar(
        select(PlatformUserRole).where(
            PlatformUserRole.user_id == user_id,
            PlatformUserRole.role == "PLATFORM_ADMIN",
            PlatformUserRole.status == "ACTIVE",
        )
    )


def get_effective_platform_grant(db: Session, user: IAMUser) -> PlatformUserRole | None:
    grant = get_active_platform_grant(db, user.id)
    return grant if is_effective_platform_administrator(user, grant) else None


def _escape_search(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _platform_user_conditions(
    *,
    search: str | None,
    local_status: str | None,
    email_verified: bool | None,
    verification_required: bool | None,
    is_platform_admin: bool | None,
    tenant_id: int | None,
    created_from: datetime | None,
    created_to: datetime | None,
    last_login_from: datetime | None,
    last_login_to: datetime | None,
) -> list:
    conditions: list = []
    if search:
        pattern = f"%{_escape_search(search.strip())}%"
        conditions.append(
            or_(
                IAMUser.email.ilike(pattern, escape="\\"),
                IAMUser.display_name.ilike(pattern, escape="\\"),
                IAMUser.user_principal_name.ilike(pattern, escape="\\"),
                IAMUser.employee_id.ilike(pattern, escape="\\"),
            )
        )
    if local_status:
        conditions.append(IAMUser.status == local_status)
    if email_verified is not None:
        conditions.append(IAMUser.email_verified.is_(email_verified))
    if verification_required is not None:
        conditions.append(IAMUser.verification_required.is_(verification_required))
    effective_grant_exists = exists(
        select(PlatformUserRole.id).where(
            PlatformUserRole.user_id == IAMUser.id,
            PlatformUserRole.role == "PLATFORM_ADMIN",
            PlatformUserRole.status == "ACTIVE",
        ).correlate(IAMUser)
    )
    effective_condition = and_(
        IAMUser.status == "ACTIVE",
        IAMUser.email_verified.is_(True),
        IAMUser.verification_required.is_(False),
        effective_grant_exists,
    )
    if is_platform_admin is True:
        conditions.append(effective_condition)
    elif is_platform_admin is False:
        conditions.append(~effective_condition)
    if tenant_id is not None:
        conditions.append(
            exists(
                select(TenantUser.id).where(
                    TenantUser.user_id == IAMUser.id,
                    TenantUser.tenant_id == tenant_id,
                )
            )
        )
    if created_from is not None:
        conditions.append(IAMUser.created_at >= created_from)
    if created_to is not None:
        conditions.append(IAMUser.created_at <= created_to)
    if last_login_from is not None:
        conditions.append(IAMUser.last_login_at >= last_login_from)
    if last_login_to is not None:
        conditions.append(IAMUser.last_login_at <= last_login_to)
    return conditions


def list_platform_users(
    db: Session,
    *,
    page: int,
    page_size: int,
    search: str | None = None,
    local_status: str | None = None,
    email_verified: bool | None = None,
    verification_required: bool | None = None,
    is_platform_admin: bool | None = None,
    tenant_id: int | None = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
    last_login_from: datetime | None = None,
    last_login_to: datetime | None = None,
) -> PageResult:
    conditions = _platform_user_conditions(
        search=search,
        local_status=local_status,
        email_verified=email_verified,
        verification_required=verification_required,
        is_platform_admin=is_platform_admin,
        tenant_id=tenant_id,
        created_from=created_from,
        created_to=created_to,
        last_login_from=last_login_from,
        last_login_to=last_login_to,
    )
    active_tenant_count = (
        select(func.count(TenantUser.id))
        .join(Tenant, Tenant.id == TenantUser.tenant_id)
        .where(
            TenantUser.user_id == IAMUser.id,
            TenantUser.status == "ACTIVE",
            Tenant.status == "ACTIVE",
        )
        .correlate(IAMUser)
        .scalar_subquery()
    )
    total = int(
        db.scalar(select(func.count(IAMUser.id)).where(*conditions)) or 0
    )
    rows = list(
        db.execute(
            select(
                IAMUser,
                PlatformUserRole,
                active_tenant_count.label("active_tenant_count"),
            )
            .outerjoin(PlatformUserRole, PlatformUserRole.user_id == IAMUser.id)
            .where(*conditions)
            .order_by(IAMUser.created_at.desc(), IAMUser.id.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        ).all()
    )
    return PageResult(rows, page, page_size, total)


def get_platform_user(
    db: Session,
    user_id: int,
) -> tuple[IAMUser, PlatformUserRole | None, list[tuple[TenantUser, Tenant]], int]:
    row = db.execute(
        select(IAMUser, PlatformUserRole)
        .outerjoin(PlatformUserRole, PlatformUserRole.user_id == IAMUser.id)
        .where(IAMUser.id == user_id)
    ).one_or_none()
    if row is None:
        raise _error(
            IdentityErrorCode.USER_NOT_FOUND,
            "Platform user was not found.",
            status_code=404,
        )
    user, grant = row
    memberships = list(
        db.execute(
            select(TenantUser, Tenant)
            .join(Tenant, Tenant.id == TenantUser.tenant_id)
            .where(TenantUser.user_id == user.id)
            .order_by(Tenant.name, Tenant.id, TenantUser.id)
        ).all()
    )
    active_count = sum(
        membership.status == "ACTIVE" and tenant.status == "ACTIVE"
        for membership, tenant in memberships
    )
    return user, grant, memberships, active_count


def list_platform_administrators(
    db: Session,
    *,
    page: int = 1,
    page_size: int = 50,
) -> PageResult:
    total = int(db.scalar(select(func.count(PlatformUserRole.id))) or 0)
    rows = list(
        db.execute(
            select(PlatformUserRole, IAMUser)
            .join(IAMUser, IAMUser.id == PlatformUserRole.user_id)
            .order_by(PlatformUserRole.created_at.desc(), PlatformUserRole.id.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        ).all()
    )
    return PageResult(rows, page, page_size, total)


def list_platform_tenants(db: Session) -> list[Tenant]:
    """Return every tenant, including disabled tenants, for platform administration."""
    return list(db.scalars(select(Tenant).order_by(Tenant.name, Tenant.id)))


def _lock_target_user(
    db: Session,
    *,
    user_id: int | None,
    external_iam_user_id: str | None,
) -> IAMUser:
    if user_id is not None:
        statement = select(IAMUser).where(IAMUser.id == user_id)
    else:
        statement = select(IAMUser).where(
            IAMUser.external_iam_user_id == external_iam_user_id
        )
    user = db.scalar(statement.with_for_update())
    if user is None:
        raise _error(
            IdentityErrorCode.USER_NOT_FOUND,
            "Platform user was not found.",
            status_code=404,
        )
    return user


def _validate_grant_eligibility(user: IAMUser) -> None:
    if user.status == "DISABLED":
        raise _error(
            IdentityErrorCode.ACCOUNT_DISABLED,
            "Disabled users cannot receive platform authority.",
            status_code=409,
        )
    if user.status == "PENDING":
        raise _error(
            IdentityErrorCode.ACCOUNT_PENDING_APPROVAL,
            "Pending users cannot receive platform authority.",
            status_code=409,
        )
    if not user.email_verified or user.verification_required:
        raise _error(
            IdentityErrorCode.EMAIL_VERIFICATION_REQUIRED,
            "Email verification is required before platform authority can be granted.",
            status_code=409,
        )


def grant_platform_administrator(
    db: Session,
    *,
    user_id: int | None = None,
    external_iam_user_id: str | None = None,
    created_by_user_id: int | None,
) -> GrantMutation:
    user = _lock_target_user(
        db,
        user_id=user_id,
        external_iam_user_id=external_iam_user_id,
    )
    _validate_grant_eligibility(user)
    grant = db.scalar(
        select(PlatformUserRole)
        .where(PlatformUserRole.user_id == user.id)
        .with_for_update()
    )
    now = datetime.now(UTC)
    if grant is not None and grant.status == "ACTIVE":
        raise _error(
            IdentityErrorCode.PLATFORM_ADMIN_ALREADY_GRANTED,
            "The user already has an active Platform Administrator grant.",
            status_code=409,
        )
    if grant is None:
        grant = PlatformUserRole(
            user_id=user.id,
            role="PLATFORM_ADMIN",
            status="ACTIVE",
            created_by_user_id=created_by_user_id,
            created_at=now,
            updated_at=now,
        )
        db.add(grant)
        action = "CREATED"
        old_state = None
    else:
        old_state = {"role": grant.role, "status": grant.status}
        grant.role = "PLATFORM_ADMIN"
        grant.status = "ACTIVE"
        grant.updated_at = now
        action = "REACTIVATED"
    db.flush()
    return GrantMutation(grant, user, action, old_state)


def _lock_all_platform_grants(db: Session) -> list[PlatformUserRole]:
    return list(
        db.scalars(
            select(PlatformUserRole)
            .order_by(PlatformUserRole.id)
            .with_for_update()
        )
    )


def _effective_admin_count(db: Session) -> int:
    return int(
        db.scalar(
            select(func.count(PlatformUserRole.id))
            .join(IAMUser, IAMUser.id == PlatformUserRole.user_id)
            .where(
                PlatformUserRole.role == "PLATFORM_ADMIN",
                PlatformUserRole.status == "ACTIVE",
                IAMUser.status == "ACTIVE",
                IAMUser.email_verified.is_(True),
                IAMUser.verification_required.is_(False),
            )
        )
        or 0
    )


def revoke_platform_administrator(db: Session, grant_id: int) -> GrantMutation:
    unresolved = db.get(PlatformUserRole, grant_id)
    if unresolved is None:
        raise _error(
            IdentityErrorCode.PLATFORM_ADMIN_NOT_GRANTED,
            "Platform administrator grant was not found.",
            status_code=404,
        )
    user = db.scalar(
        select(IAMUser).where(IAMUser.id == unresolved.user_id).with_for_update()
    )
    grants = _lock_all_platform_grants(db)
    grant = next((item for item in grants if item.id == grant_id), None)
    if user is None or grant is None:
        raise _error(
            IdentityErrorCode.PLATFORM_ADMIN_NOT_GRANTED,
            "Platform administrator grant was not found.",
            status_code=404,
        )
    if grant.status != "ACTIVE":
        return GrantMutation(grant, user, "ALREADY_INACTIVE", None)
    if is_effective_platform_administrator(user, grant) and _effective_admin_count(db) <= 1:
        raise _error(
            IdentityErrorCode.LAST_PLATFORM_ADMIN_PROTECTED,
            "The final effective Platform Administrator cannot be revoked.",
            status_code=409,
        )
    old_state = {"role": grant.role, "status": grant.status}
    grant.status = "DISABLED"
    grant.updated_at = datetime.now(UTC)
    db.flush()
    return GrantMutation(grant, user, "REVOKED", old_state)


def update_user_status(
    db: Session,
    user_id: int,
    status_value: str,
) -> StatusMutation:
    unresolved_user = db.get(IAMUser, user_id)
    if unresolved_user is None:
        raise _error(
            IdentityErrorCode.USER_NOT_FOUND,
            "Platform user was not found.",
            status_code=404,
        )
    requested = status_value.strip().upper()
    if requested not in {"ACTIVE", "DISABLED"}:
        raise _error(
            IdentityErrorCode.USER_STATUS_INVALID,
            "User status must be ACTIVE or DISABLED.",
            status_code=422,
        )
    if requested == "DISABLED" and unresolved_user.status != requested:
        tenant_ids = list(
            db.scalars(
                select(TenantUser.tenant_id)
                .where(
                    TenantUser.user_id == user_id,
                    TenantUser.status == "ACTIVE",
                )
                .order_by(TenantUser.tenant_id)
            )
        )
        if tenant_ids:
            list(
                db.scalars(
                    select(Tenant)
                    .where(Tenant.id.in_(tenant_ids))
                    .order_by(Tenant.id)
                    .with_for_update()
                )
            )
    user = db.scalar(select(IAMUser).where(IAMUser.id == user_id).with_for_update())
    if user is None:
        raise _error(
            IdentityErrorCode.USER_NOT_FOUND,
            "Platform user was not found.",
            status_code=404,
        )
    old_status = user.status
    if old_status == requested:
        return StatusMutation(user, old_status, False)
    allowed = {
        ("PENDING", "ACTIVE"),
        ("ACTIVE", "DISABLED"),
        ("DISABLED", "ACTIVE"),
    }
    if (old_status, requested) not in allowed:
        raise _error(
            IdentityErrorCode.USER_STATUS_TRANSITION_NOT_ALLOWED,
            f"Transition from {old_status} to {requested} is not allowed.",
            status_code=409,
        )
    if requested == "DISABLED":
        from . import tenant_role_assignment_service, tenant_service

        grant = get_active_platform_grant(db, user.id)
        if grant is not None and is_effective_platform_administrator(user, grant):
            _lock_all_platform_grants(db)
            if _effective_admin_count(db) <= 1:
                raise _error(
                    IdentityErrorCode.LAST_PLATFORM_ADMIN_PROTECTED,
                    "The final effective Platform Administrator cannot be disabled.",
                    status_code=409,
                )
        memberships = list(
            db.scalars(
                select(TenantUser)
                .where(
                    TenantUser.user_id == user.id,
                    TenantUser.status == "ACTIVE",
                )
                .order_by(TenantUser.tenant_id, TenantUser.id)
                .with_for_update()
            )
        )
        for membership in memberships:
            if "TENANT_ADMIN" in tenant_role_assignment_service.effective_role_codes(
                db,
                membership,
                actor_user_id=user.id,
            ):
                tenant_service.ensure_not_last_active_tenant_admin(
                    db,
                    membership,
                    next_status="DISABLED",
                )
        now = datetime.now(UTC)
        db.execute(
            update(EmailVerificationToken)
            .where(
                EmailVerificationToken.user_id == user.id,
                EmailVerificationToken.consumed_at.is_(None),
                EmailVerificationToken.invalidated_at.is_(None),
            )
            .values(
                invalidated_at=now,
                invalidation_reason="USER_DISABLED",
            )
        )
    user.status = requested
    user.updated_at = datetime.now(UTC)
    db.flush()
    return StatusMutation(user, old_status, True)


def resolve_bootstrap_user(
    db: Session,
    *,
    user_id: int | None = None,
    external_issuer: str | None = None,
    external_subject: str | None = None,
    employee_id: str | None = None,
    email: str | None = None,
    legacy_subject: str | None = None,
) -> IAMUser:
    selectors = [
        user_id is not None,
        bool(external_issuer or external_subject),
        bool(employee_id),
        bool(email),
        bool(legacy_subject),
    ]
    if sum(selectors) != 1 or bool(external_issuer) != bool(external_subject):
        raise _error(
            IdentityErrorCode.PLATFORM_ADMIN_BOOTSTRAP_REQUIRED,
            "Exactly one explicit bootstrap identity selector is required.",
            status_code=422,
        )
    if user_id is not None:
        statement = select(IAMUser).where(IAMUser.id == user_id)
    elif external_issuer and external_subject:
        statement = select(IAMUser).where(
            IAMUser.external_issuer == external_issuer,
            IAMUser.external_subject == external_subject,
        )
    elif employee_id:
        statement = select(IAMUser).where(IAMUser.employee_id == employee_id)
    elif email:
        statement = select(IAMUser).where(func.lower(IAMUser.email) == email.lower())
    else:
        statement = select(IAMUser).where(
            IAMUser.external_iam_user_id == legacy_subject
        )
    users = list(db.scalars(statement.with_for_update()).all())
    if not users:
        raise _error(
            IdentityErrorCode.USER_NOT_FOUND,
            "Bootstrap target was not found.",
            status_code=404,
        )
    if len(users) != 1:
        raise _error(
            IdentityErrorCode.PLATFORM_ADMIN_BOOTSTRAP_CONFLICT,
            "Bootstrap identity selector is ambiguous.",
            status_code=409,
        )
    return users[0]


def bootstrap_platform_administrator(
    db: Session,
    *,
    user: IAMUser,
) -> GrantMutation:
    _validate_grant_eligibility(user)
    existing = db.scalar(
        select(PlatformUserRole)
        .where(PlatformUserRole.user_id == user.id)
        .with_for_update()
    )
    if existing is not None and existing.status == "ACTIVE":
        return GrantMutation(existing, user, "EXISTING", None)
    _lock_all_platform_grants(db)
    if _effective_admin_count(db) > 0:
        raise _error(
            IdentityErrorCode.PLATFORM_ADMIN_BOOTSTRAP_CONFLICT,
            "An effective Platform Administrator already exists; use the authenticated API.",
            status_code=409,
        )
    return grant_platform_administrator(
        db,
        user_id=user.id,
        created_by_user_id=None,
    )


def update_tenant_status(
    db: Session,
    tenant_id: int,
    status_value: str,
) -> tuple[Tenant, str]:
    status_value = status_value.strip().upper()
    if status_value not in TENANT_STATUSES:
        raise HTTPException(status_code=422, detail="Invalid tenant status")
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    old_status = tenant.status
    tenant.status = status_value
    tenant.updated_at = datetime.now(UTC)
    db.flush()
    return tenant, old_status
