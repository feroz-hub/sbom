"""Administrator-authorized native enrollment; commit before email delivery."""

from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.context import CurrentContext
from ..models import AccountActionToken, IAMUser, Tenant, TenantUser, UserIdentity
from ..settings import get_settings
from . import account_action_token_service as tokens
from . import tenant_role_assignment_service as roles
from .email_templates import render_activation_email
from .identity_service import normalize_email
from .native_auth_service import audit
from .native_security_delivery import send_security_email


def authorize(context: CurrentContext, tenant_id: int) -> None:
    permission = "platform:user:manage_status" if context.is_platform_admin else "tenant:user:invite"
    if not context.has_permission(permission) or (
        not context.is_platform_admin and (context.tenant_id != tenant_id or "TENANT_ADMIN" not in context.roles)
    ):
        raise HTTPException(403, "Insufficient permission")


def add_membership(
    db: Session, context: CurrentContext, tenant_id: int, user_id: int, role_codes: list[str]
) -> TenantUser:
    authorize(context, tenant_id)
    roles.validate_role_delegation(role_codes, is_platform_admin=context.is_platform_admin)
    with db.begin_nested():
        tenant = db.scalar(select(Tenant).where(Tenant.id == tenant_id).with_for_update())
        if not tenant or tenant.status != "ACTIVE":
            raise HTTPException(404, "Active tenant not found")
        user = db.scalar(select(IAMUser).where(IAMUser.id == user_id).with_for_update())
        if not user:
            raise HTTPException(404, "User not found")
        existing = db.scalar(select(TenantUser).where(TenantUser.tenant_id == tenant_id, TenantUser.user_id == user_id))
        if existing:
            current_roles = sorted(roles.effective_role_codes(db, existing))
            raise HTTPException(409, {
                "code": "MEMBERSHIP_ALREADY_EXISTS",
                "message": f"{user.display_name or user.email} is already a member of {tenant.name}.",
                "roles": current_roles,
                "tenant_id": tenant.id,
                "user_id": user.id,
            })
        if not role_codes:
            raise HTTPException(422, "At least one role is required")
        now = datetime.now(UTC)
        member = TenantUser(
            tenant_id=tenant_id, user_id=user_id, role=role_codes[0], status="ACTIVE", created_at=now, updated_at=now
        )
        db.add(member)
        db.flush()
        roles.create_initial_assignments(
            db,
            member,
            role_codes=role_codes,
            primary_role_code=role_codes[0],
            actor_user_id=context.user_id,
            source="PLATFORM_ADMIN" if context.is_platform_admin else "TENANT_ADMIN",
        )
        audit(
            db,
            "TENANT_MEMBER_ADDED",
            user_id,
            actor_user_id=context.user_id,
            tenant_id=tenant_id,
            target_membership_id=member.id,
        )
        for code in role_codes:
            audit(
                db,
                "ROLE_ASSIGNED",
                user_id,
                actor_user_id=context.user_id,
                tenant_id=tenant_id,
                new_value={"role": code},
            )
        db.flush()
    return member


def provision_native_identity(db: Session, payload, *, actor_user_id: int) -> IAMUser:
    """Resolve only the Native provider identifier; never link an HCL profile by email.

    Caller owns the transaction and membership authorization. The unique Native
    identifier index arbitrates concurrent attempts to create the same identity.
    """
    if not get_settings().native_user_creation_enabled:
        raise HTTPException(404, "Native enrollment unavailable")
    email = normalize_email(payload.email)
    if not email:
        raise HTTPException(422, "A valid email address is required")
    identity = db.scalar(select(UserIdentity).where(
        UserIdentity.provider_type == "NATIVE", UserIdentity.provider_identifier == email,
    ))
    if identity:
        user = db.scalar(select(IAMUser).where(IAMUser.id == identity.user_id).with_for_update()
                         .execution_options(populate_existing=True))
        if user.status not in {"ACTIVE", "PENDING_EMAIL_VERIFICATION"}:
            raise HTTPException(409, "The existing Native account is not eligible for invitation")
        if user.status == "ACTIVE" and (not user.email_verified or user.verification_required):
            raise HTTPException(409, "The existing Native account requires email verification")
        return user
    now = datetime.now(UTC)
    user = IAMUser(
        first_name=payload.first_name, last_name=payload.last_name, email=email, phone=payload.phone,
        display_name=f"{payload.first_name} {payload.last_name}", status="PENDING_EMAIL_VERIFICATION",
        created_at=now, updated_at=now,
    )
    db.add(user)
    db.flush()
    db.add(UserIdentity(user_id=user.id, provider_type="NATIVE", provider_identifier=email,
                        created_at=now, updated_at=now))
    db.flush()
    audit(db, "NATIVE_USER_CREATED", user.id, actor_user_id=actor_user_id)
    return user


def create_user(db, context, payload):
    authorize(context, payload.tenant_id)
    roles.validate_role_delegation(payload.role_codes, is_platform_admin=context.is_platform_admin)
    with db.begin_nested():
        # Serialize with tenant lifecycle operations before locking users.
        tenant = db.scalar(select(Tenant).where(Tenant.id == payload.tenant_id).with_for_update())
        if not tenant or tenant.status != "ACTIVE":
            raise HTTPException(404, "Active tenant not found")
        user = provision_native_identity(db, payload, actor_user_id=context.user_id)
        add_membership(db, context, payload.tenant_id, user.id, payload.role_codes)
        issued = (tokens.issue_activation_token(db, user.id, actor_user_id=context.user_id)
                  if user.status == "PENDING_EMAIL_VERIFICATION" else None)
        db.flush()
    return user, issued


def resend(
    db: Session, context: CurrentContext, tenant_id: int, user_id: int
) -> tuple[IAMUser, tokens.IssuedAccountActionToken]:
    if not get_settings().native_user_creation_enabled:
        raise HTTPException(404, "Native enrollment unavailable")
    authorize(context, tenant_id)
    with db.begin_nested():
        user = db.scalar(select(IAMUser).where(IAMUser.id == user_id).with_for_update())
        member = db.scalar(
            select(TenantUser.id).where(
                TenantUser.tenant_id == tenant_id, TenantUser.user_id == user_id, TenantUser.status == "ACTIVE"
            )
        )
        if not user or not member or user.status != "PENDING_EMAIL_VERIFICATION":
            raise HTTPException(404, "Pending tenant user not found")
        s = get_settings()
        now = datetime.now(UTC)
        latest = db.scalar(
            select(AccountActionToken)
            .where(AccountActionToken.user_id == user_id)
            .order_by(AccountActionToken.created_at.desc())
            .limit(1)
        )
        if latest and latest.created_at + timedelta(seconds=s.email_verification_resend_cooldown_seconds) > now:
            raise HTTPException(429, "Activation resend is rate limited")
        for duration, limit in [
            (timedelta(hours=1), s.email_verification_max_sends_per_hour),
            (timedelta(days=1), s.email_verification_max_sends_per_day),
        ]:
            count = db.scalar(
                select(func.count(AccountActionToken.id)).where(
                    AccountActionToken.user_id == user_id, AccountActionToken.created_at >= now - duration
                )
            )
            if count >= limit:
                raise HTTPException(429, "Activation resend is rate limited")
        issued = tokens.issue_activation_token(db, user_id, actor_user_id=context.user_id)
        audit(db, "ACCOUNT_ACTIVATION_RESENT", user_id, actor_user_id=context.user_id, tenant_id=tenant_id)
    return user, issued


def deliver_activation(user: IAMUser, issued: tokens.IssuedAccountActionToken) -> dict[str, str | None]:
    s = get_settings()
    url = s.native_activation_frontend_url
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment or parsed.username:
        return {"status": "FAILED", "error_code": "INVALID_ACTIVATION_URL"}
    # Fragment keeps the raw token out of HTTP request URLs and access logs.
    activation_url = f"{url}#token={issued.raw_token}"
    rendered = render_activation_email(
        first_name=user.first_name,
        activation_url=activation_url,
        ttl_seconds=s.native_account_activation_ttl_seconds,
        support_email=s.platform_admin_contact_email or None,
    )
    return send_security_email(
        issued.email_snapshot,
        rendered.subject,
        rendered.text_body,
        f"<security-{issued.id}@sbom.invalid>",
        html_body=rendered.html_body,
    )
