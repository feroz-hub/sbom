"""Administrator-authorized native enrollment; commit before email delivery."""

from datetime import UTC, datetime, timedelta
from html import escape
from urllib.parse import urlsplit

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.context import CurrentContext
from ..models import AccountActionToken, IAMUser, Tenant, TenantUser, UserIdentity
from ..settings import get_settings
from . import account_action_token_service as tokens
from . import email_sender
from . import tenant_role_assignment_service as roles
from .identity_service import normalize_email
from .native_auth_service import audit


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
            raise HTTPException(409, "Membership already exists; use role management")
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


def create_user(db, context, payload):
    if not get_settings().native_user_creation_enabled:
        raise HTTPException(404, "Native enrollment unavailable")
    authorize(context, payload.tenant_id)
    email = normalize_email(payload.email)
    if not email:
        raise HTTPException(422, "A valid email address is required")
    with db.begin_nested():
        # Serialize with tenant lifecycle operations before locking users.
        tenant = db.scalar(select(Tenant).where(Tenant.id == payload.tenant_id).with_for_update())
        if not tenant or tenant.status != "ACTIVE":
            raise HTTPException(404, "Active tenant not found")
        if db.scalar(
            select(UserIdentity.id).where(
                UserIdentity.provider_type == "NATIVE", UserIdentity.provider_identifier == email
            )
        ):
            raise HTTPException(409, "Native identity already exists; use the existing user ID")
        now = datetime.now(UTC)
        user = IAMUser(
            first_name=payload.first_name,
            last_name=payload.last_name,
            email=email,
            phone=payload.phone,
            display_name=f"{payload.first_name} {payload.last_name}",
            status="PENDING_EMAIL_VERIFICATION",
            created_at=now,
            updated_at=now,
        )
        db.add(user)
        db.flush()
        db.add(
            UserIdentity(
                user_id=user.id, provider_type="NATIVE", provider_identifier=email, created_at=now, updated_at=now
            )
        )
        db.flush()
        add_membership(db, context, payload.tenant_id, user.id, payload.role_codes)
        issued = tokens.issue_activation_token(db, user.id, actor_user_id=context.user_id)
        audit(db, "NATIVE_USER_CREATED", user.id, actor_user_id=context.user_id, tenant_id=payload.tenant_id)
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
    text = (
        f"Hello {user.first_name or ''},\nActivate your SBOM Analyser account:\n{activation_url}\n"
        "This link is valid for five hours. If you did not expect this invitation, ignore it.\n"
        f"Support: {s.platform_admin_contact_email or 'Contact your administrator'}"
    )
    try:
        result = email_sender.get_email_sender().send_email(
            email_sender.build_email(
                s,
                recipient_email=issued.email_snapshot,
                subject="Activate your SBOM Analyser account",
                text_body=text,
                html_body=f"<p>{escape(text).replace(chr(10), '<br>')}</p>",
            )
        )
        return {"status": str(result.status), "error_code": result.error_code}
    except Exception:
        # Never serialize an SMTP exception that may contain message contents.
        return {"status": "FAILED", "error_code": "DELIVERY_FAILED"}
