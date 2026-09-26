"""Operator-only enrollment. Caller owns commit; no passwords or tokens returned."""
from datetime import UTC, datetime

from sqlalchemy import func, select, text

from ..models import IAMUser, NativePlatformBootstrap, SecurityMailOutbox, UserIdentity
from ..settings import get_settings
from . import account_action_token_service as tokens
from . import platform_service
from .identity_service import normalize_email
from .native_auth_service import audit
from .security_mail_outbox import cipher


class BootstrapRefused(ValueError):
    pass


def _lock(db):
    if db.bind.dialect.name != "postgresql":
        raise BootstrapRefused("Native bootstrap requires PostgreSQL")
    db.execute(text("SELECT pg_advisory_xact_lock(734621062)"))


def _enabled():
    s = get_settings()
    if not (s.native_platform_bootstrap_enabled and s.auth_enabled and s.native_auth_enabled
            and s.native_user_creation_enabled and s.native_security_outbox_enabled):
        raise BootstrapRefused("Native bootstrap configuration is disabled or incomplete")
    cipher()  # Never issue a token without a working encrypted outbox.


def _available(db):
    if platform_service._effective_admin_count(db):
        raise BootstrapRefused("A usable Platform Administrator already exists")


def create(db, *, email, first_name, last_name, phone, operator_reference):
    _enabled()
    if not all(isinstance(v, str) and v.strip() for v in (email, first_name, last_name, phone, operator_reference)):
        raise BootstrapRefused("All identity fields and operator reference are required")
    if len(operator_reference) > 128 or len(first_name) > 100 or len(last_name) > 100 or len(phone) > 50:
        raise BootstrapRefused("Bootstrap input exceeds allowed length")
    email = normalize_email(email)
    if not email or len(email) > 320 or "@" not in email or any(c.isspace() for c in email):
        raise BootstrapRefused("Invalid bootstrap email")
    _lock(db)
    _available(db)
    if db.get(NativePlatformBootstrap, 1):
        raise BootstrapRefused("Bootstrap already reserved; use status or resend-activation")
    if db.scalar(select(IAMUser.id).where(func.lower(IAMUser.email) == email)) or db.scalar(
        select(UserIdentity.id).where(UserIdentity.provider_identifier == email)
    ):
        raise BootstrapRefused("Identity collision; bootstrap never links existing users")
    now = datetime.now(UTC)
    user = IAMUser(first_name=first_name.strip(), last_name=last_name.strip(), phone=phone.strip(), email=email,
                   display_name=f"{first_name.strip()} {last_name.strip()}", status="PENDING_EMAIL_VERIFICATION",
                   email_verified=False, verification_required=True, created_at=now, updated_at=now)
    db.add(user)
    db.flush()
    db.add(UserIdentity(user_id=user.id, provider_type="NATIVE", provider_identifier=email, created_at=now, updated_at=now))
    db.add(NativePlatformBootstrap(id=1, user_id=user.id, state="PENDING", created_at=now, operator_reference=operator_reference))
    db.flush()
    tokens.issue_activation_token(db, user.id, actor_user_id=None)
    audit(db, "NATIVE_PLATFORM_BOOTSTRAP_CREATED", user.id)
    db.flush()
    return user.id


def resend(db):
    _enabled()
    _lock(db)
    _available(db)
    row = db.get(NativePlatformBootstrap, 1, populate_existing=True)
    if not row or row.state != "PENDING":
        raise BootstrapRefused("No pending Native bootstrap")
    tokens.issue_activation_token(db, row.user_id, actor_user_id=None)
    audit(db, "NATIVE_PLATFORM_BOOTSTRAP_ACTIVATION_RESENT", row.user_id)
    db.flush()
    return row.user_id


def lock_for_activation(db, uid):
    # Lock before user/token locks, matching create/resend. Ordinary activation
    # does not participate in bootstrap locking.
    if db.scalar(select(NativePlatformBootstrap.id).where(NativePlatformBootstrap.user_id == uid)):
        _lock(db)


def finalize(db, user):
    row = db.scalar(select(NativePlatformBootstrap).where(NativePlatformBootstrap.user_id == user.id))
    if row is None:
        return
    if row.state != "PENDING":
        raise BootstrapRefused("Bootstrap already completed")
    # Activation remains available after operators disable enrollment mode.
    # Only the durably reserved identity can reach this path.
    platform_service.bootstrap_platform_administrator(db, user=user)
    row.state, row.completed_at = "COMPLETED", datetime.now(UTC)
    audit(db, "NATIVE_PLATFORM_BOOTSTRAP_COMPLETED", user.id)
    db.flush()


def status(db):
    row = db.get(NativePlatformBootstrap, 1)
    result = {"enabled": get_settings().native_platform_bootstrap_enabled,
              "state": row.state if row else "NOT_STARTED",
              "platform_admin_available": bool(platform_service._effective_admin_count(db))}
    if row:
        user = db.get(IAMUser, row.user_id)
        delivery = db.scalar(select(SecurityMailOutbox.status).where(SecurityMailOutbox.user_id == row.user_id)
                             .order_by(SecurityMailOutbox.id.desc()).limit(1))
        result.update(user_id=row.user_id, email=user.email, account_status=user.status, delivery_status=delivery)
    return result
