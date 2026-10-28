"""Secure email-verification token lifecycle and delivery orchestration."""

from __future__ import annotations

import hashlib
import re
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

from fastapi import Request
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from ..core.identity_states import IdentityAuditEvent, IdentityErrorCode, identity_http_error
from ..models import EmailVerificationToken, IAMUser
from ..schemas_identity import VerificationContext
from ..settings import get_settings
from . import audit_service
from .email_sender import (
    EmailDeliveryResult,
    EmailDeliveryStatus,
    VerificationEmailSender,
    get_verification_email_sender,
)
from .identity_service import normalize_email

TOKEN_BYTES = 32
TOKEN_MIN_LENGTH = 40
TOKEN_MAX_LENGTH = 128
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
GENERIC_INVALID_MESSAGE = (
    "This verification link is invalid or has expired. "
    "Request a new verification email to continue."
)


class VerificationRateLimited(Exception):
    def __init__(self, resend_available_at: datetime):
        self.resend_available_at = resend_available_at
        super().__init__("Verification resend is rate limited")


class VerificationTokenInvalid(Exception):
    pass


@dataclass(frozen=True, slots=True)
class VerificationDelivery:
    status: str
    last_sent_at: datetime | None
    resend_available_at: datetime | None
    expires_at: datetime | None
    newly_requested: bool = False


def hash_verification_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _aware(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


def _correlation_id(request: Request | None) -> str | None:
    if request is None:
        return None
    return (
        request.headers.get("x-request-id")
        or request.headers.get("x-correlation-id")
        or ""
    )[:128] or None


def _audit(
    db: Session,
    event: IdentityAuditEvent,
    *,
    user_id: int | None,
    request: Request | None,
    outcome: str = "SUCCESS",
    reason_code: str | None = None,
    delivery_status: str | None = None,
) -> None:
    metadata = {"target_type": "EMAIL_VERIFICATION"}
    if reason_code:
        metadata["reason_code"] = reason_code
    if delivery_status:
        metadata["delivery_status"] = delivery_status
    audit_service.write_authorization_audit(
        db,
        action=str(event),
        outcome=outcome,
        actor_user_id=user_id,
        target_user_id=user_id,
        tenant_id=None,
        request=request,
        new_value=metadata,
        detail=reason_code,
    )


def _latest_token(db: Session, user_id: int) -> EmailVerificationToken | None:
    return db.scalar(
        select(EmailVerificationToken)
        .where(EmailVerificationToken.user_id == user_id)
        .order_by(EmailVerificationToken.created_at.desc(), EmailVerificationToken.id.desc())
        .limit(1)
    )


def _delivery_from_token(
    token: EmailVerificationToken | None,
    *,
    newly_requested: bool = False,
) -> VerificationDelivery:
    if token is None:
        return VerificationDelivery("NOT_REQUESTED", None, None, None, newly_requested)
    settings = get_settings()
    created = _aware(token.created_at)
    last_sent = _aware(token.delivery_attempted_at)
    return VerificationDelivery(
        str(token.delivery_status),
        last_sent,
        created + timedelta(seconds=settings.email_verification_resend_cooldown_seconds)
        if created
        else None,
        _aware(token.expires_at),
        newly_requested,
    )


def _wait_for_delivery_resolution(
    db: Session,
    token_id: int,
) -> VerificationDelivery:
    """Observe an in-flight duplicate delivery after releasing all row locks."""
    settings = get_settings()
    deadline = time.monotonic() + min(
        30.0,
        settings.smtp_connect_timeout_seconds
        + settings.smtp_send_timeout_seconds
        + 1.0,
    )
    while time.monotonic() < deadline:
        token = db.get(EmailVerificationToken, token_id)
        if token is None:
            return VerificationDelivery("NOT_REQUESTED", None, None, None)
        db.refresh(token)
        if token.delivery_status != str(EmailDeliveryStatus.PENDING):
            return _delivery_from_token(token)
        time.sleep(0.025)
    token = db.get(EmailVerificationToken, token_id)
    return _delivery_from_token(token)


def verification_context(db: Session, user: IAMUser) -> VerificationContext | None:
    if user.email_verified and not user.verification_required:
        return VerificationContext(
            delivery_status=None,
            last_sent_at=None,
            resend_available_at=None,
            expires_at=None,
        )
    delivery = _delivery_from_token(_latest_token(db, user.id))
    return VerificationContext(
        delivery_status=delivery.status,
        last_sent_at=delivery.last_sent_at.isoformat() if delivery.last_sent_at else None,
        resend_available_at=(
            delivery.resend_available_at.isoformat()
            if delivery.resend_available_at
            else None
        ),
        expires_at=delivery.expires_at.isoformat() if delivery.expires_at else None,
    )


def _assert_eligible(user: IAMUser) -> None:
    if user.status == "DISABLED":
        raise identity_http_error(
            IdentityErrorCode.ACCOUNT_DISABLED,
            "This SBOM Analyzer account is disabled. Contact support.",
        )
    if user.status == "PENDING":
        raise identity_http_error(
            IdentityErrorCode.ACCOUNT_PENDING_APPROVAL,
            "This SBOM Analyzer account is awaiting administrator approval.",
        )
    if user.email_verified and not user.verification_required:
        raise identity_http_error(
            IdentityErrorCode.VERIFICATION_ALREADY_COMPLETED,
            "Email verification has already been completed.",
            status_code=409,
        )
    if not user.email:
        raise identity_http_error(
            IdentityErrorCode.VERIFICATION_DELIVERY_FAILED,
            "A verification email cannot be delivered. Contact support.",
            status_code=503,
        )


def _check_send_limits(
    db: Session,
    user_id: int,
    *,
    now: datetime,
    latest: EmailVerificationToken | None,
) -> None:
    settings = get_settings()
    if latest is not None:
        created = _aware(latest.created_at)
        if created is not None:
            available = created + timedelta(
                seconds=settings.email_verification_resend_cooldown_seconds
            )
            if now < available:
                raise VerificationRateLimited(available)
    hour_count = db.scalar(
        select(func.count(EmailVerificationToken.id)).where(
            EmailVerificationToken.user_id == user_id,
            EmailVerificationToken.created_at >= now - timedelta(hours=1),
        )
    )
    day_count = db.scalar(
        select(func.count(EmailVerificationToken.id)).where(
            EmailVerificationToken.user_id == user_id,
            EmailVerificationToken.created_at >= now - timedelta(days=1),
        )
    )
    if int(hour_count or 0) >= settings.email_verification_max_sends_per_hour:
        raise VerificationRateLimited(now + timedelta(hours=1))
    if int(day_count or 0) >= settings.email_verification_max_sends_per_day:
        raise VerificationRateLimited(now + timedelta(days=1))


def issue_verification_email(
    db: Session,
    user_id: int,
    *,
    request: Request | None = None,
    resend: bool,
    sender: VerificationEmailSender | None = None,
) -> VerificationDelivery:
    """Create one active token, commit it, then perform external delivery."""
    now = datetime.now(UTC)
    user = db.scalar(select(IAMUser).where(IAMUser.id == user_id).with_for_update())
    if user is None:
        raise identity_http_error(
            IdentityErrorCode.VERIFICATION_DELIVERY_FAILED,
            "A verification email cannot be delivered. Contact support.",
            status_code=503,
        )
    _assert_eligible(user)
    latest = _latest_token(db, user.id)
    current_email = normalize_email(user.email)
    if (
        not resend
        and latest is not None
        and normalize_email(latest.email_snapshot) == current_email
    ):
        latest_created = _aware(latest.created_at)
        if latest_created and now < latest_created + timedelta(
            seconds=get_settings().email_verification_resend_cooldown_seconds
        ):
            token_id = latest.id
            pending = latest.delivery_status == str(EmailDeliveryStatus.PENDING)
            db.commit()
            if pending:
                return _wait_for_delivery_resolution(db, token_id)
            return _delivery_from_token(latest)
        if (
            latest.consumed_at is None
            and latest.invalidated_at is None
            and (_aware(latest.expires_at) or now) > now
        ):
            token_id = latest.id
            pending = latest.delivery_status == str(EmailDeliveryStatus.PENDING)
            db.commit()
            if pending:
                return _wait_for_delivery_resolution(db, token_id)
            return _delivery_from_token(latest)
    try:
        _check_send_limits(
            db,
            user.id,
            now=now,
            latest=(
                latest
                if latest is not None
                and normalize_email(latest.email_snapshot) == current_email
                else None
            ),
        )
    except VerificationRateLimited:
        _audit(
            db,
            IdentityAuditEvent.VERIFICATION_RESEND_RATE_LIMITED,
            user_id=user.id,
            request=request,
            outcome="DENIED",
            reason_code=str(IdentityErrorCode.VERIFICATION_RESEND_RATE_LIMITED),
        )
        db.commit()
        raise
    if resend:
        _audit(
            db,
            IdentityAuditEvent.VERIFICATION_RESEND_REQUESTED,
            user_id=user.id,
            request=request,
        )
    invalidated = db.scalars(
        select(EmailVerificationToken).where(
            EmailVerificationToken.user_id == user.id,
            EmailVerificationToken.consumed_at.is_(None),
            EmailVerificationToken.invalidated_at.is_(None),
        )
    ).all()
    for old in invalidated:
        old.invalidated_at = now
        old.invalidation_reason = "SUPERSEDED_BY_RESEND"
    if invalidated:
        _audit(
            db,
            IdentityAuditEvent.VERIFICATION_TOKEN_INVALIDATED,
            user_id=user.id,
            request=request,
            reason_code="SUPERSEDED_BY_RESEND",
        )

    raw_token = secrets.token_urlsafe(TOKEN_BYTES)
    settings = get_settings()
    expires_at = now + timedelta(seconds=settings.email_verification_token_expiry_seconds)
    normalized_recipient = normalize_email(user.email)
    if normalized_recipient is None:
        raise identity_http_error(
            IdentityErrorCode.VERIFICATION_DELIVERY_FAILED,
            "A verification email cannot be delivered. Contact support.",
            status_code=503,
        )
    token = EmailVerificationToken(
        user_id=user.id,
        token_hash=hash_verification_token(raw_token),
        email_snapshot=normalized_recipient,
        expires_at=expires_at,
        created_at=now,
        correlation_id=_correlation_id(request),
        delivery_status=str(EmailDeliveryStatus.PENDING),
    )
    db.add(token)
    db.flush()
    token_id = token.id
    recipient = user.email
    recipient_name = user.display_name
    _audit(
        db,
        IdentityAuditEvent.VERIFICATION_TOKEN_CREATED,
        user_id=user.id,
        request=request,
    )
    db.commit()

    url = (
        f"{settings.email_verification_frontend_url.rstrip('?')}"
        f"?token={quote(raw_token, safe='')}"
    )
    delivery_sender = sender or get_verification_email_sender()
    try:
        result: EmailDeliveryResult = delivery_sender.send_verification_email(
            recipient_email=recipient,
            recipient_name=recipient_name,
            verification_url=url,
            expires_at=expires_at,
            correlation_id=_correlation_id(request),
        )
    except Exception:  # Provider boundary must fail closed without leaking details.
        result = EmailDeliveryResult(
            EmailDeliveryStatus.FAILED,
            "EMAIL_PROVIDER_UNEXPECTED_FAILURE",
        )
    del raw_token, url

    token = db.scalar(
        select(EmailVerificationToken)
        .where(EmailVerificationToken.id == token_id)
        .with_for_update()
    )
    if token is None:
        raise RuntimeError("Verification token disappeared during delivery")
    attempted = datetime.now(UTC)
    token.delivery_status = str(result.status)
    token.delivery_attempted_at = attempted
    token.delivery_error_code = result.error_code
    if result.status != EmailDeliveryStatus.SENT:
        token.invalidated_at = attempted
        token.invalidation_reason = "DELIVERY_NOT_CONFIRMED"
        event = IdentityAuditEvent.VERIFICATION_EMAIL_FAILED
        outcome = "FAILED"
    else:
        event = IdentityAuditEvent.VERIFICATION_EMAIL_SENT
        outcome = "SUCCESS"
    _audit(
        db,
        event,
        user_id=user_id,
        request=request,
        outcome=outcome,
        reason_code=result.error_code,
        delivery_status=str(result.status),
    )
    db.commit()
    return _delivery_from_token(token, newly_requested=True)


def ensure_initial_verification_delivery(
    db: Session,
    user: IAMUser,
    *,
    request: Request | None = None,
    sender: VerificationEmailSender | None = None,
) -> VerificationDelivery | None:
    if user.status != "ACTIVE" or user.email_verified or not user.verification_required:
        return None
    latest = _latest_token(db, user.id)
    if (
        latest is not None
        and normalize_email(latest.email_snapshot) == normalize_email(user.email)
        and not get_settings().email_delivery_enabled
    ):
        return _delivery_from_token(latest)
    try:
        return issue_verification_email(
            db,
            user.id,
            request=request,
            resend=False,
            sender=sender,
        )
    except VerificationRateLimited:
        return _delivery_from_token(_latest_token(db, user.id))


def _reject_confirmation(
    db: Session,
    event: IdentityAuditEvent,
    *,
    user_id: int | None,
    request: Request | None,
    reason_code: str,
) -> None:
    _audit(
        db,
        event,
        user_id=user_id,
        request=request,
        outcome="DENIED",
        reason_code=reason_code,
    )
    db.commit()
    raise VerificationTokenInvalid(GENERIC_INVALID_MESSAGE)


def confirm_verification_token(
    db: Session,
    raw_token: str,
    *,
    request: Request | None = None,
) -> IAMUser:
    if (
        not isinstance(raw_token, str)
        or not TOKEN_MIN_LENGTH <= len(raw_token) <= TOKEN_MAX_LENGTH
        or TOKEN_PATTERN.fullmatch(raw_token) is None
    ):
        _reject_confirmation(
            db,
            IdentityAuditEvent.EMAIL_VERIFICATION_FAILED,
            user_id=None,
            request=request,
            reason_code="TOKEN_MALFORMED",
        )
    token_hash = hash_verification_token(raw_token)
    token = db.scalar(
        select(EmailVerificationToken).where(
            EmailVerificationToken.token_hash == token_hash
        )
    )
    now = datetime.now(UTC)
    if token is None:
        _reject_confirmation(
            db,
            IdentityAuditEvent.EMAIL_VERIFICATION_FAILED,
            user_id=None,
            request=request,
            reason_code="TOKEN_UNKNOWN",
        )
    user_id = int(token.user_id)
    user = db.scalar(select(IAMUser).where(IAMUser.id == user_id).with_for_update())
    token = db.scalar(
        select(EmailVerificationToken)
        .where(EmailVerificationToken.token_hash == token_hash)
        .with_for_update()
    )
    if token is None:
        _reject_confirmation(
            db,
            IdentityAuditEvent.EMAIL_VERIFICATION_FAILED,
            user_id=user_id,
            request=request,
            reason_code="TOKEN_UNKNOWN",
        )
    if token.consumed_at is not None or token.invalidated_at is not None:
        _reject_confirmation(
            db,
            IdentityAuditEvent.EMAIL_VERIFICATION_REPLAY_REJECTED,
            user_id=user_id,
            request=request,
            reason_code="TOKEN_INACTIVE",
        )
    if (_aware(token.expires_at) or now) <= now:
        token.invalidated_at = now
        token.invalidation_reason = "EXPIRED"
        _reject_confirmation(
            db,
            IdentityAuditEvent.EMAIL_VERIFICATION_EXPIRED,
            user_id=user_id,
            request=request,
            reason_code="TOKEN_EXPIRED",
        )
    if user is None or user.status != "ACTIVE":
        _reject_confirmation(
            db,
            IdentityAuditEvent.EMAIL_VERIFICATION_FAILED,
            user_id=user_id,
            request=request,
            reason_code="USER_INELIGIBLE",
        )
    if user.email_verified or not user.verification_required:
        _reject_confirmation(
            db,
            IdentityAuditEvent.EMAIL_VERIFICATION_REPLAY_REJECTED,
            user_id=user_id,
            request=request,
            reason_code="ALREADY_VERIFIED",
        )
    if normalize_email(user.email) != normalize_email(token.email_snapshot):
        token.invalidated_at = now
        token.invalidation_reason = "EMAIL_CHANGED"
        _reject_confirmation(
            db,
            IdentityAuditEvent.EMAIL_VERIFICATION_EMAIL_MISMATCH,
            user_id=user_id,
            request=request,
            reason_code="EMAIL_MISMATCH",
        )

    user.email_verified = True
    user.email_verified_at = now
    user.verification_required = False
    user.updated_at = now
    token.consumed_at = now
    db.execute(
        update(EmailVerificationToken)
        .where(
            EmailVerificationToken.user_id == user.id,
            EmailVerificationToken.id != token.id,
            EmailVerificationToken.consumed_at.is_(None),
            EmailVerificationToken.invalidated_at.is_(None),
        )
        .values(invalidated_at=now, invalidation_reason="VERIFICATION_COMPLETED")
    )
    _audit(
        db,
        IdentityAuditEvent.EMAIL_VERIFICATION_SUCCEEDED,
        user_id=user.id,
        request=request,
    )
    db.commit()
    return user


def cleanup_verification_tokens(db: Session, *, now: datetime | None = None) -> int:
    current = now or datetime.now(UTC)
    cutoff = current - timedelta(days=get_settings().email_verification_token_retention_days)
    result = db.execute(
        delete(EmailVerificationToken).where(
            EmailVerificationToken.created_at < cutoff,
            (
                EmailVerificationToken.consumed_at.is_not(None)
                | EmailVerificationToken.invalidated_at.is_not(None)
                | (EmailVerificationToken.expires_at < cutoff)
            ),
        )
    )
    db.commit()
    return int(getattr(result, "rowcount", 0) or 0)
