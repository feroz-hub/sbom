"""PostgreSQL owns delivery. Celery receives no user/token/payload arguments.

Locks serialize workers and issuance. SMTP cannot offer exactly-once delivery:
a crash after SMTP acceptance but before commit can resend the SAME token with
the SAME Message-ID. No retry ever issues credentials or accounts.
"""

import base64
import os
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import delete, or_, select, update

from ..db import SessionLocal
from ..models import AccountActionToken, IAMUser, SecurityMailOutbox
from ..settings import get_settings
from . import audit_service


def cipher():
    try:
        key = base64.b64decode(get_settings().native_security_outbox_key, validate=True)
        if len(key) != 32:
            raise ValueError()
        return AESGCM(key)
    except Exception:
        raise RuntimeError("Security mail encryption is not configured") from None


def aad(token_id, purpose, recipient):
    return f"{token_id}:{purpose}:{recipient}".encode()


def enqueue(db, issued, user_id, purpose):
    if not get_settings().native_security_outbox_enabled:
        return
    now = datetime.now(UTC)
    nonce = os.urandom(12)
    payload = nonce + cipher().encrypt(nonce, issued.raw_token.encode(), aad(issued.id, purpose, issued.email_snapshot))
    db.execute(
        update(SecurityMailOutbox)
        .where(
            SecurityMailOutbox.user_id == user_id,
            SecurityMailOutbox.purpose == purpose,
            SecurityMailOutbox.status == "PENDING",
        )
        .values(status="CANCELLED", payload=None)
    )
    db.add(
        SecurityMailOutbox(
            token_id=issued.id,
            user_id=user_id,
            purpose=purpose,
            recipient=issued.email_snapshot,
            payload=payload,
            status="PENDING",
            attempts=0,
            next_attempt_at=now,
            created_at=now,
            expires_at=issued.expires_at,
        )
    )
    db.flush()


def deliver_one(row_id):
    from .account_action_token_service import IssuedAccountActionToken
    from .native_enrollment_service import deliver_activation
    from .native_security_delivery import deliver_reset

    with SessionLocal() as db:
        uid = db.scalar(select(SecurityMailOutbox.user_id).where(SecurityMailOutbox.id == row_id))
        if uid is None:
            return
        user = db.scalar(select(IAMUser).where(IAMUser.id == uid).with_for_update())
        row = db.scalar(
            select(SecurityMailOutbox).where(SecurityMailOutbox.id == row_id).with_for_update(skip_locked=True)
        )
        now = datetime.now(UTC)
        if row is None or row.status != "PENDING":
            return
        token = db.get(AccountActionToken, row.token_id, populate_existing=True)
        if row.expires_at <= now:
            row.status = "EXPIRED"
        elif (
            not token
            or token.invalidated_at
            or token.consumed_at
            or token.email_snapshot != row.recipient
            or not user
            or user.email.strip().lower() != row.recipient
            or (row.purpose == "ACCOUNT_ACTIVATION" and user.status != "PENDING_EMAIL_VERIFICATION")
            or (row.purpose == "PASSWORD_RESET" and user.status not in {"ACTIVE", "LOCKED", "FORCE_PASSWORD_CHANGE"})
        ):
            row.status = "CANCELLED"
        elif row.next_attempt_at > now:
            return
        else:
            row.attempts += 1
            try:
                raw = (
                    cipher()
                    .decrypt(row.payload[:12], row.payload[12:], aad(row.token_id, row.purpose, row.recipient))
                    .decode()
                )
                issued = IssuedAccountActionToken(row.token_id, raw, row.expires_at, row.recipient)
                result = (deliver_activation if row.purpose == "ACCOUNT_ACTIVATION" else deliver_reset)(user, issued)
                sent = result["status"] == "SENT"
            except Exception:
                # No exception text, token, recipient or ciphertext in logs/audit.
                sent = False
            if sent:
                row.status, row.sent_at = "DELIVERED", now
            elif row.attempts >= get_settings().native_security_outbox_max_attempts:
                row.status, row.failed_at = "FAILED", now
            else:
                row.next_attempt_at = now + timedelta(seconds=min(3600, 30 * 2 ** (row.attempts - 1)))
        if row.status != "PENDING":
            row.payload = None
        audit_service.write_authorization_audit(
            db,
            action="SECURITY_MAIL_DELIVERY",
            target_user_id=uid,
            outcome="SUCCESS" if row.status == "DELIVERED" else "FAILED",
            new_value={"delivery_id": row.id, "status": row.status, "attempt": row.attempts},
        )
        db.commit()


def dispatch():
    if not get_settings().native_security_outbox_enabled:
        return
    with SessionLocal() as db:
        now = datetime.now(UTC)
        ids = list(
            db.scalars(
                select(SecurityMailOutbox.id)
                .where(SecurityMailOutbox.status == "PENDING", or_(SecurityMailOutbox.next_attempt_at <= now, SecurityMailOutbox.expires_at <= now))
                .order_by(SecurityMailOutbox.id)
                .limit(100)
            )
        )
        # Retain safe delivery metadata only for seven days after expiry.
        db.execute(delete(SecurityMailOutbox).where(SecurityMailOutbox.expires_at < now - timedelta(days=7)))
        db.commit()
    for row_id in ids:
        deliver_one(row_id)
