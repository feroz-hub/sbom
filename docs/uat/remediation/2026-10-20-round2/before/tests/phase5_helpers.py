from __future__ import annotations

from datetime import UTC, datetime
from threading import Lock
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

from app.models import IAMUser
from app.services.email_sender import EmailDeliveryResult, EmailDeliveryStatus


class FakeVerificationEmailSender:
    def __init__(
        self,
        status: EmailDeliveryStatus = EmailDeliveryStatus.SENT,
        error_code: str | None = None,
    ):
        self.status = status
        self.error_code = error_code
        self.messages: list[dict] = []
        self._lock = Lock()

    def send_verification_email(self, **message) -> EmailDeliveryResult:
        with self._lock:
            self.messages.append(dict(message))
        return EmailDeliveryResult(self.status, self.error_code)

    @property
    def raw_token(self) -> str:
        return parse_qs(urlsplit(self.messages[-1]["verification_url"]).query)["token"][0]


def seed_unverified_user(
    db,
    *,
    status: str = "ACTIVE",
    email: str | None = None,
    suffix: str | None = None,
) -> IAMUser:
    value = suffix or uuid4().hex
    now = datetime.now(UTC)
    user = IAMUser(
        external_iam_user_id=f"phase5-{value}",
        external_issuer="https://hcl-cs.example.test",
        external_subject=f"phase5-{value}",
        email=email or f"phase5-{value}@example.test",
        display_name="Phase Five User",
        user_principal_name=f"phase5-{value}@example.test",
        employee_id=f"employee-{value[:12]}",
        status=status,
        email_verified=False,
        email_verified_at=None,
        verification_required=True,
        created_at=now,
        updated_at=now,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def claims_for_user(user: IAMUser, **overrides) -> dict:
    values = {
        "iss": user.external_issuer,
        "sub": user.external_subject,
        "email": user.email,
        "name": user.display_name,
        "preferred_username": user.user_principal_name,
        "employee_id": user.employee_id,
    }
    values.update(overrides)
    return values
