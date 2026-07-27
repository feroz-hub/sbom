"""Local identity normalization and compatibility lookup primitives.

The external identity authority is the exact trusted JWT issuer plus its
stable subject.  Email, UPN, and employee ID are mutable profile attributes
and are deliberately excluded from identity lookup.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from fastapi import Request
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError, MultipleResultsFound, SQLAlchemyError
from sqlalchemy.orm import Session

from ..core.identity_states import (
    IdentityAuditEvent,
    IdentityErrorCode,
    identity_http_error,
)
from ..models import EmailVerificationToken, IAMUser
from ..settings import get_settings
from . import audit_service

MAX_ISSUER_LENGTH = 512
MAX_SUBJECT_LENGTH = 255
MAX_EMAIL_LENGTH = 320
MAX_UPN_LENGTH = 320
MAX_EMPLOYEE_ID_LENGTH = 128
MAX_PROFILE_VALUE_LENGTH = 255


def _required_text(value: Any, *, field: str, max_length: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field} must not be empty")
    if len(normalized) > max_length:
        raise ValueError(f"{field} exceeds maximum length {max_length}")
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise ValueError(f"{field} contains control characters")
    return normalized


def normalize_issuer(value: Any) -> str:
    """Trim an issuer without altering its case, path, or trailing slash.

    JWT validation requires an exact issuer match, so this function does not
    silently collapse issuer URLs that the token validator treats as distinct.
    """
    issuer = _required_text(value, field="issuer", max_length=MAX_ISSUER_LENGTH)
    parsed = urlsplit(issuer)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("issuer must be an absolute HTTPS URL without credentials, query, or fragment")
    return issuer


def normalize_subject(value: Any) -> str:
    return _required_text(value, field="subject", max_length=MAX_SUBJECT_LENGTH)


def normalize_email(value: Any) -> str | None:
    if value is None:
        return None
    email = _required_text(value, field="email", max_length=MAX_EMAIL_LENGTH).lower()
    local, separator, domain = email.rpartition("@")
    if (
        not separator
        or email.count("@") != 1
        or not local
        or not domain
        or local.startswith(".")
        or local.endswith(".")
        or ".." in local
        or ".." in domain
        or domain.startswith(("-", "."))
        or domain.endswith(("-", "."))
        or any(character.isspace() for character in email)
    ):
        raise ValueError("email is invalid")
    return email


def normalize_user_principal_name(value: Any) -> str | None:
    if value is None:
        return None
    return _required_text(value, field="user principal name", max_length=MAX_UPN_LENGTH).lower()


def normalize_display_name(value: Any) -> str:
    return _required_text(value, field="display name", max_length=MAX_PROFILE_VALUE_LENGTH)


def normalize_department(value: Any) -> str | None:
    return normalize_optional_profile_value(value, field="department")


def normalize_optional_profile_value(
    value: Any,
    *,
    field: str,
    max_length: int = MAX_PROFILE_VALUE_LENGTH,
) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    normalized = value.strip()
    if not normalized:
        return None
    if len(normalized) > max_length:
        raise ValueError(f"{field} exceeds maximum length {max_length}")
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise ValueError(f"{field} contains control characters")
    return normalized


def normalize_employee_id(value: Any) -> str | None:
    return normalize_optional_profile_value(
        value,
        field="employee ID",
        max_length=MAX_EMPLOYEE_ID_LENGTH,
    )


def find_by_external_identity(
    db: Session,
    *,
    issuer: str,
    subject: str,
    for_update: bool = False,
) -> IAMUser | None:
    """Find exactly one composite identity; duplicate rows fail closed."""
    normalized_issuer = normalize_issuer(issuer)
    normalized_subject = normalize_subject(subject)
    statement = select(IAMUser).where(
        IAMUser.external_issuer == normalized_issuer,
        IAMUser.external_subject == normalized_subject,
    )
    if for_update:
        statement = statement.with_for_update()
    return db.execute(statement).scalar_one_or_none()


def find_by_legacy_external_id(
    db: Session,
    external_iam_user_id: str,
    *,
    for_update: bool = False,
) -> IAMUser | None:
    """Compatibility lookup for callers not yet upgraded to issuer + subject."""
    normalized_subject = normalize_subject(external_iam_user_id)
    statement = select(IAMUser).where(
        IAMUser.external_iam_user_id == normalized_subject
    )
    if for_update:
        statement = statement.with_for_update()
    return db.execute(statement).scalar_one_or_none()


def normalized_profile_from_claims(claims: dict[str, Any]) -> dict[str, str | None]:
    return {
        "email": normalize_email(claims.get("email")),
        "display_name": normalize_optional_profile_value(
            claims.get("name") or claims.get("preferred_username"),
            field="display name",
        ),
        "employee_id": normalize_employee_id(claims.get("employee_id")),
        "user_principal_name": normalize_user_principal_name(claims.get("preferred_username")),
        "department": normalize_optional_profile_value(claims.get("department"), field="department"),
    }


@dataclass(frozen=True, slots=True)
class ExternalIdentityClaims:
    issuer: str
    subject: str
    email: str
    display_name: str
    preferred_username: str
    employee_id: str | None
    department: str | None


@dataclass(frozen=True, slots=True)
class ProvisioningResult:
    user: IAMUser
    created: bool
    linked: bool
    changed_fields: tuple[str, ...]
    email_changed: bool

    @property
    def changed(self) -> bool:
        return self.created or self.linked or bool(self.changed_fields)


def validate_external_identity_claims(
    claims: dict[str, Any],
    *,
    require_employee_id: bool | None = None,
) -> ExternalIdentityClaims:
    """Validate and normalize trusted identity claims after JWT validation."""
    require_employee_id = (
        get_settings().hcl_iam_require_employee_id
        if require_employee_id is None
        else require_employee_id
    )
    try:
        issuer = normalize_issuer(claims.get("iss"))
        subject = normalize_subject(claims.get("sub"))
        email = normalize_email(claims.get("email"))
        display_name = normalize_display_name(claims.get("name"))
        preferred_username = normalize_user_principal_name(claims.get("preferred_username"))
        employee_id = normalize_employee_id(claims.get("employee_id"))
        department = normalize_department(claims.get("department"))
        if email is None or preferred_username is None:
            raise ValueError("required identity claim is missing")
        if require_employee_id and employee_id is None:
            raise ValueError("employee ID is required")
    except (TypeError, ValueError):
        raise identity_http_error(
            IdentityErrorCode.REQUIRED_CLAIM_MISSING,
            "The access token does not contain a valid required identity profile.",
            status_code=401,
        ) from None
    return ExternalIdentityClaims(
        issuer=issuer,
        subject=subject,
        email=email,
        display_name=display_name,
        preferred_username=preferred_username,
        employee_id=employee_id,
        department=department,
    )


def _subject_fingerprint(identity: ExternalIdentityClaims) -> str:
    digest = hashlib.sha256(f"{identity.issuer}\0{identity.subject}".encode()).hexdigest()
    return digest[:24]


def _collision_safe_legacy_id(identity: ExternalIdentityClaims) -> str:
    """Preserve the deprecated unique key when two issuers reuse one subject.

    Phase 3 retained a single-column uniqueness constraint for compatibility,
    while the authoritative identity is the issuer/subject pair. The first
    issuer keeps the historical subject value; later issuer collisions receive
    a deterministic compatibility-only value.
    """
    digest = hashlib.sha256(f"{identity.issuer}\0{identity.subject}".encode()).hexdigest()
    return f"{identity.subject[:188]}::{digest}"


def _audit_identity(
    db: Session,
    *,
    event: IdentityAuditEvent,
    user_id: int | None,
    request: Request | None,
    outcome: str = "SUCCESS",
    changed_fields: list[str] | tuple[str, ...] | None = None,
    reason_code: str | None = None,
    identity: ExternalIdentityClaims | None = None,
) -> None:
    metadata: dict[str, Any] = {"target_type": "IAM_USER"}
    if changed_fields:
        metadata["changed_fields"] = sorted(changed_fields)
    if reason_code:
        metadata["reason_code"] = reason_code
    if identity:
        metadata["issuer"] = identity.issuer
        metadata["subject_fingerprint"] = _subject_fingerprint(identity)
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


def _identity_conflict(
    db: Session,
    identity: ExternalIdentityClaims,
    request: Request | None,
) -> None:
    _audit_identity(
        db,
        event=IdentityAuditEvent.IDENTITY_CONFLICT,
        user_id=None,
        request=request,
        outcome="DENIED",
        reason_code=str(IdentityErrorCode.IDENTITY_CONFLICT),
        identity=identity,
    )
    raise identity_http_error(
        IdentityErrorCode.IDENTITY_CONFLICT,
        "The external identity conflicts with an existing local account. Contact support.",
    )


def _elapsed_seconds(value: datetime | None, now: datetime) -> float:
    if value is None:
        return float("inf")
    comparable = value.replace(tzinfo=UTC) if value.tzinfo is None else value
    return (now - comparable).total_seconds()


def _synchronize_user(
    db: Session,
    user: IAMUser,
    identity: ExternalIdentityClaims,
    *,
    now: datetime,
    request: Request | None,
) -> tuple[tuple[str, ...], bool]:
    changed_fields: list[str] = []
    email_changed = False
    if user.email != identity.email:
        user.email = identity.email
        user.email_verified = False
        user.email_verified_at = None
        user.verification_required = True
        changed_fields.append("email")
        email_changed = True

    for field, value in (
        ("display_name", identity.display_name),
        ("user_principal_name", identity.preferred_username),
        ("employee_id", identity.employee_id),
        ("department", identity.department),
    ):
        if getattr(user, field) != value:
            setattr(user, field, value)
            changed_fields.append(field)

    sync_due = _elapsed_seconds(user.last_claim_sync_at, now) >= get_settings().identity_claim_sync_interval_seconds
    if changed_fields or sync_due:
        user.last_claim_sync_at = now
    if _elapsed_seconds(user.last_login_at, now) > 300:
        user.last_login_at = now
        changed_fields.append("last_login_at")
    if changed_fields or sync_due:
        user.updated_at = now
        db.add(user)
        db.flush()

    profile_fields = tuple(field for field in changed_fields if field != "last_login_at")
    if profile_fields:
        _audit_identity(
            db,
            event=IdentityAuditEvent.CLAIMS_SYNCHRONIZED,
            user_id=user.id,
            request=request,
            changed_fields=profile_fields,
            identity=identity,
        )
    if email_changed:
        invalidated_at = now
        result = db.execute(
            update(EmailVerificationToken)
            .where(
                EmailVerificationToken.user_id == user.id,
                EmailVerificationToken.consumed_at.is_(None),
                EmailVerificationToken.invalidated_at.is_(None),
            )
            .values(
                invalidated_at=invalidated_at,
                invalidation_reason="EMAIL_CHANGED",
            )
        )
        if int(getattr(result, "rowcount", 0) or 0):
            _audit_identity(
                db,
                event=IdentityAuditEvent.VERIFICATION_TOKEN_INVALIDATED,
                user_id=user.id,
                request=request,
                reason_code="EMAIL_CHANGED",
                identity=identity,
            )
        _audit_identity(
            db,
            event=IdentityAuditEvent.EMAIL_CHANGED,
            user_id=user.id,
            request=request,
            changed_fields=("email",),
            identity=identity,
        )
        _audit_identity(
            db,
            event=IdentityAuditEvent.REVERIFICATION_REQUIRED,
            user_id=user.id,
            request=request,
            reason_code=str(IdentityErrorCode.EMAIL_VERIFICATION_REQUIRED),
            identity=identity,
        )
    return tuple(changed_fields), email_changed


def provision_local_identity(
    db: Session,
    claims: dict[str, Any] | ExternalIdentityClaims,
    *,
    request: Request | None = None,
    before_insert: Any | None = None,
) -> ProvisioningResult:
    """Provision or synchronize one local identity without committing.

    The caller owns the outer transaction. A nested transaction confines a
    first-login uniqueness race so unrelated caller state is not rolled back.
    """
    identity = (
        claims
        if isinstance(claims, ExternalIdentityClaims)
        else validate_external_identity_claims(claims)
    )
    now = datetime.now(UTC)
    try:
        composite = find_by_external_identity(
            db,
            issuer=identity.issuer,
            subject=identity.subject,
            for_update=True,
        )
        legacy = find_by_legacy_external_id(
            db,
            identity.subject,
            for_update=True,
        )
    except MultipleResultsFound:
        _identity_conflict(db, identity, request)

    if composite is not None and legacy is not None and composite.id != legacy.id:
        _identity_conflict(db, identity, request)

    linked = False
    created = False
    legacy_external_id = identity.subject
    user = composite
    if user is None and legacy is not None:
        if (
            legacy.external_issuer not in (None, identity.issuer)
            and legacy.external_subject == identity.subject
        ):
            # The same opaque subject may legitimately be issued by separate
            # authorities. Do not merge them through the deprecated key.
            legacy_external_id = _collision_safe_legacy_id(identity)
            legacy = None

    if user is None and legacy is not None:
        if (
            legacy.external_issuer not in (None, identity.issuer)
            or legacy.external_subject not in (None, identity.subject)
        ):
            _identity_conflict(db, identity, request)
        try:
            with db.begin_nested():
                legacy.external_issuer = identity.issuer
                legacy.external_subject = identity.subject
                db.add(legacy)
                db.flush()
            user = legacy
            linked = True
        except IntegrityError:
            user = find_by_external_identity(
                db,
                issuer=identity.issuer,
                subject=identity.subject,
                for_update=True,
            )
            if user is None or user.id != legacy.id:
                _identity_conflict(db, identity, request)
        if linked:
            assert user is not None
            _audit_identity(
                db,
                event=IdentityAuditEvent.EXTERNAL_IDENTITY_LINKED,
                user_id=user.id,
                request=request,
                identity=identity,
            )

    if user is None:
        if before_insert is not None:
            before_insert()
        candidate = IAMUser(
            external_iam_user_id=legacy_external_id,
            external_issuer=identity.issuer,
            external_subject=identity.subject,
            email=identity.email,
            display_name=identity.display_name,
            employee_id=identity.employee_id,
            user_principal_name=identity.preferred_username,
            department=identity.department,
            status="ACTIVE",
            email_verified=False,
            email_verified_at=None,
            verification_required=True,
            last_claim_sync_at=now,
            last_login_at=now,
            created_at=now,
            updated_at=now,
        )
        try:
            with db.begin_nested():
                db.add(candidate)
                db.flush()
            user = candidate
            created = True
        except IntegrityError:
            user = find_by_external_identity(
                db,
                issuer=identity.issuer,
                subject=identity.subject,
                for_update=True,
            )
            if user is None:
                _identity_conflict(db, identity, request)
        except SQLAlchemyError:
            _audit_identity(
                db,
                event=IdentityAuditEvent.USER_PROVISIONING_FAILED,
                user_id=None,
                request=request,
                outcome="FAILED",
                reason_code=str(IdentityErrorCode.PROVISIONING_FAILED),
                identity=identity,
            )
            raise identity_http_error(
                IdentityErrorCode.PROVISIONING_FAILED,
                "Local identity provisioning is temporarily unavailable.",
                status_code=503,
            ) from None
        if created:
            assert user is not None
            _audit_identity(
                db,
                event=IdentityAuditEvent.USER_PROVISIONED,
                user_id=user.id,
                request=request,
                changed_fields=(
                    "email",
                    "display_name",
                    "user_principal_name",
                    "employee_id",
                    "department",
                ),
                identity=identity,
            )

    changed_fields: tuple[str, ...] = ()
    email_changed = False
    if not created:
        changed_fields, email_changed = _synchronize_user(
            db,
            user,
            identity,
            now=now,
            request=request,
        )
    return ProvisioningResult(
        user=user,
        created=created,
        linked=linked,
        changed_fields=changed_fields,
        email_changed=email_changed,
    )
