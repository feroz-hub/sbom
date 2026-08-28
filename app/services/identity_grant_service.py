"""Database-backed validation for parsed HCL IAM identity grants."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.identity_grants import IdentityGrantScope, ParsedIdentityGrant
from app.models import AuthorizationRole, Tenant


class IdentityGrantValidationReason(StrEnum):
    """Machine-stable reasons why a parsed identity grant is invalid locally."""

    INVALID_GRANT_TYPE = "INVALID_GRANT_TYPE"
    INVALID_SCOPE = "INVALID_SCOPE"
    TENANT_KEY_REQUIRED = "TENANT_KEY_REQUIRED"
    PLATFORM_TENANT_KEY_FORBIDDEN = "PLATFORM_TENANT_KEY_FORBIDDEN"
    TENANT_NOT_FOUND = "TENANT_NOT_FOUND"
    TENANT_INACTIVE = "TENANT_INACTIVE"
    ROLE_NOT_FOUND = "ROLE_NOT_FOUND"
    ROLE_INACTIVE = "ROLE_INACTIVE"
    ROLE_SCOPE_MISMATCH = "ROLE_SCOPE_MISMATCH"


class IdentityGrantValidationError(ValueError):
    """Controlled failure for a grant that has no valid local definition."""

    def __init__(self, reason: IdentityGrantValidationReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


@dataclass(frozen=True, slots=True)
class ValidatedIdentityGrant:
    """Immutable local tenant/role resolution result; not an access decision."""

    scope: IdentityGrantScope
    role: str
    tenant_key: str | None
    tenant_id: int | None


def _fail(reason: IdentityGrantValidationReason) -> NoReturn:
    raise IdentityGrantValidationError(reason)


def _role_for_scope(
    db: Session,
    *,
    code: str,
    scope: IdentityGrantScope,
) -> AuthorizationRole:
    roles = tuple(
        db.scalars(
            select(AuthorizationRole)
            .where(AuthorizationRole.code == code)
            .order_by(AuthorizationRole.id)
        )
    )
    if not roles:
        _fail(IdentityGrantValidationReason.ROLE_NOT_FOUND)
    role = next((item for item in roles if item.scope == scope.value), None)
    if role is None:
        _fail(IdentityGrantValidationReason.ROLE_SCOPE_MISMATCH)
    if role.status != "ACTIVE":
        _fail(IdentityGrantValidationReason.ROLE_INACTIVE)
    return role


def validate_identity_grant(
    db: Session,
    grant: ParsedIdentityGrant,
) -> ValidatedIdentityGrant:
    """Validate one parsed grant against active tenant and role catalogue rows.

    The function performs no user, membership, permission, JWT, request, or
    authorization-mode processing. A successful result is not an access decision.
    """
    if not isinstance(grant, ParsedIdentityGrant):
        _fail(IdentityGrantValidationReason.INVALID_GRANT_TYPE)

    if grant.scope is IdentityGrantScope.TENANT:
        if grant.tenant_key is None:
            _fail(IdentityGrantValidationReason.TENANT_KEY_REQUIRED)
        tenant = db.scalar(
            select(Tenant).where(Tenant.tenant_key == grant.tenant_key)
        )
        if tenant is None:
            _fail(IdentityGrantValidationReason.TENANT_NOT_FOUND)
        if tenant.status != "ACTIVE":
            _fail(IdentityGrantValidationReason.TENANT_INACTIVE)
        _role_for_scope(db, code=grant.role, scope=grant.scope)
        return ValidatedIdentityGrant(
            scope=grant.scope,
            role=grant.role,
            tenant_key=grant.tenant_key,
            tenant_id=tenant.id,
        )

    if grant.scope is IdentityGrantScope.PLATFORM:
        if grant.tenant_key is not None:
            _fail(IdentityGrantValidationReason.PLATFORM_TENANT_KEY_FORBIDDEN)
        _role_for_scope(db, code=grant.role, scope=grant.scope)
        return ValidatedIdentityGrant(
            scope=grant.scope,
            role=grant.role,
            tenant_key=None,
            tenant_id=None,
        )

    _fail(IdentityGrantValidationReason.INVALID_SCOPE)
