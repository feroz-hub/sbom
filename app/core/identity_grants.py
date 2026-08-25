"""Deterministic parsing for one future HCL IAM identity grant value."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from app.core.tenant_keys import is_valid_tenant_key

_ROLE_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")
_PLATFORM_SCOPE = "platform"
_PLATFORM_ADMIN_ROLE = "PLATFORM_ADMIN"


class IdentityGrantScope(StrEnum):
    """Static scope encoded by an IAM identity grant value."""

    TENANT = "TENANT"
    PLATFORM = "PLATFORM"


@dataclass(frozen=True, slots=True)
class ParsedIdentityGrant:
    """Immutable, syntax-only representation of one identity grant."""

    scope: IdentityGrantScope
    role: str
    tenant_key: str | None


class IdentityGrantParseError(ValueError):
    """Raised when one identity grant does not match the canonical grammar."""


def parse_identity_grant(value: object) -> ParsedIdentityGrant:
    """Parse one ``<tenant_key>:<role>`` or ``platform:PLATFORM_ADMIN`` value.

    This parser performs syntax and static scope validation only. Tenant and
    role existence, activation, and authorization are validated in later phases.
    """
    if not isinstance(value, str):
        raise IdentityGrantParseError("identity grant must be a string")
    if not value:
        raise IdentityGrantParseError("identity grant must not be empty")
    if value != value.strip():
        raise IdentityGrantParseError("identity grant must not contain surrounding whitespace")
    if value.count(":") != 1:
        raise IdentityGrantParseError("identity grant must contain exactly one ':' delimiter")

    scope_value, role = value.split(":")
    if not scope_value:
        raise IdentityGrantParseError("identity grant scope must not be empty")
    if not role:
        raise IdentityGrantParseError("identity grant role must not be empty")
    if not _ROLE_PATTERN.fullmatch(role):
        raise IdentityGrantParseError("identity grant role must use uppercase identifier syntax")

    if scope_value == _PLATFORM_SCOPE:
        if role != _PLATFORM_ADMIN_ROLE:
            raise IdentityGrantParseError("platform scope only permits PLATFORM_ADMIN")
        return ParsedIdentityGrant(
            scope=IdentityGrantScope.PLATFORM,
            role=role,
            tenant_key=None,
        )

    if not is_valid_tenant_key(scope_value):
        raise IdentityGrantParseError("identity grant tenant key is not canonical")
    if role == _PLATFORM_ADMIN_ROLE:
        raise IdentityGrantParseError("PLATFORM_ADMIN is reserved for platform scope")
    return ParsedIdentityGrant(
        scope=IdentityGrantScope.TENANT,
        role=role,
        tenant_key=scope_value,
    )
