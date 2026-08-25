from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from app.core.identity_grants import (
    IdentityGrantParseError,
    IdentityGrantScope,
    ParsedIdentityGrant,
    parse_identity_grant,
)

TENANT_KEY_ONE = "tnt_00000000000000000000000000000001"
TENANT_KEY_TWO = "tnt_abcdefabcdefabcdefabcdefabcdefab"


@pytest.mark.parametrize(
    ("tenant_key", "role"),
    [
        (TENANT_KEY_ONE, "TENANT_ADMIN"),
        (TENANT_KEY_TWO, "SECURITY_ANALYST"),
    ],
)
def test_valid_tenant_grant_parses(tenant_key: str, role: str) -> None:
    grant = parse_identity_grant(f"{tenant_key}:{role}")

    assert grant == ParsedIdentityGrant(
        scope=IdentityGrantScope.TENANT,
        tenant_key=tenant_key,
        role=role,
    )


def test_syntactically_valid_unknown_tenant_role_parses_without_catalogue_lookup() -> None:
    grant = parse_identity_grant(f"{TENANT_KEY_ONE}:NON_EXISTENT_ROLE")

    assert grant.scope is IdentityGrantScope.TENANT
    assert grant.tenant_key == TENANT_KEY_ONE
    assert grant.role == "NON_EXISTENT_ROLE"


def test_platform_admin_grant_parses() -> None:
    grant = parse_identity_grant("platform:PLATFORM_ADMIN")

    assert grant.scope is IdentityGrantScope.PLATFORM
    assert grant.tenant_key is None
    assert grant.role == "PLATFORM_ADMIN"


@pytest.mark.parametrize(
    "value",
    [
        "no-delimiter",
        "tenant:role:extra",
        ":TENANT_ADMIN",
        f"{TENANT_KEY_ONE}:",
        "platform:",
        "tnt_invalid:TENANT_ADMIN",
        "tnt_ABCDEFABCDEFABCDEFABCDEFABCDEFAB:TENANT_ADMIN",
        "Tnt_abcdefabcdefabcdefabcdefabcdefab:TENANT_ADMIN",
        "tnt_0000000000000000000000000000001:TENANT_ADMIN",
        "tnt_000000000000000000000000000000001:TENANT_ADMIN",
        "tnt_0000000000000000000000000000000g:TENANT_ADMIN",
        f"{TENANT_KEY_ONE}:tenant_admin",
        f"{TENANT_KEY_ONE}:TenantAdmin",
        f"{TENANT_KEY_ONE}:SECURITY-ANALYST",
        f"{TENANT_KEY_ONE}:TENANT ADMIN",
        f" {TENANT_KEY_ONE}:TENANT_ADMIN",
        f"{TENANT_KEY_ONE}:TENANT_ADMIN ",
        " platform:PLATFORM_ADMIN",
        "platform:PLATFORM_ADMIN ",
        "platform :PLATFORM_ADMIN",
        "platform: PLATFORM_ADMIN",
        "platform:TENANT_ADMIN",
        "platform:SECURITY_ANALYST",
        "platform:VIEWER",
        f"{TENANT_KEY_ONE}:PLATFORM_ADMIN",
        "PLATFORM:PLATFORM_ADMIN",
        "Platform:PLATFORM_ADMIN",
        "platform:platform_admin",
        "",
    ],
)
def test_malformed_or_scope_invalid_grants_are_rejected(value: str) -> None:
    with pytest.raises(IdentityGrantParseError):
        parse_identity_grant(value)


@pytest.mark.parametrize("value", [None, 123, [], {}])
def test_non_string_grants_are_rejected_cleanly(value: object) -> None:
    with pytest.raises(IdentityGrantParseError, match="must be a string"):
        parse_identity_grant(value)


def test_parser_rejects_instead_of_normalizing_input() -> None:
    value = " platform:PLATFORM_ADMIN "

    with pytest.raises(IdentityGrantParseError, match="surrounding whitespace"):
        parse_identity_grant(value)
    assert value == " platform:PLATFORM_ADMIN "


def test_parsed_grant_is_immutable() -> None:
    grant = parse_identity_grant(f"{TENANT_KEY_ONE}:VIEWER")

    with pytest.raises(FrozenInstanceError):
        grant.role = "TENANT_ADMIN"
