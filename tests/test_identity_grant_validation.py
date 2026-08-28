from __future__ import annotations

from datetime import UTC, datetime
from typing import cast
from uuid import uuid4

import pytest
from app.core.identity_grants import (
    IdentityGrantScope,
    ParsedIdentityGrant,
    parse_identity_grant,
)
from app.db import SessionLocal
from app.models import AuthorizationRole, Tenant
from app.services.identity_grant_service import (
    IdentityGrantValidationError,
    IdentityGrantValidationReason,
    ValidatedIdentityGrant,
    validate_identity_grant,
)
from sqlalchemy import select


def _tenant(db, *, status: str = "ACTIVE") -> Tenant:
    suffix = uuid4().hex
    now = datetime.now(UTC)
    tenant = Tenant(
        tenant_key=f"tnt_{suffix}",
        name=f"Unrelated tenant name {suffix}",
        slug=f"unrelated-slug-{suffix}",
        external_iam_tenant_id=f"unrelated-external-{suffix}",
        status=status,
        created_at=now,
        updated_at=now,
    )
    db.add(tenant)
    db.flush()
    return tenant


def _role(db, code: str) -> AuthorizationRole:
    role = db.scalar(
        select(AuthorizationRole).where(AuthorizationRole.code == code)
    )
    assert role is not None
    return role


def _assert_reason(
    expected: IdentityGrantValidationReason,
    function,
) -> None:
    with pytest.raises(IdentityGrantValidationError) as error:
        function()
    assert error.value.reason is expected


def test_active_tenant_and_active_tenant_role_validate_by_tenant_key() -> None:
    with SessionLocal() as db:
        tenant = _tenant(db)
        parsed = parse_identity_grant(f"{tenant.tenant_key}:TENANT_ADMIN")

        validated = validate_identity_grant(db, parsed)

        assert validated == ValidatedIdentityGrant(
            scope=IdentityGrantScope.TENANT,
            role="TENANT_ADMIN",
            tenant_key=tenant.tenant_key,
            tenant_id=tenant.id,
        )
        assert tenant.name != tenant.tenant_key
        assert tenant.slug != tenant.tenant_key
        assert tenant.external_iam_tenant_id != tenant.tenant_key
        db.rollback()


def test_tenant_name_slug_and_external_id_changes_do_not_affect_resolution() -> None:
    with SessionLocal() as db:
        tenant = _tenant(db)
        parsed = parse_identity_grant(f"{tenant.tenant_key}:SECURITY_ANALYST")
        original_id = tenant.id
        tenant.name = "Renamed tenant"
        tenant.slug = f"renamed-{uuid4().hex}"
        tenant.external_iam_tenant_id = f"renamed-external-{uuid4().hex}"
        db.flush()

        validated = validate_identity_grant(db, parsed)

        assert validated.tenant_id == original_id
        assert validated.tenant_key == tenant.tenant_key
        db.rollback()


def test_unknown_tenant_key_is_rejected() -> None:
    parsed = parse_identity_grant(
        "tnt_ffffffffffffffffffffffffffffffff:TENANT_ADMIN"
    )
    with SessionLocal() as db:
        _assert_reason(
            IdentityGrantValidationReason.TENANT_NOT_FOUND,
            lambda: validate_identity_grant(db, parsed),
        )


@pytest.mark.parametrize("status", ["PENDING", "DISABLED"])
def test_non_active_tenant_is_rejected(status: str) -> None:
    with SessionLocal() as db:
        tenant = _tenant(db, status=status)
        parsed = parse_identity_grant(f"{tenant.tenant_key}:TENANT_ADMIN")

        _assert_reason(
            IdentityGrantValidationReason.TENANT_INACTIVE,
            lambda: validate_identity_grant(db, parsed),
        )
        db.rollback()


def test_syntactically_valid_unknown_role_fails_catalogue_validation() -> None:
    with SessionLocal() as db:
        tenant = _tenant(db)
        parsed = parse_identity_grant(f"{tenant.tenant_key}:NON_EXISTENT_ROLE")
        assert parsed.role == "NON_EXISTENT_ROLE"

        _assert_reason(
            IdentityGrantValidationReason.ROLE_NOT_FOUND,
            lambda: validate_identity_grant(db, parsed),
        )
        db.rollback()


@pytest.mark.parametrize("status", ["DISABLED", "DRAFT"])
def test_non_active_tenant_role_is_rejected(status: str) -> None:
    with SessionLocal() as db:
        tenant = _tenant(db)
        role = _role(db, "VIEWER")
        role.status = status
        db.flush()
        parsed = parse_identity_grant(f"{tenant.tenant_key}:VIEWER")

        _assert_reason(
            IdentityGrantValidationReason.ROLE_INACTIVE,
            lambda: validate_identity_grant(db, parsed),
        )
        db.rollback()


def test_tenant_grant_with_platform_scoped_role_is_rejected() -> None:
    with SessionLocal() as db:
        tenant = _tenant(db)
        parsed = ParsedIdentityGrant(
            scope=IdentityGrantScope.TENANT,
            role="PLATFORM_ADMIN",
            tenant_key=tenant.tenant_key,
        )

        _assert_reason(
            IdentityGrantValidationReason.ROLE_SCOPE_MISMATCH,
            lambda: validate_identity_grant(db, parsed),
        )
        db.rollback()


def test_active_platform_admin_catalogue_grant_validates_without_tenant() -> None:
    parsed = parse_identity_grant("platform:PLATFORM_ADMIN")
    with SessionLocal() as db:
        validated = validate_identity_grant(db, parsed)

    assert validated == ValidatedIdentityGrant(
        scope=IdentityGrantScope.PLATFORM,
        role="PLATFORM_ADMIN",
        tenant_key=None,
        tenant_id=None,
    )


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("missing", IdentityGrantValidationReason.ROLE_NOT_FOUND),
        ("inactive", IdentityGrantValidationReason.ROLE_INACTIVE),
        ("wrong_scope", IdentityGrantValidationReason.ROLE_SCOPE_MISMATCH),
    ],
)
def test_invalid_platform_admin_catalogue_state_is_rejected(
    mutation: str,
    expected: IdentityGrantValidationReason,
) -> None:
    parsed = parse_identity_grant("platform:PLATFORM_ADMIN")
    with SessionLocal() as db:
        role = _role(db, "PLATFORM_ADMIN")
        if mutation == "missing":
            role.code = "PLATFORM_ADMIN_TEMP"
        elif mutation == "inactive":
            role.status = "DISABLED"
        else:
            role.scope = "TENANT"
        db.flush()

        _assert_reason(expected, lambda: validate_identity_grant(db, parsed))
        db.rollback()


def test_validator_rejects_raw_grant_instead_of_reparsing_it() -> None:
    with SessionLocal() as db:
        _assert_reason(
            IdentityGrantValidationReason.INVALID_GRANT_TYPE,
            lambda: validate_identity_grant(db, "platform:PLATFORM_ADMIN"),
        )


def test_tenant_scope_requires_tenant_key() -> None:
    grant = ParsedIdentityGrant(
        scope=IdentityGrantScope.TENANT,
        role="TENANT_ADMIN",
        tenant_key=None,
    )

    with SessionLocal() as db:
        _assert_reason(
            IdentityGrantValidationReason.TENANT_KEY_REQUIRED,
            lambda: validate_identity_grant(db, grant),
        )


def test_platform_scope_forbids_tenant_key() -> None:
    grant = ParsedIdentityGrant(
        scope=IdentityGrantScope.PLATFORM,
        role="PLATFORM_ADMIN",
        tenant_key="tnt_00000000000000000000000000000001",
    )

    with SessionLocal() as db:
        _assert_reason(
            IdentityGrantValidationReason.PLATFORM_TENANT_KEY_FORBIDDEN,
            lambda: validate_identity_grant(db, grant),
        )


def test_unknown_scope_is_rejected() -> None:
    grant = ParsedIdentityGrant(
        scope=cast(IdentityGrantScope, "UNKNOWN"),
        role="TENANT_ADMIN",
        tenant_key=None,
    )

    with SessionLocal() as db:
        _assert_reason(
            IdentityGrantValidationReason.INVALID_SCOPE,
            lambda: validate_identity_grant(db, grant),
        )
