from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from app.auth import AuthConfigError, validate_auth_setup
from app.core.identity_grants import IdentityGrantScope
from app.core.security import _resolve_context
from app.models import (
    AuthorizationAuditLog,
    AuthorizationRole,
    IAMUser,
    PlatformUserRole,
    Tenant,
    TenantUser,
)
from app.services.auth_context_service import resolve_authorization_state
from app.services.identity_grant_compare_service import (
    AuthorityGrant,
    IAMShadowAuthority,
    IdentityGrantAuthorityModeError,
    compare_identity_grant_authority,
    iam_shadow_authority,
    observe_identity_grant_authority,
)
from app.services.tenant_role_assignment_service import create_initial_assignments
from app.settings import reset_settings
from sqlalchemy import select


def _user(db) -> IAMUser:
    suffix = uuid4().hex
    now = datetime.now(UTC)
    user = IAMUser(
        external_iam_user_id=f"compare-{suffix}",
        external_issuer="https://hcl-cs.example.test",
        external_subject=f"compare-{suffix}",
        email=f"compare-{suffix}@example.test",
        display_name="Compare User",
        user_principal_name=f"compare-{suffix}@example.test",
        employee_id=f"employee-{suffix}",
        department="Security",
        status="ACTIVE",
        email_verified=True,
        email_verified_at=now,
        verification_required=False,
        created_at=now,
        updated_at=now,
    )
    db.add(user)
    db.flush()
    return user


def _tenant(db, label: str, *, status: str = "ACTIVE") -> Tenant:
    suffix = uuid4().hex
    now = datetime.now(UTC)
    tenant = Tenant(
        name=f"{label} {suffix}",
        slug=f"{label.lower()}-{suffix}",
        external_iam_tenant_id=f"external-{suffix}",
        status=status,
        created_at=now,
        updated_at=now,
    )
    db.add(tenant)
    db.flush()
    return tenant


def _membership(db, user: IAMUser, tenant: Tenant, *roles: str) -> TenantUser:
    now = datetime.now(UTC)
    membership = TenantUser(
        tenant_id=tenant.id,
        user_id=user.id,
        role=roles[0],
        status="ACTIVE",
        created_at=now,
        updated_at=now,
    )
    db.add(membership)
    db.flush()
    create_initial_assignments(
        db,
        membership,
        role_codes=roles,
        primary_role_code=roles[0],
        actor_user_id=user.id,
        source="SYSTEM",
    )
    return membership


def _claims(user: IAMUser, grant_claim: object = None, *, include_claim: bool = True) -> dict:
    claims = {
        "iss": user.external_issuer,
        "sub": user.external_subject,
        "email": user.email,
        "name": user.display_name,
        "preferred_username": user.user_principal_name,
        "employee_id": user.employee_id,
        "department": user.department,
        "role": ["SECURITY_ANALYST"],
        "tenant_id": "diagnostic-only",
    }
    if include_claim:
        claims["sbom_grant"] = grant_claim
    return claims


def _grant(scope: IdentityGrantScope, tenant_id: int | None, role: str) -> AuthorityGrant:
    return AuthorityGrant(scope=scope, tenant_id=tenant_id, role=role)


def test_pure_comparison_is_order_independent_and_reports_set_differences() -> None:
    tenant_admin = _grant(IdentityGrantScope.TENANT, 10, "TENANT_ADMIN")
    viewer = _grant(IdentityGrantScope.TENANT, 20, "VIEWER")
    analyst = _grant(IdentityGrantScope.TENANT, 10, "SECURITY_ANALYST")

    exact = compare_identity_grant_authority(
        frozenset((tenant_admin, viewer)),
        IAMShadowAuthority(frozenset((viewer, tenant_admin))),
    )
    assert exact.is_match
    assert exact.matched == frozenset((tenant_admin, viewer))
    assert not exact.local_only
    assert not exact.iam_only

    different = compare_identity_grant_authority(
        frozenset((tenant_admin, viewer)),
        IAMShadowAuthority(frozenset((analyst, viewer))),
    )
    assert not different.is_match
    assert different.matched == frozenset((viewer,))
    assert different.local_only == frozenset((tenant_admin,))
    assert different.iam_only == frozenset((analyst,))


def test_claim_shapes_missing_empty_single_and_duplicate_are_deterministic() -> None:
    from app.db import SessionLocal

    with SessionLocal() as db:
        tenant = _tenant(db, "ClaimShape")
        raw = f"{tenant.tenant_key}:VIEWER"

        missing = iam_shadow_authority(db, {}, claim_path="sbom_grant")
        empty = iam_shadow_authority(db, {"sbom_grant": []}, claim_path="sbom_grant")
        single = iam_shadow_authority(db, {"sbom_grant": raw}, claim_path="sbom_grant")
        duplicate = iam_shadow_authority(
            db,
            {"custom": {"grants": [raw, raw]}},
            claim_path="custom.grants",
        )
        malformed = iam_shadow_authority(
            db,
            {"sbom_grant": {"grant": raw}},
            claim_path="sbom_grant",
        )

        assert missing.grants == empty.grants == frozenset()
        assert single.grants == duplicate.grants == frozenset(
            {_grant(IdentityGrantScope.TENANT, tenant.id, "VIEWER")}
        )
        assert not duplicate.invalid_reason_counts
        assert malformed.grants == frozenset()
        assert malformed.invalid_reason_counts == (("CLAIM_SHAPE_INVALID", 1),)
        db.rollback()


def test_compare_exact_match_ignores_order_and_duplicate_iam_values(monkeypatch) -> None:
    from app.db import SessionLocal

    monkeypatch.setenv("IDENTITY_GRANT_AUTHORITY_MODE", "COMPARE")
    reset_settings()
    with SessionLocal() as db:
        user = _user(db)
        first = _tenant(db, "First")
        second = _tenant(db, "Second")
        _membership(db, user, first, "TENANT_ADMIN")
        _membership(db, user, second, "VIEWER")
        state = resolve_authorization_state(db, user, selected_tenant=first.slug)
        claims = _claims(
            user,
            [
                f"{second.tenant_key}:VIEWER",
                f"{first.tenant_key}:TENANT_ADMIN",
                f"{second.tenant_key}:VIEWER",
            ],
        )

        comparison = observe_identity_grant_authority(db, state, claims)

        assert comparison is not None and comparison.is_match
        assert len(comparison.matched) == 2
        assert not comparison.local_only
        assert not comparison.iam_only
        db.rollback()


def test_role_difference_is_one_local_only_and_one_iam_only(monkeypatch) -> None:
    from app.db import SessionLocal

    monkeypatch.setenv("IDENTITY_GRANT_AUTHORITY_MODE", "COMPARE")
    reset_settings()
    with SessionLocal() as db:
        user = _user(db)
        tenant = _tenant(db, "RoleDifference")
        _membership(db, user, tenant, "TENANT_ADMIN")
        state = resolve_authorization_state(db, user)

        comparison = observe_identity_grant_authority(
            db,
            state,
            _claims(user, [f"{tenant.tenant_key}:VIEWER"]),
        )

        assert comparison is not None and not comparison.is_match
        assert comparison.local_only == frozenset(
            {_grant(IdentityGrantScope.TENANT, tenant.id, "TENANT_ADMIN")}
        )
        assert comparison.iam_only == frozenset(
            {_grant(IdentityGrantScope.TENANT, tenant.id, "VIEWER")}
        )
        db.rollback()


def test_invalid_shadow_grants_have_zero_authority_and_safe_reason_counts(monkeypatch) -> None:
    from app.db import SessionLocal

    monkeypatch.setenv("IDENTITY_GRANT_AUTHORITY_MODE", "COMPARE")
    reset_settings()
    with SessionLocal() as db:
        user = _user(db)
        local_tenant = _tenant(db, "Local")
        inactive_tenant = _tenant(db, "Inactive", status="DISABLED")
        _membership(db, user, local_tenant, "TENANT_ADMIN")
        viewer = db.scalar(
            select(AuthorizationRole).where(AuthorizationRole.code == "VIEWER")
        )
        assert viewer is not None
        viewer.scope = "PLATFORM"
        db.flush()
        state = resolve_authorization_state(db, user)

        comparison = observe_identity_grant_authority(
            db,
            state,
            _claims(
                user,
                [
                    "not-a-grant",
                    "tnt_ffffffffffffffffffffffffffffffff:SECURITY_ANALYST",
                    f"{inactive_tenant.tenant_key}:SECURITY_ANALYST",
                    f"{local_tenant.tenant_key}:NON_EXISTENT_ROLE",
                    f"{local_tenant.tenant_key}:VIEWER",
                ],
            ),
        )

        assert comparison is not None
        assert comparison.iam_only == frozenset()
        assert comparison.local_only == frozenset(
            {_grant(IdentityGrantScope.TENANT, local_tenant.id, "TENANT_ADMIN")}
        )
        assert dict(comparison.invalid_iam_reason_counts) == {
            "PARSE_ERROR": 1,
            "ROLE_NOT_FOUND": 1,
            "ROLE_SCOPE_MISMATCH": 1,
            "TENANT_INACTIVE": 1,
            "TENANT_NOT_FOUND": 1,
        }
        malformed_shape = observe_identity_grant_authority(
            db,
            state,
            _claims(
                user,
                {"unexpected": f"{local_tenant.tenant_key}:TENANT_ADMIN"},
            ),
        )
        assert malformed_shape is not None
        assert malformed_shape.local_only == comparison.local_only
        assert malformed_shape.iam_only == frozenset()
        assert malformed_shape.invalid_iam_reason_counts == (
            ("CLAIM_SHAPE_INVALID", 1),
        )
        assert state.active_tenant is local_tenant
        db.rollback()


def test_platform_compare_exact_local_only_and_iam_only_are_observational(monkeypatch) -> None:
    from app.db import SessionLocal

    monkeypatch.setenv("IDENTITY_GRANT_AUTHORITY_MODE", "COMPARE")
    reset_settings()
    with SessionLocal() as db:
        local_admin = _user(db)
        now = datetime.now(UTC)
        db.add(
            PlatformUserRole(
                user_id=local_admin.id,
                role="PLATFORM_ADMIN",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
            )
        )
        db.flush()
        local_admin_state = resolve_authorization_state(db, local_admin)

        exact = observe_identity_grant_authority(
            db,
            local_admin_state,
            _claims(local_admin, ["platform:PLATFORM_ADMIN"]),
        )
        local_only = observe_identity_grant_authority(
            db,
            local_admin_state,
            _claims(local_admin, include_claim=False),
        )

        local_user = _user(db)
        local_user_state = resolve_authorization_state(db, local_user)
        iam_only = observe_identity_grant_authority(
            db,
            local_user_state,
            _claims(local_user, ["platform:PLATFORM_ADMIN"]),
        )

        platform = _grant(IdentityGrantScope.PLATFORM, None, "PLATFORM_ADMIN")
        assert exact is not None and exact.is_match
        assert exact.matched == frozenset({platform})
        assert local_only is not None
        assert local_only.local_only == frozenset({platform})
        assert iam_only is not None
        assert iam_only.iam_only == frozenset({platform})
        assert local_user_state.is_platform_admin is False
        db.rollback()


def test_local_mode_does_not_read_or_apply_iam_grants(monkeypatch) -> None:
    from app.db import SessionLocal

    monkeypatch.setenv("IDENTITY_GRANT_AUTHORITY_MODE", "LOCAL")
    reset_settings()
    with SessionLocal() as db:
        user = _user(db)
        local_tenant = _tenant(db, "LocalAuthority")
        other_tenant = _tenant(db, "OtherAuthority")
        _membership(db, user, local_tenant, "VIEWER")
        db.commit()

        context = _resolve_context(
            db,
            _claims(
                user,
                [
                    f"{other_tenant.tenant_key}:TENANT_ADMIN",
                    "platform:PLATFORM_ADMIN",
                ],
            ),
            local_tenant.slug,
        )

        assert context.tenant_id == local_tenant.id
        assert context.roles == frozenset({"VIEWER"})
        assert context.is_platform_admin is False
        assert db.scalar(
            select(AuthorizationAuditLog).where(
                AuthorizationAuditLog.action == "IAM_IDENTITY_AUTHORITY_COMPARE"
            )
        ) is None
        db.rollback()


def test_compare_cross_tenant_iam_grant_cannot_change_local_context(monkeypatch) -> None:
    from app.db import SessionLocal

    monkeypatch.setenv("IDENTITY_GRANT_AUTHORITY_MODE", "COMPARE")
    reset_settings()
    with SessionLocal() as db:
        user = _user(db)
        local_tenant = _tenant(db, "LocalCrossTenant")
        iam_tenant = _tenant(db, "IamCrossTenant")
        _membership(db, user, local_tenant, "TENANT_ADMIN")
        db.commit()

        context = _resolve_context(
            db,
            _claims(user, [f"{iam_tenant.tenant_key}:VIEWER"]),
            local_tenant.slug,
        )

        assert context.tenant_id == local_tenant.id
        assert context.roles == frozenset({"TENANT_ADMIN"})
        assert context.is_platform_admin is False
        audit = db.scalar(
            select(AuthorizationAuditLog)
            .where(
                AuthorizationAuditLog.action == "IAM_IDENTITY_AUTHORITY_COMPARE",
                AuthorizationAuditLog.target_user_id == user.id,
            )
            .order_by(AuthorizationAuditLog.id.desc())
        )
        assert audit is not None
        assert audit.outcome == "FAILED"
        assert audit.new_value["local_only"] == [
            {
                "scope": "TENANT",
                "tenant_id": local_tenant.id,
                "role": "TENANT_ADMIN",
            }
        ]
        assert audit.new_value["iam_only"] == [
            {
                "scope": "TENANT",
                "tenant_id": iam_tenant.id,
                "role": "VIEWER",
            }
        ]
        assert "sbom_grant" not in audit.new_value
        db.rollback()


def test_iam_mode_is_rejected_at_startup_and_runtime(monkeypatch) -> None:
    from app.db import SessionLocal

    monkeypatch.setenv("IDENTITY_GRANT_AUTHORITY_MODE", "IAM")
    reset_settings()
    with pytest.raises(AuthConfigError, match="not enabled"):
        validate_auth_setup()

    with SessionLocal() as db:
        user = _user(db)
        tenant = _tenant(db, "IamGuard")
        _membership(db, user, tenant, "VIEWER")
        state = resolve_authorization_state(db, user)
        with pytest.raises(IdentityGrantAuthorityModeError, match="not enabled"):
            observe_identity_grant_authority(
                db,
                state,
                _claims(user, [f"{tenant.tenant_key}:TENANT_ADMIN"]),
            )
        assert state.active_tenant is tenant
        db.rollback()
