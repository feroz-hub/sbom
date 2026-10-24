from __future__ import annotations

from argparse import Namespace

import pytest
from app.db import SessionLocal
from app.models import AuthorizationAuditLog, PlatformUserRole, TenantUser
from fastapi import HTTPException
from scripts.bootstrap_platform_admin import (
    CONFIRMATION,
    build_parser,
    execute_bootstrap,
)
from sqlalchemy import func, select

from tests.phase6_helpers import seed_platform_grant, seed_user


def _args(**overrides) -> Namespace:
    values = {
        "user_id": None,
        "issuer": None,
        "subject": None,
        "employee_id": None,
        "email": None,
        "change_reference": "CHANGE-600",
        "confirm": CONFIRMATION,
    }
    values.update(overrides)
    return Namespace(**values)


@pytest.fixture(autouse=True)
def _authenticated_bootstrap_environment(monkeypatch):
    from app.settings import reset_settings

    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("DEV_DEFAULT_TENANT", "false")
    reset_settings()
    yield
    reset_settings()


def test_exact_composite_identity_bootstrap_is_audited_and_has_no_membership():
    with SessionLocal() as db:
        user = seed_user(db)
        issuer = user.external_issuer
        subject = user.external_subject
        user_id = user.id
        db.commit()

    with SessionLocal() as db:
        action, selected_id = execute_bootstrap(
            db,
            _args(issuer=issuer, subject=subject),
        )
        assert action == "CREATED"
        assert selected_id == user_id

    with SessionLocal() as db:
        grant = db.scalar(
            select(PlatformUserRole).where(
                PlatformUserRole.user_id == user_id
            )
        )
        assert grant.status == "ACTIVE"
        assert db.scalar(
            select(func.count(TenantUser.id)).where(
                TenantUser.user_id == user_id
            )
        ) == 0
        audit = db.scalar(
            select(AuthorizationAuditLog).where(
                AuthorizationAuditLog.action == "PLATFORM_ADMIN_BOOTSTRAPPED"
            )
        )
        assert audit.target_user_id == user_id
        assert audit.tenant_id is None
        assert audit.correlation_id == "CHANGE-600"
        assert "subject" not in str(audit.new_value).lower()


def test_user_id_bootstrap_is_idempotent():
    with SessionLocal() as db:
        user = seed_user(db)
        user_id = user.id
        db.commit()

    with SessionLocal() as db:
        assert execute_bootstrap(db, _args(user_id=user_id))[0] == "CREATED"
    with SessionLocal() as db:
        assert execute_bootstrap(db, _args(user_id=user_id))[0] == "EXISTING"
        assert db.scalar(
            select(func.count(PlatformUserRole.id)).where(
                PlatformUserRole.user_id == user_id
            )
        ) == 1


def test_inactive_grant_can_be_bootstrap_reactivated_when_no_effective_admin():
    with SessionLocal() as db:
        user = seed_user(db)
        grant = seed_platform_grant(db, user, status="DISABLED")
        user_id = user.id
        grant_id = grant.id
        db.commit()

    with SessionLocal() as db:
        action, _ = execute_bootstrap(db, _args(user_id=user_id))
        assert action == "REACTIVATED"
        assert db.get(PlatformUserRole, grant_id).status == "ACTIVE"


def test_unknown_and_ambiguous_bootstrap_selectors_are_rejected_and_audited():
    with SessionLocal() as db:
        first = seed_user(db, email="ambiguous@example.test")
        second = seed_user(db, email="ambiguous@example.test")
        db.commit()

    with SessionLocal() as db:
        with pytest.raises(HTTPException) as unknown:
            execute_bootstrap(db, _args(user_id=999999))
        assert unknown.value.detail["code"] == "IAM_USER_NOT_FOUND"

    with SessionLocal() as db:
        with pytest.raises(HTTPException) as ambiguous:
            execute_bootstrap(
                db, _args(email="ambiguous@example.test")
            )
        assert (
            ambiguous.value.detail["code"]
            == "IAM_PLATFORM_ADMIN_BOOTSTRAP_CONFLICT"
        )
        assert db.scalar(
            select(func.count(PlatformUserRole.id))
        ) == 0
        assert db.scalar(
            select(func.count(AuthorizationAuditLog.id)).where(
                AuthorizationAuditLog.action
                == "PLATFORM_ADMIN_BOOTSTRAP_REJECTED"
            )
        ) == 2


@pytest.mark.parametrize(
    ("status", "verified", "code"),
    [
        ("DISABLED", True, "IAM_ACCOUNT_DISABLED"),
        ("PENDING", True, "IAM_ACCOUNT_PENDING_APPROVAL"),
        ("ACTIVE", False, "IAM_EMAIL_VERIFICATION_REQUIRED"),
    ],
)
def test_ineligible_bootstrap_target_is_rejected(status, verified, code):
    with SessionLocal() as db:
        user = seed_user(db, status=status, verified=verified)
        user_id = user.id
        db.commit()

    with SessionLocal() as db:
        with pytest.raises(HTTPException) as exc_info:
            execute_bootstrap(db, _args(user_id=user_id))
        assert exc_info.value.detail["code"] == code
        assert db.scalar(select(PlatformUserRole)) is None


def test_bootstrap_rejects_new_target_when_effective_admin_exists():
    with SessionLocal() as db:
        existing = seed_user(db)
        seed_platform_grant(db, existing)
        target = seed_user(db)
        target_id = target.id
        db.commit()

    with SessionLocal() as db:
        with pytest.raises(HTTPException) as exc_info:
            execute_bootstrap(db, _args(user_id=target_id))
        assert (
            exc_info.value.detail["code"]
            == "IAM_PLATFORM_ADMIN_BOOTSTRAP_CONFLICT"
        )


def test_bootstrap_requires_explicit_confirmation_and_selector():
    parser = build_parser()
    assert parser is not None
    with SessionLocal() as db:
        user = seed_user(db)
        user_id = user.id
        db.commit()

    with SessionLocal() as db:
        with pytest.raises(SystemExit):
            execute_bootstrap(
                db,
                _args(user_id=user_id, confirm="WRONG"),
            )
    with SessionLocal() as db:
        with pytest.raises(HTTPException) as exc_info:
            execute_bootstrap(db, _args())
        assert (
            exc_info.value.detail["code"]
            == "IAM_PLATFORM_ADMIN_BOOTSTRAP_REQUIRED"
        )


def test_first_user_and_startup_do_not_automatically_grant_platform_authority():
    with SessionLocal() as db:
        user = seed_user(db)
        user_id = user.id
        db.commit()
    with SessionLocal() as db:
        assert db.scalar(
            select(PlatformUserRole).where(
                PlatformUserRole.user_id == user_id
            )
        ) is None
