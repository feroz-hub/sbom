"""Acceptance architecture regressions; real DB, ephemeral keys, no staging claims."""

from datetime import UTC, datetime

import pytest
from app.db import SessionLocal
from app.models import AuthorizationAuditLog, NativeUserCredential, UserIdentity
from app.services import native_auth_service as auth
from app.services import native_jwt_service as jwt
from app.services import native_password_service as passwords
from app.settings import get_settings
from sqlalchemy import func, select

from tests.test_native_iam_phase2 import PASSWORD, enrolled
from tests.test_native_iam_phase2 import native_config as native_config


def test_password_change_proof_has_no_login_side_effects(monkeypatch):
    with SessionLocal() as db:
        user = enrolled(db)
        auth.login(db, user.email, PASSWORD)
        db.commit()
        identity = db.scalar(
            select(UserIdentity).where(UserIdentity.user_id == user.id, UserIdentity.provider_type == "NATIVE")
        )
        credential = db.scalar(select(NativeUserCredential).where(NativeUserCredential.user_id == user.id))
        before = user.last_login_at, identity.last_authenticated_at
        count = db.scalar(
            select(func.count())
            .select_from(AuthorizationAuditLog)
            .where(AuthorizationAuditLog.action == "LOGIN_SUCCESS")
        )
        monkeypatch.setattr(jwt, "issue_token", lambda *a: pytest.fail("Password proof issued a JWT"))
        assert passwords.change_password(
            db, user.id, credential.security_version, PASSWORD, "a replacement native passphrase"
        )
        db.commit()
        assert (user.last_login_at, identity.last_authenticated_at) == before
        assert (
            db.scalar(
                select(func.count())
                .select_from(AuthorizationAuditLog)
                .where(AuthorizationAuditLog.action == "LOGIN_SUCCESS")
            )
            == count
        )


def test_forced_proof_has_no_login_activity(monkeypatch):
    with SessionLocal() as db:
        user = enrolled(db)
        user.status = "FORCE_PASSWORD_CHANGE"
        db.commit()
        monkeypatch.setattr(jwt, "issue_token", lambda *a: pytest.fail("Forced proof issued a JWT"))
        assert passwords.forced_proof(db, user.email, PASSWORD)
        assert user.last_login_at is None
        assert user.status == "FORCE_PASSWORD_CHANGE"


def test_public_only_validator_needs_no_private_key(monkeypatch):
    with SessionLocal() as db:
        user = enrolled(db)
        token = auth.login(db, user.email, PASSWORD)
        db.commit()
        uid = user.id
    monkeypatch.setattr(get_settings(), "native_jwt_private_key", "")
    assert jwt.validate_token(token)["sub"] == str(uid)
    with pytest.raises(RuntimeError, match="signing key"):
        jwt.active_signing_key()


def test_validation_does_not_fallback_to_private_key(monkeypatch):
    with SessionLocal() as db:
        user = enrolled(db)
        token = auth.login(db, user.email, PASSWORD)
        db.commit()
    monkeypatch.setattr(get_settings(), "native_jwt_public_key", "")
    with pytest.raises(RuntimeError, match="public verification key"):
        jwt.validate_token(token)


def test_password_proof_retains_global_lockout(monkeypatch):
    monkeypatch.setattr(get_settings(), "native_login_max_failed_attempts", 2)
    with SessionLocal() as db:
        user = enrolled(db)
        credential = db.scalar(select(NativeUserCredential).where(NativeUserCredential.user_id == user.id))
        version = credential.security_version
        for _ in range(2):
            assert not passwords.change_password(db, user.id, version, "wrong", "new long native password")
            db.commit()
        assert user.status == "LOCKED" and credential.security_version > version
        assert credential.locked_until > datetime.now(UTC)
        assert user.last_login_at is None


def test_inventory_preserves_tenant_roles_without_email_or_credentials():
    from scripts.iam_migration_inventory import inventory

    with SessionLocal() as db:
        user = enrolled(db)
        result = inventory(db)
        row = next(r for r in result["users"] if r["user_id"] == user.id)
        assert row["category"] == "NATIVE_ONLY"
        assert row["memberships"][0]["roles"] == ["DEVELOPER", "SECURITY_ANALYST"]
        assert user.email not in str(result) and "password_hash" not in str(result)


def test_active_public_key_pair_mismatch_fails_production(monkeypatch):
    from app.services.native_operations import validate_configuration
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr(get_settings(), "native_iam_production", True)
    monkeypatch.setattr(
        get_settings(),
        "native_jwt_public_key",
        other.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode(),
    )
    with pytest.raises(RuntimeError, match="signing_or_outbox_key"):
        validate_configuration()
