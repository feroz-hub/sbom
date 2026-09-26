"""Native Phase 2: PostgreSQL security and provider convergence regressions."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import jwt
import pytest
from app.core.context import CurrentContext
from app.core.security import _resolve_context, get_current_claims
from app.db import SessionLocal
from app.models import AccountActionToken, AuthorizationAuditLog, IAMUser, NativeUserCredential, Tenant, TenantUser
from app.routers.native_auth import NewUser
from app.services import audit_service, password_service
from app.services import native_auth_service as auth
from app.services import native_enrollment_service as enroll
from app.services import native_jwt_service as tokens
from app.services import tenant_role_assignment_service as roles
from app.services.account_action_token_service import InvalidAccountActionToken
from app.settings import get_settings
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from sqlalchemy import func, select

from tests.phase6_helpers import seed_platform_grant, seed_user

PASSWORD = "a long native test passphrase"


@pytest.fixture(autouse=True)
def native_config(monkeypatch):
    s = get_settings()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    for name, value in dict(
        native_auth_enabled=True,
        native_user_creation_enabled=True,
        auth_enabled=True,
        dev_default_tenant=False,
        native_jwt_issuer="https://native.test",
        native_jwt_public_key=key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode(),
        native_jwt_private_key=key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode(),
    ).items():
        monkeypatch.setattr(s, name, value)


def context(db, platform=True):
    actor = seed_user(db)
    db.commit()
    return CurrentContext(
        actor.id,
        actor.external_iam_user_id,
        actor.email,
        actor.display_name,
        1,
        "default",
        frozenset({"PLATFORM_ADMIN"} if platform else {"TENANT_ADMIN"}),
        frozenset({"platform:user:manage_status", "tenant:user:invite"}),
        platform,
    )


def payload(**kwargs):
    return NewUser(
        **(
            dict(
                first_name="John",
                last_name="Smith",
                phone="+919876543210",
                email="john@example.test",
                tenant_id=1,
                role_codes=["SECURITY_ANALYST", "DEVELOPER"],
            )
            | kwargs
        )
    )


def enrolled(db):
    user, issued = enroll.create_user(db, context(db), payload())
    db.commit()
    auth.activate(db, issued.raw_token, PASSWORD)
    db.commit()
    return user


def credential(db, user):
    return db.scalar(
        select(NativeUserCredential)
        .where(NativeUserCredential.user_id == user.id)
        .execution_options(populate_existing=True)
    )


@pytest.mark.parametrize(
    "platform,assigned,allowed",
    [
        (True, ["TENANT_ADMIN"], True),
        (False, ["SECURITY_ANALYST", "DEVELOPER", "VIEWER"], True),
        (False, ["TENANT_ADMIN"], False),
        (False, ["PLATFORM_ADMIN"], False),
    ],
)
def test_creation_delegation(platform, assigned, allowed):
    with SessionLocal() as db:
        actor = context(db, platform)
        if allowed:
            user, issued = enroll.create_user(db, actor, payload(role_codes=assigned))
            assert user.status == "PENDING_EMAIL_VERIFICATION"
            row = db.get(AccountActionToken, issued.id)
            assert (row.expires_at - row.created_at).total_seconds() == 18000
            member = db.scalar(select(TenantUser).where(TenantUser.user_id == user.id))
            assert roles.effective_role_codes(db, member) == frozenset(assigned)
        else:
            with pytest.raises(roles.AssignmentProblem):
                enroll.create_user(db, actor, payload(role_codes=assigned))
            assert db.scalar(select(func.count(IAMUser.id))) == 1


def test_cross_tenant_and_duplicate():
    with SessionLocal() as db:
        actor = context(db, False)
        with pytest.raises(HTTPException) as exc:
            enroll.create_user(db, actor, payload(tenant_id=2))
        assert exc.value.status_code == 403
        enroll.create_user(db, actor, payload())
        with pytest.raises(HTTPException) as exc:
            enroll.create_user(db, actor, payload(email=" JOHN@example.test "))
        assert exc.value.status_code == 409


def test_activation_single_use_and_audit():
    with SessionLocal() as db:
        user, issued = enroll.create_user(db, context(db), payload())
        auth.activate(db, issued.raw_token, PASSWORD)
        db.commit()
        assert user.status == "ACTIVE" and user.email_verified and not user.verification_required
        assert user.email_verified_at
        assert credential(db, user).password_hash.startswith("$argon2id$")
        assert {"PASSWORD_SET", "ACCOUNT_ACTIVATED"} <= set(db.scalars(select(AuthorizationAuditLog.action)))
        with pytest.raises(InvalidAccountActionToken):
            auth.activate(db, issued.raw_token, PASSWORD)


def test_same_token_tenant_isolation_and_live_roles():
    with SessionLocal() as db:
        user = enrolled(db)
        actor = context(db)
        now = datetime.now(UTC)
        db.add(Tenant(id=2, name="Second", slug="second", status="ACTIVE", created_at=now, updated_at=now))
        db.flush()
        enroll.add_membership(db, actor, 2, user.id, ["VIEWER"])
        db.commit()
        token = auth.login(db, user.email, PASSWORD)
        db.commit()
        claims = get_current_claims("Bearer " + token)
        first = _resolve_context(db, claims, "1")
        second = _resolve_context(db, claims, "2")
        assert first.roles == frozenset({"SECURITY_ANALYST", "DEVELOPER"})
        assert second.roles == frozenset({"VIEWER"})
        assert "analysis:run" in first.permissions and "analysis:run" not in second.permissions
        assert db.scalar(select(func.count(TenantUser.id)).where(TenantUser.user_id == user.id)) == 2
        with pytest.raises(HTTPException):
            _resolve_context(db, claims, "99999")
        roles.replace_roles(
            db,
            1,
            user.id,
            role_codes=["VIEWER"],
            primary_role_code="VIEWER",
            expected_version=1,
            reason=None,
            actor_user_id=actor.user_id,
            is_platform_admin=True,
        )
        db.commit()
        assert "analysis:run" not in _resolve_context(db, claims, "1").permissions
        roles.grant_role(
            db,
            1,
            user.id,
            role_code="SECURITY_ANALYST",
            expected_version=2,
            make_primary=False,
            reason=None,
            actor_user_id=actor.user_id,
            is_platform_admin=True,
        )
        db.commit()
        assert "analysis:run" in _resolve_context(db, claims, "1").permissions


def test_lockout_last_platform_admin_revocation_and_unlock():
    with SessionLocal() as db:
        user = enrolled(db)
        seed_platform_grant(db, user)
        db.commit()
        token = auth.login(db, user.email, PASSWORD)
        db.commit()
        initial = credential(db, user).security_version
        for attempt in range(1, 6):
            assert auth.login(db, user.email, "wrong") is None
            db.commit()
            assert credential(db, user).failed_login_count == attempt
        assert user.status == "LOCKED"
        cred = credential(db, user)
        assert cred.locked_at and cred.locked_until and cred.security_version == initial + 1
        assert auth.login(db, user.email, PASSWORD) is None
        with pytest.raises(HTTPException):
            tokens.resolve_user(db, tokens.validate_token(token))
        cred.locked_until = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
        assert auth.login(db, user.email, "wrong") is None
        assert user.status == "LOCKED"
        assert auth.login(db, user.email, PASSWORD)
        db.commit()
        assert user.status == "ACTIVE" and credential(db, user).failed_login_count == 0
        with pytest.raises(HTTPException):
            tokens.resolve_user(db, tokens.validate_token(token))
        assert {"USER_LOCKED", "USER_UNLOCKED"} <= set(db.scalars(select(AuthorizationAuditLog.action)))


def test_concurrent_failed_attempts():
    with SessionLocal() as db:
        user = enrolled(db)
        credential(db, user).failed_login_count = 3
        user_id, email = user.id, user.email
        db.commit()
    barrier = Barrier(2)

    def attempt(_):
        with SessionLocal() as db:
            barrier.wait(timeout=10)
            result = auth.login(db, email, "wrong")
            db.commit()
            return result

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(attempt, range(2))) == [None, None]
    with SessionLocal() as db:
        user = db.get(IAMUser, user_id)
        assert user.status == "LOCKED" and credential(db, user).failed_login_count == 5


@pytest.mark.parametrize(
    "claim,value",
    [
        ("iss", "https://wrong.test"),
        ("aud", "wrong"),
        ("exp", 1),
        ("sub", "abc"),
        ("sub", "01"),
        ("auth_provider", "HCL_CS"),
        ("security_version", True),
        ("jti", ""),
        ("iat", 9999999999),
    ],
)
def test_bad_jwt_claims(claim, value):
    with SessionLocal() as db:
        user = enrolled(db)
        token = auth.login(db, user.email, PASSWORD)
        claims = tokens.validate_token(token)
        claims[claim] = value
        bad = jwt.encode(claims, tokens.signing_key(), algorithm="RS256")
        with pytest.raises(HTTPException):
            tokens.validate_token(bad)


@pytest.mark.parametrize("missing", tokens.REQUIRED)
def test_required_claims(missing):
    with SessionLocal() as db:
        user = enrolled(db)
        claims = tokens.validate_token(auth.login(db, user.email, PASSWORD))
        del claims[missing]
        with pytest.raises(HTTPException):
            tokens.validate_token(jwt.encode(claims, tokens.signing_key(), algorithm="RS256"))


def test_signature_algorithm_and_disabled():
    with SessionLocal() as db:
        user = enrolled(db)
        token = auth.login(db, user.email, PASSWORD)
        claims = tokens.validate_token(token)
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        for bad in [
            jwt.encode(claims, other, algorithm="RS256"),
            jwt.encode(claims, "x" * 32, algorithm="HS256"),
            jwt.encode(claims, "", algorithm="none"),
        ]:
            with pytest.raises(HTTPException):
                tokens.validate_token(bad)
        user.status = "DISABLED"
        db.commit()
        with pytest.raises(HTTPException):
            tokens.resolve_user(db, claims)
        assert auth.login(db, user.email, PASSWORD) is None
        assert auth.login(db, "unknown@example.test", PASSWORD) is None


def test_audit_failure_rolls_back_activation(monkeypatch):
    with SessionLocal() as db:
        user, issued = enroll.create_user(db, context(db), payload())
        db.commit()

        def fail(*args, **kwargs):
            if kwargs.get("action") == "PASSWORD_SET":
                raise RuntimeError("unavailable")

        monkeypatch.setattr(audit_service, "write_authorization_audit", fail)
        with pytest.raises(RuntimeError):
            auth.activate(db, issued.raw_token, PASSWORD)
        db.commit()
        assert db.get(IAMUser, user.id).status == "PENDING_EMAIL_VERIFICATION"
        assert credential(db, user) is None
        assert db.get(AccountActionToken, issued.id).consumed_at is None


def test_concurrent_enrollment_one_identity():
    with SessionLocal() as db:
        actor = context(db)
    barrier = Barrier(2)

    def create(_):
        with SessionLocal() as db:
            barrier.wait(timeout=10)
            try:
                enroll.create_user(db, actor, payload())
                db.commit()
                return "CREATED"
            except HTTPException as exc:
                db.rollback()
                assert exc.status_code == 409
                return "DUPLICATE"

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(create, range(2))) == ["CREATED", "DUPLICATE"]
    with SessionLocal() as db:
        assert db.scalar(select(func.count(IAMUser.id)).where(IAMUser.email == "john@example.test")) == 1
        assert db.scalar(select(func.count(TenantUser.id))) == 1


def test_concurrent_activation_one_winner():
    with SessionLocal() as db:
        user, issued = enroll.create_user(db, context(db), payload())
        db.commit()
    barrier = Barrier(2)

    def activate(_):
        with SessionLocal() as db:
            barrier.wait(timeout=10)
            try:
                auth.activate(db, issued.raw_token, PASSWORD)
                db.commit()
                return "ACTIVE"
            except InvalidAccountActionToken:
                db.rollback()
                return "REJECTED"

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(activate, range(2))) == ["ACTIVE", "REJECTED"]


@pytest.mark.parametrize("mutation", ["expired", "invalidated", "email", "disabled"])
def test_activation_rejection(mutation):
    from app.models import UserIdentity

    with SessionLocal() as db:
        user, issued = enroll.create_user(db, context(db), payload())
        row = db.get(AccountActionToken, issued.id)
        if mutation == "expired":
            row.created_at -= timedelta(hours=6)
            row.expires_at -= timedelta(hours=6)
        elif mutation == "invalidated":
            row.invalidated_at = datetime.now(UTC)
        elif mutation == "email":
            db.scalar(
                select(UserIdentity).where(UserIdentity.user_id == user.id)
            ).provider_identifier = "changed@example.test"
        else:
            user.status = "DISABLED"
        db.commit()
        with pytest.raises(InvalidAccountActionToken):
            auth.activate(db, issued.raw_token, PASSWORD)
        assert credential(db, user) is None


def test_email_failure_resend_rotation_and_scope(monkeypatch):
    from app.services import email_sender

    class FailedSender:
        def send_email(self, message):
            assert "#token=" in message.get_body(preferencelist=("plain",)).get_content()
            raise RuntimeError("SMTP failed")

    monkeypatch.setattr(email_sender, "get_email_sender", lambda: FailedSender())
    with SessionLocal() as db:
        actor = context(db, False)
        user, old = enroll.create_user(db, actor, payload())
        db.commit()
        assert enroll.deliver_activation(user, old)["status"] == "FAILED"
        assert user.status == "PENDING_EMAIL_VERIFICATION"
        with pytest.raises(HTTPException) as exc:
            enroll.resend(db, actor, 1, user.id)
        assert exc.value.status_code == 429
        with pytest.raises(HTTPException) as exc:
            enroll.resend(db, actor, 2, user.id)
        assert exc.value.status_code == 403
        db.get(AccountActionToken, old.id).created_at -= timedelta(minutes=2)
        db.commit()
        _, new = enroll.resend(db, actor, 1, user.id)
        db.commit()
        with pytest.raises(InvalidAccountActionToken):
            auth.activate(db, old.raw_token, PASSWORD)
        auth.activate(db, new.raw_token, PASSWORD)
        db.commit()
        assert user.status == "ACTIVE"
        assert db.scalar(select(func.count(TenantUser.id))) == 1


def test_success_resets_and_rehashes():
    from argon2 import PasswordHasher

    with SessionLocal() as db:
        user = enrolled(db)
        cred = credential(db, user)
        cred.password_hash = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(PASSWORD)
        db.commit()
        assert auth.login(db, user.email, "wrong") is None
        db.commit()
        assert auth.login(db, user.email, PASSWORD)
        db.commit()
        cred = credential(db, user)
        assert cred.failed_login_count == 0 and not password_service.needs_rehash(cred.password_hash)
        assert user.last_login_at


@pytest.mark.parametrize("status", ["PENDING_EMAIL_VERIFICATION", "DISABLED", "FORCE_PASSWORD_CHANGE"])
def test_nonactive_login(status):
    with SessionLocal() as db:
        user = enrolled(db)
        user.status = status
        db.commit()
        assert auth.login(db, user.email, PASSWORD) is None


def test_creation_and_login_audit_rollback(monkeypatch):
    with SessionLocal() as db:
        actor = context(db)
        original = audit_service.write_authorization_audit

        def fail_creation(*args, **kwargs):
            if kwargs.get("action") == "NATIVE_USER_CREATED":
                raise RuntimeError("audit unavailable")
            return original(*args, **kwargs)

        monkeypatch.setattr(audit_service, "write_authorization_audit", fail_creation)
        with pytest.raises(RuntimeError):
            enroll.create_user(db, actor, payload())
        db.commit()
        assert db.scalar(select(func.count(TenantUser.id))) == 0
        assert db.scalar(select(func.count(AccountActionToken.id))) == 0
        monkeypatch.setattr(audit_service, "write_authorization_audit", original)
        user = enrolled(db)

        def fail_login(*args, **kwargs):
            raise RuntimeError("audit unavailable")

        monkeypatch.setattr(audit_service, "write_authorization_audit", fail_login)
        with pytest.raises(RuntimeError):
            auth.login(db, user.email, "wrong")
        db.commit()
        assert credential(db, user).failed_login_count == 0


def test_disable_enable_does_not_revive_token():
    from app.services.platform_service import update_user_status

    with SessionLocal() as db:
        user = enrolled(db)
        token = auth.login(db, user.email, PASSWORD)
        db.commit()
        claims = tokens.validate_token(token)
        update_user_status(db, user.id, "DISABLED")
        db.commit()
        update_user_status(db, user.id, "ACTIVE")
        db.commit()
        with pytest.raises(HTTPException):
            tokens.resolve_user(db, claims)


@pytest.mark.parametrize(
    "setting,value",
    [
        ("native_jwt_algorithm", "HS256"),
        ("native_jwt_private_key", ""),
        ("native_jwt_issuer", "http://native.test"),
        ("native_jwt_audience", ""),
        ("tenant_role_assignment_mode", "LEGACY"),
        ("authorization_catalog_fail_closed", False),
    ],
)
def test_signing_config_fails_closed(monkeypatch, setting, value):
    monkeypatch.setattr(get_settings(), setting, value)
    with pytest.raises(RuntimeError):
        tokens.signing_key()


def test_public_and_admin_http_boundaries():
    from app import error_handlers
    from app.core.security import get_current_tenant_context
    from app.routers.native_auth import router
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    api = FastAPI()
    api.include_router(router)
    error_handlers.install(api)
    with SessionLocal() as db:
        actor = context(db, False)
    api.dependency_overrides[get_current_tenant_context] = lambda: actor
    with TestClient(api) as client:
        denied = client.post("/api/tenants/2/native-users", json=payload(tenant_id=2).model_dump())
        assert denied.status_code == 403
        denied = client.post("/api/platform/native-users", json=payload().model_dump())
        assert denied.status_code == 403
        created = client.post("/api/tenants/1/native-users", json=payload().model_dump())
        assert created.status_code == 201, created.text
        first = client.post("/api/auth/native/login", json={"email": "john@example.test", "password": PASSWORD})
        second = client.post("/api/auth/native/login", json={"email": "unknown@example.test", "password": PASSWORD})
        assert first.status_code == second.status_code == 401 and first.json() == second.json()
        secret = "do-not-reflect-this-secret"
        malformed = client.post("/api/auth/native/activate", json={"token": secret, "password": {"secret": secret}})
        assert malformed.status_code == 422 and secret not in malformed.text


def test_http_activation_login_and_shared_context():
    from app.routers.native_auth import router
    from app.routers.tenants import router as tenant_router
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    with SessionLocal() as db:
        user, issued = enroll.create_user(db, context(db), payload())
        user_id = user.id
        db.commit()
    api = FastAPI()
    api.include_router(router)
    api.include_router(tenant_router)
    with TestClient(api) as client:
        activated = client.post("/api/auth/native/activate", json={"token": issued.raw_token, "password": PASSWORD})
        assert activated.status_code == 200, activated.text
        login = client.post("/api/auth/native/login", json={"email": "john@example.test", "password": PASSWORD})
        assert login.status_code == 200, login.text
        assert login.headers["cache-control"] == "no-store"
        token = login.json()["access_token"]
        headers = {"Authorization": "Bearer " + token, "X-Tenant-ID": "1"}
        result = client.get("/api/auth/context", headers=headers)
        assert result.status_code == 200, result.text
        assert result.json()["user"]["id"] == user_id
        assert set(result.json()["tenant_context"]["active_tenant"]["roles"]) == {"SECURITY_ANALYST", "DEVELOPER"}
        for _ in range(5):
            assert (
                client.post(
                    "/api/auth/native/login", json={"email": "john@example.test", "password": "wrong"}
                ).status_code
                == 401
            )
        assert client.get("/api/auth/context", headers=headers).status_code == 401
        assert client.get("/api/auth/me", headers=headers).status_code == 401


def test_login_uses_native_identifier_not_profile_email():
    with SessionLocal() as db:
        user = enrolled(db)
        user.email = "changed-profile@example.test"
        db.commit()
        assert auth.login(db, user.email, PASSWORD) is None
        assert auth.login(db, " JOHN@example.test ", PASSWORD)


def test_future_not_before_and_token_roles_are_not_authority():
    with SessionLocal() as db:
        user = enrolled(db)
        claims = tokens.validate_token(auth.login(db, user.email, PASSWORD))
        claims["roles"] = ["PLATFORM_ADMIN"]
        claims["permissions"] = ["platform:admin"]
        token = jwt.encode(claims, tokens.signing_key(), algorithm="RS256")
        resolved = _resolve_context(db, tokens.validate_token(token), "1")
        assert not resolved.is_platform_admin and "PLATFORM_ADMIN" not in resolved.roles
        claims["nbf"] = int(datetime.now(UTC).timestamp()) + 3600
        with pytest.raises(HTTPException):
            tokens.validate_token(jwt.encode(claims, tokens.signing_key(), algorithm="RS256"))


def test_configured_lockout_threshold_and_duration(monkeypatch):
    monkeypatch.setattr(get_settings(), "native_login_max_failed_attempts", 2)
    monkeypatch.setattr(get_settings(), "native_login_lockout_seconds", 120)
    with SessionLocal() as db:
        user = enrolled(db)
        assert auth.login(db, user.email, "wrong") is None
        db.commit()
        assert user.status == "ACTIVE"
        assert auth.login(db, user.email, "wrong") is None
        db.commit()
        cred = credential(db, user)
        assert user.status == "LOCKED"
        assert (cred.locked_until - cred.locked_at).total_seconds() == 120
