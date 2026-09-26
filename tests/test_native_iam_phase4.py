"""Native password/security tests against disposable PostgreSQL."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import jwt
import pytest
from app.db import SessionLocal
from app.models import AccountActionToken, AuthorizationAuditLog, IAMUser
from app.routers.native_auth import router
from app.services import audit_service, native_abuse_service, password_service
from app.services import native_auth_service as auth
from app.services import native_jwt_service as tokens
from app.services import native_password_service as passwords
from app.services.account_action_token_service import InvalidAccountActionToken, hash_action_token
from app.services.account_state_service import transition_account
from app.settings import get_settings
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import select

from tests.phase6_helpers import seed_user
from tests.test_native_iam_phase2 import PASSWORD, credential, enrolled
from tests.test_native_iam_phase2 import native_config as native_config

NEW = "a different secure passphrase 42"


@pytest.fixture
def account(native_config):
    with SessionLocal() as db:
        user = enrolled(db)
        uid = user.id
        old = auth.login(db, user.email, PASSWORD)
        db.commit()
    return uid, old


@pytest.fixture
def client():
    api = FastAPI()
    api.include_router(router)
    with TestClient(api) as client:
        yield client


def reset_token(uid):
    with SessionLocal() as db:
        user, issued = passwords.request_reset(db, db.get(IAMUser, uid).email)
        db.commit()
        return issued


def assert_replaced(uid, old):
    with SessionLocal() as db:
        user = db.get(IAMUser, uid)
        assert auth.login(db, user.email, PASSWORD) is None
        db.commit()
        assert auth.login(db, user.email, NEW)
        db.commit()
        with pytest.raises(HTTPException):
            tokens.resolve_user(db, tokens.validate_token(old))


def test_active_change_revokes_and_audits(account, client):
    uid, old = account
    response = client.post(
        "/api/auth/native/change-password",
        headers={"Authorization": f"Bearer {old}"},
        json={"current_password": PASSWORD, "new_password": NEW},
    )
    assert response.status_code == 200, response.text
    assert_replaced(uid, old)
    with SessionLocal() as db:
        actions = set(db.scalars(select(AuthorizationAuditLog.action)))
        assert {"PASSWORD_CHANGED", "ALL_SESSIONS_REVOKED"} <= actions


@pytest.mark.parametrize(
    "current,new,status",
    [
        ("wrong", NEW, 401),
        (PASSWORD, PASSWORD, 422),
        (PASSWORD, " " * 20, 422),
        (PASSWORD, "short", 422),
        (PASSWORD, "ü" * 600, 422),
    ],
)
def test_change_rejections(account, client, current, new, status):
    uid, old = account
    response = client.post(
        "/api/auth/native/change-password",
        headers={"Authorization": f"Bearer {old}"},
        json={"current_password": current, "new_password": new},
    )
    assert response.status_code == status, response.text
    with SessionLocal() as db:
        assert tokens.resolve_user(db, tokens.validate_token(old)).id == uid


def test_forced_login_only_routes_to_change_and_completes(account, client):
    uid, old = account
    with SessionLocal() as db:
        user = transition_account(db, uid, "FORCE_PASSWORD_CHANGE", actor_user_id=uid)
        email = user.email
        db.commit()
    response = client.post("/api/auth/native/login", json={"email": email, "password": PASSWORD})
    assert response.json() == {"password_change_required": True}
    assert client.get("/api/auth/native/session", headers={"Authorization": f"Bearer {old}"}).status_code == 401
    response = client.post(
        "/api/auth/native/force-change-password",
        json={"email": email, "current_password": PASSWORD, "new_password": NEW},
    )
    assert response.status_code == 200, response.text
    assert_replaced(uid, old)
    with SessionLocal() as db:
        assert db.get(IAMUser, uid).status == "ACTIVE"
        assert {"PASSWORD_CHANGED", "PASSWORD_ACCOUNT_ACTIVATED"} <= set(
            db.scalars(select(AuthorizationAuditLog.action))
        )


@pytest.mark.parametrize(
    "state,eligible",
    [
        ("ACTIVE", True),
        ("LOCKED", True),
        ("FORCE_PASSWORD_CHANGE", True),
        ("DISABLED", False),
        ("PENDING_EMAIL_VERIFICATION", False),
        ("PENDING", False),
    ],
)
def test_reset_status_policy(account, state, eligible):
    uid, old = account
    with SessionLocal() as db:
        user = db.get(IAMUser, uid)
        user.status = state
        db.commit()
        issued = passwords.request_reset(db, user.email)
        db.commit()
        assert bool(issued) == eligible
        if eligible:
            passwords.reset_password(db, issued[1].raw_token, NEW)
            db.commit()
            assert db.get(IAMUser, uid).status == "ACTIVE"
            cred = credential(db, user)
            assert cred.locked_at is None and cred.locked_until is None and cred.failed_login_count == 0
        else:
            assert db.get(IAMUser, uid).status == state
    if eligible:
        assert_replaced(uid, old)


@pytest.mark.parametrize("kind", ["unknown", "hcl", "native", "disabled"])
def test_forgot_generic_no_enumeration(account, client, monkeypatch, kind):
    uid, old = account
    monkeypatch.setattr(
        "app.services.native_security_delivery.deliver_reset", lambda *a: {"status": "SENT", "error_code": None}
    )
    with SessionLocal() as db:
        email = "unknown@example.test"
        if kind == "hcl":
            email = seed_user(db).email
        if kind in {"native", "disabled"}:
            user = db.get(IAMUser, uid)
            email = user.email
            if kind == "disabled":
                user.status = "DISABLED"
        db.commit()
    response = client.post("/api/auth/native/forgot-password", json={"email": email})
    assert response.status_code == 200
    assert response.json() == {"message": passwords.GENERIC_RESET}
    with SessionLocal() as db:
        issued = db.scalars(select(AccountActionToken).where(AccountActionToken.purpose == "PASSWORD_RESET")).all()
        assert len(issued) == (1 if kind == "native" else 0)


def test_reset_hashed_single_use_and_revokes(account):
    uid, old = account
    issued = reset_token(uid)
    with SessionLocal() as db:
        row = db.get(AccountActionToken, issued.id)
        assert row.token_hash == hash_action_token(issued.raw_token) and row.token_hash != issued.raw_token
        assert row.purpose == "PASSWORD_RESET"
        passwords.reset_password(db, issued.raw_token, NEW)
        db.commit()
        with pytest.raises(InvalidAccountActionToken):
            passwords.reset_password(db, issued.raw_token, "yet another secure passphrase")
    assert_replaced(uid, old)


@pytest.mark.parametrize("condition", ["expired", "invalidated", "email", "disabled", "purpose"])
def test_reset_rejects_invalid_binding(account, condition):
    uid, old = account
    issued = reset_token(uid)
    with SessionLocal() as db:
        row = db.get(AccountActionToken, issued.id)
        if condition == "expired":
            row.created_at -= timedelta(hours=2)
            row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        if condition == "invalidated":
            row.invalidated_at = datetime.now(UTC)
        if condition == "email":
            row.email_snapshot = "other@example.test"
        if condition == "disabled":
            db.get(IAMUser, uid).status = "DISABLED"
        if condition == "purpose":
            row.purpose = "ACCOUNT_ACTIVATION"
        db.commit()
        with pytest.raises(InvalidAccountActionToken):
            passwords.reset_password(db, issued.raw_token, NEW)
        db.commit()
        assert db.get(AccountActionToken, issued.id).consumed_at is None
        if condition == "disabled":
            assert db.get(IAMUser, uid).status == "DISABLED"


def test_reset_rotation_invalidates_previous(account):
    uid, old = account
    first = reset_token(uid)
    with SessionLocal() as db:
        db.get(AccountActionToken, first.id).created_at -= timedelta(minutes=2)
        db.commit()
    second = reset_token(uid)
    with SessionLocal() as db:
        with pytest.raises(InvalidAccountActionToken):
            passwords.reset_password(db, first.raw_token, NEW)
        passwords.reset_password(db, second.raw_token, NEW)
        db.commit()


@pytest.mark.parametrize("operation", ["change", "force", "reset"])
def test_concurrent_password_operations_one_winner(account, operation):
    uid, old = account
    issued = reset_token(uid)
    with SessionLocal() as db:
        email = db.get(IAMUser, uid).email
        if operation == "force":
            transition_account(db, uid, "FORCE_PASSWORD_CHANGE", actor_user_id=uid)
        db.commit()
    barrier = Barrier(2)

    def attempt(_):
        with SessionLocal() as db:
            barrier.wait(timeout=10)
            try:
                if operation == "reset":
                    result = passwords.reset_password(db, issued.raw_token, NEW)
                elif operation == "force":
                    result = passwords.complete_forced(db, email, PASSWORD, NEW)
                else:
                    result = passwords.change_password(
                        db, uid, tokens.validate_token(old)["security_version"], PASSWORD, NEW
                    )
                db.commit()
                return bool(result)
            except (HTTPException, InvalidAccountActionToken):
                db.rollback()
                return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(attempt, range(2))) == [False, True]
    assert_replaced(uid, old)


def test_audit_failure_rolls_back_hash_token_and_version(account, monkeypatch):
    uid, old = account
    issued = reset_token(uid)

    def fail(*a, **kw):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(audit_service, "write_authorization_audit", fail)
    with SessionLocal() as db:
        before = credential(db, db.get(IAMUser, uid)).password_hash
        with pytest.raises(RuntimeError):
            passwords.reset_password(db, issued.raw_token, NEW)
        db.commit()
        assert credential(db, db.get(IAMUser, uid)).password_hash == before
        assert db.get(AccountActionToken, issued.id).consumed_at is None
        assert tokens.resolve_user(db, tokens.validate_token(old)).id == uid


@pytest.mark.parametrize(
    "endpoint,payload",
    [
        ("login", {"email": "absent@example.test", "password": "wrong"}),
        ("forgot-password", {"email": "absent@example.test"}),
        ("activate", {"token": "a" * 43, "password": NEW}),
        ("reset-password", {"token": "a" * 43, "new_password": NEW}),
    ],
)
def test_public_endpoint_abuse_limits(client, native_config, monkeypatch, endpoint, payload):
    monkeypatch.setenv("API_RATE_LIMIT_ENABLED", "true")
    monkeypatch.setattr(get_settings(), "native_auth_ip_limit_per_minute", 1)
    native_abuse_service.limiter.cache_clear()
    first = client.post("/api/auth/native/" + endpoint, json=payload)
    assert first.status_code != 429
    assert client.post("/api/auth/native/" + endpoint, json=payload).status_code == 429


def test_logout_all_revokes_old_jwt(account, client):
    uid, old = account
    assert client.post("/api/auth/native/logout-all", headers={"Authorization": f"Bearer {old}"}).status_code == 200
    assert client.get("/api/auth/native/session", headers={"Authorization": f"Bearer {old}"}).status_code == 401


def test_policy_preserves_unicode_and_spaces(monkeypatch):
    monkeypatch.setattr(get_settings(), "native_password_min_length", 14)
    value = "  a long pässword  "
    password_service.validate_password(value)
    hashed = password_service.hash_password(value)
    assert password_service.verify_password(value, hashed)
    assert not password_service.verify_password(value.strip(), hashed)
    with pytest.raises(HTTPException):
        password_service.validate_password("twelve chars!")


def test_signing_rotation(account, monkeypatch):
    import json

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    uid, old = account
    s = get_settings()
    old_public = (
        tokens.signing_key()
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    next_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr(
        s,
        "native_jwt_private_key",
        next_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode(),
    )
    monkeypatch.setattr(
        s,
        "native_jwt_public_key",
        next_key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode(),
    )
    monkeypatch.setattr(s, "native_jwt_active_kid", "native-v2")
    monkeypatch.setattr(
        s,
        "native_jwt_verification_keys_json",
        json.dumps({"native-v1": {"public_key": old_public, "not_after": int(datetime.now(UTC).timestamp()) + 900}}),
    )
    assert tokens.validate_token(old)["sub"] == str(uid)
    with SessionLocal() as db:
        user = db.get(IAMUser, uid)
        new = tokens.issue_token(user, credential(db, user))
    assert jwt.get_unverified_header(new)["kid"] == "native-v2"
    assert tokens.validate_token(new)["sub"] == str(uid)
    monkeypatch.setattr(s, "native_jwt_verification_keys_json", "{}")
    with pytest.raises(HTTPException):
        tokens.validate_token(old)
    wrong = jwt.encode(tokens.validate_token(new), "a" * 32, algorithm="HS256", headers={"kid": "native-v2"})
    with pytest.raises(HTTPException):
        tokens.validate_token(wrong)


def test_forgot_normalizes_hash_cost_for_all_account_classes(account, monkeypatch):
    uid, _ = account
    original = password_service.verify_password
    calls = []

    def counted(*args):
        calls.append(1)
        return original(*args)

    monkeypatch.setattr(password_service, "verify_password", counted)
    with SessionLocal() as db:
        user = db.get(IAMUser, uid)
        for email in ["absent@example.test", user.email]:
            before = len(calls)
            passwords.request_reset(db, email)
            db.commit()
            assert len(calls) - before == 1


def test_resend_route_is_throttled_before_token_or_email_work(account, client, monkeypatch):
    from app.core.security import get_current_tenant_context

    from tests.test_native_iam_phase2 import context

    with SessionLocal() as db:
        actor = context(db)
        db.commit()
    client.app.dependency_overrides[get_current_tenant_context] = lambda: actor
    monkeypatch.setenv("API_RATE_LIMIT_ENABLED", "true")
    monkeypatch.setattr(get_settings(), "native_auth_ip_limit_per_minute", 1)
    native_abuse_service.limiter.cache_clear()
    path = f"/api/tenants/1/native-users/{account[0]}/resend-activation"
    assert client.post(path).status_code == 404  # Already active, ineligible.
    assert client.post(path).status_code == 429


def test_account_limit_is_normalized_and_independent_of_source(native_config, monkeypatch):
    from starlette.requests import Request

    monkeypatch.setenv("API_RATE_LIMIT_ENABLED", "true")
    monkeypatch.setattr(get_settings(), "native_auth_account_limit_per_minute", 1)
    native_abuse_service.limiter.cache_clear()

    def request(ip):
        return Request({"type": "http", "client": (ip, 1234), "headers": []})

    native_abuse_service.check(request("10.0.0.1"), "login", " A@EXAMPLE.TEST ")
    with pytest.raises(HTTPException) as exc:
        native_abuse_service.check(request("10.0.0.2"), "login", "a@example.test")
    assert exc.value.status_code == 429


def test_disabled_account_cannot_complete_forced_flow(account, client):
    uid, _ = account
    with SessionLocal() as db:
        user = db.get(IAMUser, uid)
        email = user.email
        user.status = "DISABLED"
        db.commit()
    response = client.post(
        "/api/auth/native/force-change-password",
        json={"email": email, "current_password": PASSWORD, "new_password": NEW},
    )
    assert response.status_code == 401
    with SessionLocal() as db:
        assert db.get(IAMUser, uid).status == "DISABLED"


def test_forced_wrong_password_temporary_lock_does_not_clear_requirement(account, client):
    uid, _ = account
    with SessionLocal() as db:
        user = transition_account(db, uid, "FORCE_PASSWORD_CHANGE", actor_user_id=uid)
        email = user.email
        db.commit()
    for _ in range(5):
        assert client.post("/api/auth/native/login", json={"email": email, "password": "wrong"}).status_code == 401
    assert client.post("/api/auth/native/login", json={"email": email, "password": PASSWORD}).status_code == 401
    with SessionLocal() as db:
        assert db.get(IAMUser, uid).status == "FORCE_PASSWORD_CHANGE"
        assert credential(db, db.get(IAMUser, uid)).locked_until


def test_expired_overlap_key_rejected(account, monkeypatch):
    import json

    from cryptography.hazmat.primitives import serialization

    _, old = account
    public = (
        tokens.signing_key()
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    monkeypatch.setattr(get_settings(), "native_jwt_active_kid", "next-key")
    monkeypatch.setattr(
        get_settings(),
        "native_jwt_verification_keys_json",
        json.dumps({"native-v1": {"public_key": public, "not_after": int(datetime.now(UTC).timestamp()) - 1}}),
    )
    with pytest.raises(HTTPException):
        tokens.validate_token(old)
