"""Phase 5 operational security against disposable PostgreSQL."""

import base64
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from app.db import SessionLocal
from app.models import AccountActionToken, IAMUser, SecurityMailOutbox
from app.services import native_enrollment_service as enrollment
from app.services import native_operations
from app.services import native_password_service as passwords
from app.services import security_mail_outbox as outbox
from app.settings import get_settings
from fastapi import HTTPException
from sqlalchemy import select

from tests.test_native_iam_phase2 import context, enrolled, native_config, payload  # noqa: F401


@pytest.fixture(autouse=True)
def durable(monkeypatch):
    monkeypatch.setattr(get_settings(), "native_security_outbox_enabled", True)
    monkeypatch.setattr(get_settings(), "native_security_outbox_key", base64.b64encode(os.urandom(32)).decode())


def activation():
    with SessionLocal() as db:
        user, token = enrollment.create_user(db, context(db), payload())
        db.commit()
        row = db.scalar(select(SecurityMailOutbox).where(SecurityMailOutbox.token_id == token.id))
        return row.id, token


@pytest.mark.parametrize("kind", ["activation", "reset"])
def test_delivery_survives_new_session_and_scrubs_payload(kind, monkeypatch):
    if kind == "activation":
        row_id, token = activation()
    else:
        with SessionLocal() as db:
            user = enrolled(db)
            _, token = passwords.request_reset(db, user.email)
            db.commit()
            row_id = db.scalar(select(SecurityMailOutbox.id).where(SecurityMailOutbox.token_id == token.id))
    with SessionLocal() as db:
        assert token.raw_token.encode() not in db.get(SecurityMailOutbox, row_id).payload
    sender = (
        "app.services.native_enrollment_service.deliver_activation"
        if kind == "activation"
        else "app.services.native_security_delivery.deliver_reset"
    )
    calls = []
    monkeypatch.setattr(sender, lambda u, t: calls.append(t.raw_token) or {"status": "SENT"})
    outbox.deliver_one(row_id)
    outbox.deliver_one(row_id)
    assert calls == [token.raw_token]
    with SessionLocal() as db:
        row = db.get(SecurityMailOutbox, row_id)
        assert row.status == "DELIVERED" and row.payload is None and row.sent_at


def test_retry_backoff_exhaustion_and_erasure(monkeypatch):
    row_id, token = activation()
    monkeypatch.setattr(get_settings(), "native_security_outbox_max_attempts", 2)
    monkeypatch.setattr(enrollment, "deliver_activation", lambda *a: {"status": "FAILED"})
    outbox.deliver_one(row_id)
    with SessionLocal() as db:
        row = db.get(SecurityMailOutbox, row_id)
        assert row.status == "PENDING" and row.attempts == 1
        assert (row.next_attempt_at - datetime.now(UTC)).total_seconds() > 20
        row.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
    outbox.deliver_one(row_id)
    with SessionLocal() as db:
        row = db.get(SecurityMailOutbox, row_id)
        assert row.status == "FAILED" and row.attempts == 2 and row.payload is None
        assert db.get(AccountActionToken, token.id).consumed_at is None


def test_concurrent_workers_one_send(monkeypatch):
    row_id, _ = activation()
    calls = []
    monkeypatch.setattr(enrollment, "deliver_activation", lambda *a: calls.append(1) or {"status": "SENT"})
    with ThreadPoolExecutor(2) as pool:
        list(pool.map(outbox.deliver_one, [row_id, row_id]))
    assert calls == [1]


@pytest.mark.parametrize("reason", ["expiry", "invalidated", "wrong_key", "disabled"])
def test_unsafe_delivery_never_sends(reason, monkeypatch, caplog):
    row_id, token = activation()
    with SessionLocal() as db:
        row = db.get(SecurityMailOutbox, row_id)
        if reason == "expiry":
            row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        elif reason == "invalidated":
            db.get(AccountActionToken, token.id).invalidated_at = datetime.now(UTC)
        elif reason == "disabled":
            db.get(IAMUser, row.user_id).status = "DISABLED"
        db.commit()
    if reason == "wrong_key":
        monkeypatch.setattr(get_settings(), "native_security_outbox_key", base64.b64encode(os.urandom(32)).decode())
    calls = []
    monkeypatch.setattr(enrollment, "deliver_activation", lambda *a: calls.append(1) or {"status": "SENT"})
    outbox.deliver_one(row_id)
    assert not calls and token.raw_token not in caplog.text


def test_encryption_failure_rolls_back_user_and_token(monkeypatch):
    monkeypatch.setattr(get_settings(), "native_security_outbox_key", "bad")
    with SessionLocal() as db:
        ctx = context(db)
        with pytest.raises(RuntimeError, match="encryption"):
            enrollment.create_user(db, ctx, payload())
        db.rollback()
        assert not db.scalar(select(IAMUser.id).where(IAMUser.email == "john@example.test"))


def test_safe_health_projection():
    _, token = activation()
    with SessionLocal() as db:
        health = native_operations.delivery_health(db)
        assert health["counts"]["PENDING"] == 1
        assert token.raw_token not in str(health) and token.email_snapshot not in str(health)


def test_production_fails_safe_missing_configuration(monkeypatch):
    monkeypatch.setattr(get_settings(), "native_iam_production", True)
    monkeypatch.setenv("APP_ORIGIN", "http://unsafe.test")
    with pytest.raises(RuntimeError, match="canonical_origin") as exc:
        native_operations.validate_configuration()
    assert get_settings().native_security_outbox_key not in str(exc.value)


def test_spoofed_forwarding_cannot_bypass_source(monkeypatch):
    from app.services import native_abuse_service as abuse
    from starlette.requests import Request

    monkeypatch.setenv("API_RATE_LIMIT_ENABLED", "true")
    monkeypatch.setattr(get_settings(), "native_auth_ip_limit_per_minute", 1)
    abuse.limiter.cache_clear()

    def request(ip):
        return Request({"type": "http", "client": ("same-proxy", 123), "headers": [(b"x-forwarded-for", ip.encode())]})

    abuse.check(request("1.1.1.1"), "phase5", "one")
    with pytest.raises(HTTPException) as exc:
        abuse.check(request("2.2.2.2"), "phase5", "two")
    assert exc.value.status_code == 429


def test_rate_storage_failure_closed(monkeypatch):
    from app.services import native_abuse_service as abuse
    from starlette.requests import Request

    monkeypatch.setenv("API_RATE_LIMIT_ENABLED", "true")
    monkeypatch.setattr(abuse, "limiter", lambda _: (_ for _ in ()).throw(RuntimeError("secret")))
    with pytest.raises(HTTPException) as exc:
        abuse.check(Request({"type": "http", "client": ("source", 1), "headers": []}), "login")
    assert exc.value.status_code == 503 and "secret" not in str(exc.value)


def test_new_issuance_cancels_previous_delivery(monkeypatch):
    row_id, old = activation()
    from app.services.account_action_token_service import issue_activation_token

    with SessionLocal() as db:
        row = db.get(SecurityMailOutbox, row_id)
        new = issue_activation_token(db, row.user_id, actor_user_id=None)
        db.commit()
        db.refresh(row)
        assert row.status == "CANCELLED" and row.payload is None
        assert new.id != old.id


def test_successful_retry_keeps_original_token(monkeypatch):
    row_id, token = activation()
    attempts = []

    def send(u, t):
        attempts.append(t.raw_token)
        return {"status": "SENT" if len(attempts) == 2 else "FAILED"}

    monkeypatch.setattr(enrollment, "deliver_activation", send)
    outbox.deliver_one(row_id)
    with SessionLocal() as db:
        db.get(SecurityMailOutbox, row_id).next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
    outbox.deliver_one(row_id)
    assert attempts == [token.raw_token, token.raw_token]
    with SessionLocal() as db:
        assert db.get(SecurityMailOutbox, row_id).status == "DELIVERED"


def test_rotation_timeline_two_validator_configurations(monkeypatch):
    import json
    from copy import copy

    from app.services import native_jwt_service as jwt_service
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from tests.test_native_iam_phase2 import credential

    s = get_settings()
    old_key = jwt_service.signing_key()
    new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def public(k):
        return (
            k.public_key()
            .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            .decode()
        )

    deadline = int(datetime.now(UTC).timestamp()) + 900
    with SessionLocal() as db:
        user = enrolled(db)
        token_a = jwt_service.issue_token(user, credential(db, user))
        a = copy(s)
        a.native_jwt_verification_keys_json = json.dumps({"B": {"public_key": public(new_key), "not_after": deadline}})
        b = copy(s)
        b.native_jwt_active_kid = "B"
        b.native_jwt_private_key = new_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode()
        b.native_jwt_verification_keys_json = json.dumps(
            {"native-v1": {"public_key": public(old_key), "not_after": deadline}}
        )
        monkeypatch.setattr(jwt_service, "get_settings", lambda: b)
        token_b = jwt_service.issue_token(user, credential(db, user))
    for replica in [a, b]:
        monkeypatch.setattr(jwt_service, "get_settings", lambda replica=replica: replica)
        assert jwt_service.validate_token(token_a)
        assert jwt_service.validate_token(token_b)
    b.native_jwt_verification_keys_json = "{}"
    for replica in [copy(b), copy(b)]:
        monkeypatch.setattr(jwt_service, "get_settings", lambda replica=replica: replica)
        with pytest.raises(HTTPException):
            jwt_service.validate_token(token_a)
        assert jwt_service.validate_token(token_b)


def test_production_configuration_accepts_complete_settings(monkeypatch):
    s = get_settings()
    for name, value in dict(
        native_iam_production=True,
        email_delivery_enabled=True,
        smtp_host="mail.test",
        email_from_address="support@example.test",
        smtp_use_starttls=True,
        native_auth_rate_limit_storage_uri="redis://localhost:6379/2",
        native_activation_frontend_url="https://sbom.test/activate-account",
        native_password_reset_frontend_url="https://sbom.test/reset-password",
    ).items():
        monkeypatch.setattr(s, name, value)
    monkeypatch.setenv("APP_ORIGIN", "https://sbom.test")
    monkeypatch.setenv("API_RATE_LIMIT_ENABLED", "true")
    native_operations.validate_configuration()
    monkeypatch.setattr(s, "native_jwt_verification_keys_json", "[]")
    with pytest.raises(RuntimeError, match="verification_keyset"):
        native_operations.validate_configuration()


def test_readiness_storage_failure_is_safe(monkeypatch):
    monkeypatch.setattr(native_operations, "redis_client", lambda: (_ for _ in ()).throw(RuntimeError("secret")))
    with SessionLocal() as db:
        status = native_operations.readiness(db)
    assert not status["ready"] and status["checks"]["database"] and "secret" not in str(status)


def test_delivery_audit_failure_rolls_back_pending_state(monkeypatch):
    row_id, _ = activation()
    from app.services import audit_service

    monkeypatch.setattr(enrollment, "deliver_activation", lambda *a: {"status": "SENT"})
    monkeypatch.setattr(
        audit_service,
        "write_authorization_audit",
        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("audit unavailable")),
    )
    with pytest.raises(RuntimeError):
        outbox.deliver_one(row_id)
    with SessionLocal() as db:
        row = db.get(SecurityMailOutbox, row_id)
        assert row.status == "PENDING" and row.payload is not None


@pytest.fixture
def administration_setup():
    # Reuse the approved real-RBAC fixture, without changing its expectations.
    from tests.test_native_iam_phase3 import setup

    yield from setup.__wrapped__(None)


def test_operational_endpoints_are_platform_only(administration_setup, monkeypatch):
    from tests.test_native_iam_phase3 import tenant_actor

    client, current, uid, _, _ = administration_setup
    monkeypatch.setattr(native_operations, "readiness", lambda db: {"ready": True, "checks": {}})
    assert client.get("/api/platform/iam/operations").status_code == 200
    tenant_actor(current)
    assert client.get("/api/platform/iam/operations").status_code == 403
    assert client.post(f"/api/platform/users/{uid}/logout-all").status_code == 403


def test_admin_logout_all_revokes_native_token(administration_setup):
    from app.services import native_jwt_service

    client, _, uid, _, token = administration_setup
    assert client.post(f"/api/platform/users/{uid}/logout-all").status_code == 200
    with SessionLocal() as db:
        with pytest.raises(HTTPException):
            native_jwt_service.resolve_user(db, native_jwt_service.validate_token(token))


@pytest.mark.parametrize("purpose", ["activation", "reset"])
def test_separate_worker_process_delivers_committed_outbox(purpose):
    import subprocess
    import sys

    if purpose == "activation":
        row_id, _ = activation()
    else:
        with SessionLocal() as db:
            user = enrolled(db)
            _, token = passwords.request_reset(db, user.email)
            db.commit()
            row_id = db.scalar(select(SecurityMailOutbox.id).where(SecurityMailOutbox.token_id == token.id))
    env = dict(os.environ, NATIVE_SECURITY_OUTBOX_KEY=get_settings().native_security_outbox_key)
    # Worker transport stub accepts SMTP; only numeric delivery ID crosses argv.
    code = """
from types import SimpleNamespace
from app.services import email_sender
from app.services.security_mail_outbox import deliver_one
class Sender:
    def send_email(self, message):
        assert '#token=' in message.get_body(preferencelist=('plain',)).get_content()
        return SimpleNamespace(status='SENT', error_code=None)
email_sender.get_email_sender = lambda: Sender()
deliver_one(int(__import__('sys').argv[1]))
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(row_id)], env=env, capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0
    with SessionLocal() as db:
        assert db.get(SecurityMailOutbox, row_id).status == "DELIVERED"


def test_outbox_downgrade_refuses_pending_delivery():
    from alembic import command
    from alembic.config import Config

    row_id, _ = activation()
    with pytest.raises(RuntimeError, match="Refusing downgrade"):
        command.downgrade(Config("alembic.ini"), "060_native_identity_foundation")
    with SessionLocal() as db:
        assert db.get(SecurityMailOutbox, row_id).payload is not None
