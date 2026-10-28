"""Native singleton bootstrap and atomic activation regression."""
import base64
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest
from app.db import SessionLocal
from app.models import (
    AccountActionToken,
    IAMUser,
    NativePlatformBootstrap,
    NativeUserCredential,
    PlatformUserRole,
    SecurityMailOutbox,
    UserIdentity,
)
from app.services import audit_service, email_sender, platform_service
from app.services import native_auth_service as auth
from app.services import native_platform_bootstrap as bootstrap
from app.settings import get_settings
from sqlalchemy import func, select

from tests.test_native_iam_phase2 import PASSWORD
from tests.test_native_iam_phase2 import native_config as native_config


@pytest.fixture(autouse=True)
def config(native_config, monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "native_platform_bootstrap_enabled", True)
    monkeypatch.setattr(s, "native_security_outbox_enabled", True)
    monkeypatch.setattr(s, "native_security_outbox_key", base64.b64encode(os.urandom(32)).decode())


def create(db):
    return bootstrap.create(db, email="first@native.test", first_name="First", last_name="Admin", phone="test-phone", operator_reference="test-change")


def token_from_test_mail(db, uid, monkeypatch):
    # Consume only the provider's test message, never decrypt outbox manually.
    messages = []
    class Capture:
        def send_email(self, message):
            messages.append(message)
            return email_sender.EmailDeliveryResult(email_sender.EmailDeliveryStatus.SENT)
    monkeypatch.setattr(email_sender, "get_email_sender", lambda: Capture())
    from app.services.security_mail_outbox import deliver_one
    rid = db.scalar(select(SecurityMailOutbox.id).where(SecurityMailOutbox.user_id == uid).order_by(SecurityMailOutbox.id.desc()))
    db.commit()
    deliver_one(rid)
    import re
    return re.search(r"#token=([A-Za-z0-9_-]+)", messages[0].get_body(preferencelist=("plain",)).get_content())[1]


def test_disabled(monkeypatch):
    monkeypatch.setattr(get_settings(), "native_platform_bootstrap_enabled", False)
    with SessionLocal() as db, pytest.raises(bootstrap.BootstrapRefused):
        create(db)


def test_pending_complete_and_reuse(monkeypatch):
    with SessionLocal() as db:
        uid = create(db)
        db.commit()
        assert db.get(IAMUser, uid).status == "PENDING_EMAIL_VERIFICATION"
        assert db.scalar(select(UserIdentity.provider_type).where(UserIdentity.user_id == uid)) == "NATIVE"
        assert db.scalar(select(NativeUserCredential.id).where(NativeUserCredential.user_id == uid)) is None
        assert db.scalar(select(SecurityMailOutbox.status).where(SecurityMailOutbox.user_id == uid)) == "PENDING"
        with pytest.raises(bootstrap.BootstrapRefused):
            create(db)
        db.rollback()
        raw = token_from_test_mail(db, uid, monkeypatch)
        auth.activate(db, raw, PASSWORD)
        db.commit()
        assert db.get(NativePlatformBootstrap, 1).state == "COMPLETED"
        assert db.get(IAMUser, uid).status == "ACTIVE"
        assert db.scalar(select(PlatformUserRole.status).where(PlatformUserRole.user_id == uid)) == "ACTIVE"
        assert auth.login(db, "first@native.test", PASSWORD)
        with pytest.raises(bootstrap.BootstrapRefused):
            create(db)


@pytest.mark.parametrize("failure", ["grant", "audit"])
def test_atomic_failure(monkeypatch, failure):
    with SessionLocal() as db:
        uid = create(db)
        db.commit()
        raw = token_from_test_mail(db, uid, monkeypatch)
        def fail(*args, **kwargs):
            raise RuntimeError("test failure")
        if failure == "grant":
            monkeypatch.setattr(platform_service, "bootstrap_platform_administrator", fail)
        else:
            original = audit_service.write_authorization_audit
            def fail_completion(*args, **kwargs):
                if kwargs.get("action") == "NATIVE_PLATFORM_BOOTSTRAP_COMPLETED":
                    raise RuntimeError("completion audit unavailable")
                return original(*args, **kwargs)
            monkeypatch.setattr(audit_service, "write_authorization_audit", fail_completion)
        with pytest.raises(RuntimeError):
            auth.activate(db, raw, PASSWORD)
        db.rollback()
        assert db.get(IAMUser, uid).status == "PENDING_EMAIL_VERIFICATION"
        assert db.get(NativePlatformBootstrap, 1).state == "PENDING"
        assert db.scalar(select(PlatformUserRole.id).where(PlatformUserRole.user_id == uid)) is None
        assert db.scalar(select(NativeUserCredential.id).where(NativeUserCredential.user_id == uid)) is None


def test_resend_same_user(monkeypatch):
    with SessionLocal() as db:
        uid = create(db)
        db.commit()
        old = db.scalar(select(AccountActionToken.id).where(AccountActionToken.user_id == uid))
        row = db.get(AccountActionToken, old)
        row.created_at = datetime.now(UTC) - timedelta(hours=6)
        row.expires_at = datetime.now(UTC) - timedelta(hours=1)
        db.commit()
        assert bootstrap.resend(db) == uid
        db.commit()
        assert db.get(AccountActionToken, old).invalidated_at
        assert db.scalar(select(SecurityMailOutbox.status).where(SecurityMailOutbox.token_id == old)) == "CANCELLED"
        assert db.scalar(select(func.count(IAMUser.id)).where(IAMUser.email == "first@native.test")) == 1
        raw = token_from_test_mail(db, uid, monkeypatch)
        auth.activate(db, raw, PASSWORD)
        db.commit()


def test_concurrent_one_winner():
    barrier = Barrier(2)
    def run(_):
        with SessionLocal() as db:
            barrier.wait()
            try:
                uid = create(db)
                db.commit()
                return uid
            except bootstrap.BootstrapRefused:
                db.rollback()
                return None
    with ThreadPoolExecutor(2) as pool:
        assert sum(x is not None for x in pool.map(run, range(2))) == 1


def test_unknown_provider(monkeypatch):
    monkeypatch.setattr(get_settings(), "email_provider", "microsoft_graph")
    with pytest.raises(RuntimeError, match="Unsupported EMAIL_PROVIDER"):
        email_sender.get_email_sender()


def test_create_audit_failure_rolls_back(monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError("audit unavailable")
    monkeypatch.setattr(audit_service, "write_authorization_audit", fail)
    with SessionLocal() as db:
        with pytest.raises(RuntimeError):
            create(db)
        db.rollback()
        assert db.get(NativePlatformBootstrap, 1) is None
        assert db.scalar(select(IAMUser.id).where(IAMUser.email == "first@native.test")) is None


def test_native_only_setup_and_hcl_denial(monkeypatch):
    from app.core.security import validate_hcl_auth_setup, validate_hcl_token
    from fastapi import HTTPException
    monkeypatch.setattr(get_settings(), "hcl_auth_enabled", False)
    monkeypatch.setattr(get_settings(), "hcl_iam_issuer", "")
    validate_hcl_auth_setup()
    with pytest.raises(HTTPException):
        validate_hcl_token("not-a-token")
