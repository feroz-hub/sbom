"""Local real SMTP protocol and worker-crash boundary; no external delivery."""

import base64
import os
import socketserver
import subprocess
import sys
import threading
from datetime import UTC, datetime, timedelta
from email import policy
from email.parser import BytesParser

import pytest
from app.db import SessionLocal
from app.models import AccountActionToken, IAMUser, NativeUserCredential, SecurityMailOutbox, TenantUser
from app.services import native_enrollment_service as enrollment
from app.services import security_mail_outbox as outbox
from app.settings import get_settings
from sqlalchemy import func, select

from tests.test_native_iam_phase2 import context, payload
from tests.test_native_iam_phase2 import native_config as native_config


class Sink(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class SMTP(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"220 acceptance.local SMTP\r\n")
        while line := self.rfile.readline():
            command = line.split()[0].upper()
            if command == b"DATA":
                self.wfile.write(b"354 Send message\r\n")
                body = bytearray()
                while (line := self.rfile.readline()) not in (b".\r\n", b""):
                    body.extend(line)
                self.server.messages.append(bytes(body))
                self.wfile.write(b"250 Accepted\r\n")
            elif command == b"QUIT":
                self.wfile.write(b"221 Bye\r\n")
                break
            else:
                self.wfile.write(b"250 OK\r\n")


@pytest.fixture
def mail(monkeypatch):
    server = Sink(("127.0.0.1", 0), SMTP)
    server.messages = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    s = get_settings()
    values = dict(
        native_security_outbox_enabled=True,
        native_security_outbox_key=base64.b64encode(os.urandom(32)).decode(),
        email_delivery_enabled=True,
        email_from_address="support@acceptance.test",
        smtp_host="127.0.0.1",
        smtp_port=server.server_address[1],
        smtp_use_starttls=False,
        smtp_use_tls=False,
        smtp_username="",
    )
    for key, value in values.items():
        monkeypatch.setattr(s, key, value)
    try:
        yield server, values
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def queued():
    with SessionLocal() as db:
        user, issued = enrollment.create_user(db, context(db), payload())
        db.commit()
        rowid = db.scalar(select(SecurityMailOutbox.id).where(SecurityMailOutbox.token_id == issued.id))
        return rowid, issued


def test_real_smtp_failure_then_retry(mail, monkeypatch, caplog):
    server, _ = mail
    rowid, token = queued()
    monkeypatch.setattr(get_settings(), "smtp_port", 1)  # unavailable loopback port
    outbox.deliver_one(rowid)
    with SessionLocal() as db:
        row = db.get(SecurityMailOutbox, rowid)
        assert row.status == "PENDING" and row.attempts == 1
        row.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
    monkeypatch.setattr(get_settings(), "smtp_port", server.server_address[1])
    outbox.deliver_one(rowid)
    assert len(server.messages) == 1
    message = BytesParser(policy=policy.default).parsebytes(server.messages[0])
    assert message["To"] == token.email_snapshot
    assert token.raw_token in message.get_body(preferencelist=("plain",)).get_content()
    with SessionLocal() as db:
        row = db.get(SecurityMailOutbox, rowid)
        assert row.status == "DELIVERED" and row.payload is None
    assert token.raw_token not in caplog.text


def test_smtp_accept_then_worker_crash_retries_same_token(mail):
    server, values = mail
    rowid, token = queued()
    with SessionLocal() as db:
        before = [
            db.scalar(select(func.count()).select_from(model))
            for model in [IAMUser, TenantUser, NativeUserCredential, AccountActionToken]
        ]
    env = dict(os.environ)
    for key, value in values.items():
        env[key.upper()] = str(value).lower() if isinstance(value, bool) else str(value)
    code = """
import os
from app.services import audit_service
from app.services.security_mail_outbox import deliver_one
audit_service.write_authorization_audit=lambda *a,**kw: os._exit(73)
deliver_one(int(__import__('sys').argv[1]))
"""
    result = subprocess.run([sys.executable, "-c", code, str(rowid)], env=env, capture_output=True, timeout=30)
    assert result.returncode == 73 and token.raw_token.encode() not in result.stdout + result.stderr
    assert len(server.messages) == 1
    outbox.deliver_one(rowid)
    assert len(server.messages) == 2
    messages = [BytesParser(policy=policy.default).parsebytes(m) for m in server.messages]
    assert messages[0]["Message-ID"] == messages[1]["Message-ID"]
    assert all(token.raw_token in m.get_body(preferencelist=("plain",)).get_content() for m in messages)
    with SessionLocal() as db:
        after = [
            db.scalar(select(func.count()).select_from(model))
            for model in [IAMUser, TenantUser, NativeUserCredential, AccountActionToken]
        ]
        assert before == after and db.get(SecurityMailOutbox, rowid).payload is None
