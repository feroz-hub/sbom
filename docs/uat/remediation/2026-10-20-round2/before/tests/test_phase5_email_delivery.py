from __future__ import annotations

import smtplib
from datetime import UTC, datetime, timedelta

import pytest
from app.services.email_sender import (
    DisabledVerificationEmailSender,
    EmailDeliveryStatus,
    SmtpVerificationEmailSender,
)
from app.services.email_templates import render_verification_email
from app.settings import Settings
from pydantic import ValidationError


def _settings(**overrides):
    values = {
        "_env_file": None,
        "email_delivery_enabled": True,
        "email_provider": "smtp",
        "email_from_address": "no-reply@example.test",
        "email_from_name": "SBOM Analyzer",
        "smtp_host": "smtp.example.test",
        "smtp_port": 587,
        "smtp_username": "mailer",
        "smtp_password": "top-secret-password",
        "smtp_use_tls": False,
        "smtp_use_starttls": True,
    }
    values.update(overrides)
    return Settings(**values)


class FakeSmtp:
    instances = []

    def __init__(self, host, port, timeout, **kwargs):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.kwargs = kwargs
        self.sock = None
        self.messages = []
        self.login_values = None
        self.started_tls = False
        type(self).instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def ehlo(self):
        return None

    def starttls(self, *, context):
        assert context.check_hostname is True
        assert context.verify_mode.name == "CERT_REQUIRED"
        self.started_tls = True

    def login(self, username, password):
        self.login_values = (username, password)

    def send_message(self, message):
        self.messages.append(message)


def test_template_contains_required_content_and_both_formats():
    expires = datetime.now(UTC) + timedelta(hours=24)
    url = "https://app.example.test/verify-email?token=raw-token"
    rendered = render_verification_email(
        recipient_name="Example User",
        verification_url=url,
        expires_at=expires,
    )
    assert rendered.subject == "Verify your SBOM Analyzer account"
    for body in (rendered.text_body, rendered.html_body):
        assert "SBOM Analyzer" in body
        assert "new user" in body
        assert "verification" in body
        assert url.replace("&", "&amp;") in body
        assert expires.strftime("%Y-%m-%d %H:%M UTC") in body
        assert "tenant" not in body.lower()
        assert "employee" not in body.lower()


def test_smtp_sender_uses_starttls_validated_context_and_multipart(monkeypatch):
    FakeSmtp.instances.clear()
    monkeypatch.setattr(smtplib, "SMTP", FakeSmtp)
    settings = _settings()
    sender = SmtpVerificationEmailSender(settings)
    result = sender.send_verification_email(
        recipient_email="recipient@example.test",
        recipient_name="Recipient",
        verification_url="https://app.example.test/verify-email?token=outbound-only",
        expires_at=datetime.now(UTC) + timedelta(hours=24),
        correlation_id="correlation-not-sent",
    )
    assert result.status == EmailDeliveryStatus.SENT
    smtp = FakeSmtp.instances[-1]
    assert smtp.started_tls is True
    assert smtp.login_values == ("mailer", "top-secret-password")
    message = smtp.messages[0]
    assert message["To"] == "recipient@example.test"
    assert message["Subject"] == "Verify your SBOM Analyzer account"
    assert message.is_multipart()
    assert "correlation-not-sent" not in message.as_string()


def test_smtp_failures_map_to_safe_codes(monkeypatch):
    class TimeoutSmtp(FakeSmtp):
        def send_message(self, message):
            raise TimeoutError

    monkeypatch.setattr(smtplib, "SMTP", TimeoutSmtp)
    result = SmtpVerificationEmailSender(_settings()).send_verification_email(
        recipient_email="recipient@example.test",
        recipient_name=None,
        verification_url="https://app.example.test/verify-email?token=token",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        correlation_id=None,
    )
    assert result.status == EmailDeliveryStatus.FAILED
    assert result.error_code == "SMTP_TIMEOUT"


def test_disabled_sender_never_claims_delivery():
    result = DisabledVerificationEmailSender().send_verification_email(
        recipient_email="recipient@example.test",
        recipient_name=None,
        verification_url="https://app.example.test/verify-email?token=token",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        correlation_id=None,
    )
    assert result.status == EmailDeliveryStatus.SKIPPED
    assert result.error_code == "DELIVERY_DISABLED"


def test_configuration_rejects_insecure_or_contradictory_smtp():
    with pytest.raises(ValidationError, match="cannot both"):
        _settings(smtp_use_tls=True, smtp_use_starttls=True)
    with pytest.raises(ValidationError, match="requires TLS"):
        _settings(smtp_use_tls=False, smtp_use_starttls=False)
    with pytest.raises(ValidationError, match="must use HTTPS"):
        _settings(email_verification_frontend_url="http://remote.example.test/verify")
    with pytest.raises(ValidationError, match="SMTP_PASSWORD"):
        _settings(smtp_password="")
    with pytest.raises(ValidationError, match="control characters"):
        _settings(email_from_name="SBOM Analyzer\nBcc: attacker@example.test")
    with pytest.raises(ValidationError, match="absolute URL"):
        _settings(
            email_verification_frontend_url=(
                "https://user:password@app.example.test/verify"
            )
        )


def test_smtp_secret_is_redacted_from_settings_representation():
    settings = _settings()
    assert "top-secret-password" not in repr(settings)
    assert settings.smtp_password.get_secret_value() == "top-secret-password"
