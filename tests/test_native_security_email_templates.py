"""Presentation-only coverage for multipart Native IAM messages."""

from __future__ import annotations

import re
from html import unescape
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from app.services import native_enrollment_service, native_security_delivery
from app.services.email_sender import EmailDeliveryResult, EmailDeliveryStatus, build_email
from app.services.email_templates import render_activation_email, render_password_reset_email


def test_activation_content_and_escaping() -> None:
    url = "https://app.example.test/activate-account#token=activation-secret"
    rendered = render_activation_email(
        first_name='<img src=x onerror="bad">',
        activation_url=url,
        ttl_seconds=18000,
    )
    assert rendered.subject == "Activate your SBOM Analyzer account"
    assert "Hello &lt;img" in rendered.html_body
    assert "<img" not in rendered.html_body.lower()
    assert "Hello <img" in rendered.text_body
    assert "Activate Account" in rendered.html_body
    assert "This activation link expires in 5 hours." in rendered.html_body
    assert "If you weren't expecting this account" in unescape(rendered.html_body)
    assert "Contact support" not in rendered.html_body
    assert rendered.text_body.count(url) == 1
    assert unescape(rendered.html_body).count(url) == 3  # Button, fallback href, fallback text.
    assert re.findall(r'href="([^"]+)"', rendered.html_body) == [url, url]
    assert "activation-secret" not in unescape(rendered.html_body).replace(url, "")


def test_reset_content_and_expiry() -> None:
    url = "https://app.example.test/reset-password#token=reset-secret"
    rendered = render_password_reset_email(first_name="Viewer", reset_url=url, ttl_seconds=3600)
    assert rendered.subject == "Reset your SBOM Analyzer password"
    assert "Hello Viewer," in rendered.text_body
    assert "Reset Password" in rendered.html_body
    assert "This password reset link expires in 60 minutes." in rendered.html_body
    assert "never forward this email or share the reset link" in rendered.html_body
    assert "Your password will remain unchanged" in rendered.text_body
    assert rendered.text_body.count(url) == 1
    assert unescape(rendered.html_body).count(url) == 3
    assert re.findall(r'href="([^"]+)"', rendered.html_body) == [url, url]
    assert "reset-secret" not in unescape(rendered.html_body).replace(url, "")


def test_blank_name_long_url_and_no_tracking_resources() -> None:
    url = "https://app.example.test/reset-password#token=" + "x" * 300
    rendered = render_password_reset_email(first_name="  \n ", reset_url=url, ttl_seconds=5400)
    assert "Hello," in rendered.text_body
    assert "Hello," in rendered.html_body
    assert "90 minutes" in rendered.html_body
    assert "word-break:break-all" in rendered.html_body
    assert url in unescape(rendered.html_body)
    html = rendered.html_body.lower()
    assert "<script" not in html and "<img" not in html
    assert "http://" not in html
    assert "src=" not in html


def test_multipart_and_optional_support_link() -> None:
    rendered = render_activation_email(
        first_name="Multi",
        activation_url="https://app.example.test/activate#token=single-use",
        ttl_seconds=18000,
        support_email="support@example.test",
    )
    message = build_email(
        SimpleNamespace(email_from_name="SBOM Analyzer", email_from_address="no-reply@example.test"),
        recipient_email="multi@example.test",
        subject=rendered.subject,
        text_body=rendered.text_body,
        html_body=rendered.html_body,
    )
    assert message.is_multipart()
    assert message.get_body(preferencelist=("plain",)).get_content().startswith("Hello Multi,")
    assert "<html" in message.get_body(preferencelist=("html",)).get_content()
    assert 'href="mailto:support@example.test"' in rendered.html_body


@pytest.mark.parametrize("purpose", ["activation", "reset"])
def test_existing_delivery_path_uses_rendered_multipart(purpose: str, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = SimpleNamespace(
        native_activation_frontend_url="https://app.example.test/activate-account",
        native_password_reset_frontend_url="https://app.example.test/reset-password",
        native_account_activation_ttl_seconds=18000,
        native_password_reset_ttl_seconds=3600,
        platform_admin_contact_email="",
        email_from_name="SBOM Analyzer",
        email_from_address="no-reply@example.test",
        email_provider="smtp",
    )
    monkeypatch.setattr(native_enrollment_service, "get_settings", lambda: settings)
    monkeypatch.setattr(native_security_delivery, "get_settings", lambda: settings)
    sender = Mock()
    sender.send_email.return_value = EmailDeliveryResult(EmailDeliveryStatus.SENT)
    monkeypatch.setattr(native_security_delivery.email_sender, "get_email_sender", lambda: sender)
    user = SimpleNamespace(first_name="Multi")
    issued = SimpleNamespace(id=42, raw_token="outbound-only", email_snapshot="multi@example.test")
    result = (
        native_enrollment_service.deliver_activation(user, issued)
        if purpose == "activation"
        else native_security_delivery.deliver_reset(user, issued)
    )
    assert result["status"] == "SENT"
    message = sender.send_email.call_args.args[0]
    assert message["To"] == "multi@example.test"
    assert message["Message-ID"] == "<security-42@sbom.invalid>"
    assert message.is_multipart()
    plain = message.get_body(preferencelist=("plain",)).get_content()
    html = message.get_body(preferencelist=("html",)).get_content()
    expected_url = (
        settings.native_activation_frontend_url
        if purpose == "activation"
        else settings.native_password_reset_frontend_url
    ) + "#token=outbound-only"
    assert expected_url in plain and expected_url in unescape(html)
    assert "outbound-only" not in plain.replace(expected_url, "")
    assert "outbound-only" not in unescape(html).replace(expected_url, "")
