"""Provider-neutral verification email delivery and secure SMTP adapter."""

from __future__ import annotations

import smtplib
import ssl
from dataclasses import dataclass
from datetime import datetime
from email.message import EmailMessage
from enum import StrEnum
from typing import Protocol

from ..settings import Settings, get_settings
from .email_templates import render_verification_email


class EmailDeliveryStatus(StrEnum):
    PENDING = "PENDING"
    SENT = "SENT"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


@dataclass(frozen=True, slots=True)
class EmailDeliveryResult:
    status: EmailDeliveryStatus
    error_code: str | None = None


class VerificationEmailSender(Protocol):
    def send_verification_email(
        self,
        *,
        recipient_email: str,
        recipient_name: str | None,
        verification_url: str,
        expires_at: datetime,
        correlation_id: str | None,
    ) -> EmailDeliveryResult: ...


class DisabledVerificationEmailSender:
    def send_verification_email(
        self,
        *,
        recipient_email: str,
        recipient_name: str | None,
        verification_url: str,
        expires_at: datetime,
        correlation_id: str | None,
    ) -> EmailDeliveryResult:
        return EmailDeliveryResult(EmailDeliveryStatus.SKIPPED, "DELIVERY_DISABLED")


class SmtpVerificationEmailSender:
    """Per-message SMTP connection using platform certificate validation."""

    def __init__(self, settings: Settings):
        self.settings = settings

    def _message(
        self,
        *,
        recipient_email: str,
        recipient_name: str | None,
        verification_url: str,
        expires_at: datetime,
    ) -> EmailMessage:
        rendered = render_verification_email(
            recipient_name=recipient_name,
            verification_url=verification_url,
            expires_at=expires_at,
        )
        message = EmailMessage()
        message["Subject"] = rendered.subject
        message["From"] = (
            f"{self.settings.email_from_name} <{self.settings.email_from_address}>"
        )
        message["To"] = recipient_email
        message.set_content(rendered.text_body)
        message.add_alternative(rendered.html_body, subtype="html")
        return message

    def send_verification_email(
        self,
        *,
        recipient_email: str,
        recipient_name: str | None,
        verification_url: str,
        expires_at: datetime,
        correlation_id: str | None,
    ) -> EmailDeliveryResult:
        del correlation_id  # Deliberately not sent to or logged by SMTP.
        message = self._message(
            recipient_email=recipient_email,
            recipient_name=recipient_name,
            verification_url=verification_url,
            expires_at=expires_at,
        )
        settings = self.settings
        tls_context = ssl.create_default_context()
        try:
            if settings.smtp_use_tls:
                client: smtplib.SMTP = smtplib.SMTP_SSL(
                    settings.smtp_host,
                    settings.smtp_port,
                    timeout=settings.smtp_connect_timeout_seconds,
                    context=tls_context,
                )
            else:
                client = smtplib.SMTP(
                    settings.smtp_host,
                    settings.smtp_port,
                    timeout=settings.smtp_connect_timeout_seconds,
                )
            with client:
                if client.sock is not None:
                    client.sock.settimeout(settings.smtp_send_timeout_seconds)
                client.ehlo()
                if settings.smtp_use_starttls:
                    client.starttls(context=tls_context)
                    client.ehlo()
                if settings.smtp_username:
                    client.login(
                        settings.smtp_username,
                        settings.smtp_password.get_secret_value(),
                    )
                client.send_message(message)
            return EmailDeliveryResult(EmailDeliveryStatus.SENT)
        except smtplib.SMTPAuthenticationError:
            return EmailDeliveryResult(EmailDeliveryStatus.FAILED, "SMTP_AUTHENTICATION_FAILED")
        except (ssl.SSLError, smtplib.SMTPNotSupportedError):
            return EmailDeliveryResult(EmailDeliveryStatus.FAILED, "SMTP_TLS_FAILED")
        except TimeoutError:
            return EmailDeliveryResult(EmailDeliveryStatus.FAILED, "SMTP_TIMEOUT")
        except (OSError, smtplib.SMTPException):
            return EmailDeliveryResult(EmailDeliveryStatus.FAILED, "SMTP_UNAVAILABLE")


def get_verification_email_sender() -> VerificationEmailSender:
    settings = get_settings()
    if not settings.email_delivery_enabled:
        return DisabledVerificationEmailSender()
    return SmtpVerificationEmailSender(settings)
