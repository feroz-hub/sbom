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
    SUPPRESSED = "SUPPRESSED"


@dataclass(frozen=True, slots=True)
class EmailDeliveryResult:
    status: EmailDeliveryStatus
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class EmailAttachment:
    filename: str
    media_type: str
    content: bytes


def build_email(settings: Settings, *, recipient_email: str, subject: str,
                text_body: str, html_body: str, attachments=()) -> EmailMessage:
    """Shared MIME construction. No request identifiers, tokens or arbitrary headers."""
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = f"{settings.email_from_name} <{settings.email_from_address}>"
    message["To"] = recipient_email
    message.set_content(text_body)
    message.add_alternative(html_body, subtype="html")
    for attachment in attachments:
        main, sub = attachment.media_type.split("/", 1)
        message.add_attachment(attachment.content, maintype=main, subtype=sub, filename=attachment.filename)
    return message


class EmailSender(Protocol):
    def send_email(self, message: EmailMessage) -> EmailDeliveryResult: ...


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
    def send_email(self, message: EmailMessage) -> EmailDeliveryResult:
        return EmailDeliveryResult(EmailDeliveryStatus.SKIPPED, "DELIVERY_DISABLED")

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
        return build_email(self.settings, recipient_email=recipient_email, subject=rendered.subject,
                           text_body=rendered.text_body, html_body=rendered.html_body)

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
        return self._send(message, distinguish_unknown=False)

    def send_email(self, message: EmailMessage) -> EmailDeliveryResult:
        return self._send(message, distinguish_unknown=True)

    def _send(self, message: EmailMessage, *, distinguish_unknown: bool) -> EmailDeliveryResult:
        settings = self.settings
        tls_context = ssl.create_default_context()
        dispatching = False
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
                dispatching = True
                client.send_message(message)
            return EmailDeliveryResult(EmailDeliveryStatus.SENT)
        except smtplib.SMTPAuthenticationError:
            return EmailDeliveryResult(EmailDeliveryStatus.FAILED, "SMTP_AUTHENTICATION_FAILED")
        except (ssl.SSLError, smtplib.SMTPNotSupportedError):
            return EmailDeliveryResult(EmailDeliveryStatus.FAILED, "SMTP_TLS_FAILED")
        except smtplib.SMTPRecipientsRefused:
            return EmailDeliveryResult(EmailDeliveryStatus.FAILED, "SMTP_RECIPIENT_REJECTED")
        except smtplib.SMTPDataError as exc:
            return EmailDeliveryResult(EmailDeliveryStatus.FAILED,
                                       "SMTP_TEMPORARY_REJECTION" if exc.smtp_code < 500 else "SMTP_MESSAGE_REJECTED")
        except TimeoutError:
            if distinguish_unknown and dispatching:
                return EmailDeliveryResult(EmailDeliveryStatus.FAILED, "SMTP_OUTCOME_UNKNOWN")
            return EmailDeliveryResult(EmailDeliveryStatus.FAILED, "SMTP_TIMEOUT")
        except (OSError, smtplib.SMTPException):
            if distinguish_unknown and dispatching:
                return EmailDeliveryResult(EmailDeliveryStatus.FAILED, "SMTP_OUTCOME_UNKNOWN")
            return EmailDeliveryResult(EmailDeliveryStatus.FAILED, "SMTP_UNAVAILABLE")


def get_verification_email_sender() -> VerificationEmailSender:
    settings = get_settings()
    if not settings.email_delivery_enabled:
        return DisabledVerificationEmailSender()
    return SmtpVerificationEmailSender(settings)


def get_email_sender() -> EmailSender:
    settings = get_settings()
    if not settings.email_delivery_enabled:
        return DisabledVerificationEmailSender()
    return SmtpVerificationEmailSender(settings)
