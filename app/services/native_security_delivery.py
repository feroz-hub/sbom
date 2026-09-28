"""Security-email delivery boundary; caller commits issuance before SMTP.

Durable mode uses the PostgreSQL encrypted outbox; Celery carries no token.
"""

from html import escape
from urllib.parse import urlsplit

from ..settings import get_settings
from . import email_sender
from .email_templates import render_password_reset_email


def deliver_reset(user, issued):
    s = get_settings()
    url = s.native_password_reset_frontend_url
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.query or parsed.fragment:
        return {"status": "FAILED", "error_code": "INVALID_RESET_URL"}
    rendered = render_password_reset_email(
        first_name=user.first_name,
        reset_url=f"{url}#token={issued.raw_token}",
        ttl_seconds=s.native_password_reset_ttl_seconds,
        support_email=s.platform_admin_contact_email or None,
    )
    return send_security_email(
        issued.email_snapshot,
        rendered.subject,
        rendered.text_body,
        f"<security-{issued.id}@sbom.invalid>",
        html_body=rendered.html_body,
    )


def send_security_email(recipient, subject, text, message_id=None, *, html_body=None):
    """Replaceable delivery adapter shared by activation, resend and reset.

    SMTP errors are reduced to fixed codes; never retry issuance here.
    """
    s = get_settings()
    try:
        message = email_sender.build_email(
            s,
            recipient_email=recipient,
            subject=subject,
            text_body=text,
            html_body=html_body or f"<p>{escape(text).replace(chr(10), '<br>')}</p>",
        )
        if message_id:
            message["Message-ID"] = message_id
        result = email_sender.get_email_sender().send_email(message)
        return {
            "status": str(result.status),
            "error_code": result.error_code,
            "provider": getattr(result, "provider", s.email_provider),
            "retryable": getattr(result, "retryable", True),
        }
    except Exception:
        return {"status": "FAILED", "error_code": "DELIVERY_FAILED"}
