"""Security-email delivery boundary; caller commits issuance before SMTP.

Durable mode uses the PostgreSQL encrypted outbox; Celery carries no token.
"""

from html import escape
from urllib.parse import urlsplit

from ..settings import get_settings
from . import email_sender


def deliver_reset(user, issued):
    s = get_settings()
    url = s.native_password_reset_frontend_url
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.query or parsed.fragment:
        return {"status": "FAILED", "error_code": "INVALID_RESET_URL"}
    text = (
        f"SBOM Analyser password reset\n{url}#token={issued.raw_token}\n"
        f"This link is valid for {s.native_password_reset_ttl_seconds // 60} minutes. "
        "If you did not request this, ignore this email.\n"
        f"Support: {s.platform_admin_contact_email or 'Contact your administrator'}"
    )
    return send_security_email(
        issued.email_snapshot, "Reset your SBOM Analyser password", text, f"<security-{issued.id}@sbom.invalid>"
    )


def send_security_email(recipient, subject, text, message_id=None):
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
            html_body=f"<p>{escape(text).replace(chr(10), '<br>')}</p>",
        )
        if message_id:
            message["Message-ID"] = message_id
        result = email_sender.get_email_sender().send_email(message)
        return {"status": str(result.status), "error_code": result.error_code}
    except Exception:
        return {"status": "FAILED", "error_code": "DELIVERY_FAILED"}
