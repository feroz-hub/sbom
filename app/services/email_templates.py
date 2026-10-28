"""Email-safe, shared layout for SBOM Analyzer account messages."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from html import escape


@dataclass(frozen=True, slots=True)
class RenderedEmail:
    subject: str
    text_body: str
    html_body: str


RenderedVerificationEmail = RenderedEmail


def _greeting(first_name: str | None) -> str:
    name = " ".join((first_name or "").split())
    return f"Hello {name}," if name else "Hello,"


def _expiry(seconds: int, *, hours: bool = False) -> str:
    if hours and seconds % 3600 == 0:
        count = seconds // 3600
        return f"{count} {'hour' if count == 1 else 'hours'}"
    if seconds % 60 == 0:
        count = seconds // 60
        return f"{count} {'minute' if count == 1 else 'minutes'}"
    return f"{seconds} seconds"


def render_email_layout(
    *,
    title: str,
    greeting: str,
    paragraphs: tuple[str, ...],
    button_label: str,
    action_url: str,
    expiry_notice: str,
    security_notes: tuple[str, ...],
    support_email: str | None = None,
) -> str:
    """Render text-only content inside one table-based HTML email layout."""
    safe_url = escape(action_url, quote=True)
    intro = "".join(
        f'<p style="margin:0 0 16px;color:#334155;font-size:16px;line-height:24px;">{escape(item)}</p>'
        for item in paragraphs
    )
    notes = "".join(
        f'<p style="margin:0 0 12px;color:#475569;font-size:15px;line-height:23px;">{escape(item)}</p>'
        for item in security_notes
    )
    help_line = (
        f'<p style="margin:12px 0 0;color:#64748b;font-size:13px;line-height:20px;">'
        f'Need help? <a href="mailto:{escape(support_email, quote=True)}" style="color:#0b4f8a;text-decoration:underline;">Contact support</a></p>'
        if support_email
        else ""
    )
    return f'''<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{escape(title)}</title></head>
<body style="margin:0;padding:0;background-color:#f3f6f9;color:#172b4d;font-family:Arial,Helvetica,sans-serif;">
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" bgcolor="#f3f6f9" style="width:100%;background-color:#f3f6f9;">
    <tr><td align="center" style="padding:24px 12px;">
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="600" bgcolor="#ffffff" style="width:100%;max-width:600px;background-color:#ffffff;border:1px solid #dce4ec;border-radius:8px;">
        <tr><td style="padding:28px 32px 24px;border-bottom:1px solid #e2e8f0;">
          <div style="color:#10365b;font-size:22px;font-weight:700;line-height:28px;">SBOM Analyzer</div>
          <div style="padding-top:4px;color:#527084;font-size:13px;line-height:19px;">Software Supply Chain Security</div>
        </td></tr>
        <tr><td style="padding:30px 32px 32px;">
          <h1 style="margin:0 0 24px;color:#10365b;font-size:25px;font-weight:700;line-height:32px;">{escape(title)}</h1>
          <p style="margin:0 0 16px;color:#172b4d;font-size:16px;line-height:24px;">{escape(greeting)}</p>
          {intro}
          <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:24px 0;">
            <tr><td bgcolor="#14558b" style="background-color:#14558b;border-radius:5px;text-align:center;">
              <a href="{safe_url}" style="display:inline-block;padding:14px 24px;color:#ffffff;font-size:16px;font-weight:700;line-height:20px;text-decoration:none;">{escape(button_label)}</a>
            </td></tr>
          </table>
          <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" bgcolor="#edf5fb" style="width:100%;margin:0 0 24px;background-color:#edf5fb;border-left:3px solid #16829a;">
            <tr><td style="padding:14px 16px;color:#173e5d;font-size:15px;line-height:23px;">{escape(expiry_notice)}</td></tr>
          </table>
          <p style="margin:0 0 8px;color:#334155;font-size:15px;line-height:23px;">If the button doesn't work, copy and paste this link into your browser:</p>
          <p style="margin:0 0 24px;font-size:14px;line-height:22px;word-wrap:break-word;word-break:break-all;overflow-wrap:anywhere;">
            <a href="{safe_url}" style="color:#0b4f8a;text-decoration:underline;word-wrap:break-word;word-break:break-all;overflow-wrap:anywhere;">{escape(action_url)}</a>
          </p>
          {notes}
        </td></tr>
        <tr><td style="padding:22px 32px;border-top:1px solid #e2e8f0;color:#64748b;font-size:13px;line-height:20px;">
          <strong style="color:#334155;">SBOM Analyzer</strong><br>Automated security notification<br>
          This message was sent automatically. Please do not reply to this email.
          {help_line}
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>'''


def _render_action_email(
    *,
    subject: str,
    title: str,
    first_name: str | None,
    paragraphs: tuple[str, ...],
    button_label: str,
    action_url: str,
    expiry_notice: str,
    security_notes: tuple[str, ...],
    support_email: str | None,
) -> RenderedEmail:
    greeting = _greeting(first_name)
    text = (
        f"{greeting}\n\n"
        + "\n\n".join(paragraphs)
        + f"\n\n{button_label}:\n{action_url}\n\n{expiry_notice}\n\n"
        + "\n".join(security_notes)
        + "\n\nSBOM Analyzer\n"
    )
    if support_email:
        text += f"Need help? {support_email}\n"
    html = render_email_layout(
        title=title,
        greeting=greeting,
        paragraphs=paragraphs,
        button_label=button_label,
        action_url=action_url,
        expiry_notice=expiry_notice,
        security_notes=security_notes,
        support_email=support_email,
    )
    return RenderedEmail(subject, text, html)


def render_activation_email(
    *,
    first_name: str | None,
    activation_url: str,
    ttl_seconds: int,
    support_email: str | None = None,
) -> RenderedEmail:
    return _render_action_email(
        subject="Activate your SBOM Analyzer account",
        title="Activate your account",
        first_name=first_name,
        paragraphs=(
            "Your SBOM Analyzer account has been created. Complete your account setup by creating your password.",
        ),
        button_label="Activate Account",
        action_url=activation_url,
        expiry_notice=f"This activation link expires in {_expiry(ttl_seconds, hours=True)}.",
        security_notes=("If you weren't expecting this account, you can safely ignore this email.",),
        support_email=support_email,
    )


def render_password_reset_email(
    *,
    first_name: str | None,
    reset_url: str,
    ttl_seconds: int,
    support_email: str | None = None,
) -> RenderedEmail:
    return _render_action_email(
        subject="Reset your SBOM Analyzer password",
        title="Reset your password",
        first_name=first_name,
        paragraphs=("We received a request to reset your SBOM Analyzer password.",),
        button_label="Reset Password",
        action_url=reset_url,
        expiry_notice=f"This password reset link expires in {_expiry(ttl_seconds)}.",
        security_notes=(
            "If you didn't request this password reset, no action is required. Your password will remain unchanged.",
            "For your security, never forward this email or share the reset link.",
        ),
        support_email=support_email,
    )


def render_verification_email(
    *,
    recipient_name: str | None,
    verification_url: str,
    expires_at: datetime,
) -> RenderedVerificationEmail:
    expiry = expires_at.strftime("%Y-%m-%d %H:%M UTC")
    return _render_action_email(
        subject="Verify your SBOM Analyzer account",
        title="Verify your email",
        first_name=recipient_name,
        paragraphs=(
            "Welcome to SBOM Analyzer. You are a new user and your account requires email verification before you can access the platform.",
            "A verification email has been sent to your registered email address. Please verify your account to continue.",
        ),
        button_label="Verify your account",
        action_url=verification_url,
        expiry_notice=f"This link expires at {expiry}.",
        security_notes=("If you did not request access, do not use this link.",),
        support_email=None,
    )
