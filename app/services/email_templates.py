"""Verification email rendering with plain-text and HTML alternatives."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from html import escape


@dataclass(frozen=True, slots=True)
class RenderedVerificationEmail:
    subject: str
    text_body: str
    html_body: str


def render_verification_email(
    *,
    recipient_name: str | None,
    verification_url: str,
    expires_at: datetime,
) -> RenderedVerificationEmail:
    name = (recipient_name or "there").strip() or "there"
    expiry = expires_at.strftime("%Y-%m-%d %H:%M UTC")
    subject = "Verify your SBOM Analyzer account"
    text = (
        f"Hello {name},\n\n"
        "Welcome to SBOM Analyzer. You are a new user and your account requires "
        "email verification before you can access the platform.\n\n"
        "A verification email has been sent to your registered email address. "
        "Please verify your account to continue.\n\n"
        f"Verify your account: {verification_url}\n\n"
        f"This link expires at {expiry}.\n\n"
        "If you did not request access, do not use this link. Contact your platform "
        "administrator if you need assistance.\n"
    )
    safe_name = escape(name)
    safe_url = escape(verification_url, quote=True)
    safe_expiry = escape(expiry)
    html = f"""<!doctype html>
<html lang="en">
  <body style="font-family:Arial,sans-serif;color:#172033;line-height:1.5">
    <h1 style="font-size:22px">SBOM Analyzer</h1>
    <p>Hello {safe_name},</p>
    <p>Welcome to SBOM Analyzer. You are a new user and your account requires
       email verification before you can access the platform.</p>
    <p>A verification email has been sent to your registered email address.
       Please verify your account to continue.</p>
    <p><a href="{safe_url}" style="display:inline-block;padding:12px 18px;
       background:#2457d6;color:#fff;text-decoration:none;border-radius:4px">
       Verify your account</a></p>
    <p>This link expires at {safe_expiry}.</p>
    <p>If you did not request access, do not use this link. Contact your platform
       administrator if you need assistance.</p>
  </body>
</html>"""
    return RenderedVerificationEmail(subject=subject, text_body=text, html_body=html)
