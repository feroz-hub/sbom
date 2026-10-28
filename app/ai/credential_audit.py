"""Audit logging for credential / settings mutations.

Phase 2 §2.6 hard rule: every mutation writes a row to
``ai_credential_audit_log``. The row carries user, action, target, and
a short non-sensitive context string. **Never the credential payload.**

Why a dedicated table (vs piggy-backing on ``ai_usage_log``):
``ai_usage_log`` is high-volume operational telemetry — one row per AI
call. Credential mutations are rare and security-relevant. Mixing them
makes both harder to reason about; separating them lets ops set
different retention / alerting on each.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Literal

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from ..models import AiCredentialAuditLog

log = logging.getLogger("sbom.ai.credential_audit")

AuditAction = Literal[
    "credential.create",
    "credential.update",
    "credential.delete",
    "credential.test",
    "credential.set_default",
    "credential.set_fallback",
    "credential.toggle_enabled",
    "settings.update",
]

TargetKind = Literal["credential", "settings"]


def record(
    db: Session,
    *,
    user_id: str | None,
    action: AuditAction,
    target_kind: TargetKind,
    target_id: int | None = None,
    provider_name: str | None = None,
    detail: str | None = None,
    request=None,
    old_value=None,
    new_value=None,
    override_created: bool = False,
) -> None:
    """Append one audit row. Errors are swallowed (logged, not raised).

    The detail string is capped at 240 chars at the model level; this
    helper additionally redacts anything that looks like a credential
    payload (long alphanumeric runs starting with sk- / xai- / AIzaSy)
    as a defence-in-depth check against accidental leakage.
    """
    safe_detail = _redact(detail or "")[:240]
    try:
        from ..core.context import get_bound_context
        from ..services.audit_service import write_authorization_audit
        from ..services.configuration_scope import current_configuration_tenant

        tenant_id = current_configuration_tenant()
        event = (
            ("PLATFORM_AI_CONFIGURATION_TESTED" if action.endswith("test") else "PLATFORM_AI_CONFIGURATION_UPDATED")
            if tenant_id is None
            else (
                "TENANT_AI_OVERRIDE_TESTED"
                if action.endswith("test")
                else "TENANT_AI_OVERRIDE_CREATED"
                if override_created
                else "TENANT_AI_OVERRIDE_UPDATED"
            )
        )
        write_authorization_audit(
            db,
            action=event,
            outcome="FAILED" if action.endswith("test") and "success=False" in safe_detail else "SUCCESS",
            context=get_bound_context(),
            tenant_id=tenant_id,
            request=request,
            old_value=old_value,
            new_value=new_value
            or {"provider": provider_name, "operation": action, "scope": "TENANT" if tenant_id else "PLATFORM"},
        )
        db.add(
            AiCredentialAuditLog(
                tenant_id=tenant_id,
                user_id=user_id,
                action=action,
                target_kind=target_kind,
                target_id=target_id,
                provider_name=provider_name,
                detail=safe_detail,
                created_at=datetime.now(UTC).isoformat(),
            )
        )
        db.commit()
    except Exception as exc:  # noqa: BLE001
        log.warning("ai.audit.write_failed: action=%s error_type=%s", action, type(exc).__name__)
        try:
            db.rollback()
        except SQLAlchemyError:
            log.warning("ai.audit.rollback_failed: action=%s", action, exc_info=True)


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


import re

_REDACTORS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"AIzaSy[A-Za-z0-9_\-]{16,}"),
    re.compile(r"xai-[A-Za-z0-9_\-]{16,}"),
    # Generic catch-all: long base64-ish runs (>= 32 chars).
    re.compile(r"[A-Za-z0-9+/=]{32,}"),
]


def _redact(text: str) -> str:
    """Mask common credential shapes so accidental leakage is contained."""
    out = text
    for pat in _REDACTORS:
        out = pat.sub("[REDACTED]", out)
    return out


__all__ = ["AuditAction", "TargetKind", "record"]
