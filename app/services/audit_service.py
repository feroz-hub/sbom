"""Unified audit-log writer for IAM-aware actions.

Does not commit — the caller controls the transaction boundary.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from ..core.context import CurrentContext
from ..models import AuditLog, AuthorizationAuditLog

log = logging.getLogger("sbom.audit")


def _correlation_id(request: Request | None) -> str | None:
    if request is None:
        return None
    return (request.headers.get("x-request-id") or request.headers.get("x-correlation-id") or "")[:128] or None


def _client_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    if request.client:
        return request.client.host[:64]
    return None


def write_audit_log(
    db: Session,
    context: CurrentContext | None,
    action: str,
    *,
    entity_type: str | None = None,
    entity_id: str | int | None = None,
    old_value: dict[str, Any] | None = None,
    new_value: dict[str, Any] | None = None,
    request: Request | None = None,
    detail: str | None = None,
    target_kind: str | None = None,
    target_id: int | None = None,
    metadata_json: dict[str, Any] | None = None,
) -> None:
    """Append one audit row without committing."""
    try:
        tenant_id = context.tenant_id if context else None
        user_str = context.external_user_id if context else None
        user_ref = context.user_id if context else None
        entity_id_str = str(entity_id) if entity_id is not None else None
        target_id_val = target_id
        if target_id_val is None and entity_id is not None:
            try:
                target_id_val = int(entity_id)
            except (TypeError, ValueError):
                target_id_val = None
        db.add(
            AuditLog(
                tenant_id=tenant_id or 1,
                user_id=user_str,
                user_ref_id=user_ref,
                action=action,
                target_kind=target_kind or entity_type or "unknown",
                target_id=target_id_val,
                entity_type=entity_type,
                entity_id=entity_id_str,
                old_value=old_value,
                new_value=new_value,
                detail=(detail or "")[:240] or None,
                metadata_json=metadata_json or new_value,
                ip_address=_client_ip(request),
                user_agent=(request.headers.get("user-agent", "")[:512] if request else None),
                created_at=datetime.now(UTC).isoformat(),
            )
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("audit.write_failed: action=%s err=%s", action, exc)


def write_authorization_audit(
    db: Session,
    *,
    action: str,
    outcome: str = "SUCCESS",
    context: CurrentContext | None = None,
    actor_user_id: int | None = None,
    target_user_id: int | None = None,
    target_membership_id: int | None = None,
    tenant_id: int | None = None,
    old_value: dict[str, Any] | None = None,
    new_value: dict[str, Any] | None = None,
    request: Request | None = None,
    correlation_id: str | None = None,
    detail: str | None = None,
) -> None:
    """Write structured authorization metadata without credentials or token claims."""
    db.add(
        AuthorizationAuditLog(
            actor_user_id=actor_user_id if actor_user_id is not None else (context.user_id if context else None),
            target_user_id=target_user_id,
            target_membership_id=target_membership_id,
            tenant_id=tenant_id if tenant_id is not None else (context.tenant_id if context else None),
            action=action,
            outcome=outcome,
            old_value=old_value,
            new_value=new_value,
            correlation_id=(correlation_id or _correlation_id(request) or "")[:128] or None,
            detail=(detail or "")[:240] or None,
            created_at=datetime.now(UTC),
        )
    )
