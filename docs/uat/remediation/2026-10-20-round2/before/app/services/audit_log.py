"""Generic audit-log writer for lifecycle events.

Distinct from ``app/ai/credential_audit.py`` (security-specific surface).
Delegates to ``audit_service.write_audit_log`` for new rows; commits here
for backward compatibility with existing callers.
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .audit_service import write_audit_log

log = logging.getLogger("sbom.audit")


# Action vocabulary. Keep this list closed — every new lifecycle event
# adds a literal here so callers can't drift into typos.
AuditAction = Literal[
    "project.soft_delete",
    "project.permanent_delete",
    "project.restore",
    "sbom.soft_delete",
    "sbom.permanent_delete",
    "sbom.restore",
    "sbom.update",
    "schedule.soft_delete",
    "schedule.permanent_delete",
    "run.soft_delete",
    "run.restore",
]

TargetKind = Literal["project", "sbom", "schedule", "run"]


def record(
    db: Session,
    *,
    user_id: str | None,
    action: AuditAction,
    target_kind: TargetKind,
    target_id: int,
    detail: str | None = None,
    metadata: dict[str, Any] | None = None,
    tenant_id: int | None = None,
) -> None:
    """Append one audit row. Errors are swallowed. Commits for legacy callers."""
    try:
        from ..core.context import get_bound_context

        context = get_bound_context()
        write_audit_log(
            db,
            context,
            action,
            entity_type=target_kind,
            entity_id=target_id,
            new_value=metadata,
            metadata_json=metadata,
            detail=detail,
            target_kind=target_kind,
            target_id=target_id,
        )
        if context is None and tenant_id is not None:
            # Legacy path without bound context
            from datetime import UTC, datetime

            from ..models import AuditLog

            db.add(
                AuditLog(
                    tenant_id=tenant_id,
                    user_id=user_id,
                    action=action,
                    target_kind=target_kind,
                    target_id=target_id,
                    detail=(detail or "")[:240] or None,
                    metadata_json=metadata,
                    created_at=datetime.now(UTC).isoformat(),
                )
            )
        db.commit()
    except Exception as exc:  # noqa: BLE001
        log.warning("audit.write_failed: action=%s target_id=%s err=%s", action, target_id, exc)
        try:
            db.rollback()
        except SQLAlchemyError:
            log.warning("audit.rollback_failed: action=%s target_id=%s", action, target_id, exc_info=True)


__all__ = ["AuditAction", "TargetKind", "record"]
