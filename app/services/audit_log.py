"""Generic audit-log writer for lifecycle events.

Distinct from ``app/ai/credential_audit.py`` (which is the
security-specific surface). This helper writes one row per
soft-delete / permanent-delete / restore event on user-owned data.

Errors are swallowed (logged, not raised) — the design rule is that an
audit-log write failure must never block the user's primary action.
A missing row is tolerable; a 500 because telemetry-adjacent code
threw is not.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy.orm import Session

from ..models import AuditLog

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
) -> None:
    """Append one audit row. Errors are swallowed."""
    try:
        db.add(
            AuditLog(
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
        except Exception:
            pass


__all__ = ["AuditAction", "TargetKind", "record"]
