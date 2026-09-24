"""Append-only audit for manual VEX actions (VEX-AUD-001, spec section 40).

One writer for every human action on a context — decisions, assignments and
mapping resolutions — so a context's history is a single ordered query rather
than three shapes stitched together at read time.

Nothing here updates or deletes an audit row. Corrections are new rows.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from ...models import VexInvestigation, VexOverrideAudit
from ..lifecycle.types import now_iso


def record_action(
    db: Session,
    investigation: VexInvestigation,
    *,
    action: str,
    reason: str,
    changed_by: str | None,
    previous_status: str | None = None,
    new_status: str | None = None,
    evidence_url: str | None = None,
    old_value: dict[str, Any] | None = None,
    new_value: dict[str, Any] | None = None,
) -> VexOverrideAudit:
    """Append one audit row for an action on ``investigation``.

    Flushes but does not commit: the audit row must land in the same
    transaction as the change it describes, or a rollback would leave a
    record of something that never happened.
    """
    entry = VexOverrideAudit(
        tenant_id=investigation.tenant_id,
        sbom_id=investigation.sbom_id,
        component_id=investigation.component_id,
        investigation_id=investigation.id,
        vulnerability_id=investigation.canonical_vulnerability_id,
        action=action,
        previous_status=previous_status,
        new_status=new_status,
        old_value_json=old_value,
        new_value_json=new_value,
        reason=reason,
        evidence_url=evidence_url,
        changed_by=changed_by,
        changed_at=now_iso(),
    )
    db.add(entry)
    db.flush()
    return entry


def record_assignment(
    db: Session,
    investigation: VexInvestigation,
    *,
    previous_assignee: str | None,
    new_assignee: str | None,
    reason: str,
    changed_by: str | None,
) -> VexOverrideAudit:
    """Audit an ownership change (spec section 27: Reviewer/Owner)."""
    return record_action(
        db,
        investigation,
        action=VexOverrideAudit.ACTION_ASSIGNMENT,
        reason=reason,
        changed_by=changed_by,
        previous_status=investigation.effective_status,
        new_status=investigation.effective_status,
        old_value={"assigned_to": previous_assignee},
        new_value={"assigned_to": new_assignee},
    )


def record_mapping_resolution(
    db: Session,
    investigation: VexInvestigation,
    *,
    previous_component_id: int | None,
    new_component_id: int,
    reason: str,
    changed_by: str | None,
) -> VexOverrideAudit:
    """Audit an analyst binding an unresolved assertion to a component.

    This is the one audited action that can begin with ``component_id`` NULL,
    which is why the column is nullable (VEX-MAP-001).
    """
    return record_action(
        db,
        investigation,
        action=VexOverrideAudit.ACTION_MAPPING_RESOLUTION,
        reason=reason,
        changed_by=changed_by,
        previous_status=investigation.effective_status,
        new_status=investigation.effective_status,
        old_value={"component_id": previous_component_id},
        new_value={"component_id": new_component_id},
    )


__all__ = ["record_action", "record_assignment", "record_mapping_resolution"]
