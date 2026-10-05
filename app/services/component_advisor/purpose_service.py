"""Load and curate component purpose metadata (FR-SCA-009).

Rows in ``component_purpose_metadata`` are platform-curated (NULL tenant) or
tenant overrides. Reads always return the tenant's rows plus platform rows —
never another tenant's. Writes are tenant rows only, use optimistic
concurrency (``row_version``) and are audited with old and new values.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ...models import ComponentPurposeMetadata
from ..audit_service import write_audit_log
from .purpose import PurposeRecord, PurposeSource, validate_purpose_payload


class PurposeConflict(RuntimeError):
    def __init__(self, current_row_version: int):
        super().__init__("Purpose metadata changed since it was read")
        self.current_row_version = current_row_version


def _record(row: ComponentPurposeMetadata) -> PurposeRecord:
    return PurposeRecord(
        source=PurposeSource(row.source),
        tenant_id=row.tenant_id,
        purpose=row.purpose,
        primary_use_case=row.primary_use_case,
        category=row.category,
        confidence=row.confidence,
        provenance=dict(row.provenance_json or {}),
        record_id=row.id,
    )


def purpose_records(db: Session, *, tenant_id: int, family_keys: Iterable[str] | None = None) -> dict[str, list[PurposeRecord]]:
    """``{family_key: [records]}`` visible to ``tenant_id`` (own + platform)."""
    statement = select(ComponentPurposeMetadata).where(
        or_(ComponentPurposeMetadata.tenant_id == tenant_id, ComponentPurposeMetadata.tenant_id.is_(None))
    )
    if family_keys is not None:
        keys = sorted({key for key in family_keys if key})
        if not keys:
            return {}
        statement = statement.where(ComponentPurposeMetadata.family_key.in_(keys))
    out: dict[str, list[PurposeRecord]] = defaultdict(list)
    for row in db.scalars(statement).all():
        out[row.family_key].append(_record(row))
    return dict(out)


def purpose_marker(db: Session, *, tenant_id: int) -> tuple:
    """Cache-invalidation marker for the purpose rows a tenant can see."""
    from sqlalchemy import func

    row = db.execute(
        select(
            func.count(ComponentPurposeMetadata.id),
            func.max(ComponentPurposeMetadata.updated_at),
            func.coalesce(func.sum(ComponentPurposeMetadata.row_version), 0),
        ).where(or_(ComponentPurposeMetadata.tenant_id == tenant_id, ComponentPurposeMetadata.tenant_id.is_(None)))
    ).one()
    return tuple(str(value) for value in row)


def save_tenant_purpose(
    db: Session,
    *,
    context,
    family_key: str,
    payload: dict[str, Any],
    expected_row_version: int,
    request=None,
) -> dict[str, Any]:
    """Create or replace the tenant's row for ``(family_key, source)``. Does not commit."""
    tenant_id = context.tenant_id
    values = validate_purpose_payload(payload)
    source = values.pop("source")
    row = db.scalars(
        select(ComponentPurposeMetadata)
        .where(
            ComponentPurposeMetadata.tenant_id == tenant_id,
            ComponentPurposeMetadata.family_key == family_key,
            ComponentPurposeMetadata.source == source.value,
        )
        .with_for_update()
    ).first()
    current = row.row_version if row else 0
    if current != expected_row_version:
        raise PurposeConflict(current)
    now = datetime.now(UTC)
    actor = context.actor_label()
    old = None
    if row is None:
        row = ComponentPurposeMetadata(
            tenant_id=tenant_id, family_key=family_key, source=source.value, created_at=now, created_by=actor,
            row_version=1,
        )
        db.add(row)
    else:
        old = _snapshot(row)
        row.row_version = current + 1
    row.purpose = values["purpose"]
    row.primary_use_case = values["primary_use_case"]
    row.category = values["category"]
    row.confidence = values["confidence"]
    row.provenance_json = {**(values["provenance"] or {}), "recorded_by": actor}
    row.updated_at = now
    row.updated_by = actor
    db.flush()
    new = _snapshot(row)
    write_audit_log(
        db, context, "component_advisor.purpose.saved", entity_type="component_purpose_metadata",
        entity_id=row.id, old_value=old, new_value=new, request=request,
        detail=f"{source.value} purpose for {family_key}"[:240],
    )
    return new


def _snapshot(row: ComponentPurposeMetadata) -> dict[str, Any]:
    return {
        "id": row.id,
        "family_key": row.family_key,
        "source": row.source,
        "functional_description": row.purpose,
        "primary_use_case": row.primary_use_case,
        "technology_category": row.category,
        "confidence": row.confidence,
        "provenance": dict(row.provenance_json or {}),
        "row_version": row.row_version,
        "scope": "PLATFORM" if row.tenant_id is None else "TENANT",
    }


def tenant_purpose_rows(db: Session, *, tenant_id: int, family_key: str) -> list[dict[str, Any]]:
    rows = db.scalars(
        select(ComponentPurposeMetadata).where(
            ComponentPurposeMetadata.family_key == family_key,
            or_(ComponentPurposeMetadata.tenant_id == tenant_id, ComponentPurposeMetadata.tenant_id.is_(None)),
        )
    ).all()
    return [_snapshot(row) for row in rows]


__all__ = [
    "PurposeConflict",
    "purpose_marker",
    "purpose_records",
    "save_tenant_purpose",
    "tenant_purpose_rows",
]
