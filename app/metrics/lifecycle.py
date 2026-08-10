"""
Lifecycle metrics — EOL/EOS component aggregates.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import SBOMComponent
from ..services.lifecycle import summarize_components
from ._helpers import active_head_sbom_ids_subquery


def lifecycle_eol_total(db: Session) -> int:
    """Total components in active HEAD SBOMs that are End of Life (EOL)."""
    return lifecycle_summary(db)["eol_count"]


def lifecycle_eos_upcoming_total(db: Session) -> int:
    """Total components in active HEAD SBOMs approaching End of Support (EOS) in next 90 days."""
    head_ids = active_head_sbom_ids_subquery()
    today_str = datetime.now(UTC).date().isoformat()
    upcoming_str = (datetime.now(UTC).date() + timedelta(days=90)).isoformat()

    return (
        db.execute(
            select(func.count(SBOMComponent.id))
            .where(SBOMComponent.sbom_id.in_(head_ids))
            .where((SBOMComponent.is_duplicate.is_(False)) | (SBOMComponent.is_duplicate.is_(None)))
            .where(
                (func.lower(SBOMComponent.lifecycle_status) == "eos")
                | (
                    (SBOMComponent.eos_date.is_not(None))
                    & (SBOMComponent.eos_date >= today_str)
                    & (SBOMComponent.eos_date <= upcoming_str)
                )
            )
        ).scalar()
        or 0
    )


def lifecycle_unsupported_total(db: Session) -> int:
    """Total unmaintained / unsupported components in active HEAD SBOMs."""
    summary = lifecycle_summary(db)
    return summary["unsupported_count"] + summary["eos_count"] + summary["eof_count"]


def lifecycle_summary(db: Session) -> dict:
    """Lifecycle summary over active HEAD SBOM components."""
    head_ids = active_head_sbom_ids_subquery()
    components = (
        db.execute(
            select(SBOMComponent).where(
                SBOMComponent.sbom_id.in_(head_ids),
                (SBOMComponent.is_duplicate.is_(False)) | (SBOMComponent.is_duplicate.is_(None)),
            )
        )
        .scalars()
        .all()
    )
    return summarize_components(list(components))
