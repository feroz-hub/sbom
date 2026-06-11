"""
Health metrics — SBOM completeness, missing metadata, and outdated components.
"""

from __future__ import annotations

import json

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import SBOMComponent, SBOMSource
from ._helpers import active_head_sbom_ids_subquery


def health_completeness_average(db: Session) -> float:
    """Average completeness score across active HEAD SBOMs."""
    head_ids = active_head_sbom_ids_subquery()
    score_sum = db.execute(
        select(func.sum(SBOMSource.completeness_score)).where(SBOMSource.id.in_(head_ids))
    ).scalar()
    
    count = db.execute(
        select(func.count(SBOMSource.id)).where(SBOMSource.id.in_(head_ids))
    ).scalar() or 0
    
    if count == 0 or score_sum is None:
        return 100.0
    return round(float(score_sum) / count, 1)


def health_missing_metadata_count(db: Session) -> int:
    """Total missing metadata items across active HEAD SBOMs."""
    head_ids = active_head_sbom_ids_subquery()
    reports = db.execute(
        select(SBOMSource.completeness_report).where(SBOMSource.id.in_(head_ids))
    ).scalars().all()
    
    total = 0
    for report_raw in reports:
        if not report_raw:
            continue
        try:
            report = json.loads(report_raw) if isinstance(report_raw, str) else report_raw
            total += sum(
                len(item.get("missing") or item.get("missing_fields") or [])
                for item in report.get("missing_fields") or report.get("components") or []
            )
            total += len(report.get("document_warnings") or [])
        except Exception:
            pass
    return total


def health_outdated_components_count(db: Session) -> int:
    """Total components in active HEAD SBOMs that are EOL or deprecated or unmaintained."""
    head_ids = active_head_sbom_ids_subquery()
    return (
        db.execute(
            select(func.count(SBOMComponent.id))
            .where(SBOMComponent.sbom_id.in_(head_ids))
            .where(
                (SBOMComponent.lifecycle_status == "eol") |
                (SBOMComponent.is_deprecated.is_(True)) |
                (SBOMComponent.maintenance_status == "unmaintained")
            )
        ).scalar()
        or 0
    )
