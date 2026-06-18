"""Background enrichment helpers for trusted SBOM records."""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import SBOMSource
from .completeness_service import compute_and_save_completeness
from .lifecycle.vex_provider import process_embedded_vex_for_sbom
from .lifecycle_service import sync_lifecycle_for_sbom

log = logging.getLogger(__name__)


def mark_enrichment_pending(sbom: SBOMSource) -> None:
    """Mark a trusted SBOM as queued for post-upload enrichment."""

    sbom.enrichment_status = "pending"
    sbom.enrichment_started_at = None
    sbom.enrichment_completed_at = None
    sbom.enrichment_error = None


def run_post_upload_enrichment(sbom_id: int) -> None:
    """Run slow enrichment work after upload/import response completion.

    This function owns its DB session so it is safe to schedule from
    FastAPI ``BackgroundTasks``. Failures are persisted on the SBOM row and
    never affect the already-validated trusted SBOM.
    """

    from .lifecycle.types import now_iso

    db: Session = SessionLocal()
    try:
        sbom = db.get(SBOMSource, sbom_id)
        if sbom is None:
            return

        started = now_iso()
        sbom.enrichment_status = "running"
        sbom.enrichment_started_at = started
        sbom.enrichment_error = None
        db.commit()

        sync_lifecycle_for_sbom(db, sbom_id)
        process_embedded_vex_for_sbom(db, sbom_id)

        sbom = db.get(SBOMSource, sbom_id)
        if sbom is not None:
            compute_and_save_completeness(db, sbom)
            sbom.enrichment_status = "completed"
            sbom.enrichment_completed_at = now_iso()
            sbom.enrichment_error = None
            db.commit()
    except Exception as exc:  # pragma: no cover - defensive background path
        log.exception("Post-upload enrichment failed for sbom_id=%s", sbom_id)
        db.rollback()
        sbom = db.get(SBOMSource, sbom_id)
        if sbom is not None:
            sbom.enrichment_status = "failed"
            sbom.enrichment_error = str(exc)[:2000]
            sbom.enrichment_completed_at = now_iso()
            db.commit()
    finally:
        db.close()
