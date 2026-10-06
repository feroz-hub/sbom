"""Append-only hash-bound snapshots in existing tenant-owned workspace history."""

import logging

from app.core.context import get_bound_context
from app.logger import log_context, log_event
from app.models import SBOMValidationSession, SBOMValidationSessionEvent
from app.services import audit_service
from app.services.tenant_access import get_sbom_for_tenant
from app.services.validation_repair_service import ValidationRepairService, session_repair_text, session_upload_metadata
from app.settings import get_settings
from fastapi import HTTPException
from sqlalchemy import select

from .engine import QualityEngine
from .policy import QualityPolicy

log = logging.getLogger(__name__)
EVENT = "SBOM_QUALITY_CALCULATED"


def persist_snapshot(
    db, session, raw, *, role="DRAFT", job_id=None, sbom_id=None, assessment=None, report=None, context=None
):
    if not get_settings().sbom_quality_enabled:
        return None
    context = context or get_bound_context()
    from hashlib import sha256

    artifact_hash = sha256(raw).hexdigest()
    if assessment and assessment["artifact_hash"] != artifact_hash:
        raise HTTPException(409, "Quality assessment artifact hash mismatch")
    if assessment and assessment.get("configuration"):
        try:
            bound_policy = QualityPolicy.model_validate(assessment["configuration"])
        except ValueError as exc:
            raise HTTPException(409, "Quality assessment configuration binding mismatch") from exc
        if bound_policy.fingerprint() != assessment["configuration_hash"]:
            raise HTTPException(409, "Quality assessment configuration binding mismatch")
    configuration_hash = assessment["configuration_hash"] if assessment else QualityPolicy.configured().fingerprint()
    history = db.scalars(
        select(SBOMValidationSessionEvent).where(
            SBOMValidationSessionEvent.session_id == session.id,
            SBOMValidationSessionEvent.tenant_id == session.tenant_id,
            SBOMValidationSessionEvent.event_type == EVENT,
        )
    ).all()
    for event in history:
        meta = event.metadata_json or {}
        if (
            meta.get("artifact_role") == role
            and meta.get("repair_job_id") == job_id
            and meta.get("sbom_id") == sbom_id
            and meta.get("artifact_hash") == artifact_hash
            and meta.get("engine_version") == "2.0.0"
            and meta.get("configuration_hash") == configuration_hash
        ):
            retained = meta.get("assessment", {})
            if (
                retained.get("artifact_hash") != artifact_hash
                or retained.get("configuration_hash") != configuration_hash
                or retained.get("engine_version") != meta["engine_version"]
            ):
                raise HTTPException(409, "Retained quality assessment binding mismatch")
            return retained
    scope = session_upload_metadata(db, session)
    score = assessment or QualityEngine(repair_enabled=get_settings().sbom_auto_repair_enabled).calculate(
        raw,
        report,
        validation_options={
            "strict_ntia": bool(scope.get("strict_ntia")),
            "verify_signature": bool(scope.get("verify_signature")),
        },
    ).model_dump(mode="json")
    if artifact_hash != score["artifact_hash"]:
        raise HTTPException(409, "Quality assessment artifact hash mismatch")
    workspace = ValidationRepairService(db, tenant_id=session.tenant_id)
    workspace._record_event(
        session,
        EVENT,
        actor_user_id=context.actor_label() if context else session.user_id,
        after_hash=score["artifact_hash"],
        summary="Advisory SBOM quality calculated.",
        metadata={
            "artifact_role": role,
            "repair_job_id": job_id,
            "sbom_id": sbom_id,
            "artifact_hash": score["artifact_hash"],
            "engine_version": score["engine_version"],
            "configuration_hash": score["configuration_hash"],
            "assessment": score,
        },
    )
    fields = {
        "session_id": session.id,
        "repair_job_id": job_id,
        "sbom_id": sbom_id,
        "artifact_hash": score["artifact_hash"],
        "overall_score": score["overall_score"],
        "engine_version": score["engine_version"],
    }
    with log_context(tenant_id=session.tenant_id, user_id=context.user_id if context else session.user_id):
        log_event(log, "SBOM_QUALITY_RECALCULATED" if history else EVENT, **fields)
    if context:
        audit_service.write_audit_log(
            db, context, EVENT, entity_type="sbom_quality", entity_id=session.id, new_value=fields
        )
    return score


class QualityService:
    def __init__(self, db, context):
        self.db, self.context = db, context

    def session_quality(self, session_id):
        workspace = ValidationRepairService(self.db, tenant_id=self.context.tenant_id)
        session = workspace.get_session(session_id)
        if not get_settings().sbom_quality_enabled:
            return {"enabled": False, "assessment": None, "history": []}
        raw = session_repair_text(session).encode()
        score = persist_snapshot(self.db, session, raw, context=self.context)
        self.db.flush()
        history = self.db.scalars(
            select(SBOMValidationSessionEvent)
            .where(
                SBOMValidationSessionEvent.session_id == session_id,
                SBOMValidationSessionEvent.tenant_id == self.context.tenant_id,
                SBOMValidationSessionEvent.event_type == EVENT,
            )
            .order_by(SBOMValidationSessionEvent.id)
        ).all()
        result = {
            "enabled": True,
            "assessment": score,
            "history": [{"id": e.id, "created_at": e.timestamp, **e.metadata_json} for e in history],
        }
        self.db.commit()
        return result

    def sbom_quality(self, sbom_id):
        sbom = get_sbom_for_tenant(self.db, sbom_id, self.context.tenant_id)
        if not sbom:
            raise HTTPException(404, "SBOM not found")
        if not get_settings().sbom_quality_enabled:
            return {"enabled": False, "assessment": None}
        session = self.db.scalar(
            select(SBOMValidationSession)
            .where(
                SBOMValidationSession.imported_sbom_id == sbom_id,
                SBOMValidationSession.tenant_id == self.context.tenant_id,
            )
            .order_by(SBOMValidationSession.created_at.desc())
            .with_for_update()
        )
        if session is None:
            # Reuse the established workspace creation path for historical SBOMs.
            from app.services.repair.workspace_backfill_service import WorkspaceBackfillService

            workspace = WorkspaceBackfillService(self.db, tenant_id=self.context.tenant_id)
            session, _ = workspace.get_or_create_workspace_for_sbom(sbom, context=self.context)
        score = persist_snapshot(
            self.db, session, sbom.sbom_data.encode(), role="ACCEPTED", sbom_id=sbom.id, context=self.context
        )
        self.db.commit()
        return {"enabled": get_settings().sbom_quality_enabled, "assessment": score}
