"""Tenant-scoped repair jobs with atomic, hash-bound approval via normal import."""

import logging
import uuid
from datetime import UTC, datetime

from app.logger import log_context, log_event
from app.models import SBOMRepairJob, SBOMSource, SBOMValidationSession
from app.services import audit_service
from app.services.tenant_access import get_project_for_tenant, get_sbom_for_tenant
from app.services.validation_repair_service import (
    ValidationRepairService,
    bytes_hash,
    content_hash,
    now_iso,
    session_original_bytes,
    session_repair_text,
    session_upload_metadata,
    set_session_repair_text,
)
from app.settings import get_settings
from fastapi import HTTPException
from sqlalchemy import select

from ..quality.engine import QualityEngine, comparison
from ..quality.service import persist_snapshot
from .engine import RepairEngine
from .policy import RepairPolicy

log = logging.getLogger(__name__)


class AutoRepairService:
    def __init__(self, db, context):
        self.db, self.context = db, context
        self.workspace = ValidationRepairService(db, tenant_id=context.tenant_id)

    def session(self, session_id):
        session = self.db.execute(
            select(SBOMValidationSession)
            .where(SBOMValidationSession.id == session_id, SBOMValidationSession.tenant_id == self.context.tenant_id)
            .with_for_update()
        ).scalar_one_or_none()
        if session is None:
            raise HTTPException(404, "Validation session not found")
        if datetime.fromisoformat(session.expires_at) <= datetime.now(UTC):
            raise HTTPException(410, "Validation session expired")
        if not session.can_edit:
            raise HTTPException(403, "Validation session is not editable")
        return session

    def policy(self, session):
        # Policy flags can only become stricter than the original upload.
        meta = session_upload_metadata(self.db, session)
        report = session.latest_error_report_json or {}
        strict = bool(
            meta.get("strict_ntia")
            or any(e.get("severity") == "error" and "_NTIA_" in e.get("code", "") for e in report.get("entries", []))
        )
        signature = bool(meta.get("verify_signature") or getattr(get_settings(), "SBOM_SIGNATURE_VERIFICATION", False))
        return RepairPolicy.configured(strict_ntia=strict, verify_signature=signature)

    def event(self, session, name, job=None, **fields):
        job_id = job.id if job else fields.pop("repair_job_id", None)
        sbom_id = (job.imported_sbom_id or job.source_sbom_id) if job else session.imported_sbom_id
        status = fields.pop("status", job.status if job else session.validation_status)
        fields.setdefault("format", job.report_json.get("format") if job else session.detected_format)
        fields.setdefault("spec_version", job.report_json.get("spec_version") if job else session.detected_version)
        with log_context(tenant_id=self.context.tenant_id, user_id=self.context.user_id, sbom_id=sbom_id):
            log_event(log, name, repair_job_id=job_id, status=status, repair_rule=fields.get("rule_name"), **fields)
        metadata = {"repair_job_id": job_id, "sbom_id": sbom_id, "status": status, **fields}
        self.workspace._record_event(session, name, actor_user_id=self.context.actor_label(), metadata=metadata)
        audit_service.write_audit_log(
            self.db,
            self.context,
            name,
            entity_type="sbom_repair_job",
            entity_id=job_id or session.id,
            new_value=metadata,
        )

    def analyze(self, session_id):
        session = self.session(session_id)
        policy = self.policy(session)
        source = session_repair_text(session)
        result = RepairEngine(policy).analyze(source.encode())
        result["source_sha256"] = content_hash(source)
        result["status"] = (
            "NOT_REQUIRED"
            if not result["total_errors"] and not result["truncated"] and not result["auto_fixable"]
            else "REPAIR_AVAILABLE"
            if result["auto_fixable"]
            else "MANUAL_REVIEW_REQUIRED"
        )
        result["enabled"] = policy.enabled
        result["capabilities"] = self.capabilities()
        self.event(
            session,
            "SBOM_REPAIR_ANALYZED",
            status=result["status"],
            total_errors=result["total_errors"],
            auto_fixable=result["auto_fixable"],
        )
        self.db.commit()
        return result

    def run(self, session_id):
        session = self.session(session_id)
        policy = self.policy(session)
        if not policy.enabled:
            raise HTTPException(409, "SBOM auto-repair is disabled")
        source = session_repair_text(session)
        source_hash = content_hash(source)
        original_hash = bytes_hash(session_original_bytes(session))
        if original_hash != (session.original_sha256 or session.sha256):
            raise HTTPException(409, "Original artifact hash mismatch")
        source_sbom = (
            get_sbom_for_tenant(self.db, session.imported_sbom_id, self.context.tenant_id)
            if session.imported_sbom_id
            else None
        )
        if session.imported_sbom_id and source_sbom is None:
            raise HTTPException(404, "Source SBOM not found")
        source_sbom_hash = content_hash(source_sbom.sbom_data) if source_sbom else None
        # Retry returns the same immutable result for the same source and policy.
        jobs = self.db.execute(
            select(SBOMRepairJob)
            .where(
                SBOMRepairJob.session_id == session_id,
                SBOMRepairJob.tenant_id == self.context.tenant_id,
                SBOMRepairJob.source_sha256 == source_hash,
            )
            .order_by(SBOMRepairJob.created_at.desc())
        ).scalars()
        options = {
            "strict_ntia": policy.strict_ntia,
            "verify_signature": policy.verify_signature,
            "max_passes": policy.max_passes,
            "confidence": policy.confidence,
            "max_bytes": policy.max_bytes,
            "max_seconds": policy.max_seconds,
        }
        for job in jobs:
            # Phase 2 retained unsupported SPDX jobs remain readable, but must
            # not suppress a new native SPDX run after this capability is added.
            if "spdx" in (session.detected_format or "").lower() and job.report_json.get("format") != "SPDX_JSON":
                continue
            if (
                job.approval_status != "REJECTED"
                and job.validation_options_json == options
                and job.report_json["source_project_id"] == session.project_id
                and job.source_sbom_id == session.imported_sbom_id
                and job.source_sbom_sha256 == source_sbom_hash
                and job.original_sha256 == original_hash
            ):
                return self.serialize(job)
        job_id = str(uuid.uuid4())
        self.event(session, "SBOM_REPAIR_STARTED", repair_job_id=job_id, status="REPAIR_IN_PROGRESS")
        try:
            with log_context(tenant_id=self.context.tenant_id, user_id=self.context.user_id):
                result = RepairEngine(policy).run(source.encode())
            result.report["source_project_id"] = session.project_id
            scope = session_upload_metadata(self.db, session)
            result.report["upload_options"] = scope.get("upload_options", {})
            result.report["source_product_id"] = (
                source_sbom.product_id
                if source_sbom and source_sbom.projectid == session.project_id
                else scope.get("product_id")
                if scope.get("project_id") == session.project_id
                else None
            )
            job = SBOMRepairJob(
                id=job_id,
                tenant_id=self.context.tenant_id,
                session_id=session_id,
                source_sha256=source_hash,
                original_sha256=original_hash,
                source_sbom_id=source_sbom.id if source_sbom else None,
                source_sbom_sha256=source_sbom_hash,
                candidate_sha256=bytes_hash(result.candidate),
                candidate_content=result.candidate.decode(),
                report_json=result.report,
                validation_options_json=options,
                status=result.report["status"],
                approval_status="PENDING",
                created_at=now_iso(),
                actor_user_id=self.context.actor_label(),
            )
            if get_settings().sbom_quality_enabled:
                from app.validation.errors import ErrorReport
                quality = QualityEngine(repair_enabled=policy.enabled)
                before_score = quality.calculate(source.encode(), ErrorReport.model_validate(result.report['before_validation'])).model_dump(mode='json')
                after_score = quality.calculate(result.candidate, ErrorReport.model_validate(result.report['after_validation'])).model_dump(mode='json')
                job.report_json['quality'] = comparison(before_score, after_score)
                persist_snapshot(self.db, session, source.encode(), role='REPAIR_SOURCE', job_id=job_id,
                                 assessment=before_score, context=self.context)
                persist_snapshot(self.db, session, result.candidate, role='CANDIDATE', job_id=job_id,
                                 assessment=after_score, context=self.context)
                if job.report_json['quality']['improvement'] and job.report_json['quality']['improvement'] > 0:
                    self.event(session, 'SBOM_QUALITY_IMPROVED', job,
                               session_id=session.id, before_score=before_score['overall_score'], after_score=after_score['overall_score'],
                               artifact_hash=job.candidate_sha256, engine_version=after_score['engine_version'])
            self.db.add(job)
            for change in result.report["changes"]:
                self.event(
                    session,
                    "SBOM_REPAIR_RULE_APPLIED",
                    job,
                    rule_name=change["rule_name"],
                    repair_id=change["repair_id"],
                )
            for change in result.report["rolled_back_changes"]:
                self.event(
                    session,
                    "SBOM_REPAIR_RULE_ROLLED_BACK",
                    job,
                    rule_name=change["rule_name"],
                    repair_id=change["repair_id"],
                    error_count_after_attempt=change["error_count_after_attempt"],
                )
            self.event(session, "SBOM_REPAIR_REVALIDATED", job, error_count=result.report["errors_after"])
            self.event(
                session,
                "SBOM_REPAIR_FAILED" if job.status == "REPAIR_FAILED" else "SBOM_REPAIR_COMPLETED",
                job,
                repairs_applied=result.report["repairs_applied"],
            )
            self.db.commit()
            return self.serialize(job)
        except Exception:
            self.db.rollback()
            with log_context(tenant_id=self.context.tenant_id, user_id=self.context.user_id):
                log_event(
                    log,
                    "SBOM_REPAIR_FAILED",
                    level=logging.ERROR,
                    repair_job_id=job_id,
                    status="REPAIR_FAILED",
                    sbom_id=session.imported_sbom_id,
                )
            raise

    def get(self, session_id, job_id):
        self.session(session_id)
        job = self.db.execute(
            select(SBOMRepairJob)
            .where(
                SBOMRepairJob.id == job_id,
                SBOMRepairJob.session_id == session_id,
                SBOMRepairJob.tenant_id == self.context.tenant_id,
            )
            .with_for_update()
        ).scalar_one_or_none()
        if job is None:
            raise HTTPException(404, "Repair job not found")
        return job

    def capabilities(self):
        has = self.context.has_permission
        return {
            "can_repair": has("sbom:repair:update"),
            "can_approve": has("sbom:repair:revalidate") and has("sbom:upload") and has("product:assign_sbom"),
            "can_reject": has("sbom:repair:update"),
            "can_download": has("sbom:repair:download"),
        }

    def serialize(self, job):
        quality = job.report_json.get("quality")
        if quality and (
            content_hash(job.candidate_content) != job.candidate_sha256
            or quality["before"]["artifact_hash"] != job.source_sha256
            or quality["after"]["artifact_hash"] != job.candidate_sha256
        ):
            raise HTTPException(409, "Repair quality evidence artifact hash mismatch")
        return {
            **job.report_json,
            "repair_job_id": job.id,
            "session_id": job.session_id,
            "status": job.status,
            "approval_status": job.approval_status,
            "candidate_sha256": job.candidate_sha256,
            "source_sha256": job.source_sha256,
            "capabilities": self.capabilities(),
            "imported_sbom_id": job.imported_sbom_id,
            "decided_at": job.decided_at,
        }

    def approve(self, session_id, job_id, *, expected_candidate_hash=None):
        session = self.session(session_id)
        job = self.get(session_id, job_id)
        if expected_candidate_hash is not None and expected_candidate_hash != job.candidate_sha256:
            raise HTTPException(409, "Candidate differs from the reviewed hash")
        if job.approval_status == "APPROVED":
            return {**self.serialize(job), "already_approved": True}
        if job.approval_status != "PENDING" or job.status != "REPAIRED":
            raise HTTPException(409, "Only fully repaired pending candidates may be approved")
        if session.project_id != job.report_json["source_project_id"]:
            raise HTTPException(409, "Project assignment changed; run repair again")
        if content_hash(session_repair_text(session)) != job.source_sha256:
            raise HTTPException(409, "Source draft changed; run repair again")
        if bytes_hash(session_original_bytes(session)) != job.original_sha256 or job.original_sha256 != (
            session.original_sha256 or session.sha256
        ):
            raise HTTPException(409, "Original artifact hash mismatch")
        if content_hash(job.candidate_content) != job.candidate_sha256:
            raise HTTPException(409, "Candidate hash mismatch")
        if session.imported_sbom_id != job.source_sbom_id:
            raise HTTPException(409, "Source SBOM association changed")
        if job.source_sbom_id:
            sbom = self.db.execute(
                select(SBOMSource)
                .where(SBOMSource.id == job.source_sbom_id, SBOMSource.tenant_id == self.context.tenant_id)
                .with_for_update()
            ).scalar_one_or_none()
            if not sbom or content_hash(sbom.sbom_data) != job.source_sbom_sha256:
                raise HTTPException(409, "Source SBOM changed")
        if session.project_id and not get_project_for_tenant(self.db, session.project_id, self.context.tenant_id):
            raise HTTPException(404, "Project not found")
        options = job.validation_options_json
        policy = self.policy(session)
        # Import only the hash-verified candidate, using the existing parser,
        # component synchronization and enrichment state. Preserve any accepted
        # SBOM as a separate artifact rather than silently overwriting it.
        if job.source_sbom_id:
            session.imported_sbom_id = None
            session.sbom_name = (session.sbom_name or "SBOM")[:190] + "-repaired-" + job.id
        try:
            imported = self.workspace.import_session(
                session_id,
                actor_user_id=self.context.actor_label(),
                strict_ntia=bool(options["strict_ntia"] or policy.strict_ntia),
                verify_signature=bool(options["verify_signature"] or policy.verify_signature),
                _content=job.candidate_content,
                _commit=False,
                _product_id=job.report_json.get("source_product_id"),
                _upload_options=job.report_json.get("upload_options"),
            )
            from app.services.tenant_access import get_product_for_tenant

            product = (
                get_product_for_tenant(self.db, imported.product_id, self.context.tenant_id)
                if imported.product_id
                else None
            )
            if product and (
                (job.report_json.get("upload_options") or {}).get("set_as_current") or product.current_sbom_id is None
            ):
                previous = product.current_sbom_id
                product.current_sbom_id, product.updated_at = imported.id, now_iso()
                audit_service.write_audit_log(
                    self.db,
                    self.context,
                    "product.current_sbom.changed",
                    entity_type="product",
                    entity_id=product.id,
                    old_value={"current_sbom_id": previous},
                    new_value={"current_sbom_id": imported.id, "source": "sbom.repair.approve"},
                )
            # Publish a new draft path atomically; the previous file stays intact.
            set_session_repair_text(session, job.candidate_content, _storage_id=job.id)
            job.approval_status = "APPROVED"
            job.decided_at = now_iso()
            job.decided_by = self.context.actor_label()
            job.imported_sbom_id = imported.id
            persist_snapshot(self.db, session, job.candidate_content.encode(), role='ACCEPTED', job_id=job.id,
                             sbom_id=imported.id, context=self.context)
            self.event(session, "SBOM_REPAIR_APPROVED", job, imported_sbom_id=imported.id)
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        return self.serialize(job)

    def reject(self, session_id, job_id):
        session = self.session(session_id)
        job = self.get(session_id, job_id)
        if job.approval_status == "REJECTED":
            return self.serialize(job)
        if job.approval_status != "PENDING":
            raise HTTPException(409, "Repair job already decided")
        job.approval_status, job.status = "REJECTED", "REJECTED"
        job.decided_at, job.decided_by = now_iso(), self.context.actor_label()
        self.event(session, "SBOM_REPAIR_REJECTED", job)
        self.db.commit()
        return self.serialize(job)
