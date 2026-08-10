"""Validation repair workspace service.

This module owns the quarantine boundary for malformed SBOMs. Invalid content
may be staged here for repair, but normal ``SBOMSource`` rows are created only
after the same eight-stage validator passes.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any

from fastapi import HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from ..ai.cost import BudgetGuard, estimate_cost_usd, estimate_tokens, write_usage_log_row
from ..ai.fix_generator import _budget_caps_from_settings
from ..ai.parse import ParseError, parse_llm_json
from ..ai.providers.base import AiProviderError, LlmRequest
from ..ai.registry import get_registry
from ..models import (
    Projects,
    SBOMSource,
    SBOMType,
    SBOMValidationSession,
    SBOMValidationSessionEvent,
)
from ..services.product_service import get_or_create_default_product
from ..services.sbom.format_detector import detect_sbom_format, detect_sbom_format_from_bytes
from ..services.sbom.workspace_storage import SbomWorkspaceStorage, iter_file
from ..services.sbom_enrichment_service import mark_enrichment_pending
from ..services.sbom_service import sync_sbom_components
from ..validation import ErrorReport
from ..validation import run as run_validation
from ..validation.stages import STAGE_NUMBERS
from .validation_patch_service import PatchApplyError, apply_repair_patches

SECURITY_BLOCKING_CODES = {
    "SBOM_VAL_E001_SIZE_EXCEEDED",
    "SBOM_VAL_E002_DECOMPRESSED_SIZE_EXCEEDED",
    "SBOM_VAL_E003_DECOMPRESSION_RATIO_EXCEEDED",
    "SBOM_VAL_E004_ENCODING_NOT_UTF8",
    "SBOM_VAL_E006_UNSUPPORTED_COMPRESSION",
    "SBOM_VAL_E080_JSON_DEPTH_EXCEEDED",
    "SBOM_VAL_E081_JSON_ARRAY_LENGTH_EXCEEDED",
    "SBOM_VAL_E082_JSON_STRING_LENGTH_EXCEEDED",
    "SBOM_VAL_E083_XML_DTD_FORBIDDEN",
    "SBOM_VAL_E084_XML_EXTERNAL_ENTITY_FORBIDDEN",
    "SBOM_VAL_E085_XML_ENTITY_EXPANSION",
    "SBOM_VAL_E086_YAML_UNSAFE_TAG",
    "SBOM_VAL_E087_PROTOTYPE_POLLUTION_KEY",
    "SBOM_VAL_E088_EMBEDDED_BLOB_TOO_LARGE",
    "SBOM_VAL_E089_ZIP_BOMB_RATIO",
}
SIGNATURE_ERROR_CODES = {
    "SBOM_VAL_E110_SIGNATURE_INVALID",
    "SBOM_VAL_E111_SIGNATURE_ALG_UNSUPPORTED",
    "SBOM_VAL_E112_SIGNATURE_KEY_NOT_FOUND",
}


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def bytes_hash(content: bytes | None) -> str:
    return sha256(content or b"").hexdigest()


def content_hash(content: str | None) -> str:
    return sha256((content or "").encode("utf-8", errors="replace")).hexdigest()


def content_size(content: str | None) -> int:
    return len((content or "").encode("utf-8", errors="replace"))


def count_text_lines(content: str | None) -> int:
    if not content:
        return 0
    return len(content.splitlines()) or 1


def _read_text_file(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _status_from_report(
    report: ErrorReport,
    detected_format: str | None,
    *,
    repaired: bool = False,
    safe: bool = True,
) -> str:
    if not safe:
        return "security_blocked"
    if report.has_errors():
        if not repaired and detected_format in {None, "unknown"} and report.first_error_stage == "detect":
            return "unsupported_format"
        return "failed"
    if report.warning_count and not repaired:
        return "valid_with_warnings"
    return "repaired_valid" if repaired else "valid"


def session_original_text(session: SBOMValidationSession) -> str:
    if session.raw_storage_path:
        return _read_text_file(session.raw_storage_path)
    return session.raw_content_text if session.raw_content_text is not None else (session.sanitized_content or "")


def session_original_bytes(session: SBOMValidationSession) -> bytes:
    if session.raw_storage_path:
        with open(session.raw_storage_path, "rb") as fh:
            return fh.read()
    if session.raw_content_blob is not None:
        return bytes(session.raw_content_blob)
    return session_original_text(session).encode("utf-8", errors="replace")


def session_repair_text(session: SBOMValidationSession) -> str:
    if session.repair_storage_path:
        return _read_text_file(session.repair_storage_path)
    if session.repair_content_text is not None:
        return session.repair_content_text
    return session.current_content if session.current_content is not None else session_original_text(session)


def set_session_repair_text(session: SBOMValidationSession, content: str) -> None:
    stored = SbomWorkspaceStorage().write_repair_draft(session.id, content)
    session.storage_backend = stored.storage_backend
    session.repair_storage_path = stored.storage_path
    session.repair_content_text = stored.inline_text
    session.repair_content_blob = stored.inline_blob
    session.current_content = stored.inline_text
    session.content_sha256 = stored.sha256
    session.stored_size_bytes = stored.size_bytes
    session.stored_sha256 = stored.sha256
    session.total_lines = stored.total_lines
    session.is_large_file = stored.is_large_file
    session.full_editor_allowed = stored.full_editor_allowed


class ValidationRepairPatch(BaseModel):
    target: str
    operation: str
    before: Any = None
    after: Any = None
    reason: str = ""
    validation_error_codes: list[str] = Field(default_factory=list)

    @field_validator("operation")
    @classmethod
    def normalize_operation(cls, value: str) -> str:
        normalized = (value or "").strip().lower()
        if normalized not in {"add", "replace", "remove"}:
            raise ValueError("operation must be add, replace, or remove")
        return normalized


class AiRepairSuggestion(BaseModel):
    summary: str
    risk: str = "medium"
    patches: list[ValidationRepairPatch] = Field(default_factory=list)
    requires_user_review: bool = True

    @field_validator("risk")
    @classmethod
    def normalize_risk(cls, value: str) -> str:
        normalized = (value or "medium").strip().lower()
        if normalized not in {"low", "medium", "high"}:
            return "medium"
        return normalized


def serialize_report(report: ErrorReport) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for entry in report.entries:
        raw = entry.model_dump(mode="json")
        raw["stage_number"] = STAGE_NUMBERS.get(str(raw.get("stage") or ""), 0)
        raw["can_ai_fix"] = _entry_can_ai_fix(raw)
        entries.append(raw)
    return {
        "entries": entries,
        "truncated": report.truncated,
        "failed_stage": report.first_error_stage,
        "error_count": report.error_count,
        "warning_count": report.warning_count,
        "info_count": len(report.info),
        "http_status": report.http_status,
        "status": "failed" if report.has_errors() else ("valid_with_warnings" if report.warning_count else "valid"),
    }


def session_to_dict(session: SBOMValidationSession) -> dict[str, Any]:
    inline_content = ""
    if session.full_editor_allowed:
        current_content = session_repair_text(session)
        inline_content = current_content if len(current_content.encode("utf-8", errors="replace")) <= 1024 * 1024 else ""
    original_size = session.original_size_bytes or session.file_size_bytes or 0
    original_hash = session.original_sha256 or session.sha256
    report = session.latest_error_report_json or {}
    warnings = [entry for entry in report.get("entries", []) if entry.get("severity") == "warning"]
    errors = [entry for entry in report.get("entries", []) if entry.get("severity") == "error"]
    return {
        "id": session.id,
        "workspace_id": session.id,
        "validation_session_id": session.id,
        "project_id": session.project_id,
        "user_id": session.user_id,
        "original_filename": session.original_filename,
        "sbom_name": session.sbom_name,
        "sbom_type": session.sbom_type,
        "content_type": session.content_type,
        "file_size_bytes": session.file_size_bytes or original_size,
        "sha256": session.sha256 or original_hash,
        "original_size_bytes": original_size,
        "original_sha256": original_hash,
        "stored_size_bytes": session.stored_size_bytes,
        "stored_sha256": session.stored_sha256,
        "storage_backend": session.storage_backend,
        "detected_format": session.detected_format,
        "detected_version": session.detected_version,
        "detected_spec_version": session.detected_version,
        "detection_confidence": session.detection_confidence,
        "detection_evidence": session.detection_evidence_json or [],
        # Backward compatibility for older clients. New repair UIs should
        # load /content chunks instead of relying on this inline field.
        "current_content": inline_content,
        "content_inline_truncated": not bool(inline_content) and bool(session.stored_size_bytes),
        "validation_status": session.validation_status,
        "latest_error_report": report,
        "validation_errors": errors or session.validation_errors_json or [],
        "validation_warnings": warnings,
        "stage_results": session.stage_results_json or report,
        "total_lines": session.total_lines if session.total_lines is not None else 0,
        "is_large_file": bool(session.is_large_file),
        "full_editor_allowed": bool(session.full_editor_allowed),
        "can_edit": bool(session.can_edit),
        "can_ai_fix": bool(session.can_ai_fix),
        "security_blocked_reason": session.security_blocked_reason,
        "created_at": session.created_at,
        "updated_at": session.updated_at,
        "expires_at": session.expires_at,
        "imported_sbom_id": session.imported_sbom_id,
        "repair_workspace_url": f"/repair/{session.id}",
    }


def event_to_dict(event: SBOMValidationSessionEvent) -> dict[str, Any]:
    return {
        "id": event.id,
        "session_id": event.session_id,
        "event_type": event.event_type,
        "actor_user_id": event.actor_user_id,
        "timestamp": event.timestamp,
        "summary": event.summary,
        "before_hash": event.before_hash,
        "after_hash": event.after_hash,
        "metadata": event.metadata_json or {},
    }


def _entry_can_ai_fix(raw: dict[str, Any]) -> bool:
    code = str(raw.get("code") or "")
    stage = str(raw.get("stage") or "")
    if code in SECURITY_BLOCKING_CODES or code in SIGNATURE_ERROR_CODES:
        return False
    return stage not in {"ingress", "security", "signature"}


def payload_is_safe_to_stage(report: ErrorReport) -> tuple[bool, str | None]:
    for entry in report.errors:
        if entry.code in SECURITY_BLOCKING_CODES or entry.stage in {"ingress", "security"}:
            return False, "Payload blocked by security validation"
    return True, None


def build_validation_failed_detail(
    *,
    report: ErrorReport,
    sbom_name: str,
    session: SBOMValidationSession | None,
    blocked_reason: str | None = None,
) -> dict[str, Any]:
    serialized = serialize_report(report)
    return {
        "code": "sbom_validation_failed",
        "status": "validation_failed",
        "message": (
            "SBOM validation failed. Full content is available in repair workspace."
            if session
            else (
                f"SBOM '{sbom_name}' did not pass validation; "
                f"{report.error_count} error(s) at stage '{report.first_error_stage}'."
            )
        ),
        "session_id": session.id if session else None,
        "validation_session_id": session.id if session else None,
        "repair_workspace_url": f"/repair/{session.id}" if session else None,
        "sbom_id": None,
        "file_size_bytes": session.file_size_bytes if session else None,
        "sha256": session.sha256 if session else None,
        "can_edit": bool(session and session.can_edit),
        "can_ai_fix": bool(session and session.can_ai_fix),
        "reason": blocked_reason,
        "failed_stage": report.first_error_stage,
        "error_count": report.error_count,
        "warning_count": report.warning_count,
        "entries": serialized["entries"],
        "truncated": report.truncated,
        "error_report": serialized,
        "workspace_id": session.id if session else None,
        "detected_format": session.detected_format if session else None,
        "detected_spec_version": session.detected_version if session else None,
        "detection_confidence": session.detection_confidence if session else None,
        "detection_evidence": session.detection_evidence_json if session else [],
        "total_lines": session.total_lines if session else None,
        "is_large_file": bool(session and session.is_large_file),
        "full_editor_allowed": bool(session and session.full_editor_allowed),
    }


class ValidationRepairService:
    def __init__(self, db: Session, *, tenant_id: int | None = None):
        self.db = db
        self.tenant_id = tenant_id

    def create_failed_upload_session(
        self,
        *,
        raw_text: str,
        raw_bytes: bytes | None = None,
        content_type: str | None = None,
        report: ErrorReport,
        sbom_name: str,
        original_filename: str | None = None,
        project_id: int | None = None,
        sbom_type: int | None = None,
        user_id: str | None = None,
        expires_days: int = 7,
    ) -> tuple[SBOMValidationSession | None, str | None]:
        return self.create_upload_session(
            raw_text=raw_text,
            raw_bytes=raw_bytes,
            content_type=content_type,
            report=report,
            sbom_name=sbom_name,
            original_filename=original_filename,
            project_id=project_id,
            sbom_type=sbom_type,
            user_id=user_id,
            expires_days=expires_days,
        )

    def create_upload_session(
        self,
        *,
        raw_text: str,
        raw_bytes: bytes | None = None,
        content_type: str | None = None,
        report: ErrorReport,
        sbom_name: str,
        original_filename: str | None = None,
        project_id: int | None = None,
        sbom_type: int | None = None,
        user_id: str | None = None,
        validation_status: str | None = None,
        imported_sbom_id: int | None = None,
        expires_days: int = 30,
    ) -> tuple[SBOMValidationSession | None, str | None]:
        safe, reason = payload_is_safe_to_stage(report)
        if not safe:
            return None, reason

        original_bytes = raw_bytes if raw_bytes is not None else raw_text.encode("utf-8", errors="replace")
        workspace_id = str(uuid.uuid4())
        storage = SbomWorkspaceStorage()
        stored_original = storage.store_original_upload(workspace_id, original_bytes)
        detection = detect_sbom_format_from_bytes(original_bytes)
        serialized = serialize_report(report)
        status_value = validation_status or _status_from_report(report, detection.format)
        repair_storage_path = storage.seed_repair_from_original(stored_original.storage_path, workspace_id)
        created = now_iso()
        session = SBOMValidationSession(
            id=workspace_id,
            project_id=project_id,
            user_id=user_id,
            original_filename=original_filename,
            sbom_name=sbom_name.strip(),
            sbom_type=sbom_type,
            content_type=content_type,
            file_size_bytes=stored_original.size_bytes,
            sha256=stored_original.sha256,
            original_size_bytes=stored_original.size_bytes,
            original_sha256=stored_original.sha256,
            stored_size_bytes=stored_original.size_bytes,
            stored_sha256=stored_original.sha256,
            storage_backend=stored_original.storage_backend,
            detected_format=None if detection.format == "unknown" else detection.format,
            detected_version=detection.spec_version,
            detection_confidence=detection.confidence,
            detection_evidence_json={"evidence": detection.evidence, "warnings": detection.warnings},
            raw_content_text=stored_original.inline_text,
            raw_content_blob=stored_original.inline_blob,
            raw_storage_path=stored_original.storage_path,
            sanitized_content=stored_original.inline_text,
            current_content=stored_original.inline_text,
            repair_content_text=stored_original.inline_text,
            repair_content_blob=stored_original.inline_blob,
            repair_storage_path=repair_storage_path,
            validation_status=status_value,
            validation_errors_json=[entry for entry in serialized["entries"] if entry.get("severity") == "error"],
            stage_results_json=serialized,
            latest_error_report_json=serialized,
            total_lines=stored_original.total_lines,
            is_large_file=stored_original.is_large_file,
            full_editor_allowed=stored_original.full_editor_allowed,
            can_edit=True,
            can_ai_fix=bool(status_value not in {"valid", "valid_with_warnings", "repaired_valid"}),
            content_sha256=stored_original.sha256,
            created_at=created,
            updated_at=created,
            expires_at=(datetime.now(UTC) + timedelta(days=expires_days)).replace(microsecond=0).isoformat(),
            imported_sbom_id=imported_sbom_id,
        )
        self.db.add(session)
        self.db.flush()
        self._record_event(
            session,
            "created",
            actor_user_id=user_id,
            summary=f"SBOM workspace created with validation status {status_value}.",
            after_hash=session.content_sha256,
            metadata={
                "error_count": report.error_count,
                "warning_count": report.warning_count,
                "failed_stage": report.first_error_stage,
                "file_size_bytes": stored_original.size_bytes,
                "sha256": stored_original.sha256,
                "detected_format": detection.format,
                "detected_spec_version": detection.spec_version,
                "is_large_file": stored_original.is_large_file,
            },
        )
        self.db.commit()
        self.db.refresh(session)
        return session, None

    def get_session(self, session_id: str) -> SBOMValidationSession:
        session = self.db.get(SBOMValidationSession, session_id)
        if not session or (self.tenant_id is not None and session.tenant_id != self.tenant_id):
            raise HTTPException(status_code=404, detail="Validation session not found")
        return session

    def update_session(
        self,
        session_id: str,
        content: str | None = None,
        project_id: int | None = None,
        *,
        actor_user_id: str | None = None,
    ) -> SBOMValidationSession:
        session = self.get_session(session_id)
        if not session.can_edit:
            raise HTTPException(status_code=403, detail="This validation session is not editable")

        summary_parts = []
        before = content_hash(session_repair_text(session))

        if content is not None:
            set_session_repair_text(session, content)
            session.validation_status = "repair_draft"
            summary_parts.append("content edited")

        if project_id is not None:
            project = self.db.get(Projects, project_id)
            if not project:
                raise HTTPException(status_code=404, detail="Project not found")
            session.project_id = project_id
            summary_parts.append(f"project assigned to '{project.project_name}'")

        session.updated_at = now_iso()
        self.db.add(session)

        summary = "SBOM " + " and ".join(summary_parts) + " in validation repair workspace."
        self._record_event(
            session,
            "manual_edit",
            actor_user_id=actor_user_id,
            summary=summary,
            before_hash=before if content is not None else None,
            after_hash=session.content_sha256 if content is not None else None,
        )
        self.db.commit()
        self.db.refresh(session)
        return session

    def update_content(
        self, session_id: str, content: str, *, actor_user_id: str | None = None
    ) -> SBOMValidationSession:
        return self.update_session(session_id, content=content, actor_user_id=actor_user_id)

    def validate_session(
        self,
        session_id: str,
        *,
        strict_ntia: bool = False,
        verify_signature: bool = False,
        actor_user_id: str | None = None,
    ) -> SBOMValidationSession:
        session = self.get_session(session_id)
        content = session_repair_text(session)
        report = run_validation(
            content.encode("utf-8", errors="replace"),
            strict_ntia=strict_ntia,
            verify_signature=verify_signature,
        )
        detection = detect_sbom_format(content)
        serialized = serialize_report(report)
        safe, reason = payload_is_safe_to_stage(report)
        session.latest_error_report_json = serialized
        session.validation_errors_json = [entry for entry in serialized["entries"] if entry.get("severity") == "error"]
        session.stage_results_json = serialized
        session.validation_status = _status_from_report(report, detection.format, repaired=True, safe=safe)
        session.detected_format = None if detection.format == "unknown" else detection.format
        session.detected_version = detection.spec_version
        session.detection_confidence = detection.confidence
        session.detection_evidence_json = {"evidence": detection.evidence, "warnings": detection.warnings}
        session.can_edit = bool(safe)
        session.can_ai_fix = bool(safe)
        session.security_blocked_reason = reason
        session.updated_at = now_iso()
        session.content_sha256 = content_hash(content)
        session.stored_size_bytes = content_size(content)
        session.stored_sha256 = content_hash(content)
        session.total_lines = count_text_lines(content)
        self.db.add(session)
        self._record_event(
            session,
            "validation_run",
            actor_user_id=actor_user_id,
            summary=f"Validation run completed with status {session.validation_status}.",
            after_hash=session.content_sha256,
            metadata={
                "error_count": report.error_count,
                "warning_count": report.warning_count,
                "failed_stage": report.first_error_stage,
                "strict_ntia": strict_ntia,
                "verify_signature": verify_signature,
            },
        )
        self.db.commit()
        self.db.refresh(session)
        return session

    def import_session(
        self,
        session_id: str,
        *,
        actor_user_id: str | None = None,
        strict_ntia: bool = False,
        verify_signature: bool = False,
    ) -> SBOMSource:
        session = self.validate_session(
            session_id,
            strict_ntia=strict_ntia,
            verify_signature=verify_signature,
            actor_user_id=actor_user_id,
        )
        report = _report_from_serialized(session.latest_error_report_json or {})
        if (session.latest_error_report_json or {}).get("error_count", 0) != 0:
            raise HTTPException(status_code=422, detail="Cannot import until validation passes")
        repaired_content = session_repair_text(session)
        if session.imported_sbom_id:
            existing = self.db.get(SBOMSource, session.imported_sbom_id)
            if existing:
                if session.validation_status == "imported":
                    return existing

                # Update the existing SBOMSource with repaired content
                existing.sbom_data = repaired_content
                existing.status = "validated"
                existing.failed_stage = None
                existing.validation_errors = (session.latest_error_report_json or {}).get("entries") or None
                existing.error_count = 0
                existing.warning_count = int((session.latest_error_report_json or {}).get("warning_count") or 0)
                existing.validated_at = now_iso()
                existing.modified_on = now_iso()
                if actor_user_id:
                    existing.modified_by = actor_user_id

                self.db.add(existing)
                self.db.flush()

                sync_sbom_components(self.db, existing)
                mark_enrichment_pending(existing)

                session.validation_status = "imported"
                session.updated_at = now_iso()
                self.db.add(session)

                self._record_event(
                    session,
                    "imported",
                    actor_user_id=actor_user_id,
                    summary=f"Repaired SBOM imported back to SBOM {existing.id}.",
                    after_hash=session.content_sha256,
                    metadata={"imported_sbom_id": existing.id, "warning_count": report.get("warning_count", 0)},
                )
                self.db.commit()
                self.db.refresh(existing)
                return existing
        if session.project_id is not None and self.db.get(Projects, session.project_id) is None:
            raise HTTPException(status_code=404, detail="Project not found")
        if session.sbom_type is not None and self.db.get(SBOMType, session.sbom_type) is None:
            raise HTTPException(status_code=404, detail="SBOM type not found")
        product = None
        if session.project_id is not None:
            product = get_or_create_default_product(
                self.db,
                tenant_id=session.tenant_id,
                project_id=session.project_id,
                actor=actor_user_id or session.user_id or "repair",
            )
        name = (session.sbom_name or session.original_filename or f"repaired-{session.id}").strip()
        exists = self.db.execute(select(SBOMSource.id).where(SBOMSource.sbom_name == name)).first()
        if exists:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "duplicate_name", "message": f"An SBOM with name '{name}' already exists."},
            )

        obj = SBOMSource(
            sbom_name=name,
            sbom_data=repaired_content,
            sbom_type=session.sbom_type,
            projectid=session.project_id,
            product_id=product.id if product else None,
            product_name=product.name if product else None,
            created_by=actor_user_id or session.user_id,
            created_on=now_iso(),
            status="validated",
            failed_stage=None,
            validation_errors=(session.latest_error_report_json or {}).get("entries") or None,
            error_count=0,
            warning_count=int((session.latest_error_report_json or {}).get("warning_count") or 0),
            validated_at=now_iso(),
        )
        mark_enrichment_pending(obj)
        try:
            self.db.add(obj)
            self.db.flush()
            sync_sbom_components(self.db, obj)
            session.imported_sbom_id = int(obj.id)
            session.validation_status = "imported"
            session.updated_at = now_iso()
            self.db.add(session)
            self._record_event(
                session,
                "imported",
                actor_user_id=actor_user_id,
                summary=f"Validated SBOM imported as trusted SBOM {obj.id}.",
                after_hash=session.content_sha256,
                metadata={"imported_sbom_id": obj.id, "warning_count": report.get("warning_count", 0)},
            )
            self.db.commit()
            self.db.refresh(obj)
            return obj
        except IntegrityError as exc:
            self.db.rollback()
            raise HTTPException(status_code=409, detail="Failed to import SBOM due to an integrity conflict") from exc
        except SQLAlchemyError as exc:
            self.db.rollback()
            raise HTTPException(status_code=500, detail="Failed to import repaired SBOM") from exc

    async def suggest_fixes(
        self,
        session_id: str,
        *,
        user_instruction: str | None = None,
        actor_user_id: str | None = None,
    ) -> dict[str, Any]:
        session = self.get_session(session_id)
        if not session.can_ai_fix:
            raise HTTPException(status_code=403, detail="AI fixes are disabled for this validation session")
        report = session.latest_error_report_json or {}
        if any(
            not entry.get("can_ai_fix", True) for entry in report.get("entries", []) if entry.get("severity") == "error"
        ):
            # The session may still have safe structural errors, but signature
            # and security failures must be explained by humans/tools rather
            # than patched by an LLM.
            unsafe_codes = [
                entry.get("code")
                for entry in report.get("entries", [])
                if entry.get("severity") == "error" and not entry.get("can_ai_fix", True)
            ]
            if unsafe_codes and set(unsafe_codes).issubset(SIGNATURE_ERROR_CODES | SECURITY_BLOCKING_CODES):
                raise HTTPException(status_code=403, detail="AI fixes cannot modify security or signature failures")

        suggestion = await self._call_ai_for_suggestion(session, user_instruction=user_instruction)
        safe_suggestion = _filter_ai_suggestion(suggestion)
        self._record_event(
            session,
            "ai_suggestion_generated",
            actor_user_id=actor_user_id,
            summary=safe_suggestion.summary,
            after_hash=session.content_sha256,
            metadata=safe_suggestion.model_dump(mode="json"),
        )
        self.db.commit()
        return safe_suggestion.model_dump(mode="json")

    def apply_patch(
        self,
        session_id: str,
        patches: list[dict[str, Any]],
        *,
        actor_user_id: str | None = None,
        strict_ntia: bool = False,
        verify_signature: bool = False,
    ) -> SBOMValidationSession:
        session = self.get_session(session_id)
        if not session.can_edit:
            raise HTTPException(status_code=403, detail="This validation session is not editable")
        try:
            typed_patches = [ValidationRepairPatch.model_validate(p).model_dump(mode="json") for p in patches]
            typed_patches = [
                p for p in _filter_ai_suggestion(AiRepairSuggestion(summary="selected", patches=typed_patches)).patches
            ]
            new_content = apply_repair_patches(
                session_repair_text(session), [p.model_dump(mode="json") for p in typed_patches]
            )
        except (PatchApplyError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        before = content_hash(session_repair_text(session))
        set_session_repair_text(session, new_content)
        session.updated_at = now_iso()
        self.db.add(session)
        self._record_event(
            session,
            "patch_applied",
            actor_user_id=actor_user_id,
            summary=f"Applied {len(typed_patches)} user-approved repair patch(es).",
            before_hash=before,
            after_hash=session.content_sha256,
            metadata={"patch_count": len(typed_patches), "patches": [p.model_dump(mode="json") for p in typed_patches]},
        )
        self.db.flush()
        return self.validate_session(
            session_id,
            strict_ntia=strict_ntia,
            verify_signature=verify_signature,
            actor_user_id=actor_user_id,
        )

    def history(self, session_id: str) -> list[dict[str, Any]]:
        session = self.get_session(session_id)
        return [event_to_dict(event) for event in session.events]

    def content_chunk(self, session_id: str, *, offset: int = 0, limit: int = 65536) -> dict[str, Any]:
        session = self.get_session(session_id)
        return self.content_chunk_for_source(session_id, source="repair_draft", offset=offset, limit=limit)

    def content_chunk_for_source(
        self, session_id: str, *, source: str = "repair_draft", offset: int = 0, limit: int = 65536
    ) -> dict[str, Any]:
        session = self.get_session(session_id)
        safe_offset = max(0, offset)
        safe_limit = max(1, min(limit, 1024 * 1024))
        path = SbomWorkspaceStorage().path_for(session, source)
        if path:
            chunk, total_size, eof, digest = SbomWorkspaceStorage().read_chunk_from_path(
                path, offset=safe_offset, limit=safe_limit
            )
        else:
            content = session_original_text(session) if source == "original" else session_repair_text(session)
            chunk = content[safe_offset : safe_offset + safe_limit]
            total_size = len(content)
            eof = safe_offset + len(chunk) >= total_size
            digest = content_hash(content)
        return {
            "offset": safe_offset,
            "limit": safe_limit,
            "total_size": total_size,
            "content": chunk,
            "eof": eof,
            "sha256": digest,
        }

    def content_lines(self, session_id: str, *, start_line: int = 1, line_count: int = 500) -> dict[str, Any]:
        session = self.get_session(session_id)
        return self.content_lines_for_source(session_id, source="repair_draft", start_line=start_line, line_count=line_count)

    def content_lines_for_source(
        self, session_id: str, *, source: str = "repair_draft", start_line: int = 1, line_count: int = 500
    ) -> dict[str, Any]:
        session = self.get_session(session_id)
        safe_start = max(1, start_line)
        safe_count = max(1, min(line_count, 5000))
        path = SbomWorkspaceStorage().path_for(session, source)
        if path:
            selected, total_lines, eof = SbomWorkspaceStorage().read_lines_from_path(
                path, start_line=safe_start, line_count=safe_count
            )
        else:
            content = session_original_text(session) if source == "original" else session_repair_text(session)
            lines = content.splitlines()
            selected = lines[safe_start - 1 : safe_start - 1 + safe_count]
            total_lines = len(lines)
            eof = safe_start - 1 + len(selected) >= total_lines
        return {
            "start_line": safe_start,
            "line_count": safe_count,
            "total_lines": total_lines,
            "lines": selected,
            "eof": eof,
        }

    def original_download(self, session_id: str, *, actor_user_id: str | None = None) -> tuple[bytes, str, str]:
        session = self.get_session(session_id)
        payload = session_original_bytes(session)
        media_type = session.content_type or "application/octet-stream"
        filename = session.original_filename or session.sbom_name or f"invalid-sbom-{session.id}.txt"
        self._record_event(
            session,
            "original_downloaded",
            actor_user_id=actor_user_id,
            summary="Original invalid SBOM downloaded for audit.",
            after_hash=session.original_sha256 or session.sha256 or bytes_hash(payload),
            metadata={"file_size_bytes": len(payload), "sha256": bytes_hash(payload)},
        )
        self.db.commit()
        return payload, media_type, filename

    def original_download_stream(self, session_id: str, *, actor_user_id: str | None = None):
        session = self.get_session(session_id)
        media_type = session.content_type or "application/octet-stream"
        filename = session.original_filename or session.sbom_name or f"sbom-workspace-{session.id}.txt"
        path = session.raw_storage_path
        if path:
            size = session.original_size_bytes or session.file_size_bytes
            digest = session.original_sha256 or session.sha256
            iterator = iter_file(path)
        else:
            payload = session_original_bytes(session)
            size = len(payload)
            digest = bytes_hash(payload)
            iterator = iter([payload])
        self._record_event(
            session,
            "original_downloaded",
            actor_user_id=actor_user_id,
            summary="Original SBOM downloaded for audit.",
            after_hash=digest,
            metadata={"file_size_bytes": size, "sha256": digest},
        )
        self.db.commit()
        return iterator, media_type, filename, int(size or 0)

    def repair_download_stream(self, session_id: str, *, actor_user_id: str | None = None):
        session = self.get_session(session_id)
        media_type = session.content_type or "application/octet-stream"
        filename = f"repair-draft-{session.original_filename or session.sbom_name or session.id}.txt"
        path = session.repair_storage_path
        if path:
            size = session.stored_size_bytes
            digest = session.stored_sha256
            iterator = iter_file(path)
        else:
            payload = session_repair_text(session).encode("utf-8", errors="replace")
            size = len(payload)
            digest = bytes_hash(payload)
            iterator = iter([payload])
        self._record_event(
            session,
            "repair_draft_downloaded",
            actor_user_id=actor_user_id,
            summary="Repair draft downloaded.",
            after_hash=digest,
            metadata={"file_size_bytes": size, "sha256": digest},
        )
        self.db.commit()
        return iterator, media_type, filename, int(size or 0)

    def search(self, session_id: str, *, query: str, source: str = "repair_draft", limit: int = 100) -> dict[str, Any]:
        session = self.get_session(session_id)
        path = SbomWorkspaceStorage().path_for(session, source)
        if path:
            matches = SbomWorkspaceStorage().search_lines(path, query, limit=limit)
        else:
            content = session_original_text(session) if source == "original" else session_repair_text(session)
            matches = []
            max_results = max(1, min(limit, 1000))
            for line_number, line in enumerate(content.splitlines(), start=1):
                column = line.find(query)
                if column == -1:
                    continue
                matches.append({"line_number": line_number, "column": column + 1, "preview": line[:500]})
                if len(matches) >= max_results:
                    break
        return {"query": query, "source": source, "limit": limit, "matches": matches, "truncated": len(matches) >= limit}

    def apply_line_patches(
        self,
        session_id: str,
        patches: list[dict[str, Any]],
        *,
        actor_user_id: str | None = None,
    ) -> SBOMValidationSession:
        session = self.get_session(session_id)
        if not session.can_edit:
            raise HTTPException(status_code=403, detail="This validation session is not editable")
        if not patches:
            return session
        base_path = session.repair_storage_path or session.raw_storage_path
        if not base_path:
            content = session_repair_text(session)
            lines = content.splitlines()
            for patch in sorted(patches, key=lambda p: int(p.get("start_line") or 1), reverse=True):
                operation = str(patch.get("operation") or "").lower()
                start = max(1, int(patch.get("start_line") or 1))
                end = max(start, int(patch.get("end_line") or start))
                replacement = str(patch.get("replacement_text") or "")
                if operation == "replace_lines":
                    lines[start - 1 : end] = replacement.splitlines()
                elif operation == "delete_lines":
                    del lines[start - 1 : end]
                elif operation == "insert_before_line":
                    lines[start - 1 : start - 1] = replacement.splitlines()
                else:
                    raise HTTPException(status_code=422, detail="Unsupported line patch operation")
            before = session.content_sha256
            set_session_repair_text(session, "\n".join(lines))
        else:
            before = session.content_sha256
            stored = SbomWorkspaceStorage().apply_line_patches_to_path(base_path, session.id, patches)
            session.repair_storage_path = stored.storage_path
            session.repair_content_text = None
            session.repair_content_blob = None
            session.current_content = None
            session.storage_backend = "filesystem"
            session.content_sha256 = stored.sha256
            session.stored_sha256 = stored.sha256
            session.stored_size_bytes = stored.size_bytes
            session.total_lines = stored.total_lines
            session.is_large_file = stored.is_large_file
            session.full_editor_allowed = stored.full_editor_allowed
        session.validation_status = "repair_draft"
        session.updated_at = now_iso()
        self.db.add(session)
        self._record_event(
            session,
            "line_patch_saved",
            actor_user_id=actor_user_id,
            summary=f"Saved {len(patches)} line repair patch(es).",
            before_hash=before,
            after_hash=session.content_sha256,
            metadata={"patch_count": len(patches)},
        )
        self.db.commit()
        self.db.refresh(session)
        return session

    async def _call_ai_for_suggestion(
        self,
        session: SBOMValidationSession,
        *,
        user_instruction: str | None,
    ) -> AiRepairSuggestion:
        registry = get_registry(self.db)
        try:
            provider = registry.get_default()
        except Exception as exc:
            raise HTTPException(status_code=503, detail="No AI provider is configured") from exc

        response_schema = AiRepairSuggestion.model_json_schema()
        system = (
            "You suggest SBOM validation repairs. Return only JSON matching the schema. "
            "Never fake signatures, never weaken security checks, and never claim a fix was applied. "
            "All patches require user review and will be revalidated by the server."
        )
        user = json.dumps(
            {
                "format": session.detected_format,
                "version": session.detected_version,
                "validation_report": session.latest_error_report_json,
                "content_snippet": session_repair_text(session)[:12000],
                "user_instruction": user_instruction or "",
                "output_contract": {
                    "requires_user_review": True,
                    "patches": "Use JSON Pointer targets for JSON SBOMs. Use exact text before/after only for text formats.",
                },
            },
            ensure_ascii=False,
        )
        max_output_tokens = 2000
        estimated_cost = estimate_cost_usd(
            provider=provider.name,
            model=provider.default_model,
            input_tokens=estimate_tokens(system) + estimate_tokens(user),
            output_tokens=max_output_tokens,
            is_local=getattr(provider, "is_local", False),
        )
        guard = BudgetGuard(_budget_caps_from_settings(), self.db)
        guard.check_request(estimated_usd=estimated_cost)
        request_id = str(uuid.uuid4())
        started = time.perf_counter()
        try:
            response = await provider.generate(
                LlmRequest(
                    system=system,
                    user=user,
                    response_schema=response_schema,
                    max_output_tokens=max_output_tokens,
                    temperature=0.1,
                    request_id=request_id,
                    purpose="sbom_validation_repair",
                )
            )
        except AiProviderError as exc:
            write_usage_log_row(
                self.db,
                request_id=request_id,
                provider=provider.name,
                model=provider.default_model,
                purpose="sbom_validation_repair",
                finding_cache_key=session.id,
                input_tokens=0,
                output_tokens=0,
                cost_usd=0.0,
                latency_ms=int((time.perf_counter() - started) * 1000),
                error=str(exc),
            )
            raise HTTPException(status_code=503, detail="AI provider failed to generate repair suggestions") from exc

        latency_ms = int((time.perf_counter() - started) * 1000)
        guard.record(actual_usd=response.usage.cost_usd)
        write_usage_log_row(
            self.db,
            request_id=request_id,
            provider=response.provider,
            model=response.model,
            purpose="sbom_validation_repair",
            finding_cache_key=session.id,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            cost_usd=response.usage.cost_usd,
            latency_ms=latency_ms,
        )
        if response.parsed:
            return AiRepairSuggestion.model_validate(response.parsed)
        try:
            return parse_llm_json(response.text, AiRepairSuggestion)
        except ParseError as exc:
            raise HTTPException(status_code=502, detail="AI provider returned malformed repair suggestions") from exc

    def _record_event(
        self,
        session: SBOMValidationSession,
        event_type: str,
        *,
        actor_user_id: str | None = None,
        summary: str | None = None,
        before_hash: str | None = None,
        after_hash: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.db.add(
            SBOMValidationSessionEvent(
                session_id=session.id,
                event_type=event_type,
                actor_user_id=actor_user_id,
                timestamp=now_iso(),
                summary=summary,
                before_hash=before_hash,
                after_hash=after_hash,
                metadata_json=metadata,
            )
        )


def detect_format_version(content: str) -> tuple[str | None, str | None]:
    text = (content or "").lstrip("\ufeff \t\r\n")
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        parsed = None
    if isinstance(parsed, dict):
        if parsed.get("bomFormat") == "CycloneDX":
            return "cyclonedx", str(parsed.get("specVersion") or "") or None
        if "spdxVersion" in parsed:
            return "spdx", str(parsed.get("spdxVersion") or "") or None
    lowered = text[:400].lower()
    if text.startswith("<"):
        if "cyclonedx" in lowered or "<bom" in lowered:
            return "cyclonedx-xml", None
        return "xml", None
    if lowered.startswith("spdxversion:"):
        first = text.splitlines()[0].split(":", 1)[-1].strip()
        return "spdx-tag-value", first or None
    if "bomformat:" in lowered:
        return "cyclonedx-yaml", None
    return None, None


def _filter_ai_suggestion(suggestion: AiRepairSuggestion) -> AiRepairSuggestion:
    safe: list[ValidationRepairPatch] = []
    for patch in suggestion.patches:
        codes = set(patch.validation_error_codes or [])
        target = patch.target.lower()
        reason = patch.reason.lower()
        after_text = json.dumps(patch.after, ensure_ascii=False).lower() if patch.after is not None else ""
        if codes.intersection(SIGNATURE_ERROR_CODES | SECURITY_BLOCKING_CODES):
            continue
        if "signature" in target or "signature" in reason or "signature" in after_text:
            continue
        if "__proto__" in target or "constructor/prototype" in target:
            continue
        safe.append(patch)
    return suggestion.model_copy(update={"patches": safe, "requires_user_review": True})


def _report_from_serialized(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "error_count": int(report.get("error_count") or 0),
        "warning_count": int(report.get("warning_count") or 0),
        "failed_stage": report.get("failed_stage"),
    }
