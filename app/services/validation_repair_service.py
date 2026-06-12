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
from ..services.completeness_service import compute_and_save_completeness
from ..services.lifecycle.vex_provider import process_embedded_vex_for_sbom
from ..services.lifecycle_service import sync_lifecycle_for_sbom
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


def content_hash(content: str | None) -> str:
    return sha256((content or "").encode("utf-8", errors="replace")).hexdigest()


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
        "status": "failed" if report.has_errors() else "passed",
    }


def session_to_dict(session: SBOMValidationSession) -> dict[str, Any]:
    return {
        "id": session.id,
        "project_id": session.project_id,
        "user_id": session.user_id,
        "original_filename": session.original_filename,
        "sbom_name": session.sbom_name,
        "sbom_type": session.sbom_type,
        "detected_format": session.detected_format,
        "detected_version": session.detected_version,
        "current_content": session.current_content or "",
        "validation_status": session.validation_status,
        "latest_error_report": session.latest_error_report_json or {},
        "can_edit": bool(session.can_edit),
        "can_ai_fix": bool(session.can_ai_fix),
        "security_blocked_reason": session.security_blocked_reason,
        "created_at": session.created_at,
        "updated_at": session.updated_at,
        "expires_at": session.expires_at,
        "imported_sbom_id": session.imported_sbom_id,
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
            f"SBOM '{sbom_name}' did not pass validation; "
            f"{report.error_count} error(s) at stage '{report.first_error_stage}'."
        ),
        "session_id": session.id if session else None,
        "sbom_id": None,
        "can_edit": bool(session and session.can_edit),
        "can_ai_fix": bool(session and session.can_ai_fix),
        "reason": blocked_reason,
        "failed_stage": report.first_error_stage,
        "error_count": report.error_count,
        "warning_count": report.warning_count,
        "entries": serialized["entries"],
        "truncated": report.truncated,
        "error_report": serialized,
    }


class ValidationRepairService:
    def __init__(self, db: Session):
        self.db = db

    def create_failed_upload_session(
        self,
        *,
        raw_text: str,
        report: ErrorReport,
        sbom_name: str,
        original_filename: str | None = None,
        project_id: int | None = None,
        sbom_type: int | None = None,
        user_id: str | None = None,
        expires_days: int = 7,
    ) -> tuple[SBOMValidationSession | None, str | None]:
        safe, reason = payload_is_safe_to_stage(report)
        if not safe:
            return None, reason

        detected_format, detected_version = detect_format_version(raw_text)
        created = now_iso()
        session = SBOMValidationSession(
            id=str(uuid.uuid4()),
            project_id=project_id,
            user_id=user_id,
            original_filename=original_filename,
            sbom_name=sbom_name.strip(),
            sbom_type=sbom_type,
            detected_format=detected_format,
            detected_version=detected_version,
            sanitized_content=raw_text,
            current_content=raw_text,
            validation_status="failed",
            latest_error_report_json=serialize_report(report),
            can_edit=True,
            can_ai_fix=True,
            content_sha256=content_hash(raw_text),
            created_at=created,
            updated_at=created,
            expires_at=(datetime.now(UTC) + timedelta(days=expires_days)).replace(microsecond=0).isoformat(),
        )
        self.db.add(session)
        self.db.flush()
        self._record_event(
            session,
            "created",
            actor_user_id=user_id,
            summary="Validation repair session created after failed upload.",
            after_hash=session.content_sha256,
            metadata={"error_count": report.error_count, "failed_stage": report.first_error_stage},
        )
        self.db.commit()
        self.db.refresh(session)
        return session, None

    def get_session(self, session_id: str) -> SBOMValidationSession:
        session = self.db.get(SBOMValidationSession, session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Validation session not found")
        return session

    def update_content(self, session_id: str, content: str, *, actor_user_id: str | None = None) -> SBOMValidationSession:
        session = self.get_session(session_id)
        if not session.can_edit:
            raise HTTPException(status_code=403, detail="This validation session is not editable")
        before = content_hash(session.current_content)
        session.current_content = content
        session.content_sha256 = content_hash(content)
        session.validation_status = "edited"
        session.updated_at = now_iso()
        self.db.add(session)
        self._record_event(
            session,
            "manual_edit",
            actor_user_id=actor_user_id,
            summary="SBOM content edited in validation repair workspace.",
            before_hash=before,
            after_hash=session.content_sha256,
        )
        self.db.commit()
        self.db.refresh(session)
        return session

    def validate_session(
        self,
        session_id: str,
        *,
        strict_ntia: bool = False,
        verify_signature: bool = False,
        actor_user_id: str | None = None,
    ) -> SBOMValidationSession:
        session = self.get_session(session_id)
        report = run_validation(
            (session.current_content or "").encode("utf-8"),
            strict_ntia=strict_ntia,
            verify_signature=verify_signature,
        )
        serialized = serialize_report(report)
        safe, reason = payload_is_safe_to_stage(report)
        session.latest_error_report_json = serialized
        session.validation_status = "passed" if not report.has_errors() else ("security_blocked" if not safe else "failed")
        session.can_edit = bool(safe)
        session.can_ai_fix = bool(safe)
        session.security_blocked_reason = reason
        session.updated_at = now_iso()
        session.content_sha256 = content_hash(session.current_content)
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
        if session.imported_sbom_id:
            existing = self.db.get(SBOMSource, session.imported_sbom_id)
            if existing:
                if session.validation_status == "imported":
                    return existing

                # Update the existing SBOMSource with repaired content
                existing.sbom_data = session.current_content or ""
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
                sync_lifecycle_for_sbom(self.db, int(existing.id))
                process_embedded_vex_for_sbom(self.db, int(existing.id))
                compute_and_save_completeness(self.db, existing)

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
        name = (session.sbom_name or session.original_filename or f"repaired-{session.id}").strip()
        exists = self.db.execute(select(SBOMSource.id).where(SBOMSource.sbom_name == name)).first()
        if exists:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "duplicate_name", "message": f"An SBOM with name '{name}' already exists."},
            )

        obj = SBOMSource(
            sbom_name=name,
            sbom_data=session.current_content or "",
            sbom_type=session.sbom_type,
            projectid=session.project_id,
            created_by=actor_user_id or session.user_id,
            created_on=now_iso(),
            status="validated",
            failed_stage=None,
            validation_errors=(session.latest_error_report_json or {}).get("entries") or None,
            error_count=0,
            warning_count=int((session.latest_error_report_json or {}).get("warning_count") or 0),
            validated_at=now_iso(),
        )
        try:
            self.db.add(obj)
            self.db.flush()
            sync_sbom_components(self.db, obj)
            sync_lifecycle_for_sbom(self.db, int(obj.id))
            process_embedded_vex_for_sbom(self.db, int(obj.id))
            compute_and_save_completeness(self.db, obj)
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
        if any(not entry.get("can_ai_fix", True) for entry in report.get("entries", []) if entry.get("severity") == "error"):
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
            typed_patches = [p for p in _filter_ai_suggestion(AiRepairSuggestion(summary="selected", patches=typed_patches)).patches]
            new_content = apply_repair_patches(session.current_content or "", [p.model_dump(mode="json") for p in typed_patches])
        except (PatchApplyError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        before = content_hash(session.current_content)
        session.current_content = new_content
        session.content_sha256 = content_hash(new_content)
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
                "content_snippet": (session.current_content or "")[:12000],
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
