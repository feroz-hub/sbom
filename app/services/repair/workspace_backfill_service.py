"""Backfill repair workspaces for trusted SBOM rows.

Existing SBOMs may predate the validation-session workspace model. This
service creates a real workspace from the stored original SBOM content so
validated/imported records can still be inspected and repaired without
inventing empty placeholder sessions.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core.context import CurrentContext
from ...models import SBOMSource, SBOMValidationSession
from ...services import audit_service
from ...services.sbom.format_detector import detect_sbom_format_from_bytes
from ...services.validation_repair_service import ValidationRepairService, session_to_dict
from ...validation import run as run_validation


@dataclass(frozen=True, slots=True)
class WorkspaceAvailability:
    workspace_id: str | None
    validation_session_id: str | None
    repair_workspace_url: str | None
    workspace_available: bool
    workspace_source: str
    workspace_unavailable_reason: str | None
    validation_status: str | None
    detected_format: str | None
    detected_spec_version: str | None
    original_size_bytes: int | None
    original_sha256: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "workspace_id": self.workspace_id,
            "validation_session_id": self.validation_session_id,
            "repair_workspace_url": self.repair_workspace_url,
            "workspace_available": self.workspace_available,
            "workspace_source": self.workspace_source,
            "workspace_unavailable_reason": self.workspace_unavailable_reason,
            "validation_status": self.validation_status,
            "detected_format": self.detected_format,
            "detected_spec_version": self.detected_spec_version,
            "original_size_bytes": self.original_size_bytes,
            "original_sha256": self.original_sha256,
        }


class WorkspaceBackfillService:
    def __init__(self, db: Session, *, tenant_id: int):
        self.db = db
        self.tenant_id = tenant_id

    def find_existing_workspace(self, sbom_id: int) -> SBOMValidationSession | None:
        return (
            self.db.execute(
                select(SBOMValidationSession)
                .where(
                    SBOMValidationSession.imported_sbom_id == sbom_id,
                    SBOMValidationSession.tenant_id == self.tenant_id,
                )
                .order_by(SBOMValidationSession.created_at.desc())
            )
            .scalars()
            .first()
        )

    def availability_for_sbom(
        self,
        sbom: SBOMSource,
        *,
        workspace: SBOMValidationSession | None = None,
    ) -> WorkspaceAvailability:
        existing = workspace if workspace is not None else self.find_existing_workspace(int(sbom.id))
        if existing:
            return WorkspaceAvailability(
                workspace_id=existing.id,
                validation_session_id=existing.id,
                repair_workspace_url=f"/repair/{existing.id}",
                workspace_available=True,
                workspace_source="existing_workspace",
                workspace_unavailable_reason=None,
                validation_status=existing.validation_status,
                detected_format=existing.detected_format,
                detected_spec_version=existing.detected_version,
                original_size_bytes=existing.original_size_bytes or existing.file_size_bytes,
                original_sha256=existing.original_sha256 or existing.sha256,
            )

        raw_text = self.locate_original_content(sbom)
        if raw_text is None:
            return WorkspaceAvailability(
                workspace_id=None,
                validation_session_id=None,
                repair_workspace_url=None,
                workspace_available=False,
                workspace_source="unavailable",
                workspace_unavailable_reason="Original SBOM content is not available for this legacy record.",
                validation_status=sbom.status,
                detected_format=None,
                detected_spec_version=None,
                original_size_bytes=None,
                original_sha256=None,
            )

        raw_bytes = raw_text.encode("utf-8", errors="replace")
        detection = detect_sbom_format_from_bytes(raw_bytes)
        return WorkspaceAvailability(
            workspace_id=None,
            validation_session_id=None,
            repair_workspace_url=None,
            workspace_available=True,
            workspace_source="backfillable",
            workspace_unavailable_reason=None,
            validation_status=sbom.status,
            detected_format=None if detection.format == "unknown" else detection.format,
            detected_spec_version=detection.spec_version,
            original_size_bytes=len(raw_bytes),
            original_sha256=sha256(raw_bytes).hexdigest(),
        )

    def get_or_create_workspace_for_sbom(
        self,
        sbom: SBOMSource,
        *,
        context: CurrentContext,
    ) -> tuple[SBOMValidationSession, bool]:
        existing = self.find_existing_workspace(int(sbom.id))
        if existing:
            return existing, False

        raw_text = self.locate_original_content(sbom)
        if raw_text is None:
            raise HTTPException(status_code=422, detail="Original SBOM content is not available for this legacy record.")

        raw_bytes = raw_text.encode("utf-8", errors="replace")
        report = run_validation(raw_bytes)
        status_value = self._workspace_status_for_sbom(sbom, report.warning_count)
        session, blocked_reason = ValidationRepairService(self.db, tenant_id=self.tenant_id).create_upload_session(
            raw_text=raw_text,
            raw_bytes=raw_bytes,
            content_type="application/json",
            report=report,
            sbom_name=sbom.sbom_name,
            original_filename=sbom.sbom_name,
            project_id=sbom.projectid,
            sbom_type=sbom.sbom_type,
            user_id=context.actor_label(),
            validation_status=status_value,
            imported_sbom_id=int(sbom.id),
            expires_days=3650,
        )
        if session is None:
            raise HTTPException(status_code=422, detail=blocked_reason or "SBOM content cannot be staged for repair.")

        audit_service.write_audit_log(
            self.db,
            context,
            "sbom.workspace.backfilled",
            entity_type="sbom_validation_session",
            entity_id=session.id,
            new_value={
                "sbom_id": int(sbom.id),
                "workspace_id": session.id,
                "workspace_source": "original_upload",
                "sha256": session.original_sha256 or session.sha256,
            },
        )
        self.db.commit()
        self.db.refresh(session)
        return session, True

    def create_response(self, session: SBOMValidationSession, *, created: bool) -> dict[str, Any]:
        body = session_to_dict(session)
        body["created"] = created
        body["workspace_source"] = "original_upload" if created else "existing_workspace"
        return body

    @staticmethod
    def locate_original_content(sbom: SBOMSource) -> str | None:
        if isinstance(sbom.sbom_data, str) and sbom.sbom_data:
            return sbom.sbom_data
        if sbom.sbom_data:
            return str(sbom.sbom_data)
        return None

    @staticmethod
    def _workspace_status_for_sbom(sbom: SBOMSource, warning_count: int) -> str:
        status = (sbom.status or "").strip().lower()
        if status in {"validated", "valid", "imported", "valid_with_warnings", "warning", "failed", "unsupported", "unsupported_format", "repair_draft", "repaired", "repaired_valid"}:
            if status == "validated" and warning_count:
                return "valid_with_warnings"
            return status
        return "valid_with_warnings" if warning_count else "validated"
