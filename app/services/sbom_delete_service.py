"""Transactional deletion and dependency inspection for SBOMs.

Permanent deletion is intentionally implemented here instead of relying on
ORM relationship cascades.  Several historical foreign keys use ``NO ACTION``
and SQLite installations upgraded from older revisions do not all have the
self-referencing constraints declared by the current SQLAlchemy model.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import MetaData, Table, delete, func, inspect, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..models import (
    AiFixBatch,
    AnalysisFinding,
    AnalysisRun,
    AnalysisSchedule,
    AuditLog,
    CompareCache,
    ComponentLifecycleOverrideAudit,
    RunCache,
    SBOMAnalysisReport,
    SBOMComponent,
    SBOMSource,
    SBOMValidationSession,
    SBOMValidationSessionEvent,
    VexDocument,
    VexOverrideAudit,
    VexStatement,
)
from .soft_delete import SoftDeleteService

log = logging.getLogger("sbom.delete")


class SBOMDeleteConflict(Exception):
    """The requested permanent delete is unsafe or was not confirmed."""

    def __init__(
        self,
        message: str,
        *,
        blocking_dependencies: dict[str, int] | None = None,
        impact: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.blocking_dependencies = blocking_dependencies or {}
        self.impact = impact


class SBOMDeleteService:
    """Owns SBOM soft delete, permanent delete, and delete previews."""

    _HANDLED_FK_EDGES = frozenset(
        {
            ("ai_fix_batch", "run_id", "analysis_run"),
            ("analysis_finding", "analysis_run_id", "analysis_run"),
            ("analysis_finding", "component_id", "sbom_component"),
            ("analysis_run", "sbom_id", "sbom_source"),
            ("analysis_schedule", "last_run_id", "analysis_run"),
            ("analysis_schedule", "sbom_id", "sbom_source"),
            ("component_lifecycle_override_audit", "component_id", "sbom_component"),
            ("sbom_analysis_report", "sbom_ref_id", "sbom_source"),
            ("sbom_component", "duplicate_of_component_id", "sbom_component"),
            ("sbom_component", "sbom_id", "sbom_source"),
            ("sbom_source", "converted_sbom_id", "sbom_source"),
            ("sbom_source", "parent_id", "sbom_source"),
            ("sbom_source", "source_sbom_id", "sbom_source"),
            ("sbom_validation_session_events", "session_id", "sbom_validation_sessions"),
            ("sbom_validation_sessions", "imported_sbom_id", "sbom_source"),
            ("vex_documents", "sbom_id", "sbom_source"),
            ("vex_override_audit", "component_id", "sbom_component"),
            ("vex_statements", "component_id", "sbom_component"),
            ("vex_statements", "sbom_id", "sbom_source"),
            ("vex_statements", "vex_document_id", "vex_documents"),
        }
    )

    DELETE_ORDER = [
        "validation_session_events",
        "vex_statements",
        "lifecycle_override_audits",
        "vex_override_audits",
        "analysis_findings",
        "ai_fix_batches",
        "analysis_schedules",
        "compare_and_run_caches",
        "analysis_runs",
        "vex_documents",
        "validation_sessions",
        "validation_reports",
        "components",
        "self_references",
        "sbom_sources",
    ]

    def __init__(self, db: Session):
        self.db = db
        self._tenant_id: int | None = None

    def get_sbom(self, sbom_id: int) -> SBOMSource | None:
        row = self.db.execute(
            select(SBOMSource).where(SBOMSource.id == sbom_id).execution_options(include_deleted=True)
        ).scalar_one_or_none()
        if row is not None:
            self._tenant_id = row.tenant_id
        return row

    def get_delete_impact(self, sbom_id: int) -> dict[str, Any]:
        sbom = self.get_sbom(sbom_id)
        if sbom is None:
            raise LookupError("SBOM not found")

        tree_ids, version_ids, conversion_ids = self._dependency_tree(sbom_id)
        component_ids = self._ids(SBOMComponent.id, SBOMComponent.sbom_id.in_(tree_ids))
        run_ids = self._ids(AnalysisRun.id, AnalysisRun.sbom_id.in_(tree_ids))
        vex_document_ids = self._ids(VexDocument.id, VexDocument.sbom_id.in_(tree_ids))
        session_ids = self._ids(
            SBOMValidationSession.id,
            SBOMValidationSession.imported_sbom_id.in_(tree_ids),
        )

        counts = {
            "components": len(component_ids),
            "analysis_runs": len(run_ids),
            "vulnerabilities": self._count(
                AnalysisFinding.id,
                AnalysisFinding.analysis_run_id.in_(run_ids),
                empty_ids=run_ids,
            ),
            # Remediations are project-scoped shared records, not SBOM children.
            "remediations": 0,
            "validation_reports": self._count(
                SBOMAnalysisReport.id,
                SBOMAnalysisReport.sbom_ref_id.in_(tree_ids),
            ),
            "validation_sessions": len(session_ids),
            "validation_events": self._count(
                SBOMValidationSessionEvent.id,
                SBOMValidationSessionEvent.session_id.in_(session_ids),
                empty_ids=session_ids,
            ),
            "vex_documents": len(vex_document_ids),
            "vex_statements": self._count(
                VexStatement.id,
                or_(
                    VexStatement.sbom_id.in_(tree_ids),
                    VexStatement.vex_document_id.in_(vex_document_ids),
                    VexStatement.component_id.in_(component_ids),
                ),
            ),
            "schedules": self._count(
                AnalysisSchedule.id,
                AnalysisSchedule.sbom_id.in_(tree_ids),
            ),
            "versions": len(version_ids),
            "derived_sboms": len(conversion_ids),
            "lifecycle_override_audits": self._count(
                ComponentLifecycleOverrideAudit.id,
                ComponentLifecycleOverrideAudit.component_id.in_(component_ids),
                empty_ids=component_ids,
            ),
            "vex_override_audits": self._count(
                VexOverrideAudit.id,
                VexOverrideAudit.component_id.in_(component_ids),
                empty_ids=component_ids,
            ),
            "ai_fix_batches": self._count(
                AiFixBatch.id,
                AiFixBatch.run_id.in_(run_ids),
                empty_ids=run_ids,
            ),
            "run_cache_rows": self._count(RunCache.id, RunCache.sbom_id.in_(tree_ids)),
            "compare_cache_rows": self._count(
                CompareCache.cache_key,
                or_(CompareCache.run_a_id.in_(run_ids), CompareCache.run_b_id.in_(run_ids)),
                empty_ids=run_ids,
            ),
        }

        unknown = self._unknown_fk_dependencies(
            {
                "sbom_source": tree_ids,
                "sbom_component": component_ids,
                "analysis_run": run_ids,
                "vex_documents": vex_document_ids,
                "sbom_validation_sessions": session_ids,
            }
        )
        warnings = ["Project-scoped vulnerability remediation and global provider/lifecycle caches are retained."]
        if unknown:
            warnings.append(
                "Unrecognised foreign-key dependencies must be handled before permanent deletion: "
                + ", ".join(sorted(unknown))
            )

        table_counts = {
            "ai_fix_batch": counts["ai_fix_batches"],
            "analysis_finding": counts["vulnerabilities"],
            "analysis_run": counts["analysis_runs"],
            "analysis_schedule": counts["schedules"],
            "compare_cache": counts["compare_cache_rows"],
            "component_lifecycle_override_audit": counts["lifecycle_override_audits"],
            "run_cache": counts["run_cache_rows"],
            "sbom_analysis_report": counts["validation_reports"],
            "sbom_component": counts["components"],
            "sbom_source": len(tree_ids - {sbom_id}),
            "sbom_validation_session_events": counts["validation_events"],
            "sbom_validation_sessions": counts["validation_sessions"],
            "vex_documents": counts["vex_documents"],
            "vex_override_audit": counts["vex_override_audits"],
            "vex_statements": counts["vex_statements"],
            "vulnerability_remediation": counts["remediations"],
            **unknown,
        }
        child_sboms = [
            {
                "sbom_id": row.id,
                "sbom_name": row.sbom_name,
                "parent_id": row.parent_id,
                "source_sbom_id": row.source_sbom_id,
                "converted_sbom_id": row.converted_sbom_id,
            }
            for row in self.db.execute(
                select(SBOMSource)
                .where(SBOMSource.id.in_(tree_ids - {sbom_id}))
                .order_by(SBOMSource.id)
                .execution_options(include_deleted=True)
            ).scalars()
        ]
        return {
            "sbom_id": sbom_id,
            "sbom_name": sbom.sbom_name,
            # Backward-compatible aliases for older delete dialogs.
            "components": counts["components"],
            "runs": counts["analysis_runs"],
            "findings": counts["vulnerabilities"],
            "can_delete": not unknown,
            "requires_confirmation": True,
            "dependent_counts": counts,
            "table_counts": table_counts,
            "blocking_dependencies": unknown,
            "child_sbom_ids": sorted(tree_ids - {sbom_id}),
            "child_sboms": child_sboms,
            "warnings": warnings,
            "delete_order": list(self.DELETE_ORDER),
        }

    def soft_delete_sbom(self, sbom_id: int, user_id: str | None) -> dict[str, Any]:
        sbom = self.get_sbom(sbom_id)
        if sbom is None:
            raise LookupError("SBOM not found")
        try:
            cascaded_count = SoftDeleteService(self.db).soft_delete(
                sbom,
                user_id=user_id,
                cascade=True,
            )
            self._add_audit(
                sbom_id,
                user_id,
                "sbom.soft_delete",
                detail=f"cascaded={cascaded_count}",
                metadata={"cascaded_count": cascaded_count},
            )
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        return {
            "status": "deleted",
            "permanent": False,
            "cascaded_count": cascaded_count,
            "sbom_id": sbom_id,
            "requested_by": user_id,
            "message": f"SBOM {sbom_id} moved to deleted (recoverable).",
        }

    def permanently_delete_sbom(
        self,
        sbom_id: int,
        user_id: str | None,
        confirm: bool,
    ) -> dict[str, Any]:
        impact = self.get_delete_impact(sbom_id)
        if not confirm:
            raise SBOMDeleteConflict(
                "Permanent deletion requires confirm=yes.",
                impact=impact,
            )
        if not impact["can_delete"]:
            raise SBOMDeleteConflict(
                "SBOM cannot be permanently deleted because dependent records still exist.",
                blocking_dependencies=impact["blocking_dependencies"],
                impact=impact,
            )

        tree_ids = set(impact["child_sbom_ids"]) | {sbom_id}
        component_ids = self._ids(SBOMComponent.id, SBOMComponent.sbom_id.in_(tree_ids))
        run_ids = self._ids(AnalysisRun.id, AnalysisRun.sbom_id.in_(tree_ids))
        vex_document_ids = self._ids(VexDocument.id, VexDocument.sbom_id.in_(tree_ids))
        session_ids = self._ids(
            SBOMValidationSession.id,
            SBOMValidationSession.imported_sbom_id.in_(tree_ids),
        )

        try:
            # Repair workspaces and VEX/component-owned audit data.
            self._delete(
                SBOMValidationSessionEvent, SBOMValidationSessionEvent.session_id.in_(session_ids), session_ids
            )
            self._delete(
                VexStatement,
                or_(
                    VexStatement.sbom_id.in_(tree_ids),
                    VexStatement.vex_document_id.in_(vex_document_ids),
                    VexStatement.component_id.in_(component_ids),
                ),
            )
            self._delete(
                ComponentLifecycleOverrideAudit,
                ComponentLifecycleOverrideAudit.component_id.in_(component_ids),
                component_ids,
            )
            self._delete(VexOverrideAudit, VexOverrideAudit.component_id.in_(component_ids), component_ids)

            # Run-owned data. Project schedules that merely remember one of
            # these runs are detached, not deleted.
            self._delete(AnalysisFinding, AnalysisFinding.analysis_run_id.in_(run_ids), run_ids)
            self._delete(AiFixBatch, AiFixBatch.run_id.in_(run_ids), run_ids)
            self._delete(AnalysisSchedule, AnalysisSchedule.sbom_id.in_(tree_ids))
            if run_ids:
                self.db.execute(
                    update(AnalysisSchedule)
                    .where(
                        AnalysisSchedule.last_run_id.in_(run_ids),
                        AnalysisSchedule.tenant_id == self._tenant_id,
                    )
                    .values(last_run_id=None)
                    .execution_options(synchronize_session=False)
                )
                self.db.execute(
                    delete(CompareCache)
                    .where(
                        CompareCache.tenant_id == self._tenant_id,
                        or_(CompareCache.run_a_id.in_(run_ids), CompareCache.run_b_id.in_(run_ids)),
                    )
                    .execution_options(synchronize_session=False)
                )
            self._delete(RunCache, RunCache.sbom_id.in_(tree_ids))
            self._delete(AnalysisRun, AnalysisRun.sbom_id.in_(tree_ids))

            # Remaining direct SBOM children.
            self._delete(VexDocument, VexDocument.sbom_id.in_(tree_ids))
            self._delete(SBOMValidationSession, SBOMValidationSession.id.in_(session_ids), session_ids)
            self._delete(SBOMAnalysisReport, SBOMAnalysisReport.sbom_ref_id.in_(tree_ids))

            # A malformed cross-SBOM dedupe link must not cascade-delete a
            # component owned by a different SBOM.
            if component_ids:
                self.db.execute(
                    update(SBOMComponent)
                    .where(
                        SBOMComponent.duplicate_of_component_id.in_(component_ids),
                        SBOMComponent.sbom_id.not_in(tree_ids),
                        SBOMComponent.tenant_id == self._tenant_id,
                    )
                    .values(duplicate_of_component_id=None)
                    .execution_options(synchronize_session=False)
                )
            self._delete(SBOMComponent, SBOMComponent.sbom_id.in_(tree_ids))

            # Detach references from SBOMs outside the selected descendant
            # tree before deleting the tree itself.
            self.db.execute(
                update(SBOMSource)
                .where(
                    SBOMSource.id.not_in(tree_ids),
                    SBOMSource.parent_id.in_(tree_ids),
                    SBOMSource.tenant_id == self._tenant_id,
                )
                .values(parent_id=None)
                .execution_options(synchronize_session=False)
            )
            self.db.execute(
                update(SBOMSource)
                .where(
                    SBOMSource.id.not_in(tree_ids),
                    SBOMSource.source_sbom_id.in_(tree_ids),
                    SBOMSource.tenant_id == self._tenant_id,
                )
                .values(source_sbom_id=None)
                .execution_options(synchronize_session=False)
            )
            self.db.execute(
                update(SBOMSource)
                .where(
                    SBOMSource.id.not_in(tree_ids),
                    SBOMSource.converted_sbom_id.in_(tree_ids),
                    SBOMSource.tenant_id == self._tenant_id,
                )
                .values(converted_sbom_id=None)
                .execution_options(synchronize_session=False)
            )
            self._delete(SBOMSource, SBOMSource.id.in_(tree_ids))

            self._add_audit(
                sbom_id,
                user_id,
                "sbom.permanent_delete",
                detail=f"sboms={len(tree_ids)} runs={len(run_ids)}",
                metadata={
                    "deleted_sbom_ids": sorted(tree_ids),
                    "run_ids": sorted(run_ids),
                    "dependent_counts": impact["dependent_counts"],
                },
            )
            self.db.commit()
        except IntegrityError as exc:
            self.db.rollback()
            diagnostics = self._diagnose_blockers(sbom_id)
            log.warning(
                "sbom.permanent_delete_fk_conflict sbom_id=%s blockers=%s",
                sbom_id,
                diagnostics,
                exc_info=True,
            )
            raise SBOMDeleteConflict(
                "SBOM cannot be permanently deleted because dependent records still exist.",
                blocking_dependencies=diagnostics,
            ) from exc
        except Exception:
            self.db.rollback()
            raise

        return {
            "status": "deleted",
            "permanent": True,
            "message": f"SBOM {sbom_id} and related data have been permanently deleted.",
            "sbom_id": sbom_id,
            "deleted_sbom_ids": sorted(tree_ids),
            "requested_by": user_id,
        }

    def _dependency_tree(self, root_id: int) -> tuple[set[int], set[int], set[int]]:
        tree = {root_id}
        versions: set[int] = set()
        conversions: set[int] = set()
        frontier = {root_id}
        while frontier:
            outgoing_conversion_ids = set(
                self.db.execute(
                    select(SBOMSource.converted_sbom_id)
                    .where(
                        SBOMSource.id.in_(frontier),
                        SBOMSource.converted_sbom_id.is_not(None),
                    )
                    .execution_options(include_deleted=True)
                ).scalars()
            )
            rows = self.db.execute(
                select(
                    SBOMSource.id,
                    SBOMSource.parent_id,
                    SBOMSource.source_sbom_id,
                    SBOMSource.converted_sbom_id,
                )
                .where(
                    or_(
                        SBOMSource.parent_id.in_(frontier),
                        SBOMSource.source_sbom_id.in_(frontier),
                        SBOMSource.id.in_(outgoing_conversion_ids),
                    )
                )
                .execution_options(include_deleted=True)
            ).all()
            found: set[int] = set()
            for row in rows:
                if row.id in tree:
                    continue
                found.add(row.id)
                if row.parent_id in frontier:
                    versions.add(row.id)
                if row.source_sbom_id in frontier or row.id in outgoing_conversion_ids:
                    conversions.add(row.id)
            tree.update(found)
            frontier = found
        return tree, versions, conversions

    def _ids(self, column, criterion) -> set[Any]:
        return set(self.db.execute(select(column).where(criterion).execution_options(include_deleted=True)).scalars())

    def _count(self, column, criterion, empty_ids: set[Any] | None = None) -> int:
        if empty_ids is not None and not empty_ids:
            return 0
        value = self.db.execute(
            select(func.count(column)).where(criterion).execution_options(include_deleted=True)
        ).scalar_one()
        return int(value or 0)

    def _delete(self, model, criterion, required_ids: set[Any] | None = None) -> None:
        if required_ids is not None and not required_ids:
            return
        statement = delete(model).where(criterion)
        if self._tenant_id is not None and hasattr(model, "tenant_id"):
            statement = statement.where(model.tenant_id == self._tenant_id)
        self.db.execute(statement.execution_options(synchronize_session=False))

    def _unknown_fk_dependencies(self, target_ids: dict[str, set[Any]]) -> dict[str, int]:
        bind = self.db.get_bind()
        inspector = inspect(bind)
        metadata = MetaData()
        unknown: dict[str, int] = {}
        for table_name in inspector.get_table_names():
            for fk in inspector.get_foreign_keys(table_name):
                referred = fk.get("referred_table")
                ids = target_ids.get(str(referred))
                columns = fk.get("constrained_columns") or []
                if not ids or len(columns) != 1:
                    continue
                edge = (table_name, columns[0], str(referred))
                if edge in self._HANDLED_FK_EDGES:
                    continue
                table = Table(table_name, metadata, autoload_with=bind)
                count = self.db.execute(
                    select(func.count()).select_from(table).where(table.c[columns[0]].in_(ids))
                ).scalar_one()
                if count:
                    unknown[table_name] = unknown.get(table_name, 0) + int(count)
        return unknown

    def _diagnose_blockers(self, sbom_id: int) -> dict[str, int]:
        try:
            impact = self.get_delete_impact(sbom_id)
        except Exception:
            return {"unknown_foreign_key_dependency": 1}
        if impact["blocking_dependencies"]:
            return impact["blocking_dependencies"]
        return {name: count for name, count in impact["table_counts"].items() if count} or {
            "unknown_foreign_key_dependency": 1
        }

    def _add_audit(
        self,
        sbom_id: int,
        user_id: str | None,
        action: str,
        *,
        detail: str,
        metadata: dict[str, Any],
    ) -> None:
        self.db.add(
            AuditLog(
                user_id=user_id,
                action=action,
                target_kind="sbom",
                target_id=sbom_id,
                detail=detail[:240],
                metadata_json=metadata,
                created_at=datetime.now(UTC).isoformat(),
            )
        )


__all__ = ["SBOMDeleteConflict", "SBOMDeleteService"]
