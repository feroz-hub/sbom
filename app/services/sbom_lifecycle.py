"""Operational SBOM lifecycle, separate from soft deletion and validation.

All processing entry points use the same eligibility verdict. Lifecycle writes
lock the SBOM row; analysis writers take the same lock and compare revisions,
so an old in-flight job cannot become current after a deactivate/reactivate.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

from fastapi import HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.context import CurrentContext, get_bound_context
from ..core.permissions import normalize_role
from ..logger import log_event
from ..models import AnalysisRun, AuditLog, CveCache, NvdLookupCache, SBOMSource, SourceResponseCache
from .audit_service import _correlation_id, write_audit_log

log = logging.getLogger("sbom.lifecycle")


def processing_eligibility(sbom: SBOMSource) -> dict:
    if sbom.lifecycle_status == "INACTIVE":
        return {"eligible": False, "reason_code": "SBOM_INACTIVE", "reason": "Analysis unavailable because this SBOM is inactive."}
    status = (sbom.status or "").lower()
    if status == "quarantined":
        code, reason = "SBOM_UNSAFE", "Processing unavailable because this SBOM is unsafe or quarantined."
    elif status == "pending":
        code, reason = "SBOM_VALIDATION_PENDING", "Processing unavailable while SBOM validation is pending."
    elif status != "validated" or (sbom.error_count or 0) > 0 or any(
        str(entry.get("severity", "")).lower() == "error" for entry in (sbom.validation_errors or []) if isinstance(entry, dict)
    ):
        code, reason = "SBOM_VALIDATION_BLOCKED", "Processing unavailable because this SBOM has unresolved blocking validation failures."
    else:
        return {"eligible": True, "reason_code": None, "reason": None}
    return {"eligible": False, "reason_code": code, "reason": reason}


def require_processing(sbom: SBOMSource | None, *, operation: str = "Analysis") -> None:
    if sbom is None:
        raise HTTPException(404, detail="SBOM not found")
    context = get_bound_context()
    if context and context.tenant_id != sbom.tenant_id:
        raise HTTPException(404, detail="SBOM not found")
    if operation != "Analysis" and sbom.analysis_requires_reanalysis and sbom.lifecycle_status == "ACTIVE":
        raise HTTPException(409, detail={"code": "SBOM_REANALYSIS_REQUIRED", "message": "Run a new analysis before generating current comparisons or reports.", "sbom_id": sbom.id})
    verdict = processing_eligibility(sbom)
    if not verdict["eligible"]:
        message = verdict["reason"]
        if verdict["reason_code"] == "SBOM_INACTIVE":
            message = f"{operation} unavailable because this SBOM is inactive."
        raise HTTPException(409, detail={"code": verdict["reason_code"], "message": message, "sbom_id": sbom.id})


def lock_sbom(db: Session, sbom_id: int, tenant_id: int) -> SBOMSource | None:
    return db.scalar(select(SBOMSource).where(SBOMSource.id == sbom_id, SBOMSource.tenant_id == tenant_id)
                     .with_for_update().execution_options(populate_existing=True))


@lru_cache(maxsize=1)
def validation_rules_fingerprint() -> str:
    root = Path(__file__).resolve().parents[1] / "validation"
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix in {".py", ".json", ".xsd"}:
            digest.update(str(path.relative_to(root)).encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


def analysis_fingerprint(db: Session, sbom: SBOMSource) -> dict:
    # The app uses TTL provider caches, not a single NVD dataset version.
    # Cache revisions + expiry are a conservative equivalent; absent/expired
    # evidence never establishes freshness on reactivation.
    sources = []
    for model, updated in ((SourceResponseCache, SourceResponseCache.fetched_at),
                           (NvdLookupCache, NvdLookupCache.updated_at), (CveCache, CveCache.fetched_at)):
        count, latest, expiry = db.execute(select(func.count(), func.max(updated), func.min(model.expires_at)).select_from(model)).one()
        sources.append({"cache": model.__tablename__, "count": count, "latest": latest, "expires_at": expiry})
    return {"checksum": hashlib.sha256((sbom.sbom_data or "").encode()).hexdigest(),
            "validation_rules": validation_rules_fingerprint(), "validated_at": sbom.validated_at,
            "sources": sources}


def fingerprint_is_fresh(saved: dict | None, current: dict) -> bool:
    if not saved or saved != current:
        return False
    evidence = [entry for entry in saved.get("sources", []) if entry.get("count")]
    if not evidence:
        return False
    now = datetime.now(UTC)
    try:
        expiries = [datetime.fromisoformat(entry["expires_at"].replace("Z", "+00:00")) for entry in evidence]
        return all((expiry if expiry.tzinfo else expiry.replace(tzinfo=UTC)) > now for expiry in expiries)
    except (KeyError, ValueError, TypeError):
        return False


def analysis_task_id(tenant_id: int, sbom_id: int, revision: int) -> str:
    return f"sbom-analysis-{tenant_id}-{sbom_id}-{revision}"


def transition_lifecycle(db: Session, context: CurrentContext, sbom_id: int, new_status: str, reason: str,
                         request: Request | None = None) -> SBOMSource:
    if not context.has_permission("sbom:delete") or not (
        context.is_platform_admin or "TENANT_ADMIN" in {normalize_role(role) for role in context.roles}
    ):
        raise HTTPException(403, detail="Administrator permission is required to change SBOM lifecycle.")
    if context.tenant_id is None:
        raise HTTPException(403, detail="Tenant selection required")
    if new_status not in {"ACTIVE", "INACTIVE"}:
        raise HTTPException(422, detail="Lifecycle status must be ACTIVE or INACTIVE")
    reason = reason.strip()
    if not reason:
        raise HTTPException(422, detail={"code": "SBOM_LIFECYCLE_REASON_REQUIRED", "message": "A lifecycle change reason is required."})
    sbom = lock_sbom(db, sbom_id, context.tenant_id)
    if sbom is None:
        raise HTTPException(404, detail="SBOM not found")
    old_status = sbom.lifecycle_status
    if new_status == old_status:
        raise HTTPException(409, detail={"code": "SBOM_LIFECYCLE_TRANSITION_INVALID", "message": f"SBOM is already {new_status.lower()}."})
    old_revision = sbom.lifecycle_revision
    sbom.lifecycle_revision = old_revision + 1
    sbom.lifecycle_status = new_status
    runs = list(db.scalars(select(AnalysisRun).where(AnalysisRun.sbom_id == sbom.id, AnalysisRun.tenant_id == context.tenant_id)))
    if new_status == "INACTIVE":
        for run in runs:
            if run.run_status in {"PENDING", "QUEUED", "RUNNING", "ANALYSING", "ANALYZING"}:
                run.is_current = False
                if run.run_status in {"PENDING", "QUEUED"}:
                    run.run_status = "CANCELLED"
                    run.completed_on = datetime.now(UTC).isoformat()
    else:
        from .analysis_service import SUCCESSFUL_RUN_STATUSES
        successful = [run for run in runs if run.is_current and run.run_status in SUCCESSFUL_RUN_STATUSES]
        latest = max(successful, key=lambda run: run.id, default=None)
        fresh = processing_eligibility(sbom)["eligible"] and latest is not None and fingerprint_is_fresh(
            latest.analysis_input_fingerprint, analysis_fingerprint(db, sbom))
        sbom.analysis_requires_reanalysis = not fresh
        if not fresh:
            for run in runs:
                run.is_current = False
    action = "sbom.activate" if new_status == "ACTIVE" else "sbom.deactivate"
    metadata = {"sbom_id": sbom.id, "tenant_id": context.tenant_id, "actor_id": context.user_id,
                "old_status": old_status, "new_status": new_status, "reason": reason,
                "lifecycle_revision": sbom.lifecycle_revision, "reanalysis_required": sbom.analysis_requires_reanalysis}
    try:
        write_audit_log(db, context, action, entity_type="sbom", entity_id=sbom.id,
                        old_value={"lifecycle_status": old_status}, new_value={"lifecycle_status": new_status},
                        metadata_json=metadata, detail=reason, request=request, strict=True)
        db.flush()
        db.commit()
    except Exception:
        db.rollback()
        raise
    # Broker operations happen only after the durable status + audit commit.
    if new_status == "INACTIVE":
        try:
            from ..workers.celery_app import celery_app
            celery_app.control.revoke(analysis_task_id(context.tenant_id, sbom.id, old_revision), terminate=False)
        except Exception:
            log_event(log, "sbom_lifecycle_queue_revoke_failed", level=logging.WARNING,
                      tenant_id=context.tenant_id, sbom_id=sbom.id, actor_id=context.user_id)
    from .dashboard_metrics import reset_lifetime_cache
    reset_lifetime_cache()
    log_event(log, "sbom_lifecycle_changed", request_id=_correlation_id(request),
              tenant_id=context.tenant_id, sbom_id=sbom.id, actor_id=context.user_id,
              old_status=old_status, new_status=new_status, lifecycle_action=action)
    return sbom


def lifecycle_history(db: Session, tenant_id: int, sbom_id: int) -> list[dict]:
    sbom = db.scalar(select(SBOMSource).where(SBOMSource.id == sbom_id, SBOMSource.tenant_id == tenant_id))
    if sbom is None:
        raise HTTPException(404, detail="SBOM not found")
    rows = db.scalars(select(AuditLog).where(AuditLog.tenant_id == tenant_id, AuditLog.target_id == sbom_id,
                       AuditLog.target_kind == "sbom", AuditLog.action.in_(["sbom.activate", "sbom.deactivate"]))
                      .order_by(AuditLog.id.desc()))
    return [{"id": row.id, "sbom_id": sbom_id, "tenant_id": tenant_id, "actor": row.user_id,
             "actor_id": row.user_ref_id, "timestamp": row.created_at, **(row.metadata_json or {})} for row in rows]
