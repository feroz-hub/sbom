"""Recommendation work items: create, evaluate, read (FR-SCA-011/013, NFR-SCA-004).

* :func:`create_recommendation` — validates the trigger against current
  evidence and is idempotent: an equivalent open item is returned instead of
  a duplicate (T20). The DB partial unique index is the final guard against
  races.
* :func:`evaluate_recommendation` — OPEN/REVIEW_REQUIRED → EVALUATING →
  REVIEW_REQUIRED. Same-family discovery runs over the *tenant-wide* eligible
  snapshot (tenant-observed candidates come from the whole tenant, never
  another tenant). Safe to retry: a work item that cannot be evaluated in its
  current state is returned unchanged.

Advisory only: these functions write ``component_recommendation`` /
``component_recommendation_candidate`` and audit rows, nothing else.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ....logger import get_logger, log_event
from ....metrics.component_advisor import advisor_remediation_hints
from ....models import ComponentRecommendation, ComponentRecommendationCandidate
from ...audit_service import write_audit_log
from ...dashboard_scope import DashboardScope, dashboard_scope
from ..intelligence_service import cached_snapshot, get_component_version
from .version_discovery import discover_same_family
from .workflow import (
    OPEN_STATUSES,
    RecommendationStatus,
    TriggerType,
    can_evaluate,
    eligible_triggers,
    require_transition,
    trigger_evidence,
)

logger = get_logger("sbom.component_advisor.recommendations")

_OPEN_VALUES = sorted(status.value for status in OPEN_STATUSES)


class RecommendationNotFound(LookupError):
    pass


def _now() -> datetime:
    return datetime.now(UTC)


def _open_item(db: Session, tenant_id: int, canonical_key: str, scope_key: int, trigger: TriggerType):
    return db.scalars(
        select(ComponentRecommendation).where(
            ComponentRecommendation.tenant_id == tenant_id,
            ComponentRecommendation.source_canonical_key == canonical_key,
            ComponentRecommendation.scope_key == scope_key,
            ComponentRecommendation.trigger_type == trigger.value,
            ComponentRecommendation.status.in_(_OPEN_VALUES),
        )
    ).first()


def create_recommendation(
    db: Session,
    *,
    context,
    scope: DashboardScope,
    canonical_key: str,
    trigger: TriggerType | str,
    correlation_id: str | None = None,
    request=None,
) -> tuple[ComponentRecommendation, bool]:
    """``(item, created)``. Raises ``RecommendationNotFound`` / ``TriggerNotSupported``."""
    trigger = TriggerType(trigger)
    version = get_component_version(db, scope, canonical_key)
    if version is None:
        raise RecommendationNotFound("Component not found")
    evidence = trigger_evidence(version, trigger)
    scope_key = scope.sbom_id or 0
    existing = _open_item(db, scope.tenant_id, canonical_key, scope_key, trigger)
    if existing is not None:
        return existing, False

    now = _now()
    lead = version.references[0] if version.references else {}
    item = ComponentRecommendation(
        tenant_id=scope.tenant_id,
        project_id=scope.project_id,
        product_id=scope.product_id,
        sbom_id=scope.sbom_id,
        scope_key=scope_key,
        source_component_id=lead.get("component_id") if scope.sbom_id else None,
        source_canonical_key=canonical_key,
        source_family_key=version.family_key,
        source_name=version.name,
        source_version=version.version,
        source_ecosystem=version.ecosystem,
        trigger_type=trigger.value,
        trigger_evidence_json={**evidence, "scope_level": scope.level},
        status=RecommendationStatus.OPEN.value,
        correlation_id=correlation_id,
        created_by=context.actor_label() if context else "system",
        created_at=now,
        updated_at=now,
        row_version=1,
    )
    try:
        with db.begin_nested():
            db.add(item)
            db.flush()
    except IntegrityError:
        # A concurrent request created the same open item first (T20).
        existing = _open_item(db, scope.tenant_id, canonical_key, scope_key, trigger)
        if existing is None:
            raise
        return existing, False
    write_audit_log(
        db, context, "component_advisor.recommendation.created", entity_type="component_recommendation",
        entity_id=item.id, new_value=_audit_view(item), request=request,
        detail=f"{trigger.value} for {version.name} {version.version or ''}".strip()[:240],
    )
    log_event(logger, "recommendation.created", tenant_id=scope.tenant_id, recommendation_id=item.id,
              trigger_type=trigger.value, correlation_id=correlation_id)
    return item, True


def get_recommendation(db: Session, tenant_id: int, recommendation_id: int, *, lock: bool = False) -> ComponentRecommendation:
    """Tenant-scoped fetch; another tenant's id is indistinguishable from a missing one."""
    statement = select(ComponentRecommendation).where(
        ComponentRecommendation.id == recommendation_id, ComponentRecommendation.tenant_id == tenant_id
    )
    if lock:
        statement = statement.with_for_update()
    item = db.scalars(statement).first()
    if item is None:
        raise RecommendationNotFound("Recommendation not found")
    return item


def evaluate_recommendation(
    db: Session, *, tenant_id: int, recommendation_id: int, context=None, correlation_id: str | None = None,
    request=None,
) -> ComponentRecommendation:
    """Run same-family discovery and move the item to REVIEW_REQUIRED. Does not commit."""
    item = get_recommendation(db, tenant_id, recommendation_id, lock=True)
    if not can_evaluate(item.status):
        return item
    previous_status = item.status
    item.status = require_transition(item.status, RecommendationStatus.EVALUATING).value
    item.updated_at = _now()
    db.flush()
    started = time.perf_counter()
    log_event(logger, "recommendation.discovery.started", tenant_id=tenant_id, recommendation_id=item.id,
              correlation_id=correlation_id)

    tenant_scope = DashboardScope(tenant_id)
    error = None
    try:
        with db.begin_nested(), dashboard_scope(db, tenant_scope):
            snapshot = cached_snapshot(db, tenant_scope)
            source = next((v for v in snapshot.versions if v.canonical_key == item.source_canonical_key), None)
            db.query(ComponentRecommendationCandidate).filter(
                ComponentRecommendationCandidate.recommendation_id == item.id,
                ComponentRecommendationCandidate.tenant_id == tenant_id,
            ).delete(synchronize_session=False)
            if source is None:
                summary = {"status": "SOURCE_NOT_IN_CURRENT_DATASET", "same_family_candidates": 0,
                           "alternative_candidates": 0, "alternatives_status": "NOT_EVALUATED", "excluded": []}
            else:
                family = [v for v in snapshot.versions if source.family_key and v.family_key == source.family_key]
                hints = advisor_remediation_hints(
                    db, tenant_id=tenant_id, sbom_ids=tenant_scope.eligible_sbom_ids(),
                    component_ids=[ref["component_id"] for ref in source.references],
                )
                actionable = set(source.actionable_vulnerability_ids)
                result = discover_same_family(
                    source, family,
                    lifecycle_hints=hints["lifecycle"],
                    fixed_versions={k: v for k, v in hints["fixed_versions"].items() if k in actionable},
                )
                summary = result.summary()
                if not source.family_key:
                    summary["status"] = "INSUFFICIENT_IDENTITY_EVIDENCE"
                now = _now()
                for candidate in result.candidates:
                    db.add(ComponentRecommendationCandidate(
                        tenant_id=tenant_id, recommendation_id=item.id,
                        candidate_kind=candidate.kind.value, source_type=candidate.source_type.value,
                        candidate_canonical_key=candidate.canonical_key, name=candidate.name,
                        version=candidate.version, purl=candidate.purl, ecosystem=candidate.ecosystem,
                        rank=candidate.rank, evidence_sources_json=candidate.evidence_sources,
                        reasons_json=candidate.reasons, limitations_json=candidate.limitations,
                        evaluation_json=candidate.evaluation, created_at=now,
                    ))
                summary["source_posture"] = {
                    "classification": source.classification.value,
                    "highest_actionable_severity": source.highest_actionable_severity,
                    "actionable_vulnerability_ids": list(source.actionable_vulnerability_ids),
                    "lifecycle_bucket": source.lifecycle.bucket.value,
                    "evidence": [dict(e) for e in source.evidence],
                }
            db.flush()
    except Exception as exc:  # noqa: BLE001 - degraded state is recorded, never a silent pass
        error = f"{type(exc).__name__}: {exc}"[:2000]
        summary = {"status": "DISCOVERY_FAILED", "same_family_candidates": 0, "alternative_candidates": 0,
                   "alternatives_status": "NOT_EVALUATED", "excluded": []}
        log_event(logger, "recommendation.discovery.failed", tenant_id=tenant_id, recommendation_id=item.id,
                  error_type=type(exc).__name__, correlation_id=correlation_id)

    now = _now()
    item.status = require_transition(item.status, RecommendationStatus.REVIEW_REQUIRED).value
    item.discovery_summary_json = summary
    item.evaluation_error = error
    item.evaluated_at = now
    item.updated_at = now
    item.row_version = (item.row_version or 1) + 1
    if correlation_id:
        item.correlation_id = item.correlation_id or correlation_id
    db.flush()
    duration_ms = round((time.perf_counter() - started) * 1000, 1)
    write_audit_log(
        db, context, "component_advisor.recommendation.evaluated", entity_type="component_recommendation",
        entity_id=item.id, old_value={"status": previous_status}, new_value={**_audit_view(item), "duration_ms": duration_ms},
        request=request, detail=summary["status"],
    )
    log_event(logger, "recommendation.discovery.completed", tenant_id=tenant_id, recommendation_id=item.id,
              status=summary["status"], candidates=summary.get("same_family_candidates", 0),
              duration_ms=duration_ms, correlation_id=correlation_id)
    return item


def list_recommendations(
    db: Session, *, tenant_id: int, status: list[str] | None = None, trigger_type: str | None = None,
    canonical_key: str | None = None, sbom_id: int | None = None, limit: int = 50, offset: int = 0,
) -> dict[str, Any]:
    conditions = [ComponentRecommendation.tenant_id == tenant_id]
    if status:
        conditions.append(ComponentRecommendation.status.in_([RecommendationStatus(s.upper()).value for s in status]))
    if trigger_type:
        conditions.append(ComponentRecommendation.trigger_type == TriggerType(trigger_type.upper()).value)
    if canonical_key:
        conditions.append(ComponentRecommendation.source_canonical_key == canonical_key)
    if sbom_id is not None:
        conditions.append(ComponentRecommendation.sbom_id == sbom_id)
    total = db.scalar(select(func.count(ComponentRecommendation.id)).where(*conditions)) or 0
    rows = db.scalars(
        select(ComponentRecommendation).where(*conditions)
        .order_by(ComponentRecommendation.updated_at.desc(), ComponentRecommendation.id.desc())
        .limit(limit).offset(offset)
    ).all()
    return {"total": int(total), "limit": limit, "offset": offset, "items": [serialize(row) for row in rows]}


def open_recommendations_by_key(db: Session, tenant_id: int) -> dict[str, dict[str, Any]]:
    """Latest open item per source canonical key (component list / detail badge)."""
    rows = db.execute(
        select(ComponentRecommendation.source_canonical_key, ComponentRecommendation.id,
               ComponentRecommendation.status, ComponentRecommendation.trigger_type)
        .where(ComponentRecommendation.tenant_id == tenant_id, ComponentRecommendation.status.in_(_OPEN_VALUES))
        .order_by(ComponentRecommendation.id)
    ).all()
    return {key: {"status": status, "id": rid, "trigger_type": trigger} for key, rid, status, trigger in rows}


def _audit_view(item: ComponentRecommendation) -> dict[str, Any]:
    return {
        "id": item.id, "status": item.status, "trigger_type": item.trigger_type,
        "source_canonical_key": item.source_canonical_key, "source_name": item.source_name,
        "source_version": item.source_version, "sbom_id": item.sbom_id, "correlation_id": item.correlation_id,
        "discovery_status": (item.discovery_summary_json or {}).get("status"),
    }


def serialize_candidate(candidate: ComponentRecommendationCandidate) -> dict[str, Any]:
    return {
        "id": candidate.id,
        "candidate_kind": candidate.candidate_kind,
        "source_type": candidate.source_type,
        "canonical_key": candidate.candidate_canonical_key,
        "name": candidate.name,
        "version": candidate.version,
        "purl": candidate.purl,
        "ecosystem": candidate.ecosystem,
        "rank": candidate.rank,
        "evidence_sources": list(candidate.evidence_sources_json or []),
        "reasons": list(candidate.reasons_json or []),
        "limitations": list(candidate.limitations_json or []),
        "evaluation": dict(candidate.evaluation_json or {}),
        # Scoring, confidence and compatibility gates arrive in Steps 6–7; until
        # then no candidate can be represented as an approved replacement.
        "score": candidate.score,
        "confidence": candidate.confidence or "NOT_EVALUATED",
        "blocked": bool(candidate.blocked),
        "approved_replacement": False,
    }


def serialize(item: ComponentRecommendation, *, candidates: bool = False, capabilities: dict | None = None) -> dict[str, Any]:
    payload = {
        "id": item.id,
        "status": item.status,
        "trigger_type": item.trigger_type,
        "trigger_evidence": dict(item.trigger_evidence_json or {}),
        "source": {
            "canonical_key": item.source_canonical_key,
            "family_key": item.source_family_key,
            "name": item.source_name,
            "version": item.source_version,
            "ecosystem": item.source_ecosystem,
            "component_id": item.source_component_id,
        },
        "context": {"project_id": item.project_id, "product_id": item.product_id, "sbom_id": item.sbom_id,
                    "level": "SBOM" if item.sbom_id else "TENANT"},
        "discovery": dict(item.discovery_summary_json or {}) or {"status": "NOT_EVALUATED"},
        "evaluation_error": item.evaluation_error,
        "correlation_id": item.correlation_id,
        "created_by": item.created_by,
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "updated_at": item.updated_at.isoformat() if item.updated_at else None,
        "evaluated_at": item.evaluated_at.isoformat() if item.evaluated_at else None,
        "row_version": item.row_version,
        # Spec §1.1: the advisor never changes dependencies; surfaced so no UI implies otherwise.
        "advisory_only": True,
    }
    if candidates:
        payload["candidates"] = [serialize_candidate(c) for c in sorted(item.candidates, key=lambda c: c.rank)]
    if capabilities is not None:
        payload["capabilities"] = capabilities
    return payload


def capabilities_for(item: ComponentRecommendation, context) -> dict[str, Any]:
    can_create = bool(context and context.has_permission("component_advisor:recommendation:create"))
    return {
        "can_evaluate": can_create and can_evaluate(item.status),
        # Decisions (Accept / Reject / Defer / Request evidence) arrive in Step 8.
        "can_decide": False,
        "read_only_reason": None if can_create else "Requires component_advisor:recommendation:create",
    }


__all__ = [
    "RecommendationNotFound",
    "capabilities_for",
    "create_recommendation",
    "eligible_triggers",
    "evaluate_recommendation",
    "get_recommendation",
    "list_recommendations",
    "open_recommendations_by_key",
    "serialize",
    "serialize_candidate",
]
