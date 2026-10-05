"""Append-only recommendation audit events (FR-SCA-022, NFR-SCA-007, US-SCA-15).

Each event records, where applicable: tenant, source component, candidate,
recommendation id, score / policy versions, evidence references, confidence,
decision, actor, timestamp, reason, old / new state, correlation id and
source (API or TASK). Writes flush in the caller's transaction and never
commit, like ``app/services/vex/audit.py``; rows are append-only (ORM guard in
``app.models``).
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from sqlalchemy.orm import Session

from ....models import ComponentRecommendationEvent


class EventAction(str, Enum):
    CREATED = "CREATED"
    CANDIDATE_DISCOVERED = "CANDIDATE_DISCOVERED"
    COMPATIBILITY_EVALUATED = "COMPATIBILITY_EVALUATED"
    CANDIDATE_SCORED = "CANDIDATE_SCORED"
    DISCOVERY_COMPLETED = "DISCOVERY_COMPLETED"
    MOVED_TO_REVIEW = "MOVED_TO_REVIEW"
    CANDIDATE_ADDED = "CANDIDATE_ADDED"
    RECOMMENDED = "RECOMMENDED"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    DEFERRED = "DEFERRED"
    MORE_EVIDENCE_REQUESTED = "MORE_EVIDENCE_REQUESTED"
    CLOSED = "CLOSED"
    POLICY_VERSION_PUBLISHED = "POLICY_VERSION_PUBLISHED"


def candidate_view(row) -> dict[str, Any]:
    """What an event remembers about a candidate (it may later be replaced)."""
    return {
        "id": row.id, "name": row.name, "version": row.version, "candidate_kind": row.candidate_kind,
        "source_type": row.source_type, "canonical_key": row.candidate_canonical_key,
        "blocked": bool(row.blocked), "rank": row.rank,
    }


def record_event(
    db: Session,
    *,
    tenant_id: int,
    action: EventAction,
    context=None,
    recommendation=None,
    candidate=None,
    decision: str | None = None,
    reason: str | None = None,
    old_status: str | None = None,
    new_status: str | None = None,
    policy_versions: dict[str, Any] | None = None,
    score: float | None = None,
    confidence: str | None = None,
    evidence_refs: list | None = None,
    details: dict[str, Any] | None = None,
    correlation_id: str | None = None,
    source: str = "API",
) -> ComponentRecommendationEvent:
    """Append one event. Does not commit."""
    event = ComponentRecommendationEvent(
        tenant_id=tenant_id,
        recommendation_id=recommendation.id if recommendation is not None else None,
        candidate_id=candidate.id if candidate is not None else None,
        candidate_json=candidate_view(candidate) if candidate is not None else None,
        action=action.value,
        decision=decision,
        actor=(context.actor_label() if context is not None else "system"),
        actor_user_id=(context.user_id if context is not None and context.user_id else None),
        reason=reason,
        old_status=old_status,
        new_status=new_status,
        policy_versions_json=policy_versions,
        score=score,
        confidence=confidence,
        evidence_refs_json=evidence_refs,
        details_json=details,
        correlation_id=correlation_id or (recommendation.correlation_id if recommendation is not None else None),
        source=source if context is not None else "TASK",
        created_at=datetime.now(UTC),
    )
    db.add(event)
    db.flush()
    return event


def serialize_event(event: ComponentRecommendationEvent) -> dict[str, Any]:
    return {
        "id": event.id,
        "recommendation_id": event.recommendation_id,
        "candidate_id": event.candidate_id,
        "candidate": event.candidate_json,
        "action": event.action,
        "decision": event.decision,
        "actor": event.actor,
        "actor_user_id": event.actor_user_id,
        "reason": event.reason,
        "old_status": event.old_status,
        "new_status": event.new_status,
        "policy_versions": event.policy_versions_json,
        "score": event.score,
        "confidence": event.confidence,
        "evidence_refs": event.evidence_refs_json,
        "details": event.details_json,
        "correlation_id": event.correlation_id,
        "source": event.source,
        "created_at": event.created_at.isoformat() if event.created_at else None,
    }


__all__ = ["EventAction", "candidate_view", "record_event", "serialize_event"]
