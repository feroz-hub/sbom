"""Persistence, scoping and versioning of advisor policies (FR-SCA-004/005, NFR-SCA-007).

Shape follows ``docs/scoped-configuration.md``: a platform default slot
(``tenant_id IS NULL``) and at most one tenant override slot per kind.
Resolution for a tenant:

1. The tenant slot's latest version, if any:
   ACTIVE → that version applies; DISABLED → no policy (the platform default
   is deliberately blocked); INHERIT → fall through to the platform slot.
2. Otherwise the platform slot's latest version if ACTIVE.
3. Otherwise no policy — and no component is Accepted Risk / Trusted.

Versions are append-only (an ORM guard in ``app.models`` rejects updates and
deletes), so changing a policy never rewrites the evidence behind an earlier
classification (US-SCA-03). Publishing uses optimistic concurrency on the
slot's ``row_version``. Every query filters on tenant explicitly: these
tables are not ``TenantOwnedMixin`` because platform rows have NULL tenant.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...models import AdvisorPolicy, AdvisorPolicyVersion
from ..audit_service import write_audit_log
from ..configuration_scope import scope_clause
from .policy import PolicyKind, PolicyStatus, PolicyValidationError, PolicyVersionRef, validate_rules


class PolicyConflict(RuntimeError):
    """``expected_row_version`` did not match the slot (HTTP 409)."""

    def __init__(self, current_row_version: int):
        super().__init__("Policy changed since it was read")
        self.current_row_version = current_row_version


@dataclass(frozen=True)
class EffectivePolicies:
    accepted_risk: PolicyVersionRef | None
    trust: PolicyVersionRef | None

    def key(self) -> tuple:
        return (
            self.accepted_risk.id if self.accepted_risk else None,
            self.trust.id if self.trust else None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted_risk": _summary(self.accepted_risk),
            "trust": _summary(self.trust),
        }


def _summary(ref: PolicyVersionRef | None) -> dict[str, Any] | None:
    if ref is None:
        return None
    return {"policy_version_id": ref.id, "version": ref.version, "scope": ref.scope}


def _slot(db: Session, tenant_id: int | None, kind: PolicyKind, *, lock: bool = False) -> AdvisorPolicy | None:
    statement = select(AdvisorPolicy).where(scope_clause(AdvisorPolicy, tenant_id), AdvisorPolicy.kind == kind.value)
    if lock:
        statement = statement.with_for_update()
    return db.scalars(statement).first()


def _latest(db: Session, policy_id: int) -> AdvisorPolicyVersion | None:
    return db.scalars(
        select(AdvisorPolicyVersion)
        .where(AdvisorPolicyVersion.policy_id == policy_id)
        .order_by(AdvisorPolicyVersion.version.desc())
        .limit(1)
    ).first()


def _ref(row: AdvisorPolicyVersion) -> PolicyVersionRef:
    return PolicyVersionRef(
        id=row.id,
        policy_id=row.policy_id,
        kind=PolicyKind(row.kind),
        version=row.version,
        status=PolicyStatus(row.status),
        scope="PLATFORM" if row.tenant_id is None else "TENANT",
        rules=dict(row.rules_json or {}),
        created_at=row.created_at.isoformat() if row.created_at else None,
    )


def effective_policy(db: Session, tenant_id: int, kind: PolicyKind) -> PolicyVersionRef | None:
    """The version that applies to ``tenant_id`` now, or ``None``."""
    tenant_slot = _slot(db, tenant_id, kind)
    if tenant_slot is not None:
        latest = _latest(db, tenant_slot.id)
        if latest is not None and latest.status != PolicyStatus.INHERIT.value:
            return _ref(latest) if latest.status == PolicyStatus.ACTIVE.value else None
    platform_slot = _slot(db, None, kind)
    if platform_slot is not None:
        latest = _latest(db, platform_slot.id)
        if latest is not None and latest.status == PolicyStatus.ACTIVE.value:
            return _ref(latest)
    return None


def effective_policies(db: Session, tenant_id: int) -> EffectivePolicies:
    return EffectivePolicies(
        accepted_risk=effective_policy(db, tenant_id, PolicyKind.ACCEPTED_RISK),
        trust=effective_policy(db, tenant_id, PolicyKind.TRUST),
    )


def policy_state(db: Session, tenant_id: int, kind: PolicyKind) -> dict[str, Any]:
    """What GET /policies/{kind} returns: effective, tenant override and platform default."""
    tenant_slot = _slot(db, tenant_id, kind)
    platform_slot = _slot(db, None, kind)
    tenant_latest = _latest(db, tenant_slot.id) if tenant_slot else None
    platform_latest = _latest(db, platform_slot.id) if platform_slot else None
    effective = effective_policy(db, tenant_id, kind)
    return {
        "kind": kind.value,
        "configured": effective is not None,
        "effective": effective.to_dict() if effective else None,
        "tenant_override": _ref(tenant_latest).to_dict() if tenant_latest else None,
        "platform_default": _ref(platform_latest).to_dict() if platform_latest else None,
        "row_version": tenant_slot.row_version if tenant_slot else 0,
    }


def list_versions(db: Session, tenant_id: int, kind: PolicyKind) -> list[dict[str, Any]]:
    """The tenant's version history for ``kind``, newest first (US-SCA-03)."""
    slot = _slot(db, tenant_id, kind)
    if slot is None:
        return []
    rows = db.scalars(
        select(AdvisorPolicyVersion)
        .where(AdvisorPolicyVersion.policy_id == slot.id, AdvisorPolicyVersion.tenant_id == tenant_id)
        .order_by(AdvisorPolicyVersion.version.desc())
    ).all()
    return [{**_ref(row).to_dict(), "reason": row.reason, "created_by": row.created_by} for row in rows]


def publish_version(
    db: Session,
    *,
    context,
    kind: PolicyKind,
    status: PolicyStatus,
    rules: dict[str, Any] | None,
    reason: str,
    expected_row_version: int,
    correlation_id: str | None = None,
    request=None,
) -> PolicyVersionRef:
    """Append a new tenant policy version. Does not commit.

    ``expected_row_version`` is 0 for a tenant with no override yet.
    ACTIVE requires valid rules; DISABLED / INHERIT store no rules.
    """
    tenant_id = context.tenant_id
    if tenant_id is None:
        raise PolicyValidationError("A tenant context is required to publish a tenant policy")
    if not (reason or "").strip():
        raise PolicyValidationError("reason is required")
    normalized = validate_rules(kind, rules or {}) if status is PolicyStatus.ACTIVE else {}

    now = datetime.now(UTC)
    actor = context.actor_label()
    slot = _slot(db, tenant_id, kind, lock=True)
    current = slot.row_version if slot else 0
    if current != expected_row_version:
        raise PolicyConflict(current)
    if slot is None:
        if status is PolicyStatus.INHERIT:
            raise PolicyValidationError("There is no tenant override to withdraw")
        slot = AdvisorPolicy(tenant_id=tenant_id, kind=kind.value, row_version=1, created_at=now, updated_at=now,
                             created_by=actor, updated_by=actor)
        db.add(slot)
        db.flush()
    else:
        slot.row_version = current + 1
        slot.updated_at = now
        slot.updated_by = actor

    previous = _latest(db, slot.id)
    number = (db.scalar(select(func.max(AdvisorPolicyVersion.version)).where(AdvisorPolicyVersion.policy_id == slot.id)) or 0) + 1
    row = AdvisorPolicyVersion(
        policy_id=slot.id, tenant_id=tenant_id, kind=kind.value, version=number, status=status.value,
        rules_json=normalized, reason=reason.strip(), created_at=now, created_by=actor, correlation_id=correlation_id,
    )
    db.add(row)
    db.flush()
    write_audit_log(
        db,
        context,
        "component_advisor.policy.version_published",
        entity_type="advisor_policy_version",
        entity_id=row.id,
        old_value=_ref(previous).to_dict() if previous else None,
        new_value={**_ref(row).to_dict(), "reason": row.reason, "correlation_id": correlation_id},
        request=request,
        detail=f"{kind.value} v{number} {status.value}",
    )
    from .recommendations.audit import EventAction, record_event

    record_event(
        db, tenant_id=tenant_id, action=EventAction.POLICY_VERSION_PUBLISHED, context=context,
        reason=row.reason, old_status=previous.status if previous else None, new_status=status.value,
        policy_versions={"kind": kind.value, "policy_version_id": row.id, "version": number,
                         "previous_policy_version_id": previous.id if previous else None},
        details={"rules": normalized}, correlation_id=correlation_id,
    )
    return _ref(row)


__all__ = [
    "EffectivePolicies",
    "PolicyConflict",
    "effective_policies",
    "effective_policy",
    "list_versions",
    "policy_state",
    "publish_version",
]
