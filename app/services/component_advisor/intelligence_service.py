"""Tenant-scoped component intelligence service (FR-SCA-001/002/006/023).

The only entry point routers use. Scope comes from a validated
:class:`~app.services.dashboard_scope.DashboardScope` — tenant from the
authenticated context, project/product/SBOM checked against it — so the
advisor uses the same current operational dataset as every other dashboard
(spec §1.3) and frontend-supplied ids are never trusted on their own.

Every response carries the same ``meta`` envelope (spec Step 3 "API
behaviour"): normalized applied filters, scope, as-of, freshness and policy
versions. KPIs, table rows and search results are all derived from one
cached snapshot filtered by :mod:`.filters`, so they reconcile by construction.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from ...metrics.cache import memoize_with_ttl
from ...metrics.component_advisor import (
    ComponentIntelligenceSnapshot,
    ComponentVersionIntelligence,
    advisor_invalidation_key,
    advisor_vulnerability_source_freshness,
    component_intelligence_snapshot,
)
from ..dashboard_scope import DashboardScope, scope_metadata
from .classification import INFORMATIONAL_SUPPORTED
from .filters import FREQUENT_ADOPTION_MIN_PRODUCTS, AdvisorFilters
from .policy import ComponentFacts, evaluate_accepted_risk, evaluate_trust
from .policy_service import EffectivePolicies, effective_policies
from .purpose_service import purpose_marker, purpose_records

#: Capped well under the metrics layer's 1h ceiling. The invalidation key
#: already busts the cache on any run, finding, VEX, lifecycle or activation
#: change, so the TTL only bounds staleness the key cannot see. A rebuild at
#: the sign-off scale (~200k occurrences) costs seconds, so it should be rare.
SNAPSHOT_TTL_SECONDS = 300

#: Tolerance for an ``as_of`` that means "now" (clock skew, slow clients).
AS_OF_TOLERANCE_SECONDS = 300


class AsOfNotSupported(ValueError):
    """Historical as-of is out of scope for the baseline (decision D-11)."""


def component_facts(record: ComponentVersionIntelligence) -> ComponentFacts:
    """The policy-visible facts of one version (FR-SCA-004/005)."""
    return ComponentFacts(
        classification=record.classification,
        highest_actionable_severity=max(
            (sev.upper() for sev, n in record.actionable_severity_counts.items() if n),
            key=lambda sev: ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL").index(sev),
            default=None,
        ),
        max_actionable_cvss=record.max_actionable_cvss,
        actionable_vulnerability_count=record.actionable_vulnerability_count,
        actionable_vex_statuses=record.actionable_vex_statuses,
        lifecycle=record.lifecycle.bucket,
        latest_analysis_at=record.latest_analysis_at,
        has_review_reasons=bool(record.review_reasons),
        licenses=tuple(record.licenses),
        product_count=len(record.product_ids),
    )


def build_snapshot(
    db: Session, scope: DashboardScope, *, policies: EffectivePolicies | None = None
) -> ComponentIntelligenceSnapshot:
    """Every unique component version in ``scope`` (uncached).

    Classified with the tenant's *effective* accepted-risk and trust policy
    versions; the versions used are recorded on the snapshot and on each
    record, so every classification is traceable (FR-SCA-004, NFR-SCA-002).
    """
    policies = policies or effective_policies(db, scope.tenant_id)
    accepted, trust = policies.accepted_risk, policies.trust
    snapshot = component_intelligence_snapshot(
        db,
        tenant_id=scope.tenant_id,
        sbom_ids=scope.eligible_sbom_ids(),
        accepted_risk_evaluator=(lambda record: evaluate_accepted_risk(accepted, component_facts(record))) if accepted else None,
        trust_evaluator=(lambda record: evaluate_trust(trust, component_facts(record))) if trust else None,
        purpose_records=purpose_records(db, tenant_id=scope.tenant_id),
    )
    snapshot.policies = policies
    return snapshot


def cached_snapshot(db: Session, scope: DashboardScope) -> ComponentIntelligenceSnapshot:
    """:func:`build_snapshot`, memoized per tenant + scope + change markers.

    The cache key always contains the full scope key (tenant first), so one
    tenant's snapshot can never be served to another. Callers must treat the
    returned snapshot as read-only.
    """
    policies = effective_policies(db, scope.tenant_id)
    return memoize_with_ttl(
        name="component_advisor.snapshot",
        ttl_seconds=SNAPSHOT_TTL_SECONDS,
        db=db,
        key_extra=(
            scope.key,
            advisor_invalidation_key(db, tenant_id=scope.tenant_id),
            policies.key(),
            purpose_marker(db, tenant_id=scope.tenant_id),
        ),
        compute=lambda: build_snapshot(db, scope, policies=policies),
    )


def get_component_version(
    db: Session, scope: DashboardScope, canonical_key: str
) -> ComponentVersionIntelligence | None:
    """One unique version, or ``None`` when it is not in the caller's scope.

    ``None`` covers "never existed" and "belongs to another tenant" alike, so
    a router can return the 404 convention without leaking existence.
    """
    snapshot = cached_snapshot(db, scope)
    return next((v for v in snapshot.versions if v.canonical_key == canonical_key), None)


def adoption_view(
    db: Session,
    scope: DashboardScope,
    snapshot: ComponentIntelligenceSnapshot,
    version: ComponentVersionIntelligence,
) -> dict[str, Any]:
    """Tenant adoption intelligence for one version (FR-SCA-010, US-SCA-08).

    Built only from the caller's eligible snapshot, so inactive SBOMs and other
    tenants never contribute. Presented as contextual evidence, not proof of
    safety or compatibility (spec §1.4).
    """
    from sqlalchemy import select

    from ...models import Product, Projects

    project_names = dict(
        db.execute(
            select(Projects.id, Projects.project_name).where(
                Projects.tenant_id == scope.tenant_id, Projects.id.in_(version.project_ids or [0])
            )
        ).all()
    )
    product_names = dict(
        db.execute(
            select(Product.id, Product.name).where(
                Product.tenant_id == scope.tenant_id, Product.id.in_(version.product_ids or [0])
            )
        ).all()
    )
    family = [
        v for v in snapshot.versions
        if version.family_key and v.family_key == version.family_key
    ] or [version]
    return {
        "interpretation": "CONTEXTUAL_EVIDENCE_NOT_PROOF",
        "active_sbom_occurrences": version.occurrence_count,
        "projects": [{"id": pid, "name": project_names.get(pid)} for pid in version.project_ids],
        "products": [{"id": pid, "name": product_names.get(pid)} for pid in version.product_ids],
        "observed_versions": [
            {
                "canonical_key": v.canonical_key,
                "version": v.version,
                "classification": v.classification.value,
                "lifecycle_bucket": v.lifecycle.bucket.value,
                "licenses": list(v.licenses),
                "active_sbom_occurrences": v.occurrence_count,
                "product_count": len(v.product_ids),
                "latest_analysis_at": v.latest_analysis_at,
                "is_this_version": v.canonical_key == version.canonical_key,
            }
            for v in sorted(family, key=lambda item: str(item.version or ""))
        ],
        "latest_evidence_at": version.latest_analysis_at,
    }


def resolve_as_of(as_of: str | None, *, now: datetime | None = None) -> datetime:
    """The snapshot instant. Only "now" is supported (D-11).

    A historical view would need point-in-time VEX state, which does not
    exist, so a non-current ``as_of`` is rejected rather than silently
    answered with current data.
    """
    current = now or datetime.now(UTC)
    if as_of is None or not str(as_of).strip():
        return current
    try:
        requested = datetime.fromisoformat(str(as_of).strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise AsOfNotSupported(f"as_of {as_of!r} is not an ISO-8601 timestamp") from exc
    if requested.tzinfo is None:
        requested = requested.replace(tzinfo=UTC)
    if abs((current - requested).total_seconds()) > AS_OF_TOLERANCE_SECONDS:
        raise AsOfNotSupported(
            "Historical as_of is not supported: the advisor reports current state only"
        )
    return current


def _max_iso(values) -> str | None:
    present = [value for value in values if value]
    return max(present) if present else None


def response_meta(
    db: Session,
    scope: DashboardScope,
    snapshot: ComponentIntelligenceSnapshot,
    filters: AdvisorFilters,
    as_of: datetime,
) -> dict[str, Any]:
    """The shared ``meta`` envelope for every advisor read response."""
    versions = snapshot.versions
    stale_flags = []
    if snapshot.analysed_sbom_count < snapshot.eligible_sbom_count:
        stale_flags.append("UNANALYSED_SBOMS_IN_SCOPE")
    if any(version.lifecycle.is_stale for version in versions):
        stale_flags.append("STALE_LIFECYCLE_EVIDENCE")
    if snapshot.unattributed_actionable_findings:
        stale_flags.append("UNATTRIBUTED_ACTIONABLE_FINDINGS")
    return {
        "applied_filters": filters.normalized(),
        "unsupported_filters": filters.unsupported,
        "scope": scope_metadata(db, scope),
        "as_of": as_of.isoformat(),
        "generated_at": datetime.now(UTC).isoformat(),
        "historical_view": False,
        "freshness": {
            "latest_analysis_at": snapshot.latest_analysis_at,
            "lifecycle_checked_at": _max_iso(version.lifecycle.checked_at for version in versions),
            # Platform-level vulnerability data refresh (NVD mirror). Per-run
            # source outcomes stay on each analysis run.
            "vulnerability_source_refreshed_at": advisor_vulnerability_source_freshness(db)["nvd_mirror_last_success_at"],
            # No package-metadata source is configured (Step 6); lifecycle checks stand in.
            "package_metadata_refreshed_at": None,
            "coverage": {
                "eligible_sboms": snapshot.eligible_sbom_count,
                "analysed_sboms": snapshot.analysed_sbom_count,
                "unattributed_actionable_findings": snapshot.unattributed_actionable_findings,
            },
            "stale_flags": stale_flags,
        },
        "policy_versions": snapshot.policies.to_dict() if snapshot.policies else {"accepted_risk": None, "trust": None},
        "thresholds": {"frequently_adopted_min_products": FREQUENT_ADOPTION_MIN_PRODUCTS},
        "capabilities": {"informational_severity_supported": INFORMATIONAL_SUPPORTED},
    }


__all__ = [
    "AS_OF_TOLERANCE_SECONDS",
    "AsOfNotSupported",
    "SNAPSHOT_TTL_SECONDS",
    "adoption_view",
    "build_snapshot",
    "component_facts",
    "cached_snapshot",
    "get_component_version",
    "resolve_as_of",
    "response_meta",
]
