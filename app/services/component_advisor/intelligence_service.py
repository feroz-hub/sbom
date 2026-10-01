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
    component_intelligence_snapshot,
)
from ..dashboard_scope import DashboardScope, scope_metadata
from .classification import INFORMATIONAL_SUPPORTED
from .filters import FREQUENT_ADOPTION_MIN_PRODUCTS, AdvisorFilters

#: Capped well under the metrics layer's 1h ceiling; the invalidation key
#: already busts the cache on any run, finding, VEX or lifecycle change.
SNAPSHOT_TTL_SECONDS = 60

#: Tolerance for an ``as_of`` that means "now" (clock skew, slow clients).
AS_OF_TOLERANCE_SECONDS = 300


class AsOfNotSupported(ValueError):
    """Historical as-of is out of scope for the baseline (decision D-11)."""


def build_snapshot(db: Session, scope: DashboardScope) -> ComponentIntelligenceSnapshot:
    """Every unique component version in ``scope`` (uncached)."""
    return component_intelligence_snapshot(
        db, tenant_id=scope.tenant_id, sbom_ids=scope.eligible_sbom_ids()
    )


def cached_snapshot(db: Session, scope: DashboardScope) -> ComponentIntelligenceSnapshot:
    """:func:`build_snapshot`, memoized per tenant + scope + change markers.

    The cache key always contains the full scope key (tenant first), so one
    tenant's snapshot can never be served to another. Callers must treat the
    returned snapshot as read-only.
    """
    return memoize_with_ttl(
        name="component_advisor.snapshot",
        ttl_seconds=SNAPSHOT_TTL_SECONDS,
        db=db,
        key_extra=(scope.key, advisor_invalidation_key(db, tenant_id=scope.tenant_id)),
        compute=lambda: build_snapshot(db, scope),
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
            # Source refresh tracking (NVD/OSV/GHSA, package metadata) is wired in Step 7.
            "vulnerability_source_refreshed_at": None,
            "package_metadata_refreshed_at": None,
            "coverage": {
                "eligible_sboms": snapshot.eligible_sbom_count,
                "analysed_sboms": snapshot.analysed_sbom_count,
                "unattributed_actionable_findings": snapshot.unattributed_actionable_findings,
            },
            "stale_flags": stale_flags,
        },
        # Policy seams arrive in Step 4 (FR-SCA-004/005); none configured yet.
        "policy_versions": {"accepted_risk": None, "trust": None},
        "thresholds": {"frequently_adopted_min_products": FREQUENT_ADOPTION_MIN_PRODUCTS},
        "capabilities": {"informational_severity_supported": INFORMATIONAL_SUPPORTED},
    }


__all__ = [
    "AS_OF_TOLERANCE_SECONDS",
    "AsOfNotSupported",
    "SNAPSHOT_TTL_SECONDS",
    "build_snapshot",
    "cached_snapshot",
    "get_component_version",
    "resolve_as_of",
    "response_meta",
]
