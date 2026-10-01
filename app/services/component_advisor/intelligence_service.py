"""Tenant-scoped component intelligence service (FR-SCA-001, FR-SCA-023).

The only entry point routers use. Scope comes from a validated
:class:`~app.services.dashboard_scope.DashboardScope` — tenant from the
authenticated context, project/product/SBOM checked against it — so the
advisor uses the same current operational dataset as every other dashboard
(spec §1.3) and frontend-supplied ids are never trusted on their own.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from ...metrics.component_advisor import (
    ComponentIntelligenceSnapshot,
    ComponentVersionIntelligence,
    component_intelligence_snapshot,
)
from ..dashboard_scope import DashboardScope


def build_snapshot(db: Session, scope: DashboardScope) -> ComponentIntelligenceSnapshot:
    """Every unique component version in ``scope`` with risk, usage and lifecycle."""
    return component_intelligence_snapshot(
        db, tenant_id=scope.tenant_id, sbom_ids=scope.eligible_sbom_ids()
    )


def get_component_version(
    db: Session, scope: DashboardScope, canonical_key: str
) -> ComponentVersionIntelligence | None:
    """One unique version, or ``None`` when it is not in the caller's scope.

    ``None`` covers "never existed" and "belongs to another tenant" alike, so
    a router can return the 404 convention without leaking existence.
    """
    snapshot = build_snapshot(db, scope)
    return next((v for v in snapshot.versions if v.canonical_key == canonical_key), None)


__all__ = ["build_snapshot", "get_component_version"]
