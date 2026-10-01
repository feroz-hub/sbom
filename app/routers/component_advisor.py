"""Secure Component Advisor read API (spec Step 3).

FR-SCA-001/002/006/007/008, FR-SCA-023, NFR-SCA-001, NFR-SCA-005.

* ``GET /api/component-advisor/summary`` — the nine KPI cards + distributions.
* ``GET /api/component-advisor/components`` — drill-down table (paged).
* ``GET /api/component-advisor/components/{canonical_key}`` — one version.
* ``GET /api/component-advisor/search`` — versions grouped by component family.

Scope: the tenant is the authenticated tenant; ``project_id`` / ``product_id``
/ ``sbom_id`` are validated by ``dashboard_scope_dependency`` (child without
parent → 400, foreign or unknown id → 404 without revealing existence).
Every endpoint takes the same risk / lifecycle / review / adoption / search
filters and returns the same ``meta`` envelope, so KPI counts equal row
counts for identical parameters.

Authorization: ``component_advisor:read``, enforced by the router-wide request
gate (``permission_for_request``) and again per route. Read-only: nothing
here writes to any table (spec §1.1).
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy.orm import Session

from ..core.security import require_permission
from ..db import get_db
from ..etag import maybe_not_modified
from ..logger import get_logger, log_event
from ..services.component_advisor.filters import (
    SORT_FIELDS,
    AdvisorFilters,
    FilterError,
    apply_filters,
    distributions,
    kpis,
    search_families,
    sort_versions,
)
from ..services.component_advisor.intelligence_service import (
    AsOfNotSupported,
    cached_snapshot,
    get_component_version,
    resolve_as_of,
    response_meta,
)
from ..services.dashboard_scope import DashboardScope, dashboard_scope_dependency

router = APIRouter(prefix="/api/component-advisor", tags=["component-advisor"])
logger = get_logger("sbom.component_advisor")

READ_PERMISSION = "component_advisor:read"

SortField = Literal["name", "risk", "occurrences", "products", "actionable", "latest_analysis"]
assert set(SORT_FIELDS) == set(SortField.__args__)  # keep the contract and the domain in step


def _filters(
    risk: list[str] | None = Query(default=None, description="Risk classification(s); repeat or comma-separate"),
    lifecycle: list[str] | None = Query(default=None, description="SUPPORTED, MAINTENANCE, EOS, EOL, UNKNOWN"),
    needs_review: bool | None = Query(default=None),
    frequently_adopted: bool | None = Query(default=None),
    q: str | None = Query(default=None, max_length=200),
    facet: str | None = Query(default="all", max_length=16),
) -> AdvisorFilters:
    try:
        return AdvisorFilters.parse(
            risk=risk, lifecycle=lifecycle, needs_review=needs_review,
            frequently_adopted=frequently_adopted, q=q, facet=facet,
        )
    except FilterError as exc:
        raise HTTPException(status_code=400, detail={"code": "INVALID_FILTER", "message": str(exc)}) from exc


def _as_of(as_of: str | None = Query(default=None, max_length=64)):
    try:
        return resolve_as_of(as_of)
    except AsOfNotSupported as exc:
        raise HTTPException(status_code=400, detail={"code": "AS_OF_NOT_SUPPORTED", "message": str(exc)}) from exc


def _log_query(endpoint: str, scope: DashboardScope, filters: AdvisorFilters, result_count: int) -> None:
    # NFR-SCA-004. Ids and counts only — no component names or search text.
    log_event(
        logger,
        "secure_component_advisor.query",
        endpoint=endpoint,
        tenant_id=scope.tenant_id,
        scope_level=scope.level,
        filter_count=sum(1 for value in filters.normalized().values() if value not in (None, [], "all")),
        result_count=result_count,
    )


@router.get("/summary")
def advisor_summary(
    request: Request,
    response: Response,
    scope: DashboardScope = Depends(dashboard_scope_dependency),
    filters: AdvisorFilters = Depends(_filters),
    as_of=Depends(_as_of),
    db: Session = Depends(get_db),
    _context=Depends(require_permission(READ_PERMISSION)),
) -> Any:
    """KPI cards over the filtered scope (FR-SCA-002, US-SCA-01)."""
    snapshot = cached_snapshot(db, scope)
    versions = apply_filters(snapshot.versions, filters)
    payload = {
        "kpis": kpis(versions),
        **distributions(versions),
        "meta": response_meta(db, scope, snapshot, filters, as_of),
    }
    _log_query("summary", scope, filters, len(versions))
    return maybe_not_modified(request, response, _stable(payload)) or payload


@router.get("/components")
def advisor_components(
    request: Request,
    response: Response,
    scope: DashboardScope = Depends(dashboard_scope_dependency),
    filters: AdvisorFilters = Depends(_filters),
    as_of=Depends(_as_of),
    sort_by: SortField = Query(default="risk"),
    sort_order: Literal["asc", "desc"] = Query(default="desc"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _context=Depends(require_permission(READ_PERMISSION)),
) -> Any:
    """Drill-down table (FR-SCA-001/006/007). ``total`` equals the KPI value."""
    snapshot = cached_snapshot(db, scope)
    versions = sort_versions(apply_filters(snapshot.versions, filters), sort_by, sort_order)
    payload = {
        "total": len(versions),
        "limit": limit,
        "offset": offset,
        "sort_by": sort_by,
        "sort_order": sort_order,
        "items": [version.to_dict() for version in versions[offset : offset + limit]],
        "meta": response_meta(db, scope, snapshot, filters, as_of),
    }
    _log_query("components", scope, filters, len(versions))
    return maybe_not_modified(request, response, _stable(payload)) or payload


@router.get("/components/{canonical_key}")
def advisor_component_detail(
    canonical_key: str,
    scope: DashboardScope = Depends(dashboard_scope_dependency),
    as_of=Depends(_as_of),
    db: Session = Depends(get_db),
    _context=Depends(require_permission(READ_PERMISSION)),
) -> dict[str, Any]:
    """One unique component version (FR-SCA-001, US-SCA-08).

    404 for unknown keys and for keys that exist only in another tenant or
    outside the selected scope — never 403, which would confirm existence.
    """
    version = get_component_version(db, scope, canonical_key)
    if version is None:
        raise HTTPException(status_code=404, detail="Component not found")
    snapshot = cached_snapshot(db, scope)
    return {**version.to_dict(), "meta": response_meta(db, scope, snapshot, AdvisorFilters(), as_of)}


@router.get("/search")
def advisor_search(
    q: str = Query(..., min_length=1, max_length=200),
    facet: str = Query(default="all", max_length=16),
    risk: list[str] | None = Query(default=None),
    lifecycle: list[str] | None = Query(default=None),
    limit: int = Query(default=25, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    scope: DashboardScope = Depends(dashboard_scope_dependency),
    as_of=Depends(_as_of),
    db: Session = Depends(get_db),
    _context=Depends(require_permission(READ_PERMISSION)),
) -> dict[str, Any]:
    """Search by name / PURL / supplier / ecosystem (FR-SCA-008, US-SCA-07).

    ``facet=category|purpose`` is accepted but returns no results with
    ``search_status=INSUFFICIENT_PURPOSE_EVIDENCE`` until purpose metadata
    exists (Step 4): a purpose match is never guessed from a name.
    """
    filters = _filters(risk=risk, lifecycle=lifecycle, needs_review=None, frequently_adopted=None, q=q, facet=facet)
    snapshot = cached_snapshot(db, scope)
    families = search_families(apply_filters(snapshot.versions, filters))
    if filters.facet in ("category", "purpose"):
        status = "INSUFFICIENT_PURPOSE_EVIDENCE"
    else:
        status = "OK" if families else "NO_MATCHING_COMPONENTS"
    _log_query("search", scope, filters, len(families))
    return {
        "search_status": status,
        "total": len(families),
        "limit": limit,
        "offset": offset,
        "items": families[offset : offset + limit],
        "meta": response_meta(db, scope, snapshot, filters, as_of),
    }


def _stable(payload: dict[str, Any]) -> dict[str, Any]:
    """Payload for ETag hashing without the per-request ``generated_at`` / ``as_of``."""
    meta = {k: v for k, v in payload["meta"].items() if k not in ("generated_at", "as_of")}
    return {**payload, "meta": meta}
