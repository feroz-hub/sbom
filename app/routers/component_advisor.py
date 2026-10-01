"""Secure Component Advisor read API (spec Step 3).

FR-SCA-001/002/006/007/008, FR-SCA-023, NFR-SCA-001, NFR-SCA-005.

* ``GET /api/component-advisor/summary`` — the nine KPI cards + distributions.
* ``GET /api/component-advisor/components`` — drill-down table (paged).
* ``GET /api/component-advisor/components/{canonical_key}`` — one version.
* ``GET /api/component-advisor/search`` — versions grouped by component family.
* ``GET /api/component-advisor/components/{key}/classification`` — why a version
  is in its bucket, with the accepted-risk / trust policy trace (US-SCA-03/04).
* ``GET|POST /api/component-advisor/policies/{kind}[/versions]`` — versioned
  accepted-risk / trust policies (FR-SCA-004/005).
* ``GET|PUT /api/component-advisor/purpose/{family_key}`` — curated purpose
  metadata with provenance (FR-SCA-009).

Scope: the tenant is the authenticated tenant; ``project_id`` / ``product_id``
/ ``sbom_id`` are validated by ``dashboard_scope_dependency`` (child without
parent → 400, foreign or unknown id → 404 without revealing existence).
Every endpoint takes the same risk / lifecycle / review / adoption / search
filters and returns the same ``meta`` envelope, so KPI counts equal row
counts for identical parameters.

Authorization: reads need ``component_advisor:read``; policies need
``tenant:advisor-policy:read`` / ``update``; curated purpose writes need
``component:update``. Each is enforced by the router-wide request gate
(``permission_for_request``) and again per route. The only writes are policy
versions and purpose metadata, both audited: nothing here touches SBOMs,
components, findings or VEX (spec §1.1).
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
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
    adoption_view,
    cached_snapshot,
    get_component_version,
    resolve_as_of,
    response_meta,
)
from ..services.component_advisor.policy import PolicyKind, PolicyStatus, PolicyValidationError
from ..services.component_advisor.policy_service import PolicyConflict, list_versions, policy_state, publish_version
from ..services.component_advisor.purpose_service import PurposeConflict, save_tenant_purpose, tenant_purpose_rows
from ..services.configuration_scope import require_configuration_permission
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
    trusted: bool | None = Query(default=None),
    q: str | None = Query(default=None, max_length=200),
    facet: str | None = Query(default="all", max_length=16),
) -> AdvisorFilters:
    try:
        return AdvisorFilters.parse(
            risk=risk, lifecycle=lifecycle, needs_review=needs_review,
            frequently_adopted=frequently_adopted, trusted=trusted, q=q, facet=facet,
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
    policies = snapshot.policies
    payload = {
        "kpis": kpis(
            versions,
            accepted_risk_policy_configured=bool(policies and policies.accepted_risk),
            trust_policy_configured=bool(policies and policies.trust),
        ),
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
    return {
        **version.to_dict(),
        "adoption": adoption_view(db, scope, snapshot, version),
        "meta": response_meta(db, scope, snapshot, AdvisorFilters(), as_of),
    }


@router.get("/components/{canonical_key}/classification")
def advisor_component_classification(
    canonical_key: str,
    scope: DashboardScope = Depends(dashboard_scope_dependency),
    as_of=Depends(_as_of),
    db: Session = Depends(get_db),
    _context=Depends(require_permission(READ_PERMISSION)),
) -> dict[str, Any]:
    """Why this version has its classification (FR-SCA-004/005, US-SCA-03/04).

    Returns the rule that decided the bucket, the review reasons, and the
    accepted-risk and trust policy evaluations with the policy version used.
    """
    version = get_component_version(db, scope, canonical_key)
    if version is None:
        raise HTTPException(status_code=404, detail="Component not found")
    snapshot = cached_snapshot(db, scope)
    payload = version.to_dict()
    return {
        "canonical_key": version.canonical_key,
        "classification": version.classification.value,
        "decided_by": _decided_by(version),
        "highest_actionable_severity": version.highest_actionable_severity,
        "review_reasons": list(version.review_reasons),
        "accepted_risk": payload["risk"]["accepted_risk"] or {"status": "POLICY_NOT_CONFIGURED"},
        "trust": payload["trust"],
        "meta": response_meta(db, scope, snapshot, AdvisorFilters(), as_of),
    }


def _decided_by(version) -> str:
    """The precedence rule that produced the bucket (classification.py docstring)."""
    bucket = version.classification.value
    if bucket in ("CRITICAL", "HIGH"):
        return "HIGHEST_ACTIONABLE_SEVERITY_OUTRANKS_REVIEW"
    if bucket == "REVIEW_REQUIRED":
        return "REVIEW_REASONS_PRESENT"
    if bucket == "UNKNOWN":
        return "NO_VULNERABILITY_EVIDENCE"
    if bucket == "ACCEPTED_RISK":
        return "ACCEPTED_RISK_POLICY_SATISFIED"
    if bucket in ("MEDIUM", "LOW"):
        return "HIGHEST_ACTIONABLE_SEVERITY"
    return "NO_ACTIONABLE_FINDINGS"


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
    """Search by name / PURL / supplier / ecosystem / purpose / category (FR-SCA-008/009).

    Purpose and category match only sufficiently evidenced purpose fields
    (SBOM, package or curated metadata, or MEDIUM/HIGH-confidence AI) and are
    never guessed from a component name. With no purpose evidence in scope the
    status is ``INSUFFICIENT_PURPOSE_EVIDENCE``.
    """
    filters = _filters(
        risk=risk, lifecycle=lifecycle, needs_review=None, frequently_adopted=None, trusted=None, q=q, facet=facet
    )
    snapshot = cached_snapshot(db, scope)
    families = search_families(apply_filters(snapshot.versions, filters))
    if families:
        status = "OK"
    elif filters.facet in ("category", "purpose") and not any(v.purpose.available for v in snapshot.versions):
        # Explicit degraded state (spec Step 9): no purpose evidence in scope at all.
        status = "INSUFFICIENT_PURPOSE_EVIDENCE"
    else:
        status = "NO_MATCHING_COMPONENTS"
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


# ---------------------------------------------------------------------------
# Policies (FR-SCA-004 / FR-SCA-005)
# ---------------------------------------------------------------------------

_POLICY_KINDS = {"accepted-risk": PolicyKind.ACCEPTED_RISK, "trust": PolicyKind.TRUST}


def _policy_kind(kind: str) -> PolicyKind:
    try:
        return _POLICY_KINDS[kind]
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Unknown policy kind") from exc


class PolicyVersionRequest(BaseModel):
    status: Literal["ACTIVE", "DISABLED", "INHERIT"]
    rules: dict[str, Any] | None = None
    reason: str = Field(min_length=1, max_length=2000)
    row_version: int = Field(ge=0, description="0 when the tenant has no override yet")


@router.get("/policies/{kind}")
def get_policy(
    kind: str,
    db: Session = Depends(get_db),
    context=Depends(require_configuration_permission("advisor-policy", "read")),
) -> dict[str, Any]:
    """Effective policy, tenant override and platform default for one kind."""
    return policy_state(db, context.tenant_id, _policy_kind(kind))


@router.get("/policies/{kind}/versions")
def get_policy_versions(
    kind: str,
    db: Session = Depends(get_db),
    context=Depends(require_configuration_permission("advisor-policy", "read")),
) -> dict[str, Any]:
    """Append-only version history of the tenant override (NFR-SCA-007)."""
    items = list_versions(db, context.tenant_id, _policy_kind(kind))
    return {"total": len(items), "items": items}


@router.post("/policies/{kind}/versions", status_code=201)
def post_policy_version(
    kind: str,
    request: Request,
    body: PolicyVersionRequest = Body(...),
    db: Session = Depends(get_db),
    context=Depends(require_configuration_permission("advisor-policy", "update")),
) -> dict[str, Any]:
    """Publish a new tenant policy version. Never edits an existing version.

    409 on a stale ``row_version`` (with the current value), 422 on invalid
    rules. Earlier classifications keep pointing at the version that produced
    them; new requests use the new version immediately.
    """
    policy_kind = _policy_kind(kind)
    correlation_id = getattr(request.state, "correlation_id", None)
    try:
        version = publish_version(
            db, context=context, kind=policy_kind, status=PolicyStatus(body.status), rules=body.rules,
            reason=body.reason, expected_row_version=body.row_version, correlation_id=correlation_id,
            request=request,
        )
    except PolicyConflict as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail={"code": "POLICY_CONFLICT", "message": str(exc), "row_version": exc.current_row_version},
        ) from exc
    except PolicyValidationError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail={"code": "INVALID_POLICY", "message": str(exc)}) from exc
    db.commit()
    log_event(
        logger, "secure_component_advisor.policy.published", tenant_id=context.tenant_id,
        kind=policy_kind.value, version=version.version, status=version.status.value,
        policy_version_id=version.id, correlation_id=correlation_id,
    )
    return {"version": version.to_dict(), **policy_state(db, context.tenant_id, policy_kind)}


# ---------------------------------------------------------------------------
# Curated purpose metadata (FR-SCA-009)
# ---------------------------------------------------------------------------


class PurposeRequest(BaseModel):
    source: Literal["CURATED", "PACKAGE", "AI"] = "CURATED"
    functional_description: str | None = Field(default=None, max_length=4000)
    primary_use_case: str | None = Field(default=None, max_length=255)
    technology_category: str | None = Field(default=None, max_length=128)
    confidence: Literal["HIGH", "MEDIUM", "LOW"] | None = None
    provenance: dict[str, Any] | None = None
    row_version: int = Field(ge=0)


@router.get("/purpose/{family_key:path}")
def get_purpose(
    family_key: str,
    db: Session = Depends(get_db),
    context=Depends(require_permission(READ_PERMISSION)),
) -> dict[str, Any]:
    """Purpose rows visible to the tenant for one component family (own + platform)."""
    return {"family_key": family_key, "items": tenant_purpose_rows(db, tenant_id=context.tenant_id, family_key=family_key)}


@router.put("/purpose/{family_key:path}")
def put_purpose(
    family_key: str,
    request: Request,
    body: PurposeRequest = Body(...),
    db: Session = Depends(get_db),
    context=Depends(require_permission("component:update")),
) -> dict[str, Any]:
    """Create or replace the tenant's purpose row for ``(family_key, source)``.

    AI-sourced rows must carry ``provenance.model`` and ``provenance.generated_at``
    and are always marked AI-assisted in responses (T16).
    """
    try:
        saved = save_tenant_purpose(
            db, context=context, family_key=family_key,
            payload=body.model_dump(exclude={"row_version"}), expected_row_version=body.row_version, request=request,
        )
    except PurposeConflict as exc:
        db.rollback()
        raise HTTPException(
            status_code=409, detail={"code": "PURPOSE_CONFLICT", "message": str(exc), "row_version": exc.current_row_version}
        ) from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail={"code": "INVALID_PURPOSE", "message": str(exc)}) from exc
    db.commit()
    return saved
