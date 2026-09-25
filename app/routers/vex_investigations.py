"""Portfolio-level VEX investigation API (spec sections 27-29, 40-44).

The existing VEX endpoints in ``app/routers/vex.py`` are SBOM- and
component-scoped and stay exactly as they are; this router adds the
cross-SBOM queue the investigation workflow needs.

Authorization: ``app/core/security.py:permission_for_request`` maps any path
containing ``/vex`` to ``vex:read`` for GET and ``vex:write`` otherwise, so
these routes inherit the correct gate without per-route decoration. Every
query is additionally tenant-scoped in code — the ambient
``TenantOwnedMixin`` criteria are defence in depth, not the contract.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from ..core.security import CurrentContext, get_current_tenant_context
from ..db import get_db
from ..metrics.vex import vex_component_findings, vex_severity_filter_clause
from ..models import (
    Product,
    VexOverrideAudit,
    Projects,
    SBOMComponent,
    SBOMSource,
    VexInvestigation,
    VexStatement,
)
from ..schemas_vex import (
    InvestigationAssignmentRequest,
    InvestigationDecisionRequest,
    InvestigationMappingRequest,
    InvestigationDetail,
    InvestigationListResponse,
    InvestigationSortField,
    SortOrder,
)
from ..services.lifecycle.types import now_iso
from ..services.vex.audit import (
    record_action,
    record_assignment,
    record_mapping_resolution,
)
from ..services.vex.enums import NEEDS_REVIEW_STATUSES
from ..services.vex.identity import canonical_vulnerability, parse_alias_column

router = APIRouter(tags=["vex"])

_NEEDS_REVIEW_VALUES = [status.value for status in NEEDS_REVIEW_STATUSES]

SORT_COLUMNS = {
    "vulnerability_id": VexInvestigation.canonical_vulnerability_id,
    "effective_status": VexInvestigation.effective_status,
    "reconciliation_status": VexInvestigation.reconciliation_status,
    "last_seen_at": VexInvestigation.last_seen_at,
    "first_seen_at": VexInvestigation.first_seen_at,
    "updated_at": VexInvestigation.updated_at,
    "component": SBOMComponent.name,
}
#: Severity is resolved per row from AnalysisFinding, so there is no context
#: column to sort on. Sorting the fetched page in Python would order only
#: within that page and silently mis-rank the rest, so it is rejected instead.
UNSORTABLE_FIELDS = {"severity"}


def _tenant_id(context: CurrentContext) -> int:
    if context.tenant_id is None:
        raise HTTPException(status_code=403, detail="Tenant context required")
    return context.tenant_id


def _investigation_or_404(db: Session, investigation_id: int, tenant_id: int) -> VexInvestigation:
    """Load one context, or 404.

    A cross-tenant id returns 404 rather than 403 on purpose: 403 would
    confirm the row exists in someone else's tenant (VEX-SEC-002).
    """
    row = db.scalar(
        select(VexInvestigation).where(
            VexInvestigation.id == investigation_id,
            VexInvestigation.tenant_id == tenant_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return row


def _actor(context: CurrentContext) -> str | None:
    return context.actor_label() if hasattr(context, "actor_label") else None


def _check_row_version(investigation: VexInvestigation, supplied: int) -> bool:
    """True when the caller holds the current version (VEX-AUD-002)."""
    return supplied == (investigation.row_version or 1)


def _statements_for(db: Session, investigation: VexInvestigation) -> list[VexStatement]:
    conditions = [
        VexStatement.tenant_id == investigation.tenant_id,
        VexStatement.sbom_id == investigation.sbom_id,
    ]
    if investigation.component_id is not None:
        conditions.append(VexStatement.component_id == investigation.component_id)
    else:
        conditions.append(VexStatement.component_id.is_(None))
    rows = db.scalars(select(VexStatement).where(*conditions).order_by(VexStatement.id)).all()
    target = (investigation.canonical_vulnerability_id or "").strip().upper()
    aliases = set(parse_alias_column(investigation.aliases_json))
    matches = []
    for row in rows:
        raw = (row.vulnerability_id or "").strip().upper()
        cve = (row.cve_id or "").strip().upper()
        if target in {raw, cve} or raw in aliases or cve in aliases:
            matches.append(row)
    return matches


def _severity_for(db: Session, investigation: VexInvestigation) -> str | None:
    """Severity comes from the vulnerability, never from VEX (VEX-DATA-005)."""
    if investigation.component_id is None:
        return None
    for finding in vex_component_findings(
        db,
        tenant_id=investigation.tenant_id,
        sbom_id=investigation.sbom_id,
        component_id=investigation.component_id,
    ):
        if (finding.vuln_id or "").strip().upper() == investigation.canonical_vulnerability_id:
            return finding.severity
    return None


def _row_payload(
    db: Session,
    investigation: VexInvestigation,
    *,
    component: SBOMComponent | None,
    sbom: SBOMSource | None,
    project: Projects | None,
    product: Product | None,
) -> dict[str, Any]:
    statements = _statements_for(db, investigation)
    effective = next(
        (s for s in statements if s.id == investigation.effective_vex_statement_id), None
    )
    return {
        "id": investigation.id,
        "canonical_vulnerability_id": investigation.canonical_vulnerability_id,
        "aliases": parse_alias_column(investigation.aliases_json),
        "severity": _severity_for(db, investigation),
        "component_id": investigation.component_id,
        "component_name": getattr(component, "name", None),
        "component_version": getattr(component, "version", None),
        "project_id": getattr(project, "id", None),
        "project_name": getattr(project, "project_name", None),
        "product_id": getattr(product, "id", None),
        "product_name": getattr(product, "name", None),
        "sbom_id": investigation.sbom_id,
        "sbom_name": getattr(sbom, "sbom_name", None),
        "analyzer_detection_state": investigation.analyzer_detection_state,
        "analyzer_sources": parse_alias_column(investigation.analyzer_sources_json),
        "vex_source": getattr(effective, "source_name", None),
        "native_vex_status": getattr(effective, "source_status", None),
        "effective_status": investigation.effective_status,
        "reconciliation_status": investigation.reconciliation_status,
        "justification": getattr(effective, "justification", None),
        "assigned_to": investigation.assigned_to,
        "reviewed_by": investigation.reviewed_by,
        "last_seen_at": investigation.last_seen_at,
        "updated_at": investigation.updated_at,
        "row_version": investigation.row_version or 1,
        "needs_review": investigation.reconciliation_status in _NEEDS_REVIEW_VALUES,
    }


@router.get("/api/vex/investigations", response_model=InvestigationListResponse)
def list_investigations(
    project_id: int | None = Query(default=None, ge=1),
    product_id: int | None = Query(default=None, ge=1),
    sbom_id: int | None = Query(default=None, ge=1),
    effective_status: str | None = Query(default=None, max_length=32),
    reconciliation_status: str | None = Query(default=None, max_length=32),
    severity: str | None = Query(default=None, max_length=16),
    component: str | None = Query(default=None, max_length=255),
    q: str | None = Query(default=None, max_length=500, description="Vulnerability id or alias"),
    vex_source: str | None = Query(default=None, max_length=255),
    analyzer_source: str | None = Query(default=None, max_length=64),
    needs_review: bool | None = Query(default=None),
    sort_by: InvestigationSortField = Query(default="last_seen_at"),
    sort_order: SortOrder = Query(default="desc"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    context: CurrentContext = Depends(get_current_tenant_context),
) -> dict[str, Any]:
    """The portfolio investigation queue (VEX-UI-001/002).

    Uses the same current-context predicate as the dashboard tiles
    (``is_current``, tenant, eligible SBOMs), so tile counts equal row counts
    for identical filters (VEX-DASH-004).
    """
    if sort_by in UNSORTABLE_FIELDS:
        raise HTTPException(
            status_code=400,
            detail=(
                "sort_by=severity is not supported: severity is resolved per row "
                "from analyser findings and has no column on the investigation"
            ),
        )
    tenant_id = _tenant_id(context)

    conditions: list[ColumnElement[bool]] = [
        VexInvestigation.tenant_id == tenant_id,
        VexInvestigation.is_current.is_(True),
    ]
    if sbom_id is not None:
        conditions.append(VexInvestigation.sbom_id == sbom_id)
    if project_id is not None:
        conditions.append(SBOMSource.projectid == project_id)
    if product_id is not None:
        conditions.append(SBOMSource.product_id == product_id)
    if effective_status:
        conditions.append(VexInvestigation.effective_status == effective_status.strip().upper())
    if reconciliation_status:
        conditions.append(
            VexInvestigation.reconciliation_status == reconciliation_status.strip().upper()
        )
    if severity and severity.strip():
        conditions.append(vex_severity_filter_clause(severity))
    if component and component.strip():
        conditions.append(SBOMComponent.name.ilike(f"%{component.strip()}%"))
    if q and q.strip():
        term = f"%{q.strip().upper()}%"
        # Alias search matters: a context canonicalised to its CVE must still
        # be findable by the GHSA the scanner reported (VEX-CTX-002).
        conditions.append(
            or_(
                VexInvestigation.canonical_vulnerability_id.ilike(term),
                func.upper(VexInvestigation.aliases_json).ilike(term),
            )
        )
    if vex_source and vex_source.strip():
        conditions.append(VexStatement.source_name.ilike(f"%{vex_source.strip()}%"))
    if analyzer_source and analyzer_source.strip():
        conditions.append(
            VexInvestigation.analyzer_detection_state == analyzer_source.strip().upper()
        )
    if needs_review is True:
        conditions.append(VexInvestigation.reconciliation_status.in_(_NEEDS_REVIEW_VALUES))
    elif needs_review is False:
        conditions.append(VexInvestigation.reconciliation_status.notin_(_NEEDS_REVIEW_VALUES))

    base = (
        select(VexInvestigation)
        .outerjoin(SBOMComponent, SBOMComponent.id == VexInvestigation.component_id)
        .outerjoin(SBOMSource, SBOMSource.id == VexInvestigation.sbom_id)
    )
    if vex_source and vex_source.strip():
        base = base.outerjoin(
            VexStatement, VexStatement.id == VexInvestigation.effective_vex_statement_id
        )

    total = db.scalar(
        select(func.count())
        .select_from(VexInvestigation)
        .outerjoin(SBOMComponent, SBOMComponent.id == VexInvestigation.component_id)
        .outerjoin(SBOMSource, SBOMSource.id == VexInvestigation.sbom_id)
        .outerjoin(VexStatement, VexStatement.id == VexInvestigation.effective_vex_statement_id)
        .where(*conditions)
    ) or 0

    sort_column = SORT_COLUMNS[sort_by]
    primary = sort_column.asc() if sort_order == "asc" else sort_column.desc()
    # Stable tiebreaker: without it, equal sort keys can reorder between pages
    # and a row is silently skipped or repeated while paging.
    rows = list(
        db.scalars(
            base.where(*conditions)
            .order_by(primary, VexInvestigation.id.asc())
            .offset(offset)
            .limit(limit)
        ).all()
    )

    sboms = {
        s.id: s
        for s in db.scalars(
            select(SBOMSource).where(SBOMSource.id.in_({r.sbom_id for r in rows} or {0}))
        ).all()
    }
    components = {
        c.id: c
        for c in db.scalars(
            select(SBOMComponent).where(
                SBOMComponent.id.in_({r.component_id for r in rows if r.component_id} or {0})
            )
        ).all()
    }
    projects = {
        p.id: p
        for p in db.scalars(
            select(Projects).where(
                Projects.id.in_({s.projectid for s in sboms.values() if s.projectid} or {0})
            )
        ).all()
    }
    products = {
        p.id: p
        for p in db.scalars(
            select(Product).where(
                Product.id.in_({s.product_id for s in sboms.values() if s.product_id} or {0})
            )
        ).all()
    }

    items = []
    for row in rows:
        sbom = sboms.get(row.sbom_id)
        items.append(
            _row_payload(
                db,
                row,
                component=components.get(row.component_id),
                sbom=sbom,
                project=projects.get(getattr(sbom, "projectid", None)),
                product=products.get(getattr(sbom, "product_id", None)),
            )
        )

    return {"total": int(total), "limit": limit, "offset": offset, "items": items}


@router.get("/api/vex/investigations/resolve", response_model=InvestigationDetail)
def resolve_investigation(
    sbom_id: int = Query(ge=1),
    component_id: int = Query(ge=1),
    vulnerability_id: str = Query(min_length=1, max_length=255),
    db: Session = Depends(get_db),
    context: CurrentContext = Depends(get_current_tenant_context),
) -> dict[str, Any]:
    """Find the context for a component/vulnerability pair, or 404.

    The queue addresses contexts by id, but the SBOM page only knows
    (sbom, component, CVE). This is how the shared decision editor reaches the
    same record from there, so it can show real evidence and carry the
    ``row_version`` the concurrency check needs.

    Deliberately read-only. A vulnerability that no scanner found and no
    document asserted has no context until a decision creates the statement
    behind it; fabricating one here would invent a context that the next
    reconciliation could immediately retire. The caller falls back to the
    component-scoped override for that first save.

    Declared before ``/{investigation_id}`` so "resolve" is not captured as an
    id by the path converter.
    """
    tenant_id = _tenant_id(context)
    canonical = canonical_vulnerability(vulnerability_id).canonical_id

    row = db.scalar(
        select(VexInvestigation).where(
            VexInvestigation.tenant_id == tenant_id,
            VexInvestigation.sbom_id == sbom_id,
            VexInvestigation.component_id == component_id,
            VexInvestigation.canonical_vulnerability_id == canonical,
            VexInvestigation.is_current.is_(True),
        )
    )
    if row is None:
        # The raw identifier may be an alias of the canonical one the context
        # is keyed on (VEX-CTX-002), e.g. a GHSA reported against a CVE.
        raw = vulnerability_id.strip().upper()
        for candidate in db.scalars(
            select(VexInvestigation).where(
                VexInvestigation.tenant_id == tenant_id,
                VexInvestigation.sbom_id == sbom_id,
                VexInvestigation.component_id == component_id,
                VexInvestigation.is_current.is_(True),
            )
        ).all():
            if raw in set(parse_alias_column(candidate.aliases_json)):
                row = candidate
                break

    if row is None:
        raise HTTPException(status_code=404, detail="No investigation for this pair")
    return _detail_payload(db, row)


@router.get("/api/vex/investigations/{investigation_id}", response_model=InvestigationDetail)
def get_investigation(
    investigation_id: int,
    db: Session = Depends(get_db),
    context: CurrentContext = Depends(get_current_tenant_context),
) -> dict[str, Any]:
    """Full evidence for one context, in separate sections (VEX-UI-003)."""
    tenant_id = _tenant_id(context)
    investigation = _investigation_or_404(db, investigation_id, tenant_id)
    return _detail_payload(db, investigation)


def _detail_payload(db: Session, investigation: VexInvestigation) -> dict[str, Any]:
    component = (
        db.get(SBOMComponent, investigation.component_id)
        if investigation.component_id
        else None
    )
    sbom = db.get(SBOMSource, investigation.sbom_id)
    project = db.get(Projects, sbom.projectid) if sbom and sbom.projectid else None
    product = db.get(Product, sbom.product_id) if sbom and sbom.product_id else None

    statements = _statements_for(db, investigation)
    manual = [s for s in statements if s.source_name == "Manual VEX Override"]
    latest_manual = max(manual, key=lambda s: s.id) if manual else None

    finding = None
    if investigation.component_id is not None:
        for candidate in vex_component_findings(
            db,
            tenant_id=investigation.tenant_id,
            sbom_id=investigation.sbom_id,
            component_id=investigation.component_id,
        ):
            if (candidate.vuln_id or "").strip().upper() == investigation.canonical_vulnerability_id:
                finding = candidate
                break

    imported = []
    for statement in statements:
        if statement is latest_manual:
            continue
        document = statement.vex_document
        evidence = statement.evidence_json if isinstance(statement.evidence_json, dict) else {}
        imported.append(
            {
                "statement_id": statement.id,
                "source_format": statement.source_format,
                "source_status": statement.source_status,
                "normalized_status": statement.normalized_status,
                "author": getattr(document, "author", None) or statement.source_name,
                "source_document_id": getattr(document, "source_document_id", None),
                "source_document_version": getattr(document, "source_document_version", None),
                "asserted_at": statement.asserted_at or statement.created_at,
                "justification": statement.justification,
                "impact_statement": statement.impact_statement,
                "action_statement": statement.action_statement,
                "mitigation": statement.mitigation,
                "fixed_version": statement.fixed_version,
                "evidence_url": statement.source_url or evidence.get("evidence_url"),
                "mapping_confidence": statement.match_confidence,
                "match_strategy": statement.match_strategy,
                "version_applicable": statement.version_applicable,
                "is_effective": statement.id == investigation.effective_vex_statement_id,
                "superseded": getattr(document, "superseded_by_id", None) is not None,
            }
        )

    audits = db.scalars(
        select(VexOverrideAudit)
        .where(
            VexOverrideAudit.tenant_id == investigation.tenant_id,
            VexOverrideAudit.component_id == investigation.component_id,
        )
        .order_by(VexOverrideAudit.id)
    ).all() if investigation.component_id else []

    history = [
        {
            "at": statement.asserted_at or statement.created_at,
            "kind": "import",
            "actor": getattr(statement.vex_document, "author", None) or statement.source_name,
            "summary": f"{statement.source_format or 'vex'}: {statement.source_status or statement.status}",
            "new_status": statement.normalized_status,
        }
        for statement in statements
        if statement.source_name != "Manual VEX Override"
    ]
    for audit in audits:
        old = audit.old_value_json if isinstance(audit.old_value_json, dict) else {}
        new = audit.new_value_json if isinstance(audit.new_value_json, dict) else {}
        history.append(
            {
                "at": audit.changed_at,
                "kind": "decision",
                "actor": audit.changed_by,
                "summary": f"manual decision on {audit.vulnerability_id}",
                "previous_status": old.get("status"),
                "new_status": new.get("status"),
                "reason": audit.reason,
            }
        )
    history.sort(key=lambda entry: str(entry.get("at") or ""))

    manual_evidence = (
        latest_manual.evidence_json
        if latest_manual is not None and isinstance(latest_manual.evidence_json, dict)
        else {}
    )

    return {
        "id": investigation.id,
        "sbom_id": investigation.sbom_id,
        "project_name": getattr(project, "project_name", None),
        "product_name": getattr(product, "name", None),
        "sbom_name": getattr(sbom, "sbom_name", None),
        "vulnerability": {
            "canonical_vulnerability_id": investigation.canonical_vulnerability_id,
            "aliases": parse_alias_column(investigation.aliases_json),
            # Severity describes the vulnerability and is never rewritten by
            # VEX (VEX-DATA-005).
            "severity": getattr(finding, "severity", None),
            "cvss_score": getattr(finding, "score", None),
            "description": getattr(finding, "description", None),
            "references": [r for r in [getattr(finding, "reference_url", None)] if r],
        },
        "component": {
            "component_id": investigation.component_id,
            "name": getattr(component, "name", None),
            "version": getattr(component, "version", None),
            "purl": getattr(component, "purl", None),
            "cpe": getattr(component, "cpe", None),
            "bom_ref": getattr(component, "bom_ref", None),
            "supplier": getattr(component, "supplier", None),
        },
        "analyzer_evidence": {
            "detection_state": investigation.analyzer_detection_state,
            # The recorded set, not just this finding's source: one context
            # can be evidenced by several scanners (VEX-REC-003).
            "sources": parse_alias_column(investigation.analyzer_sources_json)
            or [s for s in [getattr(finding, "source", None)] if s],
            "analysis_run_id": investigation.last_analysis_run_id,
            "match_strategy": getattr(finding, "match_strategy", None),
            "match_confidence": getattr(finding, "match_confidence", None),
            "matched_range": getattr(finding, "matched_range", None),
            "first_seen_at": investigation.first_seen_at,
            "last_seen_at": investigation.last_seen_at,
        },
        "imported_vex": imported,
        "internal_decision": {
            "effective_status": getattr(latest_manual, "normalized_status", None),
            "reviewer": investigation.reviewed_by,
            "assigned_to": investigation.assigned_to,
            "reason": manual_evidence.get("reason"),
            "justification": getattr(latest_manual, "justification", None),
            "impact_statement": getattr(latest_manual, "impact_statement", None),
            "action_statement": getattr(latest_manual, "action_statement", None),
            "evidence_url": manual_evidence.get("evidence_url"),
            "updated_at": investigation.updated_at,
        },
        "reconciliation_status": investigation.reconciliation_status,
        "effective_status": investigation.effective_status,
        "history": history,
        "row_version": investigation.row_version or 1,
    }


@router.put("/api/vex/investigations/{investigation_id}/decision", response_model=InvestigationDetail)
def set_investigation_decision(
    investigation_id: int,
    payload: InvestigationDecisionRequest,
    response: Response,
    db: Session = Depends(get_db),
    context: CurrentContext = Depends(get_current_tenant_context),
) -> Any:
    """Record a manual determination (VEX-INV-003, VEX-AUD-001/002).

    Requires ``vex:write`` via the path rule in ``permission_for_request``.
    Reuses the existing component-scoped override service so that the manual
    statement, its validation and its audit row stay in one place rather than
    being reimplemented here.
    """
    from ..services.lifecycle.vex_provider import apply_vex_override

    tenant_id = _tenant_id(context)
    investigation = _investigation_or_404(db, investigation_id, tenant_id)

    if investigation.component_id is None:
        raise HTTPException(
            status_code=409,
            detail=(
                "Cannot decide an unresolved mapping; bind the assertion to a "
                "component first (VEX-MAP-001)"
            ),
        )

    # Optimistic concurrency before any write (VEX-AUD-002).
    if not _check_row_version(investigation, payload.row_version):
        response.status_code = 409
        return _detail_payload(db, investigation)

    previous_status = investigation.effective_status
    previous_reconciliation = investigation.reconciliation_status

    # Validation lives in the existing override path (VEX-VAL-001/002), so
    # NOT_AFFECTED still needs justification or impact, FIXED still needs a
    # fixed version or evidence, and the rules cannot drift between the two
    # entry points.
    apply_vex_override(
        db,
        investigation.component_id,
        investigation.canonical_vulnerability_id,
        {
            "status": payload.status.lower(),
            "reason": payload.reason,
            "justification": payload.justification,
            "impact_statement": payload.impact_statement,
            "action_statement": payload.action_statement,
            "mitigation": payload.mitigation,
            "fixed_version": payload.fixed_version,
            "evidence_url": payload.evidence_url,
        },
        changed_by=context.actor_label() if hasattr(context, "actor_label") else None,
    )

    db.refresh(investigation)

    # apply_vex_override writes its own component-scoped audit row; this one
    # records the transition at the *context* level, including the
    # reconciliation status change the decision caused (VEX-AUD-001).
    record_action(
        db,
        investigation,
        action=VexOverrideAudit.ACTION_DECISION,
        reason=payload.reason,
        changed_by=_actor(context),
        previous_status=previous_status,
        new_status=payload.status,
        evidence_url=payload.evidence_url,
        old_value={
            "effective_status": previous_status,
            "reconciliation_status": previous_reconciliation,
        },
        new_value={
            "effective_status": payload.status,
            "reconciliation_status": investigation.reconciliation_status,
        },
    )

    investigation.assigned_to = payload.assigned_to or investigation.assigned_to
    investigation.reviewed_by = _actor(context)
    investigation.reviewed_at = now_iso()
    investigation.updated_at = now_iso()
    investigation.row_version = (investigation.row_version or 1) + 1
    db.commit()
    db.refresh(investigation)

    return _detail_payload(db, investigation)


@router.put(
    "/api/vex/investigations/{investigation_id}/assignment",
    response_model=InvestigationDetail,
)
def set_investigation_assignment(
    investigation_id: int,
    payload: InvestigationAssignmentRequest,
    response: Response,
    db: Session = Depends(get_db),
    context: CurrentContext = Depends(get_current_tenant_context),
) -> Any:
    """Assign or unassign a context. Requires ``vex:write``; audited."""
    tenant_id = _tenant_id(context)
    investigation = _investigation_or_404(db, investigation_id, tenant_id)

    if not _check_row_version(investigation, payload.row_version):
        response.status_code = 409
        return _detail_payload(db, investigation)

    previous = investigation.assigned_to
    investigation.assigned_to = payload.assigned_to
    investigation.updated_at = now_iso()
    investigation.row_version = (investigation.row_version or 1) + 1
    record_assignment(
        db,
        investigation,
        previous_assignee=previous,
        new_assignee=payload.assigned_to,
        reason=payload.reason,
        changed_by=_actor(context),
    )
    db.commit()
    db.refresh(investigation)
    return _detail_payload(db, investigation)


@router.put(
    "/api/vex/investigations/{investigation_id}/component",
    response_model=InvestigationDetail,
)
def resolve_investigation_mapping(
    investigation_id: int,
    payload: InvestigationMappingRequest,
    response: Response,
    db: Session = Depends(get_db),
    context: CurrentContext = Depends(get_current_tenant_context),
) -> Any:
    """Bind an UNRESOLVED_MAPPING context to a component (VEX-MAP-001).

    The matcher deliberately refuses to choose between weak candidates, so
    this is the analyst's escape hatch. The component must belong to the same
    tenant and the same SBOM — a binding across either would attach a
    determination to the wrong product context (VEX-CTX-001, VEX-SEC-002).
    """
    from ..services.vex.reconciliation import recompute_for_sbom

    tenant_id = _tenant_id(context)
    investigation = _investigation_or_404(db, investigation_id, tenant_id)

    if investigation.reconciliation_status != "UNRESOLVED_MAPPING":
        raise HTTPException(
            status_code=409,
            detail="Only an UNRESOLVED_MAPPING context can be bound to a component",
        )
    if not _check_row_version(investigation, payload.row_version):
        response.status_code = 409
        return _detail_payload(db, investigation)

    component = db.scalar(
        select(SBOMComponent).where(
            SBOMComponent.id == payload.component_id,
            SBOMComponent.tenant_id == tenant_id,
            SBOMComponent.sbom_id == investigation.sbom_id,
        )
    )
    if component is None:
        raise HTTPException(
            status_code=404, detail="Component not found in this tenant and SBOM"
        )

    previous_component_id = investigation.component_id
    investigation.assign_component(component.id)
    investigation.updated_at = now_iso()
    investigation.row_version = (investigation.row_version or 1) + 1
    record_mapping_resolution(
        db,
        investigation,
        previous_component_id=previous_component_id,
        new_component_id=component.id,
        reason=payload.reason,
        changed_by=_actor(context),
    )
    db.flush()

    # The binding changes what the context reconciles against, so recompute
    # rather than leaving a stale UNRESOLVED_MAPPING status behind.
    recompute_for_sbom(db, tenant_id=tenant_id, sbom_id=investigation.sbom_id)
    db.commit()
    db.refresh(investigation)
    return _detail_payload(db, investigation)


__all__ = ["router"]
