"""Read-only previous version assertions; never a decision inheritance path."""

from collections import Counter

from packageurl import PackageURL
from sqlalchemy import func, or_, select

from ...models import SBOMComponent, SBOMSource, VexInvestigation, VexOverrideAudit, VexStatement
from .identity import canonical_vulnerability, parse_alias_column


def package_identity(component):
    if component.purl:
        try:
            p = PackageURL.from_string(component.purl)
            return ("purl", p.type, p.namespace, p.name, tuple(sorted((p.qualifiers or {}).items())), p.subpath)
        except ValueError:
            return None
    if component.cpe:
        return ("cpe", component.cpe.strip())
    return None  # Names alone do not establish cross-version package continuity.


def ancestors(db, sbom):
    s = SBOMSource.__table__.c
    rows = (
        db.execute(
            select(
                s.id,
                s.parent_id,
                s.tenant_id,
                s.projectid,
                s.product_id,
                s.sbom_version,
                s.productver,
                s.is_active,
                s.lifecycle_status,
            ).where(
                s.tenant_id == sbom.tenant_id,
                s.product_id.is_not_distinct_from(sbom.product_id),
                s.projectid.is_not_distinct_from(sbom.projectid),
            )
        )
        .mappings()
        .all()
    )
    by_id, result, seen = {row["id"]: row for row in rows}, [], {sbom.id}
    parent = sbom.parent_id
    while parent in by_id and parent not in seen:
        seen.add(parent)
        row = by_id[parent]
        result.append(row)
        parent = row["parent_id"]
    return result


def previous_decisions(db, investigation, sbom, component):
    versions = ancestors(db, sbom)
    if not versions or package_identity(component) is None:
        return []
    by_version = {row["id"]: row for row in versions}
    components = db.scalars(
        select(SBOMComponent)
        .where(
            SBOMComponent.tenant_id == investigation.tenant_id,
            SBOMComponent.sbom_id.in_(by_version),
        )
        .execution_options(include_deleted=True)
    ).all()
    matches = [c for c in components if package_identity(c) == package_identity(component)]
    # Ambiguous same-name packages are not evidence of identity continuity.
    counts = Counter(c.sbom_id for c in matches)
    eligible = {c.id for c in matches if counts[c.sbom_id] == 1}
    ids = {investigation.canonical_vulnerability_id, *parse_alias_column(investigation.aliases_json)}
    rows = db.execute(
        select(VexInvestigation, VexStatement)
        .join(VexStatement, VexStatement.sbom_id == VexInvestigation.sbom_id)
        .where(
            VexInvestigation.tenant_id == investigation.tenant_id,
            VexStatement.tenant_id == investigation.tenant_id,
            VexInvestigation.sbom_id.in_(by_version),
            VexInvestigation.component_id.in_(eligible or {0}),
            VexStatement.component_id == VexInvestigation.component_id,
            or_(VexInvestigation.canonical_vulnerability_id.in_(ids),
                *(func.upper(func.coalesce(VexInvestigation.aliases_json, "")).contains('"' + alias.upper() + '"') for alias in ids)),
            or_(func.upper(VexStatement.vulnerability_id).in_(ids), func.upper(VexStatement.cve_id).in_(ids)),
        )
        .execution_options(include_deleted=True)
        .order_by(VexStatement.id.desc())
    ).all()
    audit_rows = db.scalars(select(VexOverrideAudit).where(
        VexOverrideAudit.tenant_id == investigation.tenant_id,
        VexOverrideAudit.sbom_id.in_(by_version),
        VexOverrideAudit.action == VexOverrideAudit.ACTION_DECISION,
    ).order_by(VexOverrideAudit.id.desc())).all()
    component_map = {c.id: c for c in components}
    statement_audits = {audit.new_value_json.get("id"): audit for audit in reversed(audit_rows)
                        if isinstance(audit.new_value_json, dict) and audit.new_value_json.get("id")}
    result = []
    seen = set()
    for prior, statement in rows:
        identity = canonical_vulnerability(statement.vulnerability_id, aliases=[statement.cve_id])
        statement_ids = {identity.canonical_id, *identity.aliases}
        prior_ids = {prior.canonical_vulnerability_id, *parse_alias_column(prior.aliases_json)}
        if not (statement_ids & ids and statement_ids & prior_ids) or statement.id in seen:
            continue
        seen.add(statement.id)
        c, version = component_map[prior.component_id], by_version[prior.sbom_id]
        source_audit = statement_audits.get(statement.id)
        result.append(
            {
                "investigation_id": prior.id,
                "statement_id": statement.id,
                "source_name": statement.source_name,
                "source_format": statement.source_format,
                "source_status": statement.source_status,
                "source_document_id": statement.vex_document_id,
                "is_effective_decision": prior.effective_vex_statement_id == statement.id,
                "sbom_id": prior.sbom_id,
                "sbom_version": version["sbom_version"] or version["productver"],
                "analysis_run_id": prior.last_analysis_run_id,
                "component_id": c.id,
                "component_name": c.name,
                "component_version": c.version,
                "decision": statement.normalized_status or statement.status,
                "justification": statement.justification,
                "impact_statement": statement.impact_statement,
                "action_statement": statement.action_statement,
                "vulnerability_id": identity.canonical_id,
                "aliases": list(identity.aliases),
                "purl": c.purl,
                "audit_ids": [source_audit.id] if source_audit else [audit.id for audit in audit_rows if audit.investigation_id == prior.id],
                "evidence": statement.evidence_json,
                "reviewer": source_audit.changed_by if source_audit else prior.reviewed_by if prior.effective_vex_statement_id == statement.id else None,
                "decided_at": statement.asserted_at or statement.created_at,
                "assigned_to": prior.assigned_to,
                "applicability": "REVIEW_REQUIRED",
                "component_version_changed": c.version != component.version,
            }
        )
    return result
