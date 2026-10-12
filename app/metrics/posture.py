"""Convention A: shared designated-version and last-known-posture SQL.

Persisted selection mode distinguishes administrator pins from AUTO promotion.
Without a designation, active lineage tips are current targets. Only active,
tenant/application-owned ancestors with non-obsolete successful runs can supply
fallback posture. A designated target without analyzed ancestry may retain last
known application evidence, explicitly labeled without inferring lineage. Core
projections deliberately bypass ambient dashboard filters.
"""

from sqlalchemy import and_, case, func, or_, select

from ..models import AnalysisRun, Product, Projects, SBOMSource
from .base import COMPLETED_RUN_STATUSES


def posture_projection(tenant_id=None):
    s = SBOMSource.__table__
    p = Product.__table__
    project = Projects.__table__
    eligible = select(s.c.id, s.c.tenant_id, s.c.projectid, s.c.product_id, s.c.parent_id).where(
        s.c.is_active.is_(True),
        s.c.lifecycle_status == "ACTIVE",
        or_(
            s.c.projectid.is_(None),
            s.c.projectid.in_(
                select(project.c.id).where(project.c.is_active.is_(True), project.c.tenant_id == s.c.tenant_id)
            ),
        ),
        or_(
            s.c.product_id.is_(None),
            s.c.product_id.in_(
                select(p.c.id).where(
                    p.c.is_active.is_(True),
                    p.c.deleted_at.is_(None),
                    p.c.tenant_id == s.c.tenant_id,
                    p.c.project_id == s.c.projectid,
                )
            ),
        ),
    )
    if tenant_id is not None:
        eligible = eligible.where(s.c.tenant_id == tenant_id)
    eligible = eligible.cte()
    pin = eligible.alias()
    child = eligible.alias()
    designated = (
        select(pin.c.id)
        .where(
            pin.c.id == p.c.current_sbom_id,
            pin.c.product_id == eligible.c.product_id,
            pin.c.tenant_id == eligible.c.tenant_id,
            pin.c.projectid == eligible.c.projectid,
        )
        .correlate(p, eligible)
        .scalar_subquery()
    )
    links = (
        select(s.c.id.label("descendant_id"), s.c.parent_id.label("ancestor_id"))
        .where(s.c.parent_id.is_not(None))
        .cte(recursive=True)
    )
    ancestor_node = s.alias()
    descendant_node = s.alias()
    links = links.union(
        select(links.c.descendant_id, ancestor_node.c.parent_id)
        .select_from(
            links.join(ancestor_node, ancestor_node.c.id == links.c.ancestor_id).join(
                descendant_node, descendant_node.c.id == links.c.descendant_id
            )
        )
        .where(
            ancestor_node.c.parent_id.is_not(None),
            ancestor_node.c.tenant_id == descendant_node.c.tenant_id,
            ancestor_node.c.product_id.is_not_distinct_from(descendant_node.c.product_id),
            ancestor_node.c.projectid.is_not_distinct_from(descendant_node.c.projectid),
        )
    )
    has_child = (
        select(child.c.id)
        .where(
            child.c.id.in_(
                select(links.c.descendant_id).where(links.c.ancestor_id == eligible.c.id).correlate(eligible)
            ),
            child.c.tenant_id == eligible.c.tenant_id,
            child.c.product_id.is_not_distinct_from(eligible.c.product_id),
            child.c.projectid.is_not_distinct_from(eligible.c.projectid),
        )
        .correlate(eligible)
        .exists()
    )
    targets = (
        select(eligible, designated.label("designated_sbom_id"), p.c.current_sbom_id.label("stored_designated_sbom_id"),
               p.c.current_sbom_mode.label("selection_mode"), p.c.name.label("application_name"))
        .select_from(
            eligible.outerjoin(p, and_(p.c.id == eligible.c.product_id, p.c.tenant_id == eligible.c.tenant_id))
        )
        .where(or_(designated == eligible.c.id, and_(designated.is_(None), ~has_child)))
        .cte()
    )
    # UNION (distinct), rather than UNION ALL, terminates even malformed cycles.
    ancestors = select(targets.c.id.label("target_id"), targets.c.id.label("ancestor_id")).cte(recursive=True)
    node = s.alias()
    parent = s.alias()
    ancestors = ancestors.union(
        select(ancestors.c.target_id, parent.c.id).select_from(
            ancestors.join(node, node.c.id == ancestors.c.ancestor_id).join(
                parent,
                and_(
                    parent.c.id == node.c.parent_id,
                    parent.c.tenant_id == node.c.tenant_id,
                    parent.c.product_id.is_not_distinct_from(node.c.product_id),
                    parent.c.projectid.is_not_distinct_from(node.c.projectid),
                ),
            )
        )
    )
    r = AnalysisRun.__table__
    runs = (
        select(r.c.sbom_id, func.max(r.c.id).label("run_id"))
        .where(
            r.c.is_active.is_(True),
            r.c.is_current.is_(True),
            r.c.run_status.in_(COMPLETED_RUN_STATUSES),
            r.c.tenant_id == eligible.c.tenant_id,
            r.c.sbom_id == eligible.c.id,
        )
        .select_from(r.join(eligible, r.c.sbom_id == eligible.c.id))
        .group_by(r.c.sbom_id)
        .cte()
    )
    # Prefer the selected target's own successful analysis. Otherwise walk its
    # declared ancestry, not arbitrary other products/branches with matching names.
    fallback = (
        select(func.max(ancestors.c.ancestor_id))
        .select_from(ancestors.join(runs, runs.c.sbom_id == ancestors.c.ancestor_id))
        .where(ancestors.c.target_id == targets.c.id)
        .correlate(targets)
        .scalar_subquery()
    )
    own_run = select(runs.c.run_id).where(runs.c.sbom_id == targets.c.id).correlate(targets).scalar_subquery()
    other = eligible.alias()
    application_fallback = (
        select(func.max(other.c.id))
        .select_from(other.join(runs, runs.c.sbom_id == other.c.id))
        .where(
            targets.c.designated_sbom_id.is_not(None),
            other.c.product_id == targets.c.product_id,
            other.c.projectid == targets.c.projectid,
            other.c.tenant_id == targets.c.tenant_id,
        )
        .correlate(targets)
        .scalar_subquery()
    )
    posture_id = case(
        (own_run.is_not(None), targets.c.id), else_=func.coalesce(fallback, application_fallback, targets.c.id)
    )
    return select(
        targets.c.id.label("target_sbom_id"),
        posture_id.label("posture_sbom_id"),
        targets.c.tenant_id,
        targets.c.projectid,
        targets.c.product_id,
        targets.c.designated_sbom_id,
        targets.c.stored_designated_sbom_id,
        targets.c.selection_mode,
        targets.c.application_name,
    )


def posture_sbom_ids(tenant_id=None, project_id=None, product_id=None, sbom_id=None):
    projection = posture_projection(tenant_id).subquery()
    query = select(projection.c.posture_sbom_id).distinct()
    if project_id is not None:
        query = query.where(projection.c.projectid == project_id)
    if product_id is not None:
        query = query.where(projection.c.product_id == product_id)
    if sbom_id is not None:
        query = query.where(or_(projection.c.target_sbom_id == sbom_id, projection.c.posture_sbom_id == sbom_id))
    return query


def run_evidence(db, tenant_id, sbom_ids):
    """One batch of run metadata, including failed/latest and coverage evidence."""
    from types import SimpleNamespace

    r = AnalysisRun.__table__.c
    latest = (
        select(
            r.sbom_id,
            func.max(r.id).label("latest_id"),
            func.max(
                case((and_(r.is_current.is_(True), r.run_status.in_(COMPLETED_RUN_STATUSES)), r.id), else_=None)
            ).label("successful_id"),
        )
        .where(r.tenant_id == tenant_id, r.sbom_id.in_(sbom_ids or {0}), r.is_active.is_(True))
        .group_by(r.sbom_id)
        .subquery()
    )
    return [
        SimpleNamespace(**row)
        for row in db.execute(
            select(r)
            .join(latest, or_(r.id == latest.c.latest_id, r.id == latest.c.successful_id))
            .where(
                r.tenant_id == tenant_id,
                r.sbom_id.in_(sbom_ids or {0}),
                r.is_active.is_(True),
            )
            .order_by(r.id.desc())
        ).mappings()
    ]


def posture_finding_counts(db, tenant_id, run_ids):
    """Convention A, per recorded run, matching findings.in_run.total."""
    from ..models import AnalysisFinding

    f = AnalysisFinding.__table__.c
    return dict(
        db.execute(
            select(f.analysis_run_id, func.count(f.id))
            .where(
                f.tenant_id == tenant_id,
                f.is_active.is_(True),
                f.analysis_run_id.in_(run_ids or {0}),
            )
            .group_by(f.analysis_run_id)
        ).all()
    )
