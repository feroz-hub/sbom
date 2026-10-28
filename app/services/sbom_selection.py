"""Transaction-bound promotion policy. Uploads never call this function."""
from sqlalchemy import select

from ..core.context import minimal_background_context
from ..metrics.base import COMPLETED_RUN_STATUSES
from ..models import Product, Projects, SBOMSource
from .audit_service import write_audit_log


def promote_successful_analysis(db, run):
    if not run.is_active or not run.is_current or run.run_status not in COMPLETED_RUN_STATUSES:
        return False
    sbom = db.scalar(select(SBOMSource).where(
        SBOMSource.id == run.sbom_id, SBOMSource.tenant_id == run.tenant_id,
        SBOMSource.is_active.is_(True), SBOMSource.lifecycle_status == "ACTIVE",
    ))
    if sbom is None or sbom.product_id is None:
        return False
    if run.project_id != sbom.projectid or run.product_id != sbom.product_id:
        return False
    from ..metrics.vex import latest_successful_run_id_for_sbom
    if latest_successful_run_id_for_sbom(db, tenant_id=run.tenant_id, sbom_id=sbom.id) != run.id:
        return False
    product = db.scalar(select(Product).where(
        Product.id == sbom.product_id, Product.tenant_id == run.tenant_id,
        Product.project_id == sbom.projectid, Product.is_active.is_(True), Product.deleted_at.is_(None),
    ).with_for_update().execution_options(populate_existing=True))
    if product is None or product.current_sbom_mode != "AUTO":
        return False
    if db.scalar(select(Projects.id).where(
        Projects.id == product.project_id, Projects.tenant_id == run.tenant_id, Projects.is_active.is_(True),
    )) is None:
        return False
    previous = product.current_sbom_id
    if previous == sbom.id:
        return False
    if previous is None:
        lineages = set(db.scalars(select(SBOMSource.logical_sbom_id).where(
            SBOMSource.tenant_id == sbom.tenant_id, SBOMSource.product_id == product.id,
            SBOMSource.projectid == product.project_id, SBOMSource.is_active.is_(True),
            SBOMSource.lifecycle_status == "ACTIVE",
        )))
        if len(lineages) > 1:
            return False  # Keep independently scoped posture; require explicit product designation.
    if previous is not None:
        # Only a declared descendant may replace the selected lineage. Neither
        # upload order nor a matching application name establishes continuity.
        seen, node = set(), sbom
        while node.parent_id is not None and node.id not in seen:
            seen.add(node.id)
            node = db.scalar(select(SBOMSource).where(
                SBOMSource.id == node.parent_id, SBOMSource.tenant_id == sbom.tenant_id,
                SBOMSource.product_id == product.id, SBOMSource.projectid == product.project_id,
            ).execution_options(include_deleted=True))
            if node is None:
                return False
            if node.logical_sbom_id != sbom.logical_sbom_id:
                return False
            if node.id == previous:
                break
        else:
            return False
        # Multiple active branches are an administrator decision. Completion
        # order must not silently choose one deployed branch over another.
        lineage = db.scalars(select(SBOMSource).where(
            SBOMSource.tenant_id == sbom.tenant_id, SBOMSource.product_id == product.id,
            SBOMSource.projectid == product.project_id,
        ).execution_options(include_deleted=True)).all()
        by_id = {row.id: row for row in lineage}

        def path_to_root(row):
            path = set()
            while row is not None and row.id not in path:
                path.add(row.id)
                row = by_id.get(row.parent_id)
            return path

        candidate_path = path_to_root(sbom)
        for other in lineage:
            if not other.is_active or other.lifecycle_status != "ACTIVE":
                continue
            other_path = path_to_root(other)
            if previous in other_path and other.id not in candidate_path and sbom.id not in other_path:
                return False
    product.current_sbom_id = sbom.id
    product.updated_at = run.completed_on
    write_audit_log(
        db, minimal_background_context(run.tenant_id), "product.current_sbom.changed",
        entity_type="product", entity_id=product.id,
        old_value={"current_sbom_id": previous, "mode": "AUTO"},
        new_value={"current_sbom_id": sbom.id, "mode": "AUTO", "source": "analysis.success",
                   "analysis_run_id": run.id, "coverage_incomplete": run.run_status == "PARTIAL"}, strict=True,
    )
    db.flush()
    return True
