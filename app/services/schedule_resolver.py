"""Canonical hierarchical schedule and target resolver.

Precedence is SBOM > PRODUCT > PROJECT > TENANT (the tenant layer is kept as
an existing compatibility fallback). A missing child row inherits. A CUSTOM
row may be active or paused, while an EXCLUDED row deliberately blocks all
parent inheritance.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, select

from ..models import AnalysisSchedule, Product, Projects, SBOMSource

CURRENT_ONLY = "CURRENT_ONLY"
ALL_ACTIVE_VERSIONS = "ALL_ACTIVE_VERSIONS"


@dataclass(frozen=True)
class DueTarget:
    sbom_id: int
    schedule_id: int
    schedule_scope: str
    resolution_reason: str = ""


@dataclass(frozen=True)
class EffectiveResolution:
    sbom: SBOMSource
    schedule: AnalysisSchedule | None
    state: str
    reason: str
    included: bool


@dataclass(frozen=True)
class ProductScheduleResolution:
    product: Product
    schedule: AnalysisSchedule | None
    state: str
    reason: str
    included: bool


@dataclass(frozen=True)
class TargetPreview:
    project_id: int | None
    project_name: str | None
    product_id: int | None
    product_name: str | None
    sbom_id: int | None
    sbom_name: str | None
    sbom_version: str | None
    effective_schedule_id: int | None
    effective_scope: str | None
    included: bool
    resolution: str


def _active_projects(db) -> list[Projects]:
    return list(
        db.scalars(
            select(Projects).where(
                Projects.is_active.is_(True),
                Projects.project_status == 1,
            )
        )
    )


def _active_products(db) -> list[Product]:
    active_project_ids = select(Projects.id).where(
        Projects.is_active.is_(True),
        Projects.project_status == 1,
    )
    return list(
        db.scalars(
            select(Product).where(
                Product.is_active.is_(True),
                func.lower(Product.status) == "active",
                Product.project_id.in_(active_project_ids),
            )
        )
    )


def _eligible_sboms(db) -> list[SBOMSource]:
    active_project_ids = select(Projects.id).where(
        Projects.is_active.is_(True),
        Projects.project_status == 1,
    )
    active_product_ids = select(Product.id).where(
        Product.is_active.is_(True),
        func.lower(Product.status) == "active",
        Product.project_id.in_(active_project_ids),
    )
    return list(
        db.scalars(
            select(SBOMSource).where(
                SBOMSource.is_active.is_(True),
                SBOMSource.projectid.in_(active_project_ids),
                SBOMSource.product_id.in_(active_product_ids),
            )
        )
    )


def _schedule_key(schedule: AnalysisSchedule) -> tuple[int, str, int]:
    identifier = (
        schedule.sbom_id
        if schedule.scope == "SBOM"
        else schedule.product_id
        if schedule.scope == "PRODUCT"
        else schedule.project_id
        if schedule.scope == "PROJECT"
        else schedule.tenant_id
    )
    return (int(schedule.tenant_id), schedule.scope, int(identifier))


def _index(schedules) -> dict[tuple[int, str, int], AnalysisSchedule]:
    # Ordering at the query makes even a damaged legacy database with
    # duplicate active rows deterministic until its indexes are repaired.
    return {_schedule_key(schedule): schedule for schedule in schedules}


def _schedule_index(db, tenant_id: int | None = None) -> dict[tuple[int, str, int], AnalysisSchedule]:
    stmt = select(AnalysisSchedule).where(AnalysisSchedule.is_active.is_(True)).order_by(AnalysisSchedule.id)
    if tenant_id is not None:
        stmt = stmt.where(AnalysisSchedule.tenant_id == tenant_id)
    return _index(db.scalars(stmt))


def _effective_row(sbom: SBOMSource, index) -> AnalysisSchedule | None:
    for scope, identifier in (
        ("SBOM", sbom.id),
        ("PRODUCT", sbom.product_id),
        ("PROJECT", sbom.projectid),
        ("TENANT", sbom.tenant_id),
    ):
        if identifier is not None:
            row = index.get((int(sbom.tenant_id), scope, int(identifier)))
            if row is not None:
                return row
    return None


def _valid_current_id(product: Product | None, sboms_by_id: dict[int, SBOMSource]) -> int | None:
    if product is None or product.current_sbom_id is None:
        return None
    sbom = sboms_by_id.get(int(product.current_sbom_id))
    if sbom is None or sbom.product_id != product.id or sbom.tenant_id != product.tenant_id:
        return None
    return int(sbom.id)


def _reason_for_scope(scope: str) -> str:
    return {
        "SBOM": "SBOM_OVERRIDE",
        "PRODUCT": "PRODUCT_OVERRIDE",
        "PROJECT": "PROJECT_INHERITED",
        "TENANT": "TENANT_INHERITED",
    }.get(scope, "NO_SCHEDULE")


def _resolve(
    sbom: SBOMSource,
    index,
    *,
    products_by_id: dict[int, Product],
    sboms_by_id: dict[int, SBOMSource],
) -> EffectiveResolution:
    row = _effective_row(sbom, index)
    if row is None:
        return EffectiveResolution(sbom, None, "NONE", "NO_SCHEDULE", False)
    if row.mode == "EXCLUDED":
        return EffectiveResolution(sbom, row, "EXCLUDED", "EXCLUDED", False)
    if not row.enabled:
        return EffectiveResolution(sbom, row, "PAUSED", "PAUSED", False)
    if row.scope in {"TENANT", "PROJECT", "PRODUCT"} and row.target_version_policy == CURRENT_ONLY:
        product = products_by_id.get(int(sbom.product_id)) if sbom.product_id is not None else None
        current_id = _valid_current_id(product, sboms_by_id)
        if current_id is None:
            return EffectiveResolution(sbom, row, "INHERITED", "NO_CURRENT_SBOM", False)
        if current_id != sbom.id:
            return EffectiveResolution(sbom, row, "INHERITED", "HISTORICAL_VERSION", False)
    state = "CUSTOM" if row.scope == "SBOM" else "INHERITED"
    return EffectiveResolution(sbom, row, state, _reason_for_scope(row.scope), True)


def resolve_effective_schedule(db, sbom_id: int) -> EffectiveResolution | None:
    active_project_ids = select(Projects.id).where(
        Projects.is_active.is_(True),
        Projects.project_status == 1,
    )
    sbom = db.scalar(
        select(SBOMSource).where(
            SBOMSource.id == sbom_id,
            SBOMSource.is_active.is_(True),
            SBOMSource.projectid.in_(active_project_ids),
        )
    )
    if sbom is None:
        return None
    products = _active_products(db)
    products_by_id = {item.id: item for item in products}
    # Legacy SBOMs created before the Product hierarchy may not have a
    # product_id.  They remain resolvable for diagnostics and explicit SBOM
    # overrides, but a parent CURRENT_ONLY policy cannot select them without
    # an explicit Product.current_sbom_id.
    if sbom.product_id is not None and int(sbom.product_id) not in products_by_id:
        return None
    sboms = _eligible_sboms(db)
    sboms_by_id = {item.id: item for item in sboms}
    sboms_by_id.setdefault(int(sbom.id), sbom)
    return _resolve(
        sbom,
        _schedule_index(db, sbom.tenant_id),
        products_by_id=products_by_id,
        sboms_by_id=sboms_by_id,
    )


def resolve_for_sbom(db, sbom_id: int) -> AnalysisSchedule | None:
    """Backward-compatible row-only view used by existing callers."""
    resolution = resolve_effective_schedule(db, sbom_id)
    return resolution.schedule if resolution else None


def resolve_effective_schedule_for_product(db, product_id: int) -> ProductScheduleResolution | None:
    product = next((item for item in _active_products(db) if item.id == product_id), None)
    if product is None:
        return None
    index = _schedule_index(db, product.tenant_id)
    row = (
        index.get((int(product.tenant_id), "PRODUCT", int(product.id)))
        or index.get((int(product.tenant_id), "PROJECT", int(product.project_id)))
        or index.get((int(product.tenant_id), "TENANT", int(product.tenant_id)))
    )
    if row is None:
        return ProductScheduleResolution(product, None, "NONE", "NO_SCHEDULE", False)
    if row.mode == "EXCLUDED":
        return ProductScheduleResolution(product, row, "EXCLUDED", "EXCLUDED", False)
    if not row.enabled:
        return ProductScheduleResolution(product, row, "PAUSED", "PAUSED", False)
    state = "CUSTOM" if row.scope == "PRODUCT" else "INHERITED"
    reason = "PRODUCT_OVERRIDE" if row.scope == "PRODUCT" else _reason_for_scope(row.scope)
    previews = preview_targets_for_schedule(db, row)
    included = any(item.included and item.product_id == product.id for item in previews)
    return ProductScheduleResolution(product, row, state, reason, included)


def find_due_targets(db, now_iso_str: str) -> list[DueTarget]:
    sboms = _eligible_sboms(db)
    products = _active_products(db)
    index = _schedule_index(db)
    products_by_id = {item.id: item for item in products}
    sboms_by_id = {item.id: item for item in sboms}
    targets: dict[tuple[int, int], DueTarget] = {}
    for sbom in sboms:
        resolution = _resolve(
            sbom,
            index,
            products_by_id=products_by_id,
            sboms_by_id=sboms_by_id,
        )
        row = resolution.schedule
        if not resolution.included or row is None or not row.next_run_at or row.next_run_at > now_iso_str:
            continue
        targets[(int(sbom.tenant_id), int(sbom.id))] = DueTarget(
            sbom_id=int(sbom.id),
            schedule_id=int(row.id),
            schedule_scope=row.scope,
            resolution_reason=resolution.reason,
        )
    return sorted(targets.values(), key=lambda item: (item.schedule_id, item.sbom_id))


def _in_scope(schedule: AnalysisSchedule, sbom: SBOMSource) -> bool:
    if schedule.tenant_id != sbom.tenant_id:
        return False
    if schedule.scope == "TENANT":
        return True
    if schedule.scope == "PROJECT":
        return schedule.project_id == sbom.projectid
    if schedule.scope == "PRODUCT":
        return schedule.product_id == sbom.product_id
    return schedule.scope == "SBOM" and schedule.sbom_id == sbom.id


def preview_targets_for_schedule(db, schedule: AnalysisSchedule) -> list[TargetPreview]:
    sboms = _eligible_sboms(db)
    projects = _active_projects(db)
    products = _active_products(db)
    index = _schedule_index(db, schedule.tenant_id)
    projects_by_id = {item.id: item for item in projects}
    products_by_id = {item.id: item for item in products}
    sboms_by_id = {item.id: item for item in sboms}

    previews: list[TargetPreview] = []
    for sbom in sboms:
        if not _in_scope(schedule, sbom):
            continue
        resolution = _resolve(
            sbom,
            index,
            products_by_id=products_by_id,
            sboms_by_id=sboms_by_id,
        )
        effective = resolution.schedule
        owns_target = effective is not None and effective.id == schedule.id
        reason = resolution.reason
        if not owns_target and effective is not None:
            if effective.mode == "EXCLUDED":
                reason = "EXCLUDED"
            elif not effective.enabled:
                reason = "PAUSED"
            else:
                reason = f"OVERRIDDEN_BY_{effective.scope}"
        product = products_by_id.get(int(sbom.product_id)) if sbom.product_id is not None else None
        project = projects_by_id.get(int(sbom.projectid)) if sbom.projectid is not None else None
        previews.append(
            TargetPreview(
                project_id=sbom.projectid,
                project_name=project.project_name if project else None,
                product_id=sbom.product_id,
                product_name=product.name if product else sbom.product_name,
                sbom_id=sbom.id,
                sbom_name=sbom.sbom_name,
                sbom_version=sbom.sbom_version or sbom.productver,
                effective_schedule_id=effective.id if effective else None,
                effective_scope=effective.scope if effective else None,
                included=bool(owns_target and resolution.included),
                resolution=reason,
            )
        )

    # Make missing current-SBOM configuration visible even when a product has
    # no SBOM rows at all.
    if schedule.scope in {"TENANT", "PROJECT", "PRODUCT"} and schedule.target_version_policy == CURRENT_ONLY:
        represented = {item.product_id for item in previews}
        for product in products:
            if product.tenant_id != schedule.tenant_id:
                continue
            if schedule.scope == "PROJECT" and product.project_id != schedule.project_id:
                continue
            if schedule.scope == "PRODUCT" and product.id != schedule.product_id:
                continue
            if _valid_current_id(product, sboms_by_id) is not None or product.id in represented:
                continue
            project = projects_by_id.get(product.project_id)
            effective = (
                index.get((int(product.tenant_id), "PRODUCT", int(product.id)))
                or index.get((int(product.tenant_id), "PROJECT", int(product.project_id)))
                or index.get((int(product.tenant_id), "TENANT", int(product.tenant_id)))
            )
            if effective is None:
                reason = "NO_SCHEDULE"
            elif effective.mode == "EXCLUDED":
                reason = "EXCLUDED"
            elif not effective.enabled:
                reason = "PAUSED"
            elif effective.id != schedule.id:
                reason = f"OVERRIDDEN_BY_{effective.scope}"
            else:
                reason = "NO_CURRENT_SBOM"
            previews.append(
                TargetPreview(
                    project_id=product.project_id,
                    project_name=project.project_name if project else None,
                    product_id=product.id,
                    product_name=product.name,
                    sbom_id=None,
                    sbom_name=None,
                    sbom_version=None,
                    effective_schedule_id=effective.id if effective else None,
                    effective_scope=effective.scope if effective else None,
                    included=False,
                    resolution=reason,
                )
            )

    return sorted(
        previews,
        key=lambda item: (
            item.project_name or "",
            item.product_name or "",
            item.sbom_name or "",
            item.sbom_id or 0,
        ),
    )


def targets_for_schedule(db, schedule: AnalysisSchedule) -> list[int]:
    """Concrete targets for Run Now, using exactly the preview rules."""
    return [int(item.sbom_id) for item in preview_targets_for_schedule(db, schedule) if item.included and item.sbom_id]
