"""Tests for app.services.schedule_resolver — cascade & override semantics."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest


@pytest.fixture
def db(client):
    """Yield a SQLAlchemy session bound to the test database.

    Depends on ``client`` (not ``app``) so the FastAPI lifespan has run and
    Base.metadata.create_all has built the schema.
    """
    from app.db import SessionLocal

    s = SessionLocal()
    try:
        yield s
    finally:
        s.rollback()
        s.close()


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _past_iso(minutes: int = 5) -> str:
    return (datetime.now(UTC) - timedelta(minutes=minutes)).replace(microsecond=0).isoformat()


def _future_iso(hours: int = 24) -> str:
    return (datetime.now(UTC) + timedelta(hours=hours)).replace(microsecond=0).isoformat()


def _make_project(db, name: str):
    from app.models import Projects

    p = Projects(project_name=name, project_status=1, created_on=_now_iso())
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


def _make_product(db, project_id: int, name: str):
    from app.models import Product

    slug = name.lower().replace(" ", "-")
    product = Product(
        project_id=project_id,
        name=name,
        normalized_name=name.lower(),
        slug=slug,
        status="active",
        created_at=_now_iso(),
    )
    db.add(product)
    db.commit()
    db.refresh(product)
    return product


def _make_sbom(db, project_id: int, name: str, *, product=None, current: bool = True):
    from app.models import SBOMSource

    product = product or _make_product(db, project_id, f"product-{name}")

    s = SBOMSource(
        sbom_name=name,
        projectid=project_id,
        product_id=product.id,
        product_name=product.name,
        created_on=_now_iso(),
    )
    db.add(s)
    db.flush()
    if current:
        product.current_sbom_id = s.id
    db.commit()
    db.refresh(s)
    return s


def _make_schedule(
    db,
    *,
    scope,
    project_id=None,
    product_id=None,
    sbom_id=None,
    next_run_at,
    enabled=True,
    mode="CUSTOM",
    target_version_policy="CURRENT_ONLY",
):
    from app.models import AnalysisSchedule

    sched = AnalysisSchedule(
        scope=scope,
        project_id=project_id,
        product_id=product_id,
        sbom_id=sbom_id,
        cadence="DAILY",
        hour_utc=2,
        enabled=enabled,
        mode=mode,
        target_version_policy=target_version_policy,
        next_run_at=next_run_at,
        created_on=_now_iso(),
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)
    return sched


# ---------------------------------------------------------------------------
# find_due_targets — fan-out logic for tick task
# ---------------------------------------------------------------------------


def test_project_schedule_expands_to_current_sbom_of_each_product(db):
    from app.services.schedule_resolver import find_due_targets

    p = _make_project(db, "resolver-proj-1")
    s1 = _make_sbom(db, p.id, "resolver-sbom-1a")
    s2 = _make_sbom(db, p.id, "resolver-sbom-1b")
    _make_schedule(db, scope="PROJECT", project_id=p.id, next_run_at=_past_iso())

    targets = find_due_targets(db, _now_iso())
    sbom_ids = {t.sbom_id for t in targets if t.sbom_id in {s1.id, s2.id}}
    assert sbom_ids == {s1.id, s2.id}
    assert all(t.schedule_scope == "PROJECT" for t in targets if t.sbom_id in {s1.id, s2.id})


def test_sbom_override_replaces_project_cascade(db):
    from app.services.schedule_resolver import find_due_targets

    p = _make_project(db, "resolver-proj-2")
    s1 = _make_sbom(db, p.id, "resolver-sbom-2a")
    s2 = _make_sbom(db, p.id, "resolver-sbom-2b")

    # Project schedule due now
    _make_schedule(db, scope="PROJECT", project_id=p.id, next_run_at=_past_iso())
    # s1 has its own SBOM-level schedule (also due now)
    _make_schedule(db, scope="SBOM", sbom_id=s1.id, next_run_at=_past_iso())

    targets = find_due_targets(db, _now_iso())
    by_sbom = {t.sbom_id: t for t in targets if t.sbom_id in {s1.id, s2.id}}
    # s1 fired via its own SBOM-scope schedule, NOT the project cascade
    assert by_sbom[s1.id].schedule_scope == "SBOM"
    # s2 has no override → fires via project cascade
    assert by_sbom[s2.id].schedule_scope == "PROJECT"


def test_disabled_sbom_override_still_blocks_cascade(db):
    """An explicit SBOM-level row, even paused, opts out of the cascade."""
    from app.services.schedule_resolver import find_due_targets

    p = _make_project(db, "resolver-proj-3")
    s1 = _make_sbom(db, p.id, "resolver-sbom-3a")
    _make_schedule(db, scope="PROJECT", project_id=p.id, next_run_at=_past_iso())
    _make_schedule(
        db,
        scope="SBOM",
        sbom_id=s1.id,
        next_run_at=_past_iso(),
        enabled=False,  # paused — should still block project cascade
    )

    targets = find_due_targets(db, _now_iso())
    assert s1.id not in {t.sbom_id for t in targets}


def test_future_next_run_at_not_returned(db):
    from app.services.schedule_resolver import find_due_targets

    p = _make_project(db, "resolver-proj-4")
    s1 = _make_sbom(db, p.id, "resolver-sbom-4a")
    _make_schedule(db, scope="SBOM", sbom_id=s1.id, next_run_at=_future_iso())

    targets = find_due_targets(db, _now_iso())
    assert s1.id not in {t.sbom_id for t in targets}


# ---------------------------------------------------------------------------
# resolve_for_sbom — for the "inherited" UI badge
# ---------------------------------------------------------------------------


def test_resolve_for_sbom_returns_own_schedule(db):
    from app.services.schedule_resolver import resolve_for_sbom

    p = _make_project(db, "resolver-proj-5")
    s1 = _make_sbom(db, p.id, "resolver-sbom-5a")
    _make_schedule(db, scope="PROJECT", project_id=p.id, next_run_at=_future_iso())
    own = _make_schedule(db, scope="SBOM", sbom_id=s1.id, next_run_at=_future_iso())

    resolved = resolve_for_sbom(db, s1.id)
    assert resolved is not None
    assert resolved.id == own.id
    assert resolved.scope == "SBOM"


def test_resolve_for_sbom_falls_back_to_project(db):
    from app.services.schedule_resolver import resolve_for_sbom

    p = _make_project(db, "resolver-proj-6")
    s1 = _make_sbom(db, p.id, "resolver-sbom-6a")
    proj_sched = _make_schedule(db, scope="PROJECT", project_id=p.id, next_run_at=_future_iso())

    resolved = resolve_for_sbom(db, s1.id)
    assert resolved is not None
    assert resolved.id == proj_sched.id
    assert resolved.scope == "PROJECT"


def test_resolve_for_sbom_returns_none_when_no_schedule(db):
    from app.services.schedule_resolver import resolve_for_sbom

    p = _make_project(db, "resolver-proj-7")
    s1 = _make_sbom(db, p.id, "resolver-sbom-7a")

    assert resolve_for_sbom(db, s1.id) is None


# ---------------------------------------------------------------------------
# Hierarchical target policy, exclusions, and deterministic current versions
# ---------------------------------------------------------------------------


def test_project_current_only_skips_historical_versions(db):
    from app.services.schedule_resolver import find_due_targets

    project = _make_project(db, "current-only-project")
    product = _make_product(db, project.id, "current-only-product")
    historical = _make_sbom(db, project.id, "history-1", product=product, current=False)
    current = _make_sbom(db, project.id, "current-2", product=product, current=True)
    _make_schedule(db, scope="PROJECT", project_id=project.id, next_run_at=_past_iso())

    ids = {target.sbom_id for target in find_due_targets(db, _now_iso())}
    assert current.id in ids
    assert historical.id not in ids


def test_product_current_only_targets_explicit_current(db):
    from app.services.schedule_resolver import find_due_targets

    project = _make_project(db, "product-current-project")
    product = _make_product(db, project.id, "product-current")
    historical = _make_sbom(db, project.id, "product-history", product=product, current=False)
    current = _make_sbom(db, project.id, "product-current-sbom", product=product, current=True)
    schedule = _make_schedule(
        db,
        scope="PRODUCT",
        product_id=product.id,
        next_run_at=_past_iso(),
    )

    targets = [target for target in find_due_targets(db, _now_iso()) if target.schedule_id == schedule.id]
    assert [target.sbom_id for target in targets] == [current.id]
    assert historical.id not in {target.sbom_id for target in targets}


def test_product_all_active_versions_targets_every_active_version(db):
    from app.services.schedule_resolver import find_due_targets

    project = _make_project(db, "product-all-project")
    product = _make_product(db, project.id, "product-all")
    first = _make_sbom(db, project.id, "all-first", product=product, current=False)
    second = _make_sbom(db, project.id, "all-second", product=product, current=True)
    schedule = _make_schedule(
        db,
        scope="PRODUCT",
        product_id=product.id,
        next_run_at=_past_iso(),
        target_version_policy="ALL_ACTIVE_VERSIONS",
    )

    ids = {target.sbom_id for target in find_due_targets(db, _now_iso()) if target.schedule_id == schedule.id}
    assert ids == {first.id, second.id}


def test_project_all_active_versions_respects_product_and_sbom_overrides(db):
    from app.services.schedule_resolver import find_due_targets

    project = _make_project(db, "project-all")
    inherited_product = _make_product(db, project.id, "inherited-product")
    inherited_a = _make_sbom(db, project.id, "inherited-a", product=inherited_product, current=False)
    inherited_b = _make_sbom(db, project.id, "inherited-b", product=inherited_product, current=True)
    overridden_product = _make_product(db, project.id, "overridden-product")
    blocked = _make_sbom(db, project.id, "blocked-by-product", product=overridden_product)
    exact_override = _make_sbom(db, project.id, "blocked-by-sbom", product=inherited_product, current=False)

    project_schedule = _make_schedule(
        db,
        scope="PROJECT",
        project_id=project.id,
        next_run_at=_past_iso(),
        target_version_policy="ALL_ACTIVE_VERSIONS",
    )
    _make_schedule(db, scope="PRODUCT", product_id=overridden_product.id, next_run_at=_future_iso())
    _make_schedule(db, scope="SBOM", sbom_id=exact_override.id, next_run_at=_future_iso())

    ids = {
        target.sbom_id
        for target in find_due_targets(db, _now_iso())
        if target.schedule_id == project_schedule.id
    }
    assert ids == {inherited_a.id, inherited_b.id}
    assert blocked.id not in ids
    assert exact_override.id not in ids


@pytest.mark.parametrize("mode,enabled", [("EXCLUDED", False), ("CUSTOM", False)])
def test_product_excluded_or_paused_blocks_project_inheritance(db, mode, enabled):
    from app.services.schedule_resolver import find_due_targets, resolve_effective_schedule

    project = _make_project(db, f"blocked-product-{mode}")
    product = _make_product(db, project.id, f"blocked-{mode}")
    sbom = _make_sbom(db, project.id, f"blocked-{mode}-sbom", product=product)
    _make_schedule(db, scope="PROJECT", project_id=project.id, next_run_at=_past_iso())
    child = _make_schedule(
        db,
        scope="PRODUCT",
        product_id=product.id,
        next_run_at=_past_iso(),
        mode=mode,
        enabled=enabled,
    )

    resolution = resolve_effective_schedule(db, sbom.id)
    assert resolution is not None
    assert resolution.schedule.id == child.id
    assert resolution.state == ("EXCLUDED" if mode == "EXCLUDED" else "PAUSED")
    assert sbom.id not in {target.sbom_id for target in find_due_targets(db, _now_iso())}


@pytest.mark.parametrize("mode,enabled", [("EXCLUDED", False), ("CUSTOM", False)])
def test_sbom_excluded_or_paused_blocks_parent_inheritance(db, mode, enabled):
    from app.services.schedule_resolver import find_due_targets, resolve_effective_schedule

    project = _make_project(db, f"blocked-sbom-{mode}")
    product = _make_product(db, project.id, f"blocked-sbom-product-{mode}")
    sbom = _make_sbom(db, project.id, f"blocked-sbom-{mode}", product=product)
    _make_schedule(db, scope="PRODUCT", product_id=product.id, next_run_at=_past_iso())
    child = _make_schedule(
        db,
        scope="SBOM",
        sbom_id=sbom.id,
        next_run_at=_past_iso(),
        mode=mode,
        enabled=enabled,
    )

    resolution = resolve_effective_schedule(db, sbom.id)
    assert resolution is not None and resolution.schedule.id == child.id
    assert sbom.id not in {target.sbom_id for target in find_due_targets(db, _now_iso())}


def test_no_current_sbom_is_skipped_and_visible_in_preview(db):
    from app.services.schedule_resolver import find_due_targets, preview_targets_for_schedule

    project = _make_project(db, "no-current-project")
    product = _make_product(db, project.id, "no-current-product")
    historical = _make_sbom(db, project.id, "no-current-history", product=product, current=False)
    schedule = _make_schedule(db, scope="PRODUCT", product_id=product.id, next_run_at=_past_iso())

    assert historical.id not in {target.sbom_id for target in find_due_targets(db, _now_iso())}
    preview = preview_targets_for_schedule(db, schedule)
    assert any(item.product_id == product.id and item.resolution == "NO_CURRENT_SBOM" for item in preview)
    assert not any(item.included for item in preview)


def test_project_preview_attributes_empty_product_to_product_override(db):
    from app.services.schedule_resolver import preview_targets_for_schedule

    project = _make_project(db, "empty-product-preview-project")
    product = _make_product(db, project.id, "empty-product-preview")
    parent = _make_schedule(db, scope="PROJECT", project_id=project.id, next_run_at=_future_iso())
    child = _make_schedule(db, scope="PRODUCT", product_id=product.id, next_run_at=_future_iso())

    preview = [item for item in preview_targets_for_schedule(db, parent) if item.product_id == product.id]
    assert len(preview) == 1
    assert preview[0].effective_schedule_id == child.id
    assert preview[0].effective_scope == "PRODUCT"
    assert preview[0].resolution == "OVERRIDDEN_BY_PRODUCT"
    assert preview[0].included is False


def test_changing_current_sbom_changes_next_target_without_restart(db):
    from app.services.schedule_resolver import targets_for_schedule

    project = _make_project(db, "change-current-project")
    product = _make_product(db, project.id, "change-current-product")
    first = _make_sbom(db, project.id, "change-first", product=product, current=True)
    second = _make_sbom(db, project.id, "change-second", product=product, current=False)
    schedule = _make_schedule(db, scope="PRODUCT", product_id=product.id, next_run_at=_future_iso())
    assert targets_for_schedule(db, schedule) == [first.id]

    product.current_sbom_id = second.id
    db.commit()
    assert targets_for_schedule(db, schedule) == [second.id]


def test_soft_deleted_product_sbom_and_schedule_never_execute(db):
    from app.services.schedule_resolver import find_due_targets

    project = _make_project(db, "deleted-project")
    product = _make_product(db, project.id, "deleted-product")
    sbom = _make_sbom(db, project.id, "deleted-sbom", product=product)
    schedule = _make_schedule(db, scope="PRODUCT", product_id=product.id, next_run_at=_past_iso())

    sbom.is_active = False
    db.commit()
    assert sbom.id not in {target.sbom_id for target in find_due_targets(db, _now_iso())}

    sbom.is_active = True
    product.is_active = False
    db.commit()
    assert sbom.id not in {target.sbom_id for target in find_due_targets(db, _now_iso())}

    product.is_active = True
    schedule.is_active = False
    db.commit()
    assert sbom.id not in {target.sbom_id for target in find_due_targets(db, _now_iso())}


def test_due_target_is_deduplicated_and_most_specific_schedule_wins(db):
    from app.services.schedule_resolver import find_due_targets

    project = _make_project(db, "dedupe-project")
    product = _make_product(db, project.id, "dedupe-product")
    sbom = _make_sbom(db, project.id, "dedupe-sbom", product=product)
    _make_schedule(db, scope="PROJECT", project_id=project.id, next_run_at=_past_iso())
    _make_schedule(db, scope="PRODUCT", product_id=product.id, next_run_at=_past_iso())
    exact = _make_schedule(db, scope="SBOM", sbom_id=sbom.id, next_run_at=_past_iso())

    targets = [target for target in find_due_targets(db, _now_iso()) if target.sbom_id == sbom.id]
    assert len(targets) == 1
    assert targets[0].schedule_id == exact.id
    assert targets[0].schedule_scope == "SBOM"
