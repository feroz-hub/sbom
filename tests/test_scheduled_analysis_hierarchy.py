"""Worker-level checks for hierarchical scheduling decisions."""

from datetime import UTC, datetime, timedelta

import pytest


@pytest.fixture
def db(client):
    from app.db import SessionLocal

    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def _now(offset_minutes: int = 0) -> str:
    return (datetime.now(UTC) + timedelta(minutes=offset_minutes)).replace(microsecond=0).isoformat()


def _hierarchy(db, suffix: str, *, set_current: bool = True):
    from app.models import Product, Projects, SBOMSource

    project = Projects(project_name=f"worker-project-{suffix}", project_status=1, created_on=_now())
    db.add(project)
    db.flush()
    product = Product(
        project_id=project.id,
        name=f"worker-product-{suffix}",
        normalized_name=f"worker-product-{suffix}",
        slug=f"worker-product-{suffix}",
        status="active",
        created_at=_now(),
    )
    db.add(product)
    db.flush()
    sbom = SBOMSource(
        sbom_name=f"worker-sbom-{suffix}",
        projectid=project.id,
        product_id=product.id,
        created_on=_now(),
    )
    db.add(sbom)
    db.flush()
    if set_current:
        product.current_sbom_id = sbom.id
    db.commit()
    return project, product, sbom


def test_due_schedule_without_current_target_advances_its_cursor(db):
    from app.models import AnalysisSchedule
    from app.workers.scheduled_analysis import tick_scheduled_analyses

    _project, product, _sbom = _hierarchy(db, "no-current", set_current=False)
    schedule = AnalysisSchedule(
        scope="PRODUCT",
        product_id=product.id,
        cadence="DAILY",
        hour_utc=2,
        mode="CUSTOM",
        target_version_policy="CURRENT_ONLY",
        enabled=True,
        next_run_at=_now(-10),
        created_on=_now(),
    )
    db.add(schedule)
    db.commit()
    schedule_id = schedule.id

    result = tick_scheduled_analyses.run()
    db.expire_all()
    refreshed = db.get(AnalysisSchedule, schedule_id)
    assert result == {"due": 1, "targets": 0, "enqueued": 0}
    assert refreshed.next_run_at > _now()


def test_worker_rechecks_override_before_external_analysis(db, monkeypatch):
    from app.models import AnalysisSchedule
    from app.workers.scheduled_analysis import analyze_sbom_async

    project, product, sbom = _hierarchy(db, "recheck")
    parent = AnalysisSchedule(
        scope="PROJECT",
        project_id=project.id,
        cadence="DAILY",
        hour_utc=2,
        mode="CUSTOM",
        target_version_policy="CURRENT_ONLY",
        enabled=True,
        next_run_at=_now(60),
        created_on=_now(),
    )
    exclusion = AnalysisSchedule(
        scope="PRODUCT",
        product_id=product.id,
        cadence="DAILY",
        hour_utc=2,
        mode="EXCLUDED",
        target_version_policy="CURRENT_ONLY",
        enabled=False,
        created_on=_now(),
    )
    db.add_all([parent, exclusion])
    db.commit()

    async def _must_not_run(*args, **kwargs):  # pragma: no cover - assertion sentinel
        raise AssertionError("analysis must not run after the target is excluded")

    monkeypatch.setattr("app.services.analysis_orchestrator.AnalysisOrchestrator.run", _must_not_run)
    result = analyze_sbom_async.run(sbom_id=sbom.id, schedule_id=parent.id)
    assert result == {"status": "SKIPPED", "reason": "EXCLUDED"}


def test_recent_completed_run_respects_minimum_gap(db):
    from app.models import AnalysisRun
    from app.workers.scheduled_analysis import _recent_run_exists

    project, product, sbom = _hierarchy(db, "gap")
    run = AnalysisRun(
        sbom_id=sbom.id,
        project_id=project.id,
        product_id=product.id,
        run_status="OK",
        source="NVD",
        started_on=_now(-2),
        completed_on=_now(-1),
        total_findings=0,
    )
    db.add(run)
    db.commit()
    assert _recent_run_exists(db, sbom.id, 60) is True
    assert _recent_run_exists(db, sbom.id, 0) is False
