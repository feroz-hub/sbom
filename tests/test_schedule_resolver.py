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


def _make_sbom(db, project_id: int, name: str):
    from app.models import SBOMSource

    s = SBOMSource(sbom_name=name, projectid=project_id, created_on=_now_iso())
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


def _make_schedule(db, *, scope, project_id=None, sbom_id=None, next_run_at, enabled=True):
    from app.models import AnalysisSchedule

    sched = AnalysisSchedule(
        scope=scope,
        project_id=project_id,
        sbom_id=sbom_id,
        cadence="DAILY",
        hour_utc=2,
        enabled=enabled,
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


def test_project_schedule_expands_to_all_member_sboms(db):
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
