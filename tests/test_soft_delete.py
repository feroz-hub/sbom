"""Soft-delete refactor — Phase 3 tests.

Covers the four scenarios called out by ``docs/soft-delete-audit.md`` §6
and the prompt's success-criteria checklist:

* Cascade depth — Project → SBOM → Run → Finding all soft-deleted in a
  single call.
* Cache exclusion — ``ai_fix_cache`` rows are NEVER touched by the
  cascade, even when the finding that "owns" the cache key is
  soft-deleted.
* Unique constraint with tombstones — re-creating a project with the
  same name after a soft-delete succeeds (Option C filter masks the
  tombstone from the application-level uniqueness check).
* List query filtering — both ``select(Model)`` and legacy
  ``db.query(Model)`` paths skip tombstones; ``include_deleted=True``
  bypasses the filter.

Plus restore + audit log + CompareCache hard-delete side effect.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from app.db import SessionLocal
from app.models import (
    AiFixCache,
    AnalysisFinding,
    AnalysisRun,
    AnalysisSchedule,
    AuditLog,
    CompareCache,
    Projects,
    SBOMComponent,
    SBOMSource,
)
from app.services.soft_delete import CASCADE_EXCLUDED_TABLES, SoftDeleteService
from sqlalchemy import select


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


@pytest.fixture()
def db(client):  # client fixture sets DATABASE_URL + creates schema
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def _build_tree(db) -> dict:
    """Build a Project → SBOM → Run → Finding (+ schedule, AI fix cache) tree.

    Returns a dict of created records so individual tests can index in.
    """
    proj = Projects(project_name=f"sd-test-{_now_iso()}", created_by="alice")
    db.add(proj)
    db.flush()

    sbom = SBOMSource(
        sbom_name=f"sd-sbom-{proj.id}",
        projectid=proj.id,
        created_by="alice",
        status="validated",
    )
    db.add(sbom)
    db.flush()

    component = SBOMComponent(sbom_id=sbom.id, name="log4j-core", version="2.16.0")
    db.add(component)
    db.flush()

    run = AnalysisRun(
        sbom_id=sbom.id,
        project_id=proj.id,
        run_status="completed",
        started_on=_now_iso(),
        completed_on=_now_iso(),
        source="NVD",
    )
    db.add(run)
    db.flush()

    finding = AnalysisFinding(
        analysis_run_id=run.id,
        component_id=component.id,
        vuln_id="CVE-2021-44832",
        severity="high",
        component_name="log4j-core",
        component_version="2.16.0",
    )
    db.add(finding)

    schedule = AnalysisSchedule(
        scope="PROJECT",
        project_id=proj.id,
        cadence="DAILY",
        hour_utc=2,
    )
    db.add(schedule)

    # AI fix cache — keyed on (vuln, component, version, prompt_version);
    # tenant-shared, must survive any cascade.
    cache = AiFixCache(
        cache_key=f"sd-test-key-{proj.id}",
        vuln_id="CVE-2021-44832",
        component_name="log4j-core",
        component_version="2.16.0",
        prompt_version="v1",
        remediation_prose={"text": "upgrade"},
        upgrade_command={"cmd": "bump"},
        decision_recommendation={"go": "patch"},
        provider_used="test",
        model_used="test",
        generated_at=_now_iso(),
        expires_at=_now_iso(),
        last_accessed_at=_now_iso(),
    )
    db.add(cache)

    db.commit()

    return {
        "project": proj,
        "sbom": sbom,
        "component": component,
        "run": run,
        "finding": finding,
        "schedule": schedule,
        "cache": cache,
    }


# ---------------------------------------------------------------------------
# 1. Cascade depth
# ---------------------------------------------------------------------------


def test_cascade_walks_full_ownership_tree(db):
    """Soft-deleting a project tombstones every soft-delete-eligible
    descendant in a single call."""
    tree = _build_tree(db)
    proj = tree["project"]

    service = SoftDeleteService(db)
    count = service.soft_delete(proj, user_id="alice", cascade=True)
    db.commit()

    # 6 records: project + sbom + component + run + finding + schedule.
    # AI fix cache is excluded — see test_cache_excluded.
    assert count >= 6, f"expected >=6 cascaded records, got {count}"

    # Tombstones exist in DB (bypassing Option C with include_deleted).
    for record in (
        tree["project"],
        tree["sbom"],
        tree["component"],
        tree["run"],
        tree["finding"],
        tree["schedule"],
    ):
        db.refresh(record)
        assert record.is_active is False, f"{type(record).__name__}({record.id}) was not soft-deleted"
        assert record.deactivated_at is not None
        assert record.deactivated_by == "alice"


# ---------------------------------------------------------------------------
# 2. Cache exclusion — the most expensive bug to ship
# ---------------------------------------------------------------------------


def test_cascade_does_not_touch_ai_fix_cache(db):
    """Soft-deleting the entire ownership tree must NEVER cascade into
    ``ai_fix_cache``. The cache is tenant-shared; tombstoning would
    silently regenerate paid LLM content."""
    tree = _build_tree(db)
    cache_key = tree["cache"].cache_key

    SoftDeleteService(db).soft_delete(tree["project"], user_id="alice")
    db.commit()

    # AiFixCache lacks SoftDeleteMixin, so Option C does NOT filter it.
    # A bare select must still find the row, untouched.
    surviving = db.execute(select(AiFixCache).where(AiFixCache.cache_key == cache_key)).scalar_one_or_none()
    assert surviving is not None, "ai_fix_cache row was deleted by cascade"

    # Defensive: confirm the table name is in the explicit exclusion list.
    assert "ai_fix_cache" in CASCADE_EXCLUDED_TABLES


def test_cascade_excluded_tables_include_audit_logs():
    """The audit_log + ai_credential_audit_log + ai_usage_log tables
    must remain in the exclusion list — they are append-only retention
    surfaces and should outlive every soft-delete."""
    for name in ("audit_log", "ai_credential_audit_log", "ai_usage_log"):
        assert name in CASCADE_EXCLUDED_TABLES, f"{name} missing from cascade exclusion list"


# ---------------------------------------------------------------------------
# 3. Unique constraint with tombstones — re-create after soft-delete
# ---------------------------------------------------------------------------


def test_can_recreate_project_with_same_name_after_soft_delete(db):
    """The application-level project_name uniqueness check (in
    routers/projects.py) MUST not see tombstones — Option C transparent
    filter is what makes that work."""
    proj = Projects(project_name="duplicate-target", created_by="alice")
    db.add(proj)
    db.commit()

    SoftDeleteService(db).soft_delete(proj, user_id="alice", cascade=False)
    db.commit()

    # The default-filtered SELECT (mirroring routers/projects.py:62) must
    # NOT find the tombstone.
    found = db.execute(select(Projects).where(Projects.project_name == "duplicate-target")).first()
    assert found is None, "tombstoned project leaked through the uniqueness check; Option C filter is broken"

    # And include_deleted=True still finds it.
    tombstone = db.execute(
        select(Projects).where(Projects.project_name == "duplicate-target").execution_options(include_deleted=True)
    ).scalar_one_or_none()
    assert tombstone is not None
    assert tombstone.is_active is False


# ---------------------------------------------------------------------------
# 4. List query filtering on both select() and db.query() paths
# ---------------------------------------------------------------------------


def test_list_filtering_applies_to_select_and_legacy_query(db):
    proj = Projects(project_name="filter-test-modern", created_by="alice")
    db.add(proj)
    db.commit()
    pid = proj.id

    SoftDeleteService(db).soft_delete(proj, user_id="alice", cascade=False)
    db.commit()
    # Drop the in-session identity map so the next reads emulate the
    # fresh-session boundary that every HTTP request crosses. Without
    # this, ``Session.get`` returns the cached instance straight from
    # the identity map without re-running the SELECT.
    db.expunge_all()

    # select() path
    by_select = db.execute(select(Projects).where(Projects.id == pid)).scalar_one_or_none()
    assert by_select is None

    # legacy db.query() path — same execution path under the hood
    by_query = db.query(Projects).filter(Projects.id == pid).first()
    assert by_query is None

    # db.get() also goes through do_orm_execute on a fresh fetch
    assert db.get(Projects, pid) is None

    # Bypass works for select()
    bypass_select = db.execute(
        select(Projects).where(Projects.id == pid).execution_options(include_deleted=True)
    ).scalar_one_or_none()
    assert bypass_select is not None and bypass_select.is_active is False


# ---------------------------------------------------------------------------
# 5. Restore
# ---------------------------------------------------------------------------


def test_restore_makes_record_visible_again(db):
    proj = Projects(project_name="restore-target", created_by="alice")
    db.add(proj)
    db.commit()
    pid = proj.id

    service = SoftDeleteService(db)
    service.soft_delete(proj, user_id="alice", cascade=False)
    db.commit()
    db.expunge_all()  # cross the fresh-session boundary

    # Tombstone — invisible by default
    assert db.get(Projects, pid) is None

    # Reload via include_deleted, restore, commit, re-check
    tombstone = db.execute(
        select(Projects).where(Projects.id == pid).execution_options(include_deleted=True)
    ).scalar_one()
    service.restore(tombstone)
    db.commit()

    refreshed = db.get(Projects, pid)
    assert refreshed is not None
    assert refreshed.is_active is True
    assert refreshed.deactivated_at is None
    assert refreshed.deactivated_by is None


def test_restore_does_not_cascade(db):
    """Restoration is per-record. Children stay tombstoned until the
    admin restores them individually."""
    tree = _build_tree(db)
    sbom_id = tree["sbom"].id
    run_id = tree["run"].id
    proj_id = tree["project"].id

    service = SoftDeleteService(db)
    service.soft_delete(tree["project"], user_id="alice", cascade=True)
    db.commit()

    tombstone = db.execute(
        select(Projects).where(Projects.id == proj_id).execution_options(include_deleted=True)
    ).scalar_one()
    service.restore(tombstone)
    db.commit()
    db.expunge_all()  # cross the fresh-session boundary

    # Project active again, but children remain tombstoned.
    assert db.get(Projects, proj_id) is not None
    assert db.get(SBOMSource, sbom_id) is None
    assert db.get(AnalysisRun, run_id) is None


# ---------------------------------------------------------------------------
# 6. CompareCache hard-delete side effect
# ---------------------------------------------------------------------------


def test_run_soft_delete_hard_evicts_compare_cache(db):
    """When a run is soft-deleted, its rows in compare_cache must be
    hard-deleted (cache hygiene; the cache is recomputable from live
    runs only)."""
    tree = _build_tree(db)
    run_id = tree["run"].id

    cache_row = CompareCache(
        cache_key="a" * 64,
        run_a_id=run_id,
        run_b_id=run_id + 9999,
        payload={"hello": "world"},
        computed_at=_now_iso(),
        expires_at=_now_iso(),
    )
    db.add(cache_row)
    db.commit()

    SoftDeleteService(db).soft_delete(tree["run"], user_id="alice", cascade=True)
    db.commit()

    surviving = db.execute(select(CompareCache).where(CompareCache.cache_key == "a" * 64)).scalar_one_or_none()
    assert surviving is None, "compare_cache row should have been hard-deleted alongside the run soft-delete"


# ---------------------------------------------------------------------------
# 7. Audit log writes
# ---------------------------------------------------------------------------


def test_endpoint_writes_audit_row_for_soft_delete(client, db):
    """The HTTP endpoint must write a soft-delete row to ``audit_log``."""
    proj = Projects(project_name="audit-target", created_by="alice")
    db.add(proj)
    db.commit()
    pid = proj.id

    resp = client.delete(
        f"/api/projects/{pid}",
        params={"user_id": "alice", "confirm": "yes"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "deleted"
    assert body["permanent"] is False

    # Audit log row exists
    rows = (
        db.execute(
            select(AuditLog)
            .where(AuditLog.target_kind == "project", AuditLog.target_id == pid)
            .order_by(AuditLog.id.desc())
        )
        .scalars()
        .all()
    )
    assert any(r.action == "project.soft_delete" for r in rows)


def test_endpoint_writes_audit_row_for_permanent_delete(client, db):
    proj = Projects(project_name="audit-perm-target", created_by="alice")
    db.add(proj)
    db.commit()
    pid = proj.id

    resp = client.delete(
        f"/api/projects/{pid}",
        params={"user_id": "alice", "confirm": "yes", "permanent": "true"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["permanent"] is True

    # No row left at all
    assert (
        db.execute(
            select(Projects).where(Projects.id == pid).execution_options(include_deleted=True)
        ).scalar_one_or_none()
        is None
    )

    # Audit row recorded
    rows = (
        db.execute(select(AuditLog).where(AuditLog.target_kind == "project", AuditLog.target_id == pid)).scalars().all()
    )
    assert any(r.action == "project.permanent_delete" for r in rows)


# ---------------------------------------------------------------------------
# 8. Cascade idempotency — re-running the soft-delete is a no-op
# ---------------------------------------------------------------------------


def test_soft_delete_is_idempotent(db):
    proj = Projects(project_name="idem-target", created_by="alice")
    db.add(proj)
    db.commit()

    service = SoftDeleteService(db)
    first = service.soft_delete(proj, user_id="alice", cascade=False)
    db.commit()

    # Reload tombstone via include_deleted and re-attempt
    proj_again = db.execute(
        select(Projects).where(Projects.id == proj.id).execution_options(include_deleted=True)
    ).scalar_one()
    service2 = SoftDeleteService(db)  # fresh visited set
    second = service2.soft_delete(proj_again, user_id="bob", cascade=False)
    db.commit()

    assert first == 1
    assert second == 0  # no-op on already-deleted

    db.refresh(proj_again)
    assert proj_again.deactivated_by == "alice"  # unchanged on second pass
