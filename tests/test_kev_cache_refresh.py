from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest
from app.db import Base
from app.models import AnalysisFinding, AnalysisRun, KevEntry, Projects, SBOMSource
from app.sources import kev as kev_module
from sqlalchemy import create_engine, delete
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.orm import sessionmaker


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _kev_item(
    cve_id: str,
    *,
    vendor_project: str = "Acme",
    product: str = "Widget",
    vulnerability_name: str = "Widget bug",
) -> dict:
    return {
        "cveID": cve_id,
        "vendorProject": vendor_project,
        "product": product,
        "vulnerabilityName": vulnerability_name,
        "dateAdded": "2026-01-01",
        "shortDescription": "test feed row",
        "requiredAction": "patch",
        "dueDate": "2026-02-01",
        "knownRansomwareCampaignUse": "Unknown",
    }


def _session_factory(url: str = "sqlite:///:memory:"):
    kwargs = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite:///") else {}
    engine = create_engine(url, **kwargs)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine), engine


@pytest.fixture(autouse=True)
def _reset_kev_refresh_state():
    kev_module.reset_refresh_state_for_tests()
    yield
    kev_module.reset_refresh_state_for_tests()


def test_refresh_empty_cache(monkeypatch):
    SessionFactory, _engine = _session_factory()
    db = SessionFactory()
    monkeypatch.setattr(kev_module, "_fetch_feed", lambda: [_kev_item("CVE-2026-45659")])

    assert kev_module.refresh_if_stale(db) is True

    row = db.get(KevEntry, "CVE-2026-45659")
    assert row is not None
    assert row.product == "Widget"
    assert db.query(KevEntry).count() == 1


def test_refresh_same_feed_twice_is_idempotent(monkeypatch):
    SessionFactory, _engine = _session_factory()
    db = SessionFactory()
    monkeypatch.setattr(kev_module, "_fetch_feed", lambda: [_kev_item("CVE-2026-45659")])

    assert kev_module.refresh_if_stale(db, force=True) is True
    assert kev_module.refresh_if_stale(db, force=True) is True

    assert db.query(KevEntry).count() == 1
    assert db.get(KevEntry, "CVE-2026-45659").vendor_project == "Acme"


def test_refresh_updates_existing_cve(monkeypatch):
    SessionFactory, _engine = _session_factory()
    db = SessionFactory()
    monkeypatch.setattr(kev_module, "_fetch_feed", lambda: [_kev_item("CVE-2026-45659", product="Old")])
    assert kev_module.refresh_if_stale(db, force=True) is True

    monkeypatch.setattr(
        kev_module,
        "_fetch_feed",
        lambda: [_kev_item("CVE-2026-45659", product="New", vulnerability_name="Updated bug")],
    )
    assert kev_module.refresh_if_stale(db, force=True) is True

    row = db.get(KevEntry, "CVE-2026-45659")
    assert row.product == "New"
    assert row.vulnerability_name == "Updated bug"
    assert db.query(KevEntry).count() == 1


def test_duplicate_cve_entries_in_source_feed_are_deduped(monkeypatch):
    SessionFactory, _engine = _session_factory()
    db = SessionFactory()
    monkeypatch.setattr(
        kev_module,
        "_fetch_feed",
        lambda: [
            _kev_item("CVE-2026-45659", product="First"),
            _kev_item("cve-2026-45659", product="Second"),
        ],
    )

    assert kev_module.refresh_if_stale(db, force=True) is True

    assert db.query(KevEntry).count() == 1
    assert db.get(KevEntry, "CVE-2026-45659").product == "Second"


def test_concurrent_refresh_calls_singleflight(monkeypatch, tmp_path):
    SessionFactory, _engine = _session_factory(f"sqlite:///{tmp_path / 'kev.db'}")
    fetch_count = 0
    fetch_count_lock = threading.Lock()

    def fetch_feed():
        nonlocal fetch_count
        with fetch_count_lock:
            fetch_count += 1
        time.sleep(0.05)
        return [_kev_item("CVE-2026-45659")]

    monkeypatch.setattr(kev_module, "_fetch_feed", fetch_feed)

    def refresh_once() -> bool:
        db = SessionFactory()
        try:
            return kev_module.refresh_if_stale(db)
        finally:
            db.close()

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda _: refresh_once(), range(6)))

    db = SessionFactory()
    try:
        assert results.count(True) == 1
        assert fetch_count == 1
        assert db.query(KevEntry).count() == 1
    finally:
        db.close()


def test_postgresql_upsert_statement_uses_on_conflict_do_update():
    row = kev_module._row_from_feed_item(_kev_item("CVE-2026-45659"), refreshed_at=_now_iso())
    stmt = kev_module._build_upsert_statement([row], dialect="postgresql")
    compiled = str(stmt.compile(dialect=postgresql.dialect()))

    assert "ON CONFLICT (cve_id) DO UPDATE" in compiled
    assert "vendor_project = excluded.vendor_project" in compiled
    assert "refreshed_at = excluded.refreshed_at" in compiled


def test_sqlite_upsert_statement_uses_on_conflict_do_update():
    row = kev_module._row_from_feed_item(_kev_item("CVE-2026-45659"), refreshed_at=_now_iso())
    stmt = kev_module._build_upsert_statement([row], dialect="sqlite")
    compiled = str(stmt.compile(dialect=sqlite.dialect()))

    assert "ON CONFLICT (cve_id) DO UPDATE" in compiled
    assert "vendor_project = excluded.vendor_project" in compiled
    assert "refreshed_at = excluded.refreshed_at" in compiled


def _seed_dashboard_finding(db) -> None:
    project = Projects(project_name="kev-dashboard", project_status=1, created_on=_now_iso())
    db.add(project)
    db.flush()
    sbom = SBOMSource(sbom_name="kev-dashboard-sbom", projectid=project.id, created_on=_now_iso())
    db.add(sbom)
    db.flush()
    run = AnalysisRun(
        sbom_id=sbom.id,
        project_id=project.id,
        run_status="FINDINGS",
        sbom_name=sbom.sbom_name,
        source="TEST",
        started_on=_now_iso(),
        completed_on=_now_iso(),
        duration_ms=1,
        total_components=1,
        total_findings=1,
        high_count=1,
        query_error_count=0,
    )
    db.add(run)
    db.flush()
    db.add(
        AnalysisFinding(
            analysis_run_id=run.id,
            vuln_id="CVE-2026-45659",
            severity="HIGH",
            score=8.0,
            component_name="kev-lib",
            component_version="1.0.0",
        )
    )
    db.commit()


def test_dashboard_endpoints_do_not_trigger_multiple_kev_writes(monkeypatch, client):
    from app.db import SessionLocal
    from app.metrics.cache import reset_cache
    from app.services.dashboard_metrics import reset_lifetime_cache

    db = SessionLocal()
    try:
        db.execute(delete(KevEntry))
        db.commit()
        _seed_dashboard_finding(db)
    finally:
        db.close()

    reset_cache()
    reset_lifetime_cache()
    monkeypatch.setattr(kev_module, "_fetch_feed", lambda: [_kev_item("CVE-2026-45659")])

    original_write_rows = kev_module._write_rows
    write_count = 0
    write_count_lock = threading.Lock()

    def counting_write_rows(db_arg, rows):
        nonlocal write_count
        with write_count_lock:
            write_count += 1
        time.sleep(0.05)
        return original_write_rows(db_arg, rows)

    monkeypatch.setattr(kev_module, "_write_rows", counting_write_rows)

    paths = (
        "/dashboard/exploitation",
        "/dashboard/posture",
        "/dashboard/summary",
        "/dashboard/risk-matrix",
    )
    with ThreadPoolExecutor(max_workers=len(paths)) as pool:
        responses = list(pool.map(client.get, paths))

    assert [response.status_code for response in responses] == [200, 200, 200, 200]
    assert write_count == 1


def test_failed_refresh_preserves_existing_cache_and_throttles_warning(monkeypatch, caplog):
    SessionFactory, _engine = _session_factory()
    db = SessionFactory()
    db.add(KevEntry(cve_id="CVE-2026-OLD", product="old-cache", refreshed_at="2000-01-01T00:00:00+00:00"))
    db.commit()

    monkeypatch.setattr(kev_module, "_fetch_feed", lambda: [_kev_item("CVE-2026-NEW")])

    def fail_upsert(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(kev_module, "_upsert_kev_rows", fail_upsert)

    caplog.set_level(logging.WARNING, logger="sbom.sources.kev")
    assert kev_module.refresh_if_stale(db) is False
    assert kev_module.refresh_if_stale(db) is False

    db.expire_all()
    assert db.get(KevEntry, "CVE-2026-OLD") is not None
    assert db.get(KevEntry, "CVE-2026-NEW") is None
    assert [record.message for record in caplog.records if record.message == "kev_cache_refresh_failed"] == [
        "kev_cache_refresh_failed"
    ]
