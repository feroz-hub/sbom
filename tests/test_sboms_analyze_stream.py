"""
Phase-3 smoke test for the SSE streaming analyze endpoint.

The streaming endpoint was rewritten in Phase 3 to consume the
``app.sources`` registry + ``run_sources_concurrently`` runner instead of
its old inline ``source_map`` of lambdas. This test exercises the new path
end-to-end against the same canned source-fetcher fakes used by the
snapshot tests, then asserts:

  * the request returns 200 and ``text/event-stream``
  * the SSE body contains the expected event sequence:
      ``progress: started`` → ``progress: parsed`` → per-source
      ``running``/``complete`` → ``complete``
  * the final ``complete`` event reports a non-zero finding count
    (proving the registry-driven runner actually fanned the sources out
    and aggregated their results)
  * no event leaks the legacy ``gh_token_override`` plumbing detail —
    credentials are bound at adapter construction now
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta

import pytest
from app.models import AnalysisRun, SBOMComponent, SBOMSource
from sqlalchemy import text


def _parse_sse_events(body: str) -> list[dict]:
    """
    Parse a text/event-stream body into a list of
    ``{"event": ..., "data": ...}`` dicts. Each SSE record is separated by
    a blank line; ``event:`` and ``data:`` lines are merged.
    """
    events: list[dict] = []
    for chunk in re.split(r"\n\n+", body.strip()):
        event_type = "message"
        data_lines: list[str] = []
        for line in chunk.splitlines():
            if line.startswith("event:"):
                event_type = line[len("event:") :].strip()
            elif line.startswith("data:"):
                data_lines.append(line[len("data:") :].strip())
        if not data_lines:
            continue
        try:
            data = json.loads("\n".join(data_lines))
        except json.JSONDecodeError:
            data = {"_raw": "\n".join(data_lines)}
        events.append({"event": event_type, "data": data})
    return events


@pytest.fixture()
def db(client):
    from app.db import SessionLocal

    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.mark.snapshot
def test_analyze_stream_uses_registry_emits_progress_and_persists_run(client, seeded_sbom, mock_external_sources, db):
    sbom_id = seeded_sbom["id"]
    before_ids = {
        row.id
        for row in db.query(AnalysisRun).filter(AnalysisRun.sbom_id == sbom_id).all()
    }

    resp = client.post(
        f"/api/sboms/{sbom_id}/analyze/stream",
        json={
            "sources": ["NVD", "OSV", "GITHUB"],
        },
    )

    assert resp.status_code == 200, resp.text
    assert "text/event-stream" in resp.headers.get("content-type", "")

    events = _parse_sse_events(resp.text)
    assert events, "stream produced zero SSE events"

    # ---- Phase order ----
    phases = [e["data"].get("phase") for e in events if e["event"] == "progress" and e["data"].get("phase")]
    assert phases[:2] == ["started", "parsed"], f"unexpected phase order: {phases}"

    # ---- Per-source running + complete events ----
    by_source: dict[str, list[str]] = {}
    for e in events:
        if e["event"] != "progress":
            continue
        src = e["data"].get("source")
        status = e["data"].get("status")
        if src and status:
            by_source.setdefault(src, []).append(status)

    assert set(by_source) == {"NVD", "OSV", "GITHUB"}, f"missing sources in stream events: {by_source}"
    for src, statuses in by_source.items():
        assert "running" in statuses, f"{src} never emitted running"
        assert "complete" in statuses, f"{src} never emitted complete"
        # No source should report error — the canned fakes always succeed.
        assert "error" not in statuses, f"{src} unexpectedly errored: {statuses}"

    # ---- Final complete event ----
    completes = [e for e in events if e["event"] == "complete"]
    assert len(completes) == 1, "expected exactly one terminal complete event"
    final = completes[0]["data"]

    # Mock fixture: log4j → NVD CRITICAL + GHSA CRITICAL (deduped) and
    # requests → OSV HIGH ⇒ at least 2 unique findings, ≥1 critical, ≥1 high.
    assert final["total"] >= 2
    assert final["critical"] >= 1
    assert final["high"] >= 1
    assert final["status"] == "FINDINGS"  # ADR-0001 (was FAIL)
    assert isinstance(final["runId"], int)
    assert final["errors"] == 0

    db.expire_all()
    persisted = db.get(AnalysisRun, final["runId"])
    assert persisted is not None
    assert persisted.id not in before_ids
    assert persisted.sbom_id == sbom_id
    assert persisted.run_status == "FINDINGS"
    assert persisted.started_on
    assert persisted.completed_on
    assert persisted.total_components and persisted.total_components > 0
    assert persisted.total_findings == final["total"]
    assert persisted.critical_count == final["critical"]
    assert persisted.high_count == final["high"]

    list_body = client.get(f"/api/sboms?user_id={seeded_sbom['created_by']}&page_size=500").json()
    row = next(item for item in list_body if item["id"] == sbom_id)
    assert row["latest_analysis"]["run_id"] == persisted.id
    assert row["latest_analysis"]["status"] == "completed"
    assert row["latest_analysis"]["result"] == "findings"
    assert row["latest_analysis"]["finding_count"] == persisted.total_findings
    assert row["latest_analysis"]["critical_count"] == persisted.critical_count
    assert row["latest_analysis"]["high_count"] == persisted.high_count

    detail = client.get(f"/api/sboms/{sbom_id}").json()
    assert detail["latest_analysis"]["run_id"] == persisted.id


def test_analyze_stream_parse_failure_persists_failed_run(client, db):
    sbom = SBOMSource(
        sbom_name="stream-parse-failure",
        sbom_data="{not valid json",
        status="validated",
        created_by="stream-failure-test",
    )
    db.add(sbom)
    db.commit()
    db.refresh(sbom)

    resp = client.post(
        f"/api/sboms/{sbom.id}/analyze/stream",
        json={"sources": ["NVD"]},
    )

    assert resp.status_code == 200, resp.text
    events = _parse_sse_events(resp.text)
    errors = [event for event in events if event["event"] == "error"]
    assert errors
    terminal = errors[-1]["data"]
    assert terminal["status"] == "ERROR"
    assert terminal["runId"]
    assert "SBOM parse failed" in terminal["message"]

    db.expire_all()
    run = db.get(AnalysisRun, terminal["runId"])
    assert run is not None
    assert run.sbom_id == sbom.id
    assert run.run_status == "ERROR"
    assert run.started_on
    assert run.completed_on
    assert "SBOM parse failed" in (run.raw_report or "")

    detail = client.get(f"/api/sboms/{sbom.id}").json()
    assert detail["latest_analysis"]["run_id"] == run.id
    assert detail["latest_analysis"]["status"] == "failed"
    assert detail["latest_analysis"]["result"] == "failed"
    assert "SBOM parse failed" in detail["latest_analysis"]["error_message"]


def test_analyze_stream_zero_persisted_components_marks_run_failed(client, seeded_sbom, db, monkeypatch):
    from app.routers import sboms_crud as crud

    sbom_id = seeded_sbom["id"]
    db.query(SBOMComponent).filter(SBOMComponent.sbom_id == sbom_id).delete()
    db.commit()

    def fake_sync_components(_db, _sbom):
        return []

    monkeypatch.setattr(crud, "sync_sbom_components", fake_sync_components)

    resp = client.post(
        f"/api/sboms/{sbom_id}/analyze/stream",
        json={"sources": ["NVD", "OSV", "GITHUB"]},
    )

    assert resp.status_code == 200, resp.text
    events = _parse_sse_events(resp.text)
    errors = [event for event in events if event["event"] == "error"]
    assert errors
    terminal = errors[-1]["data"]
    assert terminal["status"] == "ERROR"
    assert terminal["runId"]
    assert "No components were available for analysis" in terminal["message"]

    db.expire_all()
    run = db.get(AnalysisRun, terminal["runId"])
    assert run is not None
    assert run.run_status == "ERROR"
    assert run.total_components == 0
    assert "zero_components_loaded" in (run.raw_report or "")


def test_startup_reconciliation_interrupts_stale_running_run(db, seeded_sbom):
    from app.services.analysis_service import reconcile_stale_analysis_runs

    started = (datetime.now(UTC) - timedelta(minutes=10)).replace(microsecond=0).isoformat()
    active = AnalysisRun(
        sbom_id=seeded_sbom["id"],
        run_status="RUNNING",
        sbom_name=seeded_sbom["sbom_name"],
        source="NVD,OSV,GITHUB",
        trigger_source="manual",
        started_on=started,
        completed_on=started,
        duration_ms=0,
        total_components=0,
    )
    db.add(active)
    db.commit()
    db.refresh(active)

    interrupted = reconcile_stale_analysis_runs(db, stale_after_seconds=60)
    db.commit()

    assert [run.id for run in interrupted] == [active.id]
    db.expire_all()
    run = db.get(AnalysisRun, active.id)
    assert run.run_status == "INTERRUPTED"
    assert "application or worker stopped unexpectedly" in (run.raw_report or "")


def test_startup_reconciliation_preserves_recent_running_run(db, seeded_sbom):
    from app.services.analysis_service import reconcile_stale_analysis_runs

    started = datetime.now(UTC).replace(microsecond=0).isoformat()
    active = AnalysisRun(
        sbom_id=seeded_sbom["id"],
        run_status="RUNNING",
        sbom_name=seeded_sbom["sbom_name"],
        source="NVD,OSV,GITHUB",
        trigger_source="manual",
        started_on=started,
        completed_on=started,
        duration_ms=0,
        total_components=0,
    )
    db.add(active)
    db.commit()
    db.refresh(active)

    interrupted = reconcile_stale_analysis_runs(db, stale_after_seconds=60)
    db.commit()

    assert interrupted == []
    db.expire_all()
    run = db.get(AnalysisRun, active.id)
    assert run.run_status == "RUNNING"
    db.query(AnalysisRun).filter(AnalysisRun.id == active.id).delete()
    db.commit()


def test_analyze_stream_returns_existing_active_run_without_duplicate(client, seeded_sbom, db):
    active = AnalysisRun(
        sbom_id=seeded_sbom["id"],
        run_status="RUNNING",
        sbom_name=seeded_sbom["sbom_name"],
        source="NVD,OSV,GITHUB",
        trigger_source="manual",
        started_on="2026-07-01T00:00:00Z",
        completed_on="2026-07-01T00:00:00Z",
        duration_ms=0,
    )
    db.add(active)
    db.commit()
    db.refresh(active)
    before_count = db.query(AnalysisRun).filter(AnalysisRun.sbom_id == seeded_sbom["id"]).count()

    resp = client.post(
        f"/api/sboms/{seeded_sbom['id']}/analyze/stream",
        json={"sources": ["NVD", "OSV", "GITHUB"]},
    )

    assert resp.status_code == 200, resp.text
    events = _parse_sse_events(resp.text)
    completes = [event for event in events if event["event"] == "complete"]
    assert completes
    final = completes[-1]["data"]
    assert final["status"] == "already_running"
    assert final["runId"] == active.id
    assert final["already_running"] is True

    db.expire_all()
    after_count = db.query(AnalysisRun).filter(AnalysisRun.sbom_id == seeded_sbom["id"]).count()
    assert after_count == before_count
    db.query(AnalysisRun).filter(AnalysisRun.id == active.id).delete()
    db.commit()


def test_analyze_stream_data_error_rolls_back_and_marks_failed_with_clean_session(
    client, seeded_sbom, mock_external_sources, db, monkeypatch
):
    if db.bind.dialect.name != "postgresql":
        pytest.skip("forced aborted transaction regression is PostgreSQL-specific")

    from app.db import SessionLocal, get_db
    from app.routers import sboms_crud as crud

    rollback_calls: list[bool] = []

    def override_get_db():
        session = SessionLocal()
        original_rollback = session.rollback

        def rollback_spy():
            rollback_calls.append(True)
            return original_rollback()

        session.rollback = rollback_spy
        try:
            yield session
        finally:
            session.close()

    def fail_with_aborted_transaction(*, db, **kwargs):
        db.execute(text("SELECT 1 / 0"))

    client.app.dependency_overrides[get_db] = override_get_db
    monkeypatch.setattr(crud, "persist_analysis_run", fail_with_aborted_transaction)
    try:
        resp = client.post(
            f"/api/sboms/{seeded_sbom['id']}/analyze/stream",
            json={"sources": ["NVD", "OSV", "GITHUB"]},
            headers={"X-Correlation-ID": "forced-data-error"},
        )
    finally:
        client.app.dependency_overrides.pop(get_db, None)

    assert resp.status_code == 200, resp.text
    events = _parse_sse_events(resp.text)
    errors = [event for event in events if event["event"] == "error"]
    assert len(errors) == 1
    assert events[-1]["event"] == "error"
    assert "PendingRollbackError" not in resp.text
    assert rollback_calls

    terminal = errors[0]["data"]
    assert terminal["status"] == "ERROR"
    assert terminal["code"] == 500
    assert terminal["correlation_id"] == "forced-data-error"
    assert "database rejected" in terminal["message"]
    assert "SELECT 1 / 0" not in terminal["message"]

    db.expire_all()
    run = db.get(AnalysisRun, terminal["runId"])
    assert run is not None
    assert run.run_status == "ERROR"
    assert "database rejected" in (run.raw_report or "")
    assert "SELECT 1 / 0" not in (run.raw_report or "")


def test_analyze_stream_still_ends_cleanly_when_failed_status_cannot_be_persisted(
    client, seeded_sbom, mock_external_sources, db, monkeypatch, caplog
):
    if db.bind.dialect.name != "postgresql":
        pytest.skip("forced aborted transaction regression is PostgreSQL-specific")

    from app.routers import sboms_crud as crud

    real_session_factory = crud.SessionLocal

    class FailingCommitSession:
        def __init__(self):
            self._session = real_session_factory()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            self._session.close()

        def __getattr__(self, name):
            return getattr(self._session, name)

        def commit(self):
            raise RuntimeError("forced failed-status commit failure")

    def fail_with_aborted_transaction(*, db, **kwargs):
        db.execute(text("SELECT 1 / 0"))

    caplog.set_level("ERROR", logger="app.routers.sboms_crud")
    monkeypatch.setattr(crud, "persist_analysis_run", fail_with_aborted_transaction)
    monkeypatch.setattr(crud, "SessionLocal", FailingCommitSession)

    resp = client.post(
        f"/api/sboms/{seeded_sbom['id']}/analyze/stream",
        json={"sources": ["NVD", "OSV", "GITHUB"]},
        headers={"X-Correlation-ID": "failed-mark-fails"},
    )

    assert resp.status_code == 200, resp.text
    events = _parse_sse_events(resp.text)
    errors = [event for event in events if event["event"] == "error"]
    assert len(errors) == 1
    assert events[-1]["event"] == "error"
    assert errors[0]["data"]["status"] == "ERROR"
    assert any(record.getMessage() == "SSE analysis persistence failed" for record in caplog.records)
    assert any(record.getMessage() == "analysis.run_mark_failed.failed" for record in caplog.records)
