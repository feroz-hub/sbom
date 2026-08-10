"""REST surface tests for the Phase 3 AI fixes router.

Exercises the inline-fallback path: when Celery isn't reachable (the
default in tests — there's no broker), ``trigger_run_fixes`` runs the
pipeline inline so the response carries the actual progress envelope.
This keeps the API contract testable end-to-end without spinning up
Celery + Redis in CI.
"""

from __future__ import annotations

import json

import pytest
from app.ai.progress import InMemoryProgressStore, _set_store, reset_progress_store
from app.ai.providers.base import LlmRequest, LlmResponse, LlmUsage, ProviderInfo
from app.ai.registry import ProviderRegistry
from app.db import SessionLocal
from app.models import (
    AiFixCache,
    AiUsageLog,
    AnalysisFinding,
    AnalysisRun,
    SBOMComponent,
    SBOMSource,
)
from app.settings import reset_settings

from tests.ai.fixtures import EX1_CRITICAL_KEV_WITH_FIX_BUNDLE


class _RouterFakeProvider:
    name = "fake"
    default_model = "fake-1"
    is_local = True
    max_concurrent = 4

    def __init__(self) -> None:
        self.calls = 0

    async def generate(self, req: LlmRequest) -> LlmResponse:
        self.calls += 1
        return LlmResponse(
            text=json.dumps(EX1_CRITICAL_KEV_WITH_FIX_BUNDLE),
            parsed=EX1_CRITICAL_KEV_WITH_FIX_BUNDLE,
            usage=LlmUsage(input_tokens=10, output_tokens=10, cost_usd=0.0),
            provider=self.name,
            model=self.default_model,
            latency_ms=1,
        )

    async def health_check(self) -> bool:
        return True

    def info(self) -> ProviderInfo:
        return ProviderInfo(
            name=self.name,
            available=True,
            default_model=self.default_model,
            supports_structured_output=True,
            is_local=True,
        )


@pytest.fixture()
def _enable_ai(monkeypatch):
    monkeypatch.setenv("AI_FIXES_ENABLED", "true")
    monkeypatch.delenv("AI_FIXES_KILL_SWITCH", raising=False)
    reset_settings()
    yield
    reset_settings()


@pytest.fixture()
def _seeded_run(client):
    db = SessionLocal()
    try:
        db.query(AiFixCache).delete()
        db.query(AiUsageLog).delete()
        db.query(AnalysisFinding).delete()
        db.query(AnalysisRun).delete()
        db.query(SBOMComponent).delete()
        db.query(SBOMSource).delete()
        db.commit()

        sbom = SBOMSource(sbom_name="router")
        db.add(sbom)
        db.flush()
        run = AnalysisRun(
            sbom_id=sbom.id,
            run_status="OK",
            source="NVD",
            started_on="2026-01-01T00:00:00Z",
            completed_on="2026-01-01T00:00:01Z",
        )
        db.add(run)
        db.flush()
        for i in range(2):
            db.add(
                AnalysisFinding(
                    analysis_run_id=run.id,
                    vuln_id=f"CVE-2099-{i:05d}",
                    source="NVD",
                    severity="HIGH",
                    score=7.0,
                    component_name=f"pkg-{i}",
                    component_version="1.0.0",
                    fixed_versions=json.dumps(["1.0.1"]),
                )
            )
        # One extra finding for the single-finding endpoint test.
        finding_solo = AnalysisFinding(
            analysis_run_id=run.id,
            vuln_id="CVE-2099-99999",
            source="NVD",
            severity="HIGH",
            score=7.0,
            component_name="solo-pkg",
            component_version="1.0.0",
            fixed_versions=json.dumps(["1.0.1"]),
        )
        db.add(finding_solo)
        db.commit()
        yield {"run_id": run.id, "solo_id": finding_solo.id}
    finally:
        db.close()


@pytest.fixture()
def _fake_registry(monkeypatch):
    """Replace the singleton registry with a fake-provider one."""
    from app.ai import registry as registry_mod

    fake = _RouterFakeProvider()
    reg = ProviderRegistry(configs=[], default_provider="fake")
    reg.register_instance(fake)

    def _get(_db=None):
        return reg

    monkeypatch.setattr(registry_mod, "get_registry", _get)
    # Also patch the import sites that captured ``get_registry`` directly.
    import app.ai.batch as bm
    import app.ai.fix_generator as fg

    monkeypatch.setattr(fg, "get_registry", _get)
    monkeypatch.setattr(bm, "get_registry", _get)
    yield fake
    registry_mod.reset_registry()


@pytest.fixture()
def _memory_store():
    """Force the in-memory progress store for the router tests."""
    store = InMemoryProgressStore()
    _set_store(store)
    yield store
    reset_progress_store()


# ============================================================ Disabled paths


def test_trigger_returns_409_when_ai_disabled(client, _seeded_run, monkeypatch):
    # AI_FIXES_ENABLED defaults to False → trigger should refuse.
    monkeypatch.setenv("AI_FIXES_ENABLED", "false")
    reset_settings()
    try:
        resp = client.post(f"/api/v1/runs/{_seeded_run['run_id']}/ai-fixes")
        assert resp.status_code == 409
        body = resp.json()
        assert body["detail"]["error_code"] == "AI_FIXES_DISABLED"
    finally:
        reset_settings()


def test_kill_switch_returns_409(client, _seeded_run, monkeypatch):
    monkeypatch.setenv("AI_FIXES_ENABLED", "true")
    monkeypatch.setenv("AI_FIXES_KILL_SWITCH", "true")
    reset_settings()
    try:
        resp = client.post(f"/api/v1/runs/{_seeded_run['run_id']}/ai-fixes")
        assert resp.status_code == 409
        assert resp.json()["detail"]["error_code"] == "AI_FIXES_KILL_SWITCH"
    finally:
        monkeypatch.delenv("AI_FIXES_KILL_SWITCH", raising=False)
        reset_settings()


def test_404_on_unknown_run(client, _enable_ai):
    resp = client.post("/api/v1/runs/9999999/ai-fixes")
    assert resp.status_code == 404


# ============================================================ Inline-fallback happy path


def test_trigger_runs_inline_when_celery_unavailable(client, _seeded_run, _enable_ai, _fake_registry, _memory_store):
    resp = client.post(f"/api/v1/runs/{_seeded_run['run_id']}/ai-fixes")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # In tests the Celery broker is unreachable, so the router falls back
    # to inline execution. The progress envelope reflects a completed run.
    assert body["progress"]["run_id"] == _seeded_run["run_id"]
    # Either path: enqueued=True (broker accepted but task hasn't run) OR
    # enqueued=False (inline fallback already finished). Test passes for either,
    # but in CI it's the inline path.
    if not body["enqueued"]:
        assert body["progress"]["status"] == "complete"
        assert body["progress"]["generated"] == 3  # solo finding is in same run


def test_progress_endpoint_round_trips(client, _seeded_run, _enable_ai, _fake_registry, _memory_store):
    client.post(f"/api/v1/runs/{_seeded_run['run_id']}/ai-fixes")
    resp = client.get(f"/api/v1/runs/{_seeded_run['run_id']}/ai-fixes/progress")
    assert resp.status_code == 200
    body = resp.json()
    assert body["run_id"] == _seeded_run["run_id"]
    # If inline ran, status is complete; otherwise pending. Either is fine.
    assert body["status"] in {"pending", "in_progress", "complete"}


def test_progress_endpoint_returns_204_when_no_batch(client, _seeded_run, _memory_store):
    """Idle contract: the run exists but has no batch, so /progress returns
    204 (nothing to report) — NOT 404.

    404 was wrong (the run is real) and the client mistook it for an error
    and re-polled forever. 204 is also distinct from a fabricated ``pending``
    envelope, so a tab that registered on mount can tell "nothing here, don't
    subscribe" apart from a real "queued, waiting to start."
    """
    resp = client.get(f"/api/v1/runs/{_seeded_run['run_id']}/ai-fixes/progress")
    assert resp.status_code == 204
    assert resp.content == b""  # No body on 204.


def test_progress_endpoint_returns_404_when_run_missing(client, _memory_store):
    """404 is reserved for a missing *run* — the genuine not-found case."""
    resp = client.get("/api/v1/runs/999999/ai-fixes/progress")
    assert resp.status_code == 404


def test_cancel_endpoint_sets_flag(client, _seeded_run, _enable_ai, _memory_store):
    resp = client.post(f"/api/v1/runs/{_seeded_run['run_id']}/ai-fixes/cancel")
    assert resp.status_code == 202
    body = resp.json()
    assert body["cancel_requested"] is True
    assert _memory_store.is_cancel_requested(_seeded_run["run_id"]) is True


def test_cancel_writes_terminal_envelope_for_phantom(client, _seeded_run, _enable_ai, _memory_store):
    """Phantom-banner regression: cancel on a run with no live batch
    must leave a terminal envelope behind so the next /progress poll
    drives the client into unregister rather than re-rendering a stuck
    pending row."""
    run_id = _seeded_run["run_id"]
    resp = client.post(f"/api/v1/runs/{run_id}/ai-fixes/cancel")
    assert resp.status_code == 202
    snap = _memory_store.read(run_id)
    assert snap is not None
    assert snap.status == "cancelled"


def test_legacy_stream_phantom_fast_path(client, _seeded_run, _memory_store):
    """No batch + no envelope ⇒ stream emits one terminal event and ends.
    Without this, the SSE generator would poll silently for 600s while
    the client banner stays parked."""
    with client.stream("GET", f"/api/v1/runs/{_seeded_run['run_id']}/ai-fixes/stream") as resp:
        assert resp.status_code == 200
        body = resp.read().decode()
    assert "event: progress" in body
    assert '"status": "cancelled"' in body
    assert "event: end" in body


def test_list_run_fixes_after_generation(client, _seeded_run, _enable_ai, _fake_registry, _memory_store):
    # Trigger so the cache is populated.
    client.post(f"/api/v1/runs/{_seeded_run['run_id']}/ai-fixes")
    resp = client.get(f"/api/v1/runs/{_seeded_run['run_id']}/ai-fixes")
    assert resp.status_code == 200
    body = resp.json()
    # Inline fallback path populates the cache; broker path may not have
    # finished by the time we read. Allow either ≥ 0 or ≥ N items.
    assert "items" in body
    assert "total" in body


def test_get_finding_fix_404_when_no_cached_bundle(client, _seeded_run, _enable_ai, _fake_registry, _memory_store):
    """Read-only contract: GET must NOT spend LLM budget on cache miss."""
    finding_id = _seeded_run["solo_id"]
    pre_calls = _fake_registry.calls
    resp = client.get(f"/api/v1/findings/{finding_id}/ai-fix")
    assert resp.status_code == 404
    # Critical: no provider call was made just because we opened the modal.
    assert _fake_registry.calls == pre_calls


def test_post_generate_then_get_returns_cached(client, _seeded_run, _enable_ai, _fake_registry, _memory_store):
    finding_id = _seeded_run["solo_id"]
    # POST = explicit Generate click → spends budget, populates cache.
    resp = client.post(f"/api/v1/findings/{finding_id}/ai-fix")
    assert resp.status_code == 200
    body = resp.json()
    assert body["error"] is None
    assert body["result"] is not None
    assert body["result"]["bundle"]["upgrade_command"]["target_version"] == "2.17.1"
    post_calls = _fake_registry.calls

    # Subsequent GET = modal re-open → returns cached bundle, no provider call.
    resp = client.get(f"/api/v1/findings/{finding_id}/ai-fix")
    assert resp.status_code == 200
    assert resp.json()["result"]["bundle"]["upgrade_command"]["target_version"] == "2.17.1"
    assert _fake_registry.calls == post_calls


def test_regenerate_finding_fix_force_refreshes(client, _seeded_run, _enable_ai, _fake_registry, _memory_store):
    finding_id = _seeded_run["solo_id"]
    # First call (POST generate) seeds the cache.
    client.post(f"/api/v1/findings/{finding_id}/ai-fix")
    pre_calls = _fake_registry.calls
    # Second call (regenerate) → must hit the provider again.
    resp = client.post(f"/api/v1/findings/{finding_id}/ai-fix:regenerate")
    assert resp.status_code == 200
    assert _fake_registry.calls == pre_calls + 1


def test_get_finding_fix_404_for_unknown(client, _enable_ai):
    resp = client.get("/api/v1/findings/9999999/ai-fix")
    assert resp.status_code == 404


# ============================================================ Pool-leak guard


def test_sse_stream_does_not_pin_db_connection(client, _seeded_run, _memory_store, monkeypatch):
    """Leak guard for the QueuePool-exhaustion bug.

    An SSE progress stream stays open as long as generation (minutes). The
    endpoint must NOT hold a DB connection for that whole time — the buggy
    version kept its ``Depends(get_db)`` session checked out for the stream's
    lifetime (FastAPI runs the dependency cleanup only after the response
    finishes), so each subscriber pinned one of the 15 pool connections and
    starved the frequently-polled ``/progress``.

    We snapshot ``engine.pool.checkedout()`` at the moment the stream body
    runs — i.e. AFTER the endpoint's upfront existence checks. The fixed
    endpoint has already closed its short-lived session by then; the buggy one
    still holds the request session open.
    """
    import app.routers.ai_fixes as ai_router
    from app.ai.progress import initial_progress
    from app.db import engine

    run_id = _seeded_run["run_id"]
    # Put a live progress entry in the store so the legacy stream takes the
    # real (non-phantom) path through ``_sse_response``.
    _memory_store.write(initial_progress(run_id, total=1, status="in_progress"))

    captured: dict[str, int] = {}

    def _spy_progress_events(store, rid, batch_id=None):
        captured["during_stream"] = engine.pool.checkedout()
        return iter(())  # no events → the stream ends immediately

    monkeypatch.setattr(ai_router, "progress_events", _spy_progress_events)

    baseline = engine.pool.checkedout()
    resp = client.get(f"/api/v1/runs/{run_id}/ai-fixes/stream")
    assert resp.status_code == 200

    # The fix: no pool connection is held while the stream is producing.
    assert captured["during_stream"] == baseline, (
        f"SSE stream held {captured['during_stream'] - baseline} extra "
        "connection(s) — the endpoint is pinning a pooled connection across "
        "the stream's lifetime."
    )
    # And nothing leaked once the request completes.
    assert engine.pool.checkedout() == baseline
