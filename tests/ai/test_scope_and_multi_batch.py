"""Phase 4 multi-batch + scope-aware tests.

Covers the scope resolver (filters + finding_ids + run_id security
intersection), the multi-batch concurrency cap, cancel isolation
across concurrent batches, and the cache lock (no duplicate LLM
calls when two batches scope-overlap on the same finding).

The ``client`` fixture and the seeded run are reused from
``test_ai_fixes_router.py``; for clarity we re-seed here so each test
gets a deterministic finding set.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from app.ai.batches import (
    MAX_ACTIVE_BATCHES_PER_RUN,
    count_active_batches,
    create_batch,
    list_batches_for_run,
)
from app.ai.cache_lock import InMemoryCacheLock
from app.ai.fix_generator import AiFixGenerator
from app.ai.progress import (
    BatchProgress,
    InMemoryProgressStore,
    _set_store,
    initial_progress,
    reset_progress_store,
)
from app.ai.providers.base import LlmRequest, LlmResponse, LlmUsage, ProviderInfo
from app.ai.registry import ProviderRegistry
from app.ai.scope import (
    AiFixGenerationScope,
    count_cached_for_finding_ids,
    resolve_scope_findings,
)
from app.db import SessionLocal
from app.models import (
    AiFixBatch,
    AiFixCache,
    AiUsageLog,
    AnalysisFinding,
    AnalysisRun,
    KevEntry,
    SBOMComponent,
    SBOMSource,
)
from app.settings import reset_settings

from tests.ai.fixtures import EX1_CRITICAL_KEV_WITH_FIX_BUNDLE


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def _enable_ai(monkeypatch):
    monkeypatch.setenv("AI_FIXES_ENABLED", "true")
    monkeypatch.delenv("AI_FIXES_KILL_SWITCH", raising=False)
    reset_settings()
    yield
    reset_settings()


@pytest.fixture()
def _seeded_two_runs(client):
    """Seed two distinct runs with overlapping finding shapes.

    Layout:
      * Run A — 4 findings: CRITICAL/KEV, HIGH/no-fix, MEDIUM/with-fix, LOW/with-fix.
      * Run B — 1 finding: CRITICAL (different from any run-A row).
    The KEV table seeds CVE-2099-A001 so kev_only filters can match.
    """
    db = SessionLocal()
    try:
        for table in (
            AiFixBatch,
            AiFixCache,
            AiUsageLog,
            AnalysisFinding,
            AnalysisRun,
            SBOMComponent,
            SBOMSource,
            KevEntry,
        ):
            db.query(table).delete()
        db.commit()

        sbom = SBOMSource(sbom_name="multi-batch")
        db.add(sbom)
        db.flush()

        run_a = AnalysisRun(
            sbom_id=sbom.id,
            run_status="OK",
            source="NVD",
            started_on="2026-01-01T00:00:00Z",
            completed_on="2026-01-01T00:00:01Z",
        )
        run_b = AnalysisRun(
            sbom_id=sbom.id,
            run_status="OK",
            source="NVD",
            started_on="2026-01-01T00:00:00Z",
            completed_on="2026-01-01T00:00:01Z",
        )
        db.add_all([run_a, run_b])
        db.flush()

        a1 = AnalysisFinding(
            analysis_run_id=run_a.id,
            vuln_id="CVE-2099-A001",
            severity="CRITICAL",
            score=9.8,
            title="kev critical with fix",
            component_name="critical-kev-pkg",
            component_version="1.0.0",
            fixed_versions=json.dumps(["1.0.1"]),
        )
        a2 = AnalysisFinding(
            analysis_run_id=run_a.id,
            vuln_id="CVE-2099-A002",
            severity="HIGH",
            score=8.0,
            title="high no fix",
            component_name="high-pkg",
            component_version="2.0.0",
            fixed_versions=None,
        )
        a3 = AnalysisFinding(
            analysis_run_id=run_a.id,
            vuln_id="CVE-2099-A003",
            severity="MEDIUM",
            score=5.5,
            title="medium with fix",
            component_name="medium-pkg",
            component_version="3.0.0",
            fixed_versions=json.dumps(["3.0.1", "3.1.0"]),
        )
        a4 = AnalysisFinding(
            analysis_run_id=run_a.id,
            vuln_id="CVE-2099-A004",
            severity="LOW",
            score=2.0,
            title="low empty fix list",
            component_name="low-pkg",
            component_version="4.0.0",
            fixed_versions="[]",
        )
        b1 = AnalysisFinding(
            analysis_run_id=run_b.id,
            vuln_id="CVE-2099-B001",
            severity="CRITICAL",
            score=9.5,
            title="run-b critical",
            component_name="run-b-pkg",
            component_version="1.0.0",
            fixed_versions=json.dumps(["1.0.1"]),
        )
        db.add_all([a1, a2, a3, a4, b1])

        # Mark the run-A CRITICAL as KEV-listed so kev_only filters
        # something deterministic.
        db.add(
            KevEntry(
                cve_id="CVE-2099-A001",
                refreshed_at="2026-01-01T00:00:00Z",
            )
        )

        db.commit()
        yield {
            "run_a": run_a.id,
            "run_b": run_b.id,
            "a1": a1.id,
            "a2": a2.id,
            "a3": a3.id,
            "a4": a4.id,
            "b1": b1.id,
        }
    finally:
        db.close()


@pytest.fixture()
def _memory_store():
    store = InMemoryProgressStore()
    _set_store(store)
    yield store
    reset_progress_store()


# ============================================================================
# Scope resolution
# ============================================================================


def test_resolve_scope_none_returns_all(client, _seeded_two_runs):
    db = SessionLocal()
    try:
        rows = resolve_scope_findings(db, run_id=_seeded_two_runs["run_a"], scope=None)
        assert len(rows) == 4
    finally:
        db.close()


def test_resolve_scope_severity_filter(client, _seeded_two_runs):
    db = SessionLocal()
    try:
        scope = AiFixGenerationScope(severities=["CRITICAL", "HIGH"])
        rows = resolve_scope_findings(db, run_id=_seeded_two_runs["run_a"], scope=scope)
        ids = {r.id for r in rows}
        assert ids == {_seeded_two_runs["a1"], _seeded_two_runs["a2"]}
    finally:
        db.close()


def test_resolve_scope_kev_only_uses_kev_table_join(client, _seeded_two_runs):
    db = SessionLocal()
    try:
        scope = AiFixGenerationScope(kev_only=True)
        rows = resolve_scope_findings(db, run_id=_seeded_two_runs["run_a"], scope=scope)
        assert {r.id for r in rows} == {_seeded_two_runs["a1"]}
    finally:
        db.close()


def test_resolve_scope_fix_available_only(client, _seeded_two_runs):
    db = SessionLocal()
    try:
        scope = AiFixGenerationScope(fix_available_only=True)
        rows = resolve_scope_findings(db, run_id=_seeded_two_runs["run_a"], scope=scope)
        # a1 (with fix) + a3 (with fix). a2 has NULL, a4 has "[]" (empty).
        assert {r.id for r in rows} == {_seeded_two_runs["a1"], _seeded_two_runs["a3"]}
    finally:
        db.close()


def test_resolve_scope_search_query_substring(client, _seeded_two_runs):
    db = SessionLocal()
    try:
        # Match titles + component_name + vuln_id.
        scope = AiFixGenerationScope(search_query="medium")
        rows = resolve_scope_findings(db, run_id=_seeded_two_runs["run_a"], scope=scope)
        assert {r.id for r in rows} == {_seeded_two_runs["a3"]}
    finally:
        db.close()


def test_resolve_scope_finding_ids_overrides_filters(client, _seeded_two_runs):
    """Explicit selection wins; severity filter ignored when finding_ids set."""
    db = SessionLocal()
    try:
        scope = AiFixGenerationScope(
            severities=["CRITICAL"],
            finding_ids=[_seeded_two_runs["a3"], _seeded_two_runs["a4"]],
        )
        rows = resolve_scope_findings(db, run_id=_seeded_two_runs["run_a"], scope=scope)
        assert {r.id for r in rows} == {_seeded_two_runs["a3"], _seeded_two_runs["a4"]}
    finally:
        db.close()


def test_resolve_scope_finding_ids_intersected_with_run_id_for_security(
    client, _seeded_two_runs
):
    """A caller passing finding_ids from a different run gets the intersection.

    This is the hard security invariant: even with explicit IDs, we
    never leak findings across run boundaries.
    """
    db = SessionLocal()
    try:
        # Caller forges run_a but slips in run_b's finding id.
        scope = AiFixGenerationScope(
            finding_ids=[
                _seeded_two_runs["a1"],     # legit (run_a)
                _seeded_two_runs["b1"],     # forged (run_b — must be filtered)
            ]
        )
        rows = resolve_scope_findings(db, run_id=_seeded_two_runs["run_a"], scope=scope)
        assert {r.id for r in rows} == {_seeded_two_runs["a1"]}
    finally:
        db.close()


def test_resolve_scope_combines_multiple_filters_conjunctively(
    client, _seeded_two_runs
):
    db = SessionLocal()
    try:
        # Critical AND fix-available — should hit a1 only (a2 is HIGH).
        scope = AiFixGenerationScope(
            severities=["CRITICAL"],
            fix_available_only=True,
        )
        rows = resolve_scope_findings(db, run_id=_seeded_two_runs["run_a"], scope=scope)
        assert {r.id for r in rows} == {_seeded_two_runs["a1"]}
    finally:
        db.close()


# ============================================================================
# Cache hit counting (for the estimate endpoint)
# ============================================================================


def test_count_cached_for_finding_ids_empty_returns_zero(client, _seeded_two_runs):
    db = SessionLocal()
    try:
        assert count_cached_for_finding_ids(db, finding_ids=[]) == 0
    finally:
        db.close()


def test_count_cached_for_finding_ids_joins_against_cache_table(
    client, _seeded_two_runs
):
    db = SessionLocal()
    try:
        # Seed a cache row matching finding a1's natural key.
        db.add(
            AiFixCache(
                cache_key="aaa",
                vuln_id="CVE-2099-A001",
                component_name="critical-kev-pkg",
                component_version="1.0.0",
                prompt_version="v1",
                schema_version=1,
                remediation_prose={"a": 1},
                upgrade_command={"a": 1},
                decision_recommendation={"a": 1},
                provider_used="fake",
                model_used="fake-1",
                total_cost_usd=0.0,
                generated_at="2026-01-01T00:00:00Z",
                expires_at="2027-01-01T00:00:00Z",
                last_accessed_at="2026-01-01T00:00:00Z",
            )
        )
        db.commit()

        # All four run_a finding ids; only a1 has a cache row.
        ids = [
            _seeded_two_runs["a1"],
            _seeded_two_runs["a2"],
            _seeded_two_runs["a3"],
            _seeded_two_runs["a4"],
        ]
        assert count_cached_for_finding_ids(db, finding_ids=ids) == 1
    finally:
        db.close()


# ============================================================================
# Multi-batch concurrency cap (4th batch returns 409)
# ============================================================================


class _RouterFakeProvider:
    name = "fake"
    default_model = "fake-1"
    is_local = True
    max_concurrent = 4
    tier = "paid"

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
def _fake_registry(monkeypatch):
    from app.ai import registry as registry_mod

    fake = _RouterFakeProvider()
    reg = ProviderRegistry(configs=[], default_provider="fake")
    reg.register_instance(fake)

    def _get(_db=None):
        return reg

    monkeypatch.setattr(registry_mod, "get_registry", _get)
    import app.ai.batch as bm
    import app.ai.fix_generator as fg
    import app.routers.ai_fixes as rt

    monkeypatch.setattr(fg, "get_registry", _get)
    monkeypatch.setattr(bm, "get_registry", _get)
    monkeypatch.setattr(rt, "get_registry", _get)
    yield fake
    registry_mod.reset_registry()


def test_count_active_batches_excludes_terminal_states(
    client, _seeded_two_runs, _enable_ai, _fake_registry
):
    db = SessionLocal()
    try:
        run_id = _seeded_two_runs["run_a"]
        # Seed three rows in non-terminal states + one completed.
        for status in ("queued", "in_progress", "pending"):
            create_batch(
                db,
                run_id=run_id,
                finding_ids=[_seeded_two_runs["a1"]],
                provider_name="fake",
                scope=None,
            )
            # Set status post-create.
            row = list_batches_for_run(db, run_id=run_id)[0]
            row.status = status
            db.commit()

        # Add a completed row — should NOT count.
        completed = create_batch(
            db,
            run_id=run_id,
            finding_ids=[_seeded_two_runs["a2"]],
            provider_name="fake",
            scope=None,
        )
        completed.status = "complete"
        db.commit()

        assert count_active_batches(db, run_id=run_id) == 3
    finally:
        db.close()


def test_fourth_batch_on_run_returns_409(
    client, _seeded_two_runs, _enable_ai, _fake_registry, _memory_store
):
    """The router enforces ``MAX_ACTIVE_BATCHES_PER_RUN`` and returns
    a typed 409 with retryable=True so the frontend can prompt the user
    to wait or cancel an active batch."""
    run_id = _seeded_two_runs["run_a"]

    # Pre-seed 3 active batches directly (avoid the inline-fallback that
    # would terminate them on completion). We lock them in 'in_progress'
    # so the cap is hit deterministically.
    db = SessionLocal()
    try:
        for _ in range(MAX_ACTIVE_BATCHES_PER_RUN):
            row = create_batch(
                db,
                run_id=run_id,
                finding_ids=[_seeded_two_runs["a1"]],
                provider_name="fake",
                scope=None,
            )
            row.status = "in_progress"
            db.commit()
    finally:
        db.close()

    resp = client.post(f"/api/v1/runs/{run_id}/ai-fixes")
    assert resp.status_code == 409, resp.text
    detail = resp.json()["detail"]
    assert detail["error_code"] == "TOO_MANY_ACTIVE_BATCHES"
    assert detail["max_concurrent"] == MAX_ACTIVE_BATCHES_PER_RUN
    assert detail["retryable"] is True


# ============================================================================
# Empty-scope rejection
# ============================================================================


def test_empty_scope_returns_400(
    client, _seeded_two_runs, _enable_ai, _fake_registry, _memory_store
):
    """A scope that resolves to zero findings should refuse with a
    typed error so the frontend can surface 'No findings match' copy
    instead of starting an empty batch."""
    run_id = _seeded_two_runs["run_a"]
    body = {
        "scope": {
            "search_query": "definitely-no-match-string",
        }
    }
    resp = client.post(f"/api/v1/runs/{run_id}/ai-fixes", json=body)
    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"]["error_code"] == "EMPTY_SCOPE"


# ============================================================================
# Cancel isolation across concurrent batches
# ============================================================================


def test_per_batch_cancel_does_not_affect_other_batches(
    client, _seeded_two_runs, _enable_ai, _fake_registry, _memory_store
):
    """Cancelling batch A must NOT propagate to batch B on the same run."""
    run_id = _seeded_two_runs["run_a"]
    store = _memory_store

    # Two batches with distinct ids.
    p_a = initial_progress(run_id, total=10, batch_id="batch-a", scope_label="A")
    p_a.status = "in_progress"
    store.write(p_a)
    p_b = initial_progress(run_id, total=10, batch_id="batch-b", scope_label="B")
    p_b.status = "in_progress"
    store.write(p_b)

    store.request_cancel(run_id, "batch-a")
    assert store.is_cancel_requested(run_id, "batch-a") is True
    assert store.is_cancel_requested(run_id, "batch-b") is False


def test_legacy_cancel_propagates_to_all_batches(
    client, _seeded_two_runs, _enable_ai, _memory_store
):
    """Legacy run-level cancel halts every batch on the run.

    Documented behaviour for the deprecated POST /cancel endpoint —
    operators using the old surface can still nuke everything.
    """
    run_id = _seeded_two_runs["run_a"]
    store = _memory_store

    p_a = initial_progress(run_id, total=10, batch_id="batch-a", scope_label="A")
    p_a.status = "in_progress"
    store.write(p_a)
    p_b = initial_progress(run_id, total=10, batch_id="batch-b", scope_label="B")
    p_b.status = "in_progress"
    store.write(p_b)

    store.request_cancel(run_id)  # legacy, no batch_id
    assert store.is_cancel_requested(run_id, "batch-a") is True
    assert store.is_cancel_requested(run_id, "batch-b") is True


# ============================================================================
# Cache lock: parallel batches with overlapping scope make exactly one LLM call
# ============================================================================


class _CountingProvider:
    """Provider that counts LLM calls and adds a small delay so two
    coroutines can plausibly race on the same cache key.

    The lock should serialise them so the call counter increments by
    exactly one per unique key, regardless of concurrency.
    """

    name = "fake"
    default_model = "fake-1"
    is_local = True
    max_concurrent = 4
    tier = "paid"

    def __init__(self) -> None:
        self.calls = 0
        self._call_lock = asyncio.Lock()

    async def generate(self, req: LlmRequest) -> LlmResponse:
        async with self._call_lock:
            self.calls += 1
        # Small yield so the second coroutine has time to enter the lock.
        await asyncio.sleep(0.01)
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


def test_cache_lock_dedupes_concurrent_generations_for_same_key(
    client, _seeded_two_runs, _enable_ai
):
    """Two parallel generators racing on the same cache key must
    produce exactly ONE provider call, with the second coroutine
    receiving the cached result the first wrote.

    This is the most important multi-batch correctness invariant —
    without the lock, two scope-overlapping batches would each pay
    the LLM cost for the same finding.
    """
    counting = _CountingProvider()
    reg = ProviderRegistry(configs=[], default_provider="fake")
    reg.register_instance(counting)

    db = SessionLocal()
    try:
        finding = (
            db.query(AnalysisFinding)
            .filter(AnalysisFinding.id == _seeded_two_runs["a1"])
            .one()
        )
    finally:
        db.close()

    async def _race() -> None:
        # Two independent DB sessions + generators sharing one
        # process-local cache lock — same as two concurrent batch
        # workers in the same process. The Redis-backed lock is
        # exercised via the `RedisCacheLock` integration test (gated
        # behind AI_TEST_REDIS_URL).
        shared_lock = InMemoryCacheLock()
        db_a = SessionLocal()
        db_b = SessionLocal()
        try:
            # Re-fetch the finding into each session so SA doesn't
            # complain about cross-session attribute access.
            f_a = db_a.query(AnalysisFinding).filter(AnalysisFinding.id == finding.id).one()
            f_b = db_b.query(AnalysisFinding).filter(AnalysisFinding.id == finding.id).one()

            gen_a = AiFixGenerator(db_a, registry=reg, cache_lock=shared_lock)
            gen_b = AiFixGenerator(db_b, registry=reg, cache_lock=shared_lock)
            await asyncio.gather(
                gen_a.generate_for_finding(f_a, provider_name="fake"),
                gen_b.generate_for_finding(f_b, provider_name="fake"),
            )
        finally:
            db_a.close()
            db_b.close()

    asyncio.run(_race())
    # Hard invariant: the provider was called at most once for this key.
    assert counting.calls == 1, (
        f"expected exactly 1 LLM call under cache-lock dedup, got {counting.calls}"
    )


# ============================================================================
# Full happy path: trigger creates batch row + progress + completes inline
# ============================================================================


def test_trigger_with_scope_creates_batch_row_and_runs_inline(
    client, _seeded_two_runs, _enable_ai, _fake_registry, _memory_store
):
    """End-to-end: POST with a severity scope triggers the inline
    fallback (no Celery in tests), persists an AiFixBatch row, and
    completes with the right counts."""
    run_id = _seeded_two_runs["run_a"]
    body = {
        "scope": {
            "severities": ["CRITICAL"],
            "label": "Critical findings",
        }
    }
    resp = client.post(f"/api/v1/runs/{run_id}/ai-fixes", json=body)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["batch_id"]
    assert body["total"] == 1   # only a1 is CRITICAL
    assert body["scope_label"] == "Critical findings"

    # The durable row exists. Status depends on whether Celery
    # accepted the task (queued — no worker in tests so it never
    # runs) or fell back to inline (complete). Both are valid.
    db = SessionLocal()
    try:
        rows = list_batches_for_run(db, run_id=run_id)
        assert len(rows) == 1
        row = rows[0]
        assert row.id == body["batch_id"]
        assert row.scope_label == "Critical findings"
        assert row.total == 1
        if body["enqueued"]:
            assert row.status in {"queued", "pending", "in_progress"}
        else:
            assert row.status == "complete"
    finally:
        db.close()


def test_estimate_post_with_severity_scope_returns_scoped_count(
    client, _seeded_two_runs, _fake_registry
):
    """POST /estimate with a severity scope reports the resolved count."""
    run_id = _seeded_two_runs["run_a"]
    body = {"scope": {"severities": ["HIGH", "MEDIUM"]}}
    resp = client.post(f"/api/v1/runs/{run_id}/ai-fixes/estimate", json=body)
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload["total_findings_in_scope"] == 2  # a2 + a3
    assert payload["llm_call_count"] == payload["total_findings_in_scope"] - payload["cached_count"]
    assert payload["blocked"] is False


def test_estimate_post_no_scope_returns_full_run(
    client, _seeded_two_runs, _fake_registry
):
    run_id = _seeded_two_runs["run_a"]
    resp = client.post(f"/api/v1/runs/{run_id}/ai-fixes/estimate", json={})
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["total_findings_in_scope"] == 4


def test_legacy_get_estimate_still_works(client, _seeded_two_runs, _fake_registry):
    """The deprecated GET /estimate endpoint must keep working for
    30 days post-rollout."""
    run_id = _seeded_two_runs["run_a"]
    resp = client.get(f"/api/v1/runs/{run_id}/ai-fixes/estimate")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["findings_total"] == 4


# ============================================================================
# Per-batch endpoints
# ============================================================================


def test_list_batches_endpoint(
    client, _seeded_two_runs, _enable_ai, _fake_registry, _memory_store
):
    run_id = _seeded_two_runs["run_a"]
    client.post(
        f"/api/v1/runs/{run_id}/ai-fixes",
        json={"scope": {"severities": ["CRITICAL"], "label": "Critical"}},
    )
    resp = client.get(f"/api/v1/runs/{run_id}/ai-fixes/batches")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["scope_label"] == "Critical"


def test_batch_detail_404_for_unknown_batch(
    client, _seeded_two_runs, _enable_ai
):
    run_id = _seeded_two_runs["run_a"]
    resp = client.get(f"/api/v1/runs/{run_id}/ai-fixes/batches/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


def test_per_batch_cancel_endpoint_sets_flag(
    client, _seeded_two_runs, _enable_ai, _fake_registry, _memory_store
):
    """Cancel one batch — only that batch gets the flag; others on the
    run keep running."""
    run_id = _seeded_two_runs["run_a"]
    db = SessionLocal()
    try:
        row = create_batch(
            db,
            run_id=run_id,
            finding_ids=[_seeded_two_runs["a1"]],
            provider_name="fake",
            scope=None,
        )
        bid = row.id
        # Seed the progress store so the SSE / cancel paths can read.
        progress = BatchProgress(
            run_id=run_id,
            batch_id=bid,
            status="in_progress",
            total=1,
            remaining=1,
        )
        _memory_store.write(progress)
    finally:
        db.close()

    resp = client.post(f"/api/v1/runs/{run_id}/ai-fixes/batches/{bid}/cancel")
    assert resp.status_code == 202
    body = resp.json()
    assert body["batch_id"] == bid
    assert body["cancel_requested"] is True
    assert _memory_store.is_cancel_requested(run_id, bid) is True


def test_per_batch_stream_404_for_unknown_batch(client, _seeded_two_runs, _enable_ai):
    run_id = _seeded_two_runs["run_a"]
    resp = client.get(f"/api/v1/runs/{run_id}/ai-fixes/batches/missing-batch/stream")
    assert resp.status_code == 404
