"""End-to-end verification scenarios for the scope-aware AI fixes feature.

Mirrors the 10 scenarios in ``docs/rollout-ai-fixes.md`` §8.4. Each
test exercises the full HTTP surface against the inline-fallback
pipeline (no Celery, no real LLM) so the contracts are pinned in CI.

Scenarios that depend on real provider behaviour or live Redis
(numbers 5 and 7 in the rollout doc — concurrent cache contention
across processes, free-tier rate-limit serialisation) are NOT
covered here; they are run against staging. The single-process
contention case IS covered by
``tests/ai/test_scope_and_multi_batch.py::test_cache_lock_dedupes_concurrent_generations_for_same_key``.
"""

from __future__ import annotations

import json

import pytest
from app.ai.batches import create_batch, list_batches_for_run
from app.ai.progress import (
    BatchProgress,
    InMemoryProgressStore,
    _set_store,
    initial_progress,
    reset_progress_store,
)
from app.ai.providers.base import LlmRequest, LlmResponse, LlmUsage, ProviderInfo
from app.ai.registry import ProviderRegistry
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
# Test scaffolding (mirrors test_scope_and_multi_batch.py — kept local so
# the e2e file can be read end-to-end without jumping back).
# ---------------------------------------------------------------------------


class _StubProvider:
    name = "fake"
    default_model = "fake-1"
    is_local = True
    max_concurrent = 4
    tier = "paid"

    async def generate(self, _req: LlmRequest) -> LlmResponse:
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
    """Seed a run with 6 findings spanning 3 severities + 1 KEV row.

    Mirrors a small-but-realistic distribution so scope filters
    produce non-trivial sets.
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

        sbom = SBOMSource(sbom_name="phase5-e2e")
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

        findings_spec = [
            ("CRITICAL", "9.8", "kev-pkg", True),     # KEV-listed
            ("CRITICAL", "9.5", "crit-pkg", False),
            ("HIGH", "8.0", "high-pkg", False),
            ("HIGH", "7.5", "high-pkg-2", False),
            ("MEDIUM", "5.5", "med-pkg", False),
            ("LOW", "2.0", "low-pkg", False),
        ]
        finding_ids: list[int] = []
        for i, (sev, score, comp, is_kev) in enumerate(findings_spec):
            f = AnalysisFinding(
                analysis_run_id=run.id,
                vuln_id=f"CVE-2099-P5{i:03d}",
                severity=sev,
                score=float(score),
                title=f"finding {i}",
                component_name=comp,
                component_version="1.0.0",
                fixed_versions=json.dumps(["1.0.1"]),
            )
            db.add(f)
            db.flush()
            finding_ids.append(f.id)
            if is_kev:
                db.add(KevEntry(cve_id=f.vuln_id, refreshed_at="2026-01-01T00:00:00Z"))

        db.commit()
        yield {"run_id": run.id, "finding_ids": finding_ids}
    finally:
        db.close()


@pytest.fixture()
def _fake_registry(monkeypatch):
    from app.ai import registry as registry_mod

    fake = _StubProvider()
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


@pytest.fixture()
def _memory_store():
    store = InMemoryProgressStore()
    _set_store(store)
    yield store
    reset_progress_store()


# ---------------------------------------------------------------------------
# Scenario 1 — Filter-driven first batch
# ---------------------------------------------------------------------------


def test_scenario1_filter_driven_critical_batch_returns_resolved_count(
    client, _seeded_run, _enable_ai, _fake_registry, _memory_store
):
    """User clicks 'Critical' filter chip, fires Generate.
    Banner appears with 'Critical findings' scope label; batch
    processes only the 2 Critical findings."""
    body = {"scope": {"severities": ["CRITICAL"], "label": "Critical findings"}}
    resp = client.post(
        f"/api/v1/runs/{_seeded_run['run_id']}/ai-fixes",
        json=body,
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["total"] == 2
    assert payload["scope_label"] == "Critical findings"
    assert payload["progress"]["scope_label"] == "Critical findings"


# ---------------------------------------------------------------------------
# Scenario 2 — Multi-batch parallel
# ---------------------------------------------------------------------------


def test_scenario2_two_concurrent_batches_have_distinct_ids_and_labels(
    client, _seeded_run, _enable_ai, _fake_registry, _memory_store
):
    """Fire two batches in succession (Critical, then KEV-only) on
    the same run. Both produce distinct ``ai_fix_batch`` rows with
    their own scope labels."""
    run_id = _seeded_run["run_id"]
    r1 = client.post(
        f"/api/v1/runs/{run_id}/ai-fixes",
        json={"scope": {"severities": ["CRITICAL"], "label": "Critical findings"}},
    )
    r2 = client.post(
        f"/api/v1/runs/{run_id}/ai-fixes",
        json={"scope": {"kev_only": True, "label": "KEV findings"}},
    )
    assert r1.status_code == 200, r1.text
    assert r2.status_code == 200, r2.text
    assert r1.json()["batch_id"] != r2.json()["batch_id"]

    # The list endpoint reflects both batches with correct labels.
    listing = client.get(f"/api/v1/runs/{run_id}/ai-fixes/batches")
    assert listing.status_code == 200
    items = listing.json()["items"]
    assert len(items) == 2
    labels = {it["scope_label"] for it in items}
    assert labels == {"Critical findings", "KEV findings"}


# ---------------------------------------------------------------------------
# Scenario 3 — Selection-driven
# ---------------------------------------------------------------------------


def test_scenario3_selection_driven_uses_finding_ids(
    client, _seeded_run, _enable_ai, _fake_registry, _memory_store
):
    """Multi-select 3 specific finding ids; CTA fires with finding_ids
    + label='Selected (3)'. Batch processes exactly those 3 rows."""
    run_id = _seeded_run["run_id"]
    selection = _seeded_run["finding_ids"][:3]
    body = {"scope": {"finding_ids": selection, "label": "Selected (3)"}}
    resp = client.post(f"/api/v1/runs/{run_id}/ai-fixes", json=body)
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["total"] == 3
    assert payload["scope_label"] == "Selected (3)"


# ---------------------------------------------------------------------------
# Scenario 4 — Cache overlap (run #1's cache hits in run #2's count)
# ---------------------------------------------------------------------------


def test_scenario4_cache_overlap_reduces_second_batch_llm_calls(
    client, _seeded_run, _enable_ai, _fake_registry, _memory_store
):
    """Run a Critical batch to completion (inline fallback), then
    estimate a High+Critical batch — the 2 Critical findings are
    already cached, so the new estimate's cached_count >= 2."""
    run_id = _seeded_run["run_id"]
    # Batch 1 — Critical only.
    r1 = client.post(
        f"/api/v1/runs/{run_id}/ai-fixes",
        json={"scope": {"severities": ["CRITICAL"]}},
    )
    assert r1.status_code == 200
    # If Celery is unreachable (no broker in CI), the inline path
    # finished synchronously. If Celery accepted the job, the cache
    # may not be populated yet — skip the assertion in that case.
    if r1.json()["enqueued"]:
        pytest.skip("Celery accepted the task; inline cache population not guaranteed.")

    # Batch 2 — estimate for "High + Critical" should now report 2 cache hits.
    r2 = client.post(
        f"/api/v1/runs/{run_id}/ai-fixes/estimate",
        json={"scope": {"severities": ["HIGH", "CRITICAL"]}},
    )
    assert r2.status_code == 200
    payload = r2.json()
    # 4 findings in scope (2 Critical + 2 High); 2 are cached after batch 1.
    assert payload["total_findings_in_scope"] == 4
    assert payload["cached_count"] >= 2


# ---------------------------------------------------------------------------
# Scenario 6 — Max concurrent (4th batch returns 409)
# ---------------------------------------------------------------------------


def test_scenario6_fourth_concurrent_batch_returns_typed_409(
    client, _seeded_run, _enable_ai, _fake_registry, _memory_store
):
    """3 active batches → 4th returns ``TOO_MANY_ACTIVE_BATCHES``."""
    run_id = _seeded_run["run_id"]
    db = SessionLocal()
    try:
        for _ in range(3):
            row = create_batch(
                db,
                run_id=run_id,
                finding_ids=_seeded_run["finding_ids"][:1],
                provider_name="fake",
                scope=None,
            )
            row.status = "in_progress"
            db.commit()
    finally:
        db.close()

    resp = client.post(f"/api/v1/runs/{run_id}/ai-fixes")
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["error_code"] == "TOO_MANY_ACTIVE_BATCHES"
    assert detail["retryable"] is True
    assert detail["max_concurrent"] == 3


# ---------------------------------------------------------------------------
# Scenario 8 — Cancel one of multiple
# ---------------------------------------------------------------------------


def test_scenario8_cancel_one_batch_does_not_affect_others(
    client, _seeded_run, _enable_ai, _fake_registry, _memory_store
):
    """Cancel batch A; batch B's cancel flag is NOT set."""
    run_id = _seeded_run["run_id"]
    store = _memory_store

    pa = initial_progress(run_id, total=10, batch_id="batch-a", scope_label="A")
    pa.status = "in_progress"
    store.write(pa)
    pb = initial_progress(run_id, total=10, batch_id="batch-b", scope_label="B")
    pb.status = "in_progress"
    store.write(pb)

    db = SessionLocal()
    try:
        for bid, label in (("batch-a", "A"), ("batch-b", "B")):
            db.add(
                AiFixBatch(
                    id=bid,
                    run_id=run_id,
                    status="in_progress",
                    scope_label=label,
                    scope_json=None,
                    finding_ids_json=[],
                    provider_name="fake",
                    total=10,
                    cached_count=0,
                    generated_count=0,
                    failed_count=0,
                    cost_usd=0,
                    started_at="2026-05-04T00:00:00Z",
                    completed_at=None,
                    created_at="2026-05-04T00:00:00Z",
                    last_error=None,
                )
            )
        db.commit()
    finally:
        db.close()

    resp = client.post(
        f"/api/v1/runs/{run_id}/ai-fixes/batches/batch-a/cancel",
    )
    assert resp.status_code == 202
    assert store.is_cancel_requested(run_id, "batch-a") is True
    assert store.is_cancel_requested(run_id, "batch-b") is False


# ---------------------------------------------------------------------------
# Scenario 9 — Selection persists across filter (backend resolves IDs as supplied)
# ---------------------------------------------------------------------------


def test_scenario9_selection_across_severities_resolves_to_supplied_ids(
    client, _seeded_run, _enable_ai, _fake_registry, _memory_store
):
    """Selection of 5 findings spanning multiple severities is
    resolved verbatim — backend doesn't second-guess the client's
    selection. Security: caller can't slip in IDs from another run."""
    run_id = _seeded_run["run_id"]
    # 5 findings of mixed severities (every finding except the LOW one).
    selection = _seeded_run["finding_ids"][:5]
    resp = client.post(
        f"/api/v1/runs/{run_id}/ai-fixes",
        json={"scope": {"finding_ids": selection, "label": "Selected (5)"}},
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["total"] == 5

    # The persisted batch row's finding_ids_json equals the selection.
    db = SessionLocal()
    try:
        rows = list_batches_for_run(db, run_id=run_id)
        assert rows
        row = next(r for r in rows if r.id == payload["batch_id"])
        stored = list(row.finding_ids_json)
        assert sorted(stored) == sorted(selection)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Scenario 10 — All-cached scope (estimate reports llm_call_count=0)
# ---------------------------------------------------------------------------


def test_scenario10_all_cached_scope_reports_zero_llm_calls(
    client, _seeded_run, _enable_ai, _fake_registry, _memory_store
):
    """After running a Critical batch, re-estimating Critical scope
    should report zero net-new LLM calls (every finding cached)."""
    run_id = _seeded_run["run_id"]
    r1 = client.post(
        f"/api/v1/runs/{run_id}/ai-fixes",
        json={"scope": {"severities": ["CRITICAL"]}},
    )
    assert r1.status_code == 200
    if r1.json()["enqueued"]:
        pytest.skip("Celery accepted; inline cache population not guaranteed.")

    r2 = client.post(
        f"/api/v1/runs/{run_id}/ai-fixes/estimate",
        json={"scope": {"severities": ["CRITICAL"]}},
    )
    assert r2.status_code == 200
    payload = r2.json()
    assert payload["total_findings_in_scope"] == 2
    # Both Criticals should be in cache after the inline fallback completed.
    assert payload["cached_count"] == 2
    assert payload["llm_call_count"] == 0


# ---------------------------------------------------------------------------
# Backwards-compat: legacy single-batch endpoints still work
# ---------------------------------------------------------------------------


def test_legacy_get_estimate_endpoint_still_returns_full_run_count(
    client, _seeded_run, _fake_registry
):
    """Pre-Phase-4 frontends call ``GET /estimate`` and expect the
    legacy ``findings_total`` shape."""
    run_id = _seeded_run["run_id"]
    resp = client.get(f"/api/v1/runs/{run_id}/ai-fixes/estimate")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["findings_total"] == 6


def test_legacy_get_progress_endpoint_returns_latest_batch(
    client, _seeded_run, _enable_ai, _fake_registry, _memory_store
):
    """``GET /progress`` returns the most-recent batch's snapshot
    when no legacy run-level entry exists."""
    run_id = _seeded_run["run_id"]
    # Create a multi-batch progress entry.
    pa = initial_progress(run_id, total=2, batch_id="latest", scope_label="Latest")
    pa.status = "in_progress"
    pa.from_cache = 1
    _memory_store.write(pa)

    resp = client.get(f"/api/v1/runs/{run_id}/ai-fixes/progress")
    assert resp.status_code == 200
    body = resp.json()
    assert body["batch_id"] == "latest"
    assert body["scope_label"] == "Latest"
    assert body["from_cache"] == 1


def test_legacy_post_cancel_sets_run_level_flag(
    client, _seeded_run, _enable_ai, _memory_store
):
    """The legacy run-scoped cancel endpoint sets the legacy flag,
    which halts every batch on the run."""
    run_id = _seeded_run["run_id"]
    resp = client.post(f"/api/v1/runs/{run_id}/ai-fixes/cancel")
    assert resp.status_code == 202
    body = resp.json()
    assert body["cancel_requested"] is True
    # Both legacy and any batch-id callers see the flag as set.
    assert _memory_store.is_cancel_requested(run_id) is True
    assert _memory_store.is_cancel_requested(run_id, "batch-a") is True


def test_trigger_without_scope_processes_all_findings(
    client, _seeded_run, _enable_ai, _fake_registry, _memory_store
):
    """An empty body or no scope → run-wide batch (legacy behaviour)."""
    run_id = _seeded_run["run_id"]
    resp = client.post(f"/api/v1/runs/{run_id}/ai-fixes")
    assert resp.status_code == 200
    payload = resp.json()
    # All 6 findings in scope.
    assert payload["total"] == 6
    # No scope label when none supplied.
    assert payload["scope_label"] is None or payload["scope_label"] == ""


# ---------------------------------------------------------------------------
# Sanity guard: progress envelope carries batch_id/scope_label end-to-end
# ---------------------------------------------------------------------------


def test_progress_envelope_carries_batch_id_and_scope_label(
    client, _seeded_run, _enable_ai, _fake_registry, _memory_store
):
    """The TriggerBatchResponse.progress envelope includes
    ``batch_id`` + ``scope_label`` so the frontend can register the
    new batch with the global progress provider without a follow-up
    fetch."""
    run_id = _seeded_run["run_id"]
    resp = client.post(
        f"/api/v1/runs/{run_id}/ai-fixes",
        json={"scope": {"severities": ["HIGH"], "label": "High findings"}},
    )
    assert resp.status_code == 200
    body = resp.json()
    progress = body["progress"]
    assert progress["batch_id"] == body["batch_id"]
    assert progress["scope_label"] == "High findings"
    assert isinstance(BatchProgress.model_validate(progress), BatchProgress)
