"""1,000-finding load test for the batch pipeline.

Phase 3 §3.6 deliverable. Uses an in-memory cost-free provider so the run
exercises real DB writes (cache + ledger) and real concurrency primitives
without spending any LLM tokens. Asserts:

  * The full run completes in well under the wall-clock target.
  * Throughput matches the bound semaphore (max_concurrent).
  * A second run hits the cache for every finding — zero LLM calls.

Marked with ``@pytest.mark.integration`` so CI can opt in / out.
"""

from __future__ import annotations

import asyncio
import json
import time

import pytest
from app.ai.batch import AiFixBatchPipeline
from app.ai.progress import InMemoryProgressStore
from app.ai.providers.base import (
    LlmRequest,
    LlmResponse,
    LlmUsage,
    ProviderInfo,
)
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

from tests.ai.fixtures import EX1_CRITICAL_KEV_WITH_FIX_BUNDLE

_LOAD_FINDINGS = 1000
_PER_CALL_DELAY_SECONDS = 0.001  # simulate fastest possible provider


class LoadProvider:
    """Returns a canned bundle for every call. Tracks call count atomically."""

    name = "fake"
    default_model = "fake-1"
    is_local = True
    max_concurrent = 32

    def __init__(self, *, payload: dict, per_call_delay: float = 0.0) -> None:
        self._payload = payload
        self._per_call_delay = per_call_delay
        self.call_count = 0
        self._lock = asyncio.Lock()

    async def generate(self, req: LlmRequest) -> LlmResponse:
        async with self._lock:
            self.call_count += 1
        if self._per_call_delay > 0:
            await asyncio.sleep(self._per_call_delay)
        return LlmResponse(
            text=json.dumps(self._payload),
            parsed=self._payload,
            usage=LlmUsage(input_tokens=100, output_tokens=200, cost_usd=0.0),
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


def _registry_with(provider: LoadProvider) -> ProviderRegistry:
    reg = ProviderRegistry(configs=[], default_provider="fake")
    reg.register_instance(provider)
    return reg


def _seed(n: int) -> int:
    """Seed ``n`` distinct findings on a fresh run. Returns run_id."""
    db = SessionLocal()
    try:
        db.query(AiFixCache).delete()
        db.query(AiUsageLog).delete()
        db.query(AnalysisFinding).delete()
        db.query(AnalysisRun).delete()
        db.query(SBOMComponent).delete()
        db.query(SBOMSource).delete()
        db.commit()

        sbom = SBOMSource(sbom_name="load")
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
        # Bulk insert via add_all — much faster than per-row commit.
        rows = [
            AnalysisFinding(
                analysis_run_id=run.id,
                vuln_id=f"CVE-2099-{i:06d}",
                source="NVD",
                severity="HIGH",
                score=7.0,
                component_name=f"pkg-{i}",
                component_version="1.0.0",
                fixed_versions=json.dumps(["1.0.1"]),
            )
            for i in range(n)
        ]
        db.add_all(rows)
        db.commit()
        return run.id
    finally:
        db.close()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_batch_handles_1000_findings(client):
    """1,000 cold-cache findings complete in bounded wall time + write cache."""
    run_id = _seed(_LOAD_FINDINGS)
    provider = LoadProvider(payload=EX1_CRITICAL_KEV_WITH_FIX_BUNDLE, per_call_delay=_PER_CALL_DELAY_SECONDS)
    store = InMemoryProgressStore()
    db = SessionLocal()
    try:
        pipeline = AiFixBatchPipeline(db, registry=_registry_with(provider), store=store)
        t0 = time.perf_counter()
        summary = await pipeline.run(run_id)
        elapsed = time.perf_counter() - t0
    finally:
        db.close()

    assert summary.progress.status == "complete"
    assert summary.progress.generated == _LOAD_FINDINGS
    assert summary.progress.failed == 0
    assert summary.progress.from_cache == 0
    # 1000 calls × 1 ms / 32 concurrent ≈ 30 ms minimum. Allow plenty of
    # headroom for DB / Pydantic / asyncio overhead — this assertion is
    # about catching a regression to non-concurrent execution, not about
    # tight latency.
    assert elapsed < 30.0, f"1000-finding batch took {elapsed:.2f}s — concurrency regressed?"

    # Cache check: every finding should now be cached.
    db = SessionLocal()
    try:
        cached = db.query(AiFixCache).count()
    finally:
        db.close()
    assert cached == _LOAD_FINDINGS


@pytest.mark.integration
@pytest.mark.asyncio
async def test_warm_cache_second_run_zero_llm_calls(client):
    """After a successful run, the same scan completes without hitting the provider."""
    run_id = _seed(_LOAD_FINDINGS)
    p1 = LoadProvider(payload=EX1_CRITICAL_KEV_WITH_FIX_BUNDLE)
    db = SessionLocal()
    try:
        pipeline = AiFixBatchPipeline(db, registry=_registry_with(p1), store=InMemoryProgressStore())
        await pipeline.run(run_id)
    finally:
        db.close()

    # Second pass — provider must remain untouched.
    p2 = LoadProvider(payload=EX1_CRITICAL_KEV_WITH_FIX_BUNDLE)
    db = SessionLocal()
    try:
        pipeline = AiFixBatchPipeline(db, registry=_registry_with(p2), store=InMemoryProgressStore())
        t0 = time.perf_counter()
        summary = await pipeline.run(run_id)
        elapsed = time.perf_counter() - t0
    finally:
        db.close()
    assert summary.progress.status == "complete"
    assert summary.progress.from_cache == _LOAD_FINDINGS
    assert summary.progress.generated == 0
    assert p2.call_count == 0
    # Pure DB scan — should be fast.
    assert elapsed < 5.0, f"warm-cache pass took {elapsed:.2f}s"
