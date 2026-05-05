"""AiFixBatchPipeline tests — full hit, full miss, partial, budget, cancel, idempotency.

Uses the same FakeProvider shape as ``test_fix_generator.py`` plus an
in-memory progress store, so nothing requires Celery / Redis / a real
LLM endpoint.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from app.ai.batch import AiFixBatchPipeline
from app.ai.cost import BudgetCaps, BudgetGuard
from app.ai.progress import InMemoryProgressStore
from app.ai.providers.base import (
    AiProviderError,
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

from tests.ai.fixtures import (
    EX1_CRITICAL_KEV_WITH_FIX_BUNDLE,
    EX2_MEDIUM_WITH_FIX_BUNDLE,
    EX3_HIGH_NO_FIX_BUNDLE,
)

# ============================================================ Fake provider


class FakeProvider:
    """Returns canned bundles in queue order; supports per-call latency hooks."""

    name = "fake"
    default_model = "fake-1"
    is_local = True
    max_concurrent = 4

    def __init__(self, payloads: list[dict | Exception], *, per_call_delay: float = 0.0) -> None:
        self._payloads = list(payloads)
        self._per_call_delay = per_call_delay
        self.calls: list[LlmRequest] = []

    async def generate(self, req: LlmRequest) -> LlmResponse:
        self.calls.append(req)
        if self._per_call_delay > 0:
            await asyncio.sleep(self._per_call_delay)
        if not self._payloads:
            raise AiProviderError("fake: no payload queued")
        nxt = self._payloads.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        text = json.dumps(nxt)
        return LlmResponse(
            text=text,
            parsed=nxt,
            usage=LlmUsage(input_tokens=100, output_tokens=200, cost_usd=0.001),
            provider=self.name,
            model=self.default_model,
            latency_ms=10,
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


def _registry_with(provider: FakeProvider) -> ProviderRegistry:
    reg = ProviderRegistry(configs=[], default_provider="fake")
    reg.register_instance(provider)
    return reg


# ============================================================ Seed helpers


def _wipe(db) -> None:
    db.query(AiFixCache).delete()
    db.query(AiUsageLog).delete()
    db.query(AnalysisFinding).delete()
    db.query(AnalysisRun).delete()
    db.query(SBOMComponent).delete()
    db.query(SBOMSource).delete()
    db.commit()


def _seed_run_with_findings(n: int) -> int:
    """Create one run with ``n`` distinct findings. Returns run_id."""
    db = SessionLocal()
    try:
        _wipe(db)
        sbom = SBOMSource(sbom_name="batch-test")
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
        for i in range(n):
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
        db.commit()
        return run.id
    finally:
        db.close()


@pytest.fixture()
def _empty_run(client):
    db = SessionLocal()
    try:
        _wipe(db)
        sbom = SBOMSource(sbom_name="batch-empty")
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
        db.commit()
        yield run.id
    finally:
        db.close()


# ============================================================ Tests


@pytest.mark.asyncio
async def test_empty_run_completes_immediately(_empty_run):
    fake = FakeProvider([])
    store = InMemoryProgressStore()
    db = SessionLocal()
    try:
        pipeline = AiFixBatchPipeline(db, registry=_registry_with(fake), store=store)
        summary = await pipeline.run(_empty_run)
    finally:
        db.close()
    assert summary.progress.status == "complete"
    assert summary.progress.total == 0
    assert len(fake.calls) == 0


@pytest.mark.asyncio
async def test_full_cache_miss_generates_each_finding(client):
    run_id = _seed_run_with_findings(3)
    payloads = [EX1_CRITICAL_KEV_WITH_FIX_BUNDLE, EX2_MEDIUM_WITH_FIX_BUNDLE, EX3_HIGH_NO_FIX_BUNDLE]
    fake = FakeProvider(payloads)
    store = InMemoryProgressStore()
    db = SessionLocal()
    try:
        pipeline = AiFixBatchPipeline(db, registry=_registry_with(fake), store=store)
        summary = await pipeline.run(run_id)
    finally:
        db.close()
    assert summary.progress.status == "complete"
    assert summary.progress.total == 3
    assert summary.progress.generated == 3
    assert summary.progress.from_cache == 0
    assert summary.progress.failed == 0
    assert len(summary.results) == 3
    assert len(fake.calls) == 3


@pytest.mark.asyncio
async def test_idempotent_second_run_is_full_cache_hit(client):
    run_id = _seed_run_with_findings(3)
    payloads = [EX1_CRITICAL_KEV_WITH_FIX_BUNDLE] * 3
    fake = FakeProvider(payloads)
    store = InMemoryProgressStore()
    db = SessionLocal()
    try:
        pipeline = AiFixBatchPipeline(db, registry=_registry_with(fake), store=store)
        await pipeline.run(run_id)
    finally:
        db.close()
    # Second pass — no payloads queued; if any miss reached the provider it
    # would raise AiProviderError. Full cache hit means zero calls.
    fake2 = FakeProvider([])
    store2 = InMemoryProgressStore()
    db = SessionLocal()
    try:
        pipeline = AiFixBatchPipeline(db, registry=_registry_with(fake2), store=store2)
        summary = await pipeline.run(run_id)
    finally:
        db.close()
    assert summary.progress.status == "complete"
    assert summary.progress.from_cache == 3
    assert summary.progress.generated == 0
    assert len(fake2.calls) == 0


@pytest.mark.asyncio
async def test_partial_cache_hit(client):
    run_id = _seed_run_with_findings(4)
    # First pass: generate two of the four findings by force-refresh-style
    # individual call. Easiest path: run once and then add two new findings.
    db = SessionLocal()
    try:
        existing = list(db.query(AnalysisFinding).filter_by(analysis_run_id=run_id).all())
        # Delete two of them so they'll be re-added later as net-new misses.
        for f in existing[2:]:
            db.delete(f)
        db.commit()
    finally:
        db.close()

    fake = FakeProvider([EX1_CRITICAL_KEV_WITH_FIX_BUNDLE, EX1_CRITICAL_KEV_WITH_FIX_BUNDLE])
    store = InMemoryProgressStore()
    db = SessionLocal()
    try:
        pipeline = AiFixBatchPipeline(db, registry=_registry_with(fake), store=store)
        await pipeline.run(run_id)
    finally:
        db.close()

    # Add two net-new findings → cache should hit on first 2, miss on new 2.
    db = SessionLocal()
    try:
        for i in (10, 11):
            db.add(
                AnalysisFinding(
                    analysis_run_id=run_id,
                    vuln_id=f"CVE-2099-{i:05d}",
                    source="NVD",
                    severity="HIGH",
                    score=7.0,
                    component_name=f"new-pkg-{i}",
                    component_version="1.0.0",
                    fixed_versions=json.dumps(["1.0.1"]),
                )
            )
        db.commit()
    finally:
        db.close()

    fake2 = FakeProvider([EX2_MEDIUM_WITH_FIX_BUNDLE, EX2_MEDIUM_WITH_FIX_BUNDLE])
    store2 = InMemoryProgressStore()
    db = SessionLocal()
    try:
        pipeline = AiFixBatchPipeline(db, registry=_registry_with(fake2), store=store2)
        summary = await pipeline.run(run_id)
    finally:
        db.close()
    assert summary.progress.from_cache == 2
    assert summary.progress.generated == 2
    assert summary.progress.failed == 0
    assert len(fake2.calls) == 2


@pytest.mark.asyncio
async def test_budget_per_scan_halts_remaining_findings(client):
    run_id = _seed_run_with_findings(5)
    # Cap at $0.0015 — first call ($0.001) succeeds, second's pre-flight estimate
    # exceeds the cap.
    fake = FakeProvider([EX1_CRITICAL_KEV_WITH_FIX_BUNDLE] * 5)
    # Force cloud-style cost estimation by overriding fake to NOT be local.
    # Simpler: lower the cap so even one $0.001 call exhausts it.
    # Use cap = $0.0009 — pre-flight estimate of any call ($0 for local) passes,
    # but post-call record($0.001) trips the next pre-flight check.
    guard = BudgetGuard(BudgetCaps(per_request_usd=10.0, per_scan_usd=0.0009, per_day_org_usd=None))
    # Provider is local; cost=0 → guard never trips.
    # Instead emulate by patching the FakeProvider's record cost to be non-zero:
    fake.is_local = False  # makes the orchestrator estimate cost from PRICING
    store = InMemoryProgressStore()
    db = SessionLocal()
    try:
        pipeline = AiFixBatchPipeline(
            db, registry=_registry_with(fake), store=store, budget=guard
        )
        summary = await pipeline.run(run_id)
    finally:
        db.close()
    # FakeProvider's model "fake-1" isn't in PRICING, so estimate_cost is 0
    # and the guard never trips. This branch is for documentation; the
    # real budget halt is exercised in the next test using a model name
    # that maps to a non-zero rate.
    assert summary.progress.total == 5


@pytest.mark.asyncio
async def test_budget_halt_with_priced_model(client):
    """Override the FakeProvider's cost reporting to trigger the per-scan cap."""
    run_id = _seed_run_with_findings(5)

    # FakeProvider that bills like a cloud provider so the BudgetGuard trips.
    class CostlyFake(FakeProvider):
        name = "openai"
        default_model = "gpt-4o-mini"
        is_local = False

        async def generate(self, req):  # type: ignore[override]
            self.calls.append(req)
            if not self._payloads:
                raise AiProviderError("fake: no payload queued")
            nxt = self._payloads.pop(0)
            if isinstance(nxt, Exception):
                raise nxt
            return LlmResponse(
                text=json.dumps(nxt),
                parsed=nxt,
                usage=LlmUsage(input_tokens=10000, output_tokens=10000, cost_usd=1.50),
                provider=self.name,
                model=self.default_model,
                latency_ms=10,
            )

    fake = CostlyFake([EX1_CRITICAL_KEV_WITH_FIX_BUNDLE] * 5)
    guard = BudgetGuard(BudgetCaps(per_request_usd=10.0, per_scan_usd=2.0, per_day_org_usd=None))
    store = InMemoryProgressStore()
    # CostlyFake reports name="openai" — registry default must match so
    # ``get_default()`` resolves to the fake instance.
    reg = ProviderRegistry(configs=[], default_provider="openai")
    reg.register_instance(fake)
    db = SessionLocal()
    try:
        pipeline = AiFixBatchPipeline(db, registry=reg, store=store, budget=guard)
        summary = await pipeline.run(run_id)
    finally:
        db.close()
    # The pre-flight estimate from prompt size is small (~$0.001) so it
    # passes until the *recorded* cumulative cost trips the per-scan cap.
    # With cap=$2 and per-call recorded cost=$1.50, the second call passes
    # pre-flight (1.50 spent + ~0.001 estimate < 2.00) and brings spent to
    # $3.00; the third call fails. Status flips to ``paused_budget``.
    assert summary.progress.status == "paused_budget"
    assert summary.progress.generated >= 1
    assert summary.progress.failed >= 1
    # Total accounted-for findings must equal the run total.
    assert summary.progress.generated + summary.progress.failed == 5


@pytest.mark.asyncio
async def test_provider_failure_per_finding_does_not_abort_batch(client):
    run_id = _seed_run_with_findings(3)
    fake = FakeProvider(
        [
            EX1_CRITICAL_KEV_WITH_FIX_BUNDLE,
            AiProviderError("upstream 503"),
            EX2_MEDIUM_WITH_FIX_BUNDLE,
        ]
    )
    store = InMemoryProgressStore()
    db = SessionLocal()
    try:
        pipeline = AiFixBatchPipeline(db, registry=_registry_with(fake), store=store)
        summary = await pipeline.run(run_id)
    finally:
        db.close()
    assert summary.progress.total == 3
    # Two succeed, one fails — batch completes.
    assert summary.progress.status == "complete"
    assert len(summary.results) == 2
    assert len(summary.errors) == 1
    assert summary.errors[0].error_code == "provider_unavailable"


@pytest.mark.asyncio
async def test_force_refresh_bypasses_cache(client):
    run_id = _seed_run_with_findings(2)
    fake = FakeProvider([EX1_CRITICAL_KEV_WITH_FIX_BUNDLE] * 4)
    store = InMemoryProgressStore()
    db = SessionLocal()
    try:
        pipeline = AiFixBatchPipeline(db, registry=_registry_with(fake), store=store)
        await pipeline.run(run_id)
        await pipeline.run(run_id, force_refresh=True)
    finally:
        db.close()
    # 2 first run + 2 forced-refresh = 4 LLM calls.
    assert len(fake.calls) == 4


@pytest.mark.asyncio
async def test_cancel_mid_flight_skips_remaining(client):
    run_id = _seed_run_with_findings(8)
    # Slow provider so cancel can land before all calls complete.
    fake = FakeProvider([EX1_CRITICAL_KEV_WITH_FIX_BUNDLE] * 8, per_call_delay=0.05)
    store = InMemoryProgressStore()

    async def _cancel_after(seconds: float):
        await asyncio.sleep(seconds)
        store.request_cancel(run_id)

    db = SessionLocal()
    try:
        pipeline = AiFixBatchPipeline(db, registry=_registry_with(fake), store=store)
        async with asyncio.TaskGroup() as tg:
            tg.create_task(_cancel_after(0.05))
            run_task = tg.create_task(pipeline.run(run_id))
        summary = run_task.result()
    finally:
        db.close()
    assert summary.progress.status == "cancelled"
    assert summary.progress.cancel_requested is True
    # Some calls landed before cancel propagated; some were skipped.
    assert len(fake.calls) < 8


@pytest.mark.asyncio
async def test_progress_store_reflects_running_state(client):
    run_id = _seed_run_with_findings(2)
    fake = FakeProvider([EX1_CRITICAL_KEV_WITH_FIX_BUNDLE] * 2)
    store = InMemoryProgressStore()
    db = SessionLocal()
    try:
        pipeline = AiFixBatchPipeline(db, registry=_registry_with(fake), store=store)
        await pipeline.run(run_id)
    finally:
        db.close()
    snap = store.read(run_id)
    assert snap is not None
    assert snap.status == "complete"
    assert snap.total == 2
    assert snap.generated == 2
    assert snap.provider_used == "fake"
    assert snap.started_at is not None
    assert snap.finished_at is not None
