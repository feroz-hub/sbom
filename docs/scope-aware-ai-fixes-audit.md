# Scope-aware AI fixes — Phase 1 audit

**Status:** Phase 1 read-only audit. No code changes in this phase.
**Owner:** Feroze Basha
**Audited:** 2026-05-04
**Audited against branch:** `feat/ai-fixes-ui-integration`

This document inventories the existing AI fix generation primitives so Phase 2-5 changes are targeted, not redundant. Findings are organized by the original prompt's audit checklist.

---

## TL;DR — material discrepancies vs. the Phase 0 prompt

Three things in the prompt do not match the repo as it stands. They affect Phase 2-4 scope:

1. **TanStack Table is NOT in the repo.** Prompt §2.4 says "TanStack Table v8 assumed (verify in Phase 1 audit)" — verified: absent. The findings table is hand-rolled HTML in [FindingsTable.tsx](frontend/src/components/analysis/FindingsTable.tsx) (878 LOC, custom sort/pagination hooks). **Phase 4 row selection must be hand-built**, or we add `@tanstack/react-table` as part of this initiative (separate gate decision).
2. **The CTA component is `RunBatchProgress`, not `AiFixesCtaCard`.** Lives at [RunBatchProgress.tsx](frontend/src/components/ai-fixes/RunBatchProgress/RunBatchProgress.tsx). Same role; different name. All prompt references to `AiFixesCtaCard.tsx` should be read as `RunBatchProgress.tsx`.
3. **Progress system has zero concept of `batch_id`.** Both Redis and in-memory progress stores key by `run_id` only. The SSE stream `/runs/{id}/ai-fixes/stream` streams a single batch. The G1 banner provider (prompt §2.4) tracks runs (`Set<number>`), not batches. Prompt §2.4 says "the existing global progress banner from G1 already supports multiple banners with overflow — we use that infrastructure" — this is **partially true**: the banner UI supports multiple *rows* (capped at 3, with "+N more" overflow), but each row is one run, and a new batch on the same run replaces (does not append) the existing banner. **Multi-batch-per-run requires reshaping both Redis keys and the provider's tracked-set.**

These are not blockers — they are scope clarifications. Phase 2 plan reflects them.

---

## 1.1 Backend audit

### 1.1.1 `POST /api/v1/runs/{run_id}/ai-fixes` endpoint

**Source:** [ai_fixes.py:150-198](app/routers/ai_fixes.py#L150-L198)

**Current request schema** ([ai_fixes.py:73-80](app/routers/ai_fixes.py#L73-L80)):
```python
class TriggerBatchRequest(BaseModel):
    provider_name: str | None = None        # override default provider
    force_refresh: bool = False              # bypass cache
    budget_usd: float | None = None          # per-scan budget cap
```
No scope field. No `finding_ids`. Loads every finding for the run unconditionally at [line 165-167](app/routers/ai_fixes.py#L165-L167):
```python
total = db.execute(
    select(AnalysisFinding).where(AnalysisFinding.analysis_run_id == run_id)
).all()
```

**Where scope slots in cleanly:**
1. Add `scope: AiFixGenerationScope | None = None` to `TriggerBatchRequest`.
2. Replace the unconditional load on line 165 with a call to a new `resolve_scope_findings()` helper (sketched in Phase 2 plan).
3. Pass the resolved set (and a generated `batch_id`) into the Celery worker task / inline pipeline.

**Backwards compat:** `body or TriggerBatchRequest()` at [line 163](app/routers/ai_fixes.py#L163) — when `body=None`, behavior is unchanged. Prompt §2.4's "extend, never break" constraint is naturally satisfied because `scope=None` falls through to "all findings."

### 1.1.2 Orchestrator (`AiFixBatchPipeline`)

**Source:** [app/ai/batch.py](app/ai/batch.py) — class `AiFixBatchPipeline`.

**Public entry point:**
```python
class AiFixBatchPipeline:
    def __init__(self, db, registry=None, store=None, budget=None): ...
    async def run(self, run_id, provider_name=None, force_refresh=False) -> BatchSummary
```

Does NOT currently accept `batch_id` or any scope filter. It calls a private `_load_findings(run_id)` (around line 232-237) that runs `SELECT * FROM analysis_finding WHERE analysis_run_id = run_id`.

**Idempotency across concurrent calls:** Mostly — the cache layer ([cache.py](app/ai/cache.py) `read_cache` / `write_cache`) makes finished work idempotent. But for concurrent in-flight LLM calls on the same `(vuln, component, version)`:
- Pipeline does **not** dedupe within a single batch (irrelevant — one batch processes each finding once)
- Pipeline does **not** dedupe across batches (relevant — two parallel batches scope-overlapping the same uncached finding will both call the LLM)
- **No DB-level lock and no Redis lock around generation today.** Cache writes are last-write-wins upserts.

This confirms prompt §2.5's premise: a Redis lock around `ai_fix_gen:{cache_key}` is needed.

**Concurrency primitive inside the pipeline:** `asyncio.Semaphore(max_concurrent)` constructed per-`run()`-call. This is GOOD for multi-batch — each batch gets its own semaphore, no inter-batch serialization at this layer. (Provider-level rate limiters DO serialize, see 1.1.5.)

**Progress writes:** `self._store.write(progress)` is called per finding completion. Today the pipeline writes a single `BatchProgress` per `run_id`. Two concurrent batches racing the same key → progress field clobber. Confirmed risk for Phase 2.

### 1.1.3 SSE progress endpoint `/runs/{run_id}/ai-fixes/stream`

**Source:** [ai_fixes.py:329-345](app/routers/ai_fixes.py#L329-L345)

```python
@router.get("/runs/{run_id}/ai-fixes/stream")
def stream_progress(run_id: int, ...) -> StreamingResponse:
    ...
    for snap in progress_events(store, run_id):
        ...  # event: progress / event: end
```

**Streams a single batch's progress** — keyed on `run_id`, not `batch_id`. The generator reads `store.read(run_id)` every `poll_interval_seconds=2.0`, yields when the snapshot changes, terminates when `status` enters `{complete, failed, cancelled}`.

**No `batch_id` in the response payload** because `BatchProgress` ([progress.py:46-66](app/ai/progress.py#L46-L66)) has no such field today.

**Phase 2 changes needed:**
- New endpoint `GET /runs/{run_id}/ai-fixes/batches/{batch_id}/stream` — or extend the existing endpoint to accept an optional `?batch_id=` query param (cleaner backward compat).
- `BatchProgress.batch_id: str` field added.
- `progress_events` keyed on `(run_id, batch_id)` tuple.

### 1.1.4 Progress store

**Source:** [app/ai/progress.py](app/ai/progress.py)

**Two implementations:**
- `RedisProgressStore` (lines ~128-193) — production. Keys: `ai:fix:progress:{run_id}` (TTL 24h), `ai:fix:cancel:{run_id}`.
- `InMemoryProgressStore` (lines ~87-120) — tests + Redis-down fallback. `threading.Lock` for thread safety.

**`BatchProgress` schema** ([progress.py:46-66](app/ai/progress.py#L46-L66)):
```python
class BatchProgress(BaseModel):
    run_id: int
    status: ProgressStatus  # pending | in_progress | paused_budget | complete | failed | cancelled
    total, from_cache, generated, failed, remaining: int
    cost_so_far_usd: float
    estimated_remaining_seconds, estimated_remaining_cost_usd: int | None
    started_at, finished_at: str | None
    last_error: str | None
    cancel_requested: bool
    provider_used, model_used: str | None
```
**No `batch_id`. No `scope_label`. No `scope_json`.** All three need adding for Phase 2.

**Cancel mechanism:** `request_cancel(run_id)` writes a Redis flag; pipeline polls `is_cancel_requested(run_id)` at semaphore boundaries. Per-batch cancel requires keying both the flag and the poll on `(run_id, batch_id)`.

**Concurrency safety today:** None at the Redis layer (no per-key locks; `SET` is atomic but interleaved writes from two batches will lose data). The in-memory store has a single global lock — good for tests, would be a contention issue at scale but is not the production path. Phase 2 must move to per-`(run_id, batch_id)` keys so concurrent writes don't collide.

### 1.1.5 Cache layer

**Source:** [app/ai/cache.py](app/ai/cache.py)

**Cache key construction** ([cache.py:48-68](app/ai/cache.py#L48-L68)):
```python
def make_cache_key(
    vuln_id: str,
    component_name: str,
    component_version: str,
    prompt_version: str = PROMPT_VERSION,
) -> str:
    # sha256(vuln_id|component|version|prompt_version), normalized + lowercased
```
Tenant-shared by design. **Scope is NOT a cache key dimension** — confirms prompt §2.4's "scope is a generation filter, not a cache key dimension."

**Read/write API:**
- `read_cache(db, cache_key) -> AiFixResult | None`
- `write_cache(db, cache_key, vuln_id, component_name, component_version, bundle, ...) -> AiFixResult`
- `touch_last_accessed(db, cache_key)` — updates analytics column

**`AiFixCache` model:** PK `cache_key`. Indices on `vuln_id`, `expires_at`, and composite `(vuln_id, component_name, component_version)`. **No `locked_at`, `locked_by`, `lock_version` columns.** No existing locking primitive of any kind.

**No Redis usage anywhere in `app/ai/cache.py`.** Redis is used by the progress store but not by cache. For Phase 2 §2.5 (cache-key locks across concurrent batches), we add either:
- Redis-based lock (proposed in prompt; clean if Redis is already a hard dep) — or
- Postgres advisory lock keyed on `hashtext(cache_key)` (no new infra dep)

Recommend Redis lock since Redis is already required for the progress store. **Open question for owner gate.**

### 1.1.6 Worker task

**Source:** [app/workers/ai_fix_tasks.py:29-37](app/workers/ai_fix_tasks.py#L29-L37)

```python
@shared_task(name="ai_fix.generate_run_fixes", bind=True, ignore_result=True)
def generate_run_fixes(
    self,
    run_id: int,
    provider_name: str | None = None,
    force_refresh: bool = False,
    budget_usd: float | None = None,
) -> dict:
    ...
    pipeline.run(run_id, provider_name=provider_name, force_refresh=force_refresh)
```
Trivially extends with `batch_id: str | None = None` and `scope_finding_ids: list[int] | None = None`.

### 1.1.7 Provider rate limiters

**Source:** [app/ai/registry.py](app/ai/registry.py), `app/ai/providers/*.py`

**Registry behavior:** `get(name)` lazily instantiates a provider singleton and caches it in `self._instances`. **Each provider name has exactly one instance per registry.**

**Per-provider semaphore + rate limiter** (e.g., `app/ai/providers/openai.py` ~line 67-71):
```python
self._sem = asyncio.Semaphore(max_concurrent)
self._limiter = RateLimiter(rate=rate_per_minute, per=60.0)
```
**Both are instance variables on the singleton** — so they DO serialize across multiple concurrent batches that share the provider. Prompt §2.6's concern ("verify aiolimiter works correctly with multiple concurrent batches") is satisfied by current architecture, **on the assumption that the registry is also a singleton**. Spot-check confirms `get_registry(db)` is constructed per-request but caches its `_instances` dict. **Edge case to verify in Phase 2 testing:** if FastAPI spawns multiple worker processes, each process gets its own provider singleton, and rate limits are not shared cross-process. For the dev / single-worker case this is fine. For production with N workers, the effective rate limit is N × configured RPM. **Open question — is this acceptable, or do we need a Redis-backed token bucket?**

### 1.1.8 Estimator

**Source:** [app/ai/estimator.py:64-74](app/ai/estimator.py#L64-L74)

```python
def estimate_batch_duration(
    findings_total: int,
    cached_count: int,
    provider_name: str,
    tier: str = "paid",
    max_concurrent: int = 10,
    rate_per_minute: float | None = None,
    is_local: bool = False,
    avg_cost_per_finding_usd: float = 0.005,
) -> BatchDurationEstimate
```
Pure function on counts. **Trivially reusable for the new scope-aware estimate endpoint** — pass scoped totals + scoped cached_count.

### 1.1.9 Grounding context (cost driver for estimate endpoint)

**Source:** [app/ai/grounding.py](app/ai/grounding.py) — `build_grounding_context(finding, db, component=None)`

Per call, in worst case (cold caches): **4 DB lookups** — CveCache, SBOMComponent, KevEntry, EpssScore. Plus JSON parsing.

**Why this matters for Phase 2:** The current estimate endpoint at [ai_fixes.py:244-262](app/routers/ai_fixes.py#L244-L262) calls `build_grounding_context` for **every** finding to compute the cache key. At 513 findings this is 4 × 513 = up to 2,052 DB lookups per estimate call. The 200ms p95 target in prompt §2.8 is **not realistic** with this approach.

**Proposal (Phase 2):** Replace per-finding grounding with a single SQL query that computes cache keys in-DB:

```sql
SELECT COUNT(*) FROM ai_fix_cache c
JOIN analysis_finding f
  ON c.vuln_id = f.vuln_id
 AND c.component_name = f.component_name
 AND c.component_version = f.component_version
WHERE f.analysis_run_id = :run_id
  AND f.id = ANY(:finding_ids)  -- or scope-filter conditions
```

This skips grounding entirely for the estimate path (we only need *counts*, not bundles). **This needs owner approval** because it sidesteps the existing helper — the assumption being that the cache key dimensions (`vuln_id, component_name, component_version`) on a finding row match what `build_grounding_context` would compute. This is true today (the finding has these columns directly), but if grounding ever normalizes or substitutes them, the estimate would diverge from actual cache hits. **Open question.**

### 1.1.10 Existing tables / migrations

**Latest migration:** `010_ai_credentials_and_settings.py`. Next would be `011_*`.

**No existing `ai_fix_batch` table.** Grep confirmed. Phase 2 `ai_fix_batch` is net-new — cleaner than altering an existing schema.

**`AiFixCache` is unchanged from migration 009.** Adding `locked_at` / `locked_by` columns is possible but unnecessary if we use Redis locks (recommended).

---

## 1.2 Frontend audit

### 1.2.1 Findings table — TanStack Table presence

**Verdict: ABSENT.** `frontend/package.json` has React Query v5.56.2 but no `@tanstack/react-table` (or legacy `react-table`).

**Actual table:** [FindingsTable.tsx](frontend/src/components/analysis/FindingsTable.tsx) — 878 LOC of hand-rolled `<table>` with custom hooks `useTableSort()` and `usePagination()`. Densities (compact/comfortable/spacious), expandable rows, sortable columns, manual pagination. **No virtualization.** No row selection state. No checkbox column. No `getRowId`-equivalent.

**Phase 4 implication — two paths:**
- **Path A (lighter):** Add a hand-rolled checkbox column + a local `Set<number>` of selected `finding.id` values. Selection lives alongside existing `useState` filter state. ~200 LOC addition.
- **Path B (larger):** Adopt `@tanstack/react-table` v8 in this initiative, refactor FindingsTable. ~600 LOC churn but pays dividends for future bulk actions, virtualization, column visibility menus.

**Recommendation:** Path A for this scope. The prompt's success criteria (checkbox column, tri-state header, persistence across filter changes) all map to plain React state. Adopting TanStack Table v8 is a tangential refactor and should be its own initiative.

### 1.2.2 RunBatchProgress (the CTA card)

**Source:** [RunBatchProgress.tsx](frontend/src/components/ai-fixes/RunBatchProgress/RunBatchProgress.tsx) (lines 117-270)

Component shape:
```tsx
export function RunBatchProgress({ runId, enabled = true }: RunBatchProgressProps) {
  const { data: progress } = useGlobalAiBatchProgress(runId, { enabled });
  const trigger = useTriggerAiFixes(runId);
  const cancel = useCancelAiFixes(runId);
  const isIdle = !progress || progress.status === 'complete' || ...;
  const { data: estimate } = useRunBatchEstimate(runId, { enabled: enabled && isIdle });
  // ... render idle CTA (lines 164-200) or in-flight banner (lines 206-269)
}
```

**Idle state count source:** `estimate?.findings_total` — pulled from the `/estimate` endpoint, which today returns `findings_total = ALL findings in run`. Not filter-aware.

**No props for filter state, no props for selection.** Phase 3 must extend the prop signature:
```tsx
interface RunBatchProgressProps {
  runId: number;
  enabled?: boolean;
  scope?: ScopeSpec;       // new — drives label, estimate refetch, generate body
}
```

### 1.2.3 Global progress banner — `AiBatchProgressProvider` + `GlobalAiBatchBanner`

**Provider source:** [AiBatchProgressProvider.tsx](frontend/src/components/ai-fixes/GlobalAiBatchProgress/AiBatchProgressProvider.tsx)

**Tracked state:** `useState<Set<number>>(() => new Set())` — **keyed by run_id only.** One EventSource per tracked run. `register(runId)` / `unregister(runId)`.

**Lifecycle:** Initial snapshot fetch → SSE subscribe → poll fallback on SSE error → 8s linger after terminal status before auto-unregister.

**Banner UI:** [GlobalAiBatchBanner.tsx](frontend/src/components/ai-fixes/GlobalAiBatchProgress/GlobalAiBatchBanner.tsx)
- `MAX_VISIBLE = 3` — additional rows collapse to "+N more"
- Per row: `Run #{runId}` link + summary line + progress bar + Cancel
- `aria-live="polite"` on each row (alert-level when failed)

**Multi-batch reality:** A second `register(42)` call when run 42 is already tracked is a no-op (Set semantics). The existing EventSource keeps streaming the SAME progress key — which today represents a SINGLE batch per run. **There is no "two banners for one run" today.** Prompt §2.4's claim "already supports multiple banners with overflow" is overstated: it supports multiple *runs*, not multiple *batches per run*.

**Phase 3-4 reshape needed:**
- `tracked: Set<number>` → `tracked: Map<string, BatchTrackingEntry>` keyed by `${runId}:${batchId}`
- Per-entry EventSource hits the new `/runs/{runId}/ai-fixes/batches/{batchId}/stream` endpoint
- `register(runId, batchId, scopeLabel)` / `unregister(runId, batchId)`
- Banner row label: `Run #{runId} · {scopeLabel}` (e.g., `Run #42 · Critical findings`)
- React Query cache key changes from `['ai-batch-progress', runId]` to `['ai-batch-progress', runId, batchId]`

This is a non-trivial provider refactor and should land in Phase 3 alongside the CTA filter wiring.

### 1.2.4 Filter state location

**Source:** [findingFilters.ts](frontend/src/lib/findingFilters.ts) (predicate + types) and [FindingFilterPanel.tsx](frontend/src/components/analysis/FindingFilterPanel.tsx) (the chip UI).

**Filter shape:**
```ts
interface FindingsFilterState {
  search: string;
  severityFilter: string;     // server-side query param
  sources: string[];          // client-side
  cvssMin: number; cvssMax: number;
  epssMinPct: number;
  kevOnly: boolean;
  hasFixOnly: boolean;
}
```

**Storage:** **Local React state inside `FindingsTable`** ([FindingsTable.tsx:259-262](frontend/src/components/analysis/FindingsTable.tsx#L259-L262)):
```tsx
const [filter, setFilter] = useState<FindingsFilterState>(() => ({
  ...DEFAULT_FILTERS,
  severityFilter,
}));
```
Not in URL params. Not in Zustand. Not in Context. Sibling components (including `RunBatchProgress`) cannot read it.

**Phase 3 lift required.** Three options:
- **Lift to page** (`analysis/[id]/page.tsx`) and prop-drill into both `FindingsTable` and `RunBatchProgress`. Simplest.
- **Page-scoped Context** (`FindingsFiltersContext`). More flexible if other siblings ever need it.
- **URL params via `useSearchParams`** — best for shareable URLs and persistence across nav, but requires more plumbing.

**Recommendation:** Lift to page (Option 1) for Phase 3. Add Context only if a third consumer appears. URL params are a separate UX initiative.

### 1.2.5 useFindings hook (or equivalent)

There is no dedicated hook. The query lives directly in [analysis/[id]/page.tsx:53-58](frontend/src/app/analysis/[id]/page.tsx#L53-L58):
```tsx
const { data: findingsData } = useQuery({
  queryKey: ['findings-enriched', id, severityFilter],
  queryFn: ({ signal }) => getAllEnrichedRunFindings(id, { severity: severityFilter || undefined }, signal),
  enabled: !isNaN(id),
});
```

**Filtering split:**
- Server-side: `severityFilter` only (query param)
- Client-side: kevOnly, hasFixOnly, sources, CVSS range, EPSS percentile, search — applied via `matchesFindingFilter()` predicate after fetch.

**Phase 3 implication:** The CTA card will compute the *visible* (post-client-filter) finding ID list to send to the estimate POST. This means we have two ways to drive the backend scope:

- **Send finding_ids** (computed client-side from the filtered list) — simplest, always exact, but the array can be ~500 ids. Fine over HTTP.
- **Send filter spec** (severities, kevOnly, etc.) for backend to re-resolve — requires backend duplication of client filter logic. Risk of divergence.

**Recommendation:** Always send `finding_ids` (Direction A). The backend `resolve_scope_findings()` keeps its filter logic for the case where the API is called from non-browser clients, but the frontend always sends ids. This avoids client/server filter drift, which is a real maintenance cost.

(This is a **deviation from prompt §2.1** which proposed sending filter specs from frontend. Flagging for owner gate.)

### 1.2.6 Estimate hook + API

**Hook:** [useAiCredentials.ts:196-207](frontend/src/hooks/useAiCredentials.ts#L196-L207)
```tsx
export function useRunBatchEstimate(runId: number | null, args: { enabled?: boolean } = {}) {
  return useQuery<AiBatchDurationEstimate>({
    queryKey: ['ai', 'run-batch-estimate', runId],
    queryFn: ({ signal }) => getRunBatchEstimate(runId as number, signal),
    enabled,
    staleTime: 30_000,
  });
}
```

**API client:** `getRunBatchEstimate(runId)` — GET, no body.

**Phase 2 changes:** Backend must add `POST /api/v1/runs/{run_id}/ai-fixes/estimate` with a `scope` body. Frontend hook becomes `useRunBatchEstimate(runId, scope, { debounceMs: 300 })`. Query key becomes `['ai', 'run-batch-estimate', runId, scopeKey(scope)]` where `scopeKey` is a stable hash of the scope spec.

### 1.2.7 Trigger generation hook

**Hook:** [useAiFix.ts:177-189](frontend/src/hooks/useAiFix.ts#L177-L189) — `useTriggerAiFixes(runId)`. Mutation body type `AiTriggerBatchRequest = { provider_name?, force_refresh?, budget_usd? }`. Phase 2 extends with `scope`, `scope_label`. Phase 3 extends `onSuccess` to register the new `batch_id` with the global provider (instead of just invalidating cache).

### 1.2.8 Run detail page composition

**Source:** [analysis/[id]/page.tsx:179-260](frontend/src/app/analysis/[id]/page.tsx#L179-L260)

Layout: `<RunBatchProgress />` is a **sibling** of `<FindingsTable />`, both nested under the page-level `<div>`. Lifting filter + selection state to this page level is straightforward — no architectural rework, just pull the `useState` calls up and prop-drill.

### 1.2.9 Test infrastructure

- **Vitest** v4.1.2 wired (`vitest.config.ts`).
- **vitest-axe** v0.1.0 used for a11y assertions (`AiFixSection.axe.test.tsx`).
- **Playwright: NOT PRESENT.** No `playwright.config.ts`, no `e2e/` directory. Prompt's references to "E2E Playwright" must either:
  - Add Playwright as part of Phase 5 (separate effort, ~1 day to wire), or
  - Replace E2E scenarios with Vitest + Testing Library + MSW for mocked-API integration tests.

**Recommendation:** Use Vitest + MSW for the integration scenarios in Phases 3-4 (faster, runs in CI as-is). Defer Playwright to a separate initiative — it's a tooling decision, not a feature requirement.

---

## 1.3 Open questions for the Phase 1 gate

These need an owner decision before Phase 2 begins. None block the audit; all affect implementation scope.

1. **Lock substrate for cache contention.** Redis (proposed) vs. Postgres advisory lock. Redis matches existing infra; Postgres avoids any new dependency. **Recommend Redis.**
2. **Frontend scope wire format.** Send resolved `finding_ids[]` vs. send filter spec for backend re-resolution. The prompt assumed filter spec; I recommend `finding_ids[]` to avoid client/server filter drift. The backend `resolve_scope_findings()` keeps both code paths for non-browser API clients.
3. **TanStack Table adoption.** Path A (hand-rolled selection ~200 LOC, this scope) vs. Path B (TanStack v8 refactor, +1 week, separate initiative). **Recommend Path A.**
4. **Estimate endpoint p95 < 200ms target.** Achievable only by replacing per-finding grounding with a single SQL join (sketched above). This sidesteps `build_grounding_context` for the estimate path. Acceptable? (Cache key dimensions match finding columns directly today — verified — so the join is exact.)
5. **Provider rate limit cross-process.** Current per-process singleton means N workers × configured RPM. For Gemini free tier (15 RPM) on a 4-worker production deploy this is effectively 60 RPM and would breach the provider's actual limit. **Recommend** out-of-scope-for-this-feature flag for a future Redis-backed token bucket, but document the limitation in the runbook.
6. **E2E framework.** Vitest + MSW vs. add Playwright in Phase 5. **Recommend Vitest + MSW** for this feature; track Playwright separately.
7. **Progress provider refactor placement.** The shift from `Set<number>` keyed-by-runId to `Map<string, Entry>` keyed-by-`runId:batchId` is the largest single frontend change. It can land in Phase 3 (alongside CTA wiring) or be split into its own pre-Phase-3 step. **Recommend Phase 3** (one PR, less coordination overhead) but flag if owner wants it isolated for safer review.

---

## 1.4 Phase 2 plan preview (for context, not for execution)

When the gate clears, Phase 2 will deliver:

- Migration `011_ai_fix_batch.py` creating `ai_fix_batch(id UUID PK, run_id, status, scope_label, scope_json, finding_ids INT[], totals, started/completed timestamps)`.
- `AiFixGenerationScope` Pydantic model + `resolve_scope_findings()` helper, with security tests proving `run_id` is always intersected even when `finding_ids` is supplied.
- `BatchProgress.batch_id` field + Redis key migration to `ai:fix:progress:{run_id}:{batch_id}`.
- Per-`(run_id, batch_id)` cancel keys.
- New endpoints: list batches, get batch detail, batch-scoped SSE stream, batch-scoped cancel.
- Existing `/runs/{run_id}/ai-fixes` paths kept as deprecated aliases that fan out to the most-recent batch.
- New `POST /runs/{run_id}/ai-fixes/estimate` accepting a scope; SQL-only join path for sub-200ms.
- Redis lock around `ai_fix_gen:{cache_key}` with 30s timeout + post-acquire cache re-check.
- Per-run concurrency cap (3 active batches) with typed 409 response.
- Tests: parallel-batch cache-overlap correctness (the trickiest invariant), 4th-batch 409, cancel-isolation, security run_id intersection.

---

**End of Phase 1 audit.**
