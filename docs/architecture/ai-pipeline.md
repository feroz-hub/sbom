# Architecture — AI fix pipeline

> Audience: engineers extending or debugging the AI surface.
> Operator runbook: [docs/runbook-ai-fixes.md](../runbook-ai-fixes.md).
> User docs: [docs/features/ai-fixes.md](../features/ai-fixes.md).

This document is the engineer-facing tour of how the AI fix generator
is built, why each layer exists, and where to add code when extending.

---

## 1. High-level layout

```
┌────────────────────────────┐
│  React UI                  │   /admin/ai-usage  ·  /settings#ai
│    AiFixSection            │   CveDetailDialog
│    RunBatchProgress        │   /analysis/[id]
│    CostDashboard           │
└─────────────┬──────────────┘
              │ TanStack Query  ·  EventSource (SSE)
┌─────────────▼──────────────┐
│  FastAPI (app/routers)     │
│    /api/v1/findings/.../ai-fix       single-finding entry
│    /api/v1/runs/.../ai-fixes         batch trigger / progress / cancel / stream
│    /api/v1/ai/usage|metrics|trend    telemetry surface
└─────────────┬──────────────┘
              │ rollout gate (kill switch → master flag → canary %)
┌─────────────▼──────────────┐
│  app/ai/                   │
│    fix_generator.py  ─── orchestrator + parse + post-validate
│    batch.py          ─── async pipeline + concurrency + cancel
│    cache.py          ─── ai_fix_cache R/W + TTL bucketing
│    cost.py           ─── pricing table + BudgetGuard
│    grounding.py      ─── GroundingContext builder
│    schemas.py        ─── output Pydantic models (3 + bundle)
│    prompts/          ─── v1.system.txt · v1.user.txt
│    progress.py       ─── Redis or in-memory progress store
│    observability.py  ─── counters / histograms / gauges
│    config_loader.py  ─── DB-first EffectiveAiConfig + selected model
│    model_registry.py ─── discovery lifecycle, model test, selection
│    model_resolver.py ─── one runtime model-resolution path
│    runtime_config.py ─── shared gates/budgets
│    provider_factory.py ─ one runtime/Test Connection factory
│    rollout.py        ─── global policy + Fix-only canary sampling
│    registry.py       ─── exact credential selection + one fallback
│    providers/        ─── all eight catalog providers
└─────────────┬──────────────┘
              │ httpx.AsyncClient (shared)
┌─────────────▼──────────────┐
│  Provider HTTP API         │   Anthropic Messages · OpenAI Chat · Ollama · vLLM
└────────────────────────────┘
```

Persistent AI state lives in five tables:

* `ai_usage_log` — append-only audit ledger. One row per LLM call
  (success, failure, cache hit). Powers `/api/v1/ai/usage*` aggregates.
* `ai_fix_cache` — generated bundles, keyed by
  `sha256(vuln_id|component_name|component_version|prompt_version)`.
  Tenant-shared by design (Phase 2 §2.4).
* `ai_settings` — authoritative master enabled state, global kill switch,
  and three budget caps.
* `ai_provider_credential` — labelled encrypted credentials plus exact
  default/fallback selection and provider-specific runtime fields.
* `ai_provider_model` — historical, credential-scoped discovered models,
  provider/runtime IDs, tri-state capabilities, availability, test state, and
  the one explicit active selection.

---

## 2. Request shapes

### 2.1 Single finding (CVE detail modal)

```
GET /api/v1/findings/{id}/ai-fix
       │
       ▼
_require_ai_enabled(rollout_key=f"finding:{id}")
       │
       ▼
AiFixGenerator.generate_for_finding(finding)
       │
   build_grounding_context(finding, db)
       │
   make_cache_key(vuln, comp, ver)
       │
   cache.read_cache(key) ──────────► hit:   touch + log + return AiFixResult(cache_hit=True)
       │ miss
       ▼
   provider = registry.get_default()
   budget.check_request(estimated_cost)
   provider.generate(LlmRequest)
       │
   _parse_bundle (one retry on schema parse failure)
   _post_validate (flips tested_against_data, demotes actively_exploited, prunes citations)
       │
   budget.record(actual_cost)
   write_usage_log_row + record_call (telemetry) + log_ai_call (audit)
   cache.write_cache + return AiFixResult(cache_hit=False)
```

### 2.2 Run batch (Celery task)

```
POST /api/v1/runs/{id}/ai-fixes
       │
   _require_ai_enabled(rollout_key=f"run:{id}")
   ai_fix_tasks.generate_run_fixes.apply_async(...)
       │
       └──► Celery worker
              │
              asyncio.run(AiFixBatchPipeline(db).run(run_id))
                    │
                _load_findings(run_id)
                _partition_cache_hits → (misses, hit_results)
                progress.write(initial state)
                       │
                async with Semaphore(provider.max_concurrent):
                    for f in misses:
                        AiFixGenerator.generate_for_finding(f, scan_id=run_id)
                        progress.write(updated)
                       │
                update_cache_hit_ratio gauge
                progress.write(terminal)
```

The frontend reads progress via same-origin BFF SSE
(`/runs/{id}/ai-fixes/stream`) with 2s polling fallback. Native EventSource
cannot attach `X-Tenant-ID`, so the non-secret active tenant id is mirrored to
a strict same-site cookie and converted to the normal header by `/api/backend`.
The bearer remains in the server-side session and never enters a URL.

---

## 3. Layer responsibilities

| Layer | Responsibility | Owns |
|---|---|---|
| **Router** (`app/routers/ai_fixes.py`, `ai_usage.py`) | HTTP shaping, auth, rollout gate, error → status code mapping | Zero LLM code |
| **Rollout** (`app/ai/rollout.py`) | Kill switch / master flag / canary sampling | One pure function: `evaluate_access(rollout_key)` |
| **Pipeline** (`app/ai/batch.py`) | Async fan-out, semaphore, cancel, progress | Concurrency primitives only |
| **Orchestrator** (`app/ai/fix_generator.py`) | Per-finding flow, parse, post-validate, ledger | Decides cache vs provider |
| **Provider** (`app/ai/providers/*.py`) | HTTP, retry, circuit breaker, token-bucket | Provider-specific request body shape |
| **Registry** (`app/ai/registry.py`) | Lazy provider construction | Resolves env / DB config → instances |
| **Config loader** (`app/ai/config_loader.py`) | Canonical DB-first controls and exact credentials | Source precedence + cross-process version invalidation |
| **Provider factory** (`app/ai/provider_factory.py`) | Shared validation/construction | Runtime and Test Connection cannot drift |
| **Cache** (`app/ai/cache.py`) | Cache-key + TTL + R/W | Pure functions on `ai_fix_cache` |
| **Cost** (`app/ai/cost.py`) | Pricing table + `BudgetGuard` | Pre-flight + post-flight cost accounting |
| **Grounding** (`app/ai/grounding.py`) | Build the model's view of the world | Reads `cve_cache` / KEV / EPSS |
| **Schemas** (`app/ai/schemas.py`) | Pydantic output bundle | First line of hallucination defense |
| **Prompts** (`app/ai/prompts/`) | System + user templates | Version-pinned text files |
| **Observability** (`app/ai/observability.py`) | Counters / histograms / gauges, structured logger, OTel shim | One in-process registry |
| **Progress** (`app/ai/progress.py`) | Redis / in-memory store | Cross-process state for batch runs |

The dependency graph is intentionally one-way. The router doesn't import
provider classes. The pipeline doesn't import HTTP. The orchestrator
doesn't know about Celery. Test coverage stays sane because unit tests
can mock at the right boundary.

### Effective configuration and authorization

`EffectiveAiConfig` is the sole runtime source for feature enabled, kill
switch, and three budget caps. A DB settings row wins; env is used only when
the row is absent or DB access is unavailable. The presence of any DB
credential row for a provider suppresses its env counterpart even when the DB
row is disabled or cannot decrypt. Routing metadata (`credential_id`, label,
default, fallback) is separate from provider HTTP configuration, so it cannot
leak into fields such as `OpenAI-Organization`.

Every external invocation rechecks the common policy. AI Fixes additionally
apply the environment-controlled canary; Copilot and validation repair do not,
but both still obey the global feature flag and kill switch. Budget guards use
the canonical caps and a SQLAlchemy session factory, reconciling the durable
ledger before calls across API and worker processes.

Fallback is one attempt only and is limited to network/outage, rate/quota,
upstream 5xx, and open-circuit failures. Deterministic auth, model, request,
schema, grounding, budget, and configuration errors return directly.

---

## 4. Hallucination defense — three layers

The system enforces "no invented fix versions" at three levels, in order:

1. **Schema** (Pydantic) — `Literal` types reject `priority="asap"` or
   `exploitation_likelihood="imminent"` at parse time.
2. **Prompt** (`v1.system.txt`) — explicit hard rules forbid invented
   versions and unsupported sources.
3. **Post-validation** (`_post_validate`) — even if the model passes
   schema + ignores prompt rules, the orchestrator demotes the result:
   * `target_version` not in `ctx.fix_versions` → flip
     `tested_against_data=False` + `breaking_change_risk="unknown"`.
   * `exploitation_likelihood="actively_exploited"` without KEV → demote
     to `"high"`.
   * Citations referencing sources not in `ctx.sources_used` → pruned.

The post-validation step keeps the model's suggestion (so the UI can
show it with an "⚠ Inferred" caveat) but flips the bit so downstream
tooling treats it as low-confidence.

---

## 5. Provider abstraction

Every concrete provider implements `LlmProvider` (Protocol) in
`app/ai/providers/base.py`:

```python
class LlmProvider(Protocol):
    name: str
    default_model: str
    is_local: bool
    max_concurrent: int

    async def generate(self, req: LlmRequest) -> LlmResponse: ...
    async def list_models(self) -> list[DiscoveredModel]: ...
    async def health_check(self) -> bool: ...
    def info(self) -> ProviderInfo: ...
```

Adding a new provider is **one file**:

1. Create `app/ai/providers/myprovider.py` with a class implementing
   `LlmProvider` (talk to its HTTP API via the shared `httpx.AsyncClient`).
2. Add an entry to `PRICING` in `app/ai/cost.py` if the provider charges.
3. Wire it into `ProviderRegistry._build_provider` in
   `app/ai/registry.py`.
4. Add the env-var fields to `Settings` and the registry's
   `build_configs_from_settings`.

No router / orchestrator / pipeline / test changes required. The
abstraction enforces this — `app/ai/fix_generator.py` only imports
from `app/ai/providers/base`.

### Model discovery lifecycle

Manual refresh is exposed under
`/api/v1/ai/credentials/{credential_id}/models`; Celery Beat also runs
`ai_models.refresh_all` daily at 04:10 UTC. A successful refresh upserts by
`(provider_credential_id, provider_model_id)`, updates returned models, and
marks missing models unavailable without deletion. A failed refresh performs
no availability changes and cannot replace or disable the selected model.

Raw provider payloads are not persisted wholesale. Adapters allow-list useful
metadata and the registry removes secret-like keys and caps the serialized
size. Custom OpenAI-compatible discovery reuses the exact base URL that passed
the existing HTTPS/localhost validation.

---

## 6. Cache key invariants

```python
make_cache_key(vuln_id, component_name, component_version, prompt_version)
    = sha256(strip().lower() join "|")
```

* **Tenant-shared**: no `org_id` / `user_id` / `scan_id` — the AI advice
  for `(CVE, package, version)` is the same regardless of who asks.
* **Prompt-version-pinned**: bumping `PROMPT_VERSION` (in
  `app/ai/prompts/__init__.py`) invalidates every entry on next read.
* **Schema-version-pinned**: `SCHEMA_VERSION` mismatch on read returns
  `None` (treated as a miss); rows are not deleted, so a roll-back to
  the old schema version recovers the cache.

TTL is enforced at upsert:

| Class | TTL |
|---|---|
| KEV-listed CVE | 7 days |
| Non-KEV | 30 days |
| Negative cache (LLM failure) | 1 hour (Phase 7 follow-up) |

---

## 7. Concurrency model

* **Cloud providers** (Anthropic / OpenAI / vLLM) are network-bound:
  one `asyncio.Semaphore` per provider, sized to the provider's tier
  limit (10 / 20 / 32 default). Token-bucket `RateLimiter` per provider
  guards against burst-induced rate-limit responses.
* **Local providers** (Ollama) are GPU/CPU-bound: smaller semaphore (8
  default) because over-saturating local inference creates head-of-line
  blocking.
* The batch pipeline creates a fresh semaphore per `pipeline.run()`
  call so concurrent batches on different runs each get their own
  bound (no global pool starvation).

The orchestrator's per-finding work runs serially within each
semaphore acquisition: `provider.generate` → parse → post-validate →
cache write.

---

## 8. Observability glossary

| Metric | Type | Where it's emitted |
|---|---|---|
| `ai_request_total` | counter | `record_call` after every LLM call |
| `ai_request_latency_seconds` | histogram | `record_call` |
| `ai_cost_usd_total` | counter | `record_call` (cache hits skip) |
| `ai_cache_hit_ratio` | gauge | Pipeline completion |
| `ai_budget_remaining_daily_usd` | gauge | `BudgetGuard.record` |

See [docs/runbook-ai-fixes.md §3](../runbook-ai-fixes.md) for incident
playbooks that consume these.

---

## 9. Testing strategy

* **Provider tests** (`tests/ai/test_providers.py`) — `httpx.MockTransport`
  scripts upstream responses; no real network.
* **Orchestrator tests** (`tests/ai/test_fix_generator.py`) — `FakeProvider`
  returns canned bundles; covers cache miss/hit, force-refresh, all
  three post-validation rules, parse retry, kill switch, error → AiFixError.
* **Pipeline tests** (`tests/ai/test_batch_pipeline.py`) — full / partial
  cache, budget halt, provider failure isolation, cancel mid-flight.
* **Load test** (`tests/ai/test_batch_load.py`) — 1,000 findings end-to-end
  asserts throughput + cache rows + zero LLM calls on warm-cache pass.
* **Telemetry tests** (`tests/ai/test_observability.py`) — verifies
  the response body never appears in logs (load-bearing security test).
* **Frontend tests** (`frontend/src/components/ai-fixes/__tests__/`) —
  empty / loading / cached / error / disabled states + axe.
* **Verification script** (`scripts/verify_ai_rollout.py`) — runs every
  rollout gate combination + the live router.

---

## 10. Where to add code

| Want to … | Edit |
|---|---|
| Add a provider | `app/ai/providers/<name>.py` + registry + Settings |
| Update model pricing | `PRICING` in `app/ai/cost.py` (quarterly) |
| Tighten the prompt | `app/ai/prompts/v1.user.txt` + bump `PROMPT_VERSION` |
| Add a new field to the AI bundle | `app/ai/schemas.py` + bump `SCHEMA_VERSION` + frontend types |
| Add a new metric | `record_call` (or a new helper) in `app/ai/observability.py` |
| Lower daily cap during incident | `AI_BUDGET_PER_DAY_ORG_USD` env var |
| Disable a misbehaving provider | `AI_PROVIDERS` env var (drop from list) |
| Halt all AI immediately | Settings -> AI kill switch (env fallback only before DB migration) |
| Roll back UI surface | `AI_FIXES_ENABLED=false` |
| Pause for canary cohort only | `AI_CANARY_PERCENTAGE=10` (then 50, 100) |

---

## 11. Out of scope (tracked follow-ups)

* **F-1**: generated unified-diff PRs against user repos (was prompt
  Interpretation C — rejected for v1).
* **F-2**: per-tenant settings (org-level `ai_fixes_enabled`). Currently
  org-wide via env.
* **F-3**: negative cache (1h TTL on failed generations).
* **F-4**: streaming token-by-token display in UI.
* **F-5**: per-finding cost-cap override.
