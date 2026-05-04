# Runbook — AI fix generator

> Audience: on-call SRE / platform engineer.
> Companion to [docs/features/ai-fixes.md](features/ai-fixes.md).

This runbook covers the operational levers, telemetry, and incident
response for the AI-driven remediation feature (Phases 1-5).

---

## 1. Quick reference

| Knob | Where | Default | Effect |
|---|---|---|---|
| `AI_FIXES_ENABLED` | env → `Settings.ai_fixes_enabled` | `false` | Master flag. `false` hides every AI surface; clients see `409 AI_FIXES_DISABLED` from triggers. |
| `AI_FIXES_KILL_SWITCH` | env → `Settings.ai_fixes_kill_switch` | `false` | Operator panic button. Overrides `AI_FIXES_ENABLED` regardless. Returns `409 AI_FIXES_KILL_SWITCH`. |
| `AI_DEFAULT_PROVIDER` | env, str | `anthropic` | Provider name used when a request omits the override. Must appear in `AI_PROVIDERS`. |
| `AI_PROVIDERS` | env, csv | `anthropic,openai,ollama,vllm` | Comma-separated allowlist. Disabled providers still surface in `/api/v1/ai/providers` with `available=false`. |
| `ANTHROPIC_API_KEY` | env, secret | unset | Required for Anthropic. Without it the registry reports the provider as unavailable. |
| `OPENAI_API_KEY` | env, secret | unset | Same shape for OpenAI. |
| `OLLAMA_BASE_URL` | env | `http://localhost:11434` | Local Ollama endpoint. Empty disables. |
| `VLLM_BASE_URL` | env | unset | Self-hosted vLLM endpoint. Empty disables. |
| `AI_BUDGET_PER_REQUEST_USD` | env, float | `0.10` | Max single-call cost. Estimate exceeding cap → 402-style structured error. |
| `AI_BUDGET_PER_SCAN_USD` | env, float | `5.00` | Max cumulative cost in one batch run. Hit → status flips to `paused_budget`. |
| `AI_BUDGET_PER_DAY_ORG_USD` | env, float | `50.00` | Daily org-wide cap. Resets at UTC midnight. |
| `AI_<PROVIDER>_MODEL` | env, str | provider-specific | Default model per provider (`AI_ANTHROPIC_MODEL=claude-sonnet-4-5`). |
| `AI_<PROVIDER>_MAX_CONCURRENT` | env, int | 8-32 | Bounded `asyncio.Semaphore` size in the batch pipeline. |
| `AI_<PROVIDER>_RPM` | env, float | provider-specific | Token-bucket rate limit (requests / minute). |

All settings live in [`app/settings.py`](../app/settings.py) under the
`# AI-driven remediation` block. Pydantic env-var names are
upper-snake-case (the field name uppercased).

---

## 2. Telemetry endpoints

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/ai/usage` | Aggregate spend, cache-hit ratio, daily headroom. Powers the Settings tile. |
| `GET /api/v1/ai/usage/trend?days=N` | Per-day cost / call / cache-hit series. `N` ∈ [1, 180]. Powers the dashboard sparkline. |
| `GET /api/v1/ai/usage/top-cached?limit=N` | N most expensive cached fix bundles. `N` ∈ [1, 100]. |
| `GET /api/v1/ai/metrics` | JSON snapshot of every counter / histogram / gauge. |
| `GET /api/v1/ai/metrics/prometheus` | Prometheus text exposition format — point your scraper here. |
| `GET /api/v1/ai/providers` | Provider list + which are available. Read by the Settings page. |
| `GET /api/v1/ai/pricing` | Static pricing table (per-1k-token rates). |
| `POST /api/v1/ai/registry/reset` | Drop the cached provider registry. Picks up env / DB config changes without restart. |

Operator-facing dashboards live at:

* `/settings#ai` — read-only configuration view.
* `/admin/ai-usage` — cost trend, top-N expensive fixes, breakdowns.

---

## 3. Metric reference

These are the metrics emitted by the generator (see
[`app/ai/observability.py`](../app/ai/observability.py)):

| Metric | Type | Labels | What it tracks |
|---|---|---|---|
| `ai_request_total` | counter | `provider`, `purpose`, `outcome` | Every LLM call (success / failure / `cache_hit`). |
| `ai_request_latency_seconds` | histogram | `provider`, `purpose`, `model` | Wall-clock latency of provider calls. |
| `ai_cost_usd_total` | counter | `provider`, `purpose` | Cumulative USD spent. Cache hits don't increment. |
| `ai_cache_hit_ratio` | gauge | — | Last batch's hit ratio (most recently completed run). |
| `ai_budget_remaining_daily_usd` | gauge | — | Headroom on the daily org cap. |
| `ai_batch_finding_latency_seconds` | histogram | — | Per-finding latency in batch runs (Phase 3 throughput tracking). |

Each ledger row also lands in `ai_usage_log` (Postgres / SQLite); the
metrics surface aggregates for fast scrape, the table is the durable
record for billing reconciliation.

---

## 4. Common incidents

### 4.1 "Costs spiked overnight"

1. Open `/admin/ai-usage`. The 30-day trend sparkline shows the spike date.
2. Filter by purpose: `GET /api/v1/ai/usage` → `by_purpose` array.
3. If a single CVE / component shows up disproportionately, check
   `top-cached` — the most-expensive bundles often catch a regression
   in prompt engineering (large grounding contexts).
4. **Containment**: `export AI_FIXES_KILL_SWITCH=true` and restart the
   API. New calls return `409`; in-flight Celery tasks finish.
5. **Recovery**: drop the cap with `AI_BUDGET_PER_DAY_ORG_USD=5` and
   un-kill (`AI_FIXES_KILL_SWITCH=false`). Investigate prompt size.

### 4.2 "Provider is down"

1. Check `GET /api/v1/ai/providers`. The affected provider shows
   `available=false` if its credentials are missing; otherwise check
   the last `provider_unavailable` errors in `ai_usage_log`:
   ```sql
   SELECT created_at, provider, error
   FROM ai_usage_log
   WHERE error LIKE '%provider_error%'
   ORDER BY created_at DESC
   LIMIT 20;
   ```
2. The circuit breaker opens after **5 consecutive failures** per
   provider (configurable via `AI_<PROVIDER>_BREAKER_THRESHOLD` if you
   added one — defaults are hardcoded today). It half-opens 60s later.
3. **Containment**: switch the default provider:
   ```bash
   export AI_DEFAULT_PROVIDER=openai  # or whichever fallback is hot
   curl -X POST http://api/api/v1/ai/registry/reset
   ```

### 4.3 "Batch is stuck at paused_budget"

1. The batch hit either the per-scan cap (`AI_BUDGET_PER_SCAN_USD`) or
   the daily cap (`AI_BUDGET_PER_DAY_ORG_USD`).
2. Check which: open the run page; the banner shows "Daily AI budget
   reached" (daily cap) vs "Paused at budget cap" (per-scan).
3. **Resume**: raise the relevant cap, then trigger again. The
   force-refresh option is **not** needed — the cache absorbs everything
   that completed in the previous run, so the next attempt continues
   roughly where the prior one stopped.

### 4.4 "Schema parse failures climbing"

1. Look at `ai_request_total{outcome="schema_parse_failed"}` in Prometheus
   or `/api/v1/ai/metrics`.
2. The orchestrator retries once with a stricter prompt; persistent
   failures usually mean either a model-side regression or a prompt
   that's confused the model with an over-large grounding context.
3. **Containment**: bump `PROMPT_VERSION` in
   [`app/ai/prompts/__init__.py`](../app/ai/prompts/__init__.py) and
   redeploy with a tightened user prompt. Bumping invalidates every
   `ai_fix_cache` row, so plan for the cold-cache cost.

---

## 5. Logging

Every AI call writes one structured log entry under the
`sbom.ai.audit` logger (see
[`app/ai/observability.py:log_ai_call`](../app/ai/observability.py)).
The entry contains:

* `request_id`, `provider`, `model`, `purpose`, `finding_cache_key`
* `input_tokens`, `output_tokens`, `cost_usd`, `latency_ms`
* `cache_hit`, `outcome`
* `response_sha256` + `response_bytes` — SHA-256 of the response body.
  **The body itself is never logged** (Phase 5 §5.2 hard rule). Joining
  with provider audit logs goes via the hash.
* `error` — first 240 chars of the failure message, when present.

To grep for a specific finding's history:

```bash
# Find every entry (cache hits + misses + failures) for one cache key.
journalctl -u sbom-api | jq 'select(.finding_cache_key == "abc123")'
```

---

## 6. Prompt-version & schema-version invariants

* `PROMPT_VERSION` participates in the cache key. Bumping it forces
  every entry to regenerate on next read. Plan a budget bump alongside.
* `SCHEMA_VERSION` (in
  [`app/ai/schemas.py`](../app/ai/schemas.py)) gates cache row
  validity. Mismatched rows are treated as misses (read returns
  `None`); they're not deleted, so a roll-back to the old schema
  version recovers the cache.
* `ai_fix_cache.expires_at` is enforced on read, so even rows skipped
  by schema-version mismatch eventually fall out of the table when
  another row with the same key is written.

---

## 7. Rollout checklist (mirrors prompt §6)

1. Default-off in production (`AI_FIXES_ENABLED=false`).
2. Internal-only enable for the org's own SBOMs.
3. Daily cap defaults to **$5 (not $50)** for the first 14 days.
4. Watch `ai_request_total{outcome="provider_error"}` for elevated
   failure rates; investigate before raising caps.
5. Verify `/admin/ai-usage` populates correctly after the first batch
   completes.
6. Per-tenant enable via the future `org.ai_fixes_enabled` toggle (not
   shipped in Phase 5; tracked as F-2 follow-up).
7. Canary 10% → 50% → 100%.
8. Kill-switch dry-run: set `AI_FIXES_KILL_SWITCH=true`, confirm UI
   shows the kill-switch banner and triggers return `409`, then unset.

---

## 8. Known limitations

* **In-memory metrics registry.** Counters reset on process restart.
  The DB ledger (`ai_usage_log`) is the authoritative source for
  long-running aggregates; metrics serve fast scrape windows.
* **In-memory progress store fallback.** When Redis is unreachable, the
  progress endpoint returns process-local data — fine for single-node
  dev, wrong for multi-process production. Make sure Redis is healthy
  before enabling AI fixes in prod (`/health` should report Redis up).
* **OpenTelemetry is opt-in.** `app/ai/observability.py` soft-imports
  `opentelemetry`; spans are only emitted when the SDK is installed in
  the environment. No-op otherwise.
* **No per-tenant budget caps.** Caps are org-wide only. Per-tenant is
  Phase 6 scope.

---

## 9. Useful queries

```sql
-- Today's spend by purpose, ordered.
SELECT purpose, ROUND(SUM(cost_usd), 4) AS cost, COUNT(*) AS calls
FROM ai_usage_log
WHERE created_at >= date('now', 'start of day')
GROUP BY purpose
ORDER BY cost DESC;

-- Cache effectiveness in the last 7 days.
SELECT
  ROUND(SUM(CASE WHEN cache_hit THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) AS hit_pct,
  COUNT(*) AS total
FROM ai_usage_log
WHERE created_at >= date('now', '-7 day');

-- Top 10 most-expensive cache rows.
SELECT vuln_id, component_name, component_version, total_cost_usd
FROM ai_fix_cache
ORDER BY total_cost_usd DESC
LIMIT 10;
```
