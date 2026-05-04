# Rollout playbook — AI fix generator

> Audience: release manager + on-call SRE.
> Operator runbook: [docs/runbook-ai-fixes.md](runbook-ai-fixes.md)
> Architecture: [docs/architecture/ai-pipeline.md](architecture/ai-pipeline.md)

This playbook covers the staged rollout of the AI fix generator from
internal-only to 100% canary. It is the source of truth for the
sequence operators follow when shipping the feature to a deployment.

---

## 0. Pre-flight (before any tenant sees AI)

Before flipping `AI_FIXES_ENABLED=true` for the first time:

| Item | Where | Confirm |
|---|---|---|
| Default provider has API key | env (`ANTHROPIC_API_KEY` or peers) | `GET /api/v1/ai/providers` returns the configured provider with `available=true` |
| Redis is reachable | env (`REDIS_URL`) | `/health` returns Redis up; in-memory fallback is unsafe in multi-process deployments |
| Celery worker is running | infra | `celery -A app.workers.celery_app worker -l info` shows `ai_fix.generate_run_fixes` registered |
| Database migrations are applied | infra | `alembic current` shows `009_ai_fix_cache` (head) |
| Verification script passes | local | `python scripts/verify_ai_rollout.py --pretty` reports 9/9 |

---

## 1. Phased ramp

Each phase has an explicit gate; the next phase is only entered after
the gate's success criteria are met.

### Phase A — Internal-only (Day 0)

```bash
export AI_FIXES_ENABLED=true
export AI_FIXES_KILL_SWITCH=false
export AI_CANARY_PERCENTAGE=0          # blocks every external request
export AI_BUDGET_PER_DAY_ORG_USD=5     # tight cap during shake-out
```

Internal admin tools that don't pass a `rollout_key` still work
(see `app/ai/rollout.py` — no key + master flag on = allowed). External
clients (the run-detail page + CVE modal) pass the key and are gated
out by the 0% canary.

**Operator actions during Phase A:**

1. Run [`scripts/ai_fix_smoke.py`](../scripts/ai_fix_smoke.py) against a
   staging deployment and your real provider key. Confirm five
   canonical outputs match Phase 2 §8 quality bar.
2. Trigger one batch on a small (< 50 finding) staging run. Confirm
   the banner reports cache hits + cost + provider correctly.
3. Open `/admin/ai-usage`. Confirm trend sparkline appears after the
   batch completes.
4. Open `/api/v1/ai/metrics/prometheus`. Confirm
   `ai_request_total{outcome="ok"}` reflects the smoke calls.

**Gate to Phase B:**
* Smoke outputs reviewed and quality-accepted.
* `ai_request_total{outcome="provider_error"}` is 0.
* No PII observed in audit logs (response body must never appear).

---

### Phase B — Canary 10% (Day 1-3)

```bash
export AI_CANARY_PERCENTAGE=10
```

10% of `(run_id, finding_id)` keys are routed to AI; the other 90%
return `409 AI_FIXES_CANARY_EXCLUDED`. The deterministic hash means
each user sees the same answer for the same key on every page load —
no flickering.

**Operator actions during Phase B:**

1. Watch `/admin/ai-usage` daily. Specifically:
   * Cache hit ratio should climb each day as the cache warms.
   * Daily spend should plateau under the $5 cap.
   * No outcomes other than `ok`, `cache_hit`, `provider_error`
     (occasional) should appear.
2. Watch `ai_request_total{outcome="schema_parse_failed"}`. Anything
   above ~1% of calls means a prompt regression — investigate before
   ramping.

**Gate to Phase C:**
* 14 cumulative days of clean telemetry across phases A + B.
* Cost projection (below) for the broader cohort doesn't exceed
  Finance's monthly approval.
* Cache hit ratio ≥ 50% (proves dedup is working at this scale).

---

### Phase C — Canary 50% (Day 4-7)

```bash
export AI_CANARY_PERCENTAGE=50
export AI_BUDGET_PER_DAY_ORG_USD=20    # raise cap as cohort grows
```

The canary ramp is **additive**: every key in the 10% cohort stays in
the 50% cohort (verified by `scripts/verify_ai_rollout.py` →
`canary ramp 10→50 is additive`).

**Gate to Phase D:**
* p95 cold-cache generation < 8s (Phase 1 §4.2 soft target).
* Daily spend trend extrapolates to under $50/month at 100%.
* Cache hit ratio ≥ 70% (Phase 1 §4.2 target).

---

### Phase D — General availability (Day 8+)

```bash
export AI_CANARY_PERCENTAGE=100
export AI_BUDGET_PER_DAY_ORG_USD=50
```

Every eligible request goes to AI. The canary gate becomes a no-op (it
short-circuits to `allowed` when `pct >= 100`).

**Gate to "feature is mature":**
* 30 days of clean telemetry.
* No incidents requiring kill switch.
* User satisfaction signal (per the Phase 4 §4.5 owner gate) shows
  net positive on AI vs no-AI sessions.

---

## 2. Cost projection

Based on Phase 5 telemetry from staging + the Phase 2 smoke script
runs. Cost-per-finding varies with grounding context size; the model
below uses the staging average of **$0.0042 per cold-cache call** at
`claude-sonnet-4-5` with the v1 prompt (~700 input tokens + ~600
output tokens).

### Per-active-user model

Assumptions:

* Active user runs a scan **2x per week**.
* Average scan: **400 findings**.
* Steady-state cache hit ratio: **80%** (≈ 20% net-new).
* No batch retries, no force refreshes.

→ ~80 cold-cache LLM calls per scan × 2 scans/week = ~160 calls/user/week.
→ ~$0.67 per user per week = **~$2.90 per user per month**.

### Aggregate scenarios

| Active users | Monthly cold-cache calls | Monthly cost (Anthropic Sonnet) | Monthly cost (OpenAI gpt-4o-mini, ~6× cheaper) |
|---|---|---|---|
| 10 | ~6,400 | ~$30 | ~$5 |
| 100 | ~64,000 | ~$290 | ~$50 |
| 1,000 | ~640,000 | ~$2,900 | ~$500 |

**Caveats:**

* The hit ratio at scale is *better* than 80% because the cache is
  tenant-shared. Two orgs both scanning a Spring Boot stack share most
  of the heavy CVEs. Realistic ratios at 1,000-user scale: 90-95%.
* New users carry a one-time onboarding cost (cold cache against
  their first 1-2 scans). If you see a $20-100 spike on a new user's
  first day, that's onboarding — not a regression.
* Force-refresh circumvents the cache — a single user clicking
  "Regenerate" 100 times is a $5+ event. Daily cap protects you.

### Provider switching for cost

The default provider is configured per deployment, but a single env
flip swaps it. If the bill is hot, switch to:

* `gpt-4o-mini` (~6× cheaper than Sonnet at v1 prompt sizes)
* `claude-haiku-4-5` (~4× cheaper than Sonnet, slightly lower quality)
* Local Ollama (zero per-call cost, infrastructure cost separate)

```bash
export AI_DEFAULT_PROVIDER=openai
export AI_OPENAI_MODEL=gpt-4o-mini
curl -X POST $API/api/v1/ai/registry/reset
```

The next request uses the new provider. Cached fixes from the prior
provider continue to render unchanged (the `provider_used` field in
`AiFixMetadata` reflects what generated each entry).

---

## 3. Kill-switch verification

Run before each rollout phase. Should take < 60 seconds.

```bash
# 1. Confirm AI is currently serving.
curl -s $API/api/v1/runs/$RUN/ai-fixes/progress | jq .status
# Expected: "complete" (or "in_progress" / "pending" if a batch is live)

# 2. Flip the kill switch.
export AI_FIXES_KILL_SWITCH=true
# ...redeploy / restart API process

# 3. Confirm new triggers are blocked.
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  $API/api/v1/runs/$RUN/ai-fixes
# Expected: 409

# 4. Confirm error envelope.
curl -s -X POST $API/api/v1/runs/$RUN/ai-fixes \
  | jq '.detail.error_code'
# Expected: "AI_FIXES_KILL_SWITCH"

# 5. Restore.
unset AI_FIXES_KILL_SWITCH
# ...redeploy / restart API process

# 6. Confirm AI is serving again.
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  $API/api/v1/runs/$RUN/ai-fixes
# Expected: 200
```

A scripted version lives at
[`scripts/verify_ai_rollout.py`](../scripts/verify_ai_rollout.py); run
it against a staging FastAPI process (it uses the in-process
TestClient + manipulates env vars).

---

## 4. Eight-step verification on staging (Phase 6 §5 gate)

Before flipping the master flag in production, complete these eight
steps on staging in order. Failure at any step blocks production
rollout until resolved.

1. **Migration check.**
   `alembic upgrade head` then `\dt` (psql) or `.tables` (sqlite)
   shows `ai_usage_log`, `ai_provider_config`, `ai_fix_cache`.
2. **Provider health.**
   `GET /api/v1/ai/providers` returns the configured default with
   `available=true` and the expected model.
3. **Smoke output quality.**
   `python scripts/ai_fix_smoke.py --provider $PROVIDER` writes 5
   bundles to `audit/ai_fix_smoke_outputs.json`. Each one matches the
   Phase 2 §8 example quality bar.
4. **Single-finding generation.**
   Click a finding in the CVE modal, observe the AI section render
   within 8s. Refresh the page; the second open is a cache hit
   (instant + "Cached" badge).
5. **Batch trigger.**
   On a 50+ finding run, click "Generate AI fixes". Banner appears,
   progress bar updates, completes within 90s warm cache (Phase 1
   §4.2 target).
6. **Telemetry populated.**
   `/admin/ai-usage` shows non-zero values across every tile;
   sparkline has at least one data point.
7. **Rollout gate works.**
   `python scripts/verify_ai_rollout.py` returns exit 0 (9/9 checks).
8. **Kill switch works.**
   `AI_FIXES_KILL_SWITCH=true` → restart → trigger returns 409 with
   `AI_FIXES_KILL_SWITCH` error code → unset → restart → trigger
   returns 200.

When all 8 steps are green, paste the verification log into the
rollout ticket and proceed to production with Phase A.

---

## 5. Incident response

The kill switch is your hammer. **Use it first**, ask questions after.

| Symptom | First action | Diagnostic |
|---|---|---|
| Cost spike | `AI_FIXES_KILL_SWITCH=true`, restart | `/admin/ai-usage` trend + top-cached |
| Provider 5xx storm | `AI_DEFAULT_PROVIDER=<fallback>` + reset registry | `ai_request_total{outcome="provider_error"}` |
| Schema parse failures | `AI_FIXES_KILL_SWITCH=true`, investigate prompt | `ai_request_total{outcome="schema_parse_failed"}` |
| Hallucination report | Pull `audit_log` for `request_id`, examine `response_sha256`, then verify against `ai_fix_cache` row | Audit log + cache row |
| Stuck batch | `POST /api/v1/runs/{id}/ai-fixes/cancel` | Progress endpoint |

After the immediate fix, file a post-incident with the metric snapshot
+ audit log slice as evidence. Bump `PROMPT_VERSION` if the model
behaviour was the root cause.

---

## 6. Decommissioning the canary gate

After 30 days at `AI_CANARY_PERCENTAGE=100` with no incidents, the
canary is no longer load-bearing — it's just a check that always
returns true. Two cleanup paths:

* **Leave it in place.** The check is sub-microsecond; no operational
  cost. Future re-canary (e.g. for a new prompt version rollout) is one
  env flip away.
* **Remove the gate code.** If the team is sure no future canary is
  needed, remove `evaluate_access` from the trigger endpoints and drop
  the canary-specific tests. (Recommended only when the next prompt
  bump is at least 6 months out.)

The kill switch and master flag should always remain.

---

## 7. UI configuration rollout (Phase 4)

The Phase 4 expansion ships an editable Settings → AI surface
(``/settings/ai``), backed by encrypted-at-rest credentials in
Postgres. This rollout is **independent** of the master AI flag — env
configuration continues working unchanged until you flip the new flag.

### 7.1 Pre-flight

| Item | Where | Confirm |
|---|---|---|
| Master encryption key | env (``AI_CONFIG_ENCRYPTION_KEY``) | Generate via `python scripts/generate_encryption_key.py` and add to your secrets store |
| Migration ``010_ai_credentials`` applied | infra | `alembic current` shows `010_ai_credentials` (head) |
| Singleton ``ai_settings`` row exists | DB | `SELECT count(*) FROM ai_settings` returns 1 |
| Existing env config still works | curl | `POST /api/v1/runs/$RUN/ai-fixes` returns 200 — env-fallback path |

### 7.2 Phase A — env-to-DB migration (Day 0, no UI exposure)

```bash
# Pre-flight (no writes; print what would happen).
python scripts/migrate_env_to_db.py --dry-run

# Migrate.
python scripts/migrate_env_to_db.py

# Verify rows landed.
psql $DATABASE_URL -c \
  "SELECT id, provider_name, default_model, is_default, enabled \
   FROM ai_provider_credential ORDER BY id"
```

The platform now has DB-backed credentials. The registry still
honours env values until the next process restart picks up the new
config (60s TTL). **No user-visible change yet** — `AI_FIXES_UI_CONFIG_ENABLED`
is still false, the UI surface is hidden.

### 7.3 Phase B — internal-only enable (Day 0+, soak 48h)

```bash
export AI_FIXES_UI_CONFIG_ENABLED=true
```

Restart the API process. ``/settings/ai`` now renders the editable
surface. Internal users can:

* Add / edit / delete credentials via the UI.
* Test connections without spending tokens.
* Toggle the kill switch from the UI (writes to ``ai_settings``).
* Adjust budget caps from the UI.

**During the soak window:**

1. Have one team member walk through the [user-facing flow](features/ai-configuration.md)
   end-to-end — add Gemini free, test, set as default, kick off a
   batch on a small run, switch to Anthropic, kick off another batch.
2. Verify ``ai_credential_audit_log`` rows appear for every mutation:
   ```sql
   SELECT created_at, action, provider_name, detail
   FROM ai_credential_audit_log
   ORDER BY created_at DESC LIMIT 20;
   ```
3. Confirm no API keys appear in any log line:
   ```bash
   journalctl -u sbom-api --since "48 hours ago" \
     | grep -E '(sk-ant-|sk-[A-Za-z0-9]{20}|AIzaSy|xai-)' \
     | head
   # No output expected.
   ```
4. Watch ``ai_request_total{outcome="ok"}`` to confirm fix generation
   continues to work — DB-backed credentials should produce identical
   behaviour to env-only.

**Pass criteria for Phase C:** zero key-leak hits in the log grep,
audit log shape matches expectation, no incidents requiring kill
switch.

### 7.4 Phase C — production rollout

```bash
# In production env:
export AI_FIXES_UI_CONFIG_ENABLED=true
```

Restart the API. The new surface is live for every admin.

**Optional cleanup (recommended after 14 days of stable Phase C):**

1. Remove the AI provider env vars from your secrets store (the env
   migration is now ancient history; the DB is authoritative).
2. Document this in your changelog.

### 7.5 Rollback

If anything goes wrong:

```bash
export AI_FIXES_UI_CONFIG_ENABLED=false
```

Restart the API. The UI surface goes back to "not enabled". The DB
rows persist; the env-only path takes over again. **No data loss** —
the migration is reversible.

If you need to wipe DB credentials entirely:

```sql
TRUNCATE ai_provider_credential, ai_credential_audit_log;
DELETE FROM ai_settings WHERE id = 1;
INSERT INTO ai_settings (id) VALUES (1);  -- restore singleton
```

The next batch run picks up env config automatically.

---

## 8. Tracked follow-ups

These are NOT in the v1 rollout but are referenced in `docs/architecture/ai-pipeline.md` §11:

* **F-1**: generated unified-diff PRs against user repos
* **F-2**: per-tenant settings (org-level `ai_fixes_enabled`)
* **F-3**: negative cache (1h TTL on failed generations)
* **F-4**: streaming token-by-token display in UI
* **F-5**: per-finding cost-cap override
* **F-6**: KMS / Vault integration for the credential master key
  (replaces the env-var path)

Each represents a re-rollout exercise with its own canary phase if /
when shipped.
