# Compare runs — operator runbook

Operational playbook for the Compare Runs v2 surface (ADR-0008).

> **User-facing doc:** [docs/features/compare-runs.md](features/compare-runs.md)
> **Architecture:** [docs/adr/0008-compare-runs-architecture.md](adr/0008-compare-runs-architecture.md)

---

## 1. Surface map

| Tier | Path | What it does |
|---|---|---|
| API | `POST /api/v1/compare` | Canonical v2 diff endpoint. Reads cache; computes on miss. |
| API | `POST /api/v1/compare/{cache_key}/export` | Re-serialises a cached diff as md/csv/json. |
| API | `GET /api/runs/recent` | 20 most recent runs — picker default state. |
| API | `GET /api/runs/search?q=` | Picker autocomplete. |
| API | `GET /api/analysis-runs/compare` | **DEPRECATED** v1 endpoint. Sunset 2026-12-31. |
| DB | `compare_cache` | Diff result cache. 24h TTL, indexed on both run ids. |
| Frontend | `/analysis/compare` | The page. Strangler rewrite of v1. |
| Frontend env | `NEXT_PUBLIC_COMPARE_V1_FALLBACK` | Build-time kill-switch. |
| Backend env | `COMPARE_V1_FALLBACK` | Echo for ops verification via `/health`. |
| Backend env | `COMPARE_LICENSE_HASH_ENABLED` | Hard guard on stubbed change_kinds. Default `false`. |
| Backend env | `COMPARE_STREAMING_THRESHOLD` | Future SSE cut-off (currently a knob, not yet wired). |
| Backend env | `COMPARE_CACHE_TTL_SECONDS` | Cache row TTL. Default 86400. |

---

## 2. Cache health

### Sizing

`compare_cache` rows are typically 5 KB (small diffs) up to a few MB for
runs with thousands of findings. At a steady-state of ~50 active users
each comparing ~3 run pairs per session, expect 150–500 rows in the table.

### Inspecting the cache

```sql
-- Row count + age distribution
SELECT
  count(*) AS total_rows,
  min(computed_at) AS oldest,
  max(computed_at) AS newest,
  count(*) FILTER (WHERE expires_at < now()::text) AS expired_rows
FROM compare_cache;

-- Largest payloads (pg_column_size on the JSONB)
SELECT cache_key, run_a_id, run_b_id, pg_column_size(payload) AS bytes
FROM compare_cache
ORDER BY pg_column_size(payload) DESC
LIMIT 10;

-- Per-run cache footprint (helps decide which run to invalidate)
SELECT run_a_id AS run_id, count(*) AS rows, sum(pg_column_size(payload)) AS bytes
FROM compare_cache
GROUP BY run_a_id
UNION ALL
SELECT run_b_id, count(*), sum(pg_column_size(payload))
FROM compare_cache GROUP BY run_b_id
ORDER BY bytes DESC
LIMIT 20;
```

### Pruning expired rows

Expired rows are skipped on read but linger until something rewrites or
deletes them. Manual GC if the table grows large:

```sql
DELETE FROM compare_cache WHERE expires_at < now()::text;
```

A cron-driven sweeper isn't shipped; the 24h TTL plus occasional manual
prune is sufficient at current scale. Add a Celery beat task if the table
crosses ~10 MB.

---

## 3. Cache invalidation

### When invalidation matters

Compare cache is keyed by `(run_a_id, run_b_id)`. Because runs are
**append-only in this codebase** (every analysis creates a new
`analysis_run` row; nothing mutates or deletes existing runs), invalidation
is generally a non-issue today.

If a future code path mutates an existing run (re-running findings against
the same `run.id`) or deletes a run, that path **MUST** call:

```python
from app.services.compare_service import CompareService
CompareService(db).invalidate_for_run(run_id)
```

in the same transaction. The contract is documented at the bottom of
[`persist_analysis_run` in app/services/analysis_service.py](../app/services/analysis_service.py).

### Manually invalidating a stuck row

If a single cache row turns out to be wrong (e.g. cache schema mismatch
during a deploy):

```sql
-- By cache_key
DELETE FROM compare_cache WHERE cache_key = '<sha256>';

-- All rows referencing a specific run
DELETE FROM compare_cache WHERE run_a_id = <id> OR run_b_id = <id>;
```

The next `POST /api/v1/compare` will recompute and re-cache.

### Schema corruption

If a cache row's payload no longer validates against the current
`CompareResult` Pydantic schema (e.g. after a bumped `schema_version`), the
service detects it on read, logs `compare cache_corrupt cache_key=…`,
deletes the row, and recomputes. No operator action needed — but if you see
a flood of these, it usually means a schema migration that didn't bump
`schema_version` correctly.

---

## 4. Common failure modes

### `POST /api/v1/compare` returns 409 `COMPARE_E002_RUN_NOT_READY`

One of the runs has `run_status` outside `{OK, FINDINGS, PARTIAL}` —
typically still `RUNNING` or `ERROR`. The frontend renders the
"Run isn't ready yet" warning state and auto-polls. **No action needed**
for `RUNNING` (will resolve on its own); for `ERROR` the user has to pick
a different run.

### `POST /api/v1/compare` returns 404 `COMPARE_E001_RUN_NOT_FOUND`

The user's URL references a run id that doesn't exist — usually because the
run was hand-deleted via SQL (no API path deletes runs). Tell them to pick
a live run; if you've deleted runs intentionally and want to clean up
dangling cache, run:

```sql
DELETE FROM compare_cache
WHERE run_a_id NOT IN (SELECT id FROM analysis_run)
   OR run_b_id NOT IN (SELECT id FROM analysis_run);
```

### `POST /api/v1/compare` returns 400 `COMPARE_E003_SAME_RUN`

User picked the same run on both sides. Frontend already guards this with
the "same run twice" empty state; you should never see this from a normal
client. If you do, it's a malformed external integration.

### Rate-limited (`429`)

`POST /api/v1/compare` is rate-limited at 30/min per user, exports at
10/min. Default limits live in `app/rate_limit.py`. Bumps belong in the
Settings env (`API_RATE_LIMIT_DEFAULT`); changing the per-route limits
requires a code change.

### Cold cache slow path

p50 cold compare for a typical run (≤ 1000 components, ≤ 500 findings each):
**~250-600 ms** on the bundled SQLite. p95 should sit under 1.2 s. If
you're seeing >2 s consistently:

1. Check the structured log line `compare cache_miss cache_key=… run_a=… run_b=…`
   — confirms cache is cold (expected on first call).
2. Look for N+1: the engine performs **2 SQL queries per run** plus 1 KEV
   batch + 1 CVE-cache batch. Anything else is a regression.
3. EXPLAIN ANALYZE the finding query — should hit
   `ix_analysis_finding_run_severity` for severity lookups, and the
   FK-indexed `analysis_run_id` for the JOIN.

---

## 5. v1 deprecation telemetry

Three signals available to confirm the <1% relative-traffic threshold for
deletion:

### Structured log line

Every v1 call emits:

```
WARNING compare_v1_deprecated_call run_a=<id> run_b=<id> total_calls=<N> sunset=<date>
```

Search the access log:

```bash
# Total v1 calls in the last 7 days
grep -c 'compare_v1_deprecated_call' /var/log/sbom/access.log

# Last 24h
journalctl -u sbom --since '24h ago' | grep -c compare_v1_deprecated_call

# Compare with v2 traffic
journalctl -u sbom --since '24h ago' | grep -c 'POST /api/v1/compare '
```

### Process-local counter

```python
from app.routers.analysis import get_compare_v1_call_count
print(get_compare_v1_call_count())
```

This is **process-local**; multi-worker deployments need log aggregation
for an absolute total.

### Response headers

Every v1 response carries:

```
Deprecation: true
Sunset: Wed, 31 Dec 2026 23:59:59 GMT
Link: </api/v1/compare>; rel="successor-version"
```

SDK consumers (urllib3, requests, axios with interceptors) can surface
these to the caller automatically.

### Removal procedure

When the threshold is met:

1. Bump `app/main.py` to drop the v1 router include.
2. Remove `app/routers/analysis.py` lines 22-160 (the compare handler);
   the SARIF + CSV export handlers stay.
3. Remove `tests/test_compare_v1_deprecation.py`.
4. Bump the API version in `app/settings.py` minor.

---

## 6. Emergency kill-switch

`NEXT_PUBLIC_COMPARE_V1_FALLBACK` (frontend, build-time) +
`COMPARE_V1_FALLBACK` (backend, runtime echo). When set to `true`, the
frontend renders the preserved v1 page (with a banner) instead of v2.
**Backend behaviour does NOT change** — the kill-switch only flips the
frontend's render decision; ops can still hit v2 endpoints directly during
the rollback to confirm they work in isolation.

### When to use it

Use only for a critical v2 bug that:

- Crashes the page on load (white screen)
- Leaks PII or shows wrong runs to wrong users (cross-tenant — not possible
  today; reserved for the post-tenancy world)
- Causes data loss (the diff itself is read-only, so this is improbable)

For data-correctness bugs in the diff engine, prefer a hotfix over a
rollback — the v1 endpoint has its own correctness gaps (collapses CVE-X
against different components into one entry; see Phase 1 §C-1).

### Verification protocol (must run in staging before flipping in prod)

1. Set both env vars in staging:
   ```bash
   export NEXT_PUBLIC_COMPARE_V1_FALLBACK=true
   export COMPARE_V1_FALLBACK=true
   ```
2. Rebuild + redeploy frontend and backend.
3. Verify the backend echo:
   ```bash
   curl -s https://staging.example/health | jq .compare_v1_fallback
   # → true
   ```
4. Open `https://staging.example/analysis/compare?run_a=1&run_b=2` in a
   browser → expect:
   - Amber "Compare is temporarily running on v1" banner at the top
   - The v1 distribution bar + summary tiles + three-column lists (no Picker)
5. Hit the **v2 endpoint directly** from the staging shell to confirm it
   still serves correctly:
   ```bash
   curl -s -X POST https://staging.example/api/v1/compare \
     -H 'Content-Type: application/json' \
     -d '{"run_a_id":1,"run_b_id":2}' | jq .cache_key
   # → 64-char hex
   ```
6. Unset both env vars → redeploy → repeat step 4 → expect v2 page
   (Selection bar, Posture region, three tabs).

Both tiers must be flipped together. Flipping only the frontend means the
`/health` echo lies; flipping only the backend has no user-visible effect.

---

## 7. Performance baselines

Numbers from the test suite (in-memory SQLite, single-row diffs):

| Metric | Value |
|---|---|
| Cold compare, ≤10 findings each | <50 ms |
| Cold compare, ~500 findings each | ~250 ms |
| Cache hit | <20 ms |
| Markdown export | <30 ms |
| CSV export | <30 ms |
| JSON export | <50 ms |

Production (PostgreSQL) should be in the same ballpark for the warm path;
cold path scales with `total_findings × log(total_findings)` for the diff
plus 2 SQL queries per run for the load.

---

## 8. Rollout plan (post-merge)

| Phase | Window | What |
|---|---|---|
| **0 — pre-flight** | Day -1 | Run staging verification protocol (§6). Confirm cold + warm latency p95 under target. |
| **1 — merge** | Day 0 | Single PR merges v2 + v1 patches together (no asymmetric exposure). Migration `007_compare_cache` ships. |
| **2 — observe** | Day 0–7 | Watch `compare_v1_deprecated_call` log lines (should rise initially as cached browser sessions hit v1, then drop). Watch `compare cache_miss` p95 latency. |
| **3 — sunset planning** | Week 4 | If v1 traffic <1% of v2 for 14 consecutive days, schedule v1 endpoint removal in the next minor release. |
| **4 — sunset** | When ready | Remove v1 endpoint per §5 procedure. Bump API minor version. |

If anything goes wrong at phase 2, the kill-switch (§6) is the rollback. If
it goes wrong at phase 4 (post-removal), the only path is a code revert.
