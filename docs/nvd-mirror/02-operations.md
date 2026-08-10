# Phase 6 — NVD Mirror Operations Runbook

> **Audience:** operators deploying or running the SBOM Analyzer with the
> NVD mirror enabled. Read [00-discovery.md](00-discovery.md) and
> [01-design.md](01-design.md) first if you need background.
>
> **Date:** 2026-04-28

---

## 1. Get an NVD API key

Free, ~30 seconds. The key boosts NVD's anonymous rate limit from
**5 req / 30 s** to **50 req / 30 s** — for the mirror's bootstrap
that's the difference between ~45 minutes and ~5 minutes.

1. Go to **https://nvd.nist.gov/developers/request-an-api-key**.
2. Fill in the form (org name, email, intended use).
3. NIST emails an activation link within minutes.
4. Click the link. The page shows your key. Save it once — there is no
   "show again" UI.

Without a key, the mirror still works; bootstrap just takes longer.

---

## 2. Generate the Fernet key

This key encrypts the NVD API key at rest in `nvd_settings.api_key_ciphertext`.
Operators with read access to the database CANNOT recover the API key
without this Fernet key.

```bash
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

The output is a 44-character url-safe base64 string. Set it as
`NVD_MIRROR_FERNET_KEY` in your deployment environment.

> **Rotation.** If you rotate the Fernet key, the existing
> `api_key_ciphertext` becomes undecryptable. The mirror's settings
> repository handles this gracefully — `api_key_plaintext` reads as
> `None` and the next bootstrap will run anonymously until you re-save
> the API key via `PUT /admin/nvd-mirror/settings`.

---

## 3. Required environment variables

| Var                          | Required when            | Notes                                                                |
|------------------------------|--------------------------|-----------------------------------------------------------------------|
| `DATABASE_URL`               | always                   | `postgresql+psycopg://user:pass@host:5432/db` for prod                |
| `REDIS_URL`                  | always (Celery broker)   | `redis://host:6379/0`                                                 |
| `NVD_MIRROR_FERNET_KEY`      | mirror enabled           | See §2                                                                |
| `NVD_API_KEY`                | recommended              | Used as bootstrap seed and as live-API fallback when mirror is empty  |
| `NVD_MIRROR_ENABLED`         | optional                 | `true` to flip the env-default to enabled. The DB row is the source of truth at runtime — operators flip enabled/disabled via the admin API. |
| `NVD_MIRROR_API_ENDPOINT`    | optional                 | Override only for air-gapped or proxied deployments                   |
| `NVD_MIRROR_PAGE_SIZE`       | optional                 | 1..2000, default 2000                                                 |
| `NVD_MIRROR_WINDOW_DAYS`     | optional                 | 1..119, default 119                                                   |
| `NVD_MIRROR_MIN_FRESHNESS_HOURS` | optional             | Default 24                                                            |
| `API_AUTH_MODE`              | production               | `bearer` or `jwt`; default `none` is dev-only                          |

---

## 4. Apply the migration

The mirror's three new tables (`nvd_settings`, `cves`, `nvd_sync_runs`)
plus the GIN index on `cves.cpe_match` (PostgreSQL only) come from
Alembic revision `002_nvd_mirror_tables`. On a fresh database run:

```bash
alembic upgrade head
```

The migration is idempotent — applying it twice is a no-op. Production
must run this once **before** flipping `enabled=True`.

> **PostgreSQL extensions:** none required. The mirror uses built-in
> `JSONB`, `BYTEA`, `TIMESTAMPTZ`, `BTREE`, and `GIN` features — all
> available in stock PG ≥ 12.

---

## 5. Initial bootstrap

### 5.1 Configure

```bash
curl -X PUT https://api.example.com/admin/nvd-mirror/settings \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled": true, "api_key": "<your-nvd-api-key>"}'
```

Response shows `api_key_present: true` and `api_key_masked: "abc...xyz"`.
Plaintext is **never** echoed back.

### 5.2 Trigger the run

```bash
curl -X POST https://api.example.com/admin/nvd-mirror/sync \
  -H "Authorization: Bearer $TOKEN"
```

Returns `{"task_id": "...", "status": "queued"}`. Or just wait — the
beat scheduler fires `mirror_nvd` at minute 15 every hour.

### 5.3 Expected duration (rough)

| Mode        | Walking 2002-01-01 → today | Notes                                  |
|-------------|----------------------------|-----------------------------------------|
| With key    | ~5–10 minutes              | 50 req / 30 s, ~200 windows × 1–2 pages |
| Anonymous   | ~45–60 minutes             | 5 req / 30 s, same window count          |

The bootstrap is **resumable**. If the process is killed mid-run, the
next firing of `mirror_nvd` continues from `nvd_settings.last_modified_utc`
— it does NOT restart at 2002.

### 5.4 Observe progress

```bash
curl https://api.example.com/admin/nvd-mirror/sync/status \
  -H "Authorization: Bearer $TOKEN"
```

Returns the last 10 sync runs ordered newest-first. A typical run shows:

```json
[
  {"id": 200, "run_kind": "bootstrap", "status": "success",
   "window_start": "2026-03-12T...", "window_end": "2026-04-28T...",
   "started_at": "...", "finished_at": "...", "upserted_count": 3470},
  ...
]
```

The `/health` endpoint also exposes:

```json
{
  "status": "ok",
  "nvd_mirror": {
    "enabled": true,
    "last_success_at": "2026-04-28T16:30:00+00:00",
    "watermark": "2026-04-28T15:00:00+00:00",
    "stale": false,
    "counters": {
      "nvd.windows.success": 200,
      "nvd.cves.upserted": 247103,
      "nvd.live_fallbacks": 4,
      "nvd.api.429_count": 12
    }
  }
}
```

---

## 6. Reset the watermark (force re-bootstrap)

When you need to rebuild the mirror from scratch — for example after
a schema change in the JSONB column or a suspected partial corruption:

```bash
curl -X POST https://api.example.com/admin/nvd-mirror/watermark/reset \
  -H "Authorization: Bearer $TOKEN"
```

This sets `last_modified_utc=NULL`. The next `mirror_nvd` firing
treats the mirror as never-run and walks from 2002-01-01 again. The
existing `cves` rows are NOT deleted — the upsert with
`WHERE excluded.last_modified > cves.last_modified` re-writes them where
fresher and leaves them untouched otherwise.

If you want to actually wipe the table, do that out-of-band:

```sql
TRUNCATE TABLE cves;
```

Then reset the watermark and trigger a sync.

---

## 7. Interpreting degraded-mode warnings

Three structured log events to watch for. Each is emitted at most once
per CPE lookup, so they can be high-cardinality during heavy analysis.

### `nvd_mirror_stale_falling_back` (WARNING)

Mirror is enabled but `last_successful_sync_at` is older than
`min_freshness_hours`. The facade falls through to the live API.

* **Likely cause:** Celery worker / beat process is down, or NVD has been
  unreachable for hours.
* **Investigate:** `GET /admin/nvd-mirror/sync/status` — look for
  `status='failed'` rows. If beat is firing but every run fails, check
  network egress or NVD API status.
* **Mitigate:** the analyzer keeps working via live fallback. Restart
  worker / beat when healthy.

### `nvd_mirror_query_failed_falling_back` (ERROR)

The mirror was reached but `find_by_cpe` raised an exception.

* **Likely cause:** schema drift, DB connection issue, or a corrupted
  `cve_match` JSONB row.
* **Investigate:** the `extra` dict carries `exc_type`, `error`, and a
  `hint` recommending you disable the mirror via `PUT /admin/nvd-mirror/settings`
  if the error pattern repeats.
* **Mitigate:** disable mirror and run with live-only until root-caused.

### `nvd_mirror_empty_double_checking_live` (INFO)

Mirror is fresh and reachable but returned zero CVEs for the requested
CPE. The facade double-checks the live API.

* **Not an error.** The mirror's CPE matching is stricter than NVD's
  internal `cpeName` query in some edge cases. Live double-check ensures
  parity.
* **Investigate** only if this fires for a CPE you know NVD has CVEs for
  — that suggests a bug in the mirror's `find_by_cpe` algorithm
  ([app/nvd_mirror/adapters/cve_repository.py](../../app/nvd_mirror/adapters/cve_repository.py)).

---

## 8. Railway deployment

### 8.1 Process layout

Three separate Railway services share the same Docker image and env vars:

| Service         | Start command                          | Replicas |
|-----------------|----------------------------------------|----------|
| **api**         | `uvicorn app.main:app --host 0.0.0.0 --port 8000` | ≥ 1 (autoscale)  |
| **worker**      | `./scripts/celery_worker.sh`           | ≥ 1 (autoscale)  |
| **beat**        | `./scripts/celery_beat.sh`             | **exactly 1**    |

> ⚠ **Beat must be a single instance.** Two beat processes would each
> fire the hourly schedule, doubling NVD API calls and risking 429s.

### 8.2 Env vars per service

All three services need:

* `DATABASE_URL`
* `REDIS_URL`
* `API_AUTH_MODE` and supporting `API_AUTH_TOKENS` / `JWT_SECRET_KEY`

Worker + beat additionally need:

* `NVD_MIRROR_FERNET_KEY` — to decrypt the API key from the DB row
* `NVD_API_KEY` — only needed if you want the env-var fallback (see §3)

The api service does NOT strictly need `NVD_MIRROR_FERNET_KEY` to boot,
but without it `GET /admin/nvd-mirror/settings` returns
`api_key_present=false` even when a key is stored, and `PUT` with a
non-empty key returns 503 with a "Fernet key not configured" error.
**Set the same key on all three services.**

### 8.3 Healthcheck

Railway's `[deploy].healthcheckPath = "/health"` (already configured in
[railway.toml](../../railway.toml)) returns 200 with the mirror status
block. The healthcheck does **not** fail when the mirror is stale — that
would knock the api service out for an unrelated subsystem outage.
Inspect the `nvd_mirror.stale` flag in your monitoring instead.

### 8.4 Rollback safety

Disable the mirror in one API call:

```bash
curl -X PUT https://api.example.com/admin/nvd-mirror/settings \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"enabled": false}'
```

Within the next request, the facade returns to the legacy live-only
behaviour. No process restart needed.

---

## 9. Recording NVD fixtures (developer note)

The contract tests under
[tests/fixtures/nvd/](../../tests/fixtures/nvd/) use hand-built JSON. To
record a fresh real fixture against the live API:

```bash
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?\
lastModStartDate=2024-04-01T00:00:00.000%2B00:00&\
lastModEndDate=2024-04-02T00:00:00.000%2B00:00&\
resultsPerPage=10" \
  -H "apiKey: $NVD_API_KEY" \
  | jq '.' > tests/fixtures/nvd/cve_one_day_window.json
```

Then commit the file. **Never** run live API requests from CI — fixtures
are checked in so contract tests stay deterministic.

---

## 10. FAQ

**Q: Can I run the mirror against SQLite?**
A: No. The repository adapter uses `JSONB`, the GIN index on `cpe_match`,
and PostgreSQL-specific `INSERT ... ON CONFLICT` semantics. The dev
SQLite path works for unit tests with `enabled=False`; with the mirror
enabled you must use PostgreSQL.

**Q: What happens if `mirror_nvd` is still running when beat fires again?**
A: The new firing aborts immediately with
`{"status": "skipped", "reason": "concurrent_run_in_progress"}`. The
single-run guard at
[app/nvd_mirror/tasks.py::assert_no_run_in_flight](../../app/nvd_mirror/tasks.py#L107)
checks `nvd_sync_runs.status='running'` before starting any new work.

**Q: How do I clear a stuck `running` row?**
A: Today: directly `UPDATE nvd_sync_runs SET status='aborted'
WHERE status='running' AND started_at < now() - interval '1 hour'`.
A future enhancement (Phase 1 §9-7) automates this.

**Q: How big is the `cves` table after a full bootstrap?**
A: Roughly 250 000 rows × ~10 KB JSONB ≈ 2.5 GB. Allocate at least
4 GB of database storage to leave headroom for indexes and growth.
