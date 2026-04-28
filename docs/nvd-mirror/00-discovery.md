# Phase 0 — Repository Discovery

> **Scope:** Read-only audit performed before any code is written for the
> NVD mirror integration. Every claim below cites a file path and line
> number. Where the cowork prompt's assumptions diverge from reality, the
> divergence is flagged here so Phase 1 design can correct course.
>
> **Date:** 2026-04-28

---

## A. Project layout

### A.1 Top-level directory tree (depth 3, exclusions applied)

```
/home/kali/sbom
├── alembic/
│   └── versions/                    # Alembic migrations live here
├── app/                             # ← primary backend package
│   ├── infrastructure/              # s3 storage adapter (only)
│   ├── parsing/                     # SBOM parsers (CycloneDX/SPDX)
│   ├── pipeline/                    # multi-source orchestrator
│   ├── ports/                       # Protocol-typed ports (hexagonal)
│   ├── repositories/                # SQLAlchemy repos
│   ├── routers/                     # FastAPI routers
│   ├── samples/
│   ├── services/                    # app-service layer
│   ├── sources/                     # vulnerability source adapters
│   └── workers/                     # Celery app + tasks
├── frontend/                        # Next.js UI (out of scope)
├── samples/
├── scripts/
└── tests/
    ├── fixtures/
    └── snapshots/
```

### A.2 Primary backend package

The primary backend package is **`/home/kali/sbom/app/`**, confirmed by:

* `pyproject.toml:84` — `[tool.setuptools.packages.find] include = ["app*"]`
* `alembic/env.py:12` — `from app.db import Base, DATABASE_URL`
* `app/main.py:169` — FastAPI app constructor lives here.

There is **no** `backend/app/` shim. All Python code lives directly under `app/`.

### A.3 Dependencies relevant to the mirror

From `pyproject.toml:11-31` (and `requirements.txt`, locked to the same versions):

| Concern         | Package         | Version          | Notes                                            |
|-----------------|-----------------|------------------|--------------------------------------------------|
| HTTP (sync)     | `requests`      | `>=2.33.1`       | Used by the existing NVD path                    |
| HTTP (async)    | `httpx`         | `>=0.28.1`       | Used by OSV/GHSA in `app/analysis.py`            |
| Task queue      | `celery[redis]` | `>=5.6.3`        | Wired up — see §E.13                             |
| Redis client    | `redis`         | `>=4.5.2,<6.5`   |                                                  |
| ORM             | `sqlalchemy`    | `>=2.0.49`       | Sync engine + `declarative_base` (legacy style)  |
| DB driver       | `psycopg[binary]` | `>=3.3.3`      | PostgreSQL (production); SQLite for dev/tests    |
| Migrations      | `alembic`       | `>=1.18.4`       |                                                  |
| Settings        | `pydantic-settings` | `>=2.13.1`   | `BaseSettings` + `SettingsConfigDict`            |
| Crypto (Fernet) | **MISSING**     | —                | `cryptography` is **not** installed (see Risks)  |
| Retry helper    | **MISSING**     | —                | `tenacity` is **not** installed (see Risks)      |
| Structured logs | **MISSING**     | —                | No `structlog`; `app/logger.py` uses stdlib only |

> **Phase 2.1 deliverable** must add `cryptography` and `tenacity` to
> `pyproject.toml` (and re-pin them in `requirements.txt`). `structlog` is
> optional per the prompt — recommend NOT adding it; the stdlib `logging`
> module with `extra={}` is already the established convention here.

---

## B. Existing NVD integration

### B.4 References to "nvd" across the codebase

`grep -ril nvd app/` finds 22 Python files. The load-bearing ones for this
work (with the function/role they play) are:

| File                              | Role |
|-----------------------------------|------|
| `app/analysis.py`                 | **Canonical** sync NVD HTTP client + dataclasses (`CVERecord`, `AnalysisSettings`, `nvd_query_by_cpe`, `nvd_query_by_keyword`, `nvd_query_by_components_async`, `_finding_from_raw`, `_augment_components_with_cpe`) |
| `app/sources/nvd.py`              | `NvdSource` adapter (thin wrapper, lazy-imports the analysis module) |
| `app/sources/cpe.py`              | `cpe23_from_purl`, `slug` (PURL→CPE 2.3) |
| `app/pipeline/multi_source.py`    | The async fan-out aggregator (`run_multi_source_analysis_async`) — the OTHER NVD orchestration path |
| `app/credentials.py`              | `nvd_api_key_for_adapters()` reads `Settings.nvd_api_key` |
| `app/settings.py`                 | App-wide config; `nvd_api_key` field, `Settings.NVD_API` class attr |
| `app/routers/health.py`           | Echoes NVD config keys via `/api/analysis/config` |
| `app/routers/analyze_endpoints.py`, `app/routers/sboms_crud.py`, `app/routers/analysis.py` | Call sites |
| `tests/test_nvd_cpe_query.py`, `tests/test_nvd_perf_guards.py`, `tests/test_nvd_ssl_regression.py` | Existing test coverage |

### B.5 `nvd_query_by_cpe`

* **Path:** [app/analysis.py:501](app/analysis.py#L501)
* **Signature:** `def nvd_query_by_cpe(cpe: str, api_key: str | None, settings: AnalysisSettings | None = None) -> list[dict]:`
* **Sync or async:** **synchronous** — uses `requests.Session` ([app/analysis.py:38-40](app/analysis.py#L38-L40)).
* **HTTP client:** `requests` with a module-level `_nvd_session = requests.Session()` whose `verify` is set to `certifi.where()` (a **path string**, deliberately — see the comment at lines 24-37 explaining a prior `SSLContext` regression).
* **Rate-limit handling:** Sleeps `nvd_request_delay_with_key_seconds` (0.6 s) or `nvd_request_delay_without_key_seconds` (6.0 s) between paginated requests. On 429/5xx it retries up to `nvd_max_retries` (default 3) with exponential backoff, honouring `Retry-After` headers ([app/analysis.py:441-460](app/analysis.py#L441-L460)).
* **API key resolution:** Caller passes `api_key` directly. The shared resolver is `resolve_nvd_api_key()` at [app/analysis.py:323](app/analysis.py#L323), which reads `os.getenv(cfg.nvd_api_key_env)` — env-var name itself is configurable (default `NVD_API_KEY`).
* **Pagination:** `_nvd_fetch_cves_paginated()` at [app/analysis.py:407](app/analysis.py#L407) walks `startIndex`/`resultsPerPage` until `start + size >= totalResults`, capped by `nvd_max_pages_per_query=3` and `nvd_max_total_results_per_query=500` to prevent run-aways.
* **Return shape:** `list[dict]` — raw CVE objects as returned by NVD's REST 2.0 API (the `cve` sub-document of each `vulnerabilities[]` entry).

There is also a sibling function `nvd_query_by_keyword(name, version, api_key, settings)` at [app/analysis.py:528](app/analysis.py#L528) for the no-CPE fallback path.

### B.6 `_cpe23_from_purl` / canonical CPE generator

* **Canonical impl:** `cpe23_from_purl(purl, version_override=None)` at [app/sources/cpe.py:34](app/sources/cpe.py#L34).
* **Re-exported as `_cpe23_from_purl`** in `app/analysis.py:343` for legacy call sites.
* **Ecosystems handled** (lines 57-114): `pypi`, `npm`, `maven` (with `org.apache.*` → `apache`, `log4j-*` → `log4j` heuristics), `golang`/`go`, `rubygems`/`gem`, `nuget`, `composer`, `cargo`/`crates`. Unknown types fall through to a generic vendor=last-segment-of-namespace, product=name fallback.

### B.7 Multi-source aggregator

There are **two** orchestrators that both call into the NVD path. The mirror
must intercept BOTH or sit at a layer below them.

#### B.7.a `run_multi_source_analysis_async` ([app/pipeline/multi_source.py:17](app/pipeline/multi_source.py#L17))

This is the active fan-out path used by `analyze_sbom_multi_source_async`
([app/analysis.py:1374](app/analysis.py#L1374)). It:

1. Extracts components, augments them with CPEs derived from PURLs ([multi_source.py:51-57](app/pipeline/multi_source.py#L51)).
2. Builds an inner `_nvd()` coroutine (lines 87-215) that fans out CPE
   queries concurrently via `asyncio.Semaphore(cfg.max_concurrency)` and
   `loop.run_in_executor` over the sync `nvd_query_by_cpe` /
   `nvd_query_by_keyword`.
3. Runs `_nvd()`, `_osv()`, `_gh()`, `_vulndb()` concurrently with
   `asyncio.gather` (lines 246-256).
4. Deduplicates findings via `deduplicate_findings()` ([app/sources/dedupe.py](app/sources/dedupe.py)).
5. Returns a flat `dict` whose `details["findings"]` is the unified
   list. Each finding follows the shape produced by
   `_finding_from_raw()` ([app/analysis.py:609](app/analysis.py#L609)):

```python
{
    "vuln_id": str,
    "aliases": list[str],
    "sources": list[str],            # ["NVD"], ["OSV"], ["GITHUB"]
    "description": str | None,
    "severity": str,                  # CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN
    "score": float | None,
    "vector": str | None,
    "attack_vector": str | None,
    "cvss_version": str | None,
    "published": str | None,
    "references": list[str],
    "cwe": list[str],
    "fixed_versions": list[str],
    "component_name": str,
    "component_version": str | None,
    "cpe": str | None,
}
```

#### B.7.b `nvd_query_by_components_async` ([app/analysis.py:1235](app/analysis.py#L1235))

A second, **sequential** NVD orchestrator. This is the one wired through
the `NvdSource` adapter ([app/sources/nvd.py:42](app/sources/nvd.py#L42)) and
is used by the legacy single-source endpoints
(`POST /analyze-sbom-nvd`, etc.) via `run_sources_concurrently`
([app/sources/runner.py](app/sources/runner.py)).

Sequential by design — the comment at lines 1241-1249 explains it stays
under NVD's global token-bucket ceiling (this is bug-fix `g` from §G).

> **Phase 5 facade must replace BOTH.** The cleanest cut is at the level
> of `nvd_query_by_cpe`/`nvd_query_by_keyword` themselves: every concurrent
> fan-out and every sequential walk ultimately calls them. A facade that
> sits one level lower — `NvdLookupService.query(cpe23)` — will be picked
> up by both code paths if we route them through the service.

---

## C. Persistence layer

### C.8 Existing SQLAlchemy models

All models live in [app/models.py](app/models.py) and use the **legacy**
`Column(...)` syntax (not SQLAlchemy 2.0 typed `mapped_column`). The base
is `declarative_base()` at [app/db.py:54](app/db.py#L54).

| Class                | Table                  | PK         | Notable columns / constraints |
|----------------------|------------------------|------------|--------------------------------|
| `Projects`           | `projects`             | `id`       | name, status, audit fields     |
| `SBOMType`           | `sbom_type`            | `id`       | unique `typename`              |
| `SBOMSource`         | `sbom_source`          | `id`       | FKs to `projects`, `sbom_type` |
| `SBOMAnalysisReport` | `sbom_analysis_report` | `id`       | legacy report blob             |
| `SBOMComponent`      | `sbom_component`       | `id`       | uniq `(sbom_id,bom_ref,name,version,cpe)` |
| `AnalysisRun`        | `analysis_run`         | `id`       | severity counters, raw_report  |
| `AnalysisFinding`    | `analysis_finding`     | `id`       | uniq `(analysis_run_id, vuln_id, cpe)` |
| `RunCache`           | `run_cache`            | `id`       | run JSON blob keyed by run id  |

> The mirror's three new tables (`nvd_settings`, `cves`, `nvd_sync_runs`)
> can adopt the **modern** SQLAlchemy 2.0 typed `mapped_column` style as
> the cowork prompt asks. This is **inconsistent** with the existing
> models but the inconsistency is deliberate — Phase 1 design will note it
> and we accept the local divergence to keep the mirror models strictly
> typed.

### C.9 Migration tool

* **Tool:** Alembic, configured at [alembic.ini](alembic.ini) and
  [alembic/env.py](alembic/env.py).
* **Existing revision:** [alembic/versions/001_initial_schema.py](alembic/versions/001_initial_schema.py) — `revision = "001_initial_schema"`, `down_revision = None`. It bootstraps via `Base.metadata.create_all(bind=bind)` rather than emitting explicit `op.create_table` calls.
* **Target:** `target_metadata = Base.metadata` ([env.py:20](alembic/env.py#L20)).
* **URL discovery:** `get_url()` reads `DATABASE_URL` env var; falls back to the same `app.db.DATABASE_URL` resolver ([env.py:23-24](alembic/env.py#L23-L24)).
* `app.main:_ensure_seed_data()` ([app/main.py:81](app/main.py#L81)) **also** calls `Base.metadata.create_all(bind=engine)` at startup — meaning new tables will appear in fresh dev SQLite DBs automatically without explicit migration. **Phase 2.4 should still author a real Alembic migration** because production runs PostgreSQL where `create_all` is not the source of truth.

### C.10 Sessions: sync, FastAPI dependency

* **Sync.** `SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)` at [app/db.py:53](app/db.py#L53).
* **Provided via:** `def get_db()` generator at [app/db.py:57](app/db.py#L57), used as `Depends(get_db)` throughout the routers (e.g. [app/routers/health.py:102](app/routers/health.py#L102)).
* **No async session anywhere.** This means the mirror's `CveRepositoryPort` adapter must use a sync `Session` — or, if Phase 3 wants real async, it must introduce its own engine + `AsyncSession` ONLY for the mirror, and pay for it in tests. **Recommend: stay sync for parity.**

---

## D. Configuration

### D.11 Settings module

There are **two** different settings systems in this repo. Both are
load-bearing; the mirror needs to integrate with the right one.

#### D.11.a App-wide settings — `app/settings.py`

* Class: `Settings(BaseSettings)` at [app/settings.py:31](app/settings.py#L31).
* Loader: `get_settings()` at [app/settings.py:246](app/settings.py#L246) (memoised).
* Style: **flat**, not nested. Fields like `nvd_api_key`, `redis_url`,
  `database_url` live at the top level. Class-level constants like
  `Settings.NVD_API`, `Settings.OSV_API`, `Settings.APP_VERSION` are
  attached at module import ([settings.py:210-231](app/settings.py#L210-L231)).
* **There is no nested `cfg.nvd.*` namespace.**

#### D.11.b Analysis-time settings — `app/analysis.py`

* Class: `AnalysisSettings` at [app/analysis.py:215-253](app/analysis.py#L215-L253) — a frozen dataclass.
* Loader: `get_analysis_settings()` at [app/analysis.py:295](app/analysis.py#L295) (`@lru_cache(maxsize=1)`).
* This is where `cfg.nvd_api_base_url` actually lives ([analysis.py:219](app/analysis.py#L219)). It is **not** a backward-compat shim — it is the canonical attribute on the `AnalysisSettings` dataclass, and all NVD URL reads inside `analysis.py` and `app/routers/health.py` come from here.
* Subclassed by `_MultiSettings` at [analysis.py:677-697](app/analysis.py#L677-L697) which adds `gh_*`, `osv_*`, `vulndb_*`, `max_concurrency`, etc.

> **Divergence from the cowork prompt.** The prompt says the mirror should
> live under `cfg.nvd.*` (nested) and assumes `cfg.nvd_api_base_url`
> already exists as a *backward-compat shim*. Reality: the field already
> exists as the *primary* (flat) attribute on `AnalysisSettings`. Phase 1
> design should **not** restructure `AnalysisSettings` into nested form —
> that would be a wider-than-necessary refactor that risks breaking the
> analysis tests. Instead: add a separate flat `NvdMirrorSettings`
> dataclass (e.g. on `_MultiSettings` or a new `MirrorSettings`) and
> expose a property like `cfg.mirror.enabled`. Keep `cfg.nvd_api_base_url`
> exactly where it is.

### D.12 NVD-related settings keys currently defined

In `Settings` (`app/settings.py`):
* `nvd_api_key: str = ""` ([line 40](app/settings.py#L40))
* `Settings.NVD_API: str` (class const) ([line 210](app/settings.py#L210))

In `AnalysisSettings` (`app/analysis.py:215-253`), driven by env vars:
* `nvd_api_base_url` (default `https://services.nvd.nist.gov/rest/json/cves/2.0`)
* `nvd_detail_base_url`
* `nvd_api_key_env` (default `"NVD_API_KEY"`)
* `nvd_results_per_page` (default 2000)
* `nvd_request_timeout_seconds` (default 60)
* `nvd_max_retries` (default 3)
* `nvd_retry_backoff_seconds` (default 1.5)
* `nvd_request_delay_with_key_seconds` (default 0.6)
* `nvd_request_delay_without_key_seconds` (default 6.0)
* `nvd_concurrency_with_key` (default 10)
* `nvd_concurrency_without_key` (default 2)
* `nvd_keyword_results_limit` (default 5)
* `nvd_keyword_fallback_enabled` (default True)
* `nvd_max_pages_per_query` (default 3)
* `nvd_max_total_results_per_query` (default 500)

**No `nvd_mirror_*` keys exist yet.** They will be added in Phase 2.2.

---

## E. Background processing

### E.13 Celery wiring

**Celery is wired up.** Confirmed by:

* App: `celery_app = Celery("sbom_analyzer", ...)` at [app/workers/celery_app.py:16](app/workers/celery_app.py#L16). Broker and backend both come from `Settings.celery_broker_url or Settings.redis_url`.
* Existing tasks (one): `sbom_analyzer.run_sbom_analysis` at [app/workers/tasks.py:14](app/workers/tasks.py#L14). It runs `run_multi_source_analysis_async` inside `asyncio.run`.
* Worker launch script: [scripts/celery_worker.sh](scripts/celery_worker.sh).
* `pyproject.toml` declares `celery[redis]>=5.6.3`.
* **No `celery beat` is configured.** No periodic task table, no `celery_app.conf.beat_schedule`. Phase 4.1 must introduce beat (and a separate Railway process for it — see §F).

### E.14 Celery introduction status

Already done — see E.13. Phase 4.1's first sub-task ("if Celery is not yet
wired up, introduce it minimally") is **not needed**. We only need to add
beat + a new task. The new task should live alongside `app/workers/tasks.py`
(e.g. add `mirror_nvd` to it, or split into `app/workers/mirror_tasks.py`
to keep the module focused). The cowork prompt's path
`infrastructure/tasks.py` does not match this codebase's layout.

### E.15 BackgroundTask usage

`grep -rn 'BackgroundTask' app/` returns **zero matches**. The "past audit
removed Next.js proxy rewrites and switched to BackgroundTask + run_id"
claim from the cowork prompt is **partially incorrect** for this
repository:

* The `run_id` part is real — `RunCache` ([app/models.py:186](app/models.py#L186)) stores run JSON keyed by an integer id, and routers like `app/routers/pdf.py` and `app/routers/analyze_endpoints.py` thread that id through.
* But the runtime mechanism is **direct `await`** inside the request handler (e.g. `await _run_legacy_analysis(...)` in `analyze_endpoints.py`), with Celery available as the heavy-lifting alternative for SBOM jobs. There is no FastAPI `BackgroundTasks` parameter anywhere.

This affects nothing about the mirror design — periodic mirror runs
should go through Celery beat, not BackgroundTasks — but the discovery
note matters for honesty.

---

## F. Admin / API surface

### F.16 Registered FastAPI routers

From [app/main.py:240-266](app/main.py#L240-L266):

| Router               | Module                              | Prefix (declared)        | Auth                |
|----------------------|-------------------------------------|--------------------------|---------------------|
| `health.router`      | `app/routers/health.py`             | `/`, `/health`, `/api/analysis/config`, `/api/types` | unprotected (some routes use route-level `Depends(require_auth)`) |
| `sboms_crud.router`  | `app/routers/sboms_crud.py`         | (declared in router)     | `_protected` |
| `runs.router`        | `app/routers/runs.py`               | (declared in router)     | `_protected` |
| `projects.router`    | `app/routers/projects.py`           | (declared in router)     | `_protected` |
| `analyze_endpoints.router` | `app/routers/analyze_endpoints.py` | (declared in router) | `_protected` |
| `pdf.router`         | `app/routers/pdf.py`                | (declared in router)     | `_protected` |
| `dashboard_main.router` | `app/routers/dashboard_main.py`  | (declared in router)     | `_protected` |
| `analysis_export_router.router` | `app/routers/analysis.py` | `/api/analysis-runs`     | `_protected` |
| `sbom_features_router.router`   | `app/routers/sbom.py`     | `/api/sboms`             | `_protected` |
| `dashboard_trend_router.router` | `app/routers/dashboard.py` | `/dashboard`            | `_protected` |

### F.17 Auth boundary

Auth is implemented at [app/auth.py](app/auth.py):

* `_protected = [Depends(require_auth)]` is applied to every state-touching
  router in `main.py`.
* `require_auth(authorization: str | None = Header(...))` at
  [app/auth.py:111](app/auth.py#L111) supports three modes:
  * `none` — no-op (the **default**, used in dev). Logs a startup warning.
  * `bearer` — allowlist check via `hmac.compare_digest`.
  * `jwt` — HS256 via `jwt_secret_key`.
* **No "admin"-tier role exists.** Every protected endpoint is equally
  accessible. The mirror's `/admin/nvd-mirror/*` routes therefore have no
  built-in admin-only guard.

> **Phase 4.3 deliverable** must:
> * Use `Depends(require_auth)` for the basic gate, AND
> * Mark with a clear TODO that role-based admin auth is not yet
>   implemented. The cowork prompt explicitly allows this — "guarded by
>   existing admin dependency (or a TODO marker if no auth is in place
>   yet — explicitly flag this)".

---

## G. Bug-fix baseline (sanity check of the 7 prior fixes)

| #  | Bug                                          | Status | Evidence |
|----|-----------------------------------------------|--------|----------|
| a  | OSV CVSS vector string parsing                | ✅ Present | `_best_score_and_vector_from_osv` at [app/analysis.py:830](app/analysis.py#L830). Lines 839-847 detect `CVSS:x.y/...` vector strings, strip the `CVSS:x.y/` prefix, and treat them as vectors not numeric scores. |
| b  | GitHub "MODERATE" severity mapping            | ✅ Present | `GH_SEV_NORM` at [app/sources/severity.py:82](app/sources/severity.py#L82) maps both `MODERATE` and `moderate` → `MEDIUM`. Used by `sev_bucket()` ([severity.py:120-124](app/sources/severity.py#L120-L124)). |
| c  | OSV component version resolution              | ✅ Present | `name_to_ver` lookup built at [app/analysis.py:926](app/analysis.py#L926); applied at [analysis.py:1017](app/analysis.py#L1017) — comment explicitly cites "Bug A3 fix". |
| d  | GHSA null CVSS recovery                       | ✅ Present | [app/analysis.py:1177-1183](app/analysis.py#L1177-L1183) — when `cvss` dict is empty/null, `score`/`vector` stay `None` and `_sev_bucket()` falls back to the textual `n.get("severity")` (which goes through `GH_SEV_NORM`). |
| e  | `CVERecord` parses CVSS v3.x not just v2      | ✅ Present | `cvss_best_base()` at [app/analysis.py:192-207](app/analysis.py#L192-L207) walks v40 → v31 → v2. `extract_best_cvss()` ([app/sources/severity.py:55-78](app/sources/severity.py#L55-L78)) walks v40 → v31 → **v30** → v2. |
| f  | NVD session thread-safety                     | ✅ Present | Module-level `_nvd_session = requests.Session()` at [app/analysis.py:38-40](app/analysis.py#L38-L40). `requests.Session` is documented thread-safe for `.get()`/`.post()` reads (which is the only way it is used here). |
| g  | NVD concurrency 429 mitigation                | ✅ Present | `nvd_query_by_components_async` at [app/analysis.py:1235](app/analysis.py#L1235) is **sequential** (`for idx, cpe in enumerate(cpe_order, 1)` at [line 1330](app/analysis.py#L1330)) with an inter-request `await asyncio.sleep(sleep_s)` at [line 1359](app/analysis.py#L1359). The docstring at lines 1241-1249 explicitly explains the rationale. **Note:** the *other* orchestrator at [app/pipeline/multi_source.py:153-167](app/pipeline/multi_source.py#L153) still uses `asyncio.Semaphore(cfg.max_concurrency)` for fan-out — this is a known second pathway that the mirror replacement will obviate. |

All 7 fixes are in place. **No regressions detected.**

---

## Risks & Open Questions

These need a decision before / during Phase 1 design.

1. **Settings split (D.11).** Adding `cfg.nvd.*` style would touch
   `AnalysisSettings`, every test that constructs it via
   `dataclasses.replace`, and every consumer. **Proposal:** introduce
   `NvdMirrorSettings` as its own dataclass on `_MultiSettings`
   (`mirror: NvdMirrorSettings = field(default_factory=...)` ), giving
   `cfg.mirror.enabled` etc. without touching the existing flat keys.

2. **DB engine duality (C.10).** Dev/tests run on **SQLite**, production
   on **PostgreSQL**. The mirror's `cves` table needs `JSONB` and
   `INSERT ... ON CONFLICT` semantics — both PostgreSQL-only. **Proposal:**
   feature-flag the mirror to default `enabled=False`. Tests run two
   variants: SQLite (mirror disabled, must not regress) and a
   PostgreSQL-via-testcontainers integration test (mirror enabled, full
   path). Document the PG-only requirement in `02-operations.md`.

3. **No `cryptography` or `tenacity` installed (A.3).** Both are required
   by Phase 2/3 (Fernet at-rest encryption; retry on 429/503).
   **Proposal:** add to `pyproject.toml` and re-pin in `requirements.txt`
   in Phase 2.1 as the very first commit.

4. **`structlog` is not used (A.3).** Existing logs use stdlib `logging`
   with `extra={}`/lazy-`%`-format args. **Proposal:** mirror
   observability uses the same convention to stay consistent. Skip
   `structlog`. The cowork prompt allows this ("structlog or stdlib
   `logging` with extra={}").

5. **No admin-only auth (F.17).** `require_auth` is binary
   (authenticated/not). **Proposal:** Phase 4.3 ships with
   `Depends(require_auth)` plus an explicit TODO comment + design-doc note
   for follow-up role split. Flagged in `01-design.md` as out of scope.

6. **Two NVD orchestrators (B.7).** Both `run_multi_source_analysis_async`
   and `nvd_query_by_components_async` ultimately call into
   `nvd_query_by_cpe`/`nvd_query_by_keyword`. **Proposal:** the Phase 5
   facade replaces those two leaf functions, not the orchestrators. The
   adapters (`NvdSource`) and the inline `_fetch_cpe`/`_fetch_keyword`
   closures both already pass through these leaves; routing the leaves
   through `NvdLookupService` covers both call paths with one cut.

7. **`Base.metadata.create_all` at startup (C.9).** The dev path silently
   creates tables outside Alembic. The mirror's new tables would also
   appear via this path — but production must rely on the migration.
   **Proposal:** keep startup `create_all` for dev parity, but the
   production deploy guide must explicitly run `alembic upgrade head`
   before flipping `mirror_enabled=True`.

8. **Fernet key bootstrapping.** The cowork prompt requires
   `NVD_MIRROR_FERNET_KEY` (32 url-safe b64). Operator-friendly note:
   `python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'`.
   Will be documented in Phase 6.3.

9. **Cowork prompt path mismatches.** The prompt names paths
   `nvd_mirror/infrastructure/tasks.py` and `infrastructure/api.py`. This
   repo already has `app/infrastructure/` for s3 storage, and tasks live
   under `app/workers/`. **Proposal:** the new bounded context lives at
   `app/nvd_mirror/` (matching the prompt's package name) but its task
   module is `app/nvd_mirror/tasks.py` and its router is
   `app/nvd_mirror/api.py` — drop the `infrastructure/` sub-folder to
   match local convention. Phase 1 design will lock the tree.

10. **Deferred tools / harness.** Tools like `TodoWrite` and `WebFetch` are
    deferred in this Claude Code session. Phase 0 used `Read`, `Bash`,
    `Write`, and `TodoWrite` (loaded on demand). No external API was
    consulted — this audit is grounded entirely in the local repo.

---

## Go / No-Go Verdict

**GO** — with the proposals from `Risks & Open Questions` 1-9 carried
into Phase 1 design.

The codebase is clean, well-organised, and the bug-fix baseline is
intact. The mirror integrates cleanly via:

* New bounded context at `app/nvd_mirror/`.
* New flat settings dataclass attached to `_MultiSettings.mirror`.
* New Alembic migration for 3 new tables (PostgreSQL-only features
  acceptable; mirror is PG-only by feature-flag default).
* Extension of existing Celery wiring with beat.
* New admin router at `/admin/nvd-mirror/*` guarded by `require_auth`
  with a TODO marker for future admin role.
* A facade that wraps the existing leaf functions
  `nvd_query_by_cpe` / `nvd_query_by_keyword` so both existing
  orchestrators inherit the mirror path with one cut.

Proceed to Phase 1 design.
