# Phase 1 — Discovery & Inventory

> Read-only snapshot of the SBOM Analyzer codebase as of 2026-04-28, branch `main`, head `4435bd2`. Every entry below was confirmed by reading the corresponding file (`Read` tool) or by grep. Anything I could not verify statically is marked **`[REQUIRES VERIFICATION]`**.

---

## 1. Directory tree (depth ≤ 4, excludes `node_modules`, `.next`, `__pycache__`, `.venv`, `dist`, `build`, `.git`, `.pytest_cache`)

```
.
├── alembic/
│   └── versions/
├── app/                              # FastAPI backend
│   ├── analysis.py                   # 1433 lines — legacy multi-source orchestrator
│   ├── auth.py                       # 160 lines — none / bearer / JWT
│   ├── credentials.py                # 25 lines — settings → adapter token plumbing
│   ├── db.py                         # 62 lines — SQLAlchemy engine/session
│   ├── etag.py                       # 26 lines — conditional GET helper
│   ├── http_client.py                # 56 lines — shared async httpx client
│   ├── idempotency.py                # 119 lines — in-memory Idempotency-Key cache
│   ├── infrastructure/
│   │   └── s3_storage.py             # 61 lines — S3 adapter
│   ├── logger.py                     # 173 lines — logging setup
│   ├── main.py                       # 271 lines — app construction + startup hook
│   ├── models.py                     # 199 lines — SQLAlchemy ORM
│   ├── nvd_mirror/                   # NVD mirror sub-app (hexagonal)
│   │   ├── adapters/                 # SQLAlchemy / HTTP / Fernet adapters
│   │   ├── application/              # facade, freshness, _window_walker, query, …
│   │   ├── api.py                    # 223 lines — admin router
│   │   ├── db/models.py              # 175 lines — ORM
│   │   ├── domain/                   # mappers + domain models
│   │   ├── observability.py          # counters
│   │   ├── ports/                    # Protocol contracts
│   │   ├── schemas.py                # 117 lines — pydantic
│   │   ├── settings.py               # 123 lines
│   │   └── tasks.py                  # 291 lines — celery `mirror_nvd`
│   ├── parsing/                      # SBOM format detection / extraction
│   ├── pdf_report.py                 # 651 lines — reportlab generator
│   ├── pipeline/
│   │   ├── context.py
│   │   └── multi_source.py           # 329 lines — second copy of multi-source orchestrator
│   ├── ports/
│   │   ├── repositories.py           # 57 lines — Protocol shells
│   │   └── storage.py                # 18 lines
│   ├── rate_limit.py                 # 60 lines — slowapi wrapper
│   ├── repositories/                 # ★ Dead code (see §6)
│   │   ├── analysis_repo.py          # 197 lines — references non-existent ORM cols
│   │   ├── component_repo.py         # 144 lines
│   │   ├── project_repo.py           # 128 lines
│   │   └── sbom_repo.py              # 206 lines — references non-existent cols
│   ├── routers/
│   │   ├── analysis.py               # 236 lines — SARIF/CSV/compare
│   │   ├── analyze_endpoints.py      # 416 lines — 5 ad-hoc analyze endpoints
│   │   ├── dashboard.py              # 48 lines — /dashboard/trend
│   │   ├── dashboard_main.py         # 83 lines — /dashboard/{stats,recent-sboms,…}
│   │   ├── health.py                 # 163 lines — /, /health, /api/types, …
│   │   ├── pdf.py                    # 157 lines — /api/pdf-report
│   │   ├── projects.py               # 179 lines — projects CRUD
│   │   ├── runs.py                   # 178 lines — analysis runs / findings
│   │   ├── sbom.py                   # 161 lines — risk-summary / info
│   │   └── sboms_crud.py             # 949 lines — SBOM CRUD + analyze + analyze/stream
│   ├── samples/
│   ├── schemas.py                    # 203 lines — pydantic schemas
│   ├── services/                     # Service layer (partial)
│   │   ├── analysis_service.py       # 309 lines
│   │   ├── dashboard_service.py      # 361 lines — alternate dashboard impl (orphaned)
│   │   ├── pdf_service.py            # 237 lines
│   │   └── sbom_service.py           # 288 lines
│   ├── settings.py                   # 269 lines — pydantic-settings + class-bolted constants
│   ├── sources/                      # Vulnerability source adapter package
│   │   ├── base.py                   # 66 lines — VulnSource Protocol
│   │   ├── cpe.py                    # 127 lines — PURL → CPE 2.3
│   │   ├── dedupe.py                 # 67 lines — alias merge
│   │   ├── factory.py                # 56 lines
│   │   ├── ghsa.py                   # 60 lines — delegates to analysis.py
│   │   ├── nvd.py                    # 47 lines — delegates to analysis.py
│   │   ├── osv.py                    # 44 lines — delegates to analysis.py
│   │   ├── osv_fallback.py           # 138 lines
│   │   ├── purl.py                   # 59 lines
│   │   ├── registry.py               # 37 lines
│   │   ├── runner.py                 # 121 lines — async fan-out
│   │   ├── severity.py               # 125 lines
│   │   └── vulndb.py                 # 348 lines — full implementation in adapter
│   ├── utils.py                      # 92 lines — orphan helpers
│   └── workers/
│       ├── celery_app.py             # 47 lines
│       └── tasks.py                  # 29 lines — `run_sbom_analysis` (never enqueued)
├── audit/                            # ← This audit
├── docs/
│   └── nvd-mirror/
├── frontend/                         # Next.js (App Router) frontend
│   ├── next.config.mjs
│   ├── package.json                  # ★ next: ^9.3.3 (incompatible with App Router)
│   ├── tsconfig.json                 # strict: true
│   └── src/
│       ├── app/                      # App Router routes
│       │   ├── analysis/[id]/page.tsx     # 260 lines
│       │   ├── analysis/compare/page.tsx  # 301 lines
│       │   ├── analysis/page.tsx          # 422 lines
│       │   ├── projects/page.tsx          # 45  lines
│       │   ├── sboms/[id]/page.tsx        # 57  lines
│       │   ├── sboms/page.tsx             # 67  lines
│       │   ├── layout.tsx
│       │   ├── page.tsx                   # 77 lines (home)
│       │   ├── providers.tsx
│       │   └── globals.css
│       ├── components/
│       │   ├── analysis/{AnalysisProgress,FindingsTable,RunsTable}.tsx
│       │   ├── dashboard/{ActivityChart,RecentSboms,SeverityChart,StatsGrid,TrendChart}.tsx
│       │   ├── layout/{AppShell,Sidebar,SidebarContext,TopBar}.tsx
│       │   ├── projects/{ProjectModal,ProjectsTable}.tsx
│       │   ├── sboms/{SbomDetail,SbomStatusBadge,SbomUploadModal,SbomsTable}.tsx
│       │   ├── theme/{ThemeProvider,ThemeToggle}.tsx
│       │   └── ui/{Alert,Badge,Button,Card,Dialog,Input,Select,Spinner,Table,TableFilterBar,Toast}.tsx
│       ├── hooks/{useAnalysisStream,useBackgroundAnalysis,usePendingAnalysisRecovery,useToast}.ts(x)
│       ├── lib/{analysisRunStatusLabels,api,env,env.test,pendingAnalysis,tableFilters,utils}.ts
│       └── types/index.ts             # 231 lines — single source of TS types
├── samples/
├── scripts/
└── tests/
    ├── conftest.py
    ├── _normalize.py
    ├── fixtures/{conftest,…}/
    ├── nvd_mirror/                    # 13 mirror tests
    ├── snapshots/                     # JSON fixtures for analyze endpoint tests
    └── test_*.py                      # auth, sources_adapters, analyze_endpoints_snapshot, …
```

Top-level files of note: `ADR-001-architecture-audit.md` (34 KB), `PROJECT_LENS_REPORT*.md` (105 KB combined), `Testing.md`, `README.md`, `Dockerfile`, `pyproject.toml`, `requirements.txt`, `alembic.ini`, `pytest.ini`, `railway.toml`, `run.py`, `sbom.json`, `.env.example`.

---

## 2. Backend module map

### 2.1 `app/` (top level)

| Module | Purpose | Public surface | Direct downstream deps |
|---|---|---|---|
| `main.py` | FastAPI app construction, lifespan, routing, middleware. | `app` | `auth`, `db`, `http_client`, `rate_limit`, `routers.*`, `settings`, `nvd_mirror.api`, `services.analysis_service.backfill_analytics_tables`, `services.sbom_service.now_iso` |
| `db.py` | SQLAlchemy engine, `Base`, `SessionLocal`, FK pragma for SQLite. | `engine`, `Base`, `SessionLocal`, `get_db` | `settings.get_settings` |
| `models.py` | ORM tables: `Projects`, `SBOMType`, `SBOMSource`, `SBOMAnalysisReport`, `SBOMComponent`, `AnalysisRun`, `AnalysisFinding`, `RunCache`. | All seven model classes. | `db.Base` |
| `schemas.py` | Pydantic schemas (Project/SBOM/Analysis Create/Out/Update + `AnalysisRunSummary`). Bridges to ORM via `from_attributes=True`. | 12 classes. | pydantic |
| `settings.py` | `Settings(BaseSettings)` plus a long block of `Settings.X = "…"` runtime monkey-patches and `get_settings()/reset_settings()` singletons. | `Settings`, `get_settings`, `reset_settings`, `get_analysis_legacy_level`. | pydantic, pydantic_settings |
| `auth.py` | `require_auth` FastAPI dep + `validate_auth_setup` startup check. Modes: none / bearer allowlist / JWT HS256. | `require_auth`, `validate_auth_setup`, `AuthConfigError`. | `settings`, `pyjwt` |
| `credentials.py` | Helpers reading NVD/GitHub/VulDB tokens from `Settings`. | `nvd_api_key_for_adapters`, `github_token_for_adapters`, `vulndb_api_key_for_adapters`. | `settings` |
| `http_client.py` | App-scoped `httpx.AsyncClient` lifecycle. | `init_async_http_client`, `get_async_http_client`, `close_async_http_client`. | httpx |
| `rate_limit.py` | slowapi `Limiter` keyed by IP+token-hash. | `limiter`, `analyze_route_limit`, `rate_limit_exceeded_handler`, `rate_limit_key`. | slowapi |
| `idempotency.py` | In-memory `(scope, key) → response` cache (24h TTL) keyed by SHA256. | `run_idempotent`, `get_cached`, `put_cached`, `analysis_run_to_dict`, `normalize_idempotency_key`. | `schemas.AnalysisRunOut` |
| `etag.py` | `maybe_not_modified` for JSON conditional GETs. | one function. | hashlib |
| `logger.py` | logging config. | `setup_logging`, `get_logger`. | stdlib |
| `pdf_report.py` | reportlab PDF builder. | `build_pdf_from_run_bytes` (and many private helpers). | reportlab |
| `analysis.py` | **Legacy hub** — 1.4k lines. Contains `CVERecord` dataclass, `AnalysisSettings`, `_MultiSettings`, `_async_get/_async_post`, `nvd_query_by_cpe`, `nvd_query_by_keyword`, `osv_query_by_components`, `github_query_by_components`, `enrich_component_for_osv`, `_finding_from_raw`, `extract_cwe_from_*`, `extract_fixed_versions_osv`, etc. Re-exports `extract_components`, `parse_purl`, `cpe23_from_purl`, severity helpers, and `deduplicate_findings` from the new `app/sources/`. | Many. | `nvd_mirror.settings`, `parsing`, `sources.*`, `pipeline.multi_source` (lazy), httpx/requests |
| `utils.py` | `now_iso`, `safe_int`, `safe_float`, `normalized_key`, `compute_report_status`, `normalize_details`. **Verified zero importers** (`grep -rn "from .*utils"` returns no app-side users). | All free functions. | none |

### 2.2 `app/parsing/`

| File | Purpose | Public surface |
|---|---|---|
| `__init__.py` | re-exports `extract_components`, `detect_sbom_format`. | – |
| `extract.py` | Format-aware dispatcher (CycloneDX dict / SPDX dict / XML / JSON string). | `extract_components` |
| `format.py` | `detect_sbom_format(doc) → (format_name, spec_version)`. | `detect_sbom_format` |
| `cyclonedx.py` | CycloneDX JSON+XML parser. | `parse_cyclonedx_dict`, `parse_cyclonedx_xml` |
| `spdx.py` | SPDX JSON+XML parser. | `parse_spdx_dict`, `parse_spdx_xml` |
| `common.py` / `xml_support.py` / `registry.py` | Shared helpers. | – |

### 2.3 `app/sources/` (vulnerability source adapters)

| File | Purpose | Public surface |
|---|---|---|
| `base.py` | `VulnSource` Protocol (`name: str`, `async query(components, settings) → SourceResult`); `SourceResult` TypedDict; `empty_result()`. | – |
| `cpe.py` | `slug`, `cpe23_from_purl` (per-ecosystem heuristics for pypi/npm/maven/golang/rubygems/nuget/composer/cargo). | – |
| `purl.py` | `parse_purl` (PURL parser). | – |
| `severity.py` | `safe_score`, `parse_cvss_attack_vector`, `cvss_version_from_metrics`, `extract_best_cvss`, `sev_bucket`, `GH_SEV_NORM`. | – |
| `dedupe.py` | `deduplicate_findings` — two-pass CVE↔GHSA alias union merge. | – |
| `osv_fallback.py` | OSV `/v1/query` per-component fallback used by `analysis.osv_query_by_components`. | – |
| `nvd.py` | `NvdSource` — **delegates** to `app.analysis.nvd_query_by_components_async` via lazy import. | – |
| `osv.py` | `OsvSource` — **delegates** to `app.analysis.osv_query_by_components`. | – |
| `ghsa.py` | `GhsaSource` — **delegates** to `app.analysis.github_query_by_components` after `dataclasses.replace(settings, gh_token_override=…)`. | – |
| `vulndb.py` | `VulnDbSource` — full self-contained implementation (no delegation to legacy). | – |
| `factory.py` | `DEFAULT_ANALYSIS_SOURCES`, `SUPPORTED_ANALYSIS_SOURCES`, `normalize_source_names`, `configured_default_sources`, `build_source_adapters` (uses `credentials` module to bind keys at construction). | – |
| `registry.py` | `SOURCE_REGISTRY: dict[str, type[VulnSource]]`, `get_source(name)`. | – |
| `runner.py` | `run_sources_concurrently(sources, components, settings, progress_queue=None)` + `EVENT_RUNNING/COMPLETE/ERROR/DONE`. | – |
| `__init__.py` | public façade re-exporting all of the above. | – |

### 2.4 `app/pipeline/`

| File | Purpose |
|---|---|
| `context.py` | (28 lines) tiny dataclass for pipeline context. |
| `multi_source.py` | `run_multi_source_analysis_async(sbom_json, sources, settings)` — **second** orchestrator. Imports legacy NVD/OSV/GHSA functions, builds VulDB via `VulnDbSource`, calls `nvd_mirror.application.build_nvd_lookup_for_pipeline()` for CPE lookups, fans coroutines via `asyncio.gather`, dedupes via `sources.dedupe`. Called only from `app.workers.tasks.run_sbom_analysis` and from the `app.analysis.analyze_sbom_multi_source_async` re-export. |

### 2.5 `app/services/`

| File | Purpose | Public surface |
|---|---|---|
| `analysis_service.py` | `legacy_analysis_level`, `normalize_details`, `compute_report_status`, `persist_analysis_run` (alternative to the one in `routers/sboms_crud.py`), `backfill_analytics_tables` (called from `main.py` startup). | – |
| `sbom_service.py` | `now_iso`, `normalized_key`, `safe_int`, `coerce_sbom_data`, `load_json_bytes_with_fallback`, `sync_sbom_components`, `_upsert_components`, `resolve_component_id`, `load_sbom_from_ref`. | – |
| `dashboard_service.py` | `get_stats`, `get_recent_sboms`, `get_activity`, `get_severity_distribution`, `get_component_stats`, `get_run_status_distribution`, `get_top_vulnerable_components`, `get_top_vulnerabilities`. **Not imported by any router.** Routers/dashboard*.py compute these inline. | – |
| `pdf_service.py` | `load_run_cache`, `store_run_cache`, `rebuild_run_from_db`, `generate_pdf_report`. `routers/pdf.py` uses only `load_run_cache` (it has its own copy of `_rebuild_run_from_db`). | – |

### 2.6 `app/repositories/` — **dead code**

`grep -rn "from .repositories\|from ..repositories\|from app.repositories"` outside the package itself returns **no results** — nothing imports any of these classes.

| File | Notes |
|---|---|
| `sbom_repo.py` | `SBOMRepository.delete_sbom` references `AnalysisFinding.run_id`, `SBOMSource.project_id`, and `SBOMAnalysisReport.sbom_id` — none of these attributes exist on the actual ORM models (`analysis_run_id`, `projectid`, `sbom_ref_id`). Calling it would raise `AttributeError` at runtime. `sbom_name_exists` filters on `SBOMSource.name`, but the column is `sbom_name`. |
| `analysis_repo.py` | `list_runs` filters on `AnalysisRun.status` (column is `run_status`). `list_findings` filters on `AnalysisFinding.run_id` (column is `analysis_run_id`). `store_run_cache` writes `cached_at=…` (column is `created_on`). Three runtime-broken methods. |
| `component_repo.py` | `upsert_components` works because it uses real columns, but no caller reaches it. |
| `project_repo.py` | (not read in detail; same pattern). |

### 2.7 `app/ports/`

| File | Purpose |
|---|---|
| `repositories.py` | `SBOMRepositoryPort`, `AnalysisRepositoryPort` Protocols — describe the dead repository surface. No service in production accepts these as a typed parameter. |
| `storage.py` | `StoragePort` Protocol (S3-shaped). No production caller. |

### 2.8 `app/infrastructure/`

| File | Purpose |
|---|---|
| `s3_storage.py` | S3-compatible blob storage adapter. Not wired into any router/service. **`[REQUIRES VERIFICATION]`** that no caller exists outside what `grep` finds. |

### 2.9 `app/workers/`

| File | Purpose |
|---|---|
| `celery_app.py` | Builds the Celery app, sets up `nvd-mirror-hourly` beat schedule. |
| `tasks.py` | `run_sbom_analysis` Celery task — wraps `pipeline.multi_source.run_multi_source_analysis_async` with `asyncio.run`. **Verified: zero `.delay()` / `.apply_async()` calls anywhere in the codebase.** Task is defined and imported by `celery_app.include` but never enqueued. |

### 2.10 `app/nvd_mirror/` (hexagonal sub-app)

| File / dir | Purpose |
|---|---|
| `api.py` | Admin router `/admin/nvd-mirror/{settings,sync,sync/status,watermark/reset}`. Carries `require_auth` (no admin role split — explicit `TODO`). |
| `domain/models.py` | `NvdSettingsSnapshot`, `CveRecord`, `SyncRunRecord`, etc. |
| `domain/mappers.py` | NVD raw JSON → domain mappers. |
| `db/models.py` | SQLAlchemy ORM (`nvd_settings`, `cve`, `sync_run`). |
| `ports/` | `ClockPort`, `RemotePort`, `SecretsPort`, `SettingsRepositoryPort`, `CveRepositoryPort`, `SyncRunRepositoryPort` — Protocol shells. |
| `adapters/` | Concrete adapters: `clock.py` (system clock), `cve_repository.py`, `nvd_http.py`, `secrets.py` (Fernet), `settings_repository.py`, `sync_run_repository.py`. |
| `application/` | Use-cases: `bootstrap.py`, `incremental.py`, `_window_walker.py` (private helper for paged window walks), `query.py`, `freshness.py`, `facade.py` (`NvdLookupService` + `SessionScopedNvdLookupService` + `build_nvd_lookup_for_pipeline`). |
| `tasks.py` | Celery `mirror_nvd` task. |
| `observability.py` | In-memory counter dict. |
| `schemas.py` | Pydantic schemas for the admin router. |
| `settings.py` | `NvdMirrorSettings` dataclass + env loader. |

### 2.11 `app/routers/`

| Router | Prefix / Tag | Endpoints |
|---|---|---|
| `health.py` | – | `GET /`, `GET /health`, `GET /api/analysis/config`, `GET /api/types`. |
| `sboms_crud.py` | `/api` `[sboms]` | `GET/POST/PATCH/DELETE /sboms`, `GET /sboms/{id}/components`, `POST /sboms/{id}/analyze`, `POST /sboms/{id}/analyze/stream` (SSE). Contains its own `compute_report_status`, `persist_analysis_run`, `upsert_components`, `now_iso`, `_validate_user_id`, `_validate_positive_int`, `create_auto_report`. |
| `runs.py` | `/api` `[runs]` | `GET /runs`, `GET /runs/{id}`, `GET /runs/{id}/findings`. |
| `projects.py` | `/api` `[projects]` | Projects CRUD. |
| `analyze_endpoints.py` | – `[analyze]` | `POST /analyze-sbom-{nvd,github,osv,vulndb,consolidated}` — all delegate to `_run_legacy_analysis`. |
| `pdf.py` | `/api` `[pdf]` | `POST /api/pdf-report`. Contains its own copy of `_rebuild_run_from_db`. |
| `analysis.py` | `/api/analysis-runs` `[analysis-export]` | `GET /compare`, `GET /{run_id}/export/sarif`, `GET /{run_id}/export/csv`. |
| `sbom.py` | `/api/sboms` `[sbom-features]` | `GET /{sbom_id}/risk-summary`, `GET /{sbom_id}/info`. |
| `dashboard.py` | `/dashboard` `[dashboard-trend]` | `GET /trend`. |
| `dashboard_main.py` | `/dashboard` `[dashboard]` | `GET /stats`, `GET /recent-sboms`, `GET /activity`, `GET /severity`. |

---

## 3. Frontend module map

### 3.1 Routes (`frontend/src/app/`)

| Route | File | Notes |
|---|---|---|
| `/` | `app/page.tsx` (77) | Home dashboard. `'use client'` (whole page is client). |
| `/projects` | `app/projects/page.tsx` (45) | Client-only. |
| `/sboms` | `app/sboms/page.tsx` (67) | Client-only; uses `usePendingAnalysisRecovery`. |
| `/sboms/[id]` | `app/sboms/[id]/page.tsx` (57) | Client-only. |
| `/analysis` | `app/analysis/page.tsx` (422) | Largest route — runs list, filters, exports. |
| `/analysis/[id]` | `app/analysis/[id]/page.tsx` (260) | Run detail + findings table. |
| `/analysis/compare` | `app/analysis/compare/page.tsx` (301) | Two-run diff. |
| layout / providers | `app/layout.tsx`, `app/providers.tsx` | React Query + theme + toast providers. |

### 3.2 Components (`frontend/src/components/`)

All of the 28 component files declare `'use client'` at the top — no server components in use. Domain groups: `analysis/{AnalysisProgress,FindingsTable,RunsTable}`, `dashboard/{ActivityChart,RecentSboms,SeverityChart,StatsGrid,TrendChart}`, `layout/{AppShell,Sidebar,SidebarContext,TopBar}`, `projects/{ProjectModal,ProjectsTable}`, `sboms/{SbomDetail,SbomStatusBadge,SbomUploadModal,SbomsTable}`, `theme/{ThemeProvider,ThemeToggle}`, `ui/{Alert,Badge,Button,Card,Dialog,Input,Select,Spinner,Table,TableFilterBar,Toast}`.

### 3.3 Hooks (`frontend/src/hooks/`)

| Hook | File | Purpose |
|---|---|---|
| `useAnalysisStream` | `useAnalysisStream.ts` (277) | Manual `fetch` + ReadableStream SSE parser; tracks per-source progress + final summary. |
| `useBackgroundAnalysis` | `useBackgroundAnalysis.ts` (128) | Fire-and-forget consolidated analysis; updates React Query cache + toasts; uses `dispatchSbomStatus` `CustomEvent`. |
| `usePendingAnalysisRecovery` | `usePendingAnalysisRecovery.ts` (46) | sessionStorage replay of in-flight analyses across reload. |
| `useToast` | `useToast.tsx` (186) | Toast Provider/hook. |

### 3.4 Library (`frontend/src/lib/`)

| File | Purpose |
|---|---|
| `api.ts` (509) | Single typed fetch client. ~30 endpoint functions, manual URL strings, custom `HttpError`. |
| `env.ts` (37) | `resolveBaseUrl()` reads `NEXT_PUBLIC_API_URL` (no fallback). |
| `env.test.ts` (56) | Vitest tests for `env.ts`. |
| `pendingAnalysis.ts` (58) | sessionStorage helpers. |
| `tableFilters.ts` (15) | URL search-param helpers. |
| `analysisRunStatusLabels.ts` (79) | Status enum → label/colour. |
| `utils.ts` (92) | `cn`, `formatDate`, etc. |

### 3.5 Types (`frontend/src/types/index.ts`)

Single 231-line file. Domain interfaces: `Project`, `SBOMSource`, `SBOMComponent`, `AnalysisRun`, `AnalysisFinding`, `DashboardStats`, `RecentSbom`, `ActivityData`, `SeverityData`, `SBOMType`, `ApiError`, `CreateProjectPayload`, `UpdateProjectPayload`, `CreateSBOMPayload`, `UpdateSBOMPayload`, `AnalyzeSBOMPayload`, `PDFReportPayload`, `SBOMInfo`, `RiskComponent`, `SBOMRiskSummary`, `DashboardTrendPoint`, `DashboardTrend`, `CompareRunsResult`, `ConsolidatedAnalysisResult`. The last has `[key: string]: unknown` — escape hatch.

---

## 4. Domain model inventory

### 4.1 SQLAlchemy ORM ([`app/models.py`](../app/models.py))

| Class | Table | Notable columns |
|---|---|---|
| `Projects` | `projects` | `id`, `project_name`, `project_details`, `project_status` (1/0), `created_*`, `modified_*`. |
| `SBOMType` | `sbom_type` | `id`, `typename` (unique), `type_details`, audit. |
| `SBOMSource` | `sbom_source` | `id`, `sbom_name`, `sbom_data` (Text), `sbom_type` (FK→sbom_type.id), `projectid` (FK→projects.id), `sbom_version`, `productver`, audit. |
| `SBOMAnalysisReport` | `sbom_analysis_report` | `id`, `sbom_ref_id` (FK), `sbom_result`, `project_id` (str — legacy), `analysis_details` (Text), `reference_source`, `sbom_analysis_level`. |
| `SBOMComponent` | `sbom_component` | `id`, `sbom_id` (FK), `bom_ref`, `component_type`, `component_group`, `name`, `version`, `purl`, `cpe`, `supplier`, `scope`, `created_on`. Unique on `(sbom_id, bom_ref, name, version, cpe)`. |
| `AnalysisRun` | `analysis_run` | `id`, `sbom_id` (FK), `project_id` (FK), `run_status`, `sbom_name`, `source`, `started_on`, `completed_on`, `duration_ms`, severity counts, `query_error_count`, `raw_report` (Text). |
| `AnalysisFinding` | `analysis_finding` | `id`, `analysis_run_id` (FK), `component_id` (FK), `vuln_id`, `source`, `title`, `description`, `severity`, `score`, `vector`, `published_on`, `reference_url`, `cwe`, `cpe`, `component_name`, `component_version`, `fixed_versions` (JSON-as-string), `attack_vector`, `cvss_version`, `aliases` (JSON-as-string). Unique on `(analysis_run_id, vuln_id, cpe)`. |
| `RunCache` | `run_cache` | `id`, `run_json` (Text), `created_on`, `source`, `sbom_id`. |

NVD-mirror ORM lives separately under [`app/nvd_mirror/db/models.py`](../app/nvd_mirror/db/models.py) (`nvd_settings`, `cve`, `sync_run`).

### 4.2 Pydantic schemas ([`app/schemas.py`](../app/schemas.py))

`ORMModel` (base with `from_attributes=True`) → `ProjectOut`, `SBOMTypeOut`, `SBOMSourceOut`, `SBOMComponentOut`, `AnalysisRunOut`, `AnalysisRunSummary`, `AnalysisFindingOut`, `SBOMAnalysisReportOut`. Mutating: `ProjectCreate`, `ProjectUpdate`, `SBOMTypeCreate`, `SBOMSourceCreate`, `SBOMSourceUpdate`, `SBOMAnalysisReportCreate`. Notable: `_coerce_project_status` accepts `"Active"` / `"Inactive"` strings or 0/1 ints. NVD-mirror has a separate set in [`app/nvd_mirror/schemas.py`](../app/nvd_mirror/schemas.py).

### 4.3 TypeScript types

Single source in [`frontend/src/types/index.ts`](../frontend/src/types/index.ts). Each interface should mirror the corresponding `*Out` Pydantic schema. Drift seen on inspection:
* `AnalysisRun` declares `error_message: string | null` — backend `AnalysisRunOut` does not have `error_message`.
* `SBOMRiskSummary.components: RiskComponent[]` — verified vs `routers/sbom.py:91-96` (matches).
* `ConsolidatedAnalysisResult` is loose: `[key: string]: unknown`; the actual returned shape from `analyze_endpoints._run_legacy_analysis` has both `runId` and `id` (legacy alias) plus a nested `summary` block.

Full drift audit happens in `09_cross_cutting.md`.

---

## 5. External integration inventory

| Integration | Caller(s) | Notes |
|---|---|---|
| NVD CVE 2.0 REST (`https://services.nvd.nist.gov/rest/json/cves/2.0`) | `app.analysis.nvd_query_by_cpe` (sync via `requests.Session`), `app.analysis.nvd_query_by_keyword` (sync), and indirectly via `app.pipeline.multi_source._fetch_cpe → nvd_lookup_service.query_legacy → live_query` and via `app.sources.nvd.NvdSource.query → app.analysis.nvd_query_by_components_async`. Mirror path: `app.nvd_mirror.adapters.nvd_http`. | Two HTTP libraries used (`requests` for sync, `httpx` for async). SSL bundle pinned to `certifi.where()` — kept after a stat-on-SSLContext bug. |
| OSV `/v1/querybatch` + `/v1/vulns/{id}` (`https://api.osv.dev`) | `app.analysis.osv_query_by_components` (async via `app.analysis._async_post/_async_get`). Per-component fallback in `app.sources.osv_fallback`. | – |
| GitHub Advisory GraphQL (`https://api.github.com/graphql`) | `app.analysis.github_query_by_components`. | – |
| VulDB form API (`https://vuldb.com/?api`) | `app.sources.vulndb.VulnDbSource._post_vulndb_form` → uses `app.http_client.get_async_http_client` if available else its own httpx client. | – |
| Redis (Celery broker/backend) | `app.workers.celery_app`, `app.nvd_mirror.tasks`. | – |
| S3-compatible | `app.infrastructure.s3_storage`. **Not wired in.** | – |
| Database (Postgres or SQLite) | All routers/services via `app.db.SessionLocal`. | – |

---

## 6. Test inventory

### 6.1 Backend tests (`tests/`)

| File | Lines | Covers |
|---|---|---|
| `conftest.py` | – | Fixtures: in-memory SQLite, FastAPI TestClient, env reset. **`[REQUIRES VERIFICATION]`** of fixture details. |
| `test_auth.py` | – | `require_auth` modes: none, bearer allowlist, JWT. |
| `test_sources_adapters.py` | – | Source adapter shapes against fakes. |
| `test_analyze_endpoints_snapshot.py` + `tests/snapshots/*.json` | – | Snapshot tests for `analyze-sbom-{nvd,github,osv,consolidated}` shapes. |
| `test_sboms_analyze_snapshot.py` | – | `POST /api/sboms/{id}/analyze` shape. |
| `test_sboms_analyze_stream.py` | – | SSE streaming (`/api/sboms/{id}/analyze/stream`). |
| `test_nvd_cpe_query.py` | – | `nvd_query_by_cpe` request shaping. |
| `test_nvd_perf_guards.py` | – | Pagination caps, retry caps. |
| `test_nvd_ssl_regression.py` | – | Regression for SSLContext cert-bundle bug. |
| `nvd_mirror/test_*.py` (13 files) | – | Domain models, mappers, adapters (cve_repository, settings_repository, sync_run_repository, http, secrets), facade (5 decision branches), use-cases, observability, settings, tasks, API. |

### 6.2 Frontend tests (`frontend/src/lib/env.test.ts`)

A single 56-line vitest file covering `resolveBaseUrl`. **No tests for** `api.ts`, `useAnalysisStream`, `useBackgroundAnalysis`, `pendingAnalysis`, `analysisRunStatusLabels`, components, or routes. (Verified by `find frontend/src -name '*.test.*'`.)

### 6.3 Obvious gaps

* No integration test for `services.dashboard_service.*` (it isn't wired).
* No test for the dead `app/repositories/*` classes (which would in fact fail).
* No test exercising `app.workers.tasks.run_sbom_analysis` end-to-end.
* No test for `app.infrastructure.s3_storage`.
* No frontend tests for `useAnalysisStream` SSE parser or `useBackgroundAnalysis` cache logic.
* No contract test cross-checking Pydantic `*Out` schemas against TypeScript interfaces.

---

## 7. Notable structural facts (carried forward to Phase 2)

These are stated here as **inventory observations**, not findings yet. Each will be re-cited with severity in the principle audits.

1. **`next: ^9.3.3` is installed** — verified at `frontend/node_modules/next/package.json` (`"version": "9.3.3"`). The codebase uses App Router (`frontend/src/app/`), Server/Client component split, `'use client'` directives — none of which exist in Next 9 (App Router landed in Next 13). The previous commit (`3e744ed`) had `"next": "^16.2.2"`; the change `90beab6 chore: downgrade next dependency to version 9.3.3` is the most recent commit. **Front-end will not build with the lockfile state.** **`[REQUIRES VERIFICATION]`** by running `pnpm/npm run build` — but this is mechanical: Next 9 has no `next/font`, no `app/` router, no `Server Components`.
2. **Two competing multi-source orchestrators** — `app.analysis.analyze_sbom_multi_source_async` (re-exports to `pipeline.multi_source.run_multi_source_analysis_async`) AND the registry-based `app.sources.runner.run_sources_concurrently`. Production routers (`sboms_crud.create_auto_report`, the SSE stream, and all five `analyze_endpoints` routes) use `run_sources_concurrently`; the older orchestrator is reachable only via the never-enqueued Celery task and the `analyze_sbom_multi_source_async` re-export.
3. **`app/repositories/`** is unused dead code; some methods reference non-existent ORM columns and would `AttributeError` if invoked.
4. **`app/services/dashboard_service.py`** (361 lines) is unused — `routers/dashboard.py` and `routers/dashboard_main.py` compute their own metrics inline.
5. **Three copies of `now_iso`/`safe_int`/`compute_report_status`/`normalized_key`** at `app/utils.py`, `app/services/sbom_service.py`, `app/services/analysis_service.py`, plus inline duplicates in `app/routers/sboms_crud.py` and `app/routers/projects.py`. `app/utils.py` itself has no importers.
6. **Two copies of `_rebuild_run_from_db`** — one in `app/services/pdf_service.py`, one in `app/routers/pdf.py`. The router uses its own copy.
7. **Two copies of `persist_analysis_run` + `compute_report_status`** — one in `app/services/analysis_service.py`, one in `app/routers/sboms_crud.py`. Production endpoints use the router's copy; the service copy is invoked only by `backfill_analytics_tables`.
8. **`Settings` mutated post-class-definition** — `app/settings.py:210-231` runs eight `Settings.X = …` statements. Pydantic v2 `BaseSettings` does not mark these as fields, so they appear as plain class attributes that won't be touched by env-var loading or `.model_dump()`.
9. **`app.analysis` is a god module** — 1.4k lines, mixes dataclasses, env reading, two `lru_cache`'d settings factories, sync HTTP, async HTTP, OSV/GHSA/NVD logic, and re-exports from the new package.
10. **Source adapters delegate back into `app.analysis`** — `NvdSource`, `OsvSource`, `GhsaSource` each do a lazy import into the legacy module ("phase 5 will move it" per docstrings). The split is incomplete.

---

**Phase 1 inventory complete.** Files read directly: `app/main.py`, `app/db.py`, `app/models.py`, `app/schemas.py`, `app/settings.py`, `app/auth.py`, `app/credentials.py`, `app/idempotency.py`, `app/etag.py`, `app/rate_limit.py`, `app/utils.py`, `app/analysis.py` (full 1433 lines), `app/parsing/__init__.py`, `app/parsing/extract.py`, `app/pipeline/multi_source.py`, `app/sources/{__init__,base,nvd,osv,ghsa,vulndb,registry,factory,runner,severity,cpe,dedupe}.py`, `app/services/{__init__,sbom_service,analysis_service,dashboard_service,pdf_service}.py`, `app/repositories/{__init__,sbom_repo,analysis_repo,component_repo}.py`, `app/ports/{__init__,repositories}.py`, `app/workers/{celery_app,tasks}.py`, `app/nvd_mirror/{api.py, application/facade.py}`, all of `app/routers/*.py`, `frontend/package.json`, `frontend/tsconfig.json`, `frontend/next.config.mjs`, `frontend/src/lib/api.ts`, `frontend/src/types/index.ts`, `frontend/src/hooks/{useAnalysisStream,useBackgroundAnalysis}.ts`, `frontend/node_modules/next/package.json`. Anything beyond that range is stated only when independently verifiable by `grep` and is so noted.
