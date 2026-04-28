# Phase 2.2 — SOLID Audit

> SRP · OCP · LSP · ISP · DIP. Severities are calibrated to *this* codebase: a 1.4k-line god-module rates High, not Critical.

---

## Single Responsibility Principle (SRP)

### Finding SOLID-SRP-001: `app/analysis.py` is a god module (1433 lines, ~7 responsibilities)

- **Principle violated:** SRP
- **Severity:** High
- **Location:** [app/analysis.py:1-1434](../app/analysis.py)
- **Evidence:** The file contains:
  * NVD CVE dataclass model + `from_dict` parser (lines 47-211).
  * Settings reader + `lru_cache`'d factories (`AnalysisSettings`, `_MultiSettings`, `get_analysis_settings`, `get_analysis_settings_multi`) (lines 219-743).
  * Sync `requests.Session`-driven NVD pagination + retry (`_nvd_fetch_cves_paginated`, `nvd_query_by_cpe`, `nvd_query_by_keyword`) (lines 411-610).
  * Async HTTP helpers (`_async_get`, `_async_post`) (lines 753-805).
  * OSV query function (`osv_query_by_components`) plus enrichment heuristics (`enrich_component_for_osv`, `extract_fixed_versions_osv`) (lines 838-1095).
  * GitHub Advisory GraphQL query (`github_query_by_components`) (lines 1101-1230).
  * `AnalysisSource` enum, `nvd_query_by_components_async` orchestrator, deduplicate re-export, async wrapper `analyze_sbom_multi_source_async` (lines 1236-1394).
  * CWE extraction helpers for NVD/OSV/GHSA (lines 1407-1433).
- **Why this violates the principle:** A module with seven clear responsibilities collapses every reason-to-change onto one file. Touching the NVD pagination cap forces re-reading 1.4k lines.
- **Impact:** Long PR diffs, merge-conflict magnet, lazy-import dance to break circular dependencies (see OOP-005). Tests hit a single import surface and run more setup than needed.
- **Recommended fix:** Move bodies into `app/sources/{nvd,osv,ghsa}.py`; keep settings in `app/sources/_settings.py`; keep `CVERecord` in `app/sources/_cve_record.py`; delete the orchestrator (`app.sources.runner` already replaces it). After move, `analysis.py` should be empty or a `DeprecationWarning` stub.
- **Effort:** L (~1 day)
- **Risk of fix:** Medium — many imports across `routers/`, `pipeline/`, `services/`. Tests cover the externally observable shapes well.

### Finding SOLID-SRP-002: `app/routers/sboms_crud.py` is a 949-line router that owns persistence + orchestration

- **Principle violated:** SRP, Separation of Concerns
- **Severity:** High
- **Location:** [app/routers/sboms_crud.py:1-950](../app/routers/sboms_crud.py)
- **Evidence:** Same file:
  * Helpers `now_iso`, `_coerce_sbom_data`, `normalized_key`, `safe_int`, `compute_report_status` (duplicated elsewhere — see DRY).
  * `upsert_components`, `sync_sbom_components` — repository-shaped DB writes.
  * `persist_analysis_run` — service-shaped business logic.
  * `create_auto_report` — orchestrator that pulls sources, dedupes, persists.
  * `_validate_user_id`, `_validate_positive_int` — request validation.
  * `_sse_event`, `event_stream` — SSE protocol formatter.
  * Eight HTTP route handlers covering CRUD + analyze + analyze/stream.
- **Why this violates the principle:** A router should map HTTP requests to service calls and validate. Persistence, dedupe, SSE framing, parsing, and idempotency all live in this one file. The "router → service → repository" architecture documented in [app/main.py:13-19](../app/main.py) is contradicted here.
- **Impact:** Two duplicate implementations of `persist_analysis_run` exist (see SOLID-SRP-003). Any service-layer caller that needs to persist a run must either re-import from a router (smell) or duplicate the body.
- **Recommended fix:**
  1. Move `upsert_components`, `sync_sbom_components`, `persist_analysis_run` into a `SbomComponentRepository` and `AnalysisRunRepository`.
  2. Move `create_auto_report` into `app/services/analysis_pipeline.py` (or replace by reusing `app.sources.runner.run_sources_concurrently` + a thin persist call).
  3. Move SSE framing helper to `app/utils/sse.py`.
  4. Router file shrinks to ~200 lines of HTTP wiring.
- **Effort:** L
- **Risk of fix:** Medium — heavily covered by snapshot + stream tests.

### Finding SOLID-SRP-003: Two `persist_analysis_run` implementations exist with subtly different fields

- **Principle violated:** SRP / DRY (cross-listed)
- **Severity:** High
- **Location:** [app/routers/sboms_crud.py:176-277](../app/routers/sboms_crud.py); [app/services/analysis_service.py:119-203](../app/services/analysis_service.py)
- **Evidence:**
  ```python
  # routers/sboms_crud.py:189
  run = AnalysisRun(
      sbom_id=sbom_obj.id, project_id=sbom_obj.projectid,
      run_status=run_status, source=source,
      ...  # NO query_error_count, NO raw_report
  )
  ```
  ```python
  # services/analysis_service.py:151
  run = AnalysisRun(
      ...
      query_error_count=len(details.get("query_errors") or []),
      raw_report=json.dumps(details),
  )
  ```
- **Why this violates the principle:** Same name, same intent, two definitions; the router copy omits `query_error_count` and `raw_report`. Production analyze paths use the router copy → those AnalysisRun rows have `query_error_count = 0` and `raw_report = NULL` regardless of whether errors occurred.
- **Impact:** Bug. `AnalysisRunOut.query_error_count` will mis-report as 0 even when errors existed; the SSE stream surface (`details["query_errors"]`) is lost forever after persist.
- **Recommended fix:** Single canonical implementation in `app/services/analysis_service.py`; router calls it. Add a regression test that posts an analysis with a known-bad source and asserts `query_error_count > 0`.
- **Effort:** S
- **Risk of fix:** Medium — the test should drive the merge.

### Finding SOLID-SRP-004: `app/main.py` does both DB migration and seed

- **Principle violated:** SRP
- **Severity:** Low
- **Location:** [app/main.py:70-131, 134-148](../app/main.py)
- **Evidence:**
  ```python
  # app/main.py:82-131
  def _ensure_seed_data() -> None:
      Base.metadata.create_all(bind=engine)
      _ensure_text_column("analysis_run", "sbom_name")
      _ensure_text_column("analysis_finding", "cwe")
      ...   # 8 such calls
      db = SessionLocal()
      try:
          db.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_sbom_type_typename ON sbom_type(typename)"))
          ...
          backfill_analytics_tables(db)
      finally:
          db.close()
  ```
- **Why this violates the principle:** Lifespan does (1) Alembic-style schema migration via raw `ALTER TABLE`, (2) `create_all`, (3) reference data seed, (4) backfill, (5) cached SBOM-name update. Five distinct responsibilities in one async context. `alembic/` exists in the repo but isn't being used for these migrations.
- **Impact:** Schema migrations are not auditable; SQLite-only `_ensure_text_column` silently no-ops in Postgres.
- **Recommended fix:** Move all schema churn to Alembic (the directory already exists). Lifespan owns only client init + `validate_auth_setup` + lightweight `backfill_analytics_tables` (which itself should be moved to a CLI command).
- **Effort:** M
- **Risk of fix:** Medium — must ensure Alembic stamps the existing prod state correctly.

### Finding SOLID-SRP-005: `_run_legacy_analysis` builds an HTTP response while persisting

- **Principle violated:** SRP, CQS
- **Severity:** Medium
- **Location:** [app/routers/analyze_endpoints.py:99-256](../app/routers/analyze_endpoints.py)
- **Evidence:** Function signature returns `dict` but contains: SBOM load, CPE augmentation, OSV enrichment, adapter construction, concurrent fan-out, dedupe, severity bucketing, persistence, AND building a dual-shape response (flat `AnalysisRunOut` keys plus a `summary` block kept alive for `useBackgroundAnalysis.ts:65`).
- **Why this violates the principle:** The persist step is a side effect; the `summary.findings.bySeverity` block is a presentation concern; the `runId/id` aliasing is a back-compat concern. Three responsibilities tangled.
- **Recommended fix:** Move the persist+orchestrate body into `services/analysis_pipeline.run_adhoc(...)` returning a typed `AdhocRunResult`; build the dual-shape response in a `_to_legacy_response(result)` helper; eventually drop the dual shape after the frontend stops needing it (see Cross-Cutting).
- **Effort:** M
- **Risk of fix:** Low.

---

## Open/Closed Principle (OCP)

### Finding SOLID-OCP-001: `pipeline/multi_source.run_multi_source_analysis_async` hard-codes per-source branches

- **Principle violated:** OCP
- **Severity:** High
- **Location:** [app/pipeline/multi_source.py:60-267](../app/pipeline/multi_source.py)
- **Evidence:**
  ```python
  selected_enum: set[AnalysisSource] = set()
  for s in selected:
      try:
          selected_enum.add(AnalysisSource[s])
      except KeyError:
          LOGGER.warning("Unknown analysis source ignored: %s", s)
  ...
  coros = []
  if AnalysisSource.NVD in selected_enum:
      coros.append(_nvd())
  if AnalysisSource.OSV in selected_enum:
      coros.append(_osv())
  if AnalysisSource.GITHUB in selected_enum:
      coros.append(_gh())
  if AnalysisSource.VULNDB in selected_enum:
      coros.append(_vulndb())
  ```
- **Why this violates the principle:** Adding a fifth source (e.g. Snyk) requires editing this file. The new world (`app.sources.registry` + `app.sources.runner.run_sources_concurrently`) is open for extension via registry registration; this older orchestrator is closed.
- **Impact:** Two orchestrators exist for the same job — see also SOLID-SRP-001 and `00_inventory.md` §7-2.
- **Recommended fix:** Delete `app/pipeline/multi_source.py` once `app/workers/tasks.py` is either deleted (it's never enqueued — YAGNI-002) or rewired to call `app.sources.runner.run_sources_concurrently` directly.
- **Effort:** M
- **Risk of fix:** Low — the only callers are the never-enqueued Celery task and the `analyze_sbom_multi_source_async` re-export which has zero callers in `app/`.

### Finding SOLID-OCP-002: `app.parsing.extract.extract_components` switches on format inline rather than via registry

- **Principle violated:** OCP
- **Severity:** Low
- **Location:** [app/parsing/extract.py:12-57](../app/parsing/extract.py)
- **Evidence:** see OOP-011.
- **Why this violates the principle:** `app/parsing/registry.py` exists (35 lines per inventory) but `extract_components` doesn't use it. Adding a third format (e.g. SWID) means editing the inline if/elif.
- **Recommended fix:** Use `parsing/registry.py` (or `parsing/format.detect_sbom_format`) to dispatch to the right parser.
- **Effort:** S
- **Risk of fix:** Low.

### Finding SOLID-OCP-003: `app.sources.factory.build_source_adapters` hard-codes the factory dict

- **Principle violated:** OCP
- **Severity:** Low
- **Location:** [app/sources/factory.py:46-56](../app/sources/factory.py)
- **Evidence:** see OOP-013. `factories = {"NVD": …, "OSV": …, "GITHUB": …, "VULNDB": …}` is closed.
- **Recommended fix:** Each adapter class exposes `from_settings(cls, settings) → cls`; factory becomes `[get_source(name).from_settings(s) for name in normalize_source_names(...)]`.
- **Effort:** S
- **Risk of fix:** Low.

### Finding SOLID-OCP-004: PURL→CPE generator uses an inline `if ptype in {...}` ladder

- **Principle violated:** OCP
- **Severity:** Low
- **Location:** [app/sources/cpe.py:34-127](../app/sources/cpe.py)
- **Evidence:**
  ```python
  if ptype in {"pypi"}:
      vnd = slug(name); prd = slug(name)
  elif ptype in {"npm"}:
      ...
  elif ptype in {"maven"}:
      ...
  ```
- **Why this violates the principle:** Adding a new ecosystem mapping requires editing this function. Each branch is small and stable, so the cost is low — but the structure is closed.
- **Recommended fix:** Dispatch table `{ "pypi": _pypi_cpe, "npm": _npm_cpe, ... }` with each entry a tiny function. Even better: a default rule + a per-ecosystem override hook.
- **Effort:** S
- **Risk of fix:** Low.
- **Note:** Acceptable to defer — KISS argues against premature plugin-ifying for stable mappings.

### Finding SOLID-OCP-005: Severity bucketing repeats with hard-coded thresholds

- **Principle violated:** OCP / DRY
- **Severity:** Low
- **Location:** [app/sources/vulndb.py:64-80](../app/sources/vulndb.py); compare with [app/sources/severity.py:97-126](../app/sources/severity.py)
- **Evidence:**
  ```python
  # vulndb.py:64-80
  def _severity_from_risk(risk, score):
      ...
      if score >= 9.0: return "CRITICAL"
      if score >= 7.0: return "HIGH"
      ...
  ```
  ```python
  # severity.py:97
  def sev_bucket(score, settings, severity_text=None):
      if score >= settings.cvss_critical_threshold: return "CRITICAL"
      ...
  ```
- **Why this violates the principle:** `vulndb.py` ignores the configurable thresholds and hard-codes 9.0 / 7.0 / 4.0. If an operator overrides `CVSS_CRITICAL_THRESHOLD=8.5`, VulDB findings still bucket at 9.0.
- **Recommended fix:** Replace `_severity_from_risk` with `sev_bucket(score, settings, severity_text=name)`.
- **Effort:** S
- **Risk of fix:** Low.

---

## Liskov Substitution Principle (LSP)

### Finding SOLID-LSP-001: No structural LSP violations found in the source-adapter Protocol

- **Principle:** LSP
- **Severity:** none
- **Evidence:** `VulnSource` Protocol declares `name: str` and `async query(components, settings) → SourceResult`. All four adapters (`NvdSource`, `OsvSource`, `GhsaSource`, `VulnDbSource`) conform: returns are always `SourceResult` TypedDict. No subclass weakens postconditions or strengthens preconditions. Verified in [app/sources/{base,nvd,osv,ghsa,vulndb}.py](../app/sources/).
- **Status:** No significant violations.

### Finding SOLID-LSP-002: `AnalysisRunOut.run_status` accepts any string but the frontend expects a closed enum

- **Principle violated:** LSP (between contract layers)
- **Severity:** Medium
- **Location:** [app/schemas.py:97-117](../app/schemas.py); [frontend/src/types/index.ts:42-62](../frontend/src/types/index.ts)
- **Evidence:**
  ```python
  # schemas.py:101
  run_status: str
  ```
  ```ts
  // types/index.ts:47
  run_status: 'PASS' | 'FAIL' | 'PARTIAL' | 'ERROR' | 'RUNNING' | 'PENDING' | 'NO_DATA';
  ```
  Backend writes also include `"BACKFILL"` (services/analysis_service.py:287), `"NVD,OSV,GITHUB"` etc as `source_label` (sboms_crud.py:343), and the persisted source string `+ " (partial)"`. Yes, that is the `source` column not `run_status`, but the backend has no enforced enum on `run_status` either.
- **Why this violates the principle:** A consumer typed against the closed TS union may receive `"BACKFILL"` or any other string — the substitution principle for the API contract is broken because backend's "value" side is wider than the frontend's "type" side.
- **Recommended fix:** Server-side `Literal[…]` type on `run_status` with explicit enum (`AnalysisRunStatus`) used at write time AND the schema; the TS union should match. Cross-listed in `09_cross_cutting.md`.
- **Effort:** S
- **Risk of fix:** Low.

### Finding SOLID-LSP-003: `app/repositories/*Repository` classes don't implement their declared `*Port` Protocol

- **Principle violated:** LSP
- **Severity:** High
- **Location:** [app/repositories/sbom_repo.py:17-206](../app/repositories/sbom_repo.py); [app/repositories/analysis_repo.py:16-198](../app/repositories/analysis_repo.py); [app/ports/repositories.py:18-58](../app/ports/repositories.py)
- **Evidence:** Inventory §6 documents:
  * `SBOMRepository.delete_sbom` references `AnalysisFinding.run_id`, `SBOMSource.project_id`, `SBOMAnalysisReport.sbom_id` — none exist on the actual ORM models.
  * `SBOMRepository.sbom_name_exists` filters on `SBOMSource.name` — column is `sbom_name`.
  * `AnalysisRepository.list_runs` filters on `AnalysisRun.status` — column is `run_status`.
  * `AnalysisRepository.list_findings` filters on `AnalysisFinding.run_id` — column is `analysis_run_id`.
  * `AnalysisRepository.store_run_cache` writes `cached_at=...` — column is `created_on`.
- **Why this violates the principle:** A caller substituting `SBOMRepository` for `SBOMRepositoryPort` will crash at runtime with `AttributeError`. The class violates its declared contract.
- **Impact:** None today (no callers — see YAGNI), but the Protocol implies safe substitution.
- **Recommended fix:** Delete the repositories (YAGNI-001) or fix the column names AND add a smoke test that exercises every method.
- **Effort:** S (delete) or M (fix + test).
- **Risk of fix:** Low.

---

## Interface Segregation Principle (ISP)

### Finding SOLID-ISP-001: `_MultiSettings` forces every adapter to depend on every other adapter's config

- **Principle violated:** ISP
- **Severity:** High
- **Location:** see OOP-006.
- **Evidence:** `_MultiSettings(AnalysisSettings)` aggregates 30+ fields covering NVD timing, OSV batch, GitHub URLs, VulDB knobs, mirror settings, and concurrency. Every adapter accepts the whole object via `Any`-typed `settings` parameter and pulls its slice via `getattr(settings, "vulndb_api_base_url", default)`.
- **Why this violates the principle:** `OsvSource` shouldn't need to know that `vulndb_api_key_env` exists. The `getattr(..., default)` pattern is a workaround for the bloated interface.
- **Recommended fix:** Per-adapter typed config dataclass (`NvdConfig`, `OsvConfig`, …) constructed at adapter init time. The runner only sees `RuntimeConfig` for concurrency.
- **Effort:** M
- **Risk of fix:** Low.

### Finding SOLID-ISP-002: `Settings` carries 35+ fields used by tiny slices of code

- **Principle violated:** ISP
- **Severity:** Medium
- **Location:** [app/settings.py:31-202](../app/settings.py)
- **Evidence:** `Settings` exposes JWT, NVD, GitHub, VulDB, S3, Redis, Celery, log, CORS, server, analysis, auth fields. Routers receive it whole via `get_settings()` and reach for one or two attributes.
- **Why this violates the principle:** Tests must construct or mock the full `Settings` to exercise a code path that needs only `vulndb_api_key`. Coupling between unrelated components ride along.
- **Recommended fix:** Split `Settings` into composed sub-models: `JwtSettings`, `NvdSettings`, `GhsaSettings`, `VulnDbSettings`, `S3Settings`, `LogSettings`, `RateLimitSettings`. The top-level `AppSettings` composes them. Pydantic v2 supports nested models with env nested-delimiter loading.
- **Effort:** M
- **Risk of fix:** Low.

### Finding SOLID-ISP-003: `SBOMRepositoryPort` Protocol declares 3 of the ~6 methods the dead repo defines

- **Principle violated:** ISP (the Protocol is too narrow — implementers must guess what's needed)
- **Severity:** Low
- **Location:** [app/ports/repositories.py:18-36](../app/ports/repositories.py); [app/repositories/sbom_repo.py:17-206](../app/repositories/sbom_repo.py)
- **Evidence:** Port declares `get_sbom`, `list_sboms`, `create_sbom`. Concrete class adds `update_sbom`, `delete_sbom`, `sbom_name_exists`, `list_sbom_types`. A test fake that fulfills the Protocol fails on services that need `update_sbom`.
- **Recommended fix:** Either narrow the concrete class to the Protocol or expand the Protocol. Simpler to delete both (YAGNI-001).
- **Effort:** S
- **Risk of fix:** Low.

### Finding SOLID-ISP-004: `progress_queue: asyncio.Queue | None` in the runner forces every adapter to support streaming

- **Principle violated:** ISP (mild)
- **Severity:** Low
- **Location:** [app/sources/runner.py:46-121](../app/sources/runner.py)
- **Evidence:**
  ```python
  async def run_sources_concurrently(
      sources: Sequence[VulnSource],
      components: list[dict],
      settings: Any,
      progress_queue: asyncio.Queue | None = None,
  ) -> tuple[list[dict], list[dict], list[dict]]:
  ```
- **Why this violates the principle:** Two callers exist: SSE (passes a queue) and non-SSE (passes None). The signature is fine for now (one optional kwarg) but coupling streaming concerns into the orchestrator means the orchestrator must know the SSE event constants.
- **Recommended fix:** Acceptable as-is. If a third caller needs different events, split into `RunnerObserver` interface.
- **Effort:** Defer.
- **Risk of fix:** —

---

## Dependency Inversion Principle (DIP)

### Finding SOLID-DIP-001: Routers call SQLAlchemy directly instead of going through repositories or services

- **Principle violated:** DIP
- **Severity:** High
- **Location:** [app/routers/sboms_crud.py:402-712](../app/routers/sboms_crud.py); [app/routers/runs.py:54-178](../app/routers/runs.py); [app/routers/projects.py:59-179](../app/routers/projects.py); [app/routers/dashboard_main.py:27-83](../app/routers/dashboard_main.py); [app/routers/analysis.py:22-236](../app/routers/analysis.py); [app/routers/sbom.py:20-161](../app/routers/sbom.py)
- **Evidence:**
  ```python
  # routers/runs.py:77-85
  sbom_subq = db.query(SBOMSource.id.label("sbom_id"), SBOMSource.sbom_name.label("sbom_name")).subquery()
  base = select(AnalysisRun)
  count = select(func.count(AnalysisRun.id))
  if sbom_id is not None:
      base = base.where(AnalysisRun.sbom_id == sbom_id)
  ```
  ```python
  # routers/sbom.py:20-35
  run = (
      db.execute(select(AnalysisRun).where(AnalysisRun.sbom_id == sbom_id).order_by(AnalysisRun.id.desc()))
      .scalars().first()
  )
  ```
- **Why this violates the principle:** High-level HTTP handlers depend on the low-level SQLAlchemy module directly. The "ports" layer (`app/ports/`) and the "repositories" layer (`app/repositories/`) exist but are not in the call graph. The architecture comment in [app/main.py:13-19](../app/main.py) says "all DB access in `app/repositories/`" — that is aspirational, not actual.
- **Impact:** Hard to unit-test routers (must spin up DB or extensive mocks). Schema changes ripple to every router. Two query styles coexist (`db.query(...)` vs `db.execute(select(...))`).
- **Recommended fix:** Introduce thin repository functions (not classes) that take `db: Session` and return DTOs (or a paginated wrapper). Routers depend on these. Keep the ports/protocols only for service-layer test seams.
- **Effort:** L
- **Risk of fix:** Medium — significant test coverage exists, but reshaping internals is broad-touch.

### Finding SOLID-DIP-002: `pipeline.multi_source._nvd` constructs the NVD-mirror facade inline

- **Principle violated:** DIP
- **Severity:** Medium
- **Location:** [app/pipeline/multi_source.py:130-148](../app/pipeline/multi_source.py)
- **Evidence:**
  ```python
  from ..nvd_mirror.application import build_nvd_lookup_for_pipeline
  nvd_lookup_service = build_nvd_lookup_for_pipeline()
  ...
  cve_objs = nvd_lookup_service.query_legacy(cpe, api_key=api_key, settings=cfg)
  ```
- **Why this violates the principle:** The pipeline knows about both the legacy live-query function and the mirror facade builder. The high-level orchestrator depends on a concrete "build it for me" function rather than receiving an abstract `NvdLookupServiceLike` from a caller.
- **Impact:** Hard to test the orchestrator without spinning up a real DB session for the mirror. Test code in `tests/test_nvd_cpe_query.py` works around this by monkey-patching `nvd_query_by_cpe` directly.
- **Recommended fix:** Inject `nvd_lookup_service` (or a `LiveQuery` callable) as a function parameter. Production wiring constructs it once at app startup; tests pass a fake.
- **Effort:** S
- **Risk of fix:** Low.

### Finding SOLID-DIP-003: Frontend fetch URLs hard-coded in `lib/api.ts`

- **Principle violated:** DIP
- **Severity:** Low
- **Location:** [frontend/src/lib/api.ts:177-509](../frontend/src/lib/api.ts)
- **Evidence:**
  ```ts
  export function getRuns(filter, signal?) {
    return request<AnalysisRun[]>(`/api/runs?${params.toString()}`, { signal });
  }
  ```
- **Why this violates the principle:** Components import named functions from `api.ts`. The functions themselves contain literal paths. This is acceptable abstraction for a small app — the dependency is on a typed function name, not on `fetch`. Listed for completeness only; no fix recommended.
- **Status:** Defer — single source of truth for URLs is fine. Higher-leverage frontend issues are in `08_frontend.md`.

### Finding SOLID-DIP-004: `auth.require_auth` reads from `os.environ` per request rather than from a `Settings` dependency

- **Principle violated:** DIP, Single Source of Truth
- **Severity:** Medium
- **Location:** [app/auth.py:25-32, 111-160](../app/auth.py)
- **Evidence:**
  ```python
  # auth.py:25-32
  def _read_mode() -> str:
      return (os.getenv("API_AUTH_MODE") or "none").strip().lower() or "none"
  def _read_tokens() -> set[str]:
      raw = os.getenv("API_AUTH_TOKENS") or ""
      return {t.strip() for t in raw.split(",") if t.strip()}
  ```
- **Why this violates the principle:** Settings are loaded from `os.environ` directly inside the auth dependency, bypassing `app.settings.Settings` which has fields for `api_auth_mode` and `api_auth_tokens`. The docstring explicitly justifies this for "tests can monkeypatch without cache issues." That's a workaround for a stale-singleton bug, not an architectural choice.
- **Impact:** Two sources of truth for the same env vars. A test that does `reset_settings()` still uses `os.environ` for auth.
- **Recommended fix:** Inject `Settings` via FastAPI `Depends`; `reset_settings()` clears the singleton; `monkeypatch.setenv` triggers reload.
- **Effort:** S
- **Risk of fix:** Low (covered by `tests/test_auth.py`).

---

## Summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 6 |
| Medium | 5 |
| Low | 8 |
| **Total** | **19** |

**Highest-leverage SOLID fixes (top 3):**
1. **SOLID-SRP-003** — Merge the two `persist_analysis_run` implementations. Bug fix: `query_error_count` and `raw_report` are currently lost on production analyses.
2. **SOLID-OCP-001** — Delete `app/pipeline/multi_source.py` (and the never-enqueued Celery task). Cuts 320 lines + an enum + a `_env_list` helper, removes one of two competing orchestrators.
3. **SOLID-DIP-001** — Stop bypassing the service layer. Either kill `app/ports` + `app/repositories` (YAGNI route) or actually wire them. The middle ground today is the worst of both.
