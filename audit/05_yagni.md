# Phase 2.5 — YAGNI Audit

> Dead code, half-built features, speculative parameters. Verified by `grep`-driven reachability analysis.

---

### Finding YAGNI-001: Entire `app/repositories/` package is unreachable

- **Principle violated:** YAGNI
- **Severity:** High
- **Location:** [app/repositories/](../app/repositories/) — `sbom_repo.py` (206), `analysis_repo.py` (197), `component_repo.py` (144), `project_repo.py` (128). 675 lines total.
- **Evidence:**
  ```bash
  $ grep -rn "from .*repositories" --include='*.py' . \
        | grep -v "^app/repositories\|^app/ports\|^app/nvd_mirror"
  # → no results
  ```
  Plus, methods reference non-existent ORM columns (`AnalysisFinding.run_id`, `SBOMSource.project_id`, `SBOMSource.name`, `AnalysisRun.status`, `RunCache.cached_at`) — see SOLID-LSP-003. Calling them would `AttributeError` immediately. So they cannot have hidden runtime callers.
- **Why this violates the principle:** Aspirational hexagonal architecture that nobody has wired in. The existence is misleading — it appears in tree views, gets re-exported by `__init__.py`, but does nothing.
- **Impact:** New contributors waste time reading these files. `AnalysisRepository.list_runs` and `SBOMRepository.delete_sbom` look canonical but are broken.
- **Recommended fix:** Delete `app/repositories/` and the corresponding `app/ports/repositories.py`. Either:
  * **Now**, if the team is committed to the current router-driven query style (least churn), OR
  * **Later**, if the SOLID-DIP-001 refactor materialises and we need real repositories — write them then, against current ORM column names.
- **Effort:** S (delete) / L (wire up properly).
- **Risk of fix:** Low to delete; no production caller exists.

### Finding YAGNI-002: Celery task `run_sbom_analysis` is defined but never enqueued

- **Principle violated:** YAGNI
- **Severity:** Medium
- **Location:** [app/workers/tasks.py:14-29](../app/workers/tasks.py); [app/workers/celery_app.py](../app/workers/celery_app.py)
- **Evidence:**
  ```bash
  $ grep -rn "run_sbom_analysis\b\|sbom_analyzer.run_sbom_analysis" --include='*.py' --include='*.ts' .
  # → only the task definition + log lines + a stale docstring reference
  ```
  No `.delay()`, `.apply_async()`, `signature(...)`, or `chain(...)` anywhere. The task is included in `Celery(include=["app.workers.tasks", ...])` but nothing fires it. The `nvd-mirror-hourly` schedule fires `nvd_mirror.mirror_nvd` (a different task), not this one.
- **Why this violates the principle:** Background analysis is an aspirational architecture; the synchronous `POST /api/sboms/{id}/analyze` and the SSE `analyze/stream` are the only production paths.
- **Impact:** Worker is needed only for `mirror_nvd`. Carrying the unused task means tests must keep `app.workers.tasks` importable (which transitively imports the legacy pipeline) — extra startup cost in the test process.
- **Recommended fix:** Delete `app/workers/tasks.py` body OR wire it into a real "background analysis" endpoint. If the team wants async background analyses, a dedicated route `POST /api/sboms/{id}/analyze/async` returning a task ID is a small addition.
- **Effort:** S (delete) / M (wire up).
- **Risk of fix:** Low.

### Finding YAGNI-003: Two competing multi-source orchestrators — only one is exercised in production

- **Principle violated:** YAGNI (overlap with SOLID-OCP-001)
- **Severity:** High
- **Location:** [app/pipeline/multi_source.py:17-329](../app/pipeline/multi_source.py); [app/analysis.py:1382-1394](../app/analysis.py)
- **Evidence:** `run_multi_source_analysis_async` callers (verified by `grep`):
  * `app.workers.tasks.run_sbom_analysis` (never enqueued — YAGNI-002).
  * `app.analysis.analyze_sbom_multi_source_async` (re-exports it; this re-export has zero callers in `app/`).
  * `tests/nvd_mirror/test_facade_integration.py` (3 places — exercises the mirror end-to-end).
  Production routers use `app.sources.runner.run_sources_concurrently` instead.
- **Why this violates the principle:** A 329-line orchestrator persists only for a Celery task that's never fired and integration tests that could be retargeted at the live runner.
- **Impact:** Two divergent execution paths for "run NVD+OSV+GHSA+VulDB on an SBOM"; behavioural differences hide between them (e.g. only `multi_source.py` calls the NVD-mirror facade — `runner.py` goes straight through `NvdSource → analysis.nvd_query_by_components_async`, which has its own NVD path that does **not** use the mirror).
- **Recommended fix:**
  1. Promote the mirror-aware NVD lookup to a property of `NvdSource` (i.e. `NvdSource(api_key=..., lookup_service=...)`).
  2. Migrate `tests/nvd_mirror/test_facade_integration.py` to call `run_sources_concurrently` instead of `run_multi_source_analysis_async`.
  3. Delete `app/pipeline/multi_source.py` + `app/pipeline/context.py` + the `analyze_sbom_multi_source_async` re-export + the never-enqueued Celery task.
- **Effort:** M
- **Risk of fix:** Medium — covered by tests.

### Finding YAGNI-004: `app/services/dashboard_service.py` (361 lines) is unwired

- **Principle violated:** YAGNI
- **Severity:** Medium
- **Location:** [app/services/dashboard_service.py](../app/services/dashboard_service.py)
- **Evidence:** `routers/dashboard_main.py` and `routers/dashboard.py` compute their metrics inline. The service module's eight functions (`get_stats`, `get_recent_sboms`, `get_activity`, `get_severity_distribution`, `get_component_stats`, `get_run_status_distribution`, `get_top_vulnerable_components`, `get_top_vulnerabilities`) are imported only by `app/services/__init__.py`. No route, no test calls them. (Verified by `grep -rn "from .*dashboard_service\|services.dashboard_service\|get_top_vulnerabilities\|get_top_vulnerable_components"` — only `__init__.py` references.)
- **Impact:** Reader must guess which set of metrics is canonical. Three of the unused functions (`get_top_vulnerable_components`, `get_top_vulnerabilities`, `get_run_status_distribution`) describe dashboard widgets the frontend has never asked for.
- **Recommended fix:** Either:
  * Delete the unwired functions (`get_top_vulnerable_components`, etc.) and rewire `dashboard_main.py` to call the kept helpers (`get_stats`, `get_recent_sboms`, `get_activity`, `get_severity_distribution`).
  * Or delete the whole file if the team prefers inline router queries (smaller).
- **Effort:** S
- **Risk of fix:** Low.

### Finding YAGNI-005: `app/utils.py` has zero importers

- **Principle violated:** YAGNI
- **Severity:** Low
- **Location:** [app/utils.py:1-92](../app/utils.py)
- **Evidence:**
  ```bash
  $ grep -rn "from .utils\|from app.utils\|from ..utils" --include='*.py' .
  # → no results
  ```
- **Why this violates the principle:** All seven helpers (`now_iso`, `legacy_analysis_level`, `safe_int`, `safe_float`, `normalized_key`, `compute_report_status`, `normalize_details`) are duplicated elsewhere — see DRY-001..004.
- **Recommended fix:** Either delete `app/utils.py` entirely and consolidate into `app/services/sbom_service.py` (where the duplicates live), OR keep `app/utils.py` as the canonical home and migrate the other modules to import from it. Both are valid; the project should pick one.
- **Effort:** S
- **Risk of fix:** Low.

### Finding YAGNI-006: `app/infrastructure/s3_storage.py` and `app/ports/storage.py` are dead

- **Principle violated:** YAGNI
- **Severity:** Medium
- **Location:** [app/infrastructure/s3_storage.py](../app/infrastructure/s3_storage.py); [app/ports/storage.py](../app/ports/storage.py)
- **Evidence:**
  ```bash
  $ grep -rn "S3StorageAdapter\|StoragePort\|try_create_s3_adapter" --include='*.py' .
  # → only the definitions and the package __init__.py re-exports
  ```
  No router, service, or test creates an adapter or accepts the Protocol. `Settings` does declare `aws_*` fields (lines 98-105) — but they are read by no other code.
- **Why this violates the principle:** Speculative blob-storage backend for a feature that doesn't exist.
- **Recommended fix:** Delete `app/infrastructure/`, `app/ports/storage.py`, and the seven `aws_*` fields from `Settings`. If/when SBOM artifact storage becomes a feature, build it then with the right interface.
- **Effort:** S
- **Risk of fix:** Low.

### Finding YAGNI-007: `SBOMTypeCreate` and `SBOMAnalysisReport*` schemas have no callers

- **Principle violated:** YAGNI
- **Severity:** Low
- **Location:** [app/schemas.py:42-46, 162-168, 195-203](../app/schemas.py)
- **Evidence:**
  ```bash
  $ grep -rn "SBOMTypeCreate\|SBOMAnalysisReportCreate\|SBOMAnalysisReportOut" --include='*.py' .
  # → only the definitions in schemas.py
  ```
  `SBOMType` is created via the seed flow in `_ensure_seed_data` (no `Create` schema needed). `SBOMAnalysisReport` is a *legacy table* that `backfill_analytics_tables` migrates from at startup, never written by any endpoint.
- **Recommended fix:** Delete the three schema classes. Once `backfill_analytics_tables` finishes its job (it's idempotent and only runs on rows lacking matching `AnalysisRun`), the legacy table can be dropped via Alembic too.
- **Effort:** S (schemas) / M (drop legacy table after one boot of every prod env).
- **Risk of fix:** Low (schemas), Medium (table drop).

### Finding YAGNI-008: `AnalysisRunSummary` schema is unused

- **Principle violated:** YAGNI
- **Severity:** Low
- **Location:** [app/schemas.py:142-159](../app/schemas.py)
- **Evidence:** Defined and exported, never used as a `response_model` or `model_validate` target.
- **Recommended fix:** Delete. If a list-page-only schema is later wanted, build it then.
- **Effort:** S
- **Risk of fix:** Low.

### Finding YAGNI-009: `_ensure_text_column` SQLite-only migration helper

- **Principle violated:** YAGNI / Single Source of Truth
- **Severity:** Medium
- **Location:** [app/main.py:70-94](../app/main.py)
- **Evidence:**
  ```python
  def _ensure_text_column(table_name, column_name) -> None:
      if engine.dialect.name != "sqlite":
          return
      ...
  ```
  Used 8 times to add `sbom_name`, `cwe`, `fixed_versions`, `attack_vector`, `cvss_version`, `aliases`, `source`, `sbom_id` columns at startup.
- **Why this violates the principle:** Alembic exists ([alembic.ini](../alembic.ini), [alembic/versions/{001_initial_schema,002_nvd_mirror_tables}.py](../alembic/versions/)). The startup helper is a pre-Alembic workaround that should not survive once those columns are in `001_initial_schema.py`.
- **Impact:** Postgres prod boots are silent no-ops here; every new column needs both an Alembic migration AND a `_ensure_text_column` call. Drift risk.
- **Recommended fix:** Verify the columns are already in `alembic/versions/001_initial_schema.py` ([REQUIRES VERIFICATION] — `cat alembic/versions/001_initial_schema.py`). Delete `_ensure_text_column` and the eight calls. Same with `_update_sbom_names`.
- **Effort:** S (after verification).
- **Risk of fix:** Low if the columns are in 001; otherwise add a 003 migration first.

### Finding YAGNI-010: `_MultiSettings.gh_token_override` field exists only as a back-compat shim

- **Principle violated:** YAGNI
- **Severity:** Low
- **Location:** [app/analysis.py:686-688](../app/analysis.py); [app/sources/ghsa.py:50-57](../app/sources/ghsa.py)
- **Evidence:** The docstring on `gh_token_override` reads:
  ```python
  # Per-request override for GitHub token. When set, takes precedence over the
  # environment variable read via `gh_token_env`. Lets request handlers pass a
  # caller-supplied token without mutating process-global os.environ.
  ```
  Used only by `GhsaSource.query` via `dataclasses.replace(settings, gh_token_override=self.token)`. The "request handlers" are no longer the code path — the per-request token comes via constructor (`GhsaSource(token=...)`) instead.
- **Why this violates the principle:** Intermediate abstraction kept alive only because the `github_query_by_components` function in `app/analysis.py` reads it. After SOLID-SRP-001 (move bodies into `app/sources/ghsa.py`), the field is dead.
- **Recommended fix:** Delete after the move. Until then, keep.
- **Effort:** S
- **Risk of fix:** Low (gated on SRP-001).

### Finding YAGNI-011: `app.analysis.AnalysisSource` enum exists for one branch chain

- **Principle violated:** YAGNI / OCP overlap
- **Severity:** Low
- **Location:** [app/analysis.py:1236-1240](../app/analysis.py)
- **Evidence:** `class AnalysisSource(str, Enum): NVD = "NVD"; OSV = "OSV"; GITHUB = "GITHUB"; VULNDB = "VULNDB"` is used only inside `pipeline/multi_source.py`'s `if AnalysisSource.NVD in selected_enum: …` ladder. The new world (`app.sources.factory.SUPPORTED_ANALYSIS_SOURCES`) uses plain strings.
- **Recommended fix:** Delete after YAGNI-003.
- **Effort:** S
- **Risk of fix:** Low.

### Finding YAGNI-012: `_env_str / _env_int / _env_float / _env_bool / _env_list / _env_bool_top` parallel `Settings`

- **Principle violated:** YAGNI / Single Source of Truth
- **Severity:** Medium
- **Location:** [app/analysis.py:260-296, 707-718](../app/analysis.py)
- **Evidence:** Six helpers, each doing what `pydantic_settings.BaseSettings` already does for free. They feed into the `lru_cache`'d `get_analysis_settings` / `get_analysis_settings_multi` (KISS-008). Mostly redundant, but `_env_str("ANALYSIS_HTTP_USER_AGENT", ...)` reads an env var that `Settings` doesn't declare.
- **Why this violates the principle:** Two parallel env-loading systems for the same process. Anyone who needs to override something via env has to know which one applies.
- **Recommended fix:** Move all 25+ env vars into `Settings` as fields. Delete the helpers and the two `lru_cache` factories.
- **Effort:** M
- **Risk of fix:** Low.

### Finding YAGNI-013: `analysis_legacy_level` setting carries a default of `1` and gates nothing

- **Principle violated:** YAGNI
- **Severity:** Low
- **Location:** [app/settings.py:65, 157-167, 241-243](../app/settings.py); [app/utils.py:13-16](../app/utils.py)
- **Evidence:**
  ```bash
  $ grep -rn "legacy_analysis_level\|analysis_legacy_level\|get_analysis_legacy_level" --include='*.py' .
  ```
  Only callers: `routers/health.py` (echoes the value in `/api/analysis/config`) and `services/analysis_service.py:legacy_analysis_level()` (echoes again). Nothing branches on it.
- **Why this violates the principle:** A configuration flag with no consumer except a debug echo.
- **Recommended fix:** Delete the field, the validator, the helper, and the `/api/analysis/config` key. If "legacy mode" was ever a feature, ship it now or stop teasing.
- **Effort:** S
- **Risk of fix:** Low.

### Finding YAGNI-014: `_USER_ID_PATTERN` regex permits exactly the chars Pydantic could enforce in one annotation

- **Principle violated:** YAGNI (cross-listed with KISS-007)
- **Severity:** Low
- **Status:** see KISS-007.

### Finding YAGNI-015: `nvd_mirror_admin_router` exposes endpoints without an admin role split

- **Principle violated:** YAGNI (the role split was speculatively documented but not implemented)
- **Severity:** Medium (security-adjacent)
- **Location:** [app/nvd_mirror/api.py:11-49](../app/nvd_mirror/api.py); [app/main.py:269-271](../app/main.py)
- **Evidence:** Module docstring + inline comments mark `TODO (Phase 0 §F.17): introduce an admin-role guard here`. Until then, every authenticated caller can call `PUT /admin/nvd-mirror/settings` (which **persists an API key**) and `POST /admin/nvd-mirror/sync`.
- **Why this violates the principle:** Speculation about a future role-based dependency, but the missing guard creates a real risk today.
- **Recommended fix:** Either (a) ship the admin guard now (small: a `Depends(require_admin)` that checks a JWT scope or env-var allowlist), or (b) inline the warning into `validate_auth_setup` so it logs at startup. Option (a) is the right call.
- **Effort:** S
- **Risk of fix:** Low.

### Finding YAGNI-016: `pipeline/context.py` exists with a tiny dataclass that only docs other code

- **Principle violated:** YAGNI
- **Severity:** Low
- **Location:** [app/pipeline/context.py](../app/pipeline/context.py)
- **Evidence:** 28 lines, declared but not imported anywhere outside `pipeline/__init__.py`'s re-export.
- **Recommended fix:** Delete after YAGNI-003.

### Finding YAGNI-017: Frontend `next: ^9.3.3` after a deliberate downgrade

- **Principle violated:** YAGNI / Principle of Least Astonishment / **the build is broken**
- **Severity:** Critical
- **Location:** [frontend/package.json:18](../frontend/package.json); commit `90beab6 chore: downgrade next dependency to version 9.3.3`
- **Evidence:** `frontend/node_modules/next/package.json` shows `"version": "9.3.3"`. Prior commit (`3e744ed`) had `"next": "^16.2.2"`. Code uses App Router (`frontend/src/app/`), Server/Client component split (`'use client'` directives in 28 files), `next/font`, `next/navigation` — none of which exist in Next 9 (App Router is Next 13+).
- **Why this violates the principle:** Either (a) the codebase was supposed to be on Next 14+ and the downgrade was an accident/mistake to undo, or (b) the downgrade is an intentional "we're rewriting for pages-router" plan, in which case the App Router code is dead and YAGNI says delete it. Both interpretations point to a destructive inconsistency.
- **Impact:** **Frontend cannot build.** **`[REQUIRES VERIFICATION]`** by `cd frontend && npm run build`, but no Next 9 understands `app/`, `'use client'`, or `next/navigation`.
- **Recommended fix:** **Confirm with Feroze first.** Likely path: revert `90beab6`, restore `^16.2.2` (or whatever the production target is — probably 14, given the App Router idiom). If the downgrade was deliberate, the entire `frontend/src/app/` tree must be ported to Pages Router — far larger.
- **Effort:** S (revert) / XL (port to Pages).
- **Risk of fix:** Low to revert; ask first.

### Finding YAGNI-018: `tests/_normalize.py` and `tests/snapshots/*.json` snapshot infra exists; some snapshots may be obsolete

- **Principle violated:** YAGNI (uncertain — flagged for verification)
- **Severity:** Low
- **Location:** [tests/snapshots/](../tests/snapshots/) (5 JSON files), [tests/_normalize.py](../tests/_normalize.py).
- **Evidence:** **`[REQUIRES VERIFICATION]`** — I did not read each snapshot. The fixtures `analyze_sbom_consolidated.json`, `analyze_sbom_github.json`, `analyze_sbom_nvd.json`, `analyze_sbom_osv.json`, `post_sbom_analyze.json` are referenced from the corresponding `test_*_snapshot.py` files. Possible drift: snapshots may include the legacy `summary.findings.bySeverity` block that the audit recommends dropping (KISS-011).
- **Recommended fix:** Inspect during the actual refactor; if a snapshot mentions a field marked for removal, regenerate.

---

## Summary

| Severity | Count |
|---|---|
| Critical | 1 |
| High | 2 |
| Medium | 7 |
| Low | 8 |
| **Total** | **18** |

**Highest-leverage YAGNI deletions (top 3):**
1. **YAGNI-017** — Resolve the Next.js downgrade *first*. The frontend is currently un-buildable; nothing else matters until that's settled.
2. **YAGNI-001** — Delete `app/repositories/` + `app/ports/repositories.py`. -675 lines, no behaviour change. Single commit.
3. **YAGNI-003 + YAGNI-002 + YAGNI-006 + YAGNI-016** — One purge commit:
   * Delete `app/pipeline/`, `app/workers/tasks.py`, `app/infrastructure/`, `app/ports/storage.py`.
   * Delete `app.analysis.analyze_sbom_multi_source_async`, `AnalysisSource` enum, `_env_*` helpers.
   * Migrate the 3 mirror integration tests onto `run_sources_concurrently`.
   * Promote NVD-mirror lookup from `multi_source._nvd` into `NvdSource.__init__` so the mirror is preserved.
   Net: ~600 lines deleted, two competing orchestrators reduced to one.
