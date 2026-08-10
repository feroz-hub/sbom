# Phase 6 — Refactor Proposal

> Ranked plan, mini-RFCs for the top 10, a quick-wins batch, deferred items, and a one-page exec summary at the end. **No code modified.**

---

## Top 10 highest-leverage refactors (impact/effort)

Ranked by `impact ÷ effort`. Each has a mini-RFC below.

| # | Title | Severity | Effort | Risk |
|---|---|---|---|---|
| **R1** | Resolve the Next.js downgrade (frontend currently un-buildable) | Critical | S–XL (decision-dependent) | Low (revert) / High (port to Pages) |
| **R2** | Merge the two `persist_analysis_run` implementations (fixes silent `query_error_count = 0` bug) | High | S | Low |
| **R3** | Wire `MAX_UPLOAD_BYTES` (DoS vector) | High | S | Low |
| **R4** | Stop leaking exception text in 500 responses | High | S | Low |
| **R5** | Delete `app/repositories/`, `app/ports/storage.py`, `app/infrastructure/`, `app/utils.py`, unused schemas | High (YAGNI) | S | Low |
| **R6** | Collapse the second multi-source orchestrator (delete `app/pipeline/multi_source.py`, never-enqueued Celery task) | High | M | Medium |
| **R7** | Define `AdhocAnalysisRunOut` Pydantic schema + drop FE `[key: string]: unknown` | High | M | Low |
| **R8** | Move source query bodies into `app/sources/{nvd,osv,ghsa}.py`; shrink `app.analysis` | High | L | Medium |
| **R9** | Move SBOM CRUD persistence + orchestration out of `routers/sboms_crud.py` into a service layer | High | L | Medium |
| **R10** | Native JSON columns + drop `RunCache` redundancy | Medium | M | Medium |

---

## R1 — Resolve the Next.js downgrade

**Problem.** Commit `90beab6` downgraded `next` from `^16.2.2` to `^9.3.3`. The codebase uses App Router (`frontend/src/app/`, `'use client'` directives in 28 files, `next/font/google`, `next/navigation`) — none of which exist in Next 9. **The frontend cannot build with the current lockfile state.** [REQUIRES VERIFICATION] by `cd frontend && npm install && npm run build`, but this is mechanical: Next 9 has no concept of `app/`.

**Proposed change.** **Ask Feroze first.** Two diverging paths:
* **Revert path (likely correct).** `git revert 90beab6` (or `npm i next@^14.2.0` matching the previous spec — Next 14 is the last stable 14, the prompt declares Next 14 is the target; Next 16 is the prior pin but I'd verify it ever worked). Confirm `npm run build` succeeds, `npm test` passes, dev server starts. Single PR.
* **Port path.** If the downgrade was deliberate (rewriting for Pages Router), the `frontend/src/app/` tree must be migrated: `app/page.tsx` → `pages/index.tsx`, `app/[id]/page.tsx` → `pages/[id].tsx`, `'use client'` removed (everything is client in Pages), `next/font/google` removed, etc. ~XL effort.

**Migration steps (revert path).**
1. `git revert 90beab6` (or commit a new pin to a known-good Next).
2. `cd frontend && rm -rf node_modules package-lock.json && npm install`.
3. `npm run build` — must succeed.
4. `npm test` — must pass.
5. Start dev server, smoke-test the home page and one analysis flow.
6. Commit & push.

**Tests.** Existing `frontend/src/lib/env.test.ts` runs. Smoke-test manually.

**Rollback.** Re-apply `90beab6` if the team confirms the downgrade was intentional.

**Effort.** 1–2 hours (revert) / 5+ days (port).

---

## R2 — Merge the two `persist_analysis_run` implementations

**Problem.** [app/routers/sboms_crud.py:176-277](../app/routers/sboms_crud.py) and [app/services/analysis_service.py:119-203](../app/services/analysis_service.py) both define `persist_analysis_run` with diverged behaviour. The router copy omits `query_error_count` and `raw_report` — production analyses persist with these fields silently zero/null.

**Proposed change.** Single canonical implementation in `app/services/analysis_service.py`. Router calls it.

**Migration steps.**
1. Add a regression test (`tests/test_sboms_analyze_persists_query_errors.py`): post an analysis with a known-bad source key (e.g. invalid GitHub token), assert `AnalysisRun.query_error_count > 0` and `raw_report IS NOT NULL` after persist. Should **fail** today.
2. Update [app/routers/sboms_crud.py:176](../app/routers/sboms_crud.py) `persist_analysis_run` to call `app.services.analysis_service.persist_analysis_run`. Remove the local copy.
3. Update [app/routers/analyze_endpoints.py:53](../app/routers/analyze_endpoints.py) `from .sboms_crud import compute_report_status, persist_analysis_run` → `from ..services.analysis_service import compute_report_status, persist_analysis_run`.
4. Re-run all tests; the regression test should now pass.

**Tests required.**
* New: `test_sboms_analyze_persists_query_errors`.
* Existing: `tests/test_sboms_analyze_snapshot.py`, `tests/test_analyze_endpoints_snapshot.py`, `tests/test_sboms_analyze_stream.py` must pass unchanged.

**Rollback.** Revert the merge commit; the dual-implementation form is restored.

**Effort.** 1 hour.

---

## R3 — Wire `MAX_UPLOAD_BYTES`

**Problem.** [app/settings.py:225](../app/settings.py) defines `Settings.MAX_UPLOAD_BYTES = 20 * 1024 * 1024` but no code enforces it. `POST /api/sboms` accepts arbitrarily large JSON bodies → memory exhaustion DoS.

**Proposed change.** ASGI middleware that reads `Content-Length`, rejects with 413 if oversized.

**Migration steps.**
1. Add `app/middleware/max_body.py`:
   ```python
   class MaxBodySizeMiddleware:
       def __init__(self, app, max_bytes: int):
           self.app = app
           self.max = max_bytes
       async def __call__(self, scope, receive, send):
           if scope["type"] == "http":
               for k, v in scope.get("headers", []):
                   if k == b"content-length":
                       try:
                           if int(v) > self.max:
                               return await _send_413(send)
                       except ValueError:
                           pass
           await self.app(scope, receive, send)
   ```
2. Wire into `app/main.py:184`: `app.add_middleware(MaxBodySizeMiddleware, max_bytes=settings.MAX_UPLOAD_BYTES)`.
3. Test: `POST /api/sboms` with a 21 MB body → 413.

**Tests required.**
* New: `tests/test_max_upload_size.py`.

**Rollback.** Remove the middleware registration.

**Effort.** 30 min.

---

## R4 — Generic 500 detail messages

**Problem.** Multiple endpoints leak exception text: `raise HTTPException(500, detail=f"Failed to update SBOM: {exc}")` ([app/routers/sboms_crud.py:611-612, 678-679](../app/routers/sboms_crud.py)), `f"Something went wrong: {str(e)}"` ([app/routers/projects.py:80](../app/routers/projects.py)), etc. SQLAlchemy errors can include schema names / query fragments — information disclosure.

**Proposed change.** All 500s use a generic detail; full error logged server-side. A global FastAPI exception handler enforces this for any unhandled exception.

**Migration steps.**
1. Add `app/error_handlers.py`:
   ```python
   from fastapi import FastAPI, Request
   from fastapi.responses import JSONResponse
   import logging
   log = logging.getLogger(__name__)

   def install(app: FastAPI):
       @app.exception_handler(Exception)
       async def unhandled(request: Request, exc: Exception):
           log.exception("unhandled error: %s %s", request.method, request.url.path)
           return JSONResponse(status_code=500, content={"detail": {"code": "internal_error", "message": "Internal server error"}})
   ```
2. Call from `main.py` after middleware: `error_handlers.install(app)`.
3. Update the four router files to use generic detail strings + `log.exception(...)`.

**Tests required.**
* Audit existing tests for ones that assert on the exception message — adjust.
* New: a test that triggers a 500 (e.g. mock `db.commit()` to raise) and asserts the body matches the new envelope.

**Rollback.** Revert.

**Effort.** 1–2 hours.

---

## R5 — Delete dead packages (one big purge)

**Problem.** ~700 LOC of demonstrably unused code:
* `app/repositories/{sbom,analysis,component,project}_repo.py` — verified zero importers.
* `app/ports/repositories.py`, `app/ports/storage.py` — Protocols with no production consumer.
* `app/infrastructure/s3_storage.py` — verified zero importers.
* `app/utils.py` — verified zero importers; functions duplicated elsewhere.
* `app/schemas.py` — `SBOMTypeCreate`, `SBOMAnalysisReportCreate`, `SBOMAnalysisReportOut`, `AnalysisRunSummary` — verified unused.
* `Settings` fields `aws_*` (7 fields) — used only by the dead S3 adapter.
* `Settings.analysis_legacy_level` + `legacy_analysis_level()` helpers — debug echo only.

**Proposed change.** One purge commit. No new abstractions.

**Migration steps.**
1. Verify no test imports any deleted symbol: `grep -rn "from app\.repositories\|from app\.infrastructure\|from app\.ports\.storage\|from app\.utils\|SBOMTypeCreate\|SBOMAnalysisReportCreate\|SBOMAnalysisReportOut\|AnalysisRunSummary" tests/`.
2. Delete the four `app/repositories/*` files + `app/repositories/__init__.py`.
3. Delete `app/ports/repositories.py`, `app/ports/storage.py` (keep `app/ports/__init__.py` only if it's now empty — drop the package).
4. Delete `app/infrastructure/`.
5. Delete `app/utils.py`.
6. Delete the four orphan schemas from `app/schemas.py`.
7. Drop seven `aws_*` fields from `Settings`. Drop `analysis_legacy_level` + helpers + the field in `/api/analysis/config`.
8. Run tests.

**Tests required.** Existing suite. No new tests.

**Rollback.** `git revert`.

**Effort.** 2 hours.

---

## R6 — Collapse the second multi-source orchestrator

**Problem.** Two orchestrators do the same job:
* `app/sources/runner.run_sources_concurrently` — used by all production routers.
* `app/pipeline/multi_source.run_multi_source_analysis_async` (329 lines) — used only by `app.workers.tasks.run_sbom_analysis` (never enqueued — YAGNI-002), the re-export `app.analysis.analyze_sbom_multi_source_async` (zero callers), and `tests/nvd_mirror/test_facade_integration.py`.
The pipeline orchestrator is the only path that calls the NVD-mirror facade — not `runner.py`.

**Proposed change.**
1. Promote NVD-mirror lookup into `NvdSource.__init__(api_key, *, lookup_service=None)`. Default lookup is `nvd_query_by_cpe`; production wiring constructs `lookup_service=build_nvd_lookup_for_pipeline()` once and passes it in.
2. Migrate `tests/nvd_mirror/test_facade_integration.py` from `run_multi_source_analysis_async` to `run_sources_concurrently([NvdSource(...)], components, settings)`.
3. Delete `app/pipeline/`, `app/workers/tasks.py`, `app.analysis.analyze_sbom_multi_source_async`, `app.analysis.AnalysisSource`, the never-enqueued Celery `run_sbom_analysis` task.
4. Keep `app/workers/celery_app.py` and `app/nvd_mirror/tasks.py` — `mirror_nvd` still runs hourly via beat.

**Migration steps.**
1. Add `lookup_service` constructor arg to `NvdSource`. Make sure `nvd_query_by_components_async` accepts an optional lookup callable (or refactor to use `self.lookup_service`).
2. Update `app.sources.factory.build_source_adapters` to pass the lookup service to `NvdSource(...)`.
3. Update the three integration tests in `tests/nvd_mirror/test_facade_integration.py`.
4. Verify all integration tests still pass with mirror-enabled config.
5. Delete the dead modules in one commit.

**Tests required.**
* Existing mirror integration tests (migrated).
* Add: `test_nvd_source_uses_lookup_service` — passes a fake lookup, asserts adapter calls it.

**Rollback.** Revert.

**Effort.** Half a day.

---

## R7 — Pydantic schema for `_run_legacy_analysis` response

**Problem.** Five `analyze-sbom-*` routes return hand-built dicts. FE compensates with `[key: string]: unknown`. Largest single drift surface in the app.

**Proposed change.**
1. Add `AdhocAnalysisRunOut` to `app/schemas.py` matching the **flat** shape of `AnalysisRunOut` plus the legacy `runId`/`status` aliases the FE currently reads.
2. Add `response_model=AdhocAnalysisRunOut` to all five routes in `app/routers/analyze_endpoints.py`.
3. Drop the `summary` block from the BE response. Update [frontend/src/hooks/useBackgroundAnalysis.ts:65-71](../frontend/src/hooks/useBackgroundAnalysis.ts) to read `result.total_findings` directly.
4. Tighten `frontend/src/types/index.ts:ConsolidatedAnalysisResult` to mirror `AdhocAnalysisRunOut`. Drop `[key: string]: unknown`. (Better: regenerate from OpenAPI — see Quick Wins.)

**Migration steps.**
1. PR1 (BE): add `AdhocAnalysisRunOut` schema + `response_model`. Tests update for the response_model side-effect (Pydantic strips unknown keys by default).
2. PR2 (FE): update `useBackgroundAnalysis.ts` to read flat `total_findings`. Tighten `ConsolidatedAnalysisResult`. Verify the hook tests (when written — see CC-028).
3. PR3 (BE): drop the legacy `summary`/`sbom` blocks from the response builder. Snapshot tests `tests/snapshots/analyze_sbom_consolidated.json` etc. need regeneration.

**Tests required.**
* Update snapshots in `tests/snapshots/`.
* New: integration test asserting `runId == id` and no extra keys returned.

**Rollback.** Revert PRs in reverse order. PR3 last.

**Effort.** 1 day.

---

## R8 — Move source query bodies out of `app/analysis.py`

**Problem.** `app.analysis` is 1.4k lines doing seven jobs (SOLID-SRP-001). `app.sources.{nvd,osv,ghsa}` are shells that lazy-import back into the legacy module (OOP-005). Three docstrings say "Phase 5 will move it" — but Phase 5 hasn't happened.

**Proposed change.** Physically move:
* `nvd_query_by_components_async` + `nvd_query_by_cpe` + `nvd_query_by_keyword` + `_finding_from_raw` + `_nvd_fetch_cves_paginated` + `_cpe23_virtual_match_*` + `extract_cwe_from_nvd` + the `requests.Session` setup → `app/sources/nvd.py`.
* `osv_query_by_components` + `_best_score_and_vector_from_osv` + `extract_cwe_from_osv` + `extract_fixed_versions_osv` + `enrich_component_for_osv` → `app/sources/osv.py`.
* `github_query_by_components` + `_github_ecosystem_from_purl_type` + `extract_cwe_from_ghsa` → `app/sources/ghsa.py`.
* `_async_get`, `_async_post` → `app/http_client.py` as `async_get` / `async_post`.
* `CVERecord` and CVSS-related dataclasses → `app/sources/_cve_record.py`.
* `AnalysisSettings`, `_MultiSettings`, `get_analysis_settings`, `get_analysis_settings_multi` → `app/sources/_settings.py` (+ split per-adapter — see ISP-001 follow-up).

After move, `app.analysis` becomes a deprecation shim re-exporting from `app.sources.*` for one release, then deleted.

**Migration steps.**
1. Move OSV piece first (smallest). Update `app.sources.osv.OsvSource.query` to call the new local function. Delete the lazy import. Run snapshot test.
2. Move GHSA piece. Drop `gh_token_override` field from settings; `GhsaSource.query` reads `self.token`.
3. Move NVD piece. Update `app.sources.nvd.NvdSource.query` to use the local function and the injected `lookup_service` from R6.
4. Move helpers + dataclasses to dedicated submodules.
5. `app/analysis.py` becomes a re-export stub. Once routers stop importing from `app.analysis`, delete the file.

**Tests required.** Existing snapshot + integration tests must pass at every step.

**Rollback.** Per-step `git revert`.

**Effort.** 1–2 days.

---

## R9 — Pull SBOM CRUD persistence + orchestration into a service layer

**Problem.** `app/routers/sboms_crud.py` is 949 lines, owning persistence (`upsert_components`, `persist_analysis_run`, `sync_sbom_components`), orchestration (`create_auto_report`, the SSE `event_stream`), validation, and HTTP wiring. Same for `analyze_endpoints.py:_run_legacy_analysis`.

**Proposed change.**
1. New file `app/services/analysis_pipeline.py` exposing:
   * `analyze_sbom_id(db, sbom_id, sources, *, on_event=None) -> AnalysisRun` — runs the adapters, persists, returns the row.
   * Internal helpers: `_extract_components_for_analysis(sbom)`, `_build_summary(findings)`.
2. New `app/services/sse_events.py` with `_sse_event(event_type, data)` and an `AnalyzeStreamRunner` class that yields events.
3. `routers/sboms_crud.py` becomes ~400 lines: HTTP wiring + `_validate_*` helpers + Pydantic schemas. Calls `analysis_pipeline.analyze_sbom_id(...)`.
4. `routers/analyze_endpoints.py` becomes ~120 lines: dispatch to `analysis_pipeline.analyze_sbom_id(..., sources=[…])`.

**Migration steps.**
1. Land R2 (merge `persist_analysis_run`) first.
2. Move `upsert_components` + `sync_sbom_components` into `services/sbom_service.py` (most already there — drop the router copies).
3. Move `create_auto_report` → `analysis_pipeline.analyze_sbom_id`.
4. Move `_run_legacy_analysis` body → `analysis_pipeline.analyze_sbom_id` (covers the same path).
5. Refactor SSE handler to consume `analysis_pipeline.analyze_sbom_id(..., on_event=queue.put)`.
6. Run all tests.

**Tests required.** Existing snapshots + stream tests + new CRUD tests (R recommended in CC-027).

**Rollback.** Per-step revert.

**Effort.** 1.5 days.

---

## R10 — Native JSON columns + drop `RunCache` redundancy

**Problem.**
* `AnalysisFinding.aliases` and `AnalysisFinding.fixed_versions` stored as JSON-in-Text (BE-008). Three places `json.dumps`/`json.loads`. Frontend duplicates parsing.
* `RunCache.run_json` and `AnalysisRun.raw_report` are two copies of the same data (BE-009).

**Proposed change.**
1. Alembic migration 003: change `aliases` and `fixed_versions` to `JSON` (Postgres `JSONB`, SQLite `JSON`).
2. Drop `RunCache` table (if R2 lands first — `raw_report` is the canonical copy). PDF generation falls through `_rebuild_run_from_db` which already exists.
3. Update `routers/sboms_crud.py:235-272`, `services/analysis_service.py:178-200`, `services/pdf_service.py:153`, `routers/pdf.py:73-78` to read native lists.
4. Frontend: `aliases: string[] | null`, `fixed_versions: string[] | null`. Drop `JSON.parse` in `FindingsTable.tsx:23-35` and `useBackgroundAnalysis.ts`.

**Migration steps.**
1. PR1: Alembic migration converting JSON-string → JSON. Test on staging Postgres + dev SQLite.
2. PR2: Update BE persist + read paths.
3. PR3: Update FE types + components.
4. Once `RunCache` is unused for 2 weeks, PR4: Alembic migration dropping `RunCache`.

**Tests required.**
* Unit test: round-trip a finding with non-empty `aliases` + `fixed_versions`.
* Migration test: data preserved through up + down.

**Rollback.** Down migration restores the columns. PR4 is harder to revert — schedule it last.

**Effort.** 1 day.

---

## Quick wins (≤ 30-min batch — single commit, low risk)

These are safe, mechanical, no behaviour change unless noted:

1. **DRY-001..004**: Single canonical `now_iso`, `safe_int`, `safe_float`, `compute_report_status`, `normalize_details`, `normalized_key` in `app/services/sbom_service.py`. Delete the duplicates in [routers/sboms_crud.py](../app/routers/sboms_crud.py), [routers/projects.py](../app/routers/projects.py), [services/analysis_service.py](../app/services/analysis_service.py). (Note: `app/utils.py` is being deleted in R5, so skip it.)
2. **DRY-006**: Delete `_rebuild_run_from_db` from [routers/pdf.py](../app/routers/pdf.py); call `services.pdf_service.rebuild_run_from_db`.
3. **DRY-009**: `_validate_user_id` + `_validate_positive_int` → `app/_validation.py`. Two routers import.
4. **DRY-016**: Single `analyzeSbomBySource(source, payload)` in `frontend/src/lib/api.ts`. Four functions collapse.
5. **OOP-003**: Move the eight `Settings.X = ...` constants into a new `app/constants.py` module. Update three import sites.
6. **OOP-004**: Drop the underscore-prefixed re-exports in `app/analysis.py:347-363`. Routers / sbom info import the real names directly.
7. **KISS-008**: Delete the `lru_cache(maxsize=1)` settings factories in `app/analysis.py`. Use `app.settings.get_settings()` consistently.
8. **KISS-006**: `_body_copy = deepcopy` in `app/idempotency.py`.
9. **SUP-POLA-002**: Rename `app.nvd_mirror.api.get_settings` route handler to `read_mirror_settings`.
10. **YAGNI-013**: Remove `Settings.analysis_legacy_level` + the `/api/analysis/config` echo of it.
11. **FE-009**: Two named timeout constants in `frontend/src/lib/api.ts`.
12. **CC-015 + CC-016**: Drop `nvd_api_key`/`github_token`/`vulndb_api_key` from `AnalyzeSBOMPayload` (FE) and from `useAnalysisStream`'s POST body. BE silently ignored these anyway.

**Estimated effort:** half a day for everything. **One commit per quick-win** preferred (the prompt's discipline) — total 12 commits, but each is < 5 file changes.

---

## Deferred (real but not worth fixing now)

| ID | Reason for deferral |
|---|---|
| **OOP-006 / SOLID-ISP-001** (per-adapter typed config) | Worth doing, but only after R8 lands. |
| **OOP-009 / SUP-COI-001** (composition over inheritance for settings) | Subsumed by the per-adapter config split — same fix. |
| **OOP-014 / SOLID-OCP-005 / DRY-008** (`count_severities`) | One helper, five sites. Will fall out of R8 / R9 cleanups. Cheap, but no urgency. |
| **SOLID-OCP-002** (parsing dispatch) | Two formats today; the if/elif is fine. Revisit when SWID lands. |
| **SOLID-OCP-004** (PURL → CPE) | Stable mappings; KISS argues against premature plugin-ification. |
| **SOLID-OCP-003 / OOP-013** (factory classmethod) | Trivial cleanup; do it during R8. |
| **BE-013** (sequential NVD) | Documented design choice. Don't touch. |
| **BE-016** (no async DB driver) | Real benefit but high migration cost; today's load doesn't justify. |
| **BE-038** (correlation IDs) | Nice-to-have ops feature. Add when on-call frequency justifies. |
| **CC-018** (`projectid` vs `project_id`) | Aesthetic + migration cost. Rename when you're already touching that table for another reason. |
| **CC-019** (`created_on` vs `started_on`) | Aesthetic only. |
| **FE-005** (server components migration) | Blocked on R1. Big payoff but big effort. |
| **FE-013** (URL state for filters) | UX improvement, not a correctness fix. |
| **FE-019** (Zod ↔ Pydantic generation) | Subsumed by CC-029 generated-from-OpenAPI approach — do once. |
| **KISS-009** (replace `useToast` with sonner) | Aesthetic. Custom toast works. |
| **KISS-010** (replace SSE parser with library) | Works today. Replace if reconnect logic is ever added (R: FE-011). |

---

## Executive summary

### Total findings by severity

| File | Critical | High | Medium | Low | Total |
|---|---|---|---|---|---|
| `01_oop.md` | 0 | 2 | 5 | 7 | 14 |
| `02_solid.md` | 0 | 6 | 5 | 8 | 19 |
| `03_dry.md` | 0 | 1 | 7 | 8 | 16 |
| `04_kiss.md` | 0 | 0 | 5 | 10 | 15 |
| `05_yagni.md` | 1 | 2 | 7 | 8 | 18 |
| `06_supporting_principles.md` | 0 | 3 | 9 | 9 | 21 |
| `07_backend.md` | 0 | 3 | 13 | 18 | 34 |
| `08_frontend.md` | 0 | 0 | 7 | 13 | 20 |
| `09_cross_cutting.md` | 0 | 1 | 8 | 11 | 20 |
| **Total (with cross-listing)** | **1** | **18** | **66** | **92** | **177** |
| Verified-positive (no violation) | – | – | – | – | **14** |

### Top three systemic issues (architectural, not line-level)

1. **The "phased refactor" is half-finished.** New architecture (`app/sources/`, `app/services/`, `app/repositories/`, `app/ports/`) was built alongside the old (`app/analysis.py`, inline router queries, `app/pipeline/multi_source.py`). Most of the old still runs production; most of the new is shells, dead code, or unwired. Three docstrings explicitly defer "Phase 5" moves that never happened. The codebase pays double-implementation cost without realising the abstraction value.
2. **Architectural intent contradicts wiring.** The comment in `app/main.py:13-19` says "all DB access in `app/repositories/`" — but `app/repositories/` is unreachable dead code with several methods that reference non-existent ORM columns. The hexagonal sub-app `app/nvd_mirror/` is a competent positive example of the same architecture done right; the rest of the backend doesn't use it. Decide: kill the unused parts (R5) OR finish the wiring (separate effort, ~1 week).
3. **Contract surface is not enforced.** Five `analyze-sbom-*` routes have no `response_model`. The frontend has `[key: string]: unknown` to absorb anything the backend sends. Pydantic ↔ TypeScript types drift in 6 different shape interfaces. The CRUD test layer is thin; analyses get coverage via snapshots, but persistence-side bugs (e.g. SOLID-SRP-003 / DRY-005, where `query_error_count` and `raw_report` are silently lost) survive because no test asserts those fields. Generating FE types from OpenAPI (CC-029) plus adding `response_model=…` everywhere fixes this category in one move.

### Codebase health

The SBOM Analyzer is **structurally sound but operationally fragile**. The vulnerability-source adapter design (`VulnSource` Protocol + registry + concurrent runner) is correct; the NVD-mirror sub-app is exemplary; the FastAPI/Pydantic/Tailwind stack choices are appropriate. What's holding it back is **incomplete migration discipline**: every "Phase X" promise in a docstring is an outstanding refactor IOU. The frontend is currently un-buildable due to a deliberate Next.js downgrade, and the backend has at least one silent persistence bug, one DoS-vector unenforced limit, and one auth role split that's only a comment. None of these is hard to fix; the fix is **finishing what was started**, not starting something new. After R1–R5 (≤ 1 week of work), the codebase moves from "fragile" to "shippable"; after R6–R10 (~ another 2 weeks), it's "maintainable."

---

> **Audit complete.** Findings written to `audit/`. Awaiting approval on `audit/10_refactor_plan.md` before any code changes. Reply with the finding IDs to apply, or 'apply quick wins' to start with the safe batch.
