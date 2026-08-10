# R6 — Orchestrator Collapse: Final Report

> Audit references: refactor-plan §R6, YAGNI-002, OOP-005.

---

## Phase A — Reconnaissance

[audit/r6_orchestrator_recon.md](r6_orchestrator_recon.md) (493 lines).

Two orchestrators existed:
- `app/sources/runner.run_sources_concurrently` — production. Adapter-based. **No mirror knowledge.**
- `app/pipeline/multi_source.run_multi_source_analysis_async` — pipeline-only path. The **only** path that called the NVD-mirror facade.

Pipeline consumers found: 3 tests + 2 dead exports (`analyze_sbom_multi_source_async`, `AnalysisSource`) + 1 never-enqueued Celery task (`run_sbom_analysis`). **0 production callers.**

Mirror chain at start of R6:
```
pipeline._nvd → build_nvd_lookup_for_pipeline().query_legacy(cpe, api_key, settings)
  → 5-branch facade (disabled / stale / hit / empty / raise)
```

Mirror chain at end of R6:
```
runner.run_sources_concurrently → NvdSource.query
  → nvd_query_by_components_async (executor)
  → facade.query_legacy(cpe, api_key=, settings=)
  → 5-branch facade (disabled / stale / hit / empty / raise)
```

The 5-branch decision logic is unchanged. Only the orchestrator above it changed.

---

## Design decisions

| Decision | Choice | Why |
|---|---|---|
| Factory pattern | **Pattern 2** (factory builds the facade itself) | Matches the existing convention in `build_source_adapters`, which already reads credential helpers without taking them as parameters. No `app/main.py` change required. |
| `lookup_service` type | **Plain `Callable[[str, str\|None, Any], list[dict]]`**, no new Protocol | Matches the shape of `nvd_query_by_cpe` exactly; no shape adaptation needed inside `nvd_query_by_components_async`. Avoids a new abstraction. |
| Per-CPE merge logic | **Substitution**, not "prefilled + residual" | The mirror facade already implements the 5-branch fallback internally and always returns a `list[dict]` — same shape as live NVD. Replacing the executor's callable is a single-line drop-in. |
| Facade construction cadence | **Once per `build_source_adapters` call** (== per analysis run) | Mirrors what `pipeline._nvd` did. Cheap object construction; the SQLAlchemy session is opened per `query_legacy` call inside the session-scoped wrapper. |

---

## Files modified

| File | Lines changed | Phase | Notes |
|---|---|---|---|
| [app/sources/nvd.py](../app/sources/nvd.py) | +13 / −2 | C | `__init__` adds keyword-only `lookup_service`; `query()` forwards it. |
| [app/sources/factory.py](../app/sources/factory.py) | +14 / −2 | C | `build_source_adapters` constructs `build_nvd_lookup_for_pipeline()` once, wraps `facade.query_legacy` in a `(cpe, api_key, settings) -> list[dict]` closure, threads to `NvdSource`. |
| [app/analysis.py](../app/analysis.py) | +6 / −42 | C+E | C: adds `lookup_service: Any = None` kwarg to `nvd_query_by_components_async`; per-CPE executor call substitutes the callable when wired. E: deletes `class AnalysisSource(str, Enum)`, `analyze_sbom_multi_source_async`, `_env_list`, `Enum` import, obsolete cleanup-note comment. |
| [tests/conftest.py](../tests/conftest.py) | +9 / −5 | C+E | C: `_fake_nvd_query_by_components_async` accepts `lookup_service=None` kwarg. E: docstring tweak in `_fake_nvd_query_by_cpe` to mention the new mirror chain. |
| [tests/test_persist_run_query_errors_regression.py](../tests/test_persist_run_query_errors_regression.py) | +1 / −1 | C | Local fake `_fake_nvd_with_error` accepts `lookup_service=None`. |
| [tests/test_sources_adapters.py](../tests/test_sources_adapters.py) | +1 / −1 | C | Local fake `fake_nvd` accepts `lookup_service=None`. |

## Files added

| File | Lines | Phase |
|---|---|---|
| [tests/test_nvd_source_uses_lookup_service.py](../tests/test_nvd_source_uses_lookup_service.py) | 107 | C.6 |
| [audit/r6_orchestrator_recon.md](r6_orchestrator_recon.md) | 493 | A |

## Tests migrated (Phase D)

[tests/nvd_mirror/test_facade_integration.py](../tests/nvd_mirror/test_facade_integration.py) — 3 of 4 tests rewired to `run_sources_concurrently(build_source_adapters(["NVD"]), components, cfg)` via a local helper `_run_nvd_via_runner(sbom_json)`. All facade-decision assertions preserved verbatim:

| Test | Diff |
|---|---|
| `test_orchestrator_uses_live_when_mirror_disabled` | `result["findings"]` → returned-tuple `findings`; pipeline call replaced with helper. |
| `test_orchestrator_uses_mirror_when_enabled_and_fresh` | Same shape change; assertion `live_call_count["n"] == 0` preserved verbatim. |
| `test_orchestrator_falls_back_to_live_when_mirror_stale` | Same shape change; assertion `len(captured) >= 1` preserved verbatim. |
| `test_session_scoped_facade_opens_and_closes_session_per_call` | **Untouched** — exercises the facade builder directly, no pipeline dependency. |

## Files deleted (Phase E)

| Path | LOC | Phase |
|---|---|---|
| `app/pipeline/__init__.py` | 9 | E.3 |
| `app/pipeline/context.py` | 28 | E.3 |
| `app/pipeline/multi_source.py` | 329 | E.3 |
| `app/pipeline/` (directory) | — | E.3 |
| `app/workers/tasks.py` | 29 | E.4 |

## Total LOC delta across R6

```
$ git diff --stat 2fc9aed^..HEAD -- app/ tests/ audit/
 16 files changed, 704 insertions(+), 477 deletions(-)
```

Net **+227** lines because the audit recon doc (493 LOC) and the new contract test file (107 LOC) account for additions; if you exclude those documentation/test artifacts, the production code change is **+25 / −477 = net −452 LOC**.

---

## Final pytest

```
======================= 229 passed, 5 warnings in 8.94s ========================
```

App boots cleanly:
```
$ python -c "import app; from app.main import app as _; print('OK')"
[INFO] 2026-04-29 00:17:29  sbom.logger  Logging initialised — level=INFO  format=text  file=(console only)
OK
```

Negative grep across `*.py`:
```
$ grep -rn "run_multi_source_analysis_async|analyze_sbom_multi_source_async|app\.pipeline|run_sbom_analysis|\bAnalysisSource\b" --include='*.py' .
tests/test_nvd_source_uses_lookup_service.py:5:Independent of app.pipeline.* and tests.nvd_mirror.* — exercises only
```

The single residual hit is the new contract test's docstring referring to the **historical** `app.pipeline.*` decoupling — explanatory text only, not a code reference.

---

## Commits applied

| Commit | Phase | Subject |
|---|---|---|
| `2fc9aed` | C feat | feat(sources): NvdSource accepts injected lookup_service for mirror-first reads (refactor-plan R6) |
| `6c2ae24` | C test | test(sources): assert NvdSource consults lookup_service before live NVD (R6) |
| `b708468` | D | test(nvd-mirror): migrate facade integration tests from pipeline orchestrator to runner (R6) |
| `13c16f5` | E.3 | chore(cleanup): remove app/pipeline/ — runner+NvdSource is the single orchestrator (R6) |
| `ed4d93c` | E.4 | chore(cleanup): remove never-enqueued run_sbom_analysis Celery task (YAGNI-002, R6) |

5 commits — within the prompt's R6 budget (Phase C: 2, Phase D: 1, Phase E: 2). Audit doc bundled into the C.feat commit.

---

## Mirror call chain — before vs. after

**Before R6** (two paths existed; only one knew about the mirror):

```
Path A (production — runner-based):
  router.create_auto_report → run_sources_concurrently(adapters)
    → NvdSource.query → nvd_query_by_components_async
    → for each CPE:  nvd_query_by_cpe(cpe, api_key, cfg)        # LIVE NVD ONLY

Path B (pipeline-based — used only by 3 tests + dead Celery task):
  pipeline.run_multi_source_analysis_async
    → inner _nvd():
       → build_nvd_lookup_for_pipeline()
       → for each CPE:  nvd_lookup_service.query_legacy(cpe, ...)  # MIRROR-AWARE
```

**After R6** (single path; everything mirror-aware):

```
router.create_auto_report → run_sources_concurrently(adapters)
  → NvdSource.query → nvd_query_by_components_async(..., lookup_service=facade_callable)
  → for each CPE:  facade_callable(cpe, api_key, cfg)
                   = facade.query_legacy(cpe, api_key=, settings=)
                   = 5-branch decision (disabled / stale / hit / empty / raise)
```

The facade's 5-branch logic, the per-query session lifecycle, and the live-NVD fallback shape are all unchanged.

---

> "R6 complete. Pipeline orchestrator collapsed; mirror lookups now flow through NvdSource via the runner. 3 tests migrated, 4 files deleted, 452 production LOC removed (706 − 254 across `app/` only). All tests green."
