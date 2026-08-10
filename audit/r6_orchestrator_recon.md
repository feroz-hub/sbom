# R6 — Reconnaissance: collapse the second multi-source orchestrator

> Audit references: refactor-plan §R6, YAGNI-002, OOP-005.
> Repo HEAD verified at `d7d12c4` (post-R5). Audit was on `4435bd2`.

---

## §1 — Freshness check

```
$ git log --oneline 4435bd2..HEAD -- app/pipeline/ app/sources/ app/workers/ tests/nvd_mirror/
# → no results
```

Zero commits between the audit baseline and HEAD touched any file in scope. The audit's claims are fresh.

---

## A.1 — `app/pipeline/` contents

```
$ wc -l app/pipeline/*.py
   9 app/pipeline/__init__.py
  28 app/pipeline/context.py
 329 app/pipeline/multi_source.py
 366 total
```

Files:
- [`app/pipeline/__init__.py`](../app/pipeline/__init__.py) (9 LOC) — re-exports `MultiSourcePipelineContext` and `run_multi_source_analysis_async`.
- [`app/pipeline/context.py`](../app/pipeline/context.py) (28 LOC) — defines the dataclass `MultiSourcePipelineContext`. **Searched for callers: zero hits.** Re-exported from `__init__.py` but no consumer ever instantiates it.
- [`app/pipeline/multi_source.py`](../app/pipeline/multi_source.py) (329 LOC) — defines the single async function `run_multi_source_analysis_async(sbom_json, sources=None, settings=None) -> dict`.

**External imports inside the pipeline module** (verbatim from [`multi_source.py:29-45`](../app/pipeline/multi_source.py#L29-L45)):

```python
from ..analysis import (
    LOGGER, AnalysisSource, _augment_components_with_cpe, _env_list, _executor,
    _finding_from_raw, enrich_component_for_osv, get_analysis_settings_multi,
    github_query_by_components, nvd_query_by_cpe, nvd_query_by_keyword,
    osv_query_by_components, resolve_nvd_api_key,
)
from ..credentials import vulndb_api_key_for_adapters
from ..sources.vulndb import VulnDbSource
```

**Mirror-facade call inside the pipeline** (lines 134-148):

```python
from ..nvd_mirror.application import build_nvd_lookup_for_pipeline
nvd_lookup_service = build_nvd_lookup_for_pipeline()

def _fetch_cpe(cpe: str) -> tuple[str, list[dict], str | None]:
    try:
        cve_objs = nvd_lookup_service.query_legacy(cpe, api_key=api_key, settings=cfg)
        return cpe, cve_objs, None
    except Exception as exc:
        return cpe, [], str(exc)
```

This is the load-bearing chain that R6 must preserve.

---

## A.2 — `app/sources/` runner / factory / NvdSource

### Protocol — [`app/sources/base.py`](../app/sources/base.py)

```python
class SourceResult(TypedDict):
    findings: list[dict]
    errors: list[dict]
    warnings: list[dict]

@runtime_checkable
class VulnSource(Protocol):
    name: str
    async def query(self, components: list[dict], settings: Any) -> SourceResult: ...
```

### `NvdSource` current state — [`app/sources/nvd.py`](../app/sources/nvd.py) (47 LOC)

```python
class NvdSource:
    name: str = "NVD"
    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = (api_key or "").strip() or None

    async def query(self, components, settings) -> SourceResult:
        if not components:
            return empty_result()
        from app.analysis import nvd_query_by_components_async
        findings, errors, warnings = await nvd_query_by_components_async(
            components, settings, nvd_api_key=self.api_key,
        )
        return SourceResult(findings=findings, errors=errors, warnings=warnings)
```

`nvd_query_by_components_async` is at [`app/analysis.py:1243`](../app/analysis.py#L1243). It iterates per CPE and calls `nvd_query_by_cpe(cpe, api_key, cfg)` directly — **no mirror lookup**. Live NVD only.

### `build_source_adapters` — [`app/sources/factory.py:46`](../app/sources/factory.py#L46)

Pattern 2 (the factory reads settings/credentials itself):

```python
def build_source_adapters(sources: Iterable[str]) -> list[VulnSource]:
    from ..credentials import github_token_for_adapters, nvd_api_key_for_adapters, vulndb_api_key_for_adapters
    factories = {
        "NVD": lambda: NvdSource(api_key=nvd_api_key_for_adapters()),
        "OSV": OsvSource,
        "GITHUB": lambda: GhsaSource(token=github_token_for_adapters()),
        "VULNDB": lambda: VulnDbSource(api_key=vulndb_api_key_for_adapters()),
    }
    return [factories[name]() for name in normalize_source_names(sources) if name in factories]
```

No settings parameter, no callable injection. The credential-fetch helpers are imported lazily.

### `run_sources_concurrently` — [`app/sources/runner.py:46`](../app/sources/runner.py#L46)

Signature: `(sources, components, settings, progress_queue=None) -> (findings, errors, warnings)`.

- Concurrency: `asyncio.gather` over `_run_one(src)` per adapter.
- Errors: per-adapter try/except; an adapter exception becomes `{"source": ..., "error": ...}` in the aggregated errors list. Never cancels the gather.
- Events (optional `progress_queue`): `running` → `complete | error` → final `done`.
- **No mirror knowledge.** Treats every adapter equally.

---

## A.3 — Side-by-side comparison

| Capability | `runner.run_sources_concurrently` | `pipeline.run_multi_source_analysis_async` |
|---|---|---|
| Concurrency model | `asyncio.gather` over adapter `query()` coroutines | `asyncio.gather` over four inner coroutines (`_nvd`, `_osv`, `_gh`, `_vulndb`); NVD's CPE+keyword fan-out further uses an `asyncio.Semaphore(cfg.max_concurrency)` over `loop.run_in_executor` calls |
| Adapter construction | Caller builds adapters and passes them in | Inline — VulnDb adapter built mid-flight; NVD/OSV/GH inlined as inner async fns |
| **NVD-mirror lookup** | **NO** — `NvdSource.query` calls `nvd_query_by_components_async` which calls `nvd_query_by_cpe` directly | **YES** — calls `build_nvd_lookup_for_pipeline().query_legacy(cpe, ...)` per CPE (see `multi_source.py:134-148`) |
| NVD keyword fallback | YES — handled inside `nvd_query_by_components_async` (single function, single semaphore-bounded gather) | YES — own implementation; both CPE-based and keyword-based fan-outs run via the executor |
| Per-source timeout | None at orchestrator level; relies on adapter / underlying-call timeouts | Same |
| Per-source retry | None at orchestrator level | Same |
| Event/progress emission | Optional `progress_queue` with `running/complete/error/done` | None — caller gets a single result dict at the end |
| Error aggregation shape | `[{"source": "<name>", "error": "<msg>"}, ...]` (single source-level entry per failed adapter) | `[{"source": "NVD", "cpe": "...", "error": "..."}, {"source": "NVD", "keyword": "...", "error": "..."}, ...]` (per-CPE / per-keyword granularity for NVD) |
| Result aggregation shape | `(findings, errors, warnings)` triple | full `details` dict with totals/buckets/`analysis_metadata`/notes |
| Settings access pattern | `cfg = settings` passed in by caller | `cfg = settings or get_analysis_settings_multi()` (falls back to env defaults) |
| Module-state | None | Uses `app.analysis._executor` (module-level ThreadPoolExecutor) and module logger |

**BEHAVIOR DIVERGENCES**

1. **Mirror lookup** — pipeline-only behavior. **Preserve via R6**: thread the facade through `NvdSource` so the runner-side path also goes through it.
2. **NVD per-CPE error granularity** — pipeline records `{cpe: ..., error: ...}` whereas `nvd_query_by_components_async` already does the same (see [`app/analysis.py:1351`](../app/analysis.py#L1351) — `errors.append({"source": "NVD", "cpe": cpe, "error": ...})`). **Functionally equivalent.**
3. **Result wrapping** — pipeline returns `details` dict with totals/buckets; runner returns `(findings, errors, warnings)`. **Drop the wrapping** — production routers (`create_auto_report`, `_run_legacy_analysis`, the SSE handler) all build their own `details` dict from the runner's triple already. The pipeline's result-dict construction is duplicate code that no production caller consumes.
4. **`cfg = settings or get_analysis_settings_multi()` fallback** — pipeline is callable without explicit settings. Runner's `nvd_query_by_components_async` requires a `settings` arg. **Drop**: production callers always pass settings; the fallback only matters for the dead Celery task path which is being deleted.

---

## A.4 — Mirror-lookup call chain (verified)

```
pipeline.run_multi_source_analysis_async(...)
  └─ inner coroutine `_nvd()`
       └─ build_nvd_lookup_for_pipeline()         # constructs facade once per analysis run
       └─ for cpe in cpe_set:
            └─ loop.run_in_executor(_executor, _fetch_cpe, cpe)
                 └─ nvd_lookup_service.query_legacy(cpe, api_key=api_key, settings=cfg)
                      └─ SessionScopedNvdLookupService.query_legacy(...)
                           └─ opens SQLAlchemy session
                           └─ NvdLookupService.query_legacy(...)
                                ├─ branch 1: mirror disabled       → live_query(cpe, api_key, settings)
                                ├─ branch 2: enabled but stale     → live + WARNING
                                ├─ branch 3: enabled + fresh + hit → return [dict(r.raw) for r in records]
                                ├─ branch 4: enabled + fresh + 0   → live + INFO
                                └─ branch 5: mirror raises         → live + ERROR
                           └─ session.commit() / close()
```

**Facade entry function**: [`app.nvd_mirror.application.build_nvd_lookup_for_pipeline()`](../app/nvd_mirror/application/facade.py#L223) at `facade.py:223-261`. Returns `SessionScopedNvdLookupService` whose `query_legacy(cpe, *, api_key, settings) -> list[dict]` is the per-CPE entry point.

**Live-query callable inside the facade** (closure at `facade.py:248-253`):

```python
def _late_bound_live(cpe, api_key, settings):
    from app.analysis import nvd_query_by_cpe
    return nvd_query_by_cpe(cpe, api_key, settings=settings)
```

The late re-import is intentional so test monkeypatches of `app.analysis.nvd_query_by_cpe` still take effect.

**Output shape**: `list[dict]` — raw NVD CVE JSON. The mirror serializes its `CveRecord.raw` field, which is the verbatim NVD payload, so mirror hits and live calls return identical structures.

This is the chain R6 preserves. The new chain replaces only the orchestrator layer:

```
runner.run_sources_concurrently(adapters, components, settings)
  └─ NvdSource.query(components, settings)
       └─ nvd_query_by_components_async(components, settings, nvd_api_key, lookup_service)
            └─ for cpe in cpe_order:
                 └─ loop.run_in_executor(_executor, lookup_service, cpe, api_key, cfg)
                      └─ <facade.query_legacy with the same 5 branches>
```

`lookup_service` here is a callable wrapping `facade.query_legacy` — see A.10 design.

---

## A.5 — Pipeline-orchestrator consumer inventory

```
$ grep -rn "from app.pipeline\|from .pipeline\|from ..pipeline" --include='*.py' .
app/analysis.py:1392:    from .pipeline.multi_source import run_multi_source_analysis_async
app/workers/tasks.py:24:    from app.pipeline.multi_source import run_multi_source_analysis_async
tests/nvd_mirror/test_facade_integration.py:139:    from app.pipeline.multi_source import run_multi_source_analysis_async
tests/nvd_mirror/test_facade_integration.py:247:    from app.pipeline.multi_source import run_multi_source_analysis_async
tests/nvd_mirror/test_facade_integration.py:315:    from app.pipeline.multi_source import run_multi_source_analysis_async
```

```
$ grep -rn "run_multi_source_analysis_async\|analyze_sbom_multi_source_async" --include='*.py' .
app/analysis.py:1382:async def analyze_sbom_multi_source_async(
app/analysis.py:1392:    from .pipeline.multi_source import run_multi_source_analysis_async
app/analysis.py:1394:    return await run_multi_source_analysis_async(...)
app/pipeline/__init__.py:4:from .multi_source import run_multi_source_analysis_async
app/pipeline/__init__.py:8:    "run_multi_source_analysis_async",
app/pipeline/multi_source.py:17:async def run_multi_source_analysis_async(
app/sources/dedupe.py:5:CVE ↔ GHSA alias cross-merge that ``analyze_sbom_multi_source_async``  # docstring, deletable
app/workers/tasks.py:24,27 (Celery task body)
tests/nvd_mirror/test_facade_integration.py:139, 142, 247, 250, 315, 317 (3 tests calling pipeline)
tests/test_sboms_analyze_snapshot.py:5 (docstring reference, no functional dependency)
```

```
$ grep -rn "AnalysisSource" --include='*.py' .
app/analysis.py:1236:class AnalysisSource(str, Enum):       # definition
app/pipeline/multi_source.py:31, 61, 64, 258, 260, 262, 264, 315  # only consumer
```

```
$ grep -rn "run_sbom_analysis" --include='*.py' .
app/workers/tasks.py:14, 15, 26, 28        # task definition
app/workers/celery_app.py:4                # docstring mention
```

```
$ grep -rn "run_sbom_analysis\.delay\|run_sbom_analysis\.apply_async\|send_task.*run_sbom_analysis" --include='*.py' .
# → no results

$ grep -rn "run_sbom_analysis" --include='*.ts' --include='*.tsx' frontend/src/
# → no results
```

### Classification

| File / hit | Class | Disposition |
|---|---|---|
| `app/analysis.py:1382` `analyze_sbom_multi_source_async` (re-export wrapper) | DEAD — `tests/conftest.py:184` only mentions the name in a docstring; no functional caller anywhere | Delete in Phase E |
| `app/analysis.py:1236` `class AnalysisSource(str, Enum)` | DEAD — only used inside `app/pipeline/multi_source.py` | Delete in Phase E |
| `app/workers/tasks.py:14` `run_sbom_analysis` Celery task | DEAD — no `.delay()`, no `.apply_async()`, no `send_task`, no beat schedule reference (beat schedules `nvd_mirror.mirror_nvd` only); confirms YAGNI-002 | Delete in Phase E |
| `app/pipeline/__init__.py`, `app/pipeline/multi_source.py`, `app/pipeline/context.py` | DEAD after Phase D test migration | Delete in Phase E |
| `tests/nvd_mirror/test_facade_integration.py` (3 tests calling pipeline) | TEST | Migrate in Phase D |
| `app/sources/dedupe.py:5` (docstring `"analyze_sbom_multi_source_async"`) | docstring drift | Edit in Phase E (one-line cleanup as part of the deletion commit, since the comment refers to a name that's being deleted) |
| `tests/test_sboms_analyze_snapshot.py:5` (docstring) | docstring drift | Same — edit in Phase E along with deletions |
| `tests/conftest.py:184` (`"""...analyze_sbom_multi_source_async..."""` docstring inside `_fake_nvd_query_by_cpe`) | docstring drift | Same |

**Production callers of the pipeline orchestrator**: **0**. Verdict per prompt §A.5: PROCEED.

`_env_list` is the only `_env_*` helper imported by the pipeline (line 33, used at line 59). Other `_env_*` helpers (`_env_str`, `_env_int`, `_env_float`, `_env_bool_top`, `_env_bool`) are used elsewhere in `app/analysis.py` (verified by grep — they have many callers). **`_env_list` should NOT be deleted in Phase E** unless it has no other consumers; quick recheck:

```
$ grep -rn "\b_env_list\b" --include='*.py' .
```

Will run that in Phase E to be safe. If `_env_list` is pipeline-only, delete it; if not, leave alone.

---

## A.6 — Mirror integration tests inventory

[`tests/nvd_mirror/test_facade_integration.py`](../tests/nvd_mirror/test_facade_integration.py) — **383 lines, 4 test functions**. Three call the pipeline orchestrator; the fourth tests the facade builder directly.

### `test_orchestrator_uses_live_when_mirror_disabled` (lines 101-151)

- Asserts: when settings has `enabled=False` (default), the pipeline routes NVD lookups through the facade's live branch.
- Mechanism: `monkeypatch.setattr(analysis_mod, "nvd_query_by_cpe", _fake_live)`; runs `run_multi_source_analysis_async(sbom_json, sources=["NVD"])`; asserts the fake was called and the fake's CVE flowed into `result["findings"]`.
- Migration target: `run_sources_concurrently([NvdSource(api_key=..., lookup_service=facade_callable)], components, settings)`.

### `test_orchestrator_uses_mirror_when_enabled_and_fresh` (lines 157-257)

- Asserts: with `enabled=True`, fresh watermark, and a seeded `CveRecord` matching the test SBOM's generated CPE, the mirror result wins; live `nvd_query_by_cpe` is **never called**.
- Mechanism: seeds `nvd_settings` and `nvd_cve` rows in the test DB; patches `nvd_query_by_cpe` and asserts call count is 0.
- Migration target: same as above.

### `test_orchestrator_falls_back_to_live_when_mirror_stale` (lines 263-321)

- Asserts: with `enabled=True` but stale watermark, NVD lookups go to live.
- Mechanism: seeds `last_successful_sync_at = now - 5d`, `min_freshness_hours=1`; patches live; asserts at least one live call.
- Migration target: same.

### `test_session_scoped_facade_opens_and_closes_session_per_call` (lines 327-382)

- Tests `SessionScopedNvdLookupService` directly (does **not** call the pipeline orchestrator). Constructs `build_nvd_lookup_for_pipeline()`, wraps `SessionLocal` with a counting class, asserts 3 lookups → 3 sessions opened, 3 closed.
- **No migration needed.** Decoupled from the pipeline orchestrator.

### Fixtures ([`tests/nvd_mirror/test_facade_integration.py:68-96`](../tests/nvd_mirror/test_facade_integration.py#L68-L96))

`isolated_session` builds an isolated SQLite DB, creates the schema, and rebinds `app.db.SessionLocal`. The facade builder (`build_nvd_lookup_for_pipeline`) imports `SessionLocal` from `app.db` lazily, so the rebind takes effect.

### Other tests in `tests/nvd_mirror/`

`test_facade.py`, `test_use_cases.py`, `test_api.py`, etc. — none import from `app.pipeline.*` (verified by greps above). The 3-test migration scope holds.

---

## A.7 — Celery task is never enqueued

```
$ grep -rn "run_sbom_analysis\.delay\|run_sbom_analysis\.apply_async\|send_task.*run_sbom_analysis" --include='*.py' .
# → no results

$ grep -rn "run_sbom_analysis" --include='*.ts' --include='*.tsx' frontend/src/
# → no results
```

Beat schedule in `app/workers/celery_app.py:42-47` references only `"nvd_mirror.mirror_nvd"`. **Confirmed: never enqueued.** Proceed with deletion in E.4.

---

## A.8 — What stays

Verified by reading their imports — none import from `app/pipeline/` or `app/workers/tasks.py`:

- [`app/workers/celery_app.py`](../app/workers/celery_app.py) — Celery app + beat schedule. Imports `Celery`, `crontab`, `app.settings`. Does not import the doomed task by code; only by name string in `include=[...]`. **Collateral edit** in E.4: drop `"app.workers.tasks"` from the `include=` list.
- [`app/nvd_mirror/tasks.py`](../app/nvd_mirror/tasks.py) — defines `mirror_nvd`. Imports from `.celery_app` (i.e. `app.workers.celery_app`), and from siblings inside `app.nvd_mirror`. **No pipeline imports.** Stays.
- [`app/nvd_mirror/`](../app/nvd_mirror/) package — verified `application/facade.py` is the source of `build_nvd_lookup_for_pipeline()`, which R6 keeps using. **Stays.**

---

## A.9 — Conclusion

- Pipeline orchestrator entry points found: `run_multi_source_analysis_async` (1 function), `MultiSourcePipelineContext` (1 unused dataclass).
- Production callers of the pipeline orchestrator: **0**.
- Mirror-lookup chain: `pipeline._nvd → build_nvd_lookup_for_pipeline().query_legacy(cpe, api_key, settings) → 5-branch facade → live or mirror`.
- Tests to migrate (Phase D): **3** (the 4th `test_session_scoped_facade_opens_and_closes_session_per_call` doesn't depend on the pipeline orchestrator).
- Files to delete (Phase E): `app/pipeline/__init__.py`, `app/pipeline/context.py`, `app/pipeline/multi_source.py` (whole package); `app/workers/tasks.py` becomes empty after the deletion → also delete; in `app/analysis.py` delete `class AnalysisSource(str, Enum)` (1230s) and `async def analyze_sbom_multi_source_async(...)` (1382-1394). Possibly delete `_env_list` if it has no other callers (recheck in Phase E). Update `app/workers/celery_app.py` `include=` list.
- Files to modify in Phase C: `app/sources/nvd.py` (constructor + query body), `app/sources/factory.py` (wire facade into NvdSource), `app/analysis.py` (one new kwarg + one branch in `nvd_query_by_components_async`'s per-CPE loop). **No `app/main.py` change** because Pattern 2 (factory builds the facade itself) matches the existing factory convention.
- **Verdict**: PROCEED.

---

## A.10 — Phase C design

### Pattern choice

**Pattern 2 — factory builds the facade itself.** Rationale:

- The existing factory (`app/sources/factory.py:46-57`) ALREADY reads from credentials helpers without taking those as parameters; it's a "self-sufficient" factory. Pattern 2 matches.
- The pipeline today also calls `build_nvd_lookup_for_pipeline()` per analysis run, not at app startup. Building once per `build_source_adapters` call preserves that cadence.
- Avoids a Phase 4 change in `app/main.py`. Smaller blast radius.

### Type for `lookup_service`

Plain callable: `Callable[[str, "str | None", Any], list[dict[str, Any]]]` — matches the shape of `nvd_query_by_cpe(cpe, api_key, settings) -> list[dict]`. No new Protocol needed; `app/sources/base.py` is untouched.

### Concrete edit list

**1. [`app/sources/nvd.py`](../app/sources/nvd.py)** — constructor + query body:

```python
class NvdSource:
    name: str = "NVD"

    def __init__(
        self,
        api_key: str | None = None,
        *,
        lookup_service: Any = None,  # Callable[[str, str|None, Any], list[dict]]
    ) -> None:
        self.api_key = (api_key or "").strip() or None
        self._lookup_service = lookup_service

    async def query(self, components, settings) -> SourceResult:
        if not components:
            return empty_result()
        from app.analysis import nvd_query_by_components_async
        findings, errors, warnings = await nvd_query_by_components_async(
            components,
            settings,
            nvd_api_key=self.api_key,
            lookup_service=self._lookup_service,
        )
        return SourceResult(findings=findings, errors=errors, warnings=warnings)
```

**2. [`app/analysis.py:1243`](../app/analysis.py#L1243)** — `nvd_query_by_components_async`:

- Add kwarg `lookup_service: Any = None` to the signature.
- In the per-CPE loop at line 1342-1344, replace:

  ```python
  raw_list = await loop.run_in_executor(_executor, nvd_query_by_cpe, cpe, api_key, cfg)
  ```

  with:

  ```python
  query_callable = lookup_service if lookup_service is not None else nvd_query_by_cpe
  raw_list = await loop.run_in_executor(_executor, query_callable, cpe, api_key, cfg)
  ```

That's the only edit in `app/analysis.py`. The signature change is backward-compatible (default `None`). The conftest snapshot fakes that monkeypatch `nvd_query_by_components_async` already accept `**kwargs` patterns that won't break.

**3. [`app/sources/factory.py`](../app/sources/factory.py#L46)** — `build_source_adapters`:

```python
def build_source_adapters(sources: Iterable[str]) -> list[VulnSource]:
    from ..credentials import github_token_for_adapters, nvd_api_key_for_adapters, vulndb_api_key_for_adapters
    from ..nvd_mirror.application import build_nvd_lookup_for_pipeline

    # Build the mirror-aware NVD lookup once per factory call. The
    # facade short-circuits to live NVD when the mirror is disabled
    # (the default state), so wiring it unconditionally is safe.
    facade = build_nvd_lookup_for_pipeline()

    def _nvd_lookup(cpe: str, api_key: str | None, settings: Any) -> list[dict]:
        return facade.query_legacy(cpe, api_key=api_key, settings=settings)

    factories = {
        "NVD": lambda: NvdSource(api_key=nvd_api_key_for_adapters(), lookup_service=_nvd_lookup),
        "OSV": OsvSource,
        "GITHUB": lambda: GhsaSource(token=github_token_for_adapters()),
        "VULNDB": lambda: VulnDbSource(api_key=vulndb_api_key_for_adapters()),
    }
    return [factories[name]() for name in normalize_source_names(sources) if name in factories]
```

`_nvd_lookup` is a thin synchronous closure with the exact `(cpe, api_key, settings) -> list[dict]` signature of `nvd_query_by_cpe`, so it drops in cleanly inside the `loop.run_in_executor` call inside `nvd_query_by_components_async`.

**4. `app/main.py`** — **no change**. Lifespan is untouched.

### Mirror DB-table availability check

`build_nvd_lookup_for_pipeline()` is called eagerly at every `build_source_adapters(...)` call. It opens no SQL session itself — it just stashes `SessionLocal` and the secrets adapter. The first SQL call happens lazily inside `query_legacy`. By that time, lifespan startup has already run `Base.metadata.create_all()`, and `app/main.py:51` (`from .nvd_mirror.api import router`) chain-imports `app.nvd_mirror.adapters.settings_repository` → `app.nvd_mirror.db.models` at app-import time, registering the mirror tables on `Base.metadata` BEFORE `create_all` runs. So mirror tables always exist by the time the runner-side path queries them. ✓

### Test fakes already passing through

`tests/conftest.py:222-226` monkeypatches `nvd_query_by_components_async` with `_fake_nvd_query_by_components_async(components, settings, nvd_api_key=None)`. That fake signature accepts the existing kwargs; the new `lookup_service=None` kwarg just falls through to `**kwargs`-style ignore (technically Python will reject unrecognized kwargs). **Need to verify**: the call site in `NvdSource.query` will pass `lookup_service=self._lookup_service`. If the test fake doesn't accept that kwarg, it breaks.

Cleanest fix: add `lookup_service=None` to the test fake's signature in conftest. That's a one-line touch in `tests/conftest.py`. Alternatively — and preferably — pass `lookup_service` through `**kwargs` in `NvdSource.query` so it's forward-compatible. But the existing fake accepts `nvd_api_key=None` as a named kwarg, suggesting the project expects fakes to mirror the real signature explicitly. So adding `lookup_service=None` to the fake is in keeping with project convention. **Will be a 1-line edit in `tests/conftest.py` Phase C** — non-collateral, but tightly coupled to the signature change.

### New test ([`tests/test_nvd_source_uses_lookup_service.py`](../tests/test_nvd_source_uses_lookup_service.py)) — Phase C.6

Sketch (~35 lines):

```python
"""Contract test for R6: NvdSource consults its lookup_service before
the live NVD path. Independent of app.pipeline and tests.nvd_mirror."""
import asyncio
from app.sources.nvd import NvdSource


def test_nvd_source_routes_through_lookup_service_when_provided(monkeypatch):
    captured = []
    def fake_lookup(cpe, api_key, settings):
        captured.append((cpe, api_key))
        return [{
            "id": "CVE-LOOKUP-1",
            "descriptions": [{"lang": "en", "value": "from lookup"}],
            "metrics": {}, "weaknesses": [], "configurations": [],
            "references": [], "published": "2024-01-01T00:00:00.000",
            "lastModified": "2024-04-01T00:00:00.000", "vulnStatus": "Analyzed",
        }]

    import app.analysis as analysis_mod
    live_calls = []
    def fake_live(cpe, api_key, settings=None):
        live_calls.append(cpe)
        return [{"id": "CVE-LIVE-WAS-CALLED"}]
    monkeypatch.setattr(analysis_mod, "nvd_query_by_cpe", fake_live)

    cfg = analysis_mod.get_analysis_settings_multi()
    components = [{"name": "x", "version": "1.0",
                   "cpe": "cpe:2.3:a:x:x:1.0:*:*:*:*:*:*:*"}]

    src = NvdSource(api_key="fake", lookup_service=fake_lookup)
    result = asyncio.run(src.query(components, cfg))

    assert captured and captured[0][0] == components[0]["cpe"]
    assert live_calls == []
    assert any(f.get("vuln_id") == "CVE-LOOKUP-1" for f in result["findings"])
```

This locks the contract: `lookup_service` provided ⇒ live NVD is never called.

---

> "Phase A reconnaissance written to `audit/r6_orchestrator_recon.md`. Verified: 5 consumers of the pipeline orchestrator (3 tests + 2 dead exports + 1 never-enqueued Celery task), 0 production callers, mirror-lookup chain identified. Awaiting `approve r6 phase c` before modifying NvdSource and factory."
