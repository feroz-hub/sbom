# Phase 2.4 — KISS Audit

> Where the code is more clever / abstracted / async than it needs to be.

---

### Finding KISS-001: `_async_get` / `_async_post` carry three runtime-branch fallbacks

- **Principle violated:** KISS
- **Severity:** Medium
- **Location:** [app/analysis.py:753-805](../app/analysis.py)
- **Evidence:**
  ```python
  async def _async_get(url, headers=None, params=None, timeout=60):
      if httpx is not None:
          try:
              from .http_client import get_async_http_client
              client = get_async_http_client()
          except RuntimeError:
              async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
                  r = await client.get(url, params=params, headers=headers)
                  ...
          else:
              r = await client.get(url, params=params, headers=headers, timeout=timeout)
              ...
      loop = asyncio.get_running_loop()
      return await loop.run_in_executor(_executor, lambda: requests.get(url, headers=headers, params=params, timeout=timeout).json())
  ```
- **Why this violates the principle:** Three execution paths: (1) shared async client, (2) ephemeral `httpx.AsyncClient`, (3) `requests` in a thread pool. The third path exists "in case `httpx` is missing" — but `httpx` is in `requirements.txt` (verify by reading [requirements.txt](../requirements.txt)). The second path exists for tests that don't run lifespan. The fallback chain is hard to reason about.
- **Impact:** A bug in the `requests` path won't surface in normal runs, but will be invoked by some test paths. Three sets of timeouts/headers/error semantics.
- **Recommended fix:**
  1. Treat `httpx` as a hard dependency (it already is — it's used in `vulndb.py`).
  2. Use a single `async_client_or_local()` context manager (see DRY-011).
  3. Delete the `requests`-via-executor branch.
- **Effort:** S
- **Risk of fix:** Low.

### Finding KISS-002: `analysis.py` Settings has both `Settings` and `Settings.X = …` constants AND a try/except import dance

- **Principle violated:** KISS
- **Severity:** Medium
- **Location:** [app/settings.py:14-29, 209-231](../app/settings.py)
- **Evidence:**
  ```python
  try:
      from pydantic_settings import BaseSettings, SettingsConfigDict
      HAS_SETTINGS_CONFIG_DICT = True
  except ImportError:
      try:
          from pydantic.settings import BaseSettings, SettingsConfigDict
          HAS_SETTINGS_CONFIG_DICT = True
      except ImportError:
          BaseSettings = BaseModel
          SettingsConfigDict = None
          HAS_SETTINGS_CONFIG_DICT = False
  ```
  Then later: `if HAS_SETTINGS_CONFIG_DICT: model_config = …` else nested `class Config`.
- **Why this violates the principle:** Three import paths supporting Pydantic v1 (`pydantic.settings`), Pydantic v2 with `pydantic-settings`, and "no BaseSettings". `requirements.txt` should pin one. The Pydantic v1 path is dead — the project already uses `field_validator` (Pydantic v2 idiom) elsewhere.
- **Impact:** Reader confusion; tests cannot distinguish which branch is live.
- **Recommended fix:** Pin `pydantic-settings>=2.0` and `pydantic>=2`. Delete both fallback branches. `model_config = SettingsConfigDict(env_file=".env", ...)` is the only form.
- **Effort:** S
- **Risk of fix:** Low.

### Finding KISS-003: `extract_components` retries JSON parsing twice with different invariants

- **Principle violated:** KISS
- **Severity:** Low
- **Location:** [app/parsing/extract.py:24-57](../app/parsing/extract.py)
- **Evidence:**
  ```python
  text = sbom_json.strip().lstrip(_INVISIBLE).strip() if isinstance(sbom_json, str) else ""
  if text.startswith("{") or text.startswith("["):
      try:
          doc = json.loads(text)
          ...
      except json.JSONDecodeError:
          pass
  if text.startswith("<"):
      ...
  doc = json.loads(text)   # last-resort retry
  ```
- **Why this violates the principle:** Three branches with overlapping logic (the dict-format detection in branches 1 and 3 is identical). A `JSONDecodeError` in branch 1 is silently swallowed and then raised in the last-resort branch.
- **Recommended fix:** Detect format once (`detect_sbom_format(doc)` if dict, sniff first non-whitespace char if string) → dispatch to one parser.
- **Effort:** S
- **Risk of fix:** Low.

### Finding KISS-004: SSE event handling fans into 5 nested closures with shared mutable state

- **Principle violated:** KISS
- **Severity:** Medium
- **Location:** [app/routers/sboms_crud.py:735-940](../app/routers/sboms_crud.py)
- **Evidence:** `analyze_sbom_stream` defines `_stream_not_found`, `_replay_cached`, `event_stream`, and inside it `elapsed`, `_drive_runner`. `_drive_runner` mutates `all_findings`/`all_errors` from the outer scope while the consumer loop reads `event_queue`. Final aggregates are pulled out by **scoping** rather than by return value.
- **Why this violates the principle:** Coordinating two concurrent tasks via shared lists + `event_queue` + `orchestrator.done()` is fragile. The comment at line 875 explicitly worries about this: `# Make sure the orchestrator task finished cleanly so its all_findings/all_errors mutations are visible.`
- **Impact:** Easy to introduce ordering bugs; cancel paths must dance around the queue.
- **Recommended fix:**
  ```python
  async def event_stream():
      stream = SourceStreamer(adapters, components, cfg)
      async for event in stream:
          yield _sse_event(event.type, event.payload)
      # final = stream.result()  ← single-place aggregate
      yield _sse_event("complete", _build_complete_payload(...))
  ```
  Encapsulate runner+queue inside one async iterator.
- **Effort:** M
- **Risk of fix:** Medium — covered by `tests/test_sboms_analyze_stream.py`.

### Finding KISS-005: `nvd_query_by_components_async` builds CPE inventory with three concurrent dict structures

- **Principle violated:** KISS
- **Severity:** Low
- **Location:** [app/analysis.py:1278-1303](../app/analysis.py)
- **Evidence:**
  ```python
  cpe_order: list[str] = []
  seen: set[str] = set()
  name_by_cpe: dict[str, tuple[str, str | None]] = {}
  queried = 0
  skipped = 0
  for comp in normalized_components:
      cpe = comp.get("cpe")
      if cpe:
          queried += 1
          if cpe not in seen:
              seen.add(cpe)
              cpe_order.append(cpe)
              name_by_cpe[cpe] = (comp.get("name") or "", comp.get("version"))
      else:
          skipped += 1
  ```
- **Why this violates the principle:** `cpe_order` + `seen` is `dict.fromkeys(...)` reinvented; counting `queried`/`skipped` is `len([c for c if c.cpe])`/`len([c for c if not c.cpe])`. Comprehensions would express intent in 4 lines instead of 12.
- **Recommended fix:**
  ```python
  with_cpe = [(c["cpe"], c.get("name") or "", c.get("version")) for c in normalized_components if c.get("cpe")]
  name_by_cpe = {cpe: (n, v) for cpe, n, v in with_cpe}
  cpe_order = list(name_by_cpe)
  queried, skipped = len(with_cpe), len(normalized_components) - len(with_cpe)
  ```
- **Effort:** S
- **Risk of fix:** Low — covered by snapshot tests.

### Finding KISS-006: `idempotency.run_idempotent` JSON-roundtrips the body to "deep copy"

- **Principle violated:** KISS, performance
- **Severity:** Low
- **Location:** [app/idempotency.py:61-93](../app/idempotency.py)
- **Evidence:**
  ```python
  def _body_copy(body: dict) -> dict:
      return json.loads(json.dumps(body))
  ```
- **Why this violates the principle:** `copy.deepcopy(body)` is purpose-built. `json.loads(json.dumps(...))` allocates a string, parses it, raises `TypeError` on non-JSON-serializable values (e.g. a `datetime`). Performance: a 1k-finding response gets serialized twice on every duplicate request.
- **Recommended fix:** `from copy import deepcopy; return deepcopy(body)`. Or better: store the immutable value (`MappingProxyType`) and skip copying on read.
- **Effort:** S
- **Risk of fix:** Low.

### Finding KISS-007: `_validate_user_id` raises 422 with a regex hint via two HTTPException paths

- **Principle violated:** KISS
- **Severity:** Low
- **Location:** [app/routers/sboms_crud.py:374-388](../app/routers/sboms_crud.py)
- **Evidence:** Two separate `raise HTTPException(...)` inside one function for "empty after strip" and "regex mismatch". Pydantic `Field(pattern=…, min_length=1, max_length=64)` could express the same in one line on the request schema.
- **Recommended fix:** Use `Annotated[str, StringConstraints(pattern=…, min_length=1, max_length=64)]` on the query parameter declaration. FastAPI returns 422 automatically.
- **Effort:** S
- **Risk of fix:** Low.

### Finding KISS-008: Two `lru_cache(maxsize=1)`-wrapped settings factories cache mutable env state

- **Principle violated:** KISS, Fail-Fast
- **Severity:** Medium
- **Location:** [app/analysis.py:299-324, 721-743](../app/analysis.py)
- **Evidence:**
  ```python
  @lru_cache(maxsize=1)
  def get_analysis_settings() -> AnalysisSettings: ...
  @lru_cache(maxsize=1)
  def get_analysis_settings_multi() -> _MultiSettings: ...
  ```
- **Why this violates the principle:** Pydantic-settings already gives one source of truth; this adds a second cache layer. Tests must `cache_clear()` to refresh; missing the call leaves stale settings hanging around.
- **Recommended fix:** Read from `app.settings.get_settings()` (already cached). Drop the `lru_cache`.
- **Effort:** S
- **Risk of fix:** Low (verify no test relies on `cache_clear()` behaviour).

### Finding KISS-009: `useToast.tsx` toast state machine has 186 lines for a notification primitive

- **Principle violated:** KISS
- **Severity:** Low
- **Location:** [frontend/src/hooks/useToast.tsx](../frontend/src/hooks/useToast.tsx)
- **Evidence:** Custom Provider + reducer-style state + action button + stable IDs + manual dismiss. Nothing structurally wrong, but **`sonner`** (or any other toast library) is ~5 lines of integration.
- **Recommended fix:** Defer unless the team actively wants to maintain a custom toast — but flag for the refactor plan as a candidate for replacement.
- **Effort:** S (replace) / 0 (defer)
- **Risk of fix:** Low.

### Finding KISS-010: `useAnalysisStream` hand-rolls an SSE parser with a 25-line `parseEvents`

- **Principle violated:** KISS
- **Severity:** Low
- **Location:** [frontend/src/hooks/useAnalysisStream.ts:165-189](../frontend/src/hooks/useAnalysisStream.ts)
- **Evidence:** The browser's `EventSource` API parses SSE natively. The hand-rolled parser was needed because `EventSource` only supports `GET`. The endpoint is `POST` — fair reason. But the loop builds, splits, and trims per event in 25 lines; the production-grade `eventsource-parser` package does this cleanly in 3.
- **Recommended fix:** `npm i eventsource-parser` (~1 KB, no deps). Replace `parseEvents` with `createParser(onEvent)`.
- **Effort:** S
- **Risk of fix:** Low.

### Finding KISS-011: `useBackgroundAnalysis` has a triple-nested optional access for `summary.findings.total`

- **Principle violated:** KISS
- **Severity:** Medium
- **Location:** [frontend/src/hooks/useBackgroundAnalysis.ts:65-71](../frontend/src/hooks/useBackgroundAnalysis.ts)
- **Evidence:**
  ```ts
  const raw = result as Record<string, unknown>;
  const total: number =
    (raw.summary as Record<string, unknown> | undefined)?.findings != null
      ? ((raw.summary as Record<string, Record<string, unknown>>).findings.total as number) ?? 0
      : (result.total_findings ?? 0);
  ```
- **Why this violates the principle:** Triple cast through `unknown` to read a numeric field. Symptom of a sloppy backend response: `_run_legacy_analysis` returns BOTH `total_findings` (flat) AND `summary.findings.total` (legacy). The frontend defensively reads both.
- **Impact:** This is the only `as Record<string, unknown>` cast in the frontend (verified by grep). It is here because the backend contract is intentionally dual-shape. Listed in `09_cross_cutting.md` as a contract drift.
- **Recommended fix:** Drop the `summary` block from `_run_legacy_analysis` once the consumer is updated. Read only `total_findings`. Cast disappears.
- **Effort:** S (frontend) + S (backend) — must coordinate.
- **Risk of fix:** Low.

### Finding KISS-012: `etag.maybe_not_modified` mixes "compute hash, set headers, return 304 or None"

- **Principle violated:** KISS
- **Severity:** Low
- **Location:** [app/etag.py:12-26](../app/etag.py)
- **Evidence:** Single helper does three things. Returns `None` to mean "continue normally" — caller checks `if nm is not None: return nm`. Used in three dashboard routes, each with the same boilerplate.
- **Recommended fix:** Acceptable. The alternative (a decorator) would obscure too much. Listed for completeness.

### Finding KISS-013: `app.workers.tasks.run_sbom_analysis` uses `asyncio.run` inside a Celery task

- **Principle violated:** KISS (cross-listed with YAGNI)
- **Severity:** Low
- **Location:** [app/workers/tasks.py:25-28](../app/workers/tasks.py)
- **Evidence:** `asyncio.run(run_multi_source_analysis_async(...))` per task call. Celery + asyncio is doable but invites event-loop edge-cases (each task spins up and tears down a loop). Since the task is never enqueued (YAGNI-002), this is moot.
- **Recommended fix:** Delete (YAGNI route) or use `gevent` worker / `celery[asyncio]` if revived.
- **Effort:** S (delete)
- **Risk of fix:** Low.

### Finding KISS-014: NVD pagination has overlap with the safety caps

- **Principle violated:** KISS
- **Severity:** Low
- **Location:** [app/analysis.py:411-502](../app/analysis.py)
- **Evidence:** Inside the loop:
  ```python
  if size <= 0 or start + size >= total: break
  if pages_fetched >= cfg.nvd_max_pages_per_query: ... break
  if total > cfg.nvd_max_total_results_per_query: ... break
  ```
  Three break conditions, each logged differently.
- **Recommended fix:** Acceptable — each cap has a distinct operational meaning. Don't unify.

### Finding KISS-015: `health._nvd_mirror_health` rebuilds adapters per request

- **Principle violated:** KISS
- **Severity:** Low
- **Location:** [app/routers/health.py:92-145](../app/routers/health.py)
- **Evidence:** Every `/health` call constructs a `FernetSecretsAdapter` (or `_StubSecrets`), a `SqlAlchemySettingsRepository`, calls `repo.load()`, then computes freshness. For a cheap liveness probe this is a lot.
- **Recommended fix:** Cache the adapters + snapshot for ~5s. Or split into `/health` (cheap, no DB) and `/ready` (DB-touching). Liveness probes should never hit the DB.
- **Effort:** S
- **Risk of fix:** Low.

---

## Summary

| Severity | Count |
|---|---|
| High | 0 |
| Medium | 5 |
| Low | 10 |
| **Total** | **15** |

**Highest-leverage simplifications:**
1. **KISS-002** — Pin Pydantic v2 / pydantic-settings as hard deps. Delete the three-branch import dance and the dual `model_config` / `class Config` form.
2. **KISS-008** — Drop the `lru_cache` settings factories. Use `app.settings.get_settings()` consistently.
3. **KISS-001 + DRY-011** — Single async HTTP context manager, kill the `requests`-via-executor fallback. The `requests`-only `_nvd_session` for sync NVD calls can stay.
