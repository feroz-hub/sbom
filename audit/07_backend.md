# Phase 3 — Backend Deep-Pass Audit

> Findings beyond the principle audits, focused on FastAPI / SQLAlchemy / async / Pydantic / security / observability discipline.

---

## 1. FastAPI layering

### Finding BE-001: Routers do everything; service layer is partial

- **Severity:** High
- **Location:** Cross-listed with SOLID-DIP-001, SOLID-SRP-002.
- **Notes:** Six of ten routers query `models.*` directly. The service layer only owns dashboard / pdf / sbom helpers. There is no `analyze_pipeline_service` and no repositories in the call graph.

### Finding BE-002: Two routers register under `/api/sboms` (`sboms_crud.router` and `sbom.router`)

- **Severity:** Medium
- **Location:** [app/main.py:242-261](../app/main.py); [app/routers/sboms_crud.py:75](../app/routers/sboms_crud.py); [app/routers/sbom.py:17](../app/routers/sbom.py)
- **Evidence:**
  ```python
  # main.py:242
  app.include_router(sboms_crud.router, dependencies=_protected)        # prefix="/api"
  ...
  app.include_router(
      sbom_features_router.router,
      prefix="/api/sboms",
      tags=["sbom-features"],
      dependencies=_protected,
  )
  ```
  `sboms_crud.router` declares `prefix="/api"`; routes there start with `/sboms/...`. `sbom_features_router` declares no prefix in the file but is mounted with `/api/sboms`. End result: both feed the same path namespace, but split across two files for no obvious reason.
- **Why this matters:** A reader looking for "what does GET /api/sboms/{id} do" must search two files. `risk-summary` and `info` are inside `sbom.py`; `components`, `analyze`, `analyze/stream` are in `sboms_crud.py`. The split is by historical accident (B4/B8 in the inline comment).
- **Recommended fix:** Merge `sbom.py` into `sboms_crud.py` (or split `sboms_crud.py` further into thinner files, but only AFTER SOLID-SRP-002).
- **Effort:** S
- **Risk of fix:** Low.

### Finding BE-003: `Depends(require_auth)` applied at app-level for every router but it depends on `os.environ`

- **Severity:** Medium
- **Location:** [app/main.py:239-271](../app/main.py); see SOLID-DIP-004.

---

## 2. Dependency Injection

### Finding BE-004: Settings constructed lazily inside route handlers via `get_settings()`

- **Severity:** Low
- **Location:** [app/routers/health.py:27, 36](../app/routers/health.py); [app/routers/analyze_endpoints.py:48, 55, 365](../app/routers/analyze_endpoints.py).
- **Evidence:**
  ```python
  # routers/analyze_endpoints.py:55
  DEFAULT_RESULTS_PER_PAGE = get_settings().DEFAULT_RESULTS_PER_PAGE
  ```
  Module-level call to `get_settings()` at import time. Stale once env changes.
- **Recommended fix:** `Depends(get_settings)` in handler signatures. Eliminate import-time settings reads.
- **Effort:** S
- **Risk of fix:** Low.

### Finding BE-005: `get_db` yields a session but exception cleanup leaves transaction state ambiguous

- **Severity:** Low
- **Location:** [app/db.py:57-62](../app/db.py)
- **Evidence:**
  ```python
  def get_db():
      db = SessionLocal()
      try:
          yield db
      finally:
          db.close()
  ```
- **Why this matters:** No explicit `rollback()` on exception path. Routes do `db.rollback()` in their own `except` blocks, so practically OK, but a forgotten rollback inside a service raises `PendingRollbackError` on the next session use because the session is reused per request only.
  Actually here the session is per-request (closed in finally), so this is fine. Listed only because the comment-friendly pattern is `try ... except: rollback(); raise; finally: close()`. Defer.

---

## 3. SQLAlchemy hygiene

### Finding BE-006: N+1 query in `get_recent_sboms`

- **Severity:** Medium
- **Location:** [app/services/dashboard_service.py:70-110](../app/services/dashboard_service.py)
- **Evidence:**
  ```python
  sboms = db.execute(select(SBOMSource).order_by(...).limit(limit)).scalars().all()
  for sbom in sboms:
      comp_count = db.execute(select(func.count(SBOMComponent.id)).where(...)).scalar_one() or 0
      latest_run = db.execute(select(AnalysisRun).where(...)).scalars().first()
      project_name = sbom.project.project_name if sbom.project else None  # lazy load #3
  ```
  Three queries per SBOM × `limit` SBOMs.
- **Note:** This module is currently unwired (YAGNI-004), so the bug isn't live. But it's the pattern that survives if the wired-in `routers/dashboard_main.py:dashboard_recent_sboms` is later replaced.
- **Recommended fix:** Single SQL with `joinedload(SBOMSource.project)`, `joinedload(SBOMSource.analysis_runs)` (or a lateral join for "latest"), and a counted-component subquery.
- **Effort:** M
- **Risk of fix:** Low.

### Finding BE-007: `routers/runs.py` builds a manual `subquery() + outerjoin` to fetch `sbom_name`

- **Severity:** Low
- **Location:** [app/routers/runs.py:77-104](../app/routers/runs.py)
- **Evidence:** Reasonable choice — preserves orphan runs whose SBOM was deleted. But the result is then converted to dicts via `__dict__` filtering (SUP-TDA-002).
- **Recommended fix:** Use `Mapped`/`mapped_column` SQLA 2 idiom + `joinedload` against the relationship; project response via `AnalysisRunOut`.
- **Effort:** S
- **Risk of fix:** Low.

### Finding BE-008: `models.py` columns store JSON-as-string instead of native JSON

- **Severity:** Medium
- **Location:** [app/models.py:172, 175](../app/models.py)
- **Evidence:**
  ```python
  fixed_versions = Column(Text, nullable=True)  # JSON array stored as string
  aliases = Column(Text, nullable=True)         # JSON array as string
  ```
- **Why this matters:** Postgres has `JSONB` which supports indexing and structured filters. Storing JSON as Text means the API must `json.loads`/`json.dumps` on every read+write, the FE does the same, and queries like "findings with fixed_versions containing X" are not possible.
- **Impact:** Three layers (BE persist, BE rebuild, FE parse) all do JSON marshalling. `routers/sboms_crud.py:235-239, 245-271` is the persist code; `routers/pdf.py:73-78`, `services/pdf_service.py:153` is the read code; `frontend/src/components/analysis/FindingsTable.tsx:23-30` is the FE parse.
- **Recommended fix:** `Column(JSON, nullable=True)` (SQLAlchemy translates to JSONB in Postgres, JSON in SQLite). Migration + drop the json.dumps/loads at four sites.
- **Effort:** M
- **Risk of fix:** Medium — SQLite vs Postgres behaviours differ; needs a migration (Alembic 003).

### Finding BE-009: `RunCache.run_json` duplicates `AnalysisRun.raw_report`

- **Severity:** Medium
- **Location:** [app/models.py:186-200](../app/models.py); [app/services/analysis_service.py:151-169](../app/services/analysis_service.py)
- **Evidence:** `RunCache.run_json` is the JSON dump of an ad-hoc run. `AnalysisRun.raw_report = json.dumps(details)` is the same shape persisted in the same db. `services/pdf_service.py` falls back from cache to AnalysisRun via `_rebuild_run_from_db`. Two storage formats for the same data.
- **Why this matters:** Storage doubled; consistency model unclear. The router-side `persist_analysis_run` (in `sboms_crud.py:189`) does NOT write `raw_report` (see SOLID-SRP-003 + DRY-005). So depending on the path, the cache may be the only copy.
- **Recommended fix:** Pick one: keep `raw_report` (it's already inside `AnalysisRun`) and drop `RunCache`. Or drop `raw_report` and keep `RunCache`. After SOLID-SRP-003 is fixed, the cache becomes redundant.
- **Effort:** M
- **Risk of fix:** Medium.

### Finding BE-010: Missing index on `RunCache(sbom_id)`

- **Severity:** Low
- **Location:** [app/models.py:198](../app/models.py)
- **Evidence:** `sbom_id = Column(Integer, nullable=True)` — no `index=True` or composite index. The docstring says "for cache invalidation"; any cache invalidation by sbom_id will scan.
- **Recommended fix:** Add `index=True`. Or drop the column if BE-009 deletes the table.
- **Effort:** S
- **Risk of fix:** Low.

### Finding BE-011: Two query styles coexist (`db.query(...)` vs `db.execute(select(...))`)

- **Severity:** Low (style)
- **Location:** Both styles across routers, services, repositories.
- **Recommended fix:** Pick one (modern SA2 form is `db.execute(select(...))`). Convert `db.query(...).filter(...).first()` → `db.execute(select(...).where(...)).scalar_one_or_none()`. The repositories/* code is full of `db.query` and is dead anyway.

---

## 4. Async correctness

### Finding BE-012: Sync `requests.Session` calls inside async routes via `loop.run_in_executor`

- **Severity:** Low
- **Location:** [app/analysis.py:1338-1344](../app/analysis.py); [app/pipeline/multi_source.py:166-178](../app/pipeline/multi_source.py)
- **Evidence:** `nvd_query_by_cpe` uses `requests.Session`. Async paths wrap it in `loop.run_in_executor(_executor, nvd_query_by_cpe, …)`. This is the **right** pattern.
- **Note:** Listed for completeness — no violation. The thread pool is bounded (4 or `cpu_count()`).

### Finding BE-013: NVD fetch is sequential by design (rate-limit aware)

- **Severity:** none — verified design choice
- **Location:** [app/analysis.py:1243-1373](../app/analysis.py)
- **Note:** Sequential CPE fetch with documented justification (NVD's global token bucket). **Status:** No violation.

### Finding BE-014: `_async_get` / `_async_post` triple fallback is async-correct but over-engineered

- **Severity:** Medium
- **Location:** see KISS-001.

### Finding BE-015: SSE handler creates an `asyncio.Queue` and drives the runner in a sibling task — visible mutation across tasks

- **Severity:** Medium
- **Location:** see KISS-004.

### Finding BE-016: No async DB driver

- **Severity:** Low (operational)
- **Location:** [app/db.py:9-41](../app/db.py)
- **Evidence:** Sync SQLAlchemy with `psycopg`. Routes are `async def` but DB calls are sync. FastAPI runs sync deps in a threadpool, so it works — but a long DB query blocks one thread.
- **Recommended fix:** Defer. Async SA + asyncpg is a larger migration; today's load doesn't require it.

---

## 5. Pydantic discipline

### Finding BE-017: ORM models returned directly with `response_model=…` schema

- **Severity:** Low
- **Location:** [app/routers/sboms_crud.py:402-407, 615-679](../app/routers/sboms_crud.py); [app/routers/runs.py:137-142](../app/routers/runs.py).
- **Evidence:**
  ```python
  @router.get("/sboms/{sbom_id}", response_model=SBOMSourceOut)
  def get_sbom(sbom_id, db):
      sbom = db.get(SBOMSource, sbom_id)
      ...
      return sbom   # raw ORM
  ```
  FastAPI runs the schema validator on the ORM (`from_attributes=True`). This works but exposes ORM lifecycle to the response validator. If the session closes early, attribute access on lazy-loaded fields raises. Cross-listed with OOP-001.
- **Recommended fix:** `return SBOMSourceOut.model_validate(sbom)` explicitly.
- **Effort:** S
- **Risk of fix:** Low.

### Finding BE-018: `AnalysisRunOut` has 18 nullable fields including counts

- **Severity:** Low
- **Location:** [app/schemas.py:97-117](../app/schemas.py)
- **Evidence:** `total_components: int`, `critical_count: int`, etc. — these are `nullable=False, default=0` in the ORM but Pydantic sees them as `int`. Fine for the BE side; the FE TS type marks them `number | null` defensively.
- **Recommended fix:** Tighten the FE side (CC-001). BE side already correct.

### Finding BE-019: Pydantic `BaseModel.Config` style mixed with `model_config = ConfigDict`

- **Severity:** Low
- **Location:** [app/schemas.py:14-17](../app/schemas.py); [app/settings.py:114-125](../app/settings.py)
- **Evidence:** `ORMModel` uses inner `class Config:`; `Settings` uses `model_config = SettingsConfigDict(...)`.
- **Recommended fix:** Pick one form (the latter is the Pydantic v2 idiom). Cross-listed with KISS-002.

### Finding BE-020: `ConsolidatedAnalysisResult` doesn't exist on the BE; only on the FE

- **Severity:** Medium
- **Location:** [frontend/src/types/index.ts:216-231](../frontend/src/types/index.ts); [app/routers/analyze_endpoints.py:213-255](../app/routers/analyze_endpoints.py).
- **Evidence:** The BE returns a hand-built dict from `_run_legacy_analysis`. The FE has a TS interface for it. No Pydantic schema enforces the shape. The five `analyze-sbom-*` routes have no `response_model`.
- **Why this matters:** No server-side schema validation. Any field added to the dict is silently sent to the client; any drift between dict and TS interface is invisible until runtime.
- **Recommended fix:** Define `AdhocAnalysisRunOut` Pydantic schema, set `response_model` on all five routes. Generate TS via openapi-typescript or similar.
- **Effort:** S
- **Risk of fix:** Low.

---

## 6. Error handling

### Finding BE-021: Exceptions leak as 500 with raw `str(exc)`

- **Severity:** High (security-adjacent)
- **Location:** [app/routers/projects.py:80](../app/routers/projects.py); [app/routers/sboms_crud.py:611-612, 678-679](../app/routers/sboms_crud.py); [app/routers/pdf.py:151](../app/routers/pdf.py).
- **Evidence:**
  ```python
  raise HTTPException(status_code=500, detail=f"Something went wrong: {str(e)}")
  raise HTTPException(status_code=500, detail=f"Failed to update SBOM: {exc}") from exc
  raise HTTPException(status_code=500, detail=f"Failed to delete SBOM: {exc}") from exc
  raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {e}")
  ```
- **Why this matters:** Stack traces or low-level driver errors (`SQLAlchemyError`, `psycopg.Error` messages) leak to the API caller. PostgreSQL errors can include schema names, query fragments, or hostname. Information disclosure.
- **Recommended fix:** Generic detail message; full error logged server-side only. Pattern:
  ```python
  except SQLAlchemyError as exc:
      log.exception("update_sbom failed: sbom_id=%d", sbom_id)
      raise HTTPException(status_code=500, detail="Internal database error") from exc
  ```
- **Effort:** S
- **Risk of fix:** Low.

### Finding BE-022: Broad `except Exception` swallows errors silently

- **Severity:** Medium
- **Location:** see SUP-FF-001.

### Finding BE-023: Inconsistent error envelope

- **Severity:** Medium
- **Location:** [app/routers/sboms_crud.py:425-468](../app/routers/sboms_crud.py); compare with [app/routers/projects.py:65, 76](../app/routers/projects.py).
- **Evidence:** `sboms_crud.py` raises `HTTPException(409, detail={"code": "duplicate_name", "message": "..."})` — a structured `detail`. `projects.py` raises `HTTPException(400, detail="Project with this name already exists")` — a string. Frontend's `lib/api.ts:performRequest` handles both branches but the API contract is inconsistent.
- **Recommended fix:** Define a single error envelope (e.g. `{code: str, message: str}`) and use it everywhere. Add a global FastAPI exception handler that normalises `HTTPException` to that shape.
- **Effort:** M
- **Risk of fix:** Medium — the FE has defensive parsing that handles both already.

---

## 7. Configuration

### Finding BE-024: Two parallel env-loading systems (`Settings` + `_env_*`)

- **Severity:** Medium — see YAGNI-012.

### Finding BE-025: `Settings.X = …` post-class assignments aren't fields

- **Severity:** Medium — see OOP-003.

### Finding BE-026: Drift in OSV base URL between `Settings.OSV_API` and `_MultiSettings.osv_api_base_url`

- **Severity:** Medium — see SUP-SSOT-006.

---

## 8. Security smells

### Finding BE-027: CORS configured `allow_origins=settings.cors_origins_list` with default `"*"`

- **Severity:** Medium
- **Location:** [app/main.py:176-182](../app/main.py); [app/settings.py:51, 197-202](../app/settings.py)
- **Evidence:**
  ```python
  allow_origins=settings.cors_origins_list,   # default ["*"]
  allow_credentials=False,
  allow_methods=["*"],
  allow_headers=["*"],
  ```
- **Why this matters:** Default `*` is fine **only** when `allow_credentials=False` (which is set). But `allow_methods=["*"]` and `allow_headers=["*"]` mean every header (including `Authorization`) is reflected. When deployed with `API_AUTH_MODE=jwt`, browsers can post bearer tokens cross-origin from anywhere.
- **Recommended fix:** Validate `CORS_ORIGINS` is set to an explicit allowlist in production via `validate_auth_setup()` — fail-fast if `mode=jwt|bearer` AND `cors_origins=*`.
- **Effort:** S
- **Risk of fix:** Low.

### Finding BE-028: `Authentication required` 401 leaks no info — good

- **Severity:** none
- **Note:** Verified. `_token_in_allowlist` uses `hmac.compare_digest` (timing-safe). 

### Finding BE-029: `MAX_UPLOAD_BYTES = 20 * 1024 * 1024` is defined but never enforced

- **Severity:** High
- **Location:** [app/settings.py:225](../app/settings.py); verified by `grep -rn "MAX_UPLOAD_BYTES"` returns only the definition site.
- **Why this matters:** SBOM uploads come in via `POST /api/sboms` (`payload: SBOMSourceCreate` with `sbom_data: str | None`). FastAPI / starlette doesn't reject large JSON bodies by default; SBOM JSON can easily be 100 MB. No size guard ⇒ memory exhaustion DoS vector.
- **Recommended fix:** Either (a) reject large bodies with a request middleware that checks `Content-Length` against `Settings.MAX_UPLOAD_BYTES`, or (b) move SBOM uploads to multipart `UploadFile` with `file.size` check, or (c) wire `Settings.MAX_UPLOAD_BYTES` into the existing slowapi/middleware stack. Whichever — the constant must actually do something.
- **Effort:** S
- **Risk of fix:** Low.

### Finding BE-030: `_ensure_text_column` builds SQL via `f"…{table_name}…"` interpolation

- **Severity:** Low (input is constant strings, not user-controlled — but pattern is dangerous)
- **Location:** [app/main.py:75-78](../app/main.py)
- **Evidence:**
  ```python
  conn.execute(text(f"PRAGMA table_info({table_name})"))
  conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} TEXT"))
  ```
- **Why this matters:** Even though inputs are hard-coded, the f-string SQL pattern propagates. SQLAlchemy's `text()` doesn't auto-quote identifiers.
- **Recommended fix:** Move to Alembic (YAGNI-009). Then this code dies.
- **Effort:** S
- **Risk of fix:** Low.

### Finding BE-031: NVD admin router mutates settings without an admin guard

- **Severity:** Medium — see YAGNI-015.

### Finding BE-032: Bearer token allowlist held in `os.environ` plain text

- **Severity:** Low
- **Location:** [app/auth.py:29-31](../app/auth.py).
- **Note:** Standard practice for env-driven auth. Listed only because rotation requires a process restart. Defer.

### Finding BE-033: JWT validation reads `JWT_AUDIENCE`/`JWT_ISSUER` only if non-empty — no startup check

- **Severity:** Low
- **Location:** [app/auth.py:39-46](../app/auth.py)
- **Evidence:** Empty audience/issuer means the corresponding claim isn't checked. Fine if the token issuer doesn't include them, but easy to forget configuring.
- **Recommended fix:** Document or `validate_auth_setup` warns when `mode=jwt` and both are empty.
- **Effort:** S
- **Risk of fix:** Low.

---

## 9. Background jobs

### Finding BE-034: Celery broker/backend pinned to `redis_url` with no separation

- **Severity:** Low
- **Location:** [app/workers/celery_app.py:17-31](../app/workers/celery_app.py)
- **Note:** Acceptable for small deployments; no result expiry configured. **`[REQUIRES VERIFICATION]`** of `result_backend` retention defaults.

### Finding BE-035: Celery `task_acks_late` / `worker_prefetch_multiplier` not set

- **Severity:** Low
- **Location:** [app/workers/celery_app.py:33-40](../app/workers/celery_app.py)
- **Note:** Defaults mean a crashed worker loses tasks. Since the only used task is `mirror_nvd` (idempotent + scheduled), losing one is OK. Listed for completeness.

### Finding BE-036: `mirror_nvd` failure mode unclear from current files

- **Severity:** [REQUIRES VERIFICATION]
- **Location:** [app/nvd_mirror/tasks.py](../app/nvd_mirror/tasks.py) (291 lines, not read in detail in this audit)
- **Note:** Read this file end-to-end before declaring "production ready". The audit didn't open it.

---

## 10. Logging & observability

### Finding BE-037: `setup_logging()` called twice — at module load and inside lifespan

- **Severity:** Low
- **Location:** [app/main.py:39, 158](../app/main.py)
- **Note:** Documented; `uvicorn` rewrites the root logger at startup, so the lifespan re-application is needed. Listed for completeness, no fix.

### Finding BE-038: Access log middleware is custom; no correlation ID

- **Severity:** Low
- **Location:** [app/main.py:186-224](../app/main.py)
- **Evidence:** Logs `→ METHOD path client=ip` and `← METHOD path status=N Nms`. No request ID ⇒ hard to correlate logs across the request → service → external API → DB chain.
- **Recommended fix:** Generate a UUID per request, propagate via `Request.state.request_id`, include in every log via `logging` extra. Optional — `asgi-correlation-id` package handles this.
- **Effort:** S
- **Risk of fix:** Low.

### Finding BE-039: Mirror counters in-memory only

- **Severity:** Low
- **Location:** [app/nvd_mirror/observability.py](../app/nvd_mirror/observability.py)
- **Note:** Counters reset on process restart; not exported to Prometheus or otherwise. Sufficient for dev; production should integrate with the host platform.

### Finding BE-040: PDF generation logs at INFO level for every PDF

- **Severity:** Low
- **Location:** [app/services/pdf_service.py:233](../app/services/pdf_service.py); [app/routers/pdf.py:148](../app/routers/pdf.py)
- **Note:** Fine. Mentioned only because byte size is logged — could be DEBUG.

---

## Summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 3 |
| Medium | 13 |
| Low | 18 |
| **Total** | **34** (some cross-listed) |

**Highest-leverage backend fixes:**
1. **BE-029** — Wire `MAX_UPLOAD_BYTES` into the request pipeline. The constant is defined and unenforced; this is a real DoS vector.
2. **BE-021** — Stop leaking exception text in 500 responses. Low effort, immediate security win.
3. **BE-008 / BE-009** — Move JSON-as-string columns to native JSON types AND collapse `RunCache` ↔ `AnalysisRun.raw_report` redundancy.
4. **BE-027 + YAGNI-015** — CORS hardening + admin role split for `/admin/nvd-mirror/*`. Two related production-readiness gaps.
