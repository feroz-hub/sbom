# Phase 2.6 — Supporting Principles Audit

> Separation of Concerns · Law of Demeter · Composition over Inheritance · Tell-Don't-Ask · Command-Query Separation · Fail-Fast · Single Source of Truth · Principle of Least Astonishment · High Cohesion / Low Coupling.

---

## Separation of Concerns

### Finding SUP-SOC-001: Routers own persistence + orchestration + presentation

- **Principle violated:** Separation of Concerns
- **Severity:** High
- **Location:** see SOLID-SRP-002 ([app/routers/sboms_crud.py:101-940](../app/routers/sboms_crud.py)), SOLID-SRP-005 ([app/routers/analyze_endpoints.py:99-256](../app/routers/analyze_endpoints.py)).
- **Evidence:** Cross-listed.
- **Why this violates the principle:** Same file maps HTTP to functions, performs SQLAlchemy writes, runs business logic, and shapes the JSON response.
- **Impact:** Already covered.
- **Recommended fix:** see SOLID-SRP-002.
- **Effort:** L
- **Risk of fix:** Medium.

### Finding SUP-SOC-002: `routers/health.py` mixes liveness probe + admin config + DB read

- **Principle violated:** Separation of Concerns
- **Severity:** Medium
- **Location:** [app/routers/health.py:73-145](../app/routers/health.py)
- **Evidence:** `GET /health` calls `_nvd_mirror_health(db)` which constructs Fernet adapter, settings repo, and runs a freshness query. Liveness probes hit the database **and** the Fernet key code path on every call.
- **Why this violates the principle:** Liveness should be a 200 from a static handler. Readiness can do DB checks. Mixing them means a temporarily slow DB rolls a deploy back unnecessarily.
- **Recommended fix:** Split: `GET /health` (no deps), `GET /ready` (DB ping + mirror snapshot). Update Kubernetes / Railway probe config in `railway.toml` accordingly.
- **Effort:** S
- **Risk of fix:** Low.

### Finding SUP-SOC-003: Pydantic schemas mix request, response, and "create payload" concerns

- **Principle violated:** Separation of Concerns
- **Severity:** Low
- **Location:** [app/schemas.py:14-204](../app/schemas.py)
- **Evidence:** Schemas live in one flat namespace mixing input (`*Create`, `*Update`) and output (`*Out`, `*Summary`) shapes. Acceptable for a small app, but the boundary is implicit only via naming.
- **Recommended fix:** Either split into `app/schemas/{request,response,internal}.py` or annotate explicitly. Defer.

---

## Law of Demeter

### Finding SUP-LOD-001: Service layer reaches through ORM relationships into nested objects

- **Principle violated:** Law of Demeter
- **Severity:** Low
- **Location:** [app/services/dashboard_service.py:91-93](../app/services/dashboard_service.py)
- **Evidence:**
  ```python
  if sbom.project:
      project_name = sbom.project.project_name
  ```
- **Why this violates the principle:** Reaches through `sbom → project → project_name`. Each access triggers a lazy load (the `relationship` is configured without explicit eager loading). Better: a single SQL with `joinedload(SBOMSource.project)` and a DTO returning `(sbom, project_name_or_none)`.
- **Impact:** N+1 query when `get_recent_sboms(limit=N)` is called.
- **Recommended fix:** see BE-006 in `07_backend.md`.

### Finding SUP-LOD-002: Frontend hook reaches through `summary.findings.total`

- **Principle violated:** Law of Demeter (cross-listed with KISS-011)
- **Severity:** Medium
- **Location:** [frontend/src/hooks/useBackgroundAnalysis.ts:65-71](../frontend/src/hooks/useBackgroundAnalysis.ts)
- **Evidence:** see KISS-011.
- **Recommended fix:** see KISS-011.

### Finding SUP-LOD-003: `pdf_report.py` and `pdf_service.py` reach into raw response dicts via deep gets

- **Principle violated:** LOD
- **Severity:** Low
- **Location:** [app/services/pdf_service.py:121-185](../app/services/pdf_service.py); [app/pdf_report.py:74-82](../app/pdf_report.py)
- **Evidence:** Code does `f.aliases`, then `json.loads(f.aliases)` if non-null, then iterates the parsed list. The PDF generator works on dicts that have `combined → [{"id": ..., "severity": ..., "fixed_versions": json.loads(...)}, ...]`.
- **Recommended fix:** A `RunForReport` DTO that the service produces (already deserialized) and the PDF generator consumes.

---

## Composition over Inheritance

### Finding SUP-COI-001: `_MultiSettings` extends `AnalysisSettings` purely to share fields

- **Principle violated:** Composition over Inheritance
- **Severity:** Medium
- **Location:** see OOP-009.

### Finding SUP-COI-002: `ORMModel(BaseModel)` is mini-inheritance instead of composition / mixin

- **Severity:** Low
- **Location:** see OOP-010.

---

## Tell-Don't-Ask

### Finding SUP-TDA-001: Routers manually compute severity buckets from finding lists

- **Principle violated:** Tell-Don't-Ask
- **Severity:** Low
- **Location:** see DRY-008. Each router pulls `f.severity`, normalises it, increments a counter.
- **Recommended fix:** A `Findings` value object with `.severity_counts() → dict[str,int]` would let the caller `tell` the collection what to do. Currently every caller `asks` each finding for its severity.
- **Effort:** S
- **Risk of fix:** Low.

### Finding SUP-TDA-002: Router pulls ORM `__dict__` to build response dict

- **Principle violated:** Tell-Don't-Ask
- **Severity:** Medium
- **Location:** [app/routers/runs.py:120-123](../app/routers/runs.py); cross-listed with OOP-001.
- **Evidence:**
  ```python
  for run, sbom_name in rows:
      run_dict = {k: v for k, v in run.__dict__.items() if not k.startswith("_")}
      run_dict["sbom_name"] = sbom_name or run_dict.get("sbom_name")
      items.append(run_dict)
  ```
- **Why this violates the principle:** The router *asks* the ORM for its internal `__dict__` and rebuilds a response shape itself. A schema (`AnalysisRunOut`) already exists that knows how to serialise.
- **Recommended fix:**
  ```python
  items = [
      AnalysisRunOut.model_validate(run).model_copy(update={"sbom_name": sn or run.sbom_name})
      for run, sn in rows
  ]
  ```
- **Effort:** S
- **Risk of fix:** Low.

---

## Command-Query Separation (CQS)

### Finding SUP-CQS-001: `_run_legacy_analysis` is a query that mutates

- **Principle violated:** CQS
- **Severity:** Medium
- **Location:** [app/routers/analyze_endpoints.py:99-256](../app/routers/analyze_endpoints.py)
- **Evidence:** Function returns a dict (looks like a query) but persists `AnalysisRun` and `AnalysisFinding` rows + commits. The five `POST /analyze-sbom-…` endpoints all perform writes despite the result-shape contract.
- **Why this violates the principle:** Caller cannot tell from the signature that a side effect happens. Idempotency-Key plumbing (`run_idempotent`) is the only thing that prevents double-write — but if the caller forgets to send a key, every retry creates a new `AnalysisRun`.
- **Recommended fix:** Two-step: `analyze_now(...)` returns `AdhocRunResult` without persisting; `persist(result, sbom)` writes; the route handler orchestrates both. Cleaner CQS, easier to test.
- **Effort:** M
- **Risk of fix:** Low (snapshot tests cover output shape; persistence is observable via the AnalysisRun row count).

### Finding SUP-CQS-002: `repo.load()` may write a seed row but is named `load`

- **Principle violated:** CQS / POLA
- **Severity:** Medium
- **Location:** [app/nvd_mirror/api.py:90-97](../app/nvd_mirror/api.py); [app/routers/health.py:122-125](../app/routers/health.py)
- **Evidence:**
  ```python
  # api.py:91-97
  def get_settings(repo, db):
      snap = repo.load()
      db.commit()  # commit if load() seeded the singleton row
      return NvdSettingsResponse.from_snapshot(snap)
  ```
  ```python
  # health.py:122-127
  repo = SqlAlchemySettingsRepository(db, secrets, env_defaults=env_defaults)
  snap = repo.load()
  # Don't commit a seed write inside /health — let the next admin call do it.
  ```
- **Why this violates the principle:** `load` sounds like a query but performs a flush of a seed insert. The two callers handle the surprise differently — `api.py` commits, `health.py` rolls back implicitly when the session closes.
- **Recommended fix:** Either `load` is read-only (move the seed to a separate `ensure_seeded()` operation) OR rename to `load_or_seed()` so callers know.
- **Effort:** S
- **Risk of fix:** Low.

### Finding SUP-CQS-003: `_ensure_seed_data` does seed + migrate + backfill at every startup

- **Principle violated:** CQS / SRP overlap
- **Severity:** Medium
- **Location:** [app/main.py:82-131](../app/main.py); see SOLID-SRP-004.

---

## Fail-Fast

### Finding SUP-FF-001: Broad `except Exception` blocks swallow errors silently

- **Principle violated:** Fail-Fast
- **Severity:** High
- **Location:** Multiple sites, sample:
  * [app/routers/projects.py:74-80](../app/routers/projects.py) — `except Exception as e: ... raise HTTPException(status_code=500, detail=f"Something went wrong: {str(e)}")` (leaks exception text in detail).
  * [app/routers/sboms_crud.py:478-482](../app/routers/sboms_crud.py) — bare `except Exception:` after specific errors.
  * [app/routers/sboms_crud.py:295-300](../app/routers/sboms_crud.py) — `except Exception as exc: log.warning(... %s, exc); return None` swallows arbitrary errors during component extraction.
  * [app/routers/sbom.py:130-131](../app/routers/sbom.py) — `except Exception: components = []`.
  * [app/services/pdf_service.py:38-42](../app/services/pdf_service.py) — `except (json.JSONDecodeError, TypeError): log.warning(...) return None`.
  * [app/sources/vulndb.py:233-242](../app/sources/vulndb.py) — `except Exception as exc: errors.append(...); continue` per target.
- **Why this violates the principle:** A bare `except Exception` swallows `KeyboardInterrupt` (no — those are `BaseException`), but more importantly hides programming bugs (`AttributeError`, `TypeError`) behind warnings. The `analysis.py:631` `try/except Exception` in `_finding_from_raw` is documented in OOP-012.
- **Impact:** Silent failures in component extraction → empty SBOM info; silent failures in CWE parsing → missing CWE in report.
- **Recommended fix:** Catch specific exceptions: `JSONDecodeError`, `KeyError`, `httpx.HTTPError`, etc. For "unknown error in 3rd-party data", catch a known set; let unknown exceptions propagate.
- **Effort:** M
- **Risk of fix:** Medium — risk of new 500s where there used to be silent fallbacks. Add tests as you go.

### Finding SUP-FF-002: `_finding_from_raw` swallows everything to retry the same path

- **Principle violated:** Fail-Fast (cross-listed with OOP-012)
- **Severity:** Medium
- **Location:** [app/analysis.py:613-666](../app/analysis.py).

### Finding SUP-FF-003: `validate_auth_setup` warns instead of failing on `API_AUTH_MODE=none`

- **Principle violated:** Fail-Fast (debatable)
- **Severity:** Low
- **Location:** [app/auth.py:49-54](../app/auth.py)
- **Evidence:**
  ```python
  if mode == "none":
      log.warning("API_AUTH_MODE=none — protected routes are open. ...")
      return
  ```
- **Why this violates the principle:** The default mode is `"none"`. Production deploys depending on operator-set env vars without a startup check might silently expose endpoints. A warning log is easy to miss.
- **Recommended fix:** Add an env-driven `REQUIRE_AUTH=true` (or default-on in non-dev `ENVIRONMENT=production`) that raises `AuthConfigError` if `API_AUTH_MODE` is `none`.
- **Effort:** S
- **Risk of fix:** Low.

---

## Single Source of Truth

### Finding SUP-SSOT-001: Two enum lists for analysis sources

- **Principle violated:** SSOT
- **Severity:** Medium
- **Location:** [app/analysis.py:1236-1240](../app/analysis.py); [app/sources/factory.py:13-14](../app/sources/factory.py)
- **Evidence:** `class AnalysisSource(str, Enum): NVD = "NVD"; OSV = "OSV"; GITHUB = "GITHUB"; VULNDB = "VULNDB"` AND `SUPPORTED_ANALYSIS_SOURCES = ["NVD", "OSV", "GITHUB", "VULNDB"]`.
- **Recommended fix:** Delete the `Enum` (after YAGNI-003).

### Finding SUP-SSOT-002: Severity thresholds hard-coded inside `vulndb._severity_from_risk`

- **Principle violated:** SSOT (cross-listed with SOLID-OCP-005).

### Finding SUP-SSOT-003: NVD pagination cap defined twice — `nvd_max_total_results_per_query` setting + inline 5000

- **Principle violated:** SSOT
- **Severity:** Low
- **Location:** [app/analysis.py:256](../app/analysis.py); also `analysis_max_findings_per_cpe`.
- **Evidence:** `analysis_max_findings_per_cpe = 5000` and `analysis_max_findings_total = 50000` are settings — but `nvd_max_total_results_per_query = 500` is a separate concept. Three thresholds, one job.
- **Recommended fix:** Document each threshold's intent in the dataclass docstring; consolidate where overlap exists.

### Finding SUP-SSOT-004: Default analysis sources duplicated across two helpers

- **Principle violated:** SSOT
- **Severity:** Low
- **Location:** [app/sources/factory.py:13-14, 23-24, 35-36, 39-43](../app/sources/factory.py); [app/settings.py:45-48](../app/settings.py).
- **Evidence:** `DEFAULT_ANALYSIS_SOURCES = ["NVD", "OSV", "GITHUB"]` AND `Settings.analysis_sources: str = "NVD,OSV,GITHUB"`. `normalize_source_names` falls back to `DEFAULT_ANALYSIS_SOURCES`; `Settings.analysis_sources_list` falls back to `["NVD", "OSV", "GITHUB"]`.
- **Recommended fix:** One constant in `app/sources/factory.py` is canonical; `Settings` defaults reference it.

### Finding SUP-SSOT-005: TS `AnalysisFinding` interface diverges from Pydantic `AnalysisFindingOut`

- **Principle violated:** SSOT
- **Severity:** Medium
- **Location:** see `09_cross_cutting.md` finding CC-001 (full table).

### Finding SUP-SSOT-006: API base URLs are constants in two places

- **Principle violated:** SSOT
- **Severity:** Low
- **Location:** [app/settings.py:209-219](../app/settings.py); [app/analysis.py:222-223, 689-691](../app/analysis.py).
- **Evidence:**
  ```python
  # settings.py
  Settings.NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
  Settings.OSV_API = "https://api.osv.dev/v1"
  Settings.GITHUB_GRAPHQL = "https://api.github.com/graphql"
  Settings.VULNDB_API = "https://vuldb.com/?api"
  ```
  ```python
  # analysis.py
  nvd_api_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
  ...
  osv_api_base_url: str = "https://api.osv.dev"  # note no /v1!
  gh_graphql_url: str = "https://api.github.com/graphql"
  ```
  Note: `Settings.OSV_API` is `…/v1`, `_MultiSettings.osv_api_base_url` is `…osv.dev` (no `/v1`).
- **Why this violates the principle:** Drift bug latent — different defaults for the same upstream URL.
- **Recommended fix:** Single constants module.

---

## Principle of Least Astonishment

### Finding SUP-POLA-001: Imports trigger logging side effects in `app/main.py`

- **Principle violated:** POLA
- **Severity:** Low
- **Location:** [app/main.py:38-46](../app/main.py)
- **Evidence:**
  ```python
  from .logger import get_logger, setup_logging
  setup_logging()
  log = get_logger("api")
  from .auth import require_auth, validate_auth_setup
  ```
- **Why this violates the principle:** Side-effect of importing `app.main` is to reconfigure root logging. Two reasons: (a) "subsequent imports inherit the config" (per the comment on line 38), (b) the lifespan re-applies it (line 158) because uvicorn rewrites the root logger.
- **Impact:** Anyone importing `app.main` (e.g. `import app.main as app_module` for tests) reconfigures logging. Tests must work around it.
- **Recommended fix:** Move `setup_logging()` into the lifespan only.
- **Effort:** S
- **Risk of fix:** Low.

### Finding SUP-POLA-002: `get_settings(...)` route name collides with `app.settings.get_settings`

- **Principle violated:** POLA
- **Severity:** Low
- **Location:** [app/nvd_mirror/api.py:90-97](../app/nvd_mirror/api.py)
- **Evidence:** Function defined: `def get_settings(repo: SettingsRepositoryPort = Depends(get_settings_repo), db: Session = Depends(get_db)) -> NvdSettingsResponse:` — which is also the name of the global `get_settings()` factory.
- **Recommended fix:** Rename the route handler to `get_mirror_settings` or `read_mirror_settings`.
- **Effort:** S
- **Risk of fix:** Low.

### Finding SUP-POLA-003: `DELETE /api/sboms/{id}` returns 200 with `pending_confirmation` instead of an error

- **Principle violated:** POLA
- **Severity:** Medium
- **Location:** [app/routers/sboms_crud.py:615-643](../app/routers/sboms_crud.py)
- **Evidence:**
  ```python
  if _norm(confirm) not in {"yes", "y"}:
      return {
          "status": "pending_confirmation",
          "message": (...),
          "example": f"/api/sboms/{sbom_id}?user_id={user_id}&confirm=yes",
      }
  ```
- **Why this violates the principle:** A `DELETE` returning 200 with no deletion is surprising. Either the endpoint should require `confirm=yes` and 422 otherwise, or use a `409 Conflict` for "needs confirm". Same in `routers/projects.py:170-175`.
- **Recommended fix:** Return 422 (or 412 Precondition Required) with the same message body.
- **Effort:** S
- **Risk of fix:** Low (verify FE behaviour — the FE always sends `confirm=yes`).

---

## High Cohesion / Low Coupling

### Finding SUP-COH-001: `app/analysis.py` low cohesion (god module)

- **Principle violated:** Cohesion / Coupling
- **Severity:** High
- **Location:** see SOLID-SRP-001.

### Finding SUP-COU-001: `app.sources.runner` is loosely coupled but the source adapters still depend on `app.analysis`

- **Principle violated:** Coupling
- **Severity:** Medium
- **Location:** see OOP-005.

### Finding SUP-COU-002: Frontend `useBackgroundAnalysis` couples to React Query, custom toast, custom event bus, sessionStorage, and the router

- **Principle violated:** Coupling
- **Severity:** Low
- **Location:** [frontend/src/hooks/useBackgroundAnalysis.ts:31-128](../frontend/src/hooks/useBackgroundAnalysis.ts)
- **Evidence:** Single hook imports `useToast`, `useRouter`, `useQueryClient`, calls `addPendingAnalysis`, `dispatchSbomStatus` (a `CustomEvent` global broadcast), and updates the cache. Five integration points.
- **Why this violates the principle:** Hard to test. `dispatchSbomStatus` is a one-off pub/sub via `window.dispatchEvent` — `SbomStatusBadge` listens — separate from the React Query cache, which already does the same job.
- **Recommended fix:** Drop the `CustomEvent` channel; lean on React Query's cache invalidation. Saves complexity.
- **Effort:** M
- **Risk of fix:** Low.

---

## Categories with no significant violations

### Composition over Inheritance (positive)

The NVD-mirror sub-app uses Protocols + composition exclusively (see [app/nvd_mirror/application/facade.py](../app/nvd_mirror/application/facade.py) — the `NvdLookupService` injects `settings_repo`, `cve_repo`, `clock`, `live_query` rather than inheriting). **Status:** No significant violations in that sub-app.

---

## Summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 3 |
| Medium | 9 |
| Low | 9 |
| **Total** | **21** |

**Top three supporting-principle fixes:**
1. **SUP-FF-001** — Tighten broad exception handlers. Keeps real bugs visible.
2. **SUP-CQS-001** — Split `_run_legacy_analysis` into `analyze_now()` (query) + `persist_run()` (command). Foundation for SOLID-SRP-002.
3. **SUP-SSOT-006** — One constants module for upstream URLs; the `Settings.OSV_API = …/v1` vs `_MultiSettings.osv_api_base_url = …` drift is a latent bug.
