# Phase 2.3 — DRY Audit

> Real duplications across the codebase, plus one *false-DRY* anti-pattern flagged for restraint.

---

### Finding DRY-001: `now_iso()` is defined in five places

- **Principle violated:** DRY
- **Severity:** Medium
- **Location:** [app/utils.py:8-10](../app/utils.py); [app/services/sbom_service.py:27-31](../app/services/sbom_service.py); [app/routers/sboms_crud.py:81-83](../app/routers/sboms_crud.py); [app/routers/projects.py:30-31](../app/routers/projects.py); [app/repositories/sbom_repo.py:12-14](../app/repositories/sbom_repo.py); [app/repositories/analysis_repo.py:11-13](../app/repositories/analysis_repo.py); [app/services/pdf_service.py:70-74](../app/services/pdf_service.py).
- **Evidence (sample):**
  ```python
  # routers/sboms_crud.py:81
  def now_iso() -> str:
      return datetime.now(UTC).replace(microsecond=0).isoformat()
  ```
  ```python
  # services/sbom_service.py:27
  def now_iso() -> str:
      from datetime import datetime
      return datetime.now(UTC).replace(microsecond=0).isoformat()
  ```
- **Why this violates the principle:** Same one-line helper, byte-identical bodies, defined six times (and `app/utils.py` has zero importers). `main.py:62` even comments `from .services.sbom_service import now_iso  # re-exported for tests/back-compat`.
- **Impact:** A change to ISO format (e.g. include milliseconds) requires touching all six call sites.
- **Recommended fix:** Single canonical `now_iso` in `app/utils.py` (or `app/_clock.py`). Delete the five copies. Update imports.
- **Effort:** S
- **Risk of fix:** Low.

### Finding DRY-002: `safe_int` defined three times, `safe_float` twice

- **Principle violated:** DRY
- **Severity:** Low
- **Location:** [app/utils.py:19-32](../app/utils.py); [app/services/sbom_service.py:39-44](../app/services/sbom_service.py); [app/routers/sboms_crud.py:161-165](../app/routers/sboms_crud.py); [app/services/analysis_service.py:206-213](../app/services/analysis_service.py); [app/sources/vulndb.py:29-43](../app/sources/vulndb.py).
- **Evidence:** Identical bodies (`try: return int(value)` / `except (TypeError, ValueError)`). The `vulndb.py` variant adds a `minimum=` clamp.
- **Why this violates the principle:** Same three-line guard reproduced wherever a primitive coercion was needed.
- **Recommended fix:** Promote `app/utils.py` to the canonical home. Delete duplicates.
- **Effort:** S
- **Risk of fix:** Low.

### Finding DRY-003: `compute_report_status` defined three times with identical logic

- **Principle violated:** DRY
- **Severity:** Medium
- **Location:** [app/utils.py:39-44](../app/utils.py); [app/routers/sboms_crud.py:168-173](../app/routers/sboms_crud.py); [app/services/analysis_service.py:96-111](../app/services/analysis_service.py).
- **Evidence:**
  ```python
  if total_findings > 0:
      return "FAIL"
  if query_errors:
      return "PARTIAL"
  return "PASS"
  ```
  All three copies are identical.
- **Recommended fix:** Single home in `app/services/analysis_service.py` (or `app/utils.py`). Update three import sites.
- **Effort:** S
- **Risk of fix:** Low.

### Finding DRY-004: `normalize_details` exists twice with byte-identical bodies

- **Principle violated:** DRY
- **Severity:** Medium
- **Location:** [app/utils.py:47-92](../app/utils.py); [app/services/analysis_service.py:37-93](../app/services/analysis_service.py).
- **Evidence:** 45-line identical functions building the same severity buckets dict.
- **Recommended fix:** Keep one in `app/services/analysis_service.py`. Delete `app/utils.py:normalize_details`.
- **Effort:** S
- **Risk of fix:** Low (utils version has no callers).

### Finding DRY-005: `persist_analysis_run` exists twice with diverged behaviour

- **Principle violated:** DRY (cross-listed with SOLID-SRP-003)
- **Severity:** High
- **Location:** [app/routers/sboms_crud.py:176-277](../app/routers/sboms_crud.py); [app/services/analysis_service.py:119-203](../app/services/analysis_service.py).
- **Evidence:** Both write `AnalysisRun` rows from `details` dicts; the service version also writes `query_error_count` and `raw_report`. Production paths use the router version → those fields are lost.
- **Why this violates the principle:** Worse than identical duplication: drifted duplication. The "DRY violation" hides a latent bug.
- **Recommended fix:** Merge into a single canonical implementation in the service module. Add a regression test covering `query_error_count > 0`.
- **Effort:** M
- **Risk of fix:** Medium — must verify both call sites still pass tests.

### Finding DRY-006: `_rebuild_run_from_db` exists twice (router + service) with identical bodies

- **Principle violated:** DRY
- **Severity:** Medium
- **Location:** [app/routers/pdf.py:31-110](../app/routers/pdf.py); [app/services/pdf_service.py:82-185](../app/services/pdf_service.py).
- **Evidence:** Same 80-line function, character-for-character identical (verified by reading both). The router imports `load_run_cache` from the service but defines its own `_rebuild_run_from_db`.
- **Recommended fix:** Router calls `service.rebuild_run_from_db`. Delete the router copy.
- **Effort:** S
- **Risk of fix:** Low.

### Finding DRY-007: `upsert_components` exists twice — and a third broken stub in repositories

- **Principle violated:** DRY
- **Severity:** Medium
- **Location:** [app/routers/sboms_crud.py:101-150](../app/routers/sboms_crud.py); [app/services/sbom_service.py:120-182](../app/services/sbom_service.py); [app/repositories/component_repo.py:42-131](../app/repositories/component_repo.py).
- **Evidence:** The router and service versions are nearly identical (same triplet/cpe-map structure). The repository version uses a different triplet key shape (`name|version|type`) and never gets called.
- **Recommended fix:** Keep the service version. Router calls service. Delete the dead repository version.
- **Effort:** S
- **Risk of fix:** Low.

### Finding DRY-008: Severity-bucket counter loop repeated 5+ times

- **Principle violated:** DRY (cross-listed with OOP-014)
- **Severity:** Medium
- **Location:** [app/routers/sboms_crud.py:322-325, 882-886](../app/routers/sboms_crud.py); [app/routers/analyze_endpoints.py:155-158](../app/routers/analyze_endpoints.py); [app/services/analysis_service.py:74-86](../app/services/analysis_service.py); [app/utils.py:73-85](../app/utils.py); [app/pipeline/multi_source.py:276-279](../app/pipeline/multi_source.py).
- **Evidence:**
  ```python
  buckets = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
  for f in final_findings:
      sev = str((f or {}).get("severity", "UNKNOWN")).upper()
      buckets[sev if sev in buckets else "UNKNOWN"] += 1
  ```
  Five near-identical loops; `analysis_service` and `utils` use a lowercase variant with `if/elif` (DRY-violating spelling).
- **Recommended fix:** `count_severities(findings) -> dict[str,int]` in `app/sources/severity.py`. Five sites converge.
- **Effort:** S
- **Risk of fix:** Low.

### Finding DRY-009: `_validate_user_id` and `_validate_positive_int` duplicated between two routers

- **Principle violated:** DRY
- **Severity:** Low
- **Location:** [app/routers/sboms_crud.py:374-396](../app/routers/sboms_crud.py); [app/routers/projects.py:34-56](../app/routers/projects.py).
- **Evidence:** Same regex `^[A-Za-z0-9_.-]{1,64}$`, same 422 messaging. Char-for-char identical bodies.
- **Recommended fix:** Move to `app/routers/_validation.py` (or `app.utils.validation`). Two routers import.
- **Effort:** S
- **Risk of fix:** Low.

### Finding DRY-010: NVD retry loop duplicated between `_nvd_fetch_cves_paginated` and `nvd_query_by_keyword`

- **Principle violated:** DRY
- **Severity:** Medium
- **Location:** [app/analysis.py:411-502, 569-610](../app/analysis.py).
- **Evidence:** Both functions implement the same retry-with-backoff loop, the same 429-Retry-After parsing, the same `requests.RequestException` handling. ~30 lines duplicated.
- **Recommended fix:** Single `_nvd_request_with_retry(cfg, headers, url, params, *, log_label) -> requests.Response`. Both call sites collapse.
- **Effort:** S
- **Risk of fix:** Low — covered by `tests/test_nvd_perf_guards.py` and `tests/test_nvd_ssl_regression.py`.

### Finding DRY-011: `_async_get` / `_async_post` repeat the "use shared client else fallback" dance

- **Principle violated:** DRY
- **Severity:** Low
- **Location:** [app/analysis.py:753-805](../app/analysis.py); compare [app/sources/vulndb.py:166-178](../app/sources/vulndb.py).
- **Evidence:**
  ```python
  # analysis.py:753
  async def _async_get(url, headers=None, params=None, timeout=60):
      if httpx is not None:
          try:
              from .http_client import get_async_http_client
              client = get_async_http_client()
          except RuntimeError:
              async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
                  ...
  ```
  ```python
  # vulndb.py:168
  async def _post_vulndb_form(url, data, timeout):
      try:
          from app.http_client import get_async_http_client
          client = get_async_http_client()
      except RuntimeError:
          async with httpx.AsyncClient(timeout=timeout) as client:
              ...
  ```
- **Why this violates the principle:** Same try/except dance reproduced. Also the legacy code branch falls through to `requests` via `loop.run_in_executor` — a third path.
- **Recommended fix:** Add `app.http_client.async_client_or_local(timeout)` context manager. All callers `async with async_client_or_local(timeout=t) as c: …`.
- **Effort:** S
- **Risk of fix:** Low.

### Finding DRY-012: SBOM-format detection logic exists twice

- **Principle violated:** DRY
- **Severity:** Low
- **Location:** [app/parsing/extract.py:14-57](../app/parsing/extract.py); [app/routers/sbom.py:117-125](../app/routers/sbom.py).
- **Evidence:**
  ```python
  # routers/sbom.py:117-125
  if sbom_dict.get("bomFormat") == "CycloneDX" or "components" in sbom_dict:
      fmt = "CycloneDX"; spec_version = sbom_dict.get("specVersion")
  elif sbom_dict.get("spdxVersion") or sbom_dict.get("SPDXID"):
      fmt = "SPDX"; spec_version = sbom_dict.get("spdxVersion")
  ```
  ```python
  # parsing/extract.py:16-22 (same triple-condition logic, different shape)
  ```
  And `parsing/format.py:detect_sbom_format` (per inventory) returns the same info.
- **Recommended fix:** Both call sites use `parsing.format.detect_sbom_format`. Drop inline replicas.
- **Effort:** S
- **Risk of fix:** Low.

### Finding DRY-013: Dashboard counts implemented twice (service + router)

- **Principle violated:** DRY
- **Severity:** Medium
- **Location:** [app/routers/dashboard_main.py:27-42](../app/routers/dashboard_main.py); [app/services/dashboard_service.py:24-51](../app/services/dashboard_service.py).
- **Evidence:** Service `get_stats` returns `{total_projects, total_sboms, total_vulnerabilities, total_runs}` filtering active projects; router computes `{total_projects, total_sboms, total_vulnerabilities}` without filtering. Different definitions for the same dashboard concept.
- **Recommended fix:** Decide which definition is correct (Frontend `DashboardStats` type expects three keys; service offers four). Keep one. Delete the other. The frontend probably wants the active-only count from `dashboard_service`.
- **Effort:** S
- **Risk of fix:** Low (changes a number on the dashboard — verify with stakeholder).

### Finding DRY-014: SBOM CRUD router and SBOM-features router both compute SBOM detection inline

- **Principle violated:** DRY
- **Severity:** Low
- **Location:** [app/routers/sboms_crud.py:84-94](../app/routers/sboms_crud.py); [app/routers/sbom.py:108-115](../app/routers/sbom.py); [app/services/sbom_service.py:52-67](../app/services/sbom_service.py).
- **Evidence:** Three implementations of "given `sbom_data`, parse to dict, handle string vs dict, raise on bad JSON".
- **Recommended fix:** Single `parse_stored_sbom_data(value: str | dict | None) -> dict` in `app/services/sbom_service.py`. Three sites converge.
- **Effort:** S
- **Risk of fix:** Low.

### Finding DRY-015: `get_async_http_client()` import pattern repeated

- **Principle violated:** DRY (overlap with DRY-011)
- **Severity:** Low
- **Location:** [app/analysis.py:756, 783](../app/analysis.py); [app/sources/vulndb.py:169](../app/sources/vulndb.py); [app/routers/health.py:101-145](../app/routers/health.py).
- **Evidence:** Each caller wraps the call in a try/except `RuntimeError` for the case "FastAPI lifespan didn't start the client" (e.g. tests).
- **Recommended fix:** see DRY-011.

### Finding DRY-016: Frontend `analyzeSbomNvd / Github / Osv / VulnDb` are 4× copy-paste

- **Principle violated:** DRY
- **Severity:** Low
- **Location:** [frontend/src/lib/api.ts:479-509](../frontend/src/lib/api.ts).
- **Evidence:**
  ```ts
  export function analyzeSbomNvd(payload, signal?) {
    return request<ConsolidatedAnalysisResult>('/analyze-sbom-nvd', {
      method: 'POST', body: JSON.stringify(payload), signal,
    }, 180_000);
  }
  // …same for github, osv, vulndb…
  ```
- **Recommended fix:** `analyzeSbomBySource(source: 'nvd'|'github'|'osv'|'vulndb', payload, signal?)` building the URL.
- **Effort:** S
- **Risk of fix:** Low (one call site each in the analysis page).

---

## Cross-listed false-DRY (KISS overrides)

### Finding DRY-FALSE-001: Don't unify `analysis_service.persist_analysis_run` with the router's `_run_legacy_analysis` response builder

- **Principle:** KISS (intentionally not DRY)
- **Severity:** —
- **Note:** The temptation is to build one giant `analyze_and_persist_and_respond` helper. Resist. The HTTP response shape (`runId`/`id` legacy alias, `summary` block) is presentation; persistence is data. They drift for legitimate reasons. Keep the seam.

### Finding DRY-FALSE-002: Don't share an "extract aliases as JSON" helper between FE and BE

- **Principle:** KISS
- **Severity:** —
- **Note:** Both sides parse the JSON-string `aliases`/`fixed_versions` columns. Looks duplicative — but the BE uses `json.loads`, the FE uses `JSON.parse`, and the legitimate fix is to **stop storing JSON strings** in DB columns (see `07_backend.md`), not to share a helper across runtime boundaries.

---

## Summary

| Severity | Count |
|---|---|
| High | 1 |
| Medium | 7 |
| Low | 8 |
| **Total** | **16 (+2 false-DRY notes)** |

**Top duplications to converge first:**
1. **DRY-005** (= SOLID-SRP-003) — Merge `persist_analysis_run`. This duplication is a bug.
2. **DRY-001 + DRY-003 + DRY-004 + DRY-002** — One canonical `app/utils.py` module owns `now_iso`, `safe_int`, `safe_float`, `compute_report_status`, `normalize_details`, `normalized_key`. Delete six other copies. Single commit, no behaviour change.
3. **DRY-006** — Delete the `_rebuild_run_from_db` copy in the router. Single import change.
