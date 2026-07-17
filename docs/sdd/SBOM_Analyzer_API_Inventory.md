# SBOM Analyzer — API Inventory

| | |
|---|---|
| **Doc ID** | SBOM-DOC-002-API (companion to SBOM-DOC-002 Rev 0.1) |
| **Release Date** | 07-Jul-2026 |
| **Baseline** | Repository 2026-07-06/07 · backend 2.0.0 |
| **Prepared By** | Feroze |

Complete API inventory grouped by module: 204 decorator-defined endpoints across 29 router files (raw decorator count verified equal), plus 34 runtime alias routes registered via `add_api_route` for validation-session compatibility paths. Every endpoint carries the five-row contract table (signature, description, inputs, returns, validation/errors) with auth and pagination notes. Unresolved items are tracked in SBOM_Analyzer_Open_Questions.



## 1. API architecture overview

- **Framework**: FastAPI. App is constructed in `app/main.py`; all routes live in `app/routers/*.py` plus one admin router in `app/nvd_mirror/api.py`. Interactive docs at `/docs` (FastAPI default).
- **Prefix / versioning scheme**: There is **no single global prefix**. Each router declares its own prefix, and the codebase mixes two generations:
  - **Unversioned** `/api/...` — most resources (`/api/sboms`, `/api/projects`, `/api/products`, `/api/schedules`, `/api/analysis-runs`, `/api/remediation`, `/api/auth`, `/api/admin/...`).
  - **Versioned** `/api/v1/...` — newer surfaces only: CVE detail (`/api/v1/cves`, `/api/v1/scans/...`), compare v2 (`/api/v1/compare`), AI usage/credentials (`/api/v1/ai/...`), AI fixes (`/api/v1/runs/{run_id}/ai-fixes...`, `/api/v1/findings/{finding_id}/ai-fix`).
  - **No `/api` prefix at all** — dashboard routers are mounted at `/dashboard/...`, health/service-info at `/` and `/health`, the legacy ad-hoc analyzers at `/analyze-sbom-*`, the NVD-mirror admin at `/admin/nvd-mirror/...`, and AI copilot at `/api/ai/copilot/...` (unversioned `/api`).
- **Router registration** (`app/main.py:859-914`): 28 `include_router` calls. `_protected = [Depends(enforce_request_access)]` is attached to every router **except** `health.router` (deliberately unprotected for liveness probes and `/docs`). Three routers get their prefix at include time: `app/routers/analysis.py` → `/api/analysis-runs`, `app/routers/sbom.py` → `/api/sboms`, `app/routers/dashboard.py` → `/dashboard`.
- **Auth model** (two layers):
  1. `require_auth` (`app/auth.py:138`) — token check driven by `API_AUTH_MODE` env (`none` | `bearer` | `jwt`). `none` (default dev) is a no-op. Failures: 401 `"Authentication required"`, 401 invalid scheme/token (`WWW-Authenticate: Bearer realm="sbom-analyzer"`).
  2. `enforce_request_access` (`app/core/security.py:321`) — resolves the tenant/user context (`get_current_tenant_context`), derives a permission from the request (`permission_for_request`), and raises **403 `"Insufficient permission"`** when the context lacks it. Applied router-wide via `dependencies=_protected` to every router except health. Some handlers additionally require fine-grained permissions via `require_permission("<perm>")` (noted per endpoint).
  - Tenancy: `X-Tenant-ID` header switches tenant; most handlers take `context: CurrentContext = Depends(get_current_tenant_context)` and scope every query by `tenant_id`.
- **Cross-cutting middleware/behavior**: `MaxBodySizeMiddleware` rejects oversize bodies with **413** before routing (`MAX_UPLOAD_BYTES`); global exception handler (`app/error_handlers.py`) converts unhandled exceptions to a canonical 500 envelope with `correlation_id`; SlowAPI rate limiting (`analyze_route_limit` on the analyze endpoints → **429** when exceeded); GZip; CORS; an audit-log middleware records mutating calls and export downloads.
- **Run-status vocabulary (ADR-0001)**: canonical `OK, FINDINGS, PARTIAL, ERROR, RUNNING, PENDING, NO_DATA`; legacy `PASS`/`FAIL` accepted inbound only.

### Endpoint totals and completeness check

- Raw decorator grep `@(router|app)\.(get|post|put|patch|delete)(` across `app/`: **204 matches in 29 files** (`app/routers/*.py` = 199, `app/nvd_mirror/api.py` = 5). No `@app.<verb>` routes exist in `app/main.py`; no commented-out route decorators found (grep `^\s*#\s*@router\.` = 0 matches).
- Documented below: **204 endpoints** — counts match, nothing excluded. One route function (`get_sbom_normalization_report`) is an alias that delegates to the dedupe-report handler; both paths are documented separately. The three `sbom_validation_sessions` routers (`router`, `compat_router`, `workspace_router`) are all registered and counted.
- Per-file decorator counts (raw grep): vex 7, schedules 16, lifecycle_admin 12, pdf 1, compare 2, dashboard_advanced 5, sbom_upload 1, ai_usage 10, health 4, sboms_crud 20, analysis 3, cves 3, ai_copilot 2, dashboard_main 12, runs 7, ai_credentials 11, sbom_validation_sessions 17, tenants 6, dashboard 1, analyze_endpoints 5, sbom_versions 13, projects 7, products 6, sbom 3, remediation 4, reports 1, ai_fixes 14, lifecycle 6, nvd_mirror/api 5 = **204**.

---

## 2. Endpoint inventory by functional group

Auth notation: **Protected** = router-level `enforce_request_access` (401/403 as above). **Public** = no auth dependency. Extra `require_permission("...")` noted where present.

### Group: Health and Diagnostics (`app/routers/health.py`, router prefix: none)

#### GET /

| Field | Details |
| --- | --- |
| Function Signature | GET / → `def service_info() -> dict` in `app/routers/health.py` |
| Description | Service banner: name, version, docs/health URLs. Used as a root reachability check. |
| Input Parameters | None |
| Return Values | Ad-hoc dict `{service: "sbom-analyzer-api", version, docs_url: "/docs", health_url: "/health"}`; 200 JSON |
| Validation and Error Messages | None — never raises |

Auth: **Public** (router intentionally registered without auth).

#### GET /health

| Field | Details |
| --- | --- |
| Function Signature | GET /health → `def health(db: Session = Depends(get_db)) -> dict` in `app/routers/health.py` |
| Description | Liveness/readiness probe. Reports DB connectivity (dialect) and NVD-mirror freshness (enabled, last_success_at, watermark, stale, counters). Designed to never 500 — subsystem failures degrade to `{"available": false}`. |
| Input Parameters | None |
| Return Values | Ad-hoc dict `{status: "ok", database: {available, dialect}, nvd_mirror: {enabled, last_success_at, watermark, stale, counters} or {available: false, error}}`; 200 JSON |
| Validation and Error Messages | None — all internal errors are caught and reported in-body |

Auth: **Public**.

#### GET /api/analysis/config

| Field | Details |
| --- | --- |
| Function Signature | GET /api/analysis/config → `def get_analysis_config() -> dict` in `app/routers/health.py` |
| Description | Exposes the effective multi-source analysis configuration (NVD/OSV/GHSA/VulDB endpoints, timeouts, retry/delay tuning, CVSS thresholds, finding caps, concurrency) plus feature flags (`github_configured`, `nvd_key_configured`, `vulndb_configured`, `cve_modal_enabled`, `ai_fixes_enabled`, `ai_default_provider`, `ai_ui_config_enabled`). Secret values are never returned — only env-var *names* (e.g. `nvd_api_key_env: "NVD_API_KEY"`) and boolean configured-flags. |
| Input Parameters | None |
| Return Values | Ad-hoc config dict (~30 keys, see `public_analysis_config()`); 200 JSON |
| Validation and Error Messages | None raised; default-provider resolution failures fall back to env value (logged warning) |

Auth: **Protected** via route-level `dependencies=[Depends(require_auth)]` (401s per `require_auth`; no tenant/permission check).

#### GET /api/types

| Field | Details |
| --- | --- |
| Function Signature | GET /api/types → `def list_sbom_types(db)` in `app/routers/health.py` |
| Description | Lists SBOM type lookup rows (CycloneDX, SPDX, …) for upload/edit dropdowns, ordered by typename. |
| Input Parameters | None |
| Return Values | `list[SBOMTypeOut]` — `{id, typename, type_details?, created_on?, created_by?, modified_on?, modified_by?}`; 200 JSON |
| Validation and Error Messages | None raised |

Auth: **Protected** via route-level `dependencies=[Depends(require_auth)]`.

---

### Group: SBOM Management (`app/routers/sboms_crud.py` prefix `/api`; `app/routers/sbom_upload.py` prefix `/api/sboms`; `app/routers/sbom_versions.py` prefix `/api/sboms`; `app/routers/sbom.py` mounted at `/api/sboms`; `app/routers/sbom_validation_sessions.py` three routers)

All endpoints in this group are **Protected** (router-level `enforce_request_access`).

#### GET /api/sboms/{sbom_id}

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sboms/{sbom_id} → `def get_sbom(sbom_id, include_raw, context, db)` in `app/routers/sboms_crud.py` |
| Description | Fetch a single SBOM (tenant-scoped) with workspace/repair fields and latest-analysis summary attached. Raw document body omitted unless requested. |
| Input Parameters | Path `sbom_id: int`; query `include_raw: bool = false` ("Include full raw SBOM document content in the response") |
| Return Values | `SBOMSourceOut` — key fields: `id, sbom_name, sbom_data?, sbom_type, projectid/project_id, project_name, product_id, product_name, component_count, sbom_version, status ('validated'|'failed'|'quarantined'|'pending'), failed_stage, validation_errors[], error_count, warning_count, validated_at, workspace_id, validation_session_id, repair_workspace_url, workspace_available, latest_analysis: LatestAnalysisOut {run_id, status, result, finding_count, critical/high/medium/low_count, risk_score, risk_level, started_at, completed_at, error_message}`; 200 |
| Validation and Error Messages | 404 `"SBOM not found"` when id missing for tenant |

#### POST /api/sboms/{sbom_id}/workspace

| Field | Details |
| --- | --- |
| Function Signature | POST /api/sboms/{sbom_id}/workspace → `def create_sbom_workspace(sbom_id, context, db)` in `app/routers/sboms_crud.py` |
| Description | Gets or creates (backfills) a repair workspace/validation session for a legacy SBOM so it can be edited in the repair UI. |
| Input Parameters | Path `sbom_id: int`; no body |
| Return Values | Workspace response dict from `WorkspaceBackfillService.create_response` (session id, `repair_workspace_url`, `created` flag, workspace fields); 200 |
| Validation and Error Messages | 404 `"SBOM not found"`; 403 `"Insufficient permission"` unless caller has `sbom:repair:update` (`require_permission`) |

#### GET /api/sboms/{sbom_id}/stats

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sboms/{sbom_id}/stats → `def get_sbom_document_stats(sbom_id, context, db)` in `app/routers/sboms_crud.py` |
| Description | Document-level statistics for the SBOM viewer header (size, lines, component/dependency counts, hash). |
| Input Parameters | Path `sbom_id: int` |
| Return Values | `SbomDocumentStatsResponse` — `{sbom_id, sbom_name, format, spec_version, file_size_bytes, line_count, parsed_component_count, component_count, component_total_rows, duplicate_component_count, dependency_count, relationship_count, content_sha256, validation_status}`; 200 |
| Validation and Error Messages | 404 `"SBOM not found"` |

#### GET /api/sboms/{sbom_id}/raw

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sboms/{sbom_id}/raw → `def get_sbom_raw_chunk(sbom_id, offset, limit, context, db)` in `app/routers/sboms_crud.py` |
| Description | Paged (chunked) read of the raw SBOM document for the in-app viewer — avoids shipping multi-MB bodies at once. |
| Input Parameters | Path `sbom_id: int`; query `offset: int ≥ 0` (default 0), `limit: int` 1..`MAX_RAW_CHUNK_LIMIT` (default `DEFAULT_RAW_CHUNK_LIMIT`, from `app/services/sbom_document_service.py`) |
| Return Values | `SbomRawChunkResponse` — `{sbom_id, offset, limit, total_lines, lines: list[str], preview, truncated}`; 200 |
| Validation and Error Messages | 404 `"SBOM not found"`; 404 `"SBOM has no stored document content"`; 422 auto (FastAPI) for out-of-range offset/limit |

#### GET /api/sboms/{sbom_id}/download

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sboms/{sbom_id}/download → `def download_sbom_original(sbom_id, context, db)` in `app/routers/sboms_crud.py` |
| Description | Streams the stored SBOM document as a file download (XML or JSON detected from content); writes an `sbom.download` audit-log row. |
| Input Parameters | Path `sbom_id: int` |
| Return Values | `StreamingResponse`, media type `application/xml` or `application/json`, `Content-Disposition: attachment; filename="<sbom_name>.<ext>"`; 200 (file download, non-JSON envelope) |
| Validation and Error Messages | 404 `"SBOM not found"` (also when no `sbom_data` stored) |

#### POST /api/sboms

| Field | Details |
| --- | --- |
| Function Signature | POST /api/sboms → `def create_sbom(payload, background_tasks, context, db)` in `app/routers/sboms_crud.py` |
| Description | Create an SBOM from a JSON payload (no auto-analysis). Resolves project/product assignment, enforces global name uniqueness, runs the 8-stage validation pipeline *before* insert; failed uploads are staged into `sbom_validation_sessions` instead of `sbom_source`. Component sync + post-upload enrichment run after commit (enrichment as background task). |
| Input Parameters | Body `SBOMSourceCreate` — `{sbom_name: str (required), sbom_data?: str, sbom_type?: int, projectid?/project_id?: int, product_id?: int, sbom_version?: str, created_by?: str, productver?/product_version?: str}` (aliases accepted via model_validator) |
| Return Values | `SBOMSourceOut`; **201 Created** |
| Validation and Error Messages | 404 `"SBOM type not found"`; 409 `{code: "duplicate_name", message: "An SBOM with name '<name>' already exists."}` (preflight and on `IntegrityError`); 409 `{code: "integrity_error", message: "Integrity constraint violated while creating SBOM."}`; validation failure → `report.http_status` (400/422 per stage) with structured detail `{code: "sbom_validation_failed", message: "SBOM '<name>' did not pass validation; N error(s) at stage '<stage>'.", sbom_id, status, failed_stage, error_count, warning_count, entries[], truncated}`; 500 `{code: "db_error", message: "Internal database error while creating SBOM."}`; 500 `{code: "unexpected", message: "Unexpected error while creating SBOM."}` |

#### GET /api/sboms

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sboms → `def get_sbom_details(user_id, status_filter, stage, page, page_size, cursor, response, context, db)` in `app/routers/sboms_crud.py` |
| Description | Tenant-scoped SBOM list with filters and dual pagination (offset or keyset). Each row carries workspace fields + latest-analysis rollup (batched queries). Sets `X-Total-Count` and `X-Next-Cursor` response headers. |
| Input Parameters | Query: `user_id?: str` (regex `^[A-Za-z0-9_.-]{1,64}$`), `status?: str` (alias of `status_filter`; one of validated/failed/quarantined/pending), `stage?: str` (ingress/detect/schema/semantic/integrity/security/ntia/signature), `page: int ≥1` (default 1), `page_size: int` 1..500 (default 50), `cursor?: int` (keyset: id < cursor, desc; overrides page) — **pagination: offset + keyset** |
| Return Values | `list[SBOMSourceOut]`; headers `X-Total-Count`, `X-Next-Cursor` (when full page); 200 |
| Validation and Error Messages | 422 `"Query parameter 'user_id' must not be empty or whitespace."`; 422 `"Invalid 'user_id'. Allowed: letters, digits, '_', '-', '.'; length 1–64 characters."`; 422 `"status must be one of ['failed', 'pending', 'quarantined', 'validated']"`; 422 `"stage must be one of [...]"`; 422 `"cursor must be >= 1"`; 500 `"Internal database error while fetching SBOMs."` |

#### GET /api/sboms/{sbom_id}/components

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sboms/{sbom_id}/components → `def get_sbom_components(sbom_id, include_duplicates, duplicate_only, dedupe_group_id, normalized_name, normalized_purl, page, page_size, search, sort_by, sort_order, context, db)` in `app/routers/sboms_crud.py` |
| Description | Paged, searchable, sortable component list for an SBOM, with Stage-9 dedupe filters (duplicates only, group id, normalized name/purl). |
| Input Parameters | Path `sbom_id: int (>0)`; query `include_duplicates: bool=false`, `duplicate_only: bool=false`, `dedupe_group_id?: str`, `normalized_name?: str`, `normalized_purl?: str`, `page ≥1` (default 1), `page_size` 1..1000 (default 100), `search?: str`, `sort_by: str="name"` (name/version/component_type/license/lifecycle_status), `sort_order: str="asc"` — **pagination: offset** |
| Return Values | `SBOMComponentListResponse` — `{items: list[SBOMComponentListItem], total_count, unique_count, duplicate_count, include_duplicates, page, page_size}`; 200 |
| Validation and Error Messages | 422 `"'sbom_id' must be a positive integer (>= 1)."`; 400 `"Unsupported sort_by value: <v>"`; 400 `"Unsupported sort_order value: <v>"`; 404 `"SBOM not found"`; 500 `"Internal database error while fetching SBOM components."` |

#### POST /api/sboms/{sbom_id}/components/reprocess

| Field | Details |
| --- | --- |
| Function Signature | POST /api/sboms/{sbom_id}/components/reprocess → `def reprocess_sbom_components(sbom_id, context, db)` in `app/routers/sboms_crud.py` |
| Description | Re-runs validation and re-extracts/re-syncs component rows from the stored document (for legacy rows or after repair). Updates validation status columns; audit-logged (`sbom.components.reprocess`). |
| Input Parameters | Path `sbom_id: int (>0)`; no body |
| Return Values | Ad-hoc dict `{sbom_id, component_extraction_status, component_extraction_error, component_count, format, spec_version}`; 200 |
| Validation and Error Messages | 422 positive-int check (as above); 404 `"SBOM not found"`; 400 `{code: "sbom_data_missing", message: "Cannot reprocess components because this SBOM has no stored document content."}`; 422 `{code: "sbom_validation_failed", message: "Cannot reprocess components until SBOM validation passes.", status, failed_stage, entries}`; 422 `{code: "unsupported_sbom_format", message: <skip reason>}`; 500 `{code: "db_error", message: "Failed to reprocess SBOM components."}`; 500 `{code: "component_extraction_failed", message: "Component extraction failed."}` |

#### POST /api/sboms/{sbom_id}/normalize-deduplicate

| Field | Details |
| --- | --- |
| Function Signature | POST /api/sboms/{sbom_id}/normalize-deduplicate → `def normalize_deduplicate_sbom(sbom_id, force, context, db)` in `app/routers/sboms_crud.py` |
| Description | Runs (or re-runs with `force=true`) Stage-9 normalization + deduplication over the SBOM's components; returns the stored dedupe report. Skips work and returns `status: "unchanged"` if a report already exists and `force` is false. |
| Input Parameters | Path `sbom_id: int (>0)`; query `force: bool=false` |
| Return Values | Ad-hoc dict `{sbom_id, status: "completed"|"unchanged", component_count?, report}`; 200 |
| Validation and Error Messages | 403 unless permission `sbom:update`; 422 positive-int; 404 `"SBOM not found"`; 400 `{code: "sbom_data_missing", message: "SBOM has no stored content."}`; 422 `{code: "unsupported_sbom_format", ...}`; 500 `{code: "normalization_failed", message: "Normalization failed."}` |

#### GET /api/sboms/{sbom_id}/dedupe-report

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sboms/{sbom_id}/dedupe-report → `def get_sbom_dedupe_report(sbom_id, context, db)` in `app/routers/sboms_crud.py` |
| Description | Returns the persisted Stage-9 dedupe report; empty-report shape when none exists. |
| Input Parameters | Path `sbom_id: int (>0)` |
| Return Values | Report dict `{duplicates_found, duplicates_merged, conflicts[], ref_mapping{}, remapped_dependencies{}}`; 200 |
| Validation and Error Messages | 422 positive-int; 404 `"SBOM not found"`; 500 `"Internal database error while fetching dedupe report."` |

#### GET /api/sboms/{sbom_id}/normalization-report

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sboms/{sbom_id}/normalization-report → `def get_sbom_normalization_report(sbom_id, context, db)` in `app/routers/sboms_crud.py` |
| Description | Alias of the dedupe report — delegates directly to `get_sbom_dedupe_report`. |
| Input Parameters | Path `sbom_id: int (>0)` |
| Return Values | Same report dict as above; 200 |
| Validation and Error Messages | Same as dedupe-report endpoint |

#### PATCH /api/sboms/{sbom_id}

| Field | Details |
| --- | --- |
| Function Signature | PATCH /api/sboms/{sbom_id} → `def update_sbom(sbom_id, payload, context, db)` in `app/routers/sboms_crud.py` |
| Description | Partial update of SBOM metadata (name, description, versions, project/product reassignment). Project/product change is propagated to related `AnalysisRun` rows and audit-logged (`sbom.product_changed`, `sbom.update`). |
| Input Parameters | Path `sbom_id: int`; body `SbomPatchRequest` — `{project_id?: int, product_id?: int, name?: str, product_name?: str, product_version?: str, sbom_version?: str, description?: str, change_reason?: str}` (all optional, `exclude_unset`) |
| Return Values | `SBOMSourceOut`; 200 |
| Validation and Error Messages | 404 `"SBOM not found"`; 400 `"Invalid project_id format"` (non-int or ≤0); 400 `"Invalid product_id format"`; 500 `{code: "internal_error", message: "Internal server error."}` |

#### GET /api/sboms/{sbom_id}/delete-impact

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sboms/{sbom_id}/delete-impact → `def sbom_delete_impact(sbom_id, db)` in `app/routers/sboms_crud.py` |
| Description | Pre-delete impact report: every dependent row (runs, findings, components, descendants) a permanent delete would remove. |
| Input Parameters | Path `sbom_id: int (ge=1)` |
| Return Values | Impact dict from `SBOMDeleteService.get_delete_impact` (counts per dependent entity, descendant SBOMs); 200 |
| Validation and Error Messages | 404 `"SBOM not found"` (from `LookupError`) |

#### DELETE /api/sboms/{sbom_id}

| Field | Details |
| --- | --- |
| Function Signature | DELETE /api/sboms/{sbom_id} → `def delete_sbom(sbom_id, confirm, permanent, context, db)` in `app/routers/sboms_crud.py` |
| Description | Two-phase delete. Without `confirm=yes` (and not permanent) returns a `pending_confirmation` payload instead of deleting. `permanent=false` (default) soft-deletes (marks SBOM + runs/components/findings inactive, recoverable); `permanent=true` hard-deletes with dependency conflict detection. |
| Input Parameters | Path `sbom_id: int`; query `confirm: str="no"` ("Set to 'yes' to confirm deletion"; accepts yes/y case-insensitive), `permanent: bool=false` |
| Return Values | 200 with either `{status: "pending_confirmation", message: "This operation will delete the SBOM and all related analysis data. To proceed, resend the request with confirm=yes (and add permanent=true to bypass soft delete).", example}` or the service's delete-result dict |
| Validation and Error Messages | 400 `"Invalid sbom_id. It must be a positive integer."`; 404 `"SBOM not found"`; 409 `{code: "sbom_delete_conflict", message: <exc.message>, blocking_dependencies, delete_impact?}`; 500 `{code: "internal_error", message: "Internal server error."}` |

#### POST /api/sboms/{sbom_id}/restore

| Field | Details |
| --- | --- |
| Function Signature | POST /api/sboms/{sbom_id}/restore → `def restore_sbom(sbom_id, context, db)` in `app/routers/sboms_crud.py` |
| Description | Restores a soft-deleted SBOM (Phase 3.4 admin recovery). Non-cascading — children must be restored individually. Audit-logged (`sbom.restore`). |
| Input Parameters | Path `sbom_id: int (ge=1)` |
| Return Values | `{status: "restored", id}` or `{status: "already_active", id}`; 200 |
| Validation and Error Messages | 404 `"SBOM not found"` (searched with `include_deleted=True`) |

#### POST /api/sboms/{sbom_id}/revalidate

| Field | Details |
| --- | --- |
| Function Signature | POST /api/sboms/{sbom_id}/revalidate → `def revalidate_sbom(sbom_id, db)` in `app/routers/sboms_crud.py` |
| Description | Idempotently re-runs the 8-stage validator against stored `sbom_data` and persists the resulting status columns; brings legacy rows onto the current status convention. |
| Input Parameters | Path `sbom_id: int (>0)` |
| Return Values | `SBOMSourceOut` on clean report; 200. On error-bearing report: 4xx (`report.http_status`) with `{code: "sbom_validation_failed", message: "SBOM '<name>' did not pass validation; N error(s) at stage '<stage>'.", sbom_id, status, failed_stage, error_count, warning_count, entries, truncated}` |
| Validation and Error Messages | 422 positive-int; 404 `"SBOM not found"`; 400 `{code: "sbom_data_missing", message: "Cannot revalidate this SBOM — no document body is stored on the row. Re-upload the SBOM to populate it."}`; 500 `{code: "db_error", message: "Failed to persist revalidation."}` |

#### POST /api/sboms/{sbom_id}/analyze

| Field | Details |
| --- | --- |
| Function Signature | POST /api/sboms/{sbom_id}/analyze → `async def run_analysis_for_sbom(request, response, sbom_id, force_refresh, idempotency_key, db)` in `app/routers/sboms_crud.py` |
| Description | Triggers a synchronous multi-source vulnerability analysis (NVD/OSV/GHSA/VulDB fan-out via `create_auto_report`) and persists the run. Returns the existing run (HTTP 200 instead of 201) if one is already active. Supports `Idempotency-Key` header replay. Rate-limited (`analyze_route_limit`). |
| Input Parameters | Path `sbom_id: int`; query `force_refresh: bool=false` (bypass source-response cache, refresh entries); header `Idempotency-Key?: str` |
| Return Values | `AnalysisRunOut` — `{id, sbom_id, project_id, product_id, product_name, run_status, sbom_name, source, trigger_source, started_on, completed_on, duration_ms, total_components, components_with_cpe, total_findings, critical/high/medium/low/unknown_count, query_error_count, raw_report?, metrics?}`; **201 Created** (200 when an active run already exists) |
| Validation and Error Messages | 404 `"SBOM not found"`; 500 `"Unable to generate analysis report"` (analysis failure or empty report); 429 via SlowAPI rate limit |

#### POST /api/sboms/{sbom_id}/analyze/stream

| Field | Details |
| --- | --- |
| Function Signature | POST /api/sboms/{sbom_id}/analyze/stream → `async def analyze_sbom_stream(request, sbom_id, payload, idempotency_key, context, db)` in `app/routers/sboms_crud.py` |
| Description | Runs multi-source analysis streaming per-source progress via **SSE** (`text/event-stream`). Event types: `progress` (phases started/parsed; per-source running/complete/error), `complete` (runId + severity counts + provider_status), `error` (fatal). Creates the `AnalysisRun` row up front (PENDING→RUNNING→final). Idempotency-Key replays cached `complete` events. Rate-limited. |
| Input Parameters | Path `sbom_id: int`; body `AnalyzeStreamPayload {sources?: list[str]}` (defaults to configured sources); header `Idempotency-Key?: str` |
| Return Values | `StreamingResponse` media type `text/event-stream` (headers `Cache-Control: no-cache`, `X-Accel-Buffering: no`); `complete` event payload: `{runId, status, total, critical, high, medium, low, unknown, errors, duration_ms, provider_status}`; always HTTP 200 (errors delivered as SSE events) |
| Validation and Error Messages | SSE `error` event `{message: "SBOM <id> not found", code: 404}`; SSE `error` `"SBOM parse failed: <exc>"` (code 400); SSE `error` with `mark_failed(<exc>)` (code 500, run marked ERROR); `complete` with `status: "already_running"`, message `"Analysis is already running for this SBOM."`; 429 via rate limit |

#### GET /api/sboms/{sbom_id}/analysis-runs

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sboms/{sbom_id}/analysis-runs → `def list_sbom_analysis_runs(sbom_id, page, page_size, context, db)` in `app/routers/sboms_crud.py` |
| Description | Paged list of analysis runs for one SBOM, newest first (tenant-scoped). |
| Input Parameters | Path `sbom_id: int`; query `page ≥1` (default 1), `page_size` 1..500 (default 50) — **pagination: offset** |
| Return Values | `list[AnalysisRunOut]`; 200 |
| Validation and Error Messages | 404 `"SBOM not found"` |

#### POST /api/sboms/upload

| Field | Details |
| --- | --- |
| Function Signature | POST /api/sboms/upload → `async def upload_sbom(background_tasks, request, response, file, sbom_name, project_id, product_id, sbom_type, sbom_version, product_version, productver, created_by, context, strict_ntia, db)` in `app/routers/sbom_upload.py` |
| Description | Canonical multipart SBOM ingress (ADR-0007). Runs the 8-stage validation pipeline before any DB write; rejected SBOMs are staged only in `sbom_validation_sessions` for repair, never inserted into `sbom_source`. On success creates a validation session + SBOMSource row, syncs components, and schedules background enrichment. Emits a `Warning: 299 - "product_id will become required in a future version."` header when the default product was used. |
| Input Parameters | Multipart form: `file: UploadFile` (required, "SBOM document (SPDX or CycloneDX)"), `sbom_name: str` (required, 1–255 chars), `project_id?: int`, `product_id?: int`, `sbom_type?: int`, `sbom_version?: str`, `product_version?/productver?: str`, `created_by?: str`; query `strict_ntia: bool=false` ("Promote NTIA warnings to hard errors.") |
| Return Values | `SbomAcceptedResponse` (defined in the router) — `{status: "valid"|"valid_with_warnings", workspace_id, validation_session_id, repair_workspace_url, sbom_id, sbom_name, sbom_version, product_version, project_id, product_id, product_name, project_name, spec, spec_version, detected_format, detected_spec_version, detection_confidence, detection_evidence, file_size_bytes, total_lines, sha256, is_large_file, full_editor_allowed, components, validation_errors[], validation_warnings[], warnings[], info[], enrichment_status: "pending", validation_status, message: "SBOM uploaded successfully. Enrichment is running in background."}`; **202 Accepted** |
| Validation and Error Messages | 422 `{code: "unsupported_form_fields", message: "Unsupported upload form field(s). Use snake_case request fields.", fields}`; 404 `"SBOM type not found"`; 413 with entry `SBOM_VAL_E001_SIZE_EXCEEDED`, message `"Uploaded body of N bytes exceeds MAX_UPLOAD_BYTES (M)."`; validation failure → `report.http_status` (400/413/415/422 per stage) with `build_validation_failed_detail` structure; 422 `{code: "workspace_blocked", message: <blocked_reason>}`; 500 `{code: "internal_error", message: "Failed to persist SBOM."}` |

Auth: **Protected**.

#### GET /api/sboms/{sbom_id}/risk-summary

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sboms/{sbom_id}/risk-summary → `def get_sbom_risk_summary(sbom_id, db)` in `app/routers/sbom.py` (router mounted with prefix `/api/sboms` in `app/main.py`) |
| Description | CVSS + EPSS + KEV composite risk summary computed from the latest analysis run's findings (`app/services/risk_score.py`). |
| Input Parameters | Path `sbom_id: int` |
| Return Values | Ad-hoc dict `{sbom_id, run_id, total_risk_score: float, risk_band: "CRITICAL"|..., components[], worst_finding, kev_count, epss_avg, methodology}`; 200 |
| Validation and Error Messages | 404 `"SBOM not found"`; 404 `"No analysis run found for this SBOM"` |

Auth: **Protected**.

#### GET /api/sboms/{sbom_id}/validation-report

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sboms/{sbom_id}/validation-report → `def get_sbom_validation_report(sbom_id, db, context)` in `app/routers/sbom.py` |
| Description | Returns the persisted 8-stage validation report (entries enriched with stage numbers, pre-computed severity/stage summaries). For failed/quarantined rows lacking a repair session it lazily re-runs validation and creates one. Also serves the frontend's JSON-download affordance. |
| Input Parameters | Path `sbom_id: int` |
| Return Values | `ValidationReportResponse` — `{sbom_id, filename, status, failed_stage, error_count, warning_count, info_count, entries: list[ValidationErrorEntry {code, severity, stage, stage_number, path, message, remediation, spec_reference}], validated_at, spec_detected, spec_version_detected, severity_summary{}, stage_summary{}, truncated, session_id, workspace_id, validation_session_id, repair_workspace_url, validation_status, can_edit}`; 200 |
| Validation and Error Messages | 404 `"SBOM not found"` |

Auth: **Protected**.

#### GET /api/sboms/{sbom_id}/info

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sboms/{sbom_id}/info → `def get_sbom_info(sbom_id, db)` in `app/routers/sbom.py` |
| Description | Parsed metadata about the stored SBOM without running analysis: format, spec version, component count, ecosystems (from purls), purl/cpe presence, 5-name component preview. |
| Input Parameters | Path `sbom_id: int` |
| Return Values | Ad-hoc dict `{sbom_id, format: "CycloneDX"|"SPDX"|"Unknown", spec_version, component_count, ecosystems[], has_purls, has_cpes, components_preview[]}`; 200 |
| Validation and Error Messages | 404 `"SBOM not found"`; 400 `"SBOM has no data stored"`; 400 `"Invalid SBOM JSON: <err>"` |

Auth: **Protected**.

#### POST /api/sboms/{id}/edit

| Field | Details |
| --- | --- |
| Function Signature | POST /api/sboms/{id}/edit → `def edit_sbom_endpoint(id, payload, background_tasks, user_id, db)` in `app/routers/sbom_versions.py` |
| Description | Manually edits SBOM components/metadata/dependencies and creates a **new version** row (lineage via `parent_id`). Lifecycle overrides in the payload are re-enriched in a background task. |
| Input Parameters | Path `id: int`; query `user_id?: str`; body `SbomEditPayload` — `{metadata?: dict, components: list[ComponentEditPayload], change_summary: str = "Manual edit via UI"}` |
| Return Values | `SBOMSourceOut` (the new version row); 200 |
| Validation and Error Messages | 400 with `str(ValueError)` from `edit_sbom` service (e.g. unknown SBOM, invalid update) |

Auth: **Protected**.

#### GET /api/sboms/{id}/versions

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sboms/{id}/versions → `def get_sbom_versions(id, db)` in `app/routers/sbom_versions.py` |
| Description | Returns all versions in the SBOM's lineage chain (walks to root ancestor, collects all descendants), ordered by id. |
| Input Parameters | Path `id: int` |
| Return Values | `list[SBOMSourceOut]`; 200 |
| Validation and Error Messages | 404 `"SBOM with ID {id} not found."` |

Auth: **Protected**.

#### GET /api/sboms/compare-versions

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sboms/compare-versions → `def compare_sbom_versions(version_a, version_b, db)` in `app/routers/sbom_versions.py` |
| Description | Compares two SBOM version rows and returns added / removed / changed components (`version_control_service.compare_versions`). |
| Input Parameters | Query `version_a: int` (required), `version_b: int` (required) |
| Return Values | `dict[str, Any]` diff (added/removed/changed component lists); 200 |
| Validation and Error Messages | 404 `"One or both of the specified SBOM versions were not found."` |

Auth: **Protected**.

#### POST /api/sboms/{id}/restore/{version_id}

| Field | Details |
| --- | --- |
| Function Signature | POST /api/sboms/{id}/restore/{version_id} → `def restore_sbom_version(id, version_id, user_id, db)` in `app/routers/sbom_versions.py` |
| Description | Restores a previous version by cloning it as the new head version of the lineage. |
| Input Parameters | Path `id: int`, `version_id: int`; query `user_id?: str` |
| Return Values | `SBOMSourceOut` (restored head); 200 |
| Validation and Error Messages | 400 with `str(ValueError)` from `restore_version` service |

Auth: **Protected**.

#### POST /api/sboms/{id}/lifecycle/refresh

| Field | Details |
| --- | --- |
| Function Signature | POST /api/sboms/{id}/lifecycle/refresh → `def refresh_sbom_lifecycle(id, force, db)` in `app/routers/sbom_versions.py` |
| Description | Re-runs provider-backed lifecycle enrichment (endoflife.date, npm, PyPI, etc.) for every component of the SBOM. |
| Input Parameters | Path `id: int`; query `force: bool=true` (force refresh, bypass cache) |
| Return Values | Enrichment summary dict from `LifecycleEnrichmentService.enrich_sbom`; 200 |
| Validation and Error Messages | None raised in router (service-level errors propagate to global 500 handler) |

Auth: **Protected**.

#### GET /api/sboms/{id}/lifecycle

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sboms/{id}/lifecycle → `def list_sbom_lifecycle(id, page, page_size, db)` in `app/routers/sbom_versions.py` |
| Description | Paginated lifecycle findings (status, EOL/EOS/EOF dates, recommendations) for the SBOM's non-duplicate components. |
| Input Parameters | Path `id: int`; query `page ≥1` (default 1), `page_size` 1..200 (default 25) — **pagination: offset (in-memory slice)** |
| Return Values | Ad-hoc dict `{sbom_id, page, page_size, total, items: list[component_lifecycle_dict]}`; 200 |
| Validation and Error Messages | 404 `"SBOM not found"` |

Auth: **Protected**.

#### GET /api/sboms/{id}/lifecycle/report

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sboms/{id}/lifecycle/report → `def get_sbom_lifecycle_report(id, format, report_type, db)` in `app/routers/sbom_versions.py` |
| Description | Detailed lifecycle report for export/evidence views. `format=csv` returns a CSV attachment; `format=openeox` returns an OpenEoX JSON attachment; default JSON body. |
| Input Parameters | Path `id: int`; query `format: str="json"` (regex `^(json|csv|openeox)$`), `report_type?: str` ("all, unsupported, eol_eos_eof, or deprecated") |
| Return Values | JSON report dict (200) · `text/csv` attachment `sbom_{id}_lifecycle[{_type}].csv` · `application/json` attachment `sbom_{id}_lifecycle.openeox.json` |
| Validation and Error Messages | 422 auto for format outside the regex; service errors propagate |

Auth: **Protected**.

#### GET /api/sboms/{id}/reports/lifecycle-pack

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sboms/{id}/reports/lifecycle-pack → `def get_lifecycle_report_pack(id, db)` in `app/routers/sbom_versions.py` |
| Description | ZIP bundle download: `lifecycle.json`, `lifecycle.openeox.json`, plus CSVs (all / unsupported / eol_eos_eof / deprecated). |
| Input Parameters | Path `id: int` |
| Return Values | `application/zip` attachment `sbom_{id}_lifecycle_reports.zip`; 200 (file download) |
| Validation and Error Messages | None in router |

Auth: **Protected**.

#### POST /api/sboms/{id}/convert/cyclonedx

| Field | Details |
| --- | --- |
| Function Signature | POST /api/sboms/{id}/convert/cyclonedx → `def convert_spdx_to_cyclonedx_endpoint(id, background_tasks, user_id, db)` in `app/routers/sbom_versions.py` |
| Description | Converts a validated SPDX SBOM to CycloneDX, persists the converted document as a related SBOM record, and schedules post-conversion enrichment. |
| Input Parameters | Path `id: int`; query `user_id?: str` |
| Return Values | `SbomConversionResponse` — `{source_sbom_id, converted_sbom_id, source_format: "SPDX", target_format: "CycloneDX", status/conversion_status: "completed"|"completed_with_warnings", enrichment_status: "pending", message: "Converted to CycloneDX. Lifecycle enrichment is running in background.", warnings[], errors[], conversion_report{}}`; 200 |
| Validation and Error Messages | 404 `"SBOM with ID {id} not found."`; 400 `"SBOM format is '<fmt>'; only SPDX SBOMs can be converted to CycloneDX."`; 400 `"SBOM must pass validation before conversion."`; 400 `str(ValueError)` from converter |

Auth: **Protected**.

#### GET /api/sboms/{id}/conversion-report

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sboms/{id}/conversion-report → `def get_conversion_report(id, db)` in `app/routers/sbom_versions.py` |
| Description | Returns the SPDX→CycloneDX conversion report for an SBOM (from either side of the conversion pair). |
| Input Parameters | Path `id: int` |
| Return Values | `SbomConversionReportResponse` — `{source_format, target_format, converted_at, converted_by, source_sbom_id, converted_sbom_id, conversion_status, enrichment_status, package_count, component_count, mapped_relationships, unmapped_relationships, warnings[], errors[], unmapped_fields[], component_mapping{}, relationship_mapping[], conversion_report{}}`; 200 |
| Validation and Error Messages | 404 `"SBOM with ID {id} not found."`; 404 `"No conversion report found for this SBOM."` |

Auth: **Protected**.

#### GET /api/sboms/{sbom_id}/reports/vulnerabilities.xlsx

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sboms/{sbom_id}/reports/vulnerabilities.xlsx → `def export_sbom_vulnerabilities_excel(sbom_id, include_duplicates, severity, package_name, db)` in `app/routers/sbom_versions.py` |
| Description | Excel export of the SBOM's latest stored vulnerability findings, with optional severity/package filters. |
| Input Parameters | Path `sbom_id: int`; query `include_duplicates: bool=false`, `severity?: str`, `package_name?: str` |
| Return Values | `StreamingResponse`, media type `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`, attachment `sbom-{id}-vulnerability-report.xlsx`; 200 (file download) |
| Validation and Error Messages | 404 with `str(SbomNotFoundError)` |

Auth: **Protected**.

#### GET /api/sboms/{id}/export

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sboms/{id}/export → `def export_sbom(id, format, export_mode, include_duplicates, db)` in `app/routers/sbom_versions.py` |
| Description | Exports the SBOM document: native format, converted CycloneDX (for SPDX-origin rows), lifecycle-enriched, or normalized (Stage-9 dedupe applied to the document). `format=conversion-report` downloads the conversion report JSON. Content is re-validated before export. |
| Input Parameters | Path `id: int`; query `format: str="native"` (native/json/xml/CycloneDX/SPDX/conversion-report + aliases cdx, cyclonedx-json, spdx-json, tag-value), `export_mode: str="original"` (original/converted/enriched/normalized), `include_duplicates: bool=false` |
| Return Values | `Response` with media type per format (`application/vnd.cyclonedx+json`, `application/spdx+json`, `text/spdx`, `application/xml`, `application/json`), `Content-Disposition: attachment; filename="<name>[_converted|_enriched|_original].<ext>"`; 200 (file download) |
| Validation and Error Messages | 400 `"Unsupported export format '<v>'. Supported formats: native, json, xml, CycloneDX, SPDX, conversion-report."`; 400 `"Unsupported export mode '<v>'. Supported modes: converted, enriched, normalized, original."`; 404 `"SBOM with ID {id} has no data."`; 404 `"No conversion report available for this SBOM."`; 404 `"No CycloneDX conversion exists for this SPDX SBOM. Run conversion first."`; 404 `"Converted CycloneDX SBOM not found."`; 400 `"Unsupported SBOM conversion from <a> to <b>. ..."` (three variants); 400 `"Normalized export mode is only supported for JSON formatted SBOMs."`; 400 `"Normalized export mode not supported for standard <std>."`; 422 `"Stored SBOM JSON is invalid: <exc>"`; 422 `"Stored SBOM JSON is invalid and cannot be exported: <exc>"`; 422 `{message: "Stored SBOM failed validation and cannot be exported.", errors[]}` |

Auth: **Protected**.

#### GET /api/sboms/{id}/lifecycle/diagnostics

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sboms/{id}/lifecycle/diagnostics → `def get_sbom_lifecycle_diagnostics(id, db)` in `app/routers/sbom_versions.py` |
| Description | Lifecycle enrichment diagnostics: component/enriched/unknown counts, provider vs cache hit counts, and up to 10 sample unknown / matched components with evidence. |
| Input Parameters | Path `id: int` |
| Return Values | Ad-hoc dict `{component_count, components_enriched, unknown_count, provider_hit_count, cache_hit_count, provider_failure_count, sample_unknown_components[], sample_matched_components[]}`; 200 |
| Validation and Error Messages | 404 `"SBOM not found"` |

Auth: **Protected**.

### Group: SBOM Management — Validation / Repair Workspaces (`app/routers/sbom_validation_sessions.py`)

Canonical prefix `/api/sbom-validation-sessions`. **Every endpoint below is also registered verbatim under two alias prefixes** via `add_api_route` (34 alias registrations, lines 406–440): `/api/validation-sessions/...` (`compat_router`) and `/api/sbom-workspaces/...` (`workspace_router`). Same handler, params, auth, and errors — only the prefix differs. All **Protected**. Common service-level errors (from `app/services/validation_repair_service.py`): 404 `"Validation session not found"`, 403 `"This validation session is not editable"`.

#### GET /api/sbom-validation-sessions/{session_id}

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sbom-validation-sessions/{session_id} → `def get_validation_session(session_id, context, db)` in `app/routers/sbom_validation_sessions.py` |
| Description | Fetch one repair workspace/validation session (tenant-scoped) as a dict. |
| Input Parameters | Path `session_id: str` (UUID-ish string id) |
| Return Values | `session_to_dict(...)` — session id, sbom_name, validation_status, detected_format/version, original/stored size + sha256, total_lines, can_edit, latest_error_report_json, imported_sbom_id, timestamps; 200 |
| Validation and Error Messages | 404 `"Validation session not found"` |

#### GET /api/sbom-validation-sessions/{session_id}/content

| Field | Details |
| --- | --- |
| Function Signature | GET .../{session_id}/content → `def get_validation_session_content(session_id, source, offset, limit, context, db)` in `app/routers/sbom_validation_sessions.py` |
| Description | Byte-chunked read of the session's original or repair-draft content for the repair editor. |
| Input Parameters | Path `session_id: str`; query `source: str="repair_draft"` (regex `^(original|repair_draft|repair)$`), `offset ≥0` (default 0), `limit` 1..1048576 (default 65536) — **pagination: byte offset/limit** |
| Return Values | Chunk dict from `content_chunk_for_source` (content slice + offsets/total); 200 |
| Validation and Error Messages | 404 `"Validation session not found"`; 422 auto for bad source/offset/limit |

#### GET /api/sbom-validation-sessions/{session_id}/content/chunk

| Field | Details |
| --- | --- |
| Function Signature | GET .../{session_id}/content/chunk → `def get_validation_session_content_chunk(...)` in `app/routers/sbom_validation_sessions.py` |
| Description | Exact alias of `/content` (same handler body, kept for older frontend paths). |
| Input Parameters | Identical to `/content` |
| Return Values | Identical to `/content`; 200 |
| Validation and Error Messages | Identical to `/content` |

#### GET /api/sbom-validation-sessions/{session_id}/content-lines

| Field | Details |
| --- | --- |
| Function Signature | GET .../{session_id}/content-lines → `def get_validation_session_content_lines(session_id, source, start_line, line_count, context, db)` in `app/routers/sbom_validation_sessions.py` |
| Description | Line-oriented chunk read (editor virtualisation) of original/repair content. |
| Input Parameters | Path `session_id: str`; query `source` as above, `start_line ≥1` (default 1), `line_count` 1..5000 (default 500) — **pagination: line window** |
| Return Values | Lines dict from `content_lines_for_source`; 200 |
| Validation and Error Messages | 404 `"Validation session not found"`; 422 auto |

#### GET /api/sbom-validation-sessions/{session_id}/content/lines

| Field | Details |
| --- | --- |
| Function Signature | GET .../{session_id}/content/lines → `def get_validation_session_content_lines_alias(...)` in `app/routers/sbom_validation_sessions.py` |
| Description | Exact alias of `/content-lines`. |
| Input Parameters | Identical to `/content-lines` |
| Return Values | Identical; 200 |
| Validation and Error Messages | Identical |

#### GET /api/sbom-validation-sessions/{session_id}/download-original

| Field | Details |
| --- | --- |
| Function Signature | GET .../{session_id}/download-original → `def download_original_validation_session(session_id, context, db)` in `app/routers/sbom_validation_sessions.py` |
| Description | Streams the originally-uploaded file (pre-repair) as an attachment; audit-logged (`sbom.validation_session.download_original`). Filename sanitised against header injection. |
| Input Parameters | Path `session_id: str` |
| Return Values | `StreamingResponse` with stored media type, `Content-Disposition: attachment; filename="<original>"`; 200 (file download) |
| Validation and Error Messages | 404 `"Validation session not found"` |

#### GET /api/sbom-validation-sessions/{session_id}/download-repair-draft

| Field | Details |
| --- | --- |
| Function Signature | GET .../{session_id}/download-repair-draft → `def download_repair_draft_validation_session(session_id, context, db)` in `app/routers/sbom_validation_sessions.py` |
| Description | Streams the current repair draft as an attachment; audit-logged (`sbom.validation_session.download_repair_draft`). |
| Input Parameters | Path `session_id: str` |
| Return Values | `StreamingResponse` attachment; 200 (file download) |
| Validation and Error Messages | 404 `"Validation session not found"` |

#### GET /api/sbom-validation-sessions/{session_id}/search

| Field | Details |
| --- | --- |
| Function Signature | GET .../{session_id}/search → `def search_validation_session(session_id, q, source, limit, context, db)` in `app/routers/sbom_validation_sessions.py` |
| Description | Full-text search inside the session content (original or repair draft) returning match locations for the editor. |
| Input Parameters | Path `session_id: str`; query `q: str` (required, 1..256 chars), `source` as above, `limit` 1..1000 (default 100) |
| Return Values | Match list dict from `service.search`; 200 |
| Validation and Error Messages | 404 `"Validation session not found"`; 422 auto for q length |

#### PATCH /api/sbom-validation-sessions/{session_id}

| Field | Details |
| --- | --- |
| Function Signature | PATCH .../{session_id} → `def update_validation_session(session_id, payload, context, db, x_user_id)` in `app/routers/sbom_validation_sessions.py` |
| Description | Updates session content and/or project assignment (repair editing save path). |
| Input Parameters | Path `session_id: str`; header `X-User-Id?: str`; body `SessionUpdateRequest {current_content?: str, project_id?: int}` |
| Return Values | `session_to_dict(...)`; 200 |
| Validation and Error Messages | 404 `"Validation session not found"`; 403 `"This validation session is not editable"`; 404 `"Project not found"` |

#### PUT /api/sbom-validation-sessions/{session_id}/repair-draft

| Field | Details |
| --- | --- |
| Function Signature | PUT .../{session_id}/repair-draft → `def save_repair_draft(session_id, payload, context, db, x_user_id)` in `app/routers/sbom_validation_sessions.py` |
| Description | Saves the full repair draft with optimistic-concurrency check on `base_version` (session `updated_at`); audit-logged (`sbom.validation_session.repair_draft_saved`). |
| Input Parameters | Path `session_id: str`; header `X-User-Id?`; body `RepairDraftRequest {content: str (required), base_version?: str}` |
| Return Values | `session_to_dict(...)` (with new stored_size_bytes/sha256/total_lines); 200 |
| Validation and Error Messages | 409 `"Repair draft was modified by another request"`; 404/403 as above |

#### POST /api/sbom-validation-sessions/{session_id}/validate

| Field | Details |
| --- | --- |
| Function Signature | POST .../{session_id}/validate → `def validate_session(session_id, strict_ntia, verify_signature, context, db, x_user_id)` in `app/routers/sbom_validation_sessions.py` |
| Description | Re-runs the 8-stage validator against the repair draft; persists a new error report and status; audit-logged (`sbom.validation_session.revalidated`). |
| Input Parameters | Path `session_id: str`; query `strict_ntia: bool=false`, `verify_signature: bool=false`; header `X-User-Id?` |
| Return Values | `session_to_dict(...)` including `validation_status` + latest error report; 200 |
| Validation and Error Messages | 404 `"Validation session not found"` |

#### POST /api/sbom-validation-sessions/{session_id}/revalidate

| Field | Details |
| --- | --- |
| Function Signature | POST .../{session_id}/revalidate → `def revalidate_session(...)` in `app/routers/sbom_validation_sessions.py` |
| Description | Identical behavior to `/validate` (duplicate route kept for naming compat). |
| Input Parameters | Identical to `/validate` |
| Return Values | Identical; 200 |
| Validation and Error Messages | Identical |

#### POST /api/sbom-validation-sessions/{session_id}/import

| Field | Details |
| --- | --- |
| Function Signature | POST .../{session_id}/import → `def import_session(session_id, background_tasks, strict_ntia, verify_signature, project_required, context, db, x_user_id)` in `app/routers/sbom_validation_sessions.py` |
| Description | Imports a repaired (now-passing) session into `sbom_source` as a real SBOM; schedules post-upload enrichment; audit-logged (`sbom.validation_session.imported`). |
| Input Parameters | Path `session_id: str`; query `strict_ntia: bool=false`, `verify_signature: bool=false`, `project_required: bool=false`; header `X-User-Id?` |
| Return Values | `SBOMSourceOut` (the new SBOM row); 200 |
| Validation and Error Messages | 404 `"Validation session not found"`; 400 `"Project assignment is required to import this SBOM"`; 422 `"Cannot import until validation passes"`; 404 `"Project not found"`; 404 `"SBOM type not found"`; 409 `"Failed to import SBOM due to an integrity conflict"`; 500 `"Failed to import repaired SBOM"` |

#### POST /api/sbom-validation-sessions/{session_id}/ai/suggest-fixes

| Field | Details |
| --- | --- |
| Function Signature | POST .../{session_id}/ai/suggest-fixes → `async def suggest_fixes(session_id, payload, context, db, x_user_id)` in `app/routers/sbom_validation_sessions.py` |
| Description | Asks the configured AI provider for repair suggestions (patches) targeting the session's validation errors. Refuses to touch security/signature-stage failures. |
| Input Parameters | Path `session_id: str`; header `X-User-Id?`; body `AiSuggestRequest {user_instruction?: str}` (optional) |
| Return Values | Suggestion payload (proposed patches + rationale) from `service.suggest_fixes`; 200 |
| Validation and Error Messages | 403 `"AI fixes are disabled for this validation session"`; 403 `"AI fixes cannot modify security or signature failures"`; 503 `"No AI provider is configured"`; 503 `"AI provider failed to generate repair suggestions"`; 502 `"AI provider returned malformed repair suggestions"`; 404 session not found |

#### POST /api/sbom-validation-sessions/{session_id}/apply-patch

| Field | Details |
| --- | --- |
| Function Signature | POST .../{session_id}/apply-patch → `def apply_patch(session_id, payload, strict_ntia, verify_signature, context, db, x_user_id)` in `app/routers/sbom_validation_sessions.py` |
| Description | Applies structured (JSON-pointer style) patches to the repair draft, then revalidates. |
| Input Parameters | Path `session_id: str`; query `strict_ntia`, `verify_signature` (bool, default false); header `X-User-Id?`; body `ApplyPatchRequest {patches: list[dict]}` |
| Return Values | `session_to_dict(...)`; 200 |
| Validation and Error Messages | 403 `"This validation session is not editable"`; 404 session not found |

#### POST /api/sbom-validation-sessions/{session_id}/repair/patches

| Field | Details |
| --- | --- |
| Function Signature | POST .../{session_id}/repair/patches → `def apply_line_patches(session_id, payload, context, db, x_user_id)` in `app/routers/sbom_validation_sessions.py` |
| Description | Applies line-level patch operations to the draft (editor diff save); audit-logged (`sbom.validation_session.patch_created`). |
| Input Parameters | Path `session_id: str`; header `X-User-Id?`; body `ApplyLinePatchRequest {patches: list[dict]}` |
| Return Values | `session_to_dict(...)`; 200 |
| Validation and Error Messages | 403 `"This validation session is not editable"`; 422 `"Unsupported line patch operation"`; 404 session not found |

#### GET /api/sbom-validation-sessions/{session_id}/history

| Field | Details |
| --- | --- |
| Function Signature | GET .../{session_id}/history → `def session_history(session_id, context, db)` in `app/routers/sbom_validation_sessions.py` |
| Description | Returns the session's edit/validation history entries. |
| Input Parameters | Path `session_id: str` |
| Return Values | History list from `service.history`; 200 |
| Validation and Error Messages | 404 `"Validation session not found"` |

**Alias routes** (registered with `add_api_route`, not decorators — 34 additional runtime paths): each of the 17 endpoints above also exists as `GET|PATCH|PUT|POST /api/validation-sessions/{session_id}[...]` and `/api/sbom-workspaces/{session_id}[...]` with identical contracts.

### Group: Analysis Runs (`app/routers/runs.py` prefix `/api`; `app/routers/analyze_endpoints.py` no prefix; `app/routers/analysis.py` mounted at `/api/analysis-runs`; `app/routers/compare.py` prefix `/api/v1`)

All **Protected**.

#### GET /api/runs

| Field | Details |
| --- | --- |
| Function Signature | GET /api/runs → `def list_analysis_runs(sbom_id, project_id, product_id, run_status, page, page_size, cursor, response, db)` in `app/routers/runs.py` |
| Description | List analysis runs with filters and dual pagination. LEFT OUTER join to SBOM names so orphaned runs (deleted SBOM) still appear. `run_status` is normalised to canonical ADR-0001 names (legacy PASS/FAIL matched on OK/FINDINGS). Sets `X-Total-Count` / `X-Next-Cursor` headers. |
| Input Parameters | Query: `sbom_id?/project_id?/product_id?: str` (lenient int coercion — empty/NaN/undefined/null treated as unset), `run_status?: str`, `page ≥1` (default 1), `page_size` 1..500 (default 50), `cursor?: int` (keyset id < cursor desc) — **pagination: offset + keyset** |
| Return Values | `list[AnalysisRunOut]` (see key fields in SBOM group); 200 |
| Validation and Error Messages | 422 `[{loc: ["query","int"], msg: "not a valid integer: '<v>'"}]`; 422 `[... msg: "must be >= 1"]`; 422 `"cursor must be >= 1"` |

#### GET /api/runs/aggregate

| Field | Details |
| --- | --- |
| Function Signature | GET /api/runs/aggregate → `def runs_aggregate_endpoint(sbom_id, project_id, db)` in `app/routers/runs.py` |
| Description | One-round-trip aggregate for the Analysis Runs page tiles (total runs, per-outcome buckets, total findings) computed via the metric layer (`app/metrics/runs_aggregate`, Convention C). Declared before `/runs/{run_id}` for path-matching order. |
| Input Parameters | Query `sbom_id?: str`, `project_id?: str` (lenient int coercion) |
| Return Values | `RunsAggregateOut` — `{total_runs, by_outcome: RunsAggregateBuckets {no_issues (OK), with_findings (FINDINGS), source_errors (PARTIAL), failed (ERROR), other}, total_findings}`; 200 |
| Validation and Error Messages | 422 lenient-int messages as above |

#### GET /api/runs/recent

| Field | Details |
| --- | --- |
| Function Signature | GET /api/runs/recent → `def list_recent_runs(limit, db)` in `app/routers/runs.py` |
| Description | Most recent runs (any status) for the compare-picker's default open state (ADR-0008 §5 Region 1), with SBOM/project/product names joined. |
| Input Parameters | Query `limit: int` 1..50 (default 20) |
| Return Values | `list[RunSummary]` — `{id, sbom_id, sbom_name, project_id, project_name, product_id, product_name, run_status (uppercased), completed_on, started_on, total_findings, total_components}`; 200 |
| Validation and Error Messages | 422 auto for limit bounds |

#### GET /api/runs/search

| Field | Details |
| --- | --- |
| Function Signature | GET /api/runs/search → `def search_runs(q, limit, db)` in `app/routers/runs.py` |
| Description | Compare-picker autocomplete: substring match on sbom_name / project_name / product_name, or exact run id when `q` is numeric. Empty `q` behaves like `/runs/recent`. |
| Input Parameters | Query `q: str=""` ("Substring match on sbom_name, project_name, or run id"), `limit` 1..50 (default 20) |
| Return Values | `list[RunSummary]`; 200 |
| Validation and Error Messages | 422 auto for limit bounds |

#### GET /api/runs/{run_id}

| Field | Details |
| --- | --- |
| Function Signature | GET /api/runs/{run_id} → `def get_analysis_run(run_id, db)` in `app/routers/runs.py` |
| Description | Fetch a single run with canonical finding metrics attached (`metrics` computed via `app/metrics/findings.canonical_finding_metrics_for_run`). |
| Input Parameters | Path `run_id: int` |
| Return Values | `AnalysisRunOut` incl. `metrics: dict`; 200 |
| Validation and Error Messages | 404 `"Analysis run not found"` |

#### POST /analyze-sbom-nvd

| Field | Details |
| --- | --- |
| Function Signature | POST /analyze-sbom-nvd → `async def analyze_sbom_nvd(request, payload, idempotency_key, db)` in `app/routers/analyze_endpoints.py` (router has **no prefix** — path is at server root) |
| Description | Legacy ad-hoc NVD-only analysis of an SBOM referenced by id or name. Shares `_run_legacy_analysis`: dedupe → CPE augment → adapter fan-out → `persist_analysis_run` (trigger_source="api"). Rate-limited; Idempotency-Key supported. Returns already-running envelope when a run is active. |
| Input Parameters | Body `AnalysisByRefNVD {sbom_id?: int, sbom_name?: str, results_per_page: int = DEFAULT_RESULTS_PER_PAGE}`; header `Idempotency-Key?` |
| Return Values | Flat `AnalysisRunOut`-shaped dict + legacy `summary.findings.bySeverity` block; or `{status: "already_running", message: "Analysis is already running for this SBOM.", run_id, ...counts}`; 200 |
| Validation and Error Messages | 422 `"Provide 'sbom_id' or 'sbom_name' in request body"`; 404 `str(ValueError)` from SBOM loader (missing/invalid SBOM); 400 `"No components detected in SBOM."`; 400 `"No supported sources requested. Got [...]"`; 429 rate limit |

#### POST /analyze-sbom-github

| Field | Details |
| --- | --- |
| Function Signature | POST /analyze-sbom-github → `async def analyze_sbom_github(request, payload, idempotency_key, db)` in `app/routers/analyze_endpoints.py` |
| Description | Legacy ad-hoc GitHub Security Advisory (GHSA) analysis by SBOM id/name; same shared runner and semantics as NVD variant. |
| Input Parameters | Body `AnalysisByRefGitHub {sbom_id?: int, sbom_name?: str, first: int = 100}`; header `Idempotency-Key?` |
| Return Values | Same envelope as `/analyze-sbom-nvd`; 200 |
| Validation and Error Messages | Same as `/analyze-sbom-nvd` |

#### POST /analyze-sbom-osv

| Field | Details |
| --- | --- |
| Function Signature | POST /analyze-sbom-osv → `async def analyze_sbom_osv(request, payload, idempotency_key, db)` in `app/routers/analyze_endpoints.py` |
| Description | Legacy ad-hoc OSV analysis by SBOM id/name. |
| Input Parameters | Body `AnalysisByRefOSV {sbom_id?: int, sbom_name?: str, hydrate: bool = true}`; header `Idempotency-Key?` |
| Return Values | Same envelope; 200 |
| Validation and Error Messages | Same as `/analyze-sbom-nvd` |

#### POST /analyze-sbom-vulndb

| Field | Details |
| --- | --- |
| Function Signature | POST /analyze-sbom-vulndb → `async def analyze_sbom_vulndb(request, payload, idempotency_key, db)` in `app/routers/analyze_endpoints.py` |
| Description | Legacy ad-hoc VulDB/VulnDB analysis by SBOM id/name; requires the VulnDB credential to be configured. |
| Input Parameters | Body `AnalysisByRefVulnDb {sbom_id?: int, sbom_name?: str}`; header `Idempotency-Key?` |
| Return Values | Same envelope; 200 |
| Validation and Error Messages | Same as `/analyze-sbom-nvd` plus 400 `"VULNDB_API_KEY is required for VulDB-only analysis."` |

#### POST /analyze-sbom-consolidated

| Field | Details |
| --- | --- |
| Function Signature | POST /analyze-sbom-consolidated → `async def analyze_sbom_consolidated(request, payload, idempotency_key, db)` in `app/routers/analyze_endpoints.py` |
| Description | Legacy ad-hoc combined NVD + GHSA + OSV + VulDB analysis by SBOM id/name. |
| Input Parameters | Body `AnalysisByRefConsolidated {sbom_id?: int, sbom_name?: str, results_per_page: int, first: int = 100, osv_hydrate: bool = true}`; header `Idempotency-Key?` |
| Return Values | Same envelope; 200 |
| Validation and Error Messages | Same as `/analyze-sbom-nvd` |

#### GET /api/analysis-runs/compare  **[DEPRECATED]**

| Field | Details |
| --- | --- |
| Function Signature | GET /api/analysis-runs/compare → `def compare_analysis_runs(response, run_a, run_b, db)` in `app/routers/analysis.py` (router mounted with prefix `/api/analysis-runs` in `app/main.py:893`) |
| Description | **Deprecated** v1 run diff by `vuln_id` set (ADR-0008 successor: `POST /api/v1/compare`). Emits RFC 9745/8594 headers on every response: `Deprecation: true`, `Sunset: Wed, 31 Dec 2026 23:59:59 GMT`, `Link: </api/v1/compare>; rel="successor-version"`; increments an in-process telemetry counter + WARNING log. Known identity-collision bug intentionally left (fixed only in v2). |
| Input Parameters | Query `run_a: int` (required, "First run ID"), `run_b: int` (required) |
| Return Values | Ad-hoc dict `{run_a: {id, sbom_name, completed_on}, run_b: {...}, new_findings[], resolved_findings[], common_findings[], severity_delta {critical, high, medium, low}}`; 200 |
| Validation and Error Messages | 404 `{error_code: "COMPARE_V1_E001_RUN_NOT_FOUND", message: "Run <id> not found", run_id, retryable: false}` (either run); 409 `{error_code: "COMPARE_V1_E002_RUN_NOT_READY", message: "Run <id> status=<STATUS> is not comparable", run_id, status, retryable: true}` when either run is not in `COMPARABLE_RUN_STATUSES` |

#### POST /api/v1/compare

| Field | Details |
| --- | --- |
| Function Signature | POST /api/v1/compare → `def compare_runs(request, body, db)` in `app/routers/compare.py` |
| Description | v2 run diff (ADR-0008): per-finding events with attribution, posture deltas, and component diffs. Cache-backed (`compare_cache`, keyed by sha256 of the run-id pair) — reads fresh cache, computes when stale. Rate limited `30/minute`. |
| Input Parameters | Body `CompareRequest {run_a_id: int (>0), run_b_id: int (>0)}` (extra fields forbidden) |
| Return Values | `CompareResult` — `{cache_key (64-hex), run_a/run_b: RunSummary, relationship: RunRelationship {same_project, same_sbom, days_between}, posture: PostureDelta, findings: list[FindingDiffRow], components: list[ComponentDiffRow], computed_at, schema_version}`; 200 |
| Validation and Error Messages | Structured envelope `{error_code, message, retryable}` from `CompareError` mapping: `RunNotFoundError` (404, + run_id), `RunNotReadyError` (409, + run_id/status, retryable true), `SameRunError` (400/409 per `exc.http_status`); 422 auto for non-positive ids; 429 rate limit |

Auth: **Protected**.

#### POST /api/v1/compare/{cache_key}/export

| Field | Details |
| --- | --- |
| Function Signature | POST /api/v1/compare/{cache_key}/export → `def export_compare(request, cache_key, body, db)` in `app/routers/compare.py` |
| Description | Re-serialises a cached compare result into markdown, CSV, or JSON download. Cache-only — never recomputes. Rate limited `10/minute`. Corrupt cache rows are deleted on read. |
| Input Parameters | Path `cache_key: str` (64-char hex); body `CompareExportRequest {format: "markdown"|"csv"|"json"}` |
| Return Values | `Response` attachment (media type per format), `Content-Disposition: attachment; filename="..."`; 200 (file download) |
| Validation and Error Messages | 400 `{error_code: ERR_COMPARE_BAD_REQUEST, message: "cache_key must be a 64-char hex string", retryable: false}`; 404 `{error_code: "COMPARE_E006_CACHE_MISS", message: "compare result not in cache; re-run POST /api/v1/compare first", retryable: true}`; 503 `{error_code: "COMPARE_E007_CACHE_CORRUPT", message: "cached compare result was corrupt and has been discarded; re-run POST /api/v1/compare", retryable: true}`; 429 rate limit |

Auth: **Protected**.

---

### Group: Findings (findings listing in `app/routers/runs.py`; remediation tracking in `app/routers/remediation.py`; VEX in `app/routers/vex.py`)

All **Protected**.

#### GET /api/runs/{run_id}/findings

| Field | Details |
| --- | --- |
| Function Signature | GET /api/runs/{run_id}/findings → `def list_run_findings(run_id, severity, page, page_size, response, db)` in `app/routers/runs.py` |
| Description | Paged findings for a run via the canonical metric layer (`canonical_findings_for_run` + `canonicalize_finding_rows`), optional severity filter, each row joined with its project-level remediation record (default `{status: "Open"}` stub when none). Headers `X-Total-Count`, `X-Unfiltered-Total-Count`. |
| Input Parameters | Path `run_id: int`; query `severity?: str` (normalised uppercase), `page ≥1` (default 1), `page_size` 1..1000 (default 100) — **pagination: offset (in-memory)** |
| Return Values | `list[AnalysisFindingOut]` — `{id, analysis_run_id, component_id, vuln_id, source, title, description, severity, score, vector, published_on, reference_url, cwe, cpe, component_name, component_version, fixed_versions (raw JSON str), attack_vector, cvss_version, aliases (JSON str), remediation: VulnerabilityRemediationOut|stub}`; 200 |
| Validation and Error Messages | 404 `"Analysis run not found"` |

#### GET /api/runs/{run_id}/findings-enriched

| Field | Details |
| --- | --- |
| Function Signature | GET /api/runs/{run_id}/findings-enriched → `def list_run_findings_enriched(run_id, severity, page, page_size, response, db)` in `app/routers/runs.py` |
| Description | Same surface as `/findings` but each row enriched with per-CVE exploit-likelihood signals: `in_kev` (CISA KEV), `epss` + `epss_percentile` (max across CVE aliases), composite `risk_score = cvss × (1 + EPSS_AMPLIFIER·epss) × KEV_MULTIPLIER`, `cve_aliases`. KEV/EPSS lookups batched and memoized (24h DB cache + 60s in-process). |
| Input Parameters | Same as `/findings` |
| Return Values | `list[dict]` (AnalysisFindingOut fields + `in_kev: bool, epss: float, epss_percentile: float|null, risk_score: float, cve_aliases: list[str], remediation`); headers `X-Total-Count`, `X-Unfiltered-Total-Count`; 200 |
| Validation and Error Messages | 404 `"Analysis run not found"` |

#### GET /api/remediation/project/{project_id}

| Field | Details |
| --- | --- |
| Function Signature | GET /api/remediation/project/{project_id} → `def get_project_remediations(project_id, db)` in `app/routers/remediation.py` |
| Description | All remediation tracking records for a project. |
| Input Parameters | Path `project_id: int` |
| Return Values | `list[VulnerabilityRemediationOut]` — `{id, project_id, vuln_id, component_name, component_version, status, owner, due_date, resolution_date, fix_notes, fixed_version, updated_on, ...}`; 200 |
| Validation and Error Messages | None raised in router |

#### GET /api/remediation/finding/{finding_id}

| Field | Details |
| --- | --- |
| Function Signature | GET /api/remediation/finding/{finding_id} → `def get_finding_remediation(finding_id, db)` in `app/routers/remediation.py` |
| Description | Resolves the remediation record for one finding (looked up by project + vuln_id + component name/version). |
| Input Parameters | Path `finding_id: int` |
| Return Values | `VulnerabilityRemediationOut`; 200 |
| Validation and Error Messages | 404 `"Finding with ID {finding_id} not found."`; 400 `"Finding is not associated with a project."`; 404 `"No remediation record found for this finding."` |

#### GET /api/remediation/{remediation_id}/history

| Field | Details |
| --- | --- |
| Function Signature | GET /api/remediation/{remediation_id}/history → `def get_remediation_history(remediation_id, db)` in `app/routers/remediation.py` |
| Description | Append-only change history (audit rows) for a remediation record. |
| Input Parameters | Path `remediation_id: int` |
| Return Values | `list[VulnerabilityRemediationAuditOut]`; 200 (empty list allowed if record exists) |
| Validation and Error Messages | 404 `"Remediation record with ID {remediation_id} not found."` |

#### POST /api/remediation

| Field | Details |
| --- | --- |
| Function Signature | POST /api/remediation → `def upsert_remediation(payload, project_id, user_id, db)` in `app/routers/remediation.py` |
| Description | Create-or-update a remediation tracking record (status, owner, due date, fix notes, fixed version) for a vulnerability within a project. |
| Input Parameters | Query `project_id: int` (required), `user_id?: str`; body `VulnerabilityRemediationUpsert` (vuln_id, component_name, component_version, status, owner, due_date, fix_notes, fixed_version, ...; `exclude_unset` applied) |
| Return Values | `VulnerabilityRemediationOut`; 200 |
| Validation and Error Messages | 400 with `str(ValueError)` from `create_or_update_remediation` |

#### POST /api/sboms/{sbom_id}/vex

| Field | Details |
| --- | --- |
| Function Signature | POST /api/sboms/{sbom_id}/vex → `def upload_vex_document(sbom_id, payload, context, db)` in `app/routers/vex.py` (router has no prefix; paths declared absolute) |
| Description | Imports a CycloneDX-VEX / OpenVEX-style exploitability document and stores per-vulnerability statements for the SBOM. |
| Input Parameters | Path `sbom_id: int`; body free-form `dict` — `{document?: dict (or the document itself), source_type?: str="uploaded", source_name?: str="Uploaded VEX", source_url?, author?, uploaded_by?}` |
| Return Values | Import summary from `import_vex_document` (statement counts); 200 |
| Validation and Error Messages | None in router; service-level errors propagate |

#### GET /api/sboms/{sbom_id}/vex

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sboms/{sbom_id}/vex → `def get_vex_statements(sbom_id, db)` in `app/routers/vex.py` |
| Description | Lists stored VEX statements for an SBOM. |
| Input Parameters | Path `sbom_id: int` |
| Return Values | Statement list from `list_vex_statements`; 200 |
| Validation and Error Messages | None in router |

#### GET /api/sboms/{sbom_id}/vex/report

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sboms/{sbom_id}/vex/report → `def get_vex_report(sbom_id, format, report_type, db)` in `app/routers/vex.py` |
| Description | Detailed VEX evidence report; JSON body or CSV attachment (`sbom_{id}_vex[{_type}].csv`). `report_type` filters by status (unrecognised values are ignored → unfiltered). |
| Input Parameters | Path `sbom_id: int`; query `format: str="json"` (regex `^(json|csv)$`), `report_type?: str` (affected, not_affected, fixed, under_investigation, unknown, remediation_action) |
| Return Values | JSON report dict (200) or `text/csv` attachment |
| Validation and Error Messages | 422 auto for format regex |

#### GET /api/sboms/{sbom_id}/reports/vex-pack

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sboms/{sbom_id}/reports/vex-pack → `def get_vex_report_pack(sbom_id, db)` in `app/routers/vex.py` |
| Description | ZIP download bundling `vex.json` + per-status CSVs (affected / not_affected / fixed / under_investigation / unknown / remediation_action). |
| Input Parameters | Path `sbom_id: int` |
| Return Values | `application/zip` attachment `sbom_{id}_vex_reports.zip`; 200 (file download) |
| Validation and Error Messages | None in router |

#### POST /api/sboms/{sbom_id}/vex/discover

| Field | Details |
| --- | --- |
| Function Signature | POST /api/sboms/{sbom_id}/vex/discover → `def discover_vex_documents(sbom_id, force, db)` in `app/routers/vex.py` |
| Description | Discovers and imports vendor-hosted VEX documents for the SBOM's components (non-blocking with respect to upload). |
| Input Parameters | Path `sbom_id: int`; query `force: bool=false` |
| Return Values | Discovery/import summary dict; 200 |
| Validation and Error Messages | None in router |

#### PATCH /api/components/{component_id}/vulnerabilities/{vulnerability_id}/vex-override

| Field | Details |
| --- | --- |
| Function Signature | PATCH /api/components/{component_id}/vulnerabilities/{vulnerability_id}/vex-override → `def patch_vex_override(component_id, vulnerability_id, payload, context, db)` in `app/routers/vex.py` |
| Description | Applies an audited manual VEX override (status/justification/impact/action/fixed_version/mitigation) for one component+vulnerability pair. |
| Input Parameters | Path `component_id: int`, `vulnerability_id: str`; body free-form dict incl. `updated_by`/`changed_by` |
| Return Values | Statement dict `{id, component_id, vulnerability_id, status, justification, impact_statement, action_statement, fixed_version, mitigation, source_name, source_url, confidence, created_at}`; 200 |
| Validation and Error Messages | Service-level errors propagate |

#### GET /api/components/{component_id}/vulnerabilities/{vulnerability_id}/vex-override/history

| Field | Details |
| --- | --- |
| Function Signature | GET .../vex-override/history → `def get_vex_override_history(component_id, vulnerability_id, db)` in `app/routers/vex.py` |
| Description | Audit history of manual VEX overrides for a component+vulnerability pair. |
| Input Parameters | Path `component_id: int`, `vulnerability_id: str` |
| Return Values | `{component_id, vulnerability_id, history: [{id, old_value, new_value, reason, evidence_url, changed_by, changed_at}]}`; 200 |
| Validation and Error Messages | None in router |

---

### Group: Export and Reporting (`app/routers/analysis.py` mounted at `/api/analysis-runs`; `app/routers/pdf.py` prefix `/api`; `app/routers/reports.py` prefix `/api/projects`)

All **Protected**. (SBOM-document export, Excel vulnerability report, lifecycle/VEX packs are documented in their owning groups above.)

#### GET /api/analysis-runs/{run_id}/export/sarif

| Field | Details |
| --- | --- |
| Function Signature | GET /api/analysis-runs/{run_id}/export/sarif → `def export_sarif(run_id, db)` in `app/routers/analysis.py` |
| Description | Exports run findings as SARIF 2.1.0 (GitHub Code Scanning / VS Code / Azure DevOps). Severity→level mapping CRITICAL/HIGH→error, MEDIUM→warning, LOW→note. Includes provenance properties (`match_strategy`, `match_reason`, `matched_range`, `match_confidence`) and `cve_aliases`. |
| Input Parameters | Path `run_id: int` |
| Return Values | `application/json` attachment `sbom_findings_{run_id}.sarif` (SARIF `$schema` 2.1.0, tool driver "SBOM-Analyzer"); 200 (file download) |
| Validation and Error Messages | 404 `"Analysis run not found"` |

#### GET /api/analysis-runs/{run_id}/export/csv

| Field | Details |
| --- | --- |
| Function Signature | GET /api/analysis-runs/{run_id}/export/csv → `def export_csv(run_id, db)` in `app/routers/analysis.py` |
| Description | Exports all findings of a run as CSV ordered by score desc; 19 columns incl. cve aliases (semicolon-joined), purl, provenance columns appended at the end for back-compat. |
| Input Parameters | Path `run_id: int` |
| Return Values | `text/csv` attachment `sbom_findings_{run_id}.csv`; 200 (file download) |
| Validation and Error Messages | 404 `"Analysis run not found"` |

#### POST /api/pdf-report

| Field | Details |
| --- | --- |
| Function Signature | POST /api/pdf-report → `async def create_pdf_report_by_run_id(payload, db)` in `app/routers/pdf.py` |
| Description | Generates a PDF vulnerability report for a run and returns it as a download. Tries the `RunCache` first, falls back to reconstructing a consolidated-style run dict from `AnalysisRun` + `AnalysisFinding` rows. `.pdf` extension is appended if missing. |
| Input Parameters | Body `PdfReportByIdRequest {runId: int, title?: str = "SBOM Vulnerability Report", filename?: str = "sbom_report.pdf"}` (defined in the router) |
| Return Values | `Response` media type `application/pdf`, `Content-Disposition: attachment; filename="<name>.pdf"`; 200 (file download) |
| Validation and Error Messages | 404 `"Run {run_id} not found."`; 500 `{code: "internal_error", message: "Internal server error."}` on PDF generation failure |

Auth: **Protected**.

#### POST /api/projects/{project_id}/reports/fda-510k-sbom/export

| Field | Details |
| --- | --- |
| Function Signature | POST /api/projects/{project_id}/reports/fda-510k-sbom/export → `def export_fda_510k_sbom_report(project_id, payload, request, context, db)` in `app/routers/reports.py` |
| Description | Builds and downloads the final FDA 510(k) SBOM Excel workbook for selected project SBOMs (findings + lifecycle run selections per SBOM). Audit-logged (`report.fda_510k_sbom.export`). |
| Input Parameters | Path `project_id: int`; body `Fda510kReportExportRequest {selections: list[Fda510kReportSelectionIn {sbom_id: int>0, findings_analysis_run_id?: int>0, lifecycle_analysis_run_id?: int>0}] (min 1), metadata: Fda510kReportMetadataIn {device_name*, manufacturer_sponsor*, device_software_version*, author_of_sbom_data*, prepared_by* (required non-blank via validator "Required final-report metadata is missing."), submission_type = "510(k)", submission_number?, product_code_regulation_number?, sbom_version?, date_prepared?, reviewed_approved_by?, date_approved?, ...}}` |
| Return Values | `StreamingResponse` Excel media type (`application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`) attachment; 200 (file download) |
| Validation and Error Messages | 409 with `Fda510kIncompleteAnalysisError.detail()` (structured: SBOMs missing required completed analyses); 400 `str(Fda510kReportError)`; 422 validator `"Required final-report metadata is missing."` |

Auth: **Protected**.

---

### Group: Administration — Projects and Products (`app/routers/projects.py` prefix `/api`; `app/routers/products.py` prefix `/api`)

All **Protected**.

#### POST /api/projects

| Field | Details |
| --- | --- |
| Function Signature | POST /api/projects → `def create_project(payload, context, db)` in `app/routers/projects.py` |
| Description | Creates a project; enforces globally unique `project_name`. |
| Input Parameters | Body `ProjectCreate {project_name: str (required), project_details?: str, project_status: int|str = 1 (1/'Active' or 0/'Inactive', coerced), created_by?: str}` |
| Return Values | `ProjectOut` — `{id, project_name, project_details, project_status (1/0), created_on, created_by, modified_on, modified_by, sbom_count}`; **201 Created** |
| Validation and Error Messages | 400 `"Project with this name already exists"`; 400 `"Duplicate project name not allowed"` (IntegrityError); 500 `{code: "internal_error", message: "Internal server error."}` |

#### GET /api/projects/{project_id}

| Field | Details |
| --- | --- |
| Function Signature | GET /api/projects/{project_id} → `def get_project_details(project_id, context, db)` in `app/routers/projects.py` |
| Description | Fetch one project (tenant-scoped). |
| Input Parameters | Path `project_id: int (>0)` |
| Return Values | `ProjectOut`; 200 |
| Validation and Error Messages | 422 `"'id' must be a positive integer (>= 1)."`; 404 `"Project not found"`; 500 `"Internal database error while fetching project details."` |

#### GET /api/projects

| Field | Details |
| --- | --- |
| Function Signature | GET /api/projects → `def list_projects(db)` in `app/routers/projects.py` |
| Description | Lists all projects ordered by id desc (no pagination, no tenant filter in handler — tenant scoping applied by model-level query hooks). |
| Input Parameters | None |
| Return Values | `list[ProjectOut]`; 200 |
| Validation and Error Messages | None raised |

#### PATCH /api/projects/{project_id}

| Field | Details |
| --- | --- |
| Function Signature | PATCH /api/projects/{project_id} → `def update_project(project_id, payload, context, db)` in `app/routers/projects.py` |
| Description | Partial project update (name, details, status); stamps modified_on/by. |
| Input Parameters | Path `project_id: int (>0)`; body `ProjectUpdate {project_name?, project_details?, project_status?: int|str, modified_by?}` (exclude_unset + exclude_none) |
| Return Values | `ProjectOut`; 200 |
| Validation and Error Messages | 422 positive-int; 422 `"No updatable fields provided in payload."`; 404 `"Project not found"`; 500 `"Internal database error while updating project."` |

#### GET /api/projects/{project_id}/delete-impact

| Field | Details |
| --- | --- |
| Function Signature | GET /api/projects/{project_id}/delete-impact → `def project_delete_impact(project_id, db)` in `app/routers/projects.py` |
| Description | Pre-flight cascade preview for the delete-confirmation modal: counts of active dependent SBOMs, components, runs, findings, schedules. |
| Input Parameters | Path `project_id: int (ge=1)` |
| Return Values | `{project_id, project_name, sboms, components, runs, findings, schedules}`; 200 |
| Validation and Error Messages | 404 `"Project not found"` |

#### DELETE /api/projects/{project_id}

| Field | Details |
| --- | --- |
| Function Signature | DELETE /api/projects/{project_id} → `def delete_project(project_id, confirm, permanent, context, db)` in `app/routers/projects.py` |
| Description | Two-phase delete like SBOM delete. Unconfirmed → `pending_confirmation` payload. Soft delete cascades tombstones through the ownership tree; permanent delete manually walks findings→runs→components→analysis-reports→SBOMs then hard-deletes the project. Audit-logged (`project.soft_delete` / `project.permanent_delete`). |
| Input Parameters | Path `project_id: int`; query `confirm: str="no"` ("Set to 'yes' to confirm deletion"), `permanent: bool=false` |
| Return Values | 200 with `{status: "pending_confirmation", message: "This will delete the Project. Re-send with confirm=yes to proceed (and add permanent=true to bypass soft delete).", example}` or `{status: "deleted", permanent, cascaded_count?, message: "Project <id> moved to deleted (recoverable)." | "Project <id> permanently deleted."}` |
| Validation and Error Messages | 404 `"Project not found"`; 500 `"Internal database error during permanent delete."`; 500 `"Internal database error during soft delete."` |

#### POST /api/projects/{project_id}/restore

| Field | Details |
| --- | --- |
| Function Signature | POST /api/projects/{project_id}/restore → `def restore_project(project_id, user_id, db)` in `app/routers/projects.py` |
| Description | Restores a soft-deleted project (non-cascading; children restored individually). Audit-logged (`project.restore`). |
| Input Parameters | Path `project_id: int (ge=1)`; query `user_id?: str` |
| Return Values | `{status: "restored", id}` or `{status: "already_active", id}`; 200 |
| Validation and Error Messages | 404 `"Project not found"` |

#### POST /api/projects/{project_id}/products

| Field | Details |
| --- | --- |
| Function Signature | POST /api/projects/{project_id}/products → `def create_product(payload, project_id, context, db)` in `app/routers/products.py` |
| Description | Creates a product under a project with normalized-name uniqueness per project and auto-generated unique slug. Audit-logged (`product.created`). |
| Input Parameters | Path `project_id: int (ge=1)`; body `ProductCreate {name: str 1..255 (required), description?, product_key?, vendor?, category?, status?: str="active", latest_version?, metadata_json?: dict}` |
| Return Values | `ProductRead` — `{id, tenant_id, project_id, name, normalized_name, slug, description, product_key, vendor, category, status, latest_version, metadata_json, created_by, created_at, updated_at, is_active, deleted_at, sbom_count, latest_sbom_id, latest_sbom_version}`; **201 Created** |
| Validation and Error Messages | 404 `"Project not found"`; 409 `"Product name already exists in this project"` |

#### GET /api/projects/{project_id}/products

| Field | Details |
| --- | --- |
| Function Signature | GET /api/projects/{project_id}/products → `def list_project_products(project_id, context, db)` in `app/routers/products.py` |
| Description | Lists active products of a project (name asc) with per-product SBOM counts and latest-SBOM info. |
| Input Parameters | Path `project_id: int (ge=1)` |
| Return Values | `ProductListResponse {items: list[ProductSummary {id, project_id, name, slug, description, vendor, category, status, sbom_count, latest_sbom_id, latest_sbom_version}], total}`; 200 |
| Validation and Error Messages | 404 `"Project not found"` |

#### GET /api/products/{product_id}

| Field | Details |
| --- | --- |
| Function Signature | GET /api/products/{product_id} → `def get_product(product_id, context, db)` in `app/routers/products.py` |
| Description | Fetch one product (tenant-scoped) with summary counts. |
| Input Parameters | Path `product_id: int (ge=1)` |
| Return Values | `ProductRead`; 200 |
| Validation and Error Messages | 404 `"Product not found"` |

#### PATCH /api/products/{product_id}

| Field | Details |
| --- | --- |
| Function Signature | PATCH /api/products/{product_id} → `def update_product(payload, product_id, context, db)` in `app/routers/products.py` |
| Description | Partial product update; renames re-check uniqueness and regenerate slug. Audit-logged (`product.updated`). |
| Input Parameters | Path `product_id: int (ge=1)`; body `ProductUpdate` (all optional: name 1..255, description, product_key, vendor, category, status, latest_version, metadata_json) |
| Return Values | `ProductRead`; 200 |
| Validation and Error Messages | 404 `"Product not found"`; 409 `"Product name already exists in this project"` |

#### DELETE /api/products/{product_id}

| Field | Details |
| --- | --- |
| Function Signature | DELETE /api/products/{product_id} → `def delete_product(product_id, context, db)` in `app/routers/products.py` |
| Description | Soft-deactivates a product (is_active=false + deleted_at) — refused while active SBOMs reference it. Audit-logged (`product.deleted`). |
| Input Parameters | Path `product_id: int (ge=1)` |
| Return Values | `{status: "deleted", product_id}`; 200 |
| Validation and Error Messages | 404 `"Product not found"`; 409 `"Product has SBOMs. Move SBOMs before deleting the product."` |

#### GET /api/products/{product_id}/sboms

| Field | Details |
| --- | --- |
| Function Signature | GET /api/products/{product_id}/sboms → `def list_product_sboms(product_id, context, db)` in `app/routers/products.py` |
| Description | Lists active SBOMs belonging to a product, newest first. |
| Input Parameters | Path `product_id: int (ge=1)` |
| Return Values | `list[SBOMSourceOut]`; 200 |
| Validation and Error Messages | 404 `"Product not found"` |

---

### Group: Dashboard (`app/routers/dashboard_main.py` prefix `/dashboard`; `app/routers/dashboard_advanced.py` prefix `/dashboard`; `app/routers/dashboard.py` mounted at `/dashboard`)

All **Protected**; all GET. Note: these paths have **no `/api` prefix**. Every numeric comes from the metric layer (`app/metrics/`), per the CLAUDE.md conventions. Several endpoints support conditional requests via `maybe_not_modified` (`app/etag.py`): they set `ETag` + `Cache-Control: private, max-age=5` and return **304** on `If-None-Match` hit (marked "ETag/304" below).

#### GET /dashboard/stats

| Field | Details |
| --- | --- |
| Function Signature | GET /dashboard/stats → `def dashboard_stats(request, response, db)` in `app/routers/dashboard_main.py` |
| Description | Home-dashboard KPI counts (locked definitions in `docs/dashboard-metrics-spec.md` §3). ETag/304. |
| Input Parameters | None |
| Return Values | `{total_active_projects, total_sboms, total_findings, total_distinct_vulnerabilities}` + backwards-compat aliases; 200 or 304 |
| Validation and Error Messages | None raised |

#### GET /dashboard/recent-sboms

| Field | Details |
| --- | --- |
| Function Signature | GET /dashboard/recent-sboms → `def dashboard_recent_sboms(limit, db)` in `app/routers/dashboard_main.py` |
| Description | Most recently uploaded SBOMs for the home dashboard list. |
| Input Parameters | Query `limit: int` 1..50 (default 5) |
| Return Values | `list[{id, sbom_name, created_on}]`; 200 |
| Validation and Error Messages | 422 auto for limit bounds |

#### GET /dashboard/activity

| Field | Details |
| --- | --- |
| Function Signature | GET /dashboard/activity → `def dashboard_activity(request, response, db)` in `app/routers/dashboard_main.py` |
| Description | Active (uploaded in last 30 days) vs stale SBOM counts for the activity doughnut. ETag/304. |
| Input Parameters | None |
| Return Values | `{active_30d, stale}`; 200 or 304 |
| Validation and Error Messages | None raised |

#### GET /dashboard/severity

| Field | Details |
| --- | --- |
| Function Signature | GET /dashboard/severity → `def dashboard_severity(request, response, db)` in `app/routers/dashboard_main.py` |
| Description | Severity distribution scoped to latest-successful-run-per-SBOM (Convention A). UNKNOWN returned separately (not a severity tier, ADR-0001). ETag/304. |
| Input Parameters | None |
| Return Values | Severity buckets dict `{CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN}`; 200 or 304 |
| Validation and Error Messages | None raised |

#### GET /dashboard/posture

| Field | Details |
| --- | --- |
| Function Signature | GET /dashboard/posture → `def dashboard_posture(request, response, db)` in `app/routers/dashboard_main.py` |
| Description | Single-round-trip posture envelope for the v2 hero: severity distribution, KEV count (alias-aware), high-EPSS count, total/distinct findings, `net_7day` deltas with `is_first_period`, server-computed `headline_state` / `primary_action`. v1 fields preserved. ETag/304. |
| Input Parameters | None |
| Return Values | `DashboardPostureResponse` (`app/schemas_dashboard.py`) — severity buckets, kev_count, high_epss_count, total_findings, distinct_vulnerabilities, net_7day, headline_state, primary_action, ...; 200 or 304 |
| Validation and Error Messages | None raised |

#### GET /dashboard/vulnerability-age

| Field | Details |
| --- | --- |
| Function Signature | GET /dashboard/vulnerability-age → `def dashboard_vulnerability_age(period, date_from, date_to, db)` in `app/routers/dashboard_main.py` |
| Description | "Vulnerability by Age" pie: findings in latest-run scope bucketed by CVE age; `period` narrows the scan-date observation window (rolling day/week/month/year, or custom ISO bounds). |
| Input Parameters | Query `period: Literal["all","day","week","month","year","custom"]="all"`, `date_from?: str` (ISO, custom only), `date_to?: str` |
| Return Values | `VulnerabilityAgeResponse` — `{buckets: {…age buckets…}, total, period, ...}`; 200 |
| Validation and Error Messages | 422 auto for period outside the Literal set |

#### GET /dashboard/lifetime

| Field | Details |
| --- | --- |
| Function Signature | GET /dashboard/lifetime → `def dashboard_lifetime(request, response, db)` in `app/routers/dashboard_main.py` |
| Description | Cumulative "Your Analyzer, So Far" metrics (Convention B/C growth counters), in-process cached 15 min keyed by (max run id, run count, sbom count). Adds `runs_completed_total` and `runs_distinct_dates`. ETag/304. |
| Input Parameters | None |
| Return Values | `LifetimeMetrics` (schemas_dashboard) + `runs_completed_total`, `runs_distinct_dates`; 200 or 304 |
| Validation and Error Messages | None raised |

#### GET /dashboard/lifecycle

| Field | Details |
| --- | --- |
| Function Signature | GET /dashboard/lifecycle → `def get_dashboard_lifecycle(db)` in `app/routers/dashboard_main.py` |
| Description | Component lifecycle metrics tile (EOL / upcoming EOS / unsupported / stale counts + summary). |
| Input Parameters | None |
| Return Values | `{...lifecycle_summary, eol_components, eos_upcoming, unsupported, stale_count}`; 200 |
| Validation and Error Messages | None raised |

#### GET /dashboard/vex

| Field | Details |
| --- | --- |
| Function Signature | GET /dashboard/vex → `def get_dashboard_vex(db)` in `app/routers/dashboard_main.py` |
| Description | VEX exploitability rollup for the dashboard (`vex_dashboard_summary`). |
| Input Parameters | None |
| Return Values | VEX summary dict (statement/status counts); 200 |
| Validation and Error Messages | None raised |

#### GET /dashboard/health

| Field | Details |
| --- | --- |
| Function Signature | GET /dashboard/health → `def get_dashboard_health(db)` in `app/routers/dashboard_main.py` |
| Description | SBOM data-health tile: average completeness score, missing-metadata count, outdated-components count. (Not a liveness probe — see `/health`.) |
| Input Parameters | None |
| Return Values | `{completeness_score, missing_metadata, outdated_components}`; 200 |
| Validation and Error Messages | None raised |

#### GET /dashboard/remediation-stats

| Field | Details |
| --- | --- |
| Function Signature | GET /dashboard/remediation-stats → `def get_dashboard_remediation_stats(db)` in `app/routers/dashboard_main.py` |
| Description | Remediation progress tile: status counts, aging count, SLA buckets. |
| Input Parameters | None |
| Return Values | `{status_counts, aging_count, sla: {overdue, due_soon, ok}}`; 200 |
| Validation and Error Messages | None raised |

#### GET /dashboard/summary

| Field | Details |
| --- | --- |
| Function Signature | GET /dashboard/summary → `def get_dashboard_summary(request, response, db)` in `app/routers/dashboard_main.py` |
| Description | Mega-aggregate combining posture, lifecycle, health, VEX, vulnerability_age, trend, forecast, exploitation, remediation, remediation_stats, risk_map, risk_matrix, recent_sboms in one DB session — replaces 15+ concurrent dashboard requests. |
| Input Parameters | None |
| Return Values | Composite dict with one key per panel (shapes match the individual endpoints above/below); 200 |
| Validation and Error Messages | None raised |

#### GET /dashboard/forecast

| Field | Details |
| --- | --- |
| Function Signature | GET /dashboard/forecast → `def dashboard_forecast(request, response, history_days, horizon_days, db)` in `app/routers/dashboard_advanced.py` |
| Description | OLS-projected distinct-active findings trajectory with `insufficient_history` flag and velocity `anomaly` envelope. ETag/304. |
| Input Parameters | Query `history_days: int` 14..90 (default 30, "OLS fit window."), `horizon_days: int` 7..60 (default 14, "Projection length.") |
| Return Values | Forecast payload from `metrics.findings_forecast`; 200 or 304 |
| Validation and Error Messages | 422 auto for bounds |

#### GET /dashboard/exploitation

| Field | Details |
| --- | --- |
| Function Signature | GET /dashboard/exploitation → `def dashboard_exploitation(request, response, db)` in `app/routers/dashboard_advanced.py` |
| Description | Portfolio exploitation outlook: EPSS-composed probability ≥1 in-scope CVE exploited within 30 days, with coverage + top drivers. ETag/304. |
| Input Parameters | None |
| Return Values | Payload from `metrics.portfolio_exploitation_outlook`; 200 or 304 |
| Validation and Error Messages | None raised |

#### GET /dashboard/remediation

| Field | Details |
| --- | --- |
| Function Signature | GET /dashboard/remediation → `def dashboard_remediation(request, response, db)` in `app/routers/dashboard_advanced.py` |
| Description | MTTR / SLA / velocity envelope (`metrics.remediation_summary`). ETag/304. |
| Input Parameters | None |
| Return Values | Remediation summary payload; 200 or 304 |
| Validation and Error Messages | None raised |

#### GET /dashboard/risk-map

| Field | Details |
| --- | --- |
| Function Signature | GET /dashboard/risk-map → `def dashboard_risk_map(request, response, db)` in `app/routers/dashboard_advanced.py` |
| Description | Treemap cells, one per analysed SBOM (`metrics.portfolio_risk_map`). ETag/304. |
| Input Parameters | None |
| Return Values | Risk-map payload; 200 or 304 |
| Validation and Error Messages | None raised |

#### GET /dashboard/risk-matrix

| Field | Details |
| --- | --- |
| Function Signature | GET /dashboard/risk-matrix → `def dashboard_risk_matrix(request, response, limit, db)` in `app/routers/dashboard_advanced.py` |
| Description | Impact × exploitability scatter (`metrics.portfolio_risk_matrix`). ETag/304. |
| Input Parameters | Query `limit: int` 10..1000 (default 300, "Max scatter points.") |
| Return Values | Scatter payload; 200 or 304 |
| Validation and Error Messages | 422 auto for bounds |

#### GET /dashboard/trend

| Field | Details |
| --- | --- |
| Function Signature | GET /dashboard/trend → `def dashboard_trend(request, response, days, granularity, application_ids, db)` in `app/routers/dashboard.py` (mounted at `/dashboard`, `app/main.py:905`) |
| Description | Findings trend chart. Legacy path (no `granularity`): zero-filled daily severity counts + annotations. Manager path (`granularity` set): period-bucketed distinct-active snapshots filtered to `application_ids` with fix_available/resolved overlays (annotations omitted). |
| Input Parameters | Query `days: int` 1..365 (default 30), `granularity?: Literal["day","week","month","year"]`, `application_ids?: list[int]` |
| Return Values | `FindingsTrendResponse` (schemas_dashboard) — `{days, points[]/series[] {date, critical, high, medium, low, unknown, total}, annotations[], avg_total, earliest_run_date, runs_total, runs_distinct_dates, granularity, schema_version}`; 200 |
| Validation and Error Messages | 422 auto for bounds/Literal; annotation build failures degrade to `[]` (logged) |

---

### Group: Schedules (`app/routers/schedules.py`, prefix `/api`)

All **Protected**. Shared body schema `ScheduleUpsert` (`app/schemas.py`): `{cadence: "DAILY"|"WEEKLY"|"BIWEEKLY"|"MONTHLY"|"QUARTERLY"|"CUSTOM" (required), cron_expression?: str (only when CUSTOM, 5-field), day_of_week?: int 0..6, day_of_month?: int 1..28, hour_utc: int 0..23 = 2, timezone: str = "UTC" (display only), enabled: bool = true, min_gap_minutes: int 0..1440 = 60, modified_by?: str}`. Shared response `ScheduleOut` (serialized dict): `{id, scope, project_id, product_id, sbom_id, cadence, cron_expression, day_of_week, day_of_month, hour_utc, timezone, enabled, next_run_at, last_run_at, last_run_status, last_run_id, consecutive_failures, min_gap_minutes, created_on/by, modified_on/by}`. Spec validation failures raise 422 with `str(ScheduleValidationError)`.

#### POST /api/projects/{project_id}/schedule

| Field | Details |
| --- | --- |
| Function Signature | POST /api/projects/{project_id}/schedule → `def upsert_project_schedule(payload, project_id, db)` in `app/routers/schedules.py` |
| Description | Create-or-replace the single PROJECT-scope schedule for a project; recomputes `next_run_at`. |
| Input Parameters | Path `project_id: int (ge=1)`; body `ScheduleUpsert` (full write, non-partial) |
| Return Values | `ScheduleOut`; **201 Created** (also on update — upsert) |
| Validation and Error Messages | 404 `"Project not found"`; 422 `str(ScheduleValidationError)` (e.g. invalid cadence/cron) |

#### GET /api/projects/{project_id}/schedule

| Field | Details |
| --- | --- |
| Function Signature | GET /api/projects/{project_id}/schedule → `def get_project_schedule(project_id, db)` in `app/routers/schedules.py` |
| Description | Fetch the project-scope schedule. |
| Input Parameters | Path `project_id: int (ge=1)` |
| Return Values | `ScheduleOut`; 200 |
| Validation and Error Messages | 404 `"Project not found"`; 404 `"No schedule configured for this project"` |

#### PATCH /api/projects/{project_id}/schedule

| Field | Details |
| --- | --- |
| Function Signature | PATCH /api/projects/{project_id}/schedule → `def patch_project_schedule(payload, project_id, db)` in `app/routers/schedules.py` |
| Description | Partial update of the project schedule; re-validates combined spec, refreshes `next_run_at`. |
| Input Parameters | Path `project_id: int (ge=1)`; body `ScheduleUpsert` (partial, exclude_unset) |
| Return Values | `ScheduleOut`; 200 |
| Validation and Error Messages | 404 `"Project not found"`; 404 `"No schedule configured for this project"`; 422 spec validation |

#### DELETE /api/projects/{project_id}/schedule

| Field | Details |
| --- | --- |
| Function Signature | DELETE /api/projects/{project_id}/schedule → `def delete_project_schedule(project_id, permanent, user_id, db)` in `app/routers/schedules.py` |
| Description | Soft-deletes (default) or hard-deletes the project schedule; audit-logged (`schedule.soft_delete` / `schedule.permanent_delete`). |
| Input Parameters | Path `project_id: int (ge=1)`; query `permanent: bool=false`, `user_id?: str` |
| Return Values | `{status: "deleted", permanent, id}` or `{status: "no_schedule"}`; 200 |
| Validation and Error Messages | 404 `"Project not found"` |

#### POST /api/products/{product_id}/schedule

| Field | Details |
| --- | --- |
| Function Signature | POST /api/products/{product_id}/schedule → `def upsert_product_schedule(payload, product_id, db)` in `app/routers/schedules.py` |
| Description | Create-or-replace the PRODUCT-scope schedule. |
| Input Parameters | Path `product_id: int (ge=1)`; body `ScheduleUpsert` |
| Return Values | `ScheduleOut`; **201 Created** |
| Validation and Error Messages | 404 `"Product not found"`; 422 spec validation |

#### GET /api/products/{product_id}/schedule

| Field | Details |
| --- | --- |
| Function Signature | GET /api/products/{product_id}/schedule → `def get_product_schedule(product_id, db)` in `app/routers/schedules.py` |
| Description | Fetch the product-scope schedule. |
| Input Parameters | Path `product_id: int (ge=1)` |
| Return Values | `ScheduleOut`; 200 |
| Validation and Error Messages | 404 `"Product not found"`; 404 `"No schedule configured for this product"` |

#### PATCH /api/products/{product_id}/schedule

| Field | Details |
| --- | --- |
| Function Signature | PATCH /api/products/{product_id}/schedule → `def patch_product_schedule(payload, product_id, db)` in `app/routers/schedules.py` |
| Description | Partial update of the product schedule. |
| Input Parameters | Path `product_id: int (ge=1)`; body `ScheduleUpsert` (partial) |
| Return Values | `ScheduleOut`; 200 |
| Validation and Error Messages | 404 `"Product not found"`; 404 `"No schedule configured for this product"`; 422 spec validation |

#### DELETE /api/products/{product_id}/schedule

| Field | Details |
| --- | --- |
| Function Signature | DELETE /api/products/{product_id}/schedule → `def delete_product_schedule(product_id, permanent, user_id, db)` in `app/routers/schedules.py` |
| Description | Soft/hard delete of the product schedule; audit-logged. |
| Input Parameters | Path `product_id: int (ge=1)`; query `permanent: bool=false`, `user_id?: str` |
| Return Values | `{status: "deleted", permanent, id}` or `{status: "no_schedule"}`; 200 |
| Validation and Error Messages | 404 `"Product not found"` |

#### POST /api/sboms/{sbom_id}/schedule

| Field | Details |
| --- | --- |
| Function Signature | POST /api/sboms/{sbom_id}/schedule → `def upsert_sbom_schedule(payload, sbom_id, db)` in `app/routers/schedules.py` |
| Description | Create-or-replace an SBOM-level schedule override (opts the SBOM out of project cascade). |
| Input Parameters | Path `sbom_id: int (ge=1)`; body `ScheduleUpsert` |
| Return Values | `ScheduleOut`; **201 Created** |
| Validation and Error Messages | 404 `"SBOM not found"`; 422 spec validation |

#### GET /api/sboms/{sbom_id}/schedule

| Field | Details |
| --- | --- |
| Function Signature | GET /api/sboms/{sbom_id}/schedule → `def get_sbom_schedule(sbom_id, db)` in `app/routers/schedules.py` |
| Description | Effective schedule for an SBOM after inheritance resolution; `inherited=true` when it comes from PROJECT/PRODUCT scope (UI renders "Inherits from project" badge). |
| Input Parameters | Path `sbom_id: int (ge=1)` |
| Return Values | `ScheduleResolved` — `{inherited: bool, schedule: ScheduleOut|null}`; 200 |
| Validation and Error Messages | 404 `"SBOM not found"` |

#### PATCH /api/sboms/{sbom_id}/schedule

| Field | Details |
| --- | --- |
| Function Signature | PATCH /api/sboms/{sbom_id}/schedule → `def patch_sbom_schedule(payload, sbom_id, db)` in `app/routers/schedules.py` |
| Description | Partial update of the SBOM-level override. |
| Input Parameters | Path `sbom_id: int (ge=1)`; body `ScheduleUpsert` (partial) |
| Return Values | `ScheduleOut`; 200 |
| Validation and Error Messages | 404 `"SBOM not found"`; 404 `"No SBOM-level schedule. POST a new override or rely on the project-level cascade."`; 422 spec validation |

#### DELETE /api/sboms/{sbom_id}/schedule

| Field | Details |
| --- | --- |
| Function Signature | DELETE /api/sboms/{sbom_id}/schedule → `def delete_sbom_schedule(sbom_id, permanent, user_id, db)` in `app/routers/schedules.py` |
| Description | Removes the SBOM-level override (soft by default); audit-logged. |
| Input Parameters | Path `sbom_id: int (ge=1)`; query `permanent: bool=false`, `user_id?: str` |
| Return Values | `{status: "deleted", permanent, id}` or `{status: "no_override"}`; 200 |
| Validation and Error Messages | 404 `"SBOM not found"` |

#### GET /api/schedules

| Field | Details |
| --- | --- |
| Function Signature | GET /api/schedules → `def list_schedules(scope, enabled, project_id, page, page_size, response, db)` in `app/routers/schedules.py` |
| Description | Operator flat list of all schedules with filters; sets `X-Total-Count`. |
| Input Parameters | Query `scope?: str` (PROJECT|SBOM), `enabled?: bool`, `project_id?: int (ge=1)`, `page ≥1` (default 1), `page_size` 1..500 (default 50) — **pagination: offset (in-memory slice)** |
| Return Values | `list[ScheduleOut]`; header `X-Total-Count`; 200 |
| Validation and Error Messages | 422 `"scope must be PROJECT or SBOM"` |

#### POST /api/schedules/{schedule_id}/pause

| Field | Details |
| --- | --- |
| Function Signature | POST /api/schedules/{schedule_id}/pause → `def pause_schedule(schedule_id, db)` in `app/routers/schedules.py` |
| Description | Disables the schedule and clears `next_run_at`. |
| Input Parameters | Path `schedule_id: int (ge=1)` |
| Return Values | `ScheduleOut` (enabled=false, next_run_at=null); 200 |
| Validation and Error Messages | 404 `"Schedule not found"` |

#### POST /api/schedules/{schedule_id}/resume

| Field | Details |
| --- | --- |
| Function Signature | POST /api/schedules/{schedule_id}/resume → `def resume_schedule(schedule_id, db)` in `app/routers/schedules.py` |
| Description | Re-enables the schedule and recomputes `next_run_at`. |
| Input Parameters | Path `schedule_id: int (ge=1)` |
| Return Values | `ScheduleOut`; 200 |
| Validation and Error Messages | 404 `"Schedule not found"` |

#### POST /api/schedules/{schedule_id}/run-now

| Field | Details |
| --- | --- |
| Function Signature | POST /api/schedules/{schedule_id}/run-now → `def run_schedule_now(schedule_id, db)` in `app/routers/schedules.py` |
| Description | Immediately fans out the schedule's analysis via Celery (`analyze_sbom_async.delay`) without touching `next_run_at`. PROJECT scope enqueues every project SBOM except those with an explicit SBOM-level override. |
| Input Parameters | Path `schedule_id: int (ge=1)` |
| Return Values | `{status: "enqueued"|"partial", schedule_id, sbom_ids[], failed_sbom_ids[]}`; **202 Accepted** |
| Validation and Error Messages | 404 `"Schedule not found"`; 409 `"Schedule is missing a target"`; 502 `{code: "broker_unavailable", message: "Could not enqueue any analyses — the task broker is unreachable. Check that Redis/Celery is running.", last_error, schedule_id, failed_sbom_ids}` |

---

### Group: CVE and Enrichment (`app/routers/cves.py`, prefix `/api/v1`)

All **Protected**; SlowAPI rate limits per route. Structured 400 envelope: `{error_code: "CVE_VAL_E001_UNRECOGNIZED_ID", message: "We don't recognize this advisory identifier format.", raw_id, supported_formats[], retryable: false}`.

#### GET /api/v1/cves/{cve_id}

| Field | Details |
| --- | --- |
| Function Signature | GET /api/v1/cves/{cve_id} → `async def get_cve_detail(request, cve_id, db)` in `app/routers/cves.py` |
| Description | Merged, cached (TTL-bucketed) CVE detail for the in-app CVE modal; degrades gracefully with `is_partial` + `sources_used` when upstream sources fail. Rate limit `60/minute`. |
| Input Parameters | Path `cve_id: str` (CVE/GHSA/alias formats per `SUPPORTED_FORMATS`) |
| Return Values | `CveDetail` (`app/schemas_cve.py`) — `{cve_id, aliases[], title, summary (≤2000), severity, cvss_v3_score/vector, cvss_v4_score/vector, cwe_ids[], published_at, modified_at, exploitation: CveExploitation (KEV/EPSS), fix_versions[], workaround, references, sources_used, is_partial, ...}`; 200 |
| Validation and Error Messages | 400 unrecognized-id envelope (above); 429 rate limit |

#### POST /api/v1/cves/batch

| Field | Details |
| --- | --- |
| Function Signature | POST /api/v1/cves/batch → `async def batch_cve_detail(request, body, db)` in `app/routers/cves.py` |
| Description | Bulk CVE lookup (≤50 ids). Mixed-validity batches proceed; unknown ids returned in `not_found`. All-unknown batch → 400. Rate limit `10/minute`. |
| Input Parameters | Body `CveBatchRequest {ids: list[str], 1..50}` (extra forbidden) |
| Return Values | `CveBatchResponse {items: dict[str, CveDetail], not_found: list[str]}`; 200 |
| Validation and Error Messages | 400 unrecognized-id envelope when zero ids are recognised; 422 auto for list bounds; 429 rate limit |

#### GET /api/v1/scans/{scan_id}/cves/{cve_id}

| Field | Details |
| --- | --- |
| Function Signature | GET /api/v1/scans/{scan_id}/cves/{cve_id} → `async def get_cve_detail_with_scan_context(request, scan_id, cve_id, db)` in `app/routers/cves.py` |
| Description | Scan-aware CVE detail: joins `SBOMComponent` context and computes a recommended upgrade. Rate limit `60/minute`. |
| Input Parameters | Path `scan_id: int` (analysis run id), `cve_id: str` |
| Return Values | `CveDetailWithContext` (extends CveDetail) — adds `{component: CveScanContext|null, current_version_status: "vulnerable"|"fixed"|"unknown", recommended_upgrade}`; 200 |
| Validation and Error Messages | 400 unrecognized-id envelope; 429 rate limit |

---

### Group: Lifecycle (`app/routers/lifecycle.py`, no prefix — absolute paths)

All **Protected**. (SBOM-level lifecycle endpoints are in the SBOM Management group: `/api/sboms/{id}/lifecycle*`.)

#### GET /api/lifecycle/sources

| Field | Details |
| --- | --- |
| Function Signature | GET /api/lifecycle/sources → `def list_lifecycle_sources(db)` in `app/routers/lifecycle.py` |
| Description | Enabled lifecycle providers with priority and health status (DB-config first, in-process tracker fallback). Secrets never included (`safe_config_dict`). |
| Input Parameters | None |
| Return Values | `{sources: [{name, provider_key, provider_type, priority, enabled, status, last_success, last_failure, last_error}]}`; 200 |
| Validation and Error Messages | None raised (config errors fall back to tracker) |

#### GET /api/lifecycle/provider-status

| Field | Details |
| --- | --- |
| Function Signature | GET /api/lifecycle/provider-status → `def lifecycle_provider_status(db)` in `app/routers/lifecycle.py` |
| Description | Aggregate provider health: overall status + degraded count + per-provider rows. |
| Input Parameters | None |
| Return Values | `{overall_status: "healthy"|"degraded", degraded_count, providers[]}`; 200 |
| Validation and Error Messages | None raised (falls back to tracker summary) |

#### GET /api/lifecycle/component/{component_id}

| Field | Details |
| --- | --- |
| Function Signature | GET /api/lifecycle/component/{component_id} → `def get_component_lifecycle(component_id, db)` in `app/routers/lifecycle.py` |
| Description | Lifecycle details for a single component row. |
| Input Parameters | Path `component_id: int` |
| Return Values | `SBOMComponentOut` — `{id, sbom_id, bom_ref, component_type, name, version, purl, cpe, supplier, scope, ecosystem, normalized_* fields, lifecycle_status, eol/eos/eof dates, maintenance_status, recommended_version, lifecycle_source, ...}`; 200 |
| Validation and Error Messages | 404 `"Component with ID {component_id} not found."` |

#### PUT /api/lifecycle/component/{component_id}

| Field | Details |
| --- | --- |
| Function Signature | PUT /api/lifecycle/component/{component_id} → `def update_component_lifecycle(component_id, payload, context, db)` in `app/routers/lifecycle.py` |
| Description | Backward-compatible manual lifecycle override (delegates to `apply_manual_override`, audited). |
| Input Parameters | Path `component_id: int`; body `LifecycleInfoUpdate {lifecycle_status: str (required), eos_date?, eol_date?, eof_date?, is_deprecated: bool=false, deprecated?, unsupported?, maintenance_status?, latest_version?, latest_supported_version?, recommended_version?, recommendation?, evidence_url?, reason?, note?, evidence?: dict, updated_by?}` |
| Return Values | `SBOMComponentOut`; 200 |
| Validation and Error Messages | Service-level errors propagate (404 for unknown component from service) |

#### PATCH /api/components/{component_id}/lifecycle-override

| Field | Details |
| --- | --- |
| Function Signature | PATCH /api/components/{component_id}/lifecycle-override → `def patch_component_lifecycle_override(component_id, payload, context, db)` in `app/routers/lifecycle.py` |
| Description | Preferred (audited) manual lifecycle override endpoint — same behavior as the PUT variant. |
| Input Parameters | Path `component_id: int`; body `LifecycleInfoUpdate` |
| Return Values | `SBOMComponentOut`; 200 |
| Validation and Error Messages | As above |

#### POST /api/components/{component_id}/lifecycle/refresh

| Field | Details |
| --- | --- |
| Function Signature | POST /api/components/{component_id}/lifecycle/refresh → `def refresh_component_lifecycle_endpoint(component_id, force, db)` in `app/routers/lifecycle.py` |
| Description | Force provider-backed lifecycle re-enrichment for one component. |
| Input Parameters | Path `component_id: int`; query `force: bool=true` |
| Return Values | `SBOMComponentOut`; 200 |
| Validation and Error Messages | Service-level errors propagate |

---

### Group: Administration — Lifecycle Providers and Vendor Records (`app/routers/lifecycle_admin.py`, no prefix — absolute `/api/admin/...` paths)

All **Protected** plus per-route `require_permission(...)` (403 `"Insufficient permission"` when missing). Secret values are write-only; responses expose only `value_preview`.

#### GET /api/admin/lifecycle-providers

| Field | Details |
| --- | --- |
| Function Signature | GET /api/admin/lifecycle-providers → `def list_lifecycle_providers(db, _context)` in `app/routers/lifecycle_admin.py` |
| Description | Lists all lifecycle provider configs (incl. disabled) — admin settings screen. Permission `lifecycle:provider:read`. |
| Input Parameters | None |
| Return Values | `list[LifecycleProviderConfigResponse]` (`app/schemas_lifecycle_admin.py`) — provider_key, display_name, provider_type, priority, enabled, health_status, last_success/failure, secret previews; 200 |
| Validation and Error Messages | 403 permission |

#### PUT /api/admin/lifecycle-providers/{provider_key}

| Field | Details |
| --- | --- |
| Function Signature | PUT /api/admin/lifecycle-providers/{provider_key} → `def update_lifecycle_provider(provider_key, payload, request, db, context)` in `app/routers/lifecycle_admin.py` |
| Description | Updates a provider config (enabled, priority, endpoint options). Permission `lifecycle:provider:update`; audited via service. |
| Input Parameters | Path `provider_key: str`; body `LifecycleProviderUpdateRequest` |
| Return Values | `LifecycleProviderConfigResponse`; 200 |
| Validation and Error Messages | 403 permission; service 404/422 propagate |

#### PUT /api/admin/lifecycle-providers/{provider_key}/secret

| Field | Details |
| --- | --- |
| Function Signature | PUT /api/admin/lifecycle-providers/{provider_key}/secret → `def put_lifecycle_provider_secret(provider_key, payload, request, db, context)` in `app/routers/lifecycle_admin.py` |
| Description | Stores/rotates a provider secret (e.g. API key `<REDACTED>`). Permission `lifecycle:provider:update`. |
| Input Parameters | Path `provider_key: str`; body `LifecycleProviderSecretRequest {secret_name, secret_value: <REDACTED>}` |
| Return Values | `LifecycleProviderSecretResponse {provider_key, secret_name, value_preview, updated_at}`; 200 |
| Validation and Error Messages | 403 permission; service errors propagate |

#### DELETE /api/admin/lifecycle-providers/{provider_key}/secret/{secret_name}

| Field | Details |
| --- | --- |
| Function Signature | DELETE .../secret/{secret_name} → `def delete_lifecycle_provider_secret(provider_key, secret_name, request, db, context)` in `app/routers/lifecycle_admin.py` |
| Description | Deletes a stored provider secret. Permission `lifecycle:provider:update`. |
| Input Parameters | Path `provider_key: str`, `secret_name: str` |
| Return Values | Empty body; **204 No Content** |
| Validation and Error Messages | 403 permission; service errors propagate |

#### POST /api/admin/lifecycle-providers/{provider_key}/test

| Field | Details |
| --- | --- |
| Function Signature | POST /api/admin/lifecycle-providers/{provider_key}/test → `def test_lifecycle_provider(provider_key, request, db, context)` in `app/routers/lifecycle_admin.py` |
| Description | Connectivity/auth test for a provider. Permission `lifecycle:provider:test`. |
| Input Parameters | Path `provider_key: str` |
| Return Values | `LifecycleProviderTestResponse` (success flag, latency, message); 200 |
| Validation and Error Messages | 403 permission; service errors propagate |

#### POST /api/admin/lifecycle-providers/{provider_key}/sync

| Field | Details |
| --- | --- |
| Function Signature | POST /api/admin/lifecycle-providers/{provider_key}/sync → `def sync_lifecycle_provider(provider_key, request, db, context)` in `app/routers/lifecycle_admin.py` |
| Description | Triggers a provider data sync. Permission `lifecycle:provider:sync`. |
| Input Parameters | Path `provider_key: str` |
| Return Values | `LifecycleProviderSyncResponse` (sync counts/status); 200 |
| Validation and Error Messages | 403 permission; service errors propagate |

#### GET /api/admin/lifecycle-vendor-records

| Field | Details |
| --- | --- |
| Function Signature | GET /api/admin/lifecycle-vendor-records → `def list_lifecycle_vendor_records(search, status_filter, ecosystem, limit, offset, db, _context)` in `app/routers/lifecycle_admin.py` |
| Description | Paged list of manually-curated vendor lifecycle records. Permission `lifecycle:vendor-record:read`. |
| Input Parameters | Query `search?: str`, `status?: str` (alias of status_filter), `ecosystem?: str`, `limit` 1..200 (default 50), `offset ≥0` (default 0) — **pagination: limit/offset** |
| Return Values | `LifecycleVendorRecordListResponse {items: list[LifecycleVendorRecordResponse], total, limit, offset}`; 200 |
| Validation and Error Messages | 403 permission; 422 auto bounds |

#### POST /api/admin/lifecycle-vendor-records

| Field | Details |
| --- | --- |
| Function Signature | POST /api/admin/lifecycle-vendor-records → `def create_lifecycle_vendor_record(payload, request, db, context)` in `app/routers/lifecycle_admin.py` |
| Description | Creates a vendor lifecycle record. Permission `lifecycle:vendor-record:write`. |
| Input Parameters | Body `LifecycleVendorRecordRequest` (component/ecosystem matcher + lifecycle dates/status) |
| Return Values | `LifecycleVendorRecordResponse`; **201 Created** |
| Validation and Error Messages | 403 permission; service/schema 422 propagate |

#### PUT /api/admin/lifecycle-vendor-records/{record_id}

| Field | Details |
| --- | --- |
| Function Signature | PUT /api/admin/lifecycle-vendor-records/{record_id} → `def update_lifecycle_vendor_record(record_id, payload, request, db, context)` in `app/routers/lifecycle_admin.py` |
| Description | Updates a vendor record. Permission `lifecycle:vendor-record:write`. |
| Input Parameters | Path `record_id: int`; body `LifecycleVendorRecordRequest` (exclude_unset) |
| Return Values | `LifecycleVendorRecordResponse`; 200 |
| Validation and Error Messages | 403 permission; service 404 propagates |

#### DELETE /api/admin/lifecycle-vendor-records/{record_id}

| Field | Details |
| --- | --- |
| Function Signature | DELETE /api/admin/lifecycle-vendor-records/{record_id} → `def delete_lifecycle_vendor_record(record_id, request, db, context)` in `app/routers/lifecycle_admin.py` |
| Description | Disables (soft-removes) a vendor record. Permission `lifecycle:vendor-record:delete`. |
| Input Parameters | Path `record_id: int` |
| Return Values | Empty body; **204 No Content** |
| Validation and Error Messages | 403 permission; service 404 propagates |

#### POST /api/admin/lifecycle-vendor-records/import

| Field | Details |
| --- | --- |
| Function Signature | POST /api/admin/lifecycle-vendor-records/import → `def import_lifecycle_vendor_records(payload, request, db, context)` in `app/routers/lifecycle_admin.py` |
| Description | Bulk import of vendor records. Permission `lifecycle:vendor-record:write`. |
| Input Parameters | Body `LifecycleVendorRecordImportRequest {records: list[...]}` |
| Return Values | `LifecycleVendorRecordImportResponse` (created/updated/skipped counts); 200 |
| Validation and Error Messages | 403 permission |

#### GET /api/admin/lifecycle-vendor-records/export

| Field | Details |
| --- | --- |
| Function Signature | GET /api/admin/lifecycle-vendor-records/export → `def export_lifecycle_vendor_records(db, _context)` in `app/routers/lifecycle_admin.py` |
| Description | Exports all vendor records as JSON. Permission `lifecycle:vendor-record:read`. |
| Input Parameters | None |
| Return Values | `{records: [...]}`; 200 |
| Validation and Error Messages | 403 permission |

---

### Group: Authentication and Identity (`app/routers/tenants.py`, prefix `/api`)

All **Protected**. Multi-tenancy: identity comes from the IAM-mapped context; `X-Tenant-ID` header switches the active tenant.

#### GET /api/auth/me

| Field | Details |
| --- | --- |
| Function Signature | GET /api/auth/me → `def auth_me(context)` in `app/routers/tenants.py` |
| Description | Returns the resolved identity/authorization context for the caller (used at login; middleware writes an `auth.login_mapping` audit row for this path). |
| Input Parameters | None (context from auth headers) |
| Return Values | `{user_id, external_user_id, email, display_name, tenant_id, external_tenant_id, roles[], permissions[], is_platform_admin}`; 200 |
| Validation and Error Messages | 401/403 from auth dependencies only |

#### GET /api/tenants

| Field | Details |
| --- | --- |
| Function Signature | GET /api/tenants → `def list_my_tenants(context, db)` in `app/routers/tenants.py` |
| Description | Tenants available to the current user (all tenants for platform admins), with the user's role per tenant. |
| Input Parameters | None |
| Return Values | `list[{id, name, slug, external_iam_tenant_id, status, role}]`; 200 |
| Validation and Error Messages | None raised |

#### POST /api/tenants

| Field | Details |
| --- | --- |
| Function Signature | POST /api/tenants → `def create_tenant(payload, context, db)` in `app/routers/tenants.py` |
| Description | Creates a tenant. Requires `platform:admin` permission. |
| Input Parameters | Body `TenantCreate {name: str 1..255, slug: str (regex ^[a-z0-9][a-z0-9-]{1,126}[a-z0-9]$), external_iam_tenant_id: str 1..255}` |
| Return Values | Tenant dict `{id, name, slug, external_iam_tenant_id, status, role: null}`; **201 Created** |
| Validation and Error Messages | 403 `"Insufficient permission"`; 422 auto for slug regex/lengths |

#### GET /api/tenants/{tenant_id}/users

| Field | Details |
| --- | --- |
| Function Signature | GET /api/tenants/{tenant_id}/users → `def list_tenant_users(tenant_id, context, db)` in `app/routers/tenants.py` |
| Description | Lists tenant memberships (users + roles). Permission `tenant:user:read`; cross-tenant access refused. |
| Input Parameters | Path `tenant_id: int` |
| Return Values | `list[{membership_id, user_id, external_iam_user_id, email, display_name, role, status}]`; 200 |
| Validation and Error Messages | 403 `"Tenant access denied"` (tenant mismatch); 403 permission |

#### POST /api/tenants/{tenant_id}/users

| Field | Details |
| --- | --- |
| Function Signature | POST /api/tenants/{tenant_id}/users → `def add_tenant_user(tenant_id, payload, context, db)` in `app/routers/tenants.py` |
| Description | Adds/updates a user membership in the tenant. Permission `tenant:user:invite`; role must be a known non-platform role. Audit-logged (`tenant.user.upsert`). |
| Input Parameters | Path `tenant_id: int`; body `MembershipUpsert {external_iam_user_id: str (required), email?, display_name?, role: str (required), status: str="ACTIVE"}` |
| Return Values | `{membership_id, user_id, role, status}`; **201 Created** |
| Validation and Error Messages | 403 `"Tenant access denied"`; 422 `"Invalid tenant role"` (unknown role or PLATFORM_ADMIN); 403 permission |

#### PATCH /api/tenants/{tenant_id}/users/{membership_id}

| Field | Details |
| --- | --- |
| Function Signature | PATCH /api/tenants/{tenant_id}/users/{membership_id} → `def update_tenant_user(tenant_id, membership_id, payload, context, db)` in `app/routers/tenants.py` |
| Description | Updates a membership's role and/or status. Permission `tenant:user:update`. Audit-logged (`tenant.user.update`). |
| Input Parameters | Path `tenant_id: int`, `membership_id: int`; body `MembershipUpdate {role?: str, status?: str}` |
| Return Values | `{membership_id, role, status}`; 200 |
| Validation and Error Messages | 403 `"Tenant access denied"`; 422 `"Invalid tenant role"`; 403 permission |

---

### Group: AI Remediation (`app/routers/ai_fixes.py` prefix `/api/v1`; `app/routers/ai_copilot.py` prefix `/api/ai/copilot`; `app/routers/ai_usage.py` prefix `/api/v1/ai`; `app/routers/ai_credentials.py` prefix `/api/v1/ai`)

All **Protected**. Rollout gate `_require_ai_enabled` (kill switch → master flag → canary) raises `access.http_status` with `{error_code: "AI_FIXES_KILL_SWITCH"|"AI_FIXES_DISABLED"|"AI_FIXES_CANARY_EXCLUDED", message}` on the gated endpoints. Common 404s: `"Analysis run {run_id} not found."`, `"Finding {finding_id} not found."`, `"Batch {batch_id} not found for run {run_id}."`.

#### POST /api/v1/runs/{run_id}/ai-fixes

| Field | Details |
| --- | --- |
| Function Signature | POST /api/v1/runs/{run_id}/ai-fixes → `async def trigger_run_fixes(run_id, body, db)` in `app/routers/ai_fixes.py` |
| Description | Starts an AI fix-generation batch for a run (optionally scoped to filtered/selected findings); enqueues to Celery or runs inline. Clients then subscribe to the per-batch SSE stream. |
| Input Parameters | Path `run_id: int`; body `TriggerBatchRequest {provider_name?: str, force_refresh: bool=false, budget_usd?: float ≥0, scope?: AiFixGenerationScope}` (optional) |
| Return Values | `TriggerBatchResponse {progress: BatchProgress {run_id, batch_id, scope_label, status, total, from_cache, generated, failed, remaining, cost_so_far_usd, ...}, batch_id, enqueued, total, cached_count, scope_label}`; 200 |
| Validation and Error Messages | Rollout-gate error (above); 404 run; 409 `{error_code: "TOO_MANY_ACTIVE_BATCHES", message: "This run has N active batches. Wait for one to complete before starting another.", active_count, max_concurrent, retryable: true}`; 400 `{error_code: "EMPTY_SCOPE", message: "No findings match the supplied scope."}` |

#### GET /api/v1/runs/{run_id}/ai-fixes/estimate  **[DEPRECATED]**

| Field | Details |
| --- | --- |
| Function Signature | GET /api/v1/runs/{run_id}/ai-fixes/estimate → `def estimate_run_duration_legacy(run_id, db)` in `app/routers/ai_fixes.py` (`deprecated=True`) |
| Description | Legacy whole-run duration/cost estimate (equivalent to POST variant with scope=None); kept 30 days post Phase-4. |
| Input Parameters | Path `run_id: int` |
| Return Values | `BatchDurationEstimateResponse` (total findings, cached count, llm calls, cost/seconds estimates); 200 |
| Validation and Error Messages | 404 run |

#### POST /api/v1/runs/{run_id}/ai-fixes/estimate

| Field | Details |
| --- | --- |
| Function Signature | POST /api/v1/runs/{run_id}/ai-fixes/estimate → `def estimate_run_duration(run_id, body, db)` in `app/routers/ai_fixes.py` |
| Description | Scope-aware pre-flight estimate: resolves the scope to finding ids, counts cached entries in one SQL join, projects cost/latency/bottleneck for the CTA card. |
| Input Parameters | Path `run_id: int`; body `EstimateRequest {scope?: AiFixGenerationScope}` (optional) |
| Return Values | `EstimateResponse {run_id, scope_label, total_findings_in_scope, cached_count, llm_call_count, estimated_cost_usd, estimated_seconds, provider_name, provider_tier, is_local, rate_per_minute, bottleneck, warning_recommended, active_batches_using_provider, blocked, blocked_reason}`; 200 |
| Validation and Error Messages | 404 run |

#### GET /api/v1/runs/{run_id}/ai-fixes/batches

| Field | Details |
| --- | --- |
| Function Signature | GET /api/v1/runs/{run_id}/ai-fixes/batches → `def list_run_batches(run_id, db)` in `app/routers/ai_fixes.py` |
| Description | Lists every batch (active + historical) for a run, newest-first. |
| Input Parameters | Path `run_id: int` |
| Return Values | `BatchListResponse {run_id, items: list[BatchListItem {batch_id, run_id, status, scope_label, provider_name, total, cached_count, generated_count, failed_count, cost_usd, started_at, completed_at, created_at, last_error}], total}`; 200 |
| Validation and Error Messages | 404 run |

#### GET /api/v1/runs/{run_id}/ai-fixes/batches/{batch_id}

| Field | Details |
| --- | --- |
| Function Signature | GET .../batches/{batch_id} → `def get_run_batch(run_id, batch_id, db)` in `app/routers/ai_fixes.py` |
| Description | Batch detail: durable row + live progress envelope (if any). |
| Input Parameters | Path `run_id: int`, `batch_id: str` |
| Return Values | `BatchDetailResponse {batch: BatchListItem, progress: BatchProgress|null}`; 200 |
| Validation and Error Messages | 404 run; 404 batch |

#### GET /api/v1/runs/{run_id}/ai-fixes/batches/{batch_id}/stream

| Field | Details |
| --- | --- |
| Function Signature | GET .../batches/{batch_id}/stream → `def stream_batch_progress(run_id, batch_id)` in `app/routers/ai_fixes.py` |
| Description | **SSE** stream of batch progress (`event: progress`, JSON `BatchProgress` payloads, initial `:ok` ping). Existence checks use a short-lived DB session so the long stream doesn't pin a pool connection; the stream reads only the in-memory progress store. |
| Input Parameters | Path `run_id: int`, `batch_id: str` |
| Return Values | `StreamingResponse` `text/event-stream`; 200 |
| Validation and Error Messages | 404 run; 404 batch (checked before streaming) |

#### POST /api/v1/runs/{run_id}/ai-fixes/batches/{batch_id}/cancel

| Field | Details |
| --- | --- |
| Function Signature | POST .../batches/{batch_id}/cancel → `def cancel_run_batch(run_id, batch_id, db)` in `app/routers/ai_fixes.py` |
| Description | Requests cancellation of one batch (progress-store flag honored by the pipeline loop). |
| Input Parameters | Path `run_id: int`, `batch_id: str` |
| Return Values | `{run_id, batch_id, cancel_requested: true}`; **202 Accepted** |
| Validation and Error Messages | 404 run; 404 batch |

#### GET /api/v1/runs/{run_id}/ai-fixes/progress  **[DEPRECATED]**

| Field | Details |
| --- | --- |
| Function Signature | GET /api/v1/runs/{run_id}/ai-fixes/progress → `def get_progress(run_id, db)` in `app/routers/ai_fixes.py` (`deprecated=True`) |
| Description | Most-recent batch's progress (single-batch legacy). Falls back to the durable batch row after restart so terminal states survive. |
| Input Parameters | Path `run_id: int` |
| Return Values | `BatchProgress`; 200 — or **204 No Content** ("Run exists but has no AI fix batch (idle)") |
| Validation and Error Messages | 404 run (only when the run itself is missing) |

#### POST /api/v1/runs/{run_id}/ai-fixes/cancel  **[DEPRECATED]**

| Field | Details |
| --- | --- |
| Function Signature | POST /api/v1/runs/{run_id}/ai-fixes/cancel → `def cancel_run_fixes_legacy(run_id, db)` in `app/routers/ai_fixes.py` (`deprecated=True`) |
| Description | Cancels every active batch on the run (idempotent). Writes a synthetic terminal `cancelled` envelope for phantom subscribers. |
| Input Parameters | Path `run_id: int` |
| Return Values | Cancellation dict; **202 Accepted** |
| Validation and Error Messages | 404 run |

#### GET /api/v1/runs/{run_id}/ai-fixes/stream  **[DEPRECATED]**

| Field | Details |
| --- | --- |
| Function Signature | GET /api/v1/runs/{run_id}/ai-fixes/stream → `def stream_progress_legacy(run_id)` in `app/routers/ai_fixes.py` (`deprecated=True`) |
| Description | **SSE** stream of the most-recent batch's progress (indeterminate with multiple batches). Phantom fast-path: with no live progress and no durable batch, emits one terminal `cancelled` event and closes. |
| Input Parameters | Path `run_id: int` |
| Return Values | `StreamingResponse` `text/event-stream`; 200 |
| Validation and Error Messages | 404 run |

#### GET /api/v1/runs/{run_id}/ai-fixes

| Field | Details |
| --- | --- |
| Function Signature | GET /api/v1/runs/{run_id}/ai-fixes → `def list_run_fixes(run_id, db)` in `app/routers/ai_fixes.py` |
| Description | Lists cached AI fix bundles produced for a run (cache keys derived from vuln+component grounding context). |
| Input Parameters | Path `run_id: int` |
| Return Values | `FindingFixListResponse {run_id, items: list[FindingFixListItem {cache_key, vuln_id, component_name, component_version, provider_used, model_used, total_cost_usd, generated_at, expires_at}], total}`; 200 |
| Validation and Error Messages | 404 run |

#### GET /api/v1/findings/{finding_id}/ai-fix

| Field | Details |
| --- | --- |
| Function Signature | GET /api/v1/findings/{finding_id}/ai-fix → `async def get_finding_fix(finding_id, provider_name, db)` in `app/routers/ai_fixes.py` |
| Description | Read-only cached AI fix for one finding — never spends LLM budget (modal open path). |
| Input Parameters | Path `finding_id: int`; query `provider_name?: str` (reserved) |
| Return Values | `FindingFixResponse {result?: AiFixResult, error?: AiFixError}`; 200 |
| Validation and Error Messages | Rollout gate; 404 finding; 404 `"No cached AI fix for this finding."` |

#### POST /api/v1/findings/{finding_id}/ai-fix

| Field | Details |
| --- | --- |
| Function Signature | POST /api/v1/findings/{finding_id}/ai-fix → `async def generate_finding_fix(finding_id, provider_name, db)` in `app/routers/ai_fixes.py` |
| Description | Generates the AI fix for one finding (idempotent — returns cached when present). Explicit write path behind the Generate button. |
| Input Parameters | Path `finding_id: int`; query `provider_name?: str` |
| Return Values | `FindingFixResponse`; 200 |
| Validation and Error Messages | Rollout gate; 404 finding; provider/budget failures surface inside the `error` envelope |

#### POST /api/v1/findings/{finding_id}/ai-fix:regenerate

| Field | Details |
| --- | --- |
| Function Signature | POST /api/v1/findings/{finding_id}/ai-fix:regenerate → `async def regenerate_finding_fix(finding_id, provider_name, db)` in `app/routers/ai_fixes.py` |
| Description | Force-refresh: bypasses the fix cache for this finding. |
| Input Parameters | Path `finding_id: int`; query `provider_name?: str` |
| Return Values | `FindingFixResponse`; 200 |
| Validation and Error Messages | Rollout gate; 404 finding |

#### GET /api/ai/copilot/briefing

| Field | Details |
| --- | --- |
| Function Signature | GET /api/ai/copilot/briefing → `async def copilot_briefing(force, db)` in `app/routers/ai_copilot.py` |
| Description | AI executive briefing over the portfolio snapshot, cached ≤6h per data state. Gated by the same AI rollout switch. |
| Input Parameters | Query `force: bool=false` ("Bypass the cached briefing.") |
| Return Values | Briefing payload from `generate_briefing` (markdown/summary sections); 200 |
| Validation and Error Messages | Gate: `{error_code: "AI_FIXES_DISABLED", message}` (status per gate); 429 `{error_code: "AI_BUDGET_EXCEEDED", message}`; 502 `{error_code: "AI_PROVIDER_ERROR", message}` |

#### POST /api/ai/copilot/ask

| Field | Details |
| --- | --- |
| Function Signature | POST /api/ai/copilot/ask → `async def copilot_ask(body, db)` in `app/routers/ai_copilot.py` |
| Description | Grounded one-shot Q&A over the portfolio; no cache, every call budget-guarded. |
| Input Parameters | Body `AskBody {question: str 1..500}` |
| Return Values | Answer payload from `answer_question`; 200 |
| Validation and Error Messages | Gate error; 422 `str(ValueError)`; 429 `AI_BUDGET_EXCEEDED`; 502 `AI_PROVIDER_ERROR` |

#### GET /api/v1/ai/usage

| Field | Details |
| --- | --- |
| Function Signature | GET /api/v1/ai/usage → `def get_ai_usage(db)` in `app/routers/ai_usage.py` |
| Description | Cost dashboard aggregate: today + 30-day spend/calls/cache-hit ratio, buckets by purpose and provider, budget caps and daily headroom. |
| Input Parameters | None |
| Return Values | `AiUsageSummary {today: AiUsageTotals, last_30_days, by_purpose[], by_provider[], budget_caps_usd {per_request_usd, per_scan_usd, per_day_org_usd}, spent_today_usd, daily_remaining_usd}`; 200 |
| Validation and Error Messages | None raised |

#### GET /api/v1/ai/providers

| Field | Details |
| --- | --- |
| Function Signature | GET /api/v1/ai/providers → `def list_providers(db)` in `app/routers/ai_usage.py` |
| Description | Runtime-configured providers for the Settings selector. |
| Input Parameters | None |
| Return Values | `list[ProviderInfo {name, available, default_model, supports_structured_output, is_local, notes}]`; 200 |
| Validation and Error Messages | None raised |

#### GET /api/v1/ai/pricing

| Field | Details |
| --- | --- |
| Function Signature | GET /api/v1/ai/pricing → `def list_pricing()` in `app/routers/ai_usage.py` |
| Description | Static provider/model pricing table for the cost-estimate UI. |
| Input Parameters | None |
| Return Values | `list[PricingEntry {provider, model, input_per_1k_usd, output_per_1k_usd}]`; 200 |
| Validation and Error Messages | None raised |

#### POST /api/v1/ai/registry/reset

| Field | Details |
| --- | --- |
| Function Signature | POST /api/v1/ai/registry/reset → `def reset_provider_registry()` in `app/routers/ai_usage.py` |
| Description | Drops the cached provider registry so env/DB config changes are picked up (admin convenience). |
| Input Parameters | None |
| Return Values | Empty body; **204 No Content** |
| Validation and Error Messages | None raised |

#### GET /api/v1/ai/usage/trend

| Field | Details |
| --- | --- |
| Function Signature | GET /api/v1/ai/usage/trend → `def get_usage_trend(days, db)` in `app/routers/ai_usage.py` |
| Description | Per-day cost/calls/cache-hit series for the sparkline (grouped by YYYY-MM-DD prefix; portable SQLite/Postgres). |
| Input Parameters | Query `days: int` 1..180 (default 30, "Window length.") |
| Return Values | `TrendResponse {points: list[TrendPoint {day, calls, cost_usd, cache_hits}], ...}`; 200 |
| Validation and Error Messages | 422 auto bounds |

#### GET /api/v1/ai/usage/top-cached

| Field | Details |
| --- | --- |
| Function Signature | GET /api/v1/ai/usage/top-cached → `def get_top_cached_fixes(limit, db)` in `app/routers/ai_usage.py` |
| Description | The N most expensive cache entries by total cost (org-wide; cache is tenant-shared). |
| Input Parameters | Query `limit: int` 1..100 (default 20) |
| Return Values | `list[TopCachedItem {cache_key, vuln_id, component_name, component_version, provider_used, model_used, total_cost_usd, generated_at}]`; 200 |
| Validation and Error Messages | 422 auto bounds |

#### GET /api/v1/ai/metrics

| Field | Details |
| --- | --- |
| Function Signature | GET /api/v1/ai/metrics → `def get_metrics_json()` in `app/routers/ai_usage.py` |
| Description | JSON snapshot of AI telemetry counters/histograms/gauges for the in-app dashboard. |
| Input Parameters | None |
| Return Values | Telemetry snapshot dict; 200 |
| Validation and Error Messages | None raised |

#### GET /api/v1/ai/metrics/prometheus

| Field | Details |
| --- | --- |
| Function Signature | GET /api/v1/ai/metrics/prometheus → `def get_metrics_prometheus()` in `app/routers/ai_usage.py` |
| Description | Prometheus text exposition of the same telemetry (scrape target without prometheus_client dependency). |
| Input Parameters | None |
| Return Values | `PlainTextResponse` (text/plain, Prometheus exposition format); 200 |
| Validation and Error Messages | None raised |

#### GET /api/v1/ai/providers/available

| Field | Details |
| --- | --- |
| Function Signature | GET /api/v1/ai/providers/available → `def get_provider_catalog()` in `app/routers/ai_usage.py` |
| Description | Static catalog of every supported provider (drives the "Add provider" dropdown and form field rendering) — distinct from `/providers` which reflects configured ones. |
| Input Parameters | None |
| Return Values | `list[ProviderCatalogEntry {name, display_name, requires_api_key, requires_base_url, is_local, models, free-tier limits, ...}]`; 200 |
| Validation and Error Messages | None raised |

#### GET /api/v1/ai/providers/available/{name}

| Field | Details |
| --- | --- |
| Function Signature | GET /api/v1/ai/providers/available/{name} → `def get_provider_catalog_entry(name)` in `app/routers/ai_usage.py` |
| Description | Single catalog entry lookup. |
| Input Parameters | Path `name: str` |
| Return Values | `ProviderCatalogEntry`; 200 |
| Validation and Error Messages | 404 `"Unknown provider: '<name>'"` |

#### GET /api/v1/ai/credentials

| Field | Details |
| --- | --- |
| Function Signature | GET /api/v1/ai/credentials → `def list_credentials(db)` in `app/routers/ai_credentials.py` |
| Description | Lists AI provider credential rows. API keys never returned — only `api_key_present` + `api_key_preview`. |
| Input Parameters | None |
| Return Values | `list[CredentialResponse {id, provider_name, label, api_key_present, api_key_preview, base_url, default_model, tier, is_default, is_fallback, enabled, cost_per_1k_input_usd, cost_per_1k_output_usd, is_local, last_test_at/success, created_at, updated_at}]`; 200 |
| Validation and Error Messages | None raised |

#### GET /api/v1/ai/credentials/{cred_id}

| Field | Details |
| --- | --- |
| Function Signature | GET /api/v1/ai/credentials/{cred_id} → `def get_credential(cred_id, db)` in `app/routers/ai_credentials.py` |
| Description | Fetch one credential row (key preview only). |
| Input Parameters | Path `cred_id: int` |
| Return Values | `CredentialResponse`; 200 |
| Validation and Error Messages | 404 `"Credential {cred_id} not found."` |

#### POST /api/v1/ai/credentials

| Field | Details |
| --- | --- |
| Function Signature | POST /api/v1/ai/credentials → `def create_credential(body, request, db)` in `app/routers/ai_credentials.py` |
| Description | Creates a credential; API key `<REDACTED>` is Fernet-encrypted at rest; catalog-compat validated; audit-logged (`credential.create`); config-loader cache invalidated. Default/fallback flags are never set here (explicit promotion endpoints only). |
| Input Parameters | Body `CredentialCreateRequest {provider_name: str 1..32 (required), label: str="default" 1..64, api_key?: str ≤4096 <REDACTED>, base_url?: str ≤512, default_model?: str ≤128, tier: "free"|"paid" = "paid", enabled: bool=true, cost_per_1k_input_usd/output_usd: float=0.0, is_local: bool=false}` (extra forbidden) |
| Return Values | `CredentialResponse`; **201 Created** |
| Validation and Error Messages | 400 `"Unknown provider: '<name>'"`; 400 `"<provider> requires a base URL."`; 400 `"default_model is required."`; 409 `"A credential for (<provider>, <label>) already exists."` |

#### PUT /api/v1/ai/credentials/{cred_id}

| Field | Details |
| --- | --- |
| Function Signature | PUT /api/v1/ai/credentials/{cred_id} → `def update_credential(cred_id, body, request, db)` in `app/routers/ai_credentials.py` |
| Description | Partial update; omitted `api_key` preserves the existing key (clear requires DELETE); audit-logged with changed-field list. |
| Input Parameters | Path `cred_id: int`; body `CredentialUpdateRequest` (all optional: label, api_key `<REDACTED>`, base_url, default_model, tier, enabled, costs) |
| Return Values | `CredentialResponse`; 200 |
| Validation and Error Messages | 404 `"Credential {cred_id} not found."`; catalog-compat 400s as on create |

#### DELETE /api/v1/ai/credentials/{cred_id}

| Field | Details |
| --- | --- |
| Function Signature | DELETE /api/v1/ai/credentials/{cred_id} → `def delete_credential(cred_id, request, db)` in `app/routers/ai_credentials.py` |
| Description | Deletes the credential row; audit-logged (`credential.delete`); loader cache invalidated. |
| Input Parameters | Path `cred_id: int` |
| Return Values | Empty body; **204 No Content** |
| Validation and Error Messages | 404 `"Credential {cred_id} not found."` |

#### PUT /api/v1/ai/credentials/{cred_id}/set-default

| Field | Details |
| --- | --- |
| Function Signature | PUT /api/v1/ai/credentials/{cred_id}/set-default → `def set_default_credential(cred_id, request, db)` in `app/routers/ai_credentials.py` |
| Description | Atomically promotes this credential to the org default (clears the flag on all others). Audit-logged (`credential.set_default`). |
| Input Parameters | Path `cred_id: int` |
| Return Values | `CredentialResponse` (is_default=true); 200 |
| Validation and Error Messages | 404 `"Credential {cred_id} not found."` |

#### PUT /api/v1/ai/credentials/{cred_id}/set-fallback

| Field | Details |
| --- | --- |
| Function Signature | PUT /api/v1/ai/credentials/{cred_id}/set-fallback → `def set_fallback_credential(cred_id, request, db)` in `app/routers/ai_credentials.py` |
| Description | Atomically promotes this credential to the fallback slot. Audit-logged (`credential.set_fallback`). |
| Input Parameters | Path `cred_id: int` |
| Return Values | `CredentialResponse` (is_fallback=true); 200 |
| Validation and Error Messages | 404 `"Credential {cred_id} not found."` |

#### POST /api/v1/ai/credentials/test

| Field | Details |
| --- | --- |
| Function Signature | POST /api/v1/ai/credentials/test → `async def test_unsaved_credential(body, request, db)` in `app/routers/ai_credentials.py` |
| Description | Connection probe against a supplied (un-persisted) provider config. Nothing is saved; audit-logged (`credential.test`). |
| Input Parameters | Body `TestConnectionRequest {provider_name: str 1..32 (required), api_key?: <REDACTED>, base_url?, default_model?, tier: "paid", cost fields, is_local}` (extra forbidden) |
| Return Values | `ConnectionTestResult {success, latency_ms, detected_models[], error_message, error_kind (auth/network/timeout/... enum), provider, model_tested}`; 200 (failures reported in-body, not as HTTP errors) |
| Validation and Error Messages | 400 `"Unknown provider: '<name>'"` (transient-provider build); other build failures → in-body `{success: false, error_kind: "unknown"}` |

#### POST /api/v1/ai/credentials/{cred_id}/test

| Field | Details |
| --- | --- |
| Function Signature | POST /api/v1/ai/credentials/{cred_id}/test → `async def test_saved_credential(cred_id, request, db)` in `app/routers/ai_credentials.py` |
| Description | Re-tests a saved credential; decrypts the stored key in-memory only and stamps `last_test_at`/`last_test_success` on the row. |
| Input Parameters | Path `cred_id: int` |
| Return Values | `ConnectionTestResult`; 200 (decrypt failure → in-body `{success: false, error_message: "Stored credential could not be decrypted; re-enter the key.", error_kind: "auth"}`) |
| Validation and Error Messages | 404 `"Credential {cred_id} not found."` |

#### GET /api/v1/ai/settings

| Field | Details |
| --- | --- |
| Function Signature | GET /api/v1/ai/settings → `def get_singleton_settings(db)` in `app/routers/ai_credentials.py` |
| Description | Reads the singleton AI settings row (feature flag, kill switch, budget caps); returns safe defaults mid-migration instead of 500. |
| Input Parameters | None |
| Return Values | `SettingsResponse {feature_enabled, kill_switch_active, budget_per_request_usd, budget_per_scan_usd, budget_daily_usd, updated_at, updated_by_user_id, source: "db"}`; 200 |
| Validation and Error Messages | None raised |

#### PUT /api/v1/ai/settings

| Field | Details |
| --- | --- |
| Function Signature | PUT /api/v1/ai/settings → `def update_singleton_settings(body, request, db)` in `app/routers/ai_credentials.py` |
| Description | Partial update of AI feature flags and budget caps; enforces the cap ordering invariant; audit-logged. |
| Input Parameters | Body `SettingsUpdateRequest {feature_enabled?, kill_switch_active?, budget_per_request_usd? ≥0, budget_per_scan_usd? ≥0, budget_daily_usd? ≥0}` (extra forbidden) |
| Return Values | `SettingsResponse`; 200 |
| Validation and Error Messages | 400 `"Budget caps must satisfy per_request ≤ per_scan ≤ daily."`; 422 auto for negatives |

---

### Group: Administration — NVD Mirror (`app/nvd_mirror/api.py`, prefix `/admin/nvd-mirror` — note: **no `/api` prefix**)

All **Protected** (router-level). Known TODO in code (Phase 0 §F.17): no admin-role tier exists yet — every authenticated caller can hit these.

#### GET /admin/nvd-mirror/settings

| Field | Details |
| --- | --- |
| Function Signature | GET /admin/nvd-mirror/settings → `def get_settings(repo, db)` in `app/nvd_mirror/api.py` |
| Description | Current mirror settings snapshot; NVD API key is masked in the response. Seeds the singleton row on first read. |
| Input Parameters | None |
| Return Values | `NvdSettingsResponse` (`app/nvd_mirror/schemas.py`) — enabled, api_endpoint, masked api key `<REDACTED>`, download_feeds_enabled, page_size, window_days, min_freshness_hours, last_modified_utc, last_successful_sync_at, updated_at; 200 |
| Validation and Error Messages | None raised |

#### PUT /admin/nvd-mirror/settings

| Field | Details |
| --- | --- |
| Function Signature | PUT /admin/nvd-mirror/settings → `def put_settings(payload, repo, db)` in `app/nvd_mirror/api.py` |
| Description | Partial (PATCH-like) settings update. `clear_api_key=true` clears the key; omitted `api_key` preserves it; key value `<REDACTED>` is Fernet-encrypted at rest. |
| Input Parameters | Body `NvdSettingsUpdate {enabled?, api_endpoint?, api_key?: <REDACTED>, clear_api_key?, download_feeds_enabled?, page_size?, window_days?, min_freshness_hours?}` |
| Return Values | `NvdSettingsResponse`; 200 |
| Validation and Error Messages | 503 `"Fernet key not configured — cannot persist API key. <exc>"` |

#### POST /admin/nvd-mirror/sync

| Field | Details |
| --- | --- |
| Function Signature | POST /admin/nvd-mirror/sync → `def trigger_sync()` in `app/nvd_mirror/api.py` |
| Description | Enqueues the `mirror_nvd` Celery task for immediate execution (operator-initiated; Beat also fires hourly). |
| Input Parameters | None |
| Return Values | `SyncTriggerResponse {task_id, status: "queued"}`; **202 Accepted** |
| Validation and Error Messages | 503 `"Failed to enqueue mirror task: <exc>"` (Redis/broker down) |

#### GET /admin/nvd-mirror/sync/status

| Field | Details |
| --- | --- |
| Function Signature | GET /admin/nvd-mirror/sync/status → `def get_sync_status(repo)` in `app/nvd_mirror/api.py` |
| Description | Last 10 `sync_run` rows (status, counts, timing) for the mirror admin panel. |
| Input Parameters | None |
| Return Values | `list[SyncRunResponse]`; 200 |
| Validation and Error Messages | None raised |

#### POST /admin/nvd-mirror/watermark/reset

| Field | Details |
| --- | --- |
| Function Signature | POST /admin/nvd-mirror/watermark/reset → `def reset_watermark(repo, db)` in `app/nvd_mirror/api.py` |
| Description | Sets `last_modified_utc = NULL` so the next `mirror_nvd` run performs a full re-bootstrap. |
| Input Parameters | None |
| Return Values | `NvdSettingsResponse` (post-reset snapshot); 200 |
| Validation and Error Messages | None raised |

---

## 3. Endpoint index (all 204 decorator-defined endpoints)

Auth legend: `Public` = no auth; `require_auth` = token check only; `Protected` = router-level `enforce_request_access` (token + tenant + permission); `+perm:X` = additional `require_permission("X")`.

| # | Method | Path | Function | Auth | Group |
| --- | --- | --- | --- | --- | --- |
| 1 | GET | / | `service_info` (health.py) | Public | Health and Diagnostics |
| 2 | GET | /health | `health` (health.py) | Public | Health and Diagnostics |
| 3 | GET | /api/analysis/config | `get_analysis_config` (health.py) | require_auth | Health and Diagnostics |
| 4 | GET | /api/types | `list_sbom_types` (health.py) | require_auth | Health and Diagnostics |
| 5 | GET | /api/sboms/{sbom_id} | `get_sbom` (sboms_crud.py) | Protected | SBOM Management |
| 6 | POST | /api/sboms/{sbom_id}/workspace | `create_sbom_workspace` (sboms_crud.py) | Protected +perm:sbom:repair:update | SBOM Management |
| 7 | GET | /api/sboms/{sbom_id}/stats | `get_sbom_document_stats` (sboms_crud.py) | Protected | SBOM Management |
| 8 | GET | /api/sboms/{sbom_id}/raw | `get_sbom_raw_chunk` (sboms_crud.py) | Protected | SBOM Management |
| 9 | GET | /api/sboms/{sbom_id}/download | `download_sbom_original` (sboms_crud.py) | Protected | SBOM Management |
| 10 | POST | /api/sboms | `create_sbom` (sboms_crud.py) | Protected | SBOM Management |
| 11 | GET | /api/sboms | `get_sbom_details` (sboms_crud.py) | Protected | SBOM Management |
| 12 | GET | /api/sboms/{sbom_id}/components | `get_sbom_components` (sboms_crud.py) | Protected | SBOM Management |
| 13 | POST | /api/sboms/{sbom_id}/components/reprocess | `reprocess_sbom_components` (sboms_crud.py) | Protected | SBOM Management |
| 14 | POST | /api/sboms/{sbom_id}/normalize-deduplicate | `normalize_deduplicate_sbom` (sboms_crud.py) | Protected +perm:sbom:update | SBOM Management |
| 15 | GET | /api/sboms/{sbom_id}/dedupe-report | `get_sbom_dedupe_report` (sboms_crud.py) | Protected | SBOM Management |
| 16 | GET | /api/sboms/{sbom_id}/normalization-report | `get_sbom_normalization_report` (sboms_crud.py) | Protected | SBOM Management |
| 17 | PATCH | /api/sboms/{sbom_id} | `update_sbom` (sboms_crud.py) | Protected | SBOM Management |
| 18 | GET | /api/sboms/{sbom_id}/delete-impact | `sbom_delete_impact` (sboms_crud.py) | Protected | SBOM Management |
| 19 | DELETE | /api/sboms/{sbom_id} | `delete_sbom` (sboms_crud.py) | Protected | SBOM Management |
| 20 | POST | /api/sboms/{sbom_id}/restore | `restore_sbom` (sboms_crud.py) | Protected | SBOM Management |
| 21 | POST | /api/sboms/{sbom_id}/revalidate | `revalidate_sbom` (sboms_crud.py) | Protected | SBOM Management |
| 22 | POST | /api/sboms/{sbom_id}/analyze | `run_analysis_for_sbom` (sboms_crud.py) | Protected | SBOM Management / Analysis Runs |
| 23 | POST | /api/sboms/{sbom_id}/analyze/stream | `analyze_sbom_stream` (sboms_crud.py) — SSE | Protected | SBOM Management / Analysis Runs |
| 24 | GET | /api/sboms/{sbom_id}/analysis-runs | `list_sbom_analysis_runs` (sboms_crud.py) | Protected | SBOM Management / Analysis Runs |
| 25 | POST | /api/sboms/upload | `upload_sbom` (sbom_upload.py) — multipart | Protected | SBOM Management |
| 26 | GET | /api/sboms/{sbom_id}/risk-summary | `get_sbom_risk_summary` (sbom.py) | Protected | SBOM Management |
| 27 | GET | /api/sboms/{sbom_id}/validation-report | `get_sbom_validation_report` (sbom.py) | Protected | SBOM Management |
| 28 | GET | /api/sboms/{sbom_id}/info | `get_sbom_info` (sbom.py) | Protected | SBOM Management |
| 29 | POST | /api/sboms/{id}/edit | `edit_sbom_endpoint` (sbom_versions.py) | Protected | SBOM Management |
| 30 | GET | /api/sboms/{id}/versions | `get_sbom_versions` (sbom_versions.py) | Protected | SBOM Management |
| 31 | GET | /api/sboms/compare-versions | `compare_sbom_versions` (sbom_versions.py) | Protected | SBOM Management |
| 32 | POST | /api/sboms/{id}/restore/{version_id} | `restore_sbom_version` (sbom_versions.py) | Protected | SBOM Management |
| 33 | POST | /api/sboms/{id}/lifecycle/refresh | `refresh_sbom_lifecycle` (sbom_versions.py) | Protected | Lifecycle |
| 34 | GET | /api/sboms/{id}/lifecycle | `list_sbom_lifecycle` (sbom_versions.py) | Protected | Lifecycle |
| 35 | GET | /api/sboms/{id}/lifecycle/report | `get_sbom_lifecycle_report` (sbom_versions.py) — CSV/OpenEoX download | Protected | Lifecycle / Export |
| 36 | GET | /api/sboms/{id}/reports/lifecycle-pack | `get_lifecycle_report_pack` (sbom_versions.py) — ZIP download | Protected | Lifecycle / Export |
| 37 | POST | /api/sboms/{id}/convert/cyclonedx | `convert_spdx_to_cyclonedx_endpoint` (sbom_versions.py) | Protected | SBOM Management |
| 38 | GET | /api/sboms/{id}/conversion-report | `get_conversion_report` (sbom_versions.py) | Protected | SBOM Management |
| 39 | GET | /api/sboms/{sbom_id}/reports/vulnerabilities.xlsx | `export_sbom_vulnerabilities_excel` (sbom_versions.py) — Excel download | Protected | Export and Reporting |
| 40 | GET | /api/sboms/{id}/export | `export_sbom` (sbom_versions.py) — file download | Protected | Export and Reporting |
| 41 | GET | /api/sboms/{id}/lifecycle/diagnostics | `get_sbom_lifecycle_diagnostics` (sbom_versions.py) | Protected | Lifecycle |
| 42 | GET | /api/sbom-validation-sessions/{session_id} | `get_validation_session` (sbom_validation_sessions.py) | Protected | SBOM Management (Repair) |
| 43 | GET | /api/sbom-validation-sessions/{session_id}/content | `get_validation_session_content` | Protected | SBOM Management (Repair) |
| 44 | GET | /api/sbom-validation-sessions/{session_id}/content/chunk | `get_validation_session_content_chunk` | Protected | SBOM Management (Repair) |
| 45 | GET | /api/sbom-validation-sessions/{session_id}/content-lines | `get_validation_session_content_lines` | Protected | SBOM Management (Repair) |
| 46 | GET | /api/sbom-validation-sessions/{session_id}/content/lines | `get_validation_session_content_lines_alias` | Protected | SBOM Management (Repair) |
| 47 | GET | /api/sbom-validation-sessions/{session_id}/download-original | `download_original_validation_session` — file download | Protected | SBOM Management (Repair) |
| 48 | GET | /api/sbom-validation-sessions/{session_id}/download-repair-draft | `download_repair_draft_validation_session` — file download | Protected | SBOM Management (Repair) |
| 49 | GET | /api/sbom-validation-sessions/{session_id}/search | `search_validation_session` | Protected | SBOM Management (Repair) |
| 50 | PATCH | /api/sbom-validation-sessions/{session_id} | `update_validation_session` | Protected | SBOM Management (Repair) |
| 51 | PUT | /api/sbom-validation-sessions/{session_id}/repair-draft | `save_repair_draft` | Protected | SBOM Management (Repair) |
| 52 | POST | /api/sbom-validation-sessions/{session_id}/validate | `validate_session` | Protected | SBOM Management (Repair) |
| 53 | POST | /api/sbom-validation-sessions/{session_id}/revalidate | `revalidate_session` | Protected | SBOM Management (Repair) |
| 54 | POST | /api/sbom-validation-sessions/{session_id}/import | `import_session` | Protected | SBOM Management (Repair) |
| 55 | POST | /api/sbom-validation-sessions/{session_id}/ai/suggest-fixes | `suggest_fixes` | Protected | AI Remediation (Repair) |
| 56 | POST | /api/sbom-validation-sessions/{session_id}/apply-patch | `apply_patch` | Protected | SBOM Management (Repair) |
| 57 | POST | /api/sbom-validation-sessions/{session_id}/repair/patches | `apply_line_patches` | Protected | SBOM Management (Repair) |
| 58 | GET | /api/sbom-validation-sessions/{session_id}/history | `session_history` | Protected | SBOM Management (Repair) |
| 59 | GET | /api/runs | `list_analysis_runs` (runs.py) | Protected | Analysis Runs |
| 60 | GET | /api/runs/aggregate | `runs_aggregate_endpoint` (runs.py) | Protected | Analysis Runs |
| 61 | GET | /api/runs/recent | `list_recent_runs` (runs.py) | Protected | Analysis Runs |
| 62 | GET | /api/runs/search | `search_runs` (runs.py) | Protected | Analysis Runs |
| 63 | GET | /api/runs/{run_id} | `get_analysis_run` (runs.py) | Protected | Analysis Runs |
| 64 | GET | /api/runs/{run_id}/findings | `list_run_findings` (runs.py) | Protected | Findings |
| 65 | GET | /api/runs/{run_id}/findings-enriched | `list_run_findings_enriched` (runs.py) | Protected | Findings |
| 66 | POST | /analyze-sbom-nvd | `analyze_sbom_nvd` (analyze_endpoints.py) | Protected | Analysis Runs |
| 67 | POST | /analyze-sbom-github | `analyze_sbom_github` (analyze_endpoints.py) | Protected | Analysis Runs |
| 68 | POST | /analyze-sbom-osv | `analyze_sbom_osv` (analyze_endpoints.py) | Protected | Analysis Runs |
| 69 | POST | /analyze-sbom-vulndb | `analyze_sbom_vulndb` (analyze_endpoints.py) | Protected | Analysis Runs |
| 70 | POST | /analyze-sbom-consolidated | `analyze_sbom_consolidated` (analyze_endpoints.py) | Protected | Analysis Runs |
| 71 | GET | /api/analysis-runs/compare | `compare_analysis_runs` (analysis.py) — DEPRECATED | Protected | Analysis Runs |
| 72 | GET | /api/analysis-runs/{run_id}/export/sarif | `export_sarif` (analysis.py) — file download | Protected | Export and Reporting |
| 73 | GET | /api/analysis-runs/{run_id}/export/csv | `export_csv` (analysis.py) — file download | Protected | Export and Reporting |
| 74 | POST | /api/v1/compare | `compare_runs` (compare.py) | Protected | Analysis Runs |
| 75 | POST | /api/v1/compare/{cache_key}/export | `export_compare` (compare.py) — file download | Protected | Analysis Runs / Export |
| 76 | POST | /api/sboms/{sbom_id}/vex | `upload_vex_document` (vex.py) | Protected | Findings (VEX) |
| 77 | GET | /api/sboms/{sbom_id}/vex | `get_vex_statements` (vex.py) | Protected | Findings (VEX) |
| 78 | GET | /api/sboms/{sbom_id}/vex/report | `get_vex_report` (vex.py) — CSV option | Protected | Findings (VEX) / Export |
| 79 | GET | /api/sboms/{sbom_id}/reports/vex-pack | `get_vex_report_pack` (vex.py) — ZIP download | Protected | Findings (VEX) / Export |
| 80 | POST | /api/sboms/{sbom_id}/vex/discover | `discover_vex_documents` (vex.py) | Protected | Findings (VEX) |
| 81 | PATCH | /api/components/{component_id}/vulnerabilities/{vulnerability_id}/vex-override | `patch_vex_override` (vex.py) | Protected | Findings (VEX) |
| 82 | GET | /api/components/{component_id}/vulnerabilities/{vulnerability_id}/vex-override/history | `get_vex_override_history` (vex.py) | Protected | Findings (VEX) |
| 83 | GET | /api/remediation/project/{project_id} | `get_project_remediations` (remediation.py) | Protected | Findings (Remediation) |
| 84 | GET | /api/remediation/finding/{finding_id} | `get_finding_remediation` (remediation.py) | Protected | Findings (Remediation) |
| 85 | GET | /api/remediation/{remediation_id}/history | `get_remediation_history` (remediation.py) | Protected | Findings (Remediation) |
| 86 | POST | /api/remediation | `upsert_remediation` (remediation.py) | Protected | Findings (Remediation) |
| 87 | POST | /api/pdf-report | `create_pdf_report_by_run_id` (pdf.py) — PDF download | Protected | Export and Reporting |
| 88 | POST | /api/projects/{project_id}/reports/fda-510k-sbom/export | `export_fda_510k_sbom_report` (reports.py) — Excel download | Protected | Export and Reporting |
| 89 | POST | /api/projects | `create_project` (projects.py) | Protected | Administration (Projects) |
| 90 | GET | /api/projects/{project_id} | `get_project_details` (projects.py) | Protected | Administration (Projects) |
| 91 | GET | /api/projects | `list_projects` (projects.py) | Protected | Administration (Projects) |
| 92 | PATCH | /api/projects/{project_id} | `update_project` (projects.py) | Protected | Administration (Projects) |
| 93 | GET | /api/projects/{project_id}/delete-impact | `project_delete_impact` (projects.py) | Protected | Administration (Projects) |
| 94 | DELETE | /api/projects/{project_id} | `delete_project` (projects.py) | Protected | Administration (Projects) |
| 95 | POST | /api/projects/{project_id}/restore | `restore_project` (projects.py) | Protected | Administration (Projects) |
| 96 | POST | /api/projects/{project_id}/products | `create_product` (products.py) | Protected | Administration (Products) |
| 97 | GET | /api/projects/{project_id}/products | `list_project_products` (products.py) | Protected | Administration (Products) |
| 98 | GET | /api/products/{product_id} | `get_product` (products.py) | Protected | Administration (Products) |
| 99 | PATCH | /api/products/{product_id} | `update_product` (products.py) | Protected | Administration (Products) |
| 100 | DELETE | /api/products/{product_id} | `delete_product` (products.py) | Protected | Administration (Products) |
| 101 | GET | /api/products/{product_id}/sboms | `list_product_sboms` (products.py) | Protected | Administration (Products) |
| 102 | GET | /dashboard/stats | `dashboard_stats` (dashboard_main.py) | Protected | Dashboard |
| 103 | GET | /dashboard/recent-sboms | `dashboard_recent_sboms` (dashboard_main.py) | Protected | Dashboard |
| 104 | GET | /dashboard/activity | `dashboard_activity` (dashboard_main.py) | Protected | Dashboard |
| 105 | GET | /dashboard/severity | `dashboard_severity` (dashboard_main.py) | Protected | Dashboard |
| 106 | GET | /dashboard/posture | `dashboard_posture` (dashboard_main.py) | Protected | Dashboard |
| 107 | GET | /dashboard/vulnerability-age | `dashboard_vulnerability_age` (dashboard_main.py) | Protected | Dashboard |
| 108 | GET | /dashboard/lifetime | `dashboard_lifetime` (dashboard_main.py) | Protected | Dashboard |
| 109 | GET | /dashboard/lifecycle | `get_dashboard_lifecycle` (dashboard_main.py) | Protected | Dashboard |
| 110 | GET | /dashboard/vex | `get_dashboard_vex` (dashboard_main.py) | Protected | Dashboard |
| 111 | GET | /dashboard/health | `get_dashboard_health` (dashboard_main.py) | Protected | Dashboard |
| 112 | GET | /dashboard/remediation-stats | `get_dashboard_remediation_stats` (dashboard_main.py) | Protected | Dashboard |
| 113 | GET | /dashboard/summary | `get_dashboard_summary` (dashboard_main.py) | Protected | Dashboard |
| 114 | GET | /dashboard/forecast | `dashboard_forecast` (dashboard_advanced.py) | Protected | Dashboard |
| 115 | GET | /dashboard/exploitation | `dashboard_exploitation` (dashboard_advanced.py) | Protected | Dashboard |
| 116 | GET | /dashboard/remediation | `dashboard_remediation` (dashboard_advanced.py) | Protected | Dashboard |
| 117 | GET | /dashboard/risk-map | `dashboard_risk_map` (dashboard_advanced.py) | Protected | Dashboard |
| 118 | GET | /dashboard/risk-matrix | `dashboard_risk_matrix` (dashboard_advanced.py) | Protected | Dashboard |
| 119 | GET | /dashboard/trend | `dashboard_trend` (dashboard.py) | Protected | Dashboard |
| 120 | POST | /api/projects/{project_id}/schedule | `upsert_project_schedule` (schedules.py) | Protected | Schedules |
| 121 | GET | /api/projects/{project_id}/schedule | `get_project_schedule` (schedules.py) | Protected | Schedules |
| 122 | PATCH | /api/projects/{project_id}/schedule | `patch_project_schedule` (schedules.py) | Protected | Schedules |
| 123 | DELETE | /api/projects/{project_id}/schedule | `delete_project_schedule` (schedules.py) | Protected | Schedules |
| 124 | POST | /api/products/{product_id}/schedule | `upsert_product_schedule` (schedules.py) | Protected | Schedules |
| 125 | GET | /api/products/{product_id}/schedule | `get_product_schedule` (schedules.py) | Protected | Schedules |
| 126 | PATCH | /api/products/{product_id}/schedule | `patch_product_schedule` (schedules.py) | Protected | Schedules |
| 127 | DELETE | /api/products/{product_id}/schedule | `delete_product_schedule` (schedules.py) | Protected | Schedules |
| 128 | POST | /api/sboms/{sbom_id}/schedule | `upsert_sbom_schedule` (schedules.py) | Protected | Schedules |
| 129 | GET | /api/sboms/{sbom_id}/schedule | `get_sbom_schedule` (schedules.py) | Protected | Schedules |
| 130 | PATCH | /api/sboms/{sbom_id}/schedule | `patch_sbom_schedule` (schedules.py) | Protected | Schedules |
| 131 | DELETE | /api/sboms/{sbom_id}/schedule | `delete_sbom_schedule` (schedules.py) | Protected | Schedules |
| 132 | GET | /api/schedules | `list_schedules` (schedules.py) | Protected | Schedules |
| 133 | POST | /api/schedules/{schedule_id}/pause | `pause_schedule` (schedules.py) | Protected | Schedules |
| 134 | POST | /api/schedules/{schedule_id}/resume | `resume_schedule` (schedules.py) | Protected | Schedules |
| 135 | POST | /api/schedules/{schedule_id}/run-now | `run_schedule_now` (schedules.py) | Protected | Schedules |
| 136 | GET | /api/v1/cves/{cve_id} | `get_cve_detail` (cves.py) | Protected | CVE and Enrichment |
| 137 | POST | /api/v1/cves/batch | `batch_cve_detail` (cves.py) | Protected | CVE and Enrichment |
| 138 | GET | /api/v1/scans/{scan_id}/cves/{cve_id} | `get_cve_detail_with_scan_context` (cves.py) | Protected | CVE and Enrichment |
| 139 | GET | /api/lifecycle/sources | `list_lifecycle_sources` (lifecycle.py) | Protected | Lifecycle |
| 140 | GET | /api/lifecycle/provider-status | `lifecycle_provider_status` (lifecycle.py) | Protected | Lifecycle |
| 141 | GET | /api/lifecycle/component/{component_id} | `get_component_lifecycle` (lifecycle.py) | Protected | Lifecycle |
| 142 | PUT | /api/lifecycle/component/{component_id} | `update_component_lifecycle` (lifecycle.py) | Protected | Lifecycle |
| 143 | PATCH | /api/components/{component_id}/lifecycle-override | `patch_component_lifecycle_override` (lifecycle.py) | Protected | Lifecycle |
| 144 | POST | /api/components/{component_id}/lifecycle/refresh | `refresh_component_lifecycle_endpoint` (lifecycle.py) | Protected | Lifecycle |
| 145 | GET | /api/admin/lifecycle-providers | `list_lifecycle_providers` (lifecycle_admin.py) | Protected +perm:lifecycle:provider:read | Administration |
| 146 | PUT | /api/admin/lifecycle-providers/{provider_key} | `update_lifecycle_provider` (lifecycle_admin.py) | Protected +perm:lifecycle:provider:update | Administration |
| 147 | PUT | /api/admin/lifecycle-providers/{provider_key}/secret | `put_lifecycle_provider_secret` (lifecycle_admin.py) | Protected +perm:lifecycle:provider:update | Administration |
| 148 | DELETE | /api/admin/lifecycle-providers/{provider_key}/secret/{secret_name} | `delete_lifecycle_provider_secret` (lifecycle_admin.py) | Protected +perm:lifecycle:provider:update | Administration |
| 149 | POST | /api/admin/lifecycle-providers/{provider_key}/test | `test_lifecycle_provider` (lifecycle_admin.py) | Protected +perm:lifecycle:provider:test | Administration |
| 150 | POST | /api/admin/lifecycle-providers/{provider_key}/sync | `sync_lifecycle_provider` (lifecycle_admin.py) | Protected +perm:lifecycle:provider:sync | Administration |
| 151 | GET | /api/admin/lifecycle-vendor-records | `list_lifecycle_vendor_records` (lifecycle_admin.py) | Protected +perm:lifecycle:vendor-record:read | Administration |
| 152 | POST | /api/admin/lifecycle-vendor-records | `create_lifecycle_vendor_record` (lifecycle_admin.py) | Protected +perm:lifecycle:vendor-record:write | Administration |
| 153 | PUT | /api/admin/lifecycle-vendor-records/{record_id} | `update_lifecycle_vendor_record` (lifecycle_admin.py) | Protected +perm:lifecycle:vendor-record:write | Administration |
| 154 | DELETE | /api/admin/lifecycle-vendor-records/{record_id} | `delete_lifecycle_vendor_record` (lifecycle_admin.py) | Protected +perm:lifecycle:vendor-record:delete | Administration |
| 155 | POST | /api/admin/lifecycle-vendor-records/import | `import_lifecycle_vendor_records` (lifecycle_admin.py) | Protected +perm:lifecycle:vendor-record:write | Administration |
| 156 | GET | /api/admin/lifecycle-vendor-records/export | `export_lifecycle_vendor_records` (lifecycle_admin.py) | Protected +perm:lifecycle:vendor-record:read | Administration |
| 157 | GET | /api/auth/me | `auth_me` (tenants.py) | Protected | Authentication |
| 158 | GET | /api/tenants | `list_my_tenants` (tenants.py) | Protected | Authentication |
| 159 | POST | /api/tenants | `create_tenant` (tenants.py) | Protected +perm:platform:admin | Authentication |
| 160 | GET | /api/tenants/{tenant_id}/users | `list_tenant_users` (tenants.py) | Protected +perm:tenant:user:read | Authentication |
| 161 | POST | /api/tenants/{tenant_id}/users | `add_tenant_user` (tenants.py) | Protected +perm:tenant:user:invite | Authentication |
| 162 | PATCH | /api/tenants/{tenant_id}/users/{membership_id} | `update_tenant_user` (tenants.py) | Protected +perm:tenant:user:update | Authentication |
| 163 | POST | /api/v1/runs/{run_id}/ai-fixes | `trigger_run_fixes` (ai_fixes.py) | Protected + AI gate | AI Remediation |
| 164 | GET | /api/v1/runs/{run_id}/ai-fixes/estimate | `estimate_run_duration_legacy` (ai_fixes.py) — DEPRECATED | Protected | AI Remediation |
| 165 | POST | /api/v1/runs/{run_id}/ai-fixes/estimate | `estimate_run_duration` (ai_fixes.py) | Protected | AI Remediation |
| 166 | GET | /api/v1/runs/{run_id}/ai-fixes/batches | `list_run_batches` (ai_fixes.py) | Protected | AI Remediation |
| 167 | GET | /api/v1/runs/{run_id}/ai-fixes/batches/{batch_id} | `get_run_batch` (ai_fixes.py) | Protected | AI Remediation |
| 168 | GET | /api/v1/runs/{run_id}/ai-fixes/batches/{batch_id}/stream | `stream_batch_progress` (ai_fixes.py) — SSE | Protected | AI Remediation |
| 169 | POST | /api/v1/runs/{run_id}/ai-fixes/batches/{batch_id}/cancel | `cancel_run_batch` (ai_fixes.py) | Protected | AI Remediation |
| 170 | GET | /api/v1/runs/{run_id}/ai-fixes/progress | `get_progress` (ai_fixes.py) — DEPRECATED | Protected | AI Remediation |
| 171 | POST | /api/v1/runs/{run_id}/ai-fixes/cancel | `cancel_run_fixes_legacy` (ai_fixes.py) — DEPRECATED | Protected | AI Remediation |
| 172 | GET | /api/v1/runs/{run_id}/ai-fixes/stream | `stream_progress_legacy` (ai_fixes.py) — DEPRECATED, SSE | Protected | AI Remediation |
| 173 | GET | /api/v1/runs/{run_id}/ai-fixes | `list_run_fixes` (ai_fixes.py) | Protected | AI Remediation |
| 174 | GET | /api/v1/findings/{finding_id}/ai-fix | `get_finding_fix` (ai_fixes.py) | Protected + AI gate | AI Remediation |
| 175 | POST | /api/v1/findings/{finding_id}/ai-fix | `generate_finding_fix` (ai_fixes.py) | Protected + AI gate | AI Remediation |
| 176 | POST | /api/v1/findings/{finding_id}/ai-fix:regenerate | `regenerate_finding_fix` (ai_fixes.py) | Protected + AI gate | AI Remediation |
| 177 | GET | /api/ai/copilot/briefing | `copilot_briefing` (ai_copilot.py) | Protected + AI gate | AI Remediation |
| 178 | POST | /api/ai/copilot/ask | `copilot_ask` (ai_copilot.py) | Protected + AI gate | AI Remediation |
| 179 | GET | /api/v1/ai/usage | `get_ai_usage` (ai_usage.py) | Protected | AI Remediation |
| 180 | GET | /api/v1/ai/providers | `list_providers` (ai_usage.py) | Protected | AI Remediation |
| 181 | GET | /api/v1/ai/pricing | `list_pricing` (ai_usage.py) | Protected | AI Remediation |
| 182 | POST | /api/v1/ai/registry/reset | `reset_provider_registry` (ai_usage.py) | Protected | AI Remediation |
| 183 | GET | /api/v1/ai/usage/trend | `get_usage_trend` (ai_usage.py) | Protected | AI Remediation |
| 184 | GET | /api/v1/ai/usage/top-cached | `get_top_cached_fixes` (ai_usage.py) | Protected | AI Remediation |
| 185 | GET | /api/v1/ai/metrics | `get_metrics_json` (ai_usage.py) | Protected | AI Remediation / Diagnostics |
| 186 | GET | /api/v1/ai/metrics/prometheus | `get_metrics_prometheus` (ai_usage.py) — text/plain | Protected | AI Remediation / Diagnostics |
| 187 | GET | /api/v1/ai/providers/available | `get_provider_catalog` (ai_usage.py) | Protected | AI Remediation |
| 188 | GET | /api/v1/ai/providers/available/{name} | `get_provider_catalog_entry` (ai_usage.py) | Protected | AI Remediation |
| 189 | GET | /api/v1/ai/credentials | `list_credentials` (ai_credentials.py) | Protected | AI Remediation |
| 190 | GET | /api/v1/ai/credentials/{cred_id} | `get_credential` (ai_credentials.py) | Protected | AI Remediation |
| 191 | POST | /api/v1/ai/credentials | `create_credential` (ai_credentials.py) | Protected | AI Remediation |
| 192 | PUT | /api/v1/ai/credentials/{cred_id} | `update_credential` (ai_credentials.py) | Protected | AI Remediation |
| 193 | DELETE | /api/v1/ai/credentials/{cred_id} | `delete_credential` (ai_credentials.py) | Protected | AI Remediation |
| 194 | PUT | /api/v1/ai/credentials/{cred_id}/set-default | `set_default_credential` (ai_credentials.py) | Protected | AI Remediation |
| 195 | PUT | /api/v1/ai/credentials/{cred_id}/set-fallback | `set_fallback_credential` (ai_credentials.py) | Protected | AI Remediation |
| 196 | POST | /api/v1/ai/credentials/test | `test_unsaved_credential` (ai_credentials.py) | Protected | AI Remediation |
| 197 | POST | /api/v1/ai/credentials/{cred_id}/test | `test_saved_credential` (ai_credentials.py) | Protected | AI Remediation |
| 198 | GET | /api/v1/ai/settings | `get_singleton_settings` (ai_credentials.py) | Protected | AI Remediation |
| 199 | PUT | /api/v1/ai/settings | `update_singleton_settings` (ai_credentials.py) | Protected | AI Remediation |
| 200 | GET | /admin/nvd-mirror/settings | `get_settings` (nvd_mirror/api.py) | Protected | Administration (NVD Mirror) |
| 201 | PUT | /admin/nvd-mirror/settings | `put_settings` (nvd_mirror/api.py) | Protected | Administration (NVD Mirror) |
| 202 | POST | /admin/nvd-mirror/sync | `trigger_sync` (nvd_mirror/api.py) | Protected | Administration (NVD Mirror) |
| 203 | GET | /admin/nvd-mirror/sync/status | `get_sync_status` (nvd_mirror/api.py) | Protected | Administration (NVD Mirror) |
| 204 | POST | /admin/nvd-mirror/watermark/reset | `reset_watermark` (nvd_mirror/api.py) | Protected | Administration (NVD Mirror) |

**Plus 34 alias routes** (registered via `add_api_route`, not decorators — same handlers, params, auth, and errors as rows 42–58): each of the 17 validation-session endpoints is mirrored under `/api/validation-sessions/...` (17 routes) and `/api/sbom-workspaces/...` (17 routes). Total HTTP routes registered at runtime: **238** (204 decorator-defined + 34 aliases).
