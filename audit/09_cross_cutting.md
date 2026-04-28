# Phase 5 — Cross-Cutting Audit

> Drift between BE Pydantic schemas and FE TypeScript types, naming coherence, error envelopes, auth/CSRF posture, and the test pyramid.

---

## 1. API contract drift (BE Pydantic ↔ FE TypeScript)

For each endpoint that flows typed data to the frontend, I compared the Pydantic `*Out` schema against the matching TS interface. Every drift below is either (a) **fix the BE** to match the FE expectation, or (b) **fix the FE** to match the BE response.

### Finding CC-001: `AnalysisRun` shape drift

- **Severity:** Medium
- **Location:** [app/schemas.py:97-117](../app/schemas.py); [frontend/src/types/index.ts:42-62](../frontend/src/types/index.ts)
- **Drift:**

| Field | BE (`AnalysisRunOut`) | FE (`AnalysisRun`) | Notes |
|---|---|---|---|
| `id` | `int` | `number` | OK |
| `sbom_id` | `int` | `number \| null` | BE never returns null |
| `project_id` | `int \| None` | `number \| null` | OK |
| `run_status` | `str` | closed union of 7 | **BE writes `"BACKFILL"` and others outside the union** (see SOLID-LSP-002) |
| `sbom_name` | `str \| None` | `string \| null` | OK |
| `source` | `str` | `string \| null` | BE never returns null |
| `started_on` | `str` | `string \| null` | OK (BE always sets) |
| `completed_on` | `str` | `string \| null` | OK |
| `duration_ms` | `int` | `number \| null` | OK |
| `total_components` … `unknown_count`, `query_error_count` | `int` | `number \| null` | OK (BE has defaults; FE defensive) |
| `raw_report` | `str \| None` | **MISSING on FE** | FE doesn't surface; OK |
| **`error_message`** | **NOT IN BE** | `string \| null` | **FE expects, BE never sends** |

- **Recommended fix:**
  1. Tighten `run_status` to a `Literal[...]` enum in BE (cross with SOLID-LSP-002).
  2. Drop `error_message` from the FE type (verified zero readers besides the type definition).
  3. Frontend should treat `sbom_id`, `source`, `total_components`, etc. as non-nullable since BE always sends. (Optional — defensive nullability isn't harmful.)
- **Effort:** S
- **Risk of fix:** Low.

### Finding CC-002: `SBOMSource` shape drift

- **Severity:** Low
- **Location:** [app/schemas.py:68-79](../app/schemas.py); [frontend/src/types/index.ts:12-28](../frontend/src/types/index.ts)
- **Drift:**

| Field | BE (`SBOMSourceOut`) | FE (`SBOMSource`) | Notes |
|---|---|---|---|
| `id`, `sbom_name`, `sbom_data`, `sbom_type`, `projectid`, `sbom_version`, `created_by`, `created_on`, `productver`, `modified_by`, `modified_on` | matches | matches | OK |
| **`project_name`** | **NOT IN BE** | `string \| null` (optional) | FE expects, BE doesn't send |
| `_analysisStatus` | n/a | client-only | OK (`_` prefix) |
| `_findingsCount` | n/a | client-only | OK |

- **Note:** `project_name` would be useful on the SBOM list — currently `routers/dashboard_main.py:50-51` returns `{id, sbom_name, created_on}` only; full `GET /api/sboms` returns `SBOMSourceOut` without project name. The FE either fetches projects separately and joins client-side or this field is dead.
- **Recommended fix:** Either add a `project_name` lateral-join in the BE list endpoint OR drop the field from FE. Verify which the analysis page expects — appears unused per FE inspection.
- **Effort:** S
- **Risk of fix:** Low.

### Finding CC-003: `AnalysisFinding` shape drift

- **Severity:** Medium
- **Location:** [app/schemas.py:119-140](../app/schemas.py); [frontend/src/types/index.ts:64-82](../frontend/src/types/index.ts)
- **Drift:**

| Field | BE (`AnalysisFindingOut`) | FE (`AnalysisFinding`) | Notes |
|---|---|---|---|
| `id`, `analysis_run_id` | matches | matches | OK |
| `vuln_id` | `str` | `string \| null` | BE writes `"UNKNOWN-CVE"` fallback (services/analysis_service.py:184) — never null |
| **`title`** | `str \| None` | **MISSING on FE** | FE doesn't render; OK |
| `description`, `severity`, `score`, `vector`, `published_on`, `reference_url`, `cwe`, `cpe`, `component_name`, `component_version`, `attack_vector` | matches | matches (all `\| null`) | OK |
| `fixed_versions` | `str \| None` (raw JSON string) | `string \| null` (raw JSON string) | **OK in shape, but BE-008 issue: should be native array** |
| `aliases` | `str \| None` | `string \| null` | Same — JSON-as-string |
| **`cvss_version`** | `str \| None` | **MISSING on FE** | BE-side enrichment, FE doesn't render |
| **`component_id`** | `int \| None` | **MISSING on FE** | OK — internal ref |

- **Recommended fix:**
  1. After BE-008 (native JSON columns), `fixed_versions: list[str]` and `aliases: list[str]` on the BE → matching `string[]` on FE → drop the FE `JSON.parse(...)` in `FindingsTable.tsx`.
  2. Add `title`, `cvss_version` to FE if the UI wants to surface them; otherwise drop from `AnalysisFindingOut`.
- **Effort:** M (after BE-008)
- **Risk of fix:** Low.

### Finding CC-004: `Project` / `ProjectOut` matches but unused fields

- **Severity:** none — verified.
- **Location:** [app/schemas.py:31-39](../app/schemas.py); [frontend/src/types/index.ts:1-10](../frontend/src/types/index.ts).
- **Note:** Field-for-field match. **Status:** No drift.

### Finding CC-005: `SBOMComponent` shape drift

- **Severity:** Low
- **Location:** [app/schemas.py:82-94](../app/schemas.py); [frontend/src/types/index.ts:30-40](../frontend/src/types/index.ts)
- **Drift:**

| Field | BE | FE | Notes |
|---|---|---|---|
| `bom_ref`, `component_type`, `component_group`, `purl`, `cpe`, `supplier`, `scope` | OK | OK | OK |
| **`component_group`** | `str \| None` | **MISSING on FE** | FE doesn't render |

- **Recommended fix:** Drop from BE if unused, or add to FE. Verify.

### Finding CC-006: `ConsolidatedAnalysisResult` is a 100% BE↔FE drift surface

- **Severity:** High
- **Location:** [frontend/src/types/index.ts:216-231](../frontend/src/types/index.ts); [app/routers/analyze_endpoints.py:213-255](../app/routers/analyze_endpoints.py)
- **Evidence:** BE has no Pydantic schema for the response; FE has an interface with `[key: string]: unknown` to absorb anything. The dual-shape (`runId` AND `id`, `status` AND `run_status`, `summary.findings.bySeverity`) is intentional back-compat (per the BE comment).
- **Why this matters:** Most surface-area for drift in the entire app — and intentionally hidden by the FE's `unknown` index signature.
- **Recommended fix:** see BE-020 + KISS-011 + FE-003. Define `AdhocAnalysisRunOut` Pydantic schema; tighten FE; drop the legacy `summary` block from the BE response after `useBackgroundAnalysis.ts:65-71` is updated.
- **Effort:** M
- **Risk of fix:** Low.

### Finding CC-007: `DashboardStats` mismatch (3 vs 4 keys)

- **Severity:** Low (cross-listed with DRY-013)
- **Location:** [app/routers/dashboard_main.py:33-37](../app/routers/dashboard_main.py); [frontend/src/types/index.ts:84-88](../frontend/src/types/index.ts)
- **Evidence:** Router returns `{total_projects, total_sboms, total_vulnerabilities}`; FE type expects exactly those three keys. **Match.** Service module would return `{total_projects, total_sboms, total_vulnerabilities, total_runs}` (4 keys) — extra key, FE wouldn't break, but the service is unwired (YAGNI-004).
- **Note:** Since the wired implementation matches FE, this drift is latent.

### Finding CC-008: `RecentSbom` matches the dashboard router exactly

- **Severity:** none.
- **Note:** Verified.

### Finding CC-009: `ActivityData` matches

- **Severity:** none. Verified `{active_30d, stale}`.

### Finding CC-010: `SeverityData` matches

- **Severity:** none. Five severity counts.

### Finding CC-011: `SBOMInfo` matches `routers/sbom.py:get_sbom_info`

- **Severity:** none. Verified field-for-field.

### Finding CC-012: `SBOMRiskSummary` matches

- **Severity:** none.

### Finding CC-013: `DashboardTrend` matches

- **Severity:** none.

### Finding CC-014: `CompareRunsResult` matches

- **Severity:** none.

### Finding CC-015: `AnalyzeSBOMPayload` carries credentials the BE rejects

- **Severity:** Medium
- **Location:** [frontend/src/types/index.ts:150-157](../frontend/src/types/index.ts); [app/routers/analyze_endpoints.py:65-93](../app/routers/analyze_endpoints.py)
- **Evidence:** FE TS interface declares `nvd_api_key?`, `github_token?`, `vulndb_api_key?`. BE Pydantic models (`AnalysisByRefNVD`, `AnalysisByRefConsolidated`, etc.) declare no such fields. The BE adapter classes read credentials only from server settings (`credentials.py`). Per-request override was eliminated as a security measure.
- **Why this matters:** Anyone reading the FE type thinks they can supply per-request credentials; in reality the BE silently ignores them.
- **Recommended fix:** Drop the three optional fields from `AnalyzeSBOMPayload`. **`[REQUIRES VERIFICATION]`** of FE callers — does any UI actually pass these? `frontend/src/lib/api.ts:288-294, 479-509` accept the type but the FE pages don't appear to populate them.
- **Effort:** S
- **Risk of fix:** Low.

### Finding CC-016: `useAnalysisStream` requests body includes `nvd_api_key` / `github_token`, but BE ignores them

- **Severity:** Medium
- **Location:** [frontend/src/hooks/useAnalysisStream.ts:122-130](../frontend/src/hooks/useAnalysisStream.ts); [app/routers/sboms_crud.py:368-370](../app/routers/sboms_crud.py)
- **Evidence:**
  ```ts
  body: JSON.stringify({
      sources: initialSources,
      nvd_api_key: options.nvdApiKey ?? null,
      github_token: options.githubToken ?? null,
  })
  ```
  BE Pydantic model:
  ```python
  class AnalyzeStreamPayload(BaseModel):
      sources: list[str] | None = None
  ```
  Pydantic with default `extra="ignore"` (in Settings; not declared on `AnalyzeStreamPayload`) — extras are ignored silently.
- **Why this matters:** Same as CC-015 — unused payload, false impression of feature.
- **Recommended fix:** Drop `nvdApiKey` / `githubToken` from `StartAnalysisOptions`. Update FE callers.
- **Effort:** S
- **Risk of fix:** Low.

---

## 2. Naming coherence

### Finding CC-017: `vulnerability` vs `vuln` vs `cve` vs `finding` overlap

- **Severity:** Low
- **Location:** Pervasive.
- **Evidence:**
  * BE: `AnalysisFinding` model + `find_by_cpe` (mirror) + `vuln_id` field.
  * FE: `AnalysisFinding` interface + `total_vulnerabilities` dashboard key + `vuln_id` field + `findings` arrays.
  * Variables: `findings`, `final_findings`, `raw_findings`, `f` everywhere.
- **Why this matters:** A "finding" is the project's term; "vulnerability" is the user-facing term. The BE field `total_vulnerabilities` doesn't match anything else (no `Vulnerability` model). Inconsistent terminology costs onboarding time.
- **Recommended fix:** Standardise on "finding" internally; keep "vulnerability" only in user-facing copy. Rename `total_vulnerabilities` → `total_findings` (or vice versa) in both BE dashboard and FE type. Cross with DRY-013.
- **Effort:** S (rename) — but scope creep risk.
- **Risk of fix:** Low.

### Finding CC-018: `projectid` (no underscore) on BE vs `project_id` on FE

- **Severity:** Low
- **Location:** [app/models.py:55](../app/models.py); [app/schemas.py:73](../app/schemas.py); [frontend/src/types/index.ts:16](../frontend/src/types/index.ts).
- **Evidence:**
  ```python
  # SBOMSource model + schema
  projectid = Column(Integer, ...)
  ```
  ```ts
  // SBOMSource interface
  projectid: number | null;
  ```
  But `AnalysisRun` uses `project_id` (with underscore). And `Projects` has FK as `projectid`, but `AnalysisRun.project_id`. Inconsistent.
- **Why this matters:** A reader can't tell which form to use without checking the model. Migration cost: one rename + Alembic + FE update.
- **Recommended fix:** Pick `project_id`. Add Alembic migration to rename column. Update Pydantic + TS. Tests should catch most breakage.
- **Effort:** M
- **Risk of fix:** Medium.

### Finding CC-019: `created_on` (str) vs `started_on` (str) — both ISO timestamps but one's a noun-ed past and one's a participle

- **Severity:** Low
- **Note:** Aesthetic. Defer.

### Finding CC-020: `run_status` vs `status` aliasing in `_run_legacy_analysis` response

- **Severity:** Medium (cross-listed with KISS-011, CC-006).

### Finding CC-021: `sbom_name` (BE) vs `sbomName` would be conventional camelCase JSON

- **Severity:** Low
- **Note:** Project chose snake_case across the wire. Consistent. Acceptable. Listed only because FE callers occasionally show `sbomName` in variable names.

---

## 3. Error envelope consistency

### Finding CC-022: Error response shapes are inconsistent

- **Severity:** Medium — see BE-023.
- **Location:** Cross-listed.
- **FE impact:** [frontend/src/lib/api.ts:105-128](../frontend/src/lib/api.ts) defensively handles 4 shapes:
  ```ts
  if (typeof body.detail === 'string') message = body.detail;
  else if (typeof body.detail === 'object' && !Array.isArray(body.detail) && body.detail.message) {
    message = body.detail.message; code = body.detail.code;
  }
  else if (Array.isArray(body.detail)) message = body.detail.map(e => `${e.loc?.slice(1).join('.')} — ${e.msg}`).join('; ');
  else message = JSON.stringify(body.detail);
  ```
  Each branch corresponds to a different BE shape. The FE absorbs the inconsistency, so the bug is invisible — but the absorption is itself a smell.
- **Recommended fix:** Pick one (`{code, message}` is the most useful — supports localised UI strings). Add a global FastAPI exception handler. FE simplifies to two branches: parsed envelope vs unexpected.
- **Effort:** M
- **Risk of fix:** Low.

---

## 4. Auth flow / CSRF posture

### Finding CC-023: Auth currently `none` by default; FE doesn't send tokens

- **Severity:** Medium (operational risk)
- **Location:** [app/settings.py:75-82](../app/settings.py); [frontend/src/lib/api.ts:91-103](../frontend/src/lib/api.ts).
- **Evidence:** Default `API_AUTH_MODE=none`. The FE fetch helper never sets `Authorization`. There's no FE login UI, no token storage, no refresh flow. Production deploys must (a) set `API_AUTH_MODE=bearer|jwt`, (b) configure the browser to send tokens — neither flow exists end-to-end.
- **Why this matters:** Either (a) the project is intentionally on internal-only deploy with no auth (then the codepath is YAGNI), or (b) auth is half-built and production-unsafe.
- **Recommended fix:** Decide. If (a): delete the auth modes (YAGNI). If (b): build the FE login flow and the token-injection middleware. Either way, document.
- **Effort:** L (build) / S (delete).
- **Risk of fix:** Medium.

### Finding CC-024: CORS allows any origin; `allow_credentials=False` mitigates

- **Severity:** Low — see BE-027.

### Finding CC-025: No CSRF protection — but no cookie-based auth either, so OK

- **Severity:** none.
- **Location:** Verified — no `Set-Cookie` issuing endpoint, no session-based auth path.
- **Note:** Acceptable. Pure-token auth + `SameSite=...` not relevant here.

### Finding CC-026: JWT clock skew tolerance not configured

- **Severity:** Low
- **Location:** [app/auth.py:85-108](../app/auth.py)
- **Evidence:** `jwt.decode(...)` with default `leeway=0`. Edge case: token issuer's clock 5s ahead → token rejected.
- **Recommended fix:** `leeway=int(get_settings().jwt_leeway_seconds or 30)`.
- **Effort:** S (and add the setting field).
- **Risk of fix:** Low.

---

## 5. Test pyramid

### Finding CC-027: Coverage skewed toward integration / snapshot, thin unit layer for orchestration

- **Severity:** Medium
- **Location:** [tests/](../tests/).
- **Evidence:**
  * **Unit-ish:** `test_auth.py`, `test_nvd_cpe_query.py`, `test_nvd_perf_guards.py`, `test_nvd_ssl_regression.py`, `test_sources_adapters.py`, `tests/nvd_mirror/test_*.py` (13 files — well unit-tested with fakes).
  * **Snapshot:** `test_analyze_endpoints_snapshot.py`, `test_sboms_analyze_snapshot.py` — output shape regressions.
  * **Integration:** `test_sboms_analyze_stream.py`, `tests/nvd_mirror/test_facade_integration.py`.
  * **No tests:** `services/analysis_service.persist_analysis_run` (this is where SOLID-SRP-003 / DRY-005 / BE-009 hide), `services/dashboard_service` (entire module), `routers/dashboard_main`, `routers/dashboard.py`, `routers/sbom.py`, `routers/projects.py` CRUD (entire), `routers/sboms_crud.py` CRUD (only analyze paths covered).
- **Why this matters:** Bug discovery skew. The 949-line `routers/sboms_crud.py` has snapshot tests for the analyze paths but nothing exercising create/update/delete/list. The `query_error_count = 0` bug (SOLID-SRP-003) survives because no test asserts that field on persisted runs.
- **Recommended fix:** Add a small unit-test suite per router for CRUD shapes (TestClient-driven, in-memory SQLite). One test per endpoint × happy path + one error case ≈ 30 tests, ~200 LOC.
- **Effort:** M
- **Risk of fix:** Low.

### Finding CC-028: Frontend has one test file (env.test.ts)

- **Severity:** Medium
- **Location:** [frontend/src/lib/env.test.ts](../frontend/src/lib/env.test.ts).
- **Evidence:** 56 lines of Vitest covering `resolveBaseUrl`. Verified no other `*.test.*` files.
- **Why this matters:** Hooks (`useAnalysisStream`, `useBackgroundAnalysis`, `usePendingAnalysisRecovery`) carry the most logic and have zero tests. SSE parser, optimistic cache updates, and the three persistence channels (FE-014) are untested.
- **Recommended fix:** Add Vitest + Testing Library tests for:
  * `useAnalysisStream` — feed a mocked ReadableStream, assert state transitions.
  * `useBackgroundAnalysis` — assert React Query cache mutations + toast calls (mock both).
  * `pendingAnalysis.ts` — sessionStorage round-trip.
  ~6-8 tests, ~250 LOC.
- **Effort:** M
- **Risk of fix:** Low.

### Finding CC-029: No contract test that BE Pydantic = FE TS

- **Severity:** Medium
- **Location:** —
- **Why this matters:** Without one, drift like CC-001..006 is found by humans, not CI.
- **Recommended fix:** Two cheap options:
  1. Generate FE types from BE OpenAPI (`fastapi.openapi() → openapi.json → openapi-typescript`). The generated types replace the hand-written ones for shapes that mirror Pydantic. Drift-by-construction-impossible.
  2. Or: a Python test that loads `frontend/src/types/index.ts` (via parsing) and compares against `app.schemas`. Brittle.
- **Effort:** M
- **Risk of fix:** Low.

### Finding CC-030: `tests/conftest.py` snapshot infra exists but I did not read full file

- **Severity:** [REQUIRES VERIFICATION]
- **Note:** The fixtures setup (env reset, in-memory SQLite, TestClient) was inferred from the test imports but `tests/conftest.py` was not read end-to-end. Recommend reading before relying on test isolation guarantees.

---

## Summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 1 |
| Medium | 8 |
| Low | 11 |
| Verified-positive | 8 |
| [REQUIRES VERIFICATION] | 1 |
| **Total** | **29** |

**Highest-leverage cross-cutting fixes:**
1. **CC-006 + BE-020 + FE-003** — Define `AdhocAnalysisRunOut` Pydantic schema, set `response_model` on the five `analyze-sbom-*` routes, drop the FE's `[key: string]: unknown` escape hatch. Removes the largest contract-drift surface in the app.
2. **CC-022 + BE-023** — Single error envelope. Removes the FE's 4-branch defensive parsing.
3. **CC-029** — Generate FE types from BE OpenAPI. Long-term insurance against re-introducing every drift in this audit.
4. **CC-027 / CC-028** — Add the missing CRUD tests on the BE side and hook tests on the FE side. The bugs hidden by the gap (SOLID-SRP-003 chief among them) become visible.
