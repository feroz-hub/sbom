# Secure Component Advisor — Phase 0 Repository Analysis & Implementation Plan

| | |
|---|---|
| Source spec | [`docs/specs/Secure_Component_Advisor_Requirements_v1_1.docx`](../specs/Secure_Component_Advisor_Requirements_v1_1.docx) (v1.1, 01 Oct 2026) |
| Status | **Draft — awaiting approval (STEP 1). No code has been changed.** |
| Baseline | branch `feat/native-user-management` @ `6abb9b8`, Alembic head `066_platform_config_permissions` |
| Date | 2026-10-01 |

Requirement IDs (FR-SCA-*, NFR-SCA-*, US-SCA-*) and test numbers (T1…T45, from the prompt's §10 test matrix) are used throughout.

---

## 1. Executive summary

SBOM Analyser already has most of the raw ingredients: per-SBOM component occurrences with
canonical identity keys, findings with severity/CVSS, a persistent VEX context model
(`VexInvestigation`) with the four canonical effective statuses, a reusable eligible-SBOM scope,
a scoped-configuration pattern, lifecycle enrichment with "latest/recommended version" fields,
an NVD mirror that can evaluate a CPE+version against affected ranges, an append-only domain
audit pattern, and a mature page template (VEX investigation) on the frontend.

What does **not** exist and must be built:

1. A **cross-SBOM component aggregation** (no shared component entity; nothing groups by canonical key today).
2. A **join from findings to effective VEX state** that yields "highest actionable severity".
3. **Versioned policies** (scoped configuration exists but has no versioning).
4. **Any recommendation entity, workflow, scoring, compatibility or alternative-discovery logic.**
5. **Purpose/category metadata** (no description column; parser drops component descriptions; no taxonomy).
6. A **package version catalogue** (only `latest_version`/`recommended_version` per occurrence).
7. **As-of** on dashboard responses and **historical VEX state** (only current state + audit).
8. A **browser E2E harness** (no Playwright/Cypress in the repo).

The plan below extends existing architecture everywhere it can and introduces new tables only for
the recommendation work item family and versioned policies, where nothing reusable exists.

---

## 2. Current architecture findings

### 2.1 FastAPI layering (Phase 0 item 1)
- Routers are registered in `app/main.py:706-780` with `dependencies=_protected` (`enforce_request_access`). Each router declares its own prefix.
- Path conventions are mixed: `/api/...` (projects, products, sboms, **vex**), `/api/v1/...` (ai, compare, cves, kev), `/dashboard/...` (unversioned). → **Proposed: `/api/component-advisor/...`**, mirroring the newest comparable feature (`/api/vex/investigations`, `app/routers/vex_investigations.py:65`).
- **Router-level permission is derived from the path** by `permission_for_request()` (`app/core/security.py:519-634`); unmatched GETs fall back to `dashboard:read`, unmatched writes to `tenant:settings:update`. A new prefix **must** get an explicit branch.
- There is no `app/repositories/` package despite the docstring; routers call `app/services/*` and, for metrics, `app/metrics/*`. `get_db()` (`app/db.py:143-151`) does not auto-commit.
- Cross-tenant/foreign IDs → **404** by convention (`vex_investigations.py:90-103`, `dashboard_scope.py:100-121`); missing permission → 403.
- Optimistic concurrency: manual `row_version` + `with_for_update()` + 409 with current payload (`vex_investigations.py:100-112, 688-744`).
- List envelope `{total, limit, offset, items}` (`schemas_vex.py:74-80`).
- `app/idempotency.py` is in-process only → recommendation idempotency must be DB-enforced.

### 2.2 Models & migrations (item 2)
- Integer autoincrement PKs; naming convention in `app/db.py:22-28`.
- `TenantOwnedMixin` (`app/models_mixins.py:59-67`) gives automatic read filtering + write stamping/guarding via ORM hooks (`app/db.py:180-208, 263-295`). **All new tenant tables will use it.**
- `SoftDeleteMixin` (`is_active`, `deactivated_at/by`).
- Timestamps: legacy ISO strings vs `DateTime(timezone=True)` on newer tables → **new tables use `DateTime(timezone=True)`.**
- Migrations: `alembic/versions/NNN_snake_name.py`, existence-checked DDL, explicit `ix_<table>_<col>` index names, downgrade for structural changes; permission migrations follow `065`/`066`. App refuses to start off-head (`main.py:287-341`).

### 2.3 Tenant → Project → Product → SBOM & scoping (item 3)
- `Tenant` → `Projects` (`models.py:608`) → `Product` (`:655`) → `SBOMSource` (`:727`, `projectid`, `product_id`, `parent_id` lineage) → `SBOMComponent` (`:981`).
- Authoritative tenant: `get_current_tenant_context` → `resolve_authorization_state`; `X-Tenant-ID` is accepted only if it is one of the user's memberships (`services/auth_context_service.py:162-180`). Permissions re-read per request.
- **`dashboard_scope_dependency`** (`app/services/dashboard_scope.py:138-152`) validates `project_id`/`product_id`/`sbom_id` against tenant and parent chain (child without parent → 400; foreign → 404) and installs `db.info["dashboard_scope"]`, which auto-filters `SBOMSource`, `AnalysisRun`, `AnalysisFinding`, `SBOMComponent`, `VexStatement`, `Projects`, `Product` (`app/db.py:210-260`). **`VexInvestigation` is NOT in that list** — pass `sbom_ids` explicitly.
- `DashboardScope.eligible_sbom_ids()` (`:46-80`) = active, visible-parent, non-superseded HEAD SBOMs. **This is the §1.3 "current operational dataset"; reuse as-is.**
- "Application" = existing `Product` (FE already labels it "Application" in `DashboardFilters`). No new entity needed.

### 2.4 Canonical component identity (item 4)
- `build_identity_key` (`app/normalization/component_normalizer.py:170-187`): `purl:{normalized_purl}` (versioned PURL) → `cpe:{primary_cpe}` (versioned CPE) → `name:{eco}:{name}:{version}:{supplier}` → `name:{eco}:{name}:{version}` (non-generic eco) → **None (LOW confidence)**. This matches the spec priority (PURL → CPE+version → supplier+name+version+ecosystem).
- `dedupe_canonical_id` = SHA-256 of that key — deterministic, comparable across SBOMs.
- `normalized_package_key` = `eco:name[:supplier]` (version-less) — usable as the **component family key** for same-family version discovery.
- Caveat: PURL qualifiers (e.g. `?arch=`) remain in the key, so the same version with different qualifiers counts as different unique versions.
- Dedup is intra-SBOM only; `is_duplicate=True` rows must be excluded.
- Doc drift: `docs/component-deduplication.md:19-22` describes a fallback key the normalizer does not use.

### 2.5 Component occurrence storage (item 5)
- `SBOMComponent` (`models.py:981-1080`) is **one row per SBOM occurrence**. There is no shared component entity.
- Columns available: name/version (+ normalized), PURL parts, CPE(s), supplier (+ normalized), component_type, ecosystem (+ normalized), `license` (**single comma-separated string**), hashes, identity fields, and lifecycle fields (`lifecycle_status`, `eos_date`, `eol_date`, `latest_version`, `latest_supported_version`, `recommended_version`, `lifecycle_checked_at`, `lifecycle_is_stale`, evidence JSON).
- **Gaps:** no `description`. The parsers (`app/parsing/cyclonedx.py`, `spdx.py`) do not extract component description. There is no `(tenant_id, dedupe_canonical_id)` index.

### 2.6 Findings, CVSS, severity (item 6)
- `AnalysisRun` (`models.py:1487`); successful statuses `OK`/`FINDINGS`/`PARTIAL` (`COMPLETED_RUN_STATUSES`, `app/metrics/base.py:15`).
- `AnalysisFinding` (`:1532-1587`): `analysis_run_id`, nullable `component_id` → `sbom_component.id`, canonical `vuln_id`, `aliases`, `severity`, `score`, `vector`, `cvss_version`, `fixed_versions`, `published_on`.
- Severity is a free string: `CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN` (`app/sources/severity.py:97-124`). **There is no INFORMATIONAL/NONE**; CVSS 0.0 buckets as LOW.
- Findings without `component_id` cannot be attributed to a canonical component.

### 2.7 VEX states & actionable semantics (item 7)
- `VexInvestigation` (`models.py:1319-1413`): context = tenant + sbom + component + canonical vuln (VEX-CTX-001). It holds `effective_status` ∈ {AFFECTED, NOT_AFFECTED, FIXED, UNDER_INVESTIGATION}, `reconciliation_status` ∈ {MATCHED, ANALYZER_ONLY, VEX_ONLY, CONFLICT_REVIEW_REQUIRED, REVALIDATION_REQUIRED, UNRESOLVED_MAPPING}, `is_current` and `row_version`. It has **no severity** (VEX-DATA-005: severity comes from findings).
- Computed by `reconciliation.decide()` / `recompute_for_sbom` (`app/services/vex/reconciliation.py:147-439`), triggered after each successful run, VEX import and mapping resolution. Analyser finding with no VEX → UNDER_INVESTIGATION + ANALYZER_ONLY.
- **No function maps finding → effective status.** The join pattern exists in `vex_severity_filter_clause` (`app/metrics/vex.py:258-285`).
- Legacy paths (`effective_vex_statements`, `metrics/reporting.py:121-129`) use legacy statement status. **The advisor must not use them.** `choose_vex_result` must never be wired (CLAUDE.md, VEX-INV-005).
- **Actionable per spec §2 (AFFECTED or UNDER_INVESTIGATION) maps 1:1 onto `VexInvestigation.effective_status`.** No new VEX semantics are needed.
- VEX plan status: PR-0…PR-5 done; **PR-6 (audit/concurrency/RBAC) and PR-7 (E2E) are not ticked** in `docs/plans/vex-implementation-plan.md`.

### 2.8 Effective dataset / eligible revision / as-of (item 8)
- No SBOM version table; `parent_id` lineage, HEAD = not a parent of any other SBOM. `SBOMSource.status` is not used for eligibility.
- `latest_run_per_sbom_subquery()` (`app/metrics/_helpers.py:33-46`) gives the latest successful run per active HEAD.
- As-of support is partial:
  - `latest_run_per_sbom_as_of_subquery` (`_helpers.py:49-62`) exists but **skips the active-HEAD filter**.
  - No dashboard endpoint accepts `as_of`.
  - **VEX has no point-in-time state.**

### 2.9 Lifecycle / EOL / EOS (item 9)
- Lifecycle data lives on `SBOMComponent` columns.
- `ComponentLifecycleCache` (`models.py:1083`) is a cache shared across tenants.
- `LifecycleProviderConfig` holds platform/tenant provider settings with a `health_status` column.
- Statuses: Supported, EOL, EOS, EOF, Deprecated, Unsupported, EOL Soon, Possibly Unmaintained, Unknown (`app/services/lifecycle/types.py:9-29`). There is **no "Maintenance"** status; maintenance status is free text.
- Provider chain (`provider_chain.py:14-23`): manual → vendor → OpenEoX → endoflife.date → xeol → registry → deps.dev → OSV → repo health → heuristic.
- Existing "upgrade" signals:
  - Registry latest version (npm/PyPI/NuGet/Maven/RubyGems).
  - deps.dev highest version.
  - OSV `fixed_versions[0]`.
  - Vendor `recommended_version`.
- Version comparison in `package_registry_provider.py:294-300` is PEP 440-only and is wrong for Maven/semver/Go. `app/sources/version_range.py` has ecosystem-aware logic → **reuse that**.
- **No background lifecycle refresh job.** Enrichment is synchronous on upload or via the refresh endpoints. The circuit breaker is in-memory per process.
- Note: the root CLAUDE.md lists EOL/EOS as out of scope *for the VEX workstream*. The advisor **reads** lifecycle data; it does not change lifecycle implementation (see §10, D-1).

### 2.10 Dashboard aggregation, filters, as-of, caching (item 10)
- Routers: `dashboard_main.py` (incl. `/dashboard/summary`, 14 panels), `dashboard.py`, `dashboard_advanced.py`.
- Applied-scope echo exists only on `/summary` (`_scope_metadata`, `dashboard_main.py:627-639`). Freshness is only `posture.last_successful_run_at`.
- Caching:
  - ETag via `app/etag.py`.
  - In-process TTL memoization `app/metrics/cache.py:29-72`, keyed on invalidation tuple + scope key. **Reuse it for advisor summary/list.**
- ADR-0009 + `docs/metric-conventions.md`: all numbers come from `app/metrics/`; conventions A/B/C; severity buckets must sum to the total. **Advisor counts are Convention A (latest state).**
- Architectural test `tests/test_metric_consistency.py:800-846` forbids `select(AnalysisFinding…)`/`select(AnalysisRun…)` in routers/services.

### 2.11 Roles & permissions (item 11)
- Roles: `TENANT_ADMIN`, `SECURITY_ANALYST`, `DEVELOPER`, `VIEWER`, plus `PLATFORM_ADMIN` (`app/core/permissions.py`).
- Format `resource:action`. The DB catalogue is authoritative (`authorization_permissions`, `authorization_role_permissions`).
- Adding a permission (pattern `065_scoped_configuration.py:107-145`):
  1. Write a migration.
  2. Update `ALL_PERMISSIONS`/`ROLE_PERMISSIONS`.
  3. Add a `permission_for_request` branch.
  4. Run `scripts/compare_authorization_catalog.py`.
  5. Update the FE `DEV_USER` list (`frontend/src/hooks/useAuth.tsx:89-99`).
- Per-route: `Depends(require_permission("x:y"))`. Per-record capability pattern: `app/services/vex/authorization.py:167-190` → FE `capabilities` object (`VexInvestigationCapabilities`).
- `GET /api/auth/me` returns roles + permissions.

### 2.12 Audit & correlation (item 12)
- Generic `AuditLog` (`models.py:2155`) via `audit_service.write_audit_log` (flush, no commit). There is also per-request write auditing middleware (`main.py:634-675`).
- `AuthorizationAuditLog` has `correlation_id`.
- **Best template:** `VexOverrideAudit` + `app/services/vex/audit.py:20-57`. It has real previous/new status columns, before/after JSON, a required reason, and is flushed in the same transaction.
- **Append-only is convention only** (no trigger/ORM guard).
- Correlation: `RequestLoggingMiddleware` sets `request.state.correlation_id` from `X-Request-ID`. `log_event(...)` + `log_context` with tenant/project/product/sbom/run/user/request IDs. Event names are mixed; dotted lowercase is used for newer events → `secure_component_advisor.*` fits.

### 2.13 Background jobs (item 13)
- Celery (`app/workers/celery_app.py`). Log context is propagated via publish/prerun signals. Tenant binding via `minimal_background_context(tenant_id)`.
- Retries with backoff exist on `analyze_sbom_async`; `acks_late` on report notifications.
- **No generic job table.** Job status is per feature (`ai_fix_batch`, `nvd_sync_runs`).

### 2.14 AI / recommendation / external metadata (item 14)
- AI fixes (`app/ai/*`):
  - Grounding contract (`grounding.py`).
  - Provenance metadata (`AiFixMetadata`: provider, model, prompt_version, generated_at).
  - Tenant enablement (`AiSettings` platform + tenant override, kill switch, canary).
  - Usage ledger. **Reuse the gates and provenance shape for AI-assisted purpose classification and rationale text.**
- `VulnerabilityRemediation` has a loose state machine (all transitions allowed) — not a good base. **No recommendation entity exists.**
- External sources: `CveSource` Protocol + `FetchOutcome` + `CircuitBreaker` (`app/integrations/cve/base.py:23-100`) is the best adapter contract to copy. `app/ports/` is empty.
- No package-metadata table, version catalogue, per-version release dates (only in evidence JSON), registry licenses, or descriptions.
- NVD mirror `find_by_cpe` (`app/nvd_mirror/adapters/cve_repository.py:148-363`) can evaluate a hypothetical CPE+version against affected ranges, with `published` dates. This gives per-version 24-month history **where the mirror is enabled and a CPE exists**.

### 2.15 Frontend (item 15)
- Stack: Next.js 16 App Router, React 19, TanStack Query 5, Tailwind, custom design system (`frontend/src/components/ui/*`), hand-written API client (`lib/api.ts`) and types (`types/index.ts`). `frontend/AGENTS.md` says to read the Next 16 docs before coding.
- Nav: `lib/navigation.ts:35-83` (permission-gated, group `Security Operations`).
- Scope: `components/dashboard/DashboardFilters.tsx` (Project → Application → SBOM; children are cleared on parent change; `aria-live` breadcrumb). **The tenant is the active tenant via `TenantSwitcher`, not a dropdown**, which fits the "Tenant default scope" requirement.
- Reusable UI pieces:
  - `Table` (resizable, `SortableTh`; **no column groups** → extend with a grouped header row).
  - `Pagination`, `TableFilterBar`, `Select`.
  - `SeverityBadge` (text + dot, aria-label — not color-only).
  - `EmptyState` (`role=status`), `Alert`, skeletons, toasts, `Dialog` (focus trap).
- Template page: **`frontend/src/app/vex-investigation/page.tsx`**. It keeps state in the URL, has debounced search, KPI tiles that apply filters, chips, a drill-down dialog, and `row_version` mutations.
- Mutation invalidation rule + architectural test (`frontend/src/__tests__/mutation-invalidation.test.ts`) → new `invalidateComponentAdvisorSurfaces` helper in `lib/queryInvalidation.ts`.

### 2.16 Test harnesses (item 16)
- Backend: pytest against Postgres by default (`tests/conftest.py`, DB name must contain `test`). Truncate + reseed per test. Default `-m "not integration and not bench"`.
- Backend seeding templates:
  - `tests/test_vex_investigations_api.py:35-103` (SBOM → component → run → finding → VEX → `recompute_for_sbom`).
  - `tests/test_dashboard_scope.py:20-67` (hierarchy + cross-tenant inserts via Core).
  - `tests/test_vex_scoped_authorization.py:22-65` (role actors via dependency overrides).
- Benchmarks: pytest-benchmark under `-m bench` (`tests/validation/test_perf.py`).
- Frontend: Vitest 4 + Testing Library + `vitest-axe`. Modules are mocked with `vi.mock` (no MSW). **No Playwright/Cypress; no CI workflows in repo.**

---

## 3. Reuse map (spec part → existing code)

| Spec need | Reuse | Extend / new |
|---|---|---|
| Effective active dataset (§1.3) | `DashboardScope.eligible_sbom_ids()`, `dashboard_scope_dependency`, `latest_run_per_sbom_subquery()` | Fix as-of variant to apply HEAD/active filter (Step 3, only if as-of is approved) |
| Canonical identity | `dedupe_canonical_id`, `normalized_package_key`, `build_identity_key` | Fallback key for identity-less rows; `(tenant_id, dedupe_canonical_id)` index |
| Actionable semantics | `VexInvestigation.effective_status` (is_current) + join pattern from `metrics/vex.py:258` | New metric fn: highest actionable severity per canonical version |
| Severity | `sev_bucket`, `SEVERITY_ORDER` | No INFORMATIONAL (D-4) |
| Lifecycle | `SBOMComponent.lifecycle_*`, `lifecycle/types.py` statuses | Map to spec buckets (Supported/Maintenance/EOS/EOL/Unknown) |
| Tenant isolation | `TenantOwnedMixin`, ORM hooks, 404 convention | Add new tables to the mixin |
| Permissions | catalogue + `require_permission` + `permission_for_request` + capabilities pattern | New `component_advisor:*` permissions (migration 067) |
| Policy config | Scoped configuration (null-tenant default + tenant override, `configuration_scope.py`) | Add **versioning** (append-only versions table) |
| Audit | `VexOverrideAudit` pattern + `write_audit_log` | Recommendation decision/event table; optional ORM append-only guard |
| Caching | `app/metrics/cache.py` memoize, `app/etag.py` | — |
| Jobs | Celery + log-context propagation + `minimal_background_context` | `advisor.evaluate_recommendation` task |
| External sources | `CveSource`/`FetchOutcome`/`CircuitBreaker` contract | `PackageMetadataSource` adapter Protocol (no prod source enabled) |
| Version comparison | `app/sources/version_range.py` | — (do **not** use the registry PEP 440 helper) |
| Vuln history | NVD mirror `find_by_cpe` + `published`; findings `published_on` | History service with explicit coverage |
| AI assist | `AiSettings` gates, grounding, `AiFixMetadata` provenance | Purpose classifier + rationale text (optional, off by default) |
| FE page | `vex-investigation/page.tsx`, `DashboardFilters`, `Table`, `SeverityBadge`, `EmptyState` | Column-group header; advisor pages |

---

## 4. Proposed domain changes (NFR-SCA-009)

New package **`app/services/component_advisor/`**: pure domain logic with no SQL, plus orchestrating services. All finding/run aggregation goes in **`app/metrics/component_advisor.py`** (CLAUDE.md rule).

| Module | Responsibility | Pure? |
|---|---|---|
| `classification.py` | §2 risk buckets from (actionable severities, non-actionable count, evidence flags, policy result) | ✅ |
| `lifecycle_mapping.py` | Existing lifecycle statuses → Supported / Maintenance / EOS / EOL / Unknown | ✅ |
| `policy.py` | Evaluate accepted-risk / trust policy versions → result + reasons + policy version | ✅ |
| `identity.py` | Unique-version key (`dedupe_canonical_id` or fallback) and family key (`normalized_package_key`) | ✅ |
| `intelligence_service.py` | Assemble per-version intelligence from metric rows + lifecycle + freshness | service |
| `purpose.py` | Purpose/category resolution with provenance priority (SBOM → package → curated → AI) | ✅ + service |
| `recommendations/workflow.py` | State machine + allowed transitions + idempotency key | ✅ |
| `recommendations/version_discovery.py` | Same-family candidate versions | service |
| `recommendations/alternative_discovery.py` | Tenant-observed → external adapters → manual | service |
| `recommendations/compatibility.py` | Per-check PASS/FAIL/REVIEW_REQUIRED/UNKNOWN + blocking flag | ✅ |
| `recommendations/scoring.py` | Versioned weighted scoring with factor breakdown; blocking gates applied *before* score | ✅ |
| `recommendations/confidence.py` | HIGH/MEDIUM/LOW/INSUFFICIENT_EVIDENCE from completeness + freshness | ✅ |
| `recommendations/explanation.py` | Reason/limitation codes → rationale text (template; optional AI) | ✅ |
| `history.py` | Vulnerability history over window with explicit coverage | service |
| `audit.py` | Append-only advisor events (flush, no commit) | service |
| `sources/base.py` | `PackageMetadataSource` Protocol + `FetchOutcome` reuse | contract |

**Proposed classification precedence** (mutually exclusive, reconciles to unique-version count). Steps 1 and 3c are open decisions D-3 and D-5:
1. **Review Required** when any of these hold:
   - an actionable context is `CONFLICT_REVIEW_REQUIRED`, `REVALIDATION_REQUIRED` or `UNRESOLVED_MAPPING`;
   - the identity is LOW-confidence;
   - vulnerability evidence is stale beyond the policy threshold.
2. **Unknown**: the component's SBOM has no successful analysis run in the eligible snapshot (no vulnerability evidence at all).
3. Otherwise, if there are actionable findings (VEX AFFECTED/UNDER_INVESTIGATION):
   - a. if an active accepted-risk policy is satisfied → **Accepted Risk** (records policy version + reasons);
   - b. else bucket = highest actionable severity: **Critical / High / Medium / Low**;
   - c. if the highest actionable severity is `UNKNOWN` → **Review Required**.
4. No actionable findings (none at all, or only FIXED/NOT_AFFECTED) → **No Known Actionable Vulnerabilities**, always shown with freshness and coverage.

Findings with no `VexInvestigation` row yet (reconciliation lag) are treated as UNDER_INVESTIGATION, consistent with VEX-REC-002 A. VEX-only contexts (no `AnalysisFinding`) never fabricate severity (VEX-DATA-003); they are surfaced as evidence and push the component to Review Required if AFFECTED (D-5).

---

## 5. Proposed database changes

Single additive migration per step. All new tenant tables use `TenantOwnedMixin`, integer PKs, tz-aware timestamps, and `ix_<table>_<col>` indexes.

| Step | Migration | Change | Why new rather than extend |
|---|---|---|---|
| 2 | `067_component_advisor_foundation` | Index `ix_sbom_component_tenant_canonical (tenant_id, dedupe_canonical_id)`, index on `(tenant_id, normalized_package_key)`. Permissions `component_advisor:*` + role mapping (065 pattern). | Index only; no table change |
| 4 | `068_component_advisor_policies` | `advisor_policy` (id, tenant_id NULL=platform, kind ∈ ACCEPTED_RISK/TRUST/SCORING, name, status, current_version_id, row_version) + **`advisor_policy_version`** (append-only: policy_id, version, rules_json, effective_from, created_by, created_at, reason). Partial unique indexes per scoped-config pattern. | Scoped config has no versioning; spec requires versioned, traceable policies (FR-SCA-004/005/017, NFR-SCA-007) |
| 4 | same | `component_purpose_metadata` (tenant_id NULL=curated platform, family_key, purpose, primary_use_case, category, source ∈ SBOM/PACKAGE/CURATED/AI, confidence, provenance_json, created_at). Additive `sbom_component.description` column + backfill from stored raw SBOM if available (to be verified in Step 4). | No purpose store exists (FR-SCA-009) |
| 5 | `069_component_recommendations` | `component_recommendation` (work item: tenant/project/product/sbom, source_component_id, source_canonical_id, family_key, trigger_type, status, correlation_id, row_version, timestamps). **Partial unique index on `(tenant_id, source_canonical_id, coalesce(sbom_id,0), trigger_type) WHERE status NOT IN ('ACCEPTED','REJECTED','DEFERRED','CLOSED')`** for idempotency (T20). | No recommendation entity exists (FR-SCA-011) |
| 5–7 | same | `component_recommendation_candidate` (candidate canonical id/name/version/purl, candidate_kind ∈ SAME_FAMILY_VERSION/ALTERNATIVE, source_type ∈ TENANT_OBSERVED/EXTERNAL/MANUAL, reasons_json, limitations_json, score, scoring_policy_version_id, confidence, blocked, rank, evidence_json, evidence_as_of). `component_recommendation_factor`. `component_recommendation_compatibility_check`. | Spec §6 logical model |
| 8 | same | `component_recommendation_event` (append-only: recommendation_id, candidate_id, action, actor, reason, old/new state, policy/score version, confidence, evidence refs, correlation_id, source, created_at). Plus a `write_audit_log` mirror for the tenant audit view. | Mirrors `VexOverrideAudit`; generic `AuditLog` lacks typed state/version columns |

Optional (only if the Step 3 benchmark fails NFR-SCA-005): an incremental per-SBOM rollup `component_intelligence_sbom_rollup` refreshed on run completion and reconciliation. This avoids full-tenant recomputation (NFR-SCA-006).

All migrations get downgrades. Permission rows follow the 065/066 convention.

---

## 6. Proposed API (prefix `/api/component-advisor`, router `app/routers/component_advisor.py`)

Every read response carries this envelope:

```
"meta": {
  "applied_filters": {...},
  "scope": {...},        // from _scope_metadata
  "as_of": "...",
  "generated_at": "...",
  "freshness": {
    "latest_analysis_at",
    "vulnerability_source_refreshed_at",
    "lifecycle_refreshed_at",
    "package_metadata_refreshed_at",
    "stale_flags"
  },
  "policy_versions": {...}
}
```

| # | Method & path | Permission | FR |
|---|---|---|---|
| 1 | `GET /summary` (KPIs; scope + risk/lifecycle/search filters) | `component_advisor:read` | 002, 003, 006, 007 |
| 2 | `GET /components` (drill-down list; same filters; sort; limit/offset) | `component_advisor:read` | 001, 006, 007 |
| 3 | `GET /components/{canonical_key}` (detail: usage, purpose, lifecycle, vulns, history, freshness) | `component_advisor:read` | 001, 009, 010, 016, 020 |
| 4 | `GET /search?q=&facet=name\|purl\|supplier\|ecosystem\|category\|purpose` | `component_advisor:read` | 008, 009 |
| 5 | `GET /components/{key}/classification` (accepted-risk/trust explanation) | `component_advisor:read` | 004, 005 |
| 6 | `GET/POST/PUT /policies/{kind}` (+ `/versions`) | `tenant:advisor_policy:read/update`, `platform:advisor_policy:update` | 004, 005, 017 |
| 7 | `POST /recommendations` (idempotent: returns existing open item with 200, new with 201) | `component_advisor:recommendation:create` | 011 |
| 8 | `GET /recommendations`, `GET /recommendations/{id}` (+ `capabilities`) | `component_advisor:read` | 011 |
| 9 | `GET /recommendations/{id}/candidates` | `component_advisor:read` | 012–019 |
| 10 | `GET /recommendations/{id}/candidates/{cid}/evidence` (factors, reasons, freshness, compatibility) | `component_advisor:read` | 015, 017, 018, 020 |
| 11 | `POST /recommendations/{id}/decisions` `{decision, candidate_id?, reason, row_version}` | review/accept perms per decision | 021, 022 |
| 12 | `GET /recommendations/{id}/events` | `component_advisor:audit:read` | 022 |
| 13 | `GET /analytics` (Could) | `component_advisor:read` | 024 |

The scope uses `dashboard_scope_dependency`, which gives the existing 400/404 behaviour. `canonical_key` is the `dedupe_canonical_id` hex, or `occ-<component_id>` for identity-less rows, and is always re-resolved within the tenant's eligible set (404 otherwise).

---

## 7. Proposed frontend changes

- Routes:
  - `app/component-advisor/page.tsx` — dashboard.
  - `app/component-advisor/components/[key]/page.tsx` — detail.
  - `app/component-advisor/recommendations/[id]/page.tsx` — recommendation review.
  - Nav entry in `lib/navigation.ts` under *Security Operations* with label "Secure Component Advisor".
- Mirror `vex-investigation/page.tsx`:
  - URL state.
  - `DashboardFilters` for scope.
  - Risk filter chips (9 filters).
  - Debounced search with a facet selector.
  - KPI tiles that apply filters. Trusted tile renders only if `meta.policy_versions.trust` exists.
  - Table with column-group header.
  - Explicit empty/degraded states (the 11 states in spec §Step 9).
- `lib/api.ts` + `types/index.ts` additions (hand-written, per convention).
- Hooks:
  - `useCreateRecommendation`, `useRecommendationDecision`; both invalidate via new `invalidateComponentAdvisorSurfaces` (+ `invalidateDashboardTiles` not needed — recommendations don't change findings).
  - Policy mutations invalidate summary + list.
- Action buttons are driven by backend `capabilities` (`can_create`, `can_recommend`, `can_accept`, `can_reject`, `can_defer`, `can_request_evidence`, `read_only_reason`), like the VEX panel.
- Accessibility:
  - Severity, confidence and status each get text + icon.
  - `aria-live` on result counts.
  - Focus moves to the results heading on filter change.
  - Axe tests per page.
- Terminology guard: a unit test fails if UI strings contain "Vulnerability Free", "Safe", "Secure" (as a classification) or "Safety Score".

---

## 8. Proposed permissions (mapped onto existing catalogue)

| Permission | TENANT_ADMIN | SECURITY_ANALYST | DEVELOPER | VIEWER | Spec row |
|---|---|---|---|---|---|
| `component_advisor:read` (dashboard, search, adoption, evidence view) | ✅ | ✅ | ✅* | ✅* | View / Search / Adoption / Review evidence |
| `component_advisor:recommendation:create` (run recommendation) | ✅ | ✅ | ✅* | — | Run recommendation |
| `component_advisor:recommendation:review` (recommend candidate, reject, defer, request evidence) | ✅ | ✅ | — | — | Recommend / Reject / Defer |
| `component_advisor:recommendation:accept` | ✅ | ⚠ D-7 | — | — | Accept |
| `component_advisor:audit:read` | ✅ | ✅ | — | — | Audit history |
| `tenant:advisor_policy:read` | ✅ | ✅ | — | — | Configure (SA "recommend only") |
| `tenant:advisor_policy:update` | ✅ | — | — | — | Configure |
| `platform:advisor_policy:read/update` | PLATFORM_ADMIN | | | | Platform default policy |

\* "When granted" in the spec. The baseline grants it by default for Developer/Viewer read, because the existing catalogue has no per-tenant opt-in grants. Admins can remove it via role editing. See D-7.

Spec "Limited" audit for Developer/Viewer: the baseline gives no audit access; Developer/Viewer see a decision summary on the recommendation itself.

---

## 9. Test strategy

| Layer | Harness | Covers |
|---|---|---|
| Pure domain unit | pytest, no DB | T1–T9, T21 (ordering), T23–T29, workflow transitions, confidence, terminology |
| Metric / integration | pytest + Postgres, VEX seeding template + `recompute_for_sbom` | T7 (reconciliation to unique count), T10, T13, T14–T16, T22, T30 |
| API / security | pytest `client` + role actors (`test_vex_scoped_authorization.py` pattern), second tenant via Core insert | T11, T12, T17–T20, T31–T34; isolation across every endpoint (parametrized over the route table) |
| Architectural | existing `test_metric_consistency.py` (no allowlist additions), FE `mutation-invalidation.test.ts`, new "no auto-modification" test (advisor services import no SBOM/component write paths; DB snapshot before/after accept, T33) | CLAUDE.md rules, §1.1 |
| Frontend | Vitest + RTL + `vitest-axe`, `vi.mock('@/lib/api')` | T35–T43 as page-level integration tests |
| Browser E2E | **None exists** — see D-9 | T35–T43 if Playwright approved |
| Performance | pytest-benchmark `-m bench` with seeded dataset generator | T44 |
| Regression | `pytest` + `pytest -m integration` + `npm test` before/after each step | T45 |

Test names carry the scenario and ID, e.g. `test_T05_critical_plus_low_is_critical_bucket__FR_SCA_003`.

---

## 10. Risks, conflicts and open decisions

### Conflicts with repository rules (need explicit confirmation)
- **D-1 — CLAUDE.md VEX workstream "out of scope" list.** It names *"General component inventory dashboard"*, *"EOL/EOS"* and *"alternative-library recommendations"*. I read that list as scoping the **VEX** workstream, and the advisor as a **separate workstream** that consumes VEX/lifecycle read-only and changes neither. **Please confirm**, and whether CLAUDE.md should get an "SCA workstream" section (source of truth = this spec; plan file = `docs/secure-component-advisor/implementation-plan.md`).
- **D-2 — VEX PR-6/PR-7 not complete.** Advisor actionability depends on `VexInvestigation` being correct. Proceeding is safe for reads, but the advisor's own audit/RBAC must not wait on or duplicate VEX PR-6. Confirm parallel progress is acceptable.
- **Branch:** current branch `feat/native-user-management` is unrelated. Proposed: `feat/secure-component-advisor` off `main`, one PR per step (CLAUDE.md "one PR per session").

### Domain decisions
- **D-3 — Review Required triggers.** Confirm the precedence in §4 (conflict/revalidation/unresolved mapping, LOW identity confidence, stale evidence, UNKNOWN-severity actionable finding).
- **D-4 — Informational bucket.** The severity model has no INFORMATIONAL. Proposal: keep the enum value and filter but report `supported: false`; the UI hides the chip/KPI. No severity rewrite (VEX-DATA-005 spirit).
- **D-5 — VEX-only AFFECTED contexts** (vuln asserted by VEX, not detected by analyser). Proposal: they do not create a severity bucket (no fabricated finding) but force **Review Required**.
- **D-6 — Lifecycle "Maintenance" bucket.** Not a status in the model. Proposal: Supported ← Supported; Maintenance ← EOL Soon / Deprecated / Possibly Unmaintained; EOS ← EOS / EOF; EOL ← EOL / Unsupported; Unknown ← Unknown/null.
- **D-8 — Unique-version granularity.** PURL qualifiers stay in the canonical key (e.g. `?arch=`). Accept as-is (identity per existing normalizer), or strip qualifiers for advisor grouping?
- **D-10 — Recommendation idempotency scope.** Proposal: `(tenant, source canonical version, sbom or tenant-wide, trigger)`. Alternative: per product.

### Spec §12 open decisions (seams only)
| Decision | Finding | Baseline implemented |
|---|---|---|
| Product vs Application | `Product` exists; FE already labels "Application" | Reuse Product; UI label "Product/Application". No new entity needed anywhere. |
| Accepted-risk policy scope | Scoped config **supports** platform default + tenant override, **not versioning** | Platform default + tenant override, versioned via new `advisor_policy_version`. **No default policy seeded** → Accepted Risk KPI shows "policy not configured" until an admin creates one (needs confirmation). |
| Trusted-component definition | — | Seam only, disabled. Proposed criteria fields: `max_actionable_severity`, `allowed_lifecycle[]`, `allowed_licenses[]` / `denied_licenses[]`, `max_evidence_age_days`, `min_tenant_products` (optional, never sufficient alone), `require_no_blocking_policy`. |
| Purpose metadata source | **Coverage ≈ zero today.** No description column, parser drops it, no taxonomy. Registry/deps.dev descriptions not stored. | Add description extraction (additive) + curated `component_purpose_metadata` + optional AI classifier behind `AiSettings` gates with provenance/confidence. **Purpose search (T15) will mostly return "insufficient purpose evidence" until curated data or AI is enabled.** Seed curated categories? (needs decision) |
| External candidate sources | deps.dev / registries are already called for lifecycle; no candidate source | `PackageMetadataSource` Protocol (`list_versions`, `get_metadata`, `search_by_category`) returning `FetchOutcome`, with circuit breaker. **No adapter enabled in production** without an approved list. |
| Observation window | NVD mirror `published` + `find_by_cpe` per version (needs mirror enabled + CPE); findings `published_on` for observed versions. PURL-only components have weak history coverage. | Configurable window, default 24 months. `coverage` object reports source, CPE availability, window covered, gaps. |
| Scoring weights | — | Seeded **documented default** SCORING policy v1 (for review): current_risk 0.30, lifecycle 0.20, vuln_trend 0.15, compatibility 0.15, maintenance/release cadence 0.08, license 0.05, tenant adoption 0.05, freshness 0.02. Missing data → factor normalized 0 + recorded `missing_data_treatment="PENALIZED"`. |
| Performance benchmark | Existing bench harness only | Proposed dataset: 1 tenant × 20 projects × 100 products × 500 HEAD SBOMs × 400 components (200 k occurrences, ~25 k unique versions) × 150 k findings, + 2 noise tenants; 10 concurrent readers. |

### Other open items
- **D-7 — Role defaults.** Security Analyst accept ("policy dependent"), and Developer/Viewer read-by-default vs "when granted".
- **D-9 — E2E tooling.** No Playwright in the repo. Option A (recommended): implement T35–T43 as Vitest page-integration tests plus backend API integration tests. Option B: introduce Playwright (new dependency, needs seeded backend + auth bootstrapping).
- **D-11 — As-of / historical view.** Baseline: current state only. `as_of` echoes generation time; a non-now `as_of` returns 400 `AS_OF_NOT_SUPPORTED`. A true historical view needs VEX point-in-time state, which does not exist; propose deferring.
- **License policy.** None exists anywhere in `app/`. The license compatibility check returns UNKNOWN unless an advisor policy defines allowed/denied licenses. The license string is a single comma-separated value (SPDX expressions are not parsed).

### Principal technical risks
| Risk | Mitigation |
|---|---|
| On-read aggregation too slow for 200 k occurrences | New indexes + `memoize_with_ttl`; benchmark gate in Step 3; per-SBOM rollup fallback |
| Version comparison wrong outside PEP 440 | Use `app/sources/version_range.py`; unparseable → compatibility UNKNOWN, never PASS |
| `VexInvestigation` lag after a run | Treat missing context as UNDER_INVESTIGATION (actionable) — fail-safe |
| NVD mirror disabled / no CPE | History coverage marked partial, confidence reduced (FR-SCA-019/020) |
| Append-only not DB-enforced | ORM `before_flush` guard rejecting UPDATE/DELETE on event & policy-version tables (+ test) |
| Lifecycle circuit breaker in-memory | Advisor reads persisted lifecycle fields only; never calls providers synchronously on dashboard paths (NFR-SCA-003) |

---

## 11. Per-step implementation plan with traceability

Each step = one PR. Each runs `pytest`, `pytest -m integration`, `npm test`, and reports in the §15 template.

| Step | Scope | FR / NFR / US | Tests | DB |
|---|---|---|---|---|
| **1** | This document approved; decisions D-1…D-11 answered; branch created; plan file + CLAUDE.md SCA section | — | — | — |
| **2** | `app/metrics/component_advisor.py`: per-canonical-version aggregation over eligible SBOMs × latest run × `VexInvestigation`. Domain `classification`, `lifecycle_mapping`, `identity`. `intelligence_service`. Permissions migration. No UI. | FR-001, 003; NFR-002, 006, 009; US-01, 02 | T1–T7, T10, T11 (service level) | 067 |
| **3** | Router: summary, components list, detail, search (name/PURL/supplier/ecosystem). `meta` envelope. Memoization. `permission_for_request` branch. Benchmark harness + dataset generator. | FR-002, 006, 007, 008; NFR-001, 005; US-01, 05, 06, 07 | T11–T14, T44 (initial) | — |
| **4** | Policy tables + versioned evaluation (accepted risk; trust seam, disabled). Purpose metadata (description extraction, curated store, AI seam off). Adoption intelligence in detail. Policy endpoints. | FR-004, 005, 009, 010; NFR-007; US-03, 04, 07, 08 | T8, T9, T15, T16 | 068 |
| **5** | Recommendation work item + workflow + idempotency. Triggers (Critical/High/EOL/EOS/policy/manual). Same-family version discovery (tenant-observed versions, lifecycle latest/recommended, finding `fixed_versions`). Celery task with correlation. | FR-011, 013; NFR-004; US-09 | T17–T21 | 069 |
| **6** | Alternative discovery (tenant-observed by purpose + ecosystem; adapter Protocol; manual). Compatibility checks with blocking gates. Degraded-source handling. | FR-012, 014, 015; NFR-003; US-10 | T22–T26 | (069) |
| **7** | History service (24 mo + coverage), versioned scoring + factor persistence, confidence, reason/limitation codes, freshness. | FR-016–020; US-11–13 | T27–T30 | (069) |
| **8** | Decisions endpoint, capabilities, append-only events + guard, tenant audit mirror, isolation sweep across all endpoints. | FR-021–023; NFR-001, 007; US-14–16 | T31–T34, T11–T12 (full sweep) | (069) |
| **9** | Frontend: dashboard, detail, recommendation view, empty/degraded states, a11y, invalidation helper, nav, DEV_USER permissions. | FR-002, 006–010, 018–021; NFR-008; US-01–14 | T35–T43 | — |
| **10** | Analytics endpoint (Could), observability events/metrics, final benchmark, full regression, docs (API, runbook, migration notes, policy/source/weight configuration, traceability matrix). | FR-024; NFR-003–009; US-17 | T44, T45 | — |

### Definition of Done mapping
- DoD 1–2 → Steps 2–3.
- DoD 3 → Step 4.
- DoD 4–5 → Steps 3–4.
- DoD 6–8 → Steps 5–7.
- DoD 9 → Step 8.
- DoD 10 → architectural test in Step 5, re-asserted in Step 8.
- DoD 11–15 → Step 10.

---

## 12. Approval checklist

Please confirm or amend:
1. D-1 (separate SCA workstream; CLAUDE.md section) and branch strategy.
2. D-2 (proceed while VEX PR-6/7 open).
3. D-3 … D-6, D-8, D-10 (domain semantics).
4. D-7 (role defaults).
5. D-9 (E2E approach).
6. D-11 (current-state only; defer historical as-of).
7. Spec §12 baselines in §10 (no default accepted-risk policy; trust disabled; no external source enabled; proposed default weights; proposed benchmark dataset; whether to seed curated purpose categories).
