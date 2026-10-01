# Secure Component Advisor — Implementation Plan (running log)

Plan and decisions: [`phase0-analysis.md`](./phase0-analysis.md). Spec:
[`../specs/Secure_Component_Advisor_Requirements_v1_1.docx`](../specs/Secure_Component_Advisor_Requirements_v1_1.docx).
Branch: `feat/secure-component-advisor`. Test ids T1…T45 are the prompt §10 matrix.

## Status

| Step | Scope | Status |
|---|---|---|
| 1 | Phase 0 approved; branch; plan file; CLAUDE.md SCA section | ✅ 2026-10-01 |
| 2 | Component intelligence foundation & risk semantics | ✅ 2026-10-01 |
| 3 | Dashboard / filters / drill-down / search API | ✅ 2026-10-01 |
| 4 | Accepted-risk / trust policy seam, purpose, adoption | ✅ 2026-10-01 |
| 5 | Recommendation work item & safer-version discovery | ⏳ next |
| 6 | Alternative discovery & compatibility | ☐ |
| 7 | History, scoring, confidence, freshness | ☐ |
| 8 | Human review, audit, permissions | ☐ |
| 9 | Frontend | ☐ |
| 10 | Tests, performance, observability, analytics, docs | ☐ |

## Decisions (approved 2026-10-01)

The user said "Approved, go with your recommendations" for everything in phase0-analysis.md §10 and §12:
D-1 separate workstream · D-2 proceed while VEX PR-6/7 open · D-3 Review Required precedence ·
D-4 no INFORMATIONAL bucket (filter reported unsupported) · D-5 VEX-only AFFECTED → Review Required ·
D-6 lifecycle mapping · D-7 role defaults (§8) · D-8 PURL qualifiers stay in identity ·
D-9 Vitest page tests instead of Playwright · D-10 recommendation idempotency per
(tenant, canonical version, SBOM-or-tenant, trigger) · D-11 current state only, non-now `as_of` → 400.
Spec §12 baselines: no default accepted-risk policy, trust disabled, no external source enabled,
proposed default weights, proposed benchmark dataset.

**Branch base deviation:** local `main` (`6d082b2`) is ~30 commits behind the integration line
(IAM, platform V2, VEX, migrations up to 066). The branch was cut from
`feat/native-user-management` @ `6425f3e` + the two SCA docs commits, not from `main`.

## Step 2 — Component Intelligence Foundation & Risk Semantics

Requirements: FR-SCA-001, FR-SCA-003, NFR-SCA-002, NFR-SCA-006, NFR-SCA-009 · US-SCA-01, US-SCA-02.

Delivered:
- `app/services/component_advisor/classification.py` — pure §2 buckets with D-3/D-4/D-5 precedence.
- `app/services/component_advisor/lifecycle_mapping.py` — D-6 lifecycle buckets; manual override, then latest check wins.
- `app/services/component_advisor/identity.py` — unique-version key reuses `dedupe_canonical_id` /
  `build_identity_key`; LOW-confidence rows stay per occurrence (`occ-<id>`) and are flagged for review.
- `app/metrics/component_advisor.py` — Convention A aggregation over eligible SBOMs × latest successful
  run × current `VexInvestigation`, joined on the *canonical* vulnerability id (`canonical_for_finding`).
- `app/services/component_advisor/intelligence_service.py` — `DashboardScope` entry point.
- Migration `067_component_advisor_foundation` — `(tenant_id, dedupe_canonical_id)` and
  `(tenant_id, normalized_package_key)` indexes; `component_advisor:*` permissions (frozen seed
  `app/authorization_catalog_seed_v3.py`), wired into `ROLE_PERMISSIONS`, the conftest catalogue
  reset, `scripts/compare_authorization_catalog.py` and the phase-8 seed test.

Implementation notes:
- Counting unit is the *distinct canonical vulnerability* per unique version. A vulnerability is
  actionable for the version if it is actionable in at least one current occurrence context
  (conservative across SBOMs); severity is the max across occurrences.
- Findings on `is_duplicate` rows count toward their canonical version; usage counts skip duplicates.
- Actionable findings with no `component_id` cannot be tied to a version; they are reported as
  `unattributed_actionable_findings`, never dropped silently.
- VEX-only contexts are counted (`vex_only_context_count`) but never become findings or severities.
- Purpose (`NOT_AVAILABLE`) and recommendation (`NOT_EVALUATED`) are placeholders in the contract until
  Steps 4 and 5.
- Aggregation is computed on read. Memoization and the benchmark gate come in Step 3.

Test results (Postgres on 5432, isolated DB `sbom_analyser_test_sca`):
- New: `tests/test_component_advisor_classification.py` 35 passed; `tests/test_component_advisor_intelligence.py`
  25 passed (T1–T7, T10, T11).
- Related existing suites (metric consistency, migration drift, alembic metadata, phase-8 catalogue,
  RBAC, platform tenant V2, VEX scoped authorization, phase-9 resolution, dashboard scope):
  108 passed + 1 fixed, 3 failed. All 3 fail identically on clean `HEAD` (pre-existing):
  - `test_rbac_permissions.py::test_platform_admin_has_all_permissions` and
    `::test_high_value_permission_separation`: assume PLATFORM_ADMIN holds tenant permissions,
    which platform V2 segregation removed.
  - `test_vex_scoped_authorization.py::test_platform_override_stays_tenant_bound`: response has no
    `capabilities` key.
- Fixed in passing: `scripts/compare_authorization_catalog.py` did `tuple | frozenset` for TENANT_ADMIN, so
  `test_phase8_authorization_catalog_seed.py::test_operator_comparison_reports_zero_mismatches` failed on `HEAD`.
- Full-suite baseline: the whole suite takes many hours locally (~4% after 40 min, because of per-test
  truncation). A clean-`HEAD` baseline is running in a scratch worktree; the full before/after comparison
  is recorded at Step 10 (T45).

## Step 3 — Dashboard, Filters, Drill-down and Search

Requirements: FR-SCA-002, FR-SCA-006, FR-SCA-007, FR-SCA-008, NFR-SCA-001, NFR-SCA-005 ·
US-SCA-01, US-SCA-05, US-SCA-06, US-SCA-07.

Delivered:
- Precedence amendment: CRITICAL/HIGH outrank review reasons; accepted risk never applies to
  Critical/High or to a version with review reasons.
- `app/services/component_advisor/filters.py` (pure): risk / lifecycle / needs-review /
  frequently-adopted / search filters, sorting, the nine KPI cards (each with the `/components` filter
  that reproduces it) and family-grouped search results.
- `intelligence_service.py`: memoized snapshot (TTL 60 s; key = scope + shared metrics key +
  `advisor_invalidation_key`, which also tracks VEX decisions, lifecycle checks and SBOM / product /
  project activation), `resolve_as_of` (D-11), and the shared `meta` envelope.
- `app/routers/component_advisor.py`: `GET /api/component-advisor/{summary,components,components/{key},search}`;
  `permission_for_request` branch; `component_advisor:read` re-checked per route; ETag on summary/list.
- `scope_metadata` moved from `dashboard_main.py` into `app/services/dashboard_scope.py` so both routers share it.
- Benchmark `tests/test_component_advisor_bench.py` (`-m bench`, scale via env).

API contract (all GET, scope via `project_id` / `product_id` / `sbom_id`):
- Filters: `risk` (repeat or comma; the nine spec values), `lifecycle`, `needs_review`, `frequently_adopted`,
  `q` + `facet` (`all|name|purl|supplier|ecosystem|category|purpose`), `as_of` (now only).
- Errors: 400 `INVALID_FILTER`, 400 `AS_OF_NOT_SUPPORTED`, 400 child-without-parent, 404 foreign/unknown
  scope or component key, 403 missing `component_advisor:read`.
- `meta`: `applied_filters`, `unsupported_filters`, `scope`, `as_of`, `generated_at`, `historical_view`,
  `freshness` (latest analysis, lifecycle check, coverage, stale flags), `policy_versions`, `thresholds`,
  `capabilities`.

Decisions / assumptions:
- "Frequently Adopted" = used by ≥ 3 distinct products in scope (`FREQUENT_ADOPTION_MIN_PRODUCTS`). The spec gives no
  number, so it is returned in `meta.thresholds` for review.
- Accepted-Risk and Trusted KPIs return `value: null, status: POLICY_NOT_CONFIGURED` (Trusted also `render: false`)
  rather than a misleading 0.
- Purpose/category facets return `INSUFFICIENT_PURPOSE_EVIDENCE` and never match on names.
- Search lists versions per family without ranking them; ranking is Step 7.

## Step 4 — Accepted-Risk / Trust Policy Seam, Purpose and Adoption Intelligence

Requirements: FR-SCA-004, FR-SCA-005, FR-SCA-009, FR-SCA-010, NFR-SCA-007 · US-SCA-03, US-SCA-04, US-SCA-07, US-SCA-08.

Delivered:
- Migration `068_component_advisor_policies`:
  - `advisor_policy` slots: platform default (`tenant_id IS NULL`) plus one tenant override per kind.
  - Append-only `advisor_policy_version`, guarded by an ORM `before_flush` hook that rejects UPDATE/DELETE.
  - `component_purpose_metadata`.
  - `sbom_component.description`.
  - `tenant:advisor-policy:read/update` permissions (frozen seed v4): Tenant Admin read+update, Security Analyst read.
- `policy.py` (pure): validation and evaluation for accepted-risk and trust rules, with a per-criterion trace.
  - Accepted risk is capped at MEDIUM and never applies with review reasons.
  - Trust requires a classification and a lifecycle criterion, so adoption alone can never grant it (T9).
- `policy_service.py`: tenant → platform resolution; ACTIVE / DISABLED / INHERIT versions; optimistic concurrency (409);
  each publish is audited (`component_advisor.policy.version_published`).
- `purpose.py` / `purpose_service.py`:
  - Each purpose field is resolved by source priority SBOM → PACKAGE → CURATED → AI, with provenance.
  - AI-sourced fields are flagged `ai_assisted`; AI rows require `provenance.model` + `generated_at`.
  - Search matches only evidenced fields, so LOW-confidence AI never matches (T15/T16).
- Parsers (CycloneDX JSON/XML, SPDX `description`/`summary`) now keep component descriptions;
  `scripts/backfill_component_descriptions.py` fills existing rows (only NULLs, `--dry-run` / `--apply`).
- API:
  - `GET /components/{key}/classification` (decided-by rule + policy traces).
  - `GET|POST /policies/{accepted-risk|trust}[/versions]`.
  - `GET|PUT /purpose/{family_key}` (curated writes use the existing `component:update`).
  - `adoption` block on component detail (products/projects by name, observed family versions, `CONTEXTUAL_EVIDENCE_NOT_PROOF`).
  - `trusted` filter, and real values for the Accepted-Risk / Trusted KPIs once a policy exists.
- Snapshot cache key now includes effective policy version ids and a purpose-row marker.

Decisions / assumptions:
- Every change is a new immutable version, including disable and reset: `INHERIT` withdraws a tenant override.
- Accepted-risk rules: `max_actionable_severity` (MEDIUM|LOW, required), `max_cvss_score`,
  `allowed_actionable_vex_statuses`, `max_actionable_vulnerabilities`, `allowed_lifecycle`, `max_analysis_age_days`.
  "Explicit risk acceptance" (e.g. `VulnerabilityRemediation` = Accepted Risk) is **not** implemented; open item.
- Trust rules: `allowed_classifications` (NKAV / ACCEPTED_RISK / LOW / MEDIUM only), `allowed_lifecycle` (both required),
  `allowed_licenses`, `denied_licenses`, `max_evidence_age_days`, `min_tenant_products`, `require_no_review_reasons`.
- Permission names use the scoped-configuration family form `tenant:advisor-policy:*` (the phase-0 table wrote
  `tenant:advisor_policy:*`), so the existing `require_configuration_permission` helper applies unchanged.
- "Typical development purpose" is carried by `primary_use_case`.

## Open questions / follow-ups
- ~~Review Required vs Critical~~ — **resolved 2026-10-01**: the user decided Critical/High outrank review
  reasons. Implemented in Step 3 (`classification.py`); review reasons stay on the record and the
  "Components Requiring Review" KPI counts every version with a reason, whatever its bucket.
- `latest_run_per_sbom_as_of_subquery` skips the active-HEAD filter; irrelevant until historical
  `as_of` is in scope (D-11).
- Stale-evidence thresholds (`ReviewReason.STALE_EVIDENCE`) are wired in Step 7.
- Confirm the "Frequently Adopted" threshold (3 products) or make it a tenant policy setting.
- **Platform-default policy write API** is deferred. It needs `platform:advisor-policy:*`, which changes the frozen
  Platform Admin V2 allowlist and the `/api/platform/configuration` mapping. Platform rows are already honoured
  in resolution (tested by direct insert).
- Explicit risk acceptance as an accepted-risk criterion (link to `VulnerabilityRemediation` "Accepted Risk").
- **Cold snapshot cost:** about 14 s at the sign-off scale (200k occurrences); warm summary and drill-down are about 1 s.
  TTL raised to 300 s. If cold rebuilds are unacceptable, add the per-SBOM incremental rollup (NFR-SCA-006).
- Run `scripts/backfill_component_descriptions.py --apply` after deploying 068.
