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
| 5 | Recommendation work item & safer-version discovery | ✅ 2026-10-01 |
| 6 | Alternative discovery & compatibility | ✅ 2026-10-01 |
| 7 | History, scoring, confidence, freshness | ✅ 2026-10-01 |
| 8 | Human review, audit, permissions | ⏳ next |
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

## Step 5 — Recommendation Work Item & Same-Family Safer-Version Discovery

Requirements: FR-SCA-011, FR-SCA-013, NFR-SCA-004 · US-SCA-09.

Delivered:
- Migration `069_component_recommendations`:
  - `component_recommendation` (TenantOwnedMixin, `row_version`).
  - Partial unique index `uq_component_recommendation_open` on (tenant, source canonical key,
    `scope_key` = sbom_id or 0, trigger) WHERE status is open. This is the DB guard for T20 / D-10.
  - `component_recommendation_candidate`.
- `recommendations/workflow.py` (pure):
  - States OPEN → EVALUATING → REVIEW_REQUIRED → RECOMMENDED → ACCEPTED | REJECTED | DEFERRED → CLOSED,
    with an explicit transition table. Only RECOMMENDED can reach ACCEPTED, so there are no shortcuts past review.
  - Triggers are validated against current evidence (422 `TRIGGER_NOT_SUPPORTED_BY_EVIDENCE`).
- `recommendations/version_discovery.py` (pure):
  - Same-family candidates come from tenant-observed versions, lifecycle hints (latest / latest supported /
    recommended) and finding fix versions.
  - Each candidate carries posture, fix coverage, lifecycle, license change, version direction / major change,
    freshness and adoption.
  - Missing dimensions are explicit limitations: history, cadence, platform, transitive dependencies,
    regression testing.
  - Versions that are not safer, and unobserved downgrades, are excluded with a reason.
- `recommendations/service.py`:
  - Idempotent create (existing open item → 200 `created:false`; a race is caught by the unique index).
  - Evaluation runs under the **tenant-wide** scope; the session scope is swapped so a narrower request scope
    can never poison the tenant snapshot cache.
  - Candidate writes run in a savepoint; a failure is recorded as `DISCOVERY_FAILED`, never a silent pass.
  - Audit (`component_advisor.recommendation.created/evaluated`); structured events
    `recommendation.created`, `recommendation.discovery.started/completed/failed` with correlation id and duration.
- Celery task `component_advisor.evaluate_recommendation` (`app/workers/component_advisor_tasks.py`):
  acks_late, retries on OperationalError, tenant-bound, idempotent.
- API:
  - `POST /recommendations` (scope via `project_id`/`product_id`/`sbom_id`; `evaluate` default true).
  - `GET /recommendations` (status / trigger / key / sbom filters), `GET /recommendations/{id}`,
    `GET /recommendations/{id}/candidates`, `POST /recommendations/{id}/evaluate` (409 if not OPEN/REVIEW_REQUIRED).
  - Component detail and list now show the open work item and `eligible_triggers`.

Decisions / assumptions:
- Evaluation always ends in REVIEW_REQUIRED. RECOMMENDED needs a reviewer (Step 8).
- POLICY_VIOLATION baseline: a configured trust policy evaluates the version as *not trusted*; the failed criteria
  are stored as trigger evidence. Accepted-risk "not satisfied" is not treated as a violation. **Needs product confirmation.**
- Fix coverage is conservative: a candidate fixes a vulnerability only if a declared fix version is on the same major
  line and the candidate is not older. Anything else is "unknown", never "fixed".
- Candidates are ordered for review only: observed + lower risk first, then fix coverage, then upgrades.
  There is no score until Step 7, and `approved_replacement` is always false.
- Re-evaluation replaces the candidate set; the audit log keeps each evaluation's summary.
  The decision/event table arrives in Step 8.
- Deviation from phase-0 §5: factor, compatibility-check and event tables are deferred to the migrations for
  Steps 6–8, so each migration only adds what its step uses.

## Step 6 — Tenant-First / External Alternative Discovery & Compatibility Evaluation

Requirements: FR-SCA-012, FR-SCA-014, FR-SCA-015, NFR-SCA-003 · US-SCA-10.

Delivered:
- `recommendations/alternative_discovery.py`:
  - Gate: discovery runs only with an established ecosystem (not generic), an evidenced `technology_category`
    and product constraints. Otherwise it returns `INSUFFICIENT_ECOSYSTEM_EVIDENCE` / `INSUFFICIENT_PURPOSE_EVIDENCE` /
    `PRODUCT_CONSTRAINTS_UNAVAILABLE`.
  - Order: tenant-observed families (same category + ecosystem; the safest observed version per family; adoption
    evidence, T22) → configured external adapters → manual reviewer candidates.
  - Purpose mismatches (T23) and not-safer families are excluded with reasons.
- `sources.py`: `PackageMetadataSource` adapter contract.
  - **No production adapter is registered.**
  - Each adapter call has a timeout and a per-source `CircuitBreaker` (threshold 3, reset 15 min).
  - Failures surface as `*_EXTERNAL_SOURCE_DEGRADED` plus per-source outcomes, never as errors (NFR-SCA-003).
- `recommendations/compatibility.py` (pure):
  - All 14 spec check types, each PASS / FAIL / REVIEW_REQUIRED / UNKNOWN with evidence, reason, limitation,
    blocking flag and evaluated time.
  - Blocking: different ecosystem or language, no or mismatched purpose for an alternative, outside product
    constraints, denied or unlisted license (T24), known API/ABI break, unsupported OS/runtime/architecture that the
    product needs (T25), regulatory block, lifecycle forbidden by policy (EOL forbidden by default) (T26).
  - Missing evidence is UNKNOWN and never PASS.
  - `drop_in_representable` is false unless every check passes.
- Migration `070_component_recommendation_compatibility`: `component_recommendation_compatibility_check`.
- Service:
  - Every candidate (same-family, alternative, manual) runs through the gates.
  - Ranking: same-family before alternatives (T21); blocked candidates last within each kind.
  - Manual candidates are rebuilt from their stored input on re-evaluation.
  - `add_manual_candidate` is audited.
- API:
  - `POST /recommendations/{id}/candidates` (manual; requires `component_advisor:recommendation:review`;
    REVIEW_REQUIRED items only).
  - `GET /recommendations/{id}/candidates/{cid}` and `/compatibility`.
  - The discovery summary now includes alternatives status, category, product constraints, external source
    outcomes and the blocked count.

Decisions / assumptions:
- **Product constraints baseline:** the ecosystems present in the products that use the source (tenant-wide items
  use the source's SBOMs). There is no product platform/runtime model, so OS/runtime/architecture are UNKNOWN unless
  adapter or reviewer evidence plus product needs exist.
- **License policy:** the trust policy's `allowed_licenses` / `denied_licenses` lists act as the license policy.
  Without them, a license change is REVIEW_REQUIRED.
- **Lifecycle:** a trust policy's `allowed_lifecycle` decides when it is configured. Otherwise EOL is a blocking FAIL
  and EOS is REVIEW_REQUIRED.
- Alternative purpose similarity = equal evidenced `technology_category` (case-insensitive). Finer similarity (use
  case) is not scored yet.
- Manual purpose statements are recorded as reviewer-provenanced CURATED evidence, and a reviewer cannot bypass a
  blocking check.
- One Step 5 test expectation changed: alternatives are now evaluated, so a scenario without purpose data reports
  `INSUFFICIENT_PURPOSE_EVIDENCE`.

## Step 7 — Vulnerability History, Transparent Scoring, Confidence & Freshness

Requirements: FR-SCA-016, FR-SCA-017, FR-SCA-018, FR-SCA-019, FR-SCA-020 · US-SCA-11, US-SCA-12, US-SCA-13.

Delivered:
- `recommendations/history.py` + `advisor_version_history` (metrics, **Convention C** over runs of eligible SBOMs only):
  - The window comes from the scoring policy (default 24 months).
  - Sources: TENANT_ANALYSIS, and the NVD_MIRROR `find_by_cpe` per version when the mirror is enabled and a CPE
    exists (same-family candidates use the source CPE with their version).
  - Output: disclosed count, severity distribution, Critical/High count, first/last observed, exposure days, and
    `coverage` {covered_months, sources, gaps}.
  - `NO_VULNERABILITIES_IN_COVERED_WINDOW` always carries the "not proof of security" note; no coverage is
    `NO_HISTORY_COVERAGE` (T28/T30).
- `recommendations/scoring.py`:
  - New versioned `SCORING` policy kind at `/policies/scoring`. With none configured, the documented built-in
    default `builtin-default-2026-10-01` applies.
  - Eight factors, each persisted with raw value, normalized value, weight, contribution, missing-data treatment
    (PENALIZE | EXCLUDE), evidence source / time and policy version id + label (T29).
  - The score orders candidates only (`score_semantics: ORDERS_CANDIDATES_ONLY`).
- `recommendations/confidence.py`:
  - HIGH / MEDIUM / LOW / INSUFFICIENT_EVIDENCE from completeness (policy-weight share with evidence), observed
    posture / history, UNKNOWN material checks (LICENSE, LIFECYCLE, FUNCTIONAL_PURPOSE, PRODUCT_CONSTRAINTS,
    API_COMPATIBILITY) and freshness.
  - Stale evidence lowers confidence one level. Missing material evidence lowers confidence and rules out drop-in (T27).
  - `freshness_view`: SBOM analysis, tenant observation, vulnerability source (NVD mirror last success), package
    metadata, lifecycle, observation window, stale flags.
- `recommendations/explanation.py`: rationale sentences rendered from reason / limitation / confidence codes
  (`generated_from: STRUCTURED_EVIDENCE`); a vocabulary test forbids "safe" / "secure" / "vulnerability free".
- Migration `071_component_recommendation_factors`.
- Service: one `_build_row` path (gates → history → score → freshness → confidence → explanation) for discovered and
  manual candidates. Ranking = kind, then blocked last, then score desc. Discovery summary adds `source_history`,
  `scoring_policy`, `vulnerability_source_freshness`.
- API: `GET /recommendations/{id}/candidates/{cid}/evidence`; candidates now expose score, confidence, explanation,
  history and freshness; `meta.freshness.vulnerability_source_refreshed_at` is filled.

Decisions / assumptions:
- Factor normalizations (documented in `scoring.py`):
  - risk: NKAV 1.0 … CRITICAL 0.
  - lifecycle: SUPPORTED 1, MAINTENANCE 0.6, EOS 0.2, EOL 0.
  - trend: 1 / (1 + critical/high + 0.25 × others).
  - compatibility: (PASS + 0.5 × REVIEW) / known checks; 0 when blocked.
  - license: from the LICENSE check.
  - adoption: min(products / 5, 1).
  - freshness: ≤30 d 1, ≤90 d 0.6, ≤180 d 0.3.
  - maintenance: no source yet, so always missing.
- `stale_after_days` (default 90) lowers confidence and flags staleness, but **does not** change a component's
  risk bucket. Stale evidence "reduces confidence" per FR-SCA-020; `ReviewReason.STALE_EVIDENCE` stays unused so
  KPIs stay stable. **Product decision pending** on whether stale analysis should push a component into Review Required.
- Same-family candidates still rank before alternatives regardless of score (T21); the score orders within a kind.

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
- Confirm the POLICY_VIOLATION trigger definition (Step 5 baseline: trust policy says "not trusted").
- Product platform/runtime constraints model (would turn many OS/RUNTIME/ARCH UNKNOWNs into PASS/FAIL).
- A dedicated license policy, separate from the trust policy, if the business wants license gating without trust.
- Approved external package-metadata sources (spec §12) before any adapter is registered.
- Should stale analysis evidence (older than the scoring policy's `stale_after_days`) put a component into Review Required?
  Currently it only lowers recommendation confidence.
- Review the proposed default scoring weights and normalizations.
- Windows: a stopped background pytest leaves orphan processes on the test DB. Kill them before the next run.
- Regression runs must use a frozen worktree: twice, a migration added mid-run made later app-startup tests fail
  with "schema not at head", which invalidated those runs.
