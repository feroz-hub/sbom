# Secure Component Advisor — Implementation Plan (running log)

Plan and decisions: [`phase0-analysis.md`](./phase0-analysis.md). Spec:
[`../specs/Secure_Component_Advisor_Requirements_v1_1.docx`](../specs/Secure_Component_Advisor_Requirements_v1_1.docx).
Branch: `feat/secure-component-advisor`. Test ids T1…T45 are the prompt §10 matrix.

## Status

| Step | Scope | Status |
|---|---|---|
| 1 | Phase 0 approved; branch; plan file; CLAUDE.md SCA section | ✅ 2026-10-01 |
| 2 | Component intelligence foundation & risk semantics | ✅ 2026-10-01 (this log) |
| 3 | Dashboard / filters / drill-down / search API | ⏳ next |
| 4 | Accepted-risk / trust policy seam, purpose, adoption | ☐ |
| 5 | Recommendation work item & safer-version discovery | ☐ |
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

## Open questions / follow-ups
- **Review Required vs Critical (D-3 side effect):** with the approved precedence, a version with a
  known CRITICAL finding *and* a VEX conflict on another vulnerability lands in Review Required, so it
  is not in the Critical KPI. Its `highest_actionable_severity` stays CRITICAL on the row. If the
  Critical/High KPIs should count it as well, the fix is to let CRITICAL/HIGH outrank review reasons.
  Needs a product decision before Step 3 ships the KPIs.
- `latest_run_per_sbom_as_of_subquery` skips the active-HEAD filter; irrelevant until historical
  `as_of` is in scope (D-11).
- Stale-evidence thresholds (`ReviewReason.STALE_EVIDENCE`) are wired in Step 7.
