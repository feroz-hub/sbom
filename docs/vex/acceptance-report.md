# VEX Dashboard & Investigation — Acceptance Report

**Spec:** [`docs/requirements/vex-dashboard-investigation.md`](../requirements/vex-dashboard-investigation.md) v1.0
**Branch:** `SBOM_VEX`
**Date:** 2026-09-24
**Last verified:** `pytest tests/test_vex_acceptance_e2e.py` — 22 passed (2026-09-24)

Maps every section 47 acceptance scenario and every section 48 Definition of Done item to the
test that covers it. Anything not met is listed as an open item rather than omitted.

**Status reporting rule used here:** a row is *Pass* only when a named test asserts it and that
test has been observed green. A test that exists but has not been run is marked *Written, unrun*,
never Pass. As of the last verification every row has been observed green.

---

## 1. Section 47 acceptance matrix

| # | Scenario | Test | Status |
|---|---|---|---|
| 1 | Embedded VEX CVE not found by analyser → `VEX_ONLY` | `test_vex_acceptance_e2e.py::test_embedded_vex_only_cve_survives__VEX_REC_002_C` | **Pass** |
| 2 | Analyser CVE with no VEX → `UNDER_INVESTIGATION` + `ANALYZER_ONLY` | `test_vex_reconciliation_engine.py::test_analyzer_only__VEX_REC_002_A` · `test_vex_decisions.py::test_detected_finding_yields_an_under_investigation_context__GAP_001` | **Pass** |
| 3 | Same CVE in analyser + VEX → one context, no duplicate | `test_vex_reconciliation_engine.py::test_analyzer_and_vex_not_affected__VEX_REC_002_B` | **Pass** |
| 4 | Analyser + VEX AFFECTED → AFFECTED + MATCHED | `test_vex_reconciliation_engine.py::test_analyzer_and_vex_affected__VEX_REC_002_E` | **Pass** |
| 5 | Analyser + VEX NOT_AFFECTED → NOT_AFFECTED + MATCHED | `test_vex_reconciliation_engine.py::test_analyzer_and_vex_not_affected__VEX_REC_002_B` | **Pass** |
| 6 | Analyser + VEX UNDER_INVESTIGATION → UNDER_INVESTIGATION + MATCHED | `test_vex_reconciliation_engine.py::test_analyzer_and_vex_under_investigation__VEX_REC_002_F` | **Pass** |
| 7 | Analyser redetects FIXED CVE → UNDER_INVESTIGATION + `REVALIDATION_REQUIRED` | `test_vex_reconciliation_engine.py::test_redetected_fixed_requires_revalidation__VEX_REC_002_G` | **Pass** |
| 8 | VEX-only AFFECTED → AFFECTED + `VEX_ONLY` | `test_vex_reconciliation_engine.py::test_vex_only_affected_is_flagged__VEX_REC_002_D` | **Pass** |
| 9 | VEX-only NOT_AFFECTED → NOT_AFFECTED + `VEX_ONLY` | `test_vex_reconciliation_engine.py::test_vex_only_not_affected__VEX_REC_002_C` | **Pass** |
| 10 | VEX-only FIXED → FIXED + `VEX_ONLY` | `test_vex_reconciliation_engine.py::test_vex_only_fixed__VEX_REC_002_C` | **Pass** |
| 11 | GHSA finding aliases VEX CVE → same context | `test_vex_reconciliation_engine.py::test_ghsa_finding_and_cve_vex_share_one_context__VEX_CTX_002` · e2e `test_ghsa_finding_and_cve_vex_share_one_context__VEX_CTX_002` | **Pass** |
| 12 | Same CVE on two components → two contexts | `test_vex_reconciliation_engine.py::test_same_cve_on_two_components_is_two_contexts__VEX_CTX_001` | **Pass** |
| 13 | Same CVE on two component versions → separate contexts | `test_vex_reconciliation_engine.py::test_same_cve_on_two_versions_is_two_contexts__VEX_CTX_001` | **Pass** |
| 14 | Multiple scanners find same vulnerability → one context | `test_vex_reconciliation_engine.py::test_multiple_scanners_collapse_to_one_context__VEX_REC_003` · e2e `test_three_scanners_produce_one_context__VEX_REC_003` | **Pass** |
| 15 | Ambiguous component mapping → `UNRESOLVED_MAPPING` | `test_vex_reconciliation_engine.py::test_ambiguous_weak_match_does_not_bind__VEX_MAP_001` · `test_unresolved_mapping_becomes_its_own_context__VEX_MAP_001` | **Pass** |
| 16 | VEX version range doesn't apply → VEX not applied | `test_vex_reconciliation_engine.py::test_non_applicable_statement_cannot_become_effective__VEX_MAP_002` · `test_version_range_that_does_not_apply__VEX_MAP_002` | **Pass** |
| 17 | Conflicting VEX sources → `CONFLICT_REVIEW_REQUIRED` | `test_vex_reconciliation_engine.py::test_conflicting_independent_sources__VEX_INV_005` · e2e `test_conflicting_suppliers_require_review__VEX_INV_005` | **Pass** |
| 18 | Duplicate VEX document upload → idempotent | `test_vex_investigation_foundation.py::test_reimporting_the_same_document_is_a_no_op__VEX_ING_002` | **Pass** |
| 19 | Re-analysis after manual decision → decision preserved | `test_vex_reconciliation_engine.py::test_reanalysis_preserves_a_manual_decision__VEX_INV_001` · `test_vex_audit_concurrency.py::test_reconciliation_preserves_a_manual_decision__VEX_INV_004` | **Pass** |
| 20 | Source API fails → `SOURCE_ERROR`, not `NOT_DETECTED` | `test_vex_reconciliation_engine.py::test_source_failure_is_not_not_detected__VEX_REC_004` | **Pass** |
| 21 | `not_affected` without evidence → validation failure | `test_vex_investigation_foundation.py::test_not_affected_still_requires_evidence__VEX_VAL_001` · API `test_not_affected_without_evidence_is_rejected__VEX_VAL_001` | **Pass** |
| 22 | Ordinary CycloneDX vulnerability with no analysis → not a VEX determination | `test_vex_reconciliation_engine.py::test_plain_vulnerability_entry_is_not_a_vex_assertion__VEX_ING_001` · e2e `test_plain_disclosure_entry_is_not_a_vex_determination__VEX_ING_001` | **Pass** |
| 23 | CycloneDX `false_positive` → native preserved, normalized retained | `test_vex_investigation_foundation.py::test_cyclonedx_false_positive_keeps_its_native_value__VEX_STAT_002` | **Pass** |
| 24 | Inactive SBOM → excluded from current dashboard | `test_vex_acceptance_e2e.py::test_inactive_sbom_is_excluded_from_current_counts__VEX_DASH_005` | **Pass** |
| 25 | Superseded SBOM → excluded from current dashboard | `test_vex_acceptance_e2e.py::test_superseded_sbom_version_is_excluded__VEX_DASH_005` | **Pass** |
| 26 | Cross-tenant access → rejected | `test_vex_investigations_api.py::test_cross_tenant_detail_is_404_not_403__VEX_SEC_002` · `test_vex_audit_concurrency.py::test_cross_tenant_mutations_are_rejected__VEX_SEC_002` | **Pass** |
| 27 | Concurrent analyst updates → conflict detected | `test_vex_investigations_api.py::test_stale_row_version_conflicts__VEX_AUD_002` · `test_vex_audit_concurrency.py::test_assignment_conflicts_on_a_stale_version__VEX_AUD_002` | **Pass** |

**27 of 27 Pass.** The `test_vex_acceptance_e2e.py` suite ran green (22 tests), which closed the
three rows that previously had no coverage: 1 (VEX-only survival), 24 (inactive SBOM) and 25
(superseded SBOM).

---

## 2. Section 48 Definition of Done

| # | Item | Evidence | Status |
|---|---|---|---|
| 1 | Every current analyser finding has a VEX investigation state | `test_vex_acceptance_e2e.py::test_backfill_gives_every_current_finding_a_context__DoD_1` | **Met** |
| 2 | New findings without VEX default to `UNDER_INVESTIGATION` | Row 2 above | **Met** |
| 3 | Embedded/imported VEX-only vulnerabilities retained | Rows 1, 8-10 | **Met** |
| 4 | Scanner findings and VEX reconciled without duplication | Rows 3, 14 | **Met** |
| 5 | CVE/GHSA/OSV aliases reconciled | Row 11; `app/services/vex/identity.py` | **Met** |
| 6 | VEX status is component/version/product-context specific | Rows 12, 13; `uq_vex_investigation_context` | **Met** |
| 7 | Source-native VEX status preserved | Row 23; `VexStatement.source_status` | **Met** |
| 8 | Conflicting assertions visible | Row 17; detail payload lists every assertion | **Met** |
| 9 | Fixed-but-redetected vulnerabilities require revalidation | Row 7 | **Met** |
| 10 | Manual decisions survive re-analysis and later imports | Row 19 | **Met** |
| 11 | Current investigation uses latest successful analysis state | `test_vex_reconciliation_engine.py::test_only_the_latest_successful_run_counts__GAP_008` | **Met** |
| 12 | Historical findings and decisions remain auditable | `test_vex_reconciliation_engine.py::test_vanished_context_is_retired_not_deleted__VEX_INV_002`; `test_vex_audit_concurrency.py::test_audit_is_append_only__VEX_AUD_001` | **Met** |
| 13 | Dashboard counts include analyser-only and VEX-only correctly | `test_vex_dashboard_metrics.py::test_three_analyser_cves_and_one_vex_only__VEX_DASH_001` | **Met** |
| 14 | Dashboard status totals reconcile mathematically | `test_vex_dashboard_metrics.py::InvariantTests` (3 tests) | **Met** |
| 15 | Unresolved mappings visible and cannot reduce risk | `test_vex_dashboard_metrics.py::test_unresolved_mappings_are_excluded_from_the_total__VEX_DASH_002` | **Met** |
| 16 | Dedicated VEX Investigation UI available | `frontend/src/app/vex-investigation/page.tsx`; 15 tests in `page.test.tsx` | **Met** |
| 17 | Tenant/Project/Application/SBOM filters apply consistently | `test_vex_investigations_api.py` filter tests; `test_tile_counts_equal_row_counts_for_the_same_filters__VEX_DASH_004` | **Met** |
| 18 | `vex:read` / `vex:write` enforced server-side | `test_vex_audit_concurrency.py::test_every_investigation_route_maps_to_a_vex_permission__VEX_SEC_001`, `test_role_permissions_match_the_spec__VEX_SEC_001` | **Partial — see open items** |
| 19 | Current exports continue to work | `test_vex_dashboard_metrics.py::test_vex_report_still_produces_statement_rows`; e2e `test_report_and_csv_carry_native_and_effective_status__DoD_19`, `test_vex_pack_zip_still_builds__DoD_19` | **Met** |
| 20 | All mandatory acceptance scenarios pass automated tests | Section 1 — all 27 rows Pass | **Met** |

---

## 3. Open items

These are genuinely not met. None is silently omitted.

**O-1 — Closed.** Rows 1, 24 and 25 now pass; `tests/test_vex_acceptance_e2e.py` ran green with
22 tests on 2026-09-24.

**O-2 — DoD 18 is only partially demonstrated.** The tests assert that the route-to-permission
mapping and the role-to-permission table are correct. They do **not** drive a real request as a
VIEWER and observe a 403, because the suite runs with `API_AUTH_MODE=none`. The enforcement path
itself (`require_permission`) is covered by `tests/test_rbac_permissions.py` for other resources,
so the risk is low — but a VEX-specific authenticated negative test is missing.

**O-3 — Severity is not sortable in the investigation queue.** `sort_by=severity` returns 400.
Severity lives on `AnalysisFinding` and is resolved per row, so there is no column to order by.
Supporting it means denormalising severity onto `VexInvestigation` during reconciliation. Spec
section 28 asks for sorting generally without naming severity, so this is a judgement call left
open deliberately.

**O-4 — Vendor-hosted VEX discovery is untested in this workstream.** `POST /vex/discover`
predates the enhancement and still works, but no acceptance test drives discovery end to end.
Spec section 2 lists it as existing functionality; section 47 does not require a row for it.

**O-5 — The full backend suite has not completed green since PR-4.** PR-2's and PR-3's regressions
each surfaced real defects that later PRs fixed, but PR-4 onward have been verified only by their
own suites plus targeted re-runs. Every VEX suite passes individually — foundation 29, engine 33,
dashboard 13, API 27, audit 17, acceptance 22 — but a clean *whole-suite* run is still outstanding
and remains the real gate on this report. Item 20 above claims only that the section 47 matrix
passes, not that the wider suite is green.

---

## 4. Fixtures

`tests/fixtures/vex/`:

| File | Purpose |
|---|---|
| `sbom-with-embedded-vex.cdx.json` | CycloneDX 1.6 SBOM with a `false_positive` entry, an `in_triage` entry and a plain disclosure entry carrying no analysis block |
| `supplier-a-openvex.json` | OpenVEX `not_affected` |
| `supplier-a-openvex-v2.json` | Version 2 of the same document, asserting the opposite — supersedes, does not conflict |
| `supplier-b-openvex-conflicting.json` | A second, independent supplier disagreeing with Supplier A |
| `supplier-csaf.json` | CSAF VEX with `known_not_affected` and a PURL identification helper |
| `version-range-not-applicable.json` | A range that does not cover the SBOM's component version |
