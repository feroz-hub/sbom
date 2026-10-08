# VEX Investigation — Version & Run Lifecycle Audit

**Date:** 2026-10-08 · **Spec:** [`vex-dashboard-investigation.md`](../requirements/vex-dashboard-investigation.md)
**Reproduction tests:** [`tests/test_vex_version_lifecycle.py`](../../tests/test_vex_version_lifecycle.py)

Each "Confirmed" item below was reproduced by an automated test that failed on the code as it
stood, before any change. Items found by reading code but not reproduced are marked
**Static finding**. The reported Northstar figures (108 / 108 / 108, and 12 matching) could not be
replayed: no local database holds that tenant. They are explained by B1 and B4 below. That
explanation is an inference, not a measurement.

---

## 1. Current architecture (as found)

| Concept | Representation | Notes |
|---|---|---|
| Tenant / Project / Application | `tenants`, `projects`, `products` | `Product.current_sbom_id` = designated current SBOM |
| SBOM version | One `sbom_source` row per version, linked by `parent_id` and grouped by `logical_sbom_id` | `sbom_version` is a label typed in at upload; `productver` = product version. No CycloneDX document-version column. |
| "Current" SBOM for dashboards | **HEAD** = active SBOM with no child (`DashboardScope.eligible_sbom_ids`) | `Product.current_sbom_id` is **not** consulted (see B6) |
| Analysis run | `analysis_run`; successful = OK / FINDINGS / PARTIAL; `is_current=false` = obsolete | |
| Finding | `analysis_finding`, per run (immutable) | |
| Component | `sbom_component`, per SBOM version (never shared) | |
| VEX context | `vex_investigation`, unique on tenant + SBOM + component + canonical vulnerability ID (+ discriminator for unresolved mappings) | Per SBOM version. `is_current` = present in **that SBOM's** latest successful run. |
| VEX assertion | `vex_statements` (per SBOM); manual decisions are statements with `source_name = "Manual VEX Override"` | Imported VEX is bound to one SBOM, so it cannot leak onto another version |
| Assignment / audit | `vex_investigation.assigned_to`; `vex_override_audit` (append-only) | |

**Metric computation.**
- **Tiles:** `GET /dashboard/vex` → `vex_dashboard_summary` → `vex_context_counts`. Current contexts in the eligible-SBOM scope; only the project / application / SBOM query parameters are honoured.
- **Queue:** `GET /api/vex/investigations`. Applied tenant + `is_current` plus its own filters, but **not** the eligible scope (B1).
- **Frontend:** requested the tiles with the tenant only (cache key `['dashboard-vex', tenant]`), so the tiles never followed any filter (B4).

**Run handling.**
- Reconciliation uses one run per SBOM, the latest successful one. Runs are never summed: verified, 81 + 75 + 80 does **not** happen.
- A failed run triggers no recompute, so the current posture survives it (verified).
- Re-running reconciliation on unchanged data is a no-op (existing test, still passing).

---

## 2. Gap report

### 2.1 Confirmed bugs — fixed in this change

| # | Feature | Current (before) | Expected | Severity | Fix | Files | Test |
|---|---|---|---|---|---|---|---|
| B1 | Queue scope | Queue counted every `is_current` context in the tenant. That included **superseded versions** (A1.0.0's contexts stayed beside A1.1.0's) and **inactive SBOMs**. Tiles excluded both, so card ≠ table. | Queue uses the eligible-SBOM scope, the same as the tiles (VEX-DASH-004/005, VEX-INV-002, CLAUDE.md invariant) | **P0** | `_queue_conditions` adds `sbom_id IN DashboardScope.eligible_sbom_ids()`. Project / application / SBOM filters narrow that set and cannot widen it. | `app/routers/vex_investigations.py` | `test_new_version_does_not_merge_previous_version_into_current_queue__VEX_INV_002` (was 5 vs 2), `test_inactive_sbom_is_excluded_from_queue__VEX_DASH_005`, `test_tiles_equal_queue_total_for_project_and_application_filters__VEX_DASH_004` |
| B2 | Current-run selection | `latest_successful_run_id_for_sbom` ignored `AnalysisRun.is_current`. A VEX import or decision recompute could rebuild the queue from an **obsolete** run. | Same run rule as `latest_run_per_sbom_subquery` | **P0** | Added `is_current IS TRUE`. The helper's HEAD-only rule is deliberately *not* applied, so recomputing a historical version cannot retire its history. | `app/metrics/vex.py` | `test_obsolete_run_never_becomes_current_posture__VEX_INV_002` |
| B3 | Severity under aliases | A context keyed on a CVE but reported as a GHSA showed severity `None`, and the severity filter put it in UNKNOWN. | Match the finding by canonical ID **or** alias (VEX-CTX-002) | P1 | Alias-aware match in both `vex_severity_filter_clause` and `_severity_for` | `app/metrics/vex.py`, `app/routers/vex_investigations.py` | `test_ghsa_reported_finding_keeps_its_severity__VEX_CTX_002` |
| B4 | Filtered metrics | Cards were tenant-wide only, labelled "independent of queue filters". | A "Current view" that uses the same filters as the table, plus a separately labelled tenant overview | P1 | New `GET /api/vex/investigations/summary`, using the **same** `_queue_conditions` predicate and aggregated in SQL (`vex_context_counts_where`). UI: "Current view" cards plus a collapsible "Tenant overview". | router, `app/schemas_vex.py`, `app/metrics/vex.py`, `frontend/src/app/vex-investigation/page.tsx`, `frontend/src/lib/api.ts`, `frontend/src/types/index.ts` | `test_filtered_metrics_equal_matching_count__VEX_DASH_004` (7 filter sets), `test_pagination_never_changes_metric_totals__VEX_DASH_004`, `test_filtered_status_buckets_reconcile__VEX_DASH_002`, `test_summary_is_tenant_scoped__VEX_SEC_002`, plus 3 page tests |

### 2.2 Confirmed or suspected problems — **not** fixed (need a decision or are out of scope)

| # | Finding | Status | Severity | Why not fixed | Recommended fix |
|---|---|---|---|---|---|
| B5 | The HEAD rule ignores whether the *child* is active: a deactivated or soft-deleted A1.1.0 still hides A1.0.0, so the application drops out of every dashboard. (`dashboard_scope.py:66-73`, `metrics/_helpers.py:19-30`) | Static finding | P1 | Changes SBOM active/inactive behaviour, which is out of scope for the VEX workstream, and alters every dashboard | Restrict the child check to active, `lifecycle_status='ACTIVE'` children, in both helpers, with a scope test |
| B6 | Designated current (`Product.current_sbom_id`) is ignored by every dashboard; "current" means HEAD of the lineage. Special case 28 therefore shows the newest upload even when another version is designated. | Static finding | P1 | Product decision: which definition of "current" governs posture? | Choose one definition; if it's the designated current, extend `DashboardScope` and not VEX alone |
| B7 | Pre-existing red tests on `feat/native-user-management`, failing before this change: `test_no_new_direct_finding_or_run_queries_outside_metrics` (`app/services/sbom_lifecycle.py` queries `AnalysisRun`); 11 errors plus 1 failure in `test_dashboard_scope.py` / `test_vex_audit_concurrency.py` from fixtures inserting `sbom_source` without `logical_sbom_id`; `test_component_advisor_recommendations_api.py::test_T17_…` (`can_decide` is True; confirmed to fail with this change stashed); frontend `shared-session-store.test.ts` hook timeout | Confirmed | P1 (CI hygiene) | Unrelated to VEX lifecycle; touching them would bloat this change | Separate task |
| P1 | Queue page cost: `_row_payload` runs, per row, `_statements_for` (every statement on the component), `_severity_for` (every finding for the component **across all runs**) and `owner()`. 50 rows → ~150 queries, and the finding scan grows with run history. | Static finding | P2 | Performance, not correctness | Batch statements and severities per page, keyed on `last_analysis_run_id` |

### 2.3 Missing functionality (requested; needs agreement before building)

| # | Feature | Current | Gap | Proposal |
|---|---|---|---|---|
| M1 | Version comparison (NEW / STILL DETECTED / NO LONGER OBSERVED) | Compare v2 (`POST /api/v1/compare`, ADR-0008) diffs two runs. Finding identity = canonical vulnerability ID + component name + version. Categories: added / resolved / severity_changed / unchanged. Component diff: removed / version_bumped. | Not exposed on the VEX page; no "previous successfully analysed version" resolver; no reason labels | **Reuse Compare v2** between the latest successful runs of the selected version and its parent. Map added → NEW, unchanged + severity_changed → STILL DETECTED, resolved → NO LONGER OBSERVED. Derive reasons only from the component diff (component removed / component version changed); anything else is "Unknown". Never mark FIXED. |
| M2 | Version scope (current / all / specific / historical) | After B1 the queue shows current versions only; historical contexts are kept but have no read path | No historical view | Add an optional `version_scope=current\|all` and allow an explicit historical `sbom_id` when `version_scope=all`. Default stays `current`. Additive API change. |
| M3 | Prior-decision applicability | A new version starts with no decisions. That is safe, since nothing is inherited (verified), but nobody is told that A1.0.0 had a NOT_AFFECTED for the same component and CVE. | No "previous decision" evidence | Show prior decisions for the same component name + version + CVE in the parent version as **read-only evidence** in the detail panel. Applying one is an explicit, audited analyst action. No new statuses. |
| M4 | Deployed versions | Not modelled anywhere | Multiple simultaneously deployed releases can't be represented | Product decision; out of scope for VEX |

### 2.4 Intentional current behaviour (verified, kept)

- **New finding = UNDER_INVESTIGATION + ANALYZER_ONLY.** This is the workflow default (VEX-REC-002 A), not an authored VEX statement. No `VexStatement` is created, `effective_vex_statement_id` stays NULL, and `ANALYZER_ONLY` itself says that no assertion exists. The two concepts are already separate (section 9 → "A").
- **Contexts are per SBOM version.** A1.0.0 keeps all of its contexts and decisions, and A1.1.0 gets its own. Nothing is auto-declared FIXED when it disappears; it becomes `is_current=false` history.
- **Decisions and assignments are not carried across versions.** Verified by `test_previous_not_affected_is_not_auto_applied_to_new_version__VEX_CTX_001` and `test_assignment_is_not_carried_onto_new_version__VEX_AUD_001`. A developer gains no write access on the new version's contexts.
- **PARTIAL counts as a successful run** (ADR-0001).
- **Imported VEX is SBOM-scoped.** A document for A1.0.0 never applies to A1.1.0.

---

## 3. API changes

- **New:** `GET /api/vex/investigations/summary`. Accepts exactly the list endpoint's filters and returns `{scope:"filtered", total, mapped_total, affected_count, not_affected_count, fixed_count, under_investigation_count, needs_review_count, unresolved_mapping_count, matched_count, analyzer_only_count, vex_only_count, conflict_review_count, revalidation_required_count}`. `total` equals the list `total` for the same filters.
- **Changed behaviour, unchanged shape:** `GET /api/vex/investigations` now applies the eligible-SBOM scope. An `sbom_id` for a superseded or inactive version returns 0 rows (the UI's scope picker only offers eligible SBOMs).
- **Unchanged:** `GET /dashboard/vex` (tenant overview); every existing response field.
- **No database migration.**

## 4. Acceptance status (section 19 of the request)

| Criterion | Status |
|---|---|
| Current-version view = 15 contexts, not 81 + 15 | ✅ structurally (B1). Verified with a 3 → 2 lineage fixture. |
| Historical A1.0.0 = 81 retained | ✅ retained in the database (test). ❌ no UI/API read path yet (M2). |
| Version comparison counts | ❌ not built (M1) |
| Previous decisions retained / new-version applicability evaluated | ✅ retained and not auto-applied. ❌ applicability not surfaced (M3). |
| Filtered metrics exactly match filters | ✅ (B4) |
| Tenant overview distinguished | ✅ |
| VEX-only reconciled independently | ✅ unchanged existing rules and tests |
