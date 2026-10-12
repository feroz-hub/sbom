# SBOM version lifecycle and VEX completion

> Earlier implementation record. The AUTO/MANUAL_PIN policy, migration and final validation are superseded by [lifecycle-implementation-2026-10-09.md](lifecycle-implementation-2026-10-09.md).

Date: 2026-10-09 (Asia/Kolkata). Baseline: `6e7b22e1110ef1849150671b8d253efe0479e074`.
The checkout was clean at the exact baseline; no later work was overwritten.

## Confirmed gap checklist

| Gap | Root cause | Implementation |
|---|---|---|
| B5 | HEAD exclusion counted inactive/deleted descendants | Shared tenant/application-bound lineage resolver excludes ineligible descendants and handles an active grandchild through an inactive intermediate version. |
| B6 | Dashboard HEAD ignored `Product.current_sbom_id` | Valid designation takes precedence; all dashboard metrics and VEX use one posture SQL projection. |
| Pending upload | Upload tips replaced analyzed ancestors before any successful scan | Resolve target and posture separately; pending/failed/obsolete uploads retain eligible analyzed ancestor evidence and show provenance/warnings. |
| M1 | Compare v2 was not exposed in VEX and lacked a conservative version adapter | Reuse Compare v2 set-diff logic with stored vulnerability aliases and package/component/version identity, explicit uncertainty and source coverage limitations. |
| M2 | Historical investigations were retained but unreachable in the queue | Add current/all/historical scope, tenant/application-validated explicit SBOM selection, historical version picker and read-only evidence. |
| M3 | Prior assertions were preserved but not surfaced for applicability review | Read-only previous decision panel with source statement, reviewer, date, component version and analysis provenance. No copy/reuse mutation. |
| Query cost | Statements, run-history findings and owners fetched per row | Page-scoped batch statements, recorded-run findings, memberships/users and role assignments. |

## Current version and posture policy

1. **Latest uploaded** is inventory chronology within a declared logical lineage, not a security result.
2. **Latest analyzed** is the newest eligible version with an active, non-obsolete OK/FINDINGS/PARTIAL run.
3. **Current SBOM** honors a valid `Product.current_sbom_id` in the tenant/project/application. Existing application selection, upload `set_as_current`, repair approval and scheduler semantics remain intact.
4. **Security posture** uses that target's latest successful non-obsolete run. If none exists, use its eligible analyzed ancestor. No cross-tenant/project/application fallback. If a designated target has no analyzed ancestor, retain the latest eligible analyzed evidence in that application and explicitly label it as another lineage; no lineage or vulnerability continuity is inferred.
5. Without a valid designation, active lineage tips are targets. Ineligible descendants cannot suppress an eligible ancestor. Multiple active branches remain explicit and warn that designation is needed; a common fallback ancestor is counted once.
6. The upload UI now matches the existing backend opt-in default: merely uploading does not select Current SBOM; the first upload remains automatically designated by the existing backend when no designation exists. A valid existing designation is not automatically overwritten after analysis. The established product contract uses manual Current SBOM selection (including an authorized upload selection). No new auto-promotion or inferred administrator-pin flag is introduced. A newer analyzed version makes the required selection action visible.
7. An inactive/deleted/foreign designation is ignored for posture eligibility, without inferring a new administrator selection or mutating the stored pointer. Select Current SBOM explicitly to designate a replacement.
8. Successful zero findings are authoritative. Failed/canceled/incomplete/obsolete attempts cannot replace an eligible successful posture. PARTIAL remains successful and surfaces reduced-coverage warnings.
9. Historical versions and run evidence remain available. Unlinked designated uploads cannot silently erase the last application posture; comparison/prior-decision matching still requires a suitable declared lineage. Simultaneously deployed releases are not modeled or inferred.

Selection is centralized in `app/metrics/posture.py`, used by DashboardScope and the legacy latest-state metric helper. Dashboard, vulnerability, KEV and Component Advisor consumers of that scope inherit the same policy. Run-specific analysis remains run-specific. Scheduler targeting continues to use the designation, not a fallback evidence artifact.

## Last-known-posture UX

Shared provenance distinguishes Current SBOM, Latest uploaded, Latest analyzed and Security/Last known posture, with the actual analysis run. A pending replacement displays:

> The newer SBOM has not completed analysis. Showing the last known security posture from A1.0.0.

Failed attempts and incomplete coverage have warnings. No successful evidence displays an explicit unknown/pending warning rather than declaring zero risk. Finding records and VEX context counts are separately labeled because applicable VEX-only statements can increase queue totals.

Notices are shared across dashboard filters, Component Advisor, VEX, Analysis Runs, Application details and SBOM details. Upload, designation and analysis-completion invalidation refreshes evidence; notices also poll every 15 seconds. Filter/version changes do not retain counts from a different scope.

## APIs and historical authorization

- Existing `GET /api/vex/investigations` and `/summary`: additive `version_scope=current|all|historical`. Default current. `sbom_id` supports tenant/application-validated history selection.
- List adds posture provenance, scope, version labels, recorded analysis-run IDs and historical flags; summary keeps exactly the shared filtering predicate.
- `GET /api/vex/investigations/versions`: scoped version discovery, including retained inactive/history records.
- `GET /api/vex/investigations/comparison?sbom_id=...&previous_sbom_id=...`: latest successful runs of the selected version and a declared analyzed ancestor. Both analyses required; cross-tenant/unrelated baselines rejected.
- Detail adds `previous_decisions`, version and historical metadata.
- `GET /dashboard/posture-versions`: shared provenance for scoped UI surfaces.

Historical evidence is read-only for all ordinary investigation actions; no special historical correction workflow existed to preserve. Decision, assignment, mapping and legacy component override routes enforce this server-side. Developers retain assigned-only current mutation; old assignments never grant new authority. Admin/Analyst delegation, Viewer read-only and Platform Admin tenant-scope rules remain unchanged.

## Comparison and previous decisions

NEW / STILL_DETECTED / NO_LONGER_OBSERVED / UNRESOLVED_COMPARISON are observation categories, not VEX assertions. Compare v2 owns set diffing; the VEX adapter adds stored alias resolution, PURL/CPE/package identity and component-version matching. Missing or ambiguous component identities stay unresolved. Same CVE in different components is never collapsed. Version changes are not silently treated as persistent identities.

Coverage differences, PARTIAL or source failures make absent findings unresolved. Missing coverage provenance produces a limitation warning. Identical failed-source summaries are still incomplete evidence, even if a producer omitted its error counter. No disappearance is labeled FIXED. Verified component-version changes/removals can explain an absence; otherwise the reason is not determined. Original/current details use the existing CVE dialog with exact run/component context.

Prior manual decisions are restricted to declared ancestors and unambiguous package identities. Statement/reviewer/date/analysis/component/evidence provenance is retained, applicability is REVIEW_REQUIRED, and a new decision must use the existing authorized audited workflow. No automatic decision, assignment or imported-VEX inheritance is introduced.

## Performance

A real assigned-owner page regression measured **29 SELECT/WITH queries for 1 row and 29 for 50 rows**, including request authorization and posture provenance. Row count does not increase query count. Findings come only from recorded run IDs, not all historical runs. Comparison absence explanations use a shared component-identity index rather than scanning the current inventory for every disappeared context. Provenance reads omit uploaded SBOM payload columns and load only the latest attempt/latest successful run metadata.

These are local observations, not an SLA. Recursive lineage projections remain SQL-based and tenant/application-bound; broad portfolio caching/benchmarking is future work.

## Migration and rollback

No new table, field or migration. Sole head remains **076_logical_sbom_versions** at this baseline. Existing current-SBOM fields and append-only VEX evidence are sufficient because the established manual designation contract is retained. No data backfill or inferred user intent. Code rollback requires no database downgrade; additive response fields may be ignored by older clients.

## Verification

Suites overlap; do not sum their pass counts. All PostgreSQL runs used separately owned disposable test databases, never the local application or production database.

| Executed selection | Passed | Failed | Execution errors | Notes |
|---|---:|---:|---:|---|
| Broad VEX/dashboard/lineage/Compare/metric suite | 261 | 2 | 11 | All failures/errors reproduced on clean baseline; 8 passing subtests separately |
| Final lifecycle + RBAC + decision safety selection | 46 | 0 | 0 | Includes 25 lifecycle cases and 8 passing subtests |
| Final lifecycle + Compare v2 selection | 53 | 0 | 0 | Includes all 26 new lifecycle cases, including identical failed-source coverage |
| Final posture/product/advisor/KEV selection | 91 | 0 | 0 | After designated unlinked-upload fallback |
| Earlier cross-dashboard/lifecycle/KEV selection | 46 | 1 | 0 | Existing editing/version validation failure reproduced on clean baseline |
| Critical integration acceptance selection | 118 | 0 | 0 | VEX API, role matrix, product hierarchy and acceptance flow |
| Full frontend | 1,409 | 0 | 0 | 173 files |
| Final affected frontend | 115 | 0 | 0 | 8 files; after the picker type fix |

No skips were reported in these selections. No backend collection errors occurred in the final reported selections. Superseded development runs caught and corrected a recursive-subquery correlation issue, a common-picker type inference error, and a missing comparison index import. These failed attempts are not counted as final passes. Initial isolated harness/selector errors were corrected before baseline verification.

- Application TypeScript: passed after explicit common option typing fixed the current/history picker query inference. An initial post-change typecheck caught the issue; its failed result is superseded, not claimed green.
- Production Webpack build: passed after the common picker option type fix. Frontend lint: passed with the baseline warnings below. The runtime-neutral type annotation also passed a separate final TypeScript and affected-test rerun.
- Frontend lint: 0 errors, 53 warnings identical to clean baseline (including normalized paths/line shifts).
- Changed production Python and new lifecycle test lint: passed. Across all 16 changed Python files, three existing import/unused-import violations remain in two pre-existing test files, reproduced unchanged against baseline. No new Python violations.
- Python syntax/import compilation: passed. HTTP integration runs import the complete application.
- Working-tree whitespace check: `git diff --check` passed. No commits were made.

### Baseline-confirmed failures

Clean source was archived from exact `6e7b22e1110ef1849150671b8d253efe0479e074` and executed with separate isolated PostgreSQL:

1. `tests/test_metric_consistency.py::test_no_new_direct_finding_or_run_queries_outside_metrics`: existing `app/services/sbom_lifecycle.py` AnalysisRun query. Not a new query-layer violation.
2. `tests/test_vex_audit_concurrency.py::test_reconciliation_never_crosses_tenants__VEX_SEC_002`: fixture inserts without required `logical_sbom_id`; fails and also errors during teardown.
3. `tests/test_sbom_lifecycle_remediation.py::test_sbom_editing_and_versioning`: existing unresolved-validation processing rejection (SBOM_VALIDATION_BLOCKED), reproduced clean.
4. Ten `tests/test_dashboard_scope.py` setup errors: raw fixtures omit `logical_sbom_id`, reproduced clean.

The directed baseline selections returned 1 failed/10 errors (dashboard + invariant), and 2 failed/1 error (editing + audit concurrency). Existing failures were not modified. The full repository is not claimed green.

### Intentional contract-test updates

- The old HEAD-only acceptance expected a pending child to erase its parent's posture. It now explicitly verifies last-known-posture preservation, as required by this task.
- The list envelope test now validates preserved fields and the additive version/provenance fields rather than rejecting every new key.
- New upload UI coverage verifies false by default and explicit checkbox opt-in, matching the existing backend contract.

### Commands

Use a disposable PostgreSQL URL containing a test database name and keep its value private:

```sh
TEST_DATABASE_URL="$SBOM_DISPOSABLE_TEST_DATABASE_URL" .venv/bin/python -m pytest -q tests/test_vex_lifecycle_completion.py tests/test_vex_version_lifecycle.py tests/test_vex_scoped_authorization.py tests/test_vex_work_queue.py tests/test_vex_decisions.py tests/test_vex_reconciliation_engine.py tests/test_vex_investigations_api.py tests/test_vex_dashboard_metrics.py tests/test_compare_service.py tests/test_compare_router.py tests/test_sbom_upload_version_lineage.py tests/test_dashboard_scope.py tests/test_metric_consistency.py tests/test_vex_audit_concurrency.py tests/test_vex_acceptance_e2e.py
TEST_DATABASE_URL="$SBOM_DISPOSABLE_TEST_DATABASE_URL" .venv/bin/python -m pytest -q tests/test_product_hierarchy.py tests/test_sbom_lifecycle_remediation.py tests/test_component_advisor_analytics_api.py tests/test_kev_router.py tests/test_kev_postgresql.py
npm --prefix frontend test -- --run --maxWorkers=2 --testTimeout=15000
cd frontend
npx tsc --noEmit
npm run lint
npm run build -- --webpack
```

Browser E2E was not run in this task. The automated acceptance workflow runs against the real FastAPI application and PostgreSQL through HTTP; frontend workflows have Vitest coverage. No full repository backend run or deployment validation is claimed.

## Known limitations

- No automatic promotion when an existing designation is present; explicit Current SBOM selection remains the application contract.
- No deployed-release model, automatic assignment carry-forward or previous-decision reuse action.
- Historical correction is read-only; a separate authorized correction product workflow is not introduced.
- Missing analysis source provenance limits comparison confidence and is disclosed.
- Ambiguous mappings/package identities remain unresolved/manual.
- Compare UI uses a scrollable list; dashboard-wide version analytics are out of scope.
- Existing baseline fixture/invariant failures are documented rather than modified to manufacture a green suite.

## File inventory

### Modified

- `app/metrics/_helpers.py`
- `app/metrics/vex.py`
- `app/routers/dashboard_main.py`
- `app/routers/products.py`
- `app/routers/vex.py`
- `app/routers/vex_investigations.py`
- `app/schemas_vex.py`
- `app/services/compare_service.py`
- `app/services/dashboard_scope.py`
- `app/services/vex/authorization.py`
- `docs/metric-conventions.md`
- `docs/plans/vex-implementation-plan.md`
- `docs/vex/lifecycle-audit-2026-10-08.md`
- `frontend/src/app/analysis/page.tsx`
- `frontend/src/app/products/[id]/page.tsx`
- `frontend/src/app/vex-investigation/page.test.tsx`
- `frontend/src/app/vex-investigation/page.tsx`
- `frontend/src/components/dashboard/DashboardFilters.test.tsx`
- `frontend/src/components/dashboard/DashboardFilters.tsx`
- `frontend/src/components/sboms/SbomDetail.tsx`
- `frontend/src/components/sboms/SbomUploadModal.repair.test.tsx`
- `frontend/src/components/sboms/SbomUploadModal.tsx`
- `frontend/src/components/vex/VexInvestigationPanel.tsx`
- `frontend/src/lib/api.ts`
- `frontend/src/lib/queryInvalidation.ts`
- `frontend/src/types/index.ts`
- `tests/test_vex_acceptance_e2e.py`
- `tests/test_vex_investigations_api.py`

### Added

- `app/metrics/posture.py`
- `app/services/sbom_posture.py`
- `app/services/vex/version_evidence.py`
- `docs/vex/lifecycle-completion-2026-10-09.md`
- `frontend/src/components/sboms/SbomPostureNotice.test.tsx`
- `frontend/src/components/sboms/SbomPostureNotice.tsx`
- `frontend/src/components/vex/VexVersionComparisonPanel.test.tsx`
- `frontend/src/components/vex/VexVersionComparisonPanel.tsx`
- `tests/test_vex_lifecycle_completion.py`

## Operational boundaries

No commit, push, deployment, production migration, AI repair or external enrichment was performed. The implementation stays on the existing integration branch with reviewable uncommitted changes.
