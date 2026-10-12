# Version-aware SBOM lifecycle implementation report

Date: 2026-10-09, Asia/Kolkata.

## Baseline and scope

The active branch is `feat/native-user-management`. HEAD is exactly the supplied reference `6e7b22e1110ef1849150671b8d253efe0479e074`; the reference exists and there are no descendant commits to inspect. The checkout was **not clean**: it already contained extensive lifecycle/VEX work and unrelated dashboard styling. Those changes were preserved. No commit, push, deployment, application-database migration, or production migration was performed.

This report supersedes the selection-policy and migration conclusions in `lifecycle-completion-2026-10-09.md`. That pre-existing document describes an earlier manual-only implementation and earlier test runs; its results are not the validation results of this session.

## Gaps and feature-to-requirement mapping

The specification does not assign separate story IDs to its new phases. The table maps them to phase/section numbers, audit IDs, and the existing requirement IDs in `docs/requirements/vex-dashboard-investigation.md`; no story IDs are invented.

| Requirement / story ID | Finding at start | Final implementation |
|---|---|---|
| Phases 1–2; B5, B6; VEX-DASH-004/005 | Uncommitted shared projection already fixed inactive descendants and designated current selection | Preserved and extended `metrics/posture.py` and `sbom_posture.py`; target, designation, effective current, source run, fallback and invalid selection are distinct. |
| Rule B, Phase 1 | No persisted distinction between automatic selection and administrator intent; first upload selected automatically | Migration 077 persists AUTO/MANUAL_PIN; all legacy non-null pointers become MANUAL_PIN. Ordinary uploads do not designate, including the first upload. Explicit authorized upload selection creates a pin. |
| Rule B, Phase 3 | Successful analysis did not promote AUTO versions | Transaction-bound promotion validates tenant/project/product/lineage, active ownership and the latest eligible successful snapshot. Product locking serializes concurrent changes. Branch ambiguity and independent lineages require explicit selection. Audit includes run and coverage provenance. |
| Rules C–E, Phase 2; VEX-INV-002, VEX-REC-004 | Pending/failed fallback already existed in uncommitted code | Preserved fallback, added completion time, selection mode, invalid-selection/no-posture responses and active-source eligibility; obsolete analyzer-only contexts are excluded from current list/metrics and are read-only history. |
| Phase 3; VEX-CTX-001, VEX-INV-004, VEX-DATA-003/004 | Reconciliation, manual precedence, independent version contexts, assignment retention on reruns and internal defaults were implemented at the reference | Retained existing categories and authored-assertion distinction. No automatic decision/assignment carry-forward or FIXED assertions. |
| Phase 4; M2; VEX-UI-001/002/003, VEX-INV-002 | Uncommitted current/all/historical version browsing existed; exact prior run state was not captured | Preserved version browsing. Added tenant/SBOM-bound run discovery, paginated immutable run snapshots and a frontend historical-run picker. Missing legacy snapshots are explicitly unavailable rather than reconstructed. |
| Phase 5; M1; VEX-CTX-001/002 | Uncommitted Compare v2 adapter/UI existed | Preserved canonical/alias + package/component/version comparison, coverage limitations, counts, conservative disappearance explanations and current/historical navigation. Names alone no longer establish cross-version identity. |
| Phase 6; M3; VEX-INV-004, VEX-AUD-001 | Uncommitted prior-decision panel omitted impact/action/evidence display | Added prior assertion impact, action and supporting evidence display, vulnerability/alias/PURL and audit references. Both imported and manual assertions are shown; matching is vulnerability-context bound and deduplicated by statement, preventing cross-context duplicate evidence. No copying/reaffirm mutation was added; the normal audited decision workflow remains available. |
| Phase 7; VEX-DASH-002/004 | Shared list/summary predicates and additive provenance were present in uncommitted work | Preserved shared scope and pagination-independent summary. Added nullable no-posture UI, persisted mode control and explicit invalid-selection warnings. |
| Phase 8; VEX-SEC-001/002, VEX-AUD-002 | Assignment-based authorization and historical-read-only guards existed | Preserved Admin/Analyst/Developer/Viewer/Platform restrictions; strengthened pin authority with product:update, locked designation updates and guarded obsolete contexts. |
| Phase 9; P1 (audit performance item) | Uncommitted page enrichment already batched statements, recorded-run findings and owners | Retained page batching; obsolete-context classification adds one page query, independent of page size. Run snapshot pages use a single joined query plus count/run validation. |
| Sections 13–15 | Earlier tests existed, but AUTO/pinning/run snapshots were not covered | Added `test_sbom_selection_policy.py`, migration backfill/rollback, concurrency, branches, independent lineage, obsolete/no-posture and snapshot regressions; added historical-run and policy-control UI tests. |

## Shared lifecycle policy

`app/metrics/posture.py` supplies the SQL projection used by DashboardScope and latest-state metric helpers, so Dashboard, VEX, KEV and Component Advisor share the selected posture. Run-specific Analysis displays retain their explicit run semantics. Lifetime/cumulative metrics retain their existing definitions.

- **Latest Uploaded** describes inventory chronology, including inactive retained history; it is not a successful analysis.
- **Designated Current** is the stored product pointer, with persisted selection mode. Invalid pointers are reported, not interpreted as a different administrator choice.
- **Effective Current** follows valid designation and eligible lineage fallback; pending AUTO candidates do not acquire the predecessor's findings.
- **Latest Analyzed** is eligible successful evidence within the relevant lineage.
- **Posture Source** is the actual SBOM plus latest active non-obsolete OK/FINDINGS/PARTIAL run supplying metrics.
- **Last Known Posture** is explicitly labeled during pending/failed replacement attempts. No eligible analysis produces unknown/no-posture state, not a zero-risk claim.

AUTO never promotes on upload. A successful analysis can designate an initial single-lineage product or replace its designated ancestor with a valid descendant. A sibling, unrelated lineage, stale/obsolete run, inactive artifact, or inactive/deleted owner cannot promote. Multiple active branches are an explicit administrator choice. Products with multiple independent lineages and no designation retain their independently scoped posture rather than collapsing to the first successful scan.

MANUAL_PIN remains unchanged across new uploads and analysis. Product PATCH or an explicit authorized upload/repair designation changes the selection and writes audit evidence. Returning to AUTO authorizes future eligible analysis promotions; it does not infer that a legacy pin was automatic. Version labels are never sorted semantically to infer designation.

An invalid pin remains persisted and visible. Current metrics can show eligible predecessor evidence, labeled as fallback, while requiring selection review. With no eligible source, metadata returns `NO_POSTURE` and nullable version/source fields. Deleted products do not contribute to current metrics.

Successful zero findings are authoritative. ERROR/PENDING/RUNNING/CANCELLED and obsolete runs are not replacement posture. Multiple runs are not summed. PARTIAL is successful but warns about incomplete provider coverage. Reduced coverage makes disappearance comparison unresolved rather than evidence of remediation.

## APIs and UI

Existing endpoints remain compatible with additive fields:

- `/api/products/{id}`: `current_sbom_mode`; setting a non-null pointer without mode establishes MANUAL_PIN.
- `/api/vex/investigations` and `/summary`: retained shared `version_scope=current|all|historical` and specific `sbom_id`; default Current Posture.
- `/api/vex/investigations/versions`: retained scoped version discovery.
- `/api/vex/investigations/comparison`: retained Compare v2 version workflow and coverage limitations.
- `/api/vex/investigations/analysis-runs?sbom_id=...`: tenant/SBOM-bound run discovery.
- `/api/vex/investigations/run-snapshot?sbom_id=...&analysis_run_id=...&limit=...&offset=...`: immutable reconciliation and assignment evidence captured at successful analysis completion; always read-only.
- Investigation detail: retained prior decisions, source statements and append-only audit history, now including more prior assertion evidence.
- `/dashboard/posture-versions`: additive selection/fallback/completion provenance, including explicit no-posture results.

Dashboard, Analysis, SBOM details, Product details and VEX retain shared posture notices. Product details adds AUTO/MANUAL_PIN policy selection; version selection creates a manual pin. Historical VEX selection adds the run picker, obsolete/legacy unavailable states and original analysis links. Query keys include tenant/version/run, preventing results from a previous selection appearing under a new selection.

## Migration and rollback

`077_sbom_selection_mode` follows `076_logical_sbom_versions`. It adds a constrained `products.current_sbom_mode` column and the `vex_investigation_snapshot` table with tenant, SBOM, run, context, captured payload and unique run/context identity. Both additions are necessary: a pointer cannot encode selection intent, and a mutable context's latest-run pointer cannot reproduce exact prior run decisions/assignments.

Backfill: every existing non-null current pointer becomes MANUAL_PIN, including ambiguous/invalid legacy selections; null pointers become AUTO. No relationships or old findings/assertions/audits are rewritten. Legacy historical snapshots are not fabricated.

The migration was exercised only on disposable test databases. Deploying code requires migrating the application database first, through the normal authorized release process. Rollback: stop new-code workers, preserve/export new snapshot evidence if needed, downgrade to `076_logical_sbom_versions`, and restore prior code. Downgrade retains current pointers but removes the mode and new snapshot table; it therefore loses new policy intent/snapshot evidence. Existing VEX assertions, findings and audit history remain intact. All four disposable databases created by this task were removed after validation; application databases and shared containers were left running.

## Validation

Final executed selections and results are recorded below. Interrupted/superseded runs and early failures are not reported as final passes. The system Node runtime failed to load a Homebrew shared library; frontend validation uses the Codex bundled Node executable.

| Executed selection | Result |
|---|---|
| Selection/migration/snapshot/posture/provider coverage/Product/Advisor/KEV | 125 passed (640.51s) |
| Broad VEX/RBAC/reconciliation/Compare/lineage/metrics/dashboard/acceptance | 247 passed, 8 subtests passed; 2 failed and 1 teardown error (1228.75s), all reproduced on reference |
| Final AUTO/pin/concurrency/immutable snapshot/obsolete history + 81→15 + query count + production persistence | 21 passed (68.13s), after correcting the SQL NULL historical predicate |
| Final B5/B6/M1/M2/M3 and duplicate-prior-evidence lifecycle selection | 26 passed (47.87s) |
| Final shared-scope and imported prior-assertion/no-inheritance checks | 11 passed (18.41s) |
| Full synthetic AUTO 81-to-15 acceptance, with HTTP decisions and Developer delegation | 1 passed (4.95s); pending/failed preservation, 12/3/69 comparison, retained 81 history, read-only old assignment, independent new contexts and inactive fallback |
| Full frontend, with Redis startup permitted | 1,438 passed across 175 files (238.91s), no skips |
| Earlier affected frontend | 80 passed across 5 files |
| Final affected frontend after prior-source/effective-current/cache refresh changes | 76 passed across 4 files (14.03s) |
| Redis integration isolated rerun | 8 passed (2.43s) |
| TypeScript | Passed using bundled Node |
| Final Webpack production build | Passed; includes final prior-source/effective-current/cache changes |
| Full frontend lint | 0 errors, 53 warnings; exact normalized warnings match clean reference |
| Final affected frontend lint | 0 errors, 2 pre-existing API-client warnings |
| Changed/new production Python + selection/migration tests | Ruff passed; Python compilation passed |
| Whitespace and migration graph | diff check passed; sole Alembic head 077_sbom_selection_mode |

Selections overlap; pass counts must not be summed. A first full frontend run in the sandbox passed 1,430 tests but skipped eight Redis tests after local Redis startup/teardown hook timeouts. Those tests passed outside the sandbox, and the complete suite was rerun with Redis startup permitted, yielding all 1,438 passes. Initial checks also caught an invalid background audit user reference, a test-held transaction lock, JSX operator precedence, the SQL NULL historical predicate, and a test assertion that incorrectly treated the internal default as an authored decision; these were corrected and superseded by the passing final selections. A test-selection command referencing a nonexistent file collected no tests and was rerun with valid filenames. Superseded resource-heavy runs were stopped and are not counted as successes.

The assigned-owner query regression measured **31 SELECT/WITH queries for 1 row and 31 for 50 rows** on the final implementation. This includes authorization, shared scope and provenance queries; it is a query-growth regression result, not a production latency claim.

The clean reference was archived from the exact supplied SHA into `/tmp/sbom-lifecycle-reference-6e7b22e` and tested against a separate owned disposable PostgreSQL database. The known failures reproduced: ten dashboard fixture errors omitting `logical_sbom_id`; audit-concurrency fixture failure plus teardown error with the same missing required field; the existing metric direct-query invariant in `sbom_lifecycle.py`; and the existing validation-blocked SBOM-editing test. That baseline selection ended with **3 failed and 11 errors**, in 391.36 seconds. These are not new failures and were not modified to manufacture a green suite.

## Changed files

New files in this session: migration 077, `app/services/sbom_selection.py`, `app/services/vex/run_history.py`, `tests/test_sbom_selection_policy.py`, `frontend/src/components/vex/VexRunHistoryPanel.tsx` and its tests, and this report.

Extended existing or pre-existing uncommitted work: `app/models.py`, `app/schemas.py`, `app/metrics/{_helpers,vex,posture}.py`, `app/services/{analysis_service,audit_service,sbom_posture}.py`, `app/services/sbom/repair/service.py`, `app/services/vex/version_evidence.py`, `app/routers/{products,sbom_upload,sboms_crud,vex_investigations}.py`, Product detail page/tests, VEX page, prior-decision panel, shared posture notice, frontend API/types, and product hierarchy tests. Unrelated dashboard design changes were preserved.

## Limits

No automatic reuse of old VEX decisions, inherited assignment or historical mutation API. Historic runs predating snapshot capture remain accessible through original findings and the version audit timeline, but exact prior assignment/decision snapshots are explicitly unavailable. Cross-version matching without reliable package identity is unresolved. Automatic selection between independent lineages or active branches requires explicit designation. Browser-driven E2E and production deployment validation are not claimed.
