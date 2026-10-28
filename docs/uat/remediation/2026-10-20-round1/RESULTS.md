# Remediation Round 1 — 20 October 2026

| Issue | Baseline defect | Result |
|---|---|---|
| SBO-70 | UAT-DEF-003 | **FIXED_AND_RETETESTED** |
| SBO-71 | UAT-DEF-006 | **FIXED_AND_RETETESTED** |

These results apply only to the two authorized High-severity defects. **Full UAT sign-off remains WITHHELD.** The original 485 cases retain their historical results (454 PASS, 12 FAIL, 11 BLOCKED, 8 NOT RUN); no original evidence was overwritten. Five other findings/acceptance gaps remain open: UAT-DEF-001, 002, 004, 005 and 007. Other blocked/unexecuted coverage remains as recorded in the baseline.

## SBO-70 — correction and before/after evidence

The existing detail DTO and TypeScript consumer require nullable text, while AnalysisFinding stores confidence as Float. The narrow correction formats non-null confidence as text in `_detail_payload`, including zero. No API schema, permissions, ownership, tenant isolation, evidence precedence or transaction semantics changed.

Fresh disposable Greenfield fixtures reproduced detail HTTP 500, one deliberate decision HTTP 500 with persistence, and stale-version HTTP 500 before correction. The failed mutation was not blindly retried. After correction: detail 200, decision 200 with the persisted row_version, and stale 409 with unchanged state. A read-only database query confirmed exactly one manual statement, one component audit and one investigation audit for the unique successful API decision reason; the stale request appended no audit. The history intentionally combines those two audit scopes.

Viewer and unassigned Developer mutations remain 403; foreign detail/mutation remain 404; missing NOT_AFFECTED justification remains 422. Assignment, assigned-Developer read/edit, unassignment and immediate loss of ownership all passed. Actual browser actions opened the dialog, saved an Admin decision, assigned its UAT investigation, and saved an AFFECTED decision as the assigned Developer. A fresh dialog readback showed that persisted status and its recorded reason. The editor intentionally leaves the *new* reason draft empty. The disposable assignment was removed.

Evidence: [before API](api-before.json), [after API](api-after.json), [all-role detail and Analyst decision/conflict](api-vex-roles.json), [read-only persistence](vex-persistence-readonly.json), [browser actions](browser-vex.json), [browser persisted readback](browser-vex-readback.json), [readback screenshot](vex-persisted-readback.png).

## SBO-71 — correction and before/after evidence

`parseDashboardScope` now calls the existing publicId UUIDv4 parser instead of coercing IDs with Number. It normalizes valid uppercase UUIDs and preserves the parent/child reset rules. The backend continues to validate ownership and hierarchy.

The browser reproduced a URL containing the disposable project UUID while the Project control reset to All projects. New regression tests failed against the old parser (5 failures) before correction. After correction, actual Project → Application → SBOM selection, refresh, direct deep links, drilldown URLs, parent clearing, invalid-ID handling, scoped requests and displayed counters passed. Every captured selected-scope posture matched a fresh backend-scoped posture in the final settled run. The three displayed counters matched backend values of one stored SBOM, one scanned project and one analyzed SBOM.

Independent API controls passed for Admin/Analyst/Developer/Viewer reads, invalid public IDs (422), orphaned hierarchy (400), mismatched parents (404) and foreign metric/option scopes (404). A separate clean foreign browser context could not render Olympus scoped metrics. Existing integration coverage also verifies that changing tenants does not display previous-tenant metric cache data.

Evidence: [before browser](browser-dashboard-before.json), [case-by-case browser acceptance with provenance](dashboard-acceptance.json), [settled Olympus browser attempt](browser-dashboard-after.json), [separate clean foreign browser](browser-dashboard-foreign.json), [API scope/security](api-dashboard.json), [after screenshot](dashboard-after.png), [red regression run](vitest-dashboard-red.log). The final foreign module check used a real Native BFF API login fixture because the unrelated sign-in form preparation was intermittent; it then performed actual tenant selection and browser navigation. It does not claim another successful sign-in-form UAT case. The earlier form-based foreign test also observed 404 in the live tool output, but the final saved acceptance comes from the explicitly identified fixture-based run.

## Exact checks and limits

Commands run from the repository unless a frontend working directory is stated. The wrapper targets only newly created `sbom_greenfield_uuid_remediation_r1_test_20261020`; it never truncates the live app database. The bundled Node runtime was used throughout.

| Check | Command | Actual result |
|---|---|---|
| Focused backend | `PYTHONPATH=. .venv/bin/python docs/uat/remediation/2026-10-20-round1/run-regressions.py tests/test_vex_confidence_serialization.py tests/test_vex_scoped_authorization.py tests/test_dashboard_scope.py` | **24 passed**, exit 0 |
| Broader VEX | same wrapper with `tests/test_vex_investigations_api.py tests/test_vex_confidence_serialization.py tests/test_vex_scoped_authorization.py tests/test_vex_audit_concurrency.py` | 55 passed, 13 failed; exit 1 |
| Pre-existing comparison | wrapper against the same 13 failed node IDs with pre-remediation router and fixture source temporarily restored, then candidate source restored in finally | **same 13 failures**, exit 1; numeric fixture IDs rejected at the existing UUID boundary |
| Frontend focused | in frontend: bundled Node `node_modules/vitest/vitest.mjs run src/lib/dashboardScopeUrl.test.ts src/components/dashboard/DashboardFilters.test.tsx src/app/vex-investigation/page.test.tsx src/components/vex/vexDecisionValidation.test.ts src/lib/dashboard-vex-invalidation.test.ts --maxWorkers=1` | **111 passed**, exit 0 |
| Frontend integration | same Vitest command with `src/app/__tests__/dashboard-drilldown.integration.test.tsx src/components/vex/data-sync.integration.test.tsx src/components/vex/AssigneeCombobox.test.tsx --maxWorkers=1` | **25 passed**, exit 0 |
| TypeScript | in frontend: bundled Node `node_modules/typescript/bin/tsc --noEmit` | pass, exit 0 |
| Build | `PYTHONPATH=. .venv/bin/python -m scripts.greenfield_uuid build` | optimized webpack build, TypeScript and 47 static pages passed, exit 0 |
| Backend lint | `.venv/bin/python -m ruff check app/routers/vex_investigations.py tests/test_vex_confidence_serialization.py tests/test_vex_investigations_api.py` | pass, exit 0 |
| Frontend lint | in frontend: bundled Node ESLint on the changed parser and two dashboard test files | pass, exit 0 |

The preliminary generic SQLite invocation produced 6 passes and 56 fixture setup errors because its role catalogue setup does not match this Greenfield checkout. It was replaced with the isolated PostgreSQL wrapper. An initial wrapper attempt rejected the new test database name through the existing helper allowlist; the dedicated test harness then constructed its own strictly fixed, loopback-only test URL. No application guard was changed. These are recorded setup failures, not accepted tests. No full-suite green claim is made.

Browser harness refinements included handling supported tenant selection, checking hydration with an empty password visibility control before entering credentials, scoping duplicate CVE rows to the disposable SBOM, matching required-field labels, and waiting for mutation invalidation before a subsequent assignment. An intentionally observed stale UI assignment returned 409 rather than mutating. Early comparison reads also observed high_epss_count change from 0 to 1; final dashboard comparisons ran after the VEX activity settled. Diagnostic attempts are retained separately; they were not used as passing acceptance evidence.

Logs: [focused Pytest](pytest-focused-final.log), [broader Pytest](pytest-vex.log), [pre-existing comparison](pytest-preexisting-baseline.log), [Vitest focused](vitest-after.log), [Vitest integration](vitest-integration.log), [TypeScript](typescript-final.log), [build](build.log), [Ruff](ruff.log), [ESLint](eslint.log).

## Changed files and scope preservation

- `app/routers/vex_investigations.py`: confidence normalization at the response boundary.
- `tests/test_vex_confidence_serialization.py`: six response, validation and no-duplicate regressions.
- `tests/test_vex_investigations_api.py`: numeric confidence in the shared fixture, also exercising the existing authorization matrix.
- `frontend/src/lib/dashboardScopeUrl.ts`: reuse the existing UUIDv4 parser.
- `frontend/src/lib/dashboardScopeUrl.test.ts`: real UUID roundtrip/normalization and invalid/orphaned ID regression cases.
- `frontend/src/app/__tests__/dashboard-drilldown.integration.test.tsx`: UUID hierarchy fixtures in real dashboard integration tests.
- `docs/plans/vex-implementation-plan.md`: scoped implementation/test record.
- This report and the separate Round 1 scripts/evidence.

[Remediation-only source/test diff](source.patch), [initial Git status](git-status-before.txt), [initial workspace hashes](workspace-before-sha256.json), [original report archive](before/docs/uat/SBOM_ANALYZER_FULL_UAT_REPORT.md), [original evidence hashes](uat-baseline-sha256.json), [final account/session safeguards](api-safeguards.json).

Only the verified isolated API was restarted to load its source change; no bootstrap or migration ran. Only the parser was copied into the existing private Greenfield frontend workspace. Build output used the separate Greenfield frontend-build workspace. Seeded credentials, roles, membership/account states and the original four-member Olympus directory passed final checks. Only the Round 1 investigation was assigned/edited/unassigned. Its UAT project/application/SBOM/analysis/audit data is retained for reproduction. Retained test BFF sessions were scoped-cleaned without altering accounts.

No commit, push, merge, production/historical database change or deployment occurred. Linear results are prepared in [LINEAR_RESULTS.md](LINEAR_RESULTS.md); no issue status was changed.
