# Linear remediation result drafts — no status changes sent

## SBO-70 — FIXED_AND_RETETESTED

Preserved the existing nullable-text VEX evidence contract by formatting stored numeric confidence at `_detail_payload`. Real Greenfield requests changed from detail/decision/stale 500 to 200/200/409. Read-only persistence proof: one manual statement, one component audit, one context audit; stale request adds none. Viewer/non-owner Developer remain 403, foreign remains 404, validation remains 422. Actual Admin and assigned-Developer browser saves and fresh persisted readback passed; assignment removed afterward.

Files: app/routers/vex_investigations.py; tests/test_vex_confidence_serialization.py; tests/test_vex_investigations_api.py; VEX plan and UAT evidence/report.

## SBO-71 — FIXED_AND_RETETESTED

Replaced the positive-integer URL parser with existing publicId UUIDv4 validation. Real Project → Application → SBOM selection, refresh, deep links, drilldowns, resets and UI/backend metric agreement passed. Invalid IDs and orphaned scopes remain rejected; foreign scoped metrics/options return 404. Tenant cache-isolation integration remains passing.

Files: frontend/src/lib/dashboardScopeUrl.ts; frontend/src/lib/dashboardScopeUrl.test.ts; frontend/src/app/__tests__/dashboard-drilldown.integration.test.tsx; UAT evidence/report.

## Verification shared by both issues

24 focused backend tests; 111 + 25 frontend tests; TypeScript; webpack build (47 static pages); changed-file Ruff/ESLint — passed. Broader VEX run: 55 passed / 13 failed; all 13 failed identically on pre-remediation source due to existing integer-ID fixture migration gaps. Exact commands, logs and before/after HTTP/browser evidence are in RESULTS.md in this directory.

Exact passing suites:

- Backend: `PYTHONPATH=. .venv/bin/python docs/uat/remediation/2026-10-20-round1/run-regressions.py tests/test_vex_confidence_serialization.py tests/test_vex_scoped_authorization.py tests/test_dashboard_scope.py`.
- Frontend (from frontend, using bundled Node): `node_modules/vitest/vitest.mjs run src/lib/dashboardScopeUrl.test.ts src/components/dashboard/DashboardFilters.test.tsx src/app/vex-investigation/page.test.tsx src/components/vex/vexDecisionValidation.test.ts src/lib/dashboard-vex-invalidation.test.ts --maxWorkers=1`.
- Integration (same runtime/directory): `node_modules/vitest/vitest.mjs run src/app/__tests__/dashboard-drilldown.integration.test.tsx src/components/vex/data-sync.integration.test.tsx src/components/vex/AssigneeCombobox.test.tsx --maxWorkers=1`.
- TypeScript: bundled Node `node_modules/typescript/bin/tsc --noEmit`. Build: `PYTHONPATH=. .venv/bin/python -m scripts.greenfield_uuid build`.

485-case baseline and unrelated dirty work preserved. Remaining five findings/other coverage are unchanged. Full UAT sign-off WITHHELD. No commit/push/merge/deployment; no Linear issue marked Done.
