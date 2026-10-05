# SBOM operational lifecycle

`lifecycle_status` (ACTIVE / INACTIVE) is independent of soft deletion (`is_active`), validation, and analysis freshness. Existing records default to ACTIVE. Apply Alembic revision `073_sbom_operational_lifecycle` with the normal deployment migration process before starting the updated application. Historical migrations are unchanged.

## API and authorization

- `POST /api/sboms/{id}/lifecycle`: body `{ "status": "INACTIVE", "reason": "Product retired" }` (or ACTIVE). Uses existing tenant context, `sbom:delete` permission and tenant/platform administrator role. Extra request fields are forbidden. Tenant ownership is checked explicitly under a row lock.
- `GET /api/sboms/{id}/lifecycle-history`: existing `sbom:read` permission and tenant ownership; returns lifecycle events from the existing AuditLog.
- SBOM responses add lifecycle status/revision, `analysis_requires_reanalysis`, and a processing eligibility verdict (`eligible`, `reason_code`, `reason`). Run responses expose currentness and processing eligibility. Existing fields and contracts remain compatible through additive defaults.
- Both lifecycle directions require a trimmed nonempty reason. Duplicate transitions conflict. Status and audit event commit in the same transaction; failed audits roll back the status change. Audit metadata includes full reason, tenant, SBOM, actor, old/new status, revision and timestamp. Structured logs include request/actor/tenant/SBOM/action metadata without content or reasons.

## Processing and current aggregates

Shared eligibility blocks inactive, quarantined, validation pending, failed validation, error-count and unresolved error entries. Manual, streaming and legacy analysis paths check eligibility before cached/idempotent response replay. Comparisons and new PDF, vulnerability XLSX, FDA, lifecycle and VEX report generation enforce backend restrictions. Inactive operations return HTTP 409 with `SBOM_INACTIVE` in the application's existing detail envelope. Obsolete analyses cannot generate new current comparisons/reports.

The shared dashboard scope excludes inactive SBOMs and non-current analysis runs/findings; component occurrences, unique versions, counts, severity buckets, charts, cards and drill-downs use that scope. Product current summaries and comparison pickers exclude inactive records. Inventory and historical detail lists retain inactive records. Shared metrics, lifetime metrics and advisor cache keys include the persisted lifecycle revision, so transitions invalidate caches in other API processes as well as the current process.

Deactivation does not delete or soft-delete uploaded content, components, validation evidence, runs, findings, stored artifacts or audit records. Historical report downloads use the same tenant/owner/permission and artifact expiry/integrity checks with historical scope membership, independently of current-generation eligibility.

## Jobs and freshness

Beat and manual schedule enqueue paths attach a lifecycle revision and deterministic revision-scoped Celery task ID. Deactivation best-effort revokes queued work without terminating worker processes; queued AnalysisRun rows become CANCELLED. Workers independently reject inactive, unsafe and old-generation jobs, including unversioned jobs queued before a lifecycle transition. Running scans finish safely but persistence rechecks the locked SBOM and generation, writes an obsolete/non-current result, and skips VEX reconciliation. Reactivation cannot revive that result.

Reactivation compares captured content checksum, validation rules digest and validation timestamp, plus existing vulnerability-provider cache revisions and expiry. The repository has no single vulnerability dataset version. Missing/expired/changed evidence conservatively requires reanalysis; legacy/backfilled analyses do not acquire a fabricated freshness proof. Unrelated provider cache refreshes can therefore require extra reanalysis. A new successful current scan clears reanalysis-required; failures and obsolete scans cannot clear it. Lifecycle state and freshness remain separate.

## Frontend

Shared badges, dialog, textarea validation, toast, loading/error and permission hooks render ACTIVE/INACTIVE status and administrator-only Mark Active/Mark Inactive actions. Mandatory reasons and lifecycle history are available on detail views. Inactive records retain historical views while analysis, selected comparisons, scheduled Run Now and new reports are disabled with explanations. Stale records permit reanalysis while current comparisons/reports remain disabled. Lifecycle mutations invalidate inventory, hierarchy, run, schedule, dashboard, advisor and report queries.

## Verification

Before changes: 52 focused backend tests and 37 frontend tests passed. The configured disposable PostgreSQL test database was initially absent; it was created before baseline verification. No pre-existing test failure was observed in those baseline suites.

- Broad backend regression: 200 passed.
- Final job-race regression: 7 passed, verifying obsolete running jobs do not block reanalysis.
- Final expanded backend verification: 114 passed (37 lifecycle cases plus analysis, report delivery/preservation and schedule regressions). An intermediate legacy VulnDB test failure was fixed and the affected suite rerun successfully.
- Frontend: 63 tests passed across seven SBOM, schedule and run-table files.
- Production frontend build: passed; TypeScript passed.
- Tests were run against the configured disposable PostgreSQL database; the new migration also passed an isolated SQLite upgrade/downgrade check.
- Lifecycle Python lint and whitespace checks: passed. The advisor file has an existing UP037 annotation issue, confirmed against HEAD; it was not refactored. Frontend ESLint has no errors; 22 existing SbomDetail warnings remain.
- New backend coverage includes transitions, reason validation, roles, tenant isolation, atomic audit rollback, direct and legacy bypass prevention, comparison/report/scheduler restrictions, preservation, cache invalidation, 140→40→140 findings totals, queued/running work, freshness/reanalysis and migration upgrade/downgrade defaults.
- New frontend coverage includes both transitions, required reasons, roles, error handling, readable history, eligibility, inactive historical detail, stale reports, scheduled Run Now and run comparison/PDF restrictions.

## Files changed for this feature

- `alembic/versions/073_sbom_operational_lifecycle.py`
- `app/core/security.py`
- `app/db.py`
- `app/metrics/_helpers.py`
- `app/metrics/cache.py`
- `app/metrics/component_advisor.py`
- `app/metrics/reporting.py`
- `app/metrics/runs.py`
- `app/models.py`
- `app/routers/analysis.py`
- `app/routers/analyze_endpoints.py`
- `app/routers/pdf.py`
- `app/routers/products.py`
- `app/routers/report_notifications.py`
- `app/routers/runs.py`
- `app/routers/sbom_versions.py`
- `app/routers/sboms_crud.py`
- `app/routers/schedules.py`
- `app/routers/vex.py`
- `app/schemas.py`
- `app/services/analysis_orchestrator.py`
- `app/services/analysis_service.py`
- `app/services/audit_service.py`
- `app/services/compare_service.py`
- `app/services/dashboard_metrics.py`
- `app/services/dashboard_scope.py`
- `app/services/fda_510k_excel_report_service.py`
- `app/services/report_access.py`
- `app/services/sbom_lifecycle.py`
- `app/services/sbom_service.py`
- `app/services/sbom_vulnerability_excel_report_service.py`
- `app/services/schedule_resolver.py`
- `app/services/version_control_service.py`
- `app/workers/scheduled_analysis.py`
- `frontend/src/app/analysis/page.tsx`
- `frontend/src/components/analysis/RunsTable.status.test.tsx`
- `frontend/src/components/analysis/RunsTable.tsx`
- `frontend/src/components/sboms/Fda510kReportDialog.tsx`
- `frontend/src/components/sboms/SbomDetail.components.test.tsx`
- `frontend/src/components/sboms/SbomDetail.lifecycle.test.tsx`
- `frontend/src/components/sboms/SbomDetail.tsx`
- `frontend/src/components/sboms/SbomLifecycleControls.test.tsx`
- `frontend/src/components/sboms/SbomLifecycleControls.tsx`
- `frontend/src/components/sboms/SbomsTable.analysis.test.tsx`
- `frontend/src/components/sboms/SbomsTable.tsx`
- `frontend/src/components/schedules/ScheduleCard.test.tsx`
- `frontend/src/components/schedules/ScheduleCard.tsx`
- `frontend/src/lib/api.ts`
- `frontend/src/lib/queryInvalidation.ts`
- `frontend/src/lib/sbomEligibility.ts`
- `frontend/src/types/index.ts`
- `tests/snapshots/post_sbom_analyze.json`
- `tests/test_report_notifications.py`
- `tests/test_sbom_operational_lifecycle.py`
- `tests/test_schedules_api.py`
