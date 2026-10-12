# Olympus Dashboard version-posture warning investigation

Date: 2026-10-09. Branch: `feat/native-user-management`; base: `6e7b22e1`.
The existing uncommitted lifecycle implementation is preserved.

## Root cause and request trace

The warning was false as an assertion that Olympus lacks analysis provenance.
`SbomPostureNotice` rendered “Version posture evidence is unavailable. Empty
counts do not establish zero risk.” on TanStack Query `isError`, rather than on
a successful response declaring missing analysis evidence.

The authenticated frontend request was
`GET https://localhost:13000/api/backend/dashboard/posture-versions`, forwarded
to `GET http://127.0.0.1:18000/dashboard/posture-versions`. The running API returned
HTTP **404**, `{"detail":"Not Found"}`. Its OpenAPI route table did not contain the
endpoint although the endpoint existed in the working tree. The API process had
started at 00:45:34 local time without reload, before this source was loaded;
frontend development updates had already exposed the new component.

Examples of failed API request IDs: `79921dd85f93`, `d5d45d79d551`.
This was a routing failure before posture authorization/resolution, not a valid
`UNAVAILABLE` response, and had no selected-current or last-known-analysis payload.
The separate `/dashboard/summary` request continued supplying the nonzero metrics.

The managed local development runtime was restarted. Its existing Alembic head
was checked **read-only** (`076_logical_sbom_versions`); migration execution was
explicitly skipped. The endpoint then appeared in live OpenAPI and returned HTTP
**200** (example request ID `05f6dcbde19c`). The authenticated Dashboard was
visually verified showing both named applications, the corresponding run IDs,
and 108/0 finding records. Direct browser navigation to the JSON endpoint was
blocked by the browser client; response metadata was additionally verified through
the endpoint's source and read-only execution against the actual database.

## Actual Olympus evidence

Read-only transactions used the managed development database configuration from
`.env.dev.local`, not a potentially different default `.env` database. No database
backfill or record correction was needed.

Tenant 1: Olympus. Dashboard Project/Application/SBOM: ALL.

| Application | Project | Current SBOM | Logical SBOM | Parent | Successful current run | Finding rows |
|---|---:|---:|---:|---|---|---:|
| Infusion Pump Controller (product 3) | 1 | 1 | 1 | NULL | 1 — FINDINGS | 108 |
| Test_Upload (product 5) | 3 | 2 | 2 | NULL | 2 — OK | 0 |

Both SBOMs are active, lifecycle ACTIVE, version 1.0.0; both runs are active and
`is_current=true`. `Product.current_sbom_id` correctly designates each source.
A NULL parent is valid for an independent lineage root. Neither application lacks
provenance. Other active applications without SBOMs are not fabricated as missing
SBOM posture targets; the deleted/inactive application is excluded.

Run 1 has a legitimate **provider coverage** limitation: four GITHUB query errors
and a partial source summary. Its 108 stored finding rows remain evidence, with
an incomplete-coverage warning. Run 2 is a successful legacy BACKFILL run with
zero findings and no stored source summary; no unsupported provider failure is
inferred for it.

Read-only execution confirmed the tenant summary: AVAILABLE, 2 targets, 2 available,
0 missing, 1 coverage-incomplete; tenant 1 with NULL project/product/SBOM filters.
Neither item uses last-known fallback. Current targets and posture sources are
SBOMs 1 and 2, with run IDs 1 and 2. Findings total matches the metric query: 108.

| Actual scope | Selected run IDs | Finding rows |
|---|---|---:|
| Tenant 1, ALL | 1, 2 | 108 |
| Project 1 | 1 | 108 |
| Project 3 | 2 | 0 |
| Project 1 / application 3 | 1 | 108 |
| Project 3 / application 5 | 2 | 0 |
| Project 1 / application 3 / SBOM 1 | 1 | 108 |
| Project 3 / application 5 / SBOM 2 | 2 | 0 |

## Corrective changes

- Request failures now show their HTTP status and Retry, distinct from loading
  and a valid unavailable response. HTTP 403 is an authorization error, without
  automatic retry or forced authentication redirection by this request.
- Failed refreshes retain clearly labeled cached evidence; freshness is unverified.
- Additive response summary separates EMPTY, AVAILABLE, PARTIAL and UNAVAILABLE.
  Scope fields expose the effective validated filters.
- Missing-evidence warnings name only affected applications/SBOM lineages and
  preserve separate findings from analyzed sources. They do not call nonzero
  portfolio metrics “empty”.
- Application names disambiguate identical version strings.
- Source completeness uses the existing source-summary extractor and coverage
  predicate, including legacy root-level summaries. A provider failure does not
  become missing version provenance, and a real successful zero stays available.

Version designation, active-lineage selection, latest eligible successful runs,
and pending/failed replacement fallback remain in the existing shared resolver.
DashboardScope, VEX metrics and Component Advisor continue using that resolver;
no parallel current-version policy or invented evidence was introduced.

## Files changed in this investigation

- `app/metrics/posture.py`: application name in tenant-scoped projection.
- `app/services/sbom_posture.py`: availability summary and shared coverage parsing.
- `app/routers/dashboard_main.py`: additive summary and effective scope fields.
- `frontend/src/lib/api.ts`: typed response and in-place authorization errors.
- `frontend/src/types/index.ts`: additive posture response types.
- `frontend/src/components/sboms/SbomPostureNotice.tsx`: distinct UI states and retry.
- `frontend/src/components/sboms/SbomPostureNotice.test.tsx`: UI regressions.
- `tests/test_dashboard_posture_evidence.py`: endpoint/scope/security regressions.
- `docs/vex/olympus-posture-warning-2026-10-09.md`: this investigation report.

Other pre-existing uncommitted lifecycle files were preserved.

## Validation

- Isolated PostgreSQL backend: **59 passed, 0 failed**: 11 new posture endpoint
  regressions, 26 lifecycle completion checks, 22 version lifecycle checks.
- Focused frontend: **122 passed, 0 failed, 8 files**, including 10 posture tests.
- Application TypeScript: passed.
- Changed Python Ruff: passed, four files.
- Frontend lint: 0 errors, 53 warnings across the existing working tree.
- Production Webpack build: passed in an isolated copy to protect live dev
  output. An initial /tmp copy failed during standalone tracing because its
  node_modules symlink crossed filesystem roots; an ignored repository-local
  copy with an explicit tracing root passed. No product build configuration changed.
- `git diff --check`: passed.
- Live Olympus Dashboard and seven read-only data scopes verified.

Coverage includes two analyzed applications at ALL scope, project/application/SBOM
scope, designation, missing parent/legacy version metadata, pending/failed
replacement, successful zero, partial/unavailable/empty evidence, tenant isolation,
permissions, HTTP 500 recovery, HTTP 403, loading, and cached refresh failure.
Existing lifecycle suites also cover obsolete runs and historical preservation.

No full-repository green claim is made. No commits, pushes, production migration,
production deployment, or Olympus record backfill were performed.
