# Shared version evidence rendering correction

## Confirmed root cause

The exact-label search identifies `PostureEvidence` in
`frontend/src/components/sboms/SbomPostureNotice.tsx`. It maps every returned
lineage into several paragraphs without pagination or disclosure. VEX mounts
it before its overview, filters and investigation table. It receives the
`posture` array attached to the existing investigation list response, which
can cover the entire active tenant. The former Analysis page mounted the same
renderer via `SbomPostureNotice`; that call was removed in the preceding
Analysis correction. These are version provenance entries, not duplicate
persisted analysis records.

The renderer also labels a version string as security posture and a raw
finding-row count as the last successful analysis. The backend already supplies
separate version identities, run identity, evidence warnings and an optional
completion timestamp. The defect is presentation and placement, not evidence
calculation or data duplication.

## Audit scope before implementation

| Surface | Confirmed use |
| --- | --- |
| VEX Investigation | Direct `PostureEvidence` before the operational queue; unbounded tenant/product provenance |
| Product details | `SbomPostureNotice` before the Current SBOM controls; legitimate product context with unbounded renderer |
| SBOM details | `SbomPostureNotice` before details; request uses the whole product rather than the selected SBOM |
| Analysis Runs / Consolidated / Compare | No shared feed after the preceding correction; Consolidated has separate, selected-lineage results |
| Dashboard | No shared renderer; existing metric cards and scoped filters |
| CISA KEV | No shared renderer |
| Secure Component Advisor and nested detail screens | No shared renderer |
| Schedules | No shared renderer |
| Administration / settings / platform configuration | No shared renderer |
| Root layout / AppShell / header / sidebar / route wrappers | No shared renderer or injected evidence feed |

Investigation covered exact strings, both component exports, their imports,
the posture client, backend `posture_metadata`, and existing VEX list/filter,
comparison, snapshot and detail flows. VEX status, decision, authorization and
evidence semantics follow VEX-UI-001/002/003, VEX-INV-002 and VEX-DASH-004/005.

## Intended correction

Correct the shared renderer centrally with a compact provenance summary,
visible coverage/missing/last-known warnings, and an explicitly expanded,
searchable, paginated table. Do not mount all lineage details while collapsed.
Keep raw finding rows distinct from investigation counts and show completion
time only when returned. Scope SBOM details to the selected SBOM. Put optional
VEX version comparison/history after the primary queue. No backend, database,
authorization, finding-calculation or decision changes are needed.

## Implemented correction

- `PostureEvidence` now opens as a compact provenance summary. Missing analysis,
  last-known evidence, incomplete source coverage and version notices remain
  visible. No lineage details mount until the keyboard-accessible disclosure
  opens. Expanded details use search and pagination (10 rows by default, at
  most 25), with the existing responsive table and design tokens.
- Current, uploaded, analyzed and evidence versions have separate fields.
  A version name is no longer described as a security metric. Raw finding rows
  retain their own label and are explicitly distinguished from VEX context
  counts. The existing backend `analysis_completed_on` supplies the formatted
  completion time; older/missing timestamps show `Time unavailable`. Run links
  use the returned public identity. No counts, statuses or timestamps are inferred.
- VEX overview cards precede provenance. Existing filters, paged queue,
  canonical statuses, justification/detail/review/assignment actions and dialogs
  are retained. Optional historical snapshots and version comparison now open
  after the queue. Selected-SBOM provenance is filtered against the projection's
  target/evidence identity because the existing list response is product-wide.
- Product details benefit from the central correction without a page-specific
  patch. SBOM details now pass their own public SBOM identity to the existing
  posture endpoint. Tenant/scoped query keys, retries and stale-evidence errors
  are retained; disclosures reset on tenant/scope changes.
- This is conditional rendering and pagination, not a CSS concealment. Navigation,
  headers, tenant selection, health indicators and pre-existing layout changes
  remain unchanged. No backend, API contract, schema, authorization, calculation,
  analysis record, finding or VEX decision was modified.

## Files modified

| File | Purpose |
| --- | --- |
| `frontend/src/components/sboms/SbomPostureNotice.tsx` | Central compact, expandable and paginated renderer; honest fields and loading/error states |
| `frontend/src/components/sboms/SbomDetail.tsx` | Scope version evidence to the selected SBOM |
| `frontend/src/app/vex-investigation/page.tsx` | Operational hierarchy, selected-SBOM provenance, optional version tools after the queue, responsive overview |
| `frontend/src/types/index.ts` | Type the already-returned optional completion timestamp |
| `frontend/src/components/sboms/SbomPostureNotice.test.tsx` | Collapsed DOM, 1,007-lineage pagination/search, accurate fields, absent evidence, errors and tenant switching |
| `frontend/src/components/sboms/SbomDetail.lifecycle.test.tsx` | Real selected-SBOM scope regression alongside existing operations |
| `frontend/src/app/vex-investigation/page.test.tsx` | 107-lineage queue hierarchy and scoped provenance/comparison regressions |
| `frontend/e2e/posture.config.ts` | Independent Chrome regression configuration with HTTPS certificate verification enabled |
| `frontend/e2e/posture.spec.ts` | Seven actual-frontend VEX/product regressions and screenshots, with intercepted API fixtures |
| `docs/plans/vex-implementation-plan.md` | VEX requirement mapping and session outcome |
| `docs/engineering/shared-version-evidence-ui.md` | Root cause, module audit, implementation and executed checks |
| `docs/engineering/shared-version-evidence/` | Screenshot evidence and machine-readable verification summary |

## Verification results

JavaScript commands used the bundled Node executable at
`/Users/ferozebasha/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node`.
They are abbreviated to `node` below. Backend tests used `.venv/bin/python`,
with `TEST_DATABASE_URL` and `TEST_POSTGRES_DATABASE_URL` explicitly targeting
only a newly created disposable PostgreSQL cluster on loopback port 56424,
database `sbom_posture_ui_test`. The normal test bootstrap/migrations ran there.
The test frontend used its own HTTPS port 13001 and existing trusted certificate.
All its API requests were intercepted; no real credentials or production scans
were submitted. Both temporary services were stopped after verification.

| Executed check | Result |
| --- | --- |
| Baseline Vitest: shared posture, VEX, Analysis/Compare, AppShell and Dashboard filters | **256 passed, 24 files** before source edits |
| Focused Vitest: posture, VEX, SBOM lifecycle, Analysis/Compare, layout/dashboard, KEV, Schedules, Advisor, policy and mutation-invalidation tests | **500 passed, 47 files** |
| From `frontend`: `node node_modules/vitest/vitest.mjs run --maxWorkers=1` | **1,863 passed, 1 failed across 206 files**; known inventory baseline failure below |
| `node node_modules/typescript/bin/tsc --noEmit` | **Passed**, including final rerun |
| Scoped `node node_modules/eslint/bin/eslint.js` across all seven changed frontend source/test files | **0 errors, 26 pre-existing warnings**; clean HEAD stdin lint reproduced all 22 SBOM-detail and 4 VEX-test warnings |
| From `frontend/e2e`: `node node_modules/@playwright/test/cli.js test --config posture.config.ts` | **7 passed** on the final run; desktop 1440, tablet 768, mobile 390, keyboard disclosure, bounded/searchable evidence, scope/tenant headers, loading/empty/error/denial, details and dark mode |
| From `frontend/e2e`: `node node_modules/@playwright/test/cli.js test --config analysis.config.ts` | **8 passed**; Runs paging/search/JSON, Consolidated configuration/scan request/partial results and Compare/deltas/JSON remain functional |
| `.venv/bin/python -m pytest tests/test_vex_version_lifecycle.py tests/test_vex_investigations_api.py tests/test_vex_scoped_authorization.py tests/test_dashboard_posture_coverage.py tests/test_dashboard_posture_evidence.py tests/test_analysis_history_ui_contract.py tests/test_metric_consistency.py -q --tb=short` | **117 passed**; actual backend API, tenant/role authorization, evidence/coverage, version lifecycle, queue/summary consistency, history paging and metric architecture |
| `node node_modules/next/dist/bin/next build --webpack` | **Passed**: compilation, TypeScript and 47 static pages |
| `git -c core.fsmonitor=false diff --check` and SHA-256 comparison of initial pending tracked files | **Passed**; all 11 pre-existing tracked changes remain byte-identical; generated Next type-file drift restored |

The full frontend failure is
`SbomsTable.analysis.test.tsx > uses theme-aware table row and action classes for dark mode`.
It expects a `View SBOM` button replaced by the incoming inventory redesign's
action menu. It was reproduced on clean remote revision `212490d6` before this
task, as recorded in [the preceding delivery](analysis-ui-redesign.md#final-git-integration-verification).
This task did not change that module or its test. The full suite is therefore
not reported as green.

Initial browser checks exposed excessive summary height on narrow screens;
the warning summary and tablet grid were compacted before the final passing
run. Other initial browser failures were incomplete test fixtures (product
logical-SBOM route/owner metadata and the existing outer permission gate) and
were corrected in fixtures, without changing application authorization. The
first disposable database bootstrap rejected a passwordless URL; the rerun
used an ephemeral in-memory test credential and passed. No existing database
or application credentials were changed. Existing jsdom and Python/Alembic
deprecation warnings remain reported.

## Visual evidence

Screenshots show the actual frontend with synthetic API fixtures, including the
checkout's pre-existing shell changes. They do not establish live-provider or
production data acceptance.

- [VEX desktop, 107 lineages collapsed](shared-version-evidence/vex-after-1440.png)
- [VEX tablet](shared-version-evidence/vex-after-768.png)
- [VEX mobile](shared-version-evidence/vex-after-390.png)
- [VEX dark theme](shared-version-evidence/vex-dark.png)
- [Expanded searchable evidence](shared-version-evidence/vex-evidence-1440.png)
- [Expanded mobile evidence](shared-version-evidence/vex-evidence-390.png)
- [Product details using the shared correction](shared-version-evidence/product-version-evidence.png)

## Remaining limitations

- The existing provenance endpoints still return a complete in-scope array.
  Rendering is bounded, but server pagination/lazy provenance transport would
  reduce payload and query work for very large tenants. That requires a separate
  backward-compatible backend change; this task changes no API contracts.
- The provenance DTO supplies raw finding rows and completion time, not severity
  buckets for every lineage. It is labeled version evidence. Severity stays in
  the existing investigation/findings surfaces; it is not invented here.
- The unrelated inventory test failure and 26 baseline lint warnings remain.
  The production build was verified with Webpack. Default Turbopack completion
  was not re-tested; the previously documented environment stall remains open.
- Browser checks use fixtures and backend checks use isolated tests. Full backend
  regression, real provider/worker integration, live production acceptance and
  physical mobile/assistive-device validation are not claimed.
- The separately running snapshot application on port 13000 was not redeployed
  or restarted. These changes must be built/deployed into that checkout before
  that application's UI reflects them.
