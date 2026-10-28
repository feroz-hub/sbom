# Analysis module UI correction

## Confirmed cause (before implementation)

`frontend/src/app/analysis/page.tsx` mounts `SbomPostureNotice` before the tab
navigation and before every tab panel. With no scope selected it requests
`/dashboard/posture-versions` for the entire active tenant. `PostureEvidence`
maps every returned lineage into several paragraphs, without a bound or a
collapsed container. These are version provenance summaries, not duplicate
analysis records. Their placement pushes the scan controls below the portfolio.
The same component labels `posture_sbom.version/name` as security posture and
labels a finding-row count as "Last successful analysis". The page title and
toolbar are hardcoded to Runs for all tabs.

Runs already has a table, but the page always fetches page 1 with 100 records;
the table then searches, sorts and paginates only that slice. The API already
supports paging and `X-Total-Count`. Consolidated's numeric identifier input
also conflicts with public UUID selectors. No evidence points to duplicated
database records or defective vulnerability calculations.

## Existing contracts and preservation boundaries

- `/analysis?tab=runs`, `/analysis?tab=consolidated`, the vulnerabilities tab,
  `/analysis/[id]`, and `/analysis/compare` remain available.
- `/api/runs` returns an array with `X-Total-Count`; existing clients and JSON
  export retain that contract. Optional search/order/summary parameters are
  additive. Run counts and history queries belong in `app/metrics/`.
- Consolidated uses `useAnalysisStream` and the existing scan stream. Supported
  source keys are NVD, OSV and GITHUB (displayed as GHSA). Credentials and
  processing eligibility must be respected. No new source is implemented.
- Current/uploaded/analyzed versions come from the selected lineage's posture
  response. Severity counts and completion time come from its actual run.
  Missing evidence remains unavailable; zero findings is not a security guarantee.
- Authentication, authorization, tenant context, calculations, persistence,
  comparison semantics and existing export endpoints remain intact.
- Existing dirty layout, launcher and UAT work is outside this change.

Validation results, screenshots and remaining limitations are recorded below
after implementation.

## Changes implemented

### Consolidated

The title now follows the selected tab. Configuration comes immediately after
compact, keyboard-navigable tabs. The form uses the active tenant, project,
product/application, and public SBOM selector. Project/application selections
cascade atomically for configuration; Runs retains independent scope filters.
Selecting an SBOM retrieves its actual metadata and processing eligibility.
The numeric-only input was removed. An existing queued/running attempt is
monitored through the existing SBOM endpoint and linked to its details.

Only NVD, OSV and GHSA are offered. GHSA is disabled when its server credential
is missing and excluded from submitted source selections. The existing stream,
idempotency, authorization and cache reconciliation remain in use. Terminal
status is retained from the stream, partial coverage is disclosed, source
progress has an accessible progressbar, and the disconnect control describes
its actual behavior. It does not claim to cancel server processing.

Version provenance is requested only for the selected SBOM lineage. Current,
latest uploaded and latest analyzed are separate name/version fields. Security
posture shows the real successful run's counts, including unknown severity,
and its completion time. The evidence SBOM is identified when a fallback is in
use. Missing evidence/coverage remains explicitly unavailable or incomplete;
zero findings is accompanied by a coverage limitation. Per-source summaries
reuse the existing source-coverage parser and descriptions. No vulnerability
counts or timestamps are calculated from names or fabricated in the UI.

Scan readiness is expandable. At most five recent runs appear after
configuration/execution/results, with a scoped link to the complete history.
Portfolio-wide posture paragraphs no longer mount in the Analysis page.
The shared posture component used by other modules is unchanged.

### Runs

The history table requests one server page (25 rows by default; configurable
up to 100). Search, project/application/SBOM, status and source filters run on
the server. Column ordering uses allowed SQL expressions with a persisted-ID
tie breaker. Pagination uses `X-Total-Count`; a missing header produces an error
rather than a fabricated total. Search and page changes reset correctly without
the initial debounce undoing a quick page navigation.

Columns provide run identity/copy/pin, project/product, SBOM/version, canonical
status/source, total findings, all five severity buckets, completion time,
duration, details and existing PDF export. Selection can span pages and still
uses UUIDs for Compare. Search/scope/status/source/order also carry into the
existing JSON export. Filters remain available for empty/error results.

The API adds optional `q`, `source`, `sort_by`, `sort_direction` and
`summary_only` parameters. Its default array body, full-report behavior,
`X-Total-Count`, default descending-ID ordering, and supported cursor contract
remain compatible. The table's summary mode omits raw reports and does not
load raw SBOM documents. Joined metadata is tenant-scoped and preserves
unassigned relationships. History/count queries live in the metrics layer.
Current eligible-run aggregate tiles remain separately identified; they are
not mislabeled as totals of the filtered historical table.
The existing CORS middleware exposes the two pagination response headers so
direct frontend API mode can read them; allowed origins and authorization are
unchanged. The existing authenticated frontend proxy already forwards them.

### Compare

The existing baseline/target pickers, findings/components/severity deltas,
exports and URL state are preserved. Summaries now include the actual SBOM
version when available. The selection area displays baseline and target
names/versions explicitly and scrolls with the page on small screens.
No diff calculation or finding identity logic changed.

## Files changed by this task

Paths below are relative to the repository. Pre-existing layout, shell,
launcher and UAT changes are not part of this task.

| File | Purpose |
| --- | --- |
| `frontend/src/app/analysis/page.tsx` | Tab-specific titles and hierarchy, scope controls, bounded recent runs; remove unconditional portfolio posture |
| `frontend/src/components/analysis/AnalysisHubTabs.tsx` | Compact responsive tabs, ARIA controls and arrow/Home/End keyboard behavior |
| `frontend/src/components/analysis/ConsolidatedAnalysisPanel.tsx` | Tenant/configuration/SBOM metadata, eligibility, active attempt and scan execution |
| `frontend/src/components/analysis/SelectedSbomContext.tsx` | Selected-lineage provenance and actual successful-run results |
| `frontend/src/components/analysis/AnalysisRunsHistory.tsx` | Server filters, search, pagination, selection, ordering and JSON export |
| `frontend/src/components/analysis/RunsTable.tsx` | Structured history and bounded recent table with metadata, severity and actions |
| `frontend/src/components/analysis/RunSeveritySummary.tsx` | Shared truthful counts, including unknown/unavailable severity |
| `frontend/src/components/analysis/SourceSelector.tsx` | Supported sources, credential availability, concise analyst-facing copy |
| `frontend/src/components/analysis/LiveAnalysisCard.tsx` | Terminal outcome, partial-coverage disclosure, progress accessibility and disconnect wording |
| `frontend/src/components/compare/SelectionBar/SelectionBar.tsx` | Baseline/target names and versions; responsive scrolling |
| `frontend/src/components/compare/SelectionBar/RunPicker.tsx` | Version metadata and stable option memoization |
| `frontend/src/hooks/useAnalysisUrlState.ts` | Atomic cascading scan scope, preserving history filter semantics |
| `frontend/src/hooks/useAnalysisStream.ts` | Retain the existing stream's terminal status for display |
| `frontend/src/lib/api.ts` | Read paged run totals and serialize additive history/export filters |
| `frontend/src/types/index.ts` | Optional history project name and SBOM version |
| `frontend/src/types/compare.ts` | Optional comparison SBOM version |
| `app/metrics/runs.py` | Tenant-scoped history/search/count/order, bounded metadata loading |
| `app/main.py` | Expose existing count/cursor response headers to direct browser API clients |
| `app/routers/runs.py` | Additive history query parameters and picker version metadata |
| `app/schemas.py` | Optional run metadata response fields |
| `app/schemas_compare.py` | Optional comparison version field |
| `app/services/compare_service.py` | Populate version from the existing SBOM record |
| `frontend/src/components/analysis/AnalysisModule.test.tsx` | History/configuration/metadata/partial/active-attempt regressions |
| `frontend/src/components/analysis/RunsTable.status.test.tsx` | Preserve historical eligibility checks with semantic details links |
| `frontend/src/lib/api.runs.test.ts` | Count header, public selectors and export filters |
| `tests/test_analysis_history_ui_contract.py` | 107-run paging/search/order/metadata/default-contract and tenant tests; Compare versions |
| `frontend/e2e/analysis.config.ts` | Independent Chrome regression configuration, with certificate verification enabled |
| `frontend/e2e/analysis.spec.ts` | Eight responsive/workflow/error/export/Compare/theme scenarios and screenshots |
| `frontend/e2e/analysis.compare-fixture.ts` | Existing canonical Compare test fixture reused for browser assertions |
| `docs/engineering/analysis-ui-redesign.md` | Investigation, implementation and verification report |
| `docs/engineering/analysis-ui-evidence/` | Before/after screenshots and verification summary |

## Before and after evidence

The before screenshot was captured from the existing authenticated application
on port 13000. Its process runs in a different snapshot checkout, so it was
not restarted, patched or pointed at another database. The after screenshots
show this checkout on the separate verification frontend, using deterministic
API fixtures. They verify actual rendering, not a design mockup. The shell in
the after images also includes the user's pre-existing layout changes.

- [Before: Consolidated](analysis-ui-evidence/consolidated-before.png)
- [After: Consolidated, desktop](analysis-ui-evidence/consolidated-after-1440.png)
- [After: Consolidated, tablet](analysis-ui-evidence/consolidated-after-768.png)
- [After: Consolidated, mobile](analysis-ui-evidence/consolidated-after-390.png)
- [After: Mobile dark theme](analysis-ui-evidence/consolidated-dark-390.png)
- [After: Run history](analysis-ui-evidence/runs-after-1440.png)
- [After: Run history, dark theme](analysis-ui-evidence/runs-dark-1440.png)
- [After: Partial analysis results](analysis-ui-evidence/analysis-results-after.png)
- [After: Comparison](analysis-ui-evidence/compare-after.png)

## Data limitations and remaining improvements

- Source counts in a completed stream are displayed as returned. Persisted
  per-source summaries describe query/coverage activity; they are not relabeled
  as unique vulnerability counts. Historical runs without a summary display
  an unavailable breakdown.
- Current posture projection may have no eligible evidence for a historical
  selection. The screen shows unavailable evidence rather than borrowing an
  unrelated lineage's run. Existing detailed historical runs remain accessible.
- Older cached comparison payloads may lack SBOM versions. These display
  "Unavailable" until a current response includes the optional field.
- The existing SBOM choice API/list hook supplies at most 500 choices, and
  product choices are derived from that list. Runs history itself is fully
  server-paged beyond this limit; valid direct SBOM URLs still load their
  metadata. A server-backed, searchable SBOM/application picker is a future
  improvement for very large inventories.
- Production source credentials, external provider availability/rate limiting,
  worker scheduling and a physical mobile device were not exercised here.
  Browser request/stream/exports use fixtures; backend contract and tenant
  isolation checks use a temporary PostgreSQL cluster. No production scan was
  started, no existing records were changed, and no authentication policy changed.
- Deploy both frontend and backend from this checkout to use the added history
  filters. The separately running port-13000 snapshot remains unchanged.

## Verification

All JavaScript commands used the bundled Node runtime at
`/Users/ferozebasha/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node`.
Commands below show that executable as `node`. Backend runs used `.venv/bin/python`
with both `TEST_DATABASE_URL` and `TEST_POSTGRES_DATABASE_URL` explicitly targeting
only the new disposable database on loopback port 56423. Existing database
settings were not substituted. The temporary PostgreSQL cluster was initialized
for these tests and the repository's normal migration/test fixtures ran there.

| Executed command / scope | Result |
| --- | --- |
| From `frontend`: `node node_modules/vitest/vitest.mjs run --maxWorkers=1` (final source) | **1,852 passed, 205 files** |
| Focused Vitest run across `src/components/analysis`, `src/components/compare`, stream/terminal sync, API and mutation-invalidation tests | **194 passed, 25 files** |
| `node node_modules/typescript/bin/tsc --noEmit` | **Passed** |
| `node node_modules/eslint/bin/eslint.js` with the changed Analysis/Compare components, hooks and tests | **Passed: 0 errors, 0 warnings** |
| `.venv/bin/python -m pytest tests/test_analysis_history_ui_contract.py tests/test_metric_consistency.py tests/test_run_finding_metrics.py tests/test_public_resource_uuid.py tests/test_compare_router.py tests/test_compare_service.py tests/test_compare_v1_deprecation.py -q --tb=short` | **96 passed** |
| From `frontend/e2e`: `node node_modules/@playwright/test/cli.js test --config analysis.config.ts` | **8 passed**; final screenshot/runtime-error rerun recorded in the summary artifact |
| `git -c core.fsmonitor=false diff --check` | **Passed** |

The PostgreSQL checks establish actual API pagination, filters/order,
search/count consistency, metadata, legacy canonical-status compatibility,
UUID selectors, tenant isolation, finding metrics, comparison and version
mapping. The metrics architecture check also passed. The entire backend test
suite was not run.

The browser cases intercept every API call with fixtures. They establish the
actual frontend's route titles/hierarchy, bounded rows, UUID metadata loading,
configured source selection and POST payload/tenant header, stream partial
results, errors/empty states, navigation to Compare, comparison deltas,
JSON download contents, and responsive light/dark rendering. Viewports include
1440, 768 and 390 pixels. They do not establish external source availability or
live worker integration. HTTPS verification stayed enabled.

Initial failures were resolved before the final reruns: the new history query's
joined eager loading omitted unassigned relationships (fixed with separate
bounded relationship loading), and the initial debounce could reset a quick
page change (fixed). New fixtures were corrected to supply required product
metadata and accurately mock the configuration endpoint. A details action test
was updated from button semantics to a real navigation link. An early SQLite
attempt was blocked at authorization-catalog startup, so all backend delivery
checks were rerun against isolated PostgreSQL. One build attempt was deliberately
interrupted while final code was still changing and is not counted as a pass.

Warnings in passing runs were the existing jsdom pseudo-element/navigation
limitations and Python/Pydantic/Alembic deprecations. They were not suppressed
or relabeled as failures in the delivery results.

Production compilation: `node node_modules/next/dist/bin/next build --webpack`
**passed**, including TypeScript and static page generation. The default
`next build` (Turbopack) stalled in compilation and was stopped; a retry with
an empty Turbopack cache also stalled. No compiler error was returned by those
attempts. The old cache was preserved in a temporary archive rather than
deleted. The repository's build script/configuration was not changed. The
Webpack result confirms a production build of the implementation; default
Turbopack completion remains an environment/toolchain verification gap.

The final CORS header addition was verified by rerunning all three history
contract cases, including an Origin-bearing request that asserts the count
header is browser-readable. The 96-test backend run preceded only this
response-header addition; the subsequent contract rerun passed.

Final browser evidence rerun: **8 passed in 16.9 seconds**, including explicit
assertions that no browser runtime errors occurred. Reduced-motion mode keeps
the saved evidence free of transient fade animations. The temporary frontend
and PostgreSQL cluster were stopped after verification; existing application
processes were not stopped. Next's generated type-file changes were not
retained in the patch.

## Final Git integration verification

Before committing, the branch was fast-forwarded from `ff202a79` to remote
revision `212490d6`, which includes the separate SBOM inventory redesign.
There were no overlapping files, and all previously pending files were
verified unchanged by SHA-256. Only the Analysis implementation, tests and
evidence are included in this commit.

The full frontend suite was rerun on the combined revision: **1,855 passed,
1 failed across 206 files**. The failure is
`SbomsTable.analysis.test.tsx > uses theme-aware table row and action classes
for dark mode`: it expects a `View SBOM` button that the incoming inventory
redesign replaced with its action menu. The identical failure was reproduced
in a clean archive of remote revision `212490d6`, without any Analysis changes
(9 passed, 1 failed). This is an existing remote-baseline failure; the inventory
module and its tests were left unchanged. The earlier 1,852-pass result above
applies to the pre-integration revision and does not describe this final run.
TypeScript was rerun after integration and passed. The scoped credential
candidate scan found no matches, staged whitespace checks passed, and no
generated Next type-file change is included.
