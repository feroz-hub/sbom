# Phase 1: UI data synchronization audit

Date: 2026-10-09. Repository: `feroz-hub/sbom`.

## Batch 2 implementation — dashboard and VEX automatic synchronization

Implemented on 2026-10-09 on `feat/native-user-management`, HEAD `6e7b22e1110ef1849150671b8d253efe0479e074`. Batch 1 and the original audit below are preserved. **This batch addresses UI-SYNC-03, UI-SYNC-04 and UI-SYNC-05 only.**

### Dependencies and source changes

- `frontend/src/lib/queryInvalidation.ts`: dashboard invalidation now covers `dashboard-priority-findings`, `dashboard-operational-runs`, `portfolio-trend` and `vulnerability-age`, in addition to existing families. Prefix matching retains all tenant/project/product/SBOM/filter/date/period suffixes and marks affected cached variants stale. The helper returns an awaitable promise.
- Existing analysis-completion, remediation save (`FindingsTable`), product create/edit/delete/current-version designation, SBOM upload/repair import/delete and lifecycle actions already call shared dashboard helpers. Their established paths now reach the added families without changing page/chart/filter rendering. Other inventory metadata/reassignment and project mutation omissions from UI-SYNC-06/07 remain deferred.
- Same-turn dashboard/VEX invalidations are coalesced in a private QueryClient-keyed queue inside the existing utility. This avoids repeated refetches from composed helpers. A later mutation still uses React Query's normal cancellation to replace a pre-mutation read; it does not retain an old in-flight request merely to reduce network traffic. This is an invalidation implementation detail, not a new event bus.
- `invalidateVexSurfaces` now returns a promise and refreshes `dashboard-summary` for evidence/decision/mapping changes. `dashboard-vex`, list/filtered summaries, detail, statements, component vulnerability/history and finding projections retain their dependencies. Assignment-only changes refresh queue/filtered summary/detail/resolver, while leaving security aggregate metrics and finding/statement caches alone.
- `vex-investigation-by-triple` is invalidated by SBOM ID whenever known, retaining unrelated SBOM resolver caches. An optional investigation ID targets the individual detail cache for decision/assignment/mapping. Evidence imports/discovery can affect multiple contexts, so their list/detail families remain broader. Analysis completion also invalidates resolver evidence for the analyzed SBOM after reconciliation.
- `frontend/src/components/vex/VexDecisionEditor.tsx`: successful decision saves await shared invalidation before the existing onSaved callback. Failure and HTTP 409 handling retain their existing behavior.
- `frontend/src/components/vex/VexInvestigationPanel.tsx`: assignment passes its explicit change type and SBOM/investigation IDs; mapping passes the resource IDs. Existing returned-detail updates and callbacks remain.
- `frontend/src/components/sboms/SbomDetail.tsx`: successful document upload/discovery awaits the shared VEX helper. Existing success messaging, form handling and callbacks remain.
- Removed immutable `vex-run-snapshot` from current-version posture invalidation. New analysis changes run-history availability, not a selected historical run's frozen evidence. No historical snapshot query keys were redesigned.
- New tests: `frontend/src/lib/dashboard-vex-invalidation.test.ts` and `frontend/src/components/vex/data-sync.integration.test.tsx`. Updated `frontend/src/components/sboms/SbomDetail.lifecycle.test.tsx` to stub the resolver for its legacy override scenarios, rather than wait on an unmocked network lookup. Together with this report, eight files changed in Batch 2.

No FastAPI, VEX calculations/business rules, authentication, five-minute global staleTime, polling, transport, dependency or Batch 1 implementation was changed. No reload/router refresh was introduced. UI-SYNC-06 through UI-SYNC-17 are not implemented here.

### Regression evidence and validation

Real QueryClients use a five-minute staleTime with global focus refetch disabled. Tests exercise authoritative mocked values, active/inactive/disabled observers, scoped custom date ranges and alternate periods, immutable run snapshots, same-turn duplicate refetch counts, replacement of a pre-mutation read, successful editor saves and reopening resolver data, imports/discovery, assignment-only aggregate exclusion, backend failures and HTTP 409 draft/conflict behavior. Import/discovery cache tests use an API mutation harness with the actual API adapter/shared invalidation path; existing SBOM detail suites cover the surrounding view.

| Check | Result |
|---|---|
| Final focused Vitest set, including all Batch 1 suites, dashboard widgets/drilldown, VEX page/cache tests, SBOM detail and product detail | **214 passed, 17 files, 0 failures** |
| Recheck of new cache suites plus the corrected SBOM lifecycle test fixture | **34 passed, 3 files, 0 failures** |
| Final `npm run lint` | Exit 0; **0 errors, 53 warnings**, identical warnings to the Batch 1 baseline |
| `npm exec -- tsc --noEmit --incremental false` (no project typecheck script) | **Exit 0, no diagnostics**, including the final source recheck |
| `git -c core.fsmonitor=false diff --check` | Passed |

Vitest used the project `npm run test` script with `--maxWorkers=1 --testTimeout=15000` for the 17-file set. The first new-suite run caught a wrong argument index in the trend test; concurrent validation later produced two new-test timeouts. The command-only worker/timeout adjustment and replacing per-character typing with an input change kept the cache assertions intact. The first broad run was **213 passed / 1 failed**: the existing SBOM legacy-decision fixture left resolver calls unmocked, exposed by awaiting the refresh before onSaved. The deterministic resolver stub fixed the fixture, and the complete 214-test rerun passed. Initial TypeScript validation also caught an incompatible import/discovery union in the new mutation harness; explicitly awaiting each adapter as a void mutation resolved it. No unrelated production changes were used to fix validation failures.

The complete focused set comprises `src/app/platform/page.test.tsx`, `src/app/platform/data-sync.integration.test.tsx`, `src/app/settings/platform/page.test.tsx`, both tenant list/detail page tests, `src/lib/queryInvalidation.test.ts`, `src/hooks/useAuth.test.tsx`, `src/__tests__/mutation-invalidation.test.ts`, the two new Batch 2 suites, `src/app/vex-investigation/page.test.tsx`, both SBOM detail lifecycle/components suites, `src/components/dashboard/PortfolioOverview.test.tsx`, `src/components/dashboard/__tests__/managerWidgets.test.tsx`, `src/app/__tests__/dashboard-drilldown.integration.test.tsx`, and product detail page tests. Checks ran using the bundled Node runtime. No full frontend/backend suite or production build was claimed.

### Limitations

Validation uses Vitest/RTL/jsdom and mocked backend responses, not an interactive browser against live FastAPI/PostgreSQL. Live home-dashboard navigation, VEX document discovery/providers, concurrent analysts and actual network cancellation should receive browser acceptance testing before release. Broad portfolio key prefixes remain where existing key contracts do not carry the resource identity needed for narrower invalidation; numeric SBOM and investigation IDs provide targeted resolver/detail updates. No cross-tenant leak is claimed. Existing auth clearing/denied-query regressions are rerun. Cross-user/background freshness and other audit findings remain deferred. SHA-256 verification found no unexpected existing source changes and confirmed that the original audit and Batch 1 documentation remain byte-for-byte intact after removing this added section. No commit or push was performed.

## Batch 1 implementation — platform control-plane correctness

Implemented on 2026-10-09 on `feat/native-user-management`, HEAD `6e7b22e1110ef1849150671b8d253efe0479e074`. The original audit and appendices below remain a record of the pre-implementation snapshot. **UI-SYNC-01 and UI-SYNC-02 are addressed; UI-SYNC-03 through UI-SYNC-17 remain outside this batch.**

### Changes and dependencies

- Added `invalidatePlatformTenantSurfaces(queryClient, tenantId)` to the existing `frontend/src/lib/queryInvalidation.ts`. It concurrently invalidates `['platform-summary']`, every `['platform-tenants', ...]` variant and the affected numeric `['platform-tenant', tenantId]` detail. It returns `Promise<void>` and waits for enabled active-query refreshes. Inactive caches become stale and fetch on revisit; disabled/unauthorized observers are not force-refetched.
- Tenant creation and activation/disabling in `frontend/src/app/settings/platform/tenants/page.tsx` call the helper only on successful mutation. Newly created ACTIVE and PENDING tenants follow the same path; all counts come from subsequent backend queries. Existing success/error notifications, confirmation and navigation are retained.
- Tenant detail status changes and administrator recovery in `frontend/src/app/settings/platform/tenants/[tenantId]/page.tsx` reuse that helper. Recovery retains its existing summary/list/detail dependencies and notification.
- Added `invalidatePlatformAdministratorSurfaces(queryClient)` to the same utility. It concurrently invalidates `['platform-administrators']` and `['platform-summary']`, returning an awaitable promise. Grants/revocations in `frontend/src/app/settings/platform/page.tsx` call it on success. The user directory has local-state consumers rather than another dependent platform Query cache; UI-SYNC-11 was not expanded into this batch.
- No backend, QueryClient defaults, auth implementation, dashboard rendering, transport or dependencies changed. Platform invalidation does not target SBOMs, findings, projects or other tenant business data. No manual metric arithmetic, full-cache invalidation, browser reload or router refresh was added.

### Files changed in this batch

1. `frontend/src/lib/queryInvalidation.ts` — two shared awaitable platform helpers; pre-existing unrelated helper changes preserved.
2. `frontend/src/app/settings/platform/tenants/page.tsx` — tenant create/status success paths.
3. `frontend/src/app/settings/platform/tenants/[tenantId]/page.tsx` — tenant status and existing recovery success paths.
4. `frontend/src/app/settings/platform/page.tsx` — grant/revoke success paths.
5. `frontend/src/app/platform/data-sync.integration.test.tsx` (new) — actual platform page mutations and rendered backend-derived metrics using a real QueryClient.
6. `frontend/src/lib/queryInvalidation.test.ts` (new) — active refresh completion, inactive/disabled cache invalidation and unrelated-query isolation.
7. `frontend/src/hooks/useAuth.test.tsx` — assertions that existing tenant-switch/logout behavior clears platform caches.
8. This engineering report — Batch 1 implementation and validation results.

### Regression evidence

New cache integration tests use the production-equivalent five-minute `staleTime` and `refetchOnWindowFocus: false`. They keep one QueryClient while moving between actual page components. Only backend adapters, auth context, notifications and independent candidate discovery/navigation UI are mocked; the shared invalidation utility and React Query are real.

Covered: PENDING and ACTIVE creation with a fresh inactive dashboard cache; dashboard return fetching authoritative total/pending/active counts; activation then disabling from both list and detail pages; refreshed detail and dashboard overview; active administrator list and summary on grant/revoke; preserved recovery behavior; failed creation/status/grant/revoke retaining metrics and unsaved form/confirmation state; denied reads; no unrelated tenant data refetch; disabled observers; awaiting all active refreshes; logout and tenant-switch cache clearing.

| Check | Result |
|---|---|
| Pre-edit platform page baseline (`npm run test --` four existing page suites) | **36 passed, 4 files**, 0 failures |
| New cache suites (`npm run test -- src/app/platform/data-sync.integration.test.tsx src/lib/queryInvalidation.test.ts`) | **17 passed, 2 files**, 0 failures |
| Final focused suite (`npm run test --` platform dashboard, tenant list/detail, administrators, new cache suites, useAuth and mutation-invalidation invariant) | **78 passed, 8 files**, 0 failures |
| Pre-edit full lint (`npm run lint`) | Exit 0; **0 errors, 53 existing warnings** |
| Final full lint (`npm run lint`) | Exit 0; **0 errors, 53 warnings**, matching pre-edit warnings (one existing location moved by the added import) |
| TypeScript (`npm exec -- tsc --noEmit --incremental false`; package has no typecheck script) | **Exit 0, no diagnostics** |
| Final fixture-only rerun of the two new cache suites | **17 passed, 2 files**, 0 failures |
| `git -c core.fsmonitor=false diff --check` | **Passed**, no whitespace errors |

Tests verify rendered data and cache/refetch behavior, rather than only spying on helper calls. The first new-suite run exposed three test-harness failures from React `use(params)` suspension; awaiting RTL render/rerender inside async `act` resolved them without changing production code. The final run passes. The first completed TypeScript check found a missing required `external_iam_tenant_id` in the new test fixture; adding the schema-required null value fixed it, and the final compiler run passed. Existing page baseline tests passed before edits. Checks use the bundled Node runtime on this host.

### Limits and scope

React Testing Library/jsdom proves the client-cache path under mocked authoritative backend responses. An interactive browser against live FastAPI/PostgreSQL and actual navigation/email provisioning was not exercised. Existing backend lifecycle and authorization rules remain unchanged. Read failures still use existing page error handling; this batch does not promise fresh data when the backend is unavailable. No commit, push or deployment was performed. Existing modified/untracked work was preserved. A SHA-256 comparison against 1,163 pre-edit source/document files found only the six intended existing files changed; the two new tests complete the eight-file batch. Branch and HEAD were rechecked after validation.


## Scope and evidence

Actual branch: **feat/native-user-management**. HEAD: **6e7b22e1110ef1849150671b8d253efe0479e074**. The working tree contains substantial pre-existing modified and untracked backend/frontend lifecycle and dashboard work. This report audits those actual working files, including untracked source components, rather than assuming HEAD or the screenshot represents their contents. Locations below refer to that working snapshot and can move when those changes are committed.

This is a static source audit. No branches were switched, application files changed, migrations applied, dependencies installed, endpoints invoked, or fixes implemented. The only repository artifact written by this audit is this report. No screenshot was available as a source artifact in this turn; conclusions use source code. Tests were inspected, not executed. “Confirmed” means the source establishes a missing dependency/refresh path; it does not mean a browser reproduction was performed.

The scan covers production TypeScript/JavaScript under `frontend/src`, the API adapters, FastAPI routers and selected dependent aggregation logic, and frontend tests. Appendices inventory every direct `useQuery`, `useInfiniteQuery`, `useMutation`, imported API/fetch call, local `useState`, and `useEffect` call found by TypeScript AST traversal. API calls inside hooks are included as well as imperative ones; not every POST or `useMutation` is a state-changing operation. Export, preview, compare and connection-test semantics are assessed separately. The API and route registries make endpoint ownership reviewable without treating absent invalidation as automatically defective.

## QueryClient and synchronization model

`frontend/src/app/providers.tsx:16` creates one QueryClient using `useState`. Its defaults are `staleTime: 5 * 60_000`, `refetchOnWindowFocus: false`, `retry: 1` (approximately lines 19–26). The adjacent comment says “30s”, which contradicts the actual five-minute setting. No global polling policy is configured.

A staleTime is a freshness classification, not a refetch timer: an already mounted dashboard can remain unchanged past five minutes unless an invalidation, mount, reconnect, interval or explicit refetch occurs. Invalidating a prefix normally refreshes active enabled observers; inactive caches are marked stale for a later mount. Disabled observers require special consideration. Decreasing staleTime alone cannot repair missing mutation dependencies.

Tenant switches are deliberately protected: `frontend/src/hooks/useAuth.tsx:576–588` persists the new tenant, clears QueryClient and resolves auth before exposing the tenant context. Logout also clears it at line 536. Therefore legacy keys without tenant IDs are a consistency/design risk, **not confirmed cross-tenant leakage**. New VEX, advisor, dashboard filters, sidebar and posture keys encode tenant/filter scope explicitly. Explicit tenant identity and auth context remain preferable, especially for long-lived subscriptions and async callbacks.

## Confirmed findings

Priorities: P1 affects security/administrative accuracy or several surfaces; P2 affects a narrower view or refresh efficiency; P3 documentation/maintenance. There is no source-supported P0 cache authorization bypass established by this audit.

| ID | Priority / risk | Source evidence and stale path | Recommended repair |
|---|---|---|---|
| UI-SYNC-01 | P1 / administrative metrics | Tenant list create/status success handlers in `frontend/src/app/settings/platform/tenants/page.tsx:119–145` invalidate only `platform-tenants`. Dashboard `frontend/src/app/platform/page.tsx:160–168` also consumes `platform-summary`. `lib/api.ts:660–680` POSTs `/api/tenants` or PATCHes `/api/platform/tenants/{id}`. `app/routers/tenants.py:350` creates tenant/admin membership; `app/routers/platform.py:809–845` commits status. Summary at `platform.py:204–226` derives tenant status/counts from DB. Cached summary and a cached `platform-tenant` detail can remain old when returning within the fresh interval. | One platform tenant mutation helper covering list, summary, affected detail and applicable audit/user dependencies. Reuse tenant-detail invalidation already present. |
| UI-SYNC-02 | P1 / administrative metrics | Grant/revoke at `frontend/src/app/settings/platform/page.tsx:39–55` invalidates only `platform-administrators`. `platform.py:544–643` persists grants/revocations; `/summary` counts active verified platform administrators at lines 223–225. The dashboard count is a separate cache. | Invalidate platform summary after grant/revoke and global-account status changes affecting active grants. |
| UI-SYNC-03 | P1 / security overview | `lib/queryInvalidation.ts:215–237` does not include `dashboard-priority-findings`, `dashboard-operational-runs`, `portfolio-trend`, or `vulnerability-age`. Consumers: `PortfolioOverview.tsx:118–119`, `PortfolioTrend.tsx:11`, `VulnerabilityAgePie.tsx:94`. Analysis completion/product/lifecycle/delete helpers ultimately call this helper. Independent keys therefore remain fresh after successful local mutations. Trend defaults use summary data for 30 days; the defect applies to queried alternate ranges. | Complete shared dashboard dependencies, preserving filter variants and immutable historical snapshots. |
| UI-SYNC-04 | P1 / VEX metrics | `invalidateVexSurfaces` at `lib/queryInvalidation.ts:132–150` refreshes `dashboard-vex` but not `dashboard-summary`. The active home screen (`frontend/src/app/page.tsx:80`) renders VEX data embedded in summary; backend `dashboard_main.py:536–538,637` includes it. Decision saves (`VexDecisionEditor.tsx:164–168`), document upload/discovery (`SbomDetail.tsx:870–891`) can leave home VEX counts unchanged. | Add dashboard summary to VEX decision/import dependencies; distinguish assignment-only changes where counts do not change. |
| UI-SYNC-05 | P1 / investigation evidence | `SbomDetail.tsx:557` uses `vex-investigation-by-triple`. VEX helper invalidates `vex-investigation`, which is a different first array element and does not match this key. Some detail save callbacks manually refetch it (`SbomDetail.tsx:2175`), but import/discovery and other VEX save paths lack that callback. | Include resolve-by-triple cache in VEX invalidation; test import then reopen editor without reload. |
| UI-SYNC-06 | P1 / inventory relationships | SBOM edit/assignment (`SbomDetail.tsx:359–405`) uses `invalidateProjectAssignmentSurfaces` (`queryInvalidation.ts:91–108`). It updates SBOM detail/info, project lists/details and limited dashboard metrics, but omits `sboms`, `product-sboms`, logical SBOM caches, dashboard SBOM options and report target caches. Backend `sboms_crud.py` update route persists name/project/product/version changes. A main list, product detail or selector cached before the edit can display the old metadata or ownership. | Shared metadata/ownership mutation dependency covering old/new project and product IDs plus lists/options/targets. |
| UI-SYNC-07 | P2 / project metadata and metrics | `ProjectModal.tsx:71–93` creates/updates project including status but invalidates only project lists and SBOM lists. It does not invalidate `project`, `project-detail`, or dashboard summary/tiles. Details consumed by repair workspace can retain a prior project name; summary remains cached after project count/status changes. | Use project surface helper with ID and the applicable dashboard/target dependencies. |
| UI-SYNC-08 | P1 / SBOM history/inventory | Restore creates a **new revision** (`app/routers/sbom_versions.py:295–308`). `SbomDetail.tsx:812–818` only calls `invalidateSbomVersionSurfaces` (detail/components/versions of original ID) before navigating to restored ID. Existing SBOM/logical/product lists and upload choices are not invalidated by this path. | Treat restore success as version creation, using returned revision ownership for upload/inventory invalidation. |
| UI-SYNC-09 | P2 / canonical component evidence | `SbomDetail.tsx:450` has separate `sbom-components-canonical`. Lifecycle override/refresh helpers only invalidate `sbom-components` (`queryInvalidation.ts:127–130`). Likewise general SBOM invalidation does not match canonical key. Canonical selector data can retain old lifecycle evidence while the paginated table refreshes. | Consolidate key family or explicitly refresh canonical components when component metadata changes. |
| UI-SYNC-10 | P2 / schedule consistency | Card-level pause/resume/delete/exclude/inherit (`ScheduleCard.tsx:114–185`) invalidates `schedule` and `schedule-targets`, but not `schedules`. The main schedules page (`frontend/src/app/schedules/page.tsx:93`) uses `schedules`. Schedule editor updates both lists/detail, but omits preview `schedule-targets` (`ScheduleEditor.tsx:128–129`). | Shared schedule surface dependency for all schedule-changing entry points and target-preview changes. |
| UI-SYNC-11 | P1 / users, assignments and admin coverage | `UserLifecycle.tsx:97–103` successful profile/status/membership/role/security actions increment local revision only. `NativeUserInviteForm.tsx:35` invokes parent callback only; directory parents refresh local state. `TenantUsersAccess.tsx:82–167` refreshes members/audit but not `vex-assignees` or platform summary/detail. Backend tenant/native/platform routes change memberships and active administrator coverage; `/summary` derives membership/admin counts. Existing Query caches for those projections remain untouched. | Bridge local directory actions to shared user/membership dependencies. Keep local refetch if needed, notify cached projections, and re-resolve current auth when editing self. |
| UI-SYNC-12 | P1 / incomplete run results | `frontend/src/app/analysis/[id]/page.tsx:107–128` polls active `run` every 3s, but findings use independent `findings-enriched` with no polling or terminal-transition invalidation. No effect in that page ties a polled terminal status to findings refresh. A page opened while a scheduled run is active may keep its initial findings payload after run counts become final, unless an originating analysis stream elsewhere invalidates it. | Terminal-transition detection shared by polling and local completion paths; invalidate findings and derived caches once per run transition. |
| UI-SYNC-13 | P1 / scoped background status | Unfiltered `useSbomsList.ts:12–30` polls queued/running rows and refetches on focus. Scoped SBOM query `app/sboms/page.tsx:31–35` has neither. Local background-analysis catch (`useBackgroundAnalysis.ts:135–172`) updates only exact `['sboms']`; recovery (`usePendingAnalysisRecovery.ts:27–65`) likewise only patches exact list and removes the marker even for an active run. Scoped rows and sibling metrics can miss failure/completion updates. | Apply shared polling/terminal policy to scoped lists; reconcile recovery against server run state, retaining active tracking until terminal. |
| UI-SYNC-14 | P1 / AI fix completion | Global provider writes progress envelopes and unregisters on terminal (`AiBatchProgressProvider.tsx:144,177,307–319`), without invalidating `ai-fix-list`, per-finding `ai-fix`, or usage/trend caches (the cost screen independently polls at 60 seconds / five minutes). Trigger hooks invalidate fix lists immediately at enqueue (`useAiFix.ts:205–214,296–307`), before results arrive. `useRunAiFixList` has no interval; batches optionally poll, but that does not invalidate fixes. Banner cancel only invalidates progress (`GlobalAiBatchBanner.tsx:90–97`), unlike dedicated cancel hooks. | Central AI terminal/cancel callback updating progress and invalidating result/history/usage caches. Reuse existing transport; no new SSE or WebSocket. |
| UI-SYNC-15 | P2 / lifecycle configuration readiness | `LifecycleProviderSettings.tsx:37–92` invalidates only `lifecycle-providers` for config/secrets/test/reset/sync. `SbomDetail.tsx:325` caches `lifecycle-provider-status`, a separate projection from `/api/lifecycle/provider-status`. Immediate provider readiness/config changes can stay cached. Sync enqueue does not establish completion. Vendor-record CRUD only refreshes records; existing materialized component evidence may require explicit enrichment rather than mere client invalidation. | Invalidate provider-status for immediate config changes. Separately track existing job/sync completion if available; do not claim record edits instantly recalculate analysis evidence. |
| UI-SYNC-16 | P2 / report target choices | Report editor `ReportNotificationsPage.tsx:50` caches `['reports','targets',scope,search]`. Project/product creation and SBOM assignment/restore helpers do not invalidate it. `invalidateSbomLifecycle` refreshes `reports`, but also includes unused `report-notifications-targets`/`report-subscriptions` prefixes. Existing editor options can omit newly created or moved targets. | Explicit inventory-to-report-target dependency using actual `reports/targets` key. Keep immutable delivery artifacts separate. |
| UI-SYNC-17 | P3 / performance and maintainability | Nested helpers repeat dashboard invalidations: analysis completion calls run lists (which call version posture/dashboard), dashboard tiles again, then product surfaces (which repeat version posture/dashboard). Broad advisor-policy predicate invalidates every advisor family including cached tenant variants. These calls are source-confirmed; a network request storm is **not measured**, since React Query may deduplicate in-flight requests. | Assemble/deduplicate invalidation targets per event and return one awaitable completion promise; scope where resource identity is known. |

## Freshness risks distinct from mutation defects

- **Cross-user changes:** QueryClient is browser-local; another administrator's changes do not notify this client. Most dashboard/platform queries have no interval and focus refetch is globally disabled. This establishes absence of a refresh mechanism, not a live incident. Define a bounded freshness SLA, explicit refresh/dataUpdatedAt indicators and selective focus/reconnect or polling using existing query capabilities.
- **Scheduled/backend work:** schedule run-now success returns queued SBOM IDs, not final analysis results. Enqueue invalidation is correct but insufficient for eventual completion. The run-detail and unfiltered SBOM polling patterns are reusable; list/dashboard terminal detection should be consistent. Existing analysis streaming invalidates on complete/error in `useAnalysisStream.ts:257–279`; it covers its subscribed work, not every external job.
- **Provider synchronization:** `LifecycleProviderSettings` says queued and refreshes config immediately. Do not assert new enriched results until the backend sync/enrichment contract supplies completion evidence. Catalog refresh and materialized analysis are separate operations.
- **Auth changes:** server enforces authorization independently of cache freshness. Cached user permissions, candidate lists or admin labels can be stale after another session changes access; this audit does not demonstrate an API authorization bypass.
- **Out-of-order requests:** VEX filtered queries use filter/tenant-specific keys, `placeholderData: undefined`, and queryFn AbortSignal; old requests cannot populate the new key. Directory/search effects use cancellation booleans and scope remounts. Inspect long-lived analysis/AI callbacks across tenant switches in a regression test; a concrete cross-tenant stale write was not established here.

## Mutation-to-query dependency matrix

Keys below name prefixes unless a concrete suffix is shown. This matrix groups equivalent UI actions; Appendix B lists each hook's exact mutation function and success action, and Appendix C includes imperative paths.

| UI / actions | Frontend request and backend owner / response | Current synchronization | Required consumers / disposition |
|---|---|---|---|
| Platform tenant create, activate, disable | `lib/api.ts:660–680`; POST `/api/tenants` → `tenants.py:350`, creation response; PATCH `/api/platform/tenants/{id}` → `platform.py:809`, status response after commit | List page: platform-tenants only; detail page: platform-tenant, platform-tenants, platform-summary | Summary/list/detail/audit and membership projections; UI-SYNC-01 |
| Recover tenant admin, resend activation | POST recover-admin → `platform.py:257` commits and returns tenant/admin; native-auth resend returns delivery state | Detail recovery invalidates list/detail/summary. `PlatformTenantOverview.tsx:74–80` resend invalidates detail/users/audit | Recovery is good reuse pattern; delivery refresh policy separate |
| Grant/revoke platform admin | POST/DELETE administrators → `platform.py:544,599`; grant response or 204 | platform-administrators only | platform-summary and directory projections; UI-SYNC-02 |
| Native invite; profile/global status/unlock/force password/logout sessions; add/change roles/activate/deactivate/remove membership | `UserLifecycle` direct proxy fetch; `NativeUserInviteForm`; `TenantUsersAccess` API; `native_auth.py`, `platform.py`, `tenants.py` | local revision/callback, or tenant-users + tenant-audit-history | user directory/detail, auth if self, platform summary/detail, assignee options; UI-SYNC-11 |
| Project create/update/status/delete | `ProjectModal`, `ProjectsTable`; API POST/PATCH/DELETE projects → `projects.py:75,141,226`; resource or deletion result | Create/edit: project/SBOM lists. Delete: project/SBOM/run/schedule/dashboard helpers | project details, dashboard/targets; UI-SYNC-07,16. Delete is substantially covered but newer dashboard keys missing |
| Product create/edit/status/delete; AUTO/manual current selection | `ProductFormDialog`, `ProjectApplications`, product page, upload modal; `products.py` persists and returns product | product lists/detail, product/posture/dashboard helpers; pin updates additionally schedule targets/detail | Core selection invalidation already correct; shared dashboard omissions UI-SYNC-03 and reports UI-SYNC-16 remain |
| SBOM upload / repair import | `useSbomMutations`, upload modal, repair workspace; `sbom_upload.py`, `sbom_validation_sessions.py`; created SBOM/session | upload/product/SBOM/dashboard helpers and project detail | Good shared pattern; verify missing newer dashboard and reports keys |
| SBOM edit/assign/delete/activate/deactivate/archive | `SbomDetail`, `SbomsTable`, `SbomLifecycleControls`; `sboms_crud.py`; updated resource/deletion result | Edit/assign narrow helper; delete several surface helpers; lifecycle broad shared helper + returned detail | Edit/assign UI-SYNC-06; general dashboard omissions UI-SYNC-03 |
| SBOM restore / convert | restore POST → `sbom_versions.py:295`; new revision. Conversion POST → same router; conversion response | Restore original detail/components/versions. Convert deliberately narrow conversion detail/report invalidation; enrichment status query polls | Restore UI-SYNC-08. Conversion scope intentionally avoids unrelated VEX/risk recalculation; no blanket defect inferred |
| Revalidate / repair draft save, patch, validation, approve/reject | `useSbomMutations`, `ValidationRepairWorkspace`, `SbomAutoRepairPanel`, line editor; validation/repair routers | validation/detail caches updated or invalidated; repair history/content/quality refreshed; import refreshes inventory | Good result-based cache writes; tests should assert all actual session key families |
| Start analysis / stream / schedule run-now | analyze service endpoints, run APIs, schedules router; run result or queued IDs | stream/local success invoke analysis completion; schedule enqueue refreshes run/SBOM/dashboard | Terminal/failure and external completion gaps UI-SYNC-12,13; newer dashboard keys UI-SYNC-03 |
| Schedule create/update/pause/resume/delete/exclude/inherit | `ScheduleEditor`, `ScheduleCard`, schedules page; `schedules.py`; schedule or operation response | Editor list+detail; card detail+targets; page list+detail | UI-SYNC-10; completion must not be confused with enqueue |
| VEX decision/assignment/mapping/document import/discovery | `VexDecisionEditor`, `VexInvestigationPanel`, `SbomDetail`; `vex_investigations.py`, `vex.py`; refreshed detail/import counters | Shared VEX helper + some local onSaved callbacks | Summary and triple resolver UI-SYNC-04,05; existing filtered list/summary share prefix correctly |
| Remediation update | `FindingsTable.tsx:428`; `lib/api.ts:2833` POST `/api/remediation?project_id=...`; `remediation.py:97` returns record | Writes returned record, invalidates run/current run findings/dashboard tiles | Existing correct immediate path; shared dashboard omission affects newer projections. Do not falsely report absent remediation invalidation |
| AI credential CRUD/default/fallback/model select/settings/override/reset | `useAiCredentials`, `ScopedAiConfiguration`; AI credential/platform config routers | Shared credential/config/fix helpers, model list cache; returned settings cache | Good settings dependency pattern; standalone `ai-usage-trend`/`ai-top-cached` poll at 60 seconds / five minutes but lack immediate result-completion refresh |
| Generate/regenerate/cancel AI fixes and batches | `useAiFix`, global banner/provider; `ai_fixes.py`; fix envelope/progress | Single-fix cache writes + list invalidation; trigger/cancel hooks refresh lists; provider only progress | Terminal/global-cancel gaps UI-SYNC-14 |
| Lifecycle config/secrets/test/sync/reset; vendor CRUD/import; component override/refresh | settings/admin and SBOM detail; `lifecycle_admin.py`, `lifecycle.py`, SBOM versions; config/status/refresh response or 204 | config/record lists; component refresh updates table/lifecycle/health | UI-SYNC-09,15; materialized evidence needs backend refresh, not automatic claims |
| Advisor create/evaluate/decision; publish policy | advisor hooks/policies; component advisor router; recommendation/policy state | shared advisor helper; policy setQueryData + history + advisor predicate | Correct concurrency/version handling; broad invalidation efficiency UI-SYNC-17 |
| Report subscription create/update/enable/disable/delete/send-now | `useReportNotifications`, `lib/reportApi.ts`; report-notifications router; subscription or queued delivery | shared reports prefix; deliveries poll 15s | Good dependency/polling pattern; targets affected by inventory changes UI-SYNC-16 |
| KEV sync; Copilot regenerate/ask; export/download/preview/compare | KEV router updates catalog; Copilot returns briefing/answer; exports return immutable artifact/data | KEV catalog/options/detail invalidated; Copilot briefing replaced; read-only exports need no invalidation | Do not invalidate analysis findings merely because KEV catalog sync succeeds; dependent materialized outputs require documented recomputation |

## Query keys and isolation

Appendix A gives each query's consumer, exact key expression, fetch function and refresh overrides. Notable conventions:

- Platform keys are control-plane global; tenant headers are removed for `/api/platform/` in `lib/api.ts:347`. `platform-summary` conditionally returns administrator count based on permission, so a future key factory should include relevant principal/permission context or guarantee cache reset on every context change.
- Resource IDs often act as scope (`run`, `product`, `sbom`), but list/aggregate keys such as `projects`, `reports/config`, `dashboard-posture` rely on AuthProvider cache clearing. Prefer explicit tenant scoping consistently without breaking current prefix helpers.
- VEX list keys include tenant, filters, scope, page and page size. Summary uses tenant plus filterArgs, intentionally omitting pagination. `vex-assignees` includes tenant and debounced search with pageParam. These are correct patterns to reuse.
- Advisor keys include tenant, filters/sort/page; recommendation ID precedes tenant so the existing ID invalidation matches correctly. Avoid an incompatible key reorder without updating helper prefixes.
- Report subscriptions include optional tenant ID; delivery keys include all-tenant/status/delivery ID; tenant context currently relies on clearing. Target options include scope/search. Report filters are not omitted from those query keys.
- CVE details use `cveQueryKey(scanId,cveId,componentId)` and hover prefetch uses the same factory (`components/vulnerabilities/CveDetailDialog/hooks.ts:70`). Component identity prevents same-CVE contexts collapsing.
- `logical-sbom-versions` uses `[prefix, tenant, id]` in history but `[prefix, id]` in upload choices; both work independently but duplicate fetches and complicate targeted updates. Broad prefix invalidation currently reaches both.

## Local state, imperative requests and reloads

Appendix C records all direct API calls/fetches, including Next API proxy handlers. Appendix D inventories state and effects with locations. Server-backed local state requiring deliberate synchronization includes user directory rows/total/detail/revision, search candidates, tenant search choices, repair draft/session-derived content, selected investigation detail, component lifecycle messages, and analysis/AI tracking in sessionStorage/context. Form fields, dialog visibility and selection state are client-owned; query invalidation should not reset unsaved drafts indiscriminately.

`UserLifecycle` remounts on tenant scope and guards async list/detail responses with `current` cleanup. `TenantSearchSelect` and user candidate search guard canceled effects. These are useful race-control examples, though neither shares Query cache notifications. Repair editing uses row versions/conflict handling and explicit draft ownership; preserve that behavior in any cache migration.

Production search found **no `location.reload()`**. `frontend/src/app/access-pending/page.tsx:16` is the only `router.refresh()` call: it follows an explicit access recheck and is not a CRUD reload workaround. Login/logout use full navigation intentionally (`lib/api.ts:152`, `hooks/useAuth.tsx:524–548`, `lib/auth/logout-navigation.ts:3`); password lifecycle removes reset token from history. These should not be removed merely to eliminate navigation. `router.refresh()` does not itself invalidate TanStack caches.

## Existing correct implementations to reuse

1. `lib/queryInvalidation.ts` already centralizes entity surface dependencies; extend it instead of adding scattered router/page invalidation rules.
2. Tenant-detail status/recovery (`frontend/src/app/settings/platform/tenants/[tenantId]/page.tsx:29–40`) refreshes summary/list/detail together.
3. AuthProvider clears cache and gates tenant switching; role/principal-specific analysis-config keys in `AiConfigBanner` and `PortfolioOverview` protect contextual configuration.
4. VEX filtered summary/list keys, cancellation signals, conflict callbacks and returned assignment detail preserve filter consistency and optimistic concurrency.
5. Report prefix invalidation plus 15-second delivery polling correctly distinguishes subscription mutations from queued delivery completion.
6. Unfiltered SBOM and run-detail conditional polling stops when work is no longer active; reuse it for scoped/server-triggered work.
7. Lifecycle provider save updates the returned config row before invalidating; AI settings and single-fix writes similarly use authoritative responses.
8. Advisor mutations share a helper and policy publication updates policy/history with explicit conflict handling.

## Proposed shared architecture (no implementation in this audit)

Extend the established helper module with typed **domain events**, not a blanket `queryClient.invalidateQueries()` call:

- Tenant changed/created; administrator authority changed; membership/user changed; project/product changed; SBOM metadata/version/lifecycle changed; analysis queued/terminal; VEX evidence/decision/assignment changed; schedule changed; AI config/fix batch terminal; lifecycle config/enrichment terminal; report subscription/delivery changed.
- Carry relevant tenant, resource, old/new ownership and run IDs. Centralize query key factories while preserving established domain prefixes. Use normalized filters and distinct global/tenant/principal contexts where results differ.
- Build an explicit set of affected targets, deduplicate it, then return `Promise.all` so mutations can await active refresh when required. Preserve immutable run snapshots/report artifacts unless the server contract says they change.
- Write authoritative mutation responses into matching detail caches when safe; invalidate dependent lists/aggregates. Avoid in-place mutation of cached nested objects. Mutation failure should retain valid previous data but refresh server state if a failed analysis run was persisted.
- Feed existing stream/polling terminal transitions through the same domain event once per run/batch. Use bounded conditional polling and selective focus/reconnect for cross-user freshness. No new transport or dependencies are proposed.
- Imperative local-state directories can initially keep their current fetch/revision behavior while notifying shared dependencies; later migrate server-owned rows/detail to queries if worthwhile. Keep drafts and forms local.

## Test coverage and gaps

Existing tests inspected: `frontend/src/__tests__/mutation-invalidation.test.ts`; platform/dashboard/tenant settings page tests; `components/admin/UserLifecycle.test.tsx`; lifecycle settings tests; VEX page/editor/panel tests; upload/repair/lifecycle tests; report notifications tests; AI provider/progress tests; dashboard integration and manager-widget tests. No tests were run for this source audit.

The architectural mutation test recognizes the presence of an invalidation/cache-write token, not whether all consumers are covered. It therefore accepts tenant-list invalidation without summary invalidation and misses imperative `UserLifecycle` actions. Many tests use staleTime 0, fresh QueryClients, mocked helpers or isolated consumers, masking fresh-cache navigation bugs.

Required additions:

- Seed summary/list/detail caches with production five-minute staleTime; mutate tenant via both entry points; navigate back and assert new dashboard counts and detail status. Add platform grant/revoke and membership coverage tests.
- Use a real QueryClient and real shared helpers to assert every dependent dashboard key, including scoped ranges and newer untracked dashboard components. Do not settle for a mocked-helper-called assertion.
- Edit/move/restore SBOM then revisit cached inventory/product/logical/history/report selectors; verify old/new ownership and renamed labels.
- Open scheduled running run, return empty findings, then terminal findings; assert exactly one completion refresh. Repeat failed, canceled, recovery and scoped-list cases.
- Trigger AI batch with initially empty fixes, terminal progress then generated fixes; verify fixes/history/cost refresh and global cancel behavior.
- Cross-tenant switch with in-flight request/stream, logout/login with different permissions, out-of-order filter responses; assert no prior scope data appears. Do not label an untested race a confirmed leak.
- Card-level schedule mutation then cached schedules page; editor update then target preview. Lifecycle readiness and canonical component refresh tests.
- Query-count/refetch tests for duplicate helpers using recorded fetch counts rather than counting invalidate calls alone.

## Recommended implementation sequence

1. **Batch 1: platform control-plane correctness.** Add shared platform tenant/admin/user invalidation helpers; apply to list/detail and authority actions. Add real-cache navigation tests for UI-SYNC-01/02. Keep provider defaults unchanged in this first batch so missing dependencies are demonstrably fixed.
2. Complete dashboard dependency inventory, VEX summary/triple invalidation and targeted helper tests (03–05).
3. Repair project/SBOM metadata, ownership and restore dependencies, canonical lifecycle and report targets (06–09,16).
4. Unify schedule mutations and terminal run/failure/recovery synchronization (10,12,13).
5. Bridge user directory/membership actions and AI terminal/cancel synchronization (11,14).
6. Lifecycle readiness and measured deduplication (15,17); then adopt bounded cross-user freshness, tenant/principal key factories and regression coverage incrementally.

**Proposed first-batch files:** `frontend/src/lib/queryInvalidation.ts`; `frontend/src/app/settings/platform/tenants/page.tsx`; `frontend/src/app/settings/platform/tenants/[tenantId]/page.tsx`; `frontend/src/app/settings/platform/page.tsx`; corresponding `page.test.tsx` files; `frontend/src/app/platform/page.test.tsx`; a focused `frontend/src/lib/queryInvalidation.test.ts` (new). Backend changes are not needed for these confirmed client dependency gaps. `providers.tsx` comment correction can follow with the agreed freshness policy; no global default change is needed for Batch 1.

## Inventory appendices

All locations below are repository-relative. In key expressions, spread variables/key factories remain as implemented; their definitions are cited in the source inventory rather than inventing runtime values. Functions can serve multiple components via hooks; hook consumers are discoverable by symbol reference. Appendix E lists backend route ownership, prefixes, explicit response models/status and return lines to trace UI requests to server responses.

Inventory totals: useQuery = 162, useMutation = 87, useInfiniteQuery = 1; API/fetch call sites = 341; useState = 490; useEffect = 128.

### Appendix A — all query consumers

| Location | Hook / key | Query function | Explicit refresh / gating |
|---|---|---|---|
| `frontend/src/app/admin/ai-usage/page.tsx:17` | useQuery: `['analysis-config']` | `({ signal }) => getAnalysisConfig(signal)` | `staleTime=60_000` |
| `frontend/src/app/analysis/[id]/page.tsx:107` | useQuery: `['run', id]` | `({ signal }) => getRun(id, signal)` | `enabled=!isNaN(id); refetchInterval=(query) => { const status = String(query.state.data?.run_status ?? '').toUpperCase(); return ACTIVE_RUN_STATUSES.has(status) ? 3000 : false; }; refetchOnWindowFocus=true` |
| `frontend/src/app/analysis/[id]/page.tsx:118` | useQuery: `['findings-enriched', id, severityFilter]` | `({ signal }) => getAllEnrichedRunFindings(id, { severity: severityFilter \|\| undefined }, signal)` | `enabled=!isNaN(id)` |
| `frontend/src/app/analysis/[id]/page.tsx:132` | useQuery: `['analysis-config']` | `({ signal }) => getAnalysisConfig(signal)` | `staleTime=60_000` |
| `frontend/src/app/analysis/compare/_v1/page.tsx:43` | useQuery: `['compare-runs', runA, runB]` | `({ signal }) => compareRuns(runA as number, runB as number, signal)` | `enabled=canQuery` |
| `frontend/src/app/analysis/page.tsx:87` | useQuery: `['analysis-config']` | `({ signal }) => getAnalysisConfig(signal)` | `staleTime=60_000` |
| `frontend/src/app/analysis/page.tsx:93` | useQuery: `['projects']` | `({ signal }) => getProjects(signal)` | `QueryClient defaults` |
| `frontend/src/app/analysis/page.tsx:116` | useQuery: `['runs', { projectFilter, productFilter, sbomFilter, statusFilter }]` | `({ signal }) => getRuns( { project_id: projectFilter ? Number(projectFilter) : undefined, product_id: productFilter ? Number(productFilter) : undefined, sbom_id: sbomFilter ? Number(sbomFilter) : undefined, run_status: statusFilter \|\| undefined, page: 1, page_size: 100, }, signal, )` | `QueryClient defaults` |
| `frontend/src/app/analysis/page.tsx:137` | useQuery: `['runs-aggregate', { projectFilter, productFilter, sbomFilter }]` | `({ signal }) => getRunsAggregate( { project_id: projectFilter ? Number(projectFilter) : undefined, product_id: productFilter ? Number(productFilter) : undefined, sbom_id: sbomFilter ? Number(sbomFilter) : undefined, }, signal, )` | `QueryClient defaults` |
| `frontend/src/app/component-advisor/components/[key]/page.tsx:59` | useQuery: `['component-advisor-component', activeTenantId, canonicalKey, scope]` | `({ signal }) => getAdvisorComponent(canonicalKey, scope, signal)` | `enabled=canRead` |
| `frontend/src/app/component-advisor/page.tsx:176` | useQuery: `['component-advisor-summary', activeTenantId, params]` | `({ signal }) => getAdvisorSummary(params, signal)` | `enabled=canRead` |
| `frontend/src/app/component-advisor/page.tsx:181` | useQuery: `['component-advisor-components', activeTenantId, params, page, pageSize, filters.sortBy, filters.sortOrder]` | `({ signal }) => listAdvisorComponents({ ...params, sort_by: filters.sortBy, sort_order: filters.sortOrder, limit: pageSize, offset }, signal)` | `enabled=canRead; placeholderData=(previous, previousQuery) => (previousQuery?.queryKey[1] === activeTenantId ? previous : undefined)` |
| `frontend/src/app/component-advisor/recommendations/[id]/page.tsx:43` | useQuery: `['component-advisor-recommendation', recommendationId, activeTenantId]` | `({ signal }) => getAdvisorRecommendation(recommendationId, signal)` | `enabled=canRead && Number.isSafeInteger(recommendationId)` |
| `frontend/src/app/component-advisor/recommendations/[id]/page.tsx:244` | useQuery: `['component-advisor-candidate-evidence', recommendationId, candidate?.id, activeTenantId]` | `({ signal }) => getAdvisorCandidateEvidence(recommendationId, candidate!.id, signal)` | `enabled=candidate !== null` |
| `frontend/src/app/component-advisor/recommendations/[id]/page.tsx:249` | useQuery: `['component-advisor-candidate-evidence', recommendationId, candidate?.id, 'checks', activeTenantId]` | `({ signal }) => getAdvisorCandidateCompatibility(recommendationId, candidate!.id, signal)` | `enabled=candidate !== null` |
| `frontend/src/app/kev/page.tsx:206` | useQuery: `['kev-catalog', filters, page, pageSize]` | `({ signal }) => listKevVulnerabilities( { q: filters.search \|\| undefined, vendor: filters.vendor \|\| undefined, product: filters.product \|\| undefined, ransomware: filters.ransomware === 'all' ? undefined : filters.ransomware, date_added_from: filters.dateAddedFrom \|\| undefined, date_added_to: filters.dateAddedTo \|\| undefined, due_date_from: filters.dueDateFrom \|\| undefined, due_date_to: filters.dueDateTo \|\| undefined, catalog_version: filters.catalogVersion \|\| undefined, cwe: filters.cwe \|\| undefined, sort_by: filters.sortBy, sort_order: filters.sortOrder, limit: pageSize, offset, }, signal, )` | `enabled=dateRangeError === null; placeholderData=keepPreviousData` |
| `frontend/src/app/kev/page.tsx:232` | useQuery: `['kev-filter-options', filters.vendor]` | `({ signal }) => getKevFilterOptions({ vendor: filters.vendor \|\| undefined }, signal)` | `QueryClient defaults` |
| `frontend/src/app/kev/page.tsx:237` | useQuery: `['kev-detail', selectedCve]` | `({ signal }) => getKevVulnerability(selectedCve!, signal)` | `enabled=selectedCve !== null` |
| `frontend/src/app/page.tsx:80` | useQuery: `['dashboard-summary', ...scopeKey]` | `({ signal }) => getDashboardSummary(signal, scope)` | `enabled=!!tenantId; staleTime=60_000; refetchOnWindowFocus=false` |
| `frontend/src/app/page.tsx:91` | useQuery: `['top-vulnerable-runs', ...scopeKey]` | `({ signal }) => getDashboardRuns(scope, 'FINDINGS', 100, signal, true)` | `enabled=!!tenantId` |
| `frontend/src/app/platform/page.tsx:160` | useQuery: `['platform-summary']` | `getPlatformSummary` | `enabled=!isLoading && allowed` |
| `frontend/src/app/platform/page.tsx:165` | useQuery: `['platform-tenants', 'overview']` | `() => listPlatformTenants('', 1, 5)` | `enabled=!isLoading && allowed` |
| `frontend/src/app/products/[id]/page.tsx:109` | useQuery: `['product', id]` | `({ signal }) => getProduct(id, signal)` | `enabled=Number.isFinite(id)` |
| `frontend/src/app/products/[id]/page.tsx:115` | useQuery: `['product-sboms', id]` | `({ signal }) => getProductSboms(id, signal)` | `enabled=Number.isFinite(id)` |
| `frontend/src/app/products/[id]/page.tsx:121` | useQuery: `['logical-sboms', id, masterPage]` | `({ signal }) => getLogicalSboms(id, signal, masterPage)` | `enabled=Number.isFinite(id)` |
| `frontend/src/app/projects/page.tsx:34` | useQuery: `['projects']` | `({ signal }) => getProjects(signal)` | `QueryClient defaults` |
| `frontend/src/app/projects/page.tsx:35` | useQuery: `['dashboard-scanned-projects', projectId, applicationId, sbomId]` | `({ signal }) => getDashboardScannedProjectIds(scope, signal)` | `enabled=scanned` |
| `frontend/src/app/sboms/[id]/page.tsx:20` | useQuery: `['sbom', id]` | `({ signal }) => getSbom(id, signal)` | `enabled=!isNaN(id)` |
| `frontend/src/app/sboms/page.tsx:31` | useQuery: `['sboms', 'dashboard-scope', projectId, applicationId, sbomId, analysed]` | `({ signal }) => getSboms(1, 500, signal, scope, analysed)` | `enabled=isScoped` |
| `frontend/src/app/schedules/page.tsx:93` | useQuery: `['schedules', { scope, enabled }]` | `({ signal }) => listSchedules( { scope: scope === 'all' ? undefined : scope, enabled: enabled === 'all' ? undefined : enabled === 'enabled', }, signal, )` | `QueryClient defaults` |
| `frontend/src/app/schedules/page.tsx:107` | useQuery: `['projects']` | `({ signal }) => getProjects(signal)` | `QueryClient defaults` |
| `frontend/src/app/schedules/page.tsx:112` | useQuery: `['sboms', 'for-schedules']` | `({ signal }) => getSboms(1, 500, signal)` | `QueryClient defaults` |
| `frontend/src/app/schedules/page.tsx:220` | useQuery: `['schedule-targets', previewing?.id]` | `({ signal }) => previewScheduleTargets(previewing!.id, signal)` | `enabled=previewing != null` |
| `frontend/src/app/settings/platform/page.tsx:33` | useQuery: `['platform-administrators']` | `getPlatformAdministrators` | `enabled=!authLoading && canRead` |
| `frontend/src/app/settings/platform/tenants/[tenantId]/page.tsx:28` | useQuery: `['platform-tenant', id]` | `() => getPlatformTenant(id)` | `enabled=!isLoading && canRead && valid` |
| `frontend/src/app/settings/platform/tenants/page.tsx:112` | useQuery: `['platform-tenants', tenantSearch, tenantPage]` | `() => listPlatformTenants(tenantSearch, tenantPage)` | `enabled=!authLoading && canRead` |
| `frontend/src/app/settings/users/audit/page.tsx:21` | useQuery: `['tenant-audit-history', tenantId, filters]` | `() => getTenantAuditPage(tenantId, filters)` | `enabled=!isLoading && allowed` |
| `frontend/src/app/vex-investigation/page.tsx:280` | useQuery: `['dashboard-vex', activeTenantId]` | `({ signal }) => getDashboardVex(signal)` | `enabled=canRead` |
| `frontend/src/app/vex-investigation/page.tsx:306` | useQuery: `['vex-investigations', activeTenantId, 'summary', filterArgs]` | `({ signal }) => getVexInvestigationSummary(filterArgs, signal)` | `enabled=canRead; placeholderData=undefined` |
| `frontend/src/app/vex-investigation/page.tsx:313` | useQuery: `['vex-investigations', activeTenantId, filters, scope, page, pageSize]` | `({ signal }) => listVexInvestigations( { ...filterArgs, sort_by: filters.sortBy, sort_order: filters.sortOrder, limit: pageSize, offset }, signal, )` | `enabled=canRead; placeholderData=(previous, previousQuery) => previousQuery?.queryKey[1] === activeTenantId && JSON.stringify(previousQuery.queryKey[2]) === JSON.stringify(filters) && JSON.stringify(previousQuery.queryKey[3]) === JSON.stringify(scope) ? previous : undefined` |
| `frontend/src/app/vex-investigation/page.tsx:324` | useInfiniteQuery: `['vex-assignees', activeTenantId, debouncedAssigneeSearch]` | `({ pageParam, signal }) => searchVexAssignees(debouncedAssigneeSearch, pageParam, signal)` | `enabled=canRead; initialPageParam=0; getNextPageParam=last => last.offset + last.items.length < last.total ? last.offset + last.limit : undefined` |
| `frontend/src/components/admin/LifecycleProviderSettings.tsx:31` | useQuery: `['lifecycle-providers', scopeKey]` | `({ signal }) => listLifecycleProviders(signal, scope)` | `staleTime=30_000` |
| `frontend/src/components/admin/LifecycleVendorRecordsPage.tsx:40` | useQuery: `['lifecycle-vendor-records', search]` | `({ signal }) => listLifecycleVendorRecords({ search: search \|\| undefined, limit: 100 }, signal)` | `staleTime=30_000` |
| `frontend/src/components/admin/ScopedAdvisorPolicies.tsx:34` | useQuery: `['advisor-policy-history', tenantId, definition.kind]` | `() => getAdvisorPolicyHistory(tenantId, definition.kind)` | `QueryClient defaults` |
| `frontend/src/components/admin/ScopedAdvisorPolicies.tsx:76` | useQuery: `['advisor-policy', tenantId, definition.kind]` | `() => getAdvisorPolicy(tenantId, definition.kind)` | `QueryClient defaults` |
| `frontend/src/components/admin/TenantAuditHistory.tsx:9` | useQuery: `['tenant-audit-history', tenantId]` | `() => getTenantAuditHistory(tenantId)` | `enabled=tenantId > 0` |
| `frontend/src/components/admin/TenantUsersAccess.tsx:59` | useQuery: `['tenant-users', currentTenantId]` | `() => (currentTenantId ? getTenantMembers(currentTenantId) : Promise.resolve([]))` | `enabled=!(authLoading \|\| isTenantContextLoading) && canRead && currentTenantId !== null` |
| `frontend/src/components/admin/TenantUsersAccess.tsx:65` | useQuery: `['tenant-roles', currentTenantId]` | `() => getAssignableTenantRoles(currentTenantId ?? undefined)` | `enabled=!(authLoading \|\| isTenantContextLoading) && canRead` |
| `frontend/src/components/ai-fixes/GlobalAiBatchProgress/GlobalAiBatchBanner.tsx:63` | useQuery: `queryKey` | `({ signal }) => { if (batchId == null) return getRunAiFixProgress(runId, signal); return getRunAiBatch(runId, batchId, signal).then( (detail) => detail.progress ?? null, ); }` | `QueryClient defaults` |
| `frontend/src/components/ai-fixes/GlobalAiBatchProgress/useGlobalAiBatchProgress.ts:64` | useQuery: `batchProgressQueryKey(runId ?? -1, batchId)` | `({ signal }) => { if (batchId == null) { return getRunAiFixProgress(runId as number, signal); } return getRunAiBatch(runId as number, batchId, signal).then( (detail) => detail.progress ?? null, ); }` | `enabled=active` |
| `frontend/src/components/ai-fixes/Settings/CostDashboard.tsx:33` | useQuery: `['ai-usage-trend', 30]` | `({ signal }) => getAiUsageTrend({ days: 30 }, signal)` | `refetchInterval=60_000` |
| `frontend/src/components/ai-fixes/Settings/CostDashboard.tsx:39` | useQuery: `['ai-top-cached', 20]` | `({ signal }) => getAiTopCachedFixes({ limit: 20 }, signal)` | `refetchInterval=5 * 60_000` |
| `frontend/src/components/analysis/SbomPreflightChecklist.tsx:79` | useQuery: `['sbom-info', sbomId]` | `({ signal }) => getSbomInfo(sbomId as number, signal)` | `enabled=enabled; staleTime=60_000` |
| `frontend/src/components/analysis/VulnerabilitiesByScope.tsx:110` | useQuery: `['vulnerabilities', { severity, scope }]` | `({ signal }) => getVulnerabilities({ severity: severity \|\| undefined, page_size: 2000 }, signal, scope)` | `QueryClient defaults` |
| `frontend/src/components/compare/CompareView.tsx:48` | useQuery: `['compare', 'v2', urlState.runA, urlState.runB]` | `({ signal }) => compareRunsV2( { run_a_id: urlState.runA as number, run_b_id: urlState.runB as number }, signal, )` | `enabled=canQuery; staleTime=10 * 60 * 1000` |
| `frontend/src/components/compare/SelectionBar/RunPicker.tsx:79` | useQuery: `['compare', 'picker', 'recent']` | `({ signal }) => recentRuns(20, signal)` | `enabled=open && debounced === ''; staleTime=5 * 60 * 1000` |
| `frontend/src/components/compare/SelectionBar/RunPicker.tsx:85` | useQuery: `['compare', 'picker', 'search', debounced]` | `({ signal }) => searchRuns(debounced, 20, signal)` | `enabled=open && debounced !== ''; staleTime=5 * 60 * 1000` |
| `frontend/src/components/compare/Sparkline/Sparkline.tsx:48` | useQuery: `['compare', 'sparkline', sbomId]` | `({ signal }) => getRuns({ sbom_id: sbomId as number, page_size: 30 }, signal)` | `enabled=sbomId != null; staleTime=5 * 60 * 1000` |
| `frontend/src/components/dashboard/ActivityFeed.tsx:79` | useQuery: `['recent-sboms', tenantId, scope?.projectId, scope?.applicationId, scope?.sbomId]` | `({ signal }) => getRecentSboms(8, signal, scope)` | `QueryClient defaults` |
| `frontend/src/components/dashboard/ActivityFeed.tsx:84` | useQuery: `['recent-runs', tenantId, scope?.projectId, scope?.applicationId, scope?.sbomId]` | `({ signal }) => getDashboardRuns(scope ?? { projectId: null, applicationId: null, sbomId: null }, undefined, 12, signal)` | `QueryClient defaults` |
| `frontend/src/components/dashboard/AiConfigBanner.tsx:39` | useQuery: `['analysis-config', isPlatformContext ? 'platform' : activeTenantId, user?.userId ?? 'anonymous', [...(user?.permissions ?? [])].sort().join(',')]` | `({ signal }) => getAnalysisConfig(signal)` | `enabled=!authLoading; staleTime=30_000; refetchInterval=60_000` |
| `frontend/src/components/dashboard/CounterTiles.tsx:40` | useQuery: `['dashboard-posture']` | `({ signal }) => getDashboardPosture(signal)` | `enabled=!hasProps` |
| `frontend/src/components/dashboard/DashboardFilters.tsx:42` | useQuery: `['dashboard-projects', tenantId]` | `({ signal }) => getDashboardProjectOptions(signal)` | `enabled=!!tenantId` |
| `frontend/src/components/dashboard/DashboardFilters.tsx:47` | useQuery: `['dashboard-applications', tenantId, scope.projectId]` | `({ signal }) => getDashboardApplicationOptions(scope.projectId!, signal)` | `enabled=!!tenantId && scope.projectId != null` |
| `frontend/src/components/dashboard/DashboardFilters.tsx:52` | useQuery: `['dashboard-sboms', tenantId, scope.projectId, scope.applicationId, historicalVersions]` | `({ signal }) => historicalVersions ? getVexInvestigationVersions(scope, signal) : getDashboardSbomOptions(scope, signal)` | `enabled=!!tenantId && scope.projectId != null && scope.applicationId != null` |
| `frontend/src/components/dashboard/LifecycleHealthTiles.tsx:29` | useQuery: `['dashboard-lifecycle']` | `({ signal }) => getDashboardLifecycle(signal)` | `enabled=!hasProps` |
| `frontend/src/components/dashboard/LifecycleHealthTiles.tsx:35` | useQuery: `['dashboard-health']` | `({ signal }) => getDashboardHealth(signal)` | `enabled=!hasProps` |
| `frontend/src/components/dashboard/LifecycleHealthTiles.tsx:41` | useQuery: `['dashboard-vex']` | `({ signal }) => getDashboardVex(signal)` | `enabled=!hasProps` |
| `frontend/src/components/dashboard/PortfolioOverview.tsx:115` | useQuery: `["analysis-config", isPlatformContext ? "platform" : tenantId, user?.userId ?? "anonymous", [...(user?.permissions ?? [])].sort().join(",")]` | `({ signal }) => getAnalysisConfig(signal)` | `enabled=!!tenantId && hasPermission("analysis:read"); staleTime=30_000` |
| `frontend/src/components/dashboard/PortfolioOverview.tsx:118` | useQuery: `['dashboard-priority-findings', ...keys]` | `({ signal }) => getDashboardPriorityFindings(scope, signal)` | `enabled=!!tenantId && hasPermission('analysis:read')` |
| `frontend/src/components/dashboard/PortfolioOverview.tsx:119` | useQuery: `['dashboard-operational-runs', ...keys]` | `({ signal }) => getDashboardRuns(scope, undefined, 5, signal)` | `enabled=!!tenantId && hasPermission('analysis:read')` |
| `frontend/src/components/dashboard/PortfolioTrend.tsx:11` | useQuery: `['portfolio-trend', tenantId, scope.projectId, scope.applicationId, scope.sbomId, days]` | `({ signal }) => getDashboardTrend(days, signal, scope)` | `enabled=!!tenantId && days !== 30` |
| `frontend/src/components/dashboard/TopVulnerableSboms.tsx:29` | useQuery: `['top-vulnerable-runs', tenantId, scope?.projectId, scope?.applicationId, scope?.sbomId]` | `({ signal }) => getDashboardRuns(scope ?? { projectId: null, applicationId: null, sbomId: null }, 'FINDINGS', 100, signal, true)` | `QueryClient defaults` |
| `frontend/src/components/dashboard/TrendExplorer.tsx:81` | useQuery: `['projects', tenantId]` | `({ signal }) => getProjects(signal)` | `QueryClient defaults` |
| `frontend/src/components/dashboard/TrendExplorer.tsx:87` | useQuery: `['trend-explorer', tenantId, scope?.projectId, scope?.applicationId, scope?.sbomId, granularity, [...selectedApps].sort((a, b) => a - b)]` | `({ signal }) => { const opts = { granularity, applicationIds: selectedApps.length ? selectedApps : undefined }; return scope ? getDashboardTrendFiltered(opts, signal, scope) : getDashboardTrendFiltered(opts, signal); }` | `QueryClient defaults` |
| `frontend/src/components/dashboard/VulnerabilityAgePie.tsx:94` | useQuery: `['vulnerability-age', scope?.projectId, scope?.applicationId, scope?.sbomId, period, custom ? from : '', custom ? to : '']` | `({ signal }) => { const opts = custom ? { period, from: from \|\| undefined, to: to \|\| undefined } : { period }; return scope ? getVulnerabilityAge(opts, signal, scope) : getVulnerabilityAge(opts, signal); }` | `enabled=!hasProps` |
| `frontend/src/components/dashboard/advanced/CopilotPanel.tsx:86` | useQuery: `['copilot-briefing']` | `({ signal }) => getCopilotBriefing(false, signal)` | `enabled=enabled; staleTime=5 * 60_000` |
| `frontend/src/components/dashboard/advanced/ExploitationOutlookCard.tsx:85` | useQuery: `['dashboard-exploitation']` | `({ signal }) => getDashboardExploitation(signal)` | `enabled=!hasProps` |
| `frontend/src/components/dashboard/advanced/ForecastCard.tsx:93` | useQuery: `['dashboard-forecast']` | `({ signal }) => getDashboardForecast(signal)` | `enabled=!hasProps` |
| `frontend/src/components/dashboard/advanced/PortfolioRiskMap.tsx:122` | useQuery: `['dashboard-risk-map']` | `({ signal }) => getDashboardRiskMap(signal)` | `enabled=!hasProps` |
| `frontend/src/components/dashboard/advanced/RemediationPanel.tsx:48` | useQuery: `['dashboard-remediation']` | `({ signal }) => getDashboardRemediation(signal)` | `enabled=!hasProps` |
| `frontend/src/components/dashboard/advanced/RemediationPanel.tsx:53` | useQuery: `['dashboard-remediation-stats']` | `({ signal }) => getDashboardRemediationStats(signal)` | `enabled=!hasProps` |
| `frontend/src/components/dashboard/advanced/RiskMatrixCard.tsx:97` | useQuery: `['dashboard-risk-matrix']` | `({ signal }) => getDashboardRiskMatrix(300, signal)` | `enabled=!hasProps` |
| `frontend/src/components/layout/CommandPalette.tsx:108` | useQuery: `['palette-recent-sboms', activeTenantId]` | `({ signal }) => getRecentSboms(8, signal)` | `enabled=isOpen && canSboms && Boolean(activeTenantId); staleTime=30_000` |
| `frontend/src/components/layout/CommandPalette.tsx:115` | useQuery: `['palette-recent-runs', activeTenantId]` | `({ signal }) => getRuns({ page: 1, page_size: 8 }, signal)` | `enabled=isOpen && canRuns && Boolean(activeTenantId); staleTime=30_000` |
| `frontend/src/components/layout/Sidebar.tsx:532` | useQuery: `['sidebar-recent-sboms', activeTenantId]` | `({ signal }) => getRecentSboms(3, signal)` | `enabled=canSboms && Boolean(activeTenantId); staleTime=60_000` |
| `frontend/src/components/layout/Sidebar.tsx:539` | useQuery: `['sidebar-recent-runs', activeTenantId]` | `({ signal }) => getRuns({ page: 1, page_size: 3 }, signal)` | `enabled=canRuns && Boolean(activeTenantId); staleTime=60_000` |
| `frontend/src/components/layout/SidebarStatus.tsx:62` | useQuery: `['health-poll']` | `({ signal }) => getHealth(signal)` | `staleTime=5_000; refetchInterval=30_000` |
| `frontend/src/components/projects/ProjectApplications.tsx:30` | useQuery: `['schedule', 'PRODUCT', productId]` | `({ signal }) => getEffectiveProductSchedule(productId, signal)` | `enabled=canRead` |
| `frontend/src/components/projects/ProjectApplications.tsx:61` | useQuery: `['products', project.id]` | `({ signal }) => getProducts(project.id, signal)` | `QueryClient defaults` |
| `frontend/src/components/projects/ProjectsTable.tsx:76` | useQuery: `['products', project.id]` | `({ signal }) => getProducts(project.id, signal)` | `enabled=false` |
| `frontend/src/components/projects/ProjectsTable.tsx:147` | useQuery: `['project-delete-impact', deleteTarget?.id]` | `({ signal }) => getProjectDeleteImpact(deleteTarget!.id, signal)` | `enabled=deleteTarget !== null; staleTime=0` |
| `frontend/src/components/reports/ReportNotificationsPage.tsx:30` | useQuery: `['schedule', 'TENANT', tenantId]` | `() => getTenantSchedule(tenantId)` | `QueryClient defaults` |
| `frontend/src/components/reports/ReportNotificationsPage.tsx:50` | useQuery: `['reports', 'targets', form.scope, search]` | `() => getReportTargets(form.scope, search)` | `enabled=form.scope !== 'TENANT'` |
| `frontend/src/components/sboms/ComponentVexManager.tsx:17` | useQuery: `['component-vulnerabilities', sbomId, component.id]` | `({ signal }) => getComponentVulnerabilities(sbomId, component.id, signal)` | `QueryClient defaults` |
| `frontend/src/components/sboms/ComponentVexManager.tsx:21` | useQuery: `['vex-pair-history', sbomId, component.id, historyPair]` | `({ signal }) => getVexOverrideHistory(component.id, historyPair!, signal, sbomId)` | `enabled=Boolean(historyPair)` |
| `frontend/src/components/sboms/LogicalSbomHistory.tsx:31` | useQuery: `['logical-sbom', activeTenantId, id]` | `({ signal }) => getLogicalSbom(id, signal)` | `QueryClient defaults` |
| `frontend/src/components/sboms/LogicalSbomHistory.tsx:32` | useQuery: `['logical-sbom-versions', activeTenantId, id]` | `({ signal }) => getLogicalSbomVersions(id, signal)` | `QueryClient defaults` |
| `frontend/src/components/sboms/SbomAutoRepairPanel.tsx:26` | useQuery: `['sbom-auto-repair-analysis', sessionId]` | `({ signal }) => analyzeSbomRepair(sessionId, signal)` | `QueryClient defaults` |
| `frontend/src/components/sboms/SbomAutoRepairPanel.tsx:27` | useQuery: `['sbom-auto-repair-job', sessionId]` | `({ signal }) => getLatestSbomRepair(sessionId, signal)` | `QueryClient defaults` |
| `frontend/src/components/sboms/SbomConversionCard.tsx:61` | useQuery: `['sbom-conversion-report', sbom.id]` | `() => getSbomConversionReport(sbom.id)` | `enabled=isSpdx && Boolean(conversionStatus \|\| convertedId)` |
| `frontend/src/components/sboms/SbomConversionCard.tsx:67` | useQuery: `['sbom-enrichment-status', sbom.id]` | `() => getSbom(sbom.id)` | `enabled=isSpdx && (enrichmentStatus === 'pending' \|\| enrichmentStatus === 'running'); refetchInterval=(query) => { const status = query.state.data?.enrichment_status; if (status === 'pending' \|\| status === 'running') { return 3000; } return false; }` |
| `frontend/src/components/sboms/SbomDetail.tsx:325` | useQuery: `['lifecycle-provider-status']` | `({ signal }) => getLifecycleProviderStatus(signal)` | `staleTime=60_000` |
| `frontend/src/components/sboms/SbomDetail.tsx:333` | useQuery: `['projects']` | `({ signal }) => getProjects(signal)` | `QueryClient defaults` |
| `frontend/src/components/sboms/SbomDetail.tsx:338` | useQuery: `['products', selectedProjectId]` | `({ signal }) => getProducts(selectedProjectId!, signal)` | `enabled=Boolean(selectedProjectId)` |
| `frontend/src/components/sboms/SbomDetail.tsx:344` | useQuery: `['products', detailProjectId]` | `({ signal }) => getProducts(detailProjectId!, signal)` | `enabled=Boolean(detailProjectId)` |
| `frontend/src/components/sboms/SbomDetail.tsx:427` | useQuery: `[ 'sbom-components', sbom.id, showDuplicates, componentPage, componentPageSize, debouncedComponentSearch, compSortKey, compSortDirection, ]` | `({ signal }) => getSbomComponents(sbom.id, { includeDuplicates: showDuplicates, page: componentPage, pageSize: componentPageSize, search: debouncedComponentSearch \|\| undefined, sortBy: compSortKey, sortOrder: compSortDirection, signal, })` | `QueryClient defaults` |
| `frontend/src/components/sboms/SbomDetail.tsx:450` | useQuery: `['sbom-components-canonical', sbom.id]` | `({ signal }) => getSbomComponents(sbom.id, { includeDuplicates: false, page: 1, pageSize: 1000, signal, })` | `staleTime=60_000` |
| `frontend/src/components/sboms/SbomDetail.tsx:470` | useQuery: `['sbom-dedupe-report', sbom.id]` | `({ signal }) => getSbomDedupeReport(sbom.id, signal)` | `QueryClient defaults` |
| `frontend/src/components/sboms/SbomDetail.tsx:476` | useQuery: `['runs', { sbom_id: sbom.id }]` | `({ signal }) => getRuns({ sbom_id: sbom.id }, signal)` | `refetchInterval=state.phase === 'done' ? false : undefined` |
| `frontend/src/components/sboms/SbomDetail.tsx:483` | useQuery: `['sbom-info', sbom.id]` | `({ signal }) => getSbomInfo(sbom.id, signal)` | `QueryClient defaults` |
| `frontend/src/components/sboms/SbomDetail.tsx:489` | useQuery: `['sbom-stats', sbom.id]` | `({ signal }) => getSbomStats(sbom.id, signal)` | `QueryClient defaults` |
| `frontend/src/components/sboms/SbomDetail.tsx:495` | useQuery: `['sbom-validation-report', sbom.id]` | `({ signal }) => getSbomValidationReport(sbom.id, signal)` | `QueryClient defaults` |
| `frontend/src/components/sboms/SbomDetail.tsx:505` | useQuery: `['sbom-vex', sbom.id]` | `({ signal }) => getSbomVexStatements(sbom.id, signal)` | `QueryClient defaults` |
| `frontend/src/components/sboms/SbomDetail.tsx:512` | useQuery: `['sbom-risk', sbom.id, runs?.[0]?.id ?? null]` | `({ signal }) => getSbomRiskSummary(sbom.id, signal)` | `enabled=!!runs && runs.length > 0` |
| `frontend/src/components/sboms/SbomDetail.tsx:520` | useQuery: `['sbom-versions', sbom.id]` | `({ signal }) => getSbomVersions(sbom.id, signal)` | `QueryClient defaults` |
| `frontend/src/components/sboms/SbomDetail.tsx:557` | useQuery: `['vex-investigation-by-triple', sbom.id, vexOverrideComponentId, vexOverrideVulnerability]` | `({ signal }) => getVexInvestigationByTriple( { sbom_id: sbom.id, component_id: Number(vexOverrideComponentId), vulnerability_id: vexOverrideVulnerability, }, signal, )` | `enabled=isVexOverrideOpen && Boolean(vexOverrideComponentId) && Boolean(vexOverrideVulnerability)` |
| `frontend/src/components/sboms/SbomDetail.tsx:571` | useQuery: `['component-vulnerabilities', sbom.id, Number(vexOverrideComponentId)]` | `({ signal }) => getComponentVulnerabilities(sbom.id, Number(vexOverrideComponentId), signal)` | `enabled=isVexOverrideOpen && Boolean(vexOverrideComponentId)` |
| `frontend/src/components/sboms/SbomLifecycleControls.tsx:35` | useQuery: `['sbom-lifecycle-history', sbom.id]` | `({ signal }) => getSbomLifecycleHistory(sbom.id, signal)` | `enabled=showHistory && historyOpen` |
| `frontend/src/components/sboms/SbomPostureNotice.tsx:34` | useQuery: `['sbom-posture', activeTenantId, scope.projectId, scope.applicationId, scope.sbomId]` | `({signal}) => getDashboardPostureVersions(scope, signal)` | `enabled=!!activeTenantId; refetchInterval=15000` |
| `frontend/src/components/sboms/SbomQualityPanel.tsx:53` | useQuery: `['sbom-quality', sessionId ? 'session' : 'sbom', sessionId ?? sbomId]` | `({ signal }) => sessionId ? getSessionQuality(sessionId, signal) : getSbomQuality(sbomId!, signal)` | `enabled=Boolean(sessionId \|\| sbomId)` |
| `frontend/src/components/sboms/SbomRawViewer.tsx:33` | useQuery: `['sbom-raw', sbomId, offset, RAW_PAGE_SIZE]` | `({ signal }) => getSbomRawChunk(sbomId, offset, RAW_PAGE_SIZE, signal)` | `QueryClient defaults` |
| `frontend/src/components/sboms/SbomUploadModal.tsx:143` | useQuery: `['projects']` | `({ signal }) => getProjects(signal)` | `enabled=open` |
| `frontend/src/components/sboms/SbomUploadModal.tsx:150` | useQuery: `['sbom-types']` | `({ signal }) => getSbomTypes(signal)` | `enabled=open` |
| `frontend/src/components/sboms/SbomUploadModal.tsx:178` | useQuery: `['logical-sboms', selectedProductId, 'choices']` | `({ signal }) => getLogicalSbomChoices(Number(selectedProductId), signal)` | `enabled=open && Boolean(selectedProductId)` |
| `frontend/src/components/sboms/SbomUploadModal.tsx:179` | useQuery: `['logical-sbom-versions', selectedLogicalSbomId]` | `({ signal }) => getLogicalSbomVersions(Number(selectedLogicalSbomId), signal)` | `enabled=open && Boolean(selectedLogicalSbomId)` |
| `frontend/src/components/sboms/SbomUploadModal.tsx:197` | useQuery: `['products', selectedProjectNumber]` | `({ signal }) => getProducts(selectedProjectNumber!, signal)` | `enabled=open && Boolean(selectedProjectNumber)` |
| `frontend/src/components/sboms/SbomsTable.tsx:132` | useQuery: `['sbom-delete-impact', deleteTarget?.id]` | `({ signal }) => getSbomDeleteImpact(deleteTarget!.id, signal)` | `enabled=deleteTarget !== null; staleTime=0` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:97` | useQuery: `['validation-repair-session', sessionId]` | `({ signal }) => getValidationSession(sessionId, signal)` | `QueryClient defaults` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:102` | useQuery: `['sbom-auto-repair-analysis', sessionId]` | `({ signal }) => analyzeSbomRepair(sessionId, signal)` | `enabled=Boolean(sessionQuery.data && sessionQuery.data.validation_status !== 'security_blocked')` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:103` | useQuery: `['sbom-auto-repair-job', sessionId]` | `({ signal }) => getLatestSbomRepair(sessionId, signal)` | `enabled=Boolean(sessionQuery.data && sessionQuery.data.validation_status !== 'security_blocked')` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:106` | useQuery: `['validation-repair-content', sessionId, 0, CONTENT_CHUNK_SIZE]` | `({ signal }) => getValidationSessionContent(sessionId, 0, CONTENT_CHUNK_SIZE, signal)` | `enabled=sessionQuery.data?.full_editor_allowed !== false` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:112` | useQuery: `['validation-repair-history', sessionId]` | `({ signal }) => getValidationSessionHistory(sessionId, signal)` | `QueryClient defaults` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:117` | useQuery: `['project', sessionQuery.data?.project_id]` | `({ signal }) => getProject(sessionQuery.data!.project_id!, signal)` | `enabled=sessionQuery.data?.project_id != null` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:123` | useQuery: `['projects']` | `({ signal }) => getProjects(signal)` | `QueryClient defaults` |
| `frontend/src/components/sboms/repair/LargeFileRepairEditor.tsx:51` | useQuery: `['validation-repair-lines', sessionId, startLine, pageSize]` | `({ signal }) => getValidationSessionContentLines(sessionId, startLine, pageSize, signal)` | `QueryClient defaults` |
| `frontend/src/components/sboms/repair/LargeFileRepairEditor.tsx:56` | useQuery: `['validation-repair-search', sessionId, query]` | `({ signal }) => searchValidationSession(sessionId, query, 'repair_draft', 100, signal)` | `enabled=canSearch && query.trim().length > 0` |
| `frontend/src/components/sboms/repair/RepairQualitySummary.tsx:10` | useQuery: `['sbom-quality', 'session', sessionId]` | `({ signal }) => getSessionQuality(sessionId, signal)` | `QueryClient defaults` |
| `frontend/src/components/schedules/ScheduleCard.tsx:93` | useQuery: `queryKey` | `({ signal }) => scope === 'PROJECT' ? getProjectSchedule(targetId, signal).then((s) => ({ inherited: false, schedule: s, state: s.enabled ? 'CUSTOM' : 'PAUSED', source_scope: 'PROJECT', resolution_reason: s.enabled ? 'custom' : 'paused', included: s.enabled, })) : scope === 'PRODUCT' ? getEffectiveProductSchedule(targetId, signal) : getSbomSchedule(targetId, signal)` | `QueryClient defaults` |
| `frontend/src/components/schedules/ScheduleCard.tsx:198` | useQuery: `['schedule-targets', scheduleId]` | `({ signal }) => previewScheduleTargets(scheduleId!, signal)` | `enabled=scheduleId != null` |
| `frontend/src/components/settings/ai/ScopedAiConfiguration.tsx:31` | useQuery: `['ai', 'effective-config', key]` | `({ signal }) => getEffectiveAiConfiguration(scope, signal)` | `enabled=!isLoading && allowed` |
| `frontend/src/components/vex/VexInvestigationDialog.tsx:28` | useQuery: `['vex-investigation', row?.id ?? null]` | `({ signal }) => getVexInvestigation(row!.id, signal)` | `enabled=row !== null` |
| `frontend/src/components/vex/VexRunHistoryPanel.tsx:15` | useQuery: `['vex-run-history', activeTenantId, sbomId]` | `({signal}) => getVexAnalysisRuns(sbomId, signal)` | `enabled=!!activeTenantId` |
| `frontend/src/components/vex/VexRunHistoryPanel.tsx:17` | useQuery: `['vex-run-snapshot', activeTenantId, sbomId, runId, offset]` | `({signal}) => getVexRunSnapshot(sbomId, runId, offset, signal)` | `enabled=!!activeTenantId && !!runId` |
| `frontend/src/components/vex/VexVersionComparisonPanel.tsx:18` | useQuery: `['vex-version-comparison', activeTenantId, sbomId]` | `({signal}) => getVexVersionComparison(sbomId, signal)` | `enabled=open && !!activeTenantId` |
| `frontend/src/components/vulnerabilities/CveDetailDialog/hooks.ts:34` | useQuery: `cveQueryKey(scanId, cveId ?? '', componentId)` | `({ signal }) => getCveDetail({ cveId: cveId ?? '', scanId: scanId ?? null, ...(componentId != null ? { componentId } : {}) }, signal)` | `enabled=enabled && Boolean(cveId) && isRecognised; staleTime=5 * 60 * 1000` |
| `frontend/src/hooks/useAiCredentials.ts:71` | useQuery: `[...aiCredentialsQueryKey, key]` | `({ signal }) => listAiCredentials(signal, scope)` | `enabled=args.enabled ?? true; staleTime=30_000` |
| `frontend/src/hooks/useAiCredentials.ts:186` | useQuery: `[...aiProviderModelsQueryKey(credentialId), key]` | `({ signal }) => listAiProviderModels(credentialId, signal, scope)` | `staleTime=30_000` |
| `frontend/src/hooks/useAiCredentials.ts:233` | useQuery: `[...aiCredentialSettingsQueryKey, key]` | `({ signal }) => getAiCredentialSettings(signal, scope)` | `enabled=args.enabled ?? true; staleTime=30_000` |
| `frontend/src/hooks/useAiCredentials.ts:267` | useQuery: `[...aiProviderCatalogQueryKey, key]` | `({ signal }) => listAiProviderCatalog(signal, scope)` | `staleTime=60 * 60_000` |
| `frontend/src/hooks/useAiCredentials.ts:283` | useQuery: `['ai', 'run-batch-estimate', runId]` | `({ signal }) => getRunBatchEstimate(runId as number, signal)` | `enabled=enabled; staleTime=30_000` |
| `frontend/src/hooks/useAiFix.ts:78` | useQuery: `aiFixQueryKey(findingId ?? -1, providerName)` | `({ signal }) => getFindingAiFix(findingId as number, { providerName }, signal)` | `enabled=enabled && findingId != null; staleTime=5 * 60_000` |
| `frontend/src/hooks/useAiFix.ts:143` | useQuery: `['ai-batch-progress', runId]` | `({ signal }) => getRunAiFixProgress(runId as number, signal)` | `enabled=active; refetchInterval=(qData) => { if (!active) return false; if (sseAvailable === true) return false; const data = qData.state.data; // \`\`null\`\` = backend 204 (run exists, no batch — idle). Stop, same as // a terminal status; don't poll a dead/idle endpoint forever. if (data === null) return false; if (data && isTerminal(data.status)) return false; return POLL_INTERVAL_MS; }` |
| `frontend/src/hooks/useAiFix.ts:240` | useQuery: `['ai-fix-list', runId]` | `({ signal }) => listRunAiFixes(runId as number, signal)` | `enabled=enabled && runId != null` |
| `frontend/src/hooks/useAiFix.ts:279` | useQuery: `['ai', 'run-batch-estimate', runId, debouncedKey]` | `({ signal }) => estimateRunAiFixesScoped(runId as number, debouncedScope, signal)` | `enabled=enabled && runId != null; staleTime=30_000` |
| `frontend/src/hooks/useAiFix.ts:319` | useQuery: `['ai-batch-list', runId]` | `({ signal }) => listRunAiBatches(runId as number, signal)` | `enabled=enabled && runId != null; refetchInterval=refetchIntervalMs ?? false` |
| `frontend/src/hooks/useAiFix.ts:359` | useQuery: `['ai-settings', 'providers']` | `({ signal }) => listAiProviders(signal)` | `enabled=enabled; staleTime=60_000` |
| `frontend/src/hooks/useAiFix.ts:365` | useQuery: `['ai-settings', 'pricing']` | `({ signal }) => listAiPricing(signal)` | `enabled=enabled; staleTime=60 * 60_000` |
| `frontend/src/hooks/useAiFix.ts:371` | useQuery: `['ai-settings', 'usage']` | `({ signal }) => getAiUsageSummary(signal)` | `enabled=enabled; refetchInterval=30_000` |
| `frontend/src/hooks/useReportNotifications.ts:6` | useQuery: `['reports', 'config']` | `getReportConfig` | `QueryClient defaults` |
| `frontend/src/hooks/useReportNotifications.ts:7` | useQuery: `['reports', 'subscriptions', tenantId]` | `() => getReportSubscriptions(tenantId)` | `QueryClient defaults` |
| `frontend/src/hooks/useReportNotifications.ts:8` | useQuery: `['reports', 'deliveries', allTenant, status, deliveryId]` | `() => getReportDeliveries(allTenant, status, deliveryId)` | `refetchInterval=15_000` |
| `frontend/src/hooks/useSbomsList.ts:12` | useQuery: `['sboms']` | `({ signal }) => getSboms(1, SBOMS_LIST_PAGE_SIZE, signal)` | `refetchInterval=(query) => { const rows = query.state.data ?? []; return rows.some((sbom) => { const latest = sbom.latest_analysis; if (!latest) return false; return ( ACTIVE_ANALYSIS_RESULTS.has(String(latest.result ?? '').toLowerCase()) \|\| ACTIVE_ANALYSIS_STATUSES.has(String(latest.status ?? '').toUpperCase()) ); }) ? 3000 : false; }; refetchOnWindowFocus=true` |

### Appendix B — all mutation hooks and synchronization

Read-only mutation wrappers remain in this inventory; absence of invalidation on downloads/preview is intentional.

| Location | Mutation function | Success handling | Error / settled handling |
|---|---|---|---|
| `frontend/src/app/kev/page.tsx:243` | `() => syncKevCatalog()` | `(result) => { setLastSync(result); setPage(1); queryClient.invalidateQueries({ queryKey: ['kev-catalog'] }); queryClient.invalidateQueries({ queryKey: ['kev-filter-options'] }); queryClient.invalidateQueries({ queryKey: ['kev-detail'] }); showToast('KEV catalog synced successfully', 'success'); }` | `(error) => showToast(errorMessage(error, 'KEV sync failed'), 'error'); ` |
| `frontend/src/app/products/[id]/page.tsx:123` | `(mode: 'AUTO' \| 'MANUAL_PIN') => updateProduct(id, { current_sbom_mode: mode })` | `() => { invalidateProductSurfaces(queryClient, id); showToast('Selection policy updated', 'success'); }` | `error => showToast(getApiErrorMessage(error, 'Selection policy update failed.'), 'error'); ` |
| `frontend/src/app/products/[id]/page.tsx:129` | `(currentSbomId: number) => updateProduct(id, { current_sbom_id: currentSbomId })` | `() => { invalidateProductSurfaces(queryClient, id); queryClient.invalidateQueries({ queryKey: ['product', id] }); queryClient.invalidateQueries({ queryKey: ['schedule-targets'] }); queryClient.invalidateQueries({ queryKey: ['schedule'] }); showToast('Current SBOM updated', 'success'); }` | `(error: unknown) => showToast(getApiErrorMessage(error, 'Current SBOM update failed.'), 'error'); ` |
| `frontend/src/app/schedules/page.tsx:162` | `(id: number) => pauseSchedule(id)` | `() => { showToast('Paused', 'success'); invalidate(); }` | `(error: unknown) => showToast(getApiErrorMessage(error, 'Schedule pause failed.'), 'error'); ` |
| `frontend/src/app/schedules/page.tsx:170` | `(id: number) => resumeSchedule(id)` | `() => { showToast('Resumed', 'success'); invalidate(); }` | `(error: unknown) => showToast(getApiErrorMessage(error, 'Schedule resume failed.'), 'error'); ` |
| `frontend/src/app/schedules/page.tsx:178` | `(id: number) => runScheduleNow(id)` | `(res) => { showToast( \`Enqueued ${res.sbom_ids.length} SBOM analysis${res.sbom_ids.length === 1 ? '' : 'es'}\`, 'success', ); // Enqueuing creates new runs and flips affected SBOMs into RUNNING — // refresh runs list, SBOM analysis badges, and dashboard counts so // every surface reflects the in-flight work. invalidateRunLists(queryClient); invalidateSbomLists(queryClient); invalidateDashboardTiles(queryClient); }` | `(error: unknown) => showToast(getApiErrorMessage(error, 'The scheduled analysis could not be queued.'), 'error'); ` |
| `frontend/src/app/schedules/page.tsx:194` | `({ sched, permanent, }: { sched: AnalysisSchedule; permanent: boolean; }) => sched.scope === 'TENANT' && sched.tenant_id != null ? deleteScopedSchedule('TENANT', sched.tenant_id) : sched.scope === 'PRODUCT' && sched.product_id != null ? deleteScopedSchedule('PRODUCT', sched.product_id) : sched.scope === 'PROJECT' && sched.project_id != null ? deleteProjectSchedule(sched.project_id, { permanent }) : sched.scope === 'SBOM' && sched.sbom_id != null ? deleteSbomSchedule(sched.sbom_id, { permanent }) : Promise.reject(new Error('Schedule has no resolvable target'))` | `(_data, { permanent }) => { showToast( permanent ? 'Schedule permanently removed' : 'Schedule removed', 'success', ); setConfirmDelete(null); invalidate(); }` | `(error: unknown) => showToast(getApiErrorMessage(error, 'Schedule deletion failed.'), 'error'); ` |
| `frontend/src/app/settings/platform/page.tsx:39` | `(userId: number) => grantPlatformAdministrator(userId)` | `async (_res) => { showSuccess(\`Platform Administrator authority granted to “${selectedUser?.display_name \|\| selectedUser?.email}”.\`); setSelectedUser(null); await qc.invalidateQueries({ queryKey: ['platform-administrators'] }); }` | `(error) => showError(getApiErrorMessage(error, 'Could not grant Platform Administrator.')); ` |
| `frontend/src/app/settings/platform/page.tsx:49` | `(grantId: number) => revokePlatformAdministrator(grantId)` | `async () => { showSuccess(\`Platform Administrator authority revoked.\`); setRevokeTarget(null); await qc.invalidateQueries({ queryKey: ['platform-administrators'] }); }` | `(error) => showError(getApiErrorMessage(error, 'Could not revoke Platform Administrator authority.')); ` |
| `frontend/src/app/settings/platform/tenants/[tenantId]/page.tsx:34` | `() => recoverPlatformTenantAdmin(id, candidate!.id)` | `async () => { setCandidate(null); showSuccess('Tenant Administrator recovery completed.'); await invalidateTenantSummary(); }` | `error => showError(getApiErrorMessage(error, 'Administrator recovery failed.')); ` |
| `frontend/src/app/settings/platform/tenants/[tenantId]/page.tsx:39` | `() => updatePlatformTenantStatus(id, tenant.data?.status === 'ACTIVE' ? 'DISABLED' : 'ACTIVE')` | `async () => { setConfirm(false); await invalidateTenantSummary(); }` | `error => showError(getApiErrorMessage(error, 'Tenant status could not be updated.')); ` |
| `frontend/src/app/settings/platform/tenants/page.tsx:119` | `createPlatformTenant` | `async (tenant) => { showSuccess(\`Tenant “${tenant.name}” was created successfully.\`); setForm(EMPTY_FORM); setAdminMode('existing'); setSlugEdited(false); setSelectedInitialAdmin(null); setFieldErrors({}); setFormOpen(false); await queryClient.invalidateQueries({ queryKey: ['platform-tenants'] }); router.push(\`/settings/platform/tenants/${tenant.id}\`); }` | `(error) => { setFieldErrors(validationErrorsFromResponse(error)); showError(safeErrorMessage(error)); }; ` |
| `frontend/src/app/settings/platform/tenants/page.tsx:138` | `({ id, status }: { id: number \| string; name: string; status: 'ACTIVE' \| 'DISABLED' }) => updatePlatformTenantStatus(id, status)` | `async (_result, variables) => { showSuccess(\`Tenant “${variables.name}” was ${variables.status === 'ACTIVE' ? 'activated' : 'disabled'} successfully.\`); setDisableTarget(null); await queryClient.invalidateQueries({ queryKey: ['platform-tenants'] }); }` | `(error) => showError(getApiErrorMessage(error, 'The tenant status could not be changed.')); ` |
| `frontend/src/components/admin/LifecycleProviderSettings.tsx:39` | `({ key, payload }: { key: string; payload: LifecycleProviderUpdatePayload }) => updateLifecycleProvider(key, payload, undefined, scope)` | `(updatedProvider) => { queryClient.setQueryData<LifecycleProviderConfig[]>(['lifecycle-providers', scopeKey], (current) => current?.map((provider) => provider.provider_key === updatedProvider.provider_key ? updatedProvider : provider, ) ?? current, ); invalidate(); showToast('Lifecycle provider saved', 'success'); }` | `(error: unknown) => showToast(getApiErrorMessage(error, 'Provider configuration update failed.'), 'error'); ` |
| `frontend/src/components/admin/LifecycleProviderSettings.tsx:54` | `(key: string) => testLifecycleProvider(key, undefined, scope)` | `(result, key) => { setTestResult((prev) => ({ ...prev, [key]: result })); void invalidate(); showToast(normalizeNotificationMessage(result.message, result.success ? 'Provider connection succeeded.' : 'Provider connection failed.'), result.success ? 'success' : 'error'); }` | `(error: unknown) => showToast(getApiErrorMessage(error, 'Provider connection test failed.'), 'error'); ` |
| `frontend/src/components/admin/LifecycleProviderSettings.tsx:64` | `(key: string) => syncLifecycleProvider(key, undefined, scope)` | `(result) => { void invalidate(); showToast(normalizeNotificationMessage(result.message, 'Provider synchronization was queued successfully.'), 'success'); }` | `(error: unknown) => showToast(getApiErrorMessage(error, 'Provider synchronization failed.'), 'error'); ` |
| `frontend/src/components/admin/LifecycleProviderSettings.tsx:73` | `({ key, name, value }: { key: string; name: string; value: string }) => setLifecycleProviderSecret(key, { secret_name: name, secret_value: value }, undefined, scope)` | `() => { void invalidate(); showToast('Secret saved', 'success'); }` | `(error: unknown) => showToast(getApiErrorMessage(error, 'Provider secret could not be saved.'), 'error'); ` |
| `frontend/src/components/admin/LifecycleProviderSettings.tsx:83` | `({ key, name }: { key: string; name: string }) => deleteLifecycleProviderSecret(key, name, undefined, scope)` | `() => { void invalidate(); showToast('Secret deleted', 'success'); }` | `(error: unknown) => showToast(getApiErrorMessage(error, 'Provider secret could not be deleted.'), 'error'); ` |
| `frontend/src/components/admin/LifecycleProviderSettings.tsx:92` | `resetLifecycleProviderOverride` | `() => queryClient.invalidateQueries({ queryKey: ['lifecycle-providers', scopeKey] })` | `; ` |
| `frontend/src/components/admin/LifecycleVendorRecordsPage.tsx:48` | `(payload: LifecycleVendorRecordPayload) => createLifecycleVendorRecord(payload)` | `() => { invalidate(); setCreating(false); showToast('Vendor record created', 'success'); }` | `(error: unknown) => showToast(getApiErrorMessage(error, 'Vendor record creation failed.'), 'error'); ` |
| `frontend/src/components/admin/LifecycleVendorRecordsPage.tsx:58` | `({ id, payload }: { id: number; payload: LifecycleVendorRecordPayload }) => updateLifecycleVendorRecord(id, payload)` | `() => { invalidate(); setEditing(null); showToast('Vendor record saved', 'success'); }` | `(error: unknown) => showToast(getApiErrorMessage(error, 'Vendor record update failed.'), 'error'); ` |
| `frontend/src/components/admin/LifecycleVendorRecordsPage.tsx:69` | `(id: number) => deleteLifecycleVendorRecord(id)` | `() => { invalidate(); showToast('Vendor record disabled', 'success'); }` | `(error: unknown) => showToast(getApiErrorMessage(error, 'Vendor record deletion failed.'), 'error'); ` |
| `frontend/src/components/admin/LifecycleVendorRecordsPage.tsx:78` | `(records: LifecycleVendorRecordPayload[]) => importLifecycleVendorRecords(records)` | `(result) => { invalidate(); setImportText(''); showToast(\`Imported ${result.created} records\`, result.errors.length ? 'info' : 'success'); }` | `(error: unknown) => showToast(getApiErrorMessage(error, 'Vendor record import failed.'), 'error'); ` |
| `frontend/src/components/admin/LifecycleVendorRecordsPage.tsx:89` | `() => exportLifecycleVendorRecords()` | `(result) => { const blob = new Blob([JSON.stringify(result.records, null, 2)], { type: 'application/json' }); const url = URL.createObjectURL(blob); const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'lifecycle-vendor-records.json'; anchor.click(); URL.revokeObjectURL(url); }` | `(error: unknown) => showToast(getApiErrorMessage(error, 'Vendor record export failed.'), 'error'); ` |
| `frontend/src/components/admin/PlatformTenantOverview.tsx:74` | `() => resendPlatformTenantActivation(Number(tenant.id), administrator!.user_id)` | `(result) => { void queryClient.invalidateQueries({ queryKey: ["platform-tenant", Number(tenant.id)] }); void queryClient.invalidateQueries({ queryKey: ["tenant-users", Number(tenant.id)] }); void queryClient.invalidateQueries({ queryKey: ["tenant-audit-history", Number(tenant.id)] }); setDeliveryStatus(result.delivery.status); setConfirmOpen(false); if (result.delivery.status === "SENT") showSuccess("Activation email sent successfully."); else if (result.delivery.status === "PENDING") showInfo("Activation email queued for delivery."); else showWarning( "The activation email could not be confirmed as sent. Please try again later or contact your administrator.", ); }` | `(error) => showError( error instanceof ApiError && error.status === 429 ? "Please wait before requesting another activation email." : "Unable to resend activation. Please try again or check the account in user management.", ); () => { requestInFlight.current = false; }` |
| `frontend/src/components/admin/TenantUsersAccess.tsx:71` | `async () => { if (!selectedUser \|\| !currentTenantId) return; await addTenantMember(currentTenantId, { user_id: selectedUser.id, roles: initialRoles, }); }` | `async () => { showSuccess(\`User “${selectedUser?.display_name \|\| selectedUser?.email}” was added to the tenant.\`); setSelectedUser(null); await qc.invalidateQueries({ queryKey: ['tenant-users', currentTenantId] }); await qc.invalidateQueries({ queryKey: ['tenant-audit-history', currentTenantId] }); }` | `(error) => showError(getApiErrorMessage(error, 'Failed to add member to tenant.')); ` |
| `frontend/src/components/dashboard/advanced/CopilotPanel.tsx:96` | `() => getCopilotBriefing(true)` | `(data) => { queryClient.setQueryData(['copilot-briefing'], data); setEnabled(true); }` | `; ` |
| `frontend/src/components/dashboard/advanced/CopilotPanel.tsx:106` | `(q: string) => askCopilot(q)` | `none inline` | `; ` |
| `frontend/src/components/products/ProductFormDialog.tsx:55` | `(category: string \| null) => { if (!project) throw new Error('Project is required'); const payload = { name: form.name.trim(), description: form.description.trim() \|\| null, vendor: form.vendor.trim() \|\| null, category, status: form.status, }; return product ? updateProduct(product.id, payload) : createProduct(project.id, payload); }` | `() => { if (project) queryClient.invalidateQueries({ queryKey: ['products', project.id] }); invalidateProductSurfaces(queryClient, product?.id); invalidateDashboardTiles(queryClient); showSuccess(\`Application “${form.name.trim()}” was ${product ? 'updated' : 'created'} successfully.\`); onClose(); }` | `(error: unknown) => showError(getApiErrorMessage(error, 'Application save failed. Please try again.')); ` |
| `frontend/src/components/projects/ProjectApplications.tsx:72` | `(product: Product) => deleteProduct(product.id)` | `(_data, deletedProduct) => { queryClient.invalidateQueries({ queryKey: ['products', project.id] }); invalidateProductSurfaces(queryClient, deletedProduct.id); invalidateDashboardTiles(queryClient); showSuccess(\`Application “${deletedProduct.name}” was deleted successfully.\`); setDeleteProductTarget(null); }` | `(error: unknown) => showError(getApiErrorMessage(error, 'Application deletion failed. Please try again.')); ` |
| `frontend/src/components/projects/ProjectModal.tsx:71` | `(values: FormValues) => { if (isEdit && project) { return updateProject(project.id, { project_name: values.project_name, project_details: values.project_details, project_status: toStatusInt(values.project_status), }); } return createProject({ project_name: values.project_name, project_details: values.project_details, project_status: toStatusInt(values.project_status), }); }` | `() => { invalidateProjectLists(queryClient); // SBOM rows render project_name; a rename leaves them stale until // staleTime expires. Bust the SBOM list surfaces too. invalidateSbomLists(queryClient); showSuccess(isEdit ? 'Project updated successfully.' : 'Project created successfully.'); onClose(); }` | `(error: unknown) => { const normalized = toUserFacingApiError( error, isEdit ? 'Project update failed. Please try again.' : 'Project creation failed. Please try again.', ); for (const [field, messages] of Object.entries(normalized.fieldErrors)) { if (field in schema.shape) setError(field as keyof FormValues, { message: messages[0] }); } showApiError(error, normalized.message); }; ` |
| `frontend/src/components/projects/ProjectsTable.tsx:154` | `({ id, permanent }: { id: number; permanent: boolean }) => deleteProject(id, { permanent })` | `(_data, { permanent }) => { // Project delete cascades to its SBOMs (and their runs/schedules); // refresh every affected list view so the UI matches the cascade. invalidateProjectLists(queryClient); invalidateSbomLists(queryClient); invalidateRunLists(queryClient); invalidateScheduleLists(queryClient); invalidateDashboardTiles(queryClient); const name = deleteTarget?.project_name ?? 'Project'; showSuccess(permanent ? \`Project “${name}” was deleted successfully.\` : \`Project “${name}” was archived successfully.\`); setDeleteTarget(null); }` | `(error: unknown) => { showError(getApiErrorMessage(error, 'Project deletion failed. Please try again.')); }; ` |
| `frontend/src/components/sboms/SbomAutoRepairPanel.tsx:33` | `() => runSbomRepair(sessionId)` | `(job) => invalidateRepairJob(job)` | `; ` |
| `frontend/src/components/sboms/SbomAutoRepairPanel.tsx:34` | `(decision: 'approve' \| 'reject') => decision === 'approve' ? decideSbomRepair(sessionId, latest.data!.repair_job_id, decision, latest.data!.candidate_sha256) : decideSbomRepair(sessionId, latest.data!.repair_job_id, decision)` | `(job) => { invalidateRepairJob(job); client.invalidateQueries({ queryKey: ['validation-repair-session', sessionId] }); if (job.imported_sbom_id) { invalidateSbomSurfaces(client, job.imported_sbom_id); invalidateDashboardTiles(client); invalidateProjectSurfaces(client, job.source_project_id); invalidateProductSurfaces(client, job.source_product_id); client.invalidateQueries({ queryKey: ['validation-repair-content', sessionId] }); client.invalidateQueries({ queryKey: ['validation-repair-lines', sessionId] }); client.invalidateQueries({ queryKey: ['validation-repair-search', sessionId] }); client.invalidateQueries({ queryKey: ['sbom-auto-repair-analysis', sessionId] }); onApproved?.(); } }` | `; ` |
| `frontend/src/components/sboms/SbomAutoRepairPanel.tsx:50` | `(kind: 'download' \| 'report' \| 'original') => kind === 'original' ? downloadValidationSessionOriginal(sessionId) : downloadSbomRepair(sessionId, latest.data!.repair_job_id, kind)` | `saveDownload` | `; ` |
| `frontend/src/components/sboms/SbomConversionCard.tsx:95` | `() => convertSbomToCycloneDX(sbom.id)` | `(result) => { setConvertedId(result.converted_sbom_id); setEnrichmentStatus(result.enrichment_status \|\| 'pending'); invalidateSbomConversionSurfaces(qc, sbom.id, result.converted_sbom_id); setMessage( result.message \|\| 'Converted to CycloneDX. Lifecycle enrichment is running in background.', ); showSuccess('SBOM was converted to CycloneDX successfully.'); }` | `(err: Error) => { if (isTimeoutError(err)) { setMessage( 'Conversion timed out. The server may still be processing — refresh this page in a moment.', ); return; } const safeMessage = getApiErrorMessage(err, 'SBOM conversion failed. Please try again.'); setMessage(safeMessage); showError(safeMessage); }; ` |
| `frontend/src/components/sboms/SbomLifecycleControls.tsx:36` | `() => changeSbomLifecycle(sbom.id, next, reason.trim())` | `updated => { qc.setQueryData(['sbom', sbom.id], updated); invalidateSbomLifecycle(qc, sbom); showToast(\`SBOM marked ${next.toLowerCase()}.\`, 'success'); setOpen(false); setReason(''); }` | `error => showToast(getApiErrorMessage(error, 'Unable to change SBOM lifecycle.'), 'error'); ` |
| `frontend/src/components/sboms/SbomUploadModal.tsx:206` | `(name: string) => createProduct(selectedProjectNumber!, { name })` | `(product) => { queryClient.invalidateQueries({ queryKey: ['products', selectedProjectNumber] }); setValue('productid', String(product.id), { shouldValidate: true }); setNewProductName(''); showToast('Application created', 'success'); }` | `(error: unknown) => showToast(getApiErrorMessage(error, 'Application creation failed. Please try again.'), 'error'); ` |
| `frontend/src/components/sboms/SbomsTable.tsx:139` | `({ sbom, permanent, }: { sbom: SBOMSource; permanent: boolean; }) => deleteSbom(sbom.id, sbom.created_by ?? '', { permanent })` | `(_data, { permanent, sbom }) => { invalidateSbomSurfaces(queryClient, sbom.id); invalidateProjectSurfaces(queryClient, sbom.projectid); invalidateRunLists(queryClient); invalidateScheduleLists(queryClient); invalidateDashboardTiles(queryClient); showToast(\`SBOM “${sbom.sbom_name}” was ${permanent ? 'deleted' : 'archived'} successfully.\`, 'success'); setDeleteTarget(null); }` | `(error: unknown) => { showToast(getApiErrorMessage(error, 'SBOM deletion failed. Please try again.'), 'error'); }; ` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:152` | `() => { lastSaveContent.current = content; return saveValidationSessionRepairDraft(sessionId, content, sessionQuery.data?.updated_at); }` | `(updated) => { queryClient.setQueryData(['validation-repair-session', sessionId], updated); invalidateValidationRepairHistory(queryClient, sessionId); invalidateValidationRepairDraftQueries(queryClient, sessionId); setLoadedContentSize(content.length); setTotalContentSize(content.length); setContentEof(true); setContentSha256(updated.stored_sha256 ?? null); setSavedContent(lastSaveContent.current); setLocalMessage('Draft saved in the repair workspace.'); }` | `; ` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:167` | `async () => { if (sessionQuery.data?.full_editor_allowed !== false && hasUnsavedChanges) { const saved = await saveValidationSessionRepairDraft(sessionId, content, sessionQuery.data?.updated_at); queryClient.setQueryData(['validation-repair-session', sessionId], saved); setSavedContent(content); } return validateValidationSession(sessionId); }` | `(updated) => { queryClient.setQueryData(['validation-repair-session', sessionId], updated); invalidateValidationRepairHistory(queryClient, sessionId); invalidateValidationRepairDraftQueries(queryClient, sessionId); setContentSha256(updated.stored_sha256 ?? null); if (sessionQuery.data?.full_editor_allowed !== false) setSavedContent(content); setWorkflowStep('validate'); setLocalMessage( updated.validation_status === 'passed' \|\| updated.validation_status === 'repaired_valid' ? 'Validation passed. Import is now available.' : 'Validation completed with remaining issues.', ); }` | `; ` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:192` | `() => getValidationSessionContent( sessionId, loadedContentSize \|\| content.length \|\| initialContentQuery.data?.content.length \|\| 0, CONTENT_CHUNK_SIZE, )` | `(chunk) => { setContent((old) => old + chunk.content); if (chunk.eof) setSavedContent(content + chunk.content); setLoadedContentSize(chunk.offset + chunk.content.length); setTotalContentSize(chunk.total_size); setContentEof(chunk.eof); setContentSha256(chunk.sha256); }` | `; ` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:209` | `() => downloadValidationSessionOriginal(sessionId)` | `({ blob, filename }) => { downloadBlob(blob, filename); }` | `; ` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:216` | `() => importValidationSession(sessionId, true)` | `(sbom) => { invalidateSbomSurfaces(queryClient, sbom.id); invalidateProjectSurfaces(queryClient, sbom.project_id ?? sbom.projectid ?? sessionQuery.data?.project_id); invalidateDashboardTiles(queryClient); queryClient.invalidateQueries({ queryKey: ['validation-repair-session', sessionId] }); queryClient.invalidateQueries({ queryKey: ['validation-repair-history', sessionId] }); router.push(\`/sboms/${sbom.id}\`); }` | `; ` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:228` | `() => suggestValidationSessionFixes(sessionId, { user_instruction: '' })` | `(result) => { setSuggestion(result); setAiReviewOpen(true); const initial: Record<number, boolean> = {}; result.patches.forEach((_, idx) => { initial[idx] = true; }); setSelected(initial); invalidateValidationRepairHistory(queryClient, sessionId); }` | `; ` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:242` | `async () => { if (!suggestion) return null; const patches = suggestion.patches.filter((_, idx) => selected[idx]); return applyValidationSessionPatch(sessionId, { patches }); }` | `(updated) => { if (!updated) return; queryClient.setQueryData(['validation-repair-session', sessionId], updated); invalidateValidationRepairHistory(queryClient, sessionId); invalidateValidationRepairDraftQueries(queryClient, sessionId); setContent(updated.current_content); setSavedContent(updated.current_content); setLoadedContentSize(updated.current_content.length); setTotalContentSize(updated.current_content.length); setContentEof(true); setContentSha256(updated.stored_sha256 ?? null); setSuggestion(null); setSelected({}); setLocalMessage(updated.validation_status === 'passed' ? 'Patch applied and validation passed.' : 'Patch applied and validation reran.'); }` | `; ` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:290` | `() => downloadValidationSessionRepairDraft(sessionId)` | `({ blob, filename }) => downloadBlob(blob, filename)` | `; ` |
| `frontend/src/components/sboms/repair/LargeFileRepairEditor.tsx:62` | `() => applyValidationSessionLinePatches(sessionId, [patch])` | `(updated) => { queryClient.setQueryData(['validation-repair-session', sessionId], updated); invalidateValidationRepairHistory(queryClient, sessionId); invalidateValidationRepairDraftQueries(queryClient, sessionId); onSessionUpdate(updated); setMessage('Patch saved to repair draft.'); linesQuery.refetch(); }` | `; ` |
| `frontend/src/components/schedules/ScheduleCard.tsx:119` | `(id: number) => pauseSchedule(id)` | `() => { showToast('Schedule paused', 'success'); invalidate(); }` | `(error: unknown) => showToast(getApiErrorMessage(error, 'Schedule pause failed.'), 'error'); ` |
| `frontend/src/components/schedules/ScheduleCard.tsx:128` | `(id: number) => resumeSchedule(id)` | `() => { showToast('Schedule resumed', 'success'); invalidate(); }` | `(error: unknown) => showToast(getApiErrorMessage(error, 'Schedule resume failed.'), 'error'); ` |
| `frontend/src/components/schedules/ScheduleCard.tsx:137` | `(id: number) => { if (processingReason) throw new Error(processingReason); return runScheduleNow(id); }` | `(res) => { showToast( \`Enqueued ${res.sbom_ids.length} SBOM analysis${res.sbom_ids.length === 1 ? '' : 'es'}\`, 'success', ); invalidateRunLists(queryClient); invalidateSbomLists(queryClient); invalidateDashboardTiles(queryClient); }` | `(error: unknown) => showToast(getApiErrorMessage(error, 'The scheduled analysis could not be queued.'), 'error'); ` |
| `frontend/src/components/schedules/ScheduleCard.tsx:154` | `({ permanent }: { permanent: boolean }) => scope === 'PROJECT' ? deleteProjectSchedule(targetId, { permanent }) : scope === 'PRODUCT' ? deleteProductSchedule(targetId, { permanent }) : deleteSbomSchedule(targetId, { permanent })` | `(_data, { permanent }) => { const noun = scope === 'PROJECT' ? 'Schedule' : 'Override'; showToast( permanent ? \`${noun} permanently removed\` : \`${noun} removed\`, 'success', ); setConfirmDelete(false); invalidate(); }` | `(error: unknown) => showToast(getApiErrorMessage(error, 'Schedule deletion failed.'), 'error'); ` |
| `frontend/src/components/schedules/ScheduleCard.tsx:173` | `() => excludeFromParentSchedule(scope as 'PRODUCT' \| 'SBOM', targetId)` | `() => { showToast(\`${scope === 'PRODUCT' ? 'Product' : 'SBOM'} excluded from parent schedules\`, 'success'); invalidate(); }` | `(error: unknown) => showToast(getApiErrorMessage(error, 'Schedule exclusion failed.'), 'error'); ` |
| `frontend/src/components/schedules/ScheduleCard.tsx:182` | `() => restoreScheduleInheritance(scope as 'PRODUCT' \| 'SBOM', targetId)` | `() => { showToast('Parent schedule inheritance restored', 'success'); invalidate(); }` | `(error: unknown) => showToast(getApiErrorMessage(error, 'Could not restore inheritance.'), 'error'); ` |
| `frontend/src/components/schedules/ScheduleEditor.tsx:120` | `() => scope === 'TENANT' \|\| scope === 'PRODUCT' ? upsertScopedSchedule(scope, targetId, payload) : scope === 'PROJECT' ? upsertProjectSchedule(targetId, payload) : upsertSbomSchedule(targetId, payload)` | `() => { // Invalidate both project + sbom schedule queries; cheaper than // computing the precise key for every dependent panel. queryClient.invalidateQueries({ queryKey: ['schedule'] }); queryClient.invalidateQueries({ queryKey: ['schedules'] }); showToast(existing ? 'Schedule updated' : 'Schedule created', 'success'); onClose(); }` | `(error: unknown) => { showToast(getApiErrorMessage(error, 'Schedule save failed. Please try again.'), 'error'); }; ` |
| `frontend/src/components/settings/ai/ScopedAiConfiguration.tsx:36` | `createTenantAiOverride` | `() => { client.invalidateQueries({ queryKey: ['ai'] }); invalidateAiCredentialSurfaces(client); }` | `; ` |
| `frontend/src/components/settings/ai/ScopedAiConfiguration.tsx:40` | `resetTenantAiOverride` | `() => { client.invalidateQueries({ queryKey: ['ai'] }); invalidateAiCredentialSurfaces(client); }` | `; ` |
| `frontend/src/components/vex/VexDecisionEditor.tsx:120` | `async () => { const text = (value: string) => value.trim() \|\| undefined; // Two save paths, one rule: use the context when there is one. // // With an investigation we go through the decision endpoint, which // carries row_version and rejects a stale write. Without one — a CVE no // scanner found and no document asserted — there is no context and // nothing to conflict with yet; the override creates the statement, and // reconciliation then creates the context, so every later edit takes the // first path. Both endpoints reach the same apply_vex_override service. if (investigation) { return setVexInvestigationDecision(investigation.id, { status: draft.status, row_version: investigation.row_version, reason: draft.reason.trim(), justification: text(draft.justification), impact_statement: text(draft.impactStatement), action_statement: text(draft.actionStatement), mitigation: text(draft.mitigation), fixed_version: text(draft.fixedVersion), evidence_url: text(draft.evidenceUrl), }); } return overrideVexStatement( componentId, vulnerabilityId.trim(), { status: draft.status.toLowerCase() as never, reason: draft.reason.trim(), justification: text(draft.justification) ?? null, impact_statement: text(draft.impactStatement) ?? null, action_statement: text(draft.actionStatement) ?? null, mitigation: text(draft.mitigation) ?? null, fixed_version: text(draft.fixedVersion) ?? null, evidence_url: text(draft.evidenceUrl) ?? null, }, undefined, sbomId, ); }` | `() => { setSubmitError(null); invalidateVexSurfaces(queryClient, sbomId); onSaved?.(); }` | `(error: unknown) => { if ((error as { status?: number })?.status === 409) { onConflict?.(); return; } setSubmitError(error instanceof Error ? error.message : 'Could not save the decision.'); }; ` |
| `frontend/src/components/vex/VexInvestigationPanel.tsx:39` | `(selected: string \| null) => setVexInvestigationAssignment(detail.id, { assigned_to: selected, row_version: savedDetail.row_version, reason: selected ? 'Assignment updated' : 'Assignment removed', })` | `(updated) => { setSavedDetail(updated); setAssignee(updated.internal_decision.assigned_to ?? ''); setFormError(null); invalidateVexSurfaces(queryClient); onSaved(); }` | `(error: unknown) => { if ((error as { status?: number })?.status === 409) return onConflict(); setFormError('Unable to update assignment. The current assignment was not changed. Try saving again.'); }; ` |
| `frontend/src/components/vex/VexInvestigationPanel.tsx:59` | `() => resolveVexInvestigationComponent(detail.id, { component_id: Number(componentId), row_version: detail.row_version, reason: \`Bound to component ${componentId} by analyst review\`, })` | `() => { invalidateVexSurfaces(queryClient); onSaved(); }` | `(error: unknown) => { if ((error as { status?: number })?.status === 409) return onConflict(); setFormError(error instanceof Error ? error.message : 'Could not bind the component.'); }; ` |
| `frontend/src/hooks/useAiCredentials.ts:83` | `(body) => createAiCredential(body, undefined, scope)` | `() => { invalidateAiCredentialSurfaces(qc); }` | `; ` |
| `frontend/src/hooks/useAiCredentials.ts:95` | `({ id, body }) => updateAiCredential(id, body, undefined, scope)` | `() => { invalidateAiCredentialSurfaces(qc); }` | `; ` |
| `frontend/src/hooks/useAiCredentials.ts:111` | `(id) => deleteAiCredential(id, undefined, scope)` | `() => { invalidateAiCredentialSurfaces(qc); // Cached per-finding fixes reference the deleted provider's name. invalidateAiFixCaches(qc); }` | `; ` |
| `frontend/src/hooks/useAiCredentials.ts:125` | `(id) => setAiCredentialDefault(id, undefined, scope)` | `() => { invalidateAiCredentialSurfaces(qc); }` | `; ` |
| `frontend/src/hooks/useAiCredentials.ts:137` | `(id) => setAiCredentialFallback(id, undefined, scope)` | `() => { invalidateAiCredentialSurfaces(qc); }` | `; ` |
| `frontend/src/hooks/useAiCredentials.ts:163` | `(body) => testAiCredentialUnsaved(body, undefined, scope)` | `none inline` | `; ` |
| `frontend/src/hooks/useAiCredentials.ts:171` | `(id) => testAiCredentialSaved(id, undefined, scope)` | `() => { // last_test_at / last_test_success on the row just changed — refresh // the list so the status badge updates without F5. invalidateAiCredentialSurfaces(qc); }` | `; ` |
| `frontend/src/hooks/useAiCredentials.ts:197` | `() => refreshAiProviderModels(credentialId, undefined, scope)` | `() => qc.invalidateQueries({ queryKey: [...aiProviderModelsQueryKey(credentialId), key] })` | `; ` |
| `frontend/src/hooks/useAiCredentials.ts:207` | `(modelId) => selectAiProviderModel(credentialId, modelId, undefined, scope)` | `() => { qc.invalidateQueries({ queryKey: [...aiProviderModelsQueryKey(credentialId), key] }); invalidateAiCredentialSurfaces(qc); invalidateAiFixCaches(qc); }` | `; ` |
| `frontend/src/hooks/useAiCredentials.ts:221` | `(modelId) => testAiProviderModel(credentialId, modelId, undefined, scope)` | `() => qc.invalidateQueries({ queryKey: [...aiProviderModelsQueryKey(credentialId), key] })` | `; ` |
| `frontend/src/hooks/useAiCredentials.ts:247` | `(body) => updateAiCredentialSettings(body, undefined, scope)` | `(data) => { qc.setQueryData([...aiCredentialSettingsQueryKey, key], data); invalidateAiCredentialSurfaces(qc); invalidateAiFixCaches(qc); }` | `; ` |
| `frontend/src/hooks/useAiFix.ts:86` | `() => generateFindingAiFix(findingId as number, { providerName })` | `(data) => { qc.setQueryData(aiFixQueryKey(findingId ?? -1, providerName), data); // The run-detail "AI fix" column flips from Generate → View when a // fix lands. We don't know the runId here, so invalidate the prefix. qc.invalidateQueries({ queryKey: ['ai-fix-list'] }); }` | `; ` |
| `frontend/src/hooks/useAiFix.ts:97` | `() => regenerateFindingAiFix(findingId as number, { providerName })` | `(data) => { qc.setQueryData(aiFixQueryKey(findingId ?? -1, providerName), data); qc.invalidateQueries({ queryKey: ['ai-fix-list'] }); }` | `; ` |
| `frontend/src/hooks/useAiFix.ts:205` | `(body: AiTriggerBatchRequest = {}) => triggerRunAiFixes(runId, body)` | `(resp) => { qc.setQueryData(['ai-batch-progress', runId], resp.progress); // The list of cached fixes will change as the batch completes — // invalidate so the run-detail table re-fetches when the user // opens it next. qc.invalidateQueries({ queryKey: ['ai-fix-list', runId] }); // Multi-batch history table picks up the new batch row. qc.invalidateQueries({ queryKey: ['ai-batch-list', runId] }); }` | `; ` |
| `frontend/src/hooks/useAiFix.ts:222` | `() => cancelRunAiFixes(runId)` | `() => { qc.invalidateQueries({ queryKey: ['ai-batch-progress', runId] }); // Partial fixes were cached as they came in; show them. qc.invalidateQueries({ queryKey: ['ai-fix-list', runId] }); // Batch status flips to cancelled. qc.invalidateQueries({ queryKey: ['ai-batch-list', runId] }); }` | `; ` |
| `frontend/src/hooks/useAiFix.ts:296` | `(body: AiTriggerBatchRequest = {}) => triggerRunAiFixes(runId, body)` | `(resp) => { // Seed both the batch-keyed and the legacy run-keyed cache so // any consumer that hasn't migrated to the multi-batch keys // still sees fresh data. qc.setQueryData(['ai-batch-progress', runId], resp.progress); if (resp.batch_id) { qc.setQueryData(['ai-batch-progress', runId, resp.batch_id], resp.progress); } qc.invalidateQueries({ queryKey: ['ai-fix-list', runId] }); qc.invalidateQueries({ queryKey: ['ai-batch-list', runId] }); }` | `; ` |
| `frontend/src/hooks/useAiFix.ts:331` | `(batchId: string) => cancelRunAiBatch(runId, batchId)` | `(_resp, batchId) => { qc.invalidateQueries({ queryKey: ['ai-batch-progress', runId, batchId] }); qc.invalidateQueries({ queryKey: ['ai-batch-list', runId] }); // Partial fixes were cached during the batch. qc.invalidateQueries({ queryKey: ['ai-fix-list', runId] }); // Legacy banner consumers read the no-batchId key — refresh them too. qc.invalidateQueries({ queryKey: ['ai-batch-progress', runId] }); }` | `; ` |
| `frontend/src/hooks/useComponentAdvisorMutations.ts:26` | `(args: { canonicalKey: string; trigger: RecommendationTrigger; scope?: Pick<AdvisorFilterParams, 'project_id' \| 'product_id' \| 'sbom_id'>; }) => createAdvisorRecommendation({ canonical_key: args.canonicalKey, trigger_type: args.trigger }, args.scope)` | `(item) => { invalidateComponentAdvisorSurfaces(queryClient, item.id); }` | `; ` |
| `frontend/src/hooks/useComponentAdvisorMutations.ts:40` | `() => evaluateAdvisorRecommendation(recommendationId)` | `() => { invalidateComponentAdvisorSurfaces(queryClient, recommendationId); }` | `; ` |
| `frontend/src/hooks/useComponentAdvisorMutations.ts:50` | `(args: { decision: RecommendationDecision; reason: string; rowVersion: number; candidateId?: number }) => decideAdvisorRecommendation(recommendationId, { decision: args.decision, reason: args.reason, row_version: args.rowVersion, ...(args.candidateId ? { candidate_id: args.candidateId } : {}), })` | `() => { invalidateComponentAdvisorSurfaces(queryClient, recommendationId); }` | `() => { // A 409 means someone else moved the item; refetch so the UI shows the truth. invalidateComponentAdvisorSurfaces(queryClient, recommendationId); }; ` |
| `frontend/src/hooks/useReportNotifications.ts:11` | `({ id, body }: { id?: number; body: ReportPreferences }) => id ? updateReportSubscription(id, body) : createReportSubscription(body)` | `() => invalidateReportSurfaces(qc)` | `; ` |
| `frontend/src/hooks/useReportNotifications.ts:15` | `({ id, enabled }: { id: number; enabled: boolean }) => updateReportSubscription(id, { enabled })` | `() => invalidateReportSurfaces(qc)` | `; ` |
| `frontend/src/hooks/useReportNotifications.ts:19` | `deleteReportSubscription` | `() => invalidateReportSurfaces(qc)` | `; ` |
| `frontend/src/hooks/useReportNotifications.ts:23` | `sendReportNow` | `() => invalidateReportSurfaces(qc)` | `; ` |
| `frontend/src/hooks/useReportNotifications.ts:27` | `previewReport` | `none inline` | `; ` |
| `frontend/src/hooks/useSbomMutations.ts:44` | `(payload) => uploadSbom(payload)` | `(sbom) => { invalidateUploadSurfaces(qc, sbom.project_id ?? sbom.projectid); }` | `; ` |
| `frontend/src/hooks/useSbomMutations.ts:62` | `async () => { try { await revalidateSbom(sbomId); } catch (err) { if (err instanceof HttpError && isValidationFailureDetail(err.detail)) { // Expected outcome — the run succeeded, the SBOM didn't pass. // Swallow so onSuccess fires and consumers refresh. return; } throw err; } }` | `() => { qc.invalidateQueries({ queryKey: ['sbom-validation-report', sbomId] }); qc.invalidateQueries({ queryKey: ['sbom', sbomId] }); qc.invalidateQueries({ queryKey: ['sbom-info', sbomId] }); // Validation status surfaces in the main list's Upload column. invalidateSbomLists(qc); }` | `; ` |

### Appendix C — all imported API and fetch call sites

Includes calls inside query/mutation functions, imperative handlers, effects and server-side Next proxy routes. Bare function references (for example mutationFn: createPlatformTenant) are captured in Appendix B. Dynamic UserLifecycle endpoints are assembled from platform/tenant prefix and listed in its source handlers.

| Location | Request expression |
|---|---|
| `frontend/src/app/admin/ai-usage/page.tsx:19` | `getAnalysisConfig(signal)` |
| `frontend/src/app/analysis/[id]/page.tsx:109` | `getRun(id, signal)` |
| `frontend/src/app/analysis/[id]/page.tsx:121` | `getAllEnrichedRunFindings(id, { severity: severityFilter \|\| undefined }, signal)` |
| `frontend/src/app/analysis/[id]/page.tsx:134` | `getAnalysisConfig(signal)` |
| `frontend/src/app/analysis/[id]/page.tsx:143` | `downloadPdfReport({ runId: run.id, title: \`Analysis Report — Run #${run.id}\`, filename: \`sbom-analysis-run-${run.id}.pdf\`, })` |
| `frontend/src/app/analysis/[id]/page.tsx:161` | `exportRunCsv(run.id)` |
| `frontend/src/app/analysis/[id]/page.tsx:175` | `exportRunSarif(run.id)` |
| `frontend/src/app/analysis/compare/_v1/page.tsx:45` | `compareRuns(runA as number, runB as number, signal)` |
| `frontend/src/app/analysis/page.tsx:89` | `getAnalysisConfig(signal)` |
| `frontend/src/app/analysis/page.tsx:95` | `getProjects(signal)` |
| `frontend/src/app/analysis/page.tsx:119` | `getRuns( { project_id: projectFilter ? Number(projectFilter) : undefined, product_id: productFilter ? Number(productFilter) : undefined, sbom_id: sbomFilter ? Number(sbomFilter) : undefined, run_status: statusFilter \|\| undefined, page: 1, page_size: 100, }, signal, )` |
| `frontend/src/app/analysis/page.tsx:140` | `getRunsAggregate( { project_id: projectFilter ? Number(projectFilter) : undefined, product_id: productFilter ? Number(productFilter) : undefined, sbom_id: sbomFilter ? Number(sbomFilter) : undefined, }, signal, )` |
| `frontend/src/app/analysis/page.tsx:160` | `exportRunsJson({ project_id: projectFilter ? Number(projectFilter) : undefined, product_id: productFilter ? Number(productFilter) : undefined, sbom_id: sbomFilter ? Number(sbomFilter) : undefined, run_status: statusFilter \|\| undefined, })` |
| `frontend/src/app/api/auth/entra/route.ts:26` | `fetch(\`${process.env.SBOM_API_URL \|\| 'http://localhost:8000'}/api/auth/entra/session\`, { headers: { Authorization: \`Bearer ${accessToken}\` }, cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(10000), })` |
| `frontend/src/app/api/auth/logout/route.ts:16` | `fetch(\`${config.apiUrl}/api/auth/native/logout\`, { method: 'POST', headers: { Authorization: \`Bearer ${session.accessToken}\` }, cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(3000) })` |
| `frontend/src/app/api/auth/native/[action]/route.ts:18` | `fetch(\`${process.env.SBOM_API_URL \|\| 'http://localhost:8000'}/api/auth/native/${action}\`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(session?.provider === 'NATIVE' ? { Authorization: \`Bearer ${session.accessToken}\` } : {}) }, body, cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(15000), })` |
| `frontend/src/app/api/auth/session/route.ts:14` | `fetch(\`${config.apiUrl}/api/auth/${session.provider === 'MICROSOFT_ENTRA' ? 'entra' : 'native'}/session\`, { headers: { Authorization: \`Bearer ${session.accessToken}\` }, cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(5000) })` |
| `frontend/src/app/api/backend/[...path]/route.ts:66` | `fetch(target, { method: request.method, headers, body, redirect: 'manual', cache: 'no-store' })` |
| `frontend/src/app/component-advisor/components/[key]/page.tsx:61` | `getAdvisorComponent(canonicalKey, scope, signal)` |
| `frontend/src/app/component-advisor/page.tsx:178` | `getAdvisorSummary(params, signal)` |
| `frontend/src/app/component-advisor/page.tsx:184` | `listAdvisorComponents({ ...params, sort_by: filters.sortBy, sort_order: filters.sortOrder, limit: pageSize, offset }, signal)` |
| `frontend/src/app/component-advisor/recommendations/[id]/page.tsx:45` | `getAdvisorRecommendation(recommendationId, signal)` |
| `frontend/src/app/component-advisor/recommendations/[id]/page.tsx:246` | `getAdvisorCandidateEvidence(recommendationId, candidate!.id, signal)` |
| `frontend/src/app/component-advisor/recommendations/[id]/page.tsx:251` | `getAdvisorCandidateCompatibility(recommendationId, candidate!.id, signal)` |
| `frontend/src/app/kev/page.tsx:209` | `listKevVulnerabilities( { q: filters.search \|\| undefined, vendor: filters.vendor \|\| undefined, product: filters.product \|\| undefined, ransomware: filters.ransomware === 'all' ? undefined : filters.ransomware, date_added_from: filters.dateAddedFrom \|\| undefined, date_added_to: filters.dateAddedTo \|\| undefined, due_date_from: filters.dueDateFrom \|\| undefined, due_date_to: filters.dueDateTo \|\| undefined, catalog_version: filters.catalogVersion \|\| undefined, cwe: filters.cwe \|\| undefined, sort_by: filters.sortBy, sort_order: filters.sortOrder, limit: pageSize, offset, }, signal, )` |
| `frontend/src/app/kev/page.tsx:234` | `getKevFilterOptions({ vendor: filters.vendor \|\| undefined }, signal)` |
| `frontend/src/app/kev/page.tsx:239` | `getKevVulnerability(selectedCve!, signal)` |
| `frontend/src/app/kev/page.tsx:244` | `syncKevCatalog()` |
| `frontend/src/app/page.tsx:82` | `getDashboardSummary(signal, scope)` |
| `frontend/src/app/page.tsx:94` | `getDashboardRuns(scope, 'FINDINGS', 100, signal, true)` |
| `frontend/src/app/platform/page.tsx:167` | `listPlatformTenants('', 1, 5)` |
| `frontend/src/app/products/[id]/page.tsx:111` | `getProduct(id, signal)` |
| `frontend/src/app/products/[id]/page.tsx:117` | `getProductSboms(id, signal)` |
| `frontend/src/app/products/[id]/page.tsx:121` | `getLogicalSboms(id, signal, masterPage)` |
| `frontend/src/app/products/[id]/page.tsx:124` | `updateProduct(id, { current_sbom_mode: mode })` |
| `frontend/src/app/products/[id]/page.tsx:130` | `updateProduct(id, { current_sbom_id: currentSbomId })` |
| `frontend/src/app/projects/page.tsx:34` | `getProjects(signal)` |
| `frontend/src/app/projects/page.tsx:35` | `getDashboardScannedProjectIds(scope, signal)` |
| `frontend/src/app/sboms/[id]/page.tsx:22` | `getSbom(id, signal)` |
| `frontend/src/app/sboms/page.tsx:33` | `getSboms(1, 500, signal, scope, analysed)` |
| `frontend/src/app/schedules/page.tsx:96` | `listSchedules( { scope: scope === 'all' ? undefined : scope, enabled: enabled === 'all' ? undefined : enabled === 'enabled', }, signal, )` |
| `frontend/src/app/schedules/page.tsx:109` | `getProjects(signal)` |
| `frontend/src/app/schedules/page.tsx:114` | `getSboms(1, 500, signal)` |
| `frontend/src/app/schedules/page.tsx:163` | `pauseSchedule(id)` |
| `frontend/src/app/schedules/page.tsx:171` | `resumeSchedule(id)` |
| `frontend/src/app/schedules/page.tsx:179` | `runScheduleNow(id)` |
| `frontend/src/app/schedules/page.tsx:202` | `deleteScopedSchedule('TENANT', sched.tenant_id)` |
| `frontend/src/app/schedules/page.tsx:203` | `deleteScopedSchedule('PRODUCT', sched.product_id)` |
| `frontend/src/app/schedules/page.tsx:205` | `deleteProjectSchedule(sched.project_id, { permanent })` |
| `frontend/src/app/schedules/page.tsx:207` | `deleteSbomSchedule(sched.sbom_id, { permanent })` |
| `frontend/src/app/schedules/page.tsx:222` | `previewScheduleTargets(previewing!.id, signal)` |
| `frontend/src/app/settings/platform/page.tsx:40` | `grantPlatformAdministrator(userId)` |
| `frontend/src/app/settings/platform/page.tsx:50` | `revokePlatformAdministrator(grantId)` |
| `frontend/src/app/settings/platform/tenants/[tenantId]/page.tsx:28` | `getPlatformTenant(id)` |
| `frontend/src/app/settings/platform/tenants/[tenantId]/page.tsx:35` | `recoverPlatformTenantAdmin(id, candidate!.id)` |
| `frontend/src/app/settings/platform/tenants/[tenantId]/page.tsx:40` | `updatePlatformTenantStatus(id, tenant.data?.status === 'ACTIVE' ? 'DISABLED' : 'ACTIVE')` |
| `frontend/src/app/settings/platform/tenants/page.tsx:114` | `listPlatformTenants(tenantSearch, tenantPage)` |
| `frontend/src/app/settings/platform/tenants/page.tsx:140` | `updatePlatformTenantStatus(id, status)` |
| `frontend/src/app/settings/users/audit/page.tsx:21` | `getTenantAuditPage(tenantId, filters)` |
| `frontend/src/app/vex-investigation/page.tsx:282` | `getDashboardVex(signal)` |
| `frontend/src/app/vex-investigation/page.tsx:308` | `getVexInvestigationSummary(filterArgs, signal)` |
| `frontend/src/app/vex-investigation/page.tsx:316` | `listVexInvestigations( { ...filterArgs, sort_by: filters.sortBy, sort_order: filters.sortOrder, limit: pageSize, offset }, signal, )` |
| `frontend/src/app/vex-investigation/page.tsx:326` | `searchVexAssignees(debouncedAssigneeSearch, pageParam, signal)` |
| `frontend/src/components/admin/IamOperations.tsx:14` | `fetch('/api/backend/api/platform/iam/operations', { cache: 'no-store' })` |
| `frontend/src/components/admin/LifecycleProviderSettings.tsx:33` | `listLifecycleProviders(signal, scope)` |
| `frontend/src/components/admin/LifecycleProviderSettings.tsx:41` | `updateLifecycleProvider(key, payload, undefined, scope)` |
| `frontend/src/components/admin/LifecycleProviderSettings.tsx:55` | `testLifecycleProvider(key, undefined, scope)` |
| `frontend/src/components/admin/LifecycleProviderSettings.tsx:65` | `syncLifecycleProvider(key, undefined, scope)` |
| `frontend/src/components/admin/LifecycleProviderSettings.tsx:75` | `setLifecycleProviderSecret(key, { secret_name: name, secret_value: value }, undefined, scope)` |
| `frontend/src/components/admin/LifecycleProviderSettings.tsx:84` | `deleteLifecycleProviderSecret(key, name, undefined, scope)` |
| `frontend/src/components/admin/LifecycleVendorRecordsPage.tsx:42` | `listLifecycleVendorRecords({ search: search \|\| undefined, limit: 100 }, signal)` |
| `frontend/src/components/admin/LifecycleVendorRecordsPage.tsx:49` | `createLifecycleVendorRecord(payload)` |
| `frontend/src/components/admin/LifecycleVendorRecordsPage.tsx:60` | `updateLifecycleVendorRecord(id, payload)` |
| `frontend/src/components/admin/LifecycleVendorRecordsPage.tsx:70` | `deleteLifecycleVendorRecord(id)` |
| `frontend/src/components/admin/LifecycleVendorRecordsPage.tsx:79` | `importLifecycleVendorRecords(records)` |
| `frontend/src/components/admin/LifecycleVendorRecordsPage.tsx:90` | `exportLifecycleVendorRecords()` |
| `frontend/src/components/admin/NativeUserInviteForm.tsx:35` | `fetch(\`/api/backend/api/${platform ? 'platform/native-users' : \`tenants/${tenantId}/native-users\`}\`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(selected ? { 'X-Tenant-ID': selected } : {}) }, body: JSON.stringify({ first_name: data.get('first_name'), last_name: data.get('last_name'), email: data.get('email'), phone: data.get('phone'), tenant_id: tenantId, role_codes: data.getAll('role_codes') }), })` |
| `frontend/src/components/admin/PlatformTenantOverview.tsx:76` | `resendPlatformTenantActivation(Number(tenant.id), administrator!.user_id)` |
| `frontend/src/components/admin/ScopedAdvisorPolicies.tsx:34` | `getAdvisorPolicyHistory(tenantId, definition.kind)` |
| `frontend/src/components/admin/ScopedAdvisorPolicies.tsx:47` | `publishAdvisorPolicy(tenantId, definition.kind, { status, rules: parsed, reason: reason.trim(), row_version: state.row_version })` |
| `frontend/src/components/admin/ScopedAdvisorPolicies.tsx:76` | `getAdvisorPolicy(tenantId, definition.kind)` |
| `frontend/src/components/admin/TenantAuditHistory.tsx:9` | `getTenantAuditHistory(tenantId)` |
| `frontend/src/components/admin/TenantSearchSelect.tsx:23` | `listPlatformTenants(query, page)` |
| `frontend/src/components/admin/TenantUsersAccess.tsx:61` | `getTenantMembers(currentTenantId)` |
| `frontend/src/components/admin/TenantUsersAccess.tsx:67` | `getAssignableTenantRoles(currentTenantId ?? undefined)` |
| `frontend/src/components/admin/TenantUsersAccess.tsx:74` | `addTenantMember(currentTenantId, { user_id: selectedUser.id, roles: initialRoles, })` |
| `frontend/src/components/admin/TenantUsersAccess.tsx:98` | `replaceTenantMemberRoles( currentTenantId, rolesModalMember.user_id, selectedRoles, rolesModalMember.role_assignment_version, )` |
| `frontend/src/components/admin/TenantUsersAccess.tsx:124` | `deactivateTenantMember(currentTenantId, disableModalMember.membership_id)` |
| `frontend/src/components/admin/TenantUsersAccess.tsx:147` | `activateTenantMember(currentTenantId, enableModalMember.membership_id)` |
| `frontend/src/components/admin/TenantUsersAccess.tsx:164` | `removeTenantMember(currentTenantId, removeModalMember.membership_id)` |
| `frontend/src/components/admin/UserLifecycle.tsx:30` | `fetch(\`/api/backend/api${path}\`, { method, headers: { 'Content-Type': 'application/json', ...(!path.startsWith('/platform/') && tenant ? { 'X-Tenant-ID': String(tenant) } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) })` |
| `frontend/src/components/admin/UserSearchCombobox.tsx:81` | `searchTenantUserCandidates(tenantId, query)` |
| `frontend/src/components/admin/UserSearchCombobox.tsx:82` | `searchPlatformTenantAdminCandidates(query)` |
| `frontend/src/components/admin/UserSearchCombobox.tsx:82` | `searchPlatformUsers(query)` |
| `frontend/src/components/ai-fixes/GlobalAiBatchProgress/AiBatchProgressProvider.tsx:71` | `getRunAiFixProgress(runId)` |
| `frontend/src/components/ai-fixes/GlobalAiBatchProgress/AiBatchProgressProvider.tsx:80` | `getRunAiBatch(runId, batchId)` |
| `frontend/src/components/ai-fixes/GlobalAiBatchProgress/AiBatchProgressProvider.tsx:114` | `aiFixStreamUrl(runId)` |
| `frontend/src/components/ai-fixes/GlobalAiBatchProgress/AiBatchProgressProvider.tsx:115` | `aiFixBatchStreamUrl(runId, batchId)` |
| `frontend/src/components/ai-fixes/GlobalAiBatchProgress/AiBatchProgressProvider.tsx:118` | `getRunAiFixProgress(runId)` |
| `frontend/src/components/ai-fixes/GlobalAiBatchProgress/AiBatchProgressProvider.tsx:120` | `getRunAiBatch(runId, batchId)` |
| `frontend/src/components/ai-fixes/GlobalAiBatchProgress/GlobalAiBatchBanner.tsx:66` | `getRunAiFixProgress(runId, signal)` |
| `frontend/src/components/ai-fixes/GlobalAiBatchProgress/GlobalAiBatchBanner.tsx:67` | `getRunAiBatch(runId, batchId, signal)` |
| `frontend/src/components/ai-fixes/GlobalAiBatchProgress/GlobalAiBatchBanner.tsx:92` | `cancelRunAiFixes(runId)` |
| `frontend/src/components/ai-fixes/GlobalAiBatchProgress/GlobalAiBatchBanner.tsx:94` | `cancelRunAiBatch(runId, batchId)` |
| `frontend/src/components/ai-fixes/GlobalAiBatchProgress/useGlobalAiBatchProgress.ts:68` | `getRunAiFixProgress(runId as number, signal)` |
| `frontend/src/components/ai-fixes/GlobalAiBatchProgress/useGlobalAiBatchProgress.ts:70` | `getRunAiBatch(runId as number, batchId, signal)` |
| `frontend/src/components/ai-fixes/Settings/CostDashboard.tsx:35` | `getAiUsageTrend({ days: 30 }, signal)` |
| `frontend/src/components/ai-fixes/Settings/CostDashboard.tsx:41` | `getAiTopCachedFixes({ limit: 20 }, signal)` |
| `frontend/src/components/analysis/FindingsTable.tsx:428` | `upsertRemediation(projectId, payload)` |
| `frontend/src/components/analysis/RunsTable.tsx:84` | `downloadPdfReport({ runId: run.id, title: \`Analysis Report - Run #${run.id}\`, filename: \`sbom-analysis-run-${run.id}.pdf\`, })` |
| `frontend/src/components/analysis/SbomPreflightChecklist.tsx:81` | `getSbomInfo(sbomId as number, signal)` |
| `frontend/src/components/analysis/VulnerabilitiesByScope.tsx:112` | `getVulnerabilities({ severity: severity \|\| undefined, page_size: 2000 }, signal, scope)` |
| `frontend/src/components/auth/LoginCallback.tsx:55` | `fetch('/api/auth/callback', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code, state }), })` |
| `frontend/src/components/auth/MicrosoftSignIn.tsx:17` | `fetch('/api/auth/entra', { cache: 'no-store' })` |
| `frontend/src/components/auth/MicrosoftSignIn.tsx:38` | `fetch('/api/auth/entra', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ accessToken: result.accessToken }) })` |
| `frontend/src/components/auth/NativeAuthForm.tsx:26` | `fetch(\`/api/auth/native/${activation ? 'activate' : 'login'}\`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(activation ? { token, password } : { email: form.get('email'), password }), })` |
| `frontend/src/components/auth/NativePasswordSettings.tsx:9` | `fetch('/api/auth/session')` |
| `frontend/src/components/auth/NativePasswordSettings.tsx:12` | `fetch('/api/auth/native/logout-all', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })` |
| `frontend/src/components/auth/PasswordLifecycleForm.tsx:16` | `fetch('/api/auth/session')` |
| `frontend/src/components/auth/PasswordLifecycleForm.tsx:28` | `fetch(\`/api/auth/native/${action}\`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })` |
| `frontend/src/components/compare/CompareView.tsx:51` | `compareRunsV2( { run_a_id: urlState.runA as number, run_b_id: urlState.runB as number }, signal, )` |
| `frontend/src/components/compare/ExportDialog.tsx:35` | `exportCompare(cacheKey, format)` |
| `frontend/src/components/compare/SelectionBar/RunPicker.tsx:81` | `recentRuns(20, signal)` |
| `frontend/src/components/compare/SelectionBar/RunPicker.tsx:87` | `searchRuns(debounced, 20, signal)` |
| `frontend/src/components/compare/Sparkline/Sparkline.tsx:51` | `getRuns({ sbom_id: sbomId as number, page_size: 30 }, signal)` |
| `frontend/src/components/dashboard/ActivityFeed.tsx:81` | `getRecentSboms(8, signal, scope)` |
| `frontend/src/components/dashboard/ActivityFeed.tsx:86` | `getDashboardRuns(scope ?? { projectId: null, applicationId: null, sbomId: null }, undefined, 12, signal)` |
| `frontend/src/components/dashboard/AiConfigBanner.tsx:42` | `getAnalysisConfig(signal)` |
| `frontend/src/components/dashboard/CounterTiles.tsx:42` | `getDashboardPosture(signal)` |
| `frontend/src/components/dashboard/DashboardFilters.tsx:44` | `getDashboardProjectOptions(signal)` |
| `frontend/src/components/dashboard/DashboardFilters.tsx:49` | `getDashboardApplicationOptions(scope.projectId!, signal)` |
| `frontend/src/components/dashboard/DashboardFilters.tsx:54` | `getVexInvestigationVersions(scope, signal)` |
| `frontend/src/components/dashboard/DashboardFilters.tsx:54` | `getDashboardSbomOptions(scope, signal)` |
| `frontend/src/components/dashboard/LifecycleHealthTiles.tsx:31` | `getDashboardLifecycle(signal)` |
| `frontend/src/components/dashboard/LifecycleHealthTiles.tsx:37` | `getDashboardHealth(signal)` |
| `frontend/src/components/dashboard/LifecycleHealthTiles.tsx:43` | `getDashboardVex(signal)` |
| `frontend/src/components/dashboard/PortfolioOverview.tsx:115` | `getAnalysisConfig(signal)` |
| `frontend/src/components/dashboard/PortfolioOverview.tsx:118` | `getDashboardPriorityFindings(scope, signal)` |
| `frontend/src/components/dashboard/PortfolioOverview.tsx:119` | `getDashboardRuns(scope, undefined, 5, signal)` |
| `frontend/src/components/dashboard/PortfolioTrend.tsx:13` | `getDashboardTrend(days, signal, scope)` |
| `frontend/src/components/dashboard/TopVulnerableSboms.tsx:32` | `getDashboardRuns(scope ?? { projectId: null, applicationId: null, sbomId: null }, 'FINDINGS', 100, signal, true)` |
| `frontend/src/components/dashboard/TrendExplorer.tsx:83` | `getProjects(signal)` |
| `frontend/src/components/dashboard/TrendExplorer.tsx:92` | `getDashboardTrendFiltered(opts, signal, scope)` |
| `frontend/src/components/dashboard/TrendExplorer.tsx:93` | `getDashboardTrendFiltered(opts, signal)` |
| `frontend/src/components/dashboard/VulnerabilityAgePie.tsx:98` | `getVulnerabilityAge(opts, signal, scope)` |
| `frontend/src/components/dashboard/VulnerabilityAgePie.tsx:98` | `getVulnerabilityAge(opts, signal)` |
| `frontend/src/components/dashboard/advanced/CopilotPanel.tsx:88` | `getCopilotBriefing(false, signal)` |
| `frontend/src/components/dashboard/advanced/CopilotPanel.tsx:97` | `getCopilotBriefing(true)` |
| `frontend/src/components/dashboard/advanced/CopilotPanel.tsx:107` | `askCopilot(q)` |
| `frontend/src/components/dashboard/advanced/ExploitationOutlookCard.tsx:87` | `getDashboardExploitation(signal)` |
| `frontend/src/components/dashboard/advanced/ForecastCard.tsx:95` | `getDashboardForecast(signal)` |
| `frontend/src/components/dashboard/advanced/PortfolioRiskMap.tsx:124` | `getDashboardRiskMap(signal)` |
| `frontend/src/components/dashboard/advanced/RemediationPanel.tsx:50` | `getDashboardRemediation(signal)` |
| `frontend/src/components/dashboard/advanced/RemediationPanel.tsx:55` | `getDashboardRemediationStats(signal)` |
| `frontend/src/components/dashboard/advanced/RiskMatrixCard.tsx:99` | `getDashboardRiskMatrix(300, signal)` |
| `frontend/src/components/layout/CommandPalette.tsx:110` | `getRecentSboms(8, signal)` |
| `frontend/src/components/layout/CommandPalette.tsx:117` | `getRuns({ page: 1, page_size: 8 }, signal)` |
| `frontend/src/components/layout/Sidebar.tsx:534` | `getRecentSboms(3, signal)` |
| `frontend/src/components/layout/Sidebar.tsx:541` | `getRuns({ page: 1, page_size: 3 }, signal)` |
| `frontend/src/components/layout/SidebarStatus.tsx:64` | `getHealth(signal)` |
| `frontend/src/components/products/ProductFormDialog.tsx:65` | `updateProduct(product.id, payload)` |
| `frontend/src/components/products/ProductFormDialog.tsx:65` | `createProduct(project.id, payload)` |
| `frontend/src/components/projects/ProjectApplications.tsx:33` | `getEffectiveProductSchedule(productId, signal)` |
| `frontend/src/components/projects/ProjectApplications.tsx:63` | `getProducts(project.id, signal)` |
| `frontend/src/components/projects/ProjectApplications.tsx:73` | `deleteProduct(product.id)` |
| `frontend/src/components/projects/ProjectModal.tsx:74` | `updateProject(project.id, { project_name: values.project_name, project_details: values.project_details, project_status: toStatusInt(values.project_status), })` |
| `frontend/src/components/projects/ProjectModal.tsx:80` | `createProject({ project_name: values.project_name, project_details: values.project_details, project_status: toStatusInt(values.project_status), })` |
| `frontend/src/components/projects/ProjectsTable.tsx:76` | `getProducts(project.id, signal)` |
| `frontend/src/components/projects/ProjectsTable.tsx:149` | `getProjectDeleteImpact(deleteTarget!.id, signal)` |
| `frontend/src/components/projects/ProjectsTable.tsx:156` | `deleteProject(id, { permanent })` |
| `frontend/src/components/reports/ReportNotificationsPage.tsx:30` | `getTenantSchedule(tenantId)` |
| `frontend/src/components/reports/ReportNotificationsPage.tsx:50` | `getReportTargets(form.scope, search)` |
| `frontend/src/components/reports/ReportNotificationsPage.tsx:119` | `downloadReportArtifact(deliveryId, artifactId)` |
| `frontend/src/components/sboms/ComponentVexManager.tsx:19` | `getComponentVulnerabilities(sbomId, component.id, signal)` |
| `frontend/src/components/sboms/ComponentVexManager.tsx:23` | `getVexOverrideHistory(component.id, historyPair!, signal, sbomId)` |
| `frontend/src/components/sboms/Fda510kReportDialog.tsx:101` | `exportFda510kSbomReport(projectId, { selections: sboms.map((sbom) => ({ sbom_id: sbom.id })), metadata, })` |
| `frontend/src/components/sboms/LogicalSbomHistory.tsx:31` | `getLogicalSbom(id, signal)` |
| `frontend/src/components/sboms/LogicalSbomHistory.tsx:32` | `getLogicalSbomVersions(id, signal)` |
| `frontend/src/components/sboms/SbomAutoRepairPanel.tsx:26` | `analyzeSbomRepair(sessionId, signal)` |
| `frontend/src/components/sboms/SbomAutoRepairPanel.tsx:27` | `getLatestSbomRepair(sessionId, signal)` |
| `frontend/src/components/sboms/SbomAutoRepairPanel.tsx:33` | `runSbomRepair(sessionId)` |
| `frontend/src/components/sboms/SbomAutoRepairPanel.tsx:34` | `decideSbomRepair(sessionId, latest.data!.repair_job_id, decision, latest.data!.candidate_sha256)` |
| `frontend/src/components/sboms/SbomAutoRepairPanel.tsx:34` | `decideSbomRepair(sessionId, latest.data!.repair_job_id, decision)` |
| `frontend/src/components/sboms/SbomAutoRepairPanel.tsx:51` | `downloadValidationSessionOriginal(sessionId)` |
| `frontend/src/components/sboms/SbomAutoRepairPanel.tsx:51` | `downloadSbomRepair(sessionId, latest.data!.repair_job_id, kind)` |
| `frontend/src/components/sboms/SbomConversionCard.tsx:63` | `getSbomConversionReport(sbom.id)` |
| `frontend/src/components/sboms/SbomConversionCard.tsx:69` | `getSbom(sbom.id)` |
| `frontend/src/components/sboms/SbomConversionCard.tsx:96` | `convertSbomToCycloneDX(sbom.id)` |
| `frontend/src/components/sboms/SbomConversionCard.tsx:221` | `exportSbomDocument(sbom.id, { format: 'spdx', exportMode: 'original' })` |
| `frontend/src/components/sboms/SbomConversionCard.tsx:234` | `exportSbomDocument(sbom.id, { format: 'cyclonedx', exportMode: 'converted' })` |
| `frontend/src/components/sboms/SbomConversionCard.tsx:245` | `exportSbomDocument(sbom.id, { format: 'cyclonedx', exportMode: 'enriched' })` |
| `frontend/src/components/sboms/SbomConversionCard.tsx:256` | `exportSbomDocument(sbom.id, { format: 'conversion-report' })` |
| `frontend/src/components/sboms/SbomDetail.tsx:327` | `getLifecycleProviderStatus(signal)` |
| `frontend/src/components/sboms/SbomDetail.tsx:335` | `getProjects(signal)` |
| `frontend/src/components/sboms/SbomDetail.tsx:340` | `getProducts(selectedProjectId!, signal)` |
| `frontend/src/components/sboms/SbomDetail.tsx:346` | `getProducts(detailProjectId!, signal)` |
| `frontend/src/components/sboms/SbomDetail.tsx:359` | `updateSbom(sbom.id, { project_id: selectedProjectId, product_id: selectedProductId, change_reason: assignChangeReason \|\| undefined, })` |
| `frontend/src/components/sboms/SbomDetail.tsx:398` | `updateSbom(sbom.id, payload)` |
| `frontend/src/components/sboms/SbomDetail.tsx:439` | `getSbomComponents(sbom.id, { includeDuplicates: showDuplicates, page: componentPage, pageSize: componentPageSize, search: debouncedComponentSearch \|\| undefined, sortBy: compSortKey, sortOrder: compSortDirection, signal, })` |
| `frontend/src/components/sboms/SbomDetail.tsx:453` | `getSbomComponents(sbom.id, { includeDuplicates: false, page: 1, pageSize: 1000, signal, })` |
| `frontend/src/components/sboms/SbomDetail.tsx:472` | `getSbomDedupeReport(sbom.id, signal)` |
| `frontend/src/components/sboms/SbomDetail.tsx:478` | `getRuns({ sbom_id: sbom.id }, signal)` |
| `frontend/src/components/sboms/SbomDetail.tsx:485` | `getSbomInfo(sbom.id, signal)` |
| `frontend/src/components/sboms/SbomDetail.tsx:491` | `getSbomStats(sbom.id, signal)` |
| `frontend/src/components/sboms/SbomDetail.tsx:497` | `getSbomValidationReport(sbom.id, signal)` |
| `frontend/src/components/sboms/SbomDetail.tsx:507` | `getSbomVexStatements(sbom.id, signal)` |
| `frontend/src/components/sboms/SbomDetail.tsx:514` | `getSbomRiskSummary(sbom.id, signal)` |
| `frontend/src/components/sboms/SbomDetail.tsx:522` | `getSbomVersions(sbom.id, signal)` |
| `frontend/src/components/sboms/SbomDetail.tsx:560` | `getVexInvestigationByTriple( { sbom_id: sbom.id, component_id: Number(vexOverrideComponentId), vulnerability_id: vexOverrideVulnerability, }, signal, )` |
| `frontend/src/components/sboms/SbomDetail.tsx:573` | `getComponentVulnerabilities(sbom.id, Number(vexOverrideComponentId), signal)` |
| `frontend/src/components/sboms/SbomDetail.tsx:600` | `getVexOverrideHistory(statement.component_id, statement.vulnerability_id, undefined, sbom.id)` |
| `frontend/src/components/sboms/SbomDetail.tsx:691` | `createWorkspaceForSbom(sbom.id)` |
| `frontend/src/components/sboms/SbomDetail.tsx:742` | `overrideComponentLifecycle(editingComp.id, payload)` |
| `frontend/src/components/sboms/SbomDetail.tsx:799` | `compareSbomVersions(sorted[0], sorted[1])` |
| `frontend/src/components/sboms/SbomDetail.tsx:812` | `restoreSbomVersion(sbom.id, versionId, sbom.created_by ?? undefined)` |
| `frontend/src/components/sboms/SbomDetail.tsx:832` | `refreshSbomLifecycle(sbom.id, true)` |
| `frontend/src/components/sboms/SbomDetail.tsx:848` | `refreshComponentLifecycle(component.id, true)` |
| `frontend/src/components/sboms/SbomDetail.tsx:870` | `uploadSbomVexDocument(sbom.id, { document, source_name: 'Uploaded VEX', })` |
| `frontend/src/components/sboms/SbomDetail.tsx:890` | `discoverSbomVexDocuments(sbom.id, true)` |
| `frontend/src/components/sboms/SbomDetail.tsx:1039` | `exportSbomVulnerabilityExcel(sbom.id)` |
| `frontend/src/components/sboms/SbomDetail.tsx:1240` | `exportSbomVexReportJson(sbom.id)` |
| `frontend/src/components/sboms/SbomDetail.tsx:1249` | `exportSbomVexReportCsv(sbom.id)` |
| `frontend/src/components/sboms/SbomDetail.tsx:1258` | `exportSbomVexReportPack(sbom.id)` |
| `frontend/src/components/sboms/SbomDetail.tsx:1439` | `exportSbomLifecycleReportCsv(sbom.id)` |
| `frontend/src/components/sboms/SbomDetail.tsx:1448` | `exportSbomLifecycleReportPack(sbom.id)` |
| `frontend/src/components/sboms/SbomLifecycleControls.tsx:35` | `getSbomLifecycleHistory(sbom.id, signal)` |
| `frontend/src/components/sboms/SbomLifecycleControls.tsx:37` | `changeSbomLifecycle(sbom.id, next, reason.trim())` |
| `frontend/src/components/sboms/SbomPostureNotice.tsx:36` | `getDashboardPostureVersions(scope, signal)` |
| `frontend/src/components/sboms/SbomQualityPanel.tsx:54` | `getSessionQuality(sessionId, signal)` |
| `frontend/src/components/sboms/SbomQualityPanel.tsx:54` | `getSbomQuality(sbomId!, signal)` |
| `frontend/src/components/sboms/SbomRawViewer.tsx:35` | `getSbomRawChunk(sbomId, offset, RAW_PAGE_SIZE, signal)` |
| `frontend/src/components/sboms/SbomRawViewer.tsx:52` | `downloadSbomOriginal(sbomId)` |
| `frontend/src/components/sboms/SbomUploadModal.tsx:145` | `getProjects(signal)` |
| `frontend/src/components/sboms/SbomUploadModal.tsx:152` | `getSbomTypes(signal)` |
| `frontend/src/components/sboms/SbomUploadModal.tsx:178` | `getLogicalSbomChoices(Number(selectedProductId), signal)` |
| `frontend/src/components/sboms/SbomUploadModal.tsx:179` | `getLogicalSbomVersions(Number(selectedLogicalSbomId), signal)` |
| `frontend/src/components/sboms/SbomUploadModal.tsx:199` | `getProducts(selectedProjectNumber!, signal)` |
| `frontend/src/components/sboms/SbomUploadModal.tsx:207` | `createProduct(selectedProjectNumber!, { name })` |
| `frontend/src/components/sboms/SbomsTable.tsx:134` | `getSbomDeleteImpact(deleteTarget!.id, signal)` |
| `frontend/src/components/sboms/SbomsTable.tsx:146` | `deleteSbom(sbom.id, sbom.created_by ?? '', { permanent })` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:99` | `getValidationSession(sessionId, signal)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:102` | `analyzeSbomRepair(sessionId, signal)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:103` | `getLatestSbomRepair(sessionId, signal)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:108` | `getValidationSessionContent(sessionId, 0, CONTENT_CHUNK_SIZE, signal)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:114` | `getValidationSessionHistory(sessionId, signal)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:119` | `getProject(sessionQuery.data!.project_id!, signal)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:125` | `getProjects(signal)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:131` | `updateValidationSession(sessionId, { project_id: projectId })` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:153` | `saveValidationSessionRepairDraft(sessionId, content, sessionQuery.data?.updated_at)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:170` | `saveValidationSessionRepairDraft(sessionId, content, sessionQuery.data?.updated_at)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:174` | `validateValidationSession(sessionId)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:193` | `getValidationSessionContent( sessionId, loadedContentSize \|\| content.length \|\| initialContentQuery.data?.content.length \|\| 0, CONTENT_CHUNK_SIZE, )` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:210` | `downloadValidationSessionOriginal(sessionId)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:217` | `importValidationSession(sessionId, true)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:229` | `suggestValidationSessionFixes(sessionId, { user_instruction: '' })` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:246` | `applyValidationSessionPatch(sessionId, { patches })` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:291` | `downloadValidationSessionRepairDraft(sessionId)` |
| `frontend/src/components/sboms/repair/LargeFileRepairEditor.tsx:53` | `getValidationSessionContentLines(sessionId, startLine, pageSize, signal)` |
| `frontend/src/components/sboms/repair/LargeFileRepairEditor.tsx:58` | `searchValidationSession(sessionId, query, 'repair_draft', 100, signal)` |
| `frontend/src/components/sboms/repair/LargeFileRepairEditor.tsx:63` | `applyValidationSessionLinePatches(sessionId, [patch])` |
| `frontend/src/components/sboms/repair/RepairQualitySummary.tsx:10` | `getSessionQuality(sessionId, signal)` |
| `frontend/src/components/schedules/ScheduleCard.tsx:97` | `getProjectSchedule(targetId, signal)` |
| `frontend/src/components/schedules/ScheduleCard.tsx:106` | `getEffectiveProductSchedule(targetId, signal)` |
| `frontend/src/components/schedules/ScheduleCard.tsx:107` | `getSbomSchedule(targetId, signal)` |
| `frontend/src/components/schedules/ScheduleCard.tsx:120` | `pauseSchedule(id)` |
| `frontend/src/components/schedules/ScheduleCard.tsx:129` | `resumeSchedule(id)` |
| `frontend/src/components/schedules/ScheduleCard.tsx:140` | `runScheduleNow(id)` |
| `frontend/src/components/schedules/ScheduleCard.tsx:157` | `deleteProjectSchedule(targetId, { permanent })` |
| `frontend/src/components/schedules/ScheduleCard.tsx:159` | `deleteProductSchedule(targetId, { permanent })` |
| `frontend/src/components/schedules/ScheduleCard.tsx:160` | `deleteSbomSchedule(targetId, { permanent })` |
| `frontend/src/components/schedules/ScheduleCard.tsx:174` | `excludeFromParentSchedule(scope as 'PRODUCT' \| 'SBOM', targetId)` |
| `frontend/src/components/schedules/ScheduleCard.tsx:183` | `restoreScheduleInheritance(scope as 'PRODUCT' \| 'SBOM', targetId)` |
| `frontend/src/components/schedules/ScheduleCard.tsx:200` | `previewScheduleTargets(scheduleId!, signal)` |
| `frontend/src/components/schedules/ScheduleEditor.tsx:122` | `upsertScopedSchedule(scope, targetId, payload)` |
| `frontend/src/components/schedules/ScheduleEditor.tsx:123` | `upsertProjectSchedule(targetId, payload)` |
| `frontend/src/components/schedules/ScheduleEditor.tsx:124` | `upsertSbomSchedule(targetId, payload)` |
| `frontend/src/components/settings/ai/ScopedAiConfiguration.tsx:33` | `getEffectiveAiConfiguration(scope, signal)` |
| `frontend/src/components/vex/VexDecisionEditor.tsx:133` | `setVexInvestigationDecision(investigation.id, { status: draft.status, row_version: investigation.row_version, reason: draft.reason.trim(), justification: text(draft.justification), impact_statement: text(draft.impactStatement), action_statement: text(draft.actionStatement), mitigation: text(draft.mitigation), fixed_version: text(draft.fixedVersion), evidence_url: text(draft.evidenceUrl), })` |
| `frontend/src/components/vex/VexDecisionEditor.tsx:145` | `overrideVexStatement( componentId, vulnerabilityId.trim(), { status: draft.status.toLowerCase() as never, reason: draft.reason.trim(), justification: text(draft.justification) ?? null, impact_statement: text(draft.impactStatement) ?? null, action_statement: text(draft.actionStatement) ?? null, mitigation: text(draft.mitigation) ?? null, fixed_version: text(draft.fixedVersion) ?? null, evidence_url: text(draft.evidenceUrl) ?? null, }, undefined, sbomId, )` |
| `frontend/src/components/vex/VexInvestigationDialog.tsx:30` | `getVexInvestigation(row!.id, signal)` |
| `frontend/src/components/vex/VexInvestigationPanel.tsx:41` | `setVexInvestigationAssignment(detail.id, { assigned_to: selected, row_version: savedDetail.row_version, reason: selected ? 'Assignment updated' : 'Assignment removed', })` |
| `frontend/src/components/vex/VexInvestigationPanel.tsx:61` | `resolveVexInvestigationComponent(detail.id, { component_id: Number(componentId), row_version: detail.row_version, reason: \`Bound to component ${componentId} by analyst review\`, })` |
| `frontend/src/components/vex/VexRunHistoryPanel.tsx:16` | `getVexAnalysisRuns(sbomId, signal)` |
| `frontend/src/components/vex/VexRunHistoryPanel.tsx:18` | `getVexRunSnapshot(sbomId, runId, offset, signal)` |
| `frontend/src/components/vex/VexVersionComparisonPanel.tsx:20` | `getVexVersionComparison(sbomId, signal)` |
| `frontend/src/components/vulnerabilities/CveDetailDialog/hooks.ts:36` | `getCveDetail({ cveId: cveId ?? '', scanId: scanId ?? null, ...(componentId != null ? { componentId } : {}) }, signal)` |
| `frontend/src/components/vulnerabilities/CveDetailDialog/hooks.ts:72` | `getCveDetail({ cveId, scanId: scanId ?? null }, signal)` |
| `frontend/src/hooks/useAiCredentials.ts:73` | `listAiCredentials(signal, scope)` |
| `frontend/src/hooks/useAiCredentials.ts:84` | `createAiCredential(body, undefined, scope)` |
| `frontend/src/hooks/useAiCredentials.ts:100` | `updateAiCredential(id, body, undefined, scope)` |
| `frontend/src/hooks/useAiCredentials.ts:112` | `deleteAiCredential(id, undefined, scope)` |
| `frontend/src/hooks/useAiCredentials.ts:126` | `setAiCredentialDefault(id, undefined, scope)` |
| `frontend/src/hooks/useAiCredentials.ts:138` | `setAiCredentialFallback(id, undefined, scope)` |
| `frontend/src/hooks/useAiCredentials.ts:168` | `testAiCredentialUnsaved(body, undefined, scope)` |
| `frontend/src/hooks/useAiCredentials.ts:172` | `testAiCredentialSaved(id, undefined, scope)` |
| `frontend/src/hooks/useAiCredentials.ts:188` | `listAiProviderModels(credentialId, signal, scope)` |
| `frontend/src/hooks/useAiCredentials.ts:198` | `refreshAiProviderModels(credentialId, undefined, scope)` |
| `frontend/src/hooks/useAiCredentials.ts:208` | `selectAiProviderModel(credentialId, modelId, undefined, scope)` |
| `frontend/src/hooks/useAiCredentials.ts:222` | `testAiProviderModel(credentialId, modelId, undefined, scope)` |
| `frontend/src/hooks/useAiCredentials.ts:235` | `getAiCredentialSettings(signal, scope)` |
| `frontend/src/hooks/useAiCredentials.ts:252` | `updateAiCredentialSettings(body, undefined, scope)` |
| `frontend/src/hooks/useAiCredentials.ts:269` | `listAiProviderCatalog(signal, scope)` |
| `frontend/src/hooks/useAiCredentials.ts:285` | `getRunBatchEstimate(runId as number, signal)` |
| `frontend/src/hooks/useAiFix.ts:81` | `getFindingAiFix(findingId as number, { providerName }, signal)` |
| `frontend/src/hooks/useAiFix.ts:88` | `generateFindingAiFix(findingId as number, { providerName })` |
| `frontend/src/hooks/useAiFix.ts:99` | `regenerateFindingAiFix(findingId as number, { providerName })` |
| `frontend/src/hooks/useAiFix.ts:145` | `getRunAiFixProgress(runId as number, signal)` |
| `frontend/src/hooks/useAiFix.ts:166` | `aiFixStreamUrl(runId as number)` |
| `frontend/src/hooks/useAiFix.ts:206` | `triggerRunAiFixes(runId, body)` |
| `frontend/src/hooks/useAiFix.ts:223` | `cancelRunAiFixes(runId)` |
| `frontend/src/hooks/useAiFix.ts:242` | `listRunAiFixes(runId as number, signal)` |
| `frontend/src/hooks/useAiFix.ts:282` | `estimateRunAiFixesScoped(runId as number, debouncedScope, signal)` |
| `frontend/src/hooks/useAiFix.ts:297` | `triggerRunAiFixes(runId, body)` |
| `frontend/src/hooks/useAiFix.ts:321` | `listRunAiBatches(runId as number, signal)` |
| `frontend/src/hooks/useAiFix.ts:332` | `cancelRunAiBatch(runId, batchId)` |
| `frontend/src/hooks/useAiFix.ts:361` | `listAiProviders(signal)` |
| `frontend/src/hooks/useAiFix.ts:367` | `listAiPricing(signal)` |
| `frontend/src/hooks/useAiFix.ts:373` | `getAiUsageSummary(signal)` |
| `frontend/src/hooks/useAnalysisStream.ts:147` | `fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Idempotency-Key': \`analysis-sbom-${sbomId}-${randomId}\`, 'X-Tenant-ID': tenantId, }, body: JSON.stringify({ sources: initialSources, nvd_api_key: options.nvdApiKey ?? null, github_token: options.githubToken ?? null, }), signal: controller.signal, })` |
| `frontend/src/hooks/useAuth.tsx:201` | `fetch('/api/auth/session', { credentials: 'include', cache: 'no-store' })` |
| `frontend/src/hooks/useAuth.tsx:223` | `fetch(\`${BASE_URL}/api/auth/me\`, { credentials: 'include', headers, cache: 'no-store' })` |
| `frontend/src/hooks/useAuth.tsx:231` | `fetch(\`${BASE_URL}/api/auth/me\`, { credentials: 'include', headers, cache: 'no-store' })` |
| `frontend/src/hooks/useAuth.tsx:300` | `fetch(\`${BASE_URL}/api/tenants\`, { credentials: 'include', headers, cache: 'no-store' })` |
| `frontend/src/hooks/useAuth.tsx:343` | `fetch(\`${BASE_URL}/api/auth/me\`, { credentials: 'include', headers: reFetchHeaders, cache: 'no-store' })` |
| `frontend/src/hooks/useAuth.tsx:397` | `fetch(\`${BASE_URL}/api/auth/me\`, { credentials: 'include', headers: { 'X-Tenant-ID': autoSelectedIdStr }, cache: 'no-store' })` |
| `frontend/src/hooks/useAuth.tsx:548` | `fetch('/api/auth/logout', { method: 'POST', credentials: 'include', cache: 'no-store', })` |
| `frontend/src/hooks/useBackgroundAnalysis.ts:79` | `analyzeSbom(sbomId)` |
| `frontend/src/hooks/useComponentAdvisorMutations.ts:31` | `createAdvisorRecommendation({ canonical_key: args.canonicalKey, trigger_type: args.trigger }, args.scope)` |
| `frontend/src/hooks/useComponentAdvisorMutations.ts:41` | `evaluateAdvisorRecommendation(recommendationId)` |
| `frontend/src/hooks/useComponentAdvisorMutations.ts:52` | `decideAdvisorRecommendation(recommendationId, { decision: args.decision, reason: args.reason, row_version: args.rowVersion, ...(args.candidateId ? { candidate_id: args.candidateId } : {}), })` |
| `frontend/src/hooks/usePendingAnalysisRecovery.ts:32` | `getRuns({ sbom_id: sbomId, page: 1, page_size: 1 })` |
| `frontend/src/hooks/useReportNotifications.ts:7` | `getReportSubscriptions(tenantId)` |
| `frontend/src/hooks/useReportNotifications.ts:8` | `getReportDeliveries(allTenant, status, deliveryId)` |
| `frontend/src/hooks/useReportNotifications.ts:11` | `updateReportSubscription(id, body)` |
| `frontend/src/hooks/useReportNotifications.ts:11` | `createReportSubscription(body)` |
| `frontend/src/hooks/useReportNotifications.ts:15` | `updateReportSubscription(id, { enabled })` |
| `frontend/src/hooks/useSbomMutations.ts:45` | `uploadSbom(payload)` |
| `frontend/src/hooks/useSbomMutations.ts:65` | `revalidateSbom(sbomId)` |
| `frontend/src/hooks/useSbomsList.ts:14` | `getSboms(1, SBOMS_LIST_PAGE_SIZE, signal)` |
| `frontend/src/lib/api.ts:141` | `fetch('/api/auth/session', { cache: 'no-store' })` |
| `frontend/src/lib/api.ts:326` | `fetch(url, { ...rest, signal: controller.signal })` |

### Appendix D — local state and effect inventory

Initializers are shown to distinguish form/visibility state from server-derived copies. Effects are summarized to 220 characters; their full bodies are at the cited locations. This is an inventory, not a claim every state variable has a synchronization defect.

| Location | Local state initializer |
|---|---|
| `frontend/src/app/analysis/[id]/page.tsx:68` | `[severityFilter, setSeverityFilter] = useState(() => severityFromUrl)` |
| `frontend/src/app/analysis/[id]/page.tsx:73` | `[filter, setFilter] = useState<FindingsFilterState>(() => ({ ...DEFAULT_FILTERS, severityFilter: severityFromUrl, kevOnly: kevOnlyFromUrl, kevStatus: kevOnlyFromUrl ? 'kev' : 'all', hasFixOnly: hasFixOnlyFromUrl, epssMinPct: epssMinPctFromUrl, matchReasonFilter: needsReviewFromUrl ? 'not_verified' : 'all', }))` |
| `frontend/src/app/analysis/[id]/page.tsx:85` | `[selectedIds, setSelectedIds] = useState<ReadonlySet<number>>( () => new Set(), )` |
| `frontend/src/app/analysis/[id]/page.tsx:103` | `[pdfDownloading, setPdfDownloading] = useState(false)` |
| `frontend/src/app/analysis/[id]/page.tsx:104` | `[csvDownloading, setCsvDownloading] = useState(false)` |
| `frontend/src/app/analysis/[id]/page.tsx:105` | `[sarifDownloading, setSarifDownloading] = useState(false)` |
| `frontend/src/app/analysis/compare/_v1/page.tsx:108` | `[filter, setFilter] = useState('')` |
| `frontend/src/app/analysis/page.tsx:62` | `[selectedForCompare, setSelectedForCompare] = useState<Set<number>>(new Set())` |
| `frontend/src/app/analysis/page.tsx:63` | `[selectedSources, setSelectedSources] = useState<SourceKey[]>(DEFAULT_SOURCES)` |
| `frontend/src/app/component-advisor/components/[key]/page.tsx:66` | `[trigger, setTrigger] = useState<RecommendationTrigger \| ''>('')` |
| `frontend/src/app/component-advisor/components/[key]/page.tsx:67` | `[alreadyOpen, setAlreadyOpen] = useState<number \| null>(null)` |
| `frontend/src/app/component-advisor/page.tsx:138` | `[filters, setFilters] = useState<Filters>(() => readFilters(searchParams))` |
| `frontend/src/app/component-advisor/page.tsx:139` | `[searchInput, setSearchInput] = useState(filters.q)` |
| `frontend/src/app/component-advisor/page.tsx:140` | `[page, setPage] = useState(() => Math.max(1, Number(searchParams.get('page')) \|\| 1))` |
| `frontend/src/app/component-advisor/page.tsx:141` | `[pageSize, setPageSize] = useState(DEFAULT_PAGE_SIZE)` |
| `frontend/src/app/component-advisor/page.tsx:142` | `[scope, setScope] = useState<DashboardFilterScope>(() => ({ projectId: positiveOrNull(searchParams.get('project_id')), applicationId: positiveOrNull(searchParams.get('product_id')), sbomId: positiveOrNull(searchParams.get('sbom_id')), }))` |
| `frontend/src/app/component-advisor/recommendations/[id]/page.tsx:49` | `[evidenceFor, setEvidenceFor] = useState<AdvisorCandidate \| null>(null)` |
| `frontend/src/app/component-advisor/recommendations/[id]/page.tsx:50` | `[pending, setPending] = useState<{ decision: RecommendationDecision; candidate?: AdvisorCandidate } \| null>(null)` |
| `frontend/src/app/component-advisor/recommendations/[id]/page.tsx:306` | `[reason, setReason] = useState('')` |
| `frontend/src/app/kev/page.tsx:148` | `[initial] = useState(() => initialState(searchParams))` |
| `frontend/src/app/kev/page.tsx:149` | `[filters, setFilters] = useState<KevFilters>(initial.filters)` |
| `frontend/src/app/kev/page.tsx:150` | `[searchInput, setSearchInput] = useState(initial.filters.search)` |
| `frontend/src/app/kev/page.tsx:151` | `[page, setPage] = useState(initial.page)` |
| `frontend/src/app/kev/page.tsx:152` | `[pageSize, setPageSize] = useState(initial.pageSize)` |
| `frontend/src/app/kev/page.tsx:153` | `[advancedOpen, setAdvancedOpen] = useState( Boolean( initial.filters.dateAddedFrom \|\| initial.filters.dateAddedTo \|\| initial.filters.dueDateFrom \|\| initial.filters.dueDateTo \|\| initial.filters.catalogVersion \|\| initial.filters.cwe, ), )` |
| `frontend/src/app/kev/page.tsx:163` | `[selectedCve, setSelectedCve] = useState<string \| null>(null)` |
| `frontend/src/app/kev/page.tsx:164` | `[lastSync, setLastSync] = useState<KevSyncResult \| null>(null)` |
| `frontend/src/app/products/[id]/page.tsx:106` | `[masterPage, setMasterPage] = useState(1)` |
| `frontend/src/app/products/[id]/page.tsx:107` | `[showUpload, setShowUpload] = useState(false)` |
| `frontend/src/app/projects/page.tsx:21` | `[showCreate, setShowCreate] = useState(false)` |
| `frontend/src/app/projects/page.tsx:22` | `[visibleIds, setVisibleIds] = useState<number[] \| null>(null)` |
| `frontend/src/app/providers.tsx:14` | `[queryClient] = useState( () => new QueryClient({ defaultOptions: { queries: { // 30s was too aggressive: navigating away for >30s and back // triggered a full skeleton cycle on return because the // cache was already stale. Dashboard counts / trend data // change minute-to-minute at most, so 5 min is the right // budget. Routes that need fresher data (analysis runs in // flight) can override per-query. staleTime: 5 * 60_000, // Window-focus refetch double-counts work when the same tab // navigates away and back — the route remount already // refetches when staleTime expires. refetchOnWindowFocus: false, retry: 1, }, }, }) )` |
| `frontend/src/app/sboms/page.tsx:20` | `[showUpload, setShowUpload] = useState(false)` |
| `frontend/src/app/schedules/page.tsx:86` | `[scope, setScope] = useState<ScopeFilter>('all')` |
| `frontend/src/app/schedules/page.tsx:87` | `[enabled, setEnabled] = useState<EnabledFilter>('all')` |
| `frontend/src/app/schedules/page.tsx:88` | `[search, setSearch] = useState('')` |
| `frontend/src/app/schedules/page.tsx:89` | `[editing, setEditing] = useState<AnalysisSchedule \| null>(null)` |
| `frontend/src/app/schedules/page.tsx:90` | `[confirmDelete, setConfirmDelete] = useState<AnalysisSchedule \| null>(null)` |
| `frontend/src/app/schedules/page.tsx:91` | `[previewing, setPreviewing] = useState<AnalysisSchedule \| null>(null)` |
| `frontend/src/app/settings/platform/page.tsx:30` | `[selectedUser, setSelectedUser] = useState<UserSearchResult \| null>(null)` |
| `frontend/src/app/settings/platform/page.tsx:31` | `[revokeTarget, setRevokeTarget] = useState<{ id: number; name: string } \| null>(null)` |
| `frontend/src/app/settings/platform/tenants/[tenantId]/page.tsx:26` | `[candidate, setCandidate] = useState<UserSearchResult \| null>(null)` |
| `frontend/src/app/settings/platform/tenants/[tenantId]/page.tsx:27` | `[confirm, setConfirm] = useState(false)` |
| `frontend/src/app/settings/platform/tenants/page.tsx:98` | `[formOpen, setFormOpen] = useState(false)` |
| `frontend/src/app/settings/platform/tenants/page.tsx:102` | `[form, setForm] = useState<CreateTenantRequest>(EMPTY_FORM)` |
| `frontend/src/app/settings/platform/tenants/page.tsx:103` | `[adminMode, setAdminMode] = useState<'existing' \| 'invite'>('existing')` |
| `frontend/src/app/settings/platform/tenants/page.tsx:104` | `[tenantSearch, setTenantSearch] = useState('')` |
| `frontend/src/app/settings/platform/tenants/page.tsx:105` | `[tenantPage, setTenantPage] = useState(1)` |
| `frontend/src/app/settings/platform/tenants/page.tsx:106` | `[selectedInitialAdmin, setSelectedInitialAdmin] = useState<UserSearchResult \| null>(null)` |
| `frontend/src/app/settings/platform/tenants/page.tsx:107` | `[slugEdited, setSlugEdited] = useState(false)` |
| `frontend/src/app/settings/platform/tenants/page.tsx:108` | `[fieldErrors, setFieldErrors] = useState<Partial<Record<keyof CreateTenantRequest, string>>>({})` |
| `frontend/src/app/settings/platform/tenants/page.tsx:110` | `[disableTarget, setDisableTarget] = useState<{ id: number \| string; name: string } \| null>(null)` |
| `frontend/src/app/settings/users/audit/page.tsx:18` | `[filters, setFilters] = useState({ page: 1, page_size: 25, q: '', category: '', outcome: '', from_time: '', to_time: '' })` |
| `frontend/src/app/settings/users/audit/page.tsx:19` | `[detail, setDetail] = useState<TenantAuditEvent \| null>(null)` |
| `frontend/src/app/vex-investigation/page.tsx:195` | `[mobileFiltersOpen, setMobileFiltersOpen] = useState(false)` |
| `frontend/src/app/vex-investigation/page.tsx:196` | `[assigneeSearch, setAssigneeSearch] = useState('')` |
| `frontend/src/app/vex-investigation/page.tsx:197` | `[debouncedAssigneeSearch, setDebouncedAssigneeSearch] = useState('')` |
| `frontend/src/app/vex-investigation/page.tsx:198` | `[assigneeLabel, setAssigneeLabel] = useState('')` |
| `frontend/src/app/vex-investigation/page.tsx:204` | `[initial] = useState(() => initialState(searchParams))` |
| `frontend/src/app/vex-investigation/page.tsx:205` | `[filters, setFilters] = useState<Filters>(initial.filters)` |
| `frontend/src/app/vex-investigation/page.tsx:206` | `[searchInput, setSearchInput] = useState(initial.filters.search)` |
| `frontend/src/app/vex-investigation/page.tsx:207` | `[componentInput, setComponentInput] = useState(initial.filters.component)` |
| `frontend/src/app/vex-investigation/page.tsx:208` | `[page, setPage] = useState(initial.page)` |
| `frontend/src/app/vex-investigation/page.tsx:209` | `[pageSize, setPageSize] = useState(initial.pageSize)` |
| `frontend/src/app/vex-investigation/page.tsx:210` | `[selected, setSelected] = useState<{ row: VexInvestigationRow; tab: 'details' \| 'investigation' } \| null>(null)` |
| `frontend/src/app/vex-investigation/page.tsx:213` | `[scope, setScope] = useState<DashboardFilterScope>(() => ({ projectId: positiveOrNull(searchParams.get('project_id')), applicationId: positiveOrNull(searchParams.get('product_id')), sbomId: positiveOrNull(searchParams.get('sbom_id')), }))` |
| `frontend/src/components/admin/IamOperations.tsx:8` | `[snapshot, setSnapshot] = useState<Snapshot \| null>(null)` |
| `frontend/src/components/admin/IamOperations.tsx:9` | `[error, setError] = useState(false)` |
| `frontend/src/components/admin/IamOperations.tsx:10` | `[revision, setRevision] = useState(0)` |
| `frontend/src/components/admin/LifecycleProviderForm.tsx:30` | `[enabled, setEnabled] = useState(provider.enabled)` |
| `frontend/src/components/admin/LifecycleProviderForm.tsx:31` | `[priority, setPriority] = useState(String(provider.priority))` |
| `frontend/src/components/admin/LifecycleProviderForm.tsx:32` | `[baseUrl, setBaseUrl] = useState(provider.base_url ?? '')` |
| `frontend/src/components/admin/LifecycleProviderForm.tsx:33` | `[feedUrls, setFeedUrls] = useState(provider.feed_urls.join('\n'))` |
| `frontend/src/components/admin/LifecycleProviderForm.tsx:34` | `[timeout, setTimeoutValue] = useState(String(provider.timeout_seconds))` |
| `frontend/src/components/admin/LifecycleProviderForm.tsx:35` | `[maxRetries, setMaxRetries] = useState(String(provider.max_retries))` |
| `frontend/src/components/admin/LifecycleProviderForm.tsx:36` | `[circuitBreaker, setCircuitBreaker] = useState(provider.circuit_breaker_enabled)` |
| `frontend/src/components/admin/LifecycleProviderForm.tsx:37` | `[knownDays, setKnownDays] = useState(provider.cache_ttl.known_days?.toString() ?? '')` |
| `frontend/src/components/admin/LifecycleProviderForm.tsx:38` | `[unknownHours, setUnknownHours] = useState(provider.cache_ttl.unknown_hours?.toString() ?? '')` |
| `frontend/src/components/admin/LifecycleProviderForm.tsx:39` | `[failureMinutes, setFailureMinutes] = useState(provider.cache_ttl.failure_minutes?.toString() ?? '')` |
| `frontend/src/components/admin/LifecycleProviderForm.tsx:40` | `[deprecatedDays, setDeprecatedDays] = useState(provider.cache_ttl.deprecated_days?.toString() ?? '')` |
| `frontend/src/components/admin/LifecycleProviderForm.tsx:41` | `[configText, setConfigText] = useState(JSON.stringify(provider.config ?? {}, null, 2))` |
| `frontend/src/components/admin/LifecycleProviderForm.tsx:42` | `[secretValue, setSecretValue] = useState('')` |
| `frontend/src/components/admin/LifecycleProviderSettings.tsx:28` | `[editing, setEditing] = useState<LifecycleProviderConfig \| null>(null)` |
| `frontend/src/components/admin/LifecycleProviderSettings.tsx:29` | `[testResult, setTestResult] = useState<Record<string, LifecycleProviderTestResult>>({})` |
| `frontend/src/components/admin/LifecycleVendorRecordsPage.tsx:35` | `[search, setSearch] = useState('')` |
| `frontend/src/components/admin/LifecycleVendorRecordsPage.tsx:36` | `[editing, setEditing] = useState<LifecycleVendorRecord \| null>(null)` |
| `frontend/src/components/admin/LifecycleVendorRecordsPage.tsx:37` | `[creating, setCreating] = useState(false)` |
| `frontend/src/components/admin/LifecycleVendorRecordsPage.tsx:38` | `[importText, setImportText] = useState('')` |
| `frontend/src/components/admin/LifecycleVendorRecordsPage.tsx:241` | `[form, setForm] = useState<LifecycleVendorRecordPayload>({ vendor_name: initial.vendor_name ?? '', product_name: initial.product_name ?? '', product_aliases: initial.product_aliases ?? [], ecosystem: initial.ecosystem ?? 'generic', version_pattern: initial.version_pattern ?? '', lifecycle_status: initial.lifecycle_status ?? 'EOL', maintenance_status: initial.maintenance_status ?? '', eol_date: initial.eol_date ?? '', eos_date: initial.eos_date ?? '', eof_date: initial.eof_date ?? '', latest_supported_version: initial.latest_supported_version ?? '', recommended_version: initial.recommended_version ?? '', evidence_url: initial.evidence_url ?? '', confidence: initial.confidence ?? 'High', enabled: initial.enabled ?? true, })` |
| `frontend/src/components/admin/ManageRolesModal.tsx:50` | `[draftRoles, setDraftRoles] = useState<Set<string>>(initialSelectedCodes)` |
| `frontend/src/components/admin/ManageRolesModal.tsx:51` | `[error, setError] = useState<string \| null>(errorMessage)` |
| `frontend/src/components/admin/MemberActionMenu.tsx:31` | `[open, setOpen] = useState(false)` |
| `frontend/src/components/admin/MemberActionMenu.tsx:32` | `[positionStyle, setPositionStyle] = useState<{ top: number; left: number }>({ top: 0, left: 0 })` |
| `frontend/src/components/admin/MembershipConfirmDialogs.tsx:26` | `[error, setError] = useState<string \| null>(null)` |
| `frontend/src/components/admin/MembershipConfirmDialogs.tsx:92` | `[error, setError] = useState<string \| null>(null)` |
| `frontend/src/components/admin/MembershipConfirmDialogs.tsx:153` | `[confirmedCheckbox, setConfirmedCheckbox] = useState(false)` |
| `frontend/src/components/admin/MembershipConfirmDialogs.tsx:154` | `[error, setError] = useState<string \| null>(null)` |
| `frontend/src/components/admin/NativeUserInviteForm.tsx:20` | `[message, setMessage] = useState('')` |
| `frontend/src/components/admin/NativeUserInviteForm.tsx:21` | `[busy, setBusy] = useState(false)` |
| `frontend/src/components/admin/NativeUserInviteForm.tsx:22` | `[selectedTenant, setSelectedTenant] = useState<TenantSummary \| null>(null)` |
| `frontend/src/components/admin/NativeUserInviteForm.tsx:23` | `[conflictTenant, setConflictTenant] = useState<number \| null>(null)` |
| `frontend/src/components/admin/PlatformTenantOverview.tsx:70` | `[confirmOpen, setConfirmOpen] = useState(false)` |
| `frontend/src/components/admin/PlatformTenantOverview.tsx:71` | `[deliveryStatus, setDeliveryStatus] = useState<string \| null>(null)` |
| `frontend/src/components/admin/ScopedAdvisorPolicies.tsx:22` | `[status, setStatus] = useState<AdvisorPolicyStatus>(initialStatus)` |
| `frontend/src/components/admin/ScopedAdvisorPolicies.tsx:23` | `[rules, setRules] = useState(JSON.stringify(owned?.status === 'ACTIVE' ? owned.rules : state.effective?.rules ?? definition.example, null, 2))` |
| `frontend/src/components/admin/ScopedAdvisorPolicies.tsx:24` | `[reason, setReason] = useState('')` |
| `frontend/src/components/admin/ScopedAdvisorPolicies.tsx:25` | `[error, setError] = useState('')` |
| `frontend/src/components/admin/ScopedAdvisorPolicies.tsx:26` | `[saved, setSaved] = useState(false)` |
| `frontend/src/components/admin/ScopedAdvisorPolicies.tsx:27` | `[saving, setSaving] = useState(false)` |
| `frontend/src/components/admin/ScopedAdvisorPolicies.tsx:28` | `[conflict, setConflict] = useState(false)` |
| `frontend/src/components/admin/TenantSearchSelect.tsx:11` | `[open, setOpen] = useState(false)` |
| `frontend/src/components/admin/TenantSearchSelect.tsx:12` | `[query, setQuery] = useState('')` |
| `frontend/src/components/admin/TenantSearchSelect.tsx:13` | `[page, setPage] = useState(1)` |
| `frontend/src/components/admin/TenantSearchSelect.tsx:14` | `[tenants, setTenants] = useState<TenantSummary[]>([])` |
| `frontend/src/components/admin/TenantSearchSelect.tsx:15` | `[error, setError] = useState('')` |
| `frontend/src/components/admin/TenantSearchSelect.tsx:16` | `[revision, setRevision] = useState(0)` |
| `frontend/src/components/admin/TenantUsersAccess.tsx:46` | `[selectedUser, setSelectedUser] = useState<UserSearchResult \| null>(null)` |
| `frontend/src/components/admin/TenantUsersAccess.tsx:47` | `[initialRoles, setInitialRoles] = useState<TenantRole[]>(['VIEWER'])` |
| `frontend/src/components/admin/TenantUsersAccess.tsx:50` | `[rolesModalMember, setRolesModalMember] = useState<MemberItem \| null>(null)` |
| `frontend/src/components/admin/TenantUsersAccess.tsx:51` | `[disableModalMember, setDisableModalMember] = useState<MemberItem \| null>(null)` |
| `frontend/src/components/admin/TenantUsersAccess.tsx:52` | `[enableModalMember, setEnableModalMember] = useState<MemberItem \| null>(null)` |
| `frontend/src/components/admin/TenantUsersAccess.tsx:53` | `[removeModalMember, setRemoveModalMember] = useState<MemberItem \| null>(null)` |
| `frontend/src/components/admin/TenantUsersAccess.tsx:55` | `[actionLoading, setActionLoading] = useState(false)` |
| `frontend/src/components/admin/TenantUsersAccess.tsx:56` | `[inviteOpen, setInviteOpen] = useState(false)` |
| `frontend/src/components/admin/TenantUsersAccess.tsx:57` | `[inviteBusy, setInviteBusy] = useState(false)` |
| `frontend/src/components/admin/UserActionsMenu.tsx:6` | `[open, setOpen] = useState(false)` |
| `frontend/src/components/admin/UserLifecycle.tsx:48` | `[search, setSearch] = useState('')` |
| `frontend/src/components/admin/UserLifecycle.tsx:49` | `[status, setStatus] = useState('')` |
| `frontend/src/components/admin/UserLifecycle.tsx:50` | `[role, setRole] = useState('')` |
| `frontend/src/components/admin/UserLifecycle.tsx:51` | `[provider, setProvider] = useState('')` |
| `frontend/src/components/admin/UserLifecycle.tsx:52` | `[tenantFilter, setTenantFilter] = useState<TenantSummary \| null>(null)` |
| `frontend/src/components/admin/UserLifecycle.tsx:53` | `[newTenant, setNewTenant] = useState<TenantSummary \| null>(null)` |
| `frontend/src/components/admin/UserLifecycle.tsx:54` | `[sort, setSort] = useState('name')` |
| `frontend/src/components/admin/UserLifecycle.tsx:55` | `[page, setPage] = useState(1)` |
| `frontend/src/components/admin/UserLifecycle.tsx:56` | `[rows, setRows] = useState<User[]>([])` |
| `frontend/src/components/admin/UserLifecycle.tsx:57` | `[total, setTotal] = useState(0)` |
| `frontend/src/components/admin/UserLifecycle.tsx:58` | `[selected, setSelected] = useState<User \| null>(null)` |
| `frontend/src/components/admin/UserLifecycle.tsx:59` | `[detail, setDetail] = useState<User \| null>(null)` |
| `frontend/src/components/admin/UserLifecycle.tsx:60` | `[loading, setLoading] = useState(true)` |
| `frontend/src/components/admin/UserLifecycle.tsx:61` | `[busy, setBusy] = useState(false)` |
| `frontend/src/components/admin/UserLifecycle.tsx:62` | `[error, setError] = useState('')` |
| `frontend/src/components/admin/UserLifecycle.tsx:63` | `[directoryError, setDirectoryError] = useState('')` |
| `frontend/src/components/admin/UserLifecycle.tsx:64` | `[revision, setRevision] = useState(0)` |
| `frontend/src/components/admin/UserLifecycle.tsx:65` | `[confirmation, setConfirmation] = useState<{ text: string; run: () => Promise<void> } \| null>(null)` |
| `frontend/src/components/admin/UserSearchCombobox.tsx:44` | `[query, setQuery] = useState('')` |
| `frontend/src/components/admin/UserSearchCombobox.tsx:45` | `[results, setResults] = useState<UserSearchResult[]>([])` |
| `frontend/src/components/admin/UserSearchCombobox.tsx:46` | `[loading, setLoading] = useState(false)` |
| `frontend/src/components/admin/UserSearchCombobox.tsx:47` | `[open, setOpen] = useState(false)` |
| `frontend/src/components/admin/UserSearchCombobox.tsx:48` | `[searchError, setSearchError] = useState<string \| null>(null)` |
| `frontend/src/components/admin/UserSearchCombobox.tsx:49` | `[showTechDetails, setShowTechDetails] = useState(false)` |
| `frontend/src/components/ai-fixes/AiFixSection/UpgradeCommandCard.tsx:30` | `[copied, setCopied] = useState(false)` |
| `frontend/src/components/ai-fixes/GlobalAiBatchProgress/AiBatchProgressProvider.tsx:232` | `[tracked, setTracked] = useState<Map<string, AiBatchTrackingKey>>( () => new Map(), )` |
| `frontend/src/components/ai-fixes/RunBatchProgress/RunBatchProgress.tsx:227` | `[showWarning, setShowWarning] = useState(false)` |
| `frontend/src/components/analysis/FindingFilterPanel.tsx:81` | `[expanded, setExpanded] = useState(false)` |
| `frontend/src/components/analysis/FindingFilterPanel.tsx:82` | `[presets, setPresets] = useState<FindingsFilterPreset[]>([])` |
| `frontend/src/components/analysis/FindingFilterPanel.tsx:83` | `[showPresets, setShowPresets] = useState(false)` |
| `frontend/src/components/analysis/FindingFilterPanel.tsx:84` | `[presetName, setPresetName] = useState('')` |
| `frontend/src/components/analysis/FindingsTable.tsx:353` | `[internalFilter, setInternalFilter] = useState<FindingsFilterState>(() => ({ ...DEFAULT_FILTERS, severityFilter, }))` |
| `frontend/src/components/analysis/FindingsTable.tsx:378` | `[density, setDensity] = useState<Density>('comfortable')` |
| `frontend/src/components/analysis/FindingsTable.tsx:379` | `[expandedRows, setExpandedRows] = useState<Record<number, boolean>>({})` |
| `frontend/src/components/analysis/FindingsTable.tsx:387` | `[remediationFinding, setRemediationFinding] = useState<EnrichedFinding \| null>(null)` |
| `frontend/src/components/analysis/FindingsTable.tsx:388` | `[remStatus, setRemStatus] = useState('Open')` |
| `frontend/src/components/analysis/FindingsTable.tsx:389` | `[remOwner, setRemOwner] = useState('')` |
| `frontend/src/components/analysis/FindingsTable.tsx:390` | `[remDueDate, setRemDueDate] = useState('')` |
| `frontend/src/components/analysis/FindingsTable.tsx:391` | `[remResolutionDate, setRemResolutionDate] = useState('')` |
| `frontend/src/components/analysis/FindingsTable.tsx:392` | `[remFixedVersion, setRemFixedVersion] = useState('')` |
| `frontend/src/components/analysis/FindingsTable.tsx:393` | `[remFixNotes, setRemFixNotes] = useState('')` |
| `frontend/src/components/analysis/FindingsTable.tsx:394` | `[isSavingRem, setIsSavingRem] = useState(false)` |
| `frontend/src/components/analysis/FindingsTable.tsx:395` | `[remError, setRemError] = useState('')` |
| `frontend/src/components/analysis/FindingsTable.tsx:444` | `[activeCve, setActiveCve] = useState< { id: string; seed: CveRowSeed; findingId: number \| null } \| null >(null)` |
| `frontend/src/components/analysis/RunsTable.tsx:75` | `[downloadingId, setDownloadingId] = useState<number \| null>(null)` |
| `frontend/src/components/analysis/RunsTable.tsx:76` | `[search, setSearch] = useState('')` |
| `frontend/src/components/analysis/RunsTable.tsx:77` | `[statusFilter, setStatusFilter] = useState('')` |
| `frontend/src/components/analysis/RunsTable.tsx:78` | `[sourceFilter, setSourceFilter] = useState('')` |
| `frontend/src/components/analysis/VulnerabilitiesByScope.tsx:108` | `[collapsed, setCollapsed] = useState<Set<string>>(() => new Set())` |
| `frontend/src/components/auth/LoginCallback.tsx:20` | `[status, setStatus] = useState<CallbackStatus>('processing')` |
| `frontend/src/components/auth/LoginCallback.tsx:21` | `[errorMessage, setErrorMessage] = useState('')` |
| `frontend/src/components/auth/MicrosoftSignIn.tsx:9` | `[client, setClient] = useState<PublicClientApplication \| null>(null)` |
| `frontend/src/components/auth/MicrosoftSignIn.tsx:10` | `[scope, setScope] = useState('')` |
| `frontend/src/components/auth/MicrosoftSignIn.tsx:11` | `[error, setError] = useState('')` |
| `frontend/src/components/auth/MicrosoftSignIn.tsx:12` | `[busy, setBusy] = useState(false)` |
| `frontend/src/components/auth/NativeAuthForm.tsx:14` | `[message, setMessage] = useState(activated ? 'Account activated. Sign in with your new password.' : '')` |
| `frontend/src/components/auth/NativeAuthForm.tsx:15` | `[busy, setBusy] = useState(false)` |
| `frontend/src/components/auth/NativePasswordSettings.tsx:6` | `[confirm, setConfirm] = useState(false)` |
| `frontend/src/components/auth/NativePasswordSettings.tsx:7` | `[native, setNative] = useState(false)` |
| `frontend/src/components/auth/NativePasswordSettings.tsx:8` | `[error, setError] = useState('')` |
| `frontend/src/components/auth/PasswordField.tsx:7` | `[visible, setVisible] = useState(false)` |
| `frontend/src/components/auth/PasswordLifecycleForm.tsx:10` | `[forced, setForced] = useState(false)` |
| `frontend/src/components/auth/PasswordLifecycleForm.tsx:11` | `[native, setNative] = useState(false)` |
| `frontend/src/components/auth/PasswordLifecycleForm.tsx:12` | `[message, setMessage] = useState('')` |
| `frontend/src/components/auth/PasswordLifecycleForm.tsx:13` | `[busy, setBusy] = useState(false)` |
| `frontend/src/components/compare/CompareView.tsx:41` | `[exportOpen, setExportOpen] = useState(false)` |
| `frontend/src/components/compare/CompareView.tsx:63` | `[aPick, setAPick] = useState<RunSummary \| null>(null)` |
| `frontend/src/components/compare/CompareView.tsx:64` | `[bPick, setBPick] = useState<RunSummary \| null>(null)` |
| `frontend/src/components/compare/ExportDialog.tsx:30` | `[busy, setBusy] = useState<CompareExportFormat \| null>(null)` |
| `frontend/src/components/compare/FindingRow/CveHoverCard.tsx:32` | `[open, setOpen] = useState(false)` |
| `frontend/src/components/compare/FindingsTab/FindingsTable.tsx:41` | `[activeCve, setActiveCve] = useState<{ id: string; seed: CveRowSeed } \| null>(null)` |
| `frontend/src/components/compare/KeyboardShortcutsOverlay.tsx:28` | `[open, setOpen] = useState(false)` |
| `frontend/src/components/compare/SelectionBar/RunPicker.tsx:65` | `[open, setOpen] = useState(false)` |
| `frontend/src/components/compare/SelectionBar/RunPicker.tsx:66` | `[needle, setNeedle] = useState('')` |
| `frontend/src/components/compare/SelectionBar/RunPicker.tsx:67` | `[activeIndex, setActiveIndex] = useState(-1)` |
| `frontend/src/components/compare/SelectionBar/RunPicker.tsx:68` | `[sameProjectOnly, setSameProjectOnly] = useState(false)` |
| `frontend/src/components/compare/SelectionBar/RunPicker.tsx:73` | `[debounced, setDebounced] = useState('')` |
| `frontend/src/components/component-advisor/ComponentGrid.tsx:45` | `[selected, setSelected] = useState<AdvisorComponent \| null>(null)` |
| `frontend/src/components/dashboard/FindingsTrendChart/FindingsTrendChart.tsx:122` | `[hidden, setHidden] = useState<Record<SeriesKey, boolean>>({ critical: false, high: false, medium: false, low: false, // Include unscored findings so the default legend reconciles with totals. unknown: false, })` |
| `frontend/src/components/dashboard/PortfolioOverview.tsx:116` | `[selected, setSelected] = useState<DashboardPriorityFinding \| null>(null)` |
| `frontend/src/components/dashboard/PortfolioTrend.tsx:10` | `[days, setDays] = useState(30)` |
| `frontend/src/components/dashboard/SeverityChart.tsx:85` | `[hovered, setHovered] = useState<string \| null>(null)` |
| `frontend/src/components/dashboard/TrendChart.tsx:74` | `[hidden, setHidden] = useState<Record<SeriesKey, boolean>>({ critical: false, high: false, medium: false, low: false, })` |
| `frontend/src/components/dashboard/TrendExplorer.tsx:77` | `[granularity, setGranularity] = useState<TrendGranularity>('week')` |
| `frontend/src/components/dashboard/TrendExplorer.tsx:78` | `[selectedApps, setSelectedApps] = useState<number[]>([])` |
| `frontend/src/components/dashboard/VulnerabilityAgePie.tsx:87` | `[period, setPeriod] = useState<AgePeriod>('all')` |
| `frontend/src/components/dashboard/VulnerabilityAgePie.tsx:88` | `[from, setFrom] = useState('')` |
| `frontend/src/components/dashboard/VulnerabilityAgePie.tsx:89` | `[to, setTo] = useState('')` |
| `frontend/src/components/dashboard/advanced/CopilotPanel.tsx:83` | `[question, setQuestion] = useState('')` |
| `frontend/src/components/dashboard/advanced/CopilotPanel.tsx:84` | `[enabled, setEnabled] = useState(false)` |
| `frontend/src/components/layout/CommandPalette.tsx:340` | `[open, setOpen] = useState(false)` |
| `frontend/src/components/layout/CommandPalette.tsx:341` | `[query, setQuery] = useState('')` |
| `frontend/src/components/layout/CommandPalette.tsx:342` | `[activeIndex, setActiveIndex] = useState(0)` |
| `frontend/src/components/layout/KeyboardCheatsheet.tsx:75` | `[open, setOpen] = useState(false)` |
| `frontend/src/components/layout/Sidebar.tsx:236` | `[expanded, setExpanded] = useState(isActive && !!item.children)` |
| `frontend/src/components/layout/Sidebar.tsx:237` | `[flyoutOpen, setFlyoutOpen] = useState(false)` |
| `frontend/src/components/layout/Sidebar.tsx:238` | `[flyoutTop, setFlyoutTop] = useState<number \| null>(null)` |
| `frontend/src/components/layout/SidebarContext.tsx:41` | `[collapsed, setCollapsed] = useState(false)` |
| `frontend/src/components/layout/SidebarContext.tsx:42` | `[mobileOpen, setMobileOpen] = useState(false)` |
| `frontend/src/components/layout/TenantSwitcher.tsx:40` | `[open, setOpen] = useState(false)` |
| `frontend/src/components/layout/TenantSwitcher.tsx:41` | `[search, setSearch] = useState('')` |
| `frontend/src/components/layout/TopBar.tsx:25` | `[isMac, setIsMac] = useState(false)` |
| `frontend/src/components/layout/UserMenu.tsx:36` | `[open, setOpen] = useState(false)` |
| `frontend/src/components/layout/UserMenu.tsx:37` | `[choosingTenant, setChoosingTenant] = useState(false)` |
| `frontend/src/components/layout/UserMenu.tsx:38` | `[signingOut, setSigningOut] = useState(false)` |
| `frontend/src/components/products/ProductFormDialog.tsx:52` | `[form, setForm] = useState<ProductFormState>(emptyProductForm)` |
| `frontend/src/components/products/ProductFormDialog.tsx:53` | `[categoryError, setCategoryError] = useState<string>()` |
| `frontend/src/components/projects/InventoryActionMenu.tsx:24` | `[open, setOpen] = useState(false)` |
| `frontend/src/components/projects/InventoryActionMenu.tsx:25` | `[position, setPosition] = useState({ top: 0, left: 0 })` |
| `frontend/src/components/projects/ProjectApplications.tsx:54` | `[formOpen, setFormOpen] = useState(false)` |
| `frontend/src/components/projects/ProjectApplications.tsx:55` | `[editingProduct, setEditingProduct] = useState<Product \| null>(null)` |
| `frontend/src/components/projects/ProjectApplications.tsx:56` | `[uploadProduct, setUploadProduct] = useState<Product \| null>(null)` |
| `frontend/src/components/projects/ProjectApplications.tsx:57` | `[deleteProductTarget, setDeleteProductTarget] = useState<Product \| null>(null)` |
| `frontend/src/components/projects/ProjectApplications.tsx:59` | `[search, setSearch] = useState('')` |
| `frontend/src/components/projects/ProjectApplications.tsx:60` | `[statusFilter, setStatusFilter] = useState('all')` |
| `frontend/src/components/projects/ProjectsTable.tsx:139` | `[editProject, setEditProject] = useState<Project \| null>(null)` |
| `frontend/src/components/projects/ProjectsTable.tsx:140` | `[scheduleProject, setScheduleProject] = useState<Project \| null>(null)` |
| `frontend/src/components/projects/ProjectsTable.tsx:141` | `[deleteTarget, setDeleteTarget] = useState<Project \| null>(null)` |
| `frontend/src/components/projects/ProjectsTable.tsx:142` | `[search, setSearch] = useState('')` |
| `frontend/src/components/projects/ProjectsTable.tsx:143` | `[statusFilter, setStatusFilter] = useState<'all' \| 'active' \| 'inactive'>('all')` |
| `frontend/src/components/reports/ReportNotificationsPage.tsx:29` | `[open, setOpen] = useState(false)` |
| `frontend/src/components/reports/ReportNotificationsPage.tsx:43` | `[form, setForm] = useState(initial)` |
| `frontend/src/components/reports/ReportNotificationsPage.tsx:44` | `[search, setSearch] = useState('')` |
| `frontend/src/components/reports/ReportNotificationsPage.tsx:45` | `[previewOpen, setPreviewOpen] = useState(false)` |
| `frontend/src/components/reports/ReportNotificationsPage.tsx:46` | `[error, setError] = useState('')` |
| `frontend/src/components/reports/ReportNotificationsPage.tsx:99` | `[editing, setEditing] = useState<{ preferences: ReportPreferences; id?: number } \| null>(params.has('scope') ? { preferences: initial } : null)` |
| `frontend/src/components/reports/ReportNotificationsPage.tsx:100` | `[remove, setRemove] = useState<ReportSubscription \| null>(null)` |
| `frontend/src/components/reports/ReportNotificationsPage.tsx:101` | `[allTenant, setAllTenant] = useState(false)` |
| `frontend/src/components/reports/ReportNotificationsPage.tsx:102` | `[status, setStatus] = useState('')` |
| `frontend/src/components/reports/ReportNotificationsPage.tsx:103` | `[deliveryId, setDeliveryId] = useState(() => { const value = Number(params.get('delivery')); return Number.isSafeInteger(value) && value > 0 ? value : undefined; })` |
| `frontend/src/components/sboms/ComponentVexManager.tsx:15` | `[search, setSearch] = useState('')` |
| `frontend/src/components/sboms/ComponentVexManager.tsx:16` | `[historyPair, setHistoryPair] = useState<string \| null>(null)` |
| `frontend/src/components/sboms/Fda510kReportDialog.tsx:80` | `[metadata, setMetadata] = useState<Fda510kReportMetadata>(() => initialMetadata(sboms))` |
| `frontend/src/components/sboms/Fda510kReportDialog.tsx:81` | `[error, setError] = useState<string \| null>(null)` |
| `frontend/src/components/sboms/Fda510kReportDialog.tsx:82` | `[blockers, setBlockers] = useState<Fda510kIncompleteAnalysisDetail \| null>(null)` |
| `frontend/src/components/sboms/Fda510kReportDialog.tsx:83` | `[submitting, setSubmitting] = useState(false)` |
| `frontend/src/components/sboms/SbomAutoRepairPanel.tsx:24` | `[showChanges, setShowChanges] = useState(false)` |
| `frontend/src/components/sboms/SbomAutoRepairPanel.tsx:25` | `[showErrors, setShowErrors] = useState(false)` |
| `frontend/src/components/sboms/SbomConversionCard.tsx:42` | `[message, setMessage] = useState<string \| null>(null)` |
| `frontend/src/components/sboms/SbomConversionCard.tsx:43` | `[showReport, setShowReport] = useState(false)` |
| `frontend/src/components/sboms/SbomConversionCard.tsx:44` | `[convertedId, setConvertedId] = useState<number \| null>(sbom.converted_sbom_id ?? null)` |
| `frontend/src/components/sboms/SbomConversionCard.tsx:45` | `[enrichmentStatus, setEnrichmentStatus] = useState<string \| null>( sbom.enrichment_status ?? null, )` |
| `frontend/src/components/sboms/SbomDetail.tsx:237` | `[activeTab, setActiveTab] = useState<'overview' \| 'components' \| 'normalization' \| 'versions' \| 'runs'>('overview')` |
| `frontend/src/components/sboms/SbomDetail.tsx:240` | `[editingComp, setEditingComp] = useState<SBOMComponent \| null>(null)` |
| `frontend/src/components/sboms/SbomDetail.tsx:241` | `[editName, setEditName] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:242` | `[editVersion, setEditVersion] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:243` | `[editSupplier, setEditSupplier] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:244` | `[editLicense, setEditLicense] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:245` | `[editHashes, setEditHashes] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:246` | `[editLifecycleStatus, setEditLifecycleStatus] = useState('Supported')` |
| `frontend/src/components/sboms/SbomDetail.tsx:247` | `[editEosDate, setEditEosDate] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:248` | `[editEolDate, setEditEolDate] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:249` | `[editEofDate, setEditEofDate] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:250` | `[editIsDeprecated, setEditIsDeprecated] = useState(false)` |
| `frontend/src/components/sboms/SbomDetail.tsx:251` | `[editMaintStatus, setEditMaintStatus] = useState('Supported')` |
| `frontend/src/components/sboms/SbomDetail.tsx:252` | `[editRecommendedVersion, setEditRecommendedVersion] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:253` | `[editOverrideReason, setEditOverrideReason] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:254` | `[editEvidenceUrl, setEditEvidenceUrl] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:255` | `[isSavingEdit, setIsSavingEdit] = useState(false)` |
| `frontend/src/components/sboms/SbomDetail.tsx:256` | `[editError, setEditError] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:257` | `[isOpeningWorkspace, setIsOpeningWorkspace] = useState(false)` |
| `frontend/src/components/sboms/SbomDetail.tsx:258` | `[isRefreshingLifecycle, setIsRefreshingLifecycle] = useState(false)` |
| `frontend/src/components/sboms/SbomDetail.tsx:259` | `[refreshingComponentId, setRefreshingComponentId] = useState<number \| null>(null)` |
| `frontend/src/components/sboms/SbomDetail.tsx:260` | `[lifecycleMessage, setLifecycleMessage] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:261` | `[vexDocumentText, setVexDocumentText] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:262` | `[vexMessage, setVexMessage] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:263` | `[isUploadingVex, setIsUploadingVex] = useState(false)` |
| `frontend/src/components/sboms/SbomDetail.tsx:264` | `[isDiscoveringVex, setIsDiscoveringVex] = useState(false)` |
| `frontend/src/components/sboms/SbomDetail.tsx:265` | `[downloadMessage, setDownloadMessage] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:266` | `[evidenceModal, setEvidenceModal] = useState<EvidenceModalState>(null)` |
| `frontend/src/components/sboms/SbomDetail.tsx:267` | `[managedVexComponent, setManagedVexComponent] = useState<SBOMComponent \| null>(null)` |
| `frontend/src/components/sboms/SbomDetail.tsx:268` | `[vexComponentLocked, setVexComponentLocked] = useState(false)` |
| `frontend/src/components/sboms/SbomDetail.tsx:269` | `[vexPairLocked, setVexPairLocked] = useState(false)` |
| `frontend/src/components/sboms/SbomDetail.tsx:270` | `[manualVulnerability, setManualVulnerability] = useState(false)` |
| `frontend/src/components/sboms/SbomDetail.tsx:271` | `[isVexOverrideOpen, setIsVexOverrideOpen] = useState(false)` |
| `frontend/src/components/sboms/SbomDetail.tsx:272` | `[vexOverrideComponentId, setVexOverrideComponentId] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:273` | `[vexOverrideVulnerability, setVexOverrideVulnerability] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:274` | `[vexOverrideStatus, setVexOverrideStatus] = useState<VexStatus>('under_investigation')` |
| `frontend/src/components/sboms/SbomDetail.tsx:275` | `[vexOverrideJustification, setVexOverrideJustification] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:276` | `[vexOverrideImpact, setVexOverrideImpact] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:277` | `[vexOverrideAction, setVexOverrideAction] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:278` | `[vexOverrideFixedVersion, setVexOverrideFixedVersion] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:279` | `[vexOverrideMitigation, setVexOverrideMitigation] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:280` | `[vexOverrideEvidenceUrl, setVexOverrideEvidenceUrl] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:281` | `[vexOverrideReason, setVexOverrideReason] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:282` | `[vexOverrideError, setVexOverrideError] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:283` | `[isSavingVexOverride, setIsSavingVexOverride] = useState(false)` |
| `frontend/src/components/sboms/SbomDetail.tsx:284` | `[vexOverrideHistory, setVexOverrideHistory] = useState<VexOverrideAuditEntry[]>([])` |
| `frontend/src/components/sboms/SbomDetail.tsx:285` | `[isLoadingVexHistory, setIsLoadingVexHistory] = useState(false)` |
| `frontend/src/components/sboms/SbomDetail.tsx:290` | `[selectedVersions, setSelectedVersions] = useState<number[]>([])` |
| `frontend/src/components/sboms/SbomDetail.tsx:291` | `[compareData, setCompareData] = useState<any>(null)` |
| `frontend/src/components/sboms/SbomDetail.tsx:292` | `[isComparing, setIsComparing] = useState(false)` |
| `frontend/src/components/sboms/SbomDetail.tsx:293` | `[restoreMessage, setRestoreMessage] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:296` | `[showDuplicates, setShowDuplicates] = useState(false)` |
| `frontend/src/components/sboms/SbomDetail.tsx:297` | `[componentSearch, setComponentSearch] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:298` | `[debouncedComponentSearch, setDebouncedComponentSearch] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:299` | `[componentPage, setComponentPage] = useState(1)` |
| `frontend/src/components/sboms/SbomDetail.tsx:300` | `[componentPageSize, setComponentPageSize] = useState(25)` |
| `frontend/src/components/sboms/SbomDetail.tsx:301` | `[isDedupeModalOpen, setIsDedupeModalOpen] = useState(false)` |
| `frontend/src/components/sboms/SbomDetail.tsx:304` | `[isAssignModalOpen, setIsAssignModalOpen] = useState(false)` |
| `frontend/src/components/sboms/SbomDetail.tsx:305` | `[isEditDetailsModalOpen, setIsEditDetailsModalOpen] = useState(false)` |
| `frontend/src/components/sboms/SbomDetail.tsx:308` | `[selectedProjectId, setSelectedProjectId] = useState<number \| null>(null)` |
| `frontend/src/components/sboms/SbomDetail.tsx:309` | `[selectedProductId, setSelectedProductId] = useState<number \| null>(null)` |
| `frontend/src/components/sboms/SbomDetail.tsx:310` | `[assignChangeReason, setAssignChangeReason] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:311` | `[isSavingAssign, setIsSavingAssign] = useState(false)` |
| `frontend/src/components/sboms/SbomDetail.tsx:312` | `[assignError, setAssignError] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:315` | `[detailName, setDetailName] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:316` | `[detailProductId, setDetailProductId] = useState<number \| null>(null)` |
| `frontend/src/components/sboms/SbomDetail.tsx:317` | `[detailProductVersion, setDetailProductVersion] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:318` | `[detailSbomVersion, setDetailSbomVersion] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:319` | `[detailDescription, setDetailDescription] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:320` | `[detailProjectId, setDetailProjectId] = useState<number \| null>(null)` |
| `frontend/src/components/sboms/SbomDetail.tsx:321` | `[detailChangeReason, setDetailChangeReason] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:322` | `[isSavingDetails, setIsSavingDetails] = useState(false)` |
| `frontend/src/components/sboms/SbomDetail.tsx:323` | `[detailsError, setDetailsError] = useState('')` |
| `frontend/src/components/sboms/SbomDetail.tsx:414` | `[compSortKey, setCompSortKey] = useState<ComponentSortKey>('name')` |
| `frontend/src/components/sboms/SbomDetail.tsx:415` | `[compSortDirection, setCompSortDirection] = useState<'asc' \| 'desc'>('asc')` |
| `frontend/src/components/sboms/SbomLifecycleControls.tsx:29` | `[open, setOpen] = useState(false)` |
| `frontend/src/components/sboms/SbomLifecycleControls.tsx:30` | `[reason, setReason] = useState('')` |
| `frontend/src/components/sboms/SbomLifecycleControls.tsx:31` | `[historyOpen, setHistoryOpen] = useState(false)` |
| `frontend/src/components/sboms/SbomQualityPanel.tsx:13` | `[findingsVisible, setFindingsVisible] = useState(false)` |
| `frontend/src/components/sboms/SbomRawViewer.tsx:30` | `[page, setPage] = useState(1)` |
| `frontend/src/components/sboms/SbomUploadModal.tsx:121` | `[draggingFile, setDraggingFile] = useState(false)` |
| `frontend/src/components/sboms/SbomUploadModal.tsx:124` | `[uploadError, setUploadError] = useState<string \| null>(null)` |
| `frontend/src/components/sboms/SbomUploadModal.tsx:125` | `[validationFailure, setValidationFailure] = useState<SbomValidationFailureDetail \| null>(null)` |
| `frontend/src/components/sboms/SbomUploadModal.tsx:126` | `[uploadResult, setUploadResult] = useState<SBOMSource \| null>(null)` |
| `frontend/src/components/sboms/SbomUploadModal.tsx:127` | `[selectedFile, setSelectedFile] = useState<File \| null>(null)` |
| `frontend/src/components/sboms/SbomUploadModal.tsx:128` | `[newProductName, setNewProductName] = useState('')` |
| `frontend/src/components/sboms/SbomUploadModal.tsx:129` | `[documentPreviewMeta, setDocumentPreviewMeta] = useState<{ bytes: number; lines: number; filename: string; } \| null>(null)` |
| `frontend/src/components/sboms/SbomUploadModal.tsx:134` | `[formatDetection, setFormatDetection] = useState<SbomFormatDetection \| null>(null)` |
| `frontend/src/components/sboms/SbomUploadModal.tsx:135` | `[userManuallyOverrodeFormat, setUserManuallyOverrodeFormat] = useState(false)` |
| `frontend/src/components/sboms/SbomsTable.tsx:123` | `[deleteTarget, setDeleteTarget] = useState<SBOMSource \| null>(null)` |
| `frontend/src/components/sboms/SbomsTable.tsx:124` | `[search, setSearch] = useState('')` |
| `frontend/src/components/sboms/SbomsTable.tsx:125` | `[projectFilter, setProjectFilter] = useState('')` |
| `frontend/src/components/sboms/SbomsTable.tsx:126` | `[productFilter, setProductFilter] = useState('')` |
| `frontend/src/components/sboms/SbomsTable.tsx:127` | `[analysisFilter, setAnalysisFilter] = useState('')` |
| `frontend/src/components/sboms/SbomsTable.tsx:128` | `[validationFilter, setValidationFilter] = useState('')` |
| `frontend/src/components/sboms/SbomsTable.tsx:129` | `[selectedIds, setSelectedIds] = useState<Set<number>>(() => new Set())` |
| `frontend/src/components/sboms/SbomsTable.tsx:130` | `[fdaDialogOpen, setFdaDialogOpen] = useState(false)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:56` | `[content, setContent] = useState('')` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:57` | `[loadedContentSize, setLoadedContentSize] = useState(0)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:58` | `[totalContentSize, setTotalContentSize] = useState(0)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:59` | `[contentEof, setContentEof] = useState(false)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:60` | `[contentSha256, setContentSha256] = useState<string \| null>(null)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:61` | `[contentLoaded, setContentLoaded] = useState(false)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:62` | `[suggestion, setSuggestion] = useState<AiRepairSuggestion \| null>(null)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:63` | `[selected, setSelected] = useState<Record<number, boolean>>({})` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:64` | `[localMessage, setLocalMessage] = useState<string \| null>(null)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:65` | `[focusMode, setFocusMode] = useState(false)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:66` | `[historyOpen, setHistoryOpen] = useState(false)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:67` | `[savedContent, setSavedContent] = useState<string \| null>(null)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:68` | `[selectedIssueKey, setSelectedIssueKey] = useState<string \| null>(null)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:69` | `[workflowStep, setWorkflowStep] = useState<'review' \| 'repair' \| 'validate'>('review')` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:70` | `[issuesHidden, setIssuesHidden] = useState(false)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:71` | `[mobilePane, setMobilePane] = useState<'issues' \| 'editor'>('issues')` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:72` | `[repairReviewOpen, setRepairReviewOpen] = useState(false)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:73` | `[aiReviewOpen, setAiReviewOpen] = useState(false)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:74` | `[projectSaving, setProjectSaving] = useState(false)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:75` | `[largeBusy, setLargeBusy] = useState(false)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:76` | `[largeNavigation, setLargeNavigation] = useState<{ line?: number; query?: string; token: number } \| null>(null)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:77` | `[highlight, setHighlight] = useState<SourceLocation \| null>(null)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:78` | `[editorScrollTop, setEditorScrollTop] = useState(0)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:79` | `[navigationMessage, setNavigationMessage] = useState('')` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:80` | `[searchOpen, setSearchOpen] = useState(false)` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:81` | `[editorSearch, setEditorSearch] = useState('')` |
| `frontend/src/components/sboms/ValidationReportSection.tsx:48` | `[copied, setCopied] = useState(false)` |
| `frontend/src/components/sboms/ValidationReportSection.tsx:162` | `[expanded, setExpanded] = useState(defaultExpanded)` |
| `frontend/src/components/sboms/VexDocumentImport.tsx:43` | `[dragging, setDragging] = useState(false)` |
| `frontend/src/components/sboms/VexDocumentImport.tsx:44` | `[fileName, setFileName] = useState<string \| null>(null)` |
| `frontend/src/components/sboms/VexDocumentImport.tsx:45` | `[fileError, setFileError] = useState<string \| null>(null)` |
| `frontend/src/components/sboms/repair/LargeFileRepairEditor.tsx:39` | `[startLine, setStartLine] = useState(1)` |
| `frontend/src/components/sboms/repair/LargeFileRepairEditor.tsx:40` | `[jumpLine, setJumpLine] = useState('1')` |
| `frontend/src/components/sboms/repair/LargeFileRepairEditor.tsx:41` | `[query, setQuery] = useState('')` |
| `frontend/src/components/sboms/repair/LargeFileRepairEditor.tsx:42` | `[patch, setPatch] = useState<LineRepairPatch>({ operation: 'replace_lines', start_line: 1, end_line: 1, replacement_text: '', })` |
| `frontend/src/components/sboms/repair/LargeFileRepairEditor.tsx:48` | `[message, setMessage] = useState<string \| null>(null)` |
| `frontend/src/components/sboms/repair/RepairIssueNavigator.tsx:24` | `[filter, setFilter] = useState<Filter>('all')` |
| `frontend/src/components/sboms/repair/RepairIssueNavigator.tsx:25` | `[search, setSearch] = useState('')` |
| `frontend/src/components/sboms/repair/RepairIssueNavigator.tsx:26` | `[copyMessage, setCopyMessage] = useState('')` |
| `frontend/src/components/sboms/repair/RepairQualitySummary.tsx:9` | `[open, setOpen] = useState(false)` |
| `frontend/src/components/schedules/ScheduleCard.tsx:88` | `[showEditor, setShowEditor] = useState(false)` |
| `frontend/src/components/schedules/ScheduleCard.tsx:89` | `[confirmDelete, setConfirmDelete] = useState(false)` |
| `frontend/src/components/schedules/ScheduleEditor.tsx:95` | `[form, setForm] = useState<FormState>(() => defaultsFromExisting(existing))` |
| `frontend/src/components/settings/ai/AddProviderDialog/AddProviderDialog.tsx:49` | `[providerName, setProviderName] = useState<string>('anthropic')` |
| `frontend/src/components/settings/ai/AddProviderDialog/AddProviderDialog.tsx:50` | `[label, setLabel] = useState<string>('default')` |
| `frontend/src/components/settings/ai/AddProviderDialog/AddProviderDialog.tsx:51` | `[apiKey, setApiKey] = useState<string>('')` |
| `frontend/src/components/settings/ai/AddProviderDialog/AddProviderDialog.tsx:52` | `[showKey, setShowKey] = useState(false)` |
| `frontend/src/components/settings/ai/AddProviderDialog/AddProviderDialog.tsx:53` | `[baseUrl, setBaseUrl] = useState<string>('')` |
| `frontend/src/components/settings/ai/AddProviderDialog/AddProviderDialog.tsx:54` | `[defaultModel, setDefaultModel] = useState<string>('')` |
| `frontend/src/components/settings/ai/AddProviderDialog/AddProviderDialog.tsx:55` | `[tier, setTier] = useState<AiTier>('paid')` |
| `frontend/src/components/settings/ai/AddProviderDialog/AddProviderDialog.tsx:56` | `[costIn, setCostIn] = useState<string>('0')` |
| `frontend/src/components/settings/ai/AddProviderDialog/AddProviderDialog.tsx:57` | `[costOut, setCostOut] = useState<string>('0')` |
| `frontend/src/components/settings/ai/AddProviderDialog/AddProviderDialog.tsx:58` | `[isLocal, setIsLocal] = useState<boolean>(false)` |
| `frontend/src/components/settings/ai/AddProviderDialog/AddProviderDialog.tsx:59` | `[submitError, setSubmitError] = useState<string \| null>(null)` |
| `frontend/src/components/settings/ai/AiSettingsPage.tsx:20` | `[showAdd, setShowAdd] = useState(false)` |
| `frontend/src/components/settings/ai/AiSettingsPage.tsx:21` | `[editing, setEditing] = useState<AiCredential \| null>(null)` |
| `frontend/src/components/settings/ai/BudgetCapsForm/BudgetCapsForm.tsx:26` | `[perRequest, setPerRequest] = useState('0.10')` |
| `frontend/src/components/settings/ai/BudgetCapsForm/BudgetCapsForm.tsx:27` | `[perScan, setPerScan] = useState('5.00')` |
| `frontend/src/components/settings/ai/BudgetCapsForm/BudgetCapsForm.tsx:28` | `[perDay, setPerDay] = useState('5.00')` |
| `frontend/src/components/settings/ai/BudgetCapsForm/BudgetCapsForm.tsx:29` | `[killSwitch, setKillSwitch] = useState(false)` |
| `frontend/src/components/settings/ai/BudgetCapsForm/BudgetCapsForm.tsx:30` | `[featureEnabled, setFeatureEnabled] = useState(true)` |
| `frontend/src/components/settings/ai/BudgetCapsForm/BudgetCapsForm.tsx:31` | `[error, setError] = useState<string \| null>(null)` |
| `frontend/src/components/settings/ai/BudgetCapsForm/BudgetCapsForm.tsx:32` | `[saved, setSaved] = useState(false)` |
| `frontend/src/components/settings/ai/EditProviderDialog/EditProviderDialog.tsx:44` | `[apiKey, setApiKey] = useState('')` |
| `frontend/src/components/settings/ai/EditProviderDialog/EditProviderDialog.tsx:45` | `[label, setLabel] = useState('default')` |
| `frontend/src/components/settings/ai/EditProviderDialog/EditProviderDialog.tsx:46` | `[showKey, setShowKey] = useState(false)` |
| `frontend/src/components/settings/ai/EditProviderDialog/EditProviderDialog.tsx:47` | `[baseUrl, setBaseUrl] = useState('')` |
| `frontend/src/components/settings/ai/EditProviderDialog/EditProviderDialog.tsx:48` | `[defaultModel, setDefaultModel] = useState('')` |
| `frontend/src/components/settings/ai/EditProviderDialog/EditProviderDialog.tsx:49` | `[tier, setTier] = useState<AiTier>('paid')` |
| `frontend/src/components/settings/ai/EditProviderDialog/EditProviderDialog.tsx:50` | `[costIn, setCostIn] = useState('0')` |
| `frontend/src/components/settings/ai/EditProviderDialog/EditProviderDialog.tsx:51` | `[costOut, setCostOut] = useState('0')` |
| `frontend/src/components/settings/ai/EditProviderDialog/EditProviderDialog.tsx:52` | `[isLocal, setIsLocal] = useState(false)` |
| `frontend/src/components/settings/ai/EditProviderDialog/EditProviderDialog.tsx:53` | `[submitError, setSubmitError] = useState<string \| null>(null)` |
| `frontend/src/components/settings/ai/ProvidersList/ProviderCard.tsx:49` | `[confirmDelete, setConfirmDelete] = useState(false)` |
| `frontend/src/components/settings/ai/ProvidersList/ProviderCard.tsx:50` | `[deleteText, setDeleteText] = useState('')` |
| `frontend/src/components/settings/ai/ProvidersList/ProviderCard.tsx:51` | `[menuOpen, setMenuOpen] = useState(false)` |
| `frontend/src/components/theme/ThemeProvider.tsx:32` | `[theme, setThemeState] = useState<Theme>('light')` |
| `frontend/src/components/theme/ThemeProvider.tsx:33` | `[resolvedTheme, setResolvedTheme] = useState<Theme>('light')` |
| `frontend/src/components/theme/ThemeToggle.tsx:10` | `[mounted, setMounted] = useState(false)` |
| `frontend/src/components/ui/AnimatedSeverityBar.tsx:36` | `[armed, setArmed] = useState(false)` |
| `frontend/src/components/ui/DeleteConfirmDialog.tsx:87` | `[mode, setMode] = useState<'soft' \| 'permanent'>('soft')` |
| `frontend/src/components/ui/DeleteConfirmDialog.tsx:88` | `[typed, setTyped] = useState('')` |
| `frontend/src/components/ui/Dialog.tsx:68` | `[scrollState, setScrollState] = useState<'atTop' \| 'atBottom' \| 'middle' \| 'both'>('both')` |
| `frontend/src/components/ui/ExportMenu.tsx:30` | `[open, setOpen] = useState(false)` |
| `frontend/src/components/ui/PermissionButton.tsx:19` | `[position, setPosition] = useState<{ top: number; left: number; above: boolean } \| null>(null)` |
| `frontend/src/components/ui/Select.tsx:89` | `[isOpen, setIsOpen] = useState(false)` |
| `frontend/src/components/ui/Select.tsx:90` | `[searchQuery, setSearchQuery] = useState('')` |
| `frontend/src/components/ui/Select.tsx:91` | `[highlightedIndex, setHighlightedIndex] = useState(-1)` |
| `frontend/src/components/ui/Select.tsx:92` | `[placement, setPlacement] = useState<'bottom' \| 'top'>('bottom')` |
| `frontend/src/components/vex/AssigneeCombobox.tsx:44` | `[query, setQuery] = useState('')` |
| `frontend/src/components/vex/AssigneeCombobox.tsx:45` | `[open, setOpen] = useState(false)` |
| `frontend/src/components/vex/AssigneeCombobox.tsx:46` | `[active, setActive] = useState(0)` |
| `frontend/src/components/vex/AssigneeCombobox.tsx:47` | `[position, setPosition] = useState<React.CSSProperties>({})` |
| `frontend/src/components/vex/VexDecisionEditor.tsx:97` | `[draft, setDraft] = useState<VexDecisionDraft>(() => draftFromInvestigation(investigation))` |
| `frontend/src/components/vex/VexDecisionEditor.tsx:98` | `[errors, setErrors] = useState<VexDecisionErrors>({})` |
| `frontend/src/components/vex/VexDecisionEditor.tsx:99` | `[submitError, setSubmitError] = useState<string \| null>(null)` |
| `frontend/src/components/vex/VexInvestigationPanel.tsx:24` | `[formError, setFormError] = useState<string \| null>(null)` |
| `frontend/src/components/vex/VexInvestigationPanel.tsx:25` | `[assignee, setAssignee] = useState(detail.internal_decision.assigned_to ?? '')` |
| `frontend/src/components/vex/VexInvestigationPanel.tsx:26` | `[componentId, setComponentId] = useState('')` |
| `frontend/src/components/vex/VexInvestigationPanel.tsx:27` | `[savedDetail, setSavedDetail] = useState(detail)` |
| `frontend/src/components/vex/VexRunHistoryPanel.tsx:13` | `[runId, setRunId] = useState(0)` |
| `frontend/src/components/vex/VexRunHistoryPanel.tsx:14` | `[offset, setOffset] = useState(0)` |
| `frontend/src/components/vex/VexVersionComparisonPanel.tsx:15` | `[open, setOpen] = useState(false)` |
| `frontend/src/components/vex/VexVersionComparisonPanel.tsx:16` | `[category, setCategory] = useState('ALL')` |
| `frontend/src/components/vex/VexVersionComparisonPanel.tsx:17` | `[selection, setSelection] = useState<VexComparisonContext \| null>(null)` |
| `frontend/src/components/vulnerabilities/CveDetailDialog/CveDetailDialog.tsx:142` | `[activeTab, setActiveTab] = useState(initialTab)` |
| `frontend/src/components/vulnerabilities/CveDetailDialog/CveFixSection.tsx:49` | `[copied, setCopied] = useState<string \| null>(null)` |
| `frontend/src/components/vulnerabilities/CveDetailDialog/CveHeader.tsx:34` | `[copied, setCopied] = useState(false)` |
| `frontend/src/hooks/useAiFix.ts:138` | `[sseAvailable, setSseAvailable] = useState<SSEAvailable>(null)` |
| `frontend/src/hooks/useAiFix.ts:265` | `[debouncedScope, setDebouncedScope] = useState(scope)` |
| `frontend/src/hooks/useAnalysisStream.ts:59` | `[state, setState] = useState<AnalysisStreamState>(INITIAL_STATE)` |
| `frontend/src/hooks/useAuth.tsx:150` | `[sessionAuthenticated, setSessionAuthenticated] = useState(false)` |
| `frontend/src/hooks/useAuth.tsx:151` | `[authStatus, setAuthStatus] = useState<AuthStatus>('loading')` |
| `frontend/src/hooks/useAuth.tsx:152` | `[bootstrapState, setBootstrapStateInternal] = useState<BootstrapState>('checking-session')` |
| `frontend/src/hooks/useAuth.tsx:153` | `[bootstrapError, setBootstrapError] = useState<string \| null>(null)` |
| `frontend/src/hooks/useAuth.tsx:154` | `[user, setUser] = useState<AuthUser \| null>(null)` |
| `frontend/src/hooks/useAuth.tsx:155` | `[tenants, setTenants] = useState<TenantInfo[]>([])` |
| `frontend/src/hooks/useAuth.tsx:156` | `[activeTenantIdState, setActiveTenantIdState] = useState<string \| null>(null)` |
| `frontend/src/hooks/usePagination.ts:68` | `[page, setPageRaw] = useState(1)` |
| `frontend/src/hooks/usePagination.ts:69` | `[pageSize, setPageSizeRaw] = useState(initialSize)` |
| `frontend/src/hooks/useTableSort.ts:43` | `[sort, setSort] = useState<SortState<K>>({ key: initialKey, direction: initialDirection, })` |
| `frontend/src/hooks/useToast.tsx:67` | `[toasts, setToasts] = useState<ToastItem[]>([])` |
| `frontend/src/hooks/useToast.tsx:122` | `[mounted, setMounted] = useState(false)` |
| `frontend/src/hooks/useViewMode.ts:41` | `[mode, setMode] = useState<ViewMode>(() => readStoredMode(storageKey, defaultMode))` |
| `frontend/src/lib/pinned.ts:110` | `[items, setItems] = useState<PinnedItem[]>([])` |

| Location | Effect source opening |
|---|---|
| `frontend/src/app/access-denied/page.tsx:15` | `useEffect(() => { document.title = \`${title} — SBOM Analyzer\`; }, [title])…` |
| `frontend/src/app/component-advisor/page.tsx:148` | `useEffect(() => { if (searchInput.trim() === filters.q) return; const timer = window.setTimeout(() => { setFilters((c) => ({ ...c, q: searchInput.trim() })); setPage(1); }, 350); return () => window.clearTimeout(timer); …` |
| `frontend/src/app/component-advisor/page.tsx:154` | `useEffect(() => { const params = new URLSearchParams(); filters.risk.forEach((v) => params.append('risk', v)); filters.lifecycle.forEach((v) => params.append('lifecycle', v)); if (filters.needsReview) params.set('needs_r…` |
| `frontend/src/app/error.tsx:16` | `useEffect(() => { console.error(error); }, [error])…` |
| `frontend/src/app/kev/page.tsx:166` | `useEffect(() => { const timer = window.setTimeout(() => { const search = searchInput.trim(); setFilters((current) => (current.search === search ? current : { ...current, search })); setPage(1); }, 350); return () => wind…` |
| `frontend/src/app/kev/page.tsx:175` | `useEffect(() => { const params = new URLSearchParams(); if (filters.search) params.set('q', filters.search); if (filters.vendor) params.set('vendor', filters.vendor); if (filters.product) params.set('product', filters.pr…` |
| `frontend/src/app/kev/page.tsx:262` | `useEffect(() => { if (page > totalPages && catalogQuery.data) setPage(totalPages); }, [catalogQuery.data, page, totalPages])…` |
| `frontend/src/app/settings/platform/tenants/page.tsx:99` | `useEffect(() => { if (canManage && window.location.hash === '#create-tenant') setFormOpen(true); }, [canManage])…` |
| `frontend/src/app/verification-required/page.tsx:9` | `useEffect(() => { document.title = 'Verification Required — SBOM Analyzer'; }, [])…` |
| `frontend/src/app/vex-investigation/page.tsx:199` | `useEffect(() => { const timer = window.setTimeout(() => setDebouncedAssigneeSearch(assigneeSearch.trim()), 300); return () => window.clearTimeout(timer); }, [assigneeSearch])…` |
| `frontend/src/app/vex-investigation/page.tsx:219` | `useEffect(() => { if (searchInput.trim() === filters.search) return; const timer = window.setTimeout(() => { const search = searchInput.trim(); setFilters((current) => (current.search === search ? current : { ...current,…` |
| `frontend/src/app/vex-investigation/page.tsx:228` | `useEffect(() => { if (componentInput.trim() === filters.component) return; const timer = window.setTimeout(() => { setFilters(current => ({ ...current, component: componentInput.trim() })); setPage(1); }, 300); return ()…` |
| `frontend/src/app/vex-investigation/page.tsx:239` | `useEffect(() => { if (incomingUrl === observedUrl.current) return; observedUrl.current = incomingUrl; if (incomingUrl === writtenUrl.current) return; restoringUrl.current = true; const restored = initialState(new URLSear…` |
| `frontend/src/app/vex-investigation/page.tsx:252` | `useEffect(() => { if (restoringUrl.current) { restoringUrl.current = false; return; } const params = new URLSearchParams(); if (filters.versionScope !== 'current') params.set('version_scope', filters.versionScope); if (f…` |
| `frontend/src/app/vex-investigation/page.tsx:335` | `useEffect(() => { if (!listQuery.isFetching && !listQuery.isPlaceholderData && listQuery.data && page > totalPages) setPage(totalPages); }, [page, totalPages, listQuery.isFetching, listQuery.isPlaceholderData, listQuery.…` |
| `frontend/src/components/admin/IamOperations.tsx:11` | `useEffect(() => { if (!allowed) return; let current = true; fetch('/api/backend/api/platform/iam/operations', { cache: 'no-store' }).then(async r => { if (!r.ok) throw new Error(); const value = await r.json(); if (curre…` |
| `frontend/src/components/admin/LifecycleProviderForm.tsx:44` | `useEffect(() => { setEnabled(provider.enabled); setPriority(String(provider.priority)); setBaseUrl(provider.base_url ?? ''); setFeedUrls(provider.feed_urls.join('\n')); setTimeoutValue(String(provider.timeout_seconds)); …` |
| `frontend/src/components/admin/ManageRolesModal.tsx:53` | `useEffect(() => { if (open) { setDraftRoles(new Set(initialSelectedCodes)); setError(errorMessage); } }, [open, initialSelectedCodes, errorMessage])…` |
| `frontend/src/components/admin/MemberActionMenu.tsx:69` | `useEffect(() => { const handleCloseOthers = (e: Event) => { const customEvent = e as CustomEvent<{ menuId: string }>; if (customEvent.detail?.menuId !== menuId) { setOpen(false); } }; document.addEventListener('close-mem…` |
| `frontend/src/components/admin/MemberActionMenu.tsx:82` | `useEffect(() => { if (!open) return; const handleOutsideClick = (e: MouseEvent) => { const target = e.target as Node; if ( buttonRef.current && !buttonRef.current.contains(target) && menuRef.current && !menuRef.current.c…` |
| `frontend/src/components/admin/MemberActionMenu.tsx:133` | `useEffect(() => { if (open) { const firstItem = menuRef.current?.querySelector<HTMLButtonElement>('[role="menuitem"]'); firstItem?.focus(); } }, [open])…` |
| `frontend/src/components/admin/MembershipConfirmDialogs.tsx:28` | `useEffect(() => { if (open) setError(null); }, [open])…` |
| `frontend/src/components/admin/MembershipConfirmDialogs.tsx:94` | `useEffect(() => { if (open) setError(null); }, [open])…` |
| `frontend/src/components/admin/MembershipConfirmDialogs.tsx:156` | `useEffect(() => { if (open) { setConfirmedCheckbox(false); setError(null); } }, [open])…` |
| `frontend/src/components/admin/ScopedAdvisorPolicies.tsx:29` | `useEffect(() => { setStatus(initialStatus); setRules(JSON.stringify(owned?.status === 'ACTIVE' ? owned.rules : state.effective?.rules ?? definition.example, null, 2)); setConflict(false); setError(''); }, [state, definit…` |
| `frontend/src/components/admin/TenantSearchSelect.tsx:20` | `useEffect(() => { let cancelled = false; const timer = setTimeout(() => { listPlatformTenants(query, page).then(result => { if (!cancelled) { setTenants(result); setError(''); } }).catch(() => { if (!cancelled) setError(…` |
| `frontend/src/components/admin/TenantSearchSelect.tsx:31` | `useEffect(() => { if (!open) return; const close = (event: PointerEvent) => { if (!containerRef.current?.contains(event.target as Node)) setOpen(false); }; document.addEventListener('pointerdown', close); return () => do…` |
| `frontend/src/components/admin/UserActionsMenu.tsx:10` | `useEffect(() => { if (!open) return; action.current?.focus(); const close = (event: PointerEvent) => { if (!container.current?.contains(event.target as Node)) setOpen(false); }; document.addEventListener('pointerdown', c…` |
| `frontend/src/components/admin/UserLifecycle.tsx:73` | `useEffect(() => { let current = true; setLoading(true); setDirectoryError(''); const query = new URLSearchParams({ page: String(page), page_size: '20' }); if (search.trim()) query.set('search', search.trim()); if (status…` |
| `frontend/src/components/admin/UserLifecycle.tsx:90` | `useEffect(() => { if (!selected) return; let current = true; api(\`${prefix}/${platform ? selected.id : selected.membership_id}\`, scope).then(data => { if (current) setDetail(data); }).catch(e => { if (current) setError…` |
| `frontend/src/components/admin/UserSearchCombobox.tsx:53` | `useEffect(() => { function handleClickOutside(e: MouseEvent) { if (containerRef.current && !containerRef.current.contains(e.target as Node)) { setOpen(false); } } if (open) { document.addEventListener('mousedown', handle…` |
| `frontend/src/components/admin/UserSearchCombobox.tsx:65` | `useEffect(() => { const currentRequestId = ++requestIdRef.current; let cancelled = false; if (query.trim().length < 2) { setResults([]); setLoading(false); setSearchError(null); setOpen(false); return; } const timer = se…` |
| `frontend/src/components/ai-fixes/GlobalAiBatchProgress/AiBatchProgressProvider.tsx:66` | `useEffect(() => { let cancelled = false; const fetchInitial = async () => { try { if (batchId == null) { const snap = await getRunAiFixProgress(runId); if (cancelled) return; qc.setQueryData(batchProgressQueryKey(runId, …` |
| `frontend/src/components/ai-fixes/GlobalAiBatchProgress/AiBatchProgressProvider.tsx:107` | `useEffect(() => { let stopped = false; let pollTimer: ReturnType<typeof setInterval> \| null = null; let es: EventSource \| null = null; const queryKey = batchProgressQueryKey(runId, batchId); const streamUrl = batchId =…` |
| `frontend/src/components/ai-fixes/GlobalAiBatchProgress/AiBatchProgressProvider.tsx:322` | `useEffect(() => { const linger = lingerTimers.current; const stale = staleTimers.current; return () => { linger.forEach((t) => clearTimeout(t)); linger.clear(); stale.forEach((t) => clearTimeout(t)); stale.clear(); }; },…` |
| `frontend/src/components/ai-fixes/GlobalAiBatchProgress/useGlobalAiBatchProgress.ts:83` | `useEffect(() => { if (!shouldTrack \|\| !register) return; register({ runId: runId as number, batchId, scopeLabel, }); // Deliberately do NOT auto-unregister on unmount. The provider keeps // the entry tracked until term…` |
| `frontend/src/components/analysis/ConsolidatedAnalysisPanel.tsx:48` | `useEffect(() => { if (state.phase === 'done' && state.runId != null && state.runId !== lastNotifiedRunIdRef.current) { lastNotifiedRunIdRef.current = state.runId; onComplete?.(state.runId); } }, [state.phase, state.runId…` |
| `frontend/src/components/analysis/FindingFilterPanel.tsx:86` | `useEffect(() => { setPresets(loadPresets()); }, [])…` |
| `frontend/src/components/analysis/FindingsTable.tsx:461` | `useEffect(() => { setDensity(loadDensity()); }, [])…` |
| `frontend/src/components/analysis/FindingsTable.tsx:466` | `useEffect(() => { if (typeof window === 'undefined') return; window.localStorage.setItem(DENSITY_STORAGE_KEY, density); }, [density])…` |
| `frontend/src/components/analysis/FindingsTable.tsx:472` | `useEffect(() => { setFilter((prev) => prev.severityFilter === severityFilter ? prev : { ...prev, severityFilter }, ); // setFilter intentionally omitted: its controlled-mode identity follows filter state. // eslint-disab…` |
| `frontend/src/components/analysis/FindingsTable.tsx:572` | `useEffect(() => { pagination.resetPage(); // eslint-disable-next-line react-hooks/exhaustive-deps }, [filter])…` |
| `frontend/src/components/analysis/RunsTable.tsx:168` | `useEffect(() => { pagination.resetPage(); // eslint-disable-next-line react-hooks/exhaustive-deps }, [search, statusFilter, sourceFilter])…` |
| `frontend/src/components/auth/AuthGuard.tsx:31` | `useEffect(() => { if (isPublicPath) return; if ( bootstrapState === 'checking-session' \|\| bootstrapState === 'processing-callback' \|\| bootstrapState === 'loading-auth-context' \|\| bootstrapState === 'loading-tenant-…` |
| `frontend/src/components/auth/LoginCallback.tsx:24` | `useEffect(() => { if (hasExchangedRef.current) return; hasExchangedRef.current = true; async function handleCallback() { try { setBootstrapState('processing-callback'); const url = new URL(window.location.href); const co…` |
| `frontend/src/components/auth/MicrosoftSignIn.tsx:13` | `useEffect(() => { let cancelled = false; void (async () => { try { const response = await fetch('/api/auth/entra', { cache: 'no-store' }); if (!response.ok) throw new Error(); const config: Configuration = await response…` |
| `frontend/src/components/auth/NativePasswordSettings.tsx:9` | `useEffect(() => { void fetch('/api/auth/session').then(r => r.json()).then(s => setNative(s.authenticated && s.provider === 'NATIVE')).catch(() => setNative(false)); }, [])…` |
| `frontend/src/components/auth/PasswordLifecycleForm.tsx:14` | `useEffect(() => { setForced(new URLSearchParams(window.location.search).get('forced') === '1'); if (mode === 'change') void fetch('/api/auth/session').then(r => r.json()).then(s => setNative(s.authenticated && s.provider…` |
| `frontend/src/components/compare/CompareView.tsx:68` | `useEffect(() => { if (data) { setAPick(data.run_a); setBPick(data.run_b); } }, [data])…` |
| `frontend/src/components/compare/FindingRow/CveHoverCard.tsx:35` | `useEffect(() => { return () => { if (timer.current) clearTimeout(timer.current); }; }, [])…` |
| `frontend/src/components/compare/KeyboardShortcutsOverlay.tsx:30` | `useEffect(() => { const handler = (e: KeyboardEvent) => { const target = e.target as HTMLElement \| null; const tag = target?.tagName?.toLowerCase(); const editable = tag === 'input' \|\| tag === 'textarea' \|\| target?.…` |
| `frontend/src/components/compare/SelectionBar/RunPicker.tsx:74` | `useEffect(() => { const t = setTimeout(() => setDebounced(needle.trim()), 200); return () => clearTimeout(t); }, [needle])…` |
| `frontend/src/components/compare/SelectionBar/RunPicker.tsx:130` | `useEffect(() => { if (!open) return; const handler = (e: MouseEvent) => { if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) { setOpen(false); } }; document.addEventListener('mousedown', handler); return…` |
| `frontend/src/components/compare/SelectionBar/RunPicker.tsx:144` | `useEffect(() => { setActiveIndex(flatOptions.length > 0 ? 0 : -1); }, [flatOptions])…` |
| `frontend/src/components/component-advisor/ComponentGrid.tsx:48` | `useEffect(() => { if (selected && !dialog.current?.open) dialog.current?.showModal(); }, [selected])…` |
| `frontend/src/components/dashboard/TrendExplorer.tsx:79` | `useEffect(() => { setSelectedApps([]); }, [scope?.projectId, scope?.applicationId, scope?.sbomId, tenantId])…` |
| `frontend/src/components/layout/AppShell.tsx:116` | `useEffect(() => { if (isPublicPath) return; if (config.enabled && bootstrapState === 'unauthenticated') { void login(); return; } if (bootstrapState === 'verification-required' && pathname !== '/verification-required') {…` |
| `frontend/src/components/layout/CommandPalette.tsx:350` | `useEffect(() => { const onKey = (e: KeyboardEvent) => { if ((e.metaKey \|\| e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setOpen((o) => !o); } if (open && e.key === 'Escape') { e.preventDefault(); set…` |
| `frontend/src/components/layout/CommandPalette.tsx:371` | `useEffect(() => { if (open) { setQuery(''); setActiveIndex(0); requestAnimationFrame(() => inputRef.current?.focus()); } }, [open])…` |
| `frontend/src/components/layout/CommandPalette.tsx:402` | `useEffect(() => { if (activeIndex >= grouped.flat.length) { setActiveIndex(0); } }, [grouped.flat.length, activeIndex])…` |
| `frontend/src/components/layout/CommandPalette.tsx:409` | `useEffect(() => { if (!open) return; const list = listRef.current; if (!list) return; const items = list.querySelectorAll<HTMLElement>('[data-cmd-row]'); items[activeIndex]?.scrollIntoView({ block: 'nearest', behavior: '…` |
| `frontend/src/components/layout/KeyboardCheatsheet.tsx:102` | `useEffect(() => { const onKey = (e: KeyboardEvent) => { // Custom-event opener (from CommandPalette). // Handled in a separate effect below; here we only deal with raw keys. // While the cheatsheet is open, only handle E…` |
| `frontend/src/components/layout/KeyboardCheatsheet.tsx:164` | `useEffect(() => { if (open) { previouslyFocusedRef.current = document.activeElement as HTMLElement \| null; requestAnimationFrame(() => { panelRef.current?.focus(); }); } else { previouslyFocusedRef.current?.focus(); } }…` |
| `frontend/src/components/layout/Sidebar.tsx:76` | `useEffect(() => { closeMobile(); // eslint-disable-next-line react-hooks/exhaustive-deps }, [pathname])…` |
| `frontend/src/components/layout/Sidebar.tsx:243` | `useEffect(() => { if (isActive && item.children) setExpanded(true); }, [isActive, item.children])…` |
| `frontend/src/components/layout/Sidebar.tsx:247` | `useEffect(() => { if (!collapsed) setFlyoutOpen(false); }, [collapsed])…` |
| `frontend/src/components/layout/Sidebar.tsx:251` | `useEffect(() => { if (!flyoutOpen) return; const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') { setFlyoutOpen(false); triggerRef.current?.focus(); } }; const onPointerDown = (event: PointerEvent) => { …` |
| `frontend/src/components/layout/SidebarContext.tsx:50` | `useEffect(() => { if (!mobileOpen) return; const prev = document.body.style.overflow; document.body.style.overflow = 'hidden'; return () => { document.body.style.overflow = prev; }; }, [mobileOpen])…` |
| `frontend/src/components/layout/SidebarContext.tsx:61` | `useEffect(() => { if (typeof window === 'undefined') return; const mq = window.matchMedia('(min-width: 768px)'); const onChange = (e: MediaQueryListEvent) => { if (e.matches) setMobileOpen(false); }; mq.addEventListener(…` |
| `frontend/src/components/layout/SidebarContext.tsx:72` | `useEffect(() => { if (!mobileOpen) return; const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setMobileOpen(false); }; document.addEventListener('keydown', onKey); return () => document.removeEventListener('ke…` |
| `frontend/src/components/layout/TenantSwitcher.tsx:46` | `useEffect(() => { function handleClickOutside(e: MouseEvent) { if (containerRef.current && !containerRef.current.contains(e.target as Node)) { setOpen(false); } } if (open) { document.addEventListener('mousedown', handle…` |
| `frontend/src/components/layout/TenantSwitcher.tsx:59` | `useEffect(() => { function handleKey(e: KeyboardEvent) { if (e.key === 'Escape') { setOpen(false); triggerRef.current?.focus(); } if (e.key === 'ArrowDown' \|\| e.key === 'ArrowUp') { const options = Array.from(container…` |
| `frontend/src/components/layout/TopBar.tsx:28` | `useEffect(() => { if (typeof navigator === 'undefined') return; setIsMac( /mac\|iphone\|ipad\|ipod/i.test( navigator.platform \|\| navigator.userAgent \|\| '', ), ); }, [])…` |
| `frontend/src/components/layout/UserMenu.tsx:54` | `useEffect(() => { if (!open) return; const closeOutside = (event: MouseEvent) => { if (!menuRef.current?.contains(event.target as Node)) setOpen(false); }; const handleKey = (event: KeyboardEvent) => { if (event.key === …` |
| `frontend/src/components/products/ProductFormDialog.tsx:89` | `useEffect(() => { if (!open) return; if (product) { setForm({ name: product.name, description: product.description ?? '', vendor: product.vendor ?? '', ...getProductCategoryFormValue(product.category), status: product.st…` |
| `frontend/src/components/projects/InventoryActionMenu.tsx:39` | `useEffect(() => { if (!open) return; const outside = (event: PointerEvent) => { if (!menu.current?.contains(event.target as Node) && !trigger.current?.contains(event.target as Node)) setOpen(false); }; const dismiss = ()…` |
| `frontend/src/components/projects/ProjectModal.tsx:59` | `useEffect(() => { if (project) { reset({ project_name: project.project_name, project_details: project.project_details ?? '', project_status: toStatusStr(project.project_status), }); } else { reset({ project_name: '', pro…` |
| `frontend/src/components/projects/ProjectsTable.tsx:224` | `useEffect(() => { pagination.resetPage(); // eslint-disable-next-line react-hooks/exhaustive-deps }, [search, statusFilter])…` |
| `frontend/src/components/projects/ProjectsTable.tsx:230` | `useEffect(() => { if (isLoading \|\| error) return; if (initialProjectId !== positionedProject.current) { const index = sortedRows.findIndex(project => project.id === initialProjectId); const targetPage = index < 0 ? pag…` |
| `frontend/src/components/sboms/SbomConversionCard.tsx:56` | `useEffect(() => { setConvertedId(sbom.converted_sbom_id ?? null); setEnrichmentStatus(sbom.enrichment_status ?? null); }, [sbom.converted_sbom_id, sbom.enrichment_status])…` |
| `frontend/src/components/sboms/SbomConversionCard.tsx:80` | `useEffect(() => { const polled = enrichmentPollQuery.data?.enrichment_status; if (polled && polled !== enrichmentStatus) { setEnrichmentStatus(polled); if (polled === 'completed') { setMessage('Lifecycle enrichment compl…` |
| `frontend/src/components/sboms/SbomDetail.tsx:462` | `useEffect(() => { const timer = window.setTimeout(() => { setDebouncedComponentSearch(componentSearch.trim()); setComponentPage(1); }, 250); return () => window.clearTimeout(timer); }, [componentSearch])…` |
| `frontend/src/components/sboms/SbomDetail.tsx:583` | `useEffect(() => { if (!isVexOverrideOpen) return; let cancelled = false; const statement: VexStatement \| null = JSON.parse(selectedVexDecisionJson); setVexOverrideStatus((statement?.status as VexStatus) \|\| 'under_inve…` |
| `frontend/src/components/sboms/SbomDetail.tsx:642` | `useEffect(() => { setComponentPage(1); }, [showDuplicates])…` |
| `frontend/src/components/sboms/SbomDetail.tsx:646` | `useEffect(() => { runPagination.resetPage(); }, [runs?.length])…` |
| `frontend/src/components/sboms/SbomUploadModal.tsx:217` | `useEffect(() => { if (!open) return; if (initialProjectId) { setValue('projectid', String(initialProjectId), { shouldValidate: true }); } if (initialProductId) { setValue('productid', String(initialProductId), { shouldVa…` |
| `frontend/src/components/sboms/SbomUploadModal.tsx:227` | `useEffect(() => { if (userManuallyOverrodeFormat \|\| !formatDetection \|\| !sbomTypes?.length) return; const detectedTypeId = matchSbomTypeIdForFormat(formatDetection.detected_format, sbomTypes); setValue('sbom_type_id'…` |
| `frontend/src/components/sboms/SbomUploadModal.tsx:447` | `useEffect(() => { setValue('logical_sbom_id', ''); }, [selectedProductId, setValue])…` |
| `frontend/src/components/sboms/SbomsTable.tsx:289` | `useEffect(() => { pagination.resetPage(); // eslint-disable-next-line react-hooks/exhaustive-deps }, [search, projectFilter, productFilter, analysisFilter, validationFilter])…` |
| `frontend/src/components/sboms/SbomsTable.tsx:294` | `useEffect(() => { if (productFilter && !productOptions.includes(productFilter)) { setProductFilter(''); } }, [productFilter, productOptions])…` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:89` | `useEffect(() => { if (!paneFocusRequested.current) return; paneFocusRequested.current = false; if (issuesHidden) editorPaneRef.current?.querySelector<HTMLButtonElement>('[aria-label="Show validation issues"]')?.focus(); …` |
| `frontend/src/components/sboms/ValidationRepairWorkspace.tsx:140` | `useEffect(() => { const chunk = initialContentQuery.data; if (!chunk \|\| contentLoaded) return; setContent(chunk.content); if (chunk.eof) setSavedContent(chunk.content); setLoadedContentSize(chunk.offset + chunk.content…` |
| `frontend/src/components/sboms/repair/LargeFileRepairEditor.tsx:74` | `useEffect(() => { onBusyChange(patchMutation.isPending); return () => onBusyChange(false); }, [patchMutation.isPending, onBusyChange])…` |
| `frontend/src/components/sboms/repair/LargeFileRepairEditor.tsx:75` | `useEffect(() => { if (!navigation) return; if (navigation.line) { setStartLine(navigation.line); setJumpLine(String(navigation.line)); setPatch(old => ({ ...old, start_line: navigation.line!, end_line: navigation.line! }…` |
| `frontend/src/components/sboms/repair/RepairIssueNavigator.tsx:18` | `useEffect(() => { const list = listRef.current; const selected = list?.querySelector<HTMLElement>('[data-selected="true"]'); if (!list \|\| !selected) return; const offset = selected.getBoundingClientRect().top - list.ge…` |
| `frontend/src/components/schedules/ScheduleEditor.tsx:97` | `useEffect(() => { if (open) setForm(defaultsFromExisting(existing)); }, [open, existing])…` |
| `frontend/src/components/settings/ai/AddProviderDialog/AddProviderDialog.tsx:67` | `useEffect(() => { if (!entry) return; setApiKey(''); setLabel('default'); setShowKey(false); setBaseUrl(entry.name === 'ollama' ? 'http://localhost:11434' : ''); const firstModel = entry.available_models[0]?.name ?? ''; …` |
| `frontend/src/components/settings/ai/AddProviderDialog/AddProviderDialog.tsx:85` | `useEffect(() => { testMut.reset(); }, [apiKey, baseUrl, defaultModel, tier, costIn, costOut, isLocal])…` |
| `frontend/src/components/settings/ai/AddProviderDialog/AddProviderDialog.tsx:87` | `useEffect(() => { if (!open) { setApiKey(''); setShowKey(false); testMut.reset(); setSubmitError(null); } }, [open])…` |
| `frontend/src/components/settings/ai/BudgetCapsForm/BudgetCapsForm.tsx:34` | `useEffect(() => { if (!settings) return; setPerRequest(settings.budget_per_request_usd.toFixed(2)); setPerScan(settings.budget_per_scan_usd.toFixed(2)); setPerDay(settings.budget_daily_usd.toFixed(2)); setKillSwitch(sett…` |
| `frontend/src/components/settings/ai/EditProviderDialog/EditProviderDialog.tsx:55` | `useEffect(() => { if (!credential) return; setApiKey(''); setLabel(credential.label); setShowKey(false); setBaseUrl(credential.base_url ?? ''); setDefaultModel(credential.default_model ?? ''); setTier((credential.tier ==…` |
| `frontend/src/components/settings/ai/EditProviderDialog/EditProviderDialog.tsx:71` | `useEffect(() => { testMut.reset(); }, [apiKey, baseUrl, defaultModel, tier])…` |
| `frontend/src/components/theme/ThemeProvider.tsx:35` | `useEffect(() => { const stored = localStorage.getItem(STORAGE_KEY) as Theme \| null; const initial: Theme = stored === 'dark' \|\| stored === 'light' ? stored : 'light'; setThemeState(initial); setResolvedTheme(initial);…` |
| `frontend/src/components/theme/ThemeToggle.tsx:11` | `useEffect(() => setMounted(true), [])…` |
| `frontend/src/components/ui/AnimatedSeverityBar.tsx:41` | `useEffect(() => { setArmed(false); const id = window.requestAnimationFrame(() => { window.requestAnimationFrame(() => setArmed(true)); }); return () => window.cancelAnimationFrame(id); }, [triggerKey])…` |
| `frontend/src/components/ui/DeleteConfirmDialog.tsx:94` | `useEffect(() => { if (open) { setMode('soft'); setTyped(''); } }, [open])…` |
| `frontend/src/components/ui/Dialog.tsx:79` | `useEffect(() => { if (!open) return; const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') { e.stopPropagation(); onClose(); return; } if (e.key === 'Tab' && panelRef.current) { const focusable = getFocusable(p…` |
| `frontend/src/components/ui/Dialog.tsx:116` | `useEffect(() => { if (open) { document.body.style.overflow = 'hidden'; document.body.dataset.dialogOpen = 'true'; } else { document.body.style.overflow = ''; delete document.body.dataset.dialogOpen; } return () => { docu…` |
| `frontend/src/components/ui/Dialog.tsx:130` | `useEffect(() => { if (open) { previouslyFocused.current = (document.activeElement as HTMLElement) ?? null; const raf = requestAnimationFrame(() => { if (panelRef.current) { const focusable = getFocusable(panelRef.current…` |
| `frontend/src/components/ui/ExportMenu.tsx:35` | `useEffect(() => { if (!open) return; const onDocClick = (e: MouseEvent) => { if (!containerRef.current?.contains(e.target as Node)) setOpen(false); }; const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') { setOp…` |
| `frontend/src/components/ui/Select.tsx:123` | `useEffect(() => { if (!isOpen \|\| !triggerRef.current) return; const rect = triggerRef.current.getBoundingClientRect(); const spaceBelow = window.innerHeight - rect.bottom; const spaceAbove = rect.top; if (spaceBelow < …` |
| `frontend/src/components/ui/Select.tsx:136` | `useEffect(() => { if (!isOpen) return; function handleClickOutside(e: MouseEvent) { if (containerRef.current && !containerRef.current.contains(e.target as Node)) { setIsOpen(false); setSearchQuery(''); } } document.addEv…` |
| `frontend/src/components/ui/Select.tsx:149` | `useEffect(() => { if (isOpen) { const currentIdx = options.findIndex((opt) => opt.value === currentValue); setHighlightedIndex(currentIdx >= 0 ? currentIdx : 0); if (options.length >= 10) { setTimeout(() => { searchInput…` |
| `frontend/src/components/ui/Select.tsx:166` | `useEffect(() => { if (highlightedIndex < 0 \|\| !popupRef.current) return; const el = popupRef.current.querySelector(\`#${listboxId}-opt-${highlightedIndex}\`); if (el && typeof el.scrollIntoView === 'function') { el.scr…` |
| `frontend/src/components/ui/SelectionCheckbox.tsx:45` | `useEffect(() => { if (ref.current) { ref.current.indeterminate = state === 'some'; } }, [state])…` |
| `frontend/src/components/vex/AssigneeCombobox.tsx:48` | `useEffect(() => { if (!open) return; const place = () => { const rect = input.current?.getBoundingClientRect(); if (!rect) return; if (rect.bottom < 0 \|\| rect.top > window.innerHeight) { setOpen(false); return; } const…` |
| `frontend/src/components/vex/VexDecisionEditor.tsx:102` | `useEffect(() => { setDraft(draftFromInvestigation(investigation)); setErrors({}); setSubmitError(null); }, [investigation, componentId, vulnerabilityId])…` |
| `frontend/src/components/vex/VexInvestigationPanel.tsx:33` | `useEffect(() => { setAssignee(detail.internal_decision.assigned_to ?? ''); setSavedDetail(detail); setFormError(null); }, [detail])…` |
| `frontend/src/components/vulnerabilities/CveDetailDialog/CveDetailDialog.tsx:145` | `useEffect(() => { setActiveTab(initialTab); }, [open, cveId, initialTab])…` |
| `frontend/src/hooks/useAiFix.ts:160` | `useEffect(() => { if (!active) return; if (typeof window === 'undefined' \|\| typeof EventSource === 'undefined') { setSseAvailable(false); return; } const url = aiFixStreamUrl(runId as number); let es: EventSource \| nu…` |
| `frontend/src/hooks/useAiFix.ts:271` | `useEffect(() => { const handle = setTimeout(() => setDebouncedScope(scope), debounceMs); return () => clearTimeout(handle); // eslint-disable-next-line react-hooks/exhaustive-deps -- scopeKey captures scope identity }, […` |
| `frontend/src/hooks/useAuth.tsx:492` | `useEffect(() => { const isLoadingState = bootstrapState === 'checking-session' \|\| bootstrapState === 'processing-callback' \|\| bootstrapState === 'loading-auth-context' \|\| bootstrapState === 'loading-tenant-context'…` |
| `frontend/src/hooks/useAuth.tsx:518` | `useEffect(() => { void checkAuth(); }, [checkAuth])…` |
| `frontend/src/hooks/usePagination.ts:76` | `useEffect(() => { if (page > totalPages) setPageRaw(totalPages); if (page < 1) setPageRaw(1); }, [page, totalPages])…` |
| `frontend/src/hooks/usePendingAnalysisRecovery.ts:27` | `useEffect(() => { const pending = getStillPendingAnalyses(); if (pending.length === 0) return; for (const { sbomId } of pending) { getRuns({ sbom_id: sbomId, page: 1, page_size: 1 }) .then((runs) => { if (runs.length > 0…` |
| `frontend/src/hooks/useToast.tsx:124` | `useEffect(() => setMounted(true), [])…` |
| `frontend/src/hooks/useToast.tsx:176` | `useEffect(() => { if (toast.duration <= 0) return undefined; const timer = window.setTimeout(() => dismiss(toast.id), toast.duration); return () => window.clearTimeout(timer); }, [toast.id, toast.message, toast.variant, …` |
| `frontend/src/lib/pinned.ts:113` | `useEffect(() => { const refresh = () => setItems(listPinned(kind)); refresh(); window.addEventListener(CHANGE_EVENT[kind], refresh); // Cross-tab sync: storage event fires when another tab writes. const onStorage = (e: S…` |

### Appendix E — FastAPI route/response registry

Router-relative paths retain their actual router prefixes. Application mounting may additionally prefix routers; frontend API request paths are in Appendix C and API adapters. Return-line locations identify the exact payload/service result; delegated services remain authoritative for transaction completion.

| Location / handler | Router prefix | Method / route | Explicit response / status | Return locations |
|---|---|---|---|---|
| `app/routers/ai_copilot.py:52` copilot_briefing | `'/api/ai/copilot'` | GET `'/briefing'` | `` | 59 |
| `app/routers/ai_copilot.py:79` copilot_ask | `'/api/ai/copilot'` | POST `'/ask'` | `` | 83 |
| `app/routers/ai_credentials.py:495` list_credentials | `` | GET `'/credentials'` | `response_model=list[CredentialResponse]` | 497 |
| `app/routers/ai_credentials.py:501` get_credential | `` | GET `'/credentials/{cred_id}'` | `response_model=CredentialResponse` | 505 |
| `app/routers/ai_credentials.py:509` get_effective_config_diagnostic | `` | GET `'/effective-config'` | `response_model=EffectiveConfigDiagnostic` | 552 |
| `app/routers/ai_credentials.py:579` create_credential | `` | POST `'/credentials'` | `response_model=CredentialResponse; status_code=201` | 674 |
| `app/routers/ai_credentials.py:678` update_credential | `` | PUT `'/credentials/{cred_id}'` | `response_model=CredentialResponse` | 788 |
| `app/routers/ai_credentials.py:792` delete_credential | `` | DELETE `'/credentials/{cred_id}'` | `status_code=204` |  |
| `app/routers/ai_credentials.py:825` set_default_credential | `` | PUT `'/credentials/{cred_id}/set-default'` | `response_model=CredentialResponse` | 858 |
| `app/routers/ai_credentials.py:862` set_fallback_credential | `` | PUT `'/credentials/{cred_id}/set-fallback'` | `response_model=CredentialResponse` | 893 |
| `app/routers/ai_credentials.py:902` test_unsaved_credential | `` | POST `'/credentials/test'` | `response_model=ConnectionTestResult` | 958, 940 |
| `app/routers/ai_credentials.py:962` test_saved_credential | `` | POST `'/credentials/{cred_id}/test'` | `response_model=ConnectionTestResult` | 1010 |
| `app/routers/ai_credentials.py:1019` list_provider_models | `` | GET `'/credentials/{cred_id}/models'` | `response_model=list[ProviderModelResponse]` | 1038 |
| `app/routers/ai_credentials.py:1042` refresh_provider_models | `` | POST `'/credentials/{cred_id}/models/refresh'` | `response_model=ModelRefreshResponse` | 1079 |
| `app/routers/ai_credentials.py:1083` select_provider_model | `` | POST `'/credentials/{cred_id}/models/{model_id}/select'` | `response_model=ProviderModelResponse` | 1109 |
| `app/routers/ai_credentials.py:1113` test_provider_model | `` | POST `'/credentials/{cred_id}/models/{model_id}/test'` | `response_model=ModelTestResponse` | 1132 |
| `app/routers/ai_credentials.py:1141` get_singleton_settings | `` | GET `'/settings'` | `response_model=SettingsResponse` | 1158, 1148 |
| `app/routers/ai_credentials.py:1171` update_singleton_settings | `` | PUT `'/settings'` | `response_model=SettingsResponse` | 1241 |
| `app/routers/ai_credentials.py:1245` create_tenant_override | `` | POST `'/override'` | `response_model=SettingsResponse` | 1252 |
| `app/routers/ai_credentials.py:1256` reset_tenant_override | `` | DELETE `'/override'` | `status_code=204` |  |
| `app/routers/ai_credentials.py:1283` configuration_provider_catalog | `` | GET `'/providers/available'` | `` | 1286 |
| `app/routers/ai_credentials.py:1290` configuration_provider_catalog_entry | `` | GET `'/providers/available/{name}'` | `` | 1293 |
| `app/routers/ai_fixes.py:314` trigger_run_fixes | `'/api/v1'` | POST `'/runs/{run_id}/ai-fixes'` | `response_model=TriggerBatchResponse` | 426 |
| `app/routers/ai_fixes.py:496` estimate_run_duration_legacy | `'/api/v1'` | GET `'/runs/{run_id}/ai-fixes/estimate'` | `response_model=BatchDurationEstimateResponse` | 505 |
| `app/routers/ai_fixes.py:512` estimate_run_duration | `'/api/v1'` | POST `'/runs/{run_id}/ai-fixes/estimate'` | `response_model=EstimateResponse` | 582, 538 |
| `app/routers/ai_fixes.py:681` list_run_batches | `'/api/v1'` | GET `'/runs/{run_id}/ai-fixes/batches'` | `response_model=BatchListResponse` | 685 |
| `app/routers/ai_fixes.py:696` get_run_batch | `'/api/v1'` | GET `'/runs/{run_id}/ai-fixes/batches/{batch_id}'` | `response_model=BatchDetailResponse` | 706 |
| `app/routers/ai_fixes.py:710` stream_batch_progress | `'/api/v1'` | GET `'/runs/{run_id}/ai-fixes/batches/{batch_id}/stream'` | `` | 726 |
| `app/routers/ai_fixes.py:733` cancel_run_batch | `'/api/v1'` | POST `'/runs/{run_id}/ai-fixes/batches/{batch_id}/cancel'` | `status_code=202` | 743 |
| `app/routers/ai_fixes.py:757` get_progress | `'/api/v1'` | GET `'/runs/{run_id}/ai-fixes/progress'` | `response_model=BatchProgress` | 792, 786, 791 |
| `app/routers/ai_fixes.py:800` cancel_run_fixes_legacy | `'/api/v1'` | POST `'/runs/{run_id}/ai-fixes/cancel'` | `status_code=202` | 819 |
| `app/routers/ai_fixes.py:826` stream_progress_legacy | `'/api/v1'` | GET `'/runs/{run_id}/ai-fixes/stream'` | `` | 848, 847 |
| `app/routers/ai_fixes.py:890` list_run_fixes | `'/api/v1'` | GET `'/runs/{run_id}/ai-fixes'` | `response_model=FindingFixListResponse` | 926, 910 |
| `app/routers/ai_fixes.py:953` get_finding_fix | `'/api/v1'` | GET `'/findings/{finding_id}/ai-fix'` | `response_model=FindingFixResponse` | 968 |
| `app/routers/ai_fixes.py:972` generate_finding_fix | `'/api/v1'` | POST `'/findings/{finding_id}/ai-fix'` | `response_model=FindingFixResponse` | 987 |
| `app/routers/ai_fixes.py:991` regenerate_finding_fix | `'/api/v1'` | POST `'/findings/{finding_id}/ai-fix:regenerate'` | `response_model=FindingFixResponse` | 1001 |
| `app/routers/ai_usage.py:144` get_ai_usage | `'/api/v1/ai'` | GET `'/usage'` | `response_model=AiUsageSummary` | 163 |
| `app/routers/ai_usage.py:175` list_providers | `'/api/v1/ai'` | GET `'/providers'` | `response_model=list[ProviderInfo]` | 177 |
| `app/routers/ai_usage.py:188` list_pricing | `'/api/v1/ai'` | GET `'/pricing'` | `response_model=list[PricingEntry]` | 205 |
| `app/routers/ai_usage.py:209` reset_provider_registry | `'/api/v1/ai'` | POST `'/registry/reset'` | `status_code=204` |  |
| `app/routers/ai_usage.py:238` get_usage_trend | `'/api/v1/ai'` | GET `'/usage/trend'` | `response_model=TrendResponse` | 261 |
| `app/routers/ai_usage.py:289` get_top_cached_fixes | `'/api/v1/ai'` | GET `'/usage/top-cached'` | `response_model=list[TopCachedItem]` | 300 |
| `app/routers/ai_usage.py:316` get_metrics_json | `'/api/v1/ai'` | GET `'/metrics'` | `response_model=None` | 322 |
| `app/routers/ai_usage.py:326` get_metrics_prometheus | `'/api/v1/ai'` | GET `'/metrics/prometheus'` | `` | 332 |
| `app/routers/ai_usage.py:341` get_provider_catalog | `'/api/v1/ai'` | GET `'/providers/available'` | `response_model=list[ProviderCatalogEntry]` | 352 |
| `app/routers/ai_usage.py:356` get_provider_catalog_entry | `'/api/v1/ai'` | GET `'/providers/available/{name}'` | `response_model=ProviderCatalogEntry` | 363 |
| `app/routers/analysis.py:74` compare_analysis_runs | `` | GET `'/compare'` | `status_code=200` | 161, 156 |
| `app/routers/analysis.py:185` export_sarif | `` | GET `'/{run_id}/export/sarif'` | `status_code=200` | 295, 207, 202, 204, 206 |
| `app/routers/analysis.py:303` export_csv | `` | GET `'/{run_id}/export/csv'` | `status_code=200` | 406 |
| `app/routers/analyze_endpoints.py:205` analyze_sbom_nvd | `` | POST `'/analyze-sbom-nvd'` | `` | 240, 231, 239 |
| `app/routers/analyze_endpoints.py:248` analyze_sbom_github | `` | POST `'/analyze-sbom-github'` | `` | 282, 273, 281 |
| `app/routers/analyze_endpoints.py:290` analyze_sbom_osv | `` | POST `'/analyze-sbom-osv'` | `` | 324, 315, 323 |
| `app/routers/analyze_endpoints.py:332` analyze_sbom_vulndb | `` | POST `'/analyze-sbom-vulndb'` | `` | 368, 357, 367 |
| `app/routers/analyze_endpoints.py:376` analyze_sbom_consolidated | `` | POST `'/analyze-sbom-consolidated'` | `` | 414, 405, 413 |
| `app/routers/authorization_catalog.py:131` list_roles | `'/api/platform/authorization'` | GET `'/roles'` | `response_model=AuthorizationRolePage` | 177 |
| `app/routers/authorization_catalog.py:186` get_role | `'/api/platform/authorization'` | GET `'/roles/{role_id}'` | `response_model=AuthorizationRoleDetail` | 206 |
| `app/routers/authorization_catalog.py:210` list_permissions | `'/api/platform/authorization'` | GET `'/permissions'` | `response_model=AuthorizationPermissionPage` | 256 |
| `app/routers/authorization_catalog.py:265` get_matrix | `'/api/platform/authorization'` | GET `'/matrix'` | `response_model=AuthorizationMatrixResponse` | 287 |
| `app/routers/authorization_catalog.py:291` patch_role | `'/api/platform/authorization'` | PATCH `'/roles/{role_id}'` | `response_model=AuthorizationRoleDetail` | 311 |
| `app/routers/authorization_catalog.py:326` put_role_permissions | `'/api/platform/authorization'` | PUT `'/roles/{role_id}/permissions'` | `response_model=AuthorizationRoleDetail` | 345 |
| `app/routers/compare.py:76` compare_runs | `'/api/v1'` | POST `'/compare'` | `response_model=CompareResult` | 84 |
| `app/routers/compare.py:91` export_compare | `'/api/v1'` | POST `'/compare/{cache_key}/export'` | `` | 144 |
| `app/routers/component_advisor.py:125` advisor_summary | `'/api/platform/configuration/advisor-policies'` | GET `'/summary'` | `` | 148 |
| `app/routers/component_advisor.py:152` advisor_components | `'/api/platform/configuration/advisor-policies'` | GET `'/components'` | `` | 178 |
| `app/routers/component_advisor.py:182` advisor_component_detail | `'/api/platform/configuration/advisor-policies'` | GET `'/components/{canonical_key}'` | `` | 199 |
| `app/routers/component_advisor.py:209` advisor_component_classification | `'/api/platform/configuration/advisor-policies'` | GET `'/components/{canonical_key}/classification'` | `` | 226 |
| `app/routers/component_advisor.py:255` advisor_search | `'/api/platform/configuration/advisor-policies'` | GET `'/search'` | `` | 287 |
| `app/routers/component_advisor.py:336` get_policy | `'/api/platform/configuration/advisor-policies'` | GET `'/policies/{kind}'` | `` | 342 |
| `app/routers/component_advisor.py:346` get_policy_versions | `'/api/platform/configuration/advisor-policies'` | GET `'/policies/{kind}/versions'` | `` | 353 |
| `app/routers/component_advisor.py:357` post_policy_version | `'/api/platform/configuration/advisor-policies'` | POST `'/policies/{kind}/versions'` | `status_code=201` | 393 |
| `app/routers/component_advisor.py:412` get_purpose | `'/api/platform/configuration/advisor-policies'` | GET `'/purpose/{family_key:path}'` | `` | 418 |
| `app/routers/component_advisor.py:422` put_purpose | `'/api/platform/configuration/advisor-policies'` | PUT `'/purpose/{family_key:path}'` | `` | 448 |
| `app/routers/component_advisor.py:469` create_recommendation | `'/api/platform/configuration/advisor-policies'` | POST `'/recommendations'` | `` | 507 |
| `app/routers/component_advisor.py:514` list_recommendations | `'/api/platform/configuration/advisor-policies'` | GET `'/recommendations'` | `` | 526 |
| `app/routers/component_advisor.py:535` get_recommendation | `'/api/platform/configuration/advisor-policies'` | GET `'/recommendations/{recommendation_id}'` | `` | 545 |
| `app/routers/component_advisor.py:549` get_recommendation_candidates | `'/api/platform/configuration/advisor-policies'` | GET `'/recommendations/{recommendation_id}/candidates'` | `` | 560 |
| `app/routers/component_advisor.py:564` evaluate_recommendation | `'/api/platform/configuration/advisor-policies'` | POST `'/recommendations/{recommendation_id}/evaluate'` | `` | 587 |
| `app/routers/component_advisor.py:611` add_manual_candidate | `'/api/platform/configuration/advisor-policies'` | POST `'/recommendations/{recommendation_id}/candidates'` | `status_code=201` | 633 |
| `app/routers/component_advisor.py:637` get_candidate | `'/api/platform/configuration/advisor-policies'` | GET `'/recommendations/{recommendation_id}/candidates/{candidate_id}'` | `` | 648 |
| `app/routers/component_advisor.py:655` get_candidate_compatibility | `'/api/platform/configuration/advisor-policies'` | GET `'/recommendations/{recommendation_id}/candidates/{candidate_id}/compatibility'` | `` | 666 |
| `app/routers/component_advisor.py:674` get_candidate_evidence | `'/api/platform/configuration/advisor-policies'` | GET `'/recommendations/{recommendation_id}/candidates/{candidate_id}/evidence'` | `` | 692 |
| `app/routers/component_advisor.py:728` post_decision | `'/api/platform/configuration/advisor-policies'` | POST `'/recommendations/{recommendation_id}/decisions'` | `` | 768 |
| `app/routers/component_advisor.py:772` get_recommendation_events | `'/api/platform/configuration/advisor-policies'` | GET `'/recommendations/{recommendation_id}/events'` | `` | 784 |
| `app/routers/component_advisor.py:789` get_audit_events | `'/api/platform/configuration/advisor-policies'` | GET `'/audit/events'` | `` | 798 |
| `app/routers/component_advisor.py:809` get_analytics | `'/api/platform/configuration/advisor-policies'` | GET `'/analytics'` | `` | 818 |
| `app/routers/cves.py:70` get_cve_detail | `'/api/v1'` | GET `'/cves/{cve_id}'` | `response_model=CveDetail` | 77 |
| `app/routers/cves.py:84` batch_cve_detail | `'/api/v1'` | POST `'/cves/batch'` | `response_model=CveBatchResponse` | 108 |
| `app/routers/cves.py:116` get_cve_detail_with_scan_context | `'/api/v1'` | GET `'/scans/{scan_id}/cves/{cve_id}'` | `response_model=CveDetailWithContext` | 125 |
| `app/routers/dashboard.py:35` dashboard_trend | `` | GET `'/trend'` | `response_model=FindingsTrendResponse; status_code=200` | 119, 118 |
| `app/routers/dashboard_advanced.py:38` dashboard_forecast | `'/dashboard'` | GET `'/forecast'` | `` | 56, 55 |
| `app/routers/dashboard_advanced.py:60` dashboard_exploitation | `'/dashboard'` | GET `'/exploitation'` | `` | 70, 69 |
| `app/routers/dashboard_advanced.py:74` dashboard_remediation | `'/dashboard'` | GET `'/remediation'` | `` | 80, 79 |
| `app/routers/dashboard_advanced.py:84` dashboard_risk_map | `'/dashboard'` | GET `'/risk-map'` | `` | 90, 89 |
| `app/routers/dashboard_advanced.py:94` dashboard_risk_matrix | `'/dashboard'` | GET `'/risk-matrix'` | `` | 105, 104 |
| `app/routers/dashboard_main.py:65` dashboard_posture_versions | `'/dashboard'` | GET `'/posture-versions'` | `` | 70 |
| `app/routers/dashboard_main.py:83` dashboard_project_options | `'/dashboard'` | GET `'/filter-options/projects'` | `` | 87 |
| `app/routers/dashboard_main.py:91` dashboard_scanned_project_ids | `'/dashboard'` | GET `'/scanned-project-ids'` | `` | 92 |
| `app/routers/dashboard_main.py:96` dashboard_application_options | `'/dashboard'` | GET `'/filter-options/applications'` | `` | 104 |
| `app/routers/dashboard_main.py:108` dashboard_sbom_options | `'/dashboard'` | GET `'/filter-options/sboms'` | `` | 119 |
| `app/routers/dashboard_main.py:129` dashboard_scoped_runs | `'/dashboard'` | GET `'/runs'` | `` | 136 |
| `app/routers/dashboard_main.py:140` dashboard_priority_findings | `'/dashboard'` | GET `'/priority-findings'` | `` | 146 |
| `app/routers/dashboard_main.py:150` dashboard_stats | `'/dashboard'` | GET `'/stats'` | `` | 178, 177 |
| `app/routers/dashboard_main.py:182` dashboard_recent_sboms | `'/dashboard'` | GET `'/recent-sboms'` | `` | 188 |
| `app/routers/dashboard_main.py:192` dashboard_activity | `'/dashboard'` | GET `'/activity'` | `` | 201, 200 |
| `app/routers/dashboard_main.py:205` dashboard_severity | `'/dashboard'` | GET `'/severity'` | `` | 215, 214 |
| `app/routers/dashboard_main.py:219` dashboard_posture | `'/dashboard'` | GET `'/posture'` | `response_model=DashboardPostureResponse` | 295, 294 |
| `app/routers/dashboard_main.py:321` dashboard_vulnerability_age | `'/dashboard'` | GET `'/vulnerability-age'` | `response_model=VulnerabilityAgeResponse` | 337 |
| `app/routers/dashboard_main.py:348` dashboard_lifetime | `'/dashboard'` | GET `'/lifetime'` | `response_model=LifetimeMetrics` | 372, 371 |
| `app/routers/dashboard_main.py:391` get_dashboard_lifecycle | `'/dashboard'` | GET `'/lifecycle'` | `` | 394 |
| `app/routers/dashboard_main.py:405` get_dashboard_vex | `'/dashboard'` | GET `'/vex'` | `response_model=DashboardVexResponse` | 414 |
| `app/routers/dashboard_main.py:420` get_dashboard_health | `'/dashboard'` | GET `'/health'` | `` | 422 |
| `app/routers/dashboard_main.py:430` get_dashboard_remediation_stats | `'/dashboard'` | GET `'/remediation-stats'` | `` | 435 |
| `app/routers/dashboard_main.py:447` get_dashboard_summary | `'/dashboard'` | GET `'/summary'` | `` | 653, 652 |
| `app/routers/entra_auth.py:16` session | `'/api/auth/entra'` | GET `'/session'` | `` | 22 |
| `app/routers/health.py:127` service_info | `` | GET `'/'` | `` | 128 |
| `app/routers/health.py:137` health | `` | GET `'/health'` | `` | 139 |
| `app/routers/health.py:209` get_analysis_config | `` | GET `'/api/analysis/config'` | `` | 210 |
| `app/routers/health.py:218` list_sbom_types | `` | GET `'/api/types'` | `response_model=list[SBOMTypeOut]` | 220 |
| `app/routers/health.py:224` iam_readiness | `` | GET `'/ready/iam'` | `` | 231, 229 |
| `app/routers/kev.py:229` sync_kev_catalog | `'/api/v1/kev'` | POST `'/sync'` | `response_model=KevSyncResponse` | 241 |
| `app/routers/kev.py:245` get_kev_filter_options | `'/api/v1/kev'` | GET `'/filter-options'` | `response_model=KevFilterOptionsOut` | 256 |
| `app/routers/kev.py:267` list_kev_vulnerabilities | `'/api/v1/kev'` | GET `''` | `response_model=KevVulnerabilityListOut` | 352 |
| `app/routers/kev.py:361` get_kev_vulnerability | `'/api/v1/kev'` | GET `'/{cve_id}'` | `response_model=KevVulnerabilityOut` | 368 |
| `app/routers/lifecycle.py:27` list_lifecycle_sources | `` | GET `'/api/lifecycle/sources'` | `` | 52, 32 |
| `app/routers/lifecycle.py:56` lifecycle_provider_status | `` | GET `'/api/lifecycle/provider-status'` | `` | 76, 82 |
| `app/routers/lifecycle.py:86` get_component_lifecycle | `` | GET `'/api/lifecycle/component/{component_id}'` | `response_model=SBOMComponentOut` | 93 |
| `app/routers/lifecycle.py:97` update_component_lifecycle | `` | PUT `'/api/lifecycle/component/{component_id}'` | `response_model=SBOMComponentOut` | 105 |
| `app/routers/lifecycle.py:114` patch_component_lifecycle_override | `` | PATCH `'/api/components/{component_id}/lifecycle-override'` | `response_model=SBOMComponentOut` | 122 |
| `app/routers/lifecycle.py:131` refresh_component_lifecycle_endpoint | `` | POST `'/api/components/{component_id}/lifecycle/refresh'` | `response_model=SBOMComponentOut` | 138 |
| `app/routers/lifecycle_admin.py:42` reset_provider_override | `` | DELETE `'/api/admin/lifecycle-providers/{provider_key}/override'` | `status_code=204` |  |
| `app/routers/lifecycle_admin.py:56` list_lifecycle_providers | `` | GET `'/api/admin/lifecycle-providers'` | `response_model=list[LifecycleProviderConfigResponse]` | 62 |
| `app/routers/lifecycle_admin.py:69` update_lifecycle_provider | `` | PUT `'/api/admin/lifecycle-providers/{provider_key}'` | `response_model=LifecycleProviderConfigResponse` | 86 |
| `app/routers/lifecycle_admin.py:93` put_lifecycle_provider_secret | `` | PUT `'/api/admin/lifecycle-providers/{provider_key}/secret'` | `response_model=LifecycleProviderSecretResponse` | 110 |
| `app/routers/lifecycle_admin.py:122` delete_lifecycle_provider_secret | `` | DELETE `'/api/admin/lifecycle-providers/{provider_key}/secret/{secret_name}'` | `status_code=status.HTTP_204_NO_CONTENT` | 137 |
| `app/routers/lifecycle_admin.py:144` test_lifecycle_provider | `` | POST `'/api/admin/lifecycle-providers/{provider_key}/test'` | `response_model=LifecycleProviderTestResponse` | 152 |
| `app/routers/lifecycle_admin.py:159` sync_lifecycle_provider | `` | POST `'/api/admin/lifecycle-providers/{provider_key}/sync'` | `response_model=LifecycleProviderSyncResponse` | 167 |
| `app/routers/lifecycle_admin.py:174` list_lifecycle_vendor_records | `` | GET `'/api/admin/lifecycle-vendor-records'` | `response_model=LifecycleVendorRecordListResponse` | 187 |
| `app/routers/lifecycle_admin.py:200` create_lifecycle_vendor_record | `` | POST `'/api/admin/lifecycle-vendor-records'` | `response_model=LifecycleVendorRecordResponse; status_code=status.HTTP_201_CREATED` | 210 |
| `app/routers/lifecycle_admin.py:217` update_lifecycle_vendor_record | `` | PUT `'/api/admin/lifecycle-vendor-records/{record_id}'` | `response_model=LifecycleVendorRecordResponse` | 228 |
| `app/routers/lifecycle_admin.py:235` delete_lifecycle_vendor_record | `` | DELETE `'/api/admin/lifecycle-vendor-records/{record_id}'` | `status_code=status.HTTP_204_NO_CONTENT` | 243 |
| `app/routers/lifecycle_admin.py:250` import_lifecycle_vendor_records | `` | POST `'/api/admin/lifecycle-vendor-records/import'` | `response_model=LifecycleVendorRecordImportResponse` | 258 |
| `app/routers/lifecycle_admin.py:262` export_lifecycle_vendor_records | `` | GET `'/api/admin/lifecycle-vendor-records/export'` | `` | 266 |
| `app/routers/logical_sboms.py:29` create_logical_sbom | `'/api'` | POST `'/products/{product_id}/logical-sboms'` | `response_model=LogicalSBOMOut; status_code=201` | 62 |
| `app/routers/logical_sboms.py:66` list_logical_sboms | `'/api'` | GET `'/products/{product_id}/logical-sboms'` | `response_model=LogicalSBOMListResponse` | 96 |
| `app/routers/logical_sboms.py:105` get_master | `'/api'` | GET `'/logical-sboms/{logical_id}'` | `response_model=LogicalSBOMOut` | 108 |
| `app/routers/logical_sboms.py:112` list_versions | `'/api'` | GET `'/logical-sboms/{logical_id}/versions'` | `response_model=list[SBOMSourceOut]` | 118 |
| `app/routers/native_auth.py:48` login | `'/api'` | POST `'/auth/native/login'` | `` | 71, 63 |
| `app/routers/native_auth.py:79` activate | `'/api'` | POST `'/auth/native/activate'` | `` | 91 |
| `app/routers/native_auth.py:119` platform_create | `'/api'` | POST `'/platform/native-users'` | `status_code=201` | 124 |
| `app/routers/native_auth.py:128` tenant_create | `'/api'` | POST `'/tenants/{tenant_id}/native-users'` | `status_code=201` | 136 |
| `app/routers/native_auth.py:140` add_existing | `'/api'` | POST `'/tenants/{tenant_id}/memberships'` | `status_code=201` | 152 |
| `app/routers/native_auth.py:156` resend | `'/api'` | POST `'/tenants/{tenant_id}/native-users/{user_id}/resend-activation'` | `` | 170 |
| `app/routers/native_auth.py:174` resend_initial_administrator | `'/api'` | POST `'/platform/tenants/{tenant_id}/native-users/{user_id}/resend-activation'` | `` | 179 |
| `app/routers/native_auth.py:225` forgot_password | `'/api'` | POST `'/auth/native/forgot-password'` | `` | 235 |
| `app/routers/native_auth.py:239` reset_password | `'/api'` | POST `'/auth/native/reset-password'` | `` | 249 |
| `app/routers/native_auth.py:253` change_password | `'/api'` | POST `'/auth/native/change-password'` | `` | 263 |
| `app/routers/native_auth.py:267` force_change_password | `'/api'` | POST `'/auth/native/force-change-password'` | `` | 275 |
| `app/routers/native_auth.py:279` native_session | `'/api'` | GET `'/auth/native/session'` | `` | 281 |
| `app/routers/native_auth.py:285` logout_all | `'/api'` | POST `'/auth/native/logout-all'` | `` | 293 |
| `app/routers/native_auth.py:297` record_logout | `'/api'` | POST `'/auth/native/logout'` | `` | 301 |
| `app/routers/pdf.py:114` create_pdf_report_by_run_id | `'/api'` | POST `'/pdf-report'` | `` | 164 |
| `app/routers/platform.py:205` platform_summary | `'/api/platform'` | GET `'/summary'` | `` | 226 |
| `app/routers/platform.py:230` tenant_admin_candidates | `'/api/platform'` | GET `'/tenant-admin-candidates'` | `response_model=TenantUserCandidateResponse` | 246 |
| `app/routers/platform.py:258` recover_tenant_admin | `'/api/platform'` | POST `'/tenants/{tenant_id}/recover-admin'` | `` | 290 |
| `app/routers/platform.py:294` search_platform_users | `'/api/platform'` | GET `'/users/search'` | `response_model=UserSearchResponse` | 386 |
| `app/routers/platform.py:390` list_platform_users | `'/api/platform'` | GET `'/users'` | `response_model=PlatformUserPage` | 465 |
| `app/routers/platform.py:478` get_platform_user | `'/api/platform'` | GET `'/users/{user_id}'` | `response_model=PlatformUserDetail` | 498 |
| `app/routers/platform.py:511` list_platform_administrators | `'/api/platform'` | GET `'/administrators'` | `response_model=PlatformAdministratorPage` | 535 |
| `app/routers/platform.py:549` grant_platform_administrator | `'/api/platform'` | POST `'/administrators'` | `status_code=201; response_model=PlatformAdministratorGrantResponse` | 593 |
| `app/routers/platform.py:600` revoke_platform_administrator | `'/api/platform'` | DELETE `'/administrators/{grant_id}'` | `status_code=204` |  |
| `app/routers/platform.py:746` update_iam_user_status | `'/api/platform'` | PATCH `'/users/{user_id}/status'` | `response_model=PlatformUserStatusResponse` | 755 |
| `app/routers/platform.py:763` update_iam_user_status_compatibility | `'/api/platform'` | PATCH `'/users/{user_id}'` | `response_model=PlatformUserStatusResponse` | 773 |
| `app/routers/platform.py:777` list_platform_tenants | `'/api/platform'` | GET `'/tenants'` | `` | 791 |
| `app/routers/platform.py:798` get_platform_tenant | `'/api/platform'` | GET `'/tenants/{tenant_id}'` | `` | 806 |
| `app/routers/platform.py:810` update_tenant_status | `'/api/platform'` | PATCH `'/tenants/{tenant_id}'` | `` | 845 |
| `app/routers/platform.py:849` edit_user_profile | `'/api/platform'` | PATCH `'/users/{user_id}/profile'` | `` | 854 |
| `app/routers/platform.py:858` user_audit | `'/api/platform'` | GET `'/users/{user_id}/audit'` | `` | 862 |
| `app/routers/platform.py:866` unlock_user | `'/api/platform'` | POST `'/users/{user_id}/unlock'` | `` | 869 |
| `app/routers/platform.py:873` force_password_change | `'/api/platform'` | POST `'/users/{user_id}/force-password-change'` | `` | 876 |
| `app/routers/platform.py:906` iam_operations | `'/api/platform'` | GET `'/iam/operations'` | `` | 908 |
| `app/routers/platform.py:912` revoke_native_sessions | `'/api/platform'` | POST `'/users/{user_id}/logout-all'` | `` | 919 |
| `app/routers/products.py:127` create_product | `'/api'` | POST `'/projects/{project_id}/products'` | `response_model=ProductRead; status_code=status.HTTP_201_CREATED` | 166 |
| `app/routers/products.py:170` list_project_products | `'/api'` | GET `'/projects/{project_id}/products'` | `response_model=ProductListResponse` | 187 |
| `app/routers/products.py:191` get_product | `'/api'` | GET `'/products/{product_id}'` | `response_model=ProductRead` | 199 |
| `app/routers/products.py:203` update_product | `'/api'` | PATCH `'/products/{product_id}'` | `response_model=ProductRead` | 308 |
| `app/routers/products.py:312` delete_product | `'/api'` | DELETE `'/products/{product_id}'` | `status_code=status.HTTP_200_OK` | 343 |
| `app/routers/products.py:347` list_product_sboms | `'/api'` | GET `'/products/{product_id}/sboms'` | `response_model=list[SBOMSourceOut]` | 372 |
| `app/routers/projects.py:76` create_project | `'/api'` | POST `'/projects'` | `response_model=ProjectOut; status_code=status.HTTP_201_CREATED` | 97 |
| `app/routers/projects.py:119` get_project_details | `'/api'` | GET `'/projects/{project_id}'` | `response_model=ProjectOut` | 129 |
| `app/routers/projects.py:137` list_projects | `'/api'` | GET `'/projects'` | `response_model=list[ProjectOut]` | 138 |
| `app/routers/projects.py:142` update_project | `'/api'` | PATCH `'/projects/{project_id}'` | `response_model=ProjectOut` | 167 |
| `app/routers/projects.py:175` project_delete_impact | `'/api'` | GET `'/projects/{project_id}/delete-impact'` | `status_code=status.HTTP_200_OK` | 215 |
| `app/routers/projects.py:227` delete_project | `'/api'` | DELETE `'/projects/{project_id}'` | `status_code=status.HTTP_200_OK` | 410, 249, 386 |
| `app/routers/projects.py:419` restore_project | `'/api'` | POST `'/projects/{project_id}/restore'` | `status_code=status.HTTP_200_OK` | 444, 433 |
| `app/routers/remediation.py:33` get_project_remediations | `'/api/remediation'` | GET `'/project/{project_id}'` | `response_model=list[VulnerabilityRemediationOut]` | 41 |
| `app/routers/remediation.py:45` get_finding_remediation | `'/api/remediation'` | GET `'/finding/{finding_id}'` | `response_model=VulnerabilityRemediationOut` | 69 |
| `app/routers/remediation.py:73` get_remediation_history | `'/api/remediation'` | GET `'/{remediation_id}/history'` | `response_model=list[VulnerabilityRemediationAuditOut]` | 94 |
| `app/routers/remediation.py:98` upsert_remediation | `'/api/remediation'` | POST `''` | `response_model=VulnerabilityRemediationOut` | 115 |
| `app/routers/report_notifications.py:91` configuration | `'/api'` | GET `'/report-notifications/config'` | `` | 93 |
| `app/routers/report_notifications.py:107` list_subscriptions | `'/api'` | GET `'/report-subscriptions'` | `` | 108 |
| `app/routers/report_notifications.py:119` targets | `'/api'` | GET `'/report-notifications/targets'` | `` | 132, 131 |
| `app/routers/report_notifications.py:144` tenant_subscriptions | `'/api'` | GET `'/tenants/{tenant_id}/report-subscriptions'` | `` | 147 |
| `app/routers/report_notifications.py:156` create_subscription | `'/api'` | POST `'/report-subscriptions'` | `status_code=201` | 179 |
| `app/routers/report_notifications.py:183` update_subscription | `'/api'` | PATCH `'/report-subscriptions/{identifier}'` | `` | 210 |
| `app/routers/report_notifications.py:214` delete_subscription | `'/api'` | DELETE `'/report-subscriptions/{identifier}'` | `status_code=204` | 220 |
| `app/routers/report_notifications.py:234` preview_unsaved | `'/api'` | POST `'/report-subscriptions/preview'` | `` | 237 |
| `app/routers/report_notifications.py:241` preview_saved | `'/api'` | POST `'/report-subscriptions/{identifier}/preview'` | `` | 242 |
| `app/routers/report_notifications.py:246` send_now | `'/api'` | POST `'/report-subscriptions/{identifier}/send-now'` | `status_code=202` | 271, 270 |
| `app/routers/report_notifications.py:275` deliveries | `'/api'` | GET `'/report-deliveries'` | `` | 340 |
| `app/routers/report_notifications.py:344` download | `'/api'` | GET `'/report-deliveries/{delivery_id}/artifacts/{artifact_id}'` | `` | 384 |
| `app/routers/reports.py:83` export_fda_510k_sbom_report | `'/api/projects'` | POST `'/{project_id}/reports/fda-510k-sbom/export'` | `` | 126 |
| `app/routers/runs.py:69` list_analysis_runs | `'/api'` | GET `'/runs'` | `response_model=list[AnalysisRunOut]` | 161 |
| `app/routers/runs.py:173` runs_aggregate_endpoint | `'/api'` | GET `'/runs/aggregate'` | `response_model=RunsAggregateOut` | 194 |
| `app/routers/runs.py:210` list_recent_runs | `'/api'` | GET `'/runs/recent'` | `response_model=list` | 232 |
| `app/routers/runs.py:252` search_runs | `'/api'` | GET `'/runs/search'` | `response_model=list` | 293 |
| `app/routers/runs.py:313` get_analysis_run | `'/api'` | GET `'/runs/{run_id}'` | `response_model=AnalysisRunOut` | 327 |
| `app/routers/runs.py:331` list_run_findings | `'/api'` | GET `'/runs/{run_id}/findings'` | `response_model=list[AnalysisFindingOut]` | 394 |
| `app/routers/runs.py:409` list_run_findings_enriched | `'/api'` | GET `'/runs/{run_id}/findings-enriched'` | `` | 570 |
| `app/routers/sbom.py:27` get_sbom_risk_summary | `` | GET `'/{sbom_id}/risk-summary'` | `status_code=200` | 60 |
| `app/routers/sbom.py:95` get_sbom_validation_report | `` | GET `'/{sbom_id}/validation-report'` | `status_code=200; response_model=ValidationReportResponse` | 177 |
| `app/routers/sbom.py:202` get_sbom_info | `` | GET `'/{sbom_id}/info'` | `status_code=200` | 255 |
| `app/routers/sbom_auto_repair.py:23` analyze | `'/api/sbom-validation-sessions'` | POST `'/{session_id}/repair/analyze'` | `` | 28 |
| `app/routers/sbom_auto_repair.py:32` repair | `'/api/sbom-validation-sessions'` | POST `'/{session_id}/repair'` | `` | 37 |
| `app/routers/sbom_auto_repair.py:41` latest | `'/api/sbom-validation-sessions'` | GET `'/{session_id}/repair'` | `` | 61 |
| `app/routers/sbom_auto_repair.py:65` get_job | `'/api/sbom-validation-sessions'` | GET `'/{session_id}/repair/{job_id}'` | `` | 72 |
| `app/routers/sbom_auto_repair.py:76` changes | `'/api/sbom-validation-sessions'` | GET `'/{session_id}/repair/{job_id}/changes'` | `` | 83 |
| `app/routers/sbom_auto_repair.py:91` download | `'/api/sbom-validation-sessions'` | GET `'/{session_id}/repair/{job_id}/download'` | `` | 100 |
| `app/routers/sbom_auto_repair.py:112` report | `'/api/sbom-validation-sessions'` | GET `'/{session_id}/repair/{job_id}/report'` | `` | 122 |
| `app/routers/sbom_auto_repair.py:136` approve | `'/api/sbom-validation-sessions'` | POST `'/{session_id}/repair/{job_id}/approve'` | `` | 149 |
| `app/routers/sbom_auto_repair.py:153` reject | `'/api/sbom-validation-sessions'` | POST `'/{session_id}/repair/{job_id}/reject'` | `` | 159 |
| `app/routers/sbom_auto_repair.py:163` session_quality | `'/api/sbom-validation-sessions'` | GET `'/{session_id}/quality'` | `` | 165 |
| `app/routers/sbom_upload.py:134` upload_sbom | `'/api/sboms'` | POST `'/upload'` | `status_code=status.HTTP_202_ACCEPTED; response_model=SbomAcceptedResponse` | 492 |
| `app/routers/sbom_validation_sessions.py:53` get_validation_session | `'/api/sbom-workspaces'` | GET `'/{session_id}'` | `` | 59 |
| `app/routers/sbom_validation_sessions.py:63` get_validation_session_content | `'/api/sbom-workspaces'` | GET `'/{session_id}/content'` | `` | 72 |
| `app/routers/sbom_validation_sessions.py:76` get_validation_session_content_chunk | `'/api/sbom-workspaces'` | GET `'/{session_id}/content/chunk'` | `` | 85 |
| `app/routers/sbom_validation_sessions.py:89` get_validation_session_content_lines | `'/api/sbom-workspaces'` | GET `'/{session_id}/content-lines'` | `` | 98 |
| `app/routers/sbom_validation_sessions.py:102` get_validation_session_content_lines_alias | `'/api/sbom-workspaces'` | GET `'/{session_id}/content/lines'` | `` | 111 |
| `app/routers/sbom_validation_sessions.py:115` download_original_validation_session | `'/api/sbom-workspaces'` | GET `'/{session_id}/download-original'` | `` | 132 |
| `app/routers/sbom_validation_sessions.py:140` download_repair_draft_validation_session | `'/api/sbom-workspaces'` | GET `'/{session_id}/download-repair-draft'` | `` | 157 |
| `app/routers/sbom_validation_sessions.py:165` search_validation_session | `'/api/sbom-workspaces'` | GET `'/{session_id}/search'` | `` | 174 |
| `app/routers/sbom_validation_sessions.py:178` update_validation_session | `'/api/sbom-workspaces'` | PATCH `'/{session_id}'` | `` | 186 |
| `app/routers/sbom_validation_sessions.py:197` save_repair_draft | `'/api/sbom-workspaces'` | PUT `'/{session_id}/repair-draft'` | `` | 226 |
| `app/routers/sbom_validation_sessions.py:231` validate_session | `'/api/sbom-workspaces'` | POST `'/{session_id}/validate'` | `` | 259 |
| `app/routers/sbom_validation_sessions.py:264` revalidate_session | `'/api/sbom-workspaces'` | POST `'/{session_id}/revalidate'` | `` | 292 |
| `app/routers/sbom_validation_sessions.py:297` import_session | `'/api/sbom-workspaces'` | POST `'/{session_id}/import'` | `response_model=SBOMSourceOut` | 333 |
| `app/routers/sbom_validation_sessions.py:337` suggest_fixes | `'/api/sbom-workspaces'` | POST `'/{session_id}/ai/suggest-fixes'` | `` | 345 |
| `app/routers/sbom_validation_sessions.py:354` apply_patch | `'/api/sbom-workspaces'` | POST `'/{session_id}/apply-patch'` | `` | 364 |
| `app/routers/sbom_validation_sessions.py:376` apply_line_patches | `'/api/sbom-workspaces'` | POST `'/{session_id}/repair/patches'` | `` | 398 |
| `app/routers/sbom_validation_sessions.py:402` session_history | `'/api/sbom-workspaces'` | GET `'/{session_id}/history'` | `` | 408 |
| `app/routers/sbom_versions.py:227` edit_sbom_endpoint | `'/api/sboms'` | POST `'/{id}/edit'` | `response_model=SBOMSourceOut` | 256 |
| `app/routers/sbom_versions.py:262` get_sbom_versions | `'/api/sboms'` | GET `'/{id}/versions'` | `response_model=list[SBOMSourceOut]` | 278, 271 |
| `app/routers/sbom_versions.py:282` compare_sbom_versions | `'/api/sboms'` | GET `'/compare-versions'` | `response_model=dict[str, Any]` | 292 |
| `app/routers/sbom_versions.py:296` restore_sbom_version | `'/api/sboms'` | POST `'/{id}/restore/{version_id}'` | `response_model=SBOMSourceOut` | 308 |
| `app/routers/sbom_versions.py:314` refresh_sbom_lifecycle | `'/api/sboms'` | POST `'/{id}/lifecycle/refresh'` | `` | 321 |
| `app/routers/sbom_versions.py:325` list_sbom_lifecycle | `'/api/sboms'` | GET `'/{id}/lifecycle'` | `` | 349 |
| `app/routers/sbom_versions.py:359` get_sbom_lifecycle_report | `'/api/sboms'` | GET `'/{id}/lifecycle/report'` | `` | 385, 373, 380 |
| `app/routers/sbom_versions.py:389` get_lifecycle_report_pack | `'/api/sboms'` | GET `'/{id}/reports/lifecycle-pack'` | `` | 406 |
| `app/routers/sbom_versions.py:490` convert_spdx_to_cyclonedx_endpoint | `'/api/sboms'` | POST `'/{id}/convert/cyclonedx'` | `response_model=SbomConversionResponse` | 519 |
| `app/routers/sbom_versions.py:535` get_conversion_report | `'/api/sboms'` | GET `'/{id}/conversion-report'` | `response_model=SbomConversionReportResponse` | 558 |
| `app/routers/sbom_versions.py:581` export_sbom_vulnerabilities_excel | `'/api/sboms'` | GET `'/{sbom_id}/reports/vulnerabilities.xlsx'` | `` | 602 |
| `app/routers/sbom_versions.py:610` export_sbom | `'/api/sboms'` | GET `'/{id}/export'` | `` | 877, 646 |
| `app/routers/sbom_versions.py:881` get_sbom_lifecycle_diagnostics | `'/api/sboms'` | GET `'/{id}/lifecycle/diagnostics'` | `` | 951 |
| `app/routers/sboms_crud.py:620` get_sbom | `'/api'` | GET `'/sboms/{sbom_id}'` | `response_model=SBOMSourceOut` | 629 |
| `app/routers/sboms_crud.py:633` create_sbom_workspace | `'/api'` | POST `'/sboms/{sbom_id}/workspace'` | `` | 643 |
| `app/routers/sboms_crud.py:647` get_sbom_document_stats | `'/api'` | GET `'/sboms/{sbom_id}/stats'` | `response_model=SbomDocumentStatsResponse` | 655 |
| `app/routers/sboms_crud.py:659` get_sbom_raw_chunk | `'/api'` | GET `'/sboms/{sbom_id}/raw'` | `response_model=SbomRawChunkResponse` | 672 |
| `app/routers/sboms_crud.py:676` download_sbom_original | `'/api'` | GET `'/sboms/{sbom_id}/download'` | `` | 697 |
| `app/routers/sboms_crud.py:706` create_sbom | `'/api'` | POST `'/sboms'` | `response_model=SBOMSourceOut; status_code=status.HTTP_201_CREATED` | 847 |
| `app/routers/sboms_crud.py:895` get_sbom_details | `'/api'` | GET `'/sboms'` | `response_model=list[SBOMSourceOut]` | 1005 |
| `app/routers/sboms_crud.py:1019` get_sbom_components | `'/api'` | GET `'/sboms/{sbom_id}/components'` | `response_model=SBOMComponentListResponse` | 1047 |
| `app/routers/sboms_crud.py:1068` reprocess_sbom_components | `'/api'` | POST `'/sboms/{sbom_id}/components/reprocess'` | `status_code=status.HTTP_200_OK` | 1164 |
| `app/routers/sboms_crud.py:1175` normalize_deduplicate_sbom | `'/api'` | POST `'/sboms/{sbom_id}/normalize-deduplicate'` | `status_code=status.HTTP_200_OK` | 1212, 1188 |
| `app/routers/sboms_crud.py:1221` get_sbom_dedupe_report | `'/api'` | GET `'/sboms/{sbom_id}/dedupe-report'` | `` | 1240 |
| `app/routers/sboms_crud.py:1248` get_sbom_normalization_report | `'/api'` | GET `'/sboms/{sbom_id}/normalization-report'` | `` | 1253 |
| `app/routers/sboms_crud.py:1257` update_sbom | `'/api'` | PATCH `'/sboms/{sbom_id}'` | `response_model=SBOMSourceOut` | 1403 |
| `app/routers/sboms_crud.py:1420` sbom_delete_impact | `'/api'` | GET `'/sboms/{sbom_id}/delete-impact'` | `status_code=status.HTTP_200_OK` | 1427 |
| `app/routers/sboms_crud.py:1434` delete_sbom | `'/api'` | DELETE `'/sboms/{sbom_id}'` | `status_code=status.HTTP_200_OK` | 1459, 1463, 1492, 1475 |
| `app/routers/sboms_crud.py:1507` change_sbom_lifecycle | `'/api'` | POST `'/sboms/{sbom_id}/lifecycle'` | `response_model=SBOMSourceOut` | 1515 |
| `app/routers/sboms_crud.py:1519` get_sbom_lifecycle_history | `'/api'` | GET `'/sboms/{sbom_id}/lifecycle-history'` | `` | 1524 |
| `app/routers/sboms_crud.py:1529` restore_sbom | `'/api'` | POST `'/sboms/{sbom_id}/restore'` | `status_code=status.HTTP_200_OK` | 1555, 1544 |
| `app/routers/sboms_crud.py:1560` revalidate_sbom | `'/api'` | POST `'/sboms/{sbom_id}/revalidate'` | `response_model=SBOMSourceOut` | 1622 |
| `app/routers/sboms_crud.py:1627` run_analysis_for_sbom | `'/api'` | POST `'/sboms/{sbom_id}/analyze'` | `response_model=AnalysisRunOut; status_code=status.HTTP_201_CREATED` | 1688, 1681, 1667 |
| `app/routers/sboms_crud.py:1693` analyze_sbom_stream | `'/api'` | POST `'/sboms/{sbom_id}/analyze/stream'` | `` | 2082, 1722, 1756, 1773, 1804, 1819, 1858, 1808, 1814, 1912, 2080, 1896 |
| `app/routers/sboms_crud.py:2094` list_sbom_analysis_runs | `'/api'` | GET `'/sboms/{sbom_id}/analysis-runs'` | `response_model=list[AnalysisRunOut]` | 2105 |
| `app/routers/sboms_crud.py:2119` sbom_quality | `'/api'` | GET `'/sboms/{sbom_id}/quality'` | `` | 2121 |
| `app/routers/schedules.py:71` get_tenant_schedule | `'/api'` | GET `'/tenants/{tenant_id}/schedule'` | `response_model=ScheduleOut \| None` | 73 |
| `app/routers/schedules.py:78` upsert_tenant_schedule | `'/api'` | POST `'/tenants/{tenant_id}/schedule'` | `response_model=ScheduleOut` | 91 |
| `app/routers/schedules.py:78` upsert_tenant_schedule | `'/api'` | PATCH `'/tenants/{tenant_id}/schedule'` | `response_model=ScheduleOut` | 91 |
| `app/routers/schedules.py:95` delete_tenant_schedule | `'/api'` | DELETE `'/tenants/{tenant_id}/schedule'` | `status_code=204` | 103 |
| `app/routers/schedules.py:339` upsert_project_schedule | `'/api'` | POST `'/projects/{project_id}/schedule'` | `response_model=ScheduleOut; status_code=status.HTTP_201_CREATED` | 377 |
| `app/routers/schedules.py:381` get_project_schedule | `'/api'` | GET `'/projects/{project_id}/schedule'` | `response_model=ScheduleOut` | 396 |
| `app/routers/schedules.py:400` patch_project_schedule | `'/api'` | PATCH `'/projects/{project_id}/schedule'` | `response_model=ScheduleOut` | 426 |
| `app/routers/schedules.py:430` delete_project_schedule | `'/api'` | DELETE `'/projects/{project_id}/schedule'` | `status_code=status.HTTP_200_OK` | 468, 453 |
| `app/routers/schedules.py:481` upsert_product_schedule | `'/api'` | POST `'/products/{product_id}/schedule'` | `response_model=ScheduleOut; status_code=status.HTTP_201_CREATED` | 516 |
| `app/routers/schedules.py:520` get_product_schedule | `'/api'` | GET `'/products/{product_id}/schedule'` | `response_model=ScheduleOut` | 535 |
| `app/routers/schedules.py:539` get_effective_product_schedule | `'/api'` | GET `'/products/{product_id}/schedule/effective'` | `response_model=ScheduleResolved` | 548, 547 |
| `app/routers/schedules.py:559` exclude_product_from_parent_schedule | `'/api'` | POST `'/products/{product_id}/schedule/exclude'` | `response_model=ScheduleOut` | 565 |
| `app/routers/schedules.py:569` restore_product_schedule_inheritance | `'/api'` | POST `'/products/{product_id}/schedule/inherit'` | `` | 582 |
| `app/routers/schedules.py:586` patch_product_schedule | `'/api'` | PATCH `'/products/{product_id}/schedule'` | `response_model=ScheduleOut` | 610 |
| `app/routers/schedules.py:614` delete_product_schedule | `'/api'` | DELETE `'/products/{product_id}/schedule'` | `status_code=status.HTTP_200_OK` | 644, 630 |
| `app/routers/schedules.py:657` upsert_sbom_schedule | `'/api'` | POST `'/sboms/{sbom_id}/schedule'` | `response_model=ScheduleOut; status_code=status.HTTP_201_CREATED` | 695 |
| `app/routers/schedules.py:699` get_sbom_schedule | `'/api'` | GET `'/sboms/{sbom_id}/schedule'` | `response_model=ScheduleResolved` | 721, 713 |
| `app/routers/schedules.py:732` exclude_sbom_from_parent_schedule | `'/api'` | POST `'/sboms/{sbom_id}/schedule/exclude'` | `response_model=ScheduleOut` | 738 |
| `app/routers/schedules.py:742` restore_sbom_schedule_inheritance | `'/api'` | POST `'/sboms/{sbom_id}/schedule/inherit'` | `` | 755 |
| `app/routers/schedules.py:759` patch_sbom_schedule | `'/api'` | PATCH `'/sboms/{sbom_id}/schedule'` | `response_model=ScheduleOut` | 788 |
| `app/routers/schedules.py:792` delete_sbom_schedule | `'/api'` | DELETE `'/sboms/{sbom_id}/schedule'` | `status_code=status.HTTP_200_OK` | 823, 808 |
| `app/routers/schedules.py:832` list_schedules | `'/api'` | GET `'/schedules'` | `response_model=list[ScheduleOut]` | 861 |
| `app/routers/schedules.py:880` preview_schedule_targets | `'/api'` | GET `'/schedules/{schedule_id}/targets'` | `response_model=ScheduleTargetPreview` | 891 |
| `app/routers/schedules.py:901` pause_schedule | `'/api'` | POST `'/schedules/{schedule_id}/pause'` | `response_model=ScheduleOut` | 915 |
| `app/routers/schedules.py:919` resume_schedule | `'/api'` | POST `'/schedules/{schedule_id}/resume'` | `response_model=ScheduleOut` | 938 |
| `app/routers/schedules.py:942` run_schedule_now | `'/api'` | POST `'/schedules/{schedule_id}/run-now'` | `status_code=status.HTTP_202_ACCEPTED` | 1021 |
| `app/routers/tenants.py:226` auth_me | `'/api'` | GET `'/auth/me'` | `` | 291 |
| `app/routers/tenants.py:226` auth_me | `'/api'` | GET `'/v1/auth/me'` | `` | 291 |
| `app/routers/tenants.py:295` auth_context | `'/api'` | GET `'/auth/context'` | `response_model=AuthContextResponse` | 317 |
| `app/routers/tenants.py:321` list_my_tenants | `'/api'` | GET `'/tenants'` | `` | 347 |
| `app/routers/tenants.py:351` create_tenant | `'/api'` | POST `'/tenants'` | `status_code=201; response_model=TenantCreationResponse` | 411 |
| `app/routers/tenants.py:434` list_assignable_tenant_roles | `'/api'` | GET `'/tenant-roles'` | `` | 443 |
| `app/routers/tenants.py:453` list_tenant_user_roles | `'/api'` | GET `'/tenants/{tenant_id}/users/{user_id}/roles'` | `` | 461 |
| `app/routers/tenants.py:467` grant_tenant_user_role | `'/api'` | POST `'/tenants/{tenant_id}/users/{user_id}/roles'` | `` | 501 |
| `app/routers/tenants.py:505` replace_tenant_user_roles | `'/api'` | PUT `'/tenants/{tenant_id}/users/{user_id}/roles'` | `` | 539 |
| `app/routers/tenants.py:543` revoke_tenant_user_role | `'/api'` | DELETE `'/tenants/{tenant_id}/users/{user_id}/roles/{role_code}'` | `` | 578 |
| `app/routers/tenants.py:582` tenant_user_role_history | `'/api'` | GET `'/tenants/{tenant_id}/users/{user_id}/roles/history'` | `` | 609 |
| `app/routers/tenants.py:638` search_tenant_user_candidates | `'/api'` | GET `'/tenants/{tenant_id}/user-candidates'` | `response_model=TenantUserCandidateResponse` | 703 |
| `app/routers/tenants.py:708` list_tenant_users | `'/api'` | GET `'/tenants/{tenant_id}/users'` | `` | 722, 720 |
| `app/routers/tenants.py:729` tenant_audit_history | `'/api'` | GET `'/tenants/{tenant_id}/audit-history'` | `` | 749 |
| `app/routers/tenants.py:755` get_tenant_user | `'/api'` | GET `'/tenants/{tenant_id}/users/{membership_id}'` | `` | 763 |
| `app/routers/tenants.py:769` add_tenant_user | `'/api'` | POST `'/tenants/{tenant_id}/users'` | `status_code=201` | 875 |
| `app/routers/tenants.py:883` update_tenant_user | `'/api'` | PATCH `'/tenants/{tenant_id}/users/{membership_id}'` | `` | 996 |
| `app/routers/tenants.py:1086` activate_tenant_user | `'/api'` | POST `'/tenants/{tenant_id}/users/{membership_id}/activate'` | `` | 1093 |
| `app/routers/tenants.py:1097` deactivate_tenant_user | `'/api'` | POST `'/tenants/{tenant_id}/users/{membership_id}/deactivate'` | `` | 1104 |
| `app/routers/tenants.py:1108` delete_tenant_user | `'/api'` | DELETE `'/tenants/{tenant_id}/users/{membership_id}'` | `status_code=204` |  |
| `app/routers/tenants.py:1163` edit_tenant_profile | `'/api'` | PATCH `'/tenants/{tenant_id}/users/{membership_id}/profile'` | `` | 1171 |
| `app/routers/tenants.py:1175` tenant_user_audit | `'/api'` | GET `'/tenants/{tenant_id}/users/{membership_id}/audit'` | `` | 1181 |
| `app/routers/verification.py:45` verification_status | `'/api/auth/verification'` | GET `'/status'` | `` | 54 |
| `app/routers/verification.py:61` resend_verification | `'/api/auth/verification'` | POST `'/resend'` | `` | 98, 70 |
| `app/routers/verification.py:117` confirm_verification | `'/api/auth/verification'` | POST `'/confirm'` | `` | 132 |
| `app/routers/vex.py:42` upload_vex_document | `` | POST `'/api/sboms/{sbom_id}/vex'` | `` | 51 |
| `app/routers/vex.py:64` get_vex_statements | `` | GET `'/api/sboms/{sbom_id}/vex'` | `` | 71 |
| `app/routers/vex.py:76` get_vex_report | `` | GET `'/api/sboms/{sbom_id}/vex/report'` | `` | 101, 96 |
| `app/routers/vex.py:106` get_vex_report_pack | `` | GET `'/api/sboms/{sbom_id}/reports/vex-pack'` | `` | 123 |
| `app/routers/vex.py:132` discover_vex_documents | `` | POST `'/api/sboms/{sbom_id}/vex/discover'` | `` | 141 |
| `app/routers/vex.py:145` get_component_vulnerabilities | `` | GET `'/api/sboms/{sbom_id}/components/{component_id}/vulnerabilities'` | `` | 151 |
| `app/routers/vex.py:158` patch_vex_override | `` | PATCH `'/api/sboms/{sbom_id}/components/{component_id}/vulnerabilities/{vulnerability_id}/vex-override'` | `` | 193 |
| `app/routers/vex.py:158` patch_vex_override | `` | PATCH `'/api/components/{component_id}/vulnerabilities/{vulnerability_id}/vex-override'` | `` | 193 |
| `app/routers/vex.py:212` get_vex_override_history | `` | GET `'/api/sboms/{sbom_id}/components/{component_id}/vulnerabilities/{vulnerability_id}/vex-override/history'` | `` | 231 |
| `app/routers/vex.py:212` get_vex_override_history | `` | GET `'/api/components/{component_id}/vulnerabilities/{vulnerability_id}/vex-override/history'` | `` | 231 |
| `app/routers/vex_investigations.py:422` list_investigations | `` | GET `'/api/vex/investigations'` | `response_model=InvestigationListResponse` | 514 |
| `app/routers/vex_investigations.py:519` investigation_summary | `` | GET `'/api/vex/investigations/summary'` | `response_model=InvestigationSummaryResponse` | 540 |
| `app/routers/vex_investigations.py:555` investigation_versions | `` | GET `'/api/vex/investigations/versions'` | `` | 565 |
| `app/routers/vex_investigations.py:570` investigation_analysis_runs | `` | GET `'/api/vex/investigations/analysis-runs'` | `` | 576 |
| `app/routers/vex_investigations.py:580` investigation_run_snapshot | `` | GET `'/api/vex/investigations/run-snapshot'` | `` | 590 |
| `app/routers/vex_investigations.py:594` investigation_comparison | `` | GET `'/api/vex/investigations/comparison'` | `` | 624 |
| `app/routers/vex_investigations.py:629` investigation_assignees | `` | GET `'/api/vex/investigations/assignees'` | `` | 643 |
| `app/routers/vex_investigations.py:651` resolve_investigation | `` | GET `'/api/vex/investigations/resolve'` | `response_model=InvestigationDetail` | 704 |
| `app/routers/vex_investigations.py:708` get_investigation | `` | GET `'/api/vex/investigations/{investigation_id}'` | `response_model=InvestigationDetail` | 716 |
| `app/routers/vex_investigations.py:882` set_investigation_decision | `` | PUT `'/api/vex/investigations/{investigation_id}/decision'` | `response_model=InvestigationDetail` | 972, 914 |
| `app/routers/vex_investigations.py:979` set_investigation_assignment | `` | PUT `'/api/vex/investigations/{investigation_id}/assignment'` | `response_model=InvestigationDetail` | 1010, 993 |
| `app/routers/vex_investigations.py:1017` resolve_investigation_mapping | `` | PUT `'/api/vex/investigations/{investigation_id}/component'` | `response_model=InvestigationDetail` | 1077, 1044 |
| `app/routers/vulnerabilities.py:32` list_vulnerabilities | `'/api'` | GET `'/vulnerabilities'` | `` | 62 |

### Appendix F — API adapter definition locations

All exported API adapters are included so bare hook function references can be traced. The source file and line are authoritative for request method/path/body and response type.

| Adapter module | Exported definition locations |
|---|---|
| `frontend/src/lib/advisorPolicyApi.ts` | getAdvisorPolicy:17; getAdvisorPolicyHistory:18; publishAdvisorPolicy:19 |
| `frontend/src/lib/api.ts` | BASE_URL:98; request:400; requestVoid:431; getTenantMembers:453; getAssignableTenantRoles:461; addTenantMember:470; getTenantAuditHistory:514; getTenantAuditPage:528; getPlatformSummary:537; searchPlatformTenantAdminCandidates:541; recoverPlatformTenantAdmin:547; replaceTenantMemberRoles:551; updateTenantMemberRole:570; activateTenantMember:583; deactivateTenantMember:590; removeTenantMember:597; searchPlatformUsers:604; searchTenantUserCandidates:615; getPlatformAdministrators:624; grantPlatformAdministrator:629; revokePlatformAdministrator:637; listPlatformTenants:644; getPlatformTenant:650; resendPlatformTenantActivation:655; createPlatformTenant:662; updatePlatformTenantStatus:671; getAnalysisConfig:728; getHealth:739; dashboardScopeParams:750; getDashboardProjectOptions:765; getDashboardScannedProjectIds:769; getDashboardApplicationOptions:773; getDashboardSbomOptions:777; getDashboardRuns:781; getDashboardStats:789; getRecentSboms:793; getDashboardActivity:797; getDashboardSeverity:801; getDashboardPosture:811; getDashboardSummary:815; getProjects:820; getProject:824; createProject:828; getProducts:836; getProduct:840; createProduct:844; updateProduct:852; deleteProduct:860; getProductSboms:867; updateProject:871; getProjectDeleteImpact:893; deleteProject:897; getSboms:912; changeSbomLifecycle:917; getSbomLifecycleHistory:921; getSbom:925; getSbomStats:930; getSbomRawChunk:934; downloadSbomOriginal:946; createSbom:951; uploadSbom:959; updateSbom:1013; editSbom:1025; createWorkspaceForSbom:1034; getSbomVersions:1041; compareSbomVersions:1045; restoreSbomVersion:1053; getSbomDeleteImpact:1102; deleteSbom:1106; getSbomComponents:1123; getSbomDedupeReport:1151; getSbomNormalizationReport:1155; normalizeDeduplicateSbom:1159; refreshSbomLifecycle:1166; getLifecycleProviderStatus:1177; getLifecycleSources:1181; getSbomLifecycleReport:1185; exportSbomLifecycleReportCsv:1189; exportSbomLifecycleReportPack:1199; refreshComponentLifecycle:1203; overrideComponentLifecycle:1214; analyzeSbom:1230; analyzeConsolidated:1238; getRuns:1281; getRunsAggregate:1302; getVulnerabilities:1356; getRun:1368; getRunFindings:1372; getEnrichedRunFindings:1396; getAllEnrichedRunFindings:1412; getAllRunFindings:1451; exportRunsJson:1497; downloadPdfReport:1550; getSbomTypes:1567; getSbomInfo:1572; getSbomRiskSummary:1576; getSbomValidationReport:1580; convertSbomToCycloneDX:1584; getSbomConversionReport:1592; exportSbomDocument:1596; exportSbomVulnerabilityExcel:1609; exportFda510kSbomReport:1617; revalidateSbom:1641; getValidationSession:1648; getValidationSessionContent:1652; getValidationSessionContentLines:1666; searchValidationSession:1680; downloadValidationSessionOriginal:1694; downloadValidationSessionRepairDraft:1702; saveValidationSessionRepairDraft:1710; updateValidationSession:1723; validateValidationSession:1738; importValidationSession:1745; suggestValidationSessionFixes:1753; applyValidationSessionPatch:1769; applyValidationSessionLinePatches:1781; getValidationSessionHistory:1793; getValidationRepairSession:1797; getValidationRepairContent:1798; saveValidationRepairDraft:1799; updateValidationRepairSession:1800; validateRepairSession:1801; importRepairSession:1802; suggestValidationRepairFixes:1803; applyValidationRepairPatch:1810; getValidationRepairHistory:1817; getDashboardTrend:1820; getDashboardTrendFiltered:1829; getVulnerabilityAge:1843; getDashboardLifetime:1865; getDashboardForecast:1881; getDashboardExploitation:1886; getDashboardRemediation:1891; getDashboardLifecycle:1895; getDashboardVex:1899; getDashboardHealth:1903; getDashboardRemediationStats:1911; getComponentVulnerabilities:1923; getSbomVexStatements:1928; discoverSbomVexDocuments:1932; uploadSbomVexDocument:1943; overrideVexStatement:1960; getVexOverrideHistory:1977; exportSbomVexReportJson:1984; exportSbomVexReportCsv:1990; exportSbomVexReportPack:2000; getDashboardRiskMap:2005; getDashboardRiskMatrix:2010; getCopilotBriefing:2023; askCopilot:2032; compareRuns:2041; compareRunsV2:2059; recentRuns:2067; searchRuns:2071; exportCompare:2077; downloadReportArtifact:2119; exportRunCsv:2123; exportRunSarif:2127; analyzeSbomNvd:2132; analyzeSbomGithub:2140; analyzeSbomOsv:2148; getProjectSchedule:2167; getProductSchedule:2171; getEffectiveProductSchedule:2175; upsertProductSchedule:2179; patchProductSchedule:2189; deleteProductSchedule:2199; upsertProjectSchedule:2208; patchProjectSchedule:2220; deleteProjectSchedule:2232; getSbomSchedule:2244; upsertSbomSchedule:2248; patchSbomSchedule:2260; deleteSbomSchedule:2272; getTenantSchedule:2290; upsertScopedSchedule:2294; deleteScopedSchedule:2298; excludeFromParentSchedule:2302; restoreScheduleInheritance:2308; previewScheduleTargets:2315; listSchedules:2319; pauseSchedule:2328; resumeSchedule:2335; runScheduleNow:2352; getFindingAiFix:2391; generateFindingAiFix:2413; regenerateFindingAiFix:2428; triggerRunAiFixes:2443; cancelRunAiFixes:2457; getRunAiFixProgress:2473; listRunAiFixes:2483; aiFixStreamUrl:2495; aiFixBatchStreamUrl:2501; listRunAiBatches:2506; getRunAiBatch:2514; cancelRunAiBatch:2523; estimateRunAiFixesScoped:2539; listAiProviders:2553; listAiPricing:2557; getAiUsageSummary:2561; getAiUsageTrend:2566; getAiTopCachedFixes:2575; aiConfigurationBase:2587; lifecycleConfigurationBase:2588; getEffectiveAiConfiguration:2593; createTenantAiOverride:2596; resetTenantAiOverride:2597; resetLifecycleProviderOverride:2598; listAiCredentials:2602; getAiCredential:2606; createAiCredential:2610; updateAiCredential:2622; deleteAiCredential:2635; setAiCredentialDefault:2639; setAiCredentialFallback:2649; testAiCredentialUnsaved:2660; testAiCredentialSaved:2673; listAiProviderModels:2683; refreshAiProviderModels:2687; selectAiProviderModel:2694; testAiProviderModel:2701; getAiCredentialSettings:2708; updateAiCredentialSettings:2712; listAiProviderCatalog:2725; getAiProviderCatalogEntry:2729; getRunBatchEstimate:2740; getCveDetail:2760; listKevVulnerabilities:2773; getKevFilterOptions:2801; getKevVulnerability:2814; syncKevCatalog:2824; upsertRemediation:2832; listLifecycleProviders:2842; updateLifecycleProvider:2846; setLifecycleProviderSecret:2858; deleteLifecycleProviderSecret:2873; testLifecycleProvider:2884; syncLifecycleProvider:2895; listLifecycleVendorRecords:2906; createLifecycleVendorRecord:2923; updateLifecycleVendorRecord:2934; deleteLifecycleVendorRecord:2946; importLifecycleVendorRecords:2950; exportLifecycleVendorRecords:2961; listVexInvestigations:2995; getVexInvestigationSummary:3008; getVexInvestigation:3017; searchVexAssignees:3024; setVexInvestigationDecision:3039; setVexInvestigationAssignment:3050; resolveVexInvestigationComponent:3066; getVexInvestigationByTriple:3084; advisorParams:3124; getAdvisorSummary:3145; listAdvisorComponents:3149; getAdvisorComponent:3153; searchAdvisor:3163; createAdvisorRecommendation:3167; getAdvisorRecommendation:3177; evaluateAdvisorRecommendation:3181; decideAdvisorRecommendation:3185; getAdvisorCandidateEvidence:3195; getAdvisorCandidateCompatibility:3199; analyzeSbomRepair:3204; getLatestSbomRepair:3207; runSbomRepair:3210; decideSbomRepair:3213; downloadSbomRepair:3216; getSessionQuality:3220; getSbomQuality:3223; getLogicalSboms:3227; getLogicalSbomChoices:3230; getLogicalSbom:3240; getLogicalSbomVersions:3243; createLogicalSbom:3246; getDashboardPostureVersions:3251; getVexInvestigationVersions:3254; getVexVersionComparison:3257; getDashboardPriorityFindings:3274; getVexAnalysisRuns:3280; getVexRunSnapshot:3285 |
| `frontend/src/lib/reportApi.ts` | getReportConfig:4; getReportTargets:5; getReportSubscriptions:6; getReportDeliveries:7; createReportSubscription:8; updateReportSubscription:9; deleteReportSubscription:10; previewReport:11; sendReportNow:12 |

## Batch 3 implementation — project, SBOM and inventory synchronization

Implemented on 2026-10-09 on `feat/native-user-management`, HEAD `6e7b22e1110ef1849150671b8d253efe0479e074`. Scope is **UI-SYNC-06, 07, 08, 09 and 16 only**. Original audit and Batch 1/2 sections are preserved above. No commit or push was performed.

### Shared helpers and mutation dependencies

| Mutation / finding | Synchronization implemented |
|---|---|
| Project create/edit/status — UI-SYNC-07 | New awaitable `invalidateProjectMetadata` uses the returned project ID/status. Refreshes project lists, affected `project`/`project-detail`, project product inventory, cached SBOM details belonging to the project, SBOM list/name projections, report targets, home summary and operational labels. Creation/status changes also refresh dashboard metric families. A name-only edit leaves raw findings/run lists and unrelated security counters untouched; no vulnerability recalculation or analysis starts. |
| Inventory report options — UI-SYNC-16 | New awaitable `invalidateReportTargetChoices` targets the actual `['reports','targets']` prefix. Project/SBOM list helpers and product/upload/lifecycle helpers include it, covering create/update/deletion/archiving and scoped/search variants. Target refresh does not reset editor scope/search/selection. Immutable delivery artifacts are not invalidated. Verified unused `report-subscriptions` and `report-notifications-targets` invalidation prefixes were removed from lifecycle handling; existing subscription mutation helpers remain unchanged. |
| SBOM name/version/metadata and assignment — UI-SYNC-06 | Extended awaitable `invalidateProjectAssignmentSurfaces` refreshes `sbom`/info/version detail, inventory/logical SBOM lists and versions, dashboard options, posture/operational projections, report targets, and the exact old/new project and product detail/list caches. SBOM edit and assignment handlers use the successful PATCH response for new ownership instead of assuming form selection matches final backend ownership. Ownership changes refresh security aggregates; same-owner metadata does not invalidate raw analysis or snapshots. No client writes modify historical records. |
| SBOM restore — UI-SYNC-08 | New awaitable `invalidateSbomRevisionCreated` treats the restore response as a new SBOM revision. Refreshes original history/detail, new revision detail/history/components, main/logical/product inventory, upload choices and dashboard/report targets. Uses returned project/product ownership; only omitted fields fall back to known parent context, while explicit null remains null. Existing navigation to the returned revision ID and restoration error handling remain. No optimistic revision is inserted before backend success; historical run snapshots remain fresh. |
| Component lifecycle override/refresh — UI-SYNC-09 | Awaitable `invalidateLifecycleOverrideSurfaces` includes both `['sbom-components', sbomId, ...]` and `['sbom-components-canonical', sbomId]`, plus lifecycle/health/home aggregate dependencies. Successful whole-SBOM and component refresh handlers await this helper; manual override retains existing immediate modal closure and async refresh behavior. Other SBOM component caches stay fresh, pagination/search state stays local, and no reanalysis is triggered. General SBOM surface invalidation also includes its canonical cache. |
| Upload composition | Product/upload/dashboard-summary helpers now use the established same-turn invalidation queue and return awaitable promises. Upload hook and modal pass returned product ownership and avoid the redundant second product helper call. Existing unknown-owner compatibility remains. This prevents repeated target/product/logical list refetches from nested upload helpers. |

The PATCH endpoint (`app/routers/sboms_crud.py::update_sbom`) commits and returns the updated SBOM. Restore (`app/routers/sbom_versions.py::restore_sbom_version` → `app/services/version_control_service.py::restore_version`) creates and commits a new revision, copies parent project/product/logical ownership and returns the new SBOM. Component refresh endpoints return completed enrichment results; the service commits before returning. Client changes do not reinterpret a queued operation as completed and do not change any backend business rules.

### Files changed

- `frontend/src/lib/queryInvalidation.ts`
- `frontend/src/components/projects/ProjectModal.tsx`
- `frontend/src/components/sboms/SbomDetail.tsx`
- `frontend/src/components/sboms/SbomUploadModal.tsx`
- `frontend/src/hooks/useSbomMutations.ts`
- `frontend/src/components/sboms/SbomDetail.lifecycle.test.tsx`
- `frontend/src/lib/inventory-invalidation.test.ts` (new)
- `frontend/src/components/sboms/inventory-sync.integration.test.tsx` (new)
- This report.

### Regression evidence

Real QueryClients use five-minute staleTime and no focus refetch for new cache tests. Coverage includes active refetches, inactive filter/search variants, disabled observers, exact fetch counts, old/new owners, unrelated detail preservation, immutable run and delivery preservation, server-derived row removal/addition and lifecycle values, project create/edit/status/failure, report editor reopening and retained scope/search/selection, restore parent fallback/null semantics and actual navigation, metadata response ownership differing from the form, and failed SBOM/restore/lifecycle mutations.

Actual project forms and report editor are rendered. SBOM mutation integration harnesses exercise API adapters and shared response/helper contracts; additional tests in the actual SbomDetail lifecycle suite verify restore navigation and authoritative metadata response ownership.

| Gate | Result |
|---|---|
| 3A focused project/report/helper suites | **16 passed, 3 files**, 0 failures |
| 3B metadata/ownership and existing SBOM suites | **38 passed, 3 files**, 0 failures |
| 3C revision/history and existing SBOM suites | **40 passed, 3 files**, 0 failures |
| 3D component lifecycle and existing SBOM suites | **42 passed, 3 files**, 0 failures |
| New UI/cache integration check | **24 passed, 2 files**, 0 failures before final additional active-report test |
| Expanded focus: SBOM lifecycle, new cache suites, upload repair and Batch 2 invalidation | **73 passed, 5 files**, 0 failures before final additional active-report test |
| Final combined Batch 1/2/3 regression set | **283 passed, 23 files**, 0 failures |
| TypeScript (`npm exec -- tsc --noEmit --incremental false`) | **Exit 0, no diagnostics** |
| ESLint (`npm run lint`) | **Exit 0; 0 errors, 53 unchanged baseline warnings** |
| `git -c core.fsmonitor=false diff --check` | **Passed** |

Commands run through existing npm/Vitest scripts using the bundled Node runtime; focused checks use `--maxWorkers=1 --testTimeout=15000`. An initial new test fixture used `status` rather than schema-required `lifecycle_status`; it was corrected. Two added actual-SBOM tests initially exposed missing project/product/PATCH API mocks and a required-field label selector mismatch; deterministic mocks and a matching label selector corrected the tests without changing production behavior. These were introduced test-harness failures, not asserted as unrelated baseline failures.

### Preservation and limitations

Global five-minute caching, authentication/logout/tenant switching, backend semantics, notifications, form validation and permissions remain unchanged. No dependencies, event bus, polling, SSE, WebSockets, reload or router.refresh were added. Checks include Batch 1/2 and auth-isolation regressions. No live-browser/backend/provider acceptance validation or production build is claimed. Browser acceptance should cover live project rename/status, SBOM moves including server-selected default products, restore navigation/version choices and lifecycle provider evidence. Remaining UI-SYNC-10 through 15 and 17 are deferred. SHA-256 comparison against the pre-batch source snapshot found only the expected files changed. Removing this appended section reproduces the original report hash, confirming the original audit and Batch 1/2 documentation are preserved byte-for-byte. No backend source was modified.

## Batch 4 implementation — schedule and background analysis synchronization

Implemented on 2026-10-09 on `feat/native-user-management`, HEAD `6e7b22e1110ef1849150671b8d253efe0479e074`. Scope: **UI-SYNC-10, UI-SYNC-12 and UI-SYNC-13 only**. Batch 1–3 and the original audit are preserved. No commit, push, deployment or backend business-rule changes were performed.

### Mutation and terminal-state dependencies

| Event | Behavior / shared helpers |
|---|---|
| Schedule create/edit/pause/resume/delete/exclude/restore inheritance — UI-SYNC-10 | `invalidateScheduleLists` now returns an awaitable promise covering `schedules`, `schedule` and `schedule-targets` prefixes across tenant/project/product/SBOM scope variants. Card/page mutations and editor saves use it; existing same-turn invalidation deduplication avoids overlapping refreshes. Filters and forms are not reset by invalidation. Existing confirmation, validation and error handling are preserved. |
| Run Now enqueue | New `invalidateAnalysisSubmission` refreshes schedule state, run lists/aggregates, SBOM badges and dashboard projections via existing helpers. It does not invalidate completed findings or label submission as completion. Returned SBOM IDs receive scoped recovery markers only after backend success. Captured context prevents a late acknowledgement from installing tracking in another auth context. |
| Authoritative terminal run — UI-SYNC-12 | `reconcileAnalysisTerminal` uses server run ID/status and a current-context guard. A QueryClient-owned `analysis-terminal-sync` marker deduplicates the same run/status across polling, local requests and existing streams; clearing auth cache clears this bookkeeping too. Successful/partial/failed/interrupted/canceled/no-data results share dependency refresh, not success-toast semantics. |
| Analysis result refresh | Awaitable `invalidateAnalysisCompletion` accepts an optional run ID. Known run IDs refresh that run detail and all its `findings` / `findings-enriched` filter variants, plus run lists/aggregates, applicable SBOM detail/info/stats/risk/resolver, product posture and dashboard projections. Unrelated run findings and immutable VEX run snapshots remain untouched when the run ID is known. Legacy callers without an ID retain their existing broad findings compatibility. |
| Run detail polling | `useAnalysisTerminal` observes authoritative run data from the existing three-second poll, including first mounts with terminal data. Polling stops when the known status is terminal. Repeated identical terminal data does not cause another reconciliation. Refetch errors retain existing error handling; no analysis is restarted. |
| Scoped/unfiltered SBOM lists — UI-SYNC-13 | `useSbomsList` now supports existing scope/filter key contracts and provides the same conditional polling policy to the SBOM page's filtered and unfiltered queries. It polls only known active statuses/results and reconciles active-to-terminal rows. Scoped project/product/SBOM and analysed filters remain in the query key and API request. Existing local focus behavior is retained; no global focus policy changed. |
| Direct background analysis | Immediate running indicators are applied to matching rows across existing `sboms` cache variants. Prior finding/risk values are retained during submission. Active acknowledgements preserve tracking; authoritative terminal results use the shared reconciler. A transport error refreshes submission state and leaves a recent recovery marker, rather than inventing a failed server run or zero findings. |
| Existing analysis stream | Existing transport remains. Complete events use their authoritative status/run ID; error events with a known ID read the run before terminal reconciliation. Context guards suppress old event/state writes after switching/logout/unmount. Stream cancellation remains a client transport abort; it is not asserted to be a server cancellation. |

### Actual status contracts

The analysis service defines `OK`, `FINDINGS`, `PARTIAL`, `ERROR`, `RUNNING`, `PENDING`, `INTERRUPTED` and `NO_DATA`; active compatibility codes include `QUEUED`, `ANALYSING` and `ANALYZING`. `CANCELLED` is recognized by the existing orchestrator and frontend analysis-status contract. Existing `canonicalRunStatus` maps legacy PASS→OK and FAIL→FINDINGS. No new backend enum values or cancellation API were invented. PARTIAL remains incomplete coverage; ERROR/CANCELLED/INTERRUPTED are not reported as successful analysis.

### Recovery and polling lifetime

- The previous recovery hook had no production consumer. It is now mounted by the shared SBOM-list hook.
- Markers contain scope (tenant/principal), SBOM identity, submission time, last verified check time and optional authoritative run ID. The recovery query only runs for the ready authorized current context with pending markers.
- One conditional recovery query polls every three seconds while tracked work is active or a recent result is unresolved. It batches the existing per-SBOM run requests under one query; there is no timer per SBOM. The API has no batch run-status endpoint, so each tracked SBOM still requires its own filtered run request.
- A known run ID must match. Until an ID is known, a run's server start time must match the pending submission window; an older successful run cannot clear a newly submitted job's marker.
- Server-confirmed active work renews tracking, even for a long-running job. Terminal reconciliation removes the completed marker. Missing runs/network errors retain recent markers for retry; unresolved markers expire after the existing three-minute grace period. Legacy unscoped or malformed markers are discarded because ownership cannot safely be inferred. Server job data remains available through inventory/run queries.
- Recovery rereads storage for every fetch. Captured principal/tenant generations, readiness, mount state and tenant preference prevent old asynchronous results from writing cache or recovery state after logout/switch. Ordinary auth cache clearing remains unchanged.
- A small `useSharedAnalysisPolling` hook elects one observer per Query object for list/recovery intervals. React Query owns the timers; this introduces no global polling service or event bus. Remaining observers take ownership after the owner unmounts. Tests measure one fetch per polling interval even for staggered duplicate observers.

### Files changed

Existing: `frontend/src/lib/queryInvalidation.ts`, `frontend/src/lib/pendingAnalysis.ts`, `frontend/src/hooks/useAnalysisStream.ts`, `frontend/src/hooks/useBackgroundAnalysis.ts`, `frontend/src/hooks/usePendingAnalysisRecovery.ts`, `frontend/src/hooks/useSbomsList.ts`, `frontend/src/app/sboms/page.tsx`, `frontend/src/app/analysis/[id]/page.tsx`, `frontend/src/app/schedules/page.tsx`, `frontend/src/components/schedules/ScheduleCard.tsx`, `frontend/src/components/schedules/ScheduleEditor.tsx`, `frontend/src/components/schedules/ScheduleCard.test.tsx`, and this report.

New: `frontend/src/lib/analysisSync.ts`, `frontend/src/hooks/useAnalysisScope.ts`, `frontend/src/hooks/useAnalysisTerminal.ts`, `frontend/src/hooks/useSharedAnalysisPolling.ts`, `frontend/src/lib/schedule-sync.test.ts`, `frontend/src/hooks/analysis-terminal.test.tsx`, `frontend/src/hooks/analysis-recovery.test.tsx`, `frontend/src/hooks/background-analysis.test.tsx`, `frontend/src/hooks/analysis-stream-sync.test.tsx`.

### Regression evidence

New real QueryClients use five-minute staleTime. Coverage includes actual card pause/resume and active target-preview refresh, schedule prefix consistency/deduplicated requests and enqueue leaving findings alone; terminal statuses, severity variants, already-terminal mounts, actual conditional run polling, repeat-event deduplication and immutable snapshots; unfiltered/project/product/SBOM list polling and stop conditions; active/terminal/error/canceled recovery, recent/expired missing or network results, prior-run rejection, tenant-switch/logout races, immediate scoped running indicators, queued acknowledgements, last-known finding preservation on transport failure, and staggered list observer handoff.

| Check | Result |
|---|---|
| 4A schedule suites | **19 passed, 4 files**, 0 failures |
| 4B terminal/detail/dashboard invalidation suites | **21 passed, 3 files**, 0 failures |
| Initial corrected 4C recovery/terminal/schedule check | **35 passed, 4 files**, 0 failures |
| Expanded new checks including polling handoff, background failure and existing stream transport | **44 passed, 6 files**, 0 failures |
| Final combined Batch 1–4 regression set | **337 passed, 32 files**, 0 failures |
| TypeScript (`npm exec -- tsc --noEmit --incremental false`) | **Exit 0, no diagnostics** |
| ESLint (`npm run lint`) | **Exit 0; 0 errors, 53 unchanged baseline warnings** |
| `git -c core.fsmonitor=false diff --check` | **Passed** |

Commands use existing npm scripts and bundled Node. Focused regression commands use `--maxWorkers=1 --testTimeout=15000`. Intermediate new-test failures were corrected: preview assertions now distinguish active refetch from inactive invalidation; terminal tests wait for query notifications; recovery expiry exposed and fixed stale storage reads; run IDs are normalized to numbers for the existing string-or-number SBOM schema; a toast mock with no returned ID required a corrected assertion. A prior full combined run was **332 passed / 1 new toast-assertion failure**; its corrected rerun passed **333 tests across 31 files** before the added staggered-observer and stream tests. The intervening complete run with polling-owner handoff passed **334 tests across 31 files**. Stream tests also verify prompt marker cleanup after an authoritative ERROR result and rejection of a late response across tenant switching. Temporary new hook dependency warnings were fixed; baseline-existing warnings are compared in the final results.

### Limitations and remaining acceptance work

No full frontend/backend suite, production build, live browser, real scheduler/worker/provider, or real-backend cancellation validation was claimed. Browser acceptance should cover Run Now followed by navigation, worker interruption and partial provider outcomes, filtered analysed views, refresh/recovery during a long job, logout/switch during a stream, and real schedule inheritance/target changes. Recovery retries use existing APIs and a bounded unresolved-marker lifetime; this is not cross-user real-time notification. No global staleTime/focus settings, dependencies or SSE/WebSocket infrastructure changed. UI-SYNC-11, 14, 15 and 17 remain deferred.

Batch 4 preservation check: SHA-256 comparison against the pre-batch snapshot found only the 13 listed existing files changed, plus the nine listed new source/test files. Removing this appended section reproduces the pre-batch report hash exactly, preserving the original audit and Batch 1–3 documentation. Branch and HEAD remain unchanged. No backend source, dependencies or unrelated work was modified.


## Batch 5 implementation — user management and AI fix completion synchronization

Implemented on 2026-10-09, restricted to **UI-SYNC-11 and UI-SYNC-14**. Verified branch `feat/native-user-management` and HEAD `6e7b22e1110ef1849150671b8d253efe0479e074` before editing and at delivery. No branch switch, reset, clean, stash, commit or push. No backend/business-rule, dependency, global staleTime/focus setting, report-artifact, or additional transport changes. Batch 1–4 source and regression coverage were preserved.

### UI-SYNC-11: shared identity and membership dependencies

Added awaitable `invalidateTenantMembershipSurfaces` and `invalidateUserSurfaces` to the existing `queryInvalidation.ts`. They use the existing same-turn invalidation queue. Tenant IDs are numeric for administration caches and string-normalized for the actual VEX tenant query keys. Prefixes cover all cached search/page/filter variants, including infinite assignee query pages. The global platform list prefix is required because individual variants contain multiple tenant projections; resource details remain tenant-scoped.

| Confirmed successful operation | Caller / retained local behavior | Query dependencies |
|---|---|---|
| Native platform/tenant invitation or attaching an existing account through invitation | `NativeUserInviteForm`; preserves delivery messaging and parent `onCreated`/directory revision | Affected `tenant-users`, `tenant-roles`, `tenant-audit-history`, `platform-tenant`, tenant-scoped `vex-assignees`/`vex-investigations`, all `platform-tenants` variants, `platform-summary` |
| Add/remove/enable/disable membership; replace roles | `TenantUsersAccess` and directory membership actions in `UserLifecycle`; existing dialogs, version checks and role form drafts retained | Same affected tenant dependencies and summary; administrator coverage and total memberships are server-derived |
| Profile edit | `UserLifecycle` retains local directory/detail revision and current filters/page | Affected membership labels, assignee options and known investigation details, tenant details, platform tenant lists and administrator labels; **no platform-summary invalidation** |
| Global status, unlock, forced password change | `UserLifecycle`; existing confirmation and security semantics | Known membership tenant dependencies plus `platform-administrators` and `platform-summary` |
| Logout-all native sessions | Existing backend action and local directory revision | Identity/admin/tenant projections and audit; **no summary recalculation** because account/membership counts do not change |
| Resend activation | `UserLifecycle` and `PlatformTenantOverview` | Tenant identity/audit projections; **no summary recalculation** and no claim of account activation |
| Grant/revoke platform administrator authority | Existing Batch 1 helper retained in settings platform page | Existing `platform-administrators` + `platform-summary`; self-change also refreshes authoritative session context |

Platform summary dependencies were checked against `app/routers/platform.py`: membership totals count memberships, tenant admin coverage depends on effective account/membership/role eligibility, and platform administrator totals depend on active grants and eligible active identities. A profile edit changes labels, not these counts. Global directory details supply affected tenant memberships; tenant profile edits also find other cached memberships for the same user ID without refreshing unrelated tenant details. Known VEX list rows identify affected unscoped investigation details/triple caches so assignment labels/eligibility are refreshed without invalidating security aggregates or historical snapshots.

`UserSearchCombobox` remains an imperative, debounced local-state consumer. An optional revision prop refreshes existing candidate searches after local membership/invitation and administrator changes; search text and selected filter state are retained. `TenantUsersAccess` and the platform administrator parent increment this revision. No second cache or event bus was introduced.

**Current-user authorization:** the supported `refreshSession` mechanism now accepts additive `{ authorizationChanged: true }`. Only callers with a confirmed self authority/security change use this option: it marks context loading, cancels cached requests, discards privileged cached results and awaits the existing session + `/auth/me` resolution. Ordinary refresh callers (login callback/access-pending) keep their existing behavior. Self profile changes re-resolve identity without the authority-cache purge. Existing removal/disable routing to access-pending remains; ordinary role refresh does not add a redirect or logout. Permission values are never fabricated from mutation payloads. Existing server RBAC/token semantics are unchanged.

New `useMutationScope` captures principal, tenant, auth-readiness generation, storage tenant and mount lifetime. User/membership/invitation/admin and AI mutation callbacks reject obsolete successful responses before cache updates. Failed/conflicting requests retain drafts and do not invalidate successful metrics or emit false success. Invitation creation and queued/delivered email remain distinct from account activation.

### UI-SYNC-14: AI execution reconciliation

Added `invalidateAiBatchSurfaces` to the existing invalidation utility and `aiBatchSync.ts` for authoritative terminal classification, idempotent terminal reconciliation and successful cancel-acknowledgment invalidation. The implementation reuses the existing global SSE transport and two-second fallback; it adds no connection service.

| Backend event | Shared contract | Cache behavior |
|---|---|---|
| Successful enqueue | `invalidateAiBatchSurfaces` without results; returned progress seeds legacy and batch-specific keys | Refresh `ai-batch-progress` for that run and `ai-batch-list`; do not imply fix output or generation success |
| Live progress | Existing global subscription or legacy progress hook writes its actual progress key | Counters never determine terminal success; another batch's specific key is not overwritten |
| `complete`, `failed`, `cancelled` | `reconcileAiBatchTerminal` | Refresh run's `ai-fix-list`, legacy and specific `ai-batch-progress` variants, `ai-batch-list`, per-finding `ai-fix`, `ai-settings/usage`, `ai-usage`, all `ai-usage-trend` and `ai-top-cached` variants |
| `paused_budget` with authoritative `finished_at` | Worker ends budget-halted execution in `app/ai/batch.py`; use the same terminal contract | Refresh persisted partial outputs/history/usage and stop tracking; unfinished pause envelopes remain trackable |
| Successful cooperative cancel POST | `invalidateAiBatchCancellation`, used by both dedicated hooks and banner | Refresh partial output/history/progress/usage; **do not invent `cancelled`** from `cancel_requested` |
| Failed cancel or failed progress fetch | Existing query errors; banner displays cancellation error and retains tracking | No false fix success; failed cancel does not invalidate results; existing fallback can recover transient progress failures |

Neither progress nor batch-detail API contracts expose authoritative finding-ID lists. The established `aiFixQueryKey` is `['ai-fix', findingId, providerName ?? null]` and contains no run dimension. The safe fallback therefore invalidates the existing per-finding family; run-level lists/history/progress remain targeted to the affected run. Provider configuration/pricing, unrelated run lists/progress and immutable historical snapshots are preserved. This per-finding fallback is an intentional contract limitation rather than an invented run-key shape.

Terminal bookkeeping lives in QueryClient under `ai-batch-terminal-sync` using tenant/principal scope, run and batch identity (legacy uses start time), with a fingerprint of authoritative status, persisted output/failure counters, cost, finish time and error. Identical observations from SSE/poll/query consumers return without another refresh; distinct batches and later persisted changes still refresh. Successful cancel acknowledgments have separate context/run/batch bookkeeping and do not suppress subsequent terminal reconciliation. Bookkeeping disappears with existing logout/tenant-switch cache clearing.

The provider reuses cached authoritative snapshots at registration instead of immediately repeating the consumer/trigger HTTP read. Existing fallback polling has one in-flight snapshot per subscription and stops on verified terminal/idle/missing-batch results. Initial reads cannot overwrite a later SSE update. Terminal subscriptions close and retain the existing eight-second notification linger. A stream `end` without verified terminal progress falls back to authoritative polling. Global banner cancel keeps tracking until the worker confirms the final outcome and shares dedicated cancel result/history refresh behavior; failed cancellation remains retryable.

Provider tracking is scoped by auth generation while its children stay mounted: scope cleanup removes prior subscriptions/timers without resetting unrelated form drafts. Captured guards and abort/closed transport cleanup reject late SSE, polling and mutation responses after tenant switch, logout or unmount. Batch-specific updates never manually replace another batch's progress. Both legacy run-only and specific batch consumers remain supported.

### Exact Batch 5 files

Existing files changed (changes are relative to the pre-Batch-5 working tree, not HEAD):

- `frontend/src/hooks/useAuth.tsx`
- `frontend/src/hooks/useAuth.test.tsx`
- `frontend/src/hooks/useAiFix.ts`
- `frontend/src/lib/queryInvalidation.ts`
- `frontend/src/components/admin/UserLifecycle.test.tsx`
- `frontend/src/components/admin/TenantUsersAccess.tsx`
- `frontend/src/components/admin/UserSearchCombobox.tsx`
- `frontend/src/components/admin/UserSearchCombobox.test.tsx`
- `frontend/src/components/admin/PlatformTenantOverview.tsx`
- `frontend/src/components/admin/UserLifecycle.tsx`
- `frontend/src/components/admin/NativeUserInviteForm.tsx`
- `frontend/src/components/admin/NativeUserInviteForm.test.tsx`
- `frontend/src/components/ai-fixes/GlobalAiBatchProgress/AiBatchProgressProvider.tsx`
- `frontend/src/components/ai-fixes/GlobalAiBatchProgress/useGlobalAiBatchProgress.ts`
- `frontend/src/components/ai-fixes/GlobalAiBatchProgress/GlobalAiBatchBanner.tsx`
- `frontend/src/app/settings/tenant/page.test.tsx`
- `frontend/src/app/settings/platform/page.tsx`

New files:

- `frontend/src/hooks/useMutationScope.ts`
- `frontend/src/lib/user-invalidation.test.ts`
- `frontend/src/lib/ai-batch-sync.test.ts`
- `frontend/src/lib/aiBatchSync.ts`
- `frontend/src/components/ai-fixes/GlobalAiBatchProgress/data-sync.integration.test.tsx`

Documentation appended: `docs/engineering/phase1-ui-data-sync-audit.md` (this section only).

### Validation and observed cache behavior

All cache integration clients use five-minute `staleTime`, disabled global focus refetch and real QueryClients/observers. Tests assert authoritative cached/rendered data and fetch counts rather than only mocked helper calls.

| Executed check | Exact result |
|---|---|
| Batch 5A initial focused user-management set | **81 passed, 6 files**, 0 failures |
| Batch 5A expanded invitation/self-auth/cache set | **84 passed, 6 files**, 0 failures |
| Batch 5B initial AI/provider/fix set | **76 passed, 6 files**, 0 failures |
| Batch 5B final AI/provider/fix + architectural invariant set | **80 passed, 7 files**, 0 failures |
| Combined Batch 1–5 before candidate-search expansion | **472 passed, 42 files**, 0 failures |
| Final combined Batch 1–5 including both candidate-search suites | **490 passed, 44 files**, 0 failures |
| TypeScript: `npm exec -- tsc --noEmit --incremental false` | **Exit 0** |
| ESLint: `npm run lint` | **Exit 0; 0 errors, 52 warnings**; no new warning messages versus Batch 4's 53; existing unused `_res` warning removed |
| `git -c core.fsmonitor=false diff --check` | **Exit 0** |

Tests ran with bundled Node from `/Users/ferozebasha/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin` using `npm run test -- --maxWorkers=1 --testTimeout=15000` in `frontend`. Intermediate new-test issues (required-label matching, QueryClient test wrapper/fixture, fake-timer notification flush and static invalidation helper naming) were corrected. These were introduced test/integration adjustments, not attributed to pre-existing failures. Existing jsdom pseudo-element `getComputedStyle` notices remain in accessible user-directory tests; they do not fail assertions. No unrelated production code or tests were changed to force a pass.

Observed request bounds: duplicate same-turn user helper calls produce **one refetch per active projection**; a two-page infinite assignee observer refetches its **two pages once each**. Duplicate terminal observations produce **one results/history/usage refetch per active key**; a later distinct batch produces a second, and changed persisted evidence a third. Initial enqueue produces **zero fix-result/usage refetches**. Successful cancellation produces one refresh per dependent active key and keeps actual in-progress status until terminal evidence. No-SSE fallback stops making snapshot reads after terminal reconciliation. Disabled observers execute **zero requests**; inactive relevant caches become stale and fetch server values on return. Unrelated tenant details, run-level AI caches, provider configuration and historical snapshots remain fresh in isolation tests.

Final combined test-file manifest:

- `frontend/src/app/platform/page.test.tsx`
- `frontend/src/app/platform/data-sync.integration.test.tsx`
- `frontend/src/app/settings/platform/page.test.tsx`
- `frontend/src/app/settings/platform/tenants/page.test.tsx`
- `frontend/src/app/settings/platform/tenants/[tenantId]/page.test.tsx`
- `frontend/src/lib/queryInvalidation.test.ts`
- `frontend/src/hooks/useAuth.test.tsx`
- `frontend/src/__tests__/mutation-invalidation.test.ts`
- `frontend/src/lib/dashboard-vex-invalidation.test.ts`
- `frontend/src/components/vex/data-sync.integration.test.tsx`
- `frontend/src/app/vex-investigation/page.test.tsx`
- `frontend/src/components/sboms/SbomDetail.lifecycle.test.tsx`
- `frontend/src/components/sboms/SbomDetail.components.test.tsx`
- `frontend/src/components/dashboard/PortfolioOverview.test.tsx`
- `frontend/src/components/dashboard/__tests__/managerWidgets.test.tsx`
- `frontend/src/app/__tests__/dashboard-drilldown.integration.test.tsx`
- `frontend/src/app/products/[id]/page.test.tsx`
- `frontend/src/lib/inventory-invalidation.test.ts`
- `frontend/src/components/sboms/inventory-sync.integration.test.tsx`
- `frontend/src/components/projects/ProjectModal.test.tsx`
- `frontend/src/components/reports/ReportNotificationsPage.test.tsx`
- `frontend/src/components/sboms/SbomUploadModal.repair.test.tsx`
- `frontend/src/components/projects/ProjectsTable.viewmode.test.tsx`
- `frontend/src/hooks/analysis-recovery.test.tsx`
- `frontend/src/hooks/analysis-terminal.test.tsx`
- `frontend/src/hooks/background-analysis.test.tsx`
- `frontend/src/hooks/analysis-stream-sync.test.tsx`
- `frontend/src/lib/schedule-sync.test.ts`
- `frontend/src/components/schedules/ScheduleCard.test.tsx`
- `frontend/src/components/schedules/ScheduleEditor.test.tsx`
- `frontend/src/app/schedules/page.test.tsx`
- `frontend/src/app/analysis/[id]/__tests__/drilldown.integration.test.tsx`
- `frontend/src/lib/user-invalidation.test.ts`
- `frontend/src/components/admin/UserLifecycle.test.tsx`
- `frontend/src/components/admin/NativeUserInviteForm.test.tsx`
- `frontend/src/app/settings/tenant/page.test.tsx`
- `frontend/src/lib/ai-batch-sync.test.ts`
- `frontend/src/components/ai-fixes/GlobalAiBatchProgress/data-sync.integration.test.tsx`
- `frontend/src/components/ai-fixes/__tests__/RunBatchProgress.test.tsx`
- `frontend/src/components/ai-fixes/__tests__/AiFixSection.test.tsx`
- `frontend/src/components/ai-fixes/__tests__/AiFixSection.errorCopy.test.tsx`
- `frontend/src/components/ai-fixes/__tests__/AiFixSection.axe.test.tsx`
- `frontend/src/components/admin/UserSearchCombobox.test.tsx`
- `frontend/src/components/admin/__tests__/UserSearchCombobox.test.tsx`

### Remaining acceptance work and preservation

No full frontend/backend suite, production build, live browser or real-worker/provider execution was performed for Batch 5. Remaining acceptance scenarios are real tenant/platform invitations and email delivery, self role/admin changes with live authentication, native disable/forced-password/session revocation behavior, AI provider partial failure/budget halt, cooperative cancel during generation, simultaneous batches, SSE reconnect/fallback and navigation/logout/tenant switch while a real worker is active. Remote mutations by another user remain outside this local synchronization batch; no cross-user real-time guarantees are claimed.

SHA-256 comparison against `/tmp/ui-batch5-before.json` confirms only the listed 17 existing frontend files changed and the five listed frontend files were added. Original audit and Batch 1–4 documentation remain byte-identical as the prefix before this appended section. No backend files, dependency manifests or unrelated pre-existing modified/untracked work were changed. Branch and HEAD remain unchanged, with no commit or push. **UI-SYNC-15 and UI-SYNC-17 remain deferred.**


## Batch 6 implementation — lifecycle readiness and cache performance

Implemented on 2026-10-09 on `feat/native-user-management`, HEAD `6e7b22e1110ef1849150671b8d253efe0479e074`. Scope: **UI-SYNC-15 and UI-SYNC-17 only**. Original audit and Batch 1–5 sections remain intact. The substantial pre-existing tracked/untracked work was preserved; no switch, reset, clean, stash, commit, push, backend rule change, dependency, deployment or migration was performed.

### 6A — lifecycle readiness (UI-SYNC-15)

`invalidateLifecycleProviderSurfaces` returns an awaitable Promise through the existing same-turn queue. Tenant operations invalidate `['lifecycle-providers', scopeKey]`; platform defaults invalidate the configuration family because cached tenant configurations resolve inherited defaults. Readiness changes invalidate `['lifecycle-provider-status']`, consumed by SBOM detail. Its legacy key is unscoped, but the endpoint is **contextual**, not a global tenant aggregate: `app/main.py` protects the router with `enforce_request_access`, binding `CurrentContext`; `LifecycleProviderConfigService.list_configs` resolves platform defaults plus the bound tenant's overrides. Existing auth switching/logout clears contextual caches. No query-key migration or new polling is needed.

| Confirmed successful operation | Configuration dependency | Readiness dependency / distinction |
|---|---|---|
| Save configuration; enable/disable | Affected scope, including inherited configurations for platform changes | Refresh authoritative provider-status; never derive readiness from the edited fields |
| Save/delete credential | Affected scope | Refresh provider-status; a saved credential is not proof of a successful connection |
| Reset tenant override | Tenant configuration | Refresh inherited effective provider-status |
| Connection test of owned configuration | Affected scope | Backend persists health/timestamps, including degraded failed probes; refresh status even when HTTP 200 has `success: false` |
| Tenant test of inherited platform configuration | Tenant configuration/test result | Backend does not persist platform health from this tenant test; no readiness invalidation |
| Inline sync `completed` / `failed` | Affected scope | Refresh persisted health for owned configuration; retain returned message and show failed sync as an error |
| Queued acknowledgment, if returned | Configuration only | Show queued message; do not invent terminal readiness or generated component evidence |
| Vendor create/update/disable/import | All `['lifecycle-vendor-records', search]` variants | No provider-status or existing SBOM evidence invalidation: catalog edits do not materialize new component evidence |

Actual backend contract: `provider_config_service.py::sync_provider` returns `job_id: null` and `completed`/`failed` for its inline action. Xeol DB clears its cache and may persist probe health; OpenEoX reports that feeds load during refresh/test, custom vendor records are immediately available, and other providers require no sync. There is **no lifecycle sync job-status endpoint or reliable asynchronous terminal tracking contract** here. No speculative timer or transport was added. The queued-response regression uses a mocked acknowledgment to ensure it cannot be shown as completed; this does not claim a current backend worker/job implementation.

`LifecycleProviderSettings` and `LifecycleVendorRecordsPage` capture the existing `useMutationScope` guard before requests; old-context/unmounted success callbacks cannot restore provider data or invalidate another context. Permission buttons and the scoped configuration parent remain intact. Config/secret failures retain form drafts and existing error notifications; successful connection results remain separate from editable configuration. Form save callbacks consume already-reported mutation failures instead of leaving rejected event-handler promises. Vendor search/editor state and Batch 3 canonical/paginated component synchronization are preserved. No full SBOM reanalysis is triggered.

### 6B — measured cache performance (UI-SYNC-17)

Before optimization, deterministic real-QueryClient tests populated **45 caches per scenario**: 36 active projections, four inactive variants, two disabled observers and three unrelated/immutable controls. Five-minute `staleTime`, disabled focus refetch, delayed counted query functions and abort listeners measured actual query executions and cancellations. Measurements were captured in `/tmp/b6-before.jsonl` before modifying performance logic; the identical scenarios were rerun into `/tmp/b6-after.jsonl`. These are network-equivalent query-function counts, not real HTTP/browser measurements.

| Operation / actual helper composition | Affected caches before → after | Active queries refreshed before → after | Query executions before → after | Inactive stale | Disabled stale / executions | Duplicate executions before → after |
|---|---:|---:|---:|---:|---:|---:|
| Analysis completion | 25 → 25 | 20 → 20 | 20 → 20 | 3 | 2 / 0 | 0 → 0 |
| SBOM upload | 19 → 19 | 15 → 15 | 15 → 15 | 3 | 1 / 0 | 0 → 0 |
| SBOM delete composition | 24 → 24 | 20 → 20 | 20 → 20 | 3 | 1 / 0 | 0 → 0 |
| SBOM lifecycle change | 26 → 26 | 22 → 22 | **25 → 22** | 3 | 1 / 0 | **3 → 0** |
| Project cascade deletion | 19 → 19 | 15 → 15 | 15 → 15 | 3 | 1 / 0 | 0 → 0 |
| Product update | 16 → 16 | 13 → 13 | 13 → 13 | 2 | 1 / 0 | 0 → 0 |
| VEX decision | 7 → 7 | 5 → 5 | 5 → 5 | 0 | 2 / 0 | 0 → 0 |
| AI batch terminal results | 7 → 7 | 6 → 6 | 6 → 6 | 1 | 0 / 0 | 0 → 0 |
| Tenant membership change | 5 → 5 | 5 → 5 | 5 → 5 | 0 | 0 / 0 | 0 → 0 |
| Advisor recommendation | 5 → 5 | 5 → 5 | 5 → 5 | 0 | 0 / 0 | 0 → 0 |
| Tenant advisor policy | **5 → 4** | **5 → 4** | **5 → 4** | 0 | 0 / 0 | 0 → 0 |

All three lifecycle duplicates were advisor projections refreshed by both direct and queued invalidation; they also caused three aborts. Routing lifecycle composition through the existing queue reduces **25 to 22 executions, with zero duplicate aborts**, while retaining all 26 affected caches. `invalidateSbomSurfaces`, `invalidateProjectSurfaces` and `invalidateSbomLifecycle` now return awaitable completion promises and compose existing targets. Lifecycle history uses the known SBOM ID. No coalescing window was extended across mutation events.

The original policy predicate refreshed another tenant's cached summary. `invalidateAdvisorPolicySurfaces` uses verified identities: summary/components/component tenant at index 1, recommendation tenant at index 2, candidate evidence tenant at the final index, including the optional `checks` segment. Tenant policy refresh preserves other tenants; platform policy remains broad because defaults affect inheritance. `ScopedAdvisorPolicies` captures the mutation context and refreshes history/advisor projections together after the confirmed publish. Row-version/409 conflict behavior and manual reload remain intact.

Analysis/upload/delete/project/product/VEX/AI/membership/recommendation scenarios already produced one execution per affected active key; **no speculative refactoring** was made to their terminal bookkeeping, transport or invalidation queue. Existing analysis and AI idempotency, scoped polling and context safeguards remain unchanged. Per-finding AI invalidation remains broad because progress omits finding IDs and the existing key factory has no run dimension; narrowing it would require a separate API contract change.

Additional real-cache tests cover sequential mutations, overlapping requests (old read canceled, newest data retained), failed refetch followed by recovery, awaitable completion, QueryClient isolation, tenant/platform policy scopes, inactive staleness, disabled observers and immutable controls. Two sequential mutations cause two refreshes; same-turn composed helpers cause one. An overlapping later mutation causes a second request and cancels the earlier request intentionally. Default helper error semantics are preserved: invalidateQueries resolves after a failed refetch without `throwOnError`; subsequent invalidations remain possible. Historical VEX snapshots and report deliveries execute zero requests and remain fresh.

### Exact Batch 6 files

Existing files modified:

- `frontend/src/lib/queryInvalidation.ts`
- `frontend/src/components/admin/LifecycleProviderSettings.tsx`
- `frontend/src/components/admin/LifecycleProviderForm.tsx`
- `frontend/src/components/admin/LifecycleVendorRecordsPage.tsx`
- `frontend/src/components/admin/ScopedAdvisorPolicies.tsx`
- `frontend/src/components/admin/LifecycleProviderSettings.test.tsx`
- `docs/engineering/phase1-ui-data-sync-audit.md`

New tests:

- `frontend/src/lib/lifecycle-invalidation.test.ts`
- `frontend/src/lib/cache-performance.test.ts`

`LifecycleProviderForm` accepts a separately refreshed credential indicator so secret saves/deletes update the open form without replacing its provider snapshot or resetting draft fields. Tests retain an unsaved priority of 27 while authoritative credential state changes. SBOM detail, API adapters, backend files, dependency manifests, analysis/AI terminal helpers and previous batch tests were inspected and preserved. Next's build-generated `next-env.d.ts` route imports are restored to their exact pre-batch contents.

### Validation evidence

All commands used the bundled Node runtime and existing frontend npm scripts. Vitest commands used `--maxWorkers=1`; combined/full runs used `--testTimeout=15000`.

| Check | Result |
|---|---|
| 6A lifecycle configuration + cache suites before performance edits | **33 passed, 2 files**, zero failures |
| 6A TypeScript / lint before proceeding | TypeScript exit 0; lint exit 0, 0 errors / 52 existing warnings |
| Pre-optimization request-count measurement | **11 passed, 1 file**; lifecycle duplicates recorded above |
| Final Batch 6 focused lifecycle/performance/policy suites | **66 passed, 4 files**, zero failures |
| Combined Batch 1–6 (prior 44-file manifest plus four lifecycle/performance/policy files) | **556 passed, 48 files**, zero failures |
| TypeScript `npm exec -- tsc --noEmit --incremental false` | Exit 0 |
| ESLint `npm run lint` | Exit 0; **0 errors, 52 warnings**, unchanged warning count from pre-batch baseline |
| Production build `npm run build` | Exit 0; compiled, TypeScript checked, 47 static pages generated |
| Full frontend suite | **1,622 passed, 4 failed (1,626 total), 191 files: 190 passed / 1 failed**; exit 1. Four baseline failures described below. |
| Isolated pre-Batch-6 reproduction of full-suite failing file | **4 failed, 1 file**; same four AuthProvider failures |
| `git -c core.fsmonitor=false diff --check` | Exit 0 |

Full-suite failures are in unchanged `src/hooks/useAnalysisStream.test.tsx`: duplicate manual starts, active tenant header, missing tenant handling and tenant-switch request tests all throw `useAuth must be used within an AuthProvider`. The old wrapper provides QueryClient only. In an isolated temporary frontend copy, all six Batch-6-modified frontend files were restored to **SHA-256-identical pre-batch contents**, including the previous-batch invalidation helper; rerunning that file reproduced the exact four failures. They were not changed to force a green full suite. These are baseline test-harness failures and remain a release-validation gap.

Vitest also emits existing jsdom pseudo-element/navigation limitations. No live browser, PostgreSQL/backend integration, actual lifecycle provider connectivity or real worker validation was performed. The production build is local validation only; nothing was deployed.

### Final Phase 1 findings matrix

“Implemented” means source changes and focused cache/workflow regression evidence, not live-browser or cross-user real-time acceptance. Prior sections retain the detailed mutation matrices and historical test results.

| Finding | Implementation status / batch | Source evidence | Validation evidence |
|---|---|---|---|
| UI-SYNC-01 | Implemented, Batch 1 | Platform tenant helper + tenant list/detail mutations | Platform data-sync integration; combined 556 |
| UI-SYNC-02 | Implemented, Batch 1 | Platform administrator helper + authority mutations | Platform settings/dashboard tests; combined 556 |
| UI-SYNC-03 | Implemented, Batch 2 | Shared dashboard priority/operational/trend/age dependencies | Dashboard invalidation/measurement suites; combined 556 |
| UI-SYNC-04 | Implemented, Batch 2 | VEX evidence helper includes dashboard-summary | VEX cache/integration tests; combined 556 |
| UI-SYNC-05 | Implemented, Batch 2 | SBOM-scoped investigation-by-triple invalidation | VEX cache/integration tests; combined 556 |
| UI-SYNC-06 | Implemented, Batch 3 | Authoritative old/new ownership helper + SBOM metadata mutations | Inventory reassignment integration/cache suites; combined 556 |
| UI-SYNC-07 | Implemented, Batch 3 | Project metadata helper + modal create/edit | Project/inventory tests; combined 556 |
| UI-SYNC-08 | Implemented, Batch 3 | Revision-created helper + restore navigation | Restore/inventory cache tests; combined 556 |
| UI-SYNC-09 | Implemented, Batch 3 | Canonical + paginated lifecycle evidence helper | Component evidence/cache tests; combined 556 |
| UI-SYNC-10 | Implemented, Batch 4 | Schedule change/submission helpers + card/editor/page mutations | Schedule synchronization suites; combined 556 |
| UI-SYNC-11 | Implemented, Batch 5 | User/membership helpers, directory refresh, self-auth resolution | User/assignee/auth suites; combined 556 |
| UI-SYNC-12 | Implemented, Batch 4 | Shared terminal reconciliation + run polling integration | Terminal/run-detail suites pass; legacy AuthProvider harness gap documented above |
| UI-SYNC-13 | Implemented, Batch 4 | Scoped conditional polling, recovery/context guards | Scoped/recovery/background tests; combined 556 |
| UI-SYNC-14 | Implemented, Batch 5 | AI terminal/cancel reconciliation, provider transport guards | AI cache/provider/result suites; combined 556 |
| UI-SYNC-15 | Implemented, Batch 6A | Lifecycle configuration/readiness/vendor helpers + guarded callbacks | Lifecycle helper and settings cache tests; combined 556 |
| UI-SYNC-16 | Implemented, Batch 3 | Shared reports/targets inventory dependency | Report/inventory tests; combined 556 |
| UI-SYNC-17 | Implemented, Batch 6B | Measured lifecycle coalescing + tenant policy targeting | Eleven before/after scenarios + concurrency/recovery tests; combined 556 |

### Remaining release acceptance and preservation

Live acceptance remains necessary for tenant/platform configuration and credential changes followed by cached SBOM detail navigation, owned versus inherited connection probes, Xeol inline sync failures, vendor catalog imports followed by explicit component enrichment, filtered inventory/dashboard navigation, simultaneous mutations, and logout/tenant switching during real requests. Resolve the four legacy stream-test AuthProvider harness failures in a separately scoped follow-up. No lifecycle asynchronous job tracking is claimed because there is no reliable job-status contract. Cross-user/server-originated synchronization remains outside this local mutation initiative; no transport or general real-time service was added.

SHA-256 comparison against the pre-batch snapshot found exactly the six listed existing frontend files plus this report changed, and the two listed new tests added. Backend files, all other existing frontend/documentation files and generated `next-env.d.ts` remain identical to their pre-batch contents. The original audit and all Batch 1–5 sections remain a byte-identical prefix. Active branch and HEAD remain unchanged; no commit or push was performed.

**Stop condition met for UI-SYNC-15/UI-SYNC-17; no additional feature scope, commit or push.**
