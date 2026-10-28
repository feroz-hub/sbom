# Phase 1 UI synchronization — release acceptance

Date: 2026-10-09. Repository: HCLTech SBOM Analyzer. Branch: `feat/native-user-management`. HEAD: `6e7b22e1110ef1849150671b8d253efe0479e074`.

**Release decision: NOT READY. Gate A PASSED; Gate B BLOCKED.** All frontend tests now pass, but required real-environment acceptance has not run. Source implementation and mocked/cache regression results do not establish live release readiness.

The original [Phase 1 audit and six implementation batches](phase1-ui-data-sync-audit.md) remain unchanged. No reset, clean, stash, branch switch, commit, push, deployment, database migration, shared database modification, dependency installation or real user/tenant mutation was performed.

## Gate A — frontend harness and regression verification

### Reproduction and root cause — ACC-01 (resolved)

The unchanged `frontend/src/hooks/useAnalysisStream.test.tsx` reproduced **four failures out of four tests**, all `useAuth must be used within an AuthProvider`. Its wrapper supplied QueryClient only. Batch 4's production `useAnalysisScope` reads real authorization/tenant context, so merely having a stored tenant ID is insufficient.

The harness now follows `useAuth.test.tsx`: real `AuthProvider` inside `QueryClientProvider`, synthetic `/api/auth/session` and `/api/auth/me` responses with explicit active memberships, roles and permissions, and readiness awaited before starting analysis. Auth resolution, tenant selection, logout, context cleanup and stream parsing remain production implementations. No `useAuth`, `useAnalysisScope` or production analysis behavior is broadly mocked away. The synthetic OIDC configuration avoids external identity traffic; the logout navigation side effect is stubbed using the existing auth-test convention.

The existing four tests and assertions were retained: duplicate manual starts, active tenant headers, no stream submission when persisted tenant selection is missing, and the new tenant header after switching. Stream requests are counted separately from genuine auth bootstrap requests. Tenant switching uses actual `auth.selectTenant`, rather than only editing storage. All fixture identities and memberships are synthetic; no issued token or real credential is used.

Four additional test cases cover cancellation, tenant-switch late response isolation, logout late response isolation, and restarting after a context-change abort. A real QueryClient uses a five-minute staleTime and disabled window-focus refetch. Abort signals and cache clearing are observed directly; late terminal payloads cannot install a summary or repopulate old privileged data.

### Separately demonstrated production defect — ACC-02 (resolved)

A new test used a fetch promise that rejects with `AbortError` when tenant switching aborts its signal. After authoritative auth resolution to the new tenant, the next analysis start made no request: **expected two stream requests, received one**. The old-context early return occurred before `clearPending()` released the local `runningAnalysisRef` reservation. This could leave a mounted hook silently refusing subsequent starts.

Only that catch path in `useAnalysisStream.ts` changed: release the local start reservation before checking `isCurrent()`. The existing guard still prevents retired-context state, result and cache writes. No backend analysis, worker, persisted recovery, tenant authorization, terminal status, scheduling or VEX business rule changed. This production change is supported by a failing regression before the fix and passing regression afterward, as required by the release task's exception.

### Exact files changed during acceptance

1. `frontend/src/hooks/useAnalysisStream.test.tsx` — real AuthProvider harness; original assertions preserved; four additional test cases.
2. `frontend/src/hooks/useAnalysisStream.ts` — narrowly verified cleanup ordering fix for context-change fetch failures.
3. `docs/engineering/phase1-ui-sync-acceptance.md` — this new report.

Build-generated `frontend/next-env.d.ts` was restored to its exact starting contents. All other existing tracked/untracked work and the original audit were preserved.

### Executed checks

Commands ran from `frontend` with the bundled Node runtime. Vitest used one worker; the full run used a 15-second test timeout.

| Evidence ID | Executed command / check | Actual result |
|---|---|---|
| GA-01 | `npm run test -- --maxWorkers=1 src/hooks/useAnalysisStream.test.tsx` before editing | **4 failed / 4 tests, 1 file**, missing AuthProvider |
| GA-02 | Auth/stream focused suites after initial harness fix | **34 passed, 3 files** |
| GA-03 | Added abort/restart regression before production fix | **7 passed, 1 failed / 8 tests, 1 file**; expected two requests, got one |
| GA-04 | `npm run test -- --maxWorkers=1 src/hooks/useAnalysisStream.test.tsx src/hooks/analysis-stream-sync.test.tsx src/hooks/useAuth.test.tsx` after fix | **35 passed, 3 files**, exit 0 |
| GA-05 | `npm run test -- --maxWorkers=1 --testTimeout=15000` final source | **1,630 passed / 191 files**, zero failed or skipped tests, exit 0; includes the previous 1,626 plus four new cases |
| GA-06 | `npm exec -- tsc --noEmit --incremental false` | Exit 0 |
| GA-07 | `npm run lint` | Exit 0; **0 errors, 52 existing warnings**, unchanged count |
| GA-08 | `npm run build` | Exit 0; Next.js production compilation and TypeScript passed; **47 static pages** generated |
| GA-09 | `git -c core.fsmonitor=false diff --check` | Exit 0 |

During harness development, TypeScript caught an overbroad Vitest mock signature and `HeadersInit` indexing. Both were fixed with an explicit callable request/Response type and standard `Headers` access before final validation. No unrelated production code or tests were changed to force checks to pass. Earlier 1,629-test runs passed before adding the abort/restart case; the final release count is **1,630**.

Existing jsdom pseudo-element/navigation limitations still appear in output; they are not live-browser evidence. The complete frontend suite includes all prior synchronization regression files. No backend suite, migration, live HTTP mutation or worker test is claimed by Gate A.

Local diagnostic logs, without real credentials, are available for this session:

- `/tmp/acceptance-repro.log` — original four failures.
- `/tmp/acceptance-abort-defect.log` — independently reproduced request-reservation defect.
- `/tmp/acceptance-focused-delivery.log` — 35 focused tests passed.
- `/tmp/acceptance-full-delivery.log` — final 1,630-test full suite passed.
- `/tmp/acceptance-tsc-delivery.log`, `/tmp/acceptance-lint-delivery.log`, `/tmp/acceptance-build-delivery.log` — quality checks.

These temporary paths are diagnostic evidence, not durable release artifacts. Archive sanitized logs with release CI evidence before distribution.

## Gate B — real environment availability

Preflight began **only after Gate A's final full suite and quality checks passed**. Checks were read-only: process/listener inventory, loopback TCP probes, HTTP GET probes, `pg_isready`, Redis PING, Docker availability, test configuration presence and a browser runtime bootstrap attempt. No database contents, tenant memberships, credentials or issued tokens were queried or exported.

| Dependency | Observed evidence | Availability for acceptance |
|---|---|---|
| Next.js frontend | Source/build available. No live Next process/listener found. `127.0.0.1:3000` TCP refused; HTTP GET `/` curl exit **7**, HTTP **000** | **Unavailable live target** |
| FastAPI backend | No live FastAPI listener found. Frontend upstream configuration points to loopback port **8000**. GET `http://127.0.0.1:8000/health`: curl exit **7**, HTTP **000** | **Unavailable** |
| Configured PostgreSQL | Root application configuration targets loopback port **55439**. TCP unavailable; `pg_isready -h 127.0.0.1 -p 55439` exit **2**, `no response` | **Unavailable configured endpoint** |
| Other local PostgreSQL | Port **5432** reachable; default `pg_isready` exit **0**, accepting connections | **Present but not verified as the application's disposable test database; not substituted or modified** |
| Redis | Port **6379** reachable; `redis-cli -h 127.0.0.1 -p 6379 PING` exit **0**, `PONG` | **Available connectivity only**; no claim of application broker wiring |
| Celery worker | No matching worker process found; backend unavailable | **Not available/verified** |
| Celery scheduler | No matching beat/scheduler process found | **Not available/verified** |
| Docker stack | `docker ps` could not reach runtime; details suppressed | **Unavailable** |
| Test tenants and actors | No reachable application API or verified disposable database. No synthetic live tenants/users were established or credentials supplied | **Unverified; no actor selected** |
| AI/lifecycle test providers | No reachable provider configuration API or verified test credentials | **Unverified** |
| Interactive browser | Browser skill bootstrap attempted against `iab`; response: **No Codex IAB backends were discovered** | **Unavailable in-app browser runtime** |
| Existing Playwright infrastructure | `frontend/e2e/node_modules/@playwright/test` installed; config requires `REPAIR_E2E_MANIFEST`; manifest not supplied. Existing launcher present. No Phase 1 release acceptance suite established | **Infrastructure present, live execution blocked**; browser binaries/actual sessions not verified |

Configuration URLs were classified without printing credentials, full connection strings, actual database names or tenant-sensitive records. The separate running PostgreSQL server was not assumed disposable. No staging target was supplied. Existing repair E2E infrastructure is not substituted for all nine required acceptance workflows, and its bootstrap/schema setup was not run against an unidentified database.

**Gate B result: BLOCKED.** Having source, a successful production build, Redis and a separate PostgreSQL listener does not establish a running authorized application stack.

## Scenario acceptance matrix

All A–I rows below describe required acceptance actions, **not executed mutations**. Common environment: the inspected local workstation, application frontend/backend unavailable. No staging execution occurred. Starting database/UI states could not be established. Actors/roles below are prerequisites, not identities used in a live test; no real actor or tenant was selected.

| Scenario ID | Required synthetic actor/tenant | Starting state required (not established) | Action required (not executed) | Expected result |
|---|---|---|---|---|
| A | Platform Admin; disposable tenants | Known baseline tenant/admin counts | Create tenant; activate/disable; grant/revoke admin authority | Backend-derived counts, lists and details refresh without F5 |
| B | Tenant Admin/authorized inventory editor; synthetic tenant | Two project/product scopes; SBOM revision history | Create/rename project; upload/update/reassign SBOM; restore revision; reopen report targets | Updated labels; old/new ownership correct; new restored revision visible; target choices refreshed |
| C | Authorized analyst; synthetic tenant | SBOM ready for analysis; functioning worker; scoped lists cached | Submit; observe queued/running and actual success/failure; navigate with filters; remount/recover | Authoritative findings, badges and dashboard refresh; queued acknowledgment never means completion; recovery reconciles |
| D | Analyst/Tenant Admin; synthetic tenant | Current investigation with writable evidence and known metrics | Save decision; revisit dashboard and investigation; change assignment only | Fresh VEX evidence/metrics; assignment-only operation avoids unnecessary aggregate refresh |
| E | Platform/Tenant Admin and controlled self-access actor; two synthetic tenants | Known memberships/roles and assignee eligibility | Invite/add user; replace membership role; change controlled actor's own access; switch/log out | Members and assignees refresh; actual permissions update; no previous-tenant privileged data |
| F | Authorized analyst; synthetic tenant; test AI provider | Known usage, batch history and cached fixes; real provider/worker | Enqueue; observe terminal output; safely test failure/cancel/partial results | Server-generated fixes/history/usage refresh; partial output retained; no false success from enqueue/counters |
| G | Authorized schedule manager; synthetic tenant | Known inherited/excluded targets; functioning scheduler/worker | Create/update/pause/resume; inspect targets; Run Now and wait for actual execution | Lists/details/previews agree; run stays queued/running until authoritative terminal state |
| H | Tenant/Platform configuration administrator; safe test provider credentials | Owned/inherited configurations, catalog and existing component evidence | Save config/credentials; test connection; inline sync; edit/import catalog; revisit SBOM | Persisted health refreshes without F5; transient probes remain distinct; catalog changes do not claim materialized enrichment or invented async tracking |
| I | Authorized actors in two synthetic tenants | Cached filtered dashboards, immutable snapshots, network capture available | Repeat successive mutations; overlap requests; navigate without F5; logout/switch during requests | UI equals backend; bounded refetches; stale requests canceled/isolated; immutable snapshots unchanged |

### Actual execution evidence

| Scenario ID | Actual environment/actor/tenant | Actual UI result | Relevant HTTP/result evidence | Status | Blocker reference |
|---|---|---|---|---|---|
| A | Local preflight; no actor/tenant selected | No application UI reached; no tenant/admin mutation | Frontend GET and backend health GET: curl 7 / HTTP 000; no mutation response | **BLOCKED** | ENV-01, ENV-02, ENV-03 |
| B | Same; no actor/tenant selected | No inventory/forms/selectors reached | Same failed GET probes; no upload/update/restore response | **BLOCKED** | ENV-01, ENV-02, ENV-03 |
| C | Same; no actor/tenant selected | No submitted/running/terminal execution observed | Same failed GET probes; configured DB no response; no worker/run evidence | **BLOCKED** | ENV-01, ENV-02, ENV-03, ENV-04 |
| D | Same; no actor/tenant selected | No live VEX decision or dashboard synchronization observed | Same failed GET probes; no decision/assignment response | **BLOCKED** | ENV-01, ENV-02, ENV-03 |
| E | Same; no actor/tenant selected | No live invitation, self-access change or tenant switch performed | Same failed GET probes; no live auth/membership response | **BLOCKED** | ENV-01, ENV-02, ENV-03 |
| F | Same; no actor/tenant selected | No real AI output, cancellation, partial results or usage observed | No provider/batch/worker response; backend offline | **BLOCKED** | ENV-01, ENV-02, ENV-03, ENV-04, ENV-05 |
| G | Same; no actor/tenant selected | No schedule changes or real Run Now execution observed | No schedule/enqueue/terminal response; backend/worker unavailable | **BLOCKED** | ENV-01, ENV-02, ENV-03, ENV-04 |
| H | Same; no actor/tenant selected | No real provider readiness/test/sync/catalog behavior observed | No configuration, connection-test, secret or sync response | **BLOCKED** | ENV-01, ENV-02, ENV-03, ENV-05 |
| I | Same; no actor/tenant selected | No real mutation request counts, overlapping responses or immutable-snapshot comparison captured | Only failed availability GETs; no scenario network trace | **BLOCKED** | ENV-01, ENV-02, ENV-03, ENV-06 |

No A–I scenario is marked Pass based on Vitest mocks. No record starting state, vulnerability count, invitation delivery, generated fix, worker completion, authenticated role or live metric value is invented. Gate A's abort/dedup/cache evidence is useful regression coverage, but is separate from scenario I's live network acceptance.

## Defects, blockers and risk assessment

| Reference | State | Evidence / impact |
|---|---|---|
| ACC-01 | **Resolved** | Four legacy harness failures repaired with actual AuthProvider, assertions preserved |
| ACC-02 | **Resolved** | Reproduced context-abort local reservation leak; minimal cleanup-order fix, regression passes |
| ENV-01 | **Blocking** | Frontend and FastAPI offline; no real UI/backend workflow possible |
| ENV-02 | **Blocking** | Configured PostgreSQL endpoint offline; other local server not declared disposable or substituted |
| ENV-03 | **Blocking** | No verified test tenants, role actors or controlled self-access account |
| ENV-04 | **Blocking** for analysis/schedules/AI | Worker and scheduler execution not available/verified |
| ENV-05 | **Blocking** for provider-dependent cases | Safe AI/lifecycle test configuration and credentials unverified |
| ENV-06 | **Blocking** for browser evidence | IAB backend absent; existing E2E manifest not supplied; no live browser scenario |

Automated frontend regression risk is reduced: all 1,630 tests pass, auth/tenant transitions use real provider logic, and the newly exposed request-reservation defect is fixed. Existing 52 lint warnings remain. Required integration risk is still high: actual RBAC, backend authoritative projections, worker timing, real connection/provider behavior, cooperative cancellation, invitation delivery and network/refetch behavior remain unverified. No cross-user real-time guarantee is added or inferred.

## Release recommendation and next actions

**NOT READY** under the supplied decision criteria: critical real-environment acceptance remains unverified despite a passing Gate A. No residual-risk approval has been granted, and implementation completion alone does not justify READY.

1. Provision or identify an authorized **disposable** local/staging stack with an already compatible schema: frontend, FastAPI, the configured PostgreSQL database, Redis and required worker/scheduler. Explicit approval is required before any shared-environment migration/reset/modification; none was attempted here.
2. Establish synthetic role actors and tenants, including a controlled self-permission test actor; provide safe AI/lifecycle test provider settings where required. Do not use production users or undeclared existing records.
3. Restore browser access or supply the isolated E2E manifest for the approved target. Capture sanitized UI observations, authoritative HTTP results and request counts for every A–I scenario above.
4. Record live Pass/Fail/Blocked results and defect references, fix any demonstrated defects within scope, and rerun Gate A after changes. A release owner can decide only from that evidence; this report does not grant approval or deploy.

Preservation verification compares SHA-256 hashes against the acceptance-start snapshot. Only the two listed frontend files changed and this report was added; original audit, other frontend/backend files and pre-existing unrelated tracked/untracked work remain unchanged. Branch and HEAD remained as stated. No commit or push.
