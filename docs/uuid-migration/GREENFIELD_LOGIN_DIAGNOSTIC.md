# Greenfield login investigation

Status: **GREENFIELD_LOGIN_FIXED_AND_BROWSER_VERIFIED** (live browser acceptance; final regression totals below).

Date: 2026-10-19. Scope: only the isolated `sbom-greenfield-uuid-dev` development environment. Final verification results are recorded below; existing customer and historical databases were not accessed.

## Symptom and reproduced cause

The reported manual symptom was that sign-in did nothing. A fresh Chromium context accepted the private synthetic Admin credential: `POST /api/auth/native/login` returned 200, issued an opaque Secure/HttpOnly/Lax host-only session cookie, and reached **Select tenant**. No external OIDC provider is enabled here. Password authentication itself was functioning.

A second controlled browser reproduction populated the existing tab's `sessionStorage.sbom_active_tenant_id` with a legacy integer (`1`). Login again returned 200, but subsequent `/api/backend/api/auth/me` calls returned **422**, and the application displayed **Service Temporarily Unavailable** rather than tenant selection/Dashboard. Backend request IDs `58ac451b94b4` and `831a79ee2ffa` correlate with the same failed browser attempt at 14:13:53 UTC. This is a confirmed application defect and a plausible explanation for an existing manual tab; the operator's browser state was not inspected, so its exact original state is not asserted.

`frontend/src/lib/auth.ts:getActiveTenantId()` returned an unvalidated stored value. The UUID migration had hardened writes to this preference, but old values could survive an installation change. `useAuth` then sent the integer in `X-Tenant-ID`; the backend correctly rejected it under the UUID contract. Recovery only handled the distinct 403 unauthorized-valid-tenant case, not malformed identifiers. A clean Playwright context did not contain this legacy value, explaining the earlier acceptance gap.

After correction, the identical integer-state reproduction returned 200 for authentication context (request IDs `69c8279eeadd` and `eaebe3e47e1a`, 14:15:21 UTC) and reached tenant selection. The full browser regression additionally selects Olympus and verifies Dashboard and refresh.

## Minimal correction

- `frontend/src/lib/auth.ts`: validate a persisted tenant preference against the existing UUIDv4 contract before returning it. Invalid/legacy values clear both the preference and its nonsecret tenant cookie; no invalid header is sent. Valid UUID preferences still undergo server-side membership checks.
- `frontend/src/lib/auth.tenantCookie.test.ts`: seven invalid stored-value regressions, covering integers, empty/malformed values and a non-v4 UUID.
- `frontend/src/hooks/useAuth.test.tsx`: verify a legacy integer is discarded before the first context request. Existing unauthorized-tenant recovery fixtures now use a syntactically valid but unauthorized UUID, retaining separate 403 recovery coverage.
- `frontend/src/lib/api.tenantHeader.test.ts` and `frontend/src/hooks/analysis-stream-sync.test.tsx`: convert the remaining integer tenant fixtures to UUIDs while preserving header, tenant-switch, terminal reconciliation and late-response isolation assertions.
- `frontend/e2e/greenfield-login.spec.ts` and `greenfield-login.config.ts`: real role/login, preference, refresh, expiry, logout, denial and initial-access regressions. No screenshots, video, traces, password-bearing request bodies or cookie values are recorded.

The one changed runtime file was synchronized to the launcher's existing isolated frontend workspace; Next development hot reload picked it up. No backend/container restart, schema change, password reset, account recreation, key rotation, grant or authentication bypass was needed. Subsequent `python3 scripts/dev.py start` copies the corrected repository source into that workspace normally.

## Live infrastructure and security observations

- Frontend PID 34901 (Next child 34905), API PID 34900, and Celery worker PID 34899 were running under the recorded launcher ownership registry. The virtual environment resolves to the local Python installation; the configured executable path remains `.venv/bin/python`.
- PostgreSQL container `7e2ce1d310616bcc7fe0c2b0509f38d8ff208d99ca2c2f7dddfb837df474f583`, Redis `ed96a12118c8d9d8e299e8060d690faa046d429e8fb8af34327b1f3f0afdb785`, and Mailpit `8b2276c9258fc6c5dbf3aa141d57eec0e97a5e910af09b67fd12fe4f5c3bb9b3` were running with restart count zero, their accepted images, loopback publications and sole greenfield network. No lifecycle operations were performed.
- Read-only database diagnostics confirmed PostgreSQL 16.15, `sbom_greenfield_uuid`, runtime role `greenfield_app` and sole revision `100_greenfield_uuid_final`. All six private synthetic accounts were ACTIVE, email-verified, unlocked, and matched their stored password hashes (boolean evidence only). Account passwords and hashes were never output. A single deliberately invalid Viewer login later exercises normal rejection without lockout.
- Redis at localhost56381 responded on the broker/session/result/native-rate-limit databases. Session records remain encrypted server-side; browser session values/JWTs are never recorded. Native rate limiting and security-mail delivery readiness were healthy. `/health` and `/ready/iam` returned 200.
- Browser calls use same-origin HTTPS `/api/backend` and the BFF forwards to the HTTP backend server-side. There was no browser mixed-content, CORS or CSRF failure in the successful controlled flows. Secure, HttpOnly, SameSite=Lax, Path=/ cookie metadata was verified without retaining its value.
- The self-signed localhost certificate contains DNS localhost and IP127.0.0.1, valid 2026-10-19 through 2026-11-18. The browser tests explicitly accept this development certificate; this does not install trust in the operator's browser or OS. A manual certificate interstitial must be resolved by trusting the reviewed local development certificate, not by disabling cookie/TLS protections.
- Relevant logs are `~/.sbom-greenfield-uuid/{backend,frontend,worker}.log`; launcher ownership is `.dev-runtime.json` in the checkout. Backend structured completions carry request IDs. The relevant failure was HTTP validation rather than a PostgreSQL/Redis exception; no credential/connection/key mismatch was observed.

## Verification

The first role-browser run completed 11/13 checks. Its two failures were retained: the new logout test targeted `Sign out` instead of the existing `Sign Out` label, and the new access test assumed that ProjectOut exposes `tenant_id` and that a global `/api/products` collection exists. Source review confirmed ProjectOut intentionally omits tenant_id and product listing is `/api/projects/{project_uuid}/products`. The assertions were corrected to those actual contracts without changing application behavior. A subsequent logout run returned 200 and started its redirect but exceeded the page-navigation assertion while `/logged-out` compilation was pending; the serial rerun passed. The initial original Olympus journey timed out waiting for application options following a development full reload; its serial rerun passed in 35.0 seconds. These failures are not counted as successful execution.

The focused frontend authentication run initially had 88 PASS/2 FAIL because old invalid-tenant mocks expected an integer to reach the server. The corrected tests separately cover a valid unauthorized UUID (403 recovery) and a malformed legacy integer (discarded before a request). The next focused auth run passed 90/90; an additional hook regression was then added. The first broad frontend run had 1,770 PASS/7 FAIL, exposing the remaining integer-tenant fixtures in the shared API-header and analysis-stream tests. The first fixture correction had two failures due to reversed tenant:user cache-key expectations; those were corrected to the existing implementation's ordering. A broad rerun launched before that last fixture correction retained the two old compiled assertions (1,775 PASS/2 FAIL); the corrected four-file focused run subsequently passed all 46. A final broad run is taken from the settled source with no edits during execution. All failure logs remain private evidence.

Backend Native IAM foundation/phase2–phase5: **219 PASS, 0 FAIL, 0 SKIP**, 547.43 seconds; two warnings. This uses real PostgreSQL on the task-owned regression database. The original Olympus browser journey: **1 PASS**, real login/upload/components/analysis-results, 36.8-second run including startup. TypeScript and focused ESLint returned exit 0.

**Final full frontend suite: 1,777 PASS / 0 FAIL / 0 SKIP across 198 files**, exit 0, 153.13 seconds. It ran after the source settled, with no source edits during execution. jsdom emits existing pseudo-element/navigation-not-implemented warnings; these are recorded, not counted as browser failures. The final clean browser results are appended below.

## Reproduce manually

1. Run `python3 scripts/dev.py start` from `/Users/ferozebasha/sbom` if the instance is stopped; `python3 scripts/dev.py status` reports the installed UUID environment. Leave a running instance alone rather than launching another server.
2. Open **https://localhost:13000/**. Accept/trust only the known local development certificate if the browser prompts. The native **Welcome back** form is expected; HCL/Entra are disabled in this environment.
3. Use the `admin` entry from the private local `~/.sbom-greenfield-uuid/users.json`. Its email is `admin@olympus.example.test`; inspect the password locally in an editor. Do not paste credentials into chat or use a guessed default password. The other role entries use their separately generated credentials.
4. Click **Sign in**. If **Select tenant** appears, choose **Olympus — Tenant Admin**; the screen is a successful intermediate step, not a login rejection.
5. Confirm Dashboard; refresh the page and confirm it remains authenticated. Open Projects → Olympus Release → Olympus Gateway; open SBOMs, Components List and Analysis Runs on an available SBOM.
6. Use the account menu → **Sign Out**. Protected pages must then require sign-in. Expired Native sessions require reauthentication rather than a fabricated OIDC refresh.

If an already open browser tab retains old compiled code, reload it once to load this correction. Manual localStorage/sessionStorage deletion is not required for the reproduced legacy integer case after the corrected source loads.

## Preservation and limitations

Only synthetic test sessions were expired in Redis (one test's exact hashed session key, with an expiry); no global session flush occurred. Normal logins/logout/audit entries and the original journey's labeled SBOM fixture are expected test effects. Application business records were preserved. Backend regressions use the existing task-owned regression database, never the running application's business database. No protected A/B/D/E/F resource, old W25 executor, Git commit/push or production deployment was used.

Private sanitized evidence is under `~/.sbom-greenfield-uuid/login-diagnostic/` (0700), with private 0600 evidence files. The initial fresh/stale before/after observations, backend correlation and runtime metadata are retained there. Earlier development failures are preserved in separate logs. A read-only diagnostic initially hit the ORM's raw-SQL prohibition; it was corrected to use an explicit read-only operator connection without weakening that guard. A temporary inspection helper confused browser Fetch `Response.status` with Playwright's method; this helper failure is not runtime acceptance evidence.

### Commands and execution scope

```sh
python3 scripts/dev.py status
# Read-only service health: /health and /ready/iam; fixed greenfield metadata only.
.venv/bin/python -B -m scripts.greenfield_regression tests/test_native_iam_foundation.py tests/test_native_iam_phase2.py tests/test_native_iam_phase3.py tests/test_native_iam_phase4.py tests/test_native_iam_phase5.py
cd frontend
# Use the available compatible Node binary; this host used the Codex bundled Node.
node node_modules/vitest/vitest.mjs run --maxWorkers=1
node node_modules/typescript/bin/tsc --noEmit
node node_modules/eslint/bin/eslint.js src/lib/auth.ts src/lib/auth.tenantCookie.test.ts src/hooks/useAuth.test.tsx src/lib/api.tenantHeader.test.ts src/hooks/analysis-stream-sync.test.tsx e2e/greenfield-login.spec.ts e2e/greenfield-login.config.ts
cd e2e
node node_modules/@playwright/test/cli.js test --config greenfield-login.config.ts
node node_modules/@playwright/test/cli.js test --config greenfield.config.ts
```

The private diagnostic helper reads only the fixed greenfield environment and reports booleans for credential validity. It was not added as an application feature or reusable general database probe. Docker inspection/log classification used the explicit local Unix socket and only the three recorded greenfield containers. The inspected PostgreSQL log tail had no password-authentication failures/FATALs; eight integrity constraint errors were classified (four unique, three CHECK, one FK) during the concurrently running negative regression tests. These are not attributed to login. Redis logs showed no errors in that inspected tail. No unrestricted container log content is included in this report.

### Final real browser results

**13 PASS / 0 FAIL / 0 SKIP**, 2.4 minutes, one Playwright worker and no automatic retries (`browser-final.log`).

| Scenario | Actual result |
|---|---|
| Olympus Admin | Native login 200; explicit Olympus selection; Dashboard; refresh retained tenant/session |
| Olympus Analyst | Native login 200; SECURITY_ANALYST role and Olympus context; Dashboard and refresh |
| Olympus Developer | Native login 200; DEVELOPER role and Olympus context; Dashboard and refresh |
| Olympus Viewer | Native login 200; VIEWER role; Dashboard/refresh; project mutation refused 403 and create control absent |
| Foreign tenant user | Native login 200 in Isolation Control; Olympus-scoped project request refused 403 |
| Platform user | Native login 200; platform authority; no implicit tenant; Platform Dashboard and refresh |
| Invalid password / nonexistent user | One controlled attempt each; both 401 with identical generic response; no session cookie |
| Legacy integer and malformed stored tenants | Three real browser variants recovered to authorized Olympus Dashboard |
| Logout | Actual account-menu Sign Out; BFF 200; session cookie removed; signed-out page; direct protected route returned to sign-in; backend proxy refused 401 |
| Session expiry | Only the test's own Redis session expired; refresh required native reauthentication; no fallback provider or refresh credential invented |
| Initial resource access | Projects → Olympus Release → Olympus Gateway; UUID project/product IDs and project relationship; SBOM listing |
| Original Olympus journey | Separate PASS; actual upload 202, UUID SBOM ID, component display, analysis stream 200 and persisted analysis run |

Browser page-error collectors were empty for the successful final scenarios. Navigation cancellation can appear as `net::ERR_ABORTED` in request-failure metadata when a page is intentionally left; this is kept separately from page exceptions and assertions. Self-signed TLS trust in an arbitrary manually operated browser remains a local prerequisite, not a successful OS trust-installation claim. Live external HCL/Entra authentication is disabled/unconfigured and was not tested; Native Login is the supported flow tested here.

### Source and review checks

TypeScript `tsc --noEmit`: exit 0. Focused ESLint across changed auth/helpers/fixtures and new browser sources: exit 0. `git diff --check`: passed. The direct tenant-helper/AuthProvider/header/stream-focused rerun passed **46/46** after the fixture correction. Repository branch and HEAD remain `feat/native-user-management` / `2f48ff835d9e692fc84b31aaa951aad2495888ac`. Existing dirty changes were retained. The private diagnostic directory was scanned in memory for the actual six synthetic account password values: no occurrences found in its evidence/artifacts. No password digest or password value is part of that evidence.

### Final disposition

**GREENFIELD_LOGIN_FIXED_AND_BROWSER_VERIFIED**. All 13 dedicated browser scenarios, the separate original Olympus journey, 219 backend Native IAM cases and all 1,777 frontend tests passed. TypeScript, focused ESLint and whitespace checks passed. The installed frontend source hash matches the corrected repository helper. API, IAM, frontend, worker and the same three data-service containers remain running. No unresolved failure remains in the reproduced stale-tenant login path. OS/browser trust for the self-signed certificate and unconfigured external OIDC providers remain explicit environment limitations.

Evidence: `browser-final.log`, `original-olympus-serial.log`, `backend-regressions.log`, `frontend-frozen-source-final.log`, `tenant-fixtures-corrected-final.log`, `typecheck-final.log`, `lint-final.log`, `initial-browser.json`, `stale-numeric-tenant-before.json`, `stale-numeric-tenant-after.json`, `correlated-backend.json`, `runtime-check.json`, `live-source-correlation.json` and `preservation-final.json`, all under the private diagnostic directory. `acceptance-summary.json` records nonsecret final totals and evidence/source hashes.
