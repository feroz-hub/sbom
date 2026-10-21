"""Render the master UAT report from sanitized execution evidence only."""
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EVIDENCE = ROOT / 'evidence/2026-10-19'
records = {}
for filename in ('cases.json', 'direct-api-cases.json', 'business-api-cases.json', 'extended-cases.json', 'disposable-controls.json', 'workflow-cases.json', 'vendor-cases.json', 'isolated-settings-cases.json', 'final-state-cases.json', 'outstanding-cases.json'):
    source = EVIDENCE / filename
    if source.exists():
        for case in json.loads(source.read_text()):
            records[case['id']] = case
cases = list(records.values())
module_names = {'directory': 'Users & Access', 'audit': 'Users & Access', 'candidates': 'Users & Access', 'platform': 'Platform', 'projects': 'Projects', 'sboms': 'SBOMs', 'dashboard': 'Dashboard', 'vex': 'VEX Investigation', 'kev': 'CISA KEV', 'notifications': 'Notifications'}
for c in cases:
    c['module'] = module_names.get(c['module'], c['module'])
counts = Counter(c['status'] for c in cases)
modules = defaultdict(Counter)
for c in cases:
    modules[c['module']][c['status']] += 1

text = '''# SBOM Analyzer — Full Role-Based UAT Report

Run date: **19 October 2026, Asia/Kolkata**. Sign-off: **WITHHELD**.

This report records current execution, not acceptance claims from earlier runs. Full UAT completion is **not claimed**: the explicit BLOCKED and NOT RUN cases below remain acceptance limits. No application remediation was authorized or performed.

## Environment and safeguards

- Frontend: `https://localhost:13000`; API: `http://127.0.0.1:18000`.
- The running API process was checked: database name `sbom_greenfield_uuid`, database host `127.0.0.1`; SMTP `127.0.0.1:1026`, delivery enabled, security outbox enabled. Mailpit is `http://127.0.0.1:8026`.
- Chrome runs with `ignoreHTTPSErrors=false`. System curl reported TLS verification result 0. Chrome reported TLS 1.3 with the existing mkcert issuer. No trust-store change or TLS bypass was used.
- In-app browser connection was unavailable. Local Playwright with installed Chrome was used instead. Every seeded account receives a separate context, with no saved session state. Credentials are loaded from the private file into memory. No traces, videos, cookie values, bearer tokens, passwords, or activation links are evidence artifacts.
- Existing checkout changes were preserved. UAT scripts, evidence and this report are the only files added by this task. State-changing tests use UAT-created records. The six seeded accounts retain their original roles, memberships, account status, verification and passwords; authentication/session bookkeeping necessarily changes during login/logout.

## Execution summary

'''
text += ', '.join(f'**{counts[s]} {s}**' for s in ('PASS', 'FAIL', 'BLOCKED', 'NOT RUN')) + f'. Total recorded cases: **{len(cases)}**.\n\n'
text += '''The original Admin directory check passed: Olympus Active, current membership Active, four seeded members with correct separate verification, role, membership and account states. Initially the administration-only audit endpoint returned zero records, matching the UI; the general audit endpoint also includes access events and is not the same filter.

## Account and role coverage

| Identity | Implemented role/context | Browser Native Login | Users & Access observation | Refresh | Logout/invalidation |
|---|---|---|---|---|---|
'''
for role, label in [('admin','Olympus Tenant Admin'),('analyst','Olympus Security Analyst'),('developer','Olympus Developer'),('viewer','Olympus Viewer'),('foreign','Isolation Control Tenant Admin'),('platform','Platform Admin; no tenant')]:
    auth = records.get('UAT-AUTH-' + role)
    access = records.get('UAT-USERS-ACCESS-' + role)
    refresh = records.get('UAT-REFRESH-' + role)
    logout = records.get('UAT-LOGOUT-' + role)
    observation = 'NOT RUN'
    if access:
        a = access['actual']
        observation = 'Directory, Add Existing Member, Invite New User' if a.get('read') else 'Access restricted; no member administration controls'
    text += f"| {role}@olympus.example.test | {label} | {auth['status'] if auth else 'NOT RUN'} | {observation} | {refresh['status'] if refresh else 'NOT RUN'} | {logout['status'] if logout else 'NOT RUN'} |\n"
text += '''
The live authorization catalogue is saved in [authorization-matrix.json](evidence/2026-10-19/authorization-matrix.json). API authorization is tested independently of button visibility, through authenticated browser BFF requests and separate direct backend bearer requests. Analyst can create/update projects but cannot create products or administer memberships. Developer and Viewer cannot create projects. Platform login has no inherited tenant; a forged Olympus header is rejected, while supported platform tenant-administration endpoints remain available.

## Module coverage

Page/read smoke results establish rendering and the named API read only. They do not establish every mutation, filter, integration or workflow in the module.

| Module | PASS | FAIL | BLOCKED | NOT RUN |
|---|---:|---:|---:|---:|
'''
for module, values in sorted(modules.items()):
    text += '| ' + module + ' | ' + ' | '.join(str(values[s]) for s in ('PASS','FAIL','BLOCKED','NOT RUN')) + ' |\n'
text += '''
## Confirmed defects and acceptance gaps

| Reference | Severity | Finding |
|---|---|---|
| UAT-DEF-003 | High | VEX detail/mutation/conflict responses fail; a mutation persists despite HTTP 500 |
| UAT-DEF-006 | High | Dashboard hierarchy filters discard public UUID selections |
| UAT-DEF-001 | Medium | Candidate results intercept Cancel |
| UAT-DEF-002 | Medium | Global IAM candidate discovery needs explicit no-enumeration policy disposition |
| UAT-DEF-005 | Medium | Tenant KEV Sync control disagrees with platform authorization |
| UAT-DEF-007 | Medium | Advisor policy history mistakes policy versions for SBOM versions |
| UAT-DEF-004 | Low | Native membership confirmation names HCL.CS |

### UAT-DEF-001 — Medium — Candidate results overlap the Cancel button

Reproduce as Olympus Admin: open Users & Access, Add Existing Member; search `admin@olympus.example.test`; wait for “No eligible users found for this tenant”; click Cancel normally. The floating empty-results panel intercepts the pointer. No API failure accompanies this issue. Escape dismisses the dialog.

Evidence: UAT-USER-014, [screenshot](evidence/2026-10-19/UAT-USER-014-cancel-overlap.png), recorded popup/button bounds and Playwright pointer-interception diagnostics. The same failure was observed in interactive automation and rerun in the script. Source inspection correlates the absolute `top-full z-50` results in `UserSearchCombobox.tsx` with the immediately following footer in `TenantUsersAccess.tsx`; the popup has no collision handling or reserved layout space. This is a frontend layout issue; backend candidate lookup returned 200 with the correct empty result.

Recommended fix: preserve click access to the footer by constraining/repositioning the results panel or reserving space, and verify empty, populated and error results at desktop/mobile sizes. No fix made.

### UAT-DEF-002 — Medium — Global account discovery conflicts with the strict no-enumeration UAT criterion

Reproduce as Isolation Control Admin with no Olympus membership: call own-tenant `/api/tenants/{isolation-control-uuid}/user-candidates?q=olympus`. HTTP 200 returns five matching global IAM accounts: the four Olympus tenant identities and the platform account, including email/display name/account status. Business-resource and Olympus member-directory isolation probes still reject foreign access.

This is an **acceptance-policy gap**: the implemented `tenant:user:invite` policy intentionally allows global eligible IAM account lookup for Add Existing Member. The query excludes current members, inactive and unverified accounts but does not constrain candidates to a tenant relationship. It does not return Olympus membership records. This report does not infer unrestricted cross-tenant business access from candidate discovery.

Evidence: UAT-ISOLATION-GLOBAL-CANDIDATES; `app/routers/tenants.py::search_tenant_user_candidates`; sanitized candidate response and request correlation in [direct API cases](evidence/2026-10-19/direct-api-cases.json).

Recommended disposition: the UAT owner must explicitly accept this global-directory exception, or approve a narrower discovery policy such as exact email lookup with reduced fields or an explicit cross-tenant invitation flow. No policy/source changes made.

### UAT-DEF-003 — High — VEX investigation detail returns HTTP 500

Reproduce as Olympus Admin: upload the UAT CycloneDX fixture, run OSV analysis, read the generated investigation list, then GET `/api/vex/investigations/42`. The list returns 200, but detail repeatedly returns 500; observed correlation IDs include `96f44f3529bf` and `c6605cd1fc81`. The backend log reports `ResponseValidationError`.

A separate diagnostic against the same database used a PostgreSQL READ ONLY transaction and validated the actual `_detail_payload`. It isolated `analyzer_evidence.match_confidence`: the payload contains a float while `AnalyzerEvidenceSection.match_confidence` requires `str | None`. No data/schema/source changes were made during diagnosis. See [validation evidence](evidence/2026-10-19/vex-detail-validation.json) and [read-only diagnostic](diagnose-vex-detail.py).

Impact: users cannot open affected investigation detail; UI decisions and assignment workflows depending on that detail are blocked. Mutation response paths reuse the detail schema and require separate validation before remediation is accepted.

Recommended fix: reconcile the actual confidence value with the intended API type, verify nested detail serialization, and rerun detail, decisions, assignment, concurrency and role authorization on the UUID environment. No fix made.

The complete versioned UAT decision payload also returned 500 **after persisting the decision**: the investigation row version changed from 1 to 3. Retrying the original version returned 500 instead of the expected 409 because the conflict response reused the failing detail serializer. This is one root defect affecting detail, successful mutation responses and conflict responses, not three independent defects. Viewer/non-owner Developer decisions returned 403, and the foreign account received 404 before mutation.

### UAT-DEF-004 — Low — Native membership confirmation names HCL.CS

The disable-membership confirmation for the activated Native UAT account states “Their HCL.CS identity ... will remain unchanged.” This environment has Native authentication enabled and HCL.CS disabled. Reproduce by opening the disposable Native member's action menu and choosing Disable membership. The membership mutation itself passed, preserving the user's account status and assigned role.

Evidence: UAT-MEMBERSHIP-PROVIDER-COPY and [screenshot](evidence/2026-10-19/UAT-native-membership-confirmation.png). The literal provider name is in `frontend/src/components/admin/MembershipConfirmDialogs.tsx`; the remove-member dialog also uses that literal. Recommended fix: provider-neutral identity wording, then verify Native/HCL.CS/Entra presentation without changing mutation behavior. No fix made.

### UAT-DEF-005 — Medium — Tenant Admin KEV Sync control disagrees with platform-only API policy

As Olympus Tenant Admin, the Sync KEV Catalog button is enabled. Clicking it returns 403; the observed UI response specifically reports `IAM_TENANT_SELECTION_REQUIRED`. The frontend gates the control with `tenant:settings:update`, whereas the route policy and handler require current platform authority. A separate direct request with the valid Olympus tenant context is also rejected. The button therefore cannot complete under its displayed tenant authority, regardless of the first rejection layer. Server-side protection works: these requests do not modify the global catalog. Evidence: UAT-KEV-SYNC-UI, request ID `7511a11888d2`, and [screenshot](evidence/2026-10-19/UAT-kev-admin-sync-denied.png).

The independently executed Platform Admin sync used a future cutoff with `prune_stale=false`; it fetched the actual 1748-entry catalog, matched zero rows and upserted zero rows. Tenant-role sync requests were rejected with 403. Recommended fix: gate and locate the global sync operation according to the implemented platform policy; retain server-side enforcement. No fix made.

### UAT-DEF-006 — High — Dashboard hierarchy filters discard UUID selections

As Olympus Admin, select the disposable project in the Dashboard Project filter. The URL changes to `?project=d4828e7c-e71c-40f7-bb6c-dde0f4d48d09`, but the control returns to All projects. The browser does not request the scoped dashboard summary. Refresh does not restore the selection. The direct backend `project_id=<UUID>` metrics request returned one project and the correct isolated SBOM/findings, so the backend scoped API works in the tested case.

Both the checkout and the running development frontend contain `frontend/src/lib/dashboardScopeUrl.ts::positiveId`, which calls `Number(raw)` and only accepts positive integers. Public UUIDs become NaN, so `parseDashboardScope` drops the project and dependent application/SBOM scope. This confirms the repeated reset is a functional UUID migration defect, not a navigation timeout. Evidence: UAT-DASHBOARD-FILTER-UI, UAT-DASHBOARD-FILTER-REFRESH and [browser screenshot](evidence/2026-10-19/UAT-dashboard-filter-incomplete.png).

Impact: users can believe they selected a project while viewing broader tenant metrics; dependent hierarchy filters and refresh/deep-link state cannot be accepted. Recommended fix: use the application's public-ID parser for dashboard URL state and update numeric-ID-only tests; rerun all three hierarchy levels, refresh, drill-down and tenant switching. No fix made.

### UAT-DEF-007 — Medium — Advisor policy version histories return HTTP 500

Reproduce in the UAT-created tenant as its administrator: publish a DISABLED trust, accepted-risk or scoring policy version; GET `/api/component-advisor/policies/{kind}/versions`. Publication succeeds with 201 and stale-version publication returns the correct 409, but each nonempty history returns 500 `Unresolvable public resource reference`. Correlation IDs: `8f7ac6766b8e`, `8c98bc6cca5b`, `4ffa41c1be7c`. The tenant had no SBOM rows that could accidentally satisfy the wrong lookup.

`app/public_api.py` maps every `versions` path segment to `sbom_source`. Its route-entity inference therefore treats a policy version's separate integer ID as an SBOM internal ID when serializing the generic `items` list. The tenant-scoped SBOM lookup fails, generating the observed error. The actual route inference was evaluated separately without database mutation. This also creates a risk of incorrect IDs when an unrelated same-tenant SBOM happens to share that integer; that collision variant was **not executed** and is not a separate confirmed disclosure.

Evidence: UAT-POLICY-HISTORY-trust, UAT-POLICY-HISTORY-accepted-risk, UAT-POLICY-HISTORY-scoring, [correlated backend log](evidence/2026-10-19/policy-history-correlated-log.txt), and [route diagnosis](evidence/2026-10-19/policy-history-diagnosis.json). Recommended fix: give policy histories an explicit identity contract and constrain SBOM version rewriting to SBOM routes/DTOs. Verify empty/nonempty histories, platform/tenant scope and integer collisions. No source fix made.

## Execution constraints and observations

Some initial navigation attempts stalled. A direct API health request timed out after 10 seconds with no bytes, then recovered to HTTP 200 after the browser run ended; later health latency was 0.05 seconds. Host inspection showed about 9 GB of swap in use. This is correlation, not a proven root cause. No application service was restarted. Browser readiness and navigation-wait issues in the test harness were corrected and account cases rerun; unresolved navigation remains BLOCKED rather than being called an application defect or PASS.

ENV-001: the frontend later logged “Server is approaching the used memory threshold, restarting...” contemporaneously with `ERR_EMPTY_RESPONSE`. That confirms a development-server self-restart; no restart was initiated by UAT. Module page reads were rerun after recovery. See [frontend log evidence](evidence/2026-10-19/frontend-memory-restart.txt).

ENV-002: CUSTOM cron is blocked because the optional `croniter` parser is not installed. Both syntactically invalid and valid disabled custom-cron submissions returned the dependency message, so invalid-cron syntax validation is not claimed as PASS. Monthly preset creation, effective resolution, authorization rejection and cleanup passed.

Account suspension/disable tests are BLOCKED because the observed Platform Admin catalogue lacks `platform:user:manage_status`; the correct 403 responses were preserved. No seeded account status was changed to manufacture coverage. Live AI completion is BLOCKED: the effective application feature flag is false, and the configured local Ollama service is reachable but returns an empty installed-model catalogue. The real Copilot API returns 409 `AI_FIXES_DISABLED` for tenant administrators and 403 for the tested lower roles. Hosted providers are unavailable in the runtime catalogue. An empty saved-credential list alone is not treated as proof that a local provider cannot work. OSV findings were produced by a real application run and persisted with source OSV; transport-vs-cache behavior was not separately traced.

One local automation error printed a session-cookie header in tool diagnostics. It is not in the saved report/evidence artifacts. Harness error handling now redacts cookie headers. A scoped cleanup removed this run's retained Admin BFF sessions using session creation times and the Native subject, without changing passwords, roles or account status; [cleanup evidence](evidence/2026-10-19/session-cleanup.json) contains counts only. A fresh real UI logout/replay test subsequently returned 200 before logout, 200 for logout and 401 when replaying the old cookie, with the browser cookie removed. Node API-request certificate verification initially lacked the system CA; it was rerun with Node `--use-system-ca`, never with disabled TLS verification.

The repair quarantine retained its original one-byte malformed JSON while the manual draft was saved, revalidated as `repaired_valid`, and imported as a new public SBOM UUID. Viewer/Developer repair reads are intentionally allowed by their live permissions; draft writes returned 403 and the foreign tenant returned 404. Component Advisor was tested beyond page reads: scoped creation, idempotency, read/decision authorization, invalid acceptance gate, defer, stale-version 409, close and event history passed on a UAT-created recommendation.

The vendor catalogue is a platform-managed global reference resource. Platform create/update/disable and lower-role mutation rejection passed using one unique synthetic vendor/product; the record is disabled at cleanup. Tenant lifecycle readers can search/export this global catalogue. The platform-only seeded user lacks tenant lifecycle-read context, so its tenant export request returned 403 as implemented. This is distinct from isolation of tenant-owned projects, products, SBOMs and investigations.

Settings mutations were isolated to the UAT-created tenant. Trust, accepted-risk and scoring version publication, optimistic conflicts and return to INHERIT passed; their histories exposed UAT-DEF-007. Lifecycle provider override/update validation/reset passed. AI settings save, invalid-budget 400 with rollback, reset and inherited source passed. Olympus effective AI configuration was byte-for-byte unchanged before/after those isolated mutations. The disposable tenant was disabled again in a finally cleanup. The local password-reset flow for its disposable administrator passed generic known/unknown responses, Mailpit delivery, reset consumption, single-use rejection and subsequent authentication; no seeded account password changed.

## Detailed executed cases

Every entry includes preconditions, steps, expected/actual outcome, status, HTTP result, sanitized evidence and any defect reference. HTTP 200 alone is not a blanket functional PASS.

'''
for c in cases:
    text += f"### {c['id']} — {c['status']}\n\n"
    text += f"Module: {c['module']}. Role: {c['role']}. Time (UTC): {c.get('time','not recorded')}.\n\n"
    text += f"Preconditions: {c['preconditions']}\n\nSteps executed: {c['steps']}\n\nExpected: {c['expected']}\n\n"
    text += 'Actual / sanitized evidence:\n\n```json\n' + json.dumps(c['actual'], indent=2, ensure_ascii=False) + '\n```\n\n'
    text += f"API status: {c.get('api') if c.get('api') is not None else 'not applicable / not observed'}. Defect: {c.get('defect') or 'none'}.\n\n"
text += '''## Outstanding coverage and sign-off

The recorded run covers all six seeded identities and every requested module at the levels explicitly described by its cases. It is not an assertion that every module workflow, configuration combination, provider or output format has been accepted. BLOCKED and NOT RUN cases are explicit acceptance limits, not passes.

Sign-off is **WITHHELD**. Seven findings/acceptance gaps need resolution or explicit policy disposition, including two High-severity defects. Positive suspended-account behavior, live AI completion, custom cron and defect-dependent flows remain blocked. Additional unexecuted formats/edge workflows are listed as NOT RUN. No application fixes, deployment or production acceptance are implied.

### Disposable-record cleanup and retained evidence data

- Original four Olympus members were re-read after the UAT membership was removed; original roles, active membership/account state and verification were preserved. Foreign and platform seeded memberships were not altered.
- The UAT invited account remains active with its Olympus and Isolation Control test memberships removed. The seeded platform role cannot disable accounts; that prerequisite is recorded rather than bypassed.
- The UAT tenant is DISABLED; its initial administrator remains a disposable account. AI/lifecycle overrides were removed, and the latest advisor-policy versions are INHERIT.
- Temporary report subscriptions and product analysis schedules were removed. The synthetic vendor record is disabled. The Advisor recommendation is CLOSED.
- UAT business projects, products, SBOM revisions, repaired import, analysis runs and audit records are retained to reproduce findings; their public IDs are in [business fixtures](evidence/2026-10-19/business-fixtures.json). No existing business record was deleted or deactivated. The separate empty recovery-test project remains soft-deleted after its restore test.
- This run's retained Admin BFF sessions were scoped-cleaned. No password, cookie, bearer token, private key or activation/reset URL is stored in the evidence.

## Evidence and reproduction

- [Main browser cases](evidence/2026-10-19/cases.json)
- [Independent direct API cases](evidence/2026-10-19/direct-api-cases.json)
- [Repair and Advisor workflows](evidence/2026-10-19/workflow-cases.json)
- [Isolated settings/password recovery](evidence/2026-10-19/isolated-settings-cases.json)
- [Vendor catalog controls](evidence/2026-10-19/vendor-cases.json)
- [Final state safeguards](evidence/2026-10-19/final-state-cases.json)
- [Blocked and unexecuted acceptance limits](evidence/2026-10-19/outstanding-cases.json)
- [Artifact validation and secret scan](evidence/2026-10-19/artifact-verification.json)
- [Admin directory screenshot](evidence/2026-10-19/UAT-USER-001-admin-directory.png)
- [Browser/API runner](run-role-uat.cjs), using the bundled Node runtime and installed Chrome; phases `users`, `roles`, `invitations`, `security`.
- HTTP metadata artifacts store path, method, status and request ID only. Query strings and request/response credentials are excluded.
'''
(ROOT / 'SBOM_ANALYZER_FULL_UAT_REPORT.md').write_text(text)
print(f'Master report refreshed: {len(cases)} cases; {dict(counts)}')
