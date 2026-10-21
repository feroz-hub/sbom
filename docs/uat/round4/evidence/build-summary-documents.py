"""Create reports from observed Round 4 artifacts, not historical inferred outcomes."""
from pathlib import Path
from collections import Counter
import datetime,json
D=Path(__file__).resolve().parent; O=D.parent
r=json.loads((O/'ROUND4_TEST_RESULTS.json').read_text()); m=json.loads((D/r['frozenRun']['manifest'].split('/')[-1]).read_text())
v=json.loads((D/'validation-results.json').read_text()) if (D/'validation-results.json').exists() else {'status':'NOT RUN','checks':[]}
manifest_link=r['frozenRun']['manifest']; log_link=r['frozenRun']['log']; xml_link=r['frozenRun']['xml']
files=json.loads((D/'round4-source-files.json').read_text()); c=r['frozenRun']['counts']
ready=r['status']=='ROUND4_BACKEND_REGRESSION_COMPLETED'
status='ROUND4_BACKEND_REGRESSION_COMPLETED' if ready else 'ROUND4_BACKEND_REGRESSION_PARTIALLY_COMPLETED'
failed=[t for t in r['tests'] if t['outcome'] in ('FAIL','ERROR','XPASS')]; skipped=[t for t in r['tests'] if t['outcome'] in ('SKIP','XFAIL')]
text=f'''# Round 4 backend regression report

`{status}`

Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}. Full application UAT and production sign-off: **WITHHELD**. Backend qualification: **{r['backendAcceptanceQualification']}**; skipped acceptance gates are not implicitly accepted.

## Current result

| Execution | Actual result | Qualification |
|---|---|---|
| Original 485-case UAT | 454 PASS / 12 FAIL / 11 BLOCKED / 8 NOT RUN | Historical execution, unchanged |
| 346 previously unexecuted backend nodes | 346 PASS; 0 FAIL/ERROR/SKIP; 8 additional passing subtests | Exact selection, 428.08s pytest runtime; unchanged source during this run |
| 228 originally unresolved backend nodes | 228 PASS in focused retests | Per-node evidence; overlapping selections are not summed |
| First complete frozen run | 4,383 PASS / 1 FAIL / 8 SKIP / 0 ERROR or XFAIL | 5,518.60s; unchanged source; all original 228 PASS; preserved independently |
| Final frozen backend run | {json.dumps(c)}; subtests {json.dumps(r['frozenRun']['subtestOutcomes'])} | {m.get('status')}; {r['frozenRun']['collected']} collected; no marker exclusions |
| Final frontend and static checks | {v.get('status')} | Separate current-source checks, detailed below |
| Live six-account API safeguards | 7 PASS | Six login/context/session/audit-logout checks and Olympus four-member directory |

The original 4,368-node observations came from mixed diagnostic runs. Collection preservation independently confirms all original nodes remain represented, with the three identically redacted historical database-safety selectors compared by multiplicity. The current collection contains 4,392 nodes, including 24 new regression cases. No old PASS totals are combined with new outcomes. Subtests are reported separately from collected nodes. One dynamic datetime parameter is normalized explicitly; every other original selector remains traceable, including the changed invalid-integer expectation from HTTP 400 to the intended UUID validation HTTP 422.

## Source and environment provenance

Branch: `feat/native-user-management`; base HEAD: `{m.get('head')}`. The existing dirty worktree is preserved. Round 4 is uncommitted; there was no push, merge or deployment.

The complete run command is recorded verbatim in [the manifest]({manifest_link}). It invokes pytest against `tests -o addopts= --durations=25`, removing default integration/benchmark marker exclusions. The manifest records every source hash before and after. Source unchanged during complete run: **{m.get('sourceUnchangedDuringRun','PENDING')}**. Complete runtime: **{m.get('runtimeSeconds','PENDING')} seconds**. Exit code: **{m.get('exitCode','PENDING')}**.

All schema-reset tests target new task-owned PostgreSQL databases. The final acceptance database is `sbom_greenfield_uuid_round4_acceptance2_test_20261020`; the first attempt used `sbom_greenfield_uuid_round4_acceptance_test_20261020`. Each has its own lock; concurrent test processes cannot share either database. Historical migration tests use independently owned random databases and unchanged migration sources for the precise historical transition under test. No populated application database was migrated, truncated or recreated. Redis integration uses a task-owned ephemeral loopback server. Backup/restore is explicitly opted in against disposable databases.

## Reproduction

The exact executed command and opt-ins are in the final frozen manifest; it invoked `PYTHONPATH=. .venv/bin/python docs/uat/round4/evidence/run-frozen-acceptance-attempt2.py`, which selected all `tests` with `-o addopts=`. The wrapper refuses to overwrite its existing manifest. For a new independent execution, first copy the harness/plugin into a new evidence location and give its database, lock, telemetry files and manifest distinct task-owned names. Do not invoke the preserved child runner directly: its telemetry filename belongs to this completed evidence. Start a fresh task-owned Redis and update only the new runner's private connection reference. Redis was deliberately shut down after acceptance. Never point schema-reset fixtures at the main application database. Private setup credentials are loaded in memory; no connection string is printed. Source hashes, commands, complete collection and all outcomes are retained for reproduction.

## Confirmed technical defects and corrections

| Finding | Before | Correction | Observed focused evidence |
|---|---|---|---|
| Public identity response translation N+1 | 12 distinct references issued 12 scoped SQL queries; unchanged Advisor benchmark timed out at 300s | Collect exact identity fields, resolve in scoped chunks of 500, then perform the existing translation with request-local cache | 5 new tests pass; 12 references use one query, 501 use two; missing and foreign references fail closed; benchmark passes |
| Finding-count reconciliation CLI lacked owner context | Real CLI and original test raised `TenantContextRequired` | Discover active owners through existing maintenance authorization and bind each owner explicitly; preserve rollback, dry-run and audit | Existing 4 tests and 6 new scope/rollback/idempotency tests pass |
| Fresh Greenfield marker width differed from installation contract | Newly created Alembic marker used varchar(64), existing test required 128 | Future fresh creation uses varchar(128) | Current contract test passes on a new test database; no live schema change |

Benchmark scale and thresholds were preserved: 100 SBOMs, 20,000 component occurrences, 4,908 unique versions, 5,930 findings, separate noise tenant. Focused benchmark: cold 2.68s, warm summary p95 1.101s and components p95 0.855s, within existing 2s/3s limits. Benchmark execution was 93.61s. The prior timeout and initial failed fixture attempts remain in evidence.

Most prior failures were obsolete public-integer API fixtures; only wire identifiers and response assertions were corrected to actual persisted UUIDv4 values. Internal integer primary/foreign keys, service/job identifiers, authorization, conflict and foreign-tenant assertions remain. Historical migration tests now run on their intended historical ranges rather than attempting forbidden downgrade of revision 100. Global-directory HTTP denial is explicitly asserted under the existing V5 policy; projection matching remains direct-handler unit coverage. No policy change is implied by those unit tests.

## First full-run correction

The first complete frozen attempt is preserved separately: 4,383 PASS, 1 FAIL, 8 SKIP and 12 passing subtests; source unchanged during 5,518.60 seconds. It discovered one incorrect logging-test expectation: the test assumed the final log entry was the HTTP completion event, but installed Starlette uses `httpx2`, which logs a transport line afterward. Actual HTTP 413, correlation headers and the structured 413 event were present. The isolated reproduction and event metadata are in `evidence/logging-failure-classification.json` and `pytest-logging-isolated-before.xml`. The test correction selects the exact completion event and strengthens count/status/method/path/correlation assertions, without changing application logging or permissions. The entire logging module passed after the correction: 27 PASS in 22.42s (`pytest-logging-isolated-after.xml`). The final complete run follows this correction; its outcomes are not merged with attempt 1.

## Exact failures and limitations

'''
if failed:
 text+='| Current node | Outcome | Evidence |\n|---|---|---|\n'+''.join(f"| `{t['evidenceNode']}` | {t['outcome']} | {log_link} / {xml_link} |\n" for t in failed)
else:text+='No failing outcome has been observed in the frozen run'+('.\n' if m.get('status')=='FINISHED' else ' **so far**; the run is incomplete.\n')
text+='\n### Actual skipped or expected-failure nodes\n\n'
if skipped:
 text+='| Node | Outcome | Reason |\n|---|---|---|\n'+''.join(f"| `{t['evidenceNode']}` | {t['outcome']} | {str(t.get('reason')).replace('|','/')} |\n" for t in skipped)
else:text+='No skip has been observed yet. This does not establish external integration coverage.\n'
text+='''
Four hosted-provider integrations require external credentials, which were not activated. Existing empty-population and BFF HTTP opt-ins require their declared topology and supported platform-account setup; this run does not invent those prerequisites. Real local Redis and backup/restore checks are enabled. In the first frozen attempt, the free live lifecycle-provider opt-in was omitted from its harness; its runtime SKIP is a harness configuration limitation, not evidence of provider failure or unavailability. The separate current-source preflight passed (1 PASS, 4.50s; `pytest-live-lifecycle-preflight.xml`). The second frozen run enabled the flag and the live lifecycle case passed in the full final population. The first-run SKIP remains historical; its focused preflight and final frozen outcome are separate actual executions. No test is excluded by a pytest marker. Exact observed skip reasons and nodes are recorded above when executed.

SBO-73 remains Decision Needed. Platform account-status management, idle-expiry policy and cryptographic signature verification have no new approval. Ubuntu/staging, CI and full browser E2E release gates were not executed in Round 4. Local API/TestClient evidence does not replace those gates. The long-running live API process was not restarted to load the new serializer; its authentication safeguard checks do not claim live verification of that new code. Current-code integration verification uses isolated PostgreSQL and FastAPI.

### Final validation checks

| Check | Result | Runtime seconds | Evidence |
|---|---|---:|---|
'''
for x in v['checks']:text+=f"| {x['name']} | {x['outcome']} | {x.get('runtimeSeconds','')} | {x.get('log','')} |\n"
if not v['checks']:text+='| Full Vitest, TypeScript, Ruff, ESLint, production build | NOT RUN | | Scheduled after backend run to limit host memory pressure |\n'
text+='''
## Previous remediation protection

The full inventory includes VEX serialization, stale-version concurrency, role restrictions and tenant isolation; Dashboard UUID hierarchy; Advisor history; KEV authorization; Native IAM/Users & Access; repair candidate-byte integrity; CUSTOM cron; session HTTP 503 recovery; and legacy analysis UUID boundaries. Their actual individual outcomes are in [the complete register](ROUND4_TEST_RESULTS.json) and [the protection register](evidence/prior-round-protection-register.json). Frontend-specific behavior is covered by the completed full current Vitest run: 1,805 PASS across 199 files, including Dashboard UUID filters, popup interaction, provider-neutral wording and HTTP 503 session recovery. TypeScript, Ruff, production build and full frontend ESLint passed; ESLint scanned 628 files with zero errors and 52 warnings. Source hashes remained unchanged from the backend run through final validation. No inferred PASS is assigned to an unobserved node.

The seven live API safeguard checks show all six seed identities authenticate with the expected roles, platform has no inherited tenant, and Olympus has the four expected active, verified members. Admin requires explicit tenant selection in the current multi-membership state; the harness now selects the authorized Olympus tenant. Native logout audit HTTP 200 is not described as bearer-token revocation. No seed credentials, roles or memberships were changed.

## Evidence, preservation and next gates

All 2,192 protected earlier report/evidence hashes are rechecked in [historical preservation](evidence/historical-preservation.json). Round 4 source changes are isolated from pre-existing dirty changes in [task-only patch](evidence/round4-source.patch) and [file hashes](evidence/round4-source-files.json). The original 485-case baseline is unchanged. Focused attempts, collection failures, timeouts and corrected retests are retained, not overwritten with passing logs.

- [Per-node current outcomes and original 228 reconciliation](ROUND4_TEST_RESULTS.json)
- [Root-cause classification](ROUND4_FAILURE_CLASSIFICATION.md)
- [Full frozen run manifest](evidence/frozen-acceptance-manifest.json), [log](evidence/pytest-full-frozen.log), [JUnit XML](evidence/pytest-full-frozen.xml)
- [Resumable checkpoint](evidence/CHECKPOINT.json)
- [Linear drafts](ROUND4_LINEAR_RESULTS.md)

The task-owned ephemeral Redis instance was shut down after PID/port ownership and no-persistence verification (`evidence/isolated-redis-cleanup.json`). Task-owned PostgreSQL databases remain for reproducibility; no shared service or main application database was removed. Public node metadata uses stable hash labels for three synthetic database-safety URL parameters; exact selectors remain privately in mode0600 task files (`evidence/selector-sanitization.json`).

SBO-54 requires review of the final frozen run plus current frontend/static results. SBO-55 retains its Ubuntu browser/E2E acceptance gate. No Linear status was changed, no duplicate issue was created, and no full application or release sign-off is granted.

## Round 4 changed source files

'''
text+='\n'.join(f"- `{f['path']}` ({f['type']})" for f in files)+'\n'
text=text.replace('](evidence/frozen-acceptance-manifest.json)', ']('+manifest_link+')').replace('](evidence/pytest-full-frozen.log)', ']('+log_link+')').replace('](evidence/pytest-full-frozen.xml)', ']('+xml_link+')')
(O/'ROUND4_BACKEND_REGRESSION_REPORT.md').write_text(text)
linear=f'''# Round 4 proposed Linear updates

Draft only. Existing issues were read; no issue was created, changed or marked Done.

## SBO-54 — backend/frontend regression

Existing issue: https://linear.app/sbom-analyzer/issue/SBO-54/run-full-backendfrontend-regression-against-latest-source-and-classify

Proposed status: retain In Progress pending final evidence/reviewer acceptance. Current checkpoint: `{status}`.

The exact 346 previously unexecuted nodes passed (8 additional passing subtests). All 228 original unresolved nodes passed both focused retests and the final frozen run, with individual original-to-current selectors and root-cause classification. The first complete frozen execution finished with 4,383 PASS, 1 FAIL and 8 SKIP (5,518.60s, unchanged source). Its only failure was a brittle logging assertion; the corrected module passed all 27 cases in 22.42s. The final complete collection remains 4,392 cases, and enables the previously omitted free lifecycle opt-in. Frozen run: **{m.get('status')}**, outcomes **{json.dumps(c)}**, source unchanged **{m.get('sourceUnchangedDuringRun','PENDING')}**. Final frontend/static validation: **{v.get('status')}** — 1,805 Vitest PASS / 199 files; TypeScript, Ruff, production build and full frontend ESLint passed (0 errors, 52 warnings). Twelve passing backend subtests are separate from the 4,392-case denominator. These are distinct executions, not an aggregate green result.

Confirmed fixes: tenant-bound maintenance reconciliation CLI; scoped batched public-ID response serialization (12 queries to one; unchanged 20,000-occurrence benchmark passes); fresh-install Alembic marker width. Obsolete wire integer fixtures now use persisted UUIDv4 values, internal keys remain integers, and historical migration cases use fresh transition-specific databases. Five directory cases assert actual existing V5 HTTP 403 and preserve matching/projection unit coverage; no authorization catalogue or SBO-73 policy change.

Attach: `docs/uat/round4/ROUND4_BACKEND_REGRESSION_REPORT.md`, `ROUND4_FAILURE_CLASSIFICATION.md`, `ROUND4_TEST_RESULTS.json`, frozen manifest/log/XML, task-only patch and source hashes. Preserve initial failed attempts and benchmark timeout. Review exact final skip reasons; no paid-provider credentials were activated. No commit, push or deployment was performed.

## SBO-55 — Ubuntu browser/E2E acceptance

Existing issue: https://linear.app/sbom-analyzer/issue/SBO-55/build-and-execute-full-browser-e2e-acceptance-on-isolated-ubuntu-test

Proposed status: retain In Progress. Round 4 provides backend/PostgreSQL regressions and seven local live API safeguards, not the required full isolated Ubuntu Playwright/Next/FastAPI/Redis/Celery A–I acceptance. Frontend production build and unit tests do not substitute for browser execution. Next action: run existing acceptance scenarios on the authorized Ubuntu environment, record source version/configuration and attach browser/API/worker evidence. Reuse this issue; do not create a duplicate.

## Preserved decisions and release gate

SBO-73 remains Decision Needed. No approval is inferred for global IAM discovery changes, seeded privilege elevation, idle-expiry policy or cryptographic signature verification. Existing SBO-70–76 remediation evidence is preserved; no tracker status is changed. Full application UAT/production sign-off remains withheld pending required target-environment evidence and accepted policy/external exceptions.
'''
(O/'ROUND4_LINEAR_RESULTS.md').write_text(linear)
print(status,'summary documents updated')
