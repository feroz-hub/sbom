# Integer display-ID validation

Date: 2026-10-23. This report records execution for this task, separately from the earlier UUID delivery baseline. Source hashes and the complete local implementation patch accompany this report under `evidence/`.

## Final validation

| Check | Actual result |
|---|---|
| Full frontend Vitest | **1,838 PASS, 0 FAIL, 0 SKIP; 203 test files** |
| TypeScript `tsc --noEmit` | PASS |
| Next.js Webpack production build | PASS; isolated build directory, one build worker |
| Full frontend ESLint | PASS: 0 errors, 52 existing warnings |
| Ruff `check app tests` | PASS |
| Focused formatting | 5 changed Python files PASS; unrelated pre-existing formatting in report_rendering.py retained |
| Python AST and compilation | PASS for changed Python source/tests; compiled files outside repository |
| UUID selector/HTTP URL AST preservation | 48 frontend implementation files PASS; one added numeric-label href uses the existing SBOM UUID |
| Model/schema and revisions 100/101/102 preservation | 7 selected authoritative files byte-identical to HEAD |
| Historical unrelated untracked files | 1,977 exact byte/mode/size comparisons PASS |
| OpenAPI from task-owned FastAPI | 27 response schemas with read-only integer display siblings; UUID selectors preserved; no AuthContextUser display key |
| Focused backend projection/report/real-PK regression | 82 PASS, 0 FAIL/ERROR/SKIP |
| Real Chrome | **6 scenarios PASS**, TLS verification enabled |
| Full backend inventory, reconciled | **4,633 unique cases: 4,624 PASS / 9 SKIP / 0 remaining FAIL / 0 remaining ERROR; plus 12 passing subtests** |
| Isolated AI load cases | **2 PASS** on final source; original timing limits unchanged |
| Gitleaks 8.30.1 | **PASS: 93 exact reviewed files, 0 final findings**; embedded default rules, inline allow comments ignored. Five earlier source-hash metadata false positives individually verified and explicitly labeled; no credential or detection-rule suppression |

The OpenAPI request and all runtime browser/API calls target only the new disposable environment. The historical populated revision 101 is not newly measured by this task.

## Browser coverage

1. Admin creates task-only project/application, checks numeric labels, uploads a synthetic CycloneDX SBOM, verifies numeric SBOM-label navigation uses the UUID, and checks the related Latest SBOM label. Analyst runs real analysis through the application SSE path, verifies findings, persisted numeric Run heading/history, refresh, comparison and UUID responses. A foreign tenant receives 404; integer/misformatted selectors receive 422.
2. Viewer Native Login, UUID auth context, refresh, logout, protected-route refusal, repeat login stability and user-discovery denial.
3. Tenant Admin actual Users & Access find/add/change roles/remove workflow on the task-only candidate.
4. Platform Admin purpose-limited candidate search, actual grant/revoke UI and immediate permission revocation on the task-only candidate.
5. Admin malformed/integer user selectors, foreign membership concealment and safe UUID validation-error projection.
6. Chrome 390×844 mobile emulation checks numeric Application/SBOM labels, UUID hrefs and Tenant Admin denial of platform authority.

The provider service was the local Postman OSV HTTP simulation. These results establish actual application, PostgreSQL, BFF/session, browser, identity projection and UI behavior; they do not establish live vulnerability-provider/HCL.CS/Entra acceptance. Mobile emulation is not physical-device or VoiceOver acceptance.

## Isolation and commands

The operator explicitly allowed creation/population of a new disposable test database. The task uses new `sbom_ui_integer_display_*_test_20261023` databases only. Existing populated/historical databases and original accounts are not queried or changed. Actual schema102 fixtures are installed using unchanged existing sources, not a new migration. API/UI/Redis use task ports 18500/13500/56393, and OSV simulation uses 19401. Only the task API/UI were stopped after browser verification.

Protected private runners bind the otherwise unused broker port 63392, use explicit newly owned database URLs supplied in memory, and load the existing `tests.resource_uuid_routing_guard` before collection and tests. Celery database broker is disabled. Broker/result/cache endpoints cannot reach the original worker. AI Redis tests use task Redis DB7, separate from browser session/rate-limit DBs. No credential-bearing command arguments, cookies, traces, `.env` files or raw private XML/logs are published.

Commands executed (database/environment setup is provided by the protected task runner, not ambient root `.env`):

```text
.venv/bin/python -B <protected-task-runner> tests -o addopts= --deselect=<two unchanged AI load nodes> --junitxml=<private-file>
node frontend/node_modules/vitest/vitest.mjs run --maxWorkers=1 --no-file-parallelism --reporter=json --outputFile=<private-file>
node frontend/node_modules/typescript/bin/tsc --noEmit
node frontend/node_modules/eslint/bin/eslint.js .
node frontend/node_modules/next/dist/bin/next build --webpack
ruff check app tests
ruff format --check <five changed Python files>
git -c core.fsmonitor=false diff --check
gitleaks dir <protected reviewed-file copy> --redact --report-format json
```

The build uses an isolated source copy, a 2 GiB Node heap and `CIRCLE_NODE_TOTAL=2`, which selects one worker in installed Next.js. Existing services are never restarted by these commands. Browser harnesses launch installed Chrome with `ignoreHTTPSErrors:false`; no unsafe Chrome flags or curl `-k` are used.

## Earlier development results retained

| Run | Observed result and disposition |
|---|---|
| First synthetic HTTP tests | 20 PASS / 11 FAIL: test app fixture lacked the included-router request stack; corrected fixture, then 31 PASS |
| First frontend suite | 1,816 PASS / 16 FAIL: stale UUID assertions/missing display fixtures; corrected persisted-number fixtures and labels |
| Frontend targeted follow-ups | 108 PASS / 2 FAIL, then 21 PASS / 1 FAIL; fixed fixture labels/duplicate display keys; subsequent 27 PASS |
| First PostgreSQL focused run | 85 PASS / 7 ERROR during PostgreSQL recovery; no automatic container restart or cleanup |
| Second PostgreSQL focused run | 59 PASS / 1 FAIL: new AnalysisRun fixture omitted required timestamp; corrected fixture |
| Final broad-run legacy snapshots | Four FAIL: intended five top-level display siblings plus a nested SBOM sibling were absent from golden expectations. A separate database reproduction confirmed the exact mismatch. Updated tests derive all new values independently from persisted keys; original golden JSON and all old UUID/business assertions remain unchanged. All five affected-module cases then PASS |
| First broad backend attempt (interrupted) | 268 PASS / 2 FAIL: warm-cache timing exceeded its unchanged 5-second limit; operational AI strict envelope received an unwanted display sibling |
| Component Advisor context expectation | One FAIL reproduced: three intended context display siblings. The exact expected dictionary now checks all UUID references plus the fixture rows’ real PKs; complete module rerun: 29 PASS |
| Upgrade-fixture database guard | Original IAM migration fixture rejected the new task database before DDL. Retained the three historical exact names and added only the two explicitly owned new upgrade names. Reproduction: 1 setup ERROR; complete IAM/resource migration rerun: 7 PASS. No populated/historical database used |
| Batch-serialization expectation | One FAIL reproduced: authorized repeated Project rows gained their intended display field. Exact expected rows now include the independently persisted PK, and both one-query/two-query tests also assert all actual display IDs. Full module: 5 PASS, native-document/error/tenant assertions retained |
| Optional backup client mismatch | Native macOS PostgreSQL 18.2 dump/restore failed against 16.15: sanitized diagnostic confirmed unrecognized `transaction_timeout`. Matching PostgreSQL 16 clients passed the unchanged backup/restore test on synthetic task-only data. Both failed attempts retained; no Docker lifecycle change or populated-data dump |
| Optional live lifecycle | Explicit opt-in executed successfully against endoflife.date with disposable fixtures; not mocked-provider acceptance |
| Production analysis snapshot | One FAIL reproduced: four intended display siblings. Independent Run/SBOM PK and UUID relationship checks added; original golden snapshot unchanged. Full production-analysis module: 3 PASS |
| Operational envelope correction | Display projection excludes the existing operational `/api/v1/runs/` and `/api/v1/scans/` envelopes; dedicated regression preserves their exact payloads. No worker/SSE identity or test assertion is weakened |
| Earlier broad backend continuation (interrupted for report-preview source completion) | 733 PASS / 4 SKIP, 0 FAIL/ERROR before interruption; not full-suite acceptance |
| Earlier frontend run under resource pressure | 1,819 PASS / 14 FAIL: timing failures and missing badge display forwarding; fixed forwarding and reran sequentially |
| Later successful frontend checkpoints | 1,833, then 1,834, then 1,837 PASS on their respective source checkpoints; final current source has 1,838 PASS |
| First production build | Controlled stop (exit 143) to reduce machine load; later two complete production builds PASS |
| Browser development attempts | Five incomplete/failed desktop workflows retained: Run heading timeout; recovery-time 503; response timeout; foreign sign-in navigation timeout; Upload-control timeout after viewport transitions. These are not counted as passes |
| Final browser rerun | Six scenarios above PASS; mobile viewport tested in its own fresh context |

PostgreSQL's original container start timestamp remained unchanged; `OOMKilled=false`. A server child exited and PostgreSQL performed recovery during the earlier run. The cause was not established; timing/resource pressure alone does not prove OOM. No Docker lifecycle repair was performed.

## Acceptance limits

The broad execution actually ended **4,606 PASS / 11 SKIP / 7 FAIL / 7 ERROR**, with 2 load cases deselected and 12 passing subtests, in 2:02:38. It is **not** described as a green monolithic run. The seven failures were exact response expectations for the intended display fields; seven setup errors came from the historical upgrade-fixture database whitelist. All are preserved privately and summarized above.

The complete corrected-module executions replace 49 original case outcomes. Only five test-source files changed after the broad run began; all application/common runtime source remained unchanged, as did 1,499 other frozen files. The changed shared upgrade fixture and its executed importing resource-migration module both passed their rerun. Two opt-in historical startup tests also import that fixture but remain explicit SKIP, without executing it. Original test signatures/decorators and all five golden JSON files are unchanged. This is a reconciled execution on equivalent final application source, not a single green command.

| Accepted disjoint segment | PASS | SKIP |
|---|---:|---:|
| Unchanged main cases, excluding replaced modules and two subsequently executed opt-ins | 4,571 | 9 |
| Complete corrected modules: 5 + 29 + 7 + 5 + 3 cases | 49 | 0 |
| Explicit opt-ins: live lifecycle and synthetic backup/restore | 2 | 0 |
| Isolated AI load cases | 2 | 0 |
| **Total unique inventory** | **4,624** | **9** |

Additional passing subtests: **12**, counted separately. `evidence/test-results-summary.json` binds the exact collected inventory and protected execution artifacts by SHA256. The union covers all 4,633 original case identities exactly once; no case-ID normalization or assertion-result rewriting was performed.

Sensitive Tenant/IAM User/Membership/Grant numeric display exceptions remain documented in SECURITY_REVIEW. Staging, live OIDC providers, physical accessibility/device testing and release/UAT sign-off are not claimed.

## Nine remaining explicit skips

- `tests/ai/test_real_provider_smoke.py::test_real_anthropic_test_connection`
- `tests/ai/test_real_provider_smoke.py::test_real_gemini_free_tier_test_connection`
- `tests/ai/test_real_provider_smoke.py::test_real_grok_free_tier_test_connection`
- `tests/ai/test_real_provider_smoke.py::test_real_openai_test_connection`
- `tests/test_greenfield_startup_postgresql.py::test_real_confirmed_startup_encrypts_and_restores_backup_then_commits101`
- `tests/test_greenfield_startup_postgresql.py::test_real_precommit_failure_keeps100_and_retains_claim`
- `tests/test_native_greenfield_empty.py::test_empty_database_to_native_population`
- `tests/test_native_http_acceptance.py::test_actual_http_expiry_denies_mutation`
- `tests/test_native_http_acceptance.py::test_two_actual_bffs_logout_recovery_and_security_revocation`

Four cases require external AI credentials; two require separately enabled historical startup/backup cutover acceptance; one requires explicit empty-database/Mailpit acceptance; two require the opt-in dual-BFF HTTP lifecycle environment. These are SKIP, not PASS. The live lifecycle provider and backup/restore cases initially skipped in the clean main environment were subsequently actually executed and passed, so their skips are replaced by those real results. No original test was disabled or deleted.

Task-owned API18500/UI13500 were stopped after browser verification; task Redis56393 and OSV simulation19401 were stopped after final tests. New disposable databases and protected raw evidence remain for independent review. No original service was targeted.

Protected raw evidence remains outside the repository. The local locator `~/.sbom-public-resource-uuid/ui-display-current.private.json` identifies its exact task directory. Raw XML/logs, dump files, credentials, session state and key material are not selected for publication.

## Final original-environment observation

A final non-SQL metadata check found no listener on original API port 18000 and no longer found its previously observed launcher process; original UI13000 remained running. The cause/operator activity was not established. No task command targeted that launcher/API/UI, and no repair or restart was attempted. This is an observation requiring independent original-environment follow-up, not a claim of preserved global uptime. The existing PostgreSQL container remained healthy with the same 2026-10-21 start timestamp. All feature/browser acceptance above used the separate task stack.
