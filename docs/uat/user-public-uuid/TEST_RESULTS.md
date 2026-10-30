# IAM User public UUID test results

**Final local implementation regression: PASS.** The complete corrected run collected 4,421 cases: **4,414 PASS, 7 SKIP, zero FAIL/ERROR**, plus 12 passing subtests. All historical failures and interrupted runs below remain separate evidence. This is not populated-database upgrade, staging, full UAT or production sign-off.

| Run | Actual outcome |
|---|---|
| focused-attempt1 | Interrupted after 8 setup errors: test launcher inherited Native-auth enablement incompatible with auth-disabled fixture mode. No application acceptance claimed. |
| focused-attempt2 | **20 PASS**, real PostgreSQL + published FastAPI boundary |
| identity-regression-attempt1 | 114 PASS, 11 FAIL, 3 ERROR. Stale integer HTTP fixtures plus missing explicit synthetic credential scheme in new upgrade fixture. |
| identity-regression-attempt2 | Collection refused: helper was mistakenly called in a parametrization before fixture creation. Corrected the fixture value; failure retained. |
| identity-regression-attempt3 | 70 PASS, 1 FAIL: existing unknown-user error envelope was not retained at the new boundary. |
| platform-error-envelope | **1 PASS** after preserving existing IAM_USER_NOT_FOUND envelope |
| onboarding-regression-attempt1 | 57 PASS, 1 FAIL: initial-administrator not-found code needed its existing distinct envelope |
| missing-user-codes | **2 PASS** after preserving both governance error codes/audits |
| frontend-attempt1 | 1,794 PASS, 11 FAIL; integer initial-admin fixture values no longer meet UUID form contract |
| frontend-focused-attempt2 | 53 PASS, 1 FAIL; remaining grant-call expectation still integer |
| frontend-full-attempt3 | 1,790 PASS, 22 FAIL; analysis cache-scope fixtures and tenant User expectations remained integer-based |
| backend-full-attempt1 | Interrupted: 199 PASS, 1 FAIL. Inherited Celery routing reached the existing worker; see incident below. |
| browser-attempt1 | Six role login/refresh/logout/stability scenarios passed; harness selector failure interrupted membership workflow; not full browser acceptance |
| browser-attempt2 | **8 PASS** in real Chrome, including six-role session stability and tenant membership UI lifecycle |

All 100→101 migration/fresh tests target task-owned disposable databases. Credential/membership preservation, real SQLSTATEs, unique/NOT NULL/v4 checks, immutable identities, concurrency and rollback are exercised. No main Greenfield DDL/backfill occurred.

Commands: `.venv/bin/python -B scripts/iam_uuid_test_environment.py <pytest selections>`; frontend bundled Node runs `node_modules/vitest/vitest.mjs run --maxWorkers=2`; Chrome runner `evidence/iam-browser.cjs` uses only task-owned identities/services. Exact terminal artifacts are under evidence/.

The existing 193-case suite concerns the original six resources. No unexecuted case is counted as a new IAM UUID acceptance result. Full backend/frontend inventories may exceed historical totals as new cases are added. Static/build results will be appended when completed.

## Completed final-source checks

| Check | Actual result | Evidence |
|---|---|---|
| Final affected IAM/provider/upgrade/authorization/PostgreSQL regression | **204 PASS**, zero failures/skips, 258.63 s | full-failure-corrections.xml / log |
| Full frontend Vitest | **1,812 PASS**, 200 files, zero failures, 93.68 s | frontend-full-final.log |
| Installed Chrome, final backend source | **9 PASS**, HTTPS verification enabled | browser-results.json, browser-final3.log |
| Complete model/schema and restricted runtime-role parity | **PASS**, actual disposable PostgreSQL revision 101 | schema-parity.json |
| TypeScript | **PASS**, exit 0 | typecheck-final.log |
| Frontend ESLint | **0 errors, 52 warnings** (same documented baseline warning count) | eslint-full.log |
| Production frontend build | **PASS**, exit 0 | frontend-build.log |
| Ruff app + tests | **PASS** | ruff-app-tests-final.log |
| Ruff three new test-environment scripts | **PASS** | source review / final checks |
| Ruff formatting ten new Python files | **PASS** | final checks |
| Global Ruff app/tests/scripts | **4 pre-existing findings**, unchanged baseline files | ruff-full-final.log |
| Git whitespace | **PASS** | whitespace-final.log |

The four global Ruff findings are import order in backfill_component_descriptions.py, bootstrap_fresh_database.py and compare_authorization_catalog.py, plus datetime.UTC in dev.py. Their exact baseline source bytes are preserved; no unrelated lint rewrite is part of this change. Next's generated next-env.d.ts build-path rewrite was restored to its original bytes.

The prior `backend-full-final.xml` name is historical: that run was interrupted at **192 PASS**, zero failures after 308.71 s to correct a demonstrated numeric-shaped JSON integer validation hole. It is not a complete acceptance run. The final focused suite adds explicit rejection of that input and hyphenless User selectors. The later complete-inventory attempts are recorded below; while one is in progress, no final backend acceptance is claimed.

Additional development attempts: frontend focused attempt 5 had 52 PASS/1 FAIL before its last stale integer expectation was corrected; earlier failed and mistyped-workdir runs remain in evidence. Browser attempt 1 failed on a harness button-label mismatch after six successful role scenarios. Neither is overwritten by later success.

## Browser scope and security limits

Each of Admin, Analyst, Developer, Viewer, Foreign and Platform signs in with a new synthetic task identity, receives a UUID User context, refreshes, logs out, is denied direct protected-route access and signs in again with the same persisted UUID. Foreign access to Olympus is denied; Viewer candidate discovery is denied. Tenant Admin uses actual dialogs to find/add a member, assign Developer and remove that membership. Membership IDs stay numeric. UUID path errors return 422 and a nonmember identity returns 404.

Ordinary Platform Admin global user directory/detail remains **403** under the existing privacy policy. Its approved purpose-limited tenant-administrator candidate search returns UUIDs. Positive platform grant/revoke passed both authorized API contexts and the actual browser candidate-search/grant/revoke flow. Global-directory/detail happy-path is not claimed; those routes remain 403. HCL.CS/Entra live-provider verification is unavailable locally; isolated contract tests remain separate from live-provider acceptance.

## Test routing incident and explicit cleanup

The first complete run inherited application broker configuration. The existing development worker received three test AI tasks (exact task/batch IDs and timestamps are retained in broker-isolation-resolution.json). Read-only reconciliation found no matching main database batch, usage or cache writes in the observed window, and the recorded IAM counts/marker remained unchanged. This does not claim that no worker processing happened: worker receipts are confirmed.

The three failed progress entries existed in the original development Redis. The operator explicitly approved only those keys and their three index memberships. One guarded atomic cleanup removed exactly **3 keys + 3 memberships**, independently confirmed their absence and preserved every unrelated member/score. No database cleanup occurred. See approved-progress-cleanup.json and the read-only incident evidence.

Subsequent regression children use explicit clean settings, an unavailable task-only broker endpoint and an opt-in collection/per-test routing guard. Live integration progress tests use the separate task Redis. The corrected isolated progress endpoint test passed once; no worker fallback to the main app is permitted.

## Reproduction and remaining gates

Run the backend from the repository with `.venv/bin/python -B scripts/iam_uuid_test_environment.py tests -o addopts= --durations=25 --junitxml=<new-evidence-path>`. The launcher holds an exclusive task test lock and targets only its fixed disposable databases. Run focused checks by passing the two new test modules instead of `tests`. Frontend commands use the bundled Node runtime, full Vitest with two workers, tsc --noEmit, ESLint and next build. Browser runner is evidence/iam-browser.cjs; it reads task-only private credentials in memory, records no trace/video/cookies and uses Chrome without certificate bypass.

No full UAT, staging or production acceptance is asserted. The populated application's backup/upgrade and matching service cutover require separate approval. Existing conditional hosted-provider/BFF/empty-database tests must be reported from the final inventory rather than inferred from historical results. The original 193 six-resource integrity cases are not silently counted as new IAM cases.

## Audit event identity correction

A further source review found that the platform User-root serializer also covered `/users/{user_id}/audit`, which could reinterpret an audit event integer ID as a User identity. The corrected root applies only to actual User collections/detail. Explicit `actor_user_id` conversion remains active. The final regression uses a synthetic authorized projection with real PostgreSQL identity mapping; it does not change real endpoint privacy permissions.

The exact old rule was reintroduced transiently in a controlled test and produced the demonstrated **HTTP 500 / Unresolvable public resource reference**; the corrected rule passes. The original source was restored in a finally block. Evidence: audit-id-reproduced-before.xml/log and audit-id-after2.xml/log. Test development initially hit the expected production permission 403, then an incomplete miniature FastAPI harness lacked its request stack; these are retained as harness failures, not as root-cause reproductions. The first retry was refused by the exclusive fixture lock while a run still owned the test database. One temporary Ruff F811 test-name collision was corrected. No application permission was relaxed.

The broader backend-complete-attempt3 was stopped for this correction at **269 PASS / 1 FAIL**, 681.08 s. Its failure was an unchanged warm-cache timing guard: **5.44 s observed / 5 s limit** while browser/services ran concurrently. It remains a failure, not an inferred resource-related pass. Only task-owned UI/API services were then stopped to release local resources; the exact warm-cache test is rerun without changing its threshold. A corrected complete run is required.

## Validation-error input correction

A real request with a valid User UUID and invalid empty role list produced a model-level HTTP 422 whose `input.user_id` echoed the resolved integer. The new regression captured the defect (validation-user-input-before.xml). IAM routes now pass FastAPI's existing validation-error response through the same explicit public-identity projection, retaining the established envelope, status and error message while restoring public User fields. Other route families preserve their existing handler behavior.

The preceding full attempt4 was stopped at **149 PASS**, zero failures, 223.16 s for this correction. It did pass the unchanged warm-cache timing test with browser services paused. It is an interrupted run, not complete acceptance. The new focused/full executions below must be assessed independently.

Latest focused acceptance: **28 PASS / 0 FAIL / 0 SKIP**, 26 existing deprecation warnings, 35.01 s. This includes both final serializer/error corrections plus the actual migration fixtures. `focused-final2` had **27 PASS and 1 DESELECTED** because the optional AI integration selector was excluded by the default marker expression; it is not evidence that the warm-cache case ran. The full attempts explicitly clear addopts and include integration/benchmark inventories.

Current complete execution: `backend-complete-attempt5` with source freeze `backend-complete-attempt5-source-before.json`. The immediately prior complete attempt4 passed the unchanged warm-cache timing test, but was interrupted and is not a full-suite pass. Final acceptance requires this run's actual XML and source-preservation comparison.

## Restricted application-role allocator probe

A separate actual PostgreSQL probe used only `iam_uuid_browser_app` on the task browser database. Attempt 1 failed the existing email-verification timestamp CHECK (SQLSTATE 23514) because the synthetic insert omitted its required timestamp. No constraint or privilege was changed. The corrected fixture supplied that timestamp; explicit-NULL UUID allocation returned native UUIDv4 under the restricted role, ROLLBACK completed and a new read-only transaction confirmed absence. Seven task browser accounts remain. Integer sequences may advance during rolled-back inserts; this occurred only on the disposable task database. This is one separate runtime probe, not an additional counted pytest case. See restricted-runtime-allocator-attempt1.json and restricted-runtime-allocator.json.


## Complete run 5 and corrections

The first completed full inventory finished with **4,404 PASS, 9 FAIL, 7 SKIP, and 12 passing subtests**, 5,451.01 seconds. It is a failed run, not a full acceptance result. `full-failure-classification.json` records each failed case. Seven failures were stale HTTP/graph or historical-schema fixtures; one was copy-fixture contamination by task broker tables; one was a real application validation-handler defect.

The application defect bypassed the registered Native validation-error redaction handler. The corrected public boundary dispatches to the application's registered handler (async or sync) before projecting User error fields. A dedicated regression preserves password/token input redaction. Historical Entra migration fixtures now reflect their actual revision-063 table, without altering historical migrations. The copy test receives a newly owned isolated database; the migration utility still refuses schema drift. Internal integer FK assertions remain integer.

The affected rerun passed **204 / 204**, zero FAIL/ERROR/SKIP, 258.63 seconds. This includes the two new IAM modules, Entra authentication/migrations, Native foundation/phase2, scheduler graph, onboarding authorization, role assignment and real PostgreSQL integration. The upgraded synthetic legacy account now also performs actual Native password verification twice while retaining its integer key, provider link and public UUID. A new complete inventory (`backend-complete-attempt6`) is running against frozen final source; its result is pending.

### Final browser reruns

`browser-final2.log` recorded **8 PASS / 1 FAIL**. The platform grant test used the tenant search field's accessible label and timed out before selection. Only the test selector changed to the actual platform label; application security/permissions were unchanged. `browser-final3.log` and browser-results.json then recorded **9 PASS / 0 FAIL**, installed Chrome with `ignoreHTTPSErrors:false`.

The nine scenarios include all six role login/refresh/logout/stable-UUID checks, actual tenant add/change-role/remove dialogs, actual platform grant/revoke UI using UUID selectors, and 422/404 plus public validation-input checks. Platform global directory/detail remain 403 as required by existing privacy policy. A successful grant/revoke flow uses the already authorized purpose-limited candidate search, not a new discovery grant. Task-only candidate memberships/grants are removed through the corresponding application flows. No original seeded identity is modified.

### Credential disclosure and approved remediation

A failing legacy-copy assertion rendered the setup database URL in run-5 output. The public log/XML were sanitized; exact originals are preserved only in a 0700 private directory with 0600 files. The operator separately approved rotating only `greenfield_setup` and its private setup-password file. The original preflight stopped before mutation because a version string included the Debian suffix. A read-only check established the expected 16.15 numeric version and disabled statement/duration logging. The corrected operation acknowledged COMMIT, updated the existing private file in place, physically closed, and authenticated with the new credential on an independent read-only connection. Role attributes and resource identities were unchanged. See approved-setup-rotation.json (preflight stop) and approved-setup-rotation-attempt2.json (PASS).

After successful rotation, the evidence-copy step refused to overwrite the earlier preflight record. Its already-written protected PASS outcome was copied to a new public evidence path; no password operation was repeated. Application-role credentials, signing/session keys and the six seeded users were unchanged. No schema/business mutation or service restart was needed for rotation. Future full-run evidence is sanitized while streaming and its XML is first written privately. The disclosed old credential is revoked.

A preservation comparison initially used a different search_path, producing schema-qualified FK text rather than baseline text. Repeating the bounded read-only comparison with the baseline representation produced exact agreement for marker, column absence, six IAM counts and FK definitions. No database repair occurred. Existing API/frontend/worker PIDs remained alive. Ruff command discovery also initially used a nonexistent .venv/bin/ruff; the actual installed Ruff then passed app/tests/new scripts.


Run-5's seven explicit skips were four hosted AI-provider smoke tests without credentials, the separately opt-in empty-database/Mailpit Native acceptance, and two separately opt-in dual-BFF real HTTP lifecycle tests. They are not passing results. The task browser journey provides its own live Native session evidence, but does not substitute for those skipped tests or live HCL.CS/Entra acceptance. Final run-6 skip reasons must be independently read from its resulting XML.

## Interrupted run 6 and continuing complete verification

The corrected run6 was interrupted by the session before a final XML/outcome was written; the last log progress is approximately 21%. No live pytest process remained when execution resumed. Its output and source snapshot remain unchanged and it receives no final PASS count. The new sanitized `backend-complete-attempt7` launcher uses exclusive task-DB locking, the same explicit broker isolation and private XML with sanitized public output. No test or assertion was removed to resume the complete inventory.

## Advisor local-User actor completion

Review of persisted actor semantics found two Advisor audit endpoints still returned ComponentRecommendationEvent.actor_user_id as a local IAM integer. This differs from repair actor labels/provider subjects and must be public UUID. The existing real API actor-evidence test was strengthened to require UUIDv4 while preserving integer event/recommendation IDs; it failed before the correction with an integer-input UUID error. A narrow two-path field mapping implements the contract without changing Advisor workflow, privacy, tenant permissions or service storage. See advisor-user-uuid-before.xml/log and advisor-user-uuid-after.xml/log.

The complete run7 was intentionally interrupted at **279 PASS / 4 SKIP**, zero failures, 400.41 s to apply this correction; its source-change register also records the new test edit at interruption. No complete acceptance is inferred. All prior attempts and private originals remain.

Final Advisor/IAM integration: **52 PASS / 0 FAIL / 0 SKIP**, 313.13 s (advisor-user-uuid-after.xml/log). Final-source browser rerun: **9 PASS / 0 FAIL**, browser-final4.log and browser-results.json, installed Chrome with TLS verification. The task API/frontend process groups were then closed; task Redis remains solely for regression integration. A formatting check initially requested one change in the new helper; it was applied and the corrected check passed. No semantic change followed these checks.

Complete current inventory is `backend-complete-attempt8`, with a fresh source freeze, private XML and sanitized public log. Earlier failed/interrupted runs remain unchanged. Its result is pending until actual completion, exit code and source comparison are recorded.

## Final complete acceptance — 2026-10-21

`backend-complete-attempt8` finished with exit **0**: **4,414 PASS / 7 SKIP / 0 FAIL / 0 ERROR**, plus **12 passing subtests**. Pytest runtime was **5,893.26 seconds**; the source-freezing/sanitizing launcher took 5,907.77 seconds. All **855** observed Python source hashes remained unchanged during the complete run. No default marker exclusion was applied (`tests -o addopts= --durations=25`).

Evidence: backend-complete-attempt8.xml/log/outcome.json, backend-complete-attempt8-source-before.json, and FINAL_TEST_RESULTS.json (all 4,421 node outcomes). Final source review contains 73 exact changed/new file hashes and the complete patch. Final AST/graph/SQLAlchemy schema checks, app/tests/new-script Ruff, formatting and whitespace checks pass. Full frontend remains **1,812 PASS**, TypeScript/build pass, ESLint **0 errors / 52 historical warnings**. The broader scripts Ruff scan still has the four unchanged historical findings documented above.

| Skipped case | Actual reason |
|---|---|
| AI real Gemini connection | GEMINI_API_KEY not set |
| AI real Grok connection | GROK_API_KEY not set |
| AI real Anthropic connection | ANTHROPIC_API_KEY not set |
| AI real OpenAI connection | OPENAI_API_KEY not set |
| Native empty database to population | Explicit empty DB/Mailpit acceptance not enabled |
| Two actual BFF logout/revocation | Separate opt-in real HTTP topology not enabled |
| Actual HTTP expiry mutation denial | Separate opt-in real HTTP topology not enabled |

These seven cases are not accepted as passed. Independent real Chrome Native acceptance passed **9/9** with strict TLS on task-only accounts and the final source, including both platform grant/revoke and tenant membership/role lifecycle. Live HCL.CS/Entra providers and staging remain unverified. The existing mocked provider contracts and Native credential/account restrictions pass in the full inventory. The earlier 193-case transitional migration suite was not rerun or counted as these IAM tests; existing six-resource UUID and integer Analysis Run regressions pass in this backend inventory.

Final bounded read-only observation confirms populated Greenfield remains revision **100**, IAM UUID column absent, six recorded IAM counts and integer FK definitions unchanged, and original main API/frontend/worker processes alive. Exact task Redis cleanup and separately approved setup-only credential remediation are recorded above; no populated DDL, UUID backfill or seeded-user mutation was performed. The final public evidence scan found no private-key/JWT/credential-URL/password-hash pattern matches. No commit/push/deployment or Linear change occurred.
