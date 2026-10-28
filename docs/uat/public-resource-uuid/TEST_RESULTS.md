# Test results

Historical 4,414 backend / 1,812 frontend / 9 Chrome results are reference evidence, not tests newly executed in this task.

**Final result: 4,490 backend PASS / 9 SKIP / 0 FAIL/ERROR, plus 12 passing subtests; 1,820 frontend PASS; 11 distinct real Chrome scenarios PASS.**

| Actual task run | Result |
|---|---|
| IAM contract baseline | 23 PASS / 3 FAIL: old integer Membership expectations |
| First focused integration | 51 PASS / 1 FAIL: fixture expected 200 rather than existing 201 |
| Second focused integration | 53 PASS / 2 FAIL: incomplete synthetic migration history/source-default fixtures |
| Synthetic migration development | Incomplete history/source defaults caused failures; corrected run: 3 PASS |
| Contracts development 3 | 63 PASS / 23 FAIL: stale HTTP fixtures, error envelopes, SSE connection ownership |
| Contracts development 4 | 83 PASS / 5 FAIL: remaining fixture formatting/invalid-assignee and foreign-resource expectations |
| Contracts development 5 | 89 PASS / 1 FAIL / 1 ERROR before operator infrastructure interruption; permission-before-lookup assertion corrected; PostgreSQL error retained |
| Corrected focused contracts 6 | **66 PASS, 0 FAIL/ERROR/SKIP**, including real 100→101→102 snapshots, rollback and DBAPI autocommit refusal |
| First full backend development | Interrupted for source/failure reconciliation: 1,304 PASS / 46 FAIL / 4 SKIP / 19 deselected; 4 passing subtests. Not final acceptance |
| Complete-inventory diagnostic | Interrupted to inspect the first failure: 71 PASS / 1 FAIL; warm-cache 5.23 s exceeded unchanged 5 s limit while Chrome also ran |
| Isolated existing load tests | **2 PASS**, original timing/concurrency limits unchanged, 48.27 s total |
| Frontend development inventories | Initial 81 failures and subsequent reconciliation failures preserved; none treated as passes |
| Complete frontend final | **1,820 PASS**, 201 files, zero FAIL/SKIP, 109.18 s |
| Chrome attempt 1 | 7 PASS / 2 FAIL: harness/navigation warmup failures |
| Chrome attempt 2 | Interrupted with failures during operator shutdown of services/PostgreSQL; preserved |
| Chrome resumed attempt 3 | **10 PASS**, actual installed Chrome, TLS verification enabled |
| Expanded membership Chrome | **1 PASS**: actual add/change-role/disable/re-enable/remove dialogs and UUID selectors |
| TypeScript | PASS |
| Next.js production build | PASS using isolated copied frontend and established webpack build; first Turbopack external-node_modules symlink rejection retained |
| ESLint | 0 errors / 52 historical warnings |
| Ruff app + tests + task/changed scripts | PASS |
| Global scripts Ruff | Four unchanged historical findings; no unrelated fixes |
| New-source AST/compilation and Git whitespace | PASS |
| Ten-resource catalog/metadata | PASS, disposable restricted-runtime database at 102; 144 FK definitions captured |

Further actual corrections: the first primary shard recorded 666 PASS / 4 FAIL / 4 SKIP before reconciliation; legacy query decoding exposed a real effective-route metadata defect. The first focused shard recorded 185 PASS / 4 FAIL, followed by a 46-PASS interrupted retry. Those failures and interruptions are retained. A corrected 65-case AI/internal-router set passed. A 71-case boundary run had 65 PASS / 6 FAIL (product nested projection and remaining fixture/context changes); its expanded corrected run passed **161 cases**. Legacy query correction initially had 34 PASS / 5 FAIL; after resolving the actual effective route, **39 cases passed**. A malformed-hyphen UUID case was added. No original assertion or authorization check was removed to hide a failure.

The subsequent primary shard was stopped after 1,125 PASS / 2 FAIL / 6 SKIP to repair two CVE fixture assertions. They used nonexistent or foreign-context integer selectors rather than persisted Run UUIDs. The corrected CVE and foreign-scope set passed **17 cases**. The concurrent focused shard was stopped after 1,541 PASS / 7 FAIL / 2 SKIP and four passing subtests. Its seven failures used public HTTP UUIDs as internal integer FK values in database read-back assertions. Corrected persistence, metric and scope fixtures passed **58 cases**. These are test-boundary corrections: integer persistence keys and public UUID expectations remain separately asserted. All failed and interrupted runs remain private. Both complete shards were restarted on the same v5 source snapshot. The focused shard passed; three further primary-only fixture mismatches were corrected before its final v6 rerun, as recorded below.

The first fresh frontend hash-frozen rerun was launched from the repository root instead of `frontend`: 1,818 PASS / 2 FAIL, caused by relative Tailwind/MSAL fixture paths. Retried from the required frontend directory without changing source: **1,820 PASS, 201 files, zero FAIL/SKIP**. All 626 recorded frontend source/configuration hashes remained unchanged.

The complete backend inventory (all collected cases, `-o addopts=` without default marker exclusions) contains **4,499 cases**. Its final accepted execution comprises two disjoint resource-isolated shards of 2,375 and 2,122 cases, plus two load cases run alone. Independent reconciliation verifies **zero omissions and zero overlap**, with all 950 final backend source hashes checked. Six generated parameter labels contain UUIDv1 values or a historical timestamp: only those values in four explicitly identified functions are normalized for case-identity comparison, retaining their other parameters and cardinality. IPv6 parameter text and every other case identity remain exact. The original collection/XML bytes are preserved privately and hashed; no outcome is normalized. Full case statuses are in evidence/backend-frozen-results.json.

The complete focused shard finished: **2,120 PASS / 2 SKIP / 0 FAIL/ERROR**, plus four passing subtests, in 2,892.65 seconds. The primary v5 run finished with **2,365 PASS / 3 FAIL / 7 SKIP**, plus eight passing subtests. Its three remaining failures were HTTP fixture mismatches: an internal namespaced Membership key sent publicly, an existing Run UUID compared to its integer PK, and a malformed assignee obscuring a foreign-resource concealment assertion. The corrected three modules passed **44 cases**. Application and shared helper source did not change. Static import and file-selection checks establish that none of those three primary-only test modules is selected or imported by the passing focused shard. Its executed source remains identical to the final source; that proof is in final-shard-source-equivalence.json. The complete primary shard was rerun on v6: **2,368 PASS / 7 SKIP / 0 FAIL/ERROR**, plus eight passing subtests, in 2,571.33 seconds. The three failures were not replaced with a claimed full pass; the complete rerun supplies that evidence.

The final two load tests ran alone and passed in **49.03 seconds**, preserving their original 150-second and five-second limits. This replaces the earlier load result for final-source acceptance.

## Browser coverage

Admin, Analyst, Developer, Viewer, Foreign and Platform: actual Native sign-in, User UUID context, refresh, logout/protected-route denial and repeat-login identity stability. Viewer discovery is denied; foreign tenant headers are denied. Platform directory/detail remains 403 under SBO-73; purpose-limited candidates return User UUIDs.

Tenant Admin: real existing-user search, add Membership, separate User/Membership UUIDs, Developer role mutation, disable/re-enable with the same Membership UUID, and removal.

Platform Admin: actual candidate selection, grant UUID response, target login with platform authority, revoke by Grant UUID and immediate denial on the target's existing session.

Admin uploads a real synthetic CycloneDX SBOM through the UI. Analyst starts analysis through the UI, receives SSE FINDINGS with a Run UUID, follows history to its UUID detail URL, queries findings, refreshes and receives the same identity. Integer Run selector is 422; foreign Run selector is concealed 404. Postman records one real application querybatch HTTP request and two hydration GETs against the local simulation.

The final application source was verified in ten Chrome scenarios, followed by one distinct denial scenario: actual foreign Membership UUID concealed with 404, integer Grant rejected with 422, Viewer Membership/platform mutations denied with 403, numeric analysis deep link rejected by the UI, and no Viewer add-member control. Thus the final browser evidence contains **11 distinct passing scenarios**; repeated earlier scenarios are not added to inflate that total. TLS verification was enabled throughout these accepted runs.

No private credentials, cookies, tokens, authenticated traces or raw incident logs are published. Sanitized per-case/browser summaries are under evidence; original failed runs remain private.

## Limits

Live HCL.CS/Entra and hosted AI-provider acceptance is not claimed. The existing 193-case suite concerns the original six resources; it was not rerun or counted as new three-resource evidence. Original six-resource/identity regressions in the complete Pytest inventory passed. No populated migration, staging, full UAT or release sign-off.

## Exact final skips

These nine existing provider/opt-in conditions are the actual final skips, not an inference from the historical seven. No blanket skip or new skip condition was introduced.

- `tests.ai.test_real_provider_smoke.test_real_gemini_free_tier_test_connection`: GEMINI_API_KEY not set — skipping real-provider smoke.
- `tests.ai.test_real_provider_smoke.test_real_grok_free_tier_test_connection`: GROK_API_KEY not set — skipping real-provider smoke.
- `tests.ai.test_real_provider_smoke.test_real_anthropic_test_connection`: ANTHROPIC_API_KEY not set — skipping real-provider smoke.
- `tests.ai.test_real_provider_smoke.test_real_openai_test_connection`: OPENAI_API_KEY not set — skipping real-provider smoke.
- `tests.test_greenfield_startup_postgresql.test_real_confirmed_startup_encrypts_and_restores_backup_then_commits101`: opt-in disposable startup/backup acceptance.
- `tests.test_greenfield_startup_postgresql.test_real_precommit_failure_keeps100_and_retains_claim`: opt-in disposable startup/backup acceptance.
- `tests.test_native_greenfield_empty.test_empty_database_to_native_population`: explicit empty DB/Mailpit acceptance.
- `tests.test_native_http_acceptance.test_two_actual_bffs_logout_recovery_and_security_revocation`: opt-in real HTTP acceptance.
- `tests.test_native_http_acceptance.test_actual_http_expiry_denies_mutation`: opt-in real HTTP acceptance.

The legacy startup/backup probes target the earlier IAM disposable fixture and automatic 101 cutover; the new source deliberately refuses that startup executor at 102. The empty-database/Mailpit and two-production-BFF topologies remain separately enabled operational probes. Their SKIP outcomes are not represented as passing acceptance. The task-owned PostgreSQL upgrade, encrypted backup regression, real Chrome/Native session and three-resource authorization coverage are recorded separately. Live provider, cross-instance failover and staging acceptance are not claimed.
