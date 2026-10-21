# Round 3 proposed Linear reconciliation

**Draft only. No tracker writes, duplicate issues, Done transitions or release approval.** Read-only current issue metadata is in [linear-readonly.json](evidence/linear-readonly.json).

| Existing issue | Proposed status | Exact Round3 evidence / remaining gate |
|---|---|---|
| SBO-54 | In Progress | Current inventory4368; interrupted diagnostic3645PASS/244FAIL/9SKIP/19deselected,422unfinished original nodes. Exact tracebacks/node dispositions recorded. Current-source legacy/policy/repair/VEX guards32PASS; protection163PASS. Final1805frontendPASS, type/lint/build exit0; backend244-node triage remains open;17 exact baseline failures corrected/retested;227 remain failing or unresolved at this checkpoint. Attach regression report and exact failed-node classification when complete. |
| SBO-55 | In Progress | Attach exact19-case register and local real Chrome/API evidence; track repair native-byte correction, cron dependency/validation, timezone, signed-schema dependency and session503 bootstrap defects here for triage without duplicate issue creation. Required isolated Ubuntu E2E is not executed. |
| SBO-59 | Todo / sign-off withheld | Local uncommitted source, unresolved acceptance criteria, incomplete backend triage, no staging/Ubuntu gate, SBO-73 owner decision. Full release/UAT sign-off withheld. |
| SBO-69 | In Progress | Six seeded Native/refresh/logout contexts36PASS; directory/admin search and role denials observed. Full human acceptance not inferred. |
| SBO-70 | In Review | Real detail/decision200, stale409/no duplicate version/history; Developer assigned UI save/readback, unassignment immediate403, Viewer403 and foreign404. Current focused protection suite163PASS. |
| SBO-71 | In Review | Real UUID hierarchy/deep links/refresh/drilldown/parent reset plus R3scope-switch/inactive exclusion3PASS; visible1/1/1 matches backend scope, foreign404. Current focused protection suite163PASS. |
| SBO-72 | In Review | Accepted Round2 popup implementation retained; current viewport/empty/populated/loading/error/keyboard/Cancel browser16PASS. |
| SBO-73 | Decision Needed; remain open | Existing OptionA/B proposal remains unapproved. Candidate discovery policy unchanged; no privacy-policy acceptance inferred from authorized existing workflow tests. |
| SBO-74 | In Review | Platform-only server policy preserved; current safe future-cutoff/no-prune API7PASS, exact1748-row catalogue digest unchanged; six-role browser7PASS, actual controlled platform click200/zero writes. |
| SBO-75 | In Review | Provider-neutral implementation retained; current disable/remove neutral wording plus new disposable add/disable/enable/remove lifecycle6PASS; original four memberships restored. |
| SBO-76 | In Review | Three real ACTIVE histories return200/intversionIDs; publish201/stale409 and normalized history/evaluation evidence15PASS. Policy/public-boundary guards included in final32PASS; integer collision/foreign-role boundaries retained. |

## New corrections proposed for SBO-54/SBO-55 review

1. Repair download: preserve immutable reviewed candidate bytes after route authorization rather than generic JSON reserialization. Focused hash/conflict/idempotency regression and fresh positive/negative live approvals passed.
2. CUSTOM schedules: pin croniter6.2.4 in both manifests; enforce supported five-field syntax and strict validity. Add IANA timezone validation; preserve UTC execution/Monthly presets.20focusedPASS and13livePASS.
3. Signed CycloneDX: vendor exact JSF schema dependency, register resources offline, pin jsonschema URI format checker.8focusedPASS; live deferredE110 replaces internalE025. Crypto remains unsupported.
4. Session check503: route already distinguishes service failure; AuthProvider wrongly mapped it to unauthenticated. Use existing error/Retry state and fail closed, preserving tenant preference until actual revalidation.3beforeFAIL→29focusedPASS; actual browser outage/Retry/recovery3PASS; final full frontend1805PASS.

Files/source diff and exact final commands are linked from Round3 results/regression report in the final evidence bundle. Existing branch remains dirty and unpublished.


Round3 coverage disposition: **14PASS/5BLOCKED** across the exact19 historical outstanding IDs. The original485 baseline remains unchanged. Backend current inventory has4,022 nodes with evidence across diagnostic/targeted runs and346 without; reconciled observed outcomes3,785PASS/228FAIL/9SKIP/346NOT RUN, with source qualifications. This is not frozen full-suite acceptance. Optional19:18PASS/1FAIL (unsafe Advisor benchmark fixture bootstrap, not an application permission defect).

5. Legacy analysis UUID boundary (R3-DEF-006): exact five advertised legacy routes now use existing scoped UUID translation after analysis:run authorization; numeric run IDs stay numeric and successor links use SBOM UUIDs. Files: app/public_api.py, tests/test_legacy_analysis_public_identity.py, tests/test_analyze_endpoints_snapshot.py, tests/public_id_fixture.py. Final32focusedPASS; real OSV/boundary/persistence7PASS. Missing VulnDB credentials remain required400; no paid-provider acceptance claimed.

SBO-54 follow-up:227 baseline nodes remain failing/unresolved plus1 Advisor benchmark fixture failure;346 current inventory nodes still unexecuted. Retain In Progress. SBO-55: real repair UI10PASS and serial navigation18PASS now available; Ubuntu acceptance remains unexecuted. SBO-59: WITHHELD. SBO-73: retain Decision Needed and the unchanged [OptionA/B proposal](../remediation/2026-10-20-round2/SBO-73_DECISION_PROPOSAL.md). No automatic tracker changes.

Review the exact Round3-only [source patch](evidence/round3-source.patch), [file/hash manifest](evidence/round3-source-files.json), [per-node regression inventory](evidence/backend-execution-inventory.json) and [resumable checkpoint](evidence/CHECKPOINT.json). Existing dirty work and previous fixes are preserved; no commit, push, merge or deployment.


Suggested review comments for existing acceptance issues:

- SBO-55: exact19 target disposition14PASS/5BLOCKED; source-local Chrome evidence only. Account-state capability, crypto and idle-expiry criteria need their explicit owner dispositions. Ubuntu acceptance remains open.
- SBO-54: attach all244 diagnostic traces,17 passing node reconciliations, additional Advisor benchmark failure and346 remaining selectors. Preserve In Progress; no full green claim.
- SBO-59: keep the release gate open for regression completion, unresolved decisions/exceptions and target-environment evidence. Uncommitted local changes have not been delivered or deployed.
- SBO-73: keep Decision Needed. The user approved only an isolated local AI model test; that supplies no approval to change IAM discovery.
