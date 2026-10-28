# Round 3 UAT results

**Checkpoint: ROUND3_UAT_PARTIALLY_COMPLETED. FULL_UAT_SIGNOFF_WITHHELD.**

The local coverage investigation is ongoing. All 19 original outstanding IDs have been mapped and revisited; an explicit pending disposition is retained where acceptance is incomplete. No complete 485-case rerun or formal release approval is claimed.

## Separate execution populations

| Population | Observed disposition |
|---|---|
| Immutable 2026-10-19 baseline | 485: 454 PASS, 12 FAIL, 11 BLOCKED, 8 NOT RUN. No historical result changed. |
| Original 19 revisited in Round 3 | 14 PASS, 0 FAIL, 5 BLOCKED, 0 NOT RUN. Initial load attempt timed out; serial follow-up18PASS closes the bounded navigation case, retaining the load limitation. |
| R1/R2 defect retests | VEX, UUID hierarchy, policy histories and six-role context executed; current focused suite163PASS. Popup16, membership6, safe KEV API7 and real KEV browser7 passed; no catalog changes. No inferred closure. |
| New technical defects | Six technical defects corrected and focused/live retested, including the newly found legacy analysis UUID boundary. Additional stale fixtures corrected;17 of244 diagnostic failure nodes now have passing retests. |
| Automated regressions | Full frontend 1,805 PASS on final frontend source; TypeScript/ESLint/build exit0. Broad backend diagnostic stopped with3645PASS/244FAIL/9SKIP/19deselected;422 original collection nodes unfinished. Full backend acceptance remains open. |
| External / policy gaps | Account status capability, cryptographic verification, idle-expiry contract, unapproved SBO-73 discovery decision, and target Ubuntu/staging evidence remain open. |

The original19 target completion rate is not a whole-application UAT pass rate. Among presently executed, closed original cases, 14/14 fully executed original cases pass (100% of completed cases);5 of19 remain BLOCKED. Current closure coverage is14/19 (73.68%). This is the19-target checkpoint, not485-case acceptance. Do not combine these with historical454 passes.

## Original cases — current execution

| Exact original ID | Status | Actual observation | Evidence |
|---|---|---|
| UAT-ACCOUNT-SUSPENDED | BLOCKED | Current V5 catalogue intentionally excludes platform:user:manage_status. Direct status attempt on a task-owned principal returned 403. No legal positive transition or suspension/session/audit lifecycle executed; requires an approved supported capability, not a seeded-role grant. | [governance-browser-accepted.json](evidence/governance-browser-accepted.json), [governance.json](evidence/governance.json) |
| UAT-ACCOUNT-DISABLED | BLOCKED | Direct DISABLED transition remains forbidden by current platform permission catalogue. No seeded or disposable account status was changed. Positive lifecycle remains authorization-blocked. | [governance-browser-accepted.json](evidence/governance-browser-accepted.json), [governance.json](evidence/governance.json) |
| UAT-ACCOUNT-ACTIVE | BLOCKED | New principal ACTIVE login succeeds, but reactivation from SUSPENDED/DISABLED cannot be executed without the excluded manage_status capability. Ordinary login is not reactivation acceptance. | [governance-browser-accepted.json](evidence/governance-browser-accepted.json), [governance.json](evidence/governance.json) |
| UAT-AI-LIVE-PROVIDER | PASS | User explicitly approved a small isolated free model. Real Copilot completed HTTP 200 with Ollama qwen2.5:0.5b on separate port11435 and a task-owned tenant override; cost0. Global flags/providers unchanged; server stopped. Hosted/paid provider acceptance is not established. | [readiness.json](evidence/readiness.json), [local-model.json](evidence/local-model.json), [ai-local.json](evidence/ai-local.json), [local-model-cleanup.json](evidence/local-model-cleanup.json) |
| UAT-VEX-ASSIGNED-DEVELOPER | PASS | Admin assigned owned investigation; actual Developer UI saved a justified decision; fresh Admin readback persisted it. API stale409 and no duplicate version/history, Viewer/unassigned Developer403 and foreign404; unassignment immediately revokes mutation. | [api-round3-vex.json](evidence/api-round3-vex.json), [browser-protection-vex.json](evidence/browser-protection-vex.json), [browser-protection-vex-readback.json](evidence/browser-protection-vex-readback.json) |
| UAT-SCHEDULE-VALIDATION | PASS | Before: valid and invalid CUSTOM both dependency422. Pinned supported croniter; final real invalid syntax, six/seven fields, impossible date, invalid IANA timezone reject422; valid disabled schedule201. Viewer403 and foreign404. No shared recurring execution. | [scope-creation.json](evidence/scope-creation.json), [cron-accepted.json](evidence/cron-accepted.json) |
| UAT-ENV-FRONTEND-RESTART | PASS | Initial overlapping-load attempt reached seven modules but Users & Access timed out60s with swap over9GiB. After the diagnostic workload stopped, serial follow-up passed18checks: two rounds8modules plus two clean-context concurrent session reads, no network failures. Same Next PID80918, zero added restart warnings/empty responses; navigation1.06–27.392s. This bounded follow-up closes original navigation acceptance only; the load/resource limitation and first FAIL remain explicit, with no leak-free or performance sign-off claim. | [browser-stability.json](evidence/browser-stability.json), [environment-before.json](evidence/environment-before.json), [environment-intermediate.json](evidence/environment-intermediate.json), [environment-after.json](evidence/environment-after.json), [browser-stability-serial.json](evidence/browser-stability-serial.json), [environment-serial-before.json](evidence/environment-serial-before.json), [environment-serial-after.json](evidence/environment-serial-after.json), [stability-reconciliation.json](evidence/stability-reconciliation.json) |
| UAT-SCHEDULE-CUSTOM | PASS | Valid five-field CUSTOM schedule201 while disabled; next run calculated in UTC, IANA display timezone retained. Pause/cleanup200, Monthly future-first-day02UTC preserved. Strict syntax, role and foreign controls executed. | [cron-accepted.json](evidence/cron-accepted.json) |
| UAT-DASHBOARD-DEPENDENT-FILTERS | PASS | Actual Project→Application→SBOM UUID selection, parent reset, refresh/deep links/drilldown, switch between owned scopes, inactive exclusion and three displayed metric totals matched API (1/1/1 after R3 switch). Invalid IDs rejected and foreign known UUID404. | [browser-dashboard-current.json](evidence/browser-dashboard-current.json), [browser-scope-extra-settled.json](evidence/browser-scope-extra-settled.json), [scope-exports.json](evidence/scope-exports.json) |
| UAT-VEX-DECISION-UI | PASS | Actual Admin, Analyst and assigned Developer opened investigation and saved justified decisions200; refreshed UI/history readback. Stale409/version preservation and unauthorized403/foreign404 independently exercised. | [browser-protection-vex.json](evidence/browser-protection-vex.json), [browser-protection-vex-readback.json](evidence/browser-protection-vex-readback.json), [browser-protection-vex-analyst.json](evidence/browser-protection-vex-analyst.json), [api-round3-vex.json](evidence/api-round3-vex.json) |
| UAT-PLATFORM-TENANT-WORKING-CONTEXT | PASS | Policy-authorized Platform Admin granted authority only to a new disposable principal with its own explicit membership. Actual Native UI landed platform-only, switcher listed only own tenant, entered/refreshed/returned platform and signed out. Forged Olympus header403; grant revoked and owned tenant disabled. Seeded Platform membership unchanged. | [browser-owned-platform-accepted.json](evidence/browser-owned-platform-accepted.json), [governance-browser-accepted.json](evidence/governance-browser-accepted.json) |
| UAT-ACTIVE-POLICY-RULES | PASS | Fresh tenant published ACTIVE trust/accepted-risk/scoring201 with integer policy version IDs; history200 exactly normalized rules, stale409/no extra version, real OSV/classification explanations reference active policies. INHERIT versions appended. Smart Recommendations/Vendor Alternatives remain deferred, not activated by this execution. | [active-policies-accepted.json](evidence/active-policies-accepted.json) |
| UAT-REPAIR-AUTOMATIC-APPROVAL | PASS | Reproduced immutable candidate-byte/hash mismatch409; scoped correction preserves native artifact bytes. Fresh candidate proposal/diff/revalidation; explicit Analyst rejection200 and post-reject409; Admin matching-hash approval200/public UUID; wronghash409, repeat same import, original bytes/history preserved, Viewer403/foreign404. | [repair.json](evidence/repair.json), [repair-after.json](evidence/repair-after.json), [browser-repair-final.json](evidence/browser-repair-final.json) |
| UAT-REPORT-OTHER-FORMATS | PASS | Real PDF/CSV/XLSX/SARIF and FDA510(k) workbook downloads200. Parsed nonempty PDF/pages, CSV/SARIF five findings agreement, FDA eight populated sheets with synthetic metadata. Viewer403 and foreign404. Actual Chrome Export Vulnerability Excel download and native CycloneDX download passed; files parsed/header inspected. | [scope-exports.json](evidence/scope-exports.json), [artifact-content-validation.json](evidence/artifact-content-validation.json), [browser-sbom-followup.json](evidence/browser-sbom-followup.json) |
| UAT-SBOM-SIGNATURE-CONVERSION | BLOCKED | SPDX→CycloneDX conversion and reference checks executed. Missing JSF schema/URI checker fixed; explicit signature validation reaches stable E110 verifier-not-implemented instead of internal E025. Cryptographic valid/tampered verification is deferred/unsupported, so composite case cannot PASS. Initial export raw-byte assertion was a harness error: native export intentionally formats JSON; before/after export hash matched. Bounded >5MiB paged read/search and reviewed manual line patch/revalidation/import passed with source bytes retained; automatic repair correctly respects its5MiB manual-review boundary. | [conversion.json](evidence/conversion.json), [conversion-accepted.json](evidence/conversion-accepted.json), [signature-schema-accepted.json](evidence/signature-schema-accepted.json), [large-manual-accepted.json](evidence/large-manual-accepted.json) |
| UAT-REPORT-SCHEDULED-TRIGGER | PASS | Owned bounded Celery Beat→worker schedule fired using isolated due-clock only. Controlled first SMTP_UNAVAILABLE then real120s retry→SENT; repeated ticks one delivery cycle, one Mailpit digest with two attachments. Artifact content/downloads and foreign404, pause/delete verified; owned Beat/worker stopped. Initial subject-filter harness failure corrected against actual digest subject. | [scheduled-report.json](evidence/scheduled-report.json), [report-mailpit-accepted.json](evidence/report-mailpit-accepted.json), [artifact-content-validation.json](evidence/artifact-content-validation.json) |
| UAT-PROVIDER-SECRET-ROTATION | PASS | Synthetic credentials on authenticated isolated local mock: create, rotate, verify upstream current key, revoke/read404. Tenant encryption-at-rest and redacted scoped audit inspected without exposing secrets. Viewer403/foreign404 and reset to inherited disabled global configuration. This establishes local mock acceptance, not real hosted-provider credentials. | [ai-local.json](evidence/ai-local.json), [secret-lifecycle.json](evidence/secret-lifecycle.json) |
| UAT-SESSION-EXPIRY-CONCURRENCY | BLOCKED | Six real Native clean-context flows and parallel second contexts retain isolation across refresh/logout; old cookie replay unauthenticated, second session stays valid. Owned logout-all invalidates both native JWTs401; controlled signed-token absolute expiry tests pass at TTL60/900/86400. Original independent idle expiry/long-lived role-change criterion has no idle-timeout contract in current fixed-absolute Native implementation; Product/Security disposition required. Live TTL and seeded roles unchanged. | [browser-six-roles-accepted.json](evidence/browser-six-roles-accepted.json), [governance-browser-accepted.json](evidence/governance-browser-accepted.json) |
| UAT-PLATFORM-GRANT-REVOKE | PASS | Eligible new principal: lower-role grant403, authorized grant201, same JWT authority refresh200, duplicate409, revoke204, immediate old-token platform403. Own membership required for working tenant, forged Olympus403. Seeded Platform authority unchanged. Last-admin guard current native regression passed within163-case protection suite. | [governance-browser-accepted.json](evidence/governance-browser-accepted.json), [browser-owned-platform-accepted.json](evidence/browser-owned-platform-accepted.json), [pytest-round1-round2-protection.xml](evidence/pytest-round1-round2-protection.xml) |

The detailed machine register preserves each exact original module, role, expectation and blocker, and lists executed evidence check IDs and HTTP results: [ROUND3_TEST_CASES.json](ROUND3_TEST_CASES.json). The initial feasibility matrix remains in [ROUND3_COVERAGE_MATRIX.md](ROUND3_COVERAGE_MATRIX.md).

## Accepted current evidence sets

| Evidence | PASS | FAIL | Other |
|---|---:|---:|---:|
| [api-round3-vex.json](evidence/api-round3-vex.json) | 14 | 0 | 0 |
| [browser-protection-vex.json](evidence/browser-protection-vex.json) | 5 | 0 | 0 |
| [browser-protection-vex-readback.json](evidence/browser-protection-vex-readback.json) | 1 | 0 | 0 |
| [browser-protection-vex-analyst.json](evidence/browser-protection-vex-analyst.json) | 2 | 0 | 0 |
| [browser-dashboard-current.json](evidence/browser-dashboard-current.json) | 10 | 0 | 0 |
| [browser-scope-extra-settled.json](evidence/browser-scope-extra-settled.json) | 3 | 0 | 0 |
| [browser-six-roles-accepted.json](evidence/browser-six-roles-accepted.json) | 36 | 0 | 0 |
| [browser-owned-platform-accepted.json](evidence/browser-owned-platform-accepted.json) | 8 | 0 | 0 |
| [governance-browser-accepted.json](evidence/governance-browser-accepted.json) | 21 | 0 | 0 |
| [ai-local.json](evidence/ai-local.json) | 14 | 0 | 0 |
| [secret-lifecycle.json](evidence/secret-lifecycle.json) | 11 | 0 | 0 |
| [active-policies-accepted.json](evidence/active-policies-accepted.json) | 15 | 0 | 0 |
| [repair-after.json](evidence/repair-after.json) | 22 | 0 | 0 |
| [cron-accepted.json](evidence/cron-accepted.json) | 13 | 0 | 0 |
| [scope-exports.json](evidence/scope-exports.json) | 23 | 0 | 0 |
| [artifact-content-validation.json](evidence/artifact-content-validation.json) | 0 | 0 | 5 |
| [report-mailpit-accepted.json](evidence/report-mailpit-accepted.json) | 1 | 0 | 0 |
| [conversion-accepted.json](evidence/conversion-accepted.json) | 7 | 0 | 0 |
| [signature-schema-accepted.json](evidence/signature-schema-accepted.json) | 1 | 0 | 0 |
| [large-manual-accepted.json](evidence/large-manual-accepted.json) | 9 | 0 | 0 |
| [browser-session-retry-accepted.json](evidence/browser-session-retry-accepted.json) | 3 | 0 | 0 |
| [browser-sbom-followup.json](evidence/browser-sbom-followup.json) | 4 | 0 | 0 |
| [browser-after-round3.json](evidence/browser-after-round3.json) | 16 | 0 | 0 |
| [browser-membership-round3.json](evidence/browser-membership-round3.json) | 6 | 0 | 0 |
| [api-kev-round3.json](evidence/api-kev-round3.json) | 7 | 0 | 0 |
| [browser-kev-round3-accepted.json](evidence/browser-kev-round3-accepted.json) | 7 | 0 | 0 |
| [browser-repair-final.json](evidence/browser-repair-final.json) | 10 | 0 | 0 |
| [legacy-analysis-after.json](evidence/legacy-analysis-after.json) | 7 | 0 | 0 |
| [browser-stability-serial.json](evidence/browser-stability-serial.json) | 18 | 0 | 0 |

Counts are per evidence execution set; related checks can overlap and must not be summed into unique original UAT cases. Diagnostic attempts are excluded from this acceptance index and remain available.

## Evidence qualifications

- Native Login used actual Chrome forms for all six seeded identities in clean contexts. HTTPS trust was enforced; no ignoreHTTPSErrors, insecure curl, certificate bypass or HTTP downgrade was used. Browser authentication fixtures in some additional component checks are labelled separately.
- AI used the explicitly approved free local qwen2.5:0.5b model on separate port11435/cache, only a disposable tenant override, and real Copilot completion200. The server stopped; global AI settings were compared unchanged. Hosted/paid upstream acceptance remains untested.
- Provider rotation used synthetic keys and an authenticated local mock. At-rest ciphertext/redacted audit and permission/inheritance boundaries were verified; no real hosted secrets were used.
- Scheduled reports used task-owned queues, bounded Beat/worker execution and a due-time clock only for the owned subscription. The first send failed through a controlled SMTP result; durable120s backoff then actual Mailpit delivery succeeded. Shared jobs, global clocks and SMTP configuration were unchanged. Per-attempt artifact retention is an observation, not an asserted duplicate-email defect.
- Large file: >5MiB paged read/search/manual line patch/revalidation/import passed. Automatic repair correctly stops at its documented5MiB safety boundary. The initial auto-repair expectation failure was a harness expectation error; no limit was weakened.
- Native SPDX export intentionally pretty-prints JSON. Corrected semantic/store-preservation checks passed; the original stricter raw-upload/export byte comparison remains diagnostic evidence.
- Initial policy-history comparison used unnormalized request rules; final assertions compare actual normalized published contract. Duplicate platform grant correctly returns409. Mailpit digest subject is the observed security digest, not an assumed report title.
- Independent idle timeout is not defined by the current Native fixed-absolute lifetime contract. Tests do not invent one or lower live token lifetimes. Cryptographic verifier remains an explicit deferred E110 contract.

## Release readiness

| Gate | Current finding |
|---|---|
| Supported local flows | Six-role Native/context/logout, VEX decisions, UUID hierarchy, active policy history, repair, cron, export artifacts, scoped recurring reports, local AI and synthetic secret rotation have direct evidence. |
| Partially tested | Broader main-screen E2E and complete current-source backend regression finalization remain open at this checkpoint. Actual create/upload/component/native+Excel browser downloads, repair review/reject/approve10, popup16, disposable membership6 and KEV7 passed. |
| Configuration / policy | No legal platform:user:manage_status principal under current V5 catalogue. Idle criterion requires owner decision. |
| Unsupported / external | Cryptographic verifier deferred; real hosted AI/OIDC external credentials not exercised. |
| Security/privacy | SBO-73 remains Decision Needed; no discovery policy change. |
| Automated failures | Broad backend diagnostics contain failures; 244 exact diagnostic failures indexed,17 corrected/retested;227 plus1 optional benchmark failure unresolved. Deduplicated current inventory346 nodes have no execution evidence. No full backend-green claim. |
| Git delivery | Existing dirty working tree preserved; local changes only. No commit, push, merge or deployment. |
| Staging / Ubuntu | Not executed. SBO-55 explicitly requires isolated Ubuntu evidence; macOS local results do not satisfy that gate. |
| Formal recommendation | WITHHELD: unresolved criteria/decisions, unfinished regression triage and target-environment evidence. |

## Resumable checkpoint

1. Collect broad backend process completion and classify every failed node; fix confirmed ordinary defects/obsolete UUID fixtures without weakening security.
2. R1/R2 guards and affected browser retests are complete locally; finish broader role/module E2E and full backend reconciliation.
3. Session503 browser Retry3PASS and final1805frontend/type/lint/build are complete. Serial stability follow-up18PASS completed; investigate load limits and retain the earlier load timeout.
4. Run remaining422 initial backend nodes and resolve/retest classified failures using task-owned databases. Repeat broad current-source acceptance after fixes; no synthetic green aggregate.
5. Verify protected1700-file hashes, original485 records and six seeded identities; finalize source diff and sanitized evidence.
6. Recompute this checkpoint from actual results. Do not mark Linear Done or grant release acceptance.


## Final checkpoint reconciliation

The exact19 target register is **14PASS/5BLOCKED**. Five blockers: three platform account-state lifecycle cases lack a policy-authorized status-management capability; cryptographic signed/tampered verification is unimplemented; the original independent idle-expiry criterion lacks a Native product/security contract. SBO-73 separately remains Decision Needed. No seeded identities or privileges were changed.

Current backend inventory4,368:4,022 nodes have actual evidence across diagnostic and focused runs;346 have none. Reconciled observations3,785PASS/228FAIL/9SKIP/346NOT RUN retain per-run source qualifications and are not a frozen current-source full execution. The interrupted run's original3,645PASS/244FAIL/9SKIP remains intact;17 of its exact failures now pass independently,227 remain unresolved, plus1 newly executed Advisor benchmark fixture failure. All19 optional marker exclusions were separately attempted:18PASS/1FAIL.

Six confirmed technical defects were corrected and retested. Final current-source legacy/policy/repair/VEX boundary suite32PASS; R1/R2 guard suite163PASS; original13 VEX nodes eachPASS. Full frontend1,805PASS, TypeScript/build/Ruff exit0, ESLint zero errors/52 warnings. Actual repair review/reject/approve UI10PASS; KEV six-role UI7PASS/zero catalogue writes; later bounded serial navigation18PASS, preserving the initial load timeout.

**ROUND3_UAT_PARTIALLY_COMPLETED. FULL_UAT_SIGNOFF_WITHHELD.** Remaining work is enumerated in [CHECKPOINT.json](evidence/CHECKPOINT.json), [regression results](ROUND3_REGRESSION_RESULTS.md) and [Linear drafts](LINEAR_RESULTS.md). Formal acceptance requires remaining backend execution/remediation, unresolved criterion/owner decisions and agreed Ubuntu/staging/CI evidence. No full application UAT sign-off or Linear Done transition is granted.


Final safeguards: [1,700 historical files unchanged](evidence/historical-integrity.json); [all six seeded identity/context checks PASS](evidence/final-identity-safeguard.json); [Olympus original four active/verified memberships](evidence/seeded-membership-safeguard.json); [exact KEV digest unchanged after API and UI synchronization](evidence/kev-final-catalog-safeguard.json); [main revision100 read-only](evidence/main-revision-readonly.json); [SBO-73 policy/proposal unchanged](evidence/policy-preservation.json). Nine task-owned fixture tenants are disabled; retained records/artifacts support reproduction. Global IAM fixtures were not elevated or disabled for cleanup. Approved local model cache is retained privately, its server stopped. No paid credentials, global AI enablement, external email, commit, push, merge, deployment or tracker write.

Legacy anonymous boundary follow-up:[5/5 routes return401](evidence/legacy-analysis-anonymous.json) without provider execution. This is additional evidence beyond the7 successful authenticated OSV/boundary/persistence checks.


Source delivery: review the [Round3-only patch](evidence/round3-source.patch) and [exact file/hash list](evidence/round3-source-files.json). Dependency pins and local schema provenance are included. Import-only lint maintenance and test fixture corrections are distinguished from the six application/dependency corrections in [defects](ROUND3_DEFECTS.md). [Final verification](evidence/final-verification.json) records evidence JSON/XML validity, secret-candidate scan and whitespace checks. No original evidence was overwritten.
