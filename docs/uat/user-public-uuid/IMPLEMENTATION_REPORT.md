# IAM User public UUID implementation

**IAM_USER_PUBLIC_UUID_IMPLEMENTATION_COMPLETED — local disposable acceptance only.** The populated database has not been migrated; no UAT, staging or release sign-off is asserted.

Baseline verified: `feat/native-user-management`, HEAD `aa264cd3673b074b3f9c15c9cc72a4ed95bdb222`. Existing untracked historical reports, infrastructure sources, workspaces and UAT artifacts were retained. Initial tracked hashes are preserved in evidence/baseline-tracked-sha256.json.

## Design and changes

IAMUser now has a persisted native UUID public_id through the established model convention. New forward-only revision 101 and app/iam_public_identity.py provide transactional backfill/finalization and a distinct IAM-only guard. The original six-table guard and revision 100 remain frozen. app/iam_schema.py supports ordered fresh 100→101 installation without modifying historical migration provenance.

app/iam_public_api.py explicitly distinguishes User selectors/projections from membership, grant, provider, token, audit-event and Analysis Run identities. app/public_api.py reuses the existing post-authorization boundary and request-local batched output resolution. Request lookups are constrained to the selected tenant membership except for existing explicitly authorized global invitation/governance operations. Platform permissions and privacy policy remain unchanged. Initial-administrator creation requires bootstrap authority before a User lookup. Existing governance not-found envelopes and audit events are retained.

Frontend User IDs are string-only, forms validate UUIDv4, and authentication hydration validates the local public User identity. User-specific mutation/cache identities remain strings; membership/grant/Analysis Run identities remain integers. Cached analysis scopes include the new public User UUID and tests preserve that separation. Internal service DTOs still validate integer domain keys; OpenAPI describes actual UUID wire fields.

See IDENTIFIER_CONTRACT_MATRIX.md and API_MIGRATION_MATRIX.md for the audited fields/routes and compatibility decisions. Exact hashes for 73 changed/new source files and their complete patch are in evidence/implementation-source-sha256.json and evidence/implementation-source.patch.

## Database safety and runtime separation

The populated application database was inspected read-only and remains revision 100 without IAM public_id. Tests use new task-owned databases, users and roles. The disposable browser application uses API 18300, trusted HTTPS UI 13300 and task-owned Redis 56391. It has independent Native JWT/BFF keys; tokens must not authenticate to the main application. The six existing seeded development identities were not used or modified.

The matching new backend/frontend must not be restarted against the unmigrated populated database. Review DATABASE_MIGRATION_PLAN.md before cutover. No revision 100 replay, protected-database migration, external-provider subject change, global-discovery policy change, Git delivery or deployment occurred.

## Verification and limits

Actual passing/failing development attempts and final totals are recorded in TEST_RESULTS.md; earlier failures remain evidence. Successful database tests are real PostgreSQL, and browser tests use installed Chrome with certificate validation enabled. Mocked or direct-router tests are distinguished from published-boundary and live browser evidence. The final affected PostgreSQL/API/provider/upgrade regression passed 204 cases, the full frontend passed 1,812 cases and real Chrome passed nine scenarios. The complete corrected backend inventory passed 4,414 cases, with seven explicit skips and zero failures/errors; earlier failed/interrupted attempts are retained. See TEST_RESULTS.md for development failures and remaining checks.

Ordinary Platform Admin global user-directory/detail/grant workflows remain subject to existing permissions/privacy restrictions. A denied path is not reported as a successful happy-path test. Live HCL.CS/Entra provider acceptance and populated upgrade/staging acceptance require their own environment/authorization.

## Operational incident

The initial broad test launcher inherited the running application's Celery routing, and three test tasks reached its worker. Read-only reconciliation found no corresponding main database batch/usage/cache writes in the observed interval. Three failed Redis progress entries were removed only after explicit operator approval, using an exact guarded atomic cleanup that retained unrelated entries. Test isolation was corrected and is now checked before execution and each test. This incident and every interrupted/failed attempt remain in evidence; no blanket claim that the original worker was untouched is made.

## Developer environment and cutover

Task UI: https://localhost:13300; task API: http://127.0.0.1:18300; task Redis: 127.0.0.1:56391. The private task directory is ~/.sbom-iam-public-uuid (0700), with separately generated synthetic identities and credentials (0600). Existing services at 13000/18000 and populated revision 100 were not restarted or migrated. Only task-owned API/frontend services were restarted for final-source browser checks and later paused to release regression resources. Do not launch new application source against the populated revision-100 schema.

For a new authorized disposable run, scripts/iam_uuid_test_environment.py prepares the fixed test schemas and runs focused/full pytest; scripts/iam_uuid_browser_environment.py has explicit prepare/start commands and refuses existing resource/process collisions. The browser database follows actual 100→101 ordering, has separate restricted runtime/NOLOGIN owner roles and independent auth keys. No task script drops the populated database. Review DATABASE_MIGRATION_PLAN.md before any populated cutover.

Membership public identity is deliberately not expanded: membership_id/grant_id remain internal integer resource references under existing scoped authorization. Provider subjects and Native JWT subject semantics are unchanged. No Linear mutation, Git delivery, UAT or release sign-off occurred.

Final source review also narrowed platform User detail serialization so audit-event IDs remain integers. The new regression proves the old rule failed and the corrected projection preserves audit IDs while translating actor User UUIDs. See the retained before/after evidence. Task browser UI/API were paused after nine passing scenarios to reduce resource pressure during complete backend regression; main application services were preserved.

Model-level validation errors are included in the User boundary: a regression proved an invalid role-list request could otherwise echo the already-decoded internal User key. IAM validation errors retain the existing FastAPI envelope and now project explicit User fields back to UUIDs. The captured failing request and corrected test are retained; production authorization is unchanged.


## Latest correction and operational verification

A completed full backend run found nine failures; all 204 affected checks now pass after targeted fixture corrections and preservation of the application's registered Native validation-error redaction. The final complete corrected inventory passed; see the final acceptance table below. The final real Chrome rerun passed nine scenarios, including platform grant/revoke and tenant management. Earlier browser harness failures remain recorded separately.

The disclosed setup-only credential was rotated with explicit operator approval and independently authenticated; runtime credentials and original seeded accounts were unchanged. Read-only post-rotation comparison confirmed the original revision100 marker, absent IAM UUID column, recorded IAM counts/FK definitions and original process identities. No populated database migration or application-service restart occurred.

The final Advisor audit mapping explicitly converts only the two endpoints' persisted local IAM actor references. Their event/recommendation/candidate IDs remain integers; actor labels and unrelated provider/session strings remain unchanged. This final change passed 52 focused Advisor/IAM cases and a repeated nine-scenario Chrome journey. The complete final backend run passed after those corrections, with source frozen.

## Final local acceptance and remaining boundaries

- Backend: **4,421 collected; 4,414 PASS; 7 SKIP; zero FAIL/ERROR; 12 passing subtests**. Full execution cleared marker exclusions and preserved 855 frozen source files.
- Frontend: **1,812 PASS / 200 files**; TypeScript, production build and app/tests/new-script Ruff pass; ESLint has zero errors and 52 historical warnings. Four unchanged script-wide Ruff findings remain separately documented.
- PostgreSQL: actual synthetic 100→101 upgrade, fresh installation, uniqueness/NOT NULL/v4/immutability/rollback/concurrency, integer FK and credential/provider/grant preservation pass. The restricted task runtime allocator probe and complete model/catalog parity pass.
- Chrome: **9 PASS**, certificate verification enabled, final source. Six role session UUID stability, tenant isolation and denial checks, actual tenant membership/role/remove and platform candidate/grant/revoke flows pass. Global customer-directory/detail privacy denials remain 403.
- Preservation: original branch/HEAD, frozen migration100, shared six-table guard and historical sources preserved. Original populated marker100/absent IAM UUID column/counts/FKs and main process identities rechecked read-only. No populated UUID backfill or six seeded-account modification.

Review the exact migration and backup/recovery/writer-window plan before approving populated 100→101. Deploy matching backend/frontend together only after independent upgraded-schema acceptance; cached integer User selections must be refetched. Live HCL.CS/Entra providers, seven conditional integration gates and staging acceptance remain outstanding. Membership/grant and Analysis Run integer identities are intentionally unchanged. No indefinite integer User compatibility is provided.

The task-only browser API/UI are paused after successful acceptance; Redis remains available for integration evidence. Their new databases and protected fixture identities are preserved. No automatic migration or service cutover is performed by this report. All six requested reports and the local Linear draft are complete; no Linear issue/status, Git commit/push or deployment was performed.
