# Linear implementation and migration drafts

No external issues created or modified; no status changes or completion/sign-off.

Draft 1 — Platform & Identity: **Public UUIDv4 for Membership, Platform Grant and Analysis Run.** Deliver the ten-resource public contract, strict UUID selectors, unchanged integer relationships, RBAC/tenant enforcement, frontend interactions and disposable migration acceptance. Link SBO-20, SBO-22, SBO-55 and SBO-66; preserve SBO-73 discovery/privacy policy. Attach IMPLEMENTATION_REPORT, API_CONTRACT_MATRIX, SECURITY_REVIEW and TEST_RESULTS. Code acceptance depends on the complete frozen regression evidence; this issue must not imply populated migration, deployment or full UAT sign-off.

Draft 2 — **Approve the populated 101→102 cutover** (or 100→101→102 only if a fresh independent starting observation proves 100). Require exact source review, maintenance approval, encrypted backup/restore rehearsal, row/FK/provider/credential snapshots, lock/timeout review, one transactional unit and independent read-back. Attach DATABASE_MIGRATION_102_PLAN and the final source manifest. No deployment or migration authority is created by this draft.

Search existing Linear issues before any separately requested creation to avoid duplicates.

## Development-branch delivery draft

Prepare an evidence-only delivery update referencing SBO-66, SBO-77, SBO-78, SBO-54, SBO-55, SBO-57 and SBO-59. Attach GIT_DELIVERY_REPORT after its GitHub verification, the exact implementation source manifest, the disjoint frozen-test reconciliation and the migration plan. Record source publication separately from populated migration, staging acceptance and release approval. Do not mark any issue Done or change SBO-73 discovery/privacy policy.

SBO-78's older migration-approval text describes 100→101. The latest recorded populated-environment observation is 101; the tracker needs a newly reviewed 101→102 cutover assessment, backup/restore rehearsal and separate execution authority. This Git delivery performs no database observation or migration and creates no such authority. No Linear issue was created or updated by this task.
