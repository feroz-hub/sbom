> **Implementation update:** The bootstrap proposal below has now been authorized and implemented. The current operator procedure is `native-iam-greenfield-setup.md`, with migration 062 and automatic atomic finalization during activation. Earlier bootstrap-gap and separate-finalize statements below describe the prior review checkpoint, not current behavior.

# Native IAM: greenfield staging acceptance plan

This supersedes the population-migration strategy in `native-iam-operational-acceptance.md`. No existing HCL/SF users, identities, tenants, memberships or credentials will be copied, migrated or linked. No matching by email. HCL source remains; automated HCL regression remains required. Live HCL acceptance is **DEFERRED / OPTIONAL REGRESSION**, subject to a separate decision before source removal.

## Current checkpoint

- Branch `feat/native-user-management`; HEAD and approved baseline `dea456fbe902013f5235987e4ed2b5916674899d`. Existing acceptance changes remain uncommitted. No merge/push.
- No staging target has been identified. The previously inspected local application database is revision `055_ai_model_registry`, with four IAM users; it must not be presumed to be staging. It was inspected read-only and remains untouched.
- No database creation, drop, migration, account provisioning or external email was performed in response to this strategy change.
- **STOP: a suitable first-Native-user bootstrap mechanism is missing.** The proposal below is not implemented.
- SMTP acceptance: **BLOCKED_PENDING_APPROVED_TEST_MAILBOX**.
- Existing local evidence: Native phases 1–5 plus new architecture, SMTP socket/crash, actual two-BFF HTTP/Redis and isolated backup/restore tests: **225 passed**, four warnings. Full frontend: **1,020 passed**, 138 files. TypeScript, production build, auth/BFF ESLint, changed Python Ruff and whitespace checks passed. Broader backend regression was already running at this checkpoint; its final outcome must be recorded separately.

## Supported mechanisms and the gap

`scripts/bootstrap_fresh_database.py` is the supported empty-PostgreSQL path. It refuses public tables, requires the exact database-name confirmation, installs the frozen revision-047 schema and runs Alembic upgrade through the dynamically discovered head. This avoids historical revision-001 live-metadata replay. Expected head is `061_security_mail_outbox`. Use this supported expected-bootstrap path, not ad hoc schema inserts.

Migration 048 atomically seeds and validates the immutable authorization catalogue. Normal authenticated application startup seeds master/reference data. Keep `AUTH_ENABLED=true` throughout: unauthenticated development startup would create a default development identity/tenant and is unsuitable for this Native-only population. Verify all five role definitions and their permission mappings; do not fabricate grants or role records by SQL.

`scripts/bootstrap_platform_admin.py` is an operator-controlled, audited grant mechanism for an **existing** user. `resolve_bootstrap_user()` rejects an absent target; `bootstrap_platform_administrator()` requires an active, verified eligible user. It cannot create a Native identity, issue activation or initialize a password. Its existing-target idempotence also is not a permanent one-time Native enrollment guard.

`native_enrollment_service.create_user()` requires an authorized administrator and an active tenant. Therefore it cannot create the first tenantless Native Platform User in an empty database. The development-only grant script and HCL membership seed script are not acceptable substitutes.

## Proposed smallest Native bootstrap extension — review required

Use an operator-only CLI, not a public bootstrap HTTP endpoint, with two explicit steps:

1. **Enroll the reserved first Native user.** Require an explicit disabled-by-default bootstrap setting, approved change reference, exact new-database confirmation, authenticated production-safe configuration and an approved mailbox. Under a database-wide bootstrap lock, verify zero usable Platform Admins and no completed bootstrap. Reserve exactly one candidate durably so concurrent/repeated commands cannot create additional accounts. Create a new pending IAMUser and Native UserIdentity with no tenant membership and no password, issue the normal five-hour activation token and encrypted outbox row, and audit atomically. Reject identity collisions; never select/link an existing person by email. Output only a safe local user ID/status, never token or secrets.
2. **Finalize after normal activation.** The operator supplies the reserved user ID; verify the same Native-only user has completed ordinary activation and credential creation. Under the same lock, recheck zero usable admins and the reservation, then call the existing platform-grant service and commit the required audit and durable consumed state atomically. The user then signs in normally. No pending account receives effective platform authority. If grant/audit fails, no partial grant commits.

The durable reservation/completion guard must survive process restarts, serialize concurrent attempts even when grant tables are empty, reject a different pending candidate, and prohibit reuse after completion even if the administrator later becomes disabled. Select the smallest suitable existing persistence mechanism during approved implementation; if a dedicated record/migration is genuinely required, explain it before creating it. Do not use a process flag alone. Recovery/resend must target the same reserved candidate, rotate tokens through the approved flow and remain operator-audited; it must not create replacement users silently.

Immediately after the first usable admin exists, bootstrap enrollment/finalization must reject further use. Disable the bootstrap setting after successful completion. No default password, password argument, bootstrap credential in logs, or secret in source. Operator database access is the primary control for this CLI; no new shared bootstrap secret is necessary unless the approved deployment requires one. Existing platform recovery remains separate from this one-time greenfield enrollment operation.

Required new tests before use: mode disabled, wrong target, existing admin, prior completion, concurrent enrollment/finalization, duplicate mailbox rejection, pending/expired activation, SMTP outage, restart recovery, audit rollback, active Native credential requirement, HCL rejection, and exactly one platform grant with no fabricated tenant membership.

## Execution order and acceptance gates

| Step | Action | Required evidence / gate |
| --- | --- | --- |
| 1 Target and recovery boundary | Identify old staging and proposed separate new database/server by safe identifiers. Confirm recoverable backup for old data before any changes involving it. | Named staging target and backup/restore owner; no permission to drop old DB implied. |
| 2 Empty database | Create a separately named, operator-approved PostgreSQL database with least-privilege application access. Verify server/database identity and emptiness. | Explicit target verification; no copied identities/data. |
| 3 Schema and catalogue | Run supported fresh bootstrap from frozen 047 through 061, then normal authenticated master-data initialization. | Revision 061; expected indexes/constraints; role/permission catalogue; zero application users before bootstrap. |
| 4 First Platform User | Implement only after bootstrap-design review; run the approved operator flow above. | BLOCKED_BOOTSTRAP_GAP; no manual SQL workaround. |
| 5 Activation and login | Deliver activation to approved test mailbox, activate with compliant password and finalize platform authority. | BLOCKED_PENDING_APPROVED_TEST_MAILBOX; encrypted outbox, audit, no normal access before activation. |
| 6 Tenant creation | First Platform User creates Olympus and MedTech through normal authorized application flows. | Correct ownership/roles and tenant isolation; no SQL fixture tenants. |
| 7 Native population | Create fresh Tenant Admin, Security Analyst, Developer and Viewer identities using approved test addresses. | Native-only identities and audited role assignments. |
| 8 Multi-tenant user | Assign SECURITY_ANALYST + DEVELOPER in Olympus; VIEWER in MedTech. | Tenant switching shows only target roles; membership disable in Olympus leaves MedTech usable. |
| 9 Password/security | Exercise forced change, change/reset, lockout, manual unlock, global disable/enable and session revocation. | Old authority denied; disabled account never restored by reset; explicit lockout recovery. |
| 10 Sessions/Redis | Two actual BFF replicas behind staging TLS ingress; logout, logout-all, reset/change revocation, outage/recovery, wrong key and expiry. | Fail closed, no memory fallback/offline writes; opaque secure cookie; product accepts 900-second re-login. |
| 11 Outbox | Real activation/reset mail, retry/exhaustion/expiry/cancellation and worker/broker crash drills. | No secret leakage; stable Message-ID; documented at-least-once boundary. |
| 12 Rotation/readiness | Rolling JWT A-to-B on every API replica, trusted-proxy spoofing tests, limiter outage and orchestrator readiness. | Public/private pair configured; overlap bounded; traffic removed from unready instances. |
| 13 Backup/restore | Backup the new test population; restore into a separate isolated DB with dispatch disabled until reconciled. | Users/roles intact, ciphertext protected, revision 061, matching PostgreSQL tools; secret retention reviewed. |
| 14 Acceptance | Complete human accessibility, expiry UX and operator runbook/recovery review. | Native acceptance signoff. Live HCL remains optional; automated HCL must pass. |

The Platform User itself is the PLATFORM_ADMIN test identity. Additional tenant-scoped test users and the multi-tenant user must be created only after activation, through that administrator's authorized workflows. No arbitrary employee/customer addresses and no old database population import.

## Current decision and next action

**NO-GO for live Native staging acceptance completion**, due to the first-user bootstrap gap, unidentified target and missing approved mailbox. These are Native rollout gates; SF user migration and live HCL accounts are no longer gates. SF source removal is out of scope.

Next action: review the operator-only Native bootstrap proposal and identify the new staging target and approved mailbox. Until then, preserve existing databases/configuration and do not implement the missing bootstrap mechanism. The earlier inventory script and SF role-mapping plan are unused artifacts of the superseded strategy and must not be run for this rollout.
