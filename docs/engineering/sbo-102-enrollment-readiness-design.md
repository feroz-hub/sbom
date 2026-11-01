# SBO-102: first Native administrator readiness design

Status: **PROPOSED — Engineering Lead/security approval required before implementation.**
Date: 2026-11-01. Baseline: `dev` at `cd8440586fb249d06eb00522f32ea3012be73bb9`.

This change repairs read-only status inspection only. Both
`default_readiness_checker()` and `_require_mutation_authorization()` in
`scripts/dev_native_enrollment.py` continue to refuse with
`ENROLLMENT_READINESS_CONTRACT_REQUIRED`. Passing diagnosis, possessing local
database credentials, a terminal confirmation, a correlation marker, and a
configuration fingerprint are not privileged enrollment authorization.

## Trust and approval boundary

The proposed first implementation is limited to the approved local Windows
Managed Legacy Native configuration. Other profiles and remote mail delivery
remain closed until separately reviewed. Assume the OS account, reviewed source,
protected approval-verifier configuration and approved runtime executables are
trusted. A malicious local administrator who can replace these is outside that
boundary; filesystem permissions do not protect against that administrator.

Security approval must name the operator's verified Windows identity/SID, an
independently approved normalized recipient, environment/instance, action
(`create` or `resend-activation`), exact database endpoint/name and schema head,
activation origin/path, mail destination, and approved source revision. Existing
users require an explicit identity/collision review. No existing identity is
silently linked and no existing role is upgraded by the enrollment command.

Proposed machine-checkable authorization: a short-lived signed approval envelope
issued by an Engineering Lead controlled signer, whose verification key is
installed through a separate approved protected configuration channel. The
enrolling operator must not be able to mint approvals by editing dotenv or CLI
arguments. Bind the envelope to the fields above, a unique approval ID, expiry,
action/recipient and a hash of the readiness evidence. Do not reuse Native JWT,
session or outbox keys for this purpose. Proposed maximum lifetime: five minutes,
subject to security approval. Clock anomalies, missing trust anchors, unsupported
versions, or unverifiable identities fail closed. The signer/key distribution
and verification mechanism are open approval decisions, not implemented here.

## Evidence contract

Collect bounded, fresh evidence from each actual running component. Every response
must bind a fresh challenge, process start identity (not PID alone), instance ID,
reviewed code/configuration generation and expiry to an authenticated local
channel. A caller-supplied JSON report, environment variable, generic health 200,
PID file or hash is insufficient. Proposed Windows transport: an ACL-restricted
named pipe with peer process/token verification; the protocol and its trusted
registration path require separate review. Do not expose an unauthenticated
HTTP endpoint that returns secrets or enables bootstrap.

| Required evidence | Required verification / refusal condition |
| --- | --- |
| Running configuration | API, frontend, default/reports workers and Beat attest the same selected instance and generation. Verify source/dependency identity and effective settings, including private-file identity and no unselected dotenv fallback. Restart or drift invalidates evidence. |
| Native IAM | Actual API and worker Settings have authentication, Native IAM and user creation enabled; development bypass, HCL and Entra modes are off for this flow. Database authorization catalogs and tenant-role assignments fail closed. Validate original RSA signing material and independent session/outbox keys without revealing them. |
| Database | Pin explicit connection keywords; reject ambient libpq overrides. Verify loopback endpoint/port, `current_database()`, approved role and one current schema marker in both status and the future write transaction. Database name alone is not server identity; bind the provisioned instance identity and approved cluster identity to runtime registration. Decide a least-privilege cluster identity mechanism before implementation; do not grant superuser access for inspection. |
| Operator / recipient | Verify signed approval and current OS identity. Bind normalized recipient, action and all entered identity fields to confirmation and the child. A typed operator reference is audit metadata, not identity proof. Resend must match the permanently reserved user. |
| Activation HTTPS | Pin exact approved HTTPS origin and activation path; require host/chain verification against approved local trust, no insecure TLS override or redirects to another origin. Verify effective mail URL and served frontend/API configuration agree. Reject credentials/fragments/unapproved query changes in the base URL. |
| Encrypted outbox | Verify enabled delivery, AES-GCM configuration and distinct original outbox key. Every issuance uses the existing transactional encrypted outbox; no token appears in console, logs, task payloads or approval artifacts. Key availability must be demonstrated by the actual worker without persisting a probe token. |
| SMTP / Mailpit | For the initial local scope, bind approved loopback Mailpit SMTP and UI/API endpoints to the owned process; EHLO is readiness evidence only. Disable external forwarding/relay. Explicitly approve who can access the local mailbox because it receives a privileged activation credential. No test message during status. Nonlocal SMTP requires separate TLS, recipient and delivery approval. |
| Workers / Beat | Verify owned process identity, effective configuration, default/reports routing, outbox dispatcher schedule and fresh progressing heartbeats from exactly one Beat. Queue reachability alone does not prove key/configuration agreement or delivery. |
| Redis sessions / rate limits | Verify effective dedicated logical databases/namespaces and transport/auth, fail-closed rate-limit settings, and session encryption. Read-only PING does not establish Lua/expiry semantics; use evidence from the separately approved compatibility check, bound to the current endpoint/configuration/version. No FLUSH, test login or Redis mutation during status. |
| Reservation / audit | Recheck no usable administrator and singleton state under the existing advisory lock. Persist approval/action/instance/source and outcome metadata without secrets; refusal and uncertain outcomes must be attributable. Approval-use tracking and audit persistence require a reviewed transactional schema or existing suitable mechanism before implementation. |

Fresh evidence must be checked before the child imports application services,
before create/resend, and immediately before commit. The child independently
verifies the approval and runtime evidence; parent checkers cannot grant it
authority. Keep the existing source/configuration fingerprint and
`Settings(_env_file=None)` isolation as additional drift checks. Do not toggle
bootstrap on persistently in the runtime configuration. Any authorized child-only
bootstrap setting is scoped to the reviewed operation and cannot be reused by
ordinary setup/startup.

## Transaction, replay and concurrency

1. Read-only status and diagnosis produce evidence, never a reservation or token.
   Obtain independent approval; privately collect identity details and display
   the exact approved action/target for terminal confirmation.
2. In the fresh authorized child, verify the envelope, operator, target, source
   and runtime attestations. Open a bounded transaction using pinned keywords;
   verify database identity/schema again. Acquire the existing bootstrap advisory
   lock (`734621062`) before user/token locks, preserving existing lock ordering.
3. Atomically claim the single-use approval ID in the same transaction as the
   operation. A new durable unique approval-use record is proposed, but its schema
   and lifecycle need approval. Recheck administrator eligibility, singleton
   reservation, existing-user evidence and recipient/identity collisions.
4. Call only `native_platform_bootstrap.create()` or `.resend()`. Existing create
   reserves `NativePlatformBootstrap(id=1)` permanently and creates a pending
   Native identity, activation token hash, encrypted outbox item and audits in
   one transaction. It does not grant a usable administrator role. Resend must
   preserve the reserved identity and invalidate prior unconsumed tokens through
   the existing token service. Each resend needs a new approval and cooldown.
5. Revalidate authorization/evidence before commit. Roll back on any failure.
   After a lost commit acknowledgment, return `OUTCOME_UNCONFIRMED`; inspect by
   approval ID and status before considering a retry. Do not automatically issue
   another token or delete/reset the singleton or approval record.
6. Workers deliver committed encrypted outbox entries through existing services.
   SMTP can duplicate delivery after acceptance/commit ambiguity; retries reuse
   the same token/message identity and never create another account. A mailbox
   delivery failure leaves the permanent pending reservation available only for
   explicitly authorized recovery/resend.
7. Recipient uses the trusted HTTPS activation flow. Existing
   `native_auth_service.activate()` validates password policy, takes bootstrap
   locks, consumes a purpose/user/email-bound unexpired token atomically, sets
   credentials and invokes `native_platform_bootstrap.finalize()` in the same
   transaction. Privileges are granted only by the existing platform service.
   Expired/replayed tokens, changed email, duplicate activation and competing
   administrators must fail without partial privileges.

## Security risks and required decisions

- Local mailbox access is equivalent to possession of the activation credential.
  Decide whether local Mailpit is acceptable for this development administrator
  and which OS users can access it. Do not infer mailbox ownership from SMTP EHLO.
- Approval trust distribution and runtime peer authentication are not provided by
  today's diagnosis. These are implementation blockers, not optional hardening.
- Time-of-check/time-of-use remains between independent runtime components.
  Specify a short validity window and configuration-generation lease that blocks
  reconfiguration during the transaction, or fail when such a lease cannot be
  proven. A hash/heartbeat alone cannot close that race.
- Decide durable approval-use/audit retention and schema changes, lock ordering,
  lock/statement deadlines, denied-attempt logging and resend quotas. Avoid PII
  and token/recipient leakage through failure messages or timing.
- Protected key backup/recovery must precede enrollment. Never regenerate keys
  to resolve a status error, automatically delete reservations, or recover by SQL.
- Engineering Lead must separately approve the implementation design and a named
  disposable test environment; then approve any deployment, migration and actual
  privileged enrollment. This document and the status fix grant none of those.

## Validation required after approval

First run mocked tests for every missing/mismatched/expired/forged evidence field,
operator/recipient changes, child isolation, secret redaction and default denial.
Then, only in a separately approved disposable PostgreSQL/Redis/Mailpit instance,
test fresh enrollment through real HTTPS activation, expired/replayed tokens,
create/create, create/resend and activation/activation races, existing admin and
identity collisions, restart/config drift at each boundary, lost commit replies,
SMTP ambiguity, outbox key mismatch, worker/Redis outages, approval replay and
audit completeness. Prove one reservation, at most one usable administrator from
this flow and no partial roles after rollback. No such mutation, email or
concurrency test has been run against `sbom_analyser_dev`.
