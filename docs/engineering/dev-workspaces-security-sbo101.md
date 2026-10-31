# SBO-101: privileged enrollment design for independent approval

Status: proposed security design; live initial Native creation and resend remain
unconditionally disabled in the SBO-98 managed adapter. This document is not
authorization to enable them. No provider, database, credential or trust change
has been executed for this design.

## Local threat model

The developer controls the launcher, its Python modules, arguments, environment,
working directory and user-owned JSON files. A local attacker with those same
permissions can forge a ready marker, edit a registry descriptor, replay a copied
plan, invoke a private child directly or replace configuration between checks.
TTY confirmation and a plan fingerprint detect accidental drift; neither
authenticates an independent privileged operator. Docker labels and supplied
inspect JSON do not independently prove engine/resource ownership.

A process with database-owner credentials can bypass Python services with SQL.
An effective privileged boundary therefore needs a distinct authority and
credential principal that the ordinary developer/runtime cannot impersonate.
Compromise of the host administrator, container daemon administrator, database
owner or the approved authority itself is outside a user-mode launcher's
protection. These principals must be controlled through workstation/provider
policy and least privilege, not described as protected by JSON checks.

The initial implementation supplies immutable guidance and negative synthetic
tests only. A caller-supplied status can inform a proposal; it cannot unlock the
private enrollment child or authorize a database mutation. Existing, pending and
completed reservations are never reopened by guidance.

## Proposed authority contract

Engineering Lead and security approval must select the independent authority,
its operator authentication, signing-key custody and revocation store before
implementation. No new secret or provider identity should be invented by setup.
The ordinary runtime should use a restricted role that cannot directly create
bootstrap reservations, assign platform authority or modify the authorization
ledger. Whether a separate narrowly privileged service or an approved brokered
operator process enforces that boundary is an open architecture decision.
The existing activation finalizer grants authority through the application's
database session. Any proposed role restriction must explicitly preserve that
approved transaction through a reviewed narrowly privileged path; it cannot
silently revoke required privileges or claim the present runtime is already
restricted this way. Activation-time privilege and audit atomicity are part of
the pending security/DBA design, not changes implemented by this increment.

An authenticated operator approves an exact, redacted operation plan. The
authority issues a short-lived, single-use capability bound to:

- Repository/worktree/instance and independently observed process generation.
- Engine, provider, network, volume and exact database identity; schema revision.
- Validated configuration generation, authentication mode and action
  (`initial-create` or separately approved `resend`).
- Exact intended identity and operator/change reference, held through a private
  channel; public plans contain neither identity details nor passwords.
- Approved isolated mail transport and canonical verified HTTPS activation origin.
- Independently observed Redis, default/reports worker, Beat and API/IAM readiness.
- Authenticated operator, issuer, audience, nonce, expiry and revocation identity.

Readiness evidence must originate from the approved observer/authority and be
bound to current resource/process identities. A launcher PID, timestamped file,
environment flag, `live_readiness_verified` Boolean, HTTP 200 alone or copied
descriptor cannot substitute for that evidence. Configuration generations are
opaque public references; do not publish hashes of low-entropy private values.

## Child, transaction and commit boundaries

1. The private child independently validates signature/issuer/audience, operator
   authority, nonce, expiry/revocation and every target/action/identity binding.
   Direct invocation without authority fails before application startup or any
   database write. Do not accept a parent-provided trusted marker or Boolean.
2. The approved database adapter verifies the exact pinned provider/target and
   connects using the selected restricted privilege path. It rechecks schema,
   effective administrators and durable singleton reservation under the existing
   approved service transaction and lock semantics.
3. Immediately before the privileged mutation, revalidate current resource,
   configuration, operator capability and readiness evidence. Changed or unknown
   evidence aborts. The transaction must atomically record capability consumption,
   reservation and audit outcome, or use an approved equivalent that fails closed
   on partial/network failure. A retry cannot consume the capability twice.
4. Before commit, recheck expiry/revocation and critical target/identity evidence.
   The exact cross-service atomicity, revocation/commit race and recovery protocol
   require security/DBA review; a preflight check alone is insufficient.
5. Reuse the existing Native bootstrap and activation services. Keep the
   singleton reservation, audited encrypted outbox, identity validation, Argon2id
   password handling and atomic effective-platform-grant completion. Never insert
   users, passwords, grants or reservation rows directly through a new SQL path.

Unknown consumption/commit outcomes preserve state and require an approved status
inspection. They never trigger another creation attempt, reservation deletion,
credential rotation or automated resend. The completed reservation remains
durable if its original administrator is later disabled or removed.

## Human activation and external identities

After separately approved delivery to the isolated Mailpit mailbox, the human
opens the activation page over verified HTTPS in the intended browser context
and chooses a compliant password there. Passwords never pass through AI chat,
shell arguments, plan files, fixtures or issues. Status must verify the effective
administrator grant and audit completion through an approved inspection before
the temporary creation capability is disabled. No tenants or tenant roles are
seeded by this flow.

HCL.CS/Entra uses its external identity and approved grant procedure. Native
password onboarding is not offered as an external-provider fallback. The
Engineering Lead and IdP owner must approve any first-eligible-user privileged
procedure separately, including registration/callback/issuer/audience and trust.

## Required approval and disposable acceptance

Approval must cover authority/principal deployment, token/revocation/consumption
protocol, DB privileges/atomicity, independently authenticated readiness and the
exact disposable target/mail/HTTPS resources. Only then may an implementation
enable the existing guard and run approved A01–A15 acceptance.

Negative tests must include direct child/service invocation, fabricated flags or
files, expired/revoked/replayed capability, configuration/provider/process drift,
wrong recipient/action/SMTP/origin, duplicate/concurrent create, pending/completed
reservation, partial authority/database failure and revocation during commit.
Synthetic tests of a permanently closed adapter prove refusal; they do not prove
an enabled authority protocol, cross-tenant behavior or live activation safety.

Until those decisions and tests are approved, guided setup may inspect approved
status and present next steps, but creation and resend remain **BLOCKED**.
