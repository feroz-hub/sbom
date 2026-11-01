# SBO-99 / SBO-100: platform probe spending decision

Status: temporary fail-closed policy approved by the Engineering Lead in the
FORGE chat on 2026-11-01 and implemented in this corrective pass. Durable ledger
design remains a recommendation only; no migration is included.

## Confirmed gap

Platform credential/model tests have no active tenant. `AiUsageLog` is tenant
owned, so its read/write guards correctly reject platform-scope usage. A new
BudgetGuard cannot recover earlier probe spend. Per-request caps still apply;
the daily cap is not durable for these calls. Do not fabricate a tenant, relax
tenant guards, or present platform test spending as tenant usage.

## Recommended temporary option: fail closed for billable platform probes

Approved restriction: deny potentially billable connection/model generation tests
when the execution scope is platform (no tenant), until durable platform budget
accounting exists. This includes saved and unsaved credentials and registry model
tests, before the first outbound generation request. Unknown billing/pricing is
potentially billable. Discovery remains distinct and must not mark a model tested.

Tenant-scoped tests and application generation keep their existing budgets and
authorization. Configured local and explicitly free-tier probes remain available;
the implementation must use effective server-side provider configuration, never
a browser assertion or a zero estimate for an unknown model. A configured free
tier is not evidence of provider entitlement; quota/access failures remain possible.

Blocked tests return a sanitized configuration/policy explanation and unknown
access/generation/workload states. They do not report an invalid key, disable a
credential, change selected models, fall back to another billable provider, or
write fictitious zero-cost usage. No override through a request parameter.

Implementation: one shared preflight gate for both probe entry
points, server-side scope/config inputs, existing result contracts and permission
checks retained. Activation follows the explicit approval recorded above.
Review the gate before merging; a later relaxation also requires Lead approval.

Acceptance: independent and concurrent repeated probes make zero
provider calls; saved/unsaved and registry paths behave identically; local/free
and tenant paths remain functional; blocked probes preserve credentials and do
not claim model access. Existing runtime generation and model discovery remain
unchanged. Run only mocks, with tenant and negative-authorization regressions.

Alternative: retain current probe behavior and hold PR #74 until a durable ledger
is reviewed and implemented. This is not daily-budget enforcement and cannot be
described as acceptance of the accounting requirement.

## Durable platform ledger recommendation (separate approval required)

Use platform-owned records instead of adding nullable ownership exceptions to
the tenant usage table. Proposed fields: unique logical request ID, platform
credential/model references, initiating actor, purpose, UTC timestamps, input,
reasoning-inclusive output and cached token counts, actual USD cost, estimated
reserved cost, and sanitized outcome. Use an opaque configuration revision for
attribution; never store keys, headers, prompts, outputs or key-derived hashes.

The Lead must decide the platform spending pool and daily cap. Keep platform
spend distinct from each tenant's cap; do not automatically combine balances or
charge tenants for platform administration. Define retention and actor/reference
deletion behavior before implementing foreign keys.

Reserve a bounded cost durably before the external request. Serialize concurrent
daily reservations with a transactional budget bucket/lock. Retries and fallbacks
need distinct attempt IDs under one logical request. Settle every billed success,
refusal, incomplete output and schema failure exactly once; retain a conservative
reservation for uncertain network outcomes until reconciliation. Reasoning tokens
and retry costs must be included. Ledger outages prevent new billable probes.

This likely needs additive platform usage/reservation schema and migration,
rollout/backfill policy, and changes to budget reconciliation and accounting.
No such schema change is included in PR #74. Review the design, migration,
concurrency/idempotency tests and rollback/retention plan independently first.

## Remaining merge gate

The spending-policy choice is approved. Final source review acceptance and
mandatory exact-head checks are still required before making PR #74 ready or
merging. Ledger design approval remains separate. No paid inference or deployment
is authorized.
