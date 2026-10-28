# Security review

The output-only label is not an authorization mechanism. Existing permission dependencies and tenant-scoped UUID resolution remain authoritative. Numeric selectors still fail 422, missing/foreign resources retain concealment, and permission denials retain 403. Display fields never feed links, selections, request bodies, query/cache keys, React keys or worker/SSE contracts.

Sensitive exceptions: no numeric Tenant, IAM User, Membership or Platform Grant keys are disclosed. Global allocation/order metadata is inappropriate in purpose-limited IAM discovery and membership views. Authorized names replace fallback UUIDs; technical provider identity details remain explicitly separate. No SBO-73 policy or RBAC changes.

Business-record integer labels do reveal their existing sequence values to users already authorized to see those records. This is the requested presentation contract, not a new lookup capability. Sequential values can have gaps and are not a reliable chronology or global volume count. Public UUID API selectors remain mandatory.

No models, migrations, constraints, defaults, PK/FK values, UUID values or original seeded accounts are changed. An explicit follow-up operator decision permits schema/fixture writes only in newly created task-owned disposable databases. Existing populated and historical databases are not connected to or altered. Only newly launched task services can be restarted. Raw credentials, sessions, tokens and private logs remain outside the repository.

Verification is recorded in TEST_RESULTS. Source review is not staging/UAT/release sign-off.

## Pre-existing issue outside this patch

Source review also found that `subscription_out()` in app/routers/report_notifications.py includes the internal `iam_user_id`, while the existing IAM path classifier does not include `/api/report-subscriptions`. This existing response field is not a new presentation field and is not widened by this patch; the UI no longer prints it. It warrants a separate IAM response-contract/privacy review. No protected live endpoint was queried to claim new execution evidence, and no directory policy is changed here.

## Service preservation evidence

Only the newly owned API18500/UI13500 process groups were started/stopped for this validation. The original API18000/UI13000 were later observed beneath a separate existing terminal's `dev.py start` process started at 17:11 IST. Their process identities therefore differ from an earlier observation; this task did not target that launcher or its children. No inference about another terminal's database actions is made, and the populated database's revision/counts are not remeasured here. The no-change claim covers this task's actions.

Task-owned API18500/UI13500 were stopped after browser verification; task Redis56393 and OSV simulation19401 were stopped after final tests. New disposable databases and protected raw evidence remain for independent review. No original service was targeted.

## Final scanner false-positive review

Gitleaks 8.30.1 with embedded default rules and inline allow directives ignored flagged five SHA256 values in the path-keyed source manifest as generic API keys. Every flagged value was independently recomputed from its named source file and matched exactly. The original manifest bytes remain protected locally. The public manifest now labels each entry with separate `path` and `sha256` fields; all 73 source hashes are unchanged. No credential was removed or suppressed, no detection rule or broad allowlist was changed, and application/test source did not change. Individual rule/line/source-file reviews appear in evidence/secret-scan-review.json.

## Final original-environment observation

A final non-SQL metadata check found no listener on original API port 18000 and no longer found its previously observed launcher process; original UI13000 remained running. The cause/operator activity was not established. No task command targeted that launcher/API/UI, and no repair or restart was attempted. This is an observation requiring independent original-environment follow-up, not a claim of preserved global uptime. The existing PostgreSQL container remained healthy with the same 2026-10-21 start timestamp. All feature/browser acceptance above used the separate task stack.
