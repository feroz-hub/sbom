# Troubleshooting

Scope: current diagnostic entry points, checked against e62951c2 on
28 October 2026. Use the same checkout/profile as the running instance.
A separate Git worktree does not isolate home-directory Greenfield resources.

## Begin with existing inspection commands

From the repository root:

    python scripts/dev.py --check --profile legacy
    python scripts/dev.py status --profile legacy

Use greenfield only for the intended installed macOS Greenfield stack.
--check is prerequisite inspection, not full schema/readiness or service startup.
status reports observed processes/services; it does not establish authenticated
application acceptance. There is no canonical doctor command.

| Symptom | Safe next step |
| --- | --- |
| Wrong ports or Mailpit UI | Check the [profile port table](../development/README.md#ports-environment-and-queues); legacy uses 8025/1025, Greenfield 8026/1026. |
| Missing Node/npm, dependencies or frontend types | --check reports Node/npm; start requires Node 20.9.0+ and prints the redacted tail of a failed pip/npm ci. --check does not prove a frontend install/build. cross-env is already declared. |
| Unowned/unknown PID or occupied API/frontend port | Inspect ownership; use [lifecycle recovery](../dev-launcher-lifecycle.md). Do not kill by port/name or delete a lock to bypass refusal. |
| Missing/untrusted Greenfield CA | The selected native adapter requires an independently approved mkcert CA. Ordinary start does not install root trust. Do not switch profiles to bypass a trust error; consult the platform matrix. |
| Missing/incomplete Greenfield state | Stop. Do not fall back to a different profile/database to bypass refusal. Review the specialist installation record and target with the operator. |
| Migration confirmation or source/schema refusal | Follow [database operations](../DATABASE_BOOTSTRAP_AND_UPGRADE.md). Ordinary start requires a current schema; explicit setup --migrate refuses a populated pre-UUID target before Alembic. Never stamp, replay history, weaken guards or drop data to make startup succeed. |
| Prior pending upgrade / unknown COMMIT | Preserve private pending marker, backup and journal; reconcile with an operator before retry/start. |
| Login failures | Compare backend/BFF/public build flags, canonical origin, issuer/audience and shared Redis. Use the [IAM guides](../security/README.md); do not disable authentication as a repair. |
| Report task queued but not delivered | Confirm a reports consumer, intended scheduler, private storage and controlled SMTP. Both profiles manage default/reports consumers and a full separate Beat with existing feature guards. See [report operations](../runbook-report-notifications.md). |
| API responds but app is not ready | Check database content in /health, /ready/iam, BFF access, workers and intended provider paths. An HTTP 200 alone is not release acceptance. |

## Logs and redaction

Legacy logs live in .dev-logs; Greenfield logs live under private
~/.sbom-greenfield-uuid. A verbose start can help reproduce a problem, but it is
still a writing/start operation. Share only reviewed, redacted excerpts and
nonsecret target identifiers. Never attach environment files, private state,
activation/reset links, authorization headers or raw customer records.

[scripts/check_database.py](../../scripts/check_database.py) masks its displayed
password but enables SQLite fallback when no target is resolved; specify the
intended target securely before using it.
[db_pool_diagnostics.py](../../scripts/db_pool_diagnostics.py) prints query text,
which may contain confidential literals. Do not publish its raw output.
Some other “check” commands also have apply/write modes: inspect their documented
arguments and privileges before running them.

## Escalation record

Record source revision, selected profile/OS, nonsecret database/server identity,
exact command, error class, last accepted schema revision and whether a write was
attempted or acknowledged. Preserve original evidence and distinguish observed
facts from assumptions. A rollback/recovery decision must account for writes
since backup and the [revision-100 restriction](../DATABASE_BOOTSTRAP_AND_UPGRADE.md).
