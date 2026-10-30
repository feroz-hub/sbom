# Troubleshooting

Scope: read-only SBO-98 diagnostics, controlled setup and existing recovery entry points.
Use the same checkout/profile as the running instance.
A separate Git worktree does not isolate home-directory Greenfield resources.

## Begin with existing inspection commands

From the repository root:

    python scripts/dev.py diagnose --profile legacy
    python scripts/dev.py status --profile legacy

Select Greenfield only for the intended private installation. `diagnose` performs
bounded read-only dependency, configuration, target/schema, authentication,
certificate and service observations. `--check`, including `setup --check`, uses
the same path; mutation flags are refused. `doctor` remains a temporary alias
with one stderr deprecation notice. See the [diagnostic contract](../reference/configuration.md#read-only-diagnostics-sbo-98-phase-2).
`status` reports observed processes/services. Neither command establishes browser,
provider-login, SMTP-delivery or full-stack acceptance, nor authorizes repair.

| Symptom | Safe next step |
| --- | --- |
| Wrong ports or Mailpit UI | Check the [profile port table](../development/README.md#ports-environment-and-queues); legacy uses 8025/1025, Greenfield 8026/1026. |
| Missing Node/npm, dependencies or frontend types | Review setup --plan --repair-dependencies for pinned Python/npm repair. Installers run only after project-dependencies category consent; scope, private-material and ownership gates remain. Ordinary start/diagnostics never perform repair. |
| Native compiler missing/incompatible or probe timeout | Check the selected Node architecture and approved installed native SWC package; review the dependency-repair plan. The bounded startup/build probe never invokes Next's downloader. Unconfirmed owned-probe cleanup requires independent inspection, not killing a saved/unrelated PID. |
| Missing/ambiguous configuration or wrong database target | Check selected profile/family and safe provenance. Preserve private files; do not export a connection string or switch profiles to bypass refusal. |
| Setup declined, inputs changed or partial preparation reported | Decline/cancellation before apply makes no preparation changes. Changed fingerprints require a new plan. Failed apply can retain authorized new artifacts; preserve them, diagnose and obtain recovery review instead of deleting files or resetting data. |
| Frontend workspace missing/stale or unverified | Review setup --plan for the frontend-workspace action. Owned unchanged public copies may be refreshed only by authorized setup. Preserve unexpected files, redirected links and workspace .env files for review; never copy private environment files into the generated workspace. |
| Next-only source environment or CA/Node-option review required | Review the selected authoritative profile and original source files without deleting them. Missing approved frontend fallback settings, ambiguous CA directories and unsupported preload/TLS options are not silently adopted/discarded. Never set TLS rejection to 0 to bypass the gate. |
| Missing Native administrator or pending activation | Review aggregate enrollment state, mail/worker and HTTPS prerequisites. Use only authorized existing bootstrap/activation services; diagnostics create no user, token or grant. |
| HCL.CS first eligible user unavailable | Escalate the privileged provisioning design to the Engineering Lead and identity-provider owner. Do not substitute Native enrollment, direct SQL or an auth-disabled grant. |
| Unowned/unknown PID or occupied API/frontend port | Inspect ownership; use [lifecycle recovery](../dev-launcher-lifecycle.md). Do not kill by port/name or delete a lock to bypass refusal. |
| Missing/untrusted Greenfield CA | The selected native adapter requires an independently approved mkcert CA. Ordinary start does not install root trust. Do not switch profiles to bypass a trust error; consult the platform matrix. |
| Missing/incomplete Greenfield state | Stop. Do not fall back to a different profile/database to bypass refusal. Review the specialist installation record and target with the operator. |
| Migration confirmation or source/schema refusal | Follow [database operations](../DATABASE_BOOTSTRAP_AND_UPGRADE.md). Ordinary start requires a current schema; explicit setup --migrate refuses a populated pre-UUID target before Alembic. Never stamp, replay history, weaken guards or drop data to make startup succeed. |
| Prior pending upgrade / unknown COMMIT | Preserve private pending marker, backup and journal; reconcile with an operator before retry/start. |
| Login failures | Compare backend/BFF/public build flags, canonical origin, issuer/audience and shared Redis. Use the [IAM guides](../security/README.md); do not disable authentication as a repair. |
| Report task queued but not delivered | Confirm a reports consumer, intended scheduler, private storage and controlled SMTP. Both profiles manage default/reports consumers and a full separate Beat with existing feature guards. See [report operations](../runbook-report-notifications.md). |
| API responds but app is not ready | Use diagnose's read-only database/schema inspection, inert API identifier and selected Native readiness checks, then inspect worker/provider failures. Do not treat /health as an inert probe: its NVD settings path can attempt a seed. An HTTP 200 alone is not release acceptance. |

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
