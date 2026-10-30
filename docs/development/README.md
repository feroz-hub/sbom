# Local development

Use only `python scripts/dev.py` from a complete checkout. Read the
[lifecycle guide](../dev-launcher-lifecycle.md) for implementation, ownership,
TLS and recovery, and the [bootstrap guide](../../scripts/BOOTSTRAP.md) for
controlled setup. Production deployment uses its own Compose/runtime commands.

## Profiles and platforms

Greenfield uses private ~/.sbom-greenfield-uuid and verified fixed Docker
resources. Managed Legacy uses ignored .env.dev.local and its own fixed local
database. Existing Legacy Windows/env settings can be selected with
--legacy-config windows|env; literal PowerShell assignments are read as data,
never executed. Auto selects installed Greenfield, otherwise Legacy. Partial
state, unknown ownership or wrong-profile configuration fails without fallback.

Windows/macOS/Linux adapters exist in scripts/dev.py. The actual
[verification matrix](../engineering/dev-launcher-platform-matrix.md) separates
macOS Greenfield acceptance, Linux process smoke checks and mocked adapters.
The merged [PR #44 report](../engineering/dev-launcher-windows-lifecycle.md) records
separate Managed Legacy native Windows lifecycle evidence, not new diagnostic,
HCL.CS/browser or full Linux acceptance. Greenfield's old macOS-only helper
restriction is superseded by native trust adapters; that does not establish
full platform acceptance. Pending upgrades remain blocked on Windows until its
backup/restore procedure is verified.

The [PostgreSQL HCL build](../WINDOWS_NATIVE_SETUP.md) and
[SF.8 SQL Server HCL build](../WINDOWS_NATIVE_SETUP_SF8.md) are separate external
provider integrations. “Native Windows” does not mean the Native IAM provider.

## First development setup

Install Python 3.11+, Node.js >=20.9.0 with npm, and Docker/Compose or the explicitly
configured local data services through approved workstation tooling. Begin with
`python scripts/dev.py setup --plan`; then review the actions/blockers and obtain
the required approvals before interactive setup. Each required action category
needs explicit consent, and changed inputs require a new plan. Only authorized
setup prepares its virtualenv and content-stamped pip/npm installs.
System software and trusted root certificates are not installed silently.

Review the [database gate](../DATABASE_BOOTSTRAP_AND_UPGRADE.md) before explicit
initialization/upgrade. Ordinary start refuses an outdated schema; it does not
install dependencies, create keys/certificates, create a database, initialize,
reset or automatically upgrade it. Setup offers separately controlled
provisioning, confirmed empty-database initialization, migration and isolated
frontend build flags; see the bootstrap guide for exact commands. Never use a
populated pre-UUID database across revision 100.

First-user creation remains an explicit
[Native IAM operator procedure](../native-iam-greenfield-setup.md).
External identity services, registered redirects and approved CA bundles remain
operator prerequisites. Do not change authentication to bypass a failed scenario.

## Commands that exist

```sh
python scripts/dev.py
python scripts/dev.py setup --plan
python scripts/dev.py setup
python scripts/dev.py start
python scripts/dev.py stop
python scripts/dev.py restart
python scripts/dev.py status
python scripts/dev.py diagnose
python scripts/dev.py logs --service reports --lines 80
python scripts/dev.py --check
```

No command means start. `diagnose` is read-only; `--check` and `setup --check` use
the same inspection path. `doctor` is temporarily accepted with one stderr
deprecation notice. Diagnostic mutation-flag combinations are refused before
preparation. See [diagnostic results and exit codes](../reference/configuration.md#read-only-diagnostics-sbo-98-phase-2).
Start/restart run in
the foreground; keep that terminal open and use another for inspection/stop.
Only verified launcher-owned processes are managed. Stop preserves data services,
volumes, credentials and logs. Missing startup prerequisites do not block stop/status.

Diagnostics neither install nor repair an environment. A missing configuration,
pending migration, uncreated/pending administrator or untrusted certificate needs
an explicitly authorized corrective action. HCL.CS first-eligible-user privileged
provisioning still requires Engineering Lead and identity-provider-owner approval.
Do not change providers, enable a bypass or create an administrator to make a check
pass. Read the [controlled setup and recovery contract](../reference/configuration.md#controlled-setup-and-prepared-startup-sbo-98-phase-3), including
explicit dependency-repair safeguards and retained partial artifacts. Use
`setup --plan --repair-dependencies` to review a pinned repair; only subsequent
category consent permits installers, and private-material/ownership gates remain.
Startup/build verify the already-installed native compiler without invoking
Next's downloader. Ordinary start/diagnostics never perform that repair. Setup also
requests `frontend-workspace` consent for linked source/dependencies and verified
public configuration copies. Node runtime/build use the [projected environment
and isolated workspace](../reference/configuration.md#component-environments-and-frontend-workspace-sbo-98-phase-4);
source private environment files remain untouched. Shared operator-script
configuration remains later work; setup/diagnostics never authorizes enrollment.

## Ports, environment and queues

The verified macOS Greenfield frontend/API are https://localhost:13000 and
http://127.0.0.1:18000. Other installations use selected/saved ports; do not
assume universal defaults. The lifecycle guide contains profile-specific
PostgreSQL/Redis/Mailpit ports and saved Windows configuration behavior.

Both profiles start separate default celery and reports queue consumers and one
separate full application Beat. Linux uses prefork; macOS/Windows use solo.
Greenfield preserves its 10-second mail cadence and the application's existing
feature/security guards. No manual workers or second Beat should be started.

Authenticated PostgreSQL/Redis connectivity, worker control responses, queues
and owned PIDs, connected-consumer heartbeats, scheduler ticks, API database/IAM
readiness where applicable, and verified HTTPS are required before readiness.
Actual report mail/provider/browser acceptance still needs controlled scenarios.
A saved database-backed Celery broker is refused until Redis is explicitly
configured; the manager never silently changes that transport.

See [configuration precedence](../reference/configuration.md) and
[report operations](../runbook-report-notifications.md) for production distinctions.

## Recovery and limitations

Do not use another profile, kill an unrelated port owner, rotate keys or reset
data to bypass a refusal. Preserve unresolved journals, backup material and
ownership records for diagnosis. Use status, diagnose and redacted logs, then
[operations troubleshooting](../operations/troubleshooting.md).

Do not start the same private home-directory Greenfield installation from two
worktrees. A Git worktree does not isolate runtime databases, credentials or
services. Full platform/provider/login/release acceptance remains separate from
unit or process-smoke results.
