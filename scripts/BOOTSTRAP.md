# Local setup and prerequisites

Use only `python scripts/dev.py` for local management. See the
[lifecycle guide](../docs/dev-launcher-lifecycle.md) for profiles and recovery.

Install Python 3.11+ (python.org), Node.js 20.9+ with npm (nodejs.org), and Docker
Desktop (Windows/macOS) or Docker Engine plus Compose (Linux) when using containers.
Reopen the terminal and start Docker. Suitable local PostgreSQL/Redis can be used
with explicitly selected Legacy configuration.

```sh
python scripts/dev.py diagnose
python scripts/dev.py setup --plan
python scripts/dev.py setup
python scripts/dev.py
```

`setup --plan` only inspects existing preparation and prints actions/blockers.
Interactive setup asks for an explicit `yes` for every required category, then
rechecks the plan before applying anything. Noninteractive setup never assumes
consent. Only approved setup prepares project pip/npm dependencies and missing
leaf certificates. Ordinary start requires prepared dependencies, existing
configuration/keys and HTTPS material; it never installs, discovers credentials,
creates a database or generates keys/certificates. System software and root
certificate trust remain explicit prerequisites; TLS verification stays enabled.

Run `diagnose` before deciding which preparation is necessary. It does not apply
the setup plan, install dependencies, generate keys/certificates, change trust,
create/migrate a database, enroll users or start/stop services. `setup --check`
also takes the read-only diagnostic path; it cannot be combined with provisioning,
initialization, migration or build flags. The temporary `doctor` alias emits one
stderr deprecation notice. See [diagnostic results and exit codes](../docs/reference/configuration.md#read-only-diagnostics-sbo-98-phase-2).

See [controlled setup and recovery](../docs/reference/configuration.md#controlled-setup-and-prepared-startup-sbo-98-phase-3)
for category consent, source/configuration drift, dependency-only repair limits,
Windows private-file safeguards and retained partial artifacts. Shared operator
configuration and privileged enrollment remain separately reviewed work. Setup
does not authorize administrator creation or HCL.CS first-user provisioning.

## New Managed Legacy Native installation

This procedure is for an independently approved fresh local target, not recovery
of missing keys next to an existing database. Start the approved local PostgreSQL,
Redis and Mailpit services first. Review the exact target and obtain database
operation approval before applying; these examples are not acceptance evidence:

```sh
python scripts/dev.py setup --plan --profile legacy --legacy-config managed --initialize-database --confirm-database sbom_analyser_dev
# Only after approval, inspect and consent to the same preparation plan:
python scripts/dev.py setup --profile legacy --legacy-config managed --initialize-database --confirm-database sbom_analyser_dev
```

Supply intended database credentials interactively; do not export connection
strings or put passwords in command arguments. No repository `.env`, pgpass or
container-default credential adoption occurs. Exact-name and empty-schema checks
precede initial key generation. Existing managed files are not overwritten.
Missing/incomplete original security material must be restored, not regenerated.
Native pending-account creation and email activation remain an explicit approved
operator procedure after normal authentication/mail readiness is established.

## Greenfield

Existing private state is reused. Restore original missing private files; never
copy another developer's credentials or overwrite partial state. Install mkcert
separately and explicitly approve its development CA under your organization's
policy before asking the launcher to issue a leaf.

For a genuinely new isolated installation, review ports, pinned images and the
exact database target first:

```sh
python scripts/dev.py setup --profile greenfield --provision-greenfield --confirm-database sbom_greenfield_uuid
python scripts/dev.py setup --profile greenfield --initialize-database --confirm-database sbom_greenfield_uuid
python scripts/dev.py --profile greenfield
```

Provisioning requires consent for new containers/private state, secrets,
certificates and PostgreSQL data resources; collisions fail. Provisioning alone
does not initialize application schema: the separate initialization flag/command
is still required.
The preserved image policy uses cached pinned images without silent upgrades.
If absent, obtain the exact images in infra/greenfield-uuid/compose.yml.
Initialization requires the confirmed empty database and retains metadata/grant
checks; populated databases are refused. Account bootstrap is an explicit
[Native IAM procedure](../docs/native-iam-greenfield-setup.md).

Pending schema changes block ordinary startup. Review migrations/backups:

```sh
python scripts/dev.py setup --profile greenfield --migrate --confirm-database sbom_greenfield_uuid
python scripts/dev.py setup --profile legacy --migrate --confirm-database sbom_analyser_dev
```

Greenfield requires additional exact interactive confirmation and verified backups.
Windows pending upgrades remain blocked until native backup/restore validation.
Legacy initialization uses setup --initialize-database with its exact saved database
name; do not run against existing data. Stop the managed application before changes.

## Existing Legacy

Managed Legacy preserves .env.dev.local and the fixed development database.
Legacy setup reuses only already-running selected dependencies, whether local or
Docker; it never creates or resumes Legacy containers. Provider flags preserve
saved selections rather than authorizing a conversion. A fresh private Docker
installation uses the reviewed Greenfield path, not guessed Legacy PostgreSQL
defaults. Existing complete Docker settings can reuse their own pinned credentials.
Saved Windows/HCL.CS configuration can be selected with:

```sh
python scripts/dev.py setup --plan --profile legacy --legacy-config windows
python scripts/dev.py setup --profile legacy --legacy-config windows
python scripts/dev.py --profile legacy --legacy-config windows
```

Only literal assignments in .windows/sbom.env.ps1 are accepted; PowerShell code is
never executed. Select existing root .env explicitly with --legacy-config env.
The launcher does not switch database families or authentication modes.
A saved database Celery transport is refused until Redis is explicitly configured;
it is never silently changed.

External HCL.CS, registered redirects, approved provider CA bundles, provider
credentials and administrator accounts remain operator prerequisites. See
[HCL configuration](../docs/HCL_IAM_CONFIGURATION.md) and the
[verification matrix](../docs/engineering/dev-launcher-platform-matrix.md).

Use diagnose, status and logs --service <name> for diagnosis. Restore incomplete
certificates/private state rather than rotating credentials. Resolve occupied
ports deliberately; unrelated listeners are never killed.
Stop through verified ownership before preparation; UNKNOWN records are retained
and block it. If setup reports partial preparation, retain any new artifacts and
review `diagnose` plus a new plan; do not delete private files or reset data.

Before explicit initialization/upgrade, read the [database compatibility gate](../docs/DATABASE_BOOTSTRAP_AND_UPGRADE.md).
A populated pre-UUID database cannot cross revision 100. Inspection/stop/status
remain available without complete startup prerequisites. Required setup failures
print a redacted tail (up to 35 lines); this is distinct from application logs.
