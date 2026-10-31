# Local setup and prerequisites

Use only `python scripts/dev.py` for local management. See the
[lifecycle guide](../docs/dev-launcher-lifecycle.md) for profiles and recovery.

Install Python 3.11+ (python.org), Node.js 20.9+ with npm (nodejs.org), and Docker
Desktop (Windows/macOS) or Docker Engine plus Compose (Linux) when using containers.
Reopen the terminal and start Docker. Suitable local PostgreSQL/Redis can be used
with explicitly selected Legacy configuration.

```sh
python scripts/dev.py diagnose
python scripts/dev.py setup
python scripts/dev.py
```

Project pip/npm dependencies and safe missing leaf certificates are prepared;
existing configuration/keys are preserved. System software and root certificate
trust are explicit prerequisites. The launcher never approves root trust or
bypasses TLS verification.

Run `diagnose` before deciding which preparation is necessary. It does not apply
the setup plan, install dependencies, generate keys/certificates, change trust,
create/migrate a database, enroll users or start/stop services. `setup --check`
also takes the read-only diagnostic path; it cannot be combined with provisioning,
initialization, migration or build flags. The temporary `doctor` alias emits one
stderr deprecation notice. See [diagnostic results and exit codes](../docs/reference/configuration.md#read-only-diagnostics-sbo-98-phase-2).

The SBO-98 controlled setup wizard and shared operator-script configuration are
later phases. Existing `setup` remains a preparation command, not a newly approved
installer or administrator-enrollment flow. Review its explicit actions and obtain
authorization before database preparation or privileged enrollment; diagnostics
do not grant that authorization.

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

Provisioning creates only the fixed new containers/private state; collisions fail.
The preserved image policy uses cached pinned images without silent upgrades.
If absent, obtain the exact images in infra/greenfield-uuid/compose.yml.
Initialization requires the confirmed empty database and retains metadata/grant
checks; populated databases are refused. Account bootstrap is an explicit
[Native IAM procedure](../docs/native-iam-greenfield-setup.md).

Pending schema changes block ordinary startup. Review migrations/backups:

```sh
python scripts/dev.py setup --profile greenfield --migrate
python scripts/dev.py setup --profile legacy --migrate --confirm-database sbom_analyser_dev
```

Greenfield requires additional exact interactive confirmation and verified backups.
Windows pending upgrades remain blocked until native backup/restore validation.
Legacy initialization uses setup --initialize-database with its exact saved database
name; do not run against existing data. Stop the managed application before changes.

## Existing Legacy

Managed Legacy preserves .env.dev.local and the fixed development database.
Saved Windows/HCL.CS configuration can be selected with:

```sh
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

Before explicit initialization/upgrade, read the [database compatibility gate](../docs/DATABASE_BOOTSTRAP_AND_UPGRADE.md).
A populated pre-UUID database cannot cross revision 100. Inspection/stop/status
remain available without complete startup prerequisites. Required setup failures
print a redacted tail (up to 35 lines); this is distinct from application logs.
