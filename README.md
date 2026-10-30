# SBOM Analyser

SBOM Analyser is a FastAPI and Next.js platform for SBOM validation, inventory,
vulnerability analysis, lifecycle intelligence, VEX, remediation and reporting,
with tenant isolation and database-backed authorization. It organizes Projects,
Applications and SBOM versions, combines multi-source vulnerability/KEV evidence,
and supports run comparison, controlled repair and report exports.

Application version: **2.0.0**. The source schema head verified on 29 October 2026
is **103_tenant_admin_governance**; this does not identify any deployed database.

## Architecture

The Next.js/React frontend uses an authenticated BFF to reach the FastAPI modular
monolith. PostgreSQL stores application data; Celery and Redis handle background
work. FastAPI independently enforces tenant membership and permissions.
See the [architecture overview](docs/architecture/overview.md).

## Getting started

Read the [development guide](docs/development/README.md) and choose a profile
before starting. Python 3.11+, Node.js/npm, PostgreSQL and Redis are required for
the normal development stack. The locked Next.js package requires Node >=20.9.0;
the full dependency/toolchain compatibility remains subject to validation.

From the repository root:

```sh
python3 scripts/dev.py
```

Use python where that is your configured Python command. scripts/dev.py is the
only public local development manager. Review `setup --plan` and explicitly
authorize required preparation with `setup`. Ordinary start uses the prepared
dependencies/configuration, verifies selected data services, then starts two Celery consumers (default
and reports), exactly one separate Beat, FastAPI and HTTPS Next.js. Readiness
requires real consumer/queue responses and scheduler progress, API database/IAM
readiness where applicable, and verified HTTPS.

## Development commands

```sh
python3 scripts/dev.py setup --plan
python3 scripts/dev.py setup
python3 scripts/dev.py start
python3 scripts/dev.py stop
python3 scripts/dev.py restart
python3 scripts/dev.py status
python3 scripts/dev.py diagnose
python3 scripts/dev.py logs --service reports --lines 80
```

No command means start; `diagnose` is read-only and `--check` is its compatibility
form. `doctor` remains a temporary alias with one deprecation notice on stderr.
`setup --plan` is read-only; interactive setup requires category-specific consent
and rechecks its inputs before changes. See [controlled setup and recovery](docs/reference/configuration.md#controlled-setup-and-prepared-startup-sbo-98-phase-3).
The `frontend-workspace` action prepares live source links and owned public config
copies. Node runtime/build use an [isolated workspace and projected environment](docs/reference/configuration.md#component-environments-and-frontend-workspace-sbo-98-phase-4)
without backend-only secrets; existing private environment files remain untouched.
See the [diagnostic contract](docs/reference/configuration.md#read-only-diagnostics-sbo-98-phase-2)
for checks, statuses, exit codes and limitations. Start/restart stay
in the foreground. Stop/Ctrl+C manage only verified owned application processes
and preserve data services, credentials, certificates and volumes. Port/name/PID
alone never authorizes termination. Required setup failures show a redacted tail;
application logs are available through logs.

### Profiles and persisted data

Auto selects an installed Greenfield private directory, otherwise Legacy. An
incomplete installation fails without selecting another profile/database. Pin
--profile greenfield or --profile legacy when needed; an existing runtime also
pins its Legacy configuration family.

| Profile | Saved configuration | PostgreSQL | Redis | Mailpit UI/SMTP |
| --- | --- | --- | --- | --- |
| Greenfield | Private ~/.sbom-greenfield-uuid | sbom_greenfield_uuid, 56044 | 56381 | 8026/1026 |
| Managed Legacy | Ignored .env.dev.local | sbom_analyser_dev, Docker 55439 or saved local port | Docker 56379 or saved local port | 8025/1025 |
| Existing Legacy Windows/env | Literal .windows/sbom.env.ps1 or explicitly selected .env | Saved local database, isolated from Greenfield | Saved Redis | Saved settings |

The verified macOS Greenfield URLs are https://localhost:13000 and
http://127.0.0.1:18000. Other installations use their reported/saved URLs;
Windows/env configurations retain saved ports (defaults 8000/3000 when absent).
Use --legacy-config managed|windows|env to select the intended family. Saved
PowerShell is parsed as literal assignments, never executed.

Ordinary start requires prepared dependency stamps, saved keys/configuration and
existing HTTPS material. It does not install, create credentials/certificates,
discover database credentials, create a database or initialize/upgrade schema.
Provisioning, empty-database initialization and migration require
explicit setup controls in [bootstrap guidance](scripts/BOOTSTRAP.md), with
confirmed targets and the [database gate](docs/DATABASE_BOOTSTRAP_AND_UPGRADE.md).
Do not reset data or rotate credentials to bypass a refusal.

The launcher contains Windows/macOS/Linux adapters. Prior Managed Legacy native
Windows lifecycle acceptance is recorded in the merged [PR #44 report](docs/engineering/dev-launcher-windows-lifecycle.md);
it does not establish new diagnostic, HCL.CS/browser or full Linux acceptance.
Pending Greenfield upgrades are blocked on Windows until native backup/restore validation. See the
[verification matrix](docs/engineering/dev-launcher-platform-matrix.md) and
[lifecycle guide](docs/dev-launcher-lifecycle.md). Trust is never installed silently
and TLS verification remains enabled. External identity providers and initial
administrators remain explicit operator prerequisites.

## Supported SBOM formats

The detector recognizes CycloneDX 1.4–1.6 JSON/XML and SPDX 2.2/2.3 JSON and
Tag-Value. SPDX 3.0 JSON-LD, SPDX RDF/XML and CycloneDX Protobuf remain deferred.
See the [validation guide](docs/sbom-validation.md) and
[detector](app/validation/stages/detect.py) for limits and rejection behavior.

## Database migrations

**Do not run a production upgrade across an unsupported revision.**
Revision 100_greenfield_uuid_final refuses populated application tables.
Fresh installation, an existing compatible UUID installation and a populated
pre-UUID installation require different decisions; no populated pre-UUID upgrade
is approved by these documents. Use the
[database operations guide](docs/DATABASE_BOOTSTRAP_AND_UPGRADE.md) before any
bootstrap, Alembic or deployment command.

## Documentation

Start with the [documentation index](docs/README.md).

| Subject | Guide |
| --- | --- |
| Architecture | [Current application structure](docs/architecture/overview.md) |
| Development setup and platforms | [Developer guide](docs/development/README.md) |
| Tests and quality checks | [Testing guide](docs/testing/README.md) |
| Configuration | [Profiles, environment precedence and build/runtime settings](docs/reference/configuration.md) |
| Deployment | [Ubuntu Docker procedure and its limitations](docs/UBUNTU_DOCKER_DEPLOYMENT.md) |
| Security and IAM | [Identity providers, sessions and operator runbooks](docs/security/README.md) |
| Troubleshooting | [Safe diagnosis and escalation](docs/operations/troubleshooting.md) |
| Historical records and storage | [Navigation and proposed retention strategy](docs/documentation-storage-strategy.md) |

## Contributing

Keep changes tenant-aware, permission-checked, migration-safe and reviewable.
Preserve public UUID contracts, metric conventions and cache invalidation.
Run relevant checks on disposable resources and report failures and unverified
acceptance honestly. Never commit credentials, private keys or runtime data.
