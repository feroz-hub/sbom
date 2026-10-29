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

From the repository root, using your Python 3.11+ executable:

    python scripts/dev.py --check --profile legacy
    python scripts/dev.py start --profile legacy

Use python3 where that is your configured executable. For an **already installed
macOS Greenfield environment**, select --profile greenfield instead. Greenfield's
current trust verifier blocks Windows and Linux; the legacy lifecycle contains
OS-specific Windows/Linux/macOS implementations, with current end-to-end
acceptance unverified in this documentation phase.

Start is a writing operation: legacy can install dependencies, create its local
database, generate local keys and apply migrations. Greenfield can request a
confirmed upgrade after backup/restore verification. --check does not start
services or migrate and is not full readiness/schema acceptance. Read the
[profile and platform details](docs/development/README.md#profiles-and-platforms).

## Development commands

    python scripts/dev.py status --profile legacy
    python scripts/dev.py stop --profile legacy
    python scripts/dev.py restart --profile legacy
    python scripts/dev.py start --profile legacy --verbose

Use the same checkout and intended profile. Stop/Ctrl+C preserve data services and
volumes. Application URLs are https://localhost:13000 and
http://127.0.0.1:18000. Auto selection is available but depends on existing
home-directory Greenfield state. There is no canonical doctor or setup command.

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
