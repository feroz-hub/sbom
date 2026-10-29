# Development setup and lifecycle

Authoritative entry for developer startup. Source checked: e62951c2,
28 October 2026; launcher preflight, queue and platform behavior updated
29 October 2026. Use [scripts/dev.py](../../scripts/dev.py) from the repository
root with a Python 3.11+ executable (python or python3 as installed).

## Profiles and platforms

Profile names describe different environments, not application schema versions.
In particular, legacy does not approve use of an old populated pre-UUID database.

| Profile | Windows | Linux | macOS |
| --- | --- | --- | --- |
| legacy | Windows lifecycle/process branches and solo worker exist; current full-stack acceptance unverified. | POSIX lifecycle and Linux ownership branches exist; current full-stack acceptance unverified. | macOS ownership branches exist; current full-stack acceptance unverified. |
| greenfield | Current trust verifier blocks startup; additional Unix socket/ownership assumptions exist. | Current trust verifier blocks startup outside macOS. | Implementation requires an existing trusted mkcert CA, private state and recorded Docker resources; current full-stack acceptance unverified. |
| auto | Uses legacy, with a note if Greenfield state exists. | Uses legacy, with a note if Greenfield state exists. | Selects greenfield when the home-directory installation exists, including an incomplete one; otherwise legacy. |

An explicit --profile greenfield is refused on Windows and Linux before any
Greenfield code runs (stop remains available), as are the direct Greenfield
setup entry points. The [Greenfield HTTPS implementation](../../scripts/greenfield_https.py)
explicitly requires macOS Keychain verification.
[Greenfield resource code](../../scripts/greenfield_uuid.py) also assumes Unix
sockets, ownership/mode checks and POSIX paths. This is a source-based limitation,
not an approved cross-platform support matrix.

HCL-specific Windows setup is a separate integration procedure. Select the
[PostgreSQL HCL build guide](../WINDOWS_NATIVE_SETUP.md) or
[SF.8/SQL Server HCL guide](../WINDOWS_NATIVE_SETUP_SF8.md) according to the
identity-provider build. Neither changes the meaning of the dev.py profiles.

## First development setup

1. Obtain a complete checkout. Install Python 3.11+ and Node/npm through your
   approved workstation tooling. The locked Next.js package declares Node
   >=20.9.0. start refuses an older Python before creating .venv, refuses a
   partial checkout before any setup, and refuses Node older than 20.9.0
   before npm ci; --check reports the Node.js version and npm path it finds.
2. Choose the profile explicitly. For legacy, provide reachable local
   PostgreSQL/Redis and compatible Mailpit, or Docker/Compose for project data
   services. PostgreSQL is the normal database; SQLite is not the full-stack
   default and Redis is required by the normal launcher.
3. Inspect prerequisites with the existing read-only check, then review the
   [database target classification](../DATABASE_BOOTSTRAP_AND_UPGRADE.md)
   before the first start. A populated pre-UUID database must not cross revision
   100 through automatic startup.
4. Start the selected profile. Read its effects below. Complete any first-user
   enrollment through the [Native IAM operator guide](../native-iam-greenfield-setup.md);
   do not assume a seeded administrator or enable bootstrap indefinitely.
5. Verify API, IAM readiness, trusted frontend access and expected queues.
   Passing --check alone does not establish these.

The [optional bootstrap installers](../../scripts/BOOTSTRAP.md) install
dependencies and may install system tools/copy examples/generate a local AI key.
They do not provision the full database/Redis stack and are not a production
installation procedure.

Greenfield first installation is a distinct specialist workflow that provisions
resources and can seed synthetic identities. Obtain a maintainer-reviewed,
target-specific installation procedure and local-target authorization before
using those operations. Historical acceptance records are not the authoritative
current setup guide or automatic permission to replay commands, and are not
newly indexed here. First-install platform acceptance remains unverified.
It is not a dev.py setup subcommand, a data import, or production acceptance.

## Commands that exist

Run in the same checkout; use the intended profile consistently:

    python scripts/dev.py --check --profile legacy
    python scripts/dev.py start --profile legacy
    python scripts/dev.py status --profile legacy
    python scripts/dev.py stop --profile legacy
    python scripts/dev.py restart --profile legacy
    python scripts/dev.py start --profile legacy --verbose

For an installed macOS Greenfield environment, replace legacy with greenfield.
Omitting the command defaults to start. --check overrides any lifecycle command and does
not start services, install dependencies or migrate. Legacy check can validate
saved keys, data services and Node/npm; it stops at the first missing data
service and is not a full database/schema/frontend readiness test. Greenfield check validates private-file prerequisites, trust and
recorded containers without reading application password values or migrating.

When a required setup step (venv, pip, npm ci, Compose or Alembic) fails, the
launcher prints the redacted last 35 lines of that command. Application service
logs are shown only with --verbose; otherwise the error names the .dev-logs file.

Start/restart run in the foreground. Use another terminal for stop/status.
Ctrl+C stops launcher-owned application processes while leaving PostgreSQL,
Redis, Mailpit and data volumes running.

The canonical parser has no doctor or setup subcommand, and the repository root
has no dev.py. The former sbom_launcher_bundle copy was retired; its useful
preflight and error reporting now live in scripts/dev.py.

## What start changes

| Profile | Current behavior |
| --- | --- |
| legacy | Creates/reuses .venv, installs requirements when needed, selects project Docker or local services, creates/reuses sbom_analyser_dev, generates/reuses private .env.dev.local keys, checks schema and runs Alembic upgrade, prepares frontend dependencies/certificate, then starts API, worker, full Beat and frontend. Before Alembic it refuses an unknown schema and a pre-UUID revision whose identity tables contain rows, using read-only queries. There is no Greenfield-style per-revision backup/confirmation contract here. |
| greenfield | Requires a complete existing private installation, checks resource identity and trusted HTTPS, resumes recorded containers, then checks pending schema transitions. Each pending unit requires explicit confirmation, verified encrypted backup/restore rehearsal and independent read-back before application services. Startup does not bootstrap or seed an installation. It can renew leaf certificates and refresh a private frontend working copy. |

See [database operations](../DATABASE_BOOTSTRAP_AND_UPGRADE.md#greenfield-startup)
for cancellation, incomplete-upgrade and unknown-COMMIT behavior. Do not switch
profiles to bypass a refusal or reuse another profile's credentials.

## Ports, environment and queues

| Service | legacy | greenfield |
| --- | --- | --- |
| API | 127.0.0.1:18000 | 127.0.0.1:18000 |
| HTTPS frontend | localhost:13000 | localhost:13000 |
| PostgreSQL | Docker 55439; local fallback 5432 | 127.0.0.1:56044 |
| Redis | Docker 56379; local fallback 6379 | 127.0.0.1:56381 |
| Mailpit SMTP / UI | 1025 / 8025 | 1026 / 8026 |
| Private configuration | .env.dev.local in checkout | ~/.sbom-greenfield-uuid |
| Scheduler | Full separate Beat | Embedded security-mail schedule only |

Both profiles currently select local Native authentication; neither is the HCL
integration profile. [Configuration precedence](../reference/configuration.md)
explains fixed flags and manual setup differences.

The legacy worker consumes both the default celery queue and reports, the
same queue set as the server worker; Beat remains a single separate process.
Report delivery still needs its REPORT_* settings, so do not claim reports are
ready from this launcher alone. [Report operations](../runbook-report-notifications.md)
describes the dedicated production worker; real mail and delivery acceptance
require explicit configuration.
Greenfield consumes both queues but its restricted scheduler does not tick the
application-wide report/analysis schedules. Do not start a second full Beat to
“fix” this without reviewing the intended profile policy.

Local certificate trust differs: legacy creates a self-signed certificate if
missing; manual HTTPS helpers may install trust; Greenfield only verifies an
independently trusted CA and generates/reuses leaf material. These are development
procedures, not production TLS configuration.

## Recovery and limitations

Use [lifecycle ownership/recovery](../dev-launcher-lifecycle.md) for registry,
PID reuse, Ctrl+C and stale state. Use
[troubleshooting](../operations/troubleshooting.md) for diagnostic limits and logs.

Do not start the same home-directory Greenfield installation from two worktrees.
The launcher registry is checkout-local, while Greenfield state/resources are
shared in the user's home. A clean documentation worktree does not isolate
runtime databases or services.
