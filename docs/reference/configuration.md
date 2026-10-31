# Configuration reference

Scope: development configuration boundaries and SBO-98 Phases 1–3, based on
approved main `69e71088d7fef06874fe1e2eac7a53db0fd2f333`. Examples are templates,
not one interchangeable environment.

## Pure development configuration plans (SBO-98, Phase 1)

The side-effect-free `scripts/dev_config.py` library is introduced against the
approved main baseline `69e71088d7fef06874fe1e2eac7a53db0fd2f333`. Read-only
diagnostics and prepared Legacy startup use it through the shared read-only
snapshot adapter. Controlled setup inspects an independent action plan before
delegating authorized preparation; standalone operator scripts retain their
existing entry-point guards. Configuration files, protected private readers and
process-ownership behavior remain authoritative. This is a library, not another
environment-management CLI.

Callers supply already-read snapshots and explicit profile, configuration family,
native repository/state paths and operating system. Pure text parsers preserve
the managed JSON-string, literal PowerShell and noninterpolating dotenv formats.
Adapters must retain the existing ACL, symlink/reparse-point, profile
selection and runtime-family pinning checks before reading protected files.

The resolver copies its inputs into immutable environment, provenance,
classification and component maps. It never reads ambient environment variables
or files, imports application startup, connects to services, creates credentials,
initializes state or writes files. Managed `existing` resolution preserves
process-then-saved inspection precedence; `startup` models fixed settings for an
already prepared installation. It deliberately refuses missing saved database
configuration or a PostgreSQL provider change instead of inventing credentials or
preparing a database. Windows/env and Greenfield precedence remains covered by
parity tests against the current launcher.

The database target contains only host, port and database name. Passing local
target policy does **not** establish live identity, readiness, process ownership
or permission for initialization or administrator enrollment. The new library
refuses query/fragment-bearing database URLs, control characters, ambiguous
leading database-path slashes, port zero and case-variant environment names.
Some old Windows/env inputs accepted these forms; they require explicit review,
not silent normalization or removal of TLS options. Diagnostics report these
conditions without changing files. Prepared Legacy startup uses the same target
policy instead of normalizing an ambiguous saved target.

Authentication metadata records explicit supplied flags without selecting or
converting a mode. `authentication_enabled=None` means unresolved/absent; omitted
component defaults and differing backend/frontend boolean handling still need
diagnosis. Existing Native, HCL.CS, Entra, mixed and disabled values are preserved
in inspection plans. Setup/start require authenticated development with the
development tenant bypass disabled, and refuse incompatible existing modes
instead of converting them.

Unknown settings are classified conservatively as secret. Environment values
are excluded from plan representations, but the environment maps intentionally
contain secrets and must never be serialized into logs or issues. Frontend and
public projections use explicit allowlists: the BFF keeps its legitimate session
encryption key and Redis session connection, but not database, Native signing,
SMTP, outbox or provider-storage secrets. Browser projection permits only
reviewed public names. API/worker/Beat projections retain the complete server
configuration for compatibility; narrower backend roles require the Phase 4
consumer audit. These projections are not yet used to launch processes.

Later separately reviewed phases cover component injection and authorized Native
enrollment. They must not reuse mutable preparation as a resolver, automatically
migrate/create databases, replace saved keys or install certificate trust.
Standalone bootstrap scripts are not yet connected to the shared resolver.
HCL.CS first-eligible-user provisioning still requires Engineering Lead and
identity-provider-owner design approval.

## Read-only diagnostics (SBO-98, Phase 2)

Use the single public launcher from the intended checkout:

```sh
python scripts/dev.py diagnose
python scripts/dev.py diagnose --profile legacy --legacy-config managed
python scripts/dev.py diagnose --profile legacy --legacy-config windows
python scripts/dev.py diagnose --profile greenfield
```

`diagnose` is the primary command. `doctor` is a temporary compatibility alias
which emits one deprecation notice on stderr and uses the same checks/exit policy.
Existing supported `--check` forms use the diagnostic path before mutable setup
or runtime dispatch, including `python scripts/dev.py setup --check`. Combining
diagnostics with provisioning, database initialization/migration or frontend-build
flags is a usage error, not permission to apply those changes.

The command inspects already selected configuration and uses bounded observational
checks. It never installs packages, prepares a virtualenv, writes configuration,
generates keys/certificates, changes certificate trust, creates/migrates a database,
creates users/tokens/grants, acquires or updates runtime locks, refreshes ownership,
starts/stops services or publishes Celery control RPC/tasks. PostgreSQL observations
use read-only transactions. Runtime records are observations only: uncertain or
reused PIDs are never adopted, cleared or killed. Existing UNKNOWN records remain
protected.

Observational network requests and protocol handshakes can appear in service
access logs. HTTPS inspection uses a verified TLS handshake rather than fetching
a Next.js page that could trigger development compilation. Pinned leaf verification
does not establish OS/browser trust. Never bypass certificate validation to make
a diagnostic check pass.

Reporting deadlines also cover DNS and slow protocol headers. A timed-out probe
runs only read-only operations in a daemon thread and may finish until CLI exit;
the thread is never forcibly cancelled or used for preparation. As explicitly
approved for SBO-98, timeout cleanup may stop only short-lived Node, Docker or
native trust-tool children created by that diagnostic through their original
`Popen` objects/handles. It never signals a saved PID, managed service or unrelated
process. External helpers have their own timeouts; a reporting timeout does not
prove an in-flight read-only operation has completed. Database probes retain
server-side read-only/statement limits and close without committing. A library
caller that keeps its process alive must account for that residual probe lifetime.
API inspection uses the inert service-info endpoint and selected Native readiness;
it avoids `/health`, whose NVD mirror read path can attempt a settings seed.

HTTP metadata/health probes use direct selected endpoints rather than ambient
proxy settings. HCL environments requiring a corporate proxy need an explicitly
reviewed transport adapter; successful direct discovery does not prove provider
registration or login. Ambiguous relative HCL CA paths and unreviewed Redis URL
query options are reported for review; diagnostics never rewrite or discard them.

Results carry a safe component, status, reason and corrective guidance. Connection
strings, passwords, private keys, tokens and raw provider/database exceptions are
not diagnostic output.

| Status | Meaning |
| --- | --- |
| PASS | The bounded check succeeded; it establishes only the stated observation. |
| WARN | Review a limitation or nonrequired condition; it does not authorize repair. |
| FAIL | A required check failed with actionable guidance. |
| BLOCKED | A required check cannot proceed safely until a prerequisite/approval is resolved. |
| SKIPPED | The check is not applicable or has no safely observable running component. |

Exit 0 means there are no failed or blocked required checks; 1 means a required
check failed or is blocked; 2 means invalid usage, including mutation-flag
combinations; 130 means cancellation. Existing `status` exit 3 for stopped/unhealthy
runtime remains unchanged. An intentionally stopped application is not evidence
of a crashed worker or corrupted installation.

Diagnostic coverage distinguishes:

- dependency/toolchain presence from installation and build acceptance;
- configuration provenance/conflicts from permission to rewrite private files;
- approved target identity, connectivity and schema state from initialization;
- Native JWT/session/rate-limit/outbox/mail prerequisites from live activation;
- HCL.CS configuration/TLS observations from provider registration and actual login;
- aggregate enrollment state from authorized privileged provisioning;
- existing certificate validity, verified TLS and independent native trust;
- recorded process identity, available heartbeats and bounded service health
  from full application readiness and task/mail delivery.

Missing enrollment, pending activation or a schema mismatch produces corrective
guidance only. Native enrollment still delegates to the approved bootstrap and
activation services under explicit operator authorization and exact database
identification. HCL.CS has no newly approved first-eligible-user provisioning flow.
Do not invoke bootstrap helpers as diagnostic dry runs: some wrappers commit or
write audit records even on refusal.

For an existing machine, preserve configuration, credentials, certificates and
runtime records; run `diagnose` with the intended profile/family, review its safe
findings and seek authorization for the specific corrective action. Do not reset
data, rotate keys, alter trust or switch authentication/profile to bypass a check.
Controlled setup is described below. No new live platform/provider acceptance is
implied by adding diagnostics or passing unit tests.

## Controlled setup and prepared startup (SBO-98, Phase 3)

Use the selected checkout/profile and review its plan before preparation:

```sh
python scripts/dev.py setup --plan --profile legacy --legacy-config managed
python scripts/dev.py setup --profile legacy --legacy-config managed
python scripts/dev.py --profile legacy --legacy-config managed
python scripts/dev.py diagnose --profile legacy --legacy-config managed
```

`setup --plan` is read-only: it reports required actions and blockers without
prompting for consent, installing packages, creating private files, connecting to
the database or changing runtime records. It may continue inspection in an
already-existing project interpreter when that is required to validate existing
material; this handoff does not create or repair a virtualenv. `setup --check`
continues to mean diagnostics, not setup planning or permission to apply a plan.

Interactive `setup` requires an explicit `yes` for each required category:
project dependencies, new configuration, fresh secrets, missing certificates,
explicit Greenfield data providers, database initialization/migration and optional
frontend build. Declining any category applies nothing. Noninteractive setup with
required actions refuses rather than assuming consent. A successful plan-only or
unchanged invocation returns 0; blockers, declined authorization and changed
inputs return 1; cancellation/EOF during consent returns 130.

The plan is inspected again after consent. An internal fingerprint covers
selected inputs, private-file observations, manifests and preparation/migration
source. Changed inputs, new actions or blockers require a new plan. The
fingerprint and private values are not displayed. Authorization is scoped to the
current actions and survives only a validated project-interpreter handoff; it is
not a reusable public approval switch or permission to create privileged users.
After that handoff, preparation takes the existing checkout lifecycle lock and
checks runtime records again. A concurrent launcher operation or newly appeared
record blocks preparation. Planning and diagnostics never take that lock.

Ordinary startup requires an existing project interpreter, matching Python/npm
dependency stamps, selected configuration, persistent keys and valid existing
HTTPS material. It checks connectivity and current schema before workers start.
It does not install dependencies, create a database, migrate a schema, discover
credentials, generate keys or create a certificate. A missing preparation gate
directs the developer back to a reviewed setup plan. PostgreSQL credentials are
never adopted from repository `.env`, pgpass or known container defaults.

For a genuinely new Managed Legacy Native installation, first obtain operator
approval for the exact local empty target and start the approved local
PostgreSQL, Redis and Mailpit services. The following is a procedure example,
**not an operation executed during this implementation**:

```sh
python scripts/dev.py setup --plan --profile legacy --legacy-config managed --postgres-provider local --redis-provider local --mailpit-provider local --initialize-database --confirm-database sbom_analyser_dev
# Only after the database operation is independently approved, review and consent:
python scripts/dev.py setup --profile legacy --legacy-config managed --postgres-provider local --redis-provider local --mailpit-provider local --initialize-database --confirm-database sbom_analyser_dev
```

The exact-name guard runs before preparation. Fresh setup requests the intended
PostgreSQL credentials interactively, validates them through read-only inspection
and requires an empty application schema before generating initial Native keys.
New managed configuration is published without replacing an existing file. A
missing configuration next to a populated database is a recovery case, not
permission to generate replacement keys. Initialization and migration retain
their existing empty-target, UUID-history and platform safeguards; neither is
selected by ordinary startup.

Legacy setup reuses only already-running selected local/Docker dependencies; it
does not create or resume Legacy containers. A stopped or unverified selected
provider blocks preparation. Fresh managed PostgreSQL cannot adopt a Docker
installation using default credentials; preserve an approved existing complete
configuration or use explicitly reviewed Greenfield provisioning for a new
private container installation. Provider flags never authorize conversion of a
saved installation. Greenfield provisioning requires its exact database
confirmation, independently approved CA and separate preparation categories;
creating PostgreSQL resources does not initialize application schema unless the
explicit initialization flag is also selected.

Existing Legacy Windows/env HCL.CS settings remain supported. Setup preserves
their provider, authentication, CA and redirect choices; it does not invent
registrations or require Native signing/outbox keys when Native is disabled.
The BFF's existing session key remains protected. HCL.CS first-eligible-user
privileged provisioning remains blocked pending Engineering Lead and provider
owner approval. Neither setup nor ordinary startup creates an administrator.

Recovery preserves original configuration, credentials, certificates, database
contents and uncertain runtime records. Restore incomplete or invalid original
material rather than deleting it or rotating keys. Any recorded runtime blocks
preparation until its ownership is reviewed and verified stop succeeds. A setup
failure can leave authorized project/private artifacts already created; the
`SETUP_PARTIAL_PREPARATION` report requires diagnosis and a new plan, not automatic
rollback, database reset or broad file cleanup.

Two limits remain explicit. If neither the invoking interpreter nor the existing
project interpreter can validate protected keys/certificates because required
dependencies are missing, setup blocks before mutation; this phase provides no
dependency-only repair bypass. New managed private configuration and localhost
private keys use exclusive creation and protected Windows DACLs, requiring
persistent-ACL filesystem support. Existing ACLs are not repaired, and failed
creation can retain incomplete new artifacts for operator review. Redirected
certificate/configuration parent paths are refused. System-service
installation and OS/browser root trust are never performed by setup. Native
Windows ownership/DACL inspection uses read-only native metadata APIs on one
handle, with current-user ownership and conservative trusted-grant checks. It
does not launch PowerShell, change ACLs or treat unknown metadata as safe. This
also avoids the confirmed 15-second helper timeout on fresh Windows CI hosts.
Keep checkout/state and test TEMP paths within the machine's supported Windows
path limits; no long-path or other machine policy is enabled automatically.
Native Windows/macOS/Linux, real provider login and fresh-install acceptance remain
separate validation work; documentation and fixture tests do not establish them.

## Sources and precedence

| Execution path | Effective sources |
| --- | --- |
| Manual API / Alembic | Process environment is preferred; app/db.py and alembic/env.py use dotenv, and Settings reads .env. Settings defaults fill remaining fields. A working directory/environment change can change the target. |
| Managed Legacy launcher | Reads saved .env.dev.local through the shared snapshot resolver, validates its saved providers/keys/TLS, then applies the existing fixed local Native runtime settings. Ordinary start never generates keys, discovers credentials or writes this file. Explicit fresh setup is separately authorized. Inherited values and downstream Settings/dotenv fallback can still affect fields not fixed by the launcher. |
| Existing Legacy Windows/env | Process values, then frontend .env.local, then the selected literal .windows/sbom.env.ps1 or explicitly selected root .env; defined later values win. Existing defaults and repository PYTHONPATH apply. Authenticated development, local-target and saved-mode checks refuse conflicts without conversion. |
| Greenfield launcher | Reads protected home-directory state, constructs an allowlisted environment and runs services from private working directories; disables ordinary dotenv loading and does not use legacy .env.dev.local. The private frontend copy excludes .env files. |
| Server Compose | --env-file .env.server supplies Compose interpolation. Only explicitly forwarded environment values, mounted files and public image build values reach containers; an arbitrary key in .env.server is not automatically forwarded. |
| Manual Next.js | Next.js environment loading and process variables apply. Public values can be compiled into browser code; BFF-only values stay on the server. |

Executable sources: [Settings](../../app/settings.py),
[database URL resolution](../../app/db.py),
[legacy profile resolution](../../scripts/dev.py),
[Greenfield environment](../../scripts/dev.py),
[server Compose](../../docker-compose.server.yml) and
[frontend auth parsers](../../frontend/src/lib/auth).
Do not infer a production database from any developer .env file.

Managed Legacy restricts its database to local sbom_analyser_dev. Explicitly selected
Legacy Windows/env configurations preserve their saved loopback database while
refusing Greenfield/system databases; they are never silently substituted. It may
reuse only its own approved saved connection credentials; fresh local setup
requests operator-supplied credentials. It never searches repository files or
pgpass for a substitute, nor gains permission to target another existing database.

## Template roles

| Template | Intended role |
| --- | --- |
| [.env.example](../../.env.example) | Backend/manual development baseline; authentication disabled and synthetic tenant enabled. |
| [frontend/.env.local.example](../../frontend/.env.local.example) | HCL-oriented authenticated frontend/BFF template; does not match the backend example's disabled-auth default. |
| [.env.hcl-iam.example](../../.env.hcl-iam.example) | HCL provider checklist. |
| [.env.native-iam.example](../../.env.native-iam.example) | Native IAM and production prerequisites; enablement requires a complete reviewed configuration. |
| [.env.server.example](../../.env.server.example) | Server deployment interpolation/build checklist; protected runtime copy is deployment-owned. |
| [KEV/.env.example](../../KEV/.env.example) | Separate optional KEV service, not the main application's environment. |

Copying backend and frontend examples unchanged does not create a coherent
authenticated stack. Select a profile and follow its provider guide. Keep
private files ignored and access-restricted; never paste resolved Compose
configuration or private state into an issue.

## Database and Redis

PostgreSQL is normal development/production storage. When no database URL is
resolved, SQLite fallback requires ALLOW_SQLITE=true. An explicitly supplied
SQLite URL is a separate test/emergency path; it does not establish production
or PostgreSQL feature parity.

The normal launcher and server stack require Redis. The manual Celery
CELERY_USE_DATABASE_BROKER option derives a PostgreSQL polling broker/result
backend for limited local use; it does not replace Redis-backed BFF sessions,
shared authentication limits, or the launcher's fixed Redis configuration.

Local Compose fixes development database credentials and publishes PostgreSQL
without a loopback-only bind; its values do not automatically match placeholder
passwords in .env.example. Resolve that deliberately on a private development
host. Editing POSTGRES_PASSWORD does not rotate an initialized volume's
credentials; this phase changes neither credentials nor bindings.

## Authentication and sessions

AUTH_ENABLED controls authenticated API access, not HCL alone. HCL_AUTH_ENABLED,
NATIVE_AUTH_ENABLED and ENTRA_ENABLED select provider-specific behavior.
Native-only mode still requires AUTH_ENABLED=true and current database authority.
DEV_DEFAULT_TENANT is a synthetic isolated-development mechanism, not production
tenant provisioning. Keep catalogue and role-assignment fail-closed modes intact.

Production BFF sessions require AUTH_SESSION_STORE=redis, a reachable
AUTH_SESSION_REDIS_URL and the independent 32-byte base64 session encryption key.
Native/Entra production checks also enforce canonical HTTPS APP_ORIGIN and
provider prerequisites. Redis support does not prove multi-replica acceptance.

## Build versus runtime

| Setting class | Handling |
| --- | --- |
| NEXT_PUBLIC_* | Public, potentially embedded in frontend assets at build time. Never put keys/tokens here. Keep compiled auth flags consistent with BFF/backend runtime settings. |
| SBOM_API_URL | Server-only BFF upstream; browser hostname and container service hostname can differ. |
| Database, SMTP, provider/JWT/session/outbox/encryption secrets | Protected runtime environment or approved secret files/manager. API and worker must share the appropriate persistent keys. |
| Certificate/transaction key files | Protected mounted files under deployment-owned paths, never baked into images. |
| ENTRA_* | Runtime provider settings used by API/BFF; current server Compose does not forward them. Deployment through this manifest is unverified. |

The [frontend Dockerfile](../../frontend/Dockerfile) declares public build
arguments; [production build instructions](../UBUNTU_DOCKER_DEPLOYMENT.md#11-build-the-images-again)
must use the intended provider flags. A runtime environment edit cannot be
assumed to replace already compiled browser values. NEXT_PUBLIC_APP_URL is not
consumed by the application.

For AI configuration, database-backed settings are authoritative once saved;
environment values remain bootstrap/fallback inputs where supported. See
[AI configuration](../features/ai-configuration.md) and
[credential/key lifecycle](../runbook-ai-credentials.md). Never regenerate an
existing key as a troubleshooting shortcut.
