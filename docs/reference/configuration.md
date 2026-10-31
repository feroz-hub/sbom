# Configuration reference

Scope: current configuration boundaries, checked against e62951c2 on
28 October 2026. Examples are templates, not one interchangeable environment.

## Pure development configuration plans (SBO-98, Phase 1)

The side-effect-free `scripts/dev_config.py` library is introduced against the
approved main baseline `69e71088d7fef06874fe1e2eac7a53db0fd2f333`. It is not yet
connected to launcher startup, diagnostics, setup or operator scripts. Existing
commands, configuration files, private readers and process-ownership behavior
remain authoritative. This is a library, not another environment-management CLI.

Callers supply already-read snapshots and explicit profile, configuration family,
native repository/state paths and operating system. Pure text parsers preserve
the managed JSON-string, literal PowerShell and noninterpolating dotenv formats.
Future adapters must retain the existing ACL, symlink/reparse-point, profile
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
not silent normalization or removal of TLS options. No existing file is changed,
and the unused library does not tighten the running launcher's behavior yet.

Authentication metadata records explicit supplied flags without selecting or
converting a mode. `authentication_enabled=None` means unresolved/absent; omitted
component defaults and differing backend/frontend boolean handling still need
diagnosis. Existing Native, HCL.CS, Entra, mixed and disabled values are preserved
in inspection plans. Fresh authenticated onboarding policy is a later phase.

Unknown settings are classified conservatively as secret. Environment values
are excluded from plan representations, but the environment maps intentionally
contain secrets and must never be serialized into logs or issues. Frontend and
public projections use explicit allowlists: the BFF keeps its legitimate session
encryption key and Redis session connection, but not database, Native signing,
SMTP, outbox or provider-storage secrets. Browser projection permits only
reviewed public names. API/worker/Beat projections retain the complete server
configuration for compatibility; narrower backend roles require the Phase 4
consumer audit. These projections are not yet used to launch processes.

Later separately reviewed phases introduce `python scripts/dev.py diagnose`
(with temporary `doctor` compatibility), controlled setup, component injection
and authorized Native enrollment. They must not reuse mutable preparation as a
resolver, automatically migrate/create databases, replace saved keys or install
certificate trust. HCL.CS first-eligible-user provisioning still requires
Engineering Lead and identity-provider-owner design approval.

## Sources and precedence

| Execution path | Effective sources |
| --- | --- |
| Manual API / Alembic | Process environment is preferred; app/db.py and alembic/env.py use dotenv, and Settings reads .env. Settings defaults fill remaining fields. A working directory/environment change can change the target. |
| legacy launcher | Reads saved .env.dev.local, applies fixed local service/Native flags (including ENTRA_ENABLED=false and an empty NATIVE_JWT_VERIFICATION_KEYS_JSON, so no other issuer or trusted key is added), generates/reuses required local keys and passes the resolved environment to children. Inherited process values and Settings/dotenv fallback can still affect fields not fixed by the launcher. |
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
reuse suitable local connection credentials through its resolver; that is not
permission to point it at another existing database.

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
