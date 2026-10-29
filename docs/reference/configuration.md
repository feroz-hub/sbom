# Configuration reference

Scope: current configuration boundaries, checked against e62951c2 on
28 October 2026. Examples are templates, not one interchangeable environment.

## Sources and precedence

| Execution path | Effective sources |
| --- | --- |
| Manual API / Alembic | Process environment is preferred; app/db.py, run.py and alembic/env.py use dotenv, and Settings reads .env. Settings defaults fill remaining fields. A working directory/environment change can change the target. |
| legacy launcher | Reads saved .env.dev.local, applies fixed local service/Native flags, generates/reuses required local keys and passes the resolved environment to children. Inherited process values and Settings/dotenv fallback can still affect fields not fixed by the launcher. |
| Greenfield launcher | Reads protected home-directory state, constructs an allowlisted environment and runs services from private working directories; disables ordinary dotenv loading and does not use legacy .env.dev.local. The private frontend copy excludes .env files. |
| Server Compose | --env-file .env.server supplies Compose interpolation. Only explicitly forwarded environment values, mounted files and public image build values reach containers; an arbitrary key in .env.server is not automatically forwarded. |
| Manual Next.js | Next.js environment loading and process variables apply. Public values can be compiled into browser code; BFF-only values stay on the server. |

Executable sources: [Settings](../../app/settings.py),
[database URL resolution](../../app/db.py),
[legacy profile resolution](../../scripts/dev.py),
[Greenfield environment](../../scripts/greenfield_uuid.py),
[server Compose](../../docker-compose.server.yml) and
[frontend auth parsers](../../frontend/src/lib/auth).
Do not infer a production database from any developer .env file.

The legacy launcher restricts its database to local sbom_analyser_dev. It may
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
