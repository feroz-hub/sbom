# SBOM Analyser

SBOM Analyser is a FastAPI and Next.js platform for importing, validating, normalizing, analysing, and managing software bills of materials. It combines SBOM inventory, multi-source vulnerability analysis, CISA Known Exploited Vulnerabilities (KEV), lifecycle intelligence, VEX, remediation, reporting, tenant isolation, and role-based access control in one application.

The current application version is `2.0.0`. The current Alembic schema head is `103_tenant_admin_governance`.

## Highlights

| Area | What the platform provides |
| --- | --- |
| SBOM ingestion | CycloneDX and SPDX upload, format detection, validation, quarantine, repair, conversion, and import. |
| Inventory | Component extraction, normalization, deduplication, project/product organization, versioning, comparison, and restore workflows. |
| Vulnerability analysis | NVD, OSV, GitHub Security Advisories, VulDB, EPSS, and local cache/mirror support. |
| CISA KEV | Local canonical KEV catalog, manual and scheduled sync, filters, detail views, ransomware metadata, and finding enrichment. |
| Lifecycle intelligence | EOL/EOS/EOF and maintenance signals from configured providers, confidence/evidence, overrides, and provider administration. |
| Security workflows | VEX, remediation tracking, reports, audit events, scheduled analysis, and optional AI-assisted fixes. |
| Access control | HCL.CS/HCL IAM OIDC with PKCE, backend JWT/JWKS validation, multi-tenancy, and RBAC. |

## Architecture

```text
Browser
  -> Next.js 16 / React 19
       -> unauthenticated local mode: FastAPI directly
       -> HCL.CS mode: Next.js BFF (/api/backend/*)
            -> server-side OIDC session and token refresh
  -> FastAPI API (application v2.0)
       -> routers -> services -> repositories/models
       -> PostgreSQL 16
       -> external vulnerability and lifecycle providers
       -> Celery / Redis (or PostgreSQL local fallback) for scheduled and background work
```

The backend is a modular monolith. HTTP behavior lives in `app/routers`, business behavior in `app/services`, persistence in SQLAlchemy models/repositories, validation in `app/validation`, and asynchronous tasks in `app/workers` and `app/nvd_mirror`.

In authenticated mode, the browser receives only an HTTP-only session cookie. Next.js performs Authorization Code + PKCE, stores and refreshes tokens server-side, and proxies API calls to FastAPI. FastAPI remains the authority for JWT validation, tenant membership, and permissions.

## Main features

### Scheduled security report notifications

Settings → Notifications supports per-user Tenant/Project/Product/SBOM subscriptions, consolidated
latest-state and historical/version comparisons, HTML/plain-text email, executive PDF and detailed
Excel, retained authenticated downloads, pause/resume and delivery history. The feature is opt-in
behind `REPORT_NOTIFICATIONS_ENABLED`, uses the existing SMTP relay and a separate `reports` Celery
worker, and requires private shared artifact storage. No report delivery occurs in unauthenticated
local mode. See [setup, guarantees, limitations and smoke tests](docs/runbook-report-notifications.md).

### Supported SBOM formats

The ingestion and validation paths support CycloneDX JSON/XML and SPDX JSON/tag-value documents for the versions recognized by the validators. Supported SPDX documents can be converted to the application's CycloneDX representation. SPDX 3.0 is not yet treated as fully supported.

### SBOM validation and repair

Uploads pass through a nine-stage pipeline:

| Stage | Purpose |
| --- | --- |
| 1. Ingress guard | Enforces body, decompression, and safety limits. |
| 2. Format/version detection | Identifies CycloneDX or SPDX and its supported version. |
| 3. Structural validation | Validates the document against structural/schema rules. |
| 4. Semantic validation | Checks domain-level SBOM meaning. |
| 5. Cross-reference integrity | Verifies references and internal consistency. |
| 6. Security checks | Rejects unsafe payload characteristics. |
| 7. NTIA minimum elements | Reports minimum-element coverage. |
| 8. Signature verification | Optional, feature-flagged signature path. |
| 9. Normalization and deduplication | Produces canonical component identities and duplicate metadata. |

Invalid documents are stored in validation repair sessions instead of entering inventory. The repair workspace supports full-content persistence, chunked/line-based access for large files, search, patch history, revalidation, and controlled import.

Current limits are 50 MB per upload, 200 MB decompressed, and a maximum 100:1 decompression ratio. Files above 5 MB use the large-file/asynchronous validation path where configured.

### Project and product hierarchy

Inventory is organized as:

```text
Project
  -> Product
       -> SBOM versions
            -> Components
            -> Analysis runs and findings
```

Legacy records are migrated into default product/project assignments. APIs and UI routes support product detail, associated SBOMs, and project-scoped reporting.

### Vulnerability analysis

Analysis can combine:

- NVD CVE data and the optional local NVD mirror;
- OSV package vulnerability data;
- GitHub Security Advisories;
- VulDB, when configured;
- EPSS scoring;
- the locally mirrored CISA KEV catalog.

Provider responses and CVE lookups are cached to reduce repeated external requests. Analysis findings retain provider evidence, aliases, version-range context, confidence, CVSS details, KEV status, and match reasons.

### CISA KEV catalog

Migration `044_kev_vulnerabilities_table` provides the canonical `kev_vulnerabilities` table. A sync downloads the official CISA JSON feed, normalizes it, and performs idempotent upserts.

The `/kev` frontend provides search, vendor/product/CWE/catalog filters, date and ransomware filters, sorting, pagination, and detailed CISA remediation metadata.

Integrated API routes:

| Route | Purpose |
| --- | --- |
| `POST /api/v1/kev/sync` | Full or date-filtered manual refresh. |
| `GET /api/v1/kev` | Search, filter, sort, and page catalog entries. |
| `GET /api/v1/kev/filter-options` | Retrieve filter facets and date bounds. |
| `GET /api/v1/kev/{cve_id}` | Retrieve one KEV record. |

Celery Beat schedules `kev.sync` daily at 03:10 UTC. Run only one Beat instance per deployment.

The `KEV/` directory also contains a small standalone sync service for deployments that need the catalog loader independently. The primary application uses the integrated routes and Alembic-managed table described above.

### Lifecycle, VEX, and remediation

Lifecycle enrichment combines manual overrides, cached results, and enabled providers in priority order. Supported sources include official/vendor records, Red Hat data, endoflife.date, package registries, deps.dev, OSV, repository health, OpenEoX, Xeol API/local DB, and custom vendor records where configured.

The platform also supports:

- lifecycle evidence, confidence, health, cache, and provider administration;
- VEX import, statements, component overrides, and history;
- remediation records and status transitions;
- dashboard metrics, comparison, exports, and scheduled rescans;
- optional AI fix generation with configurable providers and encrypted credentials.

## Technology

| Layer | Technology |
| --- | --- |
| Backend | Python 3.11+, FastAPI, Pydantic 2, SQLAlchemy 2, Alembic, psycopg 3 |
| Database | PostgreSQL 16; SQLite only for explicit test/emergency fallback |
| Workers | Celery with Redis; PostgreSQL polling broker for local fallback |
| Frontend | Next.js 16, React 19, TypeScript 6, TanStack Query, Tailwind CSS, Recharts |
| Authentication | OIDC Authorization Code + PKCE, HCL.CS/HCL IAM, PyJWT/JWKS |
| Testing | pytest, Vitest, Testing Library, Ruff, mypy |

## Repository layout

```text
app/                    FastAPI application
  ai/                   AI provider and fix workflows
  core/                 Request context, security, and RBAC
  integrations/         External integrations
  normalization/        Component normalization
  nvd_mirror/           NVD mirror API and tasks
  routers/              HTTP route modules
  services/             Business services
  validation/           Nine-stage validation pipeline
  workers/              Celery tasks and Beat configuration
frontend/               Next.js application
alembic/versions/       Database migrations
tests/                  Backend tests
docs/                   Architecture, user guides, and runbooks
scripts/windows/        Native Windows setup/start/stop scripts
KEV/                    Optional standalone KEV sync service
docker-compose.yml      Local PostgreSQL 16 service
```

## Local development

The public local development entrypoint is **`scripts/dev.py`**. Run it from a complete repository checkout:

```sh
python scripts/dev.py
```

Use `python3` where that is the installed Python command. `start` is the default and stays in the foreground; keep that terminal open. The launcher prepares project dependencies when needed and checks the selected profile before launching application services. It does not install system software or trusted root certificates.

Required system prerequisites are Python **3.11+**, Node.js **20.9+** with npm, and the data services selected by the profile. Docker with Compose is required for the installed Greenfield container topology; Legacy can use verified project Docker services or suitable local PostgreSQL/Redis/Mailpit. An independently approved local HTTPS trust setup is also required for browser authentication. Run the inspection command first on a new machine:

```sh
python scripts/dev.py doctor
```

Missing or unsupported prerequisites produce corrective instructions. Native platform evidence and remaining limitations are tracked in the [Windows/macOS/Linux verification matrix](docs/engineering/dev-launcher-platform-matrix.md); intended platform adapters do not imply that a fresh clone or authentication has passed on every OS.

Manage the same checkout from another terminal:

```sh
python scripts/dev.py setup
python scripts/dev.py start
python scripts/dev.py status
python scripts/dev.py logs --lines 80
python scripts/dev.py logs --service api --lines 80
python scripts/dev.py stop
python scripts/dev.py restart
python scripts/dev.py doctor --profile greenfield
python scripts/dev.py --check
```

`--check` is the inspection-only alias of `doctor`. Use `--verbose` for technical diagnostics. `logs` prints a bounded, redacted tail; review diagnostic output before sharing it.

### Profiles and persisted data

| Profile | Configuration | PostgreSQL | Redis | Mailpit web / SMTP |
| --- | --- | --- | --- | --- |
| Greenfield | Private `~/.sbom-greenfield-uuid` | `sbom_greenfield_uuid` on `56044` | `56381` | `8026` / `1026` |
| Legacy | Ignored `.env.dev.local` | `sbom_analyser_dev` on Docker `55439` or saved local port | Docker `56379` or saved local port | `8025` / `1025` |

Both profiles serve the frontend at **https://localhost:13000** and API at **http://127.0.0.1:18000**. The selected profile is reported explicitly. `--profile auto` is the default: an installed Greenfield state directory selects Greenfield; otherwise Legacy is selected. Use `--profile greenfield` or `--profile legacy` when you require a specific target. An incomplete selected installation fails; it must not silently fall back to another database or profile.

Greenfield resumes only containers matching its recorded identities and validates the existing schema. Both profiles start a default queue worker, a separate reports worker, and exactly one separate Beat using the application's full schedule and existing feature/security guards. Linux uses prefork; macOS and Windows use solo. Readiness requires worker responses, actual queues, matching owned PIDs, connected-consumer heartbeats and scheduler progress before FastAPI and HTTPS Next.js are declared ready.

Ordinary startup preserves data and does not initialize or implicitly upgrade a database. Review the [explicit setup controls](scripts/BOOTSTRAP.md) for provisioning, empty-database initialization or migrations. Windows pending Greenfield upgrades remain blocked until native backup/restore validation. First-user creation remains an explicit [Native IAM procedure](docs/native-iam-greenfield-setup.md).

Legacy preserves managed `.env.dev.local`. Existing `.windows/sbom.env.ps1` settings can be read as literal data using `--profile legacy --legacy-config windows`; root `.env` requires `--legacy-config env`. Saved databases, credentials, authentication settings and ports remain authoritative. Existing Windows configurations default to API/frontend ports 8000/3000 when absent. Configurations are never executed as PowerShell or silently replaced with another family.

### HTTPS and safe shutdown

Greenfield preserves its existing requirement for a leaf certificate issued by an independently trusted mkcert CA. Legacy retains its separate local-certificate policy and requires explicit browser trust approval where appropriate. The launcher never installs a root CA, silently trusts a certificate, or disables TLS verification. Trust/setup failures stop startup with corrective instructions. Existing complete keys/certificates are reused; incomplete or invalid material needs review. Production TLS is separate.

Ctrl+C and `stop` clean up only application processes with verified launcher ownership. PostgreSQL, Redis, Mailpit, volumes, credentials, and logs remain available. Repeated startup uses the checkout lock and reports an existing instance. Unknown or reused PIDs and unrelated port owners are reported rather than terminated. See [lifecycle, recovery, and logs](docs/dev-launcher-lifecycle.md).

### Cleanup and operator procedures

Redundant local launchers, setup scripts and distributed copies have been removed after migrating their consumers and testing the replacement. See the [exact deletion and essential-retention inventory](docs/engineering/dev-launcher-cleanup.md). Production Compose still invokes Uvicorn/Celery directly; application task modules and controlled migration/administration tools remain separate.

Use the [bootstrap guide](scripts/BOOTSTRAP.md), [HCL.CS settings](docs/HCL_IAM_CONFIGURATION.md), [Windows instructions](docs/WINDOWS_NATIVE_SETUP.md) and [verification matrix](docs/engineering/dev-launcher-platform-matrix.md) for prerequisites and limitations. No Windows or full Linux application acceptance is claimed from mocked adapters.

## HCL.CS / HCL IAM mode

Authenticated deployments use HCL.CS/HCL IAM as the OIDC provider. Copy the dedicated examples and follow the full guide:

- [HCL.CS authentication configuration](docs/HCL_IAM_CONFIGURATION.md)
- [Native Windows setup for HCL.CS and SBOM Analyser](docs/WINDOWS_NATIVE_SETUP.md)

Backend essentials:

```dotenv
AUTH_ENABLED=true
HCL_IAM_ISSUER=https://identity.example
HCL_IAM_AUDIENCE=sbom-analyser-api
HCL_IAM_DISCOVERY_URL=https://identity.example/.well-known/openid-configuration
HCL_IAM_JWKS_URL=https://identity.example/.well-known/openid-configuration/jwks
HCL_IAM_CLIENT_ID=sbom-analyser-web
HCL_IAM_ROLE_CLAIM=role
HCL_IAM_TENANT_CLAIM=tenant_id
```

Frontend/BFF essentials:

```dotenv
NEXT_PUBLIC_AUTH_ENABLED=true
NEXT_PUBLIC_HCL_IAM_ISSUER=https://identity.example
NEXT_PUBLIC_HCL_IAM_CLIENT_ID=sbom-analyser-web
NEXT_PUBLIC_HCL_IAM_REDIRECT_URI=https://localhost:3000/auth/callback
NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_REDIRECT_URI=https://localhost:3000/logged-out
NEXT_PUBLIC_HCL_IAM_SCOPES="openid profile email offline_access sbom-analyser-api"
SBOM_API_URL=http://localhost:8000
```

OIDC mode requires HTTPS for the issuer and frontend. For an existing operator-managed HCL.CS installation, retain its registered redirect URIs, CA bundle, database and configuration. `HCL_IAM_CA_BUNDLE` can point the backend or Next.js server to its approved private/local CA certificate. Certificate trust must be reviewed and approved explicitly. Root trust changes require explicit operator approval outside the launcher.

Tenant identity is derived from validated claims and local membership. An optional `X-Tenant-ID` selects one of the authenticated user's memberships; it cannot grant access to an unrelated tenant. Backend RBAC and tenant scoping are authoritative.

Defined roles are `PLATFORM_ADMIN`, `TENANT_ADMIN`, `SECURITY_ANALYST`, `DEVELOPER`, and `VIEWER`.

## Existing native Windows/HCL.CS installations

[Windows/HCL.CS instructions](docs/WINDOWS_NATIVE_SETUP.md) describe using the canonical launcher with preserved literal `.windows/` settings. External identity-service installation, trusted roots, registered redirects and administrator bootstrap remain explicit operator prerequisites.

Use `python scripts/dev.py` for managed local development. Review the [verification matrix](docs/engineering/dev-launcher-platform-matrix.md) before treating Windows execution or migration of an existing HCL.CS installation as validated.

## Configuration

Start with `.env.example` for the backend and `frontend/.env.local.example` for the frontend.

### Core backend settings

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | SQLAlchemy URL; PostgreSQL is the normal runtime database. |
| `ALLOW_SQLITE` | Explicitly permits SQLite fallback for isolated tests/emergency use. |
| `HOST`, `PORT`, `RELOAD` | API bind address, port, and development reload. |
| `CORS_ORIGINS` | Comma-separated browser origins; restrict in shared environments. |
| `AUTH_ENABLED` | Enables HCL.CS/HCL IAM authentication. |
| `DEV_DEFAULT_TENANT` | Enables the synthetic local tenant/user context when auth is disabled. |
| `APP_SECRET_KEY` / `SETTINGS_SECRET_KEY` | Encryption key material for stored provider secrets. |
| `REDIS_URL`, `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND` | Celery broker and independently resolved result-backend configuration. |

### Vulnerability and KEV settings

| Variable | Purpose |
| --- | --- |
| `ANALYSIS_SOURCES` | Comma-separated analysis providers: `NVD,OSV,GITHUB,VULNDB`. |
| `NVD_API_KEY` | Recommended for higher NVD rate limits. |
| `GITHUB_TOKEN` | Enables GitHub advisory/repository calls that require authentication. |
| `VULNDB_API_KEY` | Enables VulDB when included in analysis sources. |
| `KEV_FEED_URL` | CISA KEV JSON feed URL. |
| `KEV_TTL_SECONDS` | KEV refresh interval; default 86400 seconds. |
| `KEV_HTTP_TIMEOUT` | Feed request timeout; default 30 seconds. |
| `KEV_FAILURE_RETRY_SECONDS` | Delay before retrying a failed refresh. |
| `KEV_SINCE_DATE` | Optional `YYYY-MM-DD` cutoff for manual syncs; empty means full catalog. |

### Lifecycle settings

| Variable | Purpose |
| --- | --- |
| `OPENEOX_ENABLED`, `OPENEOX_FEED_URLS` | OpenEoX feed provider. |
| `LIFECYCLE_XEOL_ENABLED`, `LIFECYCLE_XEOL_API_URL`, `LIFECYCLE_XEOL_API_KEY` | Xeol API provider. |
| `XEOL_ENABLED`, `XEOL_DB_PATH`, `XEOL_CLI_PATH` | Local Xeol database/provider. |
| `LIFECYCLE_VENDOR_RECORDS_JSON` | Static fallback custom vendor records. |
| `LIFECYCLE_CACHE_TTL_*` | Known, unknown, deprecated, and failure cache TTLs. |
| `LIFECYCLE_EOL_SOON_DAYS`, `LIFECYCLE_EOS_SOON_DAYS` | Approaching-EOL/EOS thresholds. |

Database-backed provider administration can override supported lifecycle settings at runtime. Secrets are stored separately, encrypted, and returned only as masked previews.

### Optional AI settings

Before saving provider credentials, configure a stable 32-byte base64
`AI_CONFIG_ENCRYPTION_KEY` in the API and worker environment:

```bash
python scripts/generate_encryption_key.py
```

Store the printed value in the deployment secret store; never commit it. Then
use Settings -> AI to add and test Anthropic, OpenAI, Gemini, Grok, Sarvam,
Ollama, vLLM, or a custom OpenAI-compatible endpoint. Settings saved in the
database are authoritative for feature state, kill switch, budgets,
credentials, default, fallback, and active model selection. After saving a
credential, use **Refresh models → Test model → Set active**. Live model lists
are persisted and refreshed daily; discovery never changes the active model
automatically. The corresponding environment variables and catalog model
names are migration/bootstrap fallbacks only when no authoritative DB row
exists.
`AI_FIXES_UI_CONFIG_ENABLED` and `AI_CANARY_PERCENTAGE` remain intentional
deployment controls. See [AI configuration](docs/features/ai-configuration.md).

Never commit real `.env`, `.env.local`, certificates, API keys, or `.windows/` configuration.

## Database migrations

Apply migrations before starting the API. Startup verifies that a non-empty database is at the current Alembic head and refuses to continue when the schema is stale.

```bash
source .venv/bin/activate
python -m alembic current
python -m alembic heads
python -m alembic upgrade head
```

Recent schema work:

| Revision | Change |
| --- | --- |
| `036` | Component extraction reconciliation status. |
| `037` | Stage 9 normalization and deduplication fields. |
| `038`-`039` | Full repair content and large-file workspace metadata. |
| `040` | Analysis run trigger source. |
| `041` | Project/product hierarchy. |
| `042`-`043` | Wider vulnerability evidence and match-reason fields. |
| `044` | Canonical CISA KEV vulnerabilities table and metadata. |
| `054` | Hierarchical Project/Product/SBOM scheduling, explicit current SBOMs, and target policies. |
| `100` | Greenfield UUID finalization. |
| `101` | IAM user public UUID. |
| `102` | Public membership and grant analysis UUID. |
| `103` | Restricted tenant administrator governance permission. |

This table highlights selected revisions, not every migration. Run `python -m alembic heads` to verify the head in the checked-out codebase.

## Background workers

Managed local development starts its required workers through `python scripts/dev.py` with the selected profile's broker and schedule. Do not add a second Beat instance beside that launcher.

The following commands are for explicit operator-managed deployments or isolated smoke tests, not alternative managed development startup. Redis must normally be available before starting workers. Where an operator intentionally uses the existing SQLAlchemy transport for an isolated verification environment, PostgreSQL can provide Kombu's polling broker:

```bash
export CELERY_USE_DATABASE_BROKER=true
```

This setting derives the broker from the existing `DATABASE_URL`, avoiding a
second copy of the database password. A full `sqla+postgresql+psycopg://...`
broker URL is also accepted. The application derives the matching result backend as
`db+postgresql+psycopg://...`. Set `CELERY_RESULT_BACKEND` explicitly if a
different backend is required. This SQLAlchemy broker is appropriate for local
verification, not production throughput; production deployments should use
Redis or another production-grade Celery broker.

```bash
celery -A app.workers.celery_app worker --loglevel=info
celery -A app.workers.celery_app beat --loglevel=info
```

Scheduled work includes NVD mirroring, due analysis schedules, daily KEV sync, CVE cache cleanup, and source-response cache cleanup. Deploy Celery Beat as a single process to avoid duplicate scheduling.

### Hierarchical analysis schedules

Schedules resolve in the order `SBOM > Product > Project > Tenant`. Project and Product schedules target each Product's explicit current SBOM by default; choose `ALL_ACTIVE_VERSIONS` only when historical active versions should also be rescanned. A missing child row inherits, a disabled custom row is paused and blocks inheritance, and an explicit exclusion blocks inheritance without deleting the parent schedule.

Use the Product detail page to select the current SBOM. New Products automatically select their first accepted upload; later uploads replace it only when **Set as current SBOM** is selected. Run Now and the target preview use the same resolver as Celery Beat. See [Hierarchical analysis scheduler](docs/hierarchical-analysis-scheduler.md) for API, operations, and smoke-test details.

## API overview

Use the running application's OpenAPI document for exact request and response schemas.

| API group | Purpose |
| --- | --- |
| `/health`, `/docs` | Health and interactive OpenAPI. |
| `/api/sboms` | SBOM upload, inventory, versions, raw content, conversion, and related workflows. |
| `/api/sbom-validation-sessions` | Validation repair, content access, patches, revalidation, and import. |
| `/api/projects`, `/api/products` | Project/product hierarchy and assignment. |
| `/api/runs`, `/api/v1/compare` | Analysis runs and comparisons. |
| `/api/v1/cves`, `/api/v1/kev` | CVE detail/enrichment and the CISA KEV catalog. |
| `/dashboard` | Dashboard and advanced metrics. |
| `/api/lifecycle`, `/api/admin/lifecycle-*` | Lifecycle results and provider administration. |
| `/api/vex`, `/api/remediation` | VEX and remediation workflows. |
| `/api/schedules` | Scheduled analysis. |
| `/api/tenants`, `/api/auth/me` | Identity, tenant membership, and current context. |
| `/api/ai/copilot`, `/api/v1/ai` | Optional AI workflows, credentials, usage, and fixes. |

## Tests and quality checks

Install development dependencies when working on the codebase:

```bash
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

Backend:

```bash
python -m ruff check .
python -m mypy app
python -m pytest -q
```

Focused KEV tests:

```bash
python -m pytest -q \
  tests/test_kev_enrichment_service.py \
  tests/test_kev_router.py \
  tests/test_kev_sync_worker.py
```

Frontend:

```bash
cd frontend
npm run lint
npx tsc --noEmit
npm test
npm run build
```

Additional manual checks for the KEV UI and integrated findings are documented in [docs/kev_testing_checklist.md](docs/kev_testing_checklist.md).

## Security and deployment notes

- Do not use `AUTH_ENABLED=false` outside isolated local development.
- Use strong encryption keys and an external secret manager in shared environments.
- Restrict CORS, use HTTPS, validate the expected issuer/audience, and use asymmetric JWT algorithms such as RS256.
- Treat frontend visibility as presentation only; enforce every tenant and permission boundary in FastAPI.
- Run Alembic as a deployment step before rolling out new application instances.
- Run one Celery Beat scheduler, monitor worker failures, and back up PostgreSQL.
- Use timeouts, caching, and circuit-breaker behavior for external providers.
- Review upload/workspace storage and retention before accepting production SBOMs.

## Further documentation

- [HCL.CS authentication](docs/HCL_IAM_CONFIGURATION.md)
- [Native Windows setup](docs/WINDOWS_NATIVE_SETUP.md)
- [SBOM validation user guide](docs/sbom-validation.md)
- [Validation repair workspace](docs/sbom-validation-repair-workspace.md)
- [Validation rollout](docs/rollout-sbom-validation.md)
- [Component deduplication](docs/component-deduplication.md)
- [Lifecycle enrichment](docs/lifecycle-enrichment.md)
- [Lifecycle sources](docs/component-lifecycle-sources.md)
- [VEX integration](docs/vex-integration.md)
- [KEV testing checklist](docs/kev_testing_checklist.md)
- [AI providers](docs/ai-providers.md)
- [AI fix runbook](docs/runbook-ai-fixes.md)

## Contributing

Keep changes tenant-aware, permission-checked, migration-safe, and covered by focused tests. Add an Alembic revision for schema changes, avoid external calls without bounded timeouts/cache behavior, and update this README or the relevant runbook whenever setup, configuration, routes, or operational behavior changes.
