# SBOM Analyser

SBOM Analyser is a FastAPI and Next.js platform for importing, validating, normalizing, analysing, and managing software bills of materials. It combines SBOM inventory, multi-source vulnerability analysis, CISA Known Exploited Vulnerabilities (KEV), lifecycle intelligence, VEX, remediation, reporting, tenant isolation, and role-based access control in one application.

The current application version is `2.0.0`. The current Alembic schema head is `044_kev_vulnerabilities_table`.

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
       -> Celery / Redis for scheduled and background work
```

The backend is a modular monolith. HTTP behavior lives in `app/routers`, business behavior in `app/services`, persistence in SQLAlchemy models/repositories, validation in `app/validation`, and asynchronous tasks in `app/workers` and `app/nvd_mirror`.

In authenticated mode, the browser receives only an HTTP-only session cookie. Next.js performs Authorization Code + PKCE, stores and refreshes tokens server-side, and proxies API calls to FastAPI. FastAPI remains the authority for JWT validation, tenant membership, and permissions.

## Main features

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
| Workers | Celery and Redis |
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

## Prerequisites

- Python 3.11 or newer
- Node.js 20 or newer and npm
- PostgreSQL 16
- Redis when running Celery workers/Beat
- Docker Compose if using the provided local PostgreSQL service

## Quick start: macOS/Linux

### 1. Start PostgreSQL

```bash
docker compose up -d postgres
docker compose ps
```

The Compose service maps PostgreSQL to host port `55439` by default. Override it with `POSTGRES_PORT` if needed.

### 2. Configure and run the API

```bash
cp .env.example .env

python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

python -m alembic upgrade head
python run.py
```

The checked-in `.env.example` is ready for local PostgreSQL on port `55439` and has `AUTH_ENABLED=false`. Change all example secrets and credentials before using a shared environment.

### 3. Configure and run the frontend

```bash
cp frontend/.env.local.example frontend/.env.local
cd frontend
npm install
npm run dev
```

For unauthenticated local development, set these values in `frontend/.env.local`:

```dotenv
NEXT_PUBLIC_AUTH_ENABLED=false
NEXT_PUBLIC_API_URL=http://localhost:8000
```

Open [http://localhost:3000](http://localhost:3000). The API is at [http://localhost:8000](http://localhost:8000), health is at [http://localhost:8000/health](http://localhost:8000/health), and OpenAPI is at [http://localhost:8000/docs](http://localhost:8000/docs).

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
NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_REDIRECT_URI=https://localhost:3000
NEXT_PUBLIC_HCL_IAM_SCOPES="openid profile email offline_access sbom-analyser-api"
SBOM_API_URL=http://localhost:8000
```

OIDC mode requires HTTPS for the issuer and frontend. Generate the local frontend certificate and start Next.js with HTTPS:

```bash
cd frontend
npm run setup:https
npm run dev:https
```

Use `npm run setup:https:windows` on Windows. `HCL_IAM_CA_BUNDLE` can point the backend or Next.js server to a private/local CA certificate.

Tenant identity is derived from validated claims and local membership. An optional `X-Tenant-ID` selects one of the authenticated user's memberships; it cannot grant access to an unrelated tenant. Backend RBAC and tenant scoping are authoritative.

Defined roles are `PLATFORM_ADMIN`, `TENANT_ADMIN`, `SECURITY_ANALYST`, `DEVELOPER`, and `VIEWER`.

## Native Windows setup

For a complete Windows installation with local PostgreSQL, HCL.CS, trusted HTTPS certificates, and the SBOM application, use [docs/WINDOWS_NATIVE_SETUP.md](docs/WINDOWS_NATIVE_SETUP.md).

The repository provides:

```text
scripts/windows/Initialize-SbomLocal.ps1
scripts/windows/Start-SbomApi.ps1
scripts/windows/Start-SbomFrontend.ps1
scripts/windows/Stop-SbomLocal.ps1
```

The initializer creates the database and virtual environment, installs backend/frontend dependencies, applies Alembic migrations, configures local certificates, and writes ignored local settings under `.windows/` without overwriting a real `.env` file.

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
| `REDIS_URL`, `CELERY_BROKER_URL` | Celery broker/backend configuration. |

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

Set `AI_FIXES_ENABLED=true` and configure at least one supported provider using environment variables or Settings -> AI. Supported integrations include Anthropic, OpenAI, Gemini, Grok, Sarvam, Ollama, vLLM, and custom OpenAI-compatible endpoints where configured.

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

## Background workers

Redis must be available before starting workers.

```bash
celery -A app.workers.celery_app worker --loglevel=info
celery -A app.workers.celery_app beat --loglevel=info
```

Scheduled work includes NVD mirroring, due analysis schedules, daily KEV sync, CVE cache cleanup, and source-response cache cleanup. Deploy Celery Beat as a single process to avoid duplicate scheduling.

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
