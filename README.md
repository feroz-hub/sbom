# SBOM Analyser

SBOM Analyser is a FastAPI + Next.js platform for uploading, validating, converting, enriching, analysing, and managing SBOMs across their lifecycle.

## 1. Overview

SBOM Analyser helps security, product, compliance, and platform teams manage software bills of materials after they are created. It accepts SBOM uploads, validates them, extracts and deduplicates components, enriches those components with vulnerability and lifecycle intelligence, and provides workflows for VEX, remediation, reporting, versioning, comparison, and administrative governance.

The project supports CycloneDX and SPDX SBOM workflows, including SPDX to CycloneDX conversion where implemented. It is designed as a modular monolith: the backend exposes FastAPI routers over a service layer and SQLAlchemy models, while the frontend provides a Next.js UI for operational workflows.

Main workflows include:

| Workflow | Purpose |
| --- | --- |
| SBOM upload and validation | Import SBOMs safely through validation, quarantine, repair, and revalidation workflows. |
| SBOM conversion | Convert supported SPDX input into CycloneDX representation for downstream processing. |
| Component inventory | Extract, normalize, deduplicate, paginate, and inspect SBOM components. |
| Lifecycle enrichment | Detect EOL, EOS, EOF, deprecated, unsupported, and possibly unmaintained components. |
| Vulnerability analysis | Query configured vulnerability providers and cache results. |
| VEX and remediation | Manage VEX statements, overrides, remediation records, and status. |
| Governance | Use tenants, RBAC, audit logs, provider configuration, and IAM integration. |
| Reporting | Export reports and analysis artifacts for review and compliance. |

## 2. Current Project Status

| Area | Status |
| --- | --- |
| Local development | Supported with PostgreSQL and `AUTH_ENABLED=false`. |
| Internal demo | Supported when local database, migrations, frontend, and dev auth are configured. |
| Production | Not claimed as production-ready from the current repository state. Production use requires full backend and frontend test verification, real HCL IAM verification, secure secrets, restricted CORS, operational monitoring, and deployment hardening. |
| HCL IAM | Implemented in code with backend JWT/JWKS validation and frontend OIDC/PKCE configuration. Real IdP verification is environment-specific and should be completed before production. |
| Multi-tenancy and RBAC | Implemented in backend models, context binding, request access enforcement, and permissions. |
| Lifecycle provider admin | Implemented in backend APIs, database migrations, services, tests, and frontend admin pages. |
| Current verified tests | Targeted lifecycle provider admin tests and lifecycle provider tests have been verified recently. Full backend suite is not documented here as green because it was not reverified as fully passing after all repository changes. |

Recently verified command status in this branch:

```bash
python -m pytest -q tests/test_lifecycle_provider_admin.py
# 12 passed

python -m pytest -q tests -k "lifecycle and provider"
# 34 passed

cd frontend
npx tsc --noEmit
npm test
npm run build
# Verified earlier after the lifecycle admin UI changes
```

Use the project virtual environment when running Python commands. Avoid invoking a global or Anaconda `pytest`.

## 3. Tech Stack

### Backend

| Technology | Usage |
| --- | --- |
| Python | Project requires Python 3.11 or newer. |
| FastAPI | HTTP API and router layer. |
| SQLAlchemy 2.x | ORM and database access. |
| Alembic | Database migrations. |
| PostgreSQL | Primary database for development and deployment. |
| psycopg 3 | PostgreSQL driver. |
| Pydantic / pydantic-settings | Schemas and settings. |
| pytest | Backend tests. |
| ruff | Python linting. |
| Celery / Redis | Present in dependencies and environment configuration for background jobs where used. |
| PyJWT / JWKS | HCL IAM token validation. |
| cryptography | Secret encryption support. |

### Frontend

| Technology | Usage |
| --- | --- |
| Next.js | Frontend application framework. |
| React | UI runtime. |
| TypeScript | Frontend type safety. |
| TanStack Query | API data fetching and caching. |
| Tailwind CSS | Styling. |
| lucide-react | Icon set. |
| Recharts | Charts and dashboard visuals. |
| Vitest / Testing Library | Frontend tests. |

### External Integrations

The repository includes code or configuration for:

| Integration | Purpose |
| --- | --- |
| NVD | CVE and vulnerability intelligence. |
| OSV | Open source vulnerability lookup. |
| deps.dev | Package and dependency intelligence. |
| endoflife.date | Product lifecycle data. |
| OpenEoX | Configurable lifecycle feed source. |
| Xeol API / Xeol DB | Optional lifecycle source. |
| Package registries | Package metadata and lifecycle hints. |
| GitHub / repository health | Repository status and inactivity signals. |
| AI providers | Optional AI copilot/fix support via configured providers. |

## 4. Architecture

SBOM Analyser is organized as a Clean Architecture inspired modular monolith.

```text
Frontend (Next.js)
  -> FastAPI API
  -> Service Layer
  -> SQLAlchemy Models
  -> PostgreSQL
  -> External Providers
```

The backend is split into routers, schemas, services, models, validation modules, lifecycle providers, and migrations. Routers keep HTTP concerns at the edge. Services own business behavior such as validation, enrichment, vulnerability lookup, VEX, remediation, audit logging, tenant handling, and provider configuration. SQLAlchemy models represent persistent state, and Alembic owns schema evolution.

Lifecycle enrichment uses a provider chain:

```text
Component
  -> manual lifecycle override
  -> lifecycle cache
  -> enabled providers sorted by priority
  -> cache upsert
  -> component lifecycle result
```

Provider configuration is cached for short periods, invalidated after admin changes, and falls back to static defaults when database-backed configuration is unavailable.

IAM and request authorization flow:

```text
HCL IAM
  -> Frontend OIDC/PKCE
  -> Backend JWT/JWKS validation
  -> CurrentContext
  -> RBAC
  -> Tenant-scoped data access
```

Tenant isolation is enforced in the backend. The UI may hide controls, but backend permissions and tenant checks are authoritative.

## 5. Core Features

| Feature | Description | Status |
| --- | --- | --- |
| SBOM upload | Upload SBOM documents through the backend API and frontend UI. | Implemented |
| SPDX parsing | Parse supported SPDX SBOMs. | Implemented |
| CycloneDX parsing | Parse supported CycloneDX SBOMs. | Implemented |
| SPDX to CycloneDX conversion | Convert supported SPDX documents to CycloneDX representation. | Implemented |
| 8-stage validation | Guard, detect, schema, semantic, integrity, security, NTIA, and signature stages. | Implemented |
| Validation repair | Quarantine invalid SBOMs, repair validation sessions, and revalidate before import. | Implemented |
| Component extraction | Extract components from accepted SBOMs. | Implemented |
| Component deduplication | Normalize and deduplicate component identities. | Implemented |
| Lifecycle enrichment | Enrich components with lifecycle status, confidence, evidence, and recommendations. | Implemented |
| Vulnerability scanning | Query configured vulnerability sources and cache provider responses. | Implemented |
| VEX | Upload/list/view VEX data and apply statement/override behavior. | Implemented |
| Remediation | Track remediation records, statuses, and history. | Implemented |
| Dashboard | Dashboard APIs and frontend views for summary data. | Implemented |
| Reports/export | Export analysis and reporting artifacts. | Implemented |
| Versioning | Track SBOM versions. | Implemented |
| Compare/restore | Compare versions and restore where supported by the UI/API. | Implemented |
| Project assignment | Assign and organize SBOMs by project. | Implemented |
| Soft/permanent delete | Soft-delete behavior and permanent delete paths exist. | Implemented |
| Scheduled scans | Schedule APIs and frontend route exist. | Implemented |
| AI copilot / AI fixes | Optional AI-assisted workflows with provider configuration. | Optional/configurable |
| Audit logs | Audit log model, service usage, and lifecycle provider admin audit events. | Implemented |
| HCL IAM | OIDC/JWT/JWKS integration and RBAC context. | Implemented but real IdP verification is environment-dependent |
| Multi-tenancy | Tenant models, memberships, tenant context, and scoped data access. | Implemented |
| RBAC | Role and permission checks in backend request handling. | Implemented |
| Lifecycle provider admin UI | Admin pages and APIs for provider configuration, secrets, testing, sync, and vendor records. | Implemented |

## 6. Supported SBOM Formats

The repository includes parsers, validators, and conversion logic for CycloneDX and SPDX.

| Format | Support |
| --- | --- |
| CycloneDX JSON | Supported. |
| CycloneDX XML | Supported where parser/validator paths accept XML. |
| SPDX JSON | Supported. |
| SPDX tag-value | Supported where parser paths accept tag-value input. |
| SPDX 3.0 | Not treated as fully supported. Detection/semantic validation paths indicate SPDX 3.0 support is deferred. |
| Large SBOMs | Upload and validation limits exist; component lists are paginated in the UI/API. |

The original SBOM payload is preserved for raw view/download flows where stored. The UI may show a preview rather than the full raw document for very large SBOMs.

## 7. Validation Pipeline

The validation pipeline is organized into eight stages:

| Stage | Name | Purpose |
| --- | --- | --- |
| 1 | Ingress Guard | Enforce upload size, decompression, and basic safety checks. |
| 2 | Format & Version Detection | Detect SBOM format and supported version. |
| 3 | Structural Schema Validation | Validate document structure against expected schema behavior. |
| 4 | Semantic Validation | Validate domain-level SBOM meaning. |
| 5 | Cross-Reference Integrity | Check references and internal consistency. |
| 6 | Security Checks | Detect unsafe payload characteristics. |
| 7 | NTIA Minimum Elements | Check NTIA minimum SBOM element coverage. |
| 8 | Signature Verification | Feature-flagged signature verification path. |

Valid SBOMs continue into import, component extraction, deduplication, enrichment, and analysis workflows.

Invalid SBOMs can be placed into validation sessions rather than blindly imported. The repair workflow lets users inspect validation errors, apply fixes, and revalidate before import. This prevents failed uploads from becoming corrupted inventory records.

Signature verification is feature-flagged. The current code path treats it as optional and should be verified in the target environment before relying on it for compliance gates.

## 8. Lifecycle Enrichment

Lifecycle enrichment detects and stores component lifecycle state.

Recognized lifecycle statuses include:

| Status | Meaning |
| --- | --- |
| Supported | The product/component appears supported. |
| EOL | End of life. |
| EOS | End of support. |
| EOF | End of fix. |
| Deprecated | Deprecated by vendor/source metadata. |
| Unsupported | Unsupported or archived/disabled by authoritative source. |
| Maintenance | In maintenance mode when provider data indicates it. |
| Extended Support | Extended support period where provider data indicates it. |
| EOL Soon | Approaching configured EOL threshold. |
| Possibly Unmaintained | Repository or metadata signals inactivity without official EOL evidence. |
| Unknown | No reliable lifecycle conclusion. |

Default enabled providers:

| Provider | Default priority |
| --- | --- |
| Red Hat Lifecycle | 10 |
| Official Vendor Lifecycle | 10 |
| endoflife.date | 30 |
| Package Registry | 50 |
| deps.dev | 60 |
| OSV | 70 |
| Repository Health | 80 |

Conditional/configurable providers:

| Provider | Configuration |
| --- | --- |
| Custom Vendor Records | Managed through database-backed admin records and optional `LIFECYCLE_VENDOR_RECORDS_JSON` defaults. |
| OpenEoX | Enabled with provider admin config or `OPENEOX_ENABLED` and feed URLs. |
| Xeol API | Enabled with provider admin config or lifecycle Xeol API environment settings. |
| Local Xeol DB | Enabled with provider admin config or local Xeol DB path. |

Provider behavior:

| Concept | Behavior |
| --- | --- |
| Priority | Lower priority numbers run earlier. Providers are sorted by priority and provider name. |
| Cache-first | Lifecycle cache is checked before calling providers. |
| Deduplication | Duplicate component identities are grouped before provider lookup. |
| Confidence | Provider results include confidence; authoritative high-confidence results can stop fallback. |
| Evidence | Results can include source name, checked time, and evidence URL. |
| Manual override | Manual lifecycle override is checked before provider chain results. |
| Repository health | Repository inactivity should be treated as possibly unmaintained, not official EOL. Archived or disabled repositories may produce a stronger unsupported signal. |

## 9. Lifecycle Provider Admin UI

Lifecycle provider administration is implemented under the admin UI.

Admin users can:

| Capability | Status |
| --- | --- |
| View lifecycle providers | Implemented |
| Enable/disable providers | Implemented |
| Change provider priority | Implemented |
| Configure OpenEoX feed URLs | Implemented |
| Configure Xeol API settings | Implemented |
| Configure local Xeol DB path | Implemented |
| Manage custom vendor lifecycle records | Implemented |
| Store provider secrets securely | Implemented |
| Test provider connection | Implemented |
| Trigger provider sync/refresh | Implemented |
| View provider health and last failure | Implemented |
| View evidence/confidence in lifecycle results | Implemented in lifecycle result display paths |

Security and operational behavior:

| Area | Behavior |
| --- | --- |
| Secrets | Stored separately from provider config and encrypted at rest using an application secret key. |
| API responses | Secret values are never returned; only masked previews are returned. |
| UI | Existing secrets are shown as masked previews. |
| Audit | Provider config, secret, test, sync, and custom vendor record actions are audit logged. |
| Disabled providers | Disabled providers are not instantiated or called. |
| Runtime changes | Normal enable/disable and priority changes apply without application restart through config cache invalidation. |

Backend routes:

```text
/api/admin/lifecycle-providers
/api/admin/lifecycle-vendor-records
/api/lifecycle/sources
/api/lifecycle/provider-status
```

Frontend routes:

```text
/admin/lifecycle-providers
/admin/lifecycle-vendor-records
```

## 10. Vulnerability Analysis

The vulnerability layer integrates with provider clients and cache tables to avoid unnecessary repeated external calls.

| Provider/source | Notes |
| --- | --- |
| NVD | Supports CVE-centric lookup and NVD mirror/cache related paths. Use `NVD_API_KEY` for higher limits. |
| OSV | Used for open source vulnerability lookup. |
| deps.dev | Used for dependency/package intelligence. |
| Package registries | Used for ecosystem metadata and package-derived signals. |
| GitHub/GHSA | GitHub token support exists for repository/provider workflows where configured. |
| KEV/EPSS | Migration history and services include KEV/EPSS-related support. |

Provider calls should use timeouts, caching, and circuit-breaker style behavior where implemented. NVD lookups should prefer precise identifiers such as CVE IDs when available and avoid broad expensive queries when component metadata is incomplete.

## 11. VEX and Remediation

The repository includes VEX and remediation workflows.

| Area | Behavior |
| --- | --- |
| VEX upload/list/view | VEX routes support SBOM-scoped VEX workflows. |
| VEX statements | Statements can affect vulnerability interpretation. |
| VEX overrides | Component-level VEX override and history endpoints exist. |
| Remediation records | Remediation APIs track work items and status. |
| Remediation status | Status transitions and close workflows are present. |
| Audit history | Remediation and provider-admin actions are audit logged where services use the audit layer. |

## 12. Authentication and Authorization

### Local Development

For local development, the simplest mode is:

```bash
export AUTH_ENABLED=false
export DEV_DEFAULT_TENANT=true
```

In this mode, the backend creates or uses a development tenant and user context. This is for local development and internal demos only.

### HCL IAM

HCL IAM is the configured production identity-provider path.

Expected flow:

```text
Frontend OIDC Authorization Code + PKCE
  -> HCL IAM token endpoint
  -> Backend receives bearer JWT
  -> Backend validates JWKS signature, issuer, audience, expiry, and algorithm
  -> Backend resolves local user, tenant membership, role, and permissions
  -> Backend validates X-Tenant-ID against membership
  -> Backend enforces RBAC
```

Required IAM details:

| Detail | Environment/config |
| --- | --- |
| Issuer | `HCL_IAM_ISSUER` |
| Authorization endpoint | Frontend `NEXT_PUBLIC_HCL_IAM_AUTHORIZATION_URL` |
| Token endpoint | Frontend `NEXT_PUBLIC_HCL_IAM_TOKEN_URL` |
| JWKS URL | `HCL_IAM_JWKS_URL` |
| Client ID | `HCL_IAM_CLIENT_ID` and frontend client ID |
| API audience | `HCL_IAM_AUDIENCE` |
| Role claim | `HCL_IAM_ROLE_CLAIM` |
| Tenant claim | `HCL_IAM_TENANT_CLAIM` |
| Test users | Must be provisioned in the target IdP. |
| Test tenants | Must map to local tenant records/memberships. |

Backend authorization is mandatory. The frontend hides unauthorized pages, but the backend is the enforcement point.

## 13. Multi-Tenancy

Tenant-owned records use `tenant_id` where applicable. The backend binds a `CurrentContext` to requests and applies tenant-scoped access rules through SQLAlchemy session behavior and route-level permission checks.

Important behavior:

| Area | Behavior |
| --- | --- |
| Tenant context | Derived from authenticated identity and optional `X-Tenant-ID`. |
| Tenant switch | Supported by frontend context where tenant membership allows it. |
| Platform admin | Intended for global administration and cross-tenant operations. |
| Tenant admin | Operates within tenant policy boundaries. In current permissions, tenant admin is broad; production policy should review exact grants. |
| Dev tenant | Used only when dev auth mode is enabled. |

## 14. RBAC

Defined roles:

| Role | Intended use |
| --- | --- |
| PLATFORM_ADMIN | Platform-wide administration. |
| TENANT_ADMIN | Tenant administration. |
| SECURITY_ANALYST | Security analysis, lifecycle, VEX, remediation, dashboard, schedules, and analysis workflows. |
| DEVELOPER | Development-team read and limited remediation workflows. |
| VIEWER | Read-only access. |

Major permission groups:

| Permission area | Examples |
| --- | --- |
| SBOM | Read, upload, update, delete, export. |
| Project | Read, create, update, delete. |
| Component | Read and update. |
| Lifecycle | Read, override, provider read/update/test/sync, vendor record read/write/delete. |
| VEX | Read and write. |
| Remediation | Read, write, close. |
| Dashboard | Read. |
| Analysis | Read and run. |
| Schedule | Read and write. |
| Tenant | User and settings administration. |
| Platform | Platform administration. |

## 15. Environment Variables

Start from `.env.example` and keep local secrets out of git.

### Database

| Variable | Required | Description |
| --- | --- | --- |
| `DATABASE_URL` | Yes for PostgreSQL | SQLAlchemy database URL. Example: `postgresql+psycopg://sbom:sbom@localhost:55439/sbom_analyser`. |
| `ALLOW_SQLITE` | Optional | Set to `true` only for explicit SQLite test/dev fallback. |
| `DB_POOL_SIZE` | Optional | PostgreSQL pool size. |
| `DB_MAX_OVERFLOW` | Optional | Additional PostgreSQL overflow connections. |
| `DB_POOL_TIMEOUT` | Optional | Pool checkout timeout. |
| `DB_POOL_RECYCLE` | Optional | Connection recycle seconds. |
| `DB_POOL_PRE_PING` | Optional | Enable/disable pre-ping. |

### Auth

| Variable | Required | Description |
| --- | --- | --- |
| `AUTH_ENABLED` | Recommended | `false` for local dev; `true` for IAM-backed environments. |
| `DEV_DEFAULT_TENANT` | Optional | Enable default dev tenant/user in local mode. |
| `HCL_IAM_ISSUER` | IAM | Expected JWT issuer. |
| `HCL_IAM_AUDIENCE` | IAM | Expected API audience. |
| `HCL_IAM_JWKS_URL` | IAM | JWKS endpoint. |
| `HCL_IAM_CLIENT_ID` | IAM | OIDC client ID. |
| `HCL_IAM_ALLOWED_ALGORITHMS` | Optional | JWT algorithms, normally asymmetric algorithms such as `RS256`. |
| `HCL_IAM_ROLE_CLAIM` | Optional | Claim used for role mapping. |
| `HCL_IAM_TENANT_CLAIM` | Optional | Claim used for tenant mapping. |

### Security

| Variable | Required | Description |
| --- | --- | --- |
| `APP_SECRET_KEY` | Required for encrypted provider secrets | Application secret used by lifecycle provider secret encryption. Use a strong value outside local dev. |
| `SETTINGS_SECRET_KEY` | Alternative | Alternative secret key accepted by the lifecycle secret service. |
| `CORS_ORIGINS` | Recommended | Comma-separated allowed frontend origins. Restrict in production. |

### Upload

| Variable/setting | Current default | Description |
| --- | --- | --- |
| `MAX_UPLOAD_BYTES` | 50 MB | Maximum upload size constant in backend settings. Environment override should be verified before relying on it. |
| `MAX_DECOMPRESSED_BYTES` | 200 MB | Maximum decompressed payload size constant. |
| `MAX_DECOMPRESSION_RATIO` | 100 | Decompression bomb guard ratio constant. |

### Lifecycle

| Variable | Description |
| --- | --- |
| `OPENEOX_ENABLED` | Enables OpenEoX environment fallback provider. DB admin config can override runtime behavior. |
| `OPENEOX_FEED_URLS` | Comma-separated OpenEoX feed URLs. |
| `XEOL_ENABLED` | Enables local Xeol DB fallback provider. |
| `XEOL_DB_PATH` | Local Xeol database path. |
| `XEOL_CLI_PATH` | Optional Xeol CLI path. |
| `LIFECYCLE_XEOL_ENABLED` | Enables Xeol API fallback provider. |
| `LIFECYCLE_XEOL_API_URL` | Xeol API base URL. |
| `LIFECYCLE_XEOL_API_KEY` | Xeol API key fallback; prefer encrypted provider secret in DB. |
| `LIFECYCLE_VENDOR_RECORDS_JSON` | JSON defaults for custom vendor records. DB records are runtime source when configured. |
| `LIFECYCLE_CACHE_TTL_KNOWN_DAYS` | TTL for known lifecycle results. |
| `LIFECYCLE_CACHE_TTL_UNKNOWN_HOURS` | TTL for unknown results. |
| `LIFECYCLE_CACHE_TTL_PROVIDER_FAILURE_MINUTES` | TTL for provider failure cache entries. |
| `LIFECYCLE_CACHE_TTL_DEPRECATED_DAYS` | TTL for deprecated results. |
| `LIFECYCLE_EOL_SOON_DAYS` | Threshold for EOL soon. |
| `LIFECYCLE_EOS_SOON_DAYS` | Threshold for EOS soon. |

### Vulnerability Providers

| Variable | Description |
| --- | --- |
| `NVD_API_KEY` | Optional NVD API key for higher request limits. |
| `GITHUB_TOKEN` | Optional GitHub token for GitHub/repository-related provider behavior. |
| `VULNDB_API_KEY` | Optional VulnDB key if that source is configured. |
| `ANALYSIS_SOURCES` | Comma-separated analysis providers in `.env.example`. |

OSV and deps.dev provider settings are primarily code/config driven in the current repository. Add explicit environment variables only when provider code supports them.

### AI Providers

AI support is optional/configurable. Variables present in `.env.example` include:

| Variable | Description |
| --- | --- |
| `AI_FIXES_ENABLED` | Enable AI fix workflows. |
| `AI_FIXES_UI_CONFIG_ENABLED` | Enable UI configuration for AI fixes. |
| `OPENAI_API_KEY` | OpenAI API key. |
| `ANTHROPIC_API_KEY` | Anthropic API key. |
| `GEMINI_API_KEY` | Gemini API key. |
| `GROK_API_KEY` | Grok API key. |
| `SARVAM_API_KEY` | Sarvam API key. |

`OLLAMA_BASE_URL` and `VLLM_BASE_URL` are not present in the inspected `.env.example`; add them only if the corresponding provider code/config is introduced.

## 16. Local Setup

macOS/Linux:

```bash
cd /path/to/sbom
python -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
pip install -r requirements.txt

export DATABASE_URL="postgresql+psycopg://sbom:sbom@localhost:55439/sbom_analyser"
export APP_SECRET_KEY="dev-secret-change-this"
export AUTH_ENABLED=false

python -m alembic upgrade head
python run.py
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

Default local URLs:

| Service | URL |
| --- | --- |
| Backend | `http://localhost:8000` |
| Frontend | `http://localhost:3000` |
| Health | `http://localhost:8000/health` |

## 17. Windows Setup

PowerShell backend setup:

```powershell
cd C:\sbom
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -r requirements.txt

$env:DATABASE_URL="postgresql+psycopg://sbom:sbom@localhost:5432/sbom_analyser"
$env:APP_SECRET_KEY="dev-secret-change-this"
$env:AUTH_ENABLED="false"

python -m alembic upgrade head
python run.py
```

Windows local PostgreSQL setup:

```powershell
# Run these from PowerShell after PostgreSQL is installed and psql is on PATH.
psql -U postgres -c "CREATE USER sbom WITH PASSWORD 'sbom';"
psql -U postgres -c "CREATE DATABASE sbom_analyser OWNER sbom;"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE sbom_analyser TO sbom;"

$env:DATABASE_URL="postgresql+psycopg://sbom:sbom@localhost:5432/sbom_analyser"
```

If `psql` is not on PATH, run it from the PostgreSQL install directory, for example:

```powershell
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -U postgres -c "CREATE USER sbom WITH PASSWORD 'sbom';"
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -U postgres -c "CREATE DATABASE sbom_analyser OWNER sbom;"
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE sbom_analyser TO sbom;"
```

PowerShell frontend setup:

```powershell
cd C:\sbom\frontend
npm install
npm run dev
```

If you use Docker PostgreSQL on Windows and Docker maps PostgreSQL to `55439`, use that port in `DATABASE_URL` instead of `5432`.

## 18. PostgreSQL Setup

### Local PostgreSQL

Use this URL when PostgreSQL listens on the default host port:

```bash
export DATABASE_URL="postgresql+psycopg://sbom:sbom@localhost:5432/sbom_analyser"
```

PowerShell:

```powershell
$env:DATABASE_URL="postgresql+psycopg://sbom:sbom@localhost:5432/sbom_analyser"
```

Create database/user:

```sql
CREATE USER sbom WITH PASSWORD 'sbom';
CREATE DATABASE sbom_analyser OWNER sbom;
GRANT ALL PRIVILEGES ON DATABASE sbom_analyser TO sbom;
```

Windows PowerShell with `psql`:

```powershell
psql -U postgres -c "CREATE USER sbom WITH PASSWORD 'sbom';"
psql -U postgres -c "CREATE DATABASE sbom_analyser OWNER sbom;"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE sbom_analyser TO sbom;"
```

### Docker PostgreSQL

The repository `docker-compose.yml` defines a PostgreSQL 16 service and maps the container port to host port `${POSTGRES_PORT:-55439}`.

```bash
docker compose up -d postgres
docker compose ps
```

If Docker maps PostgreSQL to host port `55439`, use:

```bash
export DATABASE_URL="postgresql+psycopg://sbom:sbom@localhost:55439/sbom_analyser"
```

Always use the mapped host port shown by `docker compose ps`; do not assume it is always `5432`.

## 19. Database Migrations

Alembic is used for schema migrations.

Always run Alembic through the project Python environment:

```bash
source .venv/bin/activate
which python
python -m alembic current
python -m alembic heads
python -m alembic upgrade head
```

The latest inspected migration is:

```text
035_widen_audit_log_fields
```

Migration `034_lifecycle_provider_admin` adds:

| Table | Purpose |
| --- | --- |
| `lifecycle_provider_configs` | DB-backed lifecycle provider settings. |
| `lifecycle_provider_secrets` | Encrypted provider secrets and masked previews. |
| `lifecycle_vendor_records` | Custom vendor lifecycle records. |

Migration `035_widen_audit_log_fields` widens audit log fields so namespaced actions such as `lifecycle.provider_config.update` are stored without truncation.

Common migration rule:

If `DATABASE_URL` is missing, the app fails unless `ALLOW_SQLITE=true` is explicitly set. PostgreSQL is the normal development database.

## 20. Frontend Setup

Create `frontend/.env.local` from `frontend/.env.local.example`.

Local dev:

```bash
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_AUTH_ENABLED=false
```

HCL IAM mode:

```bash
NEXT_PUBLIC_AUTH_ENABLED=true
NEXT_PUBLIC_HCL_IAM_CLIENT_ID=
NEXT_PUBLIC_HCL_IAM_AUTHORIZATION_URL=
NEXT_PUBLIC_HCL_IAM_TOKEN_URL=
NEXT_PUBLIC_HCL_IAM_LOGOUT_URL=
NEXT_PUBLIC_HCL_IAM_REDIRECT_URI=http://localhost:3000/auth/callback
NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_REDIRECT_URI=http://localhost:3000
NEXT_PUBLIC_HCL_IAM_SCOPE="openid profile email"
```

Install and run:

```bash
cd frontend
npm install
npm run dev
```

Build and type-check:

```bash
cd frontend
npx tsc --noEmit
npm run build
```

## 21. Running Tests

Use the virtual environment explicitly:

```bash
cd /path/to/sbom
source .venv/bin/activate
which python
python -c "import sys; print(sys.executable)"
```

Backend:

```bash
python -m ruff check .
python -m pytest -q
python -m pytest -q tests -k "lifecycle"
python -m pytest -q tests/test_lifecycle_provider_admin.py
```

Frontend:

```bash
cd frontend
npx tsc --noEmit
npm test
npm run build
```

Current verified targeted backend status:

```text
tests/test_lifecycle_provider_admin.py: passed
tests -k "lifecycle and provider": passed
```

The full backend test suite should be run before release. This README does not claim the full backend suite is currently green.

## 22. API Overview

Major API groups present in the repository:

| API | Purpose |
| --- | --- |
| `/health` | Health check. |
| `/api/sboms` | SBOM CRUD, upload, raw/download, analysis entry points, components. |
| `/api/sboms/{id}/components` | SBOM component listing. |
| `/api/sboms/{id}/lifecycle` | Lifecycle-related SBOM/component views where routed. |
| `/api/components/{component_id}/lifecycle/refresh` | Refresh lifecycle for a component. |
| `/api/lifecycle/sources` | Safe lifecycle provider source list. |
| `/api/lifecycle/provider-status` | Provider health/status view. |
| `/api/admin/lifecycle-providers` | Admin provider configuration. |
| `/api/admin/lifecycle-vendor-records` | Admin custom vendor records. |
| `/api/projects` | Project management. |
| `/api/runs` | Analysis run management. |
| `/api/dashboard` | Dashboard data. |
| `/api/v1/compare` | SBOM comparison API. |
| `/api/vex` and SBOM-scoped VEX paths | VEX workflows. |
| `/api/remediation` | Remediation workflows. |
| `/api/tenants` | Tenant/user administration. |
| `/api/auth/me` | Current authenticated user/context. |
| `/api/ai/copilot` and `/api/v1/ai` | AI copilot, AI usage, credentials, and AI fix workflows when enabled. |
| `/api/schedules` | Scheduled analysis workflows. |
| `/api/sbom-validation-sessions` | Validation repair session workflows. |

Use the generated OpenAPI schema from the running FastAPI app for exact request/response shapes.

## 23. Large SBOM Handling

Large SBOM behavior includes:

| Area | Behavior |
| --- | --- |
| Upload size | Guarded by backend upload size limits. |
| Decompression | Protected by maximum decompressed size and decompression ratio checks. |
| Raw view | UI may show a preview rather than the entire raw SBOM. |
| Raw download | Use raw/download endpoints to inspect the preserved original when available. |
| Components | Component lists are paginated. |
| Validation | Large files may use asynchronous or session-oriented validation behavior depending on size/path. |

If the UI shows only 10 lines or 10 items, it may be preview or pagination. Check raw download, SBOM stats, and total component counts before assuming the upload failed.

## 24. Troubleshooting

### DATABASE_URL missing

Error:

```text
DATABASE_URL is not configured and fallback to SQLite is not explicitly allowed
```

Fix:

```bash
export DATABASE_URL="postgresql+psycopg://sbom:sbom@localhost:55439/sbom_analyser"
```

Only use SQLite fallback intentionally:

```bash
export ALLOW_SQLITE=true
```

### Wrong PostgreSQL port

Docker may expose PostgreSQL on `55439` instead of `5432`.

Fix:

```bash
docker compose ps
export DATABASE_URL="postgresql+psycopg://sbom:sbom@localhost:<mapped-port>/sbom_analyser"
```

### PostgreSQL password failed

Check username, password, database, and port:

```bash
psql "postgresql://sbom:sbom@localhost:55439/sbom_analyser"
```

### Alembic migration ambiguous parameter

Migration `034_lifecycle_provider_admin` seeds lifecycle provider defaults. The migration should use SQLAlchemy Core upsert behavior rather than fragile raw SQL so PostgreSQL/psycopg can type parameters correctly.

Run:

```bash
python -m alembic heads
python -m alembic current
python -m alembic upgrade head
```

### Audit log StringDataRightTruncation

Lifecycle provider admin writes namespaced audit actions such as `lifecycle.provider_config.update`. Migration `035_widen_audit_log_fields` widens audit log string columns. Run migrations if these writes fail.

### Lifecycle duplicate cache UniqueViolation

Lifecycle cache writes must use idempotent upsert behavior. If duplicate cache keys fail during refresh, inspect lifecycle cache upsert logic and database uniqueness constraints.

### Large SBOM shows only 10 lines/items

This is often pagination or preview behavior. Verify:

```text
raw download
component total count
pagination controls
validation session status
backend logs
```

### HCL IAM not working

Check:

| Item | What to verify |
| --- | --- |
| Issuer | Token `iss` exactly matches `HCL_IAM_ISSUER`. |
| Audience | Token `aud` includes `HCL_IAM_AUDIENCE`. |
| JWKS URL | Backend can fetch keys over HTTPS. |
| Client ID | Frontend and backend agree on client ID. |
| Redirect URI | Registered in IAM and matches frontend env. |
| Role claim | Claim maps to local role names. |
| Tenant claim | Claim maps to tenant membership. |
| CORS | Frontend origin is allowed. |
| Expiry | Token is not expired and clocks are sane. |

### QueuePool exhaustion

QueuePool exhaustion usually means too many concurrent database requests or sessions held too long.

Suggested checks:

| Check | Why |
| --- | --- |
| `DB_POOL_SIZE` / `DB_MAX_OVERFLOW` | Ensure capacity fits local workload. |
| Session lifecycle | Make sure sessions close after request work. |
| Dashboard load | Dashboard endpoints can fan out across several queries. |
| External calls | Avoid holding DB sessions while waiting on slow providers. |

## 25. Security Notes

| Rule | Reason |
| --- | --- |
| Do not commit `.env` files. | They contain secrets and environment-specific values. |
| Do not commit API keys or provider tokens. | Provider secrets must be stored encrypted/masked. |
| Use a strong `APP_SECRET_KEY` in production. | Required for encrypted provider secrets. |
| Restrict `CORS_ORIGINS` in production. | Avoid exposing API access to unintended origins. |
| Use HTTPS for IAM and JWKS URLs. | Protect identity and token validation. |
| Do not use `AUTH_ENABLED=false` in production. | Dev auth bypasses real identity checks. |
| Do not expose provider secrets in logs/API/UI. | Only masked previews should be shown. |
| Enforce tenant isolation in backend code. | UI hiding is not security. |
| Enforce RBAC in backend routes/services. | Every sensitive action must have backend permission checks. |

## 26. Developer Workflow

Recommended workflow:

```bash
git checkout -b codex/your-change-name
source .venv/bin/activate
python -m ruff check .
python -m pytest -q tests/test_lifecycle_provider_admin.py
python -m alembic upgrade head

cd frontend
npx tsc --noEmit
npm run build
```

Before submitting a PR:

| Requirement | Rule |
| --- | --- |
| Code style | Run `python -m ruff check .`. |
| Tests | Run targeted tests for your area and the broader suite when practical. |
| Migrations | Add a new Alembic revision for schema changes; do not silently mutate already-applied production migrations. |
| Secrets | Never log, return, or commit raw secrets. |
| Tenancy | Do not bypass tenant checks. |
| Providers | Do not call slow external providers without timeout/cache behavior. |
| Upload path | Avoid blocking SBOM upload on slow external provider calls where practical. |
| Docs | Update README/docs when setup, APIs, migrations, or behavior changes. |

## 27. Known Limitations

| Limitation | Notes |
| --- | --- |
| Production readiness | Not claimed from current repo state without full test pass, real IAM verification, and deployment hardening. |
| HCL IAM | Code exists, but real IdP behavior must be verified in the target HCL IAM tenant. |
| Full backend suite | Targeted lifecycle/provider tests are verified; full backend suite should be run before release. |
| Official vendor lifecycle data | Some vendor provider behavior may depend on static mappings or provider-specific implementation depth. Verify before relying on a given vendor. |
| Xeol CLI/sync | Local DB/API paths are configurable; scheduled or CLI sync behavior should be verified per deployment. |
| SPDX 3.0 | Support is deferred/not fully supported by current validation behavior. |
| Upload limits | Upload/decompression limits are code-defined and should be reviewed before large production imports. |

## 28. Roadmap

Short-term roadmap:

| Item | Goal |
| --- | --- |
| Real HCL IAM staging verification | Validate OIDC/JWKS/claims/tenant mapping with real IdP users. |
| Full test suite stabilization | Keep backend and frontend suites green together. |
| Scheduled lifecycle provider sync | Expand background sync for feed and local DB providers. |
| Expanded official vendor APIs | Improve vendor-specific authoritative lifecycle coverage. |
| Better large SBOM viewer | Improve raw preview, pagination, and navigation for very large files. |
| Production deployment hardening | Secrets, TLS, monitoring, migrations, backup, and operational runbooks. |

## 29. Contributing

Contributions should keep the platform secure, tenant-aware, and testable.

Guidelines:

| Area | Expectation |
| --- | --- |
| Style | Follow existing FastAPI, service, schema, model, and frontend conventions. |
| Tests | Add focused tests for new behavior and regressions. |
| Migrations | Use Alembic for schema changes and keep migrations idempotent where practical. |
| Secrets | Never store raw secrets in config tables, logs, responses, or tests. |
| RBAC | Add and enforce permissions for new privileged actions. |
| Tenancy | Ensure tenant-owned data is scoped. |
| Providers | Use cache, timeout, and fallback behavior for external integrations. |
| Documentation | Update README or docs when developer workflow changes. |
