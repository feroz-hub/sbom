# SBOM Analyzer

A full-stack **Software Bill of Materials (SBOM) vulnerability analysis platform**.

Upload SBOMs, persist extracted components, scan them against NVD, GitHub Security Advisories, OSV, and VulDB, and generate PDF vulnerability reports from a Next.js dashboard backed by FastAPI.

| Service | URL |
|---------|-----|
| Frontend UI | http://localhost:3000 |
| Backend API | http://localhost:8000 |
| Swagger docs | http://localhost:8000/docs |
| Health check | http://localhost:8000/health |

---

## Quick start (full stack)

Run these in order on a fresh machine. Use **two terminals** for the API and UI at the end.

```bash
# 1. Bootstrap (optional — installs Python 3.11, Node 20, venv, npm deps, seeds .env files)
cd /path/to/sbom
./scripts/bootstrap.sh

# 2. PostgreSQL
docker compose up -d postgres
docker compose ps

# 3. Configure backend environment
cp .env.example .env
# Edit .env if needed — default DATABASE_URL uses host port 55439

# 4. Migrate database
source .venv/bin/activate
export DATABASE_URL="postgresql+psycopg://sbom:sbom@localhost:55439/sbom_analyser"
python -m alembic upgrade head
python scripts/check_database.py

# 5. Terminal A — backend API (local dev, no HCL IAM login)
export AUTH_ENABLED=false
python3 run.py

# 6. Terminal B — frontend UI
cd frontend
cp .env.local.example .env.local
npm ci
npm run dev
```

Open **http://localhost:3000**. In dev mode (`AUTH_ENABLED=false`) the API uses a synthetic admin context — no login required.

---

## Commands reference

All commands assume the repository root unless noted. Activate the virtual environment first:

```bash
source .venv/bin/activate          # macOS / Linux
# .\.venv\Scripts\Activate.ps1     # Windows PowerShell
```

### One-time setup

```bash
# Automated bootstrap (recommended)
./scripts/bootstrap.sh               # add --skip-system if Python/Node already installed

# Manual backend
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
cp .env.example .env

# Manual frontend
cd frontend
npm ci
cp .env.local.example .env.local
```

Windows bootstrap:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\bootstrap.ps1            # add -SkipSystem if Python/Node already installed
```

### PostgreSQL

```bash
# Start / stop / status
docker compose up -d postgres
docker compose ps
docker compose logs -f postgres
docker compose stop postgres
docker compose down                  # removes containers; keeps volume data

# Default connection (host port 55439 → container 5432)
export DATABASE_URL="postgresql+psycopg://sbom:sbom@localhost:55439/sbom_analyser"
```

Set in `.env`:

```env
DATABASE_URL=postgresql+psycopg://sbom:sbom@localhost:55439/sbom_analyser
POSTGRES_PORT=55439
```

### Database migrations (Alembic)

PostgreSQL schema changes **must** be applied before starting the API. Use the project venv — do not call a global `alembic` binary.

```bash
source .venv/bin/activate
export DATABASE_URL="postgresql+psycopg://sbom:sbom@localhost:55439/sbom_analyser"

python -m alembic heads
python -m alembic current
python -m alembic upgrade head
python -m alembic check
python -m alembic history            # list migration chain
python scripts/check_database.py   # verify connectivity, dialect, alembic head
```

### Run the backend API

```bash
source .venv/bin/activate
export DATABASE_URL="postgresql+psycopg://sbom:sbom@localhost:55439/sbom_analyser"

# Local development (no HCL IAM — synthetic admin context)
export AUTH_ENABLED=false
python3 run.py

# With auto-reload on code changes
export RELOAD=true
python3 run.py

# Alternative entry point
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Verify after start:

```bash
curl -s http://localhost:8000/health
curl -s http://localhost:8000/api/auth/me    # dev context when AUTH_ENABLED=false
```

### Run the frontend

```bash
cd frontend

# Development server (hot reload)
npm run dev

# Type-check
npx tsc --noEmit

# Unit tests
npm test
npm run test:watch

# Production build + serve
npm run build
npm run start

# Lint
npm run lint
```

Required in `frontend/.env.local`:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_AUTH_ENABLED=false
```

### HCL IAM authentication (production)

Backend `.env`:

```env
AUTH_ENABLED=true
DEV_DEFAULT_TENANT=true
API_AUTH_MODE=none
HCL_IAM_ISSUER=https://<hcl-iam-domain>/<issuer-path>
HCL_IAM_AUDIENCE=sbom-analyser-api
HCL_IAM_JWKS_URL=https://<hcl-iam-domain>/<jwks-path>
HCL_IAM_CLIENT_ID=sbom-analyser-ui
HCL_IAM_ALLOWED_ALGORITHMS=RS256
HCL_IAM_ROLE_CLAIM=roles
HCL_IAM_TENANT_CLAIM=tenant_id
```

Frontend `frontend/.env.local`:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_AUTH_ENABLED=true
NEXT_PUBLIC_HCL_IAM_ISSUER=https://<hcl-iam-domain>/<issuer-path>
NEXT_PUBLIC_HCL_IAM_CLIENT_ID=sbom-analyser-ui
NEXT_PUBLIC_HCL_IAM_REDIRECT_URI=http://localhost:3000/auth/callback
NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_URI=http://localhost:3000
# Optional explicit OIDC URLs (override issuer-derived Keycloak-style paths):
# NEXT_PUBLIC_HCL_IAM_AUTHORIZATION_URL=...
# NEXT_PUBLIC_HCL_IAM_TOKEN_URL=...
# NEXT_PUBLIC_HCL_IAM_LOGOUT_URL=...
```

Then start backend and frontend as above. The UI redirects to HCL IAM for login; the API validates JWTs via JWKS and enforces tenant RBAC.

Identity / tenant admin API (requires valid bearer token + tenant context):

```bash
curl -s -H "Authorization: Bearer <token>" \
     -H "X-Tenant-ID: 1" \
     http://localhost:8000/api/auth/me

curl -s -H "Authorization: Bearer <token>" \
     http://localhost:8000/api/tenants
```

### Legacy bearer / JWT gate (deprecated for production)

Use HCL IAM in production. Legacy modes remain for isolated tooling:

```bash
# Bearer allowlist
export API_AUTH_MODE=bearer
export API_AUTH_TOKENS=tok-strong-random-1,tok-strong-random-2
python3 run.py

# HS256 JWT
export API_AUTH_MODE=jwt
export JWT_SECRET_KEY=your-secret
python3 run.py
```

The server refuses to start if `API_AUTH_MODE=bearer` and `API_AUTH_TOKENS` is empty.

### Background analysis (Celery + Redis)

Default dev runs scans **synchronously** in the API process. For background workers:

```bash
# .env
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0
```

```bash
# macOS / Linux — one process per terminal
./scripts/celery_worker.sh
./scripts/celery_beat.sh        # beat must run as a SINGLE instance
```

```powershell
# Windows (PowerShell)
celery -A app.workers.celery_app worker --loglevel=info
celery -A app.workers.celery_app beat --loglevel=info
```

### Tests and quality checks

```bash
source .venv/bin/activate
export DATABASE_URL="postgresql+psycopg://sbom:sbom@localhost:55439/sbom_analyser"

# Full backend test suite (most tests use isolated temp SQLite automatically)
python -m pytest -q
python -m pytest tests/ -v

# Targeted suites
python -m pytest tests/test_hcl_iam_auth.py -q
python -m pytest tests/test_auth_integration.py -q
python -m pytest tests/test_rbac_permissions.py -q
python -m pytest tests/test_tenant_isolation.py -q

# PostgreSQL integration tests (optional — requires disposable test DB)
export TEST_POSTGRES_DATABASE_URL="postgresql+psycopg://sbom:sbom@localhost:55439/sbom_analyser_test"
python -m pytest tests/test_postgresql_integration.py -q

# Lint / format
ruff check .
ruff check . --fix
git diff --check
```

```bash
cd frontend
npm test
npx tsc --noEmit
npm run build
```

Re-baseline snapshot tests: delete the file under `tests/snapshots/`, run pytest once to capture, run again to lock.

### AI fix tooling

```bash
source .venv/bin/activate

# Generate credential encryption key (required for DB-stored AI providers)
python scripts/generate_encryption_key.py
python scripts/generate_encryption_key.py --append-to-env

# Migrate .env provider keys into encrypted DB store
python scripts/migrate_env_to_db.py --dry-run
python scripts/migrate_env_to_db.py

# Verify rollout gates
python scripts/verify_ai_rollout.py --pretty

# Smoke-test live provider
python scripts/ai_fix_smoke.py
python scripts/ai_fix_smoke.py --provider openai
```

### SQLite → PostgreSQL migration

Use a maintenance window — stop API, Celery, and beat before migrating.

```bash
mkdir -p backups
sqlite3 ./sbom_api.db ".backup './backups/sbom_api-pre-postgres.db'"
shasum -a 256 ./sbom_api.db ./backups/sbom_api-pre-postgres.db

# Preflight (read-only)
python scripts/migrate_sqlite_to_postgres.py \
  --sqlite-url sqlite:///./sbom_api.db \
  --postgres-url postgresql+psycopg://sbom:sbom@localhost:55439/sbom_analyser \
  --dry-run

# Copy (single transaction)
python scripts/migrate_sqlite_to_postgres.py \
  --sqlite-url sqlite:///./sbom_api.db \
  --postgres-url postgresql+psycopg://sbom:sbom@localhost:55439/sbom_analyser

# Verify only
python scripts/migrate_sqlite_to_postgres.py \
  --sqlite-url sqlite:///./sbom_api.db \
  --postgres-url postgresql+psycopg://sbom:sbom@localhost:55439/sbom_analyser \
  --verify-only

# Clear disposable target (requires explicit flags)
python scripts/migrate_sqlite_to_postgres.py \
  --sqlite-url sqlite:///./sbom_api.db \
  --postgres-url postgresql+psycopg://sbom:sbom@localhost:55439/sbom_analyser \
  --truncate-target --confirm-truncate

# Post-migration backup
pg_dump --format=custom \
  --file=./backups/sbom_analyser-post-migration.dump \
  postgresql://sbom:sbom@localhost:55439/sbom_analyser
```

### Diagnostics

```bash
source .venv/bin/activate
export DATABASE_URL="postgresql+psycopg://sbom:sbom@localhost:55439/sbom_analyser"

python scripts/check_database.py
python scripts/db_pool_diagnostics.py
```

### Docs maintenance

```bash
source .venv/bin/activate
python scripts/gen_error_code_reference.py          # regenerate validation error code table
python scripts/gen_error_code_reference.py --check  # CI: fail if doc is out of sync
```

### Manual verification checklist (HCL IAM / multi-tenant)

```bash
source .venv/bin/activate
export DATABASE_URL="postgresql+psycopg://sbom:sbom@localhost:55439/sbom_analyser"
export AUTH_ENABLED=false

python -m alembic upgrade head
python scripts/check_database.py
python3 run.py &
sleep 3
curl -s http://localhost:8000/health
curl -s http://localhost:8000/api/auth/me
kill %1

cd frontend && npm run dev
```

Confirm: upload SBOM sets `tenant_id`, dashboard is tenant-scoped, cross-tenant ID access returns 404/403, tenant admin UI at `/settings/tenant`.

---

## Local Development

The **[Commands reference](#commands-reference)** above lists every setup, run, test, and migration command. The subsections below summarize the same flows with platform-specific notes.

### One-command bootstrap (recommended)

Installer scripts bring a fresh machine to a working dev state — they install
Python 3.11 + Node 20, create the venv, run `npm ci`, and seed `.env` /
`.env.local` from the example files. Both are idempotent.

```bash
# macOS / Linux
./scripts/bootstrap.sh            # add --skip-system if you already have Python/Node
```

```powershell
# Windows (PowerShell)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\bootstrap.ps1           # add -SkipSystem if you already have Python/Node
```

See [`scripts/BOOTSTRAP.md`](./scripts/BOOTSTRAP.md) for what gets installed per OS.

After bootstrap, start PostgreSQL, run migrations, then launch backend and frontend — see [Quick start](#quick-start-full-stack).

### Manual backend setup

```bash
# macOS / Linux
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
cp .env.example .env
docker compose up -d postgres
python -m alembic upgrade head
export AUTH_ENABLED=false
python3 run.py
```

```powershell
# Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
docker compose up -d postgres
python -m alembic upgrade head
$env:AUTH_ENABLED="false"
python run.py
```

The backend API starts on **http://localhost:8000**.

- `GET /` returns API service metadata
- `GET /docs` opens the FastAPI Swagger UI
- `GET /health` returns the API health check
- `GET /api/auth/me` returns the current identity context

### Manual frontend setup

```bash
# macOS / Linux
cd frontend
npm ci
cp .env.local.example .env.local
npm run dev
```

```powershell
# Windows (PowerShell)
cd frontend
npm ci
Copy-Item .env.local.example .env.local
npm run dev
```

Open the primary Next.js UI at **http://localhost:3000**.

---

## Runtime Behavior

- Uploading an SBOM to `POST /api/sboms` stores the SBOM row first, then immediately extracts and persists its components.
- After component sync, the backend triggers best-effort multi-source analysis automatically.
- If analysis fails, the uploaded SBOM and its extracted components still remain available in the UI and API.
- Manual re-analysis is available via `POST /api/sboms/{id}/analyze`.

The root API endpoint returns this shape:

```json
{
  "service": "sbom-analyzer-api",
  "version": "2.0.0",
  "docs_url": "/docs",
  "health_url": "/health"
}
```

---

## Project Structure

```
sbom/
├── run.py                  # Entry point
├── requirements.txt        # Python dependencies
├── pytest.ini              # Pytest configuration
├── .env.example            # Environment variable template
├── samples/                # Sample SBOM payloads for local testing
├── tests/                  # Pytest snapshot regression suite (see "Tests")
├── frontend/               # Primary Next.js dashboard
│   ├── package.json
│   ├── next.config.mjs     # API rewrites to the FastAPI backend
│   └── src/
│       ├── app/            # Route entry points
│       ├── components/     # UI building blocks and feature components
│       └── lib/            # API client and shared utilities
└── app/
    ├── main.py             # FastAPI application wiring + startup hook
    ├── settings.py         # Pydantic Settings singleton
    ├── analysis.py         # SBOM parsers + multi-source orchestrator
    ├── models.py           # SQLAlchemy ORM models
    ├── schemas.py          # Pydantic request/response schemas
    ├── db.py               # PostgreSQL/SQLite engine and session setup
    ├── pdf_report.py       # PDF report generation (ReportLab)
    ├── logger.py           # Structured/text logging setup
    ├── routers/            # HTTP handlers (sboms_crud, analyze_endpoints,
    │                       #  runs, projects, pdf, dashboard, health, ...)
    ├── services/           # Business logic + persistence helpers
    └── sources/            # Vulnerability source adapter package
        ├── base.py         # `VulnSource` Protocol + `SourceResult` TypedDict
        ├── nvd.py          # `NvdSource(api_key=...)`
        ├── osv.py          # `OsvSource()`
        ├── ghsa.py         # `GhsaSource(token=...)`
        ├── vulndb.py       # `VulnDbSource(api_key=...)`
        ├── registry.py     # name → adapter class lookup
        ├── runner.py       # `run_sources_concurrently(...)` fan-out
        ├── purl.py         # PURL parser
        ├── cpe.py          # PURL → CPE 2.3 generator
        ├── severity.py     # CVSS helpers + severity bucketing
        └── dedupe.py       # Two-pass CVE↔GHSA cross-deduplication
```

Every analyze endpoint — `POST /api/sboms/{id}/analyze`, `POST /api/sboms/{id}/analyze/stream`,
and the five `POST /analyze-sbom-{nvd,github,osv,vulndb,consolidated}` ad-hoc routes — fans
out through the `app.sources` adapter registry via `run_sources_concurrently`.
Adding a fourth source (e.g. Snyk, OSS Index) is a one-line change in
`app/sources/registry.py` plus a new module under `app/sources/`.

## Tests

See [Tests and quality checks](#tests-and-quality-checks) in the commands reference for the full list. Quick run:

```bash
# macOS / Linux
source .venv/bin/activate
python -m pytest tests/
```

```powershell
# Windows (PowerShell) — after activating the venv
python -m pytest tests/
```

The suite is a deterministic snapshot regression net: every analyze endpoint
is exercised against an isolated temp SQLite database with the underlying
NVD/GHSA/OSV coroutines monkeypatched to return canned data, and the JSON
responses are diffed against locked baseline files in
`tests/snapshots/`. To intentionally re-baseline a snapshot, delete its
file under `tests/snapshots/` and re-run pytest — the next run captures
the new shape and the run after that asserts it stays stable.

---

## Authentication

Production uses **HCL IAM** (OIDC + JWKS JWT validation) with multi-tenant RBAC.
Local development uses `AUTH_ENABLED=false`, which injects a synthetic admin
context so no login is required.

### HCL IAM (production)

```bash
# .env
AUTH_ENABLED=true
API_AUTH_MODE=none
HCL_IAM_ISSUER=https://<hcl-iam-domain>/<issuer-path>
HCL_IAM_AUDIENCE=sbom-analyser-api
HCL_IAM_JWKS_URL=https://<hcl-iam-domain>/<jwks-path>
HCL_IAM_CLIENT_ID=sbom-analyser-ui
```

The server refuses to start when `AUTH_ENABLED=true` but required HCL IAM
variables are missing. Set matching `NEXT_PUBLIC_*` values in
`frontend/.env.local` — see [HCL IAM authentication](#hcl-iam-authentication-production).

**Protected routes** (require a valid HCL IAM bearer token when `AUTH_ENABLED=true`):

- All `/api/*` routes (sboms, projects, runs, findings, tenants, auth, …)
- All `/analyze-sbom-*` ad-hoc routes
- All `/dashboard/*` routes

**Open routes** (no auth required, for liveness probes and `/docs`):

- `GET /`
- `GET /health`
- `GET /docs`, `GET /openapi.json`, `GET /redoc`

Roles (`TENANT_ADMIN`, `SECURITY_ANALYST`, `VIEWER`, …) are enforced via
`enforce_request_access` and tenant-scoped ORM filters. Cross-tenant resource
access returns 404 or 403.

### Local development (no login)

```bash
export AUTH_ENABLED=false
export DEV_DEFAULT_TENANT=true
python3 run.py
```

### Legacy bearer / JWT gate (deprecated)

Bearer-token and HS256 JWT gates are **deprecated for production** — use HCL IAM
instead. They remain available for isolated tooling:

```bash
export API_AUTH_MODE=bearer
export API_AUTH_TOKENS=tok-strong-random-1,tok-strong-random-2
python3 run.py
```

The server will refuse to start if `API_AUTH_MODE=bearer` is set but
`API_AUTH_TOKENS` is empty.

Multiple tokens in `API_AUTH_TOKENS` (comma-separated) lets you rotate
per-client without downtime: add a new one, redeploy clients, then
remove the old one.

---

## AI Fix Configuration

See [AI fix tooling](#ai-fix-tooling) in the commands reference for script invocations.

The platform can generate AI-assisted remediation guidance for findings.
This is **opt-in** and supports seven providers — Anthropic, OpenAI, Google
Gemini (free tier), xAI Grok (free tier), Sarvam AI, Ollama (self-hosted),
vLLM (self-hosted) — plus any custom OpenAI-compatible endpoint.

There are two ways to configure providers:

- **Settings → AI page** (`/settings/ai`) — add/edit providers at runtime,
  stored **encrypted in the DB**, no restart needed. Recommended for production.
- **Environment variables** (`.env`) — seed a provider at boot. Good for local dev.

### 1. Generate the credential encryption key (required for DB-stored providers)

Any provider credential saved through the Settings UI is encrypted at rest with
`AI_CONFIG_ENCRYPTION_KEY`. Generate one once and store it like any other
production secret — **losing it makes every saved provider credential
unrecoverable**.

```bash
# macOS / Linux
python scripts/generate_encryption_key.py                 # prints the key
python scripts/generate_encryption_key.py --append-to-env # writes it into .env
```

```powershell
# Windows (PowerShell) — after activating the venv
python scripts\generate_encryption_key.py
python scripts\generate_encryption_key.py --append-to-env
```

### 2. Configure providers via `.env`

The AI provider keys live at the bottom of `.env.example`. Set at least one and
point `AI_DEFAULT_PROVIDER` at an enabled provider:

```bash
AI_FIXES_ENABLED=true
AI_FIXES_UI_CONFIG_ENABLED=true       # exposes the Settings → AI page
AI_DEFAULT_PROVIDER=anthropic
AI_CONFIG_ENCRYPTION_KEY=<from step 1>

ANTHROPIC_API_KEY=     # AI_ANTHROPIC_MODEL=claude-sonnet-4-5
OPENAI_API_KEY=        # AI_OPENAI_MODEL=gpt-4o-mini
GEMINI_API_KEY=        # AI_GEMINI_MODEL=gemini-2.5-flash   (free tier)
GROK_API_KEY=          # AI_GROK_MODEL=grok-2-mini          (free tier)
SARVAM_API_KEY=        # AI_SARVAM_MODEL=sarvam-m  AI_SARVAM_BASE_URL=https://api.sarvam.ai/v1
# Ollama / vLLM / custom — add via the Settings → AI page (base URL + model)
```

Get API keys: Anthropic `console.anthropic.com/settings/keys` ·
OpenAI `platform.openai.com/api-keys` · Gemini `aistudio.google.com/app/apikey` ·
Grok `console.x.ai` · Sarvam `dashboard.sarvam.ai`. Full provider matrix and
pricing: [`docs/ai-providers.md`](./docs/ai-providers.md). Admin walkthrough:
[`docs/features/ai-configuration.md`](./docs/features/ai-configuration.md).

### 3. Migrate `.env` providers into the encrypted DB store (optional)

If you started with env-var keys and want them managed through the UI:

```bash
python scripts/migrate_env_to_db.py --dry-run   # preview, no writes
python scripts/migrate_env_to_db.py             # actually migrate (idempotent)
```

### 4. Verify and smoke-test

```bash
# Confirm every AI rollout gate behaves as specified
python scripts/verify_ai_rollout.py --pretty

# Run the orchestrator against real provider output (needs a live key)
python scripts/ai_fix_smoke.py                  # uses the default provider
python scripts/ai_fix_smoke.py --provider openai
```

---

## Background Analysis (Celery)

Default dev runs scans **synchronously** inside the API process — no broker
needed. See [Background analysis (Celery + Redis)](#background-analysis-celery--redis) in the commands reference.

```bash
# .env
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0
```

```bash
# macOS / Linux — one process per command, in separate terminals
./scripts/celery_worker.sh
./scripts/celery_beat.sh        # beat must run as a SINGLE instance
```

```powershell
# Windows (PowerShell) — equivalent invocations
celery -A app.workers.celery_app worker --loglevel=info
celery -A app.workers.celery_app beat --loglevel=info
```

---

## Database Migrations (Alembic)

PostgreSQL 16 is the development and production database. SQLite remains
supported for isolated tests and emergency rollback. PostgreSQL schema changes
must be applied by Alembic before the API starts; the API deliberately does not
create or alter PostgreSQL tables during startup.

Full command list: [Database migrations (Alembic)](#database-migrations-alembic) and [SQLite → PostgreSQL migration](#sqlite--postgresql-migration).

### Start PostgreSQL locally

Docker maps container port `5432` to host port `55439` by default so the stack does not
conflict with a system PostgreSQL instance already bound to `5432`.

```bash
docker compose up -d postgres
docker compose ps
```

Configure `.env`:

```env
DATABASE_URL=postgresql+psycopg://sbom:sbom@localhost:55439/sbom_analyser
```

Create or upgrade the schema, verify, then run the API:

> [!WARNING]
> Do not use global `alembic`; use `python -m alembic` from the project virtual environment (after activating it).

```bash
source .venv/bin/activate
python -m alembic heads
python -m alembic upgrade head
python -m alembic current
python -m alembic check
python scripts/check_database.py
export AUTH_ENABLED=false
python3 run.py
```

### Migrate an existing SQLite database

See [SQLite → PostgreSQL migration](#sqlite--postgresql-migration) for the full command sequence. Summary:

```bash
mkdir -p backups
sqlite3 ./sbom_api.db ".backup './backups/sbom_api-pre-postgres.db'"
shasum -a 256 ./sbom_api.db ./backups/sbom_api-pre-postgres.db
```

The PostgreSQL schema must already be at Alembic head. First perform a read-only
preflight:

```bash
python scripts/migrate_sqlite_to_postgres.py \
  --sqlite-url sqlite:///./sbom_api.db \
  --postgres-url postgresql+psycopg://sbom:sbom@localhost:55439/sbom_analyser \
  --dry-run
```

Copy all application tables in one PostgreSQL transaction:

```bash
python scripts/migrate_sqlite_to_postgres.py \
  --sqlite-url sqlite:///./sbom_api.db \
  --postgres-url postgresql+psycopg://sbom:sbom@localhost:55439/sbom_analyser
```

Verify row counts, complete primary-key digests, raw SBOM hashes, foreign keys,
constraints, and relationships:

```bash
python scripts/migrate_sqlite_to_postgres.py \
  --sqlite-url sqlite:///./sbom_api.db \
  --postgres-url postgresql+psycopg://sbom:sbom@localhost:55439/sbom_analyser \
  --verify-only
```

The target must be empty by default. Clearing a disposable or pre-backed-up
target requires both explicit flags:

```bash
python scripts/migrate_sqlite_to_postgres.py \
  --sqlite-url sqlite:///./sbom_api.db \
  --postgres-url postgresql+psycopg://sbom:sbom@localhost:55439/sbom_analyser \
  --truncate-target --confirm-truncate
```

After verification and API smoke tests, create a PostgreSQL backup before
opening traffic:

```bash
pg_dump --format=custom \
  --file=./backups/sbom_analyser-post-migration.dump \
  postgresql://sbom:sbom@localhost:55439/sbom_analyser
```

### Rollback

- Never remove or overwrite the original SQLite database during migration.
- If copy or verification fails, keep `DATABASE_URL` pointed at SQLite.
- If pre-traffic API smoke tests fail, stop the API and restore the SQLite URL.
- Do not permit application writes on PostgreSQL until all smoke tests pass;
  this avoids split-brain reconciliation during rollback.
- If a populated PostgreSQL target was cleared, restore its pre-migration
  `pg_dump` before investigating.
- Retain both the SQLite backup and the post-migration PostgreSQL dump for the
  agreed operational retention period.

---

## API Overview

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | API service metadata |
| GET | `/health` | Health check |
| GET | `/dashboard/stats` | Project / SBOM / vulnerability counts |
| GET | `/dashboard/recent-sboms` | Recently uploaded SBOMs |
| GET | `/dashboard/activity` | Active vs stale SBOM chart data |
| GET | `/dashboard/severity` | Vulnerability severity breakdown |

> Every row below requires a valid bearer token when `AUTH_ENABLED=true` (HCL IAM)
> or when `API_AUTH_MODE=bearer`. See the **Authentication** section above.
| GET/POST | `/api/projects` | List / create projects |
| GET/PATCH/DELETE | `/api/projects/{id}` | Get / update / delete project |
| GET/POST | `/api/sboms` | List / upload SBOMs; upload also persists extracted components |
| GET/PATCH/DELETE | `/api/sboms/{id}` | Get / update / delete SBOM |
| GET | `/api/sboms/{id}/components` | List components extracted from an SBOM |
| POST | `/api/sboms/{id}/analyze` | Trigger or re-run multi-source analysis |
| GET | `/api/runs` | List analysis runs |
| GET | `/api/runs/{id}/findings` | List vulnerability findings for a run |
| POST | `/analyze-sbom-nvd` | NVD-only ad-hoc scan |
| POST | `/analyze-sbom-github` | GitHub Advisory ad-hoc scan |
| POST | `/analyze-sbom-osv` | OSV ad-hoc scan |
| POST | `/analyze-sbom-vulndb` | VulDB / VulnDB ad-hoc scan |
| POST | `/analyze-sbom-consolidated` | Combined NVD + GHSA + OSV + VulDB scan |
| POST | `/api/pdf-report` | Generate PDF for a completed run |

Full interactive docs: **http://localhost:8000/docs**

---

## Environment Variables

### Backend (`.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `NVD_API_KEY` | *(none)* | NIST NVD API key (faster rate limit) |
| `GITHUB_TOKEN` | *(none)* | GitHub token for GHSA queries |
| `VULNDB_API_KEY` | *(none)* | VulDB API key for VulDB / VulnDB queries |
| `VULNDB_API_BASE_URL` | `https://vuldb.com/?api` | VulDB API endpoint |
| `VULNDB_LIMIT` | `5` | Max VulDB results returned per component query |
| `VULNDB_DETAILS` | `false` | Request detailed VulDB results; consumes more VulDB credits |
| `ANALYSIS_SOURCES` | `NVD,OSV,GITHUB,VULNDB` | Sources to use |
| `CORS_ORIGINS` | `*` runtime fallback | Comma-separated allowed origins |
| `AUTH_ENABLED` | `false` | `true` = HCL IAM JWT validation; `false` = synthetic dev admin context |
| `DEV_DEFAULT_TENANT` | `true` | Seed default tenant in dev when `AUTH_ENABLED=false` |
| `HCL_IAM_ISSUER` | *(none)* | OIDC issuer URL (required when `AUTH_ENABLED=true`) |
| `HCL_IAM_AUDIENCE` | *(none)* | Expected JWT `aud` claim |
| `HCL_IAM_JWKS_URL` | *(none)* | JWKS endpoint for JWT signature verification |
| `HCL_IAM_CLIENT_ID` | *(none)* | OIDC client id (audience alignment) |
| `HCL_IAM_ALLOWED_ALGORITHMS` | `RS256` | Comma-separated JWT algorithms |
| `HCL_IAM_ROLE_CLAIM` | `roles` | JWT claim holding role list |
| `HCL_IAM_TENANT_CLAIM` | `tenant_id` | JWT claim holding external tenant id |
| `API_AUTH_MODE` | `none` | Legacy gate: `none`, `bearer`, or `jwt` — use `none` with HCL IAM |
| `API_AUTH_TOKENS` | *(none)* | Comma-separated bearer allowlist (legacy `bearer` mode only) |
| `JWT_SECRET_KEY` | *(none)* | HS256 secret (legacy `jwt` mode only) |
| `DATABASE_URL` | *(required for PostgreSQL)* | SQLAlchemy URL; use `postgresql+psycopg://…` outside isolated SQLite tests |
| `DB_POOL_SIZE` | `20` | PostgreSQL persistent connection-pool size |
| `DB_MAX_OVERFLOW` | `20` | PostgreSQL overflow connections |
| `DB_POOL_TIMEOUT` | `30` | Seconds to wait for a PostgreSQL pool connection |
| `DB_POOL_RECYCLE` | `1800` | Seconds before a PostgreSQL pooled connection is recycled |
| `DB_POOL_PRE_PING` | `true` | Ping connections before checkout |
| `POSTGRES_PORT` | `55439` | Host port for `docker compose` PostgreSQL |
| `HOST` | `0.0.0.0` | Server host |
| `PORT` | `8000` | Server port |
| `RELOAD` | `false` | Auto-reload when using `run.py` |
| `REDIS_URL` / `CELERY_BROKER_URL` | *(none)* | Redis broker for Celery background analysis (optional) |
| `LOG_LEVEL` / `LOG_FORMAT` | `INFO` / `text` | Log verbosity and format (`text` or `json`) |

### AI fixes (`.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `AI_FIXES_ENABLED` | `true` | Master switch for AI fix generation |
| `AI_FIXES_UI_CONFIG_ENABLED` | `true` | Exposes the Settings → AI provider config page |
| `AI_CONFIG_ENCRYPTION_KEY` | *(none)* | AES-256 key encrypting DB-stored provider credentials — see **AI Fix Configuration** |
| `AI_DEFAULT_PROVIDER` | `anthropic` | Provider used for every AI fix request; must name an enabled provider |
| `ANTHROPIC_API_KEY` / `AI_ANTHROPIC_MODEL` | *(none)* / `claude-sonnet-4-5` | Anthropic credentials + model |
| `OPENAI_API_KEY` / `AI_OPENAI_MODEL` | *(none)* / `gpt-4o-mini` | OpenAI credentials + model |
| `GEMINI_API_KEY` / `AI_GEMINI_MODEL` | *(none)* / `gemini-2.5-flash` | Google Gemini credentials + model (free tier) |
| `GROK_API_KEY` / `AI_GROK_MODEL` | *(none)* / `grok-2-mini` | xAI Grok credentials + model (free tier) |
| `SARVAM_API_KEY` / `AI_SARVAM_MODEL` / `AI_SARVAM_BASE_URL` | *(none)* / `sarvam-m` / `https://api.sarvam.ai/v1` | Sarvam AI (OpenAI-compatible) |

### Frontend (`frontend/.env.local`)

| Variable | Default | Description |
|----------|---------|-------------|
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | Backend base URL used by Next.js rewrites |
| `NEXT_PUBLIC_AUTH_ENABLED` | `false` | `true` = OIDC login via HCL IAM |
| `NEXT_PUBLIC_HCL_IAM_ISSUER` | *(none)* | OIDC issuer (required when auth enabled) |
| `NEXT_PUBLIC_HCL_IAM_CLIENT_ID` | *(none)* | OIDC client id |
| `NEXT_PUBLIC_HCL_IAM_REDIRECT_URI` | `http://localhost:3000/auth/callback` | OAuth redirect URI |
| `NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_URI` | `http://localhost:3000` | Post-logout redirect |
| `NEXT_PUBLIC_HCL_IAM_AUTHORIZATION_URL` | *(issuer-derived)* | Optional explicit authorize endpoint |
| `NEXT_PUBLIC_HCL_IAM_TOKEN_URL` | *(issuer-derived)* | Optional explicit token endpoint |
| `NEXT_PUBLIC_HCL_IAM_LOGOUT_URL` | *(issuer-derived)* | Optional explicit logout endpoint |

---

## Supported SBOM Formats

- **CycloneDX** (JSON and XML)
- **SPDX** (JSON)
- **SPDX XML** is parsed on a best-effort basis where supported by the backend parser
