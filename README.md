# SBOM Analyzer

A full-stack **Software Bill of Materials (SBOM) vulnerability analysis platform**.

Upload SBOMs, persist extracted components, scan them against NVD, GitHub Security Advisories, OSV, and VulDB, and generate PDF vulnerability reports from a Next.js dashboard backed by FastAPI.

---

## Local Development

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

### Manual backend setup

```bash
# macOS / Linux
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
cp .env.example .env
python3 run.py
```

```powershell
# Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python run.py
```

The backend API starts on **http://localhost:8000**.

- `GET /` returns API service metadata
- `GET /docs` opens the FastAPI Swagger UI
- `GET /health` returns the API health check

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

```bash
# macOS / Linux
.venv/bin/python -m pytest tests/
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

Bearer-token authentication is **opt-in** via environment variable so
existing dev environments are not broken. To enable it in production:

```bash
export API_AUTH_MODE=bearer
export API_AUTH_TOKENS=tok-strong-random-1,tok-strong-random-2
python run.py
```

The server will refuse to start if `API_AUTH_MODE=bearer` is set but
`API_AUTH_TOKENS` is empty — that combination would otherwise silently
let every request through.

**Protected routes** (require `Authorization: Bearer <token>`):

- All `/api/*` routes (sboms, projects, runs, findings, components,
  PDF, analysis runs, analysis-runs export, sboms feature endpoints,
  `/api/analysis/config`, `/api/types`)
- All `/analyze-sbom-*` ad-hoc routes
- All `/dashboard/*` routes

**Open routes** (no auth required, for liveness probes and `/docs`):

- `GET /`
- `GET /health`
- `GET /docs`, `GET /openapi.json`, `GET /redoc`

Multiple tokens in `API_AUTH_TOKENS` (comma-separated) lets you rotate
per-client without downtime: add a new one, redeploy clients, then
remove the old one.

---

## AI Fix Configuration

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
needed. To offload analysis to background workers, point the app at Redis and
run the Celery worker (and beat scheduler for periodic jobs):

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

### Start PostgreSQL locally

```bash
docker compose up -d postgres
docker compose ps
```

Configure `.env`:

```env
DATABASE_URL=postgresql+psycopg://sbom:sbom@localhost:5432/sbom_analyser
```

Create or upgrade the schema, then run the API:

```bash
alembic heads
alembic upgrade head
alembic current
alembic check
uvicorn app.main:app --reload
```

### Migrate an existing SQLite database

Use a maintenance window: stop the API, Celery workers, and scheduler before
the backup and keep them stopped until verification is complete.

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
  --postgres-url postgresql+psycopg://sbom:sbom@localhost:5432/sbom_analyser \
  --dry-run
```

Copy all application tables in one PostgreSQL transaction:

```bash
python scripts/migrate_sqlite_to_postgres.py \
  --sqlite-url sqlite:///./sbom_api.db \
  --postgres-url postgresql+psycopg://sbom:sbom@localhost:5432/sbom_analyser
```

Verify row counts, complete primary-key digests, raw SBOM hashes, foreign keys,
constraints, and relationships:

```bash
python scripts/migrate_sqlite_to_postgres.py \
  --sqlite-url sqlite:///./sbom_api.db \
  --postgres-url postgresql+psycopg://sbom:sbom@localhost:5432/sbom_analyser \
  --verify-only
```

The target must be empty by default. Clearing a disposable or pre-backed-up
target requires both explicit flags:

```bash
python scripts/migrate_sqlite_to_postgres.py \
  --sqlite-url sqlite:///./sbom_api.db \
  --postgres-url postgresql+psycopg://sbom:sbom@localhost:5432/sbom_analyser \
  --truncate-target --confirm-truncate
```

After verification and API smoke tests, create a PostgreSQL backup before
opening traffic:

```bash
pg_dump --format=custom \
  --file=./backups/sbom_analyser-post-migration.dump \
  postgresql://sbom:sbom@localhost:5432/sbom_analyser
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

> Every row below requires `Authorization: Bearer <token>` when
> `API_AUTH_MODE=bearer`. See the **Authentication** section above.
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
| `API_AUTH_MODE` | `none` | `none` or `bearer`; see **Authentication** above |
| `API_AUTH_TOKENS` | *(none)* | Comma-separated bearer token allowlist (required when `API_AUTH_MODE=bearer`) |
| `DATABASE_URL` | *(required for PostgreSQL)* | SQLAlchemy URL; use `postgresql+psycopg://…` outside isolated SQLite tests |
| `DATABASE_POOL_SIZE` | `5` | PostgreSQL persistent connection-pool size |
| `DATABASE_MAX_OVERFLOW` | `10` | PostgreSQL overflow connections |
| `DATABASE_POOL_TIMEOUT` | `30` | Seconds to wait for a PostgreSQL pool connection |
| `DATABASE_POOL_RECYCLE` | `1800` | Seconds before a PostgreSQL pooled connection is recycled |
| `HOST` | `0.0.0.0` | Server host |
| `PORT` | `8000` | Server port |
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

---

## Supported SBOM Formats

- **CycloneDX** (JSON and XML)
- **SPDX** (JSON)
- **SPDX XML** is parsed on a best-effort basis where supported by the backend parser
