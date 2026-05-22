# SBOM Analyzer

A full-stack **Software Bill of Materials (SBOM) vulnerability analysis platform**.

Upload SBOMs, persist extracted components, scan them against NVD, GitHub Security Advisories, OSV, and VulDB, and generate PDF vulnerability reports from a Next.js dashboard backed by FastAPI.

---

## Local Development

```bash
# Backend
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
cp .env.example .env
python3 run.py
```

The backend API starts on **http://localhost:8000**.

- `GET /` returns API service metadata
- `GET /docs` opens the FastAPI Swagger UI
- `GET /health` returns the API health check

```bash
# Frontend
cd frontend
npm ci
cp .env.local.example .env.local
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
    ├── db.py               # Database setup (repo-root SQLite by default)
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
.venv/bin/python -m pytest tests/
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
| `DATABASE_URL` | repo-root `sbom_api.db` | SQLAlchemy database URL override |
| `HOST` | `0.0.0.0` | Server host |
| `PORT` | `8000` | Server port |

### Frontend (`frontend/.env.local`)

| Variable | Default | Description |
|----------|---------|-------------|
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | Backend base URL used by Next.js rewrites |

---

## Supported SBOM Formats

- **CycloneDX** (JSON and XML)
- **SPDX** (JSON)
- **SPDX XML** is parsed on a best-effort basis where supported by the backend parser
