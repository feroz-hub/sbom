# SBOM Analyzer

A full-stack **Software Bill of Materials (SBOM) vulnerability analysis platform**.

Upload SBOMs, persist extracted components, scan them against NVD, GitHub Security Advisories, and OSV, and generate PDF vulnerability reports from a Next.js dashboard backed by FastAPI.

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
├── .env.example            # Environment variable template
├── samples/                # Sample SBOM payloads for local testing
├── frontend/               # Primary Next.js dashboard
│   ├── package.json
│   ├── next.config.mjs     # API rewrites to the FastAPI backend
│   └── src/
│       ├── app/            # Route entry points
│       ├── components/     # UI building blocks and feature components
│       └── lib/            # API client and shared utilities
└── app/
    ├── main.py             # FastAPI application & all API routes
    ├── analysis.py         # Multi-source vulnerability analysis engine
    ├── models.py           # SQLAlchemy ORM models
    ├── schemas.py          # Pydantic request/response schemas
    ├── db.py               # Database setup (repo-root SQLite by default)
    ├── pdf_report.py       # PDF report generation (ReportLab)
    └── logger.py           # Structured/text logging setup
```

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
| POST | `/analyze-sbom-consolidated` | Combined NVD + GHSA + OSV scan |
| POST | `/api/pdf-report` | Generate PDF for a completed run |

Full interactive docs: **http://localhost:8000/docs**

---

## Environment Variables

### Backend (`.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `NVD_API_KEY` | *(none)* | NIST NVD API key (faster rate limit) |
| `GITHUB_TOKEN` | *(none)* | GitHub token for GHSA queries |
| `ANALYSIS_SOURCES` | `NVD,OSV,GITHUB` | Sources to use |
| `CORS_ORIGINS` | `*` runtime fallback | Comma-separated allowed origins |
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
