# SBOM Analyzer

A full-stack **Software Bill of Materials (SBOM) vulnerability analysis platform**.

Upload SBOMs (CycloneDX / SPDX), scan components against NVD, GitHub Security Advisories, and OSV, and generate PDF vulnerability reports — all from a web dashboard.

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure environment (copy and edit)
cp .env.example .env

# 3. Run the server
python run.py
```

Open **http://localhost:8000** in your browser.

---

## Project Structure

```
sbom/
├── run.py                  # Entry point
├── requirements.txt        # Python dependencies
├── .env.example            # Environment variable template
└── app/
    ├── main.py             # FastAPI application & all API routes
    ├── analysis.py         # Multi-source vulnerability analysis engine
    ├── models.py           # SQLAlchemy ORM models
    ├── schemas.py          # Pydantic request/response schemas
    ├── db.py               # Database setup (SQLite by default)
    ├── pdf_report.py       # PDF report generation (ReportLab)
    ├── sbom_api.db         # SQLite database (auto-created on first run)
    └── frontend/           # Web dashboard (vanilla JS + jQuery)
        ├── index.html
        ├── styles.css
        └── js/
            ├── app.init.js
            ├── api.client.js
            ├── ui.home.js
            ├── ui.projects.js
            ├── ui.sboms.js
            └── ui.analysis.js
```

---

## API Overview

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/dashboard/stats` | Project / SBOM / vulnerability counts |
| GET | `/dashboard/recent-sboms` | Recently uploaded SBOMs |
| GET | `/dashboard/activity` | Active vs stale SBOM chart data |
| GET | `/dashboard/severity` | Vulnerability severity breakdown |
| GET/POST | `/api/projects` | List / create projects |
| GET/PATCH/DELETE | `/api/projects/{id}` | Get / update / delete project |
| GET/POST | `/api/sboms` | List / upload SBOMs |
| GET/PATCH/DELETE | `/api/sboms/{id}` | Get / update / delete SBOM |
| GET | `/api/sboms/{id}/components` | List components extracted from an SBOM |
| POST | `/api/sboms/{id}/analyze` | Trigger multi-source analysis |
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

| Variable | Default | Description |
|----------|---------|-------------|
| `NVD_API_KEY` | *(none)* | NIST NVD API key (faster rate limit) |
| `GITHUB_TOKEN` | *(none)* | GitHub token for GHSA queries |
| `ANALYSIS_SOURCES` | `NVD,OSV,GITHUB` | Sources to use |
| `CORS_ORIGINS` | `*` | Comma-separated allowed origins |
| `DATABASE_URL` | `sqlite:///app/sbom_api.db` | SQLAlchemy database URL |
| `HOST` | `0.0.0.0` | Server host |
| `PORT` | `8000` | Server port |

---

## Supported SBOM Formats

- **CycloneDX** (JSON, v1.x)
- **SPDX** (JSON)
