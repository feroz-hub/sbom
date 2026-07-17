# CISA KEV Sync Service (FastAPI + PostgreSQL)

Downloads the CISA Known Exploited Vulnerabilities (KEV) catalog JSON, optionally filters entries by `dateAdded`, and upserts them into a local PostgreSQL database.

Behavior:
- `POST /kev/sync?since_date=2026-06-01` → syncs only entries added on/after that date.
- `POST /kev/sync` with no date → falls back to `KEV_SINCE_DATE` in config; if that is also empty, the **entire catalog** is parsed and upserted.
- Upserts are idempotent (`INSERT ... ON CONFLICT (cve_id) DO UPDATE`), so re-running is safe.

## Project layout

```
kev-sync/
├── app/
│   ├── __init__.py
│   ├── config.py        # env-based settings (.env supported)
│   ├── database.py      # async engine, session, ORM model
│   ├── schemas.py       # Pydantic response models
│   ├── kev_service.py   # download / filter / upsert logic
│   └── main.py          # FastAPI app and endpoints
├── requirements.txt
└── .env.example
```

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Create the database
createdb kev   # or: psql -c "CREATE DATABASE kev;"

cp .env.example .env   # edit DATABASE_URL / KEV_SINCE_DATE as needed
uvicorn app.main:app --reload
```

The table `kev_vulnerabilities` is created automatically at startup.

## Usage

```bash
# Full catalog sync (no date configured/provided)
curl -X POST http://localhost:8000/kev/sync

# Only entries added since a date
curl -X POST "http://localhost:8000/kev/sync?since_date=2026-06-01"

# Query the local DB
curl "http://localhost:8000/kev?since_date=2026-07-01&limit=20"
curl "http://localhost:8000/kev?vendor=microsoft&ransomware_only=true"
curl http://localhost:8000/kev/CVE-2021-44228
```

Sample sync response:

```json
{
  "catalog_version": "2026.07.15",
  "catalog_date_released": "2026-07-15T14:00:11.123000+00:00",
  "total_in_feed": 1254,
  "filtered_since": "2026-06-01",
  "matched_after_filter": 41,
  "upserted": 41,
  "duration_seconds": 2.31
}
```

Interactive docs: http://localhost:8000/docs

## Notes

- The CISA feed always returns the full catalog; date filtering happens locally on `dateAdded`.
- For scheduled syncs, call `POST /kev/sync` from cron/systemd/K8s CronJob, or add a background scheduler (e.g. APScheduler).
- For production schema changes, use Alembic migrations instead of `create_all`.
