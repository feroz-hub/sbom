# CISA KEV Integration Testing Checklist

## Automated Checks

Run backend KEV checks with a disposable SQLite database:

```bash
tmpdb=$(mktemp /tmp/kev-test-XXXX.sqlite)
TEST_DATABASE_URL=sqlite:///$tmpdb DATABASE_URL=sqlite:///$tmpdb ALLOW_SQLITE=true \
  pytest tests/test_kev_router.py tests/test_kev_enrichment_service.py tests/test_kev_sync_worker.py -q

tmpdb=$(mktemp /tmp/kev-cache-test-XXXX.sqlite)
TEST_DATABASE_URL=sqlite:///$tmpdb DATABASE_URL=sqlite:///$tmpdb ALLOW_SQLITE=true \
  pytest tests/test_kev_cache_refresh.py -q -k 'not dashboard_endpoints'
```

Run frontend KEV checks:

```bash
cd frontend
npm test -- findingFilters.matchTags.test.ts
npx tsc --noEmit
npm run build
```

## Manual Backend Checklist

1. Apply migrations:

   ```bash
   alembic upgrade head
   ```

2. Confirm the KEV table exists:

   ```sql
   SELECT COUNT(*) FROM kev_vulnerabilities;
   ```

3. Trigger manual sync:

   ```bash
   curl -X POST http://localhost:8000/api/v1/kev/sync \
     -H 'Content-Type: application/json' \
     -d '{}'
   ```

4. Confirm a KEV CVE can be fetched:

   ```bash
   curl http://localhost:8000/api/v1/kev/CVE-2021-44228
   ```

5. Confirm list filters:

   ```bash
   curl 'http://localhost:8000/api/v1/kev?ransomware=true&limit=10'
   curl 'http://localhost:8000/api/v1/kev?q=apache&since=2021-01-01'
   ```

6. Confirm Celery Beat has the daily task:

   ```bash
   celery -A app.workers.celery_app.celery_app inspect registered
   ```

   Expected task: `kev.sync`

## Manual Analysis/UI Checklist

1. Upload or select an SBOM that produces at least one known KEV CVE.
2. Run analysis and open the findings page.
3. Confirm KEV findings show:
   - KEV badge
   - Required Action
   - KEV Due Date
   - Vendor
   - Product
4. Confirm ransomware findings show the ransomware badge when `knownRansomwareCampaignUse` is `Known`.
5. Confirm summary counts:
   - Total Findings
   - KEV
   - Non-KEV
   - Ransomware
6. Confirm filters:
   - `KEV only` shows only KEV findings.
   - `Ransomware` shows only findings with known ransomware campaign use.
7. Confirm `GET /api/runs/{run_id}/findings-enriched` includes:
   - `is_kev`
   - `kev_date_added`
   - `kev_due_date`
   - `required_action`
   - `vendor_project`
   - `product`
   - `ransomware_status`
   - `notes`
