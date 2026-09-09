# Scheduled report notifications — implementation and operations

Implemented on `feat/sbom-version-lineage-vex-import`; migrations are
`051_report_subscription` → `052_report_delivery_artifact` → `053_tenant_analysis_schedule` → `054_hierarchical_scheduler` → `055_ai_model_registry`.
The feature is opt-in. Existing analysis, verification mail and env-only local workflows remain available with it disabled.

## Product decisions confirmed on 2026-09-07

- Use the existing single platform SMTP relay; no per-tenant SMTP secrets.
- Store artifacts in a private filesystem shared by API and report workers, outside this checkout.
- Combine `ON_EVERY_RUN` completions from a scheduler tick into one digest per subscription.
- Tenant-wide subscriptions require active `TENANT_ADMIN` or `SECURITY_ANALYST` membership.
- Other scopes require their normal read permissions. Tenant administrators can inspect/disable subscriptions; only owners can preview or send-now.
- Retention defaults to 90 days. FDA workbooks are not offered by this feature.

## Setup

1. Back up the deployment database using your normal backup procedure, then activate the backend environment and run `alembic upgrade head`. This adds three tables and extends schedule constraints; it does not replace inventory, users or findings. Never run the test suite against a production database.
2. Create a directory outside the checkout, owned by the API/report-worker OS account and mode `0700`. Files are created `0600`. Mount the same directory at the same path in both processes/containers. Configure a durable volume; do not use ephemeral container storage.
3. Configure the existing `EMAIL_DELIVERY_ENABLED`, `EMAIL_FROM_ADDRESS`, `EMAIL_FROM_NAME`, `SMTP_*` settings through the deployment secret/configuration mechanism. TLS certificate validation stays enabled. Do not put passwords into source control.
4. Configure these additional **environment-controlled operational settings**:

   | Setting | Default / requirement |
   | --- | --- |
   | `REPORT_NOTIFICATIONS_ENABLED` | `false`; set `true` to dispatch |
   | `REPORT_NOTIFICATION_BASE_URL` | Required trusted HTTPS application origin, e.g. `https://sbom.example.com`; localhost HTTP is allowed for testing |
   | `REPORT_ARTIFACT_STORAGE_PATH` | Required absolute private shared directory outside the checkout |
   | `REPORT_MAX_SBOMS_PER_DIGEST` | `250` |
   | `REPORT_MAX_ATTACHMENT_BYTES` | `10485760` per attachment |
   | `REPORT_MAX_MESSAGE_BYTES` | `20971520`, measured after MIME/base64 encoding |
   | `REPORT_RETENTION_DAYS` | `90` |
   | `REPORT_MAX_EMAILS_PER_TENANT_PER_HOUR` | `200`; durable quota reservation |
   | `REPORT_GENERATION_TIMEOUT_SECONDS` | `300` |
   | `REPORT_CYCLE_WAIT_SECONDS` | `3600`; completion-barrier deadline, separate from rendering |

5. Restart API and workers to load operational environment changes. Subscription changes are DB-backed and do **not** require restart. `AUTH_ENABLED=false` always results in `SKIPPED / DELIVERY_DISABLED`; configuring SMTP alone cannot send reports from local unauthenticated mode.
6. Run one ordinary analysis worker, one **separate** report worker (`bash scripts/report_worker.sh`), and exactly one Beat (`bash scripts/celery_beat.sh`). Report tasks are routed to `reports`; a default worker consuming only `celery` will not pick them up. The report script uses concurrency 1, prefetch 1 and process recycling to isolate CPU/memory from analysis.

For local Windows development without Redis, `CELERY_USE_DATABASE_BROKER=true` safely derives Kombu's polling SQLAlchemy broker from the existing `DATABASE_URL`; a full `CELERY_BROKER_URL=sqla+postgresql+psycopg://...` value also works. The application derives the required `db+postgresql+psycopg://...` result backend automatically. This is suitable for exercising report generation and MailHog delivery locally; keep Redis or another production-grade broker for deployed environments.
7. Check `GET /api/report-notifications/config` while authenticated. Safe diagnostic codes identify missing URL/private storage. Startup logs show flags and codes, never SMTP credentials or filesystem contents.

Preferences may be prepared and previewed before delivery is enabled. The UI explicitly distinguishes saved preferences from delivery readiness.

## Data flow and cadence

The scheduler records a durable completion barrier before enqueueing its analyses. Each terminal completion updates that barrier. A separate report task reads the persisted results. Missing/failed completion events time out into an explicitly partial digest showing the last successful data. Reports never trigger live NVD, OSV, KEV, EPSS or AI requests.

Analysis completion waits up to `REPORT_CYCLE_WAIT_SECONDS`; the smaller generation timeout only limits the report task itself. Replayed scheduler ticks reuse the existing end boundary even if a preceding delivery advanced the subscription cursor meanwhile.

`ON_EVERY_RUN` observes **scheduled** analyses, including the schedule's Run now action; it is not an alert on every ad-hoc analysis HTTP request. The barrier has one cycle per scheduler tick. `DAILY` closes at local midnight, `WEEKLY` at Monday midnight, `MONTHLY` at the first day of the month. Boundaries use the subscription's IANA timezone (UTC by default), including DST; persisted timestamps and displayed offsets are UTC. The hourly cadence tick runs at minute **50**, outside the 03:00–03:45 maintenance window. A lightweight minute outbox sweep recovers enqueue failures/retries; artifact cleanup runs at 04:50 UTC.

Subscriptions due in the same tick are resolved narrowest-first (`SBOM > PRODUCT > PROJECT > TENANT`) per recipient. Covered SBOMs are removed from broader digests. Different cadences only compete when they are due in the same cycle. A paused subscription does not suppress another subscription. Analysis schedules separately follow the same hierarchy, but an explicitly paused child **does** opt out of its parent's analysis cascade.

Broad report scopes use active **head versions**, matching latest-state dashboard convention A. Historical ancestors are comparison baselines, not duplicated latest-state portfolio entries. A direct SBOM subscription can target a historical version. Deleted SBOMs/products/projects are excluded. The full resolved scope contributes to headline totals; detail is capped by KEV → EPSS → CVSS priority with an explicit included/omitted count.

## Metrics and outputs

- A: `app.metrics.reporting.latest_snapshots` and `rollup`: canonical finding identities, full severity distribution, KEV finding/distinct-CVE counts, fix coverage, locally cached EPSS outlook and coverage, lifecycle summary, VEX-reduced count and top risks.
- B: `runs_previous_for_sbom`; C: `runs_initial_for_sbom`; D: `runs_latest_for_sbom` for the declared parent/root. These are named `app/metrics/` functions with explicit tenant/as-of predicates. B/C/D call the existing `CompareService` and reuse its cache without changing key/TTL.
- C includes initial∩latest persistent findings and age since that initial observation. This does **not** prove continuous presence in every intervening scan.
- D uses declared ancestry, never filename/version guesses, and carries stable attribution kinds plus the existing human-readable explanation. Existing `same_sbom`/`same_project` fields remain compatible.
- No baseline means `insufficient_history`, not zero change. A failed comparison degrades just that part with a safe error code. Severity floor filters detail, never headline or comparison totals. Incomplete/capped scopes are never certified unchanged.
- B/C/D aggregate the entire resolved scope, including SBOMs omitted from detail by the cap. These are sums of per-SBOM Convention B occurrences, not globally distinct CVEs. Coverage and elapsed-time ranges are explicit. The header includes tenant, schema version and unique run IDs considered; persistent-finding counts remain unfiltered.
- The email and executive PDF contain all selected part summaries. XLSX is write-only/streamed, with all selected finding/component detail, Part A–D sheets, Rollup and Metadata (run IDs, UTC time and conventions). Retained JSON is the same secret-free snapshot. Excel formula prefixes and HTML are escaped; raw SBOM documents, repair patches, credentials and provider payloads are not included.
- Oversized PDF/XLSX attachments remain stored and are replaced by an explicit omission reason plus an authenticated history link. The actual encoded MIME message is measured. JSON is downloadable, not attached.

### Historical enrichment limitation

Existing scans do **not** snapshot KEV membership or EPSS. Therefore historical “newly KEV since the baseline run” cannot honestly be reconstructed. Reports explicitly mark this field unavailable and label KEV/EPSS as **current local enrichment**. This is an intentional, visible exception to the draft's historical KEV delta request, not an invented zero. Historical recording would require a separate data contract and cannot recover old snapshots retroactively.

## Delivery guarantees, retries and security

`report_delivery` is a transactional outbox keyed by `(subscription_id, cycle_start, cycle_end)`. Database claims prevent concurrent workers from sending the same cycle twice. Each attempt has an audit event and a safe outcome code. Transient SMTP connection/rejection errors retry with exponential delays, at most three attempts. Authentication, TLS, recipient/message rejection and deterministic configuration errors are terminal.

SMTP does **not** provide an atomic transaction with PostgreSQL. A crash/timeout after SMTP dispatch may have delivered the email. Such cases are `FAILED / SMTP_OUTCOME_UNKNOWN` and are **not automatically resent**. Check the relay before deliberately using Send now to create a new cycle. This preserves duplicate safety instead of claiming mathematically impossible exactly-once transport delivery. `SENT` means relay acceptance, not proof that a person read it or that a remote mailbox accepted it.

Membership, verified IAM email, active account, current permission catalogue and scope are checked before composition and again immediately before SMTP. Changes during rendering suppress delivery. Download endpoints recheck tenant/owner/admin, permissions, current scope, retention and artifact integrity. Files are never publicly mounted or addressed through caller-provided paths. Deep links use the configured origin, never Host headers; downloads use the normal authenticated tenant-aware BFF helper. No bearer tokens appear in URLs.

Tenant sends are serialized for hourly quota reservation against durable dispatch timestamps. Preview is limited to 10 requests per user/tenant/hour; Send now to 5. Rate checks serialize on the IAM user and count audit records, so limits survive process restarts. Preview creates no subscription, delivery or artifact; it may populate the existing comparison cache and writes an audit/rate-limit event.

## API and UI

The documented subscription/delivery endpoints are implemented. Additive endpoints:

- `GET /api/report-notifications/config`: flags and safe setup diagnostics.
- `GET /api/report-notifications/targets?scope=PROJECT|PRODUCT|SBOM&search=...`: tenant-scoped picker, first 200 matching names.
- `POST /api/report-subscriptions/preview`: preview unsaved preferences.
- `GET/POST/PATCH/DELETE /api/tenants/{id}/schedule`: tenant administrator schedule management.

Open **Settings → Notifications**, or **Notify me** on a Project, Product or SBOM. Configure scope, cadence, selected parts/formats, severity floor, baseline/root choice and timezone. Preview opens an inert sandboxed frame; no email is sent. Save persists only preferences. Delivery history exposes PENDING/SENT/FAILED/SKIPPED/SUPPRESSED, attempts and authorized downloads. Tenant administration can list and disable users' subscriptions. Mutations invalidate the common report query prefix, and history polls every 15 seconds.

## Manual smoke test (test tenant and controlled relay only)

1. Apply migrations and configure the operational settings above. Start API, frontend, analysis worker, report worker and one Beat. Do not enable a real relay until the operator authorizes outbound reports.
2. Sign in as a verified tenant member. Import two declared SBOM versions and create two successful stored runs for the latest version using a controlled data source.
3. From its Notify me link, select parts A/B/C/D and both attachments. Preview: confirm run IDs, unfiltered totals, severity floor, baseline comparison, parent relationship and insufficient-history markers. Compare B/C/D against `/api/v1/compare` for the same run pairs.
4. Save. Refresh the page and confirm the preferences persist without restarting the API. Send now to the controlled relay. Confirm one ledger row, relay acceptance, readable text/HTML, PDF and XLSX. Open every artifact from delivery history through the BFF.
5. Add a broader same-cadence subscription and run the schedule. Confirm one digest for the narrower covered SBOM and no duplicate in the broader digest. Re-enqueue the **same delivery ID** in the test environment; the sender must not run twice.
6. Pause the subscription or revoke membership before a queued delivery is processed; confirm SUPPRESSED and no SMTP call. Try another tenant's artifact URL; expect 404/403. Restore membership only through normal administration.
7. In test configuration lower the attachment cap; confirm attachment omission text and retained authenticated downloads. Exercise transient vs authentication SMTP failures and check attempts/retry behavior. Never retry an ambiguous acceptance blindly.
8. Check daily/weekly/monthly boundaries and retention in a disposable database. Restore operational limits afterward. No test step should modify or auto-apply SBOM repair patches.

## Automated verification commands

Run from repository root with the isolated test database configured by `tests/conftest.py`:

```sh
.venv/bin/python -m pytest -q tests/test_report_notifications.py tests/test_report_migrations.py
.venv/bin/python -m pytest -q tests/test_schedule_resolver.py tests/test_schedules_api.py tests/test_phase5_email_delivery.py tests/test_compare_service.py tests/test_compare_router.py tests/test_metric_consistency.py
.venv/bin/alembic heads
```

From `frontend/`: `npm test`, `npm run lint`, `npx tsc --noEmit`, `npm run build`.
The report tests use PostgreSQL, real PDF/XLSX renderers and fake SMTP, including concurrent workers, revoked access during rendering, MIME limits, durable quota, completion barriers, DST and reference-load fixtures. No paid providers or real mail are called by these tests.

## Rollback

Disable `REPORT_NOTIFICATIONS_ENABLED` on API, Beat and report workers, then restart those processes. Keep the private volume and delivery ledger for audit/downloads. For schema rollback, archive reports and remove tenant-level analysis schedules explicitly first; migration 053 refuses to downgrade while any tenant schedule exists. Do not silently delete user schedules or drop reporting history just to roll back application code.
