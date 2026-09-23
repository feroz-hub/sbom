# Structured logging operations

Application and workflow events propagate through the Python root logger to
stdout and an optional JSON rotating file. Uvicorn/FastAPI and Celery loggers
propagate to the same handlers; SQLAlchemy errors propagate without enabling SQL
statement or parameter logging. Celery's `setup_logging` signal prevents its
default configuration from replacing these handlers. Existing host/telemetry
handlers are preserved; only SBOM-owned handlers are replaced and closed on
reconfiguration.

HTTP requests pass through an ASGI middleware outside body-size enforcement.
It binds `request_id`, adds `X-Request-ID` and legacy `X-Correlation-ID` response
headers, and emits one `http_request_completed` event after the final body chunk.
The existing global error handler adds the same headers to uncaught 500s.
Streaming responses are not buffered. A task failing after the response finishes
emits `http_background_task_failed` rather than another request completion.

Incoming IDs accept 1–128 ASCII letters, digits, underscores, dots, colons and
hyphens; absent/invalid IDs are regenerated. IDs are tracing values, not trusted
identity. Tenant/user IDs come from the existing authenticated context. The
middleware logs method, path (without query string), status and duration, never
headers, cookies or bodies. As with other INFO messages, raising `LOG_LEVEL` to
WARNING suppresses successful request events.

`log_context(...)` provides scoped IDs for async work and resets them on exit.
`log_event(logger, "event_name", **fields)` adds only supplied non-null fields.
Supported IDs: tenant, project, product, SBOM, analysis run, user, request. Celery
publish/prerun/postrun signals transfer these IDs through task headers and reset
them after each task. These headers are observability metadata and never grant
authorization.

```python
from app.logger import get_logger, log_context, log_event

log = get_logger("analysis")
with log_context(tenant_id=7, sbom_id=42, analysis_run_id=91):
    log_event(log, "analysis_completed", component_count=120,
              vulnerable_components=8, critical=1, high=3, medium=4, low=2,
              duration_ms=815.2)
```

Workflow events cover uploads, validation, activation, deactivation, permanent
deletion, analysis queue/start/completion/failure, component matching,
vulnerability lookup, lifecycle checking, VEX processing and report generation.
Business validation failures and partial provider failures emit failure outcomes;
pending delete confirmation never emits deletion success. Caller-owned deletion
transactions emit a prepared outcome until the caller commits. Counts are
aggregates, never complete SBOMs or vulnerability responses.

Exceptions retain `exception_type`, logger/module/function/line and stack frame
locations in `exc`, including chained causes. Exception messages, source code
lines and locals are deliberately omitted because they may contain credentials,
SQL parameters or document content. Both formatters redact sensitive field names,
credential patterns and configured environment-secret values. Callers must still
use IDs and numeric aggregates, and must not interpolate unlabelled secrets or
payloads into messages.

## Configuration and persistence

Existing variables remain supported:

| Variable | Default | Purpose |
| --- | --- | --- |
| `LOG_LEVEL` | `INFO` | Root/application threshold |
| `LOG_FORMAT` | `text` locally, `json` in Compose | Console format |
| `LOG_FILE` | unset in Python; `logs/sbom.log` in local `.env` | Optional file, always JSON |
| `LOG_MAX_MB` | `10` | Rotation size in MiB (10 × 1024 × 1024 bytes) |
| `LOG_BACKUPS` | `5` | Number of backups, plus the active file |
| `WORKER_LOG_FILE` | `/var/lib/sbom/logs/worker.log` | Compose worker file |
| `BEAT_LOG_FILE` | `/var/lib/sbom/logs/beat.log` | Compose beat file |

Compose defaults the backend file to `/var/lib/sbom/logs/backend.log`. All three
services mount the existing `app_data` volume at `/var/lib/sbom`; their files
survive container recreation. Do not run `docker compose down -v` if this volume
must be retained. The image creates a private, app-user-owned log directory.
Existing volumes/bind mounts must be writable by the container's UID 10001.

On POSIX a sidecar `.lock` serializes file writes and rotation across prefork
children, reopening the stream each time to avoid stale rotated-file handles.
Use a local filesystem with advisory-lock support. Use a separate file/volume per
service replica. Windows uses standard single-process rotation. A file I/O failure
reports a fixed diagnostic to stderr without dumping a raw log record; console
logging remains available. Retention is size-based, not a fixed number of days.

Initialization records explicitly include `console_format`, `file_format`,
`log_level`, `log_file`, `max_size` (bytes), `max_mb`, and `backup_count`.

## Deploy and inspect

Rebuild the backend image using the tag selected by `SBOM_ANALYSER_VERSION` in
the server environment (default `2.0.0`), then recreate the three services:

```bash
docker build -t sbom-analyser-backend:2.0.0 .
dc() { docker compose --env-file .env.server -f docker-compose.server.yml "$@"; }
dc up -d --no-deps --force-recreate backend worker beat

# Live container output (still enabled)
dc logs -f --tail=100 backend worker beat

# Persistent JSON files
dc exec backend tail -f /var/lib/sbom/logs/backend.log
dc exec worker tail -f /var/lib/sbom/logs/worker.log
dc exec beat tail -f /var/lib/sbom/logs/beat.log

# Active and rotated files, visible through the shared app_data mount
dc exec backend sh -c 'ls -lh /var/lib/sbom/logs/backend.log* /var/lib/sbom/logs/worker.log* /var/lib/sbom/logs/beat.log*'

# Local execution (use the project's installed environment)
.venv/bin/python run.py
tail -f logs/sbom.log
ls -lh logs/sbom.log*
```

No new production test endpoint is installed. Logging tests use temporary
applications and routes, an isolated file directory, mocked workflow results,
and a multiprocess test that verifies no missing or duplicate records during
actual rotation.

## Changed files

- Core: `app/logger.py`, `app/middleware/request_logging.py`, `app/main.py`, `app/error_handlers.py`.
- Celery/container configuration: `app/workers/celery_app.py`, `Dockerfile`, `docker-compose.server.yml`, `.env.server.example`.
- Shared workflow helpers: `app/services/sbom_workflow_logging.py`, `app/services/report_logging.py`.
- SBOM/validation/VEX: `app/routers/sbom_upload.py`, `app/routers/sboms_crud.py`, `app/routers/sbom_validation_sessions.py`, `app/routers/vex.py`, `app/validation/pipeline.py`, `app/services/sbom_delete_service.py`, `app/services/validation_repair_service.py`, `app/services/lifecycle/vex_discovery.py`, `app/services/lifecycle/vex_provider.py`.
- Analysis/lifecycle: `app/services/analysis_orchestrator.py`, `app/services/analysis_service.py`, `app/sources/runner.py`, `app/services/lifecycle/lifecycle_enrichment_service.py`.
- Reports: `app/services/pdf_service.py`, `app/services/fda_510k_excel_report_service.py`, `app/services/sbom_vulnerability_excel_report_service.py`, `app/workers/report_notifications.py`.
- Tests: `tests/test_structured_logging.py`, `tests/test_analysis_domain_logging.py`, `tests/test_sbom_workflow_logging.py`.

## Verification recorded 2026-09-23

- Full backend run: **2,296 passed, 65 failed, 8 skipped**, plus 12 passed
  subtests, in 27m22s. Output: `logs/backend-test-results.txt`.
- The full run exposed inherited-level and disabled-descendant logger issues.
  Both were corrected. A rerun of all 65 failed cases produced **22 passed,
  43 failed**. Output: `logs/failure-recheck-results.txt`.
- The exact same **43 remaining failing test IDs** reproduce on unchanged
  commit `18cb2b8`, using a separate PostgreSQL test database and an available
  in-memory broker. Baseline rerun: **6 passed, 43 failed** (49 existing tests;
  the other 16 tests were newly added here).
  Output: `logs/baseline-all-failures-results.txt`. The failing-ID sets match.
- Final focused suite: **78 passed** (68 new logging/workflow checks plus 10
  existing NVD logging checks). Output: `logs/logging-test-results.txt`.
  An earlier PostgreSQL-focused run also passed all 76 cases present at that
  point: `logs/logging-postgres-test-results.txt`.
- Ruff passed for all changed/new Python files; `git diff --check` passed.
- Compose validation confirmed three distinct log paths and the persistent
  `app_data:/var/lib/sbom` volume on all three services.

The remaining baseline failures concern existing auth/test fixtures, component
deduplication and format conversion, tenant timestamps, concurrency, a query
allowlist, NVD TLS assertions, and report-load/integration behavior. They were
not changed as part of logging. The entire suite is therefore **not green**;
the final failed-case comparison finds no new unresolved failing test IDs.

Manual checks started the backend on localhost port 18123 against an isolated
PostgreSQL test database. `/health` and `/api/types` returned 200 and echoed the
provided request IDs. Their structured completion records, a manual INFO event,
and a controlled exception with stack frames were verified in `logs/sbom.log`.
Authorization and exception-message test secrets were absent. No production
test endpoint was added. The temporary backend was shut down afterward.

Worker and beat were separately started with an in-memory broker and then
stopped. Their JSON files and console output were verified:
`logs/worker-smoke.log`, `logs/beat-smoke.log`, and the corresponding
`*-smoke-console.txt` files. Live deployed containers were not rebuilt/restarted.

Example request entry (abbreviated from the smoke test):

```json
{"level":"INFO","event":"http_request_completed","request_id":"smoke-health-20260923","method":"GET","path":"/health","status_code":200,"duration_ms":242.521}
```

Example exception entry (abbreviated):

```json
{"level":"ERROR","event":"manual_smoke_exception","request_id":"smoke-error-20260923","exception_type":"RuntimeError","module":"<stdin>","func":"<module>","line":16,"exc":"Traceback (most recent call last):\n  File \"<stdin>\", line 14, in <module>\nRuntimeError: [exception message omitted]"}
```
