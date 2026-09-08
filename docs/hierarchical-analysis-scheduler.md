# Hierarchical analysis scheduler

The analysis scheduler supports Tenant, Project, Product, and exact-SBOM schedules. Product is a first-class scheduling scope. Tenant scope remains the compatibility fallback introduced for report notifications; the primary product hierarchy is Project → Product → SBOM version.

## Effective scheduling model

The resolver in `app/services/schedule_resolver.py` is authoritative for preview, Run Now, the Celery Beat tick, and the worker's pre-execution check.

Precedence is:

1. exact SBOM row;
2. Product row;
3. Project row;
4. Tenant row;
5. no schedule.

The first active child row wins even when it is paused or excluded. This prevents a disabled override from unexpectedly falling through to a broader parent.

| Effective state | Persistence | Execution |
| --- | --- | --- |
| `INHERITED` | No child row | Uses the nearest parent row. |
| `CUSTOM` | `mode=CUSTOM`, `enabled=true` | Runs on the child cadence. |
| `PAUSED` | `mode=CUSTOM`, `enabled=false` | Does not run and does not inherit. |
| `EXCLUDED` | `mode=EXCLUDED`, `enabled=false` | Does not run and does not inherit. |
| `NONE` | No row at any level | Manual analysis only. |

Deleting/restoring a Product or SBOM schedule row returns the target to inheritance. Excluding creates an explicit row. Pausing preserves a custom schedule for later resume.

## Current SBOM and version policy

`products.current_sbom_id` is an explicit nullable foreign key to `sbom_source.id`. The API accepts it through `PATCH /api/products/{product_id}` only when the target SBOM is active, tenant-matching, and belongs to that Product. It may be cleared with `null`. Version strings are never sorted or guessed.

The first accepted upload to a Product becomes current automatically. Later multipart uploads expose `set_as_current`; when false they remain historical, and when true the Product pointer moves to the new SBOM. Moving or deleting a current SBOM clears the old pointer rather than guessing a replacement.

Project/Product target policies are:

- `CURRENT_ONLY` (default): one explicit current SBOM per eligible Product;
- `ALL_ACTIVE_VERSIONS`: every active, non-deleted SBOM in scope.

Exact SBOM schedules always target their own SBOM. A Product with no valid current SBOM is skipped under `CURRENT_ONLY`, and preview reports `NO_CURRENT_SBOM`.

## Resolution and execution

Only active Projects (`project_status=1`), active Products (`status=active`), active SBOMs, and active schedule rows are eligible. All hierarchy nodes must belong to the same tenant.

For every candidate SBOM, the resolver selects the most-specific row. Parent previews show a child as skipped when a Product/SBOM override, pause, or exclusion owns it. Due targets are deduplicated by `(tenant_id, sbom_id)`.

Celery Beat runs `scheduled_analysis.tick` every 15 minutes. It advances the cadence cursor for every due schedule, including schedules that currently have no target. Each concrete target is sent to `scheduled_analysis.analyze_sbom`. The worker resolves the target again immediately before analysis, so a newly applied pause, exclusion, or override is honored even if the task was already queued. Existing retry, failure backoff, recent-run minimum gap, and reporting-cycle behavior remain in place.

Run Now uses the same target-preview output as the automatic resolver. It does not change `next_run_at`. A broker failure that prevents every target from being queued returns an actionable 502 response.

## APIs

Schedule CRUD:

- `POST|GET|PATCH|DELETE /api/projects/{project_id}/schedule`
- `POST|GET|PATCH|DELETE /api/products/{product_id}/schedule`
- `POST|GET|PATCH|DELETE /api/sboms/{sbom_id}/schedule`
- `GET /api/products/{product_id}/schedule/effective`
- `GET /api/sboms/{sbom_id}/schedule` (effective result)

Inheritance and exclusion:

- `POST /api/products/{product_id}/schedule/exclude`
- `POST /api/products/{product_id}/schedule/inherit`
- `POST /api/sboms/{sbom_id}/schedule/exclude`
- `POST /api/sboms/{sbom_id}/schedule/inherit`

Operations:

- `GET /api/schedules?scope=PROJECT|PRODUCT|SBOM`
- `GET /api/schedules/{schedule_id}/targets`
- `POST /api/schedules/{schedule_id}/run-now`
- `POST /api/schedules/{schedule_id}/pause`
- `POST /api/schedules/{schedule_id}/resume`
- `PATCH /api/products/{product_id}` with `current_sbom_id`

Schedule management requires `product:manage_schedule`; read/effective/preview routes require `product:read`. Every route resolves its URL target and schedule against `CurrentContext.tenant_id`.

## User workflow

1. Open a Product and upload its first SBOM. Confirm it appears as Current SBOM.
2. Upload a second version. Leave **Set as current SBOM** selected to promote it, or clear the option to retain the existing current version.
3. Configure a Project schedule and leave Target versions at **Current SBOM only**.
4. Open target preview. Confirm one current version per Product and `NO_CURRENT_SBOM` for unconfigured Products.
5. Open one Product, create a different cadence, and confirm the Project preview reports that Product as overridden.
6. Exclude another Product and pause a third. Confirm both are skipped and their parent inheritance remains blocked.
7. Add an exact SBOM schedule and confirm it is the effective source for that SBOM.
8. Use Run Now and verify the returned `sbom_ids` match the included preview targets.
9. Restore inheritance and confirm the effective source moves back to Product or Project without restarting API, worker, or Beat.

## Deployment and verification

Back up the deployment database, deploy the same revision to API/worker/Beat, and run:

```bash
.venv/bin/python -m alembic upgrade head
.venv/bin/python -m alembic current
```

The expected head is `054_hierarchical_scheduler`. Then start the API, a Celery broker, at least one Celery worker, and exactly one Celery Beat process. API-only startup is insufficient for recurring execution. Redis is the production/default broker. On a local machine without Redis, set `CELERY_USE_DATABASE_BROKER=true` to derive a SQLAlchemy broker URL from the existing `DATABASE_URL` without duplicating its password. A full `CELERY_BROKER_URL=sqla+postgresql+psycopg://...` value is also accepted. The application automatically converts that broker URL to the `db+postgresql+psycopg://...` result-backend scheme. The polling SQLAlchemy transport is intended for development and smoke tests, not production.

Recommended verification:

```bash
.venv/bin/python -m pytest -q tests/test_schedule_resolver.py tests/test_schedules_api.py tests/test_scheduled_analysis_hierarchy.py tests/test_hierarchical_scheduler_migration.py tests/test_product_hierarchy.py
.venv/bin/python -m ruff check app tests
cd frontend
npx tsc --noEmit
npm test
npm run lint
npm run build
```

## Known aggregate-status limitation

A Project/Product schedule fans out into independent child tasks. The existing `last_run_at`, `last_run_status`, and `last_run_id` columns still describe the most recently completed child task, not a persisted aggregate batch result. This change preserves that behavior. Reporting cycles provide a durable completion barrier for notification digests; a general schedule-execution aggregate would require a separate data model.
