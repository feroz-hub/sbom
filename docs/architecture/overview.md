# Current architecture

Scope: maintained overview, checked against e62951c2 on 28 October 2026.
Older SDD/SSD publications are revisioned historical baselines, not current
startup or deployment instructions. Their classification and retention are
covered by the [storage proposal](../documentation-storage-strategy.md); this
current overview does not promote individual unclassified publications.

## Application boundaries

    Browser
      -> Next.js App Router / React
         -> authenticated BFF (/api/backend/*)
            -> FastAPI
         -> unauthenticated isolated local mode: FastAPI directly
      -> FastAPI routers -> services / metrics / source adapters
         -> SQLAlchemy models and PostgreSQL
         -> offline validation schemas and external providers
         -> Celery workers / Redis and the selected scheduler

The backend is a modular monolith. [app/main.py](../../app/main.py) wires routes,
middleware, security and lifespan; [routers](../../app/routers) expose HTTP
interfaces, [services](../../app/services) implement domain work, and
[models](../../app/models.py) describe persistence. SQLAlchemy queries exist in
services and routers; there is no app/repositories directory to describe as a
universal persistence layer.

[app/metrics](../../app/metrics) owns finding/run aggregates. Use the
[metric conventions](../metric-conventions.md). Validation and parsing remain
separate, with [vendored schemas](../../app/validation/schemas) for offline
structural checks.

The [frontend app](../../frontend/src/app) contains pages and BFF route handlers;
components, hooks, types and API helpers remain under frontend/src.
Authenticated browser access uses server-side sessions and the BFF; the API
independently enforces token validation, tenant membership and permissions.
[Security and IAM](../security/README.md) separates HCL, Native and Entra behavior.

## API contracts

Use the version-matched API's /docs and /openapi.json in an authorized running
environment for exact request/response schemas. Route/model wiring remains in
[app/main.py](../../app/main.py) and the resource schema/OpenAPI helpers.
The root openapi_latest.json and openapi_bf078_live.json are different snapshots;
neither filename proves current contract provenance. Keep released contracts
bound to a source revision and review any interface change separately.

## Background work and startup

The [Celery application](../../app/workers/celery_app.py) registers analysis,
mirror, KEV, cache, report and security-mail tasks. Report notifications route to
the reports queue. Production Compose consumes celery and reports and runs one
separate Beat. The Greenfield worker consumes both queues but embeds only the
restricted security-mail periodic schedule; it does not run the full scheduler.

The legacy developer worker lacks an explicit reports queue subscription.
Starting that profile does not establish report-delivery readiness; see the
[developer guide](../development/README.md).

API lifespan performs configuration/schema checks and data maintenance including
reference seeds, analytics backfill and stale-work reconciliation. It is not a
read-only probe. Database schema changes belong to the
[controlled installation/upgrade process](../DATABASE_BOOTSTRAP_AND_UPGRADE.md).

## Runtime and release boundaries

[Local Compose](../../docker-compose.yml) supplies development data services.
[Server Compose](../../docker-compose.server.yml) uses the backend image for API,
migration, worker and Beat plus a separate Next.js standalone image. Keep private
runtime settings separate from public frontend build values.

The checked-in server configuration targets linux/amd64; other production
architectures, native Windows/macOS production, provider combinations, horizontal
scale and actual installed release state are unverified here.
[Deployment guidance](../UBUNTU_DOCKER_DEPLOYMENT.md) and the database
compatibility gate govern any release.

The optional [standalone KEV service](../../KEV/README.md) has its own API/database
and is distinct from integrated application KEV. Its external deployment and
support status require an owner decision before retirement.
