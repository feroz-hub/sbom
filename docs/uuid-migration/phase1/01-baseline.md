> Local development uses `python scripts/dev.py`. Explicit Celery commands in this document are production/operator procedures.

# Phase 1 UUID migration: baseline audit

Audit date: 2026-10-16 (Asia/Kolkata). Scope: repository discovery and read-only baseline verification. No UUID migration has been implemented or applied.

## Git baseline

| Item | Observed value |
| --- | --- |
| Repository | `feroz-hub/sbom` |
| Checkout | `/Users/ferozebasha/sbom` |
| Required and actual branch | `feat/native-user-management` |
| HEAD | `2f48ff835d9e692fc84b31aaa951aad2495888ac` |
| Origin | `https://github.com/feroz-hub/sbom.git` |
| Upstream | `origin/feat/native-user-management` |
| Cached upstream comparison | 0 commits ahead, 0 behind |
| Live origin branch tip | `2f48ff835d9e692fc84b31aaa951aad2495888ac` |
| Initial working tree | Dirty: nine modified tracked files and one untracked file |

The live origin tip was checked using `git ls-remote --heads origin refs/heads/feat/native-user-management`; no fetch or local ref update was needed. HEAD, cached upstream and live origin tip matched at observation time.

Pre-existing modified files, preserved:

```text
frontend/src/app/settings/tenant/page.test.tsx
frontend/src/app/settings/users/page.tsx
frontend/src/components/admin/MemberActionMenu.tsx
frontend/src/components/admin/TenantAuditHistory.tsx
frontend/src/components/admin/TenantContextHeader.test.tsx
frontend/src/components/admin/TenantContextHeader.tsx
frontend/src/components/admin/TenantMembersTable.tsx
frontend/src/components/admin/TenantUsersAccess.tsx
frontend/src/components/admin/__tests__/MemberActionMenu.test.tsx
```

Pre-existing untracked file, preserved:

```text
frontend/src/components/admin/TenantMembersTable.test.tsx
```

The initial Git status emitted `error: daemon terminated` from the filesystem monitor while still returning status. Status was rechecked successfully with `git -c core.fsmonitor=false status --porcelain=v1`, a per-command override that does not change Git configuration.

## Repository map

Paths below are relative to the repository root.

| Area | Locations and responsibilities |
| --- | --- |
| SQLAlchemy foundation | `app/db.py`: engine, `Base`, naming conventions, `SessionLocal`, tenant-aware session behavior and database dependency. `app/models_mixins.py`: shared tenant ownership and soft-delete columns. |
| Main ORM models | `app/models.py`: tenants, identities, memberships, authorization, projects/products, logical SBOMs and versions, validation/repair, components, analysis, VEX, lifecycle, schedules, AI, audit and advisor entities. |
| Additional ORM models | `app/models_reports.py`: report subscriptions, deliveries and artifacts; imported by `app/models.py`. `app/nvd_mirror/db/models.py`: mirror settings, CVE rows and sync runs, using the shared `app.db.Base`. |
| Separate KEV subsystem | `KEV/database.py`: its own declarative base, async database setup and `KevVulnerability` model; inspect separately before deciding UUID scope. `KEV/config.py` and `KEV/schemas.py` hold associated configuration and contracts. |
| Alembic | `alembic.ini`, `alembic/env.py`, `alembic/script.py.mako`, `alembic/versions/*.py`. Environment registers main and NVD models against `Base.metadata`. |
| FastAPI assembly | `app/main.py`: application, lifespan, router registration and access dependencies. |
| FastAPI routers | `app/routers/`: projects/products, SBOM CRUD/upload/versions/logical SBOMs, validation/repair, analysis/runs/findings, reports, dashboards, CVE/KEV, VEX, lifecycle, advisor, AI, tenants/platform, native/Entra authentication, verification and authorization catalog. `app/nvd_mirror/api.py`: `/admin/nvd-mirror` router. |
| Pydantic contracts | `app/schemas.py` and `app/schemas_{authorization,compare,cve,dashboard,identity,lifecycle_admin,native_enrollment,platform,reports,tenants,user_management,vex}.py`; additional contracts in `app/ai/schemas.py`, `app/nvd_mirror/schemas.py` and domain modules under `app/services/`. JSON/XSD files in `app/validation/schemas/` are SBOM format validation schemas, a separate concern. |
| Frontend | `frontend/package.json`: Next.js, React and TypeScript application. Pages/routes in `frontend/src/app/`; UI in `frontend/src/components/`; API client in `frontend/src/lib/api.ts`; backend proxy in `frontend/src/app/api/backend/[...path]/route.ts`; shared contracts in `frontend/src/types/`; state/query behavior in `frontend/src/hooks/`. Frontend-specific guidance exists in `frontend/AGENTS.md`; no frontend files were edited. |
| Celery configuration | `app/workers/celery_app.py`: broker/result backend resolution, task includes, Beat schedule and worker lifecycle. Launchers: `scripts/dev.py`, `scripts/dev.py`, `scripts/dev.py`. |
| Celery jobs | Registered modules: `app/workers/security_mail.py`, `app/nvd_mirror/tasks.py`, `app/workers/scheduled_analysis.py`, `cve_refresh.py`, `ai_fix_tasks.py`, `source_cache.py`, `kev_sync.py`, `report_notifications.py`, `ai_model_discovery.py`, `component_advisor_tasks.py`. These are future ID serialization and task-argument audit surfaces. |
| Database configuration | `app/db.py`, `app/settings.py`, `alembic/env.py`; root `.env`, launcher `.env.dev.local`, `docker-compose.yml`, `docker-compose.server.yml` and example env files. Values and credentials are intentionally omitted. |
| Bootstrap/diagnostics | `scripts/dev.py`, `scripts/dev.py`, `scripts/check_database.py`, `scripts/bootstrap_fresh_database.py`, `scripts/schema/postgresql_047_baseline.sql`. These were inspected as source where needed; no launcher, bootstrap or migration operation was executed. |

## Repository migration head

Verified using `.venv/bin/python -B -m alembic heads`:

```text
079_lifecycle_provider_verification (head)
```

An independent AST-only inspection of revision declarations in `alembic/versions/` found:

- 79 migration files with revision identifiers.
- One base: `001_initial_schema`.
- One head: `079_lifecycle_provider_verification`.
- Head parent: `078_finding_reconciliation`.
- No missing `down_revision` references.

Head source: `alembic/versions/079_lifecycle_provider_verification.py`. Revision identifiers must be read from declarations, not inferred from filenames: `alembic/versions/055_ai_provider_model_registry.py` declares `055_ai_model_registry`.

`alembic/env.py` contains a fresh PostgreSQL upgrade path that loads the frozen revision-047 SQL baseline and stamps it before further upgrades. The initial migration is described there as using live metadata. This behavior was only inspected; no upgrade, downgrade, stamp, autogeneration or fresh-database operation was run.

## Live database revisions

Two distinct explicitly configured loopback PostgreSQL targets were accessible. Credentials were read in-process from configuration and never printed or written into this report. No application modules or startup hooks were imported for these probes.

| Configuration source | Read-only transaction verified | Observed `public.alembic_version.version_num` | Comparison with repository |
| --- | --- | --- | --- |
| Root `.env` `DATABASE_URL` (no shell override present) | `on` | `055_ai_model_registry` | Recognized ancestor; behind head |
| `.env.dev.local` `DATABASE_URL` (separate launcher configuration) | `on` | `079_lifecycle_provider_verification` | Matches head |

The probe used direct psycopg connections, restricted to explicit loopback PostgreSQL hosts, with connection timeout 3 seconds and startup options `default_transaction_read_only=on`, `statement_timeout=3000`, `lock_timeout=1000`. Each connection ran only:

```sql
SHOW transaction_read_only;
SELECT version_num FROM public.alembic_version ORDER BY version_num;
```

Each transaction was explicitly rolled back. No connection URL, password, username, database name or other secret value is included here. No fallback database was created, no services were started, and neither configuration was reconciled.

These observations identify configured database targets; they do not establish the target of a currently running API, worker, deployed service or production environment. A matching version marker does not verify physical schema equivalence. Confirm the intended deployment target before any later migration work.

## UUID-related baseline observations

- Many core ORM primary/foreign keys currently use integers, including tenant, user, project and report identities. `TenantOwnedMixin` and `app/db.py` tenant-context validation are part of the future impact surface.
- Pydantic contracts in `app/schemas.py` expose integer IDs and related fields; shared frontend types in `frontend/src/types/index.ts` expose corresponding numeric identifiers.
- Identity types are already mixed: `AiFixBatch.id` is an application-generated UUID stored as `String(36)`; NVD CVE rows use a textual `cve_id` primary key. A future migration needs an explicit entity/key scope rather than a blanket conversion assumption.
- Router parameters, authorization context, ORM relationships, frontend routing/query keys, task payloads and denormalized ID fields require later detailed inventory. This baseline is a location audit, not an exhaustive key/dependency inventory or a migration design.

## Scope and verification limits

Only this audit document was added. Existing frontend work was preserved. No checkout, pull, reset, stash, commit, push, schema change, application-code change or data modification was performed. No application, worker or development launcher was started.

Verification consisted of Git state and live remote-ref reads, source inspection, Alembic metadata inspection and the bounded read-only database revision probes above. Application tests, migration execution, schema comparison and end-to-end acceptance were outside this audit scope.
