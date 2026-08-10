# Refactor baseline — 2026-07-22

This record is the precondition for the incremental modular-monolith refactor.
It distinguishes repository failures from local environment failures and does
not waive tenant isolation, RBAC, API/SSE compatibility, or migration safety.

## Environment prerequisites

- Docker Desktop must be running with a reachable Linux VM.
- Compose service: `postgres` / container `sbom-postgres-1`.
- PostgreSQL 16, host `127.0.0.1:55439`, database/role `sbom_analyser` / `sbom`.
- Test database: `sbom_analyser_test` (destructive, truncation-isolated test data).
- Named volume: `sbom_postgres_data`, mounted at `/var/lib/postgresql/data`.
- Health check: `pg_isready -U sbom -d sbom_analyser`.
- Node 20+ and the checked-in frontend lockfile dependencies.

The initial PostgreSQL outage was a Docker Desktop VM routing failure
(`192.168.65.7:2376: no route to host`), not PostgreSQL configuration,
credentials, volume corruption, or disk exhaustion. `docker desktop restart`
followed by `docker compose up -d postgres` restored the existing volume.

## Passing checks

| Check | Reproduction command | Result |
| --- | --- | --- |
| PostgreSQL readiness | `docker exec sbom-postgres-1 pg_isready -U sbom -d sbom_analyser` | accepting connections |
| Backend focused regressions | `.venv/bin/python -m pytest -q tests/test_metric_consistency.py tests/test_postgresql_integration.py tests/test_migration_drift.py tests/test_sqlite_postgres_migration.py tests/test_sbom_lifecycle_remediation.py tests/test_hcl_iam_auth.py tests/test_identity_administration.py tests/test_kev_enrichment_service.py tests/test_large_sbom_upload_integrity.py tests/test_sbom_upload_validation_persisted.py` | 99 passed, 63 warnings |
| Backend full suite | `.venv/bin/python -m pytest -q` | 1,748 passed, 5 skipped, 600 warnings |
| Frontend full suite | `cd frontend && npm test -- --run --silent` | 86 files, 621 tests passed |
| Frontend lint | `cd frontend && npm run lint` | 0 errors, 37 warnings |
| Frontend build | `cd frontend && npm run build` | passed, 24 static pages generated |
| Backend focused Ruff | `.venv/bin/python -m ruff check app tests` | passed |
| Repository Ruff | `.venv/bin/python -m ruff check .` | 66 pre-existing findings |
| Import contracts | `.venv/bin/lint-imports` | 3 kept, 0 broken; 371 files / 2,190 dependencies |
| PostgreSQL migrations/drift | `.venv/bin/python -m pytest -q tests/test_postgresql_integration.py::test_fresh_postgresql_alembic_upgrade_and_check` | passed against a disposable clean database |
| SQLite migration chain | `DATABASE_URL=sqlite:////tmp/<new-db> ALLOW_SQLITE=true .venv/bin/python -m alembic upgrade head` | passed from empty database |

Alembic has one head: `045_secure_authorization_model`. PostgreSQL 16 is the
production/system-of-record migration target. SQLite is explicitly supported
for development and tests, so the migration chain is kept portable to it.

## Fixed baseline defects

- Test clients no longer execute unmocked post-upload lifecycle-provider I/O.
- A KEV API test now supplies the required tenant context explicitly.
- `ProjectModal` tests no longer return a mock function from `beforeEach` as an
  accidental Vitest teardown; async success, conflict, and pending paths are
  deterministic.
- The remediation router consumes the canonical metrics query boundary instead
  of adding a new direct `AnalysisFinding` / `AnalysisRun` ORM query.
- Fresh migrations seed `TENANT_ADMIN`, safely consolidate bootstrap-created
  `kev_entry` rows, tolerate current-metadata bootstrap tables, and use SQLite
  batch operations for widened finding columns.
- The SQLite-to-PostgreSQL migration fixture registers all metadata and creates
  valid tenant-owned source rows.
- Ruff correctness defects in `app/` and `tests/` were fixed, including the
  undefined `Session` annotation and a shadowed SBOM synchronization import.
- The declared import-linter dependency is installed and its existing external
  dependency contract is valid and runnable.

## Remaining accepted debt

- Ruff: 66 findings, confined to `KEV/` legacy typing style and
  `docs/sdd/build_ssd_docx.py`; no findings in `app/` or `tests/`.
- Frontend ESLint: 37 warnings, 0 errors; none introduced by stabilization.
- Backend warnings: 600, primarily Alembic configuration deprecation and one
  Pydantic class-config deprecation, plus test-only short JWT key warnings.
- Five opt-in integration tests remain skipped without Redis or live AI provider
  credentials.
- Alembic revision 001 still bootstraps from live `Base.metadata`; the fixed
  historical migrations preserve clean-install convergence but a frozen initial
  schema remains separate migration debt.
