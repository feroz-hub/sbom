# Security remediation baseline — 13 October 2026

Git HEAD: `33c5465`. Initially no tracked modifications; existing untracked `security-reports/` preserved. No application code modified before this report.

## Route inventory

`route-inventory.csv`: 436 method/path entries (428 application operations and 8 framework documentation operations). 277 authenticated entries lack explicit permission dependencies. `route-dependencies.json` captures dependency trees. Inventory follows FastAPI 0.139 included-router effective dependencies; a flat `app.routes` scan would miss application routes. Database/ownership columns are source-based indicators, not proof that every downstream operation is isolated.

Most routers inherit `enforce_request_access`; it maps URL strings to permissions and defaults to `dashboard:read` / `tenant:settings:update`. Route dependencies sometimes add narrower policies, but naming collisions take precedence (VEX/lifecycle exports, project report export). Identity, login, recovery, verification, health and legacy-helper operations need explicit classification.

## Baseline tests

Ran existing HCL IAM, legacy auth, tenant isolation and KEV router suites on disposable SQLite: **53 passed, 8 failed, 16 errors** (40.21 seconds). Tests used `TEST_DATABASE_URL=sqlite:////tmp/sbom_security_baseline_test.db`, with `TEST_POSTGRES_DATABASE_URL` empty. No production database accessed.

Failures: six HCL principal/tenant resolution tests and two legacy JWT endpoint tests. Errors: eight legacy endpoint/client tests and eight tenant isolation tests. SQLite app startup cannot seed assignable tenant roles (`AssignmentProblem: requested tenant role is not assignable`), followed by frozen-exception traceback `TypeError`. Some HCL assertions predate current identity-state behavior. These failures must be distinguished from remediation regressions. The preexisting `backend-test-final.txt` is incomplete and cannot establish a clean baseline. Full-suite/PostgreSQL baseline has not been established.

Existing tests cover RSA token expiry/issuer/audience, provider setup, native/Entra auth, authorization catalog and role assignment, tenant isolation, scoped VEX, KEV and lifecycle providers. New security tests should avoid the broken global lifespan and use isolated router/DB fixtures while retaining actual authorization dependencies.

## Confirmed review targets

- SEC-002: global lifecycle records accept tenant write/delete rights; mutation services lack authority guards.
- SEC-006: remediation upsert only gates `remediation:write`; `Closed` is an ordinary accepted status.
- SEC-007: downloads/exports can receive read or unrelated fallback permissions.
- SEC-008: `/api/v1/kev/sync` falls through to tenant settings permission; global catalog changes.
- SEC-009: project restore has no explicit tenant filter or route context; depends on ambient ORM guard.
- SEC-010: health type/config operations use permissive legacy helpers; principal helper trusts identity/role headers.
- SEC-011: remediation accepts `user_id` as audit actor; project/SBOM/version/schedule paths also accept actor fields.

## Architecture / deployment observations (read-only)

Standalone `KEV/main.py` has unauthenticated sync/read routes and initializes its own async database. Server compose does not register a KEV service; main API and Celery also have KEV functionality. Whether standalone HTTP is required externally is unresolved. Do not invent a service credential contract without documenting callers.

AI Celery tasks require tenant_id and bind a minimal system context, but do not carry/revalidate requesting user authority. Other worker entry points require further review. Redis has no host port in server compose, but uses an unauthenticated internal broker; anyone with network access can publish. Uvicorn uses `--no-proxy-headers`; application rate limiting nevertheless trusts raw X-Forwarded-For.

ORM selects receive tenant loader criteria only with a bound tenant context; before_flush checks ORM inserts/updates/deletes. Raw SQL, Core tables and bulk updates/deletes require explicit filters and do not receive equivalent universal protections. Runtime/migration database grants and network restrictions cannot be verified from source. No grants/schema/infrastructure changed.

## Incremental patches

1. Remediation close and restore tenant checks, authenticated audit identity, with negative/positive tests.
2. Global lifecycle/KEV authority at routes/services.
3. Explicit method/path authorization catalog, public/account classifications, deny unknown operations, export gates, registration regression test.
4. Authentication configuration / legacy helper / forwarding hardening, followed by focused existing provider tests.

Remaining jobs, database and session/upload controls require further dedicated review and deployment verification. No deployment authorized.
