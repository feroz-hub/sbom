# HCLTech SBOM Analyzer security remediation

13 October 2026. Baseline HEAD `33c5465`. Changes remain in the working tree for review. No deployment, production database access, grant changes, destructive testing, or new service credentials.

## Outcome and limits

Six incremental patch groups implement fail-closed route policies, production authentication validation, platform/tenant separation, confirmed endpoint fixes, trusted audit attribution, and live authorization of queued AI jobs. HCL IAM/OIDC, Native and Microsoft Entra validators remain supported.

The route inventory contains **436 registered method/path entries**, representing **434 distinct policies**. Two AI provider-catalog GET aliases are registered twice. The checked-in policy catalog declares public, authenticated account, and permission-protected operations. Registration validation runs before database initialization. Unknown operations are denied; permission lookup uses the route actually selected by FastAPI, including prefixes/aliases. Source inventories indicate guard/ownership syntax; they are not an assertion that all downstream operations have been audited.

Final verification: **230 passed, 6 deselected** in the selected security/provider regression run; the six omitted HCL principal-resolution cases are documented baseline failures, not disabled checks. All new regression cases run. Ruff passes across modified Python application/test files; `git diff --check` passes. This is not a clean full-suite or PostgreSQL integration certification.

See `baseline.md`, `route-inventory.csv` (before), `route-inventory-current.csv` (after), `policy-changes.csv`, `route-dependencies.json`, `background-entrypoints.csv`, `database-operations.csv`, `service-architecture.md`, and `test-results.json`.

## FIXED

### SEC-002 — global lifecycle vendor-record mutations

- Root cause: global rows were mutable using tenant `lifecycle:vendor-record:write/delete`; service methods performed mutations without authorization.
- Endpoints: POST `/api/admin/lifecycle-vendor-records`, PUT/DELETE `/{record_id}`, POST `/import`.
- Files: `app/routers/lifecycle_admin.py`, `app/services/lifecycle/provider_config_service.py`, `app/core/security.py`, `app/core/context.py`, `app/core/route_policies.py`.
- Implementation: require `platform:admin` and actual platform authority; select platform context from the explicit policy. Create/update/disable/import services reject missing or tenant authority before DB calls, including empty imports.
- Permission change: tenant administrators cannot mutate global lifecycle records. Existing read dependencies remain. Existing tenant write/delete catalog entries are retained for compatibility but cannot authorize these mutations. No permission migration required.
- Tests: deny each service mutation for absent context, tenant write/delete grants, and forged platform permission without platform context; positive real-DB create/update/import/disable.
- Results: new tests pass in final verification; initial negative tests reproduced the original failures. Existing full-app lifecycle suite requires a working seeded test database and an updated platform fixture for its old tenant-admin mutation expectation.
- Remaining risk: PostgreSQL behavior and global audit storage semantics require verification; deployment must use database-authorized platform grants.

### SEC-006 — remediation closure

- Root cause: `Closed` was accepted under ordinary `remediation:write`.
- Endpoint: POST `/api/remediation`.
- Files: `app/routers/remediation.py`, `app/services/remediation_service.py`.
- Implementation: check `remediation:close` before project lookup when closure is requested; service repeats authority checks, requires tenant write context, checks project ownership explicitly, filters remediation by tenant, and checks effective Closed status before mutation.
- Permission change: developers retain ordinary remediation editing; they cannot submit closure or edit a record whose effective status remains Closed without the close permission. Security analysts and tenant administrators with both permissions continue working. Direct service callers must supply a trusted bound tenant context.
- Tests: viewer/developer denials, analyst/admin successes, no inserted rows on denial, service denial before DB access, trusted audit actor.
- Results: new tests pass; original developer closure succeeded in the reproduction test.
- Remaining risk: PostgreSQL concurrency behavior and direct legacy service fixtures require follow-up verification.

### SEC-007 — downloads, exports and report production

- Root cause: URL inference chose read/unrelated permissions before export branches, including CSV/SARIF, VEX/lifecycle reports and project report exports.
- Endpoints: SBOM original download/export; vulnerability XLSX; analysis-run CSV/SARIF; VEX/lifecycle report and ZIP packs; FDA project report export; PDF report; comparison export; report artifact download; report preview/send-now. Repair downloads retain their distinct `sbom:repair:download` policy.
- Files: `app/core/route_policies.py`, `app/core/route_policy.py`, `app/core/security.py`, `app/services/report_access.py`, `tests/test_report_notifications.py`.
- Implementation: reviewed exact method/path policies require `sbom:export` on listed export operations. Scope/owner checks remain in handlers/services. Report preference authorization also requires export authority, including worker revalidation before generation and dispatch.
- Permission change: read-only viewers/developers cannot export, preview/send reports, or create/update report preferences that would generate exports. Analysts/admins need existing read/scope rights plus export. No new permission code introduced.
- Tests: all listed operations map to export; HTTP denial before business access and successful authorized gates for 13 operation variants; built-in role comparison; report service negative/positive checks.
- Results: pass. These gate tests exercise the real authorization dependency with business-access sentinels; they do not replace full exporter/rendering integration tests.
- Remaining risk: deployment must verify existing subscriptions are suppressed when recipients lack export authority; exporter/report integrations need PostgreSQL validation.

### SEC-009 — project restore

- Root cause: restore relied on ambient ORM filtering and did not include tenant ownership or route context explicitly.
- Endpoint: POST `/api/projects/{project_id}/restore`.
- Files: `app/routers/projects.py`, `app/core/route_policies.py`.
- Implementation: require `project:update`; select matching project ID and tenant ID with deleted-row visibility only; retain 404 for foreign/missing records; audit authenticated actor.
- Permission change: restore uses update authority rather than the old inferred create authority. Restore does not cascade to children.
- Tests: foreign tombstoned project returns 404 and remains inactive even without ambient ORM criteria; own project restores using update permission alone; create-only caller receives 403; spoofed audit user ignored.
- Results: pass; original foreign restore returned 200 in reproduction.
- Remaining risk: PostgreSQL soft-delete/integration tests remain to be run.

### SEC-010 — legacy helper and route classification

- Root cause: health/type helpers used legacy binary auth; legacy principal accepted caller identity/role headers; unmapped operations received fallback rights.
- Endpoints: all registered application routes; specifically `/api/types`, `/api/analysis/config`, legacy principal consumers, documentation/probes, authentication/account/proof-token flows.
- Files: `app/auth.py`, `app/routers/health.py`, `app/core/route_policy.py`, `app/core/route_policies.py`, `app/core/security.py`, `app/main.py`.
- Implementation: legacy adapters depend on the main database-authorized context; no role/actor headers accepted. Health business metadata uses the main permission guard. Exact public/account policies preserve login, activation, recovery and verification. Coverage validation recognizes actual trusted dependency factories, not lookalike function/closure names, and rejects unclassified Starlette routes/mounts.
- Permission changes: `/api/types` requires `sbom:read`; `/api/analysis/config` requires `analysis:read`. Legacy helpers now expose canonical database role names. Existing supported authentication providers are unchanged. Local API_AUTH_MODE bearer/JWT configuration is not an alternative production authorization system.
- Tests: missing/invalid auth 401, forged identity headers ignored, unknown methods denied, missing policies/guards fail registration, lookalike guard rejected, overlapping unknown route cannot borrow another operation's policy.
- Results: pass.
- Remaining risk: future mounts require explicit review; upstream gateway/deployment authentication integration must be validated.

### SEC-011 — authenticated audit actor

- Root cause: client `user_id`, `created_by`, `modified_by` or `uploaded_by` fields could supply operation attribution.
- Endpoints: remediation upsert, project update/restore, SBOM JSON/multipart creation and version edit/restore/conversion, schedule updates, VEX import.
- Files: `app/routers/{remediation,projects,sboms_crud,sbom_upload,sbom_versions,schedules,vex}.py`, `app/services/remediation_service.py`, `app/auth.py`, `app/workers/ai_fix_tasks.py`.
- Implementation: actor fields derive from authenticated context. Legacy input fields remain accepted but do not override actor attribution. Target user identifiers, intellectual document authors, remediation owners and read filters retain their original meanings. Queued AI execution binds the revalidated actor context for audit attribution.
- Permission change: attribution cannot be spoofed; no additional operation permission except those documented separately.
- Tests: spoofed remediation/project/version/schedule/SBOM/VEX actors ignored; legacy header identity ignored; positive operations continue.
- Results: pass; original attribution failures reproduced before changes.
- Remaining risk: generic audit writer still uses a tenant-1 fallback for global/system rows and some audit failures are swallowed. Changing global audit storage requires a separate migration/design patch; this implementation does not claim that issue fixed.

## PARTIALLY FIXED

### SEC-008 — global KEV synchronization

- Root cause: main API synchronization inherited a tenant-settings fallback; standalone KEV HTTP service independently has no authentication.
- Endpoints: main POST `/api/v1/kev/sync` fixed; standalone `/kev/sync` unresolved.
- Files: `app/routers/kev.py`, `app/core/security.py`, `app/core/route_policies.py`, `tests/test_kev_router.py`; architecture reviewed in `KEV/main.py`, `KEV/kev_service.py`, `docker-compose.server.yml`.
- Implementation: main API requires actual platform authority plus `platform:admin` before sync. System Beat task remains available. Existing KEV catalog tests now provide a platform caller for sync behavior; independent negative tests enforce rejection.
- Permission change: tenant admins cannot trigger main global KEV sync. Reads retain existing policies.
- Tests/results: tenant denial with zero sync calls, platform success, existing KEV read/filter/sync and worker suites pass.
- Remaining risk: standalone service is unauthenticated; no approved production caller/service identity contract has been established. Broker reachability remains trust for system jobs. Architecture was documented before changes; no new service credential mechanism introduced.

## Additional implemented hardening

- Authentication defaults enabled. Local identity requires explicit AUTH_ENABLED=false, development/test environment, development tenant, and no enabled Native/Entra/production-native mode. Server compose defaults APP_ENVIRONMENT=production. Staging/production require database authorization and role-assignment modes. Validation precedes startup data initialization; HTTPS issuer/discovery/JWKS validation no longer has a pytest-environment bypass.
- Platform permissions cannot be exercised from tenant contexts, even if a corrupt/custom role contains a platform code. Global AI registry reset and NVD mirror aliases have explicit platform policies.
- Rate-limit and audit client IPs use transport request.client; raw X-Forwarded-For is ignored. With server `--no-proxy-headers`, a reverse proxy's transport address is used. Approved proxy normalization requires deployment configuration, never client headers in application code.
- User-triggered AI jobs carry actor_user_id and tenant_id; worker rechecks active/verified account, active tenant/member, effective current role permissions and run tenant before pipeline/provider execution. Missing actor fails closed. Rejected/foreign jobs do not overwrite progress keys or invoke rollout/provider work before authorization. Old queued messages require authorized resubmission; rejected job status is returned/logged without overwriting unverified progress records. Revalidation happens at job start, not continuously during an already running operation.

## REQUIRES DEPLOYMENT VERIFICATION

- Full regression/integration run on a fresh, disposable PostgreSQL database with all catalog migrations/seeds. SQLite baseline: selected suites 53 passed / 8 failed / 16 errors. Original-commit Entra comparison reproduced 8 failures / 2 errors. Wider Native/catalog suites also fail under current SQLite fixture infrastructure; some old fixtures put platform grants into tenant contexts, which this patch intentionally rejects. Do not treat focused green tests as full-suite success.
- Verify existing role grants/export subscriptions, Native production key/outbox/SMTP setup, issuer/audience integration, API/worker version alignment and old AI queue resubmission.
- Redis has no published host port in server compose but no configured password/ACL command. Restrict network publishers and verify Redis ACL/TLS/credentials. Any compromised publisher can impersonate a valid job actor; passing actor IDs does not authenticate a broker sender.
- Inspect actual runtime/migration DB privileges and credential separation. Repository code does not prove least privilege; no live grants or schemas changed.
- Verify probe exposure, TLS termination/proxy configuration, effective browser headers, upload caps and session settings. Existing BFF sessions use Secure/HttpOnly/SameSite cookies and mutation origin checks; no frontend changes made.

## REQUIRES BUSINESS DECISION

- Whether standalone KEV HTTP is still required; retirement, approved ingress restriction or a supported service identity contract.
- Product confirmation for export-gated reports/subscription editing, mixed platform/tenant custom contexts, and canonical legacy role helper names.
- Audit representation of platform/system events and migration away from tenant-1 fallback.

## NOT YET ADDRESSED

- Exhaustive per-operation verification of all raw SQL/Core/bulk paths. `database-operations.csv` lists 138 static candidates; global cache/control-plane operations are not inherently tenant violations. Manual project-delete review found tenant-filtered run/finding/product bulk deletes and session events restricted through scoped session IDs. ORM guards do not universally cover Core/raw SQL/bulk work.
- Requesting-actor revocation review for Component Advisor and remaining user-triggered background jobs. Reports already rebuild recipient context; system jobs still trust the broker.
- Rate-limit bucket rotation through arbitrary unvalidated bearer-token values; general shared limiter deployment behavior; full CSP/security-header audit and all frontend CSRF flows.
- Repair of preexisting SQLite seeding, frozen exception traceback behavior, and failing integration fixtures. These were not bypassed or rewritten to make checks pass.

## Next recommended patch

Establish a disposable PostgreSQL baseline and update legitimate platform fixtures, then audit the remaining Core/bulk and Component Advisor job paths against real tenant fixtures. Resolve the standalone KEV/broker deployment contract before exposing or modifying that service. Keep changes separate from production deployment.
