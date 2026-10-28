# Public resource UUID implementation

Status: **PUBLIC_RESOURCE_UUID_IMPLEMENTATION_COMPLETED** — source and disposable-environment acceptance complete. No populated migration, deployment, full UAT or release sign-off.

Starting branch: `feat/native-user-management`. Starting and current HEAD: `e0c454029dea624e16d7511a1de0499e53fce237`. This is newer than the supplied historical `83444c4` baseline. Existing dirty/untracked historical evidence is preserved. No commit, push, checkout, reset or stash occurred.

The initial authenticated read-only observation found the populated database already at **101**, not the supplied historical 100, with 19 users, 19 provider links, 18 Native credentials, 21 memberships, 21 role assignments, 4 platform grants, 40 runs and 70 findings. This task did not apply 101 or 102 there. The operator independently stopped the original application stack around 21:31 IST and later stopped/restarted Docker/PostgreSQL. Those changes are recorded as operator actions; this task did not target original application PIDs or container lifecycle.

## Implementation

The final source manifest covers **141 files: 129 modified tracked files and 12 new sources**. Complete diffs and exact hashes are in `evidence/implementation-source.patch` and `evidence/implementation-source-sha256.json`. Historical migrations 100/101, the original identity guards and historical migration configuration remain unchanged. Two existing test functions were renamed to describe the newly approved UUID contract; their request, authorization, user identity and batching coverage is preserved.

- `app/models.py`: TenantUser, PlatformUserRole and AnalysisRun reuse the native UUID mixin. Integer PK/FKs remain unchanged.
- Revision 102 follows frozen 101. It allocates missing UUIDs transactionally, adds NOT NULL/UNIQUE/validated version/variant CHECKs, and installs a distinct SECURITY INVOKER guard and two triggers per table. It refuses DBAPI autocommit and unsupported predecessor markers. Downgrade refuses.
- `app/resource_schema.py`: explicit historical-100 metadata representation, followed by actual 101 and 102 bodies with atomic marker updates. Neither frozen migration is rewritten.
- `app/resource_public_api.py` and `app/public_api.py`: explicit route/field ownership, tenant/platform scoping after existing authorization, strict UUIDv4 HTTP input, scoped batched response resolution, nested references and safe error input/prose projection. Internal DTOs/services remain integer based.
- `app/resource_stream.py`: AI SSE conversion uses the authorized request-local mapping without database access during iteration. Analysis creation SSE emits its persisted UUID directly. The request translation session closes before long-lived AI streams.
- `app/resource_openapi.py`: wire UUID schemas for internal dictionary responses, namespaced VEX Membership references and documented SSE contracts.
- CSV/SARIF/compare/PDF/scheduled report projections use public Run references. Findings, audit events, assignments, provider subjects and Celery IDs retain separate contracts.
- `app/main.py`: confirmed platform request-audit failure corrected by writing tenantless operations to the global authorization audit stream; tenant-owned auditing remains unchanged.
- Frontend User/Membership/Grant/Run types, clients, polling, links, filters and query keys retain distinct UUID strings. Recovery markers retain valid UUIDs and discard stale numeric resource markers. No global numeric-to-UUID replacement was used.
- The populated startup path refuses source revision 102 before credential/database access: no implicit 101/102 cutover is enabled.

## Validation environment

New disposable databases use the `sbom_public_resource_uuid_*_test` namespace on the existing Greenfield PostgreSQL cluster; they are separate databases, not a claim of separate clusters. Browser services use API 18400, trusted HTTPS UI 13400 and dedicated Redis 56392. Browser runtime role has no SUPERUSER/CREATEDB/CREATEROLE/REPLICATION/BYPASSRLS. Seven new synthetic identities and two synthetic tenants were created; the original six seeded identities were excluded.

The full regression launcher uses a clean environment, checks its unavailable broker at 63392 before execution, and checks Celery routing before collection and each test. Test workspaces/report artifacts now use private task-owned directories. No task queue can fall back to the original development worker.

Actual results and failures are in TEST_RESULTS. The disposable browser database is at 102, all ten UUID resources pass catalog checks, and metadata comparison reports zero differences. SQLAlchemy warns about the pre-existing logical_sbom/products/sbom_source FK cycle; independently captured FK definitions and synthetic migration snapshots supplement that comparison.

Final acceptance: **4,490 backend PASS / 9 documented SKIP / 0 FAIL/ERROR**, with **12 additional passing subtests**; **1,820 frontend PASS** across 201 files; **11 distinct real Chrome scenarios PASS** with TLS verification enabled. TypeScript, production webpack build, application/tests/changed-script Ruff, new-source formatting and Git whitespace checks passed. ESLint has zero errors and 52 historical warnings; four unchanged global-script Ruff findings remain documented. Exact coverage of all 4,499 collected backend cases was independently reconciled without omissions or overlap. The accepted focused run and final primary run have identical application/shared source; the only intervening changes were three primary-only test modules that the focused run neither selected nor imported.

The final read-only populated-database check again matched the starting revision 101, all recorded row counts, the absence of the three new public columns and all 144 FK definitions. Both main API/UI ports remain closed on IPv4 and IPv6, consistent with the operator's stop. Only task services remain available: API 18400, HTTPS UI 13400 and Redis 56392. The UI also returned HTTPS 200 using curl without a certificate bypass. No code was committed, pushed, merged or deployed; CI and staging remain pending.

## Reproduction

Use `.venv/bin/python -B scripts/public_resource_uuid_test_environment.py tests -o addopts= --junitxml=<new-private-path>` for the complete inventory. `--lane focused` selects independent task-owned fixture databases. These scripts explicitly refuse arbitrary database names.

Browser setup: `scripts/public_resource_uuid_browser_environment.py prepare`, then `start`, only after verifying the named task resources are absent. Existing task resources are inspected and resumed individually, never blindly recreated. Start the local OSV simulation with `postman simulation run docs/uat/public-resource-uuid/evidence/osv.sim.yaml --port 19400 --output ndjson --no-history`. Run the evidence browser harness using bundled Node; credentials are read locally into memory, no authenticated traces/screenshots are recorded, and Chrome uses `ignoreHTTPSErrors: false`.

The OSV simulation proves real HTTP integration, persistence and UI behavior against reviewed synthetic provider responses. It does not prove public OSV availability. HCL.CS/Entra acceptance remains contract-test evidence only; live-provider acceptance is unavailable locally.

`POPULATED_DATABASE_MIGRATION_NOT_AUTHORIZED`

`FULL_UAT_SIGNOFF_WITHHELD`
