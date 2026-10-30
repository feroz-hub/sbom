# Greenfield UUID application acceptance

Date: 2026-10-19. Local development acceptance; not a production deployment.

Status: **GREENFIELD_UUID_READY_FOR_FULL_TESTING**. No legacy business records were imported or backfilled.

## Actual environment and schema

The new `sbom-greenfield-uuid-dev` Docker project contains PostgreSQL, Redis and Mailpit on its own bridge and volumes. No A/B/D/E/F resource or old migration executor was used. The ordinary bridge permits outbound traffic; localhost publication is not an egress firewall.

| Item | Actual value |
|---|---|
| PostgreSQL | 16.15, pinned image `sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54` |
| Database | `sbom_greenfield_uuid`, `127.0.0.1:56044`, OID 16384 |
| Cluster | `7698349709013049382` |
| Alembic marker / active head | `100_greenfield_uuid_final` |
| PostgreSQL container | `7e2ce1d310616bcc7fe0c2b0509f38d8ff208d99ca2c2f7dddfb837df474f583` |
| Storage / network | `sbom-greenfield-uuid-dev_pgdata`, `sbom-greenfield-uuid-dev_access` |
| Redis | localhost 56381; separate task-owned data volume |
| Mail | Mailpit SMTP localhost 1026; mailbox UI localhost 8026 |
| Backend / frontend | `http://127.0.0.1:18000`, `https://localhost:13000` |
| Schema | 71 application tables plus Alembic; 1,149 total base columns; 144 FKs; 515 total indexes; 60 sequences |

The complete current SQLAlchemy metadata registers application, reporting and NVD models. Bootstrap creates this schema, installs the explicit UUID objects and current authorization references, checks structure, and records revision 100 in the same successful installation transaction. It then closes the setup connection and reads back independently. This marker represents a new greenfield baseline, not a claim that historical data migrations ran. The 001–079 and staged 080–091 files remain unchanged. Existing populated installations cannot use this new baseline as a data-upgrade path.

A second empty, task-owned `sbom_greenfield_uuid_repro_test` database was independently bootstrapped and checked against the same metadata and references. Repeat bootstrap verifies an existing revision/schema without silently repairing it.

All six resources—tenants, projects, products, logical_sbom, sbom_source and sbom_component—have native persisted UUIDv4 `public_id`, database/client generation, explicit-NULL allocation, NOT NULL, unique constraints, validated v4/variant CHECKs and two enabled triggers. The shared security-invoker guard has a fixed pg_catalog search path. Conditional AFTER UPDATE immutability observes changes made by other BEFORE triggers. Original integer PKs/FKs remain internal. Fresh metadata includes the VEX relationship absent from the historical D physical schema; the old D catalog is not this new schema's baseline.

The runtime uses `greenfield_app` (no SUPERUSER/CREATEDB/CREATEROLE/REPLICATION/BYPASSRLS, schema CREATE or marker-write authority). Setup uses the separate privileged `greenfield_setup`; objects belong to NOLOGIN `greenfield_owner`. Credentials and signing/storage keys live only under `~/.sbom-greenfield-uuid` (0700 directory, 0600 private files). No credentials are committed or included here.

## UUID application implementation

`app/public_identity.py` and the six ORM models define the final storage contract. `app/public_api.py` translates scoped public UUID paths, queries, forms, JSON references and responses at the authenticated HTTP boundary while services keep integer relationships. Invalid/non-v4 public IDs reject with 422; missing or foreign-tenant resources return 404; unauthorized tenant selection returns 403. OpenAPI describes the UUID wire fields. Non-resource IDs (users, memberships, analysis runs, investigations, providers) retain their separate contract. Component version strings remain version strings.

Frontend routes, clients, resource selection, tenant context and cache keys preserve UUID strings. Keyset pagination exposes UUID anchors in both cursor input and X-Next-Cursor output, preserving internal integer ordering. Nested posture/version/source references and permanent-delete responses retain their public identities. Analysis defaults now follow server configuration instead of hardcoded providers. Report snapshots and links use public UUID resource references. Dialog focus timing/restoration and project default ordering were corrected during real regression testing. `ResourceId` fixture-compatible TypeScript unions remain transitional; numeric values do not gain HTTP authorization.

Core new sources: `app/{public_identity,public_api,greenfield_schema}.py`, `alembic/versions/100_greenfield_uuid_final.py`, `infra/greenfield-uuid/compose.yml`, `scripts/greenfield_{uuid,references,seed,schema_check,integrity,acceptance,regression}.py`, `scripts/dev.py`, `frontend/src/lib/publicId.ts`, `frontend/e2e/greenfield.{config,spec}.ts`, and the Makefile. Existing model, auth-context, tenant-serialization, report-composer, frontend resource/type/client and regression-test files were updated. Use `git diff --name-only` to inspect the full working tree; it also contains preserved pre-existing user changes.

## Real verification

| Check | Result |
|---|---|
| Main and separate empty-database reproducibility / metadata parity | PASS; types/nullability, PK/FK graph, index/CHECK/unique sets, UUID defaults/triggers, ownership, guard source/security/ACL and authorization references |
| Final-schema UUID integrity | **193 executed, 193 PASS, 0 FAIL, 0 SKIP**; 676 connection attempts and 676 physical closures |
| Live authenticated HTTP acceptance | **35 PASS**; UUID CRUD/filtering, six resources, invalid/missing IDs, roles and cross-tenant denial, platform tenant creation/context switching (including cross-tenant platform directory visibility while a working tenant is selected), OpenAPI, lifecycle/VEX, reports and OSV analysis |
| Frontend Vitest | **1,769 PASS / 198 files**, 0 failures/skips |
| TypeScript / production Next build | PASS |
| PostgreSQL restart / application reconnection | PASS; same cluster, marker, all six row counts and UUID sets, then 35 live HTTP checks passed |
| Local HTTP timing smoke | 10 authenticated requests; median 32.7 ms, nearest-rank p95 134.0 ms; not a production benchmark |
| Setup safety unit tests | **12 PASS**, synthetic credentials only; includes static field coverage of all 964 original core-contract bindings |
| Native/backend/report regressions | **359 distinct cases passing across serial and focused reruns**: 312 native/domain cases plus 47 reporting/FDA cases; initial combined run was 348 PASS / 11 FAIL, corrected reruns are retained |
| Playwright Olympus journey | **1 PASS**; native login, explicit Olympus selection, UUID project/product routing, upload, component results, real streamed analysis and persisted run shown |
| Ruff, Python AST, whitespace and historical preservation | PASS on implemented sources; historical migration/runner/report bytes preserved, tracker append-only |

The 193 original staged scenarios are run against a dedicated final-schema test database with the historical suite files unchanged. Final-contract adaptations are explicit: duplicate UUIDs reject with 23505; removal rejects with 23502; legacy NULL fixture/assignment scenarios establish that a NOT NULL final schema cannot represent legacy NULL rows. They do not claim an old-data backfill test. Other cases execute real allocation, type/version/variant/CHECK enforcement, immutability, BEFORE-trigger interference, concurrency, savepoints, rollback, lock/statement timeouts and independent committed reads. This task's test database alone is reset. No fixtures are written to any protected historical database.

The live API run completed actual public OSV requests for a deliberately vulnerable lodash fixture and persisted findings. VEX changes were audited and Viewer writes refused. A report was generated by the real Celery reports queue, retained as artifacts and delivered to local Mailpit; no external email recipient was used. Native login and a multi-tenant synthetic administrator exercise tenant selection and isolation. Development users are explicitly synthetic: Olympus, Isolation Control and acceptance-created tenants; no historical customers were imported.

Development failures remain in private logs: initial 181/193 integrity result exposed an UPDATE-OF trigger gap; it was fixed and all 193 reran. Integer fixture assumptions and component DTO mapping were corrected. Reporting fixtures were aligned with the actual UUID HTTP contract; a contradictory HIGH/CVSS 9.0 fixture was corrected to CVSS 8.0 while preserving its HIGH assertions. Linux-only load-probe assumptions gained explicit macOS support and unchanged measured limits. Dialog focus failures were fixed. Two overlapping backend runs were interrupted and discarded as acceptance evidence; a mutual-exclusion lock now prevents that interference. Browser login correctly presented tenant selection after the platform tenant-creation test; the journey was updated to select Olympus explicitly.

## Reproduce and operate

Requirements: compatible Docker Desktop/local Unix Docker socket (the pinned PostgreSQL image was tested on linux/arm64), Python 3.11+ (tested 3.12), compatible Node (tested bundled Node), mkcert with an independently approved/trusted local CA, and available localhost ports. Current macOS setup verifies that trust before provisioning; see the HTTPS follow-up below. Installed Google Chrome is required for the strict browser checks. On Linux the explicit local socket fallback is `/var/run/docker.sock`; remote Docker environment selection is not inherited.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt -e '.[dev]'
(cd frontend && npm ci)
(cd frontend/e2e && npm ci && npx playwright install chromium)
# Explicitly preload these exact images on a clean machine:
docker pull postgres@sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54
docker pull redis@sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2
docker pull axllent/mailpit@sha256:98b916bd3c8d61f7633a52d3ea2f58d00620cb01ca57ab59edde68c347a95365
python scripts/dev.py setup --profile greenfield --provision-greenfield --initialize-database --confirm-database sbom_greenfield_uuid
```

Current setup is controlled through scripts/dev.py: provisioning, confirmed empty-database initialization and migrations are explicit operations. See [bootstrap controls](../../scripts/BOOTSTRAP.md). Runtime startup uses the full application schedule with separate default/reports workers and one separate Beat. Historical results below describe the earlier implementation and do not establish current platform acceptance; see the [current matrix](../engineering/dev-launcher-platform-matrix.md).

For subsequent starts, the standard launcher now selects this installed UUID environment automatically:

```sh
python3 scripts/dev.py start
python3 scripts/dev.py status
python3 scripts/dev.py stop
python3 scripts/dev.py restart
python3 scripts/dev.py --check
```

Start resumes only recorded existing containers, then runs API, IAM readiness, worker and frontend checks. It performs no schema bootstrap, seeds or migrations. The launcher stays in the foreground; Ctrl+C or `stop` stops its owned application processes and preserves data services. `--profile greenfield` makes selection explicit; `--profile legacy` selects the older development path.

Open `https://localhost:13000` (now a locally trusted mkcert leaf; see the HTTPS follow-up below). The synthetic admin email is `admin@olympus.example.test`; retrieve its random password locally from the private `~/.sbom-greenfield-uuid/users.json`, never from this report. Select **Olympus** if prompted. Upload CycloneDX/SPDX under **Olympus Release → Olympus Gateway**, open Components List, run analysis and inspect Analysis Runs. Mail is viewable at `http://127.0.0.1:8026`.

```sh
make greenfield-schema
make greenfield-integrity
make greenfield-api
.venv/bin/python -m pytest --noconftest -q tests/test_dev_private_setup.py
.venv/bin/python -B -m scripts.greenfield_regression  # default native suites; test-file arguments accepted
(cd frontend && npm test -- --maxWorkers=1)
(cd frontend && npx tsc --noEmit)
.venv/bin/python scripts/dev.py setup --profile greenfield --frontend-build  # separate isolated build workspace
(cd frontend/e2e && npx playwright test --config greenfield.config.ts)
python scripts/dev.py restart --profile greenfield  # only recorded task-owned backend/frontend/worker processes
```

The fresh-process report load probes passed at 50 SBOMs/4,901 findings (**4.23 s, 172.3 MiB peak**) and 250 SBOMs/24,901 findings (**24.28 s, 288.0 MiB peak**), retaining the original elapsed-time and <512 MiB peak-memory assertions. Linux keeps its original /proc VmHWM and address-space-cap implementation. macOS uses independently tested fresh-exec ru_maxrss in bytes; a 64 MiB parent-allocation regression demonstrates that parent residency is excluded. A hard child address-space cap is unavailable on this macOS host and is explicitly reported, rather than presented as enforced.

Do not launch two backend regression commands against the same regression database; the runner enforces an exclusive lock. Live HTTP tests create labeled synthetic records and contact OSV; report preview/send rate limits remain enforced. Logs, schema receipts, integrity results and Docker identities are private under `~/.sbom-greenfield-uuid`. No automatic teardown/prune targets are provided.

## Limits and remaining release work

This is a functioning local native-auth/OSV configuration. Live Entra/HCL OIDC and paid AI/GitHub/VulDB integrations need their own external development configuration; no successful live identity-provider/provider test is claimed. AI is disabled by default, with a private encryption key available for later configuration. NVD mirror tables exist; no complete NVD feed has been imported. Native/OIDC mock tests are distinguished from actual native authentication.

The 964 original contract binding rows have static field/context coverage checks; those checks are not 964 independently executed API scenarios. Raw uploaded SBOM evidence and vendor identifiers remain opaque, and arbitrary historical JSON is not globally rewritten by guessing at numbers.

The full repository contains more test files than the explicitly selected critical suites recorded here; no claim is made that every optional/provider/live test was run. Browser coverage is the Olympus main journey, not exhaustive accessibility or every administration screen. Production load/scale, database/network/storage fault injection, backup restore and uncertain-COMMIT recovery are not certified by mocked tests or this development run. Final-schema rollback/timeouts/concurrency are real PostgreSQL tests. These limitations remain production-release work, not permission to alter old environments.

Detailed sanitized execution evidence is under `~/.sbom-greenfield-uuid`: `schema-accepted.log`, `repro-schema-acceptance.json`, `integrity-accepted.log`, `api-accepted.log`, `frontend-final-complete.log`, `backend-serial-final.log`, `report-final.log`, `report-final-complete.log`, `delete-post-fix.log`, `browser-accepted.log`, `build-accepted.log`, `typecheck-contract.log`, `postgres-restart-acceptance.json`, `contract-focused-accepted.log`, `report-load-measurements.log`, and `final-acceptance-evidence.json`. The full-regression log intentionally retains its original failures; focused reruns supply the corrected outcomes.

No Git commit/push, production deployment or old business-data transfer was performed. Branch and HEAD remain unchanged. Historical reports, staged UUID migrations and protected source evidence remain preserved.

## Standard launcher follow-up

`python3 scripts/dev.py start` now automatically selects this installed environment. Existing Docker IDs are verified before only stopped greenfield containers are resumed. Existing database/schema/seed state is retained. Runtime registration, singleton locking, cooperative stop, process birth-identity checks and foreground cleanup use the existing launcher implementation. `--check` reads resource metadata without starting containers or reading credential contents. `status` reports greenfield rather than legacy data-service ports.

The first live launcher check reached backend health and the HTTPS UI, but `/ready/iam` returned 503: database=true, rate_limits=false, delivery_worker=false. Startup timed out and owned application processes were closed. This exposed incomplete local IAM configuration in the earlier setup. The corrected environment uses dedicated Redis DB 3 for native rate limits, enables rate limiting and the durable security-mail outbox, creates a separate persistent private encryption key, and starts an embedded scheduler limited to security-mail dispatch. Local SMTP remains Mailpit; provider/mirror schedules remain disabled. No schema migration or seed initialization was performed.

Launcher verification: 161 synthetic launcher/lifecycle/setup tests passed with `--noconftest`, Ruff checks/format passed on the added/updated greenfield sources, and `dev.py --check` passed with stopped containers. An initial ordinary pytest invocation hit the repository's database-dependent session hook at the unavailable legacy port 55439 before test collection; it is not counted as a test pass. The isolated rerun excludes that unrelated global conftest for these mocked launcher tests.

Live standard-launcher verification passed: `python3 scripts/dev.py start` reached API health, IAM readiness and the HTTPS native-login page; `status` showed all six services running; `stop` cleanly terminated the three registered application groups and its foreground launcher while preserving data containers. A subsequent standard start was used to leave the application available for local checking.

## Login follow-up

A real browser with a legacy integer tenant preference could authenticate successfully but fail context loading with HTTP422. The persisted-preference reader now clears malformed/non-v4 preferences before creating tenant headers. Valid tenant selections still require server authorization. Real Native Login checks passed for all six synthetic roles, including refresh, logout, expiry and cross-tenant denial; the original Olympus upload/analysis journey passed again. See [login diagnostics](GREENFIELD_LOGIN_DIAGNOSTIC.md) for correlated evidence, exact final regression results and manual instructions. No schema, credential or permission repair was performed.

## Trusted development HTTPS follow-up

The original self-signed leaf and Playwright TLS-bypass configuration did not establish normal Chrome trust. This has now been corrected with a leaf issued by the existing trusted local mkcert CA; no Keychain change was necessary on this Mac. Setup/start requires system trust before readiness, and both greenfield browser configurations now use installed Chrome with `ignoreHTTPSErrors: false`. Existing certificates are reused rather than regenerated on each restart. `python scripts/dev.py doctor --profile greenfield` performs system-trust endpoint verification. See [HTTPS certificate fix](GREENFIELD_HTTPS_CERTIFICATE_FIX.md) for before/after fingerprints, strict-browser login results, fresh-machine prerequisites and remaining platform limitations. Historical test results above retain their original scope.
