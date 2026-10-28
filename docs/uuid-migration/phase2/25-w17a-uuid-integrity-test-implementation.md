# W1.7A — Executable PostgreSQL UUID integrity suite and isolated E proposal

**IMPLEMENTED (STAGED); 53 new offline tests +21 existing expand tests PASS. Live integrity tests NOT EXECUTED / NOT ACCEPTED. BLOCKED at independent E environment review.** 2026-10-17, Asia/Kolkata. Branch `feat/native-user-management`, HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`; dirty work preserved. No migration086 is created or needed. D remains accepted at085; it is never a DML target for this suite.

Read tracker/report24/W1.1/report10/report11/report12 and actual migration/runner/common sources, accepted085 protected catalog/commit evidence and actual six-table columns/constraints. The prior W1.6I real commitACK15:13:30.795789UTC/physical close/new runner read-back15:13:31.242164 and independent broader acceptance remain accepted history. Final manifest `02177e95f9c6def0294f9c2162cbee849ac9fda6ee1dd3177d0101e187e4ca4a` and every18 referenced artifact hash verified before this task's single database session. No historical report/source/failed-helper record was changed.

## Actual implemented files and entry points

| File | Implemented responsibility |
| --- | --- |
| [uuid_integrity_suite.py:595](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/uuid_integrity_suite.py:595) | Explicit offline/list/proposal/validate/execute CLI, table/category selection;193 actual cases, bounded two-worker execution, labelled PASS/FAIL/SKIP and stop/no retry |
| [uuid_integrity_control.py:60](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/uuid_integrity_control.py:60) | Pure E-specific authority validation before Docker/credentials/connections, pinned source/provenance/catalog/cluster/expiry/action checks, private evidence, resource guards, connection/row/time budgets |
| [uuid_integrity_fixtures.py:58](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/uuid_integrity_fixtures.py:58) | Real-catalog-checked deterministic synthetic builders; parameterized inserts, integer/composite FK hierarchy, explicit negative PKs, native UUID return/read-back; no deletion or sequence manipulation |
| [uuid_integrity_fixture_catalog.json](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/uuid_integrity_fixture_catalog.json:1) | Sanitized six-table columns/types/nullability/defaults and PK/FK/CHECK/unique definitions captured from actual D085; no business rows, role names, secrets or function bodies |
| [test_uuid_integrity_offline.py](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/test_uuid_integrity_offline.py:1) |53 isolated offline unittest cases: approval refusals, actual fixture dependency contract, source safety, parameterization, mocked transaction/closure/unknown-commit/rollback/cancellation/scope checks and case coverage |

No application settings/launcher/engine, root Alembic environment or dotenv imported; no image/resource provisioner or schema restore exists in these files. Existing pinned expand/common modules are imported for inert metadata/prefix/source helpers only. Their D-only connect/plan paths are never used by the E suite. New E connections use a separate explicit constructor.

## Current accepted085 source verification — actually executed read-only

One bounded authenticated D-only session used the existing approved disposable credential file and the explicit127.0.0.1:56041/database/user/cluster. In a REPEATABLE READ READ ONLY transaction, PostgreSQL16.15/cluster7697252084555804711/database identity/sole `085_uuid_sbom_component_expand` matched; six native nullable UUID columns/core defaults/NOT VALID v4 CHECKs/two enabled triggers per table/exact shared guard passed the existing prefix verifier. Captured roles/extensions/catalog security matched accepted085. All71business tables were empty via bounded EXISTS probes. Zero competing D client sessions; source hash/active079+staged080–085 checks passed. Physical session closed, no reconnect/retry and no database mutation.

| Catalog format | Fresh result against matching accepted085 format |
| --- | --- |
| Runner13 | `85507e89a3946cda7611e5498e816fcf5708af18a6549b08a4fbfe3ae1f0d80a` — exact match |
| Independent31 | `760c7e7b0b50688fd4f7c3471219a35fa3b025f67bf3303cc15a50f44800fd30` — exact match, complete captured catalog equal |
| Inventory |72tables /1149basecolumns /512indexes /60sequences /143FKs; no unique public UUID indexes/backfill/validation/NOT NULL enforcement |

Known missing VEX supersession FK and original integer graph remain in the accepted catalog. No ORM repair/normalization performed. This one D session was only the authorized bounded source-readiness/fixture-dependency probe; it did not execute the new connected test runner. No A/B/production connection, DDL/DML, schema dump/export/import or fixture row insertion occurred.

Filtered local Docker/host metadata after implementation matches the accepted pre-task snapshot in every recorded field except UTC, with sorted container/network/volume sets; same original D/container/image/volume/access network/loopback port/credential metadata, existing SBOM PostgreSQL/Redis/Mailpit/storage/networks, process/listener/runtime/environment-file safe metadata. Recorded application service PIDs remain absent/stale runtime/no18000or13000listeners; no service-running or A/B-data-equality claim. Local E names/resources absent from the unchanged inventory and56042 had no listener at observation; neither resource names nor an unbound port prove future isolation or reserve it. Fresh target/collision/capacity review is mandatory before any provisioning.

## Executable coverage and real expected assertions

All categories are implemented in [uuid_integrity_suite.py:146](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/uuid_integrity_suite.py:146); `--table` and `--category` can select individual table/category groups.32cases each for tenants/projects/products/logical_sbom/sbom_source,33for sbom_component (extra self-FK case),193total. A full invocation starts with fresh empty E; committed synthetic fixtures are retained. A later separate invocation will refuse nonempty E rather than silently clean/reuse it; rebaseline/recreation is a separately reviewed operation, not automatic resumability.

| Category | Cases on every table | Actual future assertion / classification |
| --- | --- | --- |
| Generation (5) | omitted, explicit NULL, supplied v4, uppercase canonical input, duplicate explicit valid v4 | INSERT RETURNING+new physical read-only read-back; integer PK/native psycopg UUID/pg_typeof uuid/non-NULL/v4/RFC variant;8-generated controlled concurrent sample. Duplicate supplied v4 values are **expected to be allowed** before unique-index stage, not a regression or global uniqueness guarantee |
| Validation (7) | v1, v5, invalid variant, nil, malformed text, integer-type mismatch, new-row NOT VALID enforcement | Wrong version/variant/nil→23514 with exact `ck_TABLE_public_id_v4`; malformed→22P02; incompatible integer→42804. Savepoint rollback and independent absence. NOT VALID still enforces new/updated rows; type canonicalization differs from API grammar |
| Immutability (8) | change assigned UUID, remove toNULL, same UUID, unrelated business update, SET DEFAULT reassignment, legacy NULL→first valid, legacy NULL→NULL/unrelated, legacy NULL→invalid | Already-assigned change/removal/default→23514 from trigger (no CHECK constraint_name); same/unrelated preserve exact mapping; valid first assignment permitted, NULL remains NULL on unrelated legacy UPDATE, invalid first assignment fails CHECK. New independent committed-state verification |
| Concurrency (4per table +component FK) | two independent concurrent insert clients, concurrent reassignment rejection, conditional NULL-only assignment race, row-lock timeout; component self-reference | Two workers, two-transaction barrier for same-row races; eight generated target UUIDs observed distinct; reassignment rejected; NULL-only race rowcounts0/1 and valid winner, never overwrite; row-lock wait55P03 and independent preservation. Integer/self FK valid; nonexistent self target23503 with savepoint rollback |
| Failure (5) | CHECK savepoint, trigger savepoint, partial outer-write/savepoint rollback, statement timeout, transaction abort/rollback | Actual SQLSTATE23514/57014/25P02 and constraint provenance; SELECT1 after savepoint; outer unrelated update survives nested failure; 50ms timeout vs200ms pg_sleep; explicit aborted rollback, close and independent absence/preservation. Not a destructive recovery test |
| BEFORE interference (3) | early and late BEFORE UPDATE UUID rewrite, two BEFORE triggers where late restores old UUID | AFTER guard checks final row state: rewrite rejected23514; alphabetically early rewrite+late restore permits unchanged final identity. Both helpers row-filtered to exact synthetic PK, removed before commit; original UUID guard never disabled/replaced |

`expect_error` checks error SQLSTATE and CHECK/trigger diagnostic provenance; it does not stringify driver errors/DETAIL/SQL or log fixture IDs/UUIDs. SQLSTATE expectations come from actual reviewed CHECK/trigger SQL plus native type conversion; only future PostgreSQL execution can establish them. Python mocks/SQLAlchemy compilation are not PG grammar or runtime acceptance.

### Realistic synthetic hierarchy and NULL-fixture boundary

[uuid_integrity_fixtures.py:155](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/uuid_integrity_fixtures.py:155) builds tenant→project→product→logical→source→component prefixes. Every row is labelled synthetic, parameterized and uses an explicit int4 negative PK reserved by table/slot, so existing sequences are neither advanced nor reset. Tenant statusACTIVE/timestamptz timestamps, project_status1, product normalized_name/slug/string created_at, logical string timestamps, source logical/tenant/product/project fields and component lifecycle_is_stale/lifecycle_manual_override/is_duplicate are supplied from actual required-column evidence. Nullable sbom_type and source lineage fields are omitted, not satisfied with guessed lookup rows. Product current-SBOM cycle remains NULL. Composite product/tenant/logical relationships are populated consistently; source sbom_version1 and component bom_ref/version remain domain identifiers, not surrogate IDs. FK values are read back and normal FK constraints remain enabled.

The catalog-derived fixture contract independently checks every NOT NULL/no-server-default field, all column names/types and populated FK tuples. Source-defined Python defaults were not assumed to execute in direct SQL. No `create_all`, ORM flush/events, foreign-key disabling or replication bypass.

Accepted D has no legacyNULL rows, and its INSERT allocator fills explicitNULL. To test the genuine pre-backfill contract on E, the suite proposes **additional E-only test DDL**, explicitly gated by `fixture_ddl_reviewed`: create `public.w17_integrity_before_v1()` (invoker/search_pathpg_catalog), create an alphabetically late row-filtered BEFORE INSERT helper that sets only the newly synthetic target's public_idNULL after the normal allocator, insert synthetic prefix, then drop only that exact helper/function before committing. This is a deliberately incompatible writer simulation, **not ordinary NULL-insert behavior**; the ordinary explicitNULL test independently requires allocation. For ordering tests, early/late BEFORE UPDATE helpers rewrite or restore only that synthetic row's identity, with both dropped before commit. No original guard/constraint/trigger is changed. Any unexpected existing helper name causes CREATE failure; no CREATE OR REPLACE/CASCADE/adoption/automatic repair. Failed helper transaction rolls back; committed final schema must match the original E baseline.

## E-only execution controls and recovery boundaries

[uuid_integrity_control.py:60](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/uuid_integrity_control.py:60) requires explicit `--target E`, exact host127.0.0.1/port56042/database `uuid_w17_e_integrity`, accepted E status, actual new non-D cluster/container/network/volume/databaseOID/server interface/postmaster pins, source-D085 fingerprints, code+fixture-catalog+all six migration hashes, matching fresh E catalog fingerprint, unexpired distinct integrity_validate/integrity_execute references and seven explicit operator flags (synthetic/parity/privileges+writers/credential/window/helper-DDL/egress). Wrong D/A/B port/name/cluster/remote/ambiguous/expired/unapproved/missing inputs stop before credentials/Docker/DB. No implicit selection by database name or port alone, application engine or environment fallback.

Connected mode also requires existing local Desktop daemon/CLI/socket, exact E labels/image, loopback-only port, exclusive new volume and network, no extra/app mounts or network members, resource limits/bridge controls, and a pinned filtered preservation hash for D/SBOM containers/volumes/networks. Database identity/major+minor/data_directory/owner/security/sole085/all guard definitions/no UUID index/eight-style maintenance requirements plus INSERT/UPDATE/SELECT/TRIGGER rights are checked. An initial empty72-table catalog/71empty business-table gate refuses business-data contamination. E13 includes catalog OIDs/role OIDs: **it must be captured after E restore and independently approved; it is not expected to equal D's raw OID-bearing13hash.** Full31/owner/ACL/dependency parity must independently normalize corresponding source/target object identities before accepting E; no roles/privileges or extension-owner exception is silently waived. Fixture catalog is a source subset for builders, not a complete restore/parity manifest.

New E-only password file `/Users/ferozebasha/.sbom-uuid-w17-e/postgres-password` must be generated later under0700/0600 with unique disposable secret, regular/non-symlink/single-link/UID protection and reviewed inode/size/mtime/ctime provenance. Bootstrap role name is kept to preserve ownership semantics, **not to reuse D's password**. Secret never appears in argv/environment/evidence/repository; controlled psycopg kwargs/passfile/dev/null/serviceempty/no ambientPG*/no dotenv, read-only-default connections. READ WRITE is selected only inside an authorized owned test transaction after identity verification. Never uses the common library's D-only connection constructor.

Limits: one cooperating session advisory7160085085 keeper +at most two active worker connections (three total),2048total opened connections,5000synthetic row attempts,256cases,900s cooperative run budget; normal statement2s/lock250ms/idle-in-transaction5s/connect5s, explicit test50ms statement timeout/200ms sleep. Thread barrier5s/future20s, two workers, cancellation flag stops further work after worker failure. Limits are proposed test caps, not measured runtime/performance guarantees; Python scheduling/network COMMIT acknowledgement is not a hard whole-run deadline. No performance claims.

Committed fixtures are retained on E; no DELETE/TRUNCATE/sequence reset or automatic teardown. Final data-scope check privately compares surviving negative IDs with in-memory fixture reservations, requires other65application tables empty, and reports counts only. Every case rechecks E schema/source/resource pins, SQLSTATE/rollback/read-back as appropriate and final catalog; final metadata must have no helper residue. JSONL evidence private0600/0700/O_EXCL/O_NOFOLLOW, fsync before cases and transaction precommit/after acknowledged fixture COMMIT; serialized evidence writing across threads, sanitized PASS/FAIL/SKIP. Known expected errors use savepoints; unforeseen failures stop and skip remaining cases. COMMIT-exit exception becomes UNKNOWN_COMMIT_STOP, no automatic reconnect/retry/recreate/cleanup. Physical connections close in finally. A remaining concurrent in-flight transaction is bounded/cancelled cooperatively; unknown outcomes require manual reconciliation. Hostile privileged concurrent DDL/writers are outside this cooperative test-window guarantee.

Process kill, network break, PG restart and storage failure are **design-only exclusions**, no automatic fault-injection path. Later approved recovery protocol must pin fixture mappings, choose the precise pre/post-COMMIT fault point, retain all evidence/storage, reconcile actual marker/catalog/committed mappings independently and prohibit blind retries. Existing W1.6B C-B02–C-B05 remain separate open findings; no old index/backfill runner was edited or accepted by these tests.

## Exact offline commands and results

Run from `/Users/ferozebasha/sbom` (all were executed using existing .venv; no install/application startup):

```sh
.venv/bin/python -B infra/uuid-migration/staged-runner/test_expand_one_step.py
.venv/bin/python -B infra/uuid-migration/staged-runner/expand_one_step.py --mode offline
.venv/bin/python -B infra/uuid-migration/staged-runner/verify_offline.py
.venv/bin/python -B infra/uuid-migration/staged-runner/test_uuid_integrity_offline.py
.venv/bin/python -B infra/uuid-migration/staged-runner/uuid_integrity_suite.py --mode offline
.venv/bin/python -B infra/uuid-migration/staged-runner/uuid_integrity_suite.py --mode list --table sbom_component --category concurrency
.venv/bin/python -B -m ruff check --no-cache infra/uuid-migration/staged-runner/*.py
.venv/bin/python -B -m ruff format --no-cache --check infra/uuid-migration/staged-runner/*.py
git -c core.fsmonitor=false diff --check
```

| Check | Executed result |
| --- | --- |
| New offline tests / CLI discovery |53PASS; all six table/category selections/193case inventory; no runtime calls in offline mode. Transaction mocks are not PostgreSQL acceptance |
| Existing expand tests |21PASS; unchanged source/graph/pinned contracts |
| Isolated offline mode |PASS active079/six staged080–085 graph/hashes/monolith exclusion |
| Existing verifier |PASS10Python files,79active+6staged,42SQLtemplates/14literal/18dynamic compilations/6unique-index-DDL compilations; no SQL executed |
| New syntax/AST/compiler checks |PASS four new Python modules +six-table fixture contract; SQLAlchemy helper/metadata/transaction text compilation and psycopg parameterized statement rendering; not server parsing |
| Ruff |All10staged-runner Python files lint and format PASS. Six historical migration I001warnings remain outside new changes; no pinned migration rewritten |
| Missing/false/expired/wrong-target tests |PASS in-memory manifests only; runtime validators refuse pending proposal before connection; no real execution approvals fabricated |
| Preservation |Fresh D catalog/source pins and one read-only session PASS; current filtered resources/processes match historical accepted baseline except observation time. File/history verification appended below |

Development history retained: first41offline tests had40PASS/one lexical no-cleanup assertion falsely matching the wordTRUNCATE in proposal prose; narrowed to actual executable SQL. Initial new-file Ruff style/import/loop-binding findings formatted/fixed only new files. Later source review added DEFAULT/legacy-invalid/final-BEFORE-ordering/synthetic-row-scope/concurrency cancellation tests; final53PASS. None was a PostgreSQL failure or retry. Real D session exit0/closed exactly once.

## Disposable E proposal — pending independent review

Private candidate `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17a-20261017T152612952531Z/e-provisioning-execution-proposal.json`; byte SHA256 **`49f7942fa62e8865ed044357f8b0144cb4abf9c1ed786b0de5b83320eb073709`**, canonical JSON digest **`76c09a5c0cf343e8907c395677bbd38f10ad654a69c78c082f2db50558c34f21`**, original expiry **`2026-10-18T15:45:39.587814+00:00`**. Parent0700/files0600 UID501; no E secret created. It is an exact **environment/provisioning proposal**, deliberately not an executable test approval: actual E pins/nulls, acceptedfalse, all seven flagsfalse and approvals{}. No action references generated. Actual E must be separately provisioned/accepted and fresh execution manifest independently reviewed before connected validate or DML. Review this proposal's resource/data/helper-DDL/role/security scope; an expired/changed proposal needs renewed review, not silent replacement.

The full nonsecret candidate is reproduced below unchanged. Proposed one-service configuration is an infrastructure specification, not an executed Compose command. No new Compose file, Docker command changing resources, image pull/build, credential file or E database exists from this task.

```json
{
  "accepted": false,
  "approval_stages": [
    "independent review of this exact offline resource/schema-copy/role/credential/egress/fixture-DDL proposal",
    "separate E-only provisioning and D-schema export/E restore/marker authorization",
    "accept actual E structural/security parity and new identity; create fresh execution candidate",
    "operator approval of actual E pins/expiry/source hashes/categories/budgets and distinct integrity_validate/integrity_execute references"
  ],
  "approvals": {},
  "baseline_procedure": [
    "New E-only OS-random secret, private0700/0600, no reuse",
    "Fresh collision/capacity/image/port/source-D identity approval before provisioning",
    "Separate reviewed D-only schema export authorization; no data/sequence positions",
    "Review full schema archive SQL/TOC; reproduce exact owners/ACLs/restricted roles",
    "One E schema-only single-transaction restore; no clean/no-owner/no-acl",
    "Independent structural/security parity; no inherited blanket ownership exception",
    "Separate explicit E-only insert of sole085 marker, no migration replay",
    "Accept E identity/catalog/parity, then independent target-specific test manifest review"
  ],
  "categories": [
    "generation",
    "validation",
    "immutability",
    "concurrency",
    "failure",
    "interference"
  ],
  "container_id": null,
  "credential_metadata": null,
  "credential_provenance_reviewed": false,
  "database": "uuid_w17_e_integrity",
  "database_oid": null,
  "e_schema_sha256": null,
  "exclusive_test_window_reviewed": false,
  "expires_utc": "2026-10-18T15:45:39.587814+00:00",
  "fault_injection": "Termination/network/PG restart/storage failures NOT IMPLEMENTED for automatic execution; separate destructive authority",
  "fixture_DDL": "E-only w17_integrity_before_v1 helper plus aa/zz row-filtered INSERT/UPDATE trigger; exact DROP before commit; never disables/replaces existing guards",
  "fixture_ddl_reviewed": false,
  "fixture_scope": "Committed synthetic negative integer PK hierarchies only; no auto DELETE/TRUNCATE/sequence reset",
  "host": "127.0.0.1",
  "max_cases": 256,
  "max_connections": 2048,
  "max_rows": 5000,
  "max_seconds": 900,
  "network_id": null,
  "network_risk": "Ordinary bridge permits outbound access including host-published services; ICC=false is not an egress firewall",
  "outbound_risk_reviewed": false,
  "password_file": "/Users/ferozebasha/.sbom-uuid-w17-e/postgres-password",
  "port": 56042,
  "postmaster_started_at": null,
  "preservation_sha256": null,
  "privileges_and_writers_reviewed": false,
  "resources": {
    "build": false,
    "cpus": 1,
    "daemon": "1f8c7fe5-5972-4adc-8d6e-363a38572be1",
    "enable_icc": false,
    "enable_ip_masquerade": true,
    "environment": {
      "PGDATA": "/var/lib/postgresql/data/pgdata",
      "POSTGRES_DB": "uuid_w17_e_integrity",
      "POSTGRES_PASSWORD_FILE": "/run/secrets/e_password",
      "POSTGRES_USER": "uuid_w1_d_bootstrap"
    },
    "gateway_mode_ipv4": "nat",
    "healthcheck": {
      "interval": "5s",
      "retries": 12,
      "test": [
        "CMD",
        "pg_isready",
        "-U",
        "uuid_w1_d_bootstrap",
        "-d",
        "uuid_w17_e_integrity"
      ],
      "timeout": "3s"
    },
    "image_id": "sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54",
    "internal": false,
    "memory_mb": 512,
    "network": "sbom-uuid-w17-e_e_access",
    "network_driver": "bridge",
    "password_mount": "/run/secrets/e_password:ro",
    "pgdata": "/var/lib/postgresql/data/pgdata",
    "pids_limit": 128,
    "postgres_settings": {
      "idle_in_transaction_session_timeout": "5s",
      "lock_timeout": "250ms",
      "max_connections": 12,
      "shared_buffers": "64MB",
      "statement_timeout": "2s",
      "work_mem": "4MB"
    },
    "project": "sbom-uuid-w17-e",
    "publication": "127.0.0.1:56042:5432",
    "pull": "never",
    "restart": "no",
    "service": "postgres_e",
    "shm_mb": 64,
    "socket": "/Users/ferozebasha/.docker/run/docker.sock",
    "volume": "sbom-uuid-w17-e_e_pgdata"
  },
  "schema_parity_reviewed": false,
  "server_address": null,
  "source_D085": {
    "independent31": "760c7e7b0b50688fd4f7c3471219a35fa3b025f67bf3303cc15a50f44800fd30",
    "runner13": "85507e89a3946cda7611e5498e816fcf5708af18a6549b08a4fbfe3ae1f0d80a"
  },
  "source_sha256": {
    "080_uuid_public_id_expand.py": "2fc6e6f9992d0763ddf6818b9e7b62d573eef2b7cda01a39689b8fffcbc623f8",
    "081_uuid_projects_expand.py": "28f803f5c5c439f1ae0f0fdb0748368b244c2c31b060bb1a61ff6302a3d2d95e",
    "082_uuid_products_expand.py": "76d830f79e699cbdd5116c1e848cc5923f10281a764a17f0abd6c1cf8c4b5ace",
    "083_uuid_logical_sbom_expand.py": "d7f8dbe4c262f4a045572c173b7fd61e38d003fa87f9ec28093427161234495e",
    "084_uuid_sbom_source_expand.py": "13a84b0d6d3201a64be7ba90a32560a5c5738a319be1fc8af29d2364aec49803",
    "085_uuid_sbom_component_expand.py": "45f331390609e52ceddbf0968651b5ec817bf26811f6f67845d1fb6d99cdbb0f",
    "expand_one_step.py": "57a4b222841a0a6a3f302a25356e20249bb0d07eaecf81d0bec00b596ecb043b",
    "uuid_integrity_control.py": "087d2f9e12d79a250cc71b57506b052bc51dbb2b98ab0fbf6aa05e208682296c",
    "uuid_integrity_fixture_catalog.json": "569c40a05306bea1651556047e512629e2cca9d0723a8379b861105740c27270",
    "uuid_integrity_fixtures.py": "7eaa30d1c16653d4b700b97f9730d704ebce68ca4ba7968290d29d7f4f7e44c5",
    "uuid_integrity_suite.py": "298b5cfc1a65b62eaa8dc808758b724608282d1f4cf33af192a97f8308d40504",
    "uuid_w1_common.py": "4b9ef6c1708ae8385db39c618aec10eba35e3b8e972b6de7c5a2583a6eabad94"
  },
  "space_gate": "Before provisioning/export: independently observe >=2GiB available host/Docker storage and >=1GiB memory headroom; stop if budget unavailable; no claim of current capacity",
  "synthetic_only_reviewed": false,
  "system_identifier": null,
  "tables": [
    "tenants",
    "projects",
    "products",
    "logical_sbom",
    "sbom_source",
    "sbom_component"
  ],
  "target": "E",
  "task": "W1.7A",
  "teardown": "Not automated; separate approval pins exact E container/network/volume/cluster; retain on failure, no wildcard/down/prune",
  "user": "uuid_w1_d_bootstrap",
  "volume_sha256": null
}
```

### Schema-copy, ownership and infrastructure gates

1. Operator reviews this exact candidate and separately authorizes new E-only resources/secret, D085 schema-only export, archive SQL/TOC review, E-only single-transaction restore and exact owner-role topology. No permission from W1.5A (B→D) transfers to D→E. No source mutation/data/sequence-value export. Use local PG16-compatible tools already present; pull/build prohibited.
2. Fresh verify D085/current pins/empty tables/security; local daemon/image/resources/collision/port and host/Docker capacity.56042 must be free then, not merely here. Stop on insufficient2GiBstorage/1GiBheadroom, unsupported driver options or any conflict; do not change ports or fall back to D. New E cluster/container/network/volume identities must be distinct from D/A/B and tracked independently.
3. Schema-only archive must preserve all application schemas/columns/defaults/CHECK states/triggers/shared function/owner/ACLs/policies/extensions/dependencies/sequence definitions without sequence values; no blanket no-owner/no-acl, no clean/drop/createDB/ORMcreate_all/migration replay. Inspect archive SQL for foreign-server/subscription/extension/function side effects. Required owner role exact protected name/approved attributes, no unapproved memberships/grants; plpgsql owner compatibility must be explicitly reviewed on E, no inherited broad exception. New roles or security differences stop for approval.
4. Restore source085 schema into E under a single fail-on-error transaction after reviewed role/security gates. Schema-only export does not carry Alembic row; **exact sole085 marker establishment is a separately explicit E-only authorized INSERT step**, not inferred or stamp/replay. Full structural/security parity to source D with normalized object identities must pass; all71tables empty before fixtures. Actual E raw13 fingerprint is newly captured/approved, with sourceD13+31 kept as provenance, not compared across unrelated OIDs. Newly observed E systemID/DBOID/postmaster/address/container/image/storage/network/credential/preservation pins require independent acceptance.
5. Ordinary dedicated NAT bridge/loopback only, no app/D networks, ICCfalse additional restriction, sole E member; outbound reachability including host-published services remains possible. Accept explicitly or stop for separate zero-egress/proxy design. ICCfalse is not a general outbound firewall. Resource limits/new privatevolume persist test fixtures. No new API/Redis/Celery/Beat/frontend/mail or integrations.
6. Only after E acceptance create a new target-specific execution candidate, review actual pins/code/hash/category-budget/fixtureDDL/expiry and supply distinct integrity_validate/integrity_execute references. New-case manifest does not authorize provisioning. Tests require an exclusive cooperating/no-unrelated-DDL window. A separate host/process metadata wrapper must record before/after current process identities as in W1.6I; suite's embedded preservation guard covers filtered Docker resources, not macOS process lifecycles.
7. Failure retains E/storage/credential/evidence and any known committed synthetic rows; no retry/cleanup/recreation. Future teardown is separately authorized with exact E project/container/systemID/original new E volume/network and confirmation D/A/B untouched; remove only individually pinned E resources after needed evidence retained. No wildcard prune/down/volume deletion. Stale helper/schema/unknown commit requires reconciliation, not blind DROP. No automatic repeat run on nonempty E.

## Files, status and next action

Source hashes of new repository artifacts:

| File | SHA256 |
| --- | --- |
| uuid_integrity_control.py | `087d2f9e12d79a250cc71b57506b052bc51dbb2b98ab0fbf6aa05e208682296c` |
| uuid_integrity_fixtures.py | `7eaa30d1c16653d4b700b97f9730d704ebce68ca4ba7968290d29d7f4f7e44c5` |
| uuid_integrity_suite.py | `298b5cfc1a65b62eaa8dc808758b724608282d1f4cf33af192a97f8308d40504` |
| test_uuid_integrity_offline.py | `09763f2ffb25c8addd2d32e0266f9808b9819094fd493bf1469a0fe5ae36aa60` |
| uuid_integrity_fixture_catalog.json | `569c40a05306bea1651556047e512629e2cca9d0723a8379b861105740c27270` |

Existing runner `57a4b222841a0a6a3f302a25356e20249bb0d07eaecf81d0bec00b596ecb043b`/common `4b9ef6c1708ae8385db39c618aec10eba35e3b8e972b6de7c5a2583a6eabad94` and all six staged revision pins unchanged; exact proposal pins include them. Protected evidence directory `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17a-20261017T152612952531Z` contains repository baseline, single-session source/labels/catalog, host metadata, offline command outputs and candidate. No secrets, full connection strings, process environments or business records exported/printed; sanitized structural definitions only in repository fixture metadata.

**W1.7A source IMPLEMENTED (STAGED), offline verification PASS; PostgreSQL integrity execution NOT EXECUTED / NOT ACCEPTED.** E provisioning/source-export/restore/marker/execution approval is pending. D remains accepted085,71empty business tables and all historic migration evidence preserved; actual database mutations0, E creations0, live integrity cases0. No indexes/backfill/business fixtures/086/active registration/application changes/Git delivery.

**Next action:** independently review exact E proposal byte hash/content/expiry, outbound-risk acceptance, new E-only secret/resource limits, sourceD085 schema-copy/owner-ACL/marker plan and helper-DDL/synthetic scope. Then separately authorize the exact E preparation/provisioning/baseline operation; only after actual E acceptance review a fresh execution candidate with real identity/catalog pins and distinct action approvals. Do not mistake this proposal or tracker update for either authorization.

Still unexecuted: all193live cases, nativeSQL/type/CHECK/trigger results, committed fixture FK/data/side effects, concurrent-writer/real lock-timeout/rollback behavior, BEFORE interference, unknown-COMMIT/manual fault recovery, capacity/runtime/performance and application/API/tenant tests. Global UUID uniqueness remains unenforced until separate unique-index stage; explicit duplicate-valid UUID case intentionally expects acceptance now. Design/mock PASS cannot close these gates.


Final W1.7A verification PASS:2,101 pre-existing repository file contents other than authorized tracker unchanged; exact six new files are report25/four Python harness-test modules/one sanitized fixture catalog. Branch/HEAD/tracked binary diff unchanged;44 historical completed-task rows/12 Phase1 issue rows retained verbatim;69 report/tracker local links/line references and whitespace checked. Exact candidate JSON in report equals private bytes/source pins/expiry/seven false flags/empty approvals; restrictive0700/0600UID501 verified. Private9-entry/10file evidence manifest SHA2568214055ff6a7a2fcb5b4af971f864039f20cc6535cfecbd387fbbe5cde83de85; protected offline outputs and single read-only session labels retained. Actual migration Ruff check exit1 with precisely six historical I001 import warnings, no new diagnostic or pinned-source rewrite; staged-runner10file lint/format exit0.53new+21existing offline tests PASS,193case enumeration PASS; live cases0/Ecreatedfalse/database mutations0. Exactly one authorized D read-only session/zero A-B, no further database connection for documentation. Next remains independent exact E proposal49f7942fa62e8865ed044357f8b0144cb4abf9c1ed786b0de5b83320eb073709 review and separately scoped provisioning/baseline authority, then actual E acceptance/new execution manifest; no connected test execution authorized.
