# W1.6A — Six-table UUID expand implementation

2026-10-16, Asia/Kolkata. **IMPLEMENTED (STAGED), NOT EXECUTED, NOT ACCEPTED.** This task created actual migration source, not an applied schema. D remains NOT ACCEPTED, W1.4c PARTIAL and W1.5 NO-GO; their infrastructure acceptance is independent of this offline coding task. No database/Docker command or application startup was executed.

## Scope, baseline and revision evidence

Read the master tracker, full six-table public contract, W1.1 additive schema design and W1.4d diagnosis; inspected current Alembic environment, all active revision declarations, relevant models/mixins and naming conventions. W1.6A scope/prerequisites/acceptance and prohibitions were recorded IN PROGRESS in the tracker before implementation.

Branch `feat/native-user-management`; HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`. Task-start dirty tree contained 20 modified tracked files and 22 untracked files, 42 existing contents snapshotted. Only the existing tracker may change among those files. No checkout/reset/pull/stash/commit/push.

Static AST inspection found **79 active revisions, sole head `079_lifecycle_provider_verification`**, declared at [079:9](/Users/ferozebasha/sbom/alembic/versions/079_lifecycle_provider_verification.py:9). The staged artifact uses revision `080_uuid_public_id_expand`, down_revision `079_lifecycle_provider_verification`, branch_labels=None, depends_on=None; its identifier is below 32 characters. No dependency or revision number was reserved by the earlier design; this successor follows the currently inspected graph.

Exact files:

- Created [080_uuid_public_id_expand.py](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/080_uuid_public_id_expand.py:1).
- Created `docs/uuid-migration/phase2/09-w1-six-table-expand-implementation.md` (this report).
- Updated [MIGRATION_MASTER_TRACKER.md](/Users/ferozebasha/sbom/docs/uuid-migration/MIGRATION_MASTER_TRACKER.md:1).

The artifact is outside `alembic/versions`. [alembic.ini:2](/Users/ferozebasha/sbom/alembic.ini:2) selects `alembic`; no version_locations registration was added. Active revision/env/model/runtime/API/frontend sources are unchanged. The predecessor is provisional until a later promotion task rechecks the graph; do not silently splice it onto a changed head or edit an applied revision.

## Implemented schema delta — source only

For each table below, upgrade is written to add nullable native PostgreSQL uuid public_id, then separately set its future-insert default, add the NOT VALID v4/variant CHECK, and create the INSERT and UPDATE row triggers. Existing integer id PK/FK structures, sequences, business/domain columns and old defaults/constraints are not altered.

| Public-schema table | New CHECK | New BEFORE INSERT trigger | New AFTER UPDATE trigger |
| --- | --- | --- | --- |
| tenants | ck_tenants_public_id_v4 | trg_tenants_public_id_insert | trg_tenants_public_id_immutable |
| projects | ck_projects_public_id_v4 | trg_projects_public_id_insert | trg_projects_public_id_immutable |
| products | ck_products_public_id_v4 | trg_products_public_id_insert | trg_products_public_id_immutable |
| logical_sbom | ck_logical_sbom_public_id_v4 | trg_logical_sbom_public_id_insert | trg_logical_sbom_public_id_immutable |
| sbom_source | ck_sbom_source_public_id_v4 | trg_sbom_source_public_id_insert | trg_sbom_source_public_id_immutable |
| sbom_component | ck_sbom_component_public_id_v4 | trg_sbom_component_public_id_insert | trg_sbom_component_public_id_immutable |

Scope/constants: [migration:21](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/080_uuid_public_id_expand.py:21); column/default/check/trigger implementation: [migration:226](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/080_uuid_public_id_expand.py:226). There is one shared `public.uuid_public_identity_guard_v1()` function, six new columns/defaults/checks and twelve triggers. No indexes, uniqueness enforcement, backfill, validated NOT NULL proof, SET NOT NULL, API serialization, token change or ORM field is included. **Duplicate supplied v4 values remain possible until the next unique-index stage; no public issuance/cutover is permitted from this expand stage.**

`op.add_column` receives no default or server_default. Its offline PostgreSQL column compilation is `public_id UUID`, without DEFAULT/NOT NULL. Only a later ALTER COLUMN SET DEFAULT supplies `pg_catalog.gen_random_uuid()`. The intended effect is that legacy rows remain NULL and future omitted values receive database UUIDv4. CHECK NOT VALID avoids a legacy-row validation scan while enforcing the predicate on future writes. This follows the staged-default/constraint behavior in [PG16 ALTER TABLE](https://www.postgresql.org/docs/16/sql-altertable.html); it is not a measured rewrite/locking result.

The regex checks PostgreSQL canonical lowercase text: version nibble 4 and variant nibble 8/9/a/b. NULL is deliberately allowed. PostgreSQL's native UUID output canonicalizes accepted input spellings; the check is not the stricter future HTTP wire grammar. [PG16 UUID type](https://www.postgresql.org/docs/16/datatype-uuid.html), [core UUIDv4 generator](https://www.postgresql.org/docs/16/functions-uuid.html). Application rejection of caller-selected identity remains later API work.

Explicit constraint SQL preserves the W1.1 names instead of applying [the ORM CHECK naming prefix](/Users/ferozebasha/sbom/app/db.py:25) twice. SQL targets use the fixed public schema; identifiers come only from the six immutable source literals, not user input.

## Identity guard and conditional trigger rationale

Function: [migration:163](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/080_uuid_public_id_expand.py:163). It is VOLATILE, SECURITY INVOKER, has search_path=pg_catalog and schema-qualified core allocation. It rejects unexpected schema/table/event/timing/level/argument context. Only its INSERT branch assigns NEW.public_id; no other NEW field is assigned, no business table is queried and no audit/timestamp/lifecycle write is emitted. [PG16 function settings/security](https://www.postgresql.org/docs/16/sql-createfunction.html).

| Row transition | Written behavior; runtime test status |
| --- | --- |
| INSERT, public_id omitted | Separate DB default generates UUIDv4; BEFORE INSERT retains it — NOT RUN |
| INSERT, explicit NULL | BEFORE INSERT assigns pg_catalog.gen_random_uuid — NOT RUN |
| INSERT, supplied valid v4 | Retained for controlled restore/import; CHECK validates, but no uniqueness yet — NOT RUN |
| INSERT/UPDATE, non-v4 or invalid variant | CHECK rejects non-NULL wrong-version/variant value; invalid UUID syntax is rejected by native type conversion — NOT RUN |
| UPDATE, OLD NULL → NEW NULL | Allowed during nullable expand; no implicit update allocation — NOT RUN |
| UPDATE, OLD NULL → valid UUID | First persistent assignment allowed for later backfill — NOT RUN |
| UPDATE, unchanged assigned UUID | Allowed; conditional AFTER event not queued — NOT RUN |
| UPDATE, assigned UUID → different UUID/NULL/DEFAULT | Generic integrity exception SQLSTATE 23514, no values embedded — NOT RUN |
| Business-field UPDATE whose BEFORE trigger alters assigned public_id | Final NEW differs; conditional AFTER guard rejects — NOT RUN |

The AFTER UPDATE trigger uses `WHEN (OLD.public_id IS DISTINCT FROM NEW.public_id)`, not UPDATE OF public_id. The predicate is evaluated after BEFORE UPDATE changes; it skips only unchanged identity. Thus it does not lose the guard when another BEFORE trigger modifies public_id during an update whose SET list names only a business column. PG16 documents these timing/column-list distinctions in [CREATE TRIGGER](https://www.postgresql.org/docs/16/sql-createtrigger.html). This implements the proposed conditional optimization for correctness review; **no performance gain or PostgreSQL execution is claimed**.

Existing user BEFORE INSERT triggers and write rules are refused by preflight, even if a BEFORE INSERT trigger is disabled. A later trigger could undo the allocator and leave NULL admissible under the transitional check. This is a conservative compatibility gate, not an instruction to disable/delete existing triggers. The future target must inventory/ratify their behavior or revise this source under review. BEFORE UPDATE triggers are not blanket-rejected; the AFTER predicate is deliberately compatible with them. The BEFORE/INSERT bit masks 2/4 were checked against [PG16 pg_trigger.h](https://raw.githubusercontent.com/postgres/postgres/REL_16_STABLE/src/include/catalog/pg_trigger.h).

New ordinary triggers do not defeat superuser/DDL-owner control or replication bypass. Runtime-role permissions, session_replication_role and future trigger additions require target review; this migration does not grant/revoke application privileges or alter replication policy. Nor does it prevent delete/reinsert identity reuse, detect duplicate UUIDs or establish historical tombstone rules.

## Preflight, transactions and recovery

[Upgrade:203](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/080_uuid_public_id_expand.py:203) refuses SQL-render-only mode, non-PostgreSQL dialect, disabled transactional DDL, missing SQLAlchemy transaction, AUTOCOMMIT execution option or a DBAPI connection that does not report autocommit=False. This implementation targets the inspected synchronous psycopg/SQLAlchemy migration setup, not arbitrary mock/async drivers. The revision module was never imported/executed during this task.

Transaction-local timeout code caps lock_timeout at 1s and statement_timeout at 10s, retaining a stricter nonzero caller limit. NOWAIT acquires ACCESS EXCLUSIVE locks in the fixed six-table order before catalog checks or object creation. ONLY prevents locking descendants before the preflight rejects inherited/partitioned layouts. No autocommit block or intermediate commit is used. [PG16 LOCK](https://www.postgresql.org/docs/16/sql-lock.html), [timeouts](https://www.postgresql.org/docs/16/runtime-config-client.html#GUC-STATEMENT-TIMEOUT), [transaction-local set_config](https://www.postgresql.org/docs/16/functions-admin.html#FUNCTIONS-ADMIN-SET). NOWAIT bounds initial table-lock acquisition, not transaction lifetime; the statement cap is per statement, not a whole-revision deadline. Local limits reset at transaction end, not on returning from upgrade inside a still-open outer transaction.

[Catalog preflight:54](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/080_uuid_public_id_expand.py:54) requires PostgreSQL major 16; core zero-argument UUID allocator with native UUID return and migration-role EXECUTE; PL/pgSQL; six plain permanent non-inherited tables with existing single int4 id PKs. It rejects any same-name guard function overload, existing public_id, proposed CHECK/trigger collision, user BEFORE INSERT trigger or write rule. No same-name object is adopted, no CREATE OR REPLACE/DDL IF NOT EXISTS is used, no old schema object is cleaned up. Missing tables fail at lock acquisition without making changes.

With the required transaction, a future error is intended to roll back the whole new delta; this is not yet demonstrated on PG16. A normal retry is only after a known complete rollback and fresh preflight. Unknown COMMIT outcome or pre-existing/partial objects requires separate catalog/version/mapping review. Do not stamp, overwrite, drop/recreate objects or silently resume based on their names. The six-table preflight happens before function/column creation.

**Transaction-granularity review gate:** W1.1 [S1 and lock plan](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/02-w1-additive-schema-design.md:102) prefers one table per revision/unit and explicitly avoids a six-table transaction. This single staged revision instead makes the entire expand delta atomic and refuses partial-state adoption, holding six table locks until the surrounding transaction commits. It has no data scan/backfill, but it is still a broader lock set. This is an explicit implementation variation requiring review before promotion; it is **not** presented as compliance with the earlier per-table boundary. Splitting into per-table revisions plus a guard-function prerequisite is the alternative if that preference is mandatory. No internal commits were inserted into the current outer Alembic transaction to disguise the difference.

Current [env.py:48](/Users/ferozebasha/sbom/alembic/env.py:48) uses an outer transaction and has application/engine imports plus a fresh-install baseline path. It was read only, never imported/run, and remains unchanged. Future integration must explicitly bound this revision's transaction/operating window, review the variation above and use only an approved accepted D baseline. Do not execute the repository env script merely to preview this file.

[Downgrade:257](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/080_uuid_public_id_expand.py:257) unconditionally raises before any operation. It does not remove columns, guards, constraints or mappings. A separate mapping-preserving fallback/recovery procedure is required; restoring an integer-exposing API or dropping an issued UUID mapping is not accepted rollback.

## Static verification actually executed

| Check | Result / execution boundary |
| --- | --- |
| Python parsing | PASS: ast.parse of staged source; no module import, bytecode generation or upgrade invocation |
| Active revision graph | PASS: AST declarations in all 79 active files; sole 079 head; staged successor dependency and identifier length checked. No Alembic CLI/env load |
| Source-level assertions | PASS: exact six-table allowlist, native UUID/nullable/no Column default, operation order, explicit schema, v4 regex/version/variant samples, final-row WHEN/no UPDATE OF, guard-only assignment, collision/trigger checks, fail-closed downgrade, no index/backfill/NOT NULL/destructive SQL |
| Offline SQLAlchemy compilation | PASS using SQLAlchemy 2.0.51 only: six CreateColumn declarations compile to public_id UUID; 26 table/function/preflight text fragments plus the subsequently added timeout block compile without unexpected bind placeholders. No engine/connection created; SQLAlchemy does not validate PostgreSQL/PLpgSQL grammar |
| Local pinned Alembic APIs | Inspected installed Alembic 1.18.5 source for Operations.get_context/get_bind and PostgreSQL transactional_ddl=True; SQLAlchemy connection/driver_connection API source inspected. No migration runtime invocation |
| Static lint | PASS: `.venv/bin/python -B -m ruff check --no-cache --isolated --select E9,F63,F7,F82 infra/uuid-migration/staged-alembic/080_uuid_public_id_expand.py` |
| Formatting | PASS after formatting only the new artifact: `.venv/bin/python -B -m ruff format --no-cache --check infra/uuid-migration/staged-alembic/080_uuid_public_id_expand.py` |
| Whitespace/preservation/links | Documentation and existing-work checks, recorded at completion; no application or database validation implied |
| PostgreSQL grammar, triggers/defaults/checks/timeout behavior, rollback | **NOT EXECUTED / NOT ACCEPTED**; no PG parser package installed, no dependency installed or SQL command executed |
| Application/migration/browser/performance tests | **NOT RUN** |

Verification corrections: an initial source assertion mistakenly rejected catalog-query IF NOT EXISTS (not DDL idempotency); it was narrowed and rerun successfully. The `.venv/bin/ruff` executable path was absent; the installed module invocation succeeded (reported CLI 0.15.10). Initial format check requested formatting; the new file alone was formatted and then passed. These were local static-check issues, not PostgreSQL findings. No failed check is counted as a passed runtime test.

## Promotion readiness, unresolved concerns and next coding stage

**Ready for source review; NOT ready for automatic active promotion or execution.** Before a separately authorized promotion/testing task:

1. Ratify/split the single-revision six-table atomic lock scope, driver requirements and future bounded runner/transaction integration. Refresh graph/dependency and approve the exact source hash; do not modify active revisions as part of this task.
2. Resolve D infrastructure acceptance independently, authorize B-shaped schema-only baseline import/parity/revision establishment and preserve B's missing VEX FK plus other drift. This task did not inspect or repair D, A/B or production.
3. Review actual trigger/rule/RLS/replication inventory and all writer/role privileges, including default allocator access for runtime roles and generic copy/upsert behavior. The conservative BEFORE INSERT gate may block an otherwise legitimate target until reviewed; do not bypass it silently.
4. Execute PG16 correctness cases from the transition table, other-BEFORE-trigger interference, explicit NULL/default/wrong-version input, transactional failure/rerun/unknown outcome, schema/data/PK/FK/sequence invariance and old-writer compatibility on the approved disposable target. Validate SQL grammar and timeout parsing there; Python/SQLAlchemy checks cannot substitute.
5. Require the following unique-index stage before backfill/public issuance. This file alone neither guarantees per-table uniqueness nor completes the approved public contract.

**Next coding stage:** separately authorize six unique public_id index artifacts and a resumable NULL-only backfill runner, with exact index-state/recovery checks, concurrent-index transaction boundaries and persistent-mapping/idempotency guarantees. Do not add those operations to this expand artifact or execute them from a design/tracker update. Later CHECK validation, NOT NULL/UNIQUE attachment and API/ORM/frontend work remain separate stages.

Only the two new implementation/report files and tracker update are authorized outputs. No active Alembic revision/env, model, API, frontend, runtime/Compose configuration or earlier report was changed. Tracker status is **IMPLEMENTED (STAGED), NOT EXECUTED, NOT ACCEPTED**. D remains **NOT ACCEPTED** and W1.5 **NO-GO**; source implementation does not waive their acceptance gates.

Final verification: all 41 pre-existing modified/untracked file contents other than the authorized tracker matched their task-start hashes; tracked binary diff unchanged; all 18 prior task-ledger rows retained verbatim; 46 local evidence links/nonblank line locations checked; active 79-revision graph/head unchanged. Final AST/source assertions, Ruff lint/format and whitespace checks passed. Staged migration SHA256: `820e9500164f10431ba9fffaf14de5c67b7ca8dcda21181f0dc4d2446cb0c158`. No SQL/PLpgSQL/runtime acceptance execution is implied.
