# W1.6A.1 — Per-table UUID expand transaction refactor

2026-10-16, Asia/Kolkata. **IMPLEMENTED (STAGED), NOT EXECUTED, NOT ACCEPTED.** GO for source review only; NO-GO for promotion/execution until the gates below pass. D remains NOT ACCEPTED; W1.4c PARTIAL and W1.5 NO-GO. No database connection, SQL execution, migration invocation, Docker command or application startup occurred.

## Baseline, scope and historical preservation

Read the master tracker, full W1.1 design, W1.6A implementation report/source, active env.py and current revision declarations. W1.6A.1 prerequisites, blockers, scope and acceptance criteria were recorded IN PROGRESS before source changes.

Verified branch `feat/native-user-management`, HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`. Task-start snapshot: 44 existing modified/untracked file contents (20 modified tracked, 24 untracked). Authorized existing edits are this tracker and staged 080 only; preserve the other 42 contents and tracked binary diff. Git status initially emitted a filesystem-monitor daemon warning; subsequent Git reads use `-c core.fsmonitor=false`, without changing repository configuration. No remote refresh or synchronization claim.

The old six-table revision is preserved byte-for-byte at [archive/080_uuid_public_id_expand.w1_6a.py.txt](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/archive/080_uuid_public_id_expand.w1_6a.py.txt:1), SHA256 `820e9500164f10431ba9fffaf14de5c67b7ca8dcda21181f0dc4d2446cb0c158`. Its .py.txt extension deliberately excludes it from Python revision discovery; never promote the archive. The prior [W1.6A report](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/09-w1-six-table-expand-implementation.md:1) and tracker completion record remain historical evidence of that original artifact; their original source line references describe the archived version, not today's refactor.

080 retains its staged filename/revision identifier but now expands **tenants only**. This is a refactor of source recorded as never registered/executed, not permission to edit an applied revision. If any target is found to have applied/stamped the original monolith, STOP: revision 080 alone cannot distinguish the two definitions. Reconcile source hashes, catalog state and execution provenance manually; do not apply this chain, stamp, overwrite or adopt objects automatically.

## Actual revision files and dependencies

AST inspection and Alembic's in-memory RevisionMap found 79 active revisions and sole head [079_lifecycle_provider_verification](/Users/ferozebasha/sbom/alembic/versions/079_lifecycle_provider_verification.py:9). Combining the six staged declarations gives one linear successor chain with head 085; active registration remains unchanged. No staged file imports another staged file or external migration helper.

| Staged source / revision | Immediate predecessor | Sole business table changed |
| --- | --- | --- |
| [080_uuid_public_id_expand.py](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/080_uuid_public_id_expand.py:15) | 079_lifecycle_provider_verification | public.tenants; also creates shared guard function once |
| [081_uuid_projects_expand.py](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/081_uuid_projects_expand.py:15) | 080_uuid_public_id_expand | public.projects |
| [082_uuid_products_expand.py](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/082_uuid_products_expand.py:15) | 081_uuid_projects_expand | public.products |
| [083_uuid_logical_sbom_expand.py](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/083_uuid_logical_sbom_expand.py:15) | 082_uuid_products_expand | public.logical_sbom |
| [084_uuid_sbom_source_expand.py](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/084_uuid_sbom_source_expand.py:15) | 083_uuid_logical_sbom_expand | public.sbom_source |
| [085_uuid_sbom_component_expand.py](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/085_uuid_sbom_component_expand.py:15) | 084_uuid_sbom_source_expand | public.sbom_component |

All have branch_labels=None and depends_on=None. PostgreSQL trigger names remain table-local; constraint/function/table operations use the public schema and schema-qualified core functions/operators/types. Source identifiers are fixed literals, never supplied by a caller. Alembic's own revision-marker update is expected metadata, separate from the one business-table delta.

## Preserved behavior and new shared-function checks

[080 upgrade](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/080_uuid_public_id_expand.py:190) and [081 upgrade](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/081_uuid_projects_expand.py:192) illustrate the identical table-scoped sequence:

1. Refuse SQL-output mode, non-PostgreSQL dialect, nontransactional DDL, missing active transaction or driver autocommit.
2. Apply transaction-local timeout caps, preserving stricter caller limits: lock_timeout at most 1s, statement_timeout at most 10s. These are per-statement limits, not an entire-unit deadline.
3. Acquire ONLY the target table in ACCESS EXCLUSIVE MODE NOWAIT. Run target-only catalog checks.
4. In 080 only, create the shared guard. In later revisions, verify its exact body, zero-argument trigger-return signature, PL/pgSQL language, volatile/invoker/non-strict/non-set/non-leakproof/parallel-unsafe properties, sole same-name definition, search_path configuration and migration-role EXECUTE access. Missing/altered/overloaded functions fail; none is replaced or recreated.
5. Add nullable native PostgreSQL UUID public_id without Column/default/server_default. Separately set INSERT default to pg_catalog.gen_random_uuid().
6. Add ck_T_public_id_v4 CHECK allowing NULL or canonical v4/variant text, NOT VALID. Install BEFORE INSERT allocator and conditional AFTER UPDATE immutable guard before committing.

The [shared guard](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/080_uuid_public_id_expand.py:150) is unchanged from W1.6A, including its six-table/event allowlist, SECURITY INVOKER and search_path=pg_catalog. It only assigns NEW.public_id for explicit NULL INSERT; it never writes business/audit/timestamp/tenant/lifecycle fields or queries business tables. Its source is embedded as an exact expected catalog value in later preflights, not imported or executed there. Future intentional edits to this function require a new reviewed version; do not relax equality checks to accept a changed definition.

| Operation / row state | Written behavior |
| --- | --- |
| INSERT, public_id omitted | Separate database default generates UUIDv4 |
| INSERT, explicit NULL | BEFORE INSERT assigns UUIDv4 |
| INSERT, supplied native valid v4 | Retained; CHECK verifies version/variant. Controlled import may preserve identity; API caller identity selection remains disallowed by future API work |
| INSERT or first NULL-to-value UPDATE, invalid type/version/variant | UUID cast or CHECK must reject; PostgreSQL execution not tested here |
| UPDATE, old non-NULL → other UUID/NULL/DEFAULT | AFTER UPDATE rejects actual reassignment/removal with generic integrity error |
| UPDATE, old NULL → valid UUID | Permitted for later NULL-only backfill |
| UPDATE, identical UUID, NULL → NULL or unrelated values with same UUID | No immutability trigger event queued; transitional NULL remains allowed |
| Downgrade | Every file raises before any operation; no mapping/object deletion |

AFTER UPDATE uses WHEN (OLD.public_id IS DISTINCT FROM NEW.public_id), never UPDATE OF public_id. The predicate sees the row after BEFORE UPDATE triggers; a change by such a trigger still queues validation. This preserves correctness while avoiding guard events for unchanged identity. It is not a measured optimization. [PostgreSQL 16 trigger timing and WHEN](https://www.postgresql.org/docs/16/sql-createtrigger.html).

Existing integer PK/FK columns, constraints/actions, sequences and all pre-existing business columns remain untouched by written operations. There is no row UPDATE/backfill, unique/index build, CHECK validation, NOT NULL enforcement or API/ORM change. Object-collision detection is implemented; **random/supplied UUID duplicate prevention is not yet implemented**. No public issuance is permitted before later uniqueness/enforcement/contract acceptance.

## Transaction boundary: exact future execution requirement

[env.py:50](/Users/ferozebasha/sbom/alembic/env.py:50) configures the connection without transaction_per_migration, then opens one outer begin_transaction around run_migrations. Installed Alembic 1.18.5 defaults transaction_per_migration=False; inspected runtime/migration.py:145, :372–455 and :615–638 show that per-step transaction contexts do not independently commit under that outer transaction. DDL and the step's revision-marker change occur within the enclosing transaction. **An invocation upgrading 079 directly to 085/head would therefore hold all six table locks until one final commit. It is prohibited by this design.** See [Alembic transaction API](https://alembic.sqlalchemy.org/en/latest/api/runtime.html#alembic.runtime.migration.MigrationContext.begin_transaction); installed pinned source governs over newer online documentation.

Required future method: six separate process/connection invocations, each with exactly one pending next revision from its verified immediate predecessor. Each invocation owns its outer transaction, completes normally, commits and closes before the next starts. No external transaction, shared open connection, multi-revision target, range upgrade, upgrade head, autocommit block or manual commit inside upgrade. The written guards verify a real transaction but cannot themselves prove that an operator did not select several revisions; enforcing the one-step invocation contract is a runner/promotion acceptance gate.

The following is a **future command contract, NOT executed**. /ABSOLUTE/APPROVED_D_ONLY/alembic.ini is a placeholder for a separately reviewed isolated runner/config, not a file created here:

```text
# Start only from independently verified single revision 079 and matching schema.
alembic -c /ABSOLUTE/APPROVED_D_ONLY/alembic.ini upgrade 080_uuid_public_id_expand
# Verify committed 080 and its complete delta; new process/connection:
alembic -c /ABSOLUTE/APPROVED_D_ONLY/alembic.ini upgrade 081_uuid_projects_expand
# Verify committed 081 before proceeding:
alembic -c /ABSOLUTE/APPROVED_D_ONLY/alembic.ini upgrade 082_uuid_products_expand
# Verify committed 082 before proceeding:
alembic -c /ABSOLUTE/APPROVED_D_ONLY/alembic.ini upgrade 083_uuid_logical_sbom_expand
# Verify committed 083 before proceeding:
alembic -c /ABSOLUTE/APPROVED_D_ONLY/alembic.ini upgrade 084_uuid_sbom_source_expand
# Verify committed 084 before proceeding:
alembic -c /ABSOLUTE/APPROVED_D_ONLY/alembic.ini upgrade 085_uuid_sbom_component_expand
# Verify committed 085 and all six deltas; no index/backfill automatically follows.
```

Future configuration must select only reviewed/promoted revision sources, an accepted/authorized D endpoint and a minimal environment without dotenv discovery/application imports/startup. With transaction_per_migration=False, its one outer transaction must contain only that single revision and marker update. No predecessor bootstrap or unrelated pending revision is allowed. Do not point these placeholder commands at the existing root config: [env.py:7](/Users/ferozebasha/sbom/alembic/env.py:7) loads dotenv, imports app/db and has a fresh-install head bootstrap branch. This task neither changes that environment nor provides/approves the isolated runner. Changing to transaction_per_migration=True might support other future orchestration but is not implemented or assumed here; external transactions still require review.

## Lock scope and remaining dependencies

Each revision explicitly locks just its own ordinary permanent, non-inherited target. First 080 additionally creates a schema-level function; later units only read its catalogs before attaching their own triggers. No earlier/later business table appears in a LOCK statement or operation target. The function's table-name allowlist does not lock those tables.

ACCESS EXCLUSIVE lasts until the single-table invocation commits/rolls back, not until upgrade returns. ONLY avoids descendant locks; preflight rejects partitions/inheritance rather than expanding to them. NOWAIT prevents waiting for the initial target lock; it does not bound every subsequent catalog/object lock. [PostgreSQL 16 LOCK](https://www.postgresql.org/docs/16/sql-lock.html).

Additional dependencies remain **UNVERIFIED on PG16**: catalog/namespace/function/type dependency locks, locks associated with CREATE TRIGGER/ALTER TABLE and Alembic's version table, existing indexes/TOAST or schema/event-trigger effects, concurrent DDL and any FK-dependent relation locking required by the actual schema. No FK alteration is requested, but this is not proof that PostgreSQL acquires no incidental relation/object locks. Inventory event triggers too: these execute on DDL and are outside this table-trigger preflight. Capture actual lock sets, timing and integer-graph invariance in a separately approved D rehearsal. Use one migration operator; DDL owners could change a shared function between verification and use, and a table lock is not a global DDL-authorization barrier.

## Partial-chain safety and reconciliation

A committed prefix is intentional: e.g. 080–082 means tenants/projects/products are expanded, the other three are not. Internal integer joins/writers remain the contract. Expanded tables allocate UUIDs on new rows; existing NULLs remain until later backfill. Keep committed mappings and guards in place; do not roll back a prefix by dropping columns or regenerating UUIDs.

| Observed future state | Required action |
| --- | --- |
| Current unit failed with known transaction rollback | Its DDL and marker should both be absent; earlier committed prefix remains. Independently verify last committed marker and exact delta before a bounded, separately permitted retry of only the next revision |
| Exact marker and object definitions match expected committed prefix | Verify identity, earlier object definitions/trigger enablement/function/grants, hashes, absence of unexpected later objects and next table preconditions; continue only from the immediate successor in a new invocation |
| Connection lost / COMMIT result unknown | Stop automatic progression. Reconnect only under execution authorization; reconcile version row, target catalogs and execution logs. If committed, advance without rerunning; if proved rolled back, retry next unit. Never infer outcome from process exit alone |
| Marker ahead but expected objects missing/altered; objects ahead of marker; multiple/missing markers; shared guard missing/changed | Manual intervention and reviewed recovery required; no stamp, IF NOT EXISTS adoption, CREATE OR REPLACE, cleanup/CASCADE or UUID reset |
| Any evidence old monolithic 080 was executed | STOP: same revision identifier is ambiguous; compare exact historical hash/schema/provenance and design new recovery/revision bookkeeping separately |
| Mid-chain concurrent writes/new UUIDs | Preserve all committed mappings; no public issuance or backfill/index work merely because expand partially succeeded |

Same-name public_id/CHECK/trigger objects are rejected even if superficially compatible; 080 rejects any same-name guard overload. No rerun silently treats a partial installation as success. Under the required transaction a unit failure is intended to roll back that unit completely; PostgreSQL failure/COMMIT/marker atomicity still needs execution evidence. Transaction-local limits reset at the invocation's transaction end.

## Writer, trigger and privilege assumptions

Static search of active migrations, scripts/schema and app Python/SQL found no relevant CREATE TRIGGER/CREATE RULE/replication-bypass/SQL role-grant declarations. The earlier writer inventory remains [W1.1 model/default/write paths](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/02-w1-additive-schema-design.md:65). Absence from these files is not a live catalog/ACL inventory or proof that deployment SQL/dynamic/external writers do not exist.

| Assumption / risk | Source behavior / future evidence required |
| --- | --- |
| Existing BEFORE INSERT triggers | Each unit fails if any user BEFORE INSERT trigger is present, including disabled/statement-level ones. Review separately; a later trigger could erase allocated UUID while NULL is allowed. Do not bypass the rejection or disable business triggers |
| Existing write rules | Each unit rejects non-SELECT pg_rewrite entries on its target. Actual rules/views/import routes still require catalog/writer review |
| BEFORE UPDATE / other DB triggers | Final-row AFTER predicate protects reassignment, but does not certify timestamp/audit/lifecycle invariance of other triggers. Future backfill must inventory and verify their side effects; no trigger disabling |
| Migration role | PG16 allocator EXECUTE is checked; actual ownership/ALTER/CREATE/schema USAGE/TRIGGER/language privileges and absence of unexpected event triggers require target review; insufficient rights fail the transaction |
| Runtime writers | Must have needed schema/type/allocator access, normal trigger execution, and no DDL-owner/superuser/replication bypass. No runtime ACL/role/replication check was executed here; written guard is not an absolute barrier against privileged actors |
| User-supplied valid UUID | Database accepts v4 for trusted restore, including PostgreSQL-accepted alternative input spellings canonicalized by the type. API create must later reject caller-selected identity; uniqueness, controlled restore and historical hard-delete non-reuse policies remain open |
| COPY, INSERT SELECT, upsert, clone/reflected writers | Ordinary defaults/triggers intended to cover legacy omitted columns and explicit NULL. INSERT ON CONFLICT that copies excluded.public_id into an existing mapped row must fail rather than rotate identity. Rehearse actual writer privileges, returning/bulk behavior and copy semantics later |
| Replication, RLS, concurrent schema changes | Not inspected live or certified. Replication trigger suppression can defeat INSERT/UPDATE protection; runtime roles must not control bypass. Keep maintenance target/tenant authorization and the integer graph unchanged |

## Static checks actually executed

| Check | Result and boundary |
| --- | --- |
| Python syntax | PASS: ast.parse all six staged sources and archived original, no imports/upgrade calls |
| Alembic revision graph/dependencies | PASS: AST declarations in 79 active files; instantiated real in-memory Alembic Revision/RevisionMap objects; sole active 079, six consecutive predecessors, sole combined 085, no missing/duplicate revisions; identifiers <=32. No CLI/env load |
| Source assertions | PASS: exact ordered targets, one ADD/ONLY lock/no table loop per file, PG16/table/PK/collision/rule/INSERT-trigger gates, same timeout/regex/guard body as archive, exact shared guard expectations in later units, nullable/native/no column default, conditional AFTER UPDATE, no external helpers/index/backfill/NOT NULL/destructive cleanup, raise-only downgrade; object names <=63 |
| SQLAlchemy offline compilation | PASS: 43 text fragments (timeouts, locks, preflights, one function and table DDL) without bind placeholders, six CreateColumn outputs exactly public_id UUID. SQLAlchemy 2.0.51; no engine/connection, staged module import or SQL execution |
| UUID pattern samples | PASS in Python: representative v4/variant valid case, wrong-version and wrong-variant rejection; canonical regex unchanged. This is not PostgreSQL casting/CHECK verification |
| Pinned transaction API inspection | Installed Alembic 1.18.5 runtime source plus active env inspected statically; no Alembic execution |
| Ruff lint | PASS: .venv/bin/python -B -m ruff check --no-cache --isolated infra/uuid-migration/staged-alembic/*.py; narrower E9,F63,F7,F82 check also passed |
| Ruff format | PASS after formatting six allowed staged Python files: .venv/bin/python -B -m ruff format --no-cache --check infra/uuid-migration/staged-alembic/*.py |
| Whitespace / preservation | git -c core.fsmonitor=false diff --check passed; final file-hash, prior-ledger/open-issue and report checks recorded below |
| PostgreSQL grammar/runtime, actual locks, privilege/writer/concurrency/rollback behavior | NOT EXECUTED; SQLAlchemy text compilation does not parse PostgreSQL/PLpgSQL or prove runtime correctness |
| Application/migration/browser/performance tests | NOT RUN |

No tests against a database, SQL parser, application or Docker were executed. No dependency was installed. Existing active env/revision/config/model/API/frontend files and previous reports remain unchanged.

## Source hashes and exact file delta

SHA256 values after formatting:

| Staged file | SHA256 |
| --- | --- |
| 080_uuid_public_id_expand.py (refactored) | 2fc6e6f9992d0763ddf6818b9e7b62d573eef2b7cda01a39689b8fffcbc623f8 |
| 081_uuid_projects_expand.py (new) | 28f803f5c5c439f1ae0f0fdb0748368b244c2c31b060bb1a61ff6302a3d2d95e |
| 082_uuid_products_expand.py (new) | 76d830f79e699cbdd5116c1e848cc5923f10281a764a17f0abd6c1cf8c4b5ace |
| 083_uuid_logical_sbom_expand.py (new) | d7f8dbe4c262f4a045572c173b7fd61e38d003fa87f9ec28093427161234495e |
| 084_uuid_sbom_source_expand.py (new) | 13a84b0d6d3201a64be7ba90a32560a5c5738a319be1fc8af29d2364aec49803 |
| 085_uuid_sbom_component_expand.py (new) | 45f331390609e52ceddbf0968651b5ec817bf26811f6f67845d1fb6d99cdbb0f |

Exact authorized delta: refactored staged 080; five new staged 081–085 Python files; one byte-preserved archive .py.txt; this new phase2/10-w1-expand-transaction-refactor.md; updated master tracker. No active Alembic registration. The original monolith hash above is historical, not the new 080 hash.

## Readiness and next action

**Ready for source review, not automatic promotion or execution.** The multi-table explicit lock source has been replaced with single-table units; the actual transaction-granularity acceptance gate remains open until the one-step runner and real commits/lock release are verified.

Before future execution: review/hash approve all six sources, refresh active graph, prove no original 080 application, implement/review isolated one-step runner, accept/authorize D and B-shaped baseline/parity, review triggers/rules/event triggers/roles/writers and execute synthetic PG16 correctness/lock/failure/recovery checks. Preserve B's missing VEX supersession FK and all unrelated drift; no repair is bundled.

Next separately authorized coding stage: concurrent unique-index artifacts after refreshed staged head 085, then resumable NULL-only backfill. Validate index state before backfill; retain permanent UUID mappings and integer joins. Later validation/enforcement/API work remains separate. No uniqueness/backfill stage is included or accepted here.

Final verification: branch/HEAD unchanged; all 42 other pre-existing file contents and tracked binary diff matched task-start hashes; 19 historical completed-task rows and all 12 Phase 1 open-issue rows retained verbatim. Seven new files and two authorized existing-file edits only. Original archive hash and all six current source hashes matched this report; 50 local links/nonblank line locations across report/tracker and whitespace checks passed. Full isolated Ruff lint/format passed again. Status remains IMPLEMENTED (STAGED), NOT EXECUTED, NOT ACCEPTED; D NOT ACCEPTED and W1.5 NO-GO.
