# W1.6B — Unique-index and resumable UUID backfill implementation

2026-10-16, Asia/Kolkata. **IMPLEMENTED (STAGED), NOT EXECUTED, NOT ACCEPTED.** GO for source review only. No database connection, SQL/Alembic execution, Docker inspection/change, migration, application startup or credential access occurred. D remains NOT ACCEPTED; W1.4c remains PARTIAL and W1.5 NO-GO.

## Scope, prerequisites and Git preservation

The pasted W1.6B request authorizes offline source artifacts under staged-runner, this report and tracker update only. Required tracker, W1.1 design, W1.6A report, W1.6A.1 report, six staged revisions, active Alembic environment and pinned driver/conventions were reviewed. Prerequisites, scope, execution blockers and acceptance criteria were recorded IN PROGRESS before coding.

Branch `feat/native-user-management`; HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`. Task-start snapshot: 51 existing modified/untracked contents, including 20 modified tracked files. Only the master tracker may change among these; preserve the other 50 contents and tracked binary diff. No Git mutation/delivery or remote synchronization claim.

Only tenants, projects, products, logical_sbom, sbom_source and sbom_component are targeted. Integer PK/FK values, sequences, tenant ownership and existing business columns/indexes remain unchanged by written operations. No API/ORM/frontend/JWT/domain identifier changes, index attachment, CHECK validation or NOT NULL enforcement are included.

## Exact implementation files

All files below are new, outside active Alembic versions:

| File | Purpose |
| --- | --- |
| [create_unique_indexes.py](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/create_unique_indexes.py:1) | Separate index validation/execution entry point; concurrent full UUID unique indexes |
| [backfill_public_ids.py](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/backfill_public_ids.py:1) | Separate backfill validation/execution entry point; bounded NULL-only committed batches |
| [uuid_w1_common.py](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/uuid_w1_common.py:1) | Explicit plan/credential/file safety, local Docker/PG identity, catalog/index/trigger gates, evidence and transaction helpers |
| [d-approval.example.json](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/d-approval.example.json:1) | Nonsecret, deliberately unusable approval/input template; no actual target approval/credentials |
| [verify_offline.py](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/verify_offline.py:1) | Reproducible offline syntax/source/graph/SQL compilation verifier; never invokes either runner |

Also created this phase2/11-w1-unique-index-backfill-implementation.md and updated [MIGRATION_MASTER_TRACKER.md](/Users/ferozebasha/sbom/docs/uuid-migration/MIGRATION_MASTER_TRACKER.md:1). Staged 080–085, their archive, previous reports, active revisions/env, runtime configuration and application files are unchanged.

## Execution safety contract

Both entry points default to --mode validate. Validation still opens a future read-only authenticated D connection and reads metadata/NULL or duplicate evidence: **it is not authorized by this offline task**. Only verify_offline.py was executed here.

A future operator must supply an explicit private JSON plan and matching --approval-id. The plan must attest accepted disposable D, reviewed B-shaped baseline/expand state, writer/role/trigger review, exclusive unrelated-DDL exclusion window and dedicated secret provenance. It pins revision 085, local daemon/container/volume/network identities, database OID, cluster system identifier, server address/start time and approved schema fingerprint. Acceptance flags and distinct validate/indexes/backfill approval references are checked; approvals expire at an explicit timezone-aware UTC time. Template flags are false, approvals unset and identity/timeout fields invalid or absent by design. No live manifest was created.

These booleans/IDs are operator attestations, not cryptographic proof or a substitute for the human task authorization. Do not fill them mechanically to bypass an acceptance failure. Preparing/approving a real plan, credentials access, metadata capture and each execution phase remain separate future work.

Before any PG connection, the future runner checks the explicit user-owned local Desktop Unix socket, approved Docker Desktop CLI binary/hash and daemon identity/type. It uses only filtered Docker info/inspect/list metadata commands, with explicit --host and a small subprocess environment; no shell, resource lifecycle command or full container environment dump. D must be project sbom-uuid-w1/service postgres_d with exclusive 127.0.0.1:56041 publication, pinned container start/image/mount/network metadata, dedicated sbom-uuid-w1_d_pgdata identity/exclusive attachment and only D attached to its approved dedicated networks. It does not connect to the existing application networks or databases.

Current known D publication failure would fail these gates. The code does not fix networking, accept current D, infer isolation from database names, or certify ordinary-bridge zero egress. Network/volume/container changes require a newly reviewed plan; names alone are insufficient.

Only hardcoded loopback D connection kwargs are used: port 56041, uuid_w1_d_rehearsal, uuid_w1_d_bootstrap. No connection string, dotenv/application/launcher import, discovery or A/B fallback. Inherited libpq PG* overrides are rejected, password is explicit, passfile=/dev/null, TLS/GSS discovery is disabled for this approved loopback-only transport. Other endpoints/platforms/remote/production targets are refused; they need a separate design.

The existing dedicated D password path is required. It and the plan must be absolute, outside checkout, single-link regular non-symlink user-owned 0600 files in a non-symlink immediate 0700 private directory, opened O_NOFOLLOW. No password is generated, overwritten, printed, hashed into reports, stored in the example or passed in command arguments. The password reader is future runtime code; it was not called.

Connections start autocommit with server default_transaction_read_only=on, search_path=pg_catalog, 10s statement/1s lock/15s idle-in-transaction limits. PG identity must match the approved database/user/session user/OID/cluster, major 16, container server address/5432, postmaster start time, no recovery and session_replication_role=origin. Session metadata is checked repeatedly; no replication or trigger bypass is enabled.

## Schema-state and role verification

The sole Alembic row must be 085_uuid_sbom_component_expand. Source inspection found 79 active revisions with sole 079 head; real in-memory Alembic graph checks combine unchanged 080–085 to one 085 staged head. These runners do not run Alembic or advance/stamp any marker. They require the completed expanded schema; they do not replace W1.6A.1's future isolated one-revision-per-transaction runner.

A deterministic catalog/ACL fingerprint covers public relations/columns/defaults, constraints, existing indexes, trigger definitions/enablement, public function source/config/ACL/ownership, rules, policies, event triggers, role attributes/membership, public namespace ACL and inheritance. Only the six intended new index relations/attributes/definitions are excluded because they are checked separately during partial index progress. No business records, sequence positions or statistics enter this fingerprint. Existing integer graph definitions and B's actual drift therefore remain pinned.

The approved fingerprint must be independently captured and reviewed **after the verified 085 sequence on the accepted B-shaped D baseline**, under the runner's session/deparser conventions. Hash equality proves equality to that approved snapshot, not its semantic correctness. No snapshot, OID, schema parity or revision was discovered/approved here. Preserve B's missing VEX supersession FK and other drift; no ORM-derived repair is bundled.

Explicit checks additionally require ordinary permanent tables, no RLS on these maintenance targets, native nullable non-generated public_id with the separate core generator default, existing int4 non-NULL single id PK, SELECT/UPDATE/owner-role maintenance access, public USAGE/CREATE and allocator/guard EXECUTE. Shared function source SHA256, language/signature/invoker/volatility/search_path properties must match staged 080. Exactly the two expected enabled user triggers and no write rules are permitted per table; enabled DDL event triggers fail closed. Additional otherwise legitimate triggers/RLS/event policies need a separately reviewed compatibility/side-effect design; do not silently disable them.

Exact pg_get_triggerdef rendering expectations are intentionally strict and **not verified on PG16**. Canonical rendering, permissions for pg_control_system/catalogs, socket/CLI behavior and all SQL grammar must be checked in future authorized rehearsal; formatting differences cause a stop, not relaxed adoption.

## Unique-index implementation and autocommit boundary

| Table | Deterministic public-schema index |
| --- | --- |
| tenants | uq_tenants_public_id |
| projects | uq_projects_public_id |
| products | uq_products_public_id |
| logical_sbom | uq_logical_sbom_public_id |
| sbom_source | uq_sbom_source_public_id |
| sbom_component | uq_sbom_component_public_id |

For each table the written command is CREATE UNIQUE INDEX CONCURRENTLY with one plain public_id key and USING btree, on the quoted public-schema table. No predicate/expression/INCLUDE/NULLS NOT DISTINCT/IF NOT EXISTS or second UUID index. PostgreSQL does not permit a schema-qualified CREATE INDEX name; the schema-qualified ON target establishes the index namespace, and pre/post checks demand that namespace. Multiple NULLs retain the default distinct semantics. [PG16 CREATE INDEX](https://www.postgresql.org/docs/16/sql-createindex.html).

Execution requires an autocommit connection with TransactionStatus.IDLE, checked again directly before the DDL. No migration transaction, Alembic multi-upgrade, conn.transaction or manual BEGIN wraps CREATE INDEX CONCURRENTLY. Session default_transaction_read_only is switched off only for an authorized index attempt; session statement_timeout uses explicit reviewed index_statement_ms (1s–1h, no implicit build budget) and lock_timeout remains 1s. Read-only/default 10s metadata settings are restored if the connection is still usable/idle. Separate artifacts avoid committing unrelated Alembic work.

Before any DDL, all six schema/index states are checked and duplicate non-NULL scans plus wrong-version/variant scans must pass for all six. Duplicate queries return only booleans, not keys/UUIDs. They can require scans; timeout stops the phase rather than claiming a result or silently extending the budget. Duplicate absence is only an observation; a concurrent conflicting writer can still make the unique build fail.

Each build is preceded/followed by identity/schema/index checks. Catalog verification pins public namespace/name/OID, intended table OID/UUID attribute, B-tree uuid_ops, one key/no INCLUDE, uniqueness, validity/readiness/liveness/immediate behavior, default NULL distinction, no expression/predicate, default direction/collation/options and no primary/exclusion/constraint attachment. Unexpected additional public_id indexes or same-name relations/constraints stop the runner.

A missing index is created once. A pre-existing valid index is accepted **only with an independently reviewed OID in accepted_index_oids**, plus every definition check. Same-process successful creations are tracked in memory and logged after verification. Invalid/incomplete/mismatched indexes stop, even with a pinned OID. No drop, reindex, recreation, silent adoption or automatic retry. A fresh run after partial success requires review of actual index state/OIDs and a newly approved plan; after an unknown outcome, do not infer failure from missing local evidence.

## Backfill batching, concurrency and restart

Backfill refuses mutation unless all six required indexes are present, valid/ready and pinned by the separately approved backfill plan. Defaults: batch-size=500, max-batches=10000, max-seconds=3600, gap-sweeps=3. Bounds: batch 1–5000, max batches 1–1000000, run seconds 1–86400, gap sweeps 1–10. These are implementation limits, not measured safe production budgets.

Each run acquires the same session advisory lock as the index runner, excluding cooperating operators. It does not block arbitrary DDL owners; a reviewed no-unrelated-DDL window is mandatory. For each table:

1. Capture current MAX(id), start an in-memory cursor below int4 minimum (negative/zero IDs included), select up to batch-size NULL rows in deterministic id order within the horizon.
2. In a new explicit READ WRITE transaction on the otherwise autocommit/read-only-default connection, acquire only this table's SHARE UPDATE EXCLUSIVE NOWAIT lock. This conservatively excludes conflicting DDL/concurrent index work/vacuum while allowing ordinary DML. Recheck identity, catalog/trigger/role snapshot and all six indexes.
3. Use one materialized candidate CTE with ORDER BY id LIMIT batch FOR UPDATE; UPDATE joins on the integer id and independently rechecks target.public_id IS NULL. SET names public_id only, generated by pg_catalog.gen_random_uuid(). RETURNING internal id is aggregated to counts/max for in-memory control; no row PK/UUID or business payload is logged/exported.
4. Require selected/updated counts equal and bounded; write a precommit event, exit transaction context and log batch_committed only after COMMIT acknowledgement. Then advance the in-memory cursor. Each previous successful batch remains durable if a later one fails.
5. Recheck NULL gaps over the whole table, restart at minimum with a fresh horizon for bounded catch-up passes, including low-PK arrivals and keys beyond earlier horizons. After all tables, reverify all gates and NULL gaps again.

FOR UPDATE SKIP LOCKED was evaluated and deliberately omitted: advancing a cursor past skipped rows would require additional gap reconciliation. Ordinary row locks plus 1s lock_timeout and a stop avoid treating skipped work as completion. The repeated UPDATE predicate prevents overwriting another writer's committed UUID; normal concurrent INSERT allocation remains the existing default/guard. [PG16 SELECT row-locking semantics](https://www.postgresql.org/docs/16/sql-select.html).

Transactions have a 20s client budget checked before each SQL query/precommit, with transaction-local statement_timeout capped at the remaining budget and at 10s. Individual row/table lock waits are capped at 1s; there are bounded row counts and work-loop limits. This is not a hard real-time guarantee for network stalls/COMMIT acknowledgement/host scheduling. Catalog checks and ordered NULL selection can scan work beyond the number of returned rows; actual plans/cost remain unmeasured.

Restart deliberately trusts the **database NULL predicate**, not a disk cursor. It rescans from minimum and skips all committed non-NULL values. Durable private evidence records batch/sweep/count checkpoints and target identity, not row IDs. Interrupted transactions roll back if PostgreSQL completed rollback; ambiguous COMMIT must first be reconciled. No committed UUID is regenerated, even if a checkpoint/event was lost.

Final NULL absence is a point-in-time observation, not a new constraint or full acceptance. No business trigger disabling, ORM flush, audit timestamp SET, integer rewrite or sequence operation exists. The approved unchanged trigger inventory is part of the only-public_id-write invariant; actual side effects/content/integer equality still require synthetic runtime evidence.

## Recovery and execution evidence

Evidence is a newly created absolute 0600 JSONL file in an existing private user-owned 0700 directory outside checkout. O_EXCL/O_NOFOLLOW prevents overwrite/symlink reuse. It records UTC, approval-plan hash, runner source hashes, nonsecret container/cluster/revision identity, table/counts/sweeps, index OIDs and outcomes. No password, connection string, process environment, business row IDs/UUIDs, raw SQL exception DETAIL or full inspect data is printed. Driver/Docker exceptions are not stringified; fixed diagnostic messages and validated SQLSTATE only. Evidence failure stops, never permits continued mutation.

| Future event | Implemented response / continuation gate |
| --- | --- |
| Existing public UUID | Never in UPDATE target predicate; preserve it. Supplied v4 duplicates/invalid values stop index preflight/build; no winner rewrite |
| Concurrent assignment/update | Ordered row locks and conditional NULL UPDATE; expected counts checked inside transaction. Other ordinary writes keep integer relationships |
| Unique violation 23505 | Stop, record fixed classification/SQLSTATE, retain earlier commits. Review collision/import/copy cause; no automatic UUID rotation/retry |
| Deadlock 40P01, lock timeout 55P03, cancellation 57014 | Stop; reconcile unit/rollback and any concurrent-index remnant. No skipped rows or automatic timeout extension/retry |
| Invalid/incomplete concurrent index | Stop before backfill; manual catalog/recovery decision required, no automatic DROP/rebuild |
| Interrupted batch / process failure | Previous commits persist. Restart under renewed authorization after identity/revision/index reconciliation; rescan NULL-only from minimum |
| Connection loss / unknown COMMIT or DDL outcome | Stop without reconnect/retry. Reconcile DB/index catalogs, private events and mappings; absence of batch_committed is not proof of rollback |
| Schema/revision/trigger/role/replication change | Repeated gates fail; no stamp, constraint/trigger bypass or silent new baseline |
| Changed daemon/container/start/volume/network/cluster/server | Stop; a same-name resource or database is insufficient. Reverify accepted target and review a replacement plan |
| Partial six-index progress | Keep valid built indexes intact; verify/pin their actual OIDs before a new separately approved invocation |
| Final NULL remains / limits exhausted | Stop without success claim; committed mappings remain. Another authorized bounded pass may safely start over |

Advisory locks and catalog fingerprints are cooperative protection, not a security boundary against privileged concurrent DDL or malicious host/plan modification. Backfill locks protect its current table; shared functions/other tables still rely on approved maintenance control. No measured performance or absolute isolation guarantee is inferred.

## Future invocation contract — not executed

Use the exact reviewed sources under the repository environment only after accepted D/B-shaped 085, approved private inputs and operation-specific authority. Each command needs a fresh evidence path; plan is outside checkout, never repository .env. Placeholder example only:

```text
python -B /ABSOLUTE/REPO/infra/uuid-migration/staged-runner/create_unique_indexes.py --mode validate --plan /PRIVATE/reviewed-plan.json --approval-id VALIDATION_APPROVAL --evidence /PRIVATE/new-index-validation.jsonl
python -B /ABSOLUTE/REPO/infra/uuid-migration/staged-runner/create_unique_indexes.py --mode execute --plan /PRIVATE/reviewed-plan.json --approval-id INDEX_APPROVAL --evidence /PRIVATE/new-index-execution.jsonl
# Independently review all six actual index OIDs, approve a new backfill plan:
python -B /ABSOLUTE/REPO/infra/uuid-migration/staged-runner/backfill_public_ids.py --mode validate --plan /PRIVATE/backfill-plan.json --approval-id VALIDATION_APPROVAL --evidence /PRIVATE/new-backfill-validation.jsonl
python -B /ABSOLUTE/REPO/infra/uuid-migration/staged-runner/backfill_public_ids.py --mode execute --plan /PRIVATE/backfill-plan.json --approval-id BACKFILL_APPROVAL --evidence /PRIVATE/new-backfill-execution.jsonl --batch-size 500
```

No command above was run. These scripts remain staged review artifacts; invocation examples grant no permission.

## Static verification actually executed

| Check / command | Actual result |
| --- | --- |
| .venv/bin/python -B infra/uuid-migration/staged-runner/verify_offline.py | PASS: four Python sources parsed; dependency/source assertions; 79 active + six staged declarations in real in-memory Alembic RevisionMap; active head 079/combined 085; staged hashes and shared guard match W1.6A.1 |
| SQLAlchemy 2.0.51 offline compilation | PASS: 42 SQL templates, 14 literal query compilations, 18 rendered dynamic query compilations and six independently compiled SQLAlchemy concurrent unique-index DDL declarations. No engine/connection created or SQL executed |
| Driver / transaction APIs | Installed psycopg 3.3.4 source inspected for explicit READ WRITE transaction startup and internal char catalog decoding; pinned requirements SQLAlchemy 2.0.51/Alembic 1.18.5 checked. Current env's outer-transaction/default-loading risks remain unchanged |
| .venv/bin/python -B -m ruff check --no-cache infra/uuid-migration/staged-runner/*.py | PASS with repository E/F/I/UP/B rules |
| .venv/bin/python -B -m ruff format --no-cache --check infra/uuid-migration/staged-runner/*.py | PASS |
| git -c core.fsmonitor=false diff --check | PASS; additional new-file whitespace, evidence-link/hash/preservation checks recorded at final verification |
| PG16 grammar/DDL/query plans/catalog deparser/transactions/permissions/concurrency/invariance/recovery | NOT EXECUTED / NOT ACCEPTED |
| Application/migration/browser/performance tests | NOT RUN |

Static-harness corrections: initial global source normalization also changed the guard's six-table allowlist and gave a false assertion; replaced with target-declaration/guard-specific inspection. A formatting-sensitive diagnostic assertion was corrected to AST inspection. Ruff import/UTC style findings were fixed only in new files; the relevant checks were rerun and passed. None was a PostgreSQL result.

The offline verifier imports only the new staged modules' inert definitions and library/compiler/graph code, never their entry points, connect/Docker/credential functions, application modules or Alembic env/migrations. No bytecode/dependency install or runtime configuration change. SQLAlchemy text compilation does not parse PostgreSQL/PLpgSQL or prove execution behavior.

## Source SHA256

| New staged file | SHA256 |
| --- | --- |
| backfill_public_ids.py | e3ce6d34743b11fb655bdaaad18357531e508fca6c3f274d3bf1af99fae8fea4 |
| create_unique_indexes.py | 8dae4c18e858167da3cd211298d1f509c2adc11b391255644d536a1d0453e7b0 |
| d-approval.example.json | 5b42c40f2154eddacd2f899f150ffba2f84942b8a649b82eae8daee0f0881b2e |
| uuid_w1_common.py | 4b9ef6c1708ae8385db39c618aec10eba35e3b8e972b6de7c5a2583a6eabad94 |
| verify_offline.py | 6da51b09fc106b189b3bd885d9c9fc8b40aed1d0c5692daa2d11610ca5a3c630 |

## Unresolved gates and next stage

**Ready for source review only; execution NO-GO.** Review the strict plan/metadata/deparser contract, privileged disposable bootstrap role, query/lock budgets, schema snapshot scope, cooperating-DDL assumptions, failure evidence and restart policy before future use. No real approved manifest, index OID inventory, cluster/schema identity or execution authority exists from this task.

D publication/secret-read/authenticated/cluster/fresh-schema acceptance and W1.5 B import/parity/revision gates must pass independently. Next approve/implement the isolated 080–085 invocation integration, and review these index/backfill artifacts for future synthetic PG16 testing. Further source coding may independently prepare CHECK validation, non-null proof/NOT NULL and UNIQUE attachment using the existing indexes; choose revisions from the then-current graph, with no automatic execution.

Future acceptance matrix (all DESIGNED, NOT RUN):

| Case | Required proof |
| --- | --- |
| R1 identity rejection | Wrong port/daemon/container/volume/network/cluster/database/revision/expired approval/template must stop before mutation; no A/B/remote contact |
| R2 catalog/role enforcement | Wrong type/default/CHECK/trigger/body/search_path/RLS/ACL/rule/event/index state fails; strict deparser behavior confirmed |
| R3 concurrent index | Actual AUTOCOMMIT PG16 builds full B-tree, default multiple NULLs, proper OID/table/valid/ready/live state; duplicate race and lock/cancellation remnant handled |
| R4 partial index restart | Valid unpinned index stops; reviewed exact pinned valid index continues; invalid/mismatched/extra index never adopted/removed |
| R5 NULL-only data | Mixed NULL/pre-existing UUIDs, negative/zero/gapped IDs and inactive tenants: all committed mappings stable; old fields/PK/FK/sequence definitions unchanged |
| R6 concurrency/gaps | Contended row locks, writer assignments, low/high-PK inserts and repeated sweeps neither overwrite nor skip unresolved NULLs |
| R7 batch recovery | Kill before commit/after commit/before evidence, disconnect during commit and repeated execution: reconcile outcomes and retain prior mappings |
| R8 failure budgets | 23505/40P01/55P03/57014, time/batch/evidence failures stop without automatic retry, privilege relaxation or unrelated changes |
| R9 writer/side effects | Legacy/direct SQL/COPY/upsert/clone writers preserve intended identity; no timestamp/audit/lifecycle/business changes due to backfill |
| R10 final boundaries | Final NULL absence is independently verified; no NOT NULL/validation/index attachment or public issuance is claimed early |
| R11 measurements | Measure catalog/Docker verification overhead, bounded scan plans, buffer/WAL/storage, lock waits, batch/insert throughput and p50/p95 on synthetic scale; no results invented |
| R12 preservation | A/B/shared infrastructure untouched; actual B drift remains; approved snapshot/data equality and integer-join behavior verified on D only |

W1.6B remains IMPLEMENTED (STAGED), NOT EXECUTED, NOT ACCEPTED. No unrelated issue or infrastructure blocker is closed.

Final verification: branch/HEAD unchanged; all 50 pre-existing file contents except the authorized tracker matched task-start hashes, including staged 080–085 and prior reports. Tracked binary diff unchanged; all 20 historical ledger rows and 12 Phase 1 open-issue rows retained verbatim. Exactly six new files (five staged-runner artifacts plus this report) and tracker update only. All five artifact hashes, 43 local report/tracker links and whitespace checked. Offline verifier, repository Ruff lint and format checks rerun successfully. No runtime acceptance implied.
