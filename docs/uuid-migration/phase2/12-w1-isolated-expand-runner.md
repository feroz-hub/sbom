# W1.6C — Isolated one-step Alembic expand runner

2026-10-16, Asia/Kolkata. **IMPLEMENTED (STAGED), NOT EXECUTED, NOT ACCEPTED.** Offline/source-review GO only; runtime execution NO-GO. D remains NOT ACCEPTED, W1.4c PARTIAL and W1.5 NO-GO. No database connection, SQL execution, Docker command, Alembic migration execution, credential access or application startup occurred.

## Scope and baseline

Required tracker, W1.6A.1 transaction refactor, W1.6B report, actual six staged 080–085 sources, actual W1.6B runners/common/offline verifier, current active revision declarations and root env/config reviewed. Prerequisites, blockers, scope and acceptance criteria recorded IN PROGRESS before implementation.

Branch feat/native-user-management; HEAD 2f48ff835d9e692fc84b31aaa951aad2495888ac. Task-start snapshot contains 57 existing modified/untracked files, including 20 modified tracked files. Only the tracker may change among them; all other 56 contents, existing staged migrations/W1.6B files/prior reports and tracked binary diff must remain intact. No branch/ref/network/Git delivery change.

Exact files created:

- [expand_one_step.py](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py:1): standalone isolated offline/connected validation/one-step execution integration.
- [test_expand_one_step.py](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/test_expand_one_step.py:1): non-database unittest/mocked lifecycle/source checks.
- docs/uuid-migration/phase2/12-w1-isolated-expand-runner.md (this report).

Updated [MIGRATION_MASTER_TRACKER.md](/Users/ferozebasha/sbom/docs/uuid-migration/MIGRATION_MASTER_TRACKER.md:1) only. No active registration or modification of staged 080–085, W1.6B source, root env/config or application files.

## W1.6B source review — findings and disposition

These findings come from source inspection, not a runtime incident or PostgreSQL test. No W1.6B code was modified. Proposed fixes require separately authorized work; none is silently claimed fixed.

| ID / classification | Exact source and finding | W1.6C disposition / remaining action |
| --- | --- | --- |
| C-B01 — confirmed integration incompatibility | [load_plan:98](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/uuid_w1_common.py:98) and [verify_identity:413](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/uuid_w1_common.py:413) require completed 085; common Evidence records constant REVISION=085. These are correct for index/backfill but unusable for intermediate expand states | Do not call these fixed-085 helpers. Separate expand manifest/prefix/marker verifier and evidence implementation; reuse only reviewed local identity SQL, Docker, private-file/connection/catalog primitives |
| C-B02 — confirmed evidence resource-handling defect | common Evidence opens its stream then emits the first event; if that emit/fsync fails before constructor completion, [guarded_main:600](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/uuid_w1_common.py:600) never receives the object and cannot explicitly close it | New expand Evidence closes on initialization failure; old source unchanged. W1.6B needs a separate repair/test request. Failure occurs before its database mutation, but descriptor/partial-evidence handling is incomplete |
| C-B03 — confirmed failure-reporting weakness | [index runner](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/create_unique_indexes.py:1) resets session settings in finally after an index attempt. A reset error can mask the original build error/SQLSTATE; autocommit index state may already be persistent | New expand runner has separate phase-based commit/outcome classification and no such autocommit DDL/reset path. Existing index recovery still requires independent catalog reconciliation; fix masking separately before index acceptance |
| C-B04 — confirmed manifest type-validation gap | common load_plan checks system_identifier.isdigit and database_oid > 0 without exact positive-int type enforcement; Python True passes the latter. Several malformed values raise incidental exceptions rather than a manifest-specific diagnostic | New expand parser enforces exact integer port/database OID, string/hash shapes and distinct action references. Old parser remains unchanged; this is robustness/explicitness, not evidence of bypassing the later actual PG identity gate |
| C-B05 — confirmed run-budget limitation | [backfill:68](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/backfill_public_ids.py:68) checks max-seconds/max-batches only before a candidate batch. Metadata/Docker/final gap checks and commit/network acknowledgement are outside a hard total deadline | Retain as an explicit unmeasured limit; future budget/failure tests or separately reviewed hard deadline needed. Not reused as the expand transaction controller |
| C-B06 — unverified rendering/approval assumptions | [verify_schema:435](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/uuid_w1_common.py:435) uses strict pg_get_triggerdef text and snapshot equality; v4 CHECK is separately checked by name presence, with semantics entrusted to the approved fingerprint | New prefix verifier explicitly checks CHECK type/unvalidated expression plus exact guard/trigger behavior. Deparser compatibility and snapshot correctness still need approved PG16 validation; never relax checks automatically |

Also inspected: exact index validity/readiness/liveness/opclass/NULL semantics/OID/no-silent-adoption checks; explicit autocommit index boundary; backfill NULL predicates/row locks/independent transactions; evidence counts and exception suppression; interrupted/unknown outcome paths. Those source contracts remain unexecuted. No unsafe incompatibility in the reused identity/connection primitives was found that blocks offline construction; they are pinned by common source SHA256 4b9ef6c1708ae8385db39c618aec10eba35e3b8e972b6de7c5a2583a6eabad94. This does not grant W1.6B runtime acceptance.

## Isolated graph and source loading

[discover](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py:63) demands exactly six root staged Python files, rejects symlinked/missing/modified files, and compares each embedded reviewed SHA256 against W1.6A.1 report evidence. All six pinned hashes are unchanged. Verified bytes are retained in memory; the future execution compiles only the selected verified bytes, avoiding a later filesystem substitution of that staged file.

Active declarations are read through AST only: 79 unique revisions, sole actual head 079_lifecycle_provider_verification and full ancestry verified with Alembic RevisionMap. Active revision source is never imported or executed. A synthetic in-memory 079 boundary node plus the six staged declarations establishes the isolated 079→080→081→082→083→084→085 graph. The synthetic boundary represents an independently verified already-applied schema; it does not implement or run earlier migrations.

[next_only](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py:123) accepts only the immediate successor of the current marker. It rejects head/heads, ranges, lists, comma-separated requests, skipping, rerunning and out-of-order steps. The connected manifest must pin the same current and explicit next revision. An in-process attempt guard prevents executing another revision in that process; a fresh invocation is required.

No ScriptDirectory/environment traversal, command.upgrade, downgrade/stamp or active config execution is used. The future selected module has only the exact reviewed inert imports/definitions until its single upgrade function is invoked under Operations.context. No SQL-output mode is offered as execution evidence.

## Target authority and prefix reconciliation

Three modes:

| Mode | Implemented behavior / authority |
| --- | --- |
| offline (default) | Local source/hash/AST/in-memory graph checks only; refuses runtime inputs. No password, Docker, database, evidence file or target manifest read. Executed during this task |
| validate | Requires explicit private target plan, expand_validate approval, next revision and new private evidence path. Future authenticated read-only local D connection validates current committed prefix and approved fingerprint; no DDL/marker change. NOT RUN; needs separate target-specific authority |
| execute | Requires independently matching expand_execute approval and all target/state gates; one selected DDL transaction, close, then independent read-only committed-state verification. NOT RUN; needs explicit D execution authority |

No real approval manifest was created. Future expand-plan fields are deliberately a different contract from W1.6B: target/disposable/accepted, baseline_reviewed, writers_and_privileges_reviewed, exclusive_ddl_window_reviewed, disposable_secret_provenance_reviewed, old_monolith_excluded; fixed D endpoint/name/user/password-file path; exact daemon/container/volume/network/cluster/database OID/server address/start time and metadata hashes; current_revision/next_revision/schema_sha256/prefix_review_reference; timezone-aware expiry; distinct approvals.expand_validate and approvals.expand_execute. Flags must be true and metadata/reference/hash types valid before connection. These attestations are operator approval records, not cryptographic proof.

A/B, 55439, remote/production endpoints, missing/changed identities and inherited libpq PG* overrides are refused. Reuse W1.6B's explicit local Desktop CLI/socket/daemon/container/publication/storage/network checks and dedicated outside-checkout 0600 password reader, with small subprocess environment and fixed loopback PG kwargs. No root .env, .env.dev.local, launcher, settings or application engine fallback. No connection string/password/raw driver error is printed.

[verify](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py:361) checks expiry, local Docker identity, independently matching PG16 database/user/cluster/session and exactly one recognized Alembic marker; then validates the entire committed prefix. It fingerprints all public catalog objects/ACLs using common snapshot queries with **no UUID-index exclusion**. The independently approved current-prefix hash must match before mutation.

For each prefix table, require ordinary permanent non-RLS shape, expected nullable native UUID/default/integer PK and maintenance rights, exact shared function body/properties, unvalidated v4/variant CHECK expression and two enabled expected triggers. Future/unexpanded tables must have no public_id/proposed CHECK/user triggers; write rules or enabled event triggers are refused. These conservative conditions can reject a legitimate target pending review.

Old monolithic 080 is not adopted: any objects ahead of the declared marker stop the runner. A manifest additionally must attest independent historical-source/provenance exclusion. Revision 080's identifier alone cannot distinguish history; if the original monolith was ever applied/stamped, STOP and design recovery separately. No script can prove historical nonexecution solely from current catalogs.

Before/after [delta comparison](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py:373) permits one new public_id attribute, one named CHECK and two triggers on only the selected table, plus the shared function only in 080. Every old captured catalog row remains unchanged; all other sections remain identical. No UUID index, unrelated business constraint or drift repair is allowed. Post-state semantic prefix checks verify new definitions; no business rows/UUID mappings are read/exported.

The captured snapshot is not complete PostgreSQL parity or logical-data proof: it reuses W1.6B's specified public catalog scope, not every global object/extension/storage property. B's missing VEX FK and other actual drift must remain pinned in the independently reviewed baseline; real schema/data/PK/FK invariance remains a future gate.

## One-revision transaction lifecycle

[apply_revision](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py:408) and [execute_step](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py:449) implement:

1. Reverify local Docker before any PG contact. Open only the fixed D connection via common.connect, whose initial session is autocommit/read-only-default. Verify PG identity before SQLAlchemy dialect initialization or migration writes.
2. Set the owned psycopg connection to autocommit=False and read_only=False, then wrap it with a new private SQLAlchemy PostgreSQL engine using NullPool, echo=False and hide_parameters=True. The engine URL contains no credentials; creator supplies only the explicit reviewed D connection. This engine is neither the application engine nor root Alembic engine.
3. Require no existing SQLAlchemy transaction, then own exactly one connection.begin context for the migration unit. Take the shared cooperating-runner session advisory lock and a NOWAIT EXCLUSIVE lock on public.alembic_version. Reverify marker, prefix and approved catalog fingerprint inside this transaction.
4. Create an isolated Config() with no filename/root environment discovery and MigrationContext configured for transactional_ddl=True, as_sql=False, transaction_per_migration=True and public version schema. Require actual PostgreSQL, active transaction and driver autocommit=False. Operations.context binds alembic.op to this context only.
5. Invoke exactly one hash-pinned upgrade function. Change public.alembic_version through an explicit bound conditional UPDATE from verified current to next, requiring rowcount exactly one. This is part of the same transaction, not a stamp or manual out-of-transaction revision change. No Alembic earlier migration traversal occurs.
6. Verify next prefix and narrow catalog delta before commit. Persist a precommit event; exit the transaction context and record commit_acknowledged only after acknowledgement. Close the physical connection through NullPool and dispose the private engine.
7. Open a **new read-only-default connection**, reverify Docker/PG identity, next marker, prefix and the same narrow delta; close it before emitting committed_verified_closed and returning success. Save the resulting catalog hash for independent review, not automatic next-step approval.
8. Before the next revision, an operator must independently review the committed prefix/hash/evidence and approve a new current/next manifest. Launch a fresh process with fresh connections. The runner never loops through six revisions or automatically advances.

There is one committed migration-unit transaction per invocation. Connection setup/dialect initialization and separate metadata verification may involve their own read transactions; they are not extra revision execution. transaction_per_migration=True alone is not relied on to bound work: the explicit single upgrade call and owned outer transaction enforce the unit. Existing staged timeout/ONLY target lock/default/CHECK/identity semantics and fail-closed downgrades remain unchanged.

Pinned Alembic 1.18.5 source inspected for Operations.context, PostgreSQLImpl.transactional_ddl=True and HeadMaintainer._update_version conditional update/rowcount behavior. No private HeadMaintainer mutation API or normal env.run_migrations is called. SQLAlchemy/psycopg transactional DDL, actual implicit BEGIN behavior and marker atomicity need PG16 proof; mocked lifecycle assertions cannot establish them.

## Failure and recovery contract

| Phase / event | Written outcome / required action |
| --- | --- |
| Source/hash/graph/manifest failure | Refuse before connection/migration; no fallback or source adoption |
| Connected marker/schema/guard/identity mismatch | Stop without migration/continuation; inspect exact target/provenance, never stamp |
| Migration SQL/lock timeout/prefix/delta error inside unit | SQLAlchemy context attempts rollback, closes connection; ROLLBACK_REQUIRES_CONFIRMATION. Do not claim rollback completed if connection is lost |
| Connection lost before commit | No automatic reconnect/retry; reconcile current marker/catalog and transaction outcome under separate authority |
| Exception during commit acknowledgement | UNKNOWN_COMMIT_STOP; committed or rolled back cannot be inferred from absent evidence. No automatic retry |
| Acknowledged commit but evidence/close/read-back/delta verification fails | COMMITTED_NOT_VERIFIED; keep mappings/schema, stop. No rollback/downgrade/drop/recreation |
| Successful close and independent verification | COMMITTED_AND_VERIFIED control-flow state; only real future execution evidence can establish this state on PostgreSQL |
| Partial chain | Independently match marker, expected prefix, reviewed catalog hash and pinned sources. Resume only immediate next under fresh approval/process |
| Old monolithic 080 / objects ahead or behind marker | Manual intervention; do not adopt/stamp/drop/rotate identifiers or infer outcome from names |
| Evidence creation/fsync/close failure | Stop; no success/continuation. Existing partial evidence and committed database state require reconciliation |

New evidence files are O_EXCL/O_NOFOLLOW 0600 under a private owned 0700 outside-checkout parent. Fields contain UTC, current/next, plan hash, nonsecret target identities and catalog hash/outcomes; no credentials, row identifiers or business payloads. Driver/Alembic/SQLAlchemy errors are not stringified; generic safe messages and phase classifications are used. Evidence failure does not excuse uncertain outcomes.

Advisory locking is cooperative. The version lock prevents competing marker changes during the unit but is an extra metadata lock beyond the target table. Other schema/function/namespace/FK/catalog locks remain unmeasured. Privileged concurrent DDL can race checks; the explicit exclusive unrelated-DDL window and source/privilege review remain mandatory. No all-history mapping non-reuse or hostile-host security guarantee is invented.

## Offline tests and checks executed

| Check | Actual result |
| --- | --- |
| .venv/bin/python -B infra/uuid-migration/staged-runner/test_expand_one_step.py | **21 tests PASS**: actual hash/079–085 graph, skipped/out-of-order/multi-revision requests, missing/modified staged file, changed active head, synthetic approved/rejected manifest, offline no-runtime path, partial delta rejection, mocked one begin/upgrade/commit/close/independent verification, SQL-error rollback, unknown commit/no retry, postcommit mismatch, marker rowcount/multiple/mismatch, guard/legacy-monolith rejection, no root imports and preserved UUID contract |
| New SQL text compilation | PASS in unittest: new literal metadata/marker statements compiled with SQLAlchemy PostgreSQL dialect; no SQL executed |
| .venv/bin/python -B infra/uuid-migration/staged-runner/expand_one_step.py --mode offline | PASS: source/evidence hashes, reviewed common dependency and active/isolated graphs; no target plan, secret, Docker or DB path called |
| Existing verify_offline.py | PASS again: 79 active + six staged graph; now parses six Python files including new inert modules; existing 42 SQL templates/14 literal/18 dynamic query compilations and six concurrent-index DDL compilations remain successful |
| Repository Ruff lint/format, Python syntax/source checks | PASS for both new source files; prior artifacts unchanged |
| Git whitespace, hash preservation, historical ledger/open issues and links | Final evidence below |
| PG16 grammar/catalog deparser, actual lock/permissions/transactions/commit/rollback/data preservation | NOT EXECUTED / NOT ACCEPTED |
| Application/migration/browser/performance tests | NOT RUN; only offline/mock/source checks executed |

Test-development corrections: the first run passed 17/18 tests; patching Alembic Operations.context directly hit its metaclass proxy and caused a mock harness error. Replaced it with a mock of the module's Operations reference, preserving the actual library object. Initial semicolon Ruff findings were corrected by formatting the two new files; checks rerun successfully. Three more tests brought the final suite to 21. No test failure was a PostgreSQL result. Synthetic manifests are in-memory only; no real approval/credential file or database was created.

## Source SHA256

| New file | SHA256 |
| --- | --- |
| expand_one_step.py | 57a4b222841a0a6a3f302a25356e20249bb0d07eaecf81d0bec00b596ecb043b |
| test_expand_one_step.py | b65e5fd2048d4259c5ace8353f647aab6f5b247bad24465a0abc7b4c86faf661 |

## Readiness and next action

**GO for source review; NO-GO for connected validation or execution now.** D and W1.5 retain their independent blockers. Review exact manifest/source hashes, new marker-update ownership, conservative prefix/deparser checks, privileged bootstrap role, snapshot scope and lock/resource windows before any D run. W1.6B issues C-B02–C-B05 remain separately recorded, not fixed or waived.

Future authorized PG16 acceptance must prove: inert isolated setup/no root config; exactly one transactional revision and marker update; target/version/permissions/triggers/rules/event conditions; commit/close/fresh read-back; failure and lost-commit reconciliation; unchanged old data/PK/FK/sequences and B drift; old writer/NULL/default/CHECK/immutability behavior; prefix continuation after each table and rejection of legacy monolith/unexpected objects. Test actual lock acquisition/release/timeouts and deparser output; mocks and compilation are insufficient.

Next separate work: review/authorize W1.6B finding repairs where desired and later CHECK validation, non-null proof/NOT NULL/UNIQUE attachment source; future D provisioning/import/parity/execution remains separately authorized. No index/backfill/UUID schema or public API cutover was executed here.

Final verification: branch/HEAD unchanged; all 56 pre-existing contents other than the authorized tracker matched task-start hashes, including all staged 080–085/W1.6B sources and historical reports. Tracked binary diff unchanged; 21 prior completed-task ledger rows and all 12 Phase 1 open-issue rows retained verbatim. Exactly three new files and tracker update. New source hashes, 53 local report/tracker links/nonblank line locations and whitespace passed. Final 21-test offline suite, offline mode, prior verifier and Ruff lint/format passed. IMPLEMENTED (STAGED), NOT EXECUTED, NOT ACCEPTED; D NOT ACCEPTED and W1.5 NO-GO.
