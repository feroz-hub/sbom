# W2.5.1 — Real driver bypass analysis and versioned compatibility correction

**W2.5.1 DRIVER COMPATIBILITY OFFLINE VERIFIED.** 2026-10-19. Exact rejected attribute and its requesting call path established from pinned installed dependencies and controlled offline instrumentation. A separate versioned correction is implemented and tested. **1,103 OFFLINE PASS / 0 FAIL / 0 SKIP**: 1,066 existing plus37focused tests. No PostgreSQL connection, Docker command, credential-content read, SQL/migration execution, retry/readback, schema change or Git delivery occurred.

The original action **`W25-F047-WRITE-20261019-V2-ONE` is CONSUMED**. Its first actual attempt remains **ROLLED_BACK_UNVERIFIED**, frozen047 remains **NOT RUNTIME ACCEPTED**, all193live integrity cases **NOT EXECUTED**. New live entrypoint is intentionally denied; this is compatibility/source acceptance only, not a new write authorization.

## Verified immutable execution evidence

[Original journal](/Users/ferozebasha/.sbom-uuid-w2-review/w25-settings-20261019T084922290438Z/write/unit-attempt.jsonl) actual raw SHA256 **`7f0153f8b1f5daf81be090d14c112660b5d3596037012fc149b4cbdc4e0e183c`** verified. All19records chain correctly from CLAIMED through AUTHORITY/CONNECT/SQL_REQUESTED/ROLLBACK_ACKNOWLEDGED/CLOSED/DISPOSED/RESOURCES_PRESERVED to durable STOP. The matching [structured outcome](/Users/ferozebasha/.sbom-uuid-w2-review/w25-settings-20261019T084922290438Z/write/write-outcome.v2.one.json) raw SHA256 `303187fa28b215e073b18affd5b6b5a3e655cde10735471e2b6e9b4aa9bd30d5` equals the final STOP result and was not edited. Approved manifest raw SHA256 `e6cc8665c51cdfaf4cd7b622a85eb25b9379a9052051120f6ff3a9650a58d987` and the exact consumed action reference match the journal. Source/packagev2 `91f3af6d98b4879d5c9a7f5e65dfd2f6d3c5e9a862c7a02f0e44be20c4022a3e` and all21current parent sources verified against original embedded bytes.

Actual recorded result: one constructor attempt/connection;8catalog requests (5initialization+3preflight),2controls;0body/marker/session statements;0/558body acknowledgments; no RW installation transaction or COMMIT. RO rollback acknowledged, physical closure/logical cleanup/disposal/resources preserved. Process exit2. This task verified saved evidence only; no new database observation was made.

Required branch `feat/native-user-management`, HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac` retained. All2,232existing repository file hashes snapshotted before implementation; all historical sources unchanged, tracker append only. Original journal, manifest, old candidates, locks/packages/reports remain untouched.

## Exact rejected attribute and caller

Rejected attribute: **`broken`**, not a guessed generic connection option. Installed SQLAlchemy2.0.51 call sequence:

1. `sqlalchemy/engine/base.py:1988`, `Connection._exec_single_context`, catches a DBAPI error.
2. `base.py:2252`, `_handle_dbapi_exception`, requests dialect disconnect classification.
3. `sqlalchemy/dialects/postgresql/psycopg.py:596`, `PGDialect_psycopg.is_disconnect`, reads `connection.closed or connection.broken` for a psycopg.Error.
4. `sqlalchemy/pool/base.py:1497`, `_ConnectionFairy.__getattr__`, forwards the latter to the DBAPI Driver proxy.
5. Original unchanged W2.4C `Driver.__getattr__` refuses the unknown attribute and raises `ValueError: Unreviewed driver bypass`, masking the first exception.

The instrumented offline reproduction records the attribute name and complete calling frames. It uses the original Driver/Session/Cursor, actual SQLAlchemy Engine/NullPool/Connection/dialect and pinned psycopg PostgresQuery/Transformer, with a wholly synthetic backend. [Full reproduction](/Users/ferozebasha/.sbom-uuid-w2-review/w251-20261019T093555664954Z/offline-root-cause-reproduction.json); [causal/accounting comparison](/Users/ferozebasha/.sbom-uuid-w2-review/w251-20261019T093555664954Z/causal-analysis.json). It reproduces the original error, phase totals and **all eight ordered SQL hashes exactly**, then the same known rollback/physical-close outcome.

Historical limitation: the actual journal did not retain the original attribute, traceback or hidden DBAPI error. These were **reconstructed offline**, not recovered through a live probe or falsely represented as fields in the original journal. The deterministic pinned-source reproduction identifies the compatibility mechanism; no new runtime observation was invented.

## Earlier client error and why it occurs at request eight

The metadata bypass is a second error. The first is psycopg3.3.4 **ProgrammingError**, reproduced primary text:

`only '%s', '%b', '%t' are allowed as placeholders, got '%''`

SQLSTATE is null. SQLAlchemy's default raw driver execution supplies an empty `immutabledict` to ordinary parameterless statements. `PGDialect_psycopg` inherits `DefaultDialect.do_execute`, which calls `cursor.execute(statement, parameters)`; `context.no_parameters` is not enabled by the reviewed W2.5 construction. psycopg's `_queries.PostgresQuery.convert` parses percent placeholders whenever `vars is not None`, including empty dicts/tuples. The third preflight query contains `NOT LIKE 'pg_toast%'`; its literal percent followed by quote is rejected by `_split_query`. The dialect's error handler then requests broken and masks that ProgrammingError.

| Request | Phase / statement | Converter outcome in exact offline reproduction |
|---|---|---|
|1|initialize: pg_catalog.version|passes|
|2|initialize: current_schema|passes|
|3|initialize: transaction isolation SHOW|passes; None parameters|
|4|initialize: standard_conforming_strings SHOW|passes|
|5|initialize: hstore type lookup|passes; actual named bound parameter|
|6|preflight: identity|passes|
|7|preflight: schemas|passes|
|8|preflight: relations, including pg_toast percent pattern|client placeholder conversion error; then rejected broken metadata|

The eighth SQL hash is `4aaa0a7cb95c8c88e164c6204429d77ccce04ea068cc2b65a510d611f61d5a65`. Driver metering records SQL_REQUESTED **before** native execution/conversion. Therefore eight charged requests do not prove eight successfully executed server queries. The source parser failure occurs before sending that statement; no schema body was reached.

Original synthetic `w25_test_support.Cursor.execute` simply matched SQL strings and returned Python rows. It never invoked psycopg's real parameter converter, so it never raised this client error and SQLAlchemy never requested broken. W2.4C/W2.5 original regression successes are retained accurately; they did not establish native parameter compatibility.

## Safety classification and minimum correction

### Boolean local-status interface

psycopg3.3.4 `_connection_base.BaseConnection.broken` reads local `pgconn.status == BAD` and `not self._closed`. It is **read-only local metadata**, not an SQL operation or adapter configuration. Tests invoke the actual pinned property getter against synthetic libpq status values.

New `w251_driver.compatible_kernel` returns a separate Driver subclass with exactly one explicit read-only `broken` property. It returns the existing raw object's Boolean only and refuses nonbool metadata. No setter, catch-all forwarding, new raw connection-unwrapping API, native pgconn, execute, cursor options, pipeline, COPY, stream or TPC exposure is added. Original trusted owner internals and Session/Cursor classes remain as previously reviewed. Metadata reads consume no SQL budget and cannot start a transaction.

### Exact parameter dispatch through the original meter

A metadata-only partial fix is tested and correctly exposes the original ProgrammingError; it is insufficient to make preflight compatible. The new dedicated dialect therefore routes only existing exact statements:

- Existing parameterless SQL with None/empty dict/SQLAlchemy immutabledict/empty tuple uses inherited `do_execute_no_params`, reaching original metered Cursor.execute once with paramsNone. Every SQL byte is unchanged; no percent escaping or string rewriting.
- The exact hstore lookup and marker INSERT retain their exact original bound dictionaries/values and ordinary `do_execute`. Missing, wrong or additional bound values refuse. Native converter tests prove values are not inlined into SQL.
- Unknown SQL/parameter shapes refuse. Both do_execute and do_execute_no_params validate; driver batches are refused because frozen047 schedules none. Original allowlist, SQL framing, per-phase metering, time/transaction controls remain authoritative.

Using paramsNone preserves literal percent text and can select psycopg's parameterless/simple-query path; its real wire behavior still requires separately approved runtime verification. The reviewed one-statement framing and exact hashes remain mandatory, so no arbitrary multi-command SQL is added. This does not increase SQL allowances or introduce a hidden initialization connection/rollback.

## Versioned integration and source preservation

Six new files under [frozen047-driver-correction](/Users/ferozebasha/sbom/infra/uuid-migration/frozen047-driver-correction/README.md). No W2.4C kernel/dialect/recipe, W2.5 source, old lock or library file was edited.

`w251_integration.reviewed` checks a new source-lock proposal, exact W2.5v2parent lock/current parent source bytes,179historical inputs and installed package pins. It returns a new isolated namespace containing compatible Driver/dialect factories. No parent globals/classes or migration guards are monkeypatched. The unchanged W2.5 Transport, transaction recipe/kernel/session and coordinator are reused only with this explicit namespace in offline tests. The real underlying driver object and installed dependency sources remain unchanged.

[New CLI](/Users/ferozebasha/sbom/infra/uuid-migration/frozen047-driver-correction/w251_entry.py) defaults to useful offline review and **always refuses live mode**. No connection constructor exists in the new directory. There is no generic force/skip/alternate-target switch or old private helper import. A future source-specific activation must separately bind this namespace to exact new manifest/source/target/resource/credential authority. The review candidate is deliberately not an executable old W2.5 manifest.

| New file | SHA256 |
|---|---|
| README.md | `5fb3382d835ad3177bc567543c2d882d54111000930797d95efe31ba765269c8` |
| source-lock.w251.v1.json | `d15bb4257d1c98d25e9be44fd403f4dbf5eb84bbba39b810317f62dd58ede2f1` |
| test_w251_offline.py | `ef5aa82751533d944712bd857c391f8680006718e37755d241fc17cb1988a817` |
| w251_driver.py | `a77dfbb680c2ff349b1e42ff07198f533bbae013c388c65de417b541e07cf78f` |
| w251_entry.py | `960254ac411b4839bbd0fcad5d29a976c37e93fd71a89ddf99d91a1a55c27e9a` |
| w251_integration.py | `e5c2bd2f384527c7995b67d146665e3b22ef58138da952acbdb77b786f24f6ea` |

The source lock transitions from immutable parent `cce0795d165c94453bdffae70302dd4c26013c8a9973945648b052374d5e1742` to separate unapproved `source-lock.w251.v1.json` SHA256 `d15bb4257d1c98d25e9be44fd403f4dbf5eb84bbba39b810317f62dd58ede2f1`. ParentSQLallowlist remains `56f476f8318e3e7999a9cb18aa9530de3d871ab4ee6305e53ad457600d3de49f`, model `9e64728cfa41fb493c98acadc75c216d7d749aeaa25ec51372e785b50732d9df`. All558statements/12directives, original budgets, marker order, four GUC setting phases, source/privilege checks and rollback/unknown-COMMIT/physical-close/readback boundaries are unchanged. No migration discovery/promotion or048–091execution path is added.

## Actual tests and static verification

Final **1,103 PASS / 0 FAIL / 0 SKIP**, including all1,066selected existing offline tests and37new focused tests. [Exact suite commands/counts/exit codes](/Users/ferozebasha/.sbom-uuid-w2-review/w251-20261019T093555664954Z/offline-tests.json), [logs](/Users/ferozebasha/.sbom-uuid-w2-review/w251-20261019T093555664954Z/logs).

New tests cover the exact original attribute/caller/converter failure, metadata-only partial fix, dangerous Driver/Cursor refusal, real native status property semantics, native converter over all permitted statement templates, exact hstore/marker bindings, literal percent preservation, SQL/parameter/driver-batch refusal, driver budget exhaustion before native conversion, native DBAPI error retention, one constructor, RO rollback before RW, unchanged558/148query/2marker/4control lifecycle, physical close, uncertainCOMMIT/no retry, four setting phases, no automatic readback, separate mocked readback86queries/2controls, source tampering, inert imports and live denial.

```bash
.venv/bin/python -B infra/uuid-migration/frozen047-driver-correction/test_w251_offline.py
.venv/bin/python -B infra/uuid-migration/frozen047-driver-correction/w251_entry.py --mode offline
ruff check --no-cache infra/uuid-migration/frozen047-driver-correction
ruff format --check infra/uuid-migration/frozen047-driver-correction
git diff --check
```

FournewPythonAST/in-memory compilations,649unchangedSQLtemplate frames/SQLAlchemy compiles,179pins, old graph91revisions/45units/active079 and installed dependency source hashes PASS. Actual versions SQLAlchemy2.0.51 and psycopg3.3.4; eight relevant dependency implementation files copied privately with raw hashes. No SQLAlchemy compiler/native converter/mock COMMIT was claimed as PostgreSQL runtime acceptance.

Development evidence retained: first33newtestsPASS; expanded final37PASS. Four initial Ruff import/unused findings fixed only in the new test file; final lint/format PASS. No unexpected unit-test failure was suppressed. The intentionally reproduced original failure remains an expected negative test, not a successful live process.

## Protected package, candidate and next review

[New source-review package](/Users/ferozebasha/.sbom-uuid-w2-review/w251-20261019T093555664954Z/w251-driver-compatibility-review-package.v1.json) raw SHA256 **`35e5424917f12bd1da8b1cc996b031e4d438ba1d14700b68dc40778d3d11229f`** contains complete sixnew source files and full /dev/null unified diffs, parent source pins, original evidence verification, exact caller stacks/eight-hash comparison, native-converter failure, installed dependency snapshots/hashes, test/log evidence, limits and full candidate JSON.

[Unapproved write source-transition candidate](/Users/ferozebasha/.sbom-uuid-w2-review/w251-20261019T093555664954Z/frozen047-write-review-candidate.w251.v1.json) SHA256 **`4baac4582e9f89bdfe3a12c3451263febef2aecc19189de05235fa8ecebb24ec`**. Expiry **`2026-10-20T08:09:44.274290+00:00`** retained from the earlier unapproved candidate; this does not renew an authorization. All8operatorflagsfalse, actionreference null/approvals{}, acceptedfalse, sevenintegrityflagsfalse/actions{}. Old consumed action is listed only as prohibited historical provenance. No new action ID was generated. No new live database identities/observations were invented; Ftarget/resources are explicit historical references requiring fresh future gates. Candidate/currentCLI cannot execute a write; later live binding requires independent source-specific review.

Private directory0700/files0600; all original journal/manifest/package/candidate/lock hashes rechecked. Report38 and tracker are new/append-only records; report37 and historical outcomes remain untouched. No new PostgreSQL/credential/Docker activity. No retry, independent SQL/readback, role/grant/marker repair, cleanup, schema change or Git operation occurred.

Remaining uncertainties: native PostgreSQL wire/simple-query protocol, real result adaptation, actual GUC/catalog/type/storage representations, transaction/lock/resource timing, physical COMMIT/rollback/recovery and application behavior remain unaccepted. The source-level cause is established and corrected, but this task does not establish fresh database state or first installation acceptance. The old action is permanently consumed.

**STOP.** Next: independent review of the source/package and proposed integration/activation contract; any later write needs a newly reviewed executor binding, exact approved raw manifest, fresh runtime preflight and a new explicit single-use action. Readback requires its own later authorization and actual write evidence. Do not reuse the old reference, reconnect, migrate or run the193integrity cases under W2.5.1.
