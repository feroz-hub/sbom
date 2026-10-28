# W2.5.1 — exact driver-error compatibility proposal

OFFLINE IMPLEMENTATION ONLY. No live probe, PostgreSQL connection, Docker command,
secret content, migration or readback. The first W2.5 action is CONSUMED. This
entrypoint's live mode always refuses. Future write authority requires independent
review of this complete source transition and a new single-use action. It cannot
reuse the old W25 approval. This is not a runtime-acceptance or retry proposal.

## Evidence and exact cause

The original 19-record journal matches raw SHA256
7f0153f8b1f5daf81be090d14c112660b5d3596037012fc149b4cbdc4e0e183c.
It records one attempt, eight catalog statement requests (five initializer and
three preflight), zero body/marker operations, acknowledged RO rollback/physical
close/disposal/resource preservation, and ROLLED_BACK_UNVERIFIED. Its structured
outcome and approved-manifest reference match. There is no original traceback
or retained original psycopg exception; this limitation is preserved.

The exact rejected attribute is `broken`. Installed SQLAlchemy2.0.51:
Connection._exec_single_context catches a DBAPI exception; its
_handle_dbapi_exception calls PGDialect_psycopg.is_disconnect; line596 reads
`connection.closed or connection.broken`. Pool proxy __getattr__ forwards the
latter to the original W2.4C Driver.__getattr__, which refuses it. This metadata
check masked the earlier DBAPI error.

The triggering parameter-conversion defect is independently reproducible with
the installed psycopg3.3.4 PostgresQuery/Transformer and actual SQLAlchemy binding:
exec_driver_sql ordinarily passes an empty immutabledict, not None.
Preflight query3 (`relations`) contains `LIKE 'pg_toast%'`. PostgresQuery.convert
parses percent placeholders whenever vars is not None, even for an empty mapping.
Its native converter raises ProgrammingError for the percent followed by quote,
SQLSTATE null. The initialized context and eight SQL hashes exactly match the
original journal. Query3 is charged before conversion; SQL_REQUESTED does not
prove that its SQL reached PostgreSQL. Initialization, identity and schemas use
no bare percent and succeed in this reproduction. It never reaches query4.

Original synthetic Cursor.execute simply matched SQL strings and returned Python
rows. It did not run the installed psycopg query converter and did not produce
this ProgrammingError, so SQLAlchemy's disconnect check never ran. New tests use
that converter for every driver operation with an entirely synthetic backend.
The historical hidden exception was not recovered by a live probe; the supported
mechanism is established by pinned source and deterministic offline reproduction.

## Minimum isolated correction

`w251_driver.py` defines a subclass of the immutable historical Driver with one
read-only `broken` Boolean property. It delegates only the original native status
getter, rejects nonbool results and has no setter. psycopg BaseConnection.broken
checks local libpq status and explicit-close state; it does not execute SQL.
No pgconn, execute, pipeline, COPY, TPC, cursor factory, native unwrapping or
catch-all forwarding is exposed. The original Cursor and Session are reused.

Fixing only broken would expose the ProgrammingError and still fail at query3.
The versioned dialect therefore adds exact parameter-dispatch validation:

- Known parameterless SQL + None/empty dict/SQLAlchemy immutabledict/empty tuple
  routes once through inherited do_execute_no_params to the original metered
  Cursor.execute. Native psycopg sees params=None; literal percent bytes are kept.
- The exact hstore name and047 marker statements retain their original bound
  mappings/values and inherited do_execute path. No interpolation/inlining.
- All other SQL or parameter shapes refuse. do_execute_no_params also validates;
  batches are refused because frozen047 schedules none. No wildcard allowlist,
  quote replacement, placeholder guessing or automatic learning.

The SQL allowlist, all558statement bytes/12directives, model, budgets and
transaction controls remain identical. The dispatch change can select psycopg's
parameterless/simple-query path; each operation is still exactly one framed,
hash-pinned statement. No multi-command SQL, hidden initialization connection,
SAVEPOINT, rollback, source suppression or engine replacement is added.

`w251_integration.py` checks its own new source lock and the exact W2.5v2 lock,
parent source bytes,179historical pins and installed dependency pins. It creates
a new private API namespace containing the compatible Driver and dialect factory.
It does not mutate the parent module, classes, guards or library source. The
original W2.5 Transport/Session/recipe/coordinator can be exercised offline with
this explicit versioned namespace. Old sources and old CLIs are not altered.
The namespace is not a live approval or a replacement runtime receipt.

## Lifecycle, scope and unresolved runtime work

Offline tests cover the original matching failure, metadata-only partial fix,
complete source-preserving dispatch, denied native access, exact driver charging,
bound parameters, phase settings, query exhaustion, RO ownership and rollback,
physical close, COMMIT/unknown-COMMIT safeguards and separate readback boundary.
They instantiate real installed SQLAlchemy APIs and native psycopg conversion,
not a PostgreSQL connection. No mock COMMIT accepts a real database installation.

The default CLI is useful offline review. Its live mode always refuses before
source loading or provider access. There is no new connection constructor in
this directory. A future source-specific activation must bind the reviewed
versioned namespace to fresh exact write authority and runtime/resource evidence,
retain original raw manifest verification, and claim a new attempt path. The
pending review candidate is deliberately NOT an executable old W25 manifest.
No approved future action, source activation, write or readback exists here.

Actual PostgreSQL syntax/catalog representations, physical native transaction
behavior, simple-query path, locks, time/capacity and COMMIT/rollback remain
runtime acceptance dependencies. Existing four-phase GUC/model/budget checks,
source/catalog/role/credential/resource approvals and exact F-only target must
remain mandatory. Never resume the consumed action or automatically proceed to
048–091, fixtures or the193live integrity cases.

    .venv/bin/python -B infra/uuid-migration/frozen047-driver-correction/w251_entry.py --mode offline
    .venv/bin/python -B infra/uuid-migration/frozen047-driver-correction/test_w251_offline.py

STOP for independent source/package review. No live execution approval.
