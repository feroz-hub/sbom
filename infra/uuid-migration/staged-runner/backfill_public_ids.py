"""Staged bounded NULL-only backfill; no ORM or local-checkpoint authority."""

import time

from uuid_w1_common import (
    TABLES,
    acquire_operator_lock,
    bounded_transaction,
    guarded_main,
    qualified,
    query,
    require,
    verify_all,
    verify_identity,
    verify_indexes,
    verify_schema,
)

MIN_CURSOR = -2147483649  # Includes negative and zero int4 primary keys.


def batch_sql(table):
    target = qualified(table)
    return f"""WITH candidates AS MATERIALIZED (
        SELECT id FROM {target}
        WHERE public_id IS NULL AND id > :cursor AND id <= :high
        ORDER BY id LIMIT :batch FOR UPDATE
    ), changed AS (
        UPDATE {target} AS target SET public_id = pg_catalog.gen_random_uuid()
        FROM candidates WHERE target.id = candidates.id AND target.public_id IS NULL
        RETURNING target.id
    )
    SELECT (SELECT pg_catalog.count(*) FROM candidates),
           (SELECT pg_catalog.count(*) FROM changed),
           (SELECT pg_catalog.max(id) FROM candidates)
    """


def gap_sql(table):
    return f"SELECT EXISTS(SELECT 1 FROM {qualified(table)} WHERE public_id IS NULL)"


def run(conn, plan, args, evidence):
    require(1 <= args.batch_size <= 5000, "Batch size must be 1..5000")
    require(1 <= args.max_batches <= 1000000 and 1 <= args.max_seconds <= 86400, "Bounded run limits required")
    require(1 <= args.gap_sweeps <= 10, "Gap sweeps must be 1..10")
    if args.mode == "execute":
        acquire_operator_lock(conn)
    verify_all(conn, plan, require_all=True)
    if args.mode == "validate":
        for table in TABLES:
            evidence.emit("validation_only", table=table, null_gap=query(conn, gap_sql(table)).fetchone()[0])
        return

    started = time.monotonic()
    batches = 0
    total = 0
    # READ WRITE is explicit only inside each transaction; autocommit catalog
    # queries retain the connection's server default_transaction_read_only=on.
    conn.read_only = False
    for table in TABLES:
        completed = False
        for sweep in range(args.gap_sweeps + 1):
            cursor = MIN_CURSOR
            high = query(conn, f"SELECT pg_catalog.max(id) FROM {qualified(table)}").fetchone()[0]
            while high is not None and cursor < high:
                require(
                    batches < args.max_batches and time.monotonic() - started < args.max_seconds,
                    "Run limit reached; committed mappings retained, restart NULL-only scan",
                )
                verify_all(conn, plan, require_all=True)
                # No SKIP LOCKED: locked rows cause bounded wait/failure, never
                # a cursor advancing past an unprocessed locked gap.
                with bounded_transaction(conn):
                    query(conn, f"LOCK TABLE ONLY {qualified(table)} IN SHARE UPDATE EXCLUSIVE MODE NOWAIT")
                    verify_identity(conn, plan)
                    tables = verify_schema(conn, plan)
                    verify_indexes(conn, plan, tables, require_all=True)
                    selected, updated, last = query(
                        conn, batch_sql(table), {"cursor": cursor, "high": high, "batch": args.batch_size}
                    ).fetchone()
                    require(
                        selected == updated and 0 <= updated <= args.batch_size,
                        "Batch count invariant failed; roll back current batch",
                    )
                    evidence.emit(
                        "batch_precommit",
                        table=table,
                        ordinal=batches + 1,
                        sweep=sweep,
                        selected=selected,
                        updated=updated,
                    )
                # Only after transaction context COMMIT acknowledgement.
                batches += 1
                total += updated
                evidence.emit(
                    "batch_committed",
                    table=table,
                    ordinal=batches,
                    sweep=sweep,
                    updated=updated,
                    total_updated=total,
                    checkpoint="database-null-predicate",
                )
                if selected == 0:
                    break
                cursor = last
            verify_all(conn, plan, require_all=True)
            remaining = query(conn, gap_sql(table)).fetchone()[0]
            evidence.emit("gap_sweep", table=table, sweep=sweep, null_gap=remaining)
            if not remaining:
                completed = True
                break
            # Restart from minimum with a fresh high-water mark; includes low-PK
            # arrivals and keys beyond the prior horizon. No persisted cursor trusted.
        require(completed, "NULL gaps remain after bounded sweeps; no completion claim")
    verify_all(conn, plan, require_all=True)
    for table in TABLES:
        require(not query(conn, gap_sql(table)).fetchone()[0], "Final all-table gap check failed")
    evidence.emit("nulls_absent_at_observation", batches=batches, total_updated=total)
    # This observation is not NOT NULL enforcement, CHECK validation or acceptance.


if __name__ == "__main__":
    raise SystemExit(guarded_main("backfill", run))
