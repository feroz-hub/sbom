"""Staged unique-index execution; never run without separate D authorization."""

from psycopg.pq import TransactionStatus
from uuid_w1_common import (
    INDEX_SQL,
    PATTERN,
    TABLES,
    acquire_operator_lock,
    guarded_main,
    index_ddl,
    index_name,
    qualified,
    query,
    require,
    verify_all,
)


def duplicates_sql(table):
    return f"""SELECT EXISTS (
        SELECT 1 FROM {qualified(table)} WHERE public_id IS NOT NULL
        GROUP BY public_id HAVING pg_catalog.count(*) > 1
    )"""


def run(conn, plan, args, evidence):
    require(
        conn.autocommit and conn.info.transaction_status == TransactionStatus.IDLE,
        "Concurrent indexes require explicit autocommit/idle connection",
    )
    if args.mode == "execute":
        acquire_operator_lock(conn)
    created = {}
    _, indexes = verify_all(conn, plan, require_all=False)
    # All tables are checked before any DDL, not only immediately before their build.
    for table in TABLES:
        require(
            query(conn, duplicates_sql(table)).fetchone() == (False,), "Duplicate non-NULL UUIDs; no index executed"
        )
        invalid = query(
            conn,
            f"SELECT EXISTS(SELECT 1 FROM {qualified(table)} WHERE public_id IS NOT NULL AND NOT (public_id::pg_catalog.text OPERATOR(pg_catalog.~) :pattern))",
            {"pattern": PATTERN},
        ).fetchone()[0]
        require(not invalid, "Existing non-v4 UUID requires review; no index executed")
    evidence.emit("preflight", verified_indexes=sum(v is not None for v in indexes.values()))
    if args.mode == "validate":
        evidence.emit("validation_only", pending_indexes=sum(v is None for v in indexes.values()))
        return
    for table in TABLES:
        _, indexes = verify_all(conn, plan, require_all=False, created=created)
        if indexes[table] is not None:
            evidence.emit("accepted_existing_index", table=table, index_oid=indexes[table])
            continue
        require(query(conn, duplicates_sql(table)).fetchone() == (False,), "Duplicate UUID appeared before index build")
        require(
            conn.autocommit and conn.info.transaction_status == TransactionStatus.IDLE,
            "Refusing concurrent index inside transaction",
        )
        # Session settings, not SET LOCAL: CREATE INDEX CONCURRENTLY owns its transactions.
        query(
            conn,
            "SELECT pg_catalog.set_config('statement_timeout',:value,false)",
            {"value": str(plan["index_statement_ms"])},
        )
        query(conn, "SELECT pg_catalog.set_config('default_transaction_read_only','off',false)")
        evidence.emit("index_attempt", table=table)
        try:
            require(
                conn.autocommit and conn.info.transaction_status == TransactionStatus.IDLE,
                "Autocommit boundary changed",
            )
            query(conn, index_ddl(table))
        finally:
            # On failure the outer handler stops; never drop/rebuild/retry a remnant.
            if not conn.closed and conn.info.transaction_status == TransactionStatus.IDLE:
                query(conn, "SELECT pg_catalog.set_config('default_transaction_read_only','on',false)")
                query(conn, "SELECT pg_catalog.set_config('statement_timeout','10000',false)")
        rows = query(conn, INDEX_SQL, {"name": index_name(table)}).fetchall()
        require(len(rows) == 1, "Post-build index identity missing; outcome requires reconciliation")
        created[table] = rows[0][0]
        _, indexes = verify_all(conn, plan, require_all=False, created=created)
        evidence.emit("index_verified", table=table, index_oid=indexes[table])
    verify_all(conn, plan, require_all=True, created=created)
    evidence.emit("all_indexes_verified", indexes=created)


if __name__ == "__main__":
    raise SystemExit(guarded_main("indexes", run))
