#!/usr/bin/env python3
"""PostgreSQL & SQLAlchemy connection pool diagnostics utility."""

import sys

from app.db import engine
from sqlalchemy import text


def main():
    print("=== Connection Pool Diagnostics ===")

    # 1. SQLAlchemy Engine Pool Info
    pool = engine.pool
    print("\n[SQLAlchemy QueuePool Stats]")
    print(
        f"Pool size: {getattr(pool, 'size', lambda: 'N/A')() if callable(getattr(pool, 'size', None)) else getattr(pool, 'size', 'N/A')}"
    )
    print(f"Checked-in connections: {pool.checkedin() if hasattr(pool, 'checkedin') else 'N/A'}")
    print(f"Checked-out connections: {pool.checkedout() if hasattr(pool, 'checkedout') else 'N/A'}")
    print(
        f"Max overflow: {getattr(pool, 'overflow', lambda: 'N/A')() if callable(getattr(pool, 'overflow', None)) else getattr(pool, 'overflow', 'N/A')}"
    )

    # 2. PostgreSQL Server-side Connection Stats
    if engine.dialect.name != "postgresql":
        print(f"\n[PostgreSQL Stats] Skipped (Dialect is {engine.dialect.name})")
        return 0

    print("\n[PostgreSQL Active Connection States]")
    try:
        with engine.connect() as conn:
            # Query states count
            state_query = text("""
                SELECT state, count(*)
                FROM pg_stat_activity
                WHERE datname = current_database()
                GROUP BY state;
            """)
            states = conn.execute(state_query).all()
            for row in states:
                print(f"  State: {row[0] or 'NULL'} -> Count: {row[1]}")

            # Query longest running queries
            query_details = text("""
                SELECT pid, state, wait_event_type, wait_event, now() - query_start AS age, left(query, 200) AS query
                FROM pg_stat_activity
                WHERE datname = current_database()
                ORDER BY query_start ASC;
            """)
            queries = conn.execute(query_details).all()
            print("\n[PostgreSQL Active Queries details]")
            for row in queries:
                print(f"  PID: {row[0]}")
                print(f"    State: {row[1]}")
                print(f"    Wait Event: {row[2] or 'None'} / {row[3] or 'None'}")
                print(f"    Age: {row[4]}")
                print(f"    Query: {row[5].strip()}")
                print("-" * 40)
    except Exception as e:
        print(f"Error querying pg_stat_activity: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
