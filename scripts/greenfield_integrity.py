"""Run the original 193 scenarios against this task's isolated FINAL-schema test DB.

Final-schema adaptations: duplicates reject; legacy NULL rows cannot be created;
NULL removal fails NOT NULL before AFTER immutability. Historical E suite unchanged.
"""

from __future__ import annotations

import fcntl
import json
import os
import sys
import threading
import time
import uuid
from contextlib import contextmanager

from scripts.greenfield_uuid import DB, ROOT, STATE, settings, url, verify_resources

sys.path.insert(0, str(ROOT / "infra/uuid-migration/staged-runner"))
import uuid_integrity_control as ctl
import uuid_integrity_fixtures as fx
import uuid_integrity_suite as original

TEST_DB = DB + "_integrity_test"


class Evidence:
    def __init__(self):
        self.lock = threading.Lock()
        self.path = STATE / ("integrity-transactions-" + str(time.time_ns()) + ".jsonl")
        self.fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)

    def emit(self, event, **kwargs):
        with self.lock:
            os.write(self.fd, (json.dumps({"event": event, "monotonic": time.monotonic(), **kwargs}) + "\n").encode())
            os.fsync(self.fd)


class Sessions:
    def __init__(self):
        self.cancelled = threading.Event()
        self.evidence = Evidence()
        self.rows = set()
        self.attempts = 0
        self.closed = 0
        self.lock = threading.Lock()
        self.deadline = time.monotonic() + 600
        self.connections = threading.BoundedSemaphore(2)

    def budget(self):
        if time.monotonic() > self.deadline:
            raise RuntimeError("Integrity suite time budget exhausted")

    def reserve_row(self, table, identity):
        with self.lock:
            if (table, identity) in self.rows:
                raise RuntimeError("Fixture collision")
            self.rows.add((table, identity))

    @contextmanager
    def open(self):
        import psycopg

        with self.lock:
            self.attempts += 1
        from sqlalchemy.engine import make_url

        u = make_url(url("greenfield_setup", "setup-password", TEST_DB))
        self.budget()
        if not self.connections.acquire(timeout=5):
            raise RuntimeError("Integrity connection budget exhausted")
        conn = None
        try:
            conn = psycopg.connect(
                host=u.host,
                hostaddr=u.host,
                port=u.port,
                dbname=u.database,
                user=u.username,
                password=u.password,
                passfile="/dev/null",
                sslmode="disable",
                gssencmode="disable",
                connect_timeout=5,
                autocommit=True,
                options="-c statement_timeout=3000 -c lock_timeout=250 -c idle_in_transaction_session_timeout=5000",
            )
            assert conn.execute("SELECT current_database()").fetchone() == (TEST_DB,)
            yield conn
        finally:
            if conn is not None:
                conn.close()
                assert conn.closed
                with self.lock:
                    self.closed += 1
            self.connections.release()

    def baseline(self, conn):
        assert conn.execute("SELECT version_num FROM alembic_version").fetchone() == ("100_greenfield_uuid_final",)


class FinalSuite(original.Suite):
    def fixture(self, table, mode="omitted", supplied=None, legacy=False):
        # Use a fresh explicit UUID for independent cases under final uniqueness.
        if legacy:
            raise RuntimeError("Legacy NULL fixture forbidden in final schema")
        return super().fixture(
            table,
            mode,
            supplied
            if isinstance(supplied, str) and supplied.isupper()
            else uuid.uuid4()
            if mode == "supplied"
            else supplied,
        )

    def generation(self, table, name):
        if name != "duplicates_permitted":
            return super().generation(table, name)
        row = self.fixture(table)
        with self.sessions.open() as conn:
            with ctl.write_transaction(conn):
                result = original.expect_error(
                    conn,
                    lambda: fx.insert_chain(
                        conn, table, self.next_slot(), self.sessions.reserve_row, "supplied", row[1]
                    ),
                    "23505",
                    table,
                )
        return {**result, "final_unique_constraint_enforced": True, "original_case": "duplicates_permitted"}

    def immutability(self, table, name):
        if name.startswith("legacy_null"):
            slot = self.next_slot()
            with self.sessions.open() as conn:
                with ctl.write_transaction(conn):
                    # A late INSERT trigger reproduces the original legacy-fixture attempt.
                    trigger = original.helper(conn, table, fx.identity(table, slot), "INSERT")
                    result = original.expect_error(
                        conn, lambda: fx.insert_chain(conn, table, slot, self.sessions.reserve_row), "23502", table
                    )
                    original.remove_helper(conn, table, trigger)
            with self.sessions.open() as reader:
                assert fx.read_identity(reader, table, fx.identity(table, slot)) is None
            return {**result, "legacy_NULL_unrepresentable_in_final_schema": True, "original_case": name}
        if name == "remove":
            row = self.fixture(table)
            with self.sessions.open() as conn:
                with ctl.write_transaction(conn):
                    result = original.expect_error(
                        conn, lambda: fx.update(conn, table, row[0], "public_id", None), "23502", table
                    )
            self.readback(table, row)
            return {**result, "NOT_NULL_precedes_AFTER_guard": True}
        return super().immutability(table, name)

    def concurrency(self, table, name):
        if name != "parallel_null_first":
            return super().concurrency(table, name)
        row = self.fixture(table)
        barrier = threading.Barrier(2, timeout=5)

        def update():
            with self.sessions.open() as conn:
                with ctl.write_transaction(conn):
                    barrier.wait()
                    return fx.update(conn, table, row[0], "public_id", uuid.uuid4(), null_only=True).rowcount

        assert self.parallel([update, update]) == [0, 0]
        self.readback(table, row)
        return {"clients": 2, "NULL_assignment_predicate_matches_no_final_rows": True}


def prepare():
    verify_resources()
    os.environ.update(settings())
    os.chdir(STATE)
    from app.greenfield_schema import application_metadata

    metadata = application_metadata()
    from app.public_identity import install_guards
    from sqlalchemy import create_engine, text

    engine = create_engine(
        url("greenfield_setup", "setup-password", "postgres"), isolation_level="AUTOCOMMIT", hide_parameters=True
    )
    with engine.connect() as conn:
        if conn.execute(
            text("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=:name)"), {"name": TEST_DB}
        ).scalar_one():
            # This exact test database is owned exclusively by this new task.
            conn.exec_driver_sql(f"DROP DATABASE {TEST_DB} WITH (FORCE)")
        conn.exec_driver_sql(f"CREATE DATABASE {TEST_DB}")
    engine.dispose()
    engine = create_engine(url("greenfield_setup", "setup-password", TEST_DB), hide_parameters=True)
    with engine.begin() as conn:
        metadata.create_all(conn)
        install_guards(conn)
        conn.exec_driver_sql("CREATE TABLE alembic_version(version_num varchar(64) PRIMARY KEY)")
        conn.execute(text("INSERT INTO alembic_version VALUES(:revision)"), {"revision": "100_greenfield_uuid_final"})
    engine.dispose()


def main():
    lock = open(STATE / "integrity.lock", "a")
    os.chmod(STATE / "integrity.lock", 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise RuntimeError("Another integrity suite owns the task test database") from None
    prepare()
    sessions = Sessions()
    suite = FinalSuite(sessions)
    results = []
    selected = original.cases(fx.TABLES, original.CASES)
    assert len(selected) == 193
    for table, category, name in selected:
        start = time.monotonic()
        try:
            observed = getattr(suite, category)(table, name)
            row = {"table": table, "category": category, "name": name, "status": "PASS", "observed": observed}
        except ctl.UnknownCommit:
            raise
        except Exception as error:
            row = {
                "table": table,
                "category": category,
                "name": name,
                "status": "FAIL",
                "error_class": type(error).__name__,
                "sqlstate": getattr(error, "sqlstate", None),
                "reason": str(error)[:150],
            }
        row["seconds"] = round(time.monotonic() - start, 3)
        results.append(row)
        print(table, category, name, row["status"], row.get("reason", ""), flush=True)
    summary = {
        "executed": len(results),
        "passed": sum(r["status"] == "PASS" for r in results),
        "failed": sum(r["status"] == "FAIL" for r in results),
        "skipped": 0,
        "connection_attempts": sessions.attempts,
        "physical_closures": sessions.closed,
        "results": results,
    }
    p = STATE / "integrity-results.json"
    p.write_text(json.dumps(summary, indent=2))
    p.chmod(0o600)
    print({k: v for k, v in summary.items() if k != "results"})
    return bool(summary["failed"])


if __name__ == "__main__":
    sys.exit(main())
