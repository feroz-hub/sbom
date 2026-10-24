"""Proposed non-autocommit transaction kernel. No default runtime providers.

SQLAlchemy begin() is a logical owner; psycopg emits its implicit BEGIN on the
first cursor query. Reserve that control before the query, never send BEGIN SQL.
Initialization and full read-only preflight share that first transaction.
"""

from __future__ import annotations

from contextlib import contextmanager


def require(value, reason):
    if not value:
        raise ValueError(reason)


def status(raw):
    value = raw.info.transaction_status
    name = getattr(value, "name", value)
    require(name in {"IDLE", "INTRANS", "INERROR"}, "Ambiguous/asynchronous transaction state")
    return name


class Cursor:
    def __init__(self, raw, owner):
        self.raw, self.owner = raw, owner

    def execute(self, sql, params=None, **kwargs):
        require(not kwargs, "Unreviewed execute options")
        self.owner.before(sql, params, False)
        try:
            self.raw.execute(sql, params)
        finally:
            self.owner.after_statement()
        return self

    def executemany(self, sql, params, **kwargs):
        require(not kwargs, "Unreviewed executemany options")
        self.owner.before(sql, params, True)
        try:
            self.raw.executemany(sql, params)
        finally:
            self.owner.after_statement()
        return self

    def __getattr__(self, name):
        require(
            name in {"description", "rowcount", "fetchone", "fetchmany", "fetchall", "close", "arraysize"},
            "Unreviewed cursor operation",
        )
        return getattr(self.raw, name)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.raw.close()


class Driver:
    """One connection, no SQL controls, no pipeline/TPC/COPY/native bypass.

    Real native-helper integration is a separate activation prerequisite. It
    must never unwrap this proxy to perform unmetered TypeInfo/reflection SQL.
    """

    def __init__(self, raw, meter, journal):
        require(raw.autocommit is False and status(raw) == "IDLE", "Idle autocommit=False required")
        require(meter.journal is journal, "One durable journal must cover all SQL and transaction phases")
        require(raw.isolation_level == 2, "psycopg READ_COMMITTED required")
        require(raw.prepare_threshold is None, "Automatic prepared-statement maintenance not approved")
        self.raw, self.meter, self.journal = raw, meter, journal
        self.mode = self.owner = None
        self.end_permission = None
        self.attempted_begin = False
        self.failed = False
        self.commit_sent = self.commit_ack = False
        self.rollback_ack = False

    @property
    def autocommit(self):
        return self.raw.autocommit

    @autocommit.setter
    def autocommit(self, _):
        raise ValueError("Isolation/autocommit changes refused after construction")

    def arm(self, mode):
        require(mode in {"ro", "rw"} and self.owner is None and not self.failed, "Invalid transaction owner")
        require(status(self.raw) == "IDLE" and not self.meter.transaction_open, "Unexpected open transaction")
        self.meter.check()
        self.raw.read_only = mode == "ro"  # psycopg property; legal only while IDLE
        require(self.raw.read_only is (mode == "ro"), "Read-only characteristic mismatch")
        self.mode = self.owner = mode
        self.attempted_begin = False

    def before(self, sql, params, many):
        require(self.owner in {"ro", "rw"} and not self.failed, "No owned transaction")
        require(self.raw.autocommit is False and self.raw.isolation_level == 2, "Driver isolation drift")
        require(self.raw.read_only is (self.mode == "ro"), "Driver read-only characteristic drift")
        require(self.mode != "ro" or self.meter.classify(sql) == "catalog_queries", "Nonquery in READ ONLY preflight")
        require(self.meter.classify(sql) != "transaction_controls", "Literal control forbidden; implicit BEGIN only")
        current = status(self.raw)
        require(current in {"IDLE", "INTRANS"}, "Aborted transaction")
        if current == "IDLE":
            require(not self.attempted_begin and not self.meter.transaction_open, "Unexpected implicit restart")
            # Reserve the statement first. Rejection cannot emit an implicit BEGIN.
            # Mutation is ineligible here; the first query is always SELECT/SHOW.
            require(self.meter.classify(sql) == "catalog_queries", "First operation must be a read")
            self.meter.driver(sql, params, many)
            with self.meter.owned_control():
                self.meter.driver("BEGIN READ ONLY" if self.mode == "ro" else "BEGIN READ WRITE", None, False)
            self.attempted_begin = True
            self.meter.transaction_open = True
        else:
            require(self.attempted_begin and self.meter.transaction_open, "Unowned backend transaction")
            self.meter.driver(sql, params, many)

    def after_statement(self):
        # A failed execute may already have started a transaction: cleanup must
        # consult actual PG status, not assume the cursor raised before BEGIN.
        current = status(self.raw)
        require(current in {"INTRANS", "INERROR"}, "Unexpected statement transaction outcome")

    def cursor(self, *args, **kwargs):
        require(not args and not kwargs, "Unreviewed cursor factory")
        return Cursor(self.raw.cursor(), self)

    @contextmanager
    def permit_end(self, kind):
        require(kind in {"commit", "rollback"} and self.end_permission is None, "Invalid end controller")
        self.end_permission = kind
        try:
            yield
        finally:
            self.end_permission = None

    def _end(self, kind):
        require(self.end_permission == kind and self.owner is not None, "Unowned DBAPI end")
        require(status(self.raw) in {"INTRANS", "INERROR"}, "No active backend transaction to end")
        require(kind == "rollback" or (self.owner == "rw" and status(self.raw) == "INTRANS"), "Unsafe COMMIT")
        with self.meter.owned_control():
            self.meter.driver(kind.upper(), None, False)
        if kind == "commit":
            self.commit_sent = self.meter.commit_sent = True
        try:
            getattr(self.raw, kind)()
            require(status(self.raw) == "IDLE", "End not acknowledged in IDLE state")
        except Exception:
            self.failed = True
            raise
        if kind == "commit":
            self.commit_ack = self.meter.commit_ack = True
        else:
            self.rollback_ack = True
        self.owner = None
        self.meter.transaction_open = False
        self.journal.record(kind.upper() + "_ACKNOWLEDGED")

    def commit(self):
        self._end("commit")

    def rollback(self):
        if self.raw.closed:
            return  # SQLAlchemy logical close AFTER physical close; no wire operation
        self._end("rollback")

    def close(self):
        self.raw.close()
        require(bool(self.raw.closed), "Physical connection closure failed")

    def __getattr__(self, name):
        require(name in {"info", "closed", "notices", "add_notice_handler", "adapters"}, "Unreviewed driver bypass")
        return getattr(self.raw, name)


class Session:
    """Own SQLAlchemy logical transactions and the corresponding one DBAPI tx.

    The injected connection is a dedicated, uninitialized SQLAlchemy Connection.
    Use recipe.py, not Engine.connect() with automatic dialect initialization.
    Initialization cannot commit/rollback or allocate another connection.
    """

    def __init__(self, connection, driver, engine, meter, journal):
        require(not connection.in_transaction(), "SQLAlchemy autobegin before ownership")
        require(connection.get_execution_options().get("isolation_level") != "AUTOCOMMIT", "Wrong SA isolation")
        require(connection.connection.driver_connection is driver, "Wrong SQLAlchemy driver")
        require(connection.dialect.name == "postgresql", "Wrong dialect")
        self.connection, self.driver, self.engine = connection, driver, engine
        self.meter, self.journal, self.tx = meter, journal, None
        self.initialized = self.ro_accepted = False
        self.ro_started = self.rw_started = False
        self.closed = False

    def begin(self, mode):
        require(self.tx is None and not self.connection.in_transaction(), "Unexpected SQLAlchemy autobegin")
        require(mode == "ro" if not self.ro_accepted else mode == "rw", "RO preflight must precede RW")
        require(not (self.ro_started if mode == "ro" else self.rw_started), "Second transaction of same kind refused")
        if mode == "ro":
            self.ro_started = True
        else:
            self.rw_started = True
        self.driver.arm(mode)
        self.tx = self.connection.begin()  # logical BEGIN only; PG begins at first cursor.execute
        require(self.connection.in_transaction() and status(self.driver.raw) == "IDLE", "Unexpected eager BEGIN")

    def initialize(self, callback):
        require(self.tx is not None and self.driver.owner == "ro" and not self.initialized, "Initializer order")
        with self.meter.phase("initialization"):
            callback(self.connection)
        require(self.connection.in_transaction() and self.driver.owner == "ro", "Initializer escaped ownership")
        self.initialized = True

    def finish_readonly(self):
        require(self.initialized and self.driver.owner == "ro", "Read-only preflight incomplete")
        self.end("rollback")
        self.ro_accepted = True

    def end(self, kind):
        require(self.tx is not None, "No logical transaction")
        with self.driver.permit_end(kind):
            getattr(self.tx, kind)()
        require(not self.connection.in_transaction(), "Logical transaction still active")
        self.tx = None

    def cleanup(self):
        if not self.driver.commit_sent and self.driver.owner and status(self.driver.raw) in {"INTRANS", "INERROR"}:
            self.meter.cleanup = True
            self.end("rollback")

    def close(self):
        errors = []
        # Physical close first: unknown COMMIT must not cause another wire SQL
        # via SQLAlchemy Connection.close()'s logical transaction cleanup.
        try:
            self.driver.close()
        except Exception as exc:
            errors.append(type(exc).__name__)
        for callback in (self.connection.close, self.engine.dispose):
            try:
                callback()
            except Exception as exc:
                errors.append(type(exc).__name__)
        self.closed = not errors
        require(not errors, "Closure/disposal incomplete: " + ",".join(errors))
