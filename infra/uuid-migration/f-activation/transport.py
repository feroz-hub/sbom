"""Driver-boundary metering and proposed owned SQLAlchemy transport.

No imports of drivers/SQLAlchemy at module load. Factories and connector are
injected. Only the driver proxy charges SQL; logical wrappers never charge it.
"""

from __future__ import annotations

import time
from contextlib import contextmanager

from security import clean_environment, require, sha

CATEGORIES = ("catalog_queries", "migration_statements", "marker_statements", "session_statements")
CONTROLS = {"BEGIN READ ONLY": "begin_ro", "BEGIN READ WRITE": "begin_rw", "ROLLBACK": "rollback", "COMMIT": "commit"}


class Meter:
    def __init__(self, limits, allowlist, parser, *, clock=time.monotonic, journal=None):
        self.limits, self.allowlist, self.parser = limits, allowlist, parser
        self.clock, self.started, self.journal = clock, clock(), journal
        self.counts = dict.fromkeys((*CATEGORIES, "attempts", "transaction_controls"), 0)
        self.category = "catalog_queries"
        self.cleanup = False
        self.control_owned = False
        self.transaction_open = False
        self.commit_sent = self.commit_ack = False

    def check(self):
        require(self.clock() - self.started < self.limits["cooperative_unit_seconds"], "Cooperative deadline exhausted")

    def charge(self, key, count=1):
        if not self.cleanup:
            self.check()
        require(type(count) is int and count > 0 and self.counts[key] + count <= self.limits[key], "Budget exhausted")
        self.counts[key] += count

    @contextmanager
    def scope(self, category):
        require(category in CATEGORIES, "Unknown SQL scope")
        old = self.category
        self.category = category
        try:
            yield
        finally:
            self.category = old

    @contextmanager
    def owned_control(self):
        require(not self.control_owned, "Nested transaction controller")
        self.control_owned = True
        try:
            yield
        finally:
            self.control_owned = False

    def driver(self, statement, parameters, many):
        require(isinstance(statement, str), "Only reviewed text driver SQL")
        control = statement.strip().rstrip(";").upper()
        if control in CONTROLS:
            require(self.control_owned, "Unowned transaction control")
            require(not many, "Batched transaction controls forbidden")
            require(control == "ROLLBACK" or not self.cleanup, "Only rollback may bypass deadline")
            require(control.startswith("BEGIN") != self.transaction_open, "Transaction ownership mismatch")
            if self.journal and not self.cleanup:
                self.check()
                require(
                    self.counts["transaction_controls"] < self.limits["transaction_controls"],
                    "Control budget exhausted",
                )
                self.journal.record("CONTROL_REQUESTED", control=CONTROLS[control])
            self.charge("transaction_controls")
            return
        self.check()
        require(not self.cleanup, "SQL after deadline/cleanup forbidden")
        parts = self.parser(statement if statement.rstrip().endswith(";") else statement + ";")
        require(len(parts) == 1, "Exactly one reviewed driver statement per call")
        first = parts[0].tokens[0].upper()
        require(
            first
            in {
                "SELECT",
                "SHOW",
                "WITH",
                "EXPLAIN",
                "CREATE",
                "ALTER",
                "DROP",
                "COMMENT",
                "INSERT",
                "UPDATE",
                "DELETE",
                "DO",
                "SET",
                "LOCK",
            },
            "Unreviewed SQL family",
        )
        category = "catalog_queries" if first in {"SELECT", "SHOW"} else self.category
        require(sha(statement.encode()) in self.allowlist[category], "Unreviewed exact driver SQL")
        if category != "catalog_queries":
            require(self.transaction_open, "Mutation/session SQL outside owned transaction")
        if category == "catalog_queries":
            require(first in {"SELECT", "SHOW"}, "Catalog scope must be SELECT/SHOW")
        if first in {"SELECT", "SHOW"}:
            require(category == "catalog_queries", "Read SQL must use query budget")
        count = 1
        if many:
            require(isinstance(parameters, (tuple, list)) and len(parameters) > 0, "Unbounded executemany refused")
            count = len(parameters)
        self.charge(category, count)
        if self.journal:
            self.journal.record("SQL_REQUESTED", category=category, count=count, sql_sha256=sha(statement.encode()))

    def acknowledged(self, statement):
        control = statement.strip().rstrip(";").upper()
        if control in CONTROLS:
            self.transaction_open = control.startswith("BEGIN")


class Cursor:
    def __init__(self, raw, meter):
        self._raw, self.meter = raw, meter

    def execute(self, statement, parameters=None, **kwargs):
        require(not kwargs, "Unreviewed driver execute options")
        self.meter.driver(statement, parameters, False)
        if statement.strip().rstrip(";").upper() == "COMMIT":
            self.meter.commit_sent = True
        self._raw.execute(statement, parameters)
        if statement.strip().rstrip(";").upper() == "COMMIT":
            self.meter.commit_ack = True
        self.meter.acknowledged(statement)
        return self

    def executemany(self, statement, parameters, **kwargs):
        require(not kwargs, "Unreviewed executemany options")
        self.meter.driver(statement, parameters, True)
        self._raw.executemany(statement, parameters)
        return self

    def __getattr__(self, name):
        require(name not in {"copy", "callproc", "nextset", "execute", "executemany"}, "Driver bypass refused")
        return getattr(self._raw, name)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self._raw.close()


class Driver:
    def __init__(self, raw, meter):
        require(raw.autocommit is True, "Dedicated AUTOCOMMIT transport required")
        self._raw, self.meter = raw, meter

    def cursor(self, *args, **kwargs):
        return Cursor(self._raw.cursor(*args, **kwargs), self.meter)

    def commit(self):
        raise ValueError("Use owned metered COMMIT SQL")

    def rollback(self):
        raise ValueError("Use owned metered ROLLBACK SQL; no implicit pool reset")

    def close(self):
        self._raw.close()
        require(bool(self._raw.closed), "Physical driver connection not closed")

    def __getattr__(self, name):
        require(
            name not in {"execute", "executemany", "transaction", "pipeline", "copy", "cancel"}, "Driver bypass refused"
        )
        return getattr(self._raw, name)

    @property
    def autocommit(self):
        return self._raw.autocommit

    @autocommit.setter
    def autocommit(self, value):
        require(value is True, "Transport autocommit cannot change")
        self._raw.autocommit = True


def connection_options(authority):
    """Explicit NEW transport proposal, not W2.3's mock connection receipt.

    AUTOCOMMIT transport is necessary to meter literal BEGIN/ROLLBACK/COMMIT.
    Unit transactions remain explicit, owned and atomic; this option must be
    separately approved in the activation wrapper, never silently substituted.
    """
    readback = authority.unit_authority.args[2] == "unit_readback"
    options = authority.modules["authority"].connection_contract(authority.unit_authority.unit, readback=readback)
    return {
        **options,
        "autocommit": True,
        "application_name": "sbom_w24a_f_readback" if readback else "sbom_w24a_f_unit",
    }


class Transport:
    """One creator attempt, no reconnect, no pool reset or implicit transaction.

    Factories are injected (future create_engine, NullPool, connector). Before
    first engine.connect, the DBAPI proxy meters dialect initialization too.
    Ordinary CLI never constructs this class. Runtime dialect compatibility is
    NOT accepted by mocked tests.
    """

    def __init__(self, *, connector, engine_factory, null_pool, options, secret, meter, environment):
        clean_environment(environment)
        require(
            set(options)
            == {
                "host",
                "hostaddr",
                "port",
                "dbname",
                "user",
                "passfile",
                "sslmode",
                "gssencmode",
                "connect_timeout",
                "autocommit",
                "application_name",
                "options",
            }
            and options["host"] == options["hostaddr"] == "127.0.0.1"
            and type(options["port"]) is int
            and options["port"] == 56043
            and options["dbname"] == "uuid_w2_f_fresh"
            and options["user"] == "uuid_w2_f_bootstrap"
            and options["passfile"] == "/dev/null"
            and options["sslmode"] == options["gssencmode"] == "disable"
            and options["connect_timeout"] == 5
            and options["autocommit"] is True
            and options["application_name"] in {"sbom_w24a_f_unit", "sbom_w24a_f_readback"},
            "Only explicit reviewed F transport eligible",
        )
        b = meter.limits
        expected_session = (
            f"-c default_transaction_read_only=on -c statement_timeout={b['statement_ms']} "
            f"-c lock_timeout={b['lock_ms']} -c idle_in_transaction_session_timeout={b['idle_transaction_ms']} "
            "-c search_path=pg_catalog -c row_security=on"
        )
        require(options["options"] == expected_session, "Session protections changed")
        self.connector, self.options, self.secret, self.meter = connector, dict(options), secret, meter
        self.driver = self.engine = self.connection = None
        self.engine_factory, self.null_pool = engine_factory, null_pool

    def _creator(self):
        password = None
        try:
            self.meter.charge("attempts")
            require(self.meter.counts["attempts"] == 1, "No second physical connection")
            # Inspect the actual future worker environment, not just a filtered
            # dictionary supplied by its caller. No worker is launched here.
            clean_environment(__import__("os").environ)
            password = bytes(self.secret).decode("ascii")
            raw = self.connector(**self.options, password=password)
            try:
                self.driver = Driver(raw, self.meter)
            except BaseException:
                raw.close()
                raise
            return self.driver
        finally:
            self.secret[:] = b"\0" * len(self.secret)
            password = None

    def open(self):
        require(self.engine is None, "Transport cannot reopen")
        self.engine = self.engine_factory(
            "postgresql+psycopg://",
            creator=self._creator,
            poolclass=self.null_pool,
            isolation_level="AUTOCOMMIT",
            skip_autocommit_rollback=True,
            pool_reset_on_return=None,
            echo=False,
            hide_parameters=True,
        )
        self.connection = self.engine.connect()
        return self.connection

    def close(self):
        errors = []
        for operation in (
            lambda: self.connection.close() if self.connection is not None else None,
            lambda: self.driver.close() if self.driver is not None and not self.driver.closed else None,
            lambda: self.engine.dispose(close=True) if self.engine is not None else None,
        ):
            try:
                operation()
            except BaseException as error:
                errors.append(type(error).__name__)
        self.secret[:] = b"\0" * len(self.secret)
        require(not errors, "Connection close/disposal incomplete")
