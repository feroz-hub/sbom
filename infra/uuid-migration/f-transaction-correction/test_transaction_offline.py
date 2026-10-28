"""Mocked transaction, source guard and actual inert SQLAlchemy binding tests."""

from __future__ import annotations

import ast
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import Mock

import connection as cx
import dialect as corrected_dialect
import kernel as k
import lifecycle as lc
import metering
import recipe
import review

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "infra/uuid-migration/f-budget-reconciliation"))
import accounting as ac
import budget_policy as bp
from review_inputs import adapters
from scoped_meter import create_meter

MOD, REG, OLD = adapters(ROOT)
PLAN = ac.build(ROOT)
PARSER = MOD["source_registry"].reference_api(ROOT, REG)["pg_lex"].statements
Q = "SELECT 1"
DDL = "ALTER TABLE public.tenants ADD COLUMN synthetic integer"
MARKER = "UPDATE public.alembic_version SET version_num=%s WHERE version_num=%s RETURNING version_num"


def make_meter(sqls=(Q, DDL, MARKER), revision="080_uuid_public_id_expand", action="unit_execute"):
    allowed = {name: [hashlib.sha256(s.encode()).hexdigest() for s in sqls] for name in OLD["transport"].CATEGORIES}
    scoped = create_meter(OLD["transport"].Meter, PLAN, revision, action, allowed, PARSER)
    return metering.wrap(type(scoped))()


class Raw:
    def __init__(self):
        self.autocommit, self.isolation_level, self.read_only, self.closed = False, 2, True, False
        self.prepare_threshold = None
        self.info = NS(transaction_status="IDLE")
        self.calls, self.pending, self.committed = [], [], []
        self.raise_commit = self.raise_rollback = self.raise_query = False

    def cursor(self):
        return RawCursor(self)

    def commit(self):
        self.calls.append("COMMIT")
        if self.raise_commit:
            raise RuntimeError("synthetic lost acknowledgment")
        self.committed.extend(self.pending)
        self.pending.clear()
        self.info.transaction_status = "IDLE"

    def rollback(self):
        self.calls.append("ROLLBACK")
        if self.raise_rollback:
            raise RuntimeError("synthetic rollback failure")
        self.pending.clear()
        self.info.transaction_status = "IDLE"

    def close(self):
        self.closed = True


class RawCursor:
    def __init__(self, raw):
        self.raw = raw
        self.rowcount = 1
        self.description = None

    def execute(self, sql, params=None):
        raw = self.raw
        if raw.info.transaction_status == "IDLE":
            raw.calls.append("IMPLICIT_BEGIN_RO" if raw.read_only else "IMPLICIT_BEGIN_RW")
            raw.info.transaction_status = "INTRANS"
        raw.calls.append(sql)
        if raw.raise_query:
            raw.info.transaction_status = "INERROR"
            raise ValueError("synthetic execute failure")
        if not sql.startswith("SELECT"):
            raw.pending.append((sql, params))

    def executemany(self, sql, params):
        for row in params:
            self.execute(sql, row)

    def close(self):
        pass


class Tx:
    def __init__(self, conn):
        self.conn = conn

    def commit(self):
        self.conn.driver.commit()
        self.conn.active = False

    def rollback(self):
        self.conn.driver.rollback()
        self.conn.active = False


class Connection:
    def __init__(self, driver):
        self.driver, self.active, self.closed = driver, False, False
        self.connection = NS(driver_connection=driver)
        self.dialect = NS(name="postgresql")
        self.isolation = "READ COMMITTED"

    def begin(self):
        if self.active:
            raise ValueError("SQLAlchemy autobegin already active")
        self.active = True
        return Tx(self)

    def in_transaction(self):
        return self.active

    def get_execution_options(self):
        return {"isolation_level": self.isolation}

    def execute(self, sql, params=None):
        self.driver.cursor().execute(sql, params)

    def close(self):
        self.closed = True


def fixture(revision="080_uuid_public_id_expand", action="unit_execute"):
    raw, meter, journal = Raw(), make_meter(revision=revision, action=action), Mock()
    meter.journal = journal
    driver = k.Driver(raw, meter, journal)
    conn, engine = Connection(driver), Mock()
    session = k.Session(conn, driver, engine, meter, journal)
    return NS(raw=raw, meter=meter, journal=journal, driver=driver, conn=conn, engine=engine, session=session)


def callbacks(f, *, body=None):
    return {
        "initialize": lambda c: c.execute(Q),
        "preflight": lambda c: c.execute(Q),
        "locks": lambda c: c.execute(Q),
        "locked": lambda c: c.execute(Q),
        "body": body or (lambda c: c.execute(DDL)),
        "post_body": lambda c: c.execute(Q),
        "marker": lambda c: marker(c, f.meter),
    }


def marker(c, meter):
    with meter.scope("marker_statements"):
        c.execute(MARKER, ("NEXT", "PREVIOUS"))
    c.execute(Q)


def run(f, **changes):
    options = callbacks(f)
    options.update(changes)
    return lc.stage(f.session, Mock(), f.journal, **options)


class LifecycleTests(unittest.TestCase):
    def test_success_four_controls_atomic_marker_and_close(self):
        f = fixture()
        result = run(f)
        self.assertEqual(result["outcome"], "COMMITTED_UNVERIFIED")
        self.assertFalse(result["accepted"])
        self.assertTrue(result["closed"])
        self.assertEqual(f.meter.counts["transaction_controls"], 4)
        self.assertEqual(f.raw.calls.count("IMPLICIT_BEGIN_RO"), 1)
        self.assertEqual(f.raw.calls.count("IMPLICIT_BEGIN_RW"), 1)
        self.assertEqual(f.raw.calls.count("COMMIT"), 1)
        self.assertEqual(f.raw.committed, [(DDL, None), (MARKER, ("NEXT", "PREVIOUS"))])
        self.assertTrue(f.conn.closed)
        f.engine.dispose.assert_called_once()

    def test_precommit_failure_rolls_back_both_schema_and_marker(self):
        f = fixture()

        def failed_marker(c):
            marker(c, f.meter)
            raise ValueError("precommit stop")

        result = run(f, marker=failed_marker)
        self.assertEqual(result["outcome"], "ROLLED_BACK_UNVERIFIED")
        self.assertEqual(f.raw.committed, [])
        self.assertEqual(f.raw.pending, [])
        self.assertNotIn("COMMIT", f.raw.calls)

    def test_unknown_commit_no_retry_or_rollback(self):
        f = fixture()
        f.raw.raise_commit = True
        result = run(f)
        self.assertEqual(result["outcome"], "UNKNOWN_COMMIT_MANUAL_RECONCILIATION")
        self.assertEqual(f.raw.calls.count("ROLLBACK"), 1)  # preflight only
        self.assertEqual(f.raw.calls.count("COMMIT"), 1)
        self.assertTrue(f.raw.closed)

    def test_rollback_failure_manual_reconciliation(self):
        f = fixture()

        def failed_body(c):
            f.raw.raise_rollback = True
            raise ValueError("body rejected")

        result = run(f, body=failed_body)
        self.assertEqual(result["outcome"], "ROLLBACK_UNCONFIRMED_MANUAL_RECONCILIATION")
        self.assertTrue(f.raw.closed)

    def test_commit_evidence_failure_preserves_commit_fact(self):
        f = fixture()

        def record(phase, **_):
            if phase == "COMMIT_ACKNOWLEDGED":
                raise OSError("fsync unavailable")

        f.journal.record.side_effect = record
        result = run(f)
        self.assertEqual(result["outcome"], "COMMITTED_EVIDENCE_INCOMPLETE")
        self.assertEqual(len(f.raw.committed), 2)
        self.assertEqual(f.raw.calls.count("ROLLBACK"), 1)

    def test_precommit_journal_failure_prevents_commit(self):
        f = fixture()
        f.journal.record.side_effect = lambda phase, **_: (
            (_ for _ in ()).throw(OSError()) if phase == "COMMIT_REQUESTED" else None
        )
        result = run(f)
        self.assertIn("ROLLED_BACK", result["outcome"])
        self.assertNotIn("COMMIT", f.raw.calls)

    def test_initializer_may_not_rollback(self):
        f = fixture()
        result = run(f, initialize=lambda c: c.driver.rollback())
        self.assertNotIn("COMMIT", f.raw.calls)
        self.assertFalse(result["accepted"])

    def test_readback_separate_budget_no_internal_connection(self):
        f = fixture(action="unit_readback")
        result = lc.read_only(
            f.session,
            NS(action="unit_readback", recheck=lambda: None),
            f.journal,
            initialize=lambda c: c.execute(Q),
            observe=lambda c: c.execute(Q),
        )
        self.assertFalse(result["accepted"])
        self.assertEqual(f.meter.counts["transaction_controls"], 2)
        self.assertEqual(f.meter.phase_counts["initialization"], 1)
        self.assertEqual(f.meter.phase_counts["readback"], 1)
        self.assertTrue(f.raw.closed)

    def test_query_error_after_begin_still_rolls_back(self):
        f = fixture()
        f.raw.raise_query = True
        result = run(f)
        self.assertIn("ROLLED_BACK", result["outcome"])
        self.assertEqual(f.raw.calls.count("ROLLBACK"), 1)

    def test_authority_drift_prevents_ddl(self):
        f = fixture()
        a = Mock()
        a.recheck.side_effect = [None, None, ValueError("changed raw manifest/source/role")]
        result = lc.stage(f.session, a, f.journal, **callbacks(f))
        self.assertFalse(result["accepted"])
        self.assertNotIn(DDL, f.raw.calls)


class StateTests(unittest.TestCase):
    def test_autocommit_true_refused(self):
        f = fixture()
        f.raw.autocommit = True
        with self.assertRaises(ValueError):
            k.Driver(f.raw, f.meter, f.journal)

    def test_wrong_isolation_refused(self):
        for value in (None, 1, 3, 4, "AUTOCOMMIT"):
            f = fixture()
            f.raw.isolation_level = value
            with self.assertRaises(ValueError):
                k.Driver(f.raw, f.meter, f.journal)

    def test_unexpected_backend_open_transaction(self):
        f = fixture()
        f.raw.info.transaction_status = "INTRANS"
        with self.assertRaises(ValueError):
            f.session.begin("ro")

    def test_sqlalchemy_autobegin_refused(self):
        f = fixture()
        f.conn.active = True
        with self.assertRaises(ValueError):
            f.session.begin("ro")

    def test_sqlalchemy_autocommit_refused(self):
        f = fixture()
        f.conn.isolation = "AUTOCOMMIT"
        with self.assertRaises(ValueError):
            k.Session(f.conn, f.driver, f.engine, f.meter, f.journal)

    def test_literal_begin_rejected_before_wire(self):
        f = fixture()
        f.session.begin("ro")
        with self.assertRaises(ValueError):
            f.conn.execute("BEGIN READ ONLY")
        self.assertEqual(f.raw.calls, [])

    def test_rw_without_preflight_rejected(self):
        with self.assertRaises(ValueError):
            fixture().session.begin("rw")

    def test_unowned_commit_and_rollback_rejected(self):
        f = fixture()
        for operation in (f.driver.commit, f.driver.rollback):
            with self.assertRaises(ValueError):
                operation()
        self.assertEqual(f.raw.calls, [])

    def test_driver_bypasses_refused(self):
        for name in ("execute", "transaction", "pipeline", "copy", "pgconn", "cancel", "tpc_begin"):
            with self.assertRaises(ValueError):
                getattr(fixture().driver, name)

    def test_ambiguous_status_refused(self):
        for value in ("UNKNOWN", "ACTIVE", "synthetic"):
            f = fixture()
            f.raw.info.transaction_status = value
            with self.assertRaises(ValueError):
                f.session.begin("ro")

    def test_nonquery_in_readonly_refused(self):
        f = fixture()
        f.session.begin("ro")
        with f.meter.scope("migration_statements"), self.assertRaises(ValueError):
            f.conn.execute(DDL)
        self.assertEqual(f.raw.calls, [])

    def test_no_second_implicit_begin(self):
        f = fixture()
        f.session.begin("ro")
        with f.meter.phase("preflight"):
            f.conn.execute(Q)
            f.raw.info.transaction_status = "IDLE"
            with self.assertRaises(ValueError):
                f.conn.execute(Q)

    def test_autocommit_cannot_change(self):
        f = fixture()
        with self.assertRaises(ValueError):
            f.driver.autocommit = True


class MeterTests(unittest.TestCase):
    def test_init_phase_exhaustion_before_driver(self):
        f = fixture()
        f.session.begin("ro")
        f.meter.phase_caps["initialization"] = 1
        with f.meter.phase("initialization"):
            f.conn.execute(Q)
            before = list(f.raw.calls)
            with self.assertRaises(ValueError):
                f.conn.execute(Q)
            self.assertEqual(f.raw.calls, before)

    def test_budget_failure_rolls_back_and_closes(self):
        f = fixture()
        f.meter.phase_caps["post_body"] = 0
        result = run(f)
        self.assertIn("ROLLED_BACK", result["outcome"])
        self.assertEqual(f.raw.committed, [])
        self.assertTrue(f.raw.closed)

    def test_executemany_counted_exactly_once(self):
        f = fixture()
        f.session.begin("ro")
        with f.meter.phase("initialization"):
            f.driver.cursor().executemany(Q, [(), (), ()])
        self.assertEqual(f.meter.counts["catalog_queries"], 3)
        self.assertEqual(f.meter.phase_counts["initialization"], 3)
        self.assertEqual(f.meter.counts["transaction_controls"], 1)

    def test_exact_sql_allowlist_preserved(self):
        f = fixture()
        f.session.begin("ro")
        with f.meter.phase("preflight"), self.assertRaises(ValueError):
            f.conn.execute("SELECT 2")
        self.assertEqual(f.raw.calls, [])

    def test_time_budget_preserved(self):
        f = fixture()
        f.meter.started -= f.meter.limits["cooperative_unit_seconds"]
        with self.assertRaises(ValueError):
            f.session.begin("ro")

    def test_control_budget_no_extra_transaction(self):
        f = fixture()
        f.meter.limits["transaction_controls"] = 1
        result = run(f)
        self.assertNotIn("COMMIT", f.raw.calls)
        self.assertFalse(result["accepted"])

    def test_every_45_unit_nonquery_limit_unchanged(self):
        for row in PLAN["rows"]:
            for action in ac.ACTIONS:
                limits = bp.select(PLAN, row["unit"], action)["limits"]
                for key, value in row["old_limits"].items():
                    if key != "catalog_queries":
                        self.assertEqual(limits[key], value)


class SourceTests(unittest.TestCase):
    def test_live_cli_denies(self):
        with self.assertRaises(ValueError):
            lc.main(["--mode", "live"])

    def test_old_live_denials_unchanged(self):
        with self.assertRaises(SystemExit):
            OLD["activation"].main(["--mode", "live"])

    def test_recipe_no_factory_or_connector_on_import(self):
        tree = ast.parse(Path(recipe.__file__).read_text())
        self.assertFalse(any(isinstance(n, ast.Import) for n in tree.body))
        self.assertTrue(all(not isinstance(n, ast.Expr) or isinstance(n.value, ast.Constant) for n in tree.body))

    def test_recipe_exact_one_creator_and_no_engine_connect(self):
        f = fixture()
        pool_factory = Mock(side_effect=lambda **kwargs: NS(**kwargs))
        engine_factory = Mock(side_effect=lambda **kwargs: NS(**kwargs))

        def connection_factory(engine, **kwargs):
            self.assertEqual(kwargs, {"_allow_revalidate": False})
            engine.pool.creator()
            return f.conn

        conn, engine = recipe.bind(
            f.driver,
            dialect_factory=lambda: NS(name="postgresql", on_connect=lambda: None),
            pool_factory=pool_factory,
            engine_factory=engine_factory,
            url_factory=str,
            connection_factory=connection_factory,
        )
        self.assertIs(conn, f.conn)
        with self.assertRaises(ValueError):
            engine.pool.creator()
        self.assertIsNone(engine.pool.reset_on_return)


class ConnectionTests(unittest.TestCase):
    def test_exact_one_attempt_no_retry_and_erasure(self):
        f = fixture()
        args = {
            "host": "127.0.0.1",
            "hostaddr": "127.0.0.1",
            "port": 56043,
            "dbname": "uuid_w2_f_fresh",
            "user": "uuid_w2_f_bootstrap",
            "passfile": "/dev/null",
            "sslmode": "disable",
            "gssencmode": "disable",
            "connect_timeout": 5,
            "application_name": "sbom_w24a_f_unit",
            "options": "SYNTHETIC_PINNED_READ_ONLY_OPTIONS",
            "autocommit": False,
        }
        secret = bytearray(b"SYNTHETIC")
        connector = Mock(side_effect=ValueError("synthetic failure"))
        with self.assertRaises(ValueError):
            cx.once(
                Mock(),
                approved_options=args,
                expected_options=args,
                clean_environment=lambda _: None,
                environment={},
                resource_gate=lambda _: None,
                secret=secret,
                connector=connector,
                meter=f.meter,
                journal=f.journal,
            )
        connector.assert_called_once()
        self.assertEqual(secret, bytearray(len(secret)))
        self.assertEqual(f.meter.counts["attempts"], 1)

    def test_wrong_f_target_and_service_refused_before_connector(self):
        for key, value in (
            ("port", 56042),
            ("host", "localhost"),
            ("dbname", "uuid_w1_d_rehearsal"),
            ("user", "postgres"),
            ("service", ""),
            ("autocommit", True),
        ):
            f = fixture()
            args = {
                "host": "127.0.0.1",
                "hostaddr": "127.0.0.1",
                "port": 56043,
                "dbname": "uuid_w2_f_fresh",
                "user": "uuid_w2_f_bootstrap",
                "passfile": "/dev/null",
                "sslmode": "disable",
                "gssencmode": "disable",
                "connect_timeout": 5,
                "application_name": "sbom_w24a_f_unit",
                "options": "SYNTHETIC_PINNED_READ_ONLY_OPTIONS",
                "autocommit": False,
            }
            args[key] = value
            connector = Mock()
            with self.assertRaises(ValueError):
                cx.once(
                    Mock(),
                    approved_options=args,
                    expected_options=args,
                    clean_environment=lambda _: None,
                    environment={},
                    resource_gate=lambda _: None,
                    secret=bytearray(b"SYNTHETIC"),
                    connector=connector,
                    meter=f.meter,
                    journal=f.journal,
                )
            connector.assert_not_called()

    def test_all_meaningful_original_options_preserved(self):
        old = {"autocommit": True, "options": "SYNTHETIC_PINNED_SETTINGS", "application_name": "sbom_w24a_f_unit"}
        self.assertEqual(cx.options(None, lambda _: old), {**old, "autocommit": False})
        self.assertIs(old["autocommit"], True)

    def test_clean_environment_refusal_before_connection(self):
        f = fixture()
        args = {
            "host": "127.0.0.1",
            "hostaddr": "127.0.0.1",
            "port": 56043,
            "dbname": "uuid_w2_f_fresh",
            "user": "uuid_w2_f_bootstrap",
            "passfile": "/dev/null",
            "sslmode": "disable",
            "gssencmode": "disable",
            "connect_timeout": 5,
            "application_name": "sbom_w24a_f_unit",
            "options": "SYNTHETIC_PINNED_READ_ONLY_OPTIONS",
            "autocommit": False,
        }
        connector = Mock()
        with self.assertRaises(ValueError):
            cx.once(
                Mock(),
                approved_options=args,
                expected_options=args,
                clean_environment=OLD["security"].clean_environment,
                environment={"PGHOST": "synthetic"},
                resource_gate=lambda _: None,
                secret=bytearray(b"SYNTHETIC"),
                connector=connector,
                meter=f.meter,
                journal=f.journal,
            )
        connector.assert_not_called()


class RealSQLAlchemyOfflineTests(unittest.TestCase):
    def test_real_logical_transactions_and_alembic_operations_on_fake_driver(self):
        import psycopg
        from alembic.migration import MigrationContext
        from alembic.operations import Operations
        from sqlalchemy.dialects.postgresql.psycopg import PGDialect_psycopg
        from sqlalchemy.engine import Connection as SAConnection
        from sqlalchemy.engine import Engine, make_url
        from sqlalchemy.pool import NullPool

        f = fixture()
        # Actual SQLAlchemy Engine/Connection/transaction and Operations objects;
        # only a synthetic DBAPI driver underneath, no engine.connect/real driver.
        d = PGDialect_psycopg(dbapi=psycopg)
        d.on_connect = lambda: None
        conn, engine = recipe.bind(
            f.driver,
            dialect_factory=lambda: d,
            pool_factory=NullPool,
            engine_factory=Engine,
            url_factory=make_url,
            connection_factory=SAConnection,
        )
        session = k.Session(conn, f.driver, engine, f.meter, f.journal)
        session.begin("ro")
        session.initialize(lambda c: c.exec_driver_sql(Q))
        session.finish_readonly()
        session.begin("rw")
        with f.meter.phase("coordinator"):
            conn.exec_driver_sql(Q)
        context = MigrationContext.configure(connection=conn, opts={"transactional_ddl": True, "as_sql": False})
        self.assertTrue(context.impl.transactional_ddl)
        self.assertTrue(conn.in_transaction())
        self.assertFalse(conn.connection.driver_connection.autocommit)
        with f.meter.scope("migration_statements"):
            Operations(context).execute(DDL)
        session.end("commit")
        session.close()
        self.assertEqual(f.raw.committed, [(DDL, {})])
        self.assertEqual(f.meter.counts["transaction_controls"], 4)


def guard_test(path, valid, autocommit=False, isolation="READ COMMITTED", active=True, ddl=True):
    def test(self):
        tree = ast.parse(path.read_text())
        upgrade = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "upgrade")
        final = 86 <= int(path.name[:3]) <= 91
        # Execute ONLY the original transaction-guard AST, never the migration
        # body, approval helper, SQL, metadata mutation or historical module.
        if final:
            guard = next(
                n
                for n in upgrade.body
                if isinstance(n, ast.Expr)
                and isinstance(n.value, ast.Call)
                and any(
                    isinstance(c, ast.Constant) and c.value == "One owned transaction required" for c in ast.walk(n)
                )
            )
        else:
            guard = next(
                n
                for n in upgrade.body
                if isinstance(n, ast.If)
                and any(
                    isinstance(c, ast.Constant) and c.value == "UUID expand refuses non-transactional execution"
                    for c in ast.walk(n)
                )
            )
        bind = NS(
            in_transaction=lambda: active,
            get_execution_options=lambda: {"isolation_level": isolation},
            connection=NS(driver_connection=NS(autocommit=autocommit)),
        )
        context = NS(impl=NS(transactional_ddl=ddl))
        code = compile(ast.Module(body=[guard], type_ignores=[]), str(path), "exec")
        namespace = {
            "bind": bind,
            "driver": bind.connection.driver_connection,
            "context": context,
            "_require": k.require,
        }
        if valid:
            exec(code, namespace)
        else:
            with self.assertRaises((ValueError, RuntimeError)):
                exec(code, namespace)

    return test


class GuardTests(unittest.TestCase):
    pass


for unit in REG["units"]:
    if unit["kind"] not in {"uuid_expand", "uuid_finalize"}:
        continue
    path = ROOT / unit["source"]
    for name, valid, args in (
        ("valid", True, {}),
        ("autocommit", False, {"autocommit": True}),
        ("isolation", False, {"isolation": "AUTOCOMMIT"}),
        ("inactive", False, {"active": False}),
    ):
        setattr(GuardTests, "test_" + path.stem + "_" + name, guard_test(path, valid, **args))


def family_test(sql):
    def test(self):
        meter = make_meter((sql,))  # even an exact SQL hash cannot bypass family classification
        with meter.scope("migration_statements"), self.assertRaises(ValueError):
            meter.driver(sql, None, False)
        self.assertEqual(sum(meter.counts.values()), 0)

    return test


class RejectedFamilyTests(unittest.TestCase):
    pass


for i, sql in enumerate(
    (
        "WITH q AS (SELECT 1) SELECT * FROM q",
        "WITH q AS (DELETE FROM t RETURNING *) SELECT * FROM q",
        "VALUES (1)",
        "TABLE public.tenants",
        "EXPLAIN SELECT 1",
        "EXPLAIN ANALYZE DELETE FROM t",
        "CALL unsafe()",
        "COPY public.tenants TO STDOUT",
        "SELECT 1; SELECT 2",
    )
):
    setattr(RejectedFamilyTests, "test_family_" + str(i), family_test(sql))


class AdditionalSafetyTests(unittest.TestCase):
    def test_second_write_transaction_refused(self):
        f = fixture()
        run(f)
        with self.assertRaises(ValueError):
            f.session.begin("rw")

    def test_same_identity_session_autocommit_stays_false(self):
        f = fixture()
        run(f)
        self.assertIs(f.raw.autocommit, False)
        self.assertEqual(f.raw.isolation_level, 2)

    def test_driver_nontransactional_ddl_guard_refusal(self):
        for unit in REG["units"]:
            if unit["kind"] == "uuid_expand":
                guard_test(ROOT / unit["source"], False, ddl=False)(self)

    def test_automatic_prepare_refused(self):
        f = fixture()
        f.raw.prepare_threshold = 5
        with self.assertRaises(ValueError):
            k.Driver(f.raw, f.meter, f.journal)

    def test_characteristic_drift_refused_before_wire(self):
        f = fixture()
        f.session.begin("ro")
        f.raw.read_only = False
        with f.meter.phase("preflight"), self.assertRaises(ValueError):
            f.conn.execute(Q)
        self.assertEqual(f.raw.calls, [])

    def test_sql_journal_failure_prevents_driver_call(self):
        f = fixture()

        def record(phase, **_):
            if phase == "SQL_REQUESTED":
                raise OSError("fsync failure")

        f.journal.record.side_effect = record
        result = run(f)
        self.assertFalse(result["accepted"])
        self.assertEqual(f.raw.calls, [])
        self.assertTrue(f.raw.closed)

    def test_physical_close_failure_does_not_skip_disposal(self):
        f = fixture()
        f.raw.close = Mock(side_effect=OSError("synthetic close failure"))
        result = run(f)
        self.assertIn("CLOSURE_INCOMPLETE", result["outcome"])
        f.engine.dispose.assert_called_once()

    def test_unbounded_executemany_refused(self):
        f = fixture()
        f.session.begin("ro")
        with f.meter.phase("preflight"), self.assertRaises(ValueError):
            f.driver.cursor().executemany(Q, (x for x in [()]))
        self.assertEqual(f.raw.calls, [])

    def test_factory_failure_closes_driver(self):
        f = fixture()
        with self.assertRaises(ValueError):
            recipe.bind(
                f.driver,
                dialect_factory=lambda: NS(name="wrong"),
                pool_factory=Mock(),
                engine_factory=Mock(),
                url_factory=str,
                connection_factory=Mock(),
            )
        self.assertTrue(f.raw.closed)


class UnitLifecycleTests(unittest.TestCase):
    pass


def lifecycle_test(revision):
    def test(self):
        f = fixture(revision)
        result = run(f)
        self.assertEqual(result["outcome"], "COMMITTED_UNVERIFIED")
        self.assertEqual(f.meter.counts["transaction_controls"], 4)
        self.assertTrue(f.raw.closed)

    return test


for row in PLAN["rows"]:
    setattr(UnitLifecycleTests, "test_" + row["unit"], lifecycle_test(row["unit"]))


class TypeDiscoveryTests(unittest.TestCase):
    def lookup(self, rows, name="hstore", active=True):
        from sqlalchemy import text

        base = type("SyntheticBase", (), {})
        ctor = Mock(side_effect=lambda **kwargs: NS(**kwargs))
        cls = corrected_dialect.factory(base, text, ctor)
        conn = Mock()
        conn.in_transaction.return_value = active
        conn.execute.return_value.mappings.return_value.all.return_value = rows
        result = cls()._type_info_fetch(conn, name)
        return result, conn, ctor

    def test_absent_hstore_stays_absent_no_native_cursor(self):
        result, conn, ctor = self.lookup([])
        self.assertIsNone(result)
        conn.execute.assert_called_once()
        ctor.assert_not_called()
        self.assertEqual(conn.execute.call_args.args[0].text, corrected_dialect.TYPE_SQL)
        self.assertEqual(conn.execute.call_args.args[1], {"name": "hstore"})

    def test_existing_type_properties_preserved(self):
        row = {"name": "hstore", "oid": 12345, "array_oid": 12346, "regtype": "hstore", "delimiter": ","}
        result, conn, ctor = self.lookup([row])
        ctor.assert_called_once_with(**row)
        self.assertEqual(result.oid, 12345)

    def test_bad_type_shape_refused(self):
        with self.assertRaises(ValueError):
            self.lookup([{"name": "hstore"}])

    def test_multiple_types_refused(self):
        with self.assertRaises(ValueError):
            self.lookup([{}, {}])

    def test_other_native_lookup_refused(self):
        with self.assertRaises(ValueError):
            self.lookup([], "other")

    def test_no_lookup_outside_owned_transaction(self):
        with self.assertRaises(ValueError):
            self.lookup([], active=False)

    def test_exact_psycopg_driver_template(self):
        from sqlalchemy import text
        from sqlalchemy.dialects.postgresql.psycopg import PGDialect_psycopg

        compiled = text(corrected_dialect.TYPE_SQL).compile(dialect=PGDialect_psycopg())
        self.assertIn("%(name)s", str(compiled))
        self.assertTrue(str(compiled).startswith("SELECT "))


class InitCursor(RawCursor):
    def execute(self, sql, params=None):
        super().execute(sql, params)
        values = {
            "select pg_catalog.version()": ("PostgreSQL 16.15 on SYNTHETIC",),
            "select current_schema()": ("pg_catalog",),
            "show transaction isolation level": ("read committed",),
            "show standard_conforming_strings": ("on",),
        }
        self.rows = [values[sql]] if sql in values else []
        self.description = [("synthetic", None, None, None, None, None, None)]
        if sql.startswith("SELECT typname"):
            self.description = [
                (n, None, None, None, None, None, None) for n in ("name", "oid", "array_oid", "regtype", "delimiter")
            ]

    def fetchone(self):
        return self.rows.pop(0) if self.rows else None

    def fetchall(self):
        rows, self.rows = self.rows, []
        return rows


class FullInitializerTests(unittest.TestCase):
    def test_installed_dialect_initialize_in_same_readonly_transaction(self):
        import psycopg
        from psycopg.types import TypeInfo
        from sqlalchemy import text
        from sqlalchemy.dialects.postgresql.psycopg import PGDialect_psycopg
        from sqlalchemy.engine import Connection as SAConnection
        from sqlalchemy.engine import Engine, make_url
        from sqlalchemy.pool import NullPool

        f = fixture()
        f.raw.cursor = lambda: InitCursor(f.raw)
        f.raw.add_notice_handler = Mock()
        cls = corrected_dialect.factory(PGDialect_psycopg, text, TypeInfo)
        d = cls(dbapi=psycopg)
        driver_sql = str(text(corrected_dialect.TYPE_SQL).compile(dialect=d))
        core = (
            "select pg_catalog.version()",
            "select current_schema()",
            "show transaction isolation level",
            "show standard_conforming_strings",
            driver_sql,
        )
        for sql in core:
            f.meter.allowlist["catalog_queries"].append(hashlib.sha256(sql.encode()).hexdigest())
        conn, engine = recipe.bind(
            f.driver,
            dialect_factory=lambda: d,
            pool_factory=NullPool,
            engine_factory=Engine,
            url_factory=make_url,
            connection_factory=SAConnection,
        )
        session = k.Session(conn, f.driver, engine, f.meter, f.journal)
        session.begin("ro")
        session.initialize(recipe.initializer)
        self.assertEqual(d.server_version_info, (16, 15))
        self.assertEqual(f.meter.phase_counts["initialization"], 5)
        self.assertEqual(f.raw.calls.count("ROLLBACK"), 0)
        self.assertFalse(d._has_native_hstore)
        self.assertEqual(f.meter.counts["transaction_controls"], 1)
        session.finish_readonly()
        session.close()
        self.assertEqual(f.raw.calls.count("ROLLBACK"), 1)
        self.assertEqual(f.meter.counts["transaction_controls"], 2)


class TransitionTests(unittest.TestCase):
    def test_all_future_sources_ast_and_hashes(self):
        path = Path(__file__).parent / "execution-transition.v3.proposed.json"
        data = json.loads(path.read_bytes())
        self.assertFalse(data["accepted"])
        self.assertEqual(data["approvals"], {})
        for dest, item in data["files"].items():
            ast.parse(item["proposed_source"])
            self.assertEqual(hashlib.sha256(item["proposed_source"].encode()).hexdigest(), item["proposed_sha256"])
            self.assertFalse((ROOT / dest).exists())

    def test_all_authority_lock_body_and_marker_boundaries_retained(self):
        data = json.loads((Path(__file__).parent / "execution-transition.v3.proposed.json").read_bytes())
        source = data["files"]["infra/uuid-migration/f-execution-v3/activation.py"]["proposed_source"]
        self.assertNotIn("control(connection, meter,", source)
        self.assertNotIn('with meter.phase("initialization")', source)
        for required in (
            "meter.assert_authority",
            "resource_gate(authority)",
            "authority.recheck()",
            "catalog.VERSION_LOCK",
            "SHARE MODE NOWAIT",
            "finalization_context",
            "len(body) == 558",
            "marker_rows(result",
            "COMMIT_REQUESTED",
            "UNKNOWN_COMMIT_MANUAL_RECONCILIATION",
            "transport.close()",
            "unit_readback",
        ):
            self.assertIn(required, source)

    def test_v4_lock_pins_exact_new_source_bytes(self):
        lock = json.loads((Path(__file__).parent / "source-lock.v4.proposed.json").read_bytes())
        for rel, expected in lock["transaction_sources"].items():
            self.assertEqual(hashlib.sha256((ROOT / rel).read_bytes()).hexdigest(), expected)
        parent = ROOT / lock["parent_source_lock"]
        self.assertEqual(hashlib.sha256(parent.read_bytes()).hexdigest(), lock["parent_byte_sha256"])
        self.assertEqual(json.loads(parent.read_bytes()), lock["parent_unchanged"])

    def test_pinned_prior_packages_and_all_twelve_guards(self):
        result = review.inspect(ROOT)
        self.assertEqual(result["historical_pins"], 113)
        self.assertEqual(len(result["guards"]), 12)
        self.assertEqual(result["connections"], 0)

    def test_actual_installed_dependency_source_bytes(self):
        from importlib.metadata import distribution

        data = json.loads((Path(__file__).parent / "dependency-review.v1.json").read_bytes())
        for name, pins in data["dependencies"].items():
            dist = distribution(name)
            self.assertEqual(dist.version, pins["version"])
            for rel, expected in pins["files"].items():
                self.assertEqual(hashlib.sha256(Path(dist.locate_file(rel)).read_bytes()).hexdigest(), expected)

    def test_review_live_denied(self):
        with self.assertRaises(ValueError):
            review.main(["--mode", "live"])

    def test_no_approval_created(self):
        data = json.loads((Path(__file__).parent / "approval.pending.json").read_bytes())
        self.assertFalse(data["accepted"])
        self.assertFalse(data["live_enabled"])
        self.assertEqual(data["execution_approvals"], {})
        self.assertEqual(data["integrity_approvals"], {})
        self.assertEqual(data["integrity_attestations"], [False] * 7)
        self.assertIsNone(data["actual_f_cluster_id"])
        self.assertIsNone(data["operator_approved_manifest_byte_sha256"])


class DurableJournalTests(unittest.TestCase):
    def journal_fixture(self, directory, action="unit_execute"):
        f = fixture(action=action)
        journal = OLD["journal"].Journal(directory, "a" * 64, "SYNTHETIC_OFFLINE_ONLY")
        f.journal = f.driver.journal = f.session.journal = f.meter.journal = journal
        return f, journal

    def test_real_durable_journal_accepts_proposed_write_phases(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = str(Path(directory).resolve())
            Path(directory).chmod(0o700)
            f, journal = self.journal_fixture(directory)
            try:
                result = run(f)
            finally:
                journal.close()
            self.assertEqual(result["outcome"], "COMMITTED_UNVERIFIED")
            rows = [json.loads(line) for line in (Path(directory) / "unit-attempt.jsonl").read_text().splitlines()]
            self.assertEqual(sum(row["phase"] == "CONTROL_REQUESTED" for row in rows), 4)
            self.assertIn("COMMIT_ACKNOWLEDGED", [row["phase"] for row in rows])
            self.assertIn("CLOSED", [row["phase"] for row in rows])
            self.assertNotIn(DDL, json.dumps(rows))

    def test_real_durable_journal_accepts_proposed_readback_phases(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = str(Path(directory).resolve())
            Path(directory).chmod(0o700)
            f, journal = self.journal_fixture(directory, "unit_readback")
            try:
                result = lc.read_only(
                    f.session,
                    NS(action="unit_readback", recheck=lambda: None),
                    journal,
                    initialize=lambda c: c.execute(Q),
                    observe=lambda c: c.execute(Q),
                )
            finally:
                journal.close()
            self.assertFalse(result["accepted"])
            self.assertTrue(f.raw.closed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
