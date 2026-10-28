"""Installed SQLAlchemy/psycopg conversion with synthetic backend, no connections."""

from __future__ import annotations

import copy
import importlib.util
import io
import json
import traceback
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import Mock, patch

import psycopg
import w251_driver
import w251_entry
import w251_integration as integration
from psycopg._queries import PostgresQuery
from psycopg.adapt import Transformer
from sqlalchemy.util import immutabledict

_CACHE = None


def inputs():
    global _CACHE
    if _CACHE is None:
        r = integration.reviewed()
        t = integration.parent_module(
            "w25_test_support", json.loads((integration.PARENT / "source-lock.w25.v2.json").read_bytes())
        )
        _CACHE = r, t
    return _CACHE


def fixture(*, corrected=True, committed=False, action="unit_execute"):
    r, t = inputs()
    f = t.fixture(action, committed=committed)
    api = r.api if corrected else r.parent_api
    f.authority.api = api
    f.transport.factories = r.modules["w25_runtime"].factories(api)
    f.raw.broken = False
    f.raw.converter_calls = []
    f.raw.native_errors = []
    f.raw.inject_error = None

    class ConverterCursor(t.Cursor):
        def execute(self, sql, params=None):
            # Use the actual pinned libpq query converter before synthetic wire.
            # PostgresQuery/Transformer construction is local, not connect().
            row = {"sql": sql, "parameters": params, "parameter_type": type(params).__name__}
            f.raw.converter_calls.append(row)
            try:
                q = PostgresQuery(Transformer())
                q.convert(sql, params)
                row["wire_sql"] = q.query
                row["wire_parameters"] = q.params
                if sql == f.raw.inject_error:
                    raise psycopg.ProgrammingError("synthetic database syntax failure")
            except psycopg.Error as exc:
                f.raw.native_errors.append(exc)
                raise
            return super().execute(sql, params)

    f.raw.cursor = lambda: ConverterCursor(f.raw)
    return f


def write(f):
    return inputs()[0].modules["w25_coordinator"].write(f.authority, f.transport, f.meter, f.journal, f.r)


class RootCauseTests(unittest.TestCase):
    def test_exact_original_rejection_and_query_phase_counts(self):
        f = fixture(corrected=False)
        old = f.authority.api["txn"]["kernel"]
        attributes = []

        class Traced(old.Driver):
            def __getattr__(self, name):
                attributes.append((name, traceback.extract_stack()))
                return super().__getattr__(name)

        f.authority.api = {
            **f.authority.api,
            "txn": {
                **f.authority.api["txn"],
                "kernel": SimpleNamespace(Driver=Traced, Session=old.Session, status=old.status),
            },
        }
        result = write(f)
        self.assertEqual(result["outcome"], "ROLLED_BACK_UNVERIFIED")
        self.assertEqual(result["failure"]["primary"], "Unreviewed driver bypass")
        rejected = [(name, stack) for name, stack in attributes if name == "broken"]
        self.assertEqual(len(rejected), 1)
        self.assertIn("is_disconnect", [frame.name for frame in rejected[0][1]])
        self.assertEqual(result["counts"]["catalog_queries"], 8)
        self.assertEqual(result["phase_counts"]["initialization"], 5)
        self.assertEqual(result["phase_counts"]["preflight"], 3)
        self.assertEqual(result["body_statements_acknowledged"], 0)
        self.assertTrue(result["physical_closed"])
        self.assertIn("only '%s', '%b', '%t'", str(f.raw.native_errors[0]))

    def test_installed_query_parser_empty_mapping_percent_failure(self):
        query = inputs()[0].parent_api["readonly"]["catalog"].QUERIES["relations"]
        for params in [{}, immutabledict(), ()]:
            with self.subTest(kind=type(params).__name__), self.assertRaises(psycopg.ProgrammingError):
                PostgresQuery(Transformer()).convert(query, params)

    def test_same_exact_sql_with_none_is_preserved(self):
        sql = inputs()[0].parent_api["readonly"]["catalog"].QUERIES["relations"]
        q = PostgresQuery(Transformer())
        q.convert(sql, None)
        self.assertEqual(q.query, sql.encode())
        self.assertIsNone(q.params)

    def test_broken_only_fix_exposes_original_native_error(self):
        f = fixture(corrected=False)
        # Independent partial fix proves metadata alone is insufficient.
        f.authority.api = {
            **f.authority.api,
            "txn": {
                **f.authority.api["txn"],
                "kernel": w251_driver.compatible_kernel(f.authority.api["txn"]["kernel"]),
            },
        }
        result = write(f)
        self.assertNotEqual(result["failure"]["primary"], "Unreviewed driver bypass")
        self.assertIn("ProgrammingError", result["failure"]["exception"])
        self.assertEqual(result["body_statements_acknowledged"], 0)

    def test_original_fake_cursor_skipped_native_conversion(self):
        r, t = inputs()
        f = t.fixture()
        result = r.modules["w25_coordinator"].write(f.authority, f.transport, f.meter, f.journal, f.r)
        self.assertEqual(result["outcome"], "COMMITTED_UNVERIFIED")
        self.assertFalse(hasattr(t.Cursor, "convert"))


class MetadataTests(unittest.TestCase):
    def driver(self):
        f = fixture()
        driver = f.transport.open().driver
        self.addCleanup(f.transport.close)
        return f, driver

    def test_explicit_broken_boolean_is_read_only_metadata(self):
        f, driver = self.driver()
        before = copy.copy(f.meter.counts)
        calls = len(f.raw.calls)
        self.assertIs(driver.broken, False)
        self.assertEqual(before, f.meter.counts)
        self.assertEqual(calls, len(f.raw.calls))

    def test_broken_is_native_psycopg_status_property(self):
        getter = psycopg.Connection.broken.fget
        for status, closed, expected in [
            (psycopg.pq.ConnStatus.OK, False, False),
            (psycopg.pq.ConnStatus.BAD, False, True),
            (psycopg.pq.ConnStatus.BAD, True, False),
        ]:
            raw = SimpleNamespace(pgconn=SimpleNamespace(status=status), _closed=closed)
            self.assertIs(getter(raw), expected)

    def test_non_boolean_metadata_refuses(self):
        f, driver = self.driver()
        for value in [0, 1, None, "false", lambda: False]:
            f.raw.broken = value
            with self.assertRaises(ValueError):
                _ = driver.broken

    def test_metadata_property_has_no_setter(self):
        _, driver = self.driver()
        with self.assertRaises(AttributeError):
            driver.broken = False

    def test_dangerous_attributes_still_refuse(self):
        _, driver = self.driver()
        for name in [
            "pgconn",
            "connection",
            "driver_connection",
            "execute",
            "pipeline",
            "copy",
            "transaction",
            "tpc_begin",
            "fileno",
            "_get_pgconn",
        ]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                getattr(driver, name)

    def test_native_cursor_options_still_refuse(self):
        _, driver = self.driver()
        with self.assertRaises(ValueError):
            driver.cursor(name="server-side")
        cursor = driver.cursor()
        for name in ["pgresult", "copy", "connection", "stream", "pipeline", "scroll"]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                getattr(cursor, name)

    def test_is_disconnect_preserves_client_error(self):
        f, driver = self.driver()
        self.assertFalse(
            f.transport.session.connection.dialect.is_disconnect(psycopg.ProgrammingError("synthetic"), driver, None)
        )

    def test_original_kernel_objects_not_monkeypatched(self):
        r, _ = inputs()
        self.assertIsNot(r.api["txn"]["kernel"], r.parent_api["txn"]["kernel"])
        self.assertNotIn("broken", r.parent_api["txn"]["kernel"].Driver.__dict__)
        self.assertIs(r.api["txn"]["kernel"].Session, r.parent_api["txn"]["kernel"].Session)
        self.assertIs(r.api["txn"]["kernel"].Cursor, r.parent_api["txn"]["kernel"].Cursor)


class BindingTests(unittest.TestCase):
    def test_all_existing_templates_use_real_native_converter(self):
        policy = inputs()[0].policy
        for sql in policy.unbound:
            self.assertFalse(policy.validate(sql, None))
            q = PostgresQuery(Transformer())
            q.convert(sql, None)
            self.assertEqual(q.query, sql.encode())
        for sql, params in policy.bound.items():
            self.assertTrue(policy.validate(sql, params))
            q = PostgresQuery(Transformer())
            q.convert(sql, params)
            self.assertIn(b"$1", q.query)
            self.assertNotIn(next(iter(params.values())).encode(), q.query)

    def test_named_marker_bound_value_is_not_inlined(self):
        f = fixture()
        result = write(f)
        self.assertEqual(result["outcome"], "COMMITTED_UNVERIFIED")
        calls = [r for r in f.raw.converter_calls if "%(revision)s" in r["sql"]]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["parameters"], {"revision": "047_email_verification_tokens"})
        self.assertNotIn(b"047_email_verification_tokens", calls[0]["wire_sql"])

    def test_hstore_remains_bound(self):
        f = fixture()
        write(f)
        calls = [r for r in f.raw.converter_calls if "%(name)s" in r["sql"]]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["parameters"], {"name": "hstore"})

    def test_empty_standard_mappings_accept_parameterless_only(self):
        p = inputs()[0].policy
        sql = next(iter(p.unbound))
        for value in [None, {}, immutabledict(), ()]:
            self.assertFalse(p.validate(sql, value))
        for value in [{"unexpected": 1}, (1,), [], "", b"", 0]:
            with self.assertRaises(ValueError):
                p.validate(sql, value)

    def test_bound_parameters_are_exact(self):
        p = inputs()[0].policy
        for sql, params in p.bound.items():
            for value in [None, {}, (), {"extra": "x"}, {next(iter(params)): "unapproved"}]:
                with self.subTest(sql=sql[:30], value=value), self.assertRaises(ValueError):
                    p.validate(sql, value)

    def test_unknown_sql_cannot_use_no_params_to_bypass(self):
        f = fixture()
        session = f.transport.open()
        session.begin("ro")
        session.initialize(f.api["txn"]["recipe"].initializer)
        before = len(f.raw.converter_calls)
        with self.assertRaises(ValueError):
            session.connection.exec_driver_sql("SELECT unreviewed")
        self.assertEqual(len(f.raw.converter_calls), before)
        session.cleanup()
        f.transport.close()

    def test_missing_marker_binding_refuses_before_driver(self):
        f = fixture()
        session = f.transport.open()
        session.begin("ro")
        session.initialize(f.api["txn"]["recipe"].initializer)
        before = len(f.raw.converter_calls)
        marker = inputs()[0].modules["w25_schema"].INSERT_MARKER
        with self.assertRaises(ValueError):
            session.connection.exec_driver_sql(marker)
        self.assertEqual(len(f.raw.converter_calls), before)
        session.cleanup()
        f.transport.close()

    def test_do_execute_no_params_also_validates_bound_sql(self):
        f = fixture()
        s = f.transport.open()
        marker = inputs()[0].modules["w25_schema"].INSERT_MARKER
        cursor = Mock()
        with self.assertRaises(ValueError):
            s.connection.dialect.do_execute_no_params(cursor, marker)
        cursor.execute.assert_not_called()
        f.transport.close()

    def test_batches_are_not_added_to_frozen_scope(self):
        f = fixture()
        s = f.transport.open()
        cursor = Mock()
        with self.assertRaises(ValueError):
            s.connection.dialect.do_executemany(cursor, "SELECT 1", [{}])
        cursor.executemany.assert_not_called()
        f.transport.close()


class LifecycleTests(unittest.TestCase):
    def test_full_conversion_binding_keeps_exact_counts(self):
        f = fixture()
        r = write(f)
        self.assertEqual(r["outcome"], "COMMITTED_UNVERIFIED")
        self.assertEqual(r["body_statements_acknowledged"], 558)
        self.assertEqual(r["counts"]["catalog_queries"], 148)
        self.assertEqual(r["counts"]["migration_statements"], 558)
        self.assertEqual(r["counts"]["marker_statements"], 2)
        self.assertEqual(r["counts"]["transaction_controls"], 4)
        self.assertEqual(r["attempts"], 1)
        self.assertTrue(r["physical_closed"])
        self.assertFalse(r["accepted"])
        f.connector.assert_called_once()

    def test_real_dbapi_failure_is_not_replaced_by_bypass(self):
        f = fixture()
        f.raw.inject_error = f.api["readonly"]["catalog"].QUERIES["relations"]
        r = write(f)
        self.assertIn("ProgrammingError", r["failure"]["exception"])
        self.assertIn("synthetic database syntax failure", r["failure"]["primary"])
        self.assertNotIn("Unreviewed driver bypass", r["failure"]["primary"])
        self.assertEqual(r["outcome"], "ROLLED_BACK_UNVERIFIED")
        self.assertTrue(r["physical_closed"])

    def test_owned_readonly_rollback_precedes_write(self):
        f = fixture()
        r = write(f)
        controls = [
            sql for sql, _ in f.raw.calls if sql in {"IMPLICIT_BEGIN_RO", "IMPLICIT_BEGIN_RW", "ROLLBACK", "COMMIT"}
        ]
        self.assertEqual(controls, ["IMPLICIT_BEGIN_RO", "ROLLBACK", "IMPLICIT_BEGIN_RW", "COMMIT"])
        self.assertTrue(r["commit_acknowledged"])

    def test_unknown_commit_is_not_retried_or_rolled_back(self):
        f = fixture()
        f.raw.fail_commit = True
        r = write(f)
        self.assertIn("UNKNOWN_COMMIT_MANUAL_RECONCILIATION", r["outcome"])
        self.assertTrue(r["physical_closed"])
        self.assertEqual(r["attempts"], 1)
        self.assertEqual([x for x, _ in f.raw.calls].count("COMMIT"), 1)
        self.assertEqual([x for x, _ in f.raw.calls].count("ROLLBACK"), 1)

    def test_query_budget_stops_before_native_conversion(self):
        f = fixture()
        f.meter.limits["catalog_queries"] = 7
        r = write(f)
        self.assertFalse(r["commit_sent"])
        self.assertTrue(r["physical_closed"])
        self.assertEqual(len(f.raw.converter_calls), 7)
        self.assertEqual(r["body_statements_acknowledged"], 0)

    def test_four_settings_phases_and_same_model_are_retained(self):
        r, t = inputs()
        catalog = r.modules["w25_catalog"]
        _, representation, baseline = t.inputs()
        phases = [
            catalog.expected_settings(baseline, readonly=ro, after=after)
            for ro, after in [(True, False), (False, False), (False, True), (True, True)]
        ]
        self.assertEqual(
            [next(x["source"] for x in rows if x["name"] == "statement_timeout") for rows in phases],
            ["client", "client", "session", "client"],
        )
        self.assertEqual(
            representation["model_sha256"], "9e64728cfa41fb493c98acadc75c216d7d749aeaa25ec51372e785b50732d9df"
        )

    def test_independent_readback_is_never_automatic(self):
        f = fixture()
        result = write(f)
        self.assertTrue(result["readback_required"])
        f.connector.assert_called_once()

    def test_second_transport_open_is_refused(self):
        f = fixture()
        f.transport.open()
        with self.assertRaises(ValueError):
            f.transport.open()
        f.connector.assert_called_once()
        f.transport.close()

    def test_import_and_offline_mode_never_use_live_providers(self):
        with (
            patch("psycopg.connect", side_effect=AssertionError("No connection")),
            patch("subprocess.run", side_effect=AssertionError("No Docker")),
            redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(w251_entry.main(["--mode", "offline"]), 0)
        self.assertEqual(json.loads(output.getvalue())["PostgreSQL_connections"], 0)

    def test_new_and_old_live_modes_remain_denied_without_authority(self):
        with self.assertRaises(ValueError):
            w251_entry.main(["--mode", "live"])
        r, _ = inputs()
        old_entry = integration.parent_module(
            "w25_entry", json.loads((integration.PARENT / "source-lock.w25.v2.json").read_bytes())
        )
        with self.assertRaises(ValueError):
            old_entry.main(["--mode", "live"])
        self.assertIsNotNone(r)

    def test_parent_source_and_consumed_authority_not_modified(self):
        integration.reviewed()
        self.assertEqual(
            integration.sha((integration.PARENT / "source-lock.w25.v2.json").read_bytes()), integration.PARENT_LOCK
        )
        self.assertEqual(
            integration.sha((integration.PARENT / "sql-allowlist.w25.json").read_bytes()), integration.SQL_PIN
        )


class AdditionalBoundaryTests(unittest.TestCase):
    def test_independent_readback_still_requires_separate_evidence(self):
        f = fixture(action="unit_readback", committed=True)
        f.authority.plan["write_evidence"] = None
        result = inputs()[0].modules["w25_coordinator"].readback(f.authority, f.transport, f.meter, f.journal, f.r)
        self.assertFalse(result["accepted"])
        self.assertEqual(result["attempts"], 0)
        f.connector.assert_not_called()

    def test_separately_mock_authorized_readback_uses_its_own_budget(self):
        f = fixture(action="unit_readback", committed=True)
        r, t = inputs()
        co = r.modules["w25_coordinator"]
        data = t.post_rows(
            f.base, f.r["model"], readonly=True, marker=[{"version_num": "047_email_verification_tokens"}]
        )
        with patch.object(co, "verify_write_evidence", return_value=co.schema_digest(data)):
            result = co.readback(f.authority, f.transport, f.meter, f.journal, f.r)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["counts"]["catalog_queries"], 86)
        self.assertEqual(result["counts"]["transaction_controls"], 2)
        self.assertTrue(result["rollback_acknowledged"])
        self.assertTrue(result["physical_closed"])
        f.connector.assert_called_once()

    def test_source_imports_are_inert(self):
        with (
            patch("psycopg.connect", side_effect=AssertionError("No connection")),
            patch("subprocess.run", side_effect=AssertionError("No process")),
        ):
            for name in ["w251_driver", "w251_integration", "w251_entry"]:
                spec = importlib.util.spec_from_file_location("_inert_" + name, integration.HERE / (name + ".py"))
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

    def test_source_lock_tamper_refuses_offline(self):
        original = integration.private_source

        def changed(path, expected):
            if path.name == "w25_runtime.py":
                raise ValueError("Synthetic source changed")
            return original(path, expected)

        with patch.object(integration, "private_source", side_effect=changed), self.assertRaises(ValueError):
            integration.reviewed()


if __name__ == "__main__":
    unittest.main(verbosity=2)
