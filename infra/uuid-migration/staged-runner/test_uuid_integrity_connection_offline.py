"""Offline E constructor regressions. Only synthetic credentials and mocked I/O.

For private-copy review, run with --artifact-dir pointing to the reviewed private
W1.7B.4 evidence directory. Never import that baseline module or invoke its CLI.
"""

import argparse
import ast
import copy
import json
import os
import re
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import psycopg
import uuid_integrity_control as ctl
from test_uuid_integrity_offline import approved

ARTIFACT_DIR = None
SYNTHETIC = b"synthetic-connection-unit-test-only\n"


def connect_calls(tree):
    return [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and isinstance(n.func.value, ast.Name)
        and n.func.value.id == "psycopg"
        and n.func.attr == "connect"
    ]


def expected_kwargs(call):
    assert not call.args and all(k.arg is not None for k in call.keywords)
    return {
        k.arg: SYNTHETIC.decode().strip() if k.arg == "password" else ast.literal_eval(k.value)
        for k in call.keywords
        if k.arg != "service"
    }


def synthetic_stat(metadata):
    return SimpleNamespace(
        st_ino=metadata["inode"],
        st_uid=metadata["uid"],
        st_size=metadata["size"],
        st_mtime_ns=int(metadata["mtime_ns"]),
        st_ctime_ns=int(metadata["ctime_ns"]),
    )


class ControlConnectionTests(unittest.TestCase):
    def setUp(self):
        self.plan = approved()
        self.sessions = ctl.Sessions(self.plan, MagicMock())
        self.conn = MagicMock()
        self.meta = synthetic_stat(self.plan["credential_metadata"])

    def open_mocked(self, error=None):
        with (
            patch.object(ctl.common, "private_file", return_value=SYNTHETIC) as credential,
            patch.object(ctl.Path, "stat", return_value=self.meta),
            patch.object(ctl.psycopg, "connect", side_effect=error, return_value=self.conn) as connect,
            patch.object(self.sessions, "identity") as identity,
        ):
            with self.sessions.open() as conn:
                self.assertIs(conn, self.conn)
            self.assertEqual(connect.call_count, 1)
            credential.assert_called_once_with(str(ctl.PASSWORD))
            identity.assert_called_once_with(self.conn)
            self.conn.close.assert_called_once()
            return connect.call_args

    def test_control_omits_service_dsn_and_merged_config(self):
        call = self.open_mocked()
        self.assertEqual(call.args, ())
        self.assertNotIn("service", call.kwargs)
        self.assertNotIn("conninfo", call.kwargs)
        self.assertEqual(
            set(call.kwargs),
            {
                "host",
                "port",
                "dbname",
                "user",
                "password",
                "passfile",
                "sslmode",
                "connect_timeout",
                "autocommit",
                "application_name",
                "options",
            },
        )

    def test_control_keeps_existing_target_and_protections(self):
        kw = self.open_mocked().kwargs
        self.assertEqual(
            (kw["host"], kw["port"], kw["dbname"], kw["user"]),
            ("127.0.0.1", 56042, "uuid_w17_e_integrity", "uuid_w1_d_bootstrap"),
        )
        self.assertEqual(
            (kw["passfile"], kw["sslmode"], kw["connect_timeout"], kw["autocommit"]), ("/dev/null", "disable", 5, True)
        )
        for setting in (
            "search_path=pg_catalog",
            "default_transaction_read_only=on",
            "statement_timeout=2000",
            "lock_timeout=250",
            "idle_in_transaction_session_timeout=5000",
        ):
            self.assertIn(setting, kw["options"])
        self.assertEqual(kw["application_name"], "uuid_w17_e_integrity")

    def test_control_target_is_not_taken_from_ambient_url_or_plan_overrides(self):
        # Direct constructor never substitutes an endpoint; the CLI still validates
        # and rejects these plans before Sessions is instantiated for live use.
        self.plan.update(host="remote", port=55439, database="other", user="other")
        with patch.dict(os.environ, {"DATABASE_URL": "synthetic-unapproved-url"}):
            kw = self.open_mocked().kwargs
        self.assertEqual(
            (kw["host"], kw["port"], kw["dbname"], kw["user"]),
            ("127.0.0.1", 56042, "uuid_w17_e_integrity", "uuid_w1_d_bootstrap"),
        )

    def test_control_rejects_changed_credential_metadata_without_connect(self):
        self.meta.st_ino += 1
        with (
            patch.object(ctl.common, "private_file", return_value=SYNTHETIC),
            patch.object(ctl.Path, "stat", return_value=self.meta),
            patch.object(ctl.psycopg, "connect") as conn,
            self.assertRaises(ctl.Stop),
        ):
            with self.sessions.open():
                self.fail("yielded")
        conn.assert_not_called()

    def test_control_does_not_retry_constructor_failure(self):
        error = psycopg.OperationalError("synthetic client rejection")
        with (
            patch.object(ctl.common, "private_file", return_value=SYNTHETIC),
            patch.object(ctl.Path, "stat", return_value=self.meta),
            patch.object(ctl.psycopg, "connect", side_effect=error) as conn,
            self.assertRaises(psycopg.OperationalError),
        ):
            with self.sessions.open():
                self.fail("yielded")
        self.assertEqual(conn.call_count, 1)
        self.assertTrue(self.sessions.slots.acquire(blocking=False))
        self.sessions.slots.release()


class ApprovalIsolationTests(unittest.TestCase):
    def setUp(self):
        self.clean = patch.dict(os.environ, {"HOME": "/Users/ferozebasha", "PATH": "/usr/bin:/bin"}, clear=True)
        self.clean.start()
        self.addCleanup(self.clean.stop)

    def refused(self, plan):
        with (
            patch.object(ctl, "docker") as docker,
            patch.object(ctl.psycopg, "connect") as conn,
            patch.object(ctl.common, "private_file") as password,
            self.assertRaises(ctl.Stop),
        ):
            ctl.validate_plan(plan, "integrity_execute", "SYNTHETIC-EXECUTE", ctl.common.TABLES, ctl.CATEGORIES)
        docker.assert_not_called()
        conn.assert_not_called()
        password.assert_not_called()

    def test_all_ambient_libpq_overrides_refused(self):
        for key in (
            "PGSERVICE",
            "PGSERVICEFILE",
            "PGSYSCONFDIR",
            "PGHOST",
            "PGHOSTADDR",
            "PGPORT",
            "PGDATABASE",
            "PGUSER",
            "PGPASSWORD",
            "PGPASSFILE",
            "PGOPTIONS",
        ):
            with self.subTest(key=key), patch.dict(os.environ, {key: "synthetic-override"}):
                self.refused(approved())

    def test_missing_expired_or_unapproved_actions_refused(self):
        for edit in (
            {"approvals": {}},
            {"expires_utc": "2000-01-01T00:00:00+00:00"},
            {"accepted": False},
            {"credential_provenance_reviewed": False},
        ):
            plan = approved()
            plan.update(edit)
            self.refused(plan)

    def test_wrong_target_role_port_and_unix_socket_refused(self):
        for key, value in (
            ("target", "D"),
            ("host", "/tmp"),
            ("host", "remote"),
            ("host", "localhost"),
            ("port", 55439),
            ("port", 56041),
            ("database", "uuid_w1_d_rehearsal"),
            ("user", "other"),
            ("system_identifier", ctl.D_CLUSTER),
        ):
            with self.subTest(key=key, value=value):
                plan = approved()
                plan[key] = value
                self.refused(plan)

    def test_credential_path_source_hash_and_resource_pins_refused(self):
        for edit in (
            {"password_file": "/tmp/other"},
            {"source_sha256": {}},
            {"container_id": ctl.D_CONTAINER},
            {"network_id": None},
            {"e_schema_sha256": None},
        ):
            plan = approved()
            plan.update(edit)
            self.refused(plan)


class PrivateCopyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if ARTIFACT_DIR is None:
            raise unittest.SkipTest("Explicit --artifact-dir required for actual private-copy source review")
        cls.source = (ARTIFACT_DIR / "baseline-corrected.private.py").read_text()
        cls.old = (ARTIFACT_DIR / "baseline-original.private.py").read_text()
        cls.old_control = (ARTIFACT_DIR / "control-before.private.py").read_text()
        cls.tree, cls.old_tree = ast.parse(cls.source), ast.parse(cls.old)

    def private_namespace(self):
        plan = approved()
        meta = synthetic_stat(plan["credential_metadata"])
        ns = {
            "psycopg": psycopg,
            "re": re,
            "gate": MagicMock(),
            "event": MagicMock(),
            "require": lambda value, label: ctl.require(value, label),
            "ctl": SimpleNamespace(
                PASSWORD=SimpleNamespace(lstat=lambda: meta), credential_metadata=ctl.credential_metadata
            ),
            "common": SimpleNamespace(private_file=MagicMock(return_value=SYNTHETIC)),
            "PLAN": {"secret_correlation": {"credential_metadata": plan["credential_metadata"]}},
        }
        nodes = [
            n
            for n in self.tree.body
            if isinstance(n, ast.FunctionDef) and n.name in ("econnect", "sanitize", "classify", "diagnostic")
        ]
        exec(compile(ast.Module(body=nodes, type_ignores=[]), "<isolated-private-constructor-only>", "exec"), ns)
        return ns

    def test_public_file_diff_is_exactly_service_line_removal(self):
        expected = self.old_control.replace('                service="",\n', "")
        self.assertEqual(Path(ctl.__file__).read_text(), expected)

    def test_both_constructor_asts_only_omit_service(self):
        for old, new in (
            (ast.parse(self.old_control), ast.parse(Path(ctl.__file__).read_text())),
            (self.old_tree, self.tree),
        ):
            before = connect_calls(old)
            after = connect_calls(new)
            self.assertEqual(len(before), 1)
            self.assertEqual(len(after), 1)
            expected = copy.deepcopy(before[0])
            self.assertEqual([k.arg for k in expected.keywords].count("service"), 1)
            expected.keywords = [k for k in expected.keywords if k.arg != "service"]
            self.assertEqual(ast.dump(after[0]), ast.dump(expected))
            self.assertFalse(after[0].args)
            self.assertTrue(all(k.arg is not None for k in after[0].keywords))

    def test_private_matches_every_other_verified_W17B2_connection_option(self):
        ns = self.private_namespace()
        with patch.object(psycopg, "connect") as conn:
            ns["econnect"]()
        self.assertEqual(conn.call_args.args, ())
        self.assertEqual(conn.call_args.kwargs, expected_kwargs(connect_calls(self.old_tree)[0]))
        self.assertNotIn("service", conn.call_args.kwargs)
        self.assertEqual(conn.call_args.kwargs["hostaddr"], "127.0.0.1")
        self.assertEqual(conn.call_args.kwargs["gssencmode"], "disable")
        self.assertIn("row_security=on", conn.call_args.kwargs["options"])

    def test_control_matches_every_other_original_control_option(self):
        test = ControlConnectionTests(methodName="test_control_keeps_existing_target_and_protections")
        test.setUp()
        self.assertEqual(test.open_mocked().kwargs, expected_kwargs(connect_calls(ast.parse(self.old_control))[0]))

    def test_private_never_takes_target_or_password_path_from_ambient_config(self):
        ns = self.private_namespace()
        ns["PLAN"].update(host="remote", port=55439, database="other", user="other", password_file="/tmp/other")
        with patch.dict(os.environ, {"DATABASE_URL": "synthetic-url"}), patch.object(psycopg, "connect") as conn:
            ns["econnect"]()
        self.assertEqual(
            (
                conn.call_args.kwargs["host"],
                conn.call_args.kwargs["hostaddr"],
                conn.call_args.kwargs["port"],
                conn.call_args.kwargs["dbname"],
            ),
            ("127.0.0.1", "127.0.0.1", 56042, "uuid_w17_e_integrity"),
        )
        ns["common"].private_file.assert_called_once_with(ns["ctl"].PASSWORD)

    def test_private_gate_and_all_other_existing_helpers_preserved(self):
        old = {n.name: n for n in self.old_tree.body if isinstance(n, ast.FunctionDef)}
        new = {n.name: n for n in self.tree.body if isinstance(n, ast.FunctionDef)}
        for name, node in old.items():
            if name != "econnect":
                self.assertEqual(ast.dump(new[name]), ast.dump(node), name)
        self.assertEqual(set(new) - set(old), {"sanitize", "classify", "diagnostic"})

    def test_private_rejects_changed_secret_metadata_before_constructor(self):
        ns = self.private_namespace()
        ns["PLAN"]["secret_correlation"]["credential_metadata"] = {}
        with patch.object(psycopg, "connect") as conn, self.assertRaises(ctl.Stop):
            ns["econnect"]()
        conn.assert_not_called()
        ns["common"].private_file.assert_not_called()

    def test_private_client_failure_reason_preserved_no_retry(self):
        ns = self.private_namespace()
        error = psycopg.OperationalError("synthetic connection refused password=synthetic-connection-unit-test-only")
        with patch.object(psycopg, "connect", side_effect=error) as conn, self.assertRaises(psycopg.OperationalError):
            ns["econnect"]()
        self.assertEqual(conn.call_count, 1)
        ns["gate"].assert_called_once_with("baseline_validate")
        ns["event"].assert_called_once()
        logged = ns["event"].call_args.kwargs
        self.assertIsNone(logged["sqlstate"])
        self.assertIn("connection refused", logged["client_primary"])
        self.assertNotIn(SYNTHETIC.decode().strip(), json.dumps(logged))
        self.assertEqual(logged["reason_classification"], "connection_refused")

    def test_private_server_primary_and_sqlstate_sanitized(self):
        class SyntheticServerError(Exception):
            sqlstate = "28P01"
            diag = SimpleNamespace(message_primary="password authentication failed token=SYNTHETIC_TOKEN")

        ns = self.private_namespace()
        with (
            patch.object(psycopg, "connect", side_effect=SyntheticServerError()) as conn,
            self.assertRaises(SyntheticServerError),
        ):
            ns["econnect"]()
        self.assertEqual(conn.call_count, 1)
        logged = ns["event"].call_args.kwargs
        self.assertEqual(logged["sqlstate"], "28P01")
        self.assertNotIn("SYNTHETIC_TOKEN", json.dumps(logged))
        self.assertIn("password authentication failed", logged["server_primary"])
        self.assertIsNone(logged["client_primary"])

    def test_long_dsn_uri_and_control_character_diagnostics_fail_closed(self):
        ns = self.private_namespace()
        for text in ("x" * 20000, "host=x port=1 user=secret", "unsafe\x00text"):
            self.assertEqual(ns["sanitize"](text, SYNTHETIC), "UNCLASSIFIED_REDACTED")
        out = ns["sanitize"]("postgresql://user:secret@host/db password='another secret'", SYNTHETIC)
        self.assertNotIn("user:secret", out)
        self.assertNotIn("another secret", out)

    def test_offline_selection_cannot_invoke_baseline_main_or_database_actions(self):
        ns = self.private_namespace()
        self.assertEqual(
            set(k for k in ns if k in ("source_check", "resource_check", "fresh_e", "review_archive")), set()
        )
        forbidden = {"execute", "cursor", "transaction", "commit", "rollback", "docker"}
        for n in ast.walk(next(n for n in self.tree.body if isinstance(n, ast.FunctionDef) and n.name == "econnect")):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                self.assertNotIn(n.func.attr, forbidden)
        with patch.object(psycopg, "connect") as conn:
            ns["econnect"]()
        self.assertEqual(conn.call_count, 1)  # mocked, no real authentication
        self.assertNotIn("baseline_execute", str(ns["gate"].call_args))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", required=True, type=Path)
    args, remaining = parser.parse_known_args()
    ARTIFACT_DIR = args.artifact_dir
    unittest.main(argv=[__file__, *remaining])
