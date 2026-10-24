"""Offline unittest suite: inert imports, AST/source reads and mocked lifecycle only."""

import ast
import copy
import io
import os
import unittest
from contextlib import contextmanager, redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import expand_one_step as runner
import uuid_w1_common as common
from sqlalchemy.dialects import postgresql


def plan():
    return {
        "target": "D",
        "disposable": True,
        "accepted": True,
        "baseline_reviewed": True,
        "writers_and_privileges_reviewed": True,
        "exclusive_ddl_window_reviewed": True,
        "disposable_secret_provenance_reviewed": True,
        "old_monolith_excluded": True,
        "host": "127.0.0.1",
        "port": 56041,
        "database": "uuid_w1_d_rehearsal",
        "user": "uuid_w1_d_bootstrap",
        "password_file": str(Path.home() / ".sbom-uuid-w1-disposable-20261016/postgres-password"),
        "docker_socket": str(Path.home() / ".docker/run/docker.sock"),
        "docker_binary": "/Applications/Docker.app/Contents/Resources/bin/docker",
        "docker_binary_sha256": "a" * 64,
        "schema_sha256": "b" * 64,
        "container_sha256": "c" * 64,
        "volume_sha256": "d" * 64,
        "container_id": "e" * 64,
        "database_oid": 123,
        "system_identifier": "123456789",
        "network_ids": {"sbom-uuid-w1_d_test": "f" * 64},
        "daemon_id": "synthetic-daemon",
        "server_address": "synthetic-address",
        "postmaster_started_at": "synthetic-start",
        "prefix_review_reference": "synthetic-review",
        "expires_utc": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        "approvals": {"expand_validate": "synthetic-validate", "expand_execute": "synthetic-execute"},
        "current_revision": runner.BASE,
        "next_revision": runner.CHAIN[1],
    }


def states():
    before = {k: [] for k in common.CATALOG_SQL}
    before["relations"] = [(10, "tenants", "r")]
    after = copy.deepcopy(before)
    after["columns"] = [(10, 2, "public_id")]
    after["constraints"] = [(20, 10, "ck_tenants_public_id_v4", "c")]
    after["triggers"] = [(30, 10), (31, 10)]
    after["functions"] = [(40, "uuid_public_identity_guard_v1")]
    return before, after


class FakeConnection:
    def __init__(self, log, commit_error=False):
        self.log = log
        self.commit_error = commit_error
        self.connection = MagicMock()
        self.connection.driver_connection = "synthetic-raw"

    def __enter__(self):
        self.log.append("connection_open")
        return self

    def __exit__(self, *args):
        self.log.append("connection_closed")

    def in_transaction(self):
        return False

    @contextmanager
    def begin(self):
        self.log.append("begin")
        try:
            yield
        except BaseException:
            self.log.append("rollback_attempt")
            raise
        else:
            self.log.append("commit_attempt")
            if self.commit_error:
                raise OSError("synthetic-unknown-commit")
            self.log.append("commit_ack")

    def execute(self, statement):
        self.log.append("marker_lock")


class OfflineTests(unittest.TestCase):
    def setUp(self):
        runner._USED = False
        self.env = patch.dict(os.environ, {}, clear=True)
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def test_actual_graph_and_hashes(self):
        blobs = runner.discover()
        self.assertEqual(tuple(blobs), runner.CHAIN[1:])
        for i, next_revision in enumerate(runner.CHAIN[1:]):
            self.assertEqual(runner.next_only(runner.CHAIN[i], next_revision), i)

    def test_skipped_and_out_of_order(self):
        for current, requested in [
            (runner.BASE, runner.CHAIN[2]),
            (runner.CHAIN[2], runner.CHAIN[1]),
            (runner.CHAIN[-1], runner.CHAIN[-1]),
        ]:
            with self.subTest(current=current), self.assertRaises(common.SafetyStop):
                runner.next_only(current, requested)

    def test_multi_revision_requests(self):
        for requested in (
            "head",
            "heads",
            "080:085",
            runner.CHAIN[1] + "," + runner.CHAIN[2],
            [runner.CHAIN[1], runner.CHAIN[2]],
        ):
            with self.subTest(requested=requested), self.assertRaises(common.SafetyStop):
                runner.next_only(runner.BASE, requested)

    def test_missing_staged_file(self):
        original = Path.glob

        def missing(path, pattern):
            values = list(original(path, pattern))
            return iter(values[1:] if path.name == "staged-alembic" else values)

        with patch.object(Path, "glob", missing), self.assertRaises(common.SafetyStop):
            runner.discover()

    def test_modified_staged_file(self):
        original = Path.read_bytes

        def altered(path):
            data = original(path)
            return data + b"\n# modified" if path.name == runner.CHAIN[1] + ".py" else data

        with patch.object(Path, "read_bytes", altered), self.assertRaises(common.SafetyStop):
            runner.discover()

    def test_changed_active_graph(self):
        original = Path.read_bytes

        def altered(path):
            data = original(path)
            return (
                data.replace(b"079_lifecycle_provider_verification", b"079_unapproved_head")
                if path.name == "079_lifecycle_provider_verification.py"
                else data
            )

        with patch.object(Path, "read_bytes", altered), self.assertRaises(common.SafetyStop):
            runner.discover()

    def test_manifest_approved_synthetic_only(self):
        runner.validate_manifest(plan(), "execute", "synthetic-execute", runner.CHAIN[1])
        runner.validate_manifest(plan(), "validate", "synthetic-validate", runner.CHAIN[1])

    def test_manifest_refusals(self):
        changes = {
            "accepted": False,
            "port": 55439,
            "host": "remote.invalid",
            "old_monolith_excluded": False,
            "current_revision": runner.CHAIN[2],
            "schema_sha256": "",
            "system_identifier": "",
            "database_oid": True,
            "next_revision": runner.CHAIN[2],
            "prefix_review_reference": "",
            "expires_utc": "2000-01-01T00:00:00+00:00",
        }
        for key, value in changes.items():
            p = plan()
            p[key] = value
            with self.subTest(key=key), self.assertRaises((common.SafetyStop, ValueError)):
                runner.validate_manifest(p, "execute", "synthetic-execute", runner.CHAIN[1])
        with self.assertRaises(common.SafetyStop):
            runner.validate_manifest(plan(), "execute", "synthetic-validate", runner.CHAIN[1])

    def test_offline_no_runtime_or_secret_paths(self):
        with (
            patch.object(common, "connect", side_effect=AssertionError("connection forbidden")),
            patch.object(common, "verify_docker", side_effect=AssertionError("Docker forbidden")),
            patch.object(common, "private_file", side_effect=AssertionError("secret forbidden")),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(runner.main(["--mode", "offline"]), 0)
            self.assertEqual(runner.main(["--mode", "offline", "--next-revision", "head"]), 2)

    def test_partial_delta_reconciliation(self):
        before, after = states()
        runner.delta(before, after, "tenants", True)
        for section in ("relations", "columns", "constraints", "triggers", "functions"):
            broken = copy.deepcopy(after)
            broken[section].append(("unexpected",))
            with self.subTest(section=section), self.assertRaises((common.SafetyStop, IndexError)):
                runner.delta(before, broken, "tenants", True)

    def lifecycle(self, commit_error=False, apply_error=False, verify_error=False):
        log = []
        conn = FakeConnection(log, commit_error)
        engine = MagicMock()
        engine.connect.return_value = conn
        engine.dispose.side_effect = lambda: log.append("engine_disposed")
        before, after = states()

        def checker(raw, p, current, pre_hash=True):
            log.append("check_" + current)
            if raw == "new-readonly" and verify_error:
                raise common.SafetyStop("synthetic post-commit mismatch")
            return before if current == runner.BASE else after

        def apply(*args):
            log.append("one_upgrade")
            if apply_error:
                raise common.SafetyStop("synthetic SQL failure")

        @contextmanager
        def readonly(p):
            log.append("independent_open")
            try:
                yield "new-readonly"
            finally:
                log.append("independent_closed")

        evidence = MagicMock()
        with (
            patch.object(common, "verify_docker"),
            patch.object(common, "acquire_operator_lock"),
            patch.object(common, "connect", readonly),
        ):
            try:
                runner.execute_step(
                    plan(),
                    runner.CHAIN[1],
                    b"synthetic-not-executed",
                    evidence,
                    engine_factory=lambda: engine,
                    checker=checker,
                    applier=apply,
                )
            except (OSError, common.SafetyStop):
                pass
        return log, evidence

    def test_mock_commit_close_then_independent_verify(self):
        log, evidence = self.lifecycle()
        self.assertEqual(log.count("one_upgrade"), 1)
        self.assertEqual(log.count("begin"), 1)
        self.assertLess(log.index("commit_ack"), log.index("connection_closed"))
        self.assertLess(log.index("connection_closed"), log.index("independent_open"))
        self.assertEqual(log[-1], "independent_closed")
        evidence.emit.assert_any_call("commit_acknowledged", revision=runner.CHAIN[1])
        with self.assertRaises(common.SafetyStop):
            runner.execute_step(plan(), runner.CHAIN[1], b"", evidence)

    def test_mock_sql_error_rolls_back_no_verification(self):
        log, evidence = self.lifecycle(apply_error=True)
        self.assertIn("rollback_attempt", log)
        self.assertNotIn("commit_ack", log)
        self.assertNotIn("independent_open", log)
        evidence.emit.assert_any_call("stopped", classification="ROLLBACK_REQUIRES_CONFIRMATION")

    def test_lock_timeout_and_connection_failure_classification(self):
        self.assertEqual(runner.outcome("transaction"), "ROLLBACK_REQUIRES_CONFIRMATION")
        self.assertEqual(runner.outcome("commit_pending"), "UNKNOWN_COMMIT_STOP")
        self.assertEqual(runner.outcome("committed"), "COMMITTED_NOT_VERIFIED")
        self.assertIn("55P03", common.SQLSTATE_REASONS)
        self.assertIn("08006", common.SQLSTATE_REASONS)

    def test_marker_rowcount_failure_stops(self):
        conn = MagicMock()
        conn.dialect.name = "postgresql"
        conn.in_transaction.return_value = True
        conn.connection.driver_connection.autocommit = False
        conn.execute.return_value.rowcount = 0
        context = MagicMock()
        context.as_sql = False
        context.impl.transactional_ddl = True
        with (
            patch.object(runner.MigrationContext, "configure", return_value=context),
            patch.object(runner, "Operations"),
            patch.object(runner, "module_from_verified_blob"),
            self.assertRaises(common.SafetyStop),
        ):
            runner.apply_revision(conn, runner.CHAIN[1], b"not executed", runner.BASE)

    def test_new_sql_compiles_offline(self):
        tree = ast.parse(Path(runner.__file__).read_text())
        count = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and ast.unparse(node.func) in ("common.query", "text"):
                position = 1 if ast.unparse(node.func) == "common.query" else 0
                if (
                    len(node.args) > position
                    and isinstance(node.args[position], ast.Constant)
                    and isinstance(node.args[position].value, str)
                ):
                    common.compiled(node.args[position].value)
                    count += 1
        self.assertGreaterEqual(count, 5)

    def test_mock_unknown_commit_never_retries(self):
        log, evidence = self.lifecycle(commit_error=True)
        self.assertEqual(log.count("one_upgrade"), 1)
        self.assertNotIn("independent_open", log)
        evidence.emit.assert_any_call("stopped", classification="UNKNOWN_COMMIT_STOP")

    def test_mock_postcommit_mismatch_not_success(self):
        _, evidence = self.lifecycle(verify_error=True)
        evidence.emit.assert_any_call("stopped", classification="COMMITTED_NOT_VERIFIED")
        self.assertFalse(any(c.args[0] == "committed_verified_closed" for c in evidence.emit.call_args_list))

    def test_marker_schema_and_old_monolith_refusal(self):
        raw = MagicMock()
        with patch.object(common, "query") as q:
            q.return_value.fetchall.return_value = [(runner.CHAIN[1],), (runner.CHAIN[2],)]
            with self.assertRaises(common.SafetyStop):
                runner.marker(raw)
        with (
            patch.object(common, "verify_docker"),
            patch.object(runner, "identity"),
            patch.object(runner, "marker", return_value=runner.CHAIN[2]),
        ):
            with self.assertRaises(common.SafetyStop):
                runner.verify(raw, plan(), runner.CHAIN[1])

    def test_prefix_objects_ahead_and_guard_changed(self):
        # Guards at marker 079 cannot be adopted, even if they resemble 080.
        with patch.object(common, "query") as q:
            q.return_value.fetchall.return_value = [("old-monolith-guard",)]
            with self.assertRaises(common.SafetyStop):
                runner.prefix(MagicMock(), runner.BASE)
            with self.assertRaises(common.SafetyStop):
                runner.prefix(MagicMock(), runner.CHAIN[1])

    def test_isolated_operations_and_conditional_marker(self):
        conn = MagicMock()
        conn.dialect.name = "postgresql"
        conn.in_transaction.return_value = True
        conn.connection.driver_connection.autocommit = False
        conn.execute.return_value.rowcount = 1
        context = MagicMock()
        context.as_sql = False
        context.impl.transactional_ddl = True
        module = MagicMock()
        with (
            patch.object(runner.MigrationContext, "configure", return_value=context) as configure,
            patch.object(runner, "Operations") as operations_class,
            patch.object(runner, "module_from_verified_blob", return_value=module),
        ):
            runner.apply_revision(conn, runner.CHAIN[1], b"not executed", runner.BASE)
        module.upgrade.assert_called_once_with()
        operations_class.context.assert_called_once_with(context)
        self.assertTrue(configure.call_args.kwargs["opts"]["transactional_ddl"])
        sql = str(conn.execute.call_args.args[0].compile(dialect=postgresql.dialect()))
        self.assertIn("UPDATE public.alembic_version", sql)
        self.assertIn("WHERE version_num=", sql)

    def test_no_root_env_or_imports_contract_preserved(self):
        source = Path(runner.__file__).read_text()
        tree = ast.parse(source)
        for n in ast.walk(tree):
            if isinstance(n, (ast.Import, ast.ImportFrom)):
                self.assertNotIn("app.", ast.unparse(n))
                self.assertNotIn("dotenv", ast.unparse(n))
        self.assertNotIn("ScriptDirectory", source)
        self.assertNotIn("run_migrations(", source)
        self.assertNotIn(".stamp(", source)
        blobs = runner.discover()
        first = blobs[runner.CHAIN[1]].decode()
        for token in (
            "nullable=True",
            "pg_catalog.gen_random_uuid()",
            "WHEN (OLD.public_id IS DISTINCT FROM NEW.public_id)",
            "SECURITY INVOKER",
            "SET search_path = pg_catalog",
            "public_id IS NULL OR",
        ):
            self.assertIn(token, first)


if __name__ == "__main__":
    unittest.main(verbosity=2)
