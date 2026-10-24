"""Offline only: no Docker, secret, PostgreSQL, fixture DML or application startup."""

import ast
import copy
import io
import json
import os
import unittest
import uuid
from contextlib import contextmanager, redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import uuid_integrity_control as ctl
import uuid_integrity_fixtures as fx
import uuid_integrity_suite as suite


class CodeError(Exception):
    def __init__(self, code, constraint=None):
        self.sqlstate = code
        self.diag = SimpleNamespace(constraint_name=constraint)


def approved():
    """Synthetic in-memory example only, never persisted as real authority."""
    plan = suite.proposal()
    plan.update(
        accepted=True,
        container_id="a" * 64,
        network_id="b" * 64,
        e_schema_sha256="c" * 64,
        volume_sha256="d" * 64,
        preservation_sha256="e" * 64,
        system_identifier="1111111111111111111",
        database_oid=20000,
        server_address="172.21.0.2/32",
        postmaster_started_at="synthetic-start",
        credential_metadata={"inode": 123, "uid": os.getuid(), "size": 10, "mtime_ns": "1", "ctime_ns": "2"},
        approvals={"integrity_validate": "SYNTHETIC-VALIDATE", "integrity_execute": "SYNTHETIC-EXECUTE"},
    )
    for key in (
        "synthetic_only_reviewed",
        "schema_parity_reviewed",
        "privileges_and_writers_reviewed",
        "credential_provenance_reviewed",
        "exclusive_test_window_reviewed",
        "fixture_ddl_reviewed",
        "outbound_risk_reviewed",
    ):
        plan[key] = True
    return plan


class FixtureTests(unittest.TestCase):
    def test_actual_catalog_required_columns_and_composite_graph(self):
        metadata = fx.verify_contract()
        self.assertEqual(metadata["source_runner13"], ctl.D13)
        self.assertEqual(metadata["source_independent31"], ctl.D31)
        self.assertEqual(set(metadata["tables"]), set(fx.TABLES))

    def test_all_six_have_negative_unique_explicit_integer_ids(self):
        ids = [fx.identity(t, s) for t in fx.TABLES for s in (1, 2, fx.MAX_SLOT)]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(-2147483648 < x < 0 for x in ids))

    def test_ids_do_not_accept_boolean_unbounded_or_injected_targets(self):
        for t, s in (("tenants;DROP", 1), ("tenants", True), ("tenants", 0), ("tenants", fx.MAX_SLOT + 1)):
            with self.subTest(table=t, slot=s), self.assertRaises(ValueError):
                fx.identity(t, s)

    def test_source_has_all_hierarchy_composites_and_no_type_lookup_dependency(self):
        data = fx.values("sbom_source", 2)
        self.assertEqual(data["tenant_id"], fx.values("logical_sbom", 2)["tenant_id"])
        self.assertEqual(data["product_id"], fx.values("logical_sbom", 2)["product_id"])
        self.assertEqual(data["logical_sbom_id"], fx.identity("logical_sbom", 2))
        self.assertNotIn("sbom_type", data)  # nullable FK; no invented sbom_type row

    def test_required_client_only_defaults_and_timestamps(self):
        self.assertEqual(fx.values("tenants", 1)["status"], "ACTIVE")
        self.assertIsNotNone(fx.values("tenants", 1)["created_at"].tzinfo)
        self.assertIsInstance(fx.values("products", 1)["created_at"], str)
        self.assertIs(fx.values("sbom_component", 1)["lifecycle_is_stale"], False)

    def test_deterministic_labeled_values(self):
        for table in fx.TABLES:
            self.assertEqual(fx.values(table, 1), fx.values(table, 1))
            self.assertTrue(any("synthetic-w17" in str(x) for x in fx.values(table, 1).values()))

    def test_parameterization_payload_never_becomes_sql(self):
        value = "synthetic'; DROP DATABASE x; --"
        data = fx.values("tenants", 1)
        data["name"] = value
        statement, args = fx.insert_statement("tenants", data)
        self.assertNotIn(value, statement.as_string())
        self.assertIn(value, args)
        self.assertEqual(statement.as_string().count("%s"), len(args))

    def test_identifier_whitelist_for_insert_and_update(self):
        with self.assertRaises(ValueError):
            fx.insert_statement("tenants", {"name);DELETE": "x"})
        with self.assertRaises(ValueError):
            fx.update(MagicMock(), "products", 1, "tenant_id", 1)
        with self.assertRaises(ValueError):
            fx.update(MagicMock(), "tenants", 1, "duplicate_of_component_id", 1)

    def test_safe_null_conditional_update(self):
        conn = MagicMock()
        fx.update(conn, "sbom_component", -1, "public_id", suite.V4, null_only=True)
        statement, args = conn.execute.call_args.args
        self.assertIn("AND public_id IS NULL", statement.as_string())
        self.assertEqual(args, (suite.V4, -1))

    def test_insert_chain_real_parameter_construction_and_parent_order(self):
        rows = {}
        statements = []

        def execute(statement, args):
            text = statement.as_string()
            statements.append(text)
            if text.startswith("INSERT"):
                table = text.split('public."')[1].split('"')[0]
                names = text.split("(", 1)[1].split(")", 1)[0].replace('"', "").split(",")
                rows[table] = dict(zip(names, args, strict=True))
                return SimpleNamespace(fetchone=lambda: (rows[table]["id"], suite.V4, "uuid"))
            table = text.split('public."')[1].split('"')[0]
            names = text.split("SELECT ")[1].split(" FROM")[0].replace('"', "").split(",")
            return SimpleNamespace(fetchone=lambda: tuple(rows[table][n] for n in names))

        reserve = MagicMock()
        row = fx.insert_chain(SimpleNamespace(execute=execute), "sbom_component", 1, reserve, "null")
        self.assertEqual(tuple(rows), fx.TABLES)
        self.assertEqual(reserve.call_count, 6)
        self.assertIsNone(rows["sbom_component"]["public_id"])
        self.assertNotIn("public_id", rows["tenants"])
        self.assertEqual(row[0], fx.identity("sbom_component", 1))


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {"HOME": str(Path.home()), "PATH": "/usr/bin:/bin"}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.plan = approved()

    def validate(self, plan=None):
        ctl.validate_plan(plan or self.plan, "integrity_execute", "SYNTHETIC-EXECUTE", fx.TABLES, ctl.CATEGORIES)

    def test_complete_in_memory_contract(self):
        self.validate()

    def test_pending_proposal_refused_before_runtime(self):
        with patch.object(ctl, "verify_resources") as docker, patch.object(ctl.psycopg, "connect") as db:
            with self.assertRaises(ctl.Stop):
                self.validate(suite.proposal())
            docker.assert_not_called()
            db.assert_not_called()

    def test_each_attestation_pending_refused(self):
        for key in (
            "synthetic_only_reviewed",
            "schema_parity_reviewed",
            "privileges_and_writers_reviewed",
            "credential_provenance_reviewed",
            "exclusive_test_window_reviewed",
            "fixture_ddl_reviewed",
            "outbound_risk_reviewed",
        ):
            with self.subTest(key=key):
                plan = copy.deepcopy(self.plan)
                plan[key] = False
                with self.assertRaises(ctl.Stop):
                    self.validate(plan)

    def test_A_B_D_remote_and_ambiguous_target_rejected(self):
        for key, value in (
            ("target", "D"),
            ("port", 55439),
            ("port", 56041),
            ("port", True),
            ("host", "localhost"),
            ("host", "remote"),
            ("database", "uuid_w1_d_rehearsal"),
            ("system_identifier", ctl.D_CLUSTER),
            ("container_id", ctl.D_CONTAINER),
        ):
            with self.subTest(key=key, value=value):
                p = copy.deepcopy(self.plan)
                p[key] = value
                with self.assertRaises(ctl.Stop):
                    self.validate(p)

    def test_missing_or_reused_action_approval(self):
        for refs in ({}, {"integrity_validate": "SYNTHETIC-EXECUTE", "integrity_execute": "SYNTHETIC-EXECUTE"}):
            p = copy.deepcopy(self.plan)
            p["approvals"] = refs
            with self.assertRaises(ctl.Stop):
                self.validate(p)

    def test_expired_or_naive_expiry(self):
        for expiry in ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(), "2027-01-01T00:00:00"):
            p = copy.deepcopy(self.plan)
            p["expires_utc"] = expiry
            with self.assertRaises(ctl.Stop):
                self.validate(p)

    def test_new_cluster_and_OID_pins_required(self):
        for key, value in (
            ("system_identifier", None),
            ("database_oid", True),
            ("e_schema_sha256", None),
            ("network_id", None),
            ("preservation_sha256", None),
        ):
            p = copy.deepcopy(self.plan)
            p[key] = value
            with self.assertRaises(ctl.Stop):
                self.validate(p)

    def test_source_catalog_and_code_hash_mismatch(self):
        for field in ("source_D085", "source_sha256"):
            p = copy.deepcopy(self.plan)
            p[field] = {}
            with self.assertRaises(ctl.Stop):
                self.validate(p)

    def test_wrong_secret_path_and_ambient_libpq(self):
        p = copy.deepcopy(self.plan)
        p["password_file"] = str(Path.home() / ".sbom-uuid-w1-disposable-20261016/postgres-password")
        with self.assertRaises(ctl.Stop):
            self.validate(p)
        with patch.dict(os.environ, {"PGSERVICE": "unexpected"}), self.assertRaises(ctl.Stop):
            self.validate()

    def test_budgets_types_and_scope(self):
        for key, value in (("max_connections", 2049), ("max_rows", 0), ("max_cases", True), ("max_seconds", 901)):
            p = copy.deepcopy(self.plan)
            p[key] = value
            with self.assertRaises(ctl.Stop):
                self.validate(p)
        p = copy.deepcopy(self.plan)
        p["tables"] = ["tenants"]
        with self.assertRaises(ctl.Stop):
            self.validate(p)

    def test_cli_pending_plan_no_Docker_secret_or_connection(self):
        with (
            patch.object(ctl.common, "private_file", return_value=json.dumps(suite.proposal()).encode()),
            patch.object(ctl, "verify_resources") as docker,
            patch.object(ctl.psycopg, "connect") as db,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                suite.main(
                    [
                        "--mode",
                        "execute",
                        "--target",
                        "E",
                        "--plan",
                        "/synthetic",
                        "--approval-id",
                        "x",
                        "--evidence",
                        "/synthetic/evidence",
                    ]
                ),
                2,
            )
            docker.assert_not_called()
            db.assert_not_called()

    def test_missing_explicit_target_refused(self):
        with patch.object(ctl.common, "private_file") as private, redirect_stdout(io.StringIO()):
            self.assertEqual(suite.main(["--mode", "execute"]), 2)
            private.assert_not_called()


class LifecycleTests(unittest.TestCase):
    def test_final_scope_rejects_unreserved_rows_without_cleanup(self):
        sessions = ctl.Sessions(approved(), MagicMock())
        names = [(t,) for t in fx.TABLES] + [("alembic_version",)] + [(f"other_{i}",) for i in range(65)]
        conn = MagicMock()
        conn.execute.side_effect = [
            SimpleNamespace(fetchall=lambda: names),
            SimpleNamespace(fetchall=lambda: [(-123,)]),
        ]
        with self.assertRaises(ctl.Stop):
            sessions.final_data_scope(conn)
        self.assertEqual(conn.execute.call_count, 2)

    def test_reserved_scope_tracks_attempts_without_changing_PK_values(self):
        sessions = ctl.Sessions(approved(), MagicMock())
        row_id = fx.identity("tenants", 1)
        sessions.reserve_row("tenants", row_id)
        self.assertEqual(sessions.fixture_ids["tenants"], {row_id})
        self.assertEqual(sessions.rows, 1)

    def test_interference_two_BEFORE_triggers_only_change_fixture_identity(self):
        conn = MagicMock()
        suite.helper(conn, "tenants", -123, "UPDATE", early=True)
        suite.helper(conn, "tenants", -123, "UPDATE", create_function=False, restore=True)
        self.assertEqual(conn.execute.call_count, 3)
        text = conn.execute.call_args.args[0].as_string()
        self.assertIn("zz_w17_integrity_before", text)
        self.assertIn("'restore'", text)
        self.assertIn("NEW.public_id := OLD.public_id", suite.HELPER_SQL)

    def test_concurrent_same_row_has_connection_transaction_barrier(self):
        source = (ctl.HERE / "uuid_integrity_suite.py").read_text()
        self.assertIn("ready.wait()", source)
        self.assertIn("threading.Barrier(2, timeout=5)", source)

    def test_validation_cases_use_real_expected_error_codes(self):
        class FakeSession:
            reserve_row = MagicMock()

            @contextmanager
            def open(self):
                conn = MagicMock()
                yield conn

        instance = suite.Suite(FakeSession())
        for name, code in (("v1", "23514"), ("malformed", "22P02"), ("integer_type", "42804")):
            with (
                patch.object(suite, "expect_error", return_value={"sqlstate": code}) as error,
                patch.object(fx, "read_identity", return_value=None),
            ):
                # successful savepoint-health scalar
                original = suite.ctl.write_transaction

                @contextmanager
                def txn(conn):
                    conn.execute.return_value.fetchone.return_value = (1,)
                    yield conn

                with patch.object(suite.ctl, "write_transaction", txn):
                    result = instance.validation("tenants", name)
                self.assertEqual(error.call_args.args[2], code)
                self.assertEqual(result["sqlstate"], code)

    def test_body_failure_rolls_back_not_unknown_commit(self):
        conn = MagicMock()
        error = CodeError("23514")
        with self.assertRaises(CodeError), ctl.write_transaction(conn):
            raise error
        self.assertIs(conn.transaction.return_value.__exit__.call_args.args[1], error)

    def test_commit_failure_classified_unknown_without_retry(self):
        conn = MagicMock()
        conn.transaction.return_value.__exit__.side_effect = OSError("not logged")
        with self.assertRaises(ctl.UnknownCommit) as context, ctl.write_transaction(conn):
            pass
        self.assertEqual(ctl.classify(context.exception)["classification"], "UNKNOWN_COMMIT_STOP")
        self.assertEqual(conn.transaction.call_count, 1)

    def test_fixture_commit_ack_close_order(self):
        log = []
        conn = MagicMock()

        @contextmanager
        def open_conn():
            log.append("open")
            try:
                yield conn
            finally:
                log.append("close")

        sessions = SimpleNamespace(
            open=open_conn,
            baseline=lambda _: log.append("baseline"),
            budget=lambda: None,
            evidence=SimpleNamespace(emit=lambda name, **_: log.append(name)),
        )
        result = ctl.acknowledged_fixture(sessions, lambda _: "synthetic-result")
        self.assertEqual(result, "synthetic-result")
        self.assertEqual(log, ["open", "baseline", "fixture_precommit", "fixture_commit_acknowledged", "close"])

    def test_fixture_error_closes_no_commit_ack(self):
        conn = MagicMock()
        events = []

        @contextmanager
        def opened():
            try:
                yield conn
            finally:
                events.append("close")

        sessions = SimpleNamespace(
            open=opened,
            baseline=lambda _: None,
            budget=lambda: None,
            evidence=SimpleNamespace(emit=lambda event, **_: events.append(event)),
        )

        def fail(_):
            raise CodeError("23514")

        with self.assertRaises(CodeError):
            ctl.acknowledged_fixture(sessions, fail)
        self.assertNotIn("fixture_commit_acknowledged", events)
        self.assertEqual(events[-1], "close")

    def test_savepoint_error_provenance_CHECK_trigger_type(self):
        for state, constraint, trigger in (
            ("23514", "ck_tenants_public_id_v4", False),
            ("23514", None, True),
            ("22P02", None, False),
            ("42804", None, False),
        ):
            conn = MagicMock()

            def fail(state=state, constraint=constraint):
                raise CodeError(state, constraint)

            result = suite.expect_error(conn, fail, state, "tenants", trigger)
            self.assertEqual(result["sqlstate"], state)
            self.assertEqual(conn.transaction.call_count, 1)

    def test_savepoint_wrong_state_or_wrong_constraint_fails(self):
        def fail():
            raise CodeError("23514", "unrelated_check")

        with self.assertRaises(ctl.Stop):
            suite.expect_error(MagicMock(), fail, "23514", "tenants")
        with self.assertRaises(ctl.Stop):
            suite.expect_error(MagicMock(), lambda: None, "23514", "tenants")

    def test_safe_error_classification_never_stringifies_secret(self):
        err = CodeError("55P03")
        err.args = ("SECRET must not leak",)
        result = ctl.classify(err)
        self.assertEqual(result["classification"], "lock_timeout")
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertEqual(ctl.classify(CodeError("25P02"))["classification"], "transaction_aborted")

    def test_rows_connections_and_concurrency_budgets(self):
        plan = approved()
        plan["max_rows"] = 1
        sessions = ctl.Sessions(plan, MagicMock())
        sessions.reserve_row()
        with self.assertRaises(ctl.Stop):
            sessions.reserve_row()
        self.assertTrue(sessions.slots.acquire(False))
        self.assertTrue(sessions.slots.acquire(False))
        self.assertTrue(sessions.slots.acquire(False))
        self.assertFalse(sessions.slots.acquire(False))

    def test_connection_identity_failure_still_closes(self):
        plan = approved()
        sessions = ctl.Sessions(plan, MagicMock())
        conn = MagicMock()
        s = SimpleNamespace(st_ino=123, st_uid=os.getuid(), st_size=10, st_mtime_ns=1, st_ctime_ns=2)
        with (
            patch.object(ctl.common, "private_file", return_value=b"synthetic!"),
            patch.object(Path, "stat", return_value=s),
            patch.object(ctl.psycopg, "connect", return_value=conn) as connect,
            patch.object(sessions, "identity", side_effect=ctl.Stop("synthetic mismatch")),
        ):
            with self.assertRaises(ctl.Stop), sessions.open():
                pass
            conn.close.assert_called_once()
            self.assertEqual(connect.call_args.kwargs["port"], 56042)
            self.assertEqual(connect.call_args.kwargs["dbname"], "uuid_w17_e_integrity")
            self.assertEqual(connect.call_args.kwargs["passfile"], "/dev/null")
            self.assertIn("default_transaction_read_only=on", connect.call_args.kwargs["options"])

    def test_connection_budget_refuses_before_secret_read(self):
        plan = approved()
        plan["max_connections"] = 1
        sessions = ctl.Sessions(plan, MagicMock())
        sessions.used = 1
        with patch.object(ctl.common, "private_file") as private:
            with self.assertRaises(ctl.Stop), sessions.open():
                pass
            private.assert_not_called()


class CoverageTests(unittest.TestCase):
    def test_duplicate_selection_refused_before_runtime(self):
        with self.assertRaises(ctl.Stop):
            ctl.validate_plan(
                approved(), "integrity_execute", "SYNTHETIC-EXECUTE", ["tenants", "tenants"], ["generation"]
            )

    def test_concurrent_failure_sets_cancellation_before_further_fixture(self):
        sessions = ctl.Sessions(approved(), MagicMock())
        instance = suite.Suite(sessions)

        def fail():
            raise CodeError("08006")

        with self.assertRaises(CodeError):
            instance.parallel([fail, lambda: None])
        self.assertTrue(sessions.cancelled.is_set())
        with self.assertRaises(ctl.Stop):
            sessions.reserve_row()

    def test_guard_reuse_and_exact_fixture_only_helper_removal(self):
        conn = MagicMock()
        with self.assertRaises(ctl.Stop):
            suite.remove_helper(conn, "tenants", "trg_tenants_public_id_insert")
        conn.execute.assert_not_called()
        suite.remove_helper(conn, "tenants", "zz_w17_integrity_before")
        self.assertEqual(conn.execute.call_count, 2)
        self.assertNotIn("uuid_public_identity_guard", str(conn.execute.call_args_list))

    def test_SQL_compilation_is_offline_not_PostgreSQL_parsing(self):
        from sqlalchemy import text
        from sqlalchemy.dialects import postgresql

        for fragment in (
            suite.HELPER_SQL,
            ctl.common.IDENTITY_SQL,
            "SET TRANSACTION READ WRITE",
            "SELECT pg_catalog.pg_sleep(0.2)",
        ):
            self.assertTrue(str(text(fragment).compile(dialect=postgresql.dialect())))
        for table in fx.TABLES:
            stmt, params = fx.insert_statement(table, fx.values(table, 1))
            self.assertEqual(stmt.as_string().count("%s"), len(params))

    def test_pending_proposal_is_not_real_E_execution_manifest(self):
        p = suite.proposal()
        self.assertEqual(p["resources"]["publication"], "127.0.0.1:56042:5432")
        self.assertEqual(p["resources"]["image_id"], ctl.IMAGE)
        self.assertFalse(p["fixture_ddl_reviewed"])
        self.assertFalse(p["outbound_risk_reviewed"])
        self.assertNotIn("DISABLE", p["fixture_DDL"])
        self.assertNotEqual(p["database"], "uuid_w1_d_rehearsal")

    def test_resource_mismatch_refused_without_database_access(self):
        p = approved()
        with (
            patch.object(ctl, "docker", return_value="unexpected daemon"),
            patch.object(ctl.psycopg, "connect") as connect,
        ):
            with self.assertRaises(ctl.Stop):
                ctl.verify_resources(p)
            connect.assert_not_called()

    def test_runtime_source_file_set_includes_fixture_contract_and_all_six_migrations(self):
        pins = ctl.source_hashes()
        self.assertIn("uuid_integrity_fixture_catalog.json", pins)
        self.assertEqual(len([name for name in pins if name[:3] in ("080", "081", "082", "083", "084", "085")]), 6)

    def test_each_table_has_all_categories_and_filtering(self):
        all_cases = suite.cases(fx.TABLES, ctl.CATEGORIES)
        self.assertLessEqual(len(all_cases), 256)
        for table in fx.TABLES:
            self.assertEqual({cat for t, cat, _ in all_cases if t == table}, set(ctl.CATEGORIES))
            self.assertTrue(all(t == table and c == "validation" for t, c, _ in suite.cases([table], ["validation"])))

    def test_required_boundary_cases_are_executable_handlers(self):
        for category, names in suite.CASES.items():
            self.assertTrue(callable(getattr(suite.Suite, category)))
            self.assertEqual(len(names), len(set(names)))
        self.assertEqual(suite.cases(["tenants"], ["generation"])[0], ("tenants", "generation", "omitted"))

    def test_native_uuid_version_variant_assertions(self):
        suite.check_uuid((-1, suite.V4, "uuid"))
        for val in (None, str(suite.V4), uuid.UUID(suite.INVALID["v1"]), uuid.UUID(suite.INVALID["variant"])):
            with self.assertRaises(ctl.Stop):
                suite.check_uuid((-1, val, "uuid"))

    def test_duplicate_explicit_uuid_case_not_misclassified(self):
        instance = suite.Suite(MagicMock())
        instance.fixture = MagicMock(side_effect=[(-1, suite.V4, "uuid"), (-2, suite.V4, "uuid")])
        result = instance.generation("tenants", "duplicates_permitted")
        self.assertIn("allowed", result["observed"])

    def test_parallel_coordinator_has_two_workers_and_bounded_barrier(self):
        instance = suite.Suite(MagicMock())
        self.assertEqual(instance.parallel([lambda: 1, lambda: 2]), [1, 2])
        with self.assertRaises(ctl.Stop):
            instance.parallel([lambda: 1])

    def test_helper_is_row_filtered_and_keeps_existing_guards(self):
        conn = MagicMock()
        name = suite.helper(conn, "tenants", -1700000000, "INSERT")
        stmt = conn.execute.call_args.args[0].as_string()
        self.assertEqual(name, "zz_w17_integrity_before")
        self.assertIn("WHEN (NEW.id=", stmt)
        self.assertIn("SECURITY INVOKER SET search_path=pg_catalog", suite.HELPER_SQL)
        self.assertNotIn("DISABLE", suite.HELPER_SQL)
        with self.assertRaises(ctl.Stop):
            suite.helper(conn, "unknown", 1, "INSERT")

    def test_no_import_or_entrypoint_has_application_initialization(self):
        for name in ("uuid_integrity_control.py", "uuid_integrity_fixtures.py", "uuid_integrity_suite.py"):
            source = (ctl.HERE / name).read_text()
            ast.parse(source)
            for n in ast.walk(ast.parse(source)):
                if isinstance(n, (ast.Import, ast.ImportFrom)):
                    self.assertNotIn("app.", ast.unparse(n))
                    self.assertNotIn("dotenv", ast.unparse(n))
            self.assertNotIn('conn.execute("TRUNCATE', source)
            self.assertNotIn("CASCADE", source)
            self.assertNotIn("DISABLE TRIGGER", source)
            self.assertNotIn("session_replication_role =", source)

    def test_offline_list_and_proposal_have_no_runtime_access(self):
        with (
            patch.object(ctl, "docker", side_effect=AssertionError("offline Docker")),
            patch.object(ctl.psycopg, "connect", side_effect=AssertionError("offline DB")),
            patch.object(ctl.common, "private_file", side_effect=AssertionError("offline secret")),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(suite.main(["--mode", "list", "--table", "tenants", "--category", "generation"]), 0)
            p = suite.proposal()
            self.assertFalse(p["accepted"])
            self.assertEqual(p["approvals"], {})
            self.assertIsNone(p["system_identifier"])

    def test_run_failure_skips_remaining_cases_without_retry(self):
        sessions = MagicMock()
        sessions.plan = approved()
        sessions.keeper_pid = 1
        conn = sessions.open.return_value.__enter__.return_value
        conn.execute.return_value.fetchone.return_value = (0,)
        instance = suite.Suite(sessions)
        instance.generation = MagicMock(side_effect=CodeError("23514"))
        with patch.object(ctl, "verify_resources"), self.assertRaises(CodeError):
            instance.run([("tenants", "generation", "omitted"), ("projects", "generation", "omitted")])
        instance.generation.assert_called_once()
        results = [x for x in sessions.evidence.emit.call_args_list if x.args[0] == "case_result"]
        self.assertEqual([x.kwargs["status"] for x in results], ["FAIL", "SKIP"])


if __name__ == "__main__":
    unittest.main()
