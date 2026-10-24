"""Offline only: synthetic credentials, intercepted constructors and catalog rows."""

import ast
import copy
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import w17b5_e_readonly as m

SYNTHETIC = b"synthetic-unit-only-password\n"


def fixtures():
    c = {
        "source_sha256": {"original.py": "old-pin"},
        "Docker_metadata_reference": {
            "container": {"id": m.E_CONTAINER},
            "network": {"id": m.E_NETWORK},
            "daemon": {"id": m.DAEMON},
            "volume": {"name": "sbom-uuid-w17-e_e_pgdata"},
        },
        "credential_reference": {"synthetic": True},
    }
    sources = {"original.py": "old-pin", "w17b5_e_readonly.py": "new-pin"}
    deps = {"psycopg": "synthetic-code-pin"}
    plan = {
        "task": "W1.7B.5",
        "candidate_sha256": m.CANDIDATE_SHA,
        "expires_utc": m.EXPIRY,
        "target": dict(m.TARGET),
        "limits": dict(m.LIMITS),
        "source_review_approved": True,
        "read_only_execution_approved": True,
        "approvals": {"read_only_execute": "SYNTHETIC-NOT-AUTHORITY"},
        "accepted": False,
        "integrity_action_approvals": {},
        "source_sha256": sources,
        "dependency_sha256": deps,
        "Docker_metadata_reference": c["Docker_metadata_reference"],
        "credential_reference": c["credential_reference"],
        "reference_sha256": m.REFERENCE_SHA,
        **{k: False for k in m.FLAGS},
    }
    return c, sources, deps, plan


def validate(plan=None, c=None, sources=None, deps=None, ref="SYNTHETIC-NOT-AUTHORITY", now=None):
    c0, s0, d0, p0 = fixtures()
    with patch.dict(os.environ, {}, clear=True):
        return m.validate_manifest(
            plan if plan is not None else p0,
            c or c0,
            ref,
            sources or s0,
            deps or d0,
            now or datetime(2026, 10, 18, tzinfo=UTC),
        )


class AuthorityTests(unittest.TestCase):
    def test_inert_module_import(self):
        path = Path(m.__file__)
        spec = importlib.util.spec_from_file_location("readonly_inert_test", path)
        module = importlib.util.module_from_spec(spec)
        # Module source loading is permitted; runtime opens/CLI/secret/DB imports are not.
        with (
            patch("os.open", side_effect=AssertionError("I/O")),
            patch("subprocess.run", side_effect=AssertionError("Docker")),
        ):
            spec.loader.exec_module(module)
        tree = ast.parse(path.read_text())
        imports = [n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
        self.assertFalse(any(x and x.startswith("app") for x in imports))

    def test_unique_json_rejects_duplicate_and_malformed(self):
        for text in ('{"a":1,"a":2}', '{"a":1', '{"x":{"a":0,"a":1}}'):
            with self.subTest(text=text), self.assertRaises((m.Refusal, ValueError)):
                m.unique_json(text)

    def test_candidate_hash_and_modified_bytes(self):
        with patch.object(m, "private_bytes", return_value=b"modified"):
            with self.assertRaises(m.Refusal):
                m.candidate()

    def test_candidate_exact_bytes_and_expiry(self):
        b = json.dumps({"expires_utc": m.EXPIRY}).encode()
        with patch.object(m, "private_bytes", return_value=b), patch.object(m, "CANDIDATE_SHA", m.sha(b)):
            self.assertEqual(m.candidate()["expires_utc"], m.EXPIRY)

    def test_manifest_missing_refuses_before_runtime_import(self):
        with patch.object(m, "candidate", side_effect=AssertionError("Should not read")):
            with self.assertRaises(m.Refusal):
                m.main(["--mode", "live"])

    def test_approved_synthetic_schema(self):
        validate()

    def test_missing_action_or_attestations(self):
        for key in ("source_review_approved", "read_only_execution_approved", "approvals"):
            plan = fixtures()[3]
            plan.pop(key)
            with self.subTest(key=key), self.assertRaises(m.Refusal):
                validate(plan=plan)
        with self.assertRaises(m.Refusal):
            validate(ref="")

    def test_expired_and_changed_expiry(self):
        with self.assertRaises(m.Refusal):
            validate(now=datetime.fromisoformat(m.EXPIRY) + timedelta(seconds=1))
        plan = fixtures()[3]
        plan["expires_utc"] = "2099-01-01T00:00:00+00:00"
        with self.assertRaises(m.Refusal):
            validate(plan=plan)

    def test_wrong_targets_and_no_unix_socket(self):
        for key, value in (
            ("host", "/tmp"),
            ("host", "remote"),
            ("hostaddr", "::1"),
            ("port", 55439),
            ("port", 56041),
            ("database", "production"),
            ("user", "postgres"),
        ):
            plan = fixtures()[3]
            plan["target"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(m.Refusal):
                validate(plan=plan)

    def test_wrong_resource_pin(self):
        for kind, key in (("container", "id"), ("daemon", "id"), ("network", "id"), ("volume", "name")):
            c, sources, deps, plan = fixtures()
            c = copy.deepcopy(c)
            c["Docker_metadata_reference"][kind][key] = "wrong"
            plan["Docker_metadata_reference"] = c["Docker_metadata_reference"]
            with self.subTest(kind=kind), self.assertRaises(m.Refusal):
                validate(plan, c, sources, deps)

    def test_source_and_dependency_and_candidate_pin_changes(self):
        for key in ("source_sha256", "dependency_sha256", "candidate_sha256", "reference_sha256"):
            plan = fixtures()[3]
            plan[key] = {} if key.endswith("sha256") and key.startswith(("source", "dependency")) else "changed"
            with self.subTest(key=key), self.assertRaises(m.Refusal):
                validate(plan=plan)

    def test_no_integrity_or_baseline_authority(self):
        for key in (*m.FLAGS, "accepted"):
            plan = fixtures()[3]
            plan[key] = True
            with self.subTest(key=key), self.assertRaises(m.Refusal):
                validate(plan=plan)
        plan = fixtures()[3]
        plan["approvals"]["integrity_execute"] = "BAD"
        with self.assertRaises(m.Refusal):
            validate(plan=plan)

    def test_ambient_pg_overrides_refused(self):
        c, sources, deps, plan = fixtures()
        for name in (
            "PGSERVICE",
            "PGSERVICEFILE",
            "PGSYSCONFDIR",
            "PGHOST",
            "PGPORT",
            "PGDATABASE",
            "PGUSER",
            "PGPASSWORD",
            "PGPASSFILE",
            "PGOPTIONS",
            "PGHOSTADDR",
        ):
            with patch.dict(os.environ, {name: "synthetic"}, clear=True), self.subTest(name=name):
                with self.assertRaises(m.Refusal):
                    m.validate_manifest(plan, c, "SYNTHETIC-NOT-AUTHORITY", sources, deps)

    def test_budget_changes_and_bool_are_rejected(self):
        for key in m.LIMITS:
            plan = fixtures()[3]
            plan["limits"][key] += 1
            with self.assertRaises(m.Refusal):
                validate(plan=plan)
        plan = fixtures()[3]
        plan["limits"]["attempts"] = True
        with self.assertRaises(m.Refusal):
            validate(plan=plan)

    def test_offline_path_no_live_options(self):
        with self.assertRaises(m.Refusal):
            m.main(["--mode", "offline", "--approval-id", "not-valid"])

    def test_live_unapproved_manifest_refuses_before_resource_or_secret(self):
        c, sources, deps, _ = fixtures()
        with (
            patch.object(m, "candidate", return_value=c),
            patch.object(m, "private_bytes", return_value=b"{}") as files,
            patch.object(m, "source_pins", return_value=sources),
            patch.object(m, "dependency_pins", return_value=deps),
            patch.object(m, "resource_preflight", side_effect=AssertionError("No resource access")) as resources,
            patch.dict(os.environ, m.CLEAN_ENV, clear=True),
        ):
            with self.assertRaises(m.Refusal):
                m.main(
                    [
                        "--mode",
                        "live",
                        "--manifest",
                        "/synthetic/plan.json",
                        "--manifest-sha256",
                        m.sha(b"{}"),
                        "--approval-id",
                        "SYNTHETIC",
                        "--evidence",
                        "/synthetic/evidence",
                    ]
                )
            files.assert_called_once_with("/synthetic/plan.json")
            resources.assert_not_called()

    def test_live_environment_cannot_inherit_PYTHONPATH_or_other_config(self):
        with (
            patch.dict(os.environ, {**m.CLEAN_ENV, "PYTHONPATH": "/synthetic"}, clear=True),
            patch.object(m, "candidate", side_effect=AssertionError("No files before clean-environment gate")),
        ):
            with self.assertRaises(m.Refusal):
                m.main(
                    [
                        "--mode",
                        "live",
                        "--manifest",
                        "/synthetic",
                        "--manifest-sha256",
                        "a" * 64,
                        "--approval-id",
                        "SYNTHETIC",
                        "--evidence",
                        "/synthetic",
                    ]
                )

    def test_new_catalog_SQL_compiles_without_database(self):
        from sqlalchemy import text
        from sqlalchemy.dialects import postgresql

        for label, statement in m.QUERIES.items():
            with self.subTest(label=label):
                self.assertTrue(str(text(statement).compile(dialect=postgresql.dialect())))

    def test_offline_mode_cannot_reach_constructor_or_metadata(self):
        c, sources, _, _ = fixtures()
        with (
            patch.object(m, "candidate", return_value=c),
            patch.object(m, "source_pins", return_value=sources),
            patch.object(m, "private_bytes", return_value=b"synthetic"),
            patch.object(m, "REFERENCE_SHA", m.sha(b"synthetic")),
            patch.object(m, "dependency_pins", return_value={}),
            patch.object(m, "resource_preflight", side_effect=AssertionError("No metadata")),
            patch.object(m.Probe, "run", side_effect=AssertionError("No constructor")),
            patch("builtins.print"),
        ):
            self.assertEqual(m.main(["--mode", "offline"]), 0)

    def test_whitelist_has_catalog_select_show_only(self):
        for sql in m.QUERIES.values():
            self.assertTrue(sql.startswith(("SELECT ", "SHOW ")))
            self.assertNotIn(";", sql)
            self.assertNotIn("public.", sql.replace("'public.alembic_version'", ""))
            self.assertNotIn("rolpassword,", sql)
        tree = ast.parse(Path(m.__file__).read_text())
        calls = [
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "connect"
        ]
        self.assertEqual(len(calls), 1)
        self.assertFalse(calls[0].args)
        self.assertNotIn("service", [k.arg for k in calls[0].keywords])
        source = Path(m.__file__).read_text()
        self.assertNotIn("import app", source)
        self.assertNotIn("import baseline", source)
        self.assertNotIn("common.connect(", source)


class BudgetTests(unittest.TestCase):
    def test_query_limit(self):
        b = m.Budget(lambda: 0)
        for _ in range(64):
            b.query()
        with self.assertRaises(m.Refusal):
            b.query()
        self.assertEqual(b.queries, 64)

    def test_controls_reserve_rollback(self):
        b = m.Budget(lambda: 0)
        for _ in range(3):
            b.control()
        with self.assertRaises(m.Refusal):
            b.control()
        b.control(cleanup=True)
        with self.assertRaises(m.Refusal):
            b.control(cleanup=True)
        self.assertEqual(b.controls, 4)

    def test_deadline_stops_further_operation(self):
        clock = MagicMock(return_value=0)
        b = m.Budget(clock)
        clock.return_value = 60
        for operation in (b.before, b.query, b.connect, b.control):
            with self.assertRaises(m.Refusal):
                operation()
        b.control(cleanup=True)

    def test_one_constructor_budget(self):
        b = m.Budget(lambda: 0)
        b.connect()
        with self.assertRaises(m.Refusal):
            b.connect()


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.budget = m.Budget(lambda: 0)
        self.evidence = MagicMock()
        self.probe = m.Probe(self.budget, self.evidence)
        self.conn = MagicMock()
        self.conn.closed = False
        self.conn.close.side_effect = lambda: setattr(self.conn, "closed", True)
        self.conn.execute.return_value.fetchall.return_value = [("on",)]
        self.connect = MagicMock(return_value=self.conn)

    def run_probe(self, observe=None):
        self.probe.run(self.connect, lambda: SYNTHETIC, observe or (lambda p: None))

    def test_exact_connection_options_omitting_service(self):
        self.run_probe()
        self.connect.assert_called_once_with(
            host="127.0.0.1",
            hostaddr="127.0.0.1",
            port=56042,
            dbname="uuid_w17_e_integrity",
            user="uuid_w1_d_bootstrap",
            password=SYNTHETIC.decode().strip(),
            passfile="/dev/null",
            sslmode="disable",
            gssencmode="disable",
            connect_timeout=5,
            autocommit=True,
            application_name="uuid_w17b2_E_baseline",
            options=m.OPTIONS,
        )

    def test_success_readonly_rollback_close(self):
        self.run_probe()
        statements = [x.args[0] for x in self.conn.execute.call_args_list]
        self.assertEqual(statements, [m.CONTROLS[0], m.QUERIES["readonly"], "ROLLBACK"])
        self.assertTrue(self.conn.closed)
        self.assertEqual(self.probe.secret, b"")

    def test_readonly_off_rejected_with_rollback(self):
        self.conn.execute.return_value.fetchall.return_value = [("off",)]
        with self.assertRaises(m.Refusal):
            self.run_probe()
        self.assertEqual(self.conn.execute.call_args_list[-1].args, ("ROLLBACK",))
        self.conn.close.assert_called_once()

    def test_constructor_failure_no_handle_no_retry(self):
        self.connect.side_effect = OSError("synthetic refused")
        with self.assertRaises(OSError):
            self.run_probe()
        self.assertEqual(self.connect.call_count, 1)
        self.conn.execute.assert_not_called()
        self.assertIsNone(self.probe.conn)
        with self.assertRaises(m.Refusal):
            self.run_probe()
        self.assertEqual(self.connect.call_count, 1)

    def test_secret_failure_has_no_constructor(self):
        with self.assertRaises(OSError):
            self.probe.run(self.connect, MagicMock(side_effect=OSError("secret unavailable")), lambda p: None)
        self.connect.assert_not_called()
        self.assertEqual(self.budget.attempts, 0)

    def test_query_error_rollback_close(self):
        def execute(sql, params=None):
            if sql == m.QUERIES["identity"]:
                raise OSError("synthetic catalog failure")
            return SimpleNamespace(fetchall=lambda: [("on",)])

        self.conn.execute.side_effect = execute
        with self.assertRaises(OSError):
            self.run_probe(lambda p: p.query("identity"))
        self.assertEqual(self.conn.execute.call_args_list[-1].args, ("ROLLBACK",))
        self.conn.close.assert_called_once()

    def test_begin_error_still_rollback_close(self):
        def execute(sql, params=None):
            if sql == m.CONTROLS[0]:
                raise OSError("synthetic begin failure")

        self.conn.execute.side_effect = execute
        with self.assertRaises(OSError):
            self.run_probe()
        self.assertEqual(self.conn.execute.call_args_list[-1].args, ("ROLLBACK",))
        self.conn.close.assert_called_once()

    def test_rollback_error_closes_no_retry(self):
        def execute(sql, params=None):
            if sql == "ROLLBACK":
                raise OSError("synthetic rollback failure")
            return SimpleNamespace(fetchall=lambda: [("on",)])

        self.conn.execute.side_effect = execute
        with self.assertRaises(OSError):
            self.run_probe()
        self.conn.close.assert_called_once()
        self.assertEqual(self.probe.secret, b"")
        self.assertEqual(sum(x.args == ("ROLLBACK",) for x in self.conn.execute.call_args_list), 1)

    def test_expiry_of_client_window_still_cleans_up(self):
        def observe(p):
            p.budget.clock = lambda: 60

        with self.assertRaises(m.Refusal):
            self.run_probe(observe)
        self.assertEqual(self.conn.execute.call_args_list[-1].args, ("ROLLBACK",))
        self.conn.close.assert_called_once()

    def test_query_budget_failure_cleans_up(self):
        def observe(p):
            p.budget.queries = 64
            p.query("identity")

        with self.assertRaises(m.Refusal):
            self.run_probe(observe)
        self.conn.close.assert_called_once()

    def test_arbitrary_SQL_DDL_DML_and_controls_rejected(self):
        self.probe.conn = self.conn
        for statement in ("DROP TABLE tenants", "INSERT INTO public.tenants VALUES(1)", "SELECT 1", "identity; DROP"):
            with self.subTest(statement=statement), self.assertRaises(m.Refusal):
                self.probe.query(statement)
        for control in ("COMMIT", "SET TRANSACTION READ WRITE", "ROLLBACK; DROP TABLE x"):
            with self.assertRaises(m.Refusal):
                self.probe.control(control)
        self.conn.execute.assert_not_called()

    def test_label_flushed_before_statement(self):
        order = []
        self.evidence.emit.side_effect = lambda *a, **k: order.append("evidence")
        self.probe.conn = self.conn
        self.conn.execute.side_effect = lambda *a, **k: order.append("sql") or SimpleNamespace(fetchall=lambda: [])
        self.probe.query("relations")
        self.assertEqual(order, ["evidence", "sql"])


class DiagnosticsTests(unittest.TestCase):
    def test_primary_sqlstate_and_secret_redaction(self):
        error = RuntimeError("raw must not be selected")
        error.sqlstate = "28P01"
        error.diag = SimpleNamespace(message_primary="password=" + SYNTHETIC.decode().strip())
        result = m.sanitized(error, SYNTHETIC)
        self.assertEqual(result["sqlstate"], "28P01")
        self.assertNotIn(SYNTHETIC.decode().strip(), json.dumps(result))

    def test_client_primary_null_sqlstate(self):
        result = m.sanitized(OSError('connection is bad: definition of service "" not found'), SYNTHETIC)
        self.assertIn("definition of service", result["primary"])
        self.assertIsNone(result["sqlstate"])

    def test_unsafe_DSN_token_hash_control_and_length(self):
        for text in (
            "host=x user=y password=secret",
            "postgresql://user:password@host/db",
            "Bearer secret",
            "SCRAM-SHA-256$secret",
            "-----BEGIN PRIVATE KEY-----",
            "a" * 20000,
            "bad\x00text",
        ):
            with self.subTest(text=text[:50]):
                result = m.sanitized(RuntimeError(text), SYNTHETIC)
                self.assertNotIn("secret", result["primary"])
                self.assertLessEqual(len(result["primary"]), 1024)


class ObservationTests(unittest.TestCase):
    def fake(self):
        ref = {
            "catalog": {"database_properties": [["synthetic"]], "schemas": [["public"]]},
            "owner_name": "synthetic_owner",
            "roles": {"roles": [["synthetic_owner"], ["builtin"]], "memberships": []},
            "extension": {"extension": [["plpgsql"]], "language": [["plpgsql"]], "routines": [["handler"]]},
            "extension_owner": [[m.TARGET["user"]]],
        }
        p = MagicMock()
        p.query.return_value = [
            [
                m.TARGET["database"],
                m.TARGET["user"],
                m.TARGET["user"],
                1234,
                "9999999999999999999",
                160015,
                "172.21.0.2",
                5432,
                "synthetic-start",
                False,
                "origin",
            ]
        ]
        return p, ref

    def test_all_readonly_observations(self):
        p, ref = self.fake()
        m.observe(p, {}, ref, "172.21.0.2")
        labels = [x.args[0] for x in p.check.call_args_list]
        self.assertEqual(len(labels), 21)
        self.assertTrue(set(labels) <= set(m.QUERIES))
        p.check.assert_any_call("owner_absent", [], ("synthetic_owner",))
        p.check.assert_any_call("roles", [["builtin"]])
        p.check.assert_any_call("alembic", [[None]])
        p.check.assert_any_call("relations", [])

    def test_D_cluster_wrong_version_address_and_database_rejected(self):
        for index, wrong in ((0, "D_database"), (4, m.D_CLUSTER), (5, 150000), (6, "127.0.0.1"), (7, 56042), (9, True)):
            p, ref = self.fake()
            p.query.return_value[0][index] = wrong
            with self.subTest(index=index), self.assertRaises(m.Refusal):
                m.observe(p, {}, ref, "172.21.0.2")

    def test_catalog_privilege_failure_stops_checks(self):
        p, ref = self.fake()

        def check(label, *a):
            if label == "privileges":
                raise PermissionError("synthetic catalog denied")

        p.check.side_effect = check
        with self.assertRaises(PermissionError):
            m.observe(p, {}, ref, "172.21.0.2")
        self.assertNotIn("roles", [x.args[0] for x in p.check.call_args_list])


class ManifestByteTests(unittest.TestCase):
    def setUp(self):
        self.c, self.sources, self.deps, self.plan = fixtures()
        self.raw = (json.dumps(self.plan, indent=2) + "\n").encode()
        self.byte_hash = hashlib.sha256(self.raw).hexdigest()

    def recheck(self, raw=None, plan=None, sources=None, deps=None, candidate=None, action=None):
        with (
            patch.object(m, "private_bytes", return_value=self.raw if raw is None else raw) as reader,
            patch.object(m, "candidate", return_value=self.c if candidate is None else candidate),
            patch.object(m, "source_pins", return_value=self.sources if sources is None else sources) as pins,
            patch.object(m, "dependency_pins", return_value=self.deps if deps is None else deps) as dependencies,
            patch.dict(os.environ, m.CLEAN_ENV, clear=True),
        ):
            result = m.recheck_manifest(
                "/synthetic/manifest.json",
                self.byte_hash,
                self.raw,
                self.plan if plan is None else plan,
                self.c,
                action or "SYNTHETIC-NOT-AUTHORITY",
            )
            reader.assert_called_once_with("/synthetic/manifest.json")
            pins.assert_called_once()
            dependencies.assert_called_once()
            return result

    def test_raw_manifest_hash_and_original_bytes_before_parsing(self):
        with patch.object(m, "private_bytes", return_value=self.raw) as reader:
            raw, plan = m.approved_manifest("/synthetic/manifest.json", self.byte_hash)
        self.assertEqual(raw, self.raw)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), self.byte_hash)
        self.assertEqual(plan, self.plan)
        reader.assert_called_once()

    def test_whitespace_changes_byte_hash_not_semantic_digest(self):
        other = json.dumps(self.plan, separators=(",", ":")).encode()
        self.assertNotEqual(hashlib.sha256(other).hexdigest(), self.byte_hash)
        self.assertEqual(m.digest(json.loads(other)), m.digest(json.loads(self.raw)))

    def test_canonical_digest_cannot_substitute_for_operator_byte_hash(self):
        canonical = m.digest(self.plan)
        self.assertNotEqual(canonical, self.byte_hash)
        with patch.object(m, "private_bytes", return_value=self.raw), self.assertRaises(m.Refusal):
            m.approved_manifest("/synthetic/manifest.json", canonical)

    def test_missing_or_malformed_hash_fails_before_review_file_read(self):
        for value in (None, "", 123, "bad", "A" * 64, "g" * 64, "a" * 63, "a" * 65):
            with self.subTest(value=value), patch.object(m, "private_bytes") as reader:
                with self.assertRaises(m.Refusal):
                    m.approved_manifest("/synthetic/manifest.json", value)
                reader.assert_not_called()

    def test_mismatched_hash_fails_before_json_parse(self):
        with patch.object(m, "private_bytes", return_value=self.raw), patch.object(m, "unique_json") as parse:
            with self.assertRaises(m.Refusal):
                m.approved_manifest("/synthetic/manifest.json", "a" * 64)
            parse.assert_not_called()

    def test_duplicate_keys_rejected_even_with_matching_raw_hash(self):
        raw = b'{"approvals":{},"approvals":{"read_only_execute":"synthetic"}}'
        with patch.object(m, "private_bytes", return_value=raw), self.assertRaises(m.Refusal):
            m.approved_manifest("/synthetic/manifest.json", hashlib.sha256(raw).hexdigest())

    def test_non_object_manifest_rejected(self):
        with patch.object(m, "private_bytes", return_value=b"[]"), self.assertRaises(m.Refusal):
            m.approved_manifest("/synthetic/manifest.json", hashlib.sha256(b"[]").hexdigest())

    def test_missing_cli_hash_fails_before_runtime_or_file_access(self):
        with patch.object(m, "candidate") as candidate, patch.object(m, "resource_preflight") as resources:
            with self.assertRaises(m.Refusal):
                m.main(
                    [
                        "--mode",
                        "live",
                        "--manifest",
                        "/synthetic/manifest.json",
                        "--approval-id",
                        "SYNTHETIC",
                        "--evidence",
                        "/synthetic/evidence.jsonl",
                    ]
                )
            candidate.assert_not_called()
            resources.assert_not_called()

    def test_identical_pre_auth_reread_revalidates_sources_and_dependencies(self):
        raw, plan = self.recheck()
        self.assertEqual(raw, self.raw)
        self.assertEqual(plan, self.plan)

    def test_replaced_target_source_or_approval_fields_fail_closed(self):
        for key, value in (
            ("target", {"database": "wrong"}),
            ("source_sha256", {}),
            ("approvals", {"read_only_execute": "CHANGED"}),
        ):
            changed = copy.deepcopy(self.plan)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(m.Refusal):
                self.recheck(raw=json.dumps(changed).encode())

    def test_whitespace_only_pre_auth_change_is_not_adopted(self):
        with self.assertRaises(m.Refusal):
            self.recheck(raw=self.raw + b"\n")

    def test_initial_parsed_plan_mutation_rejected(self):
        changed = copy.deepcopy(self.plan)
        changed["limits"]["queries"] = 65
        with self.assertRaises(m.Refusal):
            self.recheck(plan=changed)

    def test_sources_dependencies_and_action_are_revalidated(self):
        changed_sources = {**self.sources, "original.py": "changed"}
        for arguments in ({"sources": changed_sources}, {"deps": {"changed": True}}, {"action": "CHANGED"}):
            with self.subTest(arguments=arguments), self.assertRaises(m.Refusal):
                self.recheck(**arguments)

    def test_changed_candidate_is_not_adopted(self):
        with self.assertRaises(m.Refusal):
            self.recheck(candidate={**self.c, "changed": True})

    def main_mocked(self, changed=False):
        reference = b"{}"
        self.plan["reference_sha256"] = m.sha(reference)
        raw = (json.dumps(self.plan, indent=2) + "\n").encode()
        expected_hash = hashlib.sha256(raw).hexdigest()
        manifest_reads = []

        def reader(path, **kwargs):
            if path == "/synthetic/manifest.json":
                manifest_reads.append(path)
                return raw + b"\n" if changed and len(manifest_reads) > 1 else raw
            if path == m.REFERENCE:
                return reference
            raise AssertionError("Unexpected file or credential read")

        evidence, ctl = MagicMock(), MagicMock()
        with (
            patch.object(m, "candidate", return_value=self.c),
            patch.object(m, "private_bytes", side_effect=reader),
            patch.object(m, "source_pins", return_value=self.sources),
            patch.object(m, "dependency_pins", return_value=self.deps),
            patch.object(m, "REFERENCE_SHA", m.sha(reference)),
            patch.object(m, "Evidence", return_value=evidence),
            patch.object(m, "preservation", return_value={}),
            patch.object(m, "resource_preflight", return_value="172.21.0.2"),
            patch.object(m, "Probe") as probe,
            patch.dict(sys.modules, {"uuid_integrity_control": ctl}),
            patch.dict(os.environ, m.CLEAN_ENV, clear=True),
        ):
            argv = [
                "--mode",
                "live",
                "--manifest",
                "/synthetic/manifest.json",
                "--manifest-sha256",
                expected_hash,
                "--approval-id",
                "SYNTHETIC-NOT-AUTHORITY",
                "--evidence",
                "/synthetic/evidence.jsonl",
            ]
            if changed:
                with self.assertRaises(m.Refusal):
                    m.main(argv)
                probe.assert_not_called()
            else:
                self.assertEqual(m.main(argv), 3)
                probe.return_value.run.assert_called_once()
            ctl.common.private_file.assert_not_called()
            ctl.psycopg.connect.assert_not_called()
        self.assertEqual(len(manifest_reads), 2)
        evidence.close.assert_called_once()
        return evidence, raw

    def test_actual_authority_and_recheck_evidence_use_raw_and_canonical_labels(self):
        evidence, raw = self.main_mocked()
        for label in ("authority", "manifest_pre_auth"):
            call = next(x for x in evidence.emit.call_args_list if x.args[0] == label)
            self.assertEqual(call.kwargs["manifest_sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(call.kwargs["manifest_canonical_sha256"], m.digest(self.plan))
            self.assertNotEqual(call.kwargs["manifest_sha256"], call.kwargs["manifest_canonical_sha256"])
            self.assertNotIn("plan", call.kwargs)
        final = next(x for x in evidence.emit.call_args_list if x.args[0] == "readonly_acceptance")
        self.assertEqual(final.args[1], "UNKNOWN")
        self.assertEqual(final.kwargs["active_hba_rules"], "UNKNOWN")

    def test_modified_pre_auth_manifest_stops_before_any_connection_or_secret(self):
        self.main_mocked(changed=True)


class HbaEvidenceTests(unittest.TestCase):
    def test_existing_HBA_query_is_unchanged_and_file_only(self):
        self.assertEqual(
            m.QUERIES["auth"],
            "SELECT bool_and(error IS NULL AND auth_method='scram-sha-256') FROM pg_catalog.pg_hba_file_rules",
        )
        self.assertEqual(m.hba_evidence()["hba_evidence_scope"], "current_file_contents_and_parse_only")
        self.assertEqual(m.hba_evidence()["active_hba_rules"], "UNKNOWN")
        self.assertEqual(m.hba_evidence()["password_challenge"], "UNKNOWN")

    def test_HBA_pass_does_not_claim_active_authentication(self):
        evidence = MagicMock()
        probe = m.Probe(m.Budget(lambda: 0), evidence)
        probe.conn = MagicMock()
        probe.conn.execute.return_value.fetchall.return_value = [(True,)]
        probe.check("auth", [[True]])
        call = evidence.emit.call_args_list[-1]
        self.assertEqual(call.args, ("auth", "PASS"))
        self.assertEqual(call.kwargs["hba_evidence_scope"], "current_file_contents_and_parse_only")
        self.assertEqual(call.kwargs["active_hba_rules"], "UNKNOWN")
        self.assertEqual(probe.conn.execute.call_count, 1)

    def test_supplied_password_connection_event_does_not_claim_challenge(self):
        evidence = MagicMock()
        probe = m.Probe(m.Budget(lambda: 0), evidence)
        conn = MagicMock(closed=True)
        conn.execute.return_value.fetchall.return_value = [("on",)]
        connect = MagicMock(return_value=conn)
        probe.run(connect, lambda: SYNTHETIC, lambda p: None)
        call = next(x for x in evidence.emit.call_args_list if x.args == ("E-CONNECT", "CONNECTED"))
        self.assertTrue(call.kwargs["credential_supplied"])
        self.assertEqual(call.kwargs["password_challenge"], "UNKNOWN")
        connect.assert_called_once()


class PrivateFileTests(unittest.TestCase):
    def test_review_file_reader_refuses_credential_path_before_any_open(self):
        with patch("os.open", side_effect=AssertionError("No credential open")):
            with self.assertRaises(m.Refusal):
                m.private_bytes("/Users/ferozebasha/.sbom-uuid-w17-e/postgres-password")

    def test_larger_read_limit_only_for_exact_pinned_reference(self):
        with self.assertRaises(m.Refusal):
            m.private_bytes("/synthetic/other", maximum=4194304)

    def test_private_file_and_no_symlink(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as name:
            parent = Path(name)
            parent.chmod(0o700)
            path = parent / "manifest.json"
            path.write_text("{}")
            path.chmod(0o600)
            self.assertEqual(m.private_bytes(path), b"{}")
            link = parent / "link"
            link.symlink_to(path)
            with self.assertRaises(m.Refusal):
                m.private_bytes(link)

    def test_evidence_private_exclusive_and_flushed(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as name:
            parent = Path(name)
            parent.chmod(0o700)
            path = parent / "evidence.jsonl"
            evidence = m.Evidence(path)
            evidence.emit("synthetic", "PASS")
            self.assertEqual(json.loads(path.read_text())["check"], "synthetic")
            evidence.close()
            with self.assertRaises(FileExistsError):
                m.Evidence(path)


class ResourceTests(unittest.TestCase):
    def setUp(self):
        # Historical nonsecret proposal only; all resource calls remain mocked.
        self.c = json.loads(Path(m.CANDIDATE).read_text())
        self.actual = copy.deepcopy(self.c["Docker_metadata_reference"])
        self.ctl = MagicMock()
        self.ctl.docker.side_effect = self.metadata
        self.ctl.credential_metadata.return_value = self.c["credential_reference"]["metadata"]

    def metadata(self, *args):
        if args[0] == "info":
            return self.actual["daemon"]
        if args[0] == "container":
            return self.actual["container"]
        if args[0] == "ps":
            return m.E_CONTAINER
        if args[0] == "volume":
            return self.actual["volume"]
        if args[0] == "network":
            return self.actual["network"]
        raise AssertionError("Unexpected metadata operation")

    def preflight(self, **kwargs):
        with patch.object(m.sys, "platform", "darwin"):
            return m.resource_preflight(self.c, self.ctl, m.Budget(lambda: 0), **kwargs)

    def test_exact_resource_and_secret_guard_success(self):
        self.assertEqual(self.preflight(), "172.21.0.2")
        self.ctl.secret_mount.assert_called_once()
        self.ctl.correlate_secret.assert_called_once()
        self.assertTrue(
            all(x.args[0] in ("info", "container", "ps", "volume", "network") for x in self.ctl.docker.call_args_list)
        )

    def test_changed_container_daemon_storage_network_and_port(self):
        for kind, key, value in (
            ("daemon", "id", "wrong"),
            ("container", "id", "wrong"),
            ("container", "ports", {}),
            ("container", "restarts", 1),
            ("volume", "created", "changed"),
            ("network", "id", "wrong"),
        ):
            self.actual = copy.deepcopy(self.c["Docker_metadata_reference"])
            self.actual[kind][key] = value
            with self.subTest(kind=kind, key=key), self.assertRaises(m.Refusal):
                self.preflight()
        self.ctl.correlate_secret.assert_not_called()

    def test_nonDesktop_refused(self):
        with patch.object(m.sys, "platform", "linux"), self.assertRaises(m.Refusal):
            m.resource_preflight(self.c, self.ctl, m.Budget(lambda: 0))
        self.ctl.correlate_secret.assert_not_called()

    def test_content_correlation_failure_stops(self):
        self.ctl.correlate_secret.side_effect = OSError("synthetic secret mismatch")
        with self.assertRaises(OSError):
            self.preflight()

    def test_postcheck_does_not_reread_secret(self):
        self.preflight(correlate=False)
        self.ctl.correlate_secret.assert_not_called()

    def test_deadline_prevents_metadata(self):
        b = m.Budget(lambda: 0)
        b.clock = lambda: 60
        with self.assertRaises(m.Refusal):
            m.resource_preflight(self.c, self.ctl, b)
        self.ctl.docker.assert_not_called()

    def test_metadata_provenance_change_refused(self):
        self.ctl.credential_metadata.return_value = {"changed": True}
        with self.assertRaises(m.Refusal):
            self.preflight(correlate=False)

    def test_preservation_never_calls_PostgreSQL(self):
        ctl = MagicMock()
        ctl.D_CONTAINER, ctl.IMAGE = "synthetic-D-container", "synthetic-image"
        state = {
            "id": ctl.D_CONTAINER,
            "image": ctl.IMAGE,
            "state": "running",
            "mounts": [{"Destination": "/var/lib/postgresql/data", "Type": "volume", "Name": "sbom-uuid-w1_d_pgdata"}],
            "networks": {"sbom-uuid-w1_d_access": {}},
            "ports": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "56041"}]},
        }
        ctl.docker.side_effect = lambda *args: state if args[-1] == ctl.D_CONTAINER else {"synthetic": args[-1]}
        result = m.preservation(ctl, m.Budget(lambda: 0))
        self.assertEqual(len(result), 10)
        ctl.psycopg.connect.assert_not_called()
        ctl.common.connect.assert_not_called()

    def test_preservation_rejects_changed_D_storage(self):
        ctl = MagicMock()
        ctl.D_CONTAINER, ctl.IMAGE = "synthetic-D-container", "synthetic-image"
        ctl.docker.return_value = {
            "id": ctl.D_CONTAINER,
            "image": ctl.IMAGE,
            "state": "running",
            "mounts": [],
            "networks": {},
            "ports": {},
        }
        with self.assertRaises(m.Refusal):
            m.preservation(ctl, m.Budget(lambda: 0))


if __name__ == "__main__":
    unittest.main()
