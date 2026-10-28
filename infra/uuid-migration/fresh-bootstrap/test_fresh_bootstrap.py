"""Offline synthetic regressions only. No drivers, real credentials or Docker."""

from __future__ import annotations

import ast
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import fresh_bootstrap as fb
import fresh_catalog as fc
from frozen_047 import BASELINE, representation, sha
from pg_lex import Refused, statements

ROOT = Path(__file__).resolve().parents[3]
NOW = datetime(2026, 10, 18, tzinfo=UTC)


def synthetic_plan():
    return {
        "schema": "w21-f-bootstrap-v1",
        "target": deepcopy(fb.TARGET),
        "accepted": False,
        "unit": {"previous": None, "next": BASELINE},
        "identity": {"system_identifier": "1234567890123456789", "database_oid": 17001, "server_ip": "172.30.0.2"},
        "source_sha256": {"synthetic": "a" * 64},
        "budgets": deepcopy(fb.BUDGETS),
        **dict.fromkeys(fb.ATTESTATIONS, True),
        "integrity_approvals": {},
        "integrity_attestations": [False] * 7,
        "approvals": {
            "bootstrap_validate": "SYNTHETIC-VALIDATE",
            "bootstrap_install_047": "SYNTHETIC-INSTALL",
            "bootstrap_readback": "SYNTHETIC-READBACK",
        },
        "expires_at": (NOW + timedelta(hours=1)).isoformat(),
        "effective_authentication_independently_reviewed": True,
        "effective_authentication_review_reference": "SYNTHETIC-AUTH-REVIEW",
        "connection_contract": deepcopy(fb.CONNECTION_CONTRACT),
        "resources": {
            "daemon_id": "1f8c7fe5-5972-4adc-8d6e-363a38572be1",
            "socket": "/Users/ferozebasha/.docker/run/docker.sock",
            "container_id": "1" * 64,
            "network_id": "2" * 64,
            "volume_identity": "3" * 64,
            "image_id": "sha256:" + "4" * 64,
            "credential_metadata_reference": "synthetic-provenance-only",
        },
        "fresh_metadata": {},
        "expected_047_catalog_sha256": "e" * 64,
    }


def approved(plan=None):
    plan = synthetic_plan() if plan is None else plan
    raw = json.dumps(plan).encode()
    return fb.validate_manifest(raw, sha(raw), "bootstrap_validate", "SYNTHETIC-VALIDATE", {"synthetic": "a" * 64}, NOW)


def fresh_observations(plan):
    observed = dict.fromkeys(fc.QUERIES)
    for key in fc.EMPTY:
        observed[key] = []
    observed.update(
        {
            "identity": {
                "database": fb.TARGET["database"],
                "current_user": fb.TARGET["user"],
                "session_user": fb.TARGET["user"],
                "database_oid": plan["identity"]["database_oid"],
                "system_identifier": plan["identity"]["system_identifier"],
                "server_version_num": 160015,
                "transaction_read_only": "on",
                "recovery": False,
                "server_ip": plan["identity"]["server_ip"],
                "server_port": 5432,
                "data_directory": "/var/lib/postgresql/data",
            },
            "schemas": [
                {"nspname": n, "owner": "synthetic-owner", "acl": None}
                for n in ["public", "pg_catalog", "information_schema", "pg_toast"]
            ],
            "extensions": [
                {"extname": "plpgsql", "extversion": "1.0", "schema": "pg_catalog", "owner": fb.TARGET["user"]}
            ],
            "roles": [
                {
                    "oid": 10,
                    "rolname": fb.TARGET["user"],
                    "rolcanlogin": True,
                    "config_null": True,
                    "password_null": False,
                    "password_scram": True,
                }
            ],
            "memberships": [],
            "ownership_acl": [],
            "shared_dependencies": [],
            "settings": [],
            "hba_file": [],
            "alembic": {"relation": None},
        }
    )
    plan["fresh_metadata"] = {
        k: deepcopy(v) for k, v in observed.items() if k not in {*fc.EMPTY, "identity", "alembic"}
    }
    return observed


class SourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = fb.inspect_offline(ROOT)
        cls.original = (ROOT / "scripts/schema/postgresql_047_baseline.sql").read_bytes()

    def test_graph(self):
        self.assertEqual(self.result["active_head"], "079_lifecycle_provider_verification")
        self.assertEqual(self.result["combined_head"], "085_uuid_sbom_component_expand")
        self.assertEqual(len(self.result["units"]), 39)

    def test_snapshot_inventory(self):
        baseline = self.result["baseline"]
        self.assertEqual(baseline["statements"], 558)
        self.assertEqual(baseline["object_statements"], 546)
        self.assertEqual(baseline["families"]["table"], 45)
        self.assertEqual(len(baseline["directives"]), 12)

    def test_definition_bytes_and_order(self):
        old = [s.sql for s in statements(self.original.decode()) if s.tokens[0] not in {"SET", "SELECT"}]
        new = [s.sql for s in statements(self.result["baseline"]["execution_sql"]) if s.tokens[0] != "SET"]
        self.assertEqual(old, new)

    def test_directives_are_hardened(self):
        result = self.result["baseline"]["execution_sql"]
        for required in [
            "SET LOCAL check_function_bodies = on",
            "SET LOCAL row_security = on",
            "SET LOCAL statement_timeout = '30s'",
            "SET LOCAL search_path = pg_catalog, public",
        ]:
            self.assertIn(required, result)

    def test_pending_manifest_never_execution_authority(self):
        raw = (Path(__file__).parent / "approval.pending.json").read_bytes()
        plan = fb.unique_json(raw)
        self.assertFalse(plan["accepted"])
        self.assertEqual(plan["approvals"], {})
        self.assertEqual(plan["integrity_attestations"], [False] * 7)
        self.assertIsNone(plan["identity"]["system_identifier"])
        with self.assertRaises(Refused):
            fb.validate_manifest(raw, sha(raw), "bootstrap_validate", "NOT-ISSUED", plan["source_sha256"], NOW)

    def test_schema_is_complete_and_pending_deliberately_invalid(self):
        schema = json.loads((Path(__file__).parent / "approval.schema.json").read_text())
        template = json.loads((Path(__file__).parent / "approval.pending.json").read_text())
        self.assertEqual(set(schema["required"]), set(template))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["source_reviewed"], {"const": True})
        self.assertFalse(template["source_reviewed"])

    def test_saved_statement_proposal_is_pinned(self):
        proposed = (Path(__file__).parent / "047-execution.proposed.sql").read_bytes()
        diff = (Path(__file__).parent / "047-transformation.diff").read_bytes()
        self.assertEqual(sha(proposed), self.result["baseline"]["execution_sha256"])
        self.assertEqual(sha(diff), self.result["baseline"]["diff_sha256"])

    def test_frozen_tampering_refused(self):
        for change in [b"\n", b"INSERT INTO public.tenants VALUES(1);", b"SET row_security=off;"]:
            with self.subTest(change=change), self.assertRaises(Refused):
                representation(self.original + change)

    def test_no_data_or_sequence_positions(self):
        for entry in statements(self.result["baseline"]["execution_sql"]):
            self.assertNotIn(entry.tokens[0], {"INSERT", "COPY", "UPDATE", "DELETE", "SELECT", "DO"})

    def test_graph_lock_tampering_and_extra_revision(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            for relative in [*self.result["source_sha256"], "infra/uuid-migration/fresh-bootstrap/source-lock.json"]:
                dest = root / relative
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, dest)
            fb.verify_sources(root)
            extra = root / "alembic/versions/086_unapproved.py"
            extra.write_text("revision='086'\n")
            with self.assertRaises(Refused):
                fb.verify_sources(root)
            extra.unlink()
            target = root / "alembic/versions/079_lifecycle_provider_verification.py"
            target.write_text(target.read_text() + "\n")
            with self.assertRaises(Refused):
                fb.verify_sources(root)

    def test_source_symlink_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "infra/uuid-migration/fresh-bootstrap/source-lock.json"
            p.parent.mkdir(parents=True)
            p.symlink_to(ROOT / "infra/uuid-migration/fresh-bootstrap/source-lock.json")
            with self.assertRaises(Refused):
                fb.verify_sources(Path(folder))

    def test_unit_schedule_is_next_only(self):
        for unit in self.result["units"]:
            self.assertEqual(fb.next_unit(self.result["units"], unit["previous"], unit["next"]), unit)
            self.assertTrue(unit["write_close_before_readback"])
            self.assertEqual(unit["owned_transactions"], 1)
        for bad in ["head", "heads", "048:085", "080,081", "085_uuid_sbom_component_expand"]:
            with self.subTest(bad=bad), self.assertRaises(Refused):
                fb.next_unit(self.result["units"], None, bad)

    def test_seed_alternative_never_imports_app(self):
        dependencies = self.result["dependencies"]
        self.assertEqual(len(dependencies["migration_bindings"]), 2)
        self.assertFalse(dependencies["runtime_loader_implemented"])
        for result in dependencies["source_representations"].values():
            tree = ast.parse(result["source"])
            self.assertFalse(
                any(isinstance(n, ast.ImportFrom) and (n.module or "").startswith("app") for n in ast.walk(tree))
            )
            self.assertFalse(result["executed"])

    def test_migration_bodies_preserved_except_frozen_import_bindings(self):
        deps = self.result["dependencies"]
        for revision, result in deps["source_representations"].items():
            path = next(unit["source"] for unit in self.result["units"] if unit["next"] == revision)
            original = ast.parse((ROOT / path).read_bytes())
            replacements = {
                alias.asname or alias.name
                for node in original.body
                if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("app")
                for alias in node.names
            }
            original.body = [
                node
                for node in original.body
                if not (isinstance(node, ast.ImportFrom) and (node.module or "").startswith("app"))
            ]
            proposed = ast.parse(result["source"])
            proposed.body = [
                node
                for node in proposed.body
                if not (
                    isinstance(node, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id in replacements for t in node.targets)
                )
            ]
            self.assertEqual(ast.dump(original), ast.dump(proposed))

    def test_seed_representation_is_stable(self):
        _, graph = fb.verify_sources(ROOT)
        one = fb.isolated_dependencies(ROOT, graph)
        two = fb.isolated_dependencies(ROOT, graph)
        self.assertEqual(one, two)

    def test_frozen_seed_values_preserved(self):
        deps = self.result["dependencies"]
        for module, record in deps["frozen_seeds"].items():
            values = fb.seed_constants(ast.parse(record["source"]))
            for key, value in values.items():
                expression = fb.seed_expression(value)
                synthesized = ast.Module(
                    body=[ast.Assign(targets=[ast.Name(id=key, ctx=ast.Store())], value=expression)], type_ignores=[]
                )
                self.assertEqual(fb.seed_constants(ast.fix_missing_locations(synthesized))[key], value, module)

    def test_reference_contract_and_role_versions(self):
        refs = self.result["reference_contract"]
        self.assertFalse(refs["executed"])
        self.assertEqual(len(refs["after048"]["roles"]), 5)
        self.assertIn("platform:advisor-policy:update", refs["after079"]["role_permissions"]["PLATFORM_ADMIN"])
        self.assertIn("tenant:advisor-policy:update", refs["after079"]["role_permissions"]["TENANT_ADMIN"])
        self.assertNotIn("tenant:advisor-policy:update", refs["after079"]["role_permissions"]["PLATFORM_ADMIN"])
        self.assertEqual(refs["after079"]["role_versions"]["PLATFORM_ADMIN"], 4)

    def test_unapproved_seed_expression(self):
        for source in ["import app.db", "X=open('secret')", "X=frozenset()", "X=unknown", "X=1\nX=2"]:
            with self.subTest(source=source), self.assertRaises((Refused, ValueError)):
                fb.seed_constants(ast.parse(source))

    def test_no_live_connector_or_historical_helper(self):
        for file in ["fresh_bootstrap.py", "fresh_catalog.py", "frozen_047.py", "pg_lex.py"]:
            tree = ast.parse((Path(__file__).parent / file).read_bytes())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    self.assertNotIn(
                        ast.unparse(node.func), ["exec", "eval", "psycopg.connect", "create_engine", "subprocess.run"]
                    )
                if isinstance(node, ast.ImportFrom):
                    self.assertFalse((node.module or "").startswith(("app", "alembic", "dotenv", "psycopg")))

    def test_import_inert(self):
        script = """
import builtins, pathlib, os, sys, socket, subprocess, unittest.mock
sys.path.insert(0, sys.argv[1])
with unittest.mock.patch('builtins.open', side_effect=AssertionError('file')), unittest.mock.patch.object(pathlib.Path,'read_bytes',side_effect=AssertionError('read')), unittest.mock.patch('os.open',side_effect=AssertionError('os.open')), unittest.mock.patch('socket.socket',side_effect=AssertionError('network')), unittest.mock.patch('subprocess.Popen',side_effect=AssertionError('process')):
 import fresh_bootstrap, fresh_catalog, frozen_047, pg_lex
assert not any(n in sys.modules for n in ['app.db','app.settings','psycopg','dotenv','alembic'])
"""
        result = subprocess.run(
            [sys.executable, "-B", "-c", script, str(Path(__file__).parent)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_live_cli_refuses_before_source_or_file_reads(self):
        with (
            patch.object(fb, "inspect_offline", side_effect=AssertionError("runtime")),
            self.assertRaises(SystemExit) as error,
        ):
            fb.main(["--mode", "live"])
        self.assertEqual(error.exception.code, 2)


class LexerTests(unittest.TestCase):
    def test_standard_quotes_and_identifiers(self):
        sql = "SELECT 'a;''b', \"semi;\"\"colon\"; SELECT 2;"
        self.assertEqual(len(statements(sql)), 2)

    def test_dollar_function_body(self):
        sql = (
            "CREATE FUNCTION f() RETURNS void AS $body$ BEGIN PERFORM ';'; END; $body$ LANGUAGE plpgsql; SELECT $$;$$;"
        )
        self.assertEqual(len(statements(sql)), 2)

    def test_escape_strings(self):
        self.assertEqual(len(statements("SELECT E'a\\';b'; SELECT 2;")), 2)

    def test_nested_comments(self):
        framed = statements("/* ; /* ; */ ; */ SELECT 1; -- ;\n SELECT 2;")
        self.assertEqual(len(framed), 2)

    def test_comment_only_tail(self):
        self.assertEqual(len(statements("SELECT 1; -- tail;")), 1)

    def test_ambiguous_and_unterminated_rejected(self):
        for sql in [
            "SELECT 'bad",
            "SELECT $x$bad",
            "/* bad",
            "SELECT 1",
            "SELECT 'a\\b';",
            "\\connect D",
            "SELECT U&'abc';",
            ";",
            "SELECT '\x00';",
        ]:
            with self.subTest(sql=sql), self.assertRaises(Refused):
                statements(sql)

    def test_unknown_statement_not_adopted(self):
        from frozen_047 import kind

        for sql in [
            "INSERT INTO x VALUES(1);",
            "CREATE FUNCTION f() RETURNS int AS $$ SELECT 1 $$ LANGUAGE sql;",
            "SET strange=1;",
        ]:
            with self.subTest(sql=sql), self.assertRaises(Refused):
                kind(statements(sql)[0].tokens)


class ManifestTests(unittest.TestCase):
    def test_synthetic_only_valid_contract(self):
        self.assertEqual(approved()["target"], fb.TARGET)

    def test_exact_raw_not_canonical_digest(self):
        plan = synthetic_plan()
        raw = json.dumps(plan, indent=2).encode()
        self.assertNotEqual(sha(raw), fb.canonical(plan))
        with self.assertRaises(Refused):
            fb.validate_manifest(
                raw, fb.canonical(plan), "bootstrap_validate", "SYNTHETIC-VALIDATE", plan["source_sha256"], NOW
            )

    def test_duplicate_keys(self):
        with self.assertRaises(Refused):
            fb.unique_json(b'{"accepted":false,"accepted":true}')

    def test_missing_malformed_hash(self):
        for value in [None, "", "x" * 64]:
            with self.subTest(value=value), self.assertRaises(Refused):
                fb.private_manifest("/nonexistent.json", value)

    def test_protected_bytes_and_preauth_recheck(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            root.chmod(0o700)
            p = root / "manifest.json"
            raw = json.dumps(synthetic_plan()).encode()
            p.write_bytes(raw)
            p.chmod(0o600)
            self.assertEqual(fb.private_manifest(p, sha(raw))[0], raw)
            fb.recheck_manifest(
                p,
                sha(raw),
                raw,
                action="bootstrap_validate",
                approval="SYNTHETIC-VALIDATE",
                sources=synthetic_plan()["source_sha256"],
                now=NOW,
            )
            p.write_bytes(raw + b" ")
            with self.assertRaises(Refused):
                fb.recheck_manifest(
                    p,
                    sha(raw),
                    raw,
                    action="bootstrap_validate",
                    approval="SYNTHETIC-VALIDATE",
                    sources=synthetic_plan()["source_sha256"],
                    now=NOW,
                )

    def test_permissions_and_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "manifest.json"
            p.write_text("{}")
            p.chmod(0o644)
            with self.assertRaises(Refused):
                fb.private_manifest(p, sha(b"{}"))
            p.chmod(0o600)
            link = Path(folder) / "linked.json"
            link.symlink_to(p)
            with self.assertRaises(Refused):
                fb.private_manifest(link, sha(b"{}"))

    def test_environment_no_ambient_overrides(self):
        for key in [
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
            "DATABASE_URL",
            "PYTHONPATH",
            "DOCKER_HOST",
        ]:
            with self.subTest(key=key), self.assertRaises(Refused):
                fb.clean_environment({key: "synthetic"})
        self.assertEqual(fb.clean_environment({"PATH": "/usr/bin:/bin"}), {"PATH": "/usr/bin:/bin"})

    def test_failure_diagnostic_never_logs_arguments(self):
        error = RuntimeError("postgres://name:synthetic-password@host secret")
        error.sqlstate = "08001"
        result = fb.safe_error(error, "synthetic-password")
        self.assertEqual(result["sqlstate"], "08001")
        self.assertNotIn("password", json.dumps(result))


def add_manifest_refusal(name, mutate):
    def test(self):
        plan = synthetic_plan()
        mutate(plan)
        with self.assertRaises((Refused, ValueError, TypeError)):
            approved(plan)

    setattr(ManifestTests, "test_refuses_" + name, test)


for name, mutate in {
    "host": lambda p: p["target"].update(host="example.com"),
    "hostaddr": lambda p: p["target"].update(hostaddr="/tmp"),
    "port_D": lambda p: p["target"].update(port=56041),
    "port_E": lambda p: p["target"].update(port=56042),
    "port_B": lambda p: p["target"].update(port=55439),
    "database": lambda p: p["target"].update(database="uuid_w1_d_rehearsal"),
    "user": lambda p: p["target"].update(user="uuid_w1_d_bootstrap"),
    "cluster_D": lambda p: p["identity"].update(system_identifier=fb.FORBIDDEN_CLUSTER),
    "cluster_missing": lambda p: p["identity"].update(system_identifier=None),
    "oid_bool": lambda p: p["identity"].update(database_oid=True),
    "expired": lambda p: p.update(expires_at=NOW.isoformat()),
    "naive_expiry": lambda p: p.update(expires_at="2026-10-20T00:00:00"),
    "source": lambda p: p.update(source_sha256={}),
    "unapproved": lambda p: p.update(source_reviewed=False),
    "missing_action": lambda p: p.update(approvals={}),
    "reused_action": lambda p: p["approvals"].update(bootstrap_readback="SYNTHETIC-VALIDATE"),
    "accepted_baseline": lambda p: p.update(accepted=True),
    "stamp079": lambda p: p["unit"].update(next="079_lifecycle_provider_verification"),
    "integrity_approval": lambda p: p.update(integrity_approvals={"integrity_execute": "forbidden"}),
    "integrity_flag": lambda p: p.update(integrity_attestations=[True] * 7),
    "extra_connection": lambda p: p["budgets"].update(attempts=2),
    "wrong_daemon": lambda p: p["resources"].update(daemon_id="remote"),
    "missing_container": lambda p: p["resources"].update(container_id=""),
    "auth_unknown": lambda p: p.update(effective_authentication_independently_reviewed=False),
    "hidden_role_creation": lambda p: p.update(role_creation=True),
    "service_option": lambda p: p["connection_contract"].update(service=""),
    "passfile_fallback": lambda p: p["connection_contract"].update(passfile="~/.pgpass"),
    "boolean_budget": lambda p: p["budgets"].update(attempts=True),
    "missing_auth_evidence_reference": lambda p: p.update(effective_authentication_review_reference=None),
}.items():
    add_manifest_refusal(name, mutate)


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.plan = synthetic_plan()
        self.observed = fresh_observations(self.plan)

    def test_fresh_synthetic_contract(self):
        self.assertFalse(fc.validate_fresh(self.observed, self.plan)["live_accepted"])

    def test_unknown_is_not_empty(self):
        self.observed["relations"] = None
        with self.assertRaises(Refused):
            fc.validate_fresh(self.observed, self.plan)

    def test_missing_catalog_query(self):
        del self.observed["types"]
        with self.assertRaises(Refused):
            fc.validate_fresh(self.observed, self.plan)

    def test_hba_not_active_policy_proof(self):
        self.plan["effective_authentication_independently_reviewed"] = False
        with self.assertRaises(Refused):
            fc.validate_fresh(self.observed, self.plan)

    def test_database_identity_gate(self):
        for key, value in [
            ("database", "D"),
            ("current_user", "wrong"),
            ("server_version_num", 160014),
            ("system_identifier", fb.FORBIDDEN_CLUSTER),
            ("transaction_read_only", "off"),
            ("recovery", True),
            ("data_directory", "/other"),
        ]:
            observed = deepcopy(self.observed)
            observed["identity"][key] = value
            with self.subTest(key=key), self.assertRaises(Refused):
                fc.validate_fresh(observed, self.plan)

    def test_new_schema_extension_role_and_acl_refused(self):
        for category in [
            "schemas",
            "extensions",
            "roles",
            "memberships",
            "ownership_acl",
            "shared_dependencies",
            "settings",
            "hba_file",
        ]:
            observed = deepcopy(self.observed)
            observed[category].append({"unexpected": True})
            with self.subTest(category=category), self.assertRaises(Refused):
                fc.validate_fresh(observed, self.plan)

    def test_existing_marker_refused(self):
        self.observed["alembic"] = {"relation": "alembic_version"}
        with self.assertRaises(Refused):
            fc.validate_fresh(self.observed, self.plan)

    def test_catalog_queries_compile_without_engine(self):
        from sqlalchemy import text
        from sqlalchemy.dialects.postgresql import dialect

        self.assertLessEqual(len(fc.QUERIES), 64)
        for query in fc.QUERIES.values():
            self.assertTrue(query.startswith("SELECT "))
            self.assertTrue(str(text(query).compile(dialect=dialect())))
        self.assertIn("r.rolconfig IS NULL", fc.QUERIES["roles"])
        self.assertNotIn("a.rolconfig", fc.QUERIES["roles"])


def add_catalog_refusal(name):
    def test(self):
        self.observed[name] = [{"synthetic_unapproved_object": True}]
        with self.assertRaises(Refused):
            fc.validate_fresh(self.observed, self.plan)

    setattr(CatalogTests, "test_refuses_occupied_" + name, test)


for name in fc.EMPTY:
    add_catalog_refusal(name)


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.contract = fb.UnitContract(("one", "two"), "catalog")

    def installed(self):
        self.contract.begin(freshness_verified=True, separately_authorized=True)
        self.contract.lock_ack(fb.SERIALIZATION_KEY, freshness_rechecked=True)
        self.contract.schema_ack("one")
        self.contract.schema_ack("two")
        return self.contract.marker_instruction()

    def prepared(self):
        self.installed()
        self.contract.marker_ack(1, [(BASELINE,)], schema_verified=True)

    def test_marker_cannot_precede_schema(self):
        with self.assertRaises(Refused):
            self.contract.marker_instruction()
        self.contract.begin(freshness_verified=True, separately_authorized=True)
        self.contract.lock_ack(fb.SERIALIZATION_KEY, freshness_rechecked=True)
        self.contract.schema_ack("one")
        with self.assertRaises(Refused):
            self.contract.marker_instruction()

    def test_correct_parameterized_marker(self):
        instruction = self.installed()
        self.assertEqual(instruction["parameters"], (BASELINE,))
        self.assertIn("%s", instruction["insert"])
        self.assertNotIn(BASELINE, instruction["insert"])

    def test_wrong_schema_order(self):
        self.contract.begin(freshness_verified=True, separately_authorized=True)
        self.contract.lock_ack(fb.SERIALIZATION_KEY, freshness_rechecked=True)
        with self.assertRaises(Refused):
            self.contract.schema_ack("two")

    def test_wrong_returning_rows(self):
        self.installed()
        with self.assertRaises(Refused):
            self.contract.marker_ack(2, [(BASELINE,), (BASELINE,)], schema_verified=True)

    def test_no_commit_before_precommit(self):
        with self.assertRaises(Refused):
            self.contract.commit_requested()

    def test_install_forbidden_before_serialized_fresh_recheck(self):
        self.contract.begin(freshness_verified=True, separately_authorized=True)
        with self.assertRaises(Refused):
            self.contract.schema_ack("one")
        with self.assertRaises(Refused):
            self.contract.lock_ack(fb.SERIALIZATION_KEY, freshness_rechecked=False)
        with self.assertRaises(Refused):
            self.contract.lock_ack(17, freshness_rechecked=True)

    def test_known_failure_rollback_then_close(self):
        self.contract.begin(freshness_verified=True, separately_authorized=True)
        self.assertEqual(self.contract.failure(), "ROLLBACK")
        self.contract.rollback_ack()
        self.contract.close_ack(True)
        self.assertEqual(self.contract.phase, "ROLLED_BACK")
        with self.assertRaises(Refused):
            self.contract.begin(freshness_verified=True, separately_authorized=True)

    def test_unknown_commit_never_rollback_or_retry(self):
        self.prepared()
        self.contract.commit_requested()
        self.assertEqual(self.contract.failure(), "STOP_MANUAL_RECONCILIATION")
        self.contract.close_ack(True)
        with self.assertRaises(Refused):
            self.contract.rollback_ack()
        with self.assertRaises(Refused):
            self.contract.begin(freshness_verified=True, separately_authorized=True)

    def test_unconfirmed_rollback_never_retries(self):
        self.contract.begin(freshness_verified=True, separately_authorized=True)
        self.contract.failure()
        self.assertEqual(self.contract.failure(), "STOP_MANUAL_RECONCILIATION")
        with self.assertRaises(Refused):
            self.contract.rollback_ack()

    def test_commit_ack_missing_never_accepts(self):
        self.prepared()
        self.contract.commit_requested()
        self.contract.close_ack(True)
        with self.assertRaises(Refused):
            self.contract.readback(
                [BASELINE], "catalog", separate_authorization=True, new_readonly_connection_closed=True
            )

    def test_independent_readback_after_close(self):
        self.prepared()
        self.contract.commit_requested()
        self.contract.commit_ack()
        with self.assertRaises(Refused):
            self.contract.readback(
                [BASELINE], "catalog", separate_authorization=True, new_readonly_connection_closed=True
            )
        self.contract.close_ack(True)
        result = self.contract.readback(
            [BASELINE], "catalog", separate_authorization=True, new_readonly_connection_closed=True
        )
        self.assertFalse(result["runtime_accepted"])
        self.assertEqual(self.contract.phase, "VERIFIED")

    def test_mismatched_readback_or_no_authority(self):
        self.prepared()
        self.contract.commit_requested()
        self.contract.commit_ack()
        self.contract.close_ack(True)
        with self.assertRaises(Refused):
            self.contract.readback(
                [BASELINE], "wrong", separate_authorization=True, new_readonly_connection_closed=True
            )
        with self.assertRaises(Refused):
            self.contract.readback(
                [BASELINE], "catalog", separate_authorization=False, new_readonly_connection_closed=True
            )

    def test_connection_failure_no_reconnect(self):
        self.assertEqual(self.contract.failure(), "STOP_NO_TRANSACTION")
        with self.assertRaises(Refused):
            self.contract.begin(freshness_verified=True, separately_authorized=True)

    def test_budgets(self):
        budget = fb.Budget(0)
        budget.operation("connect", 0)
        with self.assertRaises(Refused):
            budget.operation("connect", 1)
        for _ in range(64):
            budget.operation("query", 1)
        with self.assertRaises(Refused):
            budget.operation("query", 2)
        for _ in range(4):
            budget.operation("control", 1)
        with self.assertRaises(Refused):
            budget.operation("control", 2)

    def test_deadline(self):
        with self.assertRaises(Refused):
            fb.Budget(0).operation("query", 120)


if __name__ == "__main__":
    unittest.main(verbosity=2)
