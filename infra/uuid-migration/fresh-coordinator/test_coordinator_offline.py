"""W2.3 offline tests. Mocks/synthetic JSON only; never reads a real secret."""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import authority as auth
import coordinator as co
import isolated_loader as loader
import observations as obs
import source_registry as src
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import dialect

ROOT = Path(__file__).resolve().parents[3]
REG = src.discover(ROOT)
NOW = datetime.now(UTC)
SYNTHETIC_AUTH_DIRECTORY = tempfile.TemporaryDirectory()


def resources(plan):
    r = plan["resources"]
    c = plan["credential_metadata"]
    return {
        "pins": copy.deepcopy(r),
        "labels": {"project": auth.TARGET["project"], "service": auth.TARGET["service"]},
        "networks": [{"name": auth.TARGET["network"], "id": r["network_id"]}],
        "volume": {
            "name": auth.TARGET["volume"],
            "identity": r["volume_identity"],
            "destination": "/var/lib/postgresql/data",
        },
        "exclusive_volume_users": [r["container_id"]],
        "publication": [{"host_ip": "127.0.0.1", "host_port": 56043, "container_port": 5432}],
        "mount": {
            "type": "bind",
            "source": "/host_mnt" + c["path"],
            "destination": "/run/secrets/f_password",
            "rw": False,
        },
        "credential": {"regular": True, "symlink": False, "metadata": copy.deepcopy(c)},
        "correlation": {
            "performed": True,
            "equal": True,
            "container_id": r["container_id"],
            "source": c["path"],
            "destination": "/run/secrets/f_password",
        },
    }


def fresh_sample(plan):
    fc = src.reference_api(ROOT, REG)["fresh_catalog"]
    raw = {key: [] for key in fc.QUERIES}
    raw.update(
        {
            "identity": {
                "database": auth.TARGET["database"],
                "current_user": auth.TARGET["user"],
                "session_user": auth.TARGET["user"],
                **plan["identity"],
                "server_version_num": 160015,
                "transaction_read_only": "on",
                "recovery": False,
                "server_port": 5432,
                "data_directory": "/var/lib/postgresql/data",
            },
            "schemas": [
                {"nspname": n, "owner": "SYNTHETIC", "acl": None}
                for n in ("public", "pg_catalog", "information_schema", "pg_toast")
            ],
            "extensions": [
                {"extname": "plpgsql", "extversion": "1.0", "schema": "pg_catalog", "owner": auth.TARGET["user"]}
            ],
            "roles": [
                {
                    "oid": 10,
                    "rolname": auth.TARGET["user"],
                    "rolcanlogin": True,
                    "config_null": True,
                    "password_null": False,
                    "password_scram": True,
                }
            ],
            "alembic": {"relation": None},
        }
    )
    plan["fresh_metadata"] = {
        k: copy.deepcopy(v) for k, v in raw.items() if k not in {*fc.EMPTY, "identity", "alembic"}
    }
    return raw


def reference_rows(state):
    e = obs.reference_requirements(ROOT, REG, state)
    if e is None:
        return {"roles": [], "permissions": [], "mappings": [], "audit_actions": []}
    mappings = e["mappings"] or {}
    codes = sorted(set(e["base_permissions"]) | {p for perms in mappings.values() for p in perms})
    return {
        "roles": [
            {
                "code": code,
                "scope": scope,
                "status": "ACTIVE",
                "is_system": True,
                "is_assignable": True,
                "version": e["versions"][code] if e["versions"] is not None else 1,
            }
            for code, scope in e["scopes"].items()
        ],
        "permissions": [
            {
                "code": code,
                "scope": "PLATFORM" if code.startswith("platform:") else "TENANT",
                "status": "ACTIVE",
                "is_system": True,
            }
            for code in codes
        ],
        "mappings": [
            {
                "role": r,
                "permission": p,
                "is_protected": (r == "PLATFORM_ADMIN" and e["number"] >= 64) or p in e["protected"].get(r, ()),
            }
            for r, perms in mappings.items()
            for p in sorted(perms)
        ],
        "audit_actions": ["AUTHORIZATION_CATALOG_SEEDED"],
    }


def observations(plan, unit, readonly=True, after=False):
    catalog = {k: [] for k in obs.catalog_queries(ROOT, REG)}
    if unit["kind"] != "frozen_047" or after:
        catalog["relations"] = [{"nspname": "public", "relname": "tenants", "relkind": "r"}]
    if after:
        catalog["columns"] = [{"synthetic_expected_post": unit["next"]}]
    raw = {
        "identity": {
            **plan["identity"],
            "database": auth.TARGET["database"],
            "user": auth.TARGET["user"],
            "session_user": auth.TARGET["user"],
            "version": 160015,
            "port": 5432,
            "data_directory": "/var/lib/postgresql/data",
            "read_only": "on" if readonly else "off",
            "recovery": False,
            "replication": "origin",
            "row_security": "on",
            "search_path": "pg_catalog",
        },
        "catalog": catalog,
        "references": reference_rows(unit["next"] if after else unit["previous"]),
        "business": []
        if unit["kind"] == "frozen_047" and not after
        else [{"schema": "public", "table": "tenants", "has_rows": False, "rls": False}],
        "clients": [],
        "locks": [],
        "marker": [unit["next"]] if after else [] if unit["previous"] is None else [unit["previous"]],
        "fresh_catalog": fresh_sample(plan) if unit["kind"] == "frozen_047" and not after else None,
        "finalization_catalog": None,
    }
    if unit["kind"] == "uuid_finalize" and not after:
        raw["finalization_catalog"] = {
            k: []
            for k in (
                "relations",
                "columns",
                "constraints",
                "indexes",
                "functions",
                "triggers",
                "roles",
                "memberships",
                "extensions",
                "schemas",
                "default_acl",
                "database",
                "sequences",
                "rules",
                "reference_roles",
                "reference_permissions",
                "reference_mappings",
            )
        }
    return raw


def plan(index=1):
    unit = REG["units"][index]
    p = {
        "schema": "w23-f-unit-v1",
        "accepted": False,
        "target": copy.deepcopy(auth.TARGET),
        "unit": {"previous": unit["previous"], "next": unit["next"]},
        "source_sha256": auth.source_bundle(ROOT, REG),
        "identity": {"system_identifier": "1234567890123456789", "database_oid": 17001, "server_ip": "172.30.0.2"},
        "resources": {
            "daemon_id": auth.DAEMON,
            "socket": auth.SOCKET,
            "container_id": "a" * 64,
            "image_id": "sha256:" + "b" * 64,
            "volume_identity": "c" * 64,
            "network_id": "d" * 64,
            "started_at": "SYNTHETIC-START",
        },
        "credential_metadata": {
            "path": "/Users/ferozebasha/.sbom-uuid-w2-f/postgres-password",
            "uid": 501,
            "inode": 123,
            "size": 32,
            "mode": 0o600,
            "parent_mode": 0o700,
            "nlink": 1,
            "mtime_ns": 123,
            "ctime_ns": 123,
        },
        "prefix_sha256": None,
        "post_sha256": None,
        "finalization_catalog_sha256": None,
        "security_sha256": None,
        "reference_sha256": None,
        "fresh_metadata": None,
        "reviews": dict.fromkeys(auth.REVIEWS, True),
        "review_references": {key: "SYNTHETIC-REVIEW-" + key for key in auth.REVIEWS},
        "approvals": {
            "unit_validate": "SYNTHETIC-VALIDATE",
            "unit_execute": "SYNTHETIC-EXECUTE",
            "unit_readback": "SYNTHETIC-READBACK",
        },
        "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        "budgets": dict(unit["budgets"]),
        "connection": auth.connection_contract(unit),
        "integrity_attestations": [False] * 7,
        "integrity_approvals": {},
    }
    before = observations(p, unit)
    after = observations(p, unit, after=True)
    p["prefix_sha256"] = src.digest(before["catalog"])
    p["post_sha256"] = src.digest(after["catalog"])
    p["security_sha256"] = src.digest({k: before["catalog"][k] for k in obs.SECURITY_KEYS})
    p["reference_sha256"] = src.digest(before["references"])
    p["post_reference_sha256"] = src.digest(after["references"])
    if before["finalization_catalog"] is not None:
        p["finalization_catalog_sha256"] = src.digest(before["finalization_catalog"])
    directory = Path(SYNTHETIC_AUTH_DIRECTORY.name).resolve()
    directory.chmod(0o700)
    record = {
        "schema": "w23-independent-auth-review-v1",
        "scope": "effective_password_authentication",
        "target": p["target"],
        "identity": p["identity"],
        "resource_sha256": src.digest(p["resources"]),
        "evidence_sha256": "e" * 64,
        "expires_at": p["expires_at"],
    }
    path = directory / (src.digest(record) + ".json")
    path.write_text(json.dumps(record))
    path.chmod(0o600)
    p["authentication_review"] = {"path": str(path), "sha256": src.sha(path.read_bytes())}
    return p


class PrivatePlan:
    def __init__(self, p, action="unit_execute"):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name).resolve()
        self.directory.chmod(0o700)
        self.path = self.directory / "approval.json"
        self.path.write_bytes(json.dumps(p).encode())
        self.path.chmod(0o600)
        self.raw = self.path.read_bytes()
        self.hash = src.sha(self.raw)
        self.authority = auth.Authority(
            self.path, self.hash, ROOT, p["unit"]["previous"], p["unit"]["next"], action, p["approvals"][action]
        )

    def close(self):
        self.temp.cleanup()


def backend(p, unit):
    b = MagicMock()
    s = MagicMock()
    s.autocommit = False
    s.closed = False
    s.dialect.default_schema_name = "public"
    s.close.side_effect = lambda: setattr(s, "closed", True)

    def query(sql, params):
        if sql == co.ADVISORY:
            return [{"acquired": True}]
        if sql == co.VERSION_SELECT:
            return [{"version_num": unit["next"] if s.marker.called else unit["previous"]}]
        raise AssertionError("Unexpected mock query")

    s.query.side_effect = query
    s.marker.return_value = {"rowcount": 1, "rows": [{"version_num": unit["next"]}]}
    b.connect.return_value = s
    b.resources.return_value = resources(p)

    def observe(session, meter, selected, *, readonly, after):
        meter.charge("catalog_queries", len(obs.catalog_queries(ROOT, REG)))
        result = observations(copy.deepcopy(p), selected, readonly, after)
        if after and not readonly:
            result["marker"] = [] if unit["previous"] is None else [unit["previous"]]
        return result

    b.observe.side_effect = observe
    return b, s


class SourceTests(unittest.TestCase):
    def test_isolated_alembic_factory_recipe(self):
        connection = MagicMock()
        factory = MagicMock()
        operations_factory = MagicMock()
        options = {
            "as_sql": False,
            "transactional_ddl": True,
            "version_table": "alembic_version",
            "version_table_schema": "public",
        }
        context, operations = loader.configure_mock_operations(connection, options, factory, operations_factory)
        factory.configure.assert_called_once_with(connection=connection, opts=options)
        operations_factory.assert_called_once_with(context)
        self.assertIs(operations, operations_factory.return_value)
        connection.execute.assert_not_called()
        context.run_migrations.assert_not_called()
        with self.assertRaises(src.Refused):
            loader.configure_mock_operations(connection, {**options, "as_sql": True}, factory, operations_factory)

    def test_45_units_and_91_linear_graph(self):
        self.assertEqual(len(REG["graph"]), 91)
        self.assertEqual(len(REG["units"]), 45)
        self.assertIsNone(REG["units"][0]["previous"])
        self.assertEqual(REG["units"][-1]["next"], "091_uuid_sbom_component_finalize")
        self.assertEqual([len(list((ROOT / f).glob("*.py"))) for f in src.SETS], [79, 6, 6])

    def test_original_package_and_lock_hashes(self):
        for key, path in [("w21", "w21-20261018T164159255183Z"), ("w22", "w22-20261018T171500606188Z")]:
            f = ROOT.parent / ".sbom-uuid-w2-review" / path / (key + "-source-review-package.json")
            self.assertEqual(src.sha(f.read_bytes()), src.PACKAGES[key])
            for rel, item in json.loads(f.read_bytes())["files"].items():
                self.assertEqual(src.sha((ROOT / rel).read_bytes()), item["sha256"])

    def test_duplicate_branch_missing_and_cycle(self):
        for case in ("duplicate", "missing", "cycle", "branch", "disconnected"):
            rows = copy.deepcopy(REG["graph"])
            if case == "duplicate":
                rows[-1]["revision"] = rows[-2]["revision"]
            elif case == "missing":
                rows.pop(0)
            elif case == "cycle":
                rows[48]["down_revision"] = rows[48]["revision"]
            elif case == "branch":
                rows[48]["branch_labels"] = "other"
            else:
                rows[-1]["down_revision"] = rows[-3]["revision"]
            with self.subTest(case=case), self.assertRaises(src.Refused):
                src.inspect_graph(rows)

    def test_tamper_and_extra_source_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            for rel in set(REG["lock"]["sources"]) | {src.DIRECTORY + "/source-lock.v2.json"}:
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT / rel).read_bytes())
            self.assertEqual(len(src.discover(root)["units"]), 45)
            p = root / "alembic/versions/999_unapproved.py"
            p.write_text("pass\n")
            with self.assertRaises(src.Refused):
                src.discover(root)
            p.unlink()
            p = root / REG["units"][1]["source"]
            p.write_bytes(p.read_bytes() + b"\n")
            with self.assertRaises(src.Refused):
                src.discover(root)

    def test_next_only_all45(self):
        for unit in REG["units"]:
            self.assertEqual(src.next_unit(REG, unit["previous"], unit["next"]), unit)
        for previous, next_ in [
            (None, "head"),
            (None, REG["units"][1]["next"]),
            ("079_lifecycle_provider_verification", REG["units"][34]["next"]),
            ("x", ["head"]),
            ("085_uuid_sbom_component_expand", "085_uuid_sbom_component_expand"),
        ]:
            with self.assertRaises(src.Refused):
                src.next_unit(REG, previous, next_)

    def test_frozen558_and_order(self):
        sql = loader.frozen_statements(ROOT, REG)
        self.assertEqual(len(sql), 558)
        self.assertIn("SET LOCAL statement_timeout = '30s'", sql[0])
        self.assertTrue(any("CREATE TABLE public.tenants" in q for q in sql))

    def test_all44_individual_modules_bind_without_upgrade(self):
        for unit in REG["units"][1:]:
            op = MagicMock()
            ctx = SimpleNamespace(as_sql=False)
            binding = loader.bind_mock(ROOT, REG, unit, op, ctx)
            self.assertEqual(binding.namespace["revision"], unit["next"])
            self.assertEqual(op.mock_calls, [])
            self.assertNotIn("app.db", binding.namespace)

    def test_seed_alternatives_exact_and_bodies_preserved(self):
        for key in REG["lock"]["seed_alternatives"]:
            unit = next(u for u in REG["units"] if u["next"] == key)
            source = loader.binding_source(ROOT, REG, unit)
            self.assertEqual(src.sha(source.encode()), REG["lock"]["seed_alternatives"][key]["sha256"])
            self.assertNotIn("from app.", source)

    def test_001_and_forged_unit_refused(self):
        u = copy.deepcopy(REG["units"][1])
        u["source"] = "alembic/versions/001_initial_schema.py"
        with self.assertRaises(src.Refused):
            loader.bind_mock(ROOT, REG, u, MagicMock(), SimpleNamespace(as_sql=False))
        with self.assertRaises(src.Refused):
            loader.bind_mock(ROOT, REG, REG["units"][1], object(), SimpleNamespace(as_sql=False))

    def test_inert_imports(self):
        for path in (ROOT / src.DIRECTORY).glob("*.py"):
            if path.name.startswith("test_"):
                continue
            spec = importlib.util.spec_from_file_location("_w23_inert_" + path.stem, path)
            module = importlib.util.module_from_spec(spec)
            import sys

            sys.modules[spec.name] = module
            try:
                with (
                    patch.object(Path, "read_bytes", side_effect=AssertionError("I/O on import")),
                    patch("socket.socket", side_effect=AssertionError("network on import")),
                ):
                    spec.loader.exec_module(module)
            finally:
                sys.modules.pop(spec.name, None)

    def test_live_cli_denies_before_source_or_manifest(self):
        with (
            patch.object(co, "inspect_offline", side_effect=AssertionError("source read")),
            self.assertRaises(SystemExit) as error,
        ):
            co.main(["--mode", "live"])
        self.assertEqual(error.exception.code, 2)

    def test_promotion_proposal_only12_exact_operations(self):
        proposal = src.promotion_plan(REG)
        self.assertEqual(len(proposal), 12)
        self.assertTrue(all(p["requires_destination_absent"] for p in proposal))
        self.assertEqual(len(list((ROOT / "alembic/versions").glob("*.py"))), 79)

    def test_catalog_templates_compile_no_engine(self):
        queries = obs.catalog_queries(ROOT, REG)
        for sql in queries.values():
            self.assertTrue(str(text(sql).compile(dialect=dialect())))
        self.assertGreater(len(queries), 24)


class ApprovalTests(unittest.TestCase):
    def test_hba_file_only_or_missing_auth_review_refused(self):
        p = plan()
        for kind in ("missing", "file_only", "changed_bytes"):
            altered = copy.deepcopy(p)
            if kind == "missing":
                altered["authentication_review"] = None
            else:
                path = Path(altered["authentication_review"]["path"])
                record = json.loads(path.read_bytes())
                record["scope"] = "hba_current_file_parse_only"
                replacement = path.parent / (kind + ".json")
                replacement.write_text(json.dumps(record))
                replacement.chmod(0o600)
                altered["authentication_review"]["path"] = str(replacement)
                if kind == "file_only":
                    altered["authentication_review"]["sha256"] = src.sha(replacement.read_bytes())
            raw = json.dumps(altered).encode()
            with self.subTest(kind=kind), self.assertRaises(src.Refused):
                auth.validate(
                    raw,
                    src.sha(raw),
                    ROOT,
                    altered["unit"]["previous"],
                    altered["unit"]["next"],
                    "unit_execute",
                    "SYNTHETIC-EXECUTE",
                )

    def test_valid_synthetic_raw_and_canonical_separate(self):
        p = plan()
        raw = json.dumps(p, indent=2).encode()
        actual, _, _ = auth.validate(
            raw, src.sha(raw), ROOT, p["unit"]["previous"], p["unit"]["next"], "unit_execute", "SYNTHETIC-EXECUTE"
        )
        self.assertEqual(actual, p)
        self.assertNotEqual(src.sha(raw), src.digest(p))

    def test_missing_raw_hash_and_duplicate_json_rejected(self):
        p = plan()
        raw = json.dumps(p).encode()
        for data, h in [(raw, None), (raw, "0" * 64), (b'{"a":1,"a":2}', src.sha(b'{"a":1,"a":2}'))]:
            with self.assertRaises(src.Refused):
                auth.validate(
                    data, h, ROOT, p["unit"]["previous"], p["unit"]["next"], "unit_execute", "SYNTHETIC-EXECUTE"
                )

    def test_private_bytes_tamper_symlink_mode(self):
        pp = PrivatePlan(plan())
        self.addCleanup(pp.close)
        pp.path.write_bytes(pp.raw + b"\n")
        with self.assertRaises(src.Refused):
            pp.authority.recheck()
        pp.path.write_bytes(pp.raw)
        pp.path.chmod(0o644)
        with self.assertRaises(src.Refused):
            auth.private_bytes(pp.path, pp.hash)
        pp.path.chmod(0o600)
        link = pp.directory / "link.json"
        link.symlink_to(pp.path)
        with self.assertRaises(src.Refused):
            auth.private_bytes(link, pp.hash)

    def test_manifest_only_cannot_create_finalization_context(self):
        p = plan(39)
        pp = PrivatePlan(p)
        self.addCleanup(pp.close)
        with self.assertRaises(src.Refused):
            obs.finalization_context(pp.authority, {"accepted": True})

    def test_fixed_connection_no_service_or_fallback(self):
        for unit in REG["units"]:
            c = auth.connection_contract(unit)
            self.assertNotIn("service", c)
            self.assertEqual(c["passfile"], "/dev/null")
            self.assertEqual(c["hostaddr"], "127.0.0.1")
            self.assertEqual(c["port"], 56043)
            self.assertIn("default_transaction_read_only=on", c["options"])

    def test_environment_refusal(self):
        for key in (
            "PGHOST",
            "PGSERVICE",
            "PGPASSWORD",
            "PGOPTIONS",
            "DATABASE_URL",
            "PYTHONPATH",
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
        ):
            with self.assertRaises(src.Refused):
                auth.clean_environment({key: "SYNTHETIC"})


def refusal_test(mutate):
    def run(self):
        p = plan()
        mutate(p)
        raw = json.dumps(p).encode()
        with self.assertRaises(src.Refused):
            auth.validate(
                raw,
                src.sha(raw),
                ROOT,
                REG["units"][1]["previous"],
                REG["units"][1]["next"],
                "unit_execute",
                "SYNTHETIC-EXECUTE",
            )

    return run


for name, mutate in {
    "wrong_host": lambda p: p["target"].update(host="remote"),
    "wrong_port": lambda p: p["target"].update(port=56041),
    "wrong_database": lambda p: p["target"].update(database="uuid_w17_e_integrity"),
    "wrong_user": lambda p: p["target"].update(user="uuid_w1_d_bootstrap"),
    "wrong_cluster": lambda p: p["identity"].update(system_identifier=auth.D_CLUSTER),
    "bool_oid": lambda p: p["identity"].update(database_oid=True),
    "loopback_internal_ip": lambda p: p["identity"].update(server_ip="127.0.0.1"),
    "expired": lambda p: p.update(expires_at="2000-01-01T00:00:00+00:00"),
    "naive_expiry": lambda p: p.update(expires_at="2099-01-01T00:00:00"),
    "wrong_source": lambda p: p["source_sha256"].update({"alembic/env.py": "0" * 64}),
    "missing_action": lambda p: p.update(approvals={}),
    "reused_action": lambda p: p["approvals"].update(unit_readback="SYNTHETIC-EXECUTE"),
    "old_d_approval": lambda p: p["approvals"].update(unit_execute="W16I-085-EXECUTE-20261017"),
    "unreviewed_security": lambda p: p["reviews"].update(security=False),
    "numeric_review": lambda p: p["reviews"].update(security=1),
    "wrong_daemon": lambda p: p["resources"].update(daemon_id="remote"),
    "wrong_socket": lambda p: p["resources"].update(socket="tcp://remote"),
    "wrong_credential": lambda p: p["credential_metadata"].update(
        path="/Users/ferozebasha/.sbom-uuid-w17-e/postgres-password"
    ),
    "credential_mode": lambda p: p["credential_metadata"].update(mode=0o644),
    "unknown_bypass": lambda p: p.update(force=True),
    "wrong_budget": lambda p: p["budgets"].update(catalog_queries=999999),
    "service": lambda p: p["connection"].update(service=""),
    "integrity_approval": lambda p: p["integrity_approvals"].update(integrity_execute="NO"),
    "skip_revision": lambda p: p["unit"].update(next=REG["units"][2]["next"]),
}.items():
    setattr(ApprovalTests, "test_refuse_" + name, refusal_test(mutate))


class LifecycleTests(unittest.TestCase):
    def test_missing_references_cannot_be_selfapproved_by_hash(self):
        p = plan(2)
        unit = REG["units"][2]
        raw = observations(p, unit)
        raw["references"] = {k: [] for k in raw["references"]}
        p["reference_sha256"] = src.digest(raw["references"])
        with self.assertRaises(src.Refused):
            obs.verify_database(ROOT, REG, p, unit, raw, readonly=True)

    def test_post_reference_seed_mismatch_stops_before_marker(self):
        p, pp, b, s = self.setup_run()
        original = b.observe.side_effect

        def changed(*args, **kwargs):
            raw = original(*args, **kwargs)
            if kwargs["after"]:
                raw["references"]["mappings"] = []
            return raw

        b.observe.side_effect = changed
        result = co.simulate_write(pp.authority, b, run_unit=MagicMock())
        self.assertEqual(result["outcome"], "ROLLED_BACK_UNVERIFIED", result)
        s.marker.assert_not_called()
        s.commit.assert_not_called()

    def test_actual080_body_bound_to_mock_operations_only(self):
        p, pp, b, s = self.setup_run(33)
        s.connection.driver_connection.autocommit = False
        s.in_transaction.return_value = True
        s.get_execution_options.return_value = {}
        s.dialect.name = "postgresql"
        result = co.simulate_write(pp.authority, b)
        self.assertEqual(result["outcome"], "COMMITTED_UNVERIFIED", result)
        operations = b.operations.return_value
        self.assertEqual(operations.add_column.call_count, 1)
        self.assertEqual(operations.add_column.call_args.args[0], "tenants")
        self.assertTrue(any("CREATE TRIGGER" in str(call.args[0]) for call in operations.execute.call_args_list))
        self.assertEqual(b.connect.call_count, 1)

    def test_readonly_validation_cannot_run_install(self):
        p = plan()
        pp = PrivatePlan(p, "unit_validate")
        self.addCleanup(pp.close)
        b, s = backend(p, pp.authority.unit)
        result = co.simulate_validate(pp.authority, b)
        self.assertEqual(result["outcome"], "MOCK_VALIDATED", result)
        self.assertEqual(b.connect.call_count, 1)
        s.commit.assert_not_called()
        s.execute.assert_not_called()
        s.marker.assert_not_called()
        self.assertEqual(s.begin.call_args.args[0], "BEGIN READ ONLY")
        self.assertTrue(result["closed"] and result["rollback"])
        with self.assertRaises(src.Refused):
            co.simulate_write(pp.authority, b)

    def test_wrong_historical_creation_schema_refused(self):
        p, pp, b, s = self.setup_run()
        s.dialect.default_schema_name = "pg_catalog"
        runner = MagicMock()
        result = co.simulate_write(pp.authority, b, run_unit=runner)
        self.assertEqual(result["outcome"], "ROLLED_BACK_UNVERIFIED", result)
        runner.assert_not_called()
        s.marker.assert_not_called()
        s.commit.assert_not_called()

    def test_privilege_error_stops_and_closes(self):
        p, pp, b, s = self.setup_run()

        class PrivilegeError(Exception):
            sqlstate = "42501"

        b.observe.side_effect = PrivilegeError("SYNTHETIC SECRET SHOULD NOT BE FORMATTED")
        result = co.simulate_write(pp.authority, b)
        self.assertEqual(result["outcome"], "ROLLED_BACK_UNVERIFIED", result)
        self.assertEqual(result["failure"]["sqlstate"], "42501")
        self.assertTrue(result["closed"])
        s.commit.assert_not_called()
        s.marker.assert_not_called()

    def test_failed_rollback_remains_unknown(self):
        p, pp, b, s = self.setup_run()
        s.rollback.side_effect = [None, OSError("SYNTHETIC rollback lost")]
        result = co.simulate_write(
            pp.authority, b, run_unit=MagicMock(side_effect=RuntimeError("SYNTHETIC unit failed"))
        )
        self.assertEqual(result["outcome"], "UNKNOWN_ROLLBACK_STOP_MANUAL_RECONCILIATION", result)
        self.assertTrue(result["closed"])
        s.commit.assert_not_called()
        self.assertEqual(b.connect.call_count, 1)

    def test_readback_catalog_mismatch_never_accepted(self):
        p, pp, b, s = self.setup_run()
        written = co.simulate_write(pp.authority, b, run_unit=MagicMock())
        read = PrivatePlan(p, "unit_readback")
        self.addCleanup(read.close)
        other, t = backend(p, read.authority.unit)
        original = other.observe.side_effect

        def changed(*args, **kwargs):
            raw = original(*args, **kwargs)
            raw["catalog"]["roles"] = [{"unexpected": True}]
            return raw

        other.observe.side_effect = changed
        result = co.simulate_readback(read.authority, other, written)
        self.assertEqual(result["outcome"], "READBACK_FAILED_STOP")
        self.assertTrue(result["closed"])
        t.commit.assert_not_called()

    def setup_run(self, index=1):
        p = plan(index)
        pp = PrivatePlan(p)
        self.addCleanup(pp.close)
        b, s = backend(p, pp.authority.unit)
        return p, pp, b, s

    def test_one_write_transaction_marker_commit_close(self):
        p, pp, b, s = self.setup_run()
        runner = MagicMock()
        result = co.simulate_write(pp.authority, b, run_unit=runner)
        self.assertEqual(result["outcome"], "COMMITTED_UNVERIFIED", result)
        self.assertTrue(result["commit_acknowledged"] and result["closed"])
        self.assertEqual(b.connect.call_count, 1)
        self.assertEqual(s.commit.call_count, 1)
        self.assertEqual(s.begin.call_args_list[0].args[0], "BEGIN READ ONLY")
        self.assertEqual(s.begin.call_args_list[1].args[0], "BEGIN READ WRITE")
        self.assertEqual(s.rollback.call_count, 1)
        self.assertEqual(result["counts"]["transaction_controls"], 4)
        self.assertEqual(
            s.marker.call_args.args[1],
            {"previous": pp.authority.unit["previous"], "revision": pp.authority.unit["next"]},
        )
        self.assertEqual(runner.call_count, 1)

    def test_frozen558_before_marker_and_one_commit(self):
        p, pp, b, s = self.setup_run(0)
        result = co.simulate_write(pp.authority, b)
        self.assertEqual(result["outcome"], "COMMITTED_UNVERIFIED", result)
        self.assertEqual(result["counts"]["migration_statements"], 558)
        self.assertEqual(result["counts"]["marker_statements"], 2)
        self.assertEqual(len(s.execute.call_args_list), 560)  # 558 + marker table + restore inspection search_path
        self.assertEqual(s.execute.call_args_list[-2].args[0], co.VERSION_CREATE)
        self.assertEqual(s.marker.call_args.args[0], co.VERSION_INSERT)

    def test_finalization_receipt_matches_unchanged_source_parser(self):
        p, pp, b, s = self.setup_run(39)
        receipts = []

        def run(binding, operations, context, meter):
            receipts.append(binding.namespace["_approval"](context))

        result = co.simulate_write(pp.authority, b, run_unit=MagicMock(side_effect=run))
        self.assertEqual(result["outcome"], "COMMITTED_UNVERIFIED", result)
        self.assertEqual(receipts[0]["catalog_sha256"], p["finalization_catalog_sha256"])
        self.assertEqual(receipts[0]["source_sha256"], REG["units"][39]["source_sha256"])

    def test_independent_readback_separate_approval_and_connection(self):
        p, pp, b, s = self.setup_run()
        result = co.simulate_write(pp.authority, b, run_unit=MagicMock())
        read = PrivatePlan(p, "unit_readback")
        self.addCleanup(read.close)
        other, t = backend(p, read.authority.unit)
        acceptance = co.simulate_readback(read.authority, other, result)
        self.assertEqual(acceptance["outcome"], "MOCK_ACCEPTED", acceptance)
        self.assertEqual(other.connect.call_count, 1)
        self.assertIsNot(t, s)
        t.commit.assert_not_called()
        with self.assertRaises(src.Refused):
            co.simulate_readback(pp.authority, other, result)

    def test_failed_schema_rollback_close_no_marker_or_retry(self):
        p, pp, b, s = self.setup_run()
        result = co.simulate_write(pp.authority, b, run_unit=MagicMock(side_effect=RuntimeError("synthetic")))
        self.assertEqual(result["outcome"], "ROLLED_BACK_UNVERIFIED", result)
        s.commit.assert_not_called()
        s.marker.assert_not_called()
        self.assertTrue(result["closed"])
        self.assertEqual(b.connect.call_count, 1)
        self.assertEqual(s.rollback.call_count, 2)

    def test_unknown_commit_never_rollback_or_retry(self):
        p, pp, b, s = self.setup_run()
        s.commit.side_effect = OSError("synthetic lost acknowledgement")
        result = co.simulate_write(pp.authority, b, run_unit=MagicMock())
        self.assertEqual(result["outcome"], "UNKNOWN_COMMIT_STOP_MANUAL_RECONCILIATION", result)
        self.assertEqual(s.rollback.call_count, 1)
        self.assertEqual(s.commit.call_count, 1)
        self.assertTrue(result["closed"])
        read = PrivatePlan(p, "unit_readback")
        self.addCleanup(read.close)
        with self.assertRaises(src.Refused):
            co.simulate_readback(read.authority, b, result)

    def test_connection_failure_no_query_no_second_attempt(self):
        p, pp, b, s = self.setup_run()
        b.connect.side_effect = OSError("password=SYNTHETIC-DO-NOT-LOG")
        result = co.simulate_write(pp.authority, b)
        self.assertEqual(result["outcome"], "BLOCKED")
        self.assertEqual(b.connect.call_count, 1)
        s.query.assert_not_called()
        self.assertNotIn("SYNTHETIC-DO-NOT-LOG", str(result))

    def test_query_failure_or_marker_mismatch_rolls_back(self):
        for reason in ("query", "marker"):
            p, pp, b, s = self.setup_run()
            if reason == "query":
                s.query.side_effect = RuntimeError("SYNTHETIC")
            else:
                s.marker.return_value = {"rowcount": 2, "rows": []}
            result = co.simulate_write(pp.authority, b, run_unit=MagicMock())
            self.assertEqual(result["outcome"], "ROLLED_BACK_UNVERIFIED", result)
            s.commit.assert_not_called()
            self.assertTrue(result["closed"])

    def test_changed_resource_or_role_between_preflight_and_ddl(self):
        for kind in ("resource", "role", "catalog", "writer", "business", "missing_business"):
            p, pp, b, s = self.setup_run()
            base = b.observe.side_effect
            if kind == "resource":
                bad = resources(p)
                bad["networks"][0]["name"] = "sbom_default"
                b.resources.side_effect = [resources(p), bad]
            else:

                def observe(session, meter, unit, readonly, after, kind=kind, base=base):
                    raw = base(session, meter, unit, readonly=readonly, after=after)
                    if not readonly:
                        if kind == "role":
                            raw["catalog"]["roles"] = [{"changed": True}]
                        if kind == "catalog":
                            raw["catalog"]["columns"] = [{"changed": True}]
                        if kind == "writer":
                            raw["clients"] = [{"pid": 1}]
                        if kind == "business":
                            raw["business"][0]["has_rows"] = True
                        if kind == "missing_business":
                            raw["business"] = []
                    return raw

                b.observe.side_effect = observe
            runner = MagicMock()
            result = co.simulate_write(pp.authority, b, run_unit=runner)
            self.assertEqual(result["outcome"], "ROLLED_BACK_UNVERIFIED", result)
            runner.assert_not_called()
            s.commit.assert_not_called()

    def test_manifest_changed_immediately_pre_auth(self):
        p, pp, b, s = self.setup_run()

        def changes():
            pp.path.write_bytes(pp.raw + b"\n")
            return resources(p)

        b.resources.side_effect = changes
        result = co.simulate_write(pp.authority, b)
        self.assertEqual(result["outcome"], "BLOCKED")
        b.connect.assert_not_called()

    def test_source_changed_at_preddl_review_no_execution(self):
        p, pp, b, s = self.setup_run()
        original = pp.authority.recheck
        calls = []

        def recheck():
            calls.append(1)
            if len(calls) == 4:
                raise src.Refused("SYNTHETIC source changed")
            return original()

        runner = MagicMock()
        with patch.object(pp.authority, "recheck", side_effect=recheck):
            result = co.simulate_write(pp.authority, b, run_unit=runner)
        runner.assert_not_called()
        s.commit.assert_not_called()
        self.assertEqual(result["outcome"], "ROLLED_BACK_UNVERIFIED")

    def test_failed_close_is_not_acceptance(self):
        p, pp, b, s = self.setup_run()
        s.close.side_effect = RuntimeError("SYNTHETIC close failure")
        result = co.simulate_write(pp.authority, b, run_unit=MagicMock())
        self.assertEqual(result["outcome"], "COMMITTED_CLOSE_UNVERIFIED")
        self.assertFalse(result["closed"])

    def test_nonmock_backend_or_runner_refused(self):
        p, pp, b, s = self.setup_run()
        with self.assertRaises(src.Refused):
            co.simulate_write(pp.authority, object())
        result = co.simulate_write(pp.authority, b, run_unit=lambda *a: None)
        self.assertEqual(result["outcome"], "ROLLED_BACK_UNVERIFIED")

    def test_safe_error_sqlstate_and_no_raw_args(self):
        class Error(Exception):
            sqlstate = "23514"

        e = co.safe_error(Error("postgresql://user:SYNTHETIC@remote"))
        self.assertEqual(e["sqlstate"], "23514")
        self.assertNotIn("SYNTHETIC", str(e))


class BudgetTests(unittest.TestCase):
    def test_distinct_ddl_and_catalog_budgets(self):
        meter = co.Meter(REG["units"][0]["budgets"])
        meter.charge("migration_statements", 558)
        self.assertEqual(meter.counts["catalog_queries"], 0)
        with self.assertRaises(src.Refused):
            meter.charge("migration_statements")

    def test_query_control_attempt_budgets(self):
        for key in ("catalog_queries", "transaction_controls", "attempts", "marker_statements", "session_statements"):
            m = co.Meter(REG["units"][0]["budgets"])
            m.charge(key, m.limits[key])
            with self.assertRaises(src.Refused):
                m.charge(key)

    def test_cooperative_deadline(self):
        clock = MagicMock(return_value=0)
        m = co.Meter(REG["units"][0]["budgets"], clock=clock)
        clock.return_value = 121
        with self.assertRaises(src.Refused):
            m.charge("catalog_queries")

    def test_driver_event_counts_executemany(self):
        m = co.Meter(REG["units"][1]["budgets"], sql_parser=src.reference_api(ROOT, REG)["pg_lex"].statements)
        m.before_cursor_execute(None, None, "SELECT 1", [{}, {}], SimpleNamespace(execution_options={}), True)
        self.assertEqual(m.counts["migration_statements"], 2)
        self.assertEqual(m.counts["catalog_queries"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
