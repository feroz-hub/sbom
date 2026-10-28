"""W2.2 inert source/catalog/transaction mocks; never accesses PG or Docker."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import unittest
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from sqlalchemy import Column, Integer, MetaData, Table, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import UUID, dialect
from sqlalchemy.schema import AddConstraint

ROOT = Path(__file__).resolve().parents[3]
FOLDER = ROOT / "infra/uuid-migration/staged-finalization"
EXPAND = ROOT / "infra/uuid-migration/staged-alembic"
TABLES = ("tenants", "projects", "products", "logical_sbom", "sbom_source", "sbom_component")
FILES = sorted(FOLDER.glob("*.py"))


def load(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MODULES = [load(p) for p in FILES]
M = MODULES[0]


def plan(module=M):
    return {
        "target": "F",
        "host": "127.0.0.1",
        "port": 56043,
        "database": "uuid_w2_f_fresh",
        "user": "uuid_w2_f_bootstrap",
        "system_identifier": "1234567890123456789",
        "database_oid": 17001,
        "server_ip": "172.30.0.2",
        "current_revision": module.down_revision,
        "next_revision": module.revision,
        "manifest_sha256": "a" * 64,
        "source_sha256": hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest(),
        "catalog_sha256": "b" * 64,
        "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        "approval_reference": "SYNTHETIC-ACTION",
        "resource_review_reference": "SYNTHETIC-RESOURCE",
        "credential_review_reference": "SYNTHETIC-PROVENANCE",
        "security_review_reference": "SYNTHETIC-SECURITY",
        "writers_stopped": True,
        "fresh_install_accepted": True,
        "coordinator_reviewed": True,
    }


def guard(module=M):
    tree = ast.parse((EXPAND / "080_uuid_public_id_expand.py").read_bytes())
    sql = next(
        ast.literal_eval(n.value)
        for n in tree.body
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "_GUARD_FUNCTION_SQL" for t in n.targets)
    )
    body = sql.split("$uuid_public_identity_guard$")[1]
    assert hashlib.sha256(body.encode()).hexdigest() == module._GUARD_SHA
    return {
        "prosrc": body,
        "lanname": "plpgsql",
        "pronargs": 0,
        "prokind": "f",
        "trigger": True,
        "provolatile": "v",
        "prosecdef": False,
        "proisstrict": False,
        "proretset": False,
        "proleakproof": False,
        "proparallel": "u",
        "proconfig": ["search_path=pg_catalog"],
        "executable": True,
    }


def prefix_rows(module, completed):
    def rows(bind, sql, values=None):
        values = values or {}
        if sql == module._GUARD:
            return [guard(module)]
        table = values.get("table") or TABLES[values.get("oid", 100) - 100]
        i = TABLES.index(table)
        done = i < completed
        if sql == module._COLUMN:
            return [
                {
                    "oid": 100 + i,
                    "relkind": "r",
                    "relpersistence": "p",
                    "relrowsecurity": False,
                    "relforcerowsecurity": False,
                    "relispartition": False,
                    "attnum": 20,
                    "uuid": True,
                    "attnotnull": done,
                    "attgenerated": "",
                    "attidentity": "",
                    "default": "gen_random_uuid()",
                    "plain": True,
                    "owner": "uuid_w2_f_bootstrap",
                    "owns": True,
                    "can_select": True,
                    "integer_pk": True,
                }
            ]
        if sql == module._CHECK:
            return [
                {
                    "contype": "c",
                    "convalidated": done,
                    "connoinherit": False,
                    "expression": f"public_id IS NULL OR public_id::text ~ '{module._PATTERN}'::text",
                }
            ]
        if sql == module._TRIGGERS:
            return [
                {
                    "tgname": f"trg_{table}_public_id_immutable",
                    "tgtype": 17,
                    "tgenabled": "O",
                    "tgnargs": 0,
                    "definition": f"CREATE TRIGGER trg_{table}_public_id_immutable AFTER UPDATE ON public.{table} FOR EACH ROW WHEN ((old.public_id IS DISTINCT FROM new.public_id)) EXECUTE FUNCTION public.uuid_public_identity_guard_v1()",
                },
                {
                    "tgname": f"trg_{table}_public_id_insert",
                    "tgtype": 7,
                    "tgenabled": "O",
                    "tgnargs": 0,
                    "definition": f"CREATE TRIGGER trg_{table}_public_id_insert BEFORE INSERT ON public.{table} FOR EACH ROW EXECUTE FUNCTION public.uuid_public_identity_guard_v1()",
                },
            ]
        if sql == module._INDEXES and done:
            return [
                {
                    "indexrelid": 900 + i,
                    **dict.fromkeys(
                        [
                            "indisunique",
                            "indisvalid",
                            "indisready",
                            "indislive",
                            "full",
                            "simple",
                            "convalidated",
                            "correct_key",
                        ],
                        True,
                    ),
                    **dict.fromkeys(["indisprimary", "indnullsnotdistinct", "condeferrable", "condeferred"], False),
                    "indnkeyatts": 1,
                    "indnatts": 1,
                    "amname": "btree",
                    "relname": f"uq_{table}_public_id",
                    "conname": f"uq_{table}_public_id",
                    "contype": "u",
                    "key_definition": "public_id",
                }
            ]
        return []

    return rows


class SourceTests(unittest.TestCase):
    def test_six_files_and_linear_graph(self):
        self.assertEqual(len(FILES), 6)
        graph = {}
        for folder in [ROOT / "alembic/versions", EXPAND, FOLDER]:
            for p in folder.glob("*.py"):
                tree = ast.parse(p.read_bytes())
                v = {}
                for n in tree.body:
                    if isinstance(n, ast.Assign):
                        for t in n.targets:
                            if isinstance(t, ast.Name) and t.id in ["revision", "down_revision"]:
                                v[t.id] = ast.literal_eval(n.value)
                self.assertNotIn(v["revision"], graph)
                graph[v["revision"]] = v["down_revision"]
        self.assertEqual(len(graph), 91)
        current = MODULES[-1].revision
        seen = []
        while current:
            self.assertNotIn(current, seen)
            seen.append(current)
            current = graph[current]
        self.assertEqual(len(seen), 91)
        for i, module in enumerate(MODULES):
            self.assertEqual(module._TABLE, TABLES[i])
            self.assertEqual(module._POSITION, i)

    def test_historical_hashes_and_w21_lock(self):
        lock = ROOT / "infra/uuid-migration/fresh-bootstrap/source-lock.json"
        self.assertEqual(
            hashlib.sha256(lock.read_bytes()).hexdigest(),
            "ea4307ed66a08da663b3826f9bdf34e3cc72849e610a5f8f70e105731ff1f632",
        )
        pins = json.loads(lock.read_text())
        for name, h in pins.items():
            self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), h, name)
        self.assertEqual(len(list(EXPAND.glob("*.py"))), 6)
        self.assertEqual(len(list((ROOT / "alembic/versions").glob("*.py"))), 79)

    def test_exactly_three_target_ddl_statements_no_business_writes(self):
        for module in MODULES:
            source = Path(module.__file__).read_text()
            tree = ast.parse(source)
            upgrade = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "upgrade")
            ddl = [n for n in ast.walk(upgrade) if isinstance(n, ast.Call) and ast.unparse(n.func) == "op.execute"]
            self.assertEqual(len(ddl), 3)
            self.assertIn('ADD CONSTRAINT "uq_{_TABLE}_public_id" UNIQUE (public_id)', source)
            self.assertIn('VALIDATE CONSTRAINT "ck_{_TABLE}_public_id_v4"', source)
            self.assertIn("ALTER COLUMN public_id SET NOT NULL", source)
            for n in ast.walk(tree):
                if isinstance(n, ast.Call):
                    self.assertNotIn(
                        ast.unparse(n.func),
                        [
                            "create_engine",
                            "psycopg.connect",
                            "op.create_index",
                            "op.drop_column",
                            "op.drop_constraint",
                            "op.alter_column",
                            "op.bulk_insert",
                            "op.execute_stamp",
                            "bind.commit",
                            "bind.rollback",
                        ],
                    )
            self.assertNotIn("CONCURRENTLY", source)
            self.assertNotIn("CREATE OR REPLACE", source)
            self.assertNotIn("UPDATE public.", source)
            self.assertNotIn("INSERT INTO public.", source)

    def test_six_self_contained_bodies_match(self):
        reference = None
        for module in MODULES:
            tree = ast.parse(Path(module.__file__).read_bytes())
            tree.body = [
                n
                for n in tree.body
                if not (
                    isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)
                )
                and not (
                    isinstance(n, ast.Assign)
                    and any(
                        isinstance(t, ast.Name) and t.id in {"revision", "down_revision", "_TABLE", "_POSITION"}
                        for t in n.targets
                    )
                )
            ]
            normalized = ast.dump(tree)
            if reference is None:
                reference = normalized
            self.assertEqual(reference, normalized)

    def test_import_does_not_touch_real_files_or_runtime(self):
        for path in FILES:
            with (
                patch("builtins.open", side_effect=AssertionError("unexpected file read")),
                patch.object(Path, "read_bytes", side_effect=AssertionError("unexpected source read")),
            ):
                module = load(path)
            self.assertEqual(module._TABLE, TABLES[module._POSITION])

    def test_catalog_and_ddl_compile_no_engine(self):
        for module in MODULES:
            queries = [
                module._IDENTITY,
                module._COLUMN,
                module._CHECK,
                module._TRIGGERS,
                module._GUARD,
                module._INDEXES,
                module._RELATIONS,
                *module._SNAPSHOT.values(),
            ]
            for query in queries:
                self.assertTrue(str(text(query).compile(dialect=dialect())))
            table = Table(module._TABLE, MetaData(), Column("id", Integer, primary_key=True), Column("public_id", UUID))
            constraint = UniqueConstraint(table.c.public_id, name=f"uq_{module._TABLE}_public_id")
            table.append_constraint(constraint)
            ddl = str(AddConstraint(constraint).compile(dialect=dialect()))
            self.assertIn("UNIQUE (public_id)", ddl)
            self.assertEqual(len(table.indexes), 0)  # no second explicit index

    def test_no_external_helpers_or_application_imports(self):
        for module in MODULES:
            tree = ast.parse(Path(module.__file__).read_bytes())
            allowed = {"hashlib", "json", "re", "datetime", "pathlib", "sqlalchemy", "alembic"}
            for n in ast.walk(tree):
                if isinstance(n, ast.ImportFrom):
                    self.assertIn(n.module, allowed)
                if isinstance(n, ast.Import):
                    for alias in n.names:
                        self.assertIn(alias.name, allowed)

    def test_downgrade_fail_closed(self):
        for module in MODULES:
            with self.subTest(table=module._TABLE), self.assertRaises(RuntimeError):
                module.downgrade()

    def test_every_expanded_and_final_prefix(self):
        for module in MODULES:
            for count in [module._POSITION, module._POSITION + 1]:
                with patch.object(module, "_rows", side_effect=prefix_rows(module, count)):
                    module._prefix(MagicMock(), count)


class ApprovalTests(unittest.TestCase):
    def test_approved_synthetic_contract(self):
        for module in MODULES:
            self.assertEqual(
                module._approval(SimpleNamespace(opts={"w22_f_finalization": plan(module)}))["next_revision"],
                module.revision,
            )

    def test_no_context_no_sql(self):
        with self.assertRaises(RuntimeError):
            M._approval(SimpleNamespace(opts={}))

    def test_wrong_actual_pg_identity(self):
        p = plan()
        identity = {
            "database": p["database"],
            "user": p["user"],
            "session_user": p["user"],
            "database_oid": p["database_oid"],
            "system_identifier": p["system_identifier"],
            "version": 160015,
            "recovery": False,
            "replication": "origin",
            "row_security": "on",
            "readonly": "off",
            "search_path": "pg_catalog",
            "port": 5432,
            "ip": p["server_ip"],
            "data_directory": "/var/lib/postgresql/data",
        }
        with patch.object(M, "_rows", return_value=[identity]):
            M._identity(None, p)
        for k, value in [
            ("database", "D"),
            ("system_identifier", "7697252084555804711"),
            ("user", "wrong"),
            ("version", 160014),
            ("replication", "replica"),
            ("row_security", "off"),
            ("search_path", "public"),
        ]:
            row = {**identity, k: value}
            with self.subTest(key=k), patch.object(M, "_rows", return_value=[row]), self.assertRaises(RuntimeError):
                M._identity(None, p)


def refusal(name, mutate):
    def test(self):
        p = plan()
        mutate(p)
        with self.assertRaises((RuntimeError, ValueError, TypeError)):
            M._approval(SimpleNamespace(opts={"w22_f_finalization": p}))

    setattr(ApprovalTests, "test_refuses_" + name, test)


for name, mutate in {
    "D": lambda p: p.update(database="uuid_w1_d_rehearsal", port=56041),
    "E": lambda p: p.update(port=56042),
    "B": lambda p: p.update(port=55439),
    "remote": lambda p: p.update(host="remote"),
    "wrong_user": lambda p: p.update(user="other"),
    "D_cluster": lambda p: p.update(system_identifier="7697252084555804711"),
    "missing_oid": lambda p: p.update(database_oid=None),
    "bool_oid": lambda p: p.update(database_oid=True),
    "missing_approval": lambda p: p.update(approval_reference=""),
    "expired": lambda p: p.update(expires_at="2026-01-01T00:00:00+00:00"),
    "naive_expiry": lambda p: p.update(expires_at="2099-01-01T00:00:00"),
    "source_changed": lambda p: p.update(source_sha256="0" * 64),
    "schema_unknown": lambda p: p.update(catalog_sha256=None),
    "wrong_revision": lambda p: p.update(current_revision="079_lifecycle_provider_verification"),
    "skipped_revision": lambda p: p.update(next_revision="091_uuid_sbom_component_finalize"),
    "writer_window": lambda p: p.update(writers_stopped=False),
    "freshness_unknown": lambda p: p.update(fresh_install_accepted=False),
    "unreviewed_coordinator": lambda p: p.update(coordinator_reviewed=False),
    "security": lambda p: p.update(security_review_reference=None),
    "hidden_backfill": lambda p: p.update(backfill=True),
}.items():
    refusal(name, mutate)


class CatalogTests(unittest.TestCase):
    def test_guard_modified_body_and_security(self):
        for k, value in [("prosrc", "changed"), ("prosecdef", True), ("proconfig", []), ("executable", False)]:
            row = guard()
            row[k] = value
            with self.subTest(key=k), patch.object(M, "_rows", return_value=[row]), self.assertRaises(RuntimeError):
                M._check_guard(None)

    def test_missing_extra_guard(self):
        for rows in [[], [guard(), guard()]]:
            with patch.object(M, "_rows", return_value=rows), self.assertRaises(RuntimeError):
                M._check_guard(None)

    def test_null_duplicate_invalid_uuid_refused(self):
        for problem in ["nulls", "duplicates", "invalid"]:
            row = dict.fromkeys(["nulls", "duplicates", "invalid"], False)
            row[problem] = True
            with (
                self.subTest(problem=problem),
                patch.object(M, "_rows", return_value=[row]),
                self.assertRaises(RuntimeError),
            ):
                M._data_preconditions(None)

    def test_empty_data_passes_all_six(self):
        with patch.object(M, "_rows", return_value=[dict.fromkeys(["nulls", "duplicates", "invalid"], False)]) as rows:
            M._data_preconditions(None)
            self.assertEqual(rows.call_count, 6)

    def test_prefix_collisions_and_properties(self):
        for category, key, value in [
            ("_COLUMN", "uuid", False),
            ("_COLUMN", "integer_pk", False),
            ("_COLUMN", "owns", False),
            ("_COLUMN", "relrowsecurity", True),
            ("_COLUMN", "plain", False),
            ("_COLUMN", "default", "other()"),
            ("_CHECK", "convalidated", True),
            ("_CHECK", "expression", "public_id IS NULL"),
            ("_TRIGGERS", "tgenabled", "D"),
        ]:
            base = prefix_rows(M, 0)

            def rows(bind, sql, values=None, category=category, key=key, value=value, base=base):
                result = base(bind, sql, values)
                if sql == getattr(M, category) and result:
                    result[0][key] = value
                return result

            with (
                self.subTest(category=category, key=key),
                patch.object(M, "_rows", side_effect=rows),
                self.assertRaises(RuntimeError),
            ):
                M._prefix(None, 0)

    def test_existing_uuid_index_refused(self):
        base = prefix_rows(M, 0)

        def rows(bind, sql, values=None):
            return [{"unexpected": True}] if sql == M._INDEXES else base(bind, sql, values)

        with patch.object(M, "_rows", side_effect=rows), self.assertRaises(RuntimeError):
            M._prefix(None, 0)

    def test_additional_uuid_check_refused(self):
        base = prefix_rows(M, 0)

        def rows(bind, sql, values=None):
            result = base(bind, sql, values)
            if sql == M._CHECK:
                result.append(dict(result[0]))
            return result

        with patch.object(M, "_rows", side_effect=rows), self.assertRaises(RuntimeError):
            M._prefix(None, 0)

    def test_additional_trigger_and_rule_refused(self):
        for kind in ["trigger", "rule"]:
            base = prefix_rows(M, 0)

            def rows(bind, sql, values=None, kind=kind, base=base):
                result = base(bind, sql, values)
                if kind == "trigger" and sql == M._TRIGGERS:
                    result.append({"tgname": "unknown"})
                if kind == "rule" and "pg_rewrite" in sql:
                    return [{"exists": True}]
                return result

            with self.subTest(kind=kind), patch.object(M, "_rows", side_effect=rows), self.assertRaises(RuntimeError):
                M._prefix(None, 0)

    def test_rls_cannot_hide_population(self):
        bind = MagicMock()
        bind.dialect = dialect()
        with (
            patch.object(
                M,
                "_rows",
                return_value=[{"relname": n, "relrowsecurity": True, "relforcerowsecurity": False} for n in TABLES],
            ),
            self.assertRaises(RuntimeError),
        ):
            M._empty_business(bind)

    def test_unique_index_exact_postcondition(self):
        for key, value in [
            ("indisunique", False),
            ("indisvalid", False),
            ("amname", "hash"),
            ("indnatts", 2),
            ("condeferrable", True),
            ("full", False),
            ("conname", "wrong"),
            ("key_definition", "public_id DESC"),
        ]:
            base = prefix_rows(M, 1)

            def rows(bind, sql, values=None, key=key, value=value, base=base):
                result = base(bind, sql, values)
                if sql == M._INDEXES and result:
                    result[0][key] = value
                return result

            with self.subTest(key=key), patch.object(M, "_rows", side_effect=rows), self.assertRaises(RuntimeError):
                M._prefix(None, 1)

    def test_populated_database_refused_not_just_target(self):
        bind = MagicMock()
        bind.dialect = dialect()

        def rows(bind, sql, values=None):
            if sql == M._RELATIONS:
                return [
                    {"relname": n, "relrowsecurity": False, "relforcerowsecurity": False}
                    for n in [*TABLES, "alembic_version", "authorization_audit_log", "iam_users"]
                ]
            return [{"occupied": True}] if '"iam_users" LIMIT 1' in sql else []

        with patch.object(M, "_rows", side_effect=rows), self.assertRaises(RuntimeError):
            M._empty_business(bind)

    def test_reference_rows_allowed_and_business_locks(self):
        bind = MagicMock()
        bind.dialect = dialect()
        names = [
            *TABLES,
            "alembic_version",
            "authorization_audit_log",
            "authorization_roles",
            "authorization_permissions",
            "authorization_role_permissions",
        ]

        def rows(bind, sql, values=None):
            return (
                [{"relname": n, "relrowsecurity": False, "relforcerowsecurity": False} for n in names]
                if sql == M._RELATIONS
                else []
            )

        with patch.object(M, "_rows", side_effect=rows):
            M._empty_business(bind)
        self.assertEqual(bind.execute.call_count, len(names))
        self.assertTrue(all("SHARE MODE NOWAIT" in str(call.args[0]) for call in bind.execute.call_args_list))


def snapshots(module=M):
    before = {key: [] for key in module._SNAPSHOT}
    before["columns"] = [
        {"attrelid": 100, "attnum": 1, "attname": "id", "attnotnull": True},
        {"attrelid": 100, "attnum": 2, "attname": "public_id", "attnotnull": False},
    ]
    before["constraints"] = [
        {
            "conrelid": 100,
            "conname": f"ck_{module._TABLE}_public_id_v4",
            "convalidated": False,
            "definition": "CHECK (reviewed_v4) NOT VALID",
        },
        {"conrelid": 100, "conname": "integer_fk", "convalidated": True},
    ]
    before["indexes"] = [{"indrelid": 100, "relname": "original_pk", "definition": "integer pk"}]
    before["relations"] = [{"nspname": "public", "relname": module._TABLE, "relacl": None}]
    after = deepcopy(before)
    after["columns"][1]["attnotnull"] = True
    after["constraints"][0]["convalidated"] = True
    after["constraints"][0]["definition"] = "CHECK (reviewed_v4)"
    after["constraints"].append({"conrelid": 100, "conname": f"uq_{module._TABLE}_public_id"})
    after["indexes"].append({"indrelid": 100, "relname": f"uq_{module._TABLE}_public_id"})
    after["relations"].append({"nspname": "public", "relname": f"uq_{module._TABLE}_public_id"})
    return before, after


class DeltaTests(unittest.TestCase):
    def test_all_six_narrow_deltas(self):
        for module in MODULES:
            before, after = snapshots(module)
            module._delta(before, after, 100)

    def test_integer_fk_index_guard_acl_security_unchanged(self):
        for key in ["functions", "roles", "extensions", "triggers", "sequences", "memberships", "reference_roles"]:
            before, after = snapshots()
            after[key] = [{"changed": True}]
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                M._delta(before, after, 100)
        before, after = snapshots()
        after["constraints"][1]["convalidated"] = False
        with self.assertRaises(RuntimeError):
            M._delta(before, after, 100)
        before, after = snapshots()
        after["indexes"][0]["definition"] = "different"
        with self.assertRaises(RuntimeError):
            M._delta(before, after, 100)

    def test_no_extra_columns_or_indexes(self):
        for key, row in [
            ("columns", {"attrelid": 100, "attnum": 3}),
            ("indexes", {"indrelid": 100, "relname": "extra_uuid"}),
        ]:
            before, after = snapshots()
            after[key].append(row)
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                M._delta(before, after, 100)

    def test_validate_check_deparser_delta_is_exact(self):
        before, after = snapshots()
        M._delta(before, after, 100)
        after["constraints"][0]["definition"] = "CHECK (different_expression)"
        with self.assertRaises(RuntimeError):
            M._delta(before, after, 100)


class UpgradeTests(unittest.TestCase):
    def test_one_table_upgrade_order_no_internal_commit(self):
        for module in MODULES:
            bind = MagicMock()
            bind.connection.driver_connection.autocommit = False
            bind.in_transaction.return_value = True
            bind.get_execution_options.return_value = {}
            context = SimpleNamespace(
                as_sql=False,
                dialect=dialect(),
                impl=SimpleNamespace(transactional_ddl=True),
                opts={"w22_f_finalization": plan(module)},
            )
            before, after = snapshots(module)
            p = plan(module)
            p["catalog_sha256"] = module._digest(before)
            context.opts = {"w22_f_finalization": p}

            def rows(bind, sql, values=None, module=module):
                if "pg_try_advisory" in sql:
                    return [{"acquired": True}]
                if "SELECT version_num" in sql:
                    return [{"version_num": module.down_revision}]
                if sql == module._COLUMN:
                    return [{"oid": 100}]
                return []

            with (
                patch.object(module.op, "get_context", return_value=context),
                patch.object(module.op, "get_bind", return_value=bind),
                patch.object(module, "_identity"),
                patch.object(module, "_prefix") as prefix,
                patch.object(module, "_data_preconditions"),
                patch.object(module, "_empty_business"),
                patch.object(module, "_snapshot", side_effect=[before, after]),
                patch.object(module, "_rows", side_effect=rows),
                patch.object(module.op, "execute") as ddl,
            ):
                module.upgrade()
                self.assertEqual(ddl.call_count, 3)
                self.assertIn("UNIQUE (public_id)", ddl.call_args_list[0].args[0])
                self.assertIn("VALIDATE CONSTRAINT", ddl.call_args_list[1].args[0])
                self.assertIn("SET NOT NULL", ddl.call_args_list[2].args[0])
                self.assertEqual(prefix.call_count, 2)
                timeout_sql = str(bind.execute.call_args_list[0].args[0])
                self.assertIn("pg_catalog.pg_settings", timeout_sql)
                self.assertIn("1000", timeout_sql)
                self.assertIn("10000", timeout_sql)
                self.assertNotIn("::interval", timeout_sql)
                bind.commit.assert_not_called()
                bind.rollback.assert_not_called()

    def test_pre_ddl_prefix_or_approval_change_refused(self):
        for kind in ("fingerprint", "changed_approval", "advisory", "writer"):
            bind = MagicMock()
            bind.connection.driver_connection.autocommit = False
            bind.in_transaction.return_value = True
            bind.get_execution_options.return_value = {}
            before, _ = snapshots()
            p = plan()
            p["catalog_sha256"] = M._digest(before) if kind != "fingerprint" else "0" * 64
            context = SimpleNamespace(
                as_sql=False,
                dialect=dialect(),
                impl=SimpleNamespace(transactional_ddl=True),
                opts={"w22_f_finalization": p},
            )

            def rows(bind, sql, values=None, kind=kind):
                if "pg_try_advisory" in sql:
                    return [{"acquired": kind != "advisory"}]
                if "SELECT version_num" in sql:
                    return [{"version_num": M.down_revision}]
                if "pg_stat_activity" in sql and kind == "writer":
                    return [{"exists": True}]
                return []

            def snapshot(bind, kind=kind, p=p, before=before):
                if kind == "changed_approval":
                    p["approval_reference"] = "CHANGED-SYNTHETIC-REFERENCE"
                return before

            with (
                self.subTest(kind=kind),
                patch.object(M.op, "get_context", return_value=context),
                patch.object(M.op, "get_bind", return_value=bind),
                patch.object(M, "_identity"),
                patch.object(M, "_prefix"),
                patch.object(M, "_data_preconditions"),
                patch.object(M, "_empty_business"),
                patch.object(M, "_snapshot", side_effect=snapshot),
                patch.object(M, "_rows", side_effect=rows),
                patch.object(M.op, "execute") as ddl,
                self.assertRaises(RuntimeError),
            ):
                M.upgrade()
            ddl.assert_not_called()
            bind.commit.assert_not_called()

    def test_sql_only_or_unapproved_refused_before_bind(self):
        for as_sql, opts in [(True, {}), (False, {})]:
            context = SimpleNamespace(
                as_sql=as_sql, dialect=dialect(), impl=SimpleNamespace(transactional_ddl=True), opts=opts
            )
            with (
                patch.object(M.op, "get_context", return_value=context),
                patch.object(M.op, "get_bind") as bind,
                self.assertRaises(RuntimeError),
            ):
                M.upgrade()
            bind.assert_not_called()

    def test_mid_ddl_failure_propagates_no_retry_or_cleanup(self):
        bind = MagicMock()
        bind.connection.driver_connection.autocommit = False
        bind.in_transaction.return_value = True
        bind.get_execution_options.return_value = {}
        before, _ = snapshots()
        p = plan()
        p["catalog_sha256"] = M._digest(before)
        context = SimpleNamespace(
            as_sql=False,
            dialect=dialect(),
            impl=SimpleNamespace(transactional_ddl=True),
            opts={"w22_f_finalization": p},
        )

        def rows(bind, sql, values=None):
            if "pg_try_advisory" in sql:
                return [{"acquired": True}]
            if "SELECT version_num" in sql:
                return [{"version_num": M.down_revision}]
            return []

        with (
            patch.object(M.op, "get_context", return_value=context),
            patch.object(M.op, "get_bind", return_value=bind),
            patch.object(M, "_identity"),
            patch.object(M, "_prefix"),
            patch.object(M, "_data_preconditions"),
            patch.object(M, "_empty_business"),
            patch.object(M, "_snapshot", return_value=before),
            patch.object(M, "_rows", side_effect=rows),
            patch.object(M.op, "execute", side_effect=[None, RuntimeError("SYNTHETIC SQL ERROR")]) as ddl,
            self.assertRaises(RuntimeError),
        ):
            M.upgrade()
        self.assertEqual(ddl.call_count, 2)
        bind.commit.assert_not_called()
        bind.rollback.assert_not_called()

    def test_unknown_commit_remains_coordinator_stop_contract(self):
        # Use unchanged W2.1 pure state machine; no runtime coordinator is run.
        path = ROOT / "infra/uuid-migration/fresh-bootstrap"
        import sys

        sys.path.insert(0, str(path))
        try:
            from fresh_bootstrap import UnitContract

            unit = UnitContract(("one",), "hash")
            unit.begin(freshness_verified=True, separately_authorized=True)
            unit.lock_ack(7160085085, freshness_rechecked=True)
            unit.schema_ack("one")
            unit.marker_instruction()
            from frozen_047 import BASELINE

            unit.marker_ack(1, [(BASELINE,)], schema_verified=True)
            unit.commit_requested()
            self.assertEqual(unit.failure(), "STOP_MANUAL_RECONCILIATION")
            with self.assertRaises(ValueError):
                unit.rollback_ack()
        finally:
            sys.path.remove(str(path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
