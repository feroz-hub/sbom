"""Offline source, plan, real collector/meter, synthetic lifecycle tests only."""

from __future__ import annotations

import ast
import copy
import importlib.util
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import ModuleType
from types import SimpleNamespace as NS
from unittest.mock import MagicMock, patch

import accounting as ac
import budget_policy as bp
from review_inputs import DIRECTORY, adapters, pinned, reviewed, sha, unique_json
from scoped_meter import create_meter

ROOT = Path(__file__).resolve().parents[3]
MODULES, REG, OLD = adapters(ROOT)
PLAN = ac.build(ROOT)
PARSER = MODULES["source_registry"].reference_api(ROOT, REG)["pg_lex"].statements


def selection(revision="080_uuid_public_id_expand", action="unit_execute"):
    return bp.select(PLAN, revision, action)


def make_meter(revision="080_uuid_public_id_expand", action="unit_execute", sqls=("SELECT 1",), base=None):
    allowed = {name: [sha(sql.encode()) for sql in sqls] for name in OLD["transport"].CATEGORIES}
    return create_meter(base or OLD["transport"].Meter, PLAN, revision, action, allowed, PARSER)


def query_templates():
    refs = MODULES["source_registry"].reference_api(ROOT, REG)
    values = list(MODULES["observations"].catalog_queries(ROOT, REG).values())
    values += list(refs["fresh_catalog"].QUERIES.values())
    values += list(MODULES["observations"].REFERENCE_SQL.values())
    a = NS(root=ROOT, registry=REG, modules=MODULES)
    values += list(OLD["catalog"].final_queries(a).values())
    values += [OLD["catalog"].IDENTITY, OLD["catalog"].MARKER, OLD["catalog"].ADVISORY, "SELECT 1"]
    for row in PLAN["rows"]:
        values += [
            "SELECT EXISTS (SELECT 1 FROM " + OLD["catalog"].relation(n) + " LIMIT 1) AS has_rows"
            for n in row["prefix_after"]
            if n not in ac.EXCLUDED
        ]
    return sorted(set(values))


class CatalogFixture:
    def __init__(self, row, phase, meter):
        self.names = row["prefix_before"] if phase in {"preflight", "locked_reinspection"} else row["prefix_after"]
        self.meter = meter
        self.raw = MagicMock()
        self.cursor = OLD["transport"].Cursor(self.raw, meter)
        self.templates = MODULES["observations"].catalog_queries(ROOT, REG)
        self.base = MODULES["source_registry"].reference_api(ROOT, REG)["fresh_catalog"].QUERIES

    def rows(self, sql):
        if sql == self.templates["relations"]:
            return [{"nspname": "public", "relname": n, "relkind": "r"} for n in self.names]
        if sql == self.templates["owners_acl"]:
            return [
                {"nspname": "public", "relname": n, "relrowsecurity": False, "relforcerowsecurity": False}
                for n in self.names
            ]
        if sql in {OLD["catalog"].IDENTITY, self.base["identity"]}:
            return [{}]
        if sql == self.base["alembic"]:
            return [{"relation": None}]
        if sql.startswith("SELECT EXISTS (SELECT 1 FROM public."):
            return [{"has_rows": False}]
        if sql == OLD["catalog"].MARKER:
            return [{"version_num": "SYNTHETIC"}]
        return []

    def query(self, connection, meter, text_factory, sql, params=None):
        # Same single charging boundary as W2.4A; no charge here.
        self.cursor.execute(sql, params)
        return self.rows(sql)


def test_unit(row):
    def test(self):
        ua = NS(unit=next(u for u in REG["units"] if u["next"] == row["unit"]))
        a = NS(unit_authority=ua, modules=MODULES, registry=REG, root=ROOT)
        # Each real collect() invocation is exercised against synthetic row
        # results. No migration upgrade, driver constructor or actual SQL runs.
        for phase in ("preflight", "locked_reinspection", "post_body", "readback"):
            action = "unit_readback" if phase == "readback" else "unit_execute"
            m = make_meter(row["unit"], action, query_templates())
            fixture = CatalogFixture(row, phase, m)
            with m.phase(phase), patch.object(OLD["catalog"], "query", fixture.query):
                OLD["catalog"].collect(a, object(), m, str, after=phase in {"post_body", "readback"})
            expected = sum(row["components"][phase].values())
            self.assertEqual(m.counts["catalog_queries"], expected)
            self.assertEqual(m.phase_counts[phase], expected)
            self.assertEqual(fixture.raw.execute.call_count, expected)
            self.assertEqual(m.counts["migration_statements"], 0)
        for action in ac.ACTIONS:
            limits = bp.select(PLAN, row["unit"], action)["limits"]
            for key, value in row["old_limits"].items():
                if key != "catalog_queries":
                    self.assertEqual(limits[key], value)

    return test


class UnitMatrixTests(unittest.TestCase):
    pass


for row in PLAN["rows"]:
    setattr(UnitMatrixTests, "test_" + row["unit"], test_unit(row))


class AccountingTests(unittest.TestCase):
    def test_saved_plan_exact_source_reproduction(self):
        self.assertEqual(PLAN, unique_json((ROOT / DIRECTORY / "observation-plan.v2.json").read_bytes()))
        self.assertEqual(
            bp.budget_proposal(PLAN), unique_json((ROOT / DIRECTORY / "query-budgets.v2.proposed.json").read_bytes())
        )

    def test_45_units_linear_graph_and_empty_start(self):
        self.assertEqual((len(REG["graph"]), len(PLAN["rows"])), (91, 45))
        self.assertEqual(PLAN["rows"][0]["prefix_before"], [])
        self.assertEqual(PLAN["rows"][-1]["tables_after"], 72)

    def test_frozen_exact_accounting(self):
        row = PLAN["rows"][0]
        self.assertEqual(
            [sum(row["components"][k].values()) for k in ("preflight", "locked_reinspection", "post_body")],
            [54, 54, 75],
        )
        self.assertEqual(row["actions"]["unit_execute"]["deterministic_queries"], 185)
        self.assertEqual(row["actions"]["unit_execute"]["limits"]["catalog_queries"], 256)

    def test_reference_growth(self):
        before, after = PLAN["rows"][1]["components"]["preflight"], PLAN["rows"][1]["components"]["post_body"]
        self.assertEqual((before["reference_data"], after["reference_data"]), (0, 4))
        self.assertEqual((PLAN["rows"][1]["business_before"], PLAN["rows"][1]["business_after"]), (44, 44))

    def test_318_is_not_actual_mature_prefix(self):
        row = PLAN["rows"][33]
        self.assertEqual((row["tables_before"], row["business_before"]), (72, 67))
        self.assertEqual(row["actions"]["unit_execute"]["deterministic_queries"], 308)
        self.assertNotEqual(row["actions"]["unit_execute"]["deterministic_queries"], 318)

    def test_first_coordinator_only_overflow_056(self):
        ids = [r["unit"][:3] for r in PLAN["rows"] if r["old_query_limit_below_deterministic_minimum"]]
        self.assertEqual(ids[0], "056")
        self.assertEqual(len(ids), 36)

    def test_growth_48_79(self):
        sizes = [r["tables_after"] for r in PLAN["rows"][:33]]
        self.assertEqual(sizes, sorted(sizes))
        self.assertEqual(sum(len(r["added_tables"]) for r in PLAN["rows"][1:33]), 26)

    def test_no_downgrade_or_table_effect_in_80_91(self):
        for r in PLAN["rows"][33:]:
            self.assertEqual(r["added_tables"], [])
            self.assertNotIn("downgrade", r["body_inventory"]["reachable_functions"])

    def test_readback_separate_smaller_limits(self):
        r = PLAN["rows"][-1]
        self.assertEqual(r["actions"]["unit_readback"]["deterministic_queries"], 102)
        self.assertNotIn("body", r["actions"]["unit_readback"]["phase_caps"])
        self.assertEqual(r["actions"]["unit_readback"]["limits"]["catalog_queries"], 120)

    def test_final_body_accounting(self):
        for p, row in enumerate(PLAN["rows"][-6:]):
            self.assertEqual(row["body_exact_queries"], 276 - 4 * p)
            self.assertEqual(sum(row["components"]["body"].values()), row["body_exact_queries"])
            self.assertEqual(row["actions"]["unit_execute"]["deterministic_queries"], 618 - 4 * p)
            self.assertGreater(row["actions"]["unit_execute"]["limits"]["catalog_queries"], 512)

    def test_final_body_branch_source_proof(self):
        # Review exact call sites and loop/branch structure without invocation.
        for row in PLAN["rows"][-6:]:
            tree = ast.parse((ROOT / row["source"]).read_bytes())
            funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
            calls = [
                n.func.id
                for n in ast.walk(funcs["upgrade"])
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            ]
            for name in ("_prefix", "_data_preconditions", "_empty_business", "_snapshot"):
                self.assertEqual(calls.count(name), 2)
            self.assertIn("if not done:", ast.unparse(funcs["_prefix"]))
            self.assertEqual(len(OLD["catalog"].final_queries(NS(root=ROOT, registry=REG, modules=MODULES))), 17)

    def test_driver_autocommit_conflict_is_unmodified(self):
        for row in PLAN["rows"][33:]:
            source = (ROOT / row["source"]).read_text()
            self.assertIn("autocommit", source)
            self.assertTrue("is False" in source or "is not False" in source)
        self.assertIn('"autocommit": True', (ROOT / "infra/uuid-migration/f-activation/transport.py").read_text())

    def test_historical_unknowns_not_claimed_proven(self):
        for r in PLAN["rows"][1:33]:
            self.assertIsNone(r["body_exact_queries"])
            self.assertFalse(r["actions"]["unit_execute"]["runtime_upper_bound_proven"])

    def test_reachable_helpers_static_only(self):
        raw = b"revision='x'\nTABLE='new_table'\ndef helper():\n op.create_table(TABLE)\ndef upgrade():\n helper()\ndef downgrade():\n op.drop_table(TABLE)\n"
        inv = ac.source_inventory(raw)
        self.assertEqual([e["table"] for e in inv["table_effects"]], ["new_table"])
        self.assertNotIn("downgrade", inv["reachable_functions"])

    def test_unknown_table_expression_refused(self):
        with self.assertRaises((ValueError, TypeError)):
            ac.source_inventory(b"def upgrade():\n op.create_table(dynamic_name)\n")

    def test_raw_table_sql_refused(self):
        with self.assertRaises(ValueError):
            ac.source_inventory(b'def upgrade():\n op.execute("CREATE TABLE evil (id int)")\n')

    def test_wrong_prefix_even_equal_count_refused(self):
        r = PLAN["rows"][33]
        names = list(r["prefix_before"])
        names[0] = "wrong_table"
        with self.assertRaises(ValueError):
            bp.check_prefix(PLAN, r["unit"], "preflight", names)

    def test_extra_schema_object_refused_before_emptiness(self):
        r = PLAN["rows"][33]
        with self.assertRaises(ValueError):
            bp.check_prefix(PLAN, r["unit"], "preflight", r["prefix_before"] + ["unexpected"])

    def test_non_query_limit_tampering(self):
        plan = copy.deepcopy(PLAN)
        plan["rows"][0]["actions"]["unit_execute"]["limits"]["transaction_controls"] = 5
        with self.assertRaises(ValueError):
            bp.select(plan, plan["rows"][0]["unit"], "unit_execute")

    def test_old_action_names_refused(self):
        with self.assertRaises(ValueError):
            bp.select(PLAN, PLAN["rows"][0]["unit"], "expand_execute")

    def test_csv_complete(self):
        import csv

        rows = list(csv.DictReader(io.StringIO(bp.accounting_csv(PLAN))))
        self.assertEqual(len(rows), 45)
        self.assertEqual(rows[0]["write_minimum"], "185")


class MeterTests(unittest.TestCase):
    def test_global_and_phase_once(self):
        m = make_meter()
        c = OLD["transport"].Cursor(MagicMock(), m)
        with m.phase("preflight"):
            c.execute("SELECT 1")
        self.assertEqual(m.counts["catalog_queries"], 1)
        self.assertEqual(m.phase_counts["preflight"], 1)
        self.assertEqual(m.counts["migration_statements"], 0)

    def test_initialization_counted(self):
        m = make_meter()
        c = OLD["transport"].Cursor(MagicMock(), m)
        with m.phase("initialization"):
            for _ in range(16):
                c.execute("SELECT 1")
            with self.assertRaises(ValueError):
                c.execute("SELECT 1")
        self.assertEqual(c._raw.execute.call_count, 16)

    def test_reflection_in_body_counted(self):
        m = make_meter(PLAN["rows"][1]["unit"])
        c = OLD["transport"].Cursor(MagicMock(), m)
        with m.phase("body"), m.scope("migration_statements"):
            c.execute("SELECT 1")
        self.assertEqual(m.counts["catalog_queries"], 1)
        self.assertEqual(m.phase_counts["body"], 1)

    def test_unattributed_query_refused(self):
        m = make_meter()
        raw = MagicMock()
        c = OLD["transport"].Cursor(raw, m)
        with self.assertRaises(ValueError):
            c.execute("SELECT 1")
        raw.execute.assert_not_called()

    def test_no_wildcard_or_unknown_sql(self):
        m = make_meter()
        raw = MagicMock()
        c = OLD["transport"].Cursor(raw, m)
        with m.phase("preflight"):
            with self.assertRaises(ValueError):
                c.execute("SELECT 2")
        raw.execute.assert_not_called()
        self.assertEqual(m.phase_counts["preflight"], 0)

    def test_phase_budget_failure_before_driver(self):
        m = make_meter()
        m.phase_caps["preflight"] = 1
        raw = MagicMock()
        c = OLD["transport"].Cursor(raw, m)
        with m.phase("preflight"):
            c.execute("SELECT 1")
            with self.assertRaises(ValueError):
                c.execute("SELECT 1")
        self.assertEqual(raw.execute.call_count, 1)

    def test_global256_failure_before_driver(self):
        m = make_meter()
        m.limits["catalog_queries"] = 256
        raw = MagicMock()
        c = OLD["transport"].Cursor(raw, m)
        for phase in ("preflight", "locked_reinspection"):
            with m.phase(phase):
                for _ in range(102):
                    c.execute("SELECT 1")
        with m.phase("post_body"):
            for _ in range(52):
                c.execute("SELECT 1")
            with self.assertRaises(ValueError):
                c.execute("SELECT 1")
        self.assertEqual(raw.execute.call_count, 256)

    def test_readback_no_body_phase(self):
        m = make_meter(action="unit_readback")
        with self.assertRaises(ValueError):
            with m.phase("body"):
                pass

    def test_executemany_conservative_count(self):
        m = make_meter()
        raw = MagicMock()
        c = OLD["transport"].Cursor(raw, m)
        with m.phase("preflight"):
            c.executemany("SELECT 1", [(), (), ()])
        self.assertEqual(m.counts["catalog_queries"], 3)
        self.assertEqual(m.phase_counts["preflight"], 3)

    def test_empty_generator_refused(self):
        m = make_meter()
        raw = MagicMock()
        c = OLD["transport"].Cursor(raw, m)
        with m.phase("preflight"):
            with self.assertRaises(ValueError):
                c.executemany("SELECT 1", iter([()]))
        raw.executemany.assert_not_called()

    def test_do_internal_select_is_not_extra_driver_query(self):
        sql = "DO $x$ BEGIN PERFORM 1; END; $x$;"
        m = make_meter(sqls=(sql,))
        raw = MagicMock()
        c = OLD["transport"].Cursor(raw, m)
        with m.owned_control():
            c.execute("BEGIN READ WRITE")
        with m.phase("body"), m.scope("migration_statements"):
            c.execute(sql)
        self.assertEqual(m.counts["migration_statements"], 1)
        self.assertEqual(m.counts["catalog_queries"], 0)

    def test_wrong_authority_schema_refused(self):
        m = make_meter()
        a = NS(
            args=(None, "080_uuid_public_id_expand", "unit_execute", "SYNTHETIC"),
            plan={"schema": "w23-f-unit-v1", "budgets": m.limits},
        )
        with self.assertRaises(ValueError):
            m.assert_authority(a)

    def test_action_authority_cannot_be_substituted(self):
        m = make_meter()
        a = NS(
            args=(None, "080_uuid_public_id_expand", "unit_readback", "SYNTHETIC"),
            plan={"schema": "w24b-f-unit-v2", "budgets": m.limits},
        )
        with self.assertRaises(ValueError):
            m.assert_authority(a)

    def test_cleanup_rollback_after_exhaustion(self):
        m = make_meter()
        raw = MagicMock()
        c = OLD["transport"].Cursor(raw, m)
        with m.owned_control():
            c.execute("BEGIN READ ONLY")
        m.phase_caps["preflight"] = 0
        with m.phase("preflight"):
            with self.assertRaises(ValueError):
                c.execute("SELECT 1")
        m.cleanup = True
        with m.owned_control():
            c.execute("ROLLBACK")
        self.assertFalse(m.transaction_open)
        driver = OLD["transport"].Driver(NS(autocommit=True, close=MagicMock(), closed=True), m)
        driver.close()
        driver._raw.close.assert_called_once()


class SourceTests(unittest.TestCase):
    def test_imports_inert(self):
        for name in ("review_inputs", "accounting", "budget_policy", "scoped_meter"):
            with (
                patch("os.open", side_effect=AssertionError("IO")),
                patch("builtins.open", side_effect=AssertionError("IO")),
            ):
                spec = importlib.util.spec_from_file_location("_inert_w24b", Path(__file__).parent / (name + ".py"))
                spec.loader.exec_module(importlib.util.module_from_spec(spec))

    def test_live_denial_new_and_old(self):
        with self.assertRaises(SystemExit) as result:
            bp.main(["--mode", "live", "--root", "/nonexistent"])
        self.assertEqual(result.exception.code, 2)
        with self.assertRaises(SystemExit) as result:
            OLD["activation"].main(["--mode", "live", "--root", "/nonexistent"])
        self.assertEqual(result.exception.code, 2)
        source = (ROOT / "infra/uuid-migration/fresh-coordinator/coordinator.py").read_text()
        self.assertIn("parser.exit(2", source)

    def test_offline_cli(self):
        with redirect_stdout(io.StringIO()) as output:
            bp.main(["--mode", "offline", "--root", str(ROOT)])
        self.assertEqual(json.loads(output.getvalue())["units"], 45)

    def test_exact_hash_and_duplicate_keys(self):
        with self.assertRaises(ValueError):
            pinned(ROOT, DIRECTORY + "/prior-sources.v1.json", "f" * 64)
        with self.assertRaises(ValueError):
            unique_json(b'{"a":1,"a":2}')

    def test_historical_sources_unchanged(self):
        prior, _, reg, _ = reviewed(ROOT)
        self.assertEqual(len(reg["lock"]["sources"]), 113)
        for rel, h in prior["sources"].items():
            self.assertEqual(sha((ROOT / rel).read_bytes()), h)

    def test_unapplied_patch_compiles(self):
        package = unique_json((ROOT / DIRECTORY / "proposed-execution-sources.v2.json").read_bytes())
        for path, item in package["files"].items():
            self.assertFalse((ROOT / path).exists())
            self.assertEqual(sha(item["proposed_source"].encode()), item["proposed_sha256"])
            compile(item["proposed_source"], path, "exec")

    def test_full_diff_reproduces_exact_source_pairs(self):
        import difflib

        package = unique_json((ROOT / DIRECTORY / "proposed-execution-sources.v2.json").read_bytes())
        expected = []
        for name in ("authority", "catalog", "activation"):
            path = "infra/uuid-migration/f-execution-v2/" + name + ".py"
            item = package["files"][path]
            original = (ROOT / item["original"]).read_text()
            expected.extend(
                difflib.unified_diff(
                    original.splitlines(True),
                    item["proposed_source"].splitlines(True),
                    fromfile=item["original"],
                    tofile=path,
                )
            )
        self.assertEqual("".join(expected), (ROOT / DIRECTORY / "integration.v2.proposed.diff").read_text())

    def test_no_source_promotion_or_live_authority(self):
        package = unique_json((ROOT / DIRECTORY / "proposed-execution-sources.v2.json").read_bytes())
        self.assertFalse(package["accepted"])
        self.assertEqual(package["execution_approvals"], {})
        self.assertEqual(len(list((ROOT / "alembic/versions").glob("*.py"))), 79)


class LifecycleTests(unittest.TestCase):
    def proposed_catalog(self):
        import builtins

        source = unique_json((ROOT / DIRECTORY / "proposed-execution-sources.v2.json").read_bytes())["files"][
            "infra/uuid-migration/f-execution-v2/catalog.py"
        ]["proposed_source"]
        module = ModuleType("_w24b_proposed_catalog")

        def imports(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "security":
                return OLD["security"]
            return builtins.__import__(name, globals, locals, fromlist, level)

        module.__dict__["__builtins__"] = {**vars(builtins), "__import__": imports}
        exec(compile(source, "proposed_catalog.py", "exec"), module.__dict__)
        return module

    def test_guard_in_actual_proposed_catalog_before_extra_table_query(self):
        module = self.proposed_catalog()
        row = PLAN["rows"][33]
        m = make_meter(row["unit"], sqls=query_templates())
        fixture = CatalogFixture(row, "preflight", m)
        fixture.names = fixture.names + ["unexpected"]
        a = NS(unit_authority=NS(unit=REG["units"][33]), modules=MODULES, registry=REG, root=ROOT)
        with m.phase("preflight"), patch.object(module, "query", fixture.query):
            with self.assertRaises(ValueError):
                module.collect(a, object(), m, str)
        # Only the30fixed catalog/identity/client/lock calls precede the guard.
        self.assertEqual(m.counts["catalog_queries"], 30)
        self.assertFalse(any("unexpected" in str(c) for c in fixture.raw.execute.call_args_list))

    def test_budget_failure_real_staged_cleanup_path_closes(self):
        import builtins

        source = unique_json((ROOT / DIRECTORY / "proposed-execution-sources.v2.json").read_bytes())["files"][
            "infra/uuid-migration/f-execution-v2/activation.py"
        ]["proposed_source"]
        module = ModuleType("_w24b_proposed_activation")
        module.__file__ = "offline_proposed_activation.py"

        def imports(name, globals=None, locals=None, fromlist=(), level=0):
            if name in OLD:
                return OLD[name]
            return builtins.__import__(name, globals, locals, fromlist, level)

        module.__dict__["__builtins__"] = {**vars(builtins), "__import__": imports}
        exec(compile(source, module.__file__, "exec"), module.__dict__)
        m = make_meter()
        m.phase_caps["preflight"] = 1
        raw = MagicMock()
        cursor = OLD["transport"].Cursor(raw, m)

        class Connection:
            def exec_driver_sql(self, sql):
                cursor.execute(sql)

        connection = Connection()
        transport = MagicMock()
        transport.options = {}
        transport.open.return_value = connection
        authority = NS(
            recheck=MagicMock(),
            unit_authority=NS(
                unit=REG["units"][33],
                args=(REG["units"][33]["previous"], REG["units"][33]["next"], "unit_execute", "SYNTHETIC"),
                plan={"schema": "w24b-f-unit-v2", "budgets": m.limits},
            ),
            plan={"connection": {}},
        )

        def observe(*args, **kw):
            cursor.execute("SELECT 1")
            cursor.execute("SELECT 1")

        with patch.object(module, "observe", observe):
            result = module.stage_unit(
                authority,
                transport,
                m,
                MagicMock(),
                resource_gate=MagicMock(),
                text_factory=str,
                context_factory=MagicMock(),
                operations_factory=MagicMock(),
            )
        self.assertEqual(result["outcome"], "ROLLED_BACK_UNVERIFIED")
        self.assertEqual(m.counts["catalog_queries"], 1)
        self.assertFalse(m.transaction_open)
        transport.open.assert_called_once()
        transport.close.assert_called_once()
        self.assertFalse(m.commit_sent)

    def test_preserved_ddl_marker_and_control_allowances(self):
        for row in PLAN["rows"]:
            n = row["nonquery_accounting"]
            old = row["old_limits"]
            self.assertLessEqual(n["marker_statements"], old["marker_statements"])
            self.assertLessEqual(n["session_statements"], old["session_statements"])
            self.assertEqual(n["write_transaction_controls"], old["transaction_controls"])
            if n["body_migration_driver_statements_exact"] is not None:
                self.assertLessEqual(
                    n["body_migration_driver_statements_exact"] + n["coordinator_table_locks"],
                    old["migration_statements"],
                )


class ContractTests(unittest.TestCase):
    def reference(self):
        lock_path = ROOT / DIRECTORY / "source-lock.v3.proposed.json"
        lock = unique_json(lock_path.read_bytes())
        return sha(lock_path.read_bytes()), {
            "schema": "w24b-observation-budget-ref-v2",
            "source_lock_sha256": sha(lock_path.read_bytes()),
            "plan_sha256": lock["new_sources"][DIRECTORY + "/observation-plan.v2.json"],
            "budget_sha256": lock["new_sources"][DIRECTORY + "/query-budgets.v2.proposed.json"],
            "unit": PLAN["rows"][33]["unit"],
            "action": "unit_execute",
        }

    def test_exact_lock_contract(self):
        h, ref = self.reference()
        result = bp.verify_contract(ROOT, h, ref)
        self.assertEqual(result["limits"]["catalog_queries"], 328)
        self.assertFalse(result["runtime_upper_bound_proven"])

    def test_modified_plan_reference_refused(self):
        h, ref = self.reference()
        ref["plan_sha256"] = "f" * 64
        with self.assertRaises(ValueError):
            bp.verify_contract(ROOT, h, ref)

    def test_missing_or_wrong_lock_hash_refused(self):
        _, ref = self.reference()
        for h in (None, "f" * 64):
            with self.assertRaises(ValueError):
                bp.verify_contract(ROOT, h, ref)

    def test_old_action_reference_refused(self):
        h, ref = self.reference()
        ref["action"] = "integrity_execute"
        with self.assertRaises(ValueError):
            bp.verify_contract(ROOT, h, ref)

    def test_execution_sources_absent_not_silently_adopted(self):
        h, _ = self.reference()
        with self.assertRaises(FileNotFoundError):
            bp.execution_bundle(ROOT, h)
        self.assertFalse((ROOT / "infra/uuid-migration/f-execution-v2").exists())

    def test_pending_not_operator_authority(self):
        p = unique_json((ROOT / DIRECTORY / "approval.pending.json").read_bytes())
        self.assertFalse(p["accepted"])
        self.assertEqual(p["approvals"], {})
        self.assertEqual(p["integrity_attestations"], [False] * 7)
        self.assertEqual(p["integrity_approvals"], {})
        self.assertIsNone(p["F_identity"])
        self.assertTrue(all(v is False for v in p["operator_reviews"].values()))

    def test_original_nonquery_limits_unmodified_in_proposal(self):
        budgets = unique_json((ROOT / DIRECTORY / "query-budgets.v2.proposed.json").read_bytes())
        self.assertFalse(budgets["accepted"])
        self.assertEqual(budgets["approvals"], {})
        for u in REG["units"]:
            row = budgets["rows"][u["next"]]
            for a in ac.ACTIONS:
                self.assertEqual(
                    {k: v for k, v in row["actions"][a]["limits"].items() if k != "catalog_queries"},
                    {k: v for k, v in u["budgets"].items() if k != "catalog_queries"},
                )

    def test_old_lock_lineage_and_no_approved_execution(self):
        p = unique_json((ROOT / DIRECTORY / "source-lock.v3.proposed.json").read_bytes())
        self.assertEqual(p["parent_lock_sha256"], "f6fe5d0a823d7af3b91dd6716dad62d2d43a90c83f9f4186227af343e5e9c83f")
        self.assertFalse(p["inherits_execution_authority"])
        self.assertEqual(p["execution_approvals"], {})
        self.assertEqual(len(p["proposed_execution_source_sha256"]), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
