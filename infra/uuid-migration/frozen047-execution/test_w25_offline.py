"""Synthetic PostgreSQL/real SQLAlchemy tests; no network, Docker or real secrets."""

from __future__ import annotations

import ast
import copy
import importlib.util
import io
import json
import unittest
from contextlib import redirect_stdout
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock, patch

import w25_catalog as cat
import w25_contract as contract
import w25_coordinator as co
import w25_entry as entry
import w25_inputs as inp
import w25_runtime as rt
import w25_schema as schema
from w25_test_support import fixture, inputs, post_rows


class SchemaTests(unittest.TestCase):
    def test_exact_frozen558_and12_directives(self):
        api, r, _ = inputs()
        self.assertEqual(len(r["statements"]), 558)
        self.assertEqual(len(r["directives"]), 12)
        self.assertEqual(r["source_sha256"], "e310421b5fea4ef93056be590756125726280671589b50d93aa85926b9833c09")
        self.assertEqual(r["execution_sha256"], "6173c58cca7061483edd1b69e9edd0c431eee808f46ae1021293549d13e8c900")
        self.assertFalse(r["runtime_accepted"])

    def test_source_object_model_inventory(self):
        _, r, _ = inputs()
        m = r["model"]
        self.assertEqual(len(m["tables"]), 46)
        self.assertEqual(len(m["sequences"]), 34)
        self.assertEqual(len(m["indexes"]), 333)
        self.assertEqual(len(m["constraints"]), 160)
        self.assertEqual(sum(map(len, m["tables"].values())), 728)

    def test_unique_partial_and_gin_are_not_lost(self):
        _, r, _ = inputs()
        ix = r["model"]["indexes"]
        self.assertTrue(any(x["method"] == "gin" and x["opclasses"] == ["jsonb_path_ops"] for x in ix))
        self.assertTrue(any(x["predicate"] and x["unique"] for x in ix))

    def test_no_business_data_or_sequence_values(self):
        api, r, _ = inputs()
        self.assertTrue(
            all(
                api["fresh"]["pg_lex"].statements(s)[0].tokens[0] in {"CREATE", "ALTER", "SET"} for s in r["statements"]
            )
        )
        self.assertNotIn("setval", " ".join(r["statements"]).lower())

    def test_047_marker_not_part_of_source_body(self):
        _, r, _ = inputs()
        self.assertTrue(all("alembic_version" not in s for s in r["statements"]))

    def test_tampered_original_refuses(self):
        api, _, _ = inputs()
        with self.assertRaises(ValueError):
            api["fresh"]["frozen_047"].representation(b"CREATE TABLE public.fake(id integer);")

    def test_expression_normalization_preserves_precedence_literals(self):
        self.assertEqual(schema.expression(("(", "id", "=", "1", ")")), ["id", "=", "1"])
        self.assertNotEqual(
            schema.expression(("a", "*", "(", "b", "+", "c", ")")), schema.expression(("a", "*", "b", "+", "c"))
        )
        self.assertEqual(schema.expression(("'UPPER'",)), ["'UPPER'"])

    def test_unknown_identifier_refuses(self):
        for x in ["x;DROP", "public.x", "../x", "BADNAME"]:
            with self.subTest(x=x), self.assertRaises(ValueError):
                schema.identifier(x)


class CatalogTests(unittest.TestCase):
    def valid(self):
        api, r, b = inputs()
        d = post_rows(b, r["model"], readonly=False, marker=[])
        return api, r, b, d

    def test_full_synthetic_post_model_passes_without_claiming_pg(self):
        a, r, b, d = self.valid()
        self.assertEqual(len(cat.verify(d, b, a, r["model"], readonly=False, after=True, marker=[])), 64)

    def test_actual_empty_marker_before_insert_required(self):
        a, r, b, d = self.valid()
        d["marker"] = [{"version_num": schema.MARKER}]
        with self.assertRaises(ValueError):
            cat.verify(d, b, a, r["model"], readonly=False, after=True, marker=[])

    def test_undeclared_catalog_key_refuses(self):
        a, r, b, d = self.valid()
        d["extra"] = []
        with self.assertRaises(ValueError):
            cat.verify(d, b, a, r["model"], readonly=False, after=True, marker=[])

    def test_privilege_source_checks_preserved(self):
        a, r, b, d = self.valid()
        d["schema_privileges"].pop()
        with self.assertRaises(ValueError):
            cat.verify(d, b, a, r["model"], readonly=False, after=True, marker=[])

    def test_wrong_system_identifier_refuses(self):
        a, r, b, d = self.valid()
        d["identity"][0]["system_identifier"] = "7697252084555804711"
        with self.assertRaises(ValueError):
            cat.verify(d, b, a, r["model"], readonly=False, after=True, marker=[])

    def test_bad_business_row_refuses(self):
        a, r, b, d = self.valid()
        d["business"][0]["has_rows"] = True
        with self.assertRaises(ValueError):
            cat.verify(d, b, a, r["model"], readonly=False, after=True, marker=[])

    def test_duplicate_storage_oid_refuses(self):
        a, r, b, d = self.valid()
        d["storage"][0]["oid"] = d["storage"][1]["oid"]
        with self.assertRaises(ValueError):
            cat.verify(d, b, a, r["model"], readonly=False, after=True, marker=[])


def tamper_case(category, index, kind):
    def test(self):
        a, r, b, d = self.valid()
        if kind == "missing":
            d[category].pop(index)
        elif kind == "duplicate":
            d[category].append(copy.deepcopy(d[category][index]))
        else:
            d[category][index][kind] = "UNREVIEWED"
        with self.assertRaises((ValueError, KeyError, TypeError)):
            cat.verify(d, b, a, r["model"], readonly=False, after=True, marker=[])

    return test


for category, indices in [
    ("relations", [0, 44, 45, 100, 400]),
    ("columns", [0, 30, 727]),
    ("constraints", [0, 40, 100, 159]),
    ("indexes", [0, 100, 332]),
    ("sequences", [0, 33]),
    ("sequence_ownership", [0, 33]),
]:
    for index in indices:
        for kind in ["missing", "duplicate"]:
            setattr(CatalogTests, f"test_{category}_{index}_{kind}", tamper_case(category, index, kind))


class LifecycleTests(unittest.TestCase):
    def run_write(self, f=None):
        f = f or fixture()
        return f, co.write(f.authority, f.transport, f.meter, f.journal, f.r)

    def test_exact_owned_sequence_and_atomic_marker(self):
        f, r = self.run_write()
        self.assertEqual(r["outcome"], "COMMITTED_UNVERIFIED")
        self.assertFalse(r["accepted"])
        self.assertTrue(r["physical_closed"])
        self.assertEqual(r["counts"]["migration_statements"], 558)
        self.assertEqual(r["counts"]["marker_statements"], 2)
        self.assertEqual(r["counts"]["transaction_controls"], 4)
        self.assertEqual(r["counts"]["catalog_queries"], 148)
        self.assertEqual(
            r["phase_counts"],
            {
                "initialization": 5,
                "preflight": 30,
                "locked_reinspection": 30,
                "body": 0,
                "post_body": 81,
                "coordinator": 2,
            },
        )
        f.connector.assert_called_once()
        self.assertEqual(f.secret, bytearray(len(f.secret)))
        self.assertTrue(f.raw.committed)
        calls = [s for s, _ in f.raw.calls]
        self.assertLess(calls.index(f.r["statements"][-1]), calls.index(schema.CREATE_MARKER))
        self.assertLess(calls.index(schema.INSERT_MARKER), calls.index("COMMIT"))
        self.assertEqual(calls.count("COMMIT"), 1)
        self.assertEqual(calls.count("ROLLBACK"), 1)
        self.assertNotIn("BEGIN READ WRITE", calls)

    def test_parameterized_exact_marker(self):
        f, r = self.run_write()
        self.assertEqual(next(p for s, p in f.raw.calls if s == schema.INSERT_MARKER), {"revision": schema.MARKER})

    def test_precommit_body_failure_rolls_back_no_retry(self):
        f = fixture()
        f.raw.fail_sql = f.r["statements"][200]
        _, r = self.run_write(f)
        self.assertEqual(r["outcome"], "ROLLED_BACK_UNVERIFIED")
        self.assertFalse(f.raw.committed)
        self.assertEqual(f.raw.marker, [])
        self.assertTrue(f.raw.closed)
        f.connector.assert_called_once()

    def test_unknown_commit_is_not_rolled_back_or_retried(self):
        f = fixture()
        f.raw.fail_commit = True
        _, r = self.run_write(f)
        self.assertIn("UNKNOWN_COMMIT", r["outcome"])
        self.assertTrue(r["commit_sent"])
        self.assertFalse(r["commit_acknowledged"])
        self.assertEqual([s for s, _ in f.raw.calls].count("ROLLBACK"), 1)
        self.assertEqual([s for s, _ in f.raw.calls].count("COMMIT"), 1)
        self.assertTrue(f.raw.closed)

    def test_failed_write_rollback_is_not_first_ro_rollback(self):
        f = fixture()
        original = f.raw.rollback

        def rollback():
            if not f.raw.read_only:
                raise RuntimeError("synthetic second rollback fails")
            return original()

        f.raw.rollback = rollback
        f.raw.fail_sql = f.r["statements"][100]
        _, r = self.run_write(f)
        self.assertIn("ROLLBACK_UNCONFIRMED", r["outcome"])
        self.assertFalse(r["accepted"])
        self.assertTrue(f.raw.closed)

    def test_catalog_delta_refusal_rolls_back(self):
        f = fixture()
        f.raw.post_mutation = lambda d: d["constraints"].pop()
        _, r = self.run_write(f)
        self.assertEqual(r["outcome"], "ROLLED_BACK_UNVERIFIED")
        self.assertFalse(f.raw.committed)

    def test_missing_source_authority_before_ddl_stops(self):
        f = fixture()
        f.authority.check_window.side_effect = ValueError("expired")
        _, r = self.run_write(f)
        self.assertEqual(r["body_statements_acknowledged"], 0)
        self.assertFalse(f.raw.committed)

    def test_resource_change_before_write_stops(self):
        f = fixture()
        f.transport.resource_gate.side_effect = [None, None, None, ValueError("drift")]
        _, r = self.run_write(f)
        self.assertFalse(f.raw.committed)

    def test_connection_failure_is_one_attempt_and_sanitized(self):
        f = fixture()
        f.connector.side_effect = RuntimeError("SYNTHETIC_ONLY_PASSWORD")
        _, r = self.run_write(f)
        self.assertEqual(r["attempts"], 1)
        self.assertFalse(r["commit_sent"])
        f.connector.assert_called_once()
        self.assertNotIn("SYNTHETIC_ONLY_PASSWORD", str(f.journal.record.call_args_list))

    def test_false_password_use_stops_before_ddl(self):
        f = fixture()
        f.raw.pgconn.used_password = False
        _, r = self.run_write(f)
        self.assertFalse(r["commit_sent"])
        self.assertTrue(f.raw.closed)

    def test_close_failure_preserves_committed_state(self):
        f = fixture()
        f.raw.fail_close = True
        _, r = self.run_write(f)
        self.assertTrue(r["commit_acknowledged"])
        self.assertIn("CLOSURE_INCOMPLETE", r["outcome"])
        self.assertFalse(r["accepted"])

    def test_commit_intent_evidence_failure_prevents_commit(self):
        f = fixture()

        def record(event, **_):
            if event == "COMMIT_REQUESTED":
                raise OSError("disk full")

        f.journal.record.side_effect = record
        _, r = self.run_write(f)
        self.assertFalse(r["commit_sent"])
        self.assertFalse(f.raw.committed)

    def test_durable_ack_failure_keeps_known_commit(self):
        f = fixture()

        def record(event, **_):
            if event == "COMMIT_ACKNOWLEDGED":
                raise OSError("disk full")

        f.journal.record.side_effect = record
        _, r = self.run_write(f)
        self.assertTrue(r["commit_acknowledged"])
        self.assertIn("COMMITTED_EVIDENCE_INCOMPLETE", r["outcome"])
        self.assertTrue(f.raw.closed)

    def test_write_does_not_run_readback(self):
        f, r = self.run_write()
        self.assertEqual(f.connector.call_count, 1)
        self.assertTrue(r["readback_required"])
        self.assertFalse(r["accepted"])

    def test_separate_readback_owns_one_ro_connection(self):
        f = fixture("unit_readback", committed=True)
        data = post_rows(f.base, f.r["model"], readonly=True, marker=[{"version_num": schema.MARKER}])
        finger = co.schema_digest(data)
        with patch.object(co, "verify_write_evidence", return_value=finger):
            r = co.readback(f.authority, f.transport, f.meter, f.journal, f.r)
        self.assertTrue(r["accepted"])
        self.assertEqual(r["counts"]["catalog_queries"], 86)
        self.assertEqual(r["counts"]["transaction_controls"], 2)
        self.assertEqual(r["counts"]["migration_statements"], 0)
        f.connector.assert_called_once()
        self.assertTrue(f.raw.closed)

    def test_readback_cannot_accept_changed_committed_schema(self):
        f = fixture("unit_readback", committed=True)
        with patch.object(co, "verify_write_evidence", return_value="f" * 64):
            r = co.readback(f.authority, f.transport, f.meter, f.journal, f.r)
        self.assertFalse(r["accepted"])
        self.assertTrue(f.raw.closed)

    def test_readback_requires_write_evidence_before_connection(self):
        f = fixture("unit_readback")
        result = co.readback(f.authority, f.transport, f.meter, f.journal, f.r)
        self.assertFalse(result["accepted"])
        self.assertEqual(result["attempts"], 0)
        f.connector.assert_not_called()

    def test_second_open_refuses(self):
        f = fixture()
        f.transport.open()
        try:
            with self.assertRaises(ValueError):
                f.transport.open()
        finally:
            f.transport.close()
        f.connector.assert_called_once()


class MeterTests(unittest.TestCase):
    def test_query_allowlist_exhausts_before_driver(self):
        f = fixture()
        f.meter.counts["catalog_queries"] = 256
        _, r = LifecycleTests().run_write(f)
        self.assertFalse(f.raw.committed)
        self.assertFalse(any(s == schema.ADVISORY for s, _ in f.raw.calls))

    def test_no_with_values_call_bypass(self):
        for sql in [
            "WITH x AS (SELECT 1) SELECT * FROM x",
            "VALUES (1)",
            "CALL danger()",
            "COPY t TO STDOUT",
            "EXPLAIN ANALYZE DELETE FROM t",
        ]:
            f = fixture()
            f.meter.allowlist["migration_statements"].append(inp.sha(sql.encode()))
            with f.meter.scope("migration_statements"), self.assertRaises(ValueError):
                f.meter.driver(sql, None, False)

    def test_phase_budget_cannot_borrow(self):
        f = fixture()
        f.meter.phase_counts["initialization"] = 16
        with f.meter.phase("initialization"), self.assertRaises(ValueError):
            f.meter.driver("select pg_catalog.version()", None, False)

    def test_no_marker_or_ddl_in_readback_allowlist(self):
        f = fixture("unit_readback")
        with f.meter.scope("marker_statements"), self.assertRaises(ValueError):
            f.meter.driver(schema.CREATE_MARKER, None, False)

    def test_no_unapproved_control_or_executemany(self):
        f = fixture()
        with self.assertRaises(ValueError):
            f.meter.driver("COMMIT", None, False)
        with self.assertRaises(ValueError):
            f.meter.driver("select pg_catalog.version()", iter([{}]), True)

    def test_readback_hard_two_controls(self):
        f = fixture("unit_readback")
        f.meter.counts["transaction_controls"] = 2
        with self.assertRaises(ValueError):
            f.meter.charge("transaction_controls")

    def test_sqlalchemy_initialization_is_in_same_ro(self):
        f = fixture()
        session = f.transport.open()
        session.begin("ro")
        session.initialize(f.api["txn"]["recipe"].initializer)
        self.assertEqual(f.meter.phase_counts["initialization"], 5)
        self.assertEqual(f.meter.counts["transaction_controls"], 1)
        self.assertFalse(any(s == "ROLLBACK" for s, _ in f.raw.calls))
        session.finish_readonly()
        f.transport.close()

    def test_native_driver_inspection_makes_no_connection(self):
        import psycopg

        with patch.object(psycopg, "connect", side_effect=AssertionError("live driver denied")) as connect:
            rt.native_driver(inputs()[0])
            connect.assert_not_called()


class AuthorityTests(unittest.TestCase):
    def candidate(self):
        # Public pending schema is deliberately inactive; fixture IDs are synthetic
        # authority data, never passed to a live connector.
        return copy.deepcopy(json.loads((inp.FOLDER / "approval.pending.json").read_bytes()))

    def test_pending_write_refuses(self):
        p = self.candidate()
        with self.assertRaises(ValueError):
            contract.validate(p, inputs()[0], action="unit_execute", reference=None, live=True)

    def test_unsupported_revision_refuses(self):
        p = self.candidate()
        p["unit"] = "048_role_permission_catalog"
        with self.assertRaises(ValueError):
            contract.validate(p, inputs()[0], action="unit_execute")

    def test_wrong_F_identity_refuses(self):
        for key, value in [("database_oid", 999), ("system_identifier", "7697252084555804711")]:
            p = self.candidate()
            p["identity"][key] = value
            with self.assertRaises(ValueError):
                contract.validate(p, inputs()[0], action="unit_execute")

    def test_wrong_target_and_old_refs_refuse(self):
        for key, value in [
            ("host", "localhost"),
            ("port", 56041),
            ("dbname", "uuid_w17_e_integrity"),
            ("user", "postgres"),
        ]:
            p = self.candidate()
            p["target"][key] = value
            with self.assertRaises(ValueError):
                contract.validate(p, inputs()[0], action="unit_execute")

    def test_expired_manifest_refuses(self):
        p = self.candidate()
        p["expires_at"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
        with self.assertRaises(ValueError):
            contract.validate(p, inputs()[0], action="unit_execute")

    def test_duplicate_json_key_refuses(self):
        with self.assertRaises(ValueError):
            inp.unique('{"x":1,"x":2}')

    def test_raw_hash_missing_or_wrong_refuses_before_any_provider(self):
        for h in [None, "not-a-hash", "f" * 64]:
            with self.assertRaises((ValueError, FileNotFoundError)):
                contract.Authority("/missing/manifest.json", h, "unit_execute", "W25-F047-WRITE-SYNTHETIC")

    def test_inert_import_no_subprocess_or_secret(self):
        with (
            patch("subprocess.run", side_effect=AssertionError("Docker/network access")),
            patch("psycopg.connect", side_effect=AssertionError("Connection access")),
        ):
            for p in inp.FOLDER.glob("w25_*.py"):
                name = "_inert_" + p.stem
                spec = importlib.util.spec_from_file_location(name, p)
                m = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(m)

    def test_live_cli_without_authority_refuses(self):
        with self.assertRaises(ValueError):
            entry.main(["--mode", "live"])

    def test_offline_cli_never_connects(self):
        with (
            patch("psycopg.connect", side_effect=AssertionError("network")),
            patch("subprocess.run", side_effect=AssertionError("Docker")),
            redirect_stdout(io.StringIO()) as out,
        ):
            self.assertEqual(entry.main(["--mode", "offline"]), 0)
        self.assertEqual(json.loads(out.getvalue())["connections"], 0)

    def test_imports_no_application_or_historical001(self):
        for p in inp.FOLDER.glob("w25_*.py"):
            tree = ast.parse(p.read_bytes())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    self.assertTrue(all(not a.name.startswith(("app", "dotenv")) for a in node.names))
                if isinstance(node, ast.ImportFrom):
                    self.assertFalse((node.module or "").startswith(("app", "dotenv")))

    def test_new_budget_preserves_historical_write_nonquery(self):
        api, r, _ = inputs()
        b = contract.budget(api, r)
        old = inp.unique(
            (inp.ROOT / "infra/uuid-migration/f-budget-reconciliation/observation-plan.v2.json").read_bytes()
        )["rows"][0]["actions"]["unit_execute"]["limits"]
        self.assertEqual(b["rows"][0]["actions"]["unit_execute"]["limits"], old)
        self.assertEqual(b["accounting"]["post_body_exact"], 81)
        self.assertEqual(b["accounting"]["readback_query_ceiling"], 104)
        for action in b["rows"][0]["actions"].values():
            self.assertEqual(action["phase_cap_sum"], sum(action["phase_caps"].values()))
            self.assertEqual(
                action["phase_cap_sum"] + action["rounding_margin"] + action["unallocated_legacy_headroom"],
                action["limits"]["catalog_queries"],
            )

    def test_original_live_denials_remain(self):
        for name in [
            "f-transaction-correction/lifecycle.py",
            "f-budget-reconciliation/budget_policy.py",
            "fresh-coordinator/coordinator.py",
        ]:
            self.assertIn("live", (inp.ROOT / "infra/uuid-migration" / name).read_text())
        inp.load_inputs()


class MoreRegressionTests(unittest.TestCase):
    def test_source_drift_between_reinspection_and_DDL(self):
        f = fixture()
        f.authority.recheck.side_effect = [None] * 5 + [ValueError("source changed")]
        r = co.write(f.authority, f.transport, f.meter, f.journal, f.r)
        self.assertEqual(r["body_statements_acknowledged"], 0)
        self.assertFalse(f.raw.committed)
        self.assertTrue(f.raw.closed)

    def toast(self):
        api, r, b = inputs()
        d = post_rows(b, r["model"], readonly=False, marker=[])
        parent = d["storage"][0]
        parent["toast_oid"] = 50000
        t = {
            **parent,
            "oid": 50000,
            "schema": "pg_toast",
            "name": "pg_toast_" + str(parent["oid"]),
            "kind": "t",
            "replica_identity": "n",
            "toast_oid": 0,
            "parent_oid": parent["oid"],
            "parent": parent["name"],
            "method": "heap",
        }
        index = {
            **t,
            "oid": 50001,
            "name": t["name"] + "_index",
            "kind": "i",
            "parent_oid": None,
            "parent": None,
            "toast_parent_oid": parent["oid"],
            "toast_parent": parent["name"],
            "method": "btree",
        }
        d["storage"] += [t, index]
        return api, r, b, d

    def test_toast_kind_t_and_exact_dependency_graph(self):
        a, r, b, d = self.toast()
        cat.verify(d, b, a, r["model"], readonly=False, after=True, marker=[])

    def test_toast_kind_r_is_not_accepted(self):
        a, r, b, d = self.toast()
        d["storage"][-2]["kind"] = "r"
        with self.assertRaises(ValueError):
            cat.verify(d, b, a, r["model"], readonly=False, after=True, marker=[])

    def test_orphan_toast_index_refuses(self):
        a, r, b, d = self.toast()
        d["storage"][-1]["toast_parent_oid"] = 999999
        with self.assertRaises(ValueError):
            cat.verify(d, b, a, r["model"], readonly=False, after=True, marker=[])

    def test_missing_toast_index_refuses(self):
        a, r, b, d = self.toast()
        d["storage"].pop()
        with self.assertRaises(ValueError):
            cat.verify(d, b, a, r["model"], readonly=False, after=True, marker=[])

    def test_missing_storage_field_refuses(self):
        a, r, b, d = self.toast()
        d["storage"][0].pop("acl")
        with self.assertRaises(ValueError):
            cat.verify(d, b, a, r["model"], readonly=False, after=True, marker=[])

    def test_toast_owner_change_refuses(self):
        a, r, b, d = self.toast()
        d["storage"][-2]["owner"] = "postgres"
        with self.assertRaises(ValueError):
            cat.verify(d, b, a, r["model"], readonly=False, after=True, marker=[])

    def test_wrong_replica_identity_refuses(self):
        a, r, b, d = self.toast()
        d["storage"][-2]["replica_identity"] = "d"
        with self.assertRaises(ValueError):
            cat.verify(d, b, a, r["model"], readonly=False, after=True, marker=[])

    def test_query_result_row_ceiling(self):
        conn = Mock()
        conn.exec_driver_sql.return_value.mappings.return_value.fetchmany.return_value = [
            {"id": i} for i in range(1025)
        ]
        with self.assertRaises(ValueError):
            cat.rows(conn, "SELECT catalog_only")

    def test_hba_observation_not_upgraded_to_loaded_policy_proof(self):
        a, _, b = inputs()
        x = a["readonly"]["catalog"].validate(b, "172.22.0.2", True)
        self.assertEqual(x["loaded_hba_rules"], "NOT_PROVEN")

    def test_readback_close_failure_cannot_accept(self):
        f = fixture("unit_readback", committed=True)
        f.raw.fail_close = True
        data = post_rows(f.base, f.r["model"], readonly=True, marker=[{"version_num": schema.MARKER}])
        with patch.object(co, "verify_write_evidence", return_value=co.schema_digest(data)):
            result = co.readback(f.authority, f.transport, f.meter, f.journal, f.r)
        self.assertFalse(result["accepted"])

    def test_readback_STOP_failure_cannot_return_success(self):
        f = fixture("unit_readback", committed=True)
        data = post_rows(f.base, f.r["model"], readonly=True, marker=[{"version_num": schema.MARKER}])

        def record(event, **_):
            if event == "STOP":
                raise OSError("disk failure")

        f.journal.record.side_effect = record
        with patch.object(co, "verify_write_evidence", return_value=co.schema_digest(data)), self.assertRaises(OSError):
            co.readback(f.authority, f.transport, f.meter, f.journal, f.r)
        self.assertTrue(f.raw.closed)

    def test_wrong_unit_action_prevents_open(self):
        f = fixture()
        f.authority.action = "unit_readback"
        result = co.write(f.authority, f.transport, f.meter, f.journal, f.r)
        self.assertFalse(result["commit_sent"])
        f.connector.assert_not_called()

    def test_writer_after_preflight_refuses_before_mutation(self):
        f = fixture()
        f.base = copy.deepcopy(f.base)
        f.base["clients"] = [{"pid": 999}]
        f.raw.base = f.base
        result = co.write(f.authority, f.transport, f.meter, f.journal, f.r)
        self.assertFalse(f.raw.committed)
        self.assertEqual(result["body_statements_acknowledged"], 0)

    def test_model_source_and_file_agree(self):
        _, r, _ = inputs()
        stored = inp.unique((inp.FOLDER / "expected-schema.w25.json").read_bytes())
        self.assertEqual(stored["model"], r["model"])
        self.assertEqual(stored["model_sha256"], r["model_sha256"])

    def test_foreign_key_column_order_is_not_normalized(self):
        self.assertNotEqual(schema.names(("(", "a", ",", "b", ")")), schema.names(("(", "b", ",", "a", ")")))

    def test_no_implicit_execution_in_pending_templates(self):
        p = inp.unique((inp.FOLDER / "approval.pending.json").read_bytes())
        self.assertFalse(p["accepted"])
        self.assertEqual(p["approvals"], {})
        self.assertEqual(p["integrity_attestations"], [False] * 7)
        self.assertTrue(all(x is False for x in p["operator"].values()))


class FinalEvidenceTests(unittest.TestCase):
    def test_total_row_budget_stops_subsequent_query(self):
        from types import SimpleNamespace

        conn = Mock()
        conn.exec_driver_sql.return_value.mappings.return_value.fetchmany.return_value = [{"id": 1}]
        meter = SimpleNamespace(observed_rows=8192)
        with self.assertRaises(ValueError):
            cat.rows(conn, "SELECT catalog_only", meter=meter)
        self.assertEqual(conn.exec_driver_sql.call_count, 1)

    def test_real_durable_journal_with_synthetic_driver(self):
        import tempfile
        from pathlib import Path

        api, _, _ = inputs()
        with tempfile.TemporaryDirectory(dir=Path.home() / ".sbom-uuid-w2-review") as folder:
            path = Path(folder) / "synthetic-unit.jsonl"
            journal = api["readonly"]["probe"].Evidence(path)
            f = fixture(journal=journal)
            manifest = Path(folder) / "synthetic-approved.json"
            manifest.write_text(json.dumps({"approvals": {"unit_execute": "W25-F047-WRITE-SYNTHETIC"}}))
            manifest.chmod(0o600)
            journal.record(
                "AUTHORITY",
                unit=schema.MARKER,
                action="unit_execute",
                sources_lock_sha256="b" * 64,
                manifest_path=str(manifest),
                manifest_sha256=inp.sha(manifest.read_bytes()),
            )
            result = co.write(f.authority, f.transport, f.meter, journal, f.r)
            journal.close()
            self.assertEqual(result["outcome"], "COMMITTED_UNVERIFIED")
            raw = path.read_bytes()
            self.assertLess(len(raw), 2097152)
            previous = "0" * 64
            events = []
            for line in raw.splitlines(keepends=True):
                event = inp.unique(line)
                self.assertEqual(event["previous_sha256"], previous)
                previous = inp.sha(line)
                events.append(event)
            self.assertEqual(events[-1]["event"], "STOP")
            self.assertEqual(sum(e["event"] == "CATALOG_OBSERVATION" for e in events), 97)
            self.assertEqual(sum(e["event"] == "COMMIT_ACKNOWLEDGED" for e in events), 1)
            f.authority.plan["write_evidence"] = {"path": str(path), "sha256": inp.sha(raw)}
            with patch.object(contract, "validate"):
                self.assertEqual(co.verify_write_evidence(f.authority), result["schema_sha256"])
            # A newly chained summary cannot replace actual ordered execution evidence.
            omitted = next(
                i
                for i, e in enumerate(events)
                if e["event"] == "SQL_REQUESTED" and e["category"] == "migration_statements"
            )
            events.pop(omitted)
            altered = b""
            previous = "0" * 64
            for event in events:
                event["previous_sha256"] = previous
                line = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode()
                previous = inp.sha(line)
                altered += line
            path.write_bytes(altered)
            f.authority.plan["write_evidence"]["sha256"] = inp.sha(altered)
            with patch.object(contract, "validate"), self.assertRaises(ValueError):
                co.verify_write_evidence(f.authority)

    def test_disposal_failure_keeps_actual_physical_close_separate(self):
        f = fixture()
        original = f.transport.open

        def opened():
            session = original()
            session.engine.dispose = Mock(side_effect=OSError("synthetic disposal"))
            return session

        f.transport.open = opened
        result = co.write(f.authority, f.transport, f.meter, f.journal, f.r)
        self.assertTrue(result["physical_closed"])
        self.assertFalse(result["logical_cleanup_and_disposal"])
        self.assertTrue(result["commit_acknowledged"])
        self.assertFalse(result["accepted"])
        self.assertIn("CLOSURE_INCOMPLETE", result["outcome"])

    def test_missing_write_proof_refuses_before_readback_connection(self):
        f = fixture("unit_readback", committed=True)
        f.authority.plan["write_evidence"] = None
        result = co.readback(f.authority, f.transport, f.meter, f.journal, f.r)
        self.assertFalse(result["accepted"])
        self.assertEqual(result["attempts"], 0)
        f.connector.assert_not_called()

    def test_bad_raw_authority_hash_before_runtime_provider_loading(self):
        with patch.object(contract, "reviewed") as runtime, self.assertRaises(ValueError):
            contract.Authority("/nonexistent/private.json", "bad", "unit_execute", "W25-F047-WRITE-SYNTHETIC")
        runtime.assert_not_called()

    def test_write_receipt_never_accepts_summary_only(self):
        f = fixture("unit_readback", committed=True)
        f.authority.plan["write_evidence"] = {"path": "/synthetic/proof", "sha256": "a" * 64}
        reader = f.api["readonly"]["security"]
        with (
            patch.object(reader, "private_bytes", return_value=b'{"accepted":true}\n'),
            self.assertRaises((ValueError, KeyError)),
        ):
            co.verify_write_evidence(f.authority)


if __name__ == "__main__":
    unittest.main(verbosity=2)
