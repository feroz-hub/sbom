"""W2.4E.1 exact ACL and acceptance-scope regressions; synthetic data only."""

from __future__ import annotations

import ast
import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import catalog as cat
import probe as pr
import test_readonly_offline as original

import security as sec


class ExactSchemaTests(unittest.TestCase):
    def validate(self, data):
        return cat.validate(data, "172.22.0.2", True)

    def test_reviewed_eleven_rows_and_four_schema_owners(self):
        data = original.observations()
        self.assertEqual(len(data["schema_privileges"]), 11)
        self.assertEqual(len(data["schemas"]), 4)
        self.assertEqual(self.validate(data)["catalog_observations"], "PASS")

    def test_observation_order_is_not_an_authority(self):
        data = original.observations()
        data["schemas"].reverse()
        data["schema_privileges"].reverse()
        self.validate(data)

    def test_public_only_old_fixture_is_refused(self):
        data = original.observations()
        data["schema_privileges"] = [r for r in data["schema_privileges"] if r["nspname"] == "public"]
        with self.assertRaisesRegex(ValueError, "Exact fresh schema privileges"):
            self.validate(data)

    def test_empty_privilege_observation_is_refused(self):
        data = original.observations()
        data["schema_privileges"] = []
        with self.assertRaises(ValueError):
            self.validate(data)

    def test_all_owner_create_and_usage_are_not_grantable(self):
        self.assertTrue(all(r[-1] is False for r in cat.SCHEMA_PRIVILEGES))
        self.assertEqual(
            {r[0] for r in cat.SCHEMA_PRIVILEGES if r[2] == "PUBLIC"},
            {"public", "pg_catalog", "information_schema"},
        )

    def test_privilege_query_observes_grantor_without_new_sql_category(self):
        self.assertIn("pg_catalog.pg_get_userbyid(a.grantor) AS grantor", cat.QUERIES["schema_privileges"])
        self.assertEqual(len(cat.QUERIES), 30)
        self.assertEqual(sec.LIMITS["queries"], 40)
        self.assertEqual(sec.LIMITS["controls"], 2)

    def test_acl_text_and_exploded_rows_must_both_match(self):
        data = original.observations()
        data["schemas"][0]["acl"] = "{}"
        with self.assertRaisesRegex(ValueError, "ACL representation"):
            self.validate(data)

    def test_toast_null_acl_has_owner_defaults_not_public_usage(self):
        data = original.observations()
        self.assertIsNone(next(r for r in data["schemas"] if r["nspname"] == "pg_toast")["acl"])
        self.assertEqual(
            {(r["grantee"], r["privilege_type"]) for r in data["schema_privileges"] if r["nspname"] == "pg_toast"},
            {(cat.BOOT, "CREATE"), (cat.BOOT, "USAGE")},
        )


def row_change(index, operation):
    def test(self):
        data = original.observations()
        rows = data["schema_privileges"]
        if operation == "missing":
            rows.pop(index)
        elif operation == "duplicate":
            rows.append(copy.deepcopy(rows[index]))
        else:
            field, value = operation
            rows[index][field] = value
        with self.assertRaises(ValueError):
            self.validate(data)

    return test


for i in range(11):
    setattr(ExactSchemaTests, f"test_missing_privilege_{i:02d}", row_change(i, "missing"))
    setattr(ExactSchemaTests, f"test_duplicate_privilege_{i:02d}", row_change(i, "duplicate"))
    setattr(ExactSchemaTests, f"test_wrong_grantor_{i:02d}", row_change(i, ("grantor", "pg_monitor")))


def schema_change(name, field, value):
    def test(self):
        data = original.observations()
        row = next(r for r in data["schemas"] if r["nspname"] == name)
        if field == "missing_row":
            data["schemas"].remove(row)
        elif value == "DELETE_FIELD":
            del row[field]
        else:
            row[field] = value
        with self.assertRaises(ValueError):
            self.validate(data)

    return test


for name in ("public", "pg_catalog", "information_schema", "pg_toast"):
    for field, value in (
        ("owner", "pg_monitor"),
        ("owner", "DELETE_FIELD"),
        ("acl", "DELETE_FIELD"),
        ("missing_row", None),
    ):
        setattr(ExactSchemaTests, f"test_{name}_{field}_{value}", schema_change(name, field, value))


class ExtraPrivilegeTests(unittest.TestCase):
    def reject(self, change):
        data = original.observations()
        change(data)
        with self.assertRaises((ValueError, KeyError)):
            cat.validate(data, "172.22.0.2", True)

    def test_public_create_extra(self):
        def change(data):
            r = copy.deepcopy(data["schema_privileges"][2])
            r["privilege_type"] = "CREATE"
            data["schema_privileges"].append(r)

        self.reject(change)

    def test_toast_public_usage_extra(self):
        def change(data):
            r = copy.deepcopy(data["schema_privileges"][-1])
            r["grantee"] = "PUBLIC"
            data["schema_privileges"].append(r)

        self.reject(change)

    def test_unexpected_grantee(self):
        self.reject(lambda d: d["schema_privileges"][3].update(grantee="pg_database_owner"))

    def test_wrong_row_owner(self):
        self.reject(lambda d: d["schema_privileges"][3].update(owner="pg_database_owner"))

    def test_unexpected_schema(self):
        self.reject(lambda d: d["schema_privileges"][3].update(nspname="alternate"))

    def test_grant_option_rejected(self):
        self.reject(lambda d: d["schema_privileges"][3].update(is_grantable=True))

    def test_numeric_false_is_not_boolean(self):
        self.reject(lambda d: d["schema_privileges"][3].update(is_grantable=0))

    def test_missing_grantor(self):
        self.reject(lambda d: d["schema_privileges"][3].pop("grantor"))

    def test_missing_grantee(self):
        self.reject(lambda d: d["schema_privileges"][3].pop("grantee"))

    def test_unexpected_field(self):
        self.reject(lambda d: d["schema_privileges"][3].update(extra="unreviewed"))

    def test_null_raw_acl_not_allowed_for_public(self):
        self.reject(lambda d: d["schemas"][0].update(acl=None))

    def test_explicit_toast_acl_requires_review(self):
        self.reject(lambda d: next(r for r in d["schemas"] if r["nspname"] == "pg_toast").update(acl="{}"))

    def test_duplicate_schema_with_missing_schema_refused(self):
        self.reject(lambda d: d["schemas"].__setitem__(1, copy.deepcopy(d["schemas"][0])))


class AcceptanceScopeTests(unittest.TestCase):
    def test_catalog_only_never_certifies_overall(self):
        a = cat.validate(original.observations(), "172.22.0.2", True)
        self.assertEqual(a["scope"], "CATALOG_OBSERVATIONS_ONLY")
        self.assertEqual(a["catalog_observations"], "PASS")
        self.assertEqual(a["authentication_evidence"], "PASS")
        self.assertEqual(a["overall_acceptance"], "NOT_EVALUATED_HERE")
        self.assertNotIn("accepted", a)
        self.assertNotIn("live_accepted", a)

    def test_complete_probe_success_is_consistent(self):
        f = original.fixture()
        result = f.p.run({})
        self.assertEqual(result["scope"], "COMPLETE_READ_ONLY_PROBE")
        self.assertTrue(result["accepted"])
        self.assertEqual(result["status"], "READ_ONLY_ACCEPTED")
        self.assertTrue(all(v == "PASS" for v in result["checks"].values()))
        self.assertNotIn("live_accepted", json.dumps(result))
        f.connector.assert_called_once()
        self.assertEqual(f.journal.record.call_args.args, ("STOP",))
        self.assertEqual(f.journal.record.call_args.kwargs["result"], result)

    def test_catalog_pass_with_rollback_failure_is_not_overall_acceptance(self):
        f = original.fixture()
        f.raw.fail_rollback = True
        result = f.p.run({})
        self.assertEqual(result["checks"]["catalog_observations"], "PASS")
        self.assertEqual(result["checks"]["authentication_evidence"], "PASS")
        self.assertEqual(result["checks"]["transaction_rollback"], "NOT_ACKNOWLEDGED")
        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "BLOCKED_OR_INCOMPLETE")
        self.assertTrue(result["closed"])

    def test_catalog_pass_with_close_failure_is_not_overall_acceptance(self):
        f = original.fixture()
        f.raw.fail_close = True
        result = f.p.run({})
        self.assertEqual(result["checks"]["catalog_observations"], "PASS")
        self.assertEqual(result["checks"]["physical_closure"], "NOT_CONFIRMED")
        self.assertFalse(result["accepted"])

    def test_resource_failure_separate_from_catalog(self):
        f = original.fixture()
        f.snapshot.side_effect = [{}, {}, ValueError("resource drift")]
        result = f.p.run({})
        self.assertEqual(result["checks"]["catalog_observations"], "PASS")
        self.assertEqual(result["checks"]["infrastructure_preservation"], "FAIL_OR_INCOMPLETE")
        self.assertFalse(result["accepted"])

    def test_auth_failure_distinct_from_catalog_and_closure(self):
        f = original.fixture()
        f.connector.side_effect = ValueError("synthetic authentication failure")
        result = f.p.run({})
        self.assertEqual(result["checks"]["authentication_evidence"], "FAIL_OR_INCOMPLETE")
        self.assertEqual(result["checks"]["catalog_observations"], "FAIL_OR_INCOMPLETE")
        self.assertEqual(result["checks"]["physical_closure"], "NOT_CONFIRMED")
        self.assertFalse(result["accepted"])

    def test_catalog_failure_keeps_password_use_evidence_distinct(self):
        f = original.fixture()
        f.raw.data["schema_privileges"] = f.raw.data["schema_privileges"][:3]
        result = f.p.run({})
        self.assertEqual(result["checks"]["authentication_evidence"], "PASS")
        self.assertEqual(result["checks"]["catalog_observations"], "FAIL_OR_INCOMPLETE")
        self.assertEqual(result["checks"]["transaction_rollback"], "PASS")
        self.assertFalse(result["accepted"])

    def test_stop_evidence_failure_prevents_successful_return(self):
        f = original.fixture()

        def record(event, **_):
            if event == "STOP":
                raise OSError("durable STOP failed")

        f.journal.record.side_effect = record
        with self.assertRaises(OSError):
            f.p.run({})
        self.assertTrue(f.raw.closed)
        self.assertTrue(f.p.rollback_ack)
        f.connector.assert_called_once()

    def test_assessment_cannot_override_failed_cleanup(self):
        f = original.fixture()
        f.raw.fail_close = True
        with patch.object(cat, "validate", return_value={"accepted": True}):
            result = f.p.run({})
        self.assertFalse(result["accepted"])

    def test_runtime_and_credential_source_are_original(self):
        d = Path(__file__).parent
        self.assertEqual(
            sec.sha((d / "runtime.py").read_bytes()), "6cec7123d910a98d3d750306cf30ad899de2686c62c4821e7931707508b3cb07"
        )
        self.assertEqual(
            sec.sha((d / "security.py").read_bytes()),
            "dcd3d6d61e3af49568c8b876c631073997b19d881b1a0c194807e364d1dc73ca",
        )
        self.assertEqual(
            sec.sha((d / "entry.py").read_bytes()), "67ba1d780f39d00d556214ac1604f2fb847f3196a6612c0165256eb0dba811ed"
        )

    def test_only_one_existing_sql_template_changes_for_grantor(self):
        # Literal query names and allowed statements remain fixed; no new action.
        tree = ast.parse(Path(pr.__file__).read_text())
        self.assertNotIn(
            "COMMIT", {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        )
        self.assertEqual(len(cat.QUERIES), 30)
        self.assertEqual(pr.OPTIONS["host"], "127.0.0.1")
        self.assertEqual(pr.OPTIONS["port"], 56043)
        self.assertEqual(pr.OPTIONS["passfile"], "/dev/null")
        self.assertNotIn("service", pr.OPTIONS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
