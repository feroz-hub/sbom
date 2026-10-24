"""Phase-specific PostgreSQL16 GUC expectations; synthetic observations only."""

from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

import w25_catalog as catalog
import w25_contract as contract
import w25_coordinator as coordinator
import w25_inputs as inputs_module
from w25_schema import MARKER
from w25_test_support import fixture, inputs, post_rows

LOCAL = {
    "statement_timeout": "30000",
    "lock_timeout": "1000",
    "idle_in_transaction_session_timeout": "30000",
    "check_function_bodies": "on",
    "row_security": "on",
    "search_path": "pg_catalog",
}
PHASES = [(True, False), (False, False), (False, True), (True, True)]


def observation(readonly, after):
    api, representation, baseline = inputs()
    marker = [{"version_num": MARKER}] if readonly and after else []
    if after:
        data = post_rows(baseline, representation["model"], readonly=readonly, marker=marker)
    else:
        data = copy.deepcopy(baseline)
        data["identity"][0]["transaction_read_only"] = "on" if readonly else "off"
        for row in data["settings"]:
            if row["name"] in {"statement_timeout", "idle_in_transaction_session_timeout"}:
                row["setting"] = "30000"
            elif row["name"] == "lock_timeout":
                row["setting"] = "1000"
            elif row["name"] == "transaction_read_only":
                row["setting"] = "on" if readonly else "off"
    return api, representation, baseline, data, marker


def validate(readonly, after, mutation=None):
    api, representation, baseline, data, marker = observation(readonly, after)
    if mutation:
        mutation(data)
    return catalog.verify(data, baseline, api, representation["model"], readonly=readonly, after=after, marker=marker)


def setting(data, name):
    return next(row for row in data["settings"] if row["name"] == name)


class SettingPhaseTests(unittest.TestCase):
    def test_initial_readonly_client_sources_pass(self):
        self.assertEqual(len(validate(True, False)), 64)

    def test_locked_readwrite_client_sources_pass(self):
        self.assertEqual(len(validate(False, False)), 64)

    def test_post_body_session_sources_pass(self):
        self.assertEqual(len(validate(False, True)), 64)

    def test_independent_readback_client_sources_pass(self):
        self.assertEqual(len(validate(True, True)), 64)

    def test_four_phases_have_explicit_distinct_labels(self):
        self.assertEqual(
            catalog.SETTING_PHASES,
            dict(zip(PHASES, ["initial_readonly", "locked_pre_ddl", "post_body", "independent_readback"], strict=True)),
        )

    def test_same_value_local_assignments_still_require_session(self):
        for name, value in LOCAL.items():
            with self.subTest(name=name):
                _, _, _, data, _ = observation(False, True)
                self.assertEqual(setting(data, name), {"name": name, "setting": value, "source": "session"})
                with self.assertRaisesRegex(ValueError, "security/session drift: settings"):
                    validate(False, True, lambda d, name=name: setting(d, name).update(source="client"))

    def test_readback_never_inherits_write_sources(self):
        for name in LOCAL:
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate(True, True, lambda d, name=name: setting(d, name).update(source="session"))

    def test_both_prebody_phases_reject_session_source(self):
        for readonly in [True, False]:
            for name in LOCAL:
                with self.subTest(readonly=readonly, name=name), self.assertRaises(ValueError):
                    validate(readonly, False, lambda d, name=name: setting(d, name).update(source="session"))

    def test_every_phase_rejects_wrong_values(self):
        for readonly, after in PHASES:
            for name in LOCAL:
                with self.subTest(phase=(readonly, after), name=name), self.assertRaises(ValueError):
                    validate(readonly, after, lambda d, name=name: setting(d, name).update(setting="UNEXPECTED"))

    def test_every_phase_rejects_arbitrary_sources(self):
        for readonly, after in PHASES:
            for name in LOCAL:
                for source in ["configuration file", "default", "command line", "override", None]:
                    with self.subTest(phase=(readonly, after), name=name, source=source), self.assertRaises(ValueError):
                        validate(
                            readonly, after, lambda d, name=name, source=source: setting(d, name).update(source=source)
                        )

    def test_every_monitored_setting_is_mandatory_in_every_phase(self):
        for readonly, after in PHASES:
            for row in inputs()[2]["settings"]:
                with self.subTest(phase=(readonly, after), name=row["name"]), self.assertRaises(ValueError):
                    validate(readonly, after, lambda d, name=row["name"]: d["settings"].remove(setting(d, name)))

    def test_unmodified_monitored_settings_sources_remain_exact(self):
        baseline = inputs()[2]
        for readonly, after in PHASES:
            _, _, _, data, _ = observation(readonly, after)
            for row in baseline["settings"]:
                if row["name"] not in LOCAL and row["name"] != "transaction_read_only":
                    self.assertEqual(setting(data, row["name"]), row)
                    with self.subTest(name=row["name"], phase=(readonly, after)), self.assertRaises(ValueError):
                        validate(readonly, after, lambda d, name=row["name"]: setting(d, name).update(source="session"))

    def test_duplicate_settings_refuse(self):
        for readonly, after in PHASES:
            with self.subTest(phase=(readonly, after)), self.assertRaises(ValueError):
                validate(readonly, after, lambda d: d["settings"].append(copy.deepcopy(d["settings"][0])))

    def test_unknown_setting_refuses(self):
        with self.assertRaises(ValueError):
            validate(
                False,
                True,
                lambda d: d["settings"].append({"name": "unreviewed", "setting": "on", "source": "session"}),
            )

    def test_incomplete_setting_row_refuses(self):
        for field in ["source", "setting", "name"]:
            with self.subTest(field=field), self.assertRaises((ValueError, KeyError)):
                validate(False, True, lambda d, field=field: d["settings"][0].pop(field))

    def test_transaction_setting_value_remains_exact(self):
        for readonly, after in PHASES:
            with self.subTest(phase=(readonly, after)), self.assertRaises(ValueError):
                validate(
                    readonly,
                    after,
                    lambda d, readonly=readonly: setting(d, "transaction_read_only").update(
                        setting="off" if readonly else "on"
                    ),
                )

    def test_transaction_source_is_session_in_all_four_phases(self):
        for readonly, after in PHASES:
            self.assertEqual(setting(observation(readonly, after)[3], "transaction_read_only")["source"], "session")
            with self.assertRaises(ValueError):
                validate(readonly, after, lambda d: setting(d, "transaction_read_only").update(source="client"))

    def test_identity_readonly_cannot_be_replaced_by_settings(self):
        for readonly, after in PHASES:
            with self.assertRaises(ValueError):
                validate(
                    readonly,
                    after,
                    lambda d, readonly=readonly: d["identity"][0].update(
                        transaction_read_only="off" if readonly else "on"
                    ),
                )

    def test_explicit_phase_requires_booleans(self):
        for readonly, after in [(1, True), (True, 0), (None, False), (False, "post_body")]:
            with self.assertRaises(ValueError):
                catalog.expected_settings(inputs()[2], readonly=readonly, after=after)

    def test_expected_baseline_is_not_mutated(self):
        baseline = copy.deepcopy(inputs()[2])
        before = copy.deepcopy(baseline)
        for readonly, after in PHASES:
            catalog.expected_settings(baseline, readonly=readonly, after=after)
        self.assertEqual(baseline, before)

    def test_exact_six_monitored_local_assignments_come_from_pinned_body(self):
        api, representation, baseline = inputs()
        directives = {
            api["fresh"]["pg_lex"].statements(d["proposed"])[0].tokens[2] for d in representation["directives"]
        }
        self.assertEqual(len(directives), 12)
        self.assertEqual(directives & {r["name"] for r in baseline["settings"]}, set(LOCAL))
        self.assertEqual(set(catalog.LOCAL_MONITORED_SETTINGS), set(LOCAL))

    def test_unmonitored_directives_are_not_invented_as_observations(self):
        api, representation, baseline = inputs()
        names = {api["fresh"]["pg_lex"].statements(d["proposed"])[0].tokens[2] for d in representation["directives"]}
        self.assertEqual(
            names - {r["name"] for r in baseline["settings"]},
            {
                "client_encoding",
                "standard_conforming_strings",
                "xmloption",
                "client_min_messages",
                "default_tablespace",
                "default_table_access_method",
            },
        )

    def test_search_path_after_reset_is_catalog_only_and_session(self):
        with self.assertRaises(ValueError):
            validate(False, True, lambda d: setting(d, "search_path").update(setting="pg_catalog, public"))
        self.assertEqual(
            setting(observation(False, True)[3], "search_path"),
            {"name": "search_path", "setting": "pg_catalog", "source": "session"},
        )

    def test_source_model_still_rejects_missing_column(self):
        with self.assertRaises(ValueError):
            validate(False, True, lambda d: d["columns"].pop())

    def test_privileges_not_relaxed(self):
        with self.assertRaises(ValueError):
            validate(False, True, lambda d: d["schema_privileges"].pop())

    def test_budget_and_source_model_artifacts_unchanged(self):
        api, representation, _ = inputs()
        plan = inputs_module.unique((inputs_module.FOLDER / "observation-budget.w25.json").read_bytes())
        self.assertEqual(contract.budget(api, representation), plan)
        self.assertEqual(plan["accounting"]["write_query_ceiling"], 256)
        self.assertEqual(plan["accounting"]["readback_query_ceiling"], 104)
        self.assertEqual(
            representation["model_sha256"], "9e64728cfa41fb493c98acadc75c216d7d749aeaa25ec51372e785b50732d9df"
        )

    def test_post_sources_integrate_without_extra_query(self):
        f = fixture()
        result = coordinator.write(f.authority, f.transport, f.meter, f.journal, f.r)
        self.assertEqual(result["outcome"], "COMMITTED_UNVERIFIED")
        self.assertEqual(result["body_statements_acknowledged"], 558)
        self.assertEqual(result["counts"]["catalog_queries"], 148)
        self.assertEqual(result["counts"]["transaction_controls"], 4)
        self.assertEqual(result["attempts"], 1)
        self.assertTrue(result["physical_closed"])
        self.assertFalse(result["accepted"])

    def test_settings_failure_rolls_back_before_marker_insert(self):
        f = fixture()
        f.raw.post_mutation = lambda d: setting(d, "statement_timeout").update(source="client")
        result = coordinator.write(f.authority, f.transport, f.meter, f.journal, f.r)
        self.assertEqual(result["outcome"], "ROLLED_BACK_UNVERIFIED")
        self.assertFalse(result["commit_sent"])
        self.assertEqual(f.raw.marker, [])
        self.assertTrue(result["physical_closed"])

    def test_unknown_commit_keeps_manual_reconciliation_boundary(self):
        f = fixture()
        f.raw.fail_commit = True
        result = coordinator.write(f.authority, f.transport, f.meter, f.journal, f.r)
        self.assertIn("UNKNOWN_COMMIT_MANUAL_RECONCILIATION", result["outcome"])
        self.assertEqual(result["attempts"], 1)
        self.assertTrue(result["physical_closed"])
        self.assertFalse(result["accepted"])

    def test_independent_readback_uses_client_settings_and_separate_rollback(self):
        f = fixture("unit_readback", committed=True)
        data = post_rows(f.base, f.r["model"], readonly=True, marker=[{"version_num": MARKER}])
        with patch.object(coordinator, "verify_write_evidence", return_value=coordinator.schema_digest(data)):
            result = coordinator.readback(f.authority, f.transport, f.meter, f.journal, f.r)
        self.assertTrue(result["accepted"])
        self.assertTrue(result["rollback_acknowledged"])
        self.assertEqual(result["counts"]["catalog_queries"], 86)
        self.assertEqual(result["counts"]["transaction_controls"], 2)
        self.assertEqual(result["attempts"], 1)

    def test_write_never_opens_automatic_readback(self):
        f = fixture()
        result = coordinator.write(f.authority, f.transport, f.meter, f.journal, f.r)
        self.assertTrue(result["readback_required"])
        f.connector.assert_called_once()

    def test_original_source_lock_is_historical_not_overwritten(self):
        original = inputs_module.FOLDER / "source-lock.w25.json"
        self.assertEqual(
            inputs_module.sha(original.read_bytes()), "1cb13be06ac8db6e17963ec4f8dababa3369b02f9405e8b935f15aa8524cacad"
        )
        self.assertEqual(contract.SOURCE_LOCK.name, "source-lock.w25.v2.json")
        self.assertIn(original.name, contract.source_files())

    def test_original_pending_file_has_no_inherited_authority(self):
        p = json.loads((inputs_module.FOLDER / "approval.pending.json").read_bytes())
        self.assertFalse(p["accepted"])
        self.assertIsNone(p["sources_lock_sha256"])
        self.assertEqual(p["approvals"], {})
        self.assertFalse(any(p["operator"].values()))
        self.assertEqual(p["integrity_attestations"], [False] * 7)


if __name__ == "__main__":
    unittest.main(verbosity=2)
