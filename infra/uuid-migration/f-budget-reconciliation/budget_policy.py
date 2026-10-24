"""Versioned OFFLINE budget proposal verification, never execution authority."""

from __future__ import annotations

import argparse
import csv
import io
import json
from pathlib import Path

from accounting import ACTIONS, build
from review_inputs import DIRECTORY, digest, pinned, require, reviewed, sha, unique_json


def budget_proposal(plan):
    return {
        "schema": "w24b-per-action-budgets-v2",
        "accepted": False,
        "approvals": {},
        "observation_plan_canonical_sha256": digest(plan),
        "unchanged_allowances": "All non-catalog-query limits exactly retain original per-unit values",
        "rows": {
            r["unit"]: {
                "previous": r["previous"],
                "old_limits": r["old_limits"],
                "actions": {
                    a: {"limits": r["actions"][a]["limits"], "phase_caps": r["actions"][a]["phase_caps"]}
                    for a in ACTIONS
                },
            }
            for r in plan["rows"]
        },
    }


def accounting_csv(plan):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(
        [
            "revision",
            "kind",
            "tables_before",
            "tables_after",
            "business_before",
            "business_after",
            "preflight",
            "locked",
            "post_body",
            "coordinator_selects",
            "body_exact_or_unknown",
            "write_minimum",
            "old_query_limit",
            "proposed_execute",
            "proposed_validate",
            "proposed_readback",
            "readback_minimum",
            "init_reserve_per_action",
            "historical_body_reserve",
            "unproven_runtime_bound",
        ]
    )
    for r in plan["rows"]:
        a = r["actions"]
        c = r["components"]
        writer.writerow(
            [
                r["unit"],
                r["kind"],
                r["tables_before"],
                r["tables_after"],
                r["business_before"],
                r["business_after"],
                sum(c["preflight"].values()),
                sum(c["locked_reinspection"].values()),
                sum(c["post_body"].values()),
                2,
                r["body_exact_queries"] if r["body_exact_queries"] is not None else "UNKNOWN",
                a["unit_execute"]["deterministic_queries"],
                r["old_limits"]["catalog_queries"],
                *[a[key]["limits"]["catalog_queries"] for key in ("unit_execute", "unit_validate", "unit_readback")],
                a["unit_readback"]["deterministic_queries"],
                16,
                a["unit_execute"]["phase_caps"]["body"],
                True,
            ]
        )
    return stream.getvalue()


def select(plan, revision, action):
    require(action in ACTIONS, "Distinct unit action required")
    rows = [r for r in plan["rows"] if r["unit"] == revision]
    require(len(rows) == 1, "Unapproved installation unit")
    row = rows[0]
    selection = row["actions"][action]
    require(
        set(selection["limits"]) == set(row["old_limits"])
        and all(selection["limits"][k] == v for k, v in row["old_limits"].items() if k != "catalog_queries"),
        "Non-query allowance modified",
    )
    require(
        all(type(v) is int and v >= 0 for v in selection["phase_caps"].values())
        and sum(selection["phase_caps"].values()) <= selection["limits"]["catalog_queries"],
        "Inconsistent phase budget",
    )
    return selection


def verify_contract(root, approved_lock_sha256, reference):
    """Require an explicitly supplied review hash; return only an offline selection.

    The future v2 unit authority must also verify original manifest bytes,
    expiry/actions/F identity/security, and include this exact reference in those
    bytes. This helper alone NEVER approves a migration or authenticates.
    """
    root = Path(root)
    lock = unique_json(pinned(root, DIRECTORY + "/source-lock.v3.proposed.json", approved_lock_sha256))
    require(
        lock["schema"] == "w24b-source-lock-v3-PROPOSAL"
        and lock["accepted"] is False
        and lock["execution_approvals"] == {}
        and lock["inherits_execution_authority"] is False,
        "Source-lock authority mismatch",
    )
    prior, _, _, _ = reviewed(root)
    require(lock["retained_sources"] == prior["sources"], "Historical lock transition mismatch")
    for rel, h in lock["new_sources"].items():
        pinned(root, rel, h)
    plan = unique_json(
        pinned(
            root, DIRECTORY + "/observation-plan.v2.json", lock["new_sources"][DIRECTORY + "/observation-plan.v2.json"]
        )
    )
    require(plan == build(root), "Observation/source accounting changed")
    budgets = unique_json(
        pinned(
            root,
            DIRECTORY + "/query-budgets.v2.proposed.json",
            lock["new_sources"][DIRECTORY + "/query-budgets.v2.proposed.json"],
        )
    )
    require(budgets == budget_proposal(plan), "Budget proposal changed")
    require(
        set(reference) == {"schema", "source_lock_sha256", "plan_sha256", "budget_sha256", "unit", "action"}
        and reference["schema"] == "w24b-observation-budget-ref-v2"
        and reference["source_lock_sha256"] == approved_lock_sha256
        and reference["plan_sha256"] == lock["new_sources"][DIRECTORY + "/observation-plan.v2.json"]
        and reference["budget_sha256"] == lock["new_sources"][DIRECTORY + "/query-budgets.v2.proposed.json"],
        "Original manifest budget reference differs",
    )
    return select(plan, reference["unit"], reference["action"])


def check_prefix(plan, revision, phase, ordinary):
    row = next((r for r in plan["rows"] if r["unit"] == revision), None)
    require(
        row is not None and phase in {"preflight", "locked_reinspection", "post_body", "readback"},
        "Unknown prefix phase",
    )
    expected = row["prefix_before"] if phase in {"preflight", "locked_reinspection"} else row["prefix_after"]
    require(
        isinstance(ordinary, (list, set, tuple))
        and len(ordinary) == len(set(ordinary))
        and set(ordinary) == set(expected),
        "Unexpected/missing public relation; stop before per-table queries",
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["offline", "live"], required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[3])
    args = parser.parse_args(argv)
    if args.mode == "live":
        parser.exit(2, "W2.4B is an offline review proposal; execution is disabled.\n")
    plan = build(args.root)
    saved = unique_json((args.root / DIRECTORY / "observation-plan.v2.json").read_bytes())
    require(plan == saved, "Saved plan differs from actual source accounting")
    print(
        json.dumps(
            {
                "units": len(plan["rows"]),
                "strategy": plan["strategy"],
                "live_enabled": False,
                "old_limits_below_known_minimum": sum(
                    r["old_query_limit_below_deterministic_minimum"] for r in plan["rows"]
                ),
                "plan_sha256": sha((args.root / DIRECTORY / "observation-plan.v2.json").read_bytes()),
                "accepted": False,
            }
        )
    )


def execution_bundle(root, approved_lock_sha256):
    """Future copied-source gate. Intentionally fails while copies are absent.

    No copies are made here. A source-specific loader/activation review must
    separately bind these exact output hashes; old pinned loaders remain strict.
    """
    root = Path(root)
    lock = unique_json(pinned(root, DIRECTORY + "/source-lock.v3.proposed.json", approved_lock_sha256))
    require(
        lock["schema"] == "w24b-source-lock-v3-PROPOSAL" and lock["inherits_execution_authority"] is False,
        "Unreviewed execution-source transition",
    )
    result = {DIRECTORY + "/source-lock.v3.proposed.json": approved_lock_sha256}
    for rel, h in {**lock["new_sources"], **lock["proposed_execution_source_sha256"]}.items():
        pinned(root, rel, h)
        result[rel] = h
    return result


if __name__ == "__main__":
    main()
