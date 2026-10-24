"""Frozen047-only authority, raw-byte manifests and historical evidence proof."""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from pathlib import Path

from w25_inputs import FOLDER, ROOT, group, load_inputs, require, reviewed, sha, unique
from w25_schema import MARKER

SOURCE_LOCK = FOLDER / "source-lock.w25.v2.json"

EVIDENCE = Path("/Users/ferozebasha/.sbom-uuid-w2-review/w24e-20261019T062728003301Z/f-readonly-attempt.jsonl")
EVIDENCE_HASH = "412ecca1fc065f25ef1b509e300c5bdd12430cef39d8cb4884e7dac4726f1076"
IDENTITY = {
    "system_identifier": "7698258353561202726",
    "database_oid": 16384,
    "database": "uuid_w2_f_fresh",
    "user": "uuid_w2_f_bootstrap",
    "version": 160015,
}
REVIEWS = (
    "source_reviewed",
    "F_identity_reviewed",
    "credential_provenance_reviewed",
    "privileged_bootstrap_reviewed",
    "exclusive_ddl_window_reviewed",
    "network_egress_reviewed",
    "transaction_budget_reviewed",
    "post_schema_model_reviewed",
)


def baseline(api):
    raw = api["readonly"]["security"].private_bytes(str(EVIDENCE), EVIDENCE_HASH)
    previous = "0" * 64
    events = []
    for line in raw.splitlines(keepends=True):
        row = unique(line)
        require(row["previous_sha256"] == previous, "Broken original F evidence chain")
        previous = sha(line)
        events.append(row)
    require(
        len(events) == 74 and events[0]["event"] == "CLAIMED" and events[-1]["event"] == "STOP", "Incomplete F evidence"
    )
    end = events[-1]["result"]
    require(
        end["accepted"] is True
        and end["attempts"] == 1
        and end["queries"] == 33
        and end["closed"] is True
        and end["rollback_ack"] is True
        and all(v == "PASS" for v in end["checks"].values()),
        "F acceptance incomplete",
    )
    observe = {}
    for row in events:
        if row["event"] == "CATALOG" and row["name"] not in observe:
            observe[row["name"]] = row["rows"]
    require(
        observe["identity"][0]["system_identifier"] == IDENTITY["system_identifier"]
        and observe["identity"][0]["database_oid"] == IDENTITY["database_oid"],
        "Wrong accepted F identity",
    )
    require(
        api["readonly"]["catalog"].validate(observe, "172.22.0.2", True) == end["assessment"],
        "F baseline not independently reproducible",
    )
    return observe


def budget(api, representation):
    original = unique((ROOT / "infra/uuid-migration/f-budget-reconciliation/observation-plan.v2.json").read_bytes())
    row = copy.deepcopy(original["rows"][0])
    require(row["unit"] == MARKER, "Wrong budget unit")
    post = 30 + 5 + (len(representation["model"]["tables"]) - 1) + 1
    require(post == 81, "Unexpected source-derived observation count")
    write = row["actions"]["unit_execute"]
    write["phase_caps"]["post_body"] = post
    read = row["actions"]["unit_readback"]
    read["phase_caps"]["readback"] = post
    read["limits"]["catalog_queries"] = 104
    for action in (write, read):
        action["phase_cap_sum"] = sum(action["phase_caps"].values())
        action["deterministic_queries"] = action["phase_cap_sum"] - action["phase_caps"]["initialization"]
        rounded = ((action["phase_cap_sum"] + 7) // 8) * 8
        action["rounding_margin"] = rounded - action["phase_cap_sum"]
        action["unallocated_legacy_headroom"] = action["limits"]["catalog_queries"] - rounded
    row["actions"] = {k: row["actions"][k] for k in ["unit_execute", "unit_readback"]}
    return {
        "schema": "w25-f047-observation-budget-v1-PROPOSAL",
        "accepted": False,
        "approvals": {},
        "rows": [row],
        "accounting": {
            "preflight_exact": 30,
            "locked_exact": 30,
            "post_body_exact": post,
            "readback_exact": post,
            "coordinator_exact": 2,
            "initialization_reserved": 16,
            "write_query_ceiling": 256,
            "readback_query_ceiling": 104,
            "readback_hard_controls": 2,
            "body_statements": 558,
            "marker_statements": 2,
            "session_statements_max": 2,
        },
        "transition": "Retains W24B write256/nonquery limits; postcap75->81, readback75->81 and96->104 (16+81=97, round8). No old budget edited. W25 source-specific approval required.",
    }


def source_files():
    require(all(not p.is_symlink() for p in (FOLDER, *FOLDER.parents)), "Symlink source")
    return {
        p.name: sha(p.read_bytes())
        for p in sorted(FOLDER.iterdir())
        if p.is_file() and p != SOURCE_LOCK and p.suffix in {".py", ".json", ".md", ".sql"}
    }


def validate(plan, api, *, action, reference=None, live=False, now=None):
    required = {
        "schema",
        "accepted",
        "unit",
        "previous",
        "action",
        "target",
        "identity",
        "sources_lock_sha256",
        "accepted_F_evidence",
        "resource_reference",
        "credential_metadata",
        "budget",
        "sql_allowlist_sha256",
        "model_sha256",
        "connection",
        "expires_at",
        "operator",
        "approvals",
        "integrity_attestations",
        "integrity_approvals",
        "write_evidence",
        "evidence_directory",
    }
    require(
        type(plan) is dict
        and set(plan) == required
        and plan["schema"] == "w25-f047-unit-v1"
        and plan["accepted"] is False,
        "Manifest schema/fields",
    )
    require(
        action in {"unit_execute", "unit_readback"}
        and plan["action"] == action
        and plan["unit"] == MARKER
        and plan["previous"] is None,
        "Only frozen047 next-only action",
    )
    require(
        plan["target"] == api["readonly"]["security"].TARGET and plan["identity"] == IDENTITY, "Wrong F target/identity"
    )
    require(
        plan["accepted_F_evidence"] == {"path": str(EVIDENCE), "sha256": EVIDENCE_HASH}, "Wrong original F evidence"
    )
    expiry = datetime.fromisoformat(plan["expires_at"])
    require(
        expiry.utcoffset() is not None
        and expiry.utcoffset().total_seconds() == 0
        and expiry > (now or datetime.now(UTC)),
        "Expired/non-UTC authority",
    )
    require(
        set(plan["operator"]) == set(REVIEWS) and all(type(v) is bool for v in plan["operator"].values()),
        "Review fields",
    )
    require(
        plan["integrity_attestations"] == [False] * 7 and plan["integrity_approvals"] == {}, "Integrity not authorized"
    )
    require(type(plan["approvals"]) is dict and set(plan["approvals"]) <= {action}, "Unexpected action authority")
    lock = unique(SOURCE_LOCK.read_bytes())
    require(
        sha(SOURCE_LOCK.read_bytes()) == plan["sources_lock_sha256"] and lock["sources"] == source_files(),
        "Source lock drift",
    )
    require(
        plan["budget"] == unique((FOLDER / "observation-budget.w25.json").read_bytes())["rows"][0]["actions"][action],
        "Unapproved budget",
    )
    from w25_schema import build

    actual = build(api)
    prepared = unique((FOLDER / "expected-schema.w25.json").read_bytes())
    require(
        plan["model_sha256"] == prepared["model_sha256"] == actual["model_sha256"]
        and prepared["model"] == actual["model"],
        "Schema source-model drift",
    )
    require(
        unique((FOLDER / "observation-budget.w25.json").read_bytes()) == budget(api, actual),
        "Prepared query plan differs from actual source inventory",
    )
    require(
        plan["sql_allowlist_sha256"] == sha((FOLDER / "sql-allowlist.w25.json").read_bytes()), "SQL allowlist drift"
    )
    from w25_runtime import connection_options

    require(plan["connection"] == connection_options(action), "Connection contract changed")
    original = unique(
        api["readonly"]["security"].private_bytes(
            "/Users/ferozebasha/.sbom-uuid-w2-review/w24e1-20261019T070747692248Z/f-readonly-approval-candidate.v3.json",
            "e3eea378f7c6fcf77b5021d6027a8b5b9ac829e0faafaeb7bc8801e4d8766cd9",
        )
    )
    require(
        plan["resource_reference"] == original["infrastructure_reference"]
        and plan["credential_metadata"] == original["credential_metadata"],
        "Resource/credential pins differ",
    )
    require(
        Path(plan["evidence_directory"]).is_absolute() and not Path(plan["evidence_directory"]).is_relative_to(ROOT),
        "Private unit evidence path",
    )
    if live:
        import re

        require(
            all(plan["operator"].values())
            and isinstance(reference, str)
            and re.fullmatch(
                "W25-F047-" + ("WRITE" if action == "unit_execute" else "READBACK") + "-[A-Z0-9-]{1,64}", reference
            )
            and plan["approvals"] == {action: reference},
            "Separate source-specific operator approval required",
        )
        require(
            plan["write_evidence"] is None
            if action == "unit_execute"
            else type(plan["write_evidence"]) is dict and set(plan["write_evidence"]) == {"path", "sha256"},
            "Readback needs separately reviewed write evidence",
        )
    return plan


class Authority:
    def __init__(self, path, expected, action, reference):
        self.path, self.expected, self.action, self.reference = path, expected, action, reference
        # Verify protected original bytes before loading runtime-provider definitions.
        reader = group("f-readonly-acceptance", ["security"])["security"]
        self.raw = reader.private_bytes(path, expected)
        self.plan = unique(self.raw)
        import re

        require(
            action in {"unit_execute", "unit_readback"}
            and self.plan.get("action") == action
            and self.plan.get("unit") == MARKER
            and self.plan.get("target") == reader.TARGET
            and self.plan.get("identity") == IDENTITY,
            "Exact F frozen047 authority required",
        )
        require(
            set(self.plan.get("operator", {})) == set(REVIEWS)
            and all(v is True for v in self.plan["operator"].values()),
            "Separate source-specific operator review required",
        )
        require(
            isinstance(reference, str)
            and re.fullmatch(
                "W25-F047-" + ("WRITE" if action == "unit_execute" else "READBACK") + "-[A-Z0-9-]{1,64}", reference
            )
            and self.plan.get("approvals") == {action: reference},
            "Distinct source-specific action required",
        )
        self.api = reviewed()
        validate(self.plan, self.api, action=action, reference=reference, live=True)
        self.baseline = baseline(self.api)
        self.recheck()

    def recheck(self):
        raw = self.api["readonly"]["security"].private_bytes(self.path, self.expected)
        require(raw == self.raw and unique(raw) == self.plan, "Manifest changed")
        validate(self.plan, self.api, action=self.action, reference=self.reference, live=True)
        load_inputs()
        self.api["readonly"]["runtime"].verify_dependencies()
        self.api["base"]["security"].verify_dependencies(
            unique((FOLDER / "dependencies.w25.json").read_bytes())["distributions"]
        )
        return self.plan

    def check_window(self):
        require(datetime.now(UTC) < datetime.fromisoformat(self.plan["expires_at"]), "Approval expired during body")
