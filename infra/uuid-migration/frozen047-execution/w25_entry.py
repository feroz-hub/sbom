"""Frozen047-only review/approved one-action CLI. Default is offline inspection."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from w25_contract import Authority, budget, validate
from w25_coordinator import readback, write
from w25_inputs import FOLDER, require, reviewed, unique
from w25_runtime import Transport, create_meter, factories, native_driver
from w25_schema import MARKER, build


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["offline", "live"], default="offline")
    parser.add_argument("--action", choices=["unit_execute", "unit_readback"])
    parser.add_argument("--manifest")
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--approval-reference")
    a = parser.parse_args(argv)
    if a.mode == "offline":
        api = reviewed()
        r = build(api)
        if a.manifest:
            p = unique(api["readonly"]["security"].private_bytes(a.manifest, a.manifest_sha256))
            validate(p, api, action=a.action or p["action"])
        print(
            json.dumps(
                {
                    "mode": "OFFLINE",
                    "unit": MARKER,
                    "statements": len(r["statements"]),
                    "directives": len(r["directives"]),
                    "model_sha256": r["model_sha256"],
                    "budget": budget(api, r)["accounting"],
                    "connections": 0,
                    "execution_approved": False,
                },
                sort_keys=True,
            )
        )
        return 0
    require(
        all([a.action, a.manifest, a.manifest_sha256, a.approval_reference]),
        "Separate exact write/readback manifest approval required",
    )
    authority = Authority(a.manifest, a.manifest_sha256, a.action, a.approval_reference)
    env = authority.api["readonly"]["security"].clean_environment(os.environ)
    authority.recheck()
    # No credential/Docker/driver access occurs before exact original-byte authority.
    api = authority.api
    representation = build(api)
    plan = unique((FOLDER / "observation-budget.w25.json").read_bytes())
    allow = unique((FOLDER / "sql-allowlist.w25.json").read_bytes())["driver_sha256"][a.action]
    directory = Path(authority.plan["evidence_directory"])
    require(directory.stat().st_mode & 0o777 == 0o700, "Private approved action directory")
    journal = api["readonly"]["probe"].Evidence(directory / "unit-attempt.jsonl")
    try:
        journal.record(
            "AUTHORITY",
            unit=MARKER,
            action=a.action,
            manifest_path=authority.path,
            manifest_sha256=authority.expected,
            sources_lock_sha256=authority.plan["sources_lock_sha256"],
        )
        meter = create_meter(api, plan, a.action, allow, journal)
        docker = api["readonly"]["runtime"].Docker(meter.check, env)
        resource = unique(
            api["readonly"]["security"].private_bytes(
                authority.plan["resource_reference"]["path"], authority.plan["resource_reference"]["sha256"]
            )
        )

        def gate():
            authority.recheck()
            api["readonly"]["runtime"].verify_resources(docker.snapshot(), resource)

        def secret():
            return api["readonly"]["runtime"].correlate(authority.plan["credential_metadata"], docker)

        gate()
        authority.recheck()
        psycopg = native_driver(api)
        transport = Transport(
            authority,
            meter,
            journal,
            connector=psycopg.connect,
            factories=factories(api),
            resource_gate=gate,
            correlate=secret,
        )
        result = (write if a.action == "unit_execute" else readback)(
            authority, transport, meter, journal, representation
        )
        print(json.dumps(result, sort_keys=True))
        return 0 if result.get("outcome") in {"COMMITTED_UNVERIFIED", "FROZEN047_INDEPENDENTLY_ACCEPTED"} else 2
    finally:
        journal.close()


if __name__ == "__main__":
    raise SystemExit(main())
