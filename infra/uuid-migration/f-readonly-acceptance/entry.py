"""Dedicated F-only CLI. Offline mode never imports a database driver."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import catalog

from security import Authority, clean_environment, private_bytes, require, unique, validate


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("offline", "live"), default="offline")
    parser.add_argument("--manifest")
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--approval-reference")
    args = parser.parse_args(argv)
    if args.mode == "offline":
        if args.manifest:
            raw = private_bytes(args.manifest, args.manifest_sha256)
            plan = validate(unique(raw), sql_pins=catalog.SQL_PINS)
            print(
                json.dumps(
                    {
                        "mode": "OFFLINE",
                        "accepted": False,
                        "approvals": plan["approvals"],
                        "operator": plan["operator"],
                        "queries_planned": len(catalog.QUERIES) + 3,
                        "manifest_sha256": args.manifest_sha256,
                        "connections": 0,
                    },
                    sort_keys=True,
                )
            )
        else:
            print(
                json.dumps(
                    {
                        "mode": "OFFLINE",
                        "queries_planned": len(catalog.QUERIES) + 3,
                        "connections": 0,
                        "live_approved": False,
                    }
                )
            )
        return 0
    require(
        args.manifest and args.manifest_sha256 and args.approval_reference,
        "Separate exact source/manifest/action approval required",
    )
    authority = Authority(args.manifest, args.manifest_sha256, args.approval_reference, catalog.SQL_PINS)
    env = clean_environment(os.environ)
    # Only AFTER exact source/raw-byte/operator/action gates do runtime imports occur.
    import runtime
    from probe import Budget, Evidence, Probe

    runtime.verify_dependencies()
    authority.recheck()
    import psycopg

    require(hasattr(psycopg.pq.PGconn, "used_password"), "Installed libpq password-use evidence unavailable")
    lock = unique((Path(__file__).parent / "dependency-lock.json").read_bytes())
    require(
        {
            "implementation": psycopg.pq.__impl__,
            "version": psycopg.pq.version(),
            "used_password_api": hasattr(psycopg.pq.PGconn, "used_password"),
        }
        == lock["libpq"],
        "Loaded libpq interface drift",
    )
    baseline = runtime.infrastructure_reference(authority.plan)
    budget = Budget()
    docker = runtime.Docker(budget.check, env)
    path = authority.plan["review_observations"]["future_evidence_path"]
    require(
        Path(path).name == "f-readonly-attempt.jsonl"
        and Path(path).parent == Path(authority.plan["infrastructure_reference"]["path"]).parent,
        "Pinned single-attempt evidence path required",
    )
    evidence = Evidence(path)
    try:
        probe = Probe(
            authority,
            budget,
            evidence,
            snapshot=docker.snapshot,
            verify_resources=runtime.verify_resources,
            correlate=lambda meta: runtime.correlate(meta, docker),
            connector=psycopg.connect,
            dependencies=runtime.verify_dependencies,
        )
        result = probe.run(baseline)
        print(
            json.dumps(
                {
                    "status": result["status"],
                    "accepted": result["accepted"],
                    "attempts": result["attempts"],
                    "queries": result["queries"],
                    "closed": result["closed"],
                },
                sort_keys=True,
            )
        )
        return 0 if result["accepted"] else 2
    finally:
        evidence.close()


if __name__ == "__main__":
    raise SystemExit(main())
