#!/usr/bin/env python3
"""End-to-end rollout verification.

Phase 6 §6.2 §6.3 acceptance: confirm every gate behaves as specified.
The script exercises :func:`app.ai.rollout.evaluate_access` directly +
the FastAPI router via the in-process TestClient.

Usage:
    python scripts/verify_ai_rollout.py
    python scripts/verify_ai_rollout.py --pretty   # human-readable report

Exit codes:
    0  every check passed
    1  at least one check failed
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Force tests-style isolated DB so we don't pollute the dev sqlite_api.db.
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app.ai.rollout import _canary_bucket, evaluate_access  # noqa: E402
from app.settings import reset_settings  # noqa: E402


@dataclass
class Check:
    name: str
    passed: bool
    detail: str = ""


def _set_env(**kwargs: str) -> None:
    for k, v in kwargs.items():
        os.environ[k] = v
    reset_settings()


def _check_kill_switch_blocks_master_flag() -> Check:
    """Kill switch must override AI_FIXES_ENABLED=true."""
    _set_env(
        AI_FIXES_KILL_SWITCH="true",
        AI_FIXES_ENABLED="true",
        AI_CANARY_PERCENTAGE="100",
    )
    decision = evaluate_access(rollout_key="run:1")
    ok = not decision.allowed and decision.reason == "kill_switch"
    return Check(
        name="kill_switch overrides master flag",
        passed=ok,
        detail=f"reason={decision.reason!r} allowed={decision.allowed}",
    )


def _check_master_flag_off_blocks() -> Check:
    _set_env(
        AI_FIXES_KILL_SWITCH="false",
        AI_FIXES_ENABLED="false",
        AI_CANARY_PERCENTAGE="100",
    )
    decision = evaluate_access(rollout_key="run:1")
    ok = not decision.allowed and decision.reason == "not_enabled"
    return Check(
        name="master flag off → not_enabled",
        passed=ok,
        detail=f"reason={decision.reason!r}",
    )


def _check_canary_zero_blocks() -> Check:
    _set_env(
        AI_FIXES_KILL_SWITCH="false",
        AI_FIXES_ENABLED="true",
        AI_CANARY_PERCENTAGE="0",
    )
    decision = evaluate_access(rollout_key="run:1")
    ok = not decision.allowed and decision.reason == "canary_excluded"
    return Check(
        name="canary 0% → canary_excluded",
        passed=ok,
        detail=f"reason={decision.reason!r}",
    )


def _check_canary_full_allows() -> Check:
    _set_env(
        AI_FIXES_KILL_SWITCH="false",
        AI_FIXES_ENABLED="true",
        AI_CANARY_PERCENTAGE="100",
    )
    decision = evaluate_access(rollout_key="run:42")
    return Check(
        name="canary 100% → allowed",
        passed=decision.allowed,
        detail=f"reason={decision.reason!r}",
    )


def _check_canary_stable_per_key() -> Check:
    """Same key under same percentage → same decision every time."""
    _set_env(
        AI_FIXES_KILL_SWITCH="false",
        AI_FIXES_ENABLED="true",
        AI_CANARY_PERCENTAGE="50",
    )
    a = evaluate_access(rollout_key="run:777")
    b = evaluate_access(rollout_key="run:777")
    c = evaluate_access(rollout_key="run:777")
    ok = a.allowed == b.allowed == c.allowed
    return Check(
        name="canary 50% deterministic per key (3 calls match)",
        passed=ok,
        detail=f"results=[{a.allowed}, {b.allowed}, {c.allowed}]",
    )


def _check_canary_distribution() -> Check:
    """Hash buckets uniformly across 1000 keys (within ±5% tolerance at 50%)."""
    _set_env(
        AI_FIXES_KILL_SWITCH="false",
        AI_FIXES_ENABLED="true",
        AI_CANARY_PERCENTAGE="50",
    )
    allowed = sum(
        1 for i in range(1000) if evaluate_access(rollout_key=f"run:{i}").allowed
    )
    ok = 450 <= allowed <= 550
    return Check(
        name="canary 50% routes ~50% of 1000 keys (±5%)",
        passed=ok,
        detail=f"allowed={allowed}/1000",
    )


def _check_canary_ramp_is_additive() -> Check:
    """Bumping percentage 10 → 50 keeps the original 10% in the cohort."""
    keys = [f"k:{i}" for i in range(500)]
    _set_env(
        AI_FIXES_KILL_SWITCH="false",
        AI_FIXES_ENABLED="true",
        AI_CANARY_PERCENTAGE="10",
    )
    in_at_10 = {k for k in keys if evaluate_access(rollout_key=k).allowed}
    _set_env(AI_CANARY_PERCENTAGE="50")
    in_at_50 = {k for k in keys if evaluate_access(rollout_key=k).allowed}
    leaks = in_at_10 - in_at_50
    ok = not leaks and len(in_at_50) > len(in_at_10)
    return Check(
        name="canary ramp 10→50 is additive (no key drops out)",
        passed=ok,
        detail=f"in_10={len(in_at_10)} in_50={len(in_at_50)} leaked={len(leaks)}",
    )


def _check_canary_bucket_helper_bounds() -> Check:
    buckets = [_canary_bucket(f"k:{i}") for i in range(200)]
    ok = all(0 <= b < 100 for b in buckets) and len(set(buckets)) > 50
    return Check(
        name="_canary_bucket returns [0, 100) with high cardinality",
        passed=ok,
        detail=f"unique_buckets={len(set(buckets))}",
    )


def _check_router_returns_409_when_blocked() -> Check:
    """Live router returns the right shape for each block reason."""
    from app.main import app
    from fastapi.testclient import TestClient

    _set_env(AI_FIXES_KILL_SWITCH="true", AI_FIXES_ENABLED="true", AI_CANARY_PERCENTAGE="100")
    with TestClient(app) as client:
        # Need any existing run id; the kill switch path returns 409 BEFORE
        # touching the DB, so any int is fine.
        resp = client.post("/api/v1/runs/1/ai-fixes")
    if resp.status_code != 409:
        return Check(
            name="router 409 on kill switch",
            passed=False,
            detail=f"status={resp.status_code} body={resp.text[:200]!r}",
        )
    body = resp.json().get("detail") or {}
    ok = body.get("error_code") == "AI_FIXES_KILL_SWITCH"
    return Check(
        name="router returns AI_FIXES_KILL_SWITCH on kill switch",
        passed=ok,
        detail=f"detail={body}",
    )


CHECKS: tuple = (
    _check_kill_switch_blocks_master_flag,
    _check_master_flag_off_blocks,
    _check_canary_zero_blocks,
    _check_canary_full_allows,
    _check_canary_stable_per_key,
    _check_canary_distribution,
    _check_canary_ramp_is_additive,
    _check_canary_bucket_helper_bounds,
    _check_router_returns_409_when_blocked,
)


def _restore() -> None:
    for k in (
        "AI_FIXES_KILL_SWITCH",
        "AI_FIXES_ENABLED",
        "AI_CANARY_PERCENTAGE",
    ):
        os.environ.pop(k, None)
    reset_settings()


def main() -> int:
    ap = argparse.ArgumentParser(description="AI rollout gate verification")
    ap.add_argument("--pretty", action="store_true", help="Human-readable output")
    args = ap.parse_args()

    results: list[Check] = []
    try:
        for fn in CHECKS:
            try:
                results.append(fn())
            except Exception as exc:  # noqa: BLE001
                results.append(Check(name=fn.__name__, passed=False, detail=f"raised: {exc}"))
    finally:
        _restore()

    failures = [c for c in results if not c.passed]
    payload = {
        "total": len(results),
        "passed": len(results) - len(failures),
        "failed": len(failures),
        "checks": [{"name": c.name, "passed": c.passed, "detail": c.detail} for c in results],
    }

    if args.pretty:
        _print_pretty(results)
    else:
        print(json.dumps(payload, indent=2))

    return 0 if not failures else 1


def _print_pretty(results: Iterable[Check]) -> None:
    print("AI rollout verification")
    print("=" * 50)
    for c in results:
        mark = "✓" if c.passed else "✗"
        print(f"  {mark} {c.name}")
        if c.detail:
            print(f"      {c.detail}")
    failures = [c for c in results if not c.passed]
    print("-" * 50)
    if failures:
        print(f"FAIL — {len(failures)} of {sum(1 for _ in results)} checks failed")
    else:
        print("OK — every gate behaves as specified")


if __name__ == "__main__":
    raise SystemExit(main())
