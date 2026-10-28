"""Offline review only. No write, readback, Docker or credential provider path."""

from __future__ import annotations

import argparse
import json


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["offline", "live"], default="offline")
    args = parser.parse_args(argv)
    if args.mode != "offline":
        raise ValueError("W2.5.1 live execution disabled; consumed W25 authority cannot be reused")
    from w251_integration import reviewed

    r = reviewed()
    print(
        json.dumps(
            {
                "mode": "OFFLINE",
                "status": "SOURCE_PROPOSAL_ONLY",
                "corrected_attribute": "broken",
                "parameterless_statement_shapes": len(r.policy.unbound),
                "bound_statement_shapes": len(r.policy.bound),
                "PostgreSQL_connections": 0,
                "Docker_commands": 0,
                "execution_approved": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
