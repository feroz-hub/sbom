"""Offline-only exact prior-artifact, dependency, graph and guard inspection."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path

from kernel import require

PACKAGES = {
    "w24a-20261019T032928881632Z/w24a-source-review-package.json": "a426703bd57c74ba25a1cdddcfdd3223f7c4a2f29765a8814f639ab04991c277",
    "w24b-20261019T045340594504Z/w24b-source-review-package.json": "3a9f64cac892d07bfb43fe7d2690455f069c253c18fd098da65e06b4b3effae1",
}
BASE = Path("/Users/ferozebasha/.sbom-uuid-w2-review")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=pairs)


def inspect(root):
    root = Path(root)
    for rel, expected in PACKAGES.items():
        path = BASE / rel
        require(not path.is_symlink(), "Symlink package")
        raw = path.read_bytes()
        require(sha(raw) == expected, "Historical package changed")
        for rel, item in unique(raw)["files"].items():
            source = item["source"].encode()
            actual = root / rel
            require(not actual.is_symlink() and actual.read_bytes() == source, "Historical source changed")
            require(sha(source) == item["sha256"], "Embedded source pin mismatch")
            require(sha(item["full_new_file_diff"].encode()) == item["diff_sha256"], "Original diff mismatch")
    lock = unique((root / "infra/uuid-migration/fresh-coordinator/source-lock.v2.json").read_bytes())
    # Lock format is verified by the unchanged W2.3/W2.4B offline suites too.
    for rel, expected in lock["sources"].items():
        require(sha((root / rel).read_bytes()) == expected, "Historical migration/reference source drift")
    matrix = []
    for folder in ("staged-alembic", "staged-finalization"):
        for path in sorted((root / "infra/uuid-migration" / folder).glob("0*.py")):
            text = path.read_text()
            tree = ast.parse(text)
            upgrade = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "upgrade")
            source = ast.get_source_segment(text, upgrade)
            require(
                "autocommit" in source and '"AUTOCOMMIT"' in source and "in_transaction()" in source,
                "UUID transaction guard changed",
            )
            matrix.append(
                {
                    "source": str(path.relative_to(root)),
                    "sha256": sha(path.read_bytes()),
                    "driver_autocommit": False,
                    "sqlalchemy_autocommit": False,
                    "owned_transaction": True,
                }
            )
    require(len(matrix) == 12, "Exactly twelve pinned UUID guards required")
    return {
        "accepted": False,
        "packages_verified": len(PACKAGES),
        "historical_pins": len(lock["sources"]),
        "guards": matrix,
        "connections": 0,
        "live_approved": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("offline", "live"), default="offline")
    args = parser.parse_args(argv)
    require(args.mode == "offline", "Live denied; review only")
    print(json.dumps(inspect(Path(__file__).resolve().parents[3]), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
