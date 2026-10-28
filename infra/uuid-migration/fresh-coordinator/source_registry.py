"""W2.3 versioned discovery. Inert import; no migration module is imported."""

from __future__ import annotations

import ast
import builtins
import hashlib
import json
import sys
from pathlib import Path
from types import ModuleType

LOCK_SHA256 = "f6fe5d0a823d7af3b91dd6716dad62d2d43a90c83f9f4186227af343e5e9c83f"
DIRECTORY = "infra/uuid-migration/fresh-coordinator"
SETS = {"alembic/versions": 79, "infra/uuid-migration/staged-alembic": 6, "infra/uuid-migration/staged-finalization": 6}
PACKAGES = {
    "w21": "7b524fd8484116a4190b4dfeb98edb7324bdca38b1ddd4989b5f13a236080b34",
    "w22": "6112f88448ddc14d4959fd504311978bc4d3ec0de8930b3cb587dc7aeb1b5196",
}


class Refused(ValueError):
    """A required independently reviewed invariant is not established."""


def require(ok, reason):
    if not ok:
        raise Refused(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result

    try:
        return json.loads(
            raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(Refused("Nonfinite JSON"))
        )
    except (TypeError, UnicodeError, json.JSONDecodeError):
        raise Refused("Invalid JSON") from None


def digest(value):
    return sha(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode())


def read_pinned(root, relative, expected):
    root, relative = Path(root), Path(relative)
    require(not relative.is_absolute() and ".." not in relative.parts, "Unsafe source path")
    path = root / relative
    require(all(not part.is_symlink() for part in (path, *path.parents)), "Symlink source refused")
    raw = path.read_bytes()
    require(sha(raw) == expected, "Source bytes differ from reviewed pin")
    return raw


def declarations(raw):
    values = {}
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in {
                    "revision",
                    "down_revision",
                    "branch_labels",
                    "depends_on",
                }:
                    require(target.id not in values, "Repeated migration declaration")
                    values[target.id] = ast.literal_eval(node.value)
    require(set(values) == {"revision", "down_revision", "branch_labels", "depends_on"}, "Incomplete declarations")
    require(
        isinstance(values["revision"], str) and values["branch_labels"] is None and values["depends_on"] is None,
        "Unapproved branch/dependency",
    )
    return values


def inspect_graph(rows):
    graph = {r["revision"]: r for r in rows}
    require(len(graph) == len(rows) == 91, "Missing or duplicate revision")
    order, current = [], "091_uuid_sbom_component_finalize"
    while current is not None:
        require(isinstance(current, str) and current in graph and current not in order, "Missing/cyclic ancestor")
        row = graph[current]
        require(row["branch_labels"] is None and row["depends_on"] is None, "Unexpected graph branch")
        order.append(current)
        current = row["down_revision"]
    require(len(order) == 91, "Disconnected or additional branch")
    ordered = [graph[key] for key in reversed(order)]
    require(all(r["revision"].startswith(f"{i:03d}_") for i, r in enumerate(ordered, 1)), "Unexpected revision order")
    require(
        ordered[46]["revision"] == "047_email_verification_tokens"
        and ordered[78]["revision"] == "079_lifecycle_provider_verification",
        "Historical boundaries changed",
    )
    return ordered


def discover(root):
    root = Path(root)
    lock = unique_json(read_pinned(root, DIRECTORY + "/source-lock.v2.json", LOCK_SHA256))
    require(
        set(lock) == {"schema", "predecessor_packages", "sources", "seed_alternatives"}, "Unknown source-lock format"
    )
    require(
        lock["schema"] == "w23-source-lock-v2" and lock["predecessor_packages"] == PACKAGES,
        "Unapproved source-lock lineage",
    )
    pins = lock["sources"]
    require(isinstance(pins, dict), "Missing source pins")
    for relative, expected in pins.items():
        read_pinned(root, relative, expected)
    rows = []
    for folder, count in SETS.items():
        paths = sorted((root / folder).glob("*.py"))
        require(
            len(paths) == count
            and {str(p.relative_to(root)) for p in paths}
            == {key for key in pins if key.startswith(folder + "/") and key.endswith(".py")},
            "Unapproved migration discovery set",
        )
        for path in paths:
            row = declarations(read_pinned(root, str(path.relative_to(root)), pins[str(path.relative_to(root))]))
            rows.append(
                {
                    **row,
                    "source": str(path.relative_to(root)),
                    "path": str(path.relative_to(root)),
                    "sha256": pins[str(path.relative_to(root))],
                }
            )
    ordered = inspect_graph(rows)
    budget_map = unique_json(
        read_pinned(root, DIRECTORY + "/unit-budgets.v1.json", pins[DIRECTORY + "/unit-budgets.v1.json"])
    )
    require(set(budget_map) == {r["revision"] for r in ordered[46:]}, "Incomplete per-unit budgets")
    units = []
    for index, row in enumerate(ordered[46:], 46):
        kind = (
            "frozen_047"
            if index == 46
            else "historical"
            if index < 79
            else "uuid_expand"
            if index < 85
            else "uuid_finalize"
        )
        units.append(
            {
                "previous": None if index == 46 else row["down_revision"],
                "next": row["revision"],
                "kind": kind,
                "source": "infra/uuid-migration/fresh-bootstrap/047-execution.proposed.sql"
                if index == 46
                else row["source"],
                "source_sha256": pins["infra/uuid-migration/fresh-bootstrap/047-execution.proposed.sql"]
                if index == 46
                else row["sha256"],
                "budgets": budget_map[row["revision"]],
            }
        )
    require(len(units) == 45, "Exactly45 installation units required")
    return {"lock": lock, "lock_sha256": LOCK_SHA256, "graph": ordered, "units": units}


def next_unit(registry, previous, requested):
    require(isinstance(requested, str) and isinstance(previous, (str, type(None))), "One explicit transition required")
    found = [u for u in registry["units"] if u["previous"] == previous and u["next"] == requested]
    require(len(found) == 1, "Skipped/repeated/out-of-order revision")
    return found[0]


def reference_api(root, registry):
    """Load only pinned inert W2.1 libraries, never any historical migration.

    Sibling imports are explicitly bound in a private namespace. No sys.path or
    application package initialization. Temporary names support dataclass setup.
    """
    modules = {}
    approved = {
        "argparse",
        "ast",
        "difflib",
        "json",
        "os",
        "re",
        "stat",
        "time",
        "dataclasses",
        "datetime",
        "pathlib",
        "hashlib",
        "collections",
        "__future__",
    }

    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        require(level == 0, "Relative dependency import refused")
        if name in modules:
            return modules[name]
        require(name.split(".")[0] in approved, "Unexpected reference-library import")
        return builtins.__import__(name, globals, locals, fromlist, level)

    for name in ("pg_lex", "frozen_047", "fresh_catalog", "fresh_bootstrap"):
        rel = f"infra/uuid-migration/fresh-bootstrap/{name}.py"
        raw = read_pinned(root, rel, registry["lock"]["sources"][rel])
        module = ModuleType("_w23_reference_" + name)
        module.__file__ = str(Path(root) / rel)
        module.__dict__["__builtins__"] = {**vars(builtins), "__import__": imports}
        sys.modules[module.__name__] = module
        try:
            exec(compile(raw, module.__file__, "exec"), module.__dict__)
        finally:
            del sys.modules[module.__name__]
        modules[name] = module
    return modules


def promotion_plan(registry):
    """Proposed operations only; never copies/renames/deletes files."""
    return [
        {
            "operation": "copy_exact_after_separate_approval",
            "source": row["source"],
            "destination": "alembic/versions/" + Path(row["source"]).name,
            "sha256": row["sha256"],
            "requires_destination_absent": True,
        }
        for row in registry["graph"][79:]
    ]
