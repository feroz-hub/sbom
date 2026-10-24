"""Inert source-only access to immutable reviewed inputs; no runtime providers."""

from __future__ import annotations

import builtins
import hashlib
import json
from pathlib import Path
from types import ModuleType

DIRECTORY = "infra/uuid-migration/f-budget-reconciliation"
PRIOR_SHA256 = "91f1819d975e131b51b63a7f62973c1fe8e85f30c6a0d76d29898d2b2198fd72"


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "Duplicate JSON key")
            value[key] = item
        return value

    return json.loads(
        raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON"))
    )


def digest(value):
    return sha(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def pinned(root, rel, expected):
    rel = Path(rel)
    require(not rel.is_absolute() and ".." not in rel.parts, "Unsafe source path")
    path = Path(root) / rel
    require(all(not p.is_symlink() for p in (path, *path.parents)), "Symlink source")
    raw = path.read_bytes()
    require(sha(raw) == expected, "Reviewed source bytes changed")
    return raw


def reviewed(root):
    prior = unique_json(pinned(root, DIRECTORY + "/prior-sources.v1.json", PRIOR_SHA256))
    for rel, expected in prior["sources"].items():
        pinned(root, rel, expected)
    for rel, expected in prior["packages"].values():
        path = Path("/Users/ferozebasha/.sbom-uuid-w2-review") / rel
        require(not path.is_symlink() and sha(path.read_bytes()) == expected, "Historical package changed")
    path = "infra/uuid-migration/f-activation/reviewed.py"
    module = ModuleType("_w24b_reviewed_bridge")
    exec(compile(pinned(root, path, prior["sources"][path]), path, "exec"), module.__dict__)
    modules, registry = module.load(root)
    require(
        (len(registry["lock"]["sources"]), len(registry["graph"]), len(registry["units"])) == (113, 91, 45),
        "Prior discovery changed",
    )
    return prior, modules, registry, module


def adapters(root):
    """Load exact inert adapter definitions, never constructors or migration bodies."""
    prior, modules, registry, bridge = reviewed(root)
    loaded = {"reviewed": bridge}
    allowed = {
        "__future__",
        "argparse",
        "ast",
        "builtins",
        "hashlib",
        "hmac",
        "json",
        "os",
        "re",
        "stat",
        "time",
        "contextlib",
        "datetime",
        "pathlib",
        "types",
    }

    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        if name in loaded and not level:
            return loaded[name]
        require(not level and name.split(".")[0] in allowed, "Unreviewed adapter import")
        return builtins.__import__(name, globals, locals, fromlist, level)

    for name in ("security", "transport", "journal", "catalog", "binding", "activation"):
        path = "infra/uuid-migration/f-activation/" + name + ".py"
        module = ModuleType("_w24b_previous_" + name)
        module.__file__ = str(Path(root) / path)
        module.__dict__["__builtins__"] = {**vars(builtins), "__import__": imports}
        exec(compile(pinned(root, path, prior["sources"][path]), str(Path(root) / path), "exec"), module.__dict__)
        loaded[name] = module
    return modules, registry, loaded
