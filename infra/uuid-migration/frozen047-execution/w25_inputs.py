"""Explicit pinned, inert module loading. No historical migration body import."""

from __future__ import annotations

import builtins
import hashlib
import json
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path("/Users/ferozebasha/sbom")
FOLDER = ROOT / "infra/uuid-migration/frozen047-execution"


def require(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(raw):
    def pairs(items):
        result = {}
        for k, v in items:
            require(k not in result, "Duplicate JSON key")
            result[k] = v
        return result

    return json.loads(
        raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON"))
    )


def digest(value):
    return sha(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode())


def load_inputs(root=ROOT):
    root = Path(root)
    require(root == ROOT, "Fixed repository only")
    data = unique((FOLDER / "retained-inputs.v1.json").read_bytes())
    require(
        data["schema"] == "w25-retained-inputs-v1" and data["accepted"] is False and data["approvals"] == {},
        "Input lock contract",
    )
    for rel, h in data["sources"].items():
        p = root / rel
        require(
            not Path(rel).is_absolute()
            and ".." not in Path(rel).parts
            and not any(x.is_symlink() for x in (p, *p.parents)),
            "Unsafe pinned input",
        )
        require(sha(p.read_bytes()) == h, "Historical source drift: " + rel)
    return data


def group(folder, names, dependencies=None):
    """Load only an enumerated inert module group with isolated import names."""
    lock = load_inputs()
    modules = dict(dependencies or {})
    allowed = {
        "__future__",
        "argparse",
        "ast",
        "builtins",
        "collections",
        "contextlib",
        "csv",
        "dataclasses",
        "datetime",
        "difflib",
        "hashlib",
        "hmac",
        "io",
        "importlib",
        "ipaddress",
        "json",
        "math",
        "os",
        "pathlib",
        "re",
        "stat",
        "subprocess",
        "sys",
        "time",
        "types",
        "warnings",
    }

    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        require(level == 0, "Relative import denied")
        if name in modules:
            return modules[name]
        require(name.split(".")[0] in allowed, "Unreviewed dependency: " + name)
        return builtins.__import__(name, globals, locals, fromlist, level)

    for name in names:
        rel = "infra/uuid-migration/" + folder + "/" + name + ".py"
        p = ROOT / rel
        require(rel in lock["sources"], "Unpinned module")
        raw = p.read_bytes()
        require(sha(raw) == lock["sources"][rel], "Module pin changed")
        module = ModuleType("_w25_" + folder.replace("-", "_") + "_" + name)
        module.__file__ = str(p)
        module.__dict__["__builtins__"] = {**vars(builtins), "__import__": imports}
        sys.modules[module.__name__] = module
        try:
            exec(compile(raw, str(p), "exec"), module.__dict__)
        finally:
            sys.modules.pop(module.__name__, None)
        modules[name] = module
    return modules


def reviewed():
    fresh = group("fresh-bootstrap", ["pg_lex", "frozen_047"])
    base = group("f-activation", ["reviewed", "security", "transport", "journal"])
    budget = group("f-budget-reconciliation", ["review_inputs", "accounting", "budget_policy", "scoped_meter"])
    txn = group("f-transaction-correction", ["kernel", "dialect", "recipe", "metering"])
    readonly = group("f-readonly-acceptance", ["security", "catalog", "runtime", "probe"])
    return {"fresh": fresh, "base": base, "budget": budget, "txn": txn, "readonly": readonly}
