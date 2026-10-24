"""Pinned W2.5.1 overlay proposal. No live entrypoint; all prior bytes preserved."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path("/Users/ferozebasha/sbom")
HERE = ROOT / "infra/uuid-migration/frozen047-driver-correction"
PARENT = ROOT / "infra/uuid-migration/frozen047-execution"
PARENT_LOCK = "cce0795d165c94453bdffae70302dd4c26013c8a9973945648b052374d5e1742"
SQL_PIN = "56f476f8318e3e7999a9cb18aa9530de3d871ab4ee6305e53ad457600d3de49f"


def require(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "Nonfinite JSON"))


def private_source(path, expected):
    require(not any(p.is_symlink() for p in (path, *path.parents)), "Symlink source path")
    raw = path.read_bytes()
    require(sha(raw) == expected, "Pinned source changed: " + str(path))
    return raw


def parent_module(name, lock):
    require(name + ".py" in lock["sources"], "Unpinned parent module")
    path = PARENT / (name + ".py")
    raw = private_source(path, lock["sources"][name + ".py"])
    if name in sys.modules:
        module = sys.modules[name]
        require(Path(module.__file__) == path, "Parent module shadowing")
        require(sha(Path(module.__file__).read_bytes()) == sha(raw), "Loaded parent source drift")
        return module
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


class SQLPolicy:
    def __init__(self):
        # Installed SQLAlchemy type is checked only during explicit review/tests.
        from sqlalchemy.util import immutabledict

        self.mapping_types = (dict, immutabledict)
        source = unique(private_source(PARENT / "sql-allowlist.w25.json", SQL_PIN))
        templates = source["templates"]
        all_sql = set(s for group in templates.values() for s in group)
        hstore = [s for s in all_sql if "%(name)s" in s]
        marker = [s for s in all_sql if "%(revision)s" in s]
        require(len(hstore) == len(marker) == 1, "Bound statement inventory changed")
        self.bound = {hstore[0]: {"name": "hstore"}, marker[0]: {"revision": "047_email_verification_tokens"}}
        require({s for s in all_sql if "%(" in s} == set(self.bound), "Unexpected bound template")
        self.unbound = frozenset(all_sql - set(self.bound))

    def validate(self, statement, parameters):
        require(type(statement) is str, "Exact text SQL required")
        if statement in self.bound:
            require(
                type(parameters) in self.mapping_types and dict(parameters) == self.bound[statement],
                "Exact reviewed bound parameters required",
            )
            return True
        require(statement in self.unbound, "Unreviewed exact statement")
        require(
            parameters is None or (type(parameters) in (*self.mapping_types, tuple) and len(parameters) == 0),
            "Parameterless statement cannot receive supplied values",
        )
        return False


def reviewed():
    """Verify actual parent/dependency bytes, return new isolated API namespace."""
    own_lock = unique((HERE / "source-lock.w251.v1.json").read_bytes())
    require(own_lock["accepted"] is False and own_lock["approvals"] == {}, "Unapproved source proposal only")
    require(own_lock["parent_lock_sha256"] == PARENT_LOCK, "Wrong source-lock transition")
    actual_names = {p.name for p in HERE.iterdir() if p.is_file() and p.name != "source-lock.w251.v1.json"}
    require(set(own_lock["sources"]) == actual_names, "Unexpected correction source")
    for name, pin in own_lock["sources"].items():
        require(Path(name).name == name, "Unsafe correction source name")
        private_source(HERE / name, pin)
    lock = unique(private_source(PARENT / "source-lock.w25.v2.json", PARENT_LOCK))
    for name, pin in lock["sources"].items():
        private_source(PARENT / name, pin)
    # Enumerated dependency order only; imports are inert and source-pinned.
    modules = {}
    for name in ("w25_inputs", "w25_schema", "w25_catalog", "w25_contract", "w25_coordinator", "w25_runtime"):
        modules[name] = parent_module(name, lock)
    api = modules["w25_inputs"].reviewed()
    api["readonly"]["runtime"].verify_dependencies()
    api["base"]["security"].verify_dependencies(
        unique((PARENT / "dependencies.w25.json").read_bytes())["distributions"]
    )
    from w251_driver import compatible_dialect, compatible_kernel

    policy = SQLPolicy()
    kernel = compatible_kernel(api["txn"]["kernel"])
    dialect = SimpleNamespace(factory=compatible_dialect(api["txn"]["dialect"].factory, policy))
    versioned = {**api, "txn": {**api["txn"], "kernel": kernel, "dialect": dialect}}
    return SimpleNamespace(api=versioned, parent_api=api, modules=modules, policy=policy)
