"""Load pinned inert W2.3 libraries; never use or weaken its mock coordinator."""

from __future__ import annotations

import builtins
import hashlib
import sys
from pathlib import Path
from types import ModuleType

PINS = {
    "source_registry": "7ad5cc988816d000b709a214d9d53378d8e6f69c3e2e581299ac6183d4a5a4c4",
    "authority": "d9d9928165c4ef0e6dfbdd4f8623cf3bb3e4aae2054a03b5db22323618bbc9d9",
    "observations": "bc3418aa1299466df389681d7a8bd17cd0583dae79cfce0957d590df87f3bfe3",
    "isolated_loader": "fcb5b5700161e7b25fda6881229069ba0de8c866291a3db99525a9c4d82aca0d",
}


def load(root):
    modules = {}

    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        if name in modules and level == 0:
            return modules[name]
        if (
            name.split(".")[0]
            not in {
                "__future__",
                "ast",
                "builtins",
                "hashlib",
                "json",
                "sys",
                "pathlib",
                "types",
                "ipaddress",
                "os",
                "re",
                "stat",
                "datetime",
                "dataclasses",
            }
            or level
        ):
            raise ValueError("Unreviewed dependency import")
        return builtins.__import__(name, globals, locals, fromlist, level)

    for name, expected in PINS.items():
        path = Path(root) / "infra/uuid-migration/fresh-coordinator" / (name + ".py")
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError("Symlink source")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("W2.3 source pin mismatch")
        module = ModuleType("_w24a_" + name)
        module.__file__ = str(path)
        module.__dict__["__builtins__"] = {**vars(builtins), "__import__": imports}
        sys.modules[module.__name__] = module
        try:
            exec(compile(raw, str(path), "exec"), module.__dict__)
        finally:
            del sys.modules[module.__name__]
        modules[name] = module
    registry = modules["source_registry"].discover(root)
    return modules, registry
