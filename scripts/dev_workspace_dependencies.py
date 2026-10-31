"""User-authorized dependency preparation, independent of private app settings.

The caller displays the immutable plan and obtains TTY consent. Its callback is
user-level confirmation, not an independent authority for privileged operations.
Only fresh missing targets or unchanged targets stamped by this adapter are
accepted. Existing partial/stale/shared artifacts are retained for review.
Installers are trusted programs, not an OS sandbox. No application is imported.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import time
import uuid
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from urllib.parse import urlsplit

if __package__:
    from . import dev_environment, dev_instance_registry, dev_instance_storage, dev_private, dev_workspace
else:
    import dev_environment
    import dev_instance_registry
    import dev_instance_storage
    import dev_private
    import dev_workspace

_MANIFESTS = ("requirements.txt", "frontend/package.json", "frontend/package-lock.json")
_STAMP = ".sbom-workspace-dependencies.json"
_SPEC_NAMES = ("alembic", "celery", "cryptography", "dotenv", "psycopg", "redis", "uvicorn")
_CONTROLLERS = ("dev_workspace_dependencies.py", "dev_environment.py", "dev_instance_registry.py",
                "dev_instance_storage.py", "dev_private.py", "dev_windows_acl.py", "dev_workspace.py")
_REQUIREMENT = re.compile(
    r"([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9_.+!-]*)"
    r"(?:\s*;\s*sys_platform\s*(==|!=)\s*['\"](win32|darwin|linux)['\"])?\Z"
)


class DependencyError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _fail(code):
    raise DependencyError(code) from None


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("DEPENDENCY_METADATA_UNVERIFIED")
        result[key] = value
    return result


def _identity(identity):
    return [str(identity.canonical_path), identity.device, identity.inode]


def _state_path(anchor, repository_id, worktree_id):
    digest = hashlib.sha256(_json([repository_id, worktree_id])).hexdigest()
    return anchor / ".sbom-dev/dependency-staging" / digest


def _directory(path):
    info = dev_instance_storage._verify(path, private=False)
    if path.resolve(strict=True) != path:
        _fail("DEPENDENCY_PATH_REDIRECTED")
    return [info.st_dev, info.st_ino]


def _file(path, root, limit=8388608):
    dev_private.validate_parent(path, root)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or getattr(before, "st_file_attributes", 0) & 1024:
        _fail("DEPENDENCY_FILE_UNVERIFIED")
    digest, count = hashlib.sha256(), 0
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        if (os.fstat(stream.fileno()).st_dev, os.fstat(stream.fileno()).st_ino) != (before.st_dev, before.st_ino):
            _fail("DEPENDENCY_FILE_CHANGED")
        while chunk := stream.read(1048576):
            count += len(chunk)
            if count > limit:
                _fail("DEPENDENCY_FILE_LIMIT")
            digest.update(chunk)
    after = path.lstat()

    def stamp(item):
        return item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns
    if stamp(before) != stamp(after) or count != before.st_size:
        _fail("DEPENDENCY_FILE_CHANGED")
    return [str(path), *stamp(after), digest.hexdigest()]


def _tree(path):
    """Metadata proof; allow only contained standard venv/.bin links, no sharing."""
    digest, count, deadline = hashlib.sha256(), 0, time.monotonic() + 15
    for directory, names, files in os.walk(path, followlinks=False):
        directory = Path(directory)
        names[:] = sorted(name for name in names if name != "__pycache__")
        for name in sorted([*names, *files]):
            if directory == path and name == _STAMP:
                continue
            count += 1
            if count > 250000 or time.monotonic() > deadline:
                _fail("DEPENDENCY_TREE_INSPECTION_LIMIT")
            current = directory / name
            info = current.lstat()
            redirected = stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 1024
            if redirected:
                target = current.resolve(strict=True)
                if not target.is_relative_to(path) or not (name == "lib64" or directory.name == ".bin"):
                    _fail("DEPENDENCY_SHARED_ARTIFACT_REFUSED")
            elif not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)) or (
                stat.S_ISREG(info.st_mode) and info.st_nlink != 1
            ):
                _fail("DEPENDENCY_SHARED_ARTIFACT_REFUSED")
            content = [] if stat.S_ISDIR(info.st_mode) else [info.st_size, info.st_mtime_ns, info.st_ctime_ns]
            digest.update(_json([str(current.relative_to(path)), info.st_dev, info.st_ino, info.st_mode, *content]))
    return digest.hexdigest()


def _requirements(raw):
    result = []
    for line in raw.decode("utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = _REQUIREMENT.fullmatch(line)
        if match is None:
            _fail("DEPENDENCY_PINNED_BINARY_REQUIREMENTS_REQUIRED")
        name, version, comparison, platform = match.groups()
        if comparison and ((sys.platform == platform) != (comparison == "==")):
            continue
        result.append((name, version))
    if not result or len(result) != len({name.lower().replace("_", "-") for name, _ in result}):
        _fail("DEPENDENCY_REQUIREMENTS_UNVERIFIED")
    return tuple(result)


def _node_packages(package, lock):
    if package.get("workspaces") or package.get("optionalDependencies") or lock.get("lockfileVersion") not in {2, 3}:
        _fail("DEPENDENCY_NPM_LOCK_POLICY_REQUIRED")
    entries = lock.get("packages")
    if not isinstance(entries, dict) or "" not in entries:
        _fail("DEPENDENCY_NPM_LOCK_POLICY_REQUIRED")
    for name, value in entries.items():
        if not isinstance(value, dict):
            _fail("DEPENDENCY_NPM_LOCK_POLICY_REQUIRED")
        if not name:
            continue
        parts = name.split("/")
        if (
            not name.startswith("node_modules/") or "\\" in name or any(part in {"", ".", ".."} for part in parts)
            or value.get("link")
            or not isinstance(value.get("version"), str)
            or re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?", value["version"]) is None
        ):
            _fail("DEPENDENCY_NPM_LOCK_POLICY_REQUIRED")
        # npm permits exact registry-version entries without these fields. The
        # approved lock uses them; they are version pins, not artifact hashes.
        if "resolved" not in value and "integrity" not in value:
            continue
        if not isinstance(value.get("resolved"), str) or not isinstance(value.get("integrity"), str):
            _fail("DEPENDENCY_NPM_LOCK_POLICY_REQUIRED")
        parsed = urlsplit(value["resolved"])
        if (
            parsed.scheme != "https" or parsed.hostname != "registry.npmjs.org"
            or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment
            or parsed.port not in {None, 443}
            or not re.fullmatch(r"sha512-[A-Za-z0-9+/]+={0,2}", value.get("integrity", ""))
        ):
            _fail("DEPENDENCY_NPM_LOCK_POLICY_REQUIRED")
    result = {}
    for field_name in ("dependencies", "devDependencies"):
        values = package.get(field_name, {})
        if not isinstance(values, dict) or values != entries[""].get(field_name, {}):
            _fail("DEPENDENCY_NPM_LOCK_MISMATCH")
        for name in values:
            if not re.fullmatch(r"(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+", name):
                _fail("DEPENDENCY_NPM_LOCK_POLICY_REQUIRED")
            version = entries.get("node_modules/" + name, {}).get("version")
            if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9_.+!-]+", version):
                _fail("DEPENDENCY_NPM_LOCK_MISMATCH")
            result[name] = version
    if "next" not in result:
        _fail("DEPENDENCY_NEXT_REQUIRED")
    return MappingProxyType(result)


@dataclass(frozen=True)
class DependencyPlan:
    repository: dev_workspace.RepositorySnapshot = field(repr=False)
    worktree: dev_workspace.WorktreeSnapshot = field(repr=False)
    state_anchor: dev_workspace.FilesystemIdentity = field(repr=False)
    manifest_hashes: Mapping[str, str]
    requirements: tuple[tuple[str, str], ...] = field(repr=False)
    node_packages: Mapping[str, str] = field(repr=False)
    tools: Mapping[str, tuple] = field(repr=False)
    tool_versions: Mapping[str, tuple]
    target_stamps: Mapping[str, str | None] = field(repr=False)
    controller_proofs: tuple[tuple, ...] = field(repr=False)
    actions: tuple[str, ...]
    blockers: tuple[str, ...]
    fingerprint: str

    def to_dict(self):
        return {"version": 1, "repository_id": self.repository.repository_id,
                "worktree_id": self.worktree.worktree_id, "commit": self.worktree.head,
                "manifest_hashes": dict(self.manifest_hashes), "tool_versions": dict(self.tool_versions),
                "actions": list(self.actions), "blockers": list(self.blockers), "fingerprint": self.fingerprint,
                "compiler_verified": False, "application_readiness_verified": False}


@dataclass(frozen=True)
class DependencyOutcome:
    code: str
    exit_code: int
    prepared: tuple[str, ...] = ()
    skipped: tuple[str, ...] = ()
    artifacts_retained: bool = False
    compiler_verified: bool = False


def _environment(tools, stage=None):
    values = {key: value for key, value in os.environ.items() if key.upper() in {"SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"}}
    values["PATH"] = os.pathsep.join(dict.fromkeys(str(Path(value[0]).parent) for value in tools.values()))
    values.update(PYTHONDONTWRITEBYTECODE="1", PYTHON_DOTENV_DISABLED="1", PIP_CONFIG_FILE=os.devnull,
                  PIP_DISABLE_PIP_VERSION_CHECK="1", PIP_NO_INPUT="1", NPM_CONFIG_USERCONFIG=os.devnull,
                  NPM_CONFIG_GLOBALCONFIG=os.devnull, NPM_CONFIG_AUDIT="false", NPM_CONFIG_FUND="false",
                  NPM_CONFIG_REGISTRY="https://registry.npmjs.org/", NPM_CONFIG_STRICT_SSL="true",
                  NEXT_TELEMETRY_DISABLED="1", CI="1")
    if stage is not None:
        values.update(HOME=str(stage / "home"), USERPROFILE=str(stage / "home"), TMP=str(stage / "tmp"),
                      TEMP=str(stage / "tmp"), TMPDIR=str(stage / "tmp"), APPDATA=str(stage / "home/AppData"),
                      LOCALAPPDATA=str(stage / "home/LocalAppData"), NPM_CONFIG_CACHE=str(stage / "cache"),
                      NPM_CONFIG_USERCONFIG=str(stage / "npm-user.conf"),
                      NPM_CONFIG_GLOBALCONFIG=str(stage / "npm-global.conf"))
    return MappingProxyType(values)


def _invoke(runner, command, root, environment, code, timeout=10):
    try:
        result = (runner or dev_workspace._run_git)(
            tuple(command), cwd=root, environment=environment, timeout=timeout, max_output=262144, input_bytes=None
        )
        if not isinstance(result, dev_workspace.CommandResult) or result.returncode != 0:
            _fail(code)
        return result.stdout
    except DependencyError:
        raise
    except Exception:
        _fail(code)


def _target(plan_values, kind, target, tools, hashes):
    if not os.path.lexists(target):
        return None
    _directory(target)
    stamp = target / _STAMP
    if not os.path.lexists(stamp):
        _fail("DEPENDENCY_EXISTING_ARTIFACT_REVIEW_REQUIRED")
    dev_instance_registry._private(stamp)
    raw = dev_environment.bounded_read_bytes(stamp, 65536)
    value = json.loads(raw, object_pairs_hook=_object)
    expected = {"version", "kind", "repository_id", "worktree_id", "root", "identity", "manifests", "tools", "versions", "tree"}
    selected = {name: hashes[name] for name in (_MANIFESTS[:1] if kind == "python" else _MANIFESTS[1:])}
    selected_tools = {name: list(proof) for name, proof in tools.items() if (name == "python") == (kind == "python")}
    if (
        not isinstance(value, dict) or set(value) != expected or type(value["version"]) is not int
        or value["version"] != 1 or value["kind"] != kind or type(value["versions"]) is not dict
        or any(value[name] != plan_values[name] for name in ("repository_id", "worktree_id", "root"))
        or value["identity"] != _directory(target) or value["manifests"] != selected
        or value["tools"] != selected_tools or value["tree"] != _tree(target)
    ):
        _fail("DEPENDENCY_EXISTING_ARTIFACT_REVIEW_REQUIRED")
    return hashlib.sha256(raw).hexdigest()


def inspect_dependencies(snapshot, selected, *, manifest_hashes=None, python_executable=None, node_executable=None,
                         npm_cli=None, runner=None, state_anchor=None):
    """Read public files/tool metadata only; never read a private .env or prepare."""
    if snapshot.status != "PASS" or selected not in snapshot.worktrees or selected.status != "PASS" or (
        selected.locked or selected.prunable or selected.bare or selected.identity is None or selected.head is None
        or snapshot.repository_id is None or selected.worktree_id is None
    ):
        _fail("DEPENDENCY_WORKTREE_UNVERIFIED")
    root = selected.identity.canonical_path
    tools, versions, hashes, stamps, blockers = {}, {}, {}, {}, []
    controllers = ()
    requirements, packages = (), MappingProxyType({})
    anchor = dev_workspace._identity(state_anchor or Path.home())
    try:
        if dev_workspace._identity(root) != selected.identity:
            _fail("DEPENDENCY_WORKTREE_CHANGED")
        try:
            _directory(root)
        except (dev_instance_storage.DirectoryInitializationError, OSError):
            _fail("DEPENDENCY_ROOT_ACCESS_REVIEW_REQUIRED")
        pending = _state_path(anchor.canonical_path, snapshot.repository_id, selected.worktree_id) / ".pending"
        dev_private.validate_parent(pending, anchor.canonical_path, allow_missing=True)
        if os.path.lexists(pending):
            _fail("DEPENDENCY_PREVIOUS_ATTEMPT_REVIEW_REQUIRED")
        source = Path(__file__).resolve().parent
        controllers = tuple(tuple(_file(source / name, source)) for name in _CONTROLLERS)
        for path in (root / ".dev-runtime.json",):
            if os.path.lexists(path):
                _fail("DEPENDENCY_RUNTIME_OR_PACKAGE_CONFIGURATION_REVIEW_REQUIRED")
        payloads = {}
        for name in _MANIFESTS:
            hashes[name] = _file(root / name, root)[-1]
            payloads[name] = dev_environment.bounded_read_bytes(root / name, 8388608)
            if hashlib.sha256(payloads[name]).hexdigest() != hashes[name]:
                _fail("DEPENDENCY_MANIFEST_CHANGED")
            if manifest_hashes is not None and manifest_hashes.get(name) != hashes[name]:
                _fail("DEPENDENCY_MANIFEST_CHANGED")
        requirements = _requirements(payloads["requirements.txt"])
        packages = _node_packages(*(json.loads(payloads[name], object_pairs_hook=_object) for name in _MANIFESTS[1:]))
        python = Path(python_executable or getattr(sys, "_base_executable", sys.executable)).resolve(strict=True)
        node = Path(node_executable or shutil.which("node") or "").resolve(strict=True)
        npm = Path(npm_cli).resolve(strict=True) if npm_cli else node.parent / "node_modules/npm/bin/npm-cli.js"
        if not npm.is_file():
            npm = Path(shutil.which("npm") or "").resolve(strict=True)
        if npm.name != "npm-cli.js":
            _fail("DEPENDENCY_NPM_CLI_REQUIRED")
        for name, path in (("python", python), ("node", node), ("npm", npm)):
            tools[name] = tuple(_file(path, path.parent, 268435456))
        environment = _environment(tools)
        raw = _invoke(runner, (str(python), "-I", "-S", "-B", "-c", "import json,sys;print(json.dumps(list(sys.version_info[:3])))"), root, environment, "DEPENDENCY_PYTHON_REQUIRED")
        version = json.loads(raw)
        if type(version) is not list or len(version) != 3 or any(type(item) is not int for item in version) or version < [3, 11, 0]:
            _fail("DEPENDENCY_PYTHON_REQUIRED")
        versions["python"] = tuple(version)
        raw = _invoke(runner, (str(node), "--version"), root, environment, "DEPENDENCY_NODE_REQUIRED").decode("ascii").strip()
        match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", raw)
        if not match or tuple(map(int, match.groups())) < (20, 9, 0):
            _fail("DEPENDENCY_NODE_REQUIRED")
        versions["node"] = tuple(map(int, match.groups()))
        values = {"repository_id": snapshot.repository_id, "worktree_id": selected.worktree_id, "root": str(root)}
        for kind, target in (("python", root / ".venv"), ("frontend", root / "frontend/node_modules")):
            stamps[kind] = _target(values, kind, target, tools, hashes)
    except DependencyError as error:
        blockers.append(error.code)
    except Exception:
        blockers.append("DEPENDENCY_INSPECTION_BLOCKED")
    public = {"repository_id": snapshot.repository_id, "worktree_id": selected.worktree_id, "head": selected.head,
              "root": _identity(selected.identity), "anchor": _identity(anchor), "hashes": hashes,
              "tools": tools, "versions": versions, "stamps": stamps, "controllers": controllers, "blockers": blockers}
    actions = tuple(("verify-" if stamps.get(kind) else "prepare-") + kind for kind in ("python", "frontend"))
    return DependencyPlan(snapshot, selected, anchor, MappingProxyType(hashes), requirements, packages,
                          MappingProxyType(tools), MappingProxyType(versions), MappingProxyType(stamps), controllers, actions,
                          tuple(blockers), hashlib.sha256(_json(public)).hexdigest())


def _revalidate(plan):
    current = dev_workspace.discover_workspaces(plan.worktree.root)
    found = next((item for item in current.worktrees if item.worktree_id == plan.worktree.worktree_id), None)
    if current.status != "PASS" or current.repository_id != plan.repository.repository_id or found is None or (
        found.identity != plan.worktree.identity or found.head != plan.worktree.head or found.status != "PASS"
        or found.locked or found.prunable or found.bare
    ):
        _fail("DEPENDENCY_WORKTREE_CHANGED")
    if dev_workspace._identity(plan.state_anchor.canonical_path) != plan.state_anchor:
        _fail("DEPENDENCY_STATE_ANCHOR_CHANGED")
    for name, expected in plan.manifest_hashes.items():
        if _file(plan.worktree.root / name, plan.worktree.root)[-1] != expected:
            _fail("DEPENDENCY_MANIFEST_CHANGED")
    for proof in plan.tools.values():
        if tuple(_file(Path(proof[0]), Path(proof[0]).parent, 268435456)) != proof:
            _fail("DEPENDENCY_TOOL_CHANGED")
    for proof in plan.controller_proofs:
        if tuple(_file(Path(proof[0]), Path(proof[0]).parent)) != proof:
            _fail("DEPENDENCY_CONTROLLER_CHANGED")
    for path in (plan.worktree.root / ".dev-runtime.json",):
        if os.path.lexists(path):
            _fail("DEPENDENCY_RUNTIME_OR_PACKAGE_CONFIGURATION_REVIEW_REQUIRED")


@contextmanager
def _lock(directory):
    identity = _directory(directory)
    path = directory / ".prepare.lock"
    if not os.path.lexists(path):
        dev_private.create_private_file(path, b"\0")
    before = dev_instance_registry._private(path)
    if before.st_size != 1:
        _fail("DEPENDENCY_LOCK_UNVERIFIED")
    descriptor = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(descriptor, "r+b") as stream:
        if (os.fstat(stream.fileno()).st_dev, os.fstat(stream.fileno()).st_ino) != (before.st_dev, before.st_ino):
            _fail("DEPENDENCY_LOCK_UNVERIFIED")
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            _fail("DEPENDENCY_PREPARATION_BUSY")
        if _directory(directory) != identity:
            _fail("DEPENDENCY_LOCK_UNVERIFIED")
        yield
        if _directory(directory) != identity or dev_instance_registry._private(path).st_ino != before.st_ino:
            _fail("DEPENDENCY_LOCK_UNVERIFIED")


def _exclusive_directory(path, root):
    dev_private.validate_parent(path, root)
    if os.name == "nt":
        dev_instance_storage._windows_create(path)
    else:
        path.mkdir(mode=0o700)
    return _directory(path)


def _publish_directory(source, destination):
    """Atomic no-replace only; never fall back to replacing an empty directory."""
    try:
        if os.name == "nt":
            os.rename(source, destination)  # Windows rename refuses an existing destination.
            return
        library = ctypes.CDLL(None, use_errno=True)
        if sys.platform.startswith("linux"):
            function = library.renameat2
            function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
            function.restype = ctypes.c_int
            result = function(-100, os.fsencode(source), -100, os.fsencode(destination), 1)
        elif sys.platform == "darwin":
            # Apple sys/stdio.h: RENAME_EXCL == 0x00000004.
            function = library.renamex_np
            function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
            function.restype = ctypes.c_int
            result = function(os.fsencode(source), os.fsencode(destination), 4)
        else:
            _fail("DEPENDENCY_EXCLUSIVE_PUBLICATION_REQUIRED")
        if result != 0:
            _fail("DEPENDENCY_EXCLUSIVE_PUBLICATION_REQUIRED")
    except DependencyError:
        raise
    except Exception:
        _fail("DEPENDENCY_EXCLUSIVE_PUBLICATION_REQUIRED")


def _verify_installed(plan, kind, target, stage, runner):
    environment = _environment(plan.tools, stage)
    if kind == "python":
        python = target / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        _file(python, target, 268435456)
        config = dev_environment.bounded_read_text(target / "pyvenv.cfg", 16384).lower()
        if re.search(r"(?m)^include-system-site-packages\s*=\s*false\s*$", config) is None:
            _fail("DEPENDENCY_VENV_ISOLATION_REQUIRED")
        _invoke(runner, (str(python), "-I", "-B", "-m", "pip", "--isolated", "check"), stage, environment, "DEPENDENCY_PIP_CHECK_FAILED", 60)
        script = (
            "import importlib.metadata as m,importlib.util,json,sys;"
            "print(json.dumps({'prefix':sys.prefix,'version':list(sys.version_info[:3]),"
            "'packages':{n:m.version(n) for n in json.loads(sys.argv[1])},"
            "'required':all(importlib.util.find_spec(n) is not None for n in json.loads(sys.argv[2]))}))"
        )
        raw = _invoke(runner, (str(python), "-I", "-B", "-c", script, json.dumps(dict(plan.requirements)), json.dumps(_SPEC_NAMES)), stage, environment, "DEPENDENCY_PYTHON_VERIFICATION_FAILED", 30)
        value = json.loads(raw, object_pairs_hook=_object)
        if value != {"prefix": str(target), "version": list(plan.tool_versions["python"]), "packages": dict(plan.requirements), "required": True}:
            _fail("DEPENDENCY_PYTHON_VERIFICATION_FAILED")
        return {"python": list(plan.tool_versions["python"])}
    node, npm = plan.tools["node"][0], plan.tools["npm"][0]
    raw = _invoke(runner, (node, npm, "--userconfig=" + environment["NPM_CONFIG_USERCONFIG"], "--globalconfig=" + environment["NPM_CONFIG_GLOBALCONFIG"], "--version"), stage, environment, "DEPENDENCY_NPM_REQUIRED", 30).decode("ascii").strip()
    if re.fullmatch(r"\d+\.\d+\.\d+", raw) is None:
        _fail("DEPENDENCY_NPM_REQUIRED")
    script = (
        "const fs=require('node:fs'),p=require('node:path');const root=process.argv[1];"
        "const names=JSON.parse(process.argv[2]);const packages={};for(const name of names)"
        "packages[name]=JSON.parse(fs.readFileSync(p.join(root,name,'package.json'),'utf8')).version;"
        "process.stdout.write(JSON.stringify({version:process.versions.node,packages}));"
    )
    for name in plan.node_packages:
        _file(target / name / "package.json", target)
    checked = json.loads(_invoke(runner, (node, "-e", script, str(target), json.dumps(list(plan.node_packages))), stage, environment, "DEPENDENCY_FRONTEND_VERIFICATION_FAILED", 30), object_pairs_hook=_object)
    if checked != {"version": ".".join(map(str, plan.tool_versions["node"])), "packages": dict(plan.node_packages)}:
        _fail("DEPENDENCY_FRONTEND_VERIFICATION_FAILED")
    return {"node": list(plan.tool_versions["node"]), "npm": raw}


def prepare_dependencies(plan, *, authorize, runner=None):
    """Apply one caller-confirmed plan. Never install during inspection or tests."""
    prepared, skipped, retained = [], [], False
    try:
        if type(plan) is not DependencyPlan or plan.blockers:
            _fail("DEPENDENCY_PLAN_BLOCKED")
        if authorize(plan) is not True:
            _fail("DEPENDENCY_APPROVAL_REQUIRED")
        _revalidate(plan)
        current = inspect_dependencies(
            plan.repository, plan.worktree, manifest_hashes=plan.manifest_hashes,
            python_executable=plan.tools["python"][0], node_executable=plan.tools["node"][0], npm_cli=plan.tools["npm"][0],
            runner=runner, state_anchor=plan.state_anchor.canonical_path,
        )
        if current.fingerprint != plan.fingerprint:
            _fail("DEPENDENCY_PLAN_CHANGED")
        # One full digest keeps native Windows paths short without treating its
        # directory name as authority; full IDs remain in each protected stamp.
        state = _state_path(plan.state_anchor.canonical_path, plan.repository.repository_id, plan.worktree.worktree_id)
        retained = True
        dev_instance_storage.initialize_private_directory(state, anchor=plan.state_anchor.canonical_path)
        with _lock(state):
            pending = state / ".pending"
            if os.path.lexists(pending):
                _fail("DEPENDENCY_PREVIOUS_ATTEMPT_REVIEW_REQUIRED")
            dev_private.create_private_file(pending, _json({
                "version": 1, "repository_id": plan.repository.repository_id,
                "worktree_id": plan.worktree.worktree_id, "fingerprint": plan.fingerprint,
            }))
            pending_proof = _file(pending, state, 65536)
            stage = state / ("a-" + uuid.uuid4().hex[:16])
            _exclusive_directory(stage, state)
            for path in (stage / "home", stage / "tmp", stage / "cache"):
                dev_instance_storage.initialize_private_directory(path, anchor=plan.state_anchor.canonical_path)
            # npm rejects loading the same path twice as user/global config.
            # Distinct newly created empty files suppress both private sources.
            for name in ("npm-user.conf", "npm-global.conf"):
                dev_private.create_private_file(stage / name, b"")
            environment = _environment(plan.tools, stage)
            requirements = stage / "requirements.txt"
            contents = dev_environment.bounded_read_bytes(plan.worktree.root / "requirements.txt", 8388608)
            if hashlib.sha256(contents).hexdigest() != plan.manifest_hashes["requirements.txt"]:
                _fail("DEPENDENCY_MANIFEST_CHANGED")
            dev_private.create_private_file(requirements, contents)
            for kind, target in (("python", plan.worktree.root / ".venv"), ("frontend", plan.worktree.root / "frontend/node_modules")):
                _revalidate(plan)
                if plan.target_stamps[kind] is not None:
                    actual_stamp = _target({"repository_id": plan.repository.repository_id, "worktree_id": plan.worktree.worktree_id, "root": str(plan.worktree.root)}, kind, target, plan.tools, plan.manifest_hashes)
                    if actual_stamp != plan.target_stamps[kind]:
                        _fail("DEPENDENCY_PLAN_CHANGED")
                    versions = _verify_installed(plan, kind, target, stage, runner)
                    recorded = json.loads(dev_environment.bounded_read_bytes(target / _STAMP, 65536), object_pairs_hook=_object)
                    if recorded["versions"] != versions:
                        _fail("DEPENDENCY_TOOL_VERSION_CHANGED")
                    skipped.append(kind)
                    continue
                if os.path.lexists(target):
                    _fail("DEPENDENCY_EXISTING_ARTIFACT_REVIEW_REQUIRED")
                if kind == "python":
                    target_identity = _exclusive_directory(target, plan.worktree.root)
                    dev_private.create_private_file(target / ".sbom-workspace-dependency-attempt", _json({
                        "version": 1, "repository_id": plan.repository.repository_id,
                        "worktree_id": plan.worktree.worktree_id, "authority": False,
                    }))
                    _invoke(runner, (plan.tools["python"][0], "-I", "-S", "-B", "-m", "venv", "--copies", str(target)), stage, environment, "DEPENDENCY_VENV_PREPARATION_FAILED", 120)
                    if _directory(target) != target_identity:
                        _fail("DEPENDENCY_PATH_CHANGED")
                    python = target / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
                    python_proof = _file(python, target, 268435456)
                    _revalidate(plan)
                    if _file(requirements, stage)[-1] != plan.manifest_hashes["requirements.txt"]:
                        _fail("DEPENDENCY_MANIFEST_CHANGED")
                    _invoke(runner, (str(python), "-I", "-B", "-m", "pip", "--isolated", "--disable-pip-version-check", "--no-input", "--no-cache-dir", "install", "--only-binary=:all:", "--index-url=https://pypi.org/simple", "--requirement", str(requirements)), stage, environment, "DEPENDENCY_PYTHON_BINARY_INSTALL_FAILED", 600)
                    if _directory(target) != target_identity or _file(python, target, 268435456) != python_proof:
                        _fail("DEPENDENCY_PATH_CHANGED")
                else:
                    # Same-volume, env-free project copies prevent npm from
                    # reading source .npmrc/.env or racing mutable manifests.
                    npm_project = plan.worktree.root / "frontend" / (".sbom-dependencies-" + uuid.uuid4().hex)
                    _exclusive_directory(npm_project, plan.worktree.root)
                    for name in _MANIFESTS[1:]:
                        contents = dev_environment.bounded_read_bytes(plan.worktree.root / name, 8388608)
                        if hashlib.sha256(contents).hexdigest() != plan.manifest_hashes[name]:
                            _fail("DEPENDENCY_MANIFEST_CHANGED")
                        dev_private.create_private_file(npm_project / Path(name).name, contents)
                    _invoke(runner, (plan.tools["node"][0], plan.tools["npm"][0], "--userconfig=" + environment["NPM_CONFIG_USERCONFIG"], "--globalconfig=" + environment["NPM_CONFIG_GLOBALCONFIG"], "ci", "--prefix", str(npm_project), "--registry=https://registry.npmjs.org/", "--strict-ssl=true", "--ignore-scripts", "--no-audit", "--no-fund"), stage, environment, "DEPENDENCY_NPM_INSTALL_FAILED", 600)
                    for name in _MANIFESTS[1:]:
                        if _file(npm_project / Path(name).name, npm_project)[-1] != plan.manifest_hashes[name]:
                            _fail("DEPENDENCY_MANIFEST_CHANGED")
                    installed = npm_project / "node_modules"
                    installed_identity = _directory(installed)
                    _tree(installed)
                    _revalidate(plan)
                    _publish_directory(installed, target)
                    if _directory(target) != installed_identity:
                        _fail("DEPENDENCY_PATH_CHANGED")
                versions = _verify_installed(plan, kind, target, stage, runner)
                _revalidate(plan)
                value = {"version": 1, "kind": kind, "repository_id": plan.repository.repository_id,
                         "worktree_id": plan.worktree.worktree_id, "root": str(plan.worktree.root),
                         "identity": _directory(target), "manifests": {name: plan.manifest_hashes[name] for name in (_MANIFESTS[:1] if kind == "python" else _MANIFESTS[1:])},
                         "tools": {name: list(proof) for name, proof in plan.tools.items() if (name == "python") == (kind == "python")},
                         "versions": versions, "tree": _tree(target)}
                dev_private.create_private_file(target / _STAMP, _json(value))
                prepared.append(kind)
            if _file(pending, state, 65536) != pending_proof:
                _fail("DEPENDENCY_JOURNAL_UNVERIFIED")
            _publish_directory(pending, state / ("done-" + uuid.uuid4().hex[:16] + ".json"))
        return DependencyOutcome("DEPENDENCIES_PREPARED_COMPILER_NOT_VERIFIED" if prepared else "DEPENDENCIES_VERIFIED_COMPILER_NOT_VERIFIED", 0, tuple(prepared), tuple(skipped), retained)
    except (EOFError, KeyboardInterrupt):
        return DependencyOutcome("DEPENDENCY_PREPARATION_CANCELLED", 130, tuple(prepared), tuple(skipped), retained)
    except DependencyError as error:
        return DependencyOutcome(error.code, 1, tuple(prepared), tuple(skipped), retained)
    except dev_instance_storage.DirectoryInitializationError:
        return DependencyOutcome("DEPENDENCY_STATE_OR_TARGET_ACCESS_REVIEW_REQUIRED", 1, tuple(prepared), tuple(skipped), retained)
    except Exception:
        return DependencyOutcome("DEPENDENCY_PREPARATION_UNCONFIRMED", 1, tuple(prepared), tuple(skipped), retained)
