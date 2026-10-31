"""Bounded tests of reviewed pure development contracts, never DB authority.

The controller checkout and its prepared local interpreter are trusted user-level
programs, not a sandbox against malicious same-user code, site hooks or packages.
A stamp/hash proves consistency with that preparation, not independent review.
Only the fixed import closure below is copied to a fresh private directory;
target conftest, dotenv, pytest configuration and unrelated modules are excluded.
No existing temporary directory is reused, repaired or removed. The explicit
``workspace test`` command authorizes only these user-level files and its child.
Database/integration/migration testing needs a future independently validated
disposable-target adapter and separate approval, regardless of caller markers.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType

if __package__:
    from . import dev_environment, dev_instance_registry, dev_instance_storage, dev_private, dev_workspace
    from . import dev_workspace_dependencies as dependencies
else:
    import dev_environment
    import dev_instance_registry
    import dev_instance_storage
    import dev_private
    import dev_workspace
    import dev_workspace_dependencies as dependencies

UNIT_TESTS = (
    "tests/test_dev_instance_plan.py",
    "tests/test_dev_instance_namespaces.py",
    "tests/test_dev_workspace_provider.py",
)
_SOURCES = (
    "scripts/__init__.py", "scripts/dev_instance_plan.py", "scripts/dev_workspace_provider.py",
    "app/__init__.py", "app/dev_instance.py", "tests/__init__.py", *UNIT_TESTS,
)
_CONTROLLERS = tuple("scripts/" + name for name in dependencies._CONTROLLERS) + (
    "scripts/dev_workspace_tests.py",
)
_STAMP = ".sbom-workspace-dependencies.json"
_OUTPUT_LIMIT = 1048576  # Per pipe; output is never returned or printed.
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_HEAD = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_CODES = frozenset({
    "TEST_PLAN_INVALID", "TEST_WORKTREE_UNVERIFIED", "TEST_WORKTREE_SELECTION_REQUIRED",
    "TEST_SOURCE_REVIEW_REQUIRED", "TEST_SOURCE_CHANGED", "TEST_VENV_PREPARATION_REQUIRED",
    "TEST_VENV_UNVERIFIED", "TEST_VENV_ISOLATION_REQUIRED", "TEST_HOME_UNVERIFIED",
    "TEST_ROOT_ACCESS_REVIEW_REQUIRED",
    "TEST_PLAN_CHANGED", "TEST_SUITE_UNSUPPORTED", "DISPOSABLE_TARGET_AUTHORIZATION_REQUIRED",
    "TEST_TEMPORARY_FILES_RETAINED", "TEST_TIMEOUT", "TEST_OUTPUT_LIMIT",
    "TEST_CHILD_CLEANUP_UNCONFIRMED", "TEST_OUTPUT_UNCONFIRMED", "TEST_EXECUTION_UNVERIFIED",
    "TEST_UNIT_PASSED", "TEST_UNIT_FAILED", "TEST_EXECUTION_CANCELLED",
})
_DATABASE_SUITES = frozenset({"db", "database", "integration", "migration", "migrations", "all"})
_COUNT_NAMES = frozenset({"passed", "failed", "skipped", "xfailed", "xpassed", "errors", "warnings", "deselected"})
_SUMMARY = re.compile(
    r"(?:=+ )?([0-9]+ (?:passed|failed|skipped|xfailed|xpassed|errors?|warnings?|deselected)"
    r"(?:, [0-9]+ (?:passed|failed|skipped|xfailed|xpassed|errors?|warnings?|deselected))*)"
    r" in [0-9]+(?:\.[0-9]+)?s(?: =+)?\Z"
)
# -I imports pytest/stdlib from the prepared environment before adding copied
# sources. The fixed fixture avoids pytest's stale-temp deletion machinery.
_BOOTSTRAP = """import pathlib,sys,uuid
import pytest
source,temporary=sys.argv[1:3]
sys.path.insert(0,source)
class FreshOnly:
    @pytest.fixture
    def tmp_path(self):
        path=pathlib.Path(temporary)/uuid.uuid4().hex
        path.mkdir(mode=0o700)
        return path
raise SystemExit(pytest.main(sys.argv[3:],plugins=[FreshOnly()]))
"""


class TestPlanningError(ValueError):
    __test__ = False

    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else "TEST_PLAN_INVALID"
        super().__init__(self.code)


def _fail(code):
    raise TestPlanningError(code) from None


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _identity(value):
    return [str(value.canonical_path), value.device, value.inode]


@dataclass(frozen=True)
class TestPlan:
    __test__ = False
    repository_id: str | None
    worktree_id: str | None
    commit: str | None
    suite: str
    root: Path = field(repr=False)
    root_identity: dev_workspace.FilesystemIdentity | None = field(repr=False)
    home_identity: dev_workspace.FilesystemIdentity | None = field(repr=False)
    sources: tuple[tuple[str, tuple], ...] = field(repr=False)
    controllers: tuple[tuple, ...] = field(repr=False)
    venv_proofs: tuple[tuple, ...] = field(repr=False)
    blockers: tuple[str, ...]
    fingerprint: str

    def to_dict(self):
        return {
            "version": 1, "repository_id": self.repository_id, "worktree_id": self.worktree_id,
            "commit": self.commit, "suite": self.suite, "scope": "pure-development-contracts",
            "tests": list(UNIT_TESTS) if self.suite == "unit" else [],
            "source_hashes": {name: proof[-1] for name, proof in self.sources},
            "blockers": list(self.blockers), "fingerprint": self.fingerprint,
            "temporary_file_policy": "fresh-private-retained", "database_authorized": False,
            "application_readiness_verified": False,
        }


@dataclass(frozen=True)
class TestOutcome:
    __test__ = False
    code: str
    exit_code: int
    counts: tuple[tuple[str, int], ...] = ()
    child_exit_code: int | None = None
    cleanup_verified: bool | None = None
    temporary_files_retained: bool = False
    retained_directory: Path | None = field(default=None, repr=False)
    probe_pid: int | None = None

    def __post_init__(self):
        valid = (type(self.code) is str and self.code in _CODES
                 and type(self.exit_code) is int and self.exit_code in {0, 1, 130}
                 and type(self.counts) is tuple and len(self.counts) <= len(_COUNT_NAMES))
        if valid:
            valid = all(type(item) is tuple and len(item) == 2 and type(item[0]) is str
                        and item[0] in _COUNT_NAMES and type(item[1]) is int and 0 <= item[1] <= 1000000
                        for item in self.counts)
            valid = valid and len({item[0] for item in self.counts}) == len(self.counts)
        if not valid:
            object.__setattr__(self, "code", "TEST_EXECUTION_UNVERIFIED")
            object.__setattr__(self, "exit_code", 1)
            object.__setattr__(self, "counts", ())
        if type(self.child_exit_code) is not int or not -0xFFFFFFFF <= self.child_exit_code <= 0xFFFFFFFF:
            object.__setattr__(self, "child_exit_code", None)
        if type(self.probe_pid) is not int or not 0 < self.probe_pid <= 0xFFFFFFFF:
            object.__setattr__(self, "probe_pid", None)
        if type(self.cleanup_verified) is not bool:
            object.__setattr__(self, "cleanup_verified", None)
        if type(self.temporary_files_retained) is not bool:
            object.__setattr__(self, "temporary_files_retained", False)

    def to_dict(self):
        return {
            "version": 1, "code": self.code, "exit_code": self.exit_code,
            "counts": dict(self.counts), "child_exit_code": self.child_exit_code,
            "cleanup_verified": self.cleanup_verified,
            "cleanup_scope": "original-test-child", "descendant_ownership_verified": False,
            "temporary_files_retained": self.temporary_files_retained, "probe_pid": self.probe_pid,
            "database_authorized": False, "application_readiness_verified": False,
        }


def _proof(path, root, limit=8388608):
    return tuple(dependencies._file(path, root, limit))


def _sources(root):
    controller = Path(__file__).resolve(strict=True).parent.parent
    proofs = []
    try:
        for name in _SOURCES:
            expected = _proof(controller / name, controller)
            observed = _proof(root / name, root)
            if expected[-1] != observed[-1]:
                _fail("TEST_SOURCE_REVIEW_REQUIRED")
            proofs.append((name, observed))
        controls = tuple(_proof(controller / name, controller) for name in (*_CONTROLLERS, *_SOURCES))
    except Exception:
        _fail("TEST_SOURCE_REVIEW_REQUIRED")
    return tuple(proofs), controls


def _venv(root, repository_id, worktree_id):
    target = root / ".venv"
    stamp = target / _STAMP
    if not os.path.lexists(stamp):
        _fail("TEST_VENV_PREPARATION_REQUIRED")
    try:
        dev_instance_registry._private(stamp)
        raw = dev_environment.bounded_read_bytes(stamp, 65536)
        value = json.loads(raw, object_pairs_hook=dependencies._object)
        tools = value["tools"]
        versions = value["versions"]
        if (type(tools) is not dict or set(tools) != {"python"}
                or type(tools["python"]) is not list or len(tools["python"]) != 7
                or type(versions) is not dict or set(versions) != {"python"}
                or type(versions["python"]) is not list or len(versions["python"]) != 3
                or any(type(item) is not int or item < 0 for item in versions["python"])
                or versions["python"] < [3, 11, 0]):
            _fail("TEST_VENV_UNVERIFIED")
        requirements = _proof(root / "requirements.txt", root)
        context = {"repository_id": repository_id, "worktree_id": worktree_id, "root": str(root)}
        digest = dependencies._target(context, "python", target, tools, {"requirements.txt": requirements[-1]})
        if digest != hashlib.sha256(raw).hexdigest():
            _fail("TEST_VENV_UNVERIFIED")
        executable = target / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        python = _proof(executable, target, 268435456)
        config = _proof(target / "pyvenv.cfg", target, 16384)
        raw_config = dev_environment.bounded_read_bytes(target / "pyvenv.cfg", 16384)
        if hashlib.sha256(raw_config).hexdigest() != config[-1]:
            _fail("TEST_VENV_UNVERIFIED")
        text = raw_config.decode("utf-8-sig").lower()
        flags = re.findall(r"(?m)^include-system-site-packages\s*=\s*(\S+)\s*$", text)
        if flags != ["false"]:
            _fail("TEST_VENV_ISOLATION_REQUIRED")
        return (python, config, _proof(stamp, target, 65536), requirements)
    except TestPlanningError:
        raise
    except Exception:
        _fail("TEST_VENV_UNVERIFIED")


def _binding(plan):
    return {
        "repository_id": plan.repository_id, "worktree_id": plan.worktree_id, "commit": plan.commit,
        "suite": plan.suite, "root": str(plan.root),
        "root_identity": _identity(plan.root_identity) if plan.root_identity else None,
        "home_identity": _identity(plan.home_identity) if plan.home_identity else None,
        "sources": plan.sources, "controllers": plan.controllers, "venv_proofs": plan.venv_proofs,
        "blockers": plan.blockers,
    }


def plan_tests(root, *, worktree_id=None, suite="unit") -> TestPlan:
    """Read-only local observations; never installs, writes, imports app or tests."""
    repository_id = selected_id = commit = root_identity = home = None
    sources = controllers = venv = ()
    blockers = ()
    safe_suite = suite if type(suite) is str and suite in {"unit", *_DATABASE_SUITES} else "unsupported"
    # A caller cannot use a suite or snapshot marker as disposable DB authority.
    if safe_suite != "unit":
        blockers = ("TEST_SUITE_UNSUPPORTED" if safe_suite == "unsupported"
                    else "DISPOSABLE_TARGET_AUTHORIZATION_REQUIRED",)
        canonical = Path(".")
    else:
        try:
            snapshot = dev_workspace.discover_workspaces(root)
            selected = [item for item in snapshot.worktrees if (
                item.worktree_id == worktree_id if worktree_id is not None else item.root == snapshot.root
            )]
            if len(selected) != 1:
                _fail("TEST_WORKTREE_SELECTION_REQUIRED")
            selected = selected[0]
            if (snapshot.status != "PASS" or selected.status != "PASS" or selected.bare
                    or selected.locked or selected.prunable or selected.identity is None
                    or type(snapshot.repository_id) is not str or not _HASH.fullmatch(snapshot.repository_id)
                    or type(selected.worktree_id) is not str or not _HASH.fullmatch(selected.worktree_id)
                    or type(selected.head) is not str or not _HEAD.fullmatch(selected.head)):
                _fail("TEST_WORKTREE_UNVERIFIED")
            canonical, root_identity = selected.identity.canonical_path, selected.identity
            repository_id, selected_id, commit = snapshot.repository_id, selected.worktree_id, selected.head
            if dev_workspace._identity(canonical) != root_identity:
                _fail("TEST_WORKTREE_UNVERIFIED")
            try:
                dependencies._directory(canonical)
            except dev_instance_storage.DirectoryInitializationError:
                _fail("TEST_ROOT_ACCESS_REVIEW_REQUIRED")
            sources, controllers = _sources(canonical)
            venv = _venv(canonical, repository_id, selected_id)
            try:
                anchor = Path.home()
                dependencies._directory(anchor)
                home = dev_workspace._identity(anchor)
            except Exception:
                _fail("TEST_HOME_UNVERIFIED")
        except TestPlanningError as error:
            blockers = (error.code,)
        except Exception:
            blockers = ("TEST_WORKTREE_UNVERIFIED",)
        canonical = root_identity.canonical_path if root_identity else Path(".")
    plan = TestPlan(repository_id, selected_id, commit, safe_suite, canonical, root_identity,
                    home, sources, controllers, venv, blockers, "")
    return TestPlan(**{**plan.__dict__, "fingerprint": hashlib.sha256(_json(_binding(plan))).hexdigest()})


def _refresh(plan):
    if type(plan) is not TestPlan or plan.blockers or plan.suite != "unit":
        _fail("TEST_PLAN_INVALID")
    current = plan_tests(plan.root, worktree_id=plan.worktree_id, suite="unit")
    if (current.blockers or current.fingerprint != plan.fingerprint or _binding(current) != _binding(plan)):
        _fail("TEST_PLAN_CHANGED")


def _mkdir(path, anchor):
    dependencies._exclusive_directory(path, anchor)
    dev_instance_storage._verify(path, private=True)


def _stage(plan, stage):
    anchor = plan.home_identity.canonical_path
    if dev_workspace._identity(anchor) != plan.home_identity:
        _fail("TEST_HOME_UNVERIFIED")
    _mkdir(stage, anchor)  # Exclusive creation: even an existing empty UUID is refused.
    for name in ("source", "home", "tmp", "cache", "source/scripts", "source/app", "source/tests"):
        _mkdir(stage / name, stage)
    for name, proof in plan.sources:
        raw = dev_environment.bounded_read_bytes(plan.root / name, 8388608)
        if hashlib.sha256(raw).hexdigest() != proof[-1] or _proof(plan.root / name, plan.root) != proof:
            _fail("TEST_SOURCE_CHANGED")
        path = stage / "source" / name
        dev_private.validate_parent(path, stage)
        dev_private.create_private_file(path, raw)
        if _proof(path, stage)[-1] != proof[-1]:
            _fail("TEST_SOURCE_CHANGED")
    return stage


def _environment(plan, stage):
    values = {key.upper(): value for key, value in os.environ.items()
              if key.upper() in {"SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"}}
    values.update(
        PATH=str(Path(plan.venv_proofs[0][0]).parent), HOME=str(stage / "home"), USERPROFILE=str(stage / "home"),
        APPDATA=str(stage / "home"), LOCALAPPDATA=str(stage / "home"), XDG_CACHE_HOME=str(stage / "cache"),
        TEMP=str(stage / "tmp"), TMP=str(stage / "tmp"), TMPDIR=str(stage / "tmp"),
        PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1", PYTHONSAFEPATH="1",
        PYTHON_DOTENV_DISABLED="1", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTEST_ADDOPTS="",
        DATABASE_URL="sqlite:///:memory:", TEST_DATABASE_URL="sqlite:///:memory:",
        TEST_POSTGRES_DATABASE_URL="sqlite:///:memory:", NATIVE_PLATFORM_BOOTSTRAP_ENABLED="false",
    )
    return MappingProxyType(values)


def _command(plan, stage):
    source = stage / "source"
    return (
        plan.venv_proofs[0][0], "-I", "-B", "-c", _BOOTSTRAP, str(source), str(stage / "tmp"),
        "-c", os.devnull, "--rootdir", str(source), "--noconftest", "-p", "no:cacheprovider",
        "-p", "no:tmpdir", "--import-mode=importlib", "--color=no", "--tb=no", "-q",
        *(str(source / name) for name in UNIT_TESTS),
    )


def _execute(command, *, cwd, environment, timeout):
    """Stop only the original Popen child; never enumerate, signal a group or PID."""
    process, threads, streams = None, [], []
    output, errors = bytearray(), bytearray()
    exceeded, broken = threading.Event(), threading.Event()
    reason, cleanup, pid = None, None, None

    def read(stream, target):
        try:
            while chunk := stream.read(65536):
                remaining = _OUTPUT_LIMIT - len(target)
                target.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    exceeded.set()
                    return
        except Exception:
            broken.set()

    try:
        options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
        process = subprocess.Popen(command, cwd=cwd, env=dict(environment), shell=False, close_fds=True,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   bufsize=0, **options)
        pid = process.pid if type(process.pid) is int and process.pid > 0 else None
        streams = [process.stdout, process.stderr]
        for stream, target in ((process.stdout, output), (process.stderr, errors)):
            thread = threading.Thread(target=read, args=(stream, target), daemon=True)
            thread.start()
            threads.append(thread)
        deadline = time.monotonic() + timeout
        while process.poll() is None:
            if exceeded.is_set() or broken.is_set() or time.monotonic() >= deadline:
                reason = "TEST_OUTPUT_LIMIT" if exceeded.is_set() else (
                    "TEST_OUTPUT_UNCONFIRMED" if broken.is_set() else "TEST_TIMEOUT")
                process.kill()
                break
            time.sleep(0.01)
        process.wait(timeout=2)
        cleanup = True
        for thread in threads:
            thread.join(timeout=2)
        if any(thread.is_alive() for thread in threads) or broken.is_set():
            reason = reason or "TEST_OUTPUT_UNCONFIRMED"
        if exceeded.is_set():
            reason = reason or "TEST_OUTPUT_LIMIT"
    except (KeyboardInterrupt, EOFError):
        reason = "TEST_EXECUTION_CANCELLED"
    except Exception:
        reason = reason or "TEST_EXECUTION_UNVERIFIED"
    finally:
        if process is not None:
            try:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=2)
                cleanup = True
            except (Exception, KeyboardInterrupt, EOFError):
                # A second interrupt is not evidence of exit. Return the known
                # original child identity and uncertainty, without PID/tree retries.
                cleanup = False
                reason = "TEST_CHILD_CLEANUP_UNCONFIRMED"
        # Closing a pipe while another thread blocks in read is not portable.
        # Daemon readers remain bounded; inherited handles never justify a tree kill.
        if not any(thread.is_alive() for thread in threads):
            for stream in streams:
                try:
                    stream.close()
                except (Exception, KeyboardInterrupt, EOFError):
                    reason = reason or "TEST_OUTPUT_UNCONFIRMED"
    code = process.returncode if process is not None and type(process.returncode) is int else None
    return bytes(output), code, reason, cleanup, pid


def _counts(raw, exit_code):
    if exit_code not in {0, 1}:
        _fail("TEST_EXECUTION_UNVERIFIED")
    summaries = []
    for line in raw.decode("ascii", errors="replace").splitlines():
        match = _SUMMARY.fullmatch(line.strip())
        if match:
            summaries.append(match.group(1))
    if len(summaries) != 1:
        _fail("TEST_EXECUTION_UNVERIFIED")
    counts = {}
    for item in summaries[0].split(", "):
        amount, name = item.split(" ")
        name = {"warning": "warnings", "error": "errors"}.get(name, name)
        value = int(amount)
        if name not in _COUNT_NAMES or name in counts or value > 1000000:
            _fail("TEST_EXECUTION_UNVERIFIED")
        counts[name] = value
    executed = sum(value for name, value in counts.items() if name not in {"warnings", "deselected"})
    failed = counts.get("failed", 0) + counts.get("errors", 0)
    if not executed or executed > 1000000 or (exit_code == 0 and failed) or (exit_code == 1 and not failed):
        _fail("TEST_EXECUTION_UNVERIFIED")
    return tuple(sorted(counts.items()))


def run_tests(plan, *, timeout=120) -> TestOutcome:
    """Explicit user-level fixed-suite execution; never accepts extra args/plugins."""
    stage = child_exit = cleanup = pid = None
    try:
        if (type(plan) is TestPlan and type(plan.blockers) is tuple and plan.blockers
                and all(type(code) is str and code in _CODES for code in plan.blockers)):
            return TestOutcome(plan.blockers[0], 1)
        if type(timeout) not in {int, float} or not 1 <= timeout <= 300:
            _fail("TEST_PLAN_INVALID")
        _refresh(plan)
        stage = plan.home_identity.canonical_path / (".sbom-unit-" + uuid.uuid4().hex)
        try:
            _stage(plan, stage)
        except TestPlanningError:
            raise
        except Exception:
            _fail("TEST_TEMPORARY_FILES_RETAINED")
        _refresh(plan)
        raw, child_exit, reason, cleanup, pid = _execute(
            _command(plan, stage), cwd=stage / "source", environment=_environment(plan, stage), timeout=timeout,
        )
        if reason:
            return TestOutcome(reason, 130 if reason == "TEST_EXECUTION_CANCELLED" else 1,
                               child_exit_code=child_exit, cleanup_verified=cleanup,
                               temporary_files_retained=True, retained_directory=stage, probe_pid=pid)
        counts = _counts(raw, child_exit)
        return TestOutcome("TEST_UNIT_PASSED" if child_exit == 0 else "TEST_UNIT_FAILED", child_exit,
                           counts, child_exit, cleanup, True, stage, pid)
    except TestPlanningError as error:
        return TestOutcome(error.code, 1, child_exit_code=child_exit, cleanup_verified=cleanup,
                           temporary_files_retained=stage is not None, retained_directory=stage, probe_pid=pid)
    except (KeyboardInterrupt, EOFError):
        unconfirmed = pid is not None and cleanup is not True
        return TestOutcome("TEST_CHILD_CLEANUP_UNCONFIRMED" if unconfirmed else "TEST_EXECUTION_CANCELLED",
                           1 if unconfirmed else 130, child_exit_code=child_exit, cleanup_verified=cleanup,
                           temporary_files_retained=stage is not None, retained_directory=stage, probe_pid=pid)
    except Exception:
        return TestOutcome("TEST_EXECUTION_UNVERIFIED", 1, child_exit_code=child_exit, cleanup_verified=cleanup,
                           temporary_files_retained=stage is not None, retained_directory=stage, probe_pid=pid)


if __name__ == "__main__":
    raise SystemExit("Use the unified launcher workspace test command; database testing is gated.")
