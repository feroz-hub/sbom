"""Owned per-instance processes through the existing launcher's Runtime API.

The caller supplies the canonical Runtime and readonly readiness/preflight
adapters. No Runtime globals or Windows termination rules are changed here.
Public proposals are not ownership proofs. Only Runtime register/refresh/stop
and original Popen handles establish the process lifecycle. No app is imported.
"""

from __future__ import annotations

import errno
import json
import os
import queue
import re
import socket
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from uuid import uuid4

if __package__:
    from . import (
        dev_config,
        dev_environment,
        dev_instance_plan,
        dev_instance_registry,
        dev_instance_storage,
        dev_private,
        dev_workspace_dependencies,
        dev_workspace_lifecycle,
        dev_workspace_preview,
        dev_workspace_readiness,
    )
else:
    import dev_config
    import dev_environment
    import dev_instance_plan
    import dev_instance_registry
    import dev_instance_storage
    import dev_private
    import dev_workspace_dependencies
    import dev_workspace_lifecycle
    import dev_workspace_preview
    import dev_workspace_readiness

_LOGS = {
    "Celery worker": "celery-worker.log",
    "Celery reports worker": "celery-reports-worker.log",
    "Celery Beat": "celery-beat.log",
    "API": "api.log",
    "Frontend": "frontend.log",
}
_TRANSPORT = frozenset(
    {
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "PATH",
        "HOME",
        "USERPROFILE",
        "TMP",
        "TEMP",
        "TMPDIR",
        "APPDATA",
        "LOCALAPPDATA",
        "LANG",
    }
)
_PRELOADS = frozenset(
    {
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONINSPECT",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "CELERY_CONFIG_MODULE",
        "DJANGO_SETTINGS_MODULE",
        "UVICORN_APP",
        "UVICORN_ENV_FILE",
        "SSLKEYLOGFILE",
    }
)
_INTERPRETER_SIGNAL = b"SBOM_DEV_INTERPRETER_STARTED_V1\n"
_SIGNAL_FIELDS = frozenset(
    {"SBOM_DEV_INTERPRETER_SIGNAL", "SBOM_DEV_INTERPRETER_HELPER", "SBOM_DEV_INTERPRETER_HELPER_PROOF"}
)
# Running -c proves the framework launcher's interpreter exec has completed.
# The marker synchronizes only; canonical Runtime still establishes ownership.
# Execute verified helper bytes without caching a controller scripts package.
_BOOTSTRAP = """import hashlib,json,os,runpy,stat,sys,types,uuid
from pathlib import Path
resource=os.environ.get('SBOM_DEV_RESOURCE_ID','')
try:
    valid=str(uuid.UUID(resource))==resource and os.environ.get('APP_ENVIRONMENT')=='development' and os.environ.get('PYTHON_DOTENV_DISABLED')=='1'
except ValueError:
    valid=False
if not valid:
    sys.exit('INSTANCE_SETTINGS_SOURCE_REQUIRED')
signal=Path(os.environ['SBOM_DEV_INTERPRETER_SIGNAL'])
directory=Path(os.environ['SBOM_DEV_STATE_DIR'])
nonce=signal.name.removeprefix('interpreter-started-').removesuffix('.signal')
helper=Path(os.environ['SBOM_DEV_INTERPRETER_HELPER'])
expected=json.loads(os.environ['SBOM_DEV_INTERPRETER_HELPER_PROOF'])
if not (signal.is_absolute() and signal.parent==directory and directory.name=='.dev-logs' and directory.parent.name==resource and len(nonce)==32 and all(c in '0123456789abcdef' for c in nonce) and signal.name=='interpreter-started-'+nonce+'.signal' and helper.is_absolute() and helper.name=='dev_private.py'):
    sys.exit('INSTANCE_INTERPRETER_HANDSHAKE_UNVERIFIED: PATH_BINDING')
def stamp(info):
    return [info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns]
before=helper.lstat()
if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or getattr(before,'st_file_attributes',0)&1024 or stamp(before)!=expected[:5]:
    sys.exit('INSTANCE_INTERPRETER_HANDSHAKE_UNVERIFIED: HELPER_IDENTITY')
fd=os.open(helper,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
with os.fdopen(fd,'rb') as stream:
    opened=os.fstat(stream.fileno())
    raw=stream.read(1048577)
    # Windows path/handle creation timestamps differ; identity + size/mtime
    # bind the open handle, while full path stamps and SHA bind its contents.
    if stamp(opened)[:4]!=stamp(before)[:4] or opened.st_nlink!=1:
        sys.exit('INSTANCE_INTERPRETER_HANDSHAKE_UNVERIFIED: HELPER_OPEN_IDENTITY')
if len(raw)>1048576 or stamp(helper.lstat())!=stamp(before) or hashlib.sha256(raw).hexdigest()!=expected[-1]:
    sys.exit('INSTANCE_INTERPRETER_HANDSHAKE_UNVERIFIED: HELPER_CONTENT')
private=types.ModuleType('_sbom_private_sync_'+nonce)
private.__file__=str(helper)
exec(compile(raw,str(helper),'exec'),private.__dict__)
private.validate_parent(signal,directory)
private.create_private_file(signal,b'SBOM_DEV_INTERPRETER_STARTED_V1\\n')
source,module=sys.argv[1:3]
sys.path.insert(0,source)
sys.argv=[module,*sys.argv[3:]]
runpy.run_module(module,run_name='__main__')
"""
_ERRORS = frozenset(
    {
        "INSTANCE_ACTIVE_RUNTIME_REQUIRED",
        "INSTANCE_CLEANUP_UNCONFIRMED",
        "INSTANCE_COMMAND_OVERRIDE_REFUSED",
        "INSTANCE_COMPONENT_LAUNCH_INVALID",
        "INSTANCE_COMPONENT_READINESS_INCOMPLETE",
        "INSTANCE_EXECUTABLE_CHANGED",
        "INSTANCE_EXECUTABLE_UNVERIFIED",
        "INSTANCE_FRONTEND_CONFIGURATION_MISMATCH",
        "INSTANCE_FRONTEND_FACTORY_REQUIRED",
        "INSTANCE_FRONTEND_GUARD_REQUIRED",
        "INSTANCE_FRONTEND_PORT_MISMATCH",
        "INSTANCE_LAUNCHER_OWNERSHIP_UNVERIFIED",
        "INSTANCE_LIFECYCLE_PREPARATION_REQUIRED",
        "INSTANCE_LOG_IDENTITY_CHANGED",
        "INSTANCE_PREFLIGHT_VERIFICATION_REQUIRED",
        "INSTANCE_PREVIEW_LAUNCH_REQUIRED",
        "INSTANCE_PRIVATE_RUNTIME_REQUIRED",
        "INSTANCE_PROCESS_IDENTITY_UNVERIFIED",
        "INSTANCE_PROCESS_REGISTRATION_FAILED",
        "INSTANCE_INTERPRETER_EXITED",
        "INSTANCE_INTERPRETER_TIMEOUT",
        "INSTANCE_INTERPRETER_HANDSHAKE_UNVERIFIED",
        "INSTANCE_READINESS_PROBE_FAILED",
        "INSTANCE_READINESS_TIMEOUT",
        "INSTANCE_RUNTIME_ADAPTER_INVALID",
        "INSTANCE_RUNTIME_DIRECTORY_CHANGED",
        "INSTANCE_RUNTIME_DOTENV_REFUSED",
        "INSTANCE_RUNTIME_RECORD_UNVERIFIED",
        "INSTANCE_SETTINGS_SOURCE_REQUIRED",
        "INSTANCE_SOURCE_RUNTIME_OVERLAP",
        "INSTANCE_START_CONTRACT_REQUIRED",
        "INSTANCE_STOP_BOUND_REQUIRED",
        "ENVIRONMENT_NAME_CONFLICT",
        "FRONTEND_SETTING_NAME_REVIEW_REQUIRED",
        "INVALID_PUBLIC_URL",
        "TLS_VERIFICATION_REQUIRED",
        "NODE_OPTIONS_REVIEW_REQUIRED",
        "DEV_INSTANCE_RESOURCE_ID_INVALID",
    }
)


class RuntimeAdapterError(ValueError):
    def __init__(self, code, *, winerror=None, probe_pid=None, inspection=None):
        self.code = (
            code
            if type(code) is str and code in _ERRORS | dev_workspace_readiness._CODES
            else "INSTANCE_RUNTIME_ADAPTER_INVALID"
        )
        self.winerror = winerror if type(winerror) is int and 0 <= winerror <= 0xFFFFFFFF else None
        self.probe_pid = probe_pid if type(probe_pid) is int and 0 < probe_pid <= 0xFFFFFFFF else None
        self.inspection = inspection if type(inspection) is RuntimeInspection else None
        super().__init__(self.code)


def _fail(code):
    raise RuntimeAdapterError(code) from None


def minimal_transport(environment=None):
    """Allow OS transport only; never inherit ambient application configuration."""
    source = os.environ if environment is None else environment
    return MappingProxyType({key.upper(): value for key, value in source.items() if key.upper() in _TRANSPORT})


@dataclass(frozen=True, slots=True)
class RuntimeInspection:
    stage: str
    category: str
    winerror: int | None = None

    def __post_init__(self):
        if (
            type(self.stage) is not str
            or self.stage
            not in {"runtime-directory", "runtime-state", "runtime-lock", "runtime-stop", "interpreter-signal"}
            or type(self.category) is not str
            or self.category
            not in {
                "OWNER_MISMATCH",
                "UNTRUSTED_GRANT",
                "OBJECT_UNVERIFIED",
                "OWNER_OR_MODE_MISMATCH",
                "OVERSIZED",
                "ACL_UNVERIFIED",
            }
            or self.winerror is not None
            and (type(self.winerror) is not int or not 0 <= self.winerror <= 0xFFFFFFFF)
        ):
            _fail("INSTANCE_RUNTIME_ADAPTER_INVALID")

    def to_dict(self):
        return {"stage": self.stage, "category": self.category, "winerror": self.winerror}


def _private_failure(stage, error=None, *, category=None, code="INSTANCE_RUNTIME_RECORD_UNVERIFIED"):
    allowed = {"OWNER_MISMATCH", "UNTRUSTED_GRANT", "OBJECT_UNVERIFIED", "OWNER_OR_MODE_MISMATCH", "OVERSIZED"}
    selected = category or getattr(error, "category", None)
    if type(selected) is not str or selected not in allowed:
        selected = (
            "OWNER_OR_MODE_MISMATCH"
            if getattr(error, "code", None) == "REGISTRY_ACCESS_UNVERIFIED"
            else "ACL_UNVERIFIED"
        )
    winerror = getattr(error, "winerror", None)
    winerror = winerror if type(winerror) is int and 0 <= winerror <= 0xFFFFFFFF else None
    raise RuntimeAdapterError(
        code, inspection=RuntimeInspection(stage, selected, winerror), winerror=winerror
    ) from None


def _private_parent(path, root):
    if not root.is_absolute() or root.resolve(strict=True) != root:
        _private_failure("runtime-directory")
    dev_private.validate_parent(path, root)
    current = root
    dev_instance_storage._verify(current, private=True)
    for part in path.parent.relative_to(root).parts:
        current /= part
        dev_instance_storage._verify(current, private=True)


def private_runtime_lock(path, *, root):
    """Create with an explicit user owner; never repair or replace an old lock."""
    path, root = Path(path), Path(root)
    try:
        if path != root / ".dev-runtime.lock":
            _private_failure("runtime-lock")
        _private_parent(path, root)
        if not os.path.lexists(path):
            try:
                dev_private.create_private_file(path, b"\0")
            except OSError as error:
                if error.errno != errno.EEXIST and getattr(error, "winerror", None) not in {80, 183}:
                    raise
        info = dev_instance_registry._private(path)
        if info.st_size > 1:
            _private_failure("runtime-lock", category="OVERSIZED")
        return info.st_dev, info.st_ino
    except RuntimeAdapterError:
        raise
    except Exception as error:
        _private_failure("runtime-lock", error)


def private_atomic_json(path, value, *, root):
    """Private state from creation, including elevated Windows default-owner tokens.

    Old targets must already satisfy the private policy. No ownership/ACL repair,
    unknown-state adoption or global token/umask changes are performed. A failed
    publication retains its uniquely named private staging artifact for review.
    """
    path, root = Path(path), Path(root)
    try:
        _private_parent(path, root)
        before = dev_instance_registry._stamp(dev_instance_registry._private(path)) if os.path.lexists(path) else None
        raw = (json.dumps(value, indent=2) + "\n").encode("utf-8")
        if len(raw) > 1048576:
            _private_failure("runtime-state", category="OVERSIZED")
        stage = path.parent / (".runtime-pending-" + uuid4().hex + ".json")
        dev_private.create_private_file(stage, raw)
        created = dev_instance_registry._stamp(dev_instance_registry._private(stage))
        for attempt in range(11):
            _private_parent(path, root)
            current = (
                dev_instance_registry._stamp(dev_instance_registry._private(path)) if os.path.lexists(path) else None
            )
            if current != before or dev_instance_registry._stamp(dev_instance_registry._private(stage)) != created:
                _private_failure("runtime-state")
            try:
                os.replace(stage, path)
                break
            except OSError as error:
                if sys.platform != "win32" or getattr(error, "winerror", None) not in {5, 32, 33} or attempt == 10:
                    raise
                time.sleep(min(0.01 * 2**attempt, 0.1))
        final = dev_instance_registry._private(path)
        if (final.st_dev, final.st_ino) != created[:2]:
            _private_failure("runtime-state")
    except RuntimeAdapterError:
        raise
    except Exception as error:
        _private_failure("runtime-state", error)


@dataclass(frozen=True, slots=True)
class RuntimeLocation:
    descriptor: dev_instance_plan.InstanceDescriptor
    root: Path = field(repr=False)
    anchor: Path = field(repr=False)
    identity: tuple = field(init=False, repr=False)

    def __post_init__(self):
        try:
            if type(self.descriptor) is not dev_instance_plan.InstanceDescriptor:
                raise ValueError()
            root, anchor = Path(self.root), Path(self.anchor)
            if (
                not root.is_absolute()
                or root.resolve(strict=True) != root
                or not anchor.is_absolute()
                or anchor.resolve(strict=True) != anchor
                or root.name != self.descriptor.instance_id
            ):
                raise ValueError()
            current, parts = dev_instance_storage._paths(root, anchor)
            dev_instance_storage._verify(current, private=False)
            for part in parts:
                current = current / part
                dev_instance_storage._verify(current, private=True)
            identity = dev_instance_storage._identity(dev_instance_storage._verify(root, private=True))
            object.__setattr__(self, "root", root)
            object.__setattr__(self, "anchor", anchor)
            object.__setattr__(self, "identity", identity)
        except Exception:
            _fail("INSTANCE_PRIVATE_RUNTIME_REQUIRED")


@dataclass(frozen=True, slots=True)
class ComponentLaunch:
    name: str
    argv: tuple[str, ...] = field(repr=False)
    cwd: Path = field(repr=False)
    environment: Mapping[str, str] = field(repr=False)
    port: int | None = None
    executable_proof: tuple = field(init=False, repr=False)

    def __post_init__(self):
        if (
            self.name not in _LOGS
            or type(self.argv) not in {tuple, list}
            or not self.argv
            or any(type(value) is not str or not value or "\0" in value or "://" in value for value in self.argv)
            or not Path(self.argv[0]).is_absolute()
            or not Path(self.cwd).is_absolute()
            or not isinstance(self.environment, Mapping)
            or any(
                type(key) is not str
                or re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", key) is None
                or type(value) is not str
                or "\0" in value
                for key, value in self.environment.items()
            )
            or any(key.upper() in _PRELOADS for key in self.environment)
            or self.port is not None
            and (type(self.port) is not int or not 1 <= self.port <= 65535)
        ):
            _fail("INSTANCE_COMPONENT_LAUNCH_INVALID")
        environment = dict(self.environment)
        if self.name == "Frontend":
            if (
                len(self.argv) < 5
                or self.argv[1] != "--require"
                or not Path(self.argv[2]).is_absolute()
                or self.argv[4] != "dev"
                or "--experimental-https" not in self.argv
                or any(
                    flag not in self.argv
                    for flag in ("--experimental-https-key", "--experimental-https-cert", "--experimental-https-ca")
                )
            ):
                _fail("INSTANCE_FRONTEND_GUARD_REQUIRED")
            suffix = "--require " + json.dumps(Path(self.argv[2]).as_posix())
            options = environment.get("NODE_OPTIONS", "").strip()
            if not options.endswith(suffix):
                _fail("INSTANCE_FRONTEND_GUARD_REQUIRED")
            environment["NODE_OPTIONS"] = options[: -len(suffix)].strip()
            metadata = {
                key: value
                for key, value in environment.items()
                if key
                in {
                    "SBOM_DEV_RESOURCE_ID",
                    "SBOM_DEV_INSTANCE",
                    "SBOM_DEV_STATE_DIR",
                    "SBOM_DEV_PROFILE",
                    "SBOM_DEV_FRONTEND_SOURCE",
                    "SBOM_DEV_FRONTEND_WORKSPACE",
                }
            }
            try:
                environment = dict(dev_config.component_environment(environment, "frontend"))
            except dev_config.ConfigurationError as error:
                _fail(error.code)
            environment.update(metadata)
            environment["NODE_OPTIONS"] = (environment.get("NODE_OPTIONS", "") + " " + suffix).strip()
        try:
            proof = tuple(dev_workspace_dependencies._file(Path(self.argv[0]), Path(self.argv[0]).parent, 268435456))
        except Exception:
            _fail("INSTANCE_EXECUTABLE_UNVERIFIED")
        object.__setattr__(self, "executable_proof", proof)
        object.__setattr__(self, "argv", tuple(self.argv))
        object.__setattr__(self, "cwd", Path(self.cwd))
        object.__setattr__(self, "environment", MappingProxyType(environment))


def preview_launch(location, launch):
    if type(location) is not RuntimeLocation or type(launch) is not dev_workspace_preview.VerifiedPreviewLaunch:
        _fail("INSTANCE_PREVIEW_LAUNCH_REQUIRED")
    try:
        if int(launch.argv[launch.argv.index("--port") + 1]) != location.descriptor.ports["frontend"]:
            raise ValueError()
    except (ValueError, IndexError):
        _fail("INSTANCE_FRONTEND_PORT_MISMATCH")
    return (
        ComponentLaunch("Frontend", launch.argv, launch.cwd, launch.environment, location.descriptor.ports["frontend"]),
    )


def isolated_launches(location, plan, *, python_executable, frontend=None, substitutions=None, transport=None):
    """Build the existing lifecycle's five roles, with an isolated Settings CWD."""
    if (
        type(location) is not RuntimeLocation
        or type(plan) is not dev_workspace_lifecycle.LifecyclePlan
        or plan.descriptor != location.descriptor
        or Path(plan.snapshot.state_root) != location.root
        or frontend is not None
        and type(frontend) is not dev_workspace_preview.VerifiedPreviewLaunch
        or any(value != "PREPARED" for value in plan.snapshot.prerequisites.values())
    ):
        _fail("INSTANCE_LIFECYCLE_PREPARATION_REQUIRED")
    source, python = Path(plan.snapshot.source_root), Path(python_executable)
    if source == location.root or source.is_relative_to(location.root) or location.root.is_relative_to(source):
        _fail("INSTANCE_SOURCE_RUNTIME_OVERLAP")
    replacements = {
        "beat_schedule_path": str(location.root / ".dev-logs/celerybeat-schedule"),
        "beat_pid_path": str(location.root / ".dev-logs/celerybeat-{runtime_token}.pid"),
        "runtime_node": "{runtime_node}",
    }
    if substitutions:
        _fail("INSTANCE_COMMAND_OVERRIDE_REFUSED")
    expected_frontend = plan.component_environment("Frontend")
    normalized_paths = {
        "AUTH_TRANSACTION_KEY_FILE",
        "HCL_IAM_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    }
    if frontend is not None and any(
        frontend.environment.get(key) != value
        for key, value in expected_frontend.items()
        if key not in _TRANSPORT | normalized_paths | {"NODE_OPTIONS"}
    ):
        _fail("INSTANCE_FRONTEND_CONFIGURATION_MISMATCH")
    result = []
    for command in plan.commands:
        if command.component == "Frontend":
            if frontend is not None:
                result.extend(preview_launch(location, frontend))
            continue
        args = command.arguments
        if args[:2] != ("-B", "-m") or args[2] not in {"celery", "uvicorn"}:
            _fail("INSTANCE_COMPONENT_LAUNCH_INVALID")
        arguments = tuple(
            value.replace("{beat_schedule_path}", replacements["beat_schedule_path"]).replace(
                "{beat_pid_path}", replacements["beat_pid_path"]
            )
            for value in args[3:]
        )
        argv = (str(python), "-I", "-B", "-c", _BOOTSTRAP, str(source), args[2], *arguments)
        env = {**minimal_transport(transport), **plan.component_environment(command.component)}
        result.append(
            ComponentLaunch(
                command.component,
                argv,
                location.root,
                env,
                location.descriptor.ports["api"] if command.component == "API" else None,
            )
        )
    return tuple(result)


@dataclass(frozen=True, slots=True)
class ServiceDiagnostic:
    component: str
    process_status: str
    pid: int | None
    log_path: str


@dataclass(frozen=True, slots=True)
class RuntimeOutcome:
    code: str
    exit_code: int
    services: tuple[ServiceDiagnostic, ...] = ()
    records_retained: bool = False
    ready: bool = False
    component: str | None = None
    winerror: int | None = None
    probe_pid: int | None = None
    inspection: RuntimeInspection | None = None

    def to_dict(self):
        result = {
            "code": self.code,
            "exit_code": self.exit_code,
            "records_retained": self.records_retained,
            "ready": self.ready,
            "component": self.component,
            "winerror": self.winerror if type(self.winerror) is int and 0 <= self.winerror <= 0xFFFFFFFF else None,
            "probe_pid": self.probe_pid if type(self.probe_pid) is int and 0 < self.probe_pid <= 0xFFFFFFFF else None,
            "services": [
                {
                    "component": item.component,
                    "process_status": item.process_status,
                    "pid": item.pid,
                    "log_path": item.log_path,
                }
                for item in self.services
            ],
        }
        if type(self.inspection) is RuntimeInspection:
            result["inspection"] = self.inspection.to_dict()
        return result


def _bounded(callback, timeout):
    result = queue.Queue(maxsize=1)

    def call():
        try:
            result.put((True, callback()))
        except (RuntimeAdapterError, dev_workspace_readiness.ReadinessError) as error:
            # Only our exact typed, enumerated diagnostics cross this boundary.
            # Arbitrary exceptions cannot supply categories, paths or credentials.
            if type(error) not in {RuntimeAdapterError, dev_workspace_readiness.ReadinessError}:
                error = RuntimeAdapterError("INSTANCE_READINESS_PROBE_FAILED")
            result.put(
                (
                    False,
                    RuntimeAdapterError(
                        error.code,
                        winerror=error.winerror,
                        probe_pid=error.probe_pid,
                        inspection=error.inspection if type(error) is RuntimeAdapterError else None,
                    ),
                )
            )
        except BaseException:
            result.put((False, RuntimeAdapterError("INSTANCE_READINESS_PROBE_FAILED")))

    threading.Thread(target=call, daemon=True, name="sbom-instance-readonly-probe").start()
    try:
        success, value = result.get(timeout=max(0.001, timeout))
    except queue.Empty:
        _fail("INSTANCE_READINESS_TIMEOUT")
    if not success:
        raise value from None
    return value


class WorkspaceRuntime:
    """Hold the canonical Runtime lock while supervising this instance only."""

    def __init__(
        self,
        location,
        *,
        runtime_factory,
        atomic_json,
        process_info,
        matches,
        popen=subprocess.Popen,
        clock=time.monotonic,
        sleep=time.sleep,
    ):
        if type(location) is not RuntimeLocation:
            _fail("INSTANCE_PRIVATE_RUNTIME_REQUIRED")
        self.location, self.factory, self.atomic_json = location, runtime_factory, atomic_json
        self.process_info, self.matches, self.popen = process_info, matches, popen
        self.clock, self.sleep, self.runtime = clock, sleep, None
        self.active_specs = ()
        self.current_component = None

    def _root(self):
        if (
            RuntimeLocation(self.location.descriptor, self.location.root, self.location.anchor).identity
            != self.location.identity
        ):
            _fail("INSTANCE_RUNTIME_DIRECTORY_CHANGED")
        if any(path.name.casefold().startswith(".env") for path in self.location.root.iterdir()):
            _fail("INSTANCE_RUNTIME_DOTENV_REFUSED")
        for name in (".dev-runtime.json", ".dev-runtime.lock", ".dev-runtime.stop"):
            path = self.location.root / name
            if os.path.lexists(path):
                try:
                    info = dev_instance_registry._private(path)
                except Exception as error:
                    _private_failure(
                        {
                            ".dev-runtime.json": "runtime-state",
                            ".dev-runtime.lock": "runtime-lock",
                            ".dev-runtime.stop": "runtime-stop",
                        }[name],
                        error,
                    )
                if info.st_size > 1048576:
                    _fail("INSTANCE_RUNTIME_RECORD_UNVERIFIED")

    def _new(self):
        self._root()
        runtime = self.factory(self.location.root)
        if (
            runtime.root != self.location.root
            or runtime.path != self.location.root / ".dev-runtime.json"
            or runtime.stop_path != self.location.root / ".dev-runtime.stop"
        ):
            _fail("INSTANCE_RUNTIME_ADAPTER_INVALID")
        configure = getattr(runtime, "configure_private_io", None)
        if callable(configure):

            def writer(path, value):
                return private_atomic_json(path, value, root=self.location.root)

            configure(
                state_writer=writer, lock_creator=lambda path: private_runtime_lock(path, root=self.location.root)
            )
            self.atomic_json = writer
        return runtime

    def _binding(self):
        descriptor = self.location.descriptor
        return {
            "repository_id": descriptor.repository_id,
            "worktree_id": descriptor.worktree_id,
            "instance_id": descriptor.instance_id,
            "root_identity": list(self.location.identity),
        }

    def _load(self, runtime):
        self._root()
        before = (
            dev_instance_registry._stamp(dev_instance_registry._private(runtime.path))
            if os.path.lexists(runtime.path)
            else None
        )
        try:
            state = runtime.load()
        except Exception:
            _fail("INSTANCE_RUNTIME_RECORD_UNVERIFIED")
        after = (
            dev_instance_registry._stamp(dev_instance_registry._private(runtime.path))
            if os.path.lexists(runtime.path)
            else None
        )
        if before != after:
            _fail("INSTANCE_RUNTIME_RECORD_UNVERIFIED")
        if state is not None and (
            state.get("workspace_context") != self._binding()
            or not isinstance(state.get("services"), dict)
            or set(state["services"]) - _LOGS.keys()
            or any(
                not isinstance(record, dict) or type(record.get("pid")) is not int or record["pid"] <= 0
                for record in state["services"].values()
            )
            or not isinstance(state.get("instance"), str)
        ):
            _fail("INSTANCE_RUNTIME_RECORD_UNVERIFIED")
        return state

    def _diagnostics(self, runtime):
        state = runtime.state or {}
        results = []
        for name, record in state.get("services", {}).items():
            if name not in _LOGS:
                continue
            try:
                status = runtime.service_status(record)
            except Exception:
                status = "UNKNOWN"
            if status not in {"RUNNING", "STOPPED", "PARTIAL", "UNOWNED", "UNKNOWN"}:
                status = "UNKNOWN"
            pid = record.get("pid") if type(record.get("pid")) is int else None
            results.append(ServiceDiagnostic(name, status, pid, str(self.location.root / ".dev-logs" / _LOGS[name])))
        return tuple(results)

    def _persist(self, runtime):
        self._root()
        self.atomic_json(runtime.path, runtime.state)

    def _cleanup(self, runtime):
        # Canonical Runtime performs fresh creation-time/executable checks,
        # cooperative Windows shutdown and unknown-tree record retention.
        return runtime.stop_services(lambda *_args: None)

    def release(self):
        if self.runtime is not None:
            self.runtime.release()
            self.runtime = None

    def _materialize(self, spec, runtime):
        env = dict(spec.environment)
        token = runtime.state["instance"]
        role = "reports" if spec.name == "Celery reports worker" else "default"
        profile = "isolated" if self.location.descriptor.mode == "isolated" else "preview"
        argv = tuple(
            value.replace("{runtime_token}", token).replace(
                "{runtime_node}", "sbom-" + profile + "-" + token[:12] + "-" + role + "@" + socket.gethostname()
            )
            for value in spec.argv
        )
        env.update(
            SBOM_DEV_RESOURCE_ID=self.location.descriptor.instance_id,
            SBOM_DEV_INSTANCE=token,
            SBOM_DEV_STATE_DIR=str(self.location.root / ".dev-logs"),
            SBOM_DEV_PROFILE="isolated" if self.location.descriptor.mode == "isolated" else "preview",
        )
        if spec.name != "Frontend":
            if (
                env.get("APP_ENVIRONMENT") != "development"
                or env.get("PYTHON_DOTENV_DISABLED") != "1"
                or env.get("AUTH_ENABLED") != "true"
                or env.get("DEV_DEFAULT_TENANT") != "false"
                or env.get("NATIVE_PLATFORM_BOOTSTRAP_ENABLED") != "false"
            ):
                _fail("INSTANCE_SETTINGS_SOURCE_REQUIRED")
            if spec.cwd != self.location.root or "-I" not in argv or "-B" not in argv or _BOOTSTRAP not in argv:
                _fail("INSTANCE_SETTINGS_SOURCE_REQUIRED")
            if spec.name in {"Celery worker", "Celery reports worker"}:
                env["SBOM_DEV_WORKER_ROLE"] = role
        return ComponentLaunch(spec.name, argv, spec.cwd, env, spec.port)

    def _interpreter_signal(self, spec, logs):
        if spec.name == "Frontend":
            return spec, None
        if any(name.upper() in _SIGNAL_FIELDS for name in spec.environment):
            _fail("INSTANCE_INTERPRETER_HANDSHAKE_UNVERIFIED")
        helper = Path(__file__).resolve(strict=True).with_name("dev_private.py")
        proof = tuple(dev_workspace_dependencies._file(helper, helper.parent, 1048576))
        path = logs / ("interpreter-started-" + uuid4().hex + ".signal")
        if os.path.lexists(path):
            _fail("INSTANCE_INTERPRETER_HANDSHAKE_UNVERIFIED")
        environment = {
            **spec.environment,
            "SBOM_DEV_INTERPRETER_SIGNAL": str(path),
            "SBOM_DEV_INTERPRETER_HELPER": str(helper),
            "SBOM_DEV_INTERPRETER_HELPER_PROOF": json.dumps(list(proof[1:])),
        }
        return ComponentLaunch(spec.name, spec.argv, spec.cwd, environment, spec.port), (path, helper, proof)

    def _wait_interpreter(self, child, signal, deadline):
        """Wait only for final interpreter execution, never trust marker identity.

        Private metadata is deliberately retained. Empty/prefix writes and
        Windows sharing violations can precede the helper's fsync/close. All
        other ambiguity fails closed. An independent elapsed-time bound also
        protects tests/callers supplying a nonadvancing scheduling clock.
        """
        path, helper, proof = signal
        budget = min(10.0, deadline - self.clock())
        if budget <= 0:
            _fail("INSTANCE_INTERPRETER_TIMEOUT")
        end = time.perf_counter() + budget
        while True:
            self.runtime.check_stop()
            if child.poll() is not None:
                _fail("INSTANCE_INTERPRETER_EXITED")
            publication_error = None
            try:
                if os.path.lexists(path):
                    dev_private.validate_parent(path, self.location.root)
                    before = dev_instance_registry._stamp(dev_instance_registry._private(path))
                    try:
                        raw = dev_environment.bounded_read_bytes(path, 128)
                    except PermissionError as error:
                        # The Windows CRT drops ERROR_SHARING_VIOLATION while
                        # the explicit-owner writer holds its exclusive handle.
                        # Retry only this read, after a successful private ACL
                        # check; persistent denial remains a reported failure.
                        if (
                            sys.platform != "win32"
                            or error.errno != errno.EACCES
                            or getattr(error, "winerror", None) is not None
                        ):
                            raise
                        publication_error = error
                    else:
                        after = dev_instance_registry._stamp(dev_instance_registry._private(path))
                        if before == after and raw == _INTERPRETER_SIGNAL:
                            if tuple(dev_workspace_dependencies._file(helper, helper.parent, 1048576)) != proof:
                                _fail("INSTANCE_INTERPRETER_HANDSHAKE_UNVERIFIED")
                            return
                        if not _INTERPRETER_SIGNAL.startswith(raw):
                            _fail("INSTANCE_INTERPRETER_HANDSHAKE_UNVERIFIED")
            except RuntimeAdapterError:
                raise
            except FileNotFoundError:
                pass
            except Exception as error:
                if getattr(error, "winerror", None) not in {32, 33}:
                    _private_failure("interpreter-signal", error, code="INSTANCE_INTERPRETER_HANDSHAKE_UNVERIFIED")
            remaining = min(end - time.perf_counter(), deadline - self.clock())
            if remaining <= 0:
                if publication_error is not None:
                    _private_failure(
                        "interpreter-signal", publication_error, code="INSTANCE_INTERPRETER_HANDSHAKE_UNVERIFIED"
                    )
                _fail("INSTANCE_INTERPRETER_TIMEOUT")
            self.sleep(min(0.02, remaining))

    @staticmethod
    def _registration_winerror(error):
        canonical = type(error).__name__ == "OwnershipError" and type(error).__module__ in {
            "scripts.dev",
            "dev",
            "__main__",
        }
        code = getattr(error, "winerror", None)
        return (
            code
            if (isinstance(error, OSError) or canonical) and type(code) is int and 0 <= code <= 0xFFFFFFFF
            else None
        )

    def start_process(self, spec, *, deadline=None):
        runtime = self.runtime
        if runtime is None or runtime.state is None:
            _fail("INSTANCE_ACTIVE_RUNTIME_REQUIRED")
        self.current_component = spec.name
        self._root()
        runtime.check_stop()
        original_proof = spec.executable_proof
        if (
            tuple(dev_workspace_dependencies._file(Path(spec.argv[0]), Path(spec.argv[0]).parent, 268435456))
            != original_proof
        ):
            _fail("INSTANCE_EXECUTABLE_CHANGED")
        spec = self._materialize(spec, runtime)
        dev_instance_storage._verify(spec.cwd, private=True)
        if (
            spec.executable_proof != original_proof
            or tuple(dev_workspace_dependencies._file(Path(spec.argv[0]), Path(spec.argv[0]).parent, 268435456))
            != original_proof
        ):
            _fail("INSTANCE_EXECUTABLE_CHANGED")
        logs = self.location.root / ".dev-logs"
        if not os.path.lexists(logs):
            dev_workspace_dependencies._exclusive_directory(logs, self.location.root)
        dev_instance_storage._verify(logs, private=True)
        spec, signal = self._interpreter_signal(spec, logs)
        path = logs / _LOGS[spec.name]
        if not os.path.lexists(path):
            dev_private.create_private_file(path, b"")
        before = dev_instance_registry._private(path)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
        try:
            current = os.fstat(fd)
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_nlink != 1
                or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
            ):
                _fail("INSTANCE_LOG_IDENTITY_CHANGED")
            options = (
                {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200)}
                if sys.platform == "win32"
                else {"start_new_session": True}
            )
            child = self.popen(
                spec.argv,
                cwd=spec.cwd,
                env=dict(spec.environment),
                stdin=subprocess.DEVNULL,
                stdout=fd,
                stderr=subprocess.STDOUT,
                close_fds=True,
                **options,
            )
        finally:
            os.close(fd)
        runtime.processes[child.pid] = child  # Required before Windows handle-based register.
        synchronization_error = None
        if signal is not None:
            try:
                self._wait_interpreter(child, signal, deadline if deadline is not None else self.clock() + 10.0)
            except BaseException as error:
                synchronization_error = error
        try:
            # Registration ALWAYS uses the original Popen, including when the
            # synchronization marker is forged, missing or the child exited.
            runtime.register(spec.name, child.pid, spec.port)
        except BaseException as error:
            winerror = self._registration_winerror(error)
            record = runtime.state["services"].setdefault(
                spec.name, {"pid": child.pid, "birth": None, "exe": None, "members": [], "tree_unverified": True}
            )
            try:
                self._persist(runtime)
            finally:
                if (not record.get("birth") or not record.get("exe")) and sys.platform == "win32":
                    # Original Popen only, never a guessed PID/group or descendants.
                    try:
                        if child.poll() is None:
                            child.terminate()
                        child.wait(timeout=2)
                    except Exception:
                        try:
                            child.kill()
                            child.wait(timeout=2)
                        except Exception:
                            pass  # Explicit unknown record remains for manual review.
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise
            if synchronization_error is not None:
                if type(synchronization_error) is RuntimeAdapterError:
                    raise RuntimeAdapterError(
                        synchronization_error.code,
                        inspection=synchronization_error.inspection,
                        winerror=synchronization_error.winerror
                        if synchronization_error.winerror is not None
                        else winerror,
                    ) from None
                raise synchronization_error
            raise RuntimeAdapterError("INSTANCE_PROCESS_REGISTRATION_FAILED", winerror=winerror) from None
        if synchronization_error is not None:
            raise synchronization_error
        return spec

    def _healthy(self, runtime):
        self._root()
        runtime.refresh()
        for record in runtime.state["services"].values():
            if not record.get("birth") or not record.get("exe") or runtime.service_status(record) != "RUNNING":
                _fail("INSTANCE_PROCESS_IDENTITY_UNVERIFIED")

    def _probe(self, spec, callback, deadline):
        # The trusted callback must verify the expected instance/target/service,
        # API + Native IAM readiness, queue/Beat health or hostname-verified TLS
        # as appropriate. A PID's mere existence or a caller READY flag is not
        # readiness. The callback receives no mutable Runtime object.
        self.current_component = spec.name
        while self.clock() < deadline:
            self._healthy(self.runtime)
            remaining = min(3.0, deadline - self.clock())
            if _bounded(lambda budget=remaining: callback(spec, budget), remaining) is True:
                self._healthy(self.runtime)
                return
            self.sleep(min(0.2, max(0.0, deadline - self.clock())))
        _fail("INSTANCE_READINESS_TIMEOUT")

    def start(self, specs, *, preflight, probes, timeout=90, frontend_factory=None):
        """Start owned roles. Deferred frontend verification runs after API/IAM.

        A frontend_factory receives immutable backend specs and its remaining
        timeout; it performs readonly verification/construction only, never
        preparation or spawning. Its result is a frontend launch specification.
        """
        runtime = None
        try:
            specs = tuple(specs)
            names = tuple(spec.name for spec in specs)
            full_names = tuple(_LOGS) if self.location.descriptor.mode == "isolated" else ("Frontend",)
            deferred = frontend_factory is not None
            expected_names = full_names[:-1] if deferred and self.location.descriptor.mode == "isolated" else full_names
            if (
                not specs
                or any(type(spec) is not ComponentLaunch for spec in specs)
                or names != expected_names
                or not callable(preflight)
                or deferred
                and (self.location.descriptor.mode != "isolated" or not callable(frontend_factory))
                or not isinstance(probes, Mapping)
                or set(probes) != set(full_names)
                or any(not callable(callback) for callback in probes.values())
                or not 0 < timeout <= 180
            ):
                _fail("INSTANCE_START_CONTRACT_REQUIRED")
            if self.runtime is not None:
                return RuntimeOutcome("INSTANCE_RUNTIME_ALREADY_ACTIVE", 1, self._diagnostics(self.runtime), True)
            deadline = self.clock() + timeout
            if _bounded(lambda: preflight(specs, min(5.0, timeout)), min(5.0, timeout)) is not True:
                _fail("INSTANCE_PREFLIGHT_VERIFICATION_REQUIRED")
            runtime = self._new()
            if not runtime.acquire():
                return RuntimeOutcome("INSTANCE_RUNTIME_BUSY", 1, records_retained=True)
            self.runtime = runtime
            state = self._load(runtime)
            if state:
                runtime.state = state
                if any(runtime.service_status(record) != "STOPPED" for record in state["services"].values()):
                    result = RuntimeOutcome(
                        "INSTANCE_EXISTING_RUNTIME_REQUIRES_STOP", 1, self._diagnostics(runtime), True
                    )
                    self.release()
                    return result
                if not self._cleanup(runtime):
                    _fail("INSTANCE_CLEANUP_UNCONFIRMED")
            runtime.begin(profile="workspace")
            runtime.state["workspace_context"] = self._binding()
            runtime.state["ready"] = False
            self._persist(runtime)
            active = []
            for spec in specs:
                active.append(self.start_process(spec, deadline=deadline))
                if spec.name in {"Celery worker", "Celery reports worker"}:
                    continue
                pending = active if spec.name == "Celery Beat" else (active[-1],)
                for current in pending:
                    self._probe(current, probes[current.name], deadline)
            if deferred:
                self.current_component = "Frontend"
                self._healthy(runtime)
                budget = min(30.0, deadline - self.clock())
                if budget <= 0:
                    _fail("INSTANCE_READINESS_TIMEOUT")
                frontend = _bounded(lambda: frontend_factory(tuple(active), budget), budget)
                self._healthy(runtime)
                if type(frontend) is ComponentLaunch and frontend.name == "Frontend":
                    frontend = dev_workspace_preview.VerifiedPreviewLaunch(
                        frontend.argv, frontend.cwd, frontend.environment, ()
                    )
                if type(frontend) is not dev_workspace_preview.VerifiedPreviewLaunch:
                    _fail("INSTANCE_FRONTEND_FACTORY_REQUIRED")
                spec = preview_launch(self.location, frontend)[0]
                active.append(self.start_process(spec, deadline=deadline))
                self._probe(active[-1], probes["Frontend"], deadline)
            self._healthy(runtime)
            if set(runtime.state["services"]) != set(full_names):
                _fail("INSTANCE_COMPONENT_READINESS_INCOMPLETE")
            runtime.state["ready"] = True
            self._persist(runtime)
            self.active_specs = tuple(active)
            return RuntimeOutcome("INSTANCE_READY", 0, self._diagnostics(runtime), True, True)
        except BaseException as error:
            complete = False
            diagnostics = self._diagnostics(runtime) if runtime is not None else ()
            if runtime is not None and self.runtime is runtime and runtime.state is not None:
                try:
                    complete = self._cleanup(runtime)
                except BaseException:
                    pass
            remaining_diagnostics = self._diagnostics(runtime) if runtime is not None else ()
            if complete:
                diagnostics = remaining_diagnostics or tuple(
                    ServiceDiagnostic(item.component, "STOPPED", item.pid, item.log_path) for item in diagnostics
                )
            else:
                diagnostics = remaining_diagnostics or diagnostics
            self.release()
            code = error.code if type(error) is RuntimeAdapterError else "INSTANCE_START_FAILED"
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                code = "INSTANCE_START_CANCELLED"
            return RuntimeOutcome(
                code,
                130 if code == "INSTANCE_START_CANCELLED" else 1,
                diagnostics,
                (runtime is not None and not complete) or os.path.lexists(self.location.root / ".dev-runtime.json"),
                component=self.current_component,
                winerror=error.winerror if type(error) is RuntimeAdapterError else None,
                probe_pid=error.probe_pid if type(error) is RuntimeAdapterError else None,
                inspection=getattr(error, "inspection", None) if type(error) is RuntimeAdapterError else None,
            )

    def stop(self, *, timeout=45):
        runtime, acquired = self.runtime, self.runtime is not None
        try:
            if not 0 < timeout <= 90:
                _fail("INSTANCE_STOP_BOUND_REQUIRED")
            runtime = runtime or self._new()
            deadline = self.clock() + timeout
            if not acquired:
                acquired = runtime.acquire()
            if not acquired:
                state = self._load(runtime)
                if (
                    not state
                    or type(state.get("launcher_pid")) is not int
                    or state["launcher_pid"] <= 0
                    or not self.matches(state.get("launcher", {}), self.process_info(state["launcher_pid"]))
                ):
                    _fail("INSTANCE_LAUNCHER_OWNERSHIP_UNVERIFIED")
                self._root()
                self.atomic_json(runtime.stop_path, {"instance": state["instance"]})
                while not acquired and self.clock() < deadline:
                    self.sleep(min(0.2, max(0.0, deadline - self.clock())))
                    acquired = runtime.acquire()
                if not acquired:
                    return RuntimeOutcome("INSTANCE_STOP_REQUEST_PENDING", 1, records_retained=True)
            runtime.state = self._load(runtime)
            if not runtime.state:
                return RuntimeOutcome("INSTANCE_STOPPED", 0)
            complete = self._cleanup(runtime)
            return RuntimeOutcome(
                "INSTANCE_STOPPED" if complete else "INSTANCE_OWNERSHIP_UNCERTAIN_RECORDS_RETAINED",
                0 if complete else 1,
                self._diagnostics(runtime),
                not complete,
            )
        except BaseException as error:
            code = error.code if type(error) is RuntimeAdapterError else "INSTANCE_STOP_UNCONFIRMED"
            return RuntimeOutcome(code, 1, self._diagnostics(runtime) if runtime else (), True)
        finally:
            if acquired and runtime is not None:
                runtime.release()
            self.runtime = None

    def restart(self, specs, *, preflight, probes, timeout=90, frontend_factory=None):
        stopped = self.stop()
        return (
            self.start(specs, preflight=preflight, probes=probes, timeout=timeout, frontend_factory=frontend_factory)
            if stopped.exit_code == 0
            else stopped
        )

    def supervise(self, probes, *, interval=2.0, timeout=5.0):
        try:
            while self.runtime is not None:
                self._healthy(self.runtime)
                for spec in self.active_specs:
                    self._probe(spec, probes[spec.name], self.clock() + timeout)
                self.sleep(interval)
        except BaseException as error:
            diagnostics = self._diagnostics(self.runtime) if self.runtime else ()
            stopped = self.stop()
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                return stopped
            code = error.code if type(error) is RuntimeAdapterError else "INSTANCE_SUPERVISION_FAILED"
            return RuntimeOutcome(
                code, 1, stopped.services or diagnostics, stopped.records_retained, component=self.current_component
            )
