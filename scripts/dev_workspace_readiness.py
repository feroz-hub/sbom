"""Read-only readiness with process-bound local listeners, never provisioning.

Trusted Runtime/provider snapshots are inputs, not approvals minted by this
module. Provider host-forwarder ownership must be independently established by
the executor; container guest PIDs cannot stand in for Windows host proxies.
No application/provider process is stopped, private setting changed, or
privileged identity created. Owned lsof probe cleanup alone may signal its
original child after fresh native creation-time/executable verification.
Enumeration and connect are not atomic: pre/post checks detect ordinary bind
races, but absolute exclusion of an intervening rebind requires parent-owned
listener handoff or independent server attestation. No such guarantee is minted.
"""

from __future__ import annotations

import base64
import ctypes
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from urllib.parse import unquote, urlsplit

if __package__:
    from . import (
        dev_frontend,
        dev_instance_plan,
        dev_instance_registry,
        dev_private,
        dev_workspace_lifecycle,
        dev_workspace_preview,
    )
else:
    import dev_frontend
    import dev_instance_plan
    import dev_instance_registry
    import dev_private
    import dev_workspace_lifecycle
    import dev_workspace_preview

_CODES = frozenset({"READINESS_CONTEXT_INVALID", "READINESS_RESULT_INVALID", "READINESS_BOUND_REQUIRED",
    "LISTENER_NOT_READY", "LISTENER_ENUMERATION_UNVERIFIED", "LISTENER_OWNER_UNVERIFIED", "PROCESS_IDENTITY_UNVERIFIED",
    "RUNTIME_BINDING_UNVERIFIED", "PROVIDER_HOST_OWNERSHIP_REQUIRED", "MACOS_LISTENER_ADAPTER_REQUIRED",
    "LISTENER_PROBE_CLEANUP_UNCONFIRMED", "HTTP_NOT_READY", "HTTP_RESPONSE_UNVERIFIED", "API_IDENTITY_UNVERIFIED",
    "IAM_NOT_READY", "FRONTEND_NOT_READY", "TLS_MATERIAL_UNVERIFIED", "TLS_VERIFICATION_REQUIRED", "TLS_HOSTNAME_REQUIRED",
    "DATABASE_TARGET_UNVERIFIED", "DATABASE_NOT_READONLY", "DATABASE_SCHEMA_NOT_READY", "DATABASE_INSPECTION_FAILED",
    "DATABASE_CLEANUP_UNCONFIRMED", "AUTHENTICATION_CONFIGURATION_REQUIRED", "NATIVE_PREREQUISITES_UNVERIFIED",
    "HCL_REGISTRATION_REQUIRED", "HCL_DISCOVERY_UNVERIFIED", "HCL_JWKS_UNVERIFIED", "BACKGROUND_NOT_READY",
    "API_READY", "FRONTEND_READY", "BACKGROUND_READY", "DATABASE_READY", "TLS_READY", "AUTHENTICATION_READY",
    "REDIS_TARGET_UNVERIFIED", "REDIS_NOT_READY", "REDIS_AUTHENTICATION_FAILED", "REDIS_RESPONSE_UNVERIFIED",
    "REDIS_SESSION_ACL_UNVERIFIED", "REDIS_CLEANUP_UNCONFIRMED", "REDIS_READY", "SESSION_READY",
    "MAIL_TARGET_UNVERIFIED", "MAIL_NOT_READY", "MAIL_TLS_REQUIRED", "MAIL_AUTHENTICATION_FAILED",
    "MAIL_RESPONSE_UNVERIFIED", "MAIL_CLEANUP_UNCONFIRMED", "MAIL_READY", "DATABASE_AMBIENT_CONFIGURATION_REFUSED"})
_PROVIDERS = {"postgres", "redis", "mailpit"}
_COMPONENTS = frozenset({*dev_workspace_lifecycle.COMPONENTS, "Database", "TLS", "Authentication", "Background", "Redis", "Session", "Mail"})
_PER_RUN = frozenset({"SBOM_DEV_INSTANCE", "SBOM_DEV_PROFILE", "SBOM_DEV_STATE_DIR", "SBOM_DEV_WORKER_ROLE"})


class ReadinessError(ValueError):
    def __init__(self, code, winerror=None, probe_pid=None):
        self.code = code if type(code) is str and code in _CODES else "READINESS_RESULT_INVALID"
        self.winerror = winerror if type(winerror) is int and 0 <= winerror <= 0xFFFFFFFF else None
        self.probe_pid = probe_pid if type(probe_pid) is int and 0 < probe_pid <= 0xFFFFFFFF else None
        super().__init__(self.code)


def _fail(code, winerror=None, probe_pid=None):
    raise ReadinessError(code, winerror, probe_pid) from None


def _windows_code(error):
    value = getattr(error, "winerror", None)
    if type(value) is int and 0 <= value <= 0xFFFFFFFF:
        return value
    if type(error).__name__ == "OwnershipError" and type(error).__module__ in {"dev", "scripts.dev"}:
        match = re.search(r"\bwinerror=([0-9]{1,10})\b", str(error))
        if match and int(match[1]) <= 0xFFFFFFFF:
            return int(match[1])
    return None


def _relevant(address, target):
    value = ipaddress.ip_address(address)
    return value.is_unspecified or value == ipaddress.ip_address(target) or getattr(value, "ipv4_mapped", None) == ipaddress.ip_address(target)


class _Tcp4(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in ("state", "local_addr", "local_port", "remote_addr", "remote_port", "pid")]


class _Tcp6(ctypes.Structure):
    _fields_ = [("local_addr", ctypes.c_ubyte * 16), ("local_scope", ctypes.c_uint32), ("local_port", ctypes.c_uint32),
               ("remote_addr", ctypes.c_ubyte * 16), ("remote_scope", ctypes.c_uint32), ("remote_port", ctypes.c_uint32),
               ("state", ctypes.c_uint32), ("pid", ctypes.c_uint32)]


def _windows_listener_pids(address, port, *, api=None):
    """GetExtendedTcpTable returns its DWORD error directly, not GetLastError.

    Microsoft iphlpapi/GetExtendedTcpTable and tcpmib/MIB_TCP[6]ROW_OWNER_PID;
    use the ctypes table offset because the documented table can have padding.
    """
    if api is None:
        library = ctypes.WinDLL("iphlpapi", use_last_error=True)
        api = library.GetExtendedTcpTable
        api.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.c_int32,
                        ctypes.c_uint32, ctypes.c_int32, ctypes.c_uint32]
        api.restype = ctypes.c_uint32
    owners = set()
    for family, row_type in ((2, _Tcp4), (23, _Tcp6)):
        class Table(ctypes.Structure):
            _fields_ = [("count", ctypes.c_uint32), ("rows", row_type * 1)]
        size, buffer = ctypes.c_uint32(0), None
        for _ in range(4):
            code = api(buffer, ctypes.byref(size), False, family, 3, 0)
            if code == 122:
                if not Table.rows.offset <= size.value <= 8388608:
                    _fail("LISTENER_ENUMERATION_UNVERIFIED", code)
                buffer = ctypes.create_string_buffer(size.value)
                continue
            if code:
                _fail("LISTENER_ENUMERATION_UNVERIFIED", int(code))
            if buffer is None or not Table.rows.offset <= size.value <= ctypes.sizeof(buffer):
                _fail("LISTENER_ENUMERATION_UNVERIFIED")
            count = ctypes.c_uint32.from_buffer_copy(buffer).value
            stride, offset = ctypes.sizeof(row_type), Table.rows.offset
            if count > 131072 or count > (size.value - offset) // stride:
                _fail("LISTENER_ENUMERATION_UNVERIFIED")
            for index in range(count):
                row = row_type.from_buffer_copy(buffer, offset + index * stride)
                local = socket.inet_ntop(socket.AF_INET, int(row.local_addr).to_bytes(4, sys.byteorder)) if family == 2 else socket.inet_ntop(socket.AF_INET6, bytes(row.local_addr))
                if row.state == 2 and socket.ntohs(row.local_port & 0xFFFF) == port and _relevant(local, address):
                    if not 0 < row.pid <= 0xFFFFFFFF:
                        _fail("LISTENER_ENUMERATION_UNVERIFIED")
                    owners.add(row.pid)
            break
        else:
            _fail("LISTENER_ENUMERATION_UNVERIFIED", 122)
    return frozenset(owners)


def _read_proc(path, limit=1048576):
    # proc pseudo-files have size zero; bounded regular-file reads are deliberate.
    with path.open("rb") as stream:
        content = stream.read(limit + 1)
    if len(content) > limit:
        _fail("LISTENER_ENUMERATION_UNVERIFIED")
    return content.decode("ascii")


def _linux_listener_pids(address, port, expected_pids, *, proc_root=Path("/proc"), clock=time.monotonic, timeout=2):
    """Attribute every matching inode using only verified candidate PID fds.

    Kernel docs networking/proc_net_tcp and filesystems/proc: tcp local/state/
    inode fields, and fd symlink socket:[inode]. Missing coverage is UNKNOWN.
    """
    deadline, inodes = clock() + timeout, set()
    namespace = os.readlink(proc_root / "self/ns/net")
    for name, width in (("tcp", 8), ("tcp6", 32)):
        rows = _read_proc(proc_root / "net" / name).splitlines()
        if not rows or "local_address" not in rows[0] or len(rows) > 65536:
            _fail("LISTENER_ENUMERATION_UNVERIFIED")
        for line in rows[1:]:
            fields = line.split()
            if len(fields) < 10 or ":" not in fields[1]:
                _fail("LISTENER_ENUMERATION_UNVERIFIED")
            encoded, encoded_port = fields[1].split(":")
            if len(encoded) != width:
                _fail("LISTENER_ENUMERATION_UNVERIFIED")
            packed = b"".join(int(encoded[index:index + 8], 16).to_bytes(4, sys.byteorder) for index in range(0, width, 8))
            local = socket.inet_ntop(socket.AF_INET if width == 8 else socket.AF_INET6, packed)
            if fields[3] == "0A" and int(encoded_port, 16) == port and _relevant(local, address):
                if not fields[9].isdigit() or int(fields[9]) <= 0:
                    _fail("LISTENER_ENUMERATION_UNVERIFIED")
                inodes.add(fields[9])
    if os.readlink(proc_root / "self/ns/net") != namespace:
        _fail("LISTENER_ENUMERATION_UNVERIFIED")
    if not inodes:
        return frozenset()
    found, owners, count = set(), set(), 0
    for pid in expected_pids:
        if clock() >= deadline or os.readlink(proc_root / str(pid) / "ns/net") != namespace:
            _fail("LISTENER_ENUMERATION_UNVERIFIED")
        for path in (proc_root / str(pid) / "fd").iterdir():
            count += 1
            if count > 131072 or clock() >= deadline:
                _fail("LISTENER_ENUMERATION_UNVERIFIED")
            try:
                target = os.readlink(path)
            except FileNotFoundError:
                continue  # Unrelated fds may close; required socket coverage still must be complete.
            match = re.fullmatch(r"socket:\[([0-9]+)\]", target)
            if match and match[1] in inodes:
                owners.add(pid)
                found.add(match[1])
        if os.readlink(proc_root / str(pid) / "ns/net") != namespace:
            _fail("LISTENER_ENUMERATION_UNVERIFIED")
    if os.readlink(proc_root / "self/ns/net") != namespace:
        _fail("LISTENER_ENUMERATION_UNVERIFIED")
    if found != inodes:
        _fail("LISTENER_OWNER_UNVERIFIED")
    return frozenset(owners)


@dataclass(frozen=True, slots=True)
class _ProbeOutput:
    returncode: int
    stdout: bytes = field(repr=False)
    stderr: bytes = field(repr=False)


def owned_lsof_probe(argv, *, process_info, matches, timeout=2, max_output=262144,
                     popen=None, tool_path=Path("/usr/sbin/lsof"), clock=time.monotonic, sleep=time.sleep):
    """Own one bounded system lsof child; never signal an unverifiable PID.

    tool_path is a trusted OS-adapter injection for synthetic tests, not a CLI
    setting. Production uses the fixed protected /usr/sbin/lsof executable.
    Stdout/stderr are drained under independent byte bounds, never logged.
    """
    child, saved = None, None
    streams, done, outputs, failures = [], [], [bytearray(), bytearray()], []
    limits = (max_output, min(max_output, 65536))
    exceeded = threading.Event()
    try:
        tool = Path(tool_path)
        if (not 0 < timeout <= 5 or not 1 <= max_output <= 1048576 or not callable(process_info) or not callable(matches)
                or tuple(argv[:1]) != (str(tool),) or tool.name != "lsof" or tool.resolve(strict=True) != tool):
            _fail("LISTENER_ENUMERATION_UNVERIFIED")
        data, proof = dev_frontend._regular(tool, 16777216)
        del data
        info = tool.lstat()
        if sys.platform == "win32":
            dev_instance_registry._private(tool)  # Synthetic native-Windows file fixture only.
        elif (info.st_uid not in {0, os.getuid()} or stat.S_IMODE(info.st_mode) & 0o022
              or not stat.S_IMODE(info.st_mode) & 0o111 or info.st_mode & (stat.S_ISUID | stat.S_ISGID)):
            _fail("LISTENER_ENUMERATION_UNVERIFIED")
        child = (popen or subprocess.Popen)(tuple(argv), cwd=Path("/"),
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "LANG": "C"},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True, start_new_session=True, bufsize=0)
        try:
            current = process_info(child.pid)
            if (current and current.get("birth") and current.get("exe")
                    and Path(current["exe"]).resolve(strict=True) == tool):
                saved = dict(current)
        except Exception:
            saved = None
        streams = [child.stdout, child.stderr]
        for index, stream in enumerate(streams):
            finished = threading.Event()
            done.append(finished)
            def drain(selected=stream, position=index, complete=finished):
                try:
                    while True:
                        remaining = limits[position] - len(outputs[position])
                        chunk = selected.read(min(8192, max(1, remaining + 1)))
                        if not chunk:
                            break
                        if len(chunk) > remaining:
                            exceeded.set()
                            break
                        outputs[position].extend(chunk)
                except Exception:
                    failures.append(True)
                finally:
                    try:
                        selected.close()
                    except Exception:
                        failures.append(True)
                    complete.set()
            threading.Thread(target=drain, daemon=True, name="sbom-owned-lsof-output").start()
        deadline = clock() + timeout
        while child.poll() is None and clock() < deadline and not exceeded.is_set():
            sleep(min(0.02, max(0, deadline - clock())))
        if child.poll() is None:
            # Every escalation uses the original Popen AND fresh native identity.
            # A failed birth/executable query protects the process from signals.
            for force in (False, True):
                if child.poll() is not None:
                    break
                try:
                    current = process_info(child.pid)
                    known = saved is not None and current and current.get("exe") and matches(saved, current)
                except Exception:
                    known = False
                if not known:
                    _fail("LISTENER_PROBE_CLEANUP_UNCONFIRMED", probe_pid=child.pid)
                if force:
                    child.kill()
                else:
                    child.terminate()
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    continue
            if child.poll() is None:
                _fail("LISTENER_PROBE_CLEANUP_UNCONFIRMED", probe_pid=child.pid)
            _fail("LISTENER_ENUMERATION_UNVERIFIED")
        for finished in done:
            if not finished.wait(timeout=0.2):
                _fail("LISTENER_ENUMERATION_UNVERIFIED")
        if exceeded.is_set() or failures or dev_frontend._regular(tool, 16777216)[1] != proof:
            _fail("LISTENER_ENUMERATION_UNVERIFIED")
        return _ProbeOutput(child.returncode, bytes(outputs[0]), bytes(outputs[1]))
    except ReadinessError:
        raise
    except Exception as error:
        try:
            unfinished = child is not None and child.poll() is None
        except Exception:
            unfinished = child is not None
        if unfinished:
            # Unexpected control/IO failures do not grant permission to kill.
            _fail("LISTENER_PROBE_CLEANUP_UNCONFIRMED", _windows_code(error), child.pid)
        _fail("LISTENER_ENUMERATION_UNVERIFIED", _windows_code(error))
    finally:
        # These are only the original unbuffered communication handles. Closing
        # them never grants permission to signal an unverifiable process. A
        # blocked daemon reader may finish when that reported probe exits.
        for stream in streams:
            try:
                if not stream.closed:
                    stream.close()
            except Exception:
                pass


def _mac_listener_pids(address, port, expected_pids, *, probe=None):
    """A trusted owned/bounded lsof probe is required; never shell or guess PIDs.

    probe receives fixed argv, timeout and output bound, and must own/revalidate
    its original child handle on cleanup. No generic unverified kill fallback.
    Apple lsof(8): -Di disables cache writes; -nP disables DNS/service lookup.
    """
    if probe is None:
        _fail("MACOS_LISTENER_ADAPTER_REQUIRED")
    argv = ("/usr/sbin/lsof", "-nP", "-Di", "+w", "-a", "-iTCP:" + str(port), "-sTCP:LISTEN", "-F0pfn")
    result = probe(argv, timeout=2, max_output=262144)
    if result.returncode not in {0, 1} or result.stderr or len(result.stdout) > 262144:
        _fail("LISTENER_ENUMERATION_UNVERIFIED")
    if result.returncode == 1:
        if result.stdout:
            _fail("LISTENER_ENUMERATION_UNVERIFIED")
        return frozenset()
    current, owners, seen_endpoint = None, set(), False
    for item in result.stdout.decode("ascii").split("\0"):
        item = item.lstrip("\n")
        if not item:
            continue
        key, value = item[:1], item[1:]
        if key == "p" and value.isdigit() and int(value) > 0:
            current = int(value)
        elif key == "f" and re.fullmatch(r"[0-9]+[A-Za-z]*", value):
            pass
        elif key == "n" and current is not None:
            match = re.fullmatch(r"(?:\[([^]]+)\]|([^:]+)):([0-9]+)", value)
            if not match or int(match[3]) != port:
                _fail("LISTENER_ENUMERATION_UNVERIFIED")
            local = match[1] or match[2]
            if local == "*" or _relevant(local, address):
                owners.add(current)
            seen_endpoint = True
        else:
            _fail("LISTENER_ENUMERATION_UNVERIFIED")
    if not seen_endpoint or not owners <= set(expected_pids):
        _fail("LISTENER_OWNER_UNVERIFIED")
    return frozenset(owners)


def listener_pids(address, port, expected_pids, *, platform=None, mac_probe=None, timeout=2):
    try:
        if (address != "127.0.0.1" or type(port) is not int or not 1 <= port <= 65535
                or type(expected_pids) not in {tuple, list, set, frozenset} or not 1 <= len(expected_pids) <= 128
                or any(type(pid) is not int or not 0 < pid <= 0xFFFFFFFF for pid in expected_pids)):
            _fail("LISTENER_ENUMERATION_UNVERIFIED")
        platform = platform or sys.platform
        if platform == "win32":
            return _windows_listener_pids(address, port)
        if platform == "linux":
            return _linux_listener_pids(address, port, expected_pids, timeout=timeout)
        if platform == "darwin":
            return _mac_listener_pids(address, port, expected_pids, probe=mac_probe)
        _fail("LISTENER_ENUMERATION_UNVERIFIED")
    except ReadinessError:
        raise
    except Exception as error:
        _fail("LISTENER_ENUMERATION_UNVERIFIED", _windows_code(error))


@dataclass(frozen=True, slots=True)
class ReadinessResult:
    component: str
    status: str
    code: str
    winerror: int | None = None
    probe_pid: int | None = None

    def __post_init__(self):
        if (type(self.component) is not str or self.component not in _COMPONENTS
                or type(self.status) is not str or self.status not in {"PASS", "PENDING", "BLOCKED"}
                or type(self.code) is not str or self.code not in _CODES
                or self.winerror is not None and (type(self.winerror) is not int or not 0 <= self.winerror <= 0xFFFFFFFF)
                or self.probe_pid is not None and (type(self.probe_pid) is not int or not 0 < self.probe_pid <= 0xFFFFFFFF)):
            _fail("READINESS_RESULT_INVALID")

    def to_dict(self):
        result = {"component": self.component, "status": self.status, "code": self.code, "winerror": self.winerror}
        if self.probe_pid is not None:
            result["probe_pid"] = self.probe_pid
        if self.component in {"TLS", "Frontend"}:
            result.update(trust_scope="explicit_client_ca_and_hostname", browser_trust_verified=False,
                          login_acceptance_verified=False)
        return result


@dataclass(frozen=True, slots=True)
class ReadinessContext:
    descriptor: dev_instance_plan.InstanceDescriptor
    environment: Mapping[str, str] = field(repr=False)
    runtime_root: Path = field(repr=False)
    source_root: Path = field(repr=False)
    tls: object = field(repr=False)
    schema_revision: str
    provider_processes: Mapping = field(default_factory=dict, repr=False)
    approved_identity_origins: tuple[str, ...] = field(default=(), repr=False)
    runtime_identity: tuple = field(init=False, repr=False)

    def __post_init__(self):
        try:
            if (type(self.descriptor) is not dev_instance_plan.InstanceDescriptor or not isinstance(self.environment, Mapping)
                    or type(self.tls) is not dev_workspace_preview.PreviewTls
                    or self.environment.get("SBOM_DEV_RESOURCE_ID") != self.descriptor.instance_id
                    or self.environment.get("APP_ENVIRONMENT") != "development"
                    or self.environment.get("PYTHON_DOTENV_DISABLED") != "1"
                    or re.fullmatch(r"[A-Za-z0-9_]{1,128}", self.schema_revision) is None):
                raise ValueError()
            env = dict(self.environment)
            if any(type(key) is not str or type(value) is not str or "\0" in value for key, value in env.items()):
                raise ValueError()
            root, source = Path(self.runtime_root), Path(self.source_root)
            if root.name != self.descriptor.instance_id or root.resolve(strict=True) != root or source.resolve(strict=True) != source:
                raise ValueError()
            info = dev_instance_registry._private(root, directory=True)
            if self.descriptor.mode == "isolated":
                snapshot = dev_workspace_lifecycle.PreparationSnapshot(self.descriptor.repository_id,
                    self.descriptor.worktree_id, self.descriptor.commit, self.descriptor.config_generation,
                    sys.platform, str(source), str(root), env, dict.fromkeys(dev_workspace_lifecycle.PREREQUISITES, "PREPARED"))
                dev_workspace_lifecycle.plan_lifecycle(self.descriptor, snapshot)
                if self.tls.ca_bundle != Path(env.get("SSL_CERT_FILE", "")):
                    raise ValueError()
            providers = {}
            for component, records in self.provider_processes.items():
                if component not in _PROVIDERS or type(records) not in {tuple, list} or not 1 <= len(records) <= 128:
                    raise ValueError()
                copied = []
                for record in records:
                    if (not isinstance(record, Mapping) or set(record) != {"pid", "birth", "exe"}
                            or type(record["pid"]) is not int or not 0 < record["pid"] <= 0xFFFFFFFF
                            or any(type(record[key]) is not str or not record[key] for key in ("birth", "exe"))):
                        raise ValueError()
                    copied.append(MappingProxyType(dict(record)))
                providers[component] = tuple(copied)
            origins = tuple(self.approved_identity_origins)
            for origin in origins:
                parsed = _https(origin)
                if parsed.path:
                    raise ValueError()
            object.__setattr__(self, "environment", MappingProxyType(env))
            object.__setattr__(self, "provider_processes", MappingProxyType(providers))
            object.__setattr__(self, "approved_identity_origins", origins)
            object.__setattr__(self, "runtime_root", root)
            object.__setattr__(self, "source_root", source)
            object.__setattr__(self, "runtime_identity", (info.st_dev, info.st_ino))
        except Exception:
            _fail("READINESS_CONTEXT_INVALID")

    @property
    def browser_trust_verified(self):
        return False

    def to_public_dict(self):
        return {"instance_id": self.descriptor.instance_id, "mode": self.descriptor.mode,
                "auth_mode": self.descriptor.auth_mode, "schema_revision": self.schema_revision,
                "browser_trust_verified": False, "browser_trust": "UNVERIFIED",
                "login_acceptance_verified": False, "privileged_enrollment_authorized": False}


def _https(url):
    value = urlsplit(url)
    if (value.scheme != "https" or not value.hostname or value.username is not None or value.password is not None
            or value.query or value.fragment or any(ord(char) <= 32 for char in url)):
        _fail("TLS_VERIFICATION_REQUIRED")
    _ = value.port
    return value


def _ssl_context(cafile=None):
    # Do not use create_default_context: Python3.14 ssl.py724 honours ambient
    # SSLKEYLOGFILE and opens a secret log. This explicit context never does.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if hasattr(ssl, "VERIFY_X509_STRICT"):
        context.verify_flags |= ssl.VERIFY_X509_STRICT
    if cafile is None:
        if os.environ.get("SSL_CERT_FILE") or os.environ.get("SSL_CERT_DIR"):
            _fail("TLS_VERIFICATION_REQUIRED")
        context.load_default_certs()
    else:
        context.load_verify_locations(cafile=str(cafile))
    return context


def validate_tls_material(tls, hostname, *, now=None):
    """Protected existing files only: key pairing + full offline server PKI.

    cryptography49 verification.PolicyBuilder/Store checks certificate policy;
    signature-only verify_directly_issued_by is not a replacement for PKI.
    The live HTTPS handshake still independently verifies chain and hostname.
    This is custom client trust only, never OS/browser root-trust verification.
    No trust store is imported or changed; that requires a separate operator flow.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.x509.verification import PolicyBuilder, Store

        before = []
        contents = []
        for path in (tls.certificate, tls.private_key, tls.ca_bundle):
            path = Path(path)
            if not path.is_absolute() or path.resolve(strict=True) != path:
                raise ValueError()
            dev_private.validate_parent(path, path.parent)
            if path == tls.private_key:
                dev_instance_registry._private(path)
            data, identity = dev_frontend._regular(path, 1048576)
            before.append((path, identity))
            contents.append(data)
        certificates = x509.load_pem_x509_certificates(contents[0])
        authorities = x509.load_pem_x509_certificates(contents[2])
        private = serialization.load_pem_private_key(contents[1], password=None)
        if not certificates or not authorities or len(certificates) > 8 or len(authorities) > 512:
            raise ValueError()
        form = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if certificates[0].public_key().public_bytes(*form) != private.public_key().public_bytes(*form):
            raise ValueError()
        for authority in authorities:
            if not authority.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError()
        verifier = PolicyBuilder().store(Store(authorities)).time(now or datetime.now(UTC)).build_server_verifier(x509.DNSName(hostname))
        verifier.verify(certificates[0], certificates[1:])
        context = _ssl_context(tls.ca_bundle)
        for path, identity in before:
            if dev_frontend._regular(path, 1048576)[1] != identity:
                raise ValueError()
        return context
    except ReadinessError:
        raise
    except Exception:
        _fail("TLS_MATERIAL_UNVERIFIED")


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    body: bytes = field(repr=False)

    def __post_init__(self):
        if type(self.status) is not int or not 100 <= self.status <= 599 or type(self.body) is not bytes or len(self.body) > 262144:
            _fail("HTTP_RESPONSE_UNVERIFIED")


def http_request(scheme, hostname, port, path, timeout, context=None, *, address=None):
    """Direct stdlib transport: no proxies, redirects, cookies or auth payload."""
    connection = None
    try:
        if scheme == "https":
            if context is None or context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname or context.keylog_filename:
                _fail("TLS_VERIFICATION_REQUIRED")
            connection = http.client.HTTPSConnection(hostname, port, timeout=timeout, context=context)
            if address is not None:
                raw = socket.create_connection((address, port), timeout=timeout)
                try:
                    connection.sock = context.wrap_socket(raw, server_hostname=hostname)
                except BaseException:
                    raw.close()
                    raise
        elif scheme == "http" and hostname == "127.0.0.1":
            connection = http.client.HTTPConnection(hostname, port, timeout=timeout)
        else:
            _fail("TLS_VERIFICATION_REQUIRED")
        connection.request("GET", path, headers={"Accept": "application/json", "Connection": "close"})
        response = connection.getresponse()
        body = response.read(262145)
        if len(body) > 262144:
            _fail("HTTP_RESPONSE_UNVERIFIED")
        return HttpResponse(response.status, body)
    finally:
        if connection is not None:
            connection.close()


class RedisReplyError(ValueError):
    """Classify an ACL denial without retaining a private server response."""

    def __init__(self, *, permission_denied=False):
        self.permission_denied = permission_denied is True
        super().__init__("REDIS_PERMISSION_DENIED" if self.permission_denied else "REDIS_RESPONSE_REJECTED")


class _ProviderWire:
    """One owned socket, bounded bytes and an absolute deadline per operation."""

    def __init__(self, *, host, port, timeout, clock=time.monotonic):
        if host != "127.0.0.1" or type(port) is not int or not 1024 <= port <= 65535:
            _fail("READINESS_CONTEXT_INVALID")
        self.host, self.clock, self.sock, self.buffer = host, clock, None, bytearray()
        self.tls_verified = False
        self.settimeout(timeout)
        self.sock = socket.create_connection((host, port), timeout=timeout)

    def settimeout(self, timeout):
        if type(timeout) not in {int, float} or not 0 < timeout <= 3:
            _fail("READINESS_BOUND_REQUIRED")
        self.deadline = self.clock() + timeout

    def _remaining(self):
        value = self.deadline - self.clock()
        if value <= 0:
            raise TimeoutError()
        return value

    def _send(self, raw):
        if type(raw) is not bytes or len(raw) > 65536:
            _fail("READINESS_RESULT_INVALID")
        self.sock.settimeout(self._remaining())
        self.sock.sendall(raw)

    def _receive(self):
        self.sock.settimeout(self._remaining())
        raw = self.sock.recv(4096)
        if not raw or len(self.buffer) + len(raw) > 65536:
            _fail("READINESS_RESULT_INVALID")
        self.buffer.extend(raw)

    def _line(self):
        while b"\r\n" not in self.buffer:
            if len(self.buffer) > 4096:
                _fail("READINESS_RESULT_INVALID")
            self._receive()
        index = self.buffer.index(b"\r\n")
        if index > 4096:
            _fail("READINESS_RESULT_INVALID")
        raw = bytes(self.buffer[:index])
        del self.buffer[:index + 2]
        return raw

    def _tls(self, context):
        if (context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname or context.keylog_filename
                or self.buffer):
            _fail("TLS_VERIFICATION_REQUIRED")
        self.sock.settimeout(self._remaining())
        self.sock = context.wrap_socket(self.sock, server_hostname=self.host)
        self.tls_verified = True

    def close(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None


class _RedisProbe(_ProviderWire):
    """RESP2 only; no implicit HELLO/client metadata, subscriptions or store writes."""

    def __init__(self, *, context, **kwargs):
        super().__init__(**kwargs)
        try:
            self._tls(context)
        except BaseException:
            try:
                self.close()
            except BaseException:
                _fail("REDIS_CLEANUP_UNCONFIRMED")
            raise

    def command(self, *parts):
        count = {"AUTH": 3, "SELECT": 2, "PING": 1, "GET": 2}
        if (not self.tls_verified or not parts or type(parts[0]) is not str or parts[0] not in count or len(parts) != count[parts[0]]
                or any(type(part) is not str for part in parts)):
            _fail("REDIS_RESPONSE_UNVERIFIED")
        values = [part.encode("utf-8") for part in parts]
        raw = b"*" + str(len(values)).encode() + b"\r\n" + b"".join(
            b"$" + str(len(value)).encode() + b"\r\n" + value + b"\r\n" for value in values)
        self._send(raw)
        response = self._line()
        if response.startswith(b"+"):
            return response[1:]
        if response.startswith(b"-"):
            raise RedisReplyError(permission_denied=response[1:].startswith(b"NOPERM "))
        if response == b"$-1":
            return None
        if not re.fullmatch(rb"\$[0-9]{1,5}", response):
            _fail("REDIS_RESPONSE_UNVERIFIED")
        length = int(response[1:])
        if length > 32768:
            _fail("REDIS_RESPONSE_UNVERIFIED")
        while len(self.buffer) < length + 2:
            self._receive()
        if self.buffer[length:length + 2] != b"\r\n":
            _fail("REDIS_RESPONSE_UNVERIFIED")
        value = bytes(self.buffer[:length])
        del self.buffer[:length + 2]
        return value


class _SmtpProbe(_ProviderWire):
    """Bounded SMTP EHLO/STARTTLS/AUTH PLAIN/QUIT; never MAIL, RCPT or DATA."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.features, self.auth_plain = set(), False
        try:
            if self._reply()[0] != 220:
                _fail("MAIL_RESPONSE_UNVERIFIED")
        except BaseException:
            try:
                self.close()
            except BaseException:
                _fail("MAIL_CLEANUP_UNCONFIRMED")
            raise

    def _reply(self):
        code, lines, size = None, [], 0
        for _ in range(64):
            line = self._line()
            size += len(line)
            if size > 32768 or re.fullmatch(rb"[0-9]{3}[ -].*", line) is None:
                _fail("MAIL_RESPONSE_UNVERIFIED")
            current = int(line[:3])
            if code is not None and current != code:
                _fail("MAIL_RESPONSE_UNVERIFIED")
            code = current
            lines.append(line[4:])
            if line[3:4] == b" ":
                return code, lines
        _fail("MAIL_RESPONSE_UNVERIFIED")

    def ehlo(self):
        self._send(b"EHLO sbom-readiness.local\r\n")
        code, lines = self._reply()
        self.features = {line.split(b" ", 1)[0].lower() for line in lines}
        self.auth_plain = any(line.upper().startswith(b"AUTH ") and b"PLAIN" in line.upper().split()[1:] for line in lines)
        return code

    def has_extn(self, name):
        return name.encode("ascii") in self.features

    def starttls(self, *, context):
        self._send(b"STARTTLS\r\n")
        code, _ = self._reply()
        if code != 220:
            _fail("MAIL_TLS_REQUIRED")
        self._tls(context)
        self.features.clear()
        self.auth_plain = False
        return code

    def login(self, username, password):
        if not self.tls_verified or not self.auth_plain or any("\0" in value for value in (username, password)):
            _fail("MAIL_AUTHENTICATION_FAILED")
        payload = base64.b64encode(("\0" + username + "\0" + password).encode("utf-8"))
        self._send(b"AUTH PLAIN " + payload + b"\r\n")
        if self._reply()[0] != 235:
            _fail("MAIL_AUTHENTICATION_FAILED")
        return True

    def quit(self):
        self._send(b"QUIT\r\n")
        if self._reply()[0] != 221:
            _fail("MAIL_RESPONSE_UNVERIFIED")


class WorkspaceReadiness:
    def __init__(self, context, launcher, runtime_provider, *, listener_inspector=listener_pids,
                 request=http_request, db_connect=None, tls_validator=validate_tls_material, clock=time.monotonic,
                 redis_connect=None, smtp_connect=None):
        if type(context) is not ReadinessContext or not callable(runtime_provider):
            _fail("READINESS_CONTEXT_INVALID")
        self.context, self.launcher, self.runtime_provider = context, launcher, runtime_provider
        if listener_inspector is listener_pids:
            def system_listener(address, port, pids, *, timeout):
                def probe(argv, **options):
                    return owned_lsof_probe(argv, process_info=launcher.process_info, matches=launcher.matches, **options)
                return listener_pids(address, port, pids, mac_probe=probe, timeout=timeout)
            self.listener_inspector = system_listener
        else:
            self.listener_inspector = listener_inspector
        self.request, self.db_connect = request, db_connect
        self.redis_connect, self.smtp_connect = redis_connect, smtp_connect
        self.tls_validator, self.clock, self._results = tls_validator, clock, {}

    @property
    def results(self):
        return MappingProxyType(dict(self._results))

    def _run(self, component, callback):
        try:
            code = callback()
            self._results[component] = ReadinessResult(component, "PASS", code)
            return True
        except ReadinessError as error:
            pending = error.code in {"LISTENER_NOT_READY", "HTTP_NOT_READY", "IAM_NOT_READY", "FRONTEND_NOT_READY", "BACKGROUND_NOT_READY", "REDIS_NOT_READY", "MAIL_NOT_READY"}
            self._results[component] = ReadinessResult(component, "PENDING" if pending else "BLOCKED", error.code, error.winerror, error.probe_pid)
            if pending:
                return False
            raise
        except ssl.SSLError:
            self._results[component] = ReadinessResult(component, "BLOCKED", "TLS_VERIFICATION_REQUIRED")
            _fail("TLS_VERIFICATION_REQUIRED")
        except (TimeoutError, ConnectionError, http.client.HTTPException):
            self._results[component] = ReadinessResult(component, "PENDING", "HTTP_NOT_READY")
            return False
        except Exception as error:
            self._results[component] = ReadinessResult(component, "BLOCKED", "HTTP_RESPONSE_UNVERIFIED", _windows_code(error))
            _fail("HTTP_RESPONSE_UNVERIFIED", _windows_code(error))

    def _deadline(self, timeout):
        if type(timeout) not in {int, float} or not 0 < timeout <= 30:
            _fail("READINESS_BOUND_REQUIRED")
        return self.clock() + timeout

    def _remaining(self, deadline):
        remaining = deadline - self.clock()
        if remaining <= 0:
            _fail("HTTP_NOT_READY")
        return min(3.0, remaining)

    def _ca(self):
        """A current protected CA file identity; never an ambient trust fallback."""
        try:
            path = Path(self.context.environment.get("SSL_CERT_FILE", ""))
            if path != self.context.tls.ca_bundle or path.resolve(strict=True) != path:
                _fail("TLS_MATERIAL_UNVERIFIED")
            dev_private.validate_parent(path, self.context.runtime_root)
            dev_instance_registry._private(path)
            return path, dev_frontend._regular(path, 1048576)[1]
        except ReadinessError:
            raise
        except Exception:
            _fail("TLS_MATERIAL_UNVERIFIED")

    def _provider_context(self):
        path, proof = self._ca()
        context = _ssl_context(path)
        if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname or context.keylog_filename:
            _fail("TLS_VERIFICATION_REQUIRED")
        if self._ca() != (path, proof):
            _fail("TLS_MATERIAL_UNVERIFIED")
        return context, (path, proof)

    def _post_provider(self, component, port, proof, ca, deadline):
        # Keep ownership checks bounded but execute them after timeout/failure too.
        self._recheck(component, port, proof, max(deadline, self.clock() + 0.25))
        if self._ca() != ca:
            _fail("TLS_MATERIAL_UNVERIFIED")

    def _provider_timeout(self, deadline, code):
        remaining = deadline - self.clock()
        if remaining <= 0:
            _fail(code)
        return min(3.0, remaining)

    def _runtime(self):
        runtime = self.runtime_provider()
        state = runtime.state or {}
        descriptor = self.context.descriptor
        binding = state.get("workspace_context", {})
        if (runtime.root != self.context.runtime_root or binding.get("instance_id") != descriptor.instance_id
                or binding.get("repository_id") != descriptor.repository_id or binding.get("worktree_id") != descriptor.worktree_id
                or binding.get("root_identity") != list(self.context.runtime_identity)
                or not isinstance(state.get("instance"), str) or not isinstance(state.get("services"), dict)):
            _fail("RUNTIME_BINDING_UNVERIFIED")
        info = dev_instance_registry._private(runtime.root, directory=True)
        if (info.st_dev, info.st_ino) != self.context.runtime_identity:
            _fail("RUNTIME_BINDING_UNVERIFIED")
        return runtime

    def _identities(self, component):
        if component in _PROVIDERS:
            records = self.context.provider_processes.get(component)
            if not records:
                _fail("PROVIDER_HOST_OWNERSHIP_REQUIRED")
        else:
            runtime = self._runtime()
            root = runtime.state["services"].get(component)
            if not root or root.get("tree_unverified") or runtime.service_status(root) != "RUNNING":
                _fail("PROCESS_IDENTITY_UNVERIFIED")
            records = (root, *root.get("members", ()))
        captured = {}
        for saved in records:
            try:
                if (not isinstance(saved, Mapping) or type(saved.get("pid")) is not int or not 0 < saved["pid"] <= 0xFFFFFFFF):
                    _fail("PROCESS_IDENTITY_UNVERIFIED")
                current = self.launcher.process_info(saved["pid"])
                if (not saved.get("birth") or not saved.get("exe") or not current or not current.get("exe")
                        or not self.launcher.matches(saved, current)):
                    _fail("PROCESS_IDENTITY_UNVERIFIED")
            except ReadinessError:
                raise
            except Exception as error:
                _fail("PROCESS_IDENTITY_UNVERIFIED", _windows_code(error))
            captured[saved["pid"]] = (saved["birth"], saved["exe"])
        return captured

    def _owned(self, component, port, deadline):
        before = self._identities(component)
        owners = self.listener_inspector("127.0.0.1", port, frozenset(before), timeout=self._remaining(deadline))
        if not owners:
            _fail("LISTENER_NOT_READY")
        if not set(owners) <= set(before) or self._identities(component) != before:
            _fail("LISTENER_OWNER_UNVERIFIED")
        return before, frozenset(owners)

    def _recheck(self, component, port, proof, deadline):
        if self._owned(component, port, deadline) != proof:
            _fail("LISTENER_OWNER_UNVERIFIED")

    def _spec(self, spec, component):
        runtime = self._runtime()
        if (spec.name != component or spec.environment.get("SBOM_DEV_RESOURCE_ID") != self.context.descriptor.instance_id
                or spec.environment.get("SBOM_DEV_INSTANCE") != runtime.state["instance"]
                or spec.port != self.context.descriptor.ports["api" if component == "API" else "frontend"]):
            _fail("RUNTIME_BINDING_UNVERIFIED")
        if component == "API" and any(spec.environment.get(key) != value for key, value in self.context.environment.items()
                                      if key not in _PER_RUN):
            _fail("RUNTIME_BINDING_UNVERIFIED")

    def _request_local(self, component, scheme, hostname, port, path, deadline, context=None):
        proof = self._owned(component, port, deadline)
        try:
            return self.request(scheme, hostname, port, path, self._remaining(deadline), context,
                                **({"address": "127.0.0.1"} if scheme == "https" else {}))
        finally:
            self._recheck(component, port, proof, max(deadline, self.clock() + 0.25))

    def api(self, spec, timeout):
        def check():
            if self.context.descriptor.mode != "isolated":
                _fail("RUNTIME_BINDING_UNVERIFIED")
            self._spec(spec, "API")
            deadline, port = self._deadline(timeout), self.context.descriptor.ports["api"]
            response = self._request_local("API", "http", "127.0.0.1", port, "/", deadline)
            # app/routers/health.py service_info is inert. /health can flush
            # NVD settings via repository.load; database checks stay readonly SQL.
            if response.status != 200 or json.loads(response.body).get("service") != "sbom-analyzer-api":
                _fail("API_IDENTITY_UNVERIFIED")
            if self.context.descriptor.auth_mode == "native":
                response = self._request_local("API", "http", "127.0.0.1", port, "/ready/iam", deadline)
                if response.status != 200 or json.loads(response.body).get("ready") is not True:
                    _fail("IAM_NOT_READY")
            return "API_READY"
        return self._run("API", check)

    def tls(self, timeout=5):
        def check():
            self._deadline(timeout)
            self.tls_validator(self.context.tls, self.context.descriptor.hostname)
            return "TLS_READY"
        return self._run("TLS", check)

    def frontend(self, spec, timeout):
        def check():
            self._spec(spec, "Frontend")
            deadline, port = self._deadline(timeout), self.context.descriptor.ports["frontend"]
            context = self.tls_validator(self.context.tls, self.context.descriptor.hostname)
            path = "/" if self.context.descriptor.mode == "mock" else (
                "/native-sign-in" if self.context.descriptor.auth_mode == "native" else "/")
            response = self._request_local("Frontend", "https", self.context.descriptor.hostname, port, path, deadline, context)
            if not 200 <= response.status < 400:
                _fail("FRONTEND_NOT_READY")
            return "FRONTEND_READY"
        return self._run("Frontend", check)

    def background(self, spec, timeout):
        def check():
            deadline = self._deadline(timeout)
            runtime = self._runtime()
            if spec.name not in set(dev_workspace_lifecycle.COMPONENTS[:3]) or spec.environment.get("SBOM_DEV_INSTANCE") != runtime.state["instance"]:
                _fail("RUNTIME_BINDING_UNVERIFIED")
            if any(spec.environment.get(key) != value for key, value in self.context.environment.items() if key not in _PER_RUN):
                _fail("RUNTIME_BINDING_UNVERIFIED")
            directory = self.context.runtime_root / ".dev-logs"
            if spec.environment.get("SBOM_DEV_STATE_DIR") != str(directory):
                _fail("RUNTIME_BINDING_UNVERIFIED")
            dev_instance_registry._private(directory, directory=True)
            for role in ("default", "reports", "beat"):
                try:
                    if dev_instance_registry._private(directory / (role + "-health.json")).st_size > 65536:
                        _fail("PROCESS_IDENTITY_UNVERIFIED")
                except FileNotFoundError:
                    _fail("BACKGROUND_NOT_READY")
            identities = {name: self._identities(name) for name in dev_workspace_lifecycle.COMPONENTS[:3]}
            port = self.context.descriptor.ports["redis"]
            proof = self._owned("redis", port, deadline)
            problem = None
            try:
                self.launcher.background_health(runtime, dict(spec.environment), require_control=True)
            except Exception as error:
                problem = error
            finally:
                self._recheck("redis", port, proof, max(deadline, self.clock() + 0.25))
                if any(self._identities(name) != saved for name, saved in identities.items()):
                    _fail("PROCESS_IDENTITY_UNVERIFIED")
            if problem is not None:
                if type(problem).__name__ == "OwnershipError":
                    _fail("PROCESS_IDENTITY_UNVERIFIED", _windows_code(problem))
                _fail("BACKGROUND_NOT_READY")
            return "BACKGROUND_READY"
        return self._run(spec.name, check)

    def database(self, timeout=5):
        def check():
            deadline, connection, problem = self._deadline(timeout), None, None
            descriptor = self.context.descriptor
            parsed = urlsplit(self.context.environment.get("DATABASE_URL", ""))
            if (descriptor.mode != "isolated" or parsed.scheme != "postgresql+psycopg" or parsed.hostname != "127.0.0.1"
                    or parsed.port != descriptor.ports["postgres"] or parsed.path != "/" + descriptor.resources["database"]
                    or unquote(parsed.username or "") != descriptor.resources["restricted_database_role"]
                    or not parsed.password or parsed.fragment):
                _fail("DATABASE_TARGET_UNVERIFIED")
            ca = self._ca()
            try:
                dev_workspace_lifecycle._tls_query(parsed, {"sslmode": "verify-full", "sslrootcert": str(ca[0]),
                                                           "gssencmode": "disable", "sslcertmode": "disable"})
            except Exception:
                _fail("DATABASE_TARGET_UNVERIFIED")
            if any(value and (name.startswith("PG") or name == "SSLKEYLOGFILE") for name, value in os.environ.items()):
                _fail("DATABASE_AMBIENT_CONFIGURATION_REFUSED")
            proof = self._owned("postgres", parsed.port, deadline)
            try:
                connect = self.db_connect
                if connect is None:
                    import psycopg
                    connect = psycopg.connect
                connection = connect(host="127.0.0.1", hostaddr="127.0.0.1", port=parsed.port,
                    dbname=descriptor.resources["database"], user=descriptor.resources["restricted_database_role"],
                    password=unquote(parsed.password), connect_timeout=max(1, int(self._remaining(deadline))), autocommit=False,
                    sslmode="verify-full", sslrootcert=str(ca[0]), gssencmode="disable", sslcertmode="disable",
                    options="-c default_transaction_read_only=on -c statement_timeout=2000 -c lock_timeout=250"
                            " -c idle_in_transaction_session_timeout=3000 -c search_path=public,pg_catalog")
                if connection.pgconn.ssl_in_use is not True:
                    _fail("TLS_VERIFICATION_REQUIRED")
                if connection.execute("SHOW transaction_read_only").fetchone() != ("on",):
                    _fail("DATABASE_NOT_READONLY")
                if connection.execute("SELECT pg_catalog.current_database(), current_user").fetchone() != (
                        descriptor.resources["database"], descriptor.resources["restricted_database_role"]):
                    _fail("DATABASE_TARGET_UNVERIFIED")
                if connection.execute("SELECT version_num FROM public.alembic_version ORDER BY version_num LIMIT 2").fetchall() != [(self.context.schema_revision,)]:
                    _fail("DATABASE_SCHEMA_NOT_READY")
            except ReadinessError as error:
                problem = error
            except BaseException as error:
                problem = ReadinessError("DATABASE_INSPECTION_FAILED", _windows_code(error))
            finally:
                if connection is not None:
                    for operation in (connection.rollback, connection.close):
                        try:
                            operation()
                        except BaseException as error:
                            problem = ReadinessError("DATABASE_CLEANUP_UNCONFIRMED", _windows_code(error))
            self._post_provider("postgres", parsed.port, proof, ca, deadline)
            if problem:
                raise problem
            return "DATABASE_READY"
        return self._run("Database", check)

    def redis(self, timeout=5, *, session=False):
        """TLS AUTH, connection-local SELECT, PING and fixed-key GET only.

        The session ACL check must reject a GET outside its exact instance
        prefix. No SET/DEL/EVAL, metadata write, queue operation or ACL mutation
        occurs. Matching provider labels/guest PIDs never substitute for host
        listener ownership supplied by the independently verified executor.
        """
        component = "Session" if session is True else "Redis"
        def check():
            if type(session) is not bool or self.context.descriptor.mode != "isolated":
                _fail("REDIS_TARGET_UNVERIFIED")
            deadline, client, problem = self._deadline(timeout), None, None
            env, descriptor = self.context.environment, self.context.descriptor
            parsed = urlsplit(env.get("AUTH_SESSION_REDIS_URL" if session else "REDIS_URL", ""))
            database = "1" if session else "0"
            if (parsed.scheme != "rediss" or parsed.hostname != "127.0.0.1" or parsed.port != descriptor.ports["redis"]
                    or parsed.path != "/" + database or unquote(parsed.username or "") != ("sbom_session" if session else "sbom_runtime")
                    or not parsed.password or parsed.fragment):
                _fail("REDIS_TARGET_UNVERIFIED")
            context, ca = self._provider_context()
            try:
                dev_workspace_lifecycle._tls_query(parsed, {} if session else {"ssl_cert_reqs": "required",
                    "ssl_check_hostname": "true", "ssl_ca_certs": str(ca[0])})
            except Exception:
                _fail("REDIS_TARGET_UNVERIFIED")
            proof = self._owned("redis", parsed.port, deadline)
            try:
                client = (self.redis_connect or _RedisProbe)(host="127.0.0.1", port=parsed.port,
                    timeout=self._provider_timeout(deadline, "REDIS_NOT_READY"), context=context, clock=self.clock)
                if client.tls_verified is not True:
                    _fail("TLS_VERIFICATION_REQUIRED")
                def command(*parts):
                    client.settimeout(self._provider_timeout(deadline, "REDIS_NOT_READY"))
                    return client.command(*parts)
                try:
                    if command("AUTH", unquote(parsed.username), unquote(parsed.password)) != b"OK":
                        _fail("REDIS_AUTHENTICATION_FAILED")
                except RedisReplyError:
                    _fail("REDIS_AUTHENTICATION_FAILED")
                if command("SELECT", database) != b"OK" or command("PING") != b"PONG":
                    _fail("REDIS_RESPONSE_UNVERIFIED")
                prefix = descriptor.resources["session_namespace" if session else "rate_limit_namespace"]
                value = command("GET", prefix + "__sbom_readiness__")
                if value is not None and type(value) is not bytes:
                    _fail("REDIS_RESPONSE_UNVERIFIED")
                if session:
                    try:
                        command("GET", "sbom:readiness:outside-session-prefix")
                    except RedisReplyError as error:
                        if not error.permission_denied:
                            _fail("REDIS_SESSION_ACL_UNVERIFIED")
                    else:
                        _fail("REDIS_SESSION_ACL_UNVERIFIED")
            except ReadinessError as error:
                problem = error
            except ssl.SSLError:
                problem = ReadinessError("TLS_VERIFICATION_REQUIRED")
            except (TimeoutError, ConnectionError, OSError) as error:
                problem = ReadinessError("REDIS_NOT_READY", _windows_code(error))
            except BaseException:
                problem = ReadinessError("REDIS_RESPONSE_UNVERIFIED")
            finally:
                if client is not None:
                    try:
                        client.close()
                    except BaseException as error:
                        problem = ReadinessError("REDIS_CLEANUP_UNCONFIRMED", _windows_code(error))
            self._post_provider("redis", parsed.port, proof, ca, deadline)
            if problem:
                raise problem
            return "SESSION_READY" if session else "REDIS_READY"
        return self._run(component, check)

    def mail(self, timeout=5):
        """Authenticate an approved SMTP listener over mandatory STARTTLS; no mail."""
        def check():
            deadline, client, problem = self._deadline(timeout), None, None
            env, descriptor = self.context.environment, self.context.descriptor
            if (descriptor.mode != "isolated" or env.get("SMTP_HOST") != "127.0.0.1"
                    or env.get("SMTP_PORT") != str(descriptor.ports["smtp"])
                    or env.get("SMTP_USE_TLS") != "false" or env.get("SMTP_USE_STARTTLS") != "true"
                    or env.get("SMTP_USERNAME") != "sbom_" + descriptor.instance_id.replace("-", "")
                    or not env.get("SMTP_PASSWORD")):
                _fail("MAIL_TARGET_UNVERIFIED")
            context, ca = self._provider_context()
            port = descriptor.ports["smtp"]
            proof = self._owned("mailpit", port, deadline)
            try:
                client = (self.smtp_connect or _SmtpProbe)(host="127.0.0.1", port=port,
                    timeout=self._provider_timeout(deadline, "MAIL_NOT_READY"), clock=self.clock)
                def operation(method, *args, **kwargs):
                    client.settimeout(self._provider_timeout(deadline, "MAIL_NOT_READY"))
                    return method(*args, **kwargs)
                if operation(client.ehlo) != 250 or client.has_extn("starttls") is not True:
                    _fail("MAIL_TLS_REQUIRED")
                if operation(client.starttls, context=context) != 220 or client.tls_verified is not True:
                    _fail("MAIL_TLS_REQUIRED")
                if operation(client.ehlo) != 250 or client.tls_verified is not True:
                    _fail("MAIL_TLS_REQUIRED")
                if operation(client.login, env["SMTP_USERNAME"], env["SMTP_PASSWORD"]) is not True:
                    _fail("MAIL_AUTHENTICATION_FAILED")
            except ReadinessError as error:
                problem = error
            except ssl.SSLError:
                problem = ReadinessError("TLS_VERIFICATION_REQUIRED")
            except (TimeoutError, ConnectionError, OSError) as error:
                problem = ReadinessError("MAIL_NOT_READY", _windows_code(error))
            except BaseException:
                problem = ReadinessError("MAIL_RESPONSE_UNVERIFIED")
            finally:
                if client is not None:
                    try:
                        client.settimeout(max(0.01, min(0.25, deadline - self.clock())))
                        client.quit()
                    except BaseException as error:
                        if problem is None:
                            problem = ReadinessError("MAIL_CLEANUP_UNCONFIRMED", _windows_code(error))
                    try:
                        client.close()
                    except BaseException as error:
                        problem = ReadinessError("MAIL_CLEANUP_UNCONFIRMED", _windows_code(error))
            self._post_provider("mailpit", port, proof, ca, deadline)
            if problem:
                raise problem
            return "MAIL_READY"
        return self._run("Mail", check)

    def authentication(self, timeout=5):
        def check():
            self._deadline(timeout)
            env, descriptor = self.context.environment, self.context.descriptor
            if (env.get("AUTH_ENABLED") != "true" or env.get("DEV_DEFAULT_TENANT") != "false"
                    or env.get("DEV_AUTH_BYPASS", "false") != "false"
                    or env.get("APP_ORIGIN") != descriptor.origin or env.get("NATIVE_PLATFORM_BOOTSTRAP_ENABLED") != "false"):
                _fail("AUTHENTICATION_CONFIGURATION_REQUIRED")
            if descriptor.auth_mode == "native":
                try:
                    self.launcher.validate_secrets(dict(env))
                    if any(env.get(key) != "true" for key in ("NATIVE_AUTH_ENABLED", "NATIVE_SECURITY_OUTBOX_ENABLED",
                           "EMAIL_DELIVERY_ENABLED", "NATIVE_AUTH_RATE_LIMIT_ENABLED")):
                        raise ValueError()
                except Exception:
                    _fail("NATIVE_PREREQUISITES_UNVERIFIED")
            else:
                self._hcl(self._deadline(timeout))
            return "AUTHENTICATION_READY"
        return self._run("Authentication", check)

    def _hcl(self, deadline):
        # Published issuer/JWKS evidence is not client registration, successful
        # login, first-user privilege approval or authorization to send mail.
        env = self.context.environment
        issuer = env.get("HCL_IAM_ISSUER", "")
        parsed = _https(issuer)
        origin = "https://" + parsed.netloc
        if (origin not in self.context.approved_identity_origins or env.get("NATIVE_AUTH_ENABLED") != "false"
                or env.get("HCL_AUTH_ENABLED") != "true" or not env.get("HCL_IAM_AUDIENCE")
                or not env.get("HCL_IAM_CLIENT_ID") or env.get("NEXT_PUBLIC_HCL_IAM_CLIENT_ID") != env["HCL_IAM_CLIENT_ID"]
                or env.get("NEXT_PUBLIC_HCL_IAM_ISSUER") != issuer
                or env.get("NEXT_PUBLIC_HCL_IAM_REDIRECT_URI") != self.context.descriptor.origin + "/api/auth/callback"):
            _fail("HCL_REGISTRATION_REQUIRED")
        ca = env.get("HCL_IAM_CA_BUNDLE")
        if ca:
            path = Path(ca) if Path(ca).is_absolute() else self.context.source_root / ca
            if not path.is_absolute() or path.resolve(strict=True) != path:
                _fail("TLS_VERIFICATION_REQUIRED")
            dev_frontend._regular(path, 1048576)
        context = _ssl_context(path if ca else None)
        def get(url):
            target = _https(url)
            if "https://" + target.netloc not in self.context.approved_identity_origins:
                _fail("HCL_REGISTRATION_REQUIRED")
            result = self.request("https", target.hostname, target.port or 443, target.path or "/", self._remaining(deadline), context)
            if result.status != 200:
                _fail("HCL_DISCOVERY_UNVERIFIED")
            return json.loads(result.body)
        document = get(env.get("HCL_IAM_DISCOVERY_URL") or issuer.rstrip("/") + "/.well-known/openid-configuration")
        if document.get("issuer") != issuer or "S256" not in document.get("code_challenge_methods_supported", ["S256"]):
            _fail("HCL_DISCOVERY_UNVERIFIED")
        keys = get(env.get("HCL_IAM_JWKS_URL") or document.get("jwks_uri", "")).get("keys")
        if not isinstance(keys, list) or not 1 <= len(keys) <= 100:
            _fail("HCL_JWKS_UNVERIFIED")
        from cryptography.hazmat.primitives.asymmetric import rsa
        for key in keys:
            if not isinstance(key, dict) or key.get("kty") != "RSA" or key.get("alg", "RS256") != "RS256" or key.get("use", "sig") != "sig" or set(key) & {"d", "p", "q", "dp", "dq", "qi"}:
                continue
            try:
                if any(type(key.get(name)) is not str or re.fullmatch(r"[A-Za-z0-9_-]{1,16384}", key[name]) is None for name in ("e", "n")):
                    continue
                values = [int.from_bytes(base64.urlsafe_b64decode(key[name] + "=" * (-len(key[name]) % 4)), "big") for name in ("e", "n")]
                if rsa.RSAPublicNumbers(*values).public_key().key_size >= 2048:
                    return
            except (ValueError, TypeError, KeyError):
                pass
        _fail("HCL_JWKS_UNVERIFIED")
