"""Explicit private visual artifacts from two owned SYNTHETIC mock previews.

Neither public Git metadata nor caller readiness flags authorize a capture.
Fresh WorkspaceReadiness observations and separately reviewed browser/OS trust
evidence are required. Client-CA TLS readiness is not browser trust. Collaborator
callbacks and the canonical launcher Runtime are trusted controller code, not an
independent privilege boundary or a sandbox against a same-user code editor.

The concrete adapter speaks Chromium CDP over a verified loopback listener using
the already installed websockets package. It never installs a browser/library,
changes trust, disables TLS/CORS/authentication, or uses an existing profile.
PNG and CDP traces remain private; their metadata proves no API/login acceptance.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib.metadata
import json
import logging
import os
import re
import stat
import subprocess
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

if __package__:
    from . import dev_environment, dev_instance_registry, dev_instance_storage, dev_private
    from . import dev_workspace_dependencies as dependencies
    from . import dev_workspace_observe as observe
    from . import dev_workspace_preview as preview
    from . import dev_workspace_readiness as readiness
    from . import dev_workspace_runtime as runtime
else:
    import dev_environment
    import dev_instance_registry
    import dev_instance_storage
    import dev_private
    import dev_workspace_dependencies as dependencies
    import dev_workspace_observe as observe
    import dev_workspace_preview as preview
    import dev_workspace_readiness as readiness
    import dev_workspace_runtime as runtime

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_BROWSERS = frozenset({"chrome", "chromium", "chromium-browser", "msedge", "chrome.exe", "msedge.exe", "Google Chrome", "Chromium", "Microsoft Edge"})
_CONTROLLERS = ("dev.py", "dev_workspace_visual.py", "dev_workspace_preview.py", "dev_workspace_runtime.py",
                "dev_workspace_readiness.py", "dev_workspace_dependencies.py", "dev_environment.py",
                "dev_private.py", "dev_instance_storage.py", "dev_instance_registry.py", "dev_windows_acl.py")
_PNG_LIMIT, _TRACE_LIMIT = 8 * 1024 * 1024, 16 * 1024 * 1024
_CODES = frozenset({
    "VISUAL_INPUT_INVALID", "VISUAL_MOCK_ONLY", "VISUAL_COMPARISON_UNVERIFIED", "VISUAL_CONTEXT_UNVERIFIED",
    "VISUAL_SOURCE_CHANGED", "VISUAL_BROWSER_UNAVAILABLE", "VISUAL_BROWSER_EXECUTABLE_UNVERIFIED",
    "VISUAL_LIBRARY_UNAVAILABLE", "VISUAL_BROWSER_TRUST_REQUIRED", "VISUAL_CONSENT_REQUIRED",
    "VISUAL_ARTIFACT_TARGET_EXISTS", "VISUAL_PRIVATE_DIRECTORY_REQUIRED", "VISUAL_BROWSER_IDENTITY_UNVERIFIED",
    "VISUAL_DEBUGGER_OWNERSHIP_UNVERIFIED", "VISUAL_PROTOCOL_UNSUPPORTED", "VISUAL_TIMEOUT",
    "VISUAL_SYNTHETIC_PAGE_REQUIRED", "VISUAL_CAPTURE_FAILED", "VISUAL_ARTIFACT_INVALID",
    "VISUAL_CLEANUP_UNCONFIRMED", "VISUAL_CAPTURE_COMPLETED", "VISUAL_CANCELLED",
    "VISUAL_BROWSER_CANDIDATE",
})


class VisualError(ValueError):
    def __init__(self, code, *, probe_pid=None):
        self.code = code if type(code) is str and code in _CODES else "VISUAL_CAPTURE_FAILED"
        self.probe_pid = probe_pid if type(probe_pid) is int and 0 < probe_pid <= 0xFFFFFFFF else None
        super().__init__(self.code)


def _fail(code, **kwargs):
    raise VisualError(code, **kwargs) from None


def _uuid(value):
    if type(value) is not str:
        _fail("VISUAL_INPUT_INVALID")
    try:
        if str(UUID(value)) == value:
            return value
    except ValueError:
        pass
    _fail("VISUAL_INPUT_INVALID")


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _file(path, limit=1048576):
    try:
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise ValueError()
        # The streaming executable reader compares birth/content identities, not
        # Windows' filename-derived .exe execute bits against descriptor mode.
        return None, tuple(dependencies._file(path, path.parent, limit)[1:])
    except Exception:
        _fail("VISUAL_SOURCE_CHANGED")


def _controllers():
    directory = Path(__file__).resolve(strict=True).parent
    return tuple((name, _file(directory / name)[1]) for name in _CONTROLLERS)


@dataclass(frozen=True, slots=True)
class Viewport:
    width: int = 1280
    height: int = 800

    def __post_init__(self):
        if any(type(value) is not int or not 320 <= value <= 1920 for value in (self.width, self.height)):
            _fail("VISUAL_INPUT_INVALID")


@dataclass(frozen=True, slots=True, repr=False)
class VisualContext:
    preview: preview.PreviewPlan
    location: runtime.RuntimeLocation
    specification: runtime.ComponentLaunch
    runtime_outcome: runtime.RuntimeOutcome

    def __post_init__(self):
        if (type(self.preview) is not preview.PreviewPlan or type(self.location) is not runtime.RuntimeLocation
                or type(self.specification) is not runtime.ComponentLaunch
                or type(self.runtime_outcome) is not runtime.RuntimeOutcome):
            _fail("VISUAL_CONTEXT_UNVERIFIED")
        descriptor = self.preview.descriptor
        if descriptor.mode != "mock" or self.preview.shared_backend is not None:
            _fail("VISUAL_MOCK_ONLY")
        spec = self.specification
        expected = (str(self.preview.node), "--require", str(self.preview.guard),
                    str(self.preview.node_modules / "next/dist/bin/next"), "dev", "--webpack", "--hostname", "127.0.0.1",
                    "--port", str(descriptor.ports["frontend"]), "--experimental-https",
                    "--experimental-https-key", str(self.preview.tls.private_key),
                    "--experimental-https-cert", str(self.preview.tls.certificate),
                    "--experimental-https-ca", str(self.preview.tls.ca_bundle))
        if (descriptor != self.location.descriptor or self.preview.state_anchor != self.location.anchor
                or spec.name != "Frontend" or spec.cwd != self.preview.workspace
                or spec.argv != expected
                or spec.environment.get("SBOM_DEV_FRONTEND_WORKSPACE") != str(self.preview.workspace)
                or spec.environment.get("SBOM_DEV_FRONTEND_SOURCE") != str(self.preview.workspace.parent / "mock-source")
                or any(key.startswith("NEXT_PUBLIC_") or key in {"SBOM_API_URL", "AUTH_SESSION_REDIS_URL"}
                       for key in spec.environment)
                or spec.port != descriptor.ports["frontend"]
                or spec.environment.get("SBOM_DEV_RESOURCE_ID") != descriptor.instance_id
                or self.runtime_outcome.ready is not True or self.runtime_outcome.exit_code != 0):
            _fail("VISUAL_CONTEXT_UNVERIFIED")

    def __repr__(self):
        return "<VisualContext: synthetic mock, fresh ownership and browser trust required>"


@dataclass(frozen=True, slots=True)
class BrowserCapability:
    code: str
    available: bool
    probed: bool = False

    def __post_init__(self):
        if self.code not in _CODES or type(self.available) is not bool or type(self.probed) is not bool:
            _fail("VISUAL_INPUT_INVALID")

    def to_dict(self):
        return {"code": self.code, "available": self.available, "browser_probed": self.probed,
                "trust_verified": False}


def detect_browser(executable):
    """Read-only capability inventory, followed by a real bounded CDP version probe at capture.

    Explicit current-user-owned portable Chromium is supported on Windows. An
    OS-owned enterprise browser needs a separately reviewed executable ACL
    adapter; its ownership is never guessed or repaired here.
    """
    try:
        path = Path(executable)
        if not os.path.lexists(path):
            return BrowserCapability("VISUAL_BROWSER_UNAVAILABLE", False)
        if path.name not in _BROWSERS:
            _fail("VISUAL_BROWSER_EXECUTABLE_UNVERIFIED")
        _file(path, 268435456)
        info = path.lstat()
        if sys.platform == "win32":
            if __package__:
                from .dev_windows_acl import verify_access
            else:
                from dev_windows_acl import verify_access
            verify_access(path, private=False)
        elif (info.st_uid not in {0, os.getuid()} or stat.S_IMODE(info.st_mode) & 0o022
              or not stat.S_IMODE(info.st_mode) & 0o111 or info.st_mode & (stat.S_ISUID | stat.S_ISGID)):
            _fail("VISUAL_BROWSER_EXECUTABLE_UNVERIFIED")
        for package, major in (("websockets", "16"), ("Pillow", None)):
            version = importlib.metadata.version(package)
            if major and version.split(".")[0] != major:
                _fail("VISUAL_LIBRARY_UNAVAILABLE")
        return BrowserCapability("VISUAL_BROWSER_CANDIDATE", True)
    except importlib.metadata.PackageNotFoundError:
        return BrowserCapability("VISUAL_LIBRARY_UNAVAILABLE", False)
    except VisualError as error:
        return BrowserCapability(error.code, False)
    except Exception:
        return BrowserCapability("VISUAL_BROWSER_EXECUTABLE_UNVERIFIED", False)


@dataclass(frozen=True, slots=True, repr=False)
class VisualPlan:
    comparison: observe.ComparisonReport
    baseline: VisualContext
    candidate: VisualContext
    operation_id: str
    browser: Path
    viewport: Viewport
    route: str
    controller_proofs: tuple
    browser_proof: tuple
    fingerprint: str

    def to_dict(self):
        return {"operation_id": self.operation_id, "category": "visual-artifacts", "mode": "mock",
                "baseline": {"instance_id": self.baseline.preview.descriptor.instance_id,
                             "commit": self.baseline.preview.descriptor.commit},
                "candidate": {"instance_id": self.candidate.preview.descriptor.instance_id,
                              "commit": self.candidate.preview.descriptor.commit},
                "viewport": {"width": self.viewport.width, "height": self.viewport.height},
                "routes": [self.route], "artifacts": ["screenshot", "cdp-trace", "pixel-diff"],
                "functional_acceptance_verified": False, "api_verified": False, "login_verified": False,
                "browser_trust_required": True}

    def __repr__(self):
        return "<VisualPlan: explicit private synthetic artifact consent required>"


def plan_visual(comparison, baseline, candidate, *, operation_id, browser_executable, viewport=None, route="/"):
    if (type(comparison) is not observe.ComparisonReport or comparison.status != "OBSERVED" or comparison.codes
            or type(baseline) is not VisualContext or type(candidate) is not VisualContext):
        _fail("VISUAL_COMPARISON_UNVERIFIED")
    _uuid(operation_id)
    viewport = viewport or Viewport()
    if type(viewport) is not Viewport or route != "/":
        _fail("VISUAL_INPUT_INVALID")
    for row, context in ((comparison.baseline, baseline), (comparison.candidate, candidate)):
        descriptor = context.preview.descriptor
        if (row is None or row.descriptor != descriptor or row.head != descriptor.commit or row.dirty
                or row.worktree_id != descriptor.worktree_id):
            _fail("VISUAL_COMPARISON_UNVERIFIED")
    if (baseline.preview.descriptor.repository_id != candidate.preview.descriptor.repository_id
            or baseline.preview.descriptor.worktree_id == candidate.preview.descriptor.worktree_id
            or baseline.location.root == candidate.location.root
            or baseline.preview.descriptor.origin == candidate.preview.descriptor.origin):
        _fail("VISUAL_COMPARISON_UNVERIFIED")
    browser = Path(browser_executable)
    proofs, executable = _controllers(), _file(browser, 268435456)[1]
    binding = [comparison.to_dict(), baseline.preview.fingerprint, candidate.preview.fingerprint,
               baseline.location.identity, candidate.location.identity, operation_id, str(browser),
               [viewport.width, viewport.height], route, proofs, executable]
    return VisualPlan(comparison, baseline, candidate, operation_id, browser, viewport, route,
                      proofs, executable, _digest(binding))


def _revalidate(plan):
    if type(plan) is not VisualPlan:
        _fail("VISUAL_INPUT_INVALID")
    if plan_visual(plan.comparison, plan.baseline, plan.candidate, operation_id=plan.operation_id,
                   browser_executable=plan.browser, viewport=plan.viewport, route=plan.route) != plan:
        _fail("VISUAL_SOURCE_CHANGED")
    for context in (plan.baseline, plan.candidate):
        if runtime.RuntimeLocation(context.location.descriptor, context.location.root, context.location.anchor) != context.location:
            _fail("VISUAL_CONTEXT_UNVERIFIED")
        preview.require_preview(context.preview)


@dataclass(frozen=True, slots=True, repr=False)
class BrowserTrustEvidence:
    """Returned ONLY by a trusted live OS/browser trust adapter, never loaded from JSON.

    The adapter must inspect the selected browser's real trust mechanism for the
    newly created profile, pin the exact existing leaf/CA and verify hostname.
    Merely checking the explicit Python CA store does not satisfy this contract.
    """
    instance_id: str
    origin: str
    browser_sha256: str
    profile_identity: tuple[int, int]
    certificate_sha256: str
    trust_scope: str

    def __post_init__(self):
        _uuid(self.instance_id)
        if (type(self.origin) is not str or not self.origin.startswith("https://")
                or any(type(value) is not str or _HASH.fullmatch(value) is None
                       for value in (self.browser_sha256, self.certificate_sha256))
                or type(self.profile_identity) is not tuple or len(self.profile_identity) != 2
                or any(type(value) is not int or value < 0 for value in self.profile_identity)
                or self.trust_scope != "verified-browser-os-store"):
            _fail("VISUAL_BROWSER_TRUST_REQUIRED")

    def __repr__(self):
        return "<BrowserTrustEvidence: live OS/browser adapter observation required>"


def _browser_trust(plan, context, profile, identity, verifier, budget):
    evidence = runtime._bounded(lambda: verifier(context, plan.browser, profile, budget), budget)
    if (type(evidence) is not BrowserTrustEvidence or evidence.instance_id != context.preview.descriptor.instance_id
            or evidence.origin != context.preview.descriptor.origin or evidence.browser_sha256 != plan.browser_proof[-1]
            or evidence.profile_identity != identity
            or evidence.certificate_sha256 != _file(context.preview.tls.certificate)[1][-1]):
        _fail("VISUAL_BROWSER_TRUST_REQUIRED")
    return evidence


def _verify_live(context, reader, timeout):
    if (type(reader) is not readiness.WorkspaceReadiness or reader.context.descriptor != context.preview.descriptor
            or reader.context.runtime_root != context.location.root or reader.context.source_root != context.preview.selected.root):
        _fail("VISUAL_CONTEXT_UNVERIFIED")
    preview.require_preview(context.preview)
    try:
        if reader.frontend(context.specification, timeout) is not True:
            _fail("VISUAL_CONTEXT_UNVERIFIED")
        result = reader.results.get("Frontend")
        if type(result) is not readiness.ReadinessResult or (result.status, result.code) != ("PASS", "FRONTEND_READY"):
            _fail("VISUAL_CONTEXT_UNVERIFIED")
        return reader._owned("Frontend", context.preview.descriptor.ports["frontend"], reader.clock() + min(timeout, 3))
    except readiness.ReadinessError:
        _fail("VISUAL_CONTEXT_UNVERIFIED")


@dataclass(frozen=True, slots=True)
class CaptureData:
    png: bytes = field(repr=False)
    trace: bytes = field(repr=False)
    browser_version: str

    def __post_init__(self):
        if (type(self.png) is not bytes or not self.png.startswith(b"\x89PNG\r\n\x1a\n") or len(self.png) > _PNG_LIMIT
                or type(self.trace) is not bytes or not 0 < len(self.trace) <= _TRACE_LIMIT
                or type(self.browser_version) is not str
                or re.fullmatch(r"(?:HeadlessChrome|Chrome|Chromium|Edg)/[0-9.]{1,32}", self.browser_version) is None):
            _fail("VISUAL_ARTIFACT_INVALID")


@dataclass(frozen=True, slots=True)
class Artifact:
    file_id: str
    role: str
    kind: str
    sha256: str
    size: int
    commit: str
    width: int
    height: int
    controller_sha256: str
    browser_version: str

    def __post_init__(self):
        _uuid(self.file_id)
        if (self.role not in {"baseline", "candidate", "comparison"}
                or self.kind not in {"screenshot", "cdp-trace", "pixel-diff"}
                or any(type(value) is not str or _HASH.fullmatch(value) is None
                       for value in (self.sha256, self.controller_sha256))
                or type(self.commit) is not str or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", self.commit) is None
                or type(self.size) is not int or not 0 < self.size <= _TRACE_LIMIT
                or re.fullmatch(r"(?:HeadlessChrome|Chrome|Chromium|Edg)/[0-9.]{1,32}", self.browser_version) is None):
            _fail("VISUAL_ARTIFACT_INVALID")
        Viewport(self.width, self.height)

    def to_dict(self):
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class VisualOutcome:
    code: str
    artifacts: tuple[Artifact, ...] = ()
    byte_equal: bool | None = None
    changed_pixels: int | None = None
    cleanup_verified: bool = True
    retained_browser_pids: tuple[int, ...] = ()

    def __post_init__(self):
        if (type(self.code) is not str or self.code not in _CODES or type(self.artifacts) is not tuple
                or any(type(item) is not Artifact for item in self.artifacts)
                or self.byte_equal is not None and type(self.byte_equal) is not bool
                or self.changed_pixels is not None and (type(self.changed_pixels) is not int or self.changed_pixels < 0)
                or type(self.cleanup_verified) is not bool or type(self.retained_browser_pids) is not tuple
                or any(type(pid) is not int or not 0 < pid <= 0xFFFFFFFF for pid in self.retained_browser_pids)):
            _fail("VISUAL_INPUT_INVALID")

    def to_dict(self):
        return {"code": self.code, "status": "CAPTURED" if self.code == "VISUAL_CAPTURE_COMPLETED" else "BLOCKED",
                "exit_code": 0 if self.code == "VISUAL_CAPTURE_COMPLETED" else 1,
                "artifacts": [item.to_dict() for item in self.artifacts], "byte_equal": self.byte_equal,
                "changed_pixels": self.changed_pixels, "cleanup_verified": self.cleanup_verified,
                "retained_browser_pids": list(self.retained_browser_pids),
                "functional_acceptance_verified": False, "api_verified": False, "login_verified": False,
                "browser_trust_modified": False, "artifacts_private": True}


def _directory(path, anchor):
    dev_instance_storage.initialize_private_directory(path, anchor=anchor)
    return dev_instance_storage._identity(dev_instance_storage._verify(path, private=True))


def _new_directory(path, anchor):
    if os.path.lexists(path):
        _fail("VISUAL_ARTIFACT_TARGET_EXISTS")
    _directory(path.parent, anchor)
    dependencies._exclusive_directory(path, path.parent)
    return dev_instance_storage._identity(dev_instance_storage._verify(path, private=True))


def _directory_unchanged(path, expected):
    if dev_instance_storage._identity(dev_instance_storage._verify(path, private=True)) != expected:
        _fail("VISUAL_PRIVATE_DIRECTORY_REQUIRED")


def _write(path, raw, root):
    dev_private.validate_parent(path, root)
    dev_private.create_private_file(path, raw)
    before = dev_instance_registry._private(path)
    observed = dev_environment.bounded_read_bytes(path, max(_PNG_LIMIT, _TRACE_LIMIT))
    if observed != raw or dev_instance_registry._stamp(dev_instance_registry._private(path)) != dev_instance_registry._stamp(before):
        _fail("VISUAL_ARTIFACT_INVALID")


def _pixel_diff(left, right, viewport):
    from io import BytesIO

    from PIL import Image, ImageChops

    result = []
    for raw in (left, right):
        with Image.open(BytesIO(raw)) as image:
            if image.format != "PNG" or image.size != (viewport.width, viewport.height):
                _fail("VISUAL_ARTIFACT_INVALID")
            result.append(image.convert("RGB"))
    diff = ImageChops.difference(*result)
    mask = ImageChops.lighter(ImageChops.lighter(diff.getchannel("R"), diff.getchannel("G")), diff.getchannel("B"))
    count = viewport.width * viewport.height - mask.histogram()[0]
    output = BytesIO()
    diff.save(output, format="PNG")
    return output.getvalue(), count


def execute_visual(plan, *, authorize, readers, verify_browser_trust=None, browser_adapter=None, timeout=60):
    """User-level synthetic-artifact action, no provider/Native authority.

    All callbacks are trusted controller integrations. No callback default,
    persisted flag or runtime READY label substitutes for fresh OS/browser trust.
    Browser adapter must own its original subprocess and verified descendants;
    uncertainty is reported and its protected records/profile are retained.
    """
    artifacts, captures, pids = [], [], []
    try:
        if (type(timeout) not in {int, float} or not 0 < timeout <= 120
                or not isinstance(readers, Mapping) or set(readers) != {"baseline", "candidate"}):
            _fail("VISUAL_INPUT_INVALID")
        if not callable(verify_browser_trust):
            _fail("VISUAL_BROWSER_TRUST_REQUIRED")
        if not callable(getattr(browser_adapter, "capture", None)):
            _fail("VISUAL_BROWSER_UNAVAILABLE")
        _revalidate(plan)
        if authorize(plan, "visual-artifacts") is not True:
            _fail("VISUAL_CONSENT_REQUIRED")
        _revalidate(plan)
        capability = browser_adapter.capability(plan.browser)
        if type(capability) is not BrowserCapability or not capability.available:
            _fail(capability.code if type(capability) is BrowserCapability else "VISUAL_BROWSER_UNAVAILABLE")
        deadline = time.monotonic() + timeout
        directories, directory_pins = {}, {}
        for role, context in (("baseline", plan.baseline), ("candidate", plan.candidate)):
            path = context.location.root / "visual" / plan.operation_id
            if os.path.lexists(path):
                _fail("VISUAL_ARTIFACT_TARGET_EXISTS")
            directories[role] = path
        for role, context in (("baseline", plan.baseline), ("candidate", plan.candidate)):
            _revalidate(plan)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _fail("VISUAL_TIMEOUT")
            before = _verify_live(context, readers[role], min(remaining, 5))
            directory = directories[role]
            directory_identity = _new_directory(directory, context.location.anchor)
            directory_pins[role] = directory_identity
            profile = directory / "browser-profile"
            identity = _new_directory(profile, context.location.anchor)
            trust = _browser_trust(plan, context, profile, identity, verify_browser_trust, min(remaining, 5))
            _revalidate(plan)
            _directory_unchanged(directory, directory_identity)
            _directory_unchanged(profile, identity)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _fail("VISUAL_TIMEOUT")
            if _verify_live(context, readers[role], min(remaining, 5)) != before:
                _fail("VISUAL_CONTEXT_UNVERIFIED")
            capture = browser_adapter.capture(plan, context, profile, directory, deadline)
            if type(capture) is not CaptureData:
                _fail("VISUAL_ARTIFACT_INVALID")
            _revalidate(plan)
            _directory_unchanged(directory, directory_identity)
            _directory_unchanged(profile, identity)
            if _browser_trust(plan, context, profile, identity, verify_browser_trust,
                              min(max(deadline - time.monotonic(), 0.25), 5)) != trust:
                _fail("VISUAL_BROWSER_TRUST_REQUIRED")
            if _verify_live(context, readers[role], min(max(deadline - time.monotonic(), 0.25), 5)) != before:
                _fail("VISUAL_CONTEXT_UNVERIFIED")
            captures.append(capture)
            for kind, suffix, raw in (("screenshot", "png", capture.png), ("cdp-trace", "json", capture.trace)):
                _directory_unchanged(directory, directory_identity)
                file_id = str(UUID(bytes=os.urandom(16), version=4))
                _write(directory / (file_id + "." + suffix), raw, directory)
                artifacts.append(Artifact(file_id, role, kind, hashlib.sha256(raw).hexdigest(), len(raw),
                                          context.preview.descriptor.commit, plan.viewport.width, plan.viewport.height,
                                          dict(plan.controller_proofs)["dev_workspace_visual.py"][-1], capture.browser_version))
        _revalidate(plan)
        for role, directory in directories.items():
            _directory_unchanged(directory, directory_pins[role])
        if captures[0].browser_version != captures[1].browser_version:
            _fail("VISUAL_SOURCE_CHANGED")
        diff, changed = _pixel_diff(captures[0].png, captures[1].png, plan.viewport)
        file_id = str(UUID(bytes=os.urandom(16), version=4))
        _write(directories["candidate"] / (file_id + ".png"), diff, directories["candidate"])
        artifacts.append(Artifact(file_id, "comparison", "pixel-diff", hashlib.sha256(diff).hexdigest(), len(diff),
                                  plan.candidate.preview.descriptor.commit, plan.viewport.width, plan.viewport.height,
                                  dict(plan.controller_proofs)["dev_workspace_visual.py"][-1], captures[1].browser_version))
        outcome = VisualOutcome("VISUAL_CAPTURE_COMPLETED", tuple(artifacts), captures[0].png == captures[1].png, changed)
        _write(directories["candidate"] / ".visual-artifacts.json",
               json.dumps(outcome.to_dict(), sort_keys=True).encode("ascii"), directories["candidate"])
        return outcome
    except VisualError as error:
        if error.probe_pid is not None:
            pids.append(error.probe_pid)
        return VisualOutcome(error.code, tuple(artifacts),
                             cleanup_verified=error.code != "VISUAL_CLEANUP_UNCONFIRMED" and not pids,
                             retained_browser_pids=tuple(pids))
    except (KeyboardInterrupt, EOFError):
        return VisualOutcome("VISUAL_CANCELLED", tuple(artifacts))
    except Exception:
        return VisualOutcome("VISUAL_CAPTURE_FAILED", tuple(artifacts))


class _Cdp:
    def __init__(self, connection, origin, deadline):
        self.connection, self.origin, self.deadline, self.serial = connection, origin, deadline, 0
        self.events = []

    async def call(self, method, parameters=None, session=None):
        self.serial += 1
        request = {"id": self.serial, "method": method, "params": parameters or {}}
        if session:
            request["sessionId"] = session
        await self.connection.send(json.dumps(request))
        while True:
            event = json.loads(await self.connection.recv())
            if type(event) is not dict:
                _fail("VISUAL_PROTOCOL_UNSUPPORTED")
            if event.get("method") == "Fetch.requestPaused":
                paused = event.get("params", {})
                url = urlsplit(paused.get("request", {}).get("url", ""))
                allowed = url.scheme == "https" and f"{url.scheme}://{url.netloc}" == self.origin and (
                    url.path == "/" or url.path.startswith("/_next/"))
                self.serial += 1
                await self.connection.send(json.dumps({"id": self.serial,
                    "method": "Fetch.continueRequest" if allowed else "Fetch.failRequest",
                    "params": {"requestId": paused["requestId"], **({} if allowed else {"errorReason": "BlockedByClient"})},
                    "sessionId": event.get("sessionId", session)}))
            elif event.get("id") == request["id"]:
                if "error" in event or type(event.get("result")) is not dict:
                    _fail("VISUAL_PROTOCOL_UNSUPPORTED")
                return event["result"]
            elif event.get("method") in {"Page.loadEventFired", "Tracing.tracingComplete"}:
                if len(self.events) >= 4096:
                    _fail("VISUAL_ARTIFACT_INVALID")
                self.events.append(event)

    async def event(self, method):
        while True:
            for index, event in enumerate(self.events):
                if event.get("method") == method:
                    return self.events.pop(index).get("params", {})
            await self.call("Browser.getVersion")


class ChromiumCdpAdapter:
    """Concrete Chromium adapter; caller supplies canonical Runtime/OS identity APIs.

    Browser.getVersion is the bounded actual capability probe. The browser
    process, renderer descendants and any uncertain records use the existing
    Runtime ownership/cleanup rules. No personal browser CDP port is discovered.
    The fresh private profile and all uncertain artifacts are retained.
    """
    def __init__(self, *, runtime_factory, atomic_json, process_info, matches, listener_inspector=readiness.listener_pids,
                 popen=None, connect=None, transport=None):
        self.factory, self.process_info, self.matches = runtime_factory, process_info, matches
        self.atomic_json = atomic_json
        self.listener_inspector, self.popen, self.connect = listener_inspector, popen or subprocess.Popen, connect
        self.transport = dict(runtime.minimal_transport(transport or {}))
        if sys.platform == "darwin" and listener_inspector is readiness.listener_pids:
            def inspect(address, port, pids, *, timeout=2):
                def probe(argv, **kwargs):
                    return readiness.owned_lsof_probe(argv, process_info=self.process_info, matches=self.matches,
                                                      **{**kwargs, "timeout": min(timeout, 5)})
                return readiness.listener_pids(address, port, pids, mac_probe=probe, timeout=timeout)
            self.listener_inspector = inspect

    capability = staticmethod(detect_browser)

    def _owned(self, ledger, child):
        ledger.refresh()
        record = ledger.state["services"].get("Visual browser")
        if (not record or record.get("tree_unverified") or ledger.service_status(record) != "RUNNING"
                or record.get("pid") != child.pid):
            _fail("VISUAL_BROWSER_IDENTITY_UNVERIFIED", probe_pid=child.pid)
        records = (record, *record.get("members", ()))
        result = {}
        for saved in records:
            current = self.process_info(saved["pid"])
            if current is None and saved["pid"] != child.pid:
                continue  # Confirmed child exit; canonical Runtime retains its tree history.
            if not current or not saved.get("birth") or not saved.get("exe") or not self.matches(saved, current):
                _fail("VISUAL_BROWSER_IDENTITY_UNVERIFIED", probe_pid=child.pid)
            result[saved["pid"]] = (saved["birth"], saved["exe"])
        return result

    def capture(self, plan, context, profile, directory, deadline):
        ledger, child, result, failure = None, None, None, None
        acquired, owned_ledger, cleanup_verified = False, False, False
        state_writer = self.atomic_json
        try:
            expected = context.location.root / "visual" / plan.operation_id
            if directory != expected or profile != directory / "browser-profile" or any(profile.iterdir()):
                _fail("VISUAL_PRIVATE_DIRECTORY_REQUIRED")
            profile_identity = dev_instance_storage._identity(dev_instance_storage._verify(profile, private=True))
            ledger_root = directory / "browser-runtime"
            _new_directory(ledger_root, context.location.anchor)
            ledger = self.factory(ledger_root)
            if (ledger.root != ledger_root or ledger.path != ledger_root / ".dev-runtime.json"
                    or ledger.stop_path != ledger_root / ".dev-runtime.stop"):
                _fail("VISUAL_BROWSER_IDENTITY_UNVERIFIED")
            configure = getattr(ledger, "configure_private_io", None)
            if callable(configure):
                def publish(path, value):
                    return runtime.private_atomic_json(path, value, root=ledger_root)
                configure(state_writer=publish,
                          lock_creator=lambda path: runtime.private_runtime_lock(path, root=ledger_root))
                state_writer = publish
            acquired = ledger.acquire()
            if acquired is not True or ledger.load() is not None:
                _fail("VISUAL_BROWSER_IDENTITY_UNVERIFIED")
            ledger.begin("visual")
            owned_ledger = True
            if _file(plan.browser, 268435456)[1] != plan.browser_proof:
                _fail("VISUAL_BROWSER_EXECUTABLE_UNVERIFIED")
            argv = (str(plan.browser), "--headless=new", "--remote-debugging-address=127.0.0.1", "--remote-debugging-port=0",
                    "--user-data-dir=" + str(profile), "--no-first-run", "--no-default-browser-check", "--disable-sync",
                    "--disable-background-networking", "--disable-component-update", "--disable-extensions", "--no-proxy-server",
                    "--host-resolver-rules=MAP " + context.preview.descriptor.hostname + " 127.0.0.1, EXCLUDE localhost", "about:blank")
            options = {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200)} if sys.platform == "win32" else {"start_new_session": True}
            child = self.popen(argv, cwd=directory, env=self.transport, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True, **options)
            ledger.processes[child.pid] = child
            try:
                ledger.register("Visual browser", child.pid)
            except BaseException:
                ledger.state["services"].setdefault("Visual browser",
                    {"pid": child.pid, "birth": None, "exe": None, "members": [], "tree_unverified": True})
                state_writer(ledger.path, ledger.state)
                _fail("VISUAL_BROWSER_IDENTITY_UNVERIFIED", probe_pid=child.pid)
            active = profile / "DevToolsActivePort"
            while not os.path.lexists(active) and time.monotonic() < deadline:
                self._owned(ledger, child)
                time.sleep(0.02)
            if not os.path.lexists(active):
                _fail("VISUAL_TIMEOUT")
            before = self._owned(ledger, child)
            if Path(before[child.pid][1]) != plan.browser:
                _fail("VISUAL_BROWSER_IDENTITY_UNVERIFIED", probe_pid=child.pid)
            _directory_unchanged(profile, profile_identity)
            raw = dev_environment.bounded_read_bytes(active, 512).decode("ascii").splitlines()
            if (len(raw) != 2 or re.fullmatch(r"[0-9]{1,5}", raw[0]) is None or not 1024 <= int(raw[0]) <= 65535
                    or re.fullmatch(r"/devtools/browser/[A-Za-z0-9-]{1,80}", raw[1]) is None):
                _fail("VISUAL_PROTOCOL_UNSUPPORTED")
            port = int(raw[0])
            owners = self.listener_inspector("127.0.0.1", port, frozenset(before), timeout=min(3, max(0.01, deadline - time.monotonic())))
            if not owners or not set(owners) <= set(before) or self._owned(ledger, child) != before:
                _fail("VISUAL_DEBUGGER_OWNERSHIP_UNVERIFIED")
            result = asyncio.run(self._capture_cdp(plan, context, "ws://127.0.0.1:" + str(port) + raw[1], deadline))
            after = self._owned(ledger, child)
            _directory_unchanged(profile, profile_identity)
            owners_after = self.listener_inspector("127.0.0.1", port, frozenset(after), timeout=1)
            if (after.get(child.pid) != before.get(child.pid) or not owners_after
                    or not set(owners_after) <= set(after)):
                _fail("VISUAL_BROWSER_IDENTITY_UNVERIFIED", probe_pid=child.pid)
        except BaseException as error:
            failure = error
        finally:
            if owned_ledger:
                try:
                    ledger.refresh()
                    cleanup_verified = ledger.stop_services(lambda *items: None) is True
                    if not cleanup_verified:
                        failure = VisualError("VISUAL_CLEANUP_UNCONFIRMED", probe_pid=child.pid if child else None)
                except BaseException:
                    failure = VisualError("VISUAL_CLEANUP_UNCONFIRMED", probe_pid=child.pid if child else None)
            if acquired:
                try:
                    ledger.release()
                except BaseException:
                    failure = VisualError("VISUAL_CLEANUP_UNCONFIRMED", probe_pid=child.pid if child else None)
        if failure is not None:
            if isinstance(failure, VisualError):
                if cleanup_verified and failure.code != "VISUAL_CLEANUP_UNCONFIRMED":
                    raise VisualError(failure.code) from None
                raise failure
            if isinstance(failure, (KeyboardInterrupt, EOFError)):
                raise failure
            if isinstance(failure, runtime.RuntimeAdapterError) and failure.code == "INSTANCE_RUNTIME_RECORD_UNVERIFIED":
                _fail("VISUAL_BROWSER_IDENTITY_UNVERIFIED")
            _fail("VISUAL_CAPTURE_FAILED")
        return result

    async def _capture_cdp(self, plan, context, endpoint, deadline):
        connect = self.connect
        if connect is None:
            from websockets.asyncio.client import connect
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _fail("VISUAL_TIMEOUT")
        try:
            async with asyncio.timeout(remaining):
                # Own a disabled logger; library debug frames can contain PNGs
                # and trace data. Never inherit the application's log handlers.
                quiet = logging.Logger("sbom-private-visual-cdp", level=logging.CRITICAL + 1)
                quiet.disabled, quiet.propagate = True, False
                async with connect(endpoint, proxy=None, compression=None, open_timeout=min(remaining, 5),
                                   close_timeout=1, max_size=24 * 1024 * 1024, max_queue=16, logger=quiet) as connection:
                    cdp = _Cdp(connection, context.preview.descriptor.origin, deadline)
                    version = (await cdp.call("Browser.getVersion")).get("product", "")
                    target = (await cdp.call("Target.createTarget", {"url": "about:blank"}))["targetId"]
                    session = (await cdp.call("Target.attachToTarget", {"targetId": target, "flatten": True}))["sessionId"]
                    for method in ("Page.enable", "Network.enable", "Runtime.enable"):
                        await cdp.call(method, session=session)
                    await cdp.call("Fetch.enable", {"patterns": [{"urlPattern": "*"}]}, session)
                    await cdp.call("Emulation.setDeviceMetricsOverride", {"width": plan.viewport.width,
                        "height": plan.viewport.height, "deviceScaleFactor": 1, "mobile": False}, session)
                    await cdp.call("Tracing.start", {"transferMode": "ReturnAsStream", "categories": "devtools.timeline,blink.user_timing"})
                    navigation = await cdp.call("Page.navigate", {"url": context.preview.descriptor.origin + plan.route}, session)
                    if navigation.get("errorText"):
                        _fail("VISUAL_BROWSER_TRUST_REQUIRED")
                    await cdp.event("Page.loadEventFired")
                    expression = "location.origin===" + json.dumps(context.preview.descriptor.origin) + " && document.body.innerText.includes('MOCK VISUAL PREVIEW — SYNTHETIC DATA')"
                    label = await cdp.call("Runtime.evaluate", {"expression": expression, "returnByValue": True}, session)
                    if label.get("result", {}).get("value") is not True:
                        _fail("VISUAL_SYNTHETIC_PAGE_REQUIRED")
                    encoded = (await cdp.call("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": False}, session))["data"]
                    if type(encoded) is not str or len(encoded) > ((_PNG_LIMIT + 2) // 3) * 4:
                        _fail("VISUAL_ARTIFACT_INVALID")
                    png = base64.b64decode(encoded, validate=True)
                    await cdp.call("Tracing.end")
                    handle = (await cdp.event("Tracing.tracingComplete"))["stream"]
                    trace = bytearray()
                    while True:
                        chunk = await cdp.call("IO.read", {"handle": handle, "size": 65536})
                        raw = base64.b64decode(chunk["data"], validate=True) if chunk.get("base64Encoded") else chunk["data"].encode("utf-8")
                        if len(trace) + len(raw) > _TRACE_LIMIT:
                            _fail("VISUAL_ARTIFACT_INVALID")
                        trace.extend(raw)
                        if chunk.get("eof") is True:
                            break
                    await cdp.call("IO.close", {"handle": handle})
                    return CaptureData(png, bytes(trace), version)
        except TimeoutError:
            _fail("VISUAL_TIMEOUT")
