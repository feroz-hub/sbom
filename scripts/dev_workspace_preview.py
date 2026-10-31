"""Separate visual previews; preparation never starts a process or a data service.

Mock pages contain synthetic data and selected public design tokens, not app auth
routes. Shared previews execute trusted selected frontend code only after the
caller's runtime adapter verifies the registered backend/TLS/auth/session/tenant.
Those callbacks are trusted integration code, not independent privileged or
Native enrollment authority. This module is not a JavaScript/network sandbox.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from urllib.parse import urlsplit

if __package__:
    from . import (
        dev_components,
        dev_config,
        dev_frontend,
        dev_instance_plan,
        dev_instance_registry,
        dev_instance_storage,
        dev_private,
        dev_workspace,
        dev_workspace_dependencies,
    )
else:
    import dev_components
    import dev_config
    import dev_frontend
    import dev_instance_plan
    import dev_instance_registry
    import dev_instance_storage
    import dev_private
    import dev_workspace
    import dev_workspace_dependencies

_MANIFEST = ".sbom-preview.json"
_TRANSPORT = frozenset(
    {
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "HOME",
        "USERPROFILE",
        "PATH",
        "TMP",
        "TEMP",
        "TMPDIR",
        "APPDATA",
        "LOCALAPPDATA",
        "LANG",
    }
)
_TLS_TRANSPORT = frozenset(
    {"NODE_OPTIONS", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_USE_SYSTEM_CA"}
)
_NEXT_FILES = {"next-env.d.ts", "tsconfig.tsbuildinfo", "AGENTS.md", "CLAUDE.md"}
_NATIVE_PROBE = (
    "const p=require('node:path');let ready=false;try{const root=process.argv[1],"
    "table=require(p.join(root,'next/dist/compiled/@napi-rs/triples')).platformArchTriples;"
    "for(const t of (table[process.platform]?.[process.arch]||[])){"
    "if((process.platform==='win32'&&t.abi!=='msvc')||(process.platform==='linux'&&t.abi==='gnux32'))continue;"
    "try{require(p.join(root,'@next/swc-'+t.platformArchABI));ready=true;break}catch{}}}catch{}"
    "process.stdout.write(JSON.stringify({ready}));"
)


class PreviewError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _fail(code):
    raise PreviewError(code) from None


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _directory(path):
    return tuple(dev_workspace_dependencies._directory(path))


def _proof(path, root, limit=1048576):
    return tuple(dev_workspace_dependencies._file(path, root, limit))


def _origin(value):
    try:
        if type(value) is not str or len(value) > 512 or any(ord(char) <= 32 for char in value):
            raise ValueError()
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
            or parsed.port is not None
            and not 1 <= parsed.port <= 65535
        ):
            raise ValueError()
    except ValueError:
        _fail("PREVIEW_BACKEND_REGISTRATION_REQUIRED")


@dataclass(frozen=True, slots=True)
class PreviewTls:
    certificate: Path = field(repr=False)
    private_key: Path = field(repr=False)
    ca_bundle: Path = field(repr=False)

    def __post_init__(self):
        try:
            for name in ("certificate", "private_key", "ca_bundle"):
                path = Path(getattr(self, name))
                if not path.is_absolute() or path.resolve(strict=True) != path:
                    raise ValueError()
                object.__setattr__(self, name, path)
            if self.private_key in {self.certificate, self.ca_bundle}:
                raise ValueError()
        except Exception:
            _fail("PREVIEW_EXISTING_TLS_REQUIRED")


def _tls_proofs(tls):
    if type(tls) is not PreviewTls:
        _fail("PREVIEW_EXISTING_TLS_REQUIRED")
    result = []
    for path in (tls.certificate, tls.private_key, tls.ca_bundle):
        dev_private.validate_parent(path, path.parent)
        info = dev_instance_registry._private(path) if path == tls.private_key else path.lstat()
        # Reuse the bounded regular-file validator, but never read/hash the key.
        if path != tls.private_key:
            _proof(path, path.parent)
        result.append((str(path), info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns))
    return tuple(result)


@dataclass(frozen=True, slots=True)
class SharedBackendRegistration:
    registration_id: str
    origin: str
    tenant_id: str
    frontend_origin: str
    auth_mode: str
    non_production: bool = True

    def __post_init__(self):
        try:
            dev_instance_plan._public_id(self.registration_id)
            dev_instance_plan._public_id(self.tenant_id)
        except ValueError:
            _fail("PREVIEW_BACKEND_REGISTRATION_REQUIRED")
        _origin(self.origin)
        _origin(self.frontend_origin)
        if (
            self.non_production is not True
            or type(self.auth_mode) is not str
            or self.auth_mode not in {"native", "hcl"}
        ):
            _fail("PREVIEW_BACKEND_REGISTRATION_REQUIRED")

    def to_dict(self):
        return {
            "registration_id": self.registration_id,
            "origin": self.origin,
            "tenant_id": self.tenant_id,
            "frontend_origin": self.frontend_origin,
            "auth_mode": self.auth_mode,
            "non_production_selection": True,
            "runtime_verification_performed": False,
        }


@dataclass(frozen=True, slots=True)
class IsolatedBackendBinding:
    """Proposed own-API target; Runtime must verify its listener and readiness."""

    instance_id: str
    origin: str

    def __post_init__(self):
        from uuid import UUID

        try:
            if (
                type(self.instance_id) is not str
                or str(UUID(self.instance_id)) != self.instance_id
                or type(self.origin) is not str
                or re.fullmatch(r"http://127\.0\.0\.1:([0-9]{1,5})", self.origin) is None
                or not 1 <= urlsplit(self.origin).port <= 65535
            ):
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            _fail("PREVIEW_ISOLATED_BACKEND_BINDING_REQUIRED")

    def to_dict(self):
        return {
            "kind": "isolated-owned-runtime",
            "instance_id": self.instance_id,
            "origin": self.origin,
            "runtime_verification_performed": False,
        }


@dataclass(frozen=True, slots=True)
class PreviewPlan:
    descriptor: dev_instance_plan.InstanceDescriptor
    repository: dev_workspace.RepositorySnapshot = field(repr=False)
    selected: dev_workspace.WorktreeSnapshot = field(repr=False)
    state_anchor: Path = field(repr=False)
    workspace: Path = field(repr=False)
    tls: PreviewTls = field(repr=False)
    shared_backend: SharedBackendRegistration | IsolatedBackendBinding | None = field(repr=False)
    proofs: tuple = field(repr=False)
    files: tuple = field(repr=False)
    links: tuple = field(repr=False)
    node: Path = field(repr=False)
    guard: Path = field(repr=False)
    node_modules: Path = field(repr=False)
    source: Path = field(repr=False)
    fingerprint: str

    def to_dict(self):
        return {
            "version": 1,
            "mode": self.descriptor.mode,
            "instance_id": self.descriptor.instance_id,
            "origin": self.descriptor.origin,
            "fingerprint": self.fingerprint,
            "category": "application-frontend" if self.descriptor.mode == "isolated" else "visual-preview",
            "compiler_verified": False,
            "tls_verified": False,
            "application_readiness_verified": False,
            "real_mutations_possible": self.shared_backend is not None,
            "backend_registration": self.shared_backend.to_dict() if self.shared_backend else None,
            "shared_backend_warning": "Frontend actions can mutate the approved non-production backend and permitted tenant; use approved test data."
            if type(self.shared_backend) is SharedBackendRegistration
            else None,
            "source_hmr": "linked trusted application source"
            if self.shared_backend
            else "copied design tokens; reprepare after source changes",
        }


def _tokens(content):
    text = re.sub(r"/\*.*?\*/", "", content.decode("utf-8"), flags=re.S)
    root = re.search(r":root\s*\{([^{}]*)\}", text)
    pairs = re.findall(r"(--[A-Za-z0-9_-]+)\s*:\s*([^;{}]+);", root[1] if root else "")
    if not pairs or len(pairs) > 512 or len({key for key, _ in pairs}) != len(pairs):
        _fail("PREVIEW_PUBLIC_STYLE_REQUIRED")
    for _, value in pairs:
        if (
            len(value) > 256
            or re.fullmatch(r"[A-Za-z0-9#.,%() /+_-]+", value) is None
            or re.search(r"url\s*\(", value, re.I)
        ):
            _fail("PREVIEW_PUBLIC_STYLE_REQUIRED")
    return ":root{" + "".join(key + ":" + value.strip() + ";" for key, value in pairs) + "}\n"


def _mock_files(style):
    layout = "import './preview.css';export default function Layout({children}){return <html lang='en'><body>{children}</body></html>}"
    page = (
        "export default function Page(){return <main><strong>MOCK VISUAL PREVIEW — SYNTHETIC DATA</strong>"
        "<h1>SBOM Analyzer</h1><p>Separate visual fixture. No application login, API, database or background workers.</p>"
        "<section><article><h2>Components</h2><p>24 synthetic</p></article><article><h2>Review queue</h2><p>3 synthetic</p>"
        "</article></section><table><thead><tr><th>Fixture component</th><th>Version</th><th>Review</th></tr></thead>"
        "<tbody><tr><td>Example library</td><td>1.0.0</td><td>Pending</td></tr></tbody></table></main>}"
    )
    css = style + (
        "body{margin:0;background:var(--dashboard-page-bg,#f8fafc);color:var(--color-foreground,#212529);font:16px Arial,sans-serif}"
        "main{max-width:1000px;margin:auto;padding:40px}strong{display:block;padding:16px;background:#fff3cd;border:2px solid #946200}"
        "section{display:flex;gap:20px;margin:24px 0}article{padding:20px;background:var(--color-surface,#fff);border:1px solid var(--color-border,#ddd)}"
        "table{width:100%;border-collapse:collapse;background:var(--row-bg,#fff)}td,th{padding:16px;text-align:left;border:1px solid var(--color-border,#ddd)}"
    )
    return {"app/layout.jsx": layout.encode(), "app/page.jsx": page.encode(), "app/preview.css": css.encode()}


def plan_preview(
    snapshot, selected, descriptor, *, state_anchor, node_executable, tls, shared_backend=None, isolated_backend=None
):
    """Inspect public inputs only; no Node execution, certificate generation or writes."""
    try:
        if (
            type(snapshot) is not dev_workspace.RepositorySnapshot
            or snapshot.status != "PASS"
            or selected not in snapshot.worktrees
            or selected.status != "PASS"
            or selected.locked
            or selected.prunable
            or selected.bare
            or selected.identity is None
            or type(descriptor) is not dev_instance_plan.InstanceDescriptor
            or descriptor.mode not in {"mock", "shared-backend", "isolated"}
            or (descriptor.repository_id, descriptor.worktree_id, descriptor.commit)
            != (snapshot.repository_id, selected.worktree_id, selected.head)
        ):
            _fail("PREVIEW_SOURCE_SELECTION_REQUIRED")
        if isolated_backend is not None:
            if shared_backend is not None or type(isolated_backend) is not IsolatedBackendBinding:
                _fail("PREVIEW_BACKEND_MODE_CONFLICT")
            shared_backend = isolated_backend
        root, anchor, node = selected.identity.canonical_path, Path(state_anchor), Path(node_executable)
        if root != selected.root or dev_workspace._identity(root) != selected.identity:
            _fail("PREVIEW_SOURCE_SELECTION_REQUIRED")
        _directory(root)
        _directory(anchor)
        if not anchor.is_absolute() or anchor.is_relative_to(root):
            _fail("PREVIEW_PRIVATE_STATE_REQUIRED")
        node = node.resolve(strict=True)
        frontend, modules, guard = (
            root / "frontend",
            root / "frontend/node_modules",
            root / "scripts/dev_next_guard.cjs",
        )
        _directory(frontend)
        _directory(modules)  # Physical selected-worktree dependencies, never another checkout's link.
        tree = dev_workspace_dependencies._tree(modules)
        source = frontend / "src"
        _directory(source)
        proofs = [
            ("root", _directory(root)),
            ("anchor", _directory(anchor)),
            ("modules", _directory(modules)),
            ("tree", tree),
            ("node", _proof(node, node.parent, 268435456)),
            ("guard", _proof(guard, root)),
            ("tls", _tls_proofs(tls)),
        ]
        for name in (
            "react/package.json",
            "react-dom/package.json",
            "next/package.json",
            "next/dist/bin/next",
            "next/dist/lib/download-swc.js",
            "next/dist/compiled/@napi-rs/triples/index.js",
        ):
            proofs.append((name, _proof(modules / name, modules)))
        native = modules / "@next"
        _directory(native)
        prefix = {"win32": "swc-win32-", "darwin": "swc-darwin-", "linux": "swc-linux-"}.get(sys.platform)
        installed_native = tuple(
            item for item in native.iterdir() if prefix is not None and item.name.startswith(prefix)
        )
        if not installed_native:
            _fail("PREVIEW_PREINSTALLED_NATIVE_COMPILER_REQUIRED")
        for item in installed_native:
            _directory(item)
        files, links = {}, {"node_modules": modules}
        if descriptor.mode == "mock":
            if shared_backend is not None:
                _fail("PREVIEW_BACKEND_MODE_CONFLICT")
            css = source / "app/globals.css"
            proof = _proof(css, root)
            content, _ = dev_frontend._regular(css, 1048576)
            if hashlib.sha256(content).hexdigest() != proof[-1]:
                _fail("PREVIEW_SOURCE_CHANGED")
            proofs.append(("style", proof))
            mock = _mock_files(_tokens(content))
            files.update(
                {
                    "package.json": _json({"name": "sbom-mock-visual-preview", "private": True}),
                    "next.config.mjs": (
                        "export default {allowedDevOrigins:" + json.dumps([descriptor.hostname]) + "};"
                    ).encode(),
                }
            )
        else:
            if descriptor.mode == "shared-backend":
                if (
                    type(shared_backend) is not SharedBackendRegistration
                    or shared_backend.frontend_origin != descriptor.origin
                    or shared_backend.auth_mode != descriptor.auth_mode
                ):
                    _fail("PREVIEW_BACKEND_REGISTRATION_REQUIRED")
            elif (
                type(shared_backend) is not IsolatedBackendBinding
                or shared_backend.instance_id != descriptor.instance_id
                or shared_backend.origin != f"http://127.0.0.1:{descriptor.ports['api']}"
            ):
                _fail("PREVIEW_ISOLATED_BACKEND_BINDING_REQUIRED")
            mock = {}
            links["src"] = source
            if (frontend / "public").exists():
                _directory(frontend / "public")
                links["public"] = frontend / "public"
            for name in sorted(dev_frontend._CONFIGS):
                if (frontend / name).exists() or (frontend / name).is_symlink():
                    proof = _proof(frontend / name, root)
                    content, _ = dev_frontend._regular(frontend / name, 1048576)
                    if hashlib.sha256(content).hexdigest() != proof[-1]:
                        _fail("PREVIEW_SOURCE_CHANGED")
                    files[name] = content
                    proofs.append(("config/" + name, proof))
            if not {"package.json", "package-lock.json", "tsconfig.json"} <= files.keys():
                _fail("PREVIEW_PUBLIC_CONFIGURATION_REQUIRED")
        proofs.extend(("link/" + name, (str(path), _directory(path))) for name, path in links.items())
        public = [
            descriptor.to_dict(),
            proofs,
            [[name, hashlib.sha256(value).hexdigest()] for name, value in sorted({**files, **mock}.items())],
            shared_backend.to_dict() if shared_backend else None,
        ]
        fingerprint = hashlib.sha256(_json(public)).hexdigest()
        state = anchor / ".sbom-dev/previews" / descriptor.instance_id / fingerprint[:24]
        if state.is_relative_to(root) or root.is_relative_to(state):
            _fail("PREVIEW_PRIVATE_STATE_REQUIRED")
        workspace = state / "frontend"
        return PreviewPlan(
            descriptor,
            snapshot,
            selected,
            anchor,
            workspace,
            tls,
            shared_backend,
            tuple(proofs),
            tuple(sorted(files.items())) + tuple(("mock/" + name, value) for name, value in sorted(mock.items())),
            tuple((name, path) for name, path in links.items()),
            node,
            guard,
            modules,
            source,
            fingerprint,
        )
    except PreviewError:
        raise
    except Exception:
        _fail("PREVIEW_SOURCE_OR_DEPENDENCY_UNVERIFIED")


def _revalidate(plan):
    if type(plan) is not PreviewPlan:
        _fail("PREVIEW_PLAN_REQUIRED")
    current = dev_workspace.discover_workspaces(plan.selected.root)
    selected = next((row for row in current.worktrees if row.worktree_id == plan.selected.worktree_id), None)
    if selected is None:
        _fail("PREVIEW_SOURCE_CHANGED")
    fresh = plan_preview(
        current,
        selected,
        plan.descriptor,
        state_anchor=plan.state_anchor,
        node_executable=plan.node,
        tls=plan.tls,
        shared_backend=plan.shared_backend if type(plan.shared_backend) is SharedBackendRegistration else None,
        isolated_backend=plan.shared_backend if type(plan.shared_backend) is IsolatedBackendBinding else None,
    )
    if fresh != plan:
        _fail("PREVIEW_SOURCE_CHANGED")


def _expected_files(plan):
    return {name: data for name, data in plan.files if not name.startswith("mock/")}


def require_preview(plan):
    """Read-only validation; unknown or partial workspaces are retained, never repaired."""
    try:
        _revalidate(plan)
        state, workspace = plan.workspace.parent, plan.workspace
        cursor, parts = dev_instance_storage._paths(state, plan.state_anchor)
        dev_instance_storage._verify(cursor, private=False)
        for part in parts:
            cursor = cursor / part
            dev_instance_storage._verify(cursor, private=True)
        dev_instance_storage._verify(workspace, private=True)
        manifest, _ = dev_frontend._regular(state / _MANIFEST, 65536)
        if json.loads(manifest) != {
            "version": 1,
            "fingerprint": plan.fingerprint,
            "workspace_identity": list(_directory(workspace)),
        }:
            _fail("PREVIEW_WORKSPACE_UNVERIFIED")
        files = _expected_files(plan)
        links = dict(plan.links)
        links["src"] = state / "mock-source" if plan.descriptor.mode == "mock" else plan.source
        allowed = set(files) | set(links) | _NEXT_FILES | {".next"}
        if any(path.name not in allowed or path.name.casefold().startswith(".env") for path in workspace.iterdir()):
            _fail("PREVIEW_WORKSPACE_UNVERIFIED")
        for name, content in files.items():
            if dev_frontend._regular(workspace / name, 1048576)[0] != content:
                _fail("PREVIEW_WORKSPACE_UNVERIFIED")
        for name, target in links.items():
            info = (workspace / name).lstat()
            dev_frontend._link(workspace / name, target, dev_frontend._identity(info))
            if dev_frontend._target(workspace / name) != target:
                _fail("PREVIEW_WORKSPACE_UNVERIFIED")
            _directory(target)
        for name in _NEXT_FILES:
            if os.path.lexists(workspace / name):
                _proof(workspace / name, workspace)
        if os.path.lexists(workspace / ".next"):
            _directory(workspace / ".next")
        for name, content in plan.files:
            if (
                name.startswith("mock/")
                and dev_frontend._regular(state / "mock-source" / name[5:], 1048576)[0] != content
            ):
                _fail("PREVIEW_WORKSPACE_UNVERIFIED")
        if plan.descriptor.mode == "mock":
            expected = {name[5:] for name, _ in plan.files if name.startswith("mock/")}
            actual = set()
            for directory, names, filenames in os.walk(state / "mock-source", followlinks=False):
                _directory(Path(directory))
                if any(name != "app" or Path(directory) != state / "mock-source" for name in names):
                    _fail("PREVIEW_WORKSPACE_UNVERIFIED")
                actual.update(
                    str((Path(directory) / name).relative_to(state / "mock-source")).replace("\\", "/")
                    for name in filenames
                )
            if actual != expected:
                _fail("PREVIEW_WORKSPACE_UNVERIFIED")
        return workspace
    except PreviewError:
        raise
    except Exception:
        _fail("PREVIEW_WORKSPACE_UNVERIFIED")


def prepare_preview(plan, *, authorize):
    """Create exclusive owned files after caller consent; no installers or processes."""
    try:
        if type(plan) is not PreviewPlan or authorize(plan) is not True:
            _fail("PREVIEW_CATEGORY_APPROVAL_REQUIRED")
        _revalidate(plan)
        state = plan.workspace.parent
        if os.path.lexists(state):
            return require_preview(plan)
        dev_instance_storage.initialize_private_directory(state.parent, anchor=plan.state_anchor)
        dev_workspace_dependencies._exclusive_directory(state, plan.state_anchor)
        dev_workspace_dependencies._exclusive_directory(plan.workspace, plan.state_anchor)
        for name, content in plan.files:
            path = state / "mock-source" / name[5:] if name.startswith("mock/") else plan.workspace / name
            dev_instance_storage.initialize_private_directory(path.parent, anchor=plan.state_anchor)
            dev_private.create_private_file(path, content)
        links = dict(plan.links)
        links["src"] = state / "mock-source" if plan.descriptor.mode == "mock" else plan.source
        for name, target in links.items():
            dev_frontend._create_link(target, plan.workspace / name)
        dev_private.create_private_file(
            state / _MANIFEST,
            _json(
                {"version": 1, "fingerprint": plan.fingerprint, "workspace_identity": list(_directory(plan.workspace))}
            ),
        )
        return require_preview(plan)
    except PreviewError:
        raise
    except Exception:
        _fail("PREVIEW_PREPARATION_UNCONFIRMED")


@dataclass(frozen=True, slots=True)
class VerifiedPreviewLaunch:
    argv: tuple[str, ...] = field(repr=False)
    cwd: Path = field(repr=False)
    environment: Mapping[str, str] = field(repr=False)
    compiler_argv: tuple[str, ...] = field(repr=False)

    def to_dict(self):
        return {
            "component": "Frontend",
            "runtime_started": False,
            "application_readiness_verified": False,
            "runtime_ownership_verified": False,
            "next_step": "verified runtime adapter must own startup and cleanup",
        }


def validate_launch(plan, environment, *, verify_backend=None, verify_tls=None, verify_compiler=None):
    """Call trusted live verifiers before returning a concrete frontend-only spec.

    TLS/backend callbacks receive (plan, frozen effective env); the compiler
    callback receives (plan, compiler argv, transport-only env). Each returns True.
    No caller readiness label/plan fingerprint is an attestation. The runtime
    must revalidate this boundary immediately before spawning its owned process.
    """
    try:
        require_preview(plan)
        if not isinstance(environment, Mapping):
            _fail("PREVIEW_ENVIRONMENT_REQUIRED")
        effective = dict(environment)
        base = plan.selected.root / "frontend"
        path_keys = ("NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE") + (
            ("AUTH_TRANSACTION_KEY_FILE", "HCL_IAM_CA_BUNDLE") if plan.shared_backend else ()
        )
        for key in path_keys:
            if value := effective.get(key):
                if type(value) is not str:
                    _fail("PREVIEW_ENVIRONMENT_REQUIRED")
                value = value.strip(dev_components._BFF_WHITESPACE) if key == "HCL_IAM_CA_BUNDLE" else value
                effective[key] = dev_components._absolute(value, base) if value else ""
        if "SSL_CERT_DIR" in effective:
            values = effective["SSL_CERT_DIR"].split(os.pathsep)
            if any(not value for value in values):
                _fail("TLS_CA_PATH_REVIEW_REQUIRED")
            effective["SSL_CERT_DIR"] = os.pathsep.join(dev_components._absolute(value, base) for value in values)
        raw = MappingProxyType(effective)
        projected = dict(dev_config.component_environment(raw, "frontend"))
        if plan.shared_backend:
            expected = {
                "AUTH_ENABLED": "true",
                "DEV_DEFAULT_TENANT": "false",
                "APP_ORIGIN": plan.descriptor.origin,
                "NEXT_PUBLIC_AUTH_ENABLED": "true",
                "NEXT_PUBLIC_ENTRA_ENABLED": "false",
                "NEXT_PUBLIC_API_URL": plan.shared_backend.origin,
                "SBOM_API_URL": plan.shared_backend.origin,
                "NATIVE_AUTH_ENABLED": str(plan.descriptor.auth_mode == "native").lower(),
                "NEXT_PUBLIC_NATIVE_AUTH_ENABLED": str(plan.descriptor.auth_mode == "native").lower(),
                "NEXT_PUBLIC_HCL_AUTH_ENABLED": str(plan.descriptor.auth_mode == "hcl").lower(),
            }
            if any(raw.get(key) != value for key, value in expected.items()):
                _fail("PREVIEW_SHARED_AUTH_OR_TARGET_REQUIRED")
            if not callable(verify_backend) or verify_backend(plan, raw) is not True:
                _fail("PREVIEW_SHARED_BACKEND_VERIFICATION_REQUIRED")
        else:
            projected = {key: value for key, value in projected.items() if key in _TRANSPORT | _TLS_TRANSPORT}
            projected.update(CI="1", NEXT_DISABLE_SWC_WASM="1", NEXT_TELEMETRY_DISABLED="1")
        if not callable(verify_tls) or verify_tls(plan, raw) is not True:
            _fail("PREVIEW_TLS_VERIFICATION_REQUIRED")
        source = plan.workspace.parent / "mock-source" if plan.descriptor.mode == "mock" else plan.source
        projected.update(SBOM_DEV_FRONTEND_WORKSPACE=str(plan.workspace), SBOM_DEV_FRONTEND_SOURCE=str(source))
        projected["SBOM_DEV_RESOURCE_ID"] = plan.descriptor.instance_id
        projected["NODE_OPTIONS"] = (
            projected.get("NODE_OPTIONS", "") + " --require " + json.dumps(plan.guard.as_posix())
        ).strip()
        compiler = (str(plan.node), "--require", str(plan.guard), "-e", _NATIVE_PROBE, str(plan.node_modules))
        frozen = MappingProxyType(projected)
        probe_env = MappingProxyType(
            {
                key: value
                for key, value in projected.items()
                if key in _TRANSPORT | {"NODE_OPTIONS", "CI", "NEXT_DISABLE_SWC_WASM", "NEXT_TELEMETRY_DISABLED"}
            }
        )
        if not callable(verify_compiler) or verify_compiler(plan, compiler, probe_env) is not True:
            _fail("PREVIEW_NATIVE_COMPILER_VERIFICATION_REQUIRED")
        require_preview(plan)
        argv = (
            str(plan.node),
            "--require",
            str(plan.guard),
            str(plan.node_modules / "next/dist/bin/next"),
            "dev",
            "--webpack",
            "--hostname",
            "127.0.0.1",
            "--port",
            str(plan.descriptor.ports["frontend"]),
            "--experimental-https",
            "--experimental-https-key",
            str(plan.tls.private_key),
            "--experimental-https-cert",
            str(plan.tls.certificate),
            "--experimental-https-ca",
            str(plan.tls.ca_bundle),
        )
        return VerifiedPreviewLaunch(argv, plan.workspace, frozen, compiler)
    except PreviewError:
        raise
    except dev_config.ConfigurationError as error:
        _fail(error.code)
    except Exception:
        _fail("PREVIEW_LAUNCH_VERIFICATION_UNCONFIRMED")
