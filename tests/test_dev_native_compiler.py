"""Optional actual compiler probe only; no Next server, HTTPS, HMR or installers.

Uses existing approved Node/native packages, tiny synthetic configuration and the
candidate production guard/probe. Installed packages are metadata-observed and
linked; only verified fixture link entries are removed, never their targets.
"""

from __future__ import annotations

import builtins
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev, dev_components, dev_frontend

_ROOT = Path(__file__).resolve().parents[1]
_SECRET = "synthetic-native-compiler-backend-secret"
_MARKER = ".fixture-downloader-evaluated"


def _metadata(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or dev_frontend._reparse(info):
        raise ValueError(
            "Native compiler fixture requires ordinary existing public package files; nothing was repaired"
        )
    return tuple(
        getattr(info, name)
        for name in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    )


def _installed_packages():
    node = shutil.which("node")
    if node is None:
        pytest.skip(
            "Native compiler fixture requires an existing approved Node executable; no installation was attempted"
        )
    candidates = [_ROOT / "frontend/node_modules"]
    if sys.platform == "win32":
        candidates.append(Path("C:/sbom/frontend/node_modules"))
    for modules in candidates:
        triples = modules / "next/dist/compiled/@napi-rs/triples"
        if not (triples / "index.js").is_file():
            continue
        packages = sorted((modules / "@next").glob("swc-" + sys.platform + "-*"))
        if not packages:
            continue
        observed = {}
        try:
            dev_frontend._directory(triples)
            table_files = list(triples.iterdir())
            if not 1 <= len(table_files) <= 16:
                raise ValueError()
            tables = {}
            for path in table_files:
                if path.name.casefold().startswith(".env") or path.suffix.lower() in {".pem", ".key", ".p12", ".pfx"}:
                    raise ValueError()
                raw, _ = dev_frontend._regular(path, limit=262144)
                tables[path.name] = raw
                observed[path] = _metadata(path)
            if sum(map(len, tables.values())) > 1048576:
                raise ValueError()
            for package in packages:
                dev_frontend._directory(package)
                raw, _ = dev_frontend._regular(package / "package.json", limit=65536)
                manifest = json.loads(raw)
                main = manifest.get("main", "")
                if (
                    manifest.get("name") != "@next/" + package.name
                    or not isinstance(main, str)
                    or Path(main).name != main
                    or Path(main).suffix != ".node"
                ):
                    raise ValueError()
                for path in package.iterdir():
                    if path.name.casefold().startswith(".env") or path.suffix.lower() in {
                        ".pem",
                        ".key",
                        ".p12",
                        ".pfx",
                    }:
                        raise ValueError()
                    observed[path] = _metadata(path)
                if package / main not in observed:
                    raise ValueError()
            for path in (modules / "next/package.json", modules / "next/dist/lib/download-swc.js"):
                observed[path] = _metadata(path)
        except (OSError, ValueError, TypeError):
            pytest.skip(
                "Native compiler fixture public package layout is unsupported or unverifiable; nothing was changed"
            )
        return Path(node), packages, tables, observed
    pytest.skip(
        "Native compiler fixture requires existing Next triples/native packages; no fallback download is allowed"
    )


def _identity(path):
    return dev_frontend._identity(path.lstat())


def _link(source, destination, links):
    source_identity = dev_frontend._directory(source)
    dev_frontend._create_link(source, destination)
    links.append((destination, source, _identity(destination), source_identity))


def _remove_links(links, root):
    for link, source, identity, source_identity in reversed(links):
        if not link.absolute().is_relative_to(root.absolute()):
            pytest.fail("Native fixture refused link cleanup outside its temporary checkout")
        dev_frontend._chain(link.parent)
        dev_frontend._link(link, source, identity)
        if dev_frontend._directory(source) != source_identity:
            pytest.fail("Native fixture link target identity changed; artifacts were retained")
        if sys.platform == "win32":
            os.rmdir(link)  # Remove this exact verified junction entry only.
        else:
            link.unlink()  # Never recursively remove an installed package.


def test_actual_production_native_compiler_probe_and_guard_preserve_installed_dependencies(tmp_path, monkeypatch):
    node, packages, tables, observed = _installed_packages()
    guard_source = _ROOT / "scripts/dev_next_guard.cjs"
    guard_bytes, _ = dev_frontend._regular(guard_source, limit=65536)
    observed[guard_source] = _metadata(guard_source)
    root, home, links, children = tmp_path / "checkout", tmp_path / "home", [], []
    home.mkdir()
    source = root / "frontend"
    source.mkdir(parents=True)
    for name in ("src", "public", "node_modules"):
        (source / name).mkdir()
    for name, content in {
        "package.json": '{"name":"native-probe-fixture"}',
        "package-lock.json": '{"lockfileVersion":3}',
        "tsconfig.json": "{}",
    }.items():
        (source / name).write_text(content, encoding="utf-8")
    scripts = root / "scripts"
    scripts.mkdir()
    (scripts / "dev_next_guard.cjs").write_bytes(guard_bytes)
    next_package = source / "node_modules/next"
    triples = next_package / "dist/compiled/@napi-rs/triples"
    triples.mkdir(parents=True)
    for name, raw in tables.items():
        (triples / name).write_bytes(raw)
    (next_package / "package.json").write_text('{"name":"next"}', encoding="utf-8")
    downloader = next_package / "dist/lib/download-swc.js"
    downloader.parent.mkdir()
    stub = (
        "require('node:fs').writeFileSync(require('node:path').join(__dirname, "
        + json.dumps(_MARKER)
        + "), 'evaluated', {flag:'wx'});"
        "throw new Error('FIXTURE_DOWNLOADER_EVALUATED');"
    ).encode("utf-8")
    downloader.write_bytes(stub)
    scope = source / "node_modules/@next"
    scope.mkdir()
    forbidden = Mock(
        side_effect=AssertionError("Actual native probe entered an installer, runtime, data or service path")
    )
    launcher = SimpleNamespace(
        ROOT=root,
        ACTIVE_PROFILE="legacy",
        SetupError=dev.SetupError,
        sys=SimpleNamespace(platform=sys.platform),
        GreenfieldStack=SimpleNamespace(STATE=root / "unused-greenfield", node_binary=lambda: node),
        Runtime=forbidden,
        LocalHttps=SimpleNamespace(private_directory=forbidden),
    )
    environment = {
        "PATH": str(node.parent),
        "HOME": str(home),
        "USERPROFILE": str(home),
        "TEMP": str(home),
        "TMP": str(home),
        "TMPDIR": str(home),
        "NODE_ENV": "development",
        "DATABASE_URL": _SECRET,
        "NATIVE_JWT_PRIVATE_KEY": _SECRET,
        "NATIVE_SECURITY_OUTBOX_KEY": _SECRET,
        "SMTP_PASSWORD": _SECRET,
        "AUTH_SESSION_ENCRYPTION_KEY": _SECRET,
        "AUTH_SESSION_REDIS_URL": "redis://fixture:" + _SECRET + "@127.0.0.1:6379/1",
        "NEXT_PUBLIC_UNREVIEWED_SECRET": _SECRET,
    }
    for name in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"):
        if name in os.environ:
            environment[name] = os.environ[name]
    original_environment = dict(environment)
    original_popen, original_import = subprocess.Popen, builtins.__import__

    def spawn(*args, **kwargs):
        assert args[0][0] == str(node) and "--require" in args[0]
        assert str(scripts / "dev_next_guard.cjs") in args[0]
        assert _SECRET not in repr(kwargs["env"])
        assert (
            not {
                "DATABASE_URL",
                "NATIVE_JWT_PRIVATE_KEY",
                "NATIVE_SECURITY_OUTBOX_KEY",
                "SMTP_PASSWORD",
                "AUTH_SESSION_ENCRYPTION_KEY",
                "AUTH_SESSION_REDIS_URL",
                "NEXT_PUBLIC_UNREVIEWED_SECRET",
                "NODE_OPTIONS",
            }
            & kwargs["env"].keys()
        )
        assert kwargs["env"]["CI"] == "1" and kwargs["env"]["NEXT_DISABLE_SWC_WASM"] == "1"
        assert not kwargs.get("shell")
        child = original_popen(*args, **kwargs)  # The production code retains this original owned handle.
        children.append(child)
        return child

    def import_without_data_services(name, *args, **kwargs):
        assert name != "app" and not name.startswith("app.")
        assert name.split(".", 1)[0] not in {"psycopg", "sqlalchemy", "redis"}
        return original_import(name, *args, **kwargs)

    try:
        for package in packages:
            _link(package, scope / package.name, links)
        workspace = dev_frontend.prepare_workspace(launcher, "legacy")
        for name in ("src", "public", "node_modules"):
            link, target = workspace / name, source / name
            links.append((link, target, _identity(link), dev_frontend._directory(target)))
        with monkeypatch.context() as boundary:
            boundary.setattr(subprocess, "Popen", spawn)
            boundary.setattr(subprocess, "run", forbidden)
            boundary.setattr(builtins, "__import__", import_without_data_services)
            boundary.setattr(socket, "create_connection", forbidden)
            for name in (
                "Runtime",
                "ensure_dependencies",
                "ensure_frontend",
                "start_process",
                "start_background",
                "ensure_database",
            ):
                boundary.setattr(dev, name, forbidden)
            assert dev_components.verify_compiler(launcher, environment, workspace, profile="legacy") is None
        assert len(children) == 1 and children[0].returncode == 0
        assert environment == original_environment
        assert not (downloader.parent / _MARKER).exists()
        assert downloader.read_bytes() == stub
        assert (scripts / "dev_next_guard.cjs").read_bytes() == guard_bytes
        assert not (next_package / "next-swc-fallback").exists() and not (next_package / "wasm").exists()
        assert {path: _metadata(path) for path in observed} == observed
        forbidden.assert_not_called()
    finally:
        running = [child.pid for child in children if child.poll() is None]
        if running:
            pytest.fail(f"Owned compiler probe exit is unconfirmed for PID(s) {running}; fixture retained at {root}")
        for child in children:
            child.wait(timeout=3)  # Reap the original child only; no signal or PID fallback.
        _remove_links(links, root)
