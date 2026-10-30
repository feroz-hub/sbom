"""Exercise the pinned route-watcher adapter with real Node and fixture modules.

No Next server, compiler, package installer, live service or private file is used.
An existing Node executable is required; missing Node or native directory-link
support skips rather than installing software or changing operating-system policy.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

GUARD = Path(__file__).resolve().parents[1] / "scripts/dev_next_guard.cjs"
CODE = "FRONTEND_WATCHER_CONTRACT_REQUIRED"
MESSAGE = (
    f"{CODE}: Frontend source watching requires the verified development workspace "
    "and supported Next watcher contract. Review python scripts/dev.py setup --plan."
)


def _directory_link(source: Path, destination: Path) -> None:
    if sys.platform == "win32":
        try:
            import _winapi

            _winapi.CreateJunction(str(source), str(destination))
        except (ImportError, AttributeError, OSError):
            pytest.skip("Existing nonprivileged Windows junction support required; no policy changes permitted")
    else:
        destination.symlink_to(source, target_is_directory=True)


def _remove_link(link: Path) -> None:
    # Every caller owns this fixture link; never recurse through its target.
    if sys.platform == "win32":
        os.rmdir(link)
    else:
        link.unlink()


@pytest.fixture
def node_executable() -> str:
    executable = shutil.which("node")
    if executable is None:
        pytest.skip("Existing Node executable required; installation is not permitted")
    return executable


@pytest.fixture
def checkout(tmp_path: Path) -> dict[str, Path]:
    root = (tmp_path / "watcher fixture with spaces").resolve()
    source = root / "frontend" / "src"
    workspace = root / ".dev-frontend"
    package = root / "frontend" / "node_modules" / "next"
    compiled = package / "dist" / "compiled" / "watchpack"
    parent = package / "dist" / "server" / "lib" / "router-utils" / "setup-dev-bundler.js"
    for directory in (root / "scripts", source / "app", workspace, compiled, parent.parent, root / "home"):
        directory.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(GUARD, root / "scripts" / "dev_next_guard.cjs")
    (package / "package.json").write_text(json.dumps({"name": "next"}), encoding="utf-8")
    downloader = package / "dist" / "lib" / "download-swc.js"
    downloader.parent.mkdir()
    downloader.write_text("throw new Error('DOWNLOADER_MUST_NOT_RUN');", encoding="utf-8")
    (compiled / "package.json").write_text(json.dumps({"main": "watchpack.js"}), encoding="utf-8")
    marker = root / "original-watch-called"
    (compiled / "watchpack.js").write_text(
        "class Watchpack { constructor(options) {this.options=options;this.calls=[];}"
        "watch(options) {this.calls.push(options);require('node:fs').writeFileSync("
        + json.dumps(str(marker))
        + ",'called');return 'original-return-value';}}"
        "Watchpack.fixtureStatic='static-preserved';module.exports=Watchpack;",
        encoding="utf-8",
    )
    parent.write_text("module.exports=require('next/dist/compiled/watchpack');", encoding="utf-8")
    other = root / "scripts" / "unrelated-consumer.cjs"
    other.write_text("module.exports=require(" + json.dumps(str(compiled / "watchpack.js")) + ");", encoding="utf-8")
    _directory_link(source, workspace / "src")
    return {
        "root": root,
        "source": source,
        "workspace": workspace,
        "compiled": compiled,
        "parent": parent,
        "other": other,
        "marker": marker,
    }


def _run_node(
    executable: str,
    checkout: dict[str, Path],
    script: str,
    *,
    overrides: dict[str, str | None] | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    root = checkout["root"]
    environment = {
        "PATH": str(Path(executable).parent),
        "HOME": str(root / "home"),
        "USERPROFILE": str(root / "home"),
        "TEMP": str(root / "home"),
        "TMP": str(root / "home"),
        "CI": "1",
        "NEXT_TELEMETRY_DISABLED": "1",
        "SBOM_DEV_FRONTEND_WORKSPACE": str(checkout["workspace"]),
        "SBOM_DEV_FRONTEND_SOURCE": str(checkout["source"]),
    }
    for name in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"):
        if name in os.environ:
            environment[name] = os.environ[name]
    for name, value in (overrides or {}).items():
        if value is None:
            environment.pop(name, None)
        else:
            environment[name] = value
    # Forward slashes and JSON quotes match the launcher's trusted preload
    # transport, including fixture checkout paths containing spaces.
    guard = root / "scripts" / "dev_next_guard.cjs"
    environment["NODE_OPTIONS"] = "--require " + json.dumps(guard.as_posix())
    command = [executable, "-e", script]
    process = subprocess.Popen(
        command,
        cwd=cwd or checkout["workspace"],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    try:
        stdout, stderr = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()  # Only the original handle created by this fixture.
        process.communicate(timeout=5)
        pytest.fail("The disposable watcher probe exceeded its bounded timeout")
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _watch_script(checkout: dict[str, Path], call: str | None = None) -> str:
    return (
        "try {const Watchpack=require("
        + json.dumps(str(checkout["parent"]))
        + ");const watcher=new Watchpack({aggregateTimeout:5});"
        + (call or "watcher.watch({directories:[process.env.SBOM_DEV_FRONTEND_WORKSPACE],startTime:0});")
        + "process.stdout.write(JSON.stringify({unguarded:true}));}"
        "catch(error) {process.stdout.write(JSON.stringify({"
        "code:error.code,message:error.message,stack:error.stack}));}"
    )


def _assert_refused(result: subprocess.CompletedProcess[str], checkout: dict[str, Path]) -> None:
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert json.loads(result.stdout) == {"code": CODE, "message": MESSAGE, "stack": MESSAGE}
    assert str(checkout["root"]) not in result.stdout
    assert checkout["root"].as_posix() not in result.stdout
    assert not checkout["marker"].exists()


def test_route_watcher_adds_lexical_src_without_mutating_input_or_original_class(node_executable, checkout):
    script = (
        "const Original=require("
        + json.dumps(str(checkout["compiled"] / "watchpack.js"))
        + ");const before=Original.prototype.watch;const Adapted=require("
        + json.dumps(str(checkout["parent"]))
        + ");const input={directories:[process.env.SBOM_DEV_FRONTEND_WORKSPACE],startTime:0};"
        "const watcher=new Adapted({aggregateTimeout:5});const returned=watcher.watch(input);"
        "process.stdout.write(JSON.stringify({directories:watcher.calls[0].directories,"
        "inputDirectories:input.directories,startTime:watcher.calls[0].startTime,returned,"
        "originalUnchanged:Original.prototype.watch===before,instance:watcher instanceof Original,"
        "separateClass:Original!==Adapted,staticValue:Adapted.fixtureStatic}));"
    )
    result = _run_node(node_executable, checkout, script)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert json.loads(result.stdout) == {
        "directories": [str(checkout["workspace"]), str(checkout["workspace"] / "src")],
        "inputDirectories": [str(checkout["workspace"])],
        "startTime": 0,
        "returned": "original-return-value",
        "originalUnchanged": True,
        "instance": True,
        "separateClass": True,
        "staticValue": "static-preserved",
    }


def test_other_watchpack_consumer_is_unchanged_even_without_workspace_metadata(node_executable, checkout):
    script = (
        "const Original=require("
        + json.dumps(str(checkout["compiled"] / "watchpack.js"))
        + ");const Other=require("
        + json.dumps(str(checkout["other"]))
        + ");const watcher=new Other();const input={files:['ordinary'],startTime:37};"
        "const returned=watcher.watch(input);process.stdout.write(JSON.stringify({"
        "same:Other===Original,inputPreserved:watcher.calls[0]===input,returned}));"
    )
    result = _run_node(
        node_executable,
        checkout,
        script,
        overrides={"SBOM_DEV_FRONTEND_WORKSPACE": None, "SBOM_DEV_FRONTEND_SOURCE": None},
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert json.loads(result.stdout) == {
        "same": True,
        "inputPreserved": True,
        "returned": "original-return-value",
    }


@pytest.mark.parametrize(
    "call",
    (
        "watcher.watch({directories:[process.env.SBOM_DEV_FRONTEND_WORKSPACE],startTime:1});",
        "watcher.watch({directories:[process.env.SBOM_DEV_FRONTEND_WORKSPACE],startTime:0,files:[]});",
        "watcher.watch({directories:[],startTime:0});",
        "watcher.watch({directories:[process.env.SBOM_DEV_FRONTEND_WORKSPACE,"
        "process.env.SBOM_DEV_FRONTEND_SOURCE],startTime:0});",
        "watcher.watch({directories:['.'],startTime:0});",
        "watcher.watch({directories:[process.env.SBOM_DEV_FRONTEND_SOURCE],startTime:0});",
        "watcher.watch([process.env.SBOM_DEV_FRONTEND_WORKSPACE],[],0);",
        "watcher.watch(new Proxy({}, {getPrototypeOf(){throw new Error('fixture-private-error')}}));",
    ),
)
def test_unsupported_route_watch_shape_fails_before_original_watch(node_executable, checkout, call):
    _assert_refused(_run_node(node_executable, checkout, _watch_script(checkout, call)), checkout)


@pytest.mark.parametrize(
    "overrides",
    (
        {"SBOM_DEV_FRONTEND_WORKSPACE": None},
        {"SBOM_DEV_FRONTEND_SOURCE": None},
        {"SBOM_DEV_FRONTEND_WORKSPACE": ""},
        {"SBOM_DEV_FRONTEND_SOURCE": "relative-source"},
        {"SBOM_DEV_FRONTEND_WORKSPACE": "relative-workspace"},
        {"SBOM_DEV_FRONTEND_SOURCE": "/missing-fixture-source"},
    ),
)
def test_missing_invalid_or_relative_metadata_fails_closed(node_executable, checkout, overrides):
    _assert_refused(_run_node(node_executable, checkout, _watch_script(checkout), overrides=overrides), checkout)


def test_working_directory_mismatch_fails_closed(node_executable, checkout):
    result = _run_node(node_executable, checkout, _watch_script(checkout), cwd=checkout["root"])
    _assert_refused(result, checkout)


def test_source_link_redirect_fails_closed(node_executable, checkout):
    other = checkout["root"] / "other-source"
    other.mkdir()
    _remove_link(checkout["workspace"] / "src")
    _directory_link(other, checkout["workspace"] / "src")
    _assert_refused(_run_node(node_executable, checkout, _watch_script(checkout)), checkout)


def test_regular_workspace_src_is_not_accepted_as_the_verified_link(node_executable, checkout):
    _remove_link(checkout["workspace"] / "src")
    (checkout["workspace"] / "src").mkdir()
    _assert_refused(_run_node(node_executable, checkout, _watch_script(checkout)), checkout)


def test_source_metadata_cannot_name_another_directory_or_directory_link(node_executable, checkout):
    other = checkout["root"] / "source-alias"
    _directory_link(checkout["source"], other)
    result = _run_node(
        node_executable,
        checkout,
        _watch_script(checkout),
        overrides={"SBOM_DEV_FRONTEND_SOURCE": str(other)},
    )
    _assert_refused(result, checkout)


def test_unknown_watchpack_export_shape_is_refused(node_executable, checkout):
    (checkout["compiled"] / "watchpack.js").write_text("module.exports={};", encoding="utf-8")
    _assert_refused(_run_node(node_executable, checkout, _watch_script(checkout)), checkout)


def test_route_import_cannot_redirect_to_another_watchpack_module(node_executable, checkout):
    original = checkout["compiled"]
    preserved = original.with_name("watchpack-preserved")
    original.rename(preserved)  # Only disposable fixture files; no installed dependency is touched.
    other = checkout["root"] / "redirected-watchpack"
    other.mkdir()
    (other / "package.json").write_text(json.dumps({"main": "watchpack.js"}), encoding="utf-8")
    marker = checkout["marker"]
    (other / "watchpack.js").write_text(
        "require('node:fs').writeFileSync(" + json.dumps(str(marker)) + ",'redirect-loaded');module.exports=class {};",
        encoding="utf-8",
    )
    _directory_link(other, original)
    _assert_refused(_run_node(node_executable, checkout, _watch_script(checkout)), checkout)


def test_revalidates_source_link_when_watch_is_called_not_only_when_module_is_loaded(node_executable, checkout):
    other = checkout["root"] / "late-source"
    other.mkdir()
    script = (
        "const Watchpack=require("
        + json.dumps(str(checkout["parent"]))
        + ");const fs=require('node:fs');const sourceLink="
        + json.dumps(str(checkout["workspace"] / "src"))
        + ";if(process.platform==='win32')fs.rmdirSync(sourceLink);else fs.unlinkSync(sourceLink);"
        "fs.symlinkSync(" + json.dumps(str(other)) + ",sourceLink,process.platform==='win32'?'junction':'dir');"
        "try {new Watchpack().watch({directories:[process.env.SBOM_DEV_FRONTEND_WORKSPACE],startTime:0});"
        "process.stdout.write(JSON.stringify({unguarded:true}));}catch(error){"
        "process.stdout.write(JSON.stringify({code:error.code,message:error.message,stack:error.stack}));}"
    )
    _assert_refused(_run_node(node_executable, checkout, script), checkout)
