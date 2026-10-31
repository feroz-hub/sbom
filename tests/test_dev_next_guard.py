"""Real Node checks against disposable fake Next trees; never install packages.

These tests require an existing Node executable and skip when it is absent.
They run no real Next server, compiler, application, network probe or database.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

GUARD_SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "dev_next_guard.cjs"
CODE = "FRONTEND_DEPENDENCY_DOWNLOAD_BLOCKED"
MESSAGE = f"{CODE}: Frontend compiler downloads are disabled. Review python scripts/dev.py setup --repair-dependencies."
GUARD_MESSAGE = (
    "FRONTEND_GUARD_REQUIRED: Frontend dependency guard requires a prepared local Next installation. "
    "Review python scripts/dev.py setup --repair-dependencies."
)


@pytest.fixture
def node_executable() -> str:
    executable = shutil.which("node")
    if executable is None:
        pytest.skip("Existing Node executable required; dependency installation is not permitted")
    return executable


@pytest.fixture
def fake_checkout(tmp_path: Path) -> Path:
    # Spaces exercise the same trusted NODE_OPTIONS quoting used by the launcher.
    root = tmp_path / "synthetic private checkout"
    (root / "scripts").mkdir(parents=True)
    (root / "home").mkdir()
    (root / "temp").mkdir()
    shutil.copyfile(GUARD_SOURCE, root / "scripts" / "dev_next_guard.cjs")
    _write_downloader(root / "frontend" / "node_modules" / "next", root / "loaded.json")
    return root


def _write_downloader(package: Path, marker: Path) -> Path:
    target = package / "dist" / "lib" / "download-swc.js"
    target.parent.mkdir(parents=True)
    (package / "package.json").write_text(
        json.dumps(
            {
                "name": "next",
                "version": "0.0.0-fixture",
                "exports": {"./compiler-alias": "./dist/lib/download-swc.js"},
            }
        ),
        encoding="utf-8",
    )
    target.write_text(
        "require('node:fs').writeFileSync(" + json.dumps(str(marker)) + ", 'evaluated');\n"
        "exports.downloadNativeNextSwc = () => 'native download ran';\n"
        "exports.downloadWasmSwc = () => 'wasm download ran';\n",
        encoding="utf-8",
    )
    return target


def _environment(root: Path, executable: str) -> dict[str, str]:
    # Do not inherit foreign NODE_OPTIONS, credentials, proxy settings or paths.
    environment = {
        "PATH": str(Path(executable).parent),
        "HOME": str(root / "home"),
        "USERPROFILE": str(root / "home"),
        "TMP": str(root / "temp"),
        "TEMP": str(root / "temp"),
        "CI": "1",
        "NEXT_TELEMETRY_DISABLED": "1",
    }
    for name in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"):
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def _run_node(
    executable: str,
    root: Path,
    script: str,
    *,
    preload: bool = True,
    inherited_preload: bool = False,
) -> subprocess.CompletedProcess[str]:
    guard = root / "scripts" / "dev_next_guard.cjs"
    command = [executable]
    if preload:
        command.extend(("--require", str(guard)))
    command.extend(("-e", script))
    environment = _environment(root, executable)
    if inherited_preload:
        environment["NODE_OPTIONS"] = f"--require {json.dumps(guard.as_posix())}"
    process = subprocess.Popen(
        command,
        cwd=root,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    try:
        stdout, stderr = process.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        # Only the handle created here is eligible for forced test cleanup.
        process.kill()
        process.communicate(timeout=5)
        pytest.fail("Disposable Node guard probe exceeded its bounded timeout")
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _assert_blocked_payload(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    payload = json.loads(result.stdout)
    assert payload == {"code": CODE, "message": MESSAGE, "stack": MESSAGE}


def _blocked_probe(request: str, function: str = "downloadNativeNextSwc") -> str:
    return (
        "try { require(" + json.dumps(request) + ")[" + json.dumps(function) + "]('fixture'); process.exitCode = 9; } "
        "catch (error) { process.stdout.write(JSON.stringify({"
        "code:error.code,message:error.message,stack:error.stack})); }"
    )


@pytest.mark.parametrize("function", ("downloadNativeNextSwc", "downloadWasmSwc"))
@pytest.mark.parametrize("extension", ("", ".js"))
def test_native_and_wasm_downloads_never_evaluate_downloader(
    node_executable: str, fake_checkout: Path, function: str, extension: str
) -> None:
    result = _run_node(
        node_executable,
        fake_checkout,
        _blocked_probe(f"./frontend/node_modules/next/dist/lib/download-swc{extension}", function),
    )
    _assert_blocked_payload(result)
    assert not (fake_checkout / "loaded.json").exists()


def test_loading_downloader_is_silent_and_returns_frozen_compatible_exports(
    node_executable: str, fake_checkout: Path
) -> None:
    result = _run_node(
        node_executable,
        fake_checkout,
        "const value=require('./frontend/node_modules/next/dist/lib/download-swc');"
        "process.stdout.write(JSON.stringify([Object.isFrozen(value),value.__esModule,"
        "typeof value.downloadNativeNextSwc,typeof value.downloadWasmSwc]));",
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert json.loads(result.stdout) == [True, True, "function", "function"]
    assert not (fake_checkout / "loaded.json").exists()


@pytest.mark.parametrize("function", ("downloadNativeNextSwc", "downloadWasmSwc"))
def test_async_next_style_caller_receives_same_safe_download_rejection(
    node_executable: str, fake_checkout: Path, function: str
) -> None:
    script = (
        "(async () => { try { await require('./frontend/node_modules/next/dist/lib/download-swc')["
        + json.dumps(function)
        + "](); process.exitCode=9; } catch(error) {process.stdout.write(JSON.stringify({"
        "code:error.code,message:error.message,stack:error.stack})); } })();"
    )
    _assert_blocked_payload(_run_node(node_executable, fake_checkout, script))
    assert not (fake_checkout / "loaded.json").exists()


def test_unrelated_module_with_same_basename_is_unchanged(node_executable: str, fake_checkout: Path) -> None:
    ordinary = fake_checkout / "not-next" / "dist" / "lib" / "download-swc.js"
    ordinary.parent.mkdir(parents=True)
    (fake_checkout / "not-next" / "package.json").write_text(
        json.dumps({"name": "ordinary-fixture-package"}), encoding="utf-8"
    )
    ordinary.write_text("module.exports = { value: 'ordinary-module' };", encoding="utf-8")
    result = _run_node(
        node_executable,
        fake_checkout,
        "process.stdout.write(require('./not-next/dist/lib/download-swc').value);",
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "ordinary-module"
    assert result.stderr == ""


def test_missing_unrelated_module_preserves_node_error_code(node_executable: str, fake_checkout: Path) -> None:
    result = _run_node(
        node_executable,
        fake_checkout,
        "try { require('./not-an-installed-module'); } catch(error) { process.stdout.write(error.code); }",
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "MODULE_NOT_FOUND"
    assert result.stderr == ""


def test_alternate_resolved_next_installation_is_also_protected(node_executable: str, fake_checkout: Path) -> None:
    target = _write_downloader(
        fake_checkout / "alternate" / "node_modules" / "next", fake_checkout / "alternate-loaded.json"
    )
    result = _run_node(node_executable, fake_checkout, _blocked_probe(str(target), "downloadWasmSwc"))
    _assert_blocked_payload(result)
    assert not (fake_checkout / "alternate-loaded.json").exists()
    assert not (fake_checkout / "loaded.json").exists()


def test_package_export_alias_cannot_bypass_resolved_target_guard(node_executable: str, fake_checkout: Path) -> None:
    result = _run_node(
        node_executable,
        fake_checkout,
        "const requireNext = require('node:module').createRequire("
        "require('node:path').resolve('frontend/probe.cjs'));"
        "try { requireNext('next/compiler-alias').downloadNativeNextSwc(); process.exitCode=9; }"
        "catch(error) { process.stdout.write(JSON.stringify({"
        "code:error.code,message:error.message,stack:error.stack})); }",
    )
    _assert_blocked_payload(result)
    assert not (fake_checkout / "loaded.json").exists()


def test_relocated_next_package_relative_caller_cannot_download(node_executable: str, fake_checkout: Path) -> None:
    package = fake_checkout / "relocated-package"
    _write_downloader(package, fake_checkout / "relocated-loaded.json")
    caller = package / "dist" / "build" / "swc" / "index.js"
    caller.parent.mkdir(parents=True)
    caller.write_text("module.exports = require('../../lib/download-swc');", encoding="utf-8")
    _assert_blocked_payload(_run_node(node_executable, fake_checkout, _blocked_probe(str(caller))))
    assert not (fake_checkout / "relocated-loaded.json").exists()


@pytest.mark.parametrize(
    "metadata",
    (None, "{invalid json", "{}", '{"name":null}', "x" * 65_537),
    ids=("missing", "invalid-json", "missing-name", "null-name", "oversized"),
)
def test_downloader_candidate_with_unknown_or_unbounded_metadata_is_protected(
    node_executable: str, fake_checkout: Path, metadata: str | None
) -> None:
    package = fake_checkout / "unverified-package"
    target = _write_downloader(package, fake_checkout / "unverified-loaded.json")
    manifest = package / "package.json"
    if metadata is None:
        manifest.unlink()
    else:
        manifest.write_text(metadata, encoding="utf-8")
    _assert_blocked_payload(_run_node(node_executable, fake_checkout, _blocked_probe(str(target))))
    assert not (fake_checkout / "unverified-loaded.json").exists()


def test_downloader_replaced_after_preload_still_never_executes(node_executable: str, fake_checkout: Path) -> None:
    target = fake_checkout / "frontend" / "node_modules" / "next" / "dist" / "lib" / "download-swc.js"
    marker = fake_checkout / "replacement-loaded.json"
    replacement = "require('node:fs').writeFileSync(" + json.dumps(str(marker)) + ", 'evaluated');"
    script = (
        "require('node:fs').writeFileSync("
        + json.dumps(str(target))
        + ","
        + json.dumps(replacement)
        + ");"
        + _blocked_probe(str(target))
    )
    _assert_blocked_payload(_run_node(node_executable, fake_checkout, script))
    assert not marker.exists()
    assert not (fake_checkout / "loaded.json").exists()


def test_missing_local_target_stops_preload_with_only_fixed_redacted_guidance(
    node_executable: str, fake_checkout: Path
) -> None:
    target = fake_checkout / "frontend" / "node_modules" / "next" / "dist" / "lib" / "download-swc.js"
    target.unlink()
    result = _run_node(node_executable, fake_checkout, "process.stdout.write('application-ran');")
    assert result.returncode != 0
    assert result.stdout == ""
    assert result.stderr == GUARD_MESSAGE + "\n"
    assert str(fake_checkout) not in result.stderr
    assert fake_checkout.as_posix() not in result.stderr
    assert "Cannot find module" not in result.stderr


def test_child_process_inherits_trusted_node_options_without_explicit_preload(
    node_executable: str, fake_checkout: Path
) -> None:
    child = _blocked_probe("./frontend/node_modules/next/dist/lib/download-swc", "downloadWasmSwc")
    script = (
        "const child = require('node:child_process').spawnSync(process.execPath, ['-e',"
        + json.dumps(child)
        + "], {env:process.env,encoding:'utf8',timeout:5000});"
        "if(child.error || child.status!==0 || child.stderr) process.exitCode=9;"
        "process.stdout.write(child.stdout || '');"
    )
    result = _run_node(node_executable, fake_checkout, script, preload=False, inherited_preload=True)
    _assert_blocked_payload(result)
    assert not (fake_checkout / "loaded.json").exists()


@pytest.mark.parametrize("inherited_preload", (False, True))
def test_worker_inherits_guard_from_argv_or_node_options(
    node_executable: str, fake_checkout: Path, inherited_preload: bool
) -> None:
    worker = (
        "const {parentPort} = require('node:worker_threads');"
        "try { require('./frontend/node_modules/next/dist/lib/download-swc').downloadNativeNextSwc();"
        "parentPort.postMessage({code:'UNGUARDED'}); } catch(error) {"
        "parentPort.postMessage({code:error.code,message:error.message,stack:error.stack}); }"
    )
    script = (
        "const {Worker} = require('node:worker_threads');"
        "const worker = new Worker(" + json.dumps(worker) + ", {eval:true});"
        "const timer=setTimeout(() => {process.exitCode=9;worker.terminate();},5000);"
        "worker.once('message', value => {process.stdout.write(JSON.stringify(value));});"
        "worker.once('error', () => {process.exitCode=9;});"
        "worker.once('exit', code => {clearTimeout(timer);if(code!==0)process.exitCode=9;});"
    )
    result = _run_node(
        node_executable,
        fake_checkout,
        script,
        preload=not inherited_preload,
        inherited_preload=inherited_preload,
    )
    _assert_blocked_payload(result)
    assert not (fake_checkout / "loaded.json").exists()


def test_repeated_argv_and_node_options_preload_is_silent_and_still_protects(
    node_executable: str, fake_checkout: Path
) -> None:
    result = _run_node(
        node_executable,
        fake_checkout,
        _blocked_probe("./frontend/node_modules/next/dist/lib/download-swc"),
        inherited_preload=True,
    )
    _assert_blocked_payload(result)
    assert not (fake_checkout / "loaded.json").exists()
