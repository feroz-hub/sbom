"""Optional real Next/HTTPS/HMR fixture, never the SBOM application stack.

Requires existing approved Node/Next/React/TypeScript dependencies and websockets.
No packages are installed, no existing private configuration is loaded, and no
database/API/worker is started. All source, TLS and runtime records are fixtures.
Next itself is copied into the fixture with compiler downloads explicitly blocked;
other installed package directories are referenced without installer execution.
Missing prerequisites skip explicitly. Cleanup uses the candidate Runtime only;
unverifiable records/artifacts are retained and fail the test, never force-cleared.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import socket
import ssl
import stat
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, build_opener

import pytest
from scripts import dev, dev_components, dev_config, dev_frontend

BACKEND = "fixture-real-next-backend-secret"
SESSION = "fixture-real-next-bff-session-secret"
PUBLIC = "fixture-real-next-approved-public"
UNAPPROVED = "fixture-real-next-unapproved-public"
BEFORE = "fixture-atomic-source-before"
AFTER = "fixture-atomic-source-after"
_ROOT = Path(__file__).resolve().parents[1]
_DOWNLOAD_ATTEMPT = ".fixture-compiler-download-attempted"
_DOWNLOAD_GUARD = (
    "'use strict';\n"
    "async function blocked() {\n"
    "  require('node:fs').writeFileSync(require('node:path').join(__dirname, "
    + json.dumps(_DOWNLOAD_ATTEMPT)
    + "), 'blocked', {flag:'wx'});\n"
    "  throw new Error('FIXTURE_COMPILER_DOWNLOAD_BLOCKED');\n"
    "}\n"
    "exports.downloadNativeNextSwc = blocked;\n"
    "exports.downloadWasmSwc = blocked;\n"
).encode("utf-8")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        raise AssertionError("The fixture refused an unexpected redirect")


class _Scripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.paths = []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            value = dict(attrs).get("src")
            if value:
                self.paths.append(value)


def _tool_environment(node, home):
    environment = {
        "PATH": str(node.parent),
        "CI": "1",
        "NEXT_TELEMETRY_DISABLED": "1",
        "NEXT_DISABLE_SWC_WASM": "1",
        "HOME": str(home),
        "USERPROFILE": str(home),
        "TEMP": str(home),
        "TMP": str(home),
        "TMPDIR": str(home),
        "APPDATA": str(home / "AppData/Roaming"),
        "LOCALAPPDATA": str(home / "AppData/Local"),
    }
    for name in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"):
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def _prerequisites(home):
    if importlib.util.find_spec("websockets") is None or importlib.util.find_spec("cryptography") is None:
        pytest.skip("Real Next fixture requires already-installed cryptography and websockets; nothing was installed")
    node = shutil.which("node")
    candidates = [_ROOT / "frontend/node_modules"]
    if os.name == "nt":
        candidates.append(Path("C:/sbom/frontend/node_modules"))
    required = (
        "next/dist/bin/next",
        "next/dist/compiled/@napi-rs/triples/index.js",
        "next/dist/lib/download-swc.js",
        "react/package.json",
        "react-dom/package.json",
        "typescript/lib/typescript.js",
        "@types/react/index.d.ts",
        "@types/node/index.d.ts",
    )
    modules = next((path for path in candidates if all((path / name).is_file() for name in required)), None)
    if not node or modules is None:
        pytest.skip(
            "Real Next fixture requires existing approved Node/Next/React/TypeScript packages; no install is allowed"
        )
    node = Path(node)
    try:
        completed = subprocess.run(
            [
                str(node),
                "-p",
                "JSON.stringify({version:process.versions.node,platform:process.platform,arch:process.arch})",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            env=_tool_environment(node, home),
        )
        details = json.loads(completed.stdout)
        match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", details["version"])
        if completed.returncode or not match or tuple(map(int, match.groups())) < dev.MIN_NODE:
            pytest.skip("The existing Node version does not meet the candidate minimum")
        if details["platform"] not in {"win32", "darwin", "linux"} or details["arch"] not in {"x64", "arm64", "ia32"}:
            pytest.skip("The installed Node platform is outside this fixture's native dependency preflight")
        # Read only the bundled pure triples table, never Next's SWC loader.
        # Match its Windows MSVC/Linux x64 ABI filtering and require the actual
        # selected npm package, rather than bypassing its entry point via .node.
        native_script = (
            "const p=require('node:path');let ready=false;try{"
            "const table=require(process.argv[1]).platformArchTriples;"
            "let triples=table[process.platform]?.[process.arch]||[];"
            "if(process.platform==='win32'&&['ia32','x64'].includes(process.arch))"
            "triples=triples.filter(t=>t.abi==='msvc');"
            "if(process.platform==='linux'&&process.arch==='x64')"
            "triples=triples.filter(t=>t.abi!=='gnux32');"
            "const version=require(process.argv[3]).version;"
            "for(const triple of triples){try{"
            "const dir=p.join(process.argv[2],'@next','swc-'+triple.platformArchABI);"
            "const metadata=require(p.join(dir,'package.json'));"
            "if(metadata.name!=='@next/swc-'+triple.platformArchABI||metadata.version!==version)continue;"
            "require(dir);ready=true;break}catch{}}"
            "}catch{}process.stdout.write(JSON.stringify({ready}));"
        )
        checked = subprocess.run(
            [
                str(node),
                "-e",
                native_script,
                str(modules / "next/dist/compiled/@napi-rs/triples/index.js"),
                str(modules),
                str(modules / "next/package.json"),
            ],
            capture_output=True,
            text=True,
            timeout=5,
            env=_tool_environment(node, home),
        )
        if checked.returncode != 0 or checked.stdout != '{"ready":true}':
            pytest.skip("No selected installed native SWC package passed preflight; fallback downloads are forbidden")
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError):
        pytest.skip("The existing Node runtime cannot be inspected within the fixture deadline")
    safe = dev_config.component_environment({"CI": "1", "NEXT_TELEMETRY_DISABLED": "1"}, "frontend")
    if any(safe.get(name) != "1" for name in ("CI", "NEXT_TELEMETRY_DISABLED", "NEXT_DISABLE_SWC_WASM")):
        pytest.skip(
            "Real Next fixture requires preserved CI/no-auto-install and telemetry-disable controls before launch"
        )
    return node, modules


def _copy_next_package(source, destination):
    """Copy public package bytes only; never give Next a writable original path."""
    dev_frontend._directory(source)
    destination.mkdir()
    count, total, copies = 0, 0, []
    deadline = time.monotonic() + 120
    for directory, names, files in os.walk(source, followlinks=False):
        directory = Path(directory)
        dev_frontend._directory(directory)
        relative = directory.relative_to(source)
        copied = destination / relative
        for name in list(names):
            # Preserve private additions and old downloaded fallbacks in place;
            # none is an input to this disposable fixture.
            if (
                name.casefold().startswith(".env")
                or name == "node_modules"
                or (relative == Path(".") and name in {"wasm", "next-swc-fallback"})
            ):
                names.remove(name)
                continue
            dev_frontend._directory(directory / name)
            (copied / name).mkdir()
        for name in files:
            if time.monotonic() >= deadline:
                pytest.fail("The bounded fixture-only package copy exceeded its deadline before any server started")
            if name.casefold().startswith(".env") or Path(name).suffix.lower() in {".key", ".pem", ".p12", ".pfx"}:
                continue
            original = directory / name
            info = original.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or dev_frontend._reparse(info):
                pytest.fail("The public Next fixture refused an unverified package file")
            count, total = count + 1, total + info.st_size
            if count > 25000 or info.st_size > 64 * 1024 * 1024 or total > 512 * 1024 * 1024:
                pytest.fail("The public Next fixture copy exceeded its bounded package limit")
            copies.append((original, copied / name, dev_frontend._identity(info), info.st_size))

    def copy_public(item):
        original, target, identity, size = item
        if time.monotonic() >= deadline:
            pytest.fail("The bounded fixture-only package copy exceeded its deadline before any server started")
        content, version = dev_frontend._regular(original, limit=64 * 1024 * 1024)
        if any(version[key] != value for key, value in identity.items()) or len(content) != size:
            pytest.fail("The public Next package changed during the fixture copy")
        # Public disposable test data needs no per-file durable flush. Keep
        # exclusive creation; bounded parallel reads avoid serialized AV latency.
        with target.open("xb") as stream:
            stream.write(content)

    with ThreadPoolExecutor(max_workers=8) as pool:
        for _ in pool.map(copy_public, copies):
            pass
    guard = destination / "dist/lib/download-swc.js"
    dev_frontend._regular(guard)
    guard.write_bytes(_DOWNLOAD_GUARD)  # Owned fixture copy only, before any process starts.
    _assert_no_compiler_fallback(destination)


def _assert_no_compiler_fallback(package):
    if dev_frontend._regular(package / "dist/lib/download-swc.js")[0] != _DOWNLOAD_GUARD:
        pytest.fail("Fixture compiler download guard changed; retain the fixture for review")
    for path in (package / "next-swc-fallback", package / "wasm", package / "dist/lib" / _DOWNLOAD_ATTEMPT):
        if path.exists() or path.is_symlink():
            pytest.fail("Fixture compiler fallback was attempted; no dependency download or repair is authorized")


def _link_identity(path):
    value = path.lstat()
    return value.st_dev, value.st_ino, value.st_mode


def _remember_link(source, destination, links):
    dev_frontend._create_link(source, destination)
    links.append((destination, source, _link_identity(destination)))


def _remove_fixture_links(links, root):
    """Remove only exact recorded fixture link objects; never recurse into deps."""
    for link, target, identity in reversed(links):
        if not link.absolute().is_relative_to(root.absolute()):
            pytest.fail("Fixture link cleanup refused a path outside its owned directory")
        if _link_identity(link) != identity or not os.path.samefile(dev_frontend._target(link), target):
            pytest.fail("Fixture link identity changed; retained artifacts require independent review")
        info = link.lstat()
        if os.name == "nt":
            if getattr(info, "st_reparse_tag", 0) != stat.IO_REPARSE_TAG_MOUNT_POINT:
                pytest.fail("Fixture cleanup refused a nonjunction directory")
            os.rmdir(link)  # Removes this verified junction entry only, never its target.
        else:
            if not stat.S_ISLNK(info.st_mode):
                pytest.fail("Fixture cleanup refused a nonsymlink path")
            link.unlink()


def _get(opener, origin, path, *, limit=1048576, timeout=3):
    parsed = urlsplit(path)
    if parsed.scheme or parsed.netloc or not path.startswith("/"):
        pytest.fail("The fixture refused a nonlocal resource URL")
    with opener.open(origin + path, timeout=timeout) as response:
        if response.status != 200:
            raise OSError("Fixture HTTP status was not ready")
        body = response.read(limit + 1)
    if len(body) > limit:
        pytest.fail("Fixture response exceeded its bounded read limit")
    return body.decode("utf-8")


def _remember_owned(runtime, identities):
    for record in (runtime.state or {}).get("services", {}).values():
        for member in (record, *record.get("members", [])):
            if member.get("birth") and member.get("exe"):
                identities[(member["pid"], member["birth"], member["exe"])] = dict(member)


def _refresh(runtime, identities):
    runtime.refresh()
    _remember_owned(runtime, identities)
    record = runtime.state["services"]["Frontend"]
    if runtime.service_status(record) != "RUNNING":
        pytest.fail("Owned Next process is not verifiably RUNNING; inspect retained fixture runtime/logs")


def _wait_probe(opener, origin, runtime, identities):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        _refresh(runtime, identities)
        try:
            payload = json.loads(
                _get(opener, origin, "/api/probe", timeout=min(3, max(0.1, deadline - time.monotonic())))
            )
            if payload == {
                "backendAbsent": True,
                "sessionPresent": True,
                "publicPresent": True,
                "unknownPublicAbsent": True,
            }:
                return
            pytest.fail("Synthetic probe reported an environment-isolation failure; values withheld")
        except (HTTPError, URLError, OSError, ValueError):
            time.sleep(min(0.2, max(0, deadline - time.monotonic())))
    pytest.fail("Owned Next fixture did not reach verified HTTPS readiness within 60 seconds; inspect fixture logs")


def _hmr_message(connection, wanted, deadline):
    while time.monotonic() < deadline:
        try:
            message = json.loads(connection.recv(timeout=min(3, max(0.1, deadline - time.monotonic()))))
        except TimeoutError:
            continue
        kind = message.get("type") or message.get("action")
        if kind in {"sync", "built"} and message.get("errors"):
            pytest.fail("Next/HMR reported compilation errors; output withheld")
        if kind in wanted:
            return message
    pytest.fail("Owned Next fixture did not publish the expected bounded Webpack HMR event")


def _page(marker):
    return (
        "'use client';\n"
        "export default function Page() { return <main>"
        f"<h1>{marker}</h1>"
        "<p>{process.env.NEXT_PUBLIC_HCL_IAM_CLIENT_ID}</p>"
        "<p>{String(process.env.NEXT_PUBLIC_UNREVIEWED_SECRET === undefined)}</p>"
        "</main>; }\n"
    )


def test_real_next_verified_https_websocket_hmr_assets_and_verified_owned_cleanup(tmp_path_factory, monkeypatch):
    # Keep native Windows fixture paths below the host's configured path limit.
    tmp_path = tmp_path_factory.mktemp("next")
    home = tmp_path / "fixture-home"
    home.mkdir()
    node, installed = _prerequisites(home)
    from websockets.sync.client import connect

    root, links = tmp_path / "checkout", []
    source = root / "frontend"
    source.mkdir(parents=True)
    (source / "src/app/api/probe").mkdir(parents=True)
    (source / "public").mkdir()
    (source / "node_modules").mkdir()
    for name in ("next.config.mjs", "tsconfig.json"):
        (source / name).write_bytes((_ROOT / "frontend" / name).read_bytes())
    package = {"name": "sbom-isolation-fixture", "private": True}
    (source / "package.json").write_text(json.dumps(package), encoding="utf-8")
    # Next's lockfile patcher exits when no node_modules/next entry exists;
    # CI=1 additionally prevents package installation or registry patching.
    (source / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": {"": package}}), encoding="utf-8"
    )
    (source / ".env.local").write_text(
        f"DATABASE_URL={BACKEND}\nNEXT_PUBLIC_UNREVIEWED_SECRET={UNAPPROVED}\n", encoding="utf-8"
    )
    page = source / "src/app/page.tsx"
    page.write_text(_page(BEFORE), encoding="utf-8")
    (source / "src/app/layout.tsx").write_text(
        "export default function Layout({ children }: { children: React.ReactNode }) { return <html><body>{children}</body></html>; }\n",
        encoding="utf-8",
    )
    (source / "src/app/api/probe/route.ts").write_text(
        "export const dynamic = 'force-dynamic';\nexport async function GET() { return Response.json({"
        "backendAbsent: ['DATABASE_URL','NATIVE_JWT_PRIVATE_KEY','NATIVE_SECURITY_OUTBOX_KEY','SMTP_PASSWORD'].every(key => process.env[key] === undefined),"
        f"sessionPresent: process.env.AUTH_SESSION_ENCRYPTION_KEY === {json.dumps(SESSION)},"
        f"publicPresent: process.env.NEXT_PUBLIC_HCL_IAM_CLIENT_ID === {json.dumps(PUBLIC)},"
        "unknownPublicAbsent: process.env.NEXT_PUBLIC_UNREVIEWED_SECRET === undefined }); }\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(dev, "ROOT", root)
    monkeypatch.setattr(dev, "CONFIG", root / ".env.dev.local")
    monkeypatch.setattr(dev, "BEAT_LOCK", root / ".dev-beat.pid")
    monkeypatch.setattr(dev, "ACTIVE_PROFILE", "legacy")
    monkeypatch.setattr(dev, "ACTIVE_LEGACY_CONFIG", "managed")
    monkeypatch.setattr(dev.GreenfieldStack, "ROOT", root)
    monkeypatch.setattr(dev.GreenfieldStack, "STATE", root / "unused-greenfield")
    monkeypatch.setattr(dev.GreenfieldStack, "node_binary", lambda: node)
    runtime, child, stopped, identities, record = dev.Runtime(root), None, True, {}, None
    copied_next = None
    try:
        next_destination = source / "node_modules/next"
        _copy_next_package(installed / "next", next_destination)
        copied_next = next_destination
        for directory in installed.iterdir():
            info = directory.lstat()
            if (
                directory.name != "next"
                and not directory.name.startswith(".")
                and stat.S_ISDIR(info.st_mode)
                and not getattr(info, "st_file_attributes", 0) & 1024
            ):
                _remember_link(directory, source / "node_modules" / directory.name, links)
        workspace = dev_frontend.prepare_workspace(dev, "legacy")
        for name in ("src", "public", "node_modules"):
            path = workspace / name
            links.append((path, source / name, _link_identity(path)))
        certificate, key = source / "certificates/localhost.pem", source / "certificates/localhost-key.pem"
        dev.create_local_certificate(certificate, key)  # Approved disposable TLS fixture only; no trust installation.
        context = ssl.create_default_context(cafile=str(certificate))
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), _NoRedirect())
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        origin = f"https://localhost:{port}"
        environment = {
            "PATH": str(node.parent),
            "CI": "1",
            "NEXT_TELEMETRY_DISABLED": "1",
            "NODE_ENV": "development",
            "SBOM_DEV_PROFILE": "legacy",
            "DEV_FRONTEND_PORT": str(port),
            "NATIVE_AUTH_ENABLED": "true",
            "NEXT_PUBLIC_AUTH_ENABLED": "true",
            "NEXT_PUBLIC_HCL_AUTH_ENABLED": "false",
            "NEXT_PUBLIC_HCL_IAM_CLIENT_ID": PUBLIC,
            "NEXT_PUBLIC_UNREVIEWED_SECRET": UNAPPROVED,
            "AUTH_SESSION_ENCRYPTION_KEY": SESSION,
            "AUTH_SESSION_STORE": "redis",
            "APP_ORIGIN": origin,
            "DATABASE_URL": BACKEND,
            "NATIVE_JWT_PRIVATE_KEY": BACKEND,
            "NATIVE_SECURITY_OUTBOX_KEY": BACKEND,
            "SMTP_PASSWORD": BACKEND,
        }
        environment.update(_tool_environment(node, home))
        projected = dev_components.process_environment(dev, "Frontend", environment, workspace)
        if any(projected.get(name) != "1" for name in ("CI", "NEXT_TELEMETRY_DISABLED", "NEXT_DISABLE_SWC_WASM")):
            pytest.fail("Real Next fixture refused to launch without CI/no-telemetry guards")
        if not runtime.acquire():
            pytest.fail("Fresh owned fixture runtime lock was unavailable")
        runtime.begin("legacy")
        monkeypatch.setattr(dev, "ACTIVE_RUNTIME", runtime)
        stopped = False
        child = dev.start_process(
            "Frontend",
            [
                str(node),
                str(source / "node_modules/next/dist/bin/next"),
                "dev",
                "--webpack",
                "--hostname",
                "127.0.0.1",
                "--port",
                str(port),
                "--experimental-https",
                "--experimental-https-cert",
                str(certificate),
                "--experimental-https-key",
                str(key),
            ],
            environment,
            workspace,
        )
        _wait_probe(opener, origin, runtime, identities)
        html = _get(opener, origin, "/")
        if BEFORE not in html:
            pytest.fail("The synthetic client page was not compiled/rendered")
        with connect(
            f"wss://localhost:{port}/_next/webpack-hmr",
            ssl=context,
            origin=origin,
            proxy=None,
            open_timeout=5,
            close_timeout=3,
            compression=None,
            ping_interval=None,
        ) as hmr:
            initial = _hmr_message(hmr, {"sync", "built"}, time.monotonic() + 15)
            replacement = root / "page-next.tsx"
            replacement.write_text(_page(AFTER), encoding="utf-8")
            replacement.replace(page)
            deadline, saw_building = time.monotonic() + 30, False
            while True:
                update = _hmr_message(hmr, {"building", "built"}, deadline)
                if (update.get("type") or update.get("action")) == "building":
                    saw_building = True
                elif saw_building and update.get("hash") != initial.get("hash"):
                    break
        _refresh(runtime, identities)
        html = _get(opener, origin, "/")
        if AFTER not in html or BEFORE in html:
            pytest.fail("Atomic source replacement was not visible after real Webpack HMR")
        # Editing source dotenv must not reload backend secrets into isolated Node.
        (source / ".env.local").write_text(
            f"DATABASE_URL={BACKEND}\nNATIVE_JWT_PRIVATE_KEY={BACKEND}\nNEXT_PUBLIC_UNREVIEWED_SECRET={UNAPPROVED}\n",
            encoding="utf-8",
        )
        _wait_probe(opener, origin, runtime, identities)
        parser = _Scripts()
        parser.feed(html)
        assets = sorted({path for path in parser.paths if path.startswith("/_next/static/") and ".js" in path})
        if not assets or len(assets) > 32:
            pytest.fail("Synthetic browser asset discovery was empty or exceeded its limit")
        browser = [html, *(_get(opener, origin, path, limit=16777216) for path in assets)]
        if not any(PUBLIC in asset for asset in browser[1:]):
            pytest.fail("Approved public marker was not present in compiled browser JavaScript")
        if any(marker in asset for marker in (BACKEND, SESSION, UNAPPROVED) for asset in browser):
            pytest.fail("Synthetic private/unapproved marker reached browser output; values withheld")
        _refresh(runtime, identities)
        record = runtime.state["services"]["Frontend"]
    finally:
        try:
            if runtime.state is not None:
                _remember_owned(runtime, identities)
                record = runtime.state.get("services", {}).get("Frontend", record)
                stopped = runtime.stop_services(dev.say)
                if record:
                    for member in (record, *record.get("members", [])):
                        if member.get("birth") and member.get("exe"):
                            identities[(member["pid"], member["birth"], member["exe"])] = dict(member)
                if stopped:
                    if child is not None:
                        child.wait(timeout=5)  # Reap only; no manual signal or kill fallback.
                    for saved in identities.values():
                        if dev.matches(saved, dev.process_info(saved["pid"])):
                            stopped = False
                            break
        finally:
            runtime.release()
        if child is not None:
            dev.show_log("Frontend", environment)  # Synthetic fixture only; bounded and redacted by the launcher.
        if not stopped:
            pytest.fail(f"Verified cleanup was incomplete; fixture runtime and artifacts retained at {root}")
        if runtime.path.exists() or not runtime.stop_services(dev.say):
            pytest.fail("Fixture runtime registry did not reach clean idempotent stopped state")
        if child is not None:
            dev_frontend.require_workspace(
                dev, "legacy"
            )  # Generated .next/types are allowed; copied tsconfig must be unchanged.
        if copied_next is not None:
            _assert_no_compiler_fallback(copied_next)
        _remove_fixture_links(links, tmp_path)
