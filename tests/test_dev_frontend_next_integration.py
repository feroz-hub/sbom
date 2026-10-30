"""Optional real Next/HTTPS/HMR fixture, never the SBOM application stack.

Requires existing approved Node/Next/React/TypeScript dependencies.
No packages are installed, no existing private configuration is loaded, and no
database/API/worker is started. All source, TLS and runtime records are fixtures.
Next itself is copied into the fixture with compiler downloads explicitly blocked;
other installed package directories are referenced without installer execution.
Missing prerequisites skip explicitly. Cleanup uses the candidate Runtime only;
unverifiable records/artifacts are retained and fail the test, never force-cleared.
"""

from __future__ import annotations

import base64
import hashlib
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
from ssl import CERT_REQUIRED, SSLContext
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


class _HMRSocket:
    """Fixture-only verified TLS/WebSocket transport; no threads or peer joins."""

    _LIMIT = 1048576

    def __init__(
        self, url, *, ssl, origin, open_timeout=5, close_timeout=3, proxy=None, compression=None, ping_interval=None
    ):
        self._socket, self._buffer, self._fragments, self._opened = None, bytearray(), None, False
        self._close_timeout = close_timeout
        parsed = urlsplit(url)
        port = parsed.port or 443
        target = parsed.path + ("?" + parsed.query if parsed.query else "")
        if (
            parsed.scheme != "wss"
            or parsed.hostname != "localhost"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or not target.startswith("/")
            or any(not 33 <= ord(char) <= 126 for char in target)
            or origin != f"https://localhost:{port}"
            or not 1 <= port <= 65535
            or not isinstance(ssl, SSLContext)
            or ssl.verify_mode != CERT_REQUIRED
            or not ssl.check_hostname
            or any(value is not None for value in (proxy, compression, ping_interval))
        ):
            raise ValueError("HMR_WEBSOCKET_POLICY_REQUIRED")
        deadline = self._deadline(open_timeout)
        self._deadline(close_timeout)
        try:
            self._socket = socket.create_connection(("127.0.0.1", port), timeout=self._remaining(deadline))
            self._socket.settimeout(self._remaining(deadline))
            self._socket = ssl.wrap_socket(self._socket, server_hostname="localhost")
            key = base64.b64encode(os.urandom(16)).decode("ascii")
            request = (
                f"GET {target} HTTP/1.1\r\nHost: localhost:{port}\r\nUpgrade: websocket\r\n"
                f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
                f"Origin: {origin}\r\n\r\n"
            ).encode("ascii")
            self._socket.settimeout(self._remaining(deadline))
            self._socket.sendall(request)
            while b"\r\n\r\n" not in self._buffer:
                if len(self._buffer) >= 8192:
                    raise ValueError("HMR_WEBSOCKET_HEADER_LIMIT")
                self._read(min(4096, 8192 - len(self._buffer)), deadline)
            end = self._buffer.index(b"\r\n\r\n") + 4
            header = bytes(self._buffer[:end])
            del self._buffer[:end]
            status = re.fullmatch(rb"HTTP/1\.1 ([0-9]{3})(?: [^\r\n]*)?", header.split(b"\r\n", 1)[0])
            if status is None:
                raise ValueError("HMR_WEBSOCKET_HANDSHAKE_INVALID")
            if status[1] != b"101":
                raise ValueError("HMR_WEBSOCKET_HANDSHAKE_HTTP_" + status[1].decode("ascii"))
            try:
                headers = {}
                for line in header.decode("ascii").split("\r\n")[1:-2]:
                    name, value = line.split(":", 1)
                    name = name.lower()
                    if name in headers:
                        raise ValueError()
                    headers[name] = value.strip()
                expected = base64.b64encode(
                    hashlib.sha1(
                        (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii"), usedforsecurity=False
                    ).digest()
                ).decode("ascii")
                if (
                    headers.get("upgrade", "").lower() != "websocket"
                    or "upgrade" not in {part.strip().lower() for part in headers.get("connection", "").split(",")}
                    or headers.get("sec-websocket-accept") != expected
                    or {"sec-websocket-extensions", "sec-websocket-protocol"} & headers.keys()
                ):
                    raise ValueError()
            except (ValueError, UnicodeError):
                raise ValueError("HMR_WEBSOCKET_HANDSHAKE_INVALID") from None
            self._opened = True
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _deadline(timeout):
        if not isinstance(timeout, (int, float)) or not 0 < timeout <= 30:
            raise ValueError("HMR_WEBSOCKET_TIMEOUT_REQUIRED")
        return time.monotonic() + timeout

    @staticmethod
    def _remaining(deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("HMR_WEBSOCKET_TIMEOUT")
        return remaining

    def _read(self, count, deadline):
        self._socket.settimeout(self._remaining(deadline))
        data = self._socket.recv(count)
        if not data:
            raise ConnectionError("HMR_WEBSOCKET_EOF")
        self._buffer.extend(data)

    def _need(self, count, deadline):
        while len(self._buffer) < count:
            self._read(min(count - len(self._buffer), 65536), deadline)

    def _control(self, opcode, payload, deadline):
        mask = os.urandom(4)
        frame = bytes((0x80 | opcode, 0x80 | len(payload))) + mask
        frame += bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        self._socket.settimeout(self._remaining(deadline))
        self._socket.sendall(frame)

    def _reply(self, opcode, payload, deadline):
        try:
            self._control(opcode, payload, deadline)
        except OSError:
            self._opened = False  # A partial send cannot be safely retried.
            self.close()
            raise ConnectionError("HMR_WEBSOCKET_CONTROL_FAILED") from None

    def recv(self, timeout=3):
        deadline = self._deadline(timeout)
        while self._opened:
            self._remaining(deadline)
            self._need(2, deadline)
            first, second = self._buffer[:2]
            opcode, size, offset = first & 15, second & 127, 2
            if first & 112 or second & 128 or opcode not in {0, 1, 8, 9, 10}:
                raise ValueError("HMR_WEBSOCKET_FRAME_INVALID")
            if size in {126, 127}:
                offset += 2 if size == 126 else 8
                self._need(offset, deadline)
                size = int.from_bytes(self._buffer[2:offset], "big")
                if size < (126 if offset == 4 else 65536):
                    raise ValueError("HMR_WEBSOCKET_FRAME_INVALID")
            if size > self._LIMIT or (opcode >= 8 and (not first & 128 or size > 125)):
                raise ValueError("HMR_WEBSOCKET_FRAME_LIMIT")
            if opcode in {0, 1}:
                if (opcode == 0) != (self._fragments is not None):
                    raise ValueError("HMR_WEBSOCKET_CONTINUATION_INVALID")
                if len(self._fragments or b"") + size > self._LIMIT:
                    raise ValueError("HMR_WEBSOCKET_MESSAGE_LIMIT")
            self._need(offset + size, deadline)
            payload = bytes(self._buffer[offset : offset + size])
            del self._buffer[: offset + size]
            if opcode == 8:
                code = int.from_bytes(payload[:2], "big") if size >= 2 else None
                if size == 1 or (code is not None and (not 1000 <= code < 5000 or code in {1004, 1005, 1006, 1015})):
                    raise ValueError("HMR_WEBSOCKET_CLOSE_INVALID")
                try:
                    payload[2:].decode("utf-8")
                except UnicodeError:
                    raise ValueError("HMR_WEBSOCKET_CLOSE_INVALID") from None
                self._reply(8, payload, deadline)
                self._opened = False
                self.close()
                raise ConnectionError("HMR_WEBSOCKET_CLOSED")
            if opcode in {9, 10}:
                if opcode == 9:
                    self._reply(10, payload, deadline)
                continue
            if self._fragments is None:
                self._fragments = bytearray()
            self._fragments.extend(payload)
            if first & 128:
                message, self._fragments = self._fragments, None
                try:
                    return message.decode("utf-8")
                except UnicodeError:
                    raise ValueError("HMR_WEBSOCKET_TEXT_INVALID") from None
        raise ConnectionError("HMR_WEBSOCKET_CLOSED")

    def close(self):
        if self._socket is not None:
            try:
                if self._opened:
                    self._control(8, b"", self._deadline(self._close_timeout))
            except OSError:
                pass
            finally:
                self._opened = False
                transport = self._socket
                self._socket = None
                transport.close()

    def __enter__(self):
        return self

    def __exit__(self, *error):
        self.close()


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
    if importlib.util.find_spec("cryptography") is None:
        pytest.skip("Real Next fixture requires already-installed cryptography; nothing was installed")
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


def _show_fixture_log(environment):
    """Bounded synthetic output, including failures when verbose mode is off."""
    try:
        with dev.log_path("Frontend").open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            stream.seek(max(0, stream.tell() - 8192))
            tail = stream.read(8192).decode("utf-8", errors="replace")
        print(
            "Fixture Frontend log (bounded, redacted):\n" + dev.redact("\n".join(tail.splitlines()[-40:]), environment)
        )
    except OSError:
        print("Fixture Frontend log unavailable; preserve the fixture for review")


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
    observation = "NOT_OBSERVED"
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
        except (HTTPError, URLError, OSError, ValueError) as error:
            reason = error.reason if isinstance(error, URLError) else error
            if isinstance(error, HTTPError):
                observation = f"HTTP_{error.code}"
            elif isinstance(reason, ssl.SSLCertVerificationError):
                observation = f"TLS_VERIFY_{reason.verify_code}"
            elif isinstance(reason, OSError):
                observation = f"OS_{reason.errno}"
            else:
                observation = "RESPONSE_INVALID"
            time.sleep(min(0.2, max(0, deadline - time.monotonic())))
    pytest.fail(
        f"Owned Next fixture did not reach verified HTTPS readiness within 60 seconds; last status={observation}; inspect fixture logs"
    )


def _wait_page(opener, origin, runtime, identities, marker, *, absent=None):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        _refresh(runtime, identities)
        try:
            html = _get(opener, origin, "/", timeout=min(5, max(0.1, deadline - time.monotonic())))
            if marker in html and (absent is None or absent not in html):
                return html
        except (HTTPError, URLError, OSError):
            pass  # Initial page compilation may exceed one bounded request.
        time.sleep(min(0.2, max(0, deadline - time.monotonic())))
    pytest.fail("Owned Next fixture did not render the expected page within its bounded compilation deadline")


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


def _wait_fixture_resource(opener, origin, runtime, identities, path, *, body=None, removed=False):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        _refresh(runtime, identities)
        try:
            observed = _get(opener, origin, path, timeout=2)
            if not removed and observed == body:
                return
        except HTTPError as error:
            if removed and error.code == 404:
                return
        except (URLError, OSError):
            pass
        time.sleep(0.2)
    pytest.fail("Owned Next did not reflect the fixture resource change within its bounded deadline")


def _page(marker):
    return (
        "'use client';\n"
        "export default function Page() { return <main>"
        f"<h1>{marker}</h1>"
        "<p>{process.env.NEXT_PUBLIC_HCL_IAM_CLIENT_ID}</p>"
        "<p>{String(process.env.NEXT_PUBLIC_UNREVIEWED_SECRET === undefined)}</p>"
        "</main>; }\n"
    )


@pytest.mark.timeout(600)  # Every phase has its own bound; leave time for verified cleanup.
def test_real_next_verified_https_websocket_hmr_assets_and_verified_owned_cleanup(tmp_path_factory, monkeypatch):
    # Keep native Windows fixture paths below the host's configured path limit.
    tmp_path = tmp_path_factory.mktemp("next")
    home = tmp_path / "fixture-home"
    home.mkdir()
    node, installed = _prerequisites(home)

    root, links = tmp_path / "checkout", []
    source = root / "frontend"
    source.mkdir(parents=True)
    (root / "scripts").mkdir()
    (root / "scripts/dev_next_guard.cjs").write_bytes((_ROOT / "scripts/dev_next_guard.cjs").read_bytes())
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
        html = _wait_page(opener, origin, runtime, identities, BEFORE)
        with _HMRSocket(
            f"wss://localhost:{port}/_next/hmr",
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
        html = _wait_page(opener, origin, runtime, identities, AFTER, absent=BEFORE)
        added = source / "src/app/api/fixture-added/route.ts"
        added.parent.mkdir()
        added.write_text("export async function GET() { return new Response('fixture-added'); }\n", encoding="utf-8")
        _wait_fixture_resource(opener, origin, runtime, identities, "/api/fixture-added", body="fixture-added")
        added.unlink()  # Fixture-owned regular source, never the installed checkout.
        added.parent.rmdir()
        _wait_fixture_resource(opener, origin, runtime, identities, "/api/fixture-added", removed=True)
        asset = source / "public/fixture-added.txt"
        asset.write_text("fixture-public-added", encoding="utf-8")
        _wait_fixture_resource(opener, origin, runtime, identities, "/fixture-added.txt", body="fixture-public-added")
        asset.unlink()
        _wait_fixture_resource(opener, origin, runtime, identities, "/fixture-added.txt", removed=True)
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
            _show_fixture_log(environment)
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
