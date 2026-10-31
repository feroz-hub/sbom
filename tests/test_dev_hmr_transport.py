"""Bounded stdlib HMR protocol tests using fake owned sockets, never services."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import socket
import ssl
from pathlib import Path
from unittest.mock import Mock

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "sbom_hmr_fixture", Path(__file__).with_name("test_dev_frontend_next_integration.py")
)
_FIXTURE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_FIXTURE)
_HMRSocket = _FIXTURE._HMRSocket
_URL = "wss://localhost:13000/_next/hmr"
_ORIGIN = "https://localhost:13000"
_PRIVATE = "synthetic-private-header-and-frame-value"


def handshake(request, *, status=101, change=None, suffix=b""):
    key = next(
        line.split(b":", 1)[1].strip() for line in request.split(b"\r\n") if line.startswith(b"Sec-WebSocket-Key:")
    )
    accept = base64.b64encode(
        hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11", usedforsecurity=False).digest()
    ).decode("ascii")
    headers = {"Upgrade": "WebSocket", "Connection": "keep-alive, Upgrade", "Sec-WebSocket-Accept": accept}
    if change:
        change(headers)
    return (
        f"HTTP/1.1 {status} {_PRIVATE}\r\n"
        + "".join(name + ": " + value + "\r\n" for name, value in headers.items())
        + "\r\n"
    ).encode("ascii") + suffix


def frame(payload=b"", *, opcode=1, final=True):
    first = (128 if final else 0) | opcode
    if len(payload) < 126:
        return bytes((first, len(payload))) + payload
    width, marker = (2, 126) if len(payload) < 65536 else (8, 127)
    return bytes((first, marker)) + len(payload).to_bytes(width, "big") + payload


def control_payload(sent, opcode):
    assert sent[0] == 128 | opcode and sent[1] & 128 and sent[1] & 127 <= 125
    length, mask = sent[1] & 127, sent[2:6]
    assert len(sent) == length + 6
    return bytes(value ^ mask[index % 4] for index, value in enumerate(sent[6:]))


class OwnedSocket:
    def __init__(self, chunks=(), response=handshake, on_read=None):
        self.chunks, self.response, self.on_read = list(chunks), response, on_read
        self.sent, self.timeouts, self.read_count, self.closed, self.close_count = [], [], 0, False, 0
        self.control_error = None

    def settimeout(self, timeout):
        assert timeout > 0
        self.timeouts.append(timeout)

    def sendall(self, data):
        assert not self.closed
        self.sent.append(bytes(data))
        if data.startswith(b"GET "):
            self.chunks.insert(0, self.response(data))
        elif self.control_error is not None:
            raise self.control_error

    def recv(self, limit):
        assert not self.closed
        self.read_count += 1
        if self.on_read is not None:
            self.on_read(self.timeouts[-1])
        if not self.chunks:
            return b""
        value = self.chunks.pop(0)
        if isinstance(value, BaseException):
            raise value
        if len(value) > limit:
            self.chunks.insert(0, value[limit:])
        return value[:limit]

    def recv_into(self, target):
        value = self.recv(len(target))
        target[: len(value)] = value
        return len(value)

    def close(self):
        self.closed = True
        self.close_count += 1


@pytest.fixture
def owned_connection(monkeypatch):
    def create(chunks=(), *, response=handshake, on_read=None, wrap_error=None):
        transport = OwnedSocket(chunks, response=response, on_read=on_read)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        connector = Mock(return_value=transport)
        wrapper = Mock(side_effect=wrap_error, return_value=transport)
        monkeypatch.setattr(socket, "create_connection", connector)

        def wrap(selected, raw, *, server_hostname):
            assert selected is context and raw is transport and server_hostname == "localhost"
            return wrapper(raw, server_hostname=server_hostname)

        monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap)
        return transport, context, connector, wrapper

    return create


def test_handshake_pins_loopback_sni_verifies_headers_and_retains_first_frame(owned_connection, monkeypatch):
    # Keep deadline addition/subtraction exact, independent of host uptime.
    monkeypatch.setattr(_FIXTURE.time, "monotonic", lambda: 0.0)
    transport, context, connector, wrapper = owned_connection(
        response=lambda request: handshake(request, suffix=frame(b'{"action":"built"}'))
    )
    with _HMRSocket(_URL, ssl=context, origin=_ORIGIN) as connection:
        assert connection.recv(timeout=1) == '{"action":"built"}'
        assert connector.call_args.args == (("127.0.0.1", 13000),)
        assert 0 < connector.call_args.kwargs["timeout"] <= 5
        assert wrapper.call_args.kwargs == {"server_hostname": "localhost"}
        assert b"Host: localhost:13000\r\n" in transport.sent[0]
        assert b"Origin: https://localhost:13000\r\n" in transport.sent[0]
        reads = transport.read_count
    assert transport.closed and transport.read_count == reads and transport.close_count == 1
    assert control_payload(transport.sent[-1], 8) == b""


@pytest.mark.parametrize("status", [401, 403, 404, 500])
def test_handshake_failure_reports_only_safe_http_status_and_closes_owned_socket(owned_connection, status):
    transport, context, _, _ = owned_connection(response=lambda request: handshake(request, status=status))
    with pytest.raises(ValueError) as caught:
        _HMRSocket(_URL, ssl=context, origin=_ORIGIN)
    assert str(caught.value) == f"HMR_WEBSOCKET_HANDSHAKE_HTTP_{status}"
    assert _PRIVATE not in str(caught.value) and transport.closed
    assert len(transport.sent) == 1  # No WebSocket close/peer wait after a refused upgrade.


@pytest.mark.parametrize(
    "failure", ["upgrade", "connection", "accept", "duplicate", "extension", "protocol", "nonascii"]
)
def test_handshake_refuses_invalid_security_headers_without_echoing_values(owned_connection, failure):
    def response(request):
        def change(headers):
            key = {
                "upgrade": "Upgrade",
                "connection": "Connection",
                "accept": "Sec-WebSocket-Accept",
                "extension": "Sec-WebSocket-Extensions",
                "protocol": "Sec-WebSocket-Protocol",
            }.get(failure)
            if key:
                headers[key] = _PRIVATE

        result = handshake(request, change=change)
        if failure == "duplicate":
            result = result.replace(b"\r\n\r\n", b"\r\nConnection: Upgrade\r\n\r\n")
        elif failure == "nonascii":
            result = result.replace(b"\r\n\r\n", b"\r\nX-Private: \xff\r\n\r\n")
        return result

    transport, context, _, _ = owned_connection(response=response)
    with pytest.raises(ValueError, match="^HMR_WEBSOCKET_HANDSHAKE_INVALID$") as caught:
        _HMRSocket(_URL, ssl=context, origin=_ORIGIN)
    assert _PRIVATE not in str(caught.value) and transport.closed


@pytest.mark.parametrize("failure", ["limit", "timeout", "eof", "invalid-status", "tls"])
def test_failed_open_has_a_bound_and_never_waits_for_a_peer_thread(owned_connection, failure, monkeypatch):
    monkeypatch.setattr(_FIXTURE.time, "monotonic", lambda: 0.0)
    responses = {"limit": b"H" * 8193, "timeout": b"", "eof": b"", "invalid-status": b"INVALID\r\n\r\n"}
    transport, context, _, _ = owned_connection(
        response=lambda request: responses.get(failure, b""),
        wrap_error=ssl.SSLCertVerificationError(1, "synthetic certificate refusal") if failure == "tls" else None,
    )
    if failure == "timeout":
        original_send = transport.sendall

        def send(data):
            original_send(data)
            transport.chunks = [TimeoutError("synthetic socket deadline")]

        transport.sendall = send
    with pytest.raises((OSError, ValueError)):
        _HMRSocket(_URL, ssl=context, origin=_ORIGIN, open_timeout=0.1)
    assert transport.closed and len(transport.sent) <= 1
    assert all(0 < timeout <= 0.1 for timeout in transport.timeouts)


@pytest.mark.parametrize(
    "policy",
    [
        "ws",
        "remote",
        "ip-host",
        "userinfo",
        "fragment",
        "origin",
        "tls-none",
        "hostname",
        "proxy",
        "compression",
        "ping",
    ],
)
def test_policy_refuses_nonlocal_or_unverified_connections_before_tcp(owned_connection, policy):
    _, context, connector, _ = owned_connection()
    url, options = _URL, {"ssl": context, "origin": _ORIGIN}
    if policy == "ws":
        url = _URL.replace("wss:", "ws:")
    elif policy in {"remote", "ip-host"}:
        url = _URL.replace("localhost", "example.invalid" if policy == "remote" else "127.0.0.1")
    elif policy == "userinfo":
        url = _URL.replace("localhost", "user:password@localhost")
    elif policy == "fragment":
        url += "#private"
    elif policy == "origin":
        options["origin"] = "https://example.invalid"
    elif policy == "tls-none":
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    elif policy == "hostname":
        context.check_hostname = False
    else:
        options[{"proxy": "proxy", "compression": "compression", "ping": "ping_interval"}[policy]] = "unsupported"
    with pytest.raises(ValueError, match="HMR_WEBSOCKET_POLICY_REQUIRED"):
        _HMRSocket(url, **options)
    connector.assert_not_called()


@pytest.mark.parametrize("name", ["open_timeout", "close_timeout"])
@pytest.mark.parametrize("timeout", [None, 0, -1, 31, float("inf"), float("nan")])
def test_open_and_close_deadlines_must_be_finite_and_bounded_before_tcp(owned_connection, name, timeout):
    _, context, connector, _ = owned_connection()
    with pytest.raises(ValueError, match="^HMR_WEBSOCKET_TIMEOUT_REQUIRED$"):
        _HMRSocket(_URL, ssl=context, origin=_ORIGIN, **{name: timeout})
    connector.assert_not_called()


@pytest.mark.parametrize("size", [0, 125, 126, 65535, 65536, 1048576])
def test_text_frames_support_canonical_lengths_up_to_one_mib(owned_connection, size):
    transport, context, _, _ = owned_connection([frame(b"x" * size)])
    with _HMRSocket(_URL, ssl=context, origin=_ORIGIN) as connection:
        assert connection.recv(timeout=2) == "x" * size
    assert transport.closed


@pytest.mark.parametrize("extended", [False, True])
def test_partial_frame_timeout_preserves_header_and_payload_for_retry(owned_connection, extended):
    payload = b"x" * 126 if extended else b"hello"
    encoded = frame(payload)
    split = 3 if extended else 4
    transport, context, _, _ = owned_connection(
        [encoded[:split], TimeoutError("synthetic partial frame"), encoded[split:]]
    )
    with _HMRSocket(_URL, ssl=context, origin=_ORIGIN) as connection:
        with pytest.raises(TimeoutError):
            connection.recv(timeout=1)
        assert bytes(connection._buffer) == encoded[:split]
        assert connection.recv(timeout=1) == payload.decode("ascii")
    assert transport.closed


def test_fragmented_text_and_ping_survive_timeout_without_resetting_message(owned_connection):
    chunks = [
        frame(b"hel", final=False),
        frame(b"echo", opcode=9),
        frame(b"", opcode=10),
        frame(b"lo", opcode=0)[:2],
        TimeoutError("synthetic continuation timeout"),
        b"lo",
    ]
    transport, context, _, _ = owned_connection(chunks)
    with _HMRSocket(_URL, ssl=context, origin=_ORIGIN) as connection:
        with pytest.raises(TimeoutError):
            connection.recv(timeout=1)
        assert connection._fragments == b"hel"
        assert connection.recv(timeout=1) == "hello"
        assert control_payload(transport.sent[1], 10) == b"echo"


def test_utf8_text_can_split_between_continuation_frames(owned_connection):
    _, context, _, _ = owned_connection([frame(b"\xc3", final=False), frame(b"\xa9", opcode=0)])
    with _HMRSocket(_URL, ssl=context, origin=_ORIGIN) as connection:
        assert connection.recv(timeout=1) == "\u00e9"


def test_midframe_eof_closes_owned_connection_without_returning_partial_text(owned_connection):
    transport, context, _, _ = owned_connection([b"\x81\x05he"])
    with _HMRSocket(_URL, ssl=context, origin=_ORIGIN) as connection:
        with pytest.raises(ConnectionError, match="^HMR_WEBSOCKET_EOF$"):
            connection.recv(timeout=1)
    assert transport.closed


@pytest.mark.parametrize(
    "wire,code",
    [
        (b"\x81\x80", "FRAME_INVALID"),
        (b"\xc1\x00", "FRAME_INVALID"),
        (frame(b"binary", opcode=2), "FRAME_INVALID"),
        (b"\x83\x00", "FRAME_INVALID"),
        (frame(b"x", opcode=9, final=False), "FRAME_LIMIT"),
        (b"\x81\x7e\x00\x01", "FRAME_INVALID"),
        (b"\x81\x7f" + (126).to_bytes(8, "big"), "FRAME_INVALID"),
        (b"\x81\x7f" + (1048577).to_bytes(8, "big"), "FRAME_LIMIT"),
        (b"\x89\x7e\x00\x7e", "FRAME_LIMIT"),
        (frame(b"unexpected", opcode=0), "CONTINUATION_INVALID"),
        (frame(b"a", final=False) + frame(b"new"), "CONTINUATION_INVALID"),
        (frame(b"\xff"), "TEXT_INVALID"),
        (frame(b"x", opcode=8), "CLOSE_INVALID"),
        (frame((1005).to_bytes(2, "big"), opcode=8), "CLOSE_INVALID"),
        (frame((1000).to_bytes(2, "big") + b"\xff", opcode=8), "CLOSE_INVALID"),
    ],
)
def test_malformed_or_oversize_server_frames_fail_closed_with_safe_reason(owned_connection, wire, code):
    transport, context, _, _ = owned_connection([wire])
    with _HMRSocket(_URL, ssl=context, origin=_ORIGIN) as connection:
        with pytest.raises(ValueError, match="^HMR_WEBSOCKET_" + code + "$"):
            connection.recv(timeout=1)
    assert transport.closed


def test_fragment_message_limit_is_checked_before_reading_extra_payload(owned_connection):
    transport, context, _, _ = owned_connection([frame(b"x" * 1048576, final=False), b"\x80\x01"])
    with _HMRSocket(_URL, ssl=context, origin=_ORIGIN) as connection:
        with pytest.raises(ValueError, match="MESSAGE_LIMIT"):
            connection.recv(timeout=2)
    assert transport.closed


def test_server_close_is_acknowledged_masked_without_waiting_or_echoing_reason(owned_connection):
    payload = (1000).to_bytes(2, "big") + _PRIVATE.encode("ascii")
    transport, context, _, _ = owned_connection([frame(payload, opcode=8)])
    with _HMRSocket(_URL, ssl=context, origin=_ORIGIN) as connection:
        with pytest.raises(ConnectionError, match="^HMR_WEBSOCKET_CLOSED$") as caught:
            connection.recv(timeout=1)
        assert _PRIVATE not in str(caught.value)
    assert control_payload(transport.sent[1], 8) == payload
    assert transport.closed and transport.close_count == 1


def test_close_timeout_closes_owned_socket_without_any_receive_or_join(owned_connection):
    transport, context, _, _ = owned_connection()
    connection = _HMRSocket(_URL, ssl=context, origin=_ORIGIN, close_timeout=0.01)
    reads = transport.read_count
    transport.control_error = TimeoutError("synthetic blocked close send")
    connection.close()
    connection.close()
    assert transport.closed and transport.close_count == 1 and transport.read_count == reads
    assert 0 < transport.timeouts[-1] <= 0.01


def test_failed_pong_closes_instead_of_retrying_a_partially_sent_control_frame(owned_connection):
    transport, context, _, _ = owned_connection([frame(b"ping", opcode=9)])
    with _HMRSocket(_URL, ssl=context, origin=_ORIGIN) as connection:
        transport.control_error = TimeoutError("synthetic partial control send")
        with pytest.raises(ConnectionError, match="^HMR_WEBSOCKET_CONTROL_FAILED$"):
            connection.recv(timeout=1)
    assert transport.closed and transport.close_count == 1


def test_ping_stream_uses_one_receive_deadline_without_per_frame_reset(owned_connection, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(_FIXTURE.time, "monotonic", lambda: clock[0])
    transport, context, _, _ = owned_connection([frame(b"ping", opcode=9)] * 20)
    with _HMRSocket(_URL, ssl=context, origin=_ORIGIN) as connection:

        def advance(timeout):
            step = min(timeout, 0.1)
            clock[0] += step
            if step == timeout:
                raise TimeoutError("synthetic receive deadline")

        transport.on_read = advance
        with pytest.raises(TimeoutError):
            connection.recv(timeout=0.25)
        assert clock[0] <= 0.25 and transport.read_count <= 5
    assert transport.closed


@pytest.mark.parametrize("chunked", [False, True])
def test_http_reader_uses_verified_loopback_tls_and_stdlib_body_framing(owned_connection, chunked):
    body = b"5\r\nhello\r\n0\r\n\r\n" if chunked else b"hello"
    headers = b"Transfer-Encoding: chunked" if chunked else b"Content-Length: 5"
    transport, context, connector, wrapper = owned_connection(
        response=lambda request: b"HTTP/1.1 200 OK\r\n" + headers + b"\r\n\r\n" + body
    )
    assert _FIXTURE._get(context, _ORIGIN, "/", timeout=1) == "hello"
    assert connector.call_args.args == (("127.0.0.1", 13000),)
    assert wrapper.call_args.kwargs == {"server_hostname": "localhost"}
    assert b"Accept-Encoding: identity\r\nConnection: close\r\n" in transport.sent[0]
    assert transport.closed and transport.close_count == 1


@pytest.mark.parametrize("phase", ["headers", "body"])
def test_http_slow_progress_cannot_extend_total_response_deadline(owned_connection, monkeypatch, phase):
    clock = [0.0]
    monkeypatch.setattr(_FIXTURE.time, "monotonic", lambda: clock[0])
    transport, context, _, _ = owned_connection(
        response=lambda request: b"H" if phase == "headers" else b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
    )
    # One byte keeps arriving inside each inactivity interval; total time must
    # still expire rather than letting HTTPResponse's header/body loop run on.
    transport.chunks.extend([b"x"] * 100)

    def progress(timeout):
        clock[0] += min(timeout, 0.1)

    transport.on_read = progress
    with pytest.raises(TimeoutError, match="^FIXTURE_HTTP_TIMEOUT$"):
        _FIXTURE._get(context, _ORIGIN, "/", timeout=0.25)
    assert clock[0] <= 0.25 and transport.read_count <= 3
    assert transport.closed and transport.close_count == 1


@pytest.mark.parametrize("status", [302, 404])
def test_http_refuses_redirects_and_preserves_safe_not_found_status(owned_connection, status):
    transport, context, connector, _ = owned_connection(
        response=lambda request: (
            f"HTTP/1.1 {status} {_PRIVATE}\r\nLocation: https://example.invalid\r\nContent-Length: 0\r\n\r\n"
        ).encode("ascii")
    )
    expected = AssertionError if status == 302 else _FIXTURE.HTTPError
    with pytest.raises(expected) as caught:
        _FIXTURE._get(context, _ORIGIN, "/", timeout=1)
    assert _PRIVATE not in str(caught.value)
    if status == 404:
        assert caught.value.code == 404
    connector.assert_called_once()
    assert transport.closed


def test_http_body_limit_closes_owned_transport_before_reporting_failure(owned_connection):
    transport, context, _, _ = owned_connection(
        response=lambda request: b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
    )
    with pytest.raises(pytest.fail.Exception, match="bounded read limit"):
        _FIXTURE._get(context, _ORIGIN, "/", limit=2)
    assert transport.closed


@pytest.mark.parametrize("disable_verification", [False, True])
def test_http_reader_refuses_unverified_tls_before_opening_socket(owned_connection, disable_verification):
    _, context, connector, _ = owned_connection()
    context.check_hostname = False
    if disable_verification:
        context.verify_mode = ssl.CERT_NONE
    with pytest.raises(ValueError, match="^FIXTURE_HTTP_VERIFIED_TLS_REQUIRED$"):
        _FIXTURE._get(context, _ORIGIN, "/")
    connector.assert_not_called()


@pytest.fixture
def page_clock(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(_FIXTURE.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(_FIXTURE.time, "sleep", lambda duration: clock.__setitem__(0, clock[0] + duration))
    return clock


def test_wait_page_retries_timeout_then_returns_compiled_page(monkeypatch, page_clock):
    refresh = Mock()
    get = Mock(side_effect=[TimeoutError("synthetic initial compilation timeout"), "<main>wanted</main>"])
    monkeypatch.setattr(_FIXTURE, "_refresh", refresh)
    monkeypatch.setattr(_FIXTURE, "_get", get)
    assert _FIXTURE._wait_page(object(), _ORIGIN, object(), {}, "wanted") == "<main>wanted</main>"
    assert get.call_count == refresh.call_count == 2 and page_clock[0] == 0.2
    assert all(0 < call.kwargs["timeout"] <= 5 for call in get.call_args_list)


def test_wait_page_rejects_stale_marker_until_only_new_page_is_present(monkeypatch, page_clock):
    refresh = Mock()
    get = Mock(side_effect=["old", "old new", "new"])
    monkeypatch.setattr(_FIXTURE, "_refresh", refresh)
    monkeypatch.setattr(_FIXTURE, "_get", get)
    assert _FIXTURE._wait_page(object(), _ORIGIN, object(), {}, "new", absent="old") == "new"
    assert get.call_count == refresh.call_count == 3 and page_clock[0] == 0.4


def test_wait_page_ownership_refusal_aborts_before_http_retry(monkeypatch, page_clock):
    get = Mock(side_effect=AssertionError("unverified process ownership reached HTTP"))
    monkeypatch.setattr(_FIXTURE, "_refresh", Mock(side_effect=ValueError("synthetic ownership refusal")))
    monkeypatch.setattr(_FIXTURE, "_get", get)
    with pytest.raises(ValueError, match="synthetic ownership refusal"):
        _FIXTURE._wait_page(object(), _ORIGIN, object(), {}, "new")
    get.assert_not_called()
    assert page_clock[0] == 0


def test_wait_page_does_not_request_after_ownership_check_consumes_budget(monkeypatch, page_clock):
    monkeypatch.setattr(_FIXTURE, "_refresh", lambda *args: page_clock.__setitem__(0, 61.0))
    get = Mock(side_effect=AssertionError("expired compilation budget reached HTTP"))
    monkeypatch.setattr(_FIXTURE, "_get", get)
    with pytest.raises(pytest.fail.Exception, match="bounded compilation deadline"):
        _FIXTURE._wait_page(object(), _ORIGIN, object(), {}, "new")
    get.assert_not_called()


def test_wait_page_caps_request_to_remaining_budget_and_stops_retrying(monkeypatch, page_clock):
    monkeypatch.setattr(_FIXTURE, "_refresh", Mock())

    def get(*args, timeout):
        page_clock[0] += timeout
        raise TimeoutError("synthetic compilation timeout")

    reader = Mock(side_effect=get)
    monkeypatch.setattr(_FIXTURE, "_get", reader)
    with pytest.raises(pytest.fail.Exception, match="bounded compilation deadline"):
        _FIXTURE._wait_page(object(), _ORIGIN, object(), {}, "new")
    assert page_clock[0] == 60 and reader.call_args.kwargs["timeout"] < 5


def _native_fixture_module():
    specification = importlib.util.spec_from_file_location(
        "sbom_native_compiler_fixture_policy", Path(__file__).with_name("test_dev_native_compiler.py")
    )
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


@pytest.fixture(params=("next", "native"))
def frontend_fixture_policy(request):
    return _FIXTURE if request.param == "next" else _native_fixture_module()


def test_dedicated_frontend_fixture_requires_prerequisites_instead_of_skipping(monkeypatch, frontend_fixture_policy):
    monkeypatch.setenv("SBOM_DEV_REQUIRE_FRONTEND_FIXTURE", "1")
    with pytest.raises(pytest.fail.Exception, match="^FRONTEND_FIXTURE_PREREQUISITE_REQUIRED: synthetic prerequisite$"):
        frontend_fixture_policy._prerequisite_unavailable("synthetic prerequisite")


@pytest.mark.parametrize("flag", (None, "", "0", "true", " 1", "1 "))
def test_optional_frontend_fixture_skips_unless_strict_flag_is_exactly_one(monkeypatch, frontend_fixture_policy, flag):
    if flag is None:
        monkeypatch.delenv("SBOM_DEV_REQUIRE_FRONTEND_FIXTURE", raising=False)
    else:
        monkeypatch.setenv("SBOM_DEV_REQUIRE_FRONTEND_FIXTURE", flag)
    with pytest.raises(pytest.skip.Exception, match="^synthetic prerequisite$"):
        frontend_fixture_policy._prerequisite_unavailable("synthetic prerequisite")


def test_actual_missing_prerequisite_path_uses_strict_policy_before_any_probe(
    monkeypatch, frontend_fixture_policy, tmp_path
):
    monkeypatch.setenv("SBOM_DEV_REQUIRE_FRONTEND_FIXTURE", "1")
    forbidden = Mock(side_effect=AssertionError("A missing prerequisite reached a live probe"))
    monkeypatch.setattr(frontend_fixture_policy.subprocess, "run", forbidden)
    if frontend_fixture_policy is _FIXTURE:
        monkeypatch.setattr(frontend_fixture_policy.importlib.util, "find_spec", lambda name: None)
        check, arguments = frontend_fixture_policy._prerequisites, (tmp_path,)
    else:
        monkeypatch.setattr(frontend_fixture_policy.shutil, "which", lambda name: None)
        check, arguments = frontend_fixture_policy._installed_packages, ()
    with pytest.raises(pytest.fail.Exception, match="^FRONTEND_FIXTURE_PREREQUISITE_REQUIRED:"):
        check(*arguments)
    forbidden.assert_not_called()
