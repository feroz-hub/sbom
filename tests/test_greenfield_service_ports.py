"""Real loopback port regressions; no database, credentials or services are used."""
from __future__ import annotations

import errno
import socket
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev
from scripts.dev import GreenfieldStack as stack


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX TIME_WAIT reuse policy")
def test_recently_closed_service_does_not_block_restart():
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        server.listen(1)
        with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
            accepted, _ = server.accept()
            with accepted:
                accepted.shutdown(socket.SHUT_WR)
            assert client.recv(1) == b""
    # Regression: no listener remains, but the old raw bind returned EADDRINUSE.
    with socket.socket() as raw:
        with pytest.raises(OSError) as observed:
            raw.bind(("127.0.0.1", port))
        assert observed.value.errno == errno.EADDRINUSE
    stack.check_service_ports((port,))
    # The preflight must release the socket so the real application can start.
    with socket.socket() as application:
        application.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        application.bind(("127.0.0.1", port))
        application.listen(1)


def test_live_listener_is_rejected_without_stopping_it():
    with socket.socket() as server:
        if sys.platform != "win32":
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        server.listen(1)
        with pytest.raises(stack.ServicePortError, match=rf"port {port}.*already in use.*No process was stopped"):
            stack.check_service_ports((port,))
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            accepted, _ = server.accept()
            accepted.close()


def test_conflict_precedes_credentials_workspace_and_process_creation(monkeypatch):
    conflict = stack.ServicePortError("Synthetic occupied port 18000")
    monkeypatch.setattr(stack, "check_service_ports", Mock(side_effect=conflict))
    forbidden = Mock(side_effect=AssertionError("side effect before port check"))
    monkeypatch.setattr(stack, "settings", forbidden)
    monkeypatch.setattr(stack, "frontend_workspace", forbidden)
    monkeypatch.setattr(stack, "verify_resources", forbidden)
    monkeypatch.setattr(dev.subprocess, "Popen", forbidden)
    monkeypatch.setattr(dev.LocalHttps, "ensure_certificate", forbidden)
    with pytest.raises(stack.ServicePortError, match="18000"):
        dev.GreenfieldProfile.start_services(Mock())
    forbidden.assert_not_called()


def test_launcher_reports_specific_conflict_without_verbose(monkeypatch):
    monkeypatch.setattr(dev, "check_application_ports", Mock())
    monkeypatch.setattr(dev, "ensure_dependencies", Mock())
    monkeypatch.setattr(dev, "ensure_frontend", Mock())
    monkeypatch.setattr(dev.GreenfieldProfile, "start", Mock(side_effect=dev.GreenfieldStack.ServicePortError("port 18000 already in use")))
    with pytest.raises(dev.SetupError, match="port 18000 already in use"):
        dev.start_application(SimpleNamespace(profile="greenfield", check=False))


@pytest.mark.parametrize("platform,reuse", [("darwin", True), ("linux", True), ("win32", False)])
def test_reuse_policy_never_enables_reuse_on_windows(monkeypatch, platform, reuse):
    sock = Mock()
    factory = Mock()
    factory.return_value.__enter__ = Mock(return_value=sock)
    factory.return_value.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(dev.socket, "socket", factory)
    monkeypatch.setattr(dev.sys, "platform", platform)
    stack.check_service_ports((18000,))
    if reuse:
        sock.setsockopt.assert_called_once_with(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    else:
        sock.setsockopt.assert_not_called()
    sock.bind.assert_called_once_with(("127.0.0.1", 18000))
