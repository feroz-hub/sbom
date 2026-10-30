"""New-file permission/error regressions; synthetic temp files, --noconftest."""

from __future__ import annotations

import ctypes
import errno
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev_private

SECRET = b"fixture-private-bytes-never-log"


def test_parent_validation_is_contained_and_creates_no_directories(tmp_path):
    root = tmp_path / "checkout"
    root.mkdir()
    path = root / "frontend/certificates/new-private-file"
    dev_private.validate_parent(path, root, allow_missing=True)
    assert list(root.iterdir()) == []
    with pytest.raises(dev_private.PrivateFileError):
        dev_private.validate_parent(path, root)
    for outside in (tmp_path / "outside/new-private-file", root / "../outside/new-private-file"):
        with pytest.raises(dev_private.PrivateFileError) as caught:
            dev_private.validate_parent(outside, root, allow_missing=True)
        assert str(tmp_path) not in str(caught.value)
    assert list(root.iterdir()) == []


def test_parent_validation_walk_is_bounded(tmp_path):
    path = tmp_path.joinpath(*("directory" for _ in range(65)), "new-private-file")
    with pytest.raises(dev_private.PrivateFileError):
        dev_private.validate_parent(path, tmp_path, allow_missing=True)


def test_parent_validation_refuses_regular_file_and_reparse_directories(tmp_path, monkeypatch):
    parent = tmp_path / "parent"
    parent.write_bytes(b"synthetic-existing-file")
    with pytest.raises(dev_private.PrivateFileError):
        dev_private.validate_parent(parent / "new-private-file", tmp_path, allow_missing=True)
    parent.unlink()
    parent.mkdir()
    original = Path.lstat

    def reparse(path):
        info = original(path)
        return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=1024) if path == parent else info

    monkeypatch.setattr(Path, "lstat", reparse)
    with pytest.raises(dev_private.PrivateFileError):
        dev_private.validate_parent(parent / "new-private-file", tmp_path)
    assert list(parent.iterdir()) == []


def redirected_checkout(tmp_path):
    root, outside = tmp_path / "checkout", tmp_path / "outside"
    (root / "frontend").mkdir(parents=True)
    outside.mkdir()
    link = root / "frontend/certificates"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Host has no approved directory-symlink creation privilege")
    return root, outside, link


def test_setup_certificate_plan_refuses_redirected_parent(tmp_path):
    from scripts import dev_setup

    root, outside, _ = redirected_checkout(tmp_path)
    actions, blockers = {}, []
    dev_setup._certificates(SimpleNamespace(ROOT=root), dev_setup._Snapshot(), actions, blockers)
    assert not actions
    assert any(item.startswith("CERTIFICATE_PARENT_UNVERIFIED") for item in blockers)
    assert list(outside.iterdir()) == []


def test_certificate_application_refuses_redirect_before_generation(tmp_path, monkeypatch):
    from scripts import dev

    root, outside, link = redirected_checkout(tmp_path)
    monkeypatch.setattr(dev, "ROOT", root)
    monkeypatch.setattr(dev, "_development_library", lambda name: dev_private)
    with pytest.raises(dev.SetupError, match="CERTIFICATE_PARENT_UNVERIFIED"):
        dev.create_local_certificate(link / "localhost.pem", link / "localhost-key.pem")
    assert link.is_symlink()
    assert list(outside.iterdir()) == []


def test_new_configuration_publication_refuses_redirected_parent(tmp_path, monkeypatch):
    from scripts import dev

    root, outside, link = redirected_checkout(tmp_path)
    monkeypatch.setattr(dev, "ROOT", root)
    monkeypatch.setattr(dev, "_development_library", lambda name: dev_private)
    with pytest.raises(dev.SetupError, match="PRIVATE_CONFIG_PARENT_UNVERIFIED"):
        dev.write_config({"SYNTHETIC_SECRET": SECRET.decode()}, link / ".env.dev.local", create_only=True)
    assert link.is_symlink()
    assert list(outside.iterdir()) == []


def test_create_new_file_and_preserve_existing(tmp_path):
    path = tmp_path / "synthetic-private-file"
    dev_private.create_private_file(path, SECRET)
    assert path.read_bytes() == SECRET
    before = path.stat()
    with pytest.raises(dev_private.PrivateFileError) as caught:
        dev_private.create_private_file(path, b"replacement")
    assert path.read_bytes() == SECRET
    assert path.stat().st_ino == before.st_ino
    assert SECRET.decode() not in str(caught.value)
    assert str(path) not in str(caught.value)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode semantics")
def test_posix_creation_requests_exclusive_nofollow_and_0600(tmp_path, monkeypatch):
    path = tmp_path / "synthetic-private-file"
    original = os.open
    opened = Mock(side_effect=original)
    monkeypatch.setattr(dev_private.os, "open", opened)
    dev_private.create_private_file(path, SECRET)
    assert opened.call_args.args[1] & os.O_CREAT
    assert opened.call_args.args[1] & os.O_EXCL
    assert opened.call_args.args[1] & getattr(os, "O_NOFOLLOW", 0) == getattr(os, "O_NOFOLLOW", 0)
    assert opened.call_args.args[2] == 0o600
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_no_parent_directory_creation(tmp_path):
    parent = tmp_path / "missing-directory"
    with pytest.raises(dev_private.PrivateFileError):
        dev_private.create_private_file(parent / "synthetic-private-file", SECRET)
    assert not parent.exists()


def test_symlink_is_not_followed_or_replaced(tmp_path):
    target, link = tmp_path / "preserved", tmp_path / "redirected"
    target.write_bytes(b"preserved-synthetic-data")
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Host has no approved symlink creation privilege")
    with pytest.raises(dev_private.PrivateFileError):
        dev_private.create_private_file(link, SECRET)
    assert link.is_symlink()
    assert target.read_bytes() == b"preserved-synthetic-data"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX descriptor ownership fixture")
def test_short_writes_are_completed_and_only_owned_descriptor_closed(tmp_path, monkeypatch):
    path = tmp_path / "synthetic-private-file"
    original_write, original_close = os.write, os.close
    writes = Mock(side_effect=lambda fd, data: original_write(fd, data[:3]))
    closed = Mock(side_effect=original_close)
    monkeypatch.setattr(dev_private.os, "write", writes)
    monkeypatch.setattr(dev_private.os, "close", closed)
    dev_private.create_private_file(path, SECRET)
    assert path.read_bytes() == SECRET
    assert writes.call_count > 1
    closed.assert_called_once()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX descriptor ownership fixture")
@pytest.mark.parametrize("stage", ["write", "fsync", "close", "zero-progress"])
def test_write_failures_close_descriptor_and_redact_details(tmp_path, monkeypatch, stage):
    path = tmp_path / "synthetic-private-file"
    original_close = os.close
    closed = Mock(side_effect=original_close)
    monkeypatch.setattr(dev_private.os, "close", closed)
    failure = OSError(errno.EIO, SECRET.decode(), str(path))
    if stage == "close":

        def close_then_fail(fd):
            original_close(fd)
            raise failure

        closed.side_effect = close_then_fail
    elif stage == "zero-progress":
        monkeypatch.setattr(dev_private.os, "write", lambda *args: 0)
    else:
        monkeypatch.setattr(dev_private.os, stage, Mock(side_effect=failure))
    with pytest.raises(dev_private.PrivateFileError) as caught:
        dev_private.create_private_file(path, SECRET)
    closed.assert_called_once()
    assert SECRET.decode() not in str(caught.value)
    assert str(path) not in str(caught.value)
    assert caught.value.__suppress_context__
    assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0


class WindowsFiles:
    """Stateful WinDLL boundary double: allocation, identity and handle ownership."""

    def __init__(self, failure=None):
        self.failure, self.last_error = failure, 0
        self.closed, self.freed, self.order = [], [], []
        self.sid_address, self.sddl = None, None
        self.descriptor, self.token, self.file = 7001, 31, 41
        self.created = 0
        for name in (
            "GetCurrentProcess",
            "CloseHandle",
            "LocalFree",
            "GetVolumePathNameW",
            "GetVolumeInformationW",
            "CreateFileW",
            "OpenProcessToken",
            "GetTokenInformation",
            "ConvertSidToStringSidW",
            "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        ):
            setattr(self, name, Mock(side_effect=getattr(self, "_" + name)))

    def fails(self, name):
        self.order.append(name)
        if name == self.failure:
            self.last_error = 5
            return True
        return False

    @staticmethod
    def number(value):
        return getattr(value, "value", value)

    def _GetCurrentProcess(self):
        return -1

    def _GetVolumePathNameW(self, path, root, count):
        if self.fails("GetVolumePathNameW"):
            return 0
        root.value = "C:\\"
        return 1

    def _GetVolumeInformationW(self, root, name, size, serial, component, flags, filesystem, capacity):
        if self.fails("GetVolumeInformationW"):
            return 0
        flags._obj.value = 0 if self.failure == "NoPersistentAcl" else 8
        return 1

    def _OpenProcessToken(self, process, access, output):
        assert process == -1 and access == 8
        if self.fails("OpenProcessToken"):
            return 0
        output._obj.value = self.token
        return 1

    def _GetTokenInformation(self, token, kind, buffer, size, output):
        assert token.value == self.token and kind == 1
        query = "GetTokenSize" if buffer is None else "GetTokenInformation"
        if self.fails(query):
            return 0
        output._obj.value = ctypes.sizeof(ctypes.c_void_p) + 16
        if buffer is None:
            self.last_error = 122
            return 0
        ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0] = 1234
        return 1

    def _ConvertSidToStringSidW(self, sid, output):
        assert sid == 1234
        if self.fails("ConvertSidToStringSidW"):
            return 0
        output._obj.value = "S-1-5-21-111-222-333-1001"
        self.sid_address = ctypes.cast(output._obj, ctypes.c_void_p).value
        return 1

    def _ConvertStringSecurityDescriptorToSecurityDescriptorW(self, text, revision, output, size):
        self.sddl = text
        assert revision == 1
        if self.fails("ConvertStringSecurityDescriptorToSecurityDescriptorW"):
            return 0
        output._obj.value = self.descriptor
        return 1

    def _CreateFileW(self, path, access, share, attributes, creation, flags, template):
        assert self.sddl == "O:S-1-5-21-111-222-333-1001D:P(A;;FA;;;S-1-5-21-111-222-333-1001)(A;;FA;;;SY)(A;;FA;;;BA)"
        assert attributes._obj.lpSecurityDescriptor == self.descriptor
        assert attributes._obj.nLength == ctypes.sizeof(attributes._obj)
        assert not attributes._obj.bInheritHandle
        assert creation == 1 and share == 0 and access == 0x40000000
        assert flags & 0x200000  # Open reparse point, never follow a final redirect.
        if self.fails("CreateFileW"):
            return ctypes.c_void_p(-1).value
        self.created += 1
        return self.file

    def _CloseHandle(self, handle):
        value = self.number(handle)
        assert value not in self.closed
        self.closed.append(value)
        return int(not self.fails("CloseHandle"))

    def _LocalFree(self, pointer):
        value = self.number(pointer)
        assert value not in self.freed
        self.freed.append(value)
        return value if self.fails("LocalFree") else None


@pytest.fixture
def windows(monkeypatch):
    kernel = WindowsFiles()
    monkeypatch.setattr(dev_private.ctypes, "WinDLL", lambda *args, **kwargs: kernel, raising=False)
    monkeypatch.setattr(dev_private.ctypes, "get_last_error", lambda: kernel.last_error, raising=False)
    monkeypatch.setattr(dev_private.os, "O_BINARY", 0x8000, raising=False)
    monkeypatch.setattr(dev_private.os, "O_NOINHERIT", 0x80, raising=False)
    adopt = Mock(return_value=91)
    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace(open_osfhandle=adopt))
    return kernel, adopt


def test_windows_secure_descriptor_precedes_creation_and_transfer(windows):
    kernel, adopt = windows
    assert dev_private._windows_fd("C:/synthetic/new-private-file") == 91
    assert kernel.created == 1
    assert kernel.closed == [kernel.token]
    assert set(kernel.freed) == {kernel.sid_address, kernel.descriptor}
    assert kernel.order.index("ConvertStringSecurityDescriptorToSecurityDescriptorW") < kernel.order.index(
        "CreateFileW"
    )
    adopt.assert_called_once_with(kernel.file, os.O_BINARY | os.O_NOINHERIT)


@pytest.mark.parametrize(
    "stage",
    [
        "GetVolumePathNameW",
        "GetVolumeInformationW",
        "NoPersistentAcl",
        "OpenProcessToken",
        "GetTokenSize",
        "GetTokenInformation",
        "ConvertSidToStringSidW",
        "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        "CreateFileW",
        "CloseHandle",
        "LocalFree",
    ],
)
def test_windows_api_failures_release_only_allocated_resources_and_never_adopt(windows, stage):
    kernel, adopt = windows
    kernel.failure = stage
    with pytest.raises(dev_private.PrivateFileError):
        dev_private._windows_fd("C:/synthetic/new-private-file")
    if "OpenProcessToken" in kernel.order and stage != "OpenProcessToken":
        assert kernel.closed.count(kernel.token) == 1
    if kernel.sid_address:
        assert kernel.sid_address in kernel.freed
    if kernel.created:
        assert kernel.closed.count(kernel.file) == 1
    assert len(kernel.closed) == len(set(kernel.closed))
    assert len(kernel.freed) == len(set(kernel.freed))
    adopt.assert_not_called()


def test_windows_crt_transfer_failure_closes_native_file_once(windows):
    kernel, adopt = windows
    adopt.side_effect = OSError(errno.EMFILE, SECRET.decode())
    with pytest.raises(OSError):
        dev_private._windows_fd("C:/synthetic/new-private-file")
    assert kernel.closed == [kernel.token, kernel.file]
    assert set(kernel.freed) == {kernel.sid_address, kernel.descriptor}


def test_windows_negative_crt_result_does_not_transfer_handle(windows):
    kernel, adopt = windows
    adopt.return_value = -1
    with pytest.raises(dev_private.PrivateFileError):
        dev_private._windows_fd("C:/synthetic/new-private-file")
    assert kernel.closed == [kernel.token, kernel.file]


def test_windows_public_success_closes_only_adopted_descriptor(windows, monkeypatch, tmp_path):
    kernel, _ = windows
    monkeypatch.setattr(dev_private.sys, "platform", "win32")
    monkeypatch.setattr(dev_private.os, "write", Mock(side_effect=lambda fd, data: len(data)))
    synced, closed = Mock(), Mock()
    monkeypatch.setattr(dev_private.os, "fsync", synced)
    monkeypatch.setattr(dev_private.os, "close", closed)
    dev_private.create_private_file(tmp_path / "synthetic-file", SECRET)
    synced.assert_called_once_with(91)
    closed.assert_called_once_with(91)
    assert kernel.closed == [kernel.token]


def test_windows_public_write_failure_closes_adopted_fd_not_handle(windows, monkeypatch, tmp_path):
    kernel, adopt = windows
    monkeypatch.setattr(dev_private.sys, "platform", "win32")
    monkeypatch.setattr(dev_private.os, "write", Mock(side_effect=OSError(errno.EIO, SECRET.decode())))
    closed = Mock()
    monkeypatch.setattr(dev_private.os, "close", closed)
    with pytest.raises(dev_private.PrivateFileError) as caught:
        dev_private.create_private_file(tmp_path / "synthetic-file", SECRET)
    assert SECRET.decode() not in str(caught.value)
    assert str(tmp_path) not in str(caught.value)
    closed.assert_called_once_with(91)
    assert kernel.closed == [kernel.token]
    adopt.assert_called_once()


@pytest.mark.parametrize("name", ["NUL", "CON", "CON .txt", "COM1", "LPT9", "normal:stream", "\\\\.\\pipe\\private"])
def test_windows_devices_and_alternate_streams_are_refused_before_creation(windows, monkeypatch, name):
    kernel, adopt = windows
    monkeypatch.setattr(dev_private.sys, "platform", "win32")
    with pytest.raises(dev_private.PrivateFileError):
        dev_private.create_private_file(name, SECRET)
    assert kernel.created == 0
    adopt.assert_not_called()


@pytest.mark.skipif(sys.platform != "win32", reason="Actual native Windows DACL acceptance")
def test_native_windows_new_file_has_protected_private_dacl(tmp_path):
    from scripts import dev

    path = tmp_path / "synthetic-private-file"
    dev_private.create_private_file(path, SECRET)
    assert path.read_bytes() == SECRET
    dev.LocalHttps._windows_access(path, private=True)  # Get-Acl only, no ACL mutation.
