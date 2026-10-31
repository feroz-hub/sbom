"""Private-directory contracts; only synthetic temporary directories, --noconftest."""

from __future__ import annotations

import ctypes as ct
import errno
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev_instance_storage as storage


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode and dir-fd semantics")
def test_posix_creates_missing_descendants_and_reuses_private_directories(tmp_path):
    anchor = tmp_path.resolve()
    target = anchor / "registry" / "instances"
    storage.initialize_private_directory(target, anchor=anchor)
    identities = {path: path.stat().st_ino for path in (anchor, target.parent, target)}
    assert stat.S_IMODE(target.stat().st_mode) == 0o700
    assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700
    storage.initialize_private_directory(target, anchor=anchor)
    assert identities == {path: path.stat().st_ino for path in identities}
    assert not list(target.iterdir())


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission semantics")
@pytest.mark.parametrize("mode", [0o755, 0o750, 0o770, 0o777])
def test_existing_nonprivate_descendant_is_refused_without_permission_repair(tmp_path, mode):
    anchor = tmp_path.resolve()
    parent = anchor / "registry"
    parent.mkdir(mode=mode)
    parent.chmod(mode)
    before = parent.stat()
    with pytest.raises(storage.DirectoryInitializationError) as caught:
        storage.initialize_private_directory(parent / "instances", anchor=anchor)
    assert caught.value.code == "INSTANCE_DIRECTORY_ACCESS_UNVERIFIED"
    assert parent.stat().st_mode == before.st_mode and parent.stat().st_ino == before.st_ino
    assert not (parent / "instances").exists()


@pytest.mark.parametrize("case", ["outside", "traversal", "anchor", "deep", "file"])
def test_invalid_paths_cannot_create_or_replace_material(tmp_path, case):
    anchor = tmp_path.resolve()
    target = anchor / "registry" / "instances"
    expected = {
        "outside": "INSTANCE_DIRECTORY_OUTSIDE_ANCHOR",
        "traversal": "INSTANCE_DIRECTORY_PATH_INVALID",
        "anchor": "INSTANCE_DIRECTORY_TARGET_REQUIRED",
        "deep": "INSTANCE_DIRECTORY_DEPTH_REQUIRED",
        "file": "INSTANCE_DIRECTORY_REDIRECTED",
    }[case]
    if case == "outside":
        target = anchor.parent / "outside-owned-fixture"
    elif case == "traversal":
        target = anchor / ".." / "outside-owned-fixture"
    elif case == "anchor":
        target = anchor
    elif case == "deep":
        target = anchor.joinpath(*("segment" for _ in range(65)))
    elif case == "file":
        target.parent.mkdir(mode=0o700)
        target.write_bytes(b"synthetic-existing-material")
    # Path validation does not require native ACL policy for these cases.
    if case == "file" and sys.platform == "win32":
        pytest.skip("Native Windows file refusal is covered with a private anchor")
    with pytest.raises(storage.DirectoryInitializationError) as caught:
        storage.initialize_private_directory(target, anchor=anchor)
    assert caught.value.code == expected
    assert str(tmp_path) not in str(caught.value)
    if case == "file":
        assert target.read_bytes() == b"synthetic-existing-material"
    else:
        assert not (anchor.parent / "outside-owned-fixture").exists()


def test_redirected_directory_is_refused_without_following_target(tmp_path, monkeypatch):
    anchor = tmp_path.resolve()
    parent = anchor / "registry"
    parent.mkdir()
    original = Path.lstat

    def metadata(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if path == parent:
            return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=1024)
        return info

    monkeypatch.setattr(Path, "lstat", metadata)
    if sys.platform == "win32":
        monkeypatch.setattr(storage.dev_windows_acl, "verify_access", lambda *args, **kwargs: None)
        monkeypatch.setattr(storage, "_pin_windows", lambda path: lambda: None)
    with pytest.raises(storage.DirectoryInitializationError) as caught:
        storage.initialize_private_directory(parent / "instances", anchor=anchor)
    assert caught.value.code == "INSTANCE_DIRECTORY_REDIRECTED"
    assert not list(parent.iterdir())


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink fixture")
def test_symlink_anchor_or_child_is_never_adopted(tmp_path):
    root = tmp_path.resolve()
    actual = root / "actual"
    actual.mkdir(mode=0o700)
    alias = root / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    with pytest.raises(storage.DirectoryInitializationError) as caught:
        storage.initialize_private_directory(alias / "instances", anchor=alias)
    assert caught.value.code == "INSTANCE_DIRECTORY_ANCHOR_REDIRECTED"
    with pytest.raises(storage.DirectoryInitializationError):
        storage.initialize_private_directory(alias / "instances", anchor=root)
    assert not list(actual.iterdir())


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX directory-fd creation")
def test_failure_retains_created_directories_without_recursive_cleanup(tmp_path, monkeypatch):
    anchor = tmp_path.resolve()
    original = os.mkdir

    def mkdir(name, mode=0o777, **kwargs):
        if name == "instances":
            raise OSError(errno.ENOSPC, "synthetic-sensitive-error")
        return original(name, mode, **kwargs)

    monkeypatch.setattr(os, "mkdir", mkdir)
    cleanup = Mock(side_effect=AssertionError("Creation must never delete partial artifacts"))
    monkeypatch.setattr(os, "rmdir", cleanup)
    with pytest.raises(storage.DirectoryInitializationError) as caught:
        storage.initialize_private_directory(anchor / "registry" / "instances", anchor=anchor)
    assert caught.value.errno == errno.ENOSPC
    assert "synthetic-sensitive-error" not in str(caught.value)
    assert (anchor / "registry").is_dir() and not (anchor / "registry" / "instances").exists()
    cleanup.assert_not_called()


class WindowsCreation:
    def __init__(self, monkeypatch, failure=None):
        self.failure, self.last_error, self.created, self.sddl = failure, 0, [], None
        self.closed, self.freed, self.buffers = [], [], []
        for name in (
            "GetCurrentProcess",
            "CloseHandle",
            "LocalFree",
            "GetVolumePathNameW",
            "GetVolumeInformationW",
            "CreateDirectoryW",
            "OpenProcessToken",
            "GetTokenInformation",
            "IsValidSid",
            "ConvertSidToStringSidW",
            "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            "CreateFileW",
            "GetFileInformationByHandle",
        ):
            setattr(self, name, Mock(side_effect=getattr(self, "_" + name)))
        monkeypatch.setattr(storage.ct, "get_last_error", lambda: self.last_error, raising=False)
        monkeypatch.setattr(storage, "_windows_apis", lambda: (self, self))

    def failed(self, name):
        if self.failure == name:
            self.last_error = 5
            return True
        return False

    def _GetCurrentProcess(self):
        return 42

    def _GetVolumePathNameW(self, name, volume, length):
        volume.value = "C:\\"
        return not self.failed("GetVolumePathNameW")

    def _GetVolumeInformationW(self, name, label, size, serial, maximum, flags, filesystem, capacity):
        ct.cast(flags, ct.POINTER(ct.c_uint32))[0] = 0 if self.failure == "no-acls" else 8
        return not self.failed("GetVolumeInformationW")

    def _OpenProcessToken(self, process, rights, token):
        ct.cast(token, ct.POINTER(ct.c_void_p))[0] = 31
        return not self.failed("OpenProcessToken")

    def _GetTokenInformation(self, token, kind, user, capacity, size):
        ct.cast(size, ct.POINTER(ct.c_uint32))[0] = 64
        if user is None:
            self.last_error = 122
            return False
        if self.failed("GetTokenInformation"):
            return False
        address = ct.addressof(user) + 16
        ct.cast(user, ct.POINTER(ct.c_void_p))[0] = address
        ct.memmove(address, bytes((1, 1)) + b"\0" * 5 + b"\x05" + b"\x01\0\0\0", 12)
        return True

    def _IsValidSid(self, sid):
        return not self.failed("IsValidSid")

    def _ConvertSidToStringSidW(self, sid, output):
        buffer = ct.create_unicode_buffer("S-1-5-21-1001")
        self.buffers.append(buffer)
        ct.cast(output, ct.POINTER(ct.c_wchar_p))[0] = ct.cast(buffer, ct.c_wchar_p)
        return not self.failed("ConvertSidToStringSidW")

    def _ConvertStringSecurityDescriptorToSecurityDescriptorW(self, sddl, revision, output, size):
        self.sddl = sddl
        buffer = ct.create_string_buffer(32)
        self.buffers.append(buffer)
        ct.cast(output, ct.POINTER(ct.c_void_p))[0] = ct.addressof(buffer)
        return not self.failed("ConvertStringSecurityDescriptorToSecurityDescriptorW")

    def _CreateDirectoryW(self, name, attributes):
        if self.failed("CreateDirectoryW"):
            return False
        self.created.append(name)
        return True

    def _LocalFree(self, value):
        self.freed.append(value.value)
        return 1 if self.failed("LocalFree") else 0

    def _CloseHandle(self, handle):
        self.closed.append(handle.value if hasattr(handle, "value") else handle)
        return not self.failed("CloseHandle")

    def _CreateFileW(self, path, rights, sharing, attributes, disposition, flags, template):
        assert sharing == 3 and flags == 0x2200000
        return None if self.failed("CreateFileW") else 41

    def _GetFileInformationByHandle(self, handle, output):
        ct.cast(output, ct.POINTER(storage.dev_windows_acl.FileInformation))[0].attributes = 16
        return not self.failed("GetFileInformationByHandle")


def test_windows_creation_supplies_owner_protected_dacl_at_create_time(monkeypatch):
    api = WindowsCreation(monkeypatch)
    storage._windows_create(Path("synthetic-directory"))
    assert api.created == ["synthetic-directory"]
    assert api.sddl == "O:S-1-5-21-1001D:P(A;OICI;FA;;;S-1-5-21-1001)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    assert api.closed == [31] and len(api.freed) == 2


@pytest.mark.parametrize(
    "failure",
    [
        "GetVolumePathNameW",
        "GetVolumeInformationW",
        "no-acls",
        "OpenProcessToken",
        "GetTokenInformation",
        "IsValidSid",
        "ConvertSidToStringSidW",
        "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        "CreateDirectoryW",
        "LocalFree",
        "CloseHandle",
    ],
)
def test_windows_api_failures_are_closed_redacted_and_release_metadata(monkeypatch, failure):
    api = WindowsCreation(monkeypatch, failure)
    with pytest.raises(storage.DirectoryInitializationError) as caught:
        storage._windows_create(Path("sensitive-fixture-path"))
    assert "sensitive-fixture-path" not in str(caught.value)
    assert caught.value.code.startswith("INSTANCE_DIRECTORY_")
    if failure not in {"LocalFree", "CloseHandle"}:
        assert not api.created
    if api.OpenProcessToken.called:
        assert 31 in api.closed


@pytest.mark.parametrize("failure", [None, "CreateFileW", "GetFileInformationByHandle", "CloseHandle"])
def test_windows_pinned_directories_never_allow_delete_sharing(monkeypatch, failure):
    api = WindowsCreation(monkeypatch, failure)
    if failure is None:
        close = storage._pin_windows(Path("fixture-directory"))
        assert not api.closed
        close()
        assert api.closed == [41]
    else:
        with pytest.raises(storage.DirectoryInitializationError):
            close = storage._pin_windows(Path("fixture-directory"))
            close()


@pytest.mark.skipif(sys.platform != "win32", reason="Actual Windows ACL/creation acceptance")
def test_native_windows_private_directory_creation_and_existing_reuse(tmp_path):
    anchor = tmp_path.resolve() / "private-anchor"
    storage._windows_create(anchor)  # Explicit brand-new synthetic directory only.
    storage.dev_windows_acl.verify_access(anchor, private=True)
    target = anchor / "registry" / "instances"
    storage.initialize_private_directory(target, anchor=anchor)
    before = {path: path.stat().st_ino for path in (anchor, target.parent, target)}
    for path in (target.parent, target):
        storage.dev_windows_acl.verify_access(path, private=True)
    storage.initialize_private_directory(target, anchor=anchor)
    assert before == {path: path.stat().st_ino for path in before}
    assert not list(target.iterdir())


@pytest.mark.skipif(sys.platform != "win32", reason="Actual Windows private anchor")
def test_native_windows_regular_file_target_is_preserved(tmp_path):
    anchor = tmp_path.resolve() / "private-anchor"
    storage._windows_create(anchor)
    target = anchor / "existing-record"
    target.write_bytes(b"synthetic-existing-material")
    before = target.stat().st_ino
    with pytest.raises(storage.DirectoryInitializationError) as caught:
        storage.initialize_private_directory(target, anchor=anchor)
    assert caught.value.code == "INSTANCE_DIRECTORY_REDIRECTED"
    assert target.read_bytes() == b"synthetic-existing-material" and target.stat().st_ino == before


def test_windows_acl_denial_is_redacted_and_never_repaired(tmp_path, monkeypatch):
    anchor = tmp_path.resolve()
    monkeypatch.setattr(storage.sys, "platform", "win32")
    denied = Mock(side_effect=storage.dev_windows_acl.AclVerificationError("sensitive-fixture-message", 5))
    monkeypatch.setattr(storage.dev_windows_acl, "verify_access", denied)
    creator = Mock(side_effect=AssertionError("Unverified anchor must not create state"))
    monkeypatch.setattr(storage, "_windows_create", creator)
    with pytest.raises(storage.DirectoryInitializationError) as caught:
        storage.initialize_private_directory(anchor / "registry", anchor=anchor)
    assert caught.value.code == "INSTANCE_DIRECTORY_ACCESS_UNVERIFIED" and caught.value.winerror == 5
    assert "sensitive-fixture-message" not in str(caught.value)
    creator.assert_not_called()


def test_changed_parent_identity_aborts_and_retains_partial_state(tmp_path, monkeypatch):
    anchor = tmp_path.resolve()
    created = []

    def verify(path, *, private):
        if path != anchor and not created:
            raise FileNotFoundError()
        return SimpleNamespace(st_dev=1, st_ino=(99 if created else 1) if path == anchor else 2)

    monkeypatch.setattr(storage.sys, "platform", "win32")
    monkeypatch.setattr(storage, "_verify", verify)
    monkeypatch.setattr(storage, "_pin_windows", lambda path: lambda: None)
    monkeypatch.setattr(storage, "_windows_create", lambda path: created.append(path))
    cleanup = Mock(side_effect=AssertionError("Must preserve partial directories"))
    monkeypatch.setattr(os, "rmdir", cleanup)
    with pytest.raises(storage.DirectoryInitializationError) as caught:
        storage.initialize_private_directory(anchor / "registry", anchor=anchor)
    assert caught.value.code == "INSTANCE_DIRECTORY_CHANGED"
    assert created == [anchor / "registry"]
    cleanup.assert_not_called()
