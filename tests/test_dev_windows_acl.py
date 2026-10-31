"""Native ACL metadata contracts; synthetic buffers/files only, --noconftest."""

from __future__ import annotations

import ctypes as ct
import struct
import sys
from unittest.mock import Mock

import pytest
from scripts import dev_windows_acl as acl

SECRET = "synthetic-private-material-never-log"


def sid(authority, *parts):
    return bytes((1, len(parts))) + authority.to_bytes(6, "big") + struct.pack("<" + "I" * len(parts), *parts)


CURRENT, SYSTEM, ADMIN, OTHER = sid(5, 21, 111, 222, 333, 1001), sid(5, 18), sid(5, 32, 544), sid(1, 0)


def ace(kind=0, rights=0x1F01FF, trustee=CURRENT, *, objects=0, flags=0):
    body = struct.pack("<I", rights)
    if kind in {5, 6, 11, 12}:
        body += struct.pack("<I", objects) + b"g" * (16 * bool(objects & 1) + 16 * bool(objects & 2))
    body += trustee
    if kind in {9, 10, 11, 12}:
        body += b"cond"  # Opaque callback data is never evaluated to weaken a grant.
    return struct.pack("<BBH", kind, flags, len(body) + 4) + body


class WindowsAcl:
    """Actual ctypes structure buffers with a stateful WinDLL/API boundary."""

    def __init__(self, entries=None, owner=CURRENT, revision=None):
        self.entries = entries if entries is not None else [ace(), ace(trustee=SYSTEM), ace(trustee=ADMIN)]
        if revision is None:
            revision = 4 if any(entry[0] in {5, 6, 11, 12} for entry in self.entries) else 2
        raw = b"".join(self.entries)
        self.acl = ct.create_string_buffer(struct.pack("<BBHHH", revision, 0, 8 + len(raw), len(self.entries), 0) + raw)
        self.owner, self.descriptor = ct.create_string_buffer(owner), ct.create_string_buffer(32)
        self.used = 8 + len(raw)
        self.count, self.free = len(self.entries), 0
        self.failure, self.last_error = None, 0
        self.attributes = 0x80
        self.file, self.token = 41, 31
        self.opened, self.token_opened, self.allocated = False, False, False
        self.null_dacl, self.null_owner, self.null_descriptor = False, False, False
        self.closed, self.freed, self.events = [], [], []
        for name in (
            "CreateFileW",
            "GetFileInformationByHandle",
            "GetCurrentProcess",
            "CloseHandle",
            "LocalFree",
            "GetSecurityInfo",
            "OpenProcessToken",
            "GetTokenInformation",
            "CreateWellKnownSid",
            "IsValidSid",
            "EqualSid",
            "IsValidAcl",
            "GetAclInformation",
            "GetAce",
        ):
            setattr(self, name, Mock(side_effect=getattr(self, "_" + name)))

    @staticmethod
    def pointer(value):
        return ct.cast(value, ct.c_void_p).value

    @classmethod
    def sid_bytes(cls, value):
        pointer = cls.pointer(value)
        count = ct.string_at(pointer, 2)[1]
        return ct.string_at(pointer, 8 + 4 * count)

    def fail(self, operation):
        self.events.append(operation)
        if self.failure == operation:
            self.last_error = 5
            return True
        return False

    def _CreateFileW(self, path, access, share, attributes, disposition, flags, template):
        assert access == 0x20080 and share == 7 and disposition == 3
        assert attributes is None and template is None
        assert flags == 0x2200000
        if self.fail("CreateFileW"):
            return ct.c_void_p(-1).value
        self.opened = True
        return self.file

    def _GetFileInformationByHandle(self, handle, output):
        assert handle == self.file
        if self.fail("GetFileInformationByHandle"):
            return 0
        output._obj.attributes = self.attributes
        return 1

    def _GetCurrentProcess(self):
        return -1

    def _GetSecurityInfo(self, handle, kind, flags, owner, group, dacl, sacl, descriptor):
        assert handle == self.file and kind == 1 and flags == 5
        assert group is None and sacl is None
        if self.fail("GetSecurityInfo"):
            self.last_error = 999  # Return-code API; GetLastError must not replace error 5.
            return 5
        owner._obj.value = None if self.null_owner else ct.addressof(self.owner)
        dacl._obj.value = None if self.null_dacl else ct.addressof(self.acl)
        descriptor._obj.value = None if self.null_descriptor else ct.addressof(self.descriptor)
        self.allocated = not self.null_descriptor
        return 0

    def _OpenProcessToken(self, process, access, output):
        assert process == -1 and access == 8
        if self.fail("OpenProcessToken"):
            return 0
        output._obj.value = self.token
        self.token_opened = True
        return 1

    def _GetTokenInformation(self, token, kind, buffer, capacity, required):
        assert token.value == self.token and kind == 1
        if buffer is None:
            if self.fail("GetTokenSize"):
                return 0
            required._obj.value = 65537 if self.failure == "OversizedToken" else 16 + len(CURRENT)
            self.last_error = 122
            return 0
        if self.fail("GetTokenInformation"):
            return 0
        ct.cast(buffer, ct.POINTER(ct.c_void_p))[0] = ct.addressof(buffer) + 16
        ct.memmove(ct.addressof(buffer) + 16, CURRENT, len(CURRENT))
        return 1

    def _CreateWellKnownSid(self, kind, domain, output, capacity):
        assert domain is None and capacity._obj.value == 68
        if self.fail("CreateWellKnownSid" + str(kind)):
            return 0
        value = {22: SYSTEM, 26: ADMIN}[kind]
        ct.memmove(output, value, len(value))
        capacity._obj.value = len(value)
        return 1

    def _IsValidSid(self, pointer):
        return int(not self.fail("IsValidSid"))

    def _EqualSid(self, left, right):
        self.events.append("EqualSid")
        return int(self.sid_bytes(left) == self.sid_bytes(right))

    def _IsValidAcl(self, pointer):
        assert pointer.value == ct.addressof(self.acl)
        return int(not self.fail("IsValidAcl"))

    def _GetAclInformation(self, pointer, info, length, kind):
        assert pointer.value == ct.addressof(self.acl)
        assert length == 12 and kind == 2
        if self.fail("GetAclInformation"):
            return 0
        info._obj.count, info._obj.used, info._obj.free = self.count, self.used, self.free
        return 1

    def _GetAce(self, pointer, index, output):
        assert pointer.value == ct.addressof(self.acl)
        if self.fail("GetAce"):
            return 0
        offset = 8 + sum(map(len, self.entries[:index]))
        output._obj.value = ct.addressof(self.acl) + offset + (4 if self.failure == "ForeignAcePointer" else 0)
        return 1

    def _LocalFree(self, descriptor):
        assert descriptor.value == ct.addressof(self.descriptor)
        assert not self.freed
        self.freed.append(descriptor.value)
        return descriptor.value if self.fail("LocalFree") else None

    def _CloseHandle(self, handle):
        assert handle in {self.file, self.token} and handle not in self.closed
        self.closed.append(handle)
        name = "CloseToken" if handle == self.token else "CloseFile"
        return int(not self.fail(name))

    def assert_released(self):
        expected = ({self.file} if self.opened else set()) | ({self.token} if self.token_opened else set())
        assert set(self.closed) == expected
        assert len(self.closed) == len(expected)
        assert len(self.freed) == int(self.allocated)


@pytest.fixture
def windows(monkeypatch):
    def install(**kwargs):
        kernel = WindowsAcl(**kwargs)
        monkeypatch.setattr(acl.ct, "WinDLL", lambda *args, **kwargs: kernel, raising=False)
        monkeypatch.setattr(acl.ct, "get_last_error", lambda: kernel.last_error, raising=False)
        return kernel

    return install


def test_exact_windows_structure_widths():
    assert ct.sizeof(acl.DWORD) == 4
    assert ct.sizeof(acl.BOOL) == 4
    assert ct.sizeof(acl.FileInformation) == 52
    assert ct.sizeof(acl.AclSizeInformation) == 12


@pytest.mark.parametrize("private", [None, "false", 0, 1])
def test_ambiguous_policy_does_not_load_native_apis(monkeypatch, private):
    forbidden = Mock(side_effect=AssertionError("An unknown ACL policy loaded native APIs"))
    monkeypatch.setattr(acl, "_apis", forbidden)
    with pytest.raises(acl.AclVerificationError, match="INVALID_POLICY"):
        acl.verify_access("synthetic-path", private=private)
    forbidden.assert_not_called()


def test_embedded_nul_never_opens_a_truncated_path(windows):
    kernel = windows()
    with pytest.raises(acl.AclVerificationError, match="INVALID_PATH"):
        acl.verify_access("synthetic-path\0ignored")
    kernel.CreateFileW.assert_not_called()


@pytest.mark.parametrize("directory", [False, True])
def test_native_api_metadata_only_same_handle_and_trusted_grants(windows, directory):
    kernel = windows()
    kernel.attributes = 0x10 if directory else 0x80
    acl.verify_access("synthetic-path")
    assert kernel.events.index("GetFileInformationByHandle") < kernel.events.index("GetSecurityInfo")
    kernel.assert_released()


@pytest.mark.parametrize(
    "operation",
    [
        "CreateFileW",
        "GetFileInformationByHandle",
        "GetSecurityInfo",
        "OpenProcessToken",
        "GetTokenSize",
        "GetTokenInformation",
        "OversizedToken",
        "CreateWellKnownSid22",
        "CreateWellKnownSid26",
        "IsValidSid",
        "IsValidAcl",
        "GetAclInformation",
        "GetAce",
        "LocalFree",
        "CloseToken",
        "CloseFile",
    ],
)
def test_every_native_api_failure_closes_only_owned_handles_and_frees_descriptor(windows, operation):
    kernel = windows()
    kernel.failure = operation
    with pytest.raises(acl.AclVerificationError) as caught:
        acl.verify_access("synthetic-path-with-" + SECRET)
    assert SECRET not in str(caught.value)
    assert "synthetic-path" not in repr(caught.value)
    if operation == "GetSecurityInfo":
        assert caught.value.winerror == 5
    if operation in {"LocalFree", "CloseToken", "CloseFile"}:
        assert caught.value.category == "CLEANUP_UNCONFIRMED"
    kernel.assert_released()


@pytest.mark.parametrize("property_name", ["null_dacl", "null_owner", "null_descriptor"])
def test_null_security_metadata_never_means_private(windows, property_name):
    kernel = windows()
    setattr(kernel, property_name, True)
    with pytest.raises(acl.AclVerificationError, match="NULL_SECURITY_METADATA"):
        acl.verify_access("synthetic-path")
    kernel.assert_released()


def test_owner_must_be_current_token_user(windows):
    kernel = windows(owner=ADMIN)
    with pytest.raises(acl.AclVerificationError, match="OWNER_MISMATCH"):
        acl.verify_access("synthetic-path", private=False)
    kernel.assert_released()


def test_reparse_metadata_is_refused_before_acl_read(windows):
    kernel = windows()
    kernel.attributes |= 0x400
    with pytest.raises(acl.AclVerificationError, match="REPARSE_POINT"):
        acl.verify_access("synthetic-path")
    kernel.GetSecurityInfo.assert_not_called()
    kernel.assert_released()


@pytest.mark.parametrize("rights", [1, 0x120089, 0x80000000])
def test_public_read_only_untrusted_grants_do_not_make_private_files_safe(windows, rights):
    kernel = windows(entries=[ace(trustee=OTHER, rights=rights)])
    acl.verify_access("synthetic-public", private=False)
    kernel.assert_released()
    kernel.closed.clear()
    kernel.freed.clear()
    with pytest.raises(acl.AclVerificationError, match="UNTRUSTED_GRANT"):
        acl.verify_access("synthetic-private", private=True)
    kernel.assert_released()


@pytest.mark.parametrize("rights", [2, 4, 16, 64, 256, 65536, 262144, 524288, 0x40000000, 0x10000000])
def test_public_mutable_or_generic_write_all_grants_are_refused(windows, rights):
    kernel = windows(entries=[ace(kind=1, trustee=OTHER), ace(trustee=OTHER, rights=rights)])
    with pytest.raises(acl.AclVerificationError, match="UNTRUSTED_GRANT"):
        acl.verify_access("synthetic-public", private=False)
    kernel.assert_released()


@pytest.mark.parametrize("kind", [5, 9, 11])
@pytest.mark.parametrize("objects", [0, 1, 2, 3])
def test_object_callback_allow_sids_and_conditions_are_conservative(windows, kind, objects):
    kernel = windows(entries=[ace(kind=kind, trustee=OTHER, rights=1, objects=objects, flags=8)])
    with pytest.raises(acl.AclVerificationError, match="UNTRUSTED_GRANT"):
        acl.verify_access("synthetic-private")
    kernel.assert_released()


@pytest.mark.parametrize("kind", [1, 6, 10, 12])
def test_known_deny_aces_never_grant_access(windows, kind):
    kernel = windows(entries=[ace(kind=kind, trustee=OTHER)])
    acl.verify_access("synthetic-private")
    kernel.assert_released()


@pytest.mark.parametrize(
    "case",
    ["empty", "too-many", "oversized", "unknown-ace", "unknown-mask", "foreign-pointer", "short-sid", "object-flags"],
)
def test_unknown_or_malformed_acl_and_ace_are_fail_closed(windows, case):
    entries = [] if case == "empty" else [ace()]
    if case == "unknown-ace":
        entries = [ace(kind=2)]
    elif case == "unknown-mask":
        entries = [ace(rights=0x04000000)]
    elif case == "short-sid":
        entries = [ace(trustee=b"\x01\x0f" + b"\x00" * 6)]
    elif case == "object-flags":
        entries = [ace(kind=5, objects=4)]
    kernel = windows(entries=entries)
    if case == "too-many":
        kernel.count = 4097
    elif case == "oversized":
        kernel.used = 65536
    elif case == "foreign-pointer":
        kernel.failure = "ForeignAcePointer"
    with pytest.raises(acl.AclVerificationError):
        acl.verify_access("synthetic-path")
    kernel.assert_released()


def test_unexpected_exception_text_is_not_exposed_and_cleanup_still_runs(windows):
    kernel = windows()
    kernel.GetAce.side_effect = OSError(5, SECRET, "synthetic-sensitive-path")
    with pytest.raises(acl.AclVerificationError) as caught:
        acl.verify_access("synthetic-sensitive-path")
    assert SECRET not in str(caught.value)
    assert "synthetic-sensitive-path" not in repr(caught.value)
    assert caught.value.__suppress_context__
    kernel.assert_released()


@pytest.mark.skipif(sys.platform != "win32", reason="Actual Windows security-descriptor metadata")
def test_native_windows_private_file_acl_is_read_without_mutation(tmp_path):
    from scripts import dev_private

    path = tmp_path / "synthetic-private-file"
    content = b"fixture-private-bytes"
    dev_private.create_private_file(path, content)
    before = path.stat()
    acl.verify_access(path)
    after = path.stat()
    assert path.read_bytes() == content
    assert (before.st_ino, before.st_size, before.st_mtime_ns) == (after.st_ino, after.st_size, after.st_mtime_ns)
