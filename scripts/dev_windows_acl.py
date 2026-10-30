"""Read native Windows ownership/DACL metadata on one pinned file handle.

No file bytes, shell helpers, permissions, certificate trust or process lifecycle
operations are used. Conditional/object allow ACEs are treated as possible grants;
deny ACEs never cancel an otherwise unacceptable grant.
"""

from __future__ import annotations

import ctypes as ct
import os
import struct

DWORD, BOOL, HANDLE = ct.c_uint32, ct.c_int32, ct.c_void_p


class AclVerificationError(OSError):
    """Only constant operation/category and a safe numeric Windows error."""

    def __init__(self, operation, code=None, category="API_FAILURE"):
        safe_code = code if type(code) is int and 0 <= code <= 0xFFFFFFFF else None
        super().__init__(f"WINDOWS_ACL_UNVERIFIED: {category}; operation={operation}; winerror={safe_code}")
        self.operation, self.category = operation, category
        self.winerror = safe_code


class FileInformation(ct.Structure):
    _fields_ = [("attributes", DWORD), ("remaining", DWORD * 12)]


class AclSizeInformation(ct.Structure):
    _fields_ = [("count", DWORD), ("used", DWORD), ("free", DWORD)]


def _apis():
    kernel = ct.WinDLL("kernel32", use_last_error=True)
    security = ct.WinDLL("advapi32", use_last_error=True)
    pointer, out_pointer = ct.c_void_p, ct.POINTER(ct.c_void_p)
    signatures = {
        "CreateFileW": (kernel, HANDLE, [ct.c_wchar_p, DWORD, DWORD, pointer, DWORD, DWORD, HANDLE]),
        "GetFileInformationByHandle": (kernel, BOOL, [HANDLE, ct.POINTER(FileInformation)]),
        "GetCurrentProcess": (kernel, HANDLE, []),
        "CloseHandle": (kernel, BOOL, [HANDLE]),
        "LocalFree": (kernel, pointer, [pointer]),
        "GetSecurityInfo": (
            security,
            DWORD,
            [HANDLE, ct.c_int32, DWORD, out_pointer, out_pointer, out_pointer, out_pointer, out_pointer],
        ),
        "OpenProcessToken": (security, BOOL, [HANDLE, DWORD, ct.POINTER(HANDLE)]),
        "GetTokenInformation": (security, BOOL, [HANDLE, ct.c_int32, pointer, DWORD, ct.POINTER(DWORD)]),
        "CreateWellKnownSid": (security, BOOL, [ct.c_int32, pointer, pointer, ct.POINTER(DWORD)]),
        "IsValidSid": (security, BOOL, [pointer]),
        "EqualSid": (security, BOOL, [pointer, pointer]),
        "IsValidAcl": (security, BOOL, [pointer]),
        "GetAclInformation": (security, BOOL, [pointer, pointer, DWORD, ct.c_int32]),
        "GetAce": (security, BOOL, [pointer, DWORD, out_pointer]),
    }
    for name, (library, result, arguments) in signatures.items():
        function = getattr(library, name)
        function.restype, function.argtypes = result, arguments
    return kernel, security


def _api_failure(operation, code=None):
    return AclVerificationError(operation, ct.get_last_error() if code is None else code)


def _sid_from_ace(raw, kind, security):
    offset = 8
    if kind in {5, 6, 11, 12}:
        if len(raw) < 12:
            raise AclVerificationError("GetAce", category="MALFORMED_ACE")
        flags = struct.unpack_from("<I", raw, 8)[0]
        if flags & ~3:
            raise AclVerificationError("GetAce", category="MALFORMED_ACE")
        offset = 12 + 16 * bool(flags & 1) + 16 * bool(flags & 2)
    if offset + 8 > len(raw) or raw[offset] != 1 or raw[offset + 1] > 15:
        raise AclVerificationError("GetAce", category="MALFORMED_SID")
    size = 8 + 4 * raw[offset + 1]
    if offset + size > len(raw):
        raise AclVerificationError("GetAce", category="MALFORMED_SID")
    sid = ct.create_string_buffer(raw[offset : offset + size])
    if not security.IsValidSid(sid):
        raise AclVerificationError("IsValidSid", category="MALFORMED_SID")
    return sid


def _verify_dacl(dacl, trusted, security, private):
    if not dacl.value or not security.IsValidAcl(dacl):
        raise AclVerificationError("IsValidAcl", category="DACL_UNVERIFIED")
    info = AclSizeInformation()
    if not security.GetAclInformation(dacl, ct.byref(info), ct.sizeof(info), 2):
        raise _api_failure("GetAclInformation")
    if not 1 <= info.count <= 4096 or not 8 <= info.used <= 65535 or info.free > 65535 - info.used:
        raise AclVerificationError("GetAclInformation", category="DACL_BOUNDS")
    revision, _, total, count, _ = struct.unpack("<BBHHH", ct.string_at(dacl, 8))
    if revision not in {2, 4} or total != info.used + info.free or count != info.count:
        raise AclVerificationError("GetAclInformation", category="DACL_BOUNDS")
    cursor, end = dacl.value + 8, dacl.value + info.used
    mutable = 2 | 4 | 16 | 64 | 256 | 65536 | 262144 | 524288 | 0x40000000 | 0x10000000
    known = 0x1FF | 0x1F0000 | 0x01000000 | 0xF0000000
    for index in range(info.count):
        pointer = ct.c_void_p()
        if not security.GetAce(dacl, index, ct.byref(pointer)):
            raise _api_failure("GetAce")
        if pointer.value != cursor or cursor + 8 > end:
            raise AclVerificationError("GetAce", category="ACE_BOUNDS")
        kind, _, size, mask = struct.unpack("<BBHI", ct.string_at(pointer, 8))
        if size < 16 or size % 4 or cursor + size > end:
            raise AclVerificationError("GetAce", category="ACE_BOUNDS")
        if kind not in {0, 1, 5, 6, 9, 10, 11, 12}:
            raise AclVerificationError("GetAce", category="UNSUPPORTED_ACE")
        if kind in {5, 6, 11, 12} and revision != 4:
            raise AclVerificationError("GetAce", category="DACL_BOUNDS")
        if mask & ~known:
            raise AclVerificationError("GetAce", category="UNSUPPORTED_ACCESS_MASK")
        sid = _sid_from_ace(ct.string_at(pointer, size), kind, security)
        if kind in {0, 5, 9, 11} and not any(security.EqualSid(sid, item) for item in trusted):
            if private or mask & mutable:
                raise AclVerificationError("GetAce", category="UNTRUSTED_GRANT")
        cursor += size
    if cursor != end:
        raise AclVerificationError("GetAce", category="DACL_BOUNDS")


def verify_access(path, private=True) -> None:
    """Verify current-user ownership and conservative private/public ACL policy."""
    if type(private) is not bool:
        raise AclVerificationError("Policy", category="INVALID_POLICY")
    try:
        kernel, security = _apis()
    except Exception:
        raise AclVerificationError("LoadLibrary", category="API_UNAVAILABLE") from None
    handle, token, descriptor = None, HANDLE(), ct.c_void_p()
    try:
        name = os.fspath(path)
        if not isinstance(name, str) or "\0" in name:
            raise AclVerificationError("CreateFileW", 123, "INVALID_PATH")
        handle = kernel.CreateFileW(name, 0x20080, 7, None, 3, 0x2200000, None)
        if handle in (None, -1, ct.c_void_p(-1).value):
            handle = None
            raise _api_failure("CreateFileW")
        information = FileInformation()
        if not kernel.GetFileInformationByHandle(handle, ct.byref(information)):
            raise _api_failure("GetFileInformationByHandle")
        if information.attributes & 0x400:
            raise AclVerificationError("GetFileInformationByHandle", category="REPARSE_POINT")
        owner, dacl = ct.c_void_p(), ct.c_void_p()
        code = security.GetSecurityInfo(handle, 1, 5, ct.byref(owner), None, ct.byref(dacl), None, ct.byref(descriptor))
        if code:
            raise _api_failure("GetSecurityInfo", code)
        if not descriptor.value or not owner.value or not dacl.value:
            raise AclVerificationError("GetSecurityInfo", category="NULL_SECURITY_METADATA")
        if not security.OpenProcessToken(kernel.GetCurrentProcess(), 8, ct.byref(token)):
            raise _api_failure("OpenProcessToken")
        size = DWORD()
        if security.GetTokenInformation(token, 1, None, 0, ct.byref(size)) or ct.get_last_error() != 122:
            raise _api_failure("GetTokenInformation")
        if not ct.sizeof(HANDLE) <= size.value <= 65536:
            raise AclVerificationError("GetTokenInformation", category="TOKEN_BOUNDS")
        user = ct.create_string_buffer(size.value)
        if not security.GetTokenInformation(token, 1, user, size.value, ct.byref(size)):
            raise _api_failure("GetTokenInformation")
        current = ct.cast(user, ct.POINTER(ct.c_void_p))[0]
        if not current or not ct.addressof(user) <= current <= ct.addressof(user) + len(user) - 8:
            raise AclVerificationError("GetTokenInformation", category="TOKEN_BOUNDS")
        revision, count = ct.string_at(current, 2)
        if revision != 1 or count > 15 or current + 8 + 4 * count > ct.addressof(user) + len(user):
            raise AclVerificationError("GetTokenInformation", category="TOKEN_BOUNDS")
        if not security.IsValidSid(owner) or not security.IsValidSid(current):
            raise AclVerificationError("IsValidSid", category="OWNER_UNVERIFIED")
        if not security.EqualSid(owner, current):
            raise AclVerificationError("EqualSid", category="OWNER_MISMATCH")
        trusted = [current]
        for kind in (22, 26):
            sid, capacity = ct.create_string_buffer(68), DWORD(68)
            if not security.CreateWellKnownSid(kind, None, sid, ct.byref(capacity)):
                raise _api_failure("CreateWellKnownSid")
            if not 8 <= capacity.value <= 68 or not security.IsValidSid(sid):
                raise AclVerificationError("CreateWellKnownSid", category="MALFORMED_SID")
            trusted.append(sid)
        _verify_dacl(dacl, trusted, security, private)
    except AclVerificationError as error:
        raise error from None
    except Exception:
        raise AclVerificationError("InspectMetadata", category="INSPECTION_UNAVAILABLE") from None
    finally:
        cleanup = None
        if descriptor.value:
            try:
                if kernel.LocalFree(descriptor):
                    cleanup = _api_failure("LocalFree")
            except Exception:
                cleanup = AclVerificationError("LocalFree", category="CLEANUP_UNCONFIRMED")
        for resource in (token.value, handle):
            if resource is not None:
                try:
                    if not kernel.CloseHandle(resource):
                        cleanup = _api_failure("CloseHandle")
                except Exception:
                    cleanup = AclVerificationError("CloseHandle", category="CLEANUP_UNCONFIRMED")
        if cleanup is not None:
            raise AclVerificationError(cleanup.operation, cleanup.winerror, "CLEANUP_UNCONFIRMED") from None
