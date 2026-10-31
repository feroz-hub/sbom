"""Explicit creation of private instance-state directories, never permission repair.

The caller must obtain approval before calling this writer. Read-only discovery
and planning must not call it. Created directories are retained after a failure.
Their names and ACLs do not authorize data-service or enrollment operations.
"""

from __future__ import annotations

import ctypes as ct
import ntpath
import os
import stat
import sys
from contextlib import ExitStack
from pathlib import Path

if __package__:
    from . import dev_windows_acl
else:
    import dev_windows_acl


class DirectoryInitializationError(OSError):
    """Fixed category/numeric OS error; never include a path or native message."""

    def __init__(self, code, os_code=None, *, windows=False):
        safe = os_code if type(os_code) is int and 0 <= os_code <= 0xFFFFFFFF else None
        label = "winerror" if windows else "errno"
        super().__init__(f"{code} ({label}={safe}); partial directories are retained.")
        self.code = code
        self.winerror = safe if windows else None
        self.errno = None if windows else safe


def _fail(code, os_code=None):
    raise DirectoryInitializationError(code, os_code, windows=sys.platform == "win32") from None


def _identity(info):
    return info.st_dev, info.st_ino


def _paths(path, anchor):
    raw, base = os.fspath(path), os.fspath(anchor)
    if not isinstance(raw, str) or not isinstance(base, str):
        _fail("INSTANCE_DIRECTORY_PATH_INVALID")
    for value in (raw, base):
        if any(ord(char) < 32 or ord(char) == 127 for char in value) or ".." in Path(value).parts:
            _fail("INSTANCE_DIRECTORY_PATH_INVALID")
        if sys.platform == "win32":
            _, tail = ntpath.splitdrive(value)
            if value.startswith(("\\\\?\\", "\\\\.\\")) or ":" in tail:
                _fail("INSTANCE_DIRECTORY_PATH_INVALID")
            for part in Path(tail).parts:
                if part in {"\\", "/"}:
                    continue
                device = part.rstrip(" .").split(".")[0].upper()
                if part.endswith((" ", ".")) or device in {
                    "CON",
                    "PRN",
                    "AUX",
                    "NUL",
                    "CLOCK$",
                    "CONIN$",
                    "CONOUT$",
                    *(f"COM{i}" for i in (*range(1, 10), "¹", "²", "³")),
                    *(f"LPT{i}" for i in (*range(1, 10), "¹", "²", "³")),
                }:
                    _fail("INSTANCE_DIRECTORY_PATH_INVALID")
    root, destination = Path(os.path.abspath(base)), Path(os.path.abspath(raw))
    try:
        relative = destination.relative_to(root)
    except ValueError:
        _fail("INSTANCE_DIRECTORY_OUTSIDE_ANCHOR")
    if len(relative.parts) > 64:
        _fail("INSTANCE_DIRECTORY_DEPTH_REQUIRED")
    if not relative.parts:
        _fail("INSTANCE_DIRECTORY_TARGET_REQUIRED")
    if os.path.normcase(str(root.resolve(strict=True))) != os.path.normcase(str(root)):
        _fail("INSTANCE_DIRECTORY_ANCHOR_REDIRECTED")
    return root, relative.parts


def _verify(path, *, private):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 1024:
        _fail("INSTANCE_DIRECTORY_REDIRECTED")
    if not info.st_ino:
        _fail("INSTANCE_DIRECTORY_IDENTITY_UNVERIFIED")
    if sys.platform == "win32":
        try:
            dev_windows_acl.verify_access(path, private=private)
        except dev_windows_acl.AclVerificationError as error:
            _fail("INSTANCE_DIRECTORY_ACCESS_UNVERIFIED", error.winerror)
    elif info.st_uid != os.getuid() or (
        stat.S_IMODE(info.st_mode) != 0o700 if private else bool(stat.S_IMODE(info.st_mode) & 0o022)
    ):
        _fail("INSTANCE_DIRECTORY_ACCESS_UNVERIFIED")
    return info


def _revalidate(identities):
    for path, identity, private in identities:
        if _identity(_verify(path, private=private)) != identity:
            _fail("INSTANCE_DIRECTORY_CHANGED")


def _windows_apis():
    kernel = ct.WinDLL("kernel32", use_last_error=True)
    security = ct.WinDLL("advapi32", use_last_error=True)
    pointer, dword, handle, boolean = ct.c_void_p, ct.c_uint32, ct.c_void_p, ct.c_int32
    signatures = {
        "GetCurrentProcess": (kernel, handle, []),
        "CloseHandle": (kernel, boolean, [handle]),
        "LocalFree": (kernel, pointer, [pointer]),
        "GetVolumePathNameW": (kernel, boolean, [ct.c_wchar_p, ct.c_wchar_p, dword]),
        "GetVolumeInformationW": (
            kernel,
            boolean,
            [ct.c_wchar_p, ct.c_wchar_p, dword, pointer, pointer, pointer, ct.c_wchar_p, dword],
        ),
        "CreateDirectoryW": (kernel, boolean, [ct.c_wchar_p, pointer]),
        "CreateFileW": (kernel, handle, [ct.c_wchar_p, dword, dword, pointer, dword, dword, handle]),
        "GetFileInformationByHandle": (kernel, boolean, [handle, pointer]),
        "OpenProcessToken": (security, boolean, [handle, dword, pointer]),
        "GetTokenInformation": (security, boolean, [handle, ct.c_int32, pointer, dword, pointer]),
        "IsValidSid": (security, boolean, [pointer]),
        "ConvertSidToStringSidW": (security, boolean, [pointer, pointer]),
        "ConvertStringSecurityDescriptorToSecurityDescriptorW": (
            security,
            boolean,
            [ct.c_wchar_p, dword, pointer, pointer],
        ),
    }
    for name, (library, result, arguments) in signatures.items():
        function = getattr(library, name)
        function.restype, function.argtypes = result, arguments
    return kernel, security


def _windows_create(path):
    class SecurityAttributes(ct.Structure):
        _fields_ = [("length", ct.c_uint32), ("descriptor", ct.c_void_p), ("inherit", ct.c_int32)]

    kernel, security = _windows_apis()
    token, sid, descriptor = ct.c_void_p(), ct.c_wchar_p(), ct.c_void_p()
    try:
        volume, flags = ct.create_unicode_buffer(32768), ct.c_uint32()
        if not kernel.GetVolumePathNameW(str(path), volume, len(volume)):
            _fail("INSTANCE_DIRECTORY_VOLUME_UNVERIFIED", ct.get_last_error())
        if not kernel.GetVolumeInformationW(volume.value, None, 0, None, None, ct.byref(flags), None, 0):
            _fail("INSTANCE_DIRECTORY_VOLUME_UNVERIFIED", ct.get_last_error())
        if not flags.value & 8:
            _fail("INSTANCE_DIRECTORY_ACLS_UNSUPPORTED", 50)
        if not security.OpenProcessToken(kernel.GetCurrentProcess(), 8, ct.byref(token)):
            _fail("INSTANCE_DIRECTORY_OWNER_UNVERIFIED", ct.get_last_error())
        size = ct.c_uint32()
        if security.GetTokenInformation(token, 1, None, 0, ct.byref(size)) or ct.get_last_error() != 122:
            _fail("INSTANCE_DIRECTORY_OWNER_UNVERIFIED", ct.get_last_error())
        if not ct.sizeof(ct.c_void_p) <= size.value <= 65536:
            _fail("INSTANCE_DIRECTORY_OWNER_UNVERIFIED", 13)
        user = ct.create_string_buffer(size.value)
        if not security.GetTokenInformation(token, 1, user, size.value, ct.byref(size)):
            _fail("INSTANCE_DIRECTORY_OWNER_UNVERIFIED", ct.get_last_error())
        current = ct.cast(user, ct.POINTER(ct.c_void_p))[0]
        if not current or not ct.addressof(user) <= current <= ct.addressof(user) + len(user) - 8:
            _fail("INSTANCE_DIRECTORY_OWNER_UNVERIFIED", 13)
        revision, count = ct.string_at(current, 2)
        if revision != 1 or count > 15 or current + 8 + count * 4 > ct.addressof(user) + len(user):
            _fail("INSTANCE_DIRECTORY_OWNER_UNVERIFIED", 13)
        if not security.IsValidSid(current) or not security.ConvertSidToStringSidW(current, ct.byref(sid)):
            _fail("INSTANCE_DIRECTORY_OWNER_UNVERIFIED", ct.get_last_error())
        sddl = f"O:{sid.value}D:P(A;OICI;FA;;;{sid.value})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ct.byref(descriptor), None):
            _fail("INSTANCE_DIRECTORY_DESCRIPTOR_UNVERIFIED", ct.get_last_error())
        attributes = SecurityAttributes(ct.sizeof(SecurityAttributes), descriptor, False)
        if not kernel.CreateDirectoryW(str(path), ct.byref(attributes)):
            _fail("INSTANCE_DIRECTORY_CREATION_FAILED", ct.get_last_error())
    finally:
        failure = None
        for allocation in (ct.cast(sid, ct.c_void_p), descriptor):
            if allocation.value and kernel.LocalFree(allocation):
                failure = ct.get_last_error()
        if token.value and not kernel.CloseHandle(token):
            failure = ct.get_last_error()
        if failure is not None:
            _fail("INSTANCE_DIRECTORY_CLEANUP_UNCONFIRMED", failure)


def _pin_windows(path):
    """Hold a verified directory without delete sharing while creating descendants."""
    kernel, _ = _windows_apis()
    handle = kernel.CreateFileW(str(path), 0x20080, 3, None, 3, 0x2200000, None)
    if handle in (None, -1, ct.c_void_p(-1).value):
        _fail("INSTANCE_DIRECTORY_PIN_UNVERIFIED", ct.get_last_error())
    information = dev_windows_acl.FileInformation()
    try:
        if not kernel.GetFileInformationByHandle(handle, ct.byref(information)):
            _fail("INSTANCE_DIRECTORY_PIN_UNVERIFIED", ct.get_last_error())
        if information.attributes & 1024 or not information.attributes & 16:
            _fail("INSTANCE_DIRECTORY_PIN_UNVERIFIED")
    except BaseException:
        if not kernel.CloseHandle(handle):
            _fail("INSTANCE_DIRECTORY_CLEANUP_UNCONFIRMED", ct.get_last_error())
        raise

    def close():
        if not kernel.CloseHandle(handle):
            _fail("INSTANCE_DIRECTORY_CLEANUP_UNCONFIRMED", ct.get_last_error())

    return close


def _pin_posix(path, expected, *, parent=None):
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path if parent is None else path.name, flags, dir_fd=parent)
    try:
        if _identity(os.fstat(descriptor)) != _identity(expected):
            _fail("INSTANCE_DIRECTORY_CHANGED")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def initialize_private_directory(path, *, anchor) -> None:
    """Explicit writer: create missing descendants; preserve existing material."""
    try:
        root, parts = _paths(path, anchor)
        root_info = _verify(root, private=False)
        identities = [(root, _identity(root_info), False)]
        with ExitStack() as pins:
            parent = None
            if sys.platform == "win32":
                pins.callback(_pin_windows(root))
            else:
                parent = _pin_posix(root, root_info)
                pins.callback(os.close, parent)
            for name in parts:
                _revalidate(identities)
                child = identities[-1][0] / name
                try:
                    before = _verify(child, private=True)
                except FileNotFoundError:
                    if sys.platform == "win32":
                        _windows_create(child)
                    else:
                        os.mkdir(name, 0o700, dir_fd=parent)
                    before = _verify(child, private=True)
                if sys.platform == "win32":
                    pins.callback(_pin_windows(child))
                else:
                    parent = _pin_posix(child, before, parent=parent)
                    pins.callback(os.close, parent)
                identities.append((child, _identity(before), True))
                _revalidate(identities)
            _revalidate(identities)
    except DirectoryInitializationError:
        raise
    except OSError as error:
        _fail(
            "INSTANCE_DIRECTORY_INITIALIZATION_FAILED",
            getattr(error, "winerror", None) if sys.platform == "win32" else error.errno,
        )
    except Exception:
        _fail("INSTANCE_DIRECTORY_INITIALIZATION_FAILED")
