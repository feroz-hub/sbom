"""Create new private files, never repair permissions or replace existing files.

Callers validate/authorize the parent directory; no directory is created here.
A failed write can leave an incomplete new private file for explicit recovery.
"""

from __future__ import annotations

import ctypes
import errno
import ntpath
import os
import stat
import sys
from pathlib import Path


class PrivateFileError(OSError):
    """Only a fixed category and safe numeric OS code; no path or file content."""

    def __init__(self, code=None, *, windows=False):
        label = "winerror" if windows else "errno"
        super().__init__(f"PRIVATE_FILE_CREATION_FAILED ({label}={code}); an incomplete new file may remain.")
        self.errno = None if windows else code
        self.winerror = code if windows else None


def validate_parent(path, root, *, allow_missing=False) -> None:
    """Refuse redirected/outside-checkout parents without creating or repairing.

    Call immediately before publication, and again after any authorized mkdir.
    The existing checkout anchor itself must be a nonredirected directory.
    """
    try:
        anchor = Path(os.path.abspath(root))
        parent = Path(os.path.abspath(path)).parent
        relative = parent.relative_to(anchor)
        if len(relative.parts) > 64:
            raise PrivateFileError(errno.ENAMETOOLONG)
        directories = [anchor]
        for part in relative.parts:
            directories.append(directories[-1] / part)
        for directory in directories:
            try:
                info = directory.lstat()
            except FileNotFoundError:
                if allow_missing and directory != anchor:
                    return
                raise
            if not stat.S_ISDIR(info.st_mode) or (
                getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024)
            ):
                raise PrivateFileError(errno.ELOOP)
    except PrivateFileError:
        raise
    except Exception as error:
        raise PrivateFileError(getattr(error, "errno", None)) from None


def _windows_apis():
    from ctypes import wintypes as wt

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    pointer = ctypes.c_void_p
    signatures = {
        "GetCurrentProcess": (kernel, wt.HANDLE, []),
        "CloseHandle": (kernel, wt.BOOL, [wt.HANDLE]),
        "LocalFree": (kernel, pointer, [pointer]),
        "GetVolumePathNameW": (kernel, wt.BOOL, [wt.LPCWSTR, wt.LPWSTR, wt.DWORD]),
        "GetVolumeInformationW": (
            kernel,
            wt.BOOL,
            [wt.LPCWSTR, wt.LPWSTR, wt.DWORD, pointer, pointer, pointer, wt.LPWSTR, wt.DWORD],
        ),
        "CreateFileW": (kernel, wt.HANDLE, [wt.LPCWSTR, wt.DWORD, wt.DWORD, pointer, wt.DWORD, wt.DWORD, wt.HANDLE]),
        "OpenProcessToken": (security, wt.BOOL, [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]),
        "GetTokenInformation": (
            security,
            wt.BOOL,
            [wt.HANDLE, ctypes.c_int, pointer, wt.DWORD, ctypes.POINTER(wt.DWORD)],
        ),
        "ConvertSidToStringSidW": (security, wt.BOOL, [pointer, ctypes.POINTER(wt.LPWSTR)]),
        "ConvertStringSecurityDescriptorToSecurityDescriptorW": (
            security,
            wt.BOOL,
            [wt.LPCWSTR, wt.DWORD, ctypes.POINTER(pointer), pointer],
        ),
    }
    for name, (library, result, arguments) in signatures.items():
        function = getattr(library, name)
        function.restype, function.argtypes = result, arguments
    return kernel, security


def _windows_fd(path):
    import msvcrt
    from ctypes import wintypes as wt

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [("nLength", wt.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p), ("bInheritHandle", wt.BOOL)]

    kernel, security = _windows_apis()
    token, sid, descriptor = wt.HANDLE(), wt.LPWSTR(), ctypes.c_void_p()
    handle = None

    def failed():
        return PrivateFileError(ctypes.get_last_error(), windows=True)

    try:
        try:
            volume, flags = ctypes.create_unicode_buffer(32768), wt.DWORD()
            if not kernel.GetVolumePathNameW(path, volume, len(volume)):
                raise failed()
            if not kernel.GetVolumeInformationW(volume.value, None, 0, None, None, ctypes.byref(flags), None, 0):
                raise failed()
            if not flags.value & 8:  # FILE_PERSISTENT_ACLS: never create secrets on FAT-like storage.
                raise PrivateFileError(50, windows=True)
            if not security.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
                raise failed()
            size = wt.DWORD()
            if security.GetTokenInformation(token, 1, None, 0, ctypes.byref(size)) or ctypes.get_last_error() != 122:
                raise failed()
            if not ctypes.sizeof(ctypes.c_void_p) <= size.value <= 65536:
                raise PrivateFileError(13, windows=True)
            user = ctypes.create_string_buffer(size.value)
            if not security.GetTokenInformation(token, 1, user, size.value, ctypes.byref(size)):
                raise failed()
            user_sid = ctypes.cast(user, ctypes.POINTER(ctypes.c_void_p))[0]
            if not security.ConvertSidToStringSidW(user_sid, ctypes.byref(sid)):
                raise failed()
            sddl = f"O:{sid.value}D:P(A;;FA;;;{sid.value})(A;;FA;;;SY)(A;;FA;;;BA)"
            if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, 1, ctypes.byref(descriptor), None
            ):
                raise failed()
            attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
            handle = kernel.CreateFileW(path, 0x40000000, 0, ctypes.byref(attributes), 1, 0x200080, None)
            if handle in (None, -1, ctypes.c_void_p(-1).value):
                handle = None
                raise failed()
        finally:
            cleanup = None
            for allocation in (ctypes.cast(sid, ctypes.c_void_p), descriptor):
                if allocation.value and kernel.LocalFree(allocation):
                    cleanup = ctypes.get_last_error()
            if token.value and not kernel.CloseHandle(token):
                cleanup = ctypes.get_last_error()
            if cleanup is not None:
                raise PrivateFileError(cleanup, windows=True)
        # Successful CRT adoption transfers HANDLE ownership; only os.close(fd)
        # may close it from this point. No native CloseHandle on an adopted file.
        fd = msvcrt.open_osfhandle(handle, os.O_BINARY | os.O_NOINHERIT)
        if fd < 0:
            raise PrivateFileError(errno.EMFILE)
        handle = None
        return fd
    finally:
        if handle is not None and not kernel.CloseHandle(handle):
            raise failed()


def create_private_file(path, content: bytes) -> None:
    """Publish bytes only into a newly created 0600/protected-DACL file."""
    if not isinstance(content, bytes):
        raise PrivateFileError(errno.EINVAL)
    fd = None
    try:
        path = os.fspath(path)
        if sys.platform == "win32":
            if path.startswith(("\\\\.\\", "\\\\?\\")):
                raise PrivateFileError(123, windows=True)
            path = os.path.abspath(path)
            _, tail = ntpath.splitdrive(path)
            device = ntpath.basename(tail).rstrip(" .").split(".")[0].rstrip(" ").upper()
            if (
                "\x00" in path
                or ":" in tail
                or path.startswith(("\\\\.\\", "\\\\?\\"))
                or device
                in {
                    "CON",
                    "PRN",
                    "AUX",
                    "NUL",
                    "CONIN$",
                    "CONOUT$",
                    "CLOCK$",
                    *(f"COM{i}" for i in (*range(1, 10), "¹", "²", "³")),
                    *(f"LPT{i}" for i in (*range(1, 10), "¹", "²", "³")),
                }
            ):
                raise PrivateFileError(123, windows=True)
            fd = _windows_fd(path)
        else:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        remaining = memoryview(content)
        while remaining:
            written = os.write(fd, remaining)
            if written <= 0:
                raise OSError(errno.EIO, "Private write made no progress")
            remaining = remaining[written:]
        os.fsync(fd)
    except PrivateFileError as error:
        raise error from None
    except Exception as error:
        code = getattr(error, "winerror", None)
        raise PrivateFileError(
            code if code is not None else getattr(error, "errno", None), windows=code is not None
        ) from None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError as error:
                raise PrivateFileError(
                    getattr(error, "winerror", None) or error.errno, windows=sys.platform == "win32"
                ) from None
