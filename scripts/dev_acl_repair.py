"""Consent-gated Windows DACL narrowing for exact launcher private-file paths.

No ownership changes, elevation, recursive ACL changes or added access grants.
An original descriptor backup is published before changing the pinned handle.
Failed verification retains the backup; it never restores a broader DACL.
"""

from __future__ import annotations

import base64
import ctypes as ct
import hashlib
import json
import ntpath
import os
import secrets
import stat
import struct
from contextlib import contextmanager
from pathlib import Path

if __package__:
    from . import dev_private
    from . import dev_windows_acl as acl
else:
    import dev_private
    import dev_windows_acl as acl

TARGETS = frozenset({".env.dev.local", ".env.dev.postgres.json", "frontend/certificates/localhost-key.pem"})


def exact_path(value, root):
    """Require a literal allowlisted spelling; reject aliases before native I/O."""
    root = Path(root).absolute()
    text = os.fspath(value)
    if (not isinstance(text, str) or not text or any(c in text for c in "\0*?[]")
            or text.startswith(("\\\\", "//")) or ":" in ntpath.splitdrive(text)[1]
            or any(p in {".", ".."} or p.endswith((" ", ".")) for p in text.replace("\\", "/").split("/") if p)):
        raise ValueError("ACL_EXACT_PATH_REQUIRED: select one literal launcher private-file path; aliases and wildcard paths are refused.")
    path = Path(text) if Path(text).is_absolute() else root / text
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        raise ValueError("ACL_TARGET_OUTSIDE_CHECKOUT: select an allowlisted private file inside this worktree.") from None
    if relative not in TARGETS:
        raise ValueError("ACL_TARGET_NOT_ALLOWED: repair only .env.dev.local, .env.dev.postgres.json or frontend/certificates/localhost-key.pem.")
    dev_private.validate_parent(path, root)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or getattr(info, "st_file_attributes", 0) & 1024):
        raise ValueError("ACL_REDIRECTED_TARGET: retain links/reparse points; repair requires one ordinary file.")
    return path


def narrowed_acl(raw, trusted_sids, current_sid):
    """Keep existing trusted allows/denies byte-for-byte; remove other allows."""
    if len(raw) < 8:
        raise ValueError("ACL_MANUAL_REVIEW_REQUIRED")
    revision, reserved, size, count, unused = struct.unpack_from("<BBHHH", raw)
    if revision not in {2, 4} or size != len(raw) or not 1 <= count <= 4096:
        raise ValueError("ACL_MANUAL_REVIEW_REQUIRED")
    kept, offset, current_mask = [], 8, 0
    for _ in range(count):
        if offset + 8 > size:
            raise ValueError("ACL_MANUAL_REVIEW_REQUIRED")
        kind, flags, length, mask = struct.unpack_from("<BBHI", raw, offset)
        if kind not in {0, 1} or length < 16 or length % 4 or offset + length > size:
            raise ValueError("ACL_MANUAL_REVIEW_REQUIRED: conditional/object ACEs require manual review.")
        ace = raw[offset:offset + length]
        sid = ace[8:]
        if sid[0] != 1 or sid[1] > 15 or len(sid) != 8 + 4 * sid[1]:
            raise ValueError("ACL_MANUAL_REVIEW_REQUIRED")
        if kind == 1 or sid in trusted_sids:
            # Protected DACL: retain access masks, clear only inherited status.
            kept.append(bytes((kind, flags & ~16)) + ace[2:])
            if kind == 0 and sid == current_sid and not flags & 8:
                current_mask |= mask
        offset += length
    if offset != size or current_mask & 0x1F01FF != 0x1F01FF:
        raise ValueError("ACL_OWNER_ACCESS_REQUIRED: current owner must already have explicit Full Control; repair never adds permissions.")
    result = b"".join(kept)
    return struct.pack("<BBHHH", revision, reserved, len(result) + 8, len(kept), unused) + result


def _sid_bytes(pointer):
    revision, count = ct.string_at(pointer, 2)
    if revision != 1 or count > 15:
        raise ValueError("ACL_OWNER_UNVERIFIED")
    return ct.string_at(pointer, 8 + 4 * count)


@contextmanager
def pinned_target(path, *, write=False):
    kernel, security = acl._apis()
    descriptor, token, handle = ct.c_void_p(), acl.HANDLE(), None
    try:
        # Deny concurrent writes/deletes, including replacement of this name.
        handle = kernel.CreateFileW(str(path), 0x20080 | (0x40000 if write else 0), 1, None, 3, 0x2200000, None)
        if handle in (None, -1, ct.c_void_p(-1).value):
            handle = None
            raise acl.AclVerificationError("CreateFileW", ct.get_last_error())
        info = acl.FileInformation()
        if not kernel.GetFileInformationByHandle(handle, ct.byref(info)) or info.attributes & (0x400 | 0x10) or info.remaining[9] != 1:
            raise ValueError("ACL_REDIRECTED_TARGET")
        final_name = kernel.GetFinalPathNameByHandleW
        final_name.argtypes = [acl.HANDLE, ct.c_wchar_p, acl.DWORD, acl.DWORD]
        final_name.restype = acl.DWORD
        buffer = ct.create_unicode_buffer(32768)
        length = final_name(handle, buffer, len(buffer), 0)
        if not 0 < length < len(buffer) or ntpath.normcase(buffer.value.removeprefix("\\\\?\\")) != ntpath.normcase(str(path)):
            raise ValueError("ACL_FINAL_PATH_MISMATCH")
        owner, dacl = ct.c_void_p(), ct.c_void_p()
        code = security.GetSecurityInfo(handle, 1, 5, ct.byref(owner), None, ct.byref(dacl), None, ct.byref(descriptor))
        if code or not owner.value or not dacl.value or not descriptor.value:
            raise acl.AclVerificationError("GetSecurityInfo", code)
        if not security.OpenProcessToken(kernel.GetCurrentProcess(), 8, ct.byref(token)):
            raise acl.AclVerificationError("OpenProcessToken", ct.get_last_error())
        size = acl.DWORD()
        security.GetTokenInformation(token, 1, None, 0, ct.byref(size))
        if not ct.sizeof(acl.HANDLE) <= size.value <= 65536:
            raise ValueError("ACL_OWNER_UNVERIFIED")
        data = ct.create_string_buffer(size.value)
        if not security.GetTokenInformation(token, 1, data, size, ct.byref(size)):
            raise ValueError("ACL_OWNER_UNVERIFIED")
        current = ct.cast(data, ct.POINTER(ct.c_void_p))[0]
        if not current or not ct.addressof(data) <= current <= ct.addressof(data) + len(data) - 8:
            raise ValueError("ACL_OWNER_UNVERIFIED")
        if not security.EqualSid(owner, current):
            raise ValueError("ACL_OWNER_MISMATCH: ownership changes require manual review.")
        trusted = [_sid_bytes(current)]
        for kind in (22, 26):
            sid, capacity = ct.create_string_buffer(68), acl.DWORD(68)
            if not security.CreateWellKnownSid(kind, None, sid, ct.byref(capacity)):
                raise ValueError("ACL_TRUSTED_SID_UNVERIFIED")
            trusted.append(_sid_bytes(sid))
        if not security.IsValidAcl(dacl):
            raise ValueError("ACL_DACL_UNVERIFIED")
        acl_size = struct.unpack_from("<H", ct.string_at(dacl, 8), 2)[0]
        raw = ct.string_at(dacl, acl_size)
        narrowed = narrowed_acl(raw, trusted, trusted[0])
        get_length = security.GetSecurityDescriptorLength
        get_length.argtypes, get_length.restype = [ct.c_void_p], acl.DWORD
        length = get_length(descriptor)
        if not 20 <= length <= 131072:
            raise ValueError("ACL_DESCRIPTOR_UNVERIFIED")
        original = ct.string_at(descriptor, length)

        def apply():
            setter = security.SetSecurityInfo
            setter.argtypes = [acl.HANDLE, ct.c_int32, acl.DWORD, ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_void_p]
            setter.restype = acl.DWORD
            buffer = ct.create_string_buffer(narrowed)
            code = setter(handle, 1, 4 | 0x80000000, None, None, buffer, None)
            if code:
                raise acl.AclVerificationError("SetSecurityInfo", code)

        yield original, narrowed, apply
    finally:
        failed = False
        if descriptor.value and kernel.LocalFree(descriptor):
            failed = True
        for resource in (token.value, handle):
            if resource is not None and not kernel.CloseHandle(resource):
                failed = True
        if failed:
            raise acl.AclVerificationError("CloseHandle", category="CLEANUP_UNCONFIRMED")


def run(args, launcher):
    if launcher.sys.platform != "win32":
        raise launcher.SetupError("ACL_WINDOWS_REQUIRED: this explicit repair action is only available on Windows.")
    plans = []
    try:
        for value in args.repair_private_file:
            path = exact_path(value, launcher.ROOT)
            with pinned_target(path) as (original, narrowed, _):
                fingerprint = hashlib.sha256(original).hexdigest()
                info = path.stat()
                identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
            plans.append((path, fingerprint, identity))
            print(f"[PLAN] Narrow private DACL on exactly {path}; retain original descriptor in a new private backup; add no grants.")
        if args.plan:
            return 0
        if not launcher.sys.stdin.isatty():
            raise launcher.SetupError("ACL_CONSENT_REQUIRED: review setup --plan, then use an interactive terminal and repeat each full path.")
        for path, _, _ in plans:
            if input(f"Authorize ACL narrowing? Type the exact full path {path}: ") != str(path):
                print("[INFO] ACL_REPAIR_DECLINED: nothing was changed.")
                return 1
        for path, fingerprint, identity in plans:
            exact_path(str(path), launcher.ROOT)
            with pinned_target(path, write=True) as (original, narrowed, apply):
                info = path.stat()
                if (hashlib.sha256(original).hexdigest() != fingerprint or
                        (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != identity):
                    raise ValueError("ACL_PLAN_CHANGED: review a new plan before repair.")
                backup = Path(launcher.ROOT) / (".env.dev.acl-backup-" + secrets.token_hex(12) + ".json")
                dev_private.create_private_file(backup, json.dumps({
                    "version": 1, "path": str(path), "descriptor": base64.b64encode(original).decode(),
                    "sha256": fingerprint,
                }).encode())
                apply()
                acl.verify_access(path)
            print(f"[PASS] Narrowed {path}; original descriptor retained in {backup.name}.")
        return 0
    except (EOFError, KeyboardInterrupt):
        print("[INFO] ACL_REPAIR_CANCELLED: retain any reported backups and review a new plan before retrying.")
        return 130
    except Exception as error:
        if isinstance(error, ValueError) and str(error).startswith("ACL_"):
            message = str(error)
        else:
            message = "ACL_REPAIR_UNVERIFIED: inspect Windows Security/Advanced on the exact file; retain any private descriptor backup. No broader ACL was restored."
        raise launcher.SetupError(message) from None
