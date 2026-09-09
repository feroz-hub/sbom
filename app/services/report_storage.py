"""Private filesystem artifacts. No public static mount; every download is authorized."""

import hashlib
import os
import re
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from sqlalchemy import select

from ..models import ReportArtifact
from ..settings import get_settings


def configuration_errors(settings=None):
    settings = settings or get_settings()
    errors = []
    try:
        url = urlsplit(settings.report_notification_base_url)
    except ValueError:
        url = urlsplit("")
    if (
        not url.hostname
        or url.username
        or url.password
        or url.query
        or url.fragment
        or url.path not in {"", "/"}
        or not (url.scheme == "https" or url.scheme == "http" and url.hostname in {"localhost", "127.0.0.1", "::1"})
    ):
        errors.append("REPORT_BASE_URL_REQUIRED")
    path = Path(settings.report_artifact_storage_path)
    repository = Path(__file__).resolve().parents[2]
    if (
        not settings.report_artifact_storage_path
        or not path.is_absolute()
        or path.resolve() in {Path("/"), Path.home()}
        or path.resolve().is_relative_to(repository)
    ):
        errors.append("REPORT_PRIVATE_STORAGE_REQUIRED")
    return errors


_windows_hardened_roots: set[str] = set()


def _harden_windows_directory(root: Path):
    """NTFS equivalent of the POSIX owner-only requirement below.

    Windows ignores ``mkdir(mode=...)`` and synthesizes ``st_mode`` as 0o777
    for any writable directory, so the POSIX bit check can never pass there.
    Instead, strip inherited ACEs and grant access to the current user and
    SYSTEM only. ``whoami``/``icacls`` ship with every supported Windows;
    SID forms keep this locale-independent. Failure fails closed, matching
    the POSIX branch.
    """
    key = str(root)
    if key in _windows_hardened_roots:
        return
    try:
        whoami = subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"],
            capture_output=True, text=True, check=True, timeout=30,
        )
        user_sid = whoami.stdout.strip().rsplit(",", 1)[-1].strip().strip('"')
        if not re.fullmatch(r"S-1-[0-9-]+", user_sid):
            raise ValueError("REPORT_STORAGE_PERMISSIONS")
        subprocess.run(
            [
                "icacls", str(root), "/inheritance:r",
                "/grant:r", f"*{user_sid}:(OI)(CI)F",
                "/grant:r", "*S-1-5-18:(OI)(CI)F",
            ],
            capture_output=True, text=True, check=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        raise ValueError("REPORT_STORAGE_PERMISSIONS") from None
    _windows_hardened_roots.add(key)


def storage_root():
    if configuration_errors():
        raise ValueError("REPORT_CONFIGURATION_INVALID")
    root = Path(get_settings().report_artifact_storage_path)
    if root.is_symlink():
        raise ValueError("REPORT_STORAGE_UNSAFE")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "nt":
        _harden_windows_directory(root)
    elif root.stat().st_mode & 0o077:
        raise ValueError("REPORT_STORAGE_PERMISSIONS")
    return root.resolve()


def artifact_path(relative):
    root = storage_root()
    path = root / relative
    if path.name != relative or path.is_symlink() or not path.resolve().is_relative_to(root):
        raise ValueError("REPORT_STORAGE_UNSAFE")
    return path


def store_artifact(db, delivery, attachment):
    relative = uuid4().hex
    path = artifact_path(relative)
    # O_NOFOLLOW is POSIX-only; O_CREAT|O_EXCL already refuses any pre-existing
    # path (including symlinks), and artifact_path() rejects symlinks upfront.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(attachment.content)
            stream.flush()
            os.fsync(stream.fileno())
        now = datetime.now(UTC)
        row = ReportArtifact(
            tenant_id=delivery.tenant_id,
            delivery_id=delivery.id,
            kind=attachment.filename.rsplit(".", 1)[-1].upper(),
            filename=attachment.filename,
            media_type=attachment.media_type,
            size_bytes=len(attachment.content),
            sha256=hashlib.sha256(attachment.content).hexdigest(),
            storage_path=relative,
            created_on=now.isoformat(),
            expires_at=(now + timedelta(days=get_settings().report_retention_days)).isoformat(),
        )
        db.add(row)
        db.flush()
        return row
    except Exception:
        path.unlink(missing_ok=True)
        raise


def purge_orphaned_artifacts(db):
    """Expire crash leftovers as well as ledger-backed artifacts.

    Only this service's random filenames are eligible. Never follow symlinks or
    remove unrelated files. The retention-age delay protects in-flight writes.
    """
    cutoff = (datetime.now(UTC) - timedelta(days=get_settings().report_retention_days)).timestamp()
    removed = 0
    for path in storage_root().iterdir():
        if not re.fullmatch(r"[0-9a-f]{32}", path.name) or path.is_symlink() or not path.is_file():
            continue
        if path.stat().st_mtime >= cutoff:
            continue
        if db.scalar(select(ReportArtifact.id).where(ReportArtifact.storage_path == path.name)) is None:
            artifact_path(path.name).unlink(missing_ok=True)
            removed += 1
        if removed >= 1000:
            break
    return removed
