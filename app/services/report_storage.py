"""Private filesystem artifacts. No public static mount; every download is authorized."""

import hashlib
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

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


def storage_root():
    if configuration_errors():
        raise ValueError("REPORT_CONFIGURATION_INVALID")
    root = Path(get_settings().report_artifact_storage_path)
    if root.is_symlink():
        raise ValueError("REPORT_STORAGE_UNSAFE")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.stat().st_mode & 0o077:
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
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
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
