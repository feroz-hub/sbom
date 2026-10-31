"""Read existing development snapshots without preparation or application imports.

Greenfield callers must pass the existing certificate/trust gate before resolving
application credentials. This adapter never reads the setup-password.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

if __package__:
    from . import dev_config
else:
    import dev_config


class EnvironmentReadError(ValueError):
    """A safe category without private file content or external exception text."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def bounded_read_bytes(path, limit=131072):
    path = Path(path)
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or getattr(before, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024)
    ):
        raise EnvironmentReadError("REDIRECTED_FILE")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        current = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise EnvironmentReadError("REDIRECTED_FILE")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise EnvironmentReadError("OVERSIZED_FILE")
    return data


def bounded_read_text(path, limit=131072):
    return bounded_read_bytes(path, limit).decode("utf-8-sig")


def select_profile(args, launcher, state):
    requested = args.profile
    recorded = (state or {}).get("profile")
    if requested == "auto" and recorded in {"legacy", "greenfield"}:
        requested = recorded
    profile = launcher.resolve_profile(requested)
    if recorded in {"legacy", "greenfield"} and recorded != profile:
        raise EnvironmentReadError("PROFILE_CONFLICT")
    family = launcher.pin_legacy_configuration(args.legacy_config, state) if profile == "legacy" else "managed"
    return profile, family


def load_legacy_snapshots(family, launcher):
    """Read only the explicitly selected family; never discover credentials."""
    paths = {
        "managed": launcher.CONFIG,
        "windows": launcher.ROOT / ".windows/sbom.env.ps1",
        "env": launcher.ROOT / ".env",
    }
    parsers = {"managed": dev_config.parse_managed, "windows": dev_config.parse_windows, "env": dev_config.parse_dotenv}
    if family not in paths:
        raise EnvironmentReadError("INVALID_SELECTION")
    saved = parsers[family](bounded_read_text(paths[family]))
    frontend = launcher.ROOT / "frontend/.env.local"
    values = dev_config.parse_dotenv(bounded_read_text(frontend)) if family != "managed" and frontend.is_file() else {}
    return saved, values


def resolve_existing(args, launcher, state):
    """Resolve snapshots; Greenfield trust must already have been verified."""
    profile, family = select_profile(args, launcher, state)
    common = {
        "profile": profile,
        "family": family,
        "inherited": dict(os.environ),
        "root": str(launcher.ROOT),
        "platform": "linux" if launcher.sys.platform.startswith("linux") else launcher.sys.platform,
    }
    if profile != "greenfield":
        saved, frontend = load_legacy_snapshots(family, launcher)
        return dev_config.resolve_configuration(**common, saved=saved, frontend=frontend)
    saved = json.loads(launcher.GreenfieldStack.read_private("environment.json"))
    if not isinstance(saved, dict):
        raise EnvironmentReadError("CONFIGURATION_INVALID")
    inputs = dev_config.GreenfieldInputs(
        str(launcher.GreenfieldStack.STATE),
        launcher.GreenfieldStack.read_private("runtime-password"),
        launcher.GreenfieldStack.read_private("security-mail-key")
        if "NATIVE_SECURITY_OUTBOX_KEY" not in saved
        else None,
        launcher.GreenfieldStack.read_private("provider-storage-key")
        if "AI_CONFIG_ENCRYPTION_KEY" not in saved
        else None,
    )
    return dev_config.resolve_configuration(**common, saved=saved, greenfield=inputs)
