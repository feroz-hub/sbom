"""Owned, environment-free Next workspaces with live authoritative source links.

Only explicit setup calls ``prepare_workspace``. Startup validation never writes.
Existing private environment/certificate files are neither copied nor repaired.
This is configuration isolation, not a sandbox against trusted frontend code.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path

_MANIFEST = ".sbom-frontend-workspace.json"
_CONFIGS = frozenset(
    {
        "package.json",
        "package-lock.json",
        "tsconfig.json",
        "next.config.mjs",
        "next.config.js",
        "next.config.ts",
        "postcss.config.mjs",
        "postcss.config.js",
        "tailwind.config.ts",
        "tailwind.config.js",
        "eslint.config.mjs",
        "AGENTS.md",
        "CLAUDE.md",
    }
)
_REQUIRED_CONFIGS = {"package.json", "package-lock.json", "tsconfig.json"}
_LINKS = {"src", "public", "node_modules"}
_GENERATED_FILES = {"next-env.d.ts", "tsconfig.tsbuildinfo", "AGENTS.md", "CLAUDE.md"}
_GENERATED_DIRECTORIES = {".next"}
_LIMIT = 8 * 1024 * 1024


class _UnsafeWorkspace(ValueError):
    pass


class _StaleWorkspace(ValueError):
    pass


class _LinkUnavailable(OSError):
    pass


def _fail(launcher, code):
    raise launcher.SetupError(
        f"{code}: review the frontend workspace through setup; retain unexpected or incomplete files. "
        "No private configuration was copied, removed or repaired."
    ) from None


def _absolute(path):
    return Path(os.path.abspath(os.fspath(path)))


def _same_path(first, second):
    return os.path.normcase(os.path.normpath(os.fspath(first))) == os.path.normcase(os.path.normpath(os.fspath(second)))


def _reparse(info):
    return bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024))


def _identity(info):
    return {"device": info.st_dev, "inode": info.st_ino, "mode": info.st_mode, "owner": info.st_uid}


def _directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or _reparse(info):
        raise _UnsafeWorkspace()
    return _identity(info)


def _chain(path, *, missing=False):
    """Inspect every parent before descending; never resolve a redirected parent."""
    for current in [*reversed(path.parents), path]:
        try:
            _directory(current)
        except FileNotFoundError:
            if missing and current == path:
                return False
            raise
    return True


def workspace_path(launcher, profile):
    if profile == "legacy":
        return _absolute(launcher.ROOT) / ".dev-frontend"
    if profile == "greenfield":
        return _absolute(launcher.GreenfieldStack.STATE) / "frontend-isolated"
    _fail(launcher, "FRONTEND_PROFILE_INVALID")


def configuration_inputs(launcher, profile):
    """Public preparation inputs for the launcher's private plan fingerprint."""
    source = _absolute(launcher.ROOT) / "frontend"
    return (*[source / name for name in sorted(_CONFIGS)], workspace_path(launcher, profile) / _MANIFEST)


def _paths(launcher, profile):
    root = _absolute(launcher.ROOT)
    _chain(root)
    source = root / "frontend"
    _chain(source)
    workspace = workspace_path(launcher, profile)
    parent = workspace.parent
    if not _chain(parent, missing=profile == "greenfield"):
        return source, workspace, False
    if profile == "greenfield":
        launcher.LocalHttps.private_directory(parent)
    if os.path.commonpath((str(parent), str(workspace))) != str(parent):
        raise _UnsafeWorkspace()
    return source, workspace, True


def _regular(path, limit=_LIMIT):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or _reparse(before):
        raise _UnsafeWorkspace()
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if _identity(opened) != _identity(before) or opened.st_nlink != 1:
            raise _UnsafeWorkspace()
        content = stream.read(limit + 1)
    if len(content) > limit or _identity(path.lstat()) != _identity(before):
        raise _UnsafeWorkspace()
    version = {
        **_identity(before),
        "size": before.st_size,
        "modified": before.st_mtime_ns,
        "sha256": hashlib.sha256(content).hexdigest(),
    }
    return content, version


def _source(source):
    configs = {}
    for name in sorted(_CONFIGS):
        try:
            configs[name] = _regular(source / name)
        except FileNotFoundError:
            continue
    if not _REQUIRED_CONFIGS <= configs.keys():
        raise _UnsafeWorkspace()
    links = {}
    for name in sorted(_LINKS):
        try:
            links[name] = _directory(source / name)
        except FileNotFoundError:
            if name != "public":
                raise
    return configs, links


def _target(link):
    value = os.readlink(link)
    if sys.platform == "win32":
        if value.startswith("\\\\?\\UNC\\"):
            value = "\\\\" + value[8:]
        elif value.startswith("\\\\?\\"):
            value = value[4:]
    return _absolute(link.parent / value)


def _link(link, target, expected):
    info = link.lstat()
    if sys.platform == "win32":
        if not _reparse(info) or getattr(info, "st_reparse_tag", 0) != getattr(
            stat, "IO_REPARSE_TAG_MOUNT_POINT", 0xA0000003
        ):
            raise _UnsafeWorkspace()
    elif not stat.S_ISLNK(info.st_mode):
        raise _UnsafeWorkspace()
    if _identity(info) != expected or not _same_path(_target(link), target):
        raise _UnsafeWorkspace()


def _manifest(source, workspace, profile, configs, links):
    copies = {name: _regular(workspace / name)[1] for name in configs}
    if any(copies[name]["sha256"] != version["sha256"] for name, (_, version) in configs.items()):
        raise _UnsafeWorkspace()
    return {
        "version": 1,
        "profile": profile,
        "source": str(source),
        "workspace": str(workspace),
        "source_identity": _directory(source),
        "workspace_identity": _directory(workspace),
        "repository_identity": _directory(source.parent),
        "parent_identity": _directory(workspace.parent),
        "links": {
            name: {"source": identity, "link": _identity((workspace / name).lstat())}
            for name, identity in links.items()
        },
        "configs": {name: {"source": version, "copy": copies[name]} for name, (_, version) in configs.items()},
    }


def _inspect(source, workspace, profile, *, refresh=False):
    _directory(workspace)
    raw, manifest_version = _regular(workspace / _MANIFEST, limit=1048576)
    value = json.loads(raw)
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "version",
            "profile",
            "source",
            "workspace",
            "source_identity",
            "workspace_identity",
            "repository_identity",
            "parent_identity",
            "links",
            "configs",
        }
        or type(value["version"]) is not int
        or value["version"] != 1
        or value["profile"] != profile
        or not _same_path(value["source"], source)
        or not _same_path(value["workspace"], workspace)
        or value["source_identity"] != _directory(source)
        or value["repository_identity"] != _directory(source.parent)
        or value["parent_identity"] != _directory(workspace.parent)
        or value["workspace_identity"] != _directory(workspace)
        or not isinstance(value["links"], dict)
        or not isinstance(value["configs"], dict)
        or not set(value["links"]) <= _LINKS
        or not set(value["configs"]) <= _CONFIGS
    ):
        raise _UnsafeWorkspace()
    known = {_MANIFEST, *value["links"], *value["configs"], *_GENERATED_FILES, *_GENERATED_DIRECTORIES}
    seen = set()
    for path in workspace.iterdir():
        name = path.name
        if name.casefold().startswith(".env") or name.casefold() in seen or name not in known:
            raise _UnsafeWorkspace()
        seen.add(name.casefold())
        if name in _GENERATED_FILES:
            _regular(path)
        elif name in _GENERATED_DIRECTORIES:
            _directory(path)
    configs, links = _source(source)
    if not set(value["configs"]) <= configs.keys() or not set(value["links"]) <= links.keys():
        raise _UnsafeWorkspace()  # Source removal requires independent review, never automatic deletion.
    stale = set(value["configs"]) != configs.keys() or set(value["links"]) != links.keys()
    for name, owned in value["links"].items():
        _link(workspace / name, source / name, owned["link"])
        stale = stale or owned["source"] != links[name]
    for name, owned in value["configs"].items():
        _, current = _regular(workspace / name)
        if current != owned["copy"] or owned["copy"]["sha256"] != owned["source"]["sha256"]:
            raise _UnsafeWorkspace()  # Never overwrite an edited/replaced workspace configuration.
        stale = stale or owned["source"] != configs[name][1]
    if stale and not refresh:
        raise _StaleWorkspace()
    return value, manifest_version, configs, links


def inspect_workspace(launcher, profile):
    """True for a current owned workspace, False only when absent; otherwise refuse."""
    try:
        source, workspace, parent_exists = _paths(launcher, profile)
        if not parent_exists:
            return False
        try:
            workspace.lstat()
        except FileNotFoundError:
            return False
        _inspect(source, workspace, profile)
        return True
    except _StaleWorkspace:
        _fail(launcher, "FRONTEND_WORKSPACE_SETUP_REQUIRED")
    except Exception:
        _fail(launcher, "FRONTEND_WORKSPACE_REVIEW_REQUIRED")


def require_workspace(launcher, profile):
    if not inspect_workspace(launcher, profile):
        _fail(launcher, "FRONTEND_WORKSPACE_SETUP_REQUIRED")
    return workspace_path(launcher, profile)


def _create(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def _create_link(source, destination):
    try:
        if sys.platform == "win32":
            import _winapi

            _winapi.CreateJunction(str(source), str(destination))
        else:
            destination.symlink_to(source, target_is_directory=True)
    except (ImportError, AttributeError, OSError):
        raise _LinkUnavailable() from None


def _refresh_owned(path, version, content):
    """Write only the verified manifest-owned file object, never a replacement path."""
    current_bytes, current = _regular(path)
    if current != version:
        raise _UnsafeWorkspace()
    fd = os.open(
        path, os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        opened = os.fstat(fd)
        if _identity(opened) != {key: version[key] for key in _identity(opened)} or opened.st_nlink != 1:
            raise _UnsafeWorkspace()
        if os.read(fd, len(current_bytes) + 1) != current_bytes or _identity(path.lstat()) != _identity(opened):
            raise _UnsafeWorkspace()
        os.lseek(fd, 0, os.SEEK_SET)
        remaining = memoryview(content)
        while remaining:
            count = os.write(fd, remaining)
            if count <= 0:
                raise _UnsafeWorkspace()
            remaining = remaining[count:]
        os.ftruncate(fd, len(content))
        os.fsync(fd)
        if _identity(path.lstat()) != _identity(opened):
            raise _UnsafeWorkspace()
    finally:
        os.close(fd)


def prepare_workspace(launcher, profile):
    """Explicit setup only: create or refresh verified public config copies/links."""
    try:
        source, workspace, parent_exists = _paths(launcher, profile)
        if not parent_exists:
            raise _UnsafeWorkspace()
        configs, links = _source(source)
        try:
            workspace.lstat()
        except FileNotFoundError:
            workspace.mkdir(mode=0o700)
            for name in links:
                _create_link(source / name, workspace / name)
            for name, (content, _) in configs.items():
                _create(workspace / name, content)
            manifest = _manifest(source, workspace, profile, configs, links)
            _create(workspace / _MANIFEST, json.dumps(manifest, sort_keys=True).encode())
        else:
            old, manifest_version, configs, links = _inspect(source, workspace, profile, refresh=True)
            if (
                set(old["links"]) == links.keys()
                and set(old["configs"]) == configs.keys()
                and all(old["links"][name]["source"] == identity for name, identity in links.items())
                and all(old["configs"][name]["source"] == version for name, (_, version) in configs.items())
            ):
                return require_workspace(launcher, profile)
            for name in links:
                if name not in old["links"]:
                    _create_link(source / name, workspace / name)
            for name, (content, version) in configs.items():
                if name not in old["configs"]:
                    _create(workspace / name, content)
                elif old["configs"][name]["source"] != version:
                    _refresh_owned(workspace / name, old["configs"][name]["copy"], content)
            manifest = _manifest(source, workspace, profile, configs, links)
            _refresh_owned(workspace / _MANIFEST, manifest_version, json.dumps(manifest, sort_keys=True).encode())
        require_workspace(launcher, profile)
        return workspace
    except _LinkUnavailable:
        _fail(launcher, "FRONTEND_WORKSPACE_LINK_UNAVAILABLE")
    except Exception:
        _fail(launcher, "FRONTEND_WORKSPACE_PREPARATION_INCOMPLETE")
