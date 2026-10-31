"""Owned frontend workspace fixtures; no Next server, services or real config."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev_frontend

SECRET = "fixture-private-content-never-copy-or-log"


class WorkspaceError(RuntimeError):
    pass


@pytest.fixture
def launcher(tmp_path):
    root = tmp_path / "repository"
    source = root / "frontend"
    source.mkdir(parents=True)
    for name in ("src", "public", "node_modules"):
        (source / name).mkdir()
    (source / "src/page.tsx").write_text("fixture original source", encoding="utf-8")
    for name, content in {
        "package.json": '{"name":"fixture"}',
        "package-lock.json": '{"lockfileVersion":3}',
        "tsconfig.json": '{"compilerOptions":{"strict":true}}',
        "next.config.mjs": "export default {};\n",
        ".env.local": "DATABASE_URL=" + SECRET,
    }.items():
        (source / name).write_text(content, encoding="utf-8")
    state = tmp_path / "private-greenfield"
    state.mkdir(mode=0o700)
    return SimpleNamespace(
        ROOT=root,
        GreenfieldStack=SimpleNamespace(STATE=state),
        LocalHttps=SimpleNamespace(private_directory=Mock()),
        SetupError=WorkspaceError,
    )


def contents(directory):
    """Snapshot direct entries without traversing a directory link/junction."""
    if not directory.exists():
        return None
    snapshot = {}
    for path in directory.iterdir():
        info = path.lstat()
        redirected = stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 1024)
        value = os.readlink(path) if redirected else path.read_bytes() if stat.S_ISREG(info.st_mode) else None
        snapshot[path.name] = (info.st_ino, info.st_mode, info.st_mtime_ns, value)
    return snapshot


@pytest.mark.parametrize("profile", ["legacy", "greenfield"])
def test_prepare_and_readonly_require_use_new_owned_workspace_without_private_files(launcher, profile):
    old = launcher.GreenfieldStack.STATE / "frontend"
    old.mkdir()
    (old / ".env.local").write_text(SECRET, encoding="utf-8")
    old_before = contents(old)
    path = dev_frontend.prepare_workspace(launcher, profile)
    expected = (
        launcher.ROOT / ".dev-frontend" if profile == "legacy" else launcher.GreenfieldStack.STATE / "frontend-isolated"
    )
    assert path == expected
    assert not any(child.name.startswith(".env") for child in path.iterdir())
    assert all(SECRET.encode() not in child.read_bytes() for child in path.iterdir() if child.is_file())
    before = contents(path)
    assert dev_frontend.inspect_workspace(launcher, profile) is True
    assert dev_frontend.require_workspace(launcher, profile) == path
    assert contents(path) == before
    assert contents(old) == old_before


def test_absent_workspace_inspection_does_not_create_or_require_installed_node_modules(launcher):
    (launcher.ROOT / "frontend/node_modules").rmdir()
    before = contents(launcher.ROOT)
    assert dev_frontend.inspect_workspace(launcher, "legacy") is False
    with pytest.raises(WorkspaceError, match="FRONTEND_WORKSPACE_SETUP_REQUIRED"):
        dev_frontend.require_workspace(launcher, "legacy")
    assert contents(launcher.ROOT) == before


@pytest.mark.parametrize("profile", ["legacy", "greenfield"])
def test_directory_links_preserve_source_atomic_save_visibility(launcher, profile):
    path = dev_frontend.prepare_workspace(launcher, profile)
    source = launcher.ROOT / "frontend/src"
    replacement = source / "page-new.tsx"
    replacement.write_text("fixture atomically saved source", encoding="utf-8")
    replacement.replace(source / "page.tsx")
    assert (path / "src/page.tsx").read_text(encoding="utf-8") == "fixture atomically saved source"
    assert dev_frontend.require_workspace(launcher, profile) == path
    if sys.platform == "win32":
        assert (path / "src").lstat().st_reparse_tag == stat.IO_REPARSE_TAG_MOUNT_POINT
    else:
        assert (path / "src").is_symlink()


def test_source_environment_file_is_never_read(launcher, monkeypatch):
    original = dev_frontend._regular

    def guarded(path, *args, **kwargs):
        assert not Path(path).name.casefold().startswith(".env"), "A private environment file was read"
        return original(path, *args, **kwargs)

    monkeypatch.setattr(dev_frontend, "_regular", guarded)
    path = dev_frontend.prepare_workspace(launcher, "legacy")
    (path / ".env.production.local").write_text(SECRET, encoding="utf-8")
    with pytest.raises(WorkspaceError):
        dev_frontend.require_workspace(launcher, "legacy")
    assert (path / ".env.production.local").read_text(encoding="utf-8") == SECRET


@pytest.mark.parametrize(
    "name", [".env", ".env.local", ".env.development", ".env.production.local", ".ENV.local", "unknown-private.json"]
)
def test_unexpected_workspace_files_are_preserved_and_block_start_and_preparation(launcher, name, capsys):
    path = dev_frontend.prepare_workspace(launcher, "legacy")
    (path / name).write_text(SECRET, encoding="utf-8")
    before = contents(path)
    with pytest.raises(WorkspaceError) as caught:
        dev_frontend.require_workspace(launcher, "legacy")
    assert SECRET not in str(caught.value)
    with pytest.raises(WorkspaceError):
        dev_frontend.prepare_workspace(launcher, "legacy")
    assert contents(path) == before
    output = capsys.readouterr()
    assert SECRET not in output.out + output.err


def test_existing_unrecorded_workspace_is_not_adopted_or_cleaned(launcher):
    path = dev_frontend.workspace_path(launcher, "legacy")
    path.mkdir()
    (path / "private-original").write_text(SECRET, encoding="utf-8")
    before = contents(path)
    with pytest.raises(WorkspaceError, match="FRONTEND_WORKSPACE_REVIEW_REQUIRED"):
        dev_frontend.require_workspace(launcher, "legacy")
    with pytest.raises(WorkspaceError):
        dev_frontend.prepare_workspace(launcher, "legacy")
    assert contents(path) == before


def test_setup_refreshes_only_verified_owned_public_config_and_is_idempotent(launcher):
    path = dev_frontend.prepare_workspace(launcher, "legacy")
    source = launcher.ROOT / "frontend/next.config.mjs"
    before = contents(path)
    source.write_text("export default { logging: { incomingRequests: false } };\n", encoding="utf-8")
    with pytest.raises(WorkspaceError, match="FRONTEND_WORKSPACE_SETUP_REQUIRED"):
        dev_frontend.require_workspace(launcher, "legacy")
    assert contents(path) == before
    assert dev_frontend.prepare_workspace(launcher, "legacy") == path
    assert (path / source.name).read_bytes() == source.read_bytes()
    refreshed = contents(path)
    assert dev_frontend.prepare_workspace(launcher, "legacy") == path
    assert contents(path) == refreshed


def test_changed_workspace_copy_is_never_overwritten_even_when_source_changes(launcher):
    path = dev_frontend.prepare_workspace(launcher, "legacy")
    (path / "next.config.mjs").write_text(SECRET, encoding="utf-8")
    (launcher.ROOT / "frontend/next.config.mjs").write_text("export default { fixture: true };", encoding="utf-8")
    before = contents(path)
    with pytest.raises(WorkspaceError):
        dev_frontend.prepare_workspace(launcher, "legacy")
    assert contents(path) == before


def test_source_config_removal_requires_review_without_deleting_old_copy(launcher):
    path = dev_frontend.prepare_workspace(launcher, "legacy")
    (launcher.ROOT / "frontend/next.config.mjs").unlink()
    before = contents(path)
    with pytest.raises(WorkspaceError):
        dev_frontend.prepare_workspace(launcher, "legacy")
    assert contents(path) == before


def test_next_generated_artifacts_are_regular_and_do_not_force_repreparation(launcher):
    path = dev_frontend.prepare_workspace(launcher, "legacy")
    (path / ".next").mkdir()
    (path / "next-env.d.ts").write_text('/// <reference types="next" />\n', encoding="utf-8")
    (path / "tsconfig.tsbuildinfo").write_text("{}", encoding="utf-8")
    (path / "AGENTS.md").write_text("fixture Next-generated rules", encoding="utf-8")
    before = contents(path)
    assert dev_frontend.require_workspace(launcher, "legacy") == path
    assert contents(path) == before


def test_replaced_dependency_directory_needs_setup_but_preserves_exact_link_target(launcher, tmp_path):
    path = dev_frontend.prepare_workspace(launcher, "legacy")
    modules = launcher.ROOT / "frontend/node_modules"
    modules.rename(tmp_path / "old-fixture-node-modules")
    modules.mkdir()
    with pytest.raises(WorkspaceError, match="FRONTEND_WORKSPACE_SETUP_REQUIRED"):
        dev_frontend.require_workspace(launcher, "legacy")
    dev_frontend.prepare_workspace(launcher, "legacy")
    assert dev_frontend.require_workspace(launcher, "legacy") == path


@pytest.mark.parametrize("which", ["workspace", "source", "source-link"])
def test_redirected_workspace_source_or_owned_link_is_refused_without_following_private_files(
    launcher, tmp_path, which
):
    path = dev_frontend.prepare_workspace(launcher, "legacy")
    outside = tmp_path / "unrelated-fixture"
    outside.mkdir()
    (outside / ".env").write_text(SECRET, encoding="utf-8")
    redirected = path if which == "workspace" else launcher.ROOT / "frontend" if which == "source" else path / "src"
    redirected.rename(tmp_path / "preserved-original")
    dev_frontend._create_link(outside, redirected)
    with pytest.raises(WorkspaceError, match="FRONTEND_WORKSPACE_REVIEW_REQUIRED"):
        dev_frontend.require_workspace(launcher, "legacy")
    assert (outside / ".env").read_text(encoding="utf-8") == SECRET


def test_manifest_paths_cannot_redirect_reads_outside_authoritative_source(launcher, tmp_path, monkeypatch):
    path = dev_frontend.prepare_workspace(launcher, "legacy")
    record = path / dev_frontend._MANIFEST
    value = json.loads(record.read_text(encoding="utf-8"))
    outside = tmp_path / "private-fixture"
    outside.mkdir()
    (outside / "package.json").write_text(SECRET, encoding="utf-8")
    value["source"] = str(outside)
    record.write_text(json.dumps(value), encoding="utf-8")
    original = dev_frontend._regular

    def guarded(candidate, *args, **kwargs):
        assert Path(candidate).parent != outside, "Untrusted manifest redirected a file read"
        return original(candidate, *args, **kwargs)

    monkeypatch.setattr(dev_frontend, "_regular", guarded)
    with pytest.raises(WorkspaceError):
        dev_frontend.require_workspace(launcher, "legacy")


def test_failed_link_preparation_retains_new_artifacts_and_never_adopts_them(launcher, monkeypatch):
    original = dev_frontend._create_link
    calls = []

    def fail_second(source, destination):
        calls.append(destination)
        if len(calls) == 2:
            raise OSError("fixture failure " + SECRET)
        return original(source, destination)

    with monkeypatch.context() as scope:
        scope.setattr(dev_frontend, "_create_link", fail_second)
        with pytest.raises(WorkspaceError) as caught:
            dev_frontend.prepare_workspace(launcher, "legacy")
        assert SECRET not in str(caught.value)
    path = dev_frontend.workspace_path(launcher, "legacy")
    assert path.exists() and any(path.iterdir())
    assert not (path / dev_frontend._MANIFEST).exists()
    before = contents(path)
    with pytest.raises(WorkspaceError):
        dev_frontend.prepare_workspace(launcher, "legacy")
    assert contents(path) == before


def test_windows_missing_junction_api_fails_closed_without_symlink_or_shell_fallback(launcher, monkeypatch):
    monkeypatch.setattr(dev_frontend.sys, "platform", "win32")
    monkeypatch.setitem(sys.modules, "_winapi", SimpleNamespace())
    forbidden = Mock(side_effect=AssertionError("Missing junction support triggered a privileged fallback"))
    monkeypatch.setattr(Path, "symlink_to", forbidden)
    with pytest.raises(WorkspaceError):
        dev_frontend.prepare_workspace(launcher, "legacy")
    forbidden.assert_not_called()


def test_readonly_validation_has_no_creation_refresh_or_write_capability(launcher, monkeypatch):
    path = dev_frontend.prepare_workspace(launcher, "legacy")
    before = contents(path)
    forbidden = Mock(side_effect=AssertionError("Readonly workspace validation attempted mutation"))
    for name in ("_create", "_create_link", "_refresh_owned"):
        monkeypatch.setattr(dev_frontend, name, forbidden)
    monkeypatch.setattr(Path, "mkdir", forbidden)
    original_open = os.open

    def readonly_open(filename, flags, *args, **kwargs):
        assert not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
        return original_open(filename, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", readonly_open)
    assert dev_frontend.inspect_workspace(launcher, "legacy") is True
    assert dev_frontend.require_workspace(launcher, "legacy") == path
    assert contents(path) == before
    forbidden.assert_not_called()


def test_manifest_cannot_adopt_a_workspace_copy_different_from_its_authoritative_source(launcher):
    path = dev_frontend.prepare_workspace(launcher, "legacy")
    copied = path / "next.config.mjs"
    copied.write_text(SECRET, encoding="utf-8")
    record = path / dev_frontend._MANIFEST
    value = json.loads(record.read_text(encoding="utf-8"))
    value["configs"][copied.name]["copy"] = dev_frontend._regular(copied)[1]
    record.write_text(json.dumps(value), encoding="utf-8")
    before = contents(path)
    with pytest.raises(WorkspaceError):
        dev_frontend.require_workspace(launcher, "legacy")
    with pytest.raises(WorkspaceError):
        dev_frontend.prepare_workspace(launcher, "legacy")
    assert contents(path) == before
