"""Read-only discovery tests; actual Git mutations are fixture setup only.

Run with --noconftest. No application, protected configuration, service, network,
existing repository mutation, runtime record or database is involved.
"""

from __future__ import annotations

import builtins
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from scripts import dev_workspace as workspace

HEAD = "1" * 40
SECOND_HEAD = "2" * 40
SECRET = "synthetic-private-stderr-and-remote-token"


def _record(root, *, head=HEAD, branch="refs/heads/main", detached=False, bare=False, locked=False, prunable=False):
    fields = [b"worktree " + os.fsencode(root)]
    if bare:
        fields.append(b"bare")
    else:
        fields.append(b"HEAD " + head.encode())
        fields.append(b"detached" if detached else b"branch " + branch.encode())
    if locked:
        fields.append(b"locked " + SECRET.encode())
    if prunable:
        fields.append(b"prunable " + SECRET.encode())
    return b"\0".join(fields) + b"\0\0"


class SyntheticGit:
    def __init__(self, roots, common, *, listing=None):
        self.roots, self.common = roots, common
        self.listing = listing or b"".join(_record(root) for root in roots)
        self.calls = []
        self.results = {}
        self.list_calls = 0
        self.changed_listing = None

    def __call__(self, command, **arguments):
        self.calls.append((command, arguments))
        for name in ("rev-parse", "worktree", "config", "ls-files", "check-attr", "status"):
            if name in command:
                operation = name
                break
        else:
            raise AssertionError("Unexpected fixture Git operation")
        override = self.results.get((str(arguments["cwd"]), operation), self.results.get(operation))
        if override is not None:
            if isinstance(override, Exception):
                raise override
            return override
        if operation == "rev-parse":
            return workspace.CommandResult(0, os.fsencode(self.common) + b"\n")
        if operation == "worktree":
            self.list_calls += 1
            return workspace.CommandResult(0, self.changed_listing if self.list_calls > 1 and self.changed_listing else self.listing)
        if operation == "config":
            return workspace.CommandResult(1)
        if operation == "ls-files":
            return workspace.CommandResult(0, b"tracked file\0")
        if operation == "check-attr":
            assert arguments["input_bytes"] == b"tracked file\0"
            return workspace.CommandResult(0, b"tracked file\0filter\0unspecified\0")
        return workspace.CommandResult(0)


@pytest.fixture
def candidate(tmp_path):
    root = (tmp_path / "main checkout with spaces").resolve()
    second = tmp_path / "second checkout"
    root.mkdir()
    second.mkdir()
    common = root / ".git"
    common.mkdir()
    return root, second, common, SyntheticGit([root, second], common)


def test_frozen_filesystem_identity_ids_and_unknown_ownership(candidate):
    root, second, common, runner = candidate
    runner.results[(str(second), "status")] = workspace.CommandResult(0, b"?? ordinary untracked file\0")
    result = workspace.discover_workspaces(root, runner=runner)
    assert result.status == "PASS" and result.codes == ()
    assert result.root == root and result.head == HEAD
    assert result.common_directory.canonical_path == common
    assert len(result.worktrees) == 2
    assert [item.dirty for item in result.worktrees] == [False, True]
    assert all(item.agent_owner == "UNKNOWN" for item in result.worktrees)
    assert len(result.repository_id) == 64 and int(result.repository_id, 16) >= 0
    assert len({item.worktree_id for item in result.worktrees}) == 2
    assert all(item.identity.device >= 0 and item.identity.inode > 0 for item in result.worktrees)
    with pytest.raises(FrozenInstanceError):
        result.head = SECOND_HEAD
    with pytest.raises(FrozenInstanceError):
        result.worktrees[0].dirty = True


def test_native_discovery_parallelism_is_bounded_and_preserves_git_order(candidate, tmp_path, monkeypatch):
    root, second, common, _ = candidate
    roots = [root, second]
    for index in range(6):
        path = tmp_path / str(index)
        path.mkdir()
        roots.append(path)
    runner = SyntheticGit(roots, common)
    monkeypatch.setattr(workspace, "_run_git", runner)
    monkeypatch.setattr(workspace.shutil, "which", lambda name: sys.executable)
    original = workspace._worktree
    barrier = threading.Barrier(4)
    lock = threading.Lock()
    active = maximum = 0

    def observe(*args):
        nonlocal active, maximum
        with lock:
            active += 1
            maximum = max(active, maximum)
        try:
            barrier.wait(timeout=5)
            return original(*args)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(workspace, "_worktree", observe)
    result = workspace.discover_workspaces(root)
    assert result.status == "PASS"
    assert maximum == 4 and active == 0
    assert [item.root for item in result.worktrees] == roots
    assert runner.list_calls == 2


def test_ids_survive_head_branch_and_dirty_changes(candidate):
    root, second, _, runner = candidate
    first = workspace.discover_workspaces(root, runner=runner)
    runner.listing = _record(root, head=SECOND_HEAD, branch="refs/heads/review") + _record(second, detached=True)
    runner.results["status"] = workspace.CommandResult(0, b" M tracked file\0")
    later = workspace.discover_workspaces(second, runner=runner)
    assert later.repository_id == first.repository_id
    assert [item.worktree_id for item in later.worktrees] == [item.worktree_id for item in first.worktrees]
    assert later.worktrees[0].branch == "refs/heads/review"
    assert later.worktrees[1].detached and later.worktrees[1].branch is None


def test_locked_prunable_and_missing_directory_are_observations_without_reason_leak(candidate):
    root, second, common, _ = candidate
    missing = second / "missing"
    runner = SyntheticGit([root], common, listing=_record(root, locked=True) + _record(missing, prunable=True))
    result = workspace.discover_workspaces(root, runner=runner)
    assert result.status == "BLOCKED"
    assert result.worktrees[0].locked is True
    absent = result.worktrees[1]
    assert absent.prunable is True and absent.identity is None and absent.dirty is None
    assert absent.status == "BLOCKED" and absent.agent_owner == "UNKNOWN"
    assert SECRET not in repr(result)


@pytest.mark.skipif(os.name == "nt", reason="Windows filenames cannot contain newline characters")
def test_porcelain_nul_preserves_newline_paths(tmp_path):
    root = (tmp_path / "checkout\nwith newline ").resolve()
    root.mkdir()
    common = root / ".git"
    common.mkdir()
    result = workspace.discover_workspaces(root, runner=SyntheticGit([root], common))
    assert result.status == "PASS" and result.root == root
    assert result.worktrees[0].root == root


@pytest.mark.parametrize(
    "listing",
    (b"worktree /fixture\nHEAD secret\n", b"worktree /fixture\0HEAD wrong\0detached\0\0",
     b"worktree /fixture\0bare\0HEAD secret\0\0", b"worktree /fixture\0unknown secret\0\0"),
)
def test_malformed_git_records_fail_with_fixed_codes(candidate, listing):
    root, _, _, runner = candidate
    runner.listing = listing
    result = workspace.discover_workspaces(root, runner=runner)
    assert result.status == "BLOCKED" and result.worktrees == ()
    assert result.codes == ("GIT_WORKTREE_FORMAT_UNVERIFIED",)
    assert "secret" not in repr(result)


def test_changed_listing_invalidates_previously_passing_records(candidate):
    root, second, _, runner = candidate
    runner.changed_listing = _record(root, head=SECOND_HEAD) + _record(second)
    result = workspace.discover_workspaces(root, runner=runner)
    assert result.codes == ("GIT_WORKTREE_SNAPSHOT_CHANGED",)
    assert all(item.status == "BLOCKED" for item in result.worktrees)


@pytest.mark.parametrize(
    ("operation", "response", "code"),
    (
        ("config", workspace.CommandResult(0, b"filter.fixture.clean\0"), "GIT_FILTER_OR_PROMISOR_REVIEW_REQUIRED"),
        ("config", workspace.CommandResult(0, b"remote.fixture.promisor\0"), "GIT_FILTER_OR_PROMISOR_REVIEW_REQUIRED"),
        ("check-attr", workspace.CommandResult(0, b"tracked file\0filter\0fixture\0"), "GIT_FILTER_OR_PROMISOR_REVIEW_REQUIRED"),
        ("check-attr", workspace.CommandResult(0, b"other file\0filter\0unspecified\0"), "GIT_ATTRIBUTES_UNVERIFIED"),
        ("status", workspace.CommandResult(5, stderr=SECRET.encode()), "GIT_COMMAND_BLOCKED"),
        ("status", workspace.CommandResult(0, b"unverifiable\0"), "GIT_STATUS_FORMAT_UNVERIFIED"),
        ("status", PermissionError(SECRET), "GIT_PROBE_UNVERIFIED"),
    ),
)
def test_unknown_dirty_state_is_blocked_not_clean(candidate, operation, response, code):
    root, _, _, runner = candidate
    runner.results[operation] = response
    result = workspace.discover_workspaces(root, runner=runner)
    assert result.status == "BLOCKED"
    assert all(item.dirty is None and code in item.codes for item in result.worktrees)
    assert SECRET not in repr(result)
    if operation in {"config", "check-attr"}:
        assert all("status" not in command for command, _ in runner.calls)


def test_transport_excludes_inherited_preloads_credential_helpers_and_git_routing(candidate, monkeypatch):
    root, _, _, runner = candidate
    for name in ("GIT_DIR", "GIT_CONFIG_COUNT", "GIT_ASKPASS", "GIT_SSH_COMMAND", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PYTHONPATH", "NODE_OPTIONS", "DATABASE_URL"):
        monkeypatch.setenv(name, SECRET)
    workspace.discover_workspaces(root, runner=runner)
    for command, arguments in runner.calls:
        env = arguments["environment"]
        assert SECRET not in repr(dict(env))
        assert env["GIT_OPTIONAL_LOCKS"] == "0" and env["GIT_NO_LAZY_FETCH"] == "1"
        assert env["GIT_ALLOW_PROTOCOL"] == "" and env["GIT_TERMINAL_PROMPT"] == "0"
        assert "--no-optional-locks" in command and "core.fsmonitor=false" in command
        assert "submodule.recurse=false" in command and "protocol.allow=never" in command
        assert "core.hooksPath=" + os.devnull in command
        assert 0 < arguments["timeout"] <= 5 and arguments["max_output"] <= 4 * 1024 * 1024
        with pytest.raises(TypeError):
            env["MUTATION"] = "forbidden"


def test_missing_git_and_output_limits_are_fixed_failures(candidate, monkeypatch):
    root, _, _, runner = candidate
    monkeypatch.setattr(workspace.shutil, "which", lambda name: None)
    assert workspace.discover_workspaces(root).codes == ("GIT_REQUIRED",)
    runner.results["worktree"] = workspace.CommandResult(0, b"x" * (workspace._OUTPUT_LIMIT + 1))
    assert workspace.discover_workspaces(root, runner=runner).codes == ("GIT_OUTPUT_LIMIT",)


def test_discovery_imports_no_application_or_database_and_opens_no_network(candidate, monkeypatch):
    root, _, _, runner = candidate
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        assert name != "app" and not name.startswith("app.")
        assert name.split(".", 1)[0] not in {"psycopg", "sqlalchemy", "redis"}
        return original_import(name, *args, **kwargs)

    def forbidden(*args, **kwargs):
        raise AssertionError("Read-only synthetic discovery reached a mutation, process or network path")

    with monkeypatch.context() as boundary:
        boundary.setattr(builtins, "__import__", guarded_import)
        boundary.setattr(socket, "socket", forbidden)
        boundary.setattr(socket, "create_connection", forbidden)
        boundary.setattr(subprocess, "Popen", forbidden)
        boundary.setattr(Path, "write_text", forbidden)
        boundary.setattr(Path, "write_bytes", forbidden)
        assert workspace.discover_workspaces(root, runner=runner).status == "PASS"


def test_runner_timeout_and_output_bounds_stop_only_its_original_child(tmp_path):
    environment = workspace._environment()
    with pytest.raises(workspace.WorkspaceError, match="^GIT_TIMEOUT$"):
        workspace._run_git(
            (sys.executable, "-I", "-S", "-c", "import time; time.sleep(10)"), cwd=tmp_path,
            environment=environment, timeout=0.1, max_output=1024,
        )
    with pytest.raises(workspace.WorkspaceError, match="^GIT_OUTPUT_LIMIT$"):
        workspace._run_git(
            (sys.executable, "-I", "-S", "-c", "print('x'*4096)"), cwd=tmp_path,
            environment=environment, timeout=2, max_output=1024,
        )


@pytest.fixture
def disposable_git(tmp_path):
    git = shutil.which("git")
    if git is None:
        pytest.skip("Disposable repository acceptance requires existing Git; no installation is permitted")
    root = (tmp_path / "actual repository with spaces").resolve()
    root.mkdir()
    environment = dict(workspace._environment())

    def run(*arguments, cwd=root):
        completed = subprocess.run(
            [git, "--no-pager", "-c", "core.hooksPath=" + os.devnull, "-c", "commit.gpgSign=false", *arguments],
            cwd=cwd, env=environment, capture_output=True, timeout=10,
        )
        assert completed.returncode == 0, "Disposable Git fixture setup failed; output withheld"
        return completed.stdout

    run("-c", "init.templateDir=", "init", "--quiet", "--initial-branch=main")
    (root / "tracked.txt").write_text("fixture tracked content\n", encoding="utf-8")
    run("add", "--", "tracked.txt")
    run("-c", "user.name=Fixture", "-c", "user.email=fixture@localhost.invalid", "commit", "--quiet", "--no-gpg-sign", "-m", "Fixture")
    return root, run


def test_actual_git_worktrees_are_isolated_immutable_observations(disposable_git, tmp_path):
    root, git = disposable_git
    linked = tmp_path / "actual linked checkout"
    git("worktree", "add", "--quiet", "-b", "feature/fixture", str(linked))
    git("worktree", "lock", "--reason", SECRET, str(linked))
    (linked / "tracked.txt").write_text("fixture changed content\n", encoding="utf-8")
    (linked / "untracked file").write_text("fixture\n", encoding="utf-8")
    main_index = root / ".git/index"
    linked_index = Path(os.fsdecode(git("rev-parse", "--path-format=absolute", "--git-path", "index", cwd=linked)[:-1]))
    observed = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in (main_index, linked_index)}
    first = workspace.discover_workspaces(root)
    second = workspace.discover_workspaces(linked)
    assert first.status == second.status == "PASS"
    assert first.repository_id == second.repository_id
    assert first.common_directory == second.common_directory
    trees = {item.root: item for item in first.worktrees}
    assert trees[root].dirty is False and trees[linked.resolve()].dirty is True
    assert trees[linked.resolve()].locked is True
    assert trees[root].branch == "refs/heads/main"
    assert trees[linked.resolve()].branch == "refs/heads/feature/fixture"
    assert all(item.agent_owner == "UNKNOWN" for item in trees.values())
    assert {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in observed} == observed
    assert SECRET not in repr(first)


def test_actual_git_filter_configuration_never_runs_a_clean_command(disposable_git, tmp_path):
    root, git = disposable_git
    marker = tmp_path / "filter-was-executed"
    executable = json.dumps(sys.executable.replace("\\", "/"))
    script = "from pathlib import Path;Path(" + repr(str(marker)) + ").write_text('unsafe')"
    git("config", "filter.fixture.clean", executable + " -c " + json.dumps(script))
    (root / ".gitattributes").write_text("tracked.txt filter=fixture\n", encoding="utf-8")
    result = workspace.discover_workspaces(root)
    assert result.status == "BLOCKED" and result.worktrees[0].dirty is None
    assert "GIT_FILTER_OR_PROMISOR_REVIEW_REQUIRED" in result.worktrees[0].codes
    assert not marker.exists()


def test_actual_git_active_filter_attribute_blocks_even_without_a_configured_driver(disposable_git):
    root, _ = disposable_git
    (root / ".gitattributes").write_text("tracked.txt filter=unconfigured-fixture\n", encoding="utf-8")
    result = workspace.discover_workspaces(root)
    assert result.status == "BLOCKED" and result.worktrees[0].dirty is None
    assert "GIT_FILTER_OR_PROMISOR_REVIEW_REQUIRED" in result.worktrees[0].codes


@pytest.mark.parametrize("bare", [False, True])
def test_unborn_or_bare_worktree_does_not_invent_a_verified_head_or_clean_state(candidate, bare):
    root, _, common, _ = candidate
    runner = SyntheticGit([root], common, listing=_record(root, head="0" * 40, bare=bare))
    result = workspace.discover_workspaces(root, runner=runner)
    assert result.status == "BLOCKED" and result.head is None
    assert result.worktrees[0].head is None
    assert result.worktrees[0].dirty is (None if bare else False)
    assert ("GIT_BARE_WORKTREE" if bare else "GIT_HEAD_UNVERIFIED") in result.worktrees[0].codes


@pytest.mark.skipif(os.name == "nt", reason="Windows filenames cannot contain newline characters")
def test_actual_git_porcelain_handles_newline_worktree_paths(disposable_git, tmp_path):
    root, git = disposable_git
    linked = tmp_path / "actual linked\ncheckout"
    git("worktree", "add", "--quiet", "--detach", str(linked))
    result = workspace.discover_workspaces(root)
    assert result.status == "PASS"
    observed = next(item for item in result.worktrees if item.root == linked.resolve())
    assert observed.detached is True and observed.branch is None and observed.dirty is False
