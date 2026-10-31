"""Public launcher integration with synthetic Git observations, no data services."""

from __future__ import annotations

import io
import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev, dev_workspace
from scripts import dev_workspace_cli as cli


@pytest.fixture
def checkout(tmp_path, monkeypatch):
    root = tmp_path.resolve() / "checkout"
    if sys.platform == "win32":
        from scripts.dev_instance_storage import _windows_create

        _windows_create(root)  # Brand-new synthetic anchor; no existing ACL changes.
    else:
        root.mkdir(mode=0o700)
    (root / "frontend").mkdir()
    (root / "scripts").mkdir()
    for name in ("requirements.txt", "frontend/package.json", "frontend/package-lock.json"):
        (root / name).write_text("public-synthetic-manifest", encoding="utf-8")
    for name in cli._CONTROLLER_SOURCES:
        (root / name).write_text("public-synthetic-controller", encoding="utf-8")
    monkeypatch.setattr(cli.Path, "home", classmethod(lambda cls: root))
    identity = dev_workspace.FilesystemIdentity(root, root.stat().st_dev, root.stat().st_ino)
    row = dev_workspace.WorktreeSnapshot(
        "b" * 64, root, identity, "c" * 40, "refs/heads/feature/SBO-101-fixture", False, False, False, False, False
    )
    snapshot = dev_workspace.RepositorySnapshot("a" * 64, root, identity, "c" * 40, (row,), identity)
    discover = Mock(return_value=snapshot)
    monkeypatch.setattr(dev_workspace, "discover_workspaces", discover)
    return SimpleNamespace(root=root, snapshot=snapshot, discover=discover)


@pytest.mark.parametrize("command", ["list", "status", "diagnose"])
def test_readonly_inventory_has_no_registry_lock_private_read_or_mutation(checkout, monkeypatch, capsys, command):
    forbidden = Mock(side_effect=AssertionError("Read-only command mutated or read private material"))
    monkeypatch.setattr(cli.dev_instance_registry.InstanceRegistry, "publish", forbidden)
    monkeypatch.setattr(os, "mkdir", forbidden)
    monkeypatch.setattr(cli.dev_environment, "bounded_read_bytes", forbidden)
    assert cli.run_cli([command, "--json"], checkout.root) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["registry_codes"] == ["REGISTRY_MISSING"]
    assert result["worktrees"][0]["runtime_ownership"] == "UNVERIFIED"
    assert result["worktrees"][0]["agent_owner"] == "UNKNOWN"
    assert not (checkout.root / ".sbom-dev").exists()
    forbidden.assert_not_called()


def test_plan_requires_no_private_configuration_and_remains_deterministic(checkout, monkeypatch, capsys):
    original = cli.dev_environment.bounded_read_bytes
    paths = []

    def public_only(path, limit):
        assert path.name in {
            "requirements.txt",
            "package.json",
            "package-lock.json",
            *(name.rsplit("/", 1)[-1] for name in cli._CONTROLLER_SOURCES),
        }
        paths.append(path)
        return original(path, limit)

    monkeypatch.setattr(cli.dev_environment, "bounded_read_bytes", public_only)
    args = ["plan", "--mode", "isolated", "--auth", "native", "--json"]
    assert cli.run_cli(args, checkout.root) == 1
    first = json.loads(capsys.readouterr().out)
    assert cli.run_cli(args, checkout.root) == 1
    second = json.loads(capsys.readouterr().out)
    assert first == second and first["descriptor"]["configuration_present"] is False
    dependency = next(action for action in first["actions"] if action["code"] == "prepare-dependencies")
    assert dependency["requires_configuration"] is False
    assert not (checkout.root / ".sbom-dev").exists() and len(paths) == 18


def test_plan_does_not_select_authentication_implicitly(checkout, capsys):
    assert cli.run_cli(["plan", "--mode", "isolated", "--json"], checkout.root) == 1
    assert json.loads(capsys.readouterr().out)["code"] == "WORKSPACE_MODE_AUTH_SELECTION_REQUIRED"


def test_unlisted_worktree_cannot_receive_plan(checkout, tmp_path, capsys):
    other = tmp_path / "other"
    other.mkdir()
    assert (
        cli.run_cli(["plan", "--worktree", str(other), "--mode", "mock", "--auth", "native", "--json"], checkout.root)
        == 1
    )
    assert json.loads(capsys.readouterr().out)["code"] == "WORKSPACE_TARGET_BLOCKED"


def test_noninteractive_registry_preparation_never_creates_state(checkout, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO())
    assert cli.run_cli(["prepare", "--scope", "registry", "--mode", "mock", "--auth", "native"], checkout.root) == 1
    assert "WORKSPACE_REGISTRY_APPROVAL_REQUIRED" in capsys.readouterr().out
    assert not (checkout.root / ".sbom-dev").exists()


@pytest.mark.parametrize("changed", ["requirements.txt", "scripts/dev_instance_registry.py"])
def test_changed_manifest_during_consent_invalidates_before_directory_creation(checkout, monkeypatch, capsys, changed):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)

    def approve(prompt):
        (checkout.root / changed).write_text("changed-public-manifest", encoding="utf-8")
        return prompt.split("Type ", 1)[1].removesuffix(": ")

    monkeypatch.setattr("builtins.input", approve)
    assert cli.run_cli(["prepare", "--scope", "registry", "--mode", "mock", "--auth", "native"], checkout.root) == 1
    assert "WORKSPACE_PLAN_CHANGED" in capsys.readouterr().out
    assert not (checkout.root / ".sbom-dev").exists()


def test_registry_consent_records_only_public_metadata_and_starts_nothing(checkout, monkeypatch, capsys):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: prompt.split("Type ", 1)[1].removesuffix(": "))
    forbidden = Mock(side_effect=AssertionError("Registry preparation attempted application/resource mutation"))
    for name in ("ensure_database", "start_process", "start_background", "ensure_dependencies", "ensure_frontend"):
        monkeypatch.setattr(dev, name, forbidden)
    assert cli.run_cli(["prepare", "--scope", "registry", "--mode", "mock", "--auth", "native"], checkout.root) == 0
    assert "WORKSPACE_REGISTRY_PREPARED" in capsys.readouterr().out
    rows = tuple(cli._registry(checkout.snapshot).root.glob("*.json"))
    assert len(rows) == 1
    record = json.loads(rows[0].read_text())
    assert record["operations"] == ["REGISTRY_PREPARED"]
    assert record["descriptor"]["live_operations_authorized"] is False
    assert "environment" not in record and "password" not in record
    forbidden.assert_not_called()


def test_invalid_arguments_do_not_echo_secret_values(checkout, capsys):
    with pytest.raises(SystemExit) as caught:
        cli.run_cli(["plan", "--password", "synthetic-private-never-echo"], checkout.root)
    assert caught.value.code == 2
    output = capsys.readouterr()
    assert "synthetic-private-never-echo" not in output.out + output.err


@pytest.mark.parametrize(
    "arguments",
    [
        ["--auth", "synthetic-private-never-echo"],
        ["--generation", "synthetic-private-never-echo"],
        ["--port-min", "synthetic-private-never-echo"],
    ],
)
def test_invalid_choices_and_types_withhold_values(checkout, capsys, arguments):
    with pytest.raises(SystemExit) as caught:
        cli.run_cli(["plan", *arguments], checkout.root)
    assert caught.value.code == 2
    captured = capsys.readouterr()
    assert "synthetic-private-never-echo" not in captured.out + captured.err


@pytest.mark.parametrize("command", ["list", "status", "diagnose"])
def test_readonly_target_must_be_listed(checkout, tmp_path, capsys, command):
    other = tmp_path / "unlisted"
    other.mkdir()
    assert cli.run_cli([command, "--worktree", str(other), "--json"], checkout.root) == 1
    assert json.loads(capsys.readouterr().out)["code"] == "WORKSPACE_TARGET_BLOCKED"


def test_manifest_ancestors_cannot_redirect_reads_outside_worktree(checkout, tmp_path, monkeypatch, capsys):
    external = tmp_path / "outside"
    external.mkdir()
    for name in ("package.json", "package-lock.json"):
        (external / name).write_text("synthetic-private-never-read", encoding="utf-8")
    frontend = checkout.root / "frontend"
    for path in frontend.iterdir():
        path.unlink()  # Only these two synthetic files, before a fixture link exists.
    frontend.rmdir()
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(external), str(frontend))
    else:
        frontend.symlink_to(external, target_is_directory=True)
    read = cli.dev_environment.bounded_read_bytes

    def observed(path, limit):
        assert path.name == "requirements.txt", "Read outside the selected checkout"
        return read(path, limit)

    monkeypatch.setattr(cli.dev_environment, "bounded_read_bytes", observed)
    try:
        assert cli.run_cli(["plan", "--mode", "mock", "--auth", "native", "--json"], checkout.root) == 1
        assert json.loads(capsys.readouterr().out)["code"] == "WORKSPACE_PUBLIC_MANIFEST_UNVERIFIED"
        assert (external / "package.json").read_text() == "synthetic-private-never-read"
    finally:
        if sys.platform == "win32":
            os.rmdir(frontend)  # Verified fixture junction entry only; never its target.
        else:
            frontend.unlink()


def test_existing_private_or_runtime_state_keeps_legacy_dispatch(tmp_path):
    assert cli.fresh_checkout(tmp_path)
    (tmp_path / ".dev-runtime.json").write_text("unknown-owned-record-preserve", encoding="utf-8")
    assert not cli.fresh_checkout(tmp_path)
    assert (tmp_path / ".dev-runtime.json").read_text() == "unknown-owned-record-preserve"


@pytest.mark.parametrize("marker", [".sbom-workspace-dependencies.json", ".sbom-workspace-dependency-attempt"])
def test_dependency_only_or_interrupted_new_setup_still_gets_inventory(tmp_path, marker):
    (tmp_path / ".venv").mkdir()
    assert not cli.fresh_checkout(tmp_path)  # Existing unmanaged behavior.
    (tmp_path / ".venv" / marker).write_text("public marker", encoding="utf-8")
    assert cli.fresh_checkout(tmp_path)
    (tmp_path / ".env.dev.local").write_text("private-synthetic-not-read", encoding="utf-8")
    assert not cli.fresh_checkout(tmp_path)


def test_workspace_dispatch_precedes_old_parser_and_runtime(checkout, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["scripts/dev.py", "workspace", "list"])
    monkeypatch.setattr(dev, "ROOT", checkout.root)
    forbidden = Mock(side_effect=AssertionError("Workspace command entered mutable legacy lifecycle"))
    monkeypatch.setattr(dev, "parse_args", forbidden)
    monkeypatch.setattr(dev, "Runtime", forbidden)
    assert dev.main() == 0
    forbidden.assert_not_called()


def _fixture_index_hashes(paths):
    import hashlib

    return {path: (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns) for path in paths}


@pytest.fixture
def dependency_inspection(checkout, monkeypatch):
    from scripts import dev_workspace_dependencies as dependencies

    plan = SimpleNamespace(
        fingerprint="d" * 64,
        actions=("prepare-python", "prepare-frontend"),
        blockers=(),
        tool_versions={"python": (3, 12, 10), "node": (26, 1, 0)},
    )
    inspect = Mock(return_value=plan)
    prepare = Mock(side_effect=AssertionError("CLI reached installer without consent"))
    monkeypatch.setattr(dependencies, "inspect_dependencies", inspect)
    monkeypatch.setattr(dependencies, "prepare_dependencies", prepare)
    return SimpleNamespace(module=dependencies, plan=plan, inspect=inspect, prepare=prepare)


def test_dependency_plan_is_independent_of_private_configuration(checkout, dependency_inspection, monkeypatch, capsys):
    original = cli.dev_environment.bounded_read_bytes

    def public_only(path, *args, **kwargs):
        assert path.name not in {".env", ".env.dev.local", ".env.local"}
        return original(path, *args, **kwargs)

    monkeypatch.setattr(cli.dev_environment, "bounded_read_bytes", public_only)
    assert cli.run_cli(["plan", "--scope", "dependencies", "--json"], checkout.root) == 0
    public = json.loads(capsys.readouterr().out)
    assert public["private_configuration_required"] is False
    assert public["category"] == "software-dependencies"
    assert public["actions"] == ["prepare-python", "prepare-frontend"]
    assert dependency_inspection.inspect.call_args.args == (checkout.snapshot, checkout.snapshot.worktrees[0])
    dependency_inspection.prepare.assert_not_called()


def test_dependency_noninteractive_preparation_requires_consent(checkout, dependency_inspection, monkeypatch, capsys):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    assert cli.run_cli(["prepare", "--scope", "dependencies"], checkout.root) == 1
    assert "WORKSPACE_DEPENDENCY_APPROVAL_REQUIRED" in capsys.readouterr().out
    dependency_inspection.prepare.assert_not_called()


@pytest.mark.parametrize("changed", [False, True])
def test_dependency_consent_revalidates_before_installer(checkout, dependency_inspection, monkeypatch, capsys, changed):
    args = cli._parser().parse_args(["prepare", "--scope", "dependencies"])
    _, public = cli._dependency_plan(args, checkout.root)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)

    def confirm(prompt):
        if changed:
            (checkout.root / "requirements.txt").write_text("changed-public-manifest", encoding="utf-8")
        return "DEPENDENCIES " + public["fingerprint"]

    monkeypatch.setattr("builtins.input", confirm)
    entered = []

    def prepare(plan, *, authorize):
        assert authorize(plan) is True
        entered.append("synthetic-only")
        return dependency_inspection.module.DependencyOutcome("DEPENDENCIES_PREPARED", 0, ("python", "frontend"))

    dependency_inspection.prepare.side_effect = prepare
    assert cli.run_cli(["prepare", "--scope", "dependencies"], checkout.root) == (1 if changed else 0)
    assert entered == ([] if changed else ["synthetic-only"])
    if changed:
        assert "DEPENDENCY_PLAN_CHANGED" in capsys.readouterr().out
    assert not (checkout.root / ".dev-runtime.json").exists()


def test_expired_dependency_consent_never_calls_installer(checkout, dependency_inspection, monkeypatch, capsys):
    args = cli._parser().parse_args(["prepare", "--scope", "dependencies"])
    _, public = cli._dependency_plan(args, checkout.root)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
    moment = [0.0]
    monkeypatch.setattr(cli.time, "monotonic", lambda: moment[0])

    def confirm(prompt):
        moment[0] = 121.0
        return "DEPENDENCIES " + public["fingerprint"]

    monkeypatch.setattr("builtins.input", confirm)
    assert cli.run_cli(["prepare", "--scope", "dependencies"], checkout.root) == 1
    assert "WORKSPACE_DEPENDENCY_APPROVAL_REQUIRED" in capsys.readouterr().out
    dependency_inspection.prepare.assert_not_called()


def test_actual_two_git_worktrees_register_independent_public_instances_without_starting_resources(
    tmp_path, monkeypatch, capsys
):
    import builtins
    import shutil
    import socket
    import subprocess
    from pathlib import Path

    from scripts import dev_instance_storage

    git = shutil.which("git")
    if git is None:
        pytest.skip("Disposable Git/registry acceptance requires existing Git; no installation is permitted")
    anchor = tmp_path.resolve() / "private-workspace-registry-fixture"
    if sys.platform == "win32":
        dev_instance_storage._windows_create(anchor)
    else:
        anchor.mkdir(mode=0o700)
    root, linked = anchor / "controller checkout", anchor / "candidate checkout"
    if sys.platform == "win32":
        dev_instance_storage._windows_create(root)
        dev_instance_storage._windows_create(root / ".git")
    else:
        root.mkdir(mode=0o700)
        (root / ".git").mkdir(mode=0o700)
    (root / "frontend").mkdir()
    (root / "scripts").mkdir()
    (root / "requirements.txt").write_text("# Disposable public dependency manifest\n", encoding="utf-8")
    package = {"name": "workspace-registry-fixture", "private": True}
    (root / "frontend/package.json").write_text(json.dumps(package), encoding="utf-8")
    (root / "frontend/package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": {"": package}}), encoding="utf-8"
    )
    controller = Path(dev.__file__).resolve().parents[1]
    for name in cli._CONTROLLER_SOURCES:
        (root / name).write_bytes((controller / name).read_bytes())
    environment = dict(dev_workspace._environment())

    def fixture_git(*arguments, cwd=root):
        completed = subprocess.run(
            [
                git,
                "--no-pager",
                "--no-optional-locks",
                "-c",
                "core.hooksPath=" + os.devnull,
                "-c",
                "core.fsmonitor=false",
                "-c",
                "submodule.recurse=false",
                "-c",
                "protocol.allow=never",
                "-c",
                "commit.gpgSign=false",
                *arguments,
            ],
            cwd=cwd,
            env=environment,
            capture_output=True,
            timeout=15,
        )
        assert completed.returncode == 0, "Disposable Git fixture setup failed; output withheld"
        return completed.stdout

    fixture_git("-c", "init.templateDir=", "init", "--quiet", "--initial-branch=main")
    fixture_git("add", "--", "requirements.txt", "frontend", "scripts")
    fixture_git(
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@localhost.invalid",
        "commit",
        "--quiet",
        "--no-gpg-sign",
        "-m",
        "Disposable public controller fixture",
    )
    fixture_git("worktree", "add", "--quiet", "-b", "feature/disposable-candidate", str(linked))
    indexes = tuple(
        Path(os.fsdecode(fixture_git("rev-parse", "--path-format=absolute", "--git-path", "index", cwd=path)[:-1]))
        for path in (root, linked)
    )
    before = _fixture_index_hashes(indexes)
    original_popen, original_import = subprocess.Popen, builtins.__import__
    expected_git = os.path.normcase(str(Path(git).resolve()))
    forbidden = Mock(side_effect=AssertionError("Public registry acceptance reached an application/provider operation"))

    def only_git(command, *arguments, **keywords):
        assert isinstance(command, tuple)
        assert os.path.normcase(str(Path(command[0]).resolve())) == expected_git
        assert keywords.get("shell") is False
        return original_popen(command, *arguments, **keywords)

    def no_application_import(name, *arguments, **keywords):
        assert name != "app" and not name.startswith("app.")
        assert name.split(".", 1)[0] not in {"psycopg", "sqlalchemy", "redis"}
        return original_import(name, *arguments, **keywords)

    consents = []

    def approve_public_registry(prompt):
        assert prompt.startswith("Only public registry metadata will be written.")
        response = prompt.split("Type ", 1)[1].removesuffix(": ")
        consents.append(response)
        return response

    with monkeypatch.context() as boundary:
        boundary.setattr(Path, "home", classmethod(lambda cls: anchor))
        boundary.setattr(subprocess, "Popen", only_git)
        boundary.setattr(builtins, "__import__", no_application_import)
        boundary.setattr(builtins, "input", approve_public_registry)
        boundary.setattr(sys.stdin, "isatty", lambda: True)
        boundary.setattr(sys.stdout, "isatty", lambda: True)
        boundary.setattr(socket, "socket", forbidden)
        boundary.setattr(socket, "create_connection", forbidden)
        for name in (
            "Runtime",
            "ensure_database",
            "start_process",
            "start_background",
            "ensure_dependencies",
            "ensure_frontend",
        ):
            boundary.setattr(dev, name, forbidden)
        observed = dev_workspace.discover_workspaces(root)
        assert observed.status == "PASS" and len(observed.worktrees) == 2
        assert len({item.worktree_id for item in observed.worktrees}) == 2
        for selected in (root, linked):
            assert (
                cli.run_cli(
                    [
                        "prepare",
                        "--scope",
                        "registry",
                        "--worktree",
                        str(selected),
                        "--mode",
                        "isolated",
                        "--auth",
                        "native",
                    ],
                    root,
                )
                == 0
            )
            assert "WORKSPACE_REGISTRY_PREPARED" in capsys.readouterr().out
        records = cli._registry(observed).read()
        assert records.codes == () and len(records.entries) == 2
        descriptors = tuple(entry.descriptor for entry in records.entries)
        first, second = descriptors
        assert first.repository_id == second.repository_id == observed.repository_id
        assert {item.worktree_id for item in descriptors} == {item.worktree_id for item in observed.worktrees}
        assert first.instance_id != second.instance_id and first.origin != second.origin
        assert not set(first.ports.values()) & set(second.ports.values())
        assert not set(first.resources.values()) & set(second.resources.values())
        assert all(not item.ownership_verified and not item.live_operations_authorized for item in descriptors)
        assert all(entry.state == "PLANNED" and entry.operations == ("REGISTRY_PREPARED",) for entry in records.entries)
        assert len(set(consents)) == 2
        boundary.setattr(cli.dev_instance_registry.InstanceRegistry, "publish", forbidden)
        boundary.setattr(dev_instance_storage, "initialize_private_directory", forbidden)
        assert cli.run_cli(["list", "--json"], root) == 0
        inventory = json.loads(capsys.readouterr().out)
        assert inventory["repository_id"] == observed.repository_id and len(inventory["worktrees"]) == 2
        assert {item["instance_id"] for item in inventory["worktrees"]} == {item.instance_id for item in descriptors}
        assert all(
            item["agent_owner"] == "UNKNOWN" and item["runtime_ownership"] == "UNVERIFIED"
            for item in inventory["worktrees"]
        )
        forbidden.assert_not_called()
    assert _fixture_index_hashes(indexes) == before
    assert not (root / ".dev-runtime.json").exists() and not (linked / ".dev-runtime.json").exists()
