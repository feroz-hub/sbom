"""Synthetic installers only: never execute pip/npm, import the app or use a DB."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev_workspace
from scripts import dev_workspace_dependencies as dependencies

SECRET = "synthetic-backend-credential-never-output"


def private_directory(path):
    if sys.platform == "win32":
        dependencies.dev_instance_storage._windows_create(path)
    else:
        path.mkdir(mode=0o700)


class SyntheticInstaller:
    def __init__(self, candidate):
        self.candidate, self.calls, self.failure = candidate, [], None
        self.npm_version = "11.6.0"
        self.on_install = None

    def __call__(self, command, **options):
        assert isinstance(command, tuple)
        assert options["input_bytes"] is None
        assert SECRET not in repr(dict(options["environment"]))
        assert "NODE_OPTIONS" not in options["environment"] and "PYTHONPATH" not in options["environment"]
        self.calls.append((command, options))
        result = dev_workspace.CommandResult
        if len(command) > 2 and Path(command[1]).name == "npm-cli.js":
            user = Path(options["environment"]["NPM_CONFIG_USERCONFIG"])
            global_config = Path(options["environment"]["NPM_CONFIG_GLOBALCONFIG"])
            assert user != global_config and user.read_bytes() == global_config.read_bytes() == b""
            assert "--prefix" in command
        if "list(sys.version_info[:3])" in command[-1]:
            return result(0, b"[3, 12, 7]")
        if command[-1] == "--version":
            return result(0, ("v26.1.0" if len(command) == 2 else self.npm_version).encode())
        if "venv" in command:
            assert "--copies" in command
            target = Path(command[-1])
            folder = target / ("Scripts" if os.name == "nt" else "bin")
            private_directory(folder)
            (folder / ("python.exe" if os.name == "nt" else "python")).write_bytes(b"synthetic-venv-python")
            (target / "pyvenv.cfg").write_text("include-system-site-packages = false\n", encoding="utf-8")
            return result(0)
        if "install" in command:
            assert "--only-binary=:all:" in command and "--isolated" in command
            assert "--no-cache-dir" in command and "--index-url=https://pypi.org/simple" in command
            copied = Path(command[-1])
            assert copied.read_bytes() == (self.candidate.root / "requirements.txt").read_bytes()
            if self.on_install:
                self.on_install()
            return result(1, stderr=SECRET.encode()) if self.failure == "pip-install" else result(0)
        if command[-1] == "check":
            return result(1, stderr=SECRET.encode()) if self.failure == "pip-check" else result(0, b"No broken requirements found.")
        if "-c" in command:
            return result(0, json.dumps({"prefix": str(self.candidate.root / ".venv"), "version": [3, 12, 7],
                                         "packages": json.loads(command[-2]), "required": True}).encode())
        if "ci" in command:
            assert {"--ignore-scripts", "--no-audit", "--no-fund"} <= set(command)
            assert {"--registry=https://registry.npmjs.org/", "--strict-ssl=true"} <= set(command)
            project = Path(command[command.index("--prefix") + 1])
            assert project != self.candidate.root / "frontend"
            assert not (project / ".env").exists() and not (project / ".npmrc").exists()
            assert (project / "package.json").read_bytes() == (self.candidate.root / "frontend/package.json").read_bytes()
            if self.failure == "npm-install":
                return result(1, stderr=SECRET.encode())
            modules = project / "node_modules"
            private_directory(modules)
            package = modules / "next"
            private_directory(package)
            (package / "package.json").write_text('{"version":"16.3.4"}', encoding="utf-8")
            return result(0)
        if "-e" in command:
            target = Path(command[-2])
            return result(0, json.dumps({"version": "26.1.0", "packages": {
                name: json.loads((target / name / "package.json").read_bytes())["version"]
                for name in json.loads(command[-1])
            }}).encode())
        raise AssertionError("Unexpected synthetic installer operation")


@pytest.fixture
def candidate(tmp_path_factory, monkeypatch):
    base = tmp_path_factory.mktemp("deps").resolve() / "fixture with spaces"
    private_directory(base)
    root, home, tools = base / "checkout", base / "home", base / "tools"
    for path in (root, home, tools, root / "frontend", root / ".git"):
        private_directory(path)
    (root / "requirements.txt").write_text("demo==1.2.3\n", encoding="utf-8")
    package = {"dependencies": {"next": "16.3.4"}}
    lock = {"lockfileVersion": 3, "packages": {"": package, "node_modules/next": {
        "version": "16.3.4", "resolved": "https://registry.npmjs.org/next/-/next-16.3.4.tgz",
        "integrity": "sha512-" + base64.b64encode(b"x" * 64).decode(),
    }}}
    (root / "frontend/package.json").write_text(json.dumps(package), encoding="utf-8")
    (root / "frontend/package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    private_directory(tools / "npm")
    private_directory(tools / "npm/bin")
    paths = {"python_executable": tools / "python.exe", "node_executable": tools / "node.exe", "npm_cli": tools / "npm/bin/npm-cli.js"}
    for path in paths.values():
        path.write_bytes(b"synthetic-public-tool:" + path.name.encode())
    identity, common = dev_workspace._identity(root), dev_workspace._identity(root / ".git")
    selected = dev_workspace.WorktreeSnapshot("b" * 64, root, identity, "c" * 40, "refs/heads/fixture", False, False, False, False, False)
    snapshot = dev_workspace.RepositorySnapshot("a" * 64, root, identity, selected.head, (selected,), common)
    fixture = SimpleNamespace(root=root, home=home, tools=paths, selected=selected, snapshot=snapshot,
                              npmrc=tools / "npm/npmrc")
    fixture.runner = SyntheticInstaller(fixture)
    monkeypatch.setattr(dev_workspace, "discover_workspaces", lambda path: snapshot)
    forbidden = Mock(side_effect=AssertionError("Synthetic dependency test attempted a real subprocess"))
    monkeypatch.setattr(dev_workspace, "_run_git", forbidden)
    fixture.forbidden = forbidden
    return fixture


def inspect(candidate, **options):
    return dependencies.inspect_dependencies(candidate.snapshot, candidate.selected, runner=candidate.runner,
                                            state_anchor=candidate.home, **candidate.tools, **options)


def test_inspection_is_immutable_readonly_and_independent_of_private_environment(candidate, monkeypatch):
    for path in (candidate.root / ".env", candidate.root / "frontend/.env.local", candidate.root / "frontend/.npmrc"):
        path.write_text(SECRET, encoding="utf-8")
    read = dependencies.dev_environment.bounded_read_bytes

    def public_only(path, limit):
        assert not path.name.startswith(".env") and path.name != ".npmrc"
        return read(path, limit)

    monkeypatch.setattr(dependencies.dev_environment, "bounded_read_bytes", public_only)
    original_open = os.open

    def no_private_open(path, *arguments, **keywords):
        assert not Path(path).name.startswith(".env") and Path(path).name != ".npmrc"
        return original_open(path, *arguments, **keywords)

    monkeypatch.setattr(os, "open", no_private_open)
    monkeypatch.setenv("DATABASE_URL", SECRET)
    monkeypatch.setenv("PIP_INDEX_URL", SECRET)
    monkeypatch.setenv("NODE_OPTIONS", SECRET)
    plan = inspect(candidate)
    assert not plan.blockers and plan.actions == ("prepare-python", "prepare-frontend")
    assert SECRET not in repr(plan) and SECRET not in json.dumps(plan.to_dict())
    assert not (candidate.root / ".venv").exists() and not (candidate.home / ".sbom-dev").exists()
    with pytest.raises(FrozenInstanceError):
        plan.actions = ()
    with pytest.raises(TypeError):
        plan.manifest_hashes["requirements.txt"] = "changed"
    assert not plan.to_dict()["compiler_verified"]


def test_approval_decline_and_manifest_drift_precede_every_mutation(candidate):
    plan = inspect(candidate)
    outcome = dependencies.prepare_dependencies(plan, authorize=lambda value: False, runner=candidate.runner)
    assert outcome.code == "DEPENDENCY_APPROVAL_REQUIRED" and not outcome.artifacts_retained
    assert not (candidate.home / ".sbom-dev").exists()

    def approve(value):
        (candidate.root / "requirements.txt").write_text("demo==9.9.9\n", encoding="utf-8")
        return True

    outcome = dependencies.prepare_dependencies(plan, authorize=approve, runner=candidate.runner)
    assert outcome.code == "DEPENDENCY_MANIFEST_CHANGED" and not outcome.artifacts_retained
    assert not (candidate.root / ".venv").exists()


def test_fresh_install_uses_only_synthetic_safe_commands_and_reuse_requires_live_verification(candidate):
    plan = inspect(candidate)
    outcome = dependencies.prepare_dependencies(plan, authorize=lambda value: value.fingerprint == plan.fingerprint,
                                              runner=candidate.runner)
    assert outcome.exit_code == 0 and outcome.prepared == ("python", "frontend") and not outcome.compiler_verified
    assert outcome.code == "DEPENDENCIES_PREPARED_COMPILER_NOT_VERIFIED"
    for _command, options in candidate.runner.calls:
        assert 0 < options["timeout"] <= 600 and options["max_output"] == 262144
        assert "PYTHONPATH" not in options["environment"] and "NODE_OPTIONS" not in options["environment"]
    newer = inspect(candidate)
    assert not newer.blockers and newer.actions == ("verify-python", "verify-frontend")
    candidate.runner.calls.clear()
    again = dependencies.prepare_dependencies(newer, authorize=lambda value: True, runner=candidate.runner)
    assert again.exit_code == 0 and again.skipped == ("python", "frontend") and not again.prepared
    assert any(command[-1] == "check" for command, _ in candidate.runner.calls)
    assert not any("install" in command or "ci" in command or "venv" in command for command, _ in candidate.runner.calls)
    candidate.forbidden.assert_not_called()


@pytest.mark.parametrize("failure", ["pip-install", "pip-check", "npm-install"])
def test_failure_retains_partial_artifacts_and_never_prints_installer_secrets(candidate, capsys, failure):
    candidate.runner.failure = failure
    outcome = dependencies.prepare_dependencies(inspect(candidate), authorize=lambda value: True, runner=candidate.runner)
    assert outcome.exit_code == 1 and outcome.artifacts_retained
    assert SECRET not in repr(outcome) and SECRET not in capsys.readouterr().out
    assert not (candidate.root / "frontend/node_modules" / dependencies._STAMP).exists()
    if failure != "npm-install":
        assert not (candidate.root / ".venv" / dependencies._STAMP).exists()
    assert inspect(candidate).blockers  # No automatic adoption/retry of partial targets.


@pytest.mark.parametrize("relative", [".venv", "frontend/node_modules"])
def test_existing_unknown_targets_are_preserved_without_installation(candidate, relative):
    target = candidate.root / relative
    private_directory(target)
    marker = target / "unknown-owned-data"
    marker.write_text("preserve", encoding="utf-8")
    plan = inspect(candidate)
    assert "DEPENDENCY_EXISTING_ARTIFACT_REVIEW_REQUIRED" in plan.blockers
    approval = Mock(side_effect=AssertionError("Blocked plan requested consent"))
    outcome = dependencies.prepare_dependencies(plan, authorize=approval, runner=candidate.runner)
    assert outcome.code == "DEPENDENCY_PLAN_BLOCKED" and marker.read_text() == "preserve"


def test_tool_and_controller_drift_abort_before_installation(candidate, monkeypatch):
    plan = inspect(candidate)
    original = dependencies._file

    def changed_controller(path, root, limit=8388608):
        proof = original(path, root, limit)
        if path.name == "dev_workspace_dependencies.py":
            proof[-1] = "0" * 64
        return proof

    monkeypatch.setattr(dependencies, "_file", changed_controller)
    outcome = dependencies.prepare_dependencies(plan, authorize=lambda value: True, runner=candidate.runner)
    assert outcome.code == "DEPENDENCY_CONTROLLER_CHANGED" and not outcome.artifacts_retained
    assert not (candidate.root / ".venv").exists()


@pytest.mark.parametrize("policy", ["local-tarball", "git-package", "workspace-link"])
def test_npm_nonregistry_or_link_sources_are_blocked_without_install(candidate, policy):
    path = candidate.root / "frontend/package-lock.json"
    data = json.loads(path.read_bytes())
    record = data["packages"]["node_modules/next"]
    record.update({"resolved": {"local-tarball": "file:../../private.tgz", "git-package": "git+ssh://example.invalid/private", "workspace-link": "https://registry.npmjs.org/next/-/next.tgz"}[policy]})
    if policy == "workspace-link":
        record["link"] = True
    path.write_text(json.dumps(data), encoding="utf-8")
    plan = inspect(candidate)
    assert "DEPENDENCY_NPM_LOCK_POLICY_REQUIRED" in plan.blockers
    assert candidate.runner.calls == []


@pytest.mark.parametrize("requirements", ["-r ../private.txt\n", "demo @ https://user:secret@example.invalid/demo.whl\n", "demo>=1\n"])
def test_unpinned_or_external_python_requirements_are_blocked(candidate, requirements):
    (candidate.root / "requirements.txt").write_text(requirements, encoding="utf-8")
    plan = inspect(candidate)
    assert "DEPENDENCY_PINNED_BINARY_REQUIREMENTS_REQUIRED" in plan.blockers
    assert candidate.runner.calls == []


@pytest.mark.parametrize("empty", [False, True])
def test_no_replace_directory_publication_preserves_unexpected_destination(candidate, empty):
    source, target = candidate.root / "new-result", candidate.root / "unknown-result"
    private_directory(source)
    private_directory(target)
    marker = target / "preserve"
    if not empty:
        marker.write_text("unknown", encoding="utf-8")
    identity = (target.stat().st_dev, target.stat().st_ino)
    with pytest.raises(dependencies.DependencyError, match="^DEPENDENCY_EXCLUSIVE_PUBLICATION_REQUIRED$"):
        dependencies._publish_directory(source, target)
    assert source.is_dir() and (target.stat().st_dev, target.stat().st_ino) == identity
    assert list(target.iterdir()) == ([] if empty else [marker])


def test_npm_version_changes_are_refused_before_skip(candidate):
    assert dependencies.prepare_dependencies(inspect(candidate), authorize=lambda value: True, runner=candidate.runner).exit_code == 0
    plan = inspect(candidate)
    candidate.runner.npm_version = "11.7.0"
    outcome = dependencies.prepare_dependencies(plan, authorize=lambda value: True, runner=candidate.runner)
    assert outcome.code == "DEPENDENCY_TOOL_VERSION_CHANGED" and outcome.skipped == ("python",)
    assert "DEPENDENCY_PREVIOUS_ATTEMPT_REVIEW_REQUIRED" in inspect(candidate).blockers


def test_stamps_detect_owned_target_tree_tampering(candidate):
    assert dependencies.prepare_dependencies(inspect(candidate), authorize=lambda value: True, runner=candidate.runner).exit_code == 0
    (candidate.root / "frontend/node_modules/next/package.json").write_text('{"version":"0.0.0"}', encoding="utf-8")
    assert "DEPENDENCY_EXISTING_ARTIFACT_REVIEW_REQUIRED" in inspect(candidate).blockers


def test_unsafe_root_access_is_actionable_before_tool_probes_or_consent(candidate, monkeypatch):
    verify = dependencies.dev_instance_storage._verify

    def unsafe(path, *, private):
        if path == candidate.root:
            raise dependencies.dev_instance_storage.DirectoryInitializationError("INSTANCE_DIRECTORY_ACCESS_UNVERIFIED")
        return verify(path, private=private)

    monkeypatch.setattr(dependencies.dev_instance_storage, "_verify", unsafe)
    assert inspect(candidate).blockers == ("DEPENDENCY_ROOT_ACCESS_REVIEW_REQUIRED",)
    assert candidate.runner.calls == []


def test_linked_dependency_root_is_protected_from_adoption(candidate):
    external = candidate.home / "other-worktree-venv"
    private_directory(external)
    (external / "preserve").write_text("outside", encoding="utf-8")
    link = candidate.root / ".venv"
    if os.name == "nt":
        import _winapi

        _winapi.CreateJunction(str(external), str(link))
    else:
        link.symlink_to(external, target_is_directory=True)
    try:
        assert inspect(candidate).blockers
        assert (external / "preserve").read_text() == "outside"
    finally:
        if os.name == "nt":
            os.rmdir(link)  # Only this exact test-created junction entry.
        else:
            link.unlink()


def test_current_public_manifests_fit_the_conservative_installer_policy():
    root = Path(dependencies.__file__).resolve().parents[1]
    assert dependencies._requirements((root / "requirements.txt").read_bytes())
    packages = dependencies._node_packages(
        json.loads((root / "frontend/package.json").read_bytes()),
        json.loads((root / "frontend/package-lock.json").read_bytes()),
    )
    assert "next" in packages


@pytest.mark.parametrize("remove", ["resolved", "integrity"])
def test_partial_registry_artifact_metadata_is_blocked(candidate, remove):
    path = candidate.root / "frontend/package-lock.json"
    data = json.loads(path.read_bytes())
    del data["packages"]["node_modules/next"][remove]
    path.write_text(json.dumps(data), encoding="utf-8")
    assert "DEPENDENCY_NPM_LOCK_POLICY_REQUIRED" in inspect(candidate).blockers


def test_missing_both_registry_artifact_fields_preserves_exact_version_pinning(candidate):
    path = candidate.root / "frontend/package-lock.json"
    data = json.loads(path.read_bytes())
    entry = data["packages"]["node_modules/next"]
    del entry["resolved"]
    del entry["integrity"]
    path.write_text(json.dumps(data), encoding="utf-8")
    assert not inspect(candidate).blockers
    entry["version"] = "^16.3.4"
    path.write_text(json.dumps(data), encoding="utf-8")
    assert "DEPENDENCY_NPM_LOCK_POLICY_REQUIRED" in inspect(candidate).blockers


@pytest.mark.parametrize("contents", [None, b"", b"# npm distribution defaults\n; reviewed comment\n",
                                      b"prefix=${APPDATA}/npm\n", b"prefix=${APPDATA}\\npm\n"])
def test_safe_builtin_npm_configuration_is_pinned_without_comment_bytes(candidate, contents):
    if contents is not None:
        candidate.npmrc.write_bytes(contents)
    plan = inspect(candidate)
    assert not plan.blockers
    public = repr(plan) + json.dumps(plan.to_dict())
    assert str(candidate.npmrc) not in public
    if contents:
        assert contents.decode() not in repr(plan.npm_builtin_policy)
        assert hashlib.sha256(contents).hexdigest() not in repr(plan.npm_builtin_policy)
    outcome = dependencies.prepare_dependencies(plan, authorize=lambda value: True, runner=candidate.runner)
    assert outcome.exit_code == 0
    assert all("--prefix" in command for command, _ in candidate.runner.calls if len(command) > 2
               and Path(command[1]).name == "npm-cli.js")


@pytest.mark.parametrize("contents", [
    b"@company:registry=https://corporate.invalid/npm\n",
    b"//registry.npmjs.org/:_authToken=" + SECRET.encode() + b"\n",
    b"registry=https://corporate.invalid/npm\n",
    b"proxy=https://corporate.invalid\n", b"https-proxy=https://corporate.invalid\n",
    b"cafile=/private/corporate.pem\n", b"strict-ssl=false\n",
    b"prefix=/somewhere/else\n", b"unknown=true\n",
    b"prefix=${APPDATA}/npm\nprefix=${APPDATA}/npm\n", b"\xff\n",
])
def test_unapproved_builtin_npm_configuration_blocks_before_tool_execution(candidate, contents, capsys):
    candidate.npmrc.write_bytes(contents)
    plan = inspect(candidate)
    assert plan.blockers == ("DEPENDENCY_NPM_BUILTIN_POLICY_REQUIRED",)
    assert not plan.npm_builtin_policy and candidate.runner.calls == []
    assert SECRET not in repr(plan) + json.dumps(plan.to_dict()) + repr(capsys.readouterr())
    assert hashlib.sha256(contents).hexdigest() not in json.dumps(plan.to_dict())
    approval = Mock(side_effect=AssertionError("Blocked policy requested consent"))
    assert dependencies.prepare_dependencies(plan, authorize=approval, runner=candidate.runner).exit_code == 1
    approval.assert_not_called()
    assert not (candidate.home / ".sbom-dev").exists()


@pytest.mark.parametrize("before,after", [(None, b""), (b"", None),
                                         (b"prefix=${APPDATA}/npm\n", b""),
                                         (b"", b"@company:registry=https://corporate.invalid/npm\n")])
def test_builtin_npm_configuration_drift_invalidates_consent_before_mutation(candidate, before, after):
    if before is not None:
        candidate.npmrc.write_bytes(before)
    plan = inspect(candidate)
    assert not plan.blockers

    def approve(value):
        if after is None:
            candidate.npmrc.unlink()  # Only the exact file created by this test.
        else:
            candidate.npmrc.write_bytes(after)
        return True

    candidate.runner.calls.clear()
    outcome = dependencies.prepare_dependencies(plan, authorize=approve, runner=candidate.runner)
    assert outcome.code == "DEPENDENCY_NPM_BUILTIN_POLICY_REQUIRED" and not outcome.artifacts_retained
    assert candidate.runner.calls == []
    assert not (candidate.root / ".venv").exists() and not (candidate.home / ".sbom-dev").exists()


def test_builtin_npm_comment_changes_bind_metadata_without_hashing_private_comments(candidate):
    candidate.npmrc.write_text("# " + SECRET + "\n", encoding="utf-8")
    plan = inspect(candidate)
    assert not plan.blockers and SECRET not in repr(plan.npm_builtin_policy)
    assert hashlib.sha256(candidate.npmrc.read_bytes()).hexdigest() not in repr(plan.npm_builtin_policy)
    candidate.npmrc.write_bytes(b"# changed distribution comment\n")
    assert inspect(candidate).fingerprint != plan.fingerprint
    with pytest.raises(dependencies.DependencyError, match="^DEPENDENCY_NPM_BUILTIN_POLICY_REQUIRED$"):
        dependencies._revalidate(plan)


def test_builtin_npm_policy_is_revalidated_after_python_install_before_npm(candidate):
    plan = inspect(candidate)
    candidate.runner.on_install = lambda: candidate.npmrc.write_bytes(b"strict-ssl=false\n")
    outcome = dependencies.prepare_dependencies(plan, authorize=lambda value: True, runner=candidate.runner)
    assert outcome.code == "DEPENDENCY_NPM_BUILTIN_POLICY_REQUIRED" and outcome.artifacts_retained
    assert not any("ci" in command for command, _ in candidate.runner.calls)
    assert candidate.npmrc.read_bytes() == b"strict-ssl=false\n"


def test_redirected_builtin_npm_configuration_is_not_read_or_adopted(candidate):
    outside = candidate.home / "private npm configuration"
    if os.name == "nt":
        private_directory(outside)
        (outside / "preserve").write_text(SECRET, encoding="utf-8")
        import _winapi

        _winapi.CreateJunction(str(outside), str(candidate.npmrc))
    else:
        outside.write_text(SECRET, encoding="utf-8")
        candidate.npmrc.symlink_to(outside)
    try:
        assert inspect(candidate).blockers == ("DEPENDENCY_NPM_BUILTIN_POLICY_REQUIRED",)
        assert candidate.runner.calls == []
    finally:
        if os.name == "nt":
            os.rmdir(candidate.npmrc)  # Only this exact test-created junction entry.
        else:
            candidate.npmrc.unlink()
