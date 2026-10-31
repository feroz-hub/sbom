"""Synthetic orchestration tests only; --noconftest, no delegated real suite.

All source/venv/stamp/temporary artifacts are brand-new pytest fixtures. Children
are fake original handles; no application import, database or live pytest child.
"""

from __future__ import annotations

import builtins
import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import types
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest.mock import Mock

import pytest
from scripts import dev_workspace as workspace
from scripts import dev_workspace_tests as testing

SECRET = "synthetic-private-environment-traceback-and-database-value"
HEAD = "a" * 40
REPOSITORY = "b" * 64
WORKTREE = "c" * 64


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    root, home = tmp_path / "checkout", tmp_path / "owned-home"
    testing._mkdir(root, tmp_path)
    testing._mkdir(home, tmp_path)
    source = Path(testing.__file__).resolve().parent.parent
    for name in ("scripts", "app", "tests", ".venv"):
        testing._mkdir(root / name, root)
    for name in testing._SOURCES:
        testing.dev_private.create_private_file(root / name, (source / name).read_bytes())
    requirements = b"pytest==9.1.1\n"
    testing.dev_private.create_private_file(root / "requirements.txt", requirements)
    target = root / ".venv"
    binary = target / ("Scripts" if os.name == "nt" else "bin")
    testing._mkdir(binary, target)
    executable = binary / ("python.exe" if os.name == "nt" else "python")
    testing.dev_private.create_private_file(executable, b"synthetic-interpreter-not-executable")
    testing.dev_private.create_private_file(target / "pyvenv.cfg", b"include-system-site-packages = false\n")
    stamp = {
        "version": 1, "kind": "python", "repository_id": REPOSITORY, "worktree_id": WORKTREE,
        "root": str(root), "identity": testing.dependencies._directory(target),
        "manifests": {"requirements.txt": hashlib.sha256(requirements).hexdigest()},
        "tools": {"python": list(testing._proof(executable, target))}, "versions": {"python": [3, 14, 6]},
        "tree": testing.dependencies._tree(target),
    }
    testing.dev_private.create_private_file(target / testing._STAMP, testing._json(stamp))
    identity = workspace._identity(root)
    selected = workspace.WorktreeSnapshot(WORKTREE, root, identity, HEAD, "refs/heads/fixture", False,
                                         False, False, False, False)
    snapshot = workspace.RepositorySnapshot(REPOSITORY, root, identity, HEAD, (selected,), identity)
    discover = Mock(return_value=snapshot)
    monkeypatch.setattr(workspace, "discover_workspaces", discover)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    return types.SimpleNamespace(root=root, home=home, target=target, executable=executable,
                                 stamp=stamp, snapshot=snapshot, selected=selected, discover=discover)


def restamp(fixture, **changes):
    """Fixture-only replacement; production never repairs/adopts a stamp."""
    value = {**fixture.stamp, **changes}
    value["tree"] = testing.dependencies._tree(fixture.target)
    path = fixture.target / testing._STAMP
    path.unlink()
    testing.dev_private.create_private_file(path, testing._json(value))
    return value


class FakeChild:
    def __init__(self, stdout=b"8 passed, 1 skipped in 0.12s\n", stderr=b"", code=0, *, running=False,
                 kill_error=False, wait_error=False):
        self.stdout, self.stderr = io.BytesIO(stdout), io.BytesIO(stderr)
        self.pid, self.returncode = 54321, None if running else code
        self.code, self.kill_error, self.wait_error = code, kill_error, wait_error
        self.kills, self.waits = 0, []

    def poll(self):
        return self.returncode

    def kill(self):
        self.kills += 1
        if self.kill_error:
            raise OSError(SECRET)
        self.returncode = -9

    def wait(self, timeout):
        self.waits.append(timeout)
        if self.wait_error:
            raise subprocess.TimeoutExpired(SECRET, timeout)
        if self.returncode is None:
            self.returncode = self.code
        return self.returncode


def fake_child(monkeypatch, child=None):
    child = child or FakeChild()
    spawn = Mock(return_value=child)
    monkeypatch.setattr(subprocess, "Popen", spawn)
    return child, spawn


def test_read_only_plan_binds_exact_source_worktree_head_and_stamped_venv(prepared, monkeypatch):
    forbidden = Mock(side_effect=AssertionError("Planning attempted a mutation or application connection"))
    with monkeypatch.context() as guard:
        guard.setattr(testing, "_mkdir", forbidden)
        guard.setattr(testing.dev_private, "create_private_file", forbidden)
        guard.setattr(testing.dev_instance_storage, "initialize_private_directory", forbidden)
        guard.setattr(subprocess, "Popen", forbidden)
        guard.setattr(socket, "socket", forbidden)
        plan = testing.plan_tests(prepared.root)
    assert not plan.blockers
    assert (plan.root, plan.root_identity, plan.commit, plan.worktree_id) == (
        prepared.root, prepared.selected.identity, HEAD, WORKTREE)
    assert plan.home_identity.canonical_path == prepared.home
    assert len(plan.sources) == len(testing._SOURCES) and len(plan.venv_proofs) == 4
    assert plan.fingerprint == hashlib.sha256(testing._json(testing._binding(plan))).hexdigest()
    assert plan.to_dict()["tests"] == list(testing.UNIT_TESTS)
    assert plan.to_dict()["scope"] == "pure-development-contracts"
    assert plan.to_dict()["database_authorized"] is False
    assert testing.plan_tests(prepared.root) == plan
    forbidden.assert_not_called()
    assert not list(prepared.home.iterdir())
    with pytest.raises(FrozenInstanceError):
        plan.commit = "d" * 40
    assert isinstance(plan.sources, tuple) and isinstance(plan.sources[0][1], tuple)


@pytest.mark.parametrize("suite", ["db", "database", "integration", "migration", "migrations", "all"])
def test_every_database_suite_is_unconditionally_blocked_without_any_observation(suite, monkeypatch):
    forbidden = Mock(side_effect=AssertionError("Database suite must not inspect or execute"))
    monkeypatch.setattr(workspace, "discover_workspaces", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    plan = testing.plan_tests(SECRET, suite=suite)
    assert plan.blockers == ("DISPOSABLE_TARGET_AUTHORIZATION_REQUIRED",)
    assert testing.run_tests(plan).code == "DISPOSABLE_TARGET_AUTHORIZATION_REQUIRED"
    assert SECRET not in repr(plan) + json.dumps(plan.to_dict())
    forbidden.assert_not_called()


@pytest.mark.parametrize("suite", ["unit -p injected", SECRET, False, [], None])
def test_unapproved_suite_and_arguments_never_select_arbitrary_tests(suite):
    assert testing.plan_tests("ignored", suite=suite).blockers == ("TEST_SUITE_UNSUPPORTED",)
    with pytest.raises(TypeError):
        testing.plan_tests("ignored", pytest_args=[SECRET])
    with pytest.raises(TypeError):
        testing.run_tests(None, tests=[SECRET])


@pytest.mark.parametrize("change", [
    {"status": "UNKNOWN"}, {"locked": True}, {"prunable": True}, {"bare": True},
    {"identity": None}, {"head": None}, {"head": SECRET}, {"worktree_id": SECRET},
])
def test_unverified_or_unavailable_worktree_fails_closed(prepared, change):
    selected = replace(prepared.selected, **change)
    prepared.discover.return_value = replace(prepared.snapshot, worktrees=(selected,))
    assert testing.plan_tests(prepared.root).blockers == ("TEST_WORKTREE_UNVERIFIED",)


def test_selects_exact_worktree_and_refuses_ambiguous_or_unknown_selection(prepared):
    assert not testing.plan_tests(prepared.root, worktree_id=WORKTREE).blockers
    assert testing.plan_tests(prepared.root, worktree_id="f" * 64).blockers == ("TEST_WORKTREE_SELECTION_REQUIRED",)
    prepared.discover.return_value = replace(prepared.snapshot, worktrees=(prepared.selected, prepared.selected))
    assert testing.plan_tests(prepared.root).blockers == ("TEST_WORKTREE_SELECTION_REQUIRED",)


def test_unverified_root_access_has_specific_diagnosis_without_acl_repair(prepared, monkeypatch):
    original = testing.dependencies._directory
    forbidden = Mock(side_effect=AssertionError("No source read, execution or permissions repair"))

    def inaccessible(path):
        if path == prepared.root:
            raise testing.dev_instance_storage.DirectoryInitializationError("INSTANCE_DIRECTORY_ACCESS_UNVERIFIED", 5,
                                                                             windows=True)
        return original(path)

    monkeypatch.setattr(testing.dependencies, "_directory", inaccessible)
    monkeypatch.setattr(testing, "_sources", forbidden)
    monkeypatch.setattr(testing.dev_instance_storage, "initialize_private_directory", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    plan = testing.plan_tests(prepared.root)
    assert plan.blockers == ("TEST_ROOT_ACCESS_REVIEW_REQUIRED",)
    assert testing.run_tests(plan).code == "TEST_ROOT_ACCESS_REVIEW_REQUIRED"
    assert not list(prepared.home.iterdir())
    forbidden.assert_not_called()


def test_source_byte_drift_cannot_be_adopted_by_new_plan(prepared):
    (prepared.root / testing.UNIT_TESTS[0]).write_text(SECRET, encoding="utf-8")
    plan = testing.plan_tests(prepared.root)
    assert plan.blockers == ("TEST_SOURCE_REVIEW_REQUIRED",)
    assert SECRET not in json.dumps(plan.to_dict()) + repr(plan)


def test_source_hardlink_is_not_accepted_as_reviewed_file(prepared):
    target = prepared.root / testing.UNIT_TESTS[0]
    os.link(target, prepared.root / "hardlinked-test")
    assert testing.plan_tests(prepared.root).blockers == ("TEST_SOURCE_REVIEW_REQUIRED",)


def test_missing_or_legacy_only_stamp_requires_explicit_dependency_preparation(prepared):
    (prepared.target / testing._STAMP).unlink()
    (prepared.target / ".sbom-requirements-sha256").write_text("f" * 64, encoding="ascii")
    assert testing.plan_tests(prepared.root).blockers == ("TEST_VENV_PREPARATION_REQUIRED",)


@pytest.mark.parametrize("changes", [
    {"repository_id": "d" * 64}, {"worktree_id": "d" * 64}, {"root": SECRET},
    {"identity": [0, 0]}, {"kind": "frontend"}, {"version": True},
    {"manifests": {"requirements.txt": "f" * 64}}, {"tools": {}},
    {"versions": {"python": [3, 10, 9]}}, {"versions": {"python": [True, 14, 0]}},
])
def test_stamp_target_version_manifest_and_preparation_identity_are_validated(prepared, changes):
    restamp(prepared, **changes)
    assert testing.plan_tests(prepared.root).blockers == ("TEST_VENV_UNVERIFIED",)


def test_duplicate_keys_and_unrecognized_stamp_fields_fail_closed(prepared):
    path = prepared.target / testing._STAMP
    path.unlink()
    testing.dev_private.create_private_file(path, b'{"version":1,"version":1}')
    assert testing.plan_tests(prepared.root).blockers == ("TEST_VENV_UNVERIFIED",)
    restamp(prepared, extra=SECRET)
    assert testing.plan_tests(prepared.root).blockers == ("TEST_VENV_UNVERIFIED",)


@pytest.mark.parametrize("raw", [b"include-system-site-packages = true\n", b"",
                                 b"include-system-site-packages = false\ninclude-system-site-packages = true\n"])
def test_venv_must_disable_system_site_packages_exactly_once(prepared, raw):
    (prepared.target / "pyvenv.cfg").write_bytes(raw)
    restamp(prepared)
    assert testing.plan_tests(prepared.root).blockers == ("TEST_VENV_ISOLATION_REQUIRED",)


def test_venv_tree_or_interpreter_drift_is_not_silently_adopted(prepared):
    prepared.executable.write_bytes(b"different synthetic executable")
    assert testing.plan_tests(prepared.root).blockers == ("TEST_VENV_UNVERIFIED",)


def test_source_venv_and_head_drift_between_plan_and_execution_never_spawns(prepared, monkeypatch):
    plan = testing.plan_tests(prepared.root)
    child, spawn = fake_child(monkeypatch)
    for change in ("head", "test", "venv"):
        with monkeypatch.context() as guard:
            if change == "head":
                selected = replace(prepared.selected, head="d" * 40)
                guard.setattr(prepared.discover, "return_value", replace(prepared.snapshot, worktrees=(selected,)))
            elif change == "test":
                guard.setattr(testing, "_sources", Mock(side_effect=testing.TestPlanningError("TEST_SOURCE_CHANGED")))
            else:
                guard.setattr(testing, "_venv", Mock(side_effect=testing.TestPlanningError("TEST_VENV_UNVERIFIED")))
            outcome = testing.run_tests(plan)
            assert outcome.code == "TEST_PLAN_CHANGED"
    spawn.assert_not_called()
    assert child.kills == 0 and not list(prepared.home.iterdir())


def test_fixed_command_copies_only_hash_reviewed_sources_and_injects_sqlite_sentinels(prepared, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", SECRET)
    monkeypatch.setenv("TEST_POSTGRES_DATABASE_URL", SECRET)
    monkeypatch.setenv("PYTHONPATH", SECRET)
    monkeypatch.setenv("PYTEST_ADDOPTS", "-p " + SECRET)
    monkeypatch.setenv("PGPASSWORD", SECRET)
    monkeypatch.setenv("APP_SECRET_KEY", SECRET)
    (prepared.root / "conftest.py").write_text(SECRET, encoding="utf-8")
    (prepared.root / "pytest.ini").write_text(SECRET, encoding="utf-8")
    (prepared.root / ".env").write_text(SECRET, encoding="utf-8")
    plan = testing.plan_tests(prepared.root)
    child, spawn = fake_child(monkeypatch)
    outcome = testing.run_tests(plan)
    assert outcome.code == "TEST_UNIT_PASSED" and outcome.exit_code == 0
    assert dict(outcome.counts) == {"passed": 8, "skipped": 1}
    assert outcome.cleanup_verified is True and child.kills == 0
    command = spawn.call_args.args[0]
    args = spawn.call_args.kwargs
    assert command[0] == str(prepared.executable)
    assert command[1:4] == ("-I", "-B", "-c")
    assert "--noconftest" in command and "no:cacheprovider" in command and "no:tmpdir" in command
    assert "--basetemp" not in command and "pytest_timeout" not in command
    assert command[command.index("--rootdir") - 2:command.index("--rootdir")] == ("-c", os.devnull)
    assert args["shell"] is False and args["close_fds"] is True and args["stdin"] == subprocess.DEVNULL
    environment = args["env"]
    for name in ("DATABASE_URL", "TEST_DATABASE_URL", "TEST_POSTGRES_DATABASE_URL"):
        assert environment[name] == "sqlite:///:memory:"
    assert "PGPASSWORD" not in environment and "PYTHONPATH" not in environment
    assert environment["PYTEST_ADDOPTS"] == ""
    assert environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert environment["PYTHON_DOTENV_DISABLED"] == "1"
    assert SECRET not in repr(command) + repr(environment) + json.dumps(outcome.to_dict())
    stage = outcome.retained_directory
    copied = stage / "source"
    assert stage.parent == prepared.home
    assert args["cwd"] == copied and copied != prepared.root
    assert sorted(str(path.relative_to(copied)).replace("\\", "/") for path in copied.rglob("*") if path.is_file()) == sorted(testing._SOURCES)
    for name in testing._SOURCES:
        assert (copied / name).read_bytes() == (prepared.root / name).read_bytes()
    assert outcome.temporary_files_retained and stage.exists()
    assert outcome.to_dict()["database_authorized"] is False
    assert outcome.to_dict()["application_readiness_verified"] is False
    assert outcome.to_dict()["cleanup_scope"] == "original-test-child"
    assert outcome.to_dict()["descendant_ownership_verified"] is False


def test_no_existing_temporary_directory_is_reused_or_deleted(prepared, monkeypatch):
    identifier = types.SimpleNamespace(hex="d" * 32)
    monkeypatch.setattr(testing.uuid, "uuid4", lambda: identifier)
    existing = prepared.home / (".sbom-unit-" + identifier.hex)
    testing._mkdir(existing, prepared.home)
    marker = existing / "preserve"
    marker.write_text(SECRET, encoding="utf-8")
    _, spawn = fake_child(monkeypatch)
    result = testing.run_tests(testing.plan_tests(prepared.root))
    assert result.exit_code == 1 and result.code == "TEST_TEMPORARY_FILES_RETAINED"
    assert marker.read_text(encoding="utf-8") == SECRET
    assert result.temporary_files_retained
    spawn.assert_not_called()


def test_partial_stage_is_retained_and_drift_revalidated_after_copy(prepared, monkeypatch):
    plan = testing.plan_tests(prepared.root)
    _, spawn = fake_child(monkeypatch)
    original = testing._stage

    def copy_then_drift(bound, stage):
        original(bound, stage)
        prepared.executable.write_bytes(b"changed after private copy")

    monkeypatch.setattr(testing, "_stage", copy_then_drift)
    result = testing.run_tests(plan)
    assert result.code == "TEST_PLAN_CHANGED" and result.temporary_files_retained
    assert result.retained_directory.is_dir()
    assert (result.retained_directory / "source" / testing.UNIT_TESTS[0]).is_file()
    spawn.assert_not_called()


def test_partial_source_copy_failure_preserves_its_private_files(prepared, monkeypatch):
    plan = testing.plan_tests(prepared.root)
    _, spawn = fake_child(monkeypatch)
    create = testing.dev_private.create_private_file
    count = 0

    def fail_second_copy(path, raw):
        nonlocal count
        count += 1
        if count == 2:
            raise OSError(SECRET)
        create(path, raw)

    monkeypatch.setattr(testing.dev_private, "create_private_file", fail_second_copy)
    result = testing.run_tests(plan)
    assert result.code == "TEST_TEMPORARY_FILES_RETAINED" and result.temporary_files_retained
    assert (result.retained_directory / "source" / testing._SOURCES[0]).is_file()
    assert SECRET not in repr(result) + json.dumps(result.to_dict())
    spawn.assert_not_called()


def test_fixed_bootstrap_supplies_only_fresh_temporary_fixture_without_deletion(tmp_path, monkeypatch):
    temporary, source = tmp_path / "private-fresh", tmp_path / "copied-source"
    temporary.mkdir(mode=0o700)
    identifier = types.SimpleNamespace(hex="e" * 32)
    monkeypatch.setattr(testing.uuid, "uuid4", lambda: identifier)
    monkeypatch.setattr(sys, "argv", ["fixed", str(source), str(temporary), "fixed-pytest-args"])
    monkeypatch.setattr(sys, "path", list(sys.path))

    def fixed_main(arguments, plugins):
        assert arguments == ["fixed-pytest-args"] and len(plugins) == 1
        first = plugins[0].tmp_path()
        assert first.parent == temporary and not list(first.iterdir())
        marker = first / "preserve"
        marker.write_text(SECRET, encoding="utf-8")
        with pytest.raises(FileExistsError):
            plugins[0].tmp_path()
        assert marker.read_text(encoding="utf-8") == SECRET
        return 0

    fake_pytest = types.SimpleNamespace(fixture=lambda function: function, main=fixed_main)
    monkeypatch.setitem(sys.modules, "pytest", fake_pytest)
    with pytest.raises(SystemExit) as caught:
        exec(testing._BOOTSTRAP, {})
    assert caught.value.code == 0
    assert sys.path[0] == str(source)


def test_actual_reviewed_copied_closure_runs_without_repository_fixtures_or_installation(prepared):
    """Manual closure smoke, not adoption of an unstamped product interpreter.

    The public runner's prepared-venv checks stay unchanged. Only this test uses
    its already-running, independently pinned pytest interpreter to validate the
    exact staged import closure. No environment/package creation is performed.
    """
    executable = Path(sys.executable).absolute()
    try:
        # Refuse redirected launch paths, including a POSIX venv symlink whose
        # resolution would silently switch Python package contexts.
        if executable.resolve(strict=True) != executable or executable.is_symlink():
            pytest.skip("Copied-closure smoke requires an existing nonredirected pytest interpreter")
        interpreter_proof = testing._proof(executable, executable.parent, 268435456)
    except testing.dependencies.DependencyError:
        pytest.skip("Existing test interpreter cannot be pinned without altering its installation")
    planned = testing.plan_tests(prepared.root)
    assert not planned.blockers
    stage = prepared.home / (".closure-" + testing.uuid.uuid4().hex)
    testing._stage(planned, stage)
    assert {str(path.relative_to(stage / "source")).replace("\\", "/")
            for path in (stage / "source").rglob("*") if path.is_file()} == set(testing._SOURCES)
    # Neither upward pytest discovery nor the checkout's application fixtures
    # may contribute executable configuration to the child.
    testing.dev_private.create_private_file(stage / "conftest.py", b"raise AssertionError('outside reviewed closure')\n")
    testing.dev_private.create_private_file(stage / "pytest.ini", b"[pytest]\naddopts = -p unapproved_fixture\n")
    command = (str(executable), *testing._command(planned, stage)[1:])
    raw, code, reason, cleanup, pid = testing._execute(command, cwd=stage / "source",
        environment=testing._environment(planned, stage), timeout=20)
    # Assertions intentionally never print arbitrary pytest stdout/tracebacks.
    assert reason is None, "Reviewed copied closure failed its bounded transport"
    assert code == 0, "Reviewed copied closure failed; stdout is withheld"
    assert cleanup is True and type(pid) is int and pid > 0
    counts = dict(testing._counts(raw, code))
    assert counts.get("passed", 0) > 0 and not counts.get("failed", 0) and not counts.get("errors", 0)
    assert testing._proof(executable, executable.parent, 268435456) == interpreter_proof


@pytest.mark.parametrize("timeout", [True, False, 0, -1, 301, float("nan"), float("inf"), SECRET])
def test_timeout_is_bounded_and_not_an_arbitrary_execution_option(prepared, monkeypatch, timeout):
    _, spawn = fake_child(monkeypatch)
    assert testing.run_tests(testing.plan_tests(prepared.root), timeout=timeout).code == "TEST_PLAN_INVALID"
    spawn.assert_not_called()


@pytest.mark.parametrize("raw,code,counts", [
    (b"1 passed in 0.01s\n", 0, {"passed": 1}),
    (b"=== 1 failed, 2 passed, 1 warning in 1.00s ===\n", 1, {"failed": 1, "passed": 2, "warnings": 1}),
    (b"2 errors in 0.11s\n", 1, {"errors": 2}),
    (b"3 skipped, 1 xfailed in 0.10s\n", 0, {"skipped": 3, "xfailed": 1}),
])
def test_only_valid_summary_counts_are_reported(raw, code, counts):
    assert dict(testing._counts(raw, code)) == counts


@pytest.mark.parametrize("raw,code", [
    (SECRET.encode(), 0), (b"", 0), (b"1 failed in 0.1s\n", 0), (b"1 passed in 0.1s\n", 1),
    (b"0 passed in 0.1s\n", 0), (b"1000001 passed in 0.1s\n", 0),
    (b"1 passed, 2 passed in 0.1s\n", 0), (b"1 passed in 0.1s\n1 passed in 0.1s\n", 0),
    (b"1 warning in 0.1s\n", 0), (b"1 passed in 0.1s\n", 2), (b"1 passed in 0.1s\n", -9),
])
def test_incoherent_or_arbitrary_output_is_not_interpreted_as_success(raw, code):
    with pytest.raises(testing.TestPlanningError, match="^TEST_EXECUTION_UNVERIFIED$"):
        testing._counts(raw, code)


def test_test_failure_is_counts_only_and_never_echoes_trace_or_secret(prepared, monkeypatch):
    fake_child(monkeypatch, FakeChild(SECRET.encode() + b"\n1 failed, 7 passed in 0.04s\n", SECRET.encode(), 1))
    result = testing.run_tests(testing.plan_tests(prepared.root))
    assert result.code == "TEST_UNIT_FAILED" and result.child_exit_code == 1
    assert dict(result.counts) == {"failed": 1, "passed": 7}
    assert SECRET not in repr(result) + json.dumps(result.to_dict())


def test_timeout_kills_only_the_original_child_handle_and_reports_confirmed_cleanup(monkeypatch):
    child, spawn = fake_child(monkeypatch, FakeChild(running=True))
    moment = iter([0.0, 2.0])
    monkeypatch.setattr(testing.time, "monotonic", lambda: next(moment))
    monkeypatch.setattr(os, "kill", Mock(side_effect=AssertionError("No PID signaling")))
    monkeypatch.setattr(os, "killpg", Mock(side_effect=AssertionError("No group signaling")), raising=False)
    _, code, reason, cleanup, pid = testing._execute(("fixed",), cwd="fixture", environment={}, timeout=1)
    assert (code, reason, cleanup, pid) == (-9, "TEST_TIMEOUT", True, 54321)
    assert child.kills == 1 and child.waits == [2, 2]
    spawn.assert_called_once()


def test_cleanup_failure_is_explicit_and_does_not_escalate_to_pid_or_tree_kill(monkeypatch):
    child, _ = fake_child(monkeypatch, FakeChild(running=True, kill_error=True, wait_error=True))
    moment = iter([0.0, 2.0])
    monkeypatch.setattr(testing.time, "monotonic", lambda: next(moment))
    _, _, reason, cleanup, pid = testing._execute(("fixed",), cwd="fixture", environment={}, timeout=1)
    assert (reason, cleanup, pid) == ("TEST_CHILD_CLEANUP_UNCONFIRMED", False, 54321)
    assert child.kills == 2


@pytest.mark.parametrize("interrupted_operation", ["poll", "kill", "wait"])
def test_second_interrupt_during_original_child_cleanup_keeps_pid_and_uncertainty(
    prepared, monkeypatch, interrupted_operation,
):
    class InterruptedChild(FakeChild):
        def __init__(self):
            super().__init__(running=True)
            self.operations = []

        def poll(self):
            self.operations.append("poll")
            if self.operations == ["poll"] or interrupted_operation == "poll":
                raise KeyboardInterrupt(SECRET)
            return None

        def kill(self):
            self.operations.append("kill")
            self.kills += 1
            if interrupted_operation == "kill":
                raise KeyboardInterrupt(SECRET)
            # Sending termination alone never establishes that the child exited.

        def wait(self, timeout):
            self.operations.append("wait")
            self.waits.append(timeout)
            raise KeyboardInterrupt(SECRET)

    child, spawn = fake_child(monkeypatch, InterruptedChild())
    forbidden = Mock(side_effect=AssertionError("No PID, process-group or alternate-process cleanup"))
    monkeypatch.setattr(os, "kill", forbidden)
    monkeypatch.setattr(os, "killpg", forbidden, raising=False)
    monkeypatch.setattr(subprocess, "run", forbidden)
    result = testing.run_tests(testing.plan_tests(prepared.root))
    assert result.code == "TEST_CHILD_CLEANUP_UNCONFIRMED" and result.exit_code == 1
    assert result.cleanup_verified is False and result.probe_pid == 54321 and result.child_exit_code is None
    assert result.temporary_files_retained and result.retained_directory.is_dir()
    expected = ["poll", "poll"] + ([] if interrupted_operation == "poll" else ["kill"])
    if interrupted_operation == "wait":
        expected.append("wait")
    assert child.operations == expected
    assert len(child.waits) <= 1 and all(timeout == 2 for timeout in child.waits)
    assert SECRET not in repr(result) + json.dumps(result.to_dict())
    spawn.assert_called_once()
    forbidden.assert_not_called()


def test_interrupt_closing_output_pipe_keeps_confirmed_original_child_status(monkeypatch):
    class InterruptedPipe(io.BytesIO):
        def close(self):
            raise KeyboardInterrupt(SECRET)

    child = FakeChild()
    child.stdout = InterruptedPipe(b"1 passed in 0.01s\n")
    fake_child(monkeypatch, child)
    _, code, reason, cleanup, pid = testing._execute(("fixed",), cwd="fixture", environment={}, timeout=1)
    assert (code, reason, cleanup, pid) == (0, "TEST_OUTPUT_UNCONFIRMED", True, 54321)
    assert child.kills == 0
    io.BytesIO.close(child.stdout)  # Close the in-memory fixture without its simulated interrupt.


def test_output_is_bounded_even_for_flooding_child(monkeypatch):
    fake_child(monkeypatch, FakeChild(b"x" * (testing._OUTPUT_LIMIT + 70000)))
    raw, _, reason, cleanup, _ = testing._execute(("fixed",), cwd="fixture", environment={}, timeout=1)
    assert len(raw) == testing._OUTPUT_LIMIT
    assert reason == "TEST_OUTPUT_LIMIT" and cleanup is True


def test_spawn_error_is_fixed_and_redacted(prepared, monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", Mock(side_effect=OSError(SECRET)))
    result = testing.run_tests(testing.plan_tests(prepared.root))
    assert result.code == "TEST_EXECUTION_UNVERIFIED" and result.cleanup_verified is None
    assert result.temporary_files_retained
    assert SECRET not in repr(result) + json.dumps(result.to_dict())


def test_unverified_summary_keeps_confirmed_child_cleanup_metadata(prepared, monkeypatch):
    fake_child(monkeypatch, FakeChild(SECRET.encode()))
    result = testing.run_tests(testing.plan_tests(prepared.root))
    assert result.code == "TEST_EXECUTION_UNVERIFIED" and result.cleanup_verified is True
    assert result.child_exit_code == 0 and result.probe_pid == 54321
    assert SECRET not in repr(result) + json.dumps(result.to_dict())


def test_prelaunch_operator_cancellation_is_safe_and_does_not_spawn(prepared, monkeypatch):
    plan = testing.plan_tests(prepared.root)
    _, spawn = fake_child(monkeypatch)
    monkeypatch.setattr(testing, "_refresh", Mock(side_effect=KeyboardInterrupt()))
    result = testing.run_tests(plan)
    assert result.code == "TEST_EXECUTION_CANCELLED" and result.exit_code == 130
    assert not result.temporary_files_retained
    spawn.assert_not_called()


def test_post_child_cancellation_preserves_known_confirmed_cleanup_status(prepared, monkeypatch):
    fake_child(monkeypatch)
    monkeypatch.setattr(testing, "_counts", Mock(side_effect=KeyboardInterrupt(SECRET)))
    result = testing.run_tests(testing.plan_tests(prepared.root))
    assert result.code == "TEST_EXECUTION_CANCELLED" and result.exit_code == 130
    assert result.cleanup_verified is True and result.probe_pid == 54321 and result.child_exit_code == 0
    assert result.temporary_files_retained
    assert SECRET not in repr(result) + json.dumps(result.to_dict())


@pytest.mark.parametrize("changes", [
    {"code": SECRET}, {"counts": ((SECRET, 1),)}, {"counts": (("passed", True),)},
    {"counts": (("passed", 1), ("passed", 2))}, {"exit_code": SECRET},
])
def test_public_outcome_never_transports_unvalidated_labels_or_raw_output(changes):
    result = testing.TestOutcome(**{"code": "TEST_UNIT_PASSED", "exit_code": 0, **changes})
    assert result.code == "TEST_EXECUTION_UNVERIFIED" and result.exit_code == 1
    assert SECRET not in repr(result) + json.dumps(result.to_dict())


def test_direct_module_invocation_has_no_alternate_live_execution(prepared, monkeypatch):
    source = Path(testing.__file__).read_text(encoding="utf-8")
    fixture = types.ModuleType("scripts.synthetic_test_runner")
    monkeypatch.setitem(sys.modules, fixture.__name__, fixture)
    fixture.__package__ = "scripts"
    fixture.__file__ = testing.__file__
    fixture.__name__ = "__main__"
    monkeypatch.setitem(sys.modules, "__main__", fixture)
    forbidden = Mock(side_effect=AssertionError("Direct module execution attempted an action"))
    with monkeypatch.context() as guard:
        guard.setattr(subprocess, "Popen", forbidden)
        guard.setattr(workspace, "discover_workspaces", forbidden)
        guard.setattr(testing.dev_private, "create_private_file", forbidden)
        with pytest.raises(SystemExit, match="database testing is gated"):
            exec(compile(source, "<synthetic-direct-runner>", "exec"), fixture.__dict__)
    forbidden.assert_not_called()


def test_import_is_read_only_and_does_not_import_application_or_environment(monkeypatch):
    source = Path(testing.__file__).read_text(encoding="utf-8")
    fixture = types.ModuleType("scripts.synthetic_readonly_test_runner")
    fixture.__package__ = "scripts"
    monkeypatch.setitem(sys.modules, fixture.__name__, fixture)
    original_import = builtins.__import__
    forbidden = Mock(side_effect=AssertionError("Import attempted an external operation"))

    def guarded_import(name, *args, **kwargs):
        assert name.split(".", 1)[0] not in {"app", "sqlalchemy", "psycopg", "celery", "pytest", "dotenv"}
        return original_import(name, *args, **kwargs)

    with monkeypatch.context() as guard:
        guard.setattr(builtins, "__import__", guarded_import)
        guard.setattr(builtins, "open", forbidden)
        guard.setattr(os, "getenv", forbidden)
        guard.setattr(os, "open", forbidden)
        guard.setattr(socket, "socket", forbidden)
        guard.setattr(subprocess, "Popen", forbidden)
        guard.setattr(Path, "resolve", forbidden)
        guard.setattr(Path, "mkdir", forbidden)
        exec(compile(source, "<synthetic-readonly-runner>", "exec"), fixture.__dict__)
        assert fixture.UNIT_TESTS == testing.UNIT_TESTS
    forbidden.assert_not_called()
