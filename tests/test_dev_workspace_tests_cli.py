"""Workspace-test CLI contracts with synthetic Git and stubbed test execution.

Run with --noconftest. No delegated pytest, application, DB, runtime, private
configuration, provider or existing directory is prepared or executed here.
"""

from __future__ import annotations

import builtins
import json
import socket
import subprocess
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev, dev_workspace
from scripts import dev_workspace_cli as cli
from scripts import dev_workspace_tests as testing

SECRET = "synthetic-private-child-output-credentials-and-token"
_DATA_PLAN = testing.plan_tests


@pytest.fixture
def checkout(tmp_path, monkeypatch):
    root = (tmp_path / "checkout").resolve()
    other = (tmp_path / "listed-worktree").resolve()
    root.mkdir(mode=0o700)
    other.mkdir(mode=0o700)

    def row(path, identifier):
        observed = path.stat()
        identity = dev_workspace.FilesystemIdentity(path, observed.st_dev, observed.st_ino)
        return dev_workspace.WorktreeSnapshot(identifier * 64, path, identity, "a" * 40,
                                             "refs/heads/synthetic", False, False, False, False, False)

    selected, second = row(root, "b"), row(other, "c")
    snapshot = dev_workspace.RepositorySnapshot("d" * 64, root, selected.identity, selected.head,
                                               (selected, second), selected.identity)
    discovery = Mock(return_value=snapshot)
    monkeypatch.setattr(dev_workspace, "discover_workspaces", discovery)
    plan = testing.TestPlan(snapshot.repository_id, selected.worktree_id, selected.head, "unit", root,
                            selected.identity, None, (), (), (), (), "e" * 64)
    planned = Mock(return_value=plan)
    result = testing.TestOutcome("TEST_UNIT_PASSED", 0, (("passed", 12), ("skipped", 1)), 0, True)
    executed = Mock(return_value=result)
    monkeypatch.setattr(testing, "plan_tests", planned)
    monkeypatch.setattr(testing, "run_tests", executed)
    return SimpleNamespace(root=root, other=other, snapshot=snapshot, selected=selected, second=second,
                           discovery=discovery, plan=plan, planned=planned, result=result, executed=executed)


@pytest.fixture(autouse=True)
def protected_boundaries(checkout, monkeypatch):
    forbidden = Mock(side_effect=AssertionError("Workspace test crossed a protected boundary"))
    for name in ("Runtime", "ensure_database", "ensure_dependencies", "ensure_frontend", "start_process",
                 "start_background", "start_application", "parse_args"):
        monkeypatch.setattr(dev, name, forbidden)
    for name in ("_registry", "_make_plan", "_prepare_registry", "_prepare_dependencies", "_lifecycle_blocked"):
        monkeypatch.setattr(cli, name, forbidden)
    monkeypatch.setattr(cli.dev_private, "create_private_file", forbidden)
    monkeypatch.setattr(cli.dev_instance_registry.InstanceRegistry, "publish", forbidden)
    monkeypatch.setattr(cli.dev_environment, "bounded_read_bytes", forbidden)
    monkeypatch.setattr(cli.dev_environment, "load_legacy_snapshots", forbidden)
    monkeypatch.setattr(cli.dev_environment, "resolve_existing", forbidden)
    monkeypatch.setattr(testing.dev_instance_storage, "initialize_private_directory", forbidden)
    monkeypatch.setattr(testing, "_execute", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    original_import = builtins.__import__

    def no_application_import(name, *arguments, **keywords):
        if name.split(".", 1)[0] in {"app", "psycopg", "sqlalchemy", "redis", "celery"}:
            return forbidden(name)
        return original_import(name, *arguments, **keywords)

    monkeypatch.setattr(builtins, "__import__", no_application_import)
    yield forbidden
    forbidden.assert_not_called()


@pytest.mark.parametrize("suite_arguments", [[], ["--suite", "unit"]])
def test_unit_plan_is_readonly_and_prints_public_fixed_scope(checkout, capsys, suite_arguments):
    assert cli.run_cli(["test", "--plan", "--json", *suite_arguments], checkout.root) == 0
    output = capsys.readouterr()
    assert not output.err
    result = json.loads(output.out)
    assert result == checkout.plan.to_dict()
    assert result["scope"] == "pure-development-contracts"
    assert result["tests"] == list(testing.UNIT_TESTS)
    assert result["database_authorized"] is False and result["application_readiness_verified"] is False
    checkout.planned.assert_called_once_with(checkout.root, worktree_id=checkout.selected.worktree_id, suite="unit")
    checkout.executed.assert_not_called()


def test_human_plan_never_reports_executed_tests_or_starts_runner(checkout, capsys):
    assert cli.run_cli(["test", "--plan"], checkout.root) == 0
    output = capsys.readouterr()
    assert "[PLANNED]" in output.out and "pure-contract" in output.out
    assert "[PASS]" not in output.out and not output.err
    checkout.executed.assert_not_called()


@pytest.mark.parametrize("as_json", [False, True])
def test_unit_execution_returns_only_validated_outcome(checkout, capsys, as_json):
    assert cli.run_cli(["test", "--suite", "unit", *(["--json"] if as_json else [])], checkout.root) == 0
    output = capsys.readouterr()
    assert not output.err
    document = json.loads(output.out if as_json else output.out.splitlines()[1])
    assert document == checkout.result.to_dict()
    assert document["counts"] == {"passed": 12, "skipped": 1}
    assert document["cleanup_scope"] == "original-test-child"
    assert document["database_authorized"] is False
    checkout.executed.assert_called_once_with(checkout.plan)


def test_selected_listed_worktree_is_the_only_target_sent_to_test_planner(checkout, capsys):
    checkout.planned.return_value = replace(checkout.plan, root=checkout.other,
                                            root_identity=checkout.second.identity,
                                            worktree_id=checkout.second.worktree_id)
    assert cli.run_cli(["test", "--worktree", str(checkout.other), "--plan", "--json"], checkout.root) == 0
    assert json.loads(capsys.readouterr().out)["worktree_id"] == checkout.second.worktree_id
    checkout.planned.assert_called_once_with(checkout.other, worktree_id=checkout.second.worktree_id, suite="unit")
    checkout.executed.assert_not_called()


@pytest.mark.parametrize("as_json", [False, True])
@pytest.mark.parametrize("plan_flag", [False, True])
def test_missing_prepared_stamp_is_blocked_without_runner(checkout, capsys, as_json, plan_flag):
    checkout.planned.return_value = replace(checkout.plan, blockers=("TEST_VENV_PREPARATION_REQUIRED",))
    arguments = ["test", *(["--json"] if as_json else []), *(["--plan"] if plan_flag else [])]
    assert cli.run_cli(arguments, checkout.root) == 1
    output = capsys.readouterr()
    assert "TEST_VENV_PREPARATION_REQUIRED" in output.out and not output.err
    if as_json:
        assert json.loads(output.out)["blockers"] == ["TEST_VENV_PREPARATION_REQUIRED"]
    checkout.executed.assert_not_called()


@pytest.mark.parametrize("suite", ["database", "integration", "migrations", "all"])
@pytest.mark.parametrize("plan_flag", [False, True])
def test_data_suite_uses_real_unconditional_gate_despite_untrusted_readiness_markers(
    checkout, monkeypatch, capsys, suite, plan_flag,
):
    for name in ("DATABASE_URL", "TEST_DATABASE_URL", "TEST_POSTGRES_DATABASE_URL", "SBOM_DEV_TEST_AUTHORIZED",
                 "SBOM_DEV_READY", "NATIVE_PLATFORM_BOOTSTRAP_ENABLED", "PYTEST_ADDOPTS"):
        monkeypatch.setenv(name, SECRET)
    monkeypatch.setattr(testing, "plan_tests", _DATA_PLAN)
    arguments = ["test", "--suite", suite, "--worktree", str(checkout.root / SECRET), "--json"]
    if plan_flag:
        arguments.append("--plan")
    assert cli.run_cli(arguments, checkout.root) == 1
    output = capsys.readouterr()
    result = json.loads(output.out)
    assert result["blockers"] == ["DISPOSABLE_TARGET_AUTHORIZATION_REQUIRED"]
    assert result["tests"] == [] and result["database_authorized"] is False
    assert SECRET not in output.out + output.err
    checkout.discovery.assert_not_called()
    checkout.executed.assert_not_called()


def test_unlisted_unit_worktree_is_refused_before_any_test_planning(checkout, capsys):
    assert cli.run_cli(["test", "--worktree", str(checkout.root / SECRET), "--json"], checkout.root) == 1
    output = capsys.readouterr()
    assert json.loads(output.out) == {"status": "BLOCKED", "code": "WORKSPACE_TARGET_BLOCKED"}
    assert SECRET not in output.out + output.err
    checkout.planned.assert_not_called()
    checkout.executed.assert_not_called()


@pytest.mark.parametrize("change", [{"status": "UNKNOWN"}, {"locked": True}, {"prunable": True}, {"bare": True}])
def test_unusable_worktree_inventory_cannot_reach_unit_runner(checkout, capsys, change):
    selected = replace(checkout.selected, **change)
    checkout.discovery.return_value = replace(checkout.snapshot, worktrees=(selected,))
    assert cli.run_cli(["test", "--json"], checkout.root) == 1
    assert json.loads(capsys.readouterr().out)["code"] == "WORKSPACE_TARGET_BLOCKED"
    checkout.planned.assert_not_called()
    checkout.executed.assert_not_called()


@pytest.mark.parametrize("arguments", [
    ["--mode", "isolated"], ["--auth", "native"], ["--provider", "container"], ["--generation", "1"],
    ["--scope", "registry"], ["--scope", "dependencies"], ["--port-min", "20001"], ["--port-max", "30000"],
])
def test_mutable_instance_and_preparation_options_are_refused_for_test(checkout, capsys, arguments):
    assert cli.run_cli(["test", *arguments, "--json"], checkout.root) == 1
    assert json.loads(capsys.readouterr().out)["code"] == "WORKSPACE_TEST_SELECTION_INVALID"
    checkout.discovery.assert_not_called()
    checkout.planned.assert_not_called()
    checkout.executed.assert_not_called()


@pytest.mark.parametrize("arguments", [
    ["--suite", SECRET], ["--suite", "tests/" + SECRET + ".py"], ["--suite", "unit -p " + SECRET],
    ["--pytest-args", SECRET], ["--plugin", SECRET], ["--venv", SECRET], ["--force", SECRET],
    ["--confirm-database", SECRET], ["--migrate", SECRET], ["--password", SECRET], [SECRET],
])
def test_unknown_suites_paths_arguments_and_mutation_flags_are_redacted_parser_errors(checkout, capsys, arguments):
    with pytest.raises(SystemExit) as caught:
        cli.run_cli(["test", *arguments, "--json"], checkout.root)
    assert caught.value.code == 2
    output = capsys.readouterr()
    assert "WORKSPACE_ARGUMENTS_INVALID" in output.err
    assert SECRET not in output.out + output.err
    checkout.discovery.assert_not_called()
    checkout.planned.assert_not_called()
    checkout.executed.assert_not_called()


@pytest.mark.parametrize("command", ["list", "plan", "prepare", "start", "stop", "restart", "status", "diagnose", "logs", "compare"])
@pytest.mark.parametrize("option", [["--plan"], ["--suite", "unit"]])
def test_test_only_options_are_refused_before_every_other_command_dispatch(checkout, capsys, command, option):
    assert cli.run_cli([command, *option, "--json"], checkout.root) == 1
    assert json.loads(capsys.readouterr().out)["code"] == "WORKSPACE_TEST_OPTIONS_REQUIRED"
    checkout.discovery.assert_not_called()
    checkout.planned.assert_not_called()
    checkout.executed.assert_not_called()


@pytest.mark.parametrize("as_json", [False, True])
def test_raw_child_output_and_trace_attributes_are_never_echoed(checkout, capsys, as_json):
    outcome = testing.TestOutcome("TEST_UNIT_FAILED", 1, (("failed", 1), ("passed", 2)), 1, True)
    checkout.executed.return_value = SimpleNamespace(
        code=outcome.code, exit_code=outcome.exit_code, retained_directory=None, to_dict=outcome.to_dict,
        stdout=SECRET, stderr=SECRET, traceback=SECRET, output=SECRET,
    )
    assert cli.run_cli(["test", *(["--json"] if as_json else [])], checkout.root) == 1
    output = capsys.readouterr()
    assert "TEST_UNIT_FAILED" in output.out and SECRET not in output.out + output.err
    assert '"failed": 1' in output.out and "stdout" not in output.out and "traceback" not in output.out


@pytest.mark.parametrize("stage", ["planning", "execution"])
def test_unexpected_adapter_exception_is_redacted_and_never_causes_fallback(checkout, capsys, stage):
    (checkout.planned if stage == "planning" else checkout.executed).side_effect = RuntimeError(SECRET)
    assert cli.run_cli(["test", "--json"], checkout.root) == 1
    output = capsys.readouterr()
    assert json.loads(output.out) == {"status": "BLOCKED", "code": "WORKSPACE_INSPECTION_FAILED"}
    assert SECRET not in output.out + output.err
    if stage == "planning":
        checkout.executed.assert_not_called()


@pytest.mark.parametrize("code,exit_code", [("TEST_PLAN_CHANGED", 1), ("TEST_EXECUTION_CANCELLED", 130),
                                           ("TEST_CHILD_CLEANUP_UNCONFIRMED", 1)])
def test_safe_failure_and_cancellation_outcomes_preserve_exit_status(checkout, capsys, code, exit_code):
    checkout.executed.return_value = testing.TestOutcome(code, exit_code)
    assert cli.run_cli(["test", "--json"], checkout.root) == exit_code
    assert json.loads(capsys.readouterr().out)["code"] == code
