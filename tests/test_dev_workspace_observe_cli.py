"""Actual observer CLI boundaries using disposable metadata and private logs."""

from __future__ import annotations

import builtins
import io
import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev, dev_instance_plan, dev_instance_registry, dev_instance_storage, dev_private, dev_workspace
from scripts import dev_workspace_cli as cli
from scripts import dev_workspace_dependencies as dependencies
from scripts import dev_workspace_observe as observe

SECRET = "synthetic-private-observation-value-never-output"


@pytest.fixture
def observed(tmp_path, monkeypatch):
    anchor = tmp_path.resolve()
    baseline, candidate, home = anchor / "baseline checkout", anchor / "candidate checkout", anchor / "private home"
    baseline.mkdir()
    candidate.mkdir()
    if sys.platform == "win32":
        dev_instance_storage._windows_create(home)  # Only this new fixture-owned home; no ACL repair.
    else:
        home.mkdir(mode=0o700)
    rows = []
    entries = []
    for index, root in enumerate((baseline, candidate)):
        identity = dev_workspace.FilesystemIdentity(root, root.stat().st_dev, root.stat().st_ino)
        row = dev_workspace.WorktreeSnapshot(
            ("b" if index == 0 else "d") * 64, root, identity, ("c" if index == 0 else "e") * 40,
            "refs/heads/" + ("baseline" if index == 0 else "candidate"),
            detached=False, bare=False, dirty=bool(index), locked=False, prunable=False,
        )
        rows.append(row)
        descriptor = dev_instance_plan.plan_instance(
            repository_id="a" * 64, worktree_id=row.worktree_id, commit="c" * 40, generation=1,
            mode="mock" if index == 0 else "isolated", auth_mode="native",
        ).descriptor
        entries.append(dev_instance_registry.RegistryEntry(descriptor, state="READY"))
    snapshot = dev_workspace.RepositorySnapshot("a" * 64, candidate, rows[1].identity, rows[1].head,
                                                tuple(rows), rows[0].identity)
    directory = home / ".sbom-dev/instances" / entries[1].descriptor.instance_id / ".dev-logs"
    dev_instance_storage.initialize_private_directory(directory, anchor=home)
    log = directory / "api.log"
    content = (
        "2026-10-31T10:20:30Z ERROR exception_class=PermissionError winerror=5 status=UNKNOWN " + SECRET + "\n"
        + json.dumps({"timestamp": "2026-10-31T10:20:31Z", "level": "INFO", "exception_class": "TimeoutError",
                      "winerror": 1460, "status": "STOPPED", "message": SECRET,
                      "DATABASE_URL": "postgresql://user:" + SECRET + "@localhost/private"}) + "\n"
    ).encode()
    dev_private.create_private_file(log, content)
    protected = {candidate / ".dev-runtime.json": b"unknown ownership; preserve", candidate / ".env.dev.local": SECRET.encode()}
    for path, value in protected.items():
        path.write_bytes(value)
    records = dev_instance_registry.RegistrySnapshot(tuple(entries))
    discover, read = Mock(return_value=snapshot), Mock(return_value=records)
    forbidden = Mock(side_effect=AssertionError("Read-only observation attempted mutation or service access"))
    monkeypatch.setattr(dev_workspace, "discover_workspaces", discover)
    monkeypatch.setattr(dev_workspace, "_run_git", forbidden)
    monkeypatch.setattr(cli, "_registry", Mock(return_value=SimpleNamespace(read=read, publish=forbidden)))
    monkeypatch.setattr(cli.Path, "home", classmethod(lambda cls: home))
    for name in ("Runtime", "start_process", "start_background", "start_application", "ensure_database", "setup_application"):
        monkeypatch.setattr(dev, name, forbidden)
    monkeypatch.setattr(dev_instance_registry.InstanceRegistry, "publish", forbidden)
    monkeypatch.setattr(dependencies, "prepare_dependencies", forbidden)
    monkeypatch.setattr(dev_private, "create_private_file", forbidden)
    monkeypatch.setattr(dev_instance_storage, "initialize_private_directory", forbidden)
    monkeypatch.setattr(dev_instance_storage, "_windows_create", forbidden)
    public_read = cli.dev_environment.bounded_read_bytes
    public_paths = {root / name for root in (baseline, candidate)
                    for name in ("requirements.txt", "frontend/package.json", "frontend/package-lock.json",
                                 *cli._CONTROLLER_SOURCES)}

    def public_manifest_read(path, limit):
        if Path(path) not in public_paths:
            forbidden()
        return public_read(path, limit)

    monkeypatch.setattr(cli.dev_environment, "bounded_read_bytes", public_manifest_read)
    monkeypatch.setattr(cli.dev_environment, "bounded_read_text", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    for name in ("Popen", "run", "check_output"):
        monkeypatch.setattr(subprocess, name, forbidden)
    for name in ("mkdir", "makedirs", "rename", "replace", "remove", "unlink", "rmdir", "kill", "system"):
        monkeypatch.setattr(os, name, forbidden)
    original_open, original_io_open, original_os_open = builtins.open, io.open, os.open

    def readonly_open(original):
        def check(path, mode="r", *args, **kwargs):
            if any(marker in mode for marker in "wax+"):
                forbidden()
            if isinstance(path, (str, bytes, os.PathLike)) and Path(path) in protected:
                forbidden()
            return original(path, mode, *args, **kwargs)
        return check

    opened = []

    def readonly_descriptor(path, flags, *args, **kwargs):
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            forbidden()
        if Path(path) in protected:
            forbidden()
        opened.append(Path(path))
        return original_os_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", readonly_open(original_open))
    monkeypatch.setattr(io, "open", readonly_open(original_io_open))
    monkeypatch.setattr(os, "open", readonly_descriptor)
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        assert name.split(".", 1)[0] not in {"app", "dotenv", "psycopg", "sqlalchemy", "celery", "redis"}
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    cpu = Mock(return_value=8)
    disk = Mock(return_value=SimpleNamespace(total=100000, free=50000))
    monkeypatch.setattr(observe.os, "cpu_count", cpu)
    monkeypatch.setattr(observe.shutil, "disk_usage", disk)
    yield SimpleNamespace(root=candidate, baseline=baseline, home=home, rows=rows, entries=entries,
                          snapshot=snapshot, discover=discover, read=read, records=records, log=log,
                          opened=opened, cpu=cpu, disk=disk, forbidden=forbidden)
    forbidden.assert_not_called()
    for path, value in {**protected, log: content}.items():
        with original_open(path, "rb") as stream:
            assert stream.read() == value


def test_compare_uses_actual_public_observer_without_inventing_acceptance(observed, capsys):
    assert cli.run_cli(["compare", "--baseline", str(observed.baseline), "--json"], observed.root) == 0
    captured = capsys.readouterr()
    public = json.loads(captured.out)
    assert public["status"] == "OBSERVED"
    assert {"COMMIT", "BRANCH", "DIRTY", "MODE", "CANDIDATE_HEAD_DRIFT"} <= set(public["differences"])
    assert public["baseline"]["reported_registry_state"] == "READY"
    assert public["candidate"]["registered_head_drift"] is True
    assert all(public[name] is False for name in ("runtime_verified", "api_verified", "visual_verified", "acceptance_verified"))
    assert public["candidate"]["proposed_urls"]["frontend"].startswith("https://")
    assert SECRET not in captured.out + captured.err and str(observed.root) not in captured.out
    assert observed.opened == []


@pytest.mark.parametrize("fault,code", [("same", "COMPARISON_DISTINCT_WORKTREES_REQUIRED"),
                                       ("unlisted", "WORKSPACE_TARGET_BLOCKED"),
                                       ("registry", "COMPARISON_REGISTRY_UNVERIFIED")])
def test_compare_refuses_unverifiable_targets_and_registry(observed, capsys, fault, code):
    baseline = observed.root if fault == "same" else observed.baseline
    if fault == "unlisted":
        baseline = observed.root.parent / "not listed"
    if fault == "registry":
        observed.read.return_value = dev_instance_registry.RegistrySnapshot(codes=("REGISTRY_UNKNOWN_ARTIFACT",))
    assert cli.run_cli(["compare", "--baseline", str(baseline), "--json"], observed.root) == 1
    public = json.loads(capsys.readouterr().out)
    assert code in public.get("codes", [public.get("code")])


def test_compare_requires_baseline_without_guessing_source(observed, capsys):
    assert cli.run_cli(["compare", "--json"], observed.root) == 1
    assert json.loads(capsys.readouterr().out)["code"] == "WORKSPACE_BASELINE_REQUIRED"
    observed.discover.assert_not_called()


@pytest.mark.parametrize("command", ["list", "status", "diagnose"])
@pytest.mark.parametrize("registered", [False, True])
def test_git_inventory_never_reports_application_ready(observed, monkeypatch, capsys, command, registered):
    if not registered:
        observed.read.return_value = dev_instance_registry.RegistrySnapshot(codes=("REGISTRY_MISSING",))
        monkeypatch.setattr(dev_instance_plan, "plan_instance", observed.forbidden)
    assert cli.run_cli([command, "--json"], observed.root) == (0 if command == "list" else 1)
    public = json.loads(capsys.readouterr().out)
    assert public["git_status"] == "PASS" and public["application_readiness_verified"] is False
    assert public["status"] == ("PASS" if command == "list" else "BLOCKED")
    for row in public["worktrees"]:
        assert row["runtime_ownership"] == "UNVERIFIED"
        if command != "list":
            diagnostics = row["diagnostics"]
            assert diagnostics["acceptance_verified"] is False and diagnostics["runtime_verified"] is False
            assert all(check["status"] in {"BLOCKED", "SKIPPED"} for check in diagnostics["results"])
            if not registered:
                assert all(check["code"] == "INSTANCE_METADATA_REQUIRED" for check in diagnostics["results"])
    observed.cpu.assert_not_called()
    observed.disk.assert_not_called()


@pytest.mark.parametrize("command", ["status", "diagnose"])
def test_explicit_host_observation_remains_separate_from_health_and_acceptance(observed, capsys, command):
    assert cli.run_cli([command, "--host", "--json"], observed.root) == 1
    public = json.loads(capsys.readouterr().out)
    diagnostics = public["worktrees"][0]["diagnostics"]
    assert diagnostics["host"] == {"cpu_count": 8, "disk_total": 100000, "disk_free": 50000}
    assert diagnostics["acceptance_verified"] is False and public["status"] == "BLOCKED"
    assert diagnostics["results"][-1] == {"category": "host", "status": "OBSERVED", "code": "HOST_CAPACITY_OBSERVED"}
    observed.cpu.assert_called_once_with()
    observed.disk.assert_called_once_with(observed.home)


@pytest.mark.parametrize("lines", [1, 80, 200])
def test_real_private_log_projection_reaches_cli_as_redacted_metadata_only(observed, capsys, lines):
    assert cli.run_cli(["logs", "--service", "api", "--lines", str(lines), "--json"], observed.root) == 0
    captured = capsys.readouterr()
    public = json.loads(captured.out)
    assert public["status"] == "OBSERVED" and public["component"] == "api"
    assert public["runtime_verified"] is False and public["code"] == "INSTANCE_LOG_METADATA_OBSERVED"
    assert public["records"][-1]["winerror"] == 1460
    assert len(public["records"]) == (1 if lines == 1 else 2)
    assert SECRET not in captured.out + captured.err and "postgresql://" not in captured.out
    assert str(observed.log) not in captured.out and "message" not in public["records"][0]
    assert observed.opened == [observed.log]


@pytest.mark.parametrize("service,status,code,exit_code", [
    ("frontend", "SKIPPED", "INSTANCE_LOG_MISSING", 0),
    ("postgres", "BLOCKED", "INSTANCE_PROVIDER_LOG_ADAPTER_REQUIRED", 1),
    ("redis", "BLOCKED", "INSTANCE_PROVIDER_LOG_ADAPTER_REQUIRED", 1),
    ("mailpit", "BLOCKED", "INSTANCE_PROVIDER_LOG_ADAPTER_REQUIRED", 1),
])
def test_missing_and_provider_logs_do_not_create_files_or_contact_engine(observed, capsys, service, status, code, exit_code):
    assert cli.run_cli(["logs", "--service", service, "--json"], observed.root) == exit_code
    public = json.loads(capsys.readouterr().out)
    assert public["status"] == status and public["code"] == code and not public["records"]
    assert public["runtime_verified"] is False and observed.opened == []


def test_uncertain_private_log_ownership_is_blocked_without_disclosing_exception(observed, monkeypatch, capsys):
    monkeypatch.setattr(observe, "_file", Mock(side_effect=PermissionError(SECRET)))
    assert cli.run_cli(["logs", "--json"], observed.root) == 1
    captured = capsys.readouterr()
    public = json.loads(captured.out)
    assert public["status"] == "BLOCKED" and public["code"] == "INSTANCE_LOG_READ_BLOCKED"
    assert SECRET not in captured.out + captured.err and observed.opened == []


def test_follow_is_bounded_and_deduplicates_ndjson_without_real_sleep(observed, monkeypatch, capsys):
    now, sleeps = [0.0], []
    monkeypatch.setattr(cli.time, "monotonic", lambda: now[0])

    def advance(seconds):
        assert seconds == 0.5
        sleeps.append(seconds)
        now[0] += 15  # Accelerate the synthetic clock; no real sleeping.

    monkeypatch.setattr(cli.time, "sleep", advance)
    assert cli.run_cli(["logs", "--follow", "--json"], observed.root) == 0
    public = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(public) == 1 and public[0]["status"] == "OBSERVED"
    assert now[0] == 30 and sleeps == [0.5, 0.5]
    assert observed.opened == [observed.log] * 3


def test_follow_cancellation_preserves_runtime_and_returns_130(observed, monkeypatch, capsys):
    monkeypatch.setattr(cli.time, "sleep", Mock(side_effect=KeyboardInterrupt))
    assert cli.run_cli(["logs", "--follow", "--json"], observed.root) == 130
    public = json.loads(capsys.readouterr().out)
    assert public["runtime_verified"] is False and public["status"] == "OBSERVED"
    assert observed.opened == [observed.log]


@pytest.mark.parametrize("lines", [0, 201, -1])
def test_invalid_log_bounds_refuse_before_inventory_or_file_inspection(observed, capsys, lines):
    assert cli.run_cli(["logs", "--lines", str(lines), "--json"], observed.root) == 1
    assert json.loads(capsys.readouterr().out)["code"] == "WORKSPACE_LOG_LIMIT_INVALID"
    observed.discover.assert_not_called()
    assert observed.opened == []


@pytest.mark.parametrize("arguments", [
    ["list", "--baseline", "not-selected"], ["status", "--service", "api"], ["compare", "--follow"],
    ["plan", "--host"], ["logs", "--baseline", "not-selected"], ["diagnose", "--lines", "1"],
])
def test_cross_command_observation_flags_are_refused_before_inventory(observed, capsys, arguments):
    assert cli.run_cli([*arguments, "--json"], observed.root) == 1
    assert json.loads(capsys.readouterr().out)["code"] == "WORKSPACE_OBSERVATION_OPTIONS_REQUIRED"
    observed.discover.assert_not_called()


@pytest.mark.parametrize("arguments", [["logs", "--service", SECRET], ["logs", "--lines", SECRET],
                                       ["diagnose", "--password", SECRET]])
def test_invalid_values_and_unknown_arguments_are_redacted(observed, capsys, arguments):
    with pytest.raises(SystemExit) as caught:
        cli.run_cli(arguments, observed.root)
    assert caught.value.code == 2
    output = capsys.readouterr()
    assert "WORKSPACE_ARGUMENTS_INVALID" in output.err and SECRET not in output.out + output.err
    observed.discover.assert_not_called()


@pytest.mark.parametrize("stamped,blockers,status,code", [
    (False, (), "BLOCKED", "DEPENDENCY_PREPARATION_REQUIRED"),
    (True, (), "WARN", "DEPENDENCY_PACKAGE_VERIFICATION_REQUIRED"),
    (False, ("DEPENDENCY_ROOT_ACCESS_REVIEW_REQUIRED",), "BLOCKED", "DEPENDENCY_ROOT_ACCESS_REVIEW_REQUIRED"),
])
def test_diagnose_software_summary_distinguishes_preparation_verification_and_access_review(
    observed, monkeypatch, capsys, stamped, blockers, status, code
):
    hashes = {"requirements.txt": "1" * 64, "frontend/package.json": "2" * 64,
              "frontend/package-lock.json": "3" * 64}
    manifest = Mock(return_value=hashes)
    versions = {} if blockers else {"python": (3, 12, 7), "node": (26, 1, 0)}
    actions = ("verify-python", "verify-frontend") if stamped else ("prepare-python", "prepare-frontend")
    inspector = Mock(return_value=SimpleNamespace(
        blockers=blockers, target_stamps={"python": "a" * 64 if stamped else None,
                                         "frontend": "b" * 64 if stamped else None},
        tool_versions=versions, actions=actions,
    ))
    monkeypatch.setattr(cli, "_manifest_hashes", manifest)
    monkeypatch.setattr(dependencies, "inspect_dependencies", inspector)
    assert cli.run_cli(["diagnose", "--json"], observed.root) == 1
    public = json.loads(capsys.readouterr().out)
    result = public["worktrees"][0]["dependency_observation"]
    assert result == {"status": status, "code": code,
                      "tool_versions": {key: list(value) for key, value in versions.items()},
                      "actions": list(actions), "package_verification_performed": False, "compiler_verified": False}
    assert public["application_readiness_verified"] is False and public["status"] == "BLOCKED"
    manifest.assert_called_once_with(observed.root, observed.rows[1].identity,
                                    observed.snapshot.root, observed.snapshot.identity)
    inspector.assert_called_once_with(observed.snapshot, observed.rows[1], manifest_hashes=hashes)
    observed.discover.assert_called_once_with(observed.root)
    assert observed.opened == []


def test_diagnose_software_exception_is_redacted_and_does_not_change_other_results(observed, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_manifest_hashes", Mock(return_value={"requirements.txt": "1" * 64}))
    inspector = Mock(side_effect=RuntimeError(SECRET))
    monkeypatch.setattr(dependencies, "inspect_dependencies", inspector)
    assert cli.run_cli(["diagnose", "--json"], observed.root) == 1
    captured = capsys.readouterr()
    public = json.loads(captured.out)
    assert public["worktrees"][0]["dependency_observation"] == {
        "status": "BLOCKED", "code": "WORKSPACE_PUBLIC_SOFTWARE_INSPECTION_UNVERIFIED",
        "package_verification_performed": False, "compiler_verified": False,
    }
    assert len(public["worktrees"][0]["diagnostics"]["results"]) == 9
    assert SECRET not in captured.out + captured.err and observed.opened == []
    observed.discover.assert_called_once_with(observed.root)


@pytest.mark.parametrize("command", ["list", "status"])
def test_quick_inventory_and_status_do_not_run_software_inspector(observed, monkeypatch, capsys, command):
    manifest = Mock(side_effect=AssertionError("Quick inventory inspected software manifests"))
    inspector = Mock(side_effect=AssertionError("Quick inventory inspected software packages"))
    monkeypatch.setattr(cli, "_manifest_hashes", manifest)
    monkeypatch.setattr(dependencies, "inspect_dependencies", inspector)
    assert cli.run_cli([command, "--json"], observed.root) == (0 if command == "list" else 1)
    public = json.loads(capsys.readouterr().out)
    assert all("dependency_observation" not in row for row in public["worktrees"])
    manifest.assert_not_called()
    inspector.assert_not_called()
    observed.discover.assert_called_once_with(observed.root)


def test_missing_public_manifests_produce_safe_unverified_software_diagnosis(observed, capsys):
    assert cli.run_cli(["diagnose", "--json"], observed.root) == 1
    public = json.loads(capsys.readouterr().out)
    assert public["worktrees"][0]["dependency_observation"]["code"] == "WORKSPACE_PUBLIC_SOFTWARE_INSPECTION_UNVERIFIED"
    assert not public["worktrees"][0]["dependency_observation"]["package_verification_performed"]


def test_fresh_inventory_reuses_readonly_software_summary_once_without_preparation(observed, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_manifest_hashes", Mock(return_value={"requirements.txt": "1" * 64}))
    inspector = Mock(return_value=SimpleNamespace(
        blockers=(), target_stamps={"python": None, "frontend": None}, tool_versions={"python": (3, 12, 7)},
        actions=("prepare-python", "prepare-frontend"),
    ))
    monkeypatch.setattr(dependencies, "inspect_dependencies", inspector)
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/public/bin/" + name)
    assert cli.initial_inventory(observed.root) == 1
    captured = capsys.readouterr()
    assert "DEPENDENCY_PREPARATION_REQUIRED" in captured.out
    assert "package/compiler readiness remains unverified" in captured.out
    assert SECRET not in captured.out + captured.err
    inspector.assert_called_once()
    observed.discover.assert_called_once_with(observed.root)
    assert observed.opened == []
