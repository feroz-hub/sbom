"""Readonly protected Runtime snapshots and real canonical Windows API branches."""

from __future__ import annotations

import ctypes
import json
import os
import socket
import subprocess
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev, dev_private
from scripts import dev_instance_storage as storage
from scripts import dev_workspace as workspace
from scripts import dev_workspace_bundle as bundle
from scripts import dev_workspace_inspect as inspect
from scripts import dev_workspace_operation_journal as operations

from tests.test_dev_windows_lifecycle import Kernel
from tests.test_dev_workspace_database_prepare import prepared as prepared

SECRET = "synthetic-private-error-password-never-print"


@pytest.fixture
def runtime_state(tmp_path_factory, prepared, monkeypatch):
    home = tmp_path_factory.mktemp("i").resolve() / "private-home"
    if os.name == "nt":
        storage._windows_create(home)
    else:
        home.mkdir(mode=0o700)
    descriptor = prepared.proposal.descriptor
    root = home / ".sbom-dev" / "instances" / descriptor.instance_id
    storage.initialize_private_directory(root, anchor=home)
    kernel = Kernel()

    class CtypesProxy:
        def __getattr__(self, name):
            return (lambda: kernel.last_error) if name == "get_last_error" else getattr(ctypes, name)

    monkeypatch.setattr(dev, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(dev, "ctypes", CtypesProxy())
    monkeypatch.setattr(dev, "_windows_kernel", lambda: kernel)
    launcher = kernel.add(900, 9000)
    services = {}
    for index, name in enumerate(inspect.runtime_adapter._LOGS):
        current = kernel.add(100 + index, 1000 + index)
        services[name] = {**current, "members": [current], "tree_unverified": False}
    state = {
        "version": 1,
        "root": str(root),
        "instance": "a" * 32,
        "profile": "workspace",
        "ready": True,
        "launcher_pid": 900,
        "launcher": launcher,
        "services": services,
        "workspace_context": {
            "repository_id": descriptor.repository_id,
            "worktree_id": descriptor.worktree_id,
            "instance_id": descriptor.instance_id,
            "root_identity": list(storage._identity(root.lstat())),
        },
        "private-extra": SECRET,
    }
    dev_private.create_private_file(root / ".dev-runtime.json", json.dumps(state).encode())
    return SimpleNamespace(home=home, root=root, descriptor=descriptor, kernel=kernel, state=state, prepared=prepared)


def rewrite(fixture):
    # Synthetic fixture writer only; production inspector never writes this file.
    (fixture.root / ".dev-runtime.json").write_text(json.dumps(fixture.state), encoding="utf-8")


def observe(fixture, **options):
    return inspect.inspect_instance(fixture.descriptor, root=fixture.root, anchor=fixture.home, launcher=dev, **options)


def service(report, name):
    return next(row for row in report.diagnostics if row.component == name)


def test_canonical_windows_running_snapshot_ignores_saved_ready_and_never_leaks_raw_state(runtime_state):
    result = observe(runtime_state)
    assert result.process_status == "RUNNING" and result.readiness_verified is False
    assert service(result, "Health").code == "READINESS_ADAPTER_REQUIRED"
    output = json.dumps(result.to_dict())
    assert SECRET not in output and runtime_state.state["services"]["API"]["exe"] not in output
    assert runtime_state.state["instance"] not in output
    assert result.to_dict()["saved_ready_flag_trusted"] is False
    runtime_state.kernel.TerminateProcess.assert_not_called()
    assert (
        runtime_state.kernel.OpenProcess.called
        and runtime_state.kernel.GetProcessTimes.called
        and runtime_state.kernel.QueryFullProcessImageNameW.called
    )
    assert runtime_state.kernel.closed


def test_readonly_runtime_and_optional_journal_have_mutation_process_network_and_lock_tripwires(
    runtime_state, monkeypatch
):
    before = (runtime_state.root / ".dev-runtime.json").read_bytes()
    forbidden = Mock(side_effect=AssertionError("Status attempted a mutation or external default"))
    original_open = os.open

    def readonly_open(path, flags, *arguments, **keywords):
        assert not flags & (os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_RDWR | os.O_APPEND)
        return original_open(path, flags, *arguments, **keywords)

    journal = operations.OperationJournal(home=runtime_state.home, instance_id=runtime_state.descriptor.instance_id)
    with monkeypatch.context() as guarded:
        for name in ("acquire", "release", "begin", "register", "refresh", "terminate", "stop_services"):
            guarded.setattr(dev.Runtime, name, forbidden)
        guarded.setattr(dev, "atomic_json", forbidden)
        guarded.setattr(dev_private, "create_private_file", forbidden)
        guarded.setattr(os, "mkdir", forbidden)
        guarded.setattr(os, "kill", forbidden)
        guarded.setattr(os, "killpg", forbidden, raising=False)
        guarded.setattr(os, "open", readonly_open)
        guarded.setattr(subprocess, "Popen", forbidden)
        guarded.setattr(subprocess, "run", forbidden)
        guarded.setattr(socket, "socket", forbidden)
        guarded.setattr(socket, "create_connection", forbidden)
        guarded.setattr(inspect.dev_instance_registry.InstanceRegistry, "_lock", forbidden)
        result = observe(runtime_state, operation_journal=journal)
    assert result.process_status == "RUNNING" and not (runtime_state.root / ".dev-runtime.lock").exists()
    assert before == (runtime_state.root / ".dev-runtime.json").read_bytes()
    forbidden.assert_not_called()


@pytest.mark.parametrize("operation", ["OpenProcess", "GetProcessTimes", "QueryFullProcessImageNameW"])
def test_native_api_access_denial_remains_unknown_with_structured_error_code(runtime_state, operation):
    runtime_state.kernel.fail(operation, 5)
    result = observe(runtime_state)
    assert result.process_status == "UNKNOWN"
    assert service(result, "API").process_status == "UNKNOWN" and service(result, "API").winerror == 5
    assert "winerror=5" not in json.dumps(result.to_dict())
    runtime_state.kernel.TerminateProcess.assert_not_called()


def test_message_only_windows_error_is_never_parsed(runtime_state, monkeypatch):
    def failure(_pid):
        raise dev.OwnershipError("private target; winerror=5; credential must not appear")

    monkeypatch.setattr(dev, "process_info", failure)
    result = observe(runtime_state)
    assert result.process_status == "UNKNOWN"
    assert all(item.winerror is None for item in result.diagnostics)
    assert "credential" not in json.dumps(result.to_dict())
    runtime_state.kernel.TerminateProcess.assert_not_called()


@pytest.mark.parametrize("operation", ["GetProcessTimes", "QueryFullProcessImageNameW"])
def test_exit_during_windows_inspection_reports_stopped_not_generic_inspection_failure(runtime_state, operation):
    runtime_state.kernel.fail(operation, 31, exit_process=True)
    result = observe(runtime_state)
    assert result.process_status == "STOPPED" and service(result, "API").code == "PROCESS_STOPPED"
    assert service(result, "API").process_status == "STOPPED"
    runtime_state.kernel.TerminateProcess.assert_not_called()


def test_pid_reuse_is_unknown_and_preserves_other_verified_process_observations(runtime_state):
    runtime_state.kernel.processes[103]["birth"] += 1
    result = observe(runtime_state)
    assert result.process_status == "PARTIAL" and service(result, "API").code == "PROCESS_IDENTITY_MISMATCH"
    assert service(result, "Frontend").process_status == "RUNNING"
    runtime_state.kernel.TerminateProcess.assert_not_called()


def test_launcher_exit_and_verified_member_orphans_remain_visible_and_protected(runtime_state):
    runtime_state.kernel.processes[900]["exited"] = True
    runtime_state.kernel.processes[100]["exited"] = True
    child = runtime_state.kernel.add(200, 2000)
    runtime_state.state["services"]["Celery worker"]["members"].append(child)
    rewrite(runtime_state)
    result = observe(runtime_state)
    assert result.process_status == "PARTIAL" and service(result, "Launcher").code == "LAUNCHER_EXITED"
    assert service(result, "Celery worker").process_status == "PARTIAL"
    runtime_state.kernel.TerminateProcess.assert_not_called()


def test_unknown_tree_and_missing_registration_never_become_stopped_permission(runtime_state):
    runtime_state.state["services"]["API"].pop("birth")
    runtime_state.state["services"]["Frontend"]["tree_unverified"] = True
    runtime_state.kernel.processes[104]["exited"] = True
    rewrite(runtime_state)
    result = observe(runtime_state)
    assert service(result, "API").code == "PROCESS_RECORD_INCOMPLETE"
    assert service(result, "Frontend").process_status == "UNKNOWN"
    assert result.process_status == "PARTIAL"


@pytest.mark.parametrize("binding", ["repository_id", "worktree_id", "instance_id", "root_identity"])
def test_wrong_workspace_context_refuses_all_process_queries(runtime_state, binding):
    runtime_state.state["workspace_context"][binding] = [0, 0] if binding == "root_identity" else "another-context"
    rewrite(runtime_state)
    result = observe(runtime_state)
    assert result.process_status == "UNKNOWN" and service(result, "Runtime").code == "RUNTIME_BINDING_MISMATCH"
    runtime_state.kernel.OpenProcess.assert_not_called()


def test_status_survives_missing_configuration_and_source_head_loss_without_source_discovery(
    runtime_state, monkeypatch
):
    forbidden = Mock(side_effect=AssertionError("Status loaded source or configuration"))
    monkeypatch.setattr(inspect.bundle, "inspect_source", forbidden)
    monkeypatch.setattr(workspace, "discover_workspaces", forbidden)
    result = observe(runtime_state, current_head=None, controller_changed=True)
    assert result.process_status == "RUNNING"
    assert (
        service(result, "Source").code == "SOURCE_DRIFT_NOT_CHECKED"
        and service(result, "Controller").code == "CONTROLLER_CHANGED"
    )
    forbidden.assert_not_called()


def test_posix_leader_exit_never_invokes_unbounded_group_or_ps_inspection(runtime_state, monkeypatch):
    monkeypatch.setattr(dev, "sys", SimpleNamespace(platform="linux"))
    recorded = {row["pid"]: row for row in runtime_state.state["services"].values()}
    recorded[900] = runtime_state.state["launcher"]
    monkeypatch.setattr(dev, "process_info", lambda pid: None if pid == 103 else recorded.get(pid))
    forbidden = Mock(side_effect=AssertionError("Unbounded process group/ps probe"))
    monkeypatch.setattr(dev, "group_members", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    result = observe(runtime_state)
    assert service(result, "API").code == "PROCESS_GROUP_INSPECTION_REQUIRED" and result.process_status == "PARTIAL"
    forbidden.assert_not_called()


def test_only_structured_allowlisted_windows_error_codes_are_projected(runtime_state, monkeypatch):
    error = PermissionError(SECRET)
    error.winerror = 5
    monkeypatch.setattr(dev, "process_info", Mock(side_effect=error))
    result = observe(runtime_state)
    assert service(result, "API").winerror == 5
    assert SECRET not in json.dumps(result.to_dict())


def test_provider_probe_requires_this_instance_recorded_ids_and_explicit_trusted_callback(runtime_state):
    candidate = runtime_state.prepared
    records = candidate.records
    attestation = inspect.ProviderAttestation(
        "f" * 64,
        runtime_state.descriptor.instance_id,
        records.engine_identity,
        records.provider_fingerprint,
        tuple(value.object_id for value in records.containers),
    )
    callback = Mock(return_value=inspect.ProviderObservation(attestation, "RUNNING"))
    result = observe(
        runtime_state, provider_records=records, provider_attestation=attestation, provider_inspector=callback
    )
    assert service(result, "Providers").result == "PASS" and callback.call_count == 1
    other = replace(attestation, instance_id="a1457128-2aaa-4141-ad12-34f3c49267e9")
    callback.reset_mock()
    refused = observe(runtime_state, provider_records=records, provider_attestation=other, provider_inspector=callback)
    assert service(refused, "Providers").code == "PROVIDER_RECORDED_IDENTITIES_REQUIRED"
    callback.assert_not_called()


def test_independent_readiness_is_bound_to_current_token_and_all_owned_pids(runtime_state):
    callback = Mock(
        side_effect=lambda token, pids, required, timeout: inspect.ReadinessObservation(token, pids, required)
    )
    result = observe(runtime_state, readiness=callback)
    assert result.readiness_verified is True and result.process_status == "RUNNING" and callback.call_count == 1
    callback.side_effect = lambda token, pids, required, timeout: inspect.ReadinessObservation("b" * 32, pids, required)
    result = observe(runtime_state, readiness=callback)
    assert result.readiness_verified is False and service(result, "Health").code == "READINESS_UNVERIFIED"


@pytest.mark.parametrize("changed_pid", [103, 900])
def test_process_exit_during_readiness_revokes_the_running_snapshot(runtime_state, changed_pid):
    def probe(token, pids, required, timeout):
        runtime_state.kernel.processes[changed_pid]["exited"] = True
        return inspect.ReadinessObservation(token, pids, required)

    result = observe(runtime_state, readiness=probe)
    assert result.process_status == "PARTIAL" and result.readiness_verified is False
    assert result.to_dict()["last_safe_error"]["pid"] == changed_pid
    runtime_state.kernel.TerminateProcess.assert_not_called()


def test_malformed_runtime_state_is_specific_and_does_not_query_processes(runtime_state):
    (runtime_state.root / ".dev-runtime.json").write_bytes((SECRET + " not JSON").encode())
    result = observe(runtime_state)
    assert result.process_status == "UNKNOWN" and service(result, "Runtime").code == "RUNTIME_STATE_UNVERIFIED"
    assert service(result, "Runtime").log_path == runtime_state.root / ".dev-logs" / "setup.log"
    assert SECRET not in json.dumps(result.to_dict())
    runtime_state.kernel.OpenProcess.assert_not_called()


def test_partial_runtime_does_not_invoke_optional_network_readiness(runtime_state):
    runtime_state.kernel.processes[103]["birth"] += 1
    callback = Mock(side_effect=AssertionError("Partial runtime must not contact service health"))
    result = observe(runtime_state, readiness=callback)
    assert result.process_status == "PARTIAL" and service(result, "Health").code == "READINESS_RUNTIME_REQUIRED"
    callback.assert_not_called()


def test_no_bundle_receipt_means_no_private_file_inspection_or_adoption(runtime_state, monkeypatch):
    forbidden = Mock(side_effect=AssertionError("Unknown bundle read"))
    monkeypatch.setattr(bundle, "_file", forbidden)
    assert service(observe(runtime_state), "Bundle").code == "BUNDLE_EXPECTED_RECEIPT_REQUIRED"
    forbidden.assert_not_called()


def test_trusted_bundle_receipt_checks_only_known_private_files_without_source_or_generation(
    runtime_state, monkeypatch
):
    candidate = runtime_state.prepared
    identity = workspace.FilesystemIdentity(runtime_state.home, *storage._identity(runtime_state.home.lstat()))
    plan = bundle.BundlePlan(
        candidate.proposal,
        None,
        identity,
        "8a4d0364-3897-4fba-9cc2-cdf9698e5ab6",
        {},
        None,
        30,
        "a" * 64,
        "b" * 64,
        "c" * 64,
    )
    storage.initialize_private_directory(plan.directory, anchor=runtime_state.home)
    for directory in ("provider", "keys", "tls"):
        storage.initialize_private_directory(plan.directory / directory, anchor=runtime_state.home)
    proofs = []
    for name in (*plan.files, ".env.dev.local", ".pending.json"):
        path = plan.directory / name
        dev_private.create_private_file(path, (SECRET + name).encode())
        _, proof = bundle._file(path, plan.directory)
        proofs.append((name, proof))
    directory_id = storage._identity(plan.directory.lstat())
    receipt_body = {
        "version": 1,
        "material_fingerprint": plan.material_fingerprint,
        "private_binding": plan.private_binding,
        "directory_identity": list(directory_id),
        "files": [[name, list(proof)] for name, proof in proofs],
    }
    dev_private.create_private_file(plan.directory / ".receipt.json", json.dumps(receipt_body).encode())
    _, receipt_proof = bundle._file(plan.directory / ".receipt.json", plan.directory)
    receipt = bundle.BundleReceipt(
        plan.material_fingerprint, plan.private_binding, directory_id, tuple(proofs), receipt_proof
    )
    forbidden = Mock(side_effect=AssertionError("Bundle status generated or rediscovered source"))
    with monkeypatch.context() as guarded:
        guarded.setattr(bundle, "_revalidate", forbidden)
        guarded.setattr(bundle, "generate_material", forbidden)
        guarded.setattr(bundle, "prepare_bundle", forbidden)
        guarded.setattr(subprocess, "Popen", forbidden)
        result = observe(runtime_state, bundle_plan=plan, expected_bundle=receipt)
    assert service(result, "Bundle").code == "BUNDLE_FILES_UNCHANGED"
    assert SECRET not in json.dumps(result.to_dict()) and receipt.private_binding not in json.dumps(result.to_dict())
    target = plan.directory / plan.files[0]
    target.write_bytes(b"synthetic-changed-file")
    assert (
        service(observe(runtime_state, bundle_plan=plan, expected_bundle=receipt), "Bundle").code
        == "BUNDLE_FILES_UNVERIFIED"
    )
    forbidden.assert_not_called()


@pytest.mark.parametrize(
    "constructor",
    [
        lambda: inspect.Diagnostic("API", "PASS", SECRET),
        lambda: inspect.InspectionReport("READY", ()),
        lambda: inspect.Diagnostic("API", "BLOCKED", "PROCESS_IDENTITY_UNVERIFIED", winerror=999999),
    ],
)
def test_public_dtos_fail_closed_on_unknown_or_private_claims(constructor):
    with pytest.raises(inspect.InspectionError) as caught:
        constructor()
    assert SECRET not in repr(caught.value)
