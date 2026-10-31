"""Actual public onboarding CLI planning with no installation inspection."""

from __future__ import annotations

import builtins
import io
import json
import os
import socket
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev, dev_instance_plan, dev_instance_registry, dev_workspace
from scripts import dev_workspace_cli as cli
from scripts import dev_workspace_dependencies as dependencies
from scripts import dev_workspace_onboarding as onboarding

SECRET = "synthetic-onboarding-private-value-never-output"


@pytest.fixture
def checkout(tmp_path, monkeypatch):
    root = tmp_path.resolve() / "public checkout with spaces"
    root.mkdir()
    (root / "frontend").mkdir()
    (root / "scripts").mkdir()
    for name in ("requirements.txt", "frontend/package.json", "frontend/package-lock.json", *cli._CONTROLLER_SOURCES):
        (root / name).write_text("public synthetic source: " + name, encoding="utf-8")
    protected = {root / ".env.dev.local": SECRET.encode(), root / "frontend/.env.local": SECRET.encode(),
                 root / ".dev-runtime.json": b"unknown ownership; preserve"}
    for path, content in protected.items():
        path.write_bytes(content)
    identity = dev_workspace.FilesystemIdentity(root, root.stat().st_dev, root.stat().st_ino)
    row = dev_workspace.WorktreeSnapshot(
        "b" * 64, root, identity, "c" * 40, "refs/heads/synthetic", False, False, False, False, False
    )
    snapshot = dev_workspace.RepositorySnapshot("a" * 64, root, identity, row.head, (row,), identity)
    discover = Mock(return_value=snapshot)
    read = Mock(return_value=dev_instance_registry.RegistrySnapshot(codes=("REGISTRY_MISSING",)))
    forbidden = Mock(side_effect=AssertionError("Onboarding guidance attempted inspection, collection or mutation"))
    registry = SimpleNamespace(read=read, publish=forbidden)
    monkeypatch.setattr(dev_workspace, "discover_workspaces", discover)
    monkeypatch.setattr(cli, "_registry", Mock(return_value=registry))
    monkeypatch.setattr(onboarding, "OnboardingContext", forbidden)
    monkeypatch.setattr(onboarding, "PublicEnrollmentStatus", forbidden)
    monkeypatch.setattr(onboarding, "plan_onboarding", forbidden)
    monkeypatch.setattr(onboarding, "revalidate_onboarding", forbidden)
    monkeypatch.setattr(dependencies, "prepare_dependencies", forbidden)
    monkeypatch.setattr(dev_instance_registry.InstanceRegistry, "publish", forbidden)
    for name in ("Runtime", "start_application", "start_process", "start_background", "ensure_dependencies",
                 "ensure_frontend", "ensure_database", "setup_application", "_apply_setup_application"):
        monkeypatch.setattr(dev, name, forbidden)
    monkeypatch.setattr(builtins, "input", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    for name in ("Popen", "run", "check_output"):
        monkeypatch.setattr(subprocess, name, forbidden)
    for name in ("mkdir", "makedirs", "rename", "replace", "remove", "unlink", "rmdir", "kill", "system"):
        monkeypatch.setattr(os, name, forbidden)
    original_open, original_io_open, original_os_open = builtins.open, io.open, os.open

    def readonly_open(original):
        def check(file, mode="r", *args, **kwargs):
            if any(marker in mode for marker in "wax+"):
                forbidden()
            if isinstance(file, (str, bytes, os.PathLike)) and Path(file) in protected:
                forbidden()
            return original(file, mode, *args, **kwargs)
        return check

    def readonly_descriptor(path, flags, *args, **kwargs):
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            forbidden()
        if Path(path) in protected:
            forbidden()
        return original_os_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", readonly_open(original_open))
    monkeypatch.setattr(io, "open", readonly_open(original_io_open))
    monkeypatch.setattr(os, "open", readonly_descriptor)
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        assert name.split(".", 1)[0] not in {"app", "psycopg", "sqlalchemy", "redis", "celery", "uvicorn"}
        assert "dev_native_enrollment" not in name and "bootstrap_" not in name
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    yield SimpleNamespace(root=root, row=row, snapshot=snapshot, discover=discover, read=read,
                          registry=registry, forbidden=forbidden)
    forbidden.assert_not_called()
    for path, content in protected.items():
        with original_open(path, "rb") as stream:
            assert stream.read() == content
    assert not (root / ".sbom-dev").exists()


def registered_entry(checkout, auth_mode):
    descriptor = dev_instance_plan.plan_instance(
        repository_id=checkout.snapshot.repository_id, worktree_id=checkout.row.worktree_id,
        commit=checkout.row.head, generation=1, mode="isolated", auth_mode=auth_mode,
        provider="container", config_generation=7, config_present=True,
    ).descriptor
    return dev_instance_registry.RegistryEntry(descriptor, state="READY")


@pytest.mark.parametrize("command", ["plan", "prepare"])
@pytest.mark.parametrize("auth_mode", ["native", "hcl"])
@pytest.mark.parametrize("existing", [False, True])
def test_fresh_and_registered_administrator_commands_return_only_real_uninspected_overview(
    checkout, monkeypatch, capsys, command, auth_mode, existing
):
    arguments = [command, "--scope", "administrator", "--json"]
    if existing:
        entry = registered_entry(checkout, auth_mode)
        records = dev_instance_registry.RegistrySnapshot((entry,))
        checkout.read.return_value = records
    else:
        arguments += ["--mode", "isolated", "--auth", auth_mode]
    monkeypatch.setenv("DATABASE_URL", SECRET)
    monkeypatch.setenv("SBOM_DEV_ENROLLMENT_READY", "1")
    monkeypatch.setenv("NATIVE_AUTH_BOOTSTRAP_ENABLED", "true")
    assert cli.run_cli(arguments, checkout.root) == 1
    captured = capsys.readouterr()
    public = json.loads(captured.out)
    expected = onboarding.uninspected_guidance(auth_mode).to_dict()
    assert {key: public[key] for key in expected} == expected
    assert set(public) == set(expected) | {"instance_id", "proposed_origin"}
    assert public["state"] == ("UNKNOWN" if auth_mode == "native" else "HCL_APPROVAL_REQUIRED")
    assert public["inspection_performed"] is False and public["live_enrollment_authorized"] is False
    assert not public["required_identity_fields"] and all(not step["executable"] for step in public["steps"])
    assert SECRET not in captured.out + captured.err
    assert not {"context", "config_generation", "status", "database_name", "schema_revision", "password"} & public.keys()
    if existing:
        assert checkout.read.return_value == records and records.entries[0] == entry
        assert public["instance_id"] == entry.descriptor.instance_id
        assert entry.descriptor.auth_mode == auth_mode and entry.descriptor.configuration_present is True


@pytest.mark.parametrize("command", ["plan", "prepare"])
def test_existing_mode_is_reused_after_head_drift_without_claiming_inspected_state(checkout, capsys, command):
    entry = registered_entry(checkout, "native")
    checkout.read.return_value = dev_instance_registry.RegistrySnapshot((entry,))
    changed = replace(checkout.row, head="d" * 40)
    checkout.discover.return_value = replace(checkout.snapshot, head=changed.head, worktrees=(changed,))
    assert cli.run_cli([command, "--scope", "administrator", "--json"], checkout.root) == 1
    public = json.loads(capsys.readouterr().out)
    assert public["state"] == "UNKNOWN" and public["auth_mode"] == "native"
    assert public["inspection_performed"] is False
    assert checkout.read.return_value.entries[0] == entry and entry.descriptor.commit == "c" * 40


def test_explicit_alternative_guidance_never_converts_existing_authentication(checkout, capsys):
    entry = registered_entry(checkout, "native")
    checkout.read.return_value = dev_instance_registry.RegistrySnapshot((entry,))
    assert cli.run_cli(["prepare", "--scope", "administrator", "--auth", "hcl", "--json"], checkout.root) == 1
    public = json.loads(capsys.readouterr().out)
    assert public["auth_mode"] == "hcl" and public["state"] == "HCL_APPROVAL_REQUIRED"
    assert checkout.read.return_value.entries[0] == entry and entry.descriptor.auth_mode == "native"
    assert "review-required-identity" not in [step["code"] for step in public["steps"]]


@pytest.mark.parametrize("command", ["plan", "prepare"])
@pytest.mark.parametrize("arguments", [["--plan"], ["--suite", "unit"]])
def test_test_only_flags_cannot_unlock_administrator_preparation(checkout, capsys, command, arguments):
    assert cli.run_cli([command, "--scope", "administrator", *arguments, "--json"], checkout.root) == 1
    assert json.loads(capsys.readouterr().out)["code"] == "WORKSPACE_TEST_OPTIONS_REQUIRED"
    checkout.discover.assert_not_called()


def test_fresh_checkout_requires_explicit_mode_and_authentication_selection(checkout, capsys):
    assert cli.run_cli(["prepare", "--scope", "administrator", "--json"], checkout.root) == 1
    assert json.loads(capsys.readouterr().out)["code"] == "WORKSPACE_MODE_AUTH_SELECTION_REQUIRED"


@pytest.mark.parametrize("mode", ["mock", "shared-backend"])
def test_administrator_guidance_cannot_target_preview_or_shared_application(checkout, capsys, mode):
    assert cli.run_cli(["prepare", "--scope", "administrator", "--mode", mode, "--auth", "native", "--json"], checkout.root) == 1
    assert json.loads(capsys.readouterr().out) == {
        "status": "BLOCKED", "code": "ONBOARDING_ISOLATED_INSTALLATION_REQUIRED"
    }


@pytest.mark.parametrize("code", ["REGISTRY_SCHEMA_INVALID", "REGISTRY_UNKNOWN_ARTIFACT"])
def test_uncertain_registry_is_preserved_without_onboarding_claim(checkout, capsys, code):
    checkout.read.return_value = dev_instance_registry.RegistrySnapshot(codes=(code,))
    assert cli.run_cli(["plan", "--scope", "administrator", "--mode", "isolated", "--auth", "native", "--json"], checkout.root) == 1
    assert json.loads(capsys.readouterr().out) == {"status": "BLOCKED", "code": code}


@pytest.mark.parametrize("arguments", [["--password", SECRET], ["--auth", SECRET], ["--generation", SECRET]])
def test_identity_unknown_and_invalid_arguments_are_rejected_without_raw_values(checkout, capsys, arguments):
    with pytest.raises(SystemExit) as caught:
        cli.run_cli(["prepare", "--scope", "administrator", *arguments], checkout.root)
    assert caught.value.code == 2
    captured = capsys.readouterr()
    assert "WORKSPACE_ARGUMENTS_INVALID" in captured.err and SECRET not in captured.out + captured.err
    checkout.discover.assert_not_called()


def test_text_guidance_requests_no_identity_and_collects_no_confirmation(checkout, capsys):
    assert cli.run_cli(["prepare", "--scope", "administrator", "--mode", "isolated", "--auth", "native"], checkout.root) == 1
    captured = capsys.readouterr()
    assert "no installation status inspection was performed" in captured.out
    assert "requests no identity details or password" in captured.out
    assert "JWT" in captured.out and "verified HTTPS" in captured.out
    assert SECRET not in captured.out + captured.err
