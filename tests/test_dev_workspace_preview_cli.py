"""Preview consent/dispatch contracts, no Node/TLS generation or services."""

import io
import json
import socket
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev_workspace_cli as cli
from scripts import dev_workspace_preview as preview
from scripts import dev_workspace_preview_cli as command


@pytest.fixture
def selected(tmp_path, monkeypatch):
    descriptor = SimpleNamespace(mode="mock", origin="https://sbom-synthetic.localhost:24000")
    args = SimpleNamespace(command="plan", json=True, preview_settings=None, worktree=None)
    plan = SimpleNamespace(
        descriptor=descriptor,
        workspace=tmp_path / "new-preview/frontend",
        shared_backend=None,
        fingerprint="a" * 64,
        to_dict=lambda: {"mode": "mock", "runtime_started": False},
    )
    monkeypatch.setattr(
        command.dev_workspace_cli, "_make_plan", lambda *_: (SimpleNamespace(descriptor=descriptor), None, None)
    )
    forbidden = Mock(side_effect=AssertionError("no engine/process/network permitted"))
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    return args, plan


def test_missing_settings_never_falls_back_to_private_checkout_configuration(selected, tmp_path):
    with pytest.raises(preview.PreviewError, match="^PREVIEW_EXISTING_TLS_AND_NODE_SELECTION_REQUIRED$"):
        command.inspect(selected[0], tmp_path)


def test_public_launcher_dispatches_only_plan_prepare_to_preview(selected, tmp_path, monkeypatch, capsys):
    callback = Mock(return_value=0)
    monkeypatch.setattr(command, "run", callback)
    assert cli.run_cli(["plan", "--scope", "preview", "--mode", "mock", "--auth", "native"], tmp_path) == 0
    assert cli.run_cli(["prepare", "--scope", "preview", "--mode", "mock", "--auth", "native"], tmp_path) == 0
    assert callback.call_count == 2
    for name in ("start", "stop", "diagnose", "test"):
        assert cli.run_cli([name, "--preview-settings", "synthetic-private", "--json"], tmp_path) == 1
        assert json.loads(capsys.readouterr().out)["code"] == "WORKSPACE_PREVIEW_OPTIONS_REQUIRED"
    assert callback.call_count == 2


@pytest.mark.parametrize(
    "value",
    [
        [],
        {},
        {"version": 1, "password": "synthetic-private"},
        {"version": 1, "node": "relative", "tls": {}, "shared_backend": None},
    ],
)
def test_unknown_or_secret_settings_fields_are_fixed_error(selected, tmp_path, value):
    source = tmp_path / "preview.json"
    source.write_text(json.dumps(value), encoding="utf-8")
    selected[0].preview_settings = source
    with pytest.raises(preview.PreviewError, match="^PREVIEW_SETTINGS_INVALID$"):
        command.inspect(selected[0], tmp_path)


def test_pure_preview_plan_does_not_claim_service_readiness(selected, tmp_path, monkeypatch, capsys):
    args, plan = selected
    monkeypatch.setattr(command, "inspect", lambda *_: plan)
    prepare = Mock(side_effect=AssertionError("planning must not prepare"))
    monkeypatch.setattr(preview, "prepare_preview", prepare)
    assert command.run(args, tmp_path) == 0
    assert json.loads(capsys.readouterr().out) == {"mode": "mock", "runtime_started": False}
    prepare.assert_not_called()


def test_noninteractive_preparation_cannot_create_files(selected, tmp_path, monkeypatch):
    args, plan = selected
    args.command = "prepare"
    monkeypatch.setattr(command, "inspect", lambda *_: plan)
    prepare = Mock(side_effect=AssertionError("no category consent"))
    monkeypatch.setattr(preview, "prepare_preview", prepare)
    with pytest.raises(preview.PreviewError, match="^PREVIEW_CATEGORY_APPROVAL_REQUIRED$"):
        command.run(args, tmp_path)
    prepare.assert_not_called()
    assert not plan.workspace.parent.exists()


def test_already_verified_preparation_is_readonly_and_needs_no_new_mutation_consent(selected, tmp_path, monkeypatch):
    args, plan = selected
    args.command = "prepare"
    plan.workspace.parent.mkdir()
    monkeypatch.setattr(command, "inspect", lambda *_: plan)
    verify = Mock(return_value=plan.workspace)
    monkeypatch.setattr(preview, "require_preview", verify)
    monkeypatch.setattr(preview, "prepare_preview", Mock(side_effect=AssertionError("no repeated write")))
    assert command.run(args, tmp_path) == 0
    verify.assert_called_once_with(plan)


def test_configuration_drift_is_rechecked_inside_preparation_boundary(selected, tmp_path, monkeypatch):
    args, plan = selected
    args.command, args.json = "prepare", False
    stream = io.StringIO()
    stream.isatty = lambda: True
    monkeypatch.setattr(command.sys, "stdin", stream)
    monkeypatch.setattr(command.sys, "stdout", stream)
    monkeypatch.setattr("builtins.input", lambda _: "PREVIEW " + plan.fingerprint)
    monkeypatch.setattr(command, "inspect", Mock(side_effect=[plan, object()]))

    def boundary(candidate, *, authorize):
        assert candidate is plan
        return authorize(candidate)

    monkeypatch.setattr(preview, "prepare_preview", boundary)
    with pytest.raises(preview.PreviewError, match="^PREVIEW_PLAN_CHANGED$"):
        command.run(args, tmp_path)
    assert not plan.workspace.parent.exists()
