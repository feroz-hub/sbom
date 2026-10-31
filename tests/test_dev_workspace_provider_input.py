"""Proposed policy parsing and launcher dispatch; no engine or private secrets."""

import json
import socket
import subprocess
from unittest.mock import Mock

import pytest
from scripts import dev_instance_plan
from scripts import dev_workspace_cli as cli
from scripts import dev_workspace_compose as compose
from scripts import dev_workspace_provider as provider
from scripts import dev_workspace_provider_input as decoder


@pytest.fixture
def proposed():
    descriptor = dev_instance_plan.plan_instance(
        repository_id="a" * 64,
        worktree_id="b" * 64,
        commit="c" * 40,
        generation=1,
        mode="isolated",
        auth_mode="native",
    ).descriptor
    container = {
        "engine": "docker",
        "policy_id": "d" * 64,
        "engine_identity": "e" * 64,
        "images": {name: name + "@sha256:" + "f" * 64 for name in ("postgres", "redis", "mailpit")},
        "users": {name: "1000:1000" for name in ("postgres", "redis", "mailpit")},
    }
    plan = provider.plan_provider(descriptor, provider.ContainerPolicy(**container))
    settings = {
        "reference": "d" * 64,
        "bundle_generation": "1" * 64,
        "host_platform": "linux",
        "platforms": {name: "linux/amd64" for name in container["images"]},
        "profiles": dict(compose._PROFILES),
        "limits": {
            name: {
                "cpus": "1",
                "memory_bytes": 512 * 1048576,
                "pids": 128,
                "tmpfs_bytes": 8 * 1048576,
                "shm_bytes": 64 * 1048576,
            }
            for name in container["images"]
        },
        "data_ownership": {name: {"uid": 1000, "gid": 1000, "mode": 448} for name in ("postgres", "redis")},
        "volume_population": {name: "copy-empty-image-directory" for name in ("postgres", "redis")},
        "health": {
            "interval_seconds": 5,
            "timeout_seconds": 2,
            "retries": 20,
            "start_period_seconds": 10,
            "stop_grace_seconds": 20,
        },
        "secret_files": [
            {"reference": reference, "source": "/private/synthetic-secret/" + reference, "host_platform": "linux"}
            for group in compose.secret_layout(plan).values()
            for reference in group.values()
        ],
    }
    return descriptor, {"version": 1, "container": container, "compose": settings}


def test_complete_proposal_stays_unapproved_and_redacts_paths(proposed):
    descriptor, data = proposed
    provider_plan, manifest = decoder.parse_policy(json.dumps(data).encode(), descriptor)
    public = json.dumps([provider_plan.to_dict(), manifest.to_dict()])
    assert "synthetic-secret" not in public
    assert manifest.to_dict()["status"] == "BLOCKED"
    assert not manifest.to_dict()["live_authorized"]
    assert "/private/synthetic-secret/" in manifest.render_private_manifest()


@pytest.mark.parametrize(
    "raw",
    [b"", b"[]", b"{", b'{"version":1,"version":1}', b"\xff", b"a" * 65537],
    ids=("empty", "array", "syntax", "duplicate", "encoding", "oversized"),
)
def test_malformed_policy_is_fixed_redacted_error(proposed, raw):
    with pytest.raises(decoder.ProviderInputError, match="^PROVIDER_POLICY_INPUT_INVALID$"):
        decoder.parse_policy(raw, proposed[0])


@pytest.mark.parametrize(
    "change",
    [
        lambda value: value.update(password="synthetic-secret"),
        lambda value: value.update(version=True),
        lambda value: value["container"]["images"].update(postgres="postgres:latest"),
        lambda value: value["container"]["users"].update(redis="0:0"),
        lambda value: value["compose"]["health"].update(timeout_seconds=999),
        lambda value: value["compose"].update(approved=True),
        lambda value: value["compose"]["secret_files"][0].update(contents="synthetic-secret"),
    ],
)
def test_no_unknown_fields_defaults_authority_or_invalid_contracts(proposed, change):
    change(proposed[1])
    with pytest.raises(decoder.ProviderInputError) as caught:
        decoder.parse_policy(json.dumps(proposed[1]).encode(), proposed[0])
    assert str(caught.value) == "PROVIDER_POLICY_INPUT_INVALID"


def test_prepare_provider_refuses_before_inventory_or_engine(tmp_path, monkeypatch, capsys):
    forbidden = Mock(side_effect=AssertionError("must not access resources"))
    monkeypatch.setattr(cli, "_make_plan", forbidden)
    assert cli.run_cli(["prepare", "--scope", "provider", "--json"], tmp_path) == 1
    assert json.loads(capsys.readouterr().out)["code"] == "PROVIDER_EXACT_TARGET_AUTHORIZATION_REQUIRED"
    forbidden.assert_not_called()


def test_policy_option_cannot_enter_other_commands(tmp_path, monkeypatch, capsys):
    forbidden = Mock(side_effect=AssertionError("must not access resources"))
    monkeypatch.setattr(cli, "_make_plan", forbidden)
    for command in ("start", "diagnose", "prepare", "logs"):
        assert cli.run_cli([command, "--provider-policy", "private-policy", "--json"], tmp_path) == 1
        assert json.loads(capsys.readouterr().out)["code"] == "WORKSPACE_PROVIDER_OPTIONS_REQUIRED"
    forbidden.assert_not_called()


def test_cli_public_provider_review_never_reads_referenced_secrets(proposed, tmp_path, monkeypatch, capsys):
    from types import SimpleNamespace

    source = tmp_path / "proposed.json"
    source.write_text(json.dumps(proposed[1]), encoding="utf-8")
    forbidden = Mock(side_effect=AssertionError("provider plan must not invoke tools or connect"))
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(cli, "_make_plan", lambda *args: (SimpleNamespace(descriptor=proposed[0]), None, None))
    assert cli.run_cli(["plan", "--scope", "provider", "--provider-policy", str(source), "--json"], tmp_path) == 1
    public = capsys.readouterr().out
    assert "synthetic-secret" not in public
    assert json.loads(public)["code"] == "PROVIDER_RUNTIME_CONTRACT_REVIEW_REQUIRED"
    assert not json.loads(public)["engine_probed"]
    forbidden.assert_not_called()
