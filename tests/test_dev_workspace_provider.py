"""Synthetic container policy/inspect contracts; no engine, service or database."""

from __future__ import annotations

import builtins
import copy
import io
import json
import os
import socket
import subprocess
import sys
from dataclasses import FrozenInstanceError, replace
from unittest.mock import Mock

import pytest
from scripts import dev_instance_plan
from scripts import dev_workspace_provider as provider

ENGINE = "e" * 64
POLICY = "d" * 64
SECRET = "synthetic-sensitive-value-never-output"


def descriptor(**values):
    return dev_instance_plan.plan_instance(
        **{
            "repository_id": "a" * 64,
            "worktree_id": "b" * 64,
            "commit": "c" * 40,
            "generation": 1,
            "mode": "isolated",
            "auth_mode": "native",
            "provider": "container",
            **values,
        }
    ).descriptor


def policy(**values):
    return provider.ContainerPolicy(
        **{
            "engine": "docker",
            "policy_id": POLICY,
            "engine_identity": ENGINE,
            "images": {
                name: f"approved.invalid/sbom/{name}@sha256:" + "f" * 64 for name in ("postgres", "redis", "mailpit")
            },
            "users": {"postgres": "999:999", "redis": "1000:1000", "mailpit": "1001:1001"},
            **values,
        }
    )


def plan(**values):
    return provider.plan_provider(descriptor(**values), policy())


def snapshot(planned):
    containers, networks, volumes = [], [], []
    pinned = {
        "version": 1,
        "engine_id": planned.policy.engine_identity,
        "containers": {},
        "networks": {},
        "volumes": {},
    }
    network_id = "1" * 64
    for index, item in enumerate(planned.containers, 2):
        value = item.to_dict()
        identity = {"id": str(index) * 64, "pid": 100 + index, "started_at": "2026-10-31T08:00:00.123456789Z"}
        value.update(
            identity,
            labels=dict(planned.labels),
            state="running",
            health="healthy",
            networks={planned.network: network_id},
        )
        containers.append(value)
        pinned["containers"][item.name] = dict(identity)
    networks.append(
        {
            "name": planned.network,
            "id": network_id,
            "labels": dict(planned.labels),
            "driver": "bridge",
            "internal": True,
            "options": {},
        }
    )
    pinned["networks"][planned.network] = network_id
    for index, name in enumerate(planned.volumes, 5):
        value = {"name": name, "id": str(index) * 64, "labels": dict(planned.labels), "driver": "local", "options": {}}
        volumes.append(value)
        pinned["volumes"][name] = value["id"]
    return {
        "version": 1,
        "engine": {"kind": planned.policy.engine, "id": planned.policy.engine_identity, "state": "ready"},
        "containers": containers,
        "networks": networks,
        "volumes": volumes,
        "absent": {"containers": [], "networks": [], "volumes": []},
    }, pinned


@pytest.mark.parametrize("engine", ["docker", "podman"])
def test_public_provider_plan_is_pinned_nonroot_loopback_isolated_and_not_executable(engine):
    selected = provider.plan_provider(descriptor(), policy(engine=engine))
    output = selected.to_dict()
    assert output["engine"] == engine and output["approval_required"] is True
    assert (
        output["ownership_verified"] is False and output["live_authorized"] is False and output["executable"] is False
    )
    assert "database-initialization" in output["required_approvals"]
    assert selected.database_owner_role != selected.database_runtime_role
    assert max(len(selected.database_owner_role), len(selected.database_runtime_role)) <= 63
    assert len(output["containers"]) == 3 and len(output["volumes"]) == 2
    for value in output["containers"]:
        assert value["privileged"] is False and value["host_network"] is False
        assert value["read_only"] is True and value["no_new_privileges"] is True and value["cap_drop"] == ["ALL"]
        assert not value["user"].startswith("0")
        assert all(binding["host_ip"] == "127.0.0.1" and binding["protocol"] == "tcp" for binding in value["ports"])
        assert all(mount["kind"] == "volume" for mount in value["mounts"])
        assert "environment" not in value and "password" not in value and "command" not in value
        assert value["credential_refs"]


def test_plan_and_policy_are_immutable_detached_and_deterministic():
    images = dict(policy().images)
    selected = policy(images=images)
    first = provider.plan_provider(descriptor(), selected)
    images["postgres"] = SECRET
    assert provider.plan_provider(descriptor(), policy()) == first
    with pytest.raises(FrozenInstanceError):
        first.network = "unrelated-network"
    with pytest.raises(TypeError):
        first.labels["secret"] = SECRET
    with pytest.raises(TypeError):
        selected.images["postgres"] = SECRET
    with pytest.raises(provider.ProviderPlanError):
        replace(first, database_owner_role=first.database_runtime_role)
    with pytest.raises(provider.ProviderPlanError):
        replace(first, fingerprint="0" * 64)


@pytest.mark.parametrize(
    "image",
    [
        "postgres:latest",
        "postgres",
        "https://fixture:secret@registry/postgres",
        "approved.invalid/postgres@sha256:123",
        "approved.invalid:0/postgres@sha256:" + "a" * 64,
        "approved.invalid//postgres@sha256:" + "a" * 64,
    ],
)
def test_policy_requires_explicit_digest_images_without_credential_or_implicit_tags(image):
    images = dict(policy().images)
    images["postgres"] = image
    with pytest.raises(provider.ProviderPlanError, match="PROVIDER_PINNED_IMAGES_REQUIRED") as error:
        policy(images=images)
    assert image not in str(error.value)


@pytest.mark.parametrize("user", ["0", "0:0", "1000:0", "root", "postgres", "-1", True, "2147483648"])
def test_policy_requires_explicit_nonroot_numeric_users(user):
    users = dict(policy().users)
    users["postgres"] = user
    with pytest.raises(provider.ProviderPlanError, match="PROVIDER_NONROOT_USERS_REQUIRED"):
        policy(users=users)


@pytest.mark.parametrize("field", ["approved", "authorization", "credentials", "Env", "password"])
def test_policy_unknown_authority_and_private_fields_are_rejected(field):
    value = policy().to_dict()
    value[field] = SECRET
    with pytest.raises(provider.ProviderPlanError) as error:
        provider.ContainerPolicy.from_dict(value)
    assert SECRET not in str(error.value)


@pytest.mark.parametrize(
    "mode, selected_provider", [("mock", "mock"), ("shared-backend", "shared"), ("isolated", "local")]
)
def test_provider_planning_never_adopts_mock_shared_or_local_existing_services(mode, selected_provider):
    with pytest.raises(provider.ProviderPlanError, match="PROVIDER_FULL_ISOLATION_REQUIRED"):
        provider.plan_provider(descriptor(mode=mode, provider=selected_provider), policy())


def test_matching_supplied_inventory_only_establishes_consistency_not_ownership_or_authority():
    selected = plan()
    inventory, pinned = snapshot(selected)
    before = copy.deepcopy((inventory, pinned))
    result = provider.verify_inventory(selected, inventory, pinned=pinned)
    assert result.status == "CONSISTENT" and result.codes == ("PROVIDER_SUPPLIED_RECORDS_CONSISTENT",)
    assert result.ownership_verified is False and result.live_authorized is False
    assert (inventory, pinned) == before
    with pytest.raises(provider.ProviderPlanError, match="PROVIDER_AUTHORIZATION_NOT_ESTABLISHED"):
        replace(result, ownership_verified=True)


def test_unbound_or_unavailable_inventory_is_unknown_and_absence_requires_explicit_report():
    selected = plan()
    inventory, pinned = snapshot(selected)
    assert provider.verify_inventory(selected, None).codes == ("PROVIDER_INVENTORY_REQUIRED",)
    assert provider.verify_inventory(selected, inventory).codes == ("PROVIDER_PINNED_IDENTITIES_REQUIRED",)
    inventory["engine"]["state"] = "unavailable"
    assert provider.verify_inventory(selected, inventory, pinned=pinned).status == "UNKNOWN"
    inventory["engine"]["state"] = "ready"
    inventory["containers"] = []
    inventory["networks"] = []
    inventory["volumes"] = []
    assert provider.verify_inventory(selected, inventory, pinned=pinned).codes == ("PROVIDER_INVENTORY_INCOMPLETE",)
    inventory["absent"] = {
        "containers": [item.name for item in selected.containers],
        "networks": [selected.network],
        "volumes": list(selected.volumes),
    }
    result = provider.verify_inventory(selected, inventory)
    assert result.status == "ABSENT" and result.codes == ("PROVIDER_REPORTED_ABSENT",)
    assert not result.ownership_verified and not result.live_authorized


def test_partial_existing_state_requires_review_and_never_implies_cleanup():
    selected = plan()
    inventory, pinned = snapshot(selected)
    removed = inventory["containers"].pop()
    inventory["absent"]["containers"] = [removed["name"]]
    result = provider.verify_inventory(selected, inventory, pinned=pinned)
    assert result.status == "BLOCKED" and result.codes == ("PROVIDER_PARTIAL_STATE_REVIEW_REQUIRED",)
    assert not hasattr(result, "cleanup") and not hasattr(result, "terminate")


@pytest.mark.parametrize("kind", ["repository", "worktree", "instance", "generation", "policy"])
def test_spoofed_ownership_labels_are_rejected(kind):
    selected = plan()
    inventory, pinned = snapshot(selected)
    inventory["containers"][0]["labels"]["io.sbom.dev." + kind] = SECRET
    result = provider.verify_inventory(selected, inventory, pinned=pinned)
    assert result.codes == ("PROVIDER_LABEL_MISMATCH",)
    assert SECRET not in json.dumps(result.to_dict())


@pytest.mark.parametrize("component", ["containers", "networks", "volumes"])
def test_cross_instance_inventory_and_identical_labels_never_replace_pinned_ids(component):
    selected = plan()
    inventory, pinned = snapshot(selected)
    inventory[component][0]["id"] = "f" * 64
    result = provider.verify_inventory(selected, inventory, pinned=pinned)
    assert result.status == "BLOCKED" and result.codes[0] in {
        "PROVIDER_PROCESS_IDENTITY_MISMATCH",
        "PROVIDER_RESOURCE_IDENTITY_MISMATCH",
    }
    other = plan(worktree_id="d" * 64, claimed_ports=tuple(selected.descriptor.ports.values()))
    assert other.network != selected.network
    assert provider.verify_inventory(other, inventory, pinned=pinned).status == "BLOCKED"


@pytest.mark.parametrize(
    "field, value",
    [
        ("pid", 9999),
        ("pid", 0),
        ("pid", True),
        ("started_at", "2026-10-31T08:01:00Z"),
        ("started_at", "invalid"),
        ("state", "exited"),
        ("health", "unhealthy"),
        ("user", "0"),
        ("image", "unapproved:latest"),
    ],
)
def test_process_identity_provider_state_image_and_user_drift_are_rejected(field, value):
    selected = plan()
    inventory, pinned = snapshot(selected)
    inventory["containers"][0][field] = value
    result = provider.verify_inventory(selected, inventory, pinned=pinned)
    assert result.status == "BLOCKED" and not result.ownership_verified


@pytest.mark.parametrize(
    "field, value",
    [
        ("privileged", True),
        ("privileged", 0),
        ("host_network", True),
        ("read_only", False),
        ("no_new_privileges", False),
        ("cap_drop", []),
        ("cap_add", ["SYS_ADMIN"]),
        ("devices", ["/dev/fixture"]),
        ("pid_mode", "host"),
        ("ipc_mode", "host"),
    ],
)
def test_privilege_and_host_network_cannot_be_inferred_safe_from_labels(field, value):
    selected = plan()
    inventory, pinned = snapshot(selected)
    inventory["containers"][0][field] = value
    result = provider.verify_inventory(selected, inventory, pinned=pinned)
    assert result.codes == ("PROVIDER_UNSAFE_CONTAINER_SECURITY",)


@pytest.mark.parametrize("field", ["host_port", "container_port"])
def test_numeric_port_types_cannot_be_spoofed_by_equal_floats(field):
    selected = plan()
    inventory, pinned = snapshot(selected)
    binding = inventory["containers"][0]["ports"][0]
    binding[field] = float(binding[field])
    result = provider.verify_inventory(selected, inventory, pinned=pinned)
    assert result.codes == ("PROVIDER_INSPECTION_SCHEMA_INVALID",)


@pytest.mark.parametrize(
    "change",
    [
        "host-bind",
        "extra-network",
        "volume-bind-options",
        "network-host-driver",
        "network-not-internal",
        "wrong-loopback",
        "extra-port",
    ],
)
def test_host_mount_network_volume_and_port_aliases_are_blocked(change):
    selected = plan()
    inventory, pinned = snapshot(selected)
    if change == "host-bind":
        inventory["containers"][0]["mounts"][0] = {
            "kind": "bind",
            "source": "/protected",
            "target": "/var/lib/postgresql/data",
        }
    elif change == "extra-network":
        inventory["containers"][0]["networks"]["foreign"] = "f" * 64
    elif change == "volume-bind-options":
        inventory["volumes"][0]["options"] = {"type": "none", "o": "bind", "device": "/protected"}
    elif change == "network-host-driver":
        inventory["networks"][0]["driver"] = "host"
    elif change == "network-not-internal":
        inventory["networks"][0]["internal"] = False
    elif change == "wrong-loopback":
        inventory["containers"][0]["ports"][0]["host_ip"] = "0.0.0.0"
    else:
        inventory["containers"][0]["ports"].append(
            {"container_port": 1234, "host_ip": "127.0.0.1", "host_port": 55555, "protocol": "tcp"}
        )
    assert provider.verify_inventory(selected, inventory, pinned=pinned).status == "BLOCKED"


@pytest.mark.parametrize("field", ["Env", "password", "authorization", "private_key"])
def test_raw_secret_bearing_inspect_payloads_are_not_echoed_or_silently_adopted(field):
    selected = plan()
    inventory, pinned = snapshot(selected)
    inventory["containers"][0][field] = SECRET
    result = provider.verify_inventory(selected, inventory, pinned=pinned)
    assert result.codes == ("PROVIDER_INSPECTION_SCHEMA_INVALID",) and SECRET not in json.dumps(result.to_dict())


def test_pure_planning_and_verification_use_no_file_network_process_env_or_application_access(monkeypatch):
    selected, approved = descriptor(), policy()
    expected = provider.plan_provider(selected, approved)
    inventory, pinned = snapshot(expected)
    forbidden = Mock(side_effect=AssertionError("Pure provider code attempted resource access"))
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        assert name != "app" and not name.startswith("app.")
        assert name.split(".", 1)[0] not in {"psycopg", "sqlalchemy", "redis"}
        return original_import(name, *args, **kwargs)

    with monkeypatch.context() as guarded:
        guarded.setattr(builtins, "open", forbidden)
        guarded.setattr(io, "open", forbidden)
        guarded.setattr(socket, "socket", forbidden)
        guarded.setattr(subprocess, "Popen", forbidden)
        guarded.setattr(os, "environ", None)
        guarded.setattr(builtins, "__import__", guarded_import)
        result = provider.plan_provider(selected, approved)
        assert result == expected
        assert provider.verify_inventory(result, inventory, pinned=pinned).status == "CONSISTENT"
    forbidden.assert_not_called()


def test_direct_provider_module_has_no_live_dispatch(tmp_path):
    result = subprocess.run(
        [sys.executable, "-B", provider.__file__, "--create"],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        timeout=10,
        check=False,
        env={key: value for key, value in os.environ.items() if key in {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP"}},
    )
    assert result.returncode == 1 and not result.stdout
    assert (
        result.stderr.strip()
        == "PROVIDER_PLANNING_ONLY: use the unified developer launcher; live provider operations require separate approval."
    )
    assert not list(tmp_path.iterdir())
