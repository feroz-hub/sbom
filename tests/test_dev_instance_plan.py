"""Pure instance proposals only; run with --noconftest and synthetic metadata."""

from __future__ import annotations

import builtins
import hashlib
import json
import os
import socket
import subprocess
import sys
import types
import uuid
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest.mock import Mock

import pytest
from scripts import dev_instance_plan as planning

REPOSITORY = "1" * 64
WORKTREE = "2" * 64
COMMIT = "3" * 40
SECRET = "fixture-private-value-never-output"


def plan(**changes):
    values = dict(
        repository_id=REPOSITORY, worktree_id=WORKTREE, commit=COMMIT, generation=1, mode="isolated", auth_mode="native"
    )
    values.update(changes)
    return planning.plan_instance(**values)


def test_identical_public_inputs_produce_canonical_uuid5_identity_and_fingerprint():
    first = plan(manifest_hashes={"requirements.txt": "a" * 64, "frontend/package-lock.json": "b" * 64})
    second = plan(manifest_hashes={"frontend/package-lock.json": "b" * 64, "requirements.txt": "a" * 64})
    assert first == second and first.fingerprint == second.fingerprint
    assert uuid.UUID(first.descriptor.instance_id).version == 5
    document = first.to_dict()
    fingerprint = document.pop("fingerprint")
    assert (
        fingerprint
        == hashlib.sha256(
            json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        ).hexdigest()
    )
    assert first.descriptor.proposal_only is True
    assert first.descriptor.ownership_verified is False and first.descriptor.live_operations_authorized is False


@pytest.mark.parametrize(
    "change",
    [
        {"repository_id": "4" * 64},
        {"worktree_id": "5" * 64},
        {"commit": "6" * 40},
        {"generation": 2},
        {"config_generation": 2},
        {"config_present": True},
        {"manifest_hashes": {"requirements.txt": "a" * 64}},
        {"auth_mode": "hcl"},
        {"provider": "local"},
        {"claimed_ports": [60000]},
        {"excluded_ports": [60001]},
        {"port_range": (30001, 39999)},
    ],
)
def test_fingerprint_binds_every_public_identity_configuration_and_constraint_change(change):
    assert plan(**change).fingerprint != plan().fingerprint


def test_only_explicit_generation_or_worktree_identity_changes_instance_identity():
    original = plan()
    assert plan(commit="4" * 40, config_generation=2).descriptor.instance_id == original.descriptor.instance_id
    assert plan(generation=2).descriptor.instance_id != original.descriptor.instance_id
    assert plan(worktree_id="5" * 64).descriptor.instance_id != original.descriptor.instance_id
    assert plan(repository_id="6" * 64).descriptor.instance_id != original.descriptor.instance_id


def test_public_uuid_ids_and_sha256_commits_round_trip_without_paths_or_credentials():
    result = plan(
        repository_id=str(uuid.UUID(int=1)),
        worktree_id=str(uuid.UUID(int=2)),
        commit="a" * 64,
        config_generation=str(uuid.UUID(int=3)),
    )
    assert (
        planning.InstanceDescriptor.from_dict(json.loads(json.dumps(result.descriptor.to_dict()))) == result.descriptor
    )


def test_input_maps_constraints_and_serialized_output_cannot_mutate_an_existing_plan():
    manifests, claims, excluded = {"requirements.txt": "a" * 64}, [22000], [22001]
    result = plan(manifest_hashes=manifests, claimed_ports=claims, excluded_ports=excluded)
    fingerprint = result.fingerprint
    manifests["requirements.txt"], claims[:], excluded[:] = "b" * 64, [23000], [23001]
    output = result.to_dict()
    output["descriptor"]["manifest_hashes"]["requirements.txt"] = "c" * 64
    output["descriptor"]["ports"]["frontend"] = 24000
    output["actions"][0]["requires_approval"] = False
    output["blockers"].clear()
    assert result.fingerprint == fingerprint
    assert result.descriptor.manifest_hashes["requirements.txt"] == "a" * 64
    with pytest.raises(TypeError):
        result.descriptor.ports["frontend"] = 24001
    with pytest.raises(TypeError):
        result.descriptor.resources["database"] = SECRET
    with pytest.raises(FrozenInstanceError):
        result.descriptor.generation = 2


def test_public_dto_constructors_copy_nested_lists_and_keep_fingerprints_stable():
    original = plan()
    actions, blockers, claims, excluded = list(original.actions), list(original.blockers), [], []
    copied = planning.InstancePlan(original.descriptor, actions, blockers, list(original.port_range), claims, excluded)
    fingerprint = copied.fingerprint
    actions.clear()
    blockers.clear()
    claims.append(20000)
    excluded.append(20001)
    assert copied.fingerprint == fingerprint and copied == original
    prerequisites = ["prepare-dependencies"]
    action = planning.PlanAction("review-provider-policy", "providers", prerequisites)
    prerequisites.clear()
    assert action.prerequisites == ("prepare-dependencies",)
    affected = ["prepare-dependencies"]
    blocker = planning.PlanBlocker("SOFTWARE_PREPARATION_APPROVAL_REQUIRED", "software-dependencies", affected)
    affected.clear()
    assert blocker.actions == ("prepare-dependencies",)


@pytest.mark.parametrize(
    "mode, expected_ports",
    [
        ("isolated", {"api", "frontend", "postgres", "redis", "smtp", "mailpit_ui"}),
        ("mock", {"frontend"}),
        ("shared-backend", {"frontend"}),
    ],
)
def test_resource_proposals_are_mode_specific_and_never_authorized(mode, expected_ports):
    result = plan(mode=mode)
    assert set(result.descriptor.ports) == expected_ports
    assert all(action.executable is False and action.requires_approval is True for action in result.actions)
    assert "INSTANCE_LIVE_OPERATIONS_GATED" in {item.code for item in result.blockers}
    if mode != "isolated":
        assert (
            not {
                "database",
                "postgres",
                "redis",
                "mailpit",
                "worker_default",
                "worker_reports",
                "beat",
                "queue_default",
                "queue_reports",
            }
            & result.descriptor.resources.keys()
        )
    if mode == "mock":
        assert set(result.descriptor.resources) == {
            "frontend",
            "artifacts",
            "logs",
            "venv",
            "frontend_dependencies",
            "frontend_workspace",
            "tls_leaf",
        }
    if mode == "shared-backend":
        assert "session_namespace" in result.descriptor.resources
        assert "SHARED_BACKEND_REGISTRATION_REQUIRED" in {item.code for item in result.blockers}
        assert not any(action.category in {"database", "providers", "administrator"} for action in result.actions)


@pytest.mark.parametrize(
    "provider, required",
    [
        ("container", "CONTAINER_ENGINE_APPROVAL_REQUIRED"),
        ("local", "LOCAL_ISOLATION_POLICY_REQUIRED"),
    ],
)
def test_isolated_provider_proposals_never_adopt_existing_local_or_container_installations(provider, required):
    result = plan(provider=provider)
    assert required in {item.code for item in result.blockers}
    assert result.descriptor.resources["database"] not in {"sbom_analyser_dev", "sbom_greenfield_uuid"}
    assert "docker" not in result.descriptor.to_dict() and "podman" not in result.descriptor.to_dict()
    assert {
        "network",
        "postgres_volume",
        "redis_volume",
        "restricted_database_role",
        "beat_schedule",
    } <= result.descriptor.resources.keys()
    assert len(result.descriptor.resources["database"]) < 63
    assert len(result.descriptor.resources["restricted_database_role"]) < 63


def test_dependency_preparation_remains_independent_when_configuration_and_manifests_are_absent():
    result = plan(config_present=False, config_generation=None, manifest_hashes={})
    dependency = next(item for item in result.actions if item.code == "prepare-dependencies")
    assert dependency.prerequisites == () and dependency.requires_configuration is False
    touching_dependencies = [item.code for item in result.blockers if dependency.code in item.actions]
    assert touching_dependencies == ["SOFTWARE_PREPARATION_APPROVAL_REQUIRED"]
    assert "PRIVATE_CONFIGURATION_MISSING" in {item.code for item in result.blockers}


def test_instance_origin_and_all_isolated_namespaces_are_distinct_across_worktrees():
    first = plan()
    second = plan(worktree_id="7" * 64, claimed_ports=first.descriptor.ports.values())
    assert first.descriptor.hostname != second.descriptor.hostname
    assert first.descriptor.hostname.endswith(".localhost") and first.descriptor.origin.startswith("https://")
    assert first.descriptor.origin == f"https://{first.descriptor.hostname}:{first.descriptor.ports['frontend']}"
    assert set(first.descriptor.ports.values()).isdisjoint(second.descriptor.ports.values())
    assert all(
        first.descriptor.resources[key] != second.descriptor.resources[key] for key in first.descriptor.resources
    )


def test_port_proposals_wrap_deterministically_and_exclude_all_claims_without_partial_allocations():
    result = plan(port_range=(21000, 21008), claimed_ports=[21000, 21001], excluded_ports=[21002])
    assert set(result.descriptor.ports.values()) == set(range(21003, 21009))
    reordered = plan(port_range=(21000, 21008), claimed_ports=[21001, 21000, 21001], excluded_ports=[21002, 21002])
    assert reordered == result and reordered.fingerprint == result.fingerprint
    with pytest.raises(planning.InstancePlanError, match="^INSTANCE_PORT_RANGE_EXHAUSTED$"):
        plan(port_range=(21000, 21005), excluded_ports=[21000])
    with pytest.raises(planning.InstancePlanError, match="^INSTANCE_PORT_RANGE_EXHAUSTED$"):
        plan(mode="mock", port_range=(13000, 13000))


@pytest.mark.parametrize(
    "change",
    [
        {"repository_id": SECRET},
        {"worktree_id": "C:/private/checkout"},
        {"commit": SECRET},
        {"generation": True},
        {"generation": 0},
        {"generation": 2147483648},
        {"config_generation": False},
        {"config_generation": SECRET},
        {"config_present": 1},
        {"mode": SECRET},
        {"auth_mode": "none"},
        {"mode": "mock", "provider": "container"},
        {"mode": "shared-backend", "provider": "local"},
        {"provider": "docker"},
        {"port_range": (True, 25000)},
        {"port_range": (1023, 25000)},
        {"port_range": (25000, 24000)},
        {"port_range": (20000,)},
        {"claimed_ports": [True]},
        {"claimed_ports": [0]},
        {"excluded_ports": [65536]},
        {"claimed_ports": SECRET},
        {"manifest_hashes": {".env.dev.local": "a" * 64}},
        {"manifest_hashes": {"requirements.txt": SECRET}},
        {"manifest_hashes": {"../requirements.txt": "a" * 64}},
    ],
)
def test_invalid_or_private_inputs_fail_with_fixed_redacted_errors(change):
    with pytest.raises(planning.InstancePlanError) as caught:
        plan(**change)
    assert SECRET not in str(caught.value) and SECRET not in repr(caught.value)
    assert "C:/private" not in str(caught.value)


@pytest.mark.parametrize(
    "field, value",
    [
        ("version", True),
        ("version", 2),
        ("instance_id", str(uuid.UUID(int=1))),
        ("repository_id", SECRET),
        ("worktree_id", SECRET),
        ("commit", "A" * 40),
        ("generation", True),
        ("config_generation", SECRET),
        ("configuration_present", 0),
        ("mode", "adopt"),
        ("auth_mode", "none"),
        ("provider", "docker"),
        ("hostname", "localhost"),
        ("origin", "https://user:" + SECRET + "@localhost:21000"),
        ("proposal_only", False),
        ("ownership_verified", True),
        ("live_operations_authorized", True),
        ("private_key", SECRET),
    ],
)
def test_descriptor_parser_rejects_unknown_fields_identity_drift_and_enabling_flags(field, value):
    raw = plan().descriptor.to_dict()
    raw[field] = value
    with pytest.raises(planning.InstancePlanError) as caught:
        planning.InstanceDescriptor.from_dict(raw)
    assert SECRET not in str(caught.value)


@pytest.mark.parametrize(
    "field, mutation",
    [
        ("ports", {"frontend": 23000}),
        ("ports", {"DATABASE_URL": 23000}),
        ("resources", {"DATABASE_URL": SECRET}),
        ("manifest_hashes", {".env": "a" * 64}),
        ("manifest_hashes", {"frontend/package.json": SECRET}),
        ("ports", []),
    ],
)
def test_descriptor_parser_enforces_nested_allowlists_and_types(field, mutation):
    raw = plan().descriptor.to_dict()
    raw[field] = mutation
    with pytest.raises(planning.InstancePlanError) as caught:
        planning.InstanceDescriptor.from_dict(raw)
    assert SECRET not in str(caught.value)


def test_descriptor_parser_rejects_missing_fields_duplicate_ports_and_reserved_ports():
    raw = plan().descriptor.to_dict()
    raw.pop("configuration_present")
    with pytest.raises(planning.InstancePlanError):
        planning.InstanceDescriptor.from_dict(raw)
    for port in (True, 5432, plan().descriptor.ports["api"]):
        raw = plan().descriptor.to_dict()
        raw["ports"]["frontend"] = port
        raw["origin"] = f"https://{raw['hostname']}:{port}"
        with pytest.raises(planning.InstancePlanError):
            planning.InstanceDescriptor.from_dict(raw)


@pytest.mark.parametrize(
    "build",
    [
        lambda: planning.PlanAction(SECRET, "providers"),
        lambda: planning.PlanAction("prepare-dependencies", SECRET),
        lambda: planning.PlanAction("prepare-dependencies", "software-dependencies", requires_approval=False),
        lambda: planning.PlanAction("prepare-dependencies", "software-dependencies", executable=True),
        lambda: planning.PlanAction("prepare-dependencies", "software-dependencies", ["prepare-dependencies"]),
        lambda: planning.PlanBlocker(SECRET, "providers", ["prepare-dependencies"]),
        lambda: planning.PlanBlocker("SOFTWARE_PREPARATION_APPROVAL_REQUIRED", "software-dependencies", [SECRET]),
        lambda: replace(plan(), descriptor={"private_key": SECRET}),
        lambda: replace(plan(), actions=[]),
        lambda: replace(plan(), blockers=[]),
        lambda: replace(plan(), claimed_ports=list(plan().descriptor.ports.values())),
    ],
)
def test_all_public_dto_constructors_refuse_unsafe_or_inconsistent_forged_plans(build):
    with pytest.raises(planning.InstancePlanError) as caught:
        build()
    assert SECRET not in str(caught.value)


@pytest.mark.parametrize("field", ["instance_id", "hostname", "origin"])
def test_descriptor_constructor_rejects_string_subclasses_with_private_representations(field):
    class PrivateString(str):
        def __repr__(self):
            return SECRET

    descriptor = plan().descriptor
    with pytest.raises(planning.InstancePlanError) as caught:
        replace(descriptor, **{field: PrivateString(getattr(descriptor, field))})
    assert SECRET not in str(caught.value)


def test_action_and_blocker_category_types_cannot_retain_private_representations():
    class PrivateString(str):
        def __repr__(self):
            return SECRET

    with pytest.raises(planning.InstancePlanError):
        planning.PlanAction("prepare-dependencies", PrivateString("software-dependencies"))
    with pytest.raises(planning.InstancePlanError):
        planning.PlanBlocker(
            "SOFTWARE_PREPARATION_APPROVAL_REQUIRED", PrivateString("software-dependencies"), ["prepare-dependencies"]
        )


def test_fresh_module_definition_and_every_mode_are_pure_under_io_environment_and_application_tripwires(monkeypatch):
    source = Path(planning.__file__).read_text(encoding="utf-8")
    compiled = compile(source, "<synthetic-public-planner>", "exec")
    fixture = types.ModuleType("sbo101_pure_planner_fixture")
    monkeypatch.setitem(sys.modules, fixture.__name__, fixture)
    forbidden = Mock(side_effect=AssertionError("Pure planning attempted an external side effect"))

    class NoEnvironment(dict):
        __getitem__ = get = items = keys = values = __iter__ = copy = forbidden
        __contains__ = __setitem__ = __delitem__ = clear = update = pop = setdefault = forbidden

    original_import = builtins.__import__

    def guarded_import(name, *arguments, **keywords):
        assert name.split(".", 1)[0] not in {"app", "psycopg", "sqlalchemy", "celery"}
        return original_import(name, *arguments, **keywords)

    # Restore tripwires before pytest itself updates its environment/reports.
    with monkeypatch.context() as guarded:
        guarded.setattr(os, "environ", NoEnvironment())
        guarded.setattr(os, "getenv", forbidden)
        guarded.setattr(os, "open", forbidden)
        guarded.setattr(os, "listdir", forbidden)
        guarded.setattr(builtins, "open", forbidden)
        for name in ("open", "read_text", "read_bytes", "write_text", "write_bytes", "mkdir", "exists", "stat"):
            guarded.setattr(Path, name, forbidden)
        guarded.setattr(socket, "socket", forbidden)
        guarded.setattr(socket, "create_connection", forbidden)
        guarded.setattr(subprocess, "Popen", forbidden)
        guarded.setattr(subprocess, "run", forbidden)
        guarded.setattr(builtins, "__import__", guarded_import)
        exec(compiled, fixture.__dict__)
        for mode in ("isolated", "mock", "shared-backend"):
            result = fixture.plan_instance(
                repository_id=REPOSITORY,
                worktree_id=WORKTREE,
                commit=COMMIT,
                generation=1,
                mode=mode,
                auth_mode="native",
            )
            assert fixture.InstanceDescriptor.from_dict(result.descriptor.to_dict()) == result.descriptor
            assert len(result.fingerprint) == 64
    forbidden.assert_not_called()
