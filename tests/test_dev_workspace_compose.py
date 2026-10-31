"""Synthetic Compose contracts only; --noconftest, no engine or real resource."""

from __future__ import annotations

import builtins
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
from scripts import dev_instance_plan
from scripts import dev_workspace_compose as compose
from scripts import dev_workspace_provider as provider

SECRET = "synthetic-private-path-and-identity-never-public"


def provider_plan(**changes):
    descriptor = dev_instance_plan.plan_instance(
        **{
            "repository_id": "a" * 64,
            "worktree_id": "b" * 64,
            "commit": "c" * 40,
            "generation": 1,
            "mode": "isolated",
            "auth_mode": "native",
            "provider": "container",
            **changes,
        }
    ).descriptor
    policy = provider.ContainerPolicy(
        "docker",
        "d" * 64,
        "e" * 64,
        {name: f"reference.invalid/{name}@sha256:" + "f" * 64 for name in compose._COMPONENTS},
        {"postgres": "999:999", "redis": "1000:1000", "mailpit": "1001:1001"},
    )
    return provider.plan_provider(descriptor, policy)


def policy(plan, **changes):
    names = [value for values in compose.secret_layout(plan).values() for value in values.values()]
    return compose.ComposePolicy(
        **{
            "reference": plan.policy.policy_id,
            "bundle_generation": "1" * 64,
            "host_platform": "linux",
            "platforms": {name: "linux/amd64" for name in compose._COMPONENTS},
            "profiles": compose._PROFILES,
            "limits": {
                name: compose.ResourceLimits("1.5", 768 * 1048576, 192, 32 * 1048576, 128 * 1048576)
                for name in compose._COMPONENTS
            },
            "data_ownership": {
                "postgres": compose.DataOwnership(999, 999, 0o700),
                "redis": compose.DataOwnership(1000, 1000, 0o700),
            },
            "volume_population": {name: "copy-empty-image-directory" for name in ("postgres", "redis")},
            "health": compose.HealthPolicy(5, 2, 20, 10, 20),
            "secret_files": tuple(compose.SecretFile(name, f"/private/{SECRET}/{name}", "linux") for name in names),
            **changes,
        }
    )


def review(plan, settings, **changes):
    return compose.ComposeContractReview(
        **{
            "reference": "2" * 64,
            "provider_fingerprint": plan.fingerprint,
            "policy_fingerprint": compose.policy_fingerprint(settings),
            "private_binding": settings.private_binding(),
            "checks": {name: "VERIFIED" for name in compose._CHECKS},
            **changes,
        }
    )


def document(plan=None, settings=None, *, accepted=False):
    plan = plan or provider_plan()
    settings = settings or policy(plan)
    manifest = compose.plan_compose(plan, settings, review=review(plan, settings) if accepted else None)
    return manifest, json.loads(manifest.render_private_manifest())


def test_reference_source_can_generate_but_does_not_claim_policy_or_image_approval():
    plan, rendered = document()
    result = plan.to_dict()
    assert result["status"] == "BLOCKED" and result["blockers"] == ["COMPOSE_RUNTIME_CONTRACT_REVIEW_REQUIRED"]
    assert all(value == "NOT_VERIFIED" for value in result["verification"].values())
    assert result["private_bundle_independently_verified"] is False
    assert result["live_authorized"] is False and result["ownership_verified"] is False
    assert result["database_authorized"] is False and result["live_execution_gates"]
    assert set(rendered["services"]) == {"postgres", "redis", "mailpit"}
    assert all(item["pull_policy"] == "never" for item in rendered["services"].values())


def test_matching_trusted_source_review_enables_resource_review_without_live_authority():
    plan, rendered = document(accepted=True)
    assert plan.blockers == () and plan.to_dict()["status"] == "READY_FOR_RESOURCE_REVIEW"
    assert all(value == "VERIFIED" for value in plan.to_dict()["verification"].values())
    assert plan.to_dict()["supplied_review"]["independently_authenticated_by_generator"] is False
    metadata = rendered["x-sbom-development"]
    assert metadata["live_authorized"] is False and metadata["ownership_verified"] is False
    assert metadata["live_execution_gates"] == list(compose._LIVE_GATES)
    assert metadata["postgres_initialization"]["ordinary_runtime_initializes_database"] is False
    assert metadata["postgres_initialization"]["authorized"] is False


def test_services_have_explicit_nonroot_limits_readonly_security_and_loopback_ports():
    plan, rendered = document()
    for original in plan.provider_plan.containers:
        item = rendered["services"][original.component]
        assert item["user"] == original.user and item["user"].split(":")[0] != "0"
        assert item["platform"] == "linux/amd64" and "@sha256:" in item["image"]
        assert item["read_only"] is True and item["privileged"] is False
        assert item["cap_drop"] == ["ALL"] and item["cap_add"] == []
        assert item["security_opt"] == ["no-new-privileges:true"]
        assert item["ipc"] == "private" and item["restart"] == "no"
        assert "network_mode" not in item and "devices" not in item and "pid" not in item
        assert item["cpus"] == "1.5" and int(item["mem_limit"]) == 768 * 1048576 and item["pids_limit"] == 192
        assert int(item["shm_size"]) == 128 * 1048576
        assert item["stop_grace_period"] == "20s"
        assert item["labels"] == dict(plan.provider_plan.labels)
        assert item["networks"] == [plan.provider_plan.network]
        assert all(port["host_ip"] == "127.0.0.1" and port["protocol"] == "tcp" for port in item["ports"])
        assert item["tmpfs"][0].startswith("/tmp:rw,noexec,nosuid,")
        assert "mode=0700" in item["tmpfs"][0]


def test_fresh_volume_mounts_are_anonymous_and_copy_up_requires_explicit_policy():
    plan, rendered = document()
    assert rendered["volumes"] == {}
    for item in rendered["services"].values():
        for mount in item["volumes"]:
            assert mount["type"] == "volume" and "source" not in mount
            assert mount["volume"] == {"nocopy": False}
            assert mount["target"] in {"/data", "/var/lib/postgresql/data"}
    claims = rendered["x-sbom-development"]["logical_volume_claims"]
    assert {item["logical_name"] for item in claims} == set(plan.provider_plan.volumes)
    assert all(item["ownership"]["mode"] == "0700" for item in claims)
    settings = replace(
        plan.policy, volume_population={"postgres": "preowned-empty-volume", "redis": "preowned-empty-volume"}
    )
    _, readonly = document(plan.provider_plan, settings)
    assert all(mount["volume"]["nocopy"] is True for item in readonly["services"].values() for mount in item["volumes"])
    assert not any(
        "chown" in str(item) or "initdb" in str(item.get("entrypoint")) for item in readonly["services"].values()
    )


def test_resolved_volume_receipts_are_exact_external_ids_for_restart_and_not_ownership():
    plan, _ = document()
    allocations = dict(zip(plan.provider_plan.volumes, ("3" * 64, "4" * 64), strict=True))
    rendered = json.loads(plan.render_private_manifest(allocations=allocations))
    assert rendered["volumes"] == {name: {"name": actual, "external": True} for name, actual in allocations.items()}
    assert all(mount["source"] in allocations for item in rendered["services"].values() for mount in item["volumes"])
    assert rendered["x-sbom-development"]["allocation_ownership_verified"] is False
    assert rendered["x-sbom-development"]["supplied_volume_allocations"] == allocations
    allocations.clear()
    assert plan.provider_plan.volumes and rendered["volumes"]


@pytest.mark.parametrize("kind", ["missing", "extra", "named", "duplicate", "wrong-instance", "type"])
def test_unverified_or_partial_allocation_shape_is_refused_without_any_lookup(kind):
    plan, _ = document()
    values = dict(zip(plan.provider_plan.volumes, ("3" * 64, "4" * 64), strict=True))
    if kind == "missing":
        values.pop(next(iter(values)))
    elif kind == "extra":
        values[SECRET] = "5" * 64
    elif kind == "named":
        values[next(iter(values))] = "existing-protected-volume"
    elif kind == "duplicate":
        values = dict.fromkeys(values, "3" * 64)
    elif kind == "wrong-instance":
        values = {name + "-wrong": item for name, item in values.items()}
    else:
        values = True
    with pytest.raises(compose.ComposePlanError, match="^COMPOSE_VOLUME_ALLOCATION_INVALID$"):
        plan.render_private_manifest(allocations=values)


def test_standard_commands_use_only_public_file_paths_and_do_not_auto_initialize_pg():
    plan, rendered = document()
    postgres, redis, mail = (rendered["services"][name] for name in ("postgres", "redis", "mailpit"))
    assert postgres["entrypoint"] == ["postgres"] and postgres["command"][0] == "-c"
    assert "ssl=on" in postgres["command"] and any(
        value.startswith("hba_file=/run/secrets/") for value in postgres["command"]
    )
    assert postgres["environment"]["POSTGRES_PASSWORD_FILE"].startswith("/run/secrets/")
    assert "POSTGRES_PASSWORD" not in postgres["environment"]
    assert postgres["environment"]["PGSSLMODE"] == "verify-full"
    assert redis["entrypoint"] == ["redis-server"] and len(redis["command"]) == 1
    assert redis["command"][0].endswith("-redis-credential") and redis["environment"] == {}
    assert mail["entrypoint"] == ["/mailpit"] and mail["command"] == []
    assert mail["environment"]["MP_SMTP_REQUIRE_STARTTLS"] == "true"
    assert mail["environment"]["MP_SMTP_AUTH_ALLOW_INSECURE"] == "false"
    assert mail["environment"]["MP_SMTP_AUTH_ACCEPT_ANY"] == "false"
    assert mail["environment"]["MP_ALLOW_UNTRUSTED_TLS"] == "false"
    for name in ("MP_UI_AUTH_FILE", "MP_SMTP_AUTH_FILE", "MP_UI_TLS_CERT", "MP_SMTP_TLS_KEY"):
        assert mail["environment"][name].startswith("/run/secrets/")
    assert all("$" not in str(item) for item in rendered["services"].values())
    assert plan.provider_plan.database_owner_role != plan.provider_plan.database_runtime_role


def test_external_health_contract_does_not_assume_image_tools_or_disable_tls_verification():
    plan, rendered = document()
    assert all(item["healthcheck"] == {"disable": True} for item in rendered["services"].values())
    health = rendered["x-sbom-development"]["external_health"]
    assert health["postgres"]["protocol"] == "postgresql-verify-full-readonly"
    assert health["postgres"]["role"] == plan.provider_plan.database_runtime_role
    assert health["redis"]["protocol"] == "rediss-authenticated-ping"
    assert health["mailpit"]["protocol"] == "https-authenticated-and-smtp-starttls"
    for item in health.values():
        assert item["verify_certificate_and_hostname"] is True and item["observed"] is False
        assert item["host"] == "127.0.0.1" and item["adapter_required"] is True
        assert item["timeout_seconds"] == 2 and item["retries"] == 20
        assert "password" not in item and "token" not in item
    assert (
        "curl" not in str(rendered) and "--insecure" not in str(rendered) and 'readyz"' not in str(rendered["services"])
    )


def test_secret_source_paths_are_private_and_unsupported_uid_mode_remapping_is_not_claimed():
    plan, rendered = document(accepted=True)
    public = json.dumps(plan.to_dict()) + repr(plan) + repr(plan.policy) + repr(plan.review)
    assert SECRET not in public and plan.policy.private_binding() not in public
    assert SECRET in plan.render_private_manifest()  # Explicit private artifact, not public diagnostics.
    assert len(rendered["secrets"]) == 14
    assert all(set(item) == {"file"} for item in rendered["secrets"].values())
    assert all(
        set(item) == {"source", "target"} for service in rendered["services"].values() for item in service["secrets"]
    )
    assert {item["source"] for service in rendered["services"].values() for item in service["secrets"]} == set(
        rendered["secrets"]
    )
    assert all(mount["type"] != "bind" for service in rendered["services"].values() for mount in service["volumes"])


def test_private_path_drift_is_rejected_without_publishing_its_hash():
    source = provider_plan()
    first = policy(source)
    changed_file = replace(first.secret_files[0], source=first.secret_files[0].source + "-changed")
    changed = replace(first, secret_files=(changed_file, *first.secret_files[1:]))
    assert first.to_dict() == changed.to_dict() and compose.policy_fingerprint(first) == compose.policy_fingerprint(
        changed
    )
    assert first.private_binding() != changed.private_binding()
    original = compose.plan_compose(source, first)
    current = compose.plan_compose(source, changed)
    assert original.fingerprint == current.fingerprint
    with pytest.raises(compose.ComposePlanError, match="^COMPOSE_PLAN_CHANGED$"):
        compose.revalidate_compose(original, provider_plan=source, policy=changed)
    stale = compose.plan_compose(source, changed, review=review(source, first))
    assert stale.blockers == ("COMPOSE_CONTRACT_REVIEW_DRIFT",)


@pytest.mark.parametrize("field", ["provider_fingerprint", "policy_fingerprint", "private_binding"])
def test_review_cannot_be_replayed_on_changed_context(field):
    source = provider_plan()
    settings = policy(source)
    stale = review(source, settings, **{field: "9" * 64})
    assert compose.plan_compose(source, settings, review=stale).blockers == ("COMPOSE_CONTRACT_REVIEW_DRIFT",)


@pytest.mark.parametrize("state", ["NOT_VERIFIED", "FAILED"])
def test_one_unverified_or_failed_contract_blocks_source_readiness(state):
    source = provider_plan()
    settings = policy(source)
    checks = {name: "VERIFIED" for name in compose._CHECKS}
    checks["nonroot_postgres_initialization"] = state
    assert compose.plan_compose(source, settings, review=review(source, settings, checks=checks)).blockers == (
        "COMPOSE_RUNTIME_CONTRACT_UNVERIFIED",
    )


@pytest.mark.parametrize("value", [True, False, {"approved": True}, "VERIFIED"])
def test_untyped_markers_cannot_replace_a_bound_source_review(value):
    source = provider_plan()
    with pytest.raises(compose.ComposePlanError, match="^COMPOSE_CONTRACT_REVIEW_REQUIRED$"):
        compose.plan_compose(source, policy(source), review=value)


def test_review_requires_exact_typed_checks_instead_of_approval_booleans():
    source = provider_plan()
    settings = policy(source)
    for checks in (
        {"approved": "VERIFIED"},
        {name: True for name in compose._CHECKS},
        {name: SECRET for name in compose._CHECKS},
    ):
        with pytest.raises(compose.ComposePlanError, match="^COMPOSE_REVIEW_CHECKS_INVALID$"):
            review(source, settings, checks=checks)


def test_two_instances_have_disjoint_projects_names_ports_labels_and_secret_references():
    first = provider_plan()
    second = provider_plan(worktree_id="8" * 64, claimed_ports=tuple(first.descriptor.ports.values()))
    one, left = document(first)
    two, right = document(second)
    assert left["name"] != right["name"] and set(left["networks"]).isdisjoint(right["networks"])
    assert set(first.volumes).isdisjoint(second.volumes) and set(left["secrets"]).isdisjoint(right["secrets"])
    for name in compose._COMPONENTS:
        assert left["services"][name]["container_name"] != right["services"][name]["container_name"]
        assert (
            left["services"][name]["labels"]["io.sbom.dev.worktree"]
            != right["services"][name]["labels"]["io.sbom.dev.worktree"]
        )
    assert set(first.descriptor.ports.values()).isdisjoint(second.descriptor.ports.values())
    assert one.fingerprint != two.fingerprint


@pytest.mark.parametrize(
    "values",
    [
        {"cpus": True},
        {"cpus": "0"},
        {"cpus": "NaN"},
        {"cpus": "65"},
        {"memory_bytes": True},
        {"memory_bytes": 1},
        {"pids": 0},
        {"tmpfs_bytes": 0},
        {"shm_bytes": 1073741824},
    ],
)
def test_resource_limits_are_explicit_bounded_and_strict(values):
    with pytest.raises(compose.ComposePlanError, match="^COMPOSE_LIMITS_INVALID$"):
        compose.ResourceLimits(
            **{
                "cpus": "1.5",
                "memory_bytes": 768 * 1048576,
                "pids": 192,
                "tmpfs_bytes": 32 * 1048576,
                "shm_bytes": 128 * 1048576,
                **values,
            }
        )


@pytest.mark.parametrize(
    "path,platform",
    [
        ("relative/private", "linux"),
        ("/private/../existing", "linux"),
        ("/private/$HOME/value", "linux"),
        ("//server/share/private", "linux"),
        ("/private/value\nsecret", "linux"),
        ("/", "linux"),
        ("C:relative", "win32"),
        ("C:\\private\\..\\existing", "win32"),
        ("C:\\private\\NUL", "win32"),
        ("C:\\private\\COM¹", "win32"),
        ("C:\\private\\CONIN$", "win32"),
        ('C:\\private\\value"', "win32"),
        ("C:\\private\\value:stream", "win32"),
        ("\\\\server\\share\\value", "win32"),
    ],
)
def test_unsafe_or_interpolated_private_paths_are_refused_without_echo(path, platform):
    reference = next(iter(compose.secret_layout(provider_plan())["postgres"].values()))
    with pytest.raises(compose.ComposePlanError, match="^COMPOSE_PRIVATE_FILE_PATH_INVALID$") as caught:
        compose.SecretFile(reference, path, platform)
    assert path not in str(caught.value)


def test_windows_private_file_paths_are_only_in_explicit_private_artifact():
    source = provider_plan()
    files = tuple(
        compose.SecretFile(name, f"C:\\private\\{SECRET}\\{name}", "win32")
        for values in compose.secret_layout(source).values()
        for name in values.values()
    )
    settings = policy(source, host_platform="win32", secret_files=files)
    result = compose.plan_compose(source, settings)
    assert SECRET not in repr(result) + json.dumps(result.to_dict())
    assert all(
        item["file"].startswith("C:\\private\\")
        for item in json.loads(result.render_private_manifest())["secrets"].values()
    )


@pytest.mark.parametrize("engine", ["docker", "podman"])
@pytest.mark.parametrize("platform", ["linux/amd64", "linux/arm64", "linux/arm64/v8"])
def test_source_manifest_is_provider_agnostic_with_explicit_pinned_platform(engine, platform):
    original = provider_plan()
    source = provider.plan_provider(original.descriptor, replace(original.policy, engine=engine))
    settings = policy(source, platforms=dict.fromkeys(compose._COMPONENTS, platform))
    result, rendered = document(source, settings, accepted=True)
    assert not result.blockers
    assert result.to_dict()["provider"]["engine"] == engine
    assert all(item["platform"] == platform for item in rendered["services"].values())


def test_ownership_layout_profile_platform_and_policy_drift_cannot_be_silently_adopted():
    source = provider_plan()
    settings = policy(source)
    for changed, code in (
        (replace(settings, reference="7" * 64), "COMPOSE_POLICY_REFERENCE_DRIFT"),
        (replace(settings, secret_files=settings.secret_files[1:]), "COMPOSE_SECRET_LAYOUT_DRIFT"),
        (
            replace(
                settings,
                data_ownership={
                    "postgres": compose.DataOwnership(1002, 1002, 0o700),
                    "redis": settings.data_ownership["redis"],
                },
            ),
            "COMPOSE_DATA_OWNER_DRIFT",
        ),
    ):
        with pytest.raises(compose.ComposePlanError, match="^" + code + "$"):
            compose.plan_compose(source, changed)
    for changes in (
        {"platforms": dict.fromkeys(compose._COMPONENTS, "windows/amd64")},
        {"profiles": {**compose._PROFILES, "redis": "sh -c " + SECRET}},
        {"volume_population": {"postgres": "root-chown", "redis": "root-chown"}},
    ):
        with pytest.raises(compose.ComposePlanError):
            replace(settings, **changes)
    with pytest.raises(TypeError):
        policy(source, environment={"PASSWORD": SECRET})


def test_user_and_group_must_both_be_explicit_nonroot_and_shared_secret_files_are_refused():
    source = provider_plan()
    less_explicit = replace(source.policy, users={**source.policy.users, "postgres": "999"})
    with pytest.raises(compose.ComposePlanError, match="^COMPOSE_EXPLICIT_UID_GID_REQUIRED$"):
        compose.plan_compose(provider.plan_provider(source.descriptor, less_explicit), policy(source))
    with pytest.raises(compose.ComposePlanError):
        compose.DataOwnership(0, 0, 0o700)
    settings = policy(source)
    duplicate = replace(settings.secret_files[1], source=settings.secret_files[0].source)
    with pytest.raises(compose.ComposePlanError, match="^COMPOSE_SHARED_SECRET_FILE_REFUSED$"):
        replace(settings, secret_files=(settings.secret_files[0], duplicate, *settings.secret_files[2:]))


def test_plan_is_immutable_detached_and_cannot_have_blockers_or_fingerprint_forged():
    plan, _ = document()
    with pytest.raises(FrozenInstanceError):
        plan.fingerprint = "9" * 64
    with pytest.raises(TypeError):
        plan.policy.platforms["postgres"] = "windows/amd64"
    with pytest.raises(compose.ComposePlanError, match="^COMPOSE_PLAN_BINDING_INVALID$"):
        replace(plan, blockers=())
    with pytest.raises(compose.ComposePlanError, match="^COMPOSE_PLAN_BINDING_INVALID$"):
        replace(plan, fingerprint="9" * 64)
    output = plan.to_dict()
    output["policy"]["platforms"]["postgres"] = SECRET
    assert plan.policy.platforms["postgres"] == "linux/amd64"


def test_pure_import_generation_and_revalidation_have_mutation_network_and_application_tripwires(monkeypatch):
    source = Path(compose.__file__).read_text(encoding="utf-8")
    compiled = compile(source, "<synthetic-pure-compose>", "exec")
    fixture = types.ModuleType("scripts.synthetic_pure_compose")
    fixture.__package__ = "scripts"
    monkeypatch.setitem(sys.modules, fixture.__name__, fixture)
    original_import = builtins.__import__
    forbidden = Mock(side_effect=AssertionError("Pure Compose generation attempted an external operation"))

    def safe_import(name, *arguments, **keywords):
        assert name.split(".", 1)[0] not in {"app", "psycopg", "sqlalchemy", "redis", "celery", "dotenv", "docker"}
        return original_import(name, *arguments, **keywords)

    original, settings = provider_plan(), None
    settings = policy(original)
    expected = compose.plan_compose(original, settings)
    with monkeypatch.context() as guard:
        guard.setattr(builtins, "__import__", safe_import)
        guard.setattr(builtins, "open", forbidden)
        guard.setattr(io, "open", forbidden)
        guard.setattr(os, "open", forbidden)
        guard.setattr(os, "getenv", forbidden)
        guard.setattr(os, "environ", None)
        guard.setattr(socket, "socket", forbidden)
        guard.setattr(socket, "create_connection", forbidden)
        guard.setattr(subprocess, "Popen", forbidden)
        guard.setattr(subprocess, "run", forbidden)
        guard.setattr(Path, "resolve", forbidden)
        guard.setattr(Path, "mkdir", forbidden)
        exec(compiled, fixture.__dict__)
        actual = compose.plan_compose(original, settings)
        assert actual == expected and actual.render_private_manifest() == expected.render_private_manifest()
        assert compose.revalidate_compose(actual, provider_plan=original, policy=settings) == actual
    forbidden.assert_not_called()


def test_direct_module_execution_has_no_provider_execution_path(monkeypatch):
    source = Path(compose.__file__).read_text(encoding="utf-8")
    fixture = types.ModuleType("__main__")
    fixture.__package__ = "scripts"
    monkeypatch.setitem(sys.modules, "__main__", fixture)
    forbidden = Mock(side_effect=AssertionError("Direct invocation attempted a live operation"))
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(Path, "mkdir", forbidden)
    with pytest.raises(SystemExit, match="COMPOSE_GENERATION_ONLY"):
        exec(compile(source, "<synthetic-compose-main>", "exec"), fixture.__dict__)
    forbidden.assert_not_called()
