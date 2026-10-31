"""Synthetic engine boundaries only: no executable, daemon, database or provider."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev_instance_plan, dev_instance_storage, dev_private
from scripts import dev_workspace_compose as compose
from scripts import dev_workspace_engine as engine
from scripts import dev_workspace_provider as provider

SECRET = "synthetic-private-value-never-disclose"
COMPONENTS = ("postgres", "redis", "mailpit")
BIRTH = "2026-10-31T00:00:00.000000001Z"
EMPTY_BIRTH = "0001-01-01T00:00:00Z"


def private_directory(path):
    if os.name == "nt":
        dev_instance_storage._windows_create(path)
    else:
        path.mkdir(mode=0o700)
    return path


class Authority:
    def __init__(self, checks=None):
        self.checks = engine._CHECKS | engine._CREATE_CHECKS | engine._DATABASE_CHECKS if checks is None else checks
        self.requests = []

    def verify(self, request):
        self.requests.append(request)
        return engine.PolicyAuthorization(request.fingerprint, frozenset(self.checks))


class FakeDocker:
    def __init__(self):
        self.calls = []
        self.info = {"ID": "synthetic-daemon", "OSType": "linux", "Architecture": "x86_64"}
        self.images, self.containers, self.volumes = {}, {}, {}
        self.network = None
        self.on_call = None

    def configure(self, plan, contract, files, *, existing):
        self.images, self.containers, self.volumes, self.network = {}, {}, {}, None
        self.plan, self.contract, self.files = plan, contract, files
        self.document = json.loads(contract.render_private_manifest())
        self.network_template = {
            "Id": "4" * 64,
            "Name": plan.network,
            "Labels": dict(plan.labels),
            "Driver": "bridge",
            "Internal": True,
            "Options": {},
        }
        if existing:
            self.network = dict(self.network_template)
        self.templates = {}
        self.logical_volumes = {}
        for index, spec in enumerate(plan.containers):
            service = self.document["services"][spec.component]
            image_id = "sha256:" + str(index + 7) * 64
            image = {
                "Id": image_id,
                "RepoDigests": [spec.image],
                "Os": "linux",
                "Architecture": "amd64",
                "Config": {"Env": ["PATH=/synthetic"], "Entrypoint": ["synthetic-entrypoint"], "Cmd": None},
            }
            self.images[spec.image] = image
            mounts = []
            for mount in spec.mounts:
                actual = str(index + 5) * 64
                self.logical_volumes[mount.name] = actual
                self.volumes[actual] = {
                    "Name": actual,
                    "CreatedAt": BIRTH,
                    "Driver": "local",
                    "Mountpoint": "/synthetic/" + actual,
                    "Scope": "local",
                    "Options": None,
                    "Labels": None,
                }
                mounts.append({"Type": "volume", "Name": actual, "Destination": mount.target, "RW": True})
            for item in service["secrets"]:
                mounts.append(
                    {
                        "Type": "bind",
                        "Source": str(files[item["source"]].path),
                        "Destination": "/run/secrets/" + item["target"],
                        "RW": False,
                    }
                )
            values = {"PATH": "/synthetic", **service["environment"]}
            value = {
                "Id": str(index + 1) * 64,
                "Name": "/" + spec.name,
                "Image": image_id,
                "Config": {
                    "Healthcheck": {"Test": ["NONE"]},
                    "Image": spec.image,
                    "User": spec.user,
                    "Labels": dict(plan.labels),
                    "Env": [key + "=" + item for key, item in values.items()],
                    "Entrypoint": service.get("entrypoint", image["Config"]["Entrypoint"]),
                    "Cmd": service.get("command", image["Config"]["Cmd"]),
                },
                "HostConfig": {
                    "NetworkMode": "4" * 64,
                    "Privileged": False,
                    "ReadonlyRootfs": True,
                    "CapDrop": ["ALL"],
                    "CapAdd": [],
                    "Devices": [],
                    "PidMode": "",
                    "IpcMode": "private",
                    "SecurityOpt": ["no-new-privileges:true"],
                    "PortBindings": {
                        f"{port.container_port}/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(port.host_port)}]
                        for port in spec.ports
                    },
                    "Memory": int(service["mem_limit"]),
                    "PidsLimit": service["pids_limit"],
                    "NanoCpus": int(float(service["cpus"]) * 1000000000),
                    "ShmSize": int(service["shm_size"]),
                    "Tmpfs": dict(item.split(":", 1) for item in service["tmpfs"]),
                },
                "Mounts": mounts,
                "State": {
                    "Status": "running" if existing else "created",
                    "StartedAt": BIRTH if existing else EMPTY_BIRTH,
                },
                "NetworkSettings": {"Networks": {plan.network: {"NetworkID": "4" * 64}}},
            }
            self.templates[spec.name] = value
            if existing:
                self.containers[value["Id"]] = value

    def records(self):
        volumes = tuple(
            (
                logical,
                actual,
                engine._digest(
                    [
                        self.volumes[actual].get(key)
                        for key in ("Name", "CreatedAt", "Driver", "Mountpoint", "Scope", "Options")
                    ]
                ),
            )
            for logical, actual in self.logical_volumes.items()
        )
        containers = tuple(
            engine.ContainerRecord(spec.component, value["Id"], value["State"]["StartedAt"])
            for spec in self.plan.containers
            for value in [self.containers[self.templates[spec.name]["Id"]]]
        )
        return engine.ResourceRecords(
            self.plan.policy.engine_identity,
            self.plan.fingerprint,
            containers,
            "4" * 64,
            volumes,
            tuple(self.files.values()),
        )

    def __call__(self, argv, *, environment, cwd, timeout):
        assert Path(argv[0]).is_absolute() and argv[1] == "--config" and argv[3] == "--host"
        assert 0 < timeout <= 125 and Path(cwd).is_absolute()
        assert (
            SECRET not in repr(environment) and "DOCKER_HOST" not in environment and "DATABASE_URL" not in environment
        )
        args = tuple(argv[5:])
        self.calls.append(args)
        if self.on_call:
            self.on_call(args)
        if args[0] == "version":
            result = {"Client": {"Version": "29.0.0"}}
        elif args[0] == "info":
            result = self.info
        elif args[:2] == ("compose", "version"):
            return b"2.39.4\n"
        elif args[:2] == ("network", "create"):
            self.network = dict(self.network_template)
            return (self.network["Id"] + "\n").encode()
        elif args[:2] == ("container", "create"):
            value = self.templates[args[args.index("--name") + 1]]
            self.containers[value["Id"]] = value
            return (value["Id"] + "\n").encode()
        elif len(args) == 3 and args[1] == "inspect":
            kind, _, object_id = args
            result = [
                {
                    "container": self.containers,
                    "network": {"4" * 64: self.network},
                    "volume": self.volumes,
                    "image": self.images,
                }[kind][object_id]
            ]
        elif args[:2] == ("container", "stop"):
            self.containers[args[-1]]["State"]["Status"] = "exited"
            return (args[-1] + "\n").encode()
        elif args[:2] == ("container", "start"):
            self.containers[args[-1]]["State"] = {"Status": "running", "StartedAt": "2026-10-31T01:00:00Z"}
            return (args[-1] + "\n").encode()
        else:
            raise AssertionError("Unexpected synthetic engine operation")
        return json.dumps(result).encode()


@pytest.fixture
def prepared(tmp_path):
    root = private_directory(tmp_path.resolve() / "private-engine")
    config = private_directory(root / "empty-cli-config")
    executable = root / "docker.exe"
    dev_private.create_private_file(executable, b"synthetic executable: must never be executed")
    fake = FakeDocker()
    endpoint = "npipe:////./pipe/docker_engine" if os.name == "nt" else "unix:///synthetic/docker.sock"
    capability = engine.discover_engine(executable=executable, config_root=config, endpoint=endpoint, runner=fake)
    assert capability.status == "AVAILABLE"
    descriptor = dev_instance_plan.plan_instance(
        repository_id="a" * 64, worktree_id="b" * 64, commit="c" * 40, generation=1, mode="isolated", auth_mode="native"
    ).descriptor
    policy = provider.ContainerPolicy(
        "docker",
        "d" * 64,
        capability.engine_identity,
        {name: "approved/" + name + "@sha256:" + str(index + 1) * 64 for index, name in enumerate(COMPONENTS)},
        {name: "1000:1000" for name in COMPONENTS},
    )
    plan = provider.plan_provider(descriptor, policy)
    files, references = {}, []
    for name in (item for values in compose.secret_layout(plan).values() for item in values.values()):
        path = root / name
        dev_private.create_private_file(path, (SECRET + ":" + name).encode())
        files[name] = engine.SecretFile.inspect(name, path)
        references.append(compose.SecretFile(name, str(path), sys.platform))
    contract_policy = compose.ComposePolicy(
        policy.policy_id,
        "e" * 64,
        sys.platform,
        {name: "linux/amd64" for name in COMPONENTS},
        dict(compose._PROFILES),
        {name: compose.ResourceLimits("1.5", 128 * 1048576, 192, 1048576, 1048576) for name in COMPONENTS},
        {name: compose.DataOwnership(1000, 1000, 0o700) for name in ("postgres", "redis")},
        {name: "preowned-empty-volume" for name in ("postgres", "redis")},
        compose.HealthPolicy(3, 2, 5, 0, 10),
        tuple(references),
    )
    review = compose.ComposeContractReview(
        "f" * 64,
        plan.fingerprint,
        compose.policy_fingerprint(contract_policy),
        contract_policy.private_binding(),
        {name: "VERIFIED" for name in compose._CHECKS},
    )
    contract = compose.plan_compose(plan, contract_policy, review=review)
    fake.configure(plan, contract, files, existing=True)
    fake.calls.clear()
    return SimpleNamespace(
        root=root,
        config=config,
        executable=executable,
        endpoint=endpoint,
        fake=fake,
        capability=capability,
        plan=plan,
        compose=contract,
        files=files,
    )


def request(fixture, action="stop", *, records=None):
    records = fixture.fake.records() if action != "create" and records is None else records
    secrets = tuple(fixture.files.values()) if action == "create" else ()
    consent = engine.ActionConsent(
        action,
        "ec282b2a-593c-4f1c-b43b-82489a6b561c",
        fixture.plan.fingerprint,
        fixture.capability.engine_identity,
        fixture.plan.policy.policy_id,
        engine.action_targets(fixture.plan, fixture.compose, recorded=records, secrets=secrets),
    )
    return engine.plan_action(
        fixture.plan, fixture.capability, consent, compose=fixture.compose, recorded=records, secrets=secrets
    )


def mutations(fake):
    return [
        args
        for args in fake.calls
        if len(args) > 1 and args[1] in {"create", "start", "stop", "rm", "remove", "up", "down", "pull"}
    ]


def test_missing_engine_and_podman_are_explicit_without_spawning(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("Missing or unsupported engine spawned a helper"))
    monkeypatch.setattr(engine.shutil, "which", lambda name: None)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    assert engine.discover_engine().status == "MISSING"
    podman = engine.PodmanAdapter.discover(executable="docker")
    assert podman.status == "UNSUPPORTED" and podman.to_dict()["engine"] == "podman"
    assert engine.PodmanAdapter.execute(None).code == "ENGINE_UNSUPPORTED"
    forbidden.assert_not_called()


def test_discovery_uses_only_explicit_local_context_and_sanitized_environment(prepared, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", SECRET)
    monkeypatch.setenv("DOCKER_HOST", "tcp://" + SECRET)
    outcome = engine.discover_engine(
        executable=prepared.executable, config_root=prepared.config, endpoint=prepared.endpoint, runner=prepared.fake
    )
    assert outcome.status == "AVAILABLE" and outcome.compose_version is None
    assert SECRET not in repr(outcome) + json.dumps(outcome.to_dict())
    assert outcome.to_dict()["ownership_verified"] is outcome.to_dict()["live_authorized"] is False
    assert not mutations(prepared.fake)


def test_optional_compose_plugin_is_pinned_before_its_version_probe(prepared):
    plugin = prepared.root / "docker-compose.exe"
    dev_private.create_private_file(plugin, b"synthetic plugin: never execute")
    prepared.fake.info["ClientInfo"] = {"Plugins": [{"Name": "compose", "Path": str(plugin)}]}
    result = engine.discover_engine(
        executable=prepared.executable, config_root=prepared.config, endpoint=prepared.endpoint, runner=prepared.fake
    )
    assert result.compose_version == "2.39.4" and result.to_dict()["compose_plugin_identity_verified"] is True
    assert str(plugin) not in repr(result) + json.dumps(result.to_dict())


def test_system_tool_symlink_is_resolved_once_then_commands_pin_the_canonical_binary(prepared, monkeypatch):
    locator = prepared.root / "system-docker-link"
    original_resolve = Path.resolve

    def resolve(path, *arguments, **keywords):
        return prepared.executable if path == locator else original_resolve(path, *arguments, **keywords)

    monkeypatch.setattr(Path, "resolve", resolve)
    result = engine.discover_engine(
        executable=locator, config_root=prepared.config, endpoint=prepared.endpoint, runner=prepared.fake
    )
    assert result.status == "AVAILABLE" and result.executable == prepared.executable
    assert result.to_dict()["code"] == "ENGINE_CAPABILITY_OBSERVED"


@pytest.mark.parametrize("problem", ["remote", "private-config", "malformed", "unsupported-platform"])
def test_discovery_refuses_unsafe_or_unknown_inputs_without_private_error_output(prepared, problem):
    endpoint, runner = prepared.endpoint, prepared.fake
    if problem == "remote":
        endpoint = "tcp://127.0.0.1:2375"
    elif problem == "private-config":
        dev_private.create_private_file(prepared.config / "config.json", SECRET.encode())
    elif problem == "malformed":
        runner = Mock(return_value=(SECRET + " not JSON").encode())
    else:
        prepared.fake.info["OSType"] = "windows"
    result = engine.discover_engine(
        executable=prepared.executable, config_root=prepared.config, endpoint=endpoint, runner=runner
    )
    assert result.status == "BLOCKED" and SECRET not in repr(result) + json.dumps(result.to_dict())
    assert not mutations(prepared.fake)


@pytest.mark.parametrize("action", ["start", "stop"])
def test_lifecycle_targets_only_recorded_ids_and_revalidates_each_mutation(prepared, action):
    authority = Authority()
    outcome = engine.DockerEngineClient(prepared.capability, authority=authority, runner=prepared.fake).execute(
        request(prepared, action)
    )
    assert outcome.code == "ENGINE_ACTION_COMPLETED" and len(outcome.completed_ids) == 3
    operations = mutations(prepared.fake)
    assert len(operations) == 3 and all(args[:2] == ("container", action) for args in operations)
    assert [args[-1] for args in operations] == (
        ["3" * 64, "2" * 64, "1" * 64] if action == "stop" else ["1" * 64, "2" * 64, "3" * 64]
    )
    assert len(authority.requests) >= 4 and outcome.to_dict()["application_ready"] is False


@pytest.mark.parametrize("missing", sorted(engine._CHECKS | engine._DATABASE_CHECKS))
def test_every_required_start_policy_check_is_enforced_before_mutation(prepared, missing):
    checks = engine._CHECKS | engine._DATABASE_CHECKS | engine._CREATE_CHECKS
    outcome = engine.DockerEngineClient(
        prepared.capability, authority=Authority(checks - {missing}), runner=prepared.fake
    ).execute(request(prepared, "start"))
    assert outcome.code == "ENGINE_POLICY_REQUIRED" and not mutations(prepared.fake)


@pytest.mark.parametrize(
    "drift",
    [
        "daemon",
        "labels",
        "user",
        "image",
        "ports",
        "mount",
        "network",
        "volume-birth",
        "command",
        "environment",
        "limits",
        "image-healthcheck",
        "secret",
    ],
)
def test_unknown_or_drifted_resources_remain_protected_from_stop(prepared, drift):
    planned = request(prepared)
    value = prepared.fake.containers["1" * 64]
    if drift == "daemon":
        prepared.fake.info["ID"] = "another-daemon"
    elif drift == "labels":
        value["Config"]["Labels"] = {}
    elif drift == "user":
        value["Config"]["User"] = "0"
    elif drift == "image":
        value["Image"] = "sha256:" + "0" * 64
    elif drift == "ports":
        value["HostConfig"]["PortBindings"] = {}
    elif drift == "mount":
        value["Mounts"][0]["Name"] = "0" * 64
    elif drift == "network":
        value["NetworkSettings"]["Networks"][prepared.plan.network]["NetworkID"] = "0" * 64
    elif drift == "volume-birth":
        prepared.fake.volumes["5" * 64]["CreatedAt"] = "another-generation"
    elif drift == "command":
        value["Config"]["Cmd"] = ["unreviewed-command"]
    elif drift == "environment":
        value["Config"]["Env"].append("PRIVATE=" + SECRET)
    elif drift == "limits":
        value["HostConfig"]["Memory"] = 0
    elif drift == "image-healthcheck":
        value["Config"]["Healthcheck"] = {"Test": ["CMD", "unsafe-default-healthcheck"]}
    else:
        next(iter(prepared.files.values())).path.write_bytes(b"synthetic replacement generation")
    result = engine.DockerEngineClient(prepared.capability, authority=Authority(), runner=prepared.fake).execute(
        planned
    )
    assert result.code in {"ENGINE_RESOURCE_DRIFT", "ENGINE_IDENTITY_CHANGED", "ENGINE_SECRET_FILE_UNVERIFIED"}
    assert not mutations(prepared.fake) and result.to_dict()["unknown_resources_preserved"] is True
    assert SECRET not in repr(result) + json.dumps(result.to_dict())


def test_exact_operator_consent_cannot_be_reused_for_another_recorded_id(prepared):
    planned = request(prepared)
    records = replace(planned.recorded, network_id="0" * 64)
    with pytest.raises(engine.EngineError, match="^ENGINE_CONSENT_REQUIRED$"):
        engine.plan_action(
            prepared.plan, prepared.capability, planned.consent, compose=prepared.compose, recorded=records
        )
    assert not mutations(prepared.fake)


def test_public_controller_code_drift_blocks_before_engine_mutation(prepared, monkeypatch):
    planned = request(prepared)
    changed = list(planned.controller_proofs)
    name, proof = changed[0]
    changed[0] = (name, (*proof[:-1], "0" * 64))
    monkeypatch.setattr(engine, "_controllers", lambda: tuple(changed))
    outcome = engine.DockerEngineClient(prepared.capability, authority=Authority(), runner=prepared.fake).execute(
        planned
    )
    assert outcome.code == "ENGINE_CONSENT_REQUIRED" and not mutations(prepared.fake)


def test_policy_adapter_private_errors_are_rejected_without_leaking_or_mutating(prepared):
    authority = Mock()
    authority.verify.side_effect = OSError(SECRET)
    result = engine.DockerEngineClient(prepared.capability, authority=authority, runner=prepared.fake).execute(
        request(prepared)
    )
    assert result.code == "ENGINE_POLICY_REQUIRED" and not mutations(prepared.fake)
    assert SECRET not in repr(result) + json.dumps(result.to_dict())


def test_partial_stop_reports_completed_ids_and_preserves_all_other_resources(prepared):
    def fail_second(args):
        if args[:2] == ("container", "stop") and args[-1] == "2" * 64:
            raise OSError(SECRET)

    prepared.fake.on_call = fail_second
    result = engine.DockerEngineClient(prepared.capability, authority=Authority(), runner=prepared.fake).execute(
        request(prepared)
    )
    assert result.code == "ENGINE_ACTION_UNCONFIRMED" and result.completed_ids == ("3" * 64,)
    assert all(args[1] not in {"rm", "remove", "down"} for args in prepared.fake.calls if len(args) > 1)
    assert len(prepared.fake.containers) == 3 and len(prepared.fake.volumes) == 2
    assert SECRET not in repr(result) + json.dumps(result.to_dict())


def test_stop_honors_the_exact_reviewed_compose_grace_and_child_deadline(prepared):
    policy = replace(prepared.compose.policy, health=replace(prepared.compose.policy.health, stop_grace_seconds=27))
    review = replace(prepared.compose.review, policy_fingerprint=compose.policy_fingerprint(policy))
    prepared.compose = compose.plan_compose(prepared.plan, policy, review=review)
    prepared.fake.configure(prepared.plan, prepared.compose, prepared.files, existing=True)

    def run(argv, **options):
        if tuple(argv[5:7]) == ("container", "stop"):
            assert options["timeout"] == 32
        return prepared.fake(argv, **options)

    outcome = engine.DockerEngineClient(prepared.capability, authority=Authority(), runner=run).execute(
        request(prepared)
    )
    assert outcome.code == "ENGINE_ACTION_COMPLETED"
    assert all(args[args.index("--time") + 1] == "27" for args in mutations(prepared.fake))


def test_fast_exit_after_start_is_unconfirmed_and_never_starts_other_components(prepared):
    def run(argv, **options):
        result = prepared.fake(argv, **options)
        if tuple(argv[5:7]) == ("container", "start"):
            prepared.fake.containers[argv[-1]]["State"]["Status"] = "exited"
        return result

    outcome = engine.DockerEngineClient(prepared.capability, authority=Authority(), runner=run).execute(
        request(prepared, "start")
    )
    assert outcome.code == "ENGINE_ACTION_UNCONFIRMED" and outcome.completed_ids == ("1" * 64,)
    assert len(mutations(prepared.fake)) == 1


def test_discovery_cleanup_uncertainty_reports_only_the_original_helper_pid(prepared):
    run = Mock(side_effect=engine.EngineError("ENGINE_CHILD_CLEANUP_UNCONFIRMED", child_pid=12345))
    outcome = engine.discover_engine(
        executable=prepared.executable, config_root=prepared.config, endpoint=prepared.endpoint, runner=run
    )
    assert outcome.code == "ENGINE_CHILD_CLEANUP_UNCONFIRMED" and outcome.to_dict()["probe_pid"] == 12345
    assert SECRET not in repr(outcome) + json.dumps(outcome.to_dict())


@pytest.mark.parametrize("action", ["create", "start", "stop"])
def test_real_docker_null_command_for_explicit_mailpit_entrypoint_is_supported(prepared, action):
    prepared.fake.configure(prepared.plan, prepared.compose, prepared.files, existing=action != "create")
    mailpit = prepared.fake.templates[prepared.plan.containers[2].name]
    mailpit["Config"]["Cmd"] = None
    outcome = engine.DockerEngineClient(prepared.capability, authority=Authority(), runner=prepared.fake).execute(
        request(prepared, action), creation_journal=Mock() if action == "create" else None
    )
    assert outcome.code == "ENGINE_ACTION_COMPLETED"


@pytest.mark.parametrize("shape", ["empty", "blank-name", "blank-id"])
def test_created_receipts_allow_unattached_endpoint_only_with_exact_recorded_network_mode(prepared, shape):
    prepared.fake.configure(prepared.plan, prepared.compose, prepared.files, existing=False)
    for value in prepared.fake.templates.values():
        value["NetworkSettings"]["Networks"] = (
            {}
            if shape == "empty"
            else {prepared.plan.network if shape == "blank-name" else "4" * 64: {"NetworkID": ""}}
        )
    outcome = engine.DockerEngineClient(prepared.capability, authority=Authority(), runner=prepared.fake).execute(
        request(prepared, "create"), creation_journal=Mock()
    )
    assert outcome.code == "ENGINE_ACTION_COMPLETED"


def test_create_uses_new_cid_receipts_anonymous_volumes_and_never_starts_postgres(prepared):
    prepared.fake.configure(prepared.plan, prepared.compose, prepared.files, existing=False)
    journal = Mock()
    result = engine.DockerEngineClient(prepared.capability, authority=Authority(), runner=prepared.fake).execute(
        request(prepared, "create"), creation_journal=journal
    )
    assert result.code == "ENGINE_ACTION_COMPLETED" and result.created_network_id == "4" * 64
    assert len(result.records.volume_births) == 2
    assert {logical for logical, _, _ in result.records.volume_births} == set(prepared.plan.volumes)
    operations = mutations(prepared.fake)
    assert operations[0][:2] == ("network", "create") and all(
        args[:2] == ("container", "create") for args in operations[1:]
    )
    for args in operations[1:]:
        assert args[args.index("--pull") + 1] == "never"
        assert not any("source=" in item for item in args if item.startswith("type=volume,"))
        assert not any(item.startswith("SBOM_DEV_") for item in args)
        assert SECRET not in repr(args)
    assert journal.record_receipt.call_count == 6  # network, three CIDs, two allocation receipts
    assert all(value["State"]["Status"] == "created" for value in prepared.fake.containers.values())


def test_creation_needs_journal_and_partial_failure_retains_receipted_resources(prepared):
    prepared.fake.configure(prepared.plan, prepared.compose, prepared.files, existing=False)
    planned = request(prepared, "create")
    client = engine.DockerEngineClient(prepared.capability, authority=Authority(), runner=prepared.fake)
    assert client.execute(planned).code == "ENGINE_CREATION_RECEIPT_REQUIRED"
    assert not mutations(prepared.fake)
    journal = Mock()
    journal.record_receipt.side_effect = OSError(SECRET)
    result = client.execute(planned, creation_journal=journal)
    assert result.code == "ENGINE_CREATION_UNCONFIRMED" and result.created_network_id == "4" * 64
    assert prepared.fake.network is not None and result.to_dict()["unknown_resources_preserved"] is True
    assert SECRET not in repr(result) + json.dumps(result.to_dict())


def test_private_bundle_drift_in_last_reservation_check_blocks_before_any_allocation(prepared):
    prepared.fake.configure(prepared.plan, prepared.compose, prepared.files, existing=False)
    planned = request(prepared, "create")
    journal = Mock()

    def verify_reservation(_request):
        if journal.verify_reservation.call_count == 2:
            next(iter(prepared.files.values())).path.write_bytes(b"synthetic replacement generation")

    journal.verify_reservation.side_effect = verify_reservation
    outcome = engine.DockerEngineClient(prepared.capability, authority=Authority(), runner=prepared.fake).execute(
        planned, creation_journal=journal
    )
    assert outcome.code == "ENGINE_SECRET_FILE_UNVERIFIED" and not mutations(prepared.fake)


def test_final_authority_rechecks_private_generation_even_when_file_metadata_is_unchanged(prepared, monkeypatch):
    prepared.fake.configure(prepared.plan, prepared.compose, prepared.files, existing=False)
    planned = request(prepared, "create")
    selected = next(iter(prepared.files.values()))
    original_bytes = selected.path.read_bytes()
    original_file = engine._file

    def fixed_metadata(path, **options):
        actual = original_file(path, **options)
        return selected.identity if path == selected.path else actual

    monkeypatch.setattr(engine, "_file", fixed_metadata)
    journal, authority = Mock(), Authority()

    def reserve(_request):
        if journal.verify_reservation.call_count == 2:
            selected.path.write_bytes(b"X" * len(original_bytes))

    journal.verify_reservation.side_effect = reserve

    def verify(current):
        checks = authority.checks if selected.path.read_bytes() == original_bytes else frozenset()
        return engine.PolicyAuthorization(current.fingerprint, frozenset(checks))

    authority.verify = verify
    outcome = engine.DockerEngineClient(prepared.capability, authority=authority, runner=prepared.fake).execute(
        planned, creation_journal=journal
    )
    assert outcome.code == "ENGINE_POLICY_REQUIRED" and not mutations(prepared.fake)


def test_policy_revocation_during_resource_inspection_is_rechecked_before_stop(prepared):
    authority = Authority()

    def revoke(args):
        if args[:2] == ("image", "inspect") and len(authority.requests) >= 2:
            authority.checks = frozenset()

    prepared.fake.on_call = revoke
    outcome = engine.DockerEngineClient(prepared.capability, authority=authority, runner=prepared.fake).execute(
        request(prepared)
    )
    assert outcome.code == "ENGINE_POLICY_REQUIRED" and not mutations(prepared.fake)


def test_policy_revocation_after_first_create_preserves_partial_receipts(prepared):
    prepared.fake.configure(prepared.plan, prepared.compose, prepared.files, existing=False)
    authority = Authority()

    def revoke(args):
        if args[:2] == ("container", "create"):
            authority.checks = frozenset()

    prepared.fake.on_call = revoke
    journal = Mock()
    result = engine.DockerEngineClient(prepared.capability, authority=authority, runner=prepared.fake).execute(
        request(prepared, "create"), creation_journal=journal
    )
    assert result.code == "ENGINE_CREATION_UNCONFIRMED" and result.completed_ids == ("1" * 64,)
    assert prepared.fake.network is not None and len(prepared.fake.containers) == 1
    assert journal.record_outcome.call_args.args[-1] is result


class FakeChild:
    pid = 12345

    def __init__(self, *, running=False, interrupts=0):
        self.stdout, self.stderr = io.BytesIO(b"bounded synthetic output"), io.BytesIO(SECRET.encode())
        self.returncode = None if running else 0
        self.interrupts, self.kills = interrupts, 0

    def poll(self):
        return self.returncode

    def kill(self):
        self.kills += 1
        if self.interrupts:
            self.interrupts -= 1
            raise KeyboardInterrupt()
        self.returncode = -9

    def wait(self, timeout):
        assert timeout == 2
        if self.returncode is None:
            raise subprocess.TimeoutExpired("synthetic", timeout)
        return self.returncode


def test_owned_helper_bounds_timeout_and_repeated_cancellation_without_pid_tree_kills(monkeypatch):
    child = FakeChild(running=True, interrupts=1)
    monkeypatch.setattr(subprocess, "Popen", Mock(return_value=child))
    clock = iter([0, 2])
    monkeypatch.setattr(engine.time, "monotonic", lambda: next(clock))
    with pytest.raises(engine.EngineError) as caught:
        engine._owned_run(("synthetic",), cwd=Path.cwd(), environment={}, timeout=1)
    assert caught.value.code == "ENGINE_CHILD_TIMEOUT" and child.kills == 2 and child.returncode == -9
    assert SECRET not in repr(caught.value)


def test_owned_helper_reports_original_pid_when_bounded_cleanup_cannot_be_verified(monkeypatch):
    child = FakeChild(running=True, interrupts=2)
    monkeypatch.setattr(subprocess, "Popen", Mock(return_value=child))
    clock = iter([0, 2])
    monkeypatch.setattr(engine.time, "monotonic", lambda: next(clock))
    with pytest.raises(engine.EngineError) as caught:
        engine._owned_run(("synthetic",), cwd=Path.cwd(), environment={}, timeout=1)
    assert caught.value.code == "ENGINE_CHILD_CLEANUP_UNCONFIRMED" and caught.value.child_pid == child.pid
    assert child.kills == 2 and SECRET not in repr(caught.value)


@pytest.mark.parametrize(
    "constructor",
    [
        lambda: engine.EngineCapability([], "ENGINE_MISSING"),
        lambda: engine.EngineCapability("MISSING", SECRET),
        lambda: engine.EngineOutcome(SECRET),
        lambda: engine.EngineOutcome("ENGINE_ACTION_COMPLETED", ({"private": SECRET},)),
        lambda: engine.ContainerRecord([SECRET], "1" * 64, BIRTH),
        lambda: engine.ActionConsent("stop", SECRET, "1" * 64, "2" * 64, "3" * 64, "4" * 64),
        lambda: engine.SecretFile("not-an-approved-reference", Path("/synthetic"), (1, 1, 1, 1, 1)),
    ],
)
def test_dto_validation_never_echoes_arbitrary_claims_or_private_inputs(constructor):
    with pytest.raises(engine.EngineError) as caught:
        constructor()
    assert SECRET not in repr(caught.value) and str(caught.value).startswith("ENGINE_")
