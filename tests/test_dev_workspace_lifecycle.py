"""Pure isolated lifecycle contracts; --noconftest, never a live stack."""

from __future__ import annotations

import base64
import builtins
import json
import os
import socket
import subprocess
import sys
import types
from dataclasses import FrozenInstanceError, replace
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import urlencode

import pytest
from scripts import dev_instance_plan as plans
from scripts import dev_workspace_lifecycle as lifecycle

SECRET = "fixture-private-lifecycle-value-never-print"
SESSION = base64.b64encode(b"a" * 32).decode()
OUTBOX = base64.b64encode(b"b" * 32).decode()
PROVIDER = base64.b64encode(b"c" * 32).decode()


def prepared(*, worktree="b" * 64, auth="native", platform="win32", module=lifecycle, **plan_changes):
    descriptor = plans.plan_instance(
        repository_id="a" * 64,
        worktree_id=worktree,
        commit="c" * 40,
        generation=1,
        mode="isolated",
        auth_mode=auth,
        config_present=True,
        config_generation=1,
        **plan_changes,
    ).descriptor
    path = PureWindowsPath if platform == "win32" else PurePosixPath
    state = path("C:/fixture/private" if platform == "win32" else "/fixture/private") / descriptor.instance_id
    source = path("C:/fixture/checkout" if platform == "win32" else "/fixture/checkout")
    ports, resources = descriptor.ports, descriptor.resources
    trust = str(state / "bundles/fixture-generation/tls/trust-bundle.pem")
    environment = {
        "SBOM_DEV_RESOURCE_ID": descriptor.instance_id,
        "SBOM_DEV_INSTANCE": "d" * 32,
        "APP_ENVIRONMENT": "development",
        "AUTH_ENABLED": "true",
        "DEV_DEFAULT_TENANT": "false",
        "ENTRA_ENABLED": "false",
        "NATIVE_PLATFORM_BOOTSTRAP_ENABLED": "false",
        "PYTHON_DOTENV_DISABLED": "1",
        "NATIVE_AUTH_ENABLED": "true" if auth == "native" else "false",
        "HCL_AUTH_ENABLED": "false" if auth == "native" else "true",
        "NEXT_PUBLIC_AUTH_ENABLED": "true",
        "NEXT_PUBLIC_ENTRA_ENABLED": "false",
        "NEXT_PUBLIC_NATIVE_AUTH_ENABLED": "true" if auth == "native" else "false",
        "NEXT_PUBLIC_HCL_AUTH_ENABLED": "false" if auth == "native" else "true",
        "AUTH_SESSION_STORE": "redis",
        "AUTH_SESSION_ENCRYPTION_KEY": SESSION,
        "AI_CONFIG_ENCRYPTION_KEY": PROVIDER,
        "APP_ORIGIN": descriptor.origin,
        "CORS_ORIGINS": descriptor.origin,
        "EMAIL_VERIFICATION_FRONTEND_URL": descriptor.origin + "/verify-email",
        "API_RATE_LIMIT_ENABLED": "true",
        "DEV_API_PORT": str(ports["api"]),
        "DEV_FRONTEND_PORT": str(ports["frontend"]),
        "SBOM_API_URL": f"http://127.0.0.1:{ports['api']}",
        "NEXT_PUBLIC_API_URL": f"http://127.0.0.1:{ports['api']}",
        "DATABASE_URL": f"postgresql+psycopg://{resources['restricted_database_role']}:{SECRET}@127.0.0.1:{ports['postgres']}/{resources['database']}?"
        + urlencode({"sslmode": "verify-full", "sslrootcert": trust,
                     "gssencmode": "disable", "sslcertmode": "disable"}),
        "SSL_CERT_FILE": trust,
        "NODE_EXTRA_CA_CERTS": trust,
        "REPORT_ARTIFACT_STORAGE_PATH": str(state / "artifacts"),
        "SBOM_WORKSPACE_STORAGE_DIR": str(state / "workspaces"),
        "SMTP_HOST": "127.0.0.1",
        "SMTP_PORT": str(ports["smtp"]),
        "SMTP_USE_TLS": "false",
        "SMTP_USE_STARTTLS": "true",
        "SMTP_USERNAME": "sbom_" + descriptor.instance_id.replace("-", ""),
        "SMTP_PASSWORD": SECRET,
        "PROVIDER_SECRET": SECRET,
    }
    for name, index in (
        ("REDIS_URL", 0),
        ("CELERY_BROKER_URL", 0),
        ("CELERY_RESULT_BACKEND", 2),
        ("AUTH_SESSION_REDIS_URL", 1),
        ("NATIVE_AUTH_RATE_LIMIT_STORAGE_URI", 3),
    ):
        username = "sbom_session" if name == "AUTH_SESSION_REDIS_URL" else "sbom_runtime"
        password = "fixture-private-frontend-redis-password" if name == "AUTH_SESSION_REDIS_URL" else SECRET
        environment[name] = f"rediss://{username}:{password}@127.0.0.1:{ports['redis']}/{index}"
        if name != "AUTH_SESSION_REDIS_URL":
            environment[name] += "?" + urlencode({
                "ssl_cert_reqs": "required", "ssl_check_hostname": "true", "ssl_ca_certs": trust,
            })
    if auth == "native":
        environment.update(
            NATIVE_SECURITY_OUTBOX_ENABLED="true",
            NATIVE_SECURITY_OUTBOX_KEY=OUTBOX,
            NATIVE_AUTH_RATE_LIMIT_ENABLED="true",
            EMAIL_DELIVERY_ENABLED="true",
            NATIVE_JWT_ISSUER=descriptor.origin + "/native",
            NATIVE_JWT_AUDIENCE="sbom-analyser-api",
            NATIVE_JWT_ACTIVE_KID="fixture-key",
            NATIVE_JWT_PRIVATE_KEY=SECRET,
            NATIVE_JWT_PUBLIC_KEY="fixture-public-native-key",
            NATIVE_ACTIVATION_FRONTEND_URL=descriptor.origin + "/activate-account",
            NATIVE_PASSWORD_RESET_FRONTEND_URL=descriptor.origin + "/reset-password",
        )
    else:
        environment.update(
            HCL_IAM_ISSUER="https://identity.example.test",
            HCL_IAM_AUDIENCE="fixture-api",
            NEXT_PUBLIC_HCL_IAM_ISSUER="https://identity.example.test",
            NEXT_PUBLIC_HCL_IAM_CLIENT_ID="fixture-client",
            NEXT_PUBLIC_HCL_IAM_REDIRECT_URI=descriptor.origin + "/api/auth/callback",
            NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_REDIRECT_URI=descriptor.origin + "/logged-out",
        )
    snapshot = module.PreparationSnapshot(
        descriptor.repository_id,
        descriptor.worktree_id,
        descriptor.commit,
        descriptor.config_generation,
        platform,
        str(source),
        str(state),
        environment,
        dict.fromkeys(module.PREREQUISITES, "PREPARED"),
    )
    return descriptor, snapshot


def test_valid_shape_has_exact_dependency_and_start_order_but_every_live_path_stays_blocked():
    descriptor, snapshot = prepared()
    plan = lifecycle.plan_lifecycle(descriptor, snapshot)
    assert plan.startup_order == ("Celery worker", "Celery reports worker", "Celery Beat", "API", "Frontend")
    assert (
        plan.steps.index("VERIFY_PROVIDER_ATTESTATION")
        < plan.steps.index("VERIFY_EXISTING_SCHEMA")
        < plan.steps.index("BEGIN_RUNTIME")
    )
    assert plan.steps.index("WAIT_BACKGROUND_READY") < plan.steps.index("START_API")
    assert (
        plan.steps.index("WAIT_API_IAM_READY")
        < plan.steps.index("START_FRONTEND")
        < plan.steps.index("WAIT_FRONTEND_HTTPS")
    )
    assert plan.ready is plan.live_operations_authorized is plan.ownership_verified is False
    assert "INSTANCE_PROVIDER_ATTESTATION_REQUIRED" in plan.blockers
    with pytest.raises(lifecycle.LifecycleError, match="^INSTANCE_PROVIDER_ATTESTATION_REQUIRED$"):
        lifecycle.require_live_execution(plan)


@pytest.mark.parametrize("platform, pool", [("win32", "solo"), ("darwin", "solo"), ("linux", "prefork")])
def test_command_contracts_use_exact_namespaces_runtime_placeholders_and_platform_pool(platform, pool):
    descriptor, snapshot = prepared(platform=platform)
    plan = lifecycle.plan_lifecycle(descriptor, snapshot)
    commands = {item.component: item for item in plan.commands}
    assert "--queues=" + descriptor.resources["queue_default"] in commands["Celery worker"].arguments
    assert "--queues=" + descriptor.resources["queue_reports"] in commands["Celery reports worker"].arguments
    assert "--pool=" + pool in commands["Celery worker"].arguments
    assert "--hostname={runtime_node}" in commands["Celery worker"].arguments
    assert "--schedule={beat_schedule_path}" in commands["Celery Beat"].arguments
    assert "--pidfile={beat_pid_path}" in commands["Celery Beat"].arguments
    assert "--no-proxy-headers" in commands["API"].arguments
    assert "{tls_cert_path}" in commands["Frontend"].arguments and "{tls_key_path}" in commands["Frontend"].arguments
    assert SECRET not in repr(plan.commands)


def test_server_and_frontend_environments_are_distinct_immutable_and_never_publicly_serialized():
    descriptor, snapshot = prepared()
    plan = lifecycle.plan_lifecycle(descriptor, snapshot)
    server = plan.component_environment("API")
    frontend = plan.component_environment("Frontend")
    assert server["DATABASE_URL"] == snapshot.environment["DATABASE_URL"]
    assert server["SBOM_DEV_INSTANCE"] == snapshot.environment["SBOM_DEV_INSTANCE"]
    assert frontend["SBOM_DEV_RESOURCE_ID"] == descriptor.instance_id
    assert frontend["AUTH_SESSION_ENCRYPTION_KEY"] == SESSION
    assert all(
        key not in frontend
        for key in (
            "DATABASE_URL",
            "NATIVE_JWT_PRIVATE_KEY",
            "NATIVE_SECURITY_OUTBOX_KEY",
            "SMTP_PASSWORD",
            "PROVIDER_SECRET",
        )
    )
    assert frontend["CI"] == frontend["NEXT_DISABLE_SWC_WASM"] == "1"
    with pytest.raises(TypeError):
        frontend["AUTH_ENABLED"] = "false"
    with pytest.raises(FrozenInstanceError):
        snapshot.commit = "d" * 40
    public = json.dumps(plan.to_public_dict())
    assert SECRET not in public + repr(plan) + repr(snapshot)
    assert SESSION not in public + repr(plan) + repr(snapshot)
    assert snapshot.state_root not in public


def test_two_instances_keep_queues_sessions_beat_targets_and_origins_separate():
    first_descriptor, first = prepared()
    second_descriptor, second = prepared(worktree="d" * 64)
    left = lifecycle.plan_lifecycle(first_descriptor, first)
    right = lifecycle.plan_lifecycle(second_descriptor, second)
    assert left.descriptor.origin != right.descriptor.origin
    for key in ("queue_default", "queue_reports", "session_namespace", "beat_namespace", "rate_limit_namespace"):
        assert left.descriptor.resources[key] != right.descriptor.resources[key]
    assert left.component_environment("API")["DATABASE_URL"] != right.component_environment("API")["DATABASE_URL"]
    # Shape/parity cannot attest cross-instance secret ownership; live stays gated.
    assert "INSTANCE_CREDENTIAL_OWNERSHIP_ATTESTATION_REQUIRED" in left.blockers


@pytest.mark.parametrize(
    "key, changed",
    [
        ("DATABASE_URL", "postgresql+psycopg://postgres:fixture@127.0.0.1:5432/sbom_analyser_dev"),
        ("DATABASE_URL", "postgresql+psycopg://postgres:fixture@127.0.0.1:56044/sbom_greenfield_uuid"),
        ("REDIS_URL", "redis://:fixture@127.0.0.1:6379/0"),
        ("CELERY_BROKER_URL", "redis://:fixture@127.0.0.1:56381/0"),
        ("APP_ORIGIN", "https://localhost:13000"),
        ("AUTH_ENABLED", "false"),
        ("DEV_DEFAULT_TENANT", "true"),
        ("NATIVE_PLATFORM_BOOTSTRAP_ENABLED", "true"),
        ("CELERY_DEFAULT_QUEUE", "celery"),
        ("CELERY_REPORTS_QUEUE", "reports"),
        ("AUTH_SESSION_KEY_PREFIX", "sbom:bff:"),
        ("NATIVE_MAIL_WORKER_HEARTBEAT_KEY", "sbom:iam:mail-worker"),
        ("SBOM_DEV_BEAT_NAMESPACE", "sbom:dev:beat"),
        ("SBOM_DEV_RESOURCE_ID", "invalid-fixture-id"),
        ("APP_ENVIRONMENT", "production"),
        ("APP_ENV", "test"),
        ("ALLOW_SQLITE", "true"),
        ("PGHOST", "127.0.0.1"),
        ("PGSSLMODE", "disable"),
        ("CELERY_CONFIG_MODULE", SECRET),
        ("NODE_OPTIONS", "--require " + SECRET),
        ("NODE_TLS_REJECT_UNAUTHORIZED", "0"),
        ("NATIVE_AUTH_ENABLED", "false"),
        ("HCL_AUTH_ENABLED", "true"),
        ("API_RATE_LIMIT_ENABLED", "false"),
    ],
)
def test_protected_targets_shared_names_ambient_loaders_and_auth_bypasses_fail_closed(key, changed):
    descriptor, snapshot = prepared()
    altered = (
        replace(snapshot, environment={**snapshot.environment, key: changed})
        if not key.startswith("PG") and key not in {"CELERY_CONFIG_MODULE", "NODE_OPTIONS"}
        else None
    )
    with pytest.raises(lifecycle.LifecycleError) as caught:
        if altered is None:
            replace(snapshot, environment={**snapshot.environment, key: changed})
        else:
            lifecycle.plan_lifecycle(descriptor, altered)
    assert SECRET not in str(caught.value)


@pytest.mark.parametrize(
    "key", ["AUTH_SESSION_REDIS_URL", "CELERY_RESULT_BACKEND", "NATIVE_AUTH_RATE_LIMIT_STORAGE_URI"]
)
def test_role_specific_redis_databases_cannot_silently_share_broker_state(key):
    descriptor, snapshot = prepared()
    altered = replace(snapshot, environment={**snapshot.environment, key: snapshot.environment["CELERY_BROKER_URL"]})
    with pytest.raises(lifecycle.LifecycleError, match="^INSTANCE_REDIS_TARGET_REFUSED$"):
        lifecycle.plan_lifecycle(descriptor, altered)


def test_native_outbox_and_bff_keys_cannot_be_shared_even_with_all_claimed_prerequisites():
    descriptor, snapshot = prepared()
    altered = replace(snapshot, environment={**snapshot.environment, "NATIVE_SECURITY_OUTBOX_KEY": SESSION})
    with pytest.raises(lifecycle.LifecycleError, match="^INSTANCE_SHARED_KEY_REFUSED$"):
        lifecycle.plan_lifecycle(descriptor, altered)


def test_hcl_issuer_and_origin_must_match_the_selected_frontend_configuration():
    descriptor, snapshot = prepared(auth="hcl")
    assert lifecycle.plan_lifecycle(descriptor, snapshot).ready is False
    for value in ("", "https://other-identity.example.test"):
        altered = replace(snapshot, environment={**snapshot.environment, "NEXT_PUBLIC_HCL_IAM_ISSUER": value})
        with pytest.raises(lifecycle.LifecycleError, match="^INSTANCE_CONFIGURATION_MISMATCH$"):
            lifecycle.plan_lifecycle(descriptor, altered)


@pytest.mark.parametrize("auth", ["native", "hcl"])
@pytest.mark.parametrize(
    "value", [None, "", "https://localhost:3000/verify-email", "https://foreign.invalid/verify-email"]
)
def test_email_verification_links_never_fall_back_to_another_instance(auth, value):
    descriptor, snapshot = prepared(auth=auth)
    environment = dict(snapshot.environment)
    if value is None:
        environment.pop("EMAIL_VERIFICATION_FRONTEND_URL")
    else:
        environment["EMAIL_VERIFICATION_FRONTEND_URL"] = value
    with pytest.raises(lifecycle.LifecycleError, match="^INSTANCE_CONFIGURATION_MISMATCH$"):
        lifecycle.plan_lifecycle(descriptor, replace(snapshot, environment=environment))


@pytest.mark.parametrize("value", [None, "", "https://localhost:3000/logged-out", "https://foreign.invalid/logged-out"])
def test_hcl_logout_requires_exact_operator_registered_instance_origin(value):
    descriptor, snapshot = prepared(auth="hcl")
    environment = dict(snapshot.environment)
    if value is None:
        environment.pop("NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_REDIRECT_URI")
    else:
        environment["NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_REDIRECT_URI"] = value
    with pytest.raises(lifecycle.LifecycleError, match="^INSTANCE_CONFIGURATION_MISMATCH$"):
        lifecycle.plan_lifecycle(descriptor, replace(snapshot, environment=environment))


@pytest.mark.parametrize("changed", ["commit", "config_generation", "environment", "prerequisites"])
def test_context_drift_requires_new_review_and_never_publishes_a_private_environment_hash(changed):
    descriptor, snapshot = prepared()
    plan = lifecycle.plan_lifecycle(descriptor, snapshot)
    updates = {
        "commit": "d" * 40,
        "config_generation": 2,
        "environment": {**snapshot.environment, "PROVIDER_SECRET": "changed-fixture"},
        "prerequisites": {**snapshot.prerequisites, "tls": "UNVERIFIED"},
    }
    with pytest.raises(lifecycle.LifecycleError, match="^INSTANCE_CONTEXT_CHANGED$"):
        lifecycle.require_current(plan, descriptor, replace(snapshot, **{changed: updates[changed]}))
    assert "fingerprint" not in plan.to_public_dict()


@pytest.mark.parametrize("missing", sorted(lifecycle.PREREQUISITES))
def test_each_preparation_requirement_is_separate_and_cannot_enable_live_execution(missing):
    descriptor, snapshot = prepared()
    altered = replace(snapshot, prerequisites={**snapshot.prerequisites, missing: "MISSING"})
    plan = lifecycle.plan_lifecycle(descriptor, altered)
    assert "INSTANCE_" + missing.upper() + "_PREPARATION_REQUIRED" in plan.blockers
    assert "INSTANCE_PROVIDER_ATTESTATION_REQUIRED" in plan.blockers


def test_local_provider_and_other_modes_remain_explicitly_unavailable_without_adoption():
    descriptor, snapshot = prepared(provider="local")
    assert "INSTANCE_LOCAL_PROVIDER_UNAVAILABLE" in lifecycle.plan_lifecycle(descriptor, snapshot).blockers
    for mode in ("mock", "shared-backend"):
        other = plans.plan_instance(
            repository_id=descriptor.repository_id,
            worktree_id=descriptor.worktree_id,
            commit=descriptor.commit,
            generation=1,
            mode=mode,
            auth_mode="native",
            config_present=True,
            config_generation=1,
        ).descriptor
        with pytest.raises(lifecycle.LifecycleError, match="^INSTANCE_MODE_ADAPTER_REQUIRED$"):
            lifecycle.plan_lifecycle(other, snapshot)


@pytest.mark.parametrize(
    "changes",
    [
        {"source_root": "C:/fixture/private"},
        {"state_root": "C:/fixture"},
        {"source_root": "C:/fixture/checkout/../other"},
        {"state_root": "C:/fixture/private/../other"},
        {"prerequisites": {}},
        {"prerequisites": dict.fromkeys(lifecycle.PREREQUISITES, True)},
    ],
)
def test_overlapping_or_traversing_paths_and_malformed_prerequisites_are_refused(changes):
    _, snapshot = prepared()
    with pytest.raises(lifecycle.LifecycleError):
        replace(snapshot, **changes)


def identity(pid=100, birth="fixture-created-1", executable="fixture-python"):
    return lifecycle.RuntimeIdentity(pid, birth, executable)


def test_partial_startup_cleanup_reverses_only_started_components_and_preserves_unknowns():
    known = identity()
    observations = [
        lifecycle.RuntimeObservation("Celery worker", "RUNNING", known, known),
        lifecycle.RuntimeObservation("Celery reports worker", "UNKNOWN", identity(101)),
        lifecycle.RuntimeObservation("Celery Beat", "PARTIAL", identity(102)),
    ]
    decisions = lifecycle.cleanup_contract(observations)
    assert [item.component for item in decisions] == ["Celery Beat", "Celery reports worker", "Celery worker"]
    assert [item.action for item in decisions] == [
        "REQUEST_RUNTIME_REVALIDATION",
        "PRESERVE",
        "REQUEST_RUNTIME_REVALIDATION",
    ]
    assert all(item.action not in {"KILL", "TERMINATE", "DELETE", "CLEAR"} for item in decisions)


@pytest.mark.parametrize(
    "changed", [identity(pid=101), identity(birth="fixture-reused"), identity(executable="fixture-other")]
)
def test_reused_or_changed_pid_identity_never_requests_termination(changed):
    (decision,) = lifecycle.cleanup_contract([lifecycle.RuntimeObservation("API", "RUNNING", identity(), changed)])
    assert decision.action == "PRESERVE" and decision.code == "INSTANCE_PID_REUSE_PRESERVED"


@pytest.mark.parametrize("status", ["UNKNOWN", "UNOWNED"])
def test_unknown_ownership_is_preserved_even_if_identity_fields_match(status):
    known = identity()
    (decision,) = lifecycle.cleanup_contract([lifecycle.RuntimeObservation("API", status, known, known)])
    assert decision.action == "PRESERVE"


def test_unregistered_processes_are_protected_and_exit_confirmation_still_goes_through_runtime():
    (unknown,) = lifecycle.cleanup_contract([lifecycle.RuntimeObservation("API", "RUNNING", current=identity())])
    (exited,) = lifecycle.cleanup_contract([lifecycle.RuntimeObservation("API", "STOPPED", recorded=identity())])
    assert unknown.action == "PRESERVE"
    assert exited.action == "REQUEST_RUNTIME_REVALIDATION"
    assert exited.code == "INSTANCE_RUNTIME_REVALIDATION_REQUIRED"


def test_cleanup_stays_available_after_configuration_drift_or_loss():
    descriptor, snapshot = prepared()
    plan = lifecycle.plan_lifecycle(descriptor, snapshot)
    with pytest.raises(lifecycle.LifecycleError):
        lifecycle.require_current(plan, descriptor, replace(snapshot, environment={}))
    known = identity()
    (decision,) = lifecycle.cleanup_contract([lifecycle.RuntimeObservation("API", "RUNNING", known, known)])
    assert decision.action == "REQUEST_RUNTIME_REVALIDATION"


@pytest.mark.parametrize(
    "build",
    [
        lambda: lifecycle.RuntimeIdentity(True, "fixture", "fixture-python"),
        lambda: lifecycle.RuntimeIdentity(100, "", SECRET),
        lambda: lifecycle.RuntimeObservation("API", "STOPPED", current=identity()),
        lambda: lifecycle.RuntimeObservation("API", [SECRET]),
        lambda: lifecycle.CleanupDecision("API", "KILL", "INSTANCE_RUNTIME_REVALIDATION_REQUIRED"),
        lambda: lifecycle.CleanupDecision("API", "PRESERVE", SECRET),
        lambda: lifecycle.cleanup_contract([lifecycle.RuntimeObservation("API", "UNKNOWN")] * 2),
    ],
)
def test_runtime_and_cleanup_dtos_refuse_invalid_identity_or_arbitrary_actions(build):
    with pytest.raises(lifecycle.LifecycleError) as caught:
        build()
    assert SECRET not in str(caught.value) + repr(caught.value)


def test_preparation_snapshot_copies_inputs_and_command_arguments_are_immutable():
    descriptor, snapshot = prepared()
    environment, prerequisites = dict(snapshot.environment), dict(snapshot.prerequisites)
    copied = replace(snapshot, environment=environment, prerequisites=prerequisites)
    environment.clear()
    prerequisites.clear()
    assert copied == snapshot
    plan = lifecycle.plan_lifecycle(descriptor, copied)
    command = plan.commands[0]
    arguments = list(command.arguments)
    clone = replace(command, arguments=arguments)
    arguments.clear()
    assert clone.arguments == command.arguments
    assert SECRET not in repr(lifecycle.RuntimeIdentity(100, SECRET, SECRET))


def test_pure_contracts_have_no_file_network_process_or_application_side_effects(monkeypatch):
    source = Path(lifecycle.__file__).read_text(encoding="utf-8")
    compiled = compile(source, "<pure-lifecycle-fixture>", "exec")
    fixture = types.ModuleType("sbo101_lifecycle_fixture")
    monkeypatch.setitem(sys.modules, fixture.__name__, fixture)
    original_import = builtins.__import__

    def forbidden(*arguments, **keywords):
        raise AssertionError("Pure lifecycle attempted an external operation")

    def guarded_import(name, *arguments, **keywords):
        assert name.split(".", 1)[0] not in {"app", "sqlalchemy", "psycopg", "celery"}
        return original_import(name, *arguments, **keywords)

    class NoEnvironment(dict):
        __iter__ = __getitem__ = __contains__ = get = items = keys = values = copy = forbidden

    # The synthetic module uses package-relative imports of the pure libraries.
    fixture.__package__ = "scripts"
    with monkeypatch.context() as guarded:
        guarded.setattr(os, "environ", NoEnvironment())
        guarded.setattr(builtins, "open", forbidden)
        guarded.setattr(os, "open", forbidden)
        guarded.setattr(os, "getenv", forbidden)
        for method in ("open", "exists", "stat", "read_text", "read_bytes", "write_text", "write_bytes", "mkdir"):
            guarded.setattr(Path, method, forbidden)
        guarded.setattr(socket, "socket", forbidden)
        guarded.setattr(socket, "create_connection", forbidden)
        guarded.setattr(subprocess, "Popen", forbidden)
        guarded.setattr(subprocess, "run", forbidden)
        guarded.setattr(os, "kill", forbidden)
        guarded.setattr(builtins, "__import__", guarded_import)
        exec(compiled, fixture.__dict__)
        descriptor, snapshot = prepared(module=fixture)
        plan = fixture.plan_lifecycle(descriptor, snapshot)
        assert plan.ready is False
        assert plan.component_environment("Frontend")["SBOM_DEV_RESOURCE_ID"] == descriptor.instance_id
        assert fixture.cleanup_contract(()) == ()
