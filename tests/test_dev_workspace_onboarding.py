"""Pure guided-admin state tests; no app/DB or existing bootstrap mutation."""

from __future__ import annotations

import builtins
import io
import json
import os
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from unittest.mock import Mock

import pytest
from scripts import dev_workspace_onboarding as onboarding

REPOSITORY = "1" * 64
WORKTREE = "2" * 64
INSTANCE = "12345678-1234-5678-9234-567812345678"
PROVIDER = "3" * 64
COMMIT = "a" * 40
SCHEMA = "103_tenant_admin_governance"
SECRET = "synthetic-private-input-never-output"


def context(**values):
    return onboarding.OnboardingContext(
        **{
            "repository_id": REPOSITORY,
            "worktree_id": WORKTREE,
            "instance_id": INSTANCE,
            "commit": COMMIT,
            "generation": 1,
            "config_generation": 1,
            "database_provider_id": PROVIDER,
            "database_host": "127.0.0.1",
            "database_port": 25432,
            "database_name": "sbom_disposable_fixture",
            "schema_revision": SCHEMA,
            "activation_origin": "https://sbom-fixture.localhost:24443",
            "auth_mode": "native",
            **values,
        }
    )


def status(code="ENROLLMENT_REQUIRED", state="NOT_STARTED", **values):
    return onboarding.PublicEnrollmentStatus(
        **{
            "code": code,
            "state": state,
            "platform_admin_available": code == "ADMIN_READY",
            "enrollment_required": code == "ENROLLMENT_REQUIRED",
            "existing_users_present": code != "ENROLLMENT_REQUIRED",
            "bootstrap_enabled": False,
            "live_readiness_verified": False,
            **values,
        }
    )


def plan(observed=None, value=None, **values):
    expected = context()
    return onboarding.plan_onboarding(
        expected_context=expected,
        observed_context=observed or expected,
        status=value or status(),
        schema_state="READY",
        **values,
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (status("ADMIN_READY", "NOT_STARTED"), "EXISTING_ADMIN"),
        (status("ADMIN_READY", "PENDING"), "EXISTING_ADMIN"),
        (status("ADMIN_READY", "COMPLETED"), "EXISTING_ADMIN"),
        (status(), "ENROLLMENT_REQUIRED"),
        (status(existing_users_present=True), "ENROLLMENT_REQUIRED"),
        (status("PENDING_ACTIVATION", "PENDING"), "ENROLLMENT_PENDING"),
        (status("BOOTSTRAP_RESERVED", "COMPLETED"), "ENROLLMENT_COMPLETED"),
        (status("BOOTSTRAP_RESERVED", "COMPLETED", existing_users_present=False), "ENROLLMENT_COMPLETED"),
        (status("BOOTSTRAP_RESERVED", "UNKNOWN"), "UNKNOWN"),
    ],
)
def test_native_state_machine_preserves_existing_pending_and_completed_reservations(value, expected):
    result = plan(value=value)
    assert result.state == expected
    output = result.to_dict()
    assert output["live_enrollment_authorized"] is False and output["observation_only"] is True
    assert output["live_gate"] == "ENROLLMENT_READINESS_CONTRACT_REQUIRED"
    assert all(step["executable"] is False for step in output["steps"])
    if expected in {"EXISTING_ADMIN", "ENROLLMENT_COMPLETED"}:
        assert not result.required_identity_fields
        assert "pending-reservation-workflow" not in [step.code for step in result.steps]
    if expected == "ENROLLMENT_COMPLETED":
        assert "preserve-completed-reservation" in [step.code for step in result.steps]


@pytest.mark.parametrize("bootstrap", [False, True])
@pytest.mark.parametrize("readiness", [False, True])
def test_caller_bootstrap_and_readiness_markers_never_authorize_live_execution(bootstrap, readiness):
    result = plan(value=status(bootstrap_enabled=bootstrap, live_readiness_verified=readiness))
    assert result.state == "ENROLLMENT_REQUIRED"
    assert result.code == "ENROLLMENT_READINESS_CONTRACT_REQUIRED"
    assert not result.live_enrollment_authorized
    with pytest.raises(onboarding.OnboardingPlanError, match="ONBOARDING_LIVE_ENROLLMENT_GATED"):
        replace(result, live_enrollment_authorized=True)


def test_required_identity_is_labels_only_and_password_is_guided_to_https_activation():
    result = plan()
    assert result.required_identity_fields == ("email", "first_name", "last_name", "phone", "operator_reference")
    activation = next(step for step in result.steps if step.code == "verified-https-activation")
    assert "verified HTTPS" in activation.guidance and "password" in activation.guidance
    assert "chat" in activation.guidance and "shell" in activation.guidance
    assert "token" not in result.to_dict() and "password" not in result.to_dict()
    assert all(not step.executable for step in result.steps)


@pytest.mark.parametrize("schema_state", ["NOT_INITIALIZED", "UNKNOWN", "INCOMPATIBLE"])
def test_schema_prerequisites_never_offer_unauthorized_enrollment(schema_state):
    selected = context()
    result = onboarding.plan_onboarding(
        expected_context=selected,
        observed_context=selected,
        status=status(),
        schema_state=schema_state,
    )
    assert (
        result.state
        == {"NOT_INITIALIZED": "NOT_INITIALIZED", "UNKNOWN": "UNKNOWN", "INCOMPATIBLE": "CONFLICT"}[schema_state]
    )
    assert not result.required_identity_fields and not result.live_enrollment_authorized


@pytest.mark.parametrize(
    "field",
    [
        "config_generation",
        "database_provider_id",
        "database_host",
        "database_port",
        "database_name",
        "schema_revision",
        "activation_origin",
    ],
)
def test_missing_public_prerequisites_are_not_initialized(field):
    selected = context(**{field: None})
    result = onboarding.plan_onboarding(
        expected_context=selected, observed_context=selected, status=status(), schema_state="READY"
    )
    assert result.state == "NOT_INITIALIZED" and not result.required_identity_fields


def test_absent_observation_never_infers_no_administrator():
    result = onboarding.plan_onboarding(expected_context=context())
    assert result.state == "UNKNOWN" and result.code == "ONBOARDING_INSPECTION_REQUIRED"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("repository_id", "4" * 64),
        ("worktree_id", "5" * 64),
        ("instance_id", "abcdefab-1234-5678-9234-567812345678"),
        ("commit", "b" * 40),
        ("generation", 2),
        ("config_generation", 2),
        ("database_provider_id", "6" * 64),
        ("database_host", "localhost"),
        ("database_port", 25433),
        ("database_name", "wrong_disposable_fixture"),
        ("schema_revision", "different_schema"),
        ("activation_origin", "https://changed.localhost:24443"),
        ("auth_mode", "hcl"),
    ],
)
def test_exact_binding_drift_blocks_old_plan_and_revalidation(field, value):
    selected = context()
    previous = plan()
    changed = replace(selected, **{field: value})
    observed = onboarding.plan_onboarding(
        expected_context=selected, observed_context=changed, status=status(), schema_state="READY"
    )
    assert observed.state == "CONFLICT"
    with pytest.raises(onboarding.OnboardingPlanError, match="ONBOARDING_PLAN_CHANGED"):
        onboarding.revalidate_onboarding(previous, observed_context=changed, status=status(), schema_state="READY")


@pytest.mark.parametrize(
    "value",
    [
        status("ADMIN_READY", "NOT_STARTED", existing_users_present=False),
        status("ADMIN_READY", "NOT_STARTED", platform_admin_available=False),
        status("ENROLLMENT_REQUIRED", "COMPLETED"),
        status("ENROLLMENT_REQUIRED", "NOT_STARTED", enrollment_required=False),
        status("PENDING_ACTIVATION", "NOT_STARTED"),
        status("BOOTSTRAP_RESERVED", "PENDING"),
    ],
)
def test_semantically_conflicting_aggregate_status_fails_closed(value):
    result = plan(value=value)
    assert result.state == "CONFLICT" and result.code == "ONBOARDING_STATUS_CONFLICT"


def test_pending_reservation_without_any_iam_user_requires_operator_review():
    pending = status("PENDING_ACTIVATION", "PENDING")
    previous = plan(value=pending)
    impossible = replace(pending, existing_users_present=False)
    result = plan(value=impossible)
    assert result.state == "CONFLICT" and result.code == "ONBOARDING_STATUS_CONFLICT"
    assert [step.code for step in result.steps] == ["operator-review-required"]
    assert not result.required_identity_fields and not result.live_enrollment_authorized
    assert all(not step.executable for step in result.steps)
    with pytest.raises(onboarding.OnboardingPlanError, match="^ONBOARDING_PLAN_CHANGED$"):
        onboarding.revalidate_onboarding(previous, observed_context=context(), status=impossible, schema_state="READY")


def test_hcl_is_a_separate_approval_flow_without_native_password_or_creation_steps():
    external = context(auth_mode="hcl")
    result = onboarding.plan_onboarding(expected_context=external, observed_context=external, schema_state="READY")
    assert result.state == "HCL_APPROVAL_REQUIRED" and not result.required_identity_fields
    assert [step.code for step in result.steps] == ["external-identity-approval"]
    output = json.dumps(result.to_dict())
    assert "password" not in output and "IdP-owner approval" in output
    assert not result.live_enrollment_authorized
    wrong = onboarding.plan_onboarding(
        expected_context=external, observed_context=external, status=status(), schema_state="READY"
    )
    assert wrong.state == "CONFLICT" and wrong.code == "ONBOARDING_EXTERNAL_NATIVE_STATUS_REFUSED"


@pytest.mark.parametrize("field", ["email", "password", "token", "authorization", "operator_reference", "database_url"])
def test_unknown_private_status_or_context_fields_are_rejected_without_echo(field):
    value = status().to_dict()
    value[field] = SECRET
    with pytest.raises(onboarding.OnboardingPlanError) as error:
        onboarding.PublicEnrollmentStatus.from_dict(value)
    assert SECRET not in str(error.value) and field not in str(error.value)
    selected = context().to_dict()
    selected[field] = SECRET
    with pytest.raises(onboarding.OnboardingPlanError) as error:
        onboarding.OnboardingContext.from_dict(selected)
    assert SECRET not in str(error.value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("generation", True),
        ("generation", 0),
        ("config_generation", False),
        ("database_provider_id", SECRET),
        ("database_host", []),
        ("database_port", True),
        ("database_name", "postgresql://fixture:secret@host/db"),
        ("schema_revision", "revision\nprivate"),
        ("auth_mode", []),
        ("commit", "f" * 39),
        ("instance_id", "unsafe-instance-name"),
        ("activation_origin", "http://localhost:24443"),
        ("activation_origin", "https://fixture:secret@localhost"),
        ("activation_origin", "https://localhost/activate-account?token=secret"),
        ("activation_origin", "https://localhost/#secret"),
        ("activation_origin", "https://bad%20host"),
    ],
)
def test_malformed_public_context_types_and_unsafe_origins_are_redacted(field, value):
    selected = context().to_dict()
    selected[field] = value
    with pytest.raises(onboarding.OnboardingPlanError) as error:
        onboarding.OnboardingContext.from_dict(selected)
    assert str(error.value).startswith("ONBOARDING_") and SECRET not in str(error.value)


@pytest.mark.parametrize(
    "field",
    [
        "platform_admin_available",
        "enrollment_required",
        "existing_users_present",
        "bootstrap_enabled",
        "live_readiness_verified",
    ],
)
@pytest.mark.parametrize("value", [0, 1, "true", None])
def test_aggregate_booleans_are_strict(field, value):
    observed = status().to_dict()
    observed[field] = value
    with pytest.raises(onboarding.OnboardingPlanError, match="ONBOARDING_STATUS_BOOL_REQUIRED"):
        onboarding.PublicEnrollmentStatus.from_dict(observed)


def test_plan_is_immutable_deterministic_and_detached_from_input():
    selected, observed = context().to_dict(), status().to_dict()
    result = onboarding.plan_onboarding(
        expected_context=selected, observed_context=dict(selected), status=observed, schema_state="READY"
    )
    assert result == plan()
    selected["database_name"] = "changed_after_planning"
    observed["state"] = "COMPLETED"
    assert result.context.database_name == "sbom_disposable_fixture"
    with pytest.raises(FrozenInstanceError):
        result.state = "EXISTING_ADMIN"
    with pytest.raises(onboarding.OnboardingPlanError):
        replace(result.steps[0], executable=True)
    with pytest.raises(onboarding.OnboardingPlanError):
        replace(result, code="CALLER_CONTROLLED_PRIVATE_CODE")
    assert (
        onboarding.revalidate_onboarding(result, observed_context=context(), status=status(), schema_state="READY")
        == result
    )


def test_readonly_planner_has_no_file_network_process_environment_or_application_access(monkeypatch):
    selected, observed = context(), status()
    expected = plan()
    forbidden = Mock(side_effect=AssertionError("Pure guidance attempted an external operation"))
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
        guarded.setattr(builtins, "__import__", guarded_import)
        guarded.setattr(os, "environ", None)
        actual = onboarding.plan_onboarding(
            expected_context=selected, observed_context=selected, status=observed, schema_state="READY"
        )
        assert actual == expected
        assert not onboarding.revalidate_onboarding(
            actual, observed_context=selected, status=observed, schema_state="READY"
        ).live_enrollment_authorized
    forbidden.assert_not_called()


def test_concurrent_guidance_never_allocates_a_reservation_or_overrides_pending_state():
    selected = context()

    def inspect_same_snapshot(_):
        return onboarding.plan_onboarding(
            expected_context=selected, observed_context=selected, status=status(), schema_state="READY"
        )

    with ThreadPoolExecutor(max_workers=4) as workers:
        results = list(workers.map(inspect_same_snapshot, range(16)))
    assert len({result.fingerprint for result in results}) == 1
    assert all(result.state == "ENROLLMENT_REQUIRED" and not result.live_enrollment_authorized for result in results)
    pending = status("PENDING_ACTIVATION", "PENDING")
    after = onboarding.plan_onboarding(
        expected_context=selected, observed_context=selected, status=pending, schema_state="READY"
    )
    assert after.state == "ENROLLMENT_PENDING"
    with pytest.raises(onboarding.OnboardingPlanError, match="ONBOARDING_PLAN_CHANGED"):
        onboarding.revalidate_onboarding(results[0], observed_context=selected, status=pending, schema_state="READY")


def test_direct_module_invocation_cannot_dispatch_enrollment(tmp_path):
    completed = subprocess.run(
        [sys.executable, "-B", onboarding.__file__, "--native-admin-create"],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        timeout=10,
        env={key: value for key, value in os.environ.items() if key in {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP"}},
        check=False,
    )
    assert completed.returncode == 1 and not completed.stdout
    assert (
        completed.stderr.strip()
        == "ONBOARDING_GUIDANCE_ONLY: use the unified developer launcher; live enrollment is blocked."
    )
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("auth_mode", ["native", "hcl"])
def test_uninspected_overview_is_immutable_detached_guidance_without_fabricated_binding(auth_mode):
    overview = onboarding.uninspected_guidance(auth_mode)
    assert overview.auth_mode == auth_mode and overview.inspection_performed is False
    assert overview.live_enrollment_authorized is False and overview.required_identity_fields == ()
    document = overview.to_dict()
    assert document["guidance_only"] is True and document["inspection_performed"] is False
    assert document["live_enrollment_authorized"] is False
    assert document["live_gate"] == (
        "ENROLLMENT_READINESS_CONTRACT_REQUIRED" if auth_mode == "native" else "HCL_OPERATOR_IDP_APPROVAL_REQUIRED"
    )
    assert not document["required_identity_fields"] and all(not step["executable"] for step in document["steps"])
    assert (
        not {"context", "status", "fingerprint", "config_generation", "database_name", "schema_revision"}
        & document.keys()
    )
    with pytest.raises(FrozenInstanceError):
        overview.auth_mode = "hcl" if auth_mode == "native" else "native"
    document["state"] = "ENROLLMENT_REQUIRED"
    document["live_enrollment_authorized"] = True
    document["required_identity_fields"].append("password")
    document["steps"].clear()
    assert overview.to_dict() == onboarding.uninspected_guidance(auth_mode).to_dict()
    assert overview.inspection_performed is False and overview.live_enrollment_authorized is False


def test_native_overview_requires_exact_inspection_and_prerequisites_without_requesting_identity():
    overview = onboarding.uninspected_guidance("native")
    assert overview.state == "UNKNOWN" and overview.code == "ONBOARDING_INSPECTION_REQUIRED"
    assert [step.code for step in overview.steps] == [
        "inspect-approved-installation",
        "review-prerequisite-plan",
        "review-native-prerequisites",
        "inspect-native-administrator-status",
        "independent-authorization-required",
    ]
    text = json.dumps(overview.to_dict())
    for prerequisite in (
        "JWT",
        "encrypted security-mail outbox",
        "Redis",
        "SMTP",
        "background workers",
        "verified HTTPS",
    ):
        assert prerequisite in text
    assert "exact database target and schema confirmation" in text
    assert "existing, pending and completed state" in text
    assert "password" not in text and "email" not in text and "operator_reference" not in text


def test_hcl_overview_has_separate_approval_and_no_native_identity_or_password_flow():
    overview = onboarding.uninspected_guidance("hcl")
    assert overview.state == "HCL_APPROVAL_REQUIRED" and overview.code == "HCL_OPERATOR_IDP_APPROVAL_REQUIRED"
    assert [step.code for step in overview.steps] == ["inspect-approved-installation", "external-identity-approval"]
    text = json.dumps(overview.to_dict())
    assert "Engineering Lead and IdP-owner approval" in text
    assert "password" not in text and "pending-reservation-workflow" not in text
    assert "review-required-identity" not in text and not overview.required_identity_fields


@pytest.mark.parametrize("invalid", [None, True, 1, "Native", "entra", SECRET, {"auth_mode": "native"}])
def test_uninspected_overview_rejects_unknown_modes_without_echo(invalid, capsys):
    with pytest.raises(onboarding.OnboardingPlanError, match="^ONBOARDING_AUTH_MODE_INVALID$") as caught:
        onboarding.uninspected_guidance(invalid)
    assert SECRET not in str(caught.value) + repr(capsys.readouterr())


def test_overview_never_inspects_environment_or_fabricates_context_or_status(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("Uninspected guidance inspected or fabricated installation state"))
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        assert name.split(".", 1)[0] not in {"app", "psycopg", "sqlalchemy", "redis"}
        return original_import(name, *args, **kwargs)

    with monkeypatch.context() as guarded:
        guarded.setattr(onboarding, "OnboardingContext", forbidden)
        guarded.setattr(onboarding, "PublicEnrollmentStatus", forbidden)
        guarded.setattr(onboarding, "plan_onboarding", forbidden)
        guarded.setattr(onboarding, "revalidate_onboarding", forbidden)
        guarded.setattr(builtins, "open", forbidden)
        guarded.setattr(io, "open", forbidden)
        guarded.setattr(socket, "socket", forbidden)
        guarded.setattr(subprocess, "Popen", forbidden)
        guarded.setattr(builtins, "__import__", guarded_import)
        guarded.setattr(os, "environ", None)
        for mode in ("native", "hcl"):
            document = onboarding.uninspected_guidance(mode).to_dict()
            assert not document["inspection_performed"] and not document["live_enrollment_authorized"]
    forbidden.assert_not_called()
