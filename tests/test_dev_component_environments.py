"""Capture real spawn/build boundaries using synthetic environments and files."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev, dev_components, dev_config, dev_diagnostics, dev_frontend, dev_prepared

BACKEND_MARKER = "fixture-backend-secret-not-for-node"
SESSION_MARKER = "fixture-legitimate-bff-session-secret"


@pytest.fixture
def checkout(tmp_path, monkeypatch):
    root = tmp_path / "checkout"
    source = root / "frontend"
    source.mkdir(parents=True)
    for name in ("src", "public", "node_modules"):
        (source / name).mkdir()
    for name, content in {
        "package.json": '{"name":"fixture"}',
        "package-lock.json": "{}",
        "tsconfig.json": "{}",
        "next.config.mjs": "export default {};",
        ".env.local": "DATABASE_URL=" + BACKEND_MARKER,
    }.items():
        (source / name).write_text(content, encoding="utf-8")
    state = tmp_path / "greenfield-state"
    state.mkdir(mode=0o700)
    monkeypatch.setattr(dev, "ROOT", root)
    monkeypatch.setattr(dev, "CONFIG", root / ".env.dev.local")
    monkeypatch.setattr(dev, "VENV", root / ".venv")
    monkeypatch.setattr(dev, "ACTIVE_PROFILE", "legacy")
    monkeypatch.setattr(dev, "ACTIVE_LEGACY_CONFIG", "managed")
    monkeypatch.setattr(dev, "ACTIVE_RUNTIME", None)
    monkeypatch.setattr(dev.GreenfieldStack, "ROOT", root)
    monkeypatch.setattr(dev.GreenfieldStack, "STATE", state)
    monkeypatch.setattr(dev.LocalHttps, "private_directory", lambda path: None)
    monkeypatch.setattr(dev.GreenfieldStack, "node_binary", lambda: root / "fixture-bin/node")
    monkeypatch.setattr(dev, "normalize_command", lambda command: list(command))
    return root


def full_environment(**overrides):
    values = {
        "PATH": "fixture-path",
        "NODE_ENV": "development",
        "AUTH_ENABLED": "true",
        "DEV_API_PORT": "18081",
        "DEV_FRONTEND_PORT": "13081",
        "SBOM_DEV_PROFILE": "legacy",
        "DATABASE_URL": "postgresql://fixture:" + BACKEND_MARKER + "@127.0.0.1:5432/fixture",
        "NATIVE_JWT_PRIVATE_KEY": BACKEND_MARKER,
        "NATIVE_SECURITY_OUTBOX_KEY": BACKEND_MARKER,
        "SMTP_PASSWORD": BACKEND_MARKER,
        "AI_CONFIG_ENCRYPTION_KEY": BACKEND_MARKER,
        "UNKNOWN_FUTURE_BACKEND_KEY": BACKEND_MARKER,
        "NEXT_PUBLIC_UNREVIEWED_SECRET": BACKEND_MARKER,
        "NATIVE_AUTH_ENABLED": "true",
        "ENTRA_ENABLED": "false",
        "NEXT_PUBLIC_AUTH_ENABLED": "true",
        "NEXT_PUBLIC_HCL_AUTH_ENABLED": "false",
        "NEXT_PUBLIC_API_URL": "http://127.0.0.1:18081",
        "SBOM_API_URL": "http://127.0.0.1:18081",
        "APP_ORIGIN": "https://localhost:13081",
        "AUTH_SESSION_STORE": "redis",
        "AUTH_SESSION_REDIS_URL": "redis://127.0.0.1:6379/1",
        "AUTH_SESSION_ENCRYPTION_KEY": SESSION_MARKER,
    }
    values.update(overrides)
    return values


def captured_spawn(monkeypatch):
    child = SimpleNamespace(pid=4321)
    popen = Mock(return_value=child)
    monkeypatch.setattr(subprocess, "Popen", popen)
    runtime = SimpleNamespace(check_stop=Mock(), processes={}, register=Mock(), state={"services": {}})
    monkeypatch.setattr(dev, "ACTIVE_RUNTIME", runtime)
    return child, popen, runtime


def file_snapshot(root):
    return {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}


@pytest.mark.parametrize(
    "key",
    [
        "HCL_IAM_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "AUTH_TRANSACTION_KEY_FILE",
        "AUTH_SESSION_ENCRYPTION_KEY",
        "AUTH_SESSION_STORE",
        "AUTH_SESSION_REDIS_URL",
    ],
)
def test_next_only_security_fallback_requires_explicit_profile_review_before_logs_or_spawn(checkout, monkeypatch, key):
    workspace = dev_frontend.prepare_workspace(dev, "legacy")
    source = checkout / "frontend/.env.development.local"
    source.write_text(key + "=fixture-next-only-value\n", encoding="utf-8")
    environment = full_environment()
    environment.pop(key, None)
    before, original = file_snapshot(checkout), dict(environment)
    forbidden = Mock(side_effect=AssertionError("unreviewed Next fallback reached a write or process spawn"))
    monkeypatch.setattr(dev, "log_path", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    with pytest.raises(dev.SetupError, match="FRONTEND_SOURCE_CONFIGURATION_REVIEW_REQUIRED") as caught:
        dev.start_process("Frontend", ["fixture-node"], environment, workspace)
    assert BACKEND_MARKER not in str(caught.value)
    assert environment == original
    assert file_snapshot(checkout) == before
    forbidden.assert_not_called()


@pytest.mark.parametrize(
    "key,canonical,source_value",
    [
        ("HCL_IAM_CA_BUNDLE", "certificates/approved-ca.pem", "certificates/next-only-ca.pem"),
        ("AUTH_TRANSACTION_KEY_FILE", "certificates/approved-cookie.pem", "certificates/next-only-cookie.pem"),
        ("AUTH_SESSION_ENCRYPTION_KEY", SESSION_MARKER, BACKEND_MARKER),
    ],
)
def test_explicit_profile_security_values_override_conflicting_next_only_file(checkout, key, canonical, source_value):
    workspace = dev_frontend.prepare_workspace(dev, "legacy")
    (checkout / "frontend/.env.development.local").write_text(f"{key}={source_value}\n", encoding="utf-8")
    environment = full_environment(**{key: canonical})
    before = file_snapshot(checkout)
    projected = dev_components.process_environment(dev, "Frontend", environment, workspace)
    expected = canonical if key == "AUTH_SESSION_ENCRYPTION_KEY" else str(checkout / "frontend" / canonical)
    assert os.path.normpath(projected[key]) == os.path.normpath(expected)
    assert source_value not in projected.values()
    assert file_snapshot(checkout) == before


def test_selected_frontend_env_local_values_already_in_canonical_environment_remain_usable(checkout):
    workspace = dev_frontend.prepare_workspace(dev, "legacy")
    selected = {
        "HCL_IAM_CA_BUNDLE": "certificates/approved-ca.pem",
        "AUTH_TRANSACTION_KEY_FILE": "certificates/approved-cookie.pem",
        "AUTH_SESSION_ENCRYPTION_KEY": SESSION_MARKER,
    }
    (checkout / "frontend/.env.local").write_text(
        "\n".join(f"{key}={value}" for key, value in selected.items()), encoding="utf-8"
    )
    environment = full_environment(**selected)
    before = file_snapshot(checkout)
    projected = dev_components.process_environment(dev, "Frontend", environment, workspace)
    assert projected["AUTH_SESSION_ENCRYPTION_KEY"] == SESSION_MARKER
    assert projected["HCL_IAM_CA_BUNDLE"] == str(checkout / "frontend" / selected["HCL_IAM_CA_BUNDLE"])
    assert projected["AUTH_TRANSACTION_KEY_FILE"] == str(checkout / "frontend" / selected["AUTH_TRANSACTION_KEY_FILE"])
    assert file_snapshot(checkout) == before


@pytest.mark.parametrize("name", [".env.production.local", ".env.production"])
def test_inactive_production_next_files_are_not_loaded_during_development(checkout, name):
    workspace = dev_frontend.prepare_workspace(dev, "legacy")
    (checkout / "frontend" / name).write_bytes(b"HCL_IAM_CA_BUNDLE=unselected\xff\n")
    before = file_snapshot(checkout)
    projected = dev_components.process_environment(dev, "Frontend", full_environment(), workspace)
    assert "HCL_IAM_CA_BUNDLE" not in projected
    assert file_snapshot(checkout) == before


@pytest.mark.parametrize("name", [".env.development.local", ".env.development", ".env.local"])
def test_test_mode_ignores_inactive_development_and_env_local_files(checkout, name):
    workspace = dev_frontend.prepare_workspace(dev, "legacy")
    (checkout / "frontend" / name).write_text("HCL_IAM_CA_BUNDLE=next-only-ca\n", encoding="utf-8")
    projected = dev_components.process_environment(dev, "Frontend", full_environment(NODE_ENV="test"), workspace)
    assert "HCL_IAM_CA_BUNDLE" not in projected


def test_test_mode_checks_its_active_env_test_local_security_fallback(checkout):
    (checkout / "frontend/.env.test.local").write_text("HCL_IAM_CA_BUNDLE=next-only-ca\n", encoding="utf-8")
    with pytest.raises(dev.SetupError, match="FRONTEND_SOURCE_CONFIGURATION_REVIEW_REQUIRED"):
        dev_components.review_source_environment(dev, full_environment(NODE_ENV="test"), "legacy")


def test_greenfield_does_not_inspect_legacy_private_environment_files(checkout, monkeypatch):
    workspace = dev_frontend.prepare_workspace(dev, "greenfield")
    (checkout / "frontend/.env.development.local").write_bytes(b"HCL_IAM_CA_BUNDLE=private\xff\n")
    before = file_snapshot(checkout)
    forbidden = Mock(side_effect=AssertionError("Greenfield inspected a Legacy private environment file"))
    monkeypatch.setattr(dev_components.dev_environment, "bounded_read_text", forbidden)
    projected = dev_components.process_environment(
        dev, "Frontend", full_environment(SBOM_DEV_PROFILE="greenfield"), workspace
    )
    assert projected["AUTH_SESSION_ENCRYPTION_KEY"] == SESSION_MARKER
    assert file_snapshot(checkout) == before
    forbidden.assert_not_called()


@pytest.mark.parametrize("case", ["symlink", "hardlink", "oversize", "directory", "invalid-utf8"])
def test_unverifiable_next_environment_source_fails_closed_without_writes(checkout, monkeypatch, case):
    workspace = dev_frontend.prepare_workspace(dev, "legacy")
    source = checkout / "frontend/.env.development.local"
    original = checkout / "preserved-fixture-input"
    original.write_bytes(b"HCL_IAM_CA_BUNDLE=fixture-private-value\n")
    if case == "symlink":
        try:
            source.symlink_to(original)
        except OSError:
            pytest.skip("Host has no approved fixture-symlink privilege")
    elif case == "hardlink":
        try:
            os.link(original, source)
        except OSError:
            pytest.skip("Fixture filesystem does not support hardlinks")
    elif case == "oversize":
        source.write_bytes(b"#" + b"x" * 131072)
    elif case == "directory":
        source.mkdir()
    else:
        source.write_bytes(b"HCL_IAM_CA_BUNDLE=invalid\xff\n")
    before = file_snapshot(checkout)
    forbidden = Mock(side_effect=AssertionError("unverifiable Next source reached process/log creation"))
    monkeypatch.setattr(dev, "log_path", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    with pytest.raises(dev.SetupError, match="FRONTEND_SOURCE_CONFIGURATION_UNVERIFIED"):
        dev.start_process("Frontend", ["fixture-node"], full_environment(), workspace)
    assert file_snapshot(checkout) == before
    forbidden.assert_not_called()


@pytest.mark.parametrize("unverifiable", [False, True])
def test_diagnose_workspace_reports_safe_source_reason_without_preparation(checkout, monkeypatch, unverifiable):
    dev_frontend.prepare_workspace(dev, "legacy")
    source = checkout / "frontend/.env.development.local"
    source.write_bytes(b"HCL_IAM_CA_BUNDLE=" + (b"\xff" if unverifiable else b"fixture-ca"))
    before = file_snapshot(checkout)
    forbidden = Mock(side_effect=AssertionError("workspace diagnosis attempted preparation, installation or spawn"))
    monkeypatch.setattr(dev_frontend, "prepare_workspace", forbidden)
    monkeypatch.setattr(dev, "ensure_frontend", forbidden)
    monkeypatch.setattr(dev, "log_path", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    result = dev_diagnostics._workspace_check("legacy", dev, full_environment())
    expected = (
        "FRONTEND_SOURCE_CONFIGURATION_UNVERIFIED" if unverifiable else "FRONTEND_SOURCE_CONFIGURATION_REVIEW_REQUIRED"
    )
    assert (result.status, result.code) == ("BLOCKED", expected)
    assert "Review" in result.guidance and "no private file" in result.guidance
    assert BACKEND_MARKER not in repr(result) and SESSION_MARKER not in repr(result)
    assert file_snapshot(checkout) == before
    forbidden.assert_not_called()


@pytest.mark.parametrize("telemetry", [None, "0", "1"])
def test_telemetry_default_is_one_and_explicit_zero_is_preserved(checkout, telemetry):
    workspace = dev_frontend.prepare_workspace(dev, "legacy")
    (checkout / "frontend/.env.development.local").write_text(
        "NEXT_TELEMETRY_DISABLED=1\nHCL_IAM_CA_BUNDLE=\nAUTH_TRANSACTION_KEY_FILE=\n", encoding="utf-8"
    )
    environment = full_environment(**({} if telemetry is None else {"NEXT_TELEMETRY_DISABLED": telemetry}))
    before = file_snapshot(checkout)
    projected = dev_components.process_environment(dev, "Frontend", environment, workspace)
    assert projected["NEXT_TELEMETRY_DISABLED"] == ("1" if telemetry is None else telemetry)
    assert file_snapshot(checkout) == before


def test_openssl_ca_file_and_directory_list_keep_original_frontend_path_semantics(checkout):
    workspace = dev_frontend.prepare_workspace(dev, "legacy")
    directories = ["certificates/corporate-roots", "../approved-ca-directory"]
    environment = full_environment(
        NODE_OPTIONS="--use-openssl-ca",
        SSL_CERT_FILE="certificates/corporate-ca.pem",
        SSL_CERT_DIR=os.pathsep.join(directories),
    )
    original, before = dict(environment), file_snapshot(checkout)
    projected = dev_components.process_environment(dev, "Frontend", environment, workspace)
    base = checkout / "frontend"
    assert projected["SSL_CERT_FILE"] == str(base / environment["SSL_CERT_FILE"])
    assert [os.path.normpath(item) for item in projected["SSL_CERT_DIR"].split(os.pathsep)] == [
        os.path.normpath(str(base / item)) for item in directories
    ]
    public = dev_config.component_environment(environment, "public")
    assert "SSL_CERT_FILE" not in public and "SSL_CERT_DIR" not in public
    assert environment == original
    assert file_snapshot(checkout) == before


@pytest.mark.parametrize(
    "directories",
    ["", os.pathsep + "certificates", "certificates" + os.pathsep, "certificates" + os.pathsep * 2 + "more"],
)
def test_empty_openssl_ca_directory_component_is_refused_before_logs_and_spawn(checkout, monkeypatch, directories):
    workspace = dev_frontend.prepare_workspace(dev, "legacy")
    environment = full_environment(NODE_OPTIONS="--use-openssl-ca", SSL_CERT_DIR=directories)
    before = file_snapshot(checkout)
    forbidden = Mock(side_effect=AssertionError("ambiguous CA directory reached logs or process creation"))
    monkeypatch.setattr(dev, "log_path", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    with pytest.raises((dev.SetupError, dev_config.ConfigurationError), match="TLS_CA_PATH_REVIEW_REQUIRED"):
        dev.start_process("Frontend", ["fixture-node"], environment, workspace)
    assert file_snapshot(checkout) == before
    forbidden.assert_not_called()


@pytest.mark.parametrize(
    "alias", ["hcl_iam_ca_bundle", "auth_session_encryption_key", "ssl_cert_file", "node_tls_reject_unauthorized"]
)
def test_noncanonical_known_frontend_name_is_not_silently_dropped_before_spawn(checkout, monkeypatch, alias):
    workspace = dev_frontend.prepare_workspace(dev, "legacy")
    environment = full_environment()
    environment.pop(alias.upper(), None)
    environment[alias] = "0" if alias == "node_tls_reject_unauthorized" else BACKEND_MARKER
    before, original = file_snapshot(checkout), dict(environment)
    forbidden = Mock(side_effect=AssertionError("ambiguous known setting reached logs or process creation"))
    monkeypatch.setattr(dev, "log_path", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    with pytest.raises((dev.SetupError, dev_config.ConfigurationError)) as caught:
        dev.start_process("Frontend", ["fixture-node"], environment, workspace)
    assert BACKEND_MARKER not in str(caught.value)
    assert environment == original and file_snapshot(checkout) == before
    forbidden.assert_not_called()


@pytest.mark.parametrize(
    "alias", ["hcl_iam_ca_bundle", "auth_transaction_key_file", "ssl_cert_dir", "node_tls_reject_unauthorized"]
)
def test_effective_next_only_known_case_alias_requires_review(checkout, monkeypatch, alias):
    workspace = dev_frontend.prepare_workspace(dev, "legacy")
    (checkout / "frontend/.env.development.local").write_text(f"{alias}=0\n", encoding="utf-8")
    environment = full_environment()
    environment.pop(alias.upper(), None)
    forbidden = Mock(side_effect=AssertionError("effective Next case alias reached logs or process creation"))
    monkeypatch.setattr(dev, "log_path", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    with pytest.raises((dev.SetupError, dev_config.ConfigurationError)):
        dev.start_process("Frontend", ["fixture-node"], environment, workspace)
    forbidden.assert_not_called()


@pytest.mark.parametrize(
    "mode,higher,lower",
    [
        ("development", ".env.development.local", ".env.local"),
        ("development", ".env.local", ".env.development"),
        ("test", ".env.test.local", ".env.test"),
    ],
)
def test_effective_blank_high_priority_setting_shadows_nonempty_lower_file(checkout, mode, higher, lower):
    workspace = dev_frontend.prepare_workspace(dev, "legacy")
    (checkout / "frontend" / higher).write_text("HCL_IAM_CA_BUNDLE=\n", encoding="utf-8")
    (checkout / "frontend" / lower).write_text("HCL_IAM_CA_BUNDLE=shadowed-value\n", encoding="utf-8")
    environment = full_environment(NODE_ENV=mode)
    before = file_snapshot(checkout)
    projected = dev_components.process_environment(dev, "Frontend", environment, workspace)
    assert "HCL_IAM_CA_BUNDLE" not in projected
    assert file_snapshot(checkout) == before


def test_windows_priority_shadowing_uses_case_insensitive_names(checkout, monkeypatch):
    (checkout / "frontend/.env.development.local").write_text("HCL_IAM_CA_BUNDLE=\n", encoding="utf-8")
    (checkout / "frontend/.env.local").write_text("hcl_iam_ca_bundle=shadowed-value\n", encoding="utf-8")
    monkeypatch.setattr(dev.sys, "platform", "win32")
    before = file_snapshot(checkout)
    dev_components.review_source_environment(dev, full_environment(), "legacy")
    assert file_snapshot(checkout) == before


def test_effective_default_telemetry_setting_shadows_lower_opt_in(checkout):
    workspace = dev_frontend.prepare_workspace(dev, "legacy")
    (checkout / "frontend/.env.development.local").write_text("NEXT_TELEMETRY_DISABLED=1\n", encoding="utf-8")
    (checkout / "frontend/.env.local").write_text("NEXT_TELEMETRY_DISABLED=0\n", encoding="utf-8")
    projected = dev_components.process_environment(dev, "Frontend", full_environment(), workspace)
    assert projected["NEXT_TELEMETRY_DISABLED"] == "1"


def test_next_only_telemetry_opt_in_is_not_silently_discarded_or_adopted(checkout):
    (checkout / "frontend/.env.development.local").write_text("NEXT_TELEMETRY_DISABLED=0\n", encoding="utf-8")
    with pytest.raises(dev.SetupError, match="FRONTEND_SOURCE_CONFIGURATION_REVIEW_REQUIRED"):
        dev_components.review_source_environment(dev, full_environment(), "legacy")


def test_next_only_tls_bypass_fails_closed_without_modification(checkout):
    path = checkout / "frontend/.env.local"
    path.write_text("NODE_TLS_REJECT_UNAUTHORIZED=0\n", encoding="utf-8")
    before = path.read_bytes()
    with pytest.raises(dev.SetupError, match="TLS_VERIFICATION_REQUIRED"):
        dev_components.review_source_environment(dev, full_environment(), "legacy")
    assert path.read_bytes() == before


def test_diagnosis_reports_ambiguous_ca_directory_without_probe(checkout, monkeypatch):
    dev_frontend.prepare_workspace(dev, "legacy")
    forbidden = Mock(side_effect=AssertionError("diagnosis attempted a probe"))
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    result = dev_diagnostics._workspace_check("legacy", dev, full_environment(SSL_CERT_DIR=""))
    assert (result.status, result.code) == ("BLOCKED", "TLS_CA_PATH_REVIEW_REQUIRED")
    forbidden.assert_not_called()


@pytest.mark.parametrize("value", ["1", "0", "true", "false"])
def test_frontend_ci_prevents_implicit_installation_without_mutating_parent(checkout, value):
    workspace = dev_frontend.prepare_workspace(dev, "legacy")
    environment = full_environment(CI=value)
    projected = dev_components.process_environment(dev, "Frontend", environment, workspace)
    assert projected["CI"] == "1"
    assert environment["CI"] == value
    assert "CI" not in dev_config.component_environment(environment, "public")


def test_verified_workspace_diagnosis_is_read_only(checkout, monkeypatch):
    dev_frontend.prepare_workspace(dev, "legacy")
    before = file_snapshot(checkout)
    forbidden = Mock(side_effect=AssertionError("successful workspace diagnosis attempted preparation or spawn"))
    monkeypatch.setattr(dev_frontend, "prepare_workspace", forbidden)
    monkeypatch.setattr(dev, "ensure_frontend", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    result = dev_diagnostics._workspace_check("legacy", dev, full_environment())
    assert (result.status, result.code) == ("PASS", "FRONTEND_WORKSPACE_VERIFIED")
    assert file_snapshot(checkout) == before
    forbidden.assert_not_called()


@pytest.mark.parametrize("profile", ["legacy", "greenfield"])
def test_actual_popen_receives_frontend_projection_while_registration_keeps_original_custom_port(
    checkout, monkeypatch, profile
):
    monkeypatch.setattr(dev, "ACTIVE_PROFILE", profile)
    workspace = dev_frontend.prepare_workspace(dev, profile)
    environment = full_environment(SBOM_DEV_PROFILE=profile)
    before = dict(environment)
    child, popen, runtime = captured_spawn(monkeypatch)
    assert dev.start_process("Frontend", ["fixture-node", "fixture-next"], environment, workspace) is child
    projected = popen.call_args.kwargs["env"]
    assert BACKEND_MARKER not in json.dumps(projected)
    assert projected["AUTH_SESSION_ENCRYPTION_KEY"] == SESSION_MARKER
    assert projected["AUTH_SESSION_REDIS_URL"] == environment["AUTH_SESSION_REDIS_URL"]
    assert projected["NEXT_PUBLIC_AUTH_ENABLED"] == "true"
    assert "DEV_FRONTEND_PORT" not in projected
    assert "DATABASE_URL" not in projected and "NATIVE_JWT_PRIVATE_KEY" not in projected
    runtime.register.assert_called_once_with("Frontend", 4321, 13081)
    assert runtime.processes[4321] is child
    assert environment == before
    assert popen.call_args.kwargs["cwd"] == workspace
    assert not any(path.name.startswith(".env") for path in workspace.iterdir())


@pytest.mark.parametrize("name", ["API", "Celery worker", "Celery reports worker", "Celery Beat"])
def test_server_process_environments_retain_shared_settings_compatibility(checkout, monkeypatch, name):
    environment = full_environment()
    before = dict(environment)
    _, popen, runtime = captured_spawn(monkeypatch)
    dev.start_process(name, ["fixture-python", "fixture-command"], environment, checkout)
    projected = popen.call_args.kwargs["env"]
    assert {key: value for key, value in projected.items() if key != "PATH"} == {
        key: value for key, value in environment.items() if key != "PATH"
    }
    assert projected["NATIVE_JWT_PRIVATE_KEY"] == BACKEND_MARKER
    assert environment == before
    runtime.register.assert_called_once_with(name, 4321, 18081 if name == "API" else None)


@pytest.mark.parametrize(
    "flags",
    [
        {"NATIVE_AUTH_ENABLED": "true", "ENTRA_ENABLED": "false", "NEXT_PUBLIC_HCL_AUTH_ENABLED": "false"},
        {"NATIVE_AUTH_ENABLED": "false", "ENTRA_ENABLED": "false", "NEXT_PUBLIC_HCL_AUTH_ENABLED": "true"},
        {"NATIVE_AUTH_ENABLED": "false", "ENTRA_ENABLED": "true", "NEXT_PUBLIC_HCL_AUTH_ENABLED": "false"},
    ],
)
def test_provider_flags_and_existing_relative_transaction_ca_paths_preserve_original_frontend_meaning(checkout, flags):
    workspace = dev_frontend.prepare_workspace(dev, "legacy")
    environment = full_environment(
        **flags,
        AUTH_TRANSACTION_KEY_FILE="certificates/existing-cookie-key.pem",
        HCL_IAM_CA_BUNDLE="../certificates/provider-ca.pem",
        NODE_EXTRA_CA_CERTS="certificates/corporate-ca.pem",
        NODE_OPTIONS="--use-openssl-ca --tls-min-v1.2 --max-old-space-size=2048",
        ENTRA_TENANT_ID="fixture-tenant",
        ENTRA_FRONTEND_CLIENT_ID="fixture-client",
        ENTRA_API_CLIENT_ID="fixture-api",
    )
    before = dict(environment)
    projected = dev_components.process_environment(dev, "Frontend", environment, workspace)
    for key, value in flags.items():
        assert projected[key] == value
    original = checkout / "frontend"
    for key in ("AUTH_TRANSACTION_KEY_FILE", "HCL_IAM_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"):
        assert os.path.normpath(projected[key]) == os.path.normpath(str(original / environment[key]))
        assert Path(projected[key]).is_absolute()
    assert projected["NODE_OPTIONS"] == environment["NODE_OPTIONS"]
    assert projected["ENTRA_FRONTEND_CLIENT_ID"] == "fixture-client"
    assert environment == before


@pytest.mark.parametrize("profile", ["legacy", "greenfield"])
def test_default_transaction_key_uses_existing_original_key_without_copying_or_generating(checkout, profile):
    workspace = dev_frontend.prepare_workspace(dev, profile)
    projected = dev_components.process_environment(
        dev, "Frontend", full_environment(SBOM_DEV_PROFILE=profile), workspace
    )
    expected = (
        checkout / "frontend/certificates/localhost-key.pem"
        if profile == "legacy"
        else dev.GreenfieldStack.STATE / "cert-key.pem"
    )
    assert projected["AUTH_TRANSACTION_KEY_FILE"] == str(expected)
    assert not expected.exists()
    assert not (workspace / "certificates").exists()


@pytest.mark.parametrize(
    "override",
    [
        {"NODE_TLS_REJECT_UNAUTHORIZED": "0"},
        {"NODE_OPTIONS": "--require=fixture-preload"},
        {"NODE_OPTIONS": "--import=fixture-preload"},
        {"NODE_OPTIONS": "--tls-min-v1.0"},
        {"NODE_OPTIONS": "--openssl-config=fixture.cnf"},
        {"NEXT_PUBLIC_API_URL": "https://fixture:" + BACKEND_MARKER + "@fixture.invalid"},
    ],
)
def test_insecure_tls_preloads_and_public_credentials_are_refused_before_spawn_or_log_writes(
    checkout, monkeypatch, override
):
    workspace = dev_frontend.prepare_workspace(dev, "legacy")
    environment = full_environment(**override)
    forbidden = Mock(side_effect=AssertionError("invalid frontend configuration reached process/log creation"))
    monkeypatch.setattr(dev, "log_path", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    with pytest.raises((dev.SetupError, dev_config.ConfigurationError)) as caught:
        dev.start_process("Frontend", ["fixture-node"], environment, workspace)
    assert BACKEND_MARKER not in str(caught.value)
    forbidden.assert_not_called()


@pytest.mark.parametrize("unsafe", ["source-cwd", "workspace-env"])
def test_unsafe_frontend_working_directory_or_environment_file_blocks_before_spawn_and_logs(
    checkout, monkeypatch, unsafe
):
    workspace = dev_frontend.prepare_workspace(dev, "legacy")
    cwd = checkout / "frontend" if unsafe == "source-cwd" else workspace
    if unsafe == "workspace-env":
        (workspace / ".env.local").write_text("DATABASE_URL=" + BACKEND_MARKER, encoding="utf-8")
    forbidden = Mock(side_effect=AssertionError("unsafe frontend directory reached process/log creation"))
    monkeypatch.setattr(dev, "log_path", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    with pytest.raises(dev.SetupError):
        dev.start_process("Frontend", ["fixture-node"], full_environment(), cwd)
    forbidden.assert_not_called()


def test_public_projection_is_an_immutable_explicit_allowlist_without_bff_or_unknown_secrets():
    environment = full_environment(NEXT_PUBLIC_HCL_IAM_CLIENT_ID="fixture-public-client")
    before = dict(environment)
    public = dev_config.component_environment(environment, "public")
    assert public["NEXT_PUBLIC_HCL_IAM_CLIENT_ID"] == "fixture-public-client"
    assert all(name.startswith("NEXT_PUBLIC_") for name in public)
    assert BACKEND_MARKER not in json.dumps(dict(public))
    assert SESSION_MARKER not in json.dumps(dict(public))
    with pytest.raises(TypeError):
        public["NEXT_PUBLIC_EXTRA"] = "changed"
    assert environment == before


def test_greenfield_build_boundary_receives_same_filtered_environment(checkout, monkeypatch):
    workspace = dev_frontend.prepare_workspace(dev, "greenfield")
    environment = full_environment(SBOM_DEV_PROFILE="greenfield")
    monkeypatch.setattr(os, "environ", {"APP_ENVIRONMENT": "development"})
    monkeypatch.setattr(dev, "Runtime", lambda root: SimpleNamespace(load=lambda: None))
    monkeypatch.setattr(dev, "validate_repository_layout", lambda: None)
    monkeypatch.setattr(dev, "validate_prerequisites", lambda: None)
    monkeypatch.setattr(dev, "require_virtualenv", lambda: None)
    monkeypatch.setattr(dev_prepared, "require_project", lambda launcher: "fixture-npm")
    monkeypatch.setattr(dev, "resolve_profile", lambda requested: "greenfield")
    monkeypatch.setattr(dev.LocalHttps, "ensure_certificate", lambda *args, **kwargs: (None, None, None, None))
    monkeypatch.setattr(dev.GreenfieldStack, "settings", lambda: dict(environment))
    monkeypatch.setattr(dev, "validate_secrets", lambda env: None)
    compiler = Mock()
    monkeypatch.setattr(dev_components, "verify_compiler", compiler)
    execute = Mock(return_value=SimpleNamespace(returncode=0))
    monkeypatch.setattr(dev, "run", execute)
    args = SimpleNamespace(
        profile="greenfield",
        legacy_config="auto",
        initialize_database=False,
        migrate=False,
        provision_greenfield=False,
        frontend_build=True,
        _setup_authorized_categories=frozenset({"frontend-build"}),
    )
    dev._prepare_authorized_setup(args, "greenfield")
    compiler.assert_called_once()
    execute.assert_called_once()
    build_env = execute.call_args.kwargs["env"]
    assert build_env["NODE_ENV"] == "production"
    assert build_env["AUTH_SESSION_ENCRYPTION_KEY"] == SESSION_MARKER
    assert BACKEND_MARKER not in json.dumps(build_env)
    assert execute.call_args.kwargs["cwd"] == workspace
    assert environment["NODE_ENV"] == "development"


def test_installed_next_environment_loader_cannot_reload_backend_secrets_from_source_directory(checkout):
    node = shutil.which("node")
    candidates = [Path(__file__).resolve().parents[1] / "frontend/node_modules/@next/env/dist/index.js"]
    if os.name == "nt":
        candidates.append(Path("C:/sbom/frontend/node_modules/@next/env/dist/index.js"))
    loader = next((candidate for candidate in candidates if candidate.is_file()), None)
    if not node or loader is None:
        pytest.skip("This optional fixture requires an already-installed Node and approved @next/env dependency")
    workspace = dev_frontend.prepare_workspace(dev, "legacy")
    child_env = dev_components.process_environment(dev, "Frontend", full_environment(), workspace)
    child_env["PATH"] = str(Path(node).parent)
    for name in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP"):
        if name in os.environ:
            child_env[name] = os.environ[name]
    script = r"""
const fs = require('node:fs');
const path = require('node:path');
const { loadEnvConfig } = require(process.argv[1]);
const workspace = process.argv[2], source = process.argv[3];
const silent = { info() {}, error() {} };
const first = loadEnvConfig(workspace, true, silent, true);
fs.writeFileSync(path.join(source, '.env.local'), 'DATABASE_URL=fixture-reload-secret\nNATIVE_JWT_PRIVATE_KEY=fixture-reload-key\nNEXT_PUBLIC_UNREVIEWED_SECRET=fixture-reload-public\n');
const second = loadEnvConfig(workspace, true, silent, true);
process.stdout.write(JSON.stringify({
  firstEmpty: first.loadedEnvFiles.length === 0,
  secondEmpty: second.loadedEnvFiles.length === 0,
  backendAbsent: process.env.DATABASE_URL === undefined && process.env.NATIVE_JWT_PRIVATE_KEY === undefined,
  unknownPublicAbsent: process.env.NEXT_PUBLIC_UNREVIEWED_SECRET === undefined,
  publicPresent: process.env.NEXT_PUBLIC_AUTH_ENABLED === 'true',
  bffSessionPresent: process.env.AUTH_SESSION_ENCRYPTION_KEY === 'fixture-legitimate-bff-session-secret'
}));
"""
    child = subprocess.Popen(
        [node, "-e", script, str(loader), str(workspace), str(checkout / "frontend")],
        cwd=workspace,
        env=child_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        stdout, stderr = child.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        child.kill()  # Only this fixture's original Popen handle; no saved PID/process tree.
        child.communicate(timeout=5)
        pytest.fail("Owned Node environment-loader fixture exceeded its reporting deadline")
    assert child.returncode == 0, "Owned Node environment-loader fixture failed; output withheld"
    assert not stderr
    assert BACKEND_MARKER not in stdout and SESSION_MARKER not in stdout
    observed = json.loads(stdout)
    assert observed == {
        "firstEmpty": True,
        "secondEmpty": True,
        "backendAbsent": True,
        "unknownPublicAbsent": True,
        "publicPresent": True,
        "bffSessionPresent": True,
    }
