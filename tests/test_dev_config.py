"""Pure configuration parity and isolation checks; run with --noconftest."""

from __future__ import annotations

import base64
import builtins
import json
import os
import socket
import subprocess
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from dotenv import dotenv_values
from scripts import dev, dev_config

PASSWORD = "fixture-password-not-for-logging"
LOCAL_URL = f"postgresql+psycopg://postgres:{PASSWORD}@127.0.0.1:5432/sbom_analyser_dev"


def resolve(**overrides):
    arguments = {
        "profile": "legacy",
        "inherited": {},
        "saved": {"DATABASE_URL": LOCAL_URL},
        "root": "C:/fixture/repository",
        "platform": "win32",
    }
    arguments.update(overrides)
    return dev_config.resolve_configuration(**arguments)


@pytest.mark.parametrize(
    "values",
    [
        {"DATABASE_URL": LOCAL_URL, "VALUE": "literal=${UNDEFINED}=suffix"},
        {"NATIVE_JWT_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----\n"},
        {"VALUE": "apostrophe ' quote \" slash \\ and \u2603", "EMPTY": ""},
    ],
)
def test_managed_text_parser_matches_existing_reader(tmp_path, values):
    text = "# Existing managed format\n" + "\n".join(f"{key}={json.dumps(value)}" for key, value in values.items())
    path = tmp_path / ".env.dev.local"
    path.write_text(text, encoding="utf-8")
    assert dev_config.parse_managed(text) == dev.read_config(path) == values


def test_managed_simple_values_preserve_equals_and_do_not_interpolate():
    text = "FLAG=true\nVALUE=${HOME}=tail\nEMPTY=\n# comment\n"
    assert dev_config.parse_managed(text) == {"FLAG": "true", "VALUE": "${HOME}=tail", "EMPTY": ""}


@pytest.mark.parametrize("text", ["INVALID LINE", 'VALUE="unterminated', 'VALUE="x" trailing'])
def test_managed_malformed_input_is_refused_without_echoing_values(text):
    with pytest.raises(dev_config.ConfigurationError):
        dev_config.parse_managed(text)


def test_windows_literal_parser_matches_existing_reader(tmp_path):
    text = (
        "# Existing PowerShell data\n$env:DATABASE_URL = '" + LOCAL_URL + "'\n$env:VALUE = 'it''s ${HOME}; literal'\n"
    )
    path = tmp_path / "sbom.env.ps1"
    path.write_text(text, encoding="utf-8-sig")
    assert dev_config.parse_windows(text) == dev.read_literal_windows_configuration(path)
    assert dev_config.parse_windows(text)["VALUE"] == "it's ${HOME}; literal"


@pytest.mark.parametrize(
    "text",
    [
        "$env:VALUE = $(Get-Content secret)",
        '$env:VALUE = "interpolated"',
        "$env:VALUE = 'literal'; Write-Output 'executable'",
        "Invoke-Expression 'fixture'",
    ],
)
def test_windows_parser_rejects_executable_content(text):
    with pytest.raises(dev_config.ConfigurationError):
        dev_config.parse_windows(text)


def test_dotenv_parser_matches_noninterpolating_existing_format(tmp_path, monkeypatch):
    monkeypatch.setenv("EXPANSION_FIXTURE", "must-not-expand")
    text = "export A='literal value'\nB=${EXPANSION_FIXTURE}\nEMPTY=\nUNSET\n# comment\n"
    path = tmp_path / ".env"
    path.write_text(text, encoding="utf-8")
    expected = {key: value for key, value in dotenv_values(path, interpolate=False).items() if value is not None}
    assert dev_config.parse_dotenv(text) == expected
    assert dev_config.parse_dotenv(text)["B"] == "${EXPANSION_FIXTURE}"


def test_managed_existing_resolution_preserves_saved_precedence_without_startup_defaults():
    inherited = {"DATABASE_URL": "not-selected", "SHARED": "inherited", "PROCESS_ONLY": "keep"}
    saved = {"DATABASE_URL": LOCAL_URL, "SHARED": "saved", "HCL_AUTH_ENABLED": "true"}
    plan = resolve(inherited=inherited, saved=saved)
    assert dict(plan.environment) == {**inherited, **saved}
    assert "DEV_API_PORT" not in plan.environment
    assert "NATIVE_AUTH_ENABLED" not in plan.environment
    assert plan.database.host == "127.0.0.1"
    assert plan.database.port == 5432
    assert plan.database.name == "sbom_analyser_dev"
    assert plan.provenance["SHARED"] != plan.provenance["PROCESS_ONLY"]
    assert plan.authentication_enabled is None


def test_public_url_cannot_project_embedded_credentials():
    with pytest.raises(dev_config.ConfigurationError) as caught:
        resolve(saved={"DATABASE_URL": LOCAL_URL, "NEXT_PUBLIC_API_URL": "https://user:fixture-secret@localhost/"})
    assert "fixture-secret" not in str(caught.value)


@pytest.mark.parametrize(
    ("postgres", "redis", "smtp", "provider"),
    [(5432, 6379, 1025, "local"), (dev.POSTGRES_PORT, dev.REDIS_PORT, dev.MAILPIT_SMTP_PORT, "docker")],
)
def test_prepared_managed_startup_matches_existing_pure_resolver(postgres, redis, smtp, provider):
    saved = {
        "DATABASE_URL": LOCAL_URL.replace(":5432/", f":{postgres}/"),
        "DEV_POSTGRES_PROVIDER": provider,
        "DEV_REDIS_PROVIDER": provider,
        "NATIVE_JWT_PRIVATE_KEY": "fixture-existing-private-key",
        "NATIVE_PLATFORM_BOOTSTRAP_ENABLED": "false",
        "HCL_AUTH_ENABLED": "true",
        "SMTP_PASSWORD": "saved-mail-value",
        "CUSTOM_SETTING": "preserved",
    }
    inherited = {"PATH": "fixture-path", "HCL_AUTH_ENABLED": "true", "PROCESS_ONLY": "keep"}
    expected = {**inherited, **dev.resolve_config(saved, postgres, redis, smtp, provider, provider)}
    plan = resolve(
        purpose="startup",
        inherited=inherited,
        saved=saved,
        ports=dev_config.ServicePorts(postgres, redis, smtp, provider, provider),
    )
    assert dict(plan.environment) == expected
    assert plan.environment["NATIVE_JWT_PRIVATE_KEY"] == "fixture-existing-private-key"
    assert plan.environment["HCL_AUTH_ENABLED"] == "false"
    assert plan.provenance["HCL_AUTH_ENABLED"] != plan.provenance["NATIVE_JWT_PRIVATE_KEY"]


@pytest.mark.parametrize("family", ["windows", "env"])
@pytest.mark.parametrize("native", ["true", "false"])
def test_saved_legacy_resolution_matches_existing_helper(tmp_path, monkeypatch, family, native):
    inherited = {"SHARED": "inherited", "PROCESS_ONLY": "keep", "PYTHONPATH": "old-path"}
    saved = {
        "DATABASE_URL": LOCAL_URL.replace("sbom_analyser_dev", "fixture_existing_development"),
        "SHARED": "saved",
        "NATIVE_AUTH_ENABLED": native,
    }
    frontend = {"SHARED": "frontend", "FRONTEND_ONLY": "keep", "NEXT_PUBLIC_AUTH_ENABLED": "true"}
    monkeypatch.setattr(dev, "ROOT", tmp_path)
    monkeypatch.setattr(dev.os, "environ", dict(inherited))
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend/.env.local").write_text(
        "\n".join(f"{key}={value}" for key, value in frontend.items()), encoding="utf-8"
    )
    if family == "windows":
        (tmp_path / ".windows").mkdir()
        (tmp_path / ".windows/sbom.env.ps1").write_text(
            "\n".join(f"$env:{key} = '{value}'" for key, value in saved.items()), encoding="utf-8"
        )
    else:
        (tmp_path / ".env").write_text("\n".join(f"{key}={value}" for key, value in saved.items()), encoding="utf-8")
    expected = dev.existing_legacy_environment(family)
    plan = resolve(family=family, inherited=inherited, saved=saved, frontend=frontend, root=str(tmp_path))
    assert dict(plan.environment) == expected
    assert plan.provenance["SHARED"] != plan.provenance["FRONTEND_ONLY"]
    assert plan.provenance["FRONTEND_ONLY"] != plan.provenance["PROCESS_ONLY"]


@pytest.mark.parametrize(
    "url",
    [
        f"postgresql+psycopg://postgres:{PASSWORD}@remote.invalid:5432/sbom_analyser_dev",
        LOCAL_URL.replace("sbom_analyser_dev", "postgres"),
        LOCAL_URL.replace("sbom_analyser_dev", "sbom_greenfield_uuid"),
        LOCAL_URL.replace("postgresql+psycopg", "sqlite"),
        LOCAL_URL + "?password=fixture-secret",
        LOCAL_URL + "#fixture-secret",
        LOCAL_URL + "#",
        LOCAL_URL + "?",
        " " + LOCAL_URL,
        LOCAL_URL.replace(":5432/", ":invalid/"),
        LOCAL_URL.replace("127.0.0.1", "[broken"),
    ],
)
def test_managed_target_policy_refuses_unsafe_targets_without_credentials(url):
    with pytest.raises(dev_config.ConfigurationError) as caught:
        resolve(saved={"DATABASE_URL": url})
    assert PASSWORD not in str(caught.value)
    assert url not in str(caught.value)
    assert PASSWORD not in repr(caught.value)


@pytest.mark.parametrize("family", ["env", "windows"])
@pytest.mark.parametrize("name", ["postgres", "template0", "template1", "sbom_greenfield_uuid"])
def test_legacy_saved_family_never_selects_system_or_greenfield_database(family, name):
    with pytest.raises(dev_config.ConfigurationError):
        resolve(family=family, saved={"DATABASE_URL": LOCAL_URL.replace("sbom_analyser_dev", name)})


@pytest.mark.parametrize("family", ["env", "windows"])
def test_legacy_saved_family_rejects_greenfield_port_and_database_broker(family):
    with pytest.raises(dev_config.ConfigurationError):
        resolve(family=family, saved={"DATABASE_URL": LOCAL_URL.replace(":5432/", ":56044/")})
    with pytest.raises(dev_config.ConfigurationError):
        resolve(family=family, saved={"DATABASE_URL": LOCAL_URL, "CELERY_USE_DATABASE_BROKER": "true"})


def test_unprepared_managed_configuration_is_not_created_from_ambient_database_url():
    with pytest.raises(dev_config.ConfigurationError):
        resolve(saved={}, inherited={"DATABASE_URL": LOCAL_URL})


def test_managed_startup_refuses_provider_change_without_replacing_credentials():
    saved = {"DATABASE_URL": LOCAL_URL, "DEV_POSTGRES_PROVIDER": "local"}
    with pytest.raises(dev_config.ConfigurationError):
        resolve(purpose="startup", saved=saved, ports=dev_config.ServicePorts(55432, 56379, 1025, "docker", "docker"))
    assert saved["DATABASE_URL"] == LOCAL_URL


@pytest.mark.parametrize(("selected_provider", "redis_port"), [("local", 6379), ("docker", dev.REDIS_PORT)])
@pytest.mark.parametrize("explicit_selection", [False, True])
@pytest.mark.parametrize("saved_provider_present", [False, True])
def test_managed_startup_matching_or_missing_redis_provider_preserves_existing_parity(
    selected_provider, redis_port, explicit_selection, saved_provider_present
):
    saved = {"DATABASE_URL": LOCAL_URL, "DEV_POSTGRES_PROVIDER": "local"}
    if saved_provider_present:
        saved["DEV_REDIS_PROVIDER"] = selected_provider
    inherited = {"DEV_REDIS_PROVIDER": "docker" if selected_provider == "local" else "local"}
    original_saved, original_inherited = dict(saved), dict(inherited)
    expected = {**inherited, **dev.resolve_config(saved, 5432, redis_port, 1025, "local", selected_provider)}
    plan = resolve(
        purpose="startup",
        inherited=inherited,
        saved=saved,
        ports=dev_config.ServicePorts(
            5432, redis_port, 1025, "local", selected_provider if explicit_selection else None
        ),
    )
    assert dict(plan.environment) == expected
    assert plan.environment["DEV_REDIS_PROVIDER"] == selected_provider
    assert plan.provenance["DEV_REDIS_PROVIDER"] == "selection.providers"
    assert saved == original_saved and inherited == original_inherited


@pytest.mark.parametrize(
    ("saved_provider", "selected_provider", "redis_port"),
    [("local", "docker", dev.REDIS_PORT), ("docker", "local", 6379), ("fixture-unknown-provider", "local", 6379)],
)
@pytest.mark.parametrize("explicit_selection", [False, True])
def test_managed_startup_refuses_redis_provider_change_without_mutating_snapshots(
    saved_provider, selected_provider, redis_port, explicit_selection
):
    saved = {
        "DATABASE_URL": LOCAL_URL,
        "DEV_POSTGRES_PROVIDER": "local",
        "DEV_REDIS_PROVIDER": saved_provider,
        "AUTH_SESSION_REDIS_URL": f"redis://fixture:{PASSWORD}@127.0.0.1:6379/1",
    }
    inherited = {"DEV_REDIS_PROVIDER": selected_provider, "PROCESS_ONLY": "unchanged"}
    original_saved, original_inherited = dict(saved), dict(inherited)
    with pytest.raises(dev_config.ConfigurationError) as caught:
        resolve(
            purpose="startup",
            inherited=inherited,
            saved=saved,
            ports=dev_config.ServicePorts(
                5432, redis_port, 1025, "local", selected_provider if explicit_selection else None
            ),
        )
    assert caught.value.code == "SETUP_REQUIRED"
    assert "Redis-provider change" in str(caught.value)
    assert PASSWORD not in str(caught.value) and PASSWORD not in repr(caught.value)
    assert saved["AUTH_SESSION_REDIS_URL"] not in str(caught.value)
    assert saved == original_saved and inherited == original_inherited


def test_managed_existing_inspection_preserves_saved_redis_provider_without_selecting_a_different_one():
    saved = {"DATABASE_URL": LOCAL_URL, "DEV_REDIS_PROVIDER": "docker"}
    plan = resolve(saved=saved, ports=dev_config.ServicePorts(5432, 6379, 1025, "local", "local"))
    assert dict(plan.environment) == saved
    assert plan.provenance["DEV_REDIS_PROVIDER"] == "managed"


def test_plan_and_nested_maps_are_immutable_and_detached_from_input():
    inherited = {"PATH": "initial-path"}
    saved = {"DATABASE_URL": LOCAL_URL, "NEXT_PUBLIC_AUTH_ENABLED": "true", "CUSTOM_SETTING": "initial"}
    plan = resolve(inherited=inherited, saved=saved)
    inherited["PATH"] = "changed"
    saved["CUSTOM_SETTING"] = "changed"
    assert plan.environment["PATH"] == "initial-path"
    assert plan.environment["CUSTOM_SETTING"] == "initial"
    with pytest.raises((FrozenInstanceError, AttributeError)):
        plan.profile = "greenfield"
    for mapping in (
        plan.environment,
        plan.provenance,
        plan.classification,
        plan.components,
        plan.components["frontend"],
    ):
        with pytest.raises(TypeError):
            mapping["FIXTURE"] = "changed"
    assert PASSWORD not in repr(plan)
    assert LOCAL_URL not in repr(plan)


def test_frontend_and_public_projections_allow_only_approved_values():
    saved = {
        "DATABASE_URL": LOCAL_URL,
        "NATIVE_JWT_PRIVATE_KEY": "fixture-signing-secret",
        "NATIVE_SECURITY_OUTBOX_KEY": "fixture-outbox-secret",
        "SMTP_PASSWORD": "fixture-smtp-secret",
        "AUTH_SESSION_ENCRYPTION_KEY": "fixture-session-secret",
        "AUTH_SESSION_REDIS_URL": "redis://127.0.0.1:6379/1",
        "NEXT_PUBLIC_AUTH_ENABLED": "true",
        "NEXT_PUBLIC_HCL_IAM_CLIENT_ID": "fixture-public-client",
        "NEXT_PUBLIC_UNREVIEWED_SECRET": "fixture-unreviewed-secret",
        "UNKNOWN_FUTURE_SETTING": "fixture-private-value",
    }
    plan = resolve(saved=saved)
    assert plan.classification["DATABASE_URL"] == "secret"
    assert plan.classification["NATIVE_JWT_PRIVATE_KEY"] == "secret"
    assert plan.classification["UNKNOWN_FUTURE_SETTING"] == "secret"
    assert plan.classification["NEXT_PUBLIC_UNREVIEWED_SECRET"] != "public"
    frontend = plan.components["frontend"]
    public = plan.components["public"]
    assert frontend["AUTH_SESSION_ENCRYPTION_KEY"] == saved["AUTH_SESSION_ENCRYPTION_KEY"]
    assert frontend["AUTH_SESSION_REDIS_URL"] == saved["AUTH_SESSION_REDIS_URL"]
    assert public["NEXT_PUBLIC_HCL_IAM_CLIENT_ID"] == "fixture-public-client"
    assert all(key.startswith("NEXT_PUBLIC_") for key in public)
    for key in (
        "DATABASE_URL",
        "NATIVE_JWT_PRIVATE_KEY",
        "NATIVE_SECURITY_OUTBOX_KEY",
        "SMTP_PASSWORD",
        "UNKNOWN_FUTURE_SETTING",
        "NEXT_PUBLIC_UNREVIEWED_SECRET",
    ):
        assert key not in frontend
        assert key not in public


@pytest.mark.parametrize(
    "settings",
    [
        {"AUTH_ENABLED": "false", "NATIVE_AUTH_ENABLED": "false", "HCL_AUTH_ENABLED": "false"},
        {"AUTH_ENABLED": "true", "NATIVE_AUTH_ENABLED": "true", "HCL_AUTH_ENABLED": "true"},
        {"AUTH_ENABLED": "true", "NATIVE_AUTH_ENABLED": "false", "HCL_AUTH_ENABLED": "true"},
    ],
)
def test_existing_mode_values_are_preserved_without_silent_conversion(settings):
    plan = resolve(saved={"DATABASE_URL": LOCAL_URL, **settings})
    for key, value in settings.items():
        assert plan.environment[key] == value
    assert plan.authentication_enabled is (settings["AUTH_ENABLED"] == "true")
    for name, key in (("native", "NATIVE_AUTH_ENABLED"), ("hclcs", "HCL_AUTH_ENABLED")):
        assert (name in plan.auth_modes) is (settings[key] == "true")


@pytest.mark.parametrize("platform", ["win32", "darwin", "linux"])
@pytest.mark.parametrize("companion_keys", [False, True])
def test_greenfield_snapshot_matches_existing_settings(tmp_path, monkeypatch, platform, companion_keys):
    state = tmp_path / "private-state"
    state.mkdir()
    root = tmp_path / "repository"
    inherited = {
        "PATH": "fixture-path",
        "HOME": "fixture-home",
        "TEMP": "fixture-temp",
        "SYSTEMROOT": "fixture-systemroot",
        "DATABASE_URL": "must-not-inherit",
        "NATIVE_JWT_PRIVATE_KEY": "must-not-inherit",
        "CUSTOM_AMBIENT_SECRET": "must-not-inherit",
    }
    provider_key = base64.urlsafe_b64encode(b"\xfb" * 32).decode()
    saved = {"CUSTOM_SAVED_SETTING": "preserved", "NATIVE_JWT_PRIVATE_KEY": "fixture-saved-signing-key"}
    if not companion_keys:
        saved.update(
            NATIVE_SECURITY_OUTBOX_KEY="fixture-saved-outbox", AI_CONFIG_ENCRYPTION_KEY="fixture-saved-provider"
        )
    files = {
        "environment.json": json.dumps(saved),
        "security-mail-key": "fixture-companion-outbox",
        "provider-storage-key": provider_key,
    }
    for name in files:
        (state / name).touch()
    reads = []

    def read_private(name):
        reads.append(name)
        return files[name]

    def runtime_url(user, filename, database="sbom_greenfield_uuid"):
        assert (user, filename, database) == ("greenfield_app", "runtime-password", "sbom_greenfield_uuid")
        return "postgresql+psycopg://greenfield_app:fixture-runtime-password@127.0.0.1:56044/sbom_greenfield_uuid"

    monkeypatch.setattr(dev.GreenfieldStack, "STATE", state)
    monkeypatch.setattr(dev.GreenfieldStack, "ROOT", root)
    monkeypatch.setattr(dev.GreenfieldStack, "read_private", staticmethod(read_private))
    monkeypatch.setattr(dev.GreenfieldStack, "url", staticmethod(runtime_url))
    monkeypatch.setattr(dev.os, "environ", dict(inherited))
    monkeypatch.setattr(dev.sys, "platform", platform)
    expected = dev.GreenfieldStack.settings()
    plan = resolve(
        profile="greenfield",
        inherited=inherited,
        saved=saved,
        root=str(root),
        platform=platform,
        greenfield=dev_config.GreenfieldInputs(
            state_root=str(state),
            runtime_password="fixture-runtime-password",
            security_mail_key="fixture-companion-outbox" if companion_keys else None,
            provider_storage_key=provider_key if companion_keys else None,
        ),
    )
    assert dict(plan.environment) == expected
    assert plan.database.name == "sbom_greenfield_uuid"
    assert plan.database.port == 56044
    assert plan.environment["REPORT_ARTIFACT_STORAGE_PATH"] == str(state / "reports")
    assert plan.environment["SBOM_WORKSPACE_STORAGE_DIR"] == str(state / "workspaces")
    assert "CUSTOM_AMBIENT_SECRET" not in plan.environment
    assert plan.environment["NATIVE_JWT_PRIVATE_KEY"] == "fixture-saved-signing-key"
    assert ("security-mail-key" in reads) is companion_keys


@pytest.mark.parametrize(
    "password",
    [
        "fixture password",
        "fixture+password",
        "fixture@password",
        "fixture:password",
        "fixture/password",
        "fixture +/@: password",
    ],
)
def test_greenfield_runtime_url_preserves_existing_sqlalchemy_password_encoding(monkeypatch, password):
    def read_private(filename):
        assert filename == "runtime-password"
        return password

    monkeypatch.setattr(dev.GreenfieldStack, "read_private", staticmethod(read_private))
    expected = dev.GreenfieldStack.url("greenfield_app", "runtime-password")
    plan = resolve(
        profile="greenfield",
        saved={"NATIVE_SECURITY_OUTBOX_KEY": "fixture-outbox", "AI_CONFIG_ENCRYPTION_KEY": "fixture-provider"},
        greenfield=dev_config.GreenfieldInputs("fixture-state", password),
    )
    assert plan.environment["DATABASE_URL"] == expected
    assert password not in repr(plan)


def test_greenfield_saved_json_null_is_refused_without_relaxing_its_existing_format():
    with pytest.raises(dev_config.ConfigurationError):
        resolve(
            profile="greenfield",
            saved={
                "NATIVE_SECURITY_OUTBOX_KEY": "fixture-outbox",
                "AI_CONFIG_ENCRYPTION_KEY": "fixture-provider",
                "CUSTOM_SETTING": None,
            },
            greenfield=dev_config.GreenfieldInputs("fixture-state", "fixture-password"),
        )


@pytest.mark.parametrize("family", ["managed", "env", "windows"])
@pytest.mark.parametrize("control", ["\r", "\n", "\t"])
def test_target_control_characters_are_refused_before_urlsplit_normalization(family, control):
    url = LOCAL_URL.replace("127.0.0.1", "127.0.0.1" + control)
    with pytest.raises(dev_config.ConfigurationError) as caught:
        resolve(family=family, saved={"DATABASE_URL": url})
    assert PASSWORD not in str(caught.value)


@pytest.mark.parametrize("family", ["managed", "env", "windows"])
def test_extra_leading_database_path_slash_is_refused(family):
    with pytest.raises(dev_config.ConfigurationError):
        resolve(family=family, saved={"DATABASE_URL": LOCAL_URL.replace("/sbom_analyser_dev", "//sbom_analyser_dev")})


@pytest.mark.parametrize("family", ["managed", "env", "windows"])
def test_zero_database_port_is_refused(family):
    with pytest.raises(dev_config.ConfigurationError):
        resolve(family=family, saved={"DATABASE_URL": LOCAL_URL.replace(":5432/", ":0/")})


@pytest.mark.parametrize("family", ["env", "windows"])
@pytest.mark.parametrize("suffix", ["?host=remote.invalid", "#fixture-fragment"])
def test_saved_legacy_target_identity_refuses_query_overrides_pending_review(family, suffix):
    with pytest.raises(dev_config.ConfigurationError):
        resolve(family=family, saved={"DATABASE_URL": LOCAL_URL + suffix})


def test_case_variant_names_are_refused_before_projection():
    with pytest.raises(dev_config.ConfigurationError):
        resolve(saved={"DATABASE_URL": LOCAL_URL, "NATIVE_AUTH_ENABLED": "true", "native_auth_enabled": "false"})


@pytest.mark.parametrize("value", [17, ["fixture"], "fixture\0value"])
def test_invalid_snapshot_values_are_refused_without_echoing_them(value):
    with pytest.raises(dev_config.ConfigurationError) as caught:
        resolve(saved={"DATABASE_URL": LOCAL_URL, "CUSTOM_SETTING": value})
    assert "fixture" not in str(caught.value)


def test_greenfield_inputs_do_not_reveal_companion_credentials_in_repr():
    inputs = dev_config.GreenfieldInputs(
        "fixture-state", "fixture-runtime-secret", "fixture-outbox-secret", "fixture-provider-secret"
    )
    assert "fixture-runtime-secret" not in repr(inputs)
    assert "fixture-outbox-secret" not in repr(inputs)
    assert "fixture-provider-secret" not in repr(inputs)


def test_resolution_uses_only_explicit_inputs_with_no_io_or_startup_imports(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Pure resolution attempted an ambient read, I/O or side effect")

    class ForbiddenEnvironment:
        __getitem__ = __iter__ = __len__ = get = items = keys = values = forbidden

    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "app" or name.startswith("app.") or name in {"psycopg", "sqlalchemy"}:
            forbidden()
        return original_import(name, *args, **kwargs)

    with monkeypatch.context() as guard:
        guard.setattr(os, "environ", ForbiddenEnvironment())
        guard.setattr(builtins, "open", forbidden)
        guard.setattr(builtins, "__import__", guarded_import)
        for method in (
            "open",
            "read_text",
            "read_bytes",
            "write_text",
            "write_bytes",
            "resolve",
            "stat",
            "exists",
            "mkdir",
        ):
            guard.setattr(Path, method, forbidden)
        guard.setattr(socket, "socket", forbidden)
        guard.setattr(socket, "create_connection", forbidden)
        for method in ("run", "Popen", "check_call", "check_output"):
            guard.setattr(subprocess, method, forbidden)
        assert dev_config.parse_managed("VALUE=${HOME}") == {"VALUE": "${HOME}"}
        assert dev_config.parse_windows("$env:VALUE = '${HOME}'") == {"VALUE": "${HOME}"}
        assert dev_config.parse_dotenv("VALUE=${HOME}") == {"VALUE": "${HOME}"}
        plan = resolve(saved={"DATABASE_URL": LOCAL_URL, "NATIVE_AUTH_ENABLED": "true"})
        assert plan.environment["DATABASE_URL"] == LOCAL_URL
        greenfield_plan = resolve(
            profile="greenfield",
            saved={"NATIVE_SECURITY_OUTBOX_KEY": "fixture-outbox", "AI_CONFIG_ENCRYPTION_KEY": "fixture-provider"},
            greenfield=dev_config.GreenfieldInputs("fixture-state", "fixture-runtime-password"),
        )
        assert greenfield_plan.database.name == "sbom_greenfield_uuid"
