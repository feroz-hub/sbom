"""Real Settings source selection and pure TS namespace, never application startup."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from app import settings
from app.dev_instance import InstanceNamespaceError, get_instance_namespace
from scripts import dev_config

FIRST = "f8cf338c-4696-5862-b36d-989ad012ac79"
SECOND = "bb1c44d6-283e-548d-936e-0b42c29651cf"


@pytest.fixture(autouse=True)
def isolated_cache(monkeypatch):
    settings.reset_settings()
    monkeypatch.delenv("SBOM_DEV_RESOURCE_ID", raising=False)
    monkeypatch.setenv("DEV_DEFAULT_TENANT", "false")
    yield
    settings.reset_settings()


def test_real_pydantic_dotenv_is_disabled_for_isolated_child_only(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("AUTH_ENABLED=false\n", encoding="utf-8")
    monkeypatch.delenv("AUTH_ENABLED", raising=False)
    monkeypatch.setenv("APP_ENVIRONMENT", "development")
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")
    # Pydantic's .env source ignores python-dotenv's disable environment flag.
    assert settings.get_settings().auth_enabled is False
    settings.reset_settings()
    monkeypatch.setenv("SBOM_DEV_RESOURCE_ID", FIRST)
    assert settings.get_settings().auth_enabled is True
    assert (tmp_path / ".env").read_text(encoding="utf-8") == "AUTH_ENABLED=false\n"


@pytest.mark.parametrize("environment", [None, "test", "staging", "production"])
def test_isolated_settings_require_explicit_development_mode(monkeypatch, environment):
    monkeypatch.setenv("SBOM_DEV_RESOURCE_ID", FIRST)
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")
    if environment is None:
        monkeypatch.delenv("APP_ENVIRONMENT", raising=False)
    else:
        monkeypatch.setenv("APP_ENVIRONMENT", environment)
    with pytest.raises(InstanceNamespaceError, match="^DEV_INSTANCE_ENVIRONMENT_UNVERIFIED$"):
        settings.get_settings()


def test_disabled_dotenv_flag_and_cache_binding_are_required(monkeypatch):
    monkeypatch.setenv("SBOM_DEV_RESOURCE_ID", FIRST)
    monkeypatch.setenv("APP_ENVIRONMENT", "development")
    monkeypatch.delenv("PYTHON_DOTENV_DISABLED", raising=False)
    with pytest.raises(InstanceNamespaceError):
        settings.get_settings()
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")
    first = settings.get_settings()
    assert settings.get_settings() is first
    monkeypatch.setenv("SBOM_DEV_RESOURCE_ID", SECOND)
    with pytest.raises(InstanceNamespaceError):
        settings.get_settings()
    monkeypatch.delenv("SBOM_DEV_RESOURCE_ID")
    with pytest.raises(InstanceNamespaceError):
        settings.get_settings()


def test_resource_metadata_is_server_only_and_not_secret_projection():
    environment = {"SBOM_DEV_RESOURCE_ID": FIRST, "DATABASE_URL": "synthetic-private-value"}
    assert dev_config.component_environment(environment, "frontend")["SBOM_DEV_RESOURCE_ID"] == FIRST
    assert "DATABASE_URL" not in dev_config.component_environment(environment, "frontend")
    assert "SBOM_DEV_RESOURCE_ID" not in dev_config.component_environment(environment, "public")
    for bad in ("", FIRST.upper(), "not-a-uuid"):
        with pytest.raises(dev_config.ConfigurationError, match="DEV_INSTANCE_RESOURCE_ID_INVALID"):
            dev_config.component_environment({"SBOM_DEV_RESOURCE_ID": bad}, "frontend")


@pytest.mark.parametrize("field", ["AUTH_ENABLED", "DEV_DEFAULT_TENANT"])
def test_isolated_settings_cannot_enable_development_auth_bypass(monkeypatch, field):
    monkeypatch.setenv("SBOM_DEV_RESOURCE_ID", FIRST)
    monkeypatch.setenv("APP_ENVIRONMENT", "development")
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")
    monkeypatch.setenv(field, "false" if field == "AUTH_ENABLED" else "true")
    with pytest.raises(InstanceNamespaceError, match="^DEV_INSTANCE_ENVIRONMENT_UNVERIFIED$"):
        settings.get_settings()


def test_actual_typescript_session_namespace_matches_python_without_backend_imports():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node unavailable; no install attempted")
    source = Path(__file__).resolve().parents[1] / "frontend/src/lib/auth/instance-namespace.ts"
    values = [
        {},
        {"SBOM_DEV_RESOURCE_ID": FIRST},
        {"SBOM_DEV_RESOURCE_ID": SECOND},
        {"SBOM_DEV_RESOURCE_ID": ""},
        {"SBOM_DEV_RESOURCE_ID": FIRST.upper()},
        {"sbom_dev_resource_id": FIRST},
    ]
    program = """
import { pathToFileURL } from 'node:url';
const { sessionNamespace } = await import(pathToFileURL(process.argv[1]).href);
console.log(JSON.stringify(JSON.parse(process.argv[2]).map(value => {
  try { return sessionNamespace(value); } catch (error) { return error.message; }
})));
"""
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"}
    }
    child = subprocess.run(
        [node, "--experimental-strip-types", "--input-type=module", "-e", program, str(source), json.dumps(values)],
        env=environment,
        cwd=source.parent,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert child.returncode == 0
    observed = json.loads(child.stdout)
    assert observed[:3] == [get_instance_namespace(value).session_namespace for value in values[:3]]
    assert observed[3:] == ["DEV_INSTANCE_RESOURCE_ID_INVALID"] * 3
