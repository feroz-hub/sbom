"""Repository consumers and controlled setup after deleting old launchers."""

import ast
import json
import re
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest
from scripts import dev

ROOT = Path(__file__).resolve().parents[1]
RETIRED_MODULES = {
    "dev_runtime",
    "dev_greenfield",
    "greenfield_uuid",
    "greenfield_https",
    "greenfield_worker",
    "test_greenfield_setup",
}


@pytest.fixture(autouse=True)
def isolate_profile_globals(monkeypatch):
    monkeypatch.setattr(dev, "ACTIVE_PROFILE", "legacy")
    monkeypatch.setattr(dev, "ACTIVE_LEGACY_CONFIG", "managed")


def test_all_manifest_retirements_are_absent_and_single_manager_remains():
    report = (ROOT / "docs/engineering/dev-launcher-cleanup.md").read_text()
    section = report.split("### Deleted files", 1)[1].split("### Essential retained files", 1)[0]
    paths = re.findall(r"^- `([^`]+)`$", section, re.M)
    assert len(paths) == 51
    assert not [path for path in paths if (ROOT / path).exists()]
    assert (ROOT / "scripts/dev.py").is_file()
    assert not list((ROOT / "scripts").rglob("*.bat"))
    assert not list((ROOT / "scripts").rglob("*.ps1"))


def test_executable_consumers_have_no_deleted_imports_or_commands():
    paths = []
    for directory in ("scripts", "tests", "app", "infra", "docs/uat"):
        paths.extend((ROOT / directory).rglob("*.py"))
    violations = []
    for path in paths:
        if "before" in path.parts:
            continue  # Frozen application snapshots are historical evidence.
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module == "scripts" and any(alias.name in RETIRED_MODULES for alias in node.names):
                    violations.append(str(path.relative_to(ROOT)))
                if module.startswith("scripts.") and module.split(".")[1] in RETIRED_MODULES:
                    violations.append(str(path.relative_to(ROOT)))
            elif isinstance(node, ast.Import):
                if any(
                    alias.name.startswith("scripts.") and alias.name.split(".")[1] in RETIRED_MODULES
                    for alias in node.names
                ):
                    violations.append(str(path.relative_to(ROOT)))
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node.value in {"scripts." + module for module in RETIRED_MODULES}:
                    violations.append(str(path.relative_to(ROOT)))
    assert not violations


def test_production_consumers_remain_independent_of_local_manager():
    docker = (ROOT / "Dockerfile").read_text()
    assert 'CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]' in docker
    assert "run.py" not in docker and "scripts/dev.py" not in docker
    compose = (ROOT / "docker-compose.server.yml").read_text()
    assert "app.workers.celery_app" in compose
    assert "--queues=celery,reports" in compose
    assert "scripts.dev" not in compose
    for name in ("bootstrap_fresh_database.py", "docker_migrate.py"):
        assert (ROOT / "scripts" / name).is_file()
    npm = json.loads((ROOT / "frontend/package.json").read_text())["scripts"]
    assert "setup:https" not in npm and "setup:https:windows" not in npm


def test_help_requires_no_retired_modules_or_project_dependencies():
    result = subprocess.run(
        [sys.executable, "-S", str(ROOT / "scripts/dev.py"), "--help"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert "setup,start,stop,restart,status,diagnose,doctor,logs" in result.stdout


def test_optional_saved_backend_reload_uses_same_canonical_command():
    normal = dev.api_command({}, 18000)
    reload = dev.api_command({"RELOAD": "true"}, 18000)
    assert "--reload" not in normal
    assert reload[: len(normal)] == normal
    assert reload[len(normal) :] == ["--reload", "--reload-dir", str(dev.ROOT / "app")]
    assert normal[normal.index("--host") + 1] == "127.0.0.1"


def test_recorded_legacy_family_is_reused_and_mismatch_fails():
    state = {"profile": "legacy", "legacy_config": "windows"}
    assert dev.pin_legacy_configuration("auto", state) == "windows"
    with pytest.raises(dev.SetupError, match="configuration differs"):
        dev.pin_legacy_configuration("managed", state)


def test_explicit_status_uses_requested_profile_for_health_and_diagnostics(monkeypatch):
    services = {
        name: {"pid": 123} for name in ("API", "Frontend", "Celery worker", "Celery reports worker", "Celery Beat")
    }
    monkeypatch.setattr(dev.Runtime, "load", lambda _: {"services": services, "ready": True})
    monkeypatch.setattr(dev.Runtime, "service_status", lambda *args: "RUNNING")
    seen = []

    def environment(profile):
        seen.append((profile, dev.ACTIVE_PROFILE))
        raise dev.SetupError("synthetic unavailable dependency")

    monkeypatch.setattr(dev, "profile_environment", environment)
    assert dev.application_status("greenfield") is False
    assert seen == [("greenfield", "greenfield")]


@pytest.mark.parametrize("flag", ["--migrate", "--initialize-database", "--provision-greenfield"])
def test_schema_setup_refuses_running_managed_services(monkeypatch, flag):
    args = dev.parse_args(["setup", "--profile", "greenfield", flag, "--confirm-database", dev.GreenfieldStack.DB])
    args._setup_authorized_categories = frozenset({"database-migrate" if flag == "--migrate" else "database-initialize"})
    monkeypatch.setattr(dev.Runtime, "load", lambda _: {"services": {"API": {"pid": 123}}})
    forbidden = Mock(side_effect=AssertionError("provisioning reached"))
    monkeypatch.setattr(dev, "validate_prerequisites", forbidden)
    monkeypatch.setattr(dev.Runtime, "acquire", forbidden)
    with pytest.raises(dev.SetupError, match="verified-ownership stop"):
        dev._apply_setup_application(args)
    forbidden.assert_not_called()


def test_data_logs_use_exact_verified_identity(monkeypatch, capsys):
    args = dev.parse_args(["logs", "--profile", "greenfield", "--service", "redis"])
    inventory = Mock()
    monkeypatch.setattr(dev.GreenfieldProfile, "inventory", inventory)
    monkeypatch.setattr(
        dev.GreenfieldStack, "read_private", lambda _: json.dumps({"sbom-greenfield-uuid-dev-redis-1": "synthetic-id"})
    )
    monkeypatch.setattr(dev.GreenfieldStack, "docker_command", lambda: ["synthetic-docker"])
    monkeypatch.setattr(dev, "profile_environment", lambda _: {})
    command = Mock(return_value=Mock(returncode=0, stdout="test log", stderr=""))
    monkeypatch.setattr(dev, "run", command)
    dev.display_logs(args)
    inventory.assert_called_once()
    command.assert_called_once_with(["synthetic-docker", "logs", "--tail", "80", "synthetic-id"])
    assert "test log" in capsys.readouterr().out


def test_external_data_logs_do_not_guess_container_ownership(monkeypatch):
    args = dev.parse_args(["logs", "--profile", "legacy", "--service", "postgres"])
    monkeypatch.setattr(dev, "ACTIVE_LEGACY_CONFIG", "windows")
    with pytest.raises(dev.SetupError, match="externally managed"):
        dev.display_logs(args)
