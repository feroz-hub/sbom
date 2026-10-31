"""Public dispatch compatibility and read-only normalization, no service I/O."""

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev
from scripts import dev_workspace_cli as cli
from scripts import dev_workspace_control as control
from scripts import dev_workspace_observe as observe


def test_workspace_setup_check_is_normalized_before_any_mutable_dispatch(monkeypatch, tmp_path):
    called = Mock(return_value=1)
    forbidden = Mock(side_effect=AssertionError("check dispatched mutable preparation"))
    monkeypatch.setattr(control, "run_setup", called)
    monkeypatch.setattr(cli, "_prepare_registry", forbidden)
    assert cli.run_cli(["setup", "--check", "--mode", "mock", "--auth", "native"], tmp_path) == 1
    args, root = called.call_args.args
    assert args.check and args.command == "setup" and root == tmp_path
    forbidden.assert_not_called()


def test_workspace_setup_plan_is_readonly_check(monkeypatch, tmp_path):
    called = Mock(return_value=1)
    monkeypatch.setattr(control, "run_setup", called)
    assert cli.run_cli(["setup", "--plan"], tmp_path) == 1
    assert called.call_args.args[0].check is True


def test_prepare_check_with_mutation_scope_never_enters_preparation(monkeypatch, tmp_path, capsys):
    forbidden = Mock(side_effect=AssertionError("check invoked a writer"))
    monkeypatch.setattr(cli, "_prepare_dependencies", forbidden)
    assert cli.run_cli(["prepare", "--check", "--scope", "dependencies", "--json"], tmp_path) == 1
    assert "WORKSPACE_READ_ONLY_OPTIONS_REQUIRED" in capsys.readouterr().out
    forbidden.assert_not_called()


def test_doctor_alias_deprecates_and_calls_diagnose_inventory(monkeypatch, tmp_path, capsys):
    inventory = Mock(return_value=1)
    monkeypatch.setattr(cli, "selected_instance", Mock(return_value=None))
    monkeypatch.setattr(cli, "_inventory", inventory)
    assert cli.run_cli(["doctor", "--json"], tmp_path) == 1
    assert inventory.call_args.kwargs["diagnostic"] and inventory.call_args.kwargs["inspect_software"]
    assert "use diagnose" in capsys.readouterr().err


@pytest.fixture
def automatic(monkeypatch):
    library = SimpleNamespace(fresh_checkout=Mock(return_value=True), selected_instance=Mock(return_value=object()))
    monkeypatch.setattr(dev, "_workspace_library", lambda: library)
    return library


@pytest.mark.parametrize(
    "arguments",
    [
        ["setup", "--profile", "legacy"],
        ["setup", "--profile", "greenfield"],
        ["setup", "--legacy-config", "managed"],
        ["setup", "--initialize-database", "--profile", "legacy"],
    ],
)
def test_explicit_existing_profile_and_database_actions_keep_approved_dispatch(automatic, arguments):
    assert dev.workspace_auto_arguments(dev.parse_args(arguments)) is None
    automatic.fresh_checkout.assert_not_called()


@pytest.mark.parametrize(
    "arguments,expected",
    [
        (["setup"], ["setup"]),
        (["setup", "--plan"], ["setup", "--check"]),
        (["setup", "--check"], ["setup", "--check"]),
        (["diagnose"], ["diagnose"]),
        (["doctor"], ["doctor"]),
        (["start"], ["start"]),
        (["stop"], ["stop"]),
        (["restart"], ["restart"]),
        (["status"], ["status"]),
        (["logs"], ["logs", "--lines", "80", "--service", "all"]),
    ],
)
def test_fresh_or_prepared_workspace_uses_single_launcher_commands(automatic, arguments, expected):
    assert dev.workspace_auto_arguments(dev.parse_args(arguments)) == expected


def test_unknown_registration_does_not_fall_back_or_expose_exception(automatic):
    error = ValueError("credential must never appear")
    error.code = "REGISTRY_UNKNOWN_ARTIFACT"
    automatic.selected_instance.side_effect = error
    with pytest.raises(dev.SetupError, match="^REGISTRY_UNKNOWN_ARTIFACT") as caught:
        dev.workspace_auto_arguments(dev.parse_args(["start"]))
    assert "credential" not in str(caught.value)


def test_old_host_uses_existing_prerequisite_diagnostics_before_new_modules(automatic, monkeypatch):
    monkeypatch.setattr(dev.sys, "version_info", (3, 9, 6))
    assert dev.workspace_auto_arguments(dev.parse_args(["diagnose"])) is None
    automatic.fresh_checkout.assert_not_called()


@pytest.mark.parametrize("command", ["start", "stop", "restart", "status", "diagnose"])
def test_known_instance_cannot_fall_back_after_source_or_home_config_appears(automatic, command):
    automatic.fresh_checkout.return_value = False
    assert dev.workspace_auto_arguments(dev.parse_args([command])) == [command]


@pytest.mark.parametrize("flag", ["--migrate", "--repair-dependencies", "--initialize-database", "--native-admin-create"])
def test_known_instance_refuses_implicit_legacy_preparation_or_admin_flags(automatic, flag):
    with pytest.raises(dev.SetupError, match="^WORKSPACE_PROFILE_CONVERSION_REFUSED"):
        dev.workspace_auto_arguments(dev.parse_args(["setup", flag]))


def test_unregistered_existing_profile_keeps_original_dispatch(automatic):
    automatic.selected_instance.return_value = None
    automatic.fresh_checkout.return_value = False
    assert dev.workspace_auto_arguments(dev.parse_args(["start"])) is None


def test_prepared_noargs_start_requires_control_verification(automatic, monkeypatch):
    automatic.run_cli = Mock(return_value=1)
    monkeypatch.setattr(dev.sys, "argv", ["dev.py"])
    assert dev.main() == 1
    automatic.run_cli.assert_called_once_with(["start"], dev.ROOT)


def test_existing_greenfield_presence_is_not_converted(tmp_path, monkeypatch):
    home, checkout = tmp_path / "home", tmp_path / "checkout"
    home.mkdir()
    checkout.mkdir()
    (home / ".sbom-greenfield-uuid").mkdir()
    monkeypatch.setattr(cli.Path, "home", classmethod(lambda cls: home))
    assert cli.fresh_checkout(checkout) is False


def test_all_logs_use_fixed_component_metadata_only(tmp_path, monkeypatch, capsys):
    descriptor = SimpleNamespace(instance_id="e90fa8f0-db52-599b-856f-df5e666ed48e")
    monkeypatch.setattr(cli, "_registered_instance", lambda *_: (None, None, SimpleNamespace(descriptor=descriptor)))
    calls = []

    def observed(instance, component, **options):
        assert instance == descriptor.instance_id and options == {"max_lines": 80}
        calls.append(component)
        return SimpleNamespace(status="SKIPPED", local_path=None, to_dict=lambda: {"component": component})

    monkeypatch.setattr(observe, "observe_logs", observed)
    assert cli.run_cli(["logs", "--service", "all", "--json"], tmp_path) == 0
    assert calls == ["api", "frontend", "worker", "reports", "beat", "postgres", "redis", "mailpit", "setup"]
    assert len(capsys.readouterr().out.splitlines()) == 9


@pytest.mark.parametrize("command", ["status", "logs"])
def test_readonly_top_level_control_creates_no_import_caches(tmp_path, command):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "dev.py").write_bytes(Path(dev.__file__).read_bytes())
    (scripts / "dev_workspace_cli.py").write_text(
        "import sys\n"
        "def fresh_checkout(root): return True\n"
        "def selected_instance(root): return object()\n"
        "def run_cli(args,root):\n"
        " assert sys.dont_write_bytecode\n"
        " assert args[0] in {'status','logs'}\n"
        " return 0\n",
        encoding="utf-8",
    )
    before = {path.relative_to(tmp_path): path.read_bytes() for path in scripts.iterdir()}
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHONDONTWRITEBYTECODE", "PYTHONPATH", "PYTHONHOME", "PYTHONPYCACHEPREFIX"}
    }
    result = subprocess.run(
        [sys.executable, "-S", str(scripts / "dev.py"), command],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 0
    after = {path.relative_to(tmp_path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    assert after == before
