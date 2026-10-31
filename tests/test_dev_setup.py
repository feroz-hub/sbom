"""Controlled setup planning/authorization with synthetic files; use --noconftest."""

from __future__ import annotations

import builtins
import hashlib
import json
import os
import socket
import subprocess
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev, dev_setup

SECRET = "fixture-setup-secret-never-log"
DATABASE_URL = f"postgresql+psycopg://postgres:{SECRET}@127.0.0.1:5432/sbom_analyser_dev"
MARKER = "_SBOM_DEV_SETUP_APPROVAL"
FINGERPRINT = "a" * 64
MANAGED_MODE_CONFLICTS = [
    *(("NATIVE_AUTH_ENABLED", value) for value in ("false", "0", "no", "off", "unknown")),
    *(("AUTH_ENABLED", value) for value in ("false", "0", "no", "off", "unknown")),
    *(("HCL_AUTH_ENABLED", value) for value in ("true", "1", "yes", "on", "unknown")),
    *(("ENTRA_ENABLED", value) for value in ("true", "1", "yes", "on", "unknown")),
    *(("DEV_DEFAULT_TENANT", value) for value in ("true", "1", "yes", "on", "unknown")),
]


@pytest.fixture
def checkout(monkeypatch, tmp_path):
    root, home = tmp_path / "checkout", tmp_path / "home"
    root.mkdir()
    home.mkdir()
    for name in dev.REQUIRED_FILES:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}" if path.suffix == ".json" else "fixture manifest\n", encoding="utf-8")
    monkeypatch.setattr(dev, "ROOT", root)
    monkeypatch.setattr(dev, "VENV", root / ".venv")
    monkeypatch.setattr(dev, "CONFIG", root / ".env.dev.local")
    monkeypatch.setattr(dev, "BEAT_LOCK", root / ".dev-beat.pid")
    monkeypatch.setattr(dev.GreenfieldStack, "ROOT", root)
    monkeypatch.setattr(dev.GreenfieldStack, "STATE", home / ".sbom-greenfield-uuid")
    monkeypatch.setattr(dev.LocalHttps, "local_ca", lambda: home / "fixture-root-ca.pem")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setattr(os, "environ", {"APP_ENVIRONMENT": "development", "HOME": str(home), "USERPROFILE": str(home)})
    return root, home


def file_snapshot(root):
    return {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def setup_args(**overrides):
    values = {
        "command": "setup",
        "profile": "legacy",
        "legacy_config": "managed",
        "plan": False,
        "check": False,
        "verbose": False,
        "initialize_database": False,
        "migrate": False,
        "provision_greenfield": False,
        "frontend_build": False,
        "confirm_database": None,
        "postgres_provider": None,
        "redis_provider": None,
        "mailpit_provider": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def forbid_mutators(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("setup inspection or refused approval attempted mutation"))
    for name in (
        "ensure_virtualenv",
        "ensure_dependencies",
        "ensure_frontend",
        "generate_keys",
        "write_config",
        "ensure_database",
        "configure_local_database",
        "prepare_managed_legacy",
        "run_migrations",
        "start_process",
        "start_background",
        "atomic_json",
        "create_local_certificate",
    ):
        monkeypatch.setattr(dev, name, forbidden)
    monkeypatch.setattr(dev.GreenfieldStack, "provision", forbidden)
    monkeypatch.setattr(dev.GreenfieldStack, "bootstrap", forbidden)
    monkeypatch.setattr(dev.Runtime, "acquire", forbidden)
    monkeypatch.setattr(dev.Runtime, "refresh", forbidden)
    monkeypatch.setattr(dev.Runtime, "terminate", forbidden)
    monkeypatch.setattr(dev.Runtime, "stop_services", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    return forbidden


def planned(*categories, blockers=(), fingerprint=FINGERPRINT):
    return dev_setup.SetupPlan(
        profile="legacy",
        family="managed",
        actions=tuple(dev_setup.SetupAction(category, "A reviewed fixture action.") for category in categories),
        blockers=tuple(blockers),
        fingerprint=fingerprint,
    )


def interactive(monkeypatch, enabled=True):
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: enabled))


def test_setup_plan_is_frozen_and_fingerprint_is_not_rendered():
    action = dev_setup.SetupAction("project-dependencies", "A reviewed fixture action.")
    plan = dev_setup.SetupPlan("legacy", "managed", (action,), (), FINGERPRINT)
    assert FINGERPRINT not in repr(plan)
    with pytest.raises((FrozenInstanceError, AttributeError)):
        plan.profile = "greenfield"
    with pytest.raises((FrozenInstanceError, AttributeError)):
        action.category = "secrets"


def test_plan_only_never_prompts_applies_or_changes_files(checkout, monkeypatch, capsys):
    root, home = checkout
    (root / "preserved-file").write_bytes(b"fixture-preserved")
    before = file_snapshot(root), file_snapshot(home)
    monkeypatch.setattr(
        dev_setup, "inspect_setup", lambda args, launcher: planned("project-dependencies", "certificates")
    )
    forbidden = Mock(side_effect=AssertionError("--plan attempted authorization or application"))
    monkeypatch.setattr(builtins, "input", forbidden)
    assert dev_setup.run_setup(setup_args(plan=True), dev, forbidden) == 0
    assert (file_snapshot(root), file_snapshot(home)) == before
    assert MARKER not in os.environ
    output = capsys.readouterr()
    assert FINGERPRINT not in output.out + output.err
    forbidden.assert_not_called()


def test_blocked_plan_never_requests_authorization_or_applies(checkout, monkeypatch, capsys):
    monkeypatch.setattr(
        dev_setup,
        "inspect_setup",
        lambda args, launcher: planned("project-dependencies", blockers=("CONFIGURATION_REVIEW_REQUIRED",)),
    )
    interactive(monkeypatch)
    forbidden = Mock(side_effect=AssertionError("blocked plan requested approval or applied changes"))
    monkeypatch.setattr(builtins, "input", forbidden)
    assert dev_setup.run_setup(setup_args(), dev, forbidden) == 1
    output = capsys.readouterr()
    assert "CONFIGURATION_REVIEW_REQUIRED" in output.out + output.err
    forbidden.assert_not_called()


def test_noninteractive_setup_requires_approval_without_prompting_or_applying(checkout, monkeypatch, capsys):
    root, home = checkout
    before = file_snapshot(root), file_snapshot(home)
    monkeypatch.setattr(dev_setup, "inspect_setup", lambda args, launcher: planned("project-dependencies"))
    interactive(monkeypatch, False)
    forbidden = Mock(side_effect=AssertionError("noninteractive setup attempted prompt or mutation"))
    monkeypatch.setattr(builtins, "input", forbidden)
    assert dev_setup.run_setup(setup_args(), dev, forbidden) == 1
    assert (file_snapshot(root), file_snapshot(home)) == before
    output = capsys.readouterr()
    assert "APPROVAL_REQUIRED" in output.out + output.err
    forbidden.assert_not_called()


@pytest.mark.parametrize("answer", ["no", "", "y", "anything", "no thanks"])
def test_every_non_yes_answer_declines_without_partial_application(checkout, monkeypatch, answer):
    root, home = checkout
    before = file_snapshot(root), file_snapshot(home)
    monkeypatch.setattr(
        dev_setup, "inspect_setup", lambda args, launcher: planned("project-dependencies", "certificates")
    )
    interactive(monkeypatch)
    prompt = Mock(side_effect=["yes", answer])
    monkeypatch.setattr(builtins, "input", prompt)
    apply = Mock(side_effect=AssertionError("declined category caused partial setup application"))
    assert dev_setup.run_setup(setup_args(), dev, apply) == 1
    assert prompt.call_count == 2
    assert (file_snapshot(root), file_snapshot(home)) == before
    assert MARKER not in os.environ
    apply.assert_not_called()


@pytest.mark.parametrize("cancellation", [EOFError, KeyboardInterrupt])
def test_cancelled_authorization_preserves_files_and_returns_130(checkout, monkeypatch, cancellation):
    root, home = checkout
    before = file_snapshot(root), file_snapshot(home)
    monkeypatch.setattr(dev_setup, "inspect_setup", lambda args, launcher: planned("project-dependencies"))
    interactive(monkeypatch)
    monkeypatch.setattr(builtins, "input", Mock(side_effect=cancellation))
    apply = Mock(side_effect=AssertionError("cancelled setup applied changes"))
    assert dev_setup.run_setup(setup_args(), dev, apply) == 130
    assert (file_snapshot(root), file_snapshot(home)) == before
    assert MARKER not in os.environ
    apply.assert_not_called()


@pytest.mark.parametrize("change", ["fingerprint", "new-category", "blocker"])
def test_setup_revalidates_after_consent_and_refuses_drift(checkout, monkeypatch, change):
    initial = planned("project-dependencies")
    changed = (
        planned("project-dependencies", fingerprint="b" * 64)
        if change == "fingerprint"
        else planned("project-dependencies", "secrets")
        if change == "new-category"
        else planned("project-dependencies", blockers=("NEW_REVIEW_REQUIRED",))
    )
    inspect = Mock(side_effect=[initial, changed])
    monkeypatch.setattr(dev_setup, "inspect_setup", inspect)
    interactive(monkeypatch)
    monkeypatch.setattr(builtins, "input", lambda prompt: "yes")
    apply = Mock(side_effect=AssertionError("setup applied a plan different from the authorized plan"))
    assert dev_setup.run_setup(setup_args(), dev, apply) == 1
    assert inspect.call_count == 2
    assert MARKER not in os.environ
    apply.assert_not_called()


def test_all_categories_require_consent_before_single_apply_and_authority_is_scoped(checkout, monkeypatch):
    plan = planned("project-dependencies", "certificates")
    inspect = Mock(return_value=plan)
    monkeypatch.setattr(dev_setup, "inspect_setup", inspect)
    monkeypatch.setattr(sys, "prefix", str(dev.VENV))
    interactive(monkeypatch)
    prompt = Mock(side_effect=["yes", "YES"])
    monkeypatch.setattr(builtins, "input", prompt)
    args = setup_args()
    previous = frozenset({"fixture-prior-authority"})
    args._setup_authorized_categories = previous

    def apply(actual):
        assert actual is args
        assert prompt.call_count == 2
        assert actual._setup_authorized_categories == frozenset({"project-dependencies", "certificates"})
        assert MARKER not in os.environ

    callback = Mock(side_effect=apply)
    assert dev_setup.run_setup(args, dev, callback) == 0
    assert inspect.call_count == 2
    callback.assert_called_once_with(args)
    assert args._setup_authorized_categories is previous
    assert MARKER not in os.environ


def test_already_prepared_plan_needs_no_prompt_or_application(checkout, monkeypatch):
    monkeypatch.setattr(dev_setup, "inspect_setup", lambda args, launcher: planned())
    interactive(monkeypatch, False)
    forbidden = Mock(side_effect=AssertionError("an unchanged setup requested consent or preparation"))
    monkeypatch.setattr(builtins, "input", forbidden)
    assert dev_setup.run_setup(setup_args(), dev, forbidden) == 0
    forbidden.assert_not_called()


@pytest.mark.parametrize("lineage", ["same-pid", "immediate-parent"])
def test_handoff_approval_is_bound_to_current_plan_and_process_lineage_and_consumed(checkout, monkeypatch, lineage):
    plan = planned("project-dependencies")
    monkeypatch.setattr(os, "getpid", lambda: 111)
    monkeypatch.setattr(os, "getppid", lambda: 222)
    monkeypatch.setattr(sys, "prefix", str(dev.VENV))
    parent_pid = 111 if lineage == "same-pid" else 222
    os.environ[MARKER] = json.dumps(
        {"fingerprint": FINGERPRINT, "categories": ["project-dependencies", "certificates"], "parent_pid": parent_pid}
    )

    def inspect(args, launcher):
        assert MARKER not in os.environ, "An inherited internal approval was not consumed before inspection"
        return plan

    monkeypatch.setattr(dev_setup, "inspect_setup", inspect)
    interactive(monkeypatch, False)
    prompt = Mock(side_effect=AssertionError("valid venv handoff prompted for authorization again"))
    monkeypatch.setattr(builtins, "input", prompt)
    args = setup_args()

    def apply(actual):
        assert MARKER not in os.environ
        assert actual._setup_authorized_categories == frozenset({"project-dependencies"})

    callback = Mock(side_effect=apply)
    assert dev_setup.run_setup(args, dev, callback) == 0
    callback.assert_called_once_with(args)
    assert not hasattr(args, "_setup_authorized_categories")
    assert MARKER not in os.environ
    prompt.assert_not_called()


@pytest.mark.parametrize("lineage", ["redirector", "other-image", "not-windows", "outside-venv", "not-descendant", "error"])
def test_windows_venv_redirector_handoff_keeps_grandparent_consent_only_through_project_redirector(
    checkout, monkeypatch, capsys, lineage
):
    # Integration review: .venv\Scripts\python.exe runs the base interpreter as its child.
    monkeypatch.setattr(os, "getpid", lambda: 111)
    monkeypatch.setattr(os, "getppid", lambda: 222)
    monkeypatch.setattr(sys, "platform", "linux" if lineage == "not-windows" else "win32")
    if lineage != "outside-venv":
        monkeypatch.setattr(sys, "prefix", str(dev.VENV))
    redirector = str(dev.venv_python()) if lineage != "other-image" else str(dev.ROOT / "other" / "python.exe")
    descendants = [
        {"pid": 333, "birth": "1", "exe": "C:/Python/python.exe"},
        {"pid": 222, "birth": "2", "exe": redirector},
        *([] if lineage == "not-descendant" else [{"pid": 111, "birth": "3", "exe": "C:/Python/python.exe"}]),
    ]
    children = Mock(side_effect=dev.OwnershipError("fixture") if lineage == "error" else None, return_value=descendants)
    monkeypatch.setattr(dev, "windows_children", children)
    os.environ[MARKER] = json.dumps(
        {"fingerprint": FINGERPRINT, "categories": ["project-dependencies"], "parent_pid": 333}
    )
    monkeypatch.setattr(dev_setup, "inspect_setup", lambda args, launcher: planned("project-dependencies"))
    interactive(monkeypatch, False)
    monkeypatch.setattr(builtins, "input", Mock(side_effect=AssertionError("handoff prompted again")))
    callback = Mock(return_value=0)
    accepted = lineage == "redirector"
    assert dev_setup.run_setup(setup_args(), dev, callback) == (0 if accepted else 1)
    assert callback.call_count == int(accepted)
    assert MARKER not in os.environ
    if not accepted:
        assert "SETUP_APPROVAL_INVALID" in capsys.readouterr().out
    if lineage in {"not-windows", "outside-venv"}:
        children.assert_not_called()


@pytest.mark.parametrize("invalid", ["json", "pid", "fingerprint", "categories-type", "missing-category"])
def test_invalid_or_stale_handoff_authority_is_refused_without_echoing_payload(checkout, monkeypatch, capsys, invalid):
    monkeypatch.setattr(os, "getpid", lambda: 111)
    monkeypatch.setattr(os, "getppid", lambda: 222)
    payload = {"fingerprint": FINGERPRINT, "categories": ["project-dependencies"], "parent_pid": 111}
    if invalid == "pid":
        payload["parent_pid"] = 999
    elif invalid == "fingerprint":
        payload["fingerprint"] = SECRET
    elif invalid == "categories-type":
        payload["categories"] = "project-dependencies"
    elif invalid == "missing-category":
        payload["categories"] = []
    os.environ[MARKER] = SECRET if invalid == "json" else json.dumps(payload)
    monkeypatch.setattr(dev_setup, "inspect_setup", lambda args, launcher: planned("project-dependencies"))
    interactive(monkeypatch, False)
    forbidden = Mock(side_effect=AssertionError("invalid internal approval triggered prompt or mutation"))
    monkeypatch.setattr(builtins, "input", forbidden)
    assert dev_setup.run_setup(setup_args(), dev, forbidden) == 1
    assert MARKER not in os.environ
    output = capsys.readouterr()
    assert "APPROVAL_INVALID" in output.out + output.err
    assert SECRET not in output.out + output.err
    forbidden.assert_not_called()


def test_venv_handoff_marker_is_temporary_and_contains_only_plan_authority(checkout, monkeypatch):
    plan = planned("project-dependencies")
    monkeypatch.setattr(dev_setup, "inspect_setup", lambda args, launcher: plan)
    monkeypatch.setattr(sys, "prefix", str(dev.ROOT / "other-python"))
    interactive(monkeypatch)
    monkeypatch.setattr(builtins, "input", lambda prompt: "yes")
    args = setup_args()

    def apply(actual):
        payload = json.loads(os.environ[MARKER])
        assert set(payload) == {"fingerprint", "categories", "parent_pid"}
        assert payload["fingerprint"] == FINGERPRINT
        assert payload["categories"] == ["project-dependencies"]
        assert payload["parent_pid"] == os.getpid()
        assert SECRET not in json.dumps(payload)
        assert actual._setup_authorized_categories == frozenset({"project-dependencies"})

    callback = Mock(side_effect=apply)
    assert dev_setup.run_setup(args, dev, callback) == 0
    callback.assert_called_once_with(args)
    assert MARKER not in os.environ
    assert not hasattr(args, "_setup_authorized_categories")


@pytest.mark.parametrize("malformed", [False, True])
def test_uncertain_runtime_and_lock_records_are_preserved_without_control(checkout, monkeypatch, malformed):
    root, _ = checkout
    value = {
        "version": 1,
        "root": str(root.resolve()),
        "profile": "legacy",
        "legacy_config": "managed",
        "instance": "fixture-instance",
        "launcher_pid": 999,
        "services": {
            "API": {"pid": 4321, "birth": None, "exe": None, "members": [], "tree_unverified": True},
        },
    }
    (root / ".dev-runtime.json").write_text(
        "invalid fixture JSON" if malformed else json.dumps(value), encoding="utf-8"
    )
    (root / ".dev-runtime.lock").write_bytes(b"fixture-existing-lock")
    (root / ".dev-runtime.stop").write_bytes(b"fixture-existing-stop-request")
    before = file_snapshot(root)
    forbidden = forbid_mutators(monkeypatch)
    plan = dev_setup.inspect_setup(setup_args(), dev)
    assert plan.blockers
    assert file_snapshot(root) == before
    forbidden.assert_not_called()


def test_greenfield_wrong_database_confirmation_precedes_provisioning(checkout, monkeypatch):
    root, home = checkout
    before = file_snapshot(root), file_snapshot(home)
    forbidden = forbid_mutators(monkeypatch)
    plan = dev_setup.inspect_setup(
        setup_args(profile="greenfield", provision_greenfield=True, confirm_database="wrong_fixture_database"), dev
    )
    assert any("DATABASE_CONFIRMATION_REQUIRED" in blocker for blocker in plan.blockers)
    assert (file_snapshot(root), file_snapshot(home)) == before
    assert not dev.GreenfieldStack.STATE.exists()
    forbidden.assert_not_called()


def test_real_inspection_of_fresh_checkout_is_readonly_and_does_not_invent_secrets(checkout, monkeypatch, capsys):
    root, home = checkout
    before = file_snapshot(root), file_snapshot(home)
    forbidden = forbid_mutators(monkeypatch)
    plan = dev_setup.inspect_setup(setup_args(), dev)
    assert plan.profile == "legacy" and plan.family == "managed"
    assert plan.actions
    assert (file_snapshot(root), file_snapshot(home)) == before
    assert not dev.CONFIG.exists()
    assert not dev.VENV.exists()
    assert not dev.GreenfieldStack.STATE.exists()
    assert SECRET not in repr(plan)
    output = capsys.readouterr()
    assert SECRET not in output.out + output.err
    forbidden.assert_not_called()


@pytest.mark.parametrize("flag", ["initialize_database", "migrate"])
def test_wrong_database_confirmation_blocks_inspection_before_any_mutator(checkout, monkeypatch, flag):
    root, _ = checkout
    dev.CONFIG.write_text("DATABASE_URL=" + json.dumps(DATABASE_URL) + "\n", encoding="utf-8")
    before = file_snapshot(root)
    forbidden = forbid_mutators(monkeypatch)
    plan = dev_setup.inspect_setup(setup_args(**{flag: True, "confirm_database": "wrong_fixture_database"}), dev)
    assert any("DATABASE_CONFIRMATION_REQUIRED" in blocker for blocker in plan.blockers)
    assert file_snapshot(root) == before
    forbidden.assert_not_called()


@pytest.mark.parametrize(
    "environment",
    [
        {"APP_ENVIRONMENT": "production"},
        {"APP_ENVIRONMENT": "staging"},
        {"APP_ENVIRONMENT": "development", "APP_ENV": "production"},
    ],
)
def test_deployment_environment_or_alias_conflict_is_never_prepared(checkout, monkeypatch, environment):
    root, _ = checkout
    monkeypatch.setattr(os, "environ", environment)
    forbidden = forbid_mutators(monkeypatch)
    plan = dev_setup.inspect_setup(setup_args(), dev)
    assert plan.blockers
    assert not dev.CONFIG.exists()
    forbidden.assert_not_called()


@pytest.mark.parametrize(
    "extra",
    [
        {"NATIVE_JWT_PRIVATE_KEY": "fixture-existing-private-key"},
        {"NATIVE_JWT_PUBLIC_KEY": "fixture-existing-public-key"},
        {"NATIVE_SECURITY_OUTBOX_KEY": "fixture-existing-outbox"},
        {"AUTH_SESSION_ENCRYPTION_KEY": "fixture-existing-session"},
    ],
)
def test_partial_existing_security_material_is_preserved_and_blocks_replacement(checkout, monkeypatch, extra):
    root, _ = checkout
    saved = {"DATABASE_URL": DATABASE_URL, **extra}
    dev.CONFIG.write_text("\n".join(f"{key}={json.dumps(value)}" for key, value in saved.items()), encoding="utf-8")
    before = file_snapshot(root)
    forbidden = forbid_mutators(monkeypatch)
    plan = dev_setup.inspect_setup(setup_args(), dev)
    assert plan.blockers
    assert file_snapshot(root) == before
    forbidden.assert_not_called()


@pytest.mark.parametrize("leaf", ["localhost.pem", "localhost-key.pem"])
def test_partial_existing_certificate_pair_is_never_replaced(checkout, monkeypatch, leaf):
    root, _ = checkout
    certificate = root / "frontend/certificates" / leaf
    certificate.parent.mkdir(parents=True)
    certificate.write_bytes(b"fixture-existing-material")
    before = file_snapshot(root)
    forbidden = forbid_mutators(monkeypatch)
    plan = dev_setup.inspect_setup(setup_args(), dev)
    assert plan.blockers
    assert file_snapshot(root) == before
    forbidden.assert_not_called()


def test_apply_failure_restores_scoped_authority_and_removes_handoff_marker(checkout, monkeypatch, capsys):
    monkeypatch.setattr(dev_setup, "inspect_setup", lambda args, launcher: planned("project-dependencies"))
    monkeypatch.setattr(sys, "prefix", str(dev.ROOT / "other-python"))
    interactive(monkeypatch)
    monkeypatch.setattr(builtins, "input", lambda prompt: "yes")
    args = setup_args()
    previous = frozenset({"fixture-prior-authority"})
    args._setup_authorized_categories = previous

    def apply(actual):
        assert actual._setup_authorized_categories == frozenset({"project-dependencies"})
        assert MARKER in os.environ
        raise RuntimeError(SECRET)

    with pytest.raises(RuntimeError):
        dev_setup.run_setup(args, dev, apply)
    assert args._setup_authorized_categories is previous
    assert MARKER not in os.environ
    output = capsys.readouterr()
    assert SECRET not in output.out + output.err


def test_plan_cli_imports_do_not_write_bytecode_or_runtime_state(tmp_path):
    root = tmp_path / "copied-checkout"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "dev.py").write_bytes(Path(dev.__file__).read_bytes())
    (scripts / "dev_setup.py").write_text(
        "import sys\n"
        "assert sys.dont_write_bytecode\n"
        "def run_setup(args, launcher, callback):\n"
        "    assert args.plan\n"
        "    return 0\n",
        encoding="utf-8",
    )
    before = file_snapshot(root)
    environment = dict(os.environ, HOME=str(tmp_path), USERPROFILE=str(tmp_path))
    environment.pop("PYTHONDONTWRITEBYTECODE", None)
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [sys.executable, "-S", str(scripts / "dev.py"), "setup", "--plan", "--profile", "legacy"],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert file_snapshot(root) == before


@pytest.mark.parametrize("name", [".env.dev.local", "requirements.txt", "frontend/package-lock.json", "scripts/dev.py"])
def test_inspection_fingerprint_tracks_configuration_manifests_and_preparation_source(checkout, monkeypatch, name):
    root, _ = checkout
    dev.CONFIG.write_text("DATABASE_URL=" + json.dumps(DATABASE_URL) + "\n", encoding="utf-8")
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text("fixture preparation source\n", encoding="utf-8")
    forbidden = forbid_mutators(monkeypatch)
    first = dev_setup.inspect_setup(setup_args(), dev)
    path.write_text(path.read_text(encoding="utf-8") + "# fixture operator change\n", encoding="utf-8")
    expected = file_snapshot(root)
    second = dev_setup.inspect_setup(setup_args(), dev)
    assert first.fingerprint != second.fingerprint
    assert first.fingerprint not in repr(first)
    assert second.fingerprint not in repr(second)
    assert file_snapshot(root) == expected
    forbidden.assert_not_called()


def test_managed_setup_cannot_convert_existing_hcl_mode(checkout, monkeypatch):
    root, _ = checkout
    saved = {"DATABASE_URL": DATABASE_URL, "HCL_AUTH_ENABLED": "true", "NATIVE_AUTH_ENABLED": "false"}
    dev.CONFIG.write_text("\n".join(f"{key}={json.dumps(value)}" for key, value in saved.items()), encoding="utf-8")
    before = file_snapshot(root)
    forbidden = forbid_mutators(monkeypatch)
    plan = dev_setup.inspect_setup(setup_args(), dev)
    assert any("MANAGED_MODE_REVIEW_REQUIRED" in blocker for blocker in plan.blockers)
    assert file_snapshot(root) == before
    forbidden.assert_not_called()


@pytest.mark.parametrize("key,value", MANAGED_MODE_CONFLICTS)
def test_managed_mode_conflicts_block_plan_and_apply_before_preparation(checkout, monkeypatch, key, value):
    root, _ = checkout
    saved = {
        "DATABASE_URL": DATABASE_URL,
        "AUTH_ENABLED": "true",
        "NATIVE_AUTH_ENABLED": "true",
        "HCL_AUTH_ENABLED": "false",
        "ENTRA_ENABLED": "false",
        "DEV_DEFAULT_TENANT": "false",
        "NATIVE_JWT_PRIVATE_KEY": "fixture-existing-private",
        "NATIVE_JWT_PUBLIC_KEY": "fixture-existing-public",
        "NATIVE_SECURITY_OUTBOX_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "AUTH_SESSION_ENCRYPTION_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        key: value,
    }
    dev.CONFIG.write_text("\n".join(f"{name}={json.dumps(item)}" for name, item in saved.items()), encoding="utf-8")
    monkeypatch.setattr(dev, "validate_secrets", Mock())
    before = file_snapshot(root)
    forbidden = forbid_mutators(monkeypatch)
    plan = dev_setup.inspect_setup(setup_args(), dev)
    assert any(item.startswith("MANAGED_MODE_REVIEW_REQUIRED") for item in plan.blockers)
    args = setup_args()
    args._setup_authorized_categories = frozenset({"project-dependencies", "certificates"})
    with pytest.raises(dev.SetupError, match="MANAGED_AUTHENTICATION_REVIEW_REQUIRED"):
        dev._apply_setup_application(args)
    assert file_snapshot(root) == before
    forbidden.assert_not_called()


@pytest.mark.parametrize("key,value", MANAGED_MODE_CONFLICTS)
def test_fresh_inherited_mode_conflict_refuses_consent_apply_and_credential_preparation(
    checkout, monkeypatch, capsys, key, value
):
    root, home = checkout
    monkeypatch.setitem(os.environ, key, value)
    original_preparation = dev.prepare_managed_legacy
    forbidden = forbid_mutators(monkeypatch)
    interactive(monkeypatch)
    prompt = Mock(side_effect=AssertionError("A conflicting fresh mode requested setup consent"))
    monkeypatch.setattr(builtins, "input", prompt)
    apply = Mock(side_effect=AssertionError("A conflicting fresh mode reached application"))
    args = setup_args(initialize_database=True, confirm_database=dev.DB_NAME)
    before = file_snapshot(root), file_snapshot(home)
    assert dev_setup.run_setup(args, dev, apply) == 1
    output = capsys.readouterr()
    assert "MANAGED_MODE_REVIEW_REQUIRED" in output.out
    args._setup_authorized_categories = frozenset(
        {"project-dependencies", "configuration", "secrets", "database-initialize"}
    )
    with pytest.raises(dev.SetupError, match="MANAGED_AUTHENTICATION_REVIEW_REQUIRED"):
        dev._apply_setup_application(args)
    with pytest.raises(dev.SetupError, match="MANAGED_AUTHENTICATION_REVIEW_REQUIRED"):
        original_preparation(setup_args=args)
    assert (file_snapshot(root), file_snapshot(home)) == before
    assert not dev.CONFIG.exists()
    assert MARKER not in os.environ
    prompt.assert_not_called()
    apply.assert_not_called()
    forbidden.assert_not_called()


def test_fresh_legacy_docker_configuration_is_blocked_before_consent(checkout, monkeypatch, capsys):
    root, home = checkout
    forbidden = forbid_mutators(monkeypatch)
    interactive(monkeypatch)
    prompt = Mock(side_effect=AssertionError("Unsupported fresh Docker configuration requested consent"))
    monkeypatch.setattr(builtins, "input", prompt)
    apply = Mock(side_effect=AssertionError("Unsupported fresh Docker configuration reached application"))
    args = setup_args(initialize_database=True, confirm_database=dev.DB_NAME, postgres_provider="docker")
    before = file_snapshot(root), file_snapshot(home)
    assert dev_setup.run_setup(args, dev, apply) == 1
    output = capsys.readouterr()
    assert "APPROVED_DATABASE_CONFIGURATION_REQUIRED" in output.out
    assert (file_snapshot(root), file_snapshot(home)) == before
    prompt.assert_not_called()
    apply.assert_not_called()
    forbidden.assert_not_called()


def test_provider_change_requires_review_without_saved_configuration_rewrite(checkout, monkeypatch):
    root, _ = checkout
    saved = {"DATABASE_URL": DATABASE_URL, "DEV_POSTGRES_PROVIDER": "local"}
    dev.CONFIG.write_text("\n".join(f"{key}={json.dumps(value)}" for key, value in saved.items()), encoding="utf-8")
    before = file_snapshot(root)
    forbidden = forbid_mutators(monkeypatch)
    plan = dev_setup.inspect_setup(setup_args(postgres_provider="docker"), dev)
    assert any("PROVIDER_CHANGE_REVIEW_REQUIRED" in blocker for blocker in plan.blockers)
    assert file_snapshot(root) == before
    forbidden.assert_not_called()


def test_public_setup_dispatch_reaches_planning_before_prerequisites_or_runtime_adoption(checkout, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["dev.py", "setup", "--plan", "--profile", "legacy"])
    forbidden = Mock(side_effect=AssertionError("setup preflight entered preparation before presenting a plan"))
    for name in (
        "ensure_virtualenv",
        "ensure_dependencies",
        "venv_python",
        "validate_python_version",
        "validate_repository_layout",
        "pin_legacy_configuration",
        "Runtime",
    ):
        monkeypatch.setattr(dev, name, forbidden)
    planned_setup = Mock(return_value=0)
    monkeypatch.setattr(dev, "setup_application", planned_setup)
    assert dev.main() == 0
    planned_setup.assert_called_once()
    assert planned_setup.call_args.args[0].plan is True
    forbidden.assert_not_called()


@pytest.mark.parametrize("condition", ["success", "busy", "record-appeared", "apply-failed"])
def test_apply_serializes_preparation_after_interpreter_handoff(checkout, monkeypatch, condition):
    events = []

    class Runtime:
        def __init__(self, root):
            self.locked = False

        def load(self):
            return {"services": {}} if self.locked and condition == "record-appeared" else None

        def acquire(self):
            events.append("acquire")
            self.locked = condition != "busy"
            return self.locked

        def release(self):
            assert self.locked
            events.append("release")

    monkeypatch.setattr(dev, "Runtime", Runtime)
    monkeypatch.setattr(dev, "validate_repository_layout", lambda: None)
    monkeypatch.setattr(dev, "validate_prerequisites", lambda: None)
    monkeypatch.setattr(dev, "ensure_virtualenv", lambda: events.append("handoff"))
    monkeypatch.setattr(dev, "ensure_dependencies", lambda: events.append("dependencies"))

    def apply(args, profile):
        assert events == ["handoff", "acquire", "dependencies"]
        events.append("apply")
        if condition == "apply-failed":
            raise dev.SetupError("synthetic preparation failure")

    monkeypatch.setattr(dev, "_prepare_authorized_setup", apply)
    args = setup_args()
    args._setup_authorized_categories = frozenset({"project-dependencies"})
    if condition == "success":
        dev._apply_setup_application(args)
        assert events == ["handoff", "acquire", "dependencies", "apply", "release"]
    else:
        with pytest.raises(dev.SetupError):
            dev._apply_setup_application(args)
        assert (
            events
            == {
                "busy": ["handoff", "acquire"],
                "record-appeared": ["handoff", "acquire", "release"],
                "apply-failed": ["handoff", "acquire", "dependencies", "apply", "release"],
            }[condition]
        )


@pytest.mark.parametrize("missing", [None, "redis", "next-cli"])
def test_matching_stamps_do_not_hide_removed_dependency_entry_points(checkout, monkeypatch, missing):
    root, _ = checkout
    python = dev.venv_python()
    python.parent.mkdir(parents=True)
    python.touch()
    (dev.VENV / ".sbom-requirements-sha256").write_text(
        hashlib.sha256((root / "requirements.txt").read_bytes()).hexdigest()
    )
    modules = root / "frontend/node_modules"
    cli = modules / "next/dist/bin/next"
    cli.parent.mkdir(parents=True)
    if missing != "next-cli":
        cli.touch()
    digest = hashlib.sha256(
        (root / "frontend/package.json").read_bytes() + b"\0" + (root / "frontend/package-lock.json").read_bytes()
    ).hexdigest()
    (modules / ".sbom-dependencies-sha256").write_text(digest)
    monkeypatch.setattr(dev_setup, "_in_project_venv", lambda launcher: True)
    monkeypatch.setattr(dev_setup.importlib.util, "find_spec", lambda name: None if name == missing else object())
    before = file_snapshot(root)
    actions, blockers = {}, []
    dev_setup._dependencies(dev_setup._Snapshot(), dev, actions, blockers)
    assert ("project-dependencies" in actions) == (missing is not None)
    assert file_snapshot(root) == before
    assert not blockers
