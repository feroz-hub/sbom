"""Disposable generated previews only: no Node, network, installs or live data."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev_instance_plan, dev_instance_storage, dev_private, dev_workspace
from scripts import dev_workspace_preview as preview

SECRET = "synthetic-private-preview-value-never-output"


def directory(path):
    if sys.platform == "win32":
        dev_instance_storage._windows_create(path)
    else:
        path.mkdir(mode=0o700)


def write(path, value):
    dev_private.create_private_file(path, value.encode() if isinstance(value, str) else value)


@pytest.fixture
def candidate(tmp_path, monkeypatch):
    base = tmp_path.resolve()
    home, tools, tlsroot = (base / name for name in ("private home", "tools", "existing TLS"))
    root = home / "checkout with spaces"  # Normal home-contained Git checkout remains supported.
    for path in (
        home,
        root,
        tools,
        tlsroot,
        root / "frontend",
        root / "scripts",
        root / "frontend/src",
        root / "frontend/src/app",
        root / "frontend/public",
        root / "frontend/node_modules",
    ):
        directory(path)
    modules = root / "frontend/node_modules"
    for relative in (
        "react",
        "react-dom",
        "next",
        "next/dist",
        "next/dist/bin",
        "next/dist/lib",
        "next/dist/compiled",
        "next/dist/compiled/@napi-rs",
        "next/dist/compiled/@napi-rs/triples",
        "@next",
        "@next/swc-" + {"win32": "win32-x64-msvc", "darwin": "darwin-x64", "linux": "linux-x64-gnu"}[sys.platform],
    ):
        directory(modules / relative)
    for relative in ("react/package.json", "react-dom/package.json", "next/package.json"):
        write(modules / relative, '{"version":"16.3.4"}')
    for relative in (
        "next/dist/bin/next",
        "next/dist/lib/download-swc.js",
        "next/dist/compiled/@napi-rs/triples/index.js",
    ):
        write(modules / relative, "// synthetic package fixture; never executed\n")
    write(root / "scripts/dev_next_guard.cjs", "// synthetic guard fixture; never executed\n")
    write(root / "frontend/src/app/globals.css", ":root {--color-foreground:#212529;--dashboard-page-bg:#F8FAFC;}")
    write(root / "frontend/src/app/page.jsx", "export default function Page(){return <p>Selected trusted frontend</p>}")
    for name, content in {
        "package.json": '{"name":"fixture","private":true}',
        "package-lock.json": "{}",
        "tsconfig.json": "{}",
    }.items():
        write(root / "frontend" / name, content)
    write(root / "frontend/.env.local", SECRET)
    node = tools / "node.exe"
    write(node, "synthetic Node; never executed")
    for name in ("leaf.pem", "key.pem", "ca.pem"):
        write(tlsroot / name, "synthetic pre-existing TLS material; verifier is mocked")
    tls = preview.PreviewTls(tlsroot / "leaf.pem", tlsroot / "key.pem", tlsroot / "ca.pem")
    identity = dev_workspace._identity(root)
    row = dev_workspace.WorktreeSnapshot(
        "b" * 64, root, identity, "c" * 40, "refs/heads/preview", False, False, False, False, False
    )
    snapshot = dev_workspace.RepositorySnapshot("a" * 64, root, identity, row.head, (row,), identity)
    monkeypatch.setattr(dev_workspace, "discover_workspaces", lambda selected: snapshot)
    forbidden = Mock(side_effect=AssertionError("Preview attempted live process, network, install or data access"))
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(preview.dev_workspace_dependencies, "prepare_dependencies", forbidden)
    result = SimpleNamespace(
        root=root, home=home, node=node, tls=tls, row=row, snapshot=snapshot, modules=modules, forbidden=forbidden
    )
    yield result
    forbidden.assert_not_called()
    assert (root / "frontend/.env.local").read_text() == SECRET


def plan(candidate, mode="mock", **options):
    descriptor = dev_instance_plan.plan_instance(
        repository_id="a" * 64, worktree_id="b" * 64, commit="c" * 40, generation=1, mode=mode, auth_mode="native"
    ).descriptor
    shared = (
        None
        if mode in {"mock", "isolated"}
        else preview.SharedBackendRegistration(
            "d" * 64, "https://approved-nonproduction.example.test", "e" * 64, descriptor.origin, "native"
        )
    )
    values = dict(state_anchor=candidate.home, node_executable=candidate.node, tls=candidate.tls, shared_backend=shared)
    values.update(options)
    return preview.plan_preview(candidate.snapshot, candidate.row, descriptor, **values)


def approvals():
    return dict(
        verify_backend=Mock(return_value=True),
        verify_tls=Mock(return_value=True),
        verify_compiler=Mock(return_value=True),
    )


def shared_environment(value):
    return {
        "AUTH_ENABLED": "true",
        "DEV_DEFAULT_TENANT": "false",
        "APP_ORIGIN": value.descriptor.origin,
        "NATIVE_AUTH_ENABLED": "true",
        "NEXT_PUBLIC_AUTH_ENABLED": "true",
        "NEXT_PUBLIC_NATIVE_AUTH_ENABLED": "true",
        "NEXT_PUBLIC_HCL_AUTH_ENABLED": "false",
        "NEXT_PUBLIC_ENTRA_ENABLED": "false",
        "NEXT_PUBLIC_API_URL": value.shared_backend.origin,
        "SBOM_API_URL": value.shared_backend.origin,
        "AUTH_SESSION_ENCRYPTION_KEY": SECRET,
        "DATABASE_URL": SECRET,
    }


def test_mock_preparation_generates_separate_labeled_static_app_without_private_files(candidate):
    value = plan(candidate)
    assert not value.to_dict()["compiler_verified"] and not (candidate.home / ".sbom-dev").exists()
    with pytest.raises(FrozenInstanceError):
        value.fingerprint = "changed"
    workspace = preview.prepare_preview(value, authorize=lambda selected: selected is value)
    assert workspace == preview.require_preview(value)
    source = workspace.parent / "mock-source"
    assert (workspace / "src").resolve() == source and (workspace / "node_modules").resolve() == candidate.modules
    assert "MOCK VISUAL PREVIEW" in (source / "app/page.jsx").read_text()
    assert "SYNTHETIC DATA" in (source / "app/page.jsx").read_text()
    assert "--color-foreground:#212529" in (source / "app/preview.css").read_text()
    assert not list(workspace.glob(".env*")) and not (source / "app/api").exists()
    checks = approvals()
    launch = preview.validate_launch(value, {"DATABASE_URL": SECRET, "AUTH_SESSION_ENCRYPTION_KEY": SECRET}, **checks)
    assert SECRET not in repr(launch) + json.dumps(launch.to_dict()) + repr(dict(launch.environment))
    assert "AUTH_ENABLED" not in launch.environment and "NEXT_PUBLIC_AUTH_ENABLED" not in launch.environment
    assert launch.argv[launch.argv.index("--hostname") + 1] == "127.0.0.1"
    assert {"--experimental-https-key", "--experimental-https-cert", "--experimental-https-ca", "--webpack"} <= set(
        launch.argv
    )
    assert str(value.guard) in launch.argv and value.guard.as_posix() in launch.environment["NODE_OPTIONS"]
    assert "--require" in launch.compiler_argv and "loadBindings" not in launch.compiler_argv[-2]
    checks["verify_backend"].assert_not_called()
    checks["verify_tls"].assert_called_once()
    checks["verify_compiler"].assert_called_once()
    with pytest.raises(TypeError):
        launch.environment["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"


def test_shared_preparation_uses_selected_source_and_preserves_auth_until_live_callbacks_verify(candidate):
    value = plan(candidate, "shared-backend")
    workspace = preview.prepare_preview(value, authorize=lambda selected: True)
    assert (workspace / "src").resolve() == candidate.root / "frontend/src"
    assert not list(workspace.glob(".env*")) and value.to_dict()["real_mutations_possible"] is True
    env, checks = shared_environment(value), approvals()
    launch = preview.validate_launch(value, env, **checks)
    assert launch.environment["AUTH_SESSION_ENCRYPTION_KEY"] == SECRET and "DATABASE_URL" not in launch.environment
    assert launch.environment["NEXT_PUBLIC_AUTH_ENABLED"] == "true"
    assert env["DATABASE_URL"] == SECRET and SECRET not in repr(value) + json.dumps(value.to_dict()) + repr(launch)
    checks["verify_backend"].assert_called_once()
    assert SECRET not in repr(dict(checks["verify_compiler"].call_args.args[2]))
    assert not launch.to_dict()["runtime_started"]


def test_shared_credential_and_ca_paths_keep_original_frontend_base_without_copying(candidate):
    value = plan(candidate, "shared-backend")
    preview.prepare_preview(value, authorize=lambda selected: True)
    env = {
        **shared_environment(value),
        "AUTH_TRANSACTION_KEY_FILE": "certificates/existing-key.pem",
        "NODE_EXTRA_CA_CERTS": "certificates/ca.pem",
        "HCL_IAM_CA_BUNDLE": " certificates/provider.pem ",
    }
    checks = approvals()
    launch = preview.validate_launch(value, env, **checks)
    for key, relative in (
        ("AUTH_TRANSACTION_KEY_FILE", "certificates/existing-key.pem"),
        ("NODE_EXTRA_CA_CERTS", "certificates/ca.pem"),
        ("HCL_IAM_CA_BUNDLE", "certificates/provider.pem"),
    ):
        assert launch.environment[key] == str(candidate.root / "frontend" / relative)
        assert checks["verify_backend"].call_args.args[1][key] == launch.environment[key]
    assert env["AUTH_TRANSACTION_KEY_FILE"] == "certificates/existing-key.pem"
    assert not (value.workspace / "certificates").exists()


def test_declined_approval_and_source_drift_never_prepare_private_artifacts(candidate):
    value = plan(candidate)
    with pytest.raises(preview.PreviewError, match="^PREVIEW_CATEGORY_APPROVAL_REQUIRED$"):
        preview.prepare_preview(value, authorize=lambda selected: False)
    assert not (candidate.home / ".sbom-dev").exists()
    (candidate.root / "frontend/src/app/globals.css").write_text(":root {--changed:#fff;}")
    with pytest.raises(preview.PreviewError, match="^PREVIEW_SOURCE_CHANGED$"):
        preview.prepare_preview(value, authorize=lambda selected: True)
    assert not (candidate.home / ".sbom-dev").exists()


@pytest.mark.parametrize("flag", ["NODE_OPTIONS", "NODE_TLS_REJECT_UNAUTHORIZED"])
def test_node_preloads_and_tls_bypass_refused_before_verifiers(candidate, flag):
    value = plan(candidate)
    preview.prepare_preview(value, authorize=lambda selected: True)
    checks = approvals()
    with pytest.raises(preview.PreviewError, match="^(NODE_OPTIONS_REVIEW_REQUIRED|TLS_VERIFICATION_REQUIRED)$"):
        preview.validate_launch(value, {flag: "--require " + SECRET if flag == "NODE_OPTIONS" else "0"}, **checks)
    assert not any(check.called for check in checks.values())


def test_mock_preserves_approved_strong_tls_options_and_original_ca_path_base(candidate):
    value = plan(candidate)
    preview.prepare_preview(value, authorize=lambda selected: True)
    launch = preview.validate_launch(
        value,
        {"NODE_OPTIONS": "--tls-min-v1.3 --use-system-ca", "NODE_EXTRA_CA_CERTS": "certificates/ca.pem"},
        **approvals(),
    )
    assert launch.environment["NODE_OPTIONS"].startswith("--tls-min-v1.3 --use-system-ca --require ")
    assert launch.environment["NODE_EXTRA_CA_CERTS"] == str(candidate.root / "frontend/certificates/ca.pem")


@pytest.mark.parametrize(
    "missing,code",
    [
        ("verify_tls", "PREVIEW_TLS_VERIFICATION_REQUIRED"),
        ("verify_compiler", "PREVIEW_NATIVE_COMPILER_VERIFICATION_REQUIRED"),
        ("verify_backend", "PREVIEW_SHARED_BACKEND_VERIFICATION_REQUIRED"),
    ],
)
def test_live_verification_callbacks_are_required_even_with_ready_labels(candidate, missing, code):
    value = plan(candidate, "shared-backend")
    preview.prepare_preview(value, authorize=lambda selected: True)
    checks = approvals()
    checks[missing] = None
    env = {**shared_environment(value), "SBOM_PREVIEW_READY": "true"}
    with pytest.raises(preview.PreviewError, match="^" + code + "$"):
        preview.validate_launch(value, env, **checks)


@pytest.mark.parametrize(
    "key,replacement",
    [
        ("NEXT_PUBLIC_API_URL", "https://wrong-target.example.test"),
        ("NEXT_PUBLIC_AUTH_ENABLED", "false"),
        ("DEV_DEFAULT_TENANT", "true"),
    ],
)
def test_shared_target_and_authentication_cannot_drift_or_convert(candidate, key, replacement):
    value = plan(candidate, "shared-backend")
    preview.prepare_preview(value, authorize=lambda selected: True)
    checks = approvals()
    with pytest.raises(preview.PreviewError, match="^PREVIEW_SHARED_AUTH_OR_TARGET_REQUIRED$"):
        preview.validate_launch(value, {**shared_environment(value), key: replacement}, **checks)
    assert not any(check.called for check in checks.values())


@pytest.mark.parametrize(
    "origin", ["http://localhost:8000", "https://user:password@example.test", "https://example.test/?token=" + SECRET]
)
def test_backend_registration_rejects_unsafe_targets_without_disclosure(origin):
    with pytest.raises(preview.PreviewError, match="^PREVIEW_BACKEND_REGISTRATION_REQUIRED$") as caught:
        preview.SharedBackendRegistration("d" * 64, origin, "e" * 64, "https://fixture.localhost:24443", "native")
    assert SECRET not in str(caught.value) and "password" not in str(caught.value)


@pytest.mark.parametrize("addition", ["dotenv", "api-route"])
def test_added_dotenv_or_api_route_is_preserved_and_blocks_mock_launch(candidate, addition):
    value = plan(candidate)
    workspace = preview.prepare_preview(value, authorize=lambda selected: True)
    if addition == "dotenv":
        path = workspace / ".env.local"
    else:
        directory(workspace.parent / "mock-source/app/api")
        path = workspace.parent / "mock-source/app/api/route.js"
    write(path, SECRET)
    with pytest.raises(preview.PreviewError, match="^PREVIEW_WORKSPACE_UNVERIFIED$"):
        preview.validate_launch(value, {}, **approvals())
    assert path.read_text() == SECRET


def test_guard_drift_after_verifier_aborts_before_returning_launch_spec(candidate):
    value = plan(candidate)
    preview.prepare_preview(value, authorize=lambda selected: True)
    checks = approvals()

    def changed(selected, command, environment):
        value.guard.write_text("// changed reviewed guard")
        return True

    checks["verify_compiler"] = changed
    with pytest.raises(preview.PreviewError, match="^PREVIEW_SOURCE_CHANGED$"):
        preview.validate_launch(value, {}, **checks)


def test_ambiguous_existing_workspace_is_retained_without_overwrite(candidate):
    value = plan(candidate)
    dev_instance_storage.initialize_private_directory(value.workspace, anchor=candidate.home)
    write(value.workspace / "preserve", SECRET)
    with pytest.raises(preview.PreviewError, match="^PREVIEW_WORKSPACE_UNVERIFIED$"):
        preview.prepare_preview(value, authorize=lambda selected: True)
    assert (value.workspace / "preserve").read_text() == SECRET


@pytest.mark.parametrize("field", ["files", "workspace", "links"])
def test_caller_cannot_reuse_fingerprint_with_changed_paths_or_generated_files(candidate, field):
    value = plan(candidate)
    changed = {
        "files": (("../../private.env", SECRET.encode()),),
        "workspace": candidate.home / "unknown",
        "links": (("node_modules", candidate.home),),
    }[field]
    forged = replace(value, **{field: changed})
    with pytest.raises(preview.PreviewError, match="^PREVIEW_SOURCE_CHANGED$"):
        preview.prepare_preview(forged, authorize=lambda selected: True)
    assert not (candidate.home / ".sbom-dev").exists() and not (candidate.home / "private.env").exists()


def test_isolated_application_requires_exact_own_backend_binding(candidate):
    with pytest.raises(preview.PreviewError, match="^PREVIEW_ISOLATED_BACKEND_BINDING_REQUIRED$"):
        plan(candidate, "isolated")


def test_isolated_frontend_uses_real_source_after_runtime_backend_verification(candidate):
    descriptor = dev_instance_plan.plan_instance(
        repository_id="a" * 64, worktree_id="b" * 64, commit="c" * 40, generation=1, mode="isolated", auth_mode="native"
    ).descriptor
    binding = preview.IsolatedBackendBinding(descriptor.instance_id, f"http://127.0.0.1:{descriptor.ports['api']}")
    value = plan(candidate, "isolated", isolated_backend=binding)
    preview.prepare_preview(value, authorize=lambda _: True)
    checks = approvals()
    launch = preview.validate_launch(value, shared_environment(value), **checks)
    assert value.to_dict()["category"] == "application-frontend"
    assert value.to_dict()["application_readiness_verified"] is False
    assert launch.environment["SBOM_DEV_RESOURCE_ID"] == descriptor.instance_id
    assert (value.workspace / "src").resolve() == candidate.root / "frontend/src"
    checks["verify_backend"].assert_called_once()


def test_another_instance_or_wrong_api_port_cannot_supply_isolated_binding(candidate):
    descriptor = dev_instance_plan.plan_instance(
        repository_id="a" * 64, worktree_id="b" * 64, commit="c" * 40, generation=1, mode="isolated", auth_mode="native"
    ).descriptor
    for binding in (
        preview.IsolatedBackendBinding(
            "00000000-0000-0000-0000-000000000000", f"http://127.0.0.1:{descriptor.ports['api']}"
        ),
        preview.IsolatedBackendBinding(descriptor.instance_id, "http://127.0.0.1:1"),
    ):
        with pytest.raises(preview.PreviewError, match="^PREVIEW_ISOLATED_BACKEND_BINDING_REQUIRED$"):
            plan(candidate, "isolated", isolated_backend=binding)


def test_unsafe_css_import_or_url_is_never_executed_or_copied(candidate):
    (candidate.root / "frontend/src/app/globals.css").write_text(
        ":root{--external:url(https://example.invalid/" + SECRET + ");}"
    )
    with pytest.raises(preview.PreviewError, match="^PREVIEW_PUBLIC_STYLE_REQUIRED$") as caught:
        plan(candidate)
    assert SECRET not in str(caught.value) and not (candidate.home / ".sbom-dev").exists()


def test_actual_selected_theme_supports_inert_mock_token_extraction():
    style = Path(__file__).resolve().parents[1] / "frontend/src/app/globals.css"
    result = preview._tokens(style.read_bytes())
    assert "--dashboard-page-bg:" in result and "--color-foreground:" in result
    assert "@import" not in result and "url(" not in result.lower()


def test_missing_tls_path_returns_only_fixed_redacted_error(candidate):
    with pytest.raises(preview.PreviewError, match="^PREVIEW_EXISTING_TLS_REQUIRED$") as caught:
        preview.PreviewTls(candidate.home / SECRET, candidate.tls.private_key, candidate.tls.ca_bundle)
    assert SECRET not in str(caught.value)
