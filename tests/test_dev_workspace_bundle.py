"""Synthetic private-bundle fixtures only; no real key/cert generation or DB.

The fake generator returns public test markers. Filesystem/receipt/consent paths
are real inside newly created pytest temp roots. Positive storage tests replace
only the private crypto validator with a strict test-marker shim; real invalid
PEM rejection is separately tested. Real crypto generation/acceptance is not run.
"""

from __future__ import annotations

import ast
import base64
import builtins
import json
import os
import re
import socket
import subprocess
import sys
import types
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import parse_qs, unquote, urlsplit

import pytest
from scripts import dev_instance_plan, dev_workspace
from scripts import dev_workspace_bundle as bundle
from scripts import dev_workspace_compose as compose
from scripts import dev_workspace_lifecycle as lifecycle
from scripts import dev_workspace_provider as provider

GENERATION = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
OTHER_GENERATION = "11111111-2222-4333-8444-555555555555"
SECRET = "synthetic-private-never-public-or-authority"


def provider_plan(**changes):
    descriptor = dev_instance_plan.plan_instance(
        **{
            "repository_id": "a" * 64,
            "worktree_id": "b" * 64,
            "commit": "c" * 40,
            "generation": 1,
            "mode": "isolated",
            "auth_mode": "native",
            "provider": "container",
            **changes,
        }
    ).descriptor
    policy = provider.ContainerPolicy(
        "docker",
        "d" * 64,
        "e" * 64,
        {name: f"synthetic.invalid/{name}@sha256:" + "f" * 64 for name in compose._COMPONENTS},
        {"postgres": "999:999", "redis": "1000:1000", "mailpit": "1001:1001"},
    )
    return provider.plan_provider(descriptor, policy)


def fake_material(plan):
    secrets = {
        name: (letter * (32 if name in bundle._BINARY_SECRET_NAMES else 40)).encode()
        for name, letter in zip(sorted(bundle._SECRET_NAMES), "ABCDEFGH", strict=True)
    }
    certificates = {"ca": ("synthetic-ca-" + plan.provider_plan.descriptor.instance_id).encode()}
    for component in ("frontend", "postgres", "redis", "mailpit"):
        for role in ("key", "cert"):
            certificates[component + "-" + role] = ("synthetic-" + component + "-" + role).encode()
    files = bundle._provider_payloads(plan, secrets, certificates)
    files.update(
        {
            "keys/auth-transaction-key": b"T" * 32,
            "tls/ca-key.pem": b"synthetic-ca-key",
            "tls/ca.pem": certificates["ca"],
            "tls/frontend-key.pem": certificates["frontend-key"],
            "tls/frontend-cert.pem": certificates["frontend-cert"],
            "tls/trust-bundle.pem": certificates["ca"],
        }
    )
    if plan.provider_plan.descriptor.auth_mode == "native":
        files.update(
            {
                "keys/native-jwt-private.pem": b"synthetic-jwt-private",
                "keys/native-jwt-public.pem": b"synthetic-jwt-public",
            }
        )
    return bundle.BundleMaterial(files, secrets)


def test_bundle_environment_and_lifecycle_consumer_share_exact_contract(fixture, synthetic_crypto):
    material = fake_material(fixture.plan)
    environment = bundle._validate_material(fixture.plan, material)
    descriptor = replace(
        fixture.provider.descriptor, configuration_present=True, config_generation=fixture.plan.generation
    )
    snapshot = lifecycle.PreparationSnapshot(
        descriptor.repository_id,
        descriptor.worktree_id,
        descriptor.commit,
        descriptor.config_generation,
        sys.platform,
        str(fixture.root),
        str(fixture.plan.state_root),
        environment,
        dict.fromkeys(lifecycle.PREREQUISITES, "PREPARED"),
    )
    assert lifecycle.plan_lifecycle(descriptor, snapshot).ready is False


def test_canonical_storage_key_is_consumed_by_both_existing_provider_services(fixture, synthetic_crypto):
    material = fake_material(fixture.plan)
    environment = bundle._validate_material(fixture.plan, material)
    root = Path(__file__).resolve().parents[1]
    secret_tree = ast.parse((root / "app/security/secrets.py").read_text(encoding="utf-8"))
    secret_class = next(
        node for node in secret_tree.body if isinstance(node, ast.ClassDef) and node.name == "SecretCipher"
    )
    method = next(node for node in secret_class.body if isinstance(node, ast.FunctionDef) and node.name == "from_env")
    method.decorator_list = []
    default = next(
        node.value.value
        for node in secret_class.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "ENV_VAR"
    )
    captured = []

    class CaptureCipher:
        ENV_VAR = default

        def __init__(self, key):
            captured.append(key)

    namespace = {
        "os": SimpleNamespace(environ=environment, getenv=environment.get),
        "base64": base64,
        "SecretCipher": CaptureCipher,
    }
    exec(compile(ast.Module(body=[method], type_ignores=[]), "provider_cipher_contract", "exec"), namespace)
    namespace["from_env"](CaptureCipher)
    tree = ast.parse((root / "app/services/lifecycle/secret_service.py").read_text(encoding="utf-8"))
    selected = [
        node
        for node in tree.body
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "SECRET_ENV_CANDIDATES" for target in node.targets)
        )
        or (isinstance(node, ast.FunctionDef) and node.name == "_cipher_from_environment")
    ]
    exec(compile(ast.Module(body=selected, type_ignores=[]), "lifecycle_cipher_contract", "exec"), namespace)
    namespace["_cipher_from_environment"]()
    assert captured == [material.secrets["provider-storage"]] * 2
    assert "APP_SECRET_KEY" not in environment and "SETTINGS_SECRET_KEY" not in environment


@pytest.fixture
def fixture(tmp_path_factory, monkeypatch):
    # Keep paths short enough for native Windows without enabling long paths.
    temporary = tmp_path_factory.mktemp("b").resolve()
    root, anchor = temporary / "s", temporary / "h"
    for path in (root, anchor):
        if os.name == "nt":
            bundle.dev_instance_storage._windows_create(
                path
            )  # New fixture only; inherited office ACLs are not repaired.
        else:
            path.mkdir(mode=0o700)
    identity = dev_workspace._identity(root)
    selected = dev_workspace.WorktreeSnapshot(
        "b" * 64, root, identity, "c" * 40, "refs/heads/fixture", False, False, False, False, False
    )
    snapshot = dev_workspace.RepositorySnapshot("a" * 64, root, identity, selected.head, (selected,), identity)
    discover = Mock(return_value=snapshot)
    monkeypatch.setattr(dev_workspace, "discover_workspaces", discover)
    source = bundle.inspect_source(root)
    original = provider_plan()
    plan = bundle.plan_bundle(
        original, source, anchor=dev_workspace._identity(anchor), generation=GENERATION, profiles=compose._PROFILES
    )
    return SimpleNamespace(
        temporary=temporary,
        root=root,
        anchor=anchor,
        source=source,
        snapshot=snapshot,
        selected=selected,
        discover=discover,
        provider=original,
        plan=plan,
    )


@pytest.fixture(autouse=True)
def protected_boundaries(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("Bundle source entered a real generator, provider or application"))
    original_import = builtins.__import__

    def safe_import(name, *arguments, **keywords):
        if name.split(".", 1)[0] in {"app", "psycopg", "sqlalchemy", "celery", "redis", "docker"}:
            return forbidden(name)
        return original_import(name, *arguments, **keywords)

    monkeypatch.setattr(builtins, "__import__", safe_import)
    monkeypatch.setattr(bundle, "generate_material", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    yield forbidden
    forbidden.assert_not_called()


@pytest.fixture
def synthetic_crypto(monkeypatch):
    def validate(plan, material):
        expected = fake_material(plan)
        if any(
            material.files[name] != expected.files[name]
            for name in expected.files
            if name.startswith("tls/") or name.startswith("keys/native-jwt")
        ):
            raise bundle.BundleError("BUNDLE_CRYPTO_MATERIAL_INVALID")

    check = Mock(side_effect=validate)
    monkeypatch.setattr(bundle, "_validate_crypto", check)
    return check


def approve(plan, category):
    assert category in {"credentials", "certificates"}
    return True


def test_plan_is_pure_immutable_and_does_not_expose_private_paths_or_hashes(fixture, monkeypatch):
    forbidden = Mock(side_effect=AssertionError("Pure plan attempted I/O or preparation"))
    with monkeypatch.context() as guard:
        guard.setattr(os, "open", forbidden)
        guard.setattr(Path, "resolve", forbidden)
        guard.setattr(Path, "mkdir", forbidden)
        guard.setattr(dev_workspace, "discover_workspaces", forbidden)
        plan = bundle.plan_bundle(
            fixture.provider,
            fixture.source,
            anchor=fixture.plan.anchor,
            generation=GENERATION,
            profiles=compose._PROFILES,
        )
    assert plan == fixture.plan
    assert not plan.directory.exists()
    public = json.dumps(plan.to_dict()) + repr(plan)
    assert str(fixture.anchor) not in public and plan.private_binding not in public
    assert plan.to_dict()["required_authorizations"] == ["credentials", "certificates"]
    assert plan.to_dict()["browser_trust_installed"] is False and plan.to_dict()["database_authorized"] is False
    with pytest.raises(FrozenInstanceError):
        plan.generation = OTHER_GENERATION
    with pytest.raises(TypeError):
        plan.profiles["postgres"] = SECRET
    forbidden.assert_not_called()


@pytest.mark.parametrize("declined", ["credentials", "certificates"])
def test_each_creation_category_needs_explicit_consent_before_any_write_or_generator(fixture, declined):
    categories = []
    generated = Mock(side_effect=fake_material)

    def authorize(plan, category):
        categories.append(category)
        return category != declined

    result = bundle.prepare_bundle(fixture.plan, authorize=authorize, generator=generated)
    assert result.code == "BUNDLE_" + declined.upper() + "_AUTHORIZATION_REQUIRED"
    assert result.exit_code == 1 and not result.artifacts_retained
    assert categories == (["credentials"] if declined == "credentials" else ["credentials", "certificates"])
    assert not (fixture.anchor / ".sbom-dev").exists()
    generated.assert_not_called()


def test_new_native_bundle_is_private_new_only_and_managed_config_is_supported(fixture, synthetic_crypto):
    generated = Mock(side_effect=fake_material)
    categories = []
    result = bundle.prepare_bundle(
        fixture.plan, authorize=lambda plan, category: categories.append(category) or True, generator=generated
    )
    assert result.code == "BUNDLE_PREPARED" and result.exit_code == 0 and result.receipt is not None
    assert categories == ["credentials", "certificates"] and result.artifacts_retained and not result.reused
    generated.assert_called_once_with(fixture.plan)
    synthetic_crypto.assert_called_once()
    root = fixture.plan.directory
    assert root.is_relative_to(fixture.temporary) and not root.is_relative_to(fixture.root)
    assert root.parent.parent.name == fixture.provider.descriptor.instance_id
    assert not (fixture.plan.state_root / ".env.dev.local").exists()
    assert {str(path.relative_to(root)).replace("\\", "/") for path in root.rglob("*") if path.is_file()} == {
        *fixture.plan.files,
        bundle._MANAGED,
        bundle._JOURNAL,
        bundle._RECEIPT,
    }
    for path in root.rglob("*"):
        bundle.dev_instance_registry._private(path, directory=path.is_dir())
    environment = bundle.dev_config.parse_managed((root / bundle._MANAGED).read_text(encoding="ascii"))
    assert environment["AUTH_ENABLED"] == "true" and environment["DEV_DEFAULT_TENANT"] == "false"
    assert environment["NATIVE_PLATFORM_BOOTSTRAP_ENABLED"] == "false"
    assert environment["NATIVE_AUTH_ENABLED"] == "true" and environment["HCL_AUTH_ENABLED"] == "false"
    assert environment["NATIVE_JWT_PRIVATE_KEY"] == "synthetic-jwt-private"
    provider_key = base64.b64decode(environment["AI_CONFIG_ENCRYPTION_KEY"], validate=True)
    assert len(provider_key) == 32
    assert provider_key not in {
        base64.b64decode(environment["AUTH_SESSION_ENCRYPTION_KEY"], validate=True),
        base64.b64decode(environment["NATIVE_SECURITY_OUTBOX_KEY"], validate=True),
    }
    assert "NATIVE_JWT_PRIVATE_KEY_FILE" not in environment
    assert environment["AUTH_TRANSACTION_KEY_FILE"] == str(root / "keys/auth-transaction-key")
    trust = str(root / "tls/trust-bundle.pem")
    assert environment["SSL_CERT_FILE"] == environment["NODE_EXTRA_CA_CERTS"] == trust
    assert parse_qs(urlsplit(environment["DATABASE_URL"]).query) == {
        "sslmode": ["verify-full"],
        "sslrootcert": [trust],
        "gssencmode": ["disable"],
        "sslcertmode": ["disable"],
    }
    for key in ("REDIS_URL", "CELERY_BROKER_URL", "CELERY_RESULT_BACKEND", "NATIVE_AUTH_RATE_LIMIT_STORAGE_URI"):
        uri = urlsplit(environment[key])
        assert uri.scheme == "rediss"
        assert parse_qs(uri.query) == {
            "ssl_cert_reqs": ["required"],
            "ssl_check_hostname": ["true"],
            "ssl_ca_certs": [trust],
        }
    assert urlsplit(environment["AUTH_SESSION_REDIS_URL"]).scheme == "rediss"
    assert not urlsplit(environment["AUTH_SESSION_REDIS_URL"]).query
    assert environment["SMTP_USE_TLS"] == "false" and environment["SMTP_USE_STARTTLS"] == "true"
    projected = bundle.dev_config.component_environment(environment, "frontend")
    for key in (
        "DATABASE_URL",
        "NATIVE_JWT_PRIVATE_KEY",
        "NATIVE_SECURITY_OUTBOX_KEY",
        "SMTP_PASSWORD",
        "AI_CONFIG_ENCRYPTION_KEY",
    ):
        assert key not in projected
    session = urlsplit(projected["AUTH_SESSION_REDIS_URL"])
    broker = urlsplit(environment["CELERY_BROKER_URL"])
    assert session.username == "sbom_session" and broker.username == "sbom_runtime"
    assert unquote(session.password) != unquote(broker.password)
    assert not any(unquote(broker.password) in value for value in projected.values())
    public = json.dumps(result.to_dict()) + repr(result) + repr(result.receipt)
    assert str(root) not in public and "synthetic-jwt" not in public
    assert fixture.plan.private_binding not in public


@pytest.mark.parametrize("auth_mode", ["native", "hcl"])
def test_frontend_redis_credential_is_independent_and_scoped_to_its_session_namespace(
    fixture, synthetic_crypto, auth_mode
):
    proposal = provider_plan(auth_mode=auth_mode)
    registration = (
        bundle.HclRegistration(
            "7" * 64,
            "https://identity.invalid/realm",
            "operator-api-audience",
            "operator-client-id",
            proposal.descriptor.origin + "/api/auth/callback",
            "openid profile email",
            post_logout_redirect_uri=proposal.descriptor.origin + "/logged-out",
        )
        if auth_mode == "hcl"
        else None
    )
    planned = bundle.plan_bundle(
        proposal,
        fixture.source,
        anchor=fixture.plan.anchor,
        generation=GENERATION,
        profiles=compose._PROFILES,
        registration=registration,
    )
    material = fake_material(planned)
    environment = bundle._validate_material(planned, material)
    projected = bundle.dev_config.component_environment(environment, "frontend")
    session = urlsplit(projected["AUTH_SESSION_REDIS_URL"])
    broker = urlsplit(environment["CELERY_BROKER_URL"])
    assert session.username == "sbom_session" and session.path == "/1"
    assert broker.username == "sbom_runtime" and broker.path == "/0"
    assert unquote(session.password).encode() == material.secrets["redis-session"]
    assert unquote(broker.password).encode() == material.secrets["redis"]
    assert unquote(session.password) != unquote(broker.password)
    assert not any(unquote(broker.password) in value for value in projected.values())
    name = "provider/" + compose.secret_layout(proposal)["redis"]["config"]
    acl = next(
        line.split()
        for line in material.files[name].decode("ascii").splitlines()
        if line.startswith("user sbom_session ")
    )
    assert acl[:5] == [
        "user",
        "sbom_session",
        "on",
        ">" + material.secrets["redis-session"].decode("ascii"),
        "~" + proposal.descriptor.resources["session_namespace"] + "*",
    ]
    assert set(acl[5:]) == {
        "-@all",
        "+get",
        "+set",
        "+del",
        "+exists",
        "+eval",
        "+evalsha",
        "+ping",
        "+auth",
        "+select",
        "+hello",
        "+client|setinfo",
        "+client|setname",
    }
    assert "~*" not in acl and "&*" not in acl
    assert "user default off\n" in material.files[name].decode("ascii")
    assert material.secrets["redis"].decode("ascii") not in " ".join(acl)
    assert (
        base64.b64decode(environment["AI_CONFIG_ENCRYPTION_KEY"], validate=True) == material.secrets["provider-storage"]
    )
    assert "AI_CONFIG_ENCRYPTION_KEY" not in projected
    assert not any(environment["AI_CONFIG_ENCRYPTION_KEY"] in value for value in projected.values())


def test_valid_existing_receipt_reuses_exact_files_without_consent_generation_or_rotation(fixture, synthetic_crypto):
    first = bundle.prepare_bundle(fixture.plan, authorize=approve, generator=fake_material)
    before = {
        str(path): (path.stat().st_ino, path.read_bytes())
        for path in fixture.plan.directory.rglob("*")
        if path.is_file()
    }
    forbidden = Mock(side_effect=AssertionError("Known bundle was regenerated or rewritten"))
    second = bundle.prepare_bundle(
        fixture.plan, authorize=forbidden, generator=forbidden, expected_receipt=first.receipt
    )
    assert second.code == "BUNDLE_EXISTING_VERIFIED" and second.exit_code == 0 and second.reused
    assert second.receipt == first.receipt
    assert before == {
        str(path): (path.stat().st_ino, path.read_bytes())
        for path in fixture.plan.directory.rglob("*")
        if path.is_file()
    }
    forbidden.assert_not_called()


@pytest.mark.parametrize("size", [300 * 1024, 600 * 1024, 1024 * 1024])
def test_combined_trust_bundle_has_its_own_bounded_publication_and_reuse_limit(fixture, monkeypatch, size):
    original = fake_material(fixture.plan)
    files = dict(original.files)
    files["tls/trust-bundle.pem"] = b"synthetic-combined-public-ca-store\n".ljust(size, b"A")
    material = bundle.BundleMaterial(files, original.secrets)

    def validate(current, observed):
        # Only the PEM parser is replaced; publication, bounded reads and receipt
        # verification remain real. No CA/private-key generation is performed.
        assert current == fixture.plan
        assert observed.files == material.files and observed.secrets == material.secrets

    crypto = Mock(side_effect=validate)
    monkeypatch.setattr(bundle, "_validate_crypto", crypto)
    generated = Mock(return_value=material)
    first = bundle.prepare_bundle(fixture.plan, authorize=approve, generator=generated)
    assert first.code == "BUNDLE_PREPARED" and first.exit_code == 0 and first.receipt is not None
    trust = fixture.plan.directory / "tls/trust-bundle.pem"
    before = (trust.stat().st_ino, trust.read_bytes())
    assert len(before[1]) == size
    assert bundle._file(trust, fixture.plan.directory)[0] == before[1]
    forbidden = Mock(side_effect=AssertionError("Known large trust store must never regenerate"))
    reused = bundle.prepare_bundle(
        fixture.plan, authorize=forbidden, generator=forbidden, expected_receipt=first.receipt
    )
    assert reused.code == "BUNDLE_EXISTING_VERIFIED" and reused.reused and reused.receipt == first.receipt
    assert before == (trust.stat().st_ino, trust.read_bytes())
    assert crypto.call_count == 2
    generated.assert_called_once_with(fixture.plan)
    forbidden.assert_not_called()


@pytest.mark.parametrize(
    "name,size",
    [
        ("tls/trust-bundle.pem", 1024 * 1024 + 1),
        ("tls/ca.pem", 256 * 1024 + 1),
        ("keys/auth-transaction-key", 256 * 1024 + 1),
    ],
)
def test_oversized_trust_store_or_individual_key_is_rejected_before_payload_publication(fixture, name, size):
    def generate(current):
        original = fake_material(current)
        files = dict(original.files)
        files[name] = b"A" * size
        return bundle.BundleMaterial(files, original.secrets)

    result = bundle.prepare_bundle(fixture.plan, authorize=approve, generator=generate)
    assert result.code == "BUNDLE_MATERIAL_INVALID" and result.exit_code == 1 and result.artifacts_retained
    assert {path.name for path in fixture.plan.directory.iterdir()} == {".pending.json"}


def test_even_a_complete_bundle_is_not_adopted_without_pinned_receipt(fixture, synthetic_crypto):
    first = bundle.prepare_bundle(fixture.plan, authorize=approve, generator=fake_material)
    assert first.exit_code == 0
    forbidden = Mock(side_effect=AssertionError("Unknown bundle must not be repaired or rotated"))
    result = bundle.prepare_bundle(fixture.plan, authorize=forbidden, generator=forbidden)
    assert result.code == "BUNDLE_EXISTING_BUNDLE_UNVERIFIED" and result.artifacts_retained
    forbidden.assert_not_called()


@pytest.mark.parametrize("changed", ["file", "receipt", "unknown", "directory"])
def test_changed_or_unknown_existing_artifact_is_preserved_and_refused(fixture, synthetic_crypto, changed):
    first = bundle.prepare_bundle(fixture.plan, authorize=approve, generator=fake_material)
    assert first.exit_code == 0
    root = fixture.plan.directory
    if changed == "file":
        target = root / "keys/auth-transaction-key"
        target.write_bytes(b"changed-synthetic-fixture")
    elif changed == "receipt":
        target = root / bundle._RECEIPT
        target.write_bytes(b"changed-synthetic-receipt")
    elif changed == "unknown":
        target = root / "preserve-unknown"
        target.write_text(SECRET, encoding="ascii")
    else:
        target = root / "provider"
        if os.name != "nt":
            target.chmod(0o750)  # Deliberately corrupt only this brand-new fixture.
        else:
            target = root / "provider" / "unknown-fixture"
            target.write_text(SECRET, encoding="ascii")
    before = target.read_bytes() if target.is_file() else target.stat().st_mode
    forbidden = Mock(side_effect=AssertionError("Modified bundle was regenerated"))
    result = bundle.prepare_bundle(
        fixture.plan, authorize=forbidden, generator=forbidden, expected_receipt=first.receipt
    )
    assert result.exit_code == 1 and result.artifacts_retained
    assert before == (target.read_bytes() if target.is_file() else target.stat().st_mode)
    assert SECRET not in json.dumps(result.to_dict())
    forbidden.assert_not_called()


def test_other_generation_is_not_silently_rotated_or_adopted(fixture, synthetic_crypto):
    first = bundle.prepare_bundle(fixture.plan, authorize=approve, generator=fake_material)
    assert first.exit_code == 0
    changed = bundle.plan_bundle(
        fixture.provider,
        fixture.source,
        anchor=fixture.plan.anchor,
        generation=OTHER_GENERATION,
        profiles=compose._PROFILES,
    )
    generated = Mock(side_effect=fake_material)
    result = bundle.prepare_bundle(changed, authorize=approve, generator=generated)
    assert result.code == "BUNDLE_EXISTING_GENERATION_REVIEW_REQUIRED"
    assert fixture.plan.directory.exists() and not changed.directory.exists()
    generated.assert_not_called()


@pytest.mark.parametrize("drift", ["head", "controller", "plan"])
def test_source_or_generation_drift_after_consent_aborts_before_new_files(fixture, monkeypatch, drift):
    plan = fixture.plan
    generated = Mock(side_effect=fake_material)

    def authorize(candidate, category):
        if drift == "head":
            selected = replace(fixture.selected, head="9" * 40)
            fixture.discover.return_value = replace(fixture.snapshot, worktrees=(selected,))
        elif drift == "controller":
            monkeypatch.setattr(bundle, "_controllers", lambda: tuple((name, "9" * 64) for name in bundle._CONTROLLERS))
        return True

    if drift == "plan":
        plan = replace(plan, generation=OTHER_GENERATION)
    result = bundle.prepare_bundle(plan, authorize=authorize, generator=generated)
    assert result.exit_code == 1 and not (fixture.anchor / ".sbom-dev").exists()
    generated.assert_not_called()


def test_partial_publication_is_retained_and_retry_cannot_regenerate(fixture, synthetic_crypto, monkeypatch):
    original = bundle._write
    calls = 0

    def interrupted(path, *arguments):
        nonlocal calls
        calls += 1
        if calls == 5:
            raise OSError(SECRET)
        return original(path, *arguments)

    monkeypatch.setattr(bundle, "_write", interrupted)
    generated = Mock(side_effect=fake_material)
    failed = bundle.prepare_bundle(fixture.plan, authorize=approve, generator=generated)
    assert failed.exit_code == 1 and failed.artifacts_retained
    assert (fixture.plan.directory / bundle._JOURNAL).is_file()
    assert not (fixture.plan.directory / bundle._RECEIPT).exists()
    before = {str(path): path.read_bytes() for path in fixture.plan.directory.rglob("*") if path.is_file()}
    retried = bundle.prepare_bundle(fixture.plan, authorize=approve, generator=generated)
    assert retried.code == "BUNDLE_EXISTING_BUNDLE_UNVERIFIED"
    assert generated.call_count == 1
    assert before == {str(path): path.read_bytes() for path in fixture.plan.directory.rglob("*") if path.is_file()}
    assert SECRET not in json.dumps(failed.to_dict())


def test_real_crypto_parser_rejects_fake_material_before_any_secret_file_is_published(fixture):
    result = bundle.prepare_bundle(fixture.plan, authorize=approve, generator=fake_material)
    assert result.code == "BUNDLE_CRYPTO_MATERIAL_INVALID" and result.exit_code == 1
    assert (fixture.plan.directory / bundle._JOURNAL).is_file()
    assert not (fixture.plan.directory / "provider").exists()
    assert not (fixture.plan.directory / bundle._MANAGED).exists()


@pytest.mark.parametrize(
    "change",
    [
        "shared",
        "redis-session-shared",
        "provider-storage-shared",
        "provider-storage-short",
        "short",
        "payload",
        "layout",
    ],
)
def test_material_independence_and_exact_provider_security_payload_are_mandatory(fixture, synthetic_crypto, change):
    material = fake_material(fixture.plan)
    if change == "shared":
        material = replace(material, secrets={**material.secrets, "outbox": material.secrets["session"]})
    elif change == "redis-session-shared":
        material = replace(material, secrets={**material.secrets, "redis-session": material.secrets["redis"]})
    elif change == "provider-storage-shared":
        material = replace(material, secrets={**material.secrets, "provider-storage": material.secrets["session"]})
    elif change == "provider-storage-short":
        material = replace(material, secrets={**material.secrets, "provider-storage": b"P" * 31})
    elif change == "short":
        material = replace(material, secrets={**material.secrets, "session": b"short"})
    elif change == "payload":
        name = "provider/" + compose.secret_layout(fixture.provider)["redis"]["config"]
        material = replace(material, files={**material.files, name: b"protected-mode no\n"})
    else:
        material = replace(material, files={**material.files, "extra": SECRET.encode()})
    result = bundle.prepare_bundle(fixture.plan, authorize=approve, generator=lambda plan: material)
    assert result.exit_code == 1 and not (fixture.plan.directory / bundle._MANAGED).exists()
    assert SECRET not in json.dumps(result.to_dict())


def test_hcl_uses_only_exact_operator_registration_and_never_creates_native_keys(fixture, synthetic_crypto):
    original = provider_plan(auth_mode="hcl")
    registration = bundle.HclRegistration(
        "7" * 64,
        "https://identity.invalid/realm",
        "operator-api-audience",
        "operator-client-id",
        original.descriptor.origin + "/api/auth/callback",
        "openid profile email",
        post_logout_redirect_uri=original.descriptor.origin + "/logged-out",
    )
    plan = bundle.plan_bundle(
        original,
        fixture.source,
        anchor=fixture.plan.anchor,
        generation=GENERATION,
        profiles=compose._PROFILES,
        registration=registration,
    )
    assert "identity.invalid" not in json.dumps(plan.to_dict()) + repr(registration)
    result = bundle.prepare_bundle(plan, authorize=approve, generator=fake_material)
    assert result.exit_code == 0
    env = bundle.dev_config.parse_managed((plan.directory / bundle._MANAGED).read_text(encoding="ascii"))
    assert env["HCL_IAM_ISSUER"] == registration.issuer and env["HCL_IAM_AUDIENCE"] == registration.audience
    assert env["NEXT_PUBLIC_HCL_IAM_CLIENT_ID"] == registration.client_id
    assert env["NEXT_PUBLIC_HCL_IAM_REDIRECT_URI"] == registration.redirect_uri
    assert env["NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_REDIRECT_URI"] == registration.post_logout_redirect_uri
    assert env["EMAIL_VERIFICATION_FRONTEND_URL"] == original.descriptor.origin + "/verify-email"
    assert env["NATIVE_AUTH_ENABLED"] == "false" and env["HCL_AUTH_ENABLED"] == "true"
    assert env["NATIVE_PLATFORM_BOOTSTRAP_ENABLED"] == "false"
    assert "NATIVE_JWT_PRIVATE_KEY" not in env and not (plan.directory / "keys/native-jwt-private.pem").exists()


def test_hcl_registration_absence_mismatch_and_credentials_are_never_invented(fixture):
    source = provider_plan(auth_mode="hcl")
    with pytest.raises(bundle.BundleError, match="BUNDLE_HCL_REGISTRATION_REQUIRED"):
        bundle.plan_bundle(
            source, fixture.source, anchor=fixture.plan.anchor, generation=GENERATION, profiles=compose._PROFILES
        )
    registration = bundle.HclRegistration(
        "7" * 64, "https://identity.invalid", "audience", "client", "https://wrong.invalid/callback", "openid"
    )
    with pytest.raises(bundle.BundleError, match="BUNDLE_HCL_REDIRECT_REGISTRATION_REQUIRED"):
        bundle.plan_bundle(
            source,
            fixture.source,
            anchor=fixture.plan.anchor,
            generation=GENERATION,
            profiles=compose._PROFILES,
            registration=registration,
        )
    with pytest.raises(TypeError):
        bundle.HclRegistration(
            "7" * 64,
            "https://identity.invalid",
            "audience",
            "client",
            "https://wrong.invalid",
            "openid",
            client_secret=SECRET,
        )


@pytest.mark.parametrize(
    "logout",
    [None, "https://localhost:3000/logged-out", "https://foreign.invalid/logged-out"],
)
def test_hcl_logout_must_be_independently_supplied_for_this_exact_instance(fixture, logout):
    source = provider_plan(auth_mode="hcl")
    registration = bundle.HclRegistration(
        "7" * 64,
        "https://identity.invalid",
        "operator-audience",
        "operator-client",
        source.descriptor.origin + "/api/auth/callback",
        "openid",
        post_logout_redirect_uri=logout,
    )
    with pytest.raises(bundle.BundleError, match="^BUNDLE_HCL_LOGOUT_REGISTRATION_REQUIRED$"):
        bundle.plan_bundle(
            source,
            fixture.source,
            anchor=fixture.plan.anchor,
            generation=GENERATION,
            profiles=compose._PROFILES,
            registration=registration,
        )
    assert not (fixture.anchor / ".sbom-dev").exists()


@pytest.mark.parametrize(
    "logout",
    [
        "",
        "http://identity.invalid/logout",
        "https://user:secret@identity.invalid/logout",
        "https://identity.invalid/logout?token",
        "https://identity.invalid/#token",
        True,
    ],
)
def test_hcl_logout_rejects_unsafe_registration_values_without_disclosing_them(logout):
    with pytest.raises(bundle.BundleError, match="^BUNDLE_HCL_REGISTRATION_INVALID$") as caught:
        bundle.HclRegistration(
            "7" * 64,
            "https://identity.invalid",
            "operator-audience",
            "operator-client",
            "https://instance.invalid/api/auth/callback",
            "openid",
            post_logout_redirect_uri=logout,
        )
    assert "secret" not in str(caught.value) and "token" not in str(caught.value)


def test_hcl_logout_projection_matches_real_server_config_and_preserves_positional_ca(fixture, synthetic_crypto):
    source = provider_plan(auth_mode="hcl")
    registration = bundle.HclRegistration(
        "7" * 64,
        "https://identity.invalid",
        "operator-audience",
        "operator-client",
        source.descriptor.origin + "/api/auth/callback",
        "openid",
        b"synthetic-operator-ca",
        post_logout_redirect_uri=source.descriptor.origin + "/logged-out",
    )
    assert registration.ca_pem == b"synthetic-operator-ca"
    planned = bundle.plan_bundle(
        source,
        fixture.source,
        anchor=fixture.plan.anchor,
        generation=GENERATION,
        profiles=compose._PROFILES,
        registration=registration,
    )
    environment = bundle._validate_material(planned, fake_material(planned))
    projected = bundle.dev_config.component_environment(environment, "frontend")
    public = bundle.dev_config.component_environment(environment, "public")
    frontend = Path(__file__).resolve().parents[1] / "frontend/src"
    consumer = (frontend / "lib/auth/server-config.ts").read_text(encoding="utf-8")
    # Read the actual consumer's ordered keys and fallback, not duplicated names.
    match = re.search(
        r"postLogoutRedirectUri:\s*process\.env\.([A-Z_]+)\s*\|\|\s*"
        r"process\.env\.([A-Z_]+)\s*\|\|\s*'([^']+)'",
        consumer,
    )
    assert match is not None
    primary, alias, fallback = match.groups()
    assert primary in projected and public[primary] == projected[primary]
    assert (projected.get(primary) or projected.get(alias) or fallback) == registration.post_logout_redirect_uri
    logout_consumer = (frontend / "app/api/auth/logout/route.ts").read_text(encoding="utf-8")
    assert "endSession.searchParams.set('post_logout_redirect_uri', config.postLogoutRedirectUri)" in logout_consumer
    assert environment["EMAIL_VERIFICATION_FRONTEND_URL"] == source.descriptor.origin + "/verify-email"
    changed = replace(registration, post_logout_redirect_uri=None)
    changed_bindings = bundle._bindings(
        source, fixture.source, fixture.plan.anchor, GENERATION, compose._PROFILES, changed, 30
    )
    assert all(
        actual != previous
        for actual, previous in zip(
            changed_bindings,
            (planned.fingerprint, planned.material_fingerprint, planned.private_binding),
            strict=True,
        )
    )


@pytest.mark.parametrize("category", ["credentials", "certificates"])
def test_hcl_logout_drift_after_consent_never_reaches_generation_or_publication(fixture, category):
    source = provider_plan(auth_mode="hcl")
    registration = bundle.HclRegistration(
        "7" * 64,
        "https://identity.invalid",
        "operator-audience",
        "operator-client",
        source.descriptor.origin + "/api/auth/callback",
        "openid",
        post_logout_redirect_uri=source.descriptor.origin + "/logged-out",
    )
    planned = bundle.plan_bundle(
        source,
        fixture.source,
        anchor=fixture.plan.anchor,
        generation=GENERATION,
        profiles=compose._PROFILES,
        registration=registration,
    )

    def authorize(candidate, requested):
        if requested == category:
            # Model a hostile caller defeating the immutable value object's API.
            object.__setattr__(candidate.registration, "post_logout_redirect_uri", "https://foreign.invalid/logout")
        return True

    forbidden = Mock(side_effect=AssertionError("Changed registration reached key generation"))
    result = bundle.prepare_bundle(planned, authorize=authorize, generator=forbidden)
    assert result.code == "BUNDLE_HCL_LOGOUT_REGISTRATION_REQUIRED" and result.exit_code == 1
    assert not (fixture.anchor / ".sbom-dev").exists()
    assert "foreign.invalid" not in json.dumps(result.to_dict())
    forbidden.assert_not_called()


def test_known_artifacts_survive_normal_source_head_advance_without_key_rotation(fixture, synthetic_crypto):
    first = bundle.prepare_bundle(fixture.plan, authorize=approve, generator=fake_material)
    assert first.exit_code == 0
    selected = replace(fixture.selected, head="8" * 40)
    fixture.discover.return_value = replace(fixture.snapshot, worktrees=(selected,))
    updated = provider_plan(commit="8" * 40)
    source = bundle.inspect_source(fixture.root)
    plan = bundle.plan_bundle(
        updated, source, anchor=fixture.plan.anchor, generation=GENERATION, profiles=compose._PROFILES
    )
    assert plan.fingerprint != fixture.plan.fingerprint
    assert plan.material_fingerprint == fixture.plan.material_fingerprint
    forbidden = Mock(side_effect=AssertionError("Source commit must not rotate existing keys"))
    reused = bundle.prepare_bundle(plan, authorize=forbidden, generator=forbidden, expected_receipt=first.receipt)
    assert reused.code == "BUNDLE_EXISTING_VERIFIED" and reused.reused
    forbidden.assert_not_called()


def test_concurrent_generation_cannot_acquire_writer_or_generate_more_material(fixture, synthetic_crypto):
    other = bundle.plan_bundle(
        fixture.provider,
        fixture.source,
        anchor=fixture.plan.anchor,
        generation=OTHER_GENERATION,
        profiles=compose._PROFILES,
    )
    nested = []
    child_generator = Mock(side_effect=AssertionError("Concurrent writer generated material"))

    def generate(plan):
        nested.append(bundle.prepare_bundle(other, authorize=approve, generator=child_generator))
        return fake_material(plan)

    result = bundle.prepare_bundle(fixture.plan, authorize=approve, generator=generate)
    assert result.exit_code == 0
    assert nested[0].exit_code == 1 and nested[0].code == "BUNDLE_BUSY"
    assert not other.directory.exists()
    child_generator.assert_not_called()


def test_private_compose_layout_and_receipt_transport_do_not_publish_source_paths(fixture, synthetic_crypto):
    files = bundle.compose_secret_files(fixture.plan, host_platform="win32" if os.name == "nt" else "linux")
    assert len(files) == 14
    assert all(Path(item.source).is_relative_to(fixture.plan.directory / "provider") for item in files)
    assert str(fixture.anchor) not in repr(files)
    assert fixture.plan.configuration_path == fixture.plan.directory / ".env.dev.local"
    result = bundle.prepare_bundle(fixture.plan, authorize=approve, generator=fake_material)
    assert result.exit_code == 0
    record = result.receipt.private_record()
    assert bundle.BundleReceipt.from_private_record(json.loads(json.dumps(record))) == result.receipt
    assert result.receipt.private_binding not in json.dumps(result.to_dict())
    malformed = {**record, "version": True}
    with pytest.raises(bundle.BundleError, match="^BUNDLE_RECEIPT_UNVERIFIED$"):
        bundle.BundleReceipt.from_private_record(malformed)


@pytest.mark.parametrize("generation", ["", SECRET, "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE", False, 1, None])
def test_generation_is_an_exact_opaque_uuid_not_a_value_or_path_hash(fixture, generation):
    with pytest.raises(bundle.BundleError, match="^BUNDLE_GENERATION_INVALID$") as caught:
        bundle.plan_bundle(
            fixture.provider,
            fixture.source,
            anchor=fixture.plan.anchor,
            generation=generation,
            profiles=compose._PROFILES,
        )
    assert SECRET not in str(caught.value)


def test_private_bundle_cannot_be_placed_inside_source_checkout(fixture):
    with pytest.raises(bundle.BundleError, match="^BUNDLE_OUTSIDE_CHECKOUT_REQUIRED$"):
        bundle.plan_bundle(
            fixture.provider,
            fixture.source,
            anchor=dev_workspace._identity(fixture.root),
            generation=GENERATION,
            profiles=compose._PROFILES,
        )


def test_truthy_authorization_marker_is_not_explicit_true(fixture):
    generated = Mock(side_effect=fake_material)
    result = bundle.prepare_bundle(fixture.plan, authorize=lambda *arguments: 1, generator=generated)
    assert result.code == "BUNDLE_CREDENTIALS_AUTHORIZATION_REQUIRED"
    assert not (fixture.anchor / ".sbom-dev").exists()
    generated.assert_not_called()


def test_same_receipt_content_with_replaced_file_identity_is_not_adopted(fixture, synthetic_crypto):
    result = bundle.prepare_bundle(fixture.plan, authorize=approve, generator=fake_material)
    assert result.exit_code == 0
    path = fixture.plan.directory / bundle._RECEIPT
    raw = path.read_bytes()
    path.unlink()  # Only this new synthetic fixture; no real/runtime record.
    bundle.dev_private.create_private_file(path, raw)
    assert bundle._file(path, fixture.plan.directory)[1] != result.receipt.receipt_proof
    reused = bundle.prepare_bundle(
        fixture.plan, authorize=approve, generator=fake_material, expected_receipt=result.receipt
    )
    assert reused.code == "BUNDLE_RECEIPT_IDENTITY_CHANGED" and reused.artifacts_retained
    assert path.read_bytes() == raw


def test_hardlinked_secret_file_is_protected_even_when_content_is_unchanged(fixture, synthetic_crypto):
    result = bundle.prepare_bundle(fixture.plan, authorize=approve, generator=fake_material)
    assert result.exit_code == 0
    target = fixture.plan.directory / "keys/auth-transaction-key"
    original = target.read_bytes()
    os.link(target, fixture.temporary / "fixture-hardlink")
    reused = bundle.prepare_bundle(
        fixture.plan, authorize=approve, generator=fake_material, expected_receipt=result.receipt
    )
    assert reused.exit_code == 1 and reused.artifacts_retained
    assert target.read_bytes() == original


def test_redirected_private_parent_never_receives_payload_or_acl_repairs(fixture):
    outside = fixture.temporary / "outside"
    if os.name == "nt":
        import _winapi

        bundle.dev_instance_storage._windows_create(outside)
        _winapi.CreateJunction(str(outside), str(fixture.anchor / ".sbom-dev"))
    else:
        outside.mkdir(mode=0o700)
        (fixture.anchor / ".sbom-dev").symlink_to(outside, target_is_directory=True)
    try:
        generated = Mock(side_effect=fake_material)
        result = bundle.prepare_bundle(fixture.plan, authorize=approve, generator=generated)
        assert result.exit_code == 1 and not list(outside.iterdir())
        generated.assert_not_called()
    finally:
        link = fixture.anchor / ".sbom-dev"
        if os.name == "nt":
            os.rmdir(link)  # Verified fixture junction entry only; never its target.
        else:
            link.unlink()


@pytest.mark.parametrize(
    "issuer",
    [
        "http://identity.invalid",
        "https://user:secret@identity.invalid",
        "https://identity.invalid?secret",
        "https://identity.invalid/#secret",
    ],
)
def test_hcl_issuer_must_be_explicit_https_without_credentials_or_query(issuer):
    with pytest.raises(bundle.BundleError, match="^BUNDLE_HCL_REGISTRATION_INVALID$") as caught:
        bundle.HclRegistration("7" * 64, issuer, "audience", "client", "https://synthetic.invalid/callback", "openid")
    assert issuer not in str(caught.value)


def test_known_receipt_cannot_be_reused_for_a_changed_private_hcl_registration(fixture, synthetic_crypto):
    original = provider_plan(auth_mode="hcl")
    registration = bundle.HclRegistration(
        "7" * 64,
        "https://identity.invalid/realm",
        "audience",
        "client",
        original.descriptor.origin + "/api/auth/callback",
        "openid",
        post_logout_redirect_uri=original.descriptor.origin + "/logged-out",
    )
    plan = bundle.plan_bundle(
        original,
        fixture.source,
        anchor=fixture.plan.anchor,
        generation=GENERATION,
        profiles=compose._PROFILES,
        registration=registration,
    )
    result = bundle.prepare_bundle(plan, authorize=approve, generator=fake_material)
    assert result.exit_code == 0
    changed = bundle.plan_bundle(
        original,
        fixture.source,
        anchor=fixture.plan.anchor,
        generation=GENERATION,
        profiles=compose._PROFILES,
        registration=replace(registration, issuer="https://changed.invalid/realm"),
    )
    assert changed.fingerprint == plan.fingerprint and changed.private_binding != plan.private_binding
    reused = bundle.prepare_bundle(changed, authorize=approve, generator=fake_material, expected_receipt=result.receipt)
    assert reused.code == "BUNDLE_RECEIPT_CONTEXT_CHANGED"
    assert "identity.invalid" not in json.dumps(plan.to_dict()) and "changed.invalid" not in json.dumps(
        changed.to_dict()
    )


def test_ambient_ssl_keylog_is_never_looked_up_or_copied_into_bundle(fixture, synthetic_crypto, monkeypatch):
    import ssl

    keylog = fixture.temporary / "must-not-be-created-keylog"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    forbidden = Mock(side_effect=AssertionError("No ambient SSL context or keylog lookup"))
    monkeypatch.setattr(ssl, "create_default_context", forbidden)
    result = bundle.prepare_bundle(fixture.plan, authorize=approve, generator=fake_material)
    assert result.exit_code == 0 and not keylog.exists()
    environment = bundle.dev_config.parse_managed(fixture.plan.configuration_path.read_text(encoding="ascii"))
    assert "SSLKEYLOGFILE" not in environment
    generator = next(
        node
        for node in ast.parse(Path(bundle.__file__).read_text(encoding="utf-8")).body
        if isinstance(node, ast.FunctionDef) and node.name == "generate_material"
    )
    assert not any(
        isinstance(node, ast.Attribute) and node.attr in {"create_default_context", "SSLContext", "keylog_filename"}
        for node in ast.walk(generator)
    )
    forbidden.assert_not_called()


@pytest.fixture
def crypto_parser(fixture, monkeypatch):
    """Strict Python doubles exercise production crypto invariants, no keygen."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID

    class Public:
        def __init__(self, number):
            self.number = number

        def public_numbers(self):
            return SimpleNamespace(n=self.number, e=65537)

        def verify(self, signature, *arguments):
            if signature != b"valid-synthetic-signature":
                raise ValueError(SECRET)

    class Private:
        key_size = 3072

        def __init__(self, number):
            self.number = number

        def public_key(self):
            return Public(self.number)

        def private_numbers(self):
            return SimpleNamespace(public_numbers=self.public_key().public_numbers())

    class Extensions:
        def __init__(self, values):
            self.values = values

        def get_extension_for_class(self, kind):
            return SimpleNamespace(value=self.values[kind])

    subject = SimpleNamespace(
        get_attributes_for_oid=lambda kind: [
            SimpleNamespace(value="SBOM development " + fixture.provider.descriptor.instance_id)
        ]
    )
    now = datetime.now(UTC)
    ca = SimpleNamespace(
        subject=subject,
        issuer=subject,
        public_key=lambda: Public(1),
        signature=b"valid-synthetic-signature",
        tbs_certificate_bytes=b"synthetic-tbs",
        signature_hash_algorithm=SimpleNamespace(name="sha256"),
        not_valid_before_utc=now - timedelta(minutes=1),
        not_valid_after_utc=now + timedelta(days=1),
        extensions=Extensions(
            {
                x509.BasicConstraints: SimpleNamespace(ca=True, path_length=0),
                x509.KeyUsage: SimpleNamespace(key_cert_sign=True),
                x509.SubjectKeyIdentifier: SimpleNamespace(digest=b"synthetic-ca-id"),
            }
        ),
    )
    material = fake_material(fixture.plan)
    certificates = {material.files["tls/ca.pem"]: ca}
    keys = {material.files["tls/ca-key.pem"]: Private(1), material.files["keys/native-jwt-private.pem"]: Private(9)}
    public_keys = {material.files["keys/native-jwt-public.pem"]: Public(9)}
    leaves = []
    layout = compose.secret_layout(fixture.provider)
    pairs = [
        ("tls/frontend-key.pem", "tls/frontend-cert.pem"),
        *(("provider/" + values["key"], "provider/" + values["cert"]) for values in layout.values()),
    ]
    for number, (key_name, cert_name) in enumerate(pairs, 2):
        leaf = SimpleNamespace(
            subject=subject,
            issuer=subject,
            public_key=lambda number=number: Public(number),
            signature=b"valid-synthetic-signature",
            tbs_certificate_bytes=b"synthetic-tbs",
            signature_hash_algorithm=SimpleNamespace(name="sha256"),
            not_valid_before_utc=now - timedelta(minutes=1),
            not_valid_after_utc=now + timedelta(hours=12),
            extensions=Extensions(
                {
                    x509.BasicConstraints: SimpleNamespace(ca=False),
                    x509.KeyUsage: SimpleNamespace(digital_signature=True, key_cert_sign=False),
                    x509.AuthorityKeyIdentifier: SimpleNamespace(key_identifier=b"synthetic-ca-id"),
                    x509.SubjectAlternativeName: x509.SubjectAlternativeName(
                        [
                            x509.DNSName(fixture.provider.descriptor.hostname),
                            x509.DNSName("localhost"),
                            x509.IPAddress(ip_address("127.0.0.1")),
                        ]
                    ),
                    x509.ExtendedKeyUsage: {ExtendedKeyUsageOID.SERVER_AUTH},
                }
            ),
        )
        certificates[material.files[cert_name]], keys[material.files[key_name]] = leaf, Private(number)
        leaves.append(leaf)
    monkeypatch.setattr(rsa, "RSAPrivateKey", Private)
    monkeypatch.setattr(rsa, "generate_private_key", Mock(side_effect=AssertionError("No real key generation")))
    monkeypatch.setattr(x509, "load_pem_x509_certificate", lambda raw: certificates[raw])
    monkeypatch.setattr(x509, "load_pem_x509_certificates", lambda raw: [ca])
    monkeypatch.setattr(serialization, "load_pem_private_key", lambda raw, password: keys[raw])
    monkeypatch.setattr(serialization, "load_pem_public_key", lambda raw: public_keys[raw])
    return SimpleNamespace(
        material=material,
        ca=ca,
        leaves=leaves,
        keys=keys,
        public_keys=public_keys,
        Private=Private,
        Public=Public,
        x509=x509,
    )


def test_production_crypto_invariant_checks_accept_matching_synthetic_parser_objects(fixture, crypto_parser):
    # Calls the real validator; only parser/key objects are replaced, never its checks.
    bundle._validate_crypto(fixture.plan, crypto_parser.material)


def test_direct_module_invocation_cannot_prepare_or_generate_material(monkeypatch):
    import secrets

    from cryptography.hazmat.primitives.asymmetric import rsa

    source = Path(bundle.__file__).read_text(encoding="utf-8")
    module = types.ModuleType("__main__")
    module.__package__ = "scripts"
    monkeypatch.setitem(sys.modules, "__main__", module)
    forbidden = Mock(side_effect=AssertionError("Direct module invocation attempted generation or publication"))
    monkeypatch.setattr(secrets, "token_bytes", forbidden)
    monkeypatch.setattr(secrets, "token_urlsafe", forbidden)
    monkeypatch.setattr(rsa, "generate_private_key", forbidden)
    monkeypatch.setattr(os, "open", forbidden)
    monkeypatch.setattr(Path, "mkdir", forbidden)
    with pytest.raises(SystemExit, match="BUNDLE_PREPARATION_ONLY"):
        exec(compile(source, "<synthetic-direct-bundle>", "exec"), module.__dict__)
    forbidden.assert_not_called()


@pytest.mark.parametrize(
    "change",
    [
        "hostname",
        "ip",
        "keypair",
        "leaf-ca",
        "issuer",
        "signature",
        "hash",
        "expiry",
        "long-ca",
        "ca-usage",
        "aki",
        "jwt",
        "shared-key",
    ],
)
def test_production_crypto_invariants_reject_bad_identity_pairs_chain_and_lifetimes(fixture, crypto_parser, change):
    parsed = crypto_parser
    x509, leaf = parsed.x509, parsed.leaves[0]
    if change == "hostname":
        leaf.extensions.values[x509.SubjectAlternativeName] = x509.SubjectAlternativeName(
            [x509.DNSName("wrong.invalid"), x509.IPAddress(ip_address("127.0.0.1"))]
        )
    elif change == "ip":
        leaf.extensions.values[x509.SubjectAlternativeName] = x509.SubjectAlternativeName(
            [x509.DNSName(fixture.provider.descriptor.hostname), x509.DNSName("localhost")]
        )
    elif change == "keypair":
        leaf.public_key = lambda: parsed.Public(999)
    elif change == "leaf-ca":
        leaf.extensions.values[x509.BasicConstraints] = SimpleNamespace(ca=True)
    elif change == "issuer":
        leaf.issuer = "wrong-issuer"
    elif change == "signature":
        leaf.signature = b"invalid-synthetic-signature"
    elif change == "hash":
        leaf.signature_hash_algorithm = SimpleNamespace(name="sha1")
    elif change == "expiry":
        leaf.not_valid_after_utc = datetime.now(UTC) - timedelta(minutes=1)
    elif change == "long-ca":
        parsed.ca.not_valid_after_utc = datetime.now(UTC) + timedelta(days=365)
    elif change == "ca-usage":
        parsed.ca.extensions.values[x509.KeyUsage] = SimpleNamespace(key_cert_sign=False)
    elif change == "aki":
        leaf.extensions.values[x509.AuthorityKeyIdentifier] = SimpleNamespace(key_identifier=b"wrong-ca")
    elif change == "jwt":
        parsed.public_keys[parsed.material.files["keys/native-jwt-public.pem"]] = parsed.Public(999)
    else:
        parsed.keys[parsed.material.files["tls/frontend-key.pem"]] = parsed.Private(1)
        leaf.public_key = lambda: parsed.Public(1)
    with pytest.raises(bundle.BundleError) as caught:
        bundle._validate_crypto(fixture.plan, parsed.material)
    assert caught.value.code.startswith("BUNDLE_") and SECRET not in str(caught.value)
