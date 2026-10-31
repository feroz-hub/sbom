"""Fake TLS material only; native private-file fixtures are new pytest paths."""

from __future__ import annotations

import ast
import builtins
import json
import os
import socket
import ssl
import subprocess
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest
from scripts import dev_instance_plan as instances
from scripts import dev_workspace as workspace
from scripts import dev_workspace_certificates as certificates

PRIVATE = "synthetic-private-key-never-disclose"
FINGERPRINT = "f" * 64
_REAL_GENERATE = certificates.generate_material


def material(plan):
    return certificates.CertificateMaterial(
        b"synthetic-ca-cert", b"synthetic-ca-key", b"synthetic-leaf-cert", b"synthetic-leaf-key"
    )


def approve(plan, category):
    assert category == "certificates"
    return certificates.CertificateConsent(plan.operation_binding, plan.generation, plan.not_after)


@pytest.fixture(autouse=True)
def no_live(monkeypatch):
    denied = Mock(side_effect=AssertionError("Live resources or key generation forbidden"))
    original = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name.split(".")[0] in {"app", "psycopg", "sqlalchemy", "celery", "redis", "docker", "alembic"}:
            return denied(name)
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded)
    monkeypatch.setattr(certificates, "generate_material", denied)
    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(subprocess, "run", denied)
    monkeypatch.setattr(ssl, "create_default_context", denied)
    from cryptography.hazmat.primitives.asymmetric import rsa

    monkeypatch.setattr(rsa, "generate_private_key", denied)
    yield denied
    denied.assert_not_called()


@pytest.fixture
def fixture(tmp_path_factory, monkeypatch):
    temporary = tmp_path_factory.mktemp("t").resolve()
    root, anchor = temporary / "s", temporary / "h"
    for path in (root, anchor):
        if os.name == "nt":
            certificates.storage._windows_create(path)
        else:
            path.mkdir(mode=0o700)
    identity = workspace._identity(root)
    selected = workspace.WorktreeSnapshot(
        "b" * 64, root, identity, "c" * 40, "refs/heads/fixture", False, False, False, False, False
    )
    snapshot = workspace.RepositorySnapshot("a" * 64, root, identity, selected.head, (selected,), identity)
    discovery = Mock(return_value=snapshot)
    monkeypatch.setattr(workspace, "discover_workspaces", discovery)
    source = certificates.inspect_source(root)
    descriptor = instances.plan_instance(
        repository_id="a" * 64, worktree_id="b" * 64, commit="c" * 40, generation=1, mode="mock", auth_mode="native"
    ).descriptor
    plan = certificates.plan_certificates(
        descriptor, source, anchor=workspace._identity(anchor), generation=str(uuid4()), now=datetime.now(UTC)
    )
    return SimpleNamespace(
        temporary=temporary,
        root=root,
        anchor=anchor,
        source=source,
        descriptor=descriptor,
        snapshot=snapshot,
        selected=selected,
        discovery=discovery,
        plan=plan,
    )


@pytest.fixture
def fake_crypto(monkeypatch):
    def check(plan, value):
        if value != material(plan):
            raise certificates.CertificateError("TLS_CRYPTO_INVALID")
        return FINGERPRINT

    mocked = Mock(side_effect=check)
    monkeypatch.setattr(certificates, "_validate_crypto", mocked)
    return mocked


def prepare(fixture, **kwargs):
    return certificates.prepare_certificates(fixture.plan, authorize=approve, generator=material, **kwargs)


def test_pure_plan_needs_no_container_database_configuration_or_io(fixture, monkeypatch):
    blocked = Mock(side_effect=AssertionError("pure plan performed IO"))
    with monkeypatch.context() as guard:
        for name in ("open", "stat", "mkdir"):
            guard.setattr(os, name, blocked)
        for name in ("read_bytes", "read_text", "stat", "resolve", "mkdir"):
            guard.setattr(Path, name, blocked)
        same = certificates.plan_certificates(
            fixture.descriptor,
            fixture.source,
            anchor=fixture.plan.anchor,
            generation=fixture.plan.generation,
            now=fixture.plan.issued_at,
        )
    assert same == fixture.plan
    with pytest.raises(FrozenInstanceError):
        same.certificate_days = 90
    public = json.dumps(same.to_dict()) + repr(same)
    for private in (str(fixture.anchor), same.operation_binding, same.material_binding, PRIVATE):
        assert private not in public
    assert "UNVERIFIED" in public and "provider_policy" not in public


@pytest.mark.parametrize("consent", [None, True, "yes", {"approved": True}])
def test_exact_typed_certificate_consent_precedes_files_and_generator(fixture, consent):
    generator = Mock(side_effect=AssertionError("must not generate"))
    result = certificates.prepare_certificates(fixture.plan, authorize=lambda *args: consent, generator=generator)
    assert result.code == "TLS_AUTHORIZATION_REQUIRED" and not result.artifacts_retained
    assert not (fixture.anchor / ".sbom-dev").exists()
    generator.assert_not_called()


@pytest.mark.parametrize("change", ["binding", "generation", "expiry"])
def test_consent_cannot_be_replayed_for_another_path_generation_or_expiry(fixture, change):
    consent = approve(fixture.plan, "certificates")
    if change == "binding":
        consent = replace(consent, operation_binding="a" * 64)
    elif change == "generation":
        consent = replace(consent, generation=str(uuid4()))
    else:
        consent = replace(consent, expires_at=consent.expires_at + timedelta(days=1))
    result = certificates.prepare_certificates(fixture.plan, authorize=lambda *args: consent, generator=material)
    assert result.code == "TLS_AUTHORIZATION_REQUIRED" and not (fixture.anchor / ".sbom-dev").exists()


def test_native_private_publication_returns_verified_preview_tls_and_typed_receipt(fixture, fake_crypto):
    result = prepare(fixture)
    assert result.code == "TLS_PREPARED" and result.exit_code == 0 and result.certificate_fingerprint == FINGERPRINT
    assert type(result.tls) is certificates.PreviewTls and type(result.receipt) is certificates.CertificateReceipt
    assert result.tls.certificate == fixture.plan.directory / "s.pem"
    assert result.tls.ca_bundle == fixture.plan.directory / "c.pem"
    assert result.tls.private_key == fixture.plan.directory / "s.key"
    assert {p.name for p in fixture.plan.directory.iterdir()} == {*certificates._FILES, "p.json", "r.json"}
    for path in fixture.plan.directory.iterdir():
        certificates.registry._private(path)
    certificates.storage._verify(fixture.plan.directory, private=True)
    public = json.dumps(result.to_dict()) + repr(result) + repr(result.receipt) + repr(result.tls)
    assert str(fixture.anchor) not in public and PRIVATE not in public
    assert fixture.plan.material_binding not in public and "UNVERIFIED" in public
    record = result.receipt.private_record()
    assert certificates.CertificateReceipt.from_private_record(record) == result.receipt
    assert record["generation"] == fixture.plan.generation and record["issued_at"] == fixture.plan.issued_at.isoformat()
    fake_crypto.assert_called_once()


def test_known_exact_receipt_reuse_never_calls_consent_or_generator(fixture, fake_crypto):
    first = prepare(fixture)
    denied = Mock(side_effect=AssertionError("known receipt must not regenerate"))
    reused = certificates.prepare_certificates(
        fixture.plan, authorize=denied, generator=denied, expected_receipt=first.receipt
    )
    assert reused.code == "TLS_EXISTING_VERIFIED" and reused.reused and reused.receipt == first.receipt
    denied.assert_not_called()


def test_head_advance_preserves_known_generation_without_silent_rotation(fixture, fake_crypto):
    first = prepare(fixture)
    selected = replace(fixture.selected, head="d" * 40)
    fixture.discovery.return_value = replace(fixture.snapshot, worktrees=(selected,), head=selected.head)
    source = certificates.inspect_source(fixture.root)
    next_plan = certificates.plan_certificates(
        replace(fixture.descriptor, commit=selected.head),
        source,
        anchor=fixture.plan.anchor,
        generation=first.receipt.generation,
        now=first.receipt.issued_at,
        certificate_days=first.receipt.certificate_days,
    )
    assert next_plan.material_binding == fixture.plan.material_binding
    assert next_plan.operation_binding != fixture.plan.operation_binding
    result = certificates.prepare_certificates(
        next_plan, authorize=approve, generator=material, expected_receipt=first.receipt
    )
    assert result.code == "TLS_EXISTING_VERIFIED" and result.receipt == first.receipt


@pytest.mark.parametrize("change", ["missing-receipt", "file", "new-fid", "extra", "receipt", "directory"])
def test_unknown_or_changed_artifacts_are_preserved_without_repair(fixture, fake_crypto, change):
    first = prepare(fixture)
    receipt = first.receipt
    if change == "missing-receipt":
        receipt = None
    elif change in {"file", "new-fid"}:
        path = fixture.plan.directory / "s.key"
        original = path.read_bytes()
        if change == "new-fid":
            path.rename(path.with_name("old.key"))
            certificates.private.dev_private.create_private_file(path, original)
            path.with_name("old.key").unlink()  # Only this brand-new synthetic fixture file.
        else:
            path.write_bytes(b"changed synthetic fixture")
    elif change == "extra":
        certificates.private.dev_private.create_private_file(fixture.plan.directory / "unknown", b"synthetic")
    elif change == "receipt":
        receipt = replace(receipt, material_binding="e" * 64)
    else:
        receipt = replace(
            receipt, directory_identity=(receipt.directory_identity[0], receipt.directory_identity[1] + 1)
        )
    before = {path.name: path.read_bytes() for path in fixture.plan.directory.iterdir()}
    result = certificates.prepare_certificates(
        fixture.plan, authorize=approve, generator=material, expected_receipt=receipt
    )
    assert result.exit_code == 1 and result.artifacts_retained and result.tls is None
    assert {path.name: path.read_bytes() for path in fixture.plan.directory.iterdir()} == before


def test_partial_generation_keeps_pending_state_and_never_regenerates(fixture, fake_crypto):
    failure = Mock(side_effect=RuntimeError(PRIVATE))
    first = certificates.prepare_certificates(fixture.plan, authorize=approve, generator=failure)
    assert first.code == "TLS_PREPARATION_UNCONFIRMED" and first.artifacts_retained and first.receipt is None
    assert {p.name for p in fixture.plan.directory.iterdir()} == {"p.json"}
    second = prepare(fixture)
    assert second.code == "TLS_RECEIPT_REQUIRED" and second.artifacts_retained
    failure.assert_called_once()
    assert PRIVATE not in json.dumps(first.to_dict())


def test_other_generation_is_retained_and_never_adopted(fixture, fake_crypto):
    first = prepare(fixture)
    other = certificates.plan_certificates(
        fixture.descriptor,
        fixture.source,
        anchor=fixture.plan.anchor,
        generation=str(uuid4()),
        now=fixture.plan.issued_at,
    )
    result = certificates.prepare_certificates(other, authorize=approve, generator=material)
    assert result.code == "TLS_UNKNOWN_GENERATION_RETAINED" and first.tls.private_key.exists()
    assert not other.directory.exists()


def test_other_instance_receipt_does_not_adopt_or_create_any_tls_state(fixture, fake_crypto):
    first = prepare(fixture)
    other_descriptor = instances.plan_instance(
        repository_id="a" * 64, worktree_id="b" * 64, commit="c" * 40, generation=2, mode="mock", auth_mode="native"
    ).descriptor
    other = certificates.plan_certificates(
        other_descriptor,
        fixture.source,
        anchor=fixture.plan.anchor,
        generation=fixture.plan.generation,
        now=fixture.plan.issued_at,
    )
    denied = Mock(side_effect=AssertionError("cross-instance receipt cannot authorize anything"))
    result = certificates.prepare_certificates(
        other, authorize=denied, generator=denied, expected_receipt=first.receipt
    )
    assert result.code == "TLS_RECEIPT_CHANGED" and not other.parent.exists()
    denied.assert_not_called()


def test_private_root_cannot_be_inside_any_selected_repository_worktree(fixture):
    with pytest.raises(certificates.CertificateError, match="^TLS_PRIVATE_ROOT_REQUIRED$"):
        certificates.plan_certificates(
            fixture.descriptor,
            fixture.source,
            anchor=workspace._identity(fixture.root),
            generation=fixture.plan.generation,
            now=fixture.plan.issued_at,
        )


def test_hardlinked_key_is_retained_and_refused_even_when_bytes_match(fixture, fake_crypto):
    first = prepare(fixture)
    alias = fixture.anchor / "linked.key"
    try:
        os.link(first.tls.private_key, alias)
    except OSError:
        pytest.skip("Synthetic fixture filesystem does not permit hard links")
    result = certificates.prepare_certificates(
        fixture.plan, authorize=approve, generator=material, expected_receipt=first.receipt
    )
    assert result.exit_code == 1 and alias.exists() and first.tls.private_key.exists()
    assert result.tls is None and first.tls.private_key.read_bytes() == material(fixture.plan).private_key


def test_redirected_private_anchor_never_receives_payload_or_permission_repair(fixture):
    original = fixture.anchor.with_name("original")
    fixture.anchor.rename(original)
    try:
        fixture.anchor.symlink_to(original, target_is_directory=True)
    except OSError:
        pytest.skip("Native account cannot create synthetic symlink fixture")
    result = prepare(fixture)
    assert result.exit_code == 1 and not (original / ".sbom-dev").exists()
    assert fixture.anchor.is_symlink()


def test_canonical_anchor_drift_blocks_before_consent_or_private_directory_creation(fixture, monkeypatch):
    original = workspace._identity

    def identity(path):
        result = original(path)
        return replace(result, canonical_path=fixture.root) if path == fixture.anchor else result

    monkeypatch.setattr(workspace, "_identity", identity)
    denied = Mock(side_effect=AssertionError("unverified anchor must not request consent"))
    result = certificates.prepare_certificates(fixture.plan, authorize=denied, generator=denied)
    assert result.code == "TLS_PRIVATE_ROOT_REQUIRED" and not (fixture.anchor / ".sbom-dev").exists()
    denied.assert_not_called()


@pytest.mark.parametrize("change", ["source", "controller", "anchor", "expired"])
def test_context_or_lifetime_drift_after_consent_precedes_publication(fixture, monkeypatch, change):
    def consent(plan, category):
        result = approve(plan, category)
        if change == "source":
            fixture.discovery.return_value = replace(
                fixture.snapshot, head="d" * 40, worktrees=(replace(fixture.selected, head="d" * 40),)
            )
        elif change == "controller":
            monkeypatch.setattr(
                certificates, "_controllers", lambda: tuple((name, "e" * 64) for name, _ in plan.source.controllers)
            )
        elif change == "anchor":
            original = certificates.storage._verify

            def verify(path, **kwargs):
                info = original(path, **kwargs)
                if path == fixture.anchor:
                    return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino + 1)
                return info

            monkeypatch.setattr(certificates.storage, "_verify", verify)
        else:
            monkeypatch.setattr(certificates, "_now", lambda: plan.not_after + timedelta(seconds=1))
        return result

    result = certificates.prepare_certificates(fixture.plan, authorize=consent, generator=material)
    assert result.exit_code == 1 and result.receipt is None and not (fixture.anchor / ".sbom-dev").exists()
    if change == "expired":
        assert result.code == "TLS_EXPIRY_INVALID"


def test_expired_known_generation_is_preserved_without_rotation(fixture, fake_crypto, monkeypatch):
    first = prepare(fixture)
    before = {path.name: path.read_bytes() for path in fixture.plan.directory.iterdir()}
    monkeypatch.setattr(certificates, "_now", lambda: fixture.plan.not_after + timedelta(seconds=1))
    denied = Mock(side_effect=AssertionError("expired generation must not rotate"))
    result = certificates.prepare_certificates(
        fixture.plan, authorize=denied, generator=denied, expected_receipt=first.receipt
    )
    assert result.code == "TLS_EXPIRY_INVALID" and result.tls is None
    assert {path.name: path.read_bytes() for path in fixture.plan.directory.iterdir()} == before
    denied.assert_not_called()


def test_unexpected_artifact_during_generation_prevents_receipt_publication(fixture, fake_crypto):
    def generate(plan):
        certificates.private.dev_private.create_private_file(plan.directory / "unknown", b"synthetic")
        return material(plan)

    result = certificates.prepare_certificates(fixture.plan, authorize=approve, generator=generate)
    assert result.code == "TLS_UNKNOWN_GENERATION_RETAINED" and result.receipt is None and result.tls is None
    assert (fixture.plan.directory / "unknown").exists() and not (fixture.plan.directory / "r.json").exists()


def test_concurrent_writer_cannot_generate_second_material(fixture, fake_crypto):
    nested = []

    def generate(plan):
        nested.append(prepare(fixture))
        return material(plan)

    result = certificates.prepare_certificates(fixture.plan, authorize=approve, generator=generate)
    assert result.exit_code == 0 and nested[0].code == "TLS_RECEIPT_REQUIRED"
    assert nested[0].tls is None


def test_concurrent_different_generation_cannot_acquire_writer_or_generate_material(fixture, fake_crypto):
    other = certificates.plan_certificates(
        fixture.descriptor,
        fixture.source,
        anchor=fixture.plan.anchor,
        generation=str(uuid4()),
        now=fixture.plan.issued_at,
    )
    results = []
    generator = Mock(side_effect=AssertionError("nested writer must not generate material"))

    def generate(plan):
        results.append(certificates.prepare_certificates(other, authorize=approve, generator=generator))
        return material(plan)

    result = certificates.prepare_certificates(fixture.plan, authorize=approve, generator=generate)
    assert result.exit_code == 0 and results[0].exit_code == 1 and results[0].tls is None
    assert not other.directory.exists()
    generator.assert_not_called()


def test_real_parser_rejects_fake_material_before_any_key_payload_write(fixture):
    result = prepare(fixture)
    assert result.code == "TLS_CRYPTO_INVALID" and result.receipt is None
    assert {p.name for p in fixture.plan.directory.iterdir()} == {"p.json"}


def test_ambient_keylog_never_creates_file_or_changes_preview_bundle(fixture, fake_crypto, monkeypatch):
    target = fixture.temporary / "forbidden-keylog"
    monkeypatch.setenv("SSLKEYLOGFILE", str(target))
    result = prepare(fixture)
    assert result.exit_code == 0 and not target.exists()
    assert b"SSLKEYLOGFILE" not in b"".join(p.read_bytes() for p in fixture.plan.directory.iterdir())


@pytest.mark.parametrize("mode", ["mock", "shared-backend"])
def test_both_preview_modes_need_no_authentication_or_provider_secrets(fixture, fake_crypto, mode):
    descriptor = instances.plan_instance(
        repository_id="a" * 64, worktree_id="b" * 64, commit="c" * 40, generation=1, mode=mode, auth_mode="hcl"
    ).descriptor
    plan = certificates.plan_certificates(
        descriptor,
        fixture.source,
        anchor=fixture.plan.anchor,
        generation=fixture.plan.generation,
        now=fixture.plan.issued_at,
    )
    result = certificates.prepare_certificates(plan, authorize=approve, generator=material)
    assert result.exit_code == 0 and not any("jwt" in name or "password" in name for name in certificates._FILES)


@pytest.fixture
def crypto_shim(fixture, monkeypatch):
    """Exercise production invariants with parsed object doubles; no RSA generation."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID

    class Public:
        def __init__(self, n):
            self.n = n

        def public_numbers(self):
            return SimpleNamespace(n=self.n, e=65537)

        def verify(self, signature, *args):
            if signature != b"valid":
                raise ValueError(PRIVATE)

    class Key:
        key_size = 3072

        def __init__(self, n, raw):
            self.n, self.raw = n, raw

        def public_key(self):
            return Public(self.n)

        def private_bytes(self, *args):
            return self.raw

    class Subject:
        def __init__(self, name):
            self.name = name

        def __len__(self):
            return 1

        def get_attributes_for_oid(self, oid):
            return [SimpleNamespace(value=self.name)]

    class Extensions:
        def __init__(self, values):
            self.values = values

        def get_extension_for_class(self, kind):
            return self.values[kind]

        def __iter__(self):
            return iter(SimpleNamespace(oid=kind.oid) for kind in self.values)

    def extension(**kwargs):
        return SimpleNamespace(critical=True, value=SimpleNamespace(**kwargs))

    ca_subject = Subject("SBOM preview " + fixture.descriptor.instance_id)
    ca = SimpleNamespace(
        subject=ca_subject,
        issuer=ca_subject,
        public_key=lambda: Public(1),
        serial_number=1,
        signature=b"valid",
        tbs_certificate_bytes=b"ca-tbs",
        signature_hash_algorithm=SimpleNamespace(name="sha256"),
        not_valid_before_utc=fixture.plan.not_before,
        not_valid_after_utc=fixture.plan.not_after,
        public_bytes=lambda *args: material(fixture.plan).ca_certificate,
        extensions=Extensions(
            {
                x509.BasicConstraints: extension(ca=True, path_length=0),
                x509.KeyUsage: extension(key_cert_sign=True, crl_sign=True),
                x509.SubjectKeyIdentifier: extension(digest=b"ca-id"),
                x509.AuthorityKeyIdentifier: extension(key_identifier=b"ca-id"),
            }
        ),
    )
    leaf = SimpleNamespace(
        subject=Subject(fixture.descriptor.hostname),
        issuer=ca_subject,
        public_key=lambda: Public(2),
        serial_number=2,
        signature=b"valid",
        tbs_certificate_bytes=b"leaf-tbs",
        signature_hash_algorithm=SimpleNamespace(name="sha256"),
        not_valid_before_utc=fixture.plan.not_before,
        not_valid_after_utc=fixture.plan.not_after,
        public_bytes=lambda *args: material(fixture.plan).certificate,
        fingerprint=lambda *args: bytes.fromhex(FINGERPRINT),
        extensions=Extensions(
            {
                x509.BasicConstraints: extension(ca=False, path_length=None),
                x509.KeyUsage: extension(
                    digital_signature=True, key_cert_sign=False, crl_sign=False, key_agreement=False
                ),
                x509.SubjectAlternativeName: SimpleNamespace(
                    value=x509.SubjectAlternativeName(
                        [
                            x509.DNSName(fixture.descriptor.hostname),
                            x509.DNSName("localhost"),
                            x509.IPAddress(ip_address("127.0.0.1")),
                        ]
                    )
                ),
                x509.ExtendedKeyUsage: SimpleNamespace(value=[ExtendedKeyUsageOID.SERVER_AUTH]),
                x509.AuthorityKeyIdentifier: extension(key_identifier=b"ca-id"),
                x509.SubjectKeyIdentifier: extension(digest=b"leaf-id"),
            }
        ),
    )
    ca_key = Key(1, material(fixture.plan).ca_private_key)
    leaf_key = Key(2, material(fixture.plan).private_key)
    monkeypatch.setattr(rsa, "RSAPrivateKey", Key)
    monkeypatch.setattr(
        x509, "load_pem_x509_certificate", lambda raw: ca if raw == material(fixture.plan).ca_certificate else leaf
    )
    monkeypatch.setattr(
        serialization,
        "load_pem_private_key",
        lambda raw, password: ca_key if raw == material(fixture.plan).ca_private_key else leaf_key,
    )
    return SimpleNamespace(ca=ca, leaf=leaf, ca_key=ca_key, leaf_key=leaf_key, x509=x509)


def test_production_pki_checks_accept_exact_strict_shim_and_validate_reuse(fixture, crypto_shim):
    assert certificates._validate_crypto(fixture.plan, material(fixture.plan)) == FINGERPRINT
    result = prepare(fixture)
    assert result.code == "TLS_PREPARED"
    assert (
        certificates.prepare_certificates(
            fixture.plan, authorize=approve, generator=material, expected_receipt=result.receipt
        ).code
        == "TLS_EXISTING_VERIFIED"
    )


@pytest.mark.parametrize(
    "change",
    [
        "ca-pair",
        "leaf-pair",
        "same-key",
        "weak",
        "ca-signature",
        "leaf-signature",
        "issuer",
        "ca-is-leaf",
        "leaf-is-ca",
        "path-length",
        "critical",
        "key-sign",
        "eku",
        "san",
        "aki",
        "expiry",
        "hash",
        "canonical",
        "serial",
        "unknown-extension",
        "ca-aki",
    ],
)
def test_production_pki_checks_reject_identity_chain_purpose_and_expiry_drift(fixture, crypto_shim, change):
    shim, x509 = crypto_shim, crypto_shim.x509
    if change == "ca-pair":
        shim.ca_key.n = 99
    elif change == "leaf-pair":
        shim.leaf_key.n = 99
    elif change == "same-key":
        shim.leaf_key.n = 1
        shim.leaf.public_key = shim.ca.public_key
    elif change == "weak":
        shim.leaf_key.key_size = 1024
    elif change == "ca-signature":
        shim.ca.signature = b"invalid"
    elif change == "leaf-signature":
        shim.leaf.signature = b"invalid"
    elif change == "issuer":
        shim.leaf.issuer = None
    elif change == "ca-is-leaf":
        shim.ca.extensions.values[x509.BasicConstraints].value.ca = False
    elif change == "leaf-is-ca":
        shim.leaf.extensions.values[x509.BasicConstraints].value.ca = True
    elif change == "path-length":
        shim.ca.extensions.values[x509.BasicConstraints].value.path_length = 1
    elif change == "critical":
        shim.leaf.extensions.values[x509.BasicConstraints].critical = False
    elif change == "key-sign":
        shim.leaf.extensions.values[x509.KeyUsage].value.key_cert_sign = True
    elif change == "eku":
        shim.leaf.extensions.values[x509.ExtendedKeyUsage].value = []
    elif change == "san":
        shim.leaf.extensions.values[x509.SubjectAlternativeName].value = x509.SubjectAlternativeName(
            [x509.DNSName("wrong.invalid")]
        )
    elif change == "aki":
        shim.leaf.extensions.values[x509.AuthorityKeyIdentifier].value.key_identifier = b"wrong"
    elif change == "expiry":
        shim.leaf.not_valid_after_utc += timedelta(seconds=1)
    elif change == "hash":
        shim.leaf.signature_hash_algorithm.name = "sha1"
    elif change == "canonical":
        shim.ca.public_bytes = lambda *args: b"different-or-appended-private-material"
    elif change == "serial":
        shim.leaf.serial_number = 0
    elif change == "ca-aki":
        shim.ca.extensions.values[x509.AuthorityKeyIdentifier].value.key_identifier = b"wrong"
    else:
        shim.ca.extensions.values[x509.NameConstraints] = SimpleNamespace(value=None)
    with pytest.raises(certificates.CertificateError, match="^TLS_CRYPTO_INVALID$") as error:
        certificates._validate_crypto(fixture.plan, material(fixture.plan))
    assert PRIVATE not in str(error.value)


def test_direct_execution_and_default_generator_without_consent_cannot_generate_keys(fixture, monkeypatch):
    namespace = {"__name__": "__main__", "__package__": "scripts", "__file__": certificates.__file__}
    source = Path(certificates.__file__).read_text(encoding="utf-8")
    with pytest.raises(SystemExit, match="TLS_PREPARATION_ONLY"):
        exec(compile(source, "<tls-direct-invocation>", "exec"), namespace)
    # Only the consent guard of the real function executes. RSA entropy remains
    # independently trapped by the autouse fixture.
    with pytest.raises(certificates.CertificateError, match="^TLS_AUTHORIZATION_REQUIRED$"):
        _REAL_GENERATE(fixture.plan, consent=None)
    tree = ast.parse(source, feature_version=(3, 11))
    assert not any(
        isinstance(node, ast.Attribute) and node.attr in {"create_default_context", "SSLContext", "keylog_filename"}
        for node in ast.walk(tree)
    )
