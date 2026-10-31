"""Explicit TLS-only material for mock/shared previews; no provider or database.

inspect_source is read-only, plan_certificates is pure. Preparation requires an
exact certificate-category consent before directories, pending state or entropy.
Consent is a user-level choice, never privileged/provider/enrollment authority.
No trust installation, issuer adoption, existing-key copy, overwrite, deletion or
permission repair exists. Only a caller's protected pinned receipt permits reuse.
Unknown/partial generations remain for review. Same-user controller modification
is outside this Python API's threat boundary; generators are trusted code, with
mandatory independent PKI validation before any key payload is published.

The storage primitives reused from dev_workspace_bundle are provider-independent
directory/file pins, exclusive writes and locking; no BundlePlan or credentials
are constructed. Private paths and path/content hashes stay in protected state.
Browser trust is always UNVERIFIED. Real key generation requires separate live
certificate consent; unit tests inject fake material and never generate keys.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

if __package__:
    from . import dev_instance_plan as instances
    from . import dev_instance_registry as registry
    from . import dev_instance_storage as storage
    from . import dev_workspace as workspace
    from . import dev_workspace_bundle as private
    from .dev_workspace_preview import PreviewTls
else:
    import dev_instance_plan as instances
    import dev_instance_registry as registry
    import dev_instance_storage as storage
    import dev_workspace as workspace
    import dev_workspace_bundle as private
    from dev_workspace_preview import PreviewTls

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_FILES = ("c.pem", "k.pem", "s.pem", "s.key")
_CONTROLLERS = (
    "dev_workspace_certificates.py",
    "dev_workspace_preview.py",
    "dev_workspace_bundle.py",
    "dev_instance_plan.py",
    "dev_workspace.py",
    "dev_instance_registry.py",
    "dev_instance_storage.py",
    "dev_private.py",
    "dev_environment.py",
    "dev_windows_acl.py",
)
_CODES = frozenset(
    {
        "TLS_INPUT_INVALID",
        "TLS_SOURCE_UNVERIFIED",
        "TLS_SOURCE_CHANGED",
        "TLS_PRIVATE_ROOT_REQUIRED",
        "TLS_AUTHORIZATION_REQUIRED",
        "TLS_EXPIRY_INVALID",
        "TLS_CRYPTO_INVALID",
        "TLS_RECEIPT_REQUIRED",
        "TLS_RECEIPT_CHANGED",
        "TLS_UNKNOWN_GENERATION_RETAINED",
        "TLS_PRIVATE_STORAGE_UNVERIFIED",
        "TLS_PREPARATION_UNCONFIRMED",
        "TLS_CANCELLED",
        "TLS_PREPARED",
        "TLS_EXISTING_VERIFIED",
    }
)


class CertificateError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else "TLS_INPUT_INVALID"
        super().__init__(self.code)


def _fail(code="TLS_INPUT_INVALID"):
    raise CertificateError(code) from None


def _hash(value):
    return type(value) is str and _HASH.fullmatch(value) is not None


def _digest(value):
    return hashlib.sha256(private._json(value)).hexdigest()


def _now():
    return datetime.now(UTC)


def _controllers():
    root = Path(__file__).resolve(strict=True).parent
    return tuple((name, private._file(root / name, root, private=False, limit=1048576)[1][-1]) for name in _CONTROLLERS)


@dataclass(frozen=True, slots=True, repr=False)
class CertificateSource:
    repository: workspace.RepositorySnapshot
    worktree: workspace.WorktreeSnapshot
    controllers: tuple

    def __repr__(self):
        return "<CertificateSource: source identity>"


def inspect_source(root, *, worktree_id=None):
    """Read public Git/source identity only; no environment or private TLS files."""
    try:
        snapshot = workspace.discover_workspaces(root)
        selected = [
            item
            for item in snapshot.worktrees
            if (item.worktree_id == worktree_id if worktree_id else item.root == snapshot.root)
        ]
        if (
            snapshot.status != "PASS"
            or len(selected) != 1
            or selected[0].status != "PASS"
            or selected[0].locked
            or selected[0].prunable
            or selected[0].bare
            or selected[0].identity is None
            or selected[0].head is None
            or workspace._identity(selected[0].root) != selected[0].identity
        ):
            _fail("TLS_SOURCE_UNVERIFIED")
        storage._verify(selected[0].root, private=False)
        return CertificateSource(snapshot, selected[0], _controllers())
    except Exception:
        _fail("TLS_SOURCE_UNVERIFIED")


@dataclass(frozen=True, slots=True, repr=False)
class CertificatePlan:
    descriptor: instances.InstanceDescriptor
    source: CertificateSource
    anchor: workspace.FilesystemIdentity
    generation: str
    issued_at: datetime
    certificate_days: int
    material_binding: str
    operation_binding: str

    @property
    def parent(self):
        return self.anchor.canonical_path / ".sbom-dev" / "tls" / UUID(self.descriptor.instance_id).hex

    @property
    def directory(self):
        return self.parent / UUID(self.generation).hex

    @property
    def not_before(self):
        return self.issued_at - timedelta(minutes=5)

    @property
    def not_after(self):
        return self.issued_at + timedelta(days=self.certificate_days)

    def __repr__(self):
        return "<CertificatePlan: exact certificate consent required>"

    def to_dict(self):
        return {
            "instance_id": self.descriptor.instance_id,
            "generation": self.generation,
            "hostname": self.descriptor.hostname,
            "mode": self.descriptor.mode,
            "expires_at": self.not_after.isoformat(),
            "required_authorizations": ["certificates"],
            "issuer": "new-per-instance-development-ca",
            "browser_trust": "UNVERIFIED",
            "database_authorized": False,
            "enrollment_authorized": False,
            "provider_authorized": False,
        }


def plan_certificates(descriptor, source, *, anchor, generation, now, certificate_days=30):
    """Pure plan: observations are supplied, revalidated later; no clock or I/O."""
    try:
        if (
            type(descriptor) is not instances.InstanceDescriptor
            or descriptor.mode not in {"mock", "shared-backend"}
            or type(source) is not CertificateSource
            or type(anchor) is not workspace.FilesystemIdentity
            or type(generation) is not str
            or str(UUID(generation)) != generation
            or type(now) is not datetime
            or now.tzinfo is not UTC
            or type(certificate_days) is not int
            or not 1 <= certificate_days <= 90
        ):
            _fail()
        selected, snapshot = source.worktree, source.repository
        if (
            selected not in snapshot.worktrees
            or snapshot.status != "PASS"
            or selected.status != "PASS"
            or selected.identity is None
            or selected.locked
            or selected.prunable
            or selected.bare
            or (descriptor.repository_id, descriptor.worktree_id, descriptor.commit)
            != (snapshot.repository_id, selected.worktree_id, selected.head)
            or selected.identity.canonical_path != selected.root
            or not isinstance(anchor.canonical_path, Path)
            or not anchor.canonical_path.is_absolute()
            or type(anchor.device) is not int
            or anchor.device < 0
            or type(anchor.inode) is not int
            or anchor.inode <= 0
            or any(anchor.canonical_path.is_relative_to(item.root) for item in snapshot.worktrees)
            or type(source.controllers) is not tuple
            or tuple(name for name, _ in source.controllers) != _CONTROLLERS
            or any(not _hash(value) for _, value in source.controllers)
        ):
            _fail("TLS_PRIVATE_ROOT_REQUIRED")
        now = now.replace(microsecond=0)
        stable = [
            descriptor.instance_id,
            descriptor.repository_id,
            descriptor.worktree_id,
            descriptor.generation,
            descriptor.hostname,
            descriptor.mode,
            generation,
            now.isoformat(),
            certificate_days,
            str(anchor.canonical_path),
            anchor.device,
            anchor.inode,
        ]
        material = _digest(stable)
        operation = _digest(
            [
                material,
                descriptor.to_dict(),
                source.controllers,
                [str(selected.identity.canonical_path), selected.identity.device, selected.identity.inode],
            ]
        )
        return CertificatePlan(descriptor, source, anchor, generation, now, certificate_days, material, operation)
    except CertificateError:
        raise
    except Exception:
        _fail()


def _revalidate(plan):
    if type(plan) is not CertificatePlan:
        _fail()
    source = inspect_source(plan.source.worktree.root, worktree_id=plan.descriptor.worktree_id)
    if (
        source != plan.source
        or plan_certificates(
            plan.descriptor,
            source,
            anchor=plan.anchor,
            generation=plan.generation,
            now=plan.issued_at,
            certificate_days=plan.certificate_days,
        )
        != plan
    ):
        _fail("TLS_SOURCE_CHANGED")
    if workspace._identity(plan.anchor.canonical_path) != plan.anchor:
        _fail("TLS_PRIVATE_ROOT_REQUIRED")
    storage._paths(plan.directory, plan.anchor.canonical_path)
    info = storage._verify(plan.anchor.canonical_path, private=False)
    if (info.st_dev, info.st_ino) != (plan.anchor.device, plan.anchor.inode):
        _fail("TLS_PRIVATE_ROOT_REQUIRED")
    if not plan.not_before <= _now() < plan.not_after:
        _fail("TLS_EXPIRY_INVALID")


@dataclass(frozen=True, slots=True)
class CertificateConsent:
    operation_binding: str = field(repr=False)
    generation: str
    expires_at: datetime
    category: str = "certificates"

    def __post_init__(self):
        try:
            valid = (
                type(self.generation) is str
                and str(UUID(self.generation)) == self.generation
                and type(self.expires_at) is datetime
                and self.expires_at.tzinfo is UTC
                and self.expires_at.microsecond == 0
            )
        except Exception:
            valid = False
        if not _hash(self.operation_binding) or self.category != "certificates" or not valid:
            _fail("TLS_AUTHORIZATION_REQUIRED")


def _consent(plan, consent):
    if (
        type(consent) is not CertificateConsent
        or consent.operation_binding != plan.operation_binding
        or consent.generation != plan.generation
        or consent.expires_at != plan.not_after
        or consent.category != "certificates"
    ):
        _fail("TLS_AUTHORIZATION_REQUIRED")


@dataclass(frozen=True, slots=True, repr=False)
class CertificateMaterial:
    ca_certificate: bytes
    ca_private_key: bytes
    certificate: bytes
    private_key: bytes

    def files(self):
        return dict(
            zip(_FILES, (self.ca_certificate, self.ca_private_key, self.certificate, self.private_key), strict=True)
        )

    def __repr__(self):
        return "<CertificateMaterial: private TLS bytes>"


def _validate_crypto(plan, material):
    """Mandatory issuer/key/chain/hostname/EKU/expiry checks; never trust generator flags."""
    from ipaddress import ip_address

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    try:
        if (
            type(material) is not CertificateMaterial
            or any(type(raw) is not bytes or not 1 <= len(raw) <= 65536 for raw in material.files().values())
            or len(set(material.files().values())) != 4
        ):
            _fail("TLS_CRYPTO_INVALID")
        ca = x509.load_pem_x509_certificate(material.ca_certificate)
        leaf = x509.load_pem_x509_certificate(material.certificate)
        ca_key = serialization.load_pem_private_key(material.ca_private_key, password=None)
        key = serialization.load_pem_private_key(material.private_key, password=None)
        if (
            ca.public_bytes(serialization.Encoding.PEM) != material.ca_certificate
            or leaf.public_bytes(serialization.Encoding.PEM) != material.certificate
            or ca_key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
            != material.ca_private_key
            or key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
            != material.private_key
        ):
            _fail("TLS_CRYPTO_INVALID")
        ca_bc = ca.extensions.get_extension_for_class(x509.BasicConstraints)
        leaf_bc = leaf.extensions.get_extension_for_class(x509.BasicConstraints)
        ca_usage = ca.extensions.get_extension_for_class(x509.KeyUsage)
        leaf_usage = leaf.extensions.get_extension_for_class(x509.KeyUsage)
        sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        base_extensions = {
            x509.BasicConstraints.oid,
            x509.KeyUsage.oid,
            x509.SubjectKeyIdentifier.oid,
            x509.AuthorityKeyIdentifier.oid,
        }
        if (
            not isinstance(ca_key, rsa.RSAPrivateKey)
            or not isinstance(key, rsa.RSAPrivateKey)
            or ca_key.key_size < 2048
            or key.key_size < 2048
            or ca_key.public_key().public_numbers().e != 65537
            or key.public_key().public_numbers().e != 65537
            or ca_key.public_key().public_numbers() != ca.public_key().public_numbers()
            or key.public_key().public_numbers() != leaf.public_key().public_numbers()
            or ca_key.public_key().public_numbers() == key.public_key().public_numbers()
            or ca.subject != ca.issuer
            or leaf.issuer != ca.subject
            or {extension.oid for extension in ca.extensions} != base_extensions
            or {extension.oid for extension in leaf.extensions}
            != base_extensions | {x509.SubjectAlternativeName.oid, x509.ExtendedKeyUsage.oid}
            or len(ca.subject) != 1
            or len(leaf.subject) != 1
            or ca.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            != "SBOM preview " + plan.descriptor.instance_id
            or leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value != plan.descriptor.hostname
            or any(not 0 < cert.serial_number < 2**159 for cert in (ca, leaf))
            or not ca_bc.critical
            or not ca_bc.value.ca
            or ca_bc.value.path_length != 0
            or not leaf_bc.critical
            or leaf_bc.value.ca
            or leaf_bc.value.path_length is not None
            or not ca_usage.critical
            or not ca_usage.value.key_cert_sign
            or not ca_usage.value.crl_sign
            or not leaf_usage.critical
            or not leaf_usage.value.digital_signature
            or leaf_usage.value.key_cert_sign
            or leaf_usage.value.crl_sign
            or leaf_usage.value.key_agreement
            or set(sans.get_values_for_type(x509.DNSName)) != {plan.descriptor.hostname, "localhost"}
            or set(sans.get_values_for_type(x509.IPAddress)) != {ip_address("127.0.0.1")}
            or len(sans) != 3
            or set(leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
            != {ExtendedKeyUsageOID.SERVER_AUTH}
            or leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
            != ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
            or ca.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
            != ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
            or any(cert.signature_hash_algorithm.name not in {"sha256", "sha384", "sha512"} for cert in (ca, leaf))
            or any(
                cert.not_valid_before_utc != plan.not_before or cert.not_valid_after_utc != plan.not_after
                for cert in (ca, leaf)
            )
            or not plan.not_before <= _now() < plan.not_after
        ):
            _fail("TLS_CRYPTO_INVALID")
        ca.public_key().verify(ca.signature, ca.tbs_certificate_bytes, padding.PKCS1v15(), ca.signature_hash_algorithm)
        ca.public_key().verify(
            leaf.signature, leaf.tbs_certificate_bytes, padding.PKCS1v15(), leaf.signature_hash_algorithm
        )
        fingerprint = leaf.fingerprint(hashes.SHA256()).hex()
        if not _hash(fingerprint):
            _fail("TLS_CRYPTO_INVALID")
        return fingerprint
    except CertificateError:
        raise
    except Exception:
        _fail("TLS_CRYPTO_INVALID")


def generate_material(plan, *, consent):
    """Real crypto source, called only after exact consent; never touches OS trust."""
    _revalidate(plan)
    _consent(plan, consent)
    from ipaddress import ip_address

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SBOM preview " + plan.descriptor.instance_id)])

    def usage(ca):
        return x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=not ca,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=ca,
            crl_sign=ca,
            encipher_only=False,
            decipher_only=False,
        )

    def builder(public, name, ca):
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(subject)
            .public_key(public)
            .serial_number(x509.random_serial_number())
            .not_valid_before(plan.not_before)
            .not_valid_after(plan.not_after)
            .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
            .add_extension(usage(ca), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        )

    ca = builder(ca_key.public_key(), subject, True).sign(ca_key, hashes.SHA256())
    leaf = (
        builder(key.public_key(), x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, plan.descriptor.hostname)]), False)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(plan.descriptor.hostname),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    def pem(value):
        return value.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )

    return CertificateMaterial(
        ca.public_bytes(serialization.Encoding.PEM),
        pem(ca_key),
        leaf.public_bytes(serialization.Encoding.PEM),
        pem(key),
    )


@contextmanager
def _parents(plan, *, create):
    identities, descriptors = [], {}
    with ExitStack() as pins:
        path, parent = plan.anchor.canonical_path, None
        for index, name in enumerate((None, ".sbom-dev", "tls", UUID(plan.descriptor.instance_id).hex)):
            if name is not None:
                path = path / name
                if create and not os.path.lexists(path):
                    if sys.platform == "win32":
                        storage._windows_create(path)
                    else:
                        os.mkdir(name, 0o700, dir_fd=parent)
            info = storage._verify(path, private=index > 0)
            if index == 0 and (info.st_dev, info.st_ino) != (plan.anchor.device, plan.anchor.inode):
                _fail("TLS_PRIVATE_ROOT_REQUIRED")
            if sys.platform == "win32":
                pins.callback(storage._pin_windows(path))
            else:
                parent = storage._pin_posix(path, info, parent=parent)
                pins.callback(os.close, parent)
                descriptors[path] = parent
            identities.append((path, (info.st_dev, info.st_ino), index > 0))

        def verify():
            storage._revalidate(identities)

        verify()
        yield path, pins, descriptors, identities, verify
        verify()


def _proof(value):
    return (
        type(value) is tuple
        and len(value) == 6
        and all(type(v) is int and v >= 0 for v in value[:5])
        and value[1] > 0
        and _hash(value[-1])
    )


@dataclass(frozen=True, slots=True, repr=False)
class CertificateReceipt:
    material_binding: str
    directory_identity: tuple
    file_proofs: tuple
    receipt_proof: tuple
    certificate_fingerprint: str
    generation: str
    issued_at: datetime
    certificate_days: int

    def __post_init__(self):
        try:
            context_valid = (
                type(self.generation) is str
                and str(UUID(self.generation)) == self.generation
                and type(self.issued_at) is datetime
                and self.issued_at.tzinfo is UTC
                and self.issued_at.microsecond == 0
                and type(self.certificate_days) is int
                and 1 <= self.certificate_days <= 90
            )
        except Exception:
            context_valid = False
        if (
            not _hash(self.material_binding)
            or not _hash(self.certificate_fingerprint)
            or not context_valid
            or type(self.directory_identity) is not tuple
            or len(self.directory_identity) != 2
            or any(type(v) is not int or v < 0 for v in self.directory_identity)
            or not self.directory_identity[1]
            or type(self.file_proofs) is not tuple
            or len(self.file_proofs) != 5
            or any(
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or item[0] not in {*_FILES, "p.json"}
                or not _proof(item[1])
                for item in self.file_proofs
            )
            or len({name for name, _ in self.file_proofs}) != 5
            or not _proof(self.receipt_proof)
        ):
            _fail("TLS_RECEIPT_CHANGED")

    def __repr__(self):
        return "<CertificateReceipt: protected pinned identities>"

    def private_record(self):
        return {
            "version": 1,
            "material_binding": self.material_binding,
            "directory_identity": list(self.directory_identity),
            "files": [[name, list(proof)] for name, proof in self.file_proofs],
            "receipt_proof": list(self.receipt_proof),
            "certificate_fingerprint": self.certificate_fingerprint,
            "generation": self.generation,
            "issued_at": self.issued_at.isoformat(),
            "certificate_days": self.certificate_days,
        }

    @classmethod
    def from_private_record(cls, value):
        try:
            if (
                type(value) is not dict
                or set(value)
                != {
                    "version",
                    "material_binding",
                    "directory_identity",
                    "files",
                    "receipt_proof",
                    "certificate_fingerprint",
                    "generation",
                    "issued_at",
                    "certificate_days",
                }
                or type(value["version"]) is not int
                or value["version"] != 1
            ):
                _fail("TLS_RECEIPT_CHANGED")
            return cls(
                value["material_binding"],
                tuple(value["directory_identity"]),
                tuple((name, tuple(proof)) for name, proof in value["files"]),
                tuple(value["receipt_proof"]),
                value["certificate_fingerprint"],
                value["generation"],
                datetime.fromisoformat(value["issued_at"]),
                value["certificate_days"],
            )
        except Exception:
            _fail("TLS_RECEIPT_CHANGED")


@dataclass(frozen=True, slots=True)
class CertificateOutcome:
    code: str
    exit_code: int
    artifacts_retained: bool = False
    reused: bool = False
    certificate_fingerprint: str | None = None
    receipt: CertificateReceipt | None = field(default=None, repr=False)
    tls: PreviewTls | None = field(default=None, repr=False)

    def __post_init__(self):
        success = type(self.code) is str and self.code in {"TLS_PREPARED", "TLS_EXISTING_VERIFIED"}
        if (
            type(self.code) is not str
            or self.code not in _CODES
            or type(self.exit_code) is not int
            or self.exit_code not in {0, 1, 130}
            or type(self.artifacts_retained) is not bool
            or type(self.reused) is not bool
            or self.certificate_fingerprint is not None
            and not _hash(self.certificate_fingerprint)
            or self.receipt is not None
            and type(self.receipt) is not CertificateReceipt
            or self.tls is not None
            and type(self.tls) is not PreviewTls
            or success != (self.exit_code == 0)
            or success
            and (
                self.receipt is None
                or self.tls is None
                or self.certificate_fingerprint != self.receipt.certificate_fingerprint
            )
            or not success
            and any(value is not None for value in (self.receipt, self.tls, self.certificate_fingerprint))
        ):
            _fail()

    def to_dict(self):
        return {
            "code": self.code,
            "exit_code": self.exit_code,
            "artifacts_retained": self.artifacts_retained,
            "reused": self.reused,
            "certificate_fingerprint": self.certificate_fingerprint,
            "browser_trust": "UNVERIFIED",
            "trust_installed": False,
            "provider_authorized": False,
            "database_authorized": False,
            "enrollment_authorized": False,
        }


def _inventory(parent, generation):
    with os.scandir(parent) as entries:
        for index, entry in enumerate(entries):
            if index > 16 or entry.name not in {generation, ".prepare.lock"}:
                _fail("TLS_UNKNOWN_GENERATION_RETAINED")


def _reuse(plan, expected):
    if type(expected) is not CertificateReceipt:
        _fail("TLS_RECEIPT_REQUIRED")
    with _parents(plan, create=False) as (parent, pins, descriptors, identities, verify):
        _inventory(parent, plan.directory.name)
        info = storage._verify(plan.directory, private=True)
        if (
            expected.material_binding != plan.material_binding
            or expected.directory_identity != (info.st_dev, info.st_ino)
            or (expected.generation, expected.issued_at, expected.certificate_days)
            != (plan.generation, plan.issued_at, plan.certificate_days)
            or {p.name for p in plan.directory.iterdir()} != {*_FILES, "p.json", "r.json"}
        ):
            _fail("TLS_RECEIPT_CHANGED")
        if sys.platform == "win32":
            pins.callback(storage._pin_windows(plan.directory))
        else:
            descriptor = storage._pin_posix(plan.directory, info, parent=descriptors[parent])
            pins.callback(os.close, descriptor)
        identities.append((plan.directory, expected.directory_identity, True))
        raw, proof = private._file(plan.directory / "r.json", plan.directory)
        if proof != expected.receipt_proof:
            _fail("TLS_RECEIPT_CHANGED")
        wanted = expected.private_record()
        del wanted["receipt_proof"]
        if json.loads(raw, object_pairs_hook=private._object) != wanted:
            _fail("TLS_RECEIPT_CHANGED")
        values = {}
        for name, wanted_proof in expected.file_proofs:
            raw, actual = private._file(plan.directory / name, plan.directory)
            if actual != wanted_proof:
                _fail("TLS_RECEIPT_CHANGED")
            values[name] = raw
        fingerprint = _validate_crypto(plan, CertificateMaterial(*(values[name] for name in _FILES)))
        if fingerprint != expected.certificate_fingerprint:
            _fail("TLS_RECEIPT_CHANGED")
        verify()
        _revalidate(plan)
    return expected


def prepare_certificates(plan, *, authorize, generator=None, expected_receipt=None):
    """New-only protected publication, or strict reuse of a known protected receipt."""
    retained = False
    try:
        _revalidate(plan)
        if os.path.lexists(plan.directory):
            retained = True
            receipt = _reuse(plan, expected_receipt)
            return CertificateOutcome(
                "TLS_EXISTING_VERIFIED",
                0,
                True,
                True,
                receipt.certificate_fingerprint,
                receipt,
                PreviewTls(plan.directory / "s.pem", plan.directory / "s.key", plan.directory / "c.pem"),
            )
        if expected_receipt is not None:
            _fail("TLS_RECEIPT_CHANGED")
        consent = authorize(plan, "certificates")
        _consent(plan, consent)
        _revalidate(plan)
        retained = True
        with _parents(plan, create=True) as (parent, pins, descriptors, identities, verify):
            with private._lock(parent, descriptors, verify):
                _inventory(parent, plan.directory.name)
                _revalidate(plan)
                private._mkdir(plan.directory, parent, pins, descriptors, identities)
                proofs = [
                    (
                        "p.json",
                        private._write(
                            plan.directory / "p.json",
                            private._json({"version": 1, "operation_binding": plan.operation_binding}),
                            plan.directory,
                            descriptors,
                            verify,
                        ),
                    )
                ]
                material = generator(plan) if generator is not None else generate_material(plan, consent=consent)
                fingerprint = _validate_crypto(plan, material)
                _revalidate(plan)
                for name, raw in material.files().items():
                    proofs.append(
                        (name, private._write(plan.directory / name, raw, plan.directory, descriptors, verify))
                    )
                _revalidate(plan)
                if {path.name for path in plan.directory.iterdir()} != {*_FILES, "p.json"}:
                    _fail("TLS_UNKNOWN_GENERATION_RETAINED")
                info = registry._private(plan.directory, directory=True)
                record = {
                    "version": 1,
                    "material_binding": plan.material_binding,
                    "directory_identity": [info.st_dev, info.st_ino],
                    "files": [[name, list(proof)] for name, proof in proofs],
                    "certificate_fingerprint": fingerprint,
                    "generation": plan.generation,
                    "issued_at": plan.issued_at.isoformat(),
                    "certificate_days": plan.certificate_days,
                }
                receipt_proof = private._write(
                    plan.directory / "r.json", private._json(record), plan.directory, descriptors, verify
                )
                receipt = CertificateReceipt(
                    plan.material_binding,
                    (info.st_dev, info.st_ino),
                    tuple(proofs),
                    receipt_proof,
                    fingerprint,
                    plan.generation,
                    plan.issued_at,
                    plan.certificate_days,
                )
        return CertificateOutcome(
            "TLS_PREPARED",
            0,
            True,
            False,
            fingerprint,
            receipt,
            PreviewTls(plan.directory / "s.pem", plan.directory / "s.key", plan.directory / "c.pem"),
        )
    except CertificateError as error:
        return CertificateOutcome(error.code, 1, retained)
    except private.BundleError:
        return CertificateOutcome("TLS_PRIVATE_STORAGE_UNVERIFIED", 1, retained)
    except (KeyboardInterrupt, EOFError):
        return CertificateOutcome("TLS_CANCELLED", 130, retained)
    except Exception:
        return CertificateOutcome("TLS_PREPARATION_UNCONFIRMED", 1, retained)


if __name__ == "__main__":
    raise SystemExit("TLS_PREPARATION_ONLY: use the unified launcher and explicit certificate review.")
