"""Explicit private bundle preparation; no application, DB, engine or OS trust.

inspect_source is read-only; plan_bundle is pure. prepare_bundle requires fresh
user-level credentials AND certificate consent before new files or entropy. A
callback is not independent privileged authority. A bundle/receipt never grants
provider, migration, enrollment or trust permission. Original installations are
never read, converted, repaired, overwritten, deleted or silently rotated.

The default generator is trusted Python code, not a hostile-code sandbox. It is
called only after consent and produces independent credentials/keys and a local
CA/leaf set. Browser trust still requires separate approval. Injected generators
are also trusted code; mandatory material/crypto checks precede publication.
Private hashes, paths, HCL values and environment projections stay private.
Receipts pin immutable artifacts, not authorization. A caller must retain their
identity record in protected state; an unknown on-disk receipt is never adopted.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import stat
import sys
from collections.abc import Mapping
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from urllib.parse import quote, unquote, urlencode, urlsplit
from uuid import UUID

if __package__:
    from . import dev_config, dev_environment, dev_instance_registry, dev_instance_storage, dev_private, dev_workspace
    from . import dev_workspace_compose as compose
    from . import dev_workspace_provider as provider
else:
    import dev_config
    import dev_environment
    import dev_instance_registry
    import dev_instance_storage
    import dev_private
    import dev_workspace
    import dev_workspace_compose as compose
    import dev_workspace_provider as provider

_CONTROLLERS = (
    "dev_workspace_bundle.py",
    "dev_workspace_compose.py",
    "dev_workspace_provider.py",
    "dev_config.py",
    "dev_environment.py",
    "dev_instance_plan.py",
    "dev_instance_registry.py",
    "dev_instance_storage.py",
    "dev_private.py",
    "dev_windows_acl.py",
    "dev_workspace.py",
)
_SECRET_NAMES = frozenset(
    {"postgres-bootstrap", "postgres-runtime", "provider-storage", "redis", "redis-session", "smtp", "session", "outbox"}
)
_BINARY_SECRET_NAMES = frozenset({"session", "outbox", "provider-storage"})
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_MANAGED = ".env.dev.local"
_JOURNAL = ".pending.json"
_RECEIPT = ".receipt.json"
_FILE_LIMIT = 256 * 1024
_TRUST_BUNDLE = "tls/trust-bundle.pem"
# The combined public, local and operator CA stores exceed individual key limits.
_TRUST_BUNDLE_LIMIT = 1024 * 1024


class BundleError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _fail(code):
    raise BundleError(code) from None


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _public_id(value):
    try:
        if type(value) is str and (_HASH.fullmatch(value) or str(UUID(value)) == value):
            return
    except ValueError:
        pass
    _fail("BUNDLE_PUBLIC_REFERENCE_INVALID")


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("BUNDLE_RECEIPT_UNVERIFIED")
        result[key] = value
    return result


def _stamp(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _file(path, root, *, private=True, limit=None):
    if limit is None:
        limit = _TRUST_BUNDLE_LIMIT if path == root / _TRUST_BUNDLE else _FILE_LIMIT
    dev_private.validate_parent(path, root)
    before = dev_instance_registry._private(path) if private else path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or getattr(before, "st_file_attributes", 0) & 1024:
        _fail("BUNDLE_FILE_UNVERIFIED")
    raw = dev_environment.bounded_read_bytes(path, limit)
    after = dev_instance_registry._private(path) if private else path.lstat()
    if _stamp(before) != _stamp(after) or len(raw) != before.st_size:
        _fail("BUNDLE_FILE_CHANGED")
    return raw, (*_stamp(after), hashlib.sha256(raw).hexdigest())


def _controllers():
    root = Path(__file__).resolve(strict=True).parent
    return tuple((name, _file(root / name, root, private=False, limit=1048576)[1][-1]) for name in _CONTROLLERS)


@dataclass(frozen=True, slots=True, repr=False)
class BundleSource:
    repository: dev_workspace.RepositorySnapshot
    worktree: dev_workspace.WorktreeSnapshot
    controller_hashes: tuple[tuple[str, str], ...]

    def __repr__(self):
        return "<BundleSource: public source binding>"


def inspect_source(root, *, worktree_id=None):
    """Read bounded Git/public source metadata; never reads private settings."""
    try:
        snapshot = dev_workspace.discover_workspaces(root)
        rows = [
            item
            for item in snapshot.worktrees
            if (item.worktree_id == worktree_id if worktree_id is not None else item.root == snapshot.root)
        ]
        if snapshot.status != "PASS" or len(rows) != 1:
            _fail("BUNDLE_SOURCE_UNVERIFIED")
        selected = rows[0]
        if (
            selected.status != "PASS"
            or selected.identity is None
            or selected.head is None
            or selected.locked
            or selected.prunable
            or selected.bare
        ):
            _fail("BUNDLE_SOURCE_UNVERIFIED")
        if dev_workspace._identity(selected.identity.canonical_path) != selected.identity:
            _fail("BUNDLE_SOURCE_UNVERIFIED")
        try:
            dev_instance_storage._verify(selected.identity.canonical_path, private=False)
        except dev_instance_storage.DirectoryInitializationError:
            _fail("BUNDLE_SOURCE_ACCESS_REVIEW_REQUIRED")
        return BundleSource(snapshot, selected, _controllers())
    except BundleError:
        raise
    except Exception:
        _fail("BUNDLE_SOURCE_UNVERIFIED")


@dataclass(frozen=True, slots=True, repr=False)
class HclRegistration:
    reference: str
    issuer: str
    audience: str
    client_id: str
    redirect_uri: str
    scopes: str
    ca_pem: bytes = b""

    def __post_init__(self):
        _public_id(self.reference)
        for value in (self.issuer, self.audience, self.client_id, self.redirect_uri, self.scopes):
            if (
                type(value) is not str
                or not value
                or len(value) > 2048
                or any(ord(char) < 32 or ord(char) == 127 for char in value)
            ):
                _fail("BUNDLE_HCL_REGISTRATION_INVALID")
        for value in (self.issuer, self.redirect_uri):
            try:
                url = urlsplit(value)
                if (
                    url.scheme != "https"
                    or not url.hostname
                    or url.username is not None
                    or url.password is not None
                    or url.query
                    or url.fragment
                ):
                    raise ValueError()
                _ = url.port
            except ValueError:
                _fail("BUNDLE_HCL_REGISTRATION_INVALID")
        if type(self.ca_pem) is not bytes or len(self.ca_pem) > _FILE_LIMIT:
            _fail("BUNDLE_HCL_REGISTRATION_INVALID")

    def __repr__(self):
        return "<HclRegistration: operator-supplied private registration>"


@dataclass(frozen=True, slots=True, repr=False)
class BundlePlan:
    provider_plan: provider.ContainerProviderPlan
    source: BundleSource
    anchor: dev_workspace.FilesystemIdentity
    generation: str
    profiles: Mapping[str, str]
    registration: HclRegistration | None
    certificate_days: int
    fingerprint: str
    material_fingerprint: str
    private_binding: str

    @property
    def state_root(self):
        return self.anchor.canonical_path / ".sbom-dev" / "instances" / self.provider_plan.descriptor.instance_id

    @property
    def directory(self):
        return self.state_root / "bundles" / self.generation

    @property
    def configuration_path(self):
        return self.directory / _MANAGED

    @property
    def provider_files(self):
        return tuple(
            sorted(
                "provider/" + name
                for values in compose.secret_layout(self.provider_plan).values()
                for name in values.values()
            )
        )

    @property
    def files(self):
        names = (
            *self.provider_files,
            "keys/auth-transaction-key",
            "tls/ca-key.pem",
            "tls/ca.pem",
            "tls/frontend-key.pem",
            "tls/frontend-cert.pem",
            "tls/trust-bundle.pem",
        )
        if self.provider_plan.descriptor.auth_mode == "native":
            names += ("keys/native-jwt-private.pem", "keys/native-jwt-public.pem")
        return tuple(sorted(names))

    def __repr__(self):
        return "<BundlePlan: credentials and certificate authorization required>"

    def to_dict(self):
        descriptor = self.provider_plan.descriptor
        return {
            "version": 1,
            "instance_id": descriptor.instance_id,
            "commit": descriptor.commit,
            "generation": self.generation,
            "auth_mode": descriptor.auth_mode,
            "policy_reference": self.provider_plan.policy.policy_id,
            "hcl_registration_reference": self.registration.reference if self.registration else None,
            "profiles": dict(self.profiles),
            "files": list(self.files) + [_MANAGED],
            "certificate_days": self.certificate_days,
            "fingerprint": self.fingerprint,
            "material_fingerprint": self.material_fingerprint,
            "required_authorizations": ["credentials", "certificates"],
            "browser_trust_installed": False,
            "provider_operations_authorized": False,
            "database_authorized": False,
            "enrollment_authorized": False,
        }


def _bindings(plan, source, anchor, generation, profiles, registration, days):
    descriptor = plan.descriptor
    stable = {
        "repository_id": descriptor.repository_id,
        "worktree_id": descriptor.worktree_id,
        "instance_id": descriptor.instance_id,
        "resource_generation": descriptor.generation,
        "ports": dict(descriptor.ports),
        "resources": dict(descriptor.resources),
        "auth_mode": descriptor.auth_mode,
        "provider_policy": plan.policy.to_dict(),
        "profiles": dict(profiles),
        "generation": generation,
        "registration_reference": registration.reference if registration else None,
        "certificate_days": days,
    }
    material = hashlib.sha256(_json(stable)).hexdigest()
    public = [stable, descriptor.commit, dict(descriptor.manifest_hashes), source.controller_hashes]
    private = [
        generation,
        str(anchor.canonical_path),
        anchor.device,
        anchor.inode,
        None
        if registration is None
        else [
            registration.issuer,
            registration.audience,
            registration.client_id,
            registration.redirect_uri,
            registration.scopes,
            registration.ca_pem.hex(),
        ],
    ]
    return hashlib.sha256(_json(public)).hexdigest(), material, hashlib.sha256(_json(private)).hexdigest()


def plan_bundle(plan, source, *, anchor, generation, profiles, registration=None, certificate_days=30):
    """Pure immutable plan; source/anchor observations are rechecked before use."""
    if type(plan) is not provider.ContainerProviderPlan or type(source) is not BundleSource:
        _fail("BUNDLE_CONTEXT_REQUIRED")
    descriptor = plan.descriptor
    if provider.plan_provider(descriptor, plan.policy) != plan:
        _fail("BUNDLE_PROVIDER_CONTEXT_CHANGED")
    selected = source.worktree
    if (
        source.repository.repository_id != descriptor.repository_id
        or selected.worktree_id != descriptor.worktree_id
        or selected.head != descriptor.commit
        or selected.identity is None
        or selected.status != "PASS"
        or source.repository.status != "PASS"
        or selected not in source.repository.worktrees
        or selected.locked
        or selected.prunable
        or selected.bare
    ):
        _fail("BUNDLE_SOURCE_CONTEXT_CHANGED")
    if (
        type(anchor) is not dev_workspace.FilesystemIdentity
        or not isinstance(anchor.canonical_path, Path)
        or not anchor.canonical_path.is_absolute()
        or type(anchor.device) is not int
        or anchor.device < 0
        or type(anchor.inode) is not int
        or anchor.inode <= 0
    ):
        _fail("BUNDLE_ANCHOR_REQUIRED")
    try:
        if type(generation) is not str or str(UUID(generation)) != generation:
            raise ValueError()
    except ValueError:
        _fail("BUNDLE_GENERATION_INVALID")
    if descriptor.config_generation not in {None, generation}:
        _fail("BUNDLE_GENERATION_CHANGED")
    if not isinstance(profiles, Mapping) or dict(profiles) != compose._PROFILES:
        _fail("BUNDLE_RUNTIME_PROFILE_REQUIRED")
    profiles = MappingProxyType(dict(profiles))
    if (
        (descriptor.auth_mode == "hcl") != (registration is not None)
        or registration is not None
        and type(registration) is not HclRegistration
    ):
        _fail("BUNDLE_HCL_REGISTRATION_REQUIRED")
    if registration is not None and registration.redirect_uri != descriptor.origin + "/api/auth/callback":
        _fail("BUNDLE_HCL_REDIRECT_REGISTRATION_REQUIRED")
    if type(certificate_days) is not int or not 1 <= certificate_days <= 90:
        _fail("BUNDLE_CERTIFICATE_POLICY_INVALID")
    if (
        type(source.controller_hashes) is not tuple
        or len(source.controller_hashes) != len(_CONTROLLERS)
        or any(
            type(pair) is not tuple
            or len(pair) != 2
            or type(pair[0]) is not str
            or type(pair[1]) is not str
            or not _HASH.fullmatch(pair[1])
            for pair in source.controller_hashes
        )
        or {name for name, _ in source.controller_hashes} != set(_CONTROLLERS)
    ):
        _fail("BUNDLE_SOURCE_PROOF_REQUIRED")
    bindings = _bindings(plan, source, anchor, generation, profiles, registration, certificate_days)
    result = BundlePlan(plan, source, anchor, generation, profiles, registration, certificate_days, *bindings)
    root = selected.identity.canonical_path
    if result.directory == root or result.directory.is_relative_to(root) or root.is_relative_to(result.directory):
        _fail("BUNDLE_OUTSIDE_CHECKOUT_REQUIRED")
    return result


def compose_secret_files(plan, *, host_platform):
    """Private references only; file identity/readability still needs verification."""
    if type(plan) is not BundlePlan:
        _fail("BUNDLE_PLAN_REQUIRED")
    return tuple(
        compose.SecretFile(Path(name).name, str(plan.directory / name), host_platform) for name in plan.provider_files
    )


def _revalidate(plan):
    current = inspect_source(plan.source.worktree.root, worktree_id=plan.source.worktree.worktree_id)
    if (
        current.repository.repository_id != plan.source.repository.repository_id
        or current.worktree.identity != plan.source.worktree.identity
        or current.worktree.head != plan.source.worktree.head
        or current.controller_hashes != plan.source.controller_hashes
        or dev_workspace._identity(plan.anchor.canonical_path) != plan.anchor
    ):
        _fail("BUNDLE_SOURCE_OR_ANCHOR_CHANGED")
    expected = plan_bundle(
        plan.provider_plan,
        plan.source,
        anchor=plan.anchor,
        generation=plan.generation,
        profiles=plan.profiles,
        registration=plan.registration,
        certificate_days=plan.certificate_days,
    )
    if expected != plan:
        _fail("BUNDLE_PLAN_CHANGED")
    controller = Path(__file__).resolve(strict=True).parent.parent
    for name, digest in plan.provider_plan.descriptor.manifest_hashes.items():
        path = (
            controller / name.removeprefix("controller/")
            if name.startswith("controller/")
            else plan.source.worktree.root / name
        )
        if (
            _file(
                path,
                controller if name.startswith("controller/") else plan.source.worktree.root,
                private=False,
                limit=8388608,
            )[1][-1]
            != digest
        ):
            _fail("BUNDLE_PUBLIC_SOURCE_CHANGED")


@dataclass(frozen=True, slots=True, repr=False)
class BundleMaterial:
    files: Mapping[str, bytes]
    secrets: Mapping[str, bytes]

    def __post_init__(self):
        if (
            not isinstance(self.files, Mapping)
            or not isinstance(self.secrets, Mapping)
            or set(self.secrets) != _SECRET_NAMES
            or any(
                type(name) is not str
                or type(raw) is not bytes
                or len(raw) > (_TRUST_BUNDLE_LIMIT if name == _TRUST_BUNDLE else _FILE_LIMIT)
                for name, raw in self.files.items()
            )
            or any(type(raw) is not bytes for raw in self.secrets.values())
        ):
            _fail("BUNDLE_MATERIAL_INVALID")
        object.__setattr__(self, "files", MappingProxyType(dict(self.files)))
        object.__setattr__(self, "secrets", MappingProxyType(dict(self.secrets)))

    def __repr__(self):
        return "<BundleMaterial: private values withheld>"


def _provider_payloads(plan, secrets, certificates):
    layout = compose.secret_layout(plan.provider_plan)
    result = {}
    for component, names in layout.items():
        for role in ("cert", "key"):
            result["provider/" + names[role]] = certificates[component + "-" + role]
        result["provider/" + names["ca"]] = certificates["ca"]
    pg = layout["postgres"]
    result["provider/" + pg["bootstrap"]] = secrets["postgres-bootstrap"] + b"\n"
    result["provider/" + pg["runtime"]] = secrets["postgres-runtime"] + b"\n"
    result["provider/" + pg["hba"]] = (
        b"local all all scram-sha-256\nhostssl all all 0.0.0.0/0 scram-sha-256\nhostssl all all ::/0 scram-sha-256\nhostnossl all all all reject\n"
    )
    redis = layout["redis"]
    config = [
        "bind 0.0.0.0",
        "protected-mode yes",
        "port 0",
        "tls-port 6379",
        "tls-auth-clients no",
        *(
            "tls-" + option + " /run/secrets/" + redis[role]
            for option, role in (("cert-file", "cert"), ("key-file", "key"), ("ca-cert-file", "ca"))
        ),
        "user default off",
        "user sbom_runtime on >"
        + secrets["redis"].decode("ascii")
        + " ~* &* +@all -@admin -@dangerous +eval +evalsha +script|load +script|exists",
        "user sbom_session on >"
        + secrets["redis-session"].decode("ascii")
        + " ~"
        + plan.provider_plan.descriptor.resources["session_namespace"]
        + "* -@all +get +set +del +exists +eval +evalsha +ping +auth +select +hello +client|setinfo +client|setname",
        "appendonly yes",
        "dir /data",
        'logfile ""',
    ]
    result["provider/" + redis["config"]] = ("\n".join(config) + "\n").encode("ascii")
    username = "sbom_" + UUID(plan.provider_plan.descriptor.instance_id).hex
    result["provider/" + layout["mailpit"]["auth"]] = username.encode() + b":" + secrets["smtp"] + b"\n"
    return result


def _environment(plan, material):
    descriptor, private = plan.provider_plan.descriptor, material.secrets
    ports, resources = descriptor.ports, descriptor.resources
    native = descriptor.auth_mode == "native"
    trust = str(plan.directory / "tls/trust-bundle.pem")

    def password(name):
        return quote(private[name].decode("ascii"), safe="")

    def redis(index, python=True, *, session=False):
        user, secret = ("sbom_session", "redis-session") if session else ("sbom_runtime", "redis")
        return f"rediss://{user}:{password(secret)}@127.0.0.1:{ports['redis']}/{index}" + (
            "?" + urlencode({"ssl_cert_reqs": "required", "ssl_check_hostname": "true", "ssl_ca_certs": trust})
            if python
            else ""
        )

    env = {
        "APP_ENVIRONMENT": "development",
        "APP_ENV": "development",
        "ALLOW_SQLITE": "false",
        "SBOM_DEV_PROFILE": "isolated",
        "SBOM_DEV_RESOURCE_ID": descriptor.instance_id,
        "PYTHON_DOTENV_DISABLED": "1",
        "AUTH_ENABLED": "true",
        "DEV_DEFAULT_TENANT": "false",
        "ENTRA_ENABLED": "false",
        "NATIVE_AUTH_ENABLED": str(native).lower(),
        "HCL_AUTH_ENABLED": str(not native).lower(),
        "NEXT_PUBLIC_AUTH_ENABLED": "true",
        "NEXT_PUBLIC_ENTRA_ENABLED": "false",
        "NEXT_PUBLIC_NATIVE_AUTH_ENABLED": str(native).lower(),
        "NEXT_PUBLIC_HCL_AUTH_ENABLED": str(not native).lower(),
        "APP_ORIGIN": descriptor.origin,
        "CORS_ORIGINS": descriptor.origin,
        "DEV_API_PORT": str(ports["api"]),
        "DEV_FRONTEND_PORT": str(ports["frontend"]),
        "SBOM_API_URL": f"http://127.0.0.1:{ports['api']}",
        "NEXT_PUBLIC_API_URL": f"http://127.0.0.1:{ports['api']}",
        "DATABASE_URL": f"postgresql+psycopg://{resources['restricted_database_role']}:{password('postgres-runtime')}@127.0.0.1:{ports['postgres']}/{resources['database']}?"
        + urlencode({"sslmode": "verify-full", "sslrootcert": trust,
                     "gssencmode": "disable", "sslcertmode": "disable"}),
        "REDIS_URL": redis(0),
        "CELERY_BROKER_URL": redis(0),
        "CELERY_RESULT_BACKEND": redis(2),
        "CELERY_USE_DATABASE_BROKER": "false",
        "AUTH_SESSION_REDIS_URL": redis(1, False, session=True),
        "AUTH_SESSION_STORE": "redis",
        "NATIVE_AUTH_RATE_LIMIT_STORAGE_URI": redis(3),
        "AUTH_SESSION_ENCRYPTION_KEY": base64.b64encode(private["session"]).decode(),
        "NATIVE_SECURITY_OUTBOX_KEY": base64.b64encode(private["outbox"]).decode(),
        "AI_CONFIG_ENCRYPTION_KEY": base64.b64encode(private["provider-storage"]).decode(),
        "AUTH_TRANSACTION_KEY_FILE": str(plan.directory / "keys/auth-transaction-key"),
        "NATIVE_PLATFORM_BOOTSTRAP_ENABLED": "false",
        "NATIVE_USER_CREATION_ENABLED": str(native).lower(),
        "NATIVE_SECURITY_OUTBOX_ENABLED": str(native).lower(),
        "NATIVE_AUTH_RATE_LIMIT_ENABLED": "true",
        "API_RATE_LIMIT_ENABLED": "true",
        "EMAIL_DELIVERY_ENABLED": "true",
        "EMAIL_PROVIDER": "smtp",
        "SMTP_HOST": "127.0.0.1",
        "SMTP_PORT": str(ports["smtp"]),
        "SMTP_USERNAME": "sbom_" + UUID(descriptor.instance_id).hex,
        "SMTP_PASSWORD": private["smtp"].decode("ascii"),
        "SMTP_USE_TLS": "false",
        "SMTP_USE_STARTTLS": "true",
        "EMAIL_FROM_ADDRESS": "sbom@example.test",
        "SSL_CERT_FILE": trust,
        "NODE_EXTRA_CA_CERTS": trust,
        "REPORT_ARTIFACT_STORAGE_PATH": str(plan.state_root / "artifacts"),
        "SBOM_WORKSPACE_STORAGE_DIR": str(plan.state_root / "workspaces"),
        "SBOM_DEV_STATE_DIR": str(plan.state_root / ".dev-logs"),
        "CELERY_DEFAULT_QUEUE": resources["queue_default"],
        "CELERY_REPORTS_QUEUE": resources["queue_reports"],
        "SBOM_DEV_BEAT_NAMESPACE": resources["beat_namespace"],
        "AUTH_SESSION_KEY_PREFIX": resources["session_namespace"],
        "NATIVE_AUTH_RATE_LIMIT_NAMESPACE": resources["rate_limit_namespace"],
        "NATIVE_MAIL_WORKER_HEARTBEAT_KEY": resources["rate_limit_namespace"] + "mail-worker",
    }
    if native:
        env.update(
            NATIVE_JWT_PRIVATE_KEY=material.files["keys/native-jwt-private.pem"].decode("ascii"),
            NATIVE_JWT_PUBLIC_KEY=material.files["keys/native-jwt-public.pem"].decode("ascii"),
            NATIVE_JWT_ISSUER=descriptor.origin + "/native",
            NATIVE_JWT_AUDIENCE="sbom-analyser-api",
            NATIVE_JWT_ACTIVE_KID="native-dev",
            NATIVE_JWT_ALGORITHM="RS256",
            NATIVE_JWT_VERIFICATION_KEYS_JSON="{}",
            NATIVE_ACTIVATION_FRONTEND_URL=descriptor.origin + "/activate-account",
            NATIVE_PASSWORD_RESET_FRONTEND_URL=descriptor.origin + "/reset-password",
            EMAIL_VERIFICATION_FRONTEND_URL=descriptor.origin + "/verify-email",
        )
    else:
        registration = plan.registration
        env.update(
            HCL_IAM_ISSUER=registration.issuer,
            HCL_IAM_AUDIENCE=registration.audience,
            HCL_IAM_CLIENT_ID=registration.client_id,
            NEXT_PUBLIC_HCL_IAM_ISSUER=registration.issuer,
            NEXT_PUBLIC_HCL_IAM_CLIENT_ID=registration.client_id,
            NEXT_PUBLIC_HCL_IAM_REDIRECT_URI=registration.redirect_uri,
            NEXT_PUBLIC_HCL_IAM_SCOPES=registration.scopes,
            HCL_IAM_CA_BUNDLE=trust,
        )
    return env


def _managed(environment):
    raw = "".join(
        key + "=" + json.dumps(value, ensure_ascii=True) + "\n" for key, value in sorted(environment.items())
    ).encode("ascii")
    if dev_config.parse_managed(raw.decode("ascii")) != environment:
        _fail("BUNDLE_MANAGED_CODEC_UNVERIFIED")
    return raw


def _validate_material(plan, material):
    if type(material) is not BundleMaterial or set(material.files) != set(plan.files):
        _fail("BUNDLE_MATERIAL_LAYOUT_INVALID")
    secrets = material.secrets
    if (
        len(set(secrets.values())) != len(secrets)
        or any(len(secrets[name]) != 32 for name in _BINARY_SECRET_NAMES)
        or any(
            not re.fullmatch(rb"[A-Za-z0-9_-]{32,128}", secrets[name])
            for name in _SECRET_NAMES - _BINARY_SECRET_NAMES
        )
        or len(material.files["keys/auth-transaction-key"]) != 32
        or material.files["keys/auth-transaction-key"] in secrets.values()
    ):
        _fail("BUNDLE_INDEPENDENT_KEYS_REQUIRED")
    layout = compose.secret_layout(plan.provider_plan)
    certificates = {"ca": material.files["tls/ca.pem"]}
    for component in ("postgres", "redis", "mailpit"):
        for role in ("cert", "key"):
            certificates[component + "-" + role] = material.files["provider/" + layout[component][role]]
    expected = _provider_payloads(plan, secrets, certificates)
    if any(material.files[name] != raw for name, raw in expected.items()):
        _fail("BUNDLE_PROVIDER_PAYLOAD_CHANGED")
    _validate_crypto(plan, material)
    environment = _environment(plan, material)
    dev_config.component_environment(environment, "frontend")
    _managed(environment)
    return environment


def _validate_crypto(plan, material):
    from datetime import UTC, datetime, timedelta
    from ipaddress import ip_address

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    try:
        files = material.files
        ca = x509.load_pem_x509_certificate(files["tls/ca.pem"])
        key = serialization.load_pem_private_key(files["tls/ca-key.pem"], password=None)
        if (
            not isinstance(key, rsa.RSAPrivateKey)
            or key.key_size < 2048
            or ca.subject != ca.issuer
            or key.public_key().public_numbers() != ca.public_key().public_numbers()
            or not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            or ca.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length != 0
            or not ca.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
            or ca.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            != "SBOM development " + plan.provider_plan.descriptor.instance_id
            or ca.signature_hash_algorithm.name not in {"sha256", "sha384", "sha512"}
        ):
            _fail("BUNDLE_CA_KEY_INVALID")
        ca.public_key().verify(ca.signature, ca.tbs_certificate_bytes, padding.PKCS1v15(), ca.signature_hash_algorithm)
        now = datetime.now(UTC)
        if (
            not ca.not_valid_before_utc <= now < ca.not_valid_after_utc
            or ca.not_valid_after_utc - ca.not_valid_before_utc > timedelta(days=plan.certificate_days, minutes=10)
        ):
            _fail("BUNDLE_CERTIFICATE_EXPIRED")
        numbers = [key.private_numbers().public_numbers.n]
        layout = compose.secret_layout(plan.provider_plan)
        pairs = [
            ("tls/frontend-key.pem", "tls/frontend-cert.pem"),
            *(("provider/" + names["key"], "provider/" + names["cert"]) for names in layout.values()),
        ]
        for private_name, cert_name in pairs:
            leaf = x509.load_pem_x509_certificate(files[cert_name])
            private = serialization.load_pem_private_key(files[private_name], password=None)
            sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            if (
                not isinstance(private, rsa.RSAPrivateKey)
                or private.key_size < 2048
                or private.public_key().public_numbers() != leaf.public_key().public_numbers()
                or leaf.issuer != ca.subject
                or leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                or set(sans.get_values_for_type(x509.DNSName)) != {plan.provider_plan.descriptor.hostname, "localhost"}
                or set(sans.get_values_for_type(x509.IPAddress)) != {ip_address("127.0.0.1")}
                or ExtendedKeyUsageOID.SERVER_AUTH
                not in leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
                or not leaf.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature
                or leaf.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
                or leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
                != ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
                or leaf.signature_hash_algorithm.name not in {"sha256", "sha384", "sha512"}
            ):
                _fail("BUNDLE_TLS_KEY_OR_IDENTITY_INVALID")
            ca.public_key().verify(
                leaf.signature, leaf.tbs_certificate_bytes, padding.PKCS1v15(), leaf.signature_hash_algorithm
            )
            if (
                not leaf.not_valid_before_utc <= now < leaf.not_valid_after_utc
                or leaf.not_valid_after_utc > ca.not_valid_after_utc
            ):
                _fail("BUNDLE_CERTIFICATE_EXPIRED")
            numbers.append(private.private_numbers().public_numbers.n)
        if plan.provider_plan.descriptor.auth_mode == "native":
            private = serialization.load_pem_private_key(files["keys/native-jwt-private.pem"], password=None)
            public = serialization.load_pem_public_key(files["keys/native-jwt-public.pem"])
            if (
                not isinstance(private, rsa.RSAPrivateKey)
                or private.key_size < 2048
                or private.public_key().public_numbers() != public.public_numbers()
            ):
                _fail("BUNDLE_JWT_PAIR_INVALID")
            numbers.append(private.private_numbers().public_numbers.n)
        if len(numbers) != len(set(numbers)):
            _fail("BUNDLE_INDEPENDENT_KEYS_REQUIRED")
        if (
            b"PRIVATE KEY" in files["tls/trust-bundle.pem"]
            or plan.registration
            and b"PRIVATE KEY" in plan.registration.ca_pem
        ):
            _fail("BUNDLE_TRUST_BUNDLE_INVALID")
        trust = x509.load_pem_x509_certificates(files["tls/trust-bundle.pem"])
        if ca not in trust or any(
            not item.extensions.get_extension_for_class(x509.BasicConstraints).value.ca for item in trust
        ):
            _fail("BUNDLE_TRUST_BUNDLE_INVALID")
        if plan.registration and plan.registration.ca_pem:
            if any(item not in trust for item in x509.load_pem_x509_certificates(plan.registration.ca_pem)):
                _fail("BUNDLE_HCL_CA_MISSING")
    except BundleError:
        raise
    except Exception:
        _fail("BUNDLE_CRYPTO_MATERIAL_INVALID")


def generate_material(plan):
    """Real generator; called only by explicitly authorized preparation."""
    import secrets
    from datetime import UTC, datetime, timedelta
    from ipaddress import ip_address

    import certifi
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.now(UTC)
    password_values = {
        name: secrets.token_urlsafe(32).encode("ascii") for name in _SECRET_NAMES - _BINARY_SECRET_NAMES
    }
    password_values.update({name: secrets.token_bytes(32) for name in _BINARY_SECRET_NAMES})
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "SBOM development " + plan.provider_plan.descriptor.instance_id)]
    )
    ca = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=plan.certificate_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    def pem(key):
        return key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )

    certificates = {"ca": ca.public_bytes(serialization.Encoding.PEM)}
    for component in ("frontend", "postgres", "redis", "mailpit"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, plan.provider_plan.descriptor.hostname)]))
            .issuer_name(ca.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=plan.certificate_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName(plan.provider_plan.descriptor.hostname),
                        x509.DNSName("localhost"),
                        x509.IPAddress(ip_address("127.0.0.1")),
                    ]
                ),
                critical=False,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        certificates[component + "-key"], certificates[component + "-cert"] = (
            pem(key),
            leaf.public_bytes(serialization.Encoding.PEM),
        )
    files = _provider_payloads(plan, password_values, certificates)
    files.update(
        {
            "keys/auth-transaction-key": secrets.token_bytes(32),
            "tls/ca-key.pem": pem(ca_key),
            "tls/ca.pem": certificates["ca"],
            "tls/frontend-key.pem": certificates["frontend-key"],
            "tls/frontend-cert.pem": certificates["frontend-cert"],
            "tls/trust-bundle.pem": certifi.contents().encode("ascii")
            + b"\n"
            + certificates["ca"]
            + (plan.registration.ca_pem if plan.registration else b""),
        }
    )
    if plan.provider_plan.descriptor.auth_mode == "native":
        jwt = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        files.update(
            {
                "keys/native-jwt-private.pem": pem(jwt),
                "keys/native-jwt-public.pem": jwt.public_key().public_bytes(
                    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
                ),
            }
        )
    return BundleMaterial(files, password_values)


@contextmanager
def _parents(plan, *, create):
    """Hold known directory objects; Windows denies rename/delete sharing."""
    anchor = plan.anchor.canonical_path
    parts = (".sbom-dev", "instances", plan.provider_plan.descriptor.instance_id, "bundles")
    identities, descriptors = [], {}
    with ExitStack() as pins:
        path = anchor
        parent = None
        for index, name in enumerate((None, *parts)):
            if name is not None:
                path = path / name
                if create and not os.path.lexists(path):
                    if sys.platform == "win32":
                        dev_instance_storage._windows_create(path)
                    else:
                        os.mkdir(name, 0o700, dir_fd=parent)
            info = dev_instance_storage._verify(path, private=index > 0)
            if index == 0 and (info.st_dev, info.st_ino) != (plan.anchor.device, plan.anchor.inode):
                _fail("BUNDLE_ANCHOR_CHANGED")
            if sys.platform == "win32":
                pins.callback(dev_instance_storage._pin_windows(path))
            else:
                parent = dev_instance_storage._pin_posix(path, info, parent=parent)
                pins.callback(os.close, parent)
                descriptors[path] = parent
            identities.append((path, (info.st_dev, info.st_ino), index > 0))

        def verify():
            dev_instance_storage._revalidate(identities)

        verify()
        yield path, pins, descriptors, identities, verify
        verify()


def _mkdir(path, parent, pins, descriptors, identities):
    dev_instance_storage._revalidate(identities)
    if sys.platform == "win32":
        dev_instance_storage._windows_create(path)
    else:
        os.mkdir(path.name, 0o700, dir_fd=descriptors[parent])
    info = dev_instance_storage._verify(path, private=True)
    if sys.platform == "win32":
        pins.callback(dev_instance_storage._pin_windows(path))
    else:
        descriptor = dev_instance_storage._pin_posix(path, info, parent=descriptors[parent])
        pins.callback(os.close, descriptor)
        descriptors[path] = descriptor
    identities.append((path, (info.st_dev, info.st_ino), True))
    dev_instance_storage._revalidate(identities)


def _write(path, raw, root, descriptors, verify):
    verify()
    dev_private.validate_parent(path, root)
    if sys.platform == "win32":
        dev_private.create_private_file(path, raw)
    else:
        descriptor = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=descriptors[path.parent],
        )
        try:
            remaining = memoryview(raw)
            while remaining:
                count = os.write(descriptor, remaining)
                if count <= 0:
                    _fail("BUNDLE_WRITE_UNCONFIRMED")
                remaining = remaining[count:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    verify()
    observed, proof = _file(path, root)
    if observed != raw:
        _fail("BUNDLE_WRITE_UNCONFIRMED")
    return proof


@contextmanager
def _lock(parent, descriptors, verify):
    path = parent / ".prepare.lock"
    if not os.path.lexists(path):
        try:
            _write(path, b"\0", parent, descriptors, verify)
        except FileExistsError:
            pass
    info = dev_instance_registry._private(path)
    if info.st_size != 1:
        _fail("BUNDLE_LOCK_UNVERIFIED")
    descriptor = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(descriptor, "r+b") as stream:
        if (os.fstat(stream.fileno()).st_dev, os.fstat(stream.fileno()).st_ino) != (info.st_dev, info.st_ino):
            _fail("BUNDLE_LOCK_UNVERIFIED")
        try:
            if sys.platform == "win32":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            _fail("BUNDLE_BUSY")
        verify()
        yield
        verify()
        if _stamp(dev_instance_registry._private(path)) != _stamp(info):
            _fail("BUNDLE_LOCK_UNVERIFIED")


def _generations(parent, generation):
    with os.scandir(parent) as entries:
        for index, entry in enumerate(entries):
            if index > 16:
                _fail("BUNDLE_GENERATION_INVENTORY_UNVERIFIED")
            if entry.name not in {generation, ".prepare.lock"}:
                _fail("BUNDLE_EXISTING_GENERATION_REVIEW_REQUIRED")
            if entry.name == ".prepare.lock" and dev_instance_registry._private(Path(entry.path)).st_size != 1:
                _fail("BUNDLE_LOCK_UNVERIFIED")


@dataclass(frozen=True, slots=True, repr=False)
class BundleReceipt:
    material_fingerprint: str
    private_binding: str
    directory_identity: tuple[int, int]
    file_proofs: tuple[tuple[str, tuple], ...]
    receipt_proof: tuple

    def __post_init__(self):
        def proof(value):
            return (
                type(value) is tuple
                and len(value) == 6
                and all(type(item) is int and item >= 0 for item in value[:5])
                and type(value[-1]) is str
                and _HASH.fullmatch(value[-1]) is not None
            )

        if (
            type(self.material_fingerprint) is not str
            or _HASH.fullmatch(self.material_fingerprint) is None
            or type(self.private_binding) is not str
            or _HASH.fullmatch(self.private_binding) is None
            or type(self.directory_identity) is not tuple
            or len(self.directory_identity) != 2
            or any(type(item) is not int or item < 0 for item in self.directory_identity)
            or self.directory_identity[1] == 0
            or type(self.file_proofs) is not tuple
            or not 1 <= len(self.file_proofs) <= 32
            or any(
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or re.fullmatch(r"(?:provider|keys|tls)/[A-Za-z0-9_.-]+|\.(?:env\.dev\.local|pending\.json)", item[0])
                is None
                or item[0].split("/")[-1] in {".", ".."}
                or not proof(item[1])
                for item in self.file_proofs
            )
            or len({name for name, _ in self.file_proofs}) != len(self.file_proofs)
            or not proof(self.receipt_proof)
        ):
            _fail("BUNDLE_RECEIPT_UNVERIFIED")

    def __repr__(self):
        return "<BundleReceipt: private pinned artifact identities>"

    def private_record(self):
        """For protected controller state only; contains private binding hashes."""
        return {
            "version": 1,
            "material_fingerprint": self.material_fingerprint,
            "private_binding": self.private_binding,
            "directory_identity": list(self.directory_identity),
            "files": [[name, list(proof)] for name, proof in self.file_proofs],
            "receipt_proof": list(self.receipt_proof),
        }

    @classmethod
    def from_private_record(cls, value):
        try:
            if (
                type(value) is not dict
                or set(value)
                != {
                    "version",
                    "material_fingerprint",
                    "private_binding",
                    "directory_identity",
                    "files",
                    "receipt_proof",
                }
                or type(value["version"]) is not int
                or value["version"] != 1
            ):
                _fail("BUNDLE_RECEIPT_UNVERIFIED")
            return cls(
                value["material_fingerprint"],
                value["private_binding"],
                tuple(value["directory_identity"]),
                tuple((name, tuple(proof)) for name, proof in value["files"]),
                tuple(value["receipt_proof"]),
            )
        except BundleError:
            raise
        except Exception:
            _fail("BUNDLE_RECEIPT_UNVERIFIED")


@dataclass(frozen=True, slots=True)
class BundleOutcome:
    code: str
    exit_code: int
    generation: str | None = None
    artifacts_retained: bool = False
    reused: bool = False
    receipt: BundleReceipt | None = field(default=None, repr=False)
    directory: Path | None = field(default=None, repr=False)

    def to_dict(self):
        return {
            "code": self.code,
            "exit_code": self.exit_code,
            "generation": self.generation,
            "artifacts_retained": self.artifacts_retained,
            "reused": self.reused,
            "browser_trust_installed": False,
            "provider_operations_authorized": False,
            "database_authorized": False,
            "enrollment_authorized": False,
        }


def _reuse(plan, expected):
    if type(expected) is not BundleReceipt:
        _fail("BUNDLE_EXISTING_BUNDLE_UNVERIFIED")
    with _parents(plan, create=False) as (parent, pins, descriptors, identities, verify):
        _generations(parent, plan.generation)
        info = dev_instance_registry._private(plan.directory, directory=True)
        if (
            (info.st_dev, info.st_ino) != expected.directory_identity
            or expected.material_fingerprint != plan.material_fingerprint
            or not hmac.compare_digest(expected.private_binding, plan.private_binding)
        ):
            _fail("BUNDLE_RECEIPT_CONTEXT_CHANGED")
        for path in (plan.directory, *(plan.directory / name for name in ("provider", "keys", "tls"))):
            current = dev_instance_storage._verify(path, private=True)
            if sys.platform == "win32":
                pins.callback(dev_instance_storage._pin_windows(path))
            else:
                descriptor = dev_instance_storage._pin_posix(path, current, parent=descriptors[path.parent])
                pins.callback(os.close, descriptor)
                descriptors[path] = descriptor
            identities.append((path, (current.st_dev, current.st_ino), True))
            verify()
        expected_children = {"provider", "keys", "tls", _JOURNAL, _RECEIPT, _MANAGED}
        if {path.name for path in plan.directory.iterdir()} != expected_children:
            _fail("BUNDLE_UNKNOWN_ARTIFACT_REVIEW_REQUIRED")
        for folder in ("provider", "keys", "tls"):
            if {path.name for path in (plan.directory / folder).iterdir()} != {
                Path(name).name for name in plan.files if name.startswith(folder + "/")
            }:
                _fail("BUNDLE_UNKNOWN_ARTIFACT_REVIEW_REQUIRED")
        raw, proof = _file(plan.directory / _RECEIPT, plan.directory)
        if proof != expected.receipt_proof:
            _fail("BUNDLE_RECEIPT_IDENTITY_CHANGED")
        value = json.loads(raw, object_pairs_hook=_object)
        wanted = {
            "version": 1,
            "material_fingerprint": expected.material_fingerprint,
            "private_binding": expected.private_binding,
            "directory_identity": list(expected.directory_identity),
            "files": [[name, list(proof)] for name, proof in expected.file_proofs],
        }
        if value != wanted:
            _fail("BUNDLE_RECEIPT_UNVERIFIED")
        payloads = {}
        if {name for name, _ in expected.file_proofs} != {*plan.files, _MANAGED, _JOURNAL} or len(
            expected.file_proofs
        ) != len(plan.files) + 2:
            _fail("BUNDLE_RECEIPT_UNVERIFIED")
        for name, proof in expected.file_proofs:
            verify()
            raw, observed = _file(plan.directory / name, plan.directory)
            if observed != proof:
                _fail("BUNDLE_FILE_IDENTITY_CHANGED")
            payloads[name] = raw
        env = dev_config.parse_managed(payloads[_MANAGED].decode("ascii"))
        layout = compose.secret_layout(plan.provider_plan)
        secrets = {
            "postgres-bootstrap": payloads["provider/" + layout["postgres"]["bootstrap"]].rstrip(b"\n"),
            "postgres-runtime": payloads["provider/" + layout["postgres"]["runtime"]].rstrip(b"\n"),
            "redis": unquote(urlsplit(env["REDIS_URL"]).password or "").encode("ascii"),
            "redis-session": unquote(urlsplit(env["AUTH_SESSION_REDIS_URL"]).password or "").encode("ascii"),
            "smtp": env["SMTP_PASSWORD"].encode("ascii"),
            "session": base64.b64decode(env["AUTH_SESSION_ENCRYPTION_KEY"], validate=True),
            "outbox": base64.b64decode(env["NATIVE_SECURITY_OUTBOX_KEY"], validate=True),
            "provider-storage": base64.b64decode(env["AI_CONFIG_ENCRYPTION_KEY"], validate=True),
        }
        material = BundleMaterial({name: payloads[name] for name in plan.files}, secrets)
        if _validate_material(plan, material) != env:
            _fail("BUNDLE_CONFIGURATION_CHANGED")
        verify()
        _revalidate(plan)
    return expected


def prepare_bundle(plan, *, authorize, generator=None, expected_receipt=None):
    """Explicit new-only publication or strict known-receipt reuse; never repair."""
    retained = False
    try:
        if type(plan) is not BundlePlan:
            _fail("BUNDLE_PLAN_REQUIRED")
        _revalidate(plan)
        if os.path.lexists(plan.directory):
            retained = True
            receipt = _reuse(plan, expected_receipt)
            return BundleOutcome("BUNDLE_EXISTING_VERIFIED", 0, plan.generation, True, True, receipt, plan.directory)
        if expected_receipt is not None:
            _fail("BUNDLE_RECEIPT_TARGET_MISSING")
        for category in ("credentials", "certificates"):
            if authorize(plan, category) is not True:
                _fail("BUNDLE_" + category.upper() + "_AUTHORIZATION_REQUIRED")
            _revalidate(plan)
        retained = True
        with _parents(plan, create=True) as (parent, pins, descriptors, identities, verify):
            with _lock(parent, descriptors, verify):
                _generations(parent, plan.generation)
                _revalidate(plan)
                _mkdir(plan.directory, parent, pins, descriptors, identities)
                proofs = [
                    (
                        _JOURNAL,
                        _write(
                            plan.directory / _JOURNAL,
                            _json({"version": 1, "plan_fingerprint": plan.fingerprint}),
                            plan.directory,
                            descriptors,
                            verify,
                        ),
                    )
                ]
                material = (generator or generate_material)(plan)
                environment = _validate_material(plan, material)
                _revalidate(plan)
                for name in ("provider", "keys", "tls"):
                    _mkdir(plan.directory / name, plan.directory, pins, descriptors, identities)
                for name, raw in sorted({**material.files, _MANAGED: _managed(environment)}.items()):
                    proofs.append((name, _write(plan.directory / name, raw, plan.directory, descriptors, verify)))
                _revalidate(plan)
                info = dev_instance_registry._private(plan.directory, directory=True)
                record = {
                    "version": 1,
                    "material_fingerprint": plan.material_fingerprint,
                    "private_binding": plan.private_binding,
                    "directory_identity": [info.st_dev, info.st_ino],
                    "files": [[name, list(proof)] for name, proof in proofs],
                }
                receipt_proof = _write(plan.directory / _RECEIPT, _json(record), plan.directory, descriptors, verify)
                receipt = BundleReceipt(
                    plan.material_fingerprint,
                    plan.private_binding,
                    (info.st_dev, info.st_ino),
                    tuple(proofs),
                    receipt_proof,
                )
        return BundleOutcome("BUNDLE_PREPARED", 0, plan.generation, True, False, receipt, plan.directory)
    except BundleError as error:
        return BundleOutcome(error.code, 1, plan.generation if type(plan) is BundlePlan else None, retained)
    except (KeyboardInterrupt, EOFError):
        return BundleOutcome(
            "BUNDLE_PREPARATION_CANCELLED", 130, plan.generation if type(plan) is BundlePlan else None, retained
        )
    except Exception:
        return BundleOutcome(
            "BUNDLE_PREPARATION_UNCONFIRMED", 1, plan.generation if type(plan) is BundlePlan else None, retained
        )


if __name__ == "__main__":
    raise SystemExit("BUNDLE_PREPARATION_ONLY: use the unified launcher and explicit credentials/certificate review.")
