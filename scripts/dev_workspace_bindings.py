"""Protected prepared-artifact continuity; never readiness or resource authority.

Only publish writes. New receipt sections require the same typed completed source
outcome; subsequent invocations may reuse unchanged sections from the protected
history, after checking pinned private files. Standalone artifact receipts and
checkout configuration are never adopted. Unknown/interrupted history is retained
and blocks publication. Hash chains and filesystem identities detect drift, not a
hostile process already running as the same OS user. Every later live operation
still needs its independent policy, identity, target and operator checks.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field, fields
from pathlib import Path
from uuid import UUID, uuid4

if __package__:
    from . import dev_environment, dev_instance_plan, dev_private
    from . import dev_instance_registry as registry
    from . import dev_instance_storage as storage
    from . import dev_workspace_bundle as bundle
    from . import dev_workspace_database_prepare as database
    from . import dev_workspace_engine as engine
    from .dev_workspace_operation_journal import _move_private
else:
    import dev_environment
    import dev_instance_plan
    import dev_instance_registry as registry
    import dev_instance_storage as storage
    import dev_private
    import dev_workspace_bundle as bundle
    import dev_workspace_database_prepare as database
    import dev_workspace_engine as engine
    from dev_workspace_operation_journal import _move_private

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_FILE = re.compile(r"[0-9]{6}\.json\Z")
_CODES = frozenset(
    {
        "BINDING_INPUT_INVALID",
        "BINDING_MISSING",
        "BINDING_OBSERVED",
        "BINDING_ACCESS_UNVERIFIED",
        "BINDING_HISTORY_UNVERIFIED",
        "BINDING_UNKNOWN_ARTIFACT",
        "BINDING_INTERRUPTED_WRITE",
        "BINDING_REVISION_CHANGED",
        "BINDING_REPLAY_BLOCKED",
        "BINDING_CONSENT_REQUIRED",
        "BINDING_COMPLETED_SOURCE_REQUIRED",
        "BINDING_ARTIFACT_CHANGED",
        "BINDING_CONTEXT_CHANGED",
        "BINDING_LIMIT_REQUIRED",
        "BINDING_PUBLICATION_UNCONFIRMED",
        "BINDING_UNSUPPORTED_RECEIPT",
    }
)


class BindingError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else "BINDING_INPUT_INVALID"
        super().__init__(self.code)


def _fail(code):
    raise BindingError(code) from None


def _uuid(value):
    try:
        if type(value) is not str or str(UUID(value)) != value:
            _fail("BINDING_INPUT_INVALID")
    except (ValueError, TypeError, AttributeError):
        _fail("BINDING_INPUT_INVALID")
    return value


def _hash(value):
    if type(value) is not str or _HASH.fullmatch(value) is None:
        _fail("BINDING_INPUT_INVALID")
    return value


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _digest(value):
    return hashlib.sha256(_json(value)).hexdigest()


def _load(raw):
    try:
        return json.loads(raw, object_pairs_hook=registry._json_object)
    except registry.RegistryError:
        _fail("BINDING_HISTORY_UNVERIFIED")


def _fields(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        _fail("BINDING_HISTORY_UNVERIFIED")
    return value


def _array(value, *, limit=64, length=None):
    if type(value) is not list or len(value) > limit or length is not None and len(value) != length:
        _fail("BINDING_HISTORY_UNVERIFIED")
    return value


def _tuple(value, length):
    if (
        type(value) is not tuple
        or len(value) != length
        or any(type(item) is not int or item < 0 for item in value)
        or not value[1]
    ):
        _fail("BINDING_INPUT_INVALID")
    return value


def _tls_module():
    # Kept lazy: an absent/unshipped certificate adapter cannot make other
    # preparation sections unusable, nor can an unknown receipt be accepted.
    try:
        if __package__:
            from . import dev_workspace_certificates
        else:
            import dev_workspace_certificates
        return dev_workspace_certificates
    except ImportError:
        _fail("BINDING_UNSUPPORTED_RECEIPT")


def _path(value):
    if (
        not isinstance(value, Path)
        or not value.is_absolute()
        or any(ord(c) < 32 or ord(c) == 127 for c in str(value))
        or ".." in value.parts
    ):
        _fail("BINDING_INPUT_INVALID")


@dataclass(frozen=True, slots=True, repr=False)
class PolicyFileReference:
    path: Path
    identity: tuple[int, int, int, int, int]

    def __post_init__(self):
        _path(self.path)
        _tuple(self.identity, 5)
        if not 0 < self.identity[2] <= 262144:
            _fail("BINDING_INPUT_INVALID")

    @classmethod
    def inspect(cls, path):
        """Read only file identity/ACL metadata; never policy contents."""
        try:
            path = Path(path)
            return cls(path, engine._file(path, private=True))
        except Exception:
            _fail("BINDING_ACCESS_UNVERIFIED")

    def __repr__(self):
        return "<PolicyFileReference: protected metadata>"


@dataclass(frozen=True, slots=True, repr=False)
class PreparedBinding:
    descriptor: dev_instance_plan.InstanceDescriptor
    bundle_generation: str | None = None
    bundle_receipt: bundle.BundleReceipt | None = None
    certificate_generation: str | None = None
    certificate_receipt: object | None = None
    resources: engine.ResourceRecords | None = None
    database_target: database.Target | None = None
    database_receipts: tuple[database.PreparationReceipt, ...] = ()
    policy_file: PolicyFileReference | None = None

    def __post_init__(self):
        if type(self.descriptor) is not dev_instance_plan.InstanceDescriptor:
            _fail("BINDING_INPUT_INVALID")
        if (self.bundle_generation is None) != (self.bundle_receipt is None) or (
            self.certificate_generation is None
        ) != (self.certificate_receipt is None):
            _fail("BINDING_INPUT_INVALID")
        if self.bundle_receipt is not None:
            _uuid(self.bundle_generation)
            if (
                type(self.bundle_receipt) is not bundle.BundleReceipt
                or self.descriptor.mode != "isolated"
                or self.descriptor.config_generation not in {None, self.bundle_generation}
            ):
                _fail("BINDING_INPUT_INVALID")
        if self.certificate_receipt is not None:
            _uuid(self.certificate_generation)
            if (
                type(self.certificate_receipt) is not _tls_module().CertificateReceipt
                or self.certificate_receipt.generation != self.certificate_generation
                or self.descriptor.mode == "isolated"
            ):
                _fail("BINDING_INPUT_INVALID")
        if self.resources is not None and (
            type(self.resources) is not engine.ResourceRecords or self.descriptor.mode != "isolated"
        ):
            _fail("BINDING_INPUT_INVALID")
        if (
            type(self.database_receipts) is not tuple
            or len(self.database_receipts) > 3
            or any(type(value) is not database.PreparationReceipt for value in self.database_receipts)
            or len({value.action for value in self.database_receipts}) != len(self.database_receipts)
        ):
            _fail("BINDING_INPUT_INVALID")
        for receipt in self.database_receipts:
            roles = {name for name, _oid in receipt.object_oids}
            if (
                len(receipt.revisions) > 8
                or len(set(receipt.revisions)) != len(receipt.revisions)
                or receipt.action == "initdb"
                and (roles or receipt.revisions)
                or receipt.action in {"database", "migrate"}
                and roles != {"owner", "runtime", "database"}
                or receipt.action == "database"
                and receipt.revisions
                or receipt.action == "migrate"
                and not receipt.revisions
            ):
                _fail("BINDING_INPUT_INVALID")
        if len({value.cluster_id for value in self.database_receipts}) > 1:
            _fail("BINDING_CONTEXT_CHANGED")
        if (
            tuple(value.action for value in self.database_receipts)
            != ("initdb", "database", "migrate")[: len(self.database_receipts)]
        ):
            _fail("BINDING_CONTEXT_CHANGED")
        if len(self.database_receipts) == 3 and dict(self.database_receipts[1].object_oids) != dict(
            self.database_receipts[2].object_oids
        ):
            _fail("BINDING_CONTEXT_CHANGED")
        if self.database_target is not None:
            target = self.database_target
            if (
                type(target) is not database.Target
                or target.instance_id != self.descriptor.instance_id
                or target.database != self.descriptor.resources.get("database")
                or target.port != self.descriptor.ports.get("postgres")
                or self.resources is None
                or not self.database_receipts
            ):
                _fail("BINDING_INPUT_INVALID")
            pg = next(value for value in self.resources.containers if value.component == "postgres")
            if (target.engine_identity, target.provider_fingerprint, target.postgres_id) != (
                self.resources.engine_identity,
                self.resources.provider_fingerprint,
                pg.object_id,
            ) or (
                self.descriptor.resources["postgres_volume"],
                target.volume_id,
                target.volume_birth,
            ) not in self.resources.volume_births:
                _fail("BINDING_CONTEXT_CHANGED")
            if any(value.target_fingerprint != target.fingerprint() for value in self.database_receipts):
                _fail("BINDING_CONTEXT_CHANGED")
        elif self.database_receipts:
            _fail("BINDING_INPUT_INVALID")
        if self.policy_file is not None and type(self.policy_file) is not PolicyFileReference:
            _fail("BINDING_INPUT_INVALID")
        if self.resources is not None:
            expected = {self.descriptor.resources["postgres_volume"], self.descriptor.resources["redis_volume"]}
            if (
                {value[0] for value in self.resources.volume_births} != expected
                or self.resources.secrets
                and self.bundle_receipt is None
            ):
                _fail("BINDING_CONTEXT_CHANGED")

    def __repr__(self):
        return "<PreparedBinding: protected preparation continuity; authority unverified>"

    def public_summary(self):
        return {
            "instance_id": self.descriptor.instance_id,
            "commit": self.descriptor.commit,
            "sections": [
                name
                for name, present in (
                    ("bundle", self.bundle_receipt),
                    ("certificates", self.certificate_receipt),
                    ("provider", self.resources),
                    ("database", self.database_receipts),
                    ("policy", self.policy_file),
                )
                if present
            ],
            "ownership_verified": False,
            "ready": False,
            "live_operations_authorized": False,
        }


@dataclass(frozen=True, slots=True, repr=False)
class CompletedSources:
    """Trusted source results, not deserialized user assertions or authority."""

    bundle_plan: bundle.BundlePlan | None = None
    bundle_outcome: bundle.BundleOutcome | None = None
    certificate_plan: object | None = None
    certificate_outcome: object | None = None
    engine_plan: engine.EngineActionPlan | None = None
    engine_outcome: engine.EngineOutcome | None = None
    database_plan: database.PreparationPlan | None = None
    database_outcome: database.PreparationOutcome | None = None
    policy_reference: PolicyFileReference | None = None

    def __post_init__(self):
        for first, second, types in (
            (self.bundle_plan, self.bundle_outcome, (bundle.BundlePlan, bundle.BundleOutcome)),
            (self.engine_plan, self.engine_outcome, (engine.EngineActionPlan, engine.EngineOutcome)),
            (self.database_plan, self.database_outcome, (database.PreparationPlan, database.PreparationOutcome)),
        ):
            if (
                (first is None) != (second is None)
                or first is not None
                and (type(first) is not types[0] or type(second) is not types[1])
            ):
                _fail("BINDING_COMPLETED_SOURCE_REQUIRED")
        if (self.certificate_plan is None) != (self.certificate_outcome is None):
            _fail("BINDING_COMPLETED_SOURCE_REQUIRED")
        if self.certificate_plan is not None:
            tls = _tls_module()
            if (
                type(self.certificate_plan) is not tls.CertificatePlan
                or type(self.certificate_outcome) is not tls.CertificateOutcome
            ):
                _fail("BINDING_COMPLETED_SOURCE_REQUIRED")
        if self.policy_reference is not None and type(self.policy_reference) is not PolicyFileReference:
            _fail("BINDING_COMPLETED_SOURCE_REQUIRED")


def _private_record(binding, home):
    def relative(path):
        try:
            return path.relative_to(home).as_posix()
        except ValueError:
            _fail("BINDING_CONTEXT_CHANGED")

    records = binding.resources
    return {
        "descriptor": binding.descriptor.to_dict(),
        "bundle_generation": binding.bundle_generation,
        "bundle_receipt": binding.bundle_receipt.private_record() if binding.bundle_receipt else None,
        "certificate_generation": binding.certificate_generation,
        "certificate_receipt": binding.certificate_receipt.private_record() if binding.certificate_receipt else None,
        "resources": None
        if records is None
        else {
            "engine_identity": records.engine_identity,
            "provider_fingerprint": records.provider_fingerprint,
            "containers": [
                {item.name: getattr(value, item.name) for item in fields(engine.ContainerRecord)}
                for value in records.containers
            ],
            "network_id": records.network_id,
            "volume_births": [list(value) for value in records.volume_births],
            "secrets": [
                {"reference": value.reference, "path": relative(value.path), "identity": list(value.identity)}
                for value in records.secrets
            ],
        },
        "database_target": {item.name: getattr(binding.database_target, item.name) for item in fields(database.Target)}
        if binding.database_target
        else None,
        "database_receipts": [
            {
                "action": value.action,
                "target_fingerprint": value.target_fingerprint,
                "cluster_id": value.cluster_id,
                "object_oids": [list(item) for item in value.object_oids],
                "revisions": list(value.revisions),
            }
            for value in binding.database_receipts
        ],
        "policy_file": {"path": relative(binding.policy_file.path), "identity": list(binding.policy_file.identity)}
        if binding.policy_file
        else None,
    }


def _decode(raw, home):
    _fields(raw, tuple(item.name for item in fields(PreparedBinding)))

    def path(value):
        if (
            type(value) is not str
            or not value
            or "\\" in value
            or any(part in {"", ".", ".."} for part in value.split("/"))
            or Path(value).is_absolute()
            or ":" in value
        ):
            _fail("BINDING_HISTORY_UNVERIFIED")
        return home / value

    def receipt(value, cls):
        if value is None:
            return None
        _array(value.get("directory_identity") if type(value) is dict else None, length=2)
        _array(value.get("receipt_proof"), length=6)
        for item in _array(value.get("files"), limit=32):
            _array(item, length=2)
            _array(item[1], length=6)
        result = cls.from_private_record(value)
        if result.private_record() != value:
            _fail("BINDING_HISTORY_UNVERIFIED")
        return result

    resources = raw["resources"]
    if resources is not None:
        _fields(
            resources,
            ("engine_identity", "provider_fingerprint", "containers", "network_id", "volume_births", "secrets"),
        )
        containers = tuple(
            engine.ContainerRecord(**_fields(value, ("component", "object_id", "started_at")))
            for value in _array(resources["containers"], length=3)
        )
        births = tuple(tuple(_array(value, length=3)) for value in _array(resources["volume_births"], length=2))
        secrets = []
        for value in _array(resources["secrets"], limit=32):
            _fields(value, ("reference", "path", "identity"))
            secrets.append(
                engine.SecretFile(value["reference"], path(value["path"]), tuple(_array(value["identity"], length=5)))
            )
        resources = engine.ResourceRecords(
            resources["engine_identity"],
            resources["provider_fingerprint"],
            containers,
            resources["network_id"],
            births,
            tuple(secrets),
        )
    target = raw["database_target"]
    if target is not None:
        target = database.Target(**_fields(target, tuple(item.name for item in fields(database.Target))))
    receipts = []
    for value in _array(raw["database_receipts"], limit=3):
        _fields(value, ("action", "target_fingerprint", "cluster_id", "object_oids", "revisions"))
        receipts.append(
            database.PreparationReceipt(
                value["action"],
                value["target_fingerprint"],
                value["cluster_id"],
                tuple(tuple(_array(item, length=2)) for item in _array(value["object_oids"], limit=3)),
                tuple(_array(value["revisions"], limit=8)),
            )
        )
    policy = raw["policy_file"]
    if policy is not None:
        _fields(policy, ("path", "identity"))
        policy = PolicyFileReference(path(policy["path"]), tuple(_array(policy["identity"], length=5)))
    value = PreparedBinding(
        dev_instance_plan.InstanceDescriptor.from_dict(raw["descriptor"]),
        raw["bundle_generation"],
        receipt(raw["bundle_receipt"], bundle.BundleReceipt),
        raw["certificate_generation"],
        receipt(raw["certificate_receipt"], _tls_module().CertificateReceipt)
        if raw["certificate_receipt"] is not None
        else None,
        resources,
        target,
        tuple(receipts),
        policy,
    )
    if _private_record(value, home) != raw:
        _fail("BINDING_HISTORY_UNVERIFIED")
    return value


@dataclass(frozen=True, slots=True)
class BindingSnapshot:
    code: str
    revision: int = 0
    binding: PreparedBinding | None = field(default=None, repr=False)

    def __post_init__(self):
        if (
            type(self.code) is not str
            or self.code not in _CODES
            or type(self.revision) is not int
            or not 0 <= self.revision <= 128
            or self.binding is not None
            and type(self.binding) is not PreparedBinding
        ):
            _fail("BINDING_INPUT_INVALID")
        if (
            (self.binding is not None) != (self.code == "BINDING_OBSERVED")
            or self.binding is not None
            and not self.revision
        ):
            _fail("BINDING_INPUT_INVALID")

    def to_dict(self):
        return {
            "code": self.code,
            "revision": self.revision,
            "binding": self.binding.public_summary() if self.binding else None,
            "ownership_verified": False,
            "ready": False,
            "live_operations_authorized": False,
            "recovery": "Preserve unknown or partial artifacts; do not adopt standalone receipts or regenerate credentials.",
        }


class BindingStore:
    MAX_REVISIONS, MAX_FILES, MAX_BYTES = 128, 130, 262144

    def __init__(self, *, home, instance_id):
        self.home, self.instance_id = Path(home), _uuid(instance_id)
        _path(self.home)
        self.root = self.home / ".sbom-dev" / "instances" / instance_id / "bindings"
        self._store = registry.InstanceRegistry(self.root, anchor=self.home)
        self._pins = None

    def _parent_pins(self):
        # A conventional owned, non-writable 0755 home is valid. Every state
        # descendant is private; no permissions are changed or repaired.
        storage._verify(self.home, private=False)
        path, result = self.home, []
        for name in (".sbom-dev", "instances", self.instance_id):
            path /= name
            result.append(registry._identity(storage._verify(path, private=True)))
        return tuple(result)

    def _scan(self):
        info = self._store._root()
        parent_pins = self._parent_pins()
        root_identity, anchor_identity = (
            registry._identity(info),
            registry._identity(storage._verify(self.home, private=False)),
        )
        before = registry._stamp(info)
        paths, lock_identity = [], None
        with os.scandir(self.root) as items:
            for index, item in enumerate(items):
                if index >= self.MAX_FILES:
                    _fail("BINDING_LIMIT_REQUIRED")
                if item.name == ".registry.lock":
                    lock = registry._private(self.root / item.name)
                    if lock.st_size != 1:
                        _fail("BINDING_ACCESS_UNVERIFIED")
                    lock_identity = registry._identity(lock)
                elif item.name.startswith(".pending-binding-"):
                    _fail("BINDING_INTERRUPTED_WRITE")
                elif _FILE.fullmatch(item.name):
                    paths.append(self.root / item.name)
                else:
                    _fail("BINDING_UNKNOWN_ARTIFACT")
        if len(paths) > self.MAX_REVISIONS:
            _fail("BINDING_LIMIT_REQUIRED")
        pins = (root_identity, anchor_identity, lock_identity, parent_pins)
        if self._pins is not None and pins != self._pins:
            _fail("BINDING_CONTEXT_CHANGED")
        history = []
        for revision, path in enumerate(sorted(paths), 1):
            prior = registry._private(path)
            raw = dev_environment.bounded_read_bytes(path, self.MAX_BYTES)
            if registry._stamp(prior) != registry._stamp(registry._private(path)):
                _fail("BINDING_HISTORY_UNVERIFIED")
            value = _fields(
                _load(raw),
                (
                    "version",
                    "instance_id",
                    "revision",
                    "previous",
                    "root_identity",
                    "anchor_identity",
                    "lock_identity",
                    "parent_identities",
                    "binding",
                    "digest",
                ),
            )
            for name in ("root_identity", "anchor_identity", "lock_identity"):
                _tuple(tuple(_array(value[name], length=2)), 2)
            for item in _array(value["parent_identities"], length=3):
                _tuple(tuple(_array(item, length=2)), 2)
            if (
                type(value["version"]) is not int
                or value["version"] != 1
                or type(value["revision"]) is not int
                or value["revision"] != revision
                or path.name != f"{revision:06d}.json"
                or value["instance_id"] != self.instance_id
                or value["previous"] != (history[-1]["digest"] if history else None)
                or value["root_identity"] != list(root_identity)
                or value["anchor_identity"] != list(anchor_identity)
                or lock_identity is None
                or value["lock_identity"] != list(lock_identity)
                or value["parent_identities"] != [list(item) for item in parent_pins]
            ):
                _fail("BINDING_HISTORY_UNVERIFIED")
            body = {key: item for key, item in value.items() if key != "digest"}
            if _hash(value["digest"]) != _digest(body):
                _fail("BINDING_HISTORY_UNVERIFIED")
            binding = _decode(value["binding"], self.home)
            if binding.descriptor.instance_id != self.instance_id:
                _fail("BINDING_CONTEXT_CHANGED")
            if history:
                self._continuity(history[-1]["decoded"], binding)
            history.append({**value, "decoded": binding, "file_stamp": registry._stamp(prior)})
        if registry._stamp(self._store._root()) != before or self._parent_pins() != parent_pins:
            _fail("BINDING_REVISION_CHANGED")
        return history, pins

    def read(self):
        """Read protected history and known file identities; never create a lock."""
        try:
            history, pins = self._scan()
            if not history:
                return BindingSnapshot("BINDING_MISSING")
            self._verify_files(history[-1]["decoded"])
            self._pins = pins
            return BindingSnapshot("BINDING_OBSERVED", len(history), history[-1]["decoded"])
        except registry.RegistryError as error:
            return BindingSnapshot(
                "BINDING_MISSING" if error.code == "REGISTRY_MISSING" else "BINDING_ACCESS_UNVERIFIED"
            )
        except BindingError as error:
            return BindingSnapshot(error.code)
        except Exception:
            return BindingSnapshot("BINDING_HISTORY_UNVERIFIED")

    @staticmethod
    def _continuity(previous, current):
        before, after = previous.descriptor.to_dict(), current.descriptor.to_dict()
        for name in ("commit", "manifest_hashes", "config_generation", "configuration_present"):
            before.pop(name)
            after.pop(name)
        if (
            before != after
            or previous.descriptor.config_generation is not None
            and previous.descriptor.config_generation != current.descriptor.config_generation
            or previous.descriptor.configuration_present
            and not current.descriptor.configuration_present
        ):
            _fail("BINDING_CONTEXT_CHANGED")
        for name in (
            "bundle_generation",
            "bundle_receipt",
            "certificate_generation",
            "certificate_receipt",
            "database_target",
        ):
            if getattr(previous, name) is not None and getattr(previous, name) != getattr(current, name):
                _fail("BINDING_CONTEXT_CHANGED")
        if previous.policy_file is not None and current.policy_file is None:
            _fail("BINDING_CONTEXT_CHANGED")
        old_receipts = {value.action: value for value in previous.database_receipts}
        if any(
            value.action not in {item.action for item in current.database_receipts}
            for value in previous.database_receipts
        ) or any(
            value.action in old_receipts and value.action != "migrate" and value != old_receipts[value.action]
            for value in current.database_receipts
        ):
            _fail("BINDING_CONTEXT_CHANGED")
        if previous.resources is not None:
            if current.resources is None or (
                previous.resources.engine_identity,
                previous.resources.provider_fingerprint,
                previous.resources.network_id,
                previous.resources.volume_births,
                previous.resources.secrets,
                tuple((v.component, v.object_id) for v in previous.resources.containers),
            ) != (
                current.resources.engine_identity,
                current.resources.provider_fingerprint,
                current.resources.network_id,
                current.resources.volume_births,
                current.resources.secrets,
                tuple((v.component, v.object_id) for v in current.resources.containers),
            ):
                _fail("BINDING_CONTEXT_CHANGED")

    def _verify_files(self, binding):
        def parents(path):
            dev_private.validate_parent(path, self.home)
            storage._verify(self.home, private=False)
            directory = self.home
            for name in path.parent.relative_to(self.home).parts:
                directory /= name
                storage._verify(directory, private=True)

        def artifacts(directory, expected, receipt_name):
            parents(directory / receipt_name)
            before = registry._private(directory, directory=True)
            if registry._identity(before) != expected.directory_identity:
                _fail("BINDING_ARTIFACT_CHANGED")
            wanted_files = {name for name, _ in expected.file_proofs}
            expected_dirs = {str(Path(name).parent) for name in wanted_files if "/" in name}
            layouts = {
                directory: {Path(name).parts[0] for name in wanted_files} | {receipt_name},
                **{
                    directory / folder: {Path(name).name for name in wanted_files if str(Path(name).parent) == folder}
                    for folder in expected_dirs
                },
            }
            for folder, names in layouts.items():
                registry._private(folder, directory=True)
                found = set()
                with os.scandir(folder) as entries:
                    for count, entry in enumerate(entries):
                        if count >= 64:
                            _fail("BINDING_LIMIT_REQUIRED")
                        found.add(entry.name)
                if found != names:
                    _fail("BINDING_ARTIFACT_CHANGED")
            raw, proof = bundle._file(directory / receipt_name, directory)
            if proof != expected.receipt_proof:
                _fail("BINDING_ARTIFACT_CHANGED")
            wanted = {key: value for key, value in expected.private_record().items() if key != "receipt_proof"}
            if json.loads(raw, object_pairs_hook=registry._json_object) != wanted:
                _fail("BINDING_ARTIFACT_CHANGED")
            for name, expected_proof in expected.file_proofs:
                parents(directory / name)
                if bundle._file(directory / name, directory)[1] != expected_proof:
                    _fail("BINDING_ARTIFACT_CHANGED")
            if registry._stamp(registry._private(directory, directory=True)) != registry._stamp(before):
                _fail("BINDING_ARTIFACT_CHANGED")

        if binding.bundle_receipt is not None:
            directory = self.root.parent / "bundles" / binding.bundle_generation
            artifacts(directory, binding.bundle_receipt, ".receipt.json")
        if binding.certificate_receipt is not None:
            directory = (
                self.home / ".sbom-dev" / "tls" / UUID(self.instance_id).hex / UUID(binding.certificate_generation).hex
            )
            artifacts(directory, binding.certificate_receipt, "r.json")
        if binding.policy_file:
            parents(binding.policy_file.path)
            if engine._file(binding.policy_file.path, private=True) != binding.policy_file.identity:
                _fail("BINDING_ARTIFACT_CHANGED")
        if binding.resources:
            directory = self.root.parent / "bundles" / binding.bundle_generation if binding.bundle_generation else None
            proofs = dict(binding.bundle_receipt.file_proofs) if binding.bundle_receipt else {}
            for secret in binding.resources.secrets:
                if (
                    directory is None
                    or not secret.path.is_relative_to(directory)
                    or secret.path.relative_to(directory).as_posix() not in proofs
                ):
                    _fail("BINDING_CONTEXT_CHANGED")
                parents(secret.path)
                if engine._file(secret.path, private=True) != secret.identity:
                    _fail("BINDING_ARTIFACT_CHANGED")

    def _completed(self, binding, previous, sources):
        def changed(name):
            return getattr(binding, name) is not None and (
                previous is None or getattr(previous, name) != getattr(binding, name)
            )

        def descriptor_matches(value):
            before, after = value.to_dict(), binding.descriptor.to_dict()
            for name in ("config_generation", "configuration_present"):
                before.pop(name)
                after.pop(name)
            return before == after

        def anchor_matches(value):
            return value.canonical_path == self.home and (value.device, value.inode) == registry._identity(
                storage._verify(self.home, private=False)
            )

        if changed("bundle_receipt"):
            plan, outcome = sources.bundle_plan, sources.bundle_outcome
            if (
                plan is None
                or outcome.code != "BUNDLE_PREPARED"
                or outcome.exit_code != 0
                or outcome.reused
                or outcome.receipt != binding.bundle_receipt
                or outcome.generation != binding.bundle_generation
                or outcome.directory != plan.directory
                or plan.directory != self.root.parent / "bundles" / binding.bundle_generation
                or not anchor_matches(plan.anchor)
                or not descriptor_matches(plan.provider_plan.descriptor)
                or (plan.material_fingerprint, plan.private_binding)
                != (binding.bundle_receipt.material_fingerprint, binding.bundle_receipt.private_binding)
            ):
                _fail("BINDING_COMPLETED_SOURCE_REQUIRED")
        if changed("certificate_receipt"):
            plan, outcome = sources.certificate_plan, sources.certificate_outcome
            if (
                plan is None
                or outcome.code != "TLS_PREPARED"
                or outcome.exit_code != 0
                or outcome.reused
                or outcome.receipt != binding.certificate_receipt
                or plan.generation != binding.certificate_generation
                or plan.directory
                != self.home
                / ".sbom-dev"
                / "tls"
                / UUID(self.instance_id).hex
                / UUID(binding.certificate_generation).hex
                or not anchor_matches(plan.anchor)
                or not descriptor_matches(plan.descriptor)
                or outcome.tls.certificate != plan.directory / "s.pem"
                or outcome.tls.private_key != plan.directory / "s.key"
                or outcome.tls.ca_bundle != plan.directory / "c.pem"
                or binding.certificate_receipt.material_binding != plan.material_binding
            ):
                _fail("BINDING_COMPLETED_SOURCE_REQUIRED")
        if changed("resources"):
            plan, outcome = sources.engine_plan, sources.engine_outcome
            first = previous is None or previous.resources is None
            if (
                plan is None
                or outcome.code != "ENGINE_ACTION_COMPLETED"
                or outcome.records != binding.resources
                or not descriptor_matches(plan.provider.descriptor)
                or first
                and (
                    plan.consent.action != "create"
                    or set(outcome.completed_ids) != {value.object_id for value in binding.resources.containers}
                )
                or (binding.resources.engine_identity, binding.resources.provider_fingerprint)
                != (plan.capability.engine_identity, plan.provider.fingerprint)
            ):
                _fail("BINDING_COMPLETED_SOURCE_REQUIRED")
        previous_receipts = previous.database_receipts if previous else ()
        new_receipts = [value for value in binding.database_receipts if value not in previous_receipts]
        if new_receipts:
            plan, outcome = sources.database_plan, sources.database_outcome
            prior = previous_receipts[-1] if previous_receipts else None
            if (
                len(new_receipts) != 1
                or plan is None
                or outcome.code != "DB_PREPARATION_COMPLETED"
                or not outcome.cleanup_verified
                or outcome.unconfirmed_helper_ids
                or outcome.receipt != new_receipts[0]
                or plan.target != binding.database_target
                or outcome.postgres_id != binding.database_target.postgres_id
                or not descriptor_matches(plan.provider_plan.descriptor)
                or plan.target.fingerprint() != new_receipts[0].target_fingerprint
                or plan.action != new_receipts[0].action
                or plan.prior != prior
                or plan.records != binding.resources
            ):
                _fail("BINDING_COMPLETED_SOURCE_REQUIRED")
        if changed("policy_file") and sources.policy_reference != binding.policy_file:
            _fail("BINDING_COMPLETED_SOURCE_REQUIRED")

    def publish(self, binding, *, expected_revision, authorize, completed=None):
        """Explicit stage-guarded append-only CAS. Failure retains partial state."""
        publication_started = False
        try:
            if (
                type(binding) is not PreparedBinding
                or binding.descriptor.instance_id != self.instance_id
                or type(expected_revision) is not int
                or not 0 <= expected_revision < self.MAX_REVISIONS
                or not callable(authorize)
            ):
                _fail("BINDING_INPUT_INVALID")
            completed = CompletedSources() if completed is None else completed
            if type(completed) is not CompletedSources:
                _fail("BINDING_COMPLETED_SOURCE_REQUIRED")

            def guard():
                if authorize(binding, expected_revision) is not True:
                    _fail("BINDING_CONSENT_REQUIRED")

            guard()
            try:
                history, _pins = self._scan()
            except registry.RegistryError as error:
                if error.code != "REGISTRY_MISSING" or expected_revision:
                    raise
                history = []
            if len(history) != expected_revision:
                _fail("BINDING_REVISION_CHANGED")
            previous = history[-1]["decoded"] if history else None
            if previous:
                self._continuity(previous, binding)
            if previous == binding:
                _fail("BINDING_REPLAY_BLOCKED")
            self._completed(binding, previous, completed)
            self._verify_files(binding)
            guard()
            storage.initialize_private_directory(self.root, anchor=self.home)
            with self._store._lock() as lock_verify:
                history, pins = self._scan()

                def verify():
                    lock_verify()
                    if self._parent_pins() != pins[3]:
                        _fail("BINDING_CONTEXT_CHANGED")

                if len(history) != expected_revision:
                    _fail("BINDING_REVISION_CHANGED")
                if previous != (history[-1]["decoded"] if history else None):
                    _fail("BINDING_REVISION_CHANGED")
                self._verify_files(binding)
                guard()
                verify()
                revision = expected_revision + 1
                body = {
                    "version": 1,
                    "instance_id": self.instance_id,
                    "revision": revision,
                    "previous": history[-1]["digest"] if history else None,
                    "root_identity": list(pins[0]),
                    "anchor_identity": list(pins[1]),
                    "lock_identity": list(pins[2]),
                    "parent_identities": [list(item) for item in pins[3]],
                    "binding": _private_record(binding, self.home),
                }
                payload = _json({**body, "digest": _digest(body)})
                if len(payload) > self.MAX_BYTES:
                    _fail("BINDING_LIMIT_REQUIRED")
                stage = self.root / (".pending-binding-" + uuid4().hex + ".json")
                destination = self.root / f"{revision:06d}.json"
                dev_private.validate_parent(stage, self.home)
                dev_private.create_private_file(stage, payload)
                info = registry._private(stage)
                if dev_environment.bounded_read_bytes(stage, self.MAX_BYTES) != payload:
                    _fail("BINDING_PUBLICATION_UNCONFIRMED")
                self._verify_files(binding)
                guard()
                verify()
                if (
                    registry._stamp(registry._private(stage)) != registry._stamp(info)
                    or dev_environment.bounded_read_bytes(stage, self.MAX_BYTES) != payload
                ):
                    _fail("BINDING_PUBLICATION_UNCONFIRMED")
                for record in history:
                    if (
                        registry._stamp(registry._private(self.root / f"{record['revision']:06d}.json"))
                        != record["file_stamp"]
                    ):
                        _fail("BINDING_REVISION_CHANGED")
                verify()
                publication_started = True
                _move_private(stage, destination)
                verify()
                if (
                    registry._identity(registry._private(destination)) != registry._identity(info)
                    or dev_environment.bounded_read_bytes(destination, self.MAX_BYTES) != payload
                ):
                    _fail("BINDING_PUBLICATION_UNCONFIRMED")
                self._pins = pins
            return BindingSnapshot("BINDING_OBSERVED", revision, binding)
        except BindingError:
            if publication_started:
                _fail("BINDING_PUBLICATION_UNCONFIRMED")
            raise
        except Exception:
            _fail("BINDING_PUBLICATION_UNCONFIRMED")
