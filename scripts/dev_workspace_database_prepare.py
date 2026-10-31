"""Separately approved isolated PostgreSQL preparation; no startup dispatch.

This module imports no driver/application and never opens a database or invokes
an engine itself. Trusted adapters execute the fixed operations below after fresh
identity and policy verification. They must use bounded, TLS-verified, explicitly
pinned connections, redact credentials without changing audit/security settings,
and provide durable claims/receipts. Caller JSON or matching names are not such
adapters. No destructive recovery or automatic retry is provided.

OS-nonroot initdb still creates a PostgreSQL bootstrap superuser. That credential
is restricted to explicit preparation, separate from the NOLOGIN schema owner
and the restricted application role. Migration execution is a distinct reviewed
transactional adapter action; historical bootstrap wrappers are never called.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Protocol
from uuid import UUID

if __package__:
    from . import dev_workspace_compose as compose
    from . import dev_workspace_engine as engine
    from . import dev_workspace_provider as provider
else:
    import dev_workspace_compose as compose
    import dev_workspace_engine as engine
    import dev_workspace_provider as provider

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_REVISION = re.compile(r"[a-zA-Z0-9_]{1,128}\Z")
_ACTIONS = frozenset({"initdb", "database", "migrate"})
_CHECKS = frozenset(
    {
        "exact-operator-action",
        "company-policy",
        "provider-ownership",
        "image-contract",
        "nonroot-volume-ownership",
        "private-bundle",
        "exclusive-preparation",
    }
)
_ACTION_CHECKS = {
    "initdb": frozenset({"fresh-empty-volume", "bootstrap-superuser", "initdb-image-tools"}),
    "database": frozenset(
        {"exact-cluster-database", "restricted-role-schema", "credential-transport", "preparation-server"}
    ),
    "migrate": frozenset(
        {
            "exact-cluster-database",
            "migration-source-review",
            "backup-and-rehearsal",
            "transactional-migrations",
            "schema-predecessor",
            "preparation-server",
        }
    ),
}
_CODES = frozenset(
    {
        "DB_PREPARATION_INPUT_INVALID",
        "DB_EXACT_CONFIRMATION_REQUIRED",
        "DB_TARGET_UNVERIFIED",
        "DB_POLICY_REQUIRED",
        "DB_SOURCE_CHANGED",
        "DB_PROVIDER_DRIFT",
        "DB_VOLUME_NOT_FRESH",
        "DB_CLUSTER_RECEIPT_REQUIRED",
        "DB_SCHEMA_RECEIPT_REQUIRED",
        "DB_ROLE_OR_SCHEMA_CONFLICT",
        "DB_REPLAY_OR_PENDING_ATTEMPT",
        "DB_HELPER_UNCONFIRMED",
        "DB_PREPARATION_UNCONFIRMED",
        "DB_PREPARATION_COMPLETED",
        "DB_MIGRATION_REVIEW_REQUIRED",
    }
)


class PreparationError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else "DB_PREPARATION_INPUT_INVALID"
        super().__init__(self.code)


def _fail(code):
    raise PreparationError(code) from None


def _hash(value):
    if type(value) is not str or _HASH.fullmatch(value) is None:
        _fail("DB_PREPARATION_INPUT_INVALID")
    return value


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class MigrationSelection:
    predecessor: tuple[str, ...]
    heads: tuple[str, ...]
    files: tuple[tuple[str, str], ...]
    strategy: str
    schema_fingerprint: str

    def __post_init__(self):
        _hash(self.schema_fingerprint)
        for revisions in (self.predecessor, self.heads):
            if (
                type(revisions) is not tuple
                or len(revisions) > 8
                or any(type(value) is not str or _REVISION.fullmatch(value) is None for value in revisions)
                or len(set(revisions)) != len(revisions)
            ):
                _fail("DB_MIGRATION_REVIEW_REQUIRED")
        if (
            not self.heads
            or self.strategy not in {"reviewed-fresh-baseline", "reviewed-upgrade"}
            or type(self.files) is not tuple
            or not 1 <= len(self.files) <= 512
        ):
            _fail("DB_MIGRATION_REVIEW_REQUIRED")
        for item in self.files:
            if (
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or re.fullmatch(
                    r"(?:alembic/(?:env\.py|versions/[A-Za-z0-9_.-]+\.py)|alembic\.ini|scripts/schema/postgresql_047_baseline\.sql)",
                    item[0],
                )
                is None
            ):
                _fail("DB_MIGRATION_REVIEW_REQUIRED")
            _hash(item[1])
        if len({name for name, _ in self.files}) != len(self.files):
            _fail("DB_MIGRATION_REVIEW_REQUIRED")


@dataclass(frozen=True, slots=True)
class Target:
    instance_id: str
    engine_identity: str
    provider_fingerprint: str
    postgres_id: str
    volume_id: str
    volume_birth: str
    image: str
    user: str
    database: str
    bootstrap_role: str
    owner_role: str
    runtime_role: str
    port: int

    def __post_init__(self):
        try:
            token = UUID(self.instance_id).hex
            if str(UUID(self.instance_id)) != self.instance_id:
                _fail("DB_TARGET_UNVERIFIED")
            for value in (
                self.engine_identity,
                self.provider_fingerprint,
                self.postgres_id,
                self.volume_id,
                self.volume_birth,
            ):
                _hash(value)
            expected = (
                "sbom_dev_" + token,
                "sbom_dev_" + token + "_bootstrap",
                "sbom_dev_" + token + "_owner",
                "sbom_dev_" + token + "_runtime",
            )
            if (
                (self.database, self.bootstrap_role, self.owner_role, self.runtime_role) != expected
                or type(self.user) is not str
                or re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", self.user) is None
                or type(self.port) is not int
                or not 1024 <= self.port <= 65535
                or self.port in {5432, 55439, 56044}
            ):
                _fail("DB_TARGET_UNVERIFIED")
            provider._image(self.image)
        except Exception:
            _fail("DB_TARGET_UNVERIFIED")

    def fingerprint(self):
        return _digest([getattr(self, name) for name in self.__dataclass_fields__])


@dataclass(frozen=True, slots=True)
class PreparationReceipt:
    action: str
    target_fingerprint: str
    cluster_id: str
    object_oids: tuple[tuple[str, int], ...] = ()
    revisions: tuple[str, ...] = ()

    def __post_init__(self):
        if type(self.action) is not str or self.action not in _ACTIONS:
            _fail("DB_PREPARATION_INPUT_INVALID")
        _hash(self.target_fingerprint)
        _hash(self.cluster_id)
        if (
            type(self.object_oids) is not tuple
            or len(self.object_oids) > 3
            or any(
                type(item) is not tuple
                or len(item) != 2
                or item[0] not in {"owner", "runtime", "database"}
                or type(item[1]) is not int
                or not 0 < item[1] < 2**32
                for item in self.object_oids
            )
            or len({name for name, _ in self.object_oids}) != len(self.object_oids)
        ):
            _fail("DB_PREPARATION_INPUT_INVALID")
        if type(self.revisions) is not tuple or any(
            type(value) is not str or _REVISION.fullmatch(value) is None for value in self.revisions
        ):
            _fail("DB_PREPARATION_INPUT_INVALID")


@dataclass(frozen=True, slots=True)
class PreparationPlan:
    action: str
    target: Target
    source_fingerprint: str
    provider_plan: provider.ContainerProviderPlan = field(repr=False)
    compose_plan: compose.ComposePlan = field(repr=False)
    records: engine.ResourceRecords = field(repr=False)
    prior: PreparationReceipt | None = None
    migration: MigrationSelection | None = None
    fingerprint: str = ""

    def __post_init__(self):
        if (
            type(self.action) is not str
            or self.action not in _ACTIONS
            or type(self.target) is not Target
            or type(self.provider_plan) is not provider.ContainerProviderPlan
            or type(self.compose_plan) is not compose.ComposePlan
            or type(self.records) is not engine.ResourceRecords
        ):
            _fail("DB_PREPARATION_INPUT_INVALID")
        _hash(self.source_fingerprint)
        _hash(self.fingerprint)

    def to_dict(self):
        return {
            "action": self.action,
            "instance_id": self.target.instance_id,
            "database": self.target.database,
            "roles": {
                "bootstrap": self.target.bootstrap_role,
                "owner": self.target.owner_role,
                "runtime": self.target.runtime_role,
            },
            "fingerprint": self.fingerprint,
            "source_fingerprint": self.source_fingerprint,
            "migration_heads": list(self.migration.heads) if self.migration else [],
            "live_authorized": False,
            "database_ready": False,
            "automatic_startup_initialization": False,
        }


def plan_preparation(
    provider_plan, compose_plan, records, action, *, confirm_database, source_fingerprint, prior=None, migration=None
):
    """Pure exact-target plan; no environment, files, driver or engine access."""
    try:
        if (
            type(provider_plan) is not provider.ContainerProviderPlan
            or type(compose_plan) is not compose.ComposePlan
            or type(records) is not engine.ResourceRecords
            or type(action) is not str
            or action not in _ACTIONS
        ):
            _fail("DB_PREPARATION_INPUT_INVALID")
        if (
            provider.plan_provider(provider_plan.descriptor, provider_plan.policy) != provider_plan
            or compose_plan.provider_plan != provider_plan
        ):
            _fail("DB_TARGET_UNVERIFIED")
        compose.revalidate_compose(
            compose_plan, provider_plan=provider_plan, policy=compose_plan.policy, review=compose_plan.review
        )
        if compose_plan.blockers or (records.engine_identity, records.provider_fingerprint) != (
            provider_plan.policy.engine_identity,
            provider_plan.fingerprint,
        ):
            _fail("DB_TARGET_UNVERIFIED")
        if type(confirm_database) is not str or confirm_database != provider_plan.descriptor.resources["database"]:
            _fail("DB_EXACT_CONFIRMATION_REQUIRED")
        _hash(source_fingerprint)
        spec = next(value for value in provider_plan.containers if value.component == "postgres")
        record = next(value for value in records.containers if value.component == "postgres")
        logical = provider_plan.descriptor.resources["postgres_volume"]
        volume = next(value for value in records.volume_births if value[0] == logical)
        token = UUID(provider_plan.descriptor.instance_id).hex
        if re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", spec.user) is None:
            _fail("DB_TARGET_UNVERIFIED")
        target = Target(
            provider_plan.descriptor.instance_id,
            records.engine_identity,
            provider_plan.fingerprint,
            record.object_id,
            volume[1],
            volume[2],
            spec.image,
            spec.user,
            confirm_database,
            provider_plan.database_owner_role,
            "sbom_dev_" + token + "_owner",
            provider_plan.database_runtime_role,
            provider_plan.descriptor.ports["postgres"],
        )
        if action == "initdb":
            if prior is not None or migration is not None:
                _fail("DB_VOLUME_NOT_FRESH")
        else:
            if type(prior) is not PreparationReceipt or prior.target_fingerprint != target.fingerprint():
                _fail("DB_CLUSTER_RECEIPT_REQUIRED")
            if action == "database" and (prior.action != "initdb" or prior.object_oids):
                _fail("DB_CLUSTER_RECEIPT_REQUIRED")
            if action == "migrate" and (
                prior.action not in {"database", "migrate"}
                or {name for name, _ in prior.object_oids} != {"database", "owner", "runtime"}
            ):
                _fail("DB_SCHEMA_RECEIPT_REQUIRED")
            if (
                action == "database"
                and migration is not None
                or action == "migrate"
                and (type(migration) is not MigrationSelection or migration.predecessor != prior.revisions)
            ):
                _fail("DB_MIGRATION_REVIEW_REQUIRED")
        binding = [
            action,
            target.fingerprint(),
            compose_plan.fingerprint,
            compose_plan.policy.private_binding(),
            source_fingerprint,
            [prior.action, prior.cluster_id, prior.object_oids, prior.revisions] if prior else None,
            [migration.predecessor, migration.heads, migration.files, migration.strategy, migration.schema_fingerprint]
            if migration
            else None,
        ]
        return PreparationPlan(
            action, target, source_fingerprint, provider_plan, compose_plan, records, prior, migration, _digest(binding)
        )
    except PreparationError:
        raise
    except Exception:
        _fail("DB_PREPARATION_INPUT_INVALID")


@dataclass(frozen=True, slots=True)
class Consent:
    action: str
    operation_id: str
    plan_fingerprint: str
    confirm_database: str

    def __post_init__(self):
        try:
            if (
                type(self.action) is not str
                or self.action not in _ACTIONS
                or type(self.operation_id) is not str
                or str(UUID(self.operation_id)) != self.operation_id
            ):
                _fail("DB_POLICY_REQUIRED")
            _hash(self.plan_fingerprint)
            if (
                type(self.confirm_database) is not str
                or re.fullmatch(r"sbom_dev_[0-9a-f]{32}", self.confirm_database) is None
            ):
                _fail("DB_EXACT_CONFIRMATION_REQUIRED")
        except Exception:
            _fail("DB_POLICY_REQUIRED")


@dataclass(frozen=True, slots=True)
class ProviderState:
    """Fresh trusted adapter observation, not a serialized permission token."""

    target_fingerprint: str
    data_state: str
    postgres_state: str
    uid: int
    gid: int
    mode: int
    cluster_id: str | None = None

    def __post_init__(self):
        _hash(self.target_fingerprint)
        if (
            type(self.data_state) is not str
            or self.data_state not in {"EMPTY", "INITIALIZED", "UNKNOWN"}
            or type(self.postgres_state) is not str
            or self.postgres_state not in {"created", "exited", "running", "unknown"}
            or any(type(value) is not int or not 0 <= value <= 2147483647 for value in (self.uid, self.gid, self.mode))
        ):
            _fail("DB_PROVIDER_DRIFT")
        if self.cluster_id is not None:
            _hash(self.cluster_id)


@dataclass(frozen=True, slots=True)
class RoleState:
    name: str
    oid: int
    login: bool
    inherit: bool = False
    superuser: bool = False
    createdb: bool = False
    createrole: bool = False
    replication: bool = False
    bypassrls: bool = False
    memberships: tuple = ()

    def __post_init__(self):
        if (
            type(self.name) is not str
            or re.fullmatch(r"sbom_dev_[0-9a-f]{32}_(?:owner|runtime)", self.name) is None
            or type(self.oid) is not int
            or not 0 < self.oid < 2**32
            or type(self.memberships) is not tuple
            or len(self.memberships) > 32
            or any(type(value) is not int or not 0 < value < 2**32 for value in self.memberships)
        ):
            _fail("DB_ROLE_OR_SCHEMA_CONFLICT")
        if any(
            type(getattr(self, name)) is not bool
            for name in ("login", "inherit", "superuser", "createdb", "createrole", "replication", "bypassrls")
        ):
            _fail("DB_ROLE_OR_SCHEMA_CONFLICT")


@dataclass(frozen=True, slots=True)
class DatabaseState:
    cluster_id: str
    database: str
    user: str
    tls_peer: str
    bounded: bool
    roles: tuple[RoleState, ...]
    database_exists: bool
    database_oid: int | None
    database_owner: str | None
    schema_empty: bool
    public_create: bool
    runtime_grants_safe: bool
    revisions: tuple[str, ...] = ()
    effective_user: str | None = None
    read_only: bool = False
    schema_fingerprint: str | None = None

    def __post_init__(self):
        _hash(self.cluster_id)
        _hash(self.tls_peer)
        if (
            type(self.database) is not str
            or re.fullmatch(r"(?:postgres|sbom_dev_[0-9a-f]{32})", self.database) is None
            or type(self.user) is not str
            or re.fullmatch(r"sbom_dev_[0-9a-f]{32}_bootstrap", self.user) is None
            or type(self.roles) is not tuple
            or len(self.roles) > 2
            or any(type(value) is not RoleState for value in self.roles)
            or len({role.name for role in self.roles}) != len(self.roles)
            or any(
                type(getattr(self, name)) is not bool
                for name in (
                    "bounded",
                    "database_exists",
                    "schema_empty",
                    "public_create",
                    "runtime_grants_safe",
                    "read_only",
                )
            )
            or self.database_oid is not None
            and (type(self.database_oid) is not int or not 0 < self.database_oid < 2**32)
            or type(self.revisions) is not tuple
            or any(type(value) is not str or _REVISION.fullmatch(value) is None for value in self.revisions)
        ):
            _fail("DB_TARGET_UNVERIFIED")
        if self.database_owner is not None and (
            type(self.database_owner) is not str
            or re.fullmatch(r"sbom_dev_[0-9a-f]{32}_owner", self.database_owner) is None
        ):
            _fail("DB_TARGET_UNVERIFIED")
        if self.effective_user is not None and (
            type(self.effective_user) is not str
            or re.fullmatch(r"sbom_dev_[0-9a-f]{32}_(?:bootstrap|owner)", self.effective_user) is None
        ):
            _fail("DB_TARGET_UNVERIFIED")
        if self.schema_fingerprint is not None:
            _hash(self.schema_fingerprint)


@dataclass(frozen=True, slots=True)
class Statement:
    template: str
    identifiers: tuple[str, ...]

    def compose(self, sql_module):
        """Driver Identifier composition only; never interpolates a password."""
        return sql_module.SQL(self.template).format(*(sql_module.Identifier(value) for value in self.identifiers))


def statements(plan, operation):
    """Fixed nonsecret operations for a reviewed transactional driver adapter."""
    target = plan.target
    role_flags = " NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
    values = {
        "create-owner": (Statement("CREATE ROLE {} NOLOGIN" + role_flags, (target.owner_role,)),),
        "create-runtime": (Statement("CREATE ROLE {} NOLOGIN" + role_flags, (target.runtime_role,)),),
        "create-database": (
            Statement("CREATE DATABASE {} OWNER {} TEMPLATE template0", (target.database, target.owner_role)),
        ),
        "prepare-schema": (
            Statement("REVOKE ALL ON DATABASE {} FROM PUBLIC", (target.database,)),
            Statement("REVOKE ALL ON SCHEMA public FROM PUBLIC", ()),
            Statement("ALTER SCHEMA public OWNER TO {}", (target.owner_role,)),
            Statement("GRANT CONNECT ON DATABASE {} TO {}", (target.database, target.runtime_role)),
            Statement("GRANT USAGE ON SCHEMA public TO {}", (target.runtime_role,)),
        ),
        "runtime-login": (Statement("ALTER ROLE {} LOGIN" + role_flags, (target.runtime_role,)),),
        "migration-owner": (Statement("SET LOCAL ROLE {}", (target.owner_role,)),),
        "runtime-grants": (
            Statement(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {}", (target.runtime_role,)
            ),
            Statement("REVOKE ALL ON public.alembic_version FROM {}", (target.runtime_role,)),
            Statement("GRANT SELECT ON public.alembic_version TO {}", (target.runtime_role,)),
            Statement("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {}", (target.runtime_role,)),
        ),
    }
    if operation not in values:
        _fail("DB_PREPARATION_INPUT_INVALID")
    return values[operation]


def initdb_command(plan):
    """Create an unstarted helper with a receipt; password value is never argv."""
    target, spec = plan.target, plan.provider_plan.containers[0]
    reference = compose.secret_layout(plan.provider_plan)["postgres"]["bootstrap"]
    secret = next(item for item in plan.records.secrets if item.reference == reference)
    if any(char in str(secret.path) for char in ',"\r\n\0'):
        _fail("DB_TARGET_UNVERIFIED")
    return (
        "container",
        "create",
        "--pull",
        "never",
        "--network",
        "none",
        "--user",
        spec.user,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--restart",
        "no",
        "--pids-limit",
        "192",
        "--memory",
        "805306368",
        "--cpus",
        "1.5",
        "--entrypoint",
        "initdb",
        "--mount",
        "type=volume,source=" + target.volume_id + ",target=/var/lib/postgresql/data,volume-nocopy",
        "--mount",
        "type=bind,source=" + str(secret.path) + ",target=/run/secrets/bootstrap-password,readonly",
        target.image,
        "--pgdata=/var/lib/postgresql/data",
        "--username=" + target.bootstrap_role,
        "--pwfile=/run/secrets/bootstrap-password",
        "--auth-host=scram-sha-256",
        "--auth-local=scram-sha-256",
        "--no-instructions",
    )


class ProviderAdapter(Protocol):
    """Own bounded engine calls; inspect exact IDs/image/mounts/private files.

    EMPTY means every entry was independently inspected; absence of PG_VERSION
    alone is insufficient. Verify the UID/GID/0700 and accepted population policy.
    Never chown, run root, adopt by label/name, or remove a helper/data resource.
    """

    def observe(self, plan: PreparationPlan) -> ProviderState: ...
    def create_helper(self, plan: PreparationPlan, command: tuple[str, ...]) -> str: ...
    def start_server(self, plan: PreparationPlan, command: tuple[str, ...], *, timeout: int) -> None:
        """Explicit preparation only; revalidate exact recorded PostgreSQL CID.

        Run only its direct-postgres entrypoint after approved initdb. This is
        never ordinary application startup or permission to initialize a volume.
        """
        ...

    def run_helper(self, plan: PreparationPlan, helper_id: str, *, timeout: int) -> int:
        """Revalidate returned CID/image/user/command/volume then run and inspect exit.

        Exit0 means this helper CID is independently verified stopped with exit0,
        not merely that Docker CLI returned0. On timeout/repeated cancellation,
        bounded cleanup may stop only that revalidated helper; uncertainty raises
        and the caller retains/reports its receipt. Never remove it or its volume.
        """
        ...


class DatabaseSession(Protocol):
    """Owned TLS/cluster-pinned session with bounded statements and writer lock.

    apply uses Statement.compose with driver Identifiers. create-database uses an
    explicit owned autocommit control session. install_runtime_credential consumes
    only the private reference via independently reviewed credential transport;
    it must not log SQL credential literals or change audit/security settings.
    """

    def inspect(self) -> DatabaseState: ...
    def begin(self) -> None: ...
    def apply(self, operation: str, sql: tuple[Statement, ...]) -> int | None: ...
    def install_runtime_credential(self, role: str, reference: str) -> None: ...
    def commit(self) -> None: ...
    def rollback(self) -> None: ...
    def close(self) -> None: ...


class DatabaseAdapter(Protocol):
    def open(self, plan: PreparationPlan, database: str, *, readonly: bool = False) -> DatabaseSession: ...


class MigrationAdapter(Protocol):
    """Execute only the independently rehashed reviewed selection in this tx.

    No auto-Alembic/fresh bootstrap, extra DBs, privileged Native grants, environment
    fallback, scripts outside the pinned closure or nontransactional operations.
    """

    def apply(self, plan: PreparationPlan, session: DatabaseSession) -> None: ...


class Authority(Protocol):
    """Reload approved policy, source/file/bundle/TLS evidence and exact consent."""

    def source_fingerprint(self, plan: PreparationPlan) -> str: ...
    def verify(
        self,
        plan: PreparationPlan,
        consent: Consent,
        stage: str,
        provider_state: ProviderState,
        database_state: DatabaseState | None,
    ) -> frozenset[str]: ...


class Journal(Protocol):
    """Durable exclusive claim, intent before mutation and post-action receipts.

    Pending/used operation IDs cannot be replayed. Failed/unknown attempts require
    independent reconciliation; existing matching roles or PG_VERSION are not it.
    """

    def claim(self, plan: PreparationPlan, consent: Consent) -> bool: ...
    def intent(self, plan: PreparationPlan, stage: str) -> None: ...
    def receipt(self, plan: PreparationPlan, kind: str, object_id: str | int) -> None: ...
    def outcome(self, plan: PreparationPlan, outcome: PreparationOutcome) -> None: ...


@dataclass(frozen=True, slots=True)
class PreparationOutcome:
    code: str
    completed: tuple[str, ...] = ()
    helper_id: str | None = None
    receipt: PreparationReceipt | None = None
    cleanup_verified: bool = True
    postgres_id: str | None = None
    unconfirmed_helper_ids: tuple[str, ...] = ()

    def __post_init__(self):
        stages = {
            "create-initdb-helper",
            "run-initdb-helper",
            "start-preparation-server",
            "begin-roles",
            "create-owner",
            "create-runtime",
            "commit-roles",
            "create-database",
            "begin-schema",
            "prepare-schema",
            "runtime-credential",
            "runtime-login",
            "commit-schema",
            "begin-migration",
            "migration-owner",
            "apply-migration",
            "runtime-grants",
            "commit-migration",
        }
        if (
            type(self.code) is not str
            or self.code not in _CODES
            or type(self.completed) is not tuple
            or any(type(value) is not str or value not in stages for value in self.completed)
            or type(self.cleanup_verified) is not bool
            or type(self.unconfirmed_helper_ids) is not tuple
            or len(self.unconfirmed_helper_ids) > 2048
            or any(type(value) is not str or _HASH.fullmatch(value) is None for value in self.unconfirmed_helper_ids)
            or len(set(self.unconfirmed_helper_ids)) != len(self.unconfirmed_helper_ids)
            or self.unconfirmed_helper_ids
            and (self.cleanup_verified or self.code == "DB_PREPARATION_COMPLETED")
            or self.receipt is not None
            and type(self.receipt) is not PreparationReceipt
        ):
            _fail("DB_PREPARATION_INPUT_INVALID")
        if self.helper_id is not None:
            _hash(self.helper_id)
        if self.postgres_id is not None:
            _hash(self.postgres_id)

    def to_dict(self):
        return {
            "code": self.code,
            "completed": list(self.completed),
            "helper_id": self.helper_id,
            "unconfirmed_helper_ids": list(self.unconfirmed_helper_ids),
            "cleanup_verified": self.cleanup_verified,
            "postgres_id": self.postgres_id,
            "uncertainty_preserved": self.code != "DB_PREPARATION_COMPLETED",
            "application_ready": False,
            "automatic_retry_permitted": False,
            "destructive_recovery_permitted": False,
        }


class PreparationExecutor:
    def __init__(self, *, provider_adapter, authority, journal, database_adapter=None, migration_adapter=None):
        required = (
            (provider_adapter, ("observe", "create_helper", "run_helper", "start_server")),
            (authority, ("source_fingerprint", "verify")),
            (journal, ("claim", "intent", "receipt", "outcome")),
        )
        if any(not callable(getattr(adapter, name, None)) for adapter, names in required for name in names):
            _fail("DB_POLICY_REQUIRED")
        self.provider, self.authority, self.journal = provider_adapter, authority, journal
        self.database, self.migrations = database_adapter, migration_adapter

    def _gate(
        self,
        plan,
        consent,
        stage,
        session=None,
        *,
        fresh=False,
        expected_database=None,
        expected_oids=(),
        readonly=False,
    ):
        current = plan_preparation(
            plan.provider_plan,
            plan.compose_plan,
            plan.records,
            plan.action,
            confirm_database=consent.confirm_database,
            source_fingerprint=plan.source_fingerprint,
            prior=plan.prior,
            migration=plan.migration,
        )
        if (
            current != plan
            or type(consent) is not Consent
            or (consent.action, consent.plan_fingerprint) != (plan.action, plan.fingerprint)
        ):
            _fail("DB_POLICY_REQUIRED")
        if self.authority.source_fingerprint(plan) != plan.source_fingerprint:
            _fail("DB_SOURCE_CHANGED")
        observed = self.provider.observe(plan)
        if type(observed) is not ProviderState or observed.target_fingerprint != plan.target.fingerprint():
            _fail("DB_PROVIDER_DRIFT")
        uid, gid = (int(value) for value in plan.target.user.split(":"))
        if (observed.uid, observed.gid, observed.mode) != (uid, gid, 0o700) or observed.data_state not in {
            "EMPTY",
            "INITIALIZED",
        }:
            _fail("DB_PROVIDER_DRIFT")
        if plan.action == "initdb" and (
            observed.postgres_state not in {"created", "exited"}
            or fresh
            and (observed.data_state != "EMPTY" or observed.cluster_id is not None)
        ):
            _fail("DB_VOLUME_NOT_FRESH")
        if plan.action != "initdb" and (
            observed.data_state != "INITIALIZED" or observed.cluster_id != plan.prior.cluster_id
        ):
            _fail("DB_CLUSTER_RECEIPT_REQUIRED")
        state = session.inspect() if session is not None else None
        if state is not None:
            if (
                type(state) is not DatabaseState
                or state.cluster_id != plan.prior.cluster_id
                or state.database != expected_database
                or state.user != plan.target.bootstrap_role
                or state.effective_user
                not in (
                    {plan.target.bootstrap_role, plan.target.owner_role}
                    if plan.action == "migrate"
                    else {None, plan.target.bootstrap_role}
                )
                or readonly
                and state.read_only is not True
                or state.bounded is not True
                or type(state.tls_peer) is not str
                or _HASH.fullmatch(state.tls_peer) is None
            ):
                _fail("DB_TARGET_UNVERIFIED")
            for role in state.roles:
                if (
                    type(role) is not RoleState
                    or role.name not in {plan.target.owner_role, plan.target.runtime_role}
                    or any(
                        getattr(role, field) is not False
                        for field in ("inherit", "superuser", "createdb", "createrole", "replication", "bypassrls")
                    )
                    or role.memberships
                    or role.name == plan.target.owner_role
                    and role.login is not False
                ):
                    _fail("DB_ROLE_OR_SCHEMA_CONFLICT")
            observed_roles = {role.name: role.oid for role in state.roles}
            for key, oid in expected_oids:
                if key == "database":
                    if state.database_oid != oid or state.database_owner != plan.target.owner_role:
                        _fail("DB_ROLE_OR_SCHEMA_CONFLICT")
                elif observed_roles.get(plan.target.owner_role if key == "owner" else plan.target.runtime_role) != oid:
                    _fail("DB_ROLE_OR_SCHEMA_CONFLICT")
            if stage == "commit-schema" and (
                state.public_create
                or not state.runtime_grants_safe
                or not state.schema_empty
                or not any(role.name == plan.target.runtime_role and role.login is True for role in state.roles)
            ):
                _fail("DB_ROLE_OR_SCHEMA_CONFLICT")
            if stage == "commit-migration" and (
                state.public_create
                or not state.runtime_grants_safe
                or state.revisions != plan.migration.heads
                or state.schema_fingerprint != plan.migration.schema_fingerprint
            ):
                _fail("DB_MIGRATION_REVIEW_REQUIRED")
        checks = self.authority.verify(plan, consent, stage, observed, state)
        if type(checks) is not frozenset or not (_CHECKS | _ACTION_CHECKS[plan.action]) <= checks:
            _fail("DB_POLICY_REQUIRED")
        return observed, state

    def execute(self, plan, consent):
        completed, helper, sessions, attempted = [], None, [], False
        claimed, cleanup_verified, known_oids, contexts = False, True, [], {}
        helper_run_attempted, helper_stopped = False, False

        def reported_helpers(error=None):
            """Diagnostic metadata only; never inspect, terminate or adopt by ID.

            Trusted adapters may fail after creation but before returning a CID.
            Refuse arbitrary iterators/attributes and retain cleanup uncertainty
            even when malformed metadata cannot be published safely.
            """
            ids, uncertain, reported = set(), False, None
            if isinstance(error, PreparationError):
                try:
                    value = getattr(error, "helper_id", None)
                except BaseException:
                    value, uncertain = None, True
                if type(value) is str and _HASH.fullmatch(value):
                    reported = value
                    ids.add(value)
                    uncertain = True
                elif value is not None:
                    uncertain = True
            missing = object()
            try:
                values = getattr(self.provider, "unconfirmed_helper_ids", missing)
            except BaseException:
                values, uncertain = missing, True
            if values is not missing:
                if type(values) in {tuple, list, set, frozenset} and len(values) <= 1024:
                    uncertain = uncertain or bool(values)
                    ids.update(value for value in values if type(value) is str and _HASH.fullmatch(value))
                else:
                    uncertain = True
            return tuple(sorted(ids)), uncertain, reported

        def close_owned(*, rollback=False):
            nonlocal cleanup_verified
            for session in reversed(sessions):
                if rollback:
                    try:
                        session.rollback()
                    except (Exception, KeyboardInterrupt, EOFError):
                        cleanup_verified = False
                try:
                    session.close()
                except (Exception, KeyboardInterrupt, EOFError):
                    cleanup_verified = False
            sessions.clear()

        def gate(stage, session=None, *, fresh=False, readonly=False):
            return self._gate(
                plan,
                consent,
                stage,
                session,
                fresh=fresh,
                expected_database=contexts.get(id(session)),
                expected_oids=tuple(known_oids),
                readonly=readonly,
            )

        def open_owned(database, *, readonly=False):
            session = self.database.open(plan, database, readonly=readonly)
            if any(session is existing for existing in sessions):
                _fail("DB_TARGET_UNVERIFIED")
            sessions.append(session)
            contexts[id(session)] = database
            return session

        try:
            if type(plan) is not PreparationPlan or type(consent) is not Consent:
                _fail("DB_PREPARATION_INPUT_INVALID")
            gate("before-claim", fresh=plan.action == "initdb")
            if self.journal.claim(plan, consent) is not True:
                _fail("DB_REPLAY_OR_PENDING_ATTEMPT")
            claimed = True

            def mutate(stage, function, session=None, *, fresh=False):
                nonlocal attempted
                self.journal.intent(plan, stage)
                gate(stage, session, fresh=fresh)
                attempted = True
                value = function()
                completed.append(stage)
                return value

            if plan.action == "initdb":
                helper = mutate(
                    "create-initdb-helper", lambda: self.provider.create_helper(plan, initdb_command(plan)), fresh=True
                )
                _hash(helper)
                self.journal.receipt(plan, "initdb-helper", helper)

                def run_initdb():
                    nonlocal helper_run_attempted
                    helper_run_attempted = True
                    return self.provider.run_helper(plan, helper, timeout=120)

                result = mutate("run-initdb-helper", run_initdb, fresh=True)
                helper_stopped = type(result) is int and result == 0
                if type(result) is not int or result != 0:
                    _fail("DB_HELPER_UNCONFIRMED")
                observed, _ = gate("verify-initdb")
                if observed.data_state != "INITIALIZED":
                    _fail("DB_HELPER_UNCONFIRMED")
                receipt = PreparationReceipt("initdb", plan.target.fingerprint(), _hash(observed.cluster_id))
                self.journal.receipt(plan, "cluster", receipt.cluster_id)
            else:
                if self.database is None:
                    _fail("DB_POLICY_REQUIRED")
                observed, _ = gate("inspect-preparation-server")
                if observed.postgres_state in {"created", "exited"}:
                    mutate(
                        "start-preparation-server",
                        lambda: self.provider.start_server(
                            plan, ("container", "start", plan.target.postgres_id), timeout=30
                        ),
                    )
                    observed, _ = gate("verify-preparation-server")
                if observed.postgres_state != "running":
                    _fail("DB_PROVIDER_DRIFT")
                control = open_owned("postgres" if plan.action == "database" else plan.target.database)
                _, initial = gate("inspect-database", control)
                if plan.action == "database":
                    if initial.database_exists or initial.roles or not initial.schema_empty:
                        _fail("DB_ROLE_OR_SCHEMA_CONFLICT")
                    mutate("begin-roles", control.begin, control)
                    for operation, key in (("create-owner", "owner"), ("create-runtime", "runtime")):
                        oid = mutate(operation, lambda op=operation: control.apply(op, statements(plan, op)), control)
                        if type(oid) is not int or not 0 < oid < 2**32:
                            _fail("DB_PREPARATION_UNCONFIRMED")
                        known_oids.append((key, oid))
                    mutate("commit-roles", control.commit, control)
                    for key, oid in known_oids:
                        self.journal.receipt(plan, key, oid)
                    database_oid = mutate(
                        "create-database",
                        lambda: control.apply("create-database", statements(plan, "create-database")),
                        control,
                    )
                    if type(database_oid) is not int or not 0 < database_oid < 2**32:
                        _fail("DB_PREPARATION_UNCONFIRMED")
                    known_oids.append(("database", database_oid))
                    self.journal.receipt(plan, "database", database_oid)
                    target = open_owned(plan.target.database)
                    mutate("begin-schema", target.begin, target)
                    mutate(
                        "prepare-schema",
                        lambda: target.apply("prepare-schema", statements(plan, "prepare-schema")),
                        target,
                    )
                    reference = compose.secret_layout(plan.provider_plan)["postgres"]["runtime"]
                    mutate(
                        "runtime-credential",
                        lambda: target.install_runtime_credential(plan.target.runtime_role, reference),
                        target,
                    )
                    mutate(
                        "runtime-login",
                        lambda: target.apply("runtime-login", statements(plan, "runtime-login")),
                        target,
                    )
                    _, ready = gate("before-schema-commit", target)
                    if (
                        ready.public_create
                        or not ready.runtime_grants_safe
                        or not ready.schema_empty
                        or not any(role.name == plan.target.runtime_role and role.login is True for role in ready.roles)
                    ):
                        _fail("DB_ROLE_OR_SCHEMA_CONFLICT")
                    mutate("commit-schema", target.commit, target)
                    receipt = PreparationReceipt(
                        "database", plan.target.fingerprint(), plan.prior.cluster_id, tuple(known_oids)
                    )
                else:
                    if (
                        self.migrations is None
                        or initial.revisions != plan.migration.predecessor
                        or initial.public_create
                        or not initial.runtime_grants_safe
                    ):
                        _fail("DB_MIGRATION_REVIEW_REQUIRED")
                    oids = dict(plan.prior.object_oids)
                    if initial.database_oid != oids["database"] or {role.name: role.oid for role in initial.roles} != {
                        plan.target.owner_role: oids["owner"],
                        plan.target.runtime_role: oids["runtime"],
                    }:
                        _fail("DB_ROLE_OR_SCHEMA_CONFLICT")
                    known_oids.extend(plan.prior.object_oids)
                    target = control
                    mutate("begin-migration", target.begin, target)
                    mutate(
                        "migration-owner",
                        lambda: target.apply("migration-owner", statements(plan, "migration-owner")),
                        target,
                    )
                    mutate("apply-migration", lambda: self.migrations.apply(plan, target), target)
                    mutate(
                        "runtime-grants",
                        lambda: target.apply("runtime-grants", statements(plan, "runtime-grants")),
                        target,
                    )
                    _, ready = gate("before-migration-commit", target)
                    if (
                        ready.public_create
                        or not ready.runtime_grants_safe
                        or ready.revisions != plan.migration.heads
                        or ready.schema_fingerprint != plan.migration.schema_fingerprint
                    ):
                        _fail("DB_MIGRATION_REVIEW_REQUIRED")
                    mutate("commit-migration", target.commit, target)
                    receipt = PreparationReceipt(
                        "migrate",
                        plan.target.fingerprint(),
                        plan.prior.cluster_id,
                        plan.prior.object_oids,
                        plan.migration.heads,
                    )
                closed = tuple(sessions)
                close_owned()
                if not cleanup_verified:
                    _fail("DB_PREPARATION_UNCONFIRMED")
                reader = open_owned(plan.target.database, readonly=True)
                if any(reader is writer for writer in closed):
                    _fail("DB_TARGET_UNVERIFIED")
                _, final = gate("verify-database", reader, readonly=True)
                expected_roles = {
                    plan.target.owner_role: dict(known_oids)["owner"],
                    plan.target.runtime_role: dict(known_oids)["runtime"],
                }
                if (
                    final.database_owner != plan.target.owner_role
                    or final.public_create
                    or not final.runtime_grants_safe
                    or final.revisions != receipt.revisions
                    or {role.name: role.oid for role in final.roles} != expected_roles
                    or not any(role.name == plan.target.runtime_role and role.login is True for role in final.roles)
                    or plan.action == "database"
                    and not final.schema_empty
                    or plan.action == "migrate"
                    and final.schema_fingerprint != plan.migration.schema_fingerprint
                ):
                    _fail("DB_PREPARATION_UNCONFIRMED")
                close_owned()
                if not cleanup_verified:
                    _fail("DB_PREPARATION_UNCONFIRMED")
            _, uncertain, _ = reported_helpers()
            if uncertain:
                cleanup_verified = False
                _fail("DB_HELPER_UNCONFIRMED")
            outcome = PreparationOutcome(
                "DB_PREPARATION_COMPLETED", tuple(completed), helper, receipt, cleanup_verified, plan.target.postgres_id
            )
            self.journal.outcome(plan, outcome)
            return outcome
        except BaseException as error:
            unconfirmed, uncertain, reported = reported_helpers(error)
            if type(helper) is not str or _HASH.fullmatch(helper) is None:
                uncertain = uncertain or helper is not None
                helper = reported or (unconfirmed[0] if len(unconfirmed) == 1 else None)
            if helper_run_attempted and not helper_stopped:
                cleanup_verified = False
                if helper is not None:
                    unconfirmed = tuple(sorted(set(unconfirmed) | {helper}))
            if uncertain:
                cleanup_verified = False
            close_owned(rollback=True)
            code = (
                error.code
                if isinstance(error, PreparationError) and not attempted and cleanup_verified
                else "DB_PREPARATION_UNCONFIRMED"
            )
            outcome = PreparationOutcome(
                code,
                tuple(completed),
                helper,
                cleanup_verified=cleanup_verified,
                postgres_id=plan.target.postgres_id if type(plan) is PreparationPlan else None,
                unconfirmed_helper_ids=unconfirmed,
            )
            if claimed:
                try:
                    self.journal.outcome(plan, outcome)
                except (Exception, KeyboardInterrupt, EOFError):
                    pass
            return outcome
