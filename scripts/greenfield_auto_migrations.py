"""Automatic local migration selection, with explicit per-unit confirmation.

No database, credentials, Docker or migration modules are touched on import.
Future migrations carry their own startup preflight/acceptance contract; the
launcher never guesses that a revision marker proves schema correctness.
"""

from __future__ import annotations

import ast
import re
from types import SimpleNamespace

from . import greenfield_migrations as common
from .greenfield_migration_graph import DiscoveryError, SourceLock, discover


def _check_pending_claim():
    pending = common.stack.STATE / "pending-schema-upgrade.json"
    if pending.exists() or pending.is_symlink():
        raise common.SchemaUpgradeError(
            "Prior schema-upgrade attempt requires manual reconciliation; no retry or startup."
        )


def observe_revision():
    """Explicit fixed-target READ ONLY observation, with physical closure."""
    e = common.engine()
    try:
        with e.connect() as c:
            common.identity(c)
            if c.exec_driver_sql("SHOW transaction_read_only").scalar_one() != "on":
                raise common.SchemaUpgradeError("Migration discovery must be READ ONLY.")
            markers = c.exec_driver_sql("SELECT version_num FROM public.alembic_version").scalars().all()
            if len(markers) != 1:
                raise common.SchemaUpgradeError("Expected exactly one database revision; no stamping or repair.")
            c.rollback()
        return markers[0]
    finally:
        e.dispose()


class LockedUnit:
    """Preserve existing exact 101/102 validators and freeze their dependencies."""

    def __init__(self, unit, source_lock):
        self.unit = unit
        self.source_lock = source_lock

    def __getattr__(self, name):
        return getattr(self.unit, name)

    def verify_sources(self):
        self.source_lock.verify()
        self.unit.verify_sources()


class MigrationUnit:
    """An individual future revision bound directly to owned Alembic Operations."""

    def __init__(self, revision, source_lock):
        self.revision = revision
        self.source_lock = source_lock
        self.PREVIOUS = revision.parent
        self.CURRENT = revision.revision
        self.CONFIRMATION = f"UPGRADE {common.stack.DB} {self.PREVIOUS.split('_')[0]} TO {self.CURRENT.split('_')[0]}"
        contract = revision.startup
        if not isinstance(contract, dict) or set(contract) != {"version", "tables", "advisory_key", "description"}:
            raise DiscoveryError("Migration needs a literal startup v1 contract and acceptance hooks: " + self.CURRENT)
        if type(contract["version"]) is not int or contract["version"] != 1:
            raise DiscoveryError("Unsupported startup contract version.")
        tables = contract["tables"]
        if not isinstance(tables, (tuple, list)) or not tables or len(tables) > 32:
            raise DiscoveryError("Startup contract needs 1..32 distinct locked tables.")
        if any(not isinstance(t, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", t) for t in tables):
            raise DiscoveryError("Unsafe startup table name.")
        if len(set(tables)) != len(tables):
            raise DiscoveryError("Duplicate startup locked table.")
        if type(contract["advisory_key"]) is not int or not 0 < contract["advisory_key"] < 2**63:
            raise DiscoveryError("Invalid advisory serialization key.")
        description = contract["description"]
        if not isinstance(description, str) or not 1 <= len(description) <= 400 or not description.isprintable():
            raise DiscoveryError("Invalid migration review description.")
        self.TABLES = tuple(tables)
        self.ADVISORY_KEY = contract["advisory_key"]
        self.description = description
        tree = ast.parse(revision.path.read_bytes())
        functions = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
        if not {"upgrade", "startup_preflight", "startup_validate"} <= functions:
            raise DiscoveryError("Migration requires upgrade, startup_preflight and startup_validate hooks.")
        # Importing a future revision must be inert. Runtime/application imports
        # belong inside its reviewed functions, not top-level initialization.
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.Assign, ast.AnnAssign)):
                if isinstance(node, ast.FunctionDef):
                    if node.decorator_list or node.args.defaults or any(x is not None for x in node.args.kw_defaults):
                        raise DiscoveryError("Startup migration functions cannot have import-time decorators/defaults.")
                else:
                    try:
                        ast.literal_eval(node.value)
                    except (ValueError, TypeError) as exc:
                        raise DiscoveryError("Startup migration top-level values must be literal.") from exc
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
                if any(n.split(".")[0] not in {"alembic", "sqlalchemy", "typing", "__future__"} for n in names):
                    raise DiscoveryError("Unreviewed import-time dependency in startup migration.")
            elif not (
                isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                raise DiscoveryError("Startup migration contains import-time executable statements.")

    def engine(self):
        return common.engine()

    def verify_sources(self):
        self.source_lock.verify()

    def module(self):
        self.verify_sources()
        raw = self.revision.path.read_bytes()
        import hashlib

        if hashlib.sha256(raw).hexdigest() != self.revision.sha256:
            raise DiscoveryError("Migration bytes changed before binding.")
        namespace = {"__name__": "_greenfield_startup_" + self.CURRENT, "__file__": str(self.revision.path)}
        exec(compile(raw, str(self.revision.path), "exec"), namespace)
        return SimpleNamespace(**namespace)

    def snapshot(self, c):
        return common.snapshot(c, omit_public_id_tables=())

    def inspect_current(self, e):
        with e.connect() as c:
            identity = common.identity(c)
            if c.exec_driver_sql("SHOW transaction_read_only").scalar_one() != "on":
                raise common.SchemaUpgradeError("Preflight/read-back must be READ ONLY.")
            markers = c.exec_driver_sql("SELECT version_num FROM public.alembic_version").scalars().all()
            if markers not in ([self.PREVIOUS], [self.CURRENT]):
                raise common.SchemaUpgradeError("Unexpected predecessor; no skipping or replay.")
            if markers == [self.CURRENT]:
                if self.module().startup_validate(c, None) is not True:
                    raise common.SchemaUpgradeError("Current schema acceptance hook failed.")
            c.rollback()
        return identity, markers[0]

    def before_upgrade(self, e):
        with e.connect() as c:
            common.review_security(c)
            if self.module().startup_preflight(c) is not True:
                raise common.SchemaUpgradeError("Migration-specific preflight failed.")
            result = self.snapshot(c)
            if any(
                [t, "r", "greenfield_owner"] not in [[r[0], r[1], r[4]] for r in result["catalog"]["relations"]]
                for t in self.TABLES
            ):
                raise common.SchemaUpgradeError("Missing/wrong-owner locked migration table.")
            c.rollback()
        return result

    def backup_and_rehearse(self, e, before, observed_identity):
        return common.backup_and_rehearse(
            e, before, observed_identity, predecessor=self.PREVIOUS, successor=self.CURRENT, snapshotter=self.snapshot
        )

    def apply_revision(self, c):
        from alembic.migration import MigrationContext
        from alembic.operations import Operations
        from sqlalchemy import text

        if not c.in_transaction() or c.connection.driver_connection.autocommit is not False:
            raise common.SchemaUpgradeError("Migration needs one owned non-autocommit PostgreSQL transaction.")
        if c.exec_driver_sql("SELECT version_num FROM public.alembic_version").scalars().all() != [self.PREVIOUS]:
            raise common.SchemaUpgradeError("Locked predecessor changed.")
        for sql in (
            "SET LOCAL statement_timeout='30s'",
            "SET LOCAL lock_timeout='250ms'",
            "SET LOCAL idle_in_transaction_session_timeout='5s'",
        ):
            c.exec_driver_sql(sql)
        with Operations.context(MigrationContext.configure(c)):
            self.module().upgrade()
        if not c.in_transaction():
            raise common.SchemaUpgradeError("Migration ended the caller-owned transaction; reconciliation required.")
        result = c.execute(
            text("UPDATE public.alembic_version SET version_num=:next WHERE version_num=:previous"),
            {"next": self.CURRENT, "previous": self.PREVIOUS},
        )
        if result.rowcount != 1:
            raise common.SchemaUpgradeError("Atomic migration marker transition failed.")

    def validate_after(self, c, before):
        if self.module().startup_validate(c, before) is not True:
            raise common.SchemaUpgradeError("Migration-specific schema/data acceptance failed.")
        if c.exec_driver_sql("SELECT version_num FROM public.alembic_version").scalars().all() != [self.CURRENT]:
            raise common.SchemaUpgradeError("Migration read-back marker mismatch.")

    def describe_upgrade(self, before):
        return (
            self.description
            + "\nSource snapshot SHA256: "
            + self.source_lock.sha256
            + "\nOne owned transaction; 30s/250ms/5s statement/lock/idle limits. "
            "Acceptance hooks must prove exact schema/security and intended data changes."
        )


def select_unit(revision, source_lock):
    if revision.revision == common.CURRENT:
        return LockedUnit(common, source_lock)
    from . import greenfield_resource_migrations

    if revision.revision == greenfield_resource_migrations.CURRENT:
        return LockedUnit(greenfield_resource_migrations, source_lock)
    return MigrationUnit(revision, source_lock)


def apply_fresh_tail(connection):
    """Use future migration bodies on an explicit NEW-install transaction only.

    The existing installer builds verified 100 then applies original 101/102.
    Future units run in that same owned fresh-install transaction; the installer
    retains COMMIT/read-back ownership. Ordinary start never calls this path.
    """
    graph = discover(common.stack.ROOT)
    lock = SourceLock.capture(common.stack.ROOT)
    markers = connection.exec_driver_sql("SELECT version_num FROM public.alembic_version").scalars().all()
    if markers != ["102_public_membership_grant_analysis_uuid"]:
        raise common.SchemaUpgradeError("Fresh-install tail requires verified 102 schema and marker.")
    for revision in graph.pending(markers[0]):
        unit = select_unit(revision, lock)
        lock.verify()
        if unit.module().startup_preflight(connection) is not True:
            raise common.SchemaUpgradeError("Fresh migration preconditions failed.")
        before = unit.snapshot(connection)
        connection.exec_driver_sql(f"SELECT pg_advisory_xact_lock({unit.ADVISORY_KEY})")
        connection.exec_driver_sql("LOCK TABLE public.alembic_version IN EXCLUSIVE MODE NOWAIT")
        for table in unit.TABLES:
            connection.exec_driver_sql(f"LOCK TABLE ONLY public.{table} IN ACCESS EXCLUSIVE MODE NOWAIT")
        unit.apply_revision(connection)
        unit.validate_after(connection, before)


def validate_current_tail(connection):
    """Independent fresh-install read-back for future migration acceptance."""
    graph = discover(common.stack.ROOT)
    lock = SourceLock.capture(common.stack.ROOT)
    for revision in graph.pending("102_public_membership_grant_analysis_uuid"):
        unit = select_unit(revision, lock)
        if unit.module().startup_validate(connection, None) is not True:
            raise common.SchemaUpgradeError("Fresh-install committed schema acceptance failed.")


def ensure_current(*, confirm=None):
    try:
        root = common.stack.ROOT
        graph = discover(root)
        lock = SourceLock.capture(root)
        _check_pending_claim()
        # Validate ALL prospective contracts before touching Docker/credentials.
        baseline_index = next(i for i, r in enumerate(graph.revisions) if r.revision == "100_greenfield_uuid_final")
        units = {r.revision: select_unit(r, lock) for r in graph.revisions[baseline_index + 1 :]}
        lock.verify()
        common.stack.verify_resources()
        current = observe_revision()
        pending = graph.pending(current)
        if not pending:
            if current not in units:
                raise common.SchemaUpgradeError("Baseline-only checkout has no final schema acceptance unit.")
            common._ensure_unit(units[current], confirm=confirm)
            return
        print(
            f"[REVIEW] Migration head {graph.head}; {len(pending)} pending revision(s). "
            "Each requires its own confirmation, verified backup and read-back.",
            flush=True,
        )
        for revision in pending:
            lock.verify()
            _check_pending_claim()
            common._ensure_unit(units[revision.revision], confirm=confirm)
            # A unit can also return if already current. Independently refuse
            # unexpected progress or a concurrent marker change before continuing.
            if observe_revision() != revision.revision:
                raise common.SchemaUpgradeError("Migration path changed after accepted unit; stop before continuation.")
    except DiscoveryError as exc:
        raise common.SchemaUpgradeError(str(exc)) from None
    except common.SchemaUpgradeError:
        raise
    except Exception as exc:
        # Discovery's initial read-only connection also needs the same safe
        # diagnostic boundary as the owned write/read-back lifecycle.
        raise common.SchemaUpgradeError(
            "Automatic migration preflight stopped; no retry or service startup. Error class: " + type(exc).__name__
        ) from None
