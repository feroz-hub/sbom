"""Catalogue-only revision 103 acceptance; never connects to an application database.

SQLite executes the real seed and metadata reads. PostgreSQL-wide catalogue/data
snapshots are explicit boundary fixtures; real PostgreSQL is covered separately.
"""

import importlib.util
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import sqlalchemy as sa
from scripts import greenfield_migrations as common

STAMP = datetime(2024, 1, 1, tzinfo=UTC)
PERMISSION = "platform:tenant_admin:manage"


def catalogue_tables(metadata):
    # Frozen columns of the three affected tables, including nullable actor
    # metadata. No IAM/model imports or schema bootstrap can reach a real DB.
    roles = sa.Table(
        "authorization_roles",
        metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("code", sa.String(64), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("is_system", sa.Boolean, nullable=False),
        sa.Column("is_assignable", sa.Boolean, nullable=False),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("created_by_user_id", sa.Integer),
        sa.Column("updated_by_user_id", sa.Integer),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    permissions = sa.Table(
        "authorization_permissions",
        metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("code", sa.String(128), nullable=False, unique=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("resource", sa.String(128), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("is_system", sa.Boolean, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    mappings = sa.Table(
        "authorization_role_permissions",
        metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("role_id", sa.Integer, nullable=False),
        sa.Column("permission_id", sa.Integer, nullable=False),
        sa.Column("is_protected", sa.Boolean, nullable=False),
        sa.Column("created_by_user_id", sa.Integer),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("role_id", "permission_id"),
    )
    return roles, permissions, mappings


@pytest.fixture
def catalogue(monkeypatch):
    path = Path(__file__).resolve().parents[1] / "alembic/versions/103_tenant_admin_governance.py"
    spec = importlib.util.spec_from_file_location("governance_startup_under_test", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    # Only PostgreSQL schema inspection is replaced; seed, catalogue reads,
    # prerequisite checks and exact data-delta validation stay real.
    if hasattr(migration, "_validate_schema"):
        monkeypatch.setattr(migration, "_validate_schema", Mock())
    engine = sa.create_engine("sqlite:///:memory:")

    @sa.event.listens_for(engine, "connect")
    def serial_sequence(dbapi_connection, record):
        dbapi_connection.create_function("pg_get_serial_sequence", 2, lambda table, column: table + "_id_seq")

    metadata = sa.MetaData()
    roles, permissions, mappings = catalogue_tables(metadata)
    metadata.create_all(engine)
    with engine.connect() as connection:
        for role_id, code, scope in ((10, "PLATFORM_ADMIN", "PLATFORM"), (20, "VIEWER", "TENANT")):
            connection.execute(
                roles.insert().values(
                    id=role_id,
                    code=code,
                    name=code,
                    scope=scope,
                    status="ACTIVE",
                    is_system=True,
                    is_assignable=True,
                    version=7,
                    created_at=STAMP,
                    updated_at=STAMP,
                )
            )
        connection.execute(
            permissions.insert().values(
                id=100,
                code="tenant:user:read",
                name="Read Users",
                scope="TENANT",
                resource="tenant:user",
                action="read",
                status="ACTIVE",
                is_system=True,
                created_at=STAMP,
                updated_at=STAMP,
            )
        )
        connection.execute(
            mappings.insert().values(
                id=1000,
                role_id=20,
                permission_id=100,
                is_protected=False,
                created_at=STAMP,
                updated_at=STAMP,
            )
        )
        subject = SimpleNamespace(
            migration=migration, connection=connection, roles=roles, permissions=permissions, mappings=mappings
        )
        monkeypatch.setattr(common, "snapshot", lambda c, **kwargs: whole_snapshot(subject))
        yield subject
        connection.rollback()
    engine.dispose()


def add_governance(catalogue, *, mapping=True, protected=True, role_id=10):
    catalogue.connection.execute(
        catalogue.permissions.insert().values(
            id=200,
            code=PERMISSION,
            name="Manage Tenant Administrators",
            scope="PLATFORM",
            resource="platform:tenant_admin",
            action="manage",
            status="ACTIVE",
            is_system=True,
            created_at=STAMP,
            updated_at=STAMP,
        )
    )
    if mapping:
        catalogue.connection.execute(
            catalogue.mappings.insert().values(
                id=2000,
                role_id=role_id,
                permission_id=200,
                is_protected=protected,
                created_at=STAMP,
                updated_at=STAMP,
            )
        )


def whole_snapshot(catalogue):
    relations = [[name, "r", "p", False, "greenfield_owner", None] for name in catalogue.migration.startup["tables"]]
    return {
        "catalog": {
            "relations": relations,
            "columns": [["tenant_users", "public_id", "uuid", True, "gen_random_uuid()"]],
            "constraints": [["tenant_users", "uuid_guard", "CHECK synthetic", True]],
            "triggers": [["tenant_users", "immutable", "O", "synthetic guard"]],
            "functions": [["guard", "greenfield_owner", None, "synthetic function"]],
            "schema": [["public", "greenfield_owner", "synthetic ACL"]],
            "roles": [["greenfield_app", True, False]],
            "default_acls": [["synthetic ACL"]],
            "database": [["greenfield_setup", None]],
            "database_settings": [],
            "sequences": [
                ["authorization_permissions_id_seq", 1, 1, 2**31 - 1, 1, False, 1, 100],
                ["authorization_role_permissions_id_seq", 1, 1, 2**31 - 1, 1, False, 1, 1000],
                ["tenant_users_id_seq", 1, 1, 2**31 - 1, 1, False, 1, 45],
            ],
        },
        "data": {
            name: [3, "original-" + name]
            for name in (
                *catalogue.migration.startup["tables"],
                "iam_users",
                "platform_user_roles",
                "tenant_users",
                "tenant_user_role_assignments",
                "tenant_user_role_assignment_history",
                "authorization_audit_logs",
                "sboms",
            )
        },
        "migration": catalogue.migration.startup_snapshot(catalogue.connection),
    }


def seeded_transition(catalogue, monkeypatch):
    before = whole_snapshot(catalogue)
    catalogue.migration._seed(catalogue.connection)
    after = deepcopy(before)
    after.pop("migration")
    current = catalogue.migration.startup_snapshot(catalogue.connection)
    old_permissions = {row["id"] for row in before["migration"]["authorization_permissions"]}
    old_mappings = {row["id"] for row in before["migration"]["authorization_role_permissions"]}
    for table, old_ids in (
        ("authorization_permissions", old_permissions),
        ("authorization_role_permissions", old_mappings),
    ):
        additions = [row for row in current[table] if row["id"] not in old_ids]
        if additions:
            next(row for row in after["catalog"]["sequences"] if row[0] == table + "_id_seq")[-1] = additions[0]["id"]
    snapshot = Mock(return_value=after)
    monkeypatch.setattr(common, "snapshot", snapshot)
    return before, after, snapshot


@pytest.mark.parametrize("state", ["absent", "permission_only", "unprotected", "protected"])
def test_seed_acceptance_preserves_unrelated_catalogue_and_is_idempotent(catalogue, monkeypatch, state):
    if state != "absent":
        add_governance(catalogue, mapping=state != "permission_only", protected=state != "unprotected")
    original = catalogue.migration.startup_snapshot(catalogue.connection)
    assert catalogue.migration.startup_preflight(catalogue.connection) is True
    before, after, snapshot = seeded_transition(catalogue, monkeypatch)
    assert catalogue.migration.startup_validate(catalogue.connection, before) is True
    current = catalogue.migration.startup_snapshot(catalogue.connection)
    # Explicit business outcomes independently check the exact-delta validator.
    assert current["authorization_roles"][1] == original["authorization_roles"][1]
    assert current["authorization_permissions"][0] == original["authorization_permissions"][0]
    assert current["authorization_role_permissions"][0] == original["authorization_role_permissions"][0]
    assert current["authorization_roles"][0]["version"] == (8 if state in {"absent", "permission_only"} else 7)
    governance = [row for row in current["authorization_permissions"] if row["code"] == PERMISSION]
    grants = [row for row in current["authorization_role_permissions"] if row["permission_id"] == governance[0]["id"]]
    assert len(governance) == len(grants) == 1
    assert grants[0]["role_id"] == 10 and grants[0]["is_protected"] is True
    catalogue.migration._seed(catalogue.connection)
    assert catalogue.migration.startup_snapshot(catalogue.connection) == current
    assert catalogue.migration.startup_validate(catalogue.connection, None) is True


def test_snapshot_is_only_catalogue_metadata_and_hooks_do_not_write(catalogue, monkeypatch):
    add_governance(catalogue)
    observed = []
    sa.event.listen(
        catalogue.connection, "before_cursor_execute", lambda c, cursor, sql, params, ctx, many: observed.append(sql)
    )
    original = catalogue.migration.startup_snapshot(catalogue.connection)
    assert set(original) == set(catalogue.migration.startup["tables"])
    assert catalogue.migration.startup_preflight(catalogue.connection) is True
    monkeypatch.setattr(catalogue.migration, "_seed", Mock(side_effect=AssertionError("acceptance must not replay")))
    assert catalogue.migration.startup_validate(catalogue.connection, None) is True
    assert catalogue.migration.startup_snapshot(catalogue.connection) == original
    assert all(sql.lstrip().upper().startswith(("SELECT", "PRAGMA")) for sql in observed)


@pytest.mark.parametrize(
    "field,value",
    [
        ("scope", "TENANT"),
        ("resource", "platform:user"),
        ("action", "delete"),
        ("status", "DISABLED"),
        ("is_system", False),
    ],
)
def test_incompatible_permission_rejected_without_mutation(catalogue, field, value):
    add_governance(catalogue)
    catalogue.connection.execute(
        catalogue.permissions.update().where(catalogue.permissions.c.id == 200).values({field: value})
    )
    original = catalogue.migration.startup_snapshot(catalogue.connection)
    with pytest.raises(RuntimeError, match="Incompatible governance permission"):
        catalogue.migration.startup_preflight(catalogue.connection)
    with pytest.raises(RuntimeError, match="Incompatible governance permission"):
        catalogue.migration.startup_validate(catalogue.connection, None)
    assert catalogue.migration.startup_snapshot(catalogue.connection) == original


@pytest.mark.parametrize("field,value", [("status", "DISABLED"), ("is_system", False), ("version", 0)])
def test_invalid_platform_role_rejected(catalogue, field, value):
    catalogue.connection.execute(catalogue.roles.update().where(catalogue.roles.c.id == 10).values({field: value}))
    with pytest.raises(RuntimeError, match="active system Platform Admin"):
        catalogue.migration.startup_preflight(catalogue.connection)


def test_unexpected_role_mapping_rejected_by_preflight_and_seed(catalogue):
    add_governance(catalogue, role_id=20)
    original = catalogue.migration.startup_snapshot(catalogue.connection)
    with pytest.raises(RuntimeError, match="unexpected role mapping"):
        catalogue.migration.startup_preflight(catalogue.connection)
    with pytest.raises(RuntimeError, match="unexpected role mapping"):
        catalogue.migration._seed(catalogue.connection)
    assert catalogue.migration.startup_snapshot(catalogue.connection) == original


@pytest.mark.parametrize("state", ["absent", "permission_only", "unprotected"])
def test_current_validation_requires_protected_mapping(catalogue, state):
    if state != "absent":
        add_governance(catalogue, mapping=state != "permission_only", protected=False)
    with pytest.raises(RuntimeError, match="Missing protected"):
        catalogue.migration.startup_validate(catalogue.connection, None)


@pytest.mark.parametrize(
    "table_name,row_id,field,value",
    [
        ("roles", 20, "name", "Changed ordinary role"),
        ("permissions", 100, "action", "write"),
        ("mappings", 1000, "is_protected", True),
        ("roles", 10, "version", 99),
        ("roles", 10, "updated_at", STAMP),
        ("permissions", 101, "name", "Overbroad management"),
        ("permissions", 101, "updated_at", STAMP),
        ("mappings", 1001, "created_by_user_id", 999),
        ("mappings", 1001, "updated_at", STAMP),
    ],
)
def test_acceptance_rejects_catalogue_tampering(catalogue, monkeypatch, table_name, row_id, field, value):
    before, after, snapshot = seeded_transition(catalogue, monkeypatch)
    table = getattr(catalogue, table_name)
    catalogue.connection.execute(table.update().where(table.c.id == row_id).values({field: value}))
    with pytest.raises(RuntimeError, match="Unapproved authorization catalogue"):
        catalogue.migration.startup_validate(catalogue.connection, before)


@pytest.mark.parametrize(
    "table",
    [
        "iam_users",
        "platform_user_roles",
        "tenant_users",
        "tenant_user_role_assignments",
        "tenant_user_role_assignment_history",
        "authorization_audit_logs",
        "sboms",
    ],
)
def test_acceptance_rejects_unrelated_identity_history_or_business_changes(catalogue, monkeypatch, table):
    before, after, snapshot = seeded_transition(catalogue, monkeypatch)
    after["data"][table][1] = "changed-digest"
    with pytest.raises(RuntimeError, match="identity, assignment, history or business"):
        catalogue.migration.startup_validate(catalogue.connection, before)


@pytest.mark.parametrize(
    "category",
    [
        "relations",
        "columns",
        "constraints",
        "triggers",
        "functions",
        "schema",
        "roles",
        "default_acls",
        "database",
        "database_settings",
    ],
)
def test_acceptance_rejects_schema_and_security_drift(catalogue, monkeypatch, category):
    before, after, snapshot = seeded_transition(catalogue, monkeypatch)
    after["catalog"][category].append(["unexpected change"])
    with pytest.raises(RuntimeError, match="Unapproved schema/security"):
        catalogue.migration.startup_validate(catalogue.connection, before)


@pytest.mark.parametrize("kind", ["add_category", "remove_category", "add_table", "remove_table"])
def test_acceptance_rejects_inventory_changes(catalogue, monkeypatch, kind):
    before, after, snapshot = seeded_transition(catalogue, monkeypatch)
    if kind == "add_category":
        after["catalog"]["unreviewed"] = []
    elif kind == "remove_category":
        del after["catalog"]["roles"]
    elif kind == "add_table":
        after["data"]["new_table"] = [0, "new"]
    else:
        del after["data"]["iam_users"]
    with pytest.raises(RuntimeError):
        catalogue.migration.startup_validate(catalogue.connection, before)


@pytest.mark.parametrize(
    "sequence,column",
    [
        ("authorization_permissions_id_seq", -1),
        ("authorization_role_permissions_id_seq", -1),
        ("tenant_users_id_seq", -1),
        ("authorization_permissions_id_seq", 4),
    ],
)
def test_acceptance_requires_exact_sequence_delta(catalogue, monkeypatch, sequence, column):
    before, after, snapshot = seeded_transition(catalogue, monkeypatch)
    row = next(row for row in after["catalog"]["sequences"] if row[0] == sequence)
    row[column] += 1
    with pytest.raises(RuntimeError, match="Unapproved schema/security change: sequences"):
        catalogue.migration.startup_validate(catalogue.connection, before)


def test_rollback_restores_seeded_catalogue_on_failed_acceptance(catalogue, monkeypatch):
    original = catalogue.migration.startup_snapshot(catalogue.connection)
    with catalogue.connection.begin_nested() as transaction:
        before, after, snapshot = seeded_transition(catalogue, monkeypatch)
        after["data"]["iam_users"][1] = "changed"
        with pytest.raises(RuntimeError):
            catalogue.migration.startup_validate(catalogue.connection, before)
        transaction.rollback()
    assert catalogue.migration.startup_snapshot(catalogue.connection) == original
