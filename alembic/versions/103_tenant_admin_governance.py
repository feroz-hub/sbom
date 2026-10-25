"""Add restricted Tenant Administrator governance permission.

Revision ID: 103_tenant_admin_governance
Revises: 102_public_membership_grant_analysis_uuid
"""

import sqlalchemy as sa
from alembic import op

revision = "103_tenant_admin_governance"
down_revision = "102_public_membership_grant_analysis_uuid"
branch_labels = None
depends_on = None

startup = {
    "version": 1,
    "tables": (
        "authorization_roles",
        "authorization_permissions",
        "authorization_role_permissions",
    ),
    "advisory_key": 7160085103,
    "description": "Add only protected Platform Admin tenant-administrator governance authority; preserve identities, tenant assignments, business data and schema/security metadata.",
}

# Frozen for deterministic replay; do not import the live catalogue.
PERMISSION = "platform:tenant_admin:manage"


def _seed(bind):
    from datetime import UTC, datetime

    metadata = sa.MetaData()
    roles = sa.Table("authorization_roles", metadata, autoload_with=bind)
    permissions = sa.Table("authorization_permissions", metadata, autoload_with=bind)
    mappings = sa.Table("authorization_role_permissions", metadata, autoload_with=bind)
    role_id = bind.execute(
        sa.select(roles.c.id).where(
            roles.c.code == "PLATFORM_ADMIN",
            roles.c.scope == "PLATFORM",
        )
    ).scalar_one()
    now = datetime.now(UTC)
    permission_id = bind.scalar(sa.select(permissions.c.id).where(permissions.c.code == PERMISSION))
    if permission_id is None:
        permission_id = bind.execute(
            permissions.insert()
            .values(
                code=PERMISSION,
                name="Manage Tenant Administrators",
                scope="PLATFORM",
                resource="platform:tenant_admin",
                action="manage",
                status="ACTIVE",
                is_system=True,
                created_at=now,
                updated_at=now,
            )
            .returning(permissions.c.id)
        ).scalar_one()
    else:
        # Refuse a pre-existing incompatible definition rather than broadening it.
        scope = bind.scalar(sa.select(permissions.c.scope).where(permissions.c.id == permission_id))
        if scope != "PLATFORM":
            raise RuntimeError("Tenant admin governance permission must be platform scoped")
    unexpected = bind.scalar(
        sa.select(mappings.c.id).where(
            mappings.c.permission_id == permission_id,
            mappings.c.role_id != role_id,
        )
    )
    if unexpected is not None:
        raise RuntimeError("Tenant admin governance permission has an unexpected role mapping")
    mapping_id = bind.scalar(
        sa.select(mappings.c.id).where(
            mappings.c.role_id == role_id,
            mappings.c.permission_id == permission_id,
        )
    )
    if mapping_id is None:
        bind.execute(
            mappings.insert().values(
                role_id=role_id,
                permission_id=permission_id,
                is_protected=True,
                created_at=now,
                updated_at=now,
            )
        )
        bind.execute(
            roles.update()
            .where(roles.c.id == role_id)
            .values(
                version=roles.c.version + 1,
                updated_at=now,
            )
        )
    else:
        bind.execute(mappings.update().where(mappings.c.id == mapping_id).values(is_protected=True))


def startup_snapshot(connection):
    """Original authorization catalogue metadata only; no identity/credential rows."""
    metadata = sa.MetaData()
    result = {}
    for name in startup["tables"]:
        table = sa.Table(name, metadata, autoload_with=connection)
        result[name] = [dict(row) for row in connection.execute(sa.select(table).order_by(table.c.id)).mappings()]
    return result


def _governance_state(catalogue):
    roles = [r for r in catalogue["authorization_roles"] if r["code"] == "PLATFORM_ADMIN" and r["scope"] == "PLATFORM"]
    if len(roles) != 1 or roles[0]["status"] != "ACTIVE" or not roles[0]["is_system"] or roles[0]["version"] < 1:
        raise RuntimeError("Expected one active system Platform Admin catalogue role")
    permissions = [p for p in catalogue["authorization_permissions"] if p["code"] == PERMISSION]
    if len(permissions) > 1:
        raise RuntimeError("Duplicate governance permission")
    permission = permissions[0] if permissions else None
    mappings = []
    if permission is not None:
        if any(
            permission[key] != value
            for key, value in {
                "scope": "PLATFORM",
                "resource": "platform:tenant_admin",
                "action": "manage",
                "status": "ACTIVE",
                "is_system": True,
            }.items()
        ):
            raise RuntimeError("Incompatible governance permission definition")
        mappings = [m for m in catalogue["authorization_role_permissions"] if m["permission_id"] == permission["id"]]
        if len(mappings) > 1 or any(m["role_id"] != roles[0]["id"] for m in mappings):
            raise RuntimeError("Governance permission has an unexpected role mapping")
    return roles[0], permission, mappings[0] if mappings else None


def startup_preflight(connection):
    # Caller verifies fixed database identity, predecessor, table ownership and
    # runtime privileges. These checks run without writes, before confirmation.
    from scripts import greenfield_migrations as common

    _validate_schema(connection, common.snapshot(connection, omit_public_id_tables=())["catalog"])
    _governance_state(startup_snapshot(connection))
    return True


def _validate_schema(connection, catalog):
    # A current 103 marker must not bypass the prior UUID/security acceptance.
    from app.resource_public_identity import GUARD_SQL
    from scripts import greenfield_resource_migrations as resources

    resources._validate_user(connection, catalog)
    resources._validate_identities(
        connection, catalog, resources.TABLES, "resource_public_identity_guard_v1", GUARD_SQL
    )
    for table in startup["tables"]:
        owners = [r[4] for r in catalog["relations"] if r[0] == table and r[1] == "r"]
        if owners != ["greenfield_owner"]:
            raise RuntimeError("Missing/wrong-owner governance catalogue table")


def _validate_catalogue_delta(original, current):
    from copy import deepcopy

    old_role, old_permission, old_mapping = _governance_state(original)
    role, permission, mapping = _governance_state(current)
    expected = deepcopy(original)
    if old_permission is None:
        added = {
            "id": permission["id"],
            "code": PERMISSION,
            "name": "Manage Tenant Administrators",
            "description": None,
            "scope": "PLATFORM",
            "resource": "platform:tenant_admin",
            "action": "manage",
            "status": "ACTIVE",
            "is_system": True,
            "created_at": mapping["created_at"],
            "updated_at": mapping["created_at"],
        }
        expected["authorization_permissions"].append(added)
    if old_mapping is None:
        added = {
            "id": mapping["id"],
            "role_id": old_role["id"],
            "permission_id": permission["id"],
            "is_protected": True,
            "created_by_user_id": None,
            "created_at": mapping["created_at"],
            "updated_at": mapping["created_at"],
        }
        if added["created_at"] is None:
            raise RuntimeError("Missing governance catalogue timestamp")
        expected["authorization_role_permissions"].append(added)
        for row in expected["authorization_roles"]:
            if row["id"] == old_role["id"]:
                row.update(version=old_role["version"] + 1, updated_at=added["created_at"])
    else:
        for row in expected["authorization_role_permissions"]:
            if row["id"] == old_mapping["id"]:
                row["is_protected"] = True
    for rows in expected.values():
        rows.sort(key=lambda row: row["id"])
    if expected != current:
        raise RuntimeError("Unapproved authorization catalogue data change")
    return old_permission is None, old_mapping is None


def startup_validate(connection, before):
    from scripts import greenfield_migrations as common

    after = common.snapshot(connection, omit_public_id_tables=())
    _validate_schema(connection, after["catalog"])
    current = startup_snapshot(connection)
    role, permission, mapping = _governance_state(current)
    if permission is None or mapping is None or mapping["is_protected"] is not True:
        raise RuntimeError("Missing protected Platform Admin governance permission")
    if before is None:
        return True  # Already-current READ ONLY acceptance; never replay _seed.
    inserted_permission, inserted_mapping = _validate_catalogue_delta(before["migration"], current)
    unchanged = set(before["data"]) - set(startup["tables"])
    if set(after["data"]) != set(before["data"]) or any(after["data"][t] != before["data"][t] for t in unchanged):
        raise RuntimeError("Existing identity, assignment, history or business data changed")
    if set(after["catalog"]) != set(before["catalog"]):
        raise RuntimeError("Unexpected schema/security categories")
    # Only inserts may advance the two catalogue sequences. All sequence
    # definitions and all other schema/security evidence remain exact.
    allowed_sequences = {}
    for table, inserted, row in (
        ("authorization_permissions", inserted_permission, permission),
        ("authorization_role_permissions", inserted_mapping, mapping),
    ):
        if inserted:
            name = connection.execute(
                sa.text("SELECT pg_get_serial_sequence(:table, 'id')"), {"table": "public." + table}
            ).scalar_one()
            if name is None:
                raise RuntimeError("Missing governance catalogue identity sequence")
            allowed_sequences[name.removeprefix("public.")] = row["id"]
    expected_sequences = []
    for row in before["catalog"]["sequences"]:
        expected_sequences.append(row[:-1] + [allowed_sequences[row[0]]] if row[0] in allowed_sequences else row)
    for key in before["catalog"]:
        expected = expected_sequences if key == "sequences" else before["catalog"][key]
        if after["catalog"][key] != expected:
            raise RuntimeError("Unapproved schema/security change: " + key)
    return True


def upgrade():
    _seed(op.get_bind())


def downgrade():
    raise RuntimeError("Removing protected governance authority requires an operator-reviewed rollback")
