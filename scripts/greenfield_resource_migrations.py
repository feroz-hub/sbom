"""One explicitly confirmed Greenfield 101->102 unit; imports are inert.

The shared launcher owns backup, transaction, closure and independent read-back.
This module defines only this unit's exact predecessor, source and catalog delta.
"""

from __future__ import annotations

import hashlib

from . import greenfield_migrations as common

stack = common.stack
SchemaUpgradeError = common.SchemaUpgradeError
PREVIOUS = "101_iam_user_public_uuid"
CURRENT = "102_public_membership_grant_analysis_uuid"
CONFIRMATION = "UPGRADE sbom_greenfield_uuid 101 TO 102"
TABLES = ("tenant_users", "platform_user_roles", "analysis_run")
ADVISORY_KEY = 7160085102
engine = common.engine
PINS = {
    **common.PINS,
    "alembic/versions/102_public_membership_grant_analysis_uuid.py": "f8b049eebc7a7cccf07029fff26336936512024372bd729127233f5e46739d06",
    "app/resource_public_identity.py": "e61cbd5602d4459c9c8112ceb541598c503534ef6bf0b9908a641dfda897afb3",
    "app/resource_schema.py": "01250c61ac17cf4fd74fc85454279cabcd22f671af6880f9c2f52d7c7d395dbf",
}

# Exact PostgreSQL 16 deparser output for the separately pinned 101/102 CHECK.
UUID_CHECK = (
    "CHECK (((\"substring\"((public_id)::text, 15, 1) = '4'::text) AND "
    '("substring"((public_id)::text, 20, 1) = ANY '
    "(ARRAY['8'::text, '9'::text, 'a'::text, 'b'::text]))))"
)


def verify_sources():
    for name, expected in PINS.items():
        if hashlib.sha256((stack.ROOT / name).read_bytes()).hexdigest() != expected:
            raise SchemaUpgradeError("Reviewed Greenfield 102 migration source changed; independent review required.")


def snapshot(c):
    # Preserve the seven existing UUID identities, including IAM users, in the
    # before/backup/locked digests. Only the three NEW columns are omitted later.
    return common.snapshot(c, omit_public_id_tables=())


def _validate_identities(c, catalog, tables, function, source):
    for table in tables:
        columns = [r for r in catalog["columns"] if r[:2] == [table, "public_id"]]
        if len(columns) != 1 or columns[0][2:] != ["uuid", True, "gen_random_uuid()"]:
            raise SchemaUpgradeError("Native UUID/NOT NULL/default mismatch: " + table)
        relations = [r for r in catalog["relations"] if r[0] in (table, f"uq_{table}_public_id")]
        if len(relations) != 2 or any(r[4] != "greenfield_owner" for r in relations):
            raise SchemaUpgradeError("Unexpected UUID table/index owner: " + table)
        constraints = [r for r in catalog["constraints"] if r[0] == table and "public_id" in r[1]]
        if sorted(constraints) != sorted(
            [
                [table, f"uq_{table}_public_id", "UNIQUE (public_id)", True],
                [table, f"ck_{table}_public_id_v4", UUID_CHECK, True],
            ]
        ):
            raise SchemaUpgradeError("UUID constraint definition/validation mismatch: " + table)
        expected_triggers = [
            [
                table,
                f"trg_{table}_public_id_allocate",
                "O",
                f"CREATE TRIGGER trg_{table}_public_id_allocate BEFORE INSERT ON public.{table} "
                f"FOR EACH ROW EXECUTE FUNCTION {function}()",
            ],
            [
                table,
                f"trg_{table}_public_id_immutable",
                "O",
                f"CREATE TRIGGER trg_{table}_public_id_immutable AFTER UPDATE ON public.{table} "
                f"FOR EACH ROW WHEN ((old.public_id IS DISTINCT FROM new.public_id)) EXECUTE FUNCTION {function}()",
            ],
        ]
        triggers = [r for r in catalog["triggers"] if r[0] == table and "public_id" in r[1]]
        if sorted(triggers) != sorted(expected_triggers):
            raise SchemaUpgradeError("UUID trigger definition/enabled state mismatch: " + table)
        row = c.exec_driver_sql(
            f"SELECT count(*),count(DISTINCT public_id),count(*) FILTER(WHERE public_id IS NULL OR "
            "substring(public_id::text,15,1)<>'4' OR substring(public_id::text,20,1) NOT IN ('8','9','a','b')) "
            f"FROM public.{table}"
        ).one()
        if row[0] != row[1] or row[2]:
            raise SchemaUpgradeError("UUID allocation/uniqueness/version/variant mismatch: " + table)
    guard = c.exec_driver_sql(
        "SELECT pg_get_userbyid(proowner),prosecdef,provolatile,proconfig,prosrc,"
        "has_function_privilege('public',oid,'EXECUTE'),"
        "(SELECT count(*)=1 AND bool_and(grantee=proowner AND grantor=proowner "
        "AND privilege_type='EXECUTE' AND NOT is_grantable) FROM aclexplode(proacl)) FROM pg_proc "
        f"WHERE oid='public.{function}()'::regprocedure"
    ).one()
    if tuple(guard) != (
        "greenfield_owner",
        False,
        "v",
        ["search_path=pg_catalog"],
        source.split("$guard$")[1],
        False,
        True,
    ):
        raise SchemaUpgradeError("UUID guard owner/security/source mismatch.")


def _validate_user(c, catalog):
    from app.iam_public_identity import GUARD_SQL

    _validate_identities(c, catalog, ("iam_users",), "iam_user_public_identity_guard_v1", GUARD_SQL)


def inspect_current(e):
    with e.connect() as c:
        observed = common.identity(c)
        if c.exec_driver_sql("SHOW transaction_read_only").scalar_one() != "on":
            raise SchemaUpgradeError("Schema preflight must be READ ONLY.")
        markers = c.exec_driver_sql("SELECT version_num FROM public.alembic_version").scalars().all()
        if markers not in ([PREVIOUS], [CURRENT]):
            raise SchemaUpgradeError("Expected exactly revision 101 or 102; no skipping, stamping or chained upgrade.")
        if markers == [CURRENT]:
            from app.resource_public_identity import GUARD_SQL

            catalog = snapshot(c)["catalog"]
            _validate_user(c, catalog)
            _validate_identities(c, catalog, TABLES, "resource_public_identity_guard_v1", GUARD_SQL)
        c.rollback()
    return observed, markers[0]


def before_upgrade(e):
    with e.connect() as c:
        common.review_security(c)
        result = snapshot(c)
        catalog = result["catalog"]
        _validate_user(c, catalog)
        for table in TABLES:
            owners = [r[4] for r in catalog["relations"] if r[0] == table and r[1] == "r"]
            if owners != ["greenfield_owner"]:
                raise SchemaUpgradeError("Unexpected resource table owner/absence: " + table)
        if (
            any(r[0] in TABLES and r[1] == "public_id" for r in catalog["columns"])
            or any(r[0] in {f"uq_{table}_public_id" for table in TABLES} for r in catalog["relations"])
            or any(r[0] in TABLES and "public_id" in r[1] for r in catalog["triggers"] + catalog["constraints"])
            or any(r[0] == "resource_public_identity_guard_v1" for r in catalog["functions"])
        ):
            raise SchemaUpgradeError("Partial resource UUID upgrade; no automatic repair permitted.")
        c.rollback()
    return result


def backup_and_rehearse(e, before, observed_identity):
    return common.backup_and_rehearse(e, before, observed_identity, predecessor=PREVIOUS, snapshotter=snapshot)


def validate_after(c, before):
    after = common.snapshot(c, omit_public_id_tables=TABLES)
    if after["data"] != before["data"]:
        raise SchemaUpgradeError("Existing business/identity values changed outside the three new UUID columns.")
    indexes = {f"uq_{table}_public_id" for table in TABLES}
    additions = {
        "relations": (lambda r: r[0] in indexes, 3),
        "columns": (lambda r: r[0] in (*TABLES, *indexes) and r[1] == "public_id", 6),
        "constraints": (lambda r: r[0] in TABLES and r[1] in {f"uq_{r[0]}_public_id", f"ck_{r[0]}_public_id_v4"}, 6),
        "triggers": (
            lambda r: r[0] in TABLES and r[1] in {f"trg_{r[0]}_public_id_allocate", f"trg_{r[0]}_public_id_immutable"},
            6,
        ),
        "functions": (lambda r: r[0] == "resource_public_identity_guard_v1", 1),
    }
    if set(after["catalog"]) != set(before["catalog"]):
        raise SchemaUpgradeError("Unexpected catalog categories after resource UUID migration.")
    for key, rows in after["catalog"].items():
        predicate, count = additions.get(key, (lambda r: False, 0))
        original = [r for r in rows if not predicate(r)]
        if original != before["catalog"][key] or len(rows) - len(original) != count:
            raise SchemaUpgradeError("Unexpected post-upgrade catalog difference: " + key)
    from app.resource_public_identity import GUARD_SQL

    _validate_user(c, after["catalog"])
    _validate_identities(c, after["catalog"], TABLES, "resource_public_identity_guard_v1", GUARD_SQL)
    if c.exec_driver_sql("SELECT version_num FROM public.alembic_version").scalars().all() != [CURRENT]:
        raise SchemaUpgradeError("Resource UUID revision verification failed.")


def apply_revision(c):
    from app.resource_schema import apply_resource_uuid_revision

    apply_resource_uuid_revision(c)


def describe_upgrade(before):
    counts = ", ".join(f"{table}={before['data'][table][0]}" for table in TABLES)
    return (
        "Membership/Grant/Run UUID allocation: " + counts + ".\n"
        "Existing integer keys, IAM UUIDs, credentials, roles and history are retained.\n"
        "One 101->102 transaction only; statement/lock/idle timeouts: 30s/250ms/5s.\n"
        "Review docs/uat/public-resource-uuid/STARTUP_MIGRATION_102.md."
    )
