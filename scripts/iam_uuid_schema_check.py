"""Read-only complete metadata and IAM-guard parity on the task's browser DB."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def verify():
    from sqlalchemy import CheckConstraint, UniqueConstraint, create_engine, inspect
    from sqlalchemy.engine import make_url

    from scripts.greenfield_uuid import url
    from scripts.iam_uuid_browser_environment import DATABASE, OWNER, ROLE, environment

    env = environment()
    os.environ.update(env)
    from app.greenfield_schema import application_metadata
    from app.public_identity import TABLES

    metadata = application_metadata()
    engine = create_engine(
        make_url(url("greenfield_setup", "setup-password", "postgres")).set(database=DATABASE), hide_parameters=True
    )
    counts = {"tables": 0, "columns": 0, "foreign_keys": 0, "indexes": 0, "checks": 0, "unique_constraints": 0}
    try:
        with engine.connect() as c:
            c.exec_driver_sql("SET TRANSACTION READ ONLY")
            catalog = inspect(c)
            assert c.exec_driver_sql("SELECT current_database()").scalar_one() == DATABASE
            assert c.exec_driver_sql("SELECT version_num FROM alembic_version").scalars().all() == [
                "101_iam_user_public_uuid"
            ]
            assert set(catalog.get_table_names()) == set(metadata.tables) | {"alembic_version"}
            for table in metadata.tables.values():
                actual = {x["name"]: x for x in catalog.get_columns(table.name)}
                assert set(actual) == set(table.columns.keys()), (table.name, "columns")
                for column in table.columns:
                    observed = actual[column.name]
                    expected = column.type.dialect_impl(c.dialect)
                    assert observed["nullable"] == column.nullable, (table.name, column.name, "nullable")
                    assert observed["type"]._type_affinity is expected._type_affinity, (table.name, column.name, "type")
                assert catalog.get_pk_constraint(table.name)["constrained_columns"] == list(
                    table.primary_key.columns.keys()
                )
                expected_fk = {
                    (
                        tuple(x.parent.name for x in fk.elements),
                        fk.referred_table.name,
                        tuple(x.column.name for x in fk.elements),
                        fk.ondelete,
                    )
                    for fk in table.foreign_key_constraints
                }
                actual_fk = {
                    (
                        tuple(fk["constrained_columns"]),
                        fk["referred_table"],
                        tuple(fk["referred_columns"]),
                        fk["options"].get("ondelete"),
                    )
                    for fk in catalog.get_foreign_keys(table.name)
                }
                assert actual_fk == expected_fk, (table.name, "foreign keys")
                indexes = {x["name"] for x in catalog.get_indexes(table.name) if not x.get("duplicates_constraint")}
                expected_indexes = {
                    c.dialect.identifier_preparer.truncate_and_render_index_name(x.name, _alembic_quote=False)
                    for x in table.indexes
                    if not x._ddl_if or x._ddl_if.dialect == "postgresql"
                }
                assert indexes == expected_indexes, (table.name, "indexes", indexes ^ expected_indexes)
                checks = {x["name"] for x in catalog.get_check_constraints(table.name)}
                expected_checks = {
                    c.dialect.identifier_preparer.truncate_and_render_constraint_name(x.name, _alembic_quote=False)
                    for x in table.constraints
                    if isinstance(x, CheckConstraint)
                }
                if table.name in (*TABLES, "iam_users"):
                    expected_checks.add("ck_" + table.name + "_public_id_v4")
                assert checks == expected_checks, (table.name, "checks")
                uniques = {tuple(x["column_names"]) for x in catalog.get_unique_constraints(table.name)}
                assert uniques == {
                    tuple(x.columns.keys()) for x in table.constraints if isinstance(x, UniqueConstraint)
                }, (table.name, "uniques")
                counts["tables"] += 1
                counts["columns"] += len(actual)
                counts["foreign_keys"] += len(actual_fk)
                counts["indexes"] += len(indexes)
                counts["checks"] += len(checks)
                counts["unique_constraints"] += len(uniques)
            guard = c.exec_driver_sql(
                "SELECT p.prosecdef,p.provolatile,p.proconfig,r.rolname,has_function_privilege('public','public.iam_user_public_identity_guard_v1()','EXECUTE') FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.oid='public.iam_user_public_identity_guard_v1()'::regprocedure"
            ).one()
            assert tuple(guard) == (False, "v", ["search_path=pg_catalog"], OWNER, False)
            assert (
                c.exec_driver_sql(
                    "SELECT count(*) FROM pg_trigger WHERE tgrelid='iam_users'::regclass AND NOT tgisinternal AND tgenabled='O'"
                ).scalar_one()
                == 2
            )
            assert c.exec_driver_sql(
                "SELECT bool_and(convalidated) FROM pg_constraint WHERE conrelid='iam_users'::regclass AND contype='c'"
            ).scalar_one()
            assert (
                c.exec_driver_sql(
                    "SELECT count(*) FROM iam_users WHERE public_id IS NULL OR substring(public_id::text,15,1)<>'4' OR substring(public_id::text,20,1) NOT IN ('8','9','a','b')"
                ).scalar_one()
                == 0
            )
            assert c.exec_driver_sql("SELECT count(DISTINCT public_id)=count(*) FROM iam_users").scalar_one()
            c.rollback()
    finally:
        engine.dispose()
    runtime = create_engine(env["DATABASE_URL"], hide_parameters=True)
    try:
        with runtime.connect() as c:
            c.exec_driver_sql("SET TRANSACTION READ ONLY")
            assert c.exec_driver_sql("SELECT current_user").scalar_one() == ROLE
            privileges = c.exec_driver_sql(
                "SELECT rolsuper,rolcreatedb,rolcreaterole,rolbypassrls,rolreplication,rolinherit,rolcanlogin FROM pg_roles WHERE rolname=current_user"
            ).one()
            assert tuple(privileges) == (False, False, False, False, False, False, True)
            assert not c.exec_driver_sql("SELECT has_schema_privilege(current_user,'public','CREATE')").scalar_one()
            assert not c.exec_driver_sql(
                "SELECT has_table_privilege(current_user,'alembic_version','UPDATE')"
            ).scalar_one()
            c.rollback()
    finally:
        runtime.dispose()
    return {
        "result": "PASS",
        "database": DATABASE,
        "revision": "101_iam_user_public_uuid",
        "counts": counts,
        "iam_guard_and_runtime_privileges": "PASS",
        "read_only": True,
    }


if __name__ == "__main__":
    result = verify()
    print(json.dumps(result, indent=2))
