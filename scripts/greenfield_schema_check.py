"""Compare the real task-owned PostgreSQL schema with complete current metadata."""

from __future__ import annotations

import json
import os

from sqlalchemy import create_engine, inspect, text

from scripts.greenfield_uuid import REVISION, STATE, settings, url


def verify(database="sbom_greenfield_uuid"):
    if database not in {"sbom_greenfield_uuid", "sbom_greenfield_uuid_repro_test"}:
        raise RuntimeError("Only task-owned application/repro targets")
    os.environ.update(settings())
    os.chdir(STATE)
    from app.greenfield_schema import application_metadata

    metadata = application_metadata()
    from app.public_identity import TABLES

    engine = create_engine(url("greenfield_setup", "setup-password", database), hide_parameters=True)
    counts = {"tables": 0, "columns": 0, "foreign_keys": 0, "indexes": 0, "checks": 0, "unique_constraints": 0}
    with engine.connect() as conn:
        catalog = inspect(conn)
        assert set(catalog.get_table_names()) == set(metadata.tables) | {"alembic_version"}
        assert conn.exec_driver_sql("SELECT version_num FROM alembic_version").scalars().all() == [REVISION]
        for table in metadata.tables.values():
            cols = {x["name"]: x for x in catalog.get_columns(table.name)}
            assert set(cols) == set(table.columns.keys()), table.name
            for column in table.columns:
                actual = cols[column.name]
                assert actual["nullable"] == column.nullable, (table.name, column.name, "nullable")
                expected_type = column.type.dialect_impl(conn.dialect)
                assert actual["type"]._type_affinity is expected_type._type_affinity, (table.name, column.name, "type")
                for attr in ("length", "timezone", "scale"):
                    assert getattr(actual["type"], attr, None) == getattr(expected_type, attr, None), (
                        table.name,
                        column.name,
                        attr,
                    )
            assert catalog.get_pk_constraint(table.name)["constrained_columns"] == list(
                table.primary_key.columns.keys()
            )

            def fk(columns, table, refs, delete):
                return (tuple(columns), table, tuple(refs), delete or None)

            expected = {
                fk(
                    [x.parent.name for x in c.elements],
                    c.referred_table.name,
                    [x.column.name for x in c.elements],
                    c.ondelete,
                )
                for c in table.foreign_key_constraints
            }
            actual = {
                fk(x["constrained_columns"], x["referred_table"], x["referred_columns"], x["options"].get("ondelete"))
                for x in catalog.get_foreign_keys(table.name)
            }
            assert actual == expected, (table.name, "FK parity")
            indexes = {x["name"] for x in catalog.get_indexes(table.name) if not x.get("duplicates_constraint")}
            expected_indexes = {
                conn.dialect.identifier_preparer.truncate_and_render_index_name(x.name, _alembic_quote=False)
                for x in table.indexes
                if not x._ddl_if or x._ddl_if.dialect == "postgresql"
            }
            assert indexes == expected_indexes, (table.name, "index parity", indexes ^ expected_indexes)
            from sqlalchemy import CheckConstraint, UniqueConstraint

            checks = {x["name"] for x in catalog.get_check_constraints(table.name)}
            expected_checks = {
                conn.dialect.identifier_preparer.truncate_and_render_constraint_name(x.name, _alembic_quote=False)
                for x in table.constraints
                if isinstance(x, CheckConstraint)
            }
            if table.name in (*TABLES, "iam_users"):
                expected_checks.add("ck_" + table.name + "_public_id_v4")
            assert checks == expected_checks, (table.name, "CHECK parity", checks ^ expected_checks)
            unique = {tuple(x["column_names"]) for x in catalog.get_unique_constraints(table.name)}
            expected_unique = {tuple(x.columns.keys()) for x in table.constraints if isinstance(x, UniqueConstraint)}
            assert unique == expected_unique, (table.name, "UNIQUE parity")
            counts["tables"] += 1
            counts["columns"] += len(cols)
            counts["foreign_keys"] += len(actual)
            counts["indexes"] += len(indexes)
            counts["checks"] += len(checks)
            counts["unique_constraints"] += len(unique)
        uuid_rows = conn.exec_driver_sql(
            "SELECT c.relname,a.attnotnull,format_type(a.atttypid,a.atttypmod),pg_get_expr(d.adbin,d.adrelid) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum WHERE n.nspname='public' AND a.attname='public_id' AND NOT a.attisdropped ORDER BY c.relname"
        ).all()
        assert len(uuid_rows) == 7
        for name, notnull, typename, default in uuid_rows:
            assert name in (*TABLES, "iam_users") and notnull and typename == "uuid" and default == "gen_random_uuid()"
            triggers = conn.execute(
                text("SELECT tgname,tgenabled FROM pg_trigger WHERE tgrelid=to_regclass(:table) AND NOT tgisinternal"),
                {"table": "public." + name},
            ).all()
            assert sorted(triggers) == sorted(
                [(f"trg_{name}_public_id_" + ("allocate" if name == "iam_users" else "insert"), "O"), (f"trg_{name}_public_id_immutable", "O")]
            )
            assert conn.execute(
                text("SELECT convalidated FROM pg_constraint WHERE conrelid=to_regclass(:table) AND conname=:name"),
                {"table": "public." + name, "name": f"ck_{name}_public_id_v4"},
            ).scalar_one()
        identity = conn.exec_driver_sql(
            "SELECT current_database(),(SELECT oid FROM pg_database WHERE datname=current_database()),system_identifier::text,current_setting('server_version') FROM pg_control_system()"
        ).one()
        role = conn.exec_driver_sql(
            "SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname='greenfield_app'"
        ).one()
        assert not any(role)
        assert not conn.exec_driver_sql("SELECT has_schema_privilege('greenfield_app','public','CREATE')").scalar_one()
        assert not conn.exec_driver_sql(
            "SELECT has_table_privilege('greenfield_app','alembic_version','UPDATE')"
        ).scalar_one()
        owners = (
            conn.exec_driver_sql(
                "SELECT DISTINCT pg_get_userbyid(c.relowner) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','S','i')"
            )
            .scalars()
            .all()
        )
        assert owners == ["greenfield_owner"], ("object owners", owners)
        guard = conn.exec_driver_sql(
            "SELECT pg_get_userbyid(proowner),prosecdef,provolatile,proconfig,prosrc FROM pg_proc WHERE oid='public.uuid_public_identity_guard_v1()'::regprocedure"
        ).one()
        assert tuple(guard[:4]) == ("greenfield_owner", False, "v", ["search_path=pg_catalog"])
        import inspect as python_inspect

        from app.public_identity import install_guards

        expected_body = (
            python_inspect.getsource(install_guards).split("AS $guard$", 1)[1].split("$guard$", 1)[0].strip()
        )
        assert guard[4].strip() == expected_body, "Shared guard definition differs from source"
        assert not conn.exec_driver_sql(
            "SELECT EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a WHERE p.oid='public.uuid_public_identity_guard_v1()'::regprocedure AND a.grantee=0)"
        ).scalar_one(), "Guard must not be executable by PUBLIC"
        for name in metadata.tables:
            assert conn.execute(
                text("SELECT has_table_privilege('greenfield_app',:table,'SELECT,INSERT,UPDATE,DELETE')"),
                {"table": name},
            ).scalar_one(), name
        from app.core.permissions import ALL_PERMISSIONS, ROLE_PERMISSIONS

        actual_permissions = set(conn.exec_driver_sql("SELECT code FROM authorization_permissions").scalars())
        assert actual_permissions == set(ALL_PERMISSIONS), (
            "permission catalog",
            actual_permissions ^ set(ALL_PERMISSIONS),
        )
        for role_name, permissions in ROLE_PERMISSIONS.items():
            actual = set(
                conn.execute(
                    text(
                        "SELECT p.code FROM authorization_role_permissions m JOIN authorization_roles r ON r.id=m.role_id JOIN authorization_permissions p ON p.id=m.permission_id WHERE r.code=:role"
                    ),
                    {"role": role_name},
                ).scalars()
            )
            assert actual == set(permissions), (role_name, "permission mapping", actual ^ set(permissions))
    engine.dispose()
    report = {
        "revision": REVISION,
        "database": identity[0],
        "database_oid": identity[1],
        "cluster_id": identity[2],
        "postgresql": identity[3],
        "counts": counts,
        "uuid_resources": list(TABLES),
        "native_UUID_NOT_NULL_unique_validated_CHECKs_two_enabled_triggers": True,
        "restricted_runtime_role": True,
        "catalog_metadata_parity": True,
        "reference_permission_parity": True,
    }
    path = STATE / ("schema-acceptance.json" if database == "sbom_greenfield_uuid" else "repro-schema-acceptance.json")
    path.write_text(json.dumps(report, indent=2))
    path.chmod(0o600)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    verify()
