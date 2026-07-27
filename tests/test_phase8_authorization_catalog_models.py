from app.db import engine
from sqlalchemy import inspect


def test_authorization_catalog_tables_and_constraints_exist():
    schema = inspect(engine)
    assert {
        "authorization_roles",
        "authorization_permissions",
        "authorization_role_permissions",
    }.issubset(schema.get_table_names())
    role_uniques = {item["name"] for item in schema.get_unique_constraints("authorization_roles")}
    mapping_uniques = {item["name"] for item in schema.get_unique_constraints("authorization_role_permissions")}
    assert "uq_authorization_roles_scope_code" in role_uniques
    assert "uq_authorization_role_permissions_role_permission" in mapping_uniques


def test_catalog_is_global_not_tenant_owned():
    schema = inspect(engine)
    for table in (
        "authorization_roles",
        "authorization_permissions",
        "authorization_role_permissions",
    ):
        assert "tenant_id" not in {column["name"] for column in schema.get_columns(table)}
