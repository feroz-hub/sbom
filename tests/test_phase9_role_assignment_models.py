from app.db import engine
from sqlalchemy import inspect


def test_phase9_tables_columns_and_constraints_exist():
    schema = inspect(engine)
    assert {
        "tenant_user_role_assignments",
        "tenant_user_role_assignment_history",
    } <= set(schema.get_table_names())
    membership_columns = {item["name"] for item in schema.get_columns("tenant_users")}
    assert "role_assignment_version" in membership_columns
    assignment_columns = {
        item["name"] for item in schema.get_columns("tenant_user_role_assignments")
    }
    assert {
        "tenant_id",
        "tenant_user_id",
        "role_id",
        "status",
        "is_primary",
        "assignment_source",
        "version",
    } <= assignment_columns


def test_assignment_has_composite_membership_foreign_key_and_unique_role():
    schema = inspect(engine)
    foreign_keys = schema.get_foreign_keys("tenant_user_role_assignments")
    assert any(
        fk["constrained_columns"] == ["tenant_user_id", "tenant_id"]
        and fk["referred_columns"] == ["id", "tenant_id"]
        for fk in foreign_keys
    )
    uniques = {
        item["name"]
        for item in schema.get_unique_constraints("tenant_user_role_assignments")
    }
    assert "uq_tenant_user_role_assignments_membership_role" in uniques
