"""Exercise 051–053 forward and backward on the disposable test database only."""

from tests.historical_migration_fixture import historical_database as _historical_database

historical_database = _historical_database

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, text


def test_report_migrations_round_trip_preserves_inventory(historical_database, client):
    engine = historical_database
    assert engine.url.database.startswith("sbom_round4_historical_test_")
    with engine.begin() as connection:
        identifier = connection.scalar(text("INSERT INTO projects(project_name,project_status,tenant_id,is_active) VALUES('migration-preservation',1,1,true) RETURNING id"))
    config = Config("alembic.ini")
    try:
        command.downgrade(config, "050_optional_external_tenant_mapping")
        assert "report_subscription" not in inspect(engine).get_table_names()
    finally:
        command.upgrade(config, "head")
    with engine.connect() as conn:
        assert (
            conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == "053_tenant_analysis_schedule"
        )
        assert (
            conn.execute(text("SELECT project_name FROM projects WHERE id=:id"), {"id": identifier}).scalar_one()
            == "migration-preservation"
        )
    indexes = {item["name"]: item for item in inspect(engine).get_indexes("report_subscription")}
    assert all(
        indexes[f"uq_report_subscription_{scope}"]["unique"] for scope in ["tenant", "project", "product", "sbom"]
    )
