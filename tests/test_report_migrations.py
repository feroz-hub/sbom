"""Exercise 051–053 forward and backward on the disposable test database only."""

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, text


def test_report_migrations_round_trip_preserves_inventory(client):
    from app.db import SessionLocal, engine
    from app.models import Projects

    assert "test" in engine.url.database.lower()
    with SessionLocal() as db:
        project = Projects(project_name="migration-preservation", project_status=1, tenant_id=1)
        db.add(project)
        db.commit()
        identifier = project.id
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
