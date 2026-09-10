"""Schema contract for revision 054 hierarchical scheduling."""

from alembic.config import Config
from alembic.script import ScriptDirectory
from app.db import engine
from sqlalchemy import inspect, text


def test_hierarchical_scheduler_is_single_head():
    scripts = ScriptDirectory.from_config(Config("alembic.ini"))
    assert scripts.get_heads() == ["055_ai_model_registry"]


def test_hierarchical_scheduler_columns_indexes_and_fk_are_installed():
    inspector = inspect(engine)
    product_columns = {column["name"]: column for column in inspector.get_columns("products")}
    schedule_columns = {column["name"]: column for column in inspector.get_columns("analysis_schedule")}
    assert product_columns["current_sbom_id"]["nullable"] is True
    assert schedule_columns["mode"]["nullable"] is False
    assert schedule_columns["target_version_policy"]["nullable"] is False

    indexes = {index["name"] for index in inspector.get_indexes("products")}
    assert "ix_products_current_sbom_id" in indexes

    fk = next(
        item
        for item in inspector.get_foreign_keys("products")
        if item["constrained_columns"] == ["current_sbom_id"]
    )
    assert fk["referred_table"] == "sbom_source"
    assert (fk.get("options") or {}).get("ondelete") == "SET NULL"


def test_existing_schedule_defaults_are_current_only_custom():
    with engine.begin() as connection:
        row = connection.execute(
            text(
                """
                INSERT INTO analysis_schedule
                    (tenant_id, scope, cadence, hour_utc, timezone, enabled,
                     consecutive_failures, min_gap_minutes, is_active)
                VALUES
                    (1, 'TENANT', 'DAILY', 2, 'UTC', true, 0, 60, true)
                RETURNING mode, target_version_policy
                """
            )
        ).one()
    assert row.mode == "CUSTOM"
    assert row.target_version_policy == "CURRENT_ONLY"
