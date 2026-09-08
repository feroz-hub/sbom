from alembic.config import Config
from alembic.script import ScriptDirectory
from app.db import engine
from sqlalchemy import inspect, text


def test_phase9_is_single_alembic_head():
    scripts = ScriptDirectory.from_config(Config("alembic.ini"))
    assert scripts.get_heads() == ["054_hierarchical_scheduler"]


def test_phase9_database_is_at_head_and_has_partial_primary_index():
    with engine.connect() as connection:
        assert connection.scalar(text("select version_num from alembic_version")) == (
            "054_hierarchical_scheduler"
        )
    indexes = inspect(engine).get_indexes("tenant_user_role_assignments")
    primary = next(
        item
        for item in indexes
        if item["name"] == "uq_tenant_user_role_assignments_active_primary"
    )
    assert primary["unique"] is True
