from __future__ import annotations

from alembic.config import Config
from alembic.script import ScriptDirectory
from app.db import engine
from sqlalchemy import inspect


def test_ai_model_registry_is_single_head_and_schema_is_installed(client):
    scripts = ScriptDirectory.from_config(Config("alembic.ini"))
    assert scripts.get_heads() == ["055_ai_model_registry"]

    inspector = inspect(engine)
    columns = {column["name"]: column for column in inspector.get_columns("ai_provider_model")}
    assert {
        "provider_credential_id", "provider_model_id", "runtime_model_id",
        "is_available", "is_selected", "supports_structured_output",
        "last_discovered_at", "last_verified_at", "raw_metadata",
    } <= columns.keys()
    constraints = inspector.get_unique_constraints("ai_provider_model")
    assert any(
        set(item["column_names"]) == {"provider_credential_id", "provider_model_id"}
        for item in constraints
    )
    indexes = {item["name"]: item for item in inspector.get_indexes("ai_provider_model")}
    assert indexes["ix_ai_provider_model_only_one_selected"]["unique"] is True
