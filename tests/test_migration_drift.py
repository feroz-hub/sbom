"""Migration/model drift guard.

This does not replace Alembic autogenerate review, but it catches the
highest-risk local failure mode: a model column was added without a
corresponding migration/startup schema path.
"""

from __future__ import annotations

from sqlalchemy import inspect

from app.db import engine
from app.models import Base


def test_model_columns_exist_in_database_schema(client):
    inspector = inspect(engine)
    missing: dict[str, list[str]] = {}

    for table in Base.metadata.sorted_tables:
        if not inspector.has_table(table.name):
            missing[table.name] = ["<table missing>"]
            continue
        db_columns = {column["name"] for column in inspector.get_columns(table.name)}
        model_columns = set(table.columns.keys())
        diff = sorted(model_columns - db_columns)
        if diff:
            missing[table.name] = diff

    assert missing == {}
