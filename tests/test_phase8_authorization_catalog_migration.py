from app.db import DATABASE_URL
from sqlalchemy import create_engine, inspect, text


def test_revision_and_version_column_are_current_and_wide():
    engine = create_engine(DATABASE_URL)
    try:
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
                "055_ai_model_registry"
            )
            width = connection.scalar(
                text(
                    "SELECT character_maximum_length FROM information_schema.columns "
                    "WHERE table_schema='public' AND table_name='alembic_version' "
                    "AND column_name='version_num'"
                )
            )
            assert width >= 128
            assert "authorization_roles" in inspect(connection).get_table_names()
    finally:
        engine.dispose()
