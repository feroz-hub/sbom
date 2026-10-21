"""Repair schema review and real PostgreSQL round-trip on a new disposable DB."""

from pathlib import Path

from alembic import command
from alembic.config import Config

from tests.historical_migration_fixture import historical_database as _historical_database

historical_database = _historical_database
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text


def test_repair_migration_postgres_round_trip(historical_database):
    root = Path(__file__).resolve().parents[1]
    scripts = ScriptDirectory.from_config(Config(str(root / "alembic.ini")))
    heads = scripts.get_heads()
    assert heads == ["074_sbom_repair_jobs"]
    assert "074_sbom_repair_jobs" in {revision.revision for revision in scripts.walk_revisions()}
    assert scripts.get_revision("074_sbom_repair_jobs").down_revision == "073_sbom_operational_lifecycle"
    # Execute the historical round-trip on the fixture's newly created 079
    # database; current Greenfield 100 keeps its irreversible UUID boundary.
    engine = historical_database
    config = Config(str(root / "alembic.ini"))
    assert engine.url.database.startswith("sbom_round4_historical_test_")
    command.downgrade(config, "073_sbom_operational_lifecycle")
    assert not inspect(engine).has_table("sbom_repair_jobs")
    assert inspect(engine).has_table("sbom_validation_sessions")
    command.upgrade(config, "head")
    schema = inspect(engine)
    columns = {column["name"]: column for column in schema.get_columns("sbom_repair_jobs")}
    assert not columns["tenant_id"]["nullable"]
    assert not columns["candidate_sha256"]["nullable"]
    assert not columns["created_at"]["nullable"]
    assert columns["decided_at"]["nullable"]
    assert columns["source_sbom_id"]["nullable"]
    assert str(columns["report_json"]["type"]) == "JSON"
    assert str(columns["validation_options_json"]["type"]) == "JSON"
    assert schema.get_pk_constraint("sbom_repair_jobs")["constrained_columns"] == ["id"]
    indexes = {tuple(index["column_names"]) for index in schema.get_indexes("sbom_repair_jobs")}
    assert {("tenant_id",), ("session_id",)} <= indexes
    foreign = {fk["constrained_columns"][0]: fk for fk in schema.get_foreign_keys("sbom_repair_jobs")}
    assert foreign["session_id"]["options"]["ondelete"] == "CASCADE"
    assert foreign["tenant_id"]["referred_table"] == "tenants"
    assert foreign["source_sbom_id"]["referred_table"] == "sbom_source"
    assert foreign["imported_sbom_id"]["referred_table"] == "sbom_source"
    with engine.connect() as connection:
        assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar() == heads[0]
