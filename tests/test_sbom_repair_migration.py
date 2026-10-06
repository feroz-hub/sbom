"""Repair schema review and real PostgreSQL round-trip on a new disposable DB."""

import os
import subprocess
import sys
import uuid
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url


def test_repair_migration_postgres_round_trip(tmp_path):
    root = Path(__file__).resolve().parents[1]
    scripts = ScriptDirectory.from_config(Config(str(root / "alembic.ini")))
    assert scripts.get_heads() == ["074_sbom_repair_jobs"]
    assert scripts.get_revision("074_sbom_repair_jobs").down_revision == "073_sbom_operational_lifecycle"
    template = make_url(os.environ["TEST_POSTGRES_DATABASE_URL"])
    name = "sbom_repair_migration_test_" + uuid.uuid4().hex[:10]
    url = template.set(database=name)
    control = create_engine(template.set(database="postgres"), isolation_level="AUTOCOMMIT", hide_parameters=True)
    with control.connect() as connection:
        connection.execute(text("CREATE DATABASE " + name))
    env = {**os.environ, "DATABASE_URL": url.render_as_string(hide_password=False), "REPAIR_MIGRATION_DB_NAME": name}
    engine = create_engine(url, hide_parameters=True)
    try:
        commands = [
            [sys.executable, "-c", "import os; from scripts.bootstrap_fresh_database import bootstrap; bootstrap(os.environ['DATABASE_URL'], os.environ['REPAIR_MIGRATION_DB_NAME'])"],
            [sys.executable, "-m", "alembic", "downgrade", "073_sbom_operational_lifecycle"],
            [sys.executable, "-m", "alembic", "upgrade", "head"],
        ]
        for index, command in enumerate(commands):
            result = subprocess.run(command, env=env, cwd=root, capture_output=True, text=True, timeout=90)
            (tmp_path / f"migration-{index}.log").write_text(result.stdout + result.stderr)
            assert result.returncode == 0, f"Migration failed; diagnostics in {tmp_path}"
            schema = inspect(engine)
            if index == 1:
                assert not schema.has_table("sbom_repair_jobs")
                assert schema.has_table("sbom_validation_sessions")
            else:
                assert schema.has_table("sbom_repair_jobs")
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
            assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar() == "074_sbom_repair_jobs"
    finally:
        engine.dispose()
        with control.connect() as connection:
            connection.execute(text("DROP DATABASE " + name + " WITH (FORCE)"))
        control.dispose()
