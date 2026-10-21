"""Historical migration tests use new owned databases and a frozen pre-UUID chain.

Greenfield 100 intentionally refuses downgrade. Never downgrade the current
application/test database to exercise historical migration functions.
"""
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

HISTORICAL_HEADS = {
    "test_entra_migration": "063_microsoft_entra_identity",
    "test_native_identity_migration": "060_native_identity_foundation",
    "test_phase3_identity_migration": "047_email_verification_tokens",
    "test_phase5_identity_migration": "047_email_verification_tokens",
    "test_report_migrations": "053_tenant_analysis_schedule",
    "test_sbom_repair_migration": "074_sbom_repair_jobs",
}


@pytest.fixture
def historical_database(client, monkeypatch, tmp_path, request):
    import app.db as database

    legacy_head = HISTORICAL_HEADS[request.module.__name__.split(".")[-1]]
    template = make_url(database.DATABASE_URL)
    assert template.get_backend_name() == "postgresql"
    assert "_test" in (template.database or "")
    name = "sbom_round4_historical_test_" + uuid4().hex
    target = template.set(database=name)
    root = Path(__file__).resolve().parents[1]
    control = create_engine(template.set(database="postgres"), isolation_level="AUTOCOMMIT", hide_parameters=True)
    engine = create_engine(target, hide_parameters=True)
    with control.connect() as connection:
        assert not connection.scalar(text("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=:name)"), {"name": name})
        connection.exec_driver_sql("CREATE DATABASE " + name)
    try:
        # Only a new, verified empty owned DB receives this immutable schema.
        with engine.connect() as connection:
            assert not inspect(connection).get_table_names()
        raw = engine.raw_connection()
        try:
            with raw.cursor() as cursor:
                cursor.execute((root / 'scripts/schema/postgresql_047_baseline.sql').read_text(), prepare=False)
                cursor.execute('CREATE TABLE public.alembic_version(version_num varchar(128) PRIMARY KEY)')
                cursor.execute("INSERT INTO public.alembic_version VALUES ('047_email_verification_tokens')")
                cursor.execute("SET search_path TO public")
            raw.commit()
        finally:
            raw.close()
        # The test-only chain contains the unchanged historical sources. 100 is
        # deliberately outside its range, never disabled in application code.
        migrations = tmp_path / 'historical-alembic'
        (migrations / 'versions').mkdir(parents=True)
        (migrations / 'env.py').symlink_to(root / 'alembic/env.py')
        for path in (root / 'alembic/versions').glob('*.py'):
            if path.name[:3].isdigit() and int(path.name[:3]) <= int(legacy_head[:3]):
                (migrations / 'versions' / path.name).symlink_to(path)
        def config(_filename='alembic.ini'):
            value = Config(str(root / 'alembic.ini'))
            value.set_main_option('script_location', str(migrations))
            return value
        url = target.render_as_string(hide_password=False)
        for key in ('DATABASE_URL', 'TEST_DATABASE_URL', 'TEST_POSTGRES_DATABASE_URL'):
            monkeypatch.setenv(key, url)
        monkeypatch.setenv('SBOM_IDENTITY_BACKFILL_ISSUER', 'https://hcl-cs.test')
        monkeypatch.setattr('logging.config.fileConfig', lambda *args, **kwargs: None)
        command.upgrade(config(), legacy_head)
        with engine.begin() as connection:
            connection.execute(text("INSERT INTO tenants(id,name,slug,external_iam_tenant_id,status,created_at,updated_at) VALUES(1,'Historical fixture','legacy-fixture','legacy-fixture','ACTIVE',now(),now())"))
        sessions = sessionmaker(bind=engine, class_=database.TenantSession, autoflush=False)
        monkeypatch.setattr(database, 'SessionLocal', sessions)
        monkeypatch.setattr(database, 'engine', engine)
        monkeypatch.setattr(database, 'DATABASE_URL', url)
        module = request.module
        for key, value in [('Config', config), ('SessionLocal', sessions), ('CURRENT_HEAD', legacy_head), ('REVISION', legacy_head)]:
            if hasattr(module, key):
                # REVISION in Phase3/5 is the migration under test, not head.
                if key == 'REVISION' and module.__name__.endswith(('test_phase3_identity_migration', 'test_phase5_identity_migration')):
                    continue
                monkeypatch.setattr(module, key, value)
        yield engine
    finally:
        engine.dispose()
        # The random name was created by this fixture, never taken from input.
        with control.connect() as connection:
            connection.exec_driver_sql("DROP DATABASE " + name + " WITH (FORCE)")
        control.dispose()
