"""Backfill preserves existing IDs, evidence and labels while grouping only declared history."""

import importlib.util
import os
import uuid
from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url


@pytest.fixture(params=["sqlite", "postgres"])
def migration_engine(request, tmp_path):
    if request.param == "sqlite":
        engine = create_engine(f"sqlite:///{tmp_path / 'migration.db'}")
        yield engine
        engine.dispose()
        return
    template = make_url(os.environ["TEST_POSTGRES_DATABASE_URL"])
    name = "logical_sbom_migration_test_" + uuid.uuid4().hex[:10]
    control = create_engine(template.set(database="postgres"), isolation_level="AUTOCOMMIT", hide_parameters=True)
    with control.connect() as connection:
        connection.execute(text("CREATE DATABASE " + name))
    engine = create_engine(template.set(database=name), hide_parameters=True)
    try:
        yield engine
    finally:
        engine.dispose()
        with control.connect() as connection:
            connection.execute(text("DROP DATABASE " + name))
        control.dispose()


def test_logical_migration_preserves_legacy_records_and_evidence(migration_engine, monkeypatch):
    path = Path(__file__).resolve().parents[1] / "alembic/versions/076_logical_sbom_versions.py"
    spec = importlib.util.spec_from_file_location("logical_migration", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    with migration_engine.begin() as connection:
        for sql in (
            "CREATE TABLE tenants (id INTEGER PRIMARY KEY)",
            "CREATE TABLE products (id INTEGER PRIMARY KEY, tenant_id INTEGER NOT NULL REFERENCES tenants(id))",
            """CREATE TABLE sbom_source (id INTEGER PRIMARY KEY, tenant_id INTEGER NOT NULL, product_id INTEGER,
                projectid INTEGER, sbom_name TEXT NOT NULL, sbom_version TEXT, productver TEXT, sbom_data TEXT,
                parent_id INTEGER, source_sbom_id INTEGER, description TEXT, created_by TEXT, created_on TEXT,
                modified_on TEXT, is_active BOOLEAN, lifecycle_status TEXT,
                CONSTRAINT uq_sbom_source_tenant_name_version UNIQUE (tenant_id, sbom_name, sbom_version))""",
            "CREATE TABLE evidence (id INTEGER PRIMARY KEY, sbom_id INTEGER REFERENCES sbom_source(id), kind TEXT, data TEXT)",
            "INSERT INTO tenants VALUES (1), (2)",
            "INSERT INTO products VALUES (10,1), (20,2)",
        ):
            connection.execute(text(sql))
        rows = [
            (1, 1, 10, 1, "Backend", "1.0", None),
            (2, 1, 10, 1, "Backend", "1.1", 1),
            (3, 1, 10, 1, "Other same name", "1.0", None),
            (4, 2, 20, 2, "Other tenant", "2.0", 2),
            # A renamed legacy node repeats a revision; preserve it in another master.
            (5, 1, 10, 1, "Renamed duplicate", "1.1", 2),
            (6, 1, None, None, "Unassigned", None, None),
        ]
        for id, tenant, product, project, name, version, parent in rows:
            connection.execute(
                text("""INSERT INTO sbom_source (id,tenant_id,product_id,projectid,sbom_name,sbom_version,parent_id,
                productver,sbom_data,created_by,created_on,is_active,lifecycle_status) VALUES
                (:id,:tenant,:product,:project,:name,:version,:parent,'3.2.0','original file','legacy','2026-01-01',:active,:lifecycle)"""),
                dict(
                    id=id,
                    tenant=tenant,
                    product=product,
                    project=project,
                    name=name,
                    version=version,
                    parent=parent,
                    active=id != 2,
                    lifecycle="INACTIVE" if id == 2 else "ACTIVE",
                ),
            )
            for offset, kind in enumerate(("component", "finding", "analysis", "vex", "lifecycle", "report", "audit")):
                connection.execute(
                    text("INSERT INTO evidence VALUES (:id,:sbom,:kind,:data)"),
                    dict(id=id * 10 + offset, sbom=id, kind=kind, data=f"original-{id}-{kind}"),
                )
        before = list(connection.execute(text("SELECT * FROM sbom_source ORDER BY id")).mappings())
        evidence = list(connection.execute(text("SELECT * FROM evidence ORDER BY id")))
        operations = Operations(MigrationContext.configure(connection))
        monkeypatch.setattr(migration, "op", operations)
        migration.upgrade()
        after = list(connection.execute(text("SELECT * FROM sbom_source ORDER BY id")).mappings())
        assert [{key: row[key] for key in before[0]} for row in after] == before
        assert list(connection.execute(text("SELECT * FROM evidence ORDER BY id"))) == evidence
        assert after[0]["logical_sbom_id"] == after[1]["logical_sbom_id"]
        assert len({after[i]["logical_sbom_id"] for i in (0, 2, 3, 4, 5)}) == 5
        assert all(row["logical_sbom_id"] for row in after)
        schema = inspect(connection)
        assert not next(c for c in schema.get_columns("sbom_source") if c["name"] == "logical_sbom_id")["nullable"]
        assert any(
            fk["constrained_columns"] == ["logical_sbom_id", "tenant_id", "product_id"]
            for fk in schema.get_foreign_keys("sbom_source")
        )
        assert any(
            uq["column_names"] == ["logical_sbom_id", "sbom_version"]
            for uq in schema.get_unique_constraints("sbom_source")
        )


@pytest.mark.parametrize("migration_engine", ["postgres"], indirect=True)
def test_full_postgres_upgrade_preserves_existing_sbom_evidence(migration_engine, tmp_path):
    """Run 075 -> 076 against the real frozen baseline and existing evidence rows."""
    import subprocess
    import sys
    from datetime import UTC, datetime

    from scripts.bootstrap_fresh_database import BASELINE_REVISION, SNAPSHOT

    root = Path(__file__).resolve().parents[1]
    raw = migration_engine.raw_connection()
    try:
        cursor = raw.cursor()
        cursor.execute(SNAPSHOT.read_text(), prepare=False)
        cursor.execute("CREATE TABLE public.alembic_version (version_num VARCHAR(128) NOT NULL PRIMARY KEY)")
        cursor.execute("INSERT INTO public.alembic_version VALUES (%s)", (BASELINE_REVISION,))
        raw.commit()
    finally:
        raw.close()
    # The frozen dump clears search_path; discard its pooled connection.
    migration_engine.dispose()
    env = {**os.environ, "DATABASE_URL": migration_engine.url.render_as_string(hide_password=False)}

    def upgrade(revision):
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", revision],
            env=env,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=120,
        )
        log = tmp_path / f"upgrade-{revision}.log"
        log.write_text(result.stdout + result.stderr)
        assert result.returncode == 0, f"Migration diagnostics: {log}"

    upgrade("075_platform_advisor_policies")
    now = datetime.now(UTC)
    with migration_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO tenants (id,name,slug,external_iam_tenant_id,status,created_at,updated_at) VALUES (901,'Migration tenant','migration-tenant','migration-tenant','ACTIVE',:now,:now)"
            ),
            {"now": now},
        )
        connection.execute(
            text(
                "INSERT INTO projects (id,tenant_id,project_name,project_status) VALUES (901,901,'Migration project',1)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO products (id,tenant_id,project_id,name,normalized_name,slug,created_at) VALUES (901,901,901,'Migration product','migration product','migration-product',:now)"
            ),
            {"now": now.isoformat()},
        )
        connection.execute(
            text(
                "INSERT INTO sbom_source (id,tenant_id,product_id,projectid,sbom_name,sbom_version,productver,sbom_data,created_on,lifecycle_status) VALUES (901,901,901,901,'Backend','1.0','3.2.0','original document',:now,'INACTIVE')"
            ),
            {"now": now.isoformat()},
        )
        connection.execute(
            text(
                "INSERT INTO sbom_source (id,tenant_id,product_id,projectid,sbom_name,sbom_version,productver,sbom_data,parent_id,created_on) VALUES (902,901,901,901,'Backend','1.1','3.2.0','new document',901,:now)"
            ),
            {"now": now.isoformat()},
        )
        connection.execute(
            text(
                "INSERT INTO sbom_component (id,tenant_id,sbom_id,name,version,lifecycle_is_stale,lifecycle_manual_override,is_duplicate) VALUES (901,901,901,'legacy-component','1.0',false,false,false)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO analysis_run (id,tenant_id,sbom_id,project_id,product_id,run_status,source,started_on,completed_on,duration_ms,total_components,components_with_cpe,total_findings,critical_count,high_count,medium_count,low_count,unknown_count,query_error_count) VALUES (901,901,901,901,901,'COMPLETED','NVD',:now,:now,0,1,0,0,0,0,0,0,0,0)"
            ),
            {"now": now.isoformat()},
        )
        connection.execute(
            text(
                "INSERT INTO analysis_finding (id,tenant_id,analysis_run_id,component_id,vuln_id) VALUES (901,901,901,901,'CVE-2021-44228')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO vex_documents (id,tenant_id,sbom_id,source_type,uploaded_at,validation_status) VALUES (901,901,901,'uploaded',:now,'accepted')"
            ),
            {"now": now.isoformat()},
        )
        connection.execute(
            text(
                "INSERT INTO sbom_analysis_report (id,tenant_id,sbom_ref_id,analysis_details) VALUES (901,901,901,'original report')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO audit_log (id,tenant_id,action,target_kind,target_id,created_at) VALUES (901,901,'sbom.upload','sbom',901,:now)"
            ),
            {"now": now.isoformat()},
        )
        evidence_before = {
            table: connection.execute(text(f"SELECT * FROM {table} WHERE id=901")).mappings().one()
            for table in ("analysis_finding", "vex_documents", "sbom_analysis_report", "audit_log")
        }
        before = list(connection.execute(text("SELECT * FROM sbom_source WHERE tenant_id=901 ORDER BY id")).mappings())
        component = connection.execute(text("SELECT * FROM sbom_component WHERE id=901")).mappings().one()
        analysis = connection.execute(text("SELECT * FROM analysis_run WHERE id=901")).mappings().one()
    upgrade("076_logical_sbom_versions")
    with migration_engine.connect() as connection:
        after = list(connection.execute(text("SELECT * FROM sbom_source WHERE tenant_id=901 ORDER BY id")).mappings())
        assert [{key: row[key] for key in before[0]} for row in after] == before
        assert after[0]["logical_sbom_id"] == after[1]["logical_sbom_id"]
        assert connection.execute(text("SELECT * FROM sbom_component WHERE id=901")).mappings().one() == component
        assert connection.execute(text("SELECT * FROM analysis_run WHERE id=901")).mappings().one() == analysis
        for table, record in evidence_before.items():
            assert connection.execute(text(f"SELECT * FROM {table} WHERE id=901")).mappings().one() == record
        assert (
            connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
            == "076_logical_sbom_versions"
        )
