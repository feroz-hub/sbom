from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

pytestmark = pytest.mark.postgres
ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def postgres_url() -> str:
    value = (os.getenv("TEST_POSTGRES_DATABASE_URL") or "").strip()
    if not value:
        pytest.skip("TEST_POSTGRES_DATABASE_URL is not configured")
    parsed = sa.engine.make_url(value)
    if "test" not in (parsed.database or "").lower():
        pytest.fail("TEST_POSTGRES_DATABASE_URL must use a disposable database containing 'test'")
    env = os.environ.copy()
    env["DATABASE_URL"] = value
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=ROOT,
        env=env,
        check=True,
    )
    return value


def _clear_application_tables(url: str) -> None:
    engine = sa.create_engine(url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as connection:
            all_table_names = list(
                connection.execute(
                    sa.text(
                        """
                        SELECT format('%I.%I', schemaname, tablename)
                        FROM pg_tables
                        WHERE schemaname = 'public'
                          AND tablename <> 'alembic_version'
                        ORDER BY tablename
                        """
                    )
                ).scalars()
            )
            table_names = [
                table_name
                for table_name in all_table_names
                if connection.execute(sa.text(f"SELECT EXISTS (SELECT 1 FROM {table_name} LIMIT 1)")).scalar()
            ]
            if table_names:
                connection.execute(sa.text(f"TRUNCATE TABLE {', '.join(table_names)} RESTART IDENTITY CASCADE"))
            sequence_names = list(
                connection.execute(
                    sa.text(
                        """
                        SELECT format('%I.%I', sequence_schema, sequence_name)
                        FROM information_schema.sequences
                        WHERE sequence_schema = 'public'
                        ORDER BY sequence_name
                        """
                    )
                ).scalars()
            )
            for sequence_name in sequence_names:
                connection.execute(sa.text(f"ALTER SEQUENCE {sequence_name} RESTART WITH 1"))
    finally:
        engine.dispose()


@pytest.fixture()
def clean_postgres(postgres_url: str):
    _clear_application_tables(postgres_url)
    yield
    _clear_application_tables(postgres_url)


def test_fresh_postgresql_alembic_upgrade_and_check(postgres_url: str) -> None:
    base_url = sa.engine.make_url(postgres_url)
    database_name = f"sbom_test_fresh_{uuid.uuid4().hex[:10]}"
    admin_url = base_url.set(database="postgres")
    admin = sa.create_engine(admin_url, isolation_level="AUTOCOMMIT")
    quoted = admin.dialect.identifier_preparer.quote(database_name)
    try:
        with admin.connect() as connection:
            connection.execute(sa.text(f"CREATE DATABASE {quoted}"))
        fresh_url = base_url.set(database=database_name).render_as_string(hide_password=False)
        env = os.environ.copy()
        env["DATABASE_URL"] = fresh_url
        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=ROOT,
            env=env,
            check=True,
        )
        subprocess.run(
            [sys.executable, "-m", "alembic", "check"],
            cwd=ROOT,
            env=env,
            check=True,
        )
    finally:
        with admin.connect() as connection:
            connection.execute(
                sa.text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :name AND pid <> pg_backend_pid()"
                ),
                {"name": database_name},
            )
            connection.execute(sa.text(f"DROP DATABASE IF EXISTS {quoted}"))
        admin.dispose()


def test_migration_script_copies_rows_and_resets_sequences(
    postgres_url: str,
    clean_postgres,
    tmp_path: Path,
) -> None:
    import app.nvd_mirror.db.models  # noqa: F401 -- register mirror tables on Base.metadata
    from app.db import Base
    from app.models import Projects, SBOMComponent, SBOMSource, SBOMType, Tenant
    from scripts.migrate_sqlite_to_postgres import main

    source_path = tmp_path / "source.db"
    source_url = f"sqlite:///{source_path}"
    source_engine = sa.create_engine(source_url)
    Base.metadata.create_all(source_engine)
    with source_engine.begin() as connection:
        connection.execute(sa.text("CREATE TABLE alembic_version (version_num VARCHAR(128) NOT NULL)"))
        connection.execute(sa.text("INSERT INTO alembic_version(version_num) VALUES ('032_postgres_compat')"))
    session_factory = sa.orm.sessionmaker(bind=source_engine)
    with session_factory() as session:
        now = datetime.now(UTC)
        tenant = Tenant(
            id=1,
            name="Default Tenant",
            slug="default",
            external_iam_tenant_id="local-default",
            status="ACTIVE",
            created_at=now,
            updated_at=now,
        )
        project = Projects(id=10, project_name="migration-project", project_status=1)
        sbom_type = SBOMType(id=4, typename="CycloneDX")
        parent = SBOMSource(
            id=20,
            sbom_name="migration-parent",
            sbom_data='{"bomFormat":"CycloneDX"}',
            sbom_type=4,
            projectid=10,
            status="validated",
        )
        child = SBOMSource(
            id=21,
            sbom_name="migration-child",
            sbom_data='{"bomFormat":"CycloneDX","version":2}',
            sbom_type=4,
            projectid=10,
            parent_id=20,
            status="validated",
        )
        component = SBOMComponent(
            id=30,
            sbom_id=20,
            name="requests",
            version="2.32.0",
            lifecycle_evidence_json={"source": "test"},
            unsupported=False,
        )
        session.add_all([tenant, project, sbom_type, parent, child, component])
        session.commit()
    source_engine.dispose()

    assert (
        main(
            [
                "--sqlite-url",
                source_url,
                "--postgres-url",
                postgres_url,
                "--dry-run",
            ]
        )
        == 0
    )
    assert main(["--sqlite-url", source_url, "--postgres-url", postgres_url]) == 0
    assert main(["--sqlite-url", source_url, "--postgres-url", postgres_url, "--verify-only"]) == 0
    assert (
        main(
            [
                "--sqlite-url",
                source_url,
                "--postgres-url",
                postgres_url,
                "--truncate-target",
                "--confirm-truncate",
            ]
        )
        == 0
    )

    target_engine = sa.create_engine(postgres_url)
    with target_engine.begin() as connection:
        assert connection.scalar(sa.text("SELECT COUNT(*) FROM sbom_source")) == 2
        assert connection.scalar(sa.text("SELECT parent_id FROM sbom_source WHERE id = 21")) == 20
        next_project_id = connection.scalar(
            sa.text(
                "INSERT INTO projects(project_name, project_status, is_active, tenant_id) "
                "VALUES ('sequence-check', 1, true, 1) RETURNING id"
            )
        )
        assert next_project_id == 11
    target_engine.dispose()


def test_postgresql_feature_smoke(
    app,
    postgres_url: str,
    clean_postgres,
    sample_sbom_dict,
    mock_external_sources,
    monkeypatch,
) -> None:
    async def _skip_enrichment(*_args, **_kwargs):
        return None

    monkeypatch.setattr("app.routers.sboms_crud.run_post_upload_enrichment", _skip_enrichment)
    monkeypatch.setattr("app.routers.sbom_versions.run_post_conversion_enrichment", _skip_enrichment)

    with TestClient(app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["database"] == {"available": True, "dialect": "postgresql"}

        project = client.post(
            "/api/projects",
            json={"project_name": f"postgres-{uuid.uuid4().hex[:8]}", "created_by": "postgres-test"},
        )
        assert project.status_code == 201, project.text
        project_id = project.json()["id"]

        created = client.post(
            "/api/sboms",
            json={
                "sbom_name": f"postgres-sbom-{uuid.uuid4().hex[:8]}",
                "sbom_data": json.dumps(sample_sbom_dict),
                "projectid": project_id,
                "created_by": "postgres-test",
            },
        )
        assert created.status_code == 201, created.text
        sbom_id = created.json()["id"]

        for path in (
            "/api/sboms",
            f"/api/sboms/{sbom_id}",
            f"/api/sboms/{sbom_id}/components",
            f"/api/sboms/{sbom_id}/dedupe-report",
            f"/api/sboms/{sbom_id}/validation-report",
            f"/api/sboms/{sbom_id}/versions",
            "/dashboard/recent-sboms",
        ):
            response = client.get(path)
            assert response.status_code == 200, f"{path}: {response.text}"

        assert client.post(f"/api/sboms/{sbom_id}/revalidate").status_code == 200
        analysis = client.post(f"/api/sboms/{sbom_id}/analyze")
        assert analysis.status_code == 201, analysis.text
        assert client.get(f"/api/sboms/{sbom_id}/risk-summary").status_code == 200

        from app.db import SessionLocal
        from app.models import SBOMComponent

        with SessionLocal() as session:
            component = (
                session.execute(sa.select(SBOMComponent).where(SBOMComponent.sbom_id == sbom_id)).scalars().first()
            )
            assert component is not None
            component.lifecycle_status = "EOL"
            component.eol_date = "2025-01-01"
            session.commit()
            component_ref = component.bom_ref or component.name
            component_name = component.name
            component_version = component.version or "unknown"
        assert client.get(f"/api/sboms/{sbom_id}/lifecycle/report").status_code == 200

        vex = client.post(
            f"/api/sboms/{sbom_id}/vex",
            json={
                "document": {
                    "bomFormat": "CycloneDX",
                    "vulnerabilities": [
                        {
                            "id": "CVE-2026-0001",
                            "analysis": {"state": "affected"},
                            "affects": [{"ref": component_ref}],
                        }
                    ],
                }
            },
        )
        assert vex.status_code == 200, vex.text
        assert client.get(f"/api/sboms/{sbom_id}/vex").status_code == 200

        remediation = client.post(
            f"/api/remediation?project_id={project_id}&user_id=postgres-test",
            json={
                "vuln_id": "CVE-2026-0001",
                "component_name": component_name,
                "component_version": component_version,
                "status": "Open",
                "owner": "security@example.test",
            },
        )
        assert remediation.status_code == 200, remediation.text

        schedule = client.post(
            f"/api/projects/{project_id}/schedule",
            json={
                "cadence": "WEEKLY",
                "day_of_week": 1,
                "hour_utc": 2,
                "timezone": "Asia/Kolkata",
                "modified_by": "postgres-test",
            },
        )
        assert schedule.status_code == 201, schedule.text

        spdx_path = ROOT / "tests/fixtures/sboms/valid/spdx_2_3_minimal.json"
        with spdx_path.open("rb") as stream:
            upload = client.post(
                "/api/sboms/upload",
                data={"sbom_name": f"postgres-spdx-{uuid.uuid4().hex[:8]}", "created_by": "postgres-test"},
                files={"file": (spdx_path.name, stream, "application/json")},
            )
        assert upload.status_code == 202, upload.text
        spdx_id = upload.json()["sbom_id"]
        conversion = client.post(f"/api/sboms/{spdx_id}/convert/cyclonedx")
        assert conversion.status_code == 200, conversion.text

        disposable = client.post(
            "/api/sboms",
            json={
                "sbom_name": f"postgres-delete-{uuid.uuid4().hex[:8]}",
                "sbom_data": json.dumps(sample_sbom_dict),
                "created_by": "postgres-test",
            },
        )
        disposable_id = disposable.json()["id"]
        assert client.get(f"/api/sboms/{disposable_id}/delete-impact").status_code == 200
        deleted = client.delete(
            f"/api/sboms/{disposable_id}",
            params={"user_id": "postgres-test", "confirm": "yes", "permanent": "true"},
        )
        assert deleted.status_code in {200, 409}, deleted.text
