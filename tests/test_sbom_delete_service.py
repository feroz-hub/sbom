from __future__ import annotations

from collections.abc import Iterator

import pytest
from app.db import Base, get_db
from app.models import (
    AiFixBatch,
    AnalysisFinding,
    AnalysisRun,
    AnalysisSchedule,
    ComponentLifecycleCache,
    ComponentLifecycleOverrideAudit,
    Projects,
    SBOMAnalysisReport,
    SBOMComponent,
    SBOMSource,
    SBOMValidationSession,
    SBOMValidationSessionEvent,
    VexDocument,
    VexOverrideAudit,
    VexStatement,
    VulnerabilityRemediation,
    VulnerabilityRemediationAudit,
)
from app.routers import sboms_crud
from app.services.sbom_delete_service import SBOMDeleteConflict, SBOMDeleteService
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, func, select, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture()
def delete_db() -> Iterator[Session]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection, _connection_record) -> None:
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    session = Session(engine)
    from datetime import UTC, datetime

    from app.models import Tenant

    now = datetime.now(UTC)
    session.add(
        Tenant(
            id=1,
            name="Default Tenant",
            slug="default",
            external_iam_tenant_id="default",
            status="ACTIVE",
            created_at=now,
            updated_at=now,
        )
    )
    session.commit()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture()
def delete_client(delete_db: Session) -> Iterator[TestClient]:
    from app.core.context import minimal_background_context
    from app.core.security import get_current_tenant_context

    factory = sessionmaker(bind=delete_db.get_bind())
    api = FastAPI()
    api.include_router(sboms_crud.router)

    def _override_db() -> Iterator[Session]:
        session = factory()
        try:
            yield session
        finally:
            session.close()

    api.dependency_overrides[get_db] = _override_db
    api.dependency_overrides[get_current_tenant_context] = lambda: minimal_background_context(1, "default")
    with TestClient(api) as client:
        yield client


def _sbom(db: Session, name: str = "delete-me", **kwargs) -> SBOMSource:
    row = SBOMSource(sbom_name=name, created_by="Feroze", **kwargs)
    db.add(row)
    db.flush()
    return row


def _component(db: Session, sbom_id: int, name: str = "openssl") -> SBOMComponent:
    row = SBOMComponent(sbom_id=sbom_id, name=name, version="1.0.0")
    db.add(row)
    db.flush()
    return row


def _run(db: Session, sbom_id: int, project_id: int | None = None) -> AnalysisRun:
    row = AnalysisRun(
        sbom_id=sbom_id,
        project_id=project_id,
        run_status="FINDINGS",
        source="NVD",
        started_on="2026-06-21T00:00:00Z",
        completed_on="2026-06-21T00:00:01Z",
        duration_ms=1000,
        total_components=1,
        components_with_cpe=1,
        total_findings=1,
        critical_count=1,
        high_count=0,
        medium_count=0,
        low_count=0,
        unknown_count=0,
        query_error_count=0,
    )
    db.add(row)
    db.flush()
    return row


def _count(db: Session, model) -> int:
    return int(db.execute(select(func.count()).select_from(model).execution_options(include_deleted=True)).scalar_one())


def test_permanent_delete_without_children_succeeds(delete_db: Session) -> None:
    sbom = _sbom(delete_db)
    sbom_id = sbom.id
    delete_db.commit()

    result = SBOMDeleteService(delete_db).permanently_delete_sbom(sbom_id, "Feroze", True)

    assert result["deleted_sbom_ids"] == [sbom_id]
    assert SBOMDeleteService(delete_db).get_sbom(sbom_id) is None


def test_permanent_delete_removes_components_and_component_audits(delete_db: Session) -> None:
    sbom = _sbom(delete_db)
    component = _component(delete_db, sbom.id)
    delete_db.add_all(
        [
            ComponentLifecycleOverrideAudit(
                component_id=component.id,
                reason="manual correction",
                changed_at="2026-06-21T00:00:00Z",
            ),
            VexOverrideAudit(
                component_id=component.id,
                vulnerability_id="CVE-2026-0001",
                reason="reviewed",
                changed_at="2026-06-21T00:00:00Z",
            ),
        ]
    )
    delete_db.commit()

    SBOMDeleteService(delete_db).permanently_delete_sbom(sbom.id, "Feroze", True)

    assert _count(delete_db, SBOMComponent) == 0
    assert _count(delete_db, ComponentLifecycleOverrideAudit) == 0
    assert _count(delete_db, VexOverrideAudit) == 0


def test_permanent_delete_removes_validation_reports(delete_db: Session) -> None:
    sbom = _sbom(delete_db)
    delete_db.add(SBOMAnalysisReport(sbom_ref_id=sbom.id, sbom_result="valid"))
    delete_db.commit()

    SBOMDeleteService(delete_db).permanently_delete_sbom(sbom.id, "Feroze", True)

    assert _count(delete_db, SBOMAnalysisReport) == 0


def test_permanent_delete_removes_validation_sessions_before_events(delete_db: Session) -> None:
    sbom = _sbom(delete_db)
    session = SBOMValidationSession(
        id="session-1",
        imported_sbom_id=sbom.id,
        validation_status="imported",
        created_at="2026-06-21T00:00:00Z",
        updated_at="2026-06-21T00:00:00Z",
        expires_at="2026-06-22T00:00:00Z",
    )
    delete_db.add(session)
    delete_db.flush()
    delete_db.add(
        SBOMValidationSessionEvent(
            session_id=session.id,
            event_type="imported",
            timestamp="2026-06-21T00:00:00Z",
        )
    )
    delete_db.commit()

    SBOMDeleteService(delete_db).permanently_delete_sbom(sbom.id, "Feroze", True)

    assert _count(delete_db, SBOMValidationSessionEvent) == 0
    assert _count(delete_db, SBOMValidationSession) == 0


def test_permanent_delete_removes_vex_documents_and_statements(delete_db: Session) -> None:
    sbom = _sbom(delete_db)
    component = _component(delete_db, sbom.id)
    document = VexDocument(
        sbom_id=sbom.id,
        source_type="uploaded",
        uploaded_at="2026-06-21T00:00:00Z",
        validation_status="accepted",
    )
    delete_db.add(document)
    delete_db.flush()
    delete_db.add(
        VexStatement(
            vex_document_id=document.id,
            sbom_id=sbom.id,
            component_id=component.id,
            vulnerability_id="CVE-2026-0001",
            status="not_affected",
            created_at="2026-06-21T00:00:00Z",
        )
    )
    delete_db.commit()

    SBOMDeleteService(delete_db).permanently_delete_sbom(sbom.id, "Feroze", True)

    assert _count(delete_db, VexStatement) == 0
    assert _count(delete_db, VexDocument) == 0


def test_findings_and_ai_batches_are_deleted_but_shared_remediation_is_retained(
    delete_db: Session,
) -> None:
    project = Projects(project_name="shared project")
    delete_db.add(project)
    delete_db.flush()
    sbom = _sbom(delete_db, projectid=project.id)
    component = _component(delete_db, sbom.id)
    run = _run(delete_db, sbom.id, project.id)
    delete_db.add(
        AnalysisFinding(
            analysis_run_id=run.id,
            component_id=component.id,
            vuln_id="CVE-2026-0001",
        )
    )
    delete_db.add(
        AiFixBatch(
            id="00000000-0000-0000-0000-000000000001",
            run_id=run.id,
            status="completed",
            finding_ids_json=[1],
            provider_name="test",
            created_at="2026-06-21T00:00:00Z",
        )
    )
    remediation = VulnerabilityRemediation(
        project_id=project.id,
        vuln_id="CVE-2026-0001",
        component_name=component.name,
        component_version=component.version,
        status="Open",
        created_on="2026-06-21T00:00:00Z",
        updated_on="2026-06-21T00:00:00Z",
    )
    delete_db.add(remediation)
    delete_db.flush()
    delete_db.add(
        VulnerabilityRemediationAudit(
            remediation_id=remediation.id,
            project_id=project.id,
            vuln_id=remediation.vuln_id,
            component_name=remediation.component_name,
            component_version=remediation.component_version,
            new_status="Open",
            changed_at="2026-06-21T00:00:00Z",
        )
    )
    delete_db.commit()

    SBOMDeleteService(delete_db).permanently_delete_sbom(sbom.id, "Feroze", True)

    assert _count(delete_db, AnalysisFinding) == 0
    assert _count(delete_db, AnalysisRun) == 0
    assert _count(delete_db, AiFixBatch) == 0
    assert _count(delete_db, VulnerabilityRemediation) == 1
    assert _count(delete_db, VulnerabilityRemediationAudit) == 1


def test_permanent_delete_removes_sbom_schedule(delete_db: Session) -> None:
    sbom = _sbom(delete_db)
    delete_db.add(
        AnalysisSchedule(
            scope="SBOM",
            sbom_id=sbom.id,
            cadence="DAILY",
            hour_utc=2,
            timezone="UTC",
            enabled=True,
        )
    )
    delete_db.commit()

    SBOMDeleteService(delete_db).permanently_delete_sbom(sbom.id, "Feroze", True)

    assert _count(delete_db, AnalysisSchedule) == 0


def test_permanent_delete_parent_removes_version_and_conversion_tree(delete_db: Session) -> None:
    parent = _sbom(delete_db, "parent")
    version = _sbom(delete_db, "version", parent_id=parent.id)
    converted = _sbom(delete_db, "converted", source_sbom_id=parent.id)
    delete_db.flush()
    parent.converted_sbom_id = converted.id
    grandchild = _sbom(delete_db, "grandchild", parent_id=version.id)
    parent_id = parent.id
    child_ids = {version.id, converted.id, grandchild.id}
    delete_db.commit()

    impact = SBOMDeleteService(delete_db).get_delete_impact(parent.id)
    result = SBOMDeleteService(delete_db).permanently_delete_sbom(parent.id, "Feroze", True)

    assert set(impact["child_sbom_ids"]) == child_ids
    assert {row["sbom_name"] for row in impact["child_sboms"]} == {
        "version",
        "converted",
        "grandchild",
    }
    assert impact["dependent_counts"]["versions"] == 2
    assert impact["dependent_counts"]["derived_sboms"] == 1
    assert set(result["deleted_sbom_ids"]) == child_ids | {parent_id}
    assert _count(delete_db, SBOMSource) == 0


def test_soft_delete_only_marks_rows_inactive(delete_db: Session) -> None:
    sbom = _sbom(delete_db)
    component = _component(delete_db, sbom.id)
    run = _run(delete_db, sbom.id)
    finding = AnalysisFinding(
        analysis_run_id=run.id,
        component_id=component.id,
        vuln_id="CVE-2026-0001",
    )
    delete_db.add(finding)
    delete_db.commit()

    result = SBOMDeleteService(delete_db).soft_delete_sbom(sbom.id, "Feroze")

    assert result["permanent"] is False
    assert _count(delete_db, SBOMSource) == 1
    assert _count(delete_db, SBOMComponent) == 1
    assert _count(delete_db, AnalysisRun) == 1
    assert _count(delete_db, AnalysisFinding) == 1
    assert SBOMDeleteService(delete_db).get_sbom(sbom.id).is_active is False


def test_delete_impact_reports_all_owned_dependency_counts(delete_db: Session) -> None:
    sbom = _sbom(delete_db)
    component = _component(delete_db, sbom.id)
    run = _run(delete_db, sbom.id)
    delete_db.add(
        AnalysisFinding(
            analysis_run_id=run.id,
            component_id=component.id,
            vuln_id="CVE-2026-0001",
        )
    )
    delete_db.add(SBOMAnalysisReport(sbom_ref_id=sbom.id))
    delete_db.commit()

    impact = SBOMDeleteService(delete_db).get_delete_impact(sbom.id)

    assert impact["can_delete"] is True
    assert impact["requires_confirmation"] is True
    assert impact["dependent_counts"]["components"] == 1
    assert impact["dependent_counts"]["analysis_runs"] == 1
    assert impact["dependent_counts"]["vulnerabilities"] == 1
    assert impact["dependent_counts"]["validation_reports"] == 1
    assert impact["delete_order"][-1] == "sbom_sources"


def test_fk_failure_rolls_back_and_api_returns_409_with_blocker(
    delete_db: Session,
    delete_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sbom = _sbom(delete_db)
    _component(delete_db, sbom.id)
    delete_db.execute(
        text(
            "CREATE TABLE legacy_sbom_child ("
            "id INTEGER PRIMARY KEY, sbom_id INTEGER NOT NULL, "
            "FOREIGN KEY(sbom_id) REFERENCES sbom_source(id))"
        )
    )
    delete_db.execute(
        text("INSERT INTO legacy_sbom_child (sbom_id) VALUES (:sbom_id)"),
        {"sbom_id": sbom.id},
    )
    delete_db.commit()

    original = SBOMDeleteService._unknown_fk_dependencies
    calls = 0

    def _miss_preflight_once(self, target_ids):
        nonlocal calls
        calls += 1
        if calls == 1:
            return {}
        return original(self, target_ids)

    monkeypatch.setattr(SBOMDeleteService, "_unknown_fk_dependencies", _miss_preflight_once)

    response = delete_client.delete(f"/api/sboms/{sbom.id}?user_id=Feroze&confirm=yes&permanent=true")

    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["code"] == "sbom_delete_conflict"
    assert detail["blocking_dependencies"]["legacy_sbom_child"] == 1
    assert SBOMDeleteService(delete_db).get_sbom(sbom.id) is not None
    assert _count(delete_db, SBOMComponent) == 1


def test_no_orphans_remain_and_global_lifecycle_cache_is_preserved(delete_db: Session) -> None:
    sbom = _sbom(delete_db)
    _component(delete_db, sbom.id)
    delete_db.add(
        ComponentLifecycleCache(
            normalized_name="openssl",
            normalized_version="1.0.0",
            checked_at="2026-06-21T00:00:00Z",
            expires_at="2026-06-22T00:00:00Z",
        )
    )
    delete_db.commit()

    SBOMDeleteService(delete_db).permanently_delete_sbom(sbom.id, "Feroze", True)

    assert delete_db.execute(text("PRAGMA foreign_key_check")).all() == []
    assert _count(delete_db, ComponentLifecycleCache) == 1


def test_unconfirmed_permanent_delete_returns_409_with_impact(
    delete_db: Session,
    delete_client: TestClient,
) -> None:
    sbom = _sbom(delete_db)
    _component(delete_db, sbom.id)
    delete_db.commit()

    response = delete_client.delete(f"/api/sboms/{sbom.id}?user_id=Feroze&confirm=no&permanent=true")

    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["delete_impact"]["dependent_counts"]["components"] == 1
    assert SBOMDeleteService(delete_db).get_sbom(sbom.id) is not None


def test_delete_impact_endpoint_returns_full_contract(
    delete_db: Session,
    delete_client: TestClient,
) -> None:
    sbom = _sbom(delete_db)
    _component(delete_db, sbom.id)
    delete_db.commit()

    response = delete_client.get(f"/api/sboms/{sbom.id}/delete-impact")

    assert response.status_code == 200
    body = response.json()
    assert body["can_delete"] is True
    assert body["requires_confirmation"] is True
    assert body["dependent_counts"]["components"] == 1
    assert body["delete_order"][-1] == "sbom_sources"


def test_service_rejects_unmapped_fk_dependencies(delete_db: Session) -> None:
    sbom = _sbom(delete_db)
    delete_db.execute(
        text(
            "CREATE TABLE future_feature ("
            "id INTEGER PRIMARY KEY, source_id INTEGER NOT NULL, "
            "FOREIGN KEY(source_id) REFERENCES sbom_source(id))"
        )
    )
    delete_db.execute(
        text("INSERT INTO future_feature (source_id) VALUES (:sbom_id)"),
        {"sbom_id": sbom.id},
    )
    delete_db.commit()

    impact = SBOMDeleteService(delete_db).get_delete_impact(sbom.id)

    assert impact["can_delete"] is False
    assert impact["table_counts"]["future_feature"] == 1
    with pytest.raises(SBOMDeleteConflict) as raised:
        SBOMDeleteService(delete_db).permanently_delete_sbom(sbom.id, "Feroze", True)
    assert raised.value.blocking_dependencies == {"future_feature": 1}
