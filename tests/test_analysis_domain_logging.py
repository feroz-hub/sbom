"""Domain events preserve workflow results and never attach report/provider payloads."""

import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from app.logger import current_log_context, log_context
from app.models import AnalysisRun, SBOMComponent, SBOMSource
from app.services import analysis_orchestrator as analysis
from app.services import pdf_service
from app.services.analysis_service import mark_analysis_run_failed
from app.services.fda_510k_excel_report_service import Fda510kExcelReportService, Fda510kTemplateMissingError
from app.services.lifecycle.lifecycle_enrichment_service import LifecycleEnrichmentService
from app.services.sbom_vulnerability_excel_report_service import SbomVulnerabilityExcelReportService


def events(caplog):
    return [
        record for record in caplog.records
        if getattr(record, "event", None) in {
            "analysis_queued", "analysis_started", "analysis_completed", "analysis_failed",
            "component_matching_completed", "vulnerability_lookup_started", "vulnerability_lookup_completed",
            "vulnerability_lookup_failed", "lifecycle_check_completed", "report_generation_started",
            "report_generation_completed", "report_generation_failed",
        }
    ]


@pytest.fixture
def session():
    return Mock()


@pytest.fixture
def sbom():
    return SBOMSource(id=12, tenant_id=4, projectid=3, sbom_name="private SBOM name")


@pytest.fixture
def provider_result(monkeypatch):
    findings = [
        {"component_name": "private-package", "component_version": "1", "vuln_id": "CVE-2026-10001", "severity": "HIGH"},
        {"component_name": "private-package", "component_version": "1", "vuln_id": "CVE-2026-10002", "severity": "CRITICAL"},
    ]
    runner = AsyncMock(return_value=(findings, [], []))
    monkeypatch.setattr(analysis, "run_sources_concurrently", runner)
    monkeypatch.setattr(analysis, "build_source_adapters", lambda _sources: [object()])
    monkeypatch.setattr(analysis, "filter_unconfirmed_provider_findings", lambda details, _components: details)
    return runner


def test_analysis_lifecycle_has_one_terminal_event_and_aggregates(session, sbom, provider_result, monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    orchestrator = analysis.AnalysisOrchestrator(session)
    monkeypatch.setattr(orchestrator, "active_run", lambda _id: None)
    component = SBOMComponent(id=9, sbom_id=sbom.id, name="private-package", version="1")
    session.execute.return_value.scalars.return_value = [component]

    def refresh(run):
        run.id, run.tenant_id = 21, sbom.tenant_id

    session.refresh.side_effect = refresh

    def persist(**kwargs):
        run = kwargs["existing_run"]
        run.run_status = kwargs["run_status"]
        for severity in ("critical", "high", "medium", "low"):
            setattr(run, severity + "_count", kwargs["details"][severity])
        return run

    monkeypatch.setattr(analysis, "persist_analysis_run", persist)
    with log_context(request_id="request-1"):
        run, execution = asyncio.run(orchestrator.run(sbom, sources=["OSV"]))
    assert current_log_context().get("analysis_run_id") is None
    assert run.run_status == execution.run_status == "FINDINGS"
    records = events(caplog)
    assert [record.event for record in records] == [
        "component_matching_completed", "analysis_queued", "analysis_started",
        "vulnerability_lookup_started", "vulnerability_lookup_completed", "analysis_completed",
    ]
    for record in records:
        assert record.sbom_id == 12
        assert record.tenant_id == 4
        assert record.request_id == "request-1"
        assert "private" not in record.getMessage()
        assert not {"payload", "findings", "components", "raw_report"}.intersection(record.__dict__)
    for record in records[-2:]:
        assert record.analysis_run_id == 21
        assert record.component_count == 1
        assert record.vulnerable_components == 1  # Two vulnerabilities on one component.
        assert (record.critical, record.high, record.medium, record.low) == (1, 1, 0, 0)
        assert record.duration_ms >= 0


def test_lookup_failure_preserves_exception_and_context(session, provider_result, caplog):
    caplog.set_level(logging.INFO)
    failure = RuntimeError("private provider response")
    provider_result.side_effect = failure
    orchestrator = analysis.AnalysisOrchestrator(session)
    orchestrator._log_ids = {"sbom_id": 12, "analysis_run_id": 21, "tenant_id": 4}
    with log_context(request_id="lookup-1"):
        with pytest.raises(RuntimeError) as caught:
            asyncio.run(orchestrator.execute_providers(components=[], sources=["OSV"]))
        assert current_log_context().get("analysis_run_id") is None
    assert caught.value is failure
    records = events(caplog)
    assert [record.event for record in records] == ["vulnerability_lookup_started", "vulnerability_lookup_failed"]
    failed = records[-1]
    assert failed.exc_info[1] is failure
    assert failed.levelno == logging.ERROR
    assert failed.analysis_run_id == 21
    assert failed.request_id == "lookup-1"
    assert failed.duration_ms >= 0
    assert failed.getMessage() == "vulnerability_lookup_failed"


@pytest.mark.parametrize("has_findings", [True, False])
def test_partial_lookup_retains_best_effort_result(session, provider_result, caplog, has_findings):
    caplog.set_level(logging.INFO)
    findings = provider_result.return_value[0] if has_findings else []
    provider_result.return_value = (findings, [{"source": "NVD", "error": "private response"}], [])
    execution = asyncio.run(analysis.AnalysisOrchestrator(session).execute_providers(components=[{}], sources=["OSV"]))
    assert execution.run_status == ("FINDINGS" if has_findings else "PARTIAL")
    failed = events(caplog)[-1]
    assert failed.event == "vulnerability_lookup_failed"
    assert failed.error_count == 1
    assert failed.levelno == logging.ERROR
    assert not failed.exc_info  # Provider stack is logged at the catch site, not fabricated here.
    assert failed.run_status == execution.run_status
    assert "private response" not in repr(failed.__dict__)


@pytest.mark.parametrize("status", ["FAIL", "ERROR", "FAILED", "INTERRUPTED", "FINDINGS", "PARTIAL", "OK"])
def test_persisted_run_status_selects_terminal_event(session, sbom, monkeypatch, caplog, status):
    caplog.set_level(logging.INFO)
    run = AnalysisRun(
        id=21, sbom_id=12, tenant_id=4, run_status=status, total_components=1,
        critical_count=0, high_count=0, medium_count=0, low_count=0,
    )
    monkeypatch.setattr(analysis, "persist_analysis_run", lambda **_: run)
    execution = SimpleNamespace(details={}, components=[{}], findings=[], run_status=status, source_label="OSV")
    result = analysis.AnalysisOrchestrator(session).persist(
        sbom=sbom, execution=execution, started_on="2026-09-22", duration_ms=42,
        trigger_source="manual", correlation_id="persist-1",
    )
    assert result is run
    record, = events(caplog)
    failed = status in {"FAIL", "ERROR", "FAILED", "INTERRUPTED"}
    assert record.event == ("analysis_failed" if failed else "analysis_completed")
    assert record.levelno == (logging.ERROR if failed else logging.INFO)
    assert not record.exc_info  # A persisted failure status is not an active exception.
    assert record.request_id == "persist-1"
    assert record.duration_ms == 42


def test_supplied_correlation_id_propagates_as_request_id(session, sbom, provider_result, caplog):
    caplog.set_level(logging.INFO)
    component = SBOMComponent(id=9, sbom_id=sbom.id, name="package", version="1")
    session.execute.return_value.scalars.return_value = [component]
    orchestrator = analysis.AnalysisOrchestrator(session)
    components = orchestrator.load_components(sbom, run_id=21, correlation_id="supplied-id")
    asyncio.run(orchestrator.execute_providers(components=components, sources=["OSV"]))
    assert all(record.request_id == "supplied-id" for record in events(caplog))
    assert current_log_context().get("request_id") is None


def test_active_run_does_not_emit_duplicate_lifecycle(session, sbom, monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    orchestrator = analysis.AnalysisOrchestrator(session)
    active = AnalysisRun(id=21, sbom_id=12, run_status="RUNNING")
    monkeypatch.setattr(orchestrator, "active_run", lambda _id: active)
    assert asyncio.run(orchestrator.run(sbom)) == (active, None)
    assert events(caplog) == []


def test_shared_failure_marker_keeps_traceback_for_stream_and_worker(session, caplog):
    caplog.set_level(logging.INFO)
    run = AnalysisRun(id=21, sbom_id=12, tenant_id=4)
    session.get.return_value = run
    failure = RuntimeError("private persistence detail")
    try:
        raise failure
    except RuntimeError:
        result = mark_analysis_run_failed(
            session, run_id=21, error_message="Safe failure", completed_on="2026-09-22", duration_ms=17,
            correlation_id="analysis-1", error_category="analysis_execution_failure",
        )
    assert result is run
    assert run.run_status == "ERROR"
    failed = events(caplog)[-1]
    assert failed.event == "analysis_failed"
    assert failed.exc_info[1] is failure
    assert failed.sbom_id == 12
    assert failed.analysis_run_id == 21
    assert failed.duration_ms == 17
    assert failed.correlation_id == "analysis-1"
    assert failed.request_id == "analysis-1"


def test_lifecycle_batch_logs_aggregates_after_commit(session, sbom, caplog):
    caplog.set_level(logging.INFO)
    session.get.return_value = sbom
    session.execute.return_value.scalars.return_value.all.return_value = []
    summary = LifecycleEnrichmentService(providers=[]).enrich_sbom(session, sbom.id)
    session.commit.assert_called_once()
    completed = events(caplog)[-1]
    assert completed.event == "lifecycle_check_completed"
    assert completed.component_count == summary["total_components"] == 0
    assert completed.provider_lookups == completed.error_count == 0
    assert completed.tenant_id == 4
    assert completed.duration_ms >= 0
    assert "provider_errors" not in completed.__dict__


def test_lifecycle_commit_failure_does_not_log_completion(session, sbom, caplog):
    caplog.set_level(logging.INFO)
    session.get.return_value = sbom
    session.execute.return_value.scalars.return_value.all.return_value = []
    session.commit.side_effect = RuntimeError("commit failed")
    with pytest.raises(RuntimeError):
        LifecycleEnrichmentService(providers=[]).enrich_sbom(session, sbom.id)
    assert events(caplog) == []


def test_individual_lifecycle_check_logs_one_component(session, monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    service = LifecycleEnrichmentService(providers=[])
    result = SimpleNamespace(lifecycle_status="eol")
    monkeypatch.setattr(service, "_enrich_component", lambda *_args, **_kwargs: result)
    component = SBOMComponent(id=9, sbom_id=12, tenant_id=4)
    assert service.enrich_component(session, component) is result
    record = events(caplog)[-1]
    assert record.event == "lifecycle_check_completed"
    assert (record.component_id, record.component_count, record.lifecycle_status) == (9, 1, "eol")
    assert current_log_context().get("sbom_id") is None


def test_pdf_generation_logs_totals_without_title_or_content(session, monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    monkeypatch.setattr(pdf_service, "load_run_cache", lambda *_: {
        "sbom": {"id": 12},
        "summary": {"components": 2, "findings": {"bySeverity": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0}}},
        "components": [{"combined": [{"description": "private vulnerability"}]}, {"combined": []}],
    })
    monkeypatch.setattr(pdf_service, "build_pdf_from_run_bytes", lambda *_args, **_kwargs: b"private PDF")
    with log_context(tenant_id=4):
        assert pdf_service.generate_pdf_report(session, 21, title="private title", filename="private") == (
            b"private PDF", "private.pdf",
        )
    records = events(caplog)
    assert [record.event for record in records] == ["report_generation_started", "report_generation_completed"]
    completed = records[-1]
    assert (completed.component_count, completed.vulnerable_components, completed.critical) == (2, 1, 1)
    assert completed.sbom_id == 12
    assert completed.analysis_run_id == 21
    assert completed.tenant_id == 4
    assert "private" not in repr(completed.__dict__)


@pytest.mark.parametrize("stage", ["cache", "missing", "renderer"])
def test_pdf_failures_keep_original_error_contract(session, monkeypatch, caplog, stage):
    caplog.set_level(logging.INFO)
    failure = RuntimeError("private internal failure")
    monkeypatch.setattr(pdf_service, "load_run_cache", Mock(
        return_value=None if stage == "missing" else {}, side_effect=failure if stage == "cache" else None,
    ))
    monkeypatch.setattr(pdf_service, "rebuild_run_from_db", lambda *_: None)
    monkeypatch.setattr(pdf_service, "build_pdf_from_run_bytes", Mock(side_effect=failure))
    with pytest.raises(RuntimeError if stage == "cache" else ValueError) as caught:
        pdf_service.generate_pdf_report(session, 21)
    if stage == "cache":
        assert caught.value is failure
    elif stage == "missing":
        assert str(caught.value) == "Run 21 not found in cache or database"
    else:
        assert str(caught.value) == "Failed to generate PDF: private internal failure"
    records = events(caplog)
    assert [record.event for record in records] == ["report_generation_started", "report_generation_failed"]
    assert records[-1].exc_info[1] is caught.value
    assert records[-1].duration_ms >= 0
    assert current_log_context().get("analysis_run_id") is None


def test_excel_logs_filtered_row_aggregates(session, sbom, monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    service = SbomVulnerabilityExcelReportService(session)
    rows = [
        {"packageName": "private", "version": "1", "packageUrl": "pkg:npm/private@1", "severity": severity}
        for severity in ("critical", "high")
    ]
    load_rows = Mock(return_value=rows)
    monkeypatch.setattr(service, "_load_rows", load_rows)
    monkeypatch.setattr(service, "_build_workbook", lambda _rows: b"workbook")
    assert service.generate(sbom, include_duplicates=True, package_name="private") == b"workbook"
    load_rows.assert_called_once_with(12, include_duplicates=True, severity=None, package_name="private")
    record = events(caplog)[-1]
    assert record.event == "report_generation_completed"
    assert (record.finding_count, record.vulnerable_components, record.critical, record.high) == (2, 1, 1, 1)
    assert "component_count" not in record.__dict__  # The full inventory is unavailable here.
    assert "private" not in repr(record.__dict__)


def test_fda_report_validation_failure_is_logged_and_unchanged(session, tmp_path, caplog):
    caplog.set_level(logging.INFO)
    service = Fda510kExcelReportService(session, template_path=tmp_path / "missing.xlsx")
    with pytest.raises(Fda510kTemplateMissingError) as caught:
        service.build(3, [], None)
    records = events(caplog)
    assert [record.event for record in records] == ["report_generation_started", "report_generation_failed"]
    assert records[-1].exc_info[1] is caught.value
    assert records[-1].project_id == 3
