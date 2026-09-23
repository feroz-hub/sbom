"""Workflow outcomes, safe fields, and FastAPI decorator compatibility."""

from __future__ import annotations

import inspect
import logging
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from app.core.context import CurrentContext
from app.logger import JsonFormatter, log_context, setup_logging
from app.routers import sbom_upload, sbom_validation_sessions, sboms_crud, vex
from app.services.lifecycle import vex_discovery
from app.services.sbom_workflow_logging import workflow_event
from app.validation.pipeline import _CallableStage, run
from fastapi import HTTPException


@pytest.fixture
def context():
    return CurrentContext(7, "external", "private@example.test", None, 3, None, frozenset(), frozenset())


@pytest.fixture(autouse=True)
def capture_events(caplog):
    setup_logging()
    caplog.set_level(logging.INFO)


def events(caplog):
    return [record.event for record in caplog.records if hasattr(record, "event")]


@pytest.mark.parametrize("outcome", ["clean", "invalid", "exception"])
def test_validation_actual_outcome_and_safe_exception(caplog, outcome):
    def stage(ctx):
        if outcome == "exception":
            raise RuntimeError("private document contents")
        if outcome == "invalid":
            ctx.report.add("SBOM_VAL_E025_SCHEMA_VIOLATION", stage="schema", path="",
                           message="private document contents", remediation="repair")
        return ctx

    with log_context(sbom_id=42):
        report = run(b"private document contents", stages=[_CallableStage("schema", stage)])
    assert report.has_errors() == (outcome != "clean")
    assert events(caplog)[0] == "sbom_validation_started"
    assert events(caplog)[-1] == ("sbom_validation_completed" if outcome == "clean" else "sbom_validation_failed")
    assert caplog.records[-1].sbom_id == 42
    assert "private document contents" not in "\n".join(JsonFormatter().format(r) for r in caplog.records)
    if outcome == "exception":
        record = next(r for r in caplog.records if getattr(r, "event", "") == "sbom_validation_stage_failed")
        assert record.exc_info[0] is RuntimeError


@pytest.mark.parametrize("function", [sbom_validation_sessions.validate_session, sbom_validation_sessions.revalidate_session])
def test_business_validation_failure_returning_200(caplog, monkeypatch, context, function):
    result = {"validation_status": "failed", "latest_error_report": {"error_count": 2, "warning_count": 1}}
    service = Mock()
    service.validate_session.return_value = SimpleNamespace(validation_status="failed", latest_error_report_json={})
    monkeypatch.setattr(sbom_validation_sessions, "ValidationRepairService", Mock(return_value=service))
    monkeypatch.setattr(sbom_validation_sessions, "session_to_dict", lambda _: result)
    monkeypatch.setattr(sbom_validation_sessions.audit_service, "write_audit_log", Mock())
    assert function("session", context=context, db=Mock()) is result
    record = caplog.records[-1]
    assert record.event.endswith("_failed")
    assert record.error_count == 2
    assert record.tenant_id == 3
    assert not record.exc_info
    assert not any(name.endswith("_completed") for name in events(caplog))


def test_pending_delete_never_logs_completion(caplog, monkeypatch, context):
    service = Mock()
    monkeypatch.setattr(sboms_crud, "SBOMDeleteService", Mock(return_value=service))
    result = sboms_crud.delete_sbom(42, confirm="no", permanent=False, context=context, db=Mock())
    assert result["status"] == "pending_confirmation"
    assert events(caplog) == ["sbom_deletion_started", "sbom_deletion_pending_confirmation"]
    service.soft_delete_sbom.assert_not_called()
    service.permanently_delete_sbom.assert_not_called()


@pytest.mark.parametrize("active", [True, False])
def test_restore_outcome(caplog, monkeypatch, context, active):
    db = Mock()
    db.execute.return_value.scalar_one_or_none.return_value = SimpleNamespace(is_active=active)
    monkeypatch.setattr(sboms_crud, "SoftDeleteService", Mock())
    monkeypatch.setattr(sboms_crud.audit_log, "record", Mock())
    result = sboms_crud.restore_sbom(42, context=context, db=db)
    assert result["status"] == ("already_active" if active else "restored")
    assert events(caplog)[-1] == ("sbom_activation_unchanged" if active else "sbom_activated")
    assert db.commit.call_count == (0 if active else 1)


def test_exception_identity_context_reset_and_no_raw_details(caplog, context):
    failure = HTTPException(422, detail="private document contents")

    @workflow_event("sbom_upload")
    def upload(context):
        raise failure

    with pytest.raises(HTTPException) as caught:
        upload(context)
    assert caught.value is failure
    record = caplog.records[-1]
    assert record.event == "sbom_upload_failed"
    assert record.user_id == 7 and record.tenant_id == 3
    assert record.exc_info[1] is failure
    assert "private document contents" not in JsonFormatter().format(record)

    @workflow_event("next")
    def next_workflow():
        return None

    next_workflow()
    assert not hasattr(caplog.records[-1], "sbom_id")
    assert not hasattr(caplog.records[-1], "user_id")


@pytest.mark.parametrize("commit", [True, False])
def test_delete_commit_boundary(caplog, commit):
    @workflow_event("sbom_permanent_deletion", result_kind="delete", completed_event="sbom_deleted")
    def delete(*, commit=True):
        return {"status": "deleted", "sbom_id": 42, "deleted_sbom_ids": [42, 43], "requested_by": "private"}

    delete(commit=commit)
    assert events(caplog)[-1] == ("sbom_deleted" if commit else "sbom_permanent_deletion_prepared")
    assert events(caplog).count("sbom_deleted") == int(commit)
    assert caplog.records[-1].deleted_sbom_count == 2
    assert not hasattr(caplog.records[-1], "requested_by")


def test_discovery_partial_failure_is_not_completion(caplog, monkeypatch):
    db = Mock()
    db.execute.return_value.scalars.return_value.all.return_value = []
    provider = Mock()
    provider.candidates.side_effect = RuntimeError("private URL with credentials")
    monkeypatch.setattr(vex_discovery, "SourceResponseCacheRepository", Mock())
    result = vex_discovery.discover_and_import_vex_documents(db, 42, providers=[provider])
    assert len(result["errors"]) == 1
    assert events(caplog)[-1] == "vex_discovery_partial"
    assert "vex_processing_completed" not in events(caplog)
    assert "private URL" not in JsonFormatter().format(caplog.records[-1])


@pytest.mark.parametrize("func", [sbom_upload.upload_sbom, sboms_crud.create_sbom, sboms_crud.delete_sbom,
                                 sboms_crud.restore_sbom, sbom_validation_sessions.validate_session,
                                 vex.upload_vex_document, vex.patch_vex_override])
def test_decorators_preserve_resolved_fastapi_signature(func):
    assert inspect.signature(func) == inspect.signature(func.__wrapped__, eval_str=True)
    assert inspect.iscoroutinefunction(func) == inspect.iscoroutinefunction(func.__wrapped__)
