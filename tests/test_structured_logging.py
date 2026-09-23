"""Logging output contracts, request coverage and prefork rollover safety."""

import asyncio
import json
import logging
import multiprocessing
from types import SimpleNamespace

import pytest
from app.logger import ProcessSafeRotatingFileHandler, log_context, log_event, setup_logging
from app.middleware.request_logging import RequestLoggingMiddleware
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.background import BackgroundTask
from starlette.responses import Response, StreamingResponse


@pytest.fixture
def log_file(tmp_path, monkeypatch):
    root = logging.getLogger()
    original = root.handlers[:]
    original_level = root.level
    # Detach our pre-existing handlers so setup doesn't close the saved ones.
    root.handlers = [h for h in original if not getattr(h, "_sbom_owned", False)]
    path = tmp_path / "test.log"
    monkeypatch.setenv("LOG_FILE", str(path))
    monkeypatch.setenv("LOG_MAX_MB", "10")
    monkeypatch.setenv("LOG_BACKUPS", "5")
    setup_logging(level="INFO", fmt="json")
    yield path
    for handler in root.handlers[:]:
        if handler not in original:
            handler.close()
    root.handlers = original
    root.setLevel(original_level)


def entries(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_json_domain_context_and_rotation_settings(log_file, capsys):
    setup_logging(level="INFO", fmt="json")
    logger = logging.getLogger("app.services.example")
    with log_context(tenant_id=7, sbom_id=21, request_id="request-a"):
        log_event(logger, "analysis_completed", analysis_run_id=31, component_count=4)
    log_event(logger, "outside_request")
    records = entries(log_file)
    event = next(r for r in records if r.get("event") == "analysis_completed")
    assert event["tenant_id"] == 7 and event["sbom_id"] == 21
    assert event["analysis_run_id"] == 31 and event["component_count"] == 4
    assert event["module"] == "test_structured_logging" and event["line"] > 0
    assert "project_id" not in event
    assert "request_id" not in records[-1]
    assert '"event": "analysis_completed"' in capsys.readouterr().out
    handler = next(h for h in logging.getLogger().handlers if isinstance(h, ProcessSafeRotatingFileHandler))
    assert handler.maxBytes == 10 * 1024 * 1024 and handler.backupCount == 5
    init = next(r for r in records if r.get("event") == "logging_initialised")
    assert init["console_format"] == init["file_format"] == "json"
    assert init["max_size"] == 10 * 1024 * 1024 and init["backup_count"] == 5


def test_error_trace_and_sensitive_values(log_file, monkeypatch, capsys):
    monkeypatch.setenv("SAMPLE_API_KEY", "known-private-value")
    setup_logging(fmt="text")
    logger = logging.getLogger("app.db")
    try:
        raise RuntimeError("password=hunter-two Authorization: Bearer never-log-me")
    except RuntimeError:
        logger.exception("Raw sensitive exception text", extra={"event": "analysis_failed"})
    logger.info(
        "Authorization: Bearer never-log-me password=hunter-two known-private-value",
        extra={"headers": {"Cookie": "session=unsafe"}, "secret": "hidden", "private_key": "pem-data"},
    )
    output = log_file.read_text() + capsys.readouterr().out
    for forbidden in ("hunter-two", "never-log-me", "known-private-value", "session=unsafe", "pem-data"):
        assert forbidden not in output
    failure = next(r for r in entries(log_file) if r.get("event") == "analysis_failed")
    assert failure["exception_type"] == "RuntimeError"
    assert "Traceback" in failure["exc"] and "test_error_trace_and_sensitive_values" in failure["exc"]
    assert failure["func"] == "test_error_trace_and_sensitive_values"


@pytest.mark.parametrize(
    "name",
    [
        "app.services.example",
        "fastapi",
        "uvicorn",
        "uvicorn.error",
        "uvicorn.access",
        "app.workers.example",
        "celery.task",
        "sqlalchemy.engine",
    ],
)
def test_logger_integration(log_file, name):
    logging.getLogger(name).error("integration diagnostic")
    assert entries(log_file)[-1]["logger"] == name


def test_uvicorn_access_omits_query_string(log_file):
    logging.getLogger("uvicorn.access").info(
        '%s - "%s %s HTTP/%s" %d', "127.0.0.1", "GET", "/health?access_token=unsafe-query", "1.1", 200
    )
    assert "unsafe-query" not in log_file.read_text()


def test_legacy_exception_argument_is_not_serialized(log_file):
    logging.getLogger("app.db").warning("database error: %s", ValueError("unmarked-private-value"))
    assert entries(log_file)[-1]["message"] == "database error: ValueError"
    assert "unmarked-private-value" not in log_file.read_text()


def test_celery_result_payload_is_not_serialized(log_file):
    data = {"id": "task-1", "name": "sbom.analysis", "runtime": 1.5, "return_value": "private-full-result"}
    logging.getLogger("celery.app.trace").info("Task %(name)s succeeded: %(return_value)s", data, extra={"data": data})
    row = entries(log_file)[-1]
    assert row["task_id"] == "task-1" and row["task_name"] == "sbom.analysis"
    assert "private-full-result" not in log_file.read_text()


def test_formatter_failure_does_not_dump_raw_arguments(log_file, monkeypatch):
    import io
    import sys

    diagnostic = io.StringIO()
    monkeypatch.setattr(sys, "__stderr__", diagnostic)
    record = logging.LogRecord("app.example", logging.INFO, __file__, 1,
                               "invalid numeric placeholder %d", ("private-argument",), None)
    for handler in logging.getLogger().handlers:
        if getattr(handler, "_sbom_owned", False):
            handler.handle(record)
    assert "private-argument" not in diagnostic.getvalue()
    assert "logging failed" in diagnostic.getvalue()


def test_async_context_isolated_across_requests(log_file):
    import httpx

    app = make_app()

    async def run_requests():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            responses = await asyncio.gather(*[
                client.get("/ok", headers={"X-Request-ID": f"concurrent-{i}"}) for i in range(12)
            ])
            assert [r.headers["X-Request-ID"] for r in responses] == [f"concurrent-{i}" for i in range(12)]

    asyncio.run(run_requests())
    records = entries(log_file)
    for i in range(12):
        matched = [r for r in records if r.get("request_id") == f"concurrent-{i}"]
        assert [r["event"] for r in matched] == ["domain_inside_request", "http_request_completed"]
    from app.logger import current_log_context
    assert "request_id" not in current_log_context()


def test_provider_exception_stack_is_captured_at_catch_site(log_file):
    from unittest.mock import AsyncMock

    from app.sources.runner import run_sources_concurrently

    source = SimpleNamespace(name="OSV", query=AsyncMock(side_effect=RuntimeError("private-provider-payload")))
    findings, errors, _ = asyncio.run(run_sources_concurrently([source], [], SimpleNamespace()))
    assert findings == [] and errors  # Existing best-effort return is preserved.
    failure = next(r for r in entries(log_file) if r.get("event") == "vulnerability_lookup_failed")
    assert failure["exception_type"] == "RuntimeError" and "_run_one" in failure["exc"]
    assert failure["source"] == "OSV"
    assert "private-provider-payload" not in log_file.read_text()


def make_app():
    app = FastAPI()
    from app.error_handlers import install

    install(app)
    app.add_middleware(RequestLoggingMiddleware)

    @app.get("/ok")
    async def ok():
        log_event(logging.getLogger("app.test"), "domain_inside_request")
        return {"ok": True}

    @app.get("/boom")
    async def boom():
        raise RuntimeError("SECRET-EXCEPTION-TEXT")

    @app.get("/stream")
    async def stream():
        async def body():
            yield b"one"
            await asyncio.sleep(0)
            yield b"two"

        return StreamingResponse(body())

    @app.get("/background")
    async def background():
        def fail():
            raise ValueError("BACKGROUND-SECRET")

        return Response(background=BackgroundTask(fail))

    return app


@pytest.mark.parametrize("headers", [{}, {"X-Request-ID": "client-request-42"}, {"X-Correlation-ID": "legacy-id"}])
def test_http_request_id_and_secrets(log_file, headers):
    response = TestClient(make_app()).get(
        "/ok?access_token=query-secret",
        headers={**headers, "Authorization": "Bearer auth-secret", "Cookie": "session=cookie-secret"},
    )
    request_id = response.headers["X-Request-ID"]
    assert request_id == response.headers["X-Correlation-ID"]
    if headers:
        assert request_id == next(iter(headers.values()))
    event = next(r for r in entries(log_file) if r.get("event") == "http_request_completed")
    assert {k: event[k] for k in ("request_id", "method", "path", "status_code")} == {
        "request_id": request_id,
        "method": "GET",
        "path": "/ok",
        "status_code": 200,
    }
    assert event["duration_ms"] >= 0
    inside = next(r for r in entries(log_file) if r.get("event") == "domain_inside_request")
    assert inside["request_id"] == request_id
    for secret in ("query-secret", "auth-secret", "cookie-secret"):
        assert secret not in log_file.read_text()


def test_http_unhandled_exception_headers_and_trace(log_file):
    response = TestClient(make_app(), raise_server_exceptions=False).get("/boom")
    event = next(r for r in entries(log_file) if r.get("event") == "http_request_completed")
    assert response.status_code == event["status_code"] == 500
    assert response.headers["X-Request-ID"] == event["request_id"] == response.json()["detail"]["correlation_id"]
    assert event["exception_type"] == "RuntimeError" and "in boom" in event["exc"]
    assert "SECRET-EXCEPTION-TEXT" not in log_file.read_text()


def test_stream_and_background_failure_emit_once(log_file):
    client = TestClient(make_app(), raise_server_exceptions=False)
    assert client.get("/stream").content == b"onetwo"
    assert client.get("/background").status_code == 200
    records = entries(log_file)
    assert len([r for r in records if r.get("event") == "http_request_completed"]) == 2
    failure = next(r for r in records if r.get("event") == "http_background_task_failed")
    assert failure["exception_type"] == "ValueError"
    assert "BACKGROUND-SECRET" not in log_file.read_text()


def test_early_body_rejection_logged(log_file):
    from app.middleware.max_body import MaxBodySizeMiddleware

    app = make_app()
    app.add_middleware(MaxBodySizeMiddleware, max_bytes=1)
    app.add_middleware(RequestLoggingMiddleware)
    response = TestClient(app).post("/ok", content=b"too large")
    assert response.status_code == 413 and response.headers["X-Request-ID"]
    assert entries(log_file)[-1]["status_code"] == 413


def _write_child(path, worker):
    setup_logging(log_file=path, max_bytes=1600, backup_count=100)
    for index in range(15):
        log_event(logging.getLogger("app.worker"), "parallel_write", worker=worker, index=index)


def test_prefork_rotation_retains_all_records(log_file, monkeypatch):
    monkeypatch.setenv("LOG_BACKUPS", "100")
    ctx = multiprocessing.get_context("fork")
    children = [ctx.Process(target=_write_child, args=(str(log_file), i)) for i in range(3)]
    for child in children:
        child.start()
    for child in children:
        child.join(15)
        assert child.exitcode == 0
    files = [p for p in log_file.parent.glob("test.log*") if not p.name.endswith(".lock")]
    assert len(files) > 1
    records = [r for p in files for r in entries(p) if r.get("event") == "parallel_write"]
    assert len(records) == 45
    assert {(r["worker"], r["index"]) for r in records} == {(w, i) for w in range(3) for i in range(15)}


def test_celery_context_and_configuration(log_file):
    from app.workers.celery_app import (
        bind_task_logging_context,
        configure_celery_logging,
        propagate_logging_context,
        reset_task_logging_context,
    )

    headers = {}
    with log_context(request_id="from-http", sbom_id=42):
        propagate_logging_context(headers=headers)
    task = SimpleNamespace(request=SimpleNamespace(headers=headers))
    configure_celery_logging(loglevel=logging.INFO)
    bind_task_logging_context(task=task)
    log_event(logging.getLogger("celery.task"), "worker_event")
    reset_task_logging_context(task=task)
    log_event(logging.getLogger("celery.beat"), "beat_event")
    records = entries(log_file)
    event = next(r for r in records if r.get("event") == "worker_event")
    assert event["request_id"] == "from-http" and event["sbom_id"] == 42
    assert "request_id" not in records[-1]


def test_reconfiguration_preserves_foreign_handlers(log_file):
    root = logging.getLogger()
    sentinel = logging.NullHandler()
    root.addHandler(sentinel)
    try:
        setup_logging()
        setup_logging()
        assert sentinel in root.handlers
        assert len([h for h in root.handlers if getattr(h, "_sbom_owned", False)]) == 2
    finally:
        root.removeHandler(sentinel)


def test_reconfiguration_restores_preexisting_disabled_descendants(log_file):
    for name in ("app.services.imported_early", "sbom.access", "celery.app.trace"):
        logger = logging.getLogger(name)
        logger.disabled = True
        logger.propagate = False
    setup_logging()
    for name in ("app.services.imported_early", "sbom.access", "celery.app.trace"):
        logging.getLogger(name).info("after framework reconfiguration")
    assert {row["logger"] for row in entries(log_file)[-3:]} == {
        "app.services.imported_early", "sbom.access", "celery.app.trace"}
