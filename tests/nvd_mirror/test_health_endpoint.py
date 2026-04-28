"""Phase 6 — /health endpoint extended with nvd_mirror block."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Iterator

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Module-scope imports — done HERE rather than inside fixtures because
# `import app.nvd_mirror.db.models` would rebind `app` in the fixture's
# local namespace and shadow the FastAPI ``app`` fixture parameter.
import app.db as _app_db
import app.nvd_mirror.db.models  # noqa: F401 — register tables on Base
from app.db import Base


@pytest.fixture()
def fernet_key(monkeypatch: pytest.MonkeyPatch) -> str:
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("NVD_MIRROR_FERNET_KEY", key)
    return key


@pytest.fixture()
def health_client(
    app, fernet_key: str, monkeypatch: pytest.MonkeyPatch
) -> Iterator[TestClient]:
    """TestClient with an isolated DB so prior tests cannot pollute the
    nvd_settings row that the /health endpoint reads.

    Other tests in the suite (test_api.py, test_facade_integration.py)
    write to the conftest's session-scoped tmp DB; this fixture rebinds
    SessionLocal for the duration of each test so the health response
    reflects a known-empty state.
    """
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    Path(path).unlink(missing_ok=True)

    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    monkeypatch.setattr(_app_db, "SessionLocal", SessionLocal)
    monkeypatch.setattr(_app_db, "engine", engine)

    try:
        with TestClient(app) as c:
            yield c
    finally:
        engine.dispose()
        Path(path).unlink(missing_ok=True)


def test_health_returns_status_ok_and_mirror_block(health_client: TestClient) -> None:
    r = health_client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "nvd_mirror" in body
    block = body["nvd_mirror"]
    # Fresh test DB — mirror is disabled by default and never run.
    assert block["enabled"] is False
    assert block["last_success_at"] is None
    assert block["watermark"] is None
    assert block["stale"] is True  # never synced → stale
    assert "counters" in block


def test_health_does_not_expose_api_key_plaintext(health_client: TestClient) -> None:
    """Hardening: /health must not leak the encrypted ciphertext or any plaintext."""
    r = health_client.get("/health")
    body_text = r.text
    # Sanity probes.
    assert "api_key" not in body_text
    assert "ciphertext" not in body_text


def test_health_includes_counter_snapshot(health_client: TestClient) -> None:
    """Counters from observability module are surfaced."""
    from app.nvd_mirror.observability import mirror_counters

    mirror_counters.reset()
    mirror_counters.increment("nvd.windows.success", 7)
    mirror_counters.increment("nvd.api.429_count", 2)

    r = health_client.get("/health")
    counters = r.json()["nvd_mirror"]["counters"]
    assert counters.get("nvd.windows.success") == 7
    assert counters.get("nvd.api.429_count") == 2
    mirror_counters.reset()


def test_health_survives_db_failure(
    health_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """/health must NEVER 500 just because the mirror sub-system is broken."""

    def _explode(*_a, **_kw):
        raise RuntimeError("simulated DB failure")

    # Make the settings_repo.load() raise.
    from app.nvd_mirror.adapters import settings_repository

    monkeypatch.setattr(
        settings_repository.SqlAlchemySettingsRepository, "load", _explode
    )

    r = health_client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    # Mirror block degrades gracefully.
    assert body["nvd_mirror"]["available"] is False
    assert "simulated DB failure" in body["nvd_mirror"]["error"]


def test_root_endpoint_unaffected(health_client: TestClient) -> None:
    """/ is the sibling unauthenticated route — make sure we didn't break it."""
    r = health_client.get("/")
    assert r.status_code == 200
    body = r.json()
    assert body["service"] == "sbom-analyzer-api"
    assert body["health_url"] == "/health"
