"""Phase 4 — admin router via FastAPI TestClient.

The router lives at ``/admin/nvd-mirror/*`` and is wired into the app
in ``app/main.py``. Tests use the session-scoped ``app`` and ``client``
fixtures from ``tests/conftest.py``. We override the secrets dependency
with a fixed Fernet key so the tests don't depend on env vars.
"""

from __future__ import annotations

import os
from typing import Iterator
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from app.nvd_mirror.adapters.secrets import FernetSecretsAdapter
from app.nvd_mirror.api import get_secrets


@pytest.fixture()
def fernet_key(monkeypatch: pytest.MonkeyPatch) -> str:
    """Provide a Fernet key via env so the real ``get_secrets`` builds a real adapter."""
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("NVD_MIRROR_FERNET_KEY", key)
    return key


@pytest.fixture()
def api_client(app, fernet_key: str) -> Iterator[TestClient]:
    """TestClient with secrets dependency overridden to use the fixture key.

    Note: ``get_secrets`` reads the env var on each request, so as long
    as ``NVD_MIRROR_FERNET_KEY`` is set, no override is strictly needed.
    But pinning via dependency_overrides makes the test deterministic
    even if other tests leak env state.
    """
    app.dependency_overrides[get_secrets] = lambda: FernetSecretsAdapter(fernet_key)
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.pop(get_secrets, None)


# --- GET /settings --------------------------------------------------------


def test_get_settings_returns_defaults_on_first_call(api_client: TestClient) -> None:
    r = api_client.get("/admin/nvd-mirror/settings")
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is False
    assert body["api_endpoint"].startswith("https://services.nvd.nist.gov")
    assert body["api_key_present"] is False
    assert body["api_key_masked"] == "(not set)"
    assert body["window_days"] == 119
    assert body["last_modified_utc"] is None


def test_get_settings_never_returns_plaintext_key(api_client: TestClient) -> None:
    """Set a key; GET masks it."""
    api_client.put(
        "/admin/nvd-mirror/settings",
        json={"enabled": True, "api_key": "super-secret-1234567890abcdef"},
    )
    r = api_client.get("/admin/nvd-mirror/settings")
    body = r.json()
    assert "super-secret-1234567890abcdef" not in r.text
    assert body["api_key_present"] is True
    # Mask shows first 3 + last 3.
    assert body["api_key_masked"] == "sup...def"


# --- PUT /settings --------------------------------------------------------


def test_put_settings_partial_update_preserves_unspecified_fields(
    api_client: TestClient,
) -> None:
    api_client.put(
        "/admin/nvd-mirror/settings",
        json={
            "enabled": True,
            "page_size": 1000,
            "api_key": "key-v1-1234567890",
        },
    )
    # Now update only enabled — page_size and api_key must persist.
    r = api_client.put(
        "/admin/nvd-mirror/settings", json={"enabled": False}
    )
    body = r.json()
    assert body["enabled"] is False
    assert body["page_size"] == 1000
    assert body["api_key_present"] is True


def test_put_settings_clear_api_key(api_client: TestClient) -> None:
    api_client.put(
        "/admin/nvd-mirror/settings",
        json={"api_key": "key-to-clear-1234567"},
    )
    r = api_client.put(
        "/admin/nvd-mirror/settings", json={"clear_api_key": True}
    )
    body = r.json()
    assert body["api_key_present"] is False
    assert body["api_key_masked"] == "(not set)"


def test_put_settings_validates_window_days_range(api_client: TestClient) -> None:
    r = api_client.put(
        "/admin/nvd-mirror/settings", json={"window_days": 200}
    )
    assert r.status_code == 422


def test_put_settings_validates_page_size_range(api_client: TestClient) -> None:
    r = api_client.put(
        "/admin/nvd-mirror/settings", json={"page_size": 5000}
    )
    assert r.status_code == 422


def test_put_settings_rejects_unknown_fields(api_client: TestClient) -> None:
    r = api_client.put(
        "/admin/nvd-mirror/settings", json={"some_unknown_field": "x"}
    )
    assert r.status_code == 422


def test_put_settings_does_not_advance_watermark(api_client: TestClient) -> None:
    """Saving settings must never move last_modified_utc backward."""
    # First, simulate a successful sync by directly setting the watermark
    # via a separate request flow — there's no admin API for this, so we
    # exercise the invariant via the settings repo on the same DB.
    from app.db import SessionLocal
    from app.nvd_mirror.adapters.secrets import FernetSecretsAdapter
    from app.nvd_mirror.adapters.settings_repository import (
        SqlAlchemySettingsRepository,
    )
    from datetime import datetime, timezone

    key = os.environ["NVD_MIRROR_FERNET_KEY"]
    s = SessionLocal()
    try:
        repo = SqlAlchemySettingsRepository(s, FernetSecretsAdapter(key))
        target = datetime(2024, 6, 1, tzinfo=timezone.utc)
        repo.advance_watermark(
            last_modified_utc=target, last_successful_sync_at=target
        )
        s.commit()
    finally:
        s.close()

    # Now PUT settings — watermark must remain.
    r = api_client.put("/admin/nvd-mirror/settings", json={"enabled": True})
    body = r.json()
    assert body["last_modified_utc"] is not None
    assert "2024-06-01" in body["last_modified_utc"]


# --- POST /sync -----------------------------------------------------------


class _FakeTask:
    """Stand-in for the Celery task proxy so tests don't need a broker."""

    def __init__(self, *, raises: Exception | None = None, task_id: str = "fake") -> None:
        self._raises = raises
        self._task_id = task_id

    def delay(self, *_args, **_kwargs):
        if self._raises:
            raise self._raises

        class _Result:
            id = self._task_id

        return _Result()


def test_post_sync_enqueues_task(api_client: TestClient) -> None:
    """Replace the celery-proxy task with a fake that has a .delay()."""
    fake = _FakeTask(task_id="fake-task-id-42")
    with patch("app.nvd_mirror.tasks.mirror_nvd", fake):
        r = api_client.post("/admin/nvd-mirror/sync")
    assert r.status_code == 202
    body = r.json()
    assert body == {"task_id": "fake-task-id-42", "status": "queued"}


def test_post_sync_returns_503_when_broker_down(api_client: TestClient) -> None:
    fake = _FakeTask(raises=ConnectionError("broker unreachable"))
    with patch("app.nvd_mirror.tasks.mirror_nvd", fake):
        r = api_client.post("/admin/nvd-mirror/sync")
    assert r.status_code == 503
    assert "broker unreachable" in r.json()["detail"]


# --- GET /sync/status -----------------------------------------------------


def test_get_sync_status_initially_empty(api_client: TestClient) -> None:
    r = api_client.get("/admin/nvd-mirror/sync/status")
    assert r.status_code == 200
    assert r.json() == []


def test_get_sync_status_returns_completed_runs(api_client: TestClient) -> None:
    # Seed a few runs directly via the repository.
    from app.db import SessionLocal
    from app.nvd_mirror.adapters.sync_run_repository import (
        SqlAlchemySyncRunRepository,
    )
    from app.nvd_mirror.domain.models import MirrorWindow
    from datetime import datetime, timezone

    s = SessionLocal()
    try:
        repo = SqlAlchemySyncRunRepository(s)
        rid = repo.begin(
            run_kind="bootstrap",
            window=MirrorWindow(
                start=datetime(2024, 4, 1, tzinfo=timezone.utc),
                end=datetime(2024, 4, 2, tzinfo=timezone.utc),
            ),
        )
        repo.finish(rid, status="success", upserts=42, error=None)
        s.commit()
    finally:
        s.close()

    r = api_client.get("/admin/nvd-mirror/sync/status")
    body = r.json()
    assert len(body) >= 1
    latest = body[0]
    assert latest["run_kind"] == "bootstrap"
    assert latest["status"] == "success"
    assert latest["upserted_count"] == 42


# --- POST /watermark/reset ------------------------------------------------


def test_watermark_reset_clears_last_modified_utc(api_client: TestClient) -> None:
    from app.db import SessionLocal
    from app.nvd_mirror.adapters.secrets import FernetSecretsAdapter
    from app.nvd_mirror.adapters.settings_repository import (
        SqlAlchemySettingsRepository,
    )
    from datetime import datetime, timezone

    key = os.environ["NVD_MIRROR_FERNET_KEY"]
    s = SessionLocal()
    try:
        repo = SqlAlchemySettingsRepository(s, FernetSecretsAdapter(key))
        target = datetime(2024, 6, 1, tzinfo=timezone.utc)
        repo.advance_watermark(
            last_modified_utc=target, last_successful_sync_at=target
        )
        s.commit()
    finally:
        s.close()

    r = api_client.post("/admin/nvd-mirror/watermark/reset")
    assert r.status_code == 200
    assert r.json()["last_modified_utc"] is None
    # last_successful_sync_at preserved (so freshness can still report it).
    assert r.json()["last_successful_sync_at"] is not None


# --- mask helper ----------------------------------------------------------


def test_mask_helper_directly() -> None:
    from app.nvd_mirror.schemas import mask_api_key

    assert mask_api_key(None) == "(not set)"
    assert mask_api_key("") == "(not set)"
    assert mask_api_key("12345678") == "***"  # <= 8 chars
    assert mask_api_key("123456789") == "123...789"  # > 8 chars
    assert mask_api_key("super-long-api-key-here") == "sup...ere"
