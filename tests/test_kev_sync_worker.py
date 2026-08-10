from __future__ import annotations

from typing import Any


class FakeSession:
    def __init__(self) -> None:
        self.closed = False
        self.rolled_back = False

    def rollback(self) -> None:
        self.rolled_back = True

    def close(self) -> None:
        self.closed = True


def test_kev_sync_task_registered_on_celery_app() -> None:
    import app.workers.kev_sync  # noqa: F401
    from app.workers.celery_app import celery_app

    assert "kev.sync" in celery_app.tasks
    assert "kev-sync-daily" in celery_app.conf.beat_schedule
    entry = celery_app.conf.beat_schedule["kev-sync-daily"]
    assert entry["task"] == "kev.sync"
    assert str(entry["schedule"]) == "<crontab: 10 3 * * * (m/h/dM/MY/d)>"


def test_sync_kev_catalog_calls_service_with_existing_session(monkeypatch) -> None:
    from app import db as db_module
    from app import settings as settings_module
    from app.services import kev_service
    from app.workers.kev_sync import sync_kev_catalog

    session = FakeSession()
    calls: list[dict[str, Any]] = []

    class FakeSettings:
        kev_since_date = ""

    def fake_sync_kev(db, *, since, prune_stale, commit):
        calls.append(
            {
                "db": db,
                "since": since,
                "prune_stale": prune_stale,
                "commit": commit,
            }
        )
        return {
            "upserted": 2,
            "total_in_feed": 3,
            "filtered_since": None,
            "duration_seconds": 0.01,
        }

    monkeypatch.setattr(db_module, "SessionLocal", lambda: session)
    monkeypatch.setattr(kev_service, "sync_kev", fake_sync_kev)
    monkeypatch.setattr(settings_module, "get_settings", lambda: FakeSettings())

    result = sync_kev_catalog.run(since=None, prune_stale=True)

    assert result["ok"] is True
    assert result["upserted"] == 2
    assert calls == [
        {
            "db": session,
            "since": None,
            "prune_stale": True,
            "commit": True,
        }
    ]
    assert session.closed is True
    assert session.rolled_back is False


def test_sync_kev_catalog_rolls_back_on_failure(monkeypatch) -> None:
    from app import db as db_module
    from app import settings as settings_module
    from app.services import kev_service
    from app.workers.kev_sync import sync_kev_catalog

    session = FakeSession()

    class FakeSettings:
        kev_since_date = "2026-01-01"

    def fake_sync_kev(db, *, since, prune_stale, commit):
        raise RuntimeError("feed unavailable")

    monkeypatch.setattr(db_module, "SessionLocal", lambda: session)
    monkeypatch.setattr(kev_service, "sync_kev", fake_sync_kev)
    monkeypatch.setattr(settings_module, "get_settings", lambda: FakeSettings())

    result = sync_kev_catalog.run(since=None, prune_stale=True)

    assert result["ok"] is False
    assert "feed unavailable" in result["error"]
    assert session.rolled_back is True
    assert session.closed is True
