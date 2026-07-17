from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import Session, sessionmaker

from app.db import Base, get_db
from app.routers.kev import router as kev_router


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


@pytest.fixture()
def db_session() -> Session:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture()
def kev_client(db_session: Session):
    app = FastAPI()
    app.include_router(kev_router)

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        yield client


def _seed_kev_entry(db: Session) -> None:
    from app.models import KevEntry

    db.add(
        KevEntry(
            cve_id="CVE-2026-45659",
            vendor_project="Acme",
            product="Widget",
            vulnerability_name="Widget overflow",
            date_added="2026-01-01",
            short_description="Short CISA description",
            required_action="Apply vendor patch",
            due_date="2026-02-01",
            known_ransomware_campaign_use="Known",
            notes="CISA notes",
            cwes=["CWE-79"],
            catalog_version="2026.01.01",
            catalog_date_released="2026-01-01T00:00:00+00:00",
            refreshed_at=_now_iso(),
        )
    )
    db.commit()


def test_post_kev_sync_uses_service(kev_client, monkeypatch) -> None:
    from app.routers import kev as kev_router

    calls: list[dict[str, Any]] = []

    def fake_sync_kev(db, *, since, prune_stale, commit):
        calls.append({"since": since, "prune_stale": prune_stale, "commit": commit})
        return {
            "catalog_version": "2026.01.01",
            "catalog_date_released": "2026-01-01T00:00:00+00:00",
            "total_in_feed": 2,
            "filtered_since": since,
            "matched_after_filter": 1,
            "upserted": 1,
            "duration_seconds": 0.01,
        }

    monkeypatch.setattr(kev_router, "sync_kev", fake_sync_kev)

    response = kev_client.post("/api/v1/kev/sync", json={"since": "2026-01-01", "prune_stale": True})

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["ok"] is True
    assert payload["upserted"] == 1
    assert payload["filtered_since"] == "2026-01-01"
    assert calls == [{"since": "2026-01-01", "prune_stale": False, "commit": True}]


def test_post_kev_sync_rejects_invalid_since(kev_client) -> None:
    response = kev_client.post("/api/v1/kev/sync", json={"since": "01/01/2026"})

    assert response.status_code == 422
    assert "YYYY-MM-DD" in response.text


def test_get_kev_by_cve_and_list_filters(kev_client, db_session: Session) -> None:
    _seed_kev_entry(db_session)

    detail = kev_client.get("/api/v1/kev/cve-2026-45659")
    assert detail.status_code == 200, detail.text
    row = detail.json()
    assert row["cve_id"] == "CVE-2026-45659"
    assert row["required_action"] == "Apply vendor patch"
    assert row["known_ransomware_campaign_use"] == "Known"
    assert row["vendor_project"] == "Acme"
    assert row["product"] == "Widget"
    assert row["cwes"] == ["CWE-79"]

    listing = kev_client.get("/api/v1/kev", params={"q": "widget", "ransomware": "true", "since": "2026-01-01"})
    assert listing.status_code == 200, listing.text
    rows = listing.json()
    assert [item["cve_id"] for item in rows] == ["CVE-2026-45659"]

    miss = kev_client.get("/api/v1/kev/CVE-2026-0000")
    assert miss.status_code == 404
