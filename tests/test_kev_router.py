from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.models import KevEntry
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


def _entry(
    cve_id: str,
    *,
    vendor: str,
    product: str,
    name: str,
    date_added: str,
    due_date: str,
    ransomware: str | None,
    cwes: list[str],
    catalog_version: str,
    description: str = "CISA short description",
    action: str = "Apply vendor patch",
    notes: str = "CISA notes",
) -> KevEntry:
    return KevEntry(
        cve_id=cve_id,
        vendor_project=vendor,
        product=product,
        vulnerability_name=name,
        date_added=date_added,
        short_description=description,
        required_action=action,
        due_date=due_date,
        known_ransomware_campaign_use=ransomware,
        notes=notes,
        cwes=cwes,
        catalog_version=catalog_version,
        catalog_date_released=f"{date_added}T00:00:00+00:00",
        refreshed_at=_now_iso(),
        first_seen_at=f"{date_added}T00:00:00+00:00",
        updated_at=f"{date_added}T12:00:00+00:00",
    )


def _seed_catalog(db: Session) -> None:
    db.add_all(
        [
            _entry(
                "CVE-2021-44228",
                vendor="Apache",
                product="Log4j2",
                name="Log4j remote code execution",
                date_added="2021-12-10",
                due_date="2021-12-24",
                ransomware="Known",
                cwes=["CWE-502", "CWE-20"],
                catalog_version="2026.07.15",
                description="JNDI remote code execution",
                action="Upgrade Log4j immediately",
                notes="Prioritize internet-facing Apache systems",
            ),
            _entry(
                "CVE-2022-0001",
                vendor="Apache",
                product="Tomcat",
                name="Tomcat request smuggling",
                date_added="2022-03-01",
                due_date="2022-03-20",
                ransomware="Unknown",
                cwes=["CWE-444"],
                catalog_version="2026.07.15",
            ),
            _entry(
                "CVE-2023-0002",
                vendor="Cisco",
                product="IOS XE",
                name="Cisco command injection",
                date_added="2023-06-15",
                due_date="2023-07-01",
                ransomware="Not Known",
                cwes=["CWE-78"],
                catalog_version="2026.07.16",
            ),
            _entry(
                "CVE-2024-0003",
                vendor="Microsoft",
                product="Windows",
                name="Windows privilege escalation",
                date_added="2024-02-10",
                due_date="2024-03-01",
                ransomware=None,
                cwes=["CWE-269", "CWE-787"],
                catalog_version="2026.07.17",
            ),
            _entry(
                "CVE-2025-0004",
                vendor="Apple",
                product="WebKit",
                name="WebKit memory corruption",
                date_added="2025-05-05",
                due_date="2025-05-26",
                ransomware="",
                cwes=["CWE-787"],
                catalog_version="2026.07.17",
            ),
        ]
    )
    db.commit()


def _list(client: TestClient, **params: Any) -> dict[str, Any]:
    response = client.get("/api/v1/kev", params=params)
    assert response.status_code == 200, response.text
    return response.json()


def test_post_kev_sync_uses_service(kev_client, monkeypatch) -> None:
    from app.routers import kev as kev_router_module

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

    monkeypatch.setattr(kev_router_module, "sync_kev", fake_sync_kev)
    response = kev_client.post(
        "/api/v1/kev/sync",
        json={"since": "2026-01-01", "prune_stale": True},
    )
    assert response.status_code == 200, response.text
    assert response.json()["upserted"] == 1
    assert calls == [{"since": "2026-01-01", "prune_stale": False, "commit": True}]


def test_post_kev_sync_rejects_invalid_since(kev_client) -> None:
    response = kev_client.post("/api/v1/kev/sync", json={"since": "01/01/2026"})
    assert response.status_code == 422
    assert "YYYY-MM-DD" in response.text


def test_get_kev_detail(kev_client, db_session: Session) -> None:
    _seed_catalog(db_session)
    response = kev_client.get("/api/v1/kev/cve-2021-44228")
    assert response.status_code == 200, response.text
    assert response.json()["cve_id"] == "CVE-2021-44228"
    assert response.json()["cwes"] == ["CWE-502", "CWE-20"]
    assert kev_client.get("/api/v1/kev/CVE-2099-0000").status_code == 404


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("CVE-2021-44228", "CVE-2021-44228"),
        ("Apache", "CVE-2021-44228"),
        ("Log4j2", "CVE-2021-44228"),
        ("remote code", "CVE-2021-44228"),
        ("JNDI", "CVE-2021-44228"),
        ("Upgrade Log4j", "CVE-2021-44228"),
        ("internet-facing", "CVE-2021-44228"),
        ("CWE-502", "CVE-2021-44228"),
    ],
)
def test_search_uses_or_across_supported_fields(
    kev_client, db_session: Session, query: str, expected: str
) -> None:
    _seed_catalog(db_session)
    payload = _list(kev_client, q=f"  {query}  ")
    assert expected in {item["cve_id"] for item in payload["items"]}


def test_vendor_product_and_combined_filters_use_and(kev_client, db_session: Session) -> None:
    _seed_catalog(db_session)
    assert _list(kev_client, vendor="apache")["total"] == 2
    assert [item["cve_id"] for item in _list(kev_client, product="LOG4J2")["items"]] == [
        "CVE-2021-44228"
    ]
    combined = _list(
        kev_client,
        vendor="Apache",
        product="Log4j2",
        ransomware="known",
        date_added_from="2021-01-01",
        cwe="CWE-502",
    )
    assert combined["total"] == 1
    assert combined["items"][0]["cve_id"] == "CVE-2021-44228"


def test_ransomware_filters_are_exact(kev_client, db_session: Session) -> None:
    _seed_catalog(db_session)
    known = _list(kev_client, ransomware="known")
    assert [item["cve_id"] for item in known["items"]] == ["CVE-2021-44228"]
    not_known = _list(kev_client, ransomware="not-known")
    assert not_known["total"] == 4
    assert all(item["known_ransomware_campaign_use"] != "Known" for item in not_known["items"])
    assert _list(kev_client, ransomware="true")["total"] == 1
    assert _list(kev_client, ransomware="false")["total"] == 4


def test_date_added_and_due_date_ranges_are_inclusive(kev_client, db_session: Session) -> None:
    _seed_catalog(db_session)
    added = _list(
        kev_client,
        date_added_from="2022-03-01",
        date_added_to="2024-02-10",
        sort_by="date_added",
        sort_order="asc",
    )
    assert [item["cve_id"] for item in added["items"]] == [
        "CVE-2022-0001",
        "CVE-2023-0002",
        "CVE-2024-0003",
    ]
    due = _list(kev_client, due_date_from="2023-07-01", due_date_to="2024-03-01")
    assert {item["cve_id"] for item in due["items"]} == {"CVE-2023-0002", "CVE-2024-0003"}
    assert _list(kev_client, since="2024-02-10")["total"] == 2


@pytest.mark.parametrize(
    "params",
    [
        {"date_added_from": "2025-01-01", "date_added_to": "2024-01-01"},
        {"due_date_from": "2025-01-01", "due_date_to": "2024-01-01"},
        {"date_added_from": "not-a-date"},
    ],
)
def test_invalid_date_ranges_are_rejected(kev_client, params: dict[str, str]) -> None:
    assert kev_client.get("/api/v1/kev", params=params).status_code == 422


def test_catalog_version_and_cwe_filters(kev_client, db_session: Session) -> None:
    _seed_catalog(db_session)
    assert _list(kev_client, catalog_version="2026.07.17")["total"] == 2
    cwe = _list(kev_client, cwe="cwe-787")
    assert {item["cve_id"] for item in cwe["items"]} == {"CVE-2024-0003", "CVE-2025-0004"}


def test_sorting_allowlist_and_directions(kev_client, db_session: Session) -> None:
    _seed_catalog(db_session)
    asc = _list(kev_client, sort_by="vendor_project", sort_order="asc")
    desc = _list(kev_client, sort_by="vendor_project", sort_order="desc")
    assert [item["vendor_project"] for item in asc["items"]] == [
        "Apache", "Apache", "Apple", "Cisco", "Microsoft"
    ]
    assert [item["vendor_project"] for item in desc["items"]] == [
        "Microsoft", "Cisco", "Apple", "Apache", "Apache"
    ]
    assert kev_client.get("/api/v1/kev", params={"sort_by": "drop table"}).status_code == 422
    assert kev_client.get("/api/v1/kev", params={"sort_order": "sideways"}).status_code == 422


def test_filtered_count_and_pagination_apply_after_filters(kev_client, db_session: Session) -> None:
    _seed_catalog(db_session)
    first = _list(
        kev_client,
        vendor="Apache",
        sort_by="cve_id",
        sort_order="asc",
        limit=1,
        offset=0,
    )
    second = _list(
        kev_client,
        vendor="Apache",
        sort_by="cve_id",
        sort_order="asc",
        limit=1,
        offset=1,
    )
    assert first["total"] == second["total"] == 2
    assert first["limit"] == 1 and second["offset"] == 1
    assert first["items"][0]["cve_id"] != second["items"][0]["cve_id"]


def test_filter_options_are_distinct_sorted_and_vendor_aware(kev_client, db_session: Session) -> None:
    _seed_catalog(db_session)
    response = kev_client.get("/api/v1/kev/filter-options")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["vendors"] == ["Apache", "Apple", "Cisco", "Microsoft"]
    assert payload["catalog_versions"] == ["2026.07.15", "2026.07.16", "2026.07.17"]
    assert payload["cwes"] == ["CWE-20", "CWE-269", "CWE-444", "CWE-502", "CWE-78", "CWE-787"]
    assert payload["date_added_min"] == "2021-12-10"
    assert payload["date_added_max"] == "2025-05-05"

    apache = kev_client.get("/api/v1/kev/filter-options", params={"vendor": "apache"}).json()
    assert apache["products"] == ["Log4j2", "Tomcat"]


def test_router_dependencies_can_preserve_authorization(db_session: Session) -> None:
    app = FastAPI()

    def deny_access() -> None:
        raise HTTPException(status_code=401, detail="authentication required")

    app.include_router(kev_router, dependencies=[Depends(deny_access)])
    with TestClient(app) as client:
        response = client.get("/api/v1/kev")
    assert response.status_code == 401
