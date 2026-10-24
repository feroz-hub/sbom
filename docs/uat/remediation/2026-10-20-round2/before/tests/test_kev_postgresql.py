from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest
from app.models import KevEntry
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

pytestmark = pytest.mark.postgres


@pytest.fixture(scope="module")
def postgres_url() -> str:
    value = (os.getenv("TEST_POSTGRES_DATABASE_URL") or "").strip()
    if not value:
        pytest.skip("TEST_POSTGRES_DATABASE_URL is not configured")
    if "test" not in (make_url(value).database or "").lower():
        pytest.fail("TEST_POSTGRES_DATABASE_URL must use a disposable database containing 'test'")
    return value


def _entry(cve_id: str, vendor: str | None, product: str | None) -> KevEntry:
    now = datetime.now(UTC).replace(microsecond=0).isoformat()
    return KevEntry(
        cve_id=cve_id,
        vendor_project=vendor,
        product=product,
        vulnerability_name="PostgreSQL filter-options regression",
        date_added="2026-07-23",
        due_date="2026-08-13",
        cwes=["CWE-79", "CWE-79", "", "   "],
        catalog_version="2026.07.23",
        refreshed_at=now,
        first_seen_at=now,
        updated_at=now,
    )


def test_filter_options_distinct_ordering_executes_on_postgresql(
    app,
    postgres_url: str,
) -> None:
    engine = create_engine(postgres_url)
    try:
        with Session(engine) as session:
            session.add_all(
                [
                    _entry("CVE-2030-0001", "Microsoft", "Windows"),
                    _entry("CVE-2030-0002", "apple", "WebKit"),
                    _entry("CVE-2030-0003", "Apple", "WebKit"),
                    _entry("CVE-2030-0004", "  Google", "Search"),
                    _entry("CVE-2030-0005", "", ""),
                    _entry("CVE-2030-0006", "   ", "   "),
                    _entry("CVE-2030-0007", None, None),
                    _entry("CVE-2030-0008", "Microsoft", "Windows"),
                ]
            )
            session.commit()

        with TestClient(app) as client:
            response = client.get("/api/v1/kev/filter-options")
            repeated_response = client.get("/api/v1/kev/filter-options")

        assert response.status_code == 200, response.text
        assert repeated_response.status_code == 200, repeated_response.text
        payload = response.json()
        assert set(payload) == {
            "vendors",
            "products",
            "catalog_versions",
            "cwes",
            "date_added_min",
            "date_added_max",
        }
        vendors = payload["vendors"]
        assert set(vendors) == {"  Google", "Apple", "apple", "Microsoft"}
        assert [vendor.lower() for vendor in vendors if vendor != "  Google"] == [
            "apple",
            "apple",
            "microsoft",
        ]
        assert repeated_response.json()["vendors"] == vendors
        assert payload["products"] == ["Search", "WebKit", "Windows"]
        assert payload["catalog_versions"] == ["2026.07.23"]
        assert payload["cwes"] == ["CWE-79"]
    finally:
        engine.dispose()
