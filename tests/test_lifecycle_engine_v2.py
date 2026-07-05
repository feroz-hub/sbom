"""Comprehensive lifecycle engine v2 tests."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from app.db import SessionLocal
from app.models import ComponentLifecycleCache, SBOMComponent, SBOMSource
from app.services.lifecycle import LifecycleEnrichmentService, normalize_component
from app.services.lifecycle.aliases import clear_alias_cache, resolve_lifecycle_alias
from app.services.lifecycle.endoflife_date_provider import EndOfLifeDateProvider
from app.services.lifecycle.lifecycle_cache_repository import (
    lifecycle_cache_row_from_result,
    upsert_lifecycle_cache_entries,
)
from app.services.lifecycle.openeox_provider import OpenEoXProvider
from app.services.lifecycle.provider_base import LifecycleProvider
from app.services.lifecycle.provider_chain import lookup_provider_chain
from app.services.lifecycle.provider_status import get_provider_status_tracker
from app.services.lifecycle.repository_health_provider import RepositoryHealthProvider
from app.services.lifecycle.risk_classification import RISK_CRITICAL, RISK_MEDIUM, classify_lifecycle_risk
from app.services.lifecycle.types import (
    DEPRECATED,
    EOL,
    HIGH,
    LOW,
    MEDIUM,
    POSSIBLY_UNMAINTAINED,
    UNKNOWN,
    UNSUPPORTED,
    LifecycleResult,
    NormalizedComponent,
    unknown_result,
)
from app.services.lifecycle.xeol_db_provider import XeolDbProvider, clear_xeol_db_cache
from sqlalchemy import func, select


@pytest.fixture()
def db(client):
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


class SlowProvider(LifecycleProvider):
    name = "Slow Provider"
    priority = 50

    def lookup(self, component: NormalizedComponent) -> LifecycleResult:
        import time

        time.sleep(10)
        return unknown_result(component, self.name)


class EolProvider(LifecycleProvider):
    name = "EOL Provider"
    priority = 10

    def lookup(self, component: NormalizedComponent) -> LifecycleResult:
        return LifecycleResult(
            component_name=component.normalized_name,
            component_version=component.normalized_version,
            ecosystem=component.ecosystem,
            purl=component.purl,
            lifecycle_status=EOL,
            eol_date="2020-01-01",
            source_name=self.name,
            confidence=HIGH,
        )


class FailProvider(LifecycleProvider):
    name = "Fail Provider"
    priority = 20

    def lookup(self, component: NormalizedComponent) -> LifecycleResult:
        raise RuntimeError("provider down")


def _future_iso(days: int = 7) -> str:
    return (datetime.now(UTC).replace(microsecond=0) + timedelta(days=days)).isoformat()


def _past_iso(days: int = 1) -> str:
    return (datetime.now(UTC).replace(microsecond=0) - timedelta(days=days)).isoformat()


def test_alias_mapping_resolves_node_to_nodejs():
    clear_alias_cache()
    entry = resolve_lifecycle_alias("node")
    assert entry is not None
    assert entry.canonical_name == "nodejs"
    assert entry.provider_product_name == "nodejs"


def test_openeox_provider_maps_known_record(tmp_path: Path):
    feed = tmp_path / "openeox.json"
    feed.write_text(
        json.dumps(
            [
                {
                    "name": "custom-app",
                    "version": "1.0",
                    "lifecycle_status": "eol",
                    "eol_date": "2024-01-01",
                    "source_url": "https://vendor.example/eol",
                }
            ]
        ),
        encoding="utf-8",
    )
    provider = OpenEoXProvider(feed_urls=[f"file://{feed}"])
    component = NormalizedComponent(
        component_id=None,
        name="custom-app",
        version="1.0.0",
        normalized_name="custom-app",
        normalized_version="1.0.0",
        ecosystem="generic",
    )
    result = provider.lookup(component)
    assert result.lifecycle_status == EOL
    assert result.source_url == "https://vendor.example/eol"
    assert result.confidence == HIGH


def test_xeol_db_provider_matches_local_export(tmp_path: Path):
    clear_xeol_db_cache()
    db_file = tmp_path / "xeol.json"
    db_file.write_text(
        json.dumps([{"name": "legacy-lib", "version": "2.0", "eol": True, "eol_date": "2023-06-01"}]),
        encoding="utf-8",
    )
    provider = XeolDbProvider(db_path=str(db_file), today=date(2024, 1, 1))
    component = NormalizedComponent(
        component_id=None,
        name="legacy-lib",
        version="2.0.1",
        normalized_name="legacy-lib",
        normalized_version="2.0.1",
        ecosystem="npm",
    )
    result = provider.lookup(component)
    assert result.lifecycle_status == EOL


def test_xeol_db_provider_matches_sqlite_export(tmp_path: Path):
    clear_xeol_db_cache()
    db_file = tmp_path / "xeol.db"
    connection = sqlite3.connect(db_file)
    try:
        connection.executescript(
            """
            CREATE TABLE products (
              id integer PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              permalink TEXT NOT NULL
            );
            CREATE TABLE cycles (
              id integer PRIMARY KEY AUTOINCREMENT,
              lts boolean,
              release_cycle TEXT NOT NULL,
              eol date,
              eol_bool boolean,
              latest_release TEXT,
              latest_release_date date,
              release_date date,
              support boolean,
              product_id integer NOT NULL
              CHECK (eol IS NOT NULL OR eol_bool IS NOT NULL)
            );
            CREATE TABLE purls (
              id integer PRIMARY KEY AUTOINCREMENT,
              purl TEXT NOT NULL,
              product_id integer NOT NULL
            );
            INSERT INTO products (id, name, permalink) VALUES (1, 'legacy-lib', 'https://example.test/legacy-lib');
            INSERT INTO cycles (release_cycle, eol, eol_bool, product_id) VALUES ('2.0', '2023-06-01', NULL, 1);
            INSERT INTO purls (purl, product_id) VALUES ('pkg:npm/legacy-lib', 1);
            """
        )
        connection.commit()
    finally:
        connection.close()

    provider = XeolDbProvider(db_path=str(db_file), today=date(2024, 1, 1))
    component = NormalizedComponent(
        component_id=None,
        name="legacy-lib",
        version="2.0.1",
        normalized_name="legacy-lib",
        normalized_version="2.0.1",
        ecosystem="npm",
    )

    result = provider.lookup(component)

    assert result.lifecycle_status == EOL
    assert result.source_name == "Xeol DB"


def test_xeol_db_provider_matches_pypi_pep_503_normalized_name(tmp_path: Path):
    clear_xeol_db_cache()
    db_file = tmp_path / "xeol.db"
    connection = sqlite3.connect(db_file)
    try:
        connection.executescript(
            """
            CREATE TABLE products (
              id integer PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              permalink TEXT NOT NULL
            );
            CREATE TABLE cycles (
              id integer PRIMARY KEY AUTOINCREMENT,
              lts boolean,
              release_cycle TEXT NOT NULL,
              eol date,
              eol_bool boolean,
              latest_release TEXT,
              latest_release_date date,
              release_date date,
              support boolean,
              product_id integer NOT NULL
              CHECK (eol IS NOT NULL OR eol_bool IS NOT NULL)
            );
            CREATE TABLE purls (
              id integer PRIMARY KEY AUTOINCREMENT,
              purl TEXT NOT NULL,
              product_id integer NOT NULL
            );
            INSERT INTO products (id, name, permalink) VALUES (1, 'boolean-py', 'https://example.test/boolean-py');
            INSERT INTO cycles (release_cycle, eol, eol_bool, product_id) VALUES ('5', '2025-01-01', NULL, 1);
            INSERT INTO purls (purl, product_id) VALUES ('pkg:pypi/boolean-py', 1);
            """
        )
        connection.commit()
    finally:
        connection.close()

    provider = XeolDbProvider(db_path=str(db_file), today=date(2026, 1, 1))
    component = normalize_component(
        SBOMComponent(
            sbom_id=1,
            name="boolean.py",
            version="5.0",
            purl="pkg:pypi/boolean.py@5.0",
            component_type="library",
        )
    )

    result = provider.lookup(component)

    assert component.normalized_name == "boolean-py"
    assert result.lifecycle_status == EOL
    assert result.source_name == "Xeol DB"
    assert result.eol_date == "2025-01-01"


def test_xeol_db_provider_returns_unknown_for_absent_pypi_package(tmp_path: Path):
    clear_xeol_db_cache()
    db_file = tmp_path / "xeol.db"
    connection = sqlite3.connect(db_file)
    try:
        connection.executescript(
            """
            CREATE TABLE products (
              id integer PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              permalink TEXT NOT NULL
            );
            CREATE TABLE cycles (
              id integer PRIMARY KEY AUTOINCREMENT,
              lts boolean,
              release_cycle TEXT NOT NULL,
              eol date,
              eol_bool boolean,
              latest_release TEXT,
              latest_release_date date,
              release_date date,
              support boolean,
              product_id integer NOT NULL
              CHECK (eol IS NOT NULL OR eol_bool IS NOT NULL)
            );
            CREATE TABLE purls (
              id integer PRIMARY KEY AUTOINCREMENT,
              purl TEXT NOT NULL,
              product_id integer NOT NULL
            );
            INSERT INTO products (id, name, permalink) VALUES (1, 'django', 'https://example.test/django');
            INSERT INTO cycles (release_cycle, eol, eol_bool, product_id) VALUES ('3.2', '2024-04-01', NULL, 1);
            INSERT INTO purls (purl, product_id) VALUES ('pkg:pypi/django', 1);
            """
        )
        connection.commit()
    finally:
        connection.close()

    provider = XeolDbProvider(db_path=str(db_file), today=date(2026, 1, 1))
    component = normalize_component(
        SBOMComponent(
            sbom_id=1,
            name="boto3",
            version="1.42.88",
            purl="pkg:pypi/boto3@1.42.88",
            component_type="library",
        )
    )

    result = provider.lookup(component)

    assert result.lifecycle_status == UNKNOWN
    assert result.source_name == "Xeol DB"
    assert result.eol_date is None


def test_provider_chain_stops_on_high_confidence_result():
    component = NormalizedComponent(
        component_id=None,
        name="pkg",
        version="1.0.0",
        normalized_name="pkg",
        normalized_version="1.0.0",
        ecosystem="generic",
    )
    called: list[str] = []

    class LateProvider(LifecycleProvider):
        name = "Late Provider"
        priority = 99

        def lookup(self, comp: NormalizedComponent) -> LifecycleResult:
            called.append(self.name)
            return unknown_result(comp, self.name)

    result, _errors = lookup_provider_chain(
        [EolProvider(), LateProvider()],
        component,
        timeout_seconds=1.0,
    )
    assert result.lifecycle_status == EOL
    assert "Late Provider" not in called


def test_unknown_result_does_not_stop_remaining_lifecycle_providers():
    component = NormalizedComponent(
        component_id=None,
        name="pkg",
        version="1.0.0",
        normalized_name="pkg",
        normalized_version="1.0.0",
        ecosystem="generic",
    )
    called: list[str] = []

    class EarlyUnknownProvider(LifecycleProvider):
        name = "Early Unknown Provider"
        priority = 10

        def lookup(self, comp: NormalizedComponent) -> LifecycleResult:
            called.append(self.name)
            return unknown_result(comp, self.name)

    class LateEolProvider(LifecycleProvider):
        name = "Late EOL Provider"
        priority = 20

        def lookup(self, comp: NormalizedComponent) -> LifecycleResult:
            called.append(self.name)
            return LifecycleResult(
                component_name=comp.normalized_name,
                component_version=comp.normalized_version,
                ecosystem=comp.ecosystem,
                purl=comp.purl,
                lifecycle_status=EOL,
                eol_date="2020-01-01",
                source_name=self.name,
                confidence=HIGH,
            )

    result, _errors = lookup_provider_chain(
        [EarlyUnknownProvider(), LateEolProvider()],
        component,
        timeout_seconds=1.0,
    )

    assert called == ["Early Unknown Provider", "Late EOL Provider"]
    assert result.lifecycle_status == EOL
    assert result.source_name == "Late EOL Provider"


def test_registry_metadata_result_does_not_count_as_lifecycle_evidence():
    component = NormalizedComponent(
        component_id=None,
        name="pkg",
        version="1.0.0",
        normalized_name="pkg",
        normalized_version="1.0.0",
        ecosystem="pypi",
    )
    called: list[str] = []

    class RegistryMetadataProvider(LifecycleProvider):
        name = "PyPI"
        priority = 10

        def lookup(self, comp: NormalizedComponent) -> LifecycleResult:
            called.append(self.name)
            return LifecycleResult(
                component_name=comp.normalized_name,
                component_version=comp.normalized_version,
                ecosystem=comp.ecosystem,
                purl=comp.purl,
                lifecycle_status=UNKNOWN,
                latest_version="2.0.0",
                recommended_version="2.0.0",
                source_name=self.name,
                confidence=LOW,
            )

    class AuthoritativeLifecycleProvider(LifecycleProvider):
        name = "Authoritative Lifecycle"
        priority = 20

        def lookup(self, comp: NormalizedComponent) -> LifecycleResult:
            called.append(self.name)
            return LifecycleResult(
                component_name=comp.normalized_name,
                component_version=comp.normalized_version,
                ecosystem=comp.ecosystem,
                purl=comp.purl,
                lifecycle_status=EOL,
                eol_date="2020-01-01",
                source_name=self.name,
                confidence=HIGH,
            )

    result, _errors = lookup_provider_chain(
        [RegistryMetadataProvider(), AuthoritativeLifecycleProvider()],
        component,
        timeout_seconds=1.0,
    )

    assert called == ["PyPI", "Authoritative Lifecycle"]
    assert result.lifecycle_status == EOL
    assert result.source_name == "Authoritative Lifecycle"
    assert result.recommended_version == "2.0.0"


def test_provider_failure_continues_fallback():
    component = NormalizedComponent(
        component_id=None,
        name="pkg",
        version="1.0.0",
        normalized_name="pkg",
        normalized_version="1.0.0",
        ecosystem="generic",
    )

    class FallbackProvider(LifecycleProvider):
        name = "Fallback Provider"
        priority = 30

        def lookup(self, comp: NormalizedComponent) -> LifecycleResult:
            return LifecycleResult(
                component_name=comp.normalized_name,
                component_version=comp.normalized_version,
                ecosystem=comp.ecosystem,
                purl=comp.purl,
                lifecycle_status=DEPRECATED,
                deprecated=True,
                source_name=self.name,
                confidence=MEDIUM,
            )

    result, _errors = lookup_provider_chain(
        [FailProvider(), FallbackProvider()],
        component,
        timeout_seconds=1.0,
    )
    assert result.lifecycle_status == DEPRECATED


def test_unknown_provider_result_does_not_open_lifecycle_circuit():
    tracker = get_provider_status_tracker()
    tracker.reset()
    component = NormalizedComponent(
        component_id=None,
        name="pkg",
        version="1.0.0",
        normalized_name="pkg",
        normalized_version="1.0.0",
        ecosystem="generic",
    )

    class NoDataProvider(LifecycleProvider):
        name = "No Data Provider"
        priority = 10

        def lookup(self, comp: NormalizedComponent) -> LifecycleResult:
            return unknown_result(comp, self.name)

    for _ in range(5):
        result, errors = lookup_provider_chain(
            [NoDataProvider()],
            component,
            timeout_seconds=1.0,
            status_tracker=tracker,
        )
        assert result.lifecycle_status == UNKNOWN
        assert errors == []

    assert tracker.is_circuit_open("No Data Provider") is False


def test_provider_timeout_returns_unknown_not_exception():
    component = NormalizedComponent(
        component_id=None,
        name="pkg",
        version="1.0.0",
        normalized_name="pkg",
        normalized_version="1.0.0",
        ecosystem="generic",
    )
    result, _errors = lookup_provider_chain([SlowProvider()], component, timeout_seconds=0.2)
    assert result.lifecycle_status == UNKNOWN


def test_duplicate_components_deduped_before_lookup(db):
    sbom = SBOMSource(sbom_name="dedupe", sbom_data="{}", status="validated")
    db.add(sbom)
    db.flush()
    for _idx in range(3):
        db.add(
            SBOMComponent(
                sbom_id=sbom.id,
                name="same-package",
                version="1.0.0",
                component_type="library",
            )
        )
    db.commit()

    provider = MagicMock()
    provider.name = "Mock Provider"
    provider.priority = 10
    provider.supports.return_value = True
    provider.lookup.return_value = LifecycleResult(
        component_name="same-package",
        component_version="1.0.0",
        ecosystem="generic",
        purl=None,
        lifecycle_status=EOL,
        eol_date="2020-01-01",
        source_name="Mock Provider",
        confidence=HIGH,
    )

    summary = LifecycleEnrichmentService(providers=[provider]).enrich_sbom(db, sbom.id, force_refresh=True)
    assert summary["total_components"] == 3
    assert summary["unique_identities"] == 1
    assert provider.lookup.call_count == 1


def test_risk_classification_eol_passed_is_critical():
    risk = classify_lifecycle_risk(
        lifecycle_status=EOL,
        eol_date="2020-01-01",
        confidence=HIGH,
        today=date(2026, 1, 1),
    )
    assert risk == RISK_CRITICAL


def test_risk_classification_eos_soon_threshold():
    risk = classify_lifecycle_risk(
        lifecycle_status="Supported",
        eos_date=(date(2026, 1, 1) + timedelta(days=30)).isoformat(),
        confidence=HIGH,
        today=date(2026, 1, 1),
    )
    assert risk == RISK_MEDIUM


def test_unknown_ttl_shorter_than_known_ttl():
    from app.services.lifecycle.lifecycle_cache_repository import _cache_ttl_for_result

    normalized = NormalizedComponent(
        component_id=None,
        name="pkg",
        version="1.0.0",
        normalized_name="pkg",
        normalized_version="1.0.0",
        ecosystem="generic",
    )
    known_ttl = _cache_ttl_for_result(
        LifecycleResult(
            component_name="pkg",
            component_version="1.0.0",
            ecosystem="generic",
            purl=None,
            lifecycle_status=EOL,
            eol_date="2020-01-01",
            source_name="test",
            confidence=HIGH,
        )
    )
    unknown_ttl = _cache_ttl_for_result(
        LifecycleResult(
            component_name="pkg",
            component_version="1.0.0",
            ecosystem="generic",
            purl=None,
            lifecycle_status=UNKNOWN,
            source_name="test",
            confidence=LOW,
        )
    )
    assert known_ttl > unknown_ttl


def test_provider_failure_uses_failure_cache_ttl():
    from app.services.lifecycle.lifecycle_cache_repository import _cache_ttl_for_result

    timeout_ttl = _cache_ttl_for_result(
        LifecycleResult(
            component_name="pkg",
            component_version="1.0.0",
            ecosystem="generic",
            purl=None,
            lifecycle_status=UNKNOWN,
            source_name="timeout provider",
            confidence=LOW,
            evidence={"provider_errors": ["timeout provider: timeout"]},
        )
    )
    unknown_ttl = _cache_ttl_for_result(
        LifecycleResult(
            component_name="pkg",
            component_version="1.0.0",
            ecosystem="generic",
            purl=None,
            lifecycle_status=UNKNOWN,
            source_name="no data provider",
            confidence=LOW,
        )
    )

    assert timeout_ttl < unknown_ttl
    assert int(timeout_ttl.total_seconds()) == 30 * 60


def test_lifecycle_sources_endpoint(client):
    get_provider_status_tracker().reset()
    response = client.get("/api/lifecycle/sources")
    assert response.status_code == 200
    body = response.json()
    assert "sources" in body


def test_lifecycle_provider_status_endpoint(client):
    response = client.get("/api/lifecycle/provider-status")
    assert response.status_code == 200
    body = response.json()
    assert body["overall_status"] in {"healthy", "degraded"}
    assert "providers" in body


def test_lifecycle_refresh_returns_summary(client, db):
    sbom = SBOMSource(sbom_name="summary", sbom_data="{}", status="validated")
    db.add(sbom)
    db.flush()
    db.add(SBOMComponent(sbom_id=sbom.id, name="pkg", version="1.0.0", component_type="library"))
    db.commit()

    response = client.post(f"/api/sboms/{sbom.id}/lifecycle/refresh?force=true")
    assert response.status_code == 200
    body = response.json()
    assert body["total_components"] == 1
    assert "unique_identities" in body
    assert "provider_lookups" in body
    assert "provider_errors" in body


def test_github_archived_maps_unsupported():
    provider = RepositoryHealthProvider(
        http_get=lambda _url: {
            "archived": True,
            "disabled": False,
            "pushed_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
        }
    )
    component = NormalizedComponent(
        component_id=None,
        name="pkg",
        version="1.0.0",
        normalized_name="pkg",
        normalized_version="1.0.0",
        ecosystem="npm",
        repository_url="https://github.com/example/pkg",
    )
    result = provider.lookup(component)
    assert result.lifecycle_status == UNSUPPORTED
    assert result.lifecycle_status != EOL


def test_postgresql_cache_upsert_prevents_duplicate_rows(db):
    normalized = NormalizedComponent(
        component_id=None,
        name="upsert-pkg",
        version="1.0.0",
        normalized_name="upsert-pkg",
        normalized_version="1.0.0",
        ecosystem="generic",
        purl="pkg:generic/upsert-pkg@1.0.0",
    )
    row = lifecycle_cache_row_from_result(
        normalized,
        LifecycleResult(
            component_name="upsert-pkg",
            component_version="1.0.0",
            ecosystem="generic",
            purl=normalized.purl,
            lifecycle_status=EOL,
            source_name="Test",
            confidence=HIGH,
        ),
    )
    upsert_lifecycle_cache_entries(db, [row])
    upsert_lifecycle_cache_entries(db, [row])
    db.commit()
    count = (
        db.execute(
            select(func.count())
            .select_from(ComponentLifecycleCache)
            .where(ComponentLifecycleCache.normalized_name == "upsert-pkg")
        ).scalar_one()
        or 0
    )
    assert count == 1


def test_evidence_url_and_confidence_saved(db):
    sbom = SBOMSource(sbom_name="evidence", sbom_data="{}", status="validated")
    db.add(sbom)
    db.flush()
    component = SBOMComponent(sbom_id=sbom.id, name="python", version="3.11.2", component_type="library")
    db.add(component)
    db.commit()

    provider = EndOfLifeDateProvider(
        http_get=lambda _url: [{"cycle": "3.11", "eol": "2027-10-31", "latest": "3.11.9"}],
        today=date(2026, 1, 1),
    )
    LifecycleEnrichmentService(providers=[provider]).enrich_component(db, component, force_refresh=True)
    db.commit()
    db.refresh(component)
    assert component.lifecycle_source == "endoflife.date"
    assert component.lifecycle_confidence == HIGH
    assert component.lifecycle_source_url is not None
