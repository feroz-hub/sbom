from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from app.db import SessionLocal
from app.models import ComponentLifecycleCache, SBOMComponent, SBOMSource
from app.services.lifecycle import LifecycleEnrichmentService, normalize_component
from app.services.lifecycle.endoflife_date_provider import EndOfLifeDateProvider
from app.services.lifecycle.osv_provider import OSVProvider
from app.services.lifecycle.package_registry_provider import PackageRegistryProvider
from app.services.lifecycle.provider_base import LifecycleProvider
from app.services.lifecycle.types import (
    DEPRECATED,
    EOL,
    HIGH,
    LOW,
    UNKNOWN,
    UNSUPPORTED,
    LifecycleResult,
    NormalizedComponent,
    unknown_result,
)
from sqlalchemy import select


@pytest.fixture()
def db(client):
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


class FailIfCalledProvider(LifecycleProvider):
    name = "Fail If Called"

    def lookup(self, component: NormalizedComponent) -> LifecycleResult:
        raise AssertionError("provider should not be called")


class UnknownProvider(LifecycleProvider):
    name = "Unknown Provider"

    def lookup(self, component: NormalizedComponent) -> LifecycleResult:
        return unknown_result(component, self.name)


class UnsupportedProvider(LifecycleProvider):
    name = "Unsupported Provider"

    def lookup(self, component: NormalizedComponent) -> LifecycleResult:
        return LifecycleResult(
            component_name=component.normalized_name,
            component_version=component.normalized_version,
            ecosystem=component.ecosystem,
            purl=component.purl,
            lifecycle_status=UNSUPPORTED,
            maintenance_status="Unsupported",
            source_name=self.name,
            confidence=HIGH,
        )


def _future_iso(days: int = 7) -> str:
    return (datetime.now(UTC).replace(microsecond=0) + timedelta(days=days)).isoformat()


def _past_iso(days: int = 1) -> str:
    return (datetime.now(UTC).replace(microsecond=0) - timedelta(days=days)).isoformat()


def test_normalization_prefers_purl_and_infers_ecosystem():
    component = SBOMComponent(
        sbom_id=1,
        name="ignored",
        version="0.0.1",
        purl="pkg:npm/%40angular/core@12.0.0",
        component_type="library",
    )

    normalized = normalize_component(component)

    assert normalized.ecosystem == "npm"
    assert normalized.normalized_name == "@angular/core"
    assert normalized.normalized_version == "12.0.0"


def test_endoflife_date_provider_marks_eol_from_matching_cycle():
    provider = EndOfLifeDateProvider(
        http_get=lambda _url: [
            {
                "cycle": "3.11",
                "eol": "2027-10-31",
                "support": "2027-04-01",
                "latest": "3.11.9",
            }
        ],
        today=date(2028, 1, 1),
    )
    component = NormalizedComponent(
        component_id=None,
        name="python",
        version="3.11.2",
        normalized_name="python",
        normalized_version="3.11.2",
        ecosystem="generic",
    )

    result = provider.lookup(component)

    assert result.lifecycle_status == EOL
    assert result.eol_date == "2027-10-31"
    assert result.eos_date == "2027-04-01"
    assert result.source_name == "endoflife.date"
    assert result.recommended_version == "3.11.9"


def test_endoflife_date_provider_returns_unknown_when_no_cycle_matches():
    provider = EndOfLifeDateProvider(http_get=lambda _url: [{"cycle": "20", "eol": "2026-01-01"}])
    component = NormalizedComponent(
        component_id=None,
        name="nodejs",
        version="18.1.0",
        normalized_name="nodejs",
        normalized_version="18.1.0",
        ecosystem="generic",
    )

    result = provider.lookup(component)

    assert result.lifecycle_status == UNKNOWN


def test_package_registry_provider_detects_npm_deprecation():
    def get_json(url: str) -> dict[str, Any]:
        assert "registry.npmjs.org" in url
        return {
            "dist-tags": {"latest": "2.0.0"},
            "versions": {"1.0.0": {"deprecated": "No longer maintained."}},
        }

    provider = PackageRegistryProvider(http_get=get_json)
    component = NormalizedComponent(
        component_id=None,
        name="left-pad",
        version="1.0.0",
        normalized_name="left-pad",
        normalized_version="1.0.0",
        ecosystem="npm",
    )

    result = provider.lookup(component)

    assert result.lifecycle_status == DEPRECATED
    assert result.deprecated is True
    assert result.recommended_version == "2.0.0"
    assert "No longer maintained" in (result.recommendation or "")


def test_package_registry_provider_keeps_pypi_old_packages_unknown():
    provider = PackageRegistryProvider(
        http_get=lambda _url: {"info": {"version": "3.0.0"}, "releases": {"1.0.0": [{"yanked": False}]}}
    )
    component = NormalizedComponent(
        component_id=None,
        name="requests",
        version="1.0.0",
        normalized_name="requests",
        normalized_version="1.0.0",
        ecosystem="pypi",
    )

    result = provider.lookup(component)

    assert result.lifecycle_status == UNKNOWN
    assert result.confidence == LOW
    assert result.recommended_version == "3.0.0"


def test_osv_provider_recommends_fixed_version_without_setting_eol():
    provider = OSVProvider(
        http_post=lambda _url, _payload: {
            "vulns": [
                {
                    "id": "GHSA-123",
                    "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]}],
                }
            ]
        }
    )
    component = NormalizedComponent(
        component_id=None,
        name="pkg",
        version="1.0.0",
        normalized_name="pkg",
        normalized_version="1.0.0",
        ecosystem="npm",
    )

    result = provider.lookup(component)

    assert result.lifecycle_status == UNKNOWN
    assert result.recommended_version == "1.2.3"
    assert result.vulnerability_count == 1


def test_lifecycle_cache_hit_avoids_provider_call(db):
    sbom = SBOMSource(sbom_name="cache-hit", sbom_data="{}", status="validated")
    db.add(sbom)
    db.flush()
    component = SBOMComponent(sbom_id=sbom.id, name="cache-package", version="1.0.0", component_type="library")
    db.add(component)
    db.add(
        ComponentLifecycleCache(
            normalized_name="cache-package",
            normalized_version="1.0.0",
            ecosystem="generic",
            purl=None,
            lifecycle_status=DEPRECATED,
            source_name="Cached Provider",
            confidence=HIGH,
            checked_at=_past_iso(),
            expires_at=_future_iso(),
            evidence_json={"cached": True},
        )
    )
    db.commit()

    result = LifecycleEnrichmentService(providers=[FailIfCalledProvider()]).enrich_component(db, component)

    assert result.lifecycle_status == DEPRECATED
    assert component.lifecycle_source == "Cached Provider"
    assert component.lifecycle_is_stale is False


def test_expired_cache_is_kept_as_stale_when_providers_have_no_data(db):
    sbom = SBOMSource(sbom_name="cache-stale", sbom_data="{}", status="validated")
    db.add(sbom)
    db.flush()
    component = SBOMComponent(sbom_id=sbom.id, name="stale-package", version="1.0.0", component_type="library")
    db.add(component)
    db.add(
        ComponentLifecycleCache(
            normalized_name="stale-package",
            normalized_version="1.0.0",
            ecosystem="generic",
            purl=None,
            lifecycle_status=EOL,
            source_name="Cached Provider",
            confidence=HIGH,
            checked_at=_past_iso(10),
            expires_at=_past_iso(),
            evidence_json={"cached": True},
        )
    )
    db.commit()

    result = LifecycleEnrichmentService(providers=[UnknownProvider()]).enrich_component(db, component)

    assert result.lifecycle_status == EOL
    assert result.stale is True
    assert component.lifecycle_is_stale is True


def test_manual_override_has_priority_over_external_provider(db):
    sbom = SBOMSource(sbom_name="manual-priority", sbom_data="{}", status="validated")
    db.add(sbom)
    db.flush()
    component = SBOMComponent(
        sbom_id=sbom.id,
        name="manual-package",
        version="1.0.0",
        component_type="library",
        lifecycle_status=DEPRECATED,
        lifecycle_manual_override=True,
        lifecycle_source="Manual Override",
        lifecycle_source_url="https://example.test/evidence",
        lifecycle_evidence_json={"reason": "vendor notice"},
    )
    db.add(component)
    db.commit()

    result = LifecycleEnrichmentService(providers=[UnsupportedProvider()]).enrich_component(db, component)

    assert result.lifecycle_status == DEPRECATED
    assert result.source_name == "Manual Override"
    assert result.confidence == HIGH


def test_lifecycle_refresh_override_report_and_dashboard_endpoints(client, db):
    sbom = SBOMSource(sbom_name="api-lifecycle", sbom_data="{}", status="validated")
    db.add(sbom)
    db.flush()
    component = SBOMComponent(sbom_id=sbom.id, name="api-package", version="1.0.0", component_type="library")
    db.add(component)
    db.add(
        ComponentLifecycleCache(
            normalized_name="api-package",
            normalized_version="1.0.0",
            ecosystem="generic",
            purl=None,
            lifecycle_status=EOL,
            eol_date="2024-01-01",
            source_name="Cached Provider",
            confidence=HIGH,
            checked_at=_past_iso(),
            expires_at=_future_iso(),
            evidence_json={"cached": True},
        )
    )
    db.commit()

    refresh_response = client.post(f"/api/sboms/{sbom.id}/lifecycle/refresh?force=false")
    assert refresh_response.status_code == 200
    assert refresh_response.json()["components_enriched"] == 1

    db.refresh(component)
    assert component.lifecycle_status == EOL

    report_response = client.get(f"/api/sboms/{sbom.id}/lifecycle/report")
    assert report_response.status_code == 200
    report = report_response.json()
    assert report["summary"]["eol_count"] == 1
    assert report["components"][0]["source_name"] == "Cached Provider"

    dashboard_response = client.get("/dashboard/lifecycle")
    assert dashboard_response.status_code == 200
    dashboard = dashboard_response.json()
    assert dashboard["total_components"] >= 1
    assert dashboard["eol_count"] >= 1

    override_response = client.patch(
        f"/api/components/{component.id}/lifecycle-override",
        json={
            "lifecycle_status": "Unsupported",
            "reason": "Vendor support contract ended.",
            "updated_by": "security@example.test",
        },
    )
    assert override_response.status_code == 200
    body = override_response.json()
    assert body["lifecycle_status"] == UNSUPPORTED
    assert body["lifecycle_manual_override"] is True

    invalid_response = client.patch(
        f"/api/components/{component.id}/lifecycle-override",
        json={"lifecycle_status": "Totally Invalid"},
    )
    assert invalid_response.status_code == 422

    audit = db.execute(select(ComponentLifecycleCache).where(ComponentLifecycleCache.normalized_name == "api-package"))
    assert audit.scalars().first() is not None
