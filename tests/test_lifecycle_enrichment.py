from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from app.db import SessionLocal
from app.models import ComponentLifecycleCache, SBOMComponent, SBOMSource
from app.services.lifecycle import LifecycleEnrichmentService, normalize_component
from app.services.lifecycle.endoflife_date_provider import EndOfLifeDateProvider
from app.services.lifecycle.normalizer import (
    build_lifecycle_lookup_key,
    infer_ecosystem,
    normalize_component_name,
    parse_purl,
)
from app.services.lifecycle.osv_provider import OSVProvider
from app.services.lifecycle.package_registry_provider import PackageRegistryProvider
from app.services.lifecycle.provider_base import LifecycleProvider
from app.services.lifecycle.repository_health_provider import RepositoryHealthProvider
from app.services.lifecycle.types import (
    DEPRECATED,
    EOF,
    EOL,
    EOS,
    HIGH,
    LOW,
    MEDIUM,
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


def test_public_normalizer_helpers_build_stable_identity():
    parsed = parse_purl("pkg:pypi/Django@4.2.0")
    assert parsed is not None
    assert normalize_component_name("Org.Spring:Core", "maven") == "org.spring/core"
    assert infer_ecosystem("python-requests", None, None, None, None) == "pypi"

    a = NormalizedComponent(
        component_id=None,
        name="Django",
        version="4.2.0",
        normalized_name="django",
        normalized_version="4.2.0",
        ecosystem="pypi",
    )
    b = NormalizedComponent(
        component_id=None,
        name="Django",
        version="4.1.0",
        normalized_name="django",
        normalized_version="4.1.0",
        ecosystem="pypi",
    )
    assert build_lifecycle_lookup_key(a) != build_lifecycle_lookup_key(b)


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


def test_endoflife_date_provider_marks_eos_and_eof_from_official_dates():
    provider = EndOfLifeDateProvider(
        http_get=lambda _url: [
            {
                "cycle": "17",
                "eol": "2030-01-01",
                "support": "2024-01-01",
                "eof": "2025-01-01",
                "latest": "17.0.10",
            }
        ],
        today=date(2026, 1, 1),
    )
    component = NormalizedComponent(
        component_id=None,
        name="java",
        version="17.0.1",
        normalized_name="java",
        normalized_version="17.0.1",
        ecosystem="maven",
    )

    result = provider.lookup(component)

    assert result.lifecycle_status == EOS
    assert result.unsupported is True
    assert result.eof_date == "2025-01-01"

    provider_eof = EndOfLifeDateProvider(
        http_get=lambda _url: [{"cycle": "1", "eol": "2030-01-01", "eof": "2025-01-01"}],
        today=date(2026, 1, 1),
    )
    eof_component = NormalizedComponent(
        component_id=None,
        name="django",
        version="1.2.3",
        normalized_name="django",
        normalized_version="1.2.3",
        ecosystem="pypi",
    )
    assert provider_eof.lookup(eof_component).lifecycle_status == EOF


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
    assert result.latest_version == "3.0.0"


def test_repository_health_provider_marks_archived_repo_unsupported():
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
    assert result.unsupported is True
    assert result.confidence == MEDIUM
    assert result.evidence["repository_url"] == "https://github.com/example/pkg"


def test_repository_health_provider_inactivity_is_not_eol():
    provider = RepositoryHealthProvider(
        http_get=lambda _url: {
            "archived": False,
            "disabled": False,
            "pushed_at": "2020-01-01T00:00:00Z",
            "updated_at": "2020-01-01T00:00:00Z",
        },
        today=datetime(2026, 1, 1, tzinfo=UTC),
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

    assert result.lifecycle_status == UNKNOWN
    assert result.maintenance_status == "Possibly Unmaintained"


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
            lookup_key="fallback:generic:cache-package:1.0.0:",
            normalized_name="cache-package",
            normalized_version="1.0.0",
            ecosystem="generic",
            purl=None,
            cpe=None,
            lifecycle_status=DEPRECATED,
            source_name="Cached Provider",
            confidence=HIGH,
            checked_at=_past_iso(),
            expires_at=_future_iso(),
            evidence_json={"cached": True},
            latest_version="2.0.0",
        )
    )
    db.commit()

    result = LifecycleEnrichmentService(providers=[FailIfCalledProvider()]).enrich_component(db, component)

    assert result.lifecycle_status == DEPRECATED
    assert component.lifecycle_source == "Cached Provider"
    assert component.lifecycle_is_stale is False
    assert component.latest_version == "2.0.0"


def test_expired_cache_is_kept_as_stale_when_providers_have_no_data(db):
    sbom = SBOMSource(sbom_name="cache-stale", sbom_data="{}", status="validated")
    db.add(sbom)
    db.flush()
    component = SBOMComponent(sbom_id=sbom.id, name="stale-package", version="1.0.0", component_type="library")
    db.add(component)
    db.add(
        ComponentLifecycleCache(
            lookup_key="fallback:generic:stale-package:1.0.0:",
            normalized_name="stale-package",
            normalized_version="1.0.0",
            ecosystem="generic",
            purl=None,
            cpe=None,
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
    assert result.unsupported is True
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


def test_apply_manual_lifecycle_override_does_not_call_external_providers(db, monkeypatch):
    sbom = SBOMSource(sbom_name="manual-save-no-provider", sbom_data="{}", status="validated")
    db.add(sbom)
    db.flush()
    component = SBOMComponent(
        sbom_id=sbom.id,
        name="manual-save-package",
        version="1.0.0",
        component_type="library",
    )
    db.add(component)
    db.commit()

    def fail_lookup(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("provider lookup should not run during save override")

    monkeypatch.setattr(LifecycleEnrichmentService, "_lookup_providers", fail_lookup)

    updated = LifecycleEnrichmentService().apply_manual_override(
        db,
        component.id,
        {
            "lifecycle_status": EOL,
            "eol_date": "2026-12-31",
            "reason": "Vendor advisory confirmed end of life.",
            "evidence_url": "https://vendor.example/advisory",
        },
        updated_by="qa",
    )

    assert updated.lifecycle_status == EOL
    assert updated.lifecycle_manual_override is True
    assert updated.lifecycle_source == "Manual Override"


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
            cpe=None,
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
    assert component.unsupported is True

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
            "latest_version": "2.0.0",
            "unsupported": True,
            "updated_by": "security@example.test",
        },
    )
    assert override_response.status_code == 200
    body = override_response.json()
    assert body["lifecycle_status"] == UNSUPPORTED
    assert body["unsupported"] is True
    assert body["latest_version"] == "2.0.0"
    assert body["lifecycle_manual_override"] is True

    invalid_response = client.patch(
        f"/api/components/{component.id}/lifecycle-override",
        json={"lifecycle_status": "Totally Invalid"},
    )
    assert invalid_response.status_code == 422

    audit = db.execute(select(ComponentLifecycleCache).where(ComponentLifecycleCache.normalized_name == "api-package"))
    assert audit.scalars().first() is not None


def test_lifecycle_diagnostics_endpoint(client, db):
    sbom = SBOMSource(sbom_name="diag-lifecycle", sbom_data="{}", status="validated")
    db.add(sbom)
    db.flush()
    component = SBOMComponent(
        sbom_id=sbom.id,
        name="diag-package",
        version="1.0.0",
        component_type="library",
        lifecycle_status=EOL,
        lifecycle_source="endoflife.date",
        lifecycle_confidence=HIGH,
        lifecycle_evidence_json={"cached": True},
        lifecycle_checked_at=_past_iso(),
    )
    db.add(component)
    db.commit()

    diag_response = client.get(f"/api/sboms/{sbom.id}/lifecycle/diagnostics")
    assert diag_response.status_code == 200
    diag = diag_response.json()
    assert diag["component_count"] == 1
    assert diag["components_enriched"] == 1
    assert diag["unknown_count"] == 0
    assert diag["cache_hit_count"] == 1
    assert diag["provider_hit_count"] == 0
    assert len(diag["sample_matched_components"]) == 1
    assert diag["sample_matched_components"][0]["name"] == "diag-package"


def test_manual_lifecycle_override_validation_and_audit(client, db):
    # Setup SBOM and component
    sbom = SBOMSource(sbom_name="override-test", sbom_data="{}", status="validated")
    db.add(sbom)
    db.flush()
    component = SBOMComponent(sbom_id=sbom.id, name="override-pkg", version="1.0.0", component_type="library")
    db.add(component)
    db.commit()

    # 1. Success validation
    # Check date validation and manual override flag setting
    import time
    start_time = time.time()

    override_res = client.patch(
        f"/api/components/{component.id}/lifecycle-override",
        json={
            "lifecycle_status": "EOL",
            "maintenance_status": "Unsupported",
            "eos_date": "2026-06-30",
            "eol_date": "2026-12-31",
            "eof_date": "2026-06-30",
            "deprecated": False,
            "unsupported": True,
            "recommended_version": "2.0.0",
            "reason": "Explicit test reason.",
            "evidence_url": "https://example.com/eol-news",
            "updated_by": "test-user"
        }
    )
    end_time = time.time()
    assert override_res.status_code == 200
    duration = end_time - start_time
    assert duration < 2.0  # completes quickly (DB only)

    # 2. Verify override saves successfully
    body = override_res.json()
    assert body["lifecycle_status"] == "EOL"
    assert body["eos_date"] == "2026-06-30"
    assert body["eol_date"] == "2026-12-31"
    assert body["eof_date"] == "2026-06-30"
    assert body["recommended_version"] == "2.0.0"
    assert body["lifecycle_manual_override"] is True
    assert body["lifecycle_source"] == "Manual Override"
    assert body["lifecycle_source_url"] == "https://example.com/eol-news"

    # 3. Verify audit history is written
    from app.models import AuditLog, ComponentLifecycleOverrideAudit
    audit_logs = db.execute(
        select(AuditLog).where(AuditLog.target_id == component.id, AuditLog.action == "component.lifecycle_override")
    ).scalars().all()
    assert len(audit_logs) == 1
    assert audit_logs[0].user_id == "test-user"

    override_audit = db.execute(
        select(ComponentLifecycleOverrideAudit).where(ComponentLifecycleOverrideAudit.component_id == component.id)
    ).scalars().all()
    assert len(override_audit) == 1
    assert override_audit[0].reason == "Explicit test reason."

    # 4. Invalid status returns 422
    invalid_status = client.patch(
        f"/api/components/{component.id}/lifecycle-override",
        json={
            "lifecycle_status": "Not A Status",
            "reason": "Test reason"
        }
    )
    assert invalid_status.status_code == 422

    # 5. Invalid date format returns 422
    invalid_date = client.patch(
        f"/api/components/{component.id}/lifecycle-override",
        json={
            "lifecycle_status": "EOL",
            "eos_date": "2026/06/30",
            "reason": "Test reason"
        }
    )
    assert invalid_date.status_code == 422

    # 6. Missing component returns 404
    missing_comp = client.patch(
        "/api/components/999999/lifecycle-override",
        json={
            "lifecycle_status": "EOL",
            "reason": "Test reason"
        }
    )
    assert missing_comp.status_code == 404

    # 7. Manual override survives lifecycle refresh
    # Create enrichment service that would normally fail if providers are called
    # But because manual override is set, it won't hit providers
    enrich_service = LifecycleEnrichmentService(providers=[FailIfCalledProvider()])
    db.refresh(component)
    result = enrich_service.enrich_component(db, component, force_refresh=True)
    assert result.lifecycle_status == "EOL"
    assert result.manual_override is True
