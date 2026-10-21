"""HTTP fixture → configured registry → persistence → report → expired refresh."""

from datetime import UTC, datetime, timedelta

import httpx
from app.db import SessionLocal
from app.models import ComponentLifecycleCache, SBOMComponent, SBOMSource
from app.services.lifecycle.lifecycle_enrichment_service import LifecycleEnrichmentService
from app.services.lifecycle.provider_config_service import LifecycleProviderConfigService
from sqlalchemy import select

from tests.tenant_fixture_scope import declare_fixture_tenant, verified_fixture_tenant


def test_configured_runtime_persistence_report_and_expiration(client, monkeypatch):
    from app.services.lifecycle import provider_http

    requests = []

    class Client:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def request(self, method, url, **kwargs):
            requests.append(url)
            # Synthetic contract fixture, not a declaration about actual Python dates.
            return httpx.Response(
                200,
                json=[{"cycle": "3.7", "eol": "2000-01-01"}, {"cycle": "3.12", "eol": "2099-01-01"}],
                request=httpx.Request(method, url),
            )

    monkeypatch.setattr(provider_http.httpx, "Client", Client)
    monkeypatch.setattr(provider_http.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))])
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        service = LifecycleProviderConfigService()
        for row in service.list_configs(db):
            service.update_config(db, row.provider_key, {"enabled": row.provider_key == "endoflife_date"}, context=None)
        service.update_config(db, "endoflife_date", {"cache_ttl_known_days": 2, "timeout_seconds": 9}, context=None)
        sbom = SBOMSource(sbom_name="lifecycle-contract-smoke", sbom_data="{}", status="validated")
        db.add(sbom)
        db.flush()
        db.add_all(
            [
                SBOMComponent(
                    sbom_id=sbom.id,
                    name="Python",
                    version=version,
                    purl=f"pkg:generic/python@{version}",
                    component_type="application",
                )
                for version in ("3.7.1", "3.12.1")
            ]
        )
        db.commit()
        summary = LifecycleEnrichmentService().enrich_sbom(db, sbom.id, force_refresh=True)
        assert summary["updated_components"] == 2 and not summary["provider_errors"]
        components = list(
            db.scalars(select(SBOMComponent).where(SBOMComponent.sbom_id == sbom.id).order_by(SBOMComponent.version))
        )
        assert {c.lifecycle_status for c in components} == {"EOL", "Supported"}
        assert all(c.lifecycle_source == "endoflife.date" and c.lifecycle_evidence_json["cycle"] for c in components)
        assert requests and all("/python/" in url or "/python.json" in url for url in requests)
        cache = list(db.scalars(select(ComponentLifecycleCache)))
        assert len(cache) == 2
        assert all(
            abs((datetime.fromisoformat(c.expires_at) - datetime.now(UTC) - timedelta(days=2)).total_seconds()) < 5
            for c in cache
        )
        config = service.get_config(db, "endoflife_date")
        assert config.last_lookup_at is not None
        calls = len(requests)
        assert LifecycleEnrichmentService().enrich_sbom(db, sbom.id)["cache_hits"] == 2
        assert len(requests) == calls
        for row in cache:
            row.expires_at = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
        db.commit()
        assert LifecycleEnrichmentService().enrich_sbom(db, sbom.id)["provider_lookups"] == 2
        assert len(requests) > calls
        report = LifecycleEnrichmentService().lifecycle_report(db, sbom.id)
        assert len(report["components"]) == 2
        assert {c["lifecycle_status"] for c in report["components"]} == {"EOL", "Supported"}
        # A forced lookup outage must not renew valid evidence or lose its provenance.
        expiration = {row.id: row.expires_at for row in db.scalars(select(ComponentLifecycleCache))}
        monkeypatch.setattr(provider_http.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.0.0.1", 443))])
        blocked = LifecycleEnrichmentService().enrich_sbom(db, sbom.id, force_refresh=True)
        assert blocked["provider_errors"]
        assert all("blocked_destination" in error for error in blocked["provider_errors"])
        assert {row.id: row.expires_at for row in db.scalars(select(ComponentLifecycleCache))} == expiration
        db.expire_all()
        refreshed = list(db.scalars(select(SBOMComponent).where(SBOMComponent.sbom_id == sbom.id)))
        assert {c.lifecycle_status for c in refreshed} == {"EOL", "Supported"}
        assert all(c.lifecycle_evidence_json.get("refresh_errors") for c in refreshed)


def test_component_and_sbom_lifecycle_routes_reject_foreign_tenant(client):
    with SessionLocal() as db:
        other = declare_fixture_tenant(db, 875, name="Lifecycle isolation fixture")
        other_id = other.id
        with verified_fixture_tenant(db, other_id):
            sbom = SBOMSource(sbom_name="foreign lifecycle", sbom_data="{}", status="validated")
            db.add(sbom)
            db.flush()
            component = SBOMComponent(sbom_id=sbom.id, name="foreign", version="1", component_type="library")
            db.add(component)
            db.commit()
            component_id = component.id
            component_public_id, sbom_public_id = str(component.public_id), str(sbom.public_id)
    requests = [
        ("GET", f"/api/lifecycle/component/{component_public_id}", None),
        ("POST", f"/api/components/{component_public_id}/lifecycle/refresh", None),
        (
            "PATCH",
            f"/api/components/{component_public_id}/lifecycle-override",
            {"lifecycle_status": "EOL", "reason": "cross tenant"},
        ),
        ("PUT", f"/api/lifecycle/component/{component_public_id}", {"lifecycle_status": "EOL", "reason": "cross tenant"}),
        ("POST", f"/api/sboms/{sbom_public_id}/lifecycle/refresh", None),
        ("GET", f"/api/sboms/{sbom_public_id}/lifecycle", None),
    ]
    for method, path, payload in requests:
        response = client.request(method, path, json=payload)
        assert response.status_code in {403, 404}, (path, response.status_code, response.text)
    with SessionLocal() as db, verified_fixture_tenant(db, other_id):
        row = db.get(SBOMComponent, component_id)
        assert not row.lifecycle_manual_override and row.lifecycle_source is None
