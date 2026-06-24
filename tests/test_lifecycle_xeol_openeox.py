from __future__ import annotations

import json
import zipfile
from datetime import date
from io import BytesIO

import pytest
from app.db import SessionLocal
from app.models import ComponentLifecycleCache, SBOMComponent, SBOMSource
from app.services.lifecycle import LifecycleEnrichmentService
from app.services.lifecycle.decision_engine import choose_lifecycle_result
from app.services.lifecycle.provider_base import LifecycleProvider
from app.services.lifecycle.types import (
    DEPRECATED,
    EOL,
    HIGH,
    SUPPORTED,
    LifecycleResult,
    NormalizedComponent,
)
from app.services.lifecycle.vendor_lifecycle_provider import VendorLifecycleProvider
from app.services.lifecycle.xeol_provider import XeolProvider
from app.settings import reset_settings
from sqlalchemy import select


@pytest.fixture()
def db(client):
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def _component() -> NormalizedComponent:
    return NormalizedComponent(
        component_id=None,
        name="Go",
        version="1.15.2",
        normalized_name="go",
        normalized_version="1.15.2",
        ecosystem="generic",
        purl="pkg:generic/go@1.15.2",
        supplier="The Go Authors",
    )


def test_xeol_provider_maps_documented_nested_response():
    calls = []

    def post(url, payload, headers):
        calls.append((url, payload, headers))
        return {
            "error": None,
            "result": {
                "componentName": "Go",
                "version": {"version": "1.15.2"},
                "eol": {
                    "now": {
                        "primary": {
                            "reason": "vendor_announced",
                            "date": "2021-08-16T00:00:00.000Z",
                        }
                    },
                    "future": None,
                },
                "lifecycles": [{"uri": "https://go.dev/doc/devel/release"}],
            },
        }

    result = XeolProvider(
        api_key="secret",
        http_post=post,
        today=date(2026, 6, 22),
    ).lookup(_component())

    assert result.lifecycle_status == EOL
    assert result.eol_date == "2021-08-16"
    assert result.source_name == "Xeol"
    assert result.source_url == "https://go.dev/doc/devel/release"
    assert result.confidence == HIGH
    assert result.evidence["reason"] == "vendor_announced"
    assert result.evidence["authority"] == "vendor-derived"
    assert calls[0][1] == {"component": {"name": "go", "version": "1.15.2", "ecosystem": "generic"}}
    assert calls[0][2]["Authorization"] == "Bearer secret"


def test_xeol_provider_maps_flat_registry_deprecation_response():
    result = XeolProvider(
        http_post=lambda *_args: {
            "eol": True,
            "eol_reason": "REGISTRY_DEPRECATED",
            "match": {"found": True},
        },
        today=date(2026, 6, 22),
    ).lookup(_component())

    assert result.lifecycle_status == DEPRECATED
    assert result.deprecated is True


def test_default_provider_chain_wires_configured_vendor_and_xeol(monkeypatch):
    monkeypatch.setenv("LIFECYCLE_XEOL_ENABLED", "true")
    monkeypatch.setenv("LIFECYCLE_XEOL_API_KEY", "configured-key")
    monkeypatch.setenv(
        "LIFECYCLE_VENDOR_RECORDS_JSON",
        json.dumps(
            [
                {
                    "name": "go",
                    "cycle": "1.15",
                    "eol_date": "2021-08-16",
                    "source_url": "https://go.dev/doc/devel/release",
                }
            ]
        ),
    )
    reset_settings()
    try:
        providers = LifecycleEnrichmentService().providers
    finally:
        reset_settings()

    assert isinstance(providers[0], VendorLifecycleProvider)
    xeol_providers = [provider for provider in providers if isinstance(provider, XeolProvider)]
    assert len(xeol_providers) == 1
    assert xeol_providers[0].api_key == "configured-key"


def test_vendor_lifecycle_record_is_authoritative_over_aggregator():
    vendor = VendorLifecycleProvider(
        [
            {
                "name": "go",
                "cycle": "1.15",
                "eol_date": "2021-08-16",
                "latest_supported_version": "1.24.4",
                "source_url": "https://go.dev/doc/devel/release",
            }
        ],
        today=date(2026, 6, 22),
    ).lookup(_component())
    aggregator = LifecycleResult(
        component_name="go",
        component_version="1.15.2",
        ecosystem="generic",
        purl="pkg:generic/go@1.15.2",
        lifecycle_status=SUPPORTED,
        source_name="endoflife.date",
        confidence=HIGH,
    )

    chosen = choose_lifecycle_result([aggregator, vendor])

    assert chosen is vendor
    assert chosen.lifecycle_status == EOL
    assert chosen.source_url == "https://go.dev/doc/devel/release"
    assert chosen.recommended_version == "1.24.4"
    assert chosen.evidence["authority"] == "vendor"


def test_xeol_eol_signal_is_not_hidden_by_supported_aggregator_result():
    xeol = LifecycleResult(
        component_name="go",
        component_version="1.15.2",
        ecosystem="generic",
        purl=None,
        lifecycle_status=EOL,
        source_name="Xeol",
        confidence=HIGH,
    )
    endoflife = LifecycleResult(
        component_name="go",
        component_version="1.15.2",
        ecosystem="generic",
        purl=None,
        lifecycle_status=SUPPORTED,
        source_name="endoflife.date",
        confidence=HIGH,
    )

    assert choose_lifecycle_result([endoflife, xeol]) is xeol


class FailIfCalledProvider(LifecycleProvider):
    name = "must-not-run"

    def lookup(self, component: NormalizedComponent) -> LifecycleResult:
        raise AssertionError("provider was called instead of the database cache")


def test_vendor_result_persists_to_component_and_cache(db):
    sbom = SBOMSource(sbom_name="vendor-cache-e2e", sbom_data="{}", status="validated")
    db.add(sbom)
    db.flush()
    component = SBOMComponent(
        sbom_id=sbom.id,
        name="go",
        version="1.15.2",
        purl="pkg:generic/go@1.15.2",
        supplier="The Go Authors",
    )
    db.add(component)
    db.commit()
    provider = VendorLifecycleProvider(
        [
            {
                "name": "go",
                "cycle": "1.15",
                "eol_date": "2021-08-16",
                "source_url": "https://go.dev/doc/devel/release",
            }
        ],
        today=date(2026, 6, 22),
    )

    first = LifecycleEnrichmentService(providers=[provider]).enrich_component(db, component)
    db.commit()
    db.refresh(component)

    assert first.lifecycle_status == EOL
    assert component.lifecycle_status == EOL
    assert component.lifecycle_source == "Vendor Lifecycle"
    assert component.lifecycle_evidence_json["authority"] == "vendor"
    cached = db.execute(
        select(ComponentLifecycleCache).where(ComponentLifecycleCache.lookup_key == "purl:pkg:generic/go@1.15.2")
    ).scalar_one()
    assert cached.lifecycle_status == EOL
    assert cached.source_url == "https://go.dev/doc/devel/release"

    second = LifecycleEnrichmentService(providers=[FailIfCalledProvider()]).enrich_component(db, component)
    assert second.lifecycle_status == EOL
    assert second.source_name == "Vendor Lifecycle"


def test_openeox_api_and_report_pack_use_persisted_lifecycle_data(client, db):
    sbom = SBOMSource(sbom_name="openeox-api", sbom_data="{}", status="validated")
    db.add(sbom)
    db.flush()
    component = SBOMComponent(
        sbom_id=sbom.id,
        name="go",
        version="1.15.2",
        purl="pkg:generic/go@1.15.2",
        supplier="The Go Authors",
        lifecycle_status=EOL,
        eol_date="2021-08-16",
        eof_date="2021-08-16",
        lifecycle_source="Vendor Lifecycle",
        lifecycle_source_url="https://go.dev/doc/devel/release",
        lifecycle_confidence=HIGH,
        lifecycle_checked_at="2026-06-22T10:00:00Z",
        lifecycle_evidence_json={"authority": "vendor"},
    )
    db.add(component)
    db.commit()

    response = client.get(f"/api/sboms/{sbom.id}/lifecycle/report?format=openeox")
    assert response.status_code == 200
    assert response.headers["content-disposition"].endswith('lifecycle.openeox.json"')
    document = response.json()
    assert document["$schema"].endswith("/shell.json")
    statement = document["statements"][0]
    assert statement["core"]["end_of_life"] == "2021-08-16T00:00:00Z"
    assert statement["core"]["end_of_security_support"] == "2021-08-16T00:00:00Z"
    assert statement["product"] == {
        "$schema": "https://docs.oasis-open.org/openeox/tbd/schema/product_software.json",
        "product_name": "go",
        "product_version": "1.15.2",
        "vendor_name": "The Go Authors",
    }
    assert statement["product_identification_helper"]["purl"] == "pkg:generic/go@1.15.2"

    pack = client.get(f"/api/sboms/{sbom.id}/reports/lifecycle-pack")
    assert pack.status_code == 200
    with zipfile.ZipFile(BytesIO(pack.content)) as archive:
        assert "lifecycle.openeox.json" in archive.namelist()
        packed = json.loads(archive.read("lifecycle.openeox.json"))
    assert packed == document
