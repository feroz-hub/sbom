from __future__ import annotations

from pathlib import Path

import certifi
import pytest
from app.db import Base
from app.models import NvdLookupCache
from app.services.nvd_cache_service import NvdCacheService
from app.services.nvd_client import (
    NvdRateLimitedError,
    NvdTemporarilyUnavailableError,
    NvdTimeoutError,
    build_headers,
    build_nvd_params_for_cpe,
    build_nvd_params_for_cve_batch,
    get_ca_bundle,
    parse_retry_after,
)
from app.services.nvd_enrichment_service import NvdEnrichmentService, collect_nvd_identifiers
from app.settings import Settings
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()


def cfg(**updates) -> Settings:
    settings = Settings(
        nvd_enabled=True,
        nvd_min_delay_with_api_key_seconds=0,
        nvd_min_delay_without_api_key_seconds=0,
    )
    return settings.model_copy(update=updates)


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.params = []

    def request_nvd(self, params):
        self.params.append(params)
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


def cpe_component(name="apache", source="sbom_provided"):
    return {
        "name": name,
        "version": "1.0",
        "cpe": f"cpe:2.3:a:{name}:{name}:1.0:*:*:*:*:*:*:*",
        "cpe_source": source,
    }


def payload(*cve_ids):
    return {"vulnerabilities": [{"cve": {"id": item, "descriptions": [], "metrics": {}}} for item in cve_ids]}


def test_cve_ids_use_cve_ids_and_maximum_100():
    values = [f"CVE-2026-{10000 + i}" for i in range(100)]
    assert build_nvd_params_for_cve_batch(values) == {"cveIds": ",".join(values)}
    with pytest.raises(ValueError, match="100"):
        build_nvd_params_for_cve_batch(values + ["CVE-2026-99999"])


def test_single_cve_still_uses_cve_ids():
    assert build_nvd_params_for_cve_batch(["cve-2026-1234"]) == {"cveIds": "CVE-2026-1234"}


def test_trusted_cpe_uses_cpe_name_and_untrusted_are_skipped():
    trusted = cpe_component()
    generated = cpe_component("generated", "generated_fallback")
    blocked = cpe_component("valid-lifecycle-runtimes")
    found = collect_nvd_identifiers([trusted, generated, blocked])
    assert found.trusted_cpes == [(trusted["cpe"], trusted)]
    assert found.skipped_generated_cpe == 1
    assert found.skipped_untrusted_cpe == 1
    assert build_nvd_params_for_cpe(trusted["cpe"]) == {"cpeName": trusted["cpe"]}


def test_purl_only_does_not_generate_lookup_and_identifiers_deduplicate():
    comp = {"name": "django", "version": "3.2", "purl": "pkg:pypi/django@3.2"}
    found = collect_nvd_identifiers(
        [comp, comp],
        [{"vuln_id": "cve-2026-1234", "aliases": ["CVE-2026-1234"]}],
    )
    assert found.trusted_cpes == []
    assert found.cve_ids == ["CVE-2026-1234"]


def test_cache_hit_avoids_http(db):
    cache = NvdCacheService(db, cfg())
    cache.save_success("CVE-2026-1234", "CVE_ID", {"id": "CVE-2026-1234"})
    db.commit()
    client = FakeClient([])
    result = NvdEnrichmentService(db, cfg(), client=client, cache=cache).enrich([], [{"vuln_id": "CVE-2026-1234"}])
    assert client.params == []
    assert result["provider_status"]["cache_hits"] == 1


def test_batch_success_and_missing_id_are_cached_individually(db):
    client = FakeClient([payload("CVE-2026-1234")])
    NvdEnrichmentService(db, cfg(), client=client).enrich(
        [], [{"vuln_id": "CVE-2026-1234"}, {"vuln_id": "CVE-2026-5678"}]
    )
    rows = {row.identifier: row for row in db.execute(select(NvdLookupCache)).scalars()}
    assert client.params == [{"cveIds": "CVE-2026-1234,CVE-2026-5678"}]
    assert rows["CVE-2026-1234"].status == "success"
    assert rows["CVE-2026-5678"].status == "no_result"


@pytest.mark.parametrize(
    ("error", "status"),
    [
        (NvdTemporarilyUnavailableError("down", http_status=503), "failed"),
        (NvdTimeoutError("slow"), "timeout"),
    ],
)
def test_temporary_failures_are_negative_cached(db, error, status):
    result = NvdEnrichmentService(db, cfg(), client=FakeClient([error])).enrich([], [{"vuln_id": "CVE-2026-1234"}])
    assert db.execute(select(NvdLookupCache)).scalar_one().status == status
    assert result["provider_status"]["status"] == "degraded"


def test_rate_limit_retry_after_is_parsed_and_cached(db):
    assert parse_retry_after("12") == 12
    error = NvdRateLimitedError("limited", http_status=429, retry_after=12)
    NvdEnrichmentService(db, cfg(), client=FakeClient([error])).enrich([], [{"vuln_id": "CVE-2026-1234"}])
    assert db.execute(select(NvdLookupCache)).scalar_one().status == "rate_limited"


def test_circuit_breaker_stops_remaining_calls(db):
    components = [cpe_component(f"vendor{i}") for i in range(5)]
    failures = [NvdTemporarilyUnavailableError("down", http_status=503) for _ in range(5)]
    client = FakeClient(failures)
    result = NvdEnrichmentService(
        db, cfg(nvd_failure_threshold=2, nvd_max_cpe_lookups_per_scan=5), client=client
    ).enrich(components, [])
    assert len(client.params) == 2
    assert result["provider_status"]["circuit_breaker_open"] is True


def test_api_key_and_ca_bundle_resolution(monkeypatch):
    assert build_headers(cfg(nvd_api_key="secret"))["apiKey"] == "secret"
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/tmp/requests-ca.pem")
    monkeypatch.setenv("SSL_CERT_FILE", "/tmp/ssl-ca.pem")
    assert get_ca_bundle() == "/tmp/requests-ca.pem"
    monkeypatch.delenv("REQUESTS_CA_BUNDLE")
    assert get_ca_bundle() == "/tmp/ssl-ca.pem"
    monkeypatch.delenv("SSL_CERT_FILE")
    assert get_ca_bundle() == certifi.where()


def test_project_code_never_disables_tls_verification():
    root = Path(__file__).resolve().parents[1] / "app"
    offenders = []
    for path in root.rglob("*.py"):
        text = path.read_text()
        if "verify=False" in text or "verify = False" in text:
            offenders.append(path)
    assert offenders == []


def test_manual_six_component_scenario_only_uses_known_cve_batch(db):
    components = [
        cpe_component("valid-lifecycle-runtimes", "generated_fallback"),
        {"name": "nodejs", "version": "16.20.2", "purl": "pkg:npm/node@16.20.2"},
        {"name": "python", "version": "3.8.10", "purl": "pkg:generic/python@3.8.10"},
        {"name": "ubuntu", "version": "20.04", "purl": "pkg:deb/ubuntu/ubuntu@20.04"},
        {"name": "postgresql", "version": "12.15", "purl": "pkg:deb/postgresql@12.15"},
        {"name": "django", "version": "3.2.25", "purl": "pkg:pypi/django@3.2.25"},
    ]
    client = FakeClient([payload("CVE-2026-1234")])
    result = NvdEnrichmentService(db, cfg(), client=client).enrich(
        components, [{"vuln_id": "CVE-2026-1234", "component_name": "django"}]
    )
    assert client.params == [{"cveIds": "CVE-2026-1234"}]
    assert result["provider_status"]["skipped_generated_cpe"] == 1
    assert result["provider_status"]["status"] == "success"
