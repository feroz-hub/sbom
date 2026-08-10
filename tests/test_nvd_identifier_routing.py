"""NVD identifier routing, SSL resilience, and multi-source continuation."""

from __future__ import annotations

import pytest
import requests

from tests.fixtures import canned_responses as canned


class _Resp:
    def __init__(self, data: dict):
        self._data = data
        self.status_code = 200
        self.headers = {}

    def raise_for_status(self) -> None:
        pass

    def json(self) -> dict:
        return self._data


def test_nvd_cve_id_uses_cve_ids_param(monkeypatch):
    import app.analysis as analysis_mod

    calls: list[dict] = []

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append(dict(params or {}))
        return _Resp(canned.NVD_EMPTY_RESPONSE)

    monkeypatch.setattr(analysis_mod._nvd_session, "get", fake_get)

    out = analysis_mod.nvd_query_by_identifier(
        "CVE-2025-7546",
        None,
        analysis_mod.get_analysis_settings(),
    )

    assert out == []
    assert len(calls) == 1
    assert calls[0].get("cveIds") == "CVE-2025-7546"
    assert "cpeName" not in calls[0]


def test_nvd_cpe_uses_cpe_name_param(monkeypatch):
    import app.analysis as analysis_mod

    calls: list[dict] = []

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append(dict(params or {}))
        return _Resp(canned.NVD_EMPTY_RESPONSE)

    monkeypatch.setattr(analysis_mod._nvd_session, "get", fake_get)

    cpe = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
    out = analysis_mod.nvd_query_by_identifier(
        cpe,
        None,
        analysis_mod.get_analysis_settings(),
    )

    assert out == []
    assert len(calls) == 1
    assert calls[0].get("cpeName") == cpe
    assert "cveId" not in calls[0]


def test_nvd_invalid_identifier_is_skipped_safely(monkeypatch):
    import app.analysis as analysis_mod

    calls: list[dict] = []

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append(dict(params or {}))
        return _Resp(canned.NVD_EMPTY_RESPONSE)

    monkeypatch.setattr(analysis_mod._nvd_session, "get", fake_get)

    settings = analysis_mod.get_analysis_settings()
    assert analysis_mod.nvd_query_by_identifier("GHSA-xxxx-xxxx-xxxx", None, settings) == []
    assert analysis_mod.nvd_query_by_cpe("CVE-2025-7546", None, settings) == []
    assert calls == []


def test_nvd_ssl_error_is_not_retried(monkeypatch):
    import app.analysis as analysis_mod

    calls = 0

    def fake_get(url, params=None, headers=None, timeout=None):
        nonlocal calls
        calls += 1
        raise requests.exceptions.SSLError("unable to get local issuer certificate")

    monkeypatch.setattr(analysis_mod._nvd_session, "get", fake_get)
    settings = analysis_mod.get_analysis_settings()
    settings = analysis_mod.replace(settings, nvd_max_retries=3)

    with pytest.raises(RuntimeError, match="NVD query failed"):
        analysis_mod.nvd_query_by_cpe(
            "cpe:2.3:a:x:x:1.0:*:*:*:*:*:*:*",
            None,
            settings,
        )

    assert calls == 1


@pytest.mark.asyncio
async def test_analysis_continues_when_nvd_fails(monkeypatch):
    import app.analysis as analysis_mod
    from app.sources import NvdSource, OsvSource
    from app.sources.runner import run_sources_concurrently

    calls = 0

    def failing_nvd(identifier, api_key, settings=None):
        nonlocal calls
        calls += 1
        raise requests.exceptions.SSLError("unable to get local issuer certificate")

    async def fake_osv(components, settings):
        return [{"vuln_id": "OSV-CONTINUES", "source": "OSV"}], [], []

    monkeypatch.setattr(analysis_mod, "nvd_query_by_identifier", failing_nvd)
    monkeypatch.setattr(analysis_mod, "osv_query_by_components", fake_osv)

    components = [
        {
            "name": "x",
            "version": "1.0",
            "cpe": "cpe:2.3:a:x:x:1.0:*:*:*:*:*:*:*",
        }
    ]
    cfg = analysis_mod.get_analysis_settings_multi()

    findings, errors, _warnings = await run_sources_concurrently(
        [NvdSource(), OsvSource()],
        components,
        cfg,
    )

    assert any(f.get("vuln_id") == "OSV-CONTINUES" for f in findings)
    assert not any(e.get("source") == "NVD" for e in errors)
    assert calls == 0, "untrusted CPEs must never reach any NVD transport"


@pytest.mark.asyncio
async def test_nvd_components_async_skips_cve_in_cpe_field(monkeypatch):
    """A malformed CPE field is not a trusted CVE enrichment source."""
    import app.analysis as analysis_mod

    captured: list[dict] = []

    def fake_identifier(identifier, api_key, settings=None):
        captured.append({"identifier": identifier})
        return []

    monkeypatch.setattr(analysis_mod, "nvd_query_by_identifier", fake_identifier)

    components = [
        {
            "name": "vuln-ref",
            "version": "1.0",
            "cpe": "CVE-2025-7546",
        }
    ]
    cfg = analysis_mod.get_analysis_settings_multi()
    findings, errors, _warnings = await analysis_mod.nvd_query_by_components_async(
        components,
        cfg,
        nvd_api_key=None,
    )

    assert findings == []
    assert errors == []
    assert captured == []
