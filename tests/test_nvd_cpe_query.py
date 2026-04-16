"""Unit tests for PURL→CPE Maven heuristics and NVD virtualMatchString fallback."""

from __future__ import annotations

from app.sources.cpe import cpe23_from_purl


def test_maven_org_apache_log4j_artifact_maps_to_apache_log4j_cpe():
    purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    cpe = cpe23_from_purl(purl)
    assert cpe == "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"


def test_maven_non_apache_group_unchanged_last_segment_vendor():
    purl = "pkg:maven/com.example/demo-lib@1.0.0"
    cpe = cpe23_from_purl(purl)
    assert cpe == "cpe:2.3:a:example:demo-lib:1.0.0:*:*:*:*:*:*:*"


def test_nvd_query_by_cpe_uses_virtual_match_when_cpe_name_empty(monkeypatch):
    import app.analysis as analysis_mod
    from tests.fixtures import canned_responses as canned

    calls: list[dict] = []

    class Resp:
        def __init__(self, data: dict):
            self._data = data
            self.status_code = 200

        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict:
            return self._data

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append(dict(params or {}))
        p = params or {}
        if p.get("cpeName") is not None:
            return Resp(canned.NVD_EMPTY_RESPONSE)
        if p.get("virtualMatchString") is not None:
            return Resp(canned.NVD_LOG4J_RESPONSE)
        return Resp(canned.NVD_EMPTY_RESPONSE)

    monkeypatch.setattr(analysis_mod._nvd_session, "get", fake_get)

    cpe = "cpe:2.3:a:log4j:log4j-core:2.14.1:*:*:*:*:*:*:*"
    out = analysis_mod.nvd_query_by_cpe(cpe, None, analysis_mod.get_analysis_settings())

    assert len(out) >= 1
    assert out[0].get("id") == "CVE-2021-44228"
    assert any("cpeName" in c for c in calls)
    assert any("virtualMatchString" in c for c in calls)


def test_nvd_virtual_match_helpers():
    from app.analysis import _cpe23_virtual_match_wildcard_vendor, _cpe23_virtual_match_wildcard_vendor_product

    cpe = "cpe:2.3:a:log4j:log4j-core:2.14.1:*:*:*:*:*:*:*"
    assert _cpe23_virtual_match_wildcard_vendor(cpe) == "cpe:2.3:a:*:log4j-core:2.14.1:*:*:*:*:*:*:*"
    assert _cpe23_virtual_match_wildcard_vendor_product(cpe) == "cpe:2.3:a:*:*:2.14.1:*:*:*:*:*:*:*"


def test_nvd_virtual_match_short_cpe_returns_none():
    from app.analysis import _cpe23_virtual_match_wildcard_vendor, _cpe23_virtual_match_wildcard_vendor_product

    assert _cpe23_virtual_match_wildcard_vendor("cpe:2.3:a") is None
    assert _cpe23_virtual_match_wildcard_vendor_product("not-a-cpe") is None
