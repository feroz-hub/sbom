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


def test_nvd_query_by_cpe_is_exact_only_no_virtual_match_fallback(monkeypatch):
    """
    Historically ``nvd_query_by_cpe`` fell back to ``virtualMatchString=…``
    when exact ``cpeName=…`` returned nothing. That fallback is deleted
    because the wildcard-vendor-wildcard-product shape
    (``cpe:2.3:a:*:*:<version>:*``) matches every CVE at the given
    version across the entire NVD database — tens of thousands of rows
    paginated at 2000/page × 0.6s sleep = 10+ min per component. One
    runaway query would freeze the whole NVD phase.

    Guard: when exact CPE returns empty, ``nvd_query_by_cpe`` must
    return ``[]`` and MUST NOT issue a ``virtualMatchString`` query.
    """
    import app.analysis as analysis_mod
    from tests.fixtures import canned_responses as canned

    calls: list[dict] = []

    class Resp:
        def __init__(self, data: dict):
            self._data = data
            self.status_code = 200
            self.headers = {}

        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict:
            return self._data

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append(dict(params or {}))
        # Exact CPE → empty. If the wildcard fallback reappears, the
        # next call will land here with a virtualMatchString key and
        # the assertion below will fail.
        return Resp(canned.NVD_EMPTY_RESPONSE)

    monkeypatch.setattr(analysis_mod._nvd_session, "get", fake_get)

    cpe = "cpe:2.3:a:log4j:log4j-core:2.14.1:*:*:*:*:*:*:*"
    out = analysis_mod.nvd_query_by_cpe(cpe, None, analysis_mod.get_analysis_settings())

    assert out == []
    assert len(calls) == 1, (
        f"expected exactly ONE HTTP call (exact CPE only), got {len(calls)}: {calls}"
    )
    assert "cpeName" in calls[0]
    assert "virtualMatchString" not in calls[0], (
        "virtualMatchString fallback is deleted — nvd_query_by_cpe must not issue it"
    )


def test_nvd_virtual_match_helpers():
    from app.analysis import _cpe23_virtual_match_wildcard_vendor, _cpe23_virtual_match_wildcard_vendor_product

    cpe = "cpe:2.3:a:log4j:log4j-core:2.14.1:*:*:*:*:*:*:*"
    assert _cpe23_virtual_match_wildcard_vendor(cpe) == "cpe:2.3:a:*:log4j-core:2.14.1:*:*:*:*:*:*:*"
    assert _cpe23_virtual_match_wildcard_vendor_product(cpe) == "cpe:2.3:a:*:*:2.14.1:*:*:*:*:*:*:*"


def test_nvd_virtual_match_short_cpe_returns_none():
    from app.analysis import _cpe23_virtual_match_wildcard_vendor, _cpe23_virtual_match_wildcard_vendor_product

    assert _cpe23_virtual_match_wildcard_vendor("cpe:2.3:a") is None
    assert _cpe23_virtual_match_wildcard_vendor_product("not-a-cpe") is None
