"""
Contract test for R6: NvdSource consults its injected lookup_service
before the live NVD path.

Independent of app.pipeline.* and tests.nvd_mirror.* — exercises only
the adapter-level injection contract that the runner-side production
path relies on.
"""

from __future__ import annotations

import asyncio


def test_nvd_source_routes_through_lookup_service_when_provided(monkeypatch):
    """When a lookup_service callable is wired, NvdSource routes per-CPE
    lookups through it. The live nvd_query_by_cpe path must NOT be hit."""
    from app.sources.nvd import NvdSource

    captured: list[tuple[str, str | None]] = []

    def fake_lookup(cpe, api_key, settings):
        captured.append((cpe, api_key))
        # Minimal raw NVD record so _finding_from_raw produces a finding.
        return [
            {
                "id": "CVE-LOOKUP-1",
                "descriptions": [{"lang": "en", "value": "from lookup"}],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "references": [],
                "published": "2024-01-01T00:00:00.000",
                "lastModified": "2024-04-01T00:00:00.000",
                "vulnStatus": "Analyzed",
            }
        ]

    # Belt-and-braces: a regression that bypasses the lookup_service must
    # surface as a test failure, not a silent live-NVD call.
    import app.analysis as analysis_mod

    live_calls: list[str] = []

    def fake_live(cpe, api_key, settings=None):
        live_calls.append(cpe)
        return [{"id": "CVE-LIVE-WAS-CALLED"}]

    monkeypatch.setattr(analysis_mod, "nvd_query_by_cpe", fake_live)

    cfg = analysis_mod.get_analysis_settings_multi()
    components = [
        {
            "name": "x",
            "version": "1.0",
            "cpe": "cpe:2.3:a:x:x:1.0:*:*:*:*:*:*:*",
        }
    ]

    src = NvdSource(api_key="fake", lookup_service=fake_lookup)
    result = asyncio.run(src.query(components, cfg))

    assert captured, "lookup_service was not called"
    assert captured[0][0] == components[0]["cpe"], (
        f"lookup_service got the wrong CPE: {captured!r}"
    )
    assert captured[0][1] == "fake", (
        f"lookup_service did not receive the constructor api_key: {captured!r}"
    )
    assert live_calls == [], (
        f"live nvd_query_by_cpe was called despite lookup_service: {live_calls!r}"
    )
    assert any(
        f.get("vuln_id") == "CVE-LOOKUP-1" for f in result["findings"]
    ), f"lookup result did not flow through to findings: {result['findings']!r}"


def test_nvd_source_falls_back_to_live_when_lookup_service_is_none(monkeypatch):
    """Without a lookup_service, NvdSource hits live NVD via
    nvd_query_by_components_async — preserves the pre-R6 default."""
    from app.sources.nvd import NvdSource

    import app.analysis as analysis_mod

    live_calls: list[str] = []

    def fake_live(cpe, api_key, settings=None):
        live_calls.append(cpe)
        return []

    monkeypatch.setattr(analysis_mod, "nvd_query_by_cpe", fake_live)

    cfg = analysis_mod.get_analysis_settings_multi()
    components = [
        {
            "name": "y",
            "version": "2.0",
            "cpe": "cpe:2.3:a:y:y:2.0:*:*:*:*:*:*:*",
        }
    ]

    src = NvdSource(api_key="fake")  # no lookup_service
    asyncio.run(src.query(components, cfg))

    assert live_calls == [components[0]["cpe"]], (
        f"live path was not consulted: {live_calls!r}"
    )
