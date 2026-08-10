from __future__ import annotations

from dataclasses import replace as dataclass_replace

import pytest
from app.analysis import get_analysis_settings_multi, github_query_by_components
from app.sources.applicability import (
    NormalizedAdvisory,
    NormalizedComponent,
    evaluate_applicability,
    evaluate_fixed_version_fallback,
    evaluate_github_vulnerable_range,
)
from app.sources.dedupe import deduplicate_findings
from app.sources.version_range import ApplicabilityStatus


def _component(name: str, version: str, ecosystem: str = "PyPI") -> NormalizedComponent:
    return NormalizedComponent(
        name=name,
        normalized_name=name,
        version=version,
        ecosystem=ecosystem,
        purl=f"pkg:pypi/{name.lower()}@{version}",
    )


def _advisory(
    package_name: str,
    *,
    ecosystem: str = "PIP",
    vulnerable_range: str | None = None,
    fixed_version: str | None = None,
) -> NormalizedAdvisory:
    return NormalizedAdvisory(
        provider="GITHUB",
        advisory_id="GHSA-test",
        package_name=package_name,
        ecosystem=ecosystem,
        vulnerable_range=vulnerable_range,
        fixed_version=fixed_version,
    )


@pytest.mark.parametrize(
    ("name", "installed", "fixed", "expected"),
    [
        ("pillow", "12.2.0", "10.0.1", ApplicabilityStatus.NOT_AFFECTED),
        ("pillow", "12.2.0", "3.1.1", ApplicabilityStatus.NOT_AFFECTED),
        ("pillow", "12.2.0", "12.2.0", ApplicabilityStatus.NOT_AFFECTED),
        ("pillow", "12.1.0", "12.2.0", ApplicabilityStatus.AFFECTED),
        ("cryptography", "44.0.0", "39.0.1", ApplicabilityStatus.NOT_AFFECTED),
        ("reportlab", "4.4.10", "3.5.28", ApplicabilityStatus.NOT_AFFECTED),
        ("pyyaml", "6.0.3", "5.4", ApplicabilityStatus.NOT_AFFECTED),
    ],
)
def test_fixed_version_fallback_uses_pep440(name: str, installed: str, fixed: str, expected: ApplicabilityStatus) -> None:
    result = evaluate_fixed_version_fallback(installed, fixed, ecosystem="pypi")
    assert result.status is expected
    assert result.fixed_version == str(fixed)


@pytest.mark.parametrize(
    ("installed", "vulnerable_range", "expected"),
    [
        ("12.2.0", "< 10.0.1", ApplicabilityStatus.NOT_AFFECTED),
        ("9.5.0", "< 10.0.1", ApplicabilityStatus.AFFECTED),
        ("12.2.0", "<= 12.2.0", ApplicabilityStatus.AFFECTED),
        ("12.2.0", "< 12.2.0", ApplicabilityStatus.NOT_AFFECTED),
        ("9.5.0", ">= 8.0.0, < 10.0.1", ApplicabilityStatus.AFFECTED),
        ("12.2.0", ">= 8.0.0, < 10.0.1", ApplicabilityStatus.NOT_AFFECTED),
        ("9.5.0", "8.0.0 - 9.5.0", ApplicabilityStatus.AFFECTED),
        ("9.5.0", "= 9.5.0", ApplicabilityStatus.AFFECTED),
    ],
)
def test_github_vulnerable_ranges(installed: str, vulnerable_range: str, expected: ApplicabilityStatus) -> None:
    result = evaluate_github_vulnerable_range(installed, vulnerable_range, ecosystem="pypi")
    assert result.status is expected


def test_malformed_github_range_is_unknown_not_confirmed() -> None:
    result = evaluate_github_vulnerable_range("12.2.0", "definitely vulnerable someday", ecosystem="pypi")
    assert result.status is ApplicabilityStatus.UNKNOWN


def test_ecosystem_mismatch_is_not_affected() -> None:
    result = evaluate_applicability(
        _component("pillow", "12.2.0", ecosystem="PyPI"),
        _advisory("pillow", ecosystem="NPM", vulnerable_range="< 99.0.0"),
    )
    assert result.status is ApplicabilityStatus.NOT_AFFECTED


def test_package_name_match_but_wrong_package_is_not_affected() -> None:
    result = evaluate_applicability(
        _component("pillow", "12.2.0"),
        _advisory("pillow-simd", vulnerable_range="< 99.0.0"),
    )
    assert result.status is ApplicabilityStatus.NOT_AFFECTED


def test_range_takes_priority_over_fixed_version() -> None:
    result = evaluate_applicability(
        _component("pillow", "12.2.0"),
        _advisory("pillow", vulnerable_range="<= 12.2.0", fixed_version="12.2.1"),
    )
    assert result.status is ApplicabilityStatus.AFFECTED


def test_same_ghsa_from_github_and_osv_dedupes_to_one_finding() -> None:
    findings = [
        {
            "vuln_id": "GHSA-test",
            "aliases": ["CVE-2099-0001"],
            "sources": ["GITHUB"],
            "component_name": "pillow",
            "component_version": "12.1.0",
            "ecosystem": "pypi",
            "applicability_status": "affected",
        },
        {
            "vuln_id": "OSV-test",
            "aliases": ["GHSA-test", "CVE-2099-0001"],
            "sources": ["OSV"],
            "component_name": "pillow",
            "component_version": "12.1.0",
            "ecosystem": "pypi",
            "applicability_status": "affected",
        },
    ]
    merged = deduplicate_findings(findings)
    assert len(merged) == 1
    assert set(merged[0]["sources"]) == {"GITHUB", "OSV"}


@pytest.mark.asyncio
async def test_github_adapter_drops_50_unaffected_candidates(monkeypatch) -> None:
    nodes = []
    for idx in range(50):
        nodes.append(
            {
                "severity": "HIGH",
                "updatedAt": "2026-01-01T00:00:00Z",
                "advisory": {
                    "ghsaId": f"GHSA-unaffected-{idx:04d}",
                    "summary": "Old Pillow issue",
                    "description": "Fixed before installed version",
                    "publishedAt": "2025-01-01T00:00:00Z",
                    "references": [{"url": "https://github.com/advisories/example"}],
                    "cvss": {"score": 7.5, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
                    "cwes": {"nodes": []},
                    "identifiers": [{"type": "CVE", "value": f"CVE-2099-{idx:04d}"}],
                },
                "vulnerableVersionRange": "< 10.0.1",
                "firstPatchedVersion": {"identifier": "10.0.1"},
                "package": {"name": "pillow", "ecosystem": "PIP"},
            }
        )

    async def _fake_post(*args, **kwargs):
        return {
            "data": {
                "securityVulnerabilities": {
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                    "nodes": nodes,
                }
            }
        }

    import app.analysis as analysis_mod

    monkeypatch.setattr(analysis_mod, "_async_post", _fake_post)
    settings = dataclass_replace(
        get_analysis_settings_multi(),
        gh_token_override="fake-token",
        source_cache_enabled=False,
    )
    findings, errors, warnings = await github_query_by_components(
        [{"name": "pillow", "version": "12.2.0", "purl": "pkg:pypi/pillow@12.2.0", "ecosystem": "PyPI"}],
        settings,
    )
    assert errors == []
    assert warnings == []
    assert findings == []
