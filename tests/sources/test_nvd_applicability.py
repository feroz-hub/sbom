from __future__ import annotations

import pytest
from app.sources.dedupe import deduplicate_findings
from app.sources.version_range import (
    ApplicabilityStatus,
    evaluate_nvd_configurations,
    evaluate_nvd_cpe_match,
    evaluate_version_bounds,
)

PILLOW = {
    "name": "pillow",
    "normalized_name": "pillow",
    "version": "12.2.0",
    "ecosystem": "PyPI",
    "purl": "pkg:pypi/pillow@12.2.0",
    "cpe": "cpe:2.3:a:python:pillow:12.2.0:*:*:*:*:*:*:*",
    "cpe_source": "trusted_mapping",
}


def _match(**extra):
    data = {
        "vulnerable": True,
        "criteria": "cpe:2.3:a:python:pillow:*:*:*:*:*:*:*:*",
    }
    data.update(extra)
    return data


def _cve(nodes):
    return {"configurations": [{"nodes": nodes}]}


@pytest.mark.parametrize(
    ("installed", "bounds", "expected"),
    [
        ("12.2.0", {"versionEndExcluding": "12.2.0"}, ApplicabilityStatus.NOT_AFFECTED),
        ("12.1.1", {"versionEndExcluding": "12.2.0"}, ApplicabilityStatus.AFFECTED),
        ("12.2.0", {"versionEndIncluding": "12.2.0"}, ApplicabilityStatus.AFFECTED),
        ("12.2.1", {"versionEndIncluding": "12.2.0"}, ApplicabilityStatus.NOT_AFFECTED),
        ("12.2.0", {"versionStartIncluding": "12.2.0"}, ApplicabilityStatus.AFFECTED),
        ("12.2.0", {"versionStartExcluding": "12.2.0"}, ApplicabilityStatus.NOT_AFFECTED),
        ("12.2.1", {"versionStartExcluding": "12.2.0"}, ApplicabilityStatus.AFFECTED),
        ("12.2.0", {"versionEndExcluding": "9.0.1"}, ApplicabilityStatus.NOT_AFFECTED),
        ("12.2.0", {"versionEndExcluding": "10.2.0"}, ApplicabilityStatus.NOT_AFFECTED),
        ("12.2.0", {"versionEndExcluding": "12.2.0"}, ApplicabilityStatus.NOT_AFFECTED),
    ],
)
def test_pypi_pep440_boundaries(installed, bounds, expected):
    result = evaluate_version_bounds(installed, "PyPI", _match(**bounds))
    assert result.status is expected


def test_keyword_candidate_without_matching_cpe_product_is_not_confirmed():
    result = evaluate_nvd_cpe_match(PILLOW, _match(criteria="cpe:2.3:a:python:pil:*:*:*:*:*:*:*:*"))
    assert result.status is ApplicabilityStatus.NOT_AFFECTED


def test_matching_package_name_different_vendor_product_is_not_confirmed():
    result = evaluate_nvd_cpe_match(PILLOW, _match(criteria="cpe:2.3:a:other:pillow:*:*:*:*:*:*:*:*"))
    assert result.status is ApplicabilityStatus.NOT_AFFECTED


def test_vulnerable_false_application_match_is_not_confirmed():
    result = evaluate_nvd_cpe_match(PILLOW, _match(vulnerable=False))
    assert result.status is ApplicabilityStatus.NOT_AFFECTED


def test_invalid_installed_version_is_unknown():
    component = dict(PILLOW, version="not a version")
    result = evaluate_nvd_cpe_match(component, _match(versionEndExcluding="12.2.0"))
    assert result.status is ApplicabilityStatus.UNKNOWN


def test_same_cve_from_multiple_providers_dedupes_to_one_finding():
    findings = [
        {"vuln_id": "CVE-1", "sources": ["NVD"], "component_name": "pillow", "component_version": "12.2.0", "ecosystem": "pypi"},
        {"vuln_id": "OSV-1", "aliases": ["CVE-1"], "sources": ["OSV"], "component_name": "pillow", "component_version": "12.2.0", "ecosystem": "pypi"},
        {"vuln_id": "GHSA-1", "aliases": ["CVE-1"], "sources": ["GITHUB"], "component_name": "pillow", "component_version": "12.2.0", "ecosystem": "pypi"},
    ]
    merged = deduplicate_findings(findings)
    assert len(merged) == 1
    assert set(merged[0]["sources"]) == {"NVD", "OSV", "GITHUB"}


def test_or_node_one_applicable_child_is_affected():
    cve = _cve([
        {"operator": "OR", "cpeMatch": [_match(versionEndExcluding="12.2.0"), _match(criteria="cpe:2.3:a:x:y:*:*:*:*:*:*:*:*")]}
    ])
    component = dict(PILLOW, version="12.1.0")
    assert evaluate_nvd_configurations(cve, component).status is ApplicabilityStatus.AFFECTED


def test_or_node_all_children_not_applicable_is_not_affected():
    cve = _cve([
        {"operator": "OR", "cpeMatch": [_match(criteria="cpe:2.3:a:x:y:*:*:*:*:*:*:*:*")]}
    ])
    assert evaluate_nvd_configurations(cve, PILLOW).status is ApplicabilityStatus.NOT_AFFECTED


def test_and_node_with_environmental_requirement_is_unknown():
    cve = {"configurations": [{"operator": "AND", "nodes": [
        {"operator": "OR", "cpeMatch": [_match(versionEndIncluding="12.2.0")]},
        {"operator": "OR", "cpeMatch": [{"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"}]},
    ]}]}
    assert evaluate_nvd_configurations(cve, PILLOW).status is ApplicabilityStatus.UNKNOWN


def test_negated_matching_node_is_inverted():
    cve = _cve([
        {"operator": "OR", "negate": True, "cpeMatch": [_match(versionEndIncluding="12.2.0")]}
    ])
    assert evaluate_nvd_configurations(cve, PILLOW).status is ApplicabilityStatus.NOT_AFFECTED
