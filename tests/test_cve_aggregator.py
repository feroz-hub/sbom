"""
Aggregator merge-rule tests — covers every "one source down" permutation
the prompt's §2.8 calls out, plus the all-fail degraded path.

These are pure-Python tests: the aggregator never touches HTTP or the DB,
so we feed it ``FetchResult`` instances directly.
"""

from __future__ import annotations

from app.integrations.cve.aggregator import merge
from app.integrations.cve.base import FetchOutcome, FetchResult
from app.schemas_cve import CveSeverity


# ---------------------------------------------------------------- helpers

OSV_DATA = {
    "summary": "OSV summary line",
    "details": "OSV long-form details, longer than the summary.",
    "aliases": ["GHSA-fake-osv", "CVE-2099-9001"],
    "severity_hint": "high",
    "fix_versions": [
        {"ecosystem": "npm", "package": "left-pad", "fixed_in": "1.3.1", "introduced_in": "0.0.1", "range": None}
    ],
    "references": [
        {"label": "Advisory", "url": "https://example.com/osv-advisory", "type": "advisory"},
        {"label": "Web", "url": "https://example.com/dup", "type": "web"},
    ],
    "published": "2024-01-15T00:00:00Z",
    "modified": "2024-01-20T00:00:00Z",
}

GHSA_DATA = {
    "title": "Remote code execution in left-pad",
    "summary": "GHSA description, the canonical prose.",
    "severity": "critical",
    "aliases": ["GHSA-fake-osv"],
    "ghsa_id": "GHSA-fake-osv",
    "cwe_ids": ["CWE-79"],
    "cwe_titles": {"CWE-79": "Cross-site Scripting"},
    "fix_versions": [
        {"ecosystem": "npm", "package": "left-pad", "fixed_in": "1.3.1", "introduced_in": None, "range": "<1.3.1"},
        {"ecosystem": "npm", "package": "left-pad", "fixed_in": "2.0.0", "introduced_in": None, "range": ">=1.4,<2.0"},
    ],
    "references": [{"label": "GHSA", "url": "https://github.com/advisories/x", "type": "advisory"}],
    "published": "2024-01-16T00:00:00Z",
    "modified": "2024-01-20T00:00:00Z",
}

NVD_DATA = {
    "summary": "NVD CVE description",
    "cvss_v3_score": 9.8,
    "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_v4_score": 9.3,
    "cvss_v4_vector": "CVSS:4.0/AV:N/AC:L",
    "attack_vector": "NETWORK",
    "attack_complexity": "LOW",
    "privileges_required": "NONE",
    "user_interaction": "NONE",
    "cwe_ids": ["CWE-79", "CWE-89"],
    "references": [
        {"label": "NVD", "url": "https://nvd.nist.gov/x", "type": "advisory"},
        {"label": "NVD", "url": "https://example.com/patch", "type": "patch"},
    ],
    "published": "2024-01-15T00:00:00Z",
    "modified": "2024-01-22T00:00:00Z",
}

EPSS_DATA = {"score": 0.42, "percentile": 0.91}
KEV_DATA = {"listed": True, "due_date": "2024-02-15", "vulnerability_name": "RCE"}


def _ok(name: str, data: dict) -> FetchResult:
    return FetchResult(source=name, outcome=FetchOutcome.OK, data=data)


def _err(name: str) -> FetchResult:
    return FetchResult(source=name, outcome=FetchOutcome.ERROR, error="boom")


def _missing(name: str) -> FetchResult:
    return FetchResult(source=name, outcome=FetchOutcome.NOT_FOUND)


def _disabled(name: str) -> FetchResult:
    return FetchResult(source=name, outcome=FetchOutcome.DISABLED)


# ------------------------------------------------------------------ tests


def test_merge_all_sources_ok():
    """Happy path — every source contributes, deterministic merge wins."""
    detail = merge(
        "CVE-2099-9001",
        [
            _ok("osv", OSV_DATA),
            _ok("ghsa", GHSA_DATA),
            _ok("nvd", NVD_DATA),
            _ok("epss", EPSS_DATA),
            _ok("kev", KEV_DATA),
        ],
    )
    # GHSA wins on summary + title + severity
    assert detail.summary == "GHSA description, the canonical prose."
    assert detail.title == "Remote code execution in left-pad"
    assert detail.severity == CveSeverity.CRITICAL
    # NVD wins on CVSS scores
    assert detail.cvss_v3_score == 9.8
    assert detail.cvss_v3_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert detail.cvss_v4_score == 9.3
    # CWE union
    assert detail.cwe_ids == ["CWE-79", "CWE-89"]
    # Fix-version dedup: 1.3.1 collapses, 2.0.0 stays.
    fixed = sorted([fv.fixed_in for fv in detail.fix_versions])
    assert fixed == ["1.3.1", "2.0.0"]
    # References: dedup by URL, capped at 25
    urls = [str(r.url) for r in detail.references]
    assert len(urls) == len(set(urls))
    assert "https://github.com/advisories/x" in urls
    # EPSS / KEV
    assert detail.exploitation.epss_score == 0.42
    assert detail.exploitation.epss_percentile == 0.91
    assert detail.exploitation.cisa_kev_listed is True
    assert detail.exploitation.attack_vector == "NETWORK"
    assert detail.exploitation.attack_complexity == "LOW"
    # Aliases — union, no self-reference
    assert "GHSA-fake-osv" in detail.aliases
    assert "CVE-2099-9001" not in detail.aliases
    # Sources used recorded
    assert set(detail.sources_used) == {"osv", "ghsa", "nvd", "epss", "kev"}
    assert detail.is_partial is False


def test_merge_falls_back_to_osv_when_ghsa_missing():
    """Without GHSA, OSV summary wins (NVD remains for CVSS only)."""
    detail = merge(
        "CVE-2099-9001",
        [_ok("osv", OSV_DATA), _missing("ghsa"), _ok("nvd", NVD_DATA), _missing("epss"), _missing("kev")],
    )
    assert detail.summary == "OSV summary line"
    assert detail.title is None
    # OSV severity_hint = high (cvss_v3_score is also 9.8 critical, but OSV hint comes first in preference)
    assert detail.severity == CveSeverity.HIGH
    assert detail.is_partial is False


def test_merge_severity_derived_from_cvss_when_no_prose_source_severity():
    """No GHSA / OSV severity → derived from CVSS v3 score."""
    detail = merge(
        "CVE-2099-9001",
        [_missing("osv"), _missing("ghsa"), _ok("nvd", NVD_DATA), _missing("epss"), _missing("kev")],
    )
    assert detail.severity == CveSeverity.CRITICAL  # 9.8 → CRITICAL


def test_merge_partial_flag_when_ghsa_errors():
    """Source error → is_partial=True; rest of merge succeeds."""
    detail = merge(
        "CVE-2099-9001",
        [_ok("osv", OSV_DATA), _err("ghsa"), _ok("nvd", NVD_DATA), _ok("epss", EPSS_DATA), _ok("kev", KEV_DATA)],
    )
    assert detail.is_partial is True
    assert "ghsa" not in detail.sources_used
    assert detail.summary == "OSV summary line"  # falls back to OSV


def test_merge_partial_flag_when_osv_errors():
    detail = merge(
        "CVE-2099-9001",
        [_err("osv"), _ok("ghsa", GHSA_DATA), _ok("nvd", NVD_DATA), _ok("epss", EPSS_DATA), _ok("kev", KEV_DATA)],
    )
    assert detail.is_partial is True
    # OSV-only fix-version row is gone, GHSA's two rows remain.
    assert {fv.fixed_in for fv in detail.fix_versions} == {"1.3.1", "2.0.0"}


def test_merge_partial_flag_when_nvd_errors():
    detail = merge(
        "CVE-2099-9001",
        [_ok("osv", OSV_DATA), _ok("ghsa", GHSA_DATA), _err("nvd"), _ok("epss", EPSS_DATA), _ok("kev", KEV_DATA)],
    )
    assert detail.is_partial is True
    assert detail.cvss_v3_score is None
    assert detail.exploitation.attack_vector is None


def test_merge_circuit_open_does_not_flip_partial_alone():
    """CIRCUIT_OPEN by itself is a normal operating state (not an error)."""
    detail = merge(
        "CVE-2099-9001",
        [
            _ok("osv", OSV_DATA),
            _ok("ghsa", GHSA_DATA),
            FetchResult(source="nvd", outcome=FetchOutcome.CIRCUIT_OPEN),
            _ok("epss", EPSS_DATA),
            _ok("kev", KEV_DATA),
        ],
    )
    assert detail.is_partial is False  # circuit-open is silent
    assert "nvd" not in detail.sources_used


def test_merge_disabled_source_is_silent():
    """DISABLED (no token configured) does not flip is_partial either."""
    detail = merge(
        "CVE-2099-9001",
        [_ok("osv", OSV_DATA), _disabled("ghsa"), _missing("nvd"), _ok("epss", EPSS_DATA), _missing("kev")],
    )
    assert detail.is_partial is False
    assert "ghsa" not in detail.sources_used


def test_merge_all_fail_returns_minimal_payload():
    """Every source down → still returns a payload, never raises."""
    detail = merge(
        "CVE-2099-9001",
        [_err("osv"), _err("ghsa"), _err("nvd"), _err("epss"), _err("kev")],
    )
    assert detail.cve_id == "CVE-2099-9001"
    assert detail.summary == ""
    assert detail.severity == CveSeverity.UNKNOWN
    assert detail.is_partial is True
    assert detail.sources_used == []
    assert detail.fix_versions == []
    assert detail.references == []


def test_merge_references_capped_at_25():
    """Reference list is hard-capped to keep payload size predictable."""
    big = {"references": [{"label": "X", "url": f"https://example.com/r{i}", "type": "web"} for i in range(40)]}
    detail = merge("CVE-2099-9002", [_ok("osv", big)])
    assert len(detail.references) == 25


def test_merge_kev_due_date_parses():
    """KEV ``due_date`` string maps to a ``date``."""
    detail = merge("CVE-2099-9003", [_ok("kev", {"listed": True, "due_date": "2024-02-15"})])
    assert detail.exploitation.cisa_kev_listed is True
    assert detail.exploitation.cisa_kev_due_date is not None
    assert detail.exploitation.cisa_kev_due_date.isoformat() == "2024-02-15"


def test_merge_invalid_kev_due_date_falls_through():
    detail = merge("CVE-2099-9004", [_ok("kev", {"listed": True, "due_date": "garbage"})])
    assert detail.exploitation.cisa_kev_listed is True
    assert detail.exploitation.cisa_kev_due_date is None
