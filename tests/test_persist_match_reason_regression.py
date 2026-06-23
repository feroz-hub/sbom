"""Regression test for PR3's persistence flow (roadmap #1, PR4 follow-up).

PR3 wired ``app/sources/version_range.cve_affects_component`` into the
NVD emit step. Kept findings now carry two new keys on the in-memory
dict: ``match_reason`` and ``matched_range``. PR2 added the matching
columns on ``analysis_finding``. PR3's follow-up note #5 warned that
``app/services/analysis_service.persist_analysis_run`` constructs
``AnalysisFinding(...)`` with an explicit column list, so any key
absent from that list is silently dropped — the DB would stay blank
while the dogfooding logs looked fine.

This test inflicts a synthetic NVD finding with both keys set,
exercises the production ``POST /api/sboms/{id}/analyze`` flow, and
asserts the resulting ``analysis_finding`` row carries both column
values. It mirrors the fixture pattern in
``test_persist_run_query_errors_regression.py`` so future regressions
on this column-list drift fail loudly.
"""

from __future__ import annotations

import pytest

_NVD_FINDING_WITH_MATCH_TAGS = {
    "vuln_id": "CVE-MATCH-REASON-REGRESSION",
    "aliases": [],
    "sources": ["NVD"],
    "description": "Synthetic finding for the match_reason persistence regression.",
    "severity": "HIGH",
    "score": 7.5,
    "vector": None,
    "attack_vector": None,
    "cvss_version": None,
    "published": "2024-01-15T12:00:00.000",
    "references": [],
    "cwe": [],
    "fixed_versions": [],
    "component_name": "log4j-core",
    "component_version": "2.14.0",
    "cpe": "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*",
    # PR3 sets these on every kept finding when the flag is on.
    "match_reason": "matched",
    "matched_range": ">= 2.0.0, < 2.17.0",
}


async def _fake_nvd_with_match_tags(components, settings, nvd_api_key=None, lookup_service=None):
    return ([_NVD_FINDING_WITH_MATCH_TAGS], [], [])


async def _fake_empty_async(*args, **kwargs):
    return [], [], []


@pytest.fixture()
def mock_nvd_with_match_tagged_finding(monkeypatch):
    import app.analysis as analysis_mod

    monkeypatch.setattr(analysis_mod, "nvd_query_by_components_async", _fake_nvd_with_match_tags)
    monkeypatch.setattr(analysis_mod, "osv_query_by_components", _fake_empty_async)
    monkeypatch.setattr(analysis_mod, "github_query_by_components", _fake_empty_async)


def test_persist_analysis_run_forwards_match_reason_and_range(client, seeded_sbom, mock_nvd_with_match_tagged_finding):
    """A finding dict carrying ``match_reason`` / ``matched_range`` must
    produce an ``analysis_finding`` row with both columns populated.
    Guards against the explicit-column-list pattern silently dropping
    new keys (the failure mode PR3's follow-up note #5 flagged)."""
    sbom_id = seeded_sbom["id"]

    resp = client.post(f"/api/sboms/{sbom_id}/analyze")
    assert resp.status_code == 201, resp.text
    run_id = resp.json()["id"]

    from app.db import SessionLocal
    from app.models import AnalysisFinding
    from sqlalchemy import select

    db = SessionLocal()
    try:
        rows = (
            db.execute(
                select(AnalysisFinding).where(
                    AnalysisFinding.analysis_run_id == run_id,
                    AnalysisFinding.vuln_id == "CVE-MATCH-REASON-REGRESSION",
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1, f"expected exactly one row for the synthetic finding, got {len(rows)}"
        row = rows[0]
        assert row.match_reason == "matched", (
            f"match_reason was {row.match_reason!r}; "
            "persist_analysis_run is dropping the field — "
            "PR3's follow-up note #5 hit"
        )
        assert row.matched_range == ">= 2.0.0, < 2.17.0", (
            f"matched_range was {row.matched_range!r}; persist_analysis_run is dropping the field"
        )
    finally:
        db.close()


def test_persist_analysis_run_tolerates_missing_match_keys(client, seeded_sbom, monkeypatch):
    """Flag-OFF parity: a finding dict without the two new keys must
    persist with NULL in both columns and no KeyError. ``.get`` semantics
    in the persistence layer guarantee this — guard it with a test so a
    future refactor to ``finding["match_reason"]`` is caught immediately.
    """
    pre_pr3_finding = {
        k: v for k, v in _NVD_FINDING_WITH_MATCH_TAGS.items() if k not in {"match_reason", "matched_range"}
    }
    pre_pr3_finding["vuln_id"] = "CVE-PRE-PR3-SHAPE"

    async def _fake_nvd_without_match_tags(components, settings, nvd_api_key=None, lookup_service=None):
        return ([pre_pr3_finding], [], [])

    import app.analysis as analysis_mod

    monkeypatch.setattr(analysis_mod, "nvd_query_by_components_async", _fake_nvd_without_match_tags)
    monkeypatch.setattr(analysis_mod, "osv_query_by_components", _fake_empty_async)
    monkeypatch.setattr(analysis_mod, "github_query_by_components", _fake_empty_async)

    sbom_id = seeded_sbom["id"]
    resp = client.post(f"/api/sboms/{sbom_id}/analyze")
    assert resp.status_code == 201, resp.text
    run_id = resp.json()["id"]

    from app.db import SessionLocal
    from app.models import AnalysisFinding
    from sqlalchemy import select

    db = SessionLocal()
    try:
        rows = (
            db.execute(
                select(AnalysisFinding).where(
                    AnalysisFinding.analysis_run_id == run_id,
                    AnalysisFinding.vuln_id == "CVE-PRE-PR3-SHAPE",
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1
        row = rows[0]
        assert row.match_reason is None
        assert row.matched_range is None
    finally:
        db.close()
