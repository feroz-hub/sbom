"""Regression test for PR-D's persistence flow (roadmap #3).

PR-D added a single explicit-kwarg line at
``analysis_service.persist_analysis_run`` to forward
``match_confidence`` onto the ``analysis_finding`` row. The pattern
mirrors PR-C's ``match_strategy`` plumbing and inherits its silent-
drop risk: a future refactor that loses the kwarg would NULL the
column while logs and dashboards looked fine.

Mirrors the fixture pattern in
``test_persist_match_strategy_regression.py``.
"""

from __future__ import annotations

import pytest


_NVD_FINDING_WITH_CONFIDENCE = {
    "vuln_id": "CVE-MATCH-CONFIDENCE-REGRESSION",
    "aliases": [],
    "sources": ["NVD"],
    "description": "Synthetic finding for the match_confidence persistence regression.",
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
    "match_strategy": "cpe_name",
    # PR-D's scorer rounds to 3 decimals; pick a value that already is.
    "match_confidence": 0.825,
}


async def _fake_nvd_with_confidence(
    components, settings, nvd_api_key=None, lookup_service=None
):
    return ([_NVD_FINDING_WITH_CONFIDENCE], [], [])


async def _fake_empty_async(*args, **kwargs):
    return [], [], []


@pytest.fixture()
def mock_nvd_with_confidence_finding(monkeypatch):
    import app.analysis as analysis_mod

    monkeypatch.setattr(
        analysis_mod, "nvd_query_by_components_async", _fake_nvd_with_confidence
    )
    monkeypatch.setattr(analysis_mod, "osv_query_by_components", _fake_empty_async)
    monkeypatch.setattr(analysis_mod, "github_query_by_components", _fake_empty_async)


def test_persist_analysis_run_forwards_match_confidence(
    client, seeded_sbom, mock_nvd_with_confidence_finding
):
    sbom_id = seeded_sbom["id"]
    resp = client.post(f"/api/sboms/{sbom_id}/analyze")
    assert resp.status_code == 201, resp.text
    run_id = resp.json()["id"]

    from sqlalchemy import select

    from app.db import SessionLocal
    from app.models import AnalysisFinding

    db = SessionLocal()
    try:
        rows = (
            db.execute(
                select(AnalysisFinding).where(
                    AnalysisFinding.analysis_run_id == run_id,
                    AnalysisFinding.vuln_id == "CVE-MATCH-CONFIDENCE-REGRESSION",
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1
        row = rows[0]
        assert row.match_confidence == pytest.approx(0.825, abs=1e-6), (
            f"match_confidence was {row.match_confidence!r}; "
            "persist_analysis_run is dropping the field — the explicit-"
            "kwarg constructor at analysis_service.py needs the kwarg"
        )
    finally:
        db.close()


def test_persist_analysis_run_tolerates_missing_match_confidence(
    client, seeded_sbom, monkeypatch
):
    """Parity case: finding without ``match_confidence`` persists with
    NULL and no KeyError.
    """
    pre_pr_d_finding = {
        k: v
        for k, v in _NVD_FINDING_WITH_CONFIDENCE.items()
        if k != "match_confidence"
    }
    pre_pr_d_finding["vuln_id"] = "CVE-PRE-PR-D-SHAPE"

    async def _fake_nvd_without_confidence(
        components, settings, nvd_api_key=None, lookup_service=None
    ):
        return ([pre_pr_d_finding], [], [])

    import app.analysis as analysis_mod

    monkeypatch.setattr(
        analysis_mod, "nvd_query_by_components_async", _fake_nvd_without_confidence
    )
    monkeypatch.setattr(analysis_mod, "osv_query_by_components", _fake_empty_async)
    monkeypatch.setattr(analysis_mod, "github_query_by_components", _fake_empty_async)

    sbom_id = seeded_sbom["id"]
    resp = client.post(f"/api/sboms/{sbom_id}/analyze")
    assert resp.status_code == 201, resp.text
    run_id = resp.json()["id"]

    from sqlalchemy import select

    from app.db import SessionLocal
    from app.models import AnalysisFinding

    db = SessionLocal()
    try:
        rows = (
            db.execute(
                select(AnalysisFinding).where(
                    AnalysisFinding.analysis_run_id == run_id,
                    AnalysisFinding.vuln_id == "CVE-PRE-PR-D-SHAPE",
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1
        assert rows[0].match_confidence is None
    finally:
        db.close()
