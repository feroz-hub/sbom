"""Regression test for PR-C's persistence flow (roadmap #6).

PR-C added ``match_strategy`` to every per-source finding dict and added
one explicit-kwarg line at ``analysis_service.persist_analysis_run`` to
forward it onto the ``analysis_finding`` row. The pattern mirrors PR4's
``match_reason`` / ``matched_range`` plumbing — and inherits its
silent-drop risk: a future PR that touches the AnalysisFinding(...)
constructor and removes the kwarg would silently NULL the column in
production while logs and dashboards looked fine.

This test inflicts a synthetic NVD finding with ``match_strategy`` set,
exercises the production ``POST /api/sboms/{id}/analyze`` flow, and
asserts the resulting ``analysis_finding`` row carries the value. It
mirrors the fixture pattern in
``test_persist_match_reason_regression.py``.
"""

from __future__ import annotations

import pytest

_NVD_FINDING_WITH_STRATEGY = {
    "vuln_id": "CVE-MATCH-STRATEGY-REGRESSION",
    "aliases": [],
    "sources": ["NVD"],
    "description": "Synthetic finding for the match_strategy persistence regression.",
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
    # PR-C sets this on every kept finding at the per-source emit step.
    "match_strategy": "cpe_name",
}


async def _fake_nvd_with_strategy(
    components, settings, nvd_api_key=None, lookup_service=None
):
    return ([_NVD_FINDING_WITH_STRATEGY], [], [])


async def _fake_empty_async(*args, **kwargs):
    return [], [], []


@pytest.fixture()
def mock_nvd_with_strategy_tagged_finding(monkeypatch):
    import app.analysis as analysis_mod

    monkeypatch.setattr(
        analysis_mod, "nvd_query_by_components_async", _fake_nvd_with_strategy
    )
    monkeypatch.setattr(analysis_mod, "osv_query_by_components", _fake_empty_async)
    monkeypatch.setattr(analysis_mod, "github_query_by_components", _fake_empty_async)


def test_persist_analysis_run_forwards_match_strategy(
    client, seeded_sbom, mock_nvd_with_strategy_tagged_finding
):
    """A finding dict carrying ``match_strategy`` must produce an
    ``analysis_finding`` row with the column populated. Guards against
    the explicit-kwarg-list pattern silently dropping the new key.
    """
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
                    AnalysisFinding.vuln_id == "CVE-MATCH-STRATEGY-REGRESSION",
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1, (
            f"expected exactly one row for the synthetic finding, "
            f"got {len(rows)}"
        )
        row = rows[0]
        assert row.match_strategy == "cpe_name", (
            f"match_strategy was {row.match_strategy!r}; "
            "persist_analysis_run is dropping the field — the explicit-"
            "kwarg constructor at analysis_service.py:243 needs the kwarg"
        )
    finally:
        db.close()


def test_persist_analysis_run_tolerates_missing_match_strategy(
    client, seeded_sbom, monkeypatch
):
    """Parity case: a finding dict without ``match_strategy`` must
    persist with NULL and no KeyError. ``.get`` semantics in the
    persistence layer guarantee this — guard it so a future refactor
    to ``finding["match_strategy"]`` is caught immediately.
    """
    pre_pr_c_finding = {
        k: v
        for k, v in _NVD_FINDING_WITH_STRATEGY.items()
        if k != "match_strategy"
    }
    pre_pr_c_finding["vuln_id"] = "CVE-PRE-PR-C-SHAPE"

    async def _fake_nvd_without_strategy(
        components, settings, nvd_api_key=None, lookup_service=None
    ):
        return ([pre_pr_c_finding], [], [])

    import app.analysis as analysis_mod

    monkeypatch.setattr(
        analysis_mod, "nvd_query_by_components_async", _fake_nvd_without_strategy
    )
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
                    AnalysisFinding.vuln_id == "CVE-PRE-PR-C-SHAPE",
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1
        assert rows[0].match_strategy is None
    finally:
        db.close()
