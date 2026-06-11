"""Integration test for PR-C (roadmap #6): a finding from each strategy
path carries the correct ``match_strategy`` end-to-end, dict → row.

Three live strategies today:
  * ``cpe_name``    — NVD via ``nvd_query_by_cpe``
  * ``purl_direct`` — OSV via ``osv_query_by_components``
                       (and the per-component ``/v1/query`` fallback in
                       ``app/sources/osv_fallback.py``; same tag)
  * ``ghsa_alias``  — GHSA via ``github_query_by_components``

The two NVD-spec'd-but-unreachable strategies (``virtual_match_string``,
``keyword_search``) are intentionally not exercised here — they have
zero call sites in the live codebase today and adding a synthetic emit
path would test code that does not run in production.

Each test monkeypatches the relevant source-side coroutine to return
exactly one synthetic finding carrying the expected strategy tag,
exercises the production analyze endpoint, and asserts the resulting
``analysis_finding`` row reflects the value.
"""

from __future__ import annotations

import pytest


def _make_finding(*, vuln_id: str, source: str, strategy: str) -> dict:
    return {
        "vuln_id": vuln_id,
        "aliases": [],
        "sources": [source],
        "description": f"Synthetic {source} finding for {strategy} integration test.",
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
        "match_strategy": strategy,
    }


async def _empty(*args, **kwargs):
    return [], [], []


def _read_row(run_id: int, vuln_id: str):
    from app.db import SessionLocal
    from app.models import AnalysisFinding
    from sqlalchemy import select

    db = SessionLocal()
    try:
        rows = (
            db.execute(
                select(AnalysisFinding).where(
                    AnalysisFinding.analysis_run_id == run_id,
                    AnalysisFinding.vuln_id == vuln_id,
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1, (
            f"expected one row for vuln_id={vuln_id!r}, got {len(rows)}"
        )
        return rows[0]
    finally:
        db.close()


@pytest.mark.parametrize(
    "source_attr,source_label,strategy,vuln_id",
    [
        (
            "nvd_query_by_components_async",
            "NVD",
            "cpe_name",
            "CVE-STRATEGY-CPE-NAME",
        ),
        (
            "osv_query_by_components",
            "OSV",
            "purl_direct",
            "CVE-STRATEGY-PURL-DIRECT",
        ),
        (
            "github_query_by_components",
            "GITHUB",
            "ghsa_alias",
            "GHSA-STRATEGY-ALIAS-XYZW",
        ),
    ],
)
def test_each_strategy_tag_flows_dict_to_row(
    client, seeded_sbom, monkeypatch, source_attr, source_label, strategy, vuln_id
):
    """End-to-end: a synthetic finding emitted by a given source with
    its strategy tag set produces a row whose ``match_strategy`` column
    matches.
    """
    finding = _make_finding(vuln_id=vuln_id, source=source_label, strategy=strategy)

    async def _emit_one(*args, **kwargs):
        return ([finding], [], [])

    import app.analysis as analysis_mod

    # Patch the target source to emit our synthetic finding; zero the
    # other two so the test isolates one strategy at a time.
    for attr in (
        "nvd_query_by_components_async",
        "osv_query_by_components",
        "github_query_by_components",
    ):
        if attr == source_attr:
            monkeypatch.setattr(analysis_mod, attr, _emit_one)
        else:
            monkeypatch.setattr(analysis_mod, attr, _empty)

    sbom_id = seeded_sbom["id"]
    resp = client.post(f"/api/sboms/{sbom_id}/analyze")
    assert resp.status_code == 201, resp.text
    run_id = resp.json()["id"]

    row = _read_row(run_id, vuln_id)
    assert row.match_strategy == strategy, (
        f"expected match_strategy={strategy!r} for {source_label} finding, "
        f"got {row.match_strategy!r}"
    )
