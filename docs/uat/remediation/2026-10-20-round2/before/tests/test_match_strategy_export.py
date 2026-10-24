"""Export tests for PR-C: the per-finding CSV and SARIF exports carry
``match_strategy`` + #1's ``match_reason`` / ``matched_range``.

Notes on scope, surfaced in PR-C's recon:
  * The brief asked for CSV / SARIF / XLSX in ``compare_export.py``.
    Reality: per-finding exports live in ``app/routers/analysis.py``
    (CSV at line 273, SARIF at line 177); ``compare_export.py`` is the
    compare-diff exporter (Markdown/CSV/JSON shape). **There is no
    XLSX export in the codebase** — so this file tests CSV + SARIF
    only.
  * Extending the compare-diff CSV (``compare_export.py``) requires
    adding optional fields to ``FindingDiffRow`` (currently
    ``extra="forbid"``) AND modifying the compare service that
    builds those rows — out of scope for the additive PR-C. Tracked
    as a follow-up.
"""

from __future__ import annotations

import csv
import io
import json

import pytest

_NVD_TAGGED_FINDING = {
    "vuln_id": "CVE-EXPORT-TEST-0001",
    "aliases": [],
    "sources": ["NVD"],
    "description": "Synthetic finding for the export-column test.",
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
    "applicability_status": "affected",
    "match_strategy": "cpe_name",
    "match_reason": "matched",
    "matched_range": ">= 2.0.0, < 2.17.0",
    # PR-D — confidence persisted alongside strategy + reason; the
    # export test now asserts all four provenance fields.
    "match_confidence": 0.873,
}


async def _empty(*args, **kwargs):
    return [], [], []


@pytest.fixture()
def run_with_tagged_finding(client, seeded_sbom, monkeypatch) -> int:
    """Run an analyze that emits one synthetic NVD finding carrying
    all three provenance fields. Returns the resulting run_id.
    """
    import app.analysis as analysis_mod

    async def _emit_one(components, settings, nvd_api_key=None, lookup_service=None):
        return ([_NVD_TAGGED_FINDING], [], [])

    monkeypatch.setattr(analysis_mod, "nvd_query_by_components_async", _emit_one)
    monkeypatch.setattr(analysis_mod, "osv_query_by_components", _empty)
    monkeypatch.setattr(analysis_mod, "github_query_by_components", _empty)

    sbom_id = seeded_sbom["id"]
    resp = client.post(f"/api/sboms/{sbom_id}/analyze")
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def test_csv_export_includes_provenance_columns(client, run_with_tagged_finding):
    """The per-finding CSV (routers/analysis.py:export_csv) writes the
    three provenance columns in the header AND populates them on the
    row produced by a tagged finding.
    """
    run_id = run_with_tagged_finding
    resp = client.get(f"/api/analysis-runs/{run_id}/export/csv")
    assert resp.status_code == 200, resp.text
    body = resp.text

    reader = csv.DictReader(io.StringIO(body))
    fieldnames = reader.fieldnames or []
    for col in (
        "match_strategy",
        "match_reason",
        "matched_range",
        "match_confidence",
    ):
        assert col in fieldnames, f"missing {col!r} column in CSV export; header was {fieldnames!r}"

    rows = [r for r in reader if r["vuln_id"] == "CVE-EXPORT-TEST-0001"]
    assert len(rows) == 1, f"expected one row for the tagged finding, got {len(rows)}"
    row = rows[0]
    assert row["match_strategy"] == "cpe_name"
    assert row["match_reason"] == "matched"
    assert row["matched_range"] == ">= 2.0.0, < 2.17.0"
    # PR-D — confidence is written with 3-decimal precision.
    assert row["match_confidence"] == "0.873"


def test_sarif_export_includes_provenance_properties(client, run_with_tagged_finding):
    """The per-finding SARIF (routers/analysis.py:export_sarif) puts
    the three provenance values inside the result's ``properties`` so
    GitHub Code Scanning / VS Code / Azure DevOps consumers can read
    them alongside the native fields.
    """
    run_id = run_with_tagged_finding
    resp = client.get(f"/api/analysis-runs/{run_id}/export/sarif")
    assert resp.status_code == 200, resp.text
    payload = json.loads(resp.text)

    runs = payload["runs"]
    assert len(runs) == 1
    results = runs[0]["results"]
    matching = [r for r in results if r["ruleId"] == "CVE-EXPORT-TEST-0001"]
    assert len(matching) == 1, f"expected one SARIF result for the tagged finding, got {len(matching)}"
    props = matching[0]["properties"]
    assert props.get("match_strategy") == "cpe_name"
    assert props.get("match_reason") == "matched"
    assert props.get("matched_range") == ">= 2.0.0, < 2.17.0"
    # PR-D — confidence comes through as a JSON number, not stringified.
    assert props.get("match_confidence") == pytest.approx(0.873, abs=1e-6)
