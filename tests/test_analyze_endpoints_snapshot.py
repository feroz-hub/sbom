"""
Snapshot regression tests for the four `/analyze-sbom-*` ad-hoc endpoints.

Each test uploads the same fixture SBOM, hits one endpoint with mocked
external HTTP, and diffs the normalised JSON against a captured baseline.
The baselines were re-captured during the Finding B Phase 4 cut-over to
match the new flat `AnalysisRunOut`-shaped response (which preserves a
backward-compatible `summary.findings.bySeverity` block for the
defensive frontend reader).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ._normalize import normalize

SNAPSHOT_DIR = Path(__file__).parent / "snapshots"
SNAPSHOT_DIR.mkdir(exist_ok=True)


def _load_or_write(name: str, actual: dict) -> dict:
    path = SNAPSHOT_DIR / f"{name}.json"
    if not path.exists():
        path.write_text(json.dumps(actual, indent=2, sort_keys=True))
        return actual
    return json.loads(path.read_text())


@pytest.mark.snapshot
def test_analyze_sbom_nvd(client, seeded_sbom, mock_external_sources):
    resp = client.post(
        "/analyze-sbom-nvd",
        json={"sbom_id": seeded_sbom["id"]},
    )
    assert resp.status_code == 200, resp.text
    actual = normalize(resp.json())
    expected = _load_or_write("analyze_sbom_nvd", actual)
    assert actual == expected


@pytest.mark.snapshot
def test_analyze_sbom_github(client, seeded_sbom, mock_external_sources):
    resp = client.post(
        "/analyze-sbom-github",
        json={"sbom_id": seeded_sbom["id"]},
    )
    assert resp.status_code == 200, resp.text
    actual = normalize(resp.json())
    expected = _load_or_write("analyze_sbom_github", actual)
    assert actual == expected


@pytest.mark.snapshot
def test_analyze_sbom_osv(client, seeded_sbom, mock_external_sources):
    resp = client.post(
        "/analyze-sbom-osv",
        json={"sbom_id": seeded_sbom["id"], "hydrate": True},
    )
    assert resp.status_code == 200, resp.text
    actual = normalize(resp.json())
    expected = _load_or_write("analyze_sbom_osv", actual)
    assert actual == expected


@pytest.mark.snapshot
def test_analyze_sbom_consolidated(client, seeded_sbom, mock_external_sources):
    resp = client.post(
        "/analyze-sbom-consolidated",
        json={
            "sbom_id": seeded_sbom["id"],
            "osv_hydrate": True,
        },
    )
    assert resp.status_code == 200, resp.text
    actual = normalize(resp.json())
    expected = _load_or_write("analyze_sbom_consolidated", actual)
    assert actual == expected
