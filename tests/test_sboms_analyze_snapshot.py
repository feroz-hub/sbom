"""
Snapshot regression test for the production multi-source analyze endpoint.

This is the path that Finding A converted from three blocking ``asyncio.run()``
calls to a single ``asyncio.gather`` over per-source adapters. R6 then
collapsed the second orchestrator (``app/pipeline/multi_source.py``) so
the runner + adapter chain is the only path. The snapshot below is the
contract; the test will go red if a future refactor changes the
persisted JSON shape.

It also serves as the regression net for Finding B (source-adapter
consolidation): the source fetchers are mocked at the boundary, so any drift
between ``analysis.py`` and the ``app.sources.*`` adapters surfaces here.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ._normalize import normalize

SNAPSHOT_DIR = Path(__file__).parent / "snapshots"
SNAPSHOT_DIR.mkdir(exist_ok=True)


def _load_or_write(name: str, actual: dict) -> dict:
    """
    Standard 'capture-on-first-run' snapshot helper.

    On first run (no snapshot file present), the normalised actual response is
    written to disk and the test passes — that captured file becomes the
    locked baseline.

    On every subsequent run, actual is normalised and compared byte-for-byte
    against the captured file. To intentionally re-baseline, delete the file.
    """
    path = SNAPSHOT_DIR / f"{name}.json"
    if not path.exists():
        path.write_text(json.dumps(actual, indent=2, sort_keys=True))
        return actual
    return json.loads(path.read_text())


@pytest.mark.snapshot
def test_post_sbom_analyze_returns_locked_shape(client, seeded_sbom, mock_external_sources):
    sbom_id = seeded_sbom["id"]

    resp = client.post(f"/api/sboms/{sbom_id}/analyze")
    assert resp.status_code == 201, resp.text

    actual = normalize(resp.json())
    expected = _load_or_write("post_sbom_analyze", actual)

    assert actual == expected, (
        "POST /api/sboms/{id}/analyze response shape drifted.\n"
        f"Snapshot: {SNAPSHOT_DIR / 'post_sbom_analyze.json'}\n"
        "If this is intentional, delete the snapshot file and re-run."
    )


@pytest.mark.snapshot
def test_post_sbom_analyze_severity_buckets_and_status(client, seeded_sbom, mock_external_sources):
    """
    Behavioural assertions that don't depend on the snapshot file — these
    document the *invariants* of the multi-source path so a refactor can't
    silently regress them.
    """
    sbom_id = seeded_sbom["id"]
    resp = client.post(f"/api/sboms/{sbom_id}/analyze")
    assert resp.status_code == 201
    body = resp.json()

    # The mock fixture returns:
    #   - log4j-core: NVD CRITICAL + GHSA CRITICAL  (deduped to one finding)
    #   - requests:   OSV HIGH
    # so we expect at least one CRITICAL and one HIGH finding.
    assert body["total_findings"] >= 2
    assert body["critical_count"] >= 1
    assert body["high_count"] >= 1

    # Run status is FAIL because there are findings (no errors).
    assert body["run_status"] == "FAIL"

    # Source label must enumerate every source the orchestrator actually used.
    assert "NVD" in body["source"]
    assert "OSV" in body["source"]
    assert "GITHUB" in body["source"]
    assert "(partial)" not in body["source"]
