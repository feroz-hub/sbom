"""
Regression test for SOLID-SRP-003 / DRY-005.

The router-side ``persist_analysis_run`` in ``app/routers/sboms_crud.py``
silently drops ``query_error_count`` and ``raw_report`` from every
``AnalysisRun`` row it writes (the columns just default to ``0`` and
``NULL``). The service-side ``persist_analysis_run`` in
``app/services/analysis_service.py`` writes them correctly, but it is
only reached by the startup ``backfill_analytics_tables`` path — every
production analyze endpoint goes through the router copy.

This test inflicts a synthetic source error onto the production
``POST /api/sboms/{id}/analyze`` flow and asserts the persisted row
captures both fields. It will FAIL on ``main`` and PASS after R2 merges
the two implementations into the service-side canonical version.
"""

from __future__ import annotations

import json

import pytest


async def _fake_nvd_with_error(components, settings, nvd_api_key=None):
    return (
        [],
        [{"source": "NVD", "message": "synthetic error for r2 regression"}],
        [],
    )


async def _fake_empty_async(*args, **kwargs):
    return [], [], []


@pytest.fixture()
def mock_sources_with_query_error(monkeypatch):
    import app.analysis as analysis_mod

    monkeypatch.setattr(analysis_mod, "nvd_query_by_components_async", _fake_nvd_with_error)
    monkeypatch.setattr(analysis_mod, "osv_query_by_components", _fake_empty_async)
    monkeypatch.setattr(analysis_mod, "github_query_by_components", _fake_empty_async)


def test_persist_analysis_run_records_query_error_count_and_raw_report(
    client, seeded_sbom, mock_sources_with_query_error
):
    sbom_id = seeded_sbom["id"]

    resp = client.post(f"/api/sboms/{sbom_id}/analyze")
    assert resp.status_code == 201, resp.text
    run_id = resp.json()["id"]

    from app.db import SessionLocal
    from app.models import AnalysisRun

    db = SessionLocal()
    try:
        run = db.get(AnalysisRun, run_id)
        assert run is not None, f"AnalysisRun id={run_id} should exist"

        assert run.query_error_count >= 1, (
            f"query_error_count was {run.query_error_count}; "
            "synthetic NVD error should have been counted (router-side "
            "persist_analysis_run is dropping the field)"
        )

        assert run.raw_report is not None, (
            "raw_report was NULL; router-side persist_analysis_run is "
            "dropping the field — entire details payload is lost"
        )
        parsed = json.loads(run.raw_report)
        assert isinstance(parsed, dict), "raw_report must parse as a JSON object"
        errors = parsed.get("query_errors") or []
        assert any(
            (e or {}).get("message") == "synthetic error for r2 regression"
            for e in errors
        ), f"raw_report.query_errors did not include synthetic error; got {errors!r}"
    finally:
        db.close()
