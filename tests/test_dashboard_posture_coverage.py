"""Dashboard posture must not call an unassessed scope clean.

The severity counts cannot tell "every source looked and found nothing" apart
from "OSV and NVD assessed 0 of 69 components" — both are zero. The posture
payload therefore carries ``coverage_status``, derived from the SAME predicate
the run status uses (``app.sources.routing.has_incomplete_source_coverage``).
"""

from __future__ import annotations

import json

import pytest
from app import metrics
from app.db import Base
from app.metrics.runs import CoverageAssessment
from app.models import AnalysisRun, SBOMSource
from app.services.dashboard_metrics import compute_posture_coverage
from app.sources.routing import summarize_source
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker


@pytest.fixture()
def db() -> Session:
    """Isolated in-memory schema — this suite only needs run rows."""
    import app.models  # noqa: F401  (registers every table on Base)

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _complete(source: str, *, queried: int = 69, matched: int = 0) -> dict:
    return summarize_source(source, queried=queried, matched=matched, skipped=0, errors=0)


def _skipped_all(source: str, *, reason: str, skipped: int = 69) -> dict:
    return summarize_source(
        source, queried=0, matched=0, skipped=skipped, errors=0, status="skipped", reason=reason
    )


def _reported_case_summary() -> list[dict]:
    """GITHUB covered 69 components; OSV and NVD covered none."""
    return [
        _complete("GITHUB"),
        _skipped_all("OSV", reason="missing_supported_package_identity"),
        _skipped_all("NVD", reason="missing_authoritative_cpe"),
    ]


def _seed_run(
    db,
    *,
    sbom_name: str,
    run_status: str,
    source_summary: list[dict] | None,
    total_findings: int = 0,
    query_error_count: int = 0,
    source: str = "NVD,OSV,GITHUB",
) -> AnalysisRun:
    sbom = SBOMSource(sbom_name=sbom_name, sbom_data="{}", is_active=True)
    db.add(sbom)
    db.flush()
    details: dict = {"findings": [], "total_findings": total_findings}
    if source_summary is not None:
        details["source_summary"] = source_summary
        details["analysis_metadata"] = {"source_summary": source_summary}
    run = AnalysisRun(
        sbom_id=sbom.id,
        run_status=run_status,
        source=source,
        started_on="2026-08-06T10:00:00Z",
        completed_on="2026-08-06T10:00:05Z",
        duration_ms=5,
        total_components=69,
        total_findings=total_findings,
        query_error_count=query_error_count,
        raw_report=json.dumps(details),
    )
    db.add(run)
    db.flush()
    return run


# ---------------------------------------------------------------------------
# The reported runtime case
# ---------------------------------------------------------------------------


def test_partial_run_with_skipped_sources_reports_incomplete(db):
    _seed_run(
        db,
        sbom_name="coverage-partial",
        run_status="PARTIAL",
        source_summary=_reported_case_summary(),
        source="NVD,OSV,GITHUB (partial)",
    )

    assessment = metrics.runs_latest_per_sbom_coverage(db)

    assert assessment.status == "incomplete"
    assert assessment.gap_sources == ["OSV", "NVD"]


def test_service_wrapper_returns_status_and_gap_sources(db):
    _seed_run(
        db,
        sbom_name="coverage-partial-service",
        run_status="PARTIAL",
        source_summary=_reported_case_summary(),
    )

    status, gap_sources = compute_posture_coverage(db)

    assert status == "incomplete"
    assert gap_sources == ["OSV", "NVD"]


# ---------------------------------------------------------------------------
# Complete / unknown
# ---------------------------------------------------------------------------


def test_ok_run_with_full_coverage_reports_complete(db):
    _seed_run(
        db,
        sbom_name="coverage-ok",
        run_status="OK",
        source_summary=[_complete("NVD"), _complete("OSV"), _complete("GITHUB")],
    )

    assessment = metrics.runs_latest_per_sbom_coverage(db)

    assert assessment.status == "complete"
    assert assessment.gap_sources == []


def test_no_runs_at_all_reports_unknown(db):
    assert metrics.runs_latest_per_sbom_coverage(db) == CoverageAssessment("unknown", [])


def test_findings_run_with_skipped_source_reports_incomplete(db):
    """FINDINGS says nothing about coverage — the summary is the only signal."""
    _seed_run(
        db,
        sbom_name="coverage-findings",
        run_status="FINDINGS",
        total_findings=4,
        source_summary=[
            _complete("GITHUB", matched=4),
            _skipped_all("OSV", reason="missing_supported_package_identity"),
        ],
    )

    assessment = metrics.runs_latest_per_sbom_coverage(db)

    assert assessment.status == "incomplete"
    assert assessment.gap_sources == ["OSV"]


def test_findings_run_with_full_coverage_reports_complete(db):
    _seed_run(
        db,
        sbom_name="coverage-findings-complete",
        run_status="FINDINGS",
        total_findings=4,
        source_summary=[_complete("GITHUB", matched=4), _complete("OSV"), _complete("NVD")],
    )

    assert metrics.runs_latest_per_sbom_coverage(db).status == "complete"


def test_source_errors_report_incomplete_without_reading_the_summary(db):
    """A failed lookup is coverage the run did not get."""
    _seed_run(
        db,
        sbom_name="coverage-errored",
        run_status="OK",
        source_summary=None,
        query_error_count=2,
    )

    assert metrics.runs_latest_per_sbom_coverage(db).status == "incomplete"


def test_partial_source_label_marker_reports_incomplete(db):
    """The persisted ``(partial)`` label is written from the shared helper."""
    _seed_run(
        db,
        sbom_name="coverage-label",
        run_status="FINDINGS",
        total_findings=1,
        source_summary=None,
        source="NVD,OSV,GITHUB (partial)",
    )

    assert metrics.runs_latest_per_sbom_coverage(db).status == "incomplete"


def test_legacy_run_without_summary_is_not_downgraded(db):
    """Absence of per-source telemetry is not evidence of a gap."""
    _seed_run(db, sbom_name="coverage-legacy", run_status="OK", source_summary=None, source="BACKFILL")

    assert metrics.runs_latest_per_sbom_coverage(db).status == "complete"


def test_unparseable_raw_report_does_not_raise(db):
    run = _seed_run(db, sbom_name="coverage-broken", run_status="FINDINGS", total_findings=1, source_summary=None)
    run.raw_report = "{not json"
    db.flush()

    assert metrics.runs_latest_per_sbom_coverage(db).status == "complete"


# ---------------------------------------------------------------------------
# Aggregation across SBOMs — worst coverage wins
# ---------------------------------------------------------------------------


def test_one_incomplete_sbom_makes_the_portfolio_incomplete(db):
    _seed_run(
        db,
        sbom_name="coverage-mixed-ok",
        run_status="OK",
        source_summary=[_complete("NVD"), _complete("OSV"), _complete("GITHUB")],
    )
    _seed_run(
        db,
        sbom_name="coverage-mixed-partial",
        run_status="PARTIAL",
        source_summary=_reported_case_summary(),
    )

    assessment = metrics.runs_latest_per_sbom_coverage(db)

    assert assessment.status == "incomplete"
    assert set(assessment.gap_sources) == {"OSV", "NVD"}


# ---------------------------------------------------------------------------
# The predicate is shared, not re-implemented
# ---------------------------------------------------------------------------


def test_coverage_metric_delegates_to_the_routing_helper(db, monkeypatch):
    """The verdict for a summary-bearing run must come from
    ``app.sources.routing.has_incomplete_source_coverage`` — not a local copy
    of the rule."""
    _seed_run(
        db,
        sbom_name="coverage-delegation",
        run_status="FINDINGS",
        total_findings=1,
        source_summary=[_complete("GITHUB", matched=1)],
    )

    calls: list[object] = []
    import app.metrics.runs as runs_metrics

    def _spy(summary):
        calls.append(summary)
        return True  # force the shared predicate's answer through

    monkeypatch.setattr(runs_metrics, "has_incomplete_source_coverage", _spy)

    assessment = runs_metrics.runs_latest_per_sbom_coverage(db)

    assert calls, "the shared routing predicate was never consulted"
    assert assessment.status == "incomplete", "the shared predicate's verdict must decide the status"


@pytest.mark.parametrize("run_status", ["ERROR", "RUNNING", "PENDING", "NO_DATA"])
def test_unsuccessful_runs_are_out_of_scope(db, run_status):
    """Same scope as every other posture metric: latest *successful* run."""
    _seed_run(db, sbom_name=f"coverage-scope-{run_status}", run_status=run_status, source_summary=None)

    assert metrics.runs_latest_per_sbom_coverage(db).status == "unknown"
