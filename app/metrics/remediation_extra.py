"""
Remediation extra metrics — Open/fixed vulnerability counts and aging metrics.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AnalysisFinding, AnalysisRun, VulnerabilityRemediation
from ._helpers import latest_run_per_sbom_subquery


def remediation_status_counts(db: Session) -> dict[str, int]:
    """
    Get the count of vulnerabilities grouped by their remediation status
    for all findings in the latest successful runs.
    """
    latest_runs = db.execute(
        select(AnalysisRun.id, AnalysisRun.project_id).where(AnalysisRun.id.in_(latest_run_per_sbom_subquery()))
    ).all()

    run_to_project = {r.id: r.project_id for r in latest_runs}
    run_ids = list(run_to_project.keys())

    counts = {"open": 0, "in_progress": 0, "fixed": 0, "accepted_risk": 0, "closed": 0}

    if not run_ids:
        return counts

    findings = db.execute(
        select(
            AnalysisFinding.vuln_id,
            AnalysisFinding.component_name,
            AnalysisFinding.component_version,
            AnalysisFinding.analysis_run_id,
        ).where(AnalysisFinding.analysis_run_id.in_(run_ids))
    ).all()

    remediations = db.execute(select(VulnerabilityRemediation)).scalars().all()
    rem_map = {
        (rem.project_id, rem.vuln_id, rem.component_name.lower(), rem.component_version): rem.status
        for rem in remediations
    }

    for vuln_id, comp_name, comp_ver, run_id in findings:
        project_id = run_to_project[run_id]
        comp_key = (comp_name or "").strip().lower()
        ver_key = (comp_ver or "").strip()
        status_raw = rem_map.get((project_id, vuln_id, comp_key, ver_key), "Open")
        status = status_raw.lower().replace(" ", "_")

        if status in counts:
            counts[status] += 1
        else:
            counts["open"] += 1

    return counts


def remediation_aging_count(db: Session, days: int = 30) -> int:
    """
    Count of active findings in the latest successful runs that were first detected
    more than `days` ago and have not been resolved (marked Fixed/Closed).
    """
    latest_runs = db.execute(
        select(AnalysisRun.id, AnalysisRun.project_id).where(AnalysisRun.id.in_(latest_run_per_sbom_subquery()))
    ).all()

    run_to_project = {r.id: r.project_id for r in latest_runs}
    run_ids = list(run_to_project.keys())

    if not run_ids:
        return 0

    findings = db.execute(
        select(
            AnalysisFinding.vuln_id,
            AnalysisFinding.component_name,
            AnalysisFinding.component_version,
            AnalysisFinding.analysis_run_id,
        ).where(AnalysisFinding.analysis_run_id.in_(run_ids))
    ).all()

    remediations = db.execute(select(VulnerabilityRemediation)).scalars().all()
    rem_map = {
        (rem.project_id, rem.vuln_id, rem.component_name.lower(), rem.component_version): rem.status
        for rem in remediations
    }

    # Filter out Fixed/Closed findings
    active_findings = []
    for vuln_id, comp_name, comp_ver, run_id in findings:
        project_id = run_to_project[run_id]
        status = rem_map.get((project_id, vuln_id, (comp_name or "").lower(), comp_ver), "Open")
        if status not in ("Fixed", "Closed"):
            active_findings.append((vuln_id, comp_name, comp_ver, project_id))

    if not active_findings:
        return 0

    # Walk all completed runs to determine first_seen date for each active finding
    all_runs = db.execute(
        select(AnalysisRun.id, AnalysisRun.completed_on, AnalysisRun.project_id)
        .where(AnalysisRun.run_status.in_(("OK", "FINDINGS", "PARTIAL")))
        .order_by(AnalysisRun.id.asc())
    ).all()

    run_completed = {r.id: r.completed_on for r in all_runs}
    all_run_ids = list(run_completed.keys())

    # Query findings in all runs for the active findings keys
    first_seen_map = {}
    if all_run_ids:
        finding_rows = db.execute(
            select(
                AnalysisFinding.analysis_run_id,
                AnalysisFinding.vuln_id,
                AnalysisFinding.component_name,
                AnalysisFinding.component_version,
            ).where(AnalysisFinding.analysis_run_id.in_(all_run_ids))
        ).all()

        for run_id, vuln_id, comp_name, comp_ver in finding_rows:
            key = (vuln_id, (comp_name or "").lower(), comp_ver)
            completed_str = run_completed[run_id]
            if not completed_str:
                continue
            try:
                run_date = datetime.fromisoformat(completed_str[:10]).date()
            except ValueError:
                continue

            if key not in first_seen_map or run_date < first_seen_map[key]:
                first_seen_map[key] = run_date

    cutoff_date = datetime.now(UTC).date() - timedelta(days=days)

    aging_count = 0
    for vuln_id, comp_name, comp_ver, _project_id in active_findings:
        key = (vuln_id, (comp_name or "").lower(), comp_ver)
        first_seen = first_seen_map.get(key)
        if first_seen and first_seen < cutoff_date:
            aging_count += 1

    return aging_count
