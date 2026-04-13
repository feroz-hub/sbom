"""
Dashboard Service Layer - Aggregated metrics and statistics for the dashboard.
"""

from __future__ import annotations

import logging
from datetime import UTC
from typing import Any

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from ..models import AnalysisFinding, AnalysisRun, Projects, SBOMComponent, SBOMSource

log = logging.getLogger(__name__)


# ============================================================
# Statistics Aggregation
# ============================================================


def get_stats(db: Session) -> dict[str, Any]:
    """
    Get overall dashboard statistics.

    Args:
        db: Database session

    Returns:
        Dictionary with:
            - total_projects: Count of active projects
            - total_sboms: Count of SBOMs
            - total_vulnerabilities: Sum of findings across all runs
            - total_runs: Count of analysis runs
    """
    total_projects = db.execute(select(func.count(Projects.id)).where(Projects.project_status == 1)).scalar_one() or 0

    total_sboms = db.execute(select(func.count(SBOMSource.id))).scalar_one() or 0

    total_vulns = db.execute(select(func.sum(AnalysisRun.total_findings))).scalar_one() or 0

    total_runs = db.execute(select(func.count(AnalysisRun.id))).scalar_one() or 0

    return {
        "total_projects": total_projects,
        "total_sboms": total_sboms,
        "total_vulnerabilities": total_vulns,
        "total_runs": total_runs,
    }


# ============================================================
# Recent Activity
# ============================================================


def get_recent_sboms(db: Session, limit: int = 5) -> list[dict[str, Any]]:
    """
    Get the most recently created or modified SBOMs.

    Args:
        db: Database session
        limit: Maximum number of results (default 5)

    Returns:
        List of SBOM dictionaries with id, name, project, created_on, component_count, latest_run
    """
    sboms = db.execute(select(SBOMSource).order_by(SBOMSource.created_on.desc()).limit(limit)).scalars().all()

    results = []
    for sbom in sboms:
        # Get component count
        comp_count = (
            db.execute(select(func.count(SBOMComponent.id)).where(SBOMComponent.sbom_id == sbom.id)).scalar_one() or 0
        )

        # Get latest run
        latest_run = (
            db.execute(
                select(AnalysisRun)
                .where(AnalysisRun.sbom_id == sbom.id)
                .order_by(AnalysisRun.completed_on.desc())
                .limit(1)
            )
            .scalars()
            .first()
        )

        project_name = None
        if sbom.project:
            project_name = sbom.project.project_name

        results.append(
            {
                "id": sbom.id,
                "name": sbom.sbom_name,
                "project": project_name,
                "created_on": sbom.created_on,
                "component_count": comp_count,
                "latest_run": {
                    "status": latest_run.run_status if latest_run else None,
                    "completed_on": latest_run.completed_on if latest_run else None,
                    "total_findings": latest_run.total_findings if latest_run else 0,
                }
                if latest_run
                else None,
            }
        )

    return results


def get_activity(db: Session) -> dict[str, Any]:
    """
    Get activity summary: counts of active vs stale SBOMs and projects.

    Active defined as having a run within the last 30 days.
    Stale defined as having no runs or run is older than 30 days.

    Args:
        db: Database session

    Returns:
        Dictionary with:
            - active_sboms: Count of SBOMs with recent runs
            - stale_sboms: Count of SBOMs without recent runs
            - active_projects: Count of projects with recent runs
            - stale_projects: Count of projects without recent runs
    """
    from datetime import datetime

    thirty_days_ago = datetime.now(UTC).replace(microsecond=0).isoformat()[:10]

    # SBOMs with runs in last 30 days
    active_sbom_ids = (
        db.execute(select(AnalysisRun.sbom_id.distinct()).where(AnalysisRun.completed_on >= thirty_days_ago))
        .scalars()
        .all()
    )

    active_sboms = len(set(active_sbom_ids)) if active_sbom_ids else 0
    total_sboms = db.execute(select(func.count(SBOMSource.id))).scalar_one() or 0
    stale_sboms = total_sboms - active_sboms

    # Projects with runs in last 30 days
    active_project_ids = (
        db.execute(
            select(AnalysisRun.project_id.distinct()).where(
                and_(AnalysisRun.project_id != None, AnalysisRun.completed_on >= thirty_days_ago)
            )
        )
        .scalars()
        .all()
    )

    active_projects = len(set(active_project_ids)) if active_project_ids else 0
    total_projects = db.execute(select(func.count(Projects.id)).where(Projects.project_status == 1)).scalar_one() or 0
    stale_projects = total_projects - active_projects

    return {
        "active_sboms": active_sboms,
        "stale_sboms": stale_sboms,
        "active_projects": active_projects,
        "stale_projects": stale_projects,
    }


# ============================================================
# Severity Distribution
# ============================================================


def get_severity_distribution(db: Session) -> dict[str, int]:
    """
    Get the distribution of vulnerability severities across all runs.

    Args:
        db: Database session

    Returns:
        Dictionary with severity counts:
            {
                "critical": int,
                "high": int,
                "medium": int,
                "low": int,
                "unknown": int,
            }
    """
    result = db.execute(
        select(
            AnalysisRun.critical_count,
            AnalysisRun.high_count,
            AnalysisRun.medium_count,
            AnalysisRun.low_count,
            AnalysisRun.unknown_count,
        )
    ).all()

    distribution = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "unknown": 0,
    }

    for row in result:
        distribution["critical"] += row[0] or 0
        distribution["high"] += row[1] or 0
        distribution["medium"] += row[2] or 0
        distribution["low"] += row[3] or 0
        distribution["unknown"] += row[4] or 0

    return distribution


# ============================================================
# Component Statistics
# ============================================================


def get_component_stats(db: Session) -> dict[str, Any]:
    """
    Get component statistics: total components and those with CPE coverage.

    Args:
        db: Database session

    Returns:
        Dictionary with:
            - total_components: Total count of all components
            - components_with_cpe: Count of components with CPE defined
            - cpe_coverage_percentage: CPE coverage percentage
    """
    total_components = db.execute(select(func.count(SBOMComponent.id))).scalar_one() or 0

    components_with_cpe = (
        db.execute(select(func.count(SBOMComponent.id)).where(SBOMComponent.cpe != None)).scalar_one() or 0
    )

    cpe_coverage = 0.0
    if total_components > 0:
        cpe_coverage = round((components_with_cpe / total_components) * 100, 2)

    return {
        "total_components": total_components,
        "components_with_cpe": components_with_cpe,
        "cpe_coverage_percentage": cpe_coverage,
    }


# ============================================================
# Run Statistics
# ============================================================


def get_run_status_distribution(db: Session) -> dict[str, int]:
    """
    Get the distribution of analysis run statuses (PASS, FAIL, ERROR, etc.).

    Args:
        db: Database session

    Returns:
        Dictionary with status counts
    """
    result = db.execute(
        select(AnalysisRun.run_status, func.count(AnalysisRun.id).label("count")).group_by(AnalysisRun.run_status)
    ).all()

    distribution = {}
    for status, count in result:
        distribution[status] = count

    return distribution


def get_top_vulnerable_components(db: Session, limit: int = 10) -> list[dict[str, Any]]:
    """
    Get the components with the most vulnerabilities.

    Args:
        db: Database session
        limit: Maximum number of results

    Returns:
        List of component dictionaries with name, version, cpe, and vulnerability count
    """
    result = db.execute(
        select(
            AnalysisFinding.component_name,
            AnalysisFinding.component_version,
            AnalysisFinding.cpe,
            func.count(AnalysisFinding.id).label("vuln_count"),
        )
        .where(AnalysisFinding.component_name != None)
        .group_by(
            AnalysisFinding.component_name,
            AnalysisFinding.component_version,
            AnalysisFinding.cpe,
        )
        .order_by(func.count(AnalysisFinding.id).desc())
        .limit(limit)
    ).all()

    components = []
    for name, version, cpe, count in result:
        components.append(
            {
                "name": name,
                "version": version,
                "cpe": cpe,
                "vulnerability_count": count,
            }
        )

    return components


def get_top_vulnerabilities(db: Session, limit: int = 10) -> list[dict[str, Any]]:
    """
    Get the most frequently occurring vulnerabilities across all components.

    Args:
        db: Database session
        limit: Maximum number of results

    Returns:
        List of vulnerability dictionaries with vuln_id, title, count, and severity
    """
    result = db.execute(
        select(
            AnalysisFinding.vuln_id,
            AnalysisFinding.title,
            AnalysisFinding.severity,
            func.count(AnalysisFinding.id).label("occurrence_count"),
        )
        .group_by(
            AnalysisFinding.vuln_id,
            AnalysisFinding.title,
            AnalysisFinding.severity,
        )
        .order_by(func.count(AnalysisFinding.id).desc())
        .limit(limit)
    ).all()

    vulns = []
    for vuln_id, title, severity, count in result:
        vulns.append(
            {
                "vuln_id": vuln_id,
                "title": title,
                "severity": severity,
                "occurrence_count": count,
            }
        )

    return vulns
