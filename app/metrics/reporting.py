"""Report metrics: stored observations only, explicit tenant and as-of boundaries.

No network/AI calls. A uses canonical component-vulnerability findings in each
active head's latest successful run. B/C/D use CompareService's Convention B.
"""

from collections import Counter, defaultdict
from datetime import datetime

from sqlalchemy import func, or_, select
from sqlalchemy.orm import load_only

from ..models import AnalysisFinding, AnalysisRun, EpssScore, KevEntry, SBOMComponent, SBOMSource, VexStatement
from ..services.finding_metrics import (
    canonical_vulnerability_id,
    canonicalize_finding_rows,
    normalize_severity,
    parse_json_list,
)
from ..services.lifecycle import summarize_components
from ._helpers import cves_for_finding
from .base import COMPLETED_RUN_STATUSES
from .exploitation import compose_exploitation_probability


def _runs(db, sbom_id, tenant_id, as_of):
    return select(AnalysisRun).where(
        AnalysisRun.sbom_id == sbom_id,
        AnalysisRun.tenant_id == tenant_id,
        AnalysisRun.run_status.in_(COMPLETED_RUN_STATUSES),
        AnalysisRun.completed_on <= as_of,
    )


def runs_latest_for_sbom(db, *, sbom_id, tenant_id, as_of):
    return db.scalars(_runs(db, sbom_id, tenant_id, as_of).order_by(AnalysisRun.id.desc()).limit(1)).first()


def runs_initial_for_sbom(db, *, sbom_id, tenant_id, as_of):
    return db.scalars(_runs(db, sbom_id, tenant_id, as_of).order_by(AnalysisRun.id).limit(1)).first()


def runs_previous_for_sbom(db, *, sbom_id, tenant_id, as_of, latest_run_id):
    return db.scalars(
        _runs(db, sbom_id, tenant_id, as_of)
        .where(AnalysisRun.id < latest_run_id)
        .order_by(AnalysisRun.id.desc())
        .limit(1)
    ).first()


def lineage(db, sbom, tenant_id):
    """Declared parents only; missing/deleted/foreign/cyclic ancestors stop traversal."""
    chain, seen = [sbom], {sbom.id}
    while chain[-1].parent_id:
        parent = db.scalar(
            select(SBOMSource).where(SBOMSource.id == chain[-1].parent_id, SBOMSource.tenant_id == tenant_id)
        )
        if parent is None or parent.id in seen:
            break
        chain.append(parent)
        seen.add(parent.id)
    return chain


def latest_snapshots(db, *, sbom_ids, tenant_id, as_of):
    """One batched read per data kind; return detached, secret-free reporting DTOs."""
    if not sbom_ids:
        return {}
    latest_success = (
        select(func.max(AnalysisRun.id))
        .where(
            AnalysisRun.tenant_id == tenant_id,
            AnalysisRun.sbom_id.in_(sbom_ids),
            AnalysisRun.completed_on <= as_of,
            AnalysisRun.run_status.in_(COMPLETED_RUN_STATUSES),
        )
        .group_by(AnalysisRun.sbom_id)
    )
    latest_any = (
        select(func.max(AnalysisRun.id))
        .where(AnalysisRun.tenant_id == tenant_id, AnalysisRun.sbom_id.in_(sbom_ids), AnalysisRun.completed_on <= as_of)
        .group_by(AnalysisRun.sbom_id)
    )
    runs = list(
        db.scalars(
            select(AnalysisRun)
            .options(load_only(AnalysisRun.id, AnalysisRun.sbom_id, AnalysisRun.run_status, AnalysisRun.completed_on))
            .where(
                AnalysisRun.tenant_id == tenant_id,
                or_(AnalysisRun.id.in_(latest_success), AnalysisRun.id.in_(latest_any)),
            )
            .order_by(AnalysisRun.id.desc())
        )
    )
    latest, latest_attempt = {}, {}
    for run in runs:
        latest_attempt.setdefault(run.sbom_id, run.run_status)
        if run.run_status in COMPLETED_RUN_STATUSES:
            latest.setdefault(run.sbom_id, run)
    run_ids = [run.id for run in latest.values()]
    grouped = defaultdict(list)
    for finding in db.scalars(
        select(AnalysisFinding).where(
            AnalysisFinding.tenant_id == tenant_id, AnalysisFinding.analysis_run_id.in_(run_ids)
        )
    ):
        grouped[finding.analysis_run_id].append(finding)
    components = defaultdict(list)
    for component in db.scalars(
        select(SBOMComponent).where(
            SBOMComponent.tenant_id == tenant_id,
            SBOMComponent.sbom_id.in_(sbom_ids),
            SBOMComponent.is_duplicate.is_(False),
        )
    ):
        components[component.sbom_id].append(component)
    vex = {}
    from ..services.lifecycle.vex_provider import effective_vex_statements

    for statement in effective_vex_statements(
        db.scalars(
            select(VexStatement)
            .where(VexStatement.tenant_id == tenant_id, VexStatement.sbom_id.in_(sbom_ids))
            .order_by(VexStatement.created_at, VexStatement.id)
        )
    ):
        key = (statement.sbom_id, statement.component_id, (statement.cve_id or statement.vulnerability_id).upper())
        vex[key] = statement.status
    canonical = {run_id: canonicalize_finding_rows(rows) for run_id, rows in grouped.items()}
    all_cves = {
        cve for rows in canonical.values() for row in rows for cve in cves_for_finding(row.vuln_id, row.aliases)
    }
    kev = set(db.scalars(select(KevEntry.cve_id).where(KevEntry.cve_id.in_(all_cves))))
    epss = dict(db.execute(select(EpssScore.cve_id, EpssScore.epss).where(EpssScore.cve_id.in_(all_cves))).all())
    result = {}
    for sid in sbom_ids:
        run = latest.get(sid)
        rows, distinct, findings = canonical.get(run.id, []) if run else [], set(), []
        for row in rows:
            cves = set(cves_for_finding(row.vuln_id, row.aliases))
            distinct |= cves
            vuln = canonical_vulnerability_id(row.vuln_id, parse_json_list(row.aliases))
            statement = vex.get((sid, row.component_id, vuln)) if row.component_id else None
            findings.append(
                {
                    "vuln_id": vuln,
                    "component_name": row.component_name or "",
                    "component_version": row.component_version or "",
                    "severity": normalize_severity(row.severity),
                    "cvss": row.score,
                    "kev_current": bool(cves & kev),
                    "epss_current": max((epss[c] for c in cves if c in epss), default=None),
                    "fix_available": bool(parse_json_list(row.fixed_versions)),
                    "vex_status": statement,
                }
            )
        severity = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")}
        severity.update(Counter(f["severity"] for f in findings))
        findings.sort(key=risk_rank, reverse=True)
        result[sid] = {
            "run_id": run.id if run else None,
            "completed_on": run.completed_on if run else None,
            "run_status": run.run_status if run else "NO_SUCCESSFUL_RUN",
            "latest_attempt_status": latest_attempt.get(sid),
            "total_components": len(components[sid]),
            "total_findings": len(findings),
            "severity": severity,
            "kev_findings": sum(f["kev_current"] for f in findings),
            "kev_cves": sorted(distinct & kev),
            "fix_available_count": sum(f["fix_available"] for f in findings),
            "vex_reduced_count": sum(f["vex_status"] in {"not_affected", "fixed"} for f in findings),
            "epss_scores": {c: epss[c] for c in distinct if c in epss},
            "distinct_cves": sorted(distinct),
            "lifecycle": summarize_components(components[sid]),
            "findings": findings,
        }
    return result


def risk_rank(finding):
    return (
        bool(finding.get("kev_current")),
        finding.get("epss_current") or 0,
        finding.get("cvss") or 0,
        finding.get("vuln_id") or "",
        finding.get("component_name") or "",
    )


def rollup(snapshots):
    rows = list(snapshots)
    severity = {s: sum(row["severity"][s] for row in rows) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")}
    cves = {c for row in rows for c in row["distinct_cves"]}
    scores = {c: score for row in rows for c, score in row["epss_scores"].items()}
    lifecycle = Counter()
    for row in rows:
        lifecycle.update(
            {key: value for key, value in row["lifecycle"].items() if key.endswith("_count") and isinstance(value, int)}
        )
    total = sum(row["total_findings"] for row in rows)
    fixes = sum(row["fix_available_count"] for row in rows)
    return {
        "total_sboms": len(rows),
        "successful_sboms": sum(row["run_id"] is not None for row in rows),
        "total_components": sum(row["total_components"] for row in rows),
        "total_findings": total,
        "severity": severity,
        "kev_findings": sum(row["kev_findings"] for row in rows),
        "kev_distinct_cves": len({c for row in rows for c in row["kev_cves"]}),
        "fix_available_count": fixes,
        "fix_available_pct": round(100 * fixes / total, 2) if total else 0,
        "vex_reduced_count": sum(row["vex_reduced_count"] for row in rows),
        "lifecycle": dict(lifecycle),
        "epss_outlook": {
            "probability_30d": compose_exploitation_probability(list(scores.values())),
            "scored_cves": len(scores),
            "distinct_cves": len(cves),
            "coverage": len(scores) / len(cves) if cves else 0,
            "assumption": "independent",
        },
    }


def elapsed_days(a, b):
    try:
        return round((datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds() / 86400, 2)
    except (TypeError, ValueError):
        return None


def comparison_rollup(comparisons):
    """Sum Convention B per-SBOM run-pair changes, never raw observations.

    These are component-vulnerability occurrences across SBOMs, not distinct
    portfolio CVEs. Missing baselines have coverage counts, not zero deltas.
    """
    rows = list(comparisons)
    available = [row for row in rows if row["status"] == "available"]
    keys = (
        "findings_added_count",
        "findings_resolved_count",
        "findings_unchanged_count",
        "findings_severity_changed_count",
        "components_added_count",
        "components_removed_count",
        "components_version_bumped_count",
        "high_critical_count_delta",
    )
    totals = {key: sum(row["posture"][key] for row in available) if available else None for key in keys}
    net = None if not available else totals["findings_added_count"] - totals["findings_resolved_count"]
    elapsed = [
        row["relationship"]["days_between"] for row in available if row["relationship"]["days_between"] is not None
    ]
    return {
        "sboms_considered": len(rows),
        "available_baselines": len(available),
        "unavailable_baselines": len(rows) - len(available),
        **totals,
        "net_finding_delta": net,
        "direction": "unavailable"
        if net is None
        else "more_findings"
        if net > 0
        else "fewer_findings"
        if net < 0
        else "unchanged_count",
        "elapsed_days_min": min(elapsed, default=None),
        "elapsed_days_max": max(elapsed, default=None),
        "newly_kev": "unavailable: historical KEV membership was not snapshotted",
    }
