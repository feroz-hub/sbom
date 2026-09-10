"""Build a detached report snapshot; renderers never hold a database session."""

import logging
from datetime import UTC, datetime

from ..metrics.reporting import (
    comparison_rollup,
    elapsed_days,
    latest_snapshots,
    lineage,
    risk_rank,
    rollup,
    runs_initial_for_sbom,
    runs_latest_for_sbom,
    runs_previous_for_sbom,
)
from ..settings import get_settings
from .compare_service import CompareService
from .finding_metrics import SEVERITY_ORDER
from .report_access import scope_sboms

PART_NAMES = {
    "A": "Latest security state",
    "B": "Since previous successful run",
    "C": "Since baseline",
    "D": "Across declared SBOM versions",
}

log = logging.getLogger(__name__)
CAVEATS = [
    "Part A: canonical component-vulnerability findings in the latest successful run per active SBOM head (Convention A).",
    "Parts B/C/D: distinct canonical vulnerability, component name and version (Convention B); not raw provider observations.",
    "KEV and EPSS are current local enrichment, not historical scan snapshots. Newly KEV since baseline is unavailable.",
    "EPSS outlook assumes independent exploitation probabilities; missing scores are not evidence of no risk. Review coverage.",
    "VEX not_affected/fixed reduce actionable exposure separately; they do not mean a vulnerability was not found.",
    "Severity floor filters finding detail only. Headline counts and comparison totals are unfiltered.",
    "The executive PDF/email contain headlines; full finding and component detail is in the Excel and JSON artifacts. All timestamps are UTC (offset +00:00).",
]


def compose_report(db, preferences, *, tenant_id, cycle_start, cycle_end, sbom_ids=None):
    all_sboms = scope_sboms(db, preferences, tenant_id)
    if sbom_ids is not None:
        allowed = set(sbom_ids)
        all_sboms = [sbom for sbom in all_sboms if sbom.id in allowed]
    snapshots = latest_snapshots(db, sbom_ids=[s.id for s in all_sboms], tenant_id=tenant_id, as_of=cycle_end)
    summary = rollup(snapshots.values())

    def rank(sbom):
        return (max((risk_rank(f)[:3] for f in snapshots[sbom.id]["findings"]), default=(False, 0, 0)), -sbom.id)

    selected = sorted(all_sboms, key=rank, reverse=True)[: get_settings().report_max_sboms_per_digest]
    selected_ids = {s.id for s in selected}
    comparison_summaries = {part: [] for part in preferences.parts if part != "A"}
    considered_runs = {s["run_id"] for s in snapshots.values() if s["run_id"] is not None}
    comparator = CompareService(db)
    report = {
        "schema_version": 1,
        "tenant_id": tenant_id,
        "scope": preferences.scope,
        "generated_at": datetime.now(UTC).isoformat(),
        "cycle_start": cycle_start,
        "cycle_end": cycle_end,
        "timezone": preferences.timezone,
        "parts": preferences.parts,
        "severity_floor": preferences.severity_floor,
        "summary": summary,
        "sboms": [],
        "total_sboms": len(all_sboms),
        "included_sboms": len(selected),
        "truncated_sboms": len(all_sboms) - len(selected),
        "caveats": CAVEATS,
        "unchanged": True,
    }
    # Compare the full scope for truthful aggregate deltas; only retain detail
    # for the capped risk-ranked selection. No remote enrichers are called.
    for sbom in all_sboms:
        current = snapshots[sbom.id]
        data = {
            "id": sbom.id,
            "name": sbom.sbom_name,
            "version": sbom.sbom_version or sbom.productver,
            "project_id": sbom.projectid,
            "product_id": sbom.product_id,
            "A": current,
            "comparisons": {},
        }
        chain = lineage(db, sbom, tenant_id)
        args = {"tenant_id": tenant_id, "as_of": cycle_end}
        for part in preferences.parts:
            if part == "A":
                continue
            baseline = None
            if current["run_id"]:
                if part == "B":
                    baseline = runs_previous_for_sbom(db, sbom_id=sbom.id, latest_run_id=current["run_id"], **args)
                elif part == "C":
                    baseline = runs_initial_for_sbom(
                        db,
                        sbom_id=chain[-1].id if preferences.baseline_mode == "FIRST_RUN_OF_LINEAGE_ROOT" else sbom.id,
                        **args,
                    )
                elif len(chain) > 1:
                    baseline = runs_latest_for_sbom(
                        db, sbom_id=chain[1 if preferences.cross_version_target == "PARENT" else -1].id, **args
                    )
            if baseline is None or baseline.id == current["run_id"]:
                data["comparisons"][part] = {
                    "status": "insufficient_history",
                    "message": "No distinct successful baseline run is available.",
                }
                report["unchanged"] = False
                continue
            try:
                considered_runs.add(baseline.id)
                result = comparator.compare(baseline.id, current["run_id"]).model_dump(mode="json")
                posture = result["posture"]
                changed = any(
                    posture[k]
                    for k in (
                        "findings_added_count",
                        "findings_resolved_count",
                        "findings_severity_changed_count",
                        "components_added_count",
                        "components_removed_count",
                        "components_version_bumped_count",
                    )
                )
                report["unchanged"] &= not changed
                result["status"] = "available"
                result["newly_kev"] = {
                    "status": "unavailable",
                    "reason": "KEV membership was not snapshotted at scan time",
                }
                if part == "C":
                    result["persistent_findings"] = [
                        {
                            **row,
                            "age_days": elapsed_days(baseline.completed_on, cycle_end),
                            "first_observed_at": baseline.completed_on,
                        }
                        for row in result["findings"]
                        if row["change_kind"] in {"unchanged", "severity_changed"}
                    ]
                    result["persistent_findings"].sort(key=risk_rank, reverse=True)
                    result["persistent_findings_count"] = len(result["persistent_findings"])
                data["comparisons"][part] = result
            except Exception as exc:
                db.rollback()
                log.warning("report.part_failed part=%s sbom_id=%s error_type=%s", part, sbom.id, type(exc).__name__)
                data["comparisons"][part] = {
                    "status": "unavailable",
                    "error_code": "REPORT_COMPARISON_FAILED",
                    "message": "Comparison could not be generated for these runs.",
                }
                report["unchanged"] = False
        for part, comparison in data["comparisons"].items():
            comparison_summaries[part].append(
                {key: comparison[key] for key in ("status", "posture", "relationship") if key in comparison}
            )
        if sbom.id not in selected_ids:
            continue
        current["findings"] = [f for f in current["findings"] if _visible(f["severity"], preferences.severity_floor)]
        for comparison in data["comparisons"].values():
            for key in ("findings", "persistent_findings"):
                if key in comparison:
                    comparison[key] = [
                        f
                        for f in comparison[key]
                        if _visible(f.get("severity_b") or f.get("severity_a"), preferences.severity_floor)
                    ]
        report["sboms"].append(data)
    selected_order = {s.id: index for index, s in enumerate(selected)}
    report["sboms"].sort(key=lambda s: selected_order[s["id"]])
    report["runs_considered"] = len(considered_runs)
    report["comparison_summary"] = {part: comparison_rollup(rows) for part, rows in comparison_summaries.items()}
    # Empty/partial/capped scopes are never certified unchanged.
    if not selected or report["truncated_sboms"] or not set(preferences.parts) & {"B", "C", "D"}:
        report["unchanged"] = False
    report["top_risks"] = sorted(
        [{**f, "sbom_id": s["id"], "sbom_name": s["name"]} for s in report["sboms"] for f in s["A"]["findings"]],
        key=risk_rank,
        reverse=True,
    )[:10]
    return report


def _visible(severity, floor):
    return floor == "ALL" or SEVERITY_ORDER.get(severity or "UNKNOWN", 0) >= SEVERITY_ORDER[floor]
