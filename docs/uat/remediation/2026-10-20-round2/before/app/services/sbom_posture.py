"""Version/posture provenance shared by dashboard, inventory and VEX surfaces."""

import json
from collections import Counter

from sqlalchemy import select

from ..metrics.base import COMPLETED_RUN_STATUSES
from ..metrics.posture import posture_finding_counts, posture_projection, run_evidence
from ..models import Product, SBOMSource, VexInvestigation
from ..sources.routing import has_incomplete_source_coverage
from .analysis_service import source_summary_from_details


def posture_metadata(db, tenant_id, project_id=None, product_id=None, sbom_id=None):
    projection = posture_projection(tenant_id).subquery()
    query = select(projection)
    if project_id is not None:
        query = query.where(projection.c.projectid == project_id)
    if product_id is not None:
        query = query.where(projection.c.product_id == product_id)
    if sbom_id is not None:
        query = query.where((projection.c.target_sbom_id == sbom_id) | (projection.c.posture_sbom_id == sbom_id))
    resolved = db.execute(query).mappings().all()
    target_ids = {row["target_sbom_id"] for row in resolved}
    # Core, explicitly tenant bound: dashboard ambient filters must not hide
    # the pending upload whose provenance this response is meant to explain.
    s = SBOMSource.__table__.c
    records = (
        db.execute(
            select(
                s.id,
                s.tenant_id,
                s.projectid,
                s.product_id,
                s.logical_sbom_id,
                s.sbom_name,
                s.sbom_version,
                s.productver,
                s.is_active,
                s.lifecycle_status,
            ).where(
                s.tenant_id == tenant_id,
                (
                    s.logical_sbom_id.in_(
                        select(s.logical_sbom_id).where(s.id.in_(target_ids or {0}), s.tenant_id == tenant_id)
                    )
                    | s.id.in_({row["posture_sbom_id"] for row in resolved} or {0})
                ),
            )
        )
        .mappings()
        .all()
    )
    logical_ids = {row["logical_sbom_id"] for row in records if row["id"] in {r["target_sbom_id"] for r in resolved}}
    records = [
        row
        for row in records
        if row["logical_sbom_id"] in logical_ids or row["id"] in {r["posture_sbom_id"] for r in resolved}
    ]
    by_id = {row["id"]: row for row in records}
    relevant = {row["posture_sbom_id"] for row in resolved} | {row["target_sbom_id"] for row in resolved}
    latest = {}
    for row in records:
        group = (row["product_id"], row["logical_sbom_id"])
        if group not in latest or row["id"] > latest[group]["id"]:
            latest[group] = row
    for row in resolved:
        target = by_id.get(row["target_sbom_id"])
        if target:
            relevant.add(latest[(target["product_id"], target["logical_sbom_id"])]["id"])
    # Read metadata via metric-layer projection without dashboard ORM criteria.
    relevant.update(by_id)
    runs = run_evidence(db, tenant_id, relevant)
    newest, successful = {}, {}
    for run in runs:
        newest.setdefault(run.sbom_id, run)
        if run.is_current and run.run_status in COMPLETED_RUN_STATUSES and by_id.get(run.sbom_id, {}).get("is_active") and by_id[run.sbom_id]["lifecycle_status"] == "ACTIVE":
            successful.setdefault(run.sbom_id, run)

    finding_counts = posture_finding_counts(db, tenant_id, {run.id for run in successful.values()})

    def version(record):
        return (
            {"id": record["id"], "name": record["sbom_name"], "version": record["sbom_version"] or record["productver"]}
            if record
            else None
        )

    branches = Counter(by_id[r["target_sbom_id"]]["logical_sbom_id"] for r in resolved if r["target_sbom_id"] in by_id)
    result = []
    for row in resolved:
        target, source = by_id.get(row["target_sbom_id"]), by_id.get(row["posture_sbom_id"])
        if not target or not source:
            continue
        uploaded = latest[(target["product_id"], target["logical_sbom_id"])]
        run = successful.get(source["id"])
        attempted = newest.get(uploaded["id"])
        state = (
            "HISTORICAL_VERSION"
            if not uploaded["is_active"] or uploaded["lifecycle_status"] != "ACTIVE"
            else "ANALYSIS_PENDING"
            if not attempted
            else "ANALYZED"
            if attempted.is_current and attempted.run_status in COMPLETED_RUN_STATUSES
            else "ANALYSIS_FAILED"
            if attempted.run_status == "ERROR"
            else "ANALYSIS_PENDING"
        )
        try:
            details = json.loads(run.raw_report or "{}") if run else {}
        except (ValueError, TypeError):
            details = {}
        summary = source_summary_from_details(details)
        coverage = run and (
            run.run_status == "PARTIAL"
            or (run.query_error_count or 0) > 0
            or "(partial)" in str(run.source or "").lower()
            or has_incomplete_source_coverage(summary)
        )
        fallback = target["id"] != source["id"] or (uploaded["is_active"] and uploaded["lifecycle_status"] == "ACTIVE" and uploaded["id"] != source["id"] and uploaded["id"] not in successful)
        warning = None
        if fallback:
            warning = f"The newer SBOM has not completed analysis. Showing the last known security posture from {source['sbom_version'] or source['productver'] or source['sbom_name']}."
        elif uploaded["id"] != target["id"] and uploaded["is_active"] and uploaded["lifecycle_status"] == "ACTIVE":
            warning = (
                "A newer analyzed SBOM is available. Select Current SBOM explicitly to change the designated version."
                if row["selection_mode"] == "MANUAL_PIN" else
                "A newer analyzed SBOM is available but was not promoted. Review lineage eligibility and active branches before changing Current SBOM."
            )
        elif not run:
            warning = "Analysis pending. No successful security posture is available for this SBOM. Findings from other SBOMs remain separate."
        elif newest.get(source["id"]) and newest[source["id"]].id != run.id:
            warning = "The latest analysis did not complete successfully. Showing the last successful analysis."
        if source["logical_sbom_id"] != target["logical_sbom_id"] and run:
            warning = (
                (warning + " " if warning else "")
                + "This is last known application evidence from another declared lineage, not an analysis or comparison of the selected upload."
            )
        if branches[target["logical_sbom_id"]] > 1 and row["designated_sbom_id"] is None:
            warning = (
                (warning + " " if warning else "")
                + "Multiple active lineage branches exist. Designate Current SBOM explicitly; branch findings are not silently merged into one version."
            )
        invalid_selection = row["stored_designated_sbom_id"] is not None and row["designated_sbom_id"] is None
        if invalid_selection:
            warning = (warning + " " if warning else "") + "The designated Current SBOM is inactive, deleted or outside this application. Showing eligible last known evidence; administrator selection requires review."
        if coverage:
            warning = (
                warning + " " if warning else ""
            ) + "Analysis coverage incomplete; some sources were unavailable or failed."
        analyzed = next(
            (
                record
                for record in sorted(records, key=lambda r: r["id"], reverse=True)
                if record["logical_sbom_id"] == target["logical_sbom_id"] and record["id"] in successful
            ),
            None,
        )
        result.append(
            {
                **dict(row),
                "current_sbom": version(target),
                "effective_current_sbom": None if row["selection_mode"] == "AUTO" and not run else version(source if row["selection_mode"] == "AUTO" and not successful.get(target["id"]) else target),
                "selection_mode": row["selection_mode"] or "AUTO",
                "invalid_selection": invalid_selection,
                "designated_current_sbom_id": row["stored_designated_sbom_id"],
                "analysis_completed_on": run.completed_on if run else None,
                "fallback_reason": "INVALID_SELECTION" if invalid_selection else "AWAITING_SUCCESSFUL_ANALYSIS" if fallback else None,
                "latest_uploaded": version(uploaded),
                "latest_analyzed": version(analyzed or source if run else analyzed),
                "posture_sbom": version(source),
                "analysis_run_id": run.id if run else None,
                "analysis_finding_rows": finding_counts.get(run.id, 0) if run else None,
                "analysis_status": state,
                "last_known_posture": bool(fallback),
                "coverage_incomplete": bool(coverage),
                "warning": warning,
                "designation_required": uploaded["id"] != target["id"] and row["designated_sbom_id"] is not None,
            }
        )
    # An invalid manual designation must remain visible even when no eligible
    # version exists. Absence of posture is not a successful zero-finding scan.
    p = Product.__table__.c
    missing = select(p.id, p.name, p.project_id, p.current_sbom_id, p.current_sbom_mode).where(
        p.tenant_id == tenant_id, p.is_active.is_(True), p.deleted_at.is_(None),
        p.current_sbom_id.is_not(None), p.id.notin_({row["product_id"] for row in resolved if row["product_id"]} or {0}),
    )
    if project_id is not None:
        missing = missing.where(p.project_id == project_id)
    if product_id is not None:
        missing = missing.where(p.id == product_id)
    if sbom_id is not None:
        missing = missing.where(p.current_sbom_id == sbom_id)
    for product in db.execute(missing).mappings():
        result.append({
            "target_sbom_id": None, "posture_sbom_id": None, "product_id": product["id"],
            "projectid": product["project_id"], "application_name": product["name"],
            "current_sbom": None, "effective_current_sbom": None, "latest_uploaded": None,
            "latest_analyzed": None, "posture_sbom": None, "analysis_run_id": None,
            "analysis_finding_rows": None, "analysis_status": "NO_POSTURE", "analysis_completed_on": None,
            "selection_mode": product["current_sbom_mode"], "invalid_selection": True,
            "designated_current_sbom_id": product["current_sbom_id"], "fallback_reason": "INVALID_SELECTION",
            "last_known_posture": False, "coverage_incomplete": False, "designation_required": True,
            "warning": "The designated Current SBOM is ineligible. No safe security posture is available; review administrator selection.",
        })
    return result


def investigation_is_historical(db, investigation):
    from ..metrics.posture import posture_sbom_ids
    from ..metrics.vex import current_investigation_evidence_clause

    return (
        not investigation.is_current
        or db.scalar(
            select(VexInvestigation.id).where(
                VexInvestigation.id == investigation.id,
                VexInvestigation.tenant_id == investigation.tenant_id,
                VexInvestigation.sbom_id.in_(posture_sbom_ids(investigation.tenant_id)),
                current_investigation_evidence_clause(),
            )
        )
        is None
    )


def posture_evidence_summary(items):
    """Analysis availability is distinct from provider completeness and HTTP failure."""
    available = sum(item.get("analysis_run_id") is not None for item in items)
    missing = len(items) - available
    return {
        "evidence_status": "EMPTY"
        if not items
        else "AVAILABLE"
        if not missing
        else "PARTIAL"
        if available
        else "UNAVAILABLE",
        "total_targets": len(items),
        "available_targets": available,
        "missing_targets": missing,
        "coverage_incomplete_targets": sum(bool(item.get("coverage_incomplete")) for item in items),
    }
