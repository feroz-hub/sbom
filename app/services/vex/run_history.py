"""Capture once; never rewrite prior investigation decisions or assignments."""
import json

from sqlalchemy import select

from ...models import VexInvestigation, VexInvestigationSnapshot, VexStatement


def capture_run_snapshot(db, run):
    from ...metrics.vex import latest_successful_run_id_for_sbom
    if latest_successful_run_id_for_sbom(db, tenant_id=run.tenant_id, sbom_id=run.sbom_id) != run.id:
        return  # Never label newer reconciled contexts as an older run's snapshot.
    try:
        report = json.loads(run.raw_report or "{}")
    except (TypeError, ValueError):
        report = {}
    if not isinstance(report, dict):
        report = {}
    if report.get("vex_snapshot_captured"):
        return
    if db.scalar(select(VexInvestigationSnapshot.id).where(
        VexInvestigationSnapshot.tenant_id == run.tenant_id,
        VexInvestigationSnapshot.analysis_run_id == run.id,
    ).limit(1)) is not None:
        return
    contexts = db.scalars(select(VexInvestigation).where(
        VexInvestigation.tenant_id == run.tenant_id, VexInvestigation.sbom_id == run.sbom_id,
        VexInvestigation.is_current.is_(True),
    )).all()
    statements = {s.id: s for s in db.scalars(select(VexStatement).where(
        VexStatement.tenant_id == run.tenant_id,
        VexStatement.id.in_({c.effective_vex_statement_id for c in contexts} or {0}),
    )).all()}
    for row in contexts:
        statement = statements.get(row.effective_vex_statement_id)
        payload = {key: getattr(row, key) for key in (
            "component_id", "canonical_vulnerability_id", "aliases_json", "effective_status",
            "reconciliation_status", "analyzer_detection_state", "analyzer_sources_json",
            "assigned_to", "reviewed_by", "reviewed_at", "effective_vex_statement_id",
        )}
        payload["statement"] = {key: getattr(statement, key) for key in (
            "status", "justification", "impact_statement", "action_statement", "evidence_json", "source_name",
        )} if statement else None
        db.add(VexInvestigationSnapshot(
            tenant_id=run.tenant_id, sbom_id=run.sbom_id, analysis_run_id=run.id,
            investigation_id=row.id, payload_json=payload, captured_at=run.completed_on,
        ))
    db.flush()
    run.raw_report = json.dumps({**report, "vex_snapshot_captured": True})
