"""SBO-70: numeric evidence must serialize on reads, writes and conflicts."""

import pytest
from app.models import AnalysisFinding, VexOverrideAudit, VexStatement
from sqlalchemy import select

from tests import test_vex_investigations_api as fixtures

db = fixtures.db
seeded = fixtures.seeded


def snapshot(db, context):
    db.refresh(context)
    return {
        "version": context.row_version,
        "status": context.effective_status,
        "audits": list(db.scalars(select(VexOverrideAudit.id).where(
            VexOverrideAudit.investigation_id == context.id,
        ).order_by(VexOverrideAudit.id))),
        "statements": list(db.scalars(select(VexStatement.id).where(
            VexStatement.sbom_id == context.sbom_id,
            VexStatement.component_id == context.component_id,
        ).order_by(VexStatement.id))),
    }


@pytest.mark.parametrize("confidence", [None, 0.0, 0.875, 1.0])
def test_numeric_confidence_detail__VEX_UI_003(client, seeded, db, confidence):
    finding = db.scalar(select(AnalysisFinding).where(
        AnalysisFinding.analysis_run_id == seeded["run"].id,
        AnalysisFinding.component_id == seeded["openssl"].id,
    ))
    finding.match_confidence = confidence
    db.commit()
    detail = fixtures.detail(client, db, "CVE-2026-5001")
    expected = None if confidence is None else str(confidence)
    assert detail["analyzer_evidence"]["match_confidence"] == expected


def test_numeric_confidence_success_conflict_no_duplicate__VEX_AUD_001_002(client, seeded, db):
    context = fixtures.context_for(db, "CVE-2026-5001")
    before = snapshot(db, context)
    response = fixtures.decide(client, context)
    assert response.status_code == 200, response.text
    assert response.json()["analyzer_evidence"]["match_confidence"] == "0.95"
    saved = snapshot(db, context)
    assert response.json()["row_version"] == saved["version"] > before["version"]
    assert saved["status"] == "NOT_AFFECTED"
    assert len(saved["audits"]) == len(before["audits"]) + 1
    assert len(saved["statements"]) == len(before["statements"]) + 1
    stale = client.put(f"{fixtures.BASE}/{context.id}/decision", json={
        "status": "AFFECTED", "row_version": before["version"], "reason": "stale editor",
    })
    assert stale.status_code == 409, stale.text
    assert stale.json()["analyzer_evidence"]["match_confidence"] == "0.95"
    assert stale.json()["row_version"] == saved["version"]
    assert snapshot(db, context) == saved


def test_invalid_decision_preserves_numeric_evidence_and_state__VEX_VAL_001(client, seeded, db):
    context = fixtures.context_for(db, "CVE-2026-5001")
    before = snapshot(db, context)
    response = client.put(f"{fixtures.BASE}/{context.id}/decision", json={
        "status": "NOT_AFFECTED", "row_version": before["version"], "reason": "missing evidence",
    })
    assert response.status_code == 422
    assert snapshot(db, context) == before
