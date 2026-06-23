"""
Remediation router — Endpoints to track vulnerability fixes/remediation status.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import AnalysisFinding, AnalysisRun, VulnerabilityRemediation
from ..schemas import VulnerabilityRemediationAuditOut, VulnerabilityRemediationOut, VulnerabilityRemediationUpsert
from ..services.remediation_service import (
    create_or_update_remediation,
    get_remediation_for_finding,
    list_remediation_history,
    list_remediations_for_project,
)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/remediation", tags=["remediation"])


@router.get("/project/{project_id}", response_model=list[VulnerabilityRemediationOut])
def get_project_remediations(project_id: int, db: Session = Depends(get_db)):
    """Fetch all remediation records for a project."""
    return list_remediations_for_project(db, project_id)


@router.get("/finding/{finding_id}", response_model=VulnerabilityRemediationOut)
def get_finding_remediation(finding_id: int, db: Session = Depends(get_db)):
    """Fetch the remediation record associated with a specific finding."""
    finding = db.get(AnalysisFinding, finding_id)
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Finding with ID {finding_id} not found.")

    run = db.get(AnalysisRun, finding.analysis_run_id)
    if not run or not run.project_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Finding is not associated with a project.")

    rem = get_remediation_for_finding(
        db, run.project_id, finding.vuln_id, finding.component_name, finding.component_version
    )
    if not rem:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="No remediation record found for this finding."
        )
    return rem


@router.get("/{remediation_id}/history", response_model=list[VulnerabilityRemediationAuditOut])
def get_remediation_history(remediation_id: int, db: Session = Depends(get_db)):
    """Fetch append-only remediation change history."""
    history = list_remediation_history(db, remediation_id)
    if not history:
        if not db.get(VulnerabilityRemediation, remediation_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Remediation record with ID {remediation_id} not found.",
            )
    return history


@router.post("", response_model=VulnerabilityRemediationOut)
def upsert_remediation(
    payload: VulnerabilityRemediationUpsert,
    project_id: int,  # pass via query param or header
    user_id: str | None = Query(None),
    db: Session = Depends(get_db),
):
    """Create or update a remediation tracking record for a vulnerability."""
    try:
        record = create_or_update_remediation(
            db,
            project_id,
            payload.model_dump(exclude_unset=True),
            changed_by=user_id,
        )
        return record
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
