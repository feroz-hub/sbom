"""Auto-repair lives on quarantine workspaces, since rejected uploads have no SBOM id."""

from fastapi import APIRouter, BackgroundTasks, Depends
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.context import CurrentContext
from app.core.security import require_permission
from app.db import get_db
from app.services.sbom.repair.service import AutoRepairService
from app.services.sbom_enrichment_service import run_post_upload_enrichment


class ApprovalRequest(BaseModel):
    candidate_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


router = APIRouter(prefix="/api/sbom-validation-sessions", tags=["sbom-auto-repair"])


@router.post("/{session_id}/repair/analyze")
def analyze(
    session_id: str,
    context: CurrentContext = Depends(require_permission("sbom:repair:read")),
    db: Session = Depends(get_db),
):
    return AutoRepairService(db, context).analyze(session_id)


@router.post("/{session_id}/repair")
def repair(
    session_id: str,
    context: CurrentContext = Depends(require_permission("sbom:repair:update")),
    db: Session = Depends(get_db),
):
    return AutoRepairService(db, context).run(session_id)


@router.get("/{session_id}/repair")
def latest(
    session_id: str,
    context: CurrentContext = Depends(require_permission("sbom:repair:read")),
    db: Session = Depends(get_db),
):
    from sqlalchemy import select

    from app.models import SBOMRepairJob

    service = AutoRepairService(db, context)
    service.session(session_id)
    job = (
        db.execute(
            select(SBOMRepairJob)
            .where(SBOMRepairJob.session_id == session_id, SBOMRepairJob.tenant_id == context.tenant_id)
            .order_by(SBOMRepairJob.created_at.desc(), SBOMRepairJob.id.desc())
        )
        .scalars()
        .first()
    )
    return service.serialize(job) if job else None


@router.get("/{session_id}/repair/{job_id}")
def get_job(
    session_id: str,
    job_id: str,
    context: CurrentContext = Depends(require_permission("sbom:repair:read")),
    db: Session = Depends(get_db),
):
    service = AutoRepairService(db, context)
    return service.serialize(service.get(session_id, job_id))


@router.get("/{session_id}/repair/{job_id}/changes")
def changes(
    session_id: str,
    job_id: str,
    context: CurrentContext = Depends(require_permission("sbom:repair:read")),
    db: Session = Depends(get_db),
):
    job = AutoRepairService(db, context).get(session_id, job_id)
    return {
        "changes": job.report_json["changes"],
        "before_validation": job.report_json["before_validation"],
        "after_validation": job.report_json["after_validation"],
    }


@router.get("/{session_id}/repair/{job_id}/download")
def download(
    session_id: str,
    job_id: str,
    context: CurrentContext = Depends(require_permission("sbom:repair:download")),
    db: Session = Depends(get_db),
):
    service = AutoRepairService(db, context)
    job = service.get(session_id, job_id)
    # Filename comes solely from server-generated job id, never SBOM content.
    return Response(
        job.candidate_content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="repaired-{job.id}.cdx.json"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )


@router.get("/{session_id}/repair/{job_id}/report")
def report(
    session_id: str,
    job_id: str,
    context: CurrentContext = Depends(require_permission("sbom:repair:download")),
    db: Session = Depends(get_db),
):
    import json

    service = AutoRepairService(db, context)
    job = service.get(session_id, job_id)
    return Response(
        json.dumps(service.serialize(job)),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="repair-report-{job.id}.json"',
            "Cache-Control": "no-store",
        },
    )


@router.post(
    "/{session_id}/repair/{job_id}/approve",
    dependencies=[Depends(require_permission("sbom:upload")), Depends(require_permission("product:assign_sbom"))],
)
def approve(
    session_id: str,
    job_id: str,
    background_tasks: BackgroundTasks,
    payload: ApprovalRequest | None = None,
    context: CurrentContext = Depends(require_permission("sbom:repair:revalidate")),
    db: Session = Depends(get_db),
):
    result = AutoRepairService(db, context).approve(
        session_id, job_id, expected_candidate_hash=payload.candidate_sha256 if payload else None
    )
    if not result.get("already_approved"):
        background_tasks.add_task(run_post_upload_enrichment, result["imported_sbom_id"], context.tenant_id)
    return result


@router.post("/{session_id}/repair/{job_id}/reject")
def reject(
    session_id: str,
    job_id: str,
    context: CurrentContext = Depends(require_permission("sbom:repair:update")),
    db: Session = Depends(get_db),
):
    return AutoRepairService(db, context).reject(session_id, job_id)


@router.get('/{session_id}/quality')
def session_quality(session_id: str, context: CurrentContext = Depends(require_permission('sbom:repair:read')), db: Session = Depends(get_db)):
    from app.services.sbom.quality.service import QualityService
    return QualityService(db, context).session_quality(session_id)
