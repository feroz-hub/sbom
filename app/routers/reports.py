"""Project-level report export endpoints."""

from __future__ import annotations

from datetime import date
from io import BytesIO
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from ..core.context import CurrentContext
from ..core.security import get_current_tenant_context
from ..db import get_db
from ..services import audit_service
from ..services.fda_510k_excel_report_service import (
    EXCEL_MEDIA_TYPE,
    Fda510kExcelReportService,
    Fda510kIncompleteAnalysisError,
    Fda510kReportError,
    Fda510kReportMetadata,
    Fda510kSelection,
)

router = APIRouter(prefix="/api/projects", tags=["reports"])


class Fda510kReportSelectionIn(BaseModel):
    sbom_id: int = Field(..., gt=0)
    findings_analysis_run_id: int | None = Field(default=None, gt=0)
    lifecycle_analysis_run_id: int | None = Field(default=None, gt=0)


class Fda510kReportMetadataIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    device_name: str
    device_model_catalog_number: str | None = None
    manufacturer_sponsor: str
    submission_type: Literal["510(k)", "De Novo", "PMA", "HDE", "IDE"] | str | None = "510(k)"
    submission_number: str | None = None
    product_code_regulation_number: str | None = None
    device_software_version: str
    top_level_primary_component: str | None = None
    author_of_sbom_data: str
    sbom_version: str | None = None
    sbom_formats_for_submission: str | None = "CycloneDX / SPDX (machine-readable) + this workbook"
    sbom_generation_tool_and_version: str | None = None
    primary_data_source: str | None = None
    prepared_by: str
    date_prepared: date | None = None
    reviewed_approved_by: str | None = None
    date_approved: date | None = None

    @field_validator("device_name", "manufacturer_sponsor", "device_software_version", "author_of_sbom_data", "prepared_by")
    @classmethod
    def required_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("Required final-report metadata is missing.")
        return value

    def to_service(self) -> Fda510kReportMetadata:
        return Fda510kReportMetadata(**self.model_dump())


class Fda510kReportExportRequest(BaseModel):
    selections: list[Fda510kReportSelectionIn] = Field(..., min_length=1)
    metadata: Fda510kReportMetadataIn


@router.post("/{project_id}/reports/fda-510k-sbom/export")
def export_fda_510k_sbom_report(
    project_id: int,
    payload: Fda510kReportExportRequest,
    request: Request,
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    """Export the final FDA 510(k) SBOM workbook for selected project SBOMs."""

    service = Fda510kExcelReportService(db)
    try:
        content, filename = service.build(
            project_id,
            [
                Fda510kSelection(
                    sbom_id=selection.sbom_id,
                    findings_analysis_run_id=selection.findings_analysis_run_id,
                    lifecycle_analysis_run_id=selection.lifecycle_analysis_run_id,
                )
                for selection in payload.selections
            ],
            payload.metadata.to_service(),
        )
    except Fda510kIncompleteAnalysisError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=exc.detail()) from exc
    except Fda510kReportError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    audit_service.write_audit_log(
        db,
        context,
        "report.fda_510k_sbom.export",
        entity_type="project",
        entity_id=project_id,
        request=request,
        detail="FDA 510(k) SBOM Excel report exported",
        metadata_json={
            "project_id": project_id,
            "sbom_ids": [selection.sbom_id for selection in payload.selections],
            "filename": filename,
        },
    )
    db.commit()
    return StreamingResponse(
        BytesIO(content),
        media_type=EXCEL_MEDIA_TYPE,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

