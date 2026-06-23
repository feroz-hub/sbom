"""
Lifecycle router — Endpoints to track component EOL/EOS information.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ..core.context import CurrentContext
from ..core.security import get_current_tenant_context
from ..db import get_db
from ..models import SBOMComponent
from ..schemas import LifecycleInfoUpdate, SBOMComponentOut
from ..services.lifecycle import LifecycleEnrichmentService, refresh_component_lifecycle

log = logging.getLogger(__name__)

router = APIRouter(tags=["lifecycle"])


@router.get("/api/lifecycle/component/{component_id}", response_model=SBOMComponentOut)
def get_component_lifecycle(component_id: int, db: Session = Depends(get_db)):
    """Fetch lifecycle details for a specific component."""
    comp = db.get(SBOMComponent, component_id)
    if not comp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Component with ID {component_id} not found."
        )
    return comp


@router.put("/api/lifecycle/component/{component_id}", response_model=SBOMComponentOut)
def update_component_lifecycle(
    component_id: int,
    payload: LifecycleInfoUpdate,
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    """Backward-compatible manual lifecycle override endpoint."""

    return LifecycleEnrichmentService().apply_manual_override(
        db,
        component_id,
        payload.model_dump(exclude_none=True),
        updated_by=payload.updated_by or context.actor_label(),
    )


@router.patch("/api/components/{component_id}/lifecycle-override", response_model=SBOMComponentOut)
def patch_component_lifecycle_override(
    component_id: int,
    payload: LifecycleInfoUpdate,
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
):
    """Apply an audited manual lifecycle override to a component."""

    return LifecycleEnrichmentService().apply_manual_override(
        db,
        component_id,
        payload.model_dump(exclude_none=True),
        updated_by=payload.updated_by or context.actor_label(),
    )


@router.post("/api/components/{component_id}/lifecycle/refresh", response_model=SBOMComponentOut)
def refresh_component_lifecycle_endpoint(
    component_id: int,
    force: bool = Query(True),
    db: Session = Depends(get_db),
):
    """Force refresh lifecycle enrichment for one component."""

    return refresh_component_lifecycle(db, component_id, force_refresh=force)
