"""
Lifecycle router — Endpoints to track component EOL/EOS information.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import SBOMComponent
from ..schemas import LifecycleInfoUpdate, SBOMComponentOut

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/lifecycle", tags=["lifecycle"])


@router.get("/component/{component_id}", response_model=SBOMComponentOut)
def get_component_lifecycle(component_id: int, db: Session = Depends(get_db)):
    """Fetch lifecycle details for a specific component."""
    comp = db.get(SBOMComponent, component_id)
    if not comp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Component with ID {component_id} not found."
        )
    return comp


@router.put("/component/{component_id}", response_model=SBOMComponentOut)
def update_component_lifecycle(
    component_id: int,
    payload: LifecycleInfoUpdate,
    db: Session = Depends(get_db)
):
    """Manually update lifecycle attributes for a specific component."""
    comp = db.get(SBOMComponent, component_id)
    if not comp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Component with ID {component_id} not found."
        )
        
    comp.lifecycle_status = payload.lifecycle_status
    comp.eos_date = payload.eos_date
    comp.eol_date = payload.eol_date
    comp.is_deprecated = payload.is_deprecated
    comp.maintenance_status = payload.maintenance_status
    
    db.add(comp)
    db.commit()
    db.refresh(comp)
    
    return comp
