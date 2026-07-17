"""CISA Known Exploited Vulnerabilities API.

Routes:
  POST /api/v1/kev/sync       manually refresh the local KEV catalog mirror
  GET  /api/v1/kev            list KEV catalog rows
  GET  /api/v1/kev/{cve_id}   fetch one KEV catalog row by CVE
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import KevEntry
from ..services.kev_service import parse_date_string, sync_kev

router = APIRouter(prefix="/api/v1/kev", tags=["kev"])


class KevSyncRequest(BaseModel):
    since: str | None = Field(
        default=None,
        description="Optional YYYY-MM-DD dateAdded cutoff. Empty syncs the full catalog.",
    )
    prune_stale: bool = Field(
        default=True,
        description="Remove local KEV CVEs absent from a full-feed sync. Ignored for since-filtered syncs.",
    )


class KevSyncResponse(BaseModel):
    ok: bool
    catalog_version: str | None = None
    catalog_date_released: str | None = None
    total_in_feed: int
    filtered_since: str | None = None
    matched_after_filter: int
    upserted: int
    duration_seconds: float


class KevVulnerabilityOut(BaseModel):
    cve_id: str
    vendor_project: str | None = None
    product: str | None = None
    vulnerability_name: str | None = None
    date_added: str | None = None
    short_description: str | None = None
    required_action: str | None = None
    due_date: str | None = None
    known_ransomware_campaign_use: str | None = None
    notes: str | None = None
    cwes: list[str] = Field(default_factory=list)
    catalog_version: str | None = None
    catalog_date_released: str | None = None
    refreshed_at: str
    first_seen_at: str | None = None
    updated_at: str | None = None


def _normalize_cve_id(cve_id: str) -> str:
    return cve_id.strip().upper()


def _validate_since(raw: str | None) -> str | None:
    if raw in (None, ""):
        return None
    parsed = parse_date_string(raw)
    if parsed is None:
        raise HTTPException(status_code=422, detail="since must be a valid YYYY-MM-DD date")
    return parsed


def _serialize(row: KevEntry) -> dict[str, Any]:
    cwes = row.cwes if isinstance(row.cwes, list) else []
    return {
        "cve_id": row.cve_id,
        "vendor_project": row.vendor_project,
        "product": row.product,
        "vulnerability_name": row.vulnerability_name,
        "date_added": row.date_added,
        "short_description": row.short_description,
        "required_action": row.required_action,
        "due_date": row.due_date,
        "known_ransomware_campaign_use": row.known_ransomware_campaign_use,
        "notes": row.notes,
        "cwes": [str(cwe) for cwe in cwes if cwe],
        "catalog_version": row.catalog_version,
        "catalog_date_released": row.catalog_date_released,
        "refreshed_at": row.refreshed_at,
        "first_seen_at": row.first_seen_at,
        "updated_at": row.updated_at,
    }


@router.post("/sync", response_model=KevSyncResponse)
def sync_kev_catalog(
    payload: KevSyncRequest | None = Body(default=None),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    body = payload or KevSyncRequest()
    since = _validate_since(body.since)
    result = sync_kev(
        db,
        since=since,
        prune_stale=body.prune_stale and since is None,
        commit=True,
    )
    return {"ok": True, **result}


@router.get("", response_model=list[KevVulnerabilityOut])
def list_kev_vulnerabilities(
    q: str | None = Query(default=None, description="Case-insensitive search across CVE/vendor/product/name."),
    ransomware: bool | None = Query(default=None, description="Filter by known ransomware campaign use."),
    since: str | None = Query(default=None, description="Minimum KEV dateAdded, YYYY-MM-DD."),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    since_date = _validate_since(since)
    stmt = select(KevEntry)
    if q:
        term = f"%{q.strip()}%"
        stmt = stmt.where(
            KevEntry.cve_id.ilike(term)
            | KevEntry.vendor_project.ilike(term)
            | KevEntry.product.ilike(term)
            | KevEntry.vulnerability_name.ilike(term)
        )
    if ransomware is not None:
        stmt = stmt.where(
            KevEntry.known_ransomware_campaign_use.ilike("Known")
            if ransomware
            else KevEntry.known_ransomware_campaign_use.ilike("Unknown")
        )
    if since_date:
        stmt = stmt.where(KevEntry.date_added >= since_date)
    rows = db.execute(stmt.order_by(KevEntry.date_added.desc(), KevEntry.cve_id).offset(offset).limit(limit)).scalars()
    return [_serialize(row) for row in rows]


@router.get("/{cve_id}", response_model=KevVulnerabilityOut)
def get_kev_vulnerability(
    cve_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    row = db.get(KevEntry, _normalize_cve_id(cve_id))
    if row is None:
        raise HTTPException(status_code=404, detail="KEV entry not found")
    return _serialize(row)


__all__ = ["router"]
