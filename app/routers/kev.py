"""CISA Known Exploited Vulnerabilities API.

Routes:
  POST /api/v1/kev/sync       manually refresh the local KEV catalog mirror
  GET  /api/v1/kev            list KEV catalog rows
  GET  /api/v1/kev/{cve_id}   fetch one KEV catalog row by CVE
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import Text, cast, exists, func, or_, select, true
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

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


class KevVulnerabilityListOut(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[KevVulnerabilityOut]


class KevFilterOptionsOut(BaseModel):
    vendors: list[str] = Field(default_factory=list)
    products: list[str] = Field(default_factory=list)
    catalog_versions: list[str] = Field(default_factory=list)
    cwes: list[str] = Field(default_factory=list)
    date_added_min: str | None = None
    date_added_max: str | None = None


KevSortField = Literal[
    "cve_id",
    "vendor_project",
    "product",
    "vulnerability_name",
    "date_added",
    "due_date",
    "known_ransomware_campaign_use",
    "catalog_version",
    "updated_at",
]
SortOrder = Literal["asc", "desc"]

SORT_COLUMNS = {
    "cve_id": KevEntry.cve_id,
    "vendor_project": KevEntry.vendor_project,
    "product": KevEntry.product,
    "vulnerability_name": KevEntry.vulnerability_name,
    "date_added": KevEntry.date_added,
    "due_date": KevEntry.due_date,
    "known_ransomware_campaign_use": KevEntry.known_ransomware_campaign_use,
    "catalog_version": KevEntry.catalog_version,
    "updated_at": KevEntry.updated_at,
}


def _normalize_cve_id(cve_id: str) -> str:
    return cve_id.strip().upper()


def _validate_since(raw: str | None) -> str | None:
    if raw in (None, ""):
        return None
    parsed = parse_date_string(raw)
    if parsed is None:
        raise HTTPException(status_code=422, detail="since must be a valid YYYY-MM-DD date")
    return parsed


def _validate_date(raw: str | None, *, field_name: str) -> str | None:
    if raw in (None, ""):
        return None
    parsed = parse_date_string(raw)
    if parsed is None:
        raise HTTPException(status_code=422, detail=f"{field_name} must be a valid YYYY-MM-DD date")
    return parsed


def _normalize_ransomware_filter(raw: str | None) -> Literal["known", "not-known"] | None:
    if raw is None:
        return None
    normalized = raw.strip().lower()
    aliases = {
        "": None,
        "all": None,
        "true": "known",
        "false": "not-known",
        "known": "known",
        "not-known": "not-known",
    }
    if normalized not in aliases:
        raise HTTPException(
            status_code=422,
            detail="ransomware must be one of: known, not-known",
        )
    return aliases[normalized]


def _exact_text(column, value: str) -> ColumnElement[bool]:
    return func.lower(func.trim(column)) == value.strip().lower()


def _cwe_condition(db: Session, cwe: str) -> ColumnElement[bool]:
    normalized = cwe.strip().upper()
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        return cast(KevEntry.cwes, JSONB).contains([normalized])

    elements = func.json_each(KevEntry.cwes).table_valued("key", "value").alias("kev_cwe")
    return exists(
        select(1)
        .select_from(elements)
        .where(func.upper(func.trim(elements.c.value)) == normalized)
    )


def _distinct_nonblank(db: Session, column, *conditions: ColumnElement[bool]) -> list[str]:
    stmt = (
        select(column)
        .where(column.isnot(None), func.trim(column) != "", *conditions)
        .distinct()
        .order_by(func.lower(column), column)
    )
    return [str(value) for value in db.execute(stmt).scalars() if value]


def _distinct_cwes(db: Session) -> list[str]:
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        elements = func.jsonb_array_elements_text(cast(KevEntry.cwes, JSONB)).table_valued("value").alias("kev_cwe")
    else:
        elements = func.json_each(KevEntry.cwes).table_valued("key", "value").alias("kev_cwe")
    value = elements.c.value
    stmt = (
        select(value)
        .select_from(KevEntry)
        .join(elements, true())
        .where(KevEntry.cwes.isnot(None), func.trim(value) != "")
        .distinct()
        .order_by(func.upper(value), value)
    )
    return [str(cwe) for cwe in db.execute(stmt).scalars() if cwe]


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


@router.get("/filter-options", response_model=KevFilterOptionsOut)
def get_kev_filter_options(
    vendor: str | None = Query(default=None, max_length=255),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    product_conditions: list[ColumnElement[bool]] = []
    if vendor and vendor.strip():
        product_conditions.append(_exact_text(KevEntry.vendor_project, vendor))

    date_min, date_max = db.execute(
        select(func.min(KevEntry.date_added), func.max(KevEntry.date_added))
    ).one()
    return {
        "vendors": _distinct_nonblank(db, KevEntry.vendor_project),
        "products": _distinct_nonblank(db, KevEntry.product, *product_conditions),
        "catalog_versions": _distinct_nonblank(db, KevEntry.catalog_version),
        "cwes": _distinct_cwes(db),
        "date_added_min": date_min,
        "date_added_max": date_max,
    }


@router.get("", response_model=KevVulnerabilityListOut)
def list_kev_vulnerabilities(
    q: str | None = Query(default=None, max_length=500),
    vendor: str | None = Query(default=None, max_length=255),
    product: str | None = Query(default=None, max_length=255),
    ransomware: str | None = Query(default=None),
    date_added_from: str | None = Query(default=None),
    date_added_to: str | None = Query(default=None),
    due_date_from: str | None = Query(default=None),
    due_date_to: str | None = Query(default=None),
    catalog_version: str | None = Query(default=None, max_length=32),
    cwe: str | None = Query(default=None, max_length=64),
    sort_by: KevSortField = Query(default="date_added"),
    sort_order: SortOrder = Query(default="desc"),
    since: str | None = Query(default=None, description="Legacy alias for date_added_from."),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    legacy_since = _validate_since(since)
    added_from = _validate_date(date_added_from, field_name="date_added_from") or legacy_since
    added_to = _validate_date(date_added_to, field_name="date_added_to")
    due_from = _validate_date(due_date_from, field_name="due_date_from")
    due_to = _validate_date(due_date_to, field_name="due_date_to")
    if added_from and added_to and added_from > added_to:
        raise HTTPException(status_code=422, detail="date_added_from must not be later than date_added_to")
    if due_from and due_to and due_from > due_to:
        raise HTTPException(status_code=422, detail="due_date_from must not be later than due_date_to")

    conditions: list[ColumnElement[bool]] = []
    if q and q.strip():
        term = f"%{q.strip()}%"
        conditions.append(
            or_(
                KevEntry.cve_id.ilike(term),
                KevEntry.vendor_project.ilike(term),
                KevEntry.product.ilike(term),
                KevEntry.vulnerability_name.ilike(term),
                KevEntry.short_description.ilike(term),
                KevEntry.required_action.ilike(term),
                KevEntry.notes.ilike(term),
                cast(KevEntry.cwes, Text).ilike(term),
            )
        )
    if vendor and vendor.strip():
        conditions.append(_exact_text(KevEntry.vendor_project, vendor))
    if product and product.strip():
        conditions.append(_exact_text(KevEntry.product, product))

    ransomware_filter = _normalize_ransomware_filter(ransomware)
    normalized_ransomware = func.lower(func.trim(KevEntry.known_ransomware_campaign_use))
    if ransomware_filter == "known":
        conditions.append(normalized_ransomware == "known")
    elif ransomware_filter == "not-known":
        conditions.append(
            or_(
                KevEntry.known_ransomware_campaign_use.is_(None),
                normalized_ransomware != "known",
            )
        )
    if added_from:
        conditions.append(KevEntry.date_added >= added_from)
    if added_to:
        conditions.append(KevEntry.date_added <= added_to)
    if due_from:
        conditions.append(KevEntry.due_date >= due_from)
    if due_to:
        conditions.append(KevEntry.due_date <= due_to)
    if catalog_version and catalog_version.strip():
        conditions.append(_exact_text(KevEntry.catalog_version, catalog_version))
    if cwe and cwe.strip():
        conditions.append(_cwe_condition(db, cwe))

    total = db.scalar(select(func.count()).select_from(KevEntry).where(*conditions)) or 0
    sort_column = SORT_COLUMNS[sort_by]
    primary_order = sort_column.asc() if sort_order == "asc" else sort_column.desc()
    order_by = [primary_order]
    if sort_by != "cve_id":
        order_by.append(KevEntry.cve_id.asc())
    rows = db.execute(
        select(KevEntry)
        .where(*conditions)
        .order_by(*order_by)
        .offset(offset)
        .limit(limit)
    ).scalars()
    return {
        "total": int(total),
        "limit": limit,
        "offset": offset,
        "items": [_serialize(row) for row in rows],
    }


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
