"""FastAPI service that downloads the CISA KEV catalog and stores it in Postgres.

Endpoints
---------
POST /kev/sync            Download the feed and upsert into Postgres.
                          Optional ?since_date=YYYY-MM-DD filters on dateAdded.
                          If omitted, falls back to KEV_SINCE_DATE from config;
                          if that is also unset, the FULL catalog is synced.
GET  /kev                 List stored entries (filter/paginate).
GET  /kev/{cve_id}        Fetch a single stored entry.
GET  /health              Liveness check.

Run:  uvicorn app.main:app --reload
"""

import logging
from contextlib import asynccontextmanager
from datetime import date
from typing import Optional

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import get_settings
from .database import KevVulnerability, get_session, init_db
from .kev_service import sync_kev
from .schemas import KevEntryOut, KevListOut, SyncResult

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="CISA KEV Sync Service",
    description=(
        "Downloads the CISA Known Exploited Vulnerabilities catalog, optionally "
        "filters by dateAdded, and upserts entries into a local PostgreSQL database."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post("/kev/sync", response_model=SyncResult)
async def trigger_sync(
    since_date: Optional[date] = Query(
        default=None,
        description=(
            "Only sync entries with dateAdded >= this date (YYYY-MM-DD). "
            "Omit to use KEV_SINCE_DATE from config, or the full catalog "
            "if that is unset."
        ),
    ),
    session: AsyncSession = Depends(get_session),
) -> SyncResult:
    """Download the KEV feed and upsert entries into Postgres."""
    settings = get_settings()
    effective_since = since_date or settings.kev_since_date

    try:
        summary = await sync_kev(session, since=effective_since)
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502, detail=f"Failed to download KEV feed: {exc}"
        ) from exc

    return SyncResult(**summary)


@app.get("/kev", response_model=KevListOut)
async def list_kev(
    since_date: Optional[date] = Query(
        default=None, description="Filter stored entries with date_added >= this date"
    ),
    vendor: Optional[str] = Query(default=None, description="Case-insensitive vendor match"),
    ransomware_only: bool = Query(default=False),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_session),
) -> KevListOut:
    """Query the locally stored KEV entries."""
    conditions = []
    if since_date:
        conditions.append(KevVulnerability.date_added >= since_date)
    if vendor:
        conditions.append(KevVulnerability.vendor_project.ilike(f"%{vendor}%"))
    if ransomware_only:
        conditions.append(
            KevVulnerability.known_ransomware_campaign_use.ilike("known")
        )

    total = (
        await session.execute(
            select(func.count()).select_from(KevVulnerability).where(*conditions)
        )
    ).scalar_one()

    result = await session.execute(
        select(KevVulnerability)
        .where(*conditions)
        .order_by(KevVulnerability.date_added.desc(), KevVulnerability.cve_id)
        .limit(limit)
        .offset(offset)
    )
    items = result.scalars().all()

    return KevListOut(
        total=total,
        limit=limit,
        offset=offset,
        items=[KevEntryOut.model_validate(i) for i in items],
    )


@app.get("/kev/{cve_id}", response_model=KevEntryOut)
async def get_kev(
    cve_id: str, session: AsyncSession = Depends(get_session)
) -> KevEntryOut:
    result = await session.execute(
        select(KevVulnerability).where(
            KevVulnerability.cve_id == cve_id.upper().strip()
        )
    )
    entry = result.scalar_one_or_none()
    if entry is None:
        raise HTTPException(status_code=404, detail=f"{cve_id} not found in local DB")
    return KevEntryOut.model_validate(entry)
