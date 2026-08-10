"""Core logic: download the CISA KEV feed, filter by dateAdded, upsert to Postgres.

Notes
-----
* The CISA JSON feed always contains the FULL catalog. Filtering by date is
  done locally on the ``dateAdded`` field of each entry.
* Upserts use PostgreSQL ``INSERT ... ON CONFLICT (cve_id) DO UPDATE`` so the
  sync is idempotent and safe to run repeatedly (e.g. on a schedule).
"""

import logging
import time
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from .config import get_settings
from .database import KevVulnerability

logger = logging.getLogger("kev.sync")

UPSERT_BATCH_SIZE = 500


def _parse_date(value: Optional[str]) -> Optional[date]:
    if not value:
        return None
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d").date()
    except ValueError:
        logger.warning("Unparseable date value in feed: %r", value)
        return None


def _parse_release_ts(value: Optional[str]) -> Optional[datetime]:
    """CISA dateReleased looks like '2026-07-15T14:00:11.123Z'."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        logger.warning("Unparseable dateReleased: %r", value)
        return None


async def download_feed() -> Dict[str, Any]:
    """Download the full KEV catalog JSON from CISA."""
    settings = get_settings()
    logger.info("Downloading KEV feed from %s", settings.kev_feed_url)
    async with httpx.AsyncClient(
        timeout=settings.http_timeout, follow_redirects=True
    ) as client:
        resp = await client.get(
            settings.kev_feed_url, headers={"Accept": "application/json"}
        )
        resp.raise_for_status()
        return resp.json()


def _map_entry(
    raw: Dict[str, Any],
    catalog_version: Optional[str],
    catalog_released: Optional[datetime],
) -> Dict[str, Any]:
    """Map one raw feed vulnerability object to table column values."""
    return {
        "cve_id": raw.get("cveID"),
        "vendor_project": raw.get("vendorProject"),
        "product": raw.get("product"),
        "vulnerability_name": raw.get("vulnerabilityName"),
        "date_added": _parse_date(raw.get("dateAdded")),
        "short_description": raw.get("shortDescription"),
        "required_action": raw.get("requiredAction"),
        "due_date": _parse_date(raw.get("dueDate")),
        "known_ransomware_campaign_use": raw.get("knownRansomwareCampaignUse"),
        "notes": raw.get("notes"),
        "cwes": raw.get("cwes") or [],
        "catalog_version": catalog_version,
        "catalog_date_released": catalog_released,
    }


def filter_entries(
    feed: Dict[str, Any], since: Optional[date]
) -> Tuple[List[Dict[str, Any]], int]:
    """Return (mapped rows matching the filter, total entries in the feed)."""
    catalog_version = feed.get("catalogVersion")
    catalog_released = _parse_release_ts(feed.get("dateReleased"))
    raw_entries: List[Dict[str, Any]] = feed.get("vulnerabilities", [])

    rows: List[Dict[str, Any]] = []
    for raw in raw_entries:
        if not raw.get("cveID"):
            continue
        added = _parse_date(raw.get("dateAdded"))
        if since is not None and (added is None or added < since):
            continue
        rows.append(_map_entry(raw, catalog_version, catalog_released))
    return rows, len(raw_entries)


async def upsert_entries(session: AsyncSession, rows: List[Dict[str, Any]]) -> int:
    """Idempotent bulk upsert keyed on cve_id. Returns number of rows written."""
    if not rows:
        return 0

    written = 0
    for i in range(0, len(rows), UPSERT_BATCH_SIZE):
        batch = rows[i : i + UPSERT_BATCH_SIZE]
        stmt = pg_insert(KevVulnerability).values(batch)
        update_cols = {
            col: stmt.excluded[col]
            for col in (
                "vendor_project",
                "product",
                "vulnerability_name",
                "date_added",
                "short_description",
                "required_action",
                "due_date",
                "known_ransomware_campaign_use",
                "notes",
                "cwes",
                "catalog_version",
                "catalog_date_released",
            )
        }
        stmt = stmt.on_conflict_do_update(
            index_elements=[KevVulnerability.cve_id], set_=update_cols
        )
        await session.execute(stmt)
        written += len(batch)

    await session.commit()
    return written


async def sync_kev(
    session: AsyncSession, since: Optional[date] = None
) -> Dict[str, Any]:
    """Full sync pipeline: download -> filter -> upsert. Returns a summary."""
    started = time.perf_counter()

    feed = await download_feed()
    rows, total_in_feed = filter_entries(feed, since)
    upserted = await upsert_entries(session, rows)

    summary = {
        "catalog_version": feed.get("catalogVersion"),
        "catalog_date_released": _parse_release_ts(feed.get("dateReleased")),
        "total_in_feed": total_in_feed,
        "filtered_since": since,
        "matched_after_filter": len(rows),
        "upserted": upserted,
        "duration_seconds": round(time.perf_counter() - started, 3),
    }
    logger.info("KEV sync complete: %s", summary)
    return summary
