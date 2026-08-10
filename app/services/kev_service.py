"""CISA KEV catalog sync service.

This module is the reusable service layer for the local KEV mirror.  It owns
feed download, CISA payload normalization, and idempotent database writes.
Existing risk scoring imports still flow through ``app.sources.kev``; that
module delegates here while preserving its historical public functions.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, date, datetime
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from ..models import KevEntry
from ..settings import get_settings

log = logging.getLogger("sbom.services.kev")

UPSERT_BATCH_SIZE = 500

UPSERT_UPDATE_COLUMNS = (
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
    "refreshed_at",
    "updated_at",
)


class KevRefreshError(RuntimeError):
    """Raised for expected refresh failures that should fall back to cache."""


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def parse_date_string(value: Any) -> str | None:
    """Return a YYYY-MM-DD string for CISA date fields, or None if invalid."""
    if value in (None, ""):
        return None
    if isinstance(value, date):
        return value.isoformat()
    raw = str(value).strip()
    try:
        return datetime.strptime(raw, "%Y-%m-%d").date().isoformat()
    except ValueError:
        log.warning("kev_sync_unparseable_date", extra={"value": raw})
        return None


def parse_release_timestamp(value: Any) -> str | None:
    """Return an ISO timestamp for CISA ``dateReleased`` metadata."""
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=UTC)
        return dt.isoformat()
    raw = str(value).strip()
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        log.warning("kev_sync_unparseable_release_timestamp", extra={"value": raw})
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.isoformat()


def download_feed(*, url: str | None = None, timeout: float | None = None) -> dict[str, Any]:
    """Download the full CISA KEV JSON feed."""
    settings = get_settings()
    feed_url = url or settings.kev_feed_url
    http_timeout = timeout if timeout is not None else settings.kev_http_timeout
    try:
        response = httpx.get(
            feed_url,
            headers={"Accept": "application/json"},
            timeout=http_timeout,
            follow_redirects=True,
        )
        response.raise_for_status()
        payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise KevRefreshError("fetch_failed") from exc
    if not isinstance(payload, dict):
        raise KevRefreshError("invalid_payload")
    if not isinstance(payload.get("vulnerabilities"), list):
        raise KevRefreshError("invalid_payload")
    return payload


def row_from_feed_item(
    vulnerability: dict[str, Any],
    *,
    refreshed_at: str,
    catalog_version: str | None = None,
    catalog_date_released: str | None = None,
) -> dict[str, Any] | None:
    """Map one raw CISA vulnerability object to ``KevEntry`` column values."""
    cve_id = (vulnerability.get("cveID") or "").strip().upper()
    if not cve_id:
        return None
    cwes = vulnerability.get("cwes")
    if not isinstance(cwes, list):
        cwes = []
    return {
        "cve_id": cve_id,
        "vendor_project": vulnerability.get("vendorProject"),
        "product": vulnerability.get("product"),
        "vulnerability_name": vulnerability.get("vulnerabilityName"),
        "date_added": parse_date_string(vulnerability.get("dateAdded")),
        "short_description": vulnerability.get("shortDescription"),
        "required_action": vulnerability.get("requiredAction"),
        "due_date": parse_date_string(vulnerability.get("dueDate")),
        "known_ransomware_campaign_use": vulnerability.get("knownRansomwareCampaignUse"),
        "notes": vulnerability.get("notes"),
        "cwes": [str(cwe) for cwe in cwes if cwe],
        "catalog_version": catalog_version,
        "catalog_date_released": catalog_date_released,
        "refreshed_at": refreshed_at,
        "first_seen_at": refreshed_at,
        "updated_at": refreshed_at,
    }


def rows_from_feed(
    feed: dict[str, Any] | list[dict[str, Any]],
    *,
    refreshed_at: str,
    since: date | str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Normalize, filter, and dedupe CISA feed rows by CVE id."""
    if isinstance(feed, dict):
        catalog_version = feed.get("catalogVersion")
        catalog_date_released = parse_release_timestamp(feed.get("dateReleased"))
        raw_entries = feed.get("vulnerabilities") or []
    else:
        catalog_version = None
        catalog_date_released = None
        raw_entries = feed

    if not isinstance(raw_entries, list):
        raise KevRefreshError("invalid_payload")

    since_str = parse_date_string(since) if since is not None else None
    by_cve: dict[str, dict[str, Any]] = {}
    for vulnerability in raw_entries:
        if not isinstance(vulnerability, dict):
            continue
        date_added = parse_date_string(vulnerability.get("dateAdded"))
        if since_str is not None and (date_added is None or date_added < since_str):
            continue
        row = row_from_feed_item(
            vulnerability,
            refreshed_at=refreshed_at,
            catalog_version=str(catalog_version) if catalog_version else None,
            catalog_date_released=catalog_date_released,
        )
        if row is not None:
            by_cve[row["cve_id"]] = row
    return list(by_cve.values()), len(raw_entries)


def build_upsert_statement(rows: list[dict[str, Any]], *, dialect: str):
    table = KevEntry.__table__
    if dialect == "postgresql":
        insert_fn = pg_insert
    elif dialect == "sqlite":
        insert_fn = sqlite_insert
    else:
        raise NotImplementedError(f"kev cache upsert only supports postgresql/sqlite; got {dialect!r}")

    stmt = insert_fn(table).values(rows)
    excluded = stmt.excluded
    return stmt.on_conflict_do_update(
        index_elements=[table.c.cve_id],
        set_={column: getattr(excluded, column) for column in UPSERT_UPDATE_COLUMNS},
    )


def upsert_kev_rows(db: Session, rows: list[dict[str, Any]], *, dialect: str) -> None:
    for start in range(0, len(rows), UPSERT_BATCH_SIZE):
        db.execute(build_upsert_statement(rows[start : start + UPSERT_BATCH_SIZE], dialect=dialect))


def upsert_kev_rows_select_merge(db: Session, rows: list[dict[str, Any]]) -> None:
    """Fallback for dialects without ``INSERT .. ON CONFLICT`` support."""
    existing_rows = (
        db.execute(select(KevEntry).where(KevEntry.cve_id.in_([row["cve_id"] for row in rows]))).scalars().all()
    )
    existing_by_cve = {row.cve_id: row for row in existing_rows}
    for row in rows:
        entry = existing_by_cve.get(row["cve_id"])
        if entry is None:
            entry = KevEntry(cve_id=row["cve_id"], refreshed_at=row["refreshed_at"])
            db.add(entry)
            existing_by_cve[row["cve_id"]] = entry
        for column, value in row.items():
            if column == "first_seen_at" and getattr(entry, "first_seen_at", None):
                continue
            setattr(entry, column, value)


def write_rows(db: Session, rows: list[dict[str, Any]], *, prune_stale: bool = True) -> None:
    """Write normalized KEV rows, optionally removing CVEs absent from a full feed."""
    if prune_stale:
        incoming_ids = {row["cve_id"] for row in rows}
        existing = {r for r in db.execute(select(KevEntry.cve_id)).scalars().all() if r}
        stale = existing - incoming_ids
        if stale:
            db.query(KevEntry).filter(KevEntry.cve_id.in_(stale)).delete(synchronize_session=False)

    dialect = db.get_bind().dialect.name
    if dialect in {"postgresql", "sqlite"}:
        upsert_kev_rows(db, rows, dialect=dialect)
    else:
        upsert_kev_rows_select_merge(db, rows)


def sync_kev(
    db: Session,
    *,
    since: date | str | None = None,
    feed: dict[str, Any] | list[dict[str, Any]] | None = None,
    prune_stale: bool = True,
    commit: bool = True,
) -> dict[str, Any]:
    """Download/filter/upsert the KEV catalog and return a sync summary."""
    started = time.perf_counter()
    payload = feed if feed is not None else download_feed()
    refreshed_at = now_iso()
    rows, total_in_feed = rows_from_feed(payload, refreshed_at=refreshed_at, since=since)
    if rows:
        write_rows(db, rows, prune_stale=prune_stale and since is None)
    if commit:
        db.commit()

    catalog_version = payload.get("catalogVersion") if isinstance(payload, dict) else None
    catalog_date_released = parse_release_timestamp(payload.get("dateReleased")) if isinstance(payload, dict) else None
    return {
        "catalog_version": catalog_version,
        "catalog_date_released": catalog_date_released,
        "total_in_feed": total_in_feed,
        "filtered_since": parse_date_string(since) if since is not None else None,
        "matched_after_filter": len(rows),
        "upserted": len(rows),
        "duration_seconds": round(time.perf_counter() - started, 3),
    }
