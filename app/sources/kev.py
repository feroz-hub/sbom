"""
CISA Known Exploited Vulnerabilities (KEV) catalog mirror.

Public feed:
    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

We refresh the local mirror once per ``KEV_TTL_SECONDS`` (default 24h).
Presence of a CVE in the local ``kev_entry`` table is the sole signal
the risk scorer needs — KEV is a categorical "yes/no" indicator. Network
failures never raise: the scorer falls back to whatever is already
cached (which on first boot may be empty, in which case no KEV boost
is applied).

Sync rather than async because:
  * It's called rarely (at most once per scoring request, at most once
    per 24h does any I/O).
  * The DB session passed in is sync (Depends(get_db)).
  * Avoids needing to run an async client in a sync request handler.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from ..models import KevEntry

log = logging.getLogger("sbom.sources.kev")

KEV_FEED_URL = os.getenv(
    "KEV_FEED_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)
KEV_TTL_SECONDS = int(os.getenv("KEV_TTL_SECONDS", str(24 * 60 * 60)))
KEV_HTTP_TIMEOUT = float(os.getenv("KEV_HTTP_TIMEOUT", "30"))
KEV_FAILURE_RETRY_SECONDS = float(os.getenv("KEV_FAILURE_RETRY_SECONDS", str(5 * 60)))

# Public async lock for async refresh callers. The current FastAPI dashboard
# handlers are sync/threadpool code, so the sync path below uses the companion
# thread lock to provide the same single-flight behavior safely.
kev_refresh_lock = asyncio.Lock()
_kev_refresh_thread_lock = threading.Lock()
_last_refresh_failed_at = 0.0
_last_refresh_failure_signature: str | None = None
_last_refresh_failure_logged_at = 0.0
_FAILURE_LOG_SUPPRESS_SECONDS = 5 * 60

_UPSERT_UPDATE_COLUMNS = (
    "vendor_project",
    "product",
    "vulnerability_name",
    "date_added",
    "short_description",
    "required_action",
    "due_date",
    "known_ransomware_use",
    "refreshed_at",
)


class KevRefreshError(RuntimeError):
    """Raised for expected refresh failures that should fall back to cache."""


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _cache_age_seconds(db: Session) -> float | None:
    """Return age (seconds) of the freshest row, or None if cache is empty."""
    row = db.execute(select(KevEntry.refreshed_at).order_by(KevEntry.refreshed_at.desc()).limit(1)).scalars().first()
    if not row:
        return None
    try:
        ts = datetime.fromisoformat(row)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        return (datetime.now(UTC) - ts).total_seconds()
    except (TypeError, ValueError):
        return None


def _fetch_feed() -> list[dict]:
    """Pull the KEV JSON feed. Returns the ``vulnerabilities`` list."""
    try:
        resp = httpx.get(KEV_FEED_URL, timeout=KEV_HTTP_TIMEOUT, follow_redirects=True)
        resp.raise_for_status()
        payload = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise KevRefreshError("fetch_failed") from exc
    vulns = payload.get("vulnerabilities")
    if not isinstance(vulns, list):
        raise KevRefreshError("invalid_payload")
    return vulns


def _cache_has_rows(db: Session) -> bool:
    return db.execute(select(KevEntry.cve_id).limit(1)).scalar_one_or_none() is not None


def _should_skip_recent_failure(*, force: bool) -> bool:
    if force or _last_refresh_failed_at <= 0:
        return False
    return (time.monotonic() - _last_refresh_failed_at) < KEV_FAILURE_RETRY_SECONDS


def _note_refresh_success() -> None:
    global _last_refresh_failed_at, _last_refresh_failure_signature, _last_refresh_failure_logged_at
    _last_refresh_failed_at = 0.0
    _last_refresh_failure_signature = None
    _last_refresh_failure_logged_at = 0.0


def _note_refresh_failure(exc: Exception, *, has_cached_data: bool) -> None:
    """Record and throttle refresh failures without dumping duplicate DB errors."""
    global _last_refresh_failed_at, _last_refresh_failure_signature, _last_refresh_failure_logged_at
    now = time.monotonic()
    signature = f"{type(exc).__name__}:{exc}"
    should_log = (
        signature != _last_refresh_failure_signature
        or (now - _last_refresh_failure_logged_at) >= _FAILURE_LOG_SUPPRESS_SECONDS
    )
    _last_refresh_failed_at = now
    if should_log:
        log.warning(
            "kev_cache_refresh_failed",
            extra={
                "error_type": type(exc).__name__,
                "has_cached_data": has_cached_data,
                "retry_after_seconds": KEV_FAILURE_RETRY_SECONDS,
            },
        )
        _last_refresh_failure_signature = signature
        _last_refresh_failure_logged_at = now


def _row_from_feed_item(vulnerability: dict[str, Any], *, refreshed_at: str) -> dict[str, Any] | None:
    cve_id = (vulnerability.get("cveID") or "").strip().upper()
    if not cve_id:
        return None
    return {
        "cve_id": cve_id,
        "vendor_project": vulnerability.get("vendorProject"),
        "product": vulnerability.get("product"),
        "vulnerability_name": vulnerability.get("vulnerabilityName"),
        "date_added": vulnerability.get("dateAdded"),
        "short_description": vulnerability.get("shortDescription"),
        "required_action": vulnerability.get("requiredAction"),
        "due_date": vulnerability.get("dueDate"),
        "known_ransomware_use": vulnerability.get("knownRansomwareCampaignUse"),
        "refreshed_at": refreshed_at,
    }


def _rows_from_feed(vulnerabilities: list[dict], *, refreshed_at: str) -> list[dict[str, Any]]:
    """Normalize and dedupe KEV feed rows by CVE id before touching the DB."""
    by_cve: dict[str, dict[str, Any]] = {}
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            continue
        row = _row_from_feed_item(vulnerability, refreshed_at=refreshed_at)
        if row is not None:
            by_cve[row["cve_id"]] = row
    return list(by_cve.values())


def _build_upsert_statement(rows: list[dict[str, Any]], *, dialect: str):
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
        set_={column: getattr(excluded, column) for column in _UPSERT_UPDATE_COLUMNS},
    )


def _upsert_kev_rows(db: Session, rows: list[dict[str, Any]], *, dialect: str) -> None:
    db.execute(_build_upsert_statement(rows, dialect=dialect))


def _upsert_kev_rows_select_merge(db: Session, rows: list[dict[str, Any]]) -> None:
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
        for column in _UPSERT_UPDATE_COLUMNS:
            setattr(entry, column, row.get(column))


def _write_rows(db: Session, rows: list[dict[str, Any]]) -> None:
    incoming_ids = {row["cve_id"] for row in rows}
    existing = {r for r in db.execute(select(KevEntry.cve_id)).scalars().all() if r}
    stale = existing - incoming_ids
    if stale:
        db.query(KevEntry).filter(KevEntry.cve_id.in_(stale)).delete(synchronize_session=False)

    dialect = db.get_bind().dialect.name
    if dialect in {"postgresql", "sqlite"}:
        _upsert_kev_rows(db, rows, dialect=dialect)
    else:
        _upsert_kev_rows_select_merge(db, rows)


def refresh_if_stale(db: Session, *, force: bool = False) -> bool:
    """
    Refresh the local KEV mirror if older than ``KEV_TTL_SECONDS``.

    Returns True if a refresh actually ran and committed; False if the
    cache was fresh, the feed couldn't be retrieved, or refresh was
    skipped. Never raises — KEV enrichment is best-effort.
    """
    if not force:
        age = _cache_age_seconds(db)
        if age is not None and age < KEV_TTL_SECONDS:
            return False
        if _should_skip_recent_failure(force=force):
            return False

    with _kev_refresh_thread_lock:
        if not force:
            age = _cache_age_seconds(db)
            if age is not None and age < KEV_TTL_SECONDS:
                return False
            if _should_skip_recent_failure(force=force):
                return False

        try:
            vulns = _fetch_feed()
            refreshed_at = _now_iso()
            rows = _rows_from_feed(vulns, refreshed_at=refreshed_at)

            if not rows:
                return False

            _write_rows(db, rows)
            db.commit()
        except Exception as exc:
            db.rollback()
            _note_refresh_failure(exc, has_cached_data=_cache_has_rows(db))
            return False

        _note_refresh_success()
        _lookup_memo.clear()
        log.info("KEV cache refreshed: %d entries", len(rows))
        return True


def lookup_kev_set(db: Session, cve_ids: list[str]) -> set[str]:
    """
    Return the subset of ``cve_ids`` that are present in the local KEV mirror.

    Always normalises CVE IDs to uppercase. Triggers a refresh-if-stale
    on the way in so the very first call after a deploy populates the
    cache instead of returning an empty set forever.
    """
    if not cve_ids:
        return set()
    refresh_if_stale(db)
    norm = [c.strip().upper() for c in cve_ids if c]
    if not norm:
        return set()
    rows = db.execute(select(KevEntry.cve_id).where(KevEntry.cve_id.in_(norm))).scalars().all()
    return set(rows)


# Convenience: small in-process memo to avoid hammering the table when
# scoring large SBOMs. Keyed by (cache-fingerprint, cve_id_tuple).
_lookup_memo: dict[tuple, set[str]] = {}
_lookup_memo_ts: float = 0.0
_LOOKUP_MEMO_TTL = 60.0  # seconds


def lookup_kev_set_memoized(db: Session, cve_ids: list[str]) -> set[str]:
    """Wrapper with a short-lived in-process memo for hot-path scoring."""
    global _lookup_memo, _lookup_memo_ts
    now = time.monotonic()
    if now - _lookup_memo_ts > _LOOKUP_MEMO_TTL:
        _lookup_memo = {}
        _lookup_memo_ts = now
    key = tuple(sorted({c.strip().upper() for c in cve_ids if c}))
    if key in _lookup_memo:
        return _lookup_memo[key]
    result = lookup_kev_set(db, list(key))
    _lookup_memo[key] = result
    return result


def reset_refresh_state_for_tests() -> None:
    """Clear in-process KEV refresh/memo state between tests."""
    global _last_refresh_failed_at, _last_refresh_failure_logged_at, _last_refresh_failure_signature, _lookup_memo_ts
    _last_refresh_failed_at = 0.0
    _last_refresh_failure_signature = None
    _last_refresh_failure_logged_at = 0.0
    _lookup_memo.clear()
    _lookup_memo_ts = 0.0
