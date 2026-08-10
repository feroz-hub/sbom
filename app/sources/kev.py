"""
CISA Known Exploited Vulnerabilities (KEV) catalog mirror.

Public feed:
    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

We refresh the local mirror once per ``KEV_TTL_SECONDS`` (default 24h).
Presence of a CVE in the local ``kev_vulnerabilities`` table is the sole signal
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
import threading
import time
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import KevEntry
from ..services import kev_service
from ..settings import get_settings

log = logging.getLogger("sbom.sources.kev")

_settings = get_settings()
KEV_FEED_URL = _settings.kev_feed_url
KEV_TTL_SECONDS = _settings.kev_ttl_seconds
KEV_HTTP_TIMEOUT = _settings.kev_http_timeout
KEV_FAILURE_RETRY_SECONDS = _settings.kev_failure_retry_seconds

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
    "known_ransomware_campaign_use",
    "notes",
    "cwes",
    "catalog_version",
    "catalog_date_released",
    "refreshed_at",
    "updated_at",
)


KevRefreshError = kev_service.KevRefreshError


def _now_iso() -> str:
    return kev_service.now_iso()


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


def _fetch_feed() -> dict[str, Any]:
    """Pull the KEV JSON feed. Kept as a monkeypatch seam for tests."""
    return kev_service.download_feed(url=KEV_FEED_URL, timeout=KEV_HTTP_TIMEOUT)


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
    return kev_service.row_from_feed_item(vulnerability, refreshed_at=refreshed_at)


def _rows_from_feed(vulnerabilities: dict[str, Any] | list[dict], *, refreshed_at: str) -> list[dict[str, Any]]:
    """Normalize and dedupe KEV feed rows by CVE id before touching the DB."""
    rows, _total = kev_service.rows_from_feed(vulnerabilities, refreshed_at=refreshed_at)
    return rows


def _build_upsert_statement(rows: list[dict[str, Any]], *, dialect: str):
    return kev_service.build_upsert_statement(rows, dialect=dialect)


def _upsert_kev_rows(db: Session, rows: list[dict[str, Any]], *, dialect: str) -> None:
    kev_service.upsert_kev_rows(db, rows, dialect=dialect)


def _upsert_kev_rows_select_merge(db: Session, rows: list[dict[str, Any]]) -> None:
    """Fallback for dialects without ``INSERT .. ON CONFLICT`` support."""
    kev_service.upsert_kev_rows_select_merge(db, rows)


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
