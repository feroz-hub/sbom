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

import logging
import os
import time
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import KevEntry

log = logging.getLogger("sbom.sources.kev")

KEV_FEED_URL = os.getenv(
    "KEV_FEED_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)
KEV_TTL_SECONDS = int(os.getenv("KEV_TTL_SECONDS", str(24 * 60 * 60)))
KEV_HTTP_TIMEOUT = float(os.getenv("KEV_HTTP_TIMEOUT", "30"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _cache_age_seconds(db: Session) -> float | None:
    """Return age (seconds) of the freshest row, or None if cache is empty."""
    row = (
        db.execute(select(KevEntry.refreshed_at).order_by(KevEntry.refreshed_at.desc()).limit(1))
        .scalars()
        .first()
    )
    if not row:
        return None
    try:
        ts = datetime.fromisoformat(row)
        return (datetime.now(timezone.utc) - ts).total_seconds()
    except ValueError:
        return None


def _fetch_feed() -> list[dict] | None:
    """Pull the KEV JSON feed. Returns ``vulnerabilities`` list or ``None`` on failure."""
    try:
        resp = httpx.get(KEV_FEED_URL, timeout=KEV_HTTP_TIMEOUT, follow_redirects=True)
        resp.raise_for_status()
        payload = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        log.warning("KEV feed fetch failed: %s", exc)
        return None
    vulns = payload.get("vulnerabilities")
    if not isinstance(vulns, list):
        log.warning("KEV feed payload missing 'vulnerabilities' list")
        return None
    return vulns


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

    vulns = _fetch_feed()
    if vulns is None:
        # Network error — keep using whatever is already cached.
        return False

    refreshed_at = _now_iso()
    incoming_ids: set[str] = set()
    rows: list[KevEntry] = []
    for v in vulns:
        cve_id = (v.get("cveID") or "").strip().upper()
        if not cve_id:
            continue
        incoming_ids.add(cve_id)
        rows.append(
            KevEntry(
                cve_id=cve_id,
                vendor_project=v.get("vendorProject"),
                product=v.get("product"),
                vulnerability_name=v.get("vulnerabilityName"),
                date_added=v.get("dateAdded"),
                short_description=v.get("shortDescription"),
                required_action=v.get("requiredAction"),
                due_date=v.get("dueDate"),
                known_ransomware_use=v.get("knownRansomwareCampaignUse"),
                refreshed_at=refreshed_at,
            )
        )

    if not rows:
        return False

    # Upsert via delete+insert pattern. KEV catalog is small (~1.2k rows),
    # so the cost of a clean replace is trivial and the code is much
    # simpler than dialect-specific UPSERT.
    try:
        existing = {
            r for r in db.execute(select(KevEntry.cve_id)).scalars().all() if r
        }
        # Drop entries that fell off the catalog
        stale = existing - incoming_ids
        if stale:
            db.query(KevEntry).filter(KevEntry.cve_id.in_(stale)).delete(
                synchronize_session=False
            )
        for row in rows:
            db.merge(row)
        db.commit()
    except Exception as exc:
        log.warning("KEV cache commit failed: %s", exc)
        db.rollback()
        return False

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
