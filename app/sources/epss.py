"""
FIRST.org EPSS (Exploit Prediction Scoring System) cache.

Public API:
    https://api.first.org/data/v1/epss?cve=CVE-1,CVE-2,...

EPSS gives each CVE a probability (0..1) that it will be exploited in
the next 30 days, plus a percentile rank within the catalog. We cache
per-CVE scores with a ``EPSS_TTL_SECONDS`` (default 24h) refresh and
fall back to ``0.0`` for CVEs that have no EPSS row (median EPSS is
~0.001 so missing data has minimal impact on the composite score).

Why per-CVE on-demand instead of bulk sync:
  * The full EPSS catalog is ~250k rows. Bulk-fetching adds infra cost
    and latency that we don't need — only the CVEs in our active SBOMs
    matter at scoring time.
  * The API supports up to 100 CVEs per call, which keeps a single
    SBOM scoring round under a handful of HTTP calls.
"""

from __future__ import annotations

import logging
import os
import re
import time
from datetime import UTC, datetime

import httpx
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from ..models import EpssScore

log = logging.getLogger("sbom.sources.epss")

EPSS_API_URL = os.getenv("EPSS_API_URL", "https://api.first.org/data/v1/epss")
EPSS_TTL_SECONDS = int(os.getenv("EPSS_TTL_SECONDS", str(24 * 60 * 60)))
EPSS_HTTP_TIMEOUT = float(os.getenv("EPSS_HTTP_TIMEOUT", "20"))
EPSS_BATCH_SIZE = int(os.getenv("EPSS_BATCH_SIZE", "100"))

# Canonical CVE id shape (``CVE-YYYY-NNNN+``). EPSS is keyed strictly on CVE
# ids, so anything that isn't a well-formed CVE can never have an EPSS row — we
# keep those out of both the API call and the cache write.
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# Columns refreshed on an ``ON CONFLICT DO UPDATE``. ``cve_id`` is the conflict
# target and is intentionally excluded.
_EPSS_UPSERT_UPDATE_COLUMNS = ("epss", "percentile", "score_date", "refreshed_at")


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _is_fresh(refreshed_at: str | None) -> bool:
    if not refreshed_at:
        return False
    try:
        ts = datetime.fromisoformat(refreshed_at)
    except ValueError:
        return False
    age = (datetime.now(UTC) - ts).total_seconds()
    return age < EPSS_TTL_SECONDS


def _normalize_cve_id(raw: str | None) -> str | None:
    """Trim + upper-case a CVE id. Returns ``None`` for an empty id."""
    if not raw:
        return None
    return raw.strip().upper() or None


def _normalize_cve_ids(cve_ids: list[str]) -> list[str]:
    """Sorted, de-duplicated, trimmed + upper-cased request set."""
    return sorted({norm for norm in (_normalize_cve_id(c) for c in cve_ids) if norm})


def _is_valid_cve_id(cve_id: str) -> bool:
    """True for a canonical ``CVE-YYYY-NNNN+`` id eligible for fetch + cache."""
    return bool(_CVE_ID_RE.match(cve_id))


def _fetch_batch(cve_ids: list[str]) -> dict[str, dict]:
    """Pull a single EPSS batch. Returns ``{cve_id: {epss, percentile, date}}``."""
    if not cve_ids:
        return {}
    try:
        resp = httpx.get(
            EPSS_API_URL,
            params={"cve": ",".join(cve_ids)},
            timeout=EPSS_HTTP_TIMEOUT,
            follow_redirects=True,
        )
        resp.raise_for_status()
        payload = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        log.warning("EPSS batch fetch failed for %d CVEs: %s", len(cve_ids), exc)
        return {}

    rows = payload.get("data") or []
    out: dict[str, dict] = {}
    for r in rows:
        cve = (r.get("cve") or "").strip().upper()
        if not cve:
            continue
        try:
            epss = float(r.get("epss") or 0.0)
        except (TypeError, ValueError):
            epss = 0.0
        try:
            percentile = float(r.get("percentile")) if r.get("percentile") is not None else None
        except (TypeError, ValueError):
            percentile = None
        out[cve] = {
            "epss": max(0.0, min(1.0, epss)),
            "percentile": percentile,
            "date": r.get("date"),
        }
    return out


def _build_epss_upsert(rows: list[dict], *, dialect: str):
    """Build an atomic ``INSERT .. ON CONFLICT (cve_id) DO UPDATE`` for the cache."""
    table = EpssScore.__table__
    if dialect == "postgresql":
        insert_fn = pg_insert
    elif dialect == "sqlite":
        insert_fn = sqlite_insert
    else:  # pragma: no cover - callers dispatch on dialect before reaching here
        raise NotImplementedError(f"epss cache upsert only supports postgresql/sqlite; got {dialect!r}")

    stmt = insert_fn(table).values(rows)
    excluded = stmt.excluded
    return stmt.on_conflict_do_update(
        index_elements=[table.c.cve_id],
        set_={column: getattr(excluded, column) for column in _EPSS_UPSERT_UPDATE_COLUMNS},
    )


def _upsert_epss_rows_select_merge(db: Session, rows: list[dict]) -> None:
    """Fallback for dialects without ``INSERT .. ON CONFLICT`` support."""
    existing = db.execute(select(EpssScore).where(EpssScore.cve_id.in_([r["cve_id"] for r in rows]))).scalars().all()
    by_cve = {row.cve_id: row for row in existing}
    for row in rows:
        entry = by_cve.get(row["cve_id"])
        if entry is None:
            entry = EpssScore(cve_id=row["cve_id"])
            db.add(entry)
            by_cve[row["cve_id"]] = entry
        for column in _EPSS_UPSERT_UPDATE_COLUMNS:
            setattr(entry, column, row.get(column))


def _persist_epss_rows(db: Session, rows: list[dict], *, pre_existing: set[str]) -> None:
    """
    Atomically upsert EPSS cache rows.

    The atomic ``ON CONFLICT DO UPDATE`` means two analyses racing to cache the
    same brand-new CVE both succeed — the later writer updates the row instead
    of hitting ``pk_epss_score``. The write is best-effort: EPSS is an optional
    enrichment cache, so any failure (transient infra error, an unexpected
    dialect) is rolled back and logged, never propagated — the caller keeps the
    in-memory scores it already holds.
    """
    if not rows:
        return
    dialect = db.get_bind().dialect.name
    try:
        if dialect in {"postgresql", "sqlite"}:
            db.execute(_build_epss_upsert(rows, dialect=dialect))
        else:
            _upsert_epss_rows_select_merge(db, rows)
        db.commit()
    except Exception as exc:
        db.rollback()
        log.warning("EPSS cache upsert failed for %d CVEs: %s", len(rows), exc)
        return

    for row in rows:
        log.debug(
            "event=epss_cache_upsert cve_id=%s operation=%s score_date=%s refreshed_at=%s",
            row["cve_id"],
            "updated" if row["cve_id"] in pre_existing else "inserted",
            row.get("score_date"),
            row["refreshed_at"],
        )


def get_epss_scores(db: Session, cve_ids: list[str]) -> dict[str, float]:
    """
    Look up EPSS probabilities for ``cve_ids``.

    Strategy:
      1. Read existing rows from ``epss_score``.
      2. Identify CVEs that are missing or stale (older than the TTL).
      3. Pull those in batches from the FIRST.org API.
      4. Upsert results into the cache.
      5. Return ``{cve_id: epss_probability}``. CVEs with no EPSS data
         (the API didn't return a row) are returned as ``0.0`` so callers
         can multiply uniformly.

    Network failures are swallowed and treated as "no EPSS row" so that
    scoring stays available when the feed is unreachable.
    """
    if not cve_ids:
        return {}

    # Trim + upper-case + de-duplicate the requested ids. This set drives the
    # return map, so a caller that passes a non-canonical id still gets a 0.0
    # entry (validation below only gates the API call and the cache write).
    norm = _normalize_cve_ids(cve_ids)
    if not norm:
        return {}

    # 1. Load what's already cached.
    cached_rows = db.execute(
        select(EpssScore.cve_id, EpssScore.epss, EpssScore.refreshed_at).where(EpssScore.cve_id.in_(norm))
    ).all()
    cached: dict[str, float] = {}
    fresh_ids: set[str] = set()
    for cve, epss, refreshed_at in cached_rows:
        cached[cve] = float(epss or 0.0)
        if _is_fresh(refreshed_at):
            fresh_ids.add(cve)

    # 2. Compute the set we need to (re-)fetch. Only canonical CVE ids are
    # eligible — a malformed id can never have an EPSS row, so we keep it out
    # of the API call and the cache write entirely.
    to_fetch = [c for c in norm if _is_valid_cve_id(c) and c not in fresh_ids]

    # 3. Batch-fetch.
    pulled: dict[str, dict] = {}
    if to_fetch:
        for i in range(0, len(to_fetch), EPSS_BATCH_SIZE):
            chunk = to_fetch[i : i + EPSS_BATCH_SIZE]
            pulled.update(_fetch_batch(chunk))

        # 4. Upsert successful rows atomically. CVEs that the API didn't
        # return are NOT cached as 0.0 — that would freeze a future EPSS
        # rating forever once one is published. We just leave them out and
        # let the caller treat them as 0.0 for this request only.
        if pulled:
            now = _now_iso()
            rows = [
                {
                    "cve_id": cve,
                    "epss": fields["epss"],
                    "percentile": fields.get("percentile"),
                    "score_date": fields.get("date"),
                    "refreshed_at": now,
                }
                for cve, fields in pulled.items()
            ]
            _persist_epss_rows(db, rows, pre_existing=set(cached))

    # 5. Build the return map, preferring fresh-fetched values, then cached.
    out: dict[str, float] = {}
    for cve in norm:
        if cve in pulled:
            out[cve] = pulled[cve]["epss"]
        elif cve in cached:
            out[cve] = cached[cve]
        else:
            out[cve] = 0.0
    return out


# Hot-path memo (parallels kev.lookup_kev_set_memoized).
_score_memo: dict[tuple, dict[str, float]] = {}
_score_memo_ts: float = 0.0
_SCORE_MEMO_TTL = 60.0


def get_epss_scores_memoized(db: Session, cve_ids: list[str]) -> dict[str, float]:
    """Wrapper with a short-lived in-process memo for hot-path scoring."""
    global _score_memo, _score_memo_ts
    now = time.monotonic()
    if now - _score_memo_ts > _SCORE_MEMO_TTL:
        _score_memo = {}
        _score_memo_ts = now
    key = tuple(_normalize_cve_ids(cve_ids))
    if key in _score_memo:
        return _score_memo[key]
    result = get_epss_scores(db, list(key))
    _score_memo[key] = result
    return result
