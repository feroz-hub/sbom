"""Repository for the per-(source, component) raw-response cache.

Roadmap #2, PR-A. Storage is the DB table ``source_response_cache``
(migration 018), mirroring ``cve_cache``'s read-time-TTL pattern so the
new cache slots into the same operational mental model.

Public surface — ``get`` / ``set``. Everything else (the table, the
clock, the deserialisation guards) is an internal concern of this
module. PR-B wires this around per-source fetch calls; nothing else
in the codebase should touch the table directly.

Design notes
------------
* **Clock is injectable.** The default is ``datetime.now(timezone.utc)``
  but tests pass a callable that returns a controlled instant so TTL
  expiry can be asserted deterministically without ``freezegun`` etc.
* **TTL on write, check on read.** ``set(...)`` records
  ``expires_at = clock() + ttl_seconds``; ``get(...)`` returns ``None``
  when ``clock() >= expires_at`` even if the row exists. This matches
  ``cve_cache``'s behaviour at [services/cve_service.py:206-229].
* **``set`` accepts ``ttl_seconds`` per call** so a future per-source
  override (e.g. NVD-with-mirror gets a tighter TTL than OSV) is a
  caller-side decision; no schema or repository change required.
* **Defensive on write.** Storage failures are logged-and-swallowed so
  a cache write that races with a schema migration or a quota event
  never fails the surrounding fetch. The next ``get`` will be a miss,
  the caller refetches, the next ``set`` will retry — exactly the
  pattern ``CveDetailService._write_cache`` uses.
* **Component key = canonical PURL string.** Same component across
  SBOMs shares one cache entry. The repository does NOT normalise the
  key — callers pass whatever stable shape they've agreed on (PR-B's
  decision point). Pre-normalising here would couple the repo to PURL
  parsing.

NOT this repository's job
-------------------------
* PURL normalisation (caller decides).
* Per-source TTL selection (caller passes ``ttl_seconds``).
* Force-refresh / bypass logic (PR-B at the wiring layer).
* Hit/miss metrics (PR-B at the wiring layer).
* Periodic sweep of expired rows (housekeeping cron, future).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select, tuple_
from sqlalchemy.orm import Session

from ..models import SourceResponseCache

log = logging.getLogger(__name__)


def _DEFAULT_CLOCK() -> datetime:
    return datetime.now(UTC)


class SourceResponseCacheRepository:
    """DB-backed cache of (source, component_key) → raw source response.

    Construct with an open ``Session`` (the caller owns the transaction
    lifecycle, matching the rest of ``app/services``). The ``clock``
    parameter is here purely for tests; production code accepts the
    default UTC-now.
    """

    def __init__(
        self,
        db: Session,
        *,
        clock: Callable[[], datetime] = _DEFAULT_CLOCK,
    ) -> None:
        self._db = db
        self._clock = clock

    # ------------------------------------------------------------------ get

    def get(self, source: str, component_key: str) -> Any | None:
        """Return the cached payload or ``None`` for miss / stale / corrupt.

        A row whose ``expires_at`` has passed is treated as a miss —
        the caller refetches and the next ``set`` overwrites the stale
        row. We deliberately do NOT delete here: deletion adds a write
        on every stale read which doubles the load under contention.
        The expires_at index makes a periodic sweep cheap if/when one
        is added.
        """
        row = self._db.get(SourceResponseCache, (source, component_key))
        if row is None:
            return None
        try:
            expires = datetime.fromisoformat(row.expires_at)
        except (TypeError, ValueError):
            # Corrupted timestamp — treat as miss. The next write
            # overwrites; we don't try to repair in place because
            # readers should be cheap and side-effect-free.
            return None
        if self._clock() >= expires:
            return None
        payload = row.payload
        if isinstance(payload, dict) or isinstance(payload, list):
            # Postgres JSONB / SQLAlchemy ``JSON`` round-trips Python
            # containers directly.
            return payload
        if isinstance(payload, str):
            # SQLite ``JSON`` is TEXT — deserialise on read.
            try:
                return json.loads(payload)
            except (TypeError, ValueError) as exc:
                log.warning(
                    "source_response_cache: payload deserialise failed "
                    "(source=%r component_key=%r): %s",
                    source, component_key, exc,
                )
                return None
        # Any other shape (None, primitive) is preserved as-is — JSON
        # technically allows primitives at the root.
        return payload

    # ------------------------------------------------------------------ set

    def set(
        self,
        source: str,
        component_key: str,
        payload: Any,
        *,
        ttl_seconds: int,
    ) -> None:
        """Upsert one cache entry. ``ttl_seconds`` is required.

        ``ttl_seconds`` is per-call rather than a constructor field so
        callers can pass a per-source override without re-instantiating
        the repository. PR-B reads ``settings.source_cache_ttl_seconds``
        as the default; future calibration can specialise per source.

        Storage failures are logged and swallowed — see the module
        docstring's defensive-write rationale. The transaction is
        committed here because that's the contract ``cve_cache``'s
        writer uses; callers don't need to remember.
        """
        if ttl_seconds <= 0:
            # Zero/negative TTL means "do not cache" — silently a no-op
            # so a caller passing a misconfigured value never bloats
            # the table with already-expired rows.
            return
        now = self._clock()
        expires = now + timedelta(seconds=ttl_seconds)
        try:
            self._db.merge(
                SourceResponseCache(
                    source=source,
                    component_key=component_key,
                    payload=payload,
                    fetched_at=now.isoformat(),
                    expires_at=expires.isoformat(),
                )
            )
            self._db.commit()
        except Exception as exc:  # pragma: no cover — defensive
            log.warning(
                "source_response_cache: write failed (source=%r component_key=%r): %s",
                source, component_key, exc,
            )
            self._db.rollback()


    # ---------------------------------------------------------- delete_expired

    def delete_expired(self, *, batch_size: int = 10000) -> int:
        """Delete up to ``batch_size`` rows whose ``expires_at`` has passed.

        Housekeeping helper for the daily Celery sweep (roadmap #2
        PR-E). Returns the count of rows deleted — useful for sweep-
        run telemetry.

        Notes
        ~~~~~
          * **Correctness** does NOT depend on this: ``get`` already
            treats expired rows as a miss (see the read-time check
            above). Sweeping only reclaims table space.
          * **Portable delete pattern**. Postgres doesn't support
            ``DELETE...LIMIT`` directly and SQLite supports it only on
            builds compiled with ``SQLITE_ENABLE_UPDATE_DELETE_LIMIT``.
            Use a subquery to select up to ``batch_size`` (source,
            component_key) pairs (the composite PK) then DELETE WHERE
            tuple IN subquery — works on both dialects.
          * **Bounded single batch per call**. Loops are deliberately
            absent so one task firing always finishes in tightly
            bounded time. Backlog (if any) drains across days of
            sweeps. If telemetry shows the backlog never drains, add
            a loop in a follow-up — for now, simplest is safest.
        """
        if batch_size <= 0:
            return 0
        now_iso = self._clock().isoformat()

        # Pick the expired composite-PK pairs first. Materialise via
        # ``.all()`` so the subsequent DELETE doesn't reference a
        # subquery on the same table (which would be a footgun on
        # some Postgres + MVCC setups).
        expired_pairs = (
            self._db.execute(
                select(
                    SourceResponseCache.source,
                    SourceResponseCache.component_key,
                )
                .where(SourceResponseCache.expires_at < now_iso)
                .limit(batch_size)
            )
            .all()
        )
        if not expired_pairs:
            return 0

        # ``tuple_`` IN subquery is supported on both Postgres and
        # SQLite; the composite-PK index makes the lookup cheap.
        try:
            result = self._db.execute(
                delete(SourceResponseCache).where(
                    tuple_(
                        SourceResponseCache.source,
                        SourceResponseCache.component_key,
                    ).in_(expired_pairs)
                )
            )
            self._db.commit()
        except Exception as exc:  # pragma: no cover — defensive
            log.warning("source_response_cache: delete_expired failed: %s", exc)
            self._db.rollback()
            return 0

        deleted = int(getattr(result, "rowcount", 0) or 0)
        if deleted <= 0:
            # Fall back to the pre-delete count when the dialect didn't
            # populate ``rowcount`` (rare on SQLite < 3.6). The selected
            # set is the upper bound, used for telemetry only.
            deleted = len(expired_pairs)
        return deleted


__all__ = ["SourceResponseCacheRepository"]
