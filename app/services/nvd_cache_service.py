"""Persistence boundary for cache-first NVD enrichment."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..models import NvdLookupCache
from ..settings import Settings, get_settings


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat()


class NvdCacheService:
    def __init__(self, db: Session, settings: Settings | None = None) -> None:
        self.db = db
        self.settings = settings or get_settings()

    @staticmethod
    def identifier_hash(identifier: str) -> str:
        return hashlib.sha256(identifier.strip().encode("utf-8")).hexdigest()

    def get_valid_cache(self, identifier: str, lookup_type: str) -> NvdLookupCache | None:
        row = self.db.execute(
            select(NvdLookupCache).where(
                NvdLookupCache.lookup_type == lookup_type,
                NvdLookupCache.identifier_hash == self.identifier_hash(identifier),
            )
        ).scalar_one_or_none()
        return row if row is not None and self.is_cache_valid(row) else None

    def is_cache_valid(self, cache_row: NvdLookupCache) -> bool:
        try:
            expires = datetime.fromisoformat(cache_row.expires_at)
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=UTC)
            return expires > _now()
        except (TypeError, ValueError):
            return False

    def _save(
        self,
        identifier: str,
        lookup_type: str,
        status: str,
        ttl: timedelta,
        *,
        response_json: Any = None,
        http_status: int | None = None,
        error_message: str | None = None,
    ) -> NvdLookupCache:
        now = _now()
        digest = self.identifier_hash(identifier)
        row = self.db.execute(
            select(NvdLookupCache).where(
                NvdLookupCache.lookup_type == lookup_type,
                NvdLookupCache.identifier_hash == digest,
            )
        ).scalar_one_or_none()
        if row is None:
            row = NvdLookupCache(
                lookup_type=lookup_type,
                identifier=identifier,
                identifier_hash=digest,
                created_at=_iso(now),
            )
        row.status = status
        row.response_json = response_json
        row.http_status = http_status
        row.error_message = (error_message or "")[:2000] or None
        row.checked_at = _iso(now)
        row.expires_at = _iso(now + ttl)
        row.updated_at = _iso(now)
        self.db.add(row)
        self.db.flush()
        return row

    def save_success(self, identifier: str, lookup_type: str, response_json: Any) -> NvdLookupCache:
        return self._save(
            identifier,
            lookup_type,
            "success",
            timedelta(hours=self.settings.nvd_success_cache_ttl_hours),
            response_json=response_json,
        )

    def save_no_result(self, identifier: str, lookup_type: str) -> NvdLookupCache:
        return self._save(
            identifier,
            lookup_type,
            "no_result",
            timedelta(hours=self.settings.nvd_no_result_cache_ttl_hours),
            response_json=None,
        )

    def save_failure(
        self,
        identifier: str,
        lookup_type: str,
        status: str,
        http_status: int | None,
        error_message: str,
    ) -> NvdLookupCache:
        return self._save(
            identifier,
            lookup_type,
            status,
            timedelta(minutes=self.settings.nvd_failure_cache_ttl_minutes),
            http_status=http_status,
            error_message=error_message,
        )

    def expire_old_cache(self) -> int:
        result = self.db.execute(delete(NvdLookupCache).where(NvdLookupCache.expires_at <= _iso(_now())))
        return int(result.rowcount or 0)
