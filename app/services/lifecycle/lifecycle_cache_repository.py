"""Idempotent persistence for ``ComponentLifecycleCache`` rows."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, tuple_
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from ...models import ComponentLifecycleCache
from ...settings import get_settings
from .normalizer import build_lifecycle_lookup_key
from .types import DEPRECATED, UNKNOWN, LifecycleResult, NormalizedComponent, now_iso

LIFECYCLE_CACHE_IDENTITY_CONSTRAINT = "uq_component_lifecycle_cache_identity"

IDENTITY_COLUMNS = (
    "normalized_name",
    "normalized_version",
    "ecosystem",
    "purl",
)

UPDATABLE_COLUMNS = (
    "lookup_key",
    "cpe",
    "lifecycle_status",
    "eos_date",
    "eol_date",
    "eof_date",
    "deprecated",
    "unsupported",
    "maintenance_status",
    "latest_version",
    "latest_supported_version",
    "recommended_version",
    "recommendation",
    "source_name",
    "source_url",
    "evidence_json",
    "confidence",
    "checked_at",
    "expires_at",
    "is_stale",
)


def lifecycle_cache_identity_key(
    normalized_name: str,
    normalized_version: str | None,
    ecosystem: str | None,
    purl: str | None,
) -> tuple[str, str | None, str, str | None]:
    """Build the cache identity tuple matching the DB unique constraint."""
    return (
        (normalized_name or "").strip().lower(),
        normalized_version,
        ecosystem or "generic",
        purl,
    )


def _cache_ttl_for_result(result: LifecycleResult) -> timedelta:
    settings = get_settings()
    evidence = result.evidence if isinstance(result.evidence, dict) else {}
    if evidence.get("provider_failure") or evidence.get("provider_error") or evidence.get("provider_errors"):
        minutes = int(getattr(settings, "lifecycle_cache_ttl_provider_failure_minutes", 30))
        return timedelta(minutes=minutes)
    if result.lifecycle_status == UNKNOWN:
        hours = int(getattr(settings, "lifecycle_cache_ttl_unknown_hours", 24))
        return timedelta(hours=hours)
    if result.lifecycle_status == DEPRECATED or result.deprecated:
        days = int(getattr(settings, "lifecycle_cache_ttl_deprecated_days", 7))
        return timedelta(days=days)
    if result.eol_date or result.eos_date or result.eof_date or result.lifecycle_status not in {UNKNOWN}:
        days = int(getattr(settings, "lifecycle_cache_ttl_known_days", 14))
        return timedelta(days=days)
    hours = int(getattr(settings, "lifecycle_cache_ttl_unknown_hours", 24))
    return timedelta(hours=hours)


def lifecycle_cache_row_from_result(
    component: NormalizedComponent,
    result: LifecycleResult,
    *,
    cache_ttl_days: int | None = None,
) -> dict[str, Any]:
    """Serialize a provider result into a cache row payload."""
    name, version, ecosystem, purl, cpe = component.cache_identity
    ttl = _cache_ttl_for_result(result)
    if cache_ttl_days is not None and result.lifecycle_status != UNKNOWN:
        ttl = timedelta(days=cache_ttl_days)
    expires_at = (datetime.now(UTC).replace(microsecond=0) + ttl).isoformat()
    return {
        "lookup_key": build_lifecycle_lookup_key(component),
        "normalized_name": name,
        "normalized_version": version,
        "ecosystem": ecosystem,
        "purl": purl,
        "cpe": cpe,
        "lifecycle_status": result.lifecycle_status,
        "eos_date": result.eos_date,
        "eol_date": result.eol_date,
        "eof_date": result.eof_date,
        "deprecated": bool(result.deprecated),
        "unsupported": bool(result.unsupported),
        "maintenance_status": result.maintenance_status,
        "latest_version": result.latest_version,
        "latest_supported_version": result.latest_supported_version,
        "recommended_version": result.recommended_version,
        "recommendation": result.recommendation,
        "source_name": result.source_name,
        "source_url": result.source_url,
        "evidence_json": result.evidence,
        "confidence": result.confidence,
        "checked_at": result.checked_at or now_iso(),
        "expires_at": expires_at,
        "is_stale": False,
    }


def _dedupe_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep the last payload per identity key so one batch writes once per key."""
    deduped: dict[tuple[str, str | None, str, str | None], dict[str, Any]] = {}
    for row in rows:
        key = lifecycle_cache_identity_key(
            row["normalized_name"],
            row.get("normalized_version"),
            row.get("ecosystem"),
            row.get("purl"),
        )
        deduped[key] = row
    return list(deduped.values())


def _upsert_with_on_conflict(db: Session, rows: list[dict[str, Any]], *, dialect: str) -> None:
    table = ComponentLifecycleCache.__table__
    if dialect == "postgresql":
        insert_fn = pg_insert
    elif dialect == "sqlite":
        insert_fn = sqlite_insert
    else:
        raise NotImplementedError(f"lifecycle cache upsert only supports postgresql/sqlite; got {dialect!r}")

    stmt = insert_fn(table).values(rows)
    excluded = stmt.excluded
    update_columns = {column: getattr(excluded, column) for column in UPDATABLE_COLUMNS}
    if dialect == "postgresql":
        stmt = stmt.on_conflict_do_update(
            constraint=LIFECYCLE_CACHE_IDENTITY_CONSTRAINT,
            set_=update_columns,
        )
    else:
        stmt = stmt.on_conflict_do_update(
            index_elements=[
                table.c.normalized_name,
                table.c.normalized_version,
                table.c.ecosystem,
                table.c.purl,
            ],
            set_=update_columns,
        )
    db.execute(stmt)


def _upsert_with_select_merge(db: Session, rows: list[dict[str, Any]]) -> None:
    """Fallback for dialects without INSERT ON CONFLICT support."""
    identity_keys = [
        lifecycle_cache_identity_key(
            row["normalized_name"],
            row.get("normalized_version"),
            row.get("ecosystem"),
            row.get("purl"),
        )
        for row in rows
    ]
    existing_rows = (
        db.execute(
            select(ComponentLifecycleCache).where(
                tuple_(
                    ComponentLifecycleCache.normalized_name,
                    ComponentLifecycleCache.normalized_version,
                    ComponentLifecycleCache.ecosystem,
                    ComponentLifecycleCache.purl,
                ).in_(identity_keys)
            )
        )
        .scalars()
        .all()
    )
    existing_by_key = {
        lifecycle_cache_identity_key(
            row.normalized_name,
            row.normalized_version,
            row.ecosystem,
            row.purl,
        ): row
        for row in existing_rows
    }
    for row in rows:
        key = lifecycle_cache_identity_key(
            row["normalized_name"],
            row.get("normalized_version"),
            row.get("ecosystem"),
            row.get("purl"),
        )
        cache_entry = existing_by_key.get(key)
        if cache_entry is None:
            cache_entry = ComponentLifecycleCache(
                normalized_name=row["normalized_name"],
                normalized_version=row.get("normalized_version"),
                ecosystem=row.get("ecosystem"),
                purl=row.get("purl"),
            )
            db.add(cache_entry)
            existing_by_key[key] = cache_entry
        for column in UPDATABLE_COLUMNS:
            setattr(cache_entry, column, row.get(column))


def upsert_lifecycle_cache_entries(db: Session, entries: list[dict[str, Any]]) -> None:
    """Insert or update lifecycle cache rows keyed by normalized identity."""
    if not entries:
        return

    rows = _dedupe_rows(entries)
    dialect = db.get_bind().dialect.name
    if dialect in {"postgresql", "sqlite"}:
        _upsert_with_on_conflict(db, rows, dialect=dialect)
    else:
        _upsert_with_select_merge(db, rows)
    db.flush()


__all__ = [
    "IDENTITY_COLUMNS",
    "LIFECYCLE_CACHE_IDENTITY_CONSTRAINT",
    "lifecycle_cache_identity_key",
    "lifecycle_cache_row_from_result",
    "upsert_lifecycle_cache_entries",
]
