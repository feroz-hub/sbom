"""Cache key, TTL policy, and read/write helpers for ``ai_fix_cache``.

Phase 2 hard rules (see prompt §2.4):

  * Cache key = ``sha256(vuln_id|component_name|component_version|prompt_version)``.
  * Tenant-shared by design — no scan_id / org_id in the key.
  * TTL: 7d for KEV-listed CVEs, 30d for everything else, 1h for negatives.
  * Schema-version mismatch on read = stale; the orchestrator regenerates.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AiFixCache
from .prompts import PROMPT_VERSION
from .schemas import (
    SCHEMA_VERSION,
    AiFixBundle,
    AiFixMetadata,
    AiFixResult,
)

log = logging.getLogger("sbom.ai.cache")

#: Stable lower-cased separators so different inputs can't collide via
#: case differences (e.g. "Log4j-Core" vs "log4j-core").
_KEY_SEPARATOR = "|"

# TTLs.
_TTL_KEV = timedelta(days=7)
_TTL_DEFAULT = timedelta(days=30)
_TTL_NEGATIVE = timedelta(hours=1)


# ---------------------------------------------------------------------------
# Key + TTL
# ---------------------------------------------------------------------------


def make_cache_key(
    *,
    vuln_id: str,
    component_name: str,
    component_version: str,
    prompt_version: str = PROMPT_VERSION,
) -> str:
    """Compute the canonical cache key.

    Inputs are normalised (strip + lower) BEFORE hashing so trivial
    casing / whitespace differences hit the same row.
    """
    payload = _KEY_SEPARATOR.join(
        [
            (vuln_id or "").strip().lower(),
            (component_name or "").strip().lower(),
            (component_version or "").strip().lower(),
            (prompt_version or "").strip().lower(),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compute_ttl(*, kev_listed: bool, is_negative: bool = False) -> timedelta:
    """Return the TTL appropriate for the given finding."""
    if is_negative:
        return _TTL_NEGATIVE
    return _TTL_KEV if kev_listed else _TTL_DEFAULT


def expires_at_iso(*, ttl: timedelta, now: datetime | None = None) -> str:
    when = now or datetime.now(UTC)
    return (when + ttl).isoformat()


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------


def read_cache(
    db: Session,
    *,
    cache_key: str,
) -> AiFixResult | None:
    """Return the cached :class:`AiFixResult` or ``None`` for miss / expired / stale.

    Stale = schema_version mismatch with :data:`SCHEMA_VERSION` (we bumped
    the bundle shape); these are treated as misses without deleting the row,
    so a roll-back to the old schema doesn't lose the cache.
    """
    row = db.execute(select(AiFixCache).where(AiFixCache.cache_key == cache_key)).scalar_one_or_none()
    if row is None:
        return None

    if int(row.schema_version or 0) != SCHEMA_VERSION:
        log.debug("ai.cache.miss.stale_schema: key=%s row_schema=%s want=%s", cache_key, row.schema_version, SCHEMA_VERSION)
        return None

    try:
        expires = datetime.fromisoformat(row.expires_at)
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
    except ValueError:
        log.warning("ai.cache.bad_expires_at: key=%s value=%r", cache_key, row.expires_at)
        return None

    now = datetime.now(UTC)
    if expires <= now:
        return None

    try:
        bundle = AiFixBundle.model_validate(
            {
                "remediation_prose": _coerce(row.remediation_prose),
                "upgrade_command": _coerce(row.upgrade_command),
                "decision_recommendation": _coerce(row.decision_recommendation),
            }
        )
    except Exception as exc:  # noqa: BLE001 — corrupt cache row should not 500 the request
        log.warning("ai.cache.corrupt_row: key=%s err=%s", cache_key, exc)
        return None

    age_seconds = max(int((now - _parse_iso(row.generated_at)).total_seconds()), 0)
    metadata = AiFixMetadata(
        cache_key=cache_key,
        cache_hit=True,
        provider_used=row.provider_used or "unknown",
        model_used=row.model_used or "unknown",
        prompt_version=row.prompt_version or PROMPT_VERSION,
        schema_version=int(row.schema_version or SCHEMA_VERSION),
        total_cost_usd=float(row.total_cost_usd or 0.0),
        generated_at=row.generated_at,
        expires_at=row.expires_at,
        age_seconds=age_seconds,
    )
    return AiFixResult(
        finding_id=None,
        vuln_id=row.vuln_id,
        component_name=row.component_name,
        component_version=row.component_version,
        bundle=bundle,
        metadata=metadata,
    )


def _coerce(value: Any) -> dict[str, Any]:
    """JSON columns come back as ``dict`` on Postgres and ``str`` on SQLite."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            obj = json.loads(value)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
    raise ValueError(f"unexpected JSON column shape: {type(value).__name__}")


def _parse_iso(s: str | None) -> datetime:
    if not s:
        return datetime.now(UTC)
    try:
        d = datetime.fromisoformat(s)
        if d.tzinfo is None:
            d = d.replace(tzinfo=UTC)
        return d
    except ValueError:
        return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Write
# ---------------------------------------------------------------------------


def write_cache(
    db: Session,
    *,
    cache_key: str,
    vuln_id: str,
    component_name: str,
    component_version: str,
    bundle: AiFixBundle,
    provider_used: str,
    model_used: str,
    total_cost_usd: float,
    kev_listed: bool,
    prompt_version: str = PROMPT_VERSION,
) -> AiFixResult:
    """Upsert the cache row + return the same shape :func:`read_cache` does.

    Errors are logged, not raised — losing a cache write after a successful
    LLM call is preferable to surfacing the failure to the user.
    """
    ttl = compute_ttl(kev_listed=kev_listed)
    generated = now_iso()
    expires = expires_at_iso(ttl=ttl)

    metadata = AiFixMetadata(
        cache_key=cache_key,
        cache_hit=False,
        provider_used=provider_used,
        model_used=model_used,
        prompt_version=prompt_version,
        schema_version=SCHEMA_VERSION,
        total_cost_usd=float(total_cost_usd),
        generated_at=generated,
        expires_at=expires,
        age_seconds=0,
    )

    payload = {
        "remediation_prose": bundle.remediation_prose.model_dump(mode="json"),
        "upgrade_command": bundle.upgrade_command.model_dump(mode="json"),
        "decision_recommendation": bundle.decision_recommendation.model_dump(mode="json"),
    }

    try:
        existing = db.execute(
            select(AiFixCache).where(AiFixCache.cache_key == cache_key)
        ).scalar_one_or_none()
        if existing is None:
            db.add(
                AiFixCache(
                    cache_key=cache_key,
                    vuln_id=vuln_id,
                    component_name=component_name,
                    component_version=component_version,
                    prompt_version=prompt_version,
                    schema_version=SCHEMA_VERSION,
                    remediation_prose=payload["remediation_prose"],
                    upgrade_command=payload["upgrade_command"],
                    decision_recommendation=payload["decision_recommendation"],
                    provider_used=provider_used,
                    model_used=model_used,
                    total_cost_usd=float(total_cost_usd),
                    generated_at=generated,
                    expires_at=expires,
                    last_accessed_at=generated,
                )
            )
        else:
            existing.vuln_id = vuln_id
            existing.component_name = component_name
            existing.component_version = component_version
            existing.prompt_version = prompt_version
            existing.schema_version = SCHEMA_VERSION
            existing.remediation_prose = payload["remediation_prose"]
            existing.upgrade_command = payload["upgrade_command"]
            existing.decision_recommendation = payload["decision_recommendation"]
            existing.provider_used = provider_used
            existing.model_used = model_used
            existing.total_cost_usd = float(total_cost_usd)
            existing.generated_at = generated
            existing.expires_at = expires
            existing.last_accessed_at = generated
        db.commit()
    except Exception as exc:  # noqa: BLE001
        log.warning("ai.cache.write_failed: key=%s err=%s", cache_key, exc)
        try:
            db.rollback()
        except Exception:
            pass

    return AiFixResult(
        finding_id=None,
        vuln_id=vuln_id,
        component_name=component_name,
        component_version=component_version,
        bundle=bundle,
        metadata=metadata,
    )


def touch_last_accessed(db: Session, *, cache_key: str) -> None:
    """Bump ``last_accessed_at`` on a hit (best effort).

    Used by analytics ("which fixes are most-read?") and future LRU eviction.
    """
    try:
        row = db.execute(select(AiFixCache).where(AiFixCache.cache_key == cache_key)).scalar_one_or_none()
        if row is not None:
            row.last_accessed_at = now_iso()
            db.commit()
    except Exception as exc:
        log.debug("ai.cache.touch_failed: key=%s err=%s", cache_key, exc)
        try:
            db.rollback()
        except Exception:
            pass
