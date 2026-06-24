"""Xeol-style local database/JSON lifecycle provider (no per-request CLI)."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

from .provider_base import LifecycleProvider
from .provider_chain import PRIORITY_XEOL
from .types import (
    DEPRECATED,
    EOL,
    EOL_SOON,
    HIGH,
    MEDIUM,
    SUPPORTED,
    UNSUPPORTED,
    LifecycleResult,
    NormalizedComponent,
    unknown_result,
)

EOL_SOON_DAYS = 90


class XeolDbProvider(LifecycleProvider):
    """Match components against a pre-synced Xeol-compatible JSON export."""

    name = "Xeol DB"
    priority = PRIORITY_XEOL

    def __init__(self, *, db_path: str | None = None, today: date | None = None) -> None:
        self.db_path = db_path
        self.today = today

    def supports(self, component: NormalizedComponent) -> bool:
        return bool(self.db_path and Path(self.db_path).is_file())

    def lookup(self, component: NormalizedComponent) -> LifecycleResult:
        records = _load_xeol_db(self.db_path)
        if not records:
            return unknown_result(component, self.name)
        record = _match_record(records, component)
        if record is None:
            return unknown_result(component, self.name)
        return _result_from_record(record, component, today=self.today, source_name=self.name)


@lru_cache(maxsize=4)
def _load_xeol_db(db_path: str | None) -> list[dict[str, Any]]:
    if not db_path:
        return []
    path = Path(db_path)
    if not path.is_file():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        for key in ("components", "records", "entities", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return [row for row in value if isinstance(row, dict)]
    return []


def clear_xeol_db_cache() -> None:
    _load_xeol_db.cache_clear()


def _match_record(records: list[dict[str, Any]], component: NormalizedComponent) -> dict[str, Any] | None:
    name = (component.normalized_name or component.name).casefold()
    version = (component.normalized_version or "").casefold().lstrip("v")
    ecosystem = (component.ecosystem or "generic").casefold()
    matches: list[tuple[int, dict[str, Any]]] = []
    for record in records:
        record_name = str(record.get("name") or record.get("component") or "").casefold()
        if name != record_name:
            continue
        record_eco = str(record.get("ecosystem") or "generic").casefold()
        if record_eco not in {"", "generic", ecosystem}:
            continue
        record_version = str(record.get("version") or "").casefold().lstrip("v")
        if record_version and version != record_version and not version.startswith(f"{record_version}."):
            continue
        matches.append((len(record_version), record))
    return max(matches, key=lambda item: item[0])[1] if matches else None


def _result_from_record(
    record: dict[str, Any],
    component: NormalizedComponent,
    *,
    today: date | None,
    source_name: str,
) -> LifecycleResult:
    current = today or datetime.now(UTC).date()
    eol_date = _iso_date(record.get("eol_date") or record.get("eol"))
    reason = str(record.get("eol_reason") or "").strip().lower()
    status = SUPPORTED
    if reason == "registry_deprecated":
        status = DEPRECATED
    elif record.get("eol") is True or (eol_date and _parse_date(eol_date) and _parse_date(eol_date) < current):
        status = EOL
    elif eol_date and _parse_date(eol_date) and current <= _parse_date(eol_date) <= current + timedelta(days=EOL_SOON_DAYS):
        status = EOL_SOON
    elif reason == "source_archived":
        status = UNSUPPORTED
    evidence_url = str(record.get("source_url") or record.get("evidence_url") or "https://www.xeol.io/")
    return LifecycleResult(
        component_name=component.normalized_name,
        component_version=component.normalized_version,
        ecosystem=component.ecosystem,
        purl=component.purl,
        cpe=component.cpe,
        lifecycle_status=status,
        eol_date=eol_date,
        deprecated=status == DEPRECATED,
        unsupported=status in {EOL, UNSUPPORTED},
        source_name=source_name,
        source_url=evidence_url,
        evidence={"provider": "xeol_db", "record": record},
        confidence=HIGH if reason == "vendor_announced" else MEDIUM,
    ).canonicalized()


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return date.fromisoformat(str(value)[:10])
        except ValueError:
            return None


def _iso_date(value: Any) -> str | None:
    parsed = _parse_date(str(value) if value is not None else None)
    return parsed.isoformat() if parsed else None


__all__ = ["XeolDbProvider", "clear_xeol_db_cache"]
