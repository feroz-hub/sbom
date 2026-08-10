"""OpenEoX-compatible lifecycle feed provider."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from .provider_base import LifecycleProvider
from .provider_chain import PRIORITY_OPENEOX
from .types import (
    DEPRECATED,
    EOF,
    EOL,
    EOL_SOON,
    EOS,
    HIGH,
    MEDIUM,
    SUPPORTED,
    UNKNOWN,
    UNSUPPORTED,
    LifecycleResult,
    NormalizedComponent,
    canonical_status,
    unknown_result,
)

OPENEOX_STATUS_MAP = {
    "eol": EOL,
    "end_of_life": EOL,
    "eos": EOS,
    "end_of_support": EOS,
    "end_of_service": EOS,
    "eof": EOF,
    "end_of_feature": EOF,
    "end_of_fix": EOF,
    "deprecated": DEPRECATED,
    "unsupported": UNSUPPORTED,
    "maintenance": "Maintenance",
    "extended_support": "Extended Support",
    "possibly_unmaintained": "Possibly Unmaintained",
    "unknown": UNKNOWN,
    "supported": SUPPORTED,
    "active": SUPPORTED,
}

EOL_SOON_DAYS = 90


class OpenEoXProvider(LifecycleProvider):
    """Ingest lifecycle evidence from configured OpenEoX-compatible JSON feeds."""

    name = "OpenEoX"
    priority = PRIORITY_OPENEOX

    def __init__(
        self,
        *,
        feed_urls: list[str] | None = None,
        local_paths: list[str] | None = None,
        timeout_seconds: float = 10.0,
        today: date | None = None,
    ) -> None:
        self.feed_urls = [url.strip() for url in (feed_urls or []) if url.strip()]
        self.local_paths = [path.strip() for path in (local_paths or []) if path.strip()]
        self.timeout_seconds = timeout_seconds
        self.today = today
        self._records = _load_openeox_records(self.feed_urls, self.local_paths, timeout_seconds)

    def supports(self, component: NormalizedComponent) -> bool:
        return bool(self._records)

    def lookup(self, component: NormalizedComponent) -> LifecycleResult:
        if not self._records:
            return unknown_result(component, self.name)
        record = _match_openeox_record(self._records, component)
        if record is None:
            return unknown_result(component, self.name)
        return _result_from_openeox_record(record, component, today=self.today, source_name=self.name)


def _load_openeox_records(
    feed_urls: list[str],
    local_paths: list[str],
    timeout_seconds: float,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in local_paths:
        records.extend(_parse_openeox_payload(_read_local_json(path)))
    for url in feed_urls:
        records.extend(_parse_openeox_payload(_fetch_json(url, timeout_seconds)))
    return records


def _read_local_json(path: str) -> Any:
    file_path = Path(path)
    if not file_path.is_file():
        return None
    try:
        return json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _fetch_json(url: str, timeout_seconds: float) -> Any:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https", "file"}:
        return None
    if parsed.scheme == "file":
        return _read_local_json(parsed.path)
    try:
        with httpx.Client(timeout=timeout_seconds, follow_redirects=True) as client:
            response = client.get(url)
            response.raise_for_status()
            return response.json()
    except (httpx.HTTPError, ValueError, TypeError):
        return None


def _parse_openeox_payload(payload: Any) -> list[dict[str, Any]]:
    if payload is None:
        return []
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("components", "products", "entries", "lifecycle"):
        value = payload.get(key)
        if isinstance(value, list):
            return [row for row in value if isinstance(row, dict)]
    return [payload]


def _match_openeox_record(records: list[dict[str, Any]], component: NormalizedComponent) -> dict[str, Any] | None:
    name = (component.normalized_name or component.name).casefold()
    version = (component.normalized_version or "").casefold().lstrip("v")
    ecosystem = (component.ecosystem or "generic").casefold()
    matches: list[tuple[int, dict[str, Any]]] = []
    for record in records:
        record_name = str(record.get("name") or record.get("product") or record.get("component") or "").casefold()
        aliases = {str(alias).casefold() for alias in record.get("aliases", []) if str(alias).strip()}
        if name != record_name and name not in aliases:
            continue
        record_eco = str(record.get("ecosystem") or record.get("type") or "generic").casefold()
        if record_eco not in {"", "generic", ecosystem}:
            continue
        record_version = (
            str(record.get("version") or record.get("version_prefix") or record.get("cycle") or "")
            .casefold()
            .lstrip("v")
        )
        if record_version and version != record_version and not version.startswith(f"{record_version}."):
            continue
        matches.append((len(record_version), record))
    return max(matches, key=lambda item: item[0])[1] if matches else None


def _result_from_openeox_record(
    record: dict[str, Any],
    component: NormalizedComponent,
    *,
    today: date | None,
    source_name: str,
) -> LifecycleResult:
    current = today or datetime.now(UTC).date()
    raw_status = record.get("lifecycle_status") or record.get("status") or record.get("phase")
    status = OPENEOX_STATUS_MAP.get(str(raw_status or "").strip().lower(), canonical_status(str(raw_status)))
    eol_date = _iso_date(record.get("eol_date") or record.get("end_of_life") or record.get("eol"))
    eos_date = _iso_date(record.get("eos_date") or record.get("end_of_support") or record.get("eos"))
    eof_date = _iso_date(record.get("eof_date") or record.get("end_of_feature") or record.get("eof"))
    if status == SUPPORTED:
        status = _status_from_dates(eol_date, eos_date, eof_date, current)
    evidence_url = str(record.get("source_url") or record.get("evidence_url") or record.get("url") or "")
    return LifecycleResult(
        component_name=component.normalized_name,
        component_version=component.normalized_version,
        ecosystem=component.ecosystem,
        purl=component.purl,
        cpe=component.cpe,
        lifecycle_status=status,
        eos_date=eos_date,
        eol_date=eol_date,
        eof_date=eof_date,
        deprecated=status == DEPRECATED,
        unsupported=status in {EOL, EOS, EOF, UNSUPPORTED},
        maintenance_status=str(record.get("maintenance_status") or status),
        latest_version=_text(record.get("latest_version")),
        latest_supported_version=_text(record.get("latest_supported_version") or record.get("latest_version")),
        recommended_version=_text(record.get("recommended_version")),
        recommendation=_text(record.get("recommendation")),
        source_name=source_name,
        source_url=evidence_url or None,
        evidence={"authority": "openeox", "record": record},
        confidence=HIGH if evidence_url else MEDIUM,
    ).canonicalized()


def _status_from_dates(
    eol_date: str | None,
    eos_date: str | None,
    eof_date: str | None,
    current: date,
) -> str:
    eol = _parse_date(eol_date)
    eos = _parse_date(eos_date)
    eof = _parse_date(eof_date)
    if eol and eol < current:
        return EOL
    if eos and eos < current:
        return EOS
    if eof and eof < current:
        return EOF
    if eol and current <= eol <= current + timedelta(days=EOL_SOON_DAYS):
        return EOL_SOON
    if eol or eos or eof:
        return SUPPORTED
    return UNKNOWN


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
    if not value:
        return None
    parsed = _parse_date(str(value))
    return parsed.isoformat() if parsed else None


def _text(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


__all__ = ["OpenEoXProvider"]
