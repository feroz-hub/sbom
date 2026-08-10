"""Authoritative lifecycle records transcribed from official vendor pages."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime, timedelta
from typing import Any

from .provider_base import LifecycleProvider
from .provider_chain import PRIORITY_VENDOR
from .types import (
    EOF,
    EOL,
    EOL_SOON,
    EOS,
    HIGH,
    SUPPORTED,
    UNKNOWN,
    LifecycleResult,
    NormalizedComponent,
    canonical_status,
    unknown_result,
)

EOL_SOON_DAYS = 180


class VendorLifecycleProvider(LifecycleProvider):
    """Match curated lifecycle records that cite an official vendor URL."""

    name = "Vendor Lifecycle"
    priority = PRIORITY_VENDOR

    def supports(self, component: NormalizedComponent) -> bool:
        return _match_record(self.records, component) is not None

    def __init__(self, records: list[dict[str, Any]] | None = None, *, today: date | None = None) -> None:
        self.records = [record for record in (records or []) if isinstance(record, dict)]
        self.today = today

    @classmethod
    def from_json(cls, value: str | None) -> VendorLifecycleProvider:
        if not value:
            return cls([])
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            parsed = []
        return cls(parsed if isinstance(parsed, list) else [])

    def lookup(self, component: NormalizedComponent) -> LifecycleResult:
        record = _match_record(self.records, component)
        if record is None or not record.get("source_url"):
            return unknown_result(component, self.name)

        eol_date = _date(record.get("eol_date") or record.get("end_of_life"))
        eos_date = _date(record.get("eos_date") or record.get("end_of_support"))
        eof_date = _date(record.get("eof_date") or record.get("end_of_security_support"))
        declared_status = record.get("lifecycle_status") or record.get("status")
        status = (
            canonical_status(str(declared_status))
            if declared_status
            else _status(
                eol_date,
                eos_date,
                eof_date,
                today=self.today,
            )
        )
        latest = _text(record.get("latest_supported_version") or record.get("latest_version"))
        recommendation = _text(record.get("recommendation"))
        if not recommendation and status in {EOL, EOS, EOF, EOL_SOON}:
            recommendation = (
                f"Upgrade to vendor-supported version {latest}."
                if latest
                else "Follow the vendor lifecycle notice and migrate to a supported release."
            )

        return LifecycleResult(
            component_name=component.normalized_name,
            component_version=component.normalized_version,
            ecosystem=component.ecosystem,
            purl=component.purl,
            cpe=component.cpe,
            supplier=component.supplier,
            lifecycle_status=status,
            eos_date=eos_date.isoformat() if eos_date else None,
            eol_date=eol_date.isoformat() if eol_date else None,
            eof_date=eof_date.isoformat() if eof_date else None,
            unsupported=status in {EOL, EOS, EOF},
            maintenance_status=_text(record.get("maintenance_status")) or status,
            latest_version=_text(record.get("latest_version")) or latest,
            latest_supported_version=latest,
            recommended_version=_text(record.get("recommended_version")) or latest,
            recommendation=recommendation,
            source_name=_text(record.get("source_name")) or self.name,
            source_url=str(record["source_url"]),
            confidence=HIGH,
            evidence={"authority": "vendor", "record": record},
        ).canonicalized()


def _match_record(records: list[dict[str, Any]], component: NormalizedComponent) -> dict[str, Any] | None:
    name = component.normalized_name.casefold()
    ecosystem = (component.ecosystem or "generic").casefold()
    version = (component.normalized_version or "").casefold().lstrip("v")
    matches: list[tuple[int, dict[str, Any]]] = []
    for record in records:
        record_name = str(record.get("name") or record.get("product_name") or "").strip().casefold()
        aliases = {str(alias).strip().casefold() for alias in record.get("aliases", []) if str(alias).strip()}
        if name != record_name and name not in aliases:
            continue
        record_ecosystem = str(record.get("ecosystem") or "generic").strip().casefold()
        if record_ecosystem not in {"", "generic", ecosystem}:
            continue
        record_version = (
            str(record.get("version") or record.get("version_prefix") or record.get("cycle") or "")
            .strip()
            .casefold()
            .lstrip("v")
        )
        if record_version and version != record_version and not version.startswith(f"{record_version}."):
            continue
        matches.append((len(record_version), record))
    return max(matches, key=lambda item: item[0])[1] if matches else None


def _status(
    eol_date: date | None,
    eos_date: date | None,
    eof_date: date | None,
    *,
    today: date | None,
) -> str:
    current = today or datetime.now(UTC).date()
    if eol_date and eol_date < current:
        return EOL
    if eos_date and eos_date < current:
        return EOS
    if eof_date and eof_date < current:
        return EOF
    if eol_date and eol_date <= current + timedelta(days=EOL_SOON_DAYS):
        return EOL_SOON
    if eol_date or eos_date or eof_date:
        return SUPPORTED
    return UNKNOWN


def _date(value: Any) -> date | None:
    if not value or str(value).strip().lower() == "tba":
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return date.fromisoformat(str(value)[:10])
        except ValueError:
            return None


def _text(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


__all__ = ["VendorLifecycleProvider"]
