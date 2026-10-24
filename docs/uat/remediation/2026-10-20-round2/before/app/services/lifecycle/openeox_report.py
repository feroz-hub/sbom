"""OpenEoX shell serialization for persisted component lifecycle data."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

OPENEOX_SHELL_SCHEMA = "https://docs.oasis-open.org/openeox/tbd/schema/shell.json"
OPENEOX_CORE_SCHEMA = "https://docs.oasis-open.org/openeox/tbd/schema/core.json"
OPENEOX_SOFTWARE_SCHEMA = "https://docs.oasis-open.org/openeox/tbd/schema/product_software.json"


def lifecycle_report_openeox(report: dict[str, Any]) -> dict[str, Any]:
    """Convert the stored lifecycle report into OpenEoX shell statements."""
    generated_at = _timestamp(report.get("generated_at"))
    statements = []
    for component in report.get("components") or []:
        if not isinstance(component, dict):
            continue
        helper: dict[str, Any] = {}
        if component.get("purl"):
            helper["purl"] = component["purl"]
        if component.get("cpe"):
            helper["cpe"] = component["cpe"]
        statements.append(
            {
                "core": {
                    "$schema": OPENEOX_CORE_SCHEMA,
                    "end_of_life": _timestamp_or_tba(component.get("eol_date") or component.get("eos_date")),
                    "end_of_security_support": _timestamp_or_tba(
                        component.get("eof_date") or component.get("eos_date") or component.get("eol_date")
                    ),
                    "last_updated": _timestamp(component.get("checked_at") or generated_at),
                },
                "product": {
                    "$schema": OPENEOX_SOFTWARE_SCHEMA,
                    "product_name": str(component.get("name") or "Unknown"),
                    "product_version": str(component.get("version") or "unknown"),
                    "vendor_name": str(component.get("supplier") or "Unknown"),
                },
                "product_identification_helper": helper,
            }
        )
    return {"$schema": OPENEOX_SHELL_SCHEMA, "statements": statements}


def _timestamp_or_tba(value: Any) -> str:
    return "tba" if value in (None, "", "tba") else _timestamp(value)


def _timestamp(value: Any) -> str:
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=UTC)
        return dt.isoformat().replace("+00:00", "Z")
    text = str(value or "").strip()
    if not text:
        return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if len(text) == 10:
        return f"{text}T00:00:00Z"
    return text.replace("+00:00", "Z")


__all__ = [
    "OPENEOX_CORE_SCHEMA",
    "OPENEOX_SHELL_SCHEMA",
    "OPENEOX_SOFTWARE_SCHEMA",
    "lifecycle_report_openeox",
]
