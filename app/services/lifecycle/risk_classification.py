"""Map lifecycle results to risk levels for dashboards and reports."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from ...settings import get_settings
from .types import DEPRECATED, EOF, EOL, EOL_SOON, EOS, HIGH, LOW, POSSIBLY_UNMAINTAINED, UNKNOWN, UNSUPPORTED

RISK_CRITICAL = "CRITICAL"
RISK_HIGH = "HIGH"
RISK_MEDIUM = "MEDIUM"
RISK_INFO = "INFO"
RISK_UNKNOWN = "UNKNOWN"


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


def classify_lifecycle_risk(
    *,
    lifecycle_status: str | None,
    eol_date: str | None = None,
    eos_date: str | None = None,
    deprecated: bool = False,
    unsupported: bool = False,
    maintenance_status: str | None = None,
    confidence: str | None = None,
    today: date | None = None,
) -> str:
    """Classify lifecycle posture into a risk bucket."""
    settings = get_settings()
    eol_soon_days = int(getattr(settings, "lifecycle_eol_soon_days", 90))
    eos_soon_days = int(getattr(settings, "lifecycle_eos_soon_days", 90))
    current = today or datetime.now(UTC).date()
    status = lifecycle_status or UNKNOWN

    if confidence in {LOW, UNKNOWN, None} and status in {EOL, EOS, EOF, UNSUPPORTED}:
        return RISK_MEDIUM

    eol = _parse_date(eol_date)
    eos = _parse_date(eos_date)

    if eol and eol < current:
        return RISK_CRITICAL if confidence == HIGH else RISK_HIGH
    if eos and eos < current:
        return RISK_HIGH
    if status in {EOL, UNSUPPORTED} or unsupported:
        return RISK_HIGH if confidence == HIGH else RISK_MEDIUM
    if status == EOS:
        return RISK_HIGH
    if status == EOF:
        return RISK_HIGH
    if eol and current <= eol <= current + timedelta(days=eol_soon_days):
        return RISK_MEDIUM if confidence == HIGH else RISK_INFO
    if eos and current <= eos <= current + timedelta(days=eos_soon_days):
        return RISK_MEDIUM
    if status == EOL_SOON:
        return RISK_MEDIUM
    if status == DEPRECATED or deprecated:
        return RISK_MEDIUM
    if status == POSSIBLY_UNMAINTAINED or maintenance_status == POSSIBLY_UNMAINTAINED:
        return RISK_MEDIUM
    if status == UNKNOWN:
        return RISK_UNKNOWN
    return RISK_INFO


__all__ = [
    "RISK_CRITICAL",
    "RISK_HIGH",
    "RISK_INFO",
    "RISK_MEDIUM",
    "RISK_UNKNOWN",
    "classify_lifecycle_risk",
]
