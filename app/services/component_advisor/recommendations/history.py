"""Vulnerability history over an observation window (FR-SCA-016, US-SCA-11).

Pure logic. Two evidence sources, each with explicit coverage:

* ``TENANT_ANALYSIS`` — findings recorded for the version by this tenant's
  analysis runs of eligible SBOMs inside the window (dates = disclosure
  ``published_on`` when present, plus first/last observation).
* ``NVD_MIRROR`` — CVEs whose affected ranges include the version's CPE,
  when the mirror is enabled and a CPE exists.

Coverage is always reported: which sources were available, how many months
of the window they actually cover, and the gaps. Zero vulnerabilities in a
covered window is reported with an explicit note that it is not proof of
security; no coverage at all is ``NO_HISTORY_COVERAGE``, never "clean".
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

DEFAULT_WINDOW_MONTHS = 24
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
ZERO_HISTORY_NOTE = "No vulnerabilities in the covered window; this is not proof of security"


def window_start(now: datetime, months: int) -> datetime:
    return now - timedelta(days=round(months * 30.4375))


def _parse(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


@dataclass(frozen=True)
class NvdObservation:
    cve_id: str
    published: datetime
    severity: str


def build_history(
    *,
    tenant: dict[str, Any] | None,
    nvd: Sequence[NvdObservation] | None,
    nvd_status: str,
    window_months: int = DEFAULT_WINDOW_MONTHS,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Merge the sources into one history with coverage (FR-SCA-016).

    ``tenant`` is :func:`app.metrics.component_advisor.advisor_version_history`
    output or ``None`` (version not observed). ``nvd_status`` is one of
    AVAILABLE / DISABLED / NO_CPE / ERROR.
    """
    now = now or datetime.now(UTC)
    start = window_start(now, window_months)
    vulns: dict[str, dict[str, Any]] = {}

    def record(vuln_id: str, severity: str, disclosed: datetime | None, observed: datetime | None, source: str):
        entry = vulns.setdefault(vuln_id, {"severity": "UNKNOWN", "disclosed": None, "first_observed": None,
                                           "last_observed": None, "sources": set()})
        if SEVERITIES.index(severity) < SEVERITIES.index(entry["severity"]):
            entry["severity"] = severity
        if disclosed and (entry["disclosed"] is None or disclosed < entry["disclosed"]):
            entry["disclosed"] = disclosed
        if observed:
            entry["first_observed"] = min(filter(None, (entry["first_observed"], observed)))
            entry["last_observed"] = max(filter(None, (entry["last_observed"], observed)))
        entry["sources"].add(source)

    sources: list[dict[str, Any]] = []
    covered_from: list[datetime] = []
    if tenant is not None and tenant.get("runs"):
        for finding in tenant["findings"]:
            record(finding["canonical_id"], finding["severity"], _parse(finding.get("published_on")),
                   _parse(finding.get("observed_at")), "TENANT_ANALYSIS")
        earliest = _parse(tenant.get("earliest_run_at"))
        if earliest:
            covered_from.append(max(earliest, start))
        sources.append({"source": "TENANT_ANALYSIS", "status": "AVAILABLE", "runs_considered": tenant["runs"],
                        "earliest_run_at": tenant.get("earliest_run_at"), "latest_run_at": tenant.get("latest_run_at")})
    else:
        sources.append({"source": "TENANT_ANALYSIS", "status": "NO_DATA", "runs_considered": 0})

    if nvd_status == "AVAILABLE":
        for observation in nvd or ():
            if observation.published >= start:
                record(observation.cve_id, observation.severity, observation.published, None, "NVD_MIRROR")
        covered_from.append(start)  # the mirror covers the whole window it was asked for
        sources.append({"source": "NVD_MIRROR", "status": "AVAILABLE", "matches": len(nvd or ())})
    else:
        sources.append({"source": "NVD_MIRROR", "status": nvd_status})

    in_window = {k: v for k, v in vulns.items() if v["disclosed"] is None or v["disclosed"] >= start}
    distribution = {severity: 0 for severity in SEVERITIES}
    for entry in in_window.values():
        distribution[entry["severity"]] += 1
    covered_start = min(covered_from) if covered_from else None
    covered_months = round(((now - covered_start).days / 30.4375), 1) if covered_start else 0.0
    gaps = []
    if covered_start is None:
        gaps.append("NO_SOURCE_COVERS_THE_WINDOW")
    elif covered_months + 0.5 < window_months:
        gaps.append(f"COVERAGE_STARTS_{covered_start.date().isoformat()}")
    if nvd_status != "AVAILABLE":
        gaps.append(f"NVD_MIRROR_{nvd_status}")

    first = min((e["first_observed"] or e["disclosed"] for e in in_window.values() if e["first_observed"] or e["disclosed"]), default=None)
    last = max((e["last_observed"] or e["disclosed"] for e in in_window.values() if e["last_observed"] or e["disclosed"]), default=None)
    status = "NO_HISTORY_COVERAGE" if covered_start is None else ("NO_VULNERABILITIES_IN_COVERED_WINDOW" if not in_window else "AVAILABLE")
    return {
        "status": status,
        "window_months": window_months,
        "window_start": start.date().isoformat(),
        "window_end": now.date().isoformat(),
        "disclosed_vulnerability_count": len(in_window),
        "severity_distribution": distribution,
        "critical_high_count": distribution["CRITICAL"] + distribution["HIGH"],
        "first_observed": first.isoformat() if first else None,
        "last_observed": last.isoformat() if last else None,
        "exposure_days": (last - first).days if first and last else None,
        "coverage": {"covered_months": covered_months, "sources": sources, "gaps": gaps},
        "note": ZERO_HISTORY_NOTE if status == "NO_VULNERABILITIES_IN_COVERED_WINDOW" else None,
    }


def candidate_cpe(source_cpe: str | None, version: str | None) -> str | None:
    """The source's CPE 2.3 with the version slot replaced (same product only)."""
    if not source_cpe or not version:
        return None
    parts = source_cpe.split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    parts[5] = version.replace(":", "\\:")
    return ":".join(parts)


def nvd_severity(score: float | None, text: str | None) -> str:
    if text and text.upper() in SEVERITIES:
        return text.upper()
    if score is None:
        return "UNKNOWN"
    return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"


def to_observations(records: Iterable[Any]) -> list[NvdObservation]:
    out = []
    for r in records:
        published = _parse(getattr(r, "published", None))
        if published is None:
            continue
        score = getattr(r, "score_v40", None) or getattr(r, "score_v31", None) or getattr(r, "score_v2", None)
        out.append(NvdObservation(r.cve_id.upper(), published, nvd_severity(score, getattr(r, "severity_text", None))))
    return out


__all__ = ["DEFAULT_WINDOW_MONTHS", "NvdObservation", "ZERO_HISTORY_NOTE", "build_history", "candidate_cpe",
           "nvd_severity", "to_observations", "window_start"]
