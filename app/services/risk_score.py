"""
Risk scoring v2 — CVSS + EPSS + KEV composite.

Replaces the bucket-and-weight heuristic that previously lived inline in
``app/routers/sbom.py``. The new formula uses each finding's actual
CVSS base score, amplifies it by the FIRST.org EPSS exploit-likelihood
score, and applies a hard multiplier when the underlying CVE is on the
CISA Known Exploited Vulnerabilities (KEV) catalog.

Per-finding score
-----------------
    finding_score = cvss * exploit_factor * kev_multiplier

    cvss               CVSS base score (0..10) from the finding;
                       falls back to a severity-mapped value when null
    exploit_factor     1 + 5 * epss   (epss in [0, 1])
                       so a CVE with EPSS=0   contributes 1x,
                          a CVE with EPSS=0.5 contributes 3.5x,
                          a CVE with EPSS=1.0 contributes 6x.
    kev_multiplier     2.0 if the CVE is on the CISA KEV list, else 1.0

Worst-case bound: 10 * 6 * 2 = 120.

Aggregation
-----------
    component_score = sum(finding_score over all findings on the component)
    total_risk_score = sum(component_score over all components)

    worst_finding   = max(finding_score across the entire SBOM)

Risk band (driven by worst-finding to be SBOM-size-invariant)
------------------------------------------------------------
    Any finding that is BOTH KEV-listed AND has CVSS >= 9.0  -> CRITICAL
    worst_finding >= 80                                       -> CRITICAL
    worst_finding >= 50                                       -> HIGH
    worst_finding >= 20                                       -> MEDIUM
    otherwise                                                 -> LOW

This is anchored to the most dangerous individual CVE in the SBOM,
not to a count-weighted aggregate, so a 1500-component SBOM doesn't
automatically land in CRITICAL purely because it has a long tail of
medium-severity dependencies.
"""

from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from typing import Iterable

from sqlalchemy.orm import Session

from ..models import AnalysisFinding
from ..sources.epss import get_epss_scores_memoized
from ..sources.kev import lookup_kev_set_memoized

log = logging.getLogger("sbom.services.risk_score")

# ---------------------------------------------------------------------
# Public methodology metadata (also surfaced on the API response so the
# UI can render a "How is this calculated?" tooltip without hard-coding
# the formula in two places).
# ---------------------------------------------------------------------
SCORER_VERSION = "2.0.0"
SCORER_NAME = "CVSS + EPSS + KEV composite"

METHODOLOGY = {
    "version": SCORER_VERSION,
    "name": SCORER_NAME,
    "formula": "finding_score = cvss * (1 + 5 * epss) * (2 if kev else 1)",
    "aggregation": "component_score = sum(finding_score); total = sum(component_score)",
    "bands": {
        "CRITICAL": "any KEV finding with CVSS>=9, or worst_finding_score>=80",
        "HIGH": "worst_finding_score>=50",
        "MEDIUM": "worst_finding_score>=20",
        "LOW": "everything else",
    },
    "sources": {
        "cvss": "stored on AnalysisFinding.score (NVD / OSV / GHSA)",
        "epss": "FIRST.org EPSS API, cached 24h",
        "kev": "CISA Known Exploited Vulnerabilities catalog, refreshed 24h",
    },
}

# CVSS fallback values when AnalysisFinding.score is NULL. Median of
# the CVSS band ranges, biased slightly toward the upper bound so we
# don't under-score findings that lack a numeric CVSS.
_SEVERITY_FALLBACK_CVSS = {
    "CRITICAL": 9.5,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.0,
    "UNKNOWN": 0.0,
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Tuning constants — kept here so they can be revised without touching
# the call sites or recomputing every score.
EPSS_AMPLIFIER = 5.0
KEV_MULTIPLIER = 2.0
KEV_CRITICAL_CVSS_THRESHOLD = 9.0
BAND_WORST_CRITICAL = 80.0
BAND_WORST_HIGH = 50.0
BAND_WORST_MEDIUM = 20.0


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def _cve_ids_for(finding: AnalysisFinding) -> list[str]:
    """Pull every CVE ID we can find on a finding (vuln_id + aliases JSON)."""
    ids: list[str] = []
    if finding.vuln_id:
        ids.extend(_CVE_RE.findall(finding.vuln_id))
    if finding.aliases:
        try:
            parsed = json.loads(finding.aliases)
            if isinstance(parsed, list):
                for a in parsed:
                    if isinstance(a, str):
                        ids.extend(_CVE_RE.findall(a))
        except (TypeError, ValueError):
            ids.extend(_CVE_RE.findall(finding.aliases))
    # de-dupe, normalize
    return sorted({i.upper() for i in ids if i})


def _resolve_cvss(finding: AnalysisFinding) -> float:
    """
    Pick the per-finding CVSS to feed the formula.

    Prefers the stored numeric ``score``. Falls back to the severity-bucket
    median (so a "CRITICAL" finding with no numeric score still contributes
    real risk instead of 0.0).
    """
    if finding.score is not None:
        try:
            v = float(finding.score)
            if 0.0 <= v <= 10.0:
                return v
        except (TypeError, ValueError):
            pass
    sev = (finding.severity or "UNKNOWN").upper()
    return _SEVERITY_FALLBACK_CVSS.get(sev, 0.0)


def _band_for(worst_finding_score: float, has_kev_critical: bool) -> str:
    if has_kev_critical or worst_finding_score >= BAND_WORST_CRITICAL:
        return "CRITICAL"
    if worst_finding_score >= BAND_WORST_HIGH:
        return "HIGH"
    if worst_finding_score >= BAND_WORST_MEDIUM:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------
# Public scoring entry point
# ---------------------------------------------------------------------


def score_findings(db: Session, findings: Iterable[AnalysisFinding]) -> dict:
    """
    Compute the v2 risk summary for a single analysis run's findings.

    Args:
        db: SQLAlchemy session, used to read/refresh the KEV and EPSS
            caches.
        findings: Iterable of ``AnalysisFinding`` rows belonging to one
            ``AnalysisRun``.

    Returns:
        Dict with keys:
            total_risk_score        float (rounded to 2dp)
            risk_band               "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
            components              list[dict]   per-component breakdown
            worst_finding           dict | None  the single highest-scoring CVE
            kev_count               int          # findings on KEV list
            epss_avg                float        mean EPSS across findings
            methodology             dict         METHODOLOGY constant
    """
    finding_list = list(findings)
    if not finding_list:
        return {
            "total_risk_score": 0.0,
            "risk_band": "LOW",
            "components": [],
            "worst_finding": None,
            "kev_count": 0,
            "epss_avg": 0.0,
            "methodology": METHODOLOGY,
        }

    # Collect every CVE ID across all findings — both KEV and EPSS are
    # keyed on CVE, so we batch the external lookups once.
    all_cves: set[str] = set()
    finding_cves: dict[int, list[str]] = {}
    for f in finding_list:
        cves = _cve_ids_for(f)
        finding_cves[id(f)] = cves
        all_cves.update(cves)

    cve_list = sorted(all_cves)
    kev_set: set[str] = lookup_kev_set_memoized(db, cve_list)
    epss_map: dict[str, float] = get_epss_scores_memoized(db, cve_list)

    # Group findings by component for the per-component breakdown.
    by_comp: dict[tuple[str, str], list[dict]] = defaultdict(list)
    worst_overall: dict | None = None
    has_kev_critical = False
    kev_count = 0
    epss_total = 0.0

    for f in finding_list:
        cves = finding_cves[id(f)]
        cvss = _resolve_cvss(f)

        # Per-finding EPSS = max EPSS across any CVE alias on the finding.
        epss = 0.0
        for c in cves:
            v = epss_map.get(c, 0.0)
            if v > epss:
                epss = v
        epss_total += epss

        # KEV is sticky: if any alias is on the list, the finding gets the boost.
        in_kev = any(c in kev_set for c in cves)
        if in_kev:
            kev_count += 1

        exploit_factor = 1.0 + EPSS_AMPLIFIER * epss
        kev_multiplier = KEV_MULTIPLIER if in_kev else 1.0
        finding_score = cvss * exploit_factor * kev_multiplier

        if in_kev and cvss >= KEV_CRITICAL_CVSS_THRESHOLD:
            has_kev_critical = True

        comp_key = (f.component_name or "unknown", f.component_version or "")
        finding_record = {
            "vuln_id": f.vuln_id,
            "severity": (f.severity or "UNKNOWN").upper(),
            "cvss": round(cvss, 2),
            "epss": round(epss, 4),
            "in_kev": in_kev,
            "score": round(finding_score, 2),
        }
        by_comp[comp_key].append(finding_record)

        if worst_overall is None or finding_score > worst_overall["score"]:
            worst_overall = {
                **finding_record,
                "component_name": comp_key[0],
                "component_version": comp_key[1],
            }

    # Per-component aggregation.
    components_out: list[dict] = []
    total_risk = 0.0
    for (cname, cver), recs in by_comp.items():
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        comp_score = 0.0
        comp_kev = 0
        comp_max = 0.0
        for r in recs:
            sev = r["severity"]
            if sev in sev_counts:
                sev_counts[sev] += 1
            comp_score += r["score"]
            if r["in_kev"]:
                comp_kev += 1
            if r["score"] > comp_max:
                comp_max = r["score"]
        total_risk += comp_score
        components_out.append(
            {
                "name": cname,
                "version": cver,
                "critical": sev_counts["CRITICAL"],
                "high": sev_counts["HIGH"],
                "medium": sev_counts["MEDIUM"],
                "low": sev_counts["LOW"],
                "kev_count": comp_kev,
                "worst_finding_score": round(comp_max, 2),
                "component_score": round(comp_score, 2),
                "highest_severity": (
                    "CRITICAL" if sev_counts["CRITICAL"]
                    else "HIGH" if sev_counts["HIGH"]
                    else "MEDIUM" if sev_counts["MEDIUM"]
                    else "LOW" if sev_counts["LOW"]
                    else "UNKNOWN"
                ),
            }
        )

    components_out.sort(key=lambda x: x["component_score"], reverse=True)

    worst_finding_score = worst_overall["score"] if worst_overall else 0.0
    risk_band = _band_for(worst_finding_score, has_kev_critical)

    epss_avg = (epss_total / len(finding_list)) if finding_list else 0.0

    return {
        "total_risk_score": round(total_risk, 2),
        "risk_band": risk_band,
        "components": components_out,
        "worst_finding": worst_overall,
        "kev_count": kev_count,
        "epss_avg": round(epss_avg, 4),
        "methodology": METHODOLOGY,
    }
