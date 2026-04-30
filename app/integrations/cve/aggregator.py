"""
Aggregator: merges per-source ``FetchResult``s into a single ``CveDetail``.

Merge rules (deterministic, documented):

  summary           prefer GHSA → fallback OSV.summary → fallback OSV.details → fallback NVD
  title             GHSA only (other sources don't carry a short title)
  severity          GHSA → OSV.severity_hint → derived-from-CVSS
  cvss_v3_score     NVD only (authoritative)
  cvss_v3_vector    NVD → OSV
  cvss_v4_score     NVD only
  cvss_v4_vector    NVD → OSV
  cwe_ids           union(NVD, GHSA, OSV) — deduped, sorted
  attack_vector,    NVD only (CVSS v3 metrics)
   complexity, etc.
  fix_versions      union(OSV, GHSA), deduped by (ecosystem, package, fixed_in)
  references        union(all), deduped by URL, capped at 25
  exploitation.epss EPSS only
  exploitation.kev  KEV only
  published_at      OSV → GHSA → NVD (earliest non-null)
  modified_at       OSV → GHSA → NVD (most recent non-null)
  aliases           union(OSV, GHSA)
  workaround        not currently surfaced by any source — left null

is_partial = True if any *enabled* source returned ``ERROR`` (timeout, 5xx,
malformed JSON). ``DISABLED``, ``NOT_FOUND``, and ``CIRCUIT_OPEN`` do not flip
the flag — those are normal operating states.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from ...schemas_cve import (
    CveDetail,
    CveExploitation,
    CveFixVersion,
    CveReference,
    CveResultStatus,
    CveSeverity,
)
from .base import CveSource, FetchOutcome, FetchResult
from .identifiers import IdKind, VulnId, classify

log = logging.getLogger("sbom.integrations.cve.aggregator")

_REFS_CAP = 25
_SEV_FROM_CVSS = (
    (9.0, CveSeverity.CRITICAL),
    (7.0, CveSeverity.HIGH),
    (4.0, CveSeverity.MEDIUM),
    (0.1, CveSeverity.LOW),
)


def _first_non_null(*values: Any) -> Any:
    for v in values:
        if v not in (None, ""):
            return v
    return None


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        # NVD uses no timezone suffix; OSV/GHSA use "Z". Normalise.
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _severity_from_cvss(score: float | None) -> CveSeverity | None:
    if score is None:
        return None
    for threshold, severity in _SEV_FROM_CVSS:
        if score >= threshold:
            return severity
    return CveSeverity.NONE


def _normalise_severity(value: Any) -> CveSeverity | None:
    if not isinstance(value, str):
        return None
    v = value.strip().lower()
    mapping = {
        "critical": CveSeverity.CRITICAL,
        "high": CveSeverity.HIGH,
        "moderate": CveSeverity.MEDIUM,
        "medium": CveSeverity.MEDIUM,
        "low": CveSeverity.LOW,
        "none": CveSeverity.NONE,
    }
    return mapping.get(v)


def merge(cve_id: str, results: list[FetchResult]) -> CveDetail:
    """Combine per-source ``FetchResult``s into a single ``CveDetail``."""
    by_source: dict[str, dict[str, Any]] = {}
    sources_used: list[str] = []
    is_partial = False
    enabled_count = 0
    for r in results:
        if r.outcome == FetchOutcome.DISABLED:
            continue
        enabled_count += 1
        if r.outcome == FetchOutcome.OK:
            by_source[r.source] = r.data
            sources_used.append(r.source)
        elif r.outcome == FetchOutcome.ERROR:
            is_partial = True
            log.warning(
                "cve source error",
                extra={"cve_id": cve_id, "source": r.source, "error": r.error},
            )
        # NOT_FOUND / CIRCUIT_OPEN → skip silently

    osv = by_source.get("osv", {})
    ghsa = by_source.get("ghsa", {})
    nvd = by_source.get("nvd", {})
    epss = by_source.get("epss", {})
    kev = by_source.get("kev", {})

    # ---- summary / title -------------------------------------------------
    summary_raw = (
        _first_non_null(ghsa.get("summary"), osv.get("summary"), osv.get("details"), nvd.get("summary"))
        or ""
    )
    summary = str(summary_raw)[:2000]
    title = ghsa.get("title")

    # ---- CVSS scores ----
    cvss_v3_score = nvd.get("cvss_v3_score")
    cvss_v3_vector = _first_non_null(nvd.get("cvss_v3_vector"), osv.get("cvss_v3_vector"))
    cvss_v4_score = nvd.get("cvss_v4_score")
    cvss_v4_vector = _first_non_null(nvd.get("cvss_v4_vector"), osv.get("cvss_v4_vector"))

    # ---- severity --------------------------------------------------------
    severity = (
        _normalise_severity(ghsa.get("severity"))
        or _normalise_severity(osv.get("severity_hint"))
        or _severity_from_cvss(cvss_v3_score)
        or _severity_from_cvss(cvss_v4_score)
        or CveSeverity.UNKNOWN
    )

    # ---- CWE ids (union) -------------------------------------------------
    cwe_ids: set[str] = set()
    for src in (nvd, ghsa, osv):
        for c in src.get("cwe_ids") or []:
            cwe_ids.add(str(c).upper())

    # ---- aliases (union) -------------------------------------------------
    aliases_set: set[str] = set()
    for src in (osv, ghsa):
        for a in src.get("aliases") or []:
            if a and a != cve_id:
                aliases_set.add(a)
    if ghsa.get("ghsa_id"):
        aliases_set.add(str(ghsa["ghsa_id"]))

    # ---- fix versions (union, dedup by ecosystem|package|fixed_in) ------
    fix_versions: list[CveFixVersion] = []
    seen: set[tuple[str, str, str | None]] = set()
    for src in (osv, ghsa):
        for fv in src.get("fix_versions") or []:
            if not isinstance(fv, dict):
                continue
            key = (str(fv.get("ecosystem", "")), str(fv.get("package", "")), fv.get("fixed_in"))
            if key in seen:
                continue
            seen.add(key)
            fix_versions.append(
                CveFixVersion(
                    ecosystem=key[0],
                    package=key[1],
                    fixed_in=fv.get("fixed_in"),
                    introduced_in=fv.get("introduced_in"),
                    range=fv.get("range"),
                )
            )

    # ---- references (union, dedup by URL, cap) ---------------------------
    references: list[CveReference] = []
    seen_urls: set[str] = set()
    for src in (ghsa, nvd, osv):
        for ref in src.get("references") or []:
            if not isinstance(ref, dict):
                continue
            url = ref.get("url")
            if not isinstance(url, str) or url in seen_urls:
                continue
            seen_urls.add(url)
            try:
                references.append(
                    CveReference(
                        label=str(ref.get("label", "Reference")),
                        url=url,
                        type=ref.get("type", "web"),
                    )
                )
            except (ValueError, TypeError):
                # Malformed URL — skip rather than fail the whole merge.
                continue
            if len(references) >= _REFS_CAP:
                break
        if len(references) >= _REFS_CAP:
            break

    # ---- exploitation ----------------------------------------------------
    epss_score = epss.get("score")
    epss_percentile = epss.get("percentile")
    kev_listed = bool(kev.get("listed"))
    kev_due_date_raw = kev.get("due_date")
    kev_due_date = None
    if isinstance(kev_due_date_raw, str) and kev_due_date_raw:
        try:
            kev_due_date = datetime.fromisoformat(kev_due_date_raw).date()
        except ValueError:
            kev_due_date = None

    exploitation = CveExploitation(
        epss_score=float(epss_score) if epss_score is not None else None,
        epss_percentile=float(epss_percentile) if epss_percentile is not None else None,
        cisa_kev_listed=kev_listed,
        cisa_kev_due_date=kev_due_date,
        attack_vector=nvd.get("attack_vector"),
        attack_complexity=nvd.get("attack_complexity"),
        privileges_required=nvd.get("privileges_required"),
        user_interaction=nvd.get("user_interaction"),
        impact_summary=None,  # not surfaced by any current source
    )

    # ---- timestamps ------------------------------------------------------
    published_at = _parse_iso(_first_non_null(osv.get("published"), ghsa.get("published"), nvd.get("published")))
    modified_at = _parse_iso(_first_non_null(osv.get("modified"), ghsa.get("modified"), nvd.get("modified")))

    # If literally no source produced data, still return a minimal payload —
    # never raise. The caller may layer SBOM-derived fields on top.
    if enabled_count > 0 and not sources_used:
        is_partial = True

    return CveDetail(
        cve_id=cve_id,
        aliases=sorted(aliases_set),
        title=title,
        summary=summary,
        severity=severity,
        cvss_v3_score=cvss_v3_score,
        cvss_v3_vector=cvss_v3_vector,
        cvss_v4_score=cvss_v4_score,
        cvss_v4_vector=cvss_v4_vector,
        cwe_ids=sorted(cwe_ids),
        published_at=published_at,
        modified_at=modified_at,
        exploitation=exploitation,
        fix_versions=fix_versions,
        workaround=None,
        references=references,
        sources_used=sources_used,  # type: ignore[arg-type]
        is_partial=is_partial,
        fetched_at=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Two-phase orchestrator
# ---------------------------------------------------------------------------
#
# ``merge()`` above is the pure mapper. ``aggregate()`` below is the
# orchestrator: it fans out per-source fetches in two phases (initial +
# alias re-fan), respects each source's ``accepted_kinds``, and resolves
# the final ``CveResultStatus`` discriminator the frontend reads.

_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$")


async def aggregate(vid: VulnId, sources: Sequence[CveSource]) -> CveDetail:
    """
    Fan out enrichment fetches and produce the merged ``CveDetail``.

    Two phases:

      Phase 1 — every source whose ``accepted_kinds`` includes ``vid.kind``
                runs in parallel against the user-supplied identifier.

      Phase 2 — if Phase 1 surfaced a CVE alias (e.g. OSV returned
                ``aliases: ["CVE-2021-44832"]`` for a GHSA we asked about),
                any source that accepts CVE *and* didn't run in Phase 1 is
                fanned out for that alias. Results land alongside Phase 1's.

    Sources that decline the original ``vid.kind`` AND don't get re-fanned
    are recorded as ``DISABLED`` for ``status`` accounting (silent — they
    never tried, so they don't flip ``is_partial``).
    """
    log.info(
        "cve aggregate start",
        extra={"cve_id": vid.normalized, "kind": vid.kind.value, "source_count": len(sources)},
    )

    primary, deferred = _split_by_kind(sources, vid.kind)

    # Phase 1 — parallel fan-out against the user-supplied id.
    primary_results = await _gather(primary, vid.normalized)

    # Phase 2 — alias re-fan only fires when the deferred set is non-empty
    # and Phase 1 surfaced a canonical CVE alias.
    alias = _extract_cve_alias(primary_results)
    secondary_results: list[FetchResult] = []
    if alias is not None and deferred:
        cve_only = [s for s in deferred if IdKind.CVE in s.accepted_kinds]
        if cve_only:
            log.info(
                "cve aggregate alias re-fan",
                extra={
                    "cve_id": vid.normalized,
                    "resolved_cve": alias,
                    "sources": [s.name for s in cve_only],
                },
            )
            secondary_results = await _gather(cve_only, alias)

    # Sources that never ran show up as DISABLED so the status calculation
    # can tell "didn't try" apart from "tried and failed".
    ran = {r.source for r in primary_results} | {r.source for r in secondary_results}
    skipped = [
        FetchResult(source=s.name, outcome=FetchOutcome.DISABLED)
        for s in sources
        if s.name not in ran
    ]

    all_results = [*primary_results, *secondary_results, *skipped]
    detail = merge(vid.normalized, all_results)

    # Replace the bool-only ``is_partial`` heuristic with a richer status
    # discriminator. The bool stays on the model for back-compat — both are
    # derived from the same per-source outcome counts.
    status = _derive_status(all_results)
    final = detail.model_copy(update={"status": status})
    log.info(
        "cve aggregate done",
        extra={
            "cve_id": vid.normalized,
            "kind": vid.kind.value,
            "status": status.value,
            "sources_used": final.sources_used,
        },
    )
    return final


def _split_by_kind(
    sources: Sequence[CveSource], kind: IdKind
) -> tuple[list[CveSource], list[CveSource]]:
    """Partition sources into (accepts-this-kind, defers)."""
    primary = [s for s in sources if kind in s.accepted_kinds]
    deferred = [s for s in sources if kind not in s.accepted_kinds]
    return primary, deferred


async def _gather(sources: Sequence[CveSource], vuln_id: str) -> list[FetchResult]:
    """Run ``sources`` in parallel against ``vuln_id``; never raises.

    Exceptions from a source are captured as ``ERROR`` ``FetchResult`` rows so
    the merger sees a uniform shape.
    """
    if not sources:
        return []
    gathered = await asyncio.gather(
        *(s.fetch(vuln_id) for s in sources), return_exceptions=True
    )
    out: list[FetchResult] = []
    for src, res in zip(sources, gathered):
        if isinstance(res, FetchResult):
            out.append(res)
            continue
        log.warning(
            "cve source raised", extra={"source": src.name, "error": repr(res)}
        )
        out.append(FetchResult(source=src.name, outcome=FetchOutcome.ERROR, error=str(res)))
    return out


def _extract_cve_alias(results: list[FetchResult]) -> str | None:
    """Pick the first canonical CVE-* alias from any OK result.

    The merge precedence (OSV → GHSA) lines up with the alias-resolution
    precedence here: OSV is canonical for OSV-side aliases, GHSA backstops.
    Multiple CVEs is rare (re-issued IDs); we take the first and log a
    warning so downstream debugging has the full list.
    """
    seen: list[str] = []
    for r in results:
        if r.outcome != FetchOutcome.OK:
            continue
        if r.source not in {"osv", "ghsa"}:
            continue
        for alias in r.data.get("aliases") or []:
            if not isinstance(alias, str):
                continue
            up = alias.strip().upper()
            if _CVE_PATTERN.match(up) and up not in seen:
                seen.append(up)
    if not seen:
        return None
    if len(seen) > 1:
        log.warning("cve alias resolution ambiguous", extra={"aliases": seen})
    return seen[0]


def _derive_status(results: list[FetchResult]) -> CveResultStatus:
    """Reduce per-source outcomes to a single user-facing status.

    Rules:
      * any OK → OK if no ERRORs, else PARTIAL
      * no OK + any ERROR → UNREACHABLE
      * no OK + only NOT_FOUND/DISABLED/CIRCUIT_OPEN → NOT_FOUND
    """
    counts: dict[FetchOutcome, int] = {}
    for r in results:
        counts[r.outcome] = counts.get(r.outcome, 0) + 1
    if counts.get(FetchOutcome.OK):
        return (
            CveResultStatus.PARTIAL
            if counts.get(FetchOutcome.ERROR, 0) > 0
            else CveResultStatus.OK
        )
    if counts.get(FetchOutcome.ERROR, 0) > 0:
        return CveResultStatus.UNREACHABLE
    return CveResultStatus.NOT_FOUND
