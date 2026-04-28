"""Pure JSON → domain mappers.

No I/O, no global state. Every function takes plain Python dicts (as
parsed from NVD's REST 2.0 JSON) and returns frozen domain dataclasses.
Bad records raise ``MalformedCveError`` so the use-case layer can drop
one record without aborting a whole window.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from .models import CpeCriterion, CveBatch, CveRecord


class MalformedCveError(ValueError):
    """One CVE in a batch failed to map. The use case skips and continues."""


# ---------------------------------------------------------------------------
# Date parsing
# ---------------------------------------------------------------------------

_NVD_DATE_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f",  # "2024-04-16T01:23:45.123"
    "%Y-%m-%dT%H:%M:%S",      # "2024-04-16T01:23:45"
)


def _parse_nvd_datetime(raw: str | None, *, field: str) -> datetime:
    """NVD timestamps are UTC but lack a tzinfo suffix. Attach UTC.

    NVD's API documentation states all dates are UTC; the historical
    dataset confirms this. Some payloads include a ``+00:00`` suffix
    (post-2024 records); we accept either form.
    """
    if not raw:
        raise MalformedCveError(f"missing required datetime field {field!r}")
    # Trim any trailing "Z" or "+00:00" suffix uniformly.
    cleaned = raw.replace("Z", "").split("+")[0].split("-00:00")[0]
    if cleaned.endswith("-"):
        cleaned = cleaned[:-1]
    for fmt in _NVD_DATE_FORMATS:
        try:
            naive = datetime.strptime(cleaned, fmt)
            return naive.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise MalformedCveError(f"could not parse datetime {field!r}={raw!r}")


# ---------------------------------------------------------------------------
# Description / severity / score
# ---------------------------------------------------------------------------


def _english_description(descriptions: list[dict[str, Any]] | None) -> str | None:
    """Return the first English description value, else any value, else None."""
    if not descriptions:
        return None
    for d in descriptions:
        lang = str((d or {}).get("lang", "")).lower()
        if lang.startswith("en"):
            value = (d or {}).get("value")
            if value:
                return str(value)
    # Fall back to the first non-empty description.
    for d in descriptions:
        value = (d or {}).get("value")
        if value:
            return str(value)
    return None


def _safe_float(v: Any) -> float | None:
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _best_metric(metrics: dict[str, Any] | None, key: str) -> dict[str, Any] | None:
    """Pick the 'Primary' metric of a given CVSS version, falling back to first."""
    entries = (metrics or {}).get(key) or []
    if not entries:
        return None
    primary = next(
        (m for m in entries if str((m or {}).get("type", "")).lower() == "primary"),
        entries[0],
    )
    return primary if isinstance(primary, dict) else None


def _extract_cvss(metrics: dict[str, Any] | None) -> tuple[
    float | None,  # v40 score
    float | None,  # v31 score
    float | None,  # v2 score
    str | None,    # severity_text — best-available baseSeverity
    str | None,    # vector_string — best-available
]:
    score_v40: float | None = None
    score_v31: float | None = None
    score_v2: float | None = None
    severity_text: str | None = None
    vector_string: str | None = None

    for src_key, score_var in (
        ("cvssMetricV40", "v40"),
        ("cvssMetricV31", "v31"),
        ("cvssMetricV30", "v31"),
        ("cvssMetricV2", "v2"),
    ):
        m = _best_metric(metrics, src_key)
        if not m:
            continue
        cvss_data = (m.get("cvssData") or {}) if isinstance(m, dict) else {}
        score = _safe_float(cvss_data.get("baseScore"))
        if score_var == "v40" and score_v40 is None:
            score_v40 = score
        elif score_var == "v31" and score_v31 is None:
            score_v31 = score
        elif score_var == "v2" and score_v2 is None:
            score_v2 = score

        if vector_string is None:
            vs = cvss_data.get("vectorString")
            if vs:
                vector_string = str(vs)
        if severity_text is None:
            sev = m.get("baseSeverity") or cvss_data.get("baseSeverity")
            if sev:
                severity_text = str(sev).upper()

    return score_v40, score_v31, score_v2, severity_text, vector_string


# ---------------------------------------------------------------------------
# CPE / CWE / references
# ---------------------------------------------------------------------------


def _cpe_stem(cpe23: str) -> str:
    """vendor:product extracted from a CPE 2.3 string, lowercased.

    Returns empty string for malformed input — the criterion will then
    fail the GIN-stem filter at query time, which is what we want.
    """
    parts = cpe23.split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return ""
    vendor, product = parts[3], parts[4]
    if not vendor or not product:
        return ""
    return f"{vendor.lower()}:{product.lower()}"


def _flatten_cpe_match(configurations: list[dict[str, Any]] | None) -> list[CpeCriterion]:
    """Walk configurations[].nodes[].cpeMatch[] into a flat list."""
    out: list[CpeCriterion] = []
    if not configurations:
        return out
    for cfg in configurations:
        if not isinstance(cfg, dict):
            continue
        for node in cfg.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            _walk_node(node, out)
    return out


def _walk_node(node: dict[str, Any], out: list[CpeCriterion]) -> None:
    for match in node.get("cpeMatch") or []:
        if not isinstance(match, dict):
            continue
        criteria = match.get("criteria")
        if not criteria:
            continue
        out.append(
            CpeCriterion(
                criteria=str(criteria),
                criteria_stem=_cpe_stem(str(criteria)),
                vulnerable=bool(match.get("vulnerable", True)),
                version_start_including=_str_or_none(match.get("versionStartIncluding")),
                version_start_excluding=_str_or_none(match.get("versionStartExcluding")),
                version_end_including=_str_or_none(match.get("versionEndIncluding")),
                version_end_excluding=_str_or_none(match.get("versionEndExcluding")),
            )
        )
    # Nested children — NVD does occasionally produce nested AND/OR trees.
    for child in node.get("children") or []:
        if isinstance(child, dict):
            _walk_node(child, out)


def _str_or_none(v: Any) -> str | None:
    return str(v) if v is not None and v != "" else None


def _extract_aliases(weaknesses: list[dict[str, Any]] | None) -> list[str]:
    """Flatten CWE-* identifiers from weaknesses; deduplicate."""
    seen: list[str] = []
    if not weaknesses:
        return seen
    for w in weaknesses:
        if not isinstance(w, dict):
            continue
        for d in w.get("description") or []:
            if not isinstance(d, dict):
                continue
            value = d.get("value")
            if isinstance(value, str) and value.startswith("CWE-") and value not in seen:
                seen.append(value)
    return seen


def _extract_references(refs: list[dict[str, Any]] | None) -> list[str]:
    if not refs:
        return []
    out: list[str] = []
    for r in refs:
        if isinstance(r, dict):
            url = r.get("url")
            if isinstance(url, str) and url:
                out.append(url)
    return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def map_cve(cve_json: Mapping[str, Any]) -> CveRecord:
    """Map one NVD CVE object (the inner ``cve`` document) to ``CveRecord``."""
    cve_dict: dict[str, Any] = dict(cve_json)
    cve_id = cve_dict.get("id")
    if not cve_id:
        raise MalformedCveError("CVE object missing 'id'")

    last_modified = _parse_nvd_datetime(cve_dict.get("lastModified"), field="lastModified")
    published = _parse_nvd_datetime(cve_dict.get("published"), field="published")

    score_v40, score_v31, score_v2, severity_text, vector_string = _extract_cvss(
        cve_dict.get("metrics")
    )

    return CveRecord(
        cve_id=str(cve_id),
        last_modified=last_modified,
        published=published,
        vuln_status=str(cve_dict.get("vulnStatus") or "Unknown"),
        description_en=_english_description(cve_dict.get("descriptions")),
        score_v40=score_v40,
        score_v31=score_v31,
        score_v2=score_v2,
        severity_text=severity_text,
        vector_string=vector_string,
        aliases=tuple(_extract_aliases(cve_dict.get("weaknesses"))),
        cpe_criteria=tuple(_flatten_cpe_match(cve_dict.get("configurations"))),
        references=tuple(_extract_references(cve_dict.get("references"))),
        raw=cve_dict,
    )


def map_batch(response_json: Mapping[str, Any]) -> CveBatch:
    """Map a full NVD CVE 2.0 response to ``CveBatch``.

    Per-record failures are dropped (with no warning here — the use
    case logs and counts errors). The batch's paging metadata is
    preserved verbatim.
    """
    response_dict: dict[str, Any] = dict(response_json)
    vulns = response_dict.get("vulnerabilities") or []
    records: list[CveRecord] = []
    for entry in vulns:
        if not isinstance(entry, dict):
            continue
        cve = entry.get("cve")
        if not isinstance(cve, dict):
            continue
        try:
            records.append(map_cve(cve))
        except MalformedCveError:
            # Skip — the loop continues. Use cases that need to know
            # call map_cve directly and catch.
            continue

    return CveBatch(
        records=tuple(records),
        start_index=int(response_dict.get("startIndex") or 0),
        results_per_page=int(response_dict.get("resultsPerPage") or len(records)),
        total_results=int(response_dict.get("totalResults") or len(records)),
    )
