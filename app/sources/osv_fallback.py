"""
OSV fallback scanner using the v1 `/query` endpoint (per-PURL).

The primary OSV implementation in `app.analysis.osv_query_by_components` uses
`/v1/querybatch` + per-vuln hydration. In environments where that path yields no
hydrated vulns (yet no explicit error), we fall back to querying per component.

This module is intentionally dependency-light and returns the same
`(findings, errors, warnings)` tuple shape used across sources.
"""

from __future__ import annotations

from typing import Any

from .match_confidence import apply_strategy_floor, score_match
from .purl import parse_purl


def _vendor_from_purl(purl: str | None) -> str | None:
    """Return the PURL namespace as the component vendor, or ``None``."""
    if not purl:
        return None
    parsed = parse_purl(purl)
    ns = parsed.get("namespace") if parsed else None
    if isinstance(ns, str) and ns.strip():
        return ns
    return None


def _osv_cve_text(vuln: dict[str, Any]) -> str:
    """Assemble OSV-side CVE text: summary + affected package/range tokens."""
    parts: list[str] = [str(vuln.get("summary") or vuln.get("details") or "")]
    for aff in vuln.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        pkg_block = aff.get("package") or {}
        if isinstance(pkg_block, dict):
            for k in ("name", "ecosystem"):
                v = pkg_block.get(k)
                if isinstance(v, str) and v:
                    parts.append(v)
        for r in aff.get("ranges") or []:
            if not isinstance(r, dict):
                continue
            for e in r.get("events") or []:
                if not isinstance(e, dict):
                    continue
                for v_field in ("introduced", "fixed", "last_affected"):
                    v_val = e.get(v_field)
                    if isinstance(v_val, str) and v_val:
                        parts.append(v_val)
    return " ".join(parts)


def _refs_to_urls(v: dict[str, Any]) -> list[str]:
    refs = v.get("references") or []
    urls: list[str] = []
    for r in refs:
        if isinstance(r, dict) and r.get("url"):
            urls.append(str(r["url"]))
    return urls


def _pick_published(v: dict[str, Any]) -> str | None:
    published = v.get("published") or v.get("modified")
    if isinstance(published, str) and published.strip():
        return published.strip()
    return None


def _normalize_osv_vuln_to_finding(
    vuln: dict[str, Any],
    *,
    component_name: str,
    component_version: str | None,
    score_and_vector_fn,
    severity_bucket_fn,
    attack_vector_fn,
    extract_cwe_fn,
    extract_fixed_versions_fn,
    settings: Any,
) -> dict[str, Any]:
    score, vector, sev_txt = score_and_vector_fn(vuln)
    bucket = severity_bucket_fn(score, settings=settings, severity_text=sev_txt)
    return {
        "vuln_id": vuln.get("id"),
        "aliases": vuln.get("aliases", []),
        "sources": ["OSV"],
        "description": vuln.get("summary") or vuln.get("details"),
        "severity": bucket,
        "score": score,
        "vector": vector,
        "attack_vector": attack_vector_fn(vector),
        "cvss_version": None,
        "published": _pick_published(vuln),
        "references": _refs_to_urls(vuln),
        "cwe": extract_cwe_fn(vuln),
        "fixed_versions": extract_fixed_versions_fn(vuln),
        "component_name": component_name or "",
        "component_version": component_version,
        "cpe": None,
        # Roadmap #6 — same purl-direct join the /v1/querybatch path
        # uses; tag identically so consumers can treat the two
        # transports as one logical strategy.
        "match_strategy": "purl_direct",
    }


async def osv_fetch_via_query_endpoint_raw(
    components: list[dict],
    settings: Any,
    *,
    post_json_fn,
) -> tuple[dict[str, list[dict]], list[dict], list[dict]]:
    """Per-component ``/v1/query`` fetcher returning RAW vulns per PURL.

    Roadmap #2 PR-D introduces this alongside the existing
    :func:`osv_query_via_query_endpoint` (which returns processed
    findings). The cache layer wants the RAW vulns so they can be
    cached opaquely and replayed through OSV's normalisation on every
    read.

    Returns ``(vulns_by_purl, errors, warnings)`` where ``vulns_by_purl``
    keys are the **input** ``comp.get("purl")`` strings (NOT the
    canonical cache key — the caller maps to cache keys as needed).
    Components without a PURL are skipped (same dedup logic as the
    legacy function — first comp per PURL wins).
    """
    if not components:
        return {}, [], []

    base = getattr(settings, "osv_api_base_url", "https://api.osv.dev").rstrip("/")
    url = f"{base}/v1/query"
    timeout = int(getattr(settings, "nvd_request_timeout_seconds", 60))

    vulns_by_purl: dict[str, list[dict]] = {}
    errors: list[dict] = []
    warnings: list[dict] = []

    seen: set[str] = set()

    for comp in components:
        purl = (comp.get("purl") or "").strip()
        if not purl or purl in seen:
            continue
        seen.add(purl)

        payload: dict[str, Any] = {"package": {"purl": purl}}
        version = comp.get("version")
        if version and "@" + str(version) not in purl and payload.get("package"):
            payload["version"] = version

        try:
            data = await post_json_fn(url, json_body=payload, timeout=timeout)
        except Exception as exc:
            errors.append({"source": "OSV", "purl": purl, "error": str(exc)})
            continue

        raw_vulns = (data or {}).get("vulns") or []
        # Even an empty list is cached deliberately; storing the empty
        # list here lets the caller mark this PURL as "checked, nothing".
        vulns_by_purl[purl] = [v for v in raw_vulns if isinstance(v, dict)]

    return vulns_by_purl, errors, warnings


async def osv_query_via_query_endpoint(
    components: list[dict],
    settings: Any,
    *,
    post_json_fn,
    best_score_and_vector_fn,
    severity_bucket_fn,
    attack_vector_fn,
    extract_cwe_fn,
    extract_fixed_versions_fn,
) -> tuple[list[dict], list[dict], list[dict]]:
    """
    Query OSV `/v1/query` for each component PURL.

    Returns (findings, errors, warnings).
    """
    if not components:
        return [], [], []

    base = getattr(settings, "osv_api_base_url", "https://api.osv.dev").rstrip("/")
    url = f"{base}/v1/query"
    timeout = int(getattr(settings, "nvd_request_timeout_seconds", 60))

    findings: list[dict] = []
    errors: list[dict] = []
    warnings: list[dict] = []

    # Per-PURL, but de-dupe exact repeats to avoid redundant calls for SBOMs
    # that contain multiple entries with the same purl.
    seen: set[str] = set()

    for comp in components:
        purl = (comp.get("purl") or "").strip()
        if not purl or purl in seen:
            continue
        seen.add(purl)

        payload = {"package": {"purl": purl}}
        # If PURL lacks version but component has it, send as separate field.
        version = comp.get("version")
        if version and "@"+str(version) not in purl and payload.get("package"):
            payload["version"] = version

        try:
            data = await post_json_fn(url, json_body=payload, timeout=timeout)
        except Exception as exc:
            errors.append({"source": "OSV", "purl": purl, "error": str(exc)})
            continue

        vulns = (data or {}).get("vulns") or []
        if not vulns:
            continue

        vendor = _vendor_from_purl(comp.get("purl"))
        for v in vulns:
            if not isinstance(v, dict):
                continue
            finding = _normalize_osv_vuln_to_finding(
                v,
                component_name=comp.get("name") or "",
                component_version=comp.get("version"),
                score_and_vector_fn=best_score_and_vector_fn,
                severity_bucket_fn=severity_bucket_fn,
                attack_vector_fn=attack_vector_fn,
                extract_cwe_fn=extract_cwe_fn,
                extract_fixed_versions_fn=extract_fixed_versions_fn,
                settings=settings,
            )
            # Roadmap #3 — same wiring as the /v1/querybatch path.
            result = score_match(
                component_name=finding.get("component_name") or "",
                component_version=finding.get("component_version"),
                component_vendor=vendor,
                cve_text=_osv_cve_text(v),
            )
            finding["match_confidence"] = apply_strategy_floor(
                result.confidence, finding.get("match_strategy")
            )
            findings.append(finding)

    return findings, errors, warnings

