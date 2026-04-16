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
    }


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

        for v in vulns:
            if not isinstance(v, dict):
                continue
            findings.append(
                _normalize_osv_vuln_to_finding(
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
            )

    return findings, errors, warnings

