"""
Vulnerability source helpers — NVD, GitHub Security Advisories, OSV.

This module hosts the per-source HTTP fetchers, response parsers, and the
multi-source combiner that the legacy `/analyze-sbom-*` endpoints depend on.

Design notes
------------
The functions here are deliberately stateless and side-effect-free so they
can be reused by:
  * The ad-hoc analyze endpoints (`app/routers/analyze_endpoints.py`)
  * The streaming analyze endpoint (`app/routers/sboms_crud.py`)
  * Any future VulnSource Protocol implementations

Each fetcher returns the raw API payload, and a paired `extract_*_records()`
function transforms that payload into a normalised dict shape:

    {
        "id":        str | None,
        "severity":  "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN" | None,
        "score":     float | None,
        "vector":    str | None,
        "published": str | None,
        "url":       str | None,
        ...
    }

Keep this module free of FastAPI-specific imports beyond `HTTPException`,
which we raise for callable-level error reporting.
"""

from __future__ import annotations

import itertools
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote

import requests
from fastapi import HTTPException
from packaging import version

from ..settings import get_settings

# ---------------------------------------------------------------------------
# Constants resolved from centralised settings
# ---------------------------------------------------------------------------
_settings = get_settings()
NVD_API = _settings.NVD_API
GITHUB_GRAPHQL = _settings.GITHUB_GRAPHQL
OSV_API = _settings.OSV_API
OSV_MAX_BATCH = _settings.OSV_MAX_BATCH
DEFAULT_RESULTS_PER_PAGE = _settings.DEFAULT_RESULTS_PER_PAGE


# ---------------------------------------------------------------------------
# CPE generation (NVD lookups)
# ---------------------------------------------------------------------------
def _slug_cpe(s: Optional[str]) -> Optional[str]:
    """Sanitise a token for CPE 2.3 (vendor/product): alphanumeric, _, -, . only."""
    if not s:
        return None
    out = []
    for ch in s.lower():
        if ch.isalnum() or ch in ("_", "-", "."):
            out.append(ch)
        else:
            out.append("_")
    token = "".join(out).strip("._-")
    return token or None


def generate_cpe(name: str, component_version: str) -> Optional[str]:
    """Generate a best-effort CPE 2.3 string; returns None if invalid."""
    if not name or not component_version:
        return None
    vnd = _slug_cpe(name)
    prd = _slug_cpe(name)
    ver = (
        "".join(c if c.isalnum() or c in "._-" else "_" for c in component_version)
        .strip("._-")
        or "*"
    )
    if not vnd or not prd:
        return None
    return f"cpe:2.3:a:{vnd}:{prd}:{ver}:*:*:*:*:*:*:*"


# ---------------------------------------------------------------------------
# NVD fetcher + extractor
# ---------------------------------------------------------------------------
def nvd_fetch(
    name: str,
    version_str: str,
    cpe: Optional[str],
    nvd_api_key: Optional[str],
    results_per_page: int = DEFAULT_RESULTS_PER_PAGE,
) -> Dict[str, Any]:
    headers = {"User-Agent": "SBOM-Analyzer/1.0 (contact: example@example.com)"}
    if nvd_api_key:
        headers["apiKey"] = nvd_api_key
    params: Dict[str, Any] = {"resultsPerPage": results_per_page}
    if not cpe:
        cpe = generate_cpe(name, version_str if isinstance(version_str, str) else "")
    if cpe:
        params["cpeName"] = cpe
    else:
        params["keywordSearch"] = name
    resp = requests.get(NVD_API, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()


def extract_vuln_records(nvd_json: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for v in nvd_json.get("vulnerabilities", []) or []:
        cve_obj = v.get("cve") or {}
        cve_id = cve_obj.get("id")
        published = cve_obj.get("published")
        severity = None
        score = None
        vector = None
        metrics = cve_obj.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key)
            if isinstance(arr, list) and arr:
                data = arr[0].get("cvssData") or {}
                severity = arr[0].get("baseSeverity") or data.get("baseSeverity")
                score = data.get("baseScore")
                vector = data.get("vectorString")
                break
        out.append(
            {
                "id": cve_id,
                "severity": severity,
                "score": score,
                "vector": vector,
                "published": published,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else None,
            }
        )
    return out


def severity_buckets(vulns: List[Dict[str, Any]]) -> Dict[str, int]:
    buckets = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for v in vulns:
        sev = (v.get("severity") or "UNKNOWN").upper()
        if sev not in buckets:
            sev = "UNKNOWN"
        buckets[sev] += 1
    return buckets


# ---------------------------------------------------------------------------
# PURL parsing (shared by GHSA + OSV)
# ---------------------------------------------------------------------------
def _parse_purl(purl: str) -> dict:
    if not purl or not purl.startswith("pkg:"):
        return {}
    rest = purl[4:]
    if "#" in rest:
        rest, _ = rest.split("#", 1)
    qualifiers: Dict[str, str] = {}
    if "?" in rest:
        rest, q = rest.split("?", 1)
        qualifiers = {
            k: v[0] for k, v in parse_qs(q, keep_blank_values=True).items()
        }
    version_tag = None
    if "@" in rest:
        rest, version_tag = rest.rsplit("@", 1)
    parts = rest.split("/")
    if len(parts) < 2:
        return {}
    ptype = parts[0].lower()
    if len(parts) == 2:
        namespace = None
        name = unquote(parts[1])
    else:
        namespace = unquote("/".join(parts[1:-1])) if len(parts) > 2 else None
        name = unquote(parts[-1])
    return {
        "type": ptype,
        "namespace": namespace,
        "name": name,
        "version": version_tag,
        "qualifiers": qualifiers,
    }


def gh_pkg_from_purl(purl: str) -> Tuple[Optional[str], Optional[str]]:
    parsed = _parse_purl(purl)
    if not parsed:
        return None, None
    ptype = parsed.get("type")
    ns = parsed.get("namespace")
    name = parsed.get("name")
    eco_map = {
        "npm": "NPM",
        "pypi": "PIP",
        "maven": "MAVEN",
        "nuget": "NUGET",
        "golang": "GO",
        "go": "GO",
        "rubygems": "RUBYGEMS",
        "gem": "RUBYGEMS",
        "composer": "COMPOSER",
        "cargo": "RUST",
        "crates": "RUST",
        "pub": "PUB",
        "swift": "SWIFT",
        "hex": "ELIXIR",
    }
    eco = eco_map.get((ptype or "").lower())
    if not eco or not name:
        return None, None
    if ptype == "maven":
        pkg = f"{ns}:{name}" if ns else name
    elif ptype in ("npm", "composer", "golang", "go"):
        pkg = f"{ns}/{name}" if ns else name
    else:
        pkg = name
    return eco, pkg


# ---------------------------------------------------------------------------
# GitHub Security Advisories
# ---------------------------------------------------------------------------
def github_fetch_advisories(
    ecosystem: str,
    package_name: str,
    github_token: str,
    first: int = 100,
) -> Dict[str, Any]:
    if not github_token:
        raise HTTPException(
            status_code=400,
            detail="GitHub token missing. Provide 'github_token' or set GITHUB_TOKEN env var.",
        )
    headers = {
        "Authorization": f"bearer {github_token.strip()}",
        "User-Agent": "SBOM-Analyzer/1.1",
        "Accept": "application/json",
    }
    query = """
    query Vulns($ecosystem: SecurityAdvisoryEcosystem!, $name: String!, $first: Int!) {
      securityVulnerabilities(ecosystem: $ecosystem, package: $name, first: $first) {
        nodes {
          severity
          updatedAt
          vulnerableVersionRange
          firstPatchedVersion { identifier }
          package { name ecosystem }
          advisory {
            ghsaId
            summary
            description
            publishedAt
            references { url }
            cvss { score vectorString }
          }
        }
      }
    }
    """
    variables = {"ecosystem": ecosystem, "name": package_name, "first": int(first)}
    resp = requests.post(
        GITHUB_GRAPHQL,
        headers=headers,
        json={"query": query, "variables": variables},
        timeout=45,
    )
    resp.raise_for_status()
    data = resp.json()
    if "errors" in data:
        raise HTTPException(
            status_code=502, detail=f"GitHub GraphQL error: {data['errors']}"
        )
    return data


def is_version_in_range(
    component_version: Optional[str], vuln_range: Optional[str]
) -> bool:
    """Return True if component_version is inside the vulnerable range."""
    if not vuln_range:
        return True
    if not component_version or not component_version.strip():
        return True
    try:
        comp_ver = version.parse(component_version.strip())
    except Exception:
        return True
    vuln_range = vuln_range.strip()
    try:
        from packaging.specifiers import SpecifierSet

        spec = SpecifierSet(vuln_range)
        return comp_ver in spec
    except Exception:
        pass
    try:
        if "<=" in vuln_range and "<" not in vuln_range.replace("<=", ""):
            v = vuln_range.split("<=", 1)[-1].strip().strip("= ")
            return comp_ver <= version.parse(v)
        if "<" in vuln_range:
            v = vuln_range.split("<", 1)[-1].strip().strip("= ")
            return comp_ver < version.parse(v)
        if ">=" in vuln_range:
            v = vuln_range.split(">=", 1)[-1].strip().strip("= ")
            return comp_ver >= version.parse(v)
        if ">" in vuln_range:
            v = vuln_range.split(">", 1)[-1].strip().strip("= ")
            return comp_ver > version.parse(v)
    except Exception:
        pass
    return True


def extract_ghsa_records(
    graphql_json: Dict[str, Any], component_version: Optional[str] = None
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    nodes = (
        ((graphql_json or {}).get("data") or {}).get("securityVulnerabilities") or {}
    ).get("nodes") or []
    for n in nodes:
        adv = n.get("advisory") or {}
        ghsa_id = adv.get("ghsaId")
        severity = (n.get("severity") or "").upper() or None
        cvss = adv.get("cvss") or {}
        score = cvss.get("score")
        vector = cvss.get("vectorString")
        published = adv.get("publishedAt")
        refs = adv.get("references") or []
        url = refs[0].get("url") if refs else None
        if not url and ghsa_id:
            url = f"https://github.com/advisories/{ghsa_id}"

        vuln_range = n.get("vulnerableVersionRange")
        if component_version and vuln_range:
            if not is_version_in_range(component_version, vuln_range):
                continue

        out.append(
            {
                "id": ghsa_id,
                "severity": severity,
                "score": score,
                "vector": vector,
                "published": published,
                "url": url,
                "vulnerableVersionRange": vuln_range,
                "firstPatchedVersion": (
                    (n.get("firstPatchedVersion") or {}).get("identifier")
                ),
            }
        )
    return out


# ---------------------------------------------------------------------------
# OSV
# ---------------------------------------------------------------------------
def _severity_from_score(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    try:
        s = float(score)
    except Exception:
        return "UNKNOWN"
    if s >= 9.0:
        return "CRITICAL"
    if s >= 7.0:
        return "HIGH"
    if s >= 4.0:
        return "MEDIUM"
    if s > 0.0:
        return "LOW"
    return "UNKNOWN"


def _build_osv_query_for_component(
    name: str, version_str: str, purl: Optional[str]
) -> Optional[Dict[str, Any]]:
    """Build a valid OSV query for a component (PURL-based)."""
    if not purl:
        return None
    parsed = _parse_purl(purl)
    if not parsed:
        return None
    purl_version = parsed.get("version")
    if purl_version:
        return {"package": {"purl": purl}}
    if version_str:
        return {"package": {"purl": purl}, "version": version_str}
    return None


def _chunked(iterable, n):
    it = iter(iterable)
    while True:
        chunk = list(itertools.islice(it, n))
        if not chunk:
            return
        yield chunk


def osv_querybatch(queries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for chunk in _chunked(queries, OSV_MAX_BATCH):
        payload = {"queries": chunk}
        resp = requests.post(f"{OSV_API}/querybatch", json=payload, timeout=60)
        resp.raise_for_status()
        data = resp.json() or {}
        chunk_results: List[Dict[str, Any]] = data.get("results") or []
        pending_indices = {
            i: r.get("next_page_token")
            for i, r in enumerate(chunk_results)
            if isinstance(r, dict) and r.get("next_page_token")
        }
        accum: Dict[int, List[Dict[str, Any]]] = {
            i: list((chunk_results[i].get("vulns") or []))
            for i in range(len(chunk_results))
        }
        while pending_indices:
            follow_up_queries = []
            map_idx = []
            for idx, token in pending_indices.items():
                q = dict(chunk[idx])
                q["page_token"] = token
                follow_up_queries.append(q)
                map_idx.append(idx)
            follow_payload = {"queries": follow_up_queries}
            follow_resp = requests.post(
                f"{OSV_API}/querybatch", json=follow_payload, timeout=60
            )
            follow_resp.raise_for_status()
            follow_data = follow_resp.json() or {}
            follow_res = follow_data.get("results") or []
            new_pending: Dict[int, str] = {}
            for j, fr in enumerate(follow_res):
                idx = map_idx[j]
                accum[idx].extend(fr.get("vulns") or [])
                tok = fr.get("next_page_token")
                if tok:
                    new_pending[idx] = tok
            pending_indices = new_pending
        for i in range(len(chunk_results)):
            results.append({"vulns": accum.get(i, [])})
    return results


def osv_get_vuln_by_id(osv_id: str) -> Dict[str, Any]:
    r = requests.get(f"{OSV_API}/vulns/{osv_id}", timeout=45)
    r.raise_for_status()
    return r.json()


def extract_osv_record(osv_json: Dict[str, Any]) -> Dict[str, Any]:
    vid = osv_json.get("id")
    published = osv_json.get("published")
    url = f"https://osv.dev/vulnerability/{vid}" if vid else None
    aliases = osv_json.get("aliases") or []
    best_score = None
    vector = None
    for s in osv_json.get("severity") or []:
        sc = s.get("score")
        try:
            scf = float(sc) if sc is not None else None
        except Exception:
            scf = None
        if scf is not None and (best_score is None or scf > best_score):
            best_score = scf
    severity = _severity_from_score(best_score)
    return {
        "id": vid,
        "severity": severity,
        "score": best_score,
        "vector": vector,
        "published": published,
        "url": url,
        "aliases": aliases,
    }


# ---------------------------------------------------------------------------
# Multi-source consolidation
# ---------------------------------------------------------------------------
def _canonical_id(v: Dict[str, Any]) -> Optional[str]:
    vid = v.get("id") or ""
    if vid.startswith("GHSA") and v.get("aliases"):
        for a in v["aliases"]:
            if a.startswith("CVE"):
                return a
    return vid


def _collect_aliases(v: Dict[str, Any]) -> set:
    als = v.get("aliases") or []
    if v.get("id"):
        als = list(set(als + [v["id"]]))
    return set(als)


def _merge_vuln_entry(
    dst: Dict[str, Any], src: Dict[str, Any], source_tag: str
) -> None:
    dst.setdefault("sources", set()).add(source_tag)
    dst_score = dst.get("score")
    src_score = src.get("score")
    if src_score is not None and (dst_score is None or src_score > dst_score):
        dst["score"] = src_score
        dst["severity"] = _severity_from_score(src_score)
    elif not dst.get("severity") and src.get("severity"):
        dst["severity"] = src.get("severity")
    for k in ("vector", "published", "url"):
        if not dst.get(k) and src.get(k):
            dst[k] = src.get(k)
    dst.setdefault("aliases", [])
    if src.get("aliases"):
        dst["aliases"] = list(set(dst["aliases"] + list(src["aliases"])))


def combine_component_findings(
    nvd_list: List[Dict[str, Any]],
    ghsa_list: List[Dict[str, Any]],
    osv_list: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    combined: Dict[str, Dict[str, Any]] = {}
    by_alias: Dict[str, str] = {}

    def _upsert(src: Dict[str, Any], tag: str):
        aliases = _collect_aliases(src)
        target_key = None
        for a in aliases:
            if a in by_alias:
                target_key = by_alias[a]
                break
        if not target_key:
            cid = _canonical_id(src)
            if cid and cid in combined:
                target_key = cid
        if not target_key:
            cid = _canonical_id(src) or f"{tag}:{len(combined) + 1}"
            combined[cid] = {
                "id": cid,
                "severity": src.get("severity"),
                "score": src.get("score"),
                "vector": src.get("vector"),
                "published": src.get("published"),
                "url": src.get("url"),
                "aliases": list(aliases) if aliases else [],
                "sources": {tag},
            }
            target_key = cid
            for a in aliases:
                by_alias[a] = target_key
        else:
            _merge_vuln_entry(combined[target_key], src, tag)
            for a in aliases:
                by_alias[a] = target_key

    for v in nvd_list or []:
        _upsert(v, "NVD")
    for v in ghsa_list or []:
        _upsert(v, "GHSA")
    for v in osv_list or []:
        _upsert(v, "OSV")

    combined_list: List[Dict[str, Any]] = []
    for k, v in combined.items():
        v["sources"] = sorted(list(v.get("sources") or []))
        combined_list.append(v)
    buckets = severity_buckets(combined_list)
    return combined_list, buckets
