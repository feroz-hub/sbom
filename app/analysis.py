from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from functools import lru_cache
from typing import Any

import requests

# Optional async HTTP client; we fall back to requests in a thread if missing
try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

from .http_client import tls_ssl_context
from .parsing import extract_components  # noqa: F401 — re-exported for callers

# Module-level requests.Session for NVD connection pooling
_nvd_session = requests.Session()
_nvd_session.verify = tls_ssl_context()
_nvd_session.headers.update({"User-Agent": "SBOM-Analyzer/enterprise-2.0"})

LOGGER = logging.getLogger(__name__)

# ============================================================
# CVE MODEL (kept inline for self-contained file)
# ============================================================


@dataclass
class CVSSv2Data:
    version: str
    vectorString: str
    baseScore: float
    accessVector: str | None = None
    accessComplexity: str | None = None
    authentication: str | None = None
    confidentialityImpact: str | None = None
    integrityImpact: str | None = None
    availabilityImpact: str | None = None


@dataclass
class CVSSv2Metric:
    source: str
    type: str
    cvssData: CVSSv2Data
    baseSeverity: str | None = None
    exploitabilityScore: float | None = None
    impactScore: float | None = None
    acInsufInfo: bool | None = None
    obtainAllPrivilege: bool | None = None
    obtainUserPrivilege: bool | None = None
    obtainOtherPrivilege: bool | None = None
    userInteractionRequired: bool | None = None


@dataclass
class Metrics:
    cvssMetricV2: list[dict[str, Any]] = field(default_factory=list)
    cvssMetricV31: list[dict[str, Any]] = field(default_factory=list)
    cvssMetricV40: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class LangDescription:
    lang: str
    value: str


@dataclass
class WeaknessDescription:
    lang: str
    value: str


@dataclass
class WeaknessItem:
    source: str
    type: str
    description: list[WeaknessDescription] = field(default_factory=list)


@dataclass
class CPEMatch:
    vulnerable: bool
    criteria: str
    matchCriteriaId: str | None = None
    versionStartIncluding: str | None = None
    versionStartExcluding: str | None = None
    versionEndIncluding: str | None = None
    versionEndExcluding: str | None = None


@dataclass
class ConfigNode:
    operator: str  # "OR" / "AND"
    negate: bool
    cpeMatch: list[CPEMatch] = field(default_factory=list)


@dataclass
class Configuration:
    nodes: list[ConfigNode] = field(default_factory=list)


@dataclass
class Reference:
    url: str
    source: str | None = None


@dataclass
class CVERecord:
    id: str
    sourceIdentifier: str | None = None
    published: str | None = None
    lastModified: str | None = None
    vulnStatus: str | None = None
    cveTags: list[str] = field(default_factory=list)
    descriptions: list[LangDescription] = field(default_factory=list)
    metrics: Metrics | None = None
    weaknesses: list[WeaknessItem] = field(default_factory=list)
    configurations: list[Configuration] = field(default_factory=list)
    references: list[Reference] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CVERecord:
        descriptions = [LangDescription(**d) for d in data.get("descriptions", [])]

        metrics = None
        metrics_dict = data.get("metrics")
        if metrics_dict:
            metrics = Metrics(
                cvssMetricV2=list(metrics_dict.get("cvssMetricV2") or []),
                cvssMetricV31=list(metrics_dict.get("cvssMetricV31") or []),
                cvssMetricV40=list(metrics_dict.get("cvssMetricV40") or []),
            )

        weaknesses: list[WeaknessItem] = []
        for w in data.get("weaknesses", []) or []:
            descs = [WeaknessDescription(**wd) for wd in w.get("description", []) or []]
            weaknesses.append(WeaknessItem(source=w.get("source", ""), type=w.get("type", ""), description=descs))

        # Minimal parse for configurations/references (not essential to output)
        references = [Reference(**r) for r in data.get("references", []) or []]

        return cls(
            id=data["id"],
            sourceIdentifier=data.get("sourceIdentifier"),
            published=data.get("published"),
            lastModified=data.get("lastModified"),
            vulnStatus=data.get("vulnStatus"),
            cveTags=data.get("cveTags", []),
            descriptions=descriptions,
            metrics=metrics,
            weaknesses=weaknesses,
            configurations=[],
            references=references,
        )

    # Helpers
    def primary_english_description(self) -> str | None:
        for d in self.descriptions:
            if d.lang and d.lang.lower().startswith("en"):
                return d.value
        return self.descriptions[0].value if self.descriptions else None

    def cvss_v2_base(self) -> float | None:
        """Legacy alias — calls cvss_best_base() for backwards compatibility."""
        return self.cvss_best_base()

    def cvss_best_base(self) -> float | None:
        """Return the best CVSS base score across V40 > V31 > V2."""
        if not self.metrics:
            return None
        for metric_list in [self.metrics.cvssMetricV40, self.metrics.cvssMetricV31, self.metrics.cvssMetricV2]:
            if not metric_list:
                continue
            primary = next(
                (m for m in metric_list if str((m or {}).get("type", "")).lower() == "primary"),
                metric_list[0],
            )
            cvss_data = (primary or {}).get("cvssData") or {}
            score = _safe_score(cvss_data.get("baseScore"))
            if score is not None:
                return score
        return None


# ============================================================
# Settings / env helpers
# ============================================================


@dataclass(frozen=True)
class AnalysisSettings:
    source_name: str = "NVD"
    http_user_agent: str = "SBOM-Analyzer/enterprise-2.0"
    nvd_api_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_detail_base_url: str = "https://nvd.nist.gov/vuln/detail"
    nvd_api_key_env: str = "NVD_API_KEY"
    nvd_results_per_page: int = 2000
    nvd_request_timeout_seconds: int = 60
    nvd_max_retries: int = 3
    nvd_retry_backoff_seconds: float = 1.5
    nvd_request_delay_with_key_seconds: float = 0.7
    nvd_request_delay_without_key_seconds: float = 6.0
    cvss_critical_threshold: float = 9.0
    cvss_high_threshold: float = 7.0
    cvss_medium_threshold: float = 4.0
    analysis_max_findings_per_cpe: int = 5000
    analysis_max_findings_total: int = 50000


def _env_str(name: str, default: str) -> str:
    value = os.getenv(name)
    if value is None:
        return default
    value = value.strip()
    return value if value else default


def _env_int(name: str, default: int, minimum: int = 0) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError:
        return default
    return max(minimum, parsed)


def _env_float(name: str, default: float, minimum: float = 0.0) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        parsed = float(value)
    except ValueError:
        return default
    return max(minimum, parsed)


@lru_cache(maxsize=1)
def get_analysis_settings() -> AnalysisSettings:
    return AnalysisSettings(
        source_name=_env_str("ANALYSIS_SOURCE_NAME", "NVD"),
        http_user_agent=_env_str("ANALYSIS_HTTP_USER_AGENT", "SBOM-Analyzer/enterprise-2.0"),
        nvd_api_base_url=_env_str("NVD_API_BASE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0"),
        nvd_detail_base_url=_env_str("NVD_DETAIL_BASE_URL", "https://nvd.nist.gov/vuln/detail"),
        nvd_api_key_env=_env_str("NVD_API_KEY_ENV", "NVD_API_KEY"),
        nvd_results_per_page=_env_int("NVD_RESULTS_PER_PAGE", 2000, minimum=1),
        nvd_request_timeout_seconds=_env_int("NVD_REQUEST_TIMEOUT_SECONDS", 60, minimum=1),
        nvd_max_retries=_env_int("NVD_MAX_RETRIES", 3, minimum=0),
        nvd_retry_backoff_seconds=_env_float("NVD_RETRY_BACKOFF_SECONDS", 1.5, minimum=0.0),
        nvd_request_delay_with_key_seconds=_env_float("NVD_REQUEST_DELAY_WITH_KEY_SECONDS", 0.7, minimum=0.0),
        nvd_request_delay_without_key_seconds=_env_float("NVD_REQUEST_DELAY_WITHOUT_KEY_SECONDS", 6.0, minimum=0.0),
        cvss_critical_threshold=_env_float("CVSS_CRITICAL_THRESHOLD", 9.0, minimum=0.0),
        cvss_high_threshold=_env_float("CVSS_HIGH_THRESHOLD", 7.0, minimum=0.0),
        cvss_medium_threshold=_env_float("CVSS_MEDIUM_THRESHOLD", 4.0, minimum=0.0),
        analysis_max_findings_per_cpe=_env_int("ANALYSIS_MAX_FINDINGS_PER_CPE", 5000, minimum=0),
        analysis_max_findings_total=_env_int("ANALYSIS_MAX_FINDINGS_TOTAL", 50000, minimum=0),
    )


def resolve_nvd_api_key(settings: AnalysisSettings | None = None) -> str | None:
    cfg = settings or get_analysis_settings()
    key = os.getenv(cfg.nvd_api_key_env)
    if key and key.strip():
        return key.strip()
    return None


# ============================================================
# CVSS helpers
# ============================================================

# ----------------------------------------------------------------------
# Phase 1 (Finding B): the canonical bodies of the helpers below now live
# in `app/services/sources/`. They are imported here under their legacy
# underscore-prefixed names so the existing call sites in this file (and
# the routers) continue to work without modification. Phase 2 source
# adapters will import directly from `services.sources` instead.
# ----------------------------------------------------------------------

from .sources.cpe import cpe23_from_purl as _cpe23_from_purl
from .sources.purl import parse_purl as _parse_purl
from .sources.severity import (
    cvss_version_from_metrics as _cvss_version_from_metrics,
)
from .sources.severity import (
    extract_best_cvss as _extract_best_cvss,
)
from .sources.severity import (
    parse_cvss_attack_vector as _parse_cvss_attack_vector,
)
from .sources.severity import (
    safe_score as _safe_score,
)
from .sources.severity import (
    sev_bucket as _sev_bucket,
)


def _augment_components_with_cpe(components: list[dict]) -> tuple[list[dict], int]:
    """
    Return a new list where missing CPEs are best-effort generated from PURLs.
    Uses component version when PURL has no version. Returns (components_with_possible_cpe, count_generated).
    """
    out = []
    generated = 0
    for c in components:
        d = dict(c or {})
        if not d.get("cpe"):
            p = d.get("purl")
            if p:
                comp_version = d.get("version")
                cpe = _cpe23_from_purl(p, version_override=comp_version)
                if cpe:
                    d["cpe"] = cpe
                    generated += 1
        out.append(d)
    return out, generated


# ============================================================
# NVD â€” sync (called in parallel across CPEs)
# ============================================================


def nvd_query_by_cpe(cpe: str, api_key: str | None, settings: AnalysisSettings | None = None) -> list[dict]:
    cfg = settings or get_analysis_settings()
    if not cpe:
        return []
    headers = {"User-Agent": cfg.http_user_agent}
    if api_key:
        headers["apiKey"] = api_key
    params = {
        "cpeName": cpe,
        "resultsPerPage": cfg.nvd_results_per_page,
        "startIndex": 0,
    }
    delay = cfg.nvd_request_delay_with_key_seconds if api_key else cfg.nvd_request_delay_without_key_seconds
    out: list[dict] = []
    # Headers are passed per-request — do NOT mutate _nvd_session.headers (thread-safety)

    while True:
        response = None
        for attempt in range(cfg.nvd_max_retries + 1):
            try:
                response = _nvd_session.get(
                    cfg.nvd_api_base_url,
                    params=params,
                    headers=headers,
                    timeout=cfg.nvd_request_timeout_seconds,
                )
                if response.status_code == 429 or response.status_code >= 500:
                    raise requests.HTTPError(f"NVD HTTP {response.status_code}", response=response)
                response.raise_for_status()
                break
            except requests.RequestException as exc:
                if attempt >= cfg.nvd_max_retries:
                    raise RuntimeError(f"NVD query failed for CPE '{cpe}': {exc}") from exc
                backoff = cfg.nvd_retry_backoff_seconds * (attempt + 1)
                LOGGER.warning("NVD request retry %s for CPE %s due to: %s", attempt + 1, cpe, exc)
                if backoff > 0:
                    time.sleep(backoff)

        if response is None:
            raise RuntimeError(f"NVD query returned no response for CPE '{cpe}'")

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", []) or []
        out.extend([item.get("cve") for item in vulnerabilities if item.get("cve")])

        total = int(data.get("totalResults", len(out)))
        start = int(params["startIndex"])
        size = int(data.get("resultsPerPage") or params["resultsPerPage"] or 0)
        if size <= 0 or start + size >= total:
            break
        params["startIndex"] = start + size
        if delay > 0:
            time.sleep(delay)
    return out


def _finding_from_raw(
    raw: dict[str, Any],
    cpe: str | None,
    component_name: str,
    component_version: str | None,
    settings: AnalysisSettings,
) -> dict[str, Any]:
    try:
        record = CVERecord.from_dict(raw)
        score = record.cvss_best_base()
        metric_score, metric_vector, metric_severity = _extract_best_cvss(raw.get("metrics") or {})
        if score is None:
            score = metric_score
        severity = _sev_bucket(score, settings=settings, severity_text=metric_severity)
        vector = metric_vector  # _extract_best_cvss picks the best vector
        published = raw.get("published")
        vuln_id = record.id
        description = record.primary_english_description()
    except Exception:
        metric_score, metric_vector, metric_severity = _extract_best_cvss(raw.get("metrics") or {})
        score = metric_score
        severity = _sev_bucket(score, settings=settings, severity_text=metric_severity)
        descriptions = raw.get("descriptions") or []
        description = None
        for desc in descriptions:
            lang = str((desc or {}).get("lang", "")).lower()
            if lang.startswith("en"):
                description = (desc or {}).get("value")
                break
        if description is None and descriptions:
            description = (descriptions[0] or {}).get("value")
        vector = metric_vector
        published = raw.get("published")
        vuln_id = raw.get("id") or "UNKNOWN-CVE"

    detail_base = settings.nvd_detail_base_url.rstrip("/")
    return {
        "vuln_id": vuln_id,
        "aliases": [],
        "sources": ["NVD"],
        "description": description,
        "severity": severity,
        "score": score,
        "vector": vector,
        "attack_vector": _parse_cvss_attack_vector(vector),
        "cvss_version": _cvss_version_from_metrics(raw.get("metrics") or {}),
        "published": published,
        "references": [r.get("url") for r in raw.get("references", [])],
        "cwe": extract_cwe_from_nvd(raw),
        "fixed_versions": [],
        "component_name": component_name,
        "component_version": component_version,
        "cpe": cpe,
    }


# Phase 5 cleanup note: the legacy single-source `analyze_sbom_against_nvd`
# function lived here. It had zero callers anywhere in the codebase
# (verified by grep across `app/` and `tests/`) — the production NVD path
# goes through `nvd_query_by_components_async` (called by `NvdSource` and
# the multi-source orchestrator). The dead function was removed.


# ============================================================
# Multi-source (async) with OSV and GitHub Advisory
# ============================================================


@dataclass(frozen=True)
class _MultiSettings(AnalysisSettings):
    gh_graphql_url: str = "https://api.github.com/graphql"
    gh_token_env: str = "GITHUB_TOKEN"
    # Per-request override for GitHub token. When set, takes precedence over the
    # environment variable read via `gh_token_env`. Lets request handlers pass a
    # caller-supplied token without mutating process-global os.environ.
    gh_token_override: str | None = None
    osv_api_base_url: str = "https://api.osv.dev"
    osv_results_per_batch: int = 1000
    max_concurrency: int = 10
    prefer_async_httpx: bool = True
    analysis_sources_env: str = "ANALYSIS_SOURCES"  # e.g., "NVD,OSV,GITHUB"


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_list(name: str, default: list[str]) -> list[str]:
    v = os.getenv(name)
    if not v:
        return default
    return [s.strip().upper() for s in v.split(",") if s.strip()]


@lru_cache(maxsize=1)
def get_analysis_settings_multi() -> _MultiSettings:
    base = get_analysis_settings()
    base_kwargs = asdict(base)
    return _MultiSettings(
        **base_kwargs,
        gh_graphql_url=_env_str("GH_GRAPHQL_URL", "https://api.github.com/graphql"),
        gh_token_env=_env_str("GH_TOKEN_ENV", "GITHUB_TOKEN"),
        osv_api_base_url=_env_str("OSV_API_BASE_URL", "https://api.osv.dev"),
        osv_results_per_batch=_env_int("OSV_RESULTS_PER_BATCH", 1000, minimum=1),
        max_concurrency=_env_int("ANALYSIS_MAX_CONCURRENCY", 10, minimum=1),
        prefer_async_httpx=_env_bool("ANALYSIS_PREFER_ASYNC_HTTPX", True),
        analysis_sources_env=_env_str("ANALYSIS_SOURCES_ENV", "ANALYSIS_SOURCES"),
    )


# -----------------------
# Async HTTP helpers
# -----------------------

_executor = concurrent.futures.ThreadPoolExecutor(max_workers=max(4, os.cpu_count() or 4))


async def _async_get(url: str, headers: dict | None = None, params: dict | None = None, timeout: int = 60):
    if httpx is not None:
        try:
            from .http_client import get_async_http_client

            client = get_async_http_client()
        except RuntimeError:
            async with httpx.AsyncClient(
                timeout=timeout, headers=headers, verify=tls_ssl_context()
            ) as client:
                r = await client.get(url, params=params, headers=headers)
                r.raise_for_status()
                return r.json()
        else:
            r = await client.get(url, params=params, headers=headers, timeout=timeout)
            r.raise_for_status()
            return r.json()
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        _executor,
        lambda: requests.get(
            url,
            headers=headers,
            params=params,
            timeout=timeout,
            verify=tls_ssl_context(),
        ).json(),
    )


async def _async_post(url: str, json_body: dict, headers: dict | None = None, timeout: int = 60):
    if httpx is not None:
        try:
            from .http_client import get_async_http_client

            client = get_async_http_client()
        except RuntimeError:
            async with httpx.AsyncClient(
                timeout=timeout, headers=headers, verify=tls_ssl_context()
            ) as client:
                r = await client.post(url, json=json_body, headers=headers)
                r.raise_for_status()
                return r.json()
        else:
            r = await client.post(url, json=json_body, headers=headers, timeout=timeout)
            r.raise_for_status()
            return r.json()
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        _executor,
        lambda: requests.post(
            url,
            json=json_body,
            headers=headers,
            timeout=timeout,
            verify=tls_ssl_context(),
        ).json(),
    )


# -----------------------
# Ecosystem helpers
# -----------------------


def _github_ecosystem_from_purl_type(ptype: str) -> str | None:
    """
    GitHub Advisory GraphQL ecosystems.
    """
    mapping = {
        "npm": "NPM",
        "pypi": "PIP",  # GH uses PIP for PyPI
        "maven": "MAVEN",
        "nuget": "NUGET",
        "golang": "GO",
        "go": "GO",
        "rubygems": "RUBYGEMS",
        "composer": "COMPOSER",
        "cargo": "RUST",
        "crates": "RUST",
        "gem": "RUBYGEMS",
        "pub": "PUB",
        "swift": "SWIFT",
        "hex": "ELIXIR",
    }
    return mapping.get((ptype or "").lower())


# ---------- OSV ----------


def _best_score_and_vector_from_osv(v: dict) -> tuple[float | None, str | None, str | None]:
    score = None
    vector = None
    severity_txt = None
    # severity[].score is often a CVSS vector string, not a float
    for sev in v.get("severity") or []:
        t = (sev.get("type") or "").upper()
        raw_score = sev.get("score") or ""
        if t in {"CVSS_V3", "CVSS_V4"}:
            if isinstance(raw_score, str) and raw_score.upper().startswith("CVSS:"):
                # It's a vector string, not a number – strip the "CVSS:x.y/" prefix
                # so downstream consumers get a clean metric string (AV:N/AC:L/…).
                if vector is None:
                    cleaned = raw_score
                    slash_idx = cleaned.find("/")
                    if slash_idx != -1:
                        cleaned = cleaned[slash_idx + 1 :]
                    vector = cleaned
            else:
                try:
                    s = float(raw_score)
                    if score is None or s > score:
                        score = s
                except (TypeError, ValueError):
                    pass
    # NVD-enriched OSV records populate database_specific.cvss.score as a real float
    database_specific = v.get("database_specific") or {}
    cvss_db = database_specific.get("cvss") or {}
    if score is None:
        db_score = cvss_db.get("score")
        if db_score is not None:
            try:
                score = float(db_score)
            except (TypeError, ValueError):
                pass
    if vector is None:
        vector = cvss_db.get("vectorString") or cvss_db.get("vector")
    # Text severity fallback from database_specific
    if severity_txt is None:
        severity_txt = database_specific.get("severity")
    return score, vector, severity_txt


async def osv_query_by_components(
    components: list[dict], settings: _MultiSettings
) -> tuple[list[dict], list[dict], list[dict]]:
    if not components:
        return [], [], []
    base = settings.osv_api_base_url.rstrip("/")
    batch_url = f"{base}/v1/querybatch"
    get_url = f"{base}/v1/vulns"

    queries: list[dict] = []
    for comp in components:
        purl = comp.get("purl")
        name = comp.get("name") or ""
        version = comp.get("version")
        q: dict = {}

        if purl:
            parsed = _parse_purl(purl)
            if parsed:
                # Prefer versioned purl; otherwise send purl + separate version if available
                if parsed.get("version"):
                    q = {"package": {"purl": purl}}
                elif version:
                    q = {"package": {"purl": purl}, "version": version}
                else:
                    q = {"package": {"purl": purl}}

        if not q and name:
            # Last-resort: ecosystem+name(+version). OSV matching is much better
            # with an ecosystem than with name-only.
            eco = (comp.get("ecosystem") or "").strip()
            if not eco:
                # Infer from group heuristics when present (common for Maven-like SBOMs)
                grp = (comp.get("group") or "").strip()
                if grp and ("." in grp or grp.lower().startswith(("org.", "com.", "net.", "io."))):
                    eco = "Maven"
                elif name.startswith("@") and "/" in name:
                    eco = "npm"
            pkg = {"name": name}
            if eco:
                pkg["ecosystem"] = eco
            q = {"package": pkg}
            if version:
                q["version"] = version

        if q:
            queries.append(q)

    findings: list[dict] = []
    query_errors: list[dict] = []
    query_warnings: list[dict] = []

    # Build name-to-version lookup for comp_ver resolution (Bug A3)
    name_to_ver: dict[str, str | None] = {(c.get("name") or "").lower(): c.get("version") for c in components}

    if not queries:
        return findings, query_errors, query_warnings

    batches = [
        queries[i : i + settings.osv_results_per_batch] for i in range(0, len(queries), settings.osv_results_per_batch)
    ]

    async def _fetch_batch(batch: list[dict]) -> list[str]:
        try:
            res = await _async_post(
                batch_url, json_body={"queries": batch}, timeout=settings.nvd_request_timeout_seconds
            )
            ids: list[str] = []
            for item in res.get("results", []) or []:
                for v in item.get("vulns", []) or []:
                    vid = v.get("id")
                    if vid:
                        ids.append(vid)
            return ids
        except Exception as exc:
            query_errors.append({"source": "OSV", "error": str(exc)})
            return []

    all_ids_nested = await asyncio.gather(*[_fetch_batch(b) for b in batches])
    unique_ids = sorted({vid for sub in all_ids_nested for vid in sub})

    sem = asyncio.Semaphore(settings.max_concurrency)

    async def _fetch_vuln(vid: str) -> dict | None:
        url = f"{get_url}/{vid}"
        try:
            async with sem:
                data = await _async_get(url, timeout=settings.nvd_request_timeout_seconds)
                return data
        except Exception as exc:
            query_errors.append({"source": "OSV", "id": vid, "error": str(exc)})
            return None

    hydrated = await asyncio.gather(*[_fetch_vuln(vid) for vid in unique_ids])
    hydrated = [h for h in hydrated if h]

    cfg = settings
    for v in hydrated:
        affected = v.get("affected") or []
        published = v.get("published") or v.get("modified")
        summary = v.get("summary") or v.get("details")
        references = v.get("references") or []
        url = None
        for ref in references:
            if ref.get("url"):
                url = ref["url"]
                break
        score, vector, sev_txt = _best_score_and_vector_from_osv(v)
        bucket = _sev_bucket(score, settings=cfg, severity_text=sev_txt)

        comp_name = ""
        comp_ver = None
        if affected:
            pkg = (affected[0] or {}).get("package") or {}
            comp_name = pkg.get("name") or ""
            comp_ver = name_to_ver.get(comp_name.lower())  # Bug A3 fix

        findings.append(
            {
                "vuln_id": v.get("id"),
                "aliases": v.get("aliases", []),
                "sources": ["OSV"],
                "description": summary,
                "severity": bucket,
                "score": score,
                "vector": vector,
                "attack_vector": _parse_cvss_attack_vector(vector),
                "cvss_version": None,
                "published": published,
                "references": [r.get("url") for r in references],
                "cwe": extract_cwe_from_osv(v),
                "fixed_versions": extract_fixed_versions_osv(v),
                "component_name": comp_name,
                "component_version": comp_ver,
                "cpe": None,
            }
        )

    return findings, query_errors, query_warnings


def enrich_component_for_osv(comp):
    comp = dict(comp)  # avoid mutating caller's dict
    name_raw = (comp.get("name") or "").strip()
    name = name_raw.lower()
    version = comp.get("version")
    group = (comp.get("group") or "").strip()

    # Only enrich if no purl already set
    if not comp.get("purl"):
        # Prefer deterministic reconstruction from SBOM fields when possible.
        #
        # CycloneDX commonly provides Maven coordinates split across `group`
        # and `name` when `purl` is absent.
        if group and version:
            # Heuristic: group with dots is strongly Maven-like (e.g. org.apache.*).
            if "." in group or group.lower().startswith(("org.", "com.", "net.", "io.")):
                comp["ecosystem"] = "Maven"
                comp["purl"] = f"pkg:maven/{group}/{name_raw}@{version}"
                return comp

        # npm scoped packages may appear as "@scope/name"
        if version and name_raw.startswith("@") and "/" in name_raw:
            scope, pkg = name_raw.split("/", 1)
            # purl spec expects '@' in namespace to be percent-encoded (%40)
            scope_enc = "%40" + scope[1:]
            comp["ecosystem"] = "npm"
            comp["purl"] = f"pkg:npm/{scope_enc}/{pkg}@{version}"
            return comp

        # A small legacy heuristic retained for Linux distro components
        if "glibc" in name:
            comp["ecosystem"] = "Debian"

    return comp


def extract_fixed_versions_osv(v):
    fixed = []
    for aff in v.get("affected", []):
        for r in aff.get("ranges", []):
            for e in r.get("events", []):
                fv = e.get("fixed")
                if fv:
                    fixed.append(fv)
    return sorted(set(fixed))


# ---------- GitHub Advisory (GHSA) ----------


async def github_query_by_components(
    components: list[dict], settings: _MultiSettings
) -> tuple[list[dict], list[dict], list[dict]]:
    # Prefer the per-request override (passed in via dataclasses.replace) before
    # falling back to the environment variable. This avoids mutating os.environ
    # from request handlers under concurrency.
    token = settings.gh_token_override or os.getenv(settings.gh_token_env)
    if not token or not token.strip():
        return [], [{"source": "GITHUB", "error": f"Missing token env: {settings.gh_token_env}"}], []

    headers = {"Authorization": f"bearer {token.strip()}", "User-Agent": settings.http_user_agent}
    url = settings.gh_graphql_url

    pkg_set: set[tuple[str, str]] = set()
    name_for_component: dict[tuple[str, str], set[tuple[str, str | None]]] = {}

    for comp in components:
        purl = comp.get("purl")
        if not purl:
            continue
        parsed = _parse_purl(purl)
        eco = _github_ecosystem_from_purl_type(parsed.get("type"))
        name = parsed.get("name")
        if not eco or not name:
            continue
        key = (eco, name)
        pkg_set.add(key)
        name_for_component.setdefault(key, set()).add((comp.get("name") or name, comp.get("version")))

    if not pkg_set:
        return [], [], []

    gql = """
    query Vulns($ecosystem: SecurityAdvisoryEcosystem!, $name: String!, $first: Int!, $after: String) {
      securityVulnerabilities(ecosystem: $ecosystem, package: $name, first: $first, after: $after) {
        pageInfo { hasNextPage endCursor }
        nodes {
          severity
          updatedAt
          advisory {
            ghsaId
            summary
            description
            publishedAt
            references { url }
            cvss { score vectorString }
            cwes(first: 10) { nodes { cweId name } }
          }
          vulnerableVersionRange
          firstPatchedVersion { identifier }
          package { name ecosystem }
        }
      }
    }
    """

    sem = asyncio.Semaphore(settings.max_concurrency)
    findings: list[dict] = []
    query_errors: list[dict] = []

    async def _run_one(eco: str, pkg: str):
        cursor = None
        page_size = 100
        while True:
            try:
                async with sem:
                    variables: dict[str, Any] = {"ecosystem": eco, "name": pkg, "first": page_size}
                    if cursor:
                        variables["after"] = cursor
                    data = await _async_post(
                        url,
                        json_body={"query": gql, "variables": variables},
                        headers=headers,
                        timeout=settings.nvd_request_timeout_seconds,
                    )
                    if "errors" in data:
                        query_errors.append({"source": "GITHUB", "package": f"{eco}/{pkg}", "error": data["errors"]})
                        return
                    sv = (data.get("data") or {}).get("securityVulnerabilities") or {}
                    nodes = sv.get("nodes") or []
                    page_info = sv.get("pageInfo") or {}
                    for n in nodes:
                        adv = n.get("advisory") or {}
                        score = None
                        vector = None
                        cvss = adv.get("cvss") or {}
                        if isinstance(cvss, dict):
                            score = _safe_score(cvss.get("score"))
                            vector = cvss.get("vectorString")
                        bucket = _sev_bucket(score, settings=settings, severity_text=n.get("severity"))
                        refs = adv.get("references") or []
                        compname, compver = next(iter(name_for_component.get((eco, pkg), {(pkg, None)})))
                        patched = (n.get("firstPatchedVersion") or {}).get("identifier")
                        findings.append(
                            {
                                "vuln_id": adv.get("ghsaId"),
                                "aliases": [adv.get("ghsaId")] if adv.get("ghsaId") else [],
                                "sources": ["GITHUB"],
                                "description": adv.get("summary") or adv.get("description"),
                                "severity": bucket,
                                "score": score,
                                "vector": vector,
                                "attack_vector": _parse_cvss_attack_vector(vector),
                                "cvss_version": None,
                                "published": adv.get("publishedAt"),
                                "references": [r.get("url") for r in refs if r.get("url")],
                                "cwe": extract_cwe_from_ghsa(n),
                                "fixed_versions": [patched] if patched else [],
                                "component_name": compname,
                                "component_version": compver,
                                "cpe": None,
                            }
                        )
                    if not page_info.get("hasNextPage"):
                        break
                    cursor = page_info.get("endCursor")
                    if not cursor:
                        break
            except Exception as exc:
                query_errors.append({"source": "GITHUB", "package": f"{eco}/{pkg}", "error": str(exc)})
                return

    await asyncio.gather(*[_run_one(eco, pkg) for eco, pkg in pkg_set])
    return findings, query_errors, []


# ---------- Multi-source orchestrator ----------


class AnalysisSource(str, Enum):
    NVD = "NVD"
    OSV = "OSV"
    GITHUB = "GITHUB"


async def nvd_query_by_components_async(
    components: list[dict],
    settings: _MultiSettings,
    nvd_api_key: str | None = None,
) -> tuple[list[dict], list[dict], list[dict]]:
    """
    Run NVD CPE lookups for all components concurrently.
    Returns (findings, errors, warnings) — same shape as osv/github counterparts.
    """
    cpe_set: set[str] = set()
    name_by_cpe: dict[str, tuple[str, str | None]] = {}
    for comp in components:
        cpe = comp.get("cpe")
        if cpe:
            cpe_set.add(cpe)
            name_by_cpe[cpe] = (comp.get("name") or "", comp.get("version"))

    if not cpe_set:
        return [], [], []

    api_key = nvd_api_key or resolve_nvd_api_key(settings)
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(settings.max_concurrency)

    def _fetch_one(cpe: str) -> tuple[str, list[dict], str | None]:
        try:
            return cpe, nvd_query_by_cpe(cpe, api_key, settings=settings), None
        except Exception as exc:
            return cpe, [], str(exc)

    async def _bounded(cpe: str):
        async with sem:
            return await loop.run_in_executor(_executor, _fetch_one, cpe)

    results = await asyncio.gather(*[_bounded(cpe) for cpe in sorted(cpe_set)])

    findings: list[dict] = []
    errors: list[dict] = []
    for cpe, raw_list, err in results:
        if err:
            errors.append({"source": "NVD", "cpe": cpe, "error": err})
            continue
        comp_name, comp_ver = name_by_cpe.get(cpe, ("", None))
        for raw in raw_list:
            if isinstance(raw, dict):
                findings.append(_finding_from_raw(raw, cpe, comp_name, comp_ver, settings))

    return findings, errors, []


# Phase 1 (Finding B): canonical implementation now lives in
# `app/services/sources/dedupe.py`. Re-exported here so existing imports
# (`from app.analysis import deduplicate_findings`) keep working.
from .sources.dedupe import deduplicate_findings  # noqa: F401


async def analyze_sbom_multi_source_async(
    sbom_json: str,
    sources: list[str] | None = None,
    settings: _MultiSettings | None = None,
) -> dict:
    """
    Asynchronously analyze an SBOM against the selected sources.
    sources: ["NVD","OSV","GITHUB"]; if None, read env ANALYSIS_SOURCES or default ["NVD"].
    Returns a normalized dict compatible with your pipeline.
    """
    from .pipeline.multi_source import run_multi_source_analysis_async

    return await run_multi_source_analysis_async(sbom_json, sources=sources, settings=settings)


# Phase 5 cleanup note: the sync wrapper `analyze_sbom_multi_source(...)`
# lived here. Its only caller was the now-deleted
# `services.analysis_service.create_auto_report`. Production code uses
# `analyze_sbom_multi_source_async` directly, awaited from async handlers.
# The sync wrapper was removed.


# -----------------------------
# CWE EXTRACTION
# -----------------------------
def extract_cwe_from_nvd(raw: dict[str, Any]) -> list[str]:
    cwes = []
    for w in raw.get("weaknesses", []) or []:
        for d in w.get("description", []) or []:
            val = d.get("value")
            if val and "CWE" in val:
                cwes.append(val)
    return list(set(cwes))


def extract_cwe_from_osv(v: dict[str, Any]) -> list[str]:
    cwes = []
    db = v.get("database_specific") or {}
    cwes.extend(db.get("cwe_ids", []))
    return list(set(cwes))


def extract_cwe_from_ghsa(node: dict[str, Any]) -> list[str]:
    """Extract CWE IDs from a GitHub Advisory securityVulnerabilities node."""
    cwes = []
    adv = node.get("advisory") or {}
    cwe_conn = adv.get("cwes") or {}
    for cwe_node in cwe_conn.get("nodes") or []:
        cwe_id = cwe_node.get("cweId")
        if cwe_id:
            cwes.append(cwe_id)
    return list(set(cwes))
