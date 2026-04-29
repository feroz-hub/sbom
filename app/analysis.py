from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import os
import time
from dataclasses import asdict, dataclass, field, replace
from functools import lru_cache
from typing import Any

import certifi
import requests

# Optional async HTTP client; we fall back to requests in a thread if missing
try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

from .nvd_mirror.settings import (
    NvdMirrorSettings,
    load_mirror_settings_from_env,
)
from .parsing import extract_components  # noqa: F401 — re-exported for callers

# Module-level requests.Session for NVD connection pooling.
#
# SSL: explicitly point at certifi's CA bundle via a PATH STRING.
#   * On macOS, the requests default (``verify=True``) usually finds certifi
#     via the OS/Python bundle lookup, so NVD worked out of the box.
#   * On Windows (venv install, or behind a corporate proxy) that lookup can
#     fail with "unable to get local issuer certificate" on every NVD call.
#     Pointing at ``certifi.where()`` explicitly makes it work on both.
#   * ``requests`` accepts ``verify`` as ``True | False | str``. We pass a
#     path STRING — never an ``ssl.SSLContext`` — because passing an
#     SSLContext here is what caused the original
#     ``TypeError: stat: path should be string, bytes, ... not SSLContext``
#     cascade that broke every NVD request for weeks. A path string cannot
#     retrigger that bug.
_nvd_session = requests.Session()
_nvd_session.verify = certifi.where()
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
    # NVD public rate limits (https://nvd.nist.gov/developers/start-here#RateLimits):
    #   no key  → 5 requests / 30 s  → ≥ 6.0 s between calls
    #   w/ key  → 50 requests / 30 s → ≥ 0.6 s between calls
    nvd_request_delay_with_key_seconds: float = 0.6
    nvd_request_delay_without_key_seconds: float = 6.0
    # Max inflight NVD CPE queries at once. The key allows 10x faster
    # issuance, so we raise concurrency proportionally. Caller can still
    # cap this via ANALYSIS_MAX_CONCURRENCY.
    nvd_concurrency_with_key: int = 10
    nvd_concurrency_without_key: int = 2
    # Fallback: when a component has no usable CPE (neither in the SBOM
    # nor derivable from its PURL), fall back to NVD's free-text
    # `keywordSearch` query — mirroring the standalone nvd_scan.py. The
    # keyword path is noisier than CPE matching, so results are capped
    # per component to limit blast radius.
    nvd_keyword_results_limit: int = 5
    nvd_keyword_fallback_enabled: bool = True
    # Per-component pagination cap. A single NVD CPE query should never
    # return thousands of results — if it does, the CPE is wildcarded
    # and the query is noise. Guards against run-away pagination that
    # can stall the whole phase for 10+ minutes.
    nvd_max_pages_per_query: int = 3
    nvd_max_total_results_per_query: int = 500
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


def _env_bool_top(name: str, default: bool) -> bool:
    """Top-level bool parser. Mirrors ``_env_bool`` later in the file but
    must be defined here so ``get_analysis_settings()`` can call it."""
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


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
        nvd_request_delay_with_key_seconds=_env_float("NVD_REQUEST_DELAY_WITH_KEY_SECONDS", 0.6, minimum=0.0),
        nvd_request_delay_without_key_seconds=_env_float("NVD_REQUEST_DELAY_WITHOUT_KEY_SECONDS", 6.0, minimum=0.0),
        nvd_concurrency_with_key=_env_int("NVD_CONCURRENCY_WITH_KEY", 10, minimum=1),
        nvd_concurrency_without_key=_env_int("NVD_CONCURRENCY_WITHOUT_KEY", 2, minimum=1),
        nvd_keyword_results_limit=_env_int("NVD_KEYWORD_RESULTS_LIMIT", 5, minimum=1),
        nvd_keyword_fallback_enabled=_env_bool_top("NVD_KEYWORD_FALLBACK_ENABLED", True),
        nvd_max_pages_per_query=_env_int("NVD_MAX_PAGES_PER_QUERY", 3, minimum=1),
        nvd_max_total_results_per_query=_env_int("NVD_MAX_TOTAL_RESULTS_PER_QUERY", 500, minimum=1),
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


def _cpe23_virtual_match_wildcard_vendor(cpe: str) -> str | None:
    """cpe:2.3:a:vendor:product:version:... -> wildcard vendor only (NVD virtualMatchString)."""
    parts = cpe.split(":")
    if len(parts) < 6:
        return None
    parts[3] = "*"
    return ":".join(parts)


def _cpe23_virtual_match_wildcard_vendor_product(cpe: str) -> str | None:
    """cpe:2.3:a:vendor:product:version:... -> wildcard vendor and product; version fixed."""
    parts = cpe.split(":")
    if len(parts) < 6:
        return None
    parts[3] = "*"
    parts[4] = "*"
    return ":".join(parts)


def _nvd_fetch_cves_paginated(
    cfg: AnalysisSettings,
    headers: dict,
    search_params: dict[str, str],
    *,
    delay: float,
    log_label: str,
) -> list[dict]:
    """
    Query NVD CVE 2.0 API with either cpeName=... or virtualMatchString=... (not both).
    Paginates through all results.
    """
    params: dict[str, Any] = {
        **search_params,
        "resultsPerPage": cfg.nvd_results_per_page,
        "startIndex": 0,
    }
    out: list[dict] = []
    pages_fetched = 0

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
                    raise RuntimeError(f"NVD query failed for {log_label}: {exc}") from exc
                # On 429 prefer the server's Retry-After — our own linear
                # backoff can undercut it and immediately hit another 429.
                backoff = cfg.nvd_retry_backoff_seconds * (attempt + 1)
                resp = getattr(exc, "response", None)
                if resp is not None and resp.status_code == 429:
                    ra = resp.headers.get("Retry-After")
                    try:
                        if ra is not None:
                            backoff = max(backoff, float(ra))
                    except (TypeError, ValueError):
                        pass
                LOGGER.warning(
                    "NVD request retry %s for %s (sleep %.2fs) due to: %s",
                    attempt + 1, log_label, backoff, exc,
                )
                if backoff > 0:
                    time.sleep(backoff)

        if response is None:
            raise RuntimeError(f"NVD query returned no response for {log_label}")

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", []) or []
        out.extend([item.get("cve") for item in vulnerabilities if item.get("cve")])
        pages_fetched += 1

        total = int(data.get("totalResults", len(out)))
        start = int(params["startIndex"])
        size = int(data.get("resultsPerPage") or params["resultsPerPage"] or 0)
        if size <= 0 or start + size >= total:
            break

        # --- Safety caps -------------------------------------------------
        # Either bound hit = the CPE/match pattern is too broad to be
        # useful. Stop paginating and keep what we already have; this
        # prevents one runaway query from freezing the whole phase.
        if pages_fetched >= cfg.nvd_max_pages_per_query:
            LOGGER.warning(
                "NVD pagination cap hit for %s — fetched %d pages, totalResults=%d, "
                "stopping (cap=%d). Result may be partial.",
                log_label, pages_fetched, total, cfg.nvd_max_pages_per_query,
            )
            break
        if total > cfg.nvd_max_total_results_per_query:
            LOGGER.warning(
                "NVD totalResults=%d exceeds cap=%d for %s — CPE/match pattern is too "
                "broad; stopping after %d results.",
                total, cfg.nvd_max_total_results_per_query, log_label, len(out),
            )
            break

        params["startIndex"] = start + size
        if delay > 0:
            time.sleep(delay)
    return out


def nvd_query_by_cpe(cpe: str, api_key: str | None, settings: AnalysisSettings | None = None) -> list[dict]:
    """
    Exact-CPE lookup only. No virtualMatchString fallbacks.

    Why: the previous wildcard-vendor-and-product fallback
    (``cpe:2.3:a:*:*:<version>:*``) matches every CVE at the given
    version across the entire NVD database — easily tens of thousands
    of rows paginated 2000 at a time with a 0.6s inter-page sleep.
    A single such component could freeze the NVD phase for 10+ minutes
    while producing only noise (CVEs for unrelated products).

    When the SBOM's CPE is wrong, OSV (PURL-based) and GHSA already
    cover the gap. Exact-only keeps the phase bounded.
    """
    cfg = settings or get_analysis_settings()
    if not cpe:
        return []
    headers = {"User-Agent": cfg.http_user_agent}
    if api_key:
        headers["apiKey"] = api_key
    delay = cfg.nvd_request_delay_with_key_seconds if api_key else cfg.nvd_request_delay_without_key_seconds

    return _nvd_fetch_cves_paginated(
        cfg, headers, {"cpeName": cpe}, delay=delay, log_label=f"cpeName={cpe!r}"
    )


def nvd_query_by_keyword(
    name: str,
    version: str | None,
    api_key: str | None,
    settings: AnalysisSettings | None = None,
) -> list[dict]:
    """
    Query NVD CVE 2.0 API using the free-text ``keywordSearch`` parameter.

    Used as a fallback for components that have no usable CPE and whose
    PURL cannot be mapped to a CPE 2.3 string. Mirrors the standalone
    ``nvd_scan.py`` behaviour.

    Because keyword search matches CVE description text (not CPE
    configuration), results are capped at
    ``settings.nvd_keyword_results_limit`` per component to bound noise.
    """
    cfg = settings or get_analysis_settings()
    if not name:
        return []
    stripped_name = name.strip()
    if not stripped_name:
        return []
    stripped_version = (version or "").strip()
    keyword = f"{stripped_name} {stripped_version}".strip() if stripped_version else stripped_name

    headers = {"User-Agent": cfg.http_user_agent}
    if api_key:
        headers["apiKey"] = api_key
    delay = cfg.nvd_request_delay_with_key_seconds if api_key else cfg.nvd_request_delay_without_key_seconds
    limit = max(1, int(cfg.nvd_keyword_results_limit))

    params: dict[str, Any] = {
        "keywordSearch": keyword,
        "resultsPerPage": limit,
        "startIndex": 0,
    }

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
                raise RuntimeError(f"NVD keyword query failed for {keyword!r}: {exc}") from exc
            backoff = cfg.nvd_retry_backoff_seconds * (attempt + 1)
            resp = getattr(exc, "response", None)
            if resp is not None and resp.status_code == 429:
                ra = resp.headers.get("Retry-After")
                try:
                    if ra is not None:
                        backoff = max(backoff, float(ra))
                except (TypeError, ValueError):
                    pass
            LOGGER.warning(
                "NVD keyword retry %s for %r (sleep %.2fs) due to: %s",
                attempt + 1, keyword, backoff, exc,
            )
            if backoff > 0:
                time.sleep(backoff)

    if response is None:
        return []

    data = response.json()
    vulnerabilities = data.get("vulnerabilities", []) or []
    out = [item.get("cve") for item in vulnerabilities if item.get("cve")]
    if delay > 0:
        time.sleep(delay)
    return out[:limit]


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
    vulndb_api_base_url: str = "https://vuldb.com/?api"
    vulndb_api_key_env: str = "VULNDB_API_KEY"
    vulndb_api_version: int = 3
    vulndb_limit: int = 5
    vulndb_details: bool = False
    vulndb_request_timeout_seconds: int = 30
    vulndb_request_delay_seconds: float = 0.0
    vulndb_max_components: int = 100
    max_concurrency: int = 10
    prefer_async_httpx: bool = True
    analysis_sources_env: str = "ANALYSIS_SOURCES"  # e.g., "NVD,OSV,GITHUB,VULNDB"
    # NVD mirror config — env-driven defaults; DB-backed `nvd_settings` row
    # is the runtime source of truth once seeded. See app/nvd_mirror/settings.py.
    mirror: NvdMirrorSettings = field(default_factory=NvdMirrorSettings)


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


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
        vulndb_api_base_url=_env_str("VULNDB_API_BASE_URL", "https://vuldb.com/?api"),
        vulndb_api_key_env=_env_str("VULNDB_API_KEY_ENV", "VULNDB_API_KEY"),
        vulndb_api_version=_env_int("VULNDB_API_VERSION", 3, minimum=1),
        vulndb_limit=_env_int("VULNDB_LIMIT", 5, minimum=1),
        vulndb_details=_env_bool("VULNDB_DETAILS", False),
        vulndb_request_timeout_seconds=_env_int("VULNDB_REQUEST_TIMEOUT_SECONDS", 30, minimum=1),
        vulndb_request_delay_seconds=_env_float("VULNDB_REQUEST_DELAY_SECONDS", 0.0, minimum=0.0),
        vulndb_max_components=_env_int("VULNDB_MAX_COMPONENTS", 100, minimum=1),
        max_concurrency=_env_int("ANALYSIS_MAX_CONCURRENCY", 10, minimum=1),
        prefer_async_httpx=_env_bool("ANALYSIS_PREFER_ASYNC_HTTPX", True),
        analysis_sources_env=_env_str("ANALYSIS_SOURCES_ENV", "ANALYSIS_SOURCES"),
        mirror=load_mirror_settings_from_env(),
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
            async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
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
        ).json(),
    )


async def _async_post(url: str, json_body: dict, headers: dict | None = None, timeout: int = 60):
    if httpx is not None:
        try:
            from .http_client import get_async_http_client

            client = get_async_http_client()
        except RuntimeError:
            async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
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

    # Fallback: some environments see empty `querybatch` results (or hydration
    # yielding zero usable records) without explicit transport errors. When
    # we had at least one purl-based query but ended up with no hydrated vulns,
    # fall back to the per-component `/v1/query` endpoint (ported from the
    # user's standalone osv_scan.py).
    if not hydrated and any((c.get("purl") or "").strip() for c in components):
        try:
            from .sources.osv_fallback import osv_query_via_query_endpoint

            f2, e2, w2 = await osv_query_via_query_endpoint(
                components,
                settings,
                post_json_fn=_async_post,
                best_score_and_vector_fn=_best_score_and_vector_from_osv,
                severity_bucket_fn=_sev_bucket,
                attack_vector_fn=_parse_cvss_attack_vector,
                extract_cwe_fn=extract_cwe_from_osv,
                extract_fixed_versions_fn=extract_fixed_versions_osv,
            )
            if f2:
                findings.extend(f2)
            if e2:
                query_errors.extend(e2)
            if w2:
                query_warnings.extend(w2)
            return findings, query_errors, query_warnings
        except Exception as exc:
            query_errors.append({"source": "OSV", "error": f"Fallback /v1/query failed: {exc}"})

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
            identifiers { type value }
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
                                "aliases": list({
                                    v for v in [
                                        adv.get("ghsaId"),
                                        *[i["value"] for i in (adv.get("identifiers") or []) if i.get("type") in ("CVE", "GHSA")],
                                    ] if v
                                }),
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


async def nvd_query_by_components_async(
    components: list[dict],
    settings: _MultiSettings,
    nvd_api_key: str | None = None,
    lookup_service: Any = None,
) -> tuple[list[dict], list[dict], list[dict]]:
    """
    Run NVD CPE lookups for every component with a CPE — SEQUENTIALLY.

    Why sequential (not fan-out):
        NVD's public rate limit is a *global* token bucket — 50 req / 30 s
        with a key, 5 req / 30 s without. A concurrent fan-out with a
        per-worker sleep violates that ceiling (N workers × 1/sleep req/s),
        which produces a pile of 429 Retry-Afters and stalls the phase.
        One request at a time with a fixed inter-request sleep stays under
        the ceiling by construction: 45 comps × 0.6 s ≈ 27 s with a key.

    Components **without** a CPE are skipped on purpose — OSV and GHSA
    already cover them via PURL, and NVD's keyword-search path is noisy
    and burns rate-limit for low-value results. Before we decide what is
    "without a CPE" we try to **derive one from the PURL**: for example,
    ``pkg:pypi/requests@2.31.0`` becomes
    ``cpe:2.3:a:requests:requests:2.31.0:*:*:*:*:*:*:*``.

    The multi-source orchestrator already augments upstream, but doing it
    here too keeps this function correct when called directly.

    Returns ``(findings, errors, warnings)`` — same shape as osv/github.
    """
    # Best-effort PURL → CPE derivation before the inventory pass. When
    # multi_source already augmented, this is a no-op (components that
    # already have ``cpe`` are passed through unchanged).
    normalized_components, generated_cpe_count = _augment_components_with_cpe(components)

    # CPE inventory + skipped count (preserve insertion order so progress
    # logs map 1:1 to the SBOM input ordering in logs/sbom.log).
    cpe_order: list[str] = []
    seen: set[str] = set()
    name_by_cpe: dict[str, tuple[str, str | None]] = {}
    queried = 0
    skipped = 0
    for comp in normalized_components:
        cpe = comp.get("cpe")
        if cpe:
            queried += 1
            if cpe not in seen:
                seen.add(cpe)
                cpe_order.append(cpe)
                name_by_cpe[cpe] = (comp.get("name") or "", comp.get("version"))
        else:
            skipped += 1
            LOGGER.debug(
                "Skipping NVD for %s@%s: no CPE",
                comp.get("name") or "?",
                comp.get("version") or "?",
            )

    LOGGER.info(
        "NVD: %d queried, %d skipped (no CPE), %d CPEs derived from PURL",
        queried, skipped, generated_cpe_count,
    )

    if not cpe_order:
        return [], [], []

    api_key = nvd_api_key or resolve_nvd_api_key(settings)

    cfg_base = get_analysis_settings()
    sleep_s = (
        cfg_base.nvd_request_delay_with_key_seconds
        if api_key
        else cfg_base.nvd_request_delay_without_key_seconds
    )

    # Tighter per-request budget for the sequential path: long timeouts and
    # multi-attempt backoffs just pile on top of NVD's 429 Retry-After and
    # stretch the phase out. Cap timeout at 20s and allow at most one retry.
    cfg = replace(
        cfg_base,
        nvd_request_timeout_seconds=min(cfg_base.nvd_request_timeout_seconds, 20),
        nvd_max_retries=min(cfg_base.nvd_max_retries, 1),
    )

    total = len(cpe_order)
    LOGGER.info(
        "NVD client: api_key=%s, sleep=%.2fs, sequential, cpe_targets=%d",
        bool(api_key),
        sleep_s,
        total,
    )

    findings: list[dict] = []
    errors: list[dict] = []
    succeeded = 0

    loop = asyncio.get_running_loop()
    # Per-CPE callable: when a lookup_service is wired (R6: NvdSource +
    # mirror facade), route through it; otherwise hit live NVD directly.
    # Both have the same `(cpe, api_key, settings) -> list[dict]` shape,
    # so the executor call is a single drop-in substitution.
    query_callable = lookup_service if lookup_service is not None else nvd_query_by_cpe
    for idx, cpe in enumerate(cpe_order, 1):
        try:
            # Run sync requests.Session call in the shared executor so we
            # do not block the event loop, but serialize the submissions.
            raw_list = await loop.run_in_executor(
                _executor, query_callable, cpe, api_key, cfg
            )
        except Exception as exc:
            LOGGER.warning(
                "NVD CPE query failed — cpe=%r error=%s: %s",
                cpe, type(exc).__name__, exc,
            )
            errors.append(
                {"source": "NVD", "cpe": cpe, "error": f"{type(exc).__name__}: {exc}"}
            )
        else:
            succeeded += 1
            comp_name, comp_ver = name_by_cpe.get(cpe, ("", None))
            for raw in raw_list:
                if isinstance(raw, dict):
                    findings.append(
                        _finding_from_raw(raw, cpe, comp_name, comp_ver, settings)
                    )

        if idx % 5 == 0 or idx == total:
            LOGGER.info("NVD progress: %d/%d", idx, total)

        # Inter-request sleep (only between components, not after the last).
        if idx < total and sleep_s > 0:
            await asyncio.sleep(sleep_s)

    LOGGER.info(
        "NVD phase complete: %d/%d succeeded (findings=%d errors=%d skipped_no_cpe=%d)",
        succeeded, total, len(findings), len(errors), skipped,
    )
    return findings, errors, []


# Phase 1 (Finding B): canonical implementation now lives in
# `app/services/sources/dedupe.py`. Re-exported here so existing imports
# (`from app.analysis import deduplicate_findings`) keep working.
from .sources.dedupe import deduplicate_findings  # noqa: F401


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
