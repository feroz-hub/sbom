from __future__ import annotations

import asyncio
import concurrent.futures
import json
import logging
import os
import time
from dataclasses import dataclass, field, fields, asdict, replace
from enum import Enum
from functools import lru_cache
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, unquote

import requests

# Optional async HTTP client; we fall back to requests in a thread if missing
try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

LOGGER = logging.getLogger(__name__)

# ============================================================
# CVE MODEL (kept inline for self-contained file)
# ============================================================

@dataclass
class CVSSv2Data:
    version: str
    vectorString: str
    baseScore: float
    accessVector: Optional[str] = None
    accessComplexity: Optional[str] = None
    authentication: Optional[str] = None
    confidentialityImpact: Optional[str] = None
    integrityImpact: Optional[str] = None
    availabilityImpact: Optional[str] = None


@dataclass
class CVSSv2Metric:
    source: str
    type: str
    cvssData: CVSSv2Data
    baseSeverity: Optional[str] = None
    exploitabilityScore: Optional[float] = None
    impactScore: Optional[float] = None
    acInsufInfo: Optional[bool] = None
    obtainAllPrivilege: Optional[bool] = None
    obtainUserPrivilege: Optional[bool] = None
    obtainOtherPrivilege: Optional[bool] = None
    userInteractionRequired: Optional[bool] = None


@dataclass
class Metrics:
    cvssMetricV2: List[CVSSv2Metric] = field(default_factory=list)


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
    description: List[WeaknessDescription] = field(default_factory=list)


@dataclass
class CPEMatch:
    vulnerable: bool
    criteria: str
    matchCriteriaId: Optional[str] = None
    versionStartIncluding: Optional[str] = None
    versionStartExcluding: Optional[str] = None
    versionEndIncluding: Optional[str] = None
    versionEndExcluding: Optional[str] = None


@dataclass
class ConfigNode:
    operator: str  # "OR" / "AND"
    negate: bool
    cpeMatch: List[CPEMatch] = field(default_factory=list)


@dataclass
class Configuration:
    nodes: List[ConfigNode] = field(default_factory=list)


@dataclass
class Reference:
    url: str
    source: Optional[str] = None


@dataclass
class CVERecord:
    id: str
    sourceIdentifier: Optional[str] = None
    published: Optional[str] = None
    lastModified: Optional[str] = None
    vulnStatus: Optional[str] = None
    cveTags: List[str] = field(default_factory=list)
    descriptions: List[LangDescription] = field(default_factory=list)
    metrics: Optional[Metrics] = None
    weaknesses: List[WeaknessItem] = field(default_factory=list)
    configurations: List[Configuration] = field(default_factory=list)
    references: List[Reference] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CVERecord":
        descriptions = [LangDescription(**d) for d in data.get("descriptions", [])]

        metrics = None
        metrics_dict = data.get("metrics")
        if metrics_dict:
            v2 = []
            for m in metrics_dict.get("cvssMetricV2", []) or []:
                cvss_data = CVSSv2Data(**m["cvssData"])
                v2.append(CVSSv2Metric(cvssData=cvss_data, **{k: v for k, v in m.items() if k != "cvssData"}))
            metrics = Metrics(cvssMetricV2=v2)

        weaknesses: List[WeaknessItem] = []
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
    def primary_english_description(self) -> Optional[str]:
        for d in self.descriptions:
            if d.lang and d.lang.lower().startswith("en"):
                return d.value
        return self.descriptions[0].value if self.descriptions else None

    def cvss_v2_base(self) -> Optional[float]:
        if not self.metrics or not self.metrics.cvssMetricV2:
            return None
        primary = next((m for m in self.metrics.cvssMetricV2 if (m.type or "").lower() == "primary"), None)
        return (primary or self.metrics.cvssMetricV2[0]).cvssData.baseScore


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


def _norm(s: Optional[str]) -> Optional[str]:
    return s.strip() if isinstance(s, str) and s.strip() else None


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


def resolve_nvd_api_key(settings: Optional[AnalysisSettings] = None) -> Optional[str]:
    cfg = settings or get_analysis_settings()
    key = os.getenv(cfg.nvd_api_key_env)
    if key and key.strip():
        return key.strip()
    return None


# ============================================================
# SBOM parsing: CycloneDX / SPDX
# ============================================================

def _parse_cyclonedx(doc: Dict) -> List[Dict]:
    comps = []
    for c in doc.get("components", []) or []:
        comps.append(
            {
                "name": _norm(c.get("name")),
                "version": _norm(c.get("version")),
                "type": _norm(c.get("type")),
                "group": _norm(c.get("group")),
                "supplier": _norm((c.get("supplier") or {}).get("name")) if isinstance(c.get("supplier"), dict) else _norm(c.get("supplier")),
                "scope": _norm(c.get("scope")),
                "purl": _norm(c.get("purl")),
                "cpe": _norm(c.get("cpe")),
                "bom_ref": _norm(c.get("bom-ref") or c.get("bomRef")),
            }
        )
    return comps


def _parse_spdx(doc: Dict) -> List[Dict]:
    comps = []
    # SPDX 2.x "packages"
    for pkg in doc.get("packages", []) or []:
        purl = None
        cpe = None
        for ref in (pkg.get("externalRefs") or []):
            rtype = (ref.get("referenceType") or "").lower()
            if rtype == "purl":
                purl = _norm(ref.get("referenceLocator"))
            if "cpe" in rtype:
                cpe = _norm(ref.get("referenceLocator"))
        supplier = None
        supplier_info = pkg.get("supplier")
        if isinstance(supplier_info, str):
            supplier = _norm(supplier_info)
        comps.append(
            {
                "name": _norm(pkg.get("name")),
                "version": _norm(pkg.get("versionInfo")),
                "type": "library",
                "group": None,
                "supplier": supplier,
                "scope": None,
                "purl": purl,
                "cpe": cpe,
                "bom_ref": _norm(pkg.get("SPDXID")),
            }
        )
    # SPDX-Lite or other representations
    for obj in doc.get("elements", []) or []:
        if obj.get("type") == "software:package":
            comps.append(
                {
                    "name": _norm(obj.get("name")),
                    "version": _norm(obj.get("version")),
                    "type": "library",
                    "group": None,
                    "supplier": None,
                    "scope": None,
                    "purl": _norm(obj.get("packageUrl") or obj.get("packageURL")),
                    "cpe": None,
                    "bom_ref": _norm(obj.get("id") or obj.get("spdx-id")),
                }
            )
    return comps


def extract_components(sbom_json: Any) -> List[Dict]:
    """Accept SBOM as JSON string or already-parsed dict."""
    if isinstance(sbom_json, dict):
        doc = sbom_json
    else:
        doc = json.loads(sbom_json)
    if doc.get("bomFormat") == "CycloneDX":
        return _parse_cyclonedx(doc)
    if doc.get("spdxVersion") or doc.get("SPDXID"):
        return _parse_spdx(doc)
    if "components" in doc:  # best-effort CycloneDX-like
        return _parse_cyclonedx(doc)
    raise ValueError("Unsupported SBOM format (expect CycloneDX or SPDX)")


# ============================================================
# CVSS helpers
# ============================================================

def _safe_score(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _extract_best_cvss(metrics: Dict[str, Any]) -> Tuple[Optional[float], Optional[str], Optional[str]]:
    if not isinstance(metrics, dict):
        return None, None, None
    metric_keys = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
    for key in metric_keys:
        entries = metrics.get(key) or []
        if not entries:
            continue
        primary = next((m for m in entries if str((m or {}).get("type", "")).lower() == "primary"), entries[0])
        cvss_data = (primary or {}).get("cvssData") or {}
        score = _safe_score(cvss_data.get("baseScore"))
        vector = cvss_data.get("vectorString")
        severity = (primary or {}).get("baseSeverity") or cvss_data.get("baseSeverity")
        return score, vector, severity
    return None, None, None


def _sev_bucket(score: Optional[float], settings: AnalysisSettings, severity_text: Optional[str] = None) -> str:
    if score is not None:
        if score >= settings.cvss_critical_threshold:
            return "CRITICAL"
        if score >= settings.cvss_high_threshold:
            return "HIGH"
        if score >= settings.cvss_medium_threshold:
            return "MEDIUM"
        return "LOW"
    if severity_text:
        text = severity_text.strip().upper()
        if text in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            return text
    return "UNKNOWN"


# ============================================================
# Robust PURL parsing (Option A requires this)
# ============================================================

def _parse_purl(purl: str) -> dict:
    """
    Minimal purl parser per spec:
      pkg:<type>/<namespace>/<name>@<version>?<qualifiers>#<subpath>
    We ignore subpath; percent-decode namespace/name; keep case for names where relevant.
    """
    if not purl or not purl.startswith("pkg:"):
        return {}
    rest = purl[4:]

    # Remove subpath if present
    if "#" in rest:
        rest, _sub = rest.split("#", 1)

    # Split query
    qualifiers: Dict[str, str] = {}
    if "?" in rest:
        rest, q = rest.split("?", 1)
        qualifiers = {k: v[0] for k, v in parse_qs(q, keep_blank_values=True).items()}

    # Separate version (last '@' is version separator)
    version = None
    if "@" in rest:
        rest, version = rest.rsplit("@", 1)
        version = unquote(version) if version else None
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

    return {"type": ptype, "namespace": namespace, "name": name, "version": version, "qualifiers": qualifiers}


def _slug(s: Optional[str]) -> Optional[str]:
    """
    Sanitize vendor/product tokens for CPE (lowercase, allowed chars).
    """
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


# ============================================================
# Heuristic CPE (2.3) generation from PURL (Option A)
# ============================================================

def _cpe23_from_purl(purl: str, version_override: Optional[str] = None) -> Optional[str]:
    """
    Best-effort mapping of purl -> CPE 2.3.
    part: 'a' (application)
    vendor/product heuristics by ecosystem; version from purl or version_override.
    """
    parsed = _parse_purl(purl)
    if not parsed:
        return None

    ptype = parsed.get("type")
    namespace = parsed.get("namespace") or ""
    name = parsed.get("name") or ""
    version = parsed.get("version") or version_override

    vnd = None
    prd = None

    # Ecosystem-specific mappings
    if ptype in {"pypi"}:
        # PyPI has no organization namespace; use name as vendor+product
        vnd = _slug(name)
        prd = _slug(name)

    elif ptype in {"npm"}:
        # npm: namespace is '@scope' (percent-decoded already)
        scope = namespace.split("/")[-1] if namespace else None
        if scope and scope.startswith("@"):
            scope = scope[1:]
        vnd = _slug(scope or name)
        prd = _slug(name)

    elif ptype in {"maven"}:
        # Maven: namespace = groupId, name = artifactId
        group = namespace or ""
        # vendor = last segment of groupId (e.g., org.apache.logging.log4j -> log4j)
        vnd = _slug(group.split(".")[-1] if group else name)
        prd = _slug(name)

    elif ptype in {"golang", "go"}:
        # Go: namespace name often like 'github.com/user', name='repo'
        # vendor = user/org if present; else first host segment
        if namespace:
            segs = namespace.split("/")
            vnd = _slug(segs[-1] if len(segs) >= 2 else segs[0])
        else:
            vnd = _slug(name)
        prd = _slug(name)

    elif ptype in {"rubygems", "gem"}:
        vnd = _slug(name)
        prd = _slug(name)

    elif ptype in {"nuget"}:
        vnd = _slug(name)
        prd = _slug(name)

    elif ptype in {"composer"}:
        # Composer: namespace is vendor; name is package
        vnd = _slug(namespace.split("/")[-1] if namespace else name)
        prd = _slug(name)

    elif ptype in {"cargo", "crates"}:
        vnd = _slug(namespace.split("/")[-1] if namespace else name)
        prd = _slug(name)

    else:
        # Fallback
        vnd = _slug(namespace.split("/")[-1] if namespace else name)
        prd = _slug(name)

    if not vnd or not prd:
        return None

    # Use version from purl or override; sanitize for CPE (alphanumeric, ., -, _)
    ver = version or "*"
    if ver != "*":
        ver = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in ver).strip("._-") or "*"
    # CPE 2.3 template: cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>
    cpe = f"cpe:2.3:a:{vnd}:{prd}:{ver}:*:*:*:*:*:*:*"
    return cpe


def _augment_components_with_cpe(components: List[dict]) -> Tuple[List[dict], int]:
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

def nvd_query_by_cpe(cpe: str, api_key: Optional[str], settings: Optional[AnalysisSettings] = None) -> List[Dict]:
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
    out: List[Dict] = []

    while True:
        response = None
        for attempt in range(cfg.nvd_max_retries + 1):
            try:
                response = requests.get(
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
    raw: Dict[str, Any],
    cpe: Optional[str],
    component_name: str,
    component_version: Optional[str],
    settings: AnalysisSettings,
) -> Dict[str, Any]:
    try:
        record = CVERecord.from_dict(raw)
        score = record.cvss_v2_base()
        metric_score, metric_vector, metric_severity = _extract_best_cvss(raw.get("metrics") or {})
        if score is None:
            score = metric_score
        severity = _sev_bucket(score, settings=settings, severity_text=metric_severity)
        vector = (
            record.metrics.cvssMetricV2[0].cvssData.vectorString
            if record.metrics and record.metrics.cvssMetricV2
            else metric_vector
        )
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
        "published": published,
        "references": [r.get("url") for r in raw.get("references", [])],
        "cwe": extract_cwe_from_nvd(raw),
        "fixed_versions": [],
        "component_name": component_name,
        "component_version": component_version,
        "cpe": cpe,
    }


def analyze_sbom_against_nvd(sbom_json: str, nvd_api_key: Optional[str], settings: Optional[AnalysisSettings] = None) -> Dict:
    """
    Legacy single-source analyzer (NVD by CPE).
    Now benefits from best-effort CPE generation from purl when CPEs are absent.
    """
    cfg = settings or get_analysis_settings()
    components = extract_components(sbom_json)
    components, generated_cpe_count = _augment_components_with_cpe(components)

    cpe_set: Set[str] = set()
    comp_by_cpe: Dict[str, Tuple[str, Optional[str]]] = {}
    for comp in components:
        cpe = comp.get("cpe")
        if cpe:
            cpe_set.add(cpe)
            comp_by_cpe[cpe] = (comp.get("name") or "", comp.get("version"))

    findings: List[Dict] = []
    query_errors: List[Dict] = []
    query_warnings: List[Dict] = []

    for cpe in sorted(cpe_set):
        try:
            cve_objs = nvd_query_by_cpe(cpe, nvd_api_key, settings=cfg)
        except Exception as exc:
            query_errors.append({"source": "NVD", "cpe": cpe, "error": str(exc)})
            continue

        if cfg.analysis_max_findings_per_cpe > 0 and len(cve_objs) > cfg.analysis_max_findings_per_cpe:
            query_warnings.append(
                {
                    "source": "NVD",
                    "cpe": cpe,
                    "warning": "Per-CPE findings limit applied",
                    "returned": len(cve_objs),
                    "used": cfg.analysis_max_findings_per_cpe,
                }
            )
            cve_objs = cve_objs[: cfg.analysis_max_findings_per_cpe]

        comp_name, comp_ver = comp_by_cpe.get(cpe, ("", None))
        for raw in (cve_objs or []):
            if isinstance(raw, dict):
                findings.append(
                    _finding_from_raw(
                        raw=raw,
                        cpe=cpe,
                        component_name=comp_name,
                        component_version=comp_ver,
                        settings=cfg,
                    )
                )

        if cfg.analysis_max_findings_total > 0 and len(findings) >= cfg.analysis_max_findings_total:
            query_warnings.append({"source": "NVD", "warning": "Global findings limit applied", "used": cfg.analysis_max_findings_total})
            findings = findings[: cfg.analysis_max_findings_total]
            break

    # Dedup by (vuln_id, cpe)
    deduped = {}
    for f in findings:
        key = (f.get("vuln_id"), f.get("cpe"))
        deduped[key] = f
    findings = list(deduped.values())

    buckets = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for f in findings:
        sev = str(f.get("severity", "UNKNOWN")).upper()
        buckets[sev if sev in buckets else "UNKNOWN"] += 1

    details: Dict[str, Any] = {
        "total_components": len(components),
        "components_with_cpe": len({c.get("cpe") for c in components if c.get("cpe")}),
        "total_findings": len(findings),
        "critical": buckets["CRITICAL"],
        "high": buckets["HIGH"],
        "medium": buckets["MEDIUM"],
        "low": buckets["LOW"],
        "unknown": buckets["UNKNOWN"],
        "query_errors": query_errors,
        "query_warnings": query_warnings,
        "findings": findings,
        "analysis_metadata": {
            "source": "NVD",
            "generated_cpe_count": generated_cpe_count,
            "nvd_api_base_url": cfg.nvd_api_base_url,
            "nvd_results_per_page": cfg.nvd_results_per_page,
            "nvd_request_timeout_seconds": cfg.nvd_request_timeout_seconds,
            "nvd_max_retries": cfg.nvd_max_retries,
            "cvss_thresholds": {
                "critical": cfg.cvss_critical_threshold,
                "high": cfg.cvss_high_threshold,
                "medium": cfg.cvss_medium_threshold,
            },
            "analysis_max_findings_per_cpe": cfg.analysis_max_findings_per_cpe,
            "analysis_max_findings_total": cfg.analysis_max_findings_total,
        },
    }
    if not cpe_set:
        details["message"] = "No CPE values found (original or generated). NVD correlation skipped."
    elif generated_cpe_count > 0:
        details["note"] = f"Generated {generated_cpe_count} CPEs from package URLs to query NVD."
    return details


# ============================================================
# Multi-source (async) with OSV and GitHub Advisory
# ============================================================

@dataclass(frozen=True)
class _MultiSettings(AnalysisSettings):
    gh_graphql_url: str = "https://api.github.com/graphql"
    gh_token_env: str = "GITHUB_TOKEN"
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


def _env_list(name: str, default: List[str]) -> List[str]:
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


async def _async_get(url: str, headers: Optional[dict] = None, params: Optional[dict] = None, timeout: int = 60):
    if httpx is not None:
        async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
            r = await client.get(url, params=params)
            r.raise_for_status()
            return r.json()
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        _executor, lambda: requests.get(url, headers=headers, params=params, timeout=timeout).json()
    )


async def _async_post(url: str, json_body: dict, headers: Optional[dict] = None, timeout: int = 60):
    if httpx is not None:
        async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
            r = await client.post(url, json=json_body)
            r.raise_for_status()
            return r.json()
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        _executor, lambda: requests.post(url, json=json_body, headers=headers, timeout=timeout).json()
    )


# -----------------------
# Ecosystem helpers
# -----------------------

def _github_ecosystem_from_purl_type(ptype: str) -> Optional[str]:
    """
    GitHub Advisory GraphQL ecosystems.
    """
    mapping = {
        "npm": "NPM",
        "pypi": "PIP",       # GH uses PIP for PyPI
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

def _best_score_and_vector_from_osv(v: dict) -> Tuple[Optional[float], Optional[str], Optional[str]]:
    score = None
    vector = None
    severity_txt = None
    for sev in v.get("severity") or []:
        t = (sev.get("type") or "").upper()
        if t in {"CVSS_V3", "CVSS_V4"}:
            try:
                s = float(sev.get("score"))
                if score is None or s > score:
                    score = s
                    severity_txt = None
            except Exception:
                continue
    if score is None:
        try:
            database_specific = v.get("database_specific") or {}
            cvss = database_specific.get("cvss") or {}
            s = cvss.get("score")
            if s is not None:
                score = float(s)
                vector = cvss.get("vectorString") or cvss.get("vector")
        except Exception:
            pass
    return score, vector, severity_txt


async def osv_query_by_components(components: List[dict], settings: _MultiSettings) -> Tuple[List[dict], List[dict], List[dict]]:
    if not components:
        return [], [], []
    base = settings.osv_api_base_url.rstrip("/")
    batch_url = f"{base}/v1/querybatch"
    get_url = f"{base}/v1/vulns"

    queries: List[dict] = []
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
            parsed = _parse_purl(purl) if purl else {}
            eco = (parsed.get("type") or "").capitalize() if parsed else None
            pkg = {"name": name}
            if eco:
                pkg["ecosystem"] = eco
            q = {"package": pkg}
            if version:
                q["version"] = version

        if q:
            queries.append(q)

    findings: List[dict] = []
    query_errors: List[dict] = []
    query_warnings: List[dict] = []

    if not queries:
        return findings, query_errors, query_warnings

    batches = [queries[i: i + settings.osv_results_per_batch] for i in range(0, len(queries), settings.osv_results_per_batch)]

    async def _fetch_batch(batch: List[dict]) -> List[str]:
        try:
            res = await _async_post(batch_url, json_body={"queries": batch}, timeout=settings.nvd_request_timeout_seconds)
            ids: List[str] = []
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

    async def _fetch_vuln(vid: str) -> Optional[dict]:
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

        findings.append(
            {
                "vuln_id": v.get("id"),
                "aliases": v.get("aliases", []),
                "sources": ["OSV"],
                "description": summary,
                "severity": bucket,
                "score": score,
                "vector": vector,
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
    name = comp.get("name", "").lower()
    version = comp.get("version")

    # Simple heuristic mapping
    if "apache" in name or "commons" in name or "jena" in name:
        ecosystem = "Maven"
        purl = f"pkg:maven/{name.replace(' ', '')}/{name}@{version}"
    elif "glibc" in name:
        ecosystem = "Debian"
        purl = None
    else:
        ecosystem = None
        purl = None

    comp["ecosystem"] = ecosystem
    comp["purl"] = purl

    return comp

def extract_fixed_versions_osv(v):
    fixed = []
    for aff in v.get("affected", []):
        for r in aff.get("ranges", []):
            for e in r.get("events", []):
                if "fixed" in e:
                    fixed.append(e["fixed"])
    return list(set(fixed))

# ---------- GitHub Advisory (GHSA) ----------

async def github_query_by_components(components: List[dict], settings: _MultiSettings) -> Tuple[List[dict], List[dict], List[dict]]:
    token = os.getenv(settings.gh_token_env)
    if not token or not token.strip():
        return [], [{"source": "GITHUB", "error": f"Missing token env: {settings.gh_token_env}"}], []

    headers = {"Authorization": f"bearer {token.strip()}", "User-Agent": settings.http_user_agent}
    url = settings.gh_graphql_url

    pkg_set: Set[Tuple[str, str]] = set()
    name_for_component: Dict[Tuple[str, str], Set[Tuple[str, Optional[str]]]] = {}

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
    query Vulns($ecosystem: SecurityAdvisoryEcosystem!, $name: String!, $first: Int!) {
      securityVulnerabilities(ecosystem: $ecosystem, package: $name, first: $first) {
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
          }
          vulnerableVersionRange
          firstPatchedVersion { identifier }
          package { name ecosystem }
        }
      }
    }
    """

    sem = asyncio.Semaphore(settings.max_concurrency)
    findings: List[dict] = []
    query_errors: List[dict] = []

    async def _run_one(eco: str, pkg: str):
        try:
            async with sem:
                data = await _async_post(url, json_body={"query": gql, "variables": {"ecosystem": eco, "name": pkg, "first": 100}}, headers=headers, timeout=settings.nvd_request_timeout_seconds)
                if "errors" in data:
                    query_errors.append({"source": "GITHUB", "package": f"{eco}/{pkg}", "error": data["errors"]})
                    return
                nodes = ((data.get("data") or {}).get("securityVulnerabilities") or {}).get("nodes") or []
                for n in nodes:
                    adv = n.get("advisory") or {}
                    score = None
                    vector = None
                    cvss = adv.get("cvss") or {}
                    if isinstance(cvss, dict):
                        score = _safe_score(cvss.get("score"))
                        vector = cvss.get("vectorString")
                    bucket = _sev_bucket(score, settings=settings, severity_text=n.get("severity"))
                    ref_url = None
                    refs = adv.get("references") or []
                    if refs:
                        ref_url = refs[0].get("url")
                    compname, compver = next(iter(name_for_component.get((eco, pkg), {(pkg, None)})))
                    findings.append(
                        {
                            "vuln_id": adv.get("ghsaId"),
                            "aliases": [adv.get("ghsaId")],
                            "sources": ["GITHUB"],
                            "description": adv.get("summary") or adv.get("description"),
                            "severity": bucket,
                            "score": score,
                            "vector": vector,
                            "published": adv.get("publishedAt"),
                            "references": [r.get("url") for r in refs if r.get("url")],
                            "cwe": extract_cwe_from_ghsa(n),
                            "fixed_versions": [n.get("firstPatchedVersion", {}).get("identifier")],
                            "component_name": compname,
                            "component_version": compver,
                            "cpe": None,
                        }
                    )
        except Exception as exc:
            query_errors.append({"source": "GITHUB", "package": f"{eco}/{pkg}", "error": str(exc)})

    await asyncio.gather(*[_run_one(eco, pkg) for eco, pkg in pkg_set])
    return findings, query_errors, []


# ---------- Multi-source orchestrator ----------

class AnalysisSource(str, Enum):
    NVD = "NVD"
    OSV = "OSV"
    GITHUB = "GITHUB"


async def analyze_sbom_multi_source_async(
    sbom_json: str,
    sources: Optional[List[str]] = None,
    settings: Optional[_MultiSettings] = None,
) -> dict:
    """
    Asynchronously analyze an SBOM against the selected sources.
    sources: ["NVD","OSV","GITHUB"]; if None, read env ANALYSIS_SOURCES or default ["NVD"].
    Returns a normalized dict compatible with your pipeline.
    """
    cfg = settings or get_analysis_settings_multi()
    components = extract_components(sbom_json)
    components = [enrich_component_for_osv(c) for c in components]
    # Augment components with generated CPEs (Option A)
    components_w_cpe, generated_cpe_count = _augment_components_with_cpe(components)

    # Resolve selected sources
    default_sources = _env_list(cfg.analysis_sources_env, ["NVD"])
    selected = [s.strip().upper() for s in (sources or default_sources)]
    selected_enum: Set[AnalysisSource] = set()
    for s in selected:
        try:
            selected_enum.add(AnalysisSource[s])
        except KeyError:
            LOGGER.warning("Unknown analysis source ignored: %s", s)

    # If no CPEs at all even after generation, skip NVD
    if not any(c.get("cpe") for c in components_w_cpe):
        if AnalysisSource.NVD in selected_enum:
            selected_enum.remove(AnalysisSource.NVD)

    all_findings: List[dict] = []
    query_errors: List[dict] = []
    query_warnings: List[dict] = []

    # NVD in parallel across CPEs (threaded)
    async def _nvd():
        nonlocal all_findings, query_errors
        cpe_set: Set[str] = set()
        name_by_cpe: Dict[str, Tuple[str, Optional[str]]] = {}
        for comp in components_w_cpe:
            cpe = comp.get("cpe")
            if cpe:
                cpe_set.add(cpe)
                name_by_cpe[cpe] = (comp.get("name") or "", comp.get("version"))
        if not cpe_set:
            return
        loop = asyncio.get_running_loop()

        def _fetch_one(cpe: str) -> Tuple[str, List[dict], Optional[str]]:
            try:
                cve_objs = nvd_query_by_cpe(cpe, resolve_nvd_api_key(cfg), settings=cfg)
                return cpe, cve_objs, None
            except Exception as exc:
                return cpe, [], str(exc)

        tasks = [loop.run_in_executor(_executor, _fetch_one, cpe) for cpe in sorted(cpe_set)]
        results = await asyncio.gather(*tasks)
        for cpe, raw_list, err in results:
            if err:
                query_errors.append({"source": "NVD", "cpe": cpe, "error": err})
                continue
            comp_name, comp_ver = name_by_cpe.get(cpe, ("", None))
            for raw in raw_list:
                if not isinstance(raw, dict):
                    continue
                all_findings.append(
                    _finding_from_raw(
                        raw=raw,
                        cpe=cpe,
                        component_name=comp_name,
                        component_version=comp_ver,
                        settings=cfg,
                    )
                )

    async def _osv():
        nonlocal all_findings, query_errors, query_warnings
        f, e, w = await osv_query_by_components(components, cfg)
        all_findings.extend(f)
        query_errors.extend(e)
        query_warnings.extend(w)

    async def _gh():
        nonlocal all_findings, query_errors
        f, e, _w = await github_query_by_components(components, cfg)
        all_findings.extend(f)
        query_errors.extend(e)

    coros = []
    if AnalysisSource.NVD in selected_enum:
        coros.append(_nvd())
    if AnalysisSource.OSV in selected_enum:
        coros.append(_osv())
    if AnalysisSource.GITHUB in selected_enum:
        coros.append(_gh())
    if coros:
        await asyncio.gather(*coros)

    # Deduplicate across sources by (vuln_id, cpe or component_name)
    for f in all_findings:
        def _merge_key(v):
            if v.get("vuln_id"):
                return v["vuln_id"]
            if v.get("aliases"):
                return tuple(sorted(v["aliases"]))
        return v.get("component_name")
    
    merged = {}

    for v in all_findings:
        key = _merge_key(v)

        if key not in merged:
            merged[key] = v
        else:
            existing = merged[key]

        # merge sources
            existing["sources"] = list(set(existing["sources"] + v["sources"]))

        # merge aliases
            existing["aliases"] = list(set(existing.get("aliases", []) + v.get("aliases", [])))

        # merge CWE
            existing["cwe"] = list(set(existing.get("cwe", []) + v.get("cwe", [])))

        # merge references
            existing["references"] = list(set(existing.get("references", []) + v.get("references", [])))

        # severity upgrade
            existing["severity"] = max(
                existing["severity"],
                v["severity"],
                key=lambda x: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(x) if x in ["LOW","MEDIUM","HIGH","CRITICAL"] else -1
            )

    findings = list(merged.values())

    buckets = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for f in findings:
        sev = str((f or {}).get("severity", "UNKNOWN")).upper()
        buckets[sev if sev in buckets else "UNKNOWN"] += 1

    details: Dict[str, Any] = {
        "total_components": len(components),
        "components_with_cpe": len({c.get("cpe") for c in components_w_cpe if c.get("cpe")}),
        "total_findings": len(findings),
        "critical": buckets["CRITICAL"],
        "high": buckets["HIGH"],
        "medium": buckets["MEDIUM"],
        "low": buckets["LOW"],
        "unknown": buckets["UNKNOWN"],
        "query_errors": query_errors,
        "query_warnings": query_warnings,
        "findings": findings,
        "analysis_metadata": {
            "sources": sorted([s.value for s in selected_enum]),
            "generated_cpe_count": generated_cpe_count,
            "nvd_api_base_url": getattr(cfg, "nvd_api_base_url", None),
            "osv_api_base_url": getattr(cfg, "osv_api_base_url", None),
            "gh_graphql_url": getattr(cfg, "gh_graphql_url", None),
        },
    }
    if generated_cpe_count > 0:
        details["note"] = f"Generated {generated_cpe_count} CPEs from package URLs to enable NVD correlation."
    if AnalysisSource.NVD in selected_enum and details["components_with_cpe"] == 0:
        details["message"] = "No CPE values could be generated; NVD correlation not executed."
    return details


def analyze_sbom_multi_source(
    sbom_json: str,
    sources: Optional[List[str]] = None,
    settings: Optional[_MultiSettings] = None,
) -> dict:
    try:
        return asyncio.run(analyze_sbom_multi_source_async(sbom_json, sources=sources, settings=settings))
    except RuntimeError:
        # If already inside an event loop, create a new loop in a worker
        def _run_in_thread() -> dict:
            return asyncio.run(analyze_sbom_multi_source_async(sbom_json, sources=sources, settings=settings))
        return concurrent.futures.ThreadPoolExecutor(max_workers=1).submit(_run_in_thread).result()

# -----------------------------
# CWE EXTRACTION
# -----------------------------
def extract_cwe_from_nvd(raw: Dict[str, Any]) -> List[str]:
    cwes = []
    for w in raw.get("weaknesses", []) or []:
        for d in w.get("description", []) or []:
            val = d.get("value")
            if val and "CWE" in val:
                cwes.append(val)
    return list(set(cwes))


def extract_cwe_from_osv(v: Dict[str, Any]) -> List[str]:
    cwes = []
    db = v.get("database_specific") or {}
    cwes.extend(db.get("cwe_ids", []))
    return list(set(cwes))


def extract_cwe_from_ghsa(node: Dict[str, Any]) -> List[str]:
    # GHSA does not always provide CWE → fallback empty
    return []