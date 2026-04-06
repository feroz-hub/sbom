from __future__ import annotations

import json
import logging
import os
import time
import re
import itertools
import requests

from datetime import datetime, timezone
from typing import Any, Optional, List, Dict, Tuple
from urllib.parse import unquote, parse_qs

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status, Path, Response, File, Form, UploadFile
from fastapi.responses import JSONResponse, Response, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from packaging import version

from pydantic import BaseModel
from sqlalchemy import select, text, delete, func
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from .logger import setup_logging, get_logger

# Initialise logging as early as possible so all subsequent imports inherit the config
setup_logging()
log = get_logger("api")

from .pdf_report import build_pdf_from_run_bytes
from .db import Base, SessionLocal, engine, get_db
from .models import (
    AnalysisFinding,
    AnalysisRun,
    Projects,
    RunCache,
    SBOMAnalysisReport,
    SBOMComponent,
    SBOMSource,
    SBOMType,
)
from .schemas import (
    AnalysisFindingOut,
    AnalysisRunOut,
    ProjectCreate,
    ProjectOut,
    ProjectUpdate,
    SBOMAnalysisReportCreate,
    SBOMAnalysisReportOut,
    SBOMComponentOut,
    SBOMSourceCreate,
    SBOMSourceOut,
    SBOMSourceUpdate,
    SBOMTypeCreate,
    SBOMTypeOut,
)
from .analysis import (
    get_analysis_settings_multi,
    analyze_sbom_multi_source,
    extract_components,
    _augment_components_with_cpe,
)

app = FastAPI(title="SBOM & Projects API", version="2.0.0")

_CORS_ORIGINS = [
    o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",") if o.strip()
] or ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------
# Request / Response logging middleware
# -----------------------------------------------
_access_log = get_logger("access")

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log every incoming request and its response status + duration."""
    t0 = time.perf_counter()
    _access_log.debug(
        "→ %s %s  client=%s",
        request.method,
        request.url.path,
        request.client.host if request.client else "unknown",
    )
    try:
        response = await call_next(request)
    except Exception as exc:
        _access_log.error(
            "✗ %s %s  UNHANDLED %s: %s",
            request.method, request.url.path, type(exc).__name__, exc,
            exc_info=True,
        )
        raise
    duration_ms = int((time.perf_counter() - t0) * 1000)
    level = logging.WARNING if response.status_code >= 400 else logging.DEBUG
    _access_log.log(
        level,
        "← %s %s  status=%d  %dms",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    return response

# -----------------------------
# Utilities
# -----------------------------
def _coerce_sbom_data(value: Any) -> Optional[str]:
    """
    Ensure sbom_data is always stored as a JSON string in the DB Text column,
    even if the client sends a dict/list. Leave strings as-is.
    """
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return value if isinstance(value, str) else str(value)

def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def legacy_analysis_level() -> int:
    raw_value = os.getenv("ANALYSIS_LEGACY_LEVEL", "1")
    try:
        parsed = int(raw_value)
    except ValueError:
        return 1
    return parsed if parsed > 0 else 1

def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default

def safe_float(value: Any) -> Optional[float]:
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None

def normalized_key(value: Optional[str]) -> str:
    return (value or "").strip().lower()

def compute_report_status(total_findings: int, query_errors: list[dict]) -> str:
    if total_findings > 0:
        return "FAIL"
    if query_errors:
        return "PARTIAL"
    return "PASS"

def normalize_details(details: Optional[dict], components: list[dict]) -> dict:
    """
    Preserve analyzer-provided totals if present; only compute from raw components
    as a fallback. Always recompute severity buckets from the 'findings' list.
    """
    data = dict(details or {})

    findings = data.get("findings")
    if not isinstance(findings, list):
        findings = []
    data["findings"] = findings

    query_errors = data.get("query_errors")
    if not isinstance(query_errors, list):
        query_errors = []
    data["query_errors"] = query_errors

    # Only set totals if the analyzer didn't already supply them
    if "total_components" not in data or not isinstance(data["total_components"], int):
        data["total_components"] = len(components)

    if "components_with_cpe" not in data or not isinstance(data["components_with_cpe"], int):
        data["components_with_cpe"] = len({c.get("cpe") for c in components if c.get("cpe")})

    if "total_findings" not in data or not isinstance(data["total_findings"], int):
        data["total_findings"] = len(findings)

    # Always recompute buckets from 'findings'
    buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for f in findings:
        sev = str((f or {}).get("severity", "UNKNOWN")).upper()
        if sev == "CRITICAL":
            buckets["critical"] += 1
        elif sev == "HIGH":
            buckets["high"] += 1
        elif sev == "MEDIUM":
            buckets["medium"] += 1
        elif sev == "LOW":
            buckets["low"] += 1
        else:
            buckets["unknown"] += 1

    data["critical"] = buckets["critical"]
    data["high"] = buckets["high"]
    data["medium"] = buckets["medium"]
    data["low"] = buckets["low"]
    data["unknown"] = buckets["unknown"]
    return data

def public_analysis_config() -> dict:
    """
    Expose multi-source analysis settings (NVD + OSV + GHSA + concurrency).
    """
    s = get_analysis_settings_multi()
    return {
        # Legacy-ish keys still useful in UI
        "source_name": getattr(s, "source_name", "NVD"),
        "http_user_agent": getattr(s, "http_user_agent", "SBOM-Analyzer/enterprise-2.0"),
        "nvd_api_base_url": getattr(s, "nvd_api_base_url", None),
        "nvd_detail_base_url": getattr(s, "nvd_detail_base_url", None),
        "nvd_api_key_env": getattr(s, "nvd_api_key_env", "NVD_API_KEY"),
        "nvd_results_per_page": getattr(s, "nvd_results_per_page", 2000),
        "nvd_request_timeout_seconds": getattr(s, "nvd_request_timeout_seconds", 60),
        "nvd_max_retries": getattr(s, "nvd_max_retries", 3),
        "nvd_retry_backoff_seconds": getattr(s, "nvd_retry_backoff_seconds", 1.5),
        "nvd_request_delay_with_key_seconds": getattr(s, "nvd_request_delay_with_key_seconds", 0.7),
        "nvd_request_delay_without_key_seconds": getattr(s, "nvd_request_delay_without_key_seconds", 6.0),
        "cvss_critical_threshold": getattr(s, "cvss_critical_threshold", 9.0),
        "cvss_high_threshold": getattr(s, "cvss_high_threshold", 7.0),
        "cvss_medium_threshold": getattr(s, "cvss_medium_threshold", 4.0),
        "analysis_max_findings_per_cpe": getattr(s, "analysis_max_findings_per_cpe", 5000),
        "analysis_max_findings_total": getattr(s, "analysis_max_findings_total", 50000),
        # Multi-source specific
        "osv_api_base_url": getattr(s, "osv_api_base_url", None),
        "osv_results_per_batch": getattr(s, "osv_results_per_batch", 1000),
        "gh_graphql_url": getattr(s, "gh_graphql_url", None),
        "gh_token_env": getattr(s, "gh_token_env", "GITHUB_TOKEN"),
        "analysis_sources_env": getattr(s, "analysis_sources_env", "ANALYSIS_SOURCES"),
        "max_concurrency": getattr(s, "max_concurrency", 10),
        "analysis_legacy_level": legacy_analysis_level(),
    }

# -----------------------------
# DB seed/backfill
# -----------------------------
def ensure_seed_data() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        db.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_sbom_type_typename ON sbom_type(typename)"))

        existing = {
            (row.typename or "").strip().lower()
            for row in db.execute(select(SBOMType)).scalars().all()
        }
        seeds = []
        if "cyclonedx" not in existing:
            seeds.append(
                SBOMType(
                    typename="CycloneDX",
                    type_details="CycloneDX format",
                    created_on=now_iso(),
                    created_by="system",
                )
            )
        if "spdx" not in existing:
            seeds.append(
                SBOMType(
                    typename="SPDX",
                    type_details="SPDX format",
                    created_on=now_iso(),
                    created_by="system",
                )
            )
        if seeds:
            db.add_all(seeds)
            db.commit()

        backfill_analytics_tables(db)
    finally:
        db.close()

def upsert_components(db: Session, sbom_obj: SBOMSource, components: list[dict]) -> dict:
    existing_rows = db.execute(
        select(SBOMComponent).where(SBOMComponent.sbom_id == sbom_obj.id)
    ).scalars().all()

    by_comp_triplet = {}
    by_cpe = {}

    for row in existing_rows:
        triplet = (
            normalized_key(row.cpe),
            normalized_key(row.name),
            normalized_key(row.version),
        )
        by_comp_triplet.setdefault(triplet, row)
        if row.cpe:
            by_cpe.setdefault(normalized_key(row.cpe), []).append(row)

    for comp in components:
        name = (comp.get("name") or "").strip()
        if not name:
            fallback = (comp.get("bom_ref") or comp.get("purl") or comp.get("cpe") or "component").strip()
            name = fallback[:255] if fallback else "component"

        version = (comp.get("version") or "").strip() or None
        cpe = (comp.get("cpe") or "").strip() or None
        triplet = (normalized_key(cpe), normalized_key(name), normalized_key(version))

        if triplet in by_comp_triplet:
            continue

        row = SBOMComponent(
            sbom_id=sbom_obj.id,
            bom_ref=(comp.get("bom_ref") or "").strip() or None,
            component_type=(comp.get("type") or "").strip() or None,
            component_group=(comp.get("group") or "").strip() or None,
            name=name,
            version=version,
            purl=(comp.get("purl") or "").strip() or None,
            cpe=cpe,
            supplier=(comp.get("supplier") or "").strip() or None,
            scope=(comp.get("scope") or "").strip() or None,
            created_on=now_iso(),
        )
        db.add(row)
        db.flush()

        by_comp_triplet[triplet] = row
        if cpe:
            by_cpe.setdefault(normalized_key(cpe), []).append(row)

    return {"triplet": by_comp_triplet, "cpe": by_cpe}

def resolve_component_id(finding: dict, component_maps: dict) -> Optional[int]:
    cpe = (finding.get("cpe") or "").strip() or None
    name = (finding.get("component_name") or "").strip() or None
    version = (finding.get("component_version") or "").strip() or None

    triplet = (
        normalized_key(cpe),
        normalized_key(name),
        normalized_key(version),
    )
    row = component_maps["triplet"].get(triplet)
    if row:
        return row.id

    if cpe:
        cpe_rows = component_maps["cpe"].get(normalized_key(cpe), [])
        if cpe_rows:
            return cpe_rows[0].id

    return None

def persist_analysis_run(
    db: Session,
    sbom_obj: SBOMSource,
    details: dict,
    components: list[dict],
    run_status: str,
    source: str,
    started_on: str,
    completed_on: str,
    duration_ms: int,
) -> AnalysisRun:
    component_maps = upsert_components(db, sbom_obj, components)

    run = AnalysisRun(
        sbom_id=sbom_obj.id,
        project_id=sbom_obj.projectid,
        run_status=run_status,
        source=source,
        started_on=started_on,
        completed_on=completed_on,
        duration_ms=duration_ms,
        total_components=safe_int(details.get("total_components")),
        components_with_cpe=safe_int(details.get("components_with_cpe")),
        total_findings=safe_int(details.get("total_findings")),
        critical_count=safe_int(details.get("critical")),
        high_count=safe_int(details.get("high")),
        medium_count=safe_int(details.get("medium")),
        low_count=safe_int(details.get("low")),
        unknown_count=safe_int(details.get("unknown")),
        query_error_count=len(details.get("query_errors") or []),
        raw_report=json.dumps(details),
    )
    db.add(run)
    db.flush()

    for finding in details.get("findings") or []:
        if not isinstance(finding, dict):
            continue

        db.add(
            AnalysisFinding(
                analysis_run_id=run.id,
                component_id=resolve_component_id(finding, component_maps),
                vuln_id=str(finding.get("vuln_id") or "UNKNOWN-CVE"),
                source=",".join(finding.get("sources", ["NVD"])),
                title=(finding.get("title") or finding.get("vuln_id")),
                description=finding.get("description"),
                severity=finding.get("severity"),
                score=safe_float(finding.get("score")),
                vector=finding.get("vector"),
                published_on=finding.get("published"),
                reference_url=finding.get("url"),
                cwe=",".join(finding.get("cwe", [])) if finding.get("cwe") else None,
                cpe=finding.get("cpe"),
                component_name=finding.get("component_name"),
                component_version=finding.get("component_version"),
            )
        )

    return run

def create_legacy_report_from_run(db: Session, sbom_obj: SBOMSource, run: AnalysisRun) -> SBOMAnalysisReport:
    report = SBOMAnalysisReport(
        sbom_ref_id=sbom_obj.id,
        sbom_result=run.run_status,
        project_id=str(sbom_obj.projectid) if sbom_obj.projectid is not None else None,
        created_on=run.completed_on,
        analysis_details=run.raw_report,
        reference_source=run.source,
        sbom_analysis_level=legacy_analysis_level(),
    )
    db.add(report)
    return report

def create_auto_report(db: Session, sbom_obj: SBOMSource) -> Optional[SBOMAnalysisReport]:
    """
    Generate an analysis run + legacy report using the new multi-source analyzer.
    (NVD by CPE + OSV by purl/ecosystem + GitHub Advisory)
    """
    started_on = now_iso()
    start_time = time.perf_counter()

    settings = get_analysis_settings_multi()  # multi-source settings  [1](https://hclo365-my.sharepoint.com/personal/techofficeintern5_hcltech_com/Documents/Microsoft%20Copilot%20Chat%20Files/analysis.py)
    source = "MULTI"  # derive precise sources below

    if not sbom_obj.sbom_data:
        details = normalize_details({"message": "SBOM data missing. Analysis skipped."}, [])
        run_status = "NO_DATA"
        components = []
    else:
        try:
            components = extract_components(sbom_obj.sbom_data)
            details = analyze_sbom_multi_source(
                sbom_json=sbom_obj.sbom_data,
                sources = ["NVD", "OSV", "GITHUB"],  # read ANALYSIS_SOURCES env or default ["NVD"]
                settings=settings,
            )
            details = normalize_details(details, components)
            run_status = compute_report_status(
                safe_int(details.get("total_findings")), details.get("query_errors") or []
            )
            used = (details.get("analysis_metadata") or {}).get("sources") or []
            if used:
                source = ",".join(used)
            if details.get("query_errors"):
                source = f"{source} (partial)"
        except Exception as exc:
            components = []
            details = normalize_details({"error": str(exc)}, components)
            run_status = "ERROR"

    completed_on = now_iso()
    duration_ms = max(0, int((time.perf_counter() - start_time) * 1000))

    run = persist_analysis_run(
        db=db,
        sbom_obj=sbom_obj,
        details=details,
        components=components,
        run_status=run_status,
        source=source,
        started_on=started_on,
        completed_on=completed_on,
        duration_ms=duration_ms,
    )

    report = create_legacy_report_from_run(db, sbom_obj, run)
    db.commit()
    db.refresh(report)
    return report


# -------------------------------
# Configuration
# -------------------------------
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_GRAPHQL = "https://api.github.com/graphql"
OSV_API = "https://api.osv.dev/v1"  # Base for /query, /querybatch, /vulns/{id}
OSV_MAX_BATCH = 1000                 # Documented batch max per request

MAX_UPLOAD_BYTES = 20 * 1024 * 1024  # 20 MB
DEFAULT_RESULTS_PER_PAGE = 20

# -----------------------------
# Run cache helpers (DB-backed — no in-memory state)
# -----------------------------
def store_run_cache(db: Session, run_record: dict) -> int:
    """Persist an ad-hoc analysis run and return the DB-assigned id."""
    cache = RunCache(run_json=json.dumps(run_record), created_on=now_iso())
    db.add(cache)
    db.commit()
    db.refresh(cache)
    return cache.id

def load_run_cache(db: Session, run_id: int) -> Optional[dict]:
    """Load a previously persisted ad-hoc run by id, or return None."""
    cache = db.get(RunCache, run_id)
    if cache is None:
        return None
    try:
        return json.loads(cache.run_json)
    except (json.JSONDecodeError, TypeError):
        return None

# -------------------------------
# Utilities: Encoding-safe JSON
# -------------------------------
def load_json_bytes_with_fallback(data: bytes) -> Any:
    """
    Decode bytes as UTF-8, fallback to UTF-8-SIG and parse JSON.
    """
    try:
        text = data.decode("utf-8")
        return json.loads(text)
    except UnicodeDecodeError:
        try:
            text = data.decode("utf-8-sig")
            return json.loads(text)
        except UnicodeDecodeError as e:
            raise HTTPException(
                status_code=400,
                detail=f"Unable to decode JSON as UTF-8/UTF-8-SIG: {e}"
            )
    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid JSON: {e}"
        )

# -------------------------------
# SBOM detection & validation
# -------------------------------


def _load_sbom_from_ref(
    db: Session,
    sbom_id: Optional[int] = None,
    sbom_name: Optional[str] = None
) -> Tuple[SBOMSource, dict, str, str, list[dict]]:
    """
    Returns (sbom_row, sbom_dict, sbom_format, spec_version, components)
    Requires either sbom_id or sbom_name. Raises HTTPException on all failures.
    """

    # Validate input
    if sbom_id is None and not (isinstance(sbom_name, str) and sbom_name.strip()):
        raise HTTPException(status_code=422, detail="Provide 'sbom_id' or 'sbom_name'")

    # Lookup by id first (if given)
    sbom_row: Optional[SBOMSource] = None
    if sbom_id is not None:
        try:
            sbom_row = db.get(SBOMSource, int(sbom_id))
        except Exception:
            sbom_row = None
        if sbom_row is None:
            raise HTTPException(status_code=404, detail=f"SBOM with id {sbom_id} not found")

    # If not found and name provided, lookup by name
    if sbom_row is None and sbom_name:
        sbom_row = db.execute(
            select(SBOMSource).where(SBOMSource.sbom_name == sbom_name.strip())
        ).scalars().first()
        if sbom_row is None:
            raise HTTPException(status_code=404, detail=f"SBOM with name '{sbom_name}' not found")

    # If both id and name provided, ensure they match the same row
    if sbom_id is not None and sbom_name and sbom_row and sbom_row.sbom_name != sbom_name.strip():
        raise HTTPException(
            status_code=404,
            detail=f"SBOM mismatch: id={sbom_id} does not match name='{sbom_name}'."
        )

    # Ensure content present
    if not sbom_row.sbom_data:
        raise HTTPException(status_code=400, detail="SBOM has no sbom_data stored")

    # Parse JSON from stored text/dict
    if isinstance(sbom_row.sbom_data, str):
        try:
            sbom_dict = json.loads(sbom_row.sbom_data)
        except json.JSONDecodeError as e:
            raise HTTPException(status_code=400, detail=f"Invalid SBOM JSON in storage: {e}")
    elif isinstance(sbom_row.sbom_data, dict):
        sbom_dict = sbom_row.sbom_data
    else:
        raise HTTPException(status_code=400, detail="Unsupported sbom_data type in storage")

    # Use your existing helpers to detect/validate and extract components
    try:
        sbom_format, spec_version, components = parse_components(sbom_dict)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"SBOM parsing error: {e}")

    return sbom_row, sbom_dict, sbom_format, spec_version, components

def detect_sbom_format(sbom: Dict[str, Any]) -> Tuple[str, str]:
    """
    Return (format, version) where format is 'cyclonedx' or 'spdx'.
    """
    # CycloneDX indicators
    if (isinstance(sbom.get("bomFormat"), str) and sbom.get("bomFormat").lower() == "cyclonedx") \
       or ("components" in sbom and isinstance(sbom["components"], list)):
        version_str = sbom.get("specVersion") or sbom.get("version") or "unknown"
        return "cyclonedx", str(version_str)

    # SPDX indicators
    if "spdxVersion" in sbom or "packages" in sbom:
        version_str = sbom.get("spdxVersion", "unknown")
        return "spdx", str(version_str)

    raise HTTPException(
        status_code=400,
        detail="Unable to detect SBOM format. Expected CycloneDX (bomFormat/components) or SPDX (spdxVersion/packages)."
    )

def validate_cyclonedx(sbom: Dict[str, Any]) -> None:
    if "components" not in sbom or not isinstance(sbom["components"], list):
        raise HTTPException(status_code=400, detail="CycloneDX: 'components' array is missing or not a list.")
    for idx, comp in enumerate(sbom["components"]):
        if not isinstance(comp, dict):
            raise HTTPException(status_code=400, detail=f"CycloneDX: component at index {idx} is not an object.")
        if not comp.get("name"):
            raise HTTPException(status_code=400, detail=f"CycloneDX: component at index {idx} has no 'name'.")

def validate_spdx(sbom: Dict[str, Any]) -> None:
    if "packages" not in sbom or not isinstance(sbom["packages"], list):
        raise HTTPException(status_code=400, detail="SPDX: 'packages' array is missing or not a list.")
    for idx, pkg in enumerate(sbom["packages"]):
        if not isinstance(pkg, dict):
            raise HTTPException(status_code=400, detail=f"SPDX: package at index {idx} is not an object.")
        if not pkg.get("name"):
            raise HTTPException(status_code=400, detail=f"SPDX: package at index {idx} has no 'name'.")

# -------------------------------
# SBOM component parsing
# -------------------------------
def extract_cyclonedx_components(sbom: Dict[str, Any]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for comp in sbom.get("components", []):
        name = comp.get("name")
        version_str = comp.get("version") or ""
        purl = comp.get("purl")
        cpe = comp.get("cpe")
        if not cpe and isinstance(comp.get("properties"), list):
            for prop in comp["properties"]:
                if (prop.get("name", "").lower() in ("cpe", "cpe23uri", "cpe22uri")):
                    cpe = prop.get("value")
                    break
        results.append({"name": name, "version": version_str, "purl": purl, "cpe": cpe})
    return results

def extract_spdx_components(sbom: Dict[str, Any]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for pkg in sbom.get("packages", []):
        name = pkg.get("name")
        version_str = pkg.get("versionInfo") or ""
        purl = None
        cpe = None
        for ref in pkg.get("externalRefs", []) or []:
            rtype = (ref.get("referenceType") or "").lower()
            locator = ref.get("referenceLocator")
            if rtype == "purl" and locator:
                purl = locator
            if rtype in ("cpe23type", "cpe22type") and locator:
                cpe = locator
        results.append({"name": name, "version": version_str, "purl": purl, "cpe": cpe})
    return results

def parse_components(sbom: Dict[str, Any]) -> Tuple[str, str, List[Dict[str, Any]]]:
    sbom_format, ver = detect_sbom_format(sbom)
    if sbom_format == "cyclonedx":
        validate_cyclonedx(sbom)
        comps = extract_cyclonedx_components(sbom)
    else:
        validate_spdx(sbom)
        comps = extract_spdx_components(sbom)
    comps = [c for c in comps if c.get("name")]
    return sbom_format, ver, comps

# -------------------------------
# NVD querying & scoring
# -------------------------------

def _slug_cpe(s: Optional[str]) -> Optional[str]:
    """Sanitize a token for CPE 2.3 (vendor/product): alphanumeric, _, -, . only."""
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
    """Generate a best-effort CPE 2.3 string; returns None if name or version missing/invalid."""
    if not name or not component_version:
        return None
    vnd = _slug_cpe(name)
    prd = _slug_cpe(name)
    ver = "".join(c if c.isalnum() or c in "._-" else "_" for c in component_version).strip("._-") or "*"
    if not vnd or not prd:
        return None
    return f"cpe:2.3:a:{vnd}:{prd}:{ver}:*:*:*:*:*:*:*"

def nvd_fetch(name: str, version_str: str, cpe: Optional[str], nvd_api_key: Optional[str],
              results_per_page: int = DEFAULT_RESULTS_PER_PAGE) -> Dict[str, Any]:
    headers = {"User-Agent": "SBOM-Analyzer/1.0 (contact: example@example.com)"}
    if nvd_api_key:
        headers["apiKey"] = nvd_api_key
    params = {"resultsPerPage": results_per_page}
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
        out.append({
            "id": cve_id,
            "severity": severity,
            "score": score,
            "vector": vector,
            "published": published,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else None
        })
    return out

def severity_buckets(vulns: List[Dict[str, Any]]) -> Dict[str, int]:
    buckets = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for v in vulns:
        sev = (v.get("severity") or "UNKNOWN").upper()
        if sev not in buckets:
            sev = "UNKNOWN"
        buckets[sev] += 1
    return buckets

# -------------------------------
# GitHub Security Advisories (GHSA)
# -------------------------------
def _parse_purl(purl: str) -> dict:
    if not purl or not purl.startswith("pkg:"):
        return {}
    rest = purl[4:]
    if "#" in rest:
        rest, _ = rest.split("#", 1)
    qualifiers = {}
    if "?" in rest:
        rest, q = rest.split("?", 1)
        qualifiers = {k: v[0] for k, v in parse_qs(q, keep_blank_values=True).items()}
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
    return {"type": ptype, "namespace": namespace, "name": name, "version": version_tag, "qualifiers": qualifiers}

def gh_pkg_from_purl(purl: str) -> Tuple[Optional[str], Optional[str]]:
    parsed = _parse_purl(purl)
    if not parsed:
        return None, None
    ptype = parsed.get("type")
    ns = parsed.get("namespace")
    name = parsed.get("name")
    eco_map = {
        "npm": "NPM", "pypi": "PIP", "maven": "MAVEN", "nuget": "NUGET",
        "golang": "GO", "go": "GO", "rubygems": "RUBYGEMS", "gem": "RUBYGEMS",
        "composer": "COMPOSER", "cargo": "RUST", "crates": "RUST", "pub": "PUB",
        "swift": "SWIFT", "hex": "ELIXIR",
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

def github_fetch_advisories(ecosystem: str, package_name: str, github_token: str, first: int = 100) -> Dict[str, Any]:
    if not github_token:
        raise HTTPException(status_code=400, detail="GitHub token missing. Provide 'github_token' or set GITHUB_TOKEN env var.")
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
    resp = requests.post(GITHUB_GRAPHQL, headers=headers, json={"query": query, "variables": variables}, timeout=45)
    resp.raise_for_status()
    data = resp.json()
    if "errors" in data:
        raise HTTPException(status_code=502, detail=f"GitHub GraphQL error: {data['errors']}")
    return data

def is_version_in_range(component_version: Optional[str], vuln_range: Optional[str]) -> bool:
    """Return True if component_version is inside the vulnerable range (so the advisory applies)."""
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
        # Try PEP 440 / packaging specifier set (e.g. ">=1.0,<2.0" or ">= 1.0.0, < 2.0.0")
        from packaging.specifiers import SpecifierSet
        spec = SpecifierSet(vuln_range)
        return comp_ver in spec
    except Exception:
        pass
    try:
        # Simple single-bound checks (e.g. "< 2.0.0" or "<= 1.5.0")
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

def extract_ghsa_records(graphql_json: Dict[str, Any], component_version=None) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    nodes = (((graphql_json or {}).get("data") or {}).get("securityVulnerabilities") or {}).get("nodes") or []
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

        out.append({
            "id": ghsa_id,
            "severity": severity,
            "score": score,
            "vector": vector,
            "published": published,
            "url": url,
            "vulnerableVersionRange": vuln_range,
            "firstPatchedVersion": ((n.get("firstPatchedVersion") or {}).get("identifier")),
        })
    return out

# -------------------------------
# OSV helpers
# -------------------------------
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

def _build_osv_query_for_component(name: str, version_str: str, purl: Optional[str]) -> Optional[Dict[str, Any]]:
    """
    Build a valid OSV query for a component.

    Rules:
    - If PURL already contains a version (pkg:type/name@version) → send only the PURL
    - If PURL has no version → send PURL + top-level version
    - If parsing fails → skip component
    """

    if not purl:
        return None

    parsed = _parse_purl(purl)
    if not parsed:
        return None

    purl_version = parsed.get("version")

    # If PURL already includes version
    if purl_version:
        return {
            "package": {
                "purl": purl
            }
        }

    # Otherwise include version separately
    if version_str:
        return {
            "package": {
                "purl": purl
            },
            "version": version_str
        }

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
        pending_indices = {i: r.get("next_page_token") for i, r in enumerate(chunk_results) if isinstance(r, dict) and r.get("next_page_token")}
        accum: Dict[int, List[Dict[str, Any]]] = {i: list((chunk_results[i].get("vulns") or [])) for i in range(len(chunk_results))}
        while pending_indices:
            follow_up_queries = []
            map_idx = []
            for idx, token in pending_indices.items():
                q = dict(chunk[idx])
                q["page_token"] = token
                follow_up_queries.append(q)
                map_idx.append(idx)
            follow_payload = {"queries": follow_up_queries}
            follow_resp = requests.post(f"{OSV_API}/querybatch", json=follow_payload, timeout=60)
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
    for s in (osv_json.get("severity") or []):
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

# -------------------------------
# Consolidation helpers
# -------------------------------
def _canonical_id(v: Dict[str, Any]) -> Optional[str]:
    vid = (v.get("id") or "")
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

def _merge_vuln_entry(dst: Dict[str, Any], src: Dict[str, Any], source_tag: str) -> None:
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

def combine_component_findings(nvd_list: List[Dict[str, Any]], ghsa_list: List[Dict[str, Any]], osv_list: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
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
            cid = _canonical_id(src) or f"{tag}:{len(combined)+1}"
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
    combined_list = []
    for k, v in combined.items():
        v["sources"] = sorted(list(v.get("sources") or []))
        combined_list.append(v)
    buckets = severity_buckets(combined_list)
    return combined_list, buckets

# ----------------------------------
# Backfill runs from existing SBOMs
# ----------------------------------
def backfill_analytics_tables(db: Session) -> None:
    sboms = db.execute(select(SBOMSource).order_by(SBOMSource.id.asc())).scalars().all()

    for sbom in sboms:
        has_run = db.execute(
            select(AnalysisRun.id).where(AnalysisRun.sbom_id == sbom.id).limit(1)
        ).scalar_one_or_none()
        if has_run is not None:
            continue

        components = []
        if sbom.sbom_data:
            try:
                components = extract_components(sbom.sbom_data)
            except Exception:
                components = []

        latest_legacy = db.execute(
            select(SBOMAnalysisReport)
            .where(SBOMAnalysisReport.sbom_ref_id == sbom.id)
            .order_by(SBOMAnalysisReport.id.desc())
        ).scalars().first()

        if latest_legacy:
            try:
                details = json.loads(latest_legacy.analysis_details or "{}")
            except json.JSONDecodeError:
                details = {"message": "Legacy report was non-JSON", "findings": []}

            details = normalize_details(details, components)
            run_status = latest_legacy.sbom_result or compute_report_status(
                safe_int(details.get("total_findings")), details.get("query_errors") or []
            )
            used = (details.get("analysis_metadata") or {}).get("sources") or []
            source = ",".join(used) if used else "BACKFILL"
            started_on = latest_legacy.created_on or now_iso()
            completed_on = latest_legacy.created_on or started_on
        else:
            details = normalize_details({"message": "Backfilled from SBOM without legacy report."}, components)
            run_status = "NO_DATA" if not sbom.sbom_data else "PASS"
            source = "BACKFILL"
            started_on = now_iso()
            completed_on = started_on

        persist_analysis_run(
            db=db,
            sbom_obj=sbom,
            details=details,
            components=components,
            run_status=run_status,
            source=source,
            started_on=started_on,
            completed_on=completed_on,
            duration_ms=0,
        )

    db.commit()

# -----------------------------
# Startup & health
# -----------------------------
@app.on_event("startup")
def on_startup() -> None:
    log.info("SBOM Analyzer starting up — initialising database …")
    ensure_seed_data()   # also calls Base.metadata.create_all — creates all tables including run_cache
    add_sbom_name_column()
    update_sbom_names()
    log.info("Startup complete. API ready.")

@app.get("/health")
def health() -> dict:
    log.debug("Health check requested")
    return {"status": "ok"}

@app.get("/api/analysis/config")
def get_analysis_config() -> dict:
    return public_analysis_config()


@app.get("/api/types", response_model=List[SBOMTypeOut])
def list_sbom_types(db: Session = Depends(get_db)):
    """List SBOM types (e.g. CycloneDX, SPDX) for upload/edit dropdowns."""
    return db.execute(select(SBOMType).order_by(SBOMType.typename.asc())).scalars().all()


# -----------------------------
# SBOM CRUD + analysis trigger
# -----------------------------
@app.get("/api/sboms/{sbom_id}", response_model=SBOMSourceOut)
def get_sbom(sbom_id: int, db: Session = Depends(get_db)):
    sbom = db.get(SBOMSource, sbom_id)
    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")
    return sbom

@app.post("/api/sboms", response_model=SBOMSourceOut, status_code=status.HTTP_201_CREATED)
def create_sbom(payload: SBOMSourceCreate, db: Session = Depends(get_db)):
    log.info("Creating SBOM: name='%s' project_id=%s", payload.sbom_name, payload.projectid)
    # --- Foreign key checks ---
    if payload.projectid is not None and db.get(Projects, payload.projectid) is None:
        log.warning("create_sbom: project_id=%s not found", payload.projectid)
        raise HTTPException(status_code=404, detail="Project not found")
    if payload.sbom_type is not None and db.get(SBOMType, payload.sbom_type) is None:
        log.warning("create_sbom: sbom_type=%s not found", payload.sbom_type)
        raise HTTPException(status_code=404, detail="SBOM type not found")

    # --- Preflight duplicate check on name (global uniqueness) ---
    if payload.sbom_name:
        exists = db.execute(
            select(SBOMSource.id).where(SBOMSource.sbom_name == payload.sbom_name.strip())
        ).first()
        if exists:
            log.warning("create_sbom: duplicate name '%s'", payload.sbom_name)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "duplicate_name", "message": f"An SBOM with name '{payload.sbom_name}' already exists."}
            )

    try:
        obj = SBOMSource(**payload.model_dump(), created_on=now_iso())
        db.add(obj)
        db.flush()   # early constraint detection
        db.commit()
        db.refresh(obj)
        log.info("SBOM created: id=%d name='%s'", obj.id, obj.sbom_name)

        # Best-effort: auto-analysis (multi-source)
        try:
            log.debug("Triggering auto-analysis for SBOM id=%d", obj.id)
            create_auto_report(db, obj)
            log.debug("Auto-analysis complete for SBOM id=%d", obj.id)
        except Exception as exc:
            log.warning("Auto-analysis failed for SBOM id=%d: %s", obj.id, exc)

        return obj

    except IntegrityError as exc:
        db.rollback()
        msg = str(getattr(exc, "orig", exc))
        log.error("create_sbom IntegrityError: %s", msg)
        if "UNIQUE" in msg.upper() and "sbom_name" in msg:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "duplicate_name", "message": f"An SBOM with name '{payload.sbom_name}' already exists."}
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "integrity_error", "message": "Integrity constraint violated while creating SBOM."}
        ) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        log.error("create_sbom DB error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=500,
            detail={"code": "db_error", "message": "Internal database error while creating SBOM."}
        ) from exc
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail={"code": "unexpected", "message": "Unexpected error while creating SBOM."}
        )

@app.post(
    "/api/sboms/{sbom_id}/analyze",
    response_model=AnalysisRunOut,
    status_code=status.HTTP_201_CREATED,
)
def run_analysis_for_sbom(sbom_id: int, db: Session = Depends(get_db)):
    log.info("Manual analysis triggered for SBOM id=%d", sbom_id)
    sbom = db.get(SBOMSource, sbom_id)
    if not sbom:
        log.warning("Analysis requested for unknown SBOM id=%d", sbom_id)
        raise HTTPException(status_code=404, detail="SBOM not found")
    report = create_auto_report(db, sbom)
    if not report:
        log.error("Analysis report generation failed for SBOM id=%d", sbom_id)
        raise HTTPException(status_code=500, detail="Unable to generate analysis report")
    # Return the AnalysisRun (not the legacy SBOMAnalysisReport) so the
    # frontend can navigate directly to /analysis/{run.id}
    run = db.execute(
        select(AnalysisRun)
        .where(AnalysisRun.sbom_id == sbom_id)
        .order_by(AnalysisRun.id.desc())
    ).scalars().first()
    if not run:
        raise HTTPException(status_code=500, detail="AnalysisRun record not found after creation")
    log.info("Analysis complete for SBOM id=%d → run id=%d status=%s", sbom_id, run.id, run.run_status)
    return run

# -----------------------------
# SBOM listing/filter + components
# -----------------------------
_USER_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

def _validate_user_id(raw: Optional[str]) -> Optional[str]:
    if raw is None:
        return None
    user_id = raw.strip()
    if not user_id:
        raise HTTPException(status_code=422, detail="Query parameter 'user_id' must not be empty or whitespace.")
    if not _USER_ID_PATTERN.fullmatch(user_id):
        raise HTTPException(
            status_code=422,
            detail=("Invalid 'user_id'. Allowed: letters, digits, '_', '-', '.'; length 1–64 characters."),
        )
    return user_id

@app.get("/api/sboms", response_model=List[SBOMSourceOut])
def get_sbom_details(
    user_id: Optional[str] = Query(None, description="Filter by CreatedBy (letters/digits/_/./-, 1–64 chars)"),
    page: int = Query(1, ge=1, description="Page number (>=1)"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page (1..500)"),
    response: Response = None,
    db: Session = Depends(get_db),
):
    user_id = _validate_user_id(user_id)
    page = 1 if page < 1 else page
    page_size = max(1, min(page_size, 500))
    offset = (page - 1) * page_size

    try:
        # Base query
        stmt = select(SBOMSource)
        count_stmt = select(func.count(SBOMSource.id))
        if user_id is not None:
            stmt = stmt.where(SBOMSource.created_by == user_id)
            count_stmt = count_stmt.where(SBOMSource.created_by == user_id)

        # Total
        total = db.execute(count_stmt).scalar_one()

        # Page
        stmt = stmt.order_by(SBOMSource.id.desc()).limit(page_size).offset(offset)
        items = db.execute(stmt).scalars().all()

        # Set total in header for frontend pagination
        if response is not None:
            response.headers["X-Total-Count"] = str(total)

        return items
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="Internal database error while fetching SBOMs.") from exc

def _validate_positive_int(value: int, param_name: str = "id") -> int:
    if not isinstance(value, int):
        raise HTTPException(status_code=422, detail=f"'{param_name}' must be an integer.")
    if value < 1:
        raise HTTPException(status_code=422, detail=f"'{param_name}' must be a positive integer (>= 1).")
    return value

@app.get("/api/sboms/{sbom_id}/components", response_model=list[SBOMComponentOut])
def get_sbom_components(
    sbom_id: int = Path(..., description="SBOM ID (positive integer)"),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=1000),
    response: Response = None,
    db: Session = Depends(get_db),
):
    sbom_id = _validate_positive_int(sbom_id, param_name="sbom_id")
    page = 1 if page < 1 else page
    page_size = max(1, min(page_size, 1000))
    offset = (page - 1) * page_size

    try:
        sbom = db.get(SBOMSource, sbom_id)
        if not sbom:
            raise HTTPException(status_code=404, detail="SBOM not found")

        # Total
        total = db.execute(
            select(func.count(SBOMComponent.id)).where(SBOMComponent.sbom_id == sbom_id)
        ).scalar_one()

        # Page
        stmt = (
            select(SBOMComponent)
            .where(SBOMComponent.sbom_id == sbom_id)
            .order_by(SBOMComponent.name.asc(), SBOMComponent.version.asc())
            .limit(page_size)
            .offset(offset)
        )
        items = db.execute(stmt).scalars().all()

        if response is not None:
            response.headers["X-Total-Count"] = str(total)

        return items
    except HTTPException:
        raise
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="Internal database error while fetching SBOM components.") from exc

# -----------------------------
# SBOM update/delete
# -----------------------------
@app.patch("/api/sboms/{sbom_id}", response_model=SBOMSourceOut)
def update_sbom(
    sbom_id: int,
    payload: SBOMSourceUpdate,
    user_id: str = Query(..., description="Must match SBOM.created_by"),
    db: Session = Depends(get_db),
):
    sbom = db.get(SBOMSource, sbom_id)
    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")

    # Ownership: allow first-claim if created_by is empty
    actual_owner = (sbom.created_by or "").strip().lower()
    caller = (user_id or "").strip().lower()
    if actual_owner and actual_owner != caller:
        raise HTTPException(status_code=403, detail="Forbidden: user cannot update this SBOM")
    if not sbom.created_by:
        sbom.created_by = user_id  # claim ownership if missing

    data = payload.model_dump(exclude_unset=True, exclude_none=True)

    # Validate FKs
    if "projectid" in data and data["projectid"] is not None:
        if db.get(Projects, data["projectid"]) is None:
            raise HTTPException(status_code=404, detail="Project not found")
    if "sbom_type" in data and data["sbom_type"] is not None:
        if db.get(SBOMType, data["sbom_type"]) is None:
            raise HTTPException(status_code=404, detail="SBOM type not found")

    # Coerce sbom_data to JSON text
    if "sbom_data" in data:
        data["sbom_data"] = _coerce_sbom_data(data["sbom_data"])

    try:
        for k, v in data.items():
            setattr(sbom, k, v)
        sbom.modified_on = now_iso()
        sbom.modified_by = data.get("modified_by") or user_id

        db.add(sbom)
        db.commit()
        db.refresh(sbom)
        return sbom
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update SBOM: {exc}") from exc

@app.delete("/api/sboms/{sbom_id}", status_code=status.HTTP_200_OK)
def delete_sbom(
    sbom_id: int,
    user_id: str = Query(..., description="CreatedBy user id; must match SBOM.created_by"),
    confirm: str = Query("no", description="Set to 'yes' to confirm deletion"),
    db: Session = Depends(get_db),
):
    if sbom_id is None or not isinstance(sbom_id, int) or sbom_id <= 0:
        raise HTTPException(status_code=400, detail="Invalid sbom_id. It must be a positive integer.")

    sbom = db.get(SBOMSource, sbom_id)
    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")

    def _norm(s: Optional[str]) -> str:
        return (s or "").strip().lower()

    # Allow delete when created_by is null/empty (no ownership constraint on un-owned SBOMs)
    if sbom.created_by and _norm(sbom.created_by) != _norm(user_id):
        raise HTTPException(status_code=403, detail="Forbidden: user cannot delete this SBOM")

    if _norm(confirm) not in {"yes", "y"}:
        return {
            "status": "pending_confirmation",
            "message": (
                "This operation will permanently delete the SBOM and all related analysis data. "
                "To proceed, resend the request with confirm=yes."
            ),
            "example": f"/api/sboms/{sbom_id}?user_id={user_id}&confirm=yes",
        }

    try:
        run_ids = db.execute(
            select(AnalysisRun.id).where(AnalysisRun.sbom_id == sbom_id)
        ).scalars().all()

        if run_ids:
            db.execute(
                delete(AnalysisFinding)
                .where(AnalysisFinding.analysis_run_id.in_(run_ids))
                .execution_options(synchronize_session=False)
            )

        db.execute(
            delete(AnalysisRun)
            .where(AnalysisRun.sbom_id == sbom_id)
            .execution_options(synchronize_session=False)
        )
        db.execute(
            delete(SBOMComponent)
            .where(SBOMComponent.sbom_id == sbom_id)
            .execution_options(synchronize_session=False)
        )
        db.execute(
            delete(SBOMAnalysisReport)
            .where(SBOMAnalysisReport.sbom_ref_id == sbom_id)
            .execution_options(synchronize_session=False)
        )
        db.flush()

        db.delete(sbom)
        db.commit()

        return {
            "status": "deleted",
            "message": f"SBOM {sbom_id} and related data have been deleted successfully.",
            "sbom_id": sbom_id,
            "requested_by": user_id,
        }
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete SBOM: {exc}") from exc

# -----------------------------
# Analysis runs & findings
# -----------------------------
  
def add_sbom_name_column():
    with engine.connect() as conn:
        try:
            conn.execute(text("ALTER TABLE analysis_run ADD COLUMN sbom_name TEXT"))
            print("sbom_name column added")
        except Exception as e:
            print("Column may already exist:", e)

def update_sbom_names():
    with engine.connect() as conn:
        conn.execute(text("""
            UPDATE analysis_run
            SET sbom_name = (
                SELECT sbom_name
                FROM sbom_source
                WHERE sbom_source.id = analysis_run.sbom_id
            )
        """))
    
@app.get("/api/runs", response_model=list[AnalysisRunOut])
def list_analysis_runs(
    sbom_id: Optional[int] = Query(None),
    project_id: Optional[int] = Query(None),
    run_status: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    response: Response = None,
    db: Session = Depends(get_db),
):
    page = 1 if page < 1 else page
    page_size = max(1, min(page_size, 500))
    offset = (page - 1) * page_size

    # Subquery: get sbom_name
    sbom_subq = (
        db.query(
            SBOMSource.id.label("sbom_id"),
            SBOMSource.sbom_name.label("sbom_name")
        )
        .subquery()
    )

    #  Base queries
    base = select(AnalysisRun)
    count = select(func.count(AnalysisRun.id))

    if sbom_id is not None:
        base = base.where(AnalysisRun.sbom_id == sbom_id)
        count = count.where(AnalysisRun.sbom_id == sbom_id)

    if project_id is not None:
        base = base.where(AnalysisRun.project_id == project_id)
        count = count.where(AnalysisRun.project_id == project_id)

    if run_status:
        norm = run_status.strip().upper()
        base = base.where(AnalysisRun.run_status == norm)
        count = count.where(AnalysisRun.run_status == norm)

    #  Total count
    total = db.execute(count).scalar_one()

    #  Main query with subquery join
    stmt = (
        base
        .join(sbom_subq, AnalysisRun.sbom_id == sbom_subq.c.sbom_id)
        .add_columns(sbom_subq.c.sbom_name)
        .order_by(AnalysisRun.id.desc())
        .limit(page_size)
        .offset(offset)
    )

    #  Execute
    rows = db.execute(stmt).all()

    #  Format response
    items = []
    for run, sbom_name in rows:
        run_dict = {**{k: v for k, v in run.__dict__.items() if not k.startswith("_")},"sbom_name": sbom_name}
        items.append(run_dict)

    #  Header
    if response is not None:
        response.headers["X-Total-Count"] = str(total)

    return items

@app.get("/api/runs/{run_id}", response_model=AnalysisRunOut)
def get_analysis_run(run_id: int, db: Session = Depends(get_db)):
    run = db.get(AnalysisRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    return run

@app.get("/api/runs/{run_id}/findings", response_model=list[AnalysisFindingOut])
def list_run_findings(
    run_id: int,
    severity: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=1000),
    response: Response = None,
    db: Session = Depends(get_db),
):
    run = db.get(AnalysisRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Analysis run not found")

    page = 1 if page < 1 else page
    page_size = max(1, min(page_size, 1000))
    offset = (page - 1) * page_size

    base = select(AnalysisFinding).where(AnalysisFinding.analysis_run_id == run_id)
    count = select(func.count(AnalysisFinding.id)).where(AnalysisFinding.analysis_run_id == run_id)

    if severity:
        norm = severity.strip().upper()
        base = base.where(AnalysisFinding.severity == norm)
        count = count.where(AnalysisFinding.severity == norm)

    total = db.execute(count).scalar_one()

    stmt = base.order_by(AnalysisFinding.score.desc()).limit(page_size).offset(offset)
    items = db.execute(stmt).scalars().all()

    if response is not None:
        response.headers["X-Total-Count"] = str(total)

    return items
    
# -----------------------------
# Projects CRUD
# -----------------------------
@app.post("/api/projects", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db)):
    try:
        # Check if project already exists
        existing_project = db.query(Projects).filter(
            Projects.project_name == payload.project_name
        ).first()

        if existing_project:
            raise HTTPException(
                status_code=400,
                detail="Project with this name already exists"
            )

        # Create new project
        obj = Projects(**payload.model_dump(), created_on=now_iso())
        db.add(obj)
        db.commit()
        db.refresh(obj)

        return obj

    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail="Duplicate project name not allowed"
        )

    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Something went wrong: {str(e)}"
        )

def _validate_project_id(value: int) -> int:
    if not isinstance(value, int):
        raise HTTPException(status_code=422, detail="'project_id' must be an integer.")
    if value < 1:
        raise HTTPException(status_code=422, detail="'project_id' must be a positive integer (>= 1).")
    return value

@app.get("/api/projects/{project_id}", response_model=ProjectOut)
def get_project_details(
    project_id: int = Path(..., description="Project ID (positive integer)"),
    db: Session = Depends(get_db)
):
    project_id = _validate_project_id(project_id)
    try:
        project = db.get(Projects, project_id)
        if not project:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
        return project
    except HTTPException:
        raise
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="Internal database error while fetching project details.") from exc

@app.get("/api/projects", response_model=list[ProjectOut])
def list_projects(db: Session = Depends(get_db)):
    return db.execute(select(Projects).order_by(Projects.id.desc())).scalars().all()

@app.patch("/api/projects/{project_id}", response_model=ProjectOut)
def update_project(
    project_id: int = Path(..., description="Project ID (positive integer)"),
    payload: ProjectUpdate = ...,
    user_id: Optional[str] = Query(
        None,
        description="Optional: if provided, must match Projects.created_by (letters/digits/_/./-, 1–64)"
    ),
    db: Session = Depends(get_db),
):
    project_id = _validate_positive_int(project_id, "project_id")
    user_id = _validate_user_id(user_id)
    data = payload.model_dump(exclude_unset=True, exclude_none=True)
    if not data:
        raise HTTPException(status_code=422, detail="No updatable fields provided in payload.")

    try:
        project = db.get(Projects, project_id)
        if not project:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

        if user_id is not None:
            if (project.created_by or "").strip().lower() != user_id.lower():
                raise HTTPException(status_code=403, detail="Forbidden: user cannot update this Project")

        for k, v in data.items():
            setattr(project, k, v)

        project.modified_on = now_iso()
        project.modified_by = data.get("modified_by") or user_id or project.modified_by

        db.add(project)
        db.commit()
        db.refresh(project)
        return project
    except HTTPException:
        raise
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="Internal database error while updating project.") from exc

@app.delete("/api/projects/{project_id}", status_code=status.HTTP_200_OK)
def delete_project(
    project_id: int,
    user_id: Optional[str] = Query(
        None,
        description="Optional: if provided, must match Projects.created_by"
    ),
    confirm: str = Query("no", description="Set to 'yes' to confirm deletion"),
    db: Session = Depends(get_db),
):
    project = db.get(Projects, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Optional ownership check if user_id provided
    if user_id is not None:
        if (project.created_by or "").strip().lower() != (user_id or "").strip().lower():
            raise HTTPException(status_code=403, detail="Forbidden: user cannot delete this Project")

    # Block deletion if dependencies exist
    has_sboms = db.execute(
        select(SBOMSource.id).where(SBOMSource.projectid == project_id).limit(1)
    ).scalar_one_or_none()
    has_runs = db.execute(
        select(AnalysisRun.id).where(AnalysisRun.project_id == project_id).limit(1)
    ).scalar_one_or_none()
    if has_sboms or has_runs:
        raise HTTPException(
            status_code=409,
            detail="Cannot delete Project: SBOMs or Analysis Runs exist. Delete/reassign them first."
        )

    # Confirmation gate
    if (confirm or "").strip().lower() not in {"yes", "y"}:
        return {
            "status": "pending_confirmation",
            "message": "This will permanently delete the Project. Re-send with confirm=yes to proceed.",
            "example": f"/api/projects/{project_id}?confirm=yes"
        }

    db.delete(project)
    db.commit()
    return {
        "status": "deleted",
        "message": f"Project {project_id} deleted successfully."
    }

# ---------- NEW: request payloads for DB-backed analysis ----------
class AnalysisByRefNVD(BaseModel):
    sbom_id: Optional[int] = None
    sbom_name: Optional[str] = None
    nvd_api_key: Optional[str] = None
    results_per_page: int = DEFAULT_RESULTS_PER_PAGE

class AnalysisByRefGitHub(BaseModel):
    sbom_id: Optional[int] = None
    sbom_name: Optional[str] = None
    github_token: Optional[str] = None  # falls back to env if None
    first: int = 100

class AnalysisByRefOSV(BaseModel):
    sbom_id: Optional[int] = None
    sbom_name: Optional[str] = None
    hydrate: bool = True

class AnalysisByRefConsolidated(BaseModel):
    sbom_id: Optional[int] = None
    sbom_name: Optional[str] = None
    nvd_api_key: Optional[str] = None
    results_per_page: int = DEFAULT_RESULTS_PER_PAGE
    github_token: Optional[str] = None
    first: int = 100
    osv_hydrate: bool = True

# -----------------------------
# NVD (DB-backed: sbom_id / sbom_name)
# -----------------------------
@app.post("/analyze-sbom-nvd")
def analyze_sbom_nvd(payload: AnalysisByRefNVD, db: Session = Depends(get_db)):
    if payload.sbom_id is None and not (payload.sbom_name and payload.sbom_name.strip()):
        raise HTTPException(status_code=422, detail="Provide 'sbom_id' or 'sbom_name' in request body")

    log.info("NVD analysis started: sbom_id=%s sbom_name=%s", payload.sbom_id, payload.sbom_name)
    t0 = time.perf_counter()

    sbom_row, _, sbom_format, spec_version, components = _load_sbom_from_ref(
        db, sbom_id=payload.sbom_id, sbom_name=payload.sbom_name
    )
    if not components:
        raise HTTPException(status_code=400, detail="No components detected in SBOM.")

    component_results: list[dict] = []
    total_errors = 0
    total_cves = 0
    with_cpe = sum(1 for c in components if c.get("cpe"))
    nvd_api_key = payload.nvd_api_key
    rpp = payload.results_per_page

    for comp in components:
        cname = comp.get("name", "")
        cver = comp.get("version", "")
        ccpe = comp.get("cpe")
        result = {"name": cname, "version": cver, "purl": comp.get("purl"), "cpe": ccpe, "cves": [], "error": None}
        try:
            nvd_json = nvd_fetch(cname, cver, ccpe, nvd_api_key, rpp)
            vulns = extract_vuln_records(nvd_json)
            result["cves"] = vulns
            total_cves += len(vulns)
        except requests.exceptions.RequestException as e:
            result["error"] = f"NVD request failed: {e}"
            total_errors += 1
        except Exception as e:
            result["error"] = f"Unexpected error: {e}"
            total_errors += 1
        component_results.append(result)

    all_vulns = [v for comp in component_results for v in comp.get("cves", [])]
    sev = severity_buckets(all_vulns)
    run_status = "PARTIAL" if total_errors > 0 else "PASS"
    duration_ms = int((time.perf_counter() - t0) * 1000)
    log.info(
        "NVD analysis complete: sbom='%s' components=%d findings=%d errors=%d status=%s duration=%dms",
        sbom_row.sbom_name, len(components), total_cves, total_errors, run_status, duration_ms,
    )

    run_record = {
        "status": run_status,
        "sbom": {"id": sbom_row.id, "name": sbom_row.sbom_name, "format": sbom_format, "specVersion": spec_version},
        "summary": {
            "components": len(components),
            "withCPE": with_cpe,
            "findings": {"total": total_cves, "bySeverity": sev},
            "errors": total_errors,
            "durationMs": duration_ms,
            "completedOn": now_iso(),
        },
        "components": component_results,
    }
    run_id = store_run_cache(db, run_record)
    run_record["runId"] = run_id
    log.debug("NVD run persisted: run_id=%d", run_id)
    return JSONResponse(run_record)


# -----------------------------
# GHSA (DB-backed: sbom_id / sbom_name)
# -----------------------------
@app.post("/analyze-sbom-github")
def analyze_sbom_github(payload: AnalysisByRefGitHub, db: Session = Depends(get_db)):
    log.info("GitHub Advisory analysis started: sbom_id=%s sbom_name=%s", payload.sbom_id, payload.sbom_name)
    t0 = time.perf_counter()

    sbom_row, _, sbom_format, spec_version, components = _load_sbom_from_ref(
        db, sbom_id=payload.sbom_id, sbom_name=payload.sbom_name
    )
    if not components:
        raise HTTPException(status_code=400, detail="No components detected in SBOM.")

    token = (payload.github_token or os.getenv("GITHUB_TOKEN") or "").strip()
    token_error = None if token else "GitHub token not provided. Supply 'github_token' or set env GITHUB_TOKEN."

    component_results: list[dict] = []
    total_errors = 0
    total_items = 0
    with_purl = sum(1 for c in components if c.get("purl"))

    for comp in components:
        cname = comp.get("name", "")
        cver = comp.get("version", "")
        cpurl = comp.get("purl")
        ecosystem, pkg_name = (None, None)
        if cpurl:
            ecosystem, pkg_name = gh_pkg_from_purl(cpurl)

        result = {
            "name": cname, "version": cver, "purl": cpurl,
            "ecosystem": ecosystem, "package": pkg_name,
            "advisories": [], "error": None
        }

        if token_error:
            result["error"] = token_error
            total_errors += 1
        elif not ecosystem or not pkg_name:
            result["error"] = "No supported PURL/ecosystem to query GitHub for this component."
            total_errors += 1
        else:
            try:
                gh_json = github_fetch_advisories(ecosystem, pkg_name, token, first=payload.first)
                advisories = extract_ghsa_records(gh_json, cver)
                result["advisories"] = advisories
                total_items += len(advisories)
            except requests.exceptions.RequestException as e:
                result["error"] = f"GitHub request failed: {e}"
                total_errors += 1
            except HTTPException as e:
                result["error"] = str(e.detail)
                total_errors += 1
            except Exception as e:
                result["error"] = f"Unexpected error: {e}"
                total_errors += 1

        component_results.append(result)

    all_items = [v for comp in component_results for v in comp.get("advisories", [])]
    sev = severity_buckets(all_items)
    run_status = "FAIL" if (total_errors > 0 and total_errors == len(components)) else ("PARTIAL" if total_errors > 0 else "PASS")
    duration_ms = int((time.perf_counter() - t0) * 1000)
    log.info(
        "GitHub analysis complete: sbom='%s' components=%d findings=%d errors=%d status=%s duration=%dms",
        sbom_row.sbom_name, len(components), len(all_items), total_errors, run_status, duration_ms,
    )

    run_record = {
        "status": run_status,
        "sbom": {"id": sbom_row.id, "name": sbom_row.sbom_name, "format": sbom_format, "specVersion": spec_version},
        "summary": {
            "components": len(components),
            "withPURL": with_purl,
            "findings": {"total": len(all_items), "bySeverity": sev},
            "errors": total_errors,
            "durationMs": duration_ms,
            "completedOn": now_iso(),
        },
        "components": component_results,
    }
    run_id = store_run_cache(db, run_record)
    run_record["runId"] = run_id
    return JSONResponse(run_record)


# -----------------------------
# OSV (DB-backed: sbom_id / sbom_name)
# -----------------------------
@app.post("/analyze-sbom-osv")
def analyze_sbom_osv(payload: AnalysisByRefOSV, db: Session = Depends(get_db)):
    log.info("OSV analysis started: sbom_id=%s sbom_name=%s", payload.sbom_id, payload.sbom_name)
    t0 = time.perf_counter()

    sbom_row, _, sbom_format, spec_version, components = _load_sbom_from_ref(
        db, sbom_id=payload.sbom_id, sbom_name=payload.sbom_name
    )
    if not components:
        raise HTTPException(status_code=400, detail="No components detected in SBOM.")

    queries: list[dict] = []
    comp_to_q_idx: list[Optional[int]] = []
    for comp in components:
        q = _build_osv_query_for_component(
            name=comp.get("name", ""),
            version_str=comp.get("version", ""),
            purl=comp.get("purl"),
        )
        if q is None:
            comp_to_q_idx.append(None)
        else:
            comp_to_q_idx.append(len(queries))
            queries.append(q)

    with_purl = sum(1 for c in components if c.get("purl"))
    if not queries:
        raise HTTPException(status_code=400, detail="No PURLs present to query OSV. Provide PURLs for OSV analysis.")

    try:
        osv_results = osv_querybatch(queries)
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=502, detail=f"OSV request failed: {e}")

    component_results: list[dict] = []
    all_osv_ids: set[str] = set()

    for idx, comp in enumerate(components):
        q_idx = comp_to_q_idx[idx]
        entry = {
            "name": comp.get("name", ""),
            "version": comp.get("version", ""),
            "purl": comp.get("purl"),
            "advisories": [],
            "error": None
        }
        if q_idx is None:
            entry["error"] = "No PURL to query OSV for this component."
        else:
            res = osv_results[q_idx] if q_idx < len(osv_results) else {"vulns": []}
            vulns = res.get("vulns") or []
            entry["advisories"] = [{"id": v.get("id"), "modified": v.get("modified")} for v in vulns if v.get("id")]
            for v in vulns:
                if v.get("id"):
                    all_osv_ids.add(v["id"])
        component_results.append(entry)

    hydrated_map: dict[str, dict] = {}
    if payload.hydrate and all_osv_ids:
        for oid in all_osv_ids:
            try:
                full = osv_get_vuln_by_id(oid)
                hydrated_map[oid] = extract_osv_record(full)
            except requests.exceptions.RequestException:
                continue
        for comp in component_results:
            for adv in comp.get("advisories") or []:
                if adv.get("id") in hydrated_map:
                    adv.update({k: v for k, v in hydrated_map[adv["id"]].items() if k not in ("id",)})

    all_items = [adv for comp in component_results for adv in (comp.get("advisories") or [])]
    buckets = severity_buckets(all_items) if hydrated_map else {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": len(all_items)}

    duration_ms = int((time.perf_counter() - t0) * 1000)
    log.info(
        "OSV analysis complete: sbom='%s' components=%d findings=%d duration=%dms",
        sbom_row.sbom_name, len(components), len(all_items), duration_ms,
    )

    run_record = {
        "status": "PASS",
        "sbom": {"id": sbom_row.id, "name": sbom_row.sbom_name, "format": sbom_format, "specVersion": spec_version},
        "summary": {
            "components": len(components),
            "withPURL": with_purl,
            "findings": {"total": len(all_items), "bySeverity": buckets},
            "errors": sum(1 for c in component_results if c.get("error")),
            "durationMs": duration_ms,
            "completedOn": now_iso(),
        },
        "components": component_results
    }
    run_id = store_run_cache(db, run_record)
    run_record["runId"] = run_id
    return JSONResponse(run_record)


# -----------------------------
# Consolidated (DB-backed)
# -----------------------------
@app.post("/analyze-sbom-consolidated")
def analyze_sbom_consolidated(payload: AnalysisByRefConsolidated, db: Session = Depends(get_db)):
    log.info("Consolidated analysis started (NVD+GHSA+OSV): sbom_id=%s sbom_name=%s", payload.sbom_id, payload.sbom_name)
    t0 = time.perf_counter()

    sbom_row, _, sbom_format, spec_version, components = _load_sbom_from_ref(
        db, sbom_id=payload.sbom_id, sbom_name=payload.sbom_name
    )
    if not components:
        log.warning("Consolidated analysis: no components found in SBOM id=%s", payload.sbom_id)
        raise HTTPException(status_code=400, detail="No components detected in SBOM.")

    # Augment components with CPE from PURL when missing (for NVD)
    components, _cpe_generated = _augment_components_with_cpe(components)

    # --- NVD ---
    nvd_component_results: list[dict] = []
    total_nvd_errors = 0
    total_nvd_items = 0
    with_cpe = sum(1 for c in components if c.get("cpe"))
    for comp in components:
        result = {"name": comp.get("name", ""), "version": comp.get("version", ""), "purl": comp.get("purl"),
                  "cpe": comp.get("cpe"), "cves": [], "error": None}
        try:
            nvd_json = nvd_fetch(result["name"], result["version"], result["cpe"],
                                 payload.nvd_api_key, payload.results_per_page)
            vulns = extract_vuln_records(nvd_json)
            result["cves"] = vulns
            total_nvd_items += len(vulns)
        except requests.exceptions.RequestException as e:
            result["error"] = f"NVD request failed: {e}"
            total_nvd_errors += 1
        except Exception as e:
            result["error"] = f"Unexpected error: {e}"
            total_nvd_errors += 1
        nvd_component_results.append(result)

    # --- GHSA ---
    token = (payload.github_token or os.getenv("GITHUB_TOKEN") or "").strip()
    ghsa_token_err = None if token else "GitHub token not provided; GHSA will be skipped for all components."
    ghsa_component_results: list[dict] = []
    total_ghsa_errors = 0
    total_ghsa_items = 0
    with_purl = sum(1 for c in components if c.get("purl"))
    for comp in components:
        cname = comp.get("name", "")
        cver = comp.get("version", "")
        cpurl = comp.get("purl")
        eco, pkg = (None, None)
        if cpurl:
            eco, pkg = gh_pkg_from_purl(cpurl)

        result = {"name": cname, "version": cver, "purl": cpurl, "ecosystem": eco, "package": pkg,
                  "advisories": [], "error": None}

        if ghsa_token_err:
            result["error"] = ghsa_token_err
        elif not eco or not pkg:
            result["error"] = "No supported PURL/ecosystem to query GitHub for this component."
            total_ghsa_errors += 1
        else:
            try:
                gh_json = github_fetch_advisories(eco, pkg, token, first=payload.first)
                advisories = extract_ghsa_records(gh_json, cver)
                result["advisories"] = advisories
                total_ghsa_items += len(advisories)
            except requests.exceptions.RequestException as e:
                result["error"] = f"GitHub request failed: {e}"
                total_ghsa_errors += 1
            except HTTPException as e:
                result["error"] = str(e.detail)
                total_ghsa_errors += 1
            except Exception as e:
                result["error"] = f"Unexpected error: {e}"
                total_ghsa_errors += 1
        ghsa_component_results.append(result)

    # --- OSV ---
    queries: list[dict] = []
    comp_to_q_idx: list[Optional[int]] = []
    for comp in components:
        q = _build_osv_query_for_component(
            name=comp.get("name", ""), version_str=comp.get("version", ""), purl=comp.get("purl")
        )
        if q is None:
            comp_to_q_idx.append(None)
        else:
            comp_to_q_idx.append(len(queries))
            queries.append(q)

    osv_component_results: list[dict] = []
    total_osv_errors = 0
    total_osv_items = 0
    hydrated_map: dict[str, dict] = {}
    osv_ids_all: set[str] = set()

    if queries:
        try:
            osv_batch = osv_querybatch(queries)
        except requests.exceptions.RequestException as e:
            for idx, comp in enumerate(components):
                entry = {"name": comp.get("name", ""), "version": comp.get("version", ""), "purl": comp.get("purl"),
                         "advisories": [], "error": f"OSV request failed: {e}"}
                if comp_to_q_idx[idx] is not None:
                    total_osv_errors += 1
                osv_component_results.append(entry)
            osv_batch = []
        else:
            temp_results = []
            for comp_idx, comp in enumerate(components):
                q_idx = comp_to_q_idx[comp_idx]
                entry = {"name": comp.get("name", ""), "version": comp.get("version", ""), "purl": comp.get("purl"),
                         "advisories": [], "error": None}
                if q_idx is None:
                    entry["error"] = "No PURL to query OSV for this component."
                else:
                    res = osv_batch[q_idx] if q_idx < len(osv_batch) else {"vulns": []}
                    vulns = res.get("vulns") or []
                    entry["advisories"] = [{"id": v.get("id"), "modified": v.get("modified")} for v in vulns if v.get("id")]
                    total_osv_items += len(vulns)
                    for v in vulns:
                        if v.get("id"):
                            osv_ids_all.add(v["id"])
                temp_results.append(entry)
            osv_component_results = temp_results
    else:
        for comp in components:
            osv_component_results.append({"name": comp.get("name", ""), "version": comp.get("version", ""),
                                          "purl": comp.get("purl"), "advisories": [], "error": "No PURL to query OSV for this component."})
            total_osv_errors += 1

    if payload.osv_hydrate and osv_ids_all:
        for oid in osv_ids_all:
            try:
                full = osv_get_vuln_by_id(oid)
                hydrated_map[oid] = extract_osv_record(full)
            except requests.exceptions.RequestException:
                continue
        for comp in osv_component_results:
            for adv in comp.get("advisories") or []:
                if adv.get("id") in hydrated_map:
                    adv.update({k: v for k, v in hydrated_map[adv["id"]].items() if k not in ("id",)})

    # --- Merge per component ---
    def _nvd_to_merge(v: dict) -> dict:
        return {"id": v.get("id"), "severity": (v.get("severity") or "UNKNOWN").upper(), "score": v.get("score"),
                "vector": v.get("vector"), "published": v.get("published"), "url": v.get("url"),
                "aliases": [v["id"]] if v.get("id") else []}
    def _ghsa_to_merge(v: dict) -> dict:
        return {"id": v.get("id"), "severity": (v.get("severity") or "UNKNOWN").upper(), "score": v.get("score"),
                "vector": v.get("vector"), "published": v.get("published"), "url": v.get("url"),
                "aliases": [v["id"]] if v.get("id") else []}
    def _osv_to_merge(v: dict) -> dict:
        return {"id": v.get("id"), "severity": (v.get("severity") or "UNKNOWN").upper(), "score": v.get("score"),
                "vector": v.get("vector"), "published": v.get("published"), "url": v.get("url"),
                "aliases": list(v.get("aliases") or []) + ([v["id"]] if v.get("id") else [])}

    consolidated_components = []
    total_combined = 0
    combined_buckets_all = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for i in range(len(components)):
        comp = components[i]
        nvd_raw = nvd_component_results[i].get("cves") or []
        ghsa_raw = ghsa_component_results[i].get("advisories") or []
        osv_raw = osv_component_results[i].get("advisories") or []
        nvd_list = [_nvd_to_merge(v) for v in nvd_raw if isinstance(v, dict)]
        ghsa_list = [_ghsa_to_merge(v) for v in ghsa_raw if isinstance(v, dict)]
        osv_list = [_osv_to_merge(v) for v in osv_raw if isinstance(v, dict)]
        combined_list, buckets = combine_component_findings(nvd_list, ghsa_list, osv_list)
        for sev, count in buckets.items():
            combined_buckets_all[sev] = combined_buckets_all.get(sev, 0) + count
        total_combined += len(combined_list)
        # API shape: component name, version, purl, cpe, vulnerabilities, severity, score, source, combined
        comp_cpe = comp.get("cpe") or nvd_component_results[i].get("cpe")
        entry = {
            "name": comp.get("name", ""),
            "version": comp.get("version", ""),
            "purl": comp.get("purl"),
            "cpe": comp_cpe,
            "vulnerabilities": combined_list,
            "severity": buckets,
            "score": max((v.get("score") for v in combined_list if v.get("score") is not None), default=None),
            "source": sorted(set(s for v in combined_list for s in (v.get("sources") or []))),
            "combined": combined_list,
        }
        consolidated_components.append(entry)

    if total_nvd_errors or total_ghsa_errors or total_osv_errors:
        status_consolidated = "PARTIAL"
    elif total_combined > 0:
        status_consolidated = "FAIL"
    else:
        status_consolidated = "PASS"
    duration_ms = int((time.perf_counter() - t0) * 1000)
    total_errors_all = total_nvd_errors + total_ghsa_errors + total_osv_errors
    log.info(
        "Consolidated analysis complete: sbom='%s' components=%d findings=%d "
        "errors=%d (nvd=%d ghsa=%d osv=%d) status=%s duration=%dms",
        sbom_row.sbom_name, len(components), total_combined,
        total_errors_all, total_nvd_errors, total_ghsa_errors, total_osv_errors,
        status_consolidated, duration_ms,
    )
    run_record = {
        "status": status_consolidated,
        "sbom": {"id": sbom_row.id, "name": sbom_row.sbom_name, "format": sbom_format, "specVersion": spec_version},
        "summary": {
            "components": len(components),
            "withCPE": with_cpe,
            "withPURL": with_purl,
            "findings": {"total": total_combined, "bySeverity": combined_buckets_all},
            "errors": total_errors_all,
            "durationMs": duration_ms,
            "completedOn": now_iso(),
        },
        "components": consolidated_components,
    }
    run_id = store_run_cache(db, run_record)
    run_record["runId"] = run_id
    log.debug("Consolidated run persisted: run_id=%d", run_id)
    return JSONResponse(run_record)


# -------------------------------
# PDF Report API
# -------------------------------
class PdfReportRequest(BaseModel):
    run: Dict[str, Any]
    title: Optional[str] = "SBOM Vulnerability Report"
    filename: Optional[str] = "sbom_report.pdf"

# -------------------------------
# PDF Report (JSON input with runId)
# -------------------------------

class PdfReportByIdRequest(BaseModel):
    runId: int
    title: Optional[str] = "SBOM Vulnerability Report"
    filename: Optional[str] = "sbom_report.pdf"  # optional

@app.post("/api/pdf-report", response_class=Response)
async def create_pdf_report_by_run_id(
    payload: PdfReportByIdRequest,
    db: Session = Depends(get_db),
):
    """
    Accepts JSON with { runId, title?, filename? }.
    Loads the run from the database, generates a PDF and returns it as a download.
    """
    log.info("PDF report requested: run_id=%d filename=%s", payload.runId, payload.filename)
    run_id = payload.runId
    run = load_run_cache(db, run_id)
    if run is None:
        log.warning("PDF report: run_id=%d not found in cache", run_id)
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found.")

    filename = payload.filename or "sbom_report.pdf"
    if not filename.lower().endswith(".pdf"):
        filename = f"{filename}.pdf"

    title = payload.title or "SBOM Vulnerability Report"

    try:
        pdf_bytes = build_pdf_from_run_bytes(run, title=title)
        log.info("PDF generated: run_id=%d size=%d bytes", run_id, len(pdf_bytes))
    except Exception as e:
        log.error("PDF generation failed: run_id=%d error=%s", run_id, e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {e}")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

# # -----------------------------
# # Legacy analysis reports CRUD
# # -----------------------------
# @app.post("/api/analysis", response_model=SBOMAnalysisReportOut, status_code=status.HTTP_201_CREATED)
# def create_report(payload: SBOMAnalysisReportCreate, db: Session = Depends(get_db)):
#     obj = SBOMAnalysisReport(**payload.model_dump(), created_on=now_iso())
#     db.add(obj)
#     db.commit()
#     db.refresh(obj)
#     return obj

# @app.get("/api/analysis", response_model=list[SBOMAnalysisReportOut])
# def list_reports(
#     project_id: Optional[str] = Query(None),
#     sbom_ref_id: Optional[int] = Query(None),
#     db: Session = Depends(get_db),
# ):
#     stmt = select(SBOMAnalysisReport).order_by(SBOMAnalysisReport.id.desc())
#     if project_id:
#         stmt = stmt.where(SBOMAnalysisReport.project_id == project_id)
#     if sbom_ref_id is not None:
#         stmt = stmt.where(SBOMAnalysisReport.sbom_ref_id == sbom_ref_id)
#     return db.execute(stmt).scalars().all()

# @app.get("/api/analysis/{report_id}", response_model=SBOMAnalysisReportOut)
# def get_analysis_report(report_id: int, db: Session = Depends(get_db)):
#     report = db.get(SBOMAnalysisReport, report_id)
#     if not report:
#         raise HTTPException(status_code=404, detail="Analysis report not found")
#     return report

# # ------------------------------------
# # Ad-hoc multi-source analysis endpoint
# # ------------------------------------
# class AnalysisRunRequest(BaseModel):
#     sbom_data: str
#     sources: Optional[list[str]] = None  # e.g., ["NVD","OSV","GITHUB"]

# @app.post("/api/analysis/run")
# def run_analysis(payload: AnalysisRunRequest):
#     """
#     Stateless analysis for a raw SBOM payload (not persisted).
#     Uses the multi-source analyzer and returns normalized details.
#     """
#     try:
#         settings = get_analysis_settings_multi()
#         details = analyze_sbom_multi_source(
#             sbom_json=payload.sbom_data,
#             sources=payload.sources,
#             settings=settings,
#         )
#         # Optionally add per-call component counts to buckets
#         try:
#             components = extract_components(payload.sbom_data)
#         except Exception:
#             components = []
#         details = normalize_details(details, components or [])
#     except ValueError as exc:
#         raise HTTPException(status_code=400, detail=str(exc)) from exc
#     except Exception as exc:
#         raise HTTPException(status_code=500, detail=str(exc)) from exc

#     report_status = compute_report_status(
#         safe_int(details.get("total_findings")), details.get("query_errors") or []
#     )
#     return {"sbom_result": report_status, "analysis_details": details}

# -----------------------------
# Dashboard endpoints
# -----------------------------
@app.get("/dashboard/stats")
def dashboard_stats(db: Session = Depends(get_db)):
    """Summary counts for the home dashboard cards."""
    total_projects = db.execute(select(func.count(Projects.id))).scalar_one()
    total_sboms = db.execute(select(func.count(SBOMSource.id))).scalar_one()
    total_vulnerabilities = db.execute(select(func.count(AnalysisFinding.id))).scalar_one()
    return {
        "total_projects": total_projects,
        "total_sboms": total_sboms,
        "total_vulnerabilities": total_vulnerabilities,
    }


@app.get("/dashboard/recent-sboms")
def dashboard_recent_sboms(
    limit: int = Query(5, ge=1, le=50),
    db: Session = Depends(get_db),
):
    """Most recently uploaded SBOMs for the home dashboard list."""
    items = db.execute(
        select(SBOMSource).order_by(SBOMSource.id.desc()).limit(limit)
    ).scalars().all()
    return [
        {"id": s.id, "sbom_name": s.sbom_name, "created_on": s.created_on}
        for s in items
    ]


@app.get("/dashboard/activity")
def dashboard_activity(db: Session = Depends(get_db)):
    """Active vs stale SBOM counts for the activity doughnut chart."""
    from datetime import timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    active = db.execute(
        select(func.count(SBOMSource.id)).where(SBOMSource.created_on >= cutoff)
    ).scalar_one()
    total = db.execute(select(func.count(SBOMSource.id))).scalar_one()
    return {"active_30d": active, "stale": max(0, total - active)}


@app.get("/dashboard/severity")
def dashboard_severity(db: Session = Depends(get_db)):
    """Aggregate severity counts across all findings for the severity chart."""
    rows = db.execute(
        select(AnalysisFinding.severity, func.count(AnalysisFinding.id))
        .group_by(AnalysisFinding.severity)
    ).all()
    buckets: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for sev, cnt in rows:
        key = (sev or "unknown").lower()
        if key in buckets:
            buckets[key] += cnt
        else:
            buckets["unknown"] += cnt
    return buckets


# -----------------------------
# Serve frontend at / (must be last so /api and /dashboard take precedence)
# -----------------------------
_FRONTEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend")
if os.path.isdir(_FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=_FRONTEND_DIR, html=True), name="frontend")
