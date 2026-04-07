"""
Analysis endpoints router for NVD, GitHub, OSV, and consolidated analysis.

Routes:
  POST /analyze-sbom-nvd             NVD-only analysis
  POST /analyze-sbom-github          GitHub Advisory analysis
  POST /analyze-sbom-osv             OSV analysis
  POST /analyze-sbom-consolidated    Combined NVD+GHSA+OSV analysis
"""
import json
import logging
import os
import time
import requests
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import SBOMSource, RunCache
from ..settings import get_settings
from ..services.sbom_service import now_iso, load_sbom_from_ref as _load_sbom_from_ref
from ..services.pdf_service import store_run_cache
from ..services.vuln_sources import (
    nvd_fetch,
    extract_vuln_records,
    severity_buckets,
    gh_pkg_from_purl,
    github_fetch_advisories,
    extract_ghsa_records,
    _build_osv_query_for_component,
    osv_querybatch,
    osv_get_vuln_by_id,
    extract_osv_record,
    combine_component_findings,
)
from ..analysis import _augment_components_with_cpe

DEFAULT_RESULTS_PER_PAGE = get_settings().DEFAULT_RESULTS_PER_PAGE

log = logging.getLogger(__name__)

router = APIRouter(tags=["analyze"])


# ---- Request Models ----

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


# ---- NVD Analysis ----

@router.post("/analyze-sbom-nvd")
def analyze_sbom_nvd(payload: AnalysisByRefNVD, db: Session = Depends(get_db)):
    """Run NVD-only analysis on an SBOM (by id or name)."""
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


# ---- GitHub Advisory Analysis ----

@router.post("/analyze-sbom-github")
def analyze_sbom_github(payload: AnalysisByRefGitHub, db: Session = Depends(get_db)):
    """Run GitHub Advisory analysis on an SBOM (by id or name)."""
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


# ---- OSV Analysis ----

@router.post("/analyze-sbom-osv")
def analyze_sbom_osv(payload: AnalysisByRefOSV, db: Session = Depends(get_db)):
    """Run OSV analysis on an SBOM (by id or name)."""
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


# ---- Consolidated (NVD + GitHub + OSV) Analysis ----

@router.post("/analyze-sbom-consolidated")
def analyze_sbom_consolidated(payload: AnalysisByRefConsolidated, db: Session = Depends(get_db)):
    """Run consolidated analysis (NVD+GHSA+OSV) on an SBOM (by id or name)."""
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
