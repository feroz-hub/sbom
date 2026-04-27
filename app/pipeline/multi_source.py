"""
Multi-source SBOM analysis pipeline (async).

Orchestrates parse → enrich → concurrent source queries → dedupe → summary.
Implementation extracted from ``app.analysis`` for clarity and testing.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ..parsing import extract_components
from ..sources.dedupe import deduplicate_findings


async def run_multi_source_analysis_async(
    sbom_json: str,
    sources: list[str] | None = None,
    settings: Any | None = None,
) -> dict:
    """
    Asynchronously analyze an SBOM against the selected sources.

    sources: ["NVD","OSV","GITHUB","VULNDB"]; if None, read env ANALYSIS_SOURCES or default ["NVD","OSV","GITHUB"].
    Returns a normalized dict compatible with the existing API.
    """
    # Late import: ``analysis`` must be fully initialized (this module is loaded from it).
    from ..analysis import (
        LOGGER,
        AnalysisSource,
        _augment_components_with_cpe,
        _env_list,
        _executor,
        _finding_from_raw,
        enrich_component_for_osv,
        get_analysis_settings_multi,
        github_query_by_components,
        nvd_query_by_cpe,
        nvd_query_by_keyword,
        osv_query_by_components,
        resolve_nvd_api_key,
    )
    from ..credentials import vulndb_api_key_for_adapters
    from ..sources.vulndb import VulnDbSource

    cfg = settings or get_analysis_settings_multi()
    components = extract_components(sbom_json)
    LOGGER.debug("Extracted %d components from SBOM", len(components))

    components = [enrich_component_for_osv(c) for c in components]
    components_w_cpe, generated_cpe_count = _augment_components_with_cpe(components)
    LOGGER.debug(
        "CPE augmentation: %d components total, %d CPEs generated",
        len(components_w_cpe),
        generated_cpe_count,
    )

    default_sources = _env_list(cfg.analysis_sources_env, ["NVD", "OSV", "GITHUB"])
    selected = [s.strip().upper() for s in (sources or default_sources)]
    selected_enum: set[AnalysisSource] = set()
    for s in selected:
        try:
            selected_enum.add(AnalysisSource[s])
        except KeyError:
            LOGGER.warning("Unknown analysis source ignored: %s", s)

    # NOTE: historically NVD was removed from `selected_enum` when no
    # component had a CPE. That produced the "NVD returns 0 findings"
    # behaviour for SBOMs whose components ship only name+version (e.g.
    # minimal SPDX) or PURLs whose type is not in `cpe23_from_purl`'s
    # switch. The new keyword-search fallback inside `_nvd()` can still
    # return findings for those components, so we keep NVD selected and
    # let `_nvd()` decide per-component whether to use cpeName/virtualMatch
    # or keywordSearch.

    LOGGER.info(
        "Starting multi-source analysis: sources=%s components=%d",
        [s.name for s in selected_enum],
        len(components_w_cpe),
    )

    all_findings: list[dict] = []
    query_errors: list[dict] = []
    query_warnings: list[dict] = []

    async def _nvd() -> None:
        nonlocal all_findings, query_errors

        # Phase 1 — CPE inventory (precise lookups via cpeName / virtualMatchString).
        cpe_set: set[str] = set()
        name_by_cpe: dict[str, tuple[str, str | None]] = {}
        for comp in components_w_cpe:
            cpe = comp.get("cpe")
            if cpe:
                cpe_set.add(cpe)
                name_by_cpe[cpe] = (comp.get("name") or "", comp.get("version"))

        # Phase 2 — keyword inventory (fallback for components with no CPE).
        # Mirrors the standalone ``nvd_scan.py`` behaviour so SBOMs whose
        # components lack a CPE / mappable PURL still get findings.
        keyword_targets: dict[tuple[str, str | None], tuple[str, str | None]] = {}
        if getattr(cfg, "nvd_keyword_fallback_enabled", True):
            for comp in components_w_cpe:
                if comp.get("cpe"):
                    continue
                raw_name = (comp.get("name") or "").strip()
                if not raw_name:
                    continue
                version_raw = comp.get("version")
                version = (version_raw or "").strip() or None
                dedup_key = (raw_name.lower(), (version or "").lower() or None)
                if dedup_key in keyword_targets:
                    continue
                keyword_targets[dedup_key] = (raw_name, version)

        if not cpe_set and not keyword_targets:
            LOGGER.debug("NVD: no CPEs and no keyword targets to query — skipping")
            return

        LOGGER.debug(
            "NVD: querying %d CPEs + %d keyword targets concurrently",
            len(cpe_set),
            len(keyword_targets),
        )
        loop = asyncio.get_running_loop()
        api_key = resolve_nvd_api_key(cfg)

        def _fetch_cpe(cpe: str) -> tuple[str, list[dict], str | None]:
            LOGGER.debug("NVD: fetching CPE '%s'", cpe)
            try:
                cve_objs = nvd_query_by_cpe(cpe, api_key, settings=cfg)
                LOGGER.debug("NVD: CPE '%s' → %d CVEs", cpe, len(cve_objs))
                return cpe, cve_objs, None
            except Exception as exc:
                LOGGER.warning("NVD: CPE '%s' query failed: %s", cpe, exc)
                return cpe, [], str(exc)

        def _fetch_keyword(
            name: str, version: str | None
        ) -> tuple[str, str | None, list[dict], str | None]:
            LOGGER.debug("NVD: fetching keyword '%s %s'", name, version or "")
            try:
                cve_objs = nvd_query_by_keyword(name, version, api_key, settings=cfg)
                LOGGER.debug(
                    "NVD: keyword '%s %s' → %d CVEs", name, version or "", len(cve_objs)
                )
                return name, version, cve_objs, None
            except Exception as exc:
                LOGGER.warning("NVD: keyword '%s %s' query failed: %s", name, version or "", exc)
                return name, version, [], str(exc)

        _nvd_sem = asyncio.Semaphore(cfg.max_concurrency)

        async def _bounded_cpe(cpe: str):
            async with _nvd_sem:
                return await loop.run_in_executor(_executor, _fetch_cpe, cpe)

        async def _bounded_keyword(name: str, version: str | None):
            async with _nvd_sem:
                return await loop.run_in_executor(_executor, _fetch_keyword, name, version)

        cpe_tasks = [_bounded_cpe(cpe) for cpe in sorted(cpe_set)]
        kw_tasks = [_bounded_keyword(n, v) for (n, v) in keyword_targets.values()]

        cpe_results = await asyncio.gather(*cpe_tasks) if cpe_tasks else []
        kw_results = await asyncio.gather(*kw_tasks) if kw_tasks else []

        nvd_findings = 0
        for cpe, raw_list, err in cpe_results:
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
                nvd_findings += 1

        for name, version, raw_list, err in kw_results:
            if err:
                query_errors.append(
                    {"source": "NVD", "keyword": f"{name} {version or ''}".strip(), "error": err}
                )
                continue
            for raw in raw_list:
                if not isinstance(raw, dict):
                    continue
                all_findings.append(
                    _finding_from_raw(
                        raw=raw,
                        cpe=None,
                        component_name=name,
                        component_version=version,
                        settings=cfg,
                    )
                )
                nvd_findings += 1

        LOGGER.info(
            "NVD complete: %d findings from %d CPEs + %d keyword targets (%d errors)",
            nvd_findings,
            len(cpe_set),
            len(keyword_targets),
            sum(1 for e in query_errors if e.get("source") == "NVD"),
        )

    async def _osv() -> None:
        nonlocal all_findings, query_errors, query_warnings
        LOGGER.debug("OSV: querying %d components", len(components))
        f, e, w = await osv_query_by_components(components, cfg)
        LOGGER.info("OSV complete: %d findings, %d errors, %d warnings", len(f), len(e), len(w))
        all_findings.extend(f)
        query_errors.extend(e)
        query_warnings.extend(w)

    async def _gh() -> None:
        nonlocal all_findings, query_errors
        LOGGER.debug("GitHub: querying %d components", len(components))
        f, e, _w = await github_query_by_components(components, cfg)
        LOGGER.info("GitHub complete: %d findings, %d errors", len(f), len(e))
        all_findings.extend(f)
        query_errors.extend(e)

    async def _vulndb() -> None:
        nonlocal all_findings, query_errors, query_warnings
        LOGGER.debug("VulDB: querying %d components", len(components_w_cpe))
        result = await VulnDbSource(api_key=vulndb_api_key_for_adapters()).query(components_w_cpe, cfg)
        f = result.get("findings", [])
        e = result.get("errors", [])
        w = result.get("warnings", [])
        LOGGER.info("VulDB complete: %d findings, %d errors, %d warnings", len(f), len(e), len(w))
        all_findings.extend(f)
        query_errors.extend(e)
        query_warnings.extend(w)

    coros = []
    if AnalysisSource.NVD in selected_enum:
        coros.append(_nvd())
    if AnalysisSource.OSV in selected_enum:
        coros.append(_osv())
    if AnalysisSource.GITHUB in selected_enum:
        coros.append(_gh())
    if AnalysisSource.VULNDB in selected_enum:
        coros.append(_vulndb())
    if coros:
        await asyncio.gather(*coros)

    findings = deduplicate_findings(all_findings)
    LOGGER.debug(
        "Deduplication: %d raw findings → %d unique findings",
        len(all_findings),
        len(findings),
    )

    buckets = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for f in findings:
        sev = str((f or {}).get("severity", "UNKNOWN")).upper()
        buckets[sev if sev in buckets else "UNKNOWN"] += 1

    LOGGER.info(
        "Multi-source analysis summary: total=%d  CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d UNKNOWN=%d  errors=%d",
        len(findings),
        buckets["CRITICAL"],
        buckets["HIGH"],
        buckets["MEDIUM"],
        buckets["LOW"],
        buckets["UNKNOWN"],
        len(query_errors),
    )

    details: dict[str, Any] = {
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
            "vulndb_api_base_url": getattr(cfg, "vulndb_api_base_url", None),
        },
    }
    if generated_cpe_count > 0:
        details["note"] = f"Generated {generated_cpe_count} CPEs from package URLs to enable NVD correlation."
    if AnalysisSource.NVD in selected_enum and details["components_with_cpe"] == 0:
        # CPE-based correlation wasn't possible, but the keyword-search
        # fallback may still have produced findings — only surface the
        # warning message when NVD yielded nothing at all.
        nvd_any = any("NVD" in (f.get("sources") or []) for f in findings)
        if not nvd_any:
            details["message"] = (
                "No CPE values could be generated; NVD keyword-search fallback returned no matches."
            )
        else:
            details["note"] = (
                "No CPE values available; NVD findings produced via keyword-search fallback "
                "(lower precision than CPE-based correlation)."
            )
    return details
